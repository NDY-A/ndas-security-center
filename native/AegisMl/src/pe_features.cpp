#include "pe_features.h"

#include <windows.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>
#include <unordered_set>
#include <vector>

#include "aegis_ml.h"
#include "features.h"

namespace aegis_ml {
namespace {

constexpr uint64_t kMaxFileSize = 256ull * 1024 * 1024;
constexpr size_t kStringScanBytes = 96ull * 1024 * 1024;
constexpr size_t kHistogramScanBytes = 256ull * 1024 * 1024;
constexpr size_t kSectionEntropyBytes = 32ull * 1024 * 1024;
constexpr int kMaxSections = 96;
constexpr int kMaxImportDlls = 200;
constexpr int kMaxImportsPerDll = 4096;
constexpr int kMaxDebugEntries = 64;

inline uint16_t Rd16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
inline uint32_t Rd32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline uint64_t Rd64(const uint8_t* p) { return (uint64_t)Rd32(p) | ((uint64_t)Rd32(p + 4) << 32); }

bool InBounds(uint64_t offset, uint64_t length, uint64_t size) {
    return offset <= size && length <= size - offset;
}

inline bool IsPrintable(uint8_t c) { return c >= 0x20 && c <= 0x7e; }

std::string Lower(std::string s) {
    for (auto& c : s) {
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    }
    return s;
}

bool ContainsI(const char* hay, size_t hayLen, const char* needle) {
    size_t n = std::strlen(needle);
    if (n == 0 || hayLen < n) return false;
    for (size_t i = 0; i + n <= hayLen; ++i) {
        size_t j = 0;
        for (; j < n; ++j) {
            char a = hay[i + j];
            char b = needle[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (a != b) break;
        }
        if (j == n) return true;
    }
    return false;
}

bool LooksLikeIp(const char* s, size_t n) {
    int parts = 0;
    size_t i = 0;
    while (i < n && parts < 4) {
        size_t digits = 0;
        int value = 0;
        while (i < n && s[i] >= '0' && s[i] <= '9' && digits < 3) {
            value = value * 10 + (s[i] - '0');
            ++digits;
            ++i;
        }
        if (digits == 0 || value > 255) return false;
        ++parts;
        if (parts < 4) {
            if (i >= n || s[i] != '.') return false;
            ++i;
        }
    }
    return parts == 4;
}

double Entropy(const uint8_t* data, size_t length) {
    if (length == 0) return 0.0;
    uint64_t counts[256] = {};
    for (size_t i = 0; i < length; ++i) ++counts[data[i]];
    double entropy = 0.0;
    double total = (double)length;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / total;
        entropy -= p * (std::log2(p));
    }
    return entropy;
}

const std::unordered_set<std::string>& InjectionApis() {
    static const std::unordered_set<std::string> s = {
        "virtualallocex", "writeprocessmemory", "createremotethread", "createremotethreadex",
        "ntunmapviewofsection", "queueuserapc", "setthreadcontext", "ntcreatethreadex",
        "rtlcreateuserthread", "ntmapviewofsection", "zwwritevirtualmemory", "mapviewofsection",
        "createremotethread32"};
    return s;
}

const std::unordered_set<std::string>& CredentialApis() {
    static const std::unordered_set<std::string> s = {
        "minidumpwritedump", "credenumeratew", "credenumeratea", "credreadw", "credreada",
        "lsaenumeratelogonsessions", "cryptunprotectdata", "samqueryinformationuser",
        "ntopenprocess", "openprocesstoken", "adjusttokenprivileges", "lookupprivilegevaluew",
        "impersonateloggedonuser"};
    return s;
}

const std::unordered_set<std::string>& PersistenceApis() {
    static const std::unordered_set<std::string> s = {
        "createservicew", "createservicea", "startservicew", "startservicea",
        "openscmanagerw", "openscmanagera", "changeserviceconfigw", "changeserviceconfiga",
        "regsetvalueexw", "regsetvalueexa", "regcreatekeyexw", "regcreatekeyexa",
        "winexec", "shellexecutew", "shellexecutea"};
    return s;
}

const std::unordered_set<std::string>& AntiDebugApis() {
    static const std::unordered_set<std::string> s = {
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "ntsetinformationthread", "blockinput", "outputdebugstringw", "outputdebugstringa",
        "getsystemfirmwaretable", "enumsystemfirmwaretables", "ntquerysysteminformation",
        "gettickcount", "queryperformancecounter", "findwindoww", "findwindowa"};
    return s;
}

const std::unordered_set<std::string>& NetworkApis() {
    static const std::unordered_set<std::string> s = {
        "internetopenurlw", "internetopenurla", "internetopenw", "internetopena",
        "urldownloadtofilew", "urldownloadtofilea", "winhttpopen", "winhttpsendrequest",
        "wsastartup", "connect", "send", "recv", "httpsendrequestw", "httpsendrequesta",
        "internetreadfile", "socket", "gethostbyname", "inet_addr", "dnsquery_w",
        "wsaconnect", "bind", "listen", "accept"};
    return s;
}

const std::unordered_set<std::string>& ProcessApis() {
    static const std::unordered_set<std::string> s = {
        "openprocess", "createprocessw", "createprocessa", "shellexecutew", "shellexecutea",
        "winexec", "createprocessasuserw", "terminateprocess", "createtoolhelp32snapshot",
        "process32first", "process32next", "process32firstw", "process32nextw",
        "openprocesstoken", "duplicatehandle"};
    return s;
}

const std::unordered_set<std::string>& ServiceApis() {
    static const std::unordered_set<std::string> s = {
        "openscmanagerw", "openscmanagera", "createservicew", "createservicea",
        "startservicew", "startservicea", "controlservice", "changeserviceconfigw",
        "changeserviceconfiga", "deleteservice"};
    return s;
}

const std::unordered_set<std::string>& RegistryApis() {
    static const std::unordered_set<std::string> s = {
        "regopenkeyexw", "regopenkeyexa", "regsetvalueexw", "regsetvalueexa",
        "regcreatekeyexw", "regcreatekeyexa", "regqueryvalueexw", "regqueryvalueexa",
        "regdeletekeyw", "regdeletekeya", "regdeletevaluew", "regdeletevaluea",
        "regclosekey", "regopenkeyw", "regopenkeya"};
    return s;
}

const std::unordered_set<std::string>& FileApis() {
    static const std::unordered_set<std::string> s = {
        "createfilew", "createfilea", "writefile", "deletefilew", "deletefilea",
        "copyfilew", "copyfilea", "movefilew", "movefilea", "setfileattributesw",
        "setfileattributesa", "findfirstfilew", "findfirstfilea", "createdirectoryw",
        "createdirectorya", "removedirectoryw", "removedirectorya"};
    return s;
}

const std::unordered_set<std::string>& CryptApis() {
    static const std::unordered_set<std::string> s = {
        "cryptencrypt", "cryptdecrypt", "cryptgenrandom", "bcryptencrypt", "bcryptdecrypt",
        "bcryptgeneraterandom", "cryptacquirecontextw", "cryptacquirecontexta",
        "ncryptopenstorageprovider", "cryptcreatehash", "crypthashdata"};
    return s;
}

const std::unordered_set<std::string>& AntiVmApis() {
    static const std::unordered_set<std::string> s = {
        "getsystemfirmwaretable", "enumsystemfirmwaretables", "enumdevicedrivers",
        "getadapteraddresses", "setupdigetdeviceregistrypropertyw", "getsyscolor",
        "setwindowshookexw", "getforegroundwindow", "getcursorpos"};
    return s;
}

const std::unordered_set<std::string>& CommonDlls() {
    static const std::unordered_set<std::string> s = {
        "kernel32.dll", "ntdll.dll", "advapi32.dll", "user32.dll", "gdi32.dll",
        "comctl32.dll", "comdlg32.dll", "shell32.dll", "shlwapi.dll", "ole32.dll",
        "oleaut32.dll", "version.dll", "psapi.dll", "dbghelp.dll", "winmm.dll",
        "crypt32.dll", "secur32.dll", "iphlpapi.dll", "userenv.dll", "rpcrt4.dll",
        "msvcrt.dll", "ucrtbase.dll", "mscoree.dll", "ws2_32.dll", "wininet.dll",
        "winhttp.dll", "urlmon.dll", "setupapi.dll", "cfgmgr32.dll", "bcrypt.dll",
        "ncrypt.dll", "imagehlp.dll", "wintrust.dll", "mpr.dll", "netapi32.dll",
        "wtsapi32.dll", "dwmapi.dll", "uxtheme.dll", "propsys.dll", "dnsapi.dll",
        "api-ms-win-core-file-l1-1-0.dll", "msvcp_win.dll", "sechost.dll", "kernelbase.dll"};
    return s;
}

bool IsKnownSectionName(const std::string& lower) {
    static const std::unordered_set<std::string> s = {
        ".text", "text", ".data", "data", ".rdata", "rdata", ".rsrc", "rsrc",
        ".reloc", "reloc", ".tls", "tls", ".bss", "bss", ".idata", "idata",
        ".edata", "edata", ".didat", "didat", ".pdata", "pdata", ".xdata", "xdata",
        ".debug", "debug", ".sdata", "sdata", "code", "init", ".crt", ".gfids",
        ".00cfg", "_.idata", ".orpc", ".rdata$zzzdbg"};
    if (s.count(lower)) return true;
    if (lower.rfind(".text$", 0) == 0 || lower.rfind(".rdata$", 0) == 0 ||
        lower.rfind(".data$", 0) == 0 || lower.rfind(".xdata$", 0) == 0) {
        return true;
    }
    return false;
}

struct ParsedSection {
    std::string name;
    uint32_t virtualSize = 0;
    uint32_t virtualAddress = 0;
    uint32_t rawSize = 0;
    uint32_t rawPtr = 0;
    uint32_t characteristics = 0;
    double entropy = 0.0;
};

struct Stats {
    long urlCount = 0;
    long ipCount = 0;
    long registryCount = 0;
    long suspiciousKeywordCount = 0;
    long kwPowershell = 0;
    long kwCmd = 0;
    long kwAppdata = 0;
    long kwTemp = 0;
    long kwBase64 = 0;
    long kwHttp = 0;
    long asciiStrings = 0;
    long wideStrings = 0;

    void CheckAscii(const char* s, size_t n) {
        bool matched = false;
        if (ContainsI(s, n, "powershell")) { ++kwPowershell; matched = true; }
        if (ContainsI(s, n, "cmd.exe") || ContainsI(s, n, "cmd /c")) { ++kwCmd; matched = true; }
        if (ContainsI(s, n, "appdata")) { ++kwAppdata; matched = true; }
        if (ContainsI(s, n, "\\temp\\") || ContainsI(s, n, "/temp/")) { ++kwTemp; matched = true; }
        if (ContainsI(s, n, "base64")) { ++kwBase64; matched = true; }
        if (ContainsI(s, n, "http://") || ContainsI(s, n, "https://")) { ++kwHttp; ++urlCount; matched = true; }
        if (ContainsI(s, n, "hkey_") || ContainsI(s, n, "software\\") ||
            ContainsI(s, n, "currentversion")) {
            ++registryCount;
            matched = true;
        }
        if (LooksLikeIp(s, n)) { ++ipCount; matched = true; }
        if (matched) ++suspiciousKeywordCount;
    }
};

void ScanStrings(const uint8_t* data, size_t length, Stats* stats) {
    size_t i = 0;
    while (i < length) {
        if (IsPrintable(data[i])) {
            size_t start = i;
            while (i < length && IsPrintable(data[i])) ++i;
            size_t n = i - start;
            if (n >= 4) {
                ++stats->asciiStrings;
                stats->CheckAscii(reinterpret_cast<const char*>(data + start), n);
            }
        } else {
            ++i;
        }
    }

    i = 0;
    while (i + 1 < length) {
        if (IsPrintable(data[i]) && data[i + 1] == 0) {
            size_t start = i;
            while (i + 1 < length && IsPrintable(data[i]) && data[i + 1] == 0) i += 2;
            size_t n = (i - start) / 2;
            if (n >= 4) {
                ++stats->wideStrings;
                char buf[512];
                size_t copy = std::min(n, sizeof(buf) - 1);
                for (size_t k = 0; k < copy; ++k) buf[k] = (char)data[start + k * 2];
                buf[copy] = 0;
                stats->CheckAscii(buf, copy);
            }
        } else {
            ++i;
        }
    }
}

long CountPattern(const uint8_t* data, size_t length, const uint8_t* pattern, size_t plen) {
    long count = 0;
    if (plen == 0 || length < plen) return 0;
    size_t i = 0;
    while (i + plen <= length) {
        const uint8_t* hit = static_cast<const uint8_t*>(memchr(data + i, pattern[0], length - i - plen + 1));
        if (!hit) break;
        size_t pos = (size_t)(hit - data);
        if (std::memcmp(data + pos, pattern, plen) == 0) {
            ++count;
            i = pos + plen;
        } else {
            i = pos + 1;
        }
    }
    return count;
}

inline double Log1p(double value) { return std::log1p(std::max(0.0, value)); }

}  // namespace

const char* FeatureNamesCsv() {
    static const std::string names = [] {
        std::string out;
#define AEGIS_ML_NAME_ENTRY(name) out += #name; out += ',';
        AEGIS_ML_FEATURE_LIST(AEGIS_ML_NAME_ENTRY)
#undef AEGIS_ML_NAME_ENTRY
        if (!out.empty()) out.pop_back();
        return out;
    }();
    return names.c_str();
}

int ExtractFeatures(const wchar_t* path, float* features, std::string* err) {
    if (!path || !features || !err) return AEGIS_ML_ERR_INVALID_ARGUMENT;
    *err = "";
    std::fill(features, features + F_COUNT, 0.0f);

    HANDLE file = CreateFileW(path, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        *err = "cannot open file";
        return AEGIS_ML_ERR_IO;
    }

    LARGE_INTEGER sizeLi{};
    if (!GetFileSizeEx(file, &sizeLi) || sizeLi.QuadPart <= 0) {
        CloseHandle(file);
        *err = sizeLi.QuadPart == 0 ? "empty file" : "cannot get file size";
        return AEGIS_ML_ERR_IO;
    }
    uint64_t fileSize = (uint64_t)sizeLi.QuadPart;
    if (fileSize > kMaxFileSize) {
        CloseHandle(file);
        *err = "file too large";
        return AEGIS_ML_ERR_TOO_LARGE;
    }

    HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mapping) {
        CloseHandle(file);
        *err = "cannot map file";
        return AEGIS_ML_ERR_IO;
    }
    const uint8_t* base = static_cast<const uint8_t*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
    if (!base) {
        CloseHandle(mapping);
        CloseHandle(file);
        *err = "cannot map view";
        return AEGIS_ML_ERR_IO;
    }

    int result = AEGIS_ML_ERR_NOT_PE;
    auto cleanup = [&] {
        UnmapViewOfFile(base);
        CloseHandle(mapping);
        CloseHandle(file);
    };

    const uint8_t* p = base;
    if (fileSize < 0x40 || p[0] != 'M' || p[1] != 'Z') {
        *err = "not a PE file (missing MZ)";
        cleanup();
        return AEGIS_ML_ERR_NOT_PE;
    }

    const uint32_t eLfanew = Rd32(p + 0x3c);
    bool fanewSane = eLfanew >= 0x40 && eLfanew <= 0x1000 && InBounds(eLfanew, 24, fileSize);
    features[F_el_fanew_sane] = fanewSane ? 1.0f : 0.0f;
    if (!fanewSane || Rd32(p + eLfanew) != 0x00004550) {
        *err = "invalid PE header";
        cleanup();
        return AEGIS_ML_ERR_NOT_PE;
    }

    const uint8_t* coff = p + eLfanew + 4;
    const uint16_t machine = Rd16(coff + 0);
    const uint16_t sectionCount = Rd16(coff + 2);
    const uint32_t timestamp = Rd32(coff + 4);
    const uint16_t optionalSize = Rd16(coff + 16);
    const uint16_t characteristics = Rd16(coff + 18);

    const uint64_t optionalOffset = (uint64_t)eLfanew + 24;
    if (sectionCount == 0 || sectionCount > kMaxSections || optionalSize < 96 ||
        !InBounds(optionalOffset, optionalSize, fileSize)) {
        *err = "unsupported PE layout";
        cleanup();
        return AEGIS_ML_ERR_NOT_PE;
    }
    const uint8_t* opt = p + optionalOffset;
    const uint16_t magic = Rd16(opt);

    bool pe32Plus = false;
    uint32_t dirCount = 0;
    uint64_t dirOffset = 0;
    uint32_t entryPoint = Rd32(opt + 16);
    uint16_t subsystem = 0;
    uint32_t checksum = 0;
    uint32_t sizeOfHeaders = 0;
    if (magic == 0x10b) {
        pe32Plus = false;
        subsystem = Rd16(opt + 68);
        checksum = Rd32(opt + 64);
        sizeOfHeaders = Rd32(opt + 60);
        dirCount = Rd32(opt + 92);
        dirOffset = optionalOffset + 96;
    } else if (magic == 0x20b) {
        pe32Plus = true;
        subsystem = Rd16(opt + 68);
        checksum = Rd32(opt + 64);
        sizeOfHeaders = Rd32(opt + 60);
        dirCount = Rd32(opt + 108);
        dirOffset = optionalOffset + 112;
    } else {
        *err = "unknown optional header";
        cleanup();
        return AEGIS_ML_ERR_NOT_PE;
    }
    (void)sizeOfHeaders;

    const uint32_t maxDirs = dirCount > 16 ? 16 : dirCount;
    auto ReadDir = [&](int index, uint32_t* rva, uint32_t* size) {
        *rva = 0;
        *size = 0;
        uint64_t at = dirOffset + (uint64_t)index * 8;
        if ((uint32_t)index >= maxDirs || !InBounds(at, 8, fileSize)) return;
        *rva = Rd32(p + at);
        *size = Rd32(p + at + 4);
    };

    uint32_t exportRva, exportSize, importRva, importSize, resourceRva, resourceSize;
    uint32_t securityRva, securitySize, relocRva, relocSize, debugRva, debugSize;
    uint32_t tlsRva, tlsSize, clrRva, clrSize;
    ReadDir(0, &exportRva, &exportSize);
    ReadDir(1, &importRva, &importSize);
    ReadDir(2, &resourceRva, &resourceSize);
    ReadDir(4, &securityRva, &securitySize);
    ReadDir(5, &relocRva, &relocSize);
    ReadDir(6, &debugRva, &debugSize);
    ReadDir(9, &tlsRva, &tlsSize);
    ReadDir(14, &clrRva, &clrSize);

    features[F_file_size_log] = (float)Log1p((double)fileSize);
    features[F_file_entropy] = (float)Entropy(p, (size_t)std::min<uint64_t>(fileSize, kHistogramScanBytes));
    features[F_is_dotnet] = clrRva != 0 && clrSize != 0 ? 1.0f : 0.0f;
    features[F_is_dll] = (characteristics & 0x2000) ? 1.0f : 0.0f;
    features[F_machine_amd64] = machine == 0x8664 ? 1.0f : 0.0f;
    features[F_machine_i386] = machine == 0x14c ? 1.0f : 0.0f;
    features[F_machine_other] = (machine != 0x8664 && machine != 0x14c) ? 1.0f : 0.0f;
    features[F_subsystem_gui] = subsystem == 2 ? 1.0f : 0.0f;
    features[F_subsystem_cui] = subsystem == 3 ? 1.0f : 0.0f;
    features[F_subsystem_other] = (subsystem != 2 && subsystem != 3) ? 1.0f : 0.0f;
    features[F_timestamp_zero] = timestamp == 0 ? 1.0f : 0.0f;
    const uint64_t now = (uint64_t)time(nullptr);
    features[F_timestamp_anomalous] =
        (timestamp != 0 && ((uint64_t)timestamp > now + 86400 || timestamp < 315532800)) ? 1.0f : 0.0f;
    features[F_has_authenticode] = securitySize > 0 ? 1.0f : 0.0f;
    features[F_has_checksum] = checksum != 0 ? 1.0f : 0.0f;
    features[F_rich_header_present] =
        CountPattern(p + 0x40, (size_t)(std::min<uint64_t>(eLfanew, fileSize) - 0x40),
                     reinterpret_cast<const uint8_t*>("Rich"), 4) > 0
            ? 1.0f
            : 0.0f;
    features[F_debug_directory_present] = debugRva != 0 && debugSize != 0 ? 1.0f : 0.0f;
    features[F_tls_directory_present] = tlsRva != 0 && tlsSize != 0 ? 1.0f : 0.0f;
    features[F_reloc_directory_present] = relocRva != 0 && relocSize != 0 ? 1.0f : 0.0f;
    features[F_resource_directory_present] = resourceRva != 0 && resourceSize != 0 ? 1.0f : 0.0f;
    features[F_export_directory_present] = exportRva != 0 && exportSize != 0 ? 1.0f : 0.0f;

    std::vector<ParsedSection> sections;
    sections.reserve(sectionCount);
    const uint64_t sectionOffset = optionalOffset + optionalSize;
    for (int i = 0; i < sectionCount; ++i) {
        uint64_t at = sectionOffset + (uint64_t)i * 40;
        if (!InBounds(at, 40, fileSize)) break;
        ParsedSection section;
        char rawName[9] = {};
        std::memcpy(rawName, p + at, 8);
        section.name = std::string(rawName);
        section.virtualSize = Rd32(p + at + 8);
        section.virtualAddress = Rd32(p + at + 12);
        section.rawSize = Rd32(p + at + 16);
        section.rawPtr = Rd32(p + at + 20);
        section.characteristics = Rd32(p + at + 36);
        if (section.rawSize > 0 && InBounds(section.rawPtr, section.rawSize, fileSize)) {
            size_t sample = (size_t)std::min<uint64_t>(section.rawSize, kSectionEntropyBytes);
            section.entropy = Entropy(p + section.rawPtr, sample);
        }
        sections.push_back(section);
    }

    auto RvaToOffset = [&](uint32_t rva, uint32_t* offset) {
        if (rva < sizeOfHeaders && rva < fileSize) {
            *offset = rva;
            return true;
        }
        for (const auto& section : sections) {
            uint64_t span = std::max<uint64_t>(section.virtualSize, section.rawSize);
            if (rva >= section.virtualAddress && (uint64_t)rva < (uint64_t)section.virtualAddress + span) {
                uint64_t delta = rva - section.virtualAddress;
                if (delta >= section.rawSize) return false;
                uint64_t fileOffset = (uint64_t)section.rawPtr + delta;
                if (fileOffset >= fileSize) return false;
                *offset = (uint32_t)fileOffset;
                return true;
            }
        }
        return false;
    };

    // Entropy and section aggregates
    double entropySum = 0.0;
    double emin = 8.0;
    double emax = 0.0;
    int highEntropy = 0;
    int veryHighEntropy = 0;
    int zeroRaw = 0;
    int execSections = 0;
    int writeSections = 0;
    int wxSections = 0;
    int nonstandard = 0;
    int mismatch = 0;
    bool hasText = false, hasData = false, hasRdata = false, hasRsrc = false, hasRelocSec = false;
    bool nameUpx = false, nameVmp = false, nameAspack = false, nameOtherPacker = false;
    bool entryInSection = false;
    double entryEntropy = 0.0;
    double ratioSum = 0.0;
    double ratioMax = 0.0;
    uint64_t overlayEnd = 0;

    for (const auto& section : sections) {
        std::string lower = Lower(section.name);
        lower.erase(std::remove(lower.begin(), lower.end(), '\0'), lower.end());
        std::string trimmed = lower;
        while (!trimmed.empty() && trimmed.back() == ' ') trimmed.pop_back();

        entropySum += section.entropy;
        emin = std::min(emin, section.entropy);
        emax = std::max(emax, section.entropy);
        if (section.entropy >= 7.2) ++highEntropy;
        if (section.entropy >= 7.8) ++veryHighEntropy;
        if (section.rawSize == 0) ++zeroRaw;

        bool isExec = (section.characteristics & 0x20000000) != 0;
        bool isWrite = (section.characteristics & 0x80000000) != 0;
        if (isExec) ++execSections;
        if (isWrite) ++writeSections;
        if (isExec && isWrite) ++wxSections;

        if (!IsKnownSectionName(trimmed)) ++nonstandard;
        if (trimmed == ".text" || trimmed == "text" || trimmed == "code") hasText = true;
        if (trimmed == ".data" || trimmed == "data") hasData = true;
        if (trimmed == ".rdata" || trimmed == "rdata") hasRdata = true;
        if (trimmed == ".rsrc" || trimmed == "rsrc") hasRsrc = true;
        if (trimmed == ".reloc" || trimmed == "reloc") hasRelocSec = true;

        if (trimmed.find("upx") != std::string::npos) nameUpx = true;
        if (trimmed.find("vmp") != std::string::npos || trimmed.find("themida") != std::string::npos ||
            trimmed.find(".enigma") != std::string::npos) {
            nameVmp = true;
        }
        if (trimmed.find("aspack") != std::string::npos || trimmed.find(".adata") != std::string::npos) {
            nameAspack = true;
        }
        if (trimmed.find("mpress") != std::string::npos || trimmed.find("petite") != std::string::npos ||
            trimmed.find("mew") != std::string::npos || trimmed.find("nsp") != std::string::npos ||
            trimmed.find(".packed") != std::string::npos || trimmed.find(".boom") != std::string::npos ||
            trimmed.find("pec") != std::string::npos || trimmed.find(".perplex") != std::string::npos ||
            trimmed.find("pklst") != std::string::npos) {
            nameOtherPacker = true;
        }

        uint64_t span = std::max<uint64_t>(section.virtualSize, section.rawSize);
        if (entryPoint >= section.virtualAddress &&
            (uint64_t)entryPoint < (uint64_t)section.virtualAddress + span) {
            entryInSection = true;
            entryEntropy = section.entropy;
        }

        double ratio = section.rawSize > 0 ? (double)std::max(section.virtualSize, section.rawSize) / (double)section.rawSize : 0.0;
        if (ratio > 0.0) {
            ratioSum += ratio;
            ratioMax = std::max(ratioMax, ratio);
        }
        if (section.rawSize > 0 && section.virtualSize > 0) {
            double vm = (double)section.virtualSize / (double)section.rawSize;
            if (vm > 8.0 || vm < 0.125) ++mismatch;
        }

        uint64_t end = (uint64_t)section.rawPtr + section.rawSize;
        if (end <= fileSize) overlayEnd = std::max(overlayEnd, end);
    }

    int sectionCountParsed = (int)sections.size();
    features[F_section_count] = (float)sectionCountParsed;
    features[F_zero_rawsize_section_count] = (float)zeroRaw;
    features[F_high_entropy_sections] = (float)highEntropy;
    features[F_very_high_entropy_sections] = (float)veryHighEntropy;
    features[F_max_section_entropy] = (float)emax;
    features[F_mean_section_entropy] = sectionCountParsed > 0 ? (float)(entropySum / sectionCountParsed) : 0.0f;
    features[F_min_section_entropy] = sectionCountParsed > 0 ? (float)std::min(emin, 8.0) : 0.0f;
    features[F_exec_section_count] = (float)execSections;
    features[F_writable_section_count] = (float)writeSections;
    features[F_wx_section_count] = (float)wxSections;
    features[F_entry_in_section] = entryInSection ? 1.0f : 0.0f;
    features[F_entry_section_entropy] = (float)entryEntropy;
    features[F_entry_section_high_entropy] = entryEntropy >= 7.2 ? 1.0f : 0.0f;
    features[F_nonstandard_section_name_count] = (float)nonstandard;
    features[F_section_name_upx] = nameUpx ? 1.0f : 0.0f;
    features[F_section_name_vmp] = nameVmp ? 1.0f : 0.0f;
    features[F_section_name_aspack] = nameAspack ? 1.0f : 0.0f;
    features[F_section_name_other_packer] = nameOtherPacker ? 1.0f : 0.0f;
    features[F_has_text_section] = hasText ? 1.0f : 0.0f;
    features[F_has_data_section] = hasData ? 1.0f : 0.0f;
    features[F_has_rdata_section] = hasRdata ? 1.0f : 0.0f;
    features[F_has_rsrc_section] = hasRsrc ? 1.0f : 0.0f;
    features[F_has_reloc_section] = hasRelocSec ? 1.0f : 0.0f;
    features[F_max_virtual_raw_ratio_log] = (float)Log1p(ratioMax);
    features[F_mean_virtual_raw_ratio] = sectionCountParsed > 0 ? (float)(ratioSum / sectionCountParsed) : 0.0f;
    features[F_size_mismatch_section_count] = (float)mismatch;

    if (overlayEnd > 0 && fileSize > overlayEnd) {
        uint64_t overlay = fileSize - overlayEnd;
        features[F_overlay_size_log] = (float)Log1p((double)overlay);
        features[F_overlay_ratio] = (float)((double)overlay / (double)fileSize);
    }

    // Export count
    if (exportRva != 0 && exportSize >= 40) {
        uint32_t exportOffset = 0;
        if (RvaToOffset(exportRva, &exportOffset) && InBounds(exportOffset, 40, fileSize)) {
            uint32_t names = Rd32(p + exportOffset + 24);
            features[F_export_count_log] = (float)Log1p((double)names);
        }
    }

    // PDB path
    if (debugRva != 0 && debugSize != 0) {
        uint32_t debugOffset = 0;
        if (RvaToOffset(debugRva, &debugOffset)) {
            for (int i = 0; i < kMaxDebugEntries; ++i) {
                uint64_t at = (uint64_t)debugOffset + (uint64_t)i * 28;
                if (!InBounds(at, 28, fileSize)) break;
                uint32_t type = Rd32(p + at + 12);
                uint32_t dataSize = Rd32(p + at + 16);
                uint32_t dataPtr = Rd32(p + at + 24);
                if (type == 2 && dataSize > 4 && InBounds(dataPtr, dataSize, fileSize)) {
                    const uint8_t* cv = p + dataPtr;
                    if (std::memcmp(cv, "RSDS", 4) == 0) {
                        uint32_t pathStart = dataPtr + 24;
                        if (pathStart < dataPtr + dataSize && pathStart < fileSize && p[pathStart] != 0) {
                            features[F_pdb_path_present] = 1.0f;
                        }
                    } else if (std::memcmp(cv, "NB10", 4) == 0) {
                        uint32_t pathStart = dataPtr + 16;
                        if (pathStart < dataPtr + dataSize && pathStart < fileSize && p[pathStart] != 0) {
                            features[F_pdb_path_present] = 1.0f;
                        }
                    }
                }
            }
        }
    }

    // Imports
    features[F_has_import_directory] = (importRva != 0 && importSize != 0) ? 1.0f : 0.0f;
    int importDllCount = 0;
    long importFuncCount = 0;
    long ordinalCount = 0;
    long injection = 0, credential = 0, persistence = 0, antiDebug = 0, network = 0;
    long processApi = 0, serviceApi = 0, registryApi = 0, fileApi = 0, cryptApi = 0, antivmApi = 0;
    bool dllKernel32 = false, dllNtdll = false, dllAdvapi32 = false, dllUser32 = false;
    bool dllWs2 = false, dllWininet = false, dllShell32 = false, dllOle32 = false;
    bool dllVcRuntime = false;
    long nonstandardDlls = 0;

    if (importRva != 0 && importSize != 0) {
        uint32_t importOffset = 0;
        if (RvaToOffset(importRva, &importOffset)) {
            for (int i = 0; i < kMaxImportDlls; ++i) {
                uint64_t at = (uint64_t)importOffset + (uint64_t)i * 20;
                if (!InBounds(at, 20, fileSize)) break;
                uint32_t nameRva = Rd32(p + at + 12);
                uint32_t thunkRva = Rd32(p + at + 0);
                uint32_t firstThunk = Rd32(p + at + 16);
                if (nameRva == 0 && thunkRva == 0 && firstThunk == 0) break;
                ++importDllCount;

                std::string dllName;
                uint32_t nameOffset = 0;
                if (nameRva != 0 && RvaToOffset(nameRva, &nameOffset)) {
                    uint64_t limit = std::min<uint64_t>(fileSize - nameOffset, 256);
                    for (uint64_t k = 0; k < limit; ++k) {
                        char c = (char)p[nameOffset + k];
                        if (c == 0) break;
                        dllName += c;
                    }
                }
                std::string dllLower = Lower(dllName);
                if (dllLower == "kernel32.dll") dllKernel32 = true;
                if (dllLower == "ntdll.dll") dllNtdll = true;
                if (dllLower == "advapi32.dll") dllAdvapi32 = true;
                if (dllLower == "user32.dll") dllUser32 = true;
                if (dllLower == "ws2_32.dll") dllWs2 = true;
                if (dllLower == "wininet.dll" || dllLower == "winhttp.dll") dllWininet = true;
                if (dllLower == "shell32.dll") dllShell32 = true;
                if (dllLower == "ole32.dll") dllOle32 = true;
                if (dllLower.find("vcruntime") != std::string::npos ||
                    dllLower.find("msvcp") != std::string::npos ||
                    dllLower.find("msvcr") != std::string::npos) {
                    dllVcRuntime = true;
                }
                if (!dllLower.empty() && CommonDlls().find(dllLower) == CommonDlls().end()) {
                    ++nonstandardDlls;
                }

                uint32_t lookup = thunkRva != 0 ? thunkRva : firstThunk;
                uint32_t thunkOffset = 0;
                if (lookup != 0 && RvaToOffset(lookup, &thunkOffset)) {
                    uint32_t step = pe32Plus ? 8 : 4;
                    for (int j = 0; j < kMaxImportsPerDll; ++j) {
                        uint64_t tat = (uint64_t)thunkOffset + (uint64_t)j * step;
                        if (!InBounds(tat, step, fileSize)) break;
                        uint64_t value = pe32Plus ? Rd64(p + tat) : Rd32(p + tat);
                        if (value == 0) break;
                        uint64_t ordinalFlag = pe32Plus ? 0x8000000000000000ull : 0x80000000ull;
                        if (value & ordinalFlag) {
                            ++ordinalCount;
                            continue;
                        }
                        ++importFuncCount;
                        uint32_t hintOffset = 0;
                        if (!RvaToOffset((uint32_t)(value & 0x7fffffff), &hintOffset)) continue;
                        uint32_t nameAt = hintOffset + 2;
                        if (nameAt >= fileSize) continue;
                        std::string funcName;
                        uint64_t limit = std::min<uint64_t>(fileSize - nameAt, 256);
                        for (uint64_t k = 0; k < limit; ++k) {
                            char c = (char)p[nameAt + k];
                            if (c == 0) break;
                            funcName += c;
                        }
                        std::string fn = Lower(funcName);
                        if (InjectionApis().count(fn)) ++injection;
                        if (CredentialApis().count(fn)) ++credential;
                        if (PersistenceApis().count(fn)) ++persistence;
                        if (AntiDebugApis().count(fn)) ++antiDebug;
                        if (NetworkApis().count(fn)) ++network;
                        if (ProcessApis().count(fn)) ++processApi;
                        if (ServiceApis().count(fn)) ++serviceApi;
                        if (RegistryApis().count(fn)) ++registryApi;
                        if (FileApis().count(fn)) ++fileApi;
                        if (CryptApis().count(fn)) ++cryptApi;
                        if (AntiVmApis().count(fn)) ++antivmApi;
                    }
                }
            }
        }
    }

    features[F_import_dll_count] = (float)importDllCount;
    features[F_import_func_count_log] = (float)Log1p((double)importFuncCount);
    features[F_import_ordinal_count] = (float)ordinalCount;
    features[F_api_injection_count] = (float)injection;
    features[F_api_credential_count] = (float)credential;
    features[F_api_persistence_count] = (float)persistence;
    features[F_api_anti_debug_count] = (float)antiDebug;
    features[F_api_network_count] = (float)network;
    features[F_api_process_count] = (float)processApi;
    features[F_api_service_count] = (float)serviceApi;
    features[F_api_registry_count] = (float)registryApi;
    features[F_api_file_count] = (float)fileApi;
    features[F_api_crypto_count] = (float)cryptApi;
    features[F_api_antivm_count] = (float)antivmApi;
    features[F_dll_kernel32] = dllKernel32 ? 1.0f : 0.0f;
    features[F_dll_ntdll] = dllNtdll ? 1.0f : 0.0f;
    features[F_dll_advapi32] = dllAdvapi32 ? 1.0f : 0.0f;
    features[F_dll_user32] = dllUser32 ? 1.0f : 0.0f;
    features[F_dll_ws2_32] = dllWs2 ? 1.0f : 0.0f;
    features[F_dll_wininet] = dllWininet ? 1.0f : 0.0f;
    features[F_dll_shell32] = dllShell32 ? 1.0f : 0.0f;
    features[F_dll_ole32] = dllOle32 ? 1.0f : 0.0f;
    features[F_dll_vcruntime] = dllVcRuntime ? 1.0f : 0.0f;
    features[F_dll_nonstandard] = (float)nonstandardDlls;
    features[F_avg_imports_per_dll] =
        importDllCount > 0 ? (float)((double)importFuncCount / (double)importDllCount) : 0.0f;

    // Strings and byte statistics over the head of the file
    size_t stringScan = (size_t)std::min<uint64_t>(fileSize, kStringScanBytes);
    Stats stats;
    ScanStrings(p, stringScan, &stats);
    features[F_ascii_string_count_log] = (float)Log1p((double)stats.asciiStrings);
    features[F_wide_string_count_log] = (float)Log1p((double)stats.wideStrings);
    features[F_url_count] = (float)stats.urlCount;
    features[F_ip_count] = (float)stats.ipCount;
    features[F_registry_path_count] = (float)stats.registryCount;
    features[F_suspicious_keyword_count] = (float)stats.suspiciousKeywordCount;
    features[F_kw_powershell] = (float)stats.kwPowershell;
    features[F_kw_cmd] = (float)stats.kwCmd;
    features[F_kw_appdata] = (float)stats.kwAppdata;
    features[F_kw_temp] = (float)stats.kwTemp;
    features[F_kw_base64] = (float)stats.kwBase64;
    features[F_kw_http] = (float)stats.kwHttp;

    long peHeaders = CountPattern(p, stringScan, reinterpret_cast<const uint8_t*>("PE\0\0"), 4);
    features[F_embedded_pe_headers] = (float)(peHeaders > 0 ? peHeaders - 1 : 0);

    size_t histScan = (size_t)std::min<uint64_t>(fileSize, kHistogramScanBytes);
    uint64_t histogram[16] = {};
    uint64_t zeroBytes = 0;
    uint64_t printable = 0;
    for (size_t i = 0; i < histScan; ++i) {
        uint8_t c = p[i];
        ++histogram[c >> 4];
        if (c == 0) ++zeroBytes;
        if (IsPrintable(c)) ++printable;
    }
    if (histScan > 0) {
        double total = (double)histScan;
        features[F_printable_ratio] = (float)((double)printable / total);
        features[F_zero_byte_ratio] = (float)((double)zeroBytes / total);
        float* bins = &features[F_hist_00_0f];
        for (int i = 0; i < 16; ++i) bins[i] = (float)((double)histogram[i] / total);
    }

    for (int i = 0; i < F_COUNT; ++i) {
        if (!std::isfinite(features[i])) features[i] = 0.0f;
    }

    result = F_COUNT;
    cleanup();
    return result;
}

}  // namespace aegis_ml
