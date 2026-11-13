#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "features.h"
#include "pe_features.h"

namespace fs = std::filesystem;

namespace {

std::string WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(), nullptr, 0, nullptr, nullptr);
    std::string out((size_t)len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(), out.data(), len, nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(), nullptr, 0);
    std::wstring out((size_t)len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(), out.data(), len);
    return out;
}

bool IsPeExtension(const fs::path& path) {
    std::wstring ext = path.extension().wstring();
    for (auto& c : ext) c = (wchar_t)towlower(c);
    return ext == L".exe" || ext == L".dll" || ext == L".sys" || ext == L".scr" || ext == L".cpl";
}

void WriteCsvField(FILE* file, const std::string& value) {
    bool needQuote = value.find_first_of(",\"\r\n") != std::string::npos;
    if (!needQuote) {
        fwrite(value.data(), 1, value.size(), file);
        return;
    }
    fputc('"', file);
    for (char c : value) {
        if (c == '"') fputc('"', file);
        fputc(c, file);
    }
    fputc('"', file);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    std::wstring output;
    std::wstring listFile;
    std::vector<std::wstring> inputs;
    int label = -1;
    bool recursive = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--output" && i + 1 < argc) {
            output = argv[++i];
        } else if (arg == L"--input" && i + 1 < argc) {
            inputs.push_back(argv[++i]);
        } else if (arg == L"--list" && i + 1 < argc) {
            listFile = argv[++i];
        } else if (arg == L"--label" && i + 1 < argc) {
            label = _wtoi(argv[++i]);
        } else if (arg == L"--recursive") {
            recursive = true;
        } else {
            fwprintf(stderr, L"unknown argument: %s\n", arg.c_str());
            return 2;
        }
    }
    if (output.empty() || label < 0 || (inputs.empty() && listFile.empty())) {
        fwprintf(stderr,
                 L"usage: AegisMlDump --output out.csv --label 0|1 (--input DIR [--input DIR2] "
                 L"[--recursive] | --list file.txt)\n");
        return 2;
    }

    std::vector<fs::path> files;
    for (const auto& input : inputs) {
        std::error_code ec;
        if (recursive) {
            for (fs::recursive_directory_iterator it(input, fs::directory_options::skip_permission_denied, ec), end;
                 it != end; it.increment(ec)) {
                if (ec) {
                    ec.clear();
                    continue;
                }
                if (it->is_regular_file(ec) && IsPeExtension(it->path())) files.push_back(it->path());
            }
        } else {
            for (fs::directory_iterator it(input, fs::directory_options::skip_permission_denied, ec), end;
                 it != end; it.increment(ec)) {
                if (ec) {
                    ec.clear();
                    continue;
                }
                if (it->is_regular_file(ec) && IsPeExtension(it->path())) files.push_back(it->path());
            }
        }
    }

    if (!listFile.empty()) {
        std::ifstream list(listFile);
        std::string line;
        while (std::getline(list, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            files.push_back(Utf8ToWide(line));
        }
    }

    FILE* out = _wfopen(output.c_str(), L"wb");
    if (!out) {
        fwprintf(stderr, L"cannot open output file: %s\n", output.c_str());
        return 1;
    }

    fprintf(out, "label,path,%s\n", aegis_ml::FeatureNamesCsv());
    long written = 0;
    long skipped = 0;
    for (const auto& file : files) {
        float features[aegis_ml::F_COUNT];
        std::string err;
        int count = aegis_ml::ExtractFeatures(file.wstring().c_str(), features, &err);
        if (count != aegis_ml::F_COUNT) {
            ++skipped;
            continue;
        }
        fprintf(out, "%d,", label);
        WriteCsvField(out, WideToUtf8(file.wstring()));
        for (int i = 0; i < count; ++i) fprintf(out, ",%.6g", features[i]);
        fputc('\n', out);
        ++written;
    }
    fclose(out);

    fwprintf(stderr, L"done: %ld rows, %ld skipped\n", written, skipped);
    return 0;
}
