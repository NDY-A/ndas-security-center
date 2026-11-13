#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <shlwapi.h>

#include <cstdarg>
#include <cstdio>
#include <string>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

namespace {

constexpr wchar_t kServiceName[] = L"NdasGuard";
constexpr wchar_t kServiceDisplayName[] = L"NDAS 自保护守卫";
constexpr wchar_t kServiceDescription[] =
    L"NDAS self-protection watchdog: restores the NDAS service and guard sentinels when they are terminated.";
constexpr wchar_t kTargetServiceName[] = L"NDASService";
constexpr wchar_t kSharedMapName[] = L"Global\\NDASGuard.Shared.v1";
constexpr wchar_t kRegistryPath[] = L"SOFTWARE\\NDAS\\Guard";
constexpr wchar_t kLogDirectory[] = L"\\NDAS\\Guard";
constexpr int kGuardCount = 10;
constexpr DWORD kPollIntervalMs = 1000;
constexpr ULONGLONG kBeatTimeoutMs = 15000;

struct SharedState {
    volatile LONG allowExit;
    volatile LONG spawnLock;
    volatile LONG activeSlot;
    volatile LONG slotPid[kGuardCount];
    volatile ULONGLONG slotBeat[kGuardCount];
};

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_serviceStatus = {};
HANDLE g_stopEvent = nullptr;

void LogMessage(const wchar_t* format, ...) {
    wchar_t programData[MAX_PATH] = {};
    if (!GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH)) return;
    std::wstring parent = std::wstring(programData) + L"\\NDAS";
    CreateDirectoryW(parent.c_str(), nullptr);
    std::wstring directory = std::wstring(programData) + kLogDirectory;
    CreateDirectoryW(directory.c_str(), nullptr);
    std::wstring path = directory + L"\\guard.log";

    WIN32_FILE_ATTRIBUTE_DATA attributes = {};
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attributes) &&
        attributes.nFileSizeHigh == 0 && attributes.nFileSizeLow > 2 * 1024 * 1024) {
        DeleteFileW(path.c_str());
    }

    FILE* file = nullptr;
    if (_wfopen_s(&file, path.c_str(), L"a") != 0 || !file) return;
    SYSTEMTIME now = {};
    GetLocalTime(&now);
    fwprintf(file, L"[%04d-%02d-%02d %02d:%02d:%02d pid=%lu] ",
             now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
             GetCurrentProcessId());
    va_list arguments;
    va_start(arguments, format);
    vfwprintf(file, format, arguments);
    va_end(arguments);
    fputws(L"\n", file);
    fclose(file);
}

bool IsSafeMode() { return GetSystemMetrics(SM_CLEANBOOT) != 0; }

bool EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_PRIVILEGES privileges = {};
    privileges.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid)) {
        CloseHandle(token);
        return false;
    }
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
    CloseHandle(token);
    return ok != FALSE;
}

void HardenCurrentProcess() {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(D;;0x1000;;;IU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)",
            SDDL_REVISION_1, &descriptor, nullptr)) {
        return;
    }
    PACL dacl = nullptr;
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    if (GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) && present && dacl) {
        SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                        nullptr, nullptr, dacl, nullptr);
    }
    LocalFree(descriptor);
}

DWORD ReadAllowExitRegistry() {
    HKEY key = nullptr;
    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRegistryPath, 0,
                      KEY_READ | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS) {
        RegQueryValueExW(key, L"AllowExit", nullptr, &type,
                         reinterpret_cast<LPBYTE>(&value), &size);
        RegCloseKey(key);
    }
    return value;
}

bool WriteAllowExitRegistry(DWORD value) {
    HKEY key = nullptr;
    DWORD disposition = 0;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRegistryPath, 0, nullptr, 0,
                        KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key, &disposition) != ERROR_SUCCESS) {
        return false;
    }
    LONG result = RegSetValueExW(key, L"AllowExit", 0, REG_DWORD,
                                 reinterpret_cast<const BYTE*>(&value), sizeof(value));
    RegCloseKey(key);
    return result == ERROR_SUCCESS;
}

HANDLE OpenSharedState(bool createIfMissing) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    SECURITY_ATTRIBUTES attributes = {};
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;WD)",
            SDDL_REVISION_1, &descriptor, nullptr)) {
        attributes.nLength = sizeof(attributes);
        attributes.lpSecurityDescriptor = descriptor;
    }
    HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE,
                                        descriptor ? &attributes : nullptr,
                                        PAGE_READWRITE, 0, sizeof(SharedState), kSharedMapName);
    if (descriptor) LocalFree(descriptor);
    if (!mapping && createIfMissing) {
        mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, kSharedMapName);
    }
    return mapping;
}

SharedState* MapSharedState(HANDLE mapping) {
    if (!mapping) return nullptr;
    return reinterpret_cast<SharedState*>(
        MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedState)));
}

bool IsProcessAlive(DWORD pid) {
    if (pid == 0) return false;
    HANDLE process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return false;
    DWORD exitCode = 0;
    bool alive = GetExitCodeProcess(process, &exitCode) && exitCode == STILL_ACTIVE;
    CloseHandle(process);
    return alive;
}

int CountAliveSlots(SharedState* state) {
    ULONGLONG now = GetTickCount64();
    int count = 0;
    for (int i = 0; i < kGuardCount; ++i) {
        LONG pid = state->slotPid[i];
        if (pid != 0 && IsProcessAlive(static_cast<DWORD>(pid)) &&
            now - state->slotBeat[i] < kBeatTimeoutMs) {
            ++count;
        }
    }
    return count;
}

void SpawnSentinel() {
    wchar_t exePath[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) return;
    std::wstring command = std::wstring(L"\"") + exePath + L"\" --sentinel";
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process = {};
    if (CreateProcessW(exePath, command.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    } else {
        LogMessage(L"spawn sentinel failed: %lu", GetLastError());
    }
}

void EnsureSentinelCount(SharedState* state, const wchar_t* source) {
    if (InterlockedCompareExchange(&state->spawnLock, 1, 0) != 0) return;
    int alive = CountAliveSlots(state);
    int missing = kGuardCount - alive;
    if (missing > 0) {
        LogMessage(L"ensure sentinels (%s): alive=%d spawn=%d", source, alive, missing);
        for (int i = 0; i < missing; ++i) SpawnSentinel();
        Sleep(300);
    }
    InterlockedExchange(&state->spawnLock, 0);
}

void KillAllSentinels(SharedState* state) {
    DWORD self = GetCurrentProcessId();
    EnableDebugPrivilege();
    for (int i = 0; i < kGuardCount; ++i) {
        LONG pid = state->slotPid[i];
        if (pid != 0 && static_cast<DWORD>(pid) != self) {
            HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE,
                                         static_cast<DWORD>(pid));
            if (process) {
                TerminateProcess(process, 0);
                WaitForSingleObject(process, 1000);
                CloseHandle(process);
            }
        }
        state->slotPid[i] = 0;
        state->slotBeat[i] = 0;
    }
}

bool QueryServiceState(SC_HANDLE service, DWORD* stateOut) {
    SERVICE_STATUS status = {};
    if (!QueryServiceStatus(service, &status)) return false;
    *stateOut = status.dwCurrentState;
    return true;
}

void ConfigureRecovery(SC_HANDLE service) {
    SC_ACTION actions[3] = {
        {SC_ACTION_RESTART, 1000},
        {SC_ACTION_RESTART, 1000},
        {SC_ACTION_RESTART, 1000},
    };
    SERVICE_FAILURE_ACTIONSW failureActions = {};
    failureActions.dwResetPeriod = 86400;
    failureActions.cActions = 3;
    failureActions.lpsaActions = actions;
    ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions);
}

void EnsureGuardService(const wchar_t* exePath) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!manager) return;
    SC_HANDLE service = OpenServiceW(manager, kServiceName, SERVICE_ALL_ACCESS);
    if (!service) {
        std::wstring binary = std::wstring(L"\"") + exePath + L"\" --service";
        service = CreateServiceW(manager, kServiceName, kServiceDisplayName,
                                 SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                 SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                 binary.c_str(), nullptr, nullptr, nullptr,
                                 L"LocalSystem", nullptr);
        if (service) {
            LogMessage(L"guard service recreated");
            SERVICE_DESCRIPTIONW description = {};
            description.lpDescription = const_cast<LPWSTR>(kServiceDescription);
            ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description);
            ConfigureRecovery(service);
        }
    }
    if (service) {
        DWORD state = 0;
        if (QueryServiceState(service, &state) && state == SERVICE_STOPPED) {
            if (StartServiceW(service, 0, nullptr)) {
                LogMessage(L"guard service restarted");
            }
        }
        CloseServiceHandle(service);
    }
    CloseServiceHandle(manager);
}

void EnsureTargetService() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return;
    SC_HANDLE service = OpenServiceW(manager, kTargetServiceName,
                                     SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service) {
        wchar_t module[MAX_PATH] = {};
        if (GetModuleFileNameW(nullptr, module, MAX_PATH)) {
            PathRemoveFileSpecW(module);
            PathRemoveFileSpecW(module);
            std::wstring target = std::wstring(module) + L"\\Service\\NDASService.exe";
            if (GetFileAttributesW(target.c_str()) != INVALID_FILE_ATTRIBUTES) {
                service = CreateServiceW(manager, kTargetServiceName, L"NDAS 防护服务",
                                         SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                         SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                         target.c_str(), nullptr, nullptr, nullptr,
                                         L"LocalSystem", nullptr);
                if (service) LogMessage(L"target service recreated");
            }
        }
    }
    if (service) {
        DWORD state = 0;
        if (QueryServiceState(service, &state) && state == SERVICE_STOPPED) {
            if (StartServiceW(service, 0, nullptr)) {
                LogMessage(L"target service restarted");
            }
        }
        CloseServiceHandle(service);
    }
    CloseServiceHandle(manager);
}

void StopServiceByName(const wchar_t* name) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return;
    SC_HANDLE service = OpenServiceW(manager, name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (service) {
        SERVICE_STATUS status = {};
        ControlService(service, SERVICE_CONTROL_STOP, &status);
        CloseServiceHandle(service);
    }
    CloseServiceHandle(manager);
}

int RegisterSlot(SharedState* state) {
    DWORD self = GetCurrentProcessId();
    ULONGLONG now = GetTickCount64();
    int aliveOthers = 0;
    for (int i = 0; i < kGuardCount; ++i) {
        LONG pid = state->slotPid[i];
        if (pid != 0 && static_cast<DWORD>(pid) != self &&
            IsProcessAlive(static_cast<DWORD>(pid)) && now - state->slotBeat[i] < kBeatTimeoutMs) {
            ++aliveOthers;
        }
    }
    if (aliveOthers >= kGuardCount) return -1;
    for (int i = 0; i < kGuardCount; ++i) {
        LONG pid = state->slotPid[i];
        bool dead = pid == 0 || !IsProcessAlive(static_cast<DWORD>(pid)) ||
                    now - state->slotBeat[i] >= kBeatTimeoutMs;
        if (!dead) continue;
        if (InterlockedCompareExchange(&state->slotPid[i], static_cast<LONG>(self), pid) == pid) {
            state->slotBeat[i] = now;
            return i;
        }
    }
    return -1;
}

void ReportStatus(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHint = 0) {
    if (!g_statusHandle) return;
    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwCurrentState = state;
    g_serviceStatus.dwWin32ExitCode = exitCode;
    g_serviceStatus.dwWaitHint = waitHint;
    g_serviceStatus.dwControlsAccepted =
        state == SERVICE_RUNNING ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    SetServiceStatus(g_statusHandle, &g_serviceStatus);
}

DWORD WINAPI ServiceControlHandler(DWORD control, DWORD, void*, void*) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        if (g_stopEvent) SetEvent(g_stopEvent);
    }
    return NO_ERROR;
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceControlHandler, nullptr);
    if (!g_statusHandle) return;
    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 5000);

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ReportStatus(SERVICE_RUNNING);

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    HANDLE mapping = OpenSharedState(true);
    SharedState* state = MapSharedState(mapping);
    bool allowExit = ReadAllowExitRegistry() != 0 || IsSafeMode();
    if (state) {
        state->allowExit = allowExit ? 1 : 0;
        if (!allowExit) {
            for (int i = 0; i < kGuardCount; ++i) {
                state->slotPid[i] = 0;
                state->slotBeat[i] = 0;
            }
        }
    }

    if (allowExit) {
        LogMessage(L"guard service started disarmed, stopping");
        if (state) UnmapViewOfFile(state);
        if (mapping) CloseHandle(mapping);
        ReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }

    LogMessage(L"guard service started");
    while (WaitForSingleObject(g_stopEvent, kPollIntervalMs) == WAIT_TIMEOUT) {
        if ((ReadAllowExitRegistry() | (state ? state->allowExit : 0)) != 0 || IsSafeMode()) {
            LogMessage(L"disarm requested, stopping guard service");
            break;
        }
        EnsureGuardService(exePath);
        EnsureTargetService();
        if (state) EnsureSentinelCount(state, L"service");
    }

    LogMessage(L"guard service stopping");
    if (state) UnmapViewOfFile(state);
    if (mapping) CloseHandle(mapping);
    ReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

int RunSentinel() {
    if (IsSafeMode()) return 0;
    EnableDebugPrivilege();
    HardenCurrentProcess();

    HANDLE mapping = OpenSharedState(true);
    SharedState* state = MapSharedState(mapping);
    if (!state) {
        if (mapping) CloseHandle(mapping);
        return 1;
    }
    if (state->allowExit || ReadAllowExitRegistry() != 0) {
        UnmapViewOfFile(state);
        CloseHandle(mapping);
        return 0;
    }

    int slot = RegisterSlot(state);
    if (slot < 0) {
        UnmapViewOfFile(state);
        CloseHandle(mapping);
        return 0;
    }

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    LogMessage(L"sentinel online (slot %d)", slot);
    state->slotBeat[slot] = GetTickCount64();

    while (true) {
        if ((ReadAllowExitRegistry() | state->allowExit) != 0 || IsSafeMode()) break;
        if (state->slotPid[slot] != static_cast<LONG>(GetCurrentProcessId())) {
            slot = RegisterSlot(state);
            if (slot < 0) break;
        }
        state->slotBeat[slot] = GetTickCount64();
        EnsureSentinelCount(state, L"sentinel");
        EnsureGuardService(exePath);
        EnsureTargetService();
        Sleep(kPollIntervalMs);
    }

    if (slot >= 0 && state->slotPid[slot] == static_cast<LONG>(GetCurrentProcessId())) {
        state->slotPid[slot] = 0;
        state->slotBeat[slot] = 0;
    }
    UnmapViewOfFile(state);
    CloseHandle(mapping);
    return 0;
}

int InstallService() {
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!manager) return 1;
    std::wstring binary = std::wstring(L"\"") + exePath + L"\" --service";
    SC_HANDLE service = CreateServiceW(manager, kServiceName, kServiceDisplayName,
                                       SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                       SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                       binary.c_str(), nullptr, nullptr, nullptr,
                                       L"LocalSystem", nullptr);
    if (!service && GetLastError() == ERROR_SERVICE_EXISTS) {
        service = OpenServiceW(manager, kServiceName, SERVICE_ALL_ACCESS);
        if (service) {
            ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_AUTO_START,
                                 SERVICE_NO_CHANGE, binary.c_str(), nullptr, nullptr,
                                 nullptr, nullptr, nullptr, nullptr);
        }
    }
    if (service) {
        SERVICE_DESCRIPTIONW description = {};
        description.lpDescription = const_cast<LPWSTR>(kServiceDescription);
        ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description);
        ConfigureRecovery(service);
        WriteAllowExitRegistry(0);
        StartServiceW(service, 0, nullptr);
        CloseServiceHandle(service);
    }
    CloseServiceHandle(manager);
    LogMessage(L"install complete");
    return service ? 0 : 1;
}

void Disarm() {
    WriteAllowExitRegistry(1);
    HANDLE mapping = OpenSharedState(true);
    SharedState* state = MapSharedState(mapping);
    if (state) {
        state->allowExit = 1;
        KillAllSentinels(state);
        UnmapViewOfFile(state);
    }
    if (mapping) CloseHandle(mapping);
    StopServiceByName(kServiceName);
    LogMessage(L"disarm complete");
}

int UninstallService(bool force) {
    if (!IsSafeMode() && !force) {
        wprintf(L"拒绝卸载：请进入安全模式后重试（或使用 --force）。\n");
        return 2;
    }
    Disarm();
    Sleep(1500);
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager) {
        SC_HANDLE service = OpenServiceW(manager, kServiceName,
                                         SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
        if (service) {
            SERVICE_STATUS status = {};
            ControlService(service, SERVICE_CONTROL_STOP, &status);
            DeleteService(service);
            CloseServiceHandle(service);
        }
        CloseServiceHandle(manager);
    }
    wprintf(L"NDAS 守卫服务已停止并删除。\n");
    return 0;
}

int PrintStatus() {
    HANDLE mapping = OpenSharedState(true);
    SharedState* state = MapSharedState(mapping);
    int alive = state ? CountAliveSlots(state) : 0;
    wprintf(L"AllowExit=%lu  sentinels=%d/%d  safeMode=%d\n",
            ReadAllowExitRegistry(), alive, kGuardCount, IsSafeMode() ? 1 : 0);
    if (state) UnmapViewOfFile(state);
    if (mapping) CloseHandle(mapping);
    return 0;
}

int RunServiceDispatcher() {
    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<LPWSTR>(kServiceName), ServiceMain},
        {nullptr, nullptr},
    };
    if (!StartServiceCtrlDispatcherW(table)) {
        return 1;
    }
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    std::wstring mode = argc > 1 ? argv[1] : L"--sentinel";
    if (mode == L"--service") return RunServiceDispatcher();
    if (mode == L"--sentinel") return RunSentinel();
    if (mode == L"--install") return InstallService();
    if (mode == L"--uninstall") {
        bool force = argc > 2 && std::wstring(argv[2]) == L"--force";
        return UninstallService(force);
    }
    if (mode == L"--disarm") {
        Disarm();
        return 0;
    }
    if (mode == L"--arm") {
        WriteAllowExitRegistry(0);
        SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (manager) {
            SC_HANDLE service = OpenServiceW(manager, kServiceName, SERVICE_START);
            if (service) {
                StartServiceW(service, 0, nullptr);
                CloseServiceHandle(service);
            }
            CloseServiceHandle(manager);
        }
        return 0;
    }
    if (mode == L"--status") return PrintStatus();
    wprintf(L"usage: NdasGuard.exe [--install|--uninstall [--force]|--disarm|--arm|--status|--service|--sentinel]\n");
    return 1;
}
