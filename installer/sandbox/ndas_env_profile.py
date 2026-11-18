"""NDAS sandbox environment profile.

Speakeasy's stock default.json exposes an obvious emulator persona
(hostname "speakeasy_host", user "speakeasy_user", Windows 7 6.1.7601).
Samples that fingerprint their environment refuse to run their payload
under such values. This module overlays a consistent "real workstation"
profile onto the loaded config before the emulator is constructed.

Lists (drives/processes/registry seeds) replace the stock decoys; dicts
are merged recursively; scalars are overwritten.
"""

import copy

PROFILE_NAME = "win10-cn-office"

_OS_VER = {"name": "windows", "major": 10, "minor": 0, "build": 19045}

_ENV = {
    "comspec": "C:\\Windows\\system32\\cmd.exe",
    "systemroot": "C:\\Windows",
    "windir": "C:\\Windows",
    "temp": "C:\\Users\\Administrator\\AppData\\Local\\Temp",
    "tmp": "C:\\Users\\Administrator\\AppData\\Local\\Temp",
    "userprofile": "C:\\Users\\Administrator",
    "systemdrive": "C:",
    "allusersprofile": "C:\\ProgramData",
    "programdata": "C:\\ProgramData",
    "programfiles": "C:\\Program Files",
    "programfiles(x86)": "C:\\Program Files (x86)",
    "appdata": "C:\\Users\\Administrator\\AppData\\Roaming",
    "localappdata": "C:\\Users\\Administrator\\AppData\\Local",
    "computername": "DESKTOP-7K2M9Q3",
    "username": "Administrator",
    "userdomain": "WORKGROUP",
}

_DRIVES = [
    {
        "root_path": "C:\\",
        "drive_type": "DRIVE_FIXED",
        "volume_guid_path": "\\\\?\\Volume{9f1c2d3e-4a5b-11ef-a123-0c9d92d4e5f6}\\",
    },
    {
        "root_path": "D:\\",
        "drive_type": "DRIVE_FIXED",
        "volume_guid_path": "\\\\?\\Volume{9f1c2d3f-4a5b-11ef-a124-0c9d92d4e5f7}\\",
    },
]

_PROCESS_SPECS = [
    ("smss.exe", 0x7FF7A1C20000, 0x3EC),
    ("csrss.exe", 0x7FF7A1B10000, 0x21C),
    ("wininit.exe", 0x7FF7A1A30000, 0x2A8),
    ("services.exe", 0x7FF7A1920000, 0x33C),
    ("lsass.exe", 0x7FF7A1800000, 0x30C),
    ("winlogon.exe", 0x7FF7A1700000, 0x2D4),
    ("svchost.exe", 0x7FF7A1600000, 0x3A0),
    ("svchost.exe", 0x7FF7A1500000, 0x4BC),
    ("svchost.exe", 0x7FF7A1400000, 0x528),
    ("dwm.exe", 0x7FF7A1300000, 0x5F8),
    ("taskhostw.exe", 0x7FF7A1200000, 0x6A4),
    ("RuntimeBroker.exe", 0x7FF7A1100000, 0x7D0),
    ("explorer.exe", 0x7FF7A1000000, 0x8B8),
    ("ctfmon.exe", 0x7FF7A0F00000, 0x9C0),
    ("conhost.exe", 0x7FF7A0E00000, 0xA2C),
]

# Host fingerprint expected by profiles and mirrored by the API hooks.
ADAPTER = {
    "name": "Ethernet",
    "description": "Intel(R) Ethernet Connection (12) I219-V",
    "mac_address": "3C-7C-3F-AB-12-34",
    "type": "ethernet",
    "ip_address": "192.168.1.23",
    "subnet_mask": "255.255.255.0",
    "dhcp_enabled": True,
}

DNS_SEEDS = {
    "microsoft.com": "20.112.250.133",
    "www.microsoft.com": "20.112.250.133",
    "windowsupdate.com": "20.70.246.20",
    "time.windows.com": "20.198.162.1",
    "baidu.com": "110.242.68.66",
    "www.baidu.com": "110.242.68.66",
    "qq.com": "113.108.81.189",
    "connectivitycheck.gstatic.com": "142.250.191.174",
}

_REGISTRY_KEYS = [
    {
        "path": "HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS",
        "values": [
            {"name": "SystemManufacturer", "type": "REG_SZ", "data": "ASUSTeK COMPUTER INC."},
            {"name": "SystemProductName", "type": "REG_SZ", "data": "PRIME B460M-A"},
            {"name": "SystemVersion", "type": "REG_SZ", "data": "System Version"},
            {"name": "SystemSerialNumber", "type": "REG_SZ", "data": "System Serial Number"},
            {"name": "BIOSVendor", "type": "REG_SZ", "data": "American Megatrends Inc."},
            {"name": "BIOSVersion", "type": "REG_SZ", "data": "1605"},
            {"name": "BIOSReleaseDate", "type": "REG_SZ", "data": "06/18/2021"},
            {"name": "BaseBoardManufacturer", "type": "REG_SZ", "data": "ASUSTeK COMPUTER INC."},
            {"name": "BaseBoardProduct", "type": "REG_SZ", "data": "PRIME B460M-A"},
            {"name": "BaseBoardVersion", "type": "REG_SZ", "data": "Rev 1.xx"},
        ],
    },
    {
        "path": "HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        "values": [
            {"name": "ProcessorNameString", "type": "REG_SZ", "data": "Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz"},
            {"name": "VendorIdentifier", "type": "REG_SZ", "data": "GenuineIntel"},
            {"name": "Identifier", "type": "REG_SZ", "data": "Intel64 Family 6 Model 165 Stepping 3"},
            {"name": "~MHz", "type": "REG_DWORD", "data": "2904"},
        ],
    },
    {
        "path": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "values": [
            {"name": "ProductName", "type": "REG_SZ", "data": "Windows 10 Pro"},
            {"name": "EditionID", "type": "REG_SZ", "data": "Professional"},
            {"name": "DisplayVersion", "type": "REG_SZ", "data": "22H2"},
            {"name": "CurrentVersion", "type": "REG_SZ", "data": "6.3"},
            {"name": "CurrentBuild", "type": "REG_SZ", "data": "19045"},
            {"name": "CurrentBuildNumber", "type": "REG_SZ", "data": "19045"},
            {"name": "UBR", "type": "REG_DWORD", "data": "3803"},
            {"name": "RegisteredOwner", "type": "REG_SZ", "data": "Administrator"},
            {"name": "InstallDate", "type": "REG_DWORD", "data": "1697241600"},
        ],
    },
    {
        "path": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
        "values": [
            {"name": "TimeZoneKeyName", "type": "REG_SZ", "data": "China Standard Time"},
            {"name": "Bias", "type": "REG_DWORD", "data": "-480"},
            {"name": "StandardName", "type": "REG_SZ", "data": "China Standard Time"},
        ],
    },
    {
        "path": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
        "values": [
            {"name": "ComputerName", "type": "REG_SZ", "data": "DESKTOP-7K2M9Q3"},
            {"name": "ActiveComputerName", "type": "REG_SZ", "data": "DESKTOP-7K2M9Q3"},
        ],
    },
    {
        "path": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
        "values": [
            {"name": "Path", "type": "REG_SZ", "data": "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem"},
            {"name": "TEMP", "type": "REG_SZ", "data": "C:\\Users\\Administrator\\AppData\\Local\\Temp"},
            {"name": "TMP", "type": "REG_SZ", "data": "C:\\Users\\Administrator\\AppData\\Local\\Temp"},
            {"name": "USERNAME", "type": "REG_SZ", "data": "Administrator"},
        ],
    },
]


def build_profile(sample_name=""):
    system32 = "C:\\Windows\\System32\\"
    processes = []
    for name, base_addr, pid in _PROCESS_SPECS:
        path = "C:\\Windows\\explorer.exe" if name == "explorer.exe" else system32 + name
        processes.append(
            {
                "name": name,
                "base_addr": hex(base_addr),
                "path": path,
                "pid": pid,
            }
        )

    profile = {
        "os_ver": copy.deepcopy(_OS_VER),
        "hostname": "DESKTOP-7K2M9Q3",
        "domain": "WORKGROUP",
        "user": {
            "name": "Administrator",
            "is_admin": True,
            "sid": "S-1-5-21-3623811015-3361044348-30300820-500",
        },
        "current_dir": "C:\\Users\\Administrator\\AppData\\Local\\Temp",
        "command_line": sample_name or "setup.exe",
        "env": copy.deepcopy(_ENV),
        "drives": copy.deepcopy(_DRIVES),
        "network": {
            "adapters": [copy.deepcopy(ADAPTER)],
            "dns": {"names": copy.deepcopy(DNS_SEEDS)},
        },
        "processes": processes,
        "registry": {"keys": copy.deepcopy(_REGISTRY_KEYS)},
        # Real GetProcAddress returns NULL for missing exports; the emulator's
        # fake function pointers make runtime-probing samples crash when they
        # call them. NULL lets the sample take its own fallback path.
        "modules": {"functions_always_exist": False},
    }
    return profile


def _deep_merge(base, override):
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = copy.deepcopy(value)
    return base


def apply_profile(config, sample_name="", profile_name=PROFILE_NAME):
    """Merge the NDAS profile into a loaded Speakeasy config (in place)."""
    _deep_merge(config, build_profile(sample_name))
    return config
