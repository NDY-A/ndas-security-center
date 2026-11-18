"""Speakeasy anti-evasion hooks for the NDAS sandbox.

Speakeasy 1.5.11 leaves several environment APIs missing or obviously fake
(GetAdaptersAddresses/NtQueryInformationProcess/GetTimeZoneInformation are
unimplemented, GetNativeSystemInfo writes nothing, GetSystemMetrics always
returns 1 so SM_REMOTESESSION claims a remote desktop, QueryPerformanceCounter
never advances, and GetProcAddress resolves "wine_get_version"). Samples use
exactly these probes to decide whether they are being analyzed.

install(emulator) registers hooks that keep the emulated machine consistent
with ndas_env_profile. Hook callbacks receive (emu, imp_api, orig, argv) and
their return value becomes the API result. Exceptions inside a hook would
abort the emulation run, so every callback is fully guarded.
"""

import struct

WINE_EXPORTS = {
    "wine_get_version",
    "wine_get_unix_file_name",
    "wine_get_build_id",
    "wine_get_host_version",
    "wine_get_dos_file_name",
}

# SM_* indices queried by anti-sandbox checks.
_SYSTEM_METRICS = {
    0: 1920,      # SM_CXSCREEN
    1: 1080,      # SM_CYSCREEN
    76: 0,        # SM_XVIRTUALSCREEN
    77: 0,        # SM_YVIRTUALSCREEN
    78: 1920,     # SM_CXVIRTUALSCREEN
    79: 1080,     # SM_CYVIRTUALSCREEN
    80: 1,        # SM_CMONITORS
    0x1000: 0,    # SM_REMOTESESSION
}

# 32-bit SYSTEM_INFO: arch/reserved, page, min/max addr, mask, cpus,
# processor type, granularity, level, revision.
_SYSTEM_INFO_X86 = (
    struct.pack("<HH", 0, 0)
    + struct.pack("<I", 0x1000)
    + struct.pack("<I", 0x10000)
    + struct.pack("<I", 0x7FFEFFFF)
    + struct.pack("<I", 0xFF)
    + struct.pack("<I", 8)
    + struct.pack("<I", 0x24A)
    + struct.pack("<I", 0x10000)
    + struct.pack("<HH", 6, 0x3C03)
)

_MEMORY_STATUS_EX = struct.pack(
    "<IIQQQQQQQ",
    64, 47,
    8589934592,    # ullTotalPhys 8 GB
    4509715660,    # ullAvailPhys ~4.2 GB
    10737418240,   # ullTotalPageFile
    6442450944,    # ullAvailPageFile
    0x7FFE0000,    # ullTotalVirtual
    1879048192,    # ullAvailVirtual
    0,
)

_MEMORY_STATUS_X86 = struct.pack(
    "<IIIIIIII",
    32, 47,
    0x80000000,    # dwTotalPhys (truncated for 32-bit callers)
    0x50000000,
    0xC0000000,
    0x60000000,
    0x7FFE0000,
    0x70000000,
)

_STATUS_SUCCESS = 0
_STATUS_PORT_NOT_SET = 0xC0000353
_STATUS_INVALID_INFO_CLASS = 0xC0000003
_ERROR_BUFFER_OVERFLOW = 111
_ERROR_NO_DATA = 232

# One SYSTEM_LOGICAL_PROCESSOR_INFORMATION entry describing an 8-core
# hyperthreaded processor; Delphi RTL requires this to finish startup.
_LOGICAL_PROCESSOR_INFO = struct.pack(
    "<IIIIIIII",
    0xFF,   # ProcessorMask
    0,      # Relationship: RelationProcessorCore
    1,      # ProcessorCore.Flags: hyperthreaded
    0, 0, 0, 0, 0,
)


def _safe(orig, argv, fallback=0):
    try:
        if orig is not None:
            return orig(argv)
    except Exception:
        pass
    return fallback


def _hook_get_proc_address(emu, imp_api, orig, argv):
    try:
        if len(argv) >= 2 and argv[1]:
            name = emu.read_mem_string(argv[1], 1)
            if name:
                base = name.split("\x00", 1)[0].strip().lower()
                if base in WINE_EXPORTS:
                    return 0
    except Exception:
        pass
    return _safe(orig, argv, 0)


def _hook_get_system_metrics(emu, imp_api, orig, argv):
    try:
        index = argv[0] if argv else -1
        if isinstance(index, int) and index in _SYSTEM_METRICS:
            return _SYSTEM_METRICS[index]
    except Exception:
        pass
    return _safe(orig, argv, 1)


def _hook_get_native_system_info(emu, imp_api, orig, argv):
    try:
        ptr = argv[0] if argv else 0
        if ptr:
            emu.mem_write(ptr, _SYSTEM_INFO_X86)
    except Exception:
        return _safe(orig, argv, 0)
    return 0


def _hook_global_memory_status_ex(emu, imp_api, orig, argv):
    try:
        ptr = argv[0] if argv else 0
        if ptr:
            emu.mem_write(ptr, _MEMORY_STATUS_EX)
            return 1
    except Exception:
        pass
    return _safe(orig, argv, 0)


def _hook_global_memory_status(emu, imp_api, orig, argv):
    try:
        ptr = argv[0] if argv else 0
        if ptr:
            emu.mem_write(ptr, _MEMORY_STATUS_X86)
            return 0
    except Exception:
        pass
    return _safe(orig, argv, 0)


def _hook_nt_query_information_process(emu, imp_api, orig, argv):
    try:
        if len(argv) >= 5:
            info_class = argv[1]
            info_ptr = argv[2]
            length = argv[3]
            ret_len_ptr = argv[4]
            if info_class == 0x7:  # ProcessDebugPort
                if info_ptr and length >= 4:
                    emu.mem_write(info_ptr, struct.pack("<I", 0))
                if ret_len_ptr:
                    emu.mem_write(ret_len_ptr, struct.pack("<I", 4))
                return _STATUS_SUCCESS
            if info_class == 0x1F:  # ProcessDebugFlags (1 = not being debugged)
                if info_ptr and length >= 4:
                    emu.mem_write(info_ptr, struct.pack("<I", 1))
                if ret_len_ptr:
                    emu.mem_write(ret_len_ptr, struct.pack("<I", 4))
                return _STATUS_SUCCESS
            if info_class == 0x1E:  # ProcessDebugObjectHandle
                if info_ptr and length >= 4:
                    emu.mem_write(info_ptr, struct.pack("<I", 0))
                if ret_len_ptr:
                    emu.mem_write(ret_len_ptr, struct.pack("<I", 0))
                return _STATUS_PORT_NOT_SET
    except Exception:
        pass
    return _STATUS_INVALID_INFO_CLASS


def _hook_get_time_zone_information(emu, imp_api, orig, argv):
    try:
        ptr = argv[0] if argv else 0
        if ptr:
            data = bytearray(172)  # TIME_ZONE_INFORMATION
            struct.pack_into("<i", data, 0, -480)  # Bias: UTC+8
            standard = "China Standard Time".encode("utf-16-le")[:62] + b"\x00\x00"
            data[4:4 + len(standard)] = standard
            daylight = "China Daylight Time".encode("utf-16-le")[:62] + b"\x00\x00"
            data[88:88 + len(daylight)] = daylight
            emu.mem_write(ptr, bytes(data))
            return 1  # TIME_ZONE_ID_STANDARD
    except Exception:
        pass
    return _safe(orig, argv, 0)


def _smbios_struct(type_, handle, formatted, strings):
    length = 4 + len(formatted)
    out = struct.pack("<BBH", type_, length, handle) + formatted
    for item in strings:
        out += item + b"\x00"
    return out + b"\x00"


def _build_smbios_blob():
    type0 = _smbios_struct(
        0, 0,
        b"\x01\x02"
        + struct.pack("<HB", 0xE000, 0xFF)
        + struct.pack("<Q", 0x09)
        + b"\x0F\x0D\x05\x0D\xFF\xFF",
        [b"American Megatrends Inc.", b"1605", b"06/18/2021"],
    )
    uuid = bytes.fromhex("4c4d415038424b343133303334313233")
    type1 = _smbios_struct(
        1, 1,
        b"\x01\x02\x03\x04" + uuid + b"\x06" + b"\x05\x06",
        [b"ASUSTeK COMPUTER INC.", b"PRIME B460M-A", b"System Version",
         b"System Serial Number", b"Default string", b"Default string"],
    )
    type2 = _smbios_struct(
        2, 2,
        b"\x01\x02\x03\x04\x05\x09\x06" + struct.pack("<H", 3) + b"\x0A\x00",
        [b"ASUSTeK COMPUTER INC.", b"PRIME B460M-A", b"Rev 1.xx",
         b"Base Board Serial Number", b"Default string", b"Default string"],
    )
    table = type0 + type1 + type2 + b"\x7F\x04\xFF\x00" + b"\x00\x00"
    return b"\x00\x03\x02\x01" + struct.pack("<I", len(table)) + table


_SMBIOS_BLOB = _build_smbios_blob()


def _hook_get_system_firmware_table(emu, imp_api, orig, argv):
    try:
        signature = argv[0] if argv else 0
        if isinstance(signature, int) and signature == 0x52534D42:  # 'RSMB'
            buffer_ptr = argv[2] if len(argv) > 2 else 0
            buffer_size = argv[3] if len(argv) > 3 else 0
            blob = _SMBIOS_BLOB
            if not buffer_ptr or buffer_size < len(blob):
                return len(blob)
            emu.mem_write(buffer_ptr, blob)
            return len(blob)
    except Exception:
        pass
    return _safe(orig, argv, 0)


def _sockaddr_in(ip, port=0):
    return struct.pack("<HH4s8x", 2, port, bytes(int(part) for part in ip.split(".")))


def _build_adapter_addresses_32(base):
    """32-bit IP_ADAPTER_ADDRESSES_LH with one Ethernet unicast address and a DNS server."""
    offsets = {
        "ansi": 400,
        "desc": 420,
        "friendly": 540,
        "unicast": 600,
        "unicast_addr": 640,
        "dns": 660,
        "dns_addr": 680,
    }
    total = 700
    buf = bytearray(total)

    name = b"Ethernet\x00"
    buf[offsets["ansi"]:offsets["ansi"] + len(name)] = name
    description = "Intel(R) Ethernet Connection (12) I219-V".encode("utf-16-le") + b"\x00\x00"
    buf[offsets["desc"]:offsets["desc"] + len(description)] = description
    friendly = "Ethernet".encode("utf-16-le") + b"\x00\x00"
    buf[offsets["friendly"]:offsets["friendly"] + len(friendly)] = friendly

    buf[offsets["unicast_addr"]:offsets["unicast_addr"] + 16] = _sockaddr_in("192.168.1.23")
    u = offsets["unicast"]
    struct.pack_into("<I", buf, u, 0)                       # Next
    struct.pack_into("<I", buf, u + 4, base + offsets["unicast_addr"])
    struct.pack_into("<i", buf, u + 8, 16)                  # iSockaddrLength
    struct.pack_into("<I", buf, u + 12, 3)                  # PrefixOrigin (Dhcp)
    struct.pack_into("<I", buf, u + 16, 3)                  # SuffixOrigin (Dhcp)
    struct.pack_into("<I", buf, u + 20, 2)                  # DadState (Preferred)
    struct.pack_into("<I", buf, u + 24, 0xFFFFFFFF)         # ValidLifetime
    struct.pack_into("<I", buf, u + 28, 0xFFFFFFFF)         # PreferredLifetime
    struct.pack_into("<I", buf, u + 32, 0xFFFFFFFF)         # LeaseLifetime
    buf[u + 36] = 24                                        # OnLinkPrefixLength

    buf[offsets["dns_addr"]:offsets["dns_addr"] + 16] = _sockaddr_in("192.168.1.1", 53)
    d = offsets["dns"]
    struct.pack_into("<I", buf, d, 0)                       # Next
    struct.pack_into("<I", buf, d + 4, base + offsets["dns_addr"])
    struct.pack_into("<i", buf, d + 8, 16)

    o = 0
    struct.pack_into("<I", buf, o + 0, 370)                 # Length
    struct.pack_into("<I", buf, o + 4, 12)                  # IfIndex
    struct.pack_into("<I", buf, o + 8, 0)                   # Next
    struct.pack_into("<I", buf, o + 12, base + offsets["ansi"])
    struct.pack_into("<I", buf, o + 16, base + offsets["unicast"])
    struct.pack_into("<I", buf, o + 20, 0)                  # FirstAnycastAddress
    struct.pack_into("<I", buf, o + 24, 0)                  # FirstMulticastAddress
    struct.pack_into("<I", buf, o + 28, base + offsets["dns"])
    struct.pack_into("<I", buf, o + 32, 0)                  # DnsSuffix
    struct.pack_into("<I", buf, o + 36, base + offsets["desc"])
    struct.pack_into("<I", buf, o + 40, base + offsets["friendly"])
    buf[o + 44:o + 52] = bytes([0x3C, 0x7C, 0x3F, 0xAB, 0x12, 0x34, 0, 0])
    struct.pack_into("<I", buf, o + 52, 6)                  # PhysicalAddressLength
    struct.pack_into("<I", buf, o + 56, 0x1C4)              # Flags
    struct.pack_into("<I", buf, o + 60, 1500)               # Mtu
    struct.pack_into("<I", buf, o + 64, 6)                  # IfType: ethernet
    struct.pack_into("<I", buf, o + 68, 1)                  # OperStatus: up
    struct.pack_into("<I", buf, o + 72, 0)                  # Ipv6IfIndex
    struct.pack_into("<Q", buf, o + 144, 1000000000)        # TransmitLinkSpeed
    struct.pack_into("<Q", buf, o + 152, 1000000000)        # ReceiveLinkSpeed
    struct.pack_into("<I", buf, o + 168, 25)                # Ipv4Metric
    struct.pack_into("<I", buf, o + 172, 10)                # Ipv6Metric
    struct.pack_into("<I", buf, o + 192, 1)                 # CompartmentId
    struct.pack_into("<I", buf, o + 212, 1)                 # ConnectionType: dedicated
    return bytes(buf)


_ADAPTER_BLOB_SIZE = 700


def _hook_get_adapters_addresses(emu, imp_api, orig, argv):
    try:
        if len(argv) >= 5:
            buffer_ptr = argv[3]
            size_ptr = argv[4]
            if not buffer_ptr:
                if size_ptr:
                    emu.mem_write(size_ptr, struct.pack("<I", _ADAPTER_BLOB_SIZE))
                return _ERROR_BUFFER_OVERFLOW
            size = 0
            if size_ptr:
                size = int.from_bytes(emu.mem_read(size_ptr, 4), "little")
            if size < _ADAPTER_BLOB_SIZE:
                if size_ptr:
                    emu.mem_write(size_ptr, struct.pack("<I", _ADAPTER_BLOB_SIZE))
                return _ERROR_BUFFER_OVERFLOW
            emu.mem_write(buffer_ptr, _build_adapter_addresses_32(buffer_ptr))
            if size_ptr:
                emu.mem_write(size_ptr, struct.pack("<I", _ADAPTER_BLOB_SIZE))
            return 0
    except Exception:
        pass
    return _ERROR_NO_DATA


def _hook_get_logical_processor_information(emu, imp_api, orig, argv):
    try:
        buffer_ptr = argv[0] if argv else 0
        size_ptr = argv[1] if len(argv) > 1 else 0
        needed = len(_LOGICAL_PROCESSOR_INFO)
        size = 0
        if size_ptr:
            size = int.from_bytes(emu.mem_read(size_ptr, 4), "little")
        if buffer_ptr and size >= needed:
            emu.mem_write(buffer_ptr, _LOGICAL_PROCESSOR_INFO)
            if size_ptr:
                emu.mem_write(size_ptr, struct.pack("<I", needed))
            return 1
        if size_ptr:
            emu.mem_write(size_ptr, struct.pack("<I", needed))
        return 0
    except Exception:
        pass
    return _safe(orig, argv, 0)


def _hook_get_volume_information(emu, imp_api, orig, argv):
    rv = _safe(orig, argv, 1)
    try:
        if rv and len(argv) >= 8:
            serial_ptr = argv[3]
            max_component_ptr = argv[4]
            flags_ptr = argv[5]
            fs_name_ptr = argv[6]
            fs_name_size = argv[7]
            if serial_ptr:
                emu.mem_write(serial_ptr, struct.pack("<I", 0x3A7C5E12))
            if max_component_ptr:
                emu.mem_write(max_component_ptr, struct.pack("<I", 255))
            if flags_ptr:
                emu.mem_write(flags_ptr, struct.pack("<I", 0x3E7FF))
            if fs_name_ptr and fs_name_size >= 5:
                emu.mem_write(fs_name_ptr, "NTFS".encode("utf-16-le") + b"\x00\x00")
    except Exception:
        pass
    return rv


# Stubs for statically imported APIs Speakeasy 1.5.11 does not implement.
# argc must match the real signature (x86 stdcall slot count, 64-bit
# parameters take two slots) or the guest stack desynchronizes.
_STATIC_STUBS = [
    ("kernel32", "GetCPInfoExW", 3, 0),
    ("kernel32", "RtlUnwind", 4, 0),
    ("kernel32", "CompareStringW", 6, 2),      # CSTR_EQUAL
    ("kernel32", "FormatMessageW", 7, 0),
    ("kernel32", "SwitchToThread", 0, 1),
    ("kernel32", "VirtualQueryEx", 4, 0),
    ("kernel32", "SetEndOfFile", 1, 0),
    ("kernel32", "EnumCalendarInfoW", 4, 0),
    ("kernel32", "RemoveDirectoryW", 1, 0),
    ("comctl32", "InitCommonControls", 0, 0),
    ("user32", "CallWindowProcW", 5, 0),
    ("user32", "ExitWindowsEx", 2, 1),
    ("oleaut32", "VariantClear", 1, 0),
    ("oleaut32", "VariantCopy", 2, 0),
    ("oleaut32", "VariantChangeType", 4, 0),
    ("oleaut32", "SafeArrayCreate", 3, 0),
    ("oleaut32", "SafeArrayPutElement", 3, 0),
    ("oleaut32", "SafeArrayGetElement", 3, 0),
    ("oleaut32", "SafeArrayAccessData", 2, 0),
    ("oleaut32", "SafeArrayUnaccessData", 1, 0),
    ("oleaut32", "SafeArrayPtrOfIndex", 3, 0),
    ("oleaut32", "SafeArrayGetUBound", 3, 0),
    ("oleaut32", "SafeArrayGetLBound", 3, 0),
    ("oleaut32", "SysReAllocStringLen", 3, 0),
    ("advapi32", "ConvertStringSecurityDescriptorToSecurityDescriptorW", 4, 0),
    ("advapi32", "ConvertSidToStringSidW", 2, 0),
]


def _make_const_stub(return_value):
    def stub(emu, imp_api, orig, argv):
        return return_value
    return stub


def _hook_get_system_windows_directory(emu, imp_api, orig, argv):
    try:
        buffer_ptr = argv[0] if argv else 0
        size = argv[1] if len(argv) > 1 else 0
        path = "C:\\Windows".encode("utf-16-le") + b"\x00\x00"
        if buffer_ptr and size >= 9:
            emu.mem_write(buffer_ptr, path)
            return len("C:\\Windows")
    except Exception:
        pass
    return 0


def _hook_variant_init(emu, imp_api, orig, argv):
    try:
        ptr = argv[0] if argv else 0
        if ptr:
            emu.mem_write(ptr, b"\x00" * 16)
    except Exception:
        pass
    return 0


def _hook_get_disk_free_space(emu, imp_api, orig, argv):
    try:
        if len(argv) >= 5:
            for offset, value in ((1, 8), (2, 512), (3, 0x100000), (4, 0x2000000)):
                ptr = argv[offset]
                if ptr:
                    emu.mem_write(ptr, struct.pack("<I", value))
        return 1
    except Exception:
        return 1


def install(emulator):
    """Register all anti-evasion hooks. Returns (applied, skipped) name lists."""
    applied = []
    skipped = []
    state = {"qpc": 0x5FD27D571F, "cursor": 0}

    def hook_query_performance_counter(emu, imp_api, orig, argv):
        try:
            state["qpc"] += 3000
            ptr = argv[0] if argv else 0
            if ptr:
                emu.mem_write(ptr, struct.pack("<Q", state["qpc"]))
            return 1
        except Exception:
            return 1

    def hook_get_cursor_pos(emu, imp_api, orig, argv):
        try:
            state["cursor"] += 1
            ptr = argv[0] if argv else 0
            if ptr:
                x = 620 + (state["cursor"] % 5)
                y = 380 + ((state["cursor"] // 5) % 3)
                emu.mem_write(ptr, struct.pack("<ii", x, y))
            return 1
        except Exception:
            return 1

    def add(module, api, callback, argc=0):
        try:
            emulator.add_api_hook(callback, module=module, api_name=api, argc=argc)
            applied.append("%s.%s" % (module, api))
        except Exception as exc:
            skipped.append("%s.%s: %s" % (module, api, exc))

    add("kernel32", "GetProcAddress", _hook_get_proc_address)
    add("kernel32", "GetSystemMetrics", _hook_get_system_metrics)
    add("kernel32", "GetNativeSystemInfo", _hook_get_native_system_info, argc=1)
    add("kernel32", "GlobalMemoryStatusEx", _hook_global_memory_status_ex, argc=1)
    add("kernel32", "GlobalMemoryStatus", _hook_global_memory_status, argc=1)
    add("ntdll", "NtQueryInformationProcess", _hook_nt_query_information_process, argc=5)
    add("kernel32", "GetTimeZoneInformation", _hook_get_time_zone_information, argc=1)
    add("kernel32", "QueryPerformanceCounter", hook_query_performance_counter)
    add("user32", "GetCursorPos", hook_get_cursor_pos)
    add("kernel32", "GetSystemFirmwareTable", _hook_get_system_firmware_table)
    add("iphlpapi", "GetAdaptersAddresses", _hook_get_adapters_addresses, argc=5)
    add("kernel32", "GetVolumeInformationW", _hook_get_volume_information)
    add("kernel32", "GetLogicalProcessorInformation", _hook_get_logical_processor_information, argc=2)

    for module, api, argc, return_value in _STATIC_STUBS:
        add(module, api, _make_const_stub(return_value), argc=argc)
    add("kernel32", "GetSystemWindowsDirectoryW", _hook_get_system_windows_directory, argc=2)
    add("oleaut32", "VariantInit", _hook_variant_init, argc=1)
    add("kernel32", "GetDiskFreeSpaceW", _hook_get_disk_free_space, argc=5)

    return applied, skipped
