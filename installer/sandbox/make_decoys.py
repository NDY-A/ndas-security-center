"""Generate replacement decoy PE images for Speakeasy.

The upstream package ships two tiny decoy binaries
(winenv/decoys/<arch>/default_exe.exe and default_driver.sys) that Microsoft
Defender flags as Win32:Trojan/Malgnet. Speakeasy only needs a structurally
valid PE image to reserve/map memory for emulated modules, so we replace them
with equivalent minimal images generated here.
"""

import json
import os
import struct
import sys

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
SECTION_RVA = 0x1000
SECTION_RAW_SIZE = 0x200
HEADERS_SIZE = 0x200


def build_pe(arch, subsystem, characteristics):
    pe32_plus = arch == 0x8664
    optional_size = 0xF0 if pe32_plus else 0xE0
    section_data = b"\x00" * SECTION_RAW_SIZE
    size_of_image = SECTION_RVA + SECTION_ALIGNMENT

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack(
        "<4sHHIIIHH",
        b"PE\x00\x00",
        arch,
        1,
        0,
        0,
        0,
        optional_size,
        characteristics,
    )

    if pe32_plus:
        optional = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x20B,              # Magic
            14,                 # MajorLinkerVersion
            0,                  # MinorLinkerVersion
            0,                  # SizeOfCode
            0,                  # SizeOfInitializedData
            0,                  # SizeOfUninitializedData
            0,                  # AddressOfEntryPoint
            SECTION_RVA,        # BaseOfCode
            0x140000000,        # ImageBase
            SECTION_ALIGNMENT,  # SectionAlignment
            FILE_ALIGNMENT,     # FileAlignment
            6, 0,               # OS version
            0, 0,               # Image version
            6, 0,               # Subsystem version
            0,                  # Win32VersionValue
            size_of_image,      # SizeOfImage
            HEADERS_SIZE,       # SizeOfHeaders
            0,                  # CheckSum
            subsystem,          # Subsystem
            0,                  # DllCharacteristics
            0x100000,           # SizeOfStackReserve
            0x1000,             # SizeOfStackCommit
            0x100000,           # SizeOfHeapReserve
            0x1000,             # SizeOfHeapCommit
            0,                  # LoaderFlags
            16,                 # NumberOfRvaAndSizes
        )
    else:
        optional = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x10B,              # Magic
            14,                 # MajorLinkerVersion
            0,                  # MinorLinkerVersion
            0,                  # SizeOfCode
            0,                  # SizeOfInitializedData
            0,                  # SizeOfUninitializedData
            0,                  # AddressOfEntryPoint
            SECTION_RVA,        # BaseOfCode
            0,                  # BaseOfData
            0x400000,           # ImageBase
            SECTION_ALIGNMENT,  # SectionAlignment
            FILE_ALIGNMENT,     # FileAlignment
            6, 0,               # OS version
            0, 0,               # Image version
            6, 0,               # Subsystem version
            0,                  # Win32VersionValue
            size_of_image,      # SizeOfImage
            HEADERS_SIZE,       # SizeOfHeaders
            0,                  # CheckSum
            subsystem,          # Subsystem
            0,                  # DllCharacteristics
            0x100000,           # SizeOfStackReserve
            0x1000,             # SizeOfStackCommit
            0x100000,           # SizeOfHeapReserve
            0x1000,             # SizeOfHeapCommit
            0,                  # LoaderFlags
            16,                 # NumberOfRvaAndSizes
        )

    optional += b"\x00" * (optional_size - len(optional))

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x10,               # VirtualSize
        SECTION_RVA,        # VirtualAddress
        SECTION_RAW_SIZE,   # SizeOfRawData
        HEADERS_SIZE,       # PointerToRawData
        0, 0,               # relocations / line numbers
        0, 0,               # counts
        0x60000020,         # CODE | EXECUTE | READ
    )

    headers = bytes(dos) + coff + optional + section
    headers += b"\x00" * (HEADERS_SIZE - len(headers))
    return headers + section_data


def write_decoy(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)


def update_manifest(directory, exe_size, driver_size):
    manifest = {
        "file_list": [
            {"module_name": "default_exe", "file_name": "default_exe.exe", "size": exe_size},
            {"module_name": "default_driver", "file_name": "default_driver.sys", "size": driver_size},
        ]
    }
    path = os.path.join(directory, "manifest.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=4)


def main():
    if len(sys.argv) != 2:
        print("usage: make_decoys.py <site-packages>")
        return 2

    decoys_root = os.path.join(sys.argv[1], "speakeasy", "winenv", "decoys")
    if not os.path.isdir(decoys_root):
        print("decoys directory not found: " + decoys_root)
        return 2

    targets = {
        "x86": (0x14C, 3, 0x0102),
        "amd64": (0x8664, 3, 0x0022),
    }
    for arch, (machine, subsystem, characteristics) in targets.items():
        directory = os.path.join(decoys_root, arch)
        exe = build_pe(machine, subsystem, characteristics)
        driver_subsystem = 1
        driver = build_pe(machine, driver_subsystem, characteristics & ~0x0100)
        write_decoy(os.path.join(directory, "default_exe.exe"), exe)
        write_decoy(os.path.join(directory, "default_driver.sys"), driver)
        update_manifest(directory, len(exe), len(driver))
        print(f"{arch}: exe={len(exe)} driver={len(driver)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
