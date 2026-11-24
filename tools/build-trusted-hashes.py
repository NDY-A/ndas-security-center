"""Build the binary trusted-hash index consumed by Aegis.Core.Signatures.TrustedHashIndex.

Input: one lower/upper-case hex SHA-256 per line (whitespace ignored, duplicates dropped).
Output: "NTH1" | u32 version=1 | u32 count | count x 32-byte digests, strictly ascending.

The canonical input for the seed build is the FRIENDLYFILE_SHA256 set extracted from
Microsoft Defender's mpasbase.vdm (see the wd-vdm lab), i.e. Microsoft's known-good
file catalog -- NOT a malware list.
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="text file with one SHA-256 hex digest per line")
    parser.add_argument(
        "--output",
        default=str(Path(__file__).resolve().parent.parent / "data" / "seed" / "trusted" / "trusted-sha256.bin"),
        help="output .bin path (default: data/seed/trusted/trusted-sha256.bin)",
    )
    args = parser.parse_args()

    digests = set()
    bad = 0
    with open(args.input, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            value = line.strip().lower()
            if not value:
                continue
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                bad += 1
                if bad <= 10:
                    print(f"skip invalid line {number}: {value[:80]!r}", file=sys.stderr)
                continue
            digests.add(bytes.fromhex(value))

    if not digests:
        print("no valid digests found", file=sys.stderr)
        return 1

    ordered = sorted(digests)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as handle:
        handle.write(b"NTH1")
        handle.write(struct.pack("<I", 1))
        handle.write(struct.pack("<I", len(ordered)))
        for digest in ordered:
            handle.write(digest)

    data = output.read_bytes()
    print(f"wrote {len(ordered)} digests ({len(data)} bytes) to {output}")
    print(f"sha256 {hashlib.sha256(data).hexdigest()}")
    if bad:
        print(f"skipped {bad} invalid lines", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
