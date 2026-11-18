"""Fail the build when data/seed files drift from data/seed/manifest.json."""

import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEED = ROOT / "data" / "seed"
MANIFEST = SEED / "manifest.json"


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    errors = []
    for name, meta in manifest.get("files", {}).items():
        path = SEED / name.replace("/", os.sep)
        if not path.exists():
            errors.append(f"missing {name}")
            continue
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != meta.get("sha256") or len(data) != meta.get("bytes"):
            errors.append(
                f"{name}: sha256={digest} bytes={len(data)} "
                f"(manifest {meta.get('sha256')} / {meta.get('bytes')})")
    if errors:
        print("SEED MANIFEST MISMATCH:")
        for error in errors:
            print(" -", error)
        return 1

    counts = manifest.get("counts", {})
    print(f"seed ok: {manifest.get('version')} specialPaths={counts.get('specialPaths')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
