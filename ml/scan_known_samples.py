#!/usr/bin/env python3
"""Scan user folders for files whose SHA-256 is in the NDY-A IOC blocklist."""
import csv
import hashlib
import os

BLOCKLIST = r"C:\Users\S4094\ioc-evidence\malware-egress-blocklist\data\hashes.csv"
ROOTS = [r"E:\下载", r"E:\下载\Compressed"]
MAX_SIZE = 500 * 1024 * 1024
INTERESTING_EXT = {
    ".exe", ".dll", ".msi", ".scr", ".com", ".cpl", ".sys", ".ps1", ".vbs", ".js",
    ".lnk", ".doc", ".docm", ".xls", ".xlsm", ".rar", ".zip", ".7z", ".cab", ".pif",
}


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(4 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def main():
    known = {}
    with open(BLOCKLIST, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            sha = (row.get("sha256") or "").strip().lower()
            if sha:
                known[sha] = (row.get("label") or "").strip()

    checked = 0
    hits = []
    for root in ROOTS:
        for dirpath, dirnames, filenames in os.walk(root):
            depth = dirpath[len(root):].count(os.sep)
            if depth > 1:
                dirnames[:] = []
                continue
            for name in filenames:
                ext = os.path.splitext(name)[1].lower()
                if ext not in INTERESTING_EXT:
                    continue
                path = os.path.join(dirpath, name)
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                if size == 0 or size > MAX_SIZE:
                    continue
                try:
                    digest = sha256_of(path)
                except OSError:
                    continue
                checked += 1
                if digest in known:
                    hits.append((path, digest, known[digest]))

    print(f"checked={checked} hits={len(hits)}")
    for path, digest, label in hits:
        print(f"HIT  {path}\n     {digest}  {label}")


if __name__ == "__main__":
    main()
