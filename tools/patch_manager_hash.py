#!/usr/bin/env python3
"""Patch the expected manager-certificate SHA-256 inside a KernelSU .ko.

The kernel module stores the manager signing certificate digest as 64 lowercase
hex characters in .rodata. Re-signing the manager APK changes that digest, so the
module must be patched before koreloc/insmod. The replacement is length-preserving.
"""
import argparse
import re
import shutil
import sys
from pathlib import Path

DEFAULT_OLD = "c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6"


def norm(value: str) -> str:
    value = value.strip().lower().replace(":", "").replace(" ", "")
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SystemExit(f"not a 64-char hex SHA-256: {value!r}")
    return value


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ko", type=Path)
    ap.add_argument("new_hash", help="new manager cert SHA-256 (hex, colons allowed)")
    ap.add_argument("--old", default=DEFAULT_OLD, help="current hash to replace")
    ap.add_argument("--all", action="store_true", help="replace every occurrence")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    old = norm(args.old)
    new = norm(args.new_hash)
    data = bytearray(args.ko.read_bytes())
    offsets = [m.start() for m in re.finditer(re.escape(old.encode()), data)]

    if not offsets:
        print(f"old hash not found in {args.ko}", file=sys.stderr)
        return 1
    if len(offsets) > 1 and not args.all:
        print("multiple occurrences (use --all): " + ", ".join(hex(o) for o in offsets), file=sys.stderr)
        return 1

    print(f"{args.ko}: {len(offsets)} occurrence(s)")
    for off in offsets:
        print(f"  {hex(off)}: {old} -> {new}")
        data[off:off + 64] = new.encode()

    if args.dry_run:
        return 0

    backup = args.ko.with_suffix(args.ko.suffix + ".orig")
    if not backup.exists():
        shutil.copy2(args.ko, backup)
        print(f"backup: {backup}")
    args.ko.write_bytes(data)
    print("patched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
