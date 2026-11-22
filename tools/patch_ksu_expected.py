#!/usr/bin/env python3
"""Rewrite the expected manager-APK certificate fingerprint/size inside a KernelSU .ko.

The kernel module verifies the manager APK's v2 signing block against two build-time
constants: the certificate length (`KSU_EXPECTED_SIZE`) and its SHA-256
(`KSU_EXPECTED_HASH`). Upstream defaults to the official release certificate, so a
manager re-signed with a different key is never crowned and loses superuser access.

This script rewrites both in place:
  * the 64-hex fingerprint stored in .rodata
  * the AArch64 immediates that carry the certificate length
    (`cmp w?, #oldsize`, `mov x2, #oldsize`, `cmp x0, #oldsize`, ...)

Usage:
    python patch_ksu_expected.py kernsu.ko <new_sha256_hex> --size <new_size> [--old-size 827]

Both old and new sizes are byte lengths of the DER signing certificate, which
`apksigner verify --print-certs` does not print; read it from the v2 block or compute
16 + sum of the SEQUENCE lengths (744 for the standard Android debug key).
"""
import argparse
import re
import shutil
import struct
from pathlib import Path

DEFAULT_OLD_HASH = "c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6"


def norm_hash(value: str) -> str:
    value = value.strip().lower().replace(":", "").replace(" ", "")
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SystemExit(f"not a 64-char hex SHA-256: {value!r}")
    return value


def patch_cmp_imm(word: int, imm12: int) -> int:
    """ADDS/SUBS (immediate): imm12 occupies bits [21:10]."""
    return (word & ~(0xFFF << 10)) | ((imm12 & 0xFFF) << 10)


def patch_mov_imm(word: int, imm16: int) -> int:
    """MOVZ/MOVK/MOVN: imm16 occupies bits [20:5]."""
    return (word & ~(0xFFFF << 5)) | ((imm16 & 0xFFFF) << 5)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ko", type=Path)
    ap.add_argument("new_hash", help="SHA-256 of the new signing certificate (hex)")
    ap.add_argument("--size", type=int, required=True, help="new certificate DER length")
    ap.add_argument("--old-size", type=int, default=827, help="current expected size")
    ap.add_argument("--old", default=DEFAULT_OLD_HASH, help="current expected hash")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    old_hash = norm_hash(args.old)
    new_hash = norm_hash(args.new_hash)
    if not (0 < args.size < 0xFFFF) or not (0 < args.old_size < 0xFFFF):
        raise SystemExit("sizes must fit in 16 bits")

    data = bytearray(args.ko.read_bytes())
    report = []

    # --- certificate fingerprint -------------------------------------------------
    needle = old_hash.encode()
    hash_hits = [m.start() for m in re.finditer(re.escape(needle), data)]
    if not hash_hits:
        print(f"[!] old fingerprint not found: {old_hash}", file=sys.stderr)
        return 1
    for off in hash_hits:
        data[off:off + 64] = new_hash.encode()
    report.append(f"hash {old_hash[:8]}… -> {new_hash[:8]}… ({len(hash_hits)} site(s))")

    # --- certificate length immediates -------------------------------------------
    old_imm = args.old_size
    new_imm = args.size
    patched = {}
    for i in range(len(data) // 4):
        off = i * 4
        word = struct.unpack_from("<I", data, off)[0]
        # CMP/SUBS Wd, Wn, #imm  (0x71xxxxxx) and CMP Xd, Xn, #imm (0xF1xxxxxx)
        if (word & 0x7F000000) in (0x71000000, 0x51000000, 0xF1000000, 0xF9000000):
            if ((word >> 10) & 0xFFF) == old_imm:
                struct.pack_into("<I", data, off, patch_cmp_imm(word, new_imm))
                patched.setdefault("cmp", []).append(off)
        # MOVZ Xd/Wd, #imm  (0xD28xxxxx) / MOVN (0x928xxxxx) / MOVK (0xF28xxxxx)
        elif (word & 0x7F800000) in (0x52800000, 0x12800000, 0x72800000):
            if ((word >> 5) & 0xFFFF) == old_imm:
                struct.pack_into("<I", data, off, patch_mov_imm(word, new_imm))
                patched.setdefault("mov", []).append(off)
    if not patched:
        print("[!] no size immediates found", file=sys.stderr)
        return 1
    for kind, offs in patched.items():
        report.append(f"{kind} #{old_imm} -> #{new_imm}: " + ", ".join(hex(o) for o in offs))

    for line in report:
        print("  " + line)
    if args.dry_run:
        print("dry run, nothing written")
        return 0

    backup = args.ko.with_suffix(args.ko.suffix + ".orig")
    if not backup.exists():
        shutil.copy2(args.ko, backup)
        print(f"  backup: {backup}")
    args.ko.write_bytes(data)
    print(f"  patched: {args.ko}")
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main())
