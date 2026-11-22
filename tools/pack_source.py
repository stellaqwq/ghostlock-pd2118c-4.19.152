#!/usr/bin/env python3
"""Bundle the sources needed to rebuild the distributed APKs (GPL compliance).

Included: the patched KernelSU manager tree, the ghostlock exploit sources, the helper
tools, the handover docs and the three upstream licences. Excluded: VCS metadata, build
outputs, IDE state, machine-specific `local.properties` and the proxy settings that were
only meaningful on the build machine.

usage: python tools/pack_source.py [--out ZIP]
"""
import argparse
import os
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCLUDE_DIRS = {".git", "build", ".gradle", ".idea", "node_modules", "__pycache__",
                ".cxx", "intermediates", ".kotlin", "tmp"}
EXCLUDE_FILES = {"local.properties", ".DS_Store", "Thumbs.db"}

# (source path, prefix inside the archive)
TREES = [
    ("ksu_port/KernelSU", "KernelSU"),
    ("ghostlock", "ghostlock"),
    ("tools", "tools"),
]
EXTRA_FILES = [
    ("ksu_port/HANDOFF.md", "docs/HANDOFF.md"),
    ("ksu_port/KernelSU/LICENSE", "LICENSES/KernelSU-GPL-3.0.txt"),
    ("ksu_port/SukiSU-Nova/LICENSE", "LICENSES/SukiSU-Nova-GPL-3.0.txt"),
    ("ksu_port/SukiSU-Nova/kernel/LICENSE", "LICENSES/kernel-GPL-2.0.txt"),
]


def iter_tree(base: Path, prefix: str):
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for name in filenames:
            if name in EXCLUDE_FILES:
                continue
            full = Path(dirpath) / name
            rel = full.relative_to(base)
            yield full, f"{prefix}/{rel.as_posix()}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT / "KernelSU_ThemePort_Source.zip")
    args = ap.parse_args(argv)
    out = args.out.resolve()

    readme = ROOT / "tools" / "SOURCE-README.md"
    if not readme.exists():
        raise SystemExit(f"missing {readme}")

    count = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.write(readme, "README.md")
        count += 1

        for rel, prefix in TREES:
            base = (ROOT / rel).resolve()
            if not base.exists():
                print(f"[!] skip missing tree {rel}")
                continue
            for full, arc in iter_tree(base, prefix):
                if full.suffix == ".apk" or full.stat().st_size > 32 * 1024 * 1024:
                    continue
                if full.name == "gradle.properties":
                    text = full.read_text(encoding="utf-8", errors="replace")
                    cleaned = "\n".join(
                        "" if line.startswith("systemProp.http") or line.startswith("systemProp.https")
                        else line
                        for line in text.splitlines()
                    )
                    z.writestr(arc, cleaned)
                else:
                    z.write(full, arc)
                count += 1
            print(f"[+] {rel} -> {prefix}/")

        for rel, arc in EXTRA_FILES:
            full = (ROOT / rel).resolve()
            if full.exists():
                z.write(full, arc)
                count += 1
            else:
                print(f"[!] missing {rel}")

    size = out.stat().st_size
    print(f"\n{count} files -> {out} ({size / 1048576:.1f} MiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
