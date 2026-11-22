#!/usr/bin/env python3
"""Replace one asset inside an APK and re-sign it with the Android debug key.

The Ghostlock one-tap flow copies `assets/kernelsu.ko` out of its own APK, so a
patched kernel module only takes effect after the APK is rebuilt. Rewriting the
zip invalidates the APK signature, therefore the archive is re-signed.

The kernel module must keep its original byte length, otherwise the app's
hard-coded `length() == 0x420b0` guard rejects it - this script verifies that.

usage:
    python repack_apk_asset.py <in.apk> <out.apk> <asset-path> <replacement>
"""
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

BUILD_TOOLS = Path(os.environ.get("ANDROID_BUILD_TOOLS", r"C:\Android\Sdk\build-tools\37.0.0"))
# Overridable so a release build can sign with the distributor's own key instead of the
# public debug one (its password is common knowledge, so it is not a trust root).
KEYSTORE = Path(os.environ.get("KSU_SIGN_KEYSTORE", str(Path.home() / ".android" / "debug.keystore")))
SIGNER_ALIAS = os.environ.get("KSU_SIGN_ALIAS", "androiddebugkey")
SIGNER_PASS = os.environ.get("KSU_SIGN_STOREPASS", "android")
KEY_PASS = os.environ.get("KSU_SIGN_KEYPASS", SIGNER_PASS)


def repack(src: Path, dst: Path, asset: str, replacement: bytes) -> None:
    zin = zipfile.ZipFile(src)
    old = zin.getinfo(asset)
    if len(replacement) != old.file_size:
        raise SystemExit(
            f"size mismatch: {asset} is {old.file_size} B, replacement is {len(replacement)} B\n"
            "the app hard-codes the asset length, so an in-place patch is mandatory"
        )

    # stale v1 signature files would survive the rewrite; apksigner regenerates them
    drop = {"META-INF/MANIFEST.MF"}
    with zipfile.ZipFile(dst, "w") as zout:
        for info in zin.infolist():
            name = info.filename
            if name in drop or (name.startswith("META-INF/") and name.endswith((".SF", ".RSA", ".DSA", ".EC"))):
                continue
            data = replacement if name == asset else zin.read(name)
            zi = zipfile.ZipInfo(name, date_time=info.date_time)
            zi.compress_type = info.compress_type
            zi.external_attr = info.external_attr
            zi.internal_attr = info.internal_attr
            zi.create_system = info.create_system
            zout.writestr(zi, data, compress_type=info.compress_type)
    zin.close()
    print(f"  repacked {len(replacement)} B into {asset}")


def run(cmd):
    import re
    printable = " ".join(str(c) for c in cmd)
    printable = re.sub(r"pass:\S+", "pass:<redacted>", printable)
    printable = re.sub(r"(?i)(-{1,2}(?:storepass|keypass))\s+\S+", r"\1 <redacted>", printable)
    print("  $ " + printable)
    subprocess.run([str(c) for c in cmd], check=True)


def main(argv):
    if len(argv) != 5:
        print(__doc__)
        return 2
    src, dst = Path(argv[1]).resolve(), Path(argv[2]).resolve()
    asset, repl = argv[3], Path(argv[4]).resolve()
    if not KEYSTORE.exists():
        raise SystemExit(f"missing keystore: {KEYSTORE}")

    raw = dst.with_name(dst.stem + ".unaligned.apk")
    repack(src, raw, asset, repl.read_bytes())

    aligned = dst.with_name(dst.stem + ".aligned.apk")
    run([BUILD_TOOLS / "zipalign.exe", "-p", "-f", "4", raw, aligned])
    run([
        BUILD_TOOLS / "apksigner.bat", "sign",
        "--ks", KEYSTORE,
        "--ks-pass", f"pass:{SIGNER_PASS}",
        "--ks-key-alias", SIGNER_ALIAS,
        "--key-pass", f"pass:{KEY_PASS}",
        "--min-sdk-version", "26",
        "--out", dst, aligned,
    ])
    raw.unlink(missing_ok=True)
    aligned.unlink(missing_ok=True)
    print(f"  signed: {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
