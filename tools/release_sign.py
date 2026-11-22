#!/usr/bin/env python3
"""Re-sign the manager and the Ghostlock package with the distributor's own release key.

Why this exists: the shipped builds are signed with the Android *debug* keystore, whose
password is public. Anyone can sign a package with the same applicationId and the system
would treat it as a legitimate update, and the kernel module (whose certificate fingerprint
is patched into `EXPECTED_HASH`) would crown it as the manager. Distributing such a build
gives away the trust root.

What this script does, in order:

1. creates (or reuses) an RSA-4096 release keystore;
2. exports its certificate and reads the DER length + SHA-256 that the kernel compares;
3. patches a *stock* kernelsu.ko with those values (`patch_ksu_expected.py`);
4. replaces the stock module embedded inside `assets/pd2055_exploit` with the patched one,
   locating it by the stock fingerprint instead of a hard-coded offset;
5. repacks and signs the Ghostlock APK with the release key;
6. zipaligns and signs the manager APK with the release key;
7. verifies the result the same way the kernel does (`apk_cert_probe.py`).

Nothing is written outside --outdir.

usage:
  python tools/release_sign.py --storepass SECRET [--keypass SECRET] \
      --manager KernelSU_themestore_clear_32680.apk \
      --ghostlock Ghostlock_PD2118_KSU_v7_ksu744.apk \
      --outdir release
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD_TOOLS = Path(os.environ.get("ANDROID_BUILD_TOOLS", r"C:\Android\Sdk\build-tools\37.0.0"))

STOCK_HASH = "c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6"
KO_SIZE = 270512
# In the stock exploit the fingerprint sits 0x14b90 bytes into the embedded module.
HASH_OFFSET_IN_KO = 0x14B90


def run(cmd, **kw):
    import re
    printable = " ".join(str(c) for c in cmd)
    # Never echo credentials into the terminal transcript.
    printable = re.sub(r"(?i)(-{1,2}(?:storepass|keypass|pass))\s+\S+", r"\1 <redacted>", printable)
    printable = re.sub(r"(?i)pass:[^\s]+", "pass:<redacted>", printable)
    print("  $ " + printable)
    return subprocess.run([str(c) for c in cmd], check=True, **kw)


def find_keytool() -> Path:
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / ("keytool.exe" if os.name == "nt" else "keytool")
        if candidate.exists():
            return candidate
    found = shutil.which("keytool")
    if found:
        return Path(found)
    raise SystemExit("keytool not found; set JAVA_HOME or add a JDK to PATH")


def ensure_keystore(path: Path, alias: str, storepass: str, keypass: str, dname: str) -> None:
    if path.exists():
        print(f"[=] reusing keystore {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    # RSA-2048 on purpose: the kernel copies the certificate into a 1024-byte stack buffer
    # (CERT_MAX_LENGTH in apk_sign.c), and an RSA-4096 certificate is ~1.4 KB, which the module
    # rejects outright. 2048 lands around 900 B, same ballpark as the debug key's 744 B.
    print(f"[+] creating RSA-2048 keystore {path}")
    run([
        find_keytool(), "-genkeypair",
        "-keystore", path,
        "-alias", alias,
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-storepass", storepass,
        "-keypass", keypass,
        "-dname", dname,
    ])


def export_cert(keystore: Path, alias: str, storepass: str, der: Path) -> None:
    run([
        find_keytool(), "-exportcert",
        "-keystore", keystore,
        "-alias", alias,
        "-storepass", storepass,
        "-file", der,
    ])


def patch_module(stock_ko: Path, der: Path, out_ko: Path) -> str:
    import hashlib
    data = der.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    print(f"[i] certificate DER = {len(data)} B, SHA-256 = {digest}")
    if len(data) > 1024:
        raise SystemExit(
            f"certificate is {len(data)} B but the kernel only accepts up to 1024 B; "
            "use an RSA-2048 key and a shorter distinguished name"
        )
    run([
        sys.executable, str(ROOT / "tools" / "patch_ksu_expected.py"),
        stock_ko, digest,
        "--size", len(data),
        "--old-size", "827",
        "--old", STOCK_HASH,
    ], cwd=ROOT)
    # patch_ksu_expected writes in place and keeps a .orig backup next to the file
    patched = stock_ko
    if out_ko.resolve() != patched.resolve():
        out_ko.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(patched, out_ko)
    return digest


def embed_module(exploit: bytes, patched_ko: bytes) -> bytes:
    needle = STOCK_HASH.encode()
    idx = exploit.find(needle)
    if idx < 0:
        raise SystemExit(
            "the exploit does not contain the stock fingerprint any more; it may already be "
            "patched, in which case pick the pristine package as --ghostlock"
        )
    ko_start = idx - HASH_OFFSET_IN_KO
    if ko_start < 0:
        raise SystemExit("unexpected layout: fingerprint too close to the file start")
    if len(patched_ko) != KO_SIZE:
        raise SystemExit(f"patched module is {len(patched_ko)} B, expected {KO_SIZE} B")
    out = bytearray(exploit)
    out[ko_start:ko_start + KO_SIZE] = patched_ko
    print(f"[i] embedded module at 0x{ko_start:x}, replaced in place")
    return bytes(out)


def sign_apk(unsigned: Path, out: Path, keystore: Path, alias: str, storepass: str, keypass: str,
             min_sdk: int) -> None:
    aligned = out.with_name(out.stem + ".aligned.apk")
    run([BUILD_TOOLS / "zipalign.exe", "-p", "-f", "4", unsigned, aligned])
    out.parent.mkdir(parents=True, exist_ok=True)
    run([
        BUILD_TOOLS / "apksigner.bat", "sign",
        "--ks", keystore,
        "--ks-pass", f"pass:{storepass}",
        "--ks-key-alias", alias,
        "--key-pass", f"pass:{keypass}",
        "--min-sdk-version", str(min_sdk),
        # KernelSU walks the signing block and rejects any pair that is neither v2 nor the
        # verity padding block, so a v3 block makes the manager fail verification and lose root.
        "--v1-signing-enabled", "false",
        "--v2-signing-enabled", "true",
        "--v3-signing-enabled", "false",
        "--out", out, aligned,
    ])
    aligned.unlink(missing_ok=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--keystore", type=Path, default=None, help="default: <outdir>/release.jks")
    ap.add_argument("--alias", default="ksuport")
    ap.add_argument("--storepass", required=True)
    ap.add_argument("--keypass", default=None, help="defaults to --storepass")
    ap.add_argument("--dname", default="CN=KernelSU Port, O=Personal, C=CN")
    ap.add_argument("--manager", type=Path, default=None)
    ap.add_argument("--ghostlock", type=Path, default=None)
    ap.add_argument("--stock-ko", type=Path, default=None)
    ap.add_argument("--outdir", type=Path, default=None)
    args = ap.parse_args(argv)

    root = args.root.resolve()
    outdir = (args.outdir or root / "release").resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    keystore = (args.keystore or outdir / "release.jks").resolve()
    keypass = args.keypass or args.storepass

    manager = (args.manager or root / "KernelSU_themestore_clear_32680.apk").resolve()
    ghostlock = (args.ghostlock or root / "Ghostlock_PD2118_KSU_v7_ksu744.apk").resolve()
    stock_ko = (args.stock_ko or root / "pd2055_asset" / "kernelsu.ko").resolve()
    for path in (manager, ghostlock, stock_ko):
        if not path.exists():
            raise SystemExit(f"missing input: {path}")

    ensure_keystore(keystore, args.alias, args.storepass, keypass, args.dname)

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        der = tmpdir / "cert.der"
        export_cert(keystore, args.alias, args.storepass, der)

        work_ko = tmpdir / "kernelsu.ko"
        shutil.copy2(stock_ko, work_ko)
        digest = patch_module(work_ko, der, work_ko)

        print("[1/3] rebuilding the Ghostlock package")
        with zipfile.ZipFile(ghostlock) as z:
            exploit = z.read("assets/pd2055_exploit")
        patched_exploit = embed_module(exploit, work_ko.read_bytes())
        staged_exploit = tmpdir / "pd2055_exploit"
        staged_exploit.write_bytes(patched_exploit)

        ghost_out = outdir / (ghostlock.stem.replace("_ksu744", "") + "_release.apk")
        env = dict(os.environ,
                   KSU_SIGN_KEYSTORE=str(keystore),
                   KSU_SIGN_ALIAS=args.alias,
                   KSU_SIGN_STOREPASS=args.storepass,
                   KSU_SIGN_KEYPASS=keypass)
        run([
            sys.executable, str(root / "tools" / "repack_apk_asset.py"),
            ghostlock, ghost_out, "assets/pd2055_exploit", staged_exploit,
        ], cwd=root, env=env)

        print("[2/3] re-signing the manager")
        manager_out = outdir / (manager.stem.replace("_clear", "") + "_release.apk")
        sign_apk(manager, manager_out, keystore, args.alias, args.storepass, keypass, min_sdk=31)

        print("[3/3] verifying")
        probe = subprocess.run(
            [sys.executable, str(root / "tools" / "apk_cert_probe.py"), str(manager_out)],
            cwd=str(root),
        )
        if probe.returncode != 0:
            raise SystemExit(
                "the kernel would reject this manager: it must carry exactly one v2 signing "
                "block and no v3 block (see the apksigner flags above)"
            )
        with zipfile.ZipFile(ghost_out) as z:
            blob = z.read("assets/pd2055_exploit")
        import hashlib
        idx = blob.find(digest.encode())
        start = idx - HASH_OFFSET_IN_KO
        embedded = blob[start:start + KO_SIZE]
        print(f"  ghostlock embedded module md5 = {hashlib.md5(embedded).hexdigest()}")
        print(f"  expected (patched)     md5 = {hashlib.md5(work_ko.read_bytes()).hexdigest()}")
        if digest.encode() not in blob:
            raise SystemExit("verification failed: release fingerprint not found in the package")

    print()
    print(f"release keystore : {keystore}")
    print(f"certificate SHA  : {digest}")
    print(f"manager          : {manager_out}")
    print(f"ghostlock        : {ghost_out}")
    print()
    print("Distribute these two files plus this SHA-256 value. Users of the debug-signed build")
    print("must uninstall the old manager first: a different signing key cannot be installed over it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
