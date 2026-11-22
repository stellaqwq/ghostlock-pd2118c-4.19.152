#!/usr/bin/env python3
"""Probe an APK the same way KernelSU's kernel/manager/apk_sign.c does.

Reads the APK Signing Block, finds the v2 block (id 0x7109871a), walks
signers -> first signer -> signed data -> digests, then the certificates
sequence, and reports the FIRST certificate's DER length and SHA-256.

Those two numbers are exactly EXPECTED_SIZE / EXPECTED_HASH in the kernel
module, so this script is the source of truth for patch_ksu_expected.py.

usage: python apk_cert_probe.py <apk> [more.apk ...]
"""
import hashlib
import struct
import sys

V2_BLOCK_ID = 0x7109871A
VERITY_PADDING_ID = 0x42726577
EOCD_MAGIC = 0x06054B50
ZIP64_LOCATOR_MAGIC = 0x07064B50
CERT_MAX_LENGTH = 1024


class Bad(Exception):
    pass


def read_exact(f, size):
    buf = f.read(size)
    if len(buf) != size:
        raise Bad("short read")
    return buf


def read_len_prefixed(f, container_end):
    (length,) = struct.unpack("<I", read_exact(f, 4))
    if length > 0x7FFFFFFF or f.tell() + length > container_end:
        raise Bad("bad length prefix")
    return f.tell() + length


def probe(path):
    with open(path, "rb") as f:
        f.seek(0, 2)
        file_size = f.tell()

        # locate EOCD (same backwards scan the kernel does)
        eocd_offset = None
        for i in range(0x10000):
            if i + 24 > file_size:
                raise Bad("no eocd")
            eocd = file_size - i - 22  # comment_size == i  =>  EOCD ends i bytes before EOF
            f.seek(eocd + 20)
            (comment_size,) = struct.unpack("<H", f.read(2))
            if comment_size != i:
                continue
            f.seek(eocd)
            chunk = f.read(22)
            if len(chunk) == 22:
                (magic,) = struct.unpack("<I", chunk[:4])
                if magic == EOCD_MAGIC:
                    eocd_offset = eocd
                    cd_size, cd_offset = struct.unpack("<II", chunk[12:20])
                    break
        if eocd_offset is None:
            raise Bad("no eocd")

        if cd_offset > eocd_offset or cd_size != eocd_offset - cd_offset:
            raise Bad("central directory mismatch")

        # reject zip64 like the kernel
        if eocd_offset >= 20:
            f.seek(eocd_offset - 20)
            (z64,) = struct.unpack("<I", f.read(4))
            if z64 == ZIP64_LOCATOR_MAGIC:
                raise Bad("zip64 apk, kernel rejects it")

        pairs_end = cd_offset - 0x18
        f.seek(pairs_end)
        (size_of_block,) = struct.unpack("<Q", f.read(8))
        magic = read_exact(f, 16)
        if magic != b"APK Sig Block 42":
            raise Bad("no APK signing block")

        head = cd_offset - size_of_block - 8
        f.seek(head)
        (size_at_head,) = struct.unpack("<Q", f.read(8))
        if size_at_head != size_of_block:
            raise Bad("signing block size mismatch")

        pos = head + 8
        v2 = []
        while pos < pairs_end:
            f.seek(pos)
            (pair_len,) = struct.unpack("<Q", read_exact(f, 8))
            pair_end = pos + 8 + pair_len
            (block_id,) = struct.unpack("<I", read_exact(f, 4))
            if block_id == V2_BLOCK_ID:
                v2.append((f.tell(), pair_end))
            elif block_id != VERITY_PADDING_ID:
                raise Bad("unexpected block id 0x%08x" % block_id)
            pos = pair_end

        if len(v2) != 1:
            raise Bad("v2 block count = %d (kernel wants exactly 1)" % len(v2))

        start, pair_end = v2[0]
        f.seek(start)  # rewind: kernel walks the v2 pair from its value start
        f.seek(start, 0)
        # kernel starts *pos at the beginning of the v2 block value
        signers_end = read_len_prefixed(f, pair_end)
        signer_end = read_len_prefixed(f, signers_end)
        signed_data_end = read_len_prefixed(f, signer_end)
        digests_end = read_len_prefixed(f, signed_data_end)

        f.seek(digests_end)
        certificates_end = read_len_prefixed(f, signed_data_end)
        (cert_size,) = struct.unpack("<I", read_exact(f, 4))
        if cert_size > CERT_MAX_LENGTH:
            raise Bad("cert length %d over CERT_MAX_LENGTH" % cert_size)
        if f.tell() + cert_size > certificates_end:
            raise Bad("cert overruns sequence")
        cert = read_exact(f, cert_size)
        return cert_size, hashlib.sha256(cert).hexdigest()


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    rc = 0
    for apk in argv[1:]:
        try:
            size, digest = probe(apk)
            print("%s\n  cert_size = %d\n  sha256    = %s" % (apk, size, digest))
        except Bad as exc:
            print("%s\n  REJECTED: %s" % (apk, exc))
            rc = 1
        except OSError as exc:
            print("%s\n  ERROR: %s" % (apk, exc))
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
