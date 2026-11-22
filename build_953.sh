#!/bin/sh
# PD2118 / V2118A (iQOO Neo5 活力版) GhostLock build, kernel 4.19.152-perf+.
#
# Toolchain: zig 0.14.1, target aarch64-linux-musl, fully static.
#   export ZIG=/path/to/zig          # or put zig on PATH
#   ./build_953.sh
#
# The embedded su daemon is a prebuilt PIE (build/embed/su_daemon_aarch64_pie),
# rebuilt from src/su_daemon.c with:
#   $ZIG c++ -target aarch64-linux-musl -O2 -pie -fPIC \
#       src/su_daemon.c -o build/embed/su_daemon_aarch64_pie
set -e
cd "$(dirname "$0")"

ZIG=${ZIG:-zig}
TGT=aarch64-linux-musl
INC="-Isrc -Isrc/targets/vivo-pd2118-9.5.3 \
-DTARGET_CONFIG_H=\"targets/vivo-pd2118-9.5.3/target.h\" \
-DKERNELSNITCH_GROWTH_MULT=${GROWTH:-3}"

SRCS="runner.c src/main.c src/slide.c src/pipe.c src/fops.c src/root.c \
src/util.c src/schedtest.c src/perftask.c src/preload.c src/su_blob.S src/wallpaper_blob.S"

mkdir -p build/embed

# .incbin does not add a dependency edge in zig's cache, and touching the .S
# file is not enough (the cache keys on content): rewrite it with a build id so
# the blob is always re-read.
cat > src/su_blob.S <<EOF
.section .rodata
.balign 16
.global embedded_su_start
.type embedded_su_start, %object
embedded_su_start:
.incbin "build/embed/su_daemon_aarch64_pie"
.global embedded_su_end
.type embedded_su_end, %object
embedded_su_end:
.byte 0
/* blob build id: \$(date +%s) */
EOF

if [ "${ONLY_PROBE:-0}" != "1" ]; then
echo "[1/2] ghostlock (static exploit)"
"$ZIG" cc -target $TGT -O2 -static -fno-stack-protector $INC $SRCS \
  -o build/ghostlock_pd2118 -lpthread
fi

echo "[2/2] ksprobe (futex timing probe)"
"$ZIG" cc -target $TGT -O2 -static -fno-stack-protector -D__ARM $INC \
  src/ksprobe.c -o build/ksprobe -lpthread

ls -l build/ghostlock_pd2118 build/ksprobe 2>/dev/null || true
