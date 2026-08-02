#!/usr/bin/env bash
# M2b: configure + build uClibc-ng from source with the cross toolchain,
# using an ISA level that matches the firmware samples (busybox-mips is
# built for mips1, see readelf Flags; the prebuilt Bootlin libc.a is mips32
# and its FLIRT patterns do NOT match the sample).
#
#   ./build_uclibc.sh mips|arm
#
# Expects uClibc-ng source at $UCLIBC_SRC (default ~/uClibc-ng-1.0.50,
# fetched from https://downloads.uclibc-ng.org/releases/1.0.50/).
# Output: built objects under $UCLIBC_SRC/libc/**/(*.o), consumed by
# build_sig.sh <arch> src.
set -euo pipefail

ARCH="${1:?usage: build_uclibc.sh mips|arm}"
TC_ROOT="${TC_ROOT:-/home/tankuku/toolchains}"
SRC="${UCLIBC_SRC:-/home/tankuku/uClibc-ng-1.0.50}"

case "$ARCH" in
  mips)
    TC="$TC_ROOT/mips32--uclibc--stable-2024.05-1"
    KARCH=mips
    ;;
  arm)
    TC="$TC_ROOT/armv7-eabihf--uclibc--stable-2024.05-1"
    KARCH=arm
    ;;
  *) echo "unknown arch: $ARCH" >&2; exit 2 ;;
esac

GCC="$(find "$TC/bin" -name '*-gcc' | head -1)"
CROSS="${GCC%-gcc}-"
LIBC_A="$(find "$TC" -name libc.a -path '*sysroot*' | head -1)"
KHDRS="$(cd "$(dirname "$LIBC_A")/../include" && pwd)"

echo "== src:   $SRC"
echo "== cross: $CROSS"
echo "== khdrs: $KHDRS"

cd "$SRC"
make ARCH="$KARCH" CROSS_COMPILE="$CROSS" defconfig

# point the build at the toolchain sysroot kernel headers
sed -i "s|^KERNEL_HEADERS=.*|KERNEL_HEADERS=\"$KHDRS\"|" .config

if [ "$ARCH" = mips ]; then
  # match busybox-mips: ELF flags say mips1 (Bootlin default is mips32).
  # uClibc-ng 1.0.50 has no CONFIG_MIPS_ISA_* selector; force via extra CFLAGS.
  sed -i 's|^UCLIBC_EXTRA_CFLAGS=.*|UCLIBC_EXTRA_CFLAGS="-march=mips1 -mfp32 -mnan=legacy"|' .config
fi
if [ "$ARCH" = arm ]; then
  # match busybox-armv7l: armv7, ARM mode (not thumb)
  sed -i 's|^COMPILE_IN_THUMB_MODE=y|# COMPILE_IN_THUMB_MODE is not set|' .config
fi

make ARCH="$KARCH" CROSS_COMPILE="$CROSS" olddefconfig < /dev/null
make ARCH="$KARCH" CROSS_COMPILE="$CROSS" -j"$(nproc)"
echo "== BUILD_OK $ARCH"
