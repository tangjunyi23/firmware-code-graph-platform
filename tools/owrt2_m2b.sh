#!/bin/bash
# M2b: fetch rb1xx (BE adm5120) SDK, extract, and build the armv7 sig from
# the already-extracted omap4 SDK.
set -x
cd /home/tankuku/toolchains/owrt
curl -sSL --retry 2 -o sdk_rb1xx.tar.bz2 https://archive.openwrt.org/attitude_adjustment/12.09/adm5120/rb1xx/OpenWrt-SDK-adm5120-for-linux-i486-gcc-4.6-linaro_uClibc-0.9.33.2.tar.bz2
mkdir -p rb1xx
tar -xjf sdk_rb1xx.tar.bz2 -C rb1xx --strip-components=1
echo RB1XX_OK
find rb1xx -name 'libc.a' | head -5
echo FIND_OK
# arm sig from omap4 (armv7-a, uClibc 0.9.33.2, gcc 4.6-linaro)
cd /home/tankuku/firmware-graph/fwgraph/libc-sigs
LIBC_A=/home/tankuku/toolchains/owrt/omap4/staging_dir/toolchain-arm_v7-a_gcc-4.6-linaro_uClibc-0.9.33.2_eabi/lib/libc.a \
SIG_NAME=fwgraph_owrt1209_uclibc_arm \
SIG_TITLE='OpenWrt 12.09 uClibc 0.9.33.2 armv7' \
./build_sig.sh arm custom
echo ARM_SIG_OK
