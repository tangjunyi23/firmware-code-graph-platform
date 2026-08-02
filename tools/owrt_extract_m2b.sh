#!/bin/bash
# M2b: extract OpenWrt 12.09 SDKs and locate their libc.a files.
set -x
cd /home/tankuku/toolchains/owrt
mkdir -p adm5120 omap4
tar -xjf sdk_adm5120.tar.bz2 -C adm5120 --strip-components=1
tar -xjf sdk_omap4.tar.bz2 -C omap4 --strip-components=1
echo EXTRACT_OK
find adm5120 omap4 -name 'libc.a' 2>/dev/null
echo LIBC_LISTED
