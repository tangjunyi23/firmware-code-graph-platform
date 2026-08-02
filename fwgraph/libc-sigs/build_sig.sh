#!/usr/bin/env bash
# M2b: build a demo FLIRT signature from a cross toolchain's static libc.
#
#   ./build_sig.sh mips|arm [toolchain|src|custom]
#
# Modes:
#   toolchain (default)  lift the ~60 function objects of funcs.txt out of
#                        the Bootlin toolchain's prebuilt libc.a. Fast, but
#                        only matches binaries built with this exact ISA
#                        level (Bootlin mips32 = mips32; busybox-mips = mips1
#                        -> zero hits on that sample).
#   src                  take the objects from a uClibc-ng source tree built
#                        by build_uclibc.sh with a sample-matching ISA level
#                        ($UCLIBC_SRC, default ~/uClibc-ng-1.0.50).
#   custom               lift objects from any prebuilt libc.a (env LIBC_A);
#                        SIG_NAME/SIG_TITLE/TEST_GCC are optional overrides.
#                        Used for era-matched sigs: the 2013 busybox samples
#                        need uClibc 0.9.33.x + gcc 4.x patterns, e.g. from
#                        OpenWrt 12.09 SDKs (see docs/m2b-notes.md).
#
# Flow: re-archive the objects, run FLAIR pelf -> sigmake -> .sig, then
# install the .sig into IDA's sig/<proc>/ directory. A static test binary
# linked against the toolchain libc is also produced (mechanism proof).
#
# Runs on the Ubuntu VM. Toolchains come from Bootlin (uClibc-ng 1.0.50,
# gcc 13.3.0):
#   ~/toolchains/mips32--uclibc--stable-2024.05-1/
#   ~/toolchains/armv7-eabihf--uclibc--stable-2024.05-1/
set -euo pipefail

ARCH="${1:?usage: build_sig.sh mips|arm [toolchain|src|custom]}"
MODE="${2:-toolchain}"
HERE="$(cd "$(dirname "$0")" && pwd)"
IDA_DIR="${IDA_DIR:-/home/tankuku/ida-pro-9.1}"
TC_ROOT="${TC_ROOT:-/home/tankuku/toolchains}"
FLAIR="$IDA_DIR/tools/flair"
OUT="${OUT_DIR:-$HERE/out}"

case "$ARCH" in
  mips) PROC=mips ;;
  arm)  PROC=arm ;;
  *) echo "unknown arch: $ARCH" >&2; exit 2 ;;
esac

if [ "$MODE" = custom ]; then
  # Generic mode: lift objects from any prebuilt libc.a (env LIBC_A).
  # Used for era-matched sigs, e.g. OpenWrt 12.09 SDKs (uClibc 0.9.33.2,
  # gcc 4.6): the 2013 busybox samples match those, not modern uClibc-ng.
  # SIG_NAME / SIG_TITLE / TEST_GCC are optional env overrides.
  LIBC_A="${LIBC_A:?custom mode needs LIBC_A=/path/to/libc.a}"
  GCC="${TEST_GCC:-}"
  TC="$LIBC_A"
  LIBGCC_A=""
else
  case "$ARCH" in
    mips) TC="$TC_ROOT/mips32--uclibc--stable-2024.05-1" ;;
    arm)  TC="$TC_ROOT/armv7-eabihf--uclibc--stable-2024.05-1" ;;
  esac
  GCC="$(find "$TC/bin" -name '*-gcc' | head -1)"
  LIBC_A="$(find "$TC" -name libc.a -path '*lib*' | head -1)"
  LIBGCC_A="$("$GCC" -print-libgcc-file-name)"
fi

AR="${GCC:+${GCC%-gcc}-ar}"
AR="${AR:-ar}"
READELF="${GCC:+${GCC%-gcc}-readelf}"
READELF="${READELF:-readelf}"

echo "== toolchain: $TC"
echo "== gcc:       $GCC"
echo "== libc.a:    $LIBC_A"
echo "== libgcc.a:  $LIBGCC_A"

WORK="$OUT/$ARCH/work_$MODE"
mkdir -p "$WORK"
cd "$WORK"
rm -f ./*.o ./*.a ./*.pat ./*.sig ./*.exc 2>/dev/null || true

# 1. lift the chosen function objects
kept=0
missing=0
if [ "$MODE" = src ]; then
  SRC="${UCLIBC_SRC:-/home/tankuku/uClibc-ng-1.0.50}"
  echo "== uclibc src: $SRC"
  while read -r fn; do
    case "$fn" in ''|\#*) continue;; esac
    fn="$(echo "$fn" | tr -d '[:space:]')"
    obj="$(find "$SRC/libc" \( -name "$fn.os" -o -name "$fn.o" \) | head -1)"
    if [ -n "$obj" ]; then
      cp "$obj" "./$fn.os"
      kept=$((kept+1))
    else
      echo "   (miss) $fn.os not in $SRC/libc"
      missing=$((missing+1))
    fi
  done < "$HERE/funcs.txt"
else
  while read -r fn; do
    case "$fn" in ''|\#*) continue;; esac
    fn="$(echo "$fn" | tr -d '[:space:]')"
    # uClibc-ng archives its objects as <fn>.os; glibc uses <fn>.o
    if ar x "$LIBC_A" "$fn.os" 2>/dev/null && [ -f "$fn.os" ]; then
      kept=$((kept+1))
    elif ar x "$LIBC_A" "$fn.o" 2>/dev/null && [ -f "$fn.o" ]; then
      kept=$((kept+1))
    else
      echo "   (miss) $fn.os/$fn.o not in libc.a"
      missing=$((missing+1))
    fi
  done < "$HERE/funcs.txt"
fi
echo "== objects kept: $kept, missing: $missing"

LIBNAME="${SIG_NAME:-fwgraph_uclibc_${ARCH}}"
rm -f "$LIBNAME.a"
shopt -s nullglob
objs=( ./*.o ./*.os )
shopt -u nullglob
ar rcs "$LIBNAME.a" "${objs[@]}"
ar t "$LIBNAME.a" | wc -l | xargs echo "== objects in demo archive:"

# 2. pelf -> .pat
"$FLAIR/pelf" "$LIBNAME.a" "$LIBNAME.pat"
grep -c '^;' < /dev/null > /dev/null 2>&1 || true
wc -l "$LIBNAME.pat" | awk '{print "== pattern lines: "$1}'

# 3. sigmake -> .sig (auto-resolve collisions: select first of each group)
SIGTITLE="${SIG_TITLE:-uClibc demo sig ($MODE $ARCH)}"
if ! "$FLAIR/sigmake" -n"$SIGTITLE" "$LIBNAME.pat" "$LIBNAME.sig"; then
  EXC=""
  for cand in "$LIBNAME.exc" out.exc; do
    [ -f "$cand" ] && EXC="$cand" && break
  done
  if [ -n "$EXC" ]; then
    echo "== resolving collisions in $EXC (select first per group, drop guard)"
    # .exc rules (per its own header):
    #   - lines starting ";---------" are a guard: delete so sigmake reads it
    #   - '+' at line start selects a module; unmarked modules are excluded
    #   - groups are separated by blank lines
    awk '
      /^;---------/ { next }
      /^[[:space:]]*$/ { first=0; print; next }
      /^;/ { print; next }
      {
        if (!first) { print "+" $0; first=1 }
        else print
      }
    ' "$EXC" > "$EXC.fixed" && mv "$EXC.fixed" "$EXC"
    "$FLAIR/sigmake" -n"$SIGTITLE" "$LIBNAME.pat" "$LIBNAME.sig"
  fi
fi
ls -la "$LIBNAME.sig"

# 4. install into IDA sig dir
mkdir -p "$IDA_DIR/sig/$PROC"
cp "$LIBNAME.sig" "$IDA_DIR/sig/$PROC/"
echo "== installed: $IDA_DIR/sig/$PROC/$LIBNAME.sig"

# 5. static test binary (mechanism proof target); skipped in custom mode
#    when no cross gcc is at hand (the SDK's gcc needs its full staging env)
if [ -n "$GCC" ]; then
  "$GCC" -O2 -static -o "$OUT/$ARCH/test_$ARCH" "$HERE/test_program.c"
  "$READELF" -h "$OUT/$ARCH/test_$ARCH" | grep -E 'Class|Machine|Flags' || true
  echo "== test binary: $OUT/$ARCH/test_$ARCH"
else
  echo "== (custom mode, no TEST_GCC: test binary skipped)"
fi
echo "== DONE $ARCH"
