#!/usr/bin/env bash
# Builds, inside the commit image as `mayhem` in /mayhem:
#   1) the lwIP stack + apps + unix port with the test/fuzz configuration, sanitized (ASan+UBSan, halting),
#   2) the three libFuzzer harnesses (/mayhem/lwip_fuzz, lwip_fuzz2, lwip_fuzz3) + run-once -standalone reproducers,
#   3) upstream's check-based unit suite (contrib/ports/unix/check/lwip_unittests) with the project's NORMAL flags.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

# 1) The sanitized project, twice: once with libFuzzer coverage instrumentation (fuzz binaries) and once
#    without (run-once -standalone reproducers, which must link with no fuzzer runtime). lwIP does
#    deliberate unaligned header accesses, so alignment checks are off (upstream's own clang build passes
#    -fno-sanitize=alignment too); the rest of UBSan stays halting.
BASE_CFLAGS="-O2 -DLWIP_DEBUG $SANITIZER_FLAGS $DEBUG_FLAGS -fno-sanitize=alignment"
INCS="-I$SRC/test/fuzz -I$SRC/contrib -I$SRC/src/include -I$SRC/contrib/ports/unix/port/include"
mkdir -p "$SRC/build"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/build/standalone_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.c -o "$SRC/build/lsan_off.o"

build_variant() {  # <fuzz|standalone> <extra cflags>
  local v="$1" extra="$2" objdir="$SRC/build/$1"
  mkdir -p "$objdir"
  make -f mayhem/lwip_fuzz.mk -j"$MAYHEM_JOBS" SRC="$SRC" OBJDIR="$objdir" CC="$CC" AR=ar \
    FUZZ_CFLAGS="$BASE_CFLAGS $extra" "$objdir/liblwipfuzz.a"
  local i=0 t
  for t in lwip_fuzz lwip_fuzz2 lwip_fuzz3; do
    i=$((i + 1))
    $CC $BASE_CFLAGS $extra $INCS -DFUZZ_VARIANT=$i -c mayhem/lwip_fuzz_harness.c -o "$objdir/$t.o"
    if [ "$v" = fuzz ]; then
      $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$objdir/$t.o" "$SRC/build/lsan_off.o" \
          "$objdir/liblwipfuzz.a" -lm -lpthread -lrt -o "$SRC/$t"
    else
      $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$SRC/build/standalone_main.o" "$objdir/$t.o" "$SRC/build/lsan_off.o" \
          "$objdir/liblwipfuzz.a" -lm -lpthread -lrt -o "$SRC/$t-standalone"
    fi
  done
}
build_variant fuzz "-fsanitize=fuzzer-no-link"
build_variant standalone ""

# 3) Upstream's unit suite, built the way upstream builds it (its Makefile, its flags).
env -u CFLAGS -u LDFLAGS -u CPPFLAGS make -C contrib/ports/unix/check -j"$MAYHEM_JOBS" CC=gcc lwip_unittests
