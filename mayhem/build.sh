#!/usr/bin/env bash
# jo/mayhem/build.sh — build (a) the sanitized fuzz_jo libFuzzer harness over jo's JSON engine
# (json.c) plus its standalone reproducer, and (b) jo's OWN autotools build + TAP test suite with
# NORMAL flags, so mayhem/test.sh only RUNS the suite (honest PATCH oracle, never compiles).
#
# json.c is the self-contained CCAN/joeyadams JSON parser jo embeds (json.h + libc only); the fuzz
# build compiles it WITH $SANITIZER_FLAGS so the FUZZED CODE is instrumented, not just the harness.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs from the ENV, overridable. SANITIZER_FLAGS uses `=` (not `:=`) so an explicit empty
# value (--build-arg SANITIZER_FLAGS=) is honored → no-sanitizer build (natural crash).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

# ── 1) Sanitized fuzz target ──────────────────────────────────────────────────
# Compile jo's JSON engine WITH $SANITIZER_FLAGS so the parser code is instrumented.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -std=gnu99 -I"$SRC" -c "$SRC/json.c" -o /tmp/json.san.o

# 1a) libFuzzer harness (the Mayhem target `jo`): harness + engine + sanitized json.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -std=gnu99 -I"$SRC" \
    "$SRC/mayhem/fuzz_jo.c" $LIB_FUZZING_ENGINE /tmp/json.san.o \
    -o /mayhem/fuzz_jo

# 1b) Standalone (non-fuzzer) reproducer: same harness + LLVM's run-once driver. C harness, so
#     $STANDALONE_FUZZ_MAIN compiles cleanly with $CC. Respects $SANITIZER_FLAGS.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -std=gnu99 -I"$SRC" \
    "$SRC/mayhem/fuzz_jo.c" /tmp/standalone_main.o /tmp/json.san.o \
    -o /mayhem/fuzz_jo-standalone

# ── 2) jo's OWN autotools build + TAP test suite (NORMAL flags, no sanitizers) ───────────────────
# A separate, clean build so mayhem/test.sh stays an honest PATCH oracle (it only RUNS the suite).
# `make check` runs tests/jo.test (the TAP driver) over tests/jo.??.sh diff'd against jo.??.exp,
# which needs the freshly-built `jo` binary in the build dir. We build in place so test.sh can find
# both the binary and the generated tests/jo.07.sh.
autoreconf -i
./configure
make -j"$MAYHEM_JOBS"

# The TAP test driver expects $(pwd)/jo; building in $SRC leaves it at $SRC/jo. Leave the tree as-is
# for test.sh (which runs `make check` here).
test -x "$SRC/jo" || { echo "build.sh: jo binary not produced" >&2; exit 1; }
