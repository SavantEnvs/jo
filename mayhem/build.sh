#!/usr/bin/env bash
# jo/mayhem/build.sh — build (a) the sanitized fuzz_jo libFuzzer harness over jo's CLI parsing path
# (jo.c) AND its JSON engine (json.c), plus its standalone reproducer, and (b) jo's OWN autotools
# build + TAP test suite with NORMAL flags, so mayhem/test.sh only RUNS the suite (honest PATCH
# oracle, never compiles).
#
# mayhem/fuzz_jo.c #includes jo.c (see the note at the top of that file: the nested-member `pile` is
# static, so the CLI path cannot be driven by linking alone), so the harness TU IS jo.c — nothing
# else compiles jo.c for the fuzz build. json.c and base64.c are compiled and linked separately,
# both WITH $SANITIZER_FLAGS so the FUZZED CODE is instrumented, not just the harness.
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
# jo.c is compiled by autotools (step 2) with the package's own -D defines; the harness TU pulls
# jo.c in with #include, so it needs PACKAGE_VERSION (jo.c:644/709, the -v/-V paths). Take it from
# configure.ac rather than hardcoding it, so the build stays correct at any commit.
JO_VERSION="$(sed -n 's/^AC_INIT(\[[^]]*\], *\[\([^]]*\)\].*/\1/p' "$SRC/configure.ac" | head -1)"
[ -n "$JO_VERSION" ] || { echo "build.sh: cannot read the version from configure.ac" >&2; exit 1; }
JO_DEFS=(-DPACKAGE_VERSION="\"$JO_VERSION\"")

# Compile jo's JSON engine and base64 codec WITH $SANITIZER_FLAGS so that code is instrumented.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -std=gnu99 -I"$SRC" -c "$SRC/json.c" -o /tmp/json.san.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -std=gnu99 -I"$SRC" -c "$SRC/base64.c" -o /tmp/base64.san.o
# Separate objects WITH libFuzzer's coverage instrumentation (-fsanitize=fuzzer-no-link):
# the .san.o objects above are sanitized but carry NO sancov edges, so the libFuzzer binary would
# run blind (guided only by the harness's own handful of branches) — the actual code it targets
# must be compiled with the coverage flag too, just not linked to a second main().
$CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -std=gnu99 -I"$SRC" -c "$SRC/json.c" -o /tmp/json.cov.o
$CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -std=gnu99 -I"$SRC" -c "$SRC/base64.c" -o /tmp/base64.cov.o

# LeakSanitizer off at BUILD time (fleet policy; see mayhem/lsan_off.c) — linked into BOTH binaries.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -std=gnu99 -c "$SRC/mayhem/lsan_off.c" -o /tmp/lsan_off.o

# 1a) libFuzzer harness (the Mayhem target): harness (= jo.c) + engine + coverage-instrumented
#     json.c/base64.c. Asserts MUST stay in (no -DNDEBUG): json.c's emit_string() assert is the
#     original mayhemheroes defect, and jo's own autotools build does not define NDEBUG either.
$CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -std=gnu99 -I"$SRC" "${JO_DEFS[@]}" \
    "$SRC/mayhem/fuzz_jo.c" $LIB_FUZZING_ENGINE /tmp/json.cov.o /tmp/base64.cov.o /tmp/lsan_off.o \
    -o /mayhem/fuzz_jo

# 1b) Standalone (non-fuzzer) reproducer: same harness + LLVM's run-once driver. C harness, so
#     $STANDALONE_FUZZ_MAIN compiles cleanly with $CC. Respects $SANITIZER_FLAGS.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -std=gnu99 -I"$SRC" "${JO_DEFS[@]}" \
    "$SRC/mayhem/fuzz_jo.c" /tmp/standalone_main.o /tmp/json.san.o /tmp/base64.san.o /tmp/lsan_off.o \
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
