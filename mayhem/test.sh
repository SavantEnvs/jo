#!/usr/bin/env bash
# jo/mayhem/test.sh — RUN jo's OWN TAP test suite (tests/jo.test, built by mayhem/build.sh) → CTRF.
# PATCH-grade oracle: it never compiles, only runs, and each test diffs jo's real output against a
# golden tests/jo.NN.exp (asserts BEHAVIOR/OUTPUT), so a no-op/exit(0) patch fails it.
#
# tests/jo.test emits TAP: a plan line "1..N" then "ok N - title" / "not ok N - title" per test.
# It runs $(pwd)/jo, so we run it from $SRC where build.sh left the compiled binary + generated tests.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

[ -x "$SRC/jo" ] || { echo "missing $SRC/jo — run mayhem/build.sh first" >&2; exit 2; }
[ -f "$SRC/tests/jo.test" ] || { echo "missing tests/jo.test — wrong tree?" >&2; exit 2; }

# Run the TAP driver; capture all output so we can parse it regardless of exit status.
out="$(sh "$SRC/tests/jo.test" 2>&1)"; echo "$out"

# Parse TAP: each result line begins "ok " or "not ok ". (The plan line "1..N" is informational.)
passed="$(printf '%s\n' "$out" | grep -cE '^ok ')"
failed="$(printf '%s\n' "$out" | grep -cE '^not ok ')"
plan="$(printf '%s\n' "$out" | sed -n 's/^1\.\.\([0-9][0-9]*\).*/\1/p' | head -1)"

# Sanity: the executed count should match the TAP plan; a mismatch means the driver died early.
if [ -n "${plan:-}" ]; then
  ran=$(( passed + failed ))
  if [ "$ran" -ne "$plan" ]; then
    echo "test.sh: TAP plan says $plan tests but $ran ran — treating shortfall as failures" >&2
    failed=$(( failed + (plan - ran) ))
  fi
fi

if [ "$(( passed + failed ))" -eq 0 ]; then
  echo "test.sh: no TAP results parsed from tests/jo.test" >&2
  emit_ctrf "jo-tap" 0 1; exit $?
fi

emit_ctrf "jo-tap" "$passed" "$failed"
