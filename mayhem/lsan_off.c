// mayhem/lsan_off.c — turn LeakSanitizer OFF at BUILD time (fleet policy: ASan stays on, LSan is
// disabled preventively for every ASan-built target; the option must never be set at runtime, see
// scripts/integration/spec-check.sh).
//
// It matters here beyond policy: jo is a short-lived CLI that deliberately never frees most of what
// it allocates (slurp_line()'s buffer, vnode()'s intermediate strings), so with LSan on, libFuzzer's
// per-input leak check would report a leak for nearly every input and bury the real crash — the
// reachable emit_string() assert this backport exists to reproduce. Leaks are also "memory/resource"
// defects, which the original mayhemheroes run had ZERO of (it was an unsanitized alpine build).
int __lsan_is_turned_off(void) { return 1; }
