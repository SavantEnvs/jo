// mayhem/fuzz_jo.c — libFuzzer harness for the BACKPORT branch repro-23961e0.
//
// WHY THIS DIFFERS FROM THE LIVE `mayhem` BRANCH HARNESS
// -----------------------------------------------------
// The original mayhemheroes target this backport reproduces (mayhemheroes/jo/jo run 11, image built
// from fork commit 77498be9) was NOT a libFuzzer harness at all: its Mayhemfile was
//
//     project: jo
//     target: jo
//     cmds:
//       - cmd: /install/bin/jo          # no @@ → Mayhem fuzzed the CLI over STDIN
//
// i.e. it fuzzed the real `jo` binary, feeding fuzzed bytes to stdin. With no arguments jo reads
// `key=value` / `key@value` lines off stdin (jo.c:752), hands each to append_kv(), and finally
// encodes the whole object with stringify() → json_stringify() (jo.c:810).
//
// The one GENUINE defect that run found (defect 2406985, CWE-20 improper-input-validation,
// severity 7.1 — the only one of its 16 with a backtrace) is:
//
//     Assertion failed: utf8_validate(str) (json.c: emit_string: 1209)
//
// jo takes the raw stdin bytes as a key/value and stores them in a JsonNode WITHOUT validating
// UTF-8; json.c's *encoder* then asserts that every string it emits is valid UTF-8, so any
// non-UTF-8 byte on stdin aborts the process. That is a real, input-triggered reachable-assert/DoS
// in the shipped program, with both frames (jo.c → json.c) in the target's own code.
//
// It is NOT reachable through the json_decode()-only harness the live `mayhem` branch ships:
// json_decode() *rejects* invalid UTF-8 up front (parse_string → utf8_validate), so a decode-only
// harness can never construct the bad node that emit_string() chokes on. This is exactly the
// "Input-interface caveat" in BACKPORT.md — the original corpus is stdin bytes for jo's CLI, and
// "if the current v2 harness for that target consumes a different input shape, the seeds reproduce
// nothing; reconstruct the original harness from the mayhemheroes fork commit and port it to v2".
// So this harness ports that CLI surface in-process, and keeps the json engine surface too.
//
// HOW THE CLI PATH IS DRIVEN IN-PROCESS
// -------------------------------------
// jo.c's parsing entry points (append_kv, stringify) are public, but `pile` — the global jo threads
// nested `key[i]=v` members through — is static, so the file is #included here (with main renamed
// out of the way) rather than linked. No upstream file is modified; this is the only TU that pulls
// jo.c in.
//
// Inputs that would make jo exit() are skipped, NOT because they are uninteresting but because an
// exit() inside LLVMFuzzerTestOneInput tears the fuzzer down and Mayhem records it as a bogus
// "crash". The exits are all file-I/O ones: vnode() treats a value starting with '@', '%' or ':' as
// a filename and errx(1)s when it cannot be read (jo.c:327/334/342), and member_to_object() does the
// same for the `key:=file` form (jo.c:502/509). Those are jo's documented "cannot read file" error
// path, not bugs — and they are the reason the original mayhemheroes run recorded 15 *uncategorized*
// non-crash "defects" (their saved output shows jo printing valid JSON and exiting, with no
// backtrace at all).
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// jo.c has its own main(); rename it so this TU can be linked against libFuzzer's.
#define main jo_main_unused
#include "jo.c"
#undef main

// True if the line would drive jo into a slurp_file()+errx() exit (see the note above).
static int jo_line_exits(const char *line)
{
	const char *eq = strchr(line, '=');

	// `key:=file` — member_to_object() slurps the file before anything else.
	if (strstr(line, ":=") != NULL)
		return 1;
	// `key=@file` / `key=%file` / `key=:file` — vnode() slurps the file.
	if (eq != NULL && (eq[1] == '@' || eq[1] == '%' || eq[1] == ':'))
		return 1;
	// In array mode (-a) the WHOLE argument is the value, so the same three prefixes apply.
	if (line[0] == '@' || line[0] == '%' || line[0] == ':')
		return 1;
	return 0;
}

// One pass of jo's `argc == 0` stdin loop (jo.c:747-816): append_kv() every line, fold the nested
// `pile` back in, then encode. `flags` mirrors a jo invocation (plain object, or -a/-p).
static void jo_cli_round(char *text, int flags, char key_delim)
{
	JsonNode *json, *op;
	char *line, *save;
	char *js;

	pile = json_mkobject();
	json = (flags & FLAG_ARRAY) ? json_mkarray() : json_mkobject();

	// slurp_line() splits stdin on '\n' and strips it; do the same. One deliberate difference:
	// jo's loop STOPS at the first empty line (in_len == 0) while strtok_r() skips it, so this
	// harness feeds a superset of the lines jo would — every one of them through append_kv()
	// exactly as jo does.
	for (line = strtok_r(text, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
		if (jo_line_exits(line))
			continue;
		// append_kv() writes into its argument (it chops at '='), which is fine: `text` is
		// this harness's own scratch copy of the fuzz input.
		append_kv(json, flags, key_delim, line);
	}

	// jo.c:795 — copy the nested objects/arrays collected in `pile` into the result.
	json_foreach(op, pile) {
		JsonNode *o;

		if (op->tag == JSON_ARRAY)
			o = json_mkarray();
		else if (op->tag == JSON_OBJECT)
			o = json_mkobject();
		else
			continue;
		json_copy_to_object(o, op, 0);
		json_append_member(json, op->key, o);
	}

	// The encode jo.c:810 does. This is where emit_string()'s utf8_validate() assert fires.
	// jo exit(2)s on a NULL return; here we just move on (a NULL is not the bug).
	js = stringify(json, flags);
	free(js);

	json_delete(json);
	json_delete(pile);
	pile = NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *s;

	// json_decode()/append_kv() both consume NUL-terminated C strings; copy + terminate.
	s = (char *)malloc(size + 1);
	if (!s)
		return 0;
	memcpy(s, data, size);
	s[size] = '\0';

	// ── 1) jo's CLI surface: the stdin path the original mayhemheroes target fuzzed. ─────────
	// Two flag combinations, because they take different routes through jo.c: the default
	// object mode goes member_to_object() → vnode() → resolve_nested(), and -a array mode
	// feeds the whole line to vnode(). -p only changes the emitter's spacing.
	{
		char *scratch = (char *)malloc(size + 1);
		if (scratch) {
			memcpy(scratch, s, size + 1);
			jo_cli_round(scratch, 0, 0);
			memcpy(scratch, s, size + 1);
			jo_cli_round(scratch, FLAG_ARRAY | FLAG_PRETTY, 0);
			free(scratch);
		}
	}

	// ── 2) jo's JSON engine (json.c) directly, as the live harness does. ─────────────────────
	// Kept because it reaches decode-side bugs the CLI path cannot: json_decode()'s
	// parse_value/parse_array mutual recursion has no depth limit and overflows the stack on
	// deeply nested input (json.c:721/791/806).
	(void)json_validate(s);
	{
		JsonNode *node = json_decode(s);
		if (node) {
			char *enc = json_encode(node);
			free(enc);

			char *pretty = json_stringify(node, "  ");
			free(pretty);

			json_delete(node);
		}
	}

	free(s);
	return 0;
}
