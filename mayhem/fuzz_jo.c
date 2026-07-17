// mayhem/fuzz_jo.c — libFuzzer harness for jo's JSON engine (json.c, the CCAN/joeyadams parser jo
// embeds). This is the in-process, sanitized successor to the original mayhemheroes `jo` target,
// which fuzzed the bare CLI over stdin: jo reads `key=value` lines and runs each value through its
// JSON sniffer (vnode -> json_decode for `key=[...]`/`key={...}`), so json.c's decode/encode is the
// real parsing surface those crashes lived in. We drive it directly here.
//
// We deliberately exercise json.c (not jo.c's append_kv/vnode) because vnode's `@file`/`%file`/`:file`
// paths call slurp_file()+errx() -> exit(), which would tear down the libFuzzer process on benign
// inputs. json_decode() instead takes a C string and returns NULL on malformed input (no exit), so it
// is the safe, self-contained surface — and it is exactly the heart of jo's parsing.
#include "json.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	// json_decode() consumes a NUL-terminated C string; copy + terminate the fuzz bytes.
	char *s = (char *)malloc(size + 1);
	if (!s)
		return 0;
	memcpy(s, data, size);
	s[size] = '\0';

	// Validation path (utf8 + structural walk) — independent of decode.
	(void)json_validate(s);

	// Decode path. On well-formed input, round-trip through the encoders to exercise the
	// emit/stringify machinery (string escaping, number formatting, nested traversal) too.
	JsonNode *node = json_decode(s);
	if (node) {
		char *enc = json_encode(node);
		free(enc);

		char *pretty = json_stringify(node, "  ");
		free(pretty);

		json_delete(node);
	}

	free(s);
	return 0;
}
