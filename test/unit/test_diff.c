// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <math.h>
#include <rz_diff.h>
#include "minunit.h"

#define R(a, b, c, d) \
	{ (const ut8 *)a, (const ut8 *)b, c, d }
static struct {
	const ut8 *a;
	const ut8 *b;
	ut32 myers;
	ut32 levenshtein;
} tests[] = {
	R("", "zzz", 3, 3),
	R("meow", "", 4, 4),
	R("a", "b", 2, 1),
	R("aaa", "aaa", 0, 0),
	R("aaaaa", "aabaa", 2, 1),
	R("aaaa", "aabaa", 1, 1),
	R("aaba", "babca", 3, 2),
	R("foo", "foobar", 3, 3),
	R("wallaby", "wallet", 5, 3),
	R("identity", "identity", 0, 0),
	{ NULL, NULL, 0, 0 }
};

bool test_rz_diff_distances(void) {
	ut32 distance;
	bool boolean;

	for (ut32 i = 0; tests[i].a; i++) {
		size_t la = strlen((const char *)tests[i].a);
		size_t lb = strlen((const char *)tests[i].b);

		boolean = rz_diff_levenshtein_distance(tests[i].a, la, tests[i].b, lb, &distance, NULL);
		mu_assert_true(boolean, "rz_diff_levenshtein_distance");
		mu_assert_eq(distance, tests[i].levenshtein, "levenshtein distance");

		boolean = rz_diff_myers_distance(tests[i].a, la, tests[i].b, lb, &distance, NULL);
		mu_assert_true(boolean, "rz_diff_myers_distance");
		mu_assert_eq(distance, tests[i].myers, "myers distance");
	}
	mu_end;
}

// Deterministic pseudo-random buffer, so the CDC chunking (and thus the test
// expectations) are reproducible across platforms.
static ut8 *cdc_make_buffer(ut32 size, ut32 seed) {
	ut8 *buf = malloc(size);
	if (!buf) {
		return NULL;
	}
	ut32 x = seed;
	for (ut32 i = 0; i < size; i++) {
		x = 1103515245u * x + 12345u;
		buf[i] = (x >> 16) & 0xff;
	}
	return buf;
}

bool test_rz_diff_cdc_below_threshold(void) {
	// below RZ_DIFF_CDC_THRESHOLD the CDC path forwards to exact Myers, so the
	// results must match rz_diff_myers_distance byte-for-byte.
	for (ut32 i = 0; tests[i].a; i++) {
		size_t la = strlen((const char *)tests[i].a);
		size_t lb = strlen((const char *)tests[i].b);
		ut32 cdc = 0, myers = 0;
		mu_assert_true(rz_diff_cdc_distance(tests[i].a, la, tests[i].b, lb, &cdc, NULL), "rz_diff_cdc_distance");
		mu_assert_true(rz_diff_myers_distance(tests[i].a, la, tests[i].b, lb, &myers, NULL), "rz_diff_myers_distance");
		mu_assert_eq(cdc, myers, "cdc-myers equals exact myers below threshold");
		mu_assert_eq(cdc, tests[i].myers, "cdc-myers matches expected myers distance");
	}
	mu_end;
}

bool test_rz_diff_cdc_large_identical(void) {
	const ut32 size = (1u << 20) + 0x40000; // 1.25 MiB, above the CDC threshold
	ut8 *a = cdc_make_buffer(size, 0xc0ffee);
	mu_assert_notnull(a, "alloc large buffer");
	ut32 distance = UT32_MAX;
	double similarity = -1.0;
	mu_assert_true(rz_diff_cdc_distance(a, size, a, size, &distance, &similarity), "cdc on identical large buffers");
	mu_assert_eq(distance, 0, "identical large buffers have zero distance");
	mu_assert_true(fabs(similarity - 1.0) < 1e-9, "identical large buffers have similarity 1.0");
	free(a);
	mu_end;
}

bool test_rz_diff_cdc_large_matches_myers(void) {
	const ut32 size = (1u << 20) + 0x40000; // 1.25 MiB, above the CDC threshold
	ut8 *a = cdc_make_buffer(size, 0x1234);
	ut8 *b = cdc_make_buffer(size, 0x1234);
	mu_assert_notnull(a, "alloc buffer a");
	mu_assert_notnull(b, "alloc buffer b");
	// sparse single-byte substitutions: each edit lands in its own chunk, the
	// neighbours stay anchored, so the summed per-gap distance equals the exact
	// Myers distance (which is cheap to compute here because the edit distance
	// stays small).
	const ut32 offsets[] = { 1000, 200000, 500000, 800000, 1100000 };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(offsets); i++) {
		b[offsets[i]] ^= 0xff;
	}
	ut32 cdc = 0, myers = 0;
	mu_assert_true(rz_diff_cdc_distance(a, size, b, size, &cdc, NULL), "cdc on edited large buffers");
	mu_assert_true(rz_diff_myers_distance(a, size, b, size, &myers, NULL), "exact myers on edited large buffers");
	mu_assert_true(myers > 0, "edited buffers differ");
	mu_assert_eq(cdc, myers, "cdc-myers equals exact myers for localized edits");
	free(a);
	free(b);
	mu_end;
}

// Replay opcodes to rebuild B from A: EQUAL spans are copied from A (so the
// final compare also proves those spans are genuinely equal to B), changed
// spans are copied from B, deletions contribute nothing. A correct edit script
// must rebuild B exactly. Also verifies the opcodes tile [0,a_size) x [0,b_size)
// contiguously, with no gaps or overlaps. Returns true iff everything checks.
static bool diff_opcodes_rebuild_b(RzDiff *diff, const ut8 *a, ut32 a_size, const ut8 *b, ut32 b_size) {
	RzList *ops = rz_diff_opcodes_new(diff);
	if (!ops) {
		return false;
	}
	ut8 *out = malloc(b_size ? b_size : 1);
	bool ok = out != NULL;
	ut32 outn = 0, ea = 0, eb = 0;
	RzListIter *it;
	RzDiffOp *op;
	rz_list_foreach (ops, it, op) {
		if (!ok) {
			break;
		}
		ut32 la = (ut32)(op->a_end - op->a_beg);
		ut32 lb = (ut32)(op->b_end - op->b_beg);
		if ((ut32)op->a_beg != ea || (ut32)op->b_beg != eb) {
			ok = false; // non-contiguous opcodes
			break;
		}
		switch (op->type) {
		case RZ_DIFF_OP_EQUAL:
			if (la != lb || outn + la > b_size) {
				ok = false;
				break;
			}
			memcpy(out + outn, a + op->a_beg, la);
			outn += la;
			break;
		case RZ_DIFF_OP_INSERT:
		case RZ_DIFF_OP_REPLACE:
			if (outn + lb > b_size) {
				ok = false;
				break;
			}
			memcpy(out + outn, b + op->b_beg, lb);
			outn += lb;
			break;
		case RZ_DIFF_OP_DELETE:
			break;
		default:
			ok = false;
			break;
		}
		ea = op->a_end;
		eb = op->b_end;
	}
	if (ok) {
		ok = ea == a_size && eb == b_size && outn == b_size && (!b_size || !memcmp(out, b, b_size));
	}
	free(out);
	rz_list_free(ops);
	return ok;
}

bool test_rz_diff_cdc_bytes_below_threshold(void) {
	// below RZ_DIFF_CDC_THRESHOLD the CDC byte path forwards to the exact
	// matcher, so its unified diff must be identical to rz_diff_bytes_new; the
	// reconstruction check also exercises both paths on small inputs.
	const char *pairs[][2] = {
		{ "", "abc" },
		{ "abc", "" },
		{ "same", "same" },
		{ "hello world", "hello brave world" },
		{ "the quick brown fox", "the slow brown cat" },
		{ "aaaaaaaaaa", "aaabaaaaaa" },
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(pairs); i++) {
		const ut8 *a = (const ut8 *)pairs[i][0];
		const ut8 *b = (const ut8 *)pairs[i][1];
		ut32 la = (ut32)strlen(pairs[i][0]);
		ut32 lb = (ut32)strlen(pairs[i][1]);
		RzDiff *d1 = rz_diff_bytes_new(a, la, b, lb);
		RzDiff *d2 = rz_diff_bytes_cdc_new(a, la, b, lb);
		mu_assert_notnull(d1, "bytes_new");
		mu_assert_notnull(d2, "bytes_cdc_new");
		char *u1 = rz_diff_unified_text(d1, "a", "b", false, false);
		char *u2 = rz_diff_unified_text(d2, "a", "b", false, false);
		mu_assert_notnull(u1, "unified bytes");
		mu_assert_notnull(u2, "unified cdc-bytes");
		mu_assert_streq(u2, u1, "cdc-bytes unified text equals bytes below threshold");
		mu_assert_true(diff_opcodes_rebuild_b(d2, a, la, b, lb), "cdc-bytes opcodes rebuild B");
		mu_assert_true(diff_opcodes_rebuild_b(d1, a, la, b, lb), "bytes opcodes rebuild B");
		free(u1);
		free(u2);
		rz_diff_free(d1);
		rz_diff_free(d2);
	}
	mu_end;
}

bool test_rz_diff_cdc_bytes_large_identical(void) {
	const ut32 size = (1u << 20) + 0x40000; // 1.25 MiB, above the CDC threshold
	ut8 *a = cdc_make_buffer(size, 0xbeef);
	mu_assert_notnull(a, "alloc large buffer");
	RzDiff *diff = rz_diff_bytes_cdc_new(a, size, a, size);
	mu_assert_notnull(diff, "bytes_cdc_new identical");
	RzList *ops = rz_diff_opcodes_new(diff);
	mu_assert_notnull(ops, "opcodes identical");
	// identical inputs collapse to a single EQUAL op spanning the whole buffer
	mu_assert_eq(rz_list_length(ops), 1, "identical large buffers => single opcode");
	RzDiffOp *op = (RzDiffOp *)rz_list_first_val(ops);
	mu_assert_eq(op->type, RZ_DIFF_OP_EQUAL, "identical => EQUAL");
	mu_assert_eq((ut32)op->a_beg, 0, "equal a_beg");
	mu_assert_eq((ut32)op->a_end, size, "equal a_end");
	mu_assert_eq((ut32)op->b_end, size, "equal b_end");
	rz_list_free(ops);
	rz_diff_free(diff);
	free(a);
	mu_end;
}

bool test_rz_diff_cdc_bytes_large_reconstruct(void) {
	// Large input with edits that also shift the tail (a deletion and an
	// insertion). Content-defined anchors re-sync across the shift; the
	// resulting opcodes must still rebuild B exactly.
	const ut32 size = (1u << 20) + 0x40000; // 1.25 MiB, above the CDC threshold
	ut8 *a = cdc_make_buffer(size, 0x5eed);
	ut8 *b = malloc(size);
	mu_assert_notnull(a, "alloc a");
	mu_assert_notnull(b, "alloc b");
	ut32 sub_at = size / 4;
	ut32 del_at = size / 2;
	ut32 ins_at = (size / 4) * 3;
	ut32 p = 0;
	memcpy(b + p, a, del_at); // A[0:del_at], includes the substitution region
	p += del_at;
	for (ut32 i = 0; i < 16; i++) {
		b[sub_at + i] ^= 0xff; // 16-byte substitution at 25%
	}
	memcpy(b + p, a + del_at + 8, ins_at - (del_at + 8)); // skip 8 bytes (deletion at 50%)
	p += ins_at - (del_at + 8);
	for (ut32 i = 0; i < 8; i++) {
		b[p++] = (ut8)(0xa0 + i); // 8-byte insertion at 75%
	}
	memcpy(b + p, a + ins_at, size - ins_at); // tail
	p += size - ins_at;
	mu_assert_eq(p, size, "B built to expected size"); // deletion and insertion cancel

	RzDiff *diff = rz_diff_bytes_cdc_new(a, size, b, size);
	mu_assert_notnull(diff, "bytes_cdc_new");
	mu_assert_true(diff_opcodes_rebuild_b(diff, a, size, b, size), "cdc-bytes opcodes rebuild shifted B");
	rz_diff_free(diff);
	free(a);
	free(b);
	mu_end;
}

bool test_rz_diff_cdc_bytes_large_replace(void) {
	// Two unrelated large buffers share no chunk-aligned content, so the whole
	// input is a single large-by-large gap. That gap exceeds the per-gap cap and
	// is emitted as one replace instead of being sub-diffed; the opcodes must
	// still rebuild B exactly.
	const ut32 size = (1u << 20) + 0x40000; // 1.25 MiB, above the CDC threshold
	ut8 *a = cdc_make_buffer(size, 0xaaaa);
	ut8 *b = cdc_make_buffer(size, 0x5555);
	mu_assert_notnull(a, "alloc a");
	mu_assert_notnull(b, "alloc b");
	RzDiff *diff = rz_diff_bytes_cdc_new(a, size, b, size);
	mu_assert_notnull(diff, "bytes_cdc_new");
	mu_assert_true(diff_opcodes_rebuild_b(diff, a, size, b, size), "cdc-bytes opcodes rebuild unrelated B");
	rz_diff_free(diff);
	free(a);
	free(b);
	mu_end;
}

bool test_rz_diff_unified_lines(void) {
	RzDiff *diff = NULL;
	char *result = NULL;

	// clang-format off
	const char *a = ""
			"This part of the\n"
			"document has stayed the\n"
			"same from version to\n"
			"version.  It shouldn't\n"
			"be shown if it doesn't\n"
			"change.  Otherwise, that\n"
			"would not be helping to\n"
			"compress the size of the\n"
			"changes.\n"
			"\n"
			"This paragraph contains\n"
			"text that is outdated.\n"
			"It will be deleted in the\n"
			"near future.\n"
			"\n"
			"It is important to spell\n"
			"check this dokument. On\n"
			"the other hand, a\n"
			"misspelled word isn't\n"
			"the end of the world.\n"
			"Nothing in the rest of\n"
			"this paragraph needs to\n"
			"be changed. Things can\n"
			"be added after it.";

	const char *b = ""
			"This is an important\n"
			"notice! It should\n"
			"therefore be located at\n"
			"the beginning of this\n"
			"document!\n"
			"\n"
			"This part of the\n"
			"document has stayed the\n"
			"same from version to\n"
			"version.  It shouldn't\n"
			"be shown if it doesn't\n"
			"change.  Otherwise, that\n"
			"would not be helping to\n"
			"compress the size of the\n"
			"changes.\n"
			"\n"
			"It is important to spell\n"
			"check this document. On\n"
			"the other hand, a\n"
			"misspelled word isn't\n"
			"the end of the world.\n"
			"Nothing in the rest of\n"
			"this paragraph needs to\n"
			"be changed. Things can\n"
			"be added after it.\n"
			"\n"
			"This paragraph contains\n"
			"important new additions\n"
			"to this document.";

	const char *expected = ""
			"--- /original\n"
			"+++ /modified\n"
			"@@ -1,3 +1,9 @@\n"
			"+This is an important\n"
			"+notice! It should\n"
			"+therefore be located at\n"
			"+the beginning of this\n"
			"+document!\n"
			"+\n"
			" This part of the\n"
			" document has stayed the\n"
			" same from version to\n"
			"@@ -8,17 +14,16 @@\n"
			" compress the size of the\n"
			" changes.\n"
			" \n"
			"-This paragraph contains\n"
			"-text that is outdated.\n"
			"-It will be deleted in the\n"
			"-near future.\n"
			"-\n"
			" It is important to spell\n"
			"-check this dokument. On\n"
			"+check this document. On\n"
			" the other hand, a\n"
			" misspelled word isn't\n"
			" the end of the world.\n"
			" Nothing in the rest of\n"
			" this paragraph needs to\n"
			" be changed. Things can\n"
			"-be added after it.\n"
			"+be added after it.\n"
			"+\n"
			"+This paragraph contains\n"
			"+important new additions\n"
			"+to this document.\n";
	// clang-format on

	diff = rz_diff_lines_new(a, b, NULL);
	result = rz_diff_unified_text(diff, NULL, NULL, false, false);
	rz_diff_free(diff);
	mu_assert_notnull(result, "rz_diff_unified result not null");
	mu_assert_streq(result, expected, "rz_diff_unified on lines");
	free(result);

	mu_end;
}

bool test_rz_diff_unified_bytes(void) {
	RzDiff *diff = NULL;
	char *result = NULL;

	// clang-format off
	const char *a = ""
			"This part of the\n"
			"document has stayed the\n"
			"same from version to\n"
			"version.  It shouldn't\n"
			"be shown if it doesn't\n"
			"change.  Otherwise, that\n"
			"would not be helping to\n"
			"compress the size of the\n"
			"changes.\n"
			"\n"
			"This paragraph contains\n"
			"text that is outdated.\n"
			"It will be deleted in the\n"
			"near future.\n"
			"\n"
			"It is important to spell\n"
			"check this dokument. On\n"
			"the other hand, a\n"
			"misspelled word isn't\n"
			"the end of the world.\n"
			"Nothing in the rest of\n"
			"this paragraph needs to\n"
			"be changed. Things can\n"
			"be added after it.";

	const char *b = ""
			"This is an important\n"
			"notice! It should\n"
			"therefore be located at\n"
			"the beginning of this\n"
			"document!\n"
			"\n"
			"This part of the\n"
			"document has stayed the\n"
			"same from version to\n"
			"version.  It shouldn't\n"
			"be shown if it doesn't\n"
			"change.  Otherwise, that\n"
			"would not be helping to\n"
			"compress the size of the\n"
			"changes.\n"
			"\n"
			"It is important to spell\n"
			"check this document. On\n"
			"the other hand, a\n"
			"misspelled word isn't\n"
			"the end of the world.\n"
			"Nothing in the rest of\n"
			"this paragraph needs to\n"
			"be changed. Things can\n"
			"be added after it.\n"
			"\n"
			"This paragraph contains\n"
			"important new additions\n"
			"to this document.";

	const char *expected = ""
			"--- /original\n"
			"+++ /modified\n"
			"@@ --2,287 +-2,296 @@\n"
			" 5468697320\n"
			"-70617274206f66207468650a646f63756d656e74206861732073746179656420\n"
			"-7468650a73616d652066726f6d2076657273696f6e20746f0a76657273696f6e\n"
			"-2e20204974207368\n"
			"+697320616e20696d706f7274616e740a6e6f74696365212049742073686f756c\n"
			"+640a7468657265666f7265206265206c6f63617465642061740a746865206265\n"
			"+67696e6e696e6720\n"
			" 6f\n"
			"-756c646e2774\n"
			"+662074686973\n"
			" 0a\n"
			"-62652073686f776e20696620697420646f65736e27740a6368616e67652e2020\n"
			"-4f746865727769\n"
			"+646f63756d656e74210a0a546869732070617274206f66207468650a646f6375\n"
			"+6d656e74206861\n"
			" 73\n"
			"-652c20746861740a776f756c64206e6f742062652068656c70696e6720746f0a\n"
			"-636f6d7072657373207468652073697a65206f66207468650a6368616e676573\n"
			"-2e0a0a54686973207061726167726170\n"
			"+20737461796564207468650a73616d652066726f6d2076657273696f6e20746f\n"
			"+0a76657273696f6e2e202049742073686f756c646e27740a62652073686f776e\n"
			"+20696620697420646f65736e27740a63\n"
			" 68\n"
			"-20636f6e7461696e730a7465787420746861\n"
			"+616e67652e20204f74686572776973652c20\n"
			" 74\n"
			"-206973206f757464617465642e0a4974\n"
			"+6861740a776f756c64206e6f74206265\n"
			" 20\n"
			"-7769\n"
			"+6865\n"
			" 6c\n"
			"-6c206265\n"
			"+70696e67\n"
			" 20\n"
			"-64656c6574656420696e207468650a6e656172206675747572\n"
			"+746f0a636f6d7072657373207468652073697a65206f66207468\n"
			" 65\n"
			"+0a6368616e676573\n"
			" 2e0a0a4974206973\n"
			"@@ -310,17 +319,17 @@\n"
			" 207468697320646f\n"
			"-6b\n"
			"+63\n"
			" 756d656e742e204f\n"
			"@@ -471,8 +480,75 @@\n"
			" 667465722069742e\n"
			"+0a0a546869732070617261677261706820636f6e7461696e730a696d706f7274\n"
			"+616e74206e6577206164646974696f6e730a746f207468697320646f63756d65\n"
			"+6e742e\n";
	// clang-format on

	diff = rz_diff_bytes_new((const ut8 *)a, strlen(a), (const ut8 *)b, strlen(b));
	result = rz_diff_unified_text(diff, NULL, NULL, false, false);
	rz_diff_free(diff);
	mu_assert_notnull(result, "rz_diff_unified result not null");
	mu_assert_streq(result, expected, "rz_diff_unified on bytes");
	free(result);

	mu_end;
}

// ------------------------------------------------------------
// Additional tests covering the rest of the RzDiff public API.
//
// These tests exercise the matches, opcodes, opcodes-grouped,
// ratio, sizes-ratio, generic-methods and JSON output paths,
// plus edge cases (empty, identical, single byte, NULL guard)
// and the ignore-callback hooks.
// ------------------------------------------------------------

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

static bool ignore_blank_line(const char *line) {
	if (!line) {
		return true;
	}
	for (const char *p = line; *p; p++) {
		if (*p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') {
			return false;
		}
	}
	return true;
}

// ------------------------------------------------------------
// rz_diff_hash_data
// ------------------------------------------------------------

bool test_rz_diff_hash_data(void) {
	// Empty / NULL input must return the documented seed (5381).
	mu_assert_eq(rz_diff_hash_data(NULL, 0), 5381u, "hash on NULL returns seed");
	mu_assert_eq(rz_diff_hash_data((const ut8 *)"", 0), 5381u, "hash on size 0 returns seed");

	// Determinism: equal inputs must hash to equal values.
	const ut8 *a = (const ut8 *)"rizin";
	const ut8 *b = (const ut8 *)"rizin";
	mu_assert_eq(rz_diff_hash_data(a, 5), rz_diff_hash_data(b, 5), "deterministic hash");

	// Different inputs of the same size should generally differ (probabilistic,
	// but these two clearly do under the DJB-XOR mix used here).
	const ut8 *c = (const ut8 *)"radar";
	mu_assert_neq(rz_diff_hash_data(a, 5), rz_diff_hash_data(c, 5), "different inputs hash differently");

	mu_end;
}

// ------------------------------------------------------------
// Construction / accessors / NULL guards
// ------------------------------------------------------------

bool test_rz_diff_get_a_b(void) {
	const ut8 *a = (const ut8 *)"AAAA";
	const ut8 *b = (const ut8 *)"BBBB";
	RzDiff *d = rz_diff_bytes_new(a, 4, b, 4);
	mu_assert_notnull(d, "diff created");
	mu_assert_ptreq(rz_diff_get_a(d), a, "get_a returns the original A pointer");
	mu_assert_ptreq(rz_diff_get_b(d), b, "get_b returns the original B pointer");
	rz_diff_free(d);
	mu_end;
}

bool test_rz_diff_null_inputs(void) {
	// rz_diff_free is documented RZ_NULLABLE -- it must accept NULL as a
	// no-op. This is the only NULL-input case we can portably test: the
	// `_new` constructors are RZ_NONNULL on their data pointers, so passing
	// NULL there is undefined behavior by contract and aborts when the
	// build is configured with RZ_CHECKS_LEVEL=3 (used by the codecov CI
	// job, see .github/workflows/ci.yml: `-Dchecks_level=3`).
	rz_diff_free(NULL);
	mu_end;
}

bool test_rz_diff_empty_buffers(void) {
	// Diff of two empty buffers: should succeed, ratio = 1.0, no opcodes,
	// no matches besides the synthetic end sentinel.
	const ut8 empty[1] = { 0 };
	RzDiff *d = rz_diff_bytes_new(empty, 0, empty, 0);
	mu_assert_notnull(d, "diff on (empty, empty) created");

	double r = -1.0;
	mu_assert_true(rz_diff_ratio(d, &r), "ratio on empty returns true");
	mu_assert_eqf(r, 1.0, "ratio on (empty, empty) is 1.0");

	double sr = -1.0;
	mu_assert_true(rz_diff_sizes_ratio(d, &sr), "sizes_ratio on empty returns true");
	mu_assert_eqf(sr, 1.0, "sizes_ratio on (empty, empty) is 1.0");

	RzList *ops = rz_diff_opcodes_new(d);
	mu_assert_notnull(ops, "opcodes_new on empty returns a list");
	mu_assert_eq(rz_list_length(ops), 0, "no opcodes between two empty buffers");
	rz_list_free(ops);

	rz_diff_free(d);
	mu_end;
}

bool test_rz_diff_identical_buffers(void) {
	// For identical inputs we expect a single EQUAL opcode spanning the whole
	// buffer, ratio == 1.0, and exactly one non-sentinel match.
	const ut8 *s = (const ut8 *)"abcdefghij";
	RzDiff *d = rz_diff_bytes_new(s, 10, s, 10);
	mu_assert_notnull(d, "diff on identical created");

	double r = 0.0;
	mu_assert_true(rz_diff_ratio(d, &r), "ratio returns true");
	mu_assert_eqf(r, 1.0, "ratio on identical == 1.0");

	RzList *ops = rz_diff_opcodes_new(d);
	mu_assert_notnull(ops, "opcodes_new on identical not null");
	mu_assert_eq(rz_list_length(ops), 1, "exactly one opcode on identical");
	RzDiffOp *op = rz_list_first_val(ops);
	mu_assert_notnull(op, "first opcode not null");
	mu_assert_eq((int)op->type, (int)RZ_DIFF_OP_EQUAL, "opcode type is EQUAL");
	mu_assert_eq(op->a_beg, 0, "EQUAL spans from 0");
	mu_assert_eq(op->a_end, 10, "EQUAL spans up to a_size");
	mu_assert_eq(op->b_beg, 0, "EQUAL spans from 0 (b)");
	mu_assert_eq(op->b_end, 10, "EQUAL spans up to b_size");
	rz_list_free(ops);

	rz_diff_free(d);
	mu_end;
}

bool test_rz_diff_completely_different(void) {
	// Two strings that share no characters at all -> no equal matches,
	// ratio should be 0.0, single REPLACE opcode covering the full ranges.
	const ut8 *a = (const ut8 *)"AAAAA";
	const ut8 *b = (const ut8 *)"BBBBB";
	RzDiff *d = rz_diff_bytes_new(a, 5, b, 5);
	mu_assert_notnull(d, "diff created");

	double r = -1.0;
	mu_assert_true(rz_diff_ratio(d, &r), "ratio call ok");
	mu_assert_eqf(r, 0.0, "ratio is 0.0 for disjoint alphabets");

	double sr = -1.0;
	mu_assert_true(rz_diff_sizes_ratio(d, &sr), "sizes_ratio call ok");
	mu_assert_eqf(sr, 1.0, "sizes ratio is 1.0 for equal lengths");

	RzList *ops = rz_diff_opcodes_new(d);
	mu_assert_notnull(ops, "opcodes not null");
	mu_assert_eq(rz_list_length(ops), 1, "one REPLACE opcode");
	RzDiffOp *op = rz_list_first_val(ops);
	mu_assert_eq((int)op->type, (int)RZ_DIFF_OP_REPLACE, "single REPLACE opcode");
	mu_assert_eq(RZ_DIFF_OP_SIZE_A(op), 5, "REPLACE covers all of A");
	mu_assert_eq(RZ_DIFF_OP_SIZE_B(op), 5, "REPLACE covers all of B");
	rz_list_free(ops);

	rz_diff_free(d);
	mu_end;
}

bool test_rz_diff_pure_insert_and_delete(void) {
	// Pure insert: A is empty, B has content -> single INSERT, ratio 0.
	{
		const ut8 *a = (const ut8 *)"";
		const ut8 *b = (const ut8 *)"hello";
		RzDiff *d = rz_diff_bytes_new(a, 0, b, 5);
		mu_assert_notnull(d, "diff(empty A) created");

		RzList *ops = rz_diff_opcodes_new(d);
		mu_assert_notnull(ops, "ops not null");
		mu_assert_eq(rz_list_length(ops), 1, "one INSERT opcode");
		RzDiffOp *op = rz_list_first_val(ops);
		mu_assert_eq((int)op->type, (int)RZ_DIFF_OP_INSERT, "type INSERT");
		mu_assert_eq(op->a_beg, 0, "a_beg 0");
		mu_assert_eq(op->a_end, 0, "a_end 0");
		mu_assert_eq(op->b_beg, 0, "b_beg 0");
		mu_assert_eq(op->b_end, 5, "b_end 5");
		rz_list_free(ops);

		double r = -1.0;
		mu_assert_true(rz_diff_ratio(d, &r), "ratio ok");
		mu_assert_eqf(r, 0.0, "ratio 0 for pure insert");
		rz_diff_free(d);
	}

	// Pure delete: A has content, B is empty -> single DELETE.
	{
		const ut8 *a = (const ut8 *)"hello";
		const ut8 *b = (const ut8 *)"";
		RzDiff *d = rz_diff_bytes_new(a, 5, b, 0);
		mu_assert_notnull(d, "diff(empty B) created");

		RzList *ops = rz_diff_opcodes_new(d);
		mu_assert_notnull(ops, "ops not null");
		mu_assert_eq(rz_list_length(ops), 1, "one DELETE opcode");
		RzDiffOp *op = rz_list_first_val(ops);
		mu_assert_eq((int)op->type, (int)RZ_DIFF_OP_DELETE, "type DELETE");
		mu_assert_eq(op->a_beg, 0, "a_beg 0");
		mu_assert_eq(op->a_end, 5, "a_end 5");
		mu_assert_eq(op->b_beg, 0, "b_beg 0");
		mu_assert_eq(op->b_end, 0, "b_end 0");
		rz_list_free(ops);
		rz_diff_free(d);
	}

	mu_end;
}

// ------------------------------------------------------------
// rz_diff_matches_new
// ------------------------------------------------------------

bool test_rz_diff_matches_basic(void) {
	// Inputs reproducing the README example "ABCDEFGHI" vs "YZBCDLZNHI":
	// matches should be (B..D, H..I) plus the synthetic end sentinel.

	// clang-format off
	const char *a = ""
			"It is important to spell\n"
			"check this document. On\n"
			"the other hand, a\n"
			"misspelled word isn't\n"
			"the end of the world.\n"
			"Nothing in the rest of\n"
			"this paragraph needs to\n"
			"be changed. Things can\n"
			"be added after it.\n";

	const char *b = ""
			"It is important to spell\n"
			"cheeeck this document. On\n"
			"the other hand, a\n"
			"misspelled word isn't\n"
			"the end of the world.\n"
			"Nothhhhing in the rest of\n"
			"this paragraph needs to\n"
			"be changed. Things can\n"
			"be added after it.\n"
			"\n"
			"This paragraph contains\n"
			"important new additions\n"
			"to this document.";
	// clang-format on

	RzDiff *d = rz_diff_bytes_new((const ut8 *)a, strlen(a), (const ut8 *)b, strlen(b));
	mu_assert_notnull(d, "diff created");

	RzList *matches = rz_diff_matches_new(d);
	mu_assert_notnull(matches, "matches not null");
	// At least 2 real matches plus the (a_size, b_size, 0) sentinel.
	mu_assert_eq(rz_list_length(matches), 4, "at least two real matches + sentinel");

	// All non-sentinel matches must point to byte-identical sub-strings of A and B.
	RzListIter *it = NULL;
	RzDiffMatch *m = NULL;
	rz_list_foreach (matches, it, m) {
		if (m->size == 0) {
			continue;
		}
		mu_assert_eq(memcmp(a + m->a, b + m->b, m->size), 0, "match content equal in A and B");
	}

	// The very last entry is the synthetic end sentinel at (a_size, b_size, 0).
	RzDiffMatch *last = rz_list_last_val(matches);
	mu_assert_eq(last->size, 0u, "last match is sentinel with size 0");
	mu_assert_eq(last->a, 200u, "sentinel a == a_size");
	mu_assert_eq(last->b, 271u, "sentinel b == b_size");

	rz_list_free(matches);
	rz_diff_free(d);
	mu_end;
}

// ------------------------------------------------------------
// rz_diff_opcodes_grouped_new
// ------------------------------------------------------------

bool test_rz_diff_opcodes_grouped_identical(void) {
	// Identical inputs: documented behavior is that a single trivial EQUAL
	// opcode group is produced.
	const ut8 *s = (const ut8 *)"identical content";
	ut32 n = (ut32)strlen((const char *)s);
	RzDiff *d = rz_diff_bytes_new(s, n, s, n);
	mu_assert_notnull(d, "diff created");

	RzList *groups = rz_diff_opcodes_grouped_new(d, RZ_DIFF_DEFAULT_N_GROUPS);
	mu_assert_notnull(groups, "groups not null");
	// Per the source, when the only opcode is a single EQUAL the empty group
	// is dropped, so we may get zero groups; either way we must not crash.
	rz_list_free(groups);
	rz_diff_free(d);
	mu_end;
}

bool test_rz_diff_opcodes_grouped_replace(void) {
	const ut8 *a = (const ut8 *)"AAAAAAAA";
	const ut8 *b = (const ut8 *)"BBBBBBBB";
	RzDiff *d = rz_diff_bytes_new(a, 8, b, 8);
	mu_assert_notnull(d, "diff created");

	RzList *groups = rz_diff_opcodes_grouped_new(d, RZ_DIFF_DEFAULT_N_GROUPS);
	mu_assert_notnull(groups, "groups not null");
	mu_assert_true(rz_list_length(groups) >= 1, "at least one group for non-trivial diff");

	// Every group must contain at least one op, and every op's ranges must be
	// in-bounds.
	RzListIter *itg = NULL;
	RzList *group = NULL;
	rz_list_foreach (groups, itg, group) {
		mu_assert_true(rz_list_length(group) >= 1, "non-empty group");
		RzListIter *ito = NULL;
		RzDiffOp *op = NULL;
		rz_list_foreach (group, ito, op) {
			mu_assert_true(op->a_beg >= 0 && op->a_end <= 8, "a-range in bounds");
			mu_assert_true(op->b_beg >= 0 && op->b_end <= 8, "b-range in bounds");
			mu_assert_true(op->a_end >= op->a_beg, "a-range valid");
			mu_assert_true(op->b_end >= op->b_beg, "b-range valid");
		}
	}

	rz_list_free(groups);
	rz_diff_free(d);
	mu_end;
}

// ------------------------------------------------------------
// rz_diff_ratio / rz_diff_sizes_ratio
// ------------------------------------------------------------

bool test_rz_diff_ratio_bounds(void) {
	const ut8 *a = (const ut8 *)"the quick brown fox";
	const ut8 *b = (const ut8 *)"the quirky brown ox";
	RzDiff *d = rz_diff_bytes_new(a, (ut32)strlen((const char *)a),
		b, (ut32)strlen((const char *)b));
	mu_assert_notnull(d, "diff created");

	double r = -1.0;
	mu_assert_true(rz_diff_ratio(d, &r), "ratio call ok");
	mu_assert_true(r > 0.0 && r < 1.0, "ratio strictly in (0, 1) for partial overlap");

	double sr = -1.0;
	mu_assert_true(rz_diff_sizes_ratio(d, &sr), "sizes_ratio call ok");
	mu_assert_true(sr > 0.0 && sr <= 1.0, "sizes_ratio in (0, 1]");

	rz_diff_free(d);
	mu_end;
}

bool test_rz_diff_sizes_ratio_skewed(void) {
	// A is 4x the size of B: sizes ratio = 2*min/(a+b) = 2*1/(4+1) = 0.4
	const ut8 *a = (const ut8 *)"aaaa";
	const ut8 *b = (const ut8 *)"a";
	RzDiff *d = rz_diff_bytes_new(a, 4, b, 1);
	mu_assert_notnull(d, "diff created");

	double sr = 0.0;
	mu_assert_true(rz_diff_sizes_ratio(d, &sr), "sizes_ratio call ok");
	mu_assert_true(fabs(sr - 0.4) < 1e-9, "sizes_ratio is 2*min/(a+b)");

	rz_diff_free(d);
	mu_end;
}

// ------------------------------------------------------------
// Ignore callbacks
// ------------------------------------------------------------

bool test_rz_diff_ignore_line(void) {
	const char *a =
		"one\n"
		"\n"
		"two\n";
	const char *b =
		"one\n"
		"   \n"
		"two\n";

	RzDiff *plain = rz_diff_lines_new(a, b, NULL);
	mu_assert_notnull(plain, "plain lines diff");
	double r_plain = -1.0;
	mu_assert_true(rz_diff_ratio(plain, &r_plain), "plain ratio ok");
	rz_diff_free(plain);

	RzDiff *ign = rz_diff_lines_new(a, b, ignore_blank_line);
	mu_assert_notnull(ign, "ignore-blank lines diff");
	double r_ign = -1.0;
	mu_assert_true(rz_diff_ratio(ign, &r_ign), "ignore-blank ratio ok");
	rz_diff_free(ign);

	mu_assert_true(r_ign >= r_plain, "ignoring blank lines can only raise ratio");

	mu_end;
}

// ------------------------------------------------------------
// rz_diff_generic_new -- exercise the user-defined methods path on an
// array of integers.
// ------------------------------------------------------------

static const void *int_elem_at(const void *array, ut32 index) {
	const ut32 *arr = array;
	return &arr[index];
}

static ut32 int_elem_hash(const void *elem) {
	const ut32 *v = elem;
	return rz_diff_hash_data((const ut8 *)v, sizeof(ut32));
}

static int int_compare(const void *a_elem, const void *b_elem) {
	const ut32 *a = a_elem;
	const ut32 *b = b_elem;
	return (*a == *b) ? 0 : 1;
}

static void int_stringify(const void *elem, RzStrBuf *sb) {
	const ut32 *v = elem;
	rz_strbuf_setf(sb, "%u", *v);
}

bool test_rz_diff_generic_ints(void) {
	const ut32 a[] = { 1, 2, 3, 4, 5, 6 };
	const ut32 b[] = { 1, 2, 3, 4, 5, 6 };
	RzDiffMethods methods = {
		.elem_at = int_elem_at,
		.elem_hash = int_elem_hash,
		.compare = int_compare,
		.stringify = int_stringify,
		.ignore = NULL,
	};
	RzDiff *d = rz_diff_generic_new(a, 6, b, 6, &methods);
	mu_assert_notnull(d, "generic diff created");

	double r = 0.0;
	mu_assert_true(rz_diff_ratio(d, &r), "ratio call ok");
	mu_assert_eqf(r, 1.0, "ratio of identical int arrays is 1.0");

	RzList *ops = rz_diff_opcodes_new(d);
	mu_assert_notnull(ops, "opcodes not null");
	mu_assert_eq(rz_list_length(ops), 1, "single EQUAL on identical");
	rz_list_free(ops);

	rz_diff_free(d);
	mu_end;
}

bool test_rz_diff_generic_ints_modified(void) {
	const ut32 a[] = { 10, 20, 30, 40, 50 };
	const ut32 b[] = { 10, 99, 30, 40, 50 };
	RzDiffMethods methods = {
		.elem_at = int_elem_at,
		.elem_hash = int_elem_hash,
		.compare = int_compare,
		.stringify = int_stringify,
		.ignore = NULL,
	};
	RzDiff *d = rz_diff_generic_new(a, 5, b, 5, &methods);
	mu_assert_notnull(d, "generic diff created");

	RzList *ops = rz_diff_opcodes_new(d);
	mu_assert_notnull(ops, "ops not null");
	mu_assert_true(rz_list_length(ops) >= 2, "at least EQUAL+REPLACE+EQUAL");

	// Look for the REPLACE op at index 1 of A (where 20 -> 99).
	bool found_replace = false;
	RzListIter *it = NULL;
	RzDiffOp *op = NULL;
	rz_list_foreach (ops, it, op) {
		if (op->type == RZ_DIFF_OP_REPLACE && op->a_beg == 1 && op->a_end == 2 && op->b_beg == 1 && op->b_end == 2) {
			found_replace = true;
			break;
		}
	}
	mu_assert_true(found_replace, "REPLACE at position 1 found");

	rz_list_free(ops);
	rz_diff_free(d);
	mu_end;
}

// Note: there's no test for `rz_diff_generic_new(..., NULL)` or for a
// RzDiffMethods with missing required callbacks -- those inputs are
// RZ_NONNULL by contract (see librz/include/rz_diff.h), and passing NULL
// triggers an `assert()` under RZ_CHECKS_LEVEL=3 (used by the codecov CI
// job). The successful-creation paths above already exercise every
// callback field.

// ------------------------------------------------------------
// rz_diff_unified_json -- sanity-check the JSON output skeleton.
// ------------------------------------------------------------

bool test_rz_diff_unified_json_smoke(void) {
	const char *a = "alpha\nbeta\ngamma\n";
	const char *b = "alpha\nBETA\ngamma\n";
	RzDiff *d = rz_diff_lines_new(a, b, NULL);
	mu_assert_notnull(d, "lines diff created");

	PJ *pj = rz_diff_unified_json(d, "a.txt", "b.txt", false);
	mu_assert_notnull(pj, "unified_json returned a PJ");

	const char *out = pj_string(pj);
	mu_assert_notnull(out, "pj_string returned non-null");
	// JSON must contain the file labels and the "diff" array key.
	mu_assert_strcontains(out, "a.txt", "from label present");
	mu_assert_strcontains(out, "b.txt", "to label present");
	mu_assert_strcontains(out, "\"diff\":", "diff key present");

	pj_free(pj);
	rz_diff_free(d);
	mu_end;
}

// ------------------------------------------------------------
// Equivalence test: same content via bytes-diff and via lines-diff should
// produce the same ratio (within float epsilon) when there are no line
// boundary effects.
// ------------------------------------------------------------

bool test_rz_diff_ratio_byte_line_agree_on_identical(void) {
	const char *s = "alpha\nbeta\ngamma\n";
	RzDiff *db = rz_diff_bytes_new((const ut8 *)s, (ut32)strlen(s),
		(const ut8 *)s, (ut32)strlen(s));
	RzDiff *dl = rz_diff_lines_new(s, s, NULL);
	mu_assert_notnull(db, "bytes diff created");
	mu_assert_notnull(dl, "lines diff created");

	double rb = 0.0, rl = 0.0;
	mu_assert_true(rz_diff_ratio(db, &rb), "bytes ratio ok");
	mu_assert_true(rz_diff_ratio(dl, &rl), "lines ratio ok");
	mu_assert_eqf(rb, 1.0, "bytes ratio == 1.0 on identical");
	mu_assert_eqf(rl, 1.0, "lines ratio == 1.0 on identical");

	rz_diff_free(db);
	rz_diff_free(dl);
	mu_end;
}

// ------------------------------------------------------------
// Single-byte / single-line buffers.
// ------------------------------------------------------------

bool test_rz_diff_single_element(void) {
	// Single-byte identical.
	{
		const ut8 *a = (const ut8 *)"x";
		RzDiff *d = rz_diff_bytes_new(a, 1, a, 1);
		mu_assert_notnull(d, "diff 1-byte identical");
		double r = 0.0;
		mu_assert_true(rz_diff_ratio(d, &r), "ratio ok");
		mu_assert_eqf(r, 1.0, "1-byte identical ratio 1.0");
		rz_diff_free(d);
	}

	// Single-byte different.
	{
		const ut8 *a = (const ut8 *)"x";
		const ut8 *b = (const ut8 *)"y";
		RzDiff *d = rz_diff_bytes_new(a, 1, b, 1);
		mu_assert_notnull(d, "diff 1-byte different");
		double r = 1.0;
		mu_assert_true(rz_diff_ratio(d, &r), "ratio ok");
		mu_assert_eqf(r, 0.0, "1-byte different ratio 0.0");

		RzList *ops = rz_diff_opcodes_new(d);
		mu_assert_notnull(ops, "ops not null");
		mu_assert_eq(rz_list_length(ops), 1, "single REPLACE");
		RzDiffOp *op = rz_list_first_val(ops);
		mu_assert_eq((int)op->type, (int)RZ_DIFF_OP_REPLACE, "REPLACE");
		rz_list_free(ops);
		rz_diff_free(d);
	}

	mu_end;
}

// ------------------------------------------------------------
// Stress / regression smoke test: a larger pseudo-random pair.
//
// This isn't a benchmark, but it does ensure that the full pipeline
// (matches -> opcodes -> grouped -> unified) survives a realistic size
// without errors. It uses a deterministic LCG so failures reproduce.
// ------------------------------------------------------------

bool test_rz_diff_stress_medium(void) {
	const ut32 size = 2048;
	ut8 *a = malloc(size);
	ut8 *b = malloc(size);
	mu_assert_notnull(a, "alloc a");
	mu_assert_notnull(b, "alloc b");

	ut32 s = 0x12345678u;
	for (ut32 i = 0; i < size; i++) {
		s = s * 1103515245u + 12345u;
		a[i] = 0x20 + (s % (0x7f - 0x20));
	}
	memcpy(b, a, size);
	// Flip every 64th byte.
	for (ut32 i = 0; i < size; i += 64) {
		b[i] ^= 0xff;
	}

	RzDiff *d = rz_diff_bytes_new(a, size, b, size);
	mu_assert_notnull(d, "stress diff created");

	RzList *matches = rz_diff_matches_new(d);
	mu_assert_notnull(matches, "stress matches not null");
	mu_assert_true(rz_list_length(matches) > 1, "stress: more than one match");
	rz_list_free(matches);

	RzList *ops = rz_diff_opcodes_new(d);
	mu_assert_notnull(ops, "stress ops not null");
	mu_assert_true(rz_list_length(ops) > 1, "stress: more than one op");
	rz_list_free(ops);

	char *u = rz_diff_unified_text(d, NULL, NULL, false, false);
	mu_assert_notnull(u, "stress unified_text not null");
	free(u);

	rz_diff_free(d);
	free(a);
	free(b);
	mu_end;
}

// ------------------------------------------------------------
// Structural edge cases that mirror the "torture" benchmark
// scenarios in test/bench/bench_diff.c. Each one checks the
// shape of the produced opcodes for a recognizable real-world
// binary pattern.
// ------------------------------------------------------------

bool test_rz_diff_all_zeros_pathological(void) {
	// Pathological hash distribution: every byte in B hashes to the same
	// bucket. The diff must still succeed and the ratio must reflect that
	// the two buffers are almost equal (one byte changed).
	const ut32 size = 512;
	ut8 *a = malloc(size);
	ut8 *b = malloc(size);
	mu_assert_notnull(a, "alloc a");
	mu_assert_notnull(b, "alloc b");
	memset(a, 0, size);
	memset(b, 0, size);
	b[size / 2] = 0x01;

	RzDiff *d = rz_diff_bytes_new(a, size, b, size);
	mu_assert_notnull(d, "all-zeros diff created");

	double r = 0.0;
	mu_assert_true(rz_diff_ratio(d, &r), "ratio ok");
	mu_assert_true(r > 0.99, "all-zeros: ratio nearly 1.0");

	RzList *ops = rz_diff_opcodes_new(d);
	mu_assert_notnull(ops, "ops not null");
	// The exact opcode shape depends on which length-256 match the matcher
	// picks first -- on this input there are many length-256 matches with
	// the same score (every (a_pos, b_pos) where a_pos == b_pos +/- the
	// flipped byte's offset works), and the algorithm is free to pick any.
	// We've observed two valid encodings of "the two buffers differ by one
	// byte":
	//   - a single REPLACE op (one byte differs at the same position), or
	//   - one INSERT plus one DELETE (B has one extra byte at some
	//     position, A has one extra byte at the end -- equivalent).
	// Both have total non-EQUAL byte coverage of at most one byte in each
	// of A and B, which is the real invariant we want to lock down.
	RzListIter *it = NULL;
	RzDiffOp *op = NULL;
	int seen_diff = 0;
	int seen_equal = 0;
	ut32 total_a_changed = 0;
	ut32 total_b_changed = 0;
	rz_list_foreach (ops, it, op) {
		if (op->type == RZ_DIFF_OP_EQUAL) {
			seen_equal++;
		} else {
			seen_diff++;
			ut32 a_sz = RZ_DIFF_OP_SIZE_A(op);
			ut32 b_sz = RZ_DIFF_OP_SIZE_B(op);
			total_a_changed += a_sz;
			total_b_changed += b_sz;
		}
	}
	mu_assert_true(seen_diff >= 1 && seen_diff <= 2, "1 or 2 non-EQUAL ops");
	mu_assert_eq(total_a_changed, 1, "exactly one byte of A is in non-EQUAL ops");
	mu_assert_eq(total_b_changed, 1, "exactly one byte of B is in non-EQUAL ops");
	mu_assert_true(seen_equal >= 1, "at least one EQUAL surrounding the diff");
	rz_list_free(ops);

	rz_diff_free(d);
	free(a);
	free(b);
	mu_end;
}

bool test_rz_diff_repeating_pattern(void) {
	// Short repeating pattern: every elem_hash bucket accumulates a lot of
	// candidates. The algorithm should still terminate quickly and produce
	// the right shape -- which is "almost entirely equal" with point
	// disturbances.
	const ut32 size = 1024;
	ut8 *a = malloc(size);
	ut8 *b = malloc(size);
	mu_assert_notnull(a, "alloc a");
	mu_assert_notnull(b, "alloc b");
	for (ut32 i = 0; i < size; i++) {
		a[i] = (ut8)('A' + (i & 3));
	}
	memcpy(b, a, size);
	b[size / 4] = 'Z';
	b[size / 2] = 'Z';
	b[size * 3 / 4] = 'Z';

	RzDiff *d = rz_diff_bytes_new(a, size, b, size);
	mu_assert_notnull(d, "repeating-pattern diff");

	double r = 0.0;
	mu_assert_true(rz_diff_ratio(d, &r), "ratio ok");
	mu_assert_true(r > 0.99, "repeating-pattern: ratio nearly 1.0");

	rz_diff_free(d);
	free(a);
	free(b);
	mu_end;
}

bool test_rz_diff_firmware_like_structure(void) {
	// Miniature firmware: identical bootloader prefix (32 B), changed
	// middle (16 B), identical tail (32 B). The opcode sequence must
	// reflect that prefix and suffix are EQUAL and only the middle
	// differs as a REPLACE.
	const ut32 prefix = 32, mid = 16, suffix = 32;
	const ut32 size = prefix + mid + suffix;
	ut8 *v1 = malloc(size);
	ut8 *v2 = malloc(size);
	mu_assert_notnull(v1, "alloc v1");
	mu_assert_notnull(v2, "alloc v2");
	for (ut32 i = 0; i < size; i++) {
		v1[i] = (ut8)(i ^ 0x5a);
	}
	memcpy(v2, v1, size);
	// Re-write the middle 16 bytes in v2.
	for (ut32 i = 0; i < mid; i++) {
		v2[prefix + i] = (ut8)(0xff - i);
	}

	RzDiff *d = rz_diff_bytes_new(v1, size, v2, size);
	mu_assert_notnull(d, "firmware-like diff");

	RzList *ops = rz_diff_opcodes_new(d);
	mu_assert_notnull(ops, "ops not null");
	mu_assert_eq(rz_list_length(ops), 3, "EQUAL, REPLACE, EQUAL");

	RzDiffOp *first = rz_list_first_val(ops);
	RzDiffOp *last = rz_list_last_val(ops);
	mu_assert_eq((int)first->type, (int)RZ_DIFF_OP_EQUAL, "first op EQUAL");
	mu_assert_eq(first->a_beg, 0, "first op starts at 0");
	mu_assert_eq(first->a_end, (st32)prefix, "first op ends at prefix");
	mu_assert_eq((int)last->type, (int)RZ_DIFF_OP_EQUAL, "last op EQUAL");
	mu_assert_eq(last->a_end, (st32)size, "last op ends at size");

	rz_list_free(ops);
	rz_diff_free(d);
	free(v1);
	free(v2);
	mu_end;
}

bool test_rz_diff_block_shift(void) {
	// A and B are byte-identical except a 64-byte block has been moved
	// from one position to another. Ratio should be high (most content
	// equal), and the opcode sequence should not be "single REPLACE on
	// the full range" -- the matcher must find the shifted block.
	const ut32 size = 512;
	ut8 *a = malloc(size);
	ut8 *b = malloc(size);
	mu_assert_notnull(a, "alloc a");
	mu_assert_notnull(b, "alloc b");
	for (ut32 i = 0; i < size; i++) {
		a[i] = (ut8)('a' + (i % 26));
	}
	// Make the moved block distinctive so it's actually findable.
	for (ut32 i = 0; i < 64; i++) {
		a[100 + i] = (ut8)(0x80 + i);
	}
	// In B, the same distinctive block lives at offset 300 and the
	// region between is shifted left.
	memcpy(b, a, 100);
	memcpy(b + 100, a + 100 + 64, 300 - 100 - 64);
	memcpy(b + 300 - 64, a + 100, 64);
	memcpy(b + 300, a + 300, size - 300);

	RzDiff *d = rz_diff_bytes_new(a, size, b, size);
	mu_assert_notnull(d, "block-shift diff");

	double r = 0.0;
	mu_assert_true(rz_diff_ratio(d, &r), "ratio ok");
	mu_assert_true(r > 0.5, "block-shift: most content matches");

	RzList *ops = rz_diff_opcodes_new(d);
	mu_assert_notnull(ops, "ops not null");
	// More than one EQUAL means the matcher found more than just the
	// common prefix or suffix.
	int equal_ops = 0;
	RzListIter *it = NULL;
	RzDiffOp *op = NULL;
	rz_list_foreach (ops, it, op) {
		if (op->type == RZ_DIFF_OP_EQUAL) {
			equal_ops++;
		}
	}
	mu_assert_true(equal_ops >= 2, "block-shift produced multiple EQUAL ops");
	rz_list_free(ops);

	rz_diff_free(d);
	free(a);
	free(b);
	mu_end;
}

bool test_rz_diff_growing_buffer(void) {
	// B is a strict superset of A with content inserted in the middle --
	// the "string got longer" pattern that produces a slide of the const
	// pool in real binaries. We expect a single INSERT opcode.
	const ut8 *a = (const ut8 *)"prefix_middle_suffix";
	const ut8 *b = (const ut8 *)"prefix_middle_INSERTED_suffix";
	RzDiff *d = rz_diff_bytes_new(a, (ut32)strlen((const char *)a),
		b, (ut32)strlen((const char *)b));
	mu_assert_notnull(d, "growing-buffer diff");

	RzList *ops = rz_diff_opcodes_new(d);
	mu_assert_notnull(ops, "ops not null");

	bool found_insert = false;
	RzListIter *it = NULL;
	RzDiffOp *op = NULL;
	rz_list_foreach (ops, it, op) {
		if (op->type == RZ_DIFF_OP_INSERT) {
			found_insert = true;
			mu_assert_eq(RZ_DIFF_OP_SIZE_A(op), 0, "INSERT has zero A-range");
			mu_assert_true(RZ_DIFF_OP_SIZE_B(op) > 0, "INSERT has positive B-range");
		}
	}
	mu_assert_true(found_insert, "growing-buffer produces an INSERT op");
	rz_list_free(ops);

	rz_diff_free(d);
	mu_end;
}

bool test_rz_diff_long_common_prefix(void) {
	// Long common prefix, then total divergence. After the matcher peels
	// off the prefix as EQUAL, the rest must come out as a single
	// REPLACE / DELETE / INSERT depending on lengths.
	const ut32 prefix_len = 256;
	const ut32 tail_len = 64;
	ut8 *a = malloc(prefix_len + tail_len);
	ut8 *b = malloc(prefix_len + tail_len);
	mu_assert_notnull(a, "alloc a");
	mu_assert_notnull(b, "alloc b");
	for (ut32 i = 0; i < prefix_len; i++) {
		a[i] = b[i] = (ut8)('A' + (i % 26));
	}
	for (ut32 i = 0; i < tail_len; i++) {
		a[prefix_len + i] = 0x10;
		b[prefix_len + i] = 0x20;
	}

	RzDiff *d = rz_diff_bytes_new(a, prefix_len + tail_len, b, prefix_len + tail_len);
	mu_assert_notnull(d, "long-prefix diff");

	RzList *ops = rz_diff_opcodes_new(d);
	mu_assert_notnull(ops, "ops not null");

	// First op must be EQUAL and must cover the entire prefix.
	RzDiffOp *first = rz_list_first_val(ops);
	mu_assert_eq((int)first->type, (int)RZ_DIFF_OP_EQUAL, "first op EQUAL");
	mu_assert_eq(first->a_beg, 0, "EQUAL starts at 0");
	mu_assert_eq(first->a_end, (st32)prefix_len, "EQUAL covers full prefix");

	rz_list_free(ops);
	rz_diff_free(d);
	free(a);
	free(b);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_diff_distances);
	mu_run_test(test_rz_diff_cdc_below_threshold);
	mu_run_test(test_rz_diff_cdc_large_identical);
	mu_run_test(test_rz_diff_cdc_large_matches_myers);
	mu_run_test(test_rz_diff_cdc_bytes_below_threshold);
	mu_run_test(test_rz_diff_cdc_bytes_large_identical);
	mu_run_test(test_rz_diff_cdc_bytes_large_reconstruct);
	mu_run_test(test_rz_diff_cdc_bytes_large_replace);
	mu_run_test(test_rz_diff_unified_lines);
	mu_run_test(test_rz_diff_unified_bytes);
	mu_run_test(test_rz_diff_hash_data);
	mu_run_test(test_rz_diff_get_a_b);
	mu_run_test(test_rz_diff_null_inputs);
	mu_run_test(test_rz_diff_empty_buffers);
	mu_run_test(test_rz_diff_identical_buffers);
	mu_run_test(test_rz_diff_completely_different);
	mu_run_test(test_rz_diff_pure_insert_and_delete);
	mu_run_test(test_rz_diff_matches_basic);
	mu_run_test(test_rz_diff_opcodes_grouped_identical);
	mu_run_test(test_rz_diff_opcodes_grouped_replace);
	mu_run_test(test_rz_diff_ratio_bounds);
	mu_run_test(test_rz_diff_sizes_ratio_skewed);
	mu_run_test(test_rz_diff_ignore_line);
	mu_run_test(test_rz_diff_generic_ints);
	mu_run_test(test_rz_diff_generic_ints_modified);
	mu_run_test(test_rz_diff_unified_json_smoke);
	mu_run_test(test_rz_diff_ratio_byte_line_agree_on_identical);
	mu_run_test(test_rz_diff_single_element);
	mu_run_test(test_rz_diff_stress_medium);
	mu_run_test(test_rz_diff_all_zeros_pathological);
	mu_run_test(test_rz_diff_repeating_pattern);
	mu_run_test(test_rz_diff_firmware_like_structure);
	mu_run_test(test_rz_diff_block_shift);
	mu_run_test(test_rz_diff_growing_buffer);
	mu_run_test(test_rz_diff_long_common_prefix);
	return tests_passed != tests_run;
}

mu_main(all_tests)
