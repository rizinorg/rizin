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
	printf("\n\n%s\n\n", expected);

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
		"@@ -1,3 +1,99 @@\n"
		"+5468697320697320616e20696d706f7274616e740a6e6f746963652120497420\n"
		"+73686f756c640a7468657265666f7265206265206c6f63617465642061740a74\n"
		"+686520626567696e6e696e67206f6620746869730a646f63756d656e74210a0a\n"
		" 546869\n"
		"@@ -190,93 +286,6 @@\n"
		" 2e0a0a\n"
		"-546869732070617261677261706820636f6e7461696e730a7465787420746861\n"
		"-74206973206f757464617465642e0a49742077696c6c2062652064656c657465\n"
		"-6420696e207468650a6e656172206675747572652e0a0a\n"
		" 497420\n"
		"@@ -315,7 +324,7 @@\n"
		" 20646f\n"
		"-6b\n"
		"+63\n"
		" 756d65\n"
		"@@ -476,3 +485,70 @@\n"
		" 69742e\n"
		"+0a0a546869732070617261677261706820636f6e7461696e730a696d706f7274\n"
		"+616e74206e6577206164646974696f6e730a746f207468697320646f63756d65\n"
		"+6e742e\n";
	// clang-format on

	diff = rz_diff_bytes_new((const ut8 *)a, strlen(a), (const ut8 *)b, strlen(b), NULL);
	result = rz_diff_unified_text(diff, NULL, NULL, false, false);
	rz_diff_free(diff);
	mu_assert_notnull(result, "rz_diff_unified result not null");
	mu_assert_streq(result, expected, "rz_diff_unified on bytes");
	free(result);

	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_diff_distances);
	mu_run_test(test_rz_diff_unified_lines);
	mu_run_test(test_rz_diff_unified_bytes);
	return tests_passed != tests_run;
}

mu_main(all_tests)
