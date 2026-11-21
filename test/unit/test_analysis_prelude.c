// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include "minunit.h"

static RzList /*<RzSearchKeyword *>*/ *masked_preludes(RzAnalysis *analysis) {
	RzList *l = rz_list_newf((RzListFree)rz_search_keyword_free);
	if (!l) {
		return NULL;
	}
	// masks ending in a full 8, 4 and single byte chunk
	rz_list_append(l, rz_search_keyword_new((const ut8 *)"\x03\xe0\x00\x21\x04\x11\x00\x00", 8, (const ut8 *)"\xff\xff\xff\xff\xff\xff\x00\x00", 8, NULL));
	rz_list_append(l, rz_search_keyword_new((const ut8 *)"\x2b\x60\x00\x00", 4, (const ut8 *)"\xff\xe0\x00\x00", 4, NULL));
	rz_list_append(l, rz_search_keyword_new((const ut8 *)"\xaa\xbb\x00", 3, (const ut8 *)"\xff\xff\xf0", 3, NULL));
	return l;
}

static RzAnalysisPlugin prelude_plugin = {
	.name = "prelude_test",
	.arch = "prelude_test",
	.bits = 32,
	.preludes = masked_preludes,
};

static bool is_prelude(RzAnalysis *analysis, const char *data, size_t len) {
	return rz_analysis_is_prelude(analysis, (const ut8 *)data, len);
}

static bool test_analysis_is_prelude_masked(void) {
	RzAnalysis *analysis = rz_analysis_new(NULL);
	mu_assert_notnull(analysis, "analysis");
	rz_analysis_plugin_add(analysis, &prelude_plugin);
	mu_assert_true(rz_analysis_use(analysis, "prelude_test"), "use plugin");

	mu_assert_true(is_prelude(analysis, "\x03\xe0\x00\x21\x04\x11\x12\x34", 8), "8-byte chunk masked");
	mu_assert_false(is_prelude(analysis, "\x03\xe0\x00\x21\x04\x12\x12\x34", 8), "8-byte chunk unmasked byte");
	mu_assert_true(is_prelude(analysis, "\x2b\x60\x30\x00", 4), "4-byte chunk masked");
	mu_assert_false(is_prelude(analysis, "\x2b\x80\x30\x00", 4), "4-byte chunk unmasked bits");
	mu_assert_true(is_prelude(analysis, "\xaa\xbb\x05", 3), "last byte masked");
	mu_assert_false(is_prelude(analysis, "\xaa\xbb\x15", 3), "last byte unmasked bits");

	rz_analysis_free(analysis);
	mu_end;
}

static int all_tests(void) {
	mu_run_test(test_analysis_is_prelude_masked);
	return tests_passed != tests_run;
}

mu_main(all_tests)
