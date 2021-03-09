// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include "minunit.h"

#include "test_analysis_block_invars.inl"

bool ht_up_count(void *user, const ut64 k, const void *v) {
	size_t *count = user;
	(*count)++;
	return true;
}

bool ht_pp_count(void *user, const void *k, const void *v) {
	size_t *count = user;
	(*count)++;
	return true;
}

static bool function_check_invariants(RzAnalysis *analysis) {
	if (!block_check_invariants(analysis)) {
		return false;
	}

	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (analysis->fcns, it, fcn) {
		mu_assert_ptreq(ht_up_find(analysis->ht_addr_fun, fcn->addr, NULL), fcn, "function in addr ht");
		mu_assert_ptreq(ht_pp_find(analysis->ht_name_fun, fcn->name, NULL), fcn, "function in name ht");
	}

	size_t addr_count = 0;
	ht_up_foreach(analysis->ht_addr_fun, ht_up_count, &addr_count);
	mu_assert_eq(addr_count, rz_list_length(analysis->fcns), "function addr ht count");

	size_t name_count = 0;
	ht_pp_foreach(analysis->ht_name_fun, ht_pp_count, &name_count);
	mu_assert_eq(name_count, rz_list_length(analysis->fcns), "function name ht count");

	return true;
}

#define check_invariants function_check_invariants
#define check_leaks      block_check_leaks

#define assert_invariants(analysis) \
	do { \
		if (!check_invariants(analysis)) { \
			return false; \
		} \
	} while (0)
#define assert_leaks(analysis) \
	do { \
		if (!check_leaks(analysis)) { \
			return false; \
		} \
	} while (0)

bool test_rz_analysis_function_relocate() {
	RzAnalysis *analysis = rz_analysis_new();
	assert_invariants(analysis);

	RzAnalysisFunction *fa = rz_analysis_create_function(analysis, "do_something", 0x1337, 0, NULL);
	assert_invariants(analysis);
	RzAnalysisFunction *fb = rz_analysis_create_function(analysis, "do_something_else", 0xdeadbeef, 0, NULL);
	assert_invariants(analysis);
	rz_analysis_create_function(analysis, "do_something_different", 0xc0ffee, 0, NULL);
	assert_invariants(analysis);

	bool success = rz_analysis_function_relocate(fa, fb->addr);
	assert_invariants(analysis);
	mu_assert_false(success, "failed relocate");
	mu_assert_eq(fa->addr, 0x1337, "failed relocate addr");

	success = rz_analysis_function_relocate(fa, 0x1234);
	assert_invariants(analysis);
	mu_assert_true(success, "successful relocate");
	mu_assert_eq(fa->addr, 0x1234, "successful relocate addr");

	assert_leaks(analysis);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_function_labels() {
	RzAnalysis *analysis = rz_analysis_new();

	RzAnalysisFunction *f = rz_analysis_create_function(analysis, "do_something", 0x1337, 0, NULL);

	bool s = rz_analysis_function_set_label(f, "smartfriend", 0x1339);
	mu_assert_true(s, "set label");
	s = rz_analysis_function_set_label(f, "stray", 0x133c);
	mu_assert_true(s, "set label");
	s = rz_analysis_function_set_label(f, "the", 0x1340);
	mu_assert_true(s, "set label");
	s = rz_analysis_function_set_label(f, "stray", 0x1234);
	mu_assert_false(s, "set label (existing name)");
	s = rz_analysis_function_set_label(f, "henlo", 0x133c);
	mu_assert_false(s, "set label (existing addr)");

	ut64 addr = rz_analysis_function_get_label(f, "smartfriend");
	mu_assert_eq(addr, 0x1339, "get label");
	addr = rz_analysis_function_get_label(f, "stray");
	mu_assert_eq(addr, 0x133c, "get label");
	addr = rz_analysis_function_get_label(f, "skies");
	mu_assert_eq(addr, UT64_MAX, "get label (unknown)");

	const char *name = rz_analysis_function_get_label_at(f, 0x1339);
	mu_assert_streq(name, "smartfriend", "get label at");
	name = rz_analysis_function_get_label_at(f, 0x133c);
	mu_assert_streq(name, "stray", "get label at");
	name = rz_analysis_function_get_label_at(f, 0x1234);
	mu_assert_null(name, "get label at (unknown)");

	rz_analysis_function_delete_label(f, "stray");
	addr = rz_analysis_function_get_label(f, "stray");
	mu_assert_eq(addr, UT64_MAX, "get label (deleted)");
	name = rz_analysis_function_get_label_at(f, 0x133c);
	mu_assert_null(name, "get label at (deleted)");
	addr = rz_analysis_function_get_label(f, "smartfriend");
	mu_assert_eq(addr, 0x1339, "get label (unaffected by delete)");
	name = rz_analysis_function_get_label_at(f, 0x1339);
	mu_assert_streq(name, "smartfriend", "get label at (unaffected by delete)");

	rz_analysis_function_delete_label_at(f, 0x1340);
	addr = rz_analysis_function_get_label(f, "the");
	mu_assert_eq(addr, UT64_MAX, "get label (deleted)");
	name = rz_analysis_function_get_label_at(f, 0x340);
	mu_assert_null(name, "get label at (deleted)");
	addr = rz_analysis_function_get_label(f, "smartfriend");
	mu_assert_eq(addr, 0x1339, "get label (unaffected by delete)");
	name = rz_analysis_function_get_label_at(f, 0x1339);
	mu_assert_streq(name, "smartfriend", "get label at (unaffected by delete)");

	rz_analysis_free(analysis);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_analysis_function_relocate);
	mu_run_test(test_rz_analysis_function_labels);
	return tests_passed != tests_run;
}

mu_main(all_tests)