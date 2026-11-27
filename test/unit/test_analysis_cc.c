// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "analysis_private.h"

#include "minunit.h"
#include "test_sdb.h"

static Sdb *ref_db() {
	Sdb *db = sdb_new0();
	sdb_set(db, "cc.sectarian.ret", "rax");
	sdb_set(db, "cc.sectarian.arg1", "rcx");
	sdb_set(db, "cc.sectarian.arg0", "rdx");
	sdb_set(db, "cc.sectarian.argn", "stack");
	sdb_set(db, "cc.sectarian.maxargs", "2");
	sdb_set(db, "sectarian", "cc");
	return db;
}

static Sdb *ref_db_self_err() {
	Sdb *db = sdb_new0();
	sdb_set(db, "cc.sectarian.ret", "rax");
	sdb_set(db, "cc.sectarian.self", "rsi");
	sdb_set(db, "cc.sectarian.error", "rdi");
	sdb_set(db, "cc.sectarian.arg1", "rcx");
	sdb_set(db, "cc.sectarian.arg0", "rdx");
	sdb_set(db, "cc.sectarian.argn", "stack");
	sdb_set(db, "cc.sectarian.maxargs", "2");
	sdb_set(db, "sectarian", "cc");
	return db;
}

static RzAnalysis *ref_analysis() {
	RzAnalysis *analysis = rz_analysis_new(NULL);
	rz_analysis_cc_set(analysis, "rax sectarian(rdx, rcx, stack)");
	return analysis;
}

static RzAnalysis *ref_analysis_self_err() {
	RzAnalysis *analysis = rz_analysis_new(NULL);
	rz_analysis_cc_set(analysis, "rax sectarian(rdx, rcx, stack)");
	rz_analysis_cc_set_self(analysis, "sectarian", "rsi");
	rz_analysis_cc_set_error(analysis, "sectarian", "rdi");
	return analysis;
}

bool test_rz_analysis_cc_set() {
	RzAnalysis *analysis = ref_analysis();
	Sdb *analysis_cc = rz_analysis_get_sdb_cc(analysis);

	Sdb *ref = ref_db();
	assert_sdb_eq(analysis_cc, ref, "set cc");
	sdb_free(ref);

	mu_assert_true(rz_analysis_cc_set(analysis, "rax empty()"), "set empty cc");
	mu_assert_eq(rz_analysis_cc_max_arg(analysis, "empty"), 0, "empty cc has no arguments");
	mu_assert_null(rz_analysis_cc_arg(analysis, "empty", 0), "empty cc has no argument register");
	mu_assert_true(rz_analysis_cc_set(analysis, "rax spaces(   )"), "set whitespace-only cc");
	mu_assert_eq(rz_analysis_cc_max_arg(analysis, "spaces"), 0, "whitespace is not an argument");
	mu_assert_true(rz_analysis_cc_set(analysis, "rax stack_only(stack)"), "set stack-only cc");
	mu_assert_eq(rz_analysis_cc_max_arg(analysis, "stack_only"), 0, "stack is not a register argument");
	mu_assert_streq(rz_analysis_cc_arg(analysis, "stack_only", 0), "stack", "stack fallback");

	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_cc_set_self_err() {
	RzAnalysis *analysis = ref_analysis_self_err();
	Sdb *analysis_cc = rz_analysis_get_sdb_cc(analysis);

	Sdb *ref = ref_db_self_err();
	assert_sdb_eq(analysis_cc, ref, "set cc");
	sdb_free(ref);

	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_cc_get() {
	RzAnalysis *analysis = ref_analysis();
	char *v = rz_analysis_cc_get(analysis, "sectarian");
	mu_assert_streq(v, "rax sectarian (rdx, rcx, stack);", "get cc");
	free(v);
	const char *vv = rz_analysis_cc_self(analysis, "sectarian");
	mu_assert_null(vv, "get self");
	vv = rz_analysis_cc_error(analysis, "sectarian");
	mu_assert_null(vv, "get error");
	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_cc_get_self_err() {
	RzAnalysis *analysis = ref_analysis_self_err();
	char *v = rz_analysis_cc_get(analysis, "sectarian");
	mu_assert_streq(v, "rax rsi.sectarian (rdx, rcx, stack) rdi;", "get cc");
	free(v);
	const char *vv = rz_analysis_cc_self(analysis, "sectarian");
	mu_assert_streq(vv, "rsi", "get self");
	vv = rz_analysis_cc_error(analysis, "sectarian");
	mu_assert_streq(vv, "rdi", "get error");
	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_cc_del() {
	RzAnalysis *analysis = ref_analysis();
	Sdb *analysis_cc = rz_analysis_get_sdb_cc(analysis);
	rz_analysis_cc_del(analysis, "sectarian");
	Sdb *ref = sdb_new0();
	assert_sdb_eq(analysis_cc, ref, "deleted");
	sdb_free(ref);
	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_cc_args_and_long_name(void) {
	RzAnalysis *analysis = rz_analysis_new(NULL);
	mu_assert_notnull(analysis, "rz_analysis_new");
	mu_assert_true(rz_analysis_cc_set(analysis,
			       "rax many(r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, stack)"),
		"set 12-arg cc");
	mu_assert_eq(rz_analysis_cc_max_arg(analysis, "many"), 12, "max_arg");
	mu_assert_streq(rz_analysis_cc_ret(analysis, "many"), "rax", "ret");
	mu_assert_streq(rz_analysis_cc_arg(analysis, "many", 0), "r0", "arg0");
	mu_assert_streq(rz_analysis_cc_arg(analysis, "many", 9), "r9", "arg9");
	mu_assert_streq(rz_analysis_cc_arg(analysis, "many", 10), "r10", "arg10");
	mu_assert_streq(rz_analysis_cc_arg(analysis, "many", 11), "r11", "arg11");
	mu_assert_streq(rz_analysis_cc_arg(analysis, "many", 12), "stack", "argn fallback");

	// Exercise heap fallback for calling convention names longer than the stack key buffer
	char long_name[260];
	memset(long_name, 'c', sizeof(long_name) - 1);
	long_name[sizeof(long_name) - 1] = '\0';
	char *expr = rz_str_newf("rax %s(rdi, rsi, stack)", long_name);
	mu_assert_notnull(expr, "long expr");
	mu_assert_true(rz_analysis_cc_set(analysis, expr), "set long cc");
	free(expr);
	mu_assert_eq(rz_analysis_cc_max_arg(analysis, long_name), 2, "long max_arg");
	mu_assert_streq(rz_analysis_cc_ret(analysis, long_name), "rax", "long ret");
	mu_assert_streq(rz_analysis_cc_arg(analysis, long_name, 0), "rdi", "long arg0");
	mu_assert_streq(rz_analysis_cc_arg(analysis, long_name, 2), "stack", "long argn");

	rz_analysis_free(analysis);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_analysis_cc_set);
	mu_run_test(test_rz_analysis_cc_set_self_err);
	mu_run_test(test_rz_analysis_cc_get);
	mu_run_test(test_rz_analysis_cc_get_self_err);
	mu_run_test(test_rz_analysis_cc_del);
	mu_run_test(test_rz_analysis_cc_args_and_long_name);
	return tests_passed != tests_run;
}

mu_main(all_tests)
