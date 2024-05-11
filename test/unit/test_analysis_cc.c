// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

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
	RzAnalysis *analysis = rz_analysis_new();
	rz_analysis_cc_set(analysis, "rax sectarian(rdx, rcx, stack)");
	return analysis;
}

static RzAnalysis *ref_analysis_self_err() {
	RzAnalysis *analysis = rz_analysis_new();
	rz_analysis_cc_set(analysis, "rax sectarian(rdx, rcx, stack)");
	rz_analysis_cc_set_self(analysis, "sectarian", "rsi");
	rz_analysis_cc_set_error(analysis, "sectarian", "rdi");
	return analysis;
}

bool test_rz_analysis_cc_set() {
	RzAnalysis *analysis = ref_analysis();

	Sdb *ref = ref_db();
	assert_sdb_eq(analysis->sdb_cc, ref, "set cc");
	sdb_free(ref);

	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_cc_set_self_err() {
	RzAnalysis *analysis = ref_analysis_self_err();

	Sdb *ref = ref_db_self_err();
	assert_sdb_eq(analysis->sdb_cc, ref, "set cc");
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
	rz_analysis_cc_del(analysis, "sectarian");
	Sdb *ref = sdb_new0();
	assert_sdb_eq(analysis->sdb_cc, ref, "deleted");
	sdb_free(ref);
	rz_analysis_free(analysis);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_analysis_cc_set);
	mu_run_test(test_rz_analysis_cc_set_self_err);
	mu_run_test(test_rz_analysis_cc_get);
	mu_run_test(test_rz_analysis_cc_get_self_err);
	mu_run_test(test_rz_analysis_cc_del);
	return tests_passed != tests_run;
}

mu_main(all_tests)
