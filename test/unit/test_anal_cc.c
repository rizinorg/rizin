#include <rz_anal.h>

#include "minunit.h"
#include "test_sdb.h"

static Sdb *ref_db() {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "cc.sectarian.ret", "rax", 0);
	sdb_set (db, "cc.sectarian.arg1", "rcx", 0);
	sdb_set (db, "cc.sectarian.arg0", "rdx", 0);
	sdb_set (db, "cc.sectarian.argn", "stack", 0);
	sdb_set (db, "sectarian", "cc", 0);
	return db;
}

static Sdb *ref_db_self_err() {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "cc.sectarian.ret", "rax", 0);
	sdb_set (db, "cc.sectarian.self", "rsi", 0);
	sdb_set (db, "cc.sectarian.error", "rdi", 0);
	sdb_set (db, "cc.sectarian.arg1", "rcx", 0);
	sdb_set (db, "cc.sectarian.arg0", "rdx", 0);
	sdb_set (db, "cc.sectarian.argn", "stack", 0);
	sdb_set (db, "sectarian", "cc", 0);
	return db;
}

static RzAnal *ref_anal() {
	RzAnal *anal = rz_anal_new ();
	rz_anal_cc_set (anal, "rax sectarian(rdx, rcx, stack)");
	return anal;
}

static RzAnal *ref_anal_self_err() {
	RzAnal *anal = rz_anal_new ();
	rz_anal_cc_set (anal, "rax sectarian(rdx, rcx, stack)");
	rz_anal_cc_set_self (anal, "sectarian", "rsi");
	rz_anal_cc_set_error (anal, "sectarian", "rdi");
	return anal;
}

bool test_r_anal_cc_set() {
	RzAnal *anal = ref_anal ();

	Sdb *ref = ref_db ();
	assert_sdb_eq (anal->sdb_cc, ref, "set cc");
	sdb_free (ref);

	rz_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_set_self_err() {
	RzAnal *anal = ref_anal_self_err ();

	Sdb *ref = ref_db_self_err ();
	assert_sdb_eq (anal->sdb_cc, ref, "set cc");
	sdb_free (ref);

	rz_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_get() {
	RzAnal *anal = ref_anal ();
	char *v = rz_anal_cc_get (anal, "sectarian");
	mu_assert_streq (v, "rax sectarian (rdx, rcx, stack);", "get cc");
	free (v);
	const char *vv = rz_anal_cc_self (anal, "sectarian");
	mu_assert_null (vv, "get self");
	vv = rz_anal_cc_error (anal, "sectarian");
	mu_assert_null (vv, "get error");
	rz_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_get_self_err() {
	RzAnal *anal = ref_anal_self_err ();
	char *v = rz_anal_cc_get (anal, "sectarian");
	mu_assert_streq (v, "rax rsi.sectarian (rdx, rcx, stack) rdi;", "get cc");
	free (v);
	const char *vv = rz_anal_cc_self (anal, "sectarian");
	mu_assert_streq (vv, "rsi", "get self");
	vv = rz_anal_cc_error (anal, "sectarian");
	mu_assert_streq (vv, "rdi", "get error");
	rz_anal_free (anal);
	mu_end;
}

bool test_r_anal_cc_del() {
	RzAnal *anal = ref_anal ();
	rz_anal_cc_del (anal, "sectarian");
	Sdb *ref = sdb_new0 ();
	assert_sdb_eq (anal->sdb_cc, ref, "deleted");
	sdb_free (ref);
	rz_anal_free (anal);
	mu_end;
}

bool all_tests() {
	mu_run_test (test_r_anal_cc_set);
	mu_run_test (test_r_anal_cc_set_self_err);
	mu_run_test (test_r_anal_cc_get);
	mu_run_test (test_r_anal_cc_get_self_err);
	mu_run_test (test_r_anal_cc_del);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
