// SPDX-FileCopyrightText: 2025 sl4y3r-07 <ayush_g@ee.iitr.ac.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "minunit.h"
#include <rz_syscall.h>

bool test_rz_syscall_get_num(void) {
	RzSyscall s = { 0 };
	Sdb *db = sdb_new(NULL, NULL, false);
	s.db = db;

	sdb_set(db, "_", "0");
	sdb_array_push(db, "foo", "5");
	sdb_array_push(db, "foo", "6");
	sdb_array_push(db, "foo", "7");

	int num = 0;
	bool ok = rz_syscall_get_num(&s, "foo", &num);
	mu_assert_true(ok, "rz_syscall_get_num should return true");
	mu_assert_eq(num, 6, "Expected syscall number 6");

	sdb_free(db);
	mu_end;
}

bool test_rz_syscall_get_num_negative_base(void) {
	RzSyscall s = { 0 };
	Sdb *db = sdb_new(NULL, NULL, false);
	s.db = db;

	sdb_set(db, "_", "-1");
	sdb_array_push(db, "foo", "5");
	sdb_array_push(db, "foo", "6");
	sdb_array_push(db, "foo", "7");

	int num = 0;
	bool ok = rz_syscall_get_num(&s, "foo", &num);
	mu_assert_true(ok, "rz_syscall_get_num should return true");
	mu_assert_eq(num, 7, "Expected syscall number 7");

	sdb_free(db);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_syscall_get_num);
	mu_run_test(test_rz_syscall_get_num_negative_base);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}