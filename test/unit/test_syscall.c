// SPDX-FileCopyrightText: 2025 sl4y3r-07 <ayush_g@ee.iitr.ac.in>
// SPDX-FileCopyrightText: 2026 Abdallh <abdallhdawi3@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "minunit.h"
#include <rz_core.h>
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

bool test_rz_syscall_get_num_null_db(void) {
	RzSyscall s = { 0 };
	s.db = NULL;

	int num = 999;
	bool ok = rz_syscall_get_num(&s, "stat", &num);
	mu_assert_false(ok, "rz_syscall_get_num should return false when db is NULL");
	mu_assert_eq(num, 999, "num should not be modified when db is NULL");

	mu_end;
}

bool test_rz_syscall_arm_linux(void) {
	RzSyscall s = { 0 };
	Sdb *db = sdb_new(NULL, NULL, false);
	s.db = db;

	sdb_set(db, "_", "0x900000");
	sdb_set(db, "0x900000.4", "write");
	sdb_set(db, "write", "0x900000,4,3,fd,buf,count");
	sdb_set(db, "0x900000.0", "read");
	sdb_set(db, "read", "0x900000,0,3,fd,buf,count");

	RzSyscallItem *item = rz_syscall_get(&s, 4, -1);
	mu_assert_notnull(item, "Should find ARM syscall 4");
	mu_assert_streq(item->name, "write", "ARM syscall 4 should be 'write'");
	mu_assert_eq(item->swi, 0x900000, "ARM syscall swi should be 0x900000");

	rz_syscall_item_free(item);
	sdb_free(db);
	mu_end;
}

bool test_rz_syscall_mips_linux(void) {
	RzSyscall s = { 0 };
	Sdb *db = sdb_new(NULL, NULL, false);
	s.db = db;

	sdb_set(db, "_", "5000");
	sdb_set(db, "0x1388.4001", "read");
	sdb_set(db, "read", "5000,4001,3,fd,buf,count");
	sdb_set(db, "0x1388.4004", "write");
	sdb_set(db, "write", "5000,4004,3,fd,buf,count");

	RzSyscallItem *item = rz_syscall_get(&s, 4001, -1);
	mu_assert_notnull(item, "Should find MIPS syscall 4001");
	mu_assert_streq(item->name, "read", "MIPS syscall 4001 should be 'read'");
	mu_assert_eq(item->swi, 5000, "MIPS syscall swi should be 5000");

	rz_syscall_item_free(item);
	sdb_free(db);
	mu_end;
}

bool test_rz_syscall_arm64_linux(void) {
	RzSyscall s = { 0 };
	Sdb *db = sdb_new(NULL, NULL, false);
	s.db = db;

	sdb_set(db, "_", "0");
	sdb_set(db, "0.64", "read");
	sdb_set(db, "read", "0,64,3,fd,buf,count");
	sdb_set(db, "0.65", "write");
	sdb_set(db, "write", "0,65,3,fd,buf,count");

	RzSyscallItem *item = rz_syscall_get(&s, 64, -1);
	mu_assert_notnull(item, "Should find ARM64 syscall 64");
	mu_assert_streq(item->name, "read", "ARM64 syscall 64 should be 'read'");

	rz_syscall_item_free(item);
	sdb_free(db);
	mu_end;
}

bool test_rz_core_syscall_as_string_valid_number(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new should succeed");

	RzSyscall *sc = rz_syscall_new();
	mu_assert_notnull(sc, "rz_syscall_new should succeed");

	sdb_set(sc->db, "_", "0");
	sdb_set(sc->db, "0.3", "read");
	sdb_set(sc->db, "read", "0,3,3,fd,buf,count");
	sdb_set(sc->db, "0.4", "write");
	sdb_set(sc->db, "write", "0,4,3,fd,buf,count");

	rz_analysis_set_syscall(core->analysis, sc);

	char *result = rz_core_syscall_as_string(core, 3, 0);
	mu_assert_notnull(result, "rz_core_syscall_as_string should return a result");
	mu_assert_strcontains(result, "read", "result should contain 'read'");

	free(result);
	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_syscall_get_num);
	mu_run_test(test_rz_syscall_get_num_negative_base);
	mu_run_test(test_rz_syscall_get_num_null_db);
	mu_run_test(test_rz_syscall_arm_linux);
	mu_run_test(test_rz_syscall_arm64_linux);
	mu_run_test(test_rz_syscall_mips_linux);
	mu_run_test(test_rz_core_syscall_as_string_valid_number);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
