// SPDX-FileCopyrightText: 2020 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_id_storage_add0(void) {
	char *str = "lol";
	RzIDStorage *ids = rz_id_storage_new(5, 23);
	ut32 id;
	bool success = rz_id_storage_add(ids, str, &id);
	void *ptr = rz_id_storage_get(ids, id);
	rz_id_storage_free(ids);
	mu_assert("id_storage_add 0", success && (ptr == str));
	mu_end;
}

bool test_rz_id_storage_add1(void) {
	char *str = "lol";
	RzIDStorage *ids = rz_id_storage_new(0, 4);
	ut32 id;
	rz_id_storage_add(ids, str, &id);
	rz_id_storage_add(ids, str, &id);
	rz_id_storage_add(ids, str, &id);
	rz_id_storage_add(ids, str, &id);
	bool success = rz_id_storage_add(ids, str, &id);
	rz_id_storage_free(ids);
	mu_assert("id_storage_add 1", !success);
	mu_end;
}

bool test_rz_id_storage_set(void) {
	char *str = "lol";
	RzIDStorage *ids = rz_id_storage_new(5, 23);
	rz_id_storage_set(ids, str, 1);
	void *ptr = rz_id_storage_get(ids, 1);
	rz_id_storage_free(ids);
	mu_assert_ptreq(ptr, str, "id_storage_set");
	mu_end;
}

bool test_rz_id_storage_delete(void) {
	RzIDStorage *ids = rz_id_storage_new(5, 23);
	ut32 id;
	rz_id_storage_add(ids, "lol", &id);
	rz_id_storage_delete(ids, id);
	void *ptr = rz_id_storage_get(ids, id);
	rz_id_storage_free(ids);
	mu_assert_ptreq(ptr, NULL, "id_storage_delete");
	mu_end;
}

bool test_rz_id_storage_take0(void) {
	char *str = "lol";
	RzIDStorage *ids = rz_id_storage_new(5, 23);
	ut32 id;
	rz_id_storage_add(ids, str, &id);
	void *ptr = rz_id_storage_take(ids, id);
	rz_id_storage_free(ids);
	mu_assert_ptreq(ptr, str, "id_storage_take 0");
	mu_end;
}

bool test_rz_id_storage_take1(void) {
	char *str = "lol";
	RzIDStorage *ids = rz_id_storage_new(5, 23);
	ut32 id;
	rz_id_storage_add(ids, str, &id);
	rz_id_storage_take(ids, id);
	void *ptr = rz_id_storage_get(ids, id);
	rz_id_storage_free(ids);
	mu_assert_ptreq(ptr, NULL, "id_storage_take 1");
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_id_storage_add0);
	mu_run_test(test_rz_id_storage_add1);
	mu_run_test(test_rz_id_storage_set);
	mu_run_test(test_rz_id_storage_delete);
	mu_run_test(test_rz_id_storage_take0);
	mu_run_test(test_rz_id_storage_take1);
	return tests_passed != tests_run;
}

mu_main(all_tests)