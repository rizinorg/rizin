// SPDX-FileCopyrightText: 2020 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

static bool test_rz_id_pool_broken_parameters(void) {
	mu_assert_ptreq(rz_id_pool_new(42, 3), NULL, "broken parameters");
	mu_end;
}

static bool test_rz_id_pool_start_id(void) {
	RzIDPool *pool = rz_id_pool_new(3, 42);
	ut32 grabbed;
	rz_id_pool_grab_id(pool, &grabbed);
	rz_id_pool_free(pool);
	mu_assert_eq(grabbed, 3, "start_id");
	mu_end;
}

static bool test_rz_id_pool_id_reuse0(void) {
	RzIDPool *pool = rz_id_pool_new(3, 42);
	ut32 grabbed[3];
	rz_id_pool_grab_id(pool, &grabbed[0]);
	rz_id_pool_grab_id(pool, &grabbed[1]);
	rz_id_pool_kick_id(pool, grabbed[0]);
	rz_id_pool_grab_id(pool, &grabbed[2]);
	rz_id_pool_free(pool);
	mu_assert_eq(grabbed[0], grabbed[2], "id_reuse0");
	mu_end;
}

static bool test_rz_id_pool_id_reuse1(void) {
	RzIDPool *pool = rz_id_pool_new(3, 42);
	ut32 grabbed[3];
	rz_id_pool_grab_id(pool, &grabbed[0]);
	rz_id_pool_grab_id(pool, &grabbed[1]);
	rz_id_pool_kick_id(pool, grabbed[1]);
	rz_id_pool_grab_id(pool, &grabbed[2]);
	rz_id_pool_free(pool);
	mu_assert_eq(grabbed[1], grabbed[2], "id_reuse1");
	mu_end;
}

static bool test_rz_id_pool_id_unique(void) {
	RzIDPool *pool = rz_id_pool_new(3, 42);
	ut32 grabbed[2];
	rz_id_pool_grab_id(pool, &grabbed[0]);
	rz_id_pool_grab_id(pool, &grabbed[1]);
	rz_id_pool_free(pool);
	mu_assert_neq(grabbed[0], grabbed[1], "id_unique");
	mu_end;
}

static bool test_rz_id_pool_id_end_of_pool(void) {
	RzIDPool *pool = rz_id_pool_new(0, 1);
	ut32 grabbed;
	rz_id_pool_grab_id(pool, &grabbed);
	rz_id_pool_grab_id(pool, &grabbed);
	const bool result = rz_id_pool_grab_id(pool, &grabbed);
	rz_id_pool_free(pool);
	mu_assert_false(result, "id_end_of_pool");
	mu_end;
}

static bool test_rz_id_pool_initial_pattern(void) {
	RzIDPool *pool = rz_id_pool_new(3, 42);
	ut32 grabbed[3];
	rz_id_pool_grab_id(pool, &grabbed[0]);
	rz_id_pool_grab_id(pool, &grabbed[1]);
	rz_id_pool_grab_id(pool, &grabbed[2]);
	rz_id_pool_free(pool);
	mu_assert_true(grabbed[0] < grabbed[1] && grabbed[1] < grabbed[2], "initial_pattern");
	mu_end;
}

static int all_tests(void) {
	mu_run_test(test_rz_id_pool_broken_parameters);
	mu_run_test(test_rz_id_pool_start_id);
	mu_run_test(test_rz_id_pool_id_reuse0);
	mu_run_test(test_rz_id_pool_id_reuse1);
	mu_run_test(test_rz_id_pool_id_unique);
	mu_run_test(test_rz_id_pool_id_end_of_pool);
	mu_run_test(test_rz_id_pool_initial_pattern);
	return tests_passed != tests_run;
}

mu_main(all_tests)