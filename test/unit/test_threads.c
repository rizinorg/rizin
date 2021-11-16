// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_th.h>
#include "minunit.h"

bool test_thread_pool_cores(void) {
	size_t cores = rz_th_physical_core_number();

	RzThreadPool *pool = rz_th_pool_new(RZ_THREAD_POOL_ALL_CORES);
	mu_assert_notnull(pool, "rz_th_pool_new(RZ_THREAD_POOL_ALL_CORES) null check");
	mu_assert_eq(pool->size, cores, "rz_th_pool_new(RZ_THREAD_POOL_ALL_CORES) core count check");
	rz_th_pool_free(pool);

	if (cores > 1) {
		/* this can be tested only when cores are more than 1 */
		pool = rz_th_pool_new(cores - 1);
		mu_assert_notnull(pool, "rz_th_pool_new(cores - 1) null check");
		mu_assert_eq(pool->size, cores - 1, "rz_th_pool_new(cores - 1) core count check");
		rz_th_pool_free(pool);
	}

	mu_end;
}

int all_tests() {
	mu_run_test(test_thread_pool_cores);
	return tests_passed != tests_run;
}

mu_main(all_tests)
