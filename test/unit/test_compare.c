// SPDX-FileCopyrightText: 2021 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmp.h>
#include "minunit.h"

char *data = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxABCDEFGHIJKLMNOPQRSTUVWX";
char *la = "abcdefghijklmnopqrstuvwxyz";
char *ua = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
char *la1 = "abcdefghijklmnopqrstuvwx";
char *ua1 = "ABCDEFGHIJKLMNOPQRSTUVWX";

bool test_cmp_data(void) {
	RzCore *core = rz_core_new();
	rz_io_open(core->io, "malloc://100", RZ_PERM_RW, 0);
	rz_io_write(core->io, (ut8 *)data, 100);

	RzCompareData *cmp = rz_core_cmp_mem_mem(core, 0, 52, 24);
	mu_assert_notnull(cmp, "RzCompareData object null");
	mu_assert_eq(cmp->len, 24, "Incorrect length");
	mu_assert_eq(cmp->addr1, 0, "Incorrect addr1");
	mu_assert_eq(cmp->addr2, 52, "Incorrect addr2");
	mu_assert_memeq(cmp->data1, (ut8 *)la, 24, "Memory at offset 0 does not match");
	mu_assert_memeq(cmp->data2, (ut8 *)la, 24, "Memory at offset 52 does not match");
	mu_assert_eq(cmp->same, true, "Memory not same");
	rz_core_cmp_free(cmp);

	mu_end;
}

int all_tests() {
	mu_run_test(test_cmp_data);

	return tests_run != tests_passed;
}

mu_main(all_tests);
