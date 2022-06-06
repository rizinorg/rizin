// SPDX-FileCopyrightText: 2021 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmp.h>
#include "minunit.h"

char *data =
	"abcdefghijklmnopqrstuvwxyz"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwx"
	"ABCDEFGHIJKLMNOPQRSTUVWX";

char *la = "abcdefghijklmnopqrstuvwxyz";
char *ua = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

bool test_cmp_mem_mem(void) {
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

	cmp = rz_core_cmp_mem_mem(core, 0, 26, 26);
	mu_assert_notnull(cmp, "RzCompareData object null");
	mu_assert_eq(cmp->len, 26, "Incorrect length");
	mu_assert_eq(cmp->addr1, 0, "Incorrect addr1");
	mu_assert_eq(cmp->addr2, 26, "Incorrect addr2");
	mu_assert_memeq(cmp->data1, (ut8 *)la, 26, "Memory at offset 0 does not match");
	mu_assert_memeq(cmp->data2, (ut8 *)ua, 26, "Memory at offset 26 does not match");
	mu_assert_eq(cmp->same, false, "Memory same");
	rz_core_cmp_free(cmp);

	cmp = rz_core_cmp_mem_mem(core, 26, 76, 26);
	mu_assert_null(cmp, "RzCompareData not null");
	rz_core_cmp_free(cmp);

	rz_core_free(core);

	mu_end;
}

bool test_cmp_mem_data(void) {
	RzCore *core = rz_core_new();
	rz_io_open(core->io, "malloc://100", RZ_PERM_RW, 0);
	rz_io_write(core->io, (ut8 *)data, 100);

	RzCompareData *cmp = rz_core_cmp_mem_data(core, 52, (ut8 *)la, 24);
	mu_assert_notnull(cmp, "RzCompareData object null");
	mu_assert_eq(cmp->len, 24, "Incorrect length");
	mu_assert_eq(cmp->addr1, 52, "Incorrect addr1");
	mu_assert_eq(cmp->addr2, UT64_MAX, "Incorrect addr2");
	mu_assert_memeq(cmp->data1, (ut8 *)la, 24, "Memory at offset 52 does not match");
	mu_assert_memeq(cmp->data2, (ut8 *)la, 24, "Data does not match");
	mu_assert_eq(cmp->same, true, "Memory not same");
	rz_core_cmp_free(cmp);

	cmp = rz_core_cmp_mem_data(core, 26, (ut8 *)la, 26);
	mu_assert_notnull(cmp, "RzCompareData object null");
	mu_assert_eq(cmp->len, 26, "Incorrect length");
	mu_assert_eq(cmp->addr1, 26, "Incorrect addr1");
	mu_assert_eq(cmp->addr2, UT64_MAX, "Incorrect addr2");
	mu_assert_memeq(cmp->data1, (ut8 *)ua, 26, "Memory at offset 26 does not match");
	mu_assert_memeq(cmp->data2, (ut8 *)la, 26, "Data does not match");
	mu_assert_eq(cmp->same, false, "Memory same");
	rz_core_cmp_free(cmp);

	cmp = rz_core_cmp_mem_data(core, 76, (ut8 *)ua, 26);
	mu_assert_null(cmp, "RzCompareData not null");
	rz_core_cmp_free(cmp);

	rz_core_free(core);

	mu_end;
}

int all_tests() {
	mu_run_test(test_cmp_mem_mem);
	mu_run_test(test_cmp_mem_data);

	return tests_run != tests_passed;
}

mu_main(all_tests);
