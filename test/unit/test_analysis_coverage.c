// SPDX-FileCopyrightText: 2025 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_analysis.h>
#include <rz_core.h>
#include <rz_io.h>

#include "minunit.h"

bool test_code_size_vs_coverage(void) {

	RzCore *r = rz_core_new();
	bool io_open1 = rz_io_open(r->io, "malloc://0x100", RZ_PERM_R, 0);
	bool io_open2 = rz_io_open(r->io, "malloc://0x50", RZ_PERM_X | RZ_PERM_RW, 0);
	mu_assert("Failed to open executable memory region", io_open1);
	mu_assert("Failed to open read-only memory region", io_open2);

	ut8 codes[] = { 0x90, 0x90, 0x90, 0xC3 }; // NOP NOP NOP RET (simple function)
	bool written = rz_io_write_at(r->io, 0x10, codes, sizeof(codes));
	mu_assert("Failed to write instructions to memory", written);

	bool meta_set = rz_meta_set(r->analysis, RZ_META_TYPE_DATA, 0x10, 0x60, "some random data");
	mu_assert("Failed to set metadata", meta_set);

	rz_core_analysis_all(r);

	long long int code = rz_core_analysis_code_count(r);
	mu_assert("Code size should be non-negative", code >= 0);

	long long int cov = rz_core_analysis_coverage_count(r);
	mu_assert("Coverage should be non-negative", cov >= 0);

	mu_assert("Coverage exceeded code size", cov <= code);

	rz_core_free(r);
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_code_size_vs_coverage);
	return tests_passed != tests_run;
}

mu_main(all_tests);
