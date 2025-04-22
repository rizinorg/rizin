// SPDX-FileCopyrightText: 2025 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_mem_align_padding(void) {
	mu_assert_eq(rz_mem_align_padding(0x0, 0), UT64_MAX, "Error case failed.");
	mu_assert_eq(rz_mem_align_padding(0x0, 3), UT64_MAX, "Error case failed.");
	mu_assert_eq(rz_mem_align_padding(0x0, UT64_MAX), UT64_MAX, "Error case failed.");

	mu_assert_eq(rz_mem_align_padding(0x0, 1), 0, "Padding mismatch.");
	mu_assert_eq(rz_mem_align_padding(0x1, 1), 0, "Padding mismatch.");
	mu_assert_eq(rz_mem_align_padding(0x800000, 1), 0, "Padding mismatch.");
	mu_assert_eq(rz_mem_align_padding(UT64_MAX, 1), 0, "Padding mismatch.");

	mu_assert_eq(rz_mem_align_padding(0x0, 2), 0, "Padding mismatch.");
	mu_assert_eq(rz_mem_align_padding(0x1, 2), 1, "Padding mismatch.");
	mu_assert_eq(rz_mem_align_padding(0x0, 0x8000000000000000), 0, "Padding mismatch.");
	mu_assert_eq(rz_mem_align_padding(0x1, 0x8000000000000000), 0x7fffffffffffffff, "Padding mismatch.");

	mu_assert_eq(rz_mem_align_padding(0x59d, 4), 3, "Padding mismatch.");
	mu_assert_eq(rz_mem_align_padding(0x7fffe, 8), 2, "Padding mismatch.");
	mu_assert_eq(rz_mem_align_padding(0x7fffe, 0x80000), 2, "Padding mismatch.");
	mu_assert_eq(rz_mem_align_padding(0x7fffe, 0x800000), 0x780002, "Padding mismatch.");

	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_mem_align_padding);

	return tests_passed != tests_run;
}

mu_main(all_tests)
