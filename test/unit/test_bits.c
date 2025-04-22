// SPDX-FileCopyrightText: 2025 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_bits_count(void) {
	mu_assert_eq(rz_bits_count_ones_ut64(0xffffffffffffffff), 64, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0), 0, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(1), 1, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0x8000000000000000), 1, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0x7fffffffffffffff), 63, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0xfffffffffffffffe), 63, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0xffffffffffefffff), 63, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0x0fffffffffffffff), 60, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0xf0ffffffffffffff), 60, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0xffffffffff0fffff), 60, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0xffffffff00000000), 32, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0x00000000ffffffff), 32, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0x0000010000000000), 1, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0x0000000000001000), 1, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0x0100000100001000), 3, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0x0400000100002000), 3, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0x0400008100002000), 4, "Bit count mismatch.");
	mu_assert_eq(rz_bits_count_ones_ut64(0x0400008100002008), 5, "Bit count mismatch.");

	for (size_t i = 0; i <= 0xff; i++) {
		size_t naive_count = 0;
		for (size_t k = 0; k < 8; k++) {
			naive_count += i & (1 << k) ? 1 : 0;
		}
		mu_assert_eq(rz_bits_count_ones_ut8(i), naive_count, "Bit count mismatch.");
	}

	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_bits_count);

	return tests_passed != tests_run;
}

mu_main(all_tests)
