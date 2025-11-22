// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"
#include "rz_util/rz_bits.h"

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

bool test_rz_bits_trailing_zero(void) {
	mu_assert_eq(rz_bits_trailing_zeros(0), 64, "Bit count mismatch.");
	for (size_t i = 1, j = 0; i != 0; i <<= 1, j++) {
		mu_assert_eq(rz_bits_trailing_zeros(i), j, "Bit count mismatch.");
	}

	mu_end;
}

bool test_rz_bits_spread(void) {
	mu_assert_eq(rz_bits_spread(0xffffffffffffffff, 0xffffffffffffffff), 0xffffffffffffffff, "Spread mismatch.");
	mu_assert_eq(rz_bits_spread(0, 0xffffffffffffffff), 0, "Spread mismatch.");
	mu_assert_eq(rz_bits_spread(0x1, 0xfffffffffffffffe), 0, "Spread mismatch.");
	mu_assert_eq(rz_bits_spread(0x8000000000000000, 0x7fffffffffffffff), 0x8000000000000000, "Spread mismatch.");
	mu_assert_eq(rz_bits_spread(0x0000000055555555, 0xffffffffffffffff), 0x55555555, "Spread mismatch.");
	mu_assert_eq(rz_bits_spread(0xf300021, 0xff), 0xf300021, "Spread mismatch.");
	mu_assert_eq(rz_bits_spread(0xf300021, 0xfe), 0xf300020, "Spread mismatch.");
	mu_assert_eq(rz_bits_spread(0xf300021, 0x7e), 0x7300020, "Spread mismatch.");
	mu_assert_eq(rz_bits_spread(0xf301021, 0x7e), 0x3301020, "Spread mismatch.");

	mu_end;
}

bool test_rz_bits_copy(void) {
	mu_assert_eq(rz_bits_copy_ut64(0x1122334455667788, 24, 0x8877665544332211, 8, 16), 0x8877665544445511, "Incorrect bit copy");
	mu_assert_eq(rz_bits_copy_ut64(0x1122334455667788, 0, 0x0, 1, 63), 0x22446688aaccef10, "Incorrect bit copy");
	mu_assert_eq(rz_bits_copy_ut64(0x1122334455667788, 0, 0x8877665544332211, 0, 64), 0x1122334455667788, "Incorrect bit copy");
	mu_assert_eq(rz_bits_copy_ut8(0xAB, 0, 0xCD, 0, 8), 0xAB, "Incorrect bit copy");

	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_bits_count);
	mu_run_test(test_rz_bits_spread);
	mu_run_test(test_rz_bits_trailing_zero);
	mu_run_test(test_rz_bits_copy);

	return tests_passed != tests_run;
}

mu_main(all_tests)
