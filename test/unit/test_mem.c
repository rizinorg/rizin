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

bool test_rz_mem_align_byte(void) {
	const ut8 one_byte[1] = { 0xff };
	const ut8 one_byte_a_2[1] = { 0x00 };
	const ut8 two_bytes[2] = { 0x00, 0x01 };
	const ut8 two_bytes_a_2[2] = { 0x01, 0x00 };
	const ut8 two_bytes_a_3[2] = { 0x00, 0x00 };
	const ut8 two_bytes_a_8[2] = { 0x00, 0x00 };
	const ut8 seven_bytes[7] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	const ut8 seven_bytes_a_2[7] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00 };
	const ut8 seven_bytes_a_3[7] = { 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00 };
	const ut8 seven_bytes_a_7[7] = { 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	const ut8 seven_bytes_a_8[7] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	const ut8 eight_bytes[8] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
	const ut8 eight_bytes_a_2[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00 };
	const ut8 eight_bytes_a_8[8] = { 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	const ut8 nine_bytes[9] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	const ut8 nine_bytes_a_8[9] = { 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	// clang-format off
	const ut8 block[0x20] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};
	const ut8 block_a_2[0x20] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00
	};
	const ut8 block_a_8[0x20] = {
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
		0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
		0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
		0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	// clang-format on

	ut8 *test_out;

#define TEST(input, expected, alignment, msg) \
	test_out = rz_mem_copy_offset(input, sizeof(input), alignment); \
	mu_assert_notnull(test_out, "NULL check failed"); \
	mu_assert_memeq(test_out, expected, sizeof(expected), msg); \
	mu_assert_eq(((ut64)test_out) % 8, 0, "Address is not aligned to 8."); \
	free(test_out);

	TEST(one_byte, one_byte, 0, "Alignment of 1 should be memcpy")
	TEST(block, block, 0, "Alignment of 1 should be memcpy")

	TEST(two_bytes, two_bytes_a_3, 3, "Alignment larger than buffer")
	TEST(two_bytes, two_bytes_a_8, 8, "Alignment larger than buffer")

	TEST(one_byte, one_byte_a_2, 2, "Invalid alignment result")

	TEST(two_bytes, two_bytes_a_2, 1, "Invalid alignment result")

	TEST(seven_bytes, seven_bytes_a_2, 1, "Invalid alignment result")
	TEST(seven_bytes, seven_bytes_a_3, 2, "Invalid alignment result")
	TEST(seven_bytes, seven_bytes_a_7, 6, "Invalid alignment result")
	TEST(seven_bytes, seven_bytes_a_8, 7, "Invalid alignment result")

	TEST(eight_bytes, eight_bytes_a_2, 1, "Invalid alignment result")
	TEST(eight_bytes, eight_bytes_a_8, 7, "Invalid alignment result")

	TEST(nine_bytes, nine_bytes_a_8, 7, "Invalid alignment result")

	TEST(block, block_a_2, 1, "Invalid alignment result")
	TEST(block, block_a_8, 7, "Invalid alignment result")

	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_mem_align_padding);
	mu_run_test(test_rz_mem_align_byte);

	return tests_passed != tests_run;
}

mu_main(all_tests)
