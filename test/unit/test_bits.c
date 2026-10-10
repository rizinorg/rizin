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

bool test_rz_bits_ut64_width(void) {
	mu_assert_eq(rz_bits_ut64_width(0), 0, "Width of 0");
	mu_assert_eq(rz_bits_ut64_width(1), 1, "Width of 1");
	mu_assert_eq(rz_bits_ut64_width(2), 2, "Width of 2");
	mu_assert_eq(rz_bits_ut64_width(3), 2, "Width of 3");
	mu_assert_eq(rz_bits_ut64_width(0xff), 8, "Width of 0xff");
	mu_assert_eq(rz_bits_ut64_width(0x100), 9, "Width of 0x100");
	mu_assert_eq(rz_bits_ut64_width(UT32_MAX), 32, "Width of UT32_MAX");
	mu_assert_eq(rz_bits_ut64_width(1ULL << 63), 64, "Width of the top bit");
	mu_assert_eq(rz_bits_ut64_width(UT64_MAX), 64, "Width of UT64_MAX");

	mu_end;
}

bool test_rz_bits_extract_stream_byte(void) {
	// buf: 0xca (11001010), 0xf0 (11110000), 0x55 (01010101)
	const ut8 buf[] = { 0xca, 0xf0, 0x55 };
	const size_t buflen = sizeof(buf);

	// Zero shift
	mu_assert_eq(rz_bits_extract_stream_byte(buf, buflen, 0, 0), 0xca, "Zero shift byte 0 mismatch");
	mu_assert_eq(rz_bits_extract_stream_byte(buf, buflen, 1, 0), 0xf0, "Zero shift byte 1 mismatch");
	mu_assert_eq(rz_bits_extract_stream_byte(buf, buflen, 2, 0), 0x55, "Zero shift byte 2 mismatch");

	// Shift 1: 0xca (11001010) and 0xf0 (11110000) -> 10010101 (0x95)
	mu_assert_eq(rz_bits_extract_stream_byte(buf, buflen, 0, 1), 0x95, "Shift 1 byte 0 mismatch");
	// Shift 1: 0xf0 (11110000) and 0x55 (01010101) -> 11100000 (0xe0)
	mu_assert_eq(rz_bits_extract_stream_byte(buf, buflen, 1, 1), 0xe0, "Shift 1 byte 1 mismatch");

	// Shift 3: 0xca (11001010) and 0xf0 (11110000) -> 01010111 (0x57)
	mu_assert_eq(rz_bits_extract_stream_byte(buf, buflen, 0, 3), 0x57, "Shift 3 byte 0 mismatch");

	// Shift 7: 0xca (11001010) and 0xf0 (11110000) -> 01111000 (0x78)
	mu_assert_eq(rz_bits_extract_stream_byte(buf, buflen, 0, 7), 0x78, "Shift 7 byte 0 mismatch");

	// End of buffer behavior: last byte (index 2) with shift 3: 0x55 << 3 = 0xa8, next byte is 0
	mu_assert_eq(rz_bits_extract_stream_byte(buf, buflen, 2, 3), 0xa8, "Shift at buffer end mismatch");

	// 1-byte buffer: final byte with shift 1 zero-pads unavailable next byte: (0xca << 1) & 0xff = 0x94
	mu_assert_eq(rz_bits_extract_stream_byte(buf, 1, 0, 1), 0x94, "1-byte buffer shift 1 zero-pads next byte");
	// 1-byte buffer: final byte with shift 7 zero-pads unavailable next byte: (0xca << 7) & 0xff = 0x00
	mu_assert_eq(rz_bits_extract_stream_byte(buf, 1, 0, 7), 0x00, "1-byte buffer shift 7 zero-pads next byte");

	// Out of bounds and overflow safety
	mu_assert_eq(rz_bits_extract_stream_byte(buf, buflen, 3, 0), 0, "Out of bounds mismatch");
	mu_assert_eq(rz_bits_extract_stream_byte(NULL, buflen, 0, 0), 0, "Null buffer mismatch");
	mu_assert_eq(rz_bits_extract_stream_byte(buf, 0, 0, 0), 0, "0-length buffer zero shift out of bounds");
	mu_assert_eq(rz_bits_extract_stream_byte(buf, 0, 0, 1), 0, "0-length buffer with shift out of bounds");
	mu_assert_eq(rz_bits_extract_stream_byte(buf, buflen, SIZE_MAX, 1), 0, "SIZE_MAX byte_pos out of bounds");
	mu_assert_eq(rz_bits_extract_stream_byte(buf, buflen, SIZE_MAX - 1, 1), 0, "SIZE_MAX - 1 byte_pos out of bounds");

	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_bits_count);
	mu_run_test(test_rz_bits_spread);
	mu_run_test(test_rz_bits_trailing_zero);
	mu_run_test(test_rz_bits_copy);
	mu_run_test(test_rz_bits_ut64_width);
	mu_run_test(test_rz_bits_extract_stream_byte);

	return tests_passed != tests_run;
}

mu_main(all_tests)
