// SPDX-FileCopyrightText: 2026 Farhan-25 <shadowfinder1799@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

static bool test_read_u32_single_byte(void) {
	ut8 buf[] = { 0x7f };
	ut32 value = 0;

	size_t n = read_u32_leb128(buf, buf + sizeof(buf), &value);

	mu_assert_eq(n, 1, "u32 single: wrong length");
	mu_assert_eq(value, 127, "u32 single: wrong value");
	mu_end;
}

static bool test_read_u32_multibyte(void) {
	ut8 buf[] = { 0xE5, 0x8E, 0x26 };
	ut32 value = 0;

	size_t n = read_u32_leb128(buf, buf + sizeof(buf), &value);

	mu_assert_eq(n, 3, "u32 multi: wrong length");
	mu_assert_eq(value, 624485, "u32 multi: wrong value");
	mu_end;
}

static bool test_read_i32_positive(void) {
	ut8 buf[] = { 0x01 };
	st32 value = 0;

	size_t n = read_i32_leb128(buf, buf + sizeof(buf), &value);

	mu_assert_eq(n, 1, "i32 positive: wrong length");
	mu_assert_eq(value, 1, "i32 positive: wrong value");
	mu_end;
}

static bool test_read_i32_negative_one(void) {
	ut8 buf[] = { 0x7f };
	st32 value = 0;

	size_t n = read_i32_leb128(buf, buf + sizeof(buf), &value);

	mu_assert_eq(n, 1, "i32 -1: wrong length");
	mu_assert_eq(value, -1, "i32 -1: wrong value");
	mu_end;
}

static bool test_read_i32_multibyte_negative(void) {
	ut8 buf[] = { 0x9B, 0xF1, 0x59 };
	st32 value = 0;

	size_t n = read_i32_leb128(buf, buf + sizeof(buf), &value);

	mu_assert_eq(n, 3, "i32 multi neg: wrong length");
	mu_assert_eq(value, -624485, "i32 multi neg: wrong value");
	mu_end;
}

static bool test_read_u64_single_byte(void) {
	ut8 buf[] = { 0x7f };
	ut64 value = 0;

	size_t n = read_u64_leb128(buf, buf + sizeof(buf), &value);

	mu_assert_eq(n, 1, "u64 single: wrong length");
	mu_assert_eq(value, 127ULL, "u64 single: wrong value");
	mu_end;
}

static bool test_read_u64_multibyte(void) {
	ut8 buf[] = { 0xE5, 0x8E, 0x26 };
	ut64 value = 0;

	size_t n = read_u64_leb128(buf, buf + sizeof(buf), &value);

	mu_assert_eq(n, 3, "u64 multi: wrong length");
	mu_assert_eq(value, 624485ULL, "u64 multi: wrong value");
	mu_end;
}

static bool test_read_i64_positive(void) {
	ut8 buf[] = { 0x01 };
	st64 value = 0;

	size_t n = read_i64_leb128(buf, buf + sizeof(buf), &value);

	mu_assert_eq(n, 1, "i64 positive: wrong length");
	mu_assert_eq(value, 1LL, "i64 positive: wrong value");
	mu_end;
}

static bool test_read_i64_negative_one(void) {
	ut8 buf[] = { 0x7f };
	st64 value = 0;

	size_t n = read_i64_leb128(buf, buf + sizeof(buf), &value);

	mu_assert_eq(n, 1, "i64 -1: wrong length");
	mu_assert_eq(value, -1LL, "i64 -1: wrong value");
	mu_end;
}

static bool test_read_i64_multibyte_negative(void) {
	ut8 buf[] = { 0x9B, 0xF1, 0x59 };
	st64 value = 0;

	size_t n = read_i64_leb128(buf, buf + sizeof(buf), &value);

	mu_assert_eq(n, 3, "i64 multi neg: wrong length");
	mu_assert_eq(value, -624485LL, "i64 multi neg: wrong value");
	mu_end;
}

static bool all_tests(void) {
	mu_run_test(test_read_u32_single_byte);
	mu_run_test(test_read_u32_multibyte);

	mu_run_test(test_read_i32_positive);
	mu_run_test(test_read_i32_negative_one);
	mu_run_test(test_read_i32_multibyte_negative);

	mu_run_test(test_read_u64_single_byte);
	mu_run_test(test_read_u64_multibyte);

	mu_run_test(test_read_i64_positive);
	mu_run_test(test_read_i64_negative_one);
	mu_run_test(test_read_i64_multibyte_negative);

	return tests_passed != tests_run;
}

mu_main(all_tests)
