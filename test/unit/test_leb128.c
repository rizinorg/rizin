#include <rz_util.h>
#include "minunit.h"

static bool test_read_u32_leb128_simple(void) {
	ut8 buf[] = { 0x7f };
	ut32 value = 0;

	size_t n = read_u32_leb128(buf, buf + sizeof(buf), &value);

	mu_assert_eq(n, 1, "Should consume 1 byte");
	mu_assert_eq(value, 0x7f, "Value should be 0x7f");

	mu_end;
}

static bool test_read_u32_leb128_multibyte(void) {
	// 624485 encoded in unsigned LEB128 = E5 8E 26
	ut8 buf[] = { 0xE5, 0x8E, 0x26 };
	ut32 value = 0;

	size_t n = read_u32_leb128(buf, buf + sizeof(buf), &value);

	mu_assert_eq(n, 3, "Should consume 3 bytes");
	mu_assert_eq(value, 624485, "Decoded value mismatch");

	mu_end;
}

static bool all_tests(void) {
	mu_run_test(test_read_u32_leb128_simple);
	mu_run_test(test_read_u32_leb128_multibyte);
	return tests_passed != tests_run;
}

mu_main(all_tests)
