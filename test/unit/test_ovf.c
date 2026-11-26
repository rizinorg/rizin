// SPDX-FileCopyrightText: 2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

int test_overflow_add(void) {
	mu_assert_true(UT8_ADD_OVFCHK(250, 32), "ut8-add 1");
	mu_assert_false(UT8_ADD_OVFCHK(250, 2), "ut8-add 2");
	mu_assert_false(UT8_ADD_OVFCHK(UT8_MAX, 0), "ut8-add (max, 0)");
	mu_assert_false(UT16_ADD_OVFCHK(ST16_MAX, 2), "ut16-add 2");
	mu_assert_false(UT16_ADD_OVFCHK(UT16_MAX, 0), "ut16-add (max, 0)");
	mu_assert_true(ST16_ADD_OVFCHK(ST16_MAX, 2), "st16-add 2");
	mu_assert_true(ST16_ADD_OVFCHK(ST16_MAX - 2, 4), "st16-add 2");
	mu_assert_true(ST16_ADD_OVFCHK(1, ST16_MAX), "st16-add 3");
	mu_assert_false(UT32_ADD_OVFCHK(UT32_MAX, 0), "ut32-add (max, 0)");
	mu_assert_false(UT64_ADD_OVFCHK(UT64_MAX, 0), "ut64-add (max, 0)");
	mu_assert_false(ST64_ADD_OVFCHK(ST64_MAX, 0), "st64-add (max, 0)");
	mu_assert_true(ST16_ADD_OVFCHK(ST16_MIN, -1), "st16-add (min, -1)");
	mu_assert_true(UT16_ADD_OVFCHK(10, -20), "ut16-add (10, -20)");
	mu_assert_false(ST16_ADD_OVFCHK(-10, 20), "st16-add (-10, 20)");
	mu_assert_true(ST32_ADD_OVFCHK(ST32_MIN, -20), "st32-add (min, -20)");
	mu_assert_false(ST32_ADD_OVFCHK(-10, 20), "st32-add (-10, 20)");
	mu_assert_true(ST64_ADD_OVFCHK(ST64_MIN, -20), "st64-add (min, -20)");
	mu_assert_false(ST64_ADD_OVFCHK(-10, 20), "st64-add 3");
	mu_end;
}

int test_underflow_sub(void) {
	mu_assert_false(ST16_SUB_OVFCHK(10, 210), "st16-sub-sign-underflow");
	mu_assert_true(UT16_SUB_OVFCHK(10, 210), "ut16-sub-underflow");
	mu_assert_true(ST16_SUB_OVFCHK(ST16_MIN, 210), "st16-sub-underflow");

	// Unsigned subtraction: non-underflowing, boundary, underflowing, and >type_max cases
	mu_assert_false(UT8_SUB_OVFCHK(200, 100), "ut8-sub no underflow");
	mu_assert_false(UT8_SUB_OVFCHK(10, 10), "ut8-sub equal");
	mu_assert_false(UT8_SUB_OVFCHK(0, 0), "ut8-sub zero");
	mu_assert_true(UT8_SUB_OVFCHK(10, 11), "ut8-sub underflow");
	mu_assert_true(UT8_SUB_OVFCHK(300, 10), "ut8-sub result > UT8_MAX");
	mu_assert_false(UT8_SUB_OVFCHK(300, 50), "ut8-sub 300-50 fits ut8");

	mu_assert_false(UT16_SUB_OVFCHK(210, 10), "ut16-sub no underflow");
	mu_assert_false(UT16_SUB_OVFCHK(UT16_MAX, UT16_MAX), "ut16-sub max-max");
	mu_assert_false(UT16_SUB_OVFCHK(UT16_MAX, 0), "ut16-sub max-0");
	mu_assert_true(UT16_SUB_OVFCHK(0, 1), "ut16-sub 0-1");
	mu_assert_true(UT16_SUB_OVFCHK(100000, 1), "ut16-sub result > UT16_MAX");

	mu_assert_false(UT32_SUB_OVFCHK(0x1089, 0x20), "ut32-sub no underflow");
	mu_assert_false(UT32_SUB_OVFCHK(UT32_MAX, UT32_MAX), "ut32-sub max-max");
	mu_assert_true(UT32_SUB_OVFCHK(0x20, 0x21), "ut32-sub underflow");
	mu_assert_true(UT32_SUB_OVFCHK((ut64)UT32_MAX + 10, 5), "ut32-sub result > UT32_MAX");

	mu_assert_false(UT64_SUB_OVFCHK(0x1089, 0x20), "ut64-sub no underflow");
	mu_assert_false(UT64_SUB_OVFCHK(UT64_MAX, UT64_MAX), "ut64-sub max-max");
	mu_assert_false(UT64_SUB_OVFCHK(UT64_MAX, 0), "ut64-sub max-0");
	mu_assert_false(UT64_SUB_OVFCHK(0, 0), "ut64-sub 0-0");
	mu_assert_true(UT64_SUB_OVFCHK(0, 1), "ut64-sub 0-1");
	mu_assert_true(UT64_SUB_OVFCHK(0x20, 0x1089), "ut64-sub underflow");

	mu_assert_false(SZT_SUB_OVFCHK(0x1089, 0x20), "szt-sub no underflow");
	mu_assert_false(SZT_SUB_OVFCHK(SIZE_MAX, SIZE_MAX), "szt-sub max-max");
	mu_assert_true(SZT_SUB_OVFCHK(0x20, 0x21), "szt-sub underflow");

	// Signed subtraction: ST*_MIN second operand (must not negate ST64_MIN)
	mu_assert_true(ST64_SUB_OVFCHK(0, ST64_MIN), "st64-sub 0 - MIN overflows");
	mu_assert_true(ST64_SUB_OVFCHK(1, ST64_MIN), "st64-sub 1 - MIN overflows");
	mu_assert_false(ST64_SUB_OVFCHK(-1, ST64_MIN), "st64-sub -1 - MIN = MAX");
	mu_assert_false(ST64_SUB_OVFCHK(ST64_MIN, ST64_MIN), "st64-sub MIN - MIN = 0");
	mu_assert_false(ST64_SUB_OVFCHK(-1, ST64_MAX), "st64-sub -1 - MAX = MIN");
	mu_assert_true(ST64_SUB_OVFCHK(-2, ST64_MAX), "st64-sub -2 - MAX underflows");

	mu_assert_true(ST32_SUB_OVFCHK(0, ST32_MIN), "st32-sub 0 - MIN overflows");
	mu_assert_false(ST32_SUB_OVFCHK(-1, ST32_MIN), "st32-sub -1 - MIN = MAX");
	mu_assert_true(ST8_SUB_OVFCHK(0, ST8_MIN), "st8-sub 0 - MIN overflows");
	mu_assert_false(ST8_SUB_OVFCHK(-1, ST8_MIN), "st8-sub -1 - MIN = MAX");

#if defined(SSIZE_MAX) && defined(SSIZE_MIN)
	mu_assert_true(SSZT_SUB_OVFCHK((ssize_t)0, SSIZE_MIN), "sszt-sub 0 - MIN overflows");
	mu_assert_false(SSZT_SUB_OVFCHK((ssize_t)-1, SSIZE_MIN), "sszt-sub -1 - MIN = MAX");
	mu_assert_false(SSZT_SUB_OVFCHK(SSIZE_MIN, SSIZE_MIN), "sszt-sub MIN - MIN = 0");
	mu_assert_true(SSZT_SUB_OVFCHK((ssize_t)-2, SSIZE_MAX), "sszt-sub -2 - MAX underflows");
	mu_assert_false(SSZT_SUB_OVFCHK((ssize_t)-1, SSIZE_MAX), "sszt-sub -1 - MAX = MIN");
#endif
	mu_end;
}

int test_underflow_add(void) {
	mu_assert_false(ST16_SUB_OVFCHK(10, -210), "st16-sub");
	mu_assert_false(ST16_SUB_OVFCHK(10, 10), "st16-sub 10");
	mu_assert_true(ST16_SUB_OVFCHK(ST16_MIN, 11), "st16-sub 10-11");
	mu_assert_false(ST16_SUB_OVFCHK(10, 11), "st16-sub 10-11");
	mu_assert_true(UT16_SUB_OVFCHK(10, 11), "ut16-sub 10-11");
	mu_end;
}

int test_overflow_mul(void) {
	mu_assert_true(UT8_MUL_OVFCHK(16, 32), "ut8-mul");
	mu_assert_false(UT8_MUL_OVFCHK(16, 2), "ut8-mul 2");
	mu_assert_true(ST8_MUL_OVFCHK(16, 100), "st8-mul 3");
	mu_assert_false(ST8_MUL_OVFCHK(16, 1), "st8-mul 4");
	mu_assert_false(ST8_MUL_OVFCHK(-2, 2), "st8-mul sign overflow");
	mu_assert_false(ST8_MUL_OVFCHK(-1, 1), "st8-mul sign overflow");
	mu_assert_false(ST8_MUL_OVFCHK(1, -1), "st8-mul sign overflow");
	mu_assert_false(ST8_MUL_OVFCHK(2, -2), "st8-mul sign overflow");
	mu_assert_false(ST8_MUL_OVFCHK(-1, -2), "st8-mul sign overflow");
	mu_assert_false(ST8_MUL_OVFCHK(-2, -1), "st8-mul sign overflow");
	mu_assert_true(ST8_MUL_OVFCHK(-16, 100), "st8-mul sign overflow");
	mu_assert_true(ST8_MUL_OVFCHK(100, -16), "st8-mul sign overflow");
	mu_assert_false(ST8_MUL_OVFCHK(3, -16), "st8-mul sign overflow");
	mu_end;
}

int test_overflow_mul2(void) {
	mu_assert_false(ST8_MUL_OVFCHK(-1, 0), "st8-mul2 -1 0");
	mu_assert_false(ST8_MUL_OVFCHK(1, 0), "st8-mul2 -1 0");
	mu_assert_true(UT8_ADD_OVFCHK(300, 0), "ut8-add out-of-range operand");
	mu_assert_true(UT8_MUL_OVFCHK(300, 1), "ut8-mul out-of-range operand");
	mu_assert_false(UT8_MUL_OVFCHK(300, 0), "ut8-mul out-of-range times zero");
	mu_assert_true(ST64_MUL_OVFCHK(ST64_MIN, -1), "st64-mul MIN * -1");
	mu_assert_true(ST64_MUL_OVFCHK(-1, ST64_MIN), "st64-mul -1 * MIN");
	mu_assert_false(ST64_MUL_OVFCHK(ST64_MIN, 1), "st64-mul MIN * 1");
	mu_assert_false(ST64_MUL_OVFCHK(-1, ST64_MAX), "st64-mul -1 * MAX");
	mu_end;
}

int all_tests() {
	mu_run_test(test_overflow_add);
	mu_run_test(test_underflow_add);
	mu_run_test(test_underflow_sub);
	mu_run_test(test_overflow_mul);
	mu_run_test(test_overflow_mul2);
	return tests_passed != tests_run;
}

mu_main(all_tests)