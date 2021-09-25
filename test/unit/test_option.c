// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_option.h>
#include <stdio.h>
#include <string.h>

#include "minunit.h"

DEFINE_RZ_OPTION(ut64); // defined ut64Option

DEFINE_RZ_OPTION_NEW(ut64); // define rz_option_ut64_new
DEFINE_RZ_OPTION_NONE(ut64); // define rz_option_ut64_none
DEFINE_RZ_OPTION_IS_NONE(ut64); // define rz_option_ut64_is_none
DEFINE_RZ_OPTION_GET_VALUE(ut64); // define rz_option_ut64_get_value

IMPLEMENT_RZ_OPTION(ut64); // implement ut64Option

IMPLEMENT_RZ_OPTION_NEW(ut64) // implement rz_option_ut64_new
IMPLEMENT_RZ_OPTION_NONE(ut64) // implement rz_option_ut64_none
IMPLEMENT_RZ_OPTION_IS_NONE(ut64) // implement rz_option_ut64_is_none
IMPLEMENT_RZ_OPTION_GET_VALUE(ut64) // implement rz_option_ut64_get_value

bool test_rz_option_new(void) {
	RZ_OPTION(ut64)
	option = RZ_OPTION_NEW(ut64)(42);

	mu_assert_eq(option.is_none, false, "is_none");
	mu_assert_eq(option.value, 42, "value");

	mu_end;
}

bool test_rz_option_none(void) {
	RZ_OPTION(ut64)
	option = RZ_OPTION_NONE(ut64)();

	mu_assert_eq(option.is_none, true, "is_none");

	mu_end;
}

bool test_rz_option_is_none(void) {
	RZ_OPTION(ut64)
	option = RZ_OPTION_NEW(ut64)(42);
	mu_assert_false(RZ_OPTION_IS_NONE(ut64)(option), "is_none");

	RZ_OPTION(ut64)
	option_none = RZ_OPTION_NONE(ut64)();
	mu_assert_true(RZ_OPTION_IS_NONE(ut64)(option_none), "is_none");

	mu_end;
}

bool test_rz_option_get_value(void) {
	RZ_OPTION(ut64)
	option = RZ_OPTION_NEW(ut64)(42);

	mu_assert_eq(RZ_OPTION_GET_VALUE(ut64)(option), 42, "value");

	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_rz_option_new);
	mu_run_test(test_rz_option_none);
	mu_run_test(test_rz_option_is_none);
	mu_run_test(test_rz_option_get_value);
	return tests_passed != tests_run;
}

mu_main(all_tests)
