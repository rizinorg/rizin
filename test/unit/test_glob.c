// SPDX-FileCopyrightText: 2016 Maijin
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_glob(void) {
	mu_assert_eq(rz_str_glob("foo.c", "*.c"), 1, "foo.c -> *.c -> 1");
	mu_assert_eq(rz_str_glob("foo.c", "*.d"), 0, "foo.c -> *.d -> 0");
	mu_assert_eq(rz_str_glob("foo.c", "foo*"), 1, "foo.c -> foo* -> 1");
	mu_assert_eq(rz_str_glob("foo.c", "*oo*"), 1, "foo.c -> *oo* -> 1");
	mu_assert_eq(rz_str_glob("foo.c", "*uu*"), 0, "foo.c -> *uu* -> 1");
	mu_assert_eq(rz_str_glob("foo.c", "f*c*"), 1, "foo.c -> f*c* -> 1");
	mu_assert_eq(rz_str_glob("foo.c", "f*d"), 0, "foo.c -> f*d -> 1");
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_glob);
	return tests_passed != tests_run;
}

mu_main(all_tests)