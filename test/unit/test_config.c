// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_config.h>
#include "minunit.h"

bool test_config() {
	RzConfig *cfg = rz_config_new(NULL);

	// string variables
	rz_config_set(cfg, "foo.bar", "bla");
	const char *bla = rz_config_get(cfg, "foo.bar");
	mu_assert_streq(bla, "bla", "String variable");

	// integer variables
	rz_config_set_i(cfg, "universe.question", 42);
	int answer = rz_config_get_i(cfg, "universe.question");
	mu_assert_eq(answer, 42, "Integer variable");

	// boolean variables
	rz_config_set_b(cfg, "true.or.false", true);
	bool what = rz_config_get_b(cfg, "true.or.false");
	mu_assert_eq(what, true, "Boolean variable");
	rz_config_toggle(cfg, "true.or.false");
	what = rz_config_get_b(cfg, "true.or.false");
	mu_assert_eq(what, false, "Boolean variable (toggle)");

	mu_end;
}

bool test_config_lock() {
	RzConfig *cfg = rz_config_new(NULL);
	cfg->lock = 1;

	// string variables
	rz_config_set(cfg, "foo.bar", "bla");
	const char *bla = rz_config_get(cfg, "foo.bar");
	mu_assert_null(bla, "String variable (locked)");

	// integer variables
	rz_config_set_i(cfg, "universe.question", 42);
	int answer = rz_config_get_i(cfg, "universe.question");
	mu_assert_neq(answer, 42, "Integer variable (locked)");

	// boolean variables
	rz_config_set_b(cfg, "true.or.false", true);
	bool what = rz_config_get_b(cfg, "true.or.false");
	mu_assert_false(what, "Boolean variable (locked)");

	mu_end;
}

bool all_tests() {
	mu_run_test(test_config);
	mu_run_test(test_config_lock);
	return tests_passed != tests_run;
}

mu_main(all_tests)
