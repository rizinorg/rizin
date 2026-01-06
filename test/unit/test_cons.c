// SPDX-FileCopyrightText: 2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2026 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include "minunit.h"

bool test_rz_cons() {
	// NOTE: not initializing a value here results in UB
	ut8 r = 0, g = 0, b = 0, a = 0;

	rz_cons_rgb_init();

	// all these strdup are for asan/valgrind to have some exact bounds to work with

	char *foo = strdup("___"); // should crash in asan mode
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);

	mu_assert_eq(r, 0, "red color");
	mu_assert_eq(g, 0, "green color");
	mu_assert_eq(b, 0, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	// old school
	foo = strdup("\x1b[32mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 0, "red color");
	mu_assert_eq(g, 127, "green color");
	mu_assert_eq(b, 0, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	foo = strdup("[32mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 0, "red color");
	mu_assert_eq(g, 127, "green color");
	mu_assert_eq(b, 0, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	foo = strdup("32mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 0, "red color");
	mu_assert_eq(g, 127, "green color");
	mu_assert_eq(b, 0, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	// 256
	foo = strdup("\x1b[38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 255, "red color");
	mu_assert_eq(g, 135, "green color");
	mu_assert_eq(b, 255, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	foo = strdup("[38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 255, "red color");
	mu_assert_eq(g, 135, "green color");
	mu_assert_eq(b, 255, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	foo = strdup("38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 255, "red color");
	mu_assert_eq(g, 135, "green color");
	mu_assert_eq(b, 255, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	// 24 bit
	foo = strdup("\x1b[38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 42, "red color");
	mu_assert_eq(g, 13, "green color");
	mu_assert_eq(b, 37, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	foo = strdup("[38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 42, "red color");
	mu_assert_eq(g, 13, "green color");
	mu_assert_eq(b, 37, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	foo = strdup("38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 42, "red color");
	mu_assert_eq(g, 13, "green color");
	mu_assert_eq(b, 37, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	// no over-read
	foo = strdup("38;2");
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);

	foo = strdup("38;5");
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);

	foo = strdup("3");
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);

	mu_end;
}

bool test_cons_justify(void) {
	rz_cons_new();
	rz_cons_reset();
	rz_cons_strcat_justify("Line1\nLine2", 2, '|');
	const char *buf = rz_cons_get_buffer();
	const char *expected = "  | Line1\nLine2";

	mu_assert_streq(buf, expected, "Justify multiple lines");

	rz_cons_reset();
	rz_cons_strcat_justify("A", 2, '|');
	buf = rz_cons_get_buffer();
	mu_assert_streq(buf, "A", "Justify single char");

	rz_cons_free();
	mu_end;
}

bool test_cons_at(void) {
	rz_cons_new();
	rz_cons_reset();
	rz_cons_strcat_at("Hello", 2, 0, 10, 1);
	const char *buf = rz_cons_get_buffer();
	mu_assert_true(strstr(buf, "Hello") != NULL, "Buffer contains Hello");
	rz_cons_free();
	mu_end;
}

bool test_cons_misc(void) {
	rz_cons_new();
	mu_assert_notnull(rz_cons_singleton(), "Singleton check");

	rz_cons_break_push(NULL, NULL);
	mu_assert_false(rz_cons_is_breaked(), "Not breaked initially");
	rz_cons_break_pop();

#if __UNIX__
	// Test UTF-8 detection via environment
	const char *env_vars[] = { "LC_ALL", "LC_CTYPE", "LANG" };
	char *old_envs[3];
	for (int i = 0; i < 3; i++) {
		old_envs[i] = rz_sys_getenv(env_vars[i]);
		rz_sys_setenv(env_vars[i], NULL);
	}

	rz_sys_setenv("LANG", "en_US.UTF-8");
	mu_assert_true(rz_cons_is_utf8(), "UTF-8 detected with LANG=en_US.UTF-8");

	rz_sys_setenv("LANG", "C");
	mu_assert_false(rz_cons_is_utf8(), "UTF-8 NOT detected with LANG=C");

	for (int i = 0; i < 3; i++) {
		rz_sys_setenv(env_vars[i], old_envs[i]);
		free(old_envs[i]);
	}
#endif

	// Interactive check
	mu_assert_false(rz_cons_is_interactive(), "Unit tests should not be interactive by default");
	rz_cons_set_interactive(true);
	mu_assert_true(rz_cons_is_interactive(), "Manually set interactive to true");
	rz_cons_set_interactive(false);
	mu_assert_false(rz_cons_is_interactive(), "Manually set interactive to false");

	rz_cons_free();
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_cons);
	mu_run_test(test_cons_justify);
	mu_run_test(test_cons_at);
	mu_run_test(test_cons_misc);
	return tests_passed != tests_run;
}

mu_main(all_tests)
