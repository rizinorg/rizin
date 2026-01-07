// SPDX-FileCopyrightText: 2026 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include "minunit.h"

bool test_rgb_tostring(void) {
	char *s = rz_cons_rgb_tostring(255, 0, 0);
	mu_assert_notnull(s, "Red string not null");
	mu_assert_streq_free(s, "red", "RGB to string Red");
	s = rz_cons_rgb_tostring(0, 255, 0);
	mu_assert_notnull(s, "Green string not null");
	mu_assert_streq_free(s, "green", "RGB to string Green");
	mu_end;
}

bool test_rgb_str(void) {
	char buf[128];
	RzColor color = { 0 };
	color.r = 255;
	color.g = 255;
	color.b = 255;
	color.a = 255;

	RzCons *c = rz_cons_new();
	rz_cons_rgb_str(buf, sizeof(buf), &color);

	mu_assert_streq(buf, "", "Disabled color mode");

	c->context->color_mode = COLOR_MODE_16M;
	rz_cons_rgb_str(buf, sizeof(buf), &color);
	mu_assert_streq(buf, "\x1b[38;2;255;255;255m", "16M color mode");

	rz_cons_free();
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rgb_tostring);
	mu_run_test(test_rgb_str);
	return tests_passed != tests_run;
}

mu_main(all_tests)
