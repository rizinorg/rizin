// SPDX-FileCopyrightText: 2026 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include "minunit.h"

bool test_pal_set_get(void) {
	rz_cons_new();

	RzColor c = rz_cons_pal_get("comment");

	rz_cons_pal_set("comment", "blue");
	c = rz_cons_pal_get("comment");
	rz_cons_pal_set("comment", "rgb:102030");
	c = rz_cons_pal_get("comment");
	mu_assert_eq(c.r, 0x10, "Red component");
	mu_assert_eq(c.g, 0x20, "Green component");
	mu_assert_eq(c.b, 0x30, "Blue component");

	rz_cons_free();
	mu_end;
}

bool test_pal_update_event(void) {
	RzCons *cons = rz_cons_new();
	cons->context->color_mode = COLOR_MODE_256;

	rz_cons_pal_set("comment", "red");
	rz_cons_pal_update_event();

	const char *s = cons->context->pal.comment;
	mu_assert_notnull(s, "Printable palette should be populated");
	mu_assert_true(strlen(s) > 0, "Should have color code");

	rz_cons_free();
	mu_end;
}

bool test_pal_parse(void) {
	RzColor c = { 0 };
	rz_cons_pal_parse("red", &c);

	memset(&c, 0, sizeof(c));
	rz_cons_pal_parse("#112233 bold", &c);
	mu_assert_eq(c.r, 0x11, "Hex Red");

	mu_end;
}

bool test_pal_json_css(void) {
	rz_cons_new();

	PJ *pj = pj_new();
	rz_cons_pal_list_as_json(pj);
	const char *s = pj_string(pj);
	mu_assert_notnull(s, "JSON palette");
	mu_assert_true(strstr(s, "\"comment\":") != NULL, "JSON contains comment");
	mu_assert_true(strstr(s, "\"prompt\":") != NULL, "JSON contains prompt");
	pj_free(pj);

	rz_cons_pal_list_as_css(NULL);

	rz_cons_free();
	mu_end;
}

bool all_tests() {
	mu_run_test(test_pal_set_get);
	mu_run_test(test_pal_update_event);
	mu_run_test(test_pal_parse);
	mu_run_test(test_pal_json_css);
	return tests_passed != tests_run;
}

mu_main(all_tests)
