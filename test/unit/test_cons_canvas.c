// SPDX-FileCopyrightText: 2026 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include "minunit.h"

bool test_canvas_new_free(void) {
	RzConsCanvas *c = rz_cons_canvas_new(10, 5);
	mu_assert_notnull(c, "Canvas should be created");
	mu_assert_eq(c->w, 10, "Width should be 10");
	mu_assert_eq(c->h, 5, "Height should be 5");
	rz_cons_canvas_free(c);
	mu_end;
}

bool test_canvas_write_tostring(void) {
	rz_cons_new();

	RzConsCanvas *c = rz_cons_canvas_new(10, 3);
	rz_cons_canvas_gotoxy(c, 0, 0);
	rz_cons_canvas_write(c, "Hello");
	rz_cons_canvas_gotoxy(c, 2, 1);
	rz_cons_canvas_write(c, "World");

	char *res = rz_cons_canvas_to_string(c);
	mu_assert_notnull(res, "Canvas string should not be null");
	mu_assert_streq_free(res, "Hello\n  World\n", "Canvas content check");

	rz_cons_canvas_free(c);
	rz_cons_free();
	mu_end;
}

bool test_canvas_resize(void) {
	rz_cons_new();
	RzConsCanvas *c = rz_cons_canvas_new(5, 2);
	rz_cons_canvas_gotoxy(c, 0, 0);
	rz_cons_canvas_write(c, "Hi");

	bool ret = rz_cons_canvas_resize(c, 10, 4);
	mu_assert_true(ret, "Resize should succeed");
	mu_assert_eq(c->w, 10, "New width 10");
	mu_assert_eq(c->h, 4, "New height 4");

	char *res = rz_cons_canvas_to_string(c);
	mu_assert_notnull(res, "Canvas string should not be null");
	mu_assert_streq_free(res, "\n\n\n", "Canvas cleared after resize");

	rz_cons_canvas_free(c);
	rz_cons_free();
	mu_end;
}

bool test_canvas_gotoxy_bounds(void) {
	rz_cons_new();
	RzConsCanvas *c = rz_cons_canvas_new(10, 5);
	bool ret;

	ret = rz_cons_canvas_gotoxy(c, 0, 0);
	mu_assert_true(ret, "0,0 is valid");

	ret = rz_cons_canvas_gotoxy(c, 9, 4);
	mu_assert_true(ret, "9,4 is valid");

	ret = rz_cons_canvas_gotoxy(c, 10, 0);
	mu_assert_false(ret, "10,0 is OOB x");

	ret = rz_cons_canvas_gotoxy(c, 0, 5);
	mu_assert_false(ret, "0,5 is OOB y");

	rz_cons_canvas_free(c);
	rz_cons_free();
	mu_end;
}

bool test_canvas_fill(void) {
	rz_cons_new();
	RzConsCanvas *c = rz_cons_canvas_new(5, 5);
	rz_cons_canvas_fill(c, 1, 1, 3, 3, 'X');
	char *res = rz_cons_canvas_to_string(c);
	mu_assert_notnull(res, "Canvas string should not be null");
	mu_assert_streq_free(res, "\n XXX\n XXX\n XXX\n", "Canvas fill square");
	rz_cons_canvas_free(c);
	rz_cons_free();
	mu_end;
}

bool test_canvas_box(void) {
	rz_cons_new();
	RzConsCanvas *c = rz_cons_canvas_new(5, 5);
	rz_cons_canvas_box(c, 0, 0, 5, 5, "");
	char *res = rz_cons_canvas_to_string(c);
	// Default box (ASCII)
	// .---.
	// |   |
	// |   |
	// |   |
	// `---'
	mu_assert_notnull(res, "Box string should not be null");
	mu_assert_streq_free(res, ".---.\n|   |\n|   |\n|   |\n`---'", "Box 5x5 content");

	rz_cons_canvas_resize(c, 3, 3);
	rz_cons_canvas_box(c, 0, 0, 3, 3, "");
	res = rz_cons_canvas_to_string(c);
	mu_assert_notnull(res, "Box resized string should not be null");
	mu_assert_streq_free(res, ".-.\n| |\n`-'", "Box 3x3 content");

	rz_cons_canvas_free(c);
	rz_cons_free();
	mu_end;
}

bool test_canvas_lines(void) {
	rz_cons_new();
	RzConsCanvas *c = rz_cons_canvas_new(5, 5);
	RzCanvasLineStyle style = { LINE_NONE, LINE_NOSYM_HORIZ, DOT_STYLE_NORMAL };

	// Diagonal line (0,0) to (3,3)
	rz_cons_canvas_line_diagonal(c, 0, 0, 3, 3, &style);
	char *res = rz_cons_canvas_to_string(c);
	mu_assert_notnull(res, "Diagonal line string should not be null");
	// Expected based on actual run:
	mu_assert_streq_free(res, "-\n \\\n  \\\n\n   |", "Diagonal line 3x3");

	// Square line
	rz_cons_canvas_resize(c, 3, 3);
	rz_cons_canvas_line_square(c, 0, 0, 2, 2, &style);
	res = rz_cons_canvas_to_string(c);
	mu_assert_notnull(res, "Square line string should not be null");
	// Expected:
	// Row 0: -
	// Row 1: '-.
	// Row 2:   |
	mu_assert_streq_free(res, "-\n'-.\n  |", "Square line content");

	rz_cons_canvas_free(c);
	rz_cons_free();
	mu_end;
}

bool all_tests() {
	mu_run_test(test_canvas_new_free);
	mu_run_test(test_canvas_write_tostring);
	mu_run_test(test_canvas_resize);
	mu_run_test(test_canvas_gotoxy_bounds);
	mu_run_test(test_canvas_fill);
	mu_run_test(test_canvas_box);
	mu_run_test(test_canvas_lines);
	return tests_passed != tests_run;
}

mu_main(all_tests)
