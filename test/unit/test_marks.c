// SPDX-FileCopyrightText: 2025 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_mark.h>
#include "minunit.h"

bool test_rz_mark_get_at() {
	RzMark *mark = rz_mark_new();

	RzMarkItem *foo = rz_mark_set(mark, "foo", 1024, 2048);

	RzMarkItem *bi;
	bi = rz_mark_get_start(mark, 1024);
	mu_assert_ptreq(bi, foo, "mark start at exact");
	bi = rz_mark_get_start(mark, 1023);
	mu_assert_null(bi, "no mark start at -1");
	bi = rz_mark_get_start(mark, 1025);
	mu_assert_null(bi, "no mark start at +1");

	bi = rz_mark_get_end(mark, 2048);
	mu_assert_ptreq(bi, foo, "mark end at exact");
	bi = rz_mark_get_start(mark, 2047);
	mu_assert_null(bi, "no mark end at -1");
	bi = rz_mark_get_start(mark, 2049);
	mu_assert_null(bi, "no mark end at +1");

	rz_mark_free(mark);
	mu_end;
}

bool test_rz_mark_set_properties() {
	RzMark *mark = rz_mark_new();
	RzMarkItem *item = rz_mark_set(mark, "foo", 100, 200);
	mu_assert_notnull(item, "mark added");

	rz_mark_item_set_comment(item, "test comment");
	mu_assert_true(item->comment, "set comment works");
	mu_assert_streq(item->comment, "test comment", "comment matches");

	rz_mark_item_set_color(item, "0xFF00FF");
	mu_assert_true(item->comment, "set color works");
	mu_assert_streq(item->color, "0xFF00FF", "color matches");

	rz_mark_item_set_realname(item, "real_foo");
	mu_assert_true(item->realname, "set realname works");
	mu_assert_streq(item->realname, "real_foo", "realname matches");

	rz_mark_free(mark);
	mu_end;
}

bool test_rz_mark_rename() {
	RzMark *mark = rz_mark_new();
	RzMarkItem *item = rz_mark_set(mark, "foo", 100, 200);
	mu_assert_notnull(item, "mark added");

	rz_mark_rename(mark, item, "bar");
	mu_assert_true(item->realname, "rename works");

	mu_assert_false(rz_mark_get(mark, "foo") != NULL, "old name no longer exists");

	RzMarkItem *renamed = rz_mark_get(mark, "bar");
	mu_assert_notnull(renamed, "new name exists");
	mu_assert_streq(renamed->name, "bar", "renamed mark name matches");

	rz_mark_free(mark);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_rz_mark_get_at);
	mu_run_test(test_rz_mark_set_properties);
	mu_run_test(test_rz_mark_rename);
	return tests_passed != tests_run;
}

mu_main(all_tests)
