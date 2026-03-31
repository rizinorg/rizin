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

bool test_rz_mark_get_all_off() {
	RzMark *mark = rz_mark_new();

	RzMarkItem *a = rz_mark_set(mark, "a", 0x100, 0x120);
	RzMarkItem *b = rz_mark_set(mark, "b", 0x110, 0x130);

	RzList *list = rz_mark_get_all_off(mark, 0x110);
	mu_assert_eq(rz_list_length(list), 2, "2 marks overlap 0x110");

	RzMarkItem *item;
	RzListIter *it;
	int found = 0;
	rz_list_foreach (list, it, item) {
		if (item == a || item == b)
			found++;
	}
	mu_assert_eq(found, 2, "both overlapping items found");

	rz_mark_free(mark);
	mu_end;
}

bool test_rz_mark_all_list() {
	RzMark *mark = rz_mark_new();

	rz_mark_set(mark, "a", 0x100, 0x120);
	rz_mark_set(mark, "b", 0x110, 0x130);
	rz_mark_set(mark, "c", 0x120, 0x140);

	RzList *all = rz_mark_all_list(mark);
	mu_assert_eq(rz_list_length(all), 3, "all marks listed");

	rz_mark_free(mark);
	mu_end;
}

bool test_rz_mark_unset() {
	RzMark *mark = rz_mark_new();
	RzMarkItem *a = rz_mark_set(mark, "a", 0, 10);
	rz_mark_set(mark, "b", 5, 15);

	bool res = rz_mark_unset(mark, a);
	mu_assert_true(res, "unset one mark");
	mu_assert_null(rz_mark_get(mark, "a"), "a no longer exists");

	bool res2 = rz_mark_unset_all_off(mark, 6);
	mu_assert_true(res2, "unset all at offset");
	mu_assert_null(rz_mark_get(mark, "b"), "b no longer exists");

	rz_mark_free(mark);
	mu_end;
}

bool test_rz_mark_rename() {
	RzMark *mark = rz_mark_new();
	RzMarkItem *item = rz_mark_set(mark, "foo", 100, 200);
	mu_assert_notnull(item, "mark added");

	rz_mark_rename(mark, item, "bar");
	mu_assert_null(rz_mark_get(mark, "foo"), "old name no longer exists");

	RzMarkItem *renamed = rz_mark_get(mark, "bar");
	mu_assert_notnull(renamed, "new name exists");
	mu_assert_streq(renamed->name, "bar", "renamed mark name matches");

	mu_assert_true(item == renamed, "renamed item is same object");

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
	mu_assert_true(item->color, "set color works");
	mu_assert_streq(item->color, "0xFF00FF", "color matches");

	rz_mark_item_set_realname(item, "real_foo");
	mu_assert_true(item->realname, "set realname works");
	mu_assert_streq(item->realname, "real_foo", "realname matches");

	rz_mark_free(mark);
	mu_end;
}

bool test_rz_mark_count_and_starts_or_ends() {
	RzMark *mark = rz_mark_new();
	rz_mark_set(mark, "a", 0, 10);
	rz_mark_set(mark, "b", 5, 15);

	int c = rz_mark_count(mark, "*");
	mu_assert_eq(c, 2, "2 marks counted");

	bool so = rz_mark_starts_or_ends(mark, 0, 10);
	mu_assert_true(so, "a starts/ends at 0/10");

	rz_mark_free(mark);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_rz_mark_get_at);
	mu_run_test(test_rz_mark_get_all_off);
	mu_run_test(test_rz_mark_all_list);
	mu_run_test(test_rz_mark_unset);
	mu_run_test(test_rz_mark_set_properties);
	mu_run_test(test_rz_mark_rename);
	mu_run_test(test_rz_mark_count_and_starts_or_ends);
	return tests_passed != tests_run;
}

mu_main(all_tests)
