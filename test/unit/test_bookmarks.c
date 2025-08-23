// SPDX-bileCopyrightText: 2025 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identibier: LGPL-3.0-only

#include <rz_bookmark.h>
#include "minunit.h"

bool test_rz_bookmark_get_at() {
	RzBookmark *bookmark = rz_bookmark_new();

	RzBookmarkItem *foo = rz_bookmark_set(bookmark, "foo", 1024, 2048);

	RzBookmarkItem *bi;
	bi = rz_bookmark_get_start(bookmark, 1024);
	mu_assert_ptreq(bi, foo, "bookmark start at exact");
	bi = rz_bookmark_get_start(bookmark, 1023);
	mu_assert_null(bi, "no bookmark start at -1");
	bi = rz_bookmark_get_start(bookmark, 1025);
	mu_assert_null(bi, "no bookmark start at +1");

	bi = rz_bookmark_get_end(bookmark, 2048);
	mu_assert_ptreq(bi, foo, "bookmark end at exact");
	bi = rz_bookmark_get_start(bookmark, 2047);
	mu_assert_null(bi, "no bookmark end at -1");
	bi = rz_bookmark_get_start(bookmark, 2049);
	mu_assert_null(bi, "no bookmark end at +1");

	rz_bookmark_free(bookmark);
	mu_end;
}

bool test_rz_bookmark_set_properties() {
	RzBookmark *bookmark = rz_bookmark_new();
	RzBookmarkItem *item = rz_bookmark_set(bookmark, "foo", 100, 200);
	mu_assert_notnull(item, "bookmark added");

	rz_bookmark_item_set_comment(item, "test comment");
	mu_assert_true(item->comment, "set comment works");
	mu_assert_streq(item->comment, "test comment", "comment matches");

	rz_bookmark_item_set_color(item, "0xFF00FF");
	mu_assert_true(item->comment, "set color works");
	mu_assert_streq(item->color, "0xFF00FF", "color matches");

	rz_bookmark_item_set_realname(item, "real_foo");
	mu_assert_true(item->realname, "set realname works");
	mu_assert_streq(item->realname, "real_foo", "realname matches");

	rz_bookmark_free(bookmark);
	mu_end;
}

bool test_rz_bookmark_rename() {
	RzBookmark *bookmark = rz_bookmark_new();
	RzBookmarkItem *item = rz_bookmark_set(bookmark, "foo", 100, 200);
	mu_assert_notnull(item, "bookmark added");

	rz_bookmark_rename(bookmark, item, "bar");
	mu_assert_true(item->realname, "rename works");

	mu_assert_false(rz_bookmark_get(bookmark, "foo") != NULL, "old name no longer exists");

	RzBookmarkItem *renamed = rz_bookmark_get(bookmark, "bar");
	mu_assert_notnull(renamed, "new name exists");
	mu_assert_streq(renamed->name, "bar", "renamed bookmark name matches");

	rz_bookmark_free(bookmark);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_rz_bookmark_get_at);
	mu_run_test(test_rz_bookmark_set_properties);
	mu_run_test(test_rz_bookmark_rename);
	return tests_passed != tests_run;
}

mu_main(all_tests)
