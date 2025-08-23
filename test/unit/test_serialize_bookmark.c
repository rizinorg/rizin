// SPDX-FileCopyrightText: 2025 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bookmark.h>
#include <rz_flag.h>
#include "minunit.h"
#include "test_sdb.h"

Sdb *ref_0_db() {
	Sdb *db = sdb_new0();

	Sdb *bookmarks_db = sdb_ns(db, "bookmarks", true);
	sdb_set(bookmarks_db, "foobars", "{\"realname\":\"Foobars\",\"from\":4000,\"to\":5000,\"color\":\"white\",\"comment\":\"windowpane\"}");
	sdb_set(bookmarks_db, "f00b4r5", "{\"realname\":\"f00b4r5\",\"from\":5000,\"to\":6213}");
	sdb_set(bookmarks_db, "deliverance", "{\"realname\":\"deliverance\",\"from\":1403,\"to\":1500}");

	return db;
}

RzBookmark *ref_0_bookmark() {
	RzBookmark *bookmark = rz_bookmark_new();

	rz_bookmark_set(bookmark, "deliverance", 0x578 + 3, 1500);
	rz_bookmark_set(bookmark, "f00b4r5", 5000, 6213);

	RzBookmarkItem *foobars = rz_bookmark_set(bookmark, "foobars", 4000, 5000);
	rz_bookmark_item_set_realname(foobars, "Foobars");
	rz_bookmark_item_set_color(foobars, "white");
	rz_bookmark_item_set_comment(foobars, "windowpane");

	return bookmark;
}

RzBookmark *ref_1_bookmark() {
	RzBookmark *bookmark = rz_bookmark_new();
	return bookmark;
}

static bool test_save(RzBookmark *bookmark, Sdb *ref) {
	Sdb *db = sdb_new0();
	rz_serialize_bookmark_save(db, bookmark);
	assert_sdb_eq(db, ref, "save");
	sdb_free(db);
	sdb_free(ref);
	rz_bookmark_free(bookmark);
	return true;
}

typedef struct {
	bool equal;
	RzBookmark *other;
} bookmarkCmpCtx;

static bool bookmark_cmp(RzBookmarkItem *actual, RzBookmarkItem *expected) {
	mu_assert_notnull(expected, "bookmark");
	assert_streq_null(actual->realname, expected->realname, "bookmark realname");
	mu_assert_eq_fmt(actual->from, expected->from, "bookmark from", "0x%" PFMT64x);
	mu_assert_eq_fmt(actual->to, expected->to, "bookmark to", "0x%" PFMT64x);
	assert_streq_null(actual->color, expected->color, "bookmark color");
	assert_streq_null(actual->comment, expected->comment, "bookmark comment");
	return true;
}

static bool bookmark_cmp_cb(RzBookmarkItem *fi, void *user) {
	bookmarkCmpCtx *ctx = user;
	RzBookmarkItem *fo = rz_bookmark_get(ctx->other, fi->name);
	if (!bookmark_cmp(fi, fo)) {
		ctx->equal = false;
		return false;
	}
	return true;
}

static bool test_load(Sdb *db, RzBookmark *ref) {
	RzBookmark *bookmark = rz_bookmark_new();

	bool loaded = rz_serialize_bookmark_load(db, bookmark, NULL);
	sdb_free(db);
	mu_assert("load success", loaded);

	size_t actual_count = rz_bookmark_count(bookmark, NULL);
	size_t expected_count = rz_bookmark_count(ref, NULL);
	mu_assert_eq(actual_count, expected_count, "bookmarks count");

	bookmarkCmpCtx cmp_ctx = { true, ref };
	rz_bookmark_foreach(bookmark, bookmark_cmp_cb, &cmp_ctx);
	mu_assert("bookmarks equal", cmp_ctx.equal);

	rz_bookmark_free(bookmark);
	rz_bookmark_free(ref);
	return true;
}

#define TEST_CALL(name, call) \
	bool name() { \
		if (!(call)) { \
			return false; \
		} \
		mu_end; \
	}

TEST_CALL(test_bookmark_0_save, test_save(ref_0_bookmark(), ref_0_db()));
TEST_CALL(test_bookmark_0_load, test_load(ref_0_db(), ref_0_bookmark()));

int all_tests() {
	mu_run_test(test_bookmark_0_save);
	mu_run_test(test_bookmark_0_load);
	return tests_passed != tests_run;
}

mu_main(all_tests)
