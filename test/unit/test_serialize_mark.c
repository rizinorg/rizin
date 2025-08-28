// SPDX-FileCopyrightText: 2025 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_mark.h>
#include <rz_flag.h>
#include "minunit.h"
#include "test_sdb.h"

Sdb *ref_0_db() {
	Sdb *db = sdb_new0();

	Sdb *marks_db = sdb_ns(db, "marks", true);
	sdb_set(marks_db, "foobars", "{\"realname\":\"Foobars\",\"from\":4000,\"to\":5000,\"color\":\"white\",\"comment\":\"windowpane\"}");
	sdb_set(marks_db, "f00b4r5", "{\"realname\":\"f00b4r5\",\"from\":5000,\"to\":6213}");
	sdb_set(marks_db, "deliverance", "{\"realname\":\"deliverance\",\"from\":1403,\"to\":1500}");

	return db;
}

RzMark *ref_0_mark() {
	RzMark *mark = rz_mark_new();

	rz_mark_set(mark, "deliverance", 0x578 + 3, 1500);
	rz_mark_set(mark, "f00b4r5", 5000, 6213);

	RzMarkItem *foobars = rz_mark_set(mark, "foobars", 4000, 5000);
	rz_mark_item_set_realname(foobars, "Foobars");
	rz_mark_item_set_color(foobars, "white");
	rz_mark_item_set_comment(foobars, "windowpane");

	return mark;
}

RzMark *ref_1_mark() {
	RzMark *mark = rz_mark_new();
	return mark;
}

static bool test_save(RzMark *mark, Sdb *ref) {
	Sdb *db = sdb_new0();
	rz_serialize_mark_save(db, mark);
	assert_sdb_eq(db, ref, "save");
	sdb_free(db);
	sdb_free(ref);
	rz_mark_free(mark);
	return true;
}

typedef struct {
	bool equal;
	RzMark *other;
} markCmpCtx;

static bool mark_cmp(RzMarkItem *actual, RzMarkItem *expected) {
	mu_assert_notnull(expected, "mark");
	assert_streq_null(actual->realname, expected->realname, "mark realname");
	mu_assert_eq_fmt(actual->from, expected->from, "mark from", "0x%" PFMT64x);
	mu_assert_eq_fmt(actual->to, expected->to, "mark to", "0x%" PFMT64x);
	assert_streq_null(actual->color, expected->color, "mark color");
	assert_streq_null(actual->comment, expected->comment, "mark comment");
	return true;
}

static bool mark_cmp_cb(RzMarkItem *fi, void *user) {
	markCmpCtx *ctx = user;
	RzMarkItem *fo = rz_mark_get(ctx->other, fi->name);
	if (!mark_cmp(fi, fo)) {
		ctx->equal = false;
		return false;
	}
	return true;
}

static bool test_load(Sdb *db, RzMark *ref) {
	RzMark *mark = rz_mark_new();

	bool loaded = rz_serialize_mark_load(db, mark, NULL);
	sdb_free(db);
	mu_assert("load success", loaded);

	size_t actual_count = rz_mark_count(mark, NULL);
	size_t expected_count = rz_mark_count(ref, NULL);
	mu_assert_eq(actual_count, expected_count, "marks count");

	markCmpCtx cmp_ctx = { true, ref };
	rz_mark_foreach(mark, mark_cmp_cb, &cmp_ctx);
	mu_assert("marks equal", cmp_ctx.equal);

	rz_mark_free(mark);
	rz_mark_free(ref);
	return true;
}

#define TEST_CALL(name, call) \
	bool name() { \
		if (!(call)) { \
			return false; \
		} \
		mu_end; \
	}

TEST_CALL(test_mark_0_save, test_save(ref_0_mark(), ref_0_db()));
TEST_CALL(test_mark_0_load, test_load(ref_0_db(), ref_0_mark()));

int all_tests() {
	mu_run_test(test_mark_0_save);
	mu_run_test(test_mark_0_load);
	return tests_passed != tests_run;
}

mu_main(all_tests)
