// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include <sdb.h>
#include "minunit.h"

// #define SAVE_FILES

static Sdb *test_sdb_new(const char *file) {
#ifdef SAVE_FILES
	Sdb *r = sdb_new(NULL, file, 0);
	// sdb_disk_create (r);
#else
	Sdb *r = sdb_new0();
#endif
	sdb_set(r, "some", "stuff");
	sdb_set(r, "and", "even");
	sdb_set(r, "more", "stuff");

	sdb_ns(r, "emptyns", true);

	Sdb *test_ns = sdb_ns(r, "test", true);
	sdb_set(test_ns, "a", "123");
	sdb_set(test_ns, "b", "test");
	sdb_set(test_ns, "c", "hello");

	Sdb *subspace_ns = sdb_ns(test_ns, "subspace", true);
	sdb_set(subspace_ns, "some", "values");
	sdb_set(subspace_ns, "are", "saved");
	sdb_set(subspace_ns, "here", "lol");
	return r;
}

static void test_sdb_free(Sdb *sdb) {
	if (!sdb) {
		return;
	}
#ifdef SAVE_FILES
	sdb_sync(sdb); // sdb_disk_finish (sdb);
#endif
	sdb_free(sdb);
}

typedef struct {
	char buf[2048];
	size_t buf_len;
} Ctx;

void diff_cb(const SdbDiff *diff, void *user) {
	Ctx *ctx = user;
	int r = sdb_diff_format(ctx->buf + ctx->buf_len, sizeof(ctx->buf) - ctx->buf_len, diff);
	if (r >= 0) {
		ctx->buf_len += r;
		if (ctx->buf_len >= sizeof(ctx->buf)) {
			ctx->buf_len = sizeof(ctx->buf) - 1;
		}
		if (ctx->buf_len < sizeof(ctx->buf) + 1) {
			ctx->buf[ctx->buf_len++] = '\n';
			ctx->buf[ctx->buf_len] = '\0';
		}
	}
}

static bool diff_str(Sdb *a, Sdb *b, char **diff) {
	Ctx ctx = { 0 };
	bool eq = sdb_diff(a, b, diff ? diff_cb : NULL, diff ? &ctx : NULL);
	if (diff) {
		*diff = strdup(ctx.buf);
	}
	return eq;
}

bool test_sdb_diff_equal_empty() {
	Sdb *a = sdb_new0();
	Sdb *b = sdb_new0();
	mu_assert("equal db (no diff)", diff_str(a, b, NULL));
	char *diff;
	mu_assert("equal db (diff)", diff_str(a, b, &diff));
	mu_assert_streq(diff, "", "equal db diff");
	free(diff);
	test_sdb_free(a);
	test_sdb_free(b);
	mu_end;
}

bool test_sdb_diff_equal() {
	Sdb *a = test_sdb_new("equal_a.sdb");
	Sdb *b = test_sdb_new("equal_b.sdb");
	mu_assert("equal db (no diff)", diff_str(a, b, NULL));
	char *diff;
	mu_assert("equal db (diff)", diff_str(a, b, &diff));
	mu_assert_streq(diff, "", "equal db diff");
	free(diff);
	test_sdb_free(a);
	test_sdb_free(b);
	mu_end;
}

bool test_sdb_diff_ns_empty() {
	Sdb *a = test_sdb_new("ns_empty_a.sdb");
	Sdb *b = test_sdb_new("ns_empty_b.sdb");
	sdb_ns_unset(b, "emptyns", NULL);

	mu_assert("empty ns removed (no diff)", !diff_str(a, b, NULL));
	char *diff;
	mu_assert("empty ns removed (diff)", !diff_str(a, b, &diff));
	mu_assert_streq(diff, "-NS emptyns\n", "empty ns removed diff");
	free(diff);

	mu_assert("empty ns added (no diff)", !diff_str(b, a, NULL));
	mu_assert("empty ns added (diff)", !diff_str(b, a, &diff));
	mu_assert_streq(diff, "+NS emptyns\n", "empty ns added diff");
	free(diff);

	test_sdb_free(a);
	test_sdb_free(b);
	mu_end;
}

bool test_sdb_diff_ns() {
	Sdb *a = test_sdb_new("ns_a.sdb");
	Sdb *b = test_sdb_new("ns_b.sdb");
	sdb_ns_unset(b, "test", NULL);

	mu_assert("ns removed (no diff)", !diff_str(a, b, NULL));
	char *diff;
	mu_assert("ns removed (diff)", !diff_str(a, b, &diff));
	mu_assert_streq(diff,
		"-NS test\n"
		"-NS test/subspace\n"
		"-   test/subspace/here=lol\n"
		"-   test/subspace/some=values\n"
		"-   test/subspace/are=saved\n"
		"-   test/a=123\n"
		"-   test/c=hello\n"
		"-   test/b=test\n",
		"ns removed diff");
	free(diff);

	mu_assert("ns added (no diff)", !diff_str(b, a, NULL));
	mu_assert("ns added (diff)", !diff_str(b, a, &diff));
	mu_assert_streq(diff,
		"+NS test\n"
		"+NS test/subspace\n"
		"+   test/subspace/here=lol\n"
		"+   test/subspace/some=values\n"
		"+   test/subspace/are=saved\n"
		"+   test/a=123\n"
		"+   test/c=hello\n"
		"+   test/b=test\n",
		"ns added diff");
	free(diff);

	test_sdb_free(a);
	test_sdb_free(b);
	mu_end;
}

bool test_sdb_diff_ns_sub() {
	Sdb *a = test_sdb_new("ns_sub_a.sdb");
	Sdb *b = test_sdb_new("ns_sub_b.sdb");
	sdb_ns_unset(sdb_ns(b, "test", 0), "subspace", NULL);

	mu_assert("sub ns removed (no diff)", !diff_str(a, b, NULL));
	char *diff;
	mu_assert("sub ns removed (diff)", !diff_str(a, b, &diff));
	mu_assert_streq(diff,
		"-NS test/subspace\n"
		"-   test/subspace/here=lol\n"
		"-   test/subspace/some=values\n"
		"-   test/subspace/are=saved\n",
		"sub ns removed diff");
	free(diff);

	mu_assert("sub ns added (no diff)", !diff_str(b, a, NULL));
	mu_assert("sub ns added (diff)", !diff_str(b, a, &diff));
	mu_assert_streq(diff,
		"+NS test/subspace\n"
		"+   test/subspace/here=lol\n"
		"+   test/subspace/some=values\n"
		"+   test/subspace/are=saved\n",
		"sub ns added diff");
	free(diff);

	test_sdb_free(a);
	test_sdb_free(b);
	mu_end;
}

bool test_sdb_diff_kv() {
	Sdb *a = test_sdb_new("kv_a.sdb");
	Sdb *b = test_sdb_new("kv_b.sdb");
	sdb_unset(b, "more");
	sdb_unset(sdb_ns(b, "test", false), "a");

	mu_assert("kv removed (no diff)", !diff_str(a, b, NULL));
	char *diff;
	mu_assert("kv removed (diff)", !diff_str(a, b, &diff));
	mu_assert_streq(diff,
		"-   test/a=123\n"
		"-   more=stuff\n",
		"ns removed diff");
	free(diff);

	mu_assert("kv added (no diff)", !diff_str(b, a, NULL));
	mu_assert("kv added (diff)", !diff_str(b, a, &diff));
	mu_assert_streq(diff,
		"+   test/a=123\n"
		"+   more=stuff\n",
		"ns added diff");
	free(diff);

	test_sdb_free(a);
	test_sdb_free(b);
	mu_end;
}

bool test_sdb_diff_kv_value() {
	Sdb *a = test_sdb_new("kv_value_a.sdb");
	Sdb *b = test_sdb_new("kv_value_b.sdb");
	sdb_set(b, "more", "cowbell");
	sdb_set(sdb_ns(b, "test", false), "a", "reaper");

	mu_assert("kv value changed (no diff)", !diff_str(a, b, NULL));
	char *diff;
	mu_assert("kv value changed (diff)", !diff_str(a, b, &diff));
	mu_assert_streq(diff,
		"-   test/a=123\n"
		"+   test/a=reaper\n"
		"-   more=stuff\n"
		"+   more=cowbell\n",
		"ns value changed diff");
	free(diff);

	test_sdb_free(a);
	test_sdb_free(b);
	mu_end;
}

int all_tests() {
	mu_run_test(test_sdb_diff_equal_empty);
	mu_run_test(test_sdb_diff_equal);
	mu_run_test(test_sdb_diff_ns_empty);
	mu_run_test(test_sdb_diff_ns);
	mu_run_test(test_sdb_diff_ns_sub);
	mu_run_test(test_sdb_diff_kv);
	mu_run_test(test_sdb_diff_kv_value);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	// Sdb *sdb = test_sdb_new();
	// sdb_query (sdb, "*");
	// sdb_query (sdb, "***");
	// test_sdb_free (sdb);
	// return 0;
	return all_tests();
}
