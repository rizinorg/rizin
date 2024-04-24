// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_flag.h>
#include "minunit.h"
#include "test_sdb.h"

Sdb *ref_0_db() {
	Sdb *db = sdb_new0();

	sdb_set(db, "realnames", "1", 0);

	Sdb *spaces_db = sdb_ns(db, "spaces", true);
	sdb_set(spaces_db, "name", "fs", 0);
	sdb_set(spaces_db, "spacestack", "[\"reveries\"]", 0);
	Sdb *spaces_spaces_db = sdb_ns(spaces_db, "spaces", true);
	sdb_set(spaces_spaces_db, "ghost", "s", 0);
	sdb_set(spaces_spaces_db, "reveries", "s", 0);

	Sdb *tags_db = sdb_ns(db, "tags", true);
	sdb_set(tags_db, "tag." PERTURBATOR, PERTURBATOR, 0);
	sdb_set(tags_db, "tag.lotus", "eater", 0);

	Sdb *zones_db = sdb_ns(db, "zones", true);
	sdb_set(zones_db, "blackwater park", "{\"from\":12345,\"to\":12648243}", 0);
	sdb_set(zones_db, PERTURBATOR, "{\"from\":3735928559,\"to\":18446744073709551614}", 0);

	Sdb *flags_db = sdb_ns(db, "flags", true);
	sdb_set(flags_db, "foobars", "{\"realname\":\"Foobars\",\"demangled\":true,\"offset\":4919,\"size\":16,\"space\":\"reveries\",\"color\":\"white\",\"comment\":\"windowpane\",\"alias\":\"f00b4r5\"}", 0);
	sdb_set(flags_db, "f00b4r5", "{\"realname\":\"f00b4r5\",\"demangled\":false,\"offset\":4919,\"size\":1}", 0);
	sdb_set(flags_db, "deliverance", "{\"realname\":\"deliverance\",\"demangled\":false,\"offset\":1403,\"size\":19}", 0);

	return db;
}

RzFlag *ref_0_flag() {
	RzFlag *flag = rz_flag_new();

	flag->realnames = true;

	rz_flag_set(flag, "deliverance", 0x42 + 1337, 0x13);
	rz_flag_set(flag, "f00b4r5", 0x1337, 1);

	rz_flag_space_set(flag, "ghost");
	rz_flag_space_set(flag, "reveries");

	RzFlagItem *foobars = rz_flag_set(flag, "foobars", 0x1337, 0x10);
	rz_flag_item_set_demangled(foobars, true);
	rz_flag_item_set_realname(foobars, "Foobars");
	rz_flag_item_set_color(foobars, "white");
	rz_flag_item_set_comment(foobars, "windowpane");
	rz_flag_item_set_alias(foobars, "f00b4r5");

	rz_flag_tags_set(flag, "lotus", "eater");
	rz_flag_tags_set(flag, PERTURBATOR, PERTURBATOR);

	rz_flag_zone_add(flag, PERTURBATOR, 0xdeadbeef);
	rz_flag_zone_add(flag, PERTURBATOR, UT64_MAX - 1);
	rz_flag_zone_add(flag, "blackwater park", 0xc0ff33);
	rz_flag_zone_add(flag, "blackwater park", 12345);

	return flag;
}

Sdb *ref_1_db() {
	Sdb *db = sdb_new0();

	sdb_set(db, "realnames", "0", 0);

	Sdb *spaces_db = sdb_ns(db, "spaces", true);
	sdb_set(spaces_db, "name", "fs", 0);
	sdb_set(spaces_db, "spacestack", "[\"*\"]", 0);
	sdb_ns(spaces_db, "spaces", true);
	sdb_ns(db, "tags", true);
	sdb_ns(db, "zones", true);
	sdb_ns(db, "flags", true);

	return db;
}

RzFlag *ref_1_flag() {
	RzFlag *flag = rz_flag_new();
	flag->realnames = false;
	return flag;
}

static bool test_save(RzFlag *flag, Sdb *ref) {
	Sdb *db = sdb_new0();
	rz_serialize_flag_save(db, flag);
	assert_sdb_eq(db, ref, "save");
	sdb_free(db);
	sdb_free(ref);
	rz_flag_free(flag);
	return true;
}

static bool space_eq(RzSpace *actual, RzSpace *expected) {
	mu_assert("space null", (!actual) == (!expected));
	if (expected != NULL) {
		mu_assert_streq(actual->name, expected->name, "space name");
	}
	return true;
}

static bool spaces_eq(RzSpaces *actual, RzSpaces *expected) {
	assert_streq_null(actual->name, expected->name, "spaces name");

	RBIter actual_iter = rz_rbtree_first(actual->spaces);
	RBIter expected_iter = rz_rbtree_first(expected->spaces);
	while (rz_rbtree_iter_has(&actual_iter) && rz_rbtree_iter_has(&expected_iter)) {
		RzSpace *actual_space = rz_rbtree_iter_get(&actual_iter, RzSpace, rb);
		RzSpace *expected_space = rz_rbtree_iter_get(&expected_iter, RzSpace, rb);
		if (!space_eq(actual_space, expected_space)) {
			return false;
		}
		rz_rbtree_iter_next(&actual_iter);
		rz_rbtree_iter_next(&expected_iter);
	}
	mu_assert("spaces count", !rz_rbtree_iter_has(&actual_iter) && !rz_rbtree_iter_has(&expected_iter));

	if (!space_eq(actual->current, expected->current)) {
		return false;
	}

	RzListIter *actual_stack_iter = rz_list_iterator(actual->spacestack);
	RzListIter *expected_stack_iter = rz_list_iterator(expected->spacestack);
	while (actual_stack_iter && expected_stack_iter) {
		RzSpace *actual_space = rz_list_iter_get(actual_stack_iter);
		RzSpace *expected_space = rz_list_iter_get(expected_stack_iter);
		if (!space_eq(actual_space, expected_space)) {
			return false;
		}
	}
	mu_assert("spacestack count", !actual_stack_iter && !expected_stack_iter);

	return true;
}

typedef struct {
	bool equal;
	RzFlag *other;
} FlagCmpCtx;

static bool flag_cmp(RzFlagItem *actual, RzFlagItem *expected) {
	mu_assert_notnull(expected, "flag");
	assert_streq_null(rz_flag_item_get_realname(actual), rz_flag_item_get_realname(expected), "flag realname");
	mu_assert_eq(rz_flag_item_get_demangled(actual), rz_flag_item_get_demangled(expected), "flag demangled");
	mu_assert_eq_fmt(rz_flag_item_get_offset(actual), rz_flag_item_get_offset(expected), "flag offset", "0x%" PFMT64x);
	mu_assert_eq_fmt(rz_flag_item_get_size(actual), rz_flag_item_get_size(expected), "flag size", "0x%" PFMT64x);
	RzSpace *expected_space = rz_flag_item_get_space(expected);
	mu_assert_eq(!rz_flag_item_get_space(actual), !expected_space, "flag space null");
	if (expected_space) {
		mu_assert_streq(rz_flag_item_get_space(actual)->name, expected_space->name, "flag space");
	}
	assert_streq_null(rz_flag_item_get_color(actual), rz_flag_item_get_color(expected), "flag color");
	assert_streq_null(rz_flag_item_get_comment(actual), rz_flag_item_get_comment(expected), "flag comment");
	assert_streq_null(rz_flag_item_get_alias(actual), rz_flag_item_get_alias(expected), "flag alias");
	return true;
}

static bool flag_cmp_cb(RzFlagItem *fi, void *user) {
	FlagCmpCtx *ctx = user;
	RzFlagItem *fo = rz_flag_get(ctx->other, rz_flag_item_get_name(fi));
	if (!flag_cmp(fi, fo)) {
		ctx->equal = false;
		return false;
	}
	return true;
}

static bool test_load(Sdb *db, RzFlag *ref) {
	RzFlag *flag = rz_flag_new();

	bool loaded = rz_serialize_flag_load(db, flag, NULL);
	sdb_free(db);
	mu_assert("load success", loaded);

	if (!spaces_eq(&flag->spaces, &ref->spaces)) {
		return false;
	}

	size_t zones_length_actual = flag->zones ? rz_list_length(flag->zones) : 0;
	size_t zones_length_expect = ref->zones ? rz_list_length(ref->zones) : 0;
	mu_assert_eq(zones_length_actual, zones_length_expect, "zones count");
	RzListIter *actual_iter;
	RzFlagZoneItem *actual_zone;
	rz_list_foreach (flag->zones, actual_iter, actual_zone) {
		RzListIter *expected_iter;
		RzFlagZoneItem *expected_zone;
		rz_list_foreach (ref->zones, expected_iter, expected_zone) {
			if (strcmp(actual_zone->name, expected_zone->name) != 0) {
				continue;
			}
			mu_assert_streq(actual_zone->name, expected_zone->name, "zone name");
			mu_assert_eq_fmt(actual_zone->from, expected_zone->from, "zone from", "0x%" PFMT64x);
			mu_assert_eq_fmt(actual_zone->to, expected_zone->to, "zone from", "0x%" PFMT64x);
			goto kontinju;
		}
		mu_assert("zone", false);
	kontinju:
		continue;
	}

	mu_assert_eq(flag->realnames, ref->realnames, "realnames");
	assert_sdb_eq(flag->tags, ref->tags, "tags");

	mu_assert_eq(rz_flag_count(flag, NULL), rz_flag_count(ref, NULL), "flags count");
	FlagCmpCtx cmp_ctx = { true, ref };
	rz_flag_foreach(flag, flag_cmp_cb, &cmp_ctx);

	rz_flag_free(flag);
	rz_flag_free(ref);
	return true;
}

#define TEST_CALL(name, call) \
	bool name() { \
		if (!(call)) { \
			return false; \
		} \
		mu_end; \
	}

TEST_CALL(test_flag_0_save, test_save(ref_0_flag(), ref_0_db()));
TEST_CALL(test_flag_1_save, test_save(ref_1_flag(), ref_1_db()));
TEST_CALL(test_flag_0_load, test_load(ref_0_db(), ref_0_flag()));
TEST_CALL(test_flag_1_load, test_load(ref_1_db(), ref_1_flag()));

int all_tests() {
	mu_run_test(test_flag_0_save);
	mu_run_test(test_flag_1_save);
	mu_run_test(test_flag_0_load);
	mu_run_test(test_flag_1_load);
	return tests_passed != tests_run;
}

mu_main(all_tests)
