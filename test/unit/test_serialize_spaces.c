// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_spaces.h>
#include "minunit.h"
#include "test_sdb.h"

bool test_spaces_save(void) {
	RzSpaces *spaces = rz_spaces_new("myspaces");
	rz_spaces_add(spaces, "a");
	rz_spaces_add(spaces, "b");
	rz_spaces_add(spaces, "c");
	rz_spaces_add(spaces, PERTURBATOR);

	Sdb *db = sdb_new0();
	rz_serialize_spaces_save(db, spaces);

	Sdb *expected = sdb_new0();
	sdb_set(expected, "name", "myspaces");
	sdb_set(expected, "spacestack", "[\"*\"]");
	Sdb *expected_spaces = sdb_ns(expected, "spaces", true);
	sdb_set(expected_spaces, "a", "s");
	sdb_set(expected_spaces, "b", "s");
	sdb_set(expected_spaces, "c", "s");
	sdb_set(expected_spaces, PERTURBATOR, "s");

	assert_sdb_eq(db, expected, "spaces save (no current, empty stack)");
	sdb_free(db);

	rz_spaces_set(spaces, PERTURBATOR);
	db = sdb_new0();
	rz_serialize_spaces_save(db, spaces);

	sdb_set(expected, "spacestack", "[\"" PERTURBATOR_JSON "\"]");

	assert_sdb_eq(db, expected, "spaces save (current, empty stack)");
	sdb_free(db);

	rz_spaces_push(spaces, "a");
	rz_spaces_push(spaces, "b");
	db = sdb_new0();
	rz_serialize_spaces_save(db, spaces);

	sdb_set(expected, "spacestack", "[\"" PERTURBATOR_JSON "\",\"a\",\"b\"]");
	assert_sdb_eq(db, expected, "spaces save (current, stack)");

	sdb_free(db);
	sdb_free(expected);
	rz_spaces_free(spaces);
	mu_end;
}

bool test_spaces_load_noname_nostack(void) {
	Sdb *db = sdb_new0();
	sdb_set(db, "name", "myspaces");
	sdb_set(db, "spacestack", "[\"*\"]");
	Sdb *db_spaces = sdb_ns(db, "spaces", true);
	sdb_set(db_spaces, "a", "s");
	sdb_set(db_spaces, "b", "s");
	sdb_set(db_spaces, "c", "s");
	sdb_set(db_spaces, PERTURBATOR, "s");

	RzSpaces *spaces = rz_spaces_new("fixed name");
	bool loaded = rz_serialize_spaces_load(db, spaces, false, NULL);
	mu_assert("load success", loaded);
	mu_assert_streq(spaces->name, "fixed name", "spaces load without name");
	mu_assert_null(spaces->current, "spaces load no current");
	mu_assert_eq(rz_list_length(spaces->spacestack), 0, "empty spacestack");
	RBIter rbiter;
	RzSpace *space;
	int i = 0;
	rz_rbtree_foreach (spaces->spaces, rbiter, space, RzSpace, rb) {
		switch (i) {
		case 0:
			mu_assert_streq(space->name, PERTURBATOR, "loaded spaces");
			break;
		case 1:
			mu_assert_streq(space->name, "a", "loaded spaces");
			break;
		case 2:
			mu_assert_streq(space->name, "b", "loaded spaces");
			break;
		case 3:
			mu_assert_streq(space->name, "c", "loaded spaces");
			break;
		default:
			break;
		}
		i++;
	}
	mu_assert_eq(i, 4, "loaded spaces count");
	rz_spaces_free(spaces);

	sdb_free(db);
	mu_end;
}

bool test_spaces_load_name_stack(void) {
	Sdb *db = sdb_new0();
	sdb_set(db, "name", "myspaces");
	sdb_set(db, "spacestack", "[\"a\",\"*\",\"" PERTURBATOR_JSON "\",\"b\",\"" PERTURBATOR_JSON "\"]");
	Sdb *db_spaces = sdb_ns(db, "spaces", true);
	sdb_set(db_spaces, "a", "s");
	sdb_set(db_spaces, "b", "s");
	sdb_set(db_spaces, "c", "s");
	sdb_set(db_spaces, PERTURBATOR, "s");

	RzSpaces *spaces = rz_spaces_new("");
	bool loaded = rz_serialize_spaces_load(db, spaces, true, NULL);
	mu_assert("load success", loaded);
	mu_assert_streq(spaces->name, "myspaces", "loaded name");
	mu_assert_notnull(spaces->current, "current non-null");
	mu_assert_streq(spaces->current->name, PERTURBATOR, "current");
	mu_assert_eq(rz_list_length(spaces->spacestack), 4, "spacestack size");
	mu_assert_streq((const char *)rz_list_get_n(spaces->spacestack, 0), "a", "spacestack");
	mu_assert_streq((const char *)rz_list_get_n(spaces->spacestack, 1), "*", "spacestack");
	mu_assert_streq((const char *)rz_list_get_n(spaces->spacestack, 2), PERTURBATOR, "spacestack");
	mu_assert_streq((const char *)rz_list_get_n(spaces->spacestack, 3), "b", "spacestack");
	RBIter rbiter;
	RzSpace *space;
	int i = 0;
	rz_rbtree_foreach (spaces->spaces, rbiter, space, RzSpace, rb) {
		switch (i) {
		case 0:
			mu_assert_streq(space->name, PERTURBATOR, "loaded spaces");
			break;
		case 1:
			mu_assert_streq(space->name, "a", "loaded spaces");
			break;
		case 2:
			mu_assert_streq(space->name, "b", "loaded spaces");
			break;
		case 3:
			mu_assert_streq(space->name, "c", "loaded spaces");
			break;
		default:
			break;
		}
		i++;
	}
	mu_assert_eq(i, 4, "loaded spaces count");
	rz_spaces_free(spaces);

	sdb_free(db);
	mu_end;
}

int all_tests() {
	mu_run_test(test_spaces_save);
	mu_run_test(test_spaces_load_noname_nostack);
	mu_run_test(test_spaces_load_name_stack);
	return tests_passed != tests_run;
}

mu_main(all_tests)