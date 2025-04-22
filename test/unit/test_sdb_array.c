// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include <sdb.h>
#include "minunit.h"

bool test_sdb_array_push_pop(void) {
	Sdb *db = sdb_new(NULL, NULL, false);
	char *p;

	sdb_array_push(db, "foo", "foo");
	sdb_array_push(db, "foo", "bar");
	sdb_array_push(db, "foo", "cow");

	mu_assert_streq(sdb_const_get(db, "foo"), "cow,bar,foo", "Not all items found");

	p = sdb_array_pop(db, "foo");
	mu_assert_streq(p, "cow", "cow was not at the top");
	free(p);

	p = sdb_array_pop(db, "foo");
	mu_assert_streq(p, "bar", "bar was not at the top");
	free(p);

	p = sdb_array_pop(db, "foo");
	mu_assert_streq(p, "foo", "foo was not at the top");
	free(p);

	p = sdb_array_pop(db, "foo");
	mu_assert_eq((int)(size_t)p, (int)(size_t)NULL, "there shouldn't be any element in the array");
	free(p);

	sdb_free(db);
	mu_end;
}

bool test_sdb_array_add_remove(void) {
	Sdb *db = sdb_new(NULL, NULL, false);
	sdb_array_add(db, "foo", "foo");
	sdb_array_add(db, "foo", "bar");
	sdb_array_add(db, "foo", "cow");

	mu_assert_streq(sdb_const_get(db, "foo"), "foo,bar,cow", "Not all items found");

	sdb_array_remove(db, "foo", "bar");
	mu_assert_streq(sdb_const_get(db, "foo"), "foo,cow", "bar was not deleted");
	sdb_array_remove(db, "foo", "nothing");
	mu_assert_streq(sdb_const_get(db, "foo"), "foo,cow", "nothing should be deleted");
	sdb_array_remove(db, "foo", "cow");
	sdb_array_remove(db, "foo", "foo");
	mu_assert_eq((int)(size_t)sdb_const_get(db, "foo"), (int)(size_t)NULL, "all elements should be deleted");

	sdb_free(db);
	mu_end;
}

int all_tests() {
	mu_run_test(test_sdb_array_push_pop);
	mu_run_test(test_sdb_array_add_remove);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
