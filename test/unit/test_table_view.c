// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_table_view_in_place(void) {
	RzTable *t = rz_table_new();
	mu_assert_notnull(t, "RzTable created successfully");

	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_STRING, "name");
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_NUMBER, "value");

	rz_table_add_row(t, "apple", "10", NULL);
	rz_table_add_row(t, "banana", "20", NULL);
	rz_table_add_row(t, "cherry", "30", NULL);

	RzTableView *view = rz_table_view_new(t);
	mu_assert_notnull(view, "RzTableView created successfully");
	mu_assert_ptreq(view->table, t, "RzTableView points to the original table");

	bool qr = rz_table_view_query(view, "value/gt/15");
	mu_assert_true(qr, "view query succeeded");

	char *orig_str = rz_table_tostring(t);
	mu_assert_streq(orig_str,
		"name   value \n"
		"-------------\n"
		"banana    20\n"
		"cherry    30\n",
		"original table is modified in-place by view query");
	free(orig_str);

	char *view_str = rz_table_view_tostring(view);
	mu_assert_streq(view_str,
		"name   value \n"
		"-------------\n"
		"banana    20\n"
		"cherry    30\n",
		"view string is correct");
	free(view_str);

	rz_table_view_free(view);
	rz_table_free(t);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_table_view_in_place);
	return tests_passed != tests_run;
}

mu_main(all_tests)
