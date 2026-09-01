// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_table_view_cloning(void) {
	RzTable *t = rz_table_new();
	mu_assert_notnull(t, "RzTable created successfully");

	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_STRING, "name");
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_NUMBER, "value");

	rz_table_add_row(t, "apple", "10", NULL);
	rz_table_add_row(t, "banana", "20", NULL);
	rz_table_add_row(t, "cherry", "30", NULL);

	RzTableView *view = rz_table_view_new(t);
	mu_assert_notnull(view, "RzTableView created successfully");
	mu_assert_ptrneq(view->table, t, "RzTableView table is cloned, not same pointer");

	bool qr = rz_table_view_query(view, "value/gt/15");
	mu_assert_true(qr, "view query succeeded");

	char *orig_str = rz_table_tostring(t);
	mu_assert_streq(orig_str,
		"name   value \n"
		"-------------\n"
		"apple     10\n"
		"banana    20\n"
		"cherry    30\n",
		"original table is unmodified by view query");
	free(orig_str);

	char *view_str = rz_table_view_tostring(view);
	mu_assert_streq(view_str,
		"name   value \n"
		"-------------\n"
		"banana    20\n"
		"cherry    30\n",
		"view string is correct");
	free(view_str);

	qr = rz_table_view_query(view, "value/sort/rev");
	mu_assert_true(qr, "second query succeeded");

	char *view_str2 = rz_table_view_tostring(view);
	mu_assert_streq(view_str2,
		"name   value \n"
		"-------------\n"
		"cherry    30\n"
		"banana    20\n",
		"view string is correct after second query");
	free(view_str2);

	// Create view from view
	RzTableView *view2 = rz_table_view_new_from_view(view);
	mu_assert_notnull(view2, "RzTableView from view created successfully");
	mu_assert_ptrneq(view2->table, view->table, "new view has its own cloned table");

	qr = rz_table_view_query(view2, "value/eq/20");
	mu_assert_true(qr, "query on view2 succeeded");

	char *view2_str = rz_table_view_tostring(view2);
	mu_assert_streq(view2_str,
		"name   value \n"
		"-------------\n"
		"banana    20\n",
		"view2 query results are correct");
	free(view2_str);

	// Verify that view is unmodified by query on view2
	char *view_str3 = rz_table_view_tostring(view);
	mu_assert_streq(view_str3,
		"name   value \n"
		"-------------\n"
		"cherry    30\n"
		"banana    20\n",
		"first view is not modified by query on second view");
	free(view_str3);

	rz_table_view_free(view2);
	rz_table_view_free(view);
	rz_table_free(t);
	mu_end;
}
bool all_tests() {
	mu_run_test(test_rz_table_view_cloning);
	return tests_passed != tests_run;
}

mu_main(all_tests)
