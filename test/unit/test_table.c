// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"
#define BUF_LENGTH 100

// TODO test rz_str_chop_path

bool test_rz_table(void) {
	RzTable *t = rz_table_new();

	// rz_table_fromcsv (t, csv);
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_STRING, "name");
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_NUMBER, "address");

	rz_table_add_row(t, "hello", "100", NULL);
	rz_table_add_row(t, "namings", "20000", NULL);

	// rz_table_filter (t, 1, '>', "200");
	// rz_table_filter (t, 1, '=', "100");
	// rz_table_query (t, "[1]/q/100");
	rz_table_sort(t, 1, true);
	{
		char *j = rz_table_tojson(t);
		const char *jOK = "[{\"name\":\"namings\",\"address\":20000},{\"name\":\"hello\",\"address\":100}]";
		mu_assert_streq(j, jOK, "rz_table_get_sections");
		free(j);
	}
	rz_table_free(t);
	mu_end;
}

RzTable *__table_test_data1() {
	RzTable *t = rz_table_new();

	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_STRING, "ascii");
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_NUMBER, "code");

	rz_table_add_row(t, "a", "97", NULL);
	rz_table_add_row(t, "b", "98", NULL);
	rz_table_add_row(t, "c", "99", NULL);

	return t;
}

bool test_rz_table_tostring(void) {
	RzTable *t = __table_test_data1();
	char buf[BUF_LENGTH];

	int i;
	for (i = 0; i < 4; i++) {
		char *s = rz_table_tostring(t);
		snprintf(buf, BUF_LENGTH, "%d-th call to rz_table_tostring", i);
		mu_assert_streq(s,
			"ascii code \n"
			"-----------\n"
			"a       97\n"
			"b       98\n"
			"c       99\n",
			buf);
		free(s);
	}
	rz_table_free(t);
	mu_end;
}

bool test_rz_table_sort1(void) {
	RzTable *t = __table_test_data1();

	rz_table_sort(t, 1, true);
	char *strd = rz_table_tostring(t);
	mu_assert_streq(strd,
		"ascii code \n"
		"-----------\n"
		"c       99\n"
		"b       98\n"
		"a       97\n",
		"sort decreasing second column using number type");
	free(strd);

	rz_table_sort(t, 1, false);
	char *stri = rz_table_tostring(t);
	mu_assert_streq(stri,
		"ascii code \n"
		"-----------\n"
		"a       97\n"
		"b       98\n"
		"c       99\n",
		"sort increasing second column using number type");
	free(stri);
	rz_table_free(t);
	mu_end;
}

bool test_rz_table_uniq(void) {
	RzTable *t = __table_test_data1();

	rz_table_uniq(t);
	char *strd = rz_table_tostring(t);
	mu_assert_streq(strd,
		"ascii code \n"
		"-----------\n"
		"a       97\n"
		"b       98\n"
		"c       99\n",
		"uniq delete nothing");
	free(strd);

	rz_table_add_row(t, "a", "97", NULL);
	rz_table_add_row(t, "a", "97", NULL);
	rz_table_add_row(t, "a", "97", NULL);
	rz_table_add_row(t, "b", "98", NULL);
	rz_table_add_row(t, "c", "99", NULL);
	rz_table_add_row(t, "b", "98", NULL);
	rz_table_add_row(t, "c", "99", NULL);
	rz_table_add_row(t, "d", "99", NULL);
	rz_table_add_row(t, "b", "98", NULL);
	rz_table_add_row(t, "d", "99", NULL);
	rz_table_add_row(t, "c", "99", NULL);
	rz_table_add_row(t, "c", "100", NULL);
	rz_table_uniq(t);
	char *stri = rz_table_tostring(t);
	mu_assert_streq(stri,
		"ascii code \n"
		"-----------\n"
		"a       97\n"
		"b       98\n"
		"c       99\n"
		"d       99\n"
		"c      100\n",
		"uniq delete some rows");
	free(stri);
	rz_table_free(t);
	mu_end;
}

static void simple_merge(RzTableRow *acc, RzTableRow *new_row, size_t nth) {
	RzPVector *lhs = acc->items;
	RzPVector *rhs = new_row->items;
	char *item_lhs;

	for (size_t cnt = 0; cnt < rz_pvector_len(lhs) && cnt < rz_pvector_len(rhs); cnt++) {
		if (cnt == nth) {
			continue;
		}

		item_lhs = rz_pvector_at(lhs, cnt);
		if (!strcmp(item_lhs, "a")) {
			free(item_lhs);
			rz_pvector_set(lhs, cnt, rz_str_dup("a | e"));
		} else if (!strcmp(item_lhs, "b")) {
			free(item_lhs);
			rz_pvector_set(lhs, cnt, rz_str_dup("b | f"));
		} else if (!strcmp(item_lhs, "c")) {
			free(item_lhs);
			rz_pvector_set(lhs, cnt, rz_str_dup("c | h"));
		} else if (!strcmp(item_lhs, "d")) {
			free(item_lhs);
			rz_pvector_set(lhs, cnt, rz_str_dup("d | g"));
		}
	}
}

bool test_rz_table_group(void) {
	RzTable *t = __table_test_data1();

	rz_table_group(t, -1, NULL);
	char *str = rz_table_tostring(t);
	mu_assert_streq(str,
		"ascii code \n"
		"-----------\n"
		"a       97\n"
		"b       98\n"
		"c       99\n",
		"group delete nothing");
	free(str);

	rz_table_add_row(t, "a", "97", NULL);
	rz_table_add_row(t, "a", "97", NULL);
	rz_table_add_row(t, "a", "97", NULL);
	rz_table_add_row(t, "b", "98", NULL);
	rz_table_add_row(t, "c", "99", NULL);
	rz_table_add_row(t, "b", "98", NULL);
	rz_table_add_row(t, "c", "99", NULL);
	rz_table_add_row(t, "d", "1", NULL);
	rz_table_add_row(t, "b", "98", NULL);
	rz_table_add_row(t, "d", "99", NULL);
	rz_table_add_row(t, "c", "99", NULL);
	rz_table_add_row(t, "c", "100", NULL);

	rz_table_group(t, 0, NULL);
	str = rz_table_tostring(t);
	mu_assert_streq(str,
		"ascii code \n"
		"-----------\n"
		"a       97\n"
		"b       98\n"
		"c       99\n"
		"d        1\n",
		"group delete some rows");
	free(str);

	rz_table_add_row(t, "e", "97", NULL);
	rz_table_add_row(t, "f", "98", NULL);
	rz_table_add_row(t, "g", "99", NULL);
	rz_table_add_row(t, "h", "1", NULL);

	rz_table_group(t, 1, simple_merge);
	str = rz_table_tostring(t);
	mu_assert_streq(str,
		"ascii code \n"
		"-----------\n"
		"a | e   97\n"
		"b | f   98\n"
		"c | h   99\n"
		"d | g    1\n",
		"group delete some rows");
	free(str);

	rz_table_free(t);
	mu_end;
}

bool test_rz_table_columns_select() {
	RzTable *t = NULL;
#define CREATE_TABLE \
	rz_table_free(t); \
	t = rz_table_new(); \
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_NUMBER, "name"); \
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_NUMBER, "address"); \
	rz_table_add_row(t, "hello", "100", NULL); \
	rz_table_add_row(t, "namings", "20000", NULL);

	CREATE_TABLE
	char *s = rz_table_tocsv(t);
	mu_assert_streq(s,
		"name,address\n"
		"hello,100\n"
		"namings,20000\n",
		"original");
	free(s);

	RzList *newcols = rz_list_new();
	rz_table_columns_select(t, newcols);
	s = rz_table_tocsv(t);
	mu_assert_streq(s, "", "no cols");
	free(s);

	CREATE_TABLE
	rz_list_push(newcols, "address");
	rz_table_columns_select(t, newcols);
	s = rz_table_tocsv(t);
	mu_assert_streq(s,
		"address\n"
		"100\n"
		"20000\n",
		"select");
	free(s);

	CREATE_TABLE
	rz_list_push(newcols, "name");
	rz_table_columns_select(t, newcols);
	s = rz_table_tocsv(t);
	mu_assert_streq(s,
		"address,name\n"
		"100,hello\n"
		"20000,namings\n",
		"reorder");
	free(s);

	CREATE_TABLE
	rz_list_push(newcols, "name");
	rz_list_push(newcols, "address");
	rz_table_columns_select(t, newcols);
	s = rz_table_tocsv(t);
	mu_assert_streq(s,
		"address,name,name,address\n"
		"100,hello,hello,100\n"
		"20000,namings,namings,20000\n",
		"replicate");
	free(s);

	rz_list_free(newcols);
	rz_table_free(t);
	mu_end;
#undef CREATE_TABLE
}

bool test_rz_table_transpose() {
	RzTable *t = __table_test_data1();
	rz_table_add_row(t, "d", "100", NULL);
	RzTable *transpose = rz_table_transpose(t);
	char *table = rz_table_tostring(transpose);
	mu_assert_streq(table,
		"Name  Value1 Value2 Value3 Value4 \n"
		"----------------------------------\n"
		"ascii a      b      c      d\n"
		"code  97     98     99     100\n",
		"rz_table_transpose");
	free(table);
	rz_table_free(transpose);
	rz_table_free(t);
	mu_end;
}

bool test_rz_table_add_row_columnsf() {
	RzTable *t = __table_test_data1();
	rz_table_add_rowf(t, "s", "e");
	rz_table_add_row_columnsf(t, "d", 10);

	char *table = rz_table_tostring(t);
	mu_assert_streq(table,
		"ascii code \n"
		"-----------\n"
		"a       97\n"
		"b       98\n"
		"c       99\n"
		"e       10\n",
		"rz_table_add_row_columnsf");
	free(table);
	rz_table_free(t);
	mu_end;
}

bool test_rz_table_query(void) {
	RzTable *t = __table_test_data1();
	bool qr = rz_table_query(t, "code/sort/rev");
	mu_assert_true(qr, "table sorted decrementally");
	char *s = rz_table_tostring(t);
	mu_assert_streq(s,
		"ascii code \n"
		"-----------\n"
		"c       99\n"
		"b       98\n"
		"a       97\n",
		"sort table by number column");
	free(s);
	qr = rz_table_query(t, "code/sort/rev");
	mu_assert_true(qr, "table sorted incrementally");
	qr = rz_table_query(t, "code/le/98");
	mu_assert_true(qr, "table filter by <=98");
	s = rz_table_tostring(t);
	mu_assert_streq(s,
		"ascii code \n"
		"-----------\n"
		"b       98\n"
		"a       97\n",
		"filter table by <=98");
	free(s);
	qr = rz_table_query(t, "ascii");
	mu_assert_true(qr, "table columns extraction");
	s = rz_table_tostring(t);
	mu_assert_streq(s,
		"ascii \n"
		"------\n"
		"b\n"
		"a\n",
		"extract only one table column");
	free(s);
	rz_table_free(t);
	t = __table_test_data1();
	qr = rz_table_query(t, ":csv");
	mu_assert_true(qr, "table as CSV");
	s = rz_table_tostring(t);
	mu_assert_streq(s,
		"ascii,code\n"
		"a,97\n"
		"b,98\n"
		"c,99\n",
		"table as CSV");
	free(s);
	qr = rz_table_query(t, ":json");
	mu_assert_true(qr, "table as JSON");
	s = rz_table_tostring(t);
	mu_assert_streq(s,
		"[{\"ascii\":\"a\",\"code\":97},"
		"{\"ascii\":\"b\",\"code\":98},"
		"{\"ascii\":\"c\",\"code\":99}]\n",
		"table as JSON");
	free(s);
	rz_table_free(t);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_table);
	mu_run_test(test_rz_table_tostring);
	mu_run_test(test_rz_table_sort1);
	mu_run_test(test_rz_table_uniq);
	mu_run_test(test_rz_table_group);
	mu_run_test(test_rz_table_columns_select);
	mu_run_test(test_rz_table_transpose);
	mu_run_test(test_rz_table_add_row_columnsf);
	mu_run_test(test_rz_table_query);
	return tests_passed != tests_run;
}

mu_main(all_tests)
