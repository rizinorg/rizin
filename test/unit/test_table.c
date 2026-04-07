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

bool test_rz_table_query_regressions(void) {
	// book ex 2: length alias should stay str-based for minlen filtering
	RzTable *t = rz_table_new();
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_STRING, "string");
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_NUMBER, "len");

	rz_table_add_row(t, "abcdefgh", "8", NULL);
	rz_table_add_row(t, "(([]A\\A])", "9", NULL);
	rz_table_add_row(t, "longer_string", "13", NULL);

	bool qr = rz_table_query(t, "string/minlen/8:length/sort/rev:*/page/0/15:csv");
	mu_assert_true(qr, "table filter by string length");
	char *s = rz_table_tostring(t);
	mu_assert_streq(s,
		"string,len\n"
		"longer_string,13\n"
		"(([]A\\A]),9\n",
		"book length alias should filter str without parsing them as math");
	free(s);
	rz_table_free(t);

	// str eq must stay str based, even for num looking txt
	t = rz_table_new();
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_STRING, "name");
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_NUMBER, "id");

	rz_table_add_row(t, "16", "1", NULL);
	rz_table_add_row(t, "0x10", "2", NULL);
	rz_table_add_row(t, "010", "3", NULL);
	rz_table_add_row(t, "(([]A\\A])", "4", NULL);

	qr = rz_table_query(t, "name/eq/0x10:id/sort:json");
	mu_assert_true(qr, "table string eq should stay string-based");
	s = rz_table_tostring(t);
	mu_assert_streq(s,
		"[{\"name\":\"0x10\",\"id\":2}]\n",
		"string eq should not match other numeric-looking rows");
	free(s);
	rz_table_free(t);

	// str ineq should exclude only the exact str match on str cols
	t = rz_table_new();
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_STRING, "name");
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_NUMBER, "id");

	rz_table_add_row(t, "16", "1", NULL);
	rz_table_add_row(t, "0x10", "2", NULL);
	rz_table_add_row(t, "010", "3", NULL);
	rz_table_add_row(t, "(([]A\\A])", "4", NULL);

	qr = rz_table_query(t, "name/ne/0x10:id/sort:json");
	mu_assert_true(qr, "table string ne should stay string-based");
	s = rz_table_tostring(t);
	mu_assert_streq(s,
		"[{\"name\":\"16\",\"id\":1},{\"name\":\"010\",\"id\":3},{\"name\":\"(([]A\\\\A])\",\"id\":4}]\n",
		"string ne should only exclude the exact matching row");
	free(s);
	rz_table_free(t);

	// book ex 3: exact vaddr filters and addr alias sorts by the num addr col
	t = rz_table_new();
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_NUMBER, "nth");
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_NUMBER, "vaddr");
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_STRING, "name");

	rz_table_add_row(t, "1", "0x900", "preinit", NULL);
	rz_table_add_row(t, "2", "0x1500", "foo_init", NULL);
	rz_table_add_row(t, "3", "0x1400", "bar_init", NULL);
	rz_table_add_row(t, "4", "0x2000", "foo_init", NULL);

	qr = rz_table_query(t, "name/uniq:vaddr/gt/0x1000:name/str/init:addr/sort:json");
	mu_assert_true(qr, "table filter by addr alias");
	s = rz_table_tostring(t);
	mu_assert_streq(s,
		"[{\"nth\":3,\"vaddr\":5120,\"name\":\"bar_init\"},{\"nth\":2,\"vaddr\":5376,\"name\":\"foo_init\"}]\n",
		"handbook addr alias should sort by the numeric vaddr column");
	free(s);
	rz_table_free(t);

	// addr aliases must not bind to str headers when a num addr col exists
	t = rz_table_new();
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_STRING, "address");
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_NUMBER, "paddr");
	rz_table_add_column(t, RZ_TABLE_COLUMN_TYPE_STRING, "name");

	rz_table_add_row(t, "alpha", "0x10", "late", NULL);
	rz_table_add_row(t, "zeta", "0x2", "early", NULL);

	qr = rz_table_query(t, "addr/sort:json");
	mu_assert_true(qr, "table sort by addr alias should prefer numeric address columns");
	s = rz_table_tostring(t);
	mu_assert_streq(s,
		"[{\"address\":\"zeta\",\"paddr\":2,\"name\":\"early\"},{\"address\":\"alpha\",\"paddr\":16,\"name\":\"late\"}]\n",
		"addr alias should skip string address headers and use numeric address columns");
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
	mu_run_test(test_rz_table_query_regressions);
	return tests_passed != tests_run;
}

mu_main(all_tests)
