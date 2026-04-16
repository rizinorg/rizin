// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_config.h>
#include "minunit.h"

bool test_config_strings() {
	RzConfig *cfg = rz_config_new(NULL);
	bool ret = false;
	const char *bla = NULL;

	// normal string
	ret = rz_config_add_string(cfg, "foo.bar", "is foo.bar desc", "bla");
	mu_assert_true(ret, "added foo.bar");

	ret = rz_config_is_readonly(cfg, "foo.bar");
	mu_assert_false(ret, "foo.bar is not readonly");

	bla = rz_config_get_string(cfg, "foo.bar");
	mu_assert_streq(bla, "bla", "String variable 1");

	ret = rz_config_set_string(cfg, "foo.bar", "woff");
	mu_assert_true(ret, "set foo.bar (rw)");

	bla = rz_config_get_string(cfg, "foo.bar");
	mu_assert_streq(bla, "woff", "String variable 2");

	ret = rz_config_set_readonly(cfg, "foo.bar", true);
	mu_assert_true(ret, "foo.bar set as readonly");

	ret = rz_config_is_readonly(cfg, "foo.bar");
	mu_assert_true(ret, "foo.bar is readonly");

	ret = rz_config_set_string(cfg, "foo.bar", "oink");
	mu_assert_false(ret, "set foo.bar (ro) 1");

	bla = rz_config_get_string(cfg, "foo.bar");
	mu_assert_streq(bla, "woff", "String variable 3");

	ret = rz_config_set_readonly(cfg, "foo.bar", false);
	mu_assert_true(ret, "foo.bar set not readonly");

	ret = rz_config_set_string(cfg, "foo.bar", NULL);
	mu_assert_true(ret, "set foo.bar (rw) 2");

	bla = rz_config_get_string(cfg, "foo.bar");
	mu_assert_notnull(bla, "foo.bar is not null");
	mu_assert_streq(bla, "", "String variable 4");

	ret = rz_config_set_any(cfg, "foo.bar", "this is a string");
	mu_assert_true(ret, "set ANY foo.bar");

	bla = rz_config_get_string(cfg, "foo.bar");
	mu_assert_streq(bla, "this is a string", "String variable 5");

	// options string

	ret = rz_config_add_options(cfg, "foo.options", "is foo.options desc", "option1", "option2", "option3", "option4", NULL);
	mu_assert_true(ret, "added foo.options");

	bla = rz_config_get_string(cfg, "foo.options");
	mu_assert_streq(bla, "option1", "options variable 1");

	ret = rz_config_set_string(cfg, "foo.options", "jjjjjjj");
	mu_assert_false(ret, "set foo.options to invalid");

	ret = rz_config_set_string(cfg, "foo.options", "");
	mu_assert_false(ret, "set foo.options to invalid");

	ret = rz_config_set_string(cfg, "foo.options", "option2");
	mu_assert_true(ret, "set foo.options to option2");

	bla = rz_config_get_string(cfg, "foo.options");
	mu_assert_streq(bla, "option2", "options variable 2");

	ret = rz_config_set_any(cfg, "foo.options", "option3");
	mu_assert_true(ret, "set ANY foo.options");

	bla = rz_config_get_string(cfg, "foo.options");
	mu_assert_streq(bla, "option3", "options variable 3");

	rz_config_free(cfg);
	mu_end;
}

bool test_config_intergers() {
	RzConfig *cfg = rz_config_new(NULL);
	bool ret = false;

	// integer variables
	ret = rz_config_add_integer(cfg, "universe.question", "is universe.question desc", 42);
	mu_assert_true(ret, "added universe.question");

	ut64 answer = rz_config_get_integer(cfg, "universe.question");
	mu_assert_eq(answer, 42, "Integer variable 1");

	ret = rz_config_is_readonly(cfg, "universe.question");
	mu_assert_false(ret, "universe.question is not readonly");

	ret = rz_config_set_readonly(cfg, "universe.question", true);
	mu_assert_true(ret, "universe.question set as readonly");

	ret = rz_config_is_readonly(cfg, "universe.question");
	mu_assert_true(ret, "universe.question is readonly");

	ret = rz_config_set_integer(cfg, "universe.question", 99);
	mu_assert_false(ret, "set universe.question (ro)");

	answer = rz_config_get_integer(cfg, "universe.question");
	mu_assert_eq(answer, 42, "Integer variable 2");

	ret = rz_config_set_readonly(cfg, "universe.question", false);
	mu_assert_true(ret, "universe.question is not readonly");

	ret = rz_config_set_any(cfg, "universe.question", "2000");
	mu_assert_true(ret, "set ANY universe.question");

	answer = rz_config_get_integer(cfg, "universe.question");
	mu_assert_eq(answer, 2000, "Integer variable 3");

	rz_config_free(cfg);
	mu_end;
}

bool test_config_booleans() {
	RzConfig *cfg = rz_config_new(NULL);
	bool ret = false;

	// boolean variables
	ret = rz_config_add_bool(cfg, "true.or.false", "is true.or.false desc", true);
	mu_assert_true(ret, "added true.or.false");

	bool what = rz_config_get_bool(cfg, "true.or.false");
	mu_assert_true(what, "Boolean variable");

	ret = rz_config_toggle_bool(cfg, "true.or.false");
	mu_assert_true(ret, "toggle true.or.false");

	what = rz_config_get_bool(cfg, "true.or.false");
	mu_assert_false(what, "Boolean variable (toggle)");

	ret = rz_config_is_readonly(cfg, "true.or.false");
	mu_assert_false(ret, "true.or.false is not readonly");

	ret = rz_config_set_readonly(cfg, "true.or.false", true);
	mu_assert_true(ret, "true.or.false set as readonly");

	ret = rz_config_is_readonly(cfg, "true.or.false");
	mu_assert_true(ret, "true.or.false is readonly");

	ret = rz_config_set_b(cfg, "true.or.false", true);
	mu_assert_false(ret, "set true.or.false (ro)");

	what = rz_config_get_bool(cfg, "true.or.false");
	mu_assert_false(what, "Boolean variable 2");

	ret = rz_config_toggle_bool(cfg, "true.or.false");
	mu_assert_false(ret, "toggle fails true.or.false");

	what = rz_config_get_bool(cfg, "true.or.false");
	mu_assert_false(what, "Boolean variable 2");

	ret = rz_config_set_readonly(cfg, "true.or.false", false);
	mu_assert_true(ret, "true.or.false is not readonly");

	ret = rz_config_set_any(cfg, "true.or.false", "yes");
	mu_assert_true(ret, "set ANY true.or.false");

	what = rz_config_get_bool(cfg, "true.or.false");
	mu_assert_true(what, "Boolean variable 2");

	rz_config_free(cfg);
	mu_end;
}

bool test_config_lists() {
	RzConfig *cfg = rz_config_new(NULL);
	bool ret = false;
	const char *elem = NULL;
	const RzList *list = NULL;
	RzListIter *it;

	// list variables
	ret = rz_config_add_list(cfg, "thy.list", "is thy.list desc", "r1", "r2", "r3", NULL);
	mu_assert_true(ret, "added thy.list");

	list = rz_config_get_list(cfg, "thy.list");
	mu_assert_notnull(list, "List is not null variable");
	mu_assert_eq(rz_list_length(list), 3, "List size is 3");

	it = rz_list_head(list);
	elem = rz_list_val(it);
	mu_assert_streq(elem, "r1", "list[0] is r1");

	it = rz_list_next(it);
	elem = rz_list_val(it);
	mu_assert_streq(elem, "r2", "list[1] is r2");

	it = rz_list_next(it);
	elem = rz_list_val(it);
	mu_assert_streq(elem, "r3", "list[2] is r3");

	ret = rz_config_set_list2(cfg, "thy.list", "x0", "x1", "x2", "x3", "x4", NULL);
	mu_assert_true(ret, "set thy.list");

	list = rz_config_get_list(cfg, "thy.list");
	mu_assert_notnull(list, "List is not null variable");
	mu_assert_eq(rz_list_length(list), 5, "List size is 5");

	elem = rz_list_first_val(list);
	mu_assert_streq(elem, "x0", "list[first] is x0");

	elem = rz_list_last_val(list);
	mu_assert_streq(elem, "x4", "list[last] is x4");

	ret = rz_config_set_list3(cfg, "thy.list", "rax,rbx");
	mu_assert_true(ret, "set thy.list as string");

	list = rz_config_get_list(cfg, "thy.list");
	mu_assert_notnull(list, "List is not null variable");
	mu_assert_eq(rz_list_length(list), 2, "List size is 2");

	ret = rz_config_set_list(cfg, "thy.list", NULL);
	mu_assert_true(ret, "set thy.list as string");

	list = rz_config_get_list(cfg, "thy.list");
	mu_assert_notnull(list, "List is not null variable");
	mu_assert_eq(rz_list_length(list), 0, "List is empty");

	rz_config_free(cfg);
	mu_end;
}

bool test_config_invalid() {
	RzConfig *cfg = rz_config_new(NULL);

	mu_assert_null(rz_config_get_string(cfg, "string.here"), "string.here does not exist");
	mu_assert_null(rz_config_get_list(cfg, "list.here"), "list.here does not exist");
	mu_assert_eq(rz_config_get_integer(cfg, "int.here"), 0, "int.here does not exist");
	mu_assert_false(rz_config_get_bool(cfg, "bool.here"), "bool.here does not exist");

	rz_config_free(cfg);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_config_strings);
	mu_run_test(test_config_intergers);
	mu_run_test(test_config_booleans);
	mu_run_test(test_config_lists);
	mu_run_test(test_config_invalid);
	return tests_passed != tests_run;
}

mu_main(all_tests)
