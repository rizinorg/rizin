// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_config.h>
#include "minunit.h"

static bool test_config_validator(void *user, const void *value) {
	(void)value;
	return user != NULL;
}

bool test_config_strings() {
	RzConfig *cfg = rz_config_new(NULL);
	bool ret = false;
	const char *bla = NULL;

	// normal string
	ret = rz_config_add_string(cfg, "foo.bar", "is foo.bar desc", "bla");
	mu_assert_true(ret, "added foo.bar");

	ret = rz_config_set_validator(cfg, "foo.bar", test_config_validator, &ret);
	mu_assert_true(ret, "can set validator when options NOT are set");

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

	ret = rz_config_set_validator(cfg, "foo.options", test_config_validator, &ret);
	mu_assert_false(ret, "cannot set validator when options are set");

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

	char *s = rz_config_get_as_string(cfg, "foo.options");
	mu_assert_streq(s, "option3", "get as string foo.options");
	free(s);

	rz_config_free(cfg);
	mu_end;
}

bool test_config_intergers() {
	RzConfig *cfg = rz_config_new(NULL);
	bool ret = false;

	// integer variables
	ret = rz_config_add_integer(cfg, "universe.question", "is universe.question desc", 42);
	mu_assert_true(ret, "added universe.question");

	ret = rz_config_set_validator(cfg, "universe.question", test_config_validator, &ret);
	mu_assert_true(ret, "can set validator for int");

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

	char *s = rz_config_get_as_string(cfg, "universe.question");
	mu_assert_streq(s, "2000", "get as string universe.question");
	free(s);

	rz_config_free(cfg);
	mu_end;
}

bool test_config_booleans() {
	RzConfig *cfg = rz_config_new(NULL);
	bool ret = false;

	// boolean variables
	ret = rz_config_add_bool(cfg, "true.or.false", "is true.or.false desc", true);
	mu_assert_true(ret, "added true.or.false");

	ret = rz_config_set_validator(cfg, "true.or.false", test_config_validator, &ret);
	mu_assert_true(ret, "can set validator for bool");

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

	char *s = rz_config_get_as_string(cfg, "true.or.false");
	mu_assert_streq(s, "true", "get as string true.or.false");
	free(s);

	rz_config_free(cfg);
	mu_end;
}

bool test_config_lists() {
	RzConfig *cfg = rz_config_new(NULL);
	bool ret = false;
	const char *elem = NULL;
	RzList *list = NULL;
	RzListIter *it;

	// list variables
	ret = rz_config_add_list(cfg, "thy.list", "is thy.list desc", "r1", "r2", "r3", NULL);
	mu_assert_true(ret, "added thy.list");

	ret = rz_config_set_validator(cfg, "thy.list", test_config_validator, &ret);
	mu_assert_true(ret, "can set validator for list");

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
	rz_list_free(list);

	ret = rz_config_set_list2(cfg, "thy.list", "x0", "x1", "x2", "x3", "x4", NULL);
	mu_assert_true(ret, "set thy.list");

	list = rz_config_get_list(cfg, "thy.list");
	mu_assert_notnull(list, "List is not null variable");
	mu_assert_eq(rz_list_length(list), 5, "List size is 5");

	char *s = rz_config_get_as_string(cfg, "thy.list");
	mu_assert_streq(s, "x0,x1,x2,x3,x4", "get as string thy.list");
	free(s);

	elem = rz_list_first_val(list);
	mu_assert_streq(elem, "x0", "list[first] is x0");

	elem = rz_list_last_val(list);
	mu_assert_streq(elem, "x4", "list[last] is x4");
	rz_list_free(list);

	ret = rz_config_set_list3(cfg, "thy.list", "rax,rbx");
	mu_assert_true(ret, "set thy.list as string");

	list = rz_config_get_list(cfg, "thy.list");
	mu_assert_notnull(list, "List is not null variable");
	mu_assert_eq(rz_list_length(list), 2, "List size is 2");
	rz_list_free(list);

	ret = rz_config_set_list(cfg, "thy.list", NULL);
	mu_assert_true(ret, "set thy.list as string");

	list = rz_config_get_list(cfg, "thy.list");
	mu_assert_notnull(list, "List is not null variable");
	mu_assert_eq(rz_list_length(list), 0, "List is empty");
	rz_list_free(list);

	rz_config_free(cfg);
	mu_end;
}

bool test_config_itv() {
	RzConfig *cfg = rz_config_new(NULL);
	bool ret = false;
	RzInterval itv = { 0 };

	// interval variables
	ret = rz_config_add_interval(cfg, "this.limit", "is this.limit desc", 0x230, 0x4fff);
	mu_assert_true(ret, "added this.limit [0x230, 0x4fff]");

	ret = rz_config_set_validator(cfg, "this.limit", test_config_validator, &ret);
	mu_assert_true(ret, "can set validator for itv");

	itv = rz_config_get_interval(cfg, "this.limit");
	mu_assert_eq(rz_itv_begin(itv), 0x230, "interval starts at 0x230 (inclusive)");
	mu_assert_eq(rz_itv_end(itv), 0x4fff, "interval ends at 0x4fff (inclusive)");
	mu_assert_eq(rz_itv_size(itv), 0x4dcf, "interval size at 0x4dcf");

	itv.addr = 0x1000;
	itv.size = 0x4f;
	ret = rz_config_set_interval(cfg, "this.limit", itv);
	mu_assert_true(ret, "set this.limit [0x1000, 0x104f]");

	itv = rz_config_get_interval(cfg, "this.limit");
	mu_assert_eq(rz_itv_begin(itv), 0x1000, "interval starts at 0x1000 (inclusive)");
	mu_assert_eq(rz_itv_end(itv), 0x104f, "interval ends at 0x104f (inclusive)");
	mu_assert_eq(rz_itv_size(itv), 0x4f, "interval size at 0x4f");

	ret = rz_config_set_interval2(cfg, "this.limit", 0x80000000, 0x8fffffff);
	mu_assert_true(ret, "set this.limit [0x80000000, 0x8fffffff]");

	itv = rz_config_get_interval(cfg, "this.limit");
	mu_assert_eq(rz_itv_begin(itv), 0x80000000, "interval starts at 0x80000000 (inclusive)");
	mu_assert_eq(rz_itv_end(itv), 0x8fffffff, "interval ends at 0x8fffffff (inclusive)");
	mu_assert_eq(rz_itv_size(itv), 0xfffffff, "interval size at 0xfffffff");

	ret = rz_config_is_readonly(cfg, "this.limit");
	mu_assert_false(ret, "this.limit is not readonly");

	ret = rz_config_set_readonly(cfg, "this.limit", true);
	mu_assert_true(ret, "this.limit set as readonly");

	ret = rz_config_is_readonly(cfg, "this.limit");
	mu_assert_true(ret, "this.limit is readonly");

	ret = rz_config_set_interval2(cfg, "this.limit", 0, 1);
	mu_assert_false(ret, "set this.limit [0, 1] RO");

	itv = rz_config_get_interval(cfg, "this.limit");
	mu_assert_eq(rz_itv_begin(itv), 0x80000000, "interval starts at 0x80000000 (inclusive)");
	mu_assert_eq(rz_itv_end(itv), 0x8fffffff, "interval ends at 0x8fffffff (inclusive)");
	mu_assert_eq(rz_itv_size(itv), 0xfffffff, "interval size at 0xfffffff");

	ret = rz_config_set_readonly(cfg, "this.limit", false);
	mu_assert_true(ret, "this.limit set as readonly");

	ret = rz_config_is_readonly(cfg, "this.limit");
	mu_assert_false(ret, "this.limit is not readonly");

	ret = rz_config_set_interval3(cfg, "this.limit", " 0x11111 , 0x22222     ");
	mu_assert_true(ret, "set this.limit [0x11111, 0x22222]");

	itv = rz_config_get_interval(cfg, "this.limit");
	mu_assert_eq(rz_itv_begin(itv), 0x11111, "interval starts at 0x11111 (inclusive)");
	mu_assert_eq(rz_itv_end(itv), 0x22222, "interval ends at 0x22222 (inclusive)");
	mu_assert_eq(rz_itv_size(itv), 0x11111, "interval size at 0x11111");

	ret = rz_config_set_interval2(cfg, "this.limit", 0x80000000, 0x100);
	mu_assert_false(ret, "cannot set this.limit [0x80000000, 0x100]");

	ret = rz_config_set_interval3(cfg, "this.limit", "0x500000,0x8888");
	mu_assert_false(ret, "cannot set this.limit [0x500000, 0x8888]");

	ret = rz_config_add_interval(cfg, "bad.limit", NULL, 0x9999, 0);
	mu_assert_false(ret, "cannot set bad.limit [0x9999, 0]");

	char *s = rz_config_get_as_string(cfg, "this.limit");
	mu_assert_streq(s, "0x00011111,0x00022222", "get as string this.limit");
	free(s);

	rz_config_free(cfg);
	mu_end;
}

bool test_config_invalid() {
	RzInterval itv = { 0x1000, 0x2000 };
	RzConfig *cfg = rz_config_new(NULL);

	mu_assert_null(rz_config_get_string(cfg, "string.here"), "string.here does not exist");
	mu_assert_null(rz_config_get_list(cfg, "list.here"), "list.here does not exist");
	mu_assert_eq(rz_config_get_integer(cfg, "int.here"), 0, "int.here does not exist");
	mu_assert_false(rz_config_get_bool(cfg, "bool.here"), "bool.here does not exist");
	mu_assert_false(rz_config_set_validator(cfg, "self.validator", test_config_validator, &itv), "self.validator does not exist");
	itv = rz_config_get_interval(cfg, "itv.here");
	mu_assert_eq(rz_itv_begin(itv), 0, "itv.here does not exist (addr = 0)");
	mu_assert_eq(rz_itv_size(itv), 0, "itv.here does not exist (size = 0)");

	rz_config_free(cfg);
	mu_end;
}

typedef struct bind_test_s {
	ut32 get;
	ut32 set;
	ut32 opts;
	ut32 bind;
	const void *set_val;
	RzList *list;
} bind_test_t;

static bool any_get(void *user, void *p) {
	bind_test_t *bt = user;
	switch (bt->bind) {
	case RZ_CONFIG_VAR_TYPE_BOOL: {
		bool *value = p;
		*value = true;
		bt->get++;
		return true;
	}
	case RZ_CONFIG_VAR_TYPE_INT: {
		ut64 *value = p;
		*value = 42;
		bt->get++;
		return true;
	}
	case RZ_CONFIG_VAR_TYPE_STR: {
		const char **value = p;
		*value = "what";
		bt->get++;
		return true;
	}
	case RZ_CONFIG_VAR_TYPE_LIST: {
		const RzList **value = p;
		*value = bt->list;
		bt->get++;
		return true;
	}
	case RZ_CONFIG_VAR_TYPE_ITV: {
		RzInterval *value = p;
		value->addr = 0x2222;
		value->size = 0x1111;
		bt->get++;
		return true;
	}
	default:
		return false;
	}
}

static bool any_set(void *user, const void *p) {
	bind_test_t *bt = user;
	switch (bt->bind) {
	case RZ_CONFIG_VAR_TYPE_BOOL:
		bt->set_val = NULL;
		bt->set++;
		return true;
	case RZ_CONFIG_VAR_TYPE_INT:
		bt->set_val = (void *)5555;
		bt->set++;
		return true;
	case RZ_CONFIG_VAR_TYPE_STR:
		/* fall-thru */
	case RZ_CONFIG_VAR_TYPE_LIST:
		bt->set_val = p;
		bt->set++;
		return true;
	case RZ_CONFIG_VAR_TYPE_ITV: {
		const RzInterval *itv = p;
		RzInterval *v = (void *)bt->set_val;
		*v = *itv;
		bt->set++;
		return true;
	}
	default:
		return false;
	}
}

static bool any_opts(void *user, RzList /*<char *>*/ **options) {
	bind_test_t *bt = user;
	switch (bt->bind) {
	case RZ_CONFIG_VAR_TYPE_STR:
		*options = rz_str_split_duplist("foo,bar", ",", true);
		bt->opts++;
		return true;
	case RZ_CONFIG_VAR_TYPE_BOOL:
		/* fall-thru */
	case RZ_CONFIG_VAR_TYPE_INT:
		/* fall-thru */
	case RZ_CONFIG_VAR_TYPE_LIST:
		/* fall-thru */
	case RZ_CONFIG_VAR_TYPE_ITV:
		bt->opts++;
		return true;
	default:
		return false;
	}
}

bool test_config_binds() {
	bool ret = false;
	bind_test_t bt = { 0 };
	RzInterval itv = { 0x1000, 0x2000 };

	RzConfig *cfg = rz_config_new(NULL);
	mu_assert_notnull(cfg, "alloc RzConfig");

	bt.list = rz_str_split_duplist("init,fini", ",", true);
	mu_assert_notnull(bt.list, "alloc list");

	// add binds
	bt.bind = RZ_CONFIG_VAR_TYPE_BOOL;
	ret = rz_config_add_bool_bind(cfg, "bind.bool", "is bind.bool desc", any_get, any_set, any_opts, &bt);
	mu_assert_true(ret, "added bind.bool");

	ret = rz_config_set_validator(cfg, "bind.bool", test_config_validator, &ret);
	mu_assert_false(ret, "cannot set validator when bind");

	bt.bind = RZ_CONFIG_VAR_TYPE_INT;
	ret = rz_config_add_integer_bind(cfg, "bind.integer", "is bind.integer desc", any_get, any_set, any_opts, &bt);
	mu_assert_true(ret, "added bind.integer");

	ret = rz_config_set_validator(cfg, "bind.integer", test_config_validator, &ret);
	mu_assert_false(ret, "cannot set validator when bind");

	bt.bind = RZ_CONFIG_VAR_TYPE_STR;
	ret = rz_config_add_string_bind(cfg, "bind.string", "is bind.string desc", any_get, any_set, any_opts, &bt);
	mu_assert_true(ret, "added bind.string");

	ret = rz_config_set_validator(cfg, "bind.string", test_config_validator, &ret);
	mu_assert_false(ret, "cannot set validator when bind");

	bt.bind = RZ_CONFIG_VAR_TYPE_LIST;
	ret = rz_config_add_list_bind(cfg, "bind.list", "is bind.list desc", any_get, any_set, any_opts, &bt);
	mu_assert_true(ret, "added bind.list");

	ret = rz_config_set_validator(cfg, "bind.list", test_config_validator, &ret);
	mu_assert_false(ret, "cannot set validator when bind");

	bt.bind = RZ_CONFIG_VAR_TYPE_ITV;
	ret = rz_config_add_interval_bind(cfg, "bind.interval", "is bind.interval desc", any_get, any_set, any_opts, &bt);
	mu_assert_true(ret, "added bind.interval");

	ret = rz_config_set_validator(cfg, "bind.interval", test_config_validator, &ret);
	mu_assert_false(ret, "cannot set validator when bind");

	bt.bind = RZ_CONFIG_VAR_TYPE_BOOL;
	mu_assert_true(rz_config_get_bool(cfg, "bind.bool"), "get bind.bool");

	bt.bind = RZ_CONFIG_VAR_TYPE_INT;
	mu_assert_eq(rz_config_get_integer(cfg, "bind.integer"), 42, "get bind.integer");

	bt.bind = RZ_CONFIG_VAR_TYPE_STR;
	mu_assert_streq(rz_config_get_string(cfg, "bind.string"), "what", "get bind.string");

	bt.bind = RZ_CONFIG_VAR_TYPE_LIST;
	mu_assert_ptreq(rz_config_get_list(cfg, "bind.list"), bt.list, "get bind.list");

	bt.bind = RZ_CONFIG_VAR_TYPE_ITV;
	itv = rz_config_get_interval(cfg, "bind.interval");
	mu_assert_eq(rz_itv_begin(itv), 0x2222, "bind.interval does not exist (addr = 0x2222)");
	mu_assert_eq(rz_itv_size(itv), 0x1111, "bind.interval does not exist (size = 0x1111)");

	bt.bind = RZ_CONFIG_VAR_TYPE_BOOL;
	ret = rz_config_set_bool(cfg, "bind.bool", false);
	mu_assert_true(ret, "set bind.bool");
	mu_assert_null(bt.set_val, "has actually set bind.bool");

	bt.bind = RZ_CONFIG_VAR_TYPE_INT;
	ret = rz_config_set_integer(cfg, "bind.integer", 5555);
	mu_assert_true(ret, "set bind.integer");
	mu_assert_ptreq(bt.set_val, (void *)5555, "has actually set bind.integer");

	bt.bind = RZ_CONFIG_VAR_TYPE_STR;
	ret = rz_config_set_string(cfg, "bind.string", "foo");
	mu_assert_true(ret, "set bind.string");
	mu_assert_streq(bt.set_val, "foo", "has actually set bind.string");

	bt.bind = RZ_CONFIG_VAR_TYPE_LIST;
	ret = rz_config_set_list(cfg, "bind.list", bt.list);
	mu_assert_true(ret, "set bind.list");
	mu_assert_ptreq(bt.set_val, bt.list, "has actually set bind.list");

	bt.bind = RZ_CONFIG_VAR_TYPE_ITV;
	bt.set_val = &itv;
	ret = rz_config_set_interval2(cfg, "bind.interval", 0x80000000, 0x8fffffff);
	mu_assert_true(ret, "set bind.interval");
	mu_assert_eq(rz_itv_begin(itv), 0x80000000, "bind.interval does not exist (beg = 0x80000000)");
	mu_assert_eq(rz_itv_end(itv), 0x8fffffff, "bind.interval does not exist (end = 0x8fffffff)");

	mu_assert_eq(bt.opts, 5, "called bind.get_options");
	mu_assert_eq(bt.get, 5, "called bind.get_value");
	mu_assert_eq(bt.set, 5, "called bind.set_value");

	rz_config_free(cfg);
	rz_list_free(bt.list);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_config_strings);
	mu_run_test(test_config_intergers);
	mu_run_test(test_config_booleans);
	mu_run_test(test_config_lists);
	mu_run_test(test_config_itv);
	mu_run_test(test_config_invalid);
	mu_run_test(test_config_binds);
	return tests_passed != tests_run;
}

mu_main(all_tests)
