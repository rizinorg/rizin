// SPDX-FileCopyrightText: 2019 xarkes
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_flag.h>
#include "minunit.h"

bool test_rz_flag_get_set(void) {
	RzFlag *flags;
	RzFlagItem *fi;

	flags = rz_flag_new();
	mu_assert_notnull(flags, "rz_flag_new () failed");

	rz_flag_set(flags, "foo", 1024, 50);
	fi = rz_flag_get_i(flags, 1024);
	mu_assert_notnull(fi, "cannot find 'foo' flag at 1024");

	rz_flag_set(flags, "foo", 300LL, 0);
	fi = rz_flag_get_i(flags, 0);
	mu_assert_null(fi, "found a flag at 0 while there is none");
	fi = rz_flag_get_i(flags, 300LL);
	mu_assert_notnull(fi, "cannot find 'foo' flag at 300LL");

	fi = rz_flag_get(flags, "foo");
	mu_assert_notnull(fi, "cannot find 'foo' flag");

	rz_flag_free(flags);
	mu_end;
}

bool test_rz_flag_by_spaces(void) {
	RzFlag *flags;
	RzFlagItem *fi;

	flags = rz_flag_new();
	rz_flag_space_set(flags, "sp1");
	rz_flag_set(flags, "foo1", 1024, 50);
	rz_flag_set(flags, "foo2", 1024, 0);
	rz_flag_space_set(flags, "sp2");
	rz_flag_set(flags, "foo3", 1024, 50);
	rz_flag_set(flags, "foo4", 1024, 0);
	rz_flag_space_set(flags, "sp3");
	rz_flag_set(flags, "foo5", 1024, 50);
	rz_flag_set(flags, "foo6", 1024, 0);
	rz_flag_space_set(flags, "sp4");
	rz_flag_set(flags, "foo7", 1024, 50);

	fi = rz_flag_get_by_spaces(flags, 1024, "sp2", "sp4", NULL);
	mu_assert_notnull(fi, "should be retrieved");
	mu_assert_streq(fi->name, "foo3", "first defined in sp2 should be get");

	fi = rz_flag_get_by_spaces(flags, 1024, NULL);
	mu_assert_notnull(fi, "something should be retrieved");
	mu_assert_streq(fi->name, "foo1", "a random one should be get (the first)");

	fi = rz_flag_get_by_spaces(flags, 1024, "sp5", "sp8", "sp1", "sp3", "sp10", NULL);
	mu_assert_notnull(fi, "something should be retrieved");
	mu_assert_streq(fi->name, "foo1", "first defined in sp1 should be get");

	rz_flag_free(flags);
	mu_end;
}

bool test_rz_flag_get_at() {
	RzFlag *flag = rz_flag_new();

	rz_flag_space_set(flag, "sp1");
	RzFlagItem *foo = rz_flag_set(flag, "foo", 1024, 0);

	RzFlagItem *fi;
	fi = rz_flag_get_at(flag, 1024, false);
	mu_assert_ptreq(fi, foo, "flag at exact");
	fi = rz_flag_get_at(flag, 1023, false);
	mu_assert_null(fi, "no flag at -1");
	fi = rz_flag_get_at(flag, 1025, false);
	mu_assert_null(fi, "no flag at +1");

	fi = rz_flag_get_at(flag, 1024, true);
	mu_assert_ptreq(fi, foo, "flag at exact");
	fi = rz_flag_get_at(flag, 1023, true);
	mu_assert_null(fi, "no flag at -1");
	fi = rz_flag_get_at(flag, 1025, true);
	mu_assert_ptreq(fi, foo, "flag at +1");
	fi = rz_flag_get_at(flag, 1234, true);
	mu_assert_ptreq(fi, foo, "flag at +more");

	rz_flag_space_set(flag, "sp2");

	fi = rz_flag_get_at(flag, 1024, false);
	mu_assert_null(fi, "space mask");
	fi = rz_flag_get_at(flag, 1023, false);
	mu_assert_null(fi, "space mask");
	fi = rz_flag_get_at(flag, 1025, false);
	mu_assert_null(fi, "space mask");

	fi = rz_flag_get_at(flag, 1024, true);
	mu_assert_null(fi, "space mask");
	fi = rz_flag_get_at(flag, 1023, true);
	mu_assert_null(fi, "space mask");
	fi = rz_flag_get_at(flag, 1025, true);
	mu_assert_null(fi, "space mask");
	fi = rz_flag_get_at(flag, 1234, true);
	mu_assert_null(fi, "space mask");

	RzFlagItem *oof = rz_flag_set(flag, "oof", 1234, 0);

	fi = rz_flag_get_at(flag, 1234, false);
	mu_assert_ptreq(fi, oof, "other space");

	rz_flag_space_set(flag, "sp1");

	fi = rz_flag_get_at(flag, 1024, false);
	mu_assert_ptreq(fi, foo, "non-interference of spaces");
	fi = rz_flag_get_at(flag, 1023, false);
	mu_assert_null(fi, "non-interference of spaces");
	fi = rz_flag_get_at(flag, 1025, false);
	mu_assert_null(fi, "non-interference of spaces");

	fi = rz_flag_get_at(flag, 1024, true);
	mu_assert_ptreq(fi, foo, "non-interference of spaces");
	fi = rz_flag_get_at(flag, 1023, true);
	mu_assert_null(fi, "non-interference of spaces");
	fi = rz_flag_get_at(flag, 1025, true);
	mu_assert_ptreq(fi, foo, "non-interference of spaces");
	fi = rz_flag_get_at(flag, 1234, true);
	mu_assert_ptreq(fi, foo, "non-interference of spaces");
	fi = rz_flag_get_at(flag, 2048, true);
	mu_assert_ptreq(fi, foo, "non-interference of spaces");

	rz_flag_free(flag);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_rz_flag_get_set);
	mu_run_test(test_rz_flag_by_spaces);
	mu_run_test(test_rz_flag_get_at);
	return tests_passed != tests_run;
}

mu_main(all_tests)
