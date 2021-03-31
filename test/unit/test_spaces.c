// SPDX-FileCopyrightText: 2019 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_space_basic(void) {
	RzSpaces *sps = rz_spaces_new("spacename");
	mu_assert_streq(sps->name, "spacename", "spacename should be the name");

	RzSpace *sp = rz_spaces_get(sps, "notexisting");
	mu_assert_null(sp, "NULL should be returned if not existing");
	sp = rz_spaces_current(sps);
	mu_assert_null(sp, "the current flagspace should not exist");

	sp = rz_spaces_set(sps, "firstspace");
	mu_assert_notnull(sp, "a flagspace should be created");
	mu_assert_streq(sp->name, "firstspace", "right flag space name");

	sp = rz_spaces_current(sps);
	mu_assert_notnull(sp, "the current flagspace should exist");
	mu_assert_streq(sp->name, "firstspace", "right flag space name");

	sp = rz_spaces_get(sps, "firstspace");
	mu_assert_notnull(sp, "a flagspace should be created");
	mu_assert_streq(sp->name, "firstspace", "right flag space name");

	rz_spaces_free(sps);
	mu_end;
}

bool test_space_stack(void) {
	RzSpaces *sps = rz_spaces_new("spacename");

	RzSpace *first = rz_spaces_set(sps, "firstspace");
	rz_spaces_set(sps, "secondspace");
	RzSpace *third = rz_spaces_set(sps, "thirdspace");
	rz_spaces_set(sps, NULL);

	rz_spaces_push(sps, "firstspace");
	rz_spaces_push(sps, "*");
	rz_spaces_push(sps, "thirdspace");

	RzSpace *s = rz_spaces_current(sps);
	mu_assert_ptreq(s, third, "third now set");
	rz_spaces_pop(sps);
	s = rz_spaces_current(sps);
	mu_assert_null(s, "all set");
	rz_spaces_pop(sps);
	s = rz_spaces_current(sps);
	mu_assert_ptreq(s, first, "first now set");
	rz_spaces_pop(sps);
	s = rz_spaces_current(sps);
	mu_assert_null(s, "nothing set");

	rz_spaces_push(sps, "fourthspace");
	s = rz_spaces_current(sps);
	mu_assert_streq(s->name, "fourthspace", "fourth created");

	s = rz_spaces_get(sps, "fourthspace");
	mu_assert_notnull(s, "fourth should exist");

	rz_spaces_free(sps);
	mu_end;
}

static void count_event(RzEvent *ev, int type, void *user, void *data) {
	RzSpaceEvent *spev = (RzSpaceEvent *)data;

	if (!strcmp(spev->data.count.space->name, "firstspace")) {
		spev->res = 1;
	} else if (!strcmp(spev->data.count.space->name, "secondspace")) {
		spev->res = 2;
	} else if (!strcmp(spev->data.count.space->name, "thirdspace")) {
		spev->res = 3;
	}
}

static bool test_event_called = false;

static void test_event(RzEvent *ev, int type, void *user, void *data) {
	test_event_called = true;
}

bool test_space_event(void) {
	RzSpaces *sps = rz_spaces_new("spacename");
	rz_spaces_add(sps, "firstspace");
	rz_spaces_add(sps, "secondspace");
	RzSpace *third = rz_spaces_add(sps, "thirdspace");

	rz_event_hook(sps->event, RZ_SPACE_EVENT_COUNT, count_event, NULL);
	rz_event_hook(sps->event, RZ_SPACE_EVENT_UNSET, test_event, NULL);
	rz_event_hook(sps->event, RZ_SPACE_EVENT_RENAME, test_event, NULL);

	int c = rz_spaces_count(sps, "firstspace");
	mu_assert_eq(c, 1, "first contain 1");
	c = rz_spaces_count(sps, "thirdspace");
	mu_assert_eq(c, 3, "third contain 3");

	test_event_called = false;
	rz_spaces_rename(sps, "thirdspace", "mynewname");
	mu_assert("rename_event has been called", test_event_called);

	RzSpace *s = rz_spaces_get(sps, "thirdspace");
	mu_assert_null(s, "thirdspace should not exist anymore");
	s = rz_spaces_get(sps, "mynewname");
	mu_assert_notnull(s, "mynewname should exist now");
	mu_assert_ptreq(s, third, "and it should be equal to thirdspace ptr");

	test_event_called = false;
	rz_spaces_unset(sps, "mynewname");
	mu_assert("unset_event has been called", test_event_called);

	rz_spaces_free(sps);
	mu_end;
}

int all_tests() {
	mu_run_test(test_space_basic);
	mu_run_test(test_space_stack);
	mu_run_test(test_space_event);
	return tests_passed != tests_run;
}

mu_main(all_tests)