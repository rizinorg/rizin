// SPDX-FileCopyrightText: 2019 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

typedef struct {
	int count;
	int last_type;
	void *last_data;
} EventTestAcc;

static void callback_test(RzEvent *ev, int type, void *user, void *data) {
	EventTestAcc *acc = user;
	acc->count++;
	acc->last_type = type;
	acc->last_data = data;
}

bool test_rz_event(void) {
	RzEvent *ev = rz_event_new((void *)0x1337);
	mu_assert_notnull(ev, "rz_event_new ()");
	mu_assert_ptreq(ev->user, (void *)0x1337, "ev->user");

	EventTestAcc acc_all = { 0 };
	EventTestAcc acc_specific = { 0 };

	RzEventCallbackHandle handle_all = rz_event_hook(ev, RZ_EVENT_ALL, callback_test, &acc_all);
	RzEventCallbackHandle handle_specific = rz_event_hook(ev, RZ_EVENT_META_SET, callback_test, &acc_specific);

	rz_event_send(ev, RZ_EVENT_META_DEL, (void *)0x4242);

	mu_assert_eq(acc_all.count, 1, "all count after event");
	mu_assert_eq(acc_all.last_type, RZ_EVENT_META_DEL, "all type after event");
	mu_assert_ptreq(acc_all.last_data, (void *)0x4242, "all type after event");
	mu_assert_eq(acc_specific.count, 0, "specific count after other event");

	rz_event_send(ev, RZ_EVENT_META_SET, (void *)0xdeadbeef);

	mu_assert_eq(acc_all.count, 2, "all count after event");
	mu_assert_eq(acc_all.last_type, RZ_EVENT_META_SET, "all type after event");
	mu_assert_ptreq(acc_all.last_data, (void *)0xdeadbeef, "all type after event");

	mu_assert_eq(acc_specific.count, 1, "specific count after event");
	mu_assert_eq(acc_specific.last_type, RZ_EVENT_META_SET, "specific type after event");
	mu_assert_ptreq(acc_specific.last_data, (void *)0xdeadbeef, "specific type after event");

	rz_event_unhook(ev, handle_all);
	rz_event_send(ev, RZ_EVENT_META_SET, (void *)0xc0ffee);

	mu_assert_eq(acc_all.count, 2, "all count after event after being removed");
	mu_assert_eq(acc_all.last_type, RZ_EVENT_META_SET, "all type after event after being removed");
	mu_assert_ptreq(acc_all.last_data, (void *)0xdeadbeef, "all type after event after being removed");

	mu_assert_eq(acc_specific.count, 2, "specific count after event");
	mu_assert_eq(acc_specific.last_type, RZ_EVENT_META_SET, "specific type after event");
	mu_assert_ptreq(acc_specific.last_data, (void *)0xc0ffee, "specific type after event");

	rz_event_unhook(ev, handle_specific);
	rz_event_send(ev, RZ_EVENT_META_SET, (void *)0xc0ffee);

	mu_assert_eq(acc_specific.count, 2, "specific count after event after being removed");
	mu_assert_eq(acc_specific.last_type, RZ_EVENT_META_SET, "specific type after event after being removed");
	mu_assert_ptreq(acc_specific.last_data, (void *)0xc0ffee, "specific type after event after being removed");

	rz_event_free(ev);

	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_event);
	return tests_passed != tests_run;
}

mu_main(all_tests)