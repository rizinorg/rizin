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

	rz_event_send(ev, RZ_EVENT_META_DEL, (void *)(size_t)0x4242);

	mu_assert_eq(acc_all.count, 1, "all count after event");
	mu_assert_eq(acc_all.last_type, RZ_EVENT_META_DEL, "all type after event");
	mu_assert_ptreq(acc_all.last_data, (void *)0x4242, "all type after event");
	mu_assert_eq(acc_specific.count, 0, "specific count after other event");

	rz_event_send(ev, RZ_EVENT_META_SET, (void *)(size_t)0xdeadbeef);

	mu_assert_eq(acc_all.count, 2, "all count after event");
	mu_assert_eq(acc_all.last_type, RZ_EVENT_META_SET, "all type after event");
	mu_assert_ptreq(acc_all.last_data, (void *)0xdeadbeef, "all type after event");

	mu_assert_eq(acc_specific.count, 1, "specific count after event");
	mu_assert_eq(acc_specific.last_type, RZ_EVENT_META_SET, "specific type after event");
	mu_assert_ptreq(acc_specific.last_data, (void *)0xdeadbeef, "specific type after event");

	rz_event_unhook(ev, handle_all);
	rz_event_send(ev, RZ_EVENT_META_SET, (void *)(size_t)0xc0ffee);

	mu_assert_eq(acc_all.count, 2, "all count after event after being removed");
	mu_assert_eq(acc_all.last_type, RZ_EVENT_META_SET, "all type after event after being removed");
	mu_assert_ptreq(acc_all.last_data, (void *)0xdeadbeef, "all type after event after being removed");

	mu_assert_eq(acc_specific.count, 2, "specific count after event");
	mu_assert_eq(acc_specific.last_type, RZ_EVENT_META_SET, "specific type after event");
	mu_assert_ptreq(acc_specific.last_data, (void *)0xc0ffee, "specific type after event");

	rz_event_unhook(ev, handle_specific);
	rz_event_send(ev, RZ_EVENT_META_SET, (void *)(size_t)0xc0ffee);

	mu_assert_eq(acc_specific.count, 2, "specific count after event after being removed");
	mu_assert_eq(acc_specific.last_type, RZ_EVENT_META_SET, "specific type after event after being removed");
	mu_assert_ptreq(acc_specific.last_data, (void *)0xc0ffee, "specific type after event after being removed");

	rz_event_free(ev);

	mu_end;
}

static void callback_inc(RzEvent *ev, int type, void *user, void *data) {
	(*(int *)user)++;
}

typedef struct {
	RzEventCallbackHandle handle;
	int counter;
} SelfUnhookCtx;

static void callback_inc_self_unhook(RzEvent *ev, int type, void *user, void *data) {
	SelfUnhookCtx *ctx = user;
	ctx->counter++;
	rz_event_unhook(ev, ctx->handle);
}

bool test_rz_event_self_unhook(int hook_type, int send_type) {
	// hook some counter-increasing callbacks and one in between that unhooks itself
	int counters[4] = { 0 };
	SelfUnhookCtx ctx = { 0 };
	RzEvent *ev = rz_event_new(NULL);
	rz_event_hook(ev, hook_type, callback_inc, &counters[0]);
	rz_event_hook(ev, hook_type, callback_inc, &counters[1]);
	ctx.handle = rz_event_hook(ev, hook_type, callback_inc_self_unhook, &ctx);
	rz_event_hook(ev, hook_type, callback_inc, &counters[2]);
	rz_event_hook(ev, hook_type, callback_inc, &counters[3]);

	rz_event_send(ev, send_type, NULL);
	// after the first event, all callbacks should have been triggered once
	mu_assert_eq(counters[0], 1, "persistently hooked counter 0");
	mu_assert_eq(counters[1], 1, "persistently hooked counter 1");
	mu_assert_eq(counters[2], 1, "persistently hooked counter 2");
	mu_assert_eq(counters[3], 1, "persistently hooked counter 3");
	mu_assert_eq(ctx.counter, 1, "now unhooked counter increased on first event");

	// at this point the self-unhooking should be unhooked already
	// but the others should still be there.
	rz_event_send(ev, send_type, NULL);
	mu_assert_eq(counters[0], 2, "persistently hooked counter 0");
	mu_assert_eq(counters[1], 2, "persistently hooked counter 1");
	mu_assert_eq(counters[2], 2, "persistently hooked counter 2");
	mu_assert_eq(counters[3], 2, "persistently hooked counter 3");
	mu_assert_eq(ctx.counter, 1, "unhooked counter is unhooked");

	rz_event_free(ev);
	mu_end;
}

bool test_rz_event_unhook_by_callback(void) {
	int shared = 0;
	int other = 0;
	RzEvent *ev = rz_event_new(NULL);
	mu_assert_notnull(ev, "rz_event_new ()");
	rz_event_hook(ev, RZ_EVENT_META_SET, callback_inc, &shared);
	rz_event_hook(ev, RZ_EVENT_META_SET, callback_inc, &shared);
	rz_event_hook(ev, RZ_EVENT_META_SET, callback_inc, &shared);
	rz_event_hook(ev, RZ_EVENT_META_SET, callback_inc, &other);
	rz_event_send(ev, RZ_EVENT_META_SET, NULL);
	mu_assert_eq(shared, 3, "three firings");
	mu_assert_eq(other, 1, "other fires");

	// Drops every matching subscription at once, keeps the rest.
	rz_event_unhook_by_callback(ev, RZ_EVENT_META_SET, callback_inc, &shared);
	rz_event_send(ev, RZ_EVENT_META_SET, NULL);
	mu_assert_eq(shared, 3, "all matching drained");
	mu_assert_eq(other, 2, "other kept");

	// Draining an empty set is a no-op.
	rz_event_unhook_by_callback(ev, RZ_EVENT_META_SET, callback_inc, &shared);
	rz_event_send(ev, RZ_EVENT_META_SET, NULL);
	mu_assert_eq(other, 3, "other still kept");

	// Hooks registered for all events drain through the ALL type as well.
	rz_event_hook(ev, RZ_EVENT_ALL, callback_inc, &shared);
	rz_event_hook(ev, RZ_EVENT_ALL, callback_inc, &shared);
	rz_event_send(ev, RZ_EVENT_META_SET, NULL);
	mu_assert_eq(shared, 5, "all-hooks fire");
	mu_assert_eq(other, 4, "other fires");
	rz_event_unhook_by_callback(ev, RZ_EVENT_ALL, callback_inc, &shared);
	rz_event_send(ev, RZ_EVENT_META_SET, NULL);
	mu_assert_eq(shared, 5, "all-hooks drained");
	mu_assert_eq(other, 5, "other still kept");

	rz_event_free(ev);
	mu_end;
}

typedef struct {
	int type;
	int counter;
} SelfDrainCtx;

static void callback_self_drain(RzEvent *ev, int type, void *user, void *data) {
	SelfDrainCtx *ctx = user;
	(void)type;
	(void)data;
	ctx->counter++;
	rz_event_unhook_by_callback(ev, ctx->type, callback_self_drain, ctx);
}

bool test_rz_event_unhook_by_callback_dispatch(void) {
	// Draining from inside a dispatch must terminate: removals defer to
	// after the send instead of looping on re-collected handles.
	SelfDrainCtx ctx = { 0 };
	int other = 0;
	RzEvent *ev = rz_event_new(NULL);
	mu_assert_notnull(ev, "rz_event_new ()");
	ctx.type = RZ_EVENT_META_SET;
	rz_event_hook(ev, RZ_EVENT_META_SET, callback_self_drain, &ctx);
	rz_event_hook(ev, RZ_EVENT_META_SET, callback_inc, &other);
	rz_event_send(ev, RZ_EVENT_META_SET, NULL);
	mu_assert_eq(ctx.counter, 1, "self-drain fired once");
	mu_assert_eq(other, 1, "other fired once");
	rz_event_send(ev, RZ_EVENT_META_SET, NULL);
	mu_assert_eq(ctx.counter, 1, "self-drain stayed drained");
	mu_assert_eq(other, 2, "other kept");
	rz_event_free(ev);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_event);
	mu_run_test(test_rz_event_self_unhook, RZ_EVENT_ALL, RZ_EVENT_META_SET);
	mu_run_test(test_rz_event_self_unhook, RZ_EVENT_META_SET, RZ_EVENT_META_SET);
	mu_run_test(test_rz_event_unhook_by_callback);
	mu_run_test(test_rz_event_unhook_by_callback_dispatch);
	return tests_passed != tests_run;
}

mu_main(all_tests)
