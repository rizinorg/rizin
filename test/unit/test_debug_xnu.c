// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include "minunit.h"
#include "../../librz/debug/p/native/xnu/xnu_wait.h"

typedef struct {
	RzDebugReasonType reason;
	int signal;
	ut64 elapsed;
	bool cancel;
} MockException;

typedef struct {
	const MockException *events;
	size_t count;
	size_t received;
	ut32 timeouts[4];
	bool invalid_receive;
} MockWait;

// The unit runner is single-threaded; these replace the clock and interrupt source.
static ut64 mock_now;
static bool mock_cancelled;

static ut64 mock_time_now(void) {
	return mock_now;
}

static bool mock_is_breaked(RzInterrupt *intr) {
	return mock_cancelled;
}

static RzDebugReasonType mock_wait_for_exception(RzDebug *dbg, int pid,
	ut32 timeout_ms, bool quiet_signal) {
	MockWait *mock = dbg->plugin_data;
	if (!timeout_ms || !quiet_signal || pid != 42 || mock->received >= mock->count ||
		mock->received >= RZ_ARRAY_SIZE(mock->timeouts)) {
		mock->invalid_receive = true;
		return RZ_DEBUG_REASON_ERROR;
	}
	mock->timeouts[mock->received] = timeout_ms;
	const MockException *event = &mock->events[mock->received++];
	mock_now += event->elapsed;
	mock_cancelled = event->cancel;
	dbg->reason.signum = event->signal;
	return event->reason;
}

// Exercise the production loop on every host without invoking Mach or sleeping.
#define rz_time_now_mono        mock_time_now
#define rz_interrupt_is_breaked mock_is_breaked
#define xnu_wait_for_exception  mock_wait_for_exception
#define xnu_wait_for_attach     test_wait_for_attach
#include "../../librz/debug/p/native/xnu/xnu_wait.c"
#undef xnu_wait_for_attach
#undef xnu_wait_for_exception
#undef rz_interrupt_is_breaked
#undef rz_time_now_mono

bool test_xnu_attach_interrupted_wait(void) {
	const MockException events[] = {
		{ RZ_DEBUG_REASON_MACH_RCV_INTERRUPTED, 0, 400000, false },
		{ RZ_DEBUG_REASON_MACH_RCV_INTERRUPTED, 0, 599501, false },
		{ RZ_DEBUG_REASON_SIGNAL, 17, 0, false },
	};
	MockWait mock = { .events = events, .count = RZ_ARRAY_SIZE(events) };
	RzDebug dbg = { .plugin_data = &mock };
	mock_now = 0;
	mock_cancelled = false;
	mu_assert_true(test_wait_for_attach(&dbg, 42, 17, 1000), "consume attach stop after interruption");
	mu_assert_false(mock.invalid_receive, "bounded quiet receives for the target PID");
	mu_assert_eq(mock.received, 3, "retry both interruptions");
	mu_assert_eq(mock.timeouts[0], 1000, "initial timeout");
	mu_assert_eq(mock.timeouts[1], 600, "retain original deadline");
	mu_assert_eq(mock.timeouts[2], 1, "round up sub-millisecond remainder");
	mu_end;
}

bool test_xnu_attach_wait_failure(void) {
	const MockException failures[] = {
		{ RZ_DEBUG_REASON_UNKNOWN, 0, 1000000, false },
		{ RZ_DEBUG_REASON_MACH_RCV_INTERRUPTED, 0, 1000000, false },
		{ RZ_DEBUG_REASON_MACH_RCV_INTERRUPTED, 0, 1, true },
		{ RZ_DEBUG_REASON_SIGNAL, 18, 1, false },
		{ RZ_DEBUG_REASON_BREAKPOINT, 17, 1, false },
		{ RZ_DEBUG_REASON_DEAD, 0, 1, false },
		{ RZ_DEBUG_REASON_ERROR, 0, 1, false },
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(failures); i++) {
		MockWait mock = { .events = &failures[i], .count = 1 };
		RzDebug dbg = { .plugin_data = &mock };
		mock_now = 0;
		mock_cancelled = false;
		mu_assert_false(test_wait_for_attach(&dbg, 42, 17, 1000), "reject incomplete attach");
		mu_assert_false(mock.invalid_receive, "do not discard other stops or restart the deadline");
		mu_assert_eq(mock.received, 1, "stop receiving on timeout, cancellation or another event");
	}
	mu_end;
}

bool test_xnu_attach_wait_cancelled(void) {
	MockWait mock = { 0 };
	RzDebug dbg = { .plugin_data = &mock };
	mock_now = 0;
	mock_cancelled = true;
	mu_assert_false(test_wait_for_attach(&dbg, 42, 17, 1000), "honor cancellation before waiting");
	mu_assert_eq(mock.received, 0, "do not block on a cancelled attach");
	mu_assert_false(mock.invalid_receive, "no receive attempted");
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_xnu_attach_interrupted_wait);
	mu_run_test(test_xnu_attach_wait_failure);
	mu_run_test(test_xnu_attach_wait_cancelled);
	return tests_passed != tests_run;
}

mu_main(all_tests)
