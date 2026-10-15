#ifndef RZ_INTERRUPT_H
#define RZ_INTERRUPT_H

#include <stdbool.h>
#include <rz_types.h>
#include <rz_util/rz_stack.h>

typedef void (*RzInterruptEvent)(void *user);
typedef bool (*RzInterruptIsBreaked)(void *user);
typedef void *(*RzInterruptSleepBegin)(void *user);
typedef void (*RzInterruptSleepEnd)(void *user, void *bed);
typedef void (*RzInterruptBreakCallback)(void *user);

typedef struct rz_interrupt_t {
	bool is_breaked;
	bool hook_signals;
	ut64 timeout; // must come from rz_time_now_mono()

	RzStack *break_stack;
	RzInterruptEvent current_cb;
	void *current_user;

	void *user;
	RzInterruptSleepBegin sleep_begin;
	RzInterruptSleepEnd sleep_end;
	RzInterruptBreakCallback cb_break;
} RzInterrupt;

RZ_API RZ_OWN RzInterrupt *rz_interrupt_new(void);
RZ_API void rz_interrupt_free(RZ_NULLABLE RzInterrupt *intr);
RZ_API void rz_interrupt_raise(RZ_NULLABLE RzInterrupt *intr);
RZ_API void rz_interrupt_break_push(RZ_NULLABLE RzInterrupt *intr, RZ_NULLABLE RzInterruptEvent cb, RZ_NULLABLE void *user);
RZ_API void rz_interrupt_break_pop(RZ_NULLABLE RzInterrupt *intr);
RZ_API void rz_interrupt_timeout(RZ_NULLABLE RzInterrupt *intr, int timeout);
RZ_API void rz_interrupt_break_clear(RZ_NONNULL RzInterrupt *intr);
RZ_API void rz_interrupt_break_end(RZ_NULLABLE RzInterrupt *intr);
RZ_API bool rz_interrupt_is_breaked(RZ_NULLABLE RzInterrupt *intr);
RZ_API void rz_interrupt_break_timeout(RZ_NULLABLE RzInterrupt *intr, int timeout);

static inline void *rz_interrupt_sleep_begin(RzInterrupt *intr) {
	if (intr && intr->sleep_begin) {
		return intr->sleep_begin(intr->user);
	}
	return NULL;
}

static inline void rz_interrupt_sleep_end(RzInterrupt *intr, void *bed) {
	if (intr && intr->sleep_end) {
		intr->sleep_end(intr->user, bed);
	}
}

static inline void rz_interrupt_set_breaked(RzInterrupt *intr, bool breaked) {
	if (intr) {
		intr->is_breaked = breaked;
	}
}

#endif
