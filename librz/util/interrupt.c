// SPDX-FileCopyrightText: 2026 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_interrupt.h>
#include <rz_util/rz_alloc.h>
#include <rz_util/rz_sys.h>
#include <rz_util/rz_time.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_stack.h>
#include <stdlib.h>

typedef struct rz_interrupt_frame_t {
	RzInterruptEvent cb;
	void *user;
} RzInterruptFrame;

#if __WINDOWS__
#include <windows.h>
#include <signal.h>
#elif __UNIX__
#include <signal.h>
#endif

// <stdatomic.h> is only supported in GCC >= 4.9
// https://gcc.gnu.org/gcc-4.9/changes.html#c
#if __UNIX__ || __WINDOWS__
#if defined(_MSC_VER)
typedef volatile LONG atomic_int;
#define atomic_fetch_add(p, v) InterlockedExchangeAdd((volatile LONG *)(p), (LONG)(v))
#define atomic_fetch_sub(p, v) InterlockedExchangeAdd((volatile LONG *)(p), -(LONG)(v))
#elif defined(__GNUC__) && (__GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 9)) && !defined(__clang__)
typedef volatile int atomic_int;
#define atomic_fetch_add(p, v) __sync_fetch_and_add(p, v)
#define atomic_fetch_sub(p, v) __sync_fetch_and_sub(p, v)
#else
#include <stdatomic.h>
#endif

static volatile sig_atomic_t g_sigint_flag = 0; ///< Process-wide SIGINT / Ctrl+C arrival flag
static atomic_int g_hook_count = 0; ///< Active reference counter for hooked signal handlers

#if __WINDOWS__
/**
 * \brief Windows Console Ctrl handler callback
 */
static BOOL WINAPI rz_interrupt_w32_control(DWORD dwCtrlType) {
	if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_BREAK_EVENT) {
		g_sigint_flag = 1;
		return TRUE; // Prevents default process termination
	}
	return FALSE;
}

static void rz_interrupt_hook(void) {
	if (atomic_fetch_add(&g_hook_count, 1) == 0) {
		g_sigint_flag = 0;
		SetConsoleCtrlHandler((PHANDLER_ROUTINE)rz_interrupt_w32_control, TRUE);
	}
}

static void rz_interrupt_unhook(void) {
	if (atomic_fetch_sub(&g_hook_count, 1) == 1) {
		SetConsoleCtrlHandler((PHANDLER_ROUTINE)rz_interrupt_w32_control, FALSE);
		g_sigint_flag = 0;
	}
}
#elif __UNIX__
/**
 * \brief Signal handler for SIGINT
 */
static void interrupt_signal_handler(int sig) {
	(void)sig;
	g_sigint_flag = 1;
}

static void rz_interrupt_hook(void) {
	if (atomic_fetch_add(&g_hook_count, 1) == 0) {
		g_sigint_flag = 0;
		rz_sys_signal(SIGINT, interrupt_signal_handler);
	}
}

static void rz_interrupt_unhook(void) {
	if (atomic_fetch_sub(&g_hook_count, 1) == 1) {
		rz_sys_signal(SIGINT, SIG_IGN);
		g_sigint_flag = 0;
	}
}
#endif
#endif

static void break_stack_free(void *ptr) {
	RzInterruptFrame *frame = (RzInterruptFrame *)ptr;
	free(frame);
}

RZ_API RZ_OWN RzInterrupt *rz_interrupt_new(void) {
	RzInterrupt *intr = RZ_NEW0(RzInterrupt);
	if (!intr) {
		return NULL;
	}
	intr->break_stack = rz_stack_newf(6, break_stack_free);
	if (!intr->break_stack) {
		rz_interrupt_free(intr);
		return NULL;
	}
	return intr;
}

RZ_API void rz_interrupt_free(RZ_NULLABLE RzInterrupt *intr) {
	if (!intr) {
		return;
	}
#if __UNIX__ || __WINDOWS__
	if (intr->hook_signals && !rz_stack_is_empty(intr->break_stack)) {
		rz_interrupt_unhook();
	}
#endif
	rz_stack_free(intr->break_stack);
	free(intr);
}

RZ_API void rz_interrupt_raise(RZ_NULLABLE RzInterrupt *intr) {
	if (!intr) {
		return;
	}
	intr->is_breaked = true;
	if (intr->current_cb) {
		intr->current_cb(intr->current_user);
	}
}

RZ_API void rz_interrupt_break_push(RZ_NULLABLE RzInterrupt *intr, RZ_NULLABLE RzInterruptEvent cb, RZ_NULLABLE void *user) {
	if (!intr || !intr->break_stack) {
		return;
	}

	RzInterruptFrame *frame = RZ_NEW0(RzInterruptFrame);
	if (!frame) {
		return;
	}

	if (rz_stack_is_empty(intr->break_stack)) {
#if __UNIX__ || __WINDOWS__
		if (intr->hook_signals) {
			rz_interrupt_hook();
		}
#endif
		intr->is_breaked = false;
	}

	frame->cb = intr->current_cb;
	frame->user = intr->current_user;
	rz_stack_push(intr->break_stack, frame);

	intr->current_cb = cb;
	intr->current_user = user;
}

RZ_API void rz_interrupt_break_pop(RZ_NULLABLE RzInterrupt *intr) {
	if (!intr || !intr->break_stack || rz_stack_is_empty(intr->break_stack)) {
		return;
	}

	RzInterruptFrame *frame = (RzInterruptFrame *)rz_stack_pop(intr->break_stack);
	if (frame) {
		intr->current_cb = frame->cb;
		intr->current_user = frame->user;
		free(frame);
	}

	if (rz_stack_is_empty(intr->break_stack)) {
#if __UNIX__ || __WINDOWS__
		if (intr->hook_signals) {
			rz_interrupt_unhook();
		}
#endif
		intr->is_breaked = false;
	}
}

RZ_API void rz_interrupt_timeout(RZ_NULLABLE RzInterrupt *intr, int timeout) {
	if (!intr) {
		return;
	}
	intr->timeout = (timeout && !intr->timeout) ? rz_time_now_mono() + ((ut64)timeout << 20) : 0;
}

RZ_API void rz_interrupt_break_clear(RZ_NONNULL RzInterrupt *intr) {
	rz_return_if_fail(intr);
	intr->is_breaked = false;
}

RZ_API void rz_interrupt_break_end(RZ_NULLABLE RzInterrupt *intr) {
	if (!intr) {
		return;
	}
	intr->is_breaked = false;
	intr->timeout = 0;

#if __UNIX__ || __WINDOWS__
	if (intr->hook_signals && !rz_stack_is_empty(intr->break_stack)) {
		rz_interrupt_unhook();
	}
#endif

	if (intr->break_stack) {
		rz_stack_free(intr->break_stack);
		intr->break_stack = rz_stack_newf(6, break_stack_free);
	}
	intr->current_cb = NULL;
	intr->current_user = NULL;
}

RZ_API bool rz_interrupt_is_breaked(RZ_NULLABLE RzInterrupt *intr) {
	if (!intr) {
		return false;
	}

#if __UNIX__ || __WINDOWS__
	if (intr->hook_signals && g_sigint_flag) {
		intr->is_breaked = true;
	}
#endif

	if (intr->timeout > 0) {
		if (rz_time_now_mono() > intr->timeout) {
			intr->is_breaked = true;
			intr->timeout = 0;
		}
	}

	return intr->is_breaked;
}

RZ_API void rz_interrupt_break_timeout(RZ_NULLABLE RzInterrupt *intr, int timeout) {
	if (!intr) {
		return;
	}
	intr->timeout = (timeout && !intr->timeout)
		? rz_time_now_mono() + ((ut64)timeout << 20)
		: 0;
}