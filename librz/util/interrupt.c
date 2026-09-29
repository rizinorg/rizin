// SPDX-FileCopyrightText: 2026 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_interrupt.h>
#include <rz_util/rz_alloc.h>
#include <rz_util/rz_sys.h>
#include <rz_util/rz_time.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_stack.h>
#include <stdlib.h>

#if __UNIX__
#include <signal.h>
#endif

#include <stdatomic.h>

typedef struct rz_interrupt_frame_t {
	RzInterruptEvent cb;
	void *user;
} RzInterruptFrame;

static volatile sig_atomic_t g_sigint_flag = 0; ///< Process-wide SIGINT arrival flag
static atomic_int g_hook_count = 0; ///< Active reference counter for hooked signal handlers

#if __UNIX__
/**
 * \brief      Signal handler for SIGINT
 *
 * \param[in]  sig  Signal identifier received from OS
 */
static void interrupt_signal_handler(int sig) {
	(void)sig;
	g_sigint_flag = 1;
}

/**
 * \brief      Hooks process-wide OS SIGINT signal when transition 0 -> 1 occurs
 */
static void rz_interrupt_hook(void) {
	if (atomic_fetch_add(&g_hook_count, 1) == 0) {
		g_sigint_flag = 0;
		rz_sys_signal(SIGINT, interrupt_signal_handler);
	}
}

/**
 * \brief      Unhooks process-wide OS SIGINT signal when transition 1 -> 0 occurs
 */
static void rz_interrupt_unhook(void) {
	if (atomic_fetch_sub(&g_hook_count, 1) == 1) {
		rz_sys_signal(SIGINT, SIG_IGN);
		g_sigint_flag = 0;
	}
}
#endif

/**
 * \brief      Frees an RzInterruptFrame item stored in the break stack
 *
 * \param      ptr  Pointer to the RzInterruptFrame structure to free
 */
static void break_stack_free(void *ptr) {
	RzInterruptFrame *frame = (RzInterruptFrame *)ptr;
	free(frame);
}

/**
 * \brief      Initialize a new interrupt context structure
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
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

/**
 * \brief      Frees an RzInterrupt structure and unhooks signal if active
 *
 * \param      intr  The RzInterrupt structure to free
 */
RZ_API void rz_interrupt_free(RZ_NULLABLE RzInterrupt *intr) {
	if (!intr) {
		return;
	}
#if __UNIX__
	if (intr->hook_signals && !rz_stack_is_empty(intr->break_stack)) {
		rz_interrupt_unhook();
	}
#endif
	rz_stack_free(intr->break_stack);
	free(intr);
}

/**
 * \brief      Triggers an interrupt state on the given context
 *
 * \param[in]  intr  The RzInterrupt structure to raise
 */
RZ_API void rz_interrupt_raise(RZ_NULLABLE RzInterrupt *intr) {
	if (!intr) {
		return;
	}
	intr->is_breaked = true;
	if (intr->current_cb) {
		intr->current_cb(intr->current_user);
	}
}

/**
 * \brief      Pushes a new interrupt frame and hooks signals on first frame
 *
 * \param[in]  intr  The RzInterrupt context structure
 * \param[in]  cb    Callback function to execute on interrupt
 * \param[in]  user  User context data passed to callback
 */
RZ_API void rz_interrupt_break_push(RZ_NULLABLE RzInterrupt *intr, RZ_NULLABLE RzInterruptEvent cb, RZ_NULLABLE void *user) {
	if (!intr || !intr->break_stack) {
		return;
	}

	RzInterruptFrame *frame = RZ_NEW0(RzInterruptFrame);
	if (!frame) {
		return;
	}

	if (rz_stack_is_empty(intr->break_stack)) {
#if __UNIX__
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

/**
 * \brief      Pops the active interrupt frame and unhooks signals on empty stack
 *
 * \param[in]  intr  The RzInterrupt context structure
 */
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
#if __UNIX__
		if (intr->hook_signals) {
			rz_interrupt_unhook();
		}
#endif
		intr->is_breaked = false;
	}
}

/**
 * \brief      Sets a monotonic timeout value for the interrupt
 *
 * \param[in]  intr     The RzInterrupt structure to modify
 * \param[in]  timeout  Relative timeout value in milliseconds
 */
RZ_API void rz_interrupt_timeout(RZ_NULLABLE RzInterrupt *intr, int timeout) {
	if (!intr) {
		return;
	}
	intr->timeout = (timeout && !intr->timeout) ? rz_time_now_mono() + ((ut64)timeout << 20) : 0;
}

/**
 * \brief      Clears the break flag for the specified interrupt structure
 *
 * \param[in]  intr  The RzInterrupt structure to clear
 */
RZ_API void rz_interrupt_break_clear(RZ_NONNULL RzInterrupt *intr) {
	rz_return_if_fail(intr);
	intr->is_breaked = false;
}

/**
 * \brief      Resets break state and unwinds the entire interrupt stack
 *
 * \param[in]  intr  The RzInterrupt structure to end
 */
RZ_API void rz_interrupt_break_end(RZ_NULLABLE RzInterrupt *intr) {
	if (!intr) {
		return;
	}
	intr->is_breaked = false;
	intr->timeout = 0;

#if __UNIX__
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

/**
 * \brief      Checks if the interrupt structure has received a break or timeout
 *
 * \param[in]  intr  The RzInterrupt structure to query
 *
 * \return     Returns true if breaked or timed out, false otherwise
 */
RZ_API bool rz_interrupt_is_breaked(RZ_NULLABLE RzInterrupt *intr) {
	if (!intr) {
		return false;
	}

	if (intr->hook_signals && g_sigint_flag) {
		intr->is_breaked = true;
	}

	if (intr->timeout > 0) {
		if (rz_time_now_mono() > intr->timeout) {
			intr->is_breaked = true;
			intr->timeout = 0;
		}
	}

	return intr->is_breaked;
}

/**
 * \brief      Configures break timeout relative to current monotonic time
 *
 * \param[in]  intr     The RzInterrupt structure to modify
 * \param[in]  timeout  Relative timeout duration
 */
RZ_API void rz_interrupt_break_timeout(RZ_NULLABLE RzInterrupt *intr, int timeout) {
	if (!intr) {
		return;
	}
	intr->timeout = (timeout && !intr->timeout)
		? rz_time_now_mono() + ((ut64)timeout << 20)
		: 0;
}