// SPDX-License-Identifier: LGPL-3.0-only

#include "xnu_wait.h"

/**
 * \brief Consume the attach stop without extending the deadline on interrupted receives.
 *
 * Suspending the task cannot replace this handshake: an unconsumed attach signal
 * would otherwise stop the first continue before any user breakpoint.
 *
 * \param stop_signal The host's attach-stop signal (SIGSTOP on Darwin).
 * \param timeout_ms Maximum wait in milliseconds; must be nonzero.
 * \return true only after receiving the expected signal.
 */
RZ_IPI bool xnu_wait_for_attach(RzDebug *dbg, int pid, int stop_signal, ut32 timeout_ms) {
	rz_return_val_if_fail(dbg && timeout_ms, false);
	ut64 deadline = rz_time_now_mono() + (ut64)timeout_ms * 1000;
	for (;;) {
		ut64 now = rz_time_now_mono();
		if (now >= deadline || rz_interrupt_is_breaked(dbg->intr)) {
			return false;
		}
		// Round up: zero requests an infinite Mach receive.
		ut32 remaining = (deadline - now + 999) / 1000;
		RzDebugReasonType reason = xnu_wait_for_exception(dbg, pid, remaining, true);
		if (reason != RZ_DEBUG_REASON_MACH_RCV_INTERRUPTED) {
			return reason == RZ_DEBUG_REASON_SIGNAL && dbg->reason.signum == stop_signal;
		}
	}
}
