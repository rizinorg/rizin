// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_XNU_WAIT_H
#define RZ_XNU_WAIT_H

#include <rz_debug.h>

#define RZ_DEBUG_REASON_MACH_RCV_INTERRUPTED -2

RZ_IPI RzDebugReasonType xnu_wait_for_exception(RzDebug *dbg, int pid, ut32 timeout_ms, bool quiet_signal);
RZ_IPI bool xnu_wait_for_attach(RzDebug *dbg, int pid, int stop_signal, ut32 timeout_ms);

#endif
