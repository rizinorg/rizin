// SPDX-FileCopyrightText: 2019 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>

RZ_API bool rz_w32_add_winmsg_breakpoint(RzDebug *dbg, const char *msg_name, const char *window_id);
RZ_API void rz_w32_identify_window(void);
RZ_API void rz_w32_print_windows(RzDebug *dbg);
