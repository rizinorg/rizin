// SPDX-FileCopyrightText: 2019 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>

typedef struct _window {
	DWORD pid;
	DWORD tid;
	HANDLE h;
	char *name;
	ut64 proc;
} window;

RZ_API bool rz_w32_add_winmsg_breakpoint(RzDebug *dbg, const char *arg_name, const char *arg_addr);
RZ_API void rz_w32_identify_window(void);
RZ_API void rz_w32_print_windows(RzDebug *dbg);
