// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

#include "bt/generic-x86.c"
#include "bt/generic-x64.c"
#include "bt/fuzzy-all.c"

typedef RzList *(*RzDebugFrameCallback)(RzDebug *dbg, ut64 at);

static void prepend_current_pc(RzDebug *dbg, RzList *list) {
	RzDebugFrame *frame;
	const char *pcname;
	if (list) {
		pcname = rz_reg_get_name(dbg->reg, RZ_REG_NAME_PC);
		if (pcname) {
			ut64 addr = rz_reg_getv(dbg->reg, pcname);
			frame = RZ_NEW0(RzDebugFrame);
			frame->addr = addr;
			frame->size = 0;
			rz_list_prepend(list, frame);
		}
	}
}

#if HAVE_PTRACE
struct frames_proxy_args {
	RzDebugFrameCallback cb;
	RzDebug *dbg;
	ut64 at;
};

static void *backtrace_proxy(void *user) {
	struct frames_proxy_args *args = user;
	if (args->cb) {
		return args->cb(args->dbg, args->at);
	}
	return NULL;
}
#endif

static RzList *rz_debug_native_frames(RzDebug *dbg, ut64 at) {
	RzDebugFrameCallback cb = NULL;
	if (dbg->btalgo) {
		if (!strcmp(dbg->btalgo, "fuzzy")) {
			cb = backtrace_fuzzy;
		} else if (!strcmp(dbg->btalgo, "analysis")) {
			if (dbg->bits == RZ_SYS_BITS_64) {
				cb = backtrace_x86_64_analysis;
			} else {
				cb = backtrace_x86_32_analysis;
			}
		}
	}
	if (!cb) {
		if (dbg->bits == RZ_SYS_BITS_64) {
			cb = backtrace_x86_64;
		} else {
			cb = backtrace_x86_32;
		}
	}

	RzList *list;
	if (dbg->btalgo && !strcmp(dbg->btalgo, "trace")) {
		list = rz_list_clone(dbg->call_frames);
	} else {
#if HAVE_PTRACE
		struct frames_proxy_args args = { cb, dbg, at };
		list = rz_debug_ptrace_func(dbg, backtrace_proxy, &args);
#else
		list = cb(dbg, at);
#endif
	}

	prepend_current_pc(dbg, list);
	return list;
}
