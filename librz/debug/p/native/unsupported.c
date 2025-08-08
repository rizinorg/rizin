// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file This is a file with dummy debugger functions for when
 *       the native debugger is unsupported.
 */

#include <rz_debug.h>

static bool rz_debug_native_init(RzDebug *dbg, void **user) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return false;
}

static void rz_debug_native_fini(RzDebug *debug, void *user) {
	RZ_LOG_ERROR("Unsupported platform\n");
}

static bool rz_debug_native_step(RzDebug *dbg) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return false;
}

static int rz_debug_native_continue(RzDebug *dbg, int pid, int tid, int sig) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return -1;
}

static int rz_debug_native_stop(RzDebug *dbg) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return -1;
}

static int rz_debug_native_continue_syscall(RzDebug *dbg, int pid, int sc) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return -1;
}

static int rz_debug_native_attach(RzDebug *dbg, int pid) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return -1;
}

static int rz_debug_native_detach(RzDebug *dbg, int pid) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return -1;
}

static int rz_debug_native_select(RzDebug *dbg, int pid, int tid) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return -1;
}

static RzList *rz_debug_native_pids(RzDebug *dbg, int pid) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return NULL;
}

RzList *rz_debug_native_threads(RzDebug *dbg, int pid) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return NULL;
}

static RzDebugReasonType rz_debug_native_wait(RzDebug *dbg, int pid) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return RZ_DEBUG_REASON_UNKNOWN;
}

static bool rz_debug_native_kill(RzDebug *dbg, int pid, int tid, int sig) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return false;
}

static RzList *rz_debug_native_frames(RzDebug *dbg, ut64 at) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return NULL;
}

static char *rz_debug_native_reg_profile(RzDebug *dbg) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return NULL;
}

static int rz_debug_native_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return -1;
}

static RzDebugInfo *rz_debug_native_info(RzDebug *dbg, const char *arg) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return NULL;
}

static int rz_debug_native_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return -1;
}

static RzDebugMap *rz_debug_native_map_alloc(RzDebug *dbg, ut64 addr, int size, bool thp) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return NULL;
}

static int rz_debug_native_map_dealloc(RzDebug *dbg, ut64 addr, int size) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return -1;
}

static RzList *rz_debug_native_map_get(RzDebug *dbg) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return NULL;
}

static RzList *rz_debug_native_modules_get(RzDebug *dbg) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return NULL;
}

static int rz_debug_native_map_protect(RzDebug *dbg, ut64 addr, int size, int perms) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return -1;
}

static int rz_debug_native_drx(RzDebug *dbg, int n, ut64 addr, int size, int rwx, int g, int api_type) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return -1;
}

static bool rz_debug_gcore(RzDebug *dbg, char *path, RzBuffer *dest) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return false;
}

static int rz_debug_native_bp(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
	RZ_LOG_ERROR("Unsupported platform\n");
	return -1;
}

RzDebugPlugin rz_debug_plugin_native = {
	.name = "native",
	.license = "LGPL3",
	.init = &rz_debug_native_init,
	.fini = &rz_debug_native_fini,
	.step = &rz_debug_native_step,
	.cont = &rz_debug_native_continue,
	.stop = &rz_debug_native_stop,
	.contsc = &rz_debug_native_continue_syscall,
	.attach = &rz_debug_native_attach,
	.detach = &rz_debug_native_detach,
	.select = &rz_debug_native_select,
	.pids = &rz_debug_native_pids,
	.threads = &rz_debug_native_threads,
	.wait = &rz_debug_native_wait,
	.kill = &rz_debug_native_kill,
	.frames = &rz_debug_native_frames, // rename to backtrace ?
	.reg_profile = rz_debug_native_reg_profile,
	.reg_read = rz_debug_native_reg_read,
	.info = rz_debug_native_info,
	.reg_write = (void *)&rz_debug_native_reg_write,
	.map_alloc = rz_debug_native_map_alloc,
	.map_dealloc = rz_debug_native_map_dealloc,
	.map_get = rz_debug_native_map_get,
	.modules_get = rz_debug_native_modules_get,
	.map_protect = rz_debug_native_map_protect,
	.breakpoint = rz_debug_native_bp,
	.drx = rz_debug_native_drx,
	.gcore = rz_debug_gcore,
};