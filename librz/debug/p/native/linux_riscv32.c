// SPDX-FileCopyrightText: 2024-2026 mostafa <ubermenchun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util/rz_log.h"
#include <sys/ptrace.h>
#include <sys/uio.h>

#include "linux/linux_debug.h"

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

#include "linux_riscv_common.c"
#include "bt.c"
static char *rz_debug_native_reg_profile(RzDebug *dbg) {
#include "reg/linux-riscv32.h"
}

static int rz_debug_native_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	if (size < 1) {
		return false;
	}
	int pid = dbg->tid;
	switch (type) {
	case RZ_REG_TYPE_DRX:
	case RZ_REG_TYPE_FPU:
	case RZ_REG_TYPE_MMX:
	case RZ_REG_TYPE_XMM:
	case RZ_REG_TYPE_YMM:
		RZ_LOG_ERROR("Unsupported register type on this platform, type: %d\n", type);
		return false;
	case RZ_REG_TYPE_SEG:
	case RZ_REG_TYPE_FLG:
	case RZ_REG_TYPE_GPR: {
		RZ_DEBUG_REG_T regs;
		memset(&regs, 0, sizeof(regs));
		memset(buf, 0, size);
		struct iovec io = {
			.iov_base = &regs,
			.iov_len = sizeof(regs),
		};
		int ret = rz_debug_ptrace(dbg, PTRACE_GETREGSET, pid, (void *)(size_t)NT_PRSTATUS, &io);
		if (ret != 0) {
			rz_sys_perror("PTRACE_GETREGSET");
			return false;
		}
		size = RZ_MIN(sizeof(regs), size);
		memcpy(buf, &regs, size);
		return size;
	} break;
	}
	return false;
}

static int rz_debug_native_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	int pid = dbg->tid;
	switch (type) {
	case RZ_REG_TYPE_DRX:
	case RZ_REG_TYPE_FPU:
		RZ_LOG_ERROR("Unsupported register type on this platform, type: %d\n", type);
		return false;
	case RZ_REG_TYPE_GPR: {
		struct iovec io = {
			.iov_base = (void *)buf,
			.iov_len = sizeof(RZ_DEBUG_REG_T),
		};
		int ret = rz_debug_ptrace(dbg, PTRACE_SETREGSET, pid, (void *)(size_t)NT_PRSTATUS, (rz_ptrace_data_t)(size_t)&io);
		if (ret == -1) {
			rz_sys_perror("PTRACE_SETREGSET");
			return false;
		}
		return true;
	}
	default:
		RZ_LOG_DEBUG("TODO: reg_write_non-gpr (%d)\n", type);
		return false;
	}
	return false;
}

static int rz_debug_native_bp(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
	return false;
}

static bool rz_debug_gcore(RzDebug *dbg, char *path, RzBuffer *dest) {
	RZ_LOG_ERROR("gcore: unsupported on this platform\n");
	return false;
}

RzDebugPlugin rz_debug_plugin_native = {
	.name = "native",
	.license = "LGPL3",
	.arch = "riscv",
	.bits = RZ_SYS_BITS_32,
	.canstep = 0,
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
	.frames = &rz_debug_native_frames,
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
