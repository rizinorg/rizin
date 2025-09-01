// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>

#include <sys/mman.h>
#include "linux/linux_debug.h"
#include "procfs.h"
#include "bt.c"

#ifdef __WALL
#define WAITPID_FLAGS __WALL
#else
#define WAITPID_FLAGS 0
#endif

static char *rz_debug_native_reg_profile(RzDebug *dbg) {
#if __powerpc64__
#include "reg/linux-ppc64.h"
#elif __powerpc__
#include "reg/linux-ppc.h"
#endif
}

static bool rz_debug_native_step(RzDebug *dbg) {
	return linux_step(dbg);
}

static int rz_debug_native_attach(RzDebug *dbg, int pid) {
	return linux_attach(dbg, pid);
}

static int rz_debug_native_detach(RzDebug *dbg, int pid) {
	return rz_debug_ptrace(dbg, PTRACE_DETACH, pid, NULL, (rz_ptrace_data_t)(size_t)0);
}

static int rz_debug_native_select(RzDebug *dbg, int pid, int tid) {
	return linux_select(dbg, pid, tid);
}

static int rz_debug_native_continue_syscall(RzDebug *dbg, int pid, int num) {
	linux_set_options(dbg, pid);
	return rz_debug_ptrace(dbg, PTRACE_SYSCALL, pid, 0, 0);
}

static void interrupt_process(RzDebug *dbg) {
	rz_debug_kill(dbg, dbg->pid, dbg->tid, SIGINT);
	rz_cons_break_pop();
}

static int rz_debug_native_stop(RzDebug *dbg) {
	return linux_stop_threads(dbg, dbg->reason.tid);
}

static int rz_debug_native_continue(RzDebug *dbg, int pid, int tid, int sig) {
	int contsig = dbg->reason.signum;
	int ret = -1;

	if (sig != -1) {
		contsig = sig;
	}
	/* SIGINT handler for attached processes: dbg.consbreak (disabled by default) */
	if (dbg->consbreak) {
		rz_cons_break_push((RzConsBreak)interrupt_process, dbg);
	}

	if (dbg->continue_all_threads && dbg->n_threads && dbg->threads) {
		RzDebugPid *th;
		RzListIter *it;
		rz_list_foreach (dbg->threads, it, th) {
			ret = rz_debug_ptrace(dbg, PTRACE_CONT, th->pid, 0, 0);
			if (ret) {
				RZ_LOG_ERROR(" (%d) is running or dead.\n", th->pid);
			}
		}
	} else {
		ret = rz_debug_ptrace(dbg, PTRACE_CONT, tid, NULL, (rz_ptrace_data_t)(size_t)contsig);
		if (ret) {
			rz_sys_perror("PTRACE_CONT");
		}
	}
	// return ret >= 0 ? tid : false;
	return tid;
}

static RzDebugInfo *rz_debug_native_info(RzDebug *dbg, const char *arg) {
	return linux_info(dbg, arg);
}

static RzDebugReasonType rz_debug_native_wait(RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;
	if (pid == -1) {
		RZ_LOG_ERROR(" rz_debug_native_wait called with pid -1\n");
		return RZ_DEBUG_REASON_ERROR;
	}

	reason = linux_dbg_wait(dbg, dbg->tid);
	dbg->reason.type = reason;
	return reason;
}

#undef MAXPID
#define MAXPID 99999

static RzList /*<RzDebugPid *>*/ *rz_debug_native_pids(RzDebug *dbg, int pid) {
	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}
	return linux_pid_list(pid, list);
}

RZ_API RZ_OWN RzList /*<RzDebugPid *>*/ *rz_debug_native_threads(RzDebug *dbg, int pid) {
	RzList *list = rz_list_new();
	if (!list) {
		RZ_LOG_ERROR("Cannot create list\n");
		return NULL;
	}
	return linux_thread_list(dbg, pid, list);
}

RZ_API ut64 rz_debug_get_tls(RZ_NONNULL RzDebug *dbg, int tid) {
	rz_return_val_if_fail(dbg, 0);
	return get_linux_tls_val(dbg, tid);
}

static int rz_debug_native_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	if (size < 1) {
		return false;
	}
	bool showfpu = false;
	int pid = dbg->tid;
	int ret = 0;
	if (type < -1) {
		showfpu = true;
		type = -type;
	}
	switch (type) {
	case RZ_REG_TYPE_DRX:
	case RZ_REG_TYPE_FPU:
	case RZ_REG_TYPE_MMX:
	case RZ_REG_TYPE_XMM: {
		RZ_LOG_ERROR("Unsupported register type on this platform, type: %d\n", type);
		return false;
	} break;
	case RZ_REG_TYPE_SEG:
	case RZ_REG_TYPE_FLG:
	case RZ_REG_TYPE_GPR: {
		RZ_DEBUG_REG_T regs;
		memset(&regs, 0, sizeof(regs));
		memset(buf, 0, size);
		/* linux -{arm/mips/riscv/x86/x86_64} */
		ret = rz_debug_ptrace(dbg, PTRACE_GETREGS, pid, NULL, &regs);
		/*
		 * if perror here says 'no such process' and the
		 * process exists still.. is because there's a missing call
		 * to 'wait'. and the process is not yet available to accept
		 * more ptrace queries.
		 */
		if (ret != 0) {
			rz_sys_perror("PTRACE_GETREGS");
			return false;
		}
		size = RZ_MIN(sizeof(regs), size);
		memcpy(buf, &regs, size);
		return size;
	} break;
	case RZ_REG_TYPE_YMM: {
		RZ_LOG_ERROR("Unsupported register type on this platform, type: %d\n", type);
		return false;
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
		int ret = rz_debug_ptrace(dbg, PTRACE_SETREGS, pid, 0, (void *)buf);
		if (ret == -1) {
			rz_sys_perror("reg_write");
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

static RzDebugMap *rz_debug_native_map_alloc(RzDebug *dbg, ut64 addr, int size, bool thp) {
	return linux_map_alloc(dbg, addr, size, thp);
}

static int rz_debug_native_map_dealloc(RzDebug *dbg, ut64 addr, int size) {
	return linux_map_dealloc(dbg, addr, size);
}

static RzList /*<RzDebugMap *>*/ *rz_debug_native_map_get(RzDebug *dbg) {
	if (dbg->pid == -1) {
		return NULL;
	}
	RzList *map_list = linux_map_get(dbg);
	if (!map_list) {
		RZ_LOG_ERROR("Cannot create process map list.\n");
		return NULL;
	}
	return map_list;
}

static RzList /*<RzDebugMap *>*/ *rz_debug_native_modules_get(RzDebug *dbg) {
	char *lastname = NULL;
	RzDebugMap *map;
	RzListIter *iter, *iter2;
	RzList *list, *last;
	bool must_delete;
	if (!(list = rz_debug_native_map_get(dbg))) {
		return NULL;
	}
	if (!(last = rz_list_newf((RzListFree)rz_debug_map_free))) {
		rz_list_free(list);
		return NULL;
	}
	rz_list_foreach_safe (list, iter, iter2, map) {
		const char *file = map->file;
		if (!map->file) {
			file = map->file = rz_str_dup(map->name);
		}
		must_delete = true;
		if (file && *file == '/') {
			if (!lastname || strcmp(lastname, file)) {
				must_delete = false;
			}
		}
		if (must_delete) {
			rz_list_delete(list, iter);
		} else {
			rz_list_append(last, map);
			free(lastname);
			lastname = rz_str_dup(file);
		}
	}
	list->free = NULL;
	free(lastname);
	rz_list_free(list);
	return last;
}

static bool rz_debug_native_kill(RzDebug *dbg, int pid, int tid, int sig) {
	bool ret = false;
	if (pid == 0) {
		pid = dbg->pid;
	}
	if (sig == SIGKILL && dbg->threads) {
		rz_list_free(dbg->threads);
		dbg->threads = NULL;
	}
	if ((rz_sys_kill(pid, sig) != -1)) {
		ret = true;
	}
	if (errno == 1) {
		ret = -true; // EPERM
	}
	return ret;
}

static int rz_debug_native_drx(RzDebug *dbg, int n, ut64 addr, int sz, int rwx, int g, int api_type) {
	RZ_LOG_ERROR("drx: Unsupported platform\n");
	return -1;
}

static int rz_debug_native_bp(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
	return false;
}

static RzList /*<RzDebugDesc *>*/ *rz_debug_desc_native_list(int pid) {
	return linux_desc_list(pid);
}

static int rz_debug_native_map_protect(RzDebug *dbg, ut64 addr, int size, int perms) {
	return linux_map_protect(dbg, addr, size, perms);
}

static int rz_debug_desc_native_open(const char *path) {
	return 0;
}

static bool rz_debug_gcore(RzDebug *dbg, char *path, RzBuffer *dest) {
	RZ_LOG_ERROR("Unsupported on this platform\n");
	return false;
}

struct rz_debug_desc_plugin_t rz_debug_desc_plugin_native = {
	.open = rz_debug_desc_native_open,
	.list = rz_debug_desc_native_list,
};

bool rz_debug_native_init(RzDebug *dbg, void **user) {
	dbg->cur->desc = rz_debug_desc_plugin_native;
	return true;
}

void rz_debug_native_fini(RzDebug *dbg, void *user) {
	if (!user) {
		return;
	}
	free(user);
}

RzDebugPlugin rz_debug_plugin_native = {
	.name = "native",
	.license = "LGPL3",
#if __powerpc64__ /* PPC64LE*/
	.bits = RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
#else /* PPC32LE */
	.bits = RZ_SYS_BITS_32,
#endif /* PPC32LE */
	.arch = "ppc",
	.canstep = 1,
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