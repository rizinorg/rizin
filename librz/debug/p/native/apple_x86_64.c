// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <errno.h>
#if !defined(__HAIKU__) && !defined(__sun)
#include <sys/ptrace.h>
#endif
#include <sys/wait.h>
#include <signal.h>

#include <sys/resource.h>
#include "xnu/xnu_debug.h"

#ifdef __WALL
#define WAITPID_FLAGS __WALL
#else
#define WAITPID_FLAGS 0
#endif

#define PROC_NAME_SZ   1024
#define PROC_REGION_SZ 100
// PROC_REGION_SZ - 2 (used for `0x`). Due to how RZ_STR_DEF works this can't be
// computed.
#define PROC_REGION_LEFT_SZ 98
#define PROC_PERM_SZ        5
#define PROC_UNKSTR_SZ      128

static char *rz_debug_native_reg_profile(RzDebug *dbg) {
	return xnu_reg_profile(dbg);
}

static bool rz_debug_native_step(RzDebug *dbg) {
	return xnu_step(dbg);
}

static int rz_debug_native_attach(RzDebug *dbg, int pid) {
	return xnu_attach(dbg, pid);
}

static int rz_debug_native_detach(RzDebug *dbg, int pid) {
	return xnu_detach(dbg, pid);
}

static int rz_debug_native_continue_syscall(RzDebug *dbg, int pid, int num) {
	eprintf("TODO: continue syscall not implemented yet\n");
	return -1;
}

static int rz_debug_native_stop(RzDebug *dbg) {
	return 0;
}

static int rz_debug_native_continue(RzDebug *dbg, int pid, int tid, int sig) {
	bool ret = xnu_continue(dbg, pid, tid, sig);
	if (!ret) {
		return -1;
	}
	return tid;
}

static RzDebugInfo *rz_debug_native_info(RzDebug *dbg, const char *arg) {
	return xnu_info(dbg, arg);
}

static RzDebugReasonType rz_debug_native_wait(RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;

	if (pid == -1) {
		eprintf("ERROR: rz_debug_native_wait called with pid -1\n");
		return RZ_DEBUG_REASON_ERROR;
	}
	rz_cons_break_push(NULL, NULL);
	do {
		reason = xnu_wait(dbg, pid);
		if (reason == RZ_DEBUG_REASON_MACH_RCV_INTERRUPTED) {
			if (rz_cons_is_breaked()) {
				// Perhaps check the inferior is still alive,
				// otherwise xnu_stop will fail.
				reason = xnu_stop(dbg, pid)
					? RZ_DEBUG_REASON_USERSUSP
					: RZ_DEBUG_REASON_UNKNOWN;
			} else {
				// Weird; we'll retry the wait.
				continue;
			}
		}
		break;
	} while (true);
	rz_cons_break_pop();
	dbg->reason.tid = pid;
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
	if (pid) {
		RzDebugPid *p = xnu_get_pid(pid);
		if (p) {
			rz_list_append(list, p);
		}
	} else {
		int i;
		for (i = 1; i < MAXPID; i++) {
			RzDebugPid *p = xnu_get_pid(i);
			if (p) {
				rz_list_append(list, p);
			}
		}
	}
	return list;
}

RZ_API RZ_OWN RzList /*<RzDebugPid *>*/ *rz_debug_native_threads(RzDebug *dbg, int pid) {
	RzList *list = rz_list_new();
	if (!list) {
		eprintf("No list?\n");
		return NULL;
	}
	return xnu_thread_list(dbg, pid, list);
}

RZ_API ut64 rz_debug_get_tls(RZ_NONNULL RzDebug *dbg, int tid) {
	rz_return_val_if_fail(dbg, 0);
	return 0;
}

static int rz_debug_native_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	if (size < 1) {
		return false;
	}
	return xnu_reg_read(dbg, type, buf, size);
}

static int rz_debug_native_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	// XXX use switch or so
	if (type == RZ_REG_TYPE_DRX) {
		return xnu_reg_write(dbg, type, buf, size);
	} else if (type == RZ_REG_TYPE_GPR) {
		return xnu_reg_write(dbg, type, buf, size);
	} else if (type == RZ_REG_TYPE_FPU) {
		return false;
	} // else eprintf ("TODO: reg_write_non-gpr (%d)\n", type);
	return false;
}

static RzDebugMap *rz_debug_native_map_alloc(RzDebug *dbg, ut64 addr, int size, bool thp) {
	(void)thp;
	return xnu_map_alloc(dbg, addr, size);
}

static int rz_debug_native_map_dealloc(RzDebug *dbg, ut64 addr, int size) {
	return xnu_map_dealloc(dbg, addr, size);
}

static RzList /*<RzDebugMap *>*/ *rz_debug_native_map_get(RzDebug *dbg) {
	RzList *list = NULL;
	list = xnu_dbg_maps(dbg, 0);
	return list;
}

static RzList /*<RzDebugMap *>*/ *rz_debug_native_modules_get(RzDebug *dbg) {
	char *lastname = NULL;
	RzDebugMap *map;
	RzListIter *iter, *iter2;
	RzList *list, *last;
	bool must_delete;
	list = xnu_dbg_maps(dbg, 1);
	if (list && !rz_list_empty(list)) {
		return list;
	}
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
			file = map->file = strdup(map->name);
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
			lastname = strdup(file);
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

struct rz_debug_desc_plugin_t rz_debug_desc_plugin_native;
static bool rz_debug_native_init(RzDebug *dbg, void **user) {
	dbg->cur->desc = rz_debug_desc_plugin_native;
	return rz_xnu_debug_init(dbg, user);
}

static void rz_debug_native_fini(RzDebug *dbg, void *user) {
	rz_xnu_debug_fini(dbg, user);
}

static void sync_drx_regs(RzDebug *dbg, drxt *regs, size_t num_regs) {
	/* sanity check, we rely on this assumption */
	if (num_regs != NUM_DRX_REGISTERS) {
		eprintf("drx: Unsupported number of registers for get_debug_regs\n");
		return;
	}

	// sync drx regs
#define R dbg->reg
	regs[0] = rz_reg_getv(R, "dr0");
	regs[1] = rz_reg_getv(R, "dr1");
	regs[2] = rz_reg_getv(R, "dr2");
	regs[3] = rz_reg_getv(R, "dr3");
	/*
	RESERVED
	regs[4] = rz_reg_getv (R, "dr4");
	regs[5] = rz_reg_getv (R, "dr5");
*/
	regs[6] = rz_reg_getv(R, "dr6");
	regs[7] = rz_reg_getv(R, "dr7");
}

static void set_drx_regs(RzDebug *dbg, drxt *regs, size_t num_regs) {
	/* sanity check, we rely on this assumption */
	if (num_regs != NUM_DRX_REGISTERS) {
		eprintf("drx: Unsupported number of registers for get_debug_regs\n");
		return;
	}

#define R dbg->reg
	rz_reg_setv(R, "dr0", regs[0]);
	rz_reg_setv(R, "dr1", regs[1]);
	rz_reg_setv(R, "dr2", regs[2]);
	rz_reg_setv(R, "dr3", regs[3]);
	rz_reg_setv(R, "dr6", regs[6]);
	rz_reg_setv(R, "dr7", regs[7]);
}

static int rz_debug_native_drx(RzDebug *dbg, int n, ut64 addr, int sz, int rwx, int g, int api_type) {
	int retval = false;
	drxt regs[NUM_DRX_REGISTERS] = { 0 };
	// sync drx regs
	sync_drx_regs(dbg, regs, NUM_DRX_REGISTERS);

	switch (api_type) {
	case DRX_API_LIST:
		drx_list(regs);
		retval = false;
		break;
	case DRX_API_GET_BP:
		/* get the index of the breakpoint at addr */
		retval = drx_get_at(regs, addr);
		break;
	case DRX_API_REMOVE_BP:
		/* remove hardware breakpoint */
		drx_set(regs, n, addr, -1, 0, 0);
		retval = true;
		break;
	case DRX_API_SET_BP:
		/* set hardware breakpoint */
		drx_set(regs, n, addr, sz, rwx, g);
		retval = true;
		break;
	default:
		/* this should not happen, someone misused the API */
		eprintf("drx: Unsupported api type in rz_debug_native_drx\n");
		retval = false;
	}

	set_drx_regs(dbg, regs, NUM_DRX_REGISTERS);

	return retval;
}

static int rz_debug_native_bp(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
	if (b && b->hw) {
		return set
			? drx_add((RzDebug *)bp->user, bp, b)
			: drx_del((RzDebug *)bp->user, bp, b);
	}
	return false;
}

static int getMaxFiles(void) {
	struct rlimit limit;
	if (getrlimit(RLIMIT_NOFILE, &limit) != 0) {
		return 1024;
	}
	return limit.rlim_cur;
}

static RzList *xnu_desc_list(int pid) {
#if TARGET_OS_IPHONE || __POWERPC__
	return NULL;
#else
#define xwrz_testwx(x) ((x & 1) << 2) | (x & 2) | ((x & 4) >> 2)
	RzDebugDesc *desc;
	RzList *ret = rz_list_new();
	struct vnode_fdinfowithpath vi;
	int i, nb, type = 0;
	int maxfd = getMaxFiles();

	for (i = 0; i < maxfd; i++) {
		nb = proc_pidfdinfo(pid, i, PROC_PIDFDVNODEPATHINFO, &vi, sizeof(vi));
		if (nb < 1) {
			continue;
		}
		if (nb < sizeof(vi)) {
			perror("too few bytes");
			break;
		}
		// printf ("FD %d RWX %x ", i, vi.pfi.fi_openflags);
		// printf ("PATH %s\n", vi.pvip.vip_path);
		desc = rz_debug_desc_new(i,
			vi.pvip.vip_path,
			xwrz_testwx(vi.pfi.fi_openflags),
			type, 0);
		rz_list_append(ret, desc);
	}
	return ret;
#endif
}

static RzList /*<RzDebugDesc *>*/ *rz_debug_desc_native_list(int pid) {
	return xnu_desc_list(pid);
}

static int rz_debug_native_map_protect(RzDebug *dbg, ut64 addr, int size, int perms) {
	return xnu_map_protect(dbg, addr, size, perms);
}

static int rz_debug_desc_native_open(const char *path) {
	return 0;
}

static bool rz_debug_gcore(RzDebug *dbg, char *path, RzBuffer *dest) {
	(void)path;
	return xnu_generate_corefile(dbg, dest);
}