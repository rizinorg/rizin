// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/mman.h>
#include <rz_drx.h>
#include "linux/linux_debug.h"
#include "procfs.h"
#include "linux/linux_coredump.h"
#include "drx.c" // x86 specific
#include "bt.c"

#ifdef __WALL
#define WAITPID_FLAGS __WALL
#else
#define WAITPID_FLAGS 0
#endif

static char *rz_debug_native_reg_profile(RzDebug *dbg) {
	if (dbg->bits & RZ_SYS_BITS_32) {
#if __x86_64__
#include "reg/linux-x64-32.h" // 32 binary on x86_64
#else
#include "reg/linux-x86.h"
#endif
	} else {
#include "reg/linux-x64.h"
	}
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
				RZ_LOG_ERROR("(%d) is running or dead.\n", th->pid);
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
		RZ_LOG_ERROR("rz_debug_native_wait called with pid -1\n");
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

#define PRINT_FPU(fpregs) \
	rz_cons_printf("cwd = 0x%04x  ; control   ", (fpregs).cwd); \
	rz_cons_printf("swd = 0x%04x  ; status\n", (fpregs).swd); \
	rz_cons_printf("ftw = 0x%04x              ", (fpregs).ftw); \
	rz_cons_printf("fop = 0x%04x\n", (fpregs).fop); \
	rz_cons_printf("rip = 0x%016" PFMT64x "  ", (ut64)(fpregs).rip); \
	rz_cons_printf("rdp = 0x%016" PFMT64x "\n", (ut64)(fpregs).rdp); \
	rz_cons_printf("mxcsr = 0x%08x        ", (fpregs).mxcsr); \
	rz_cons_printf("mxcr_mask = 0x%08x\n", (fpregs).mxcr_mask)

#define PRINT_FPU_NOXMM(fpregs) \
	rz_cons_printf("cwd = 0x%04lx  ; control   ", (fpregs).cwd); \
	rz_cons_printf("swd = 0x%04lx  ; status\n", (fpregs).swd); \
	rz_cons_printf("twd = 0x%04lx              ", (fpregs).twd); \
	rz_cons_printf("fip = 0x%04lx          \n", (fpregs).fip); \
	rz_cons_printf("fcs = 0x%04lx              ", (fpregs).fcs); \
	rz_cons_printf("foo = 0x%04lx          \n", (fpregs).foo); \
	rz_cons_printf("fos = 0x%04lx              ", (fpregs).fos)

static void print_fpu(void *f) {
#if __x86_64__
	struct user_fpregs_struct fpregs = *(struct user_fpregs_struct *)f;
	rz_cons_printf("---- x86-64 ----\n");
	PRINT_FPU(fpregs);
	rz_cons_printf("size = 0x%08x\n", (ut32)sizeof(fpregs));
	for (int i = 0; i < 16; i++) {
		ut32 *a = (ut32 *)&fpregs.xmm_space;
		a = a + (i * 4);
		rz_cons_printf("xmm%d = %08x %08x %08x %08x   ", i, (int)a[0], (int)a[1],
			(int)a[2], (int)a[3]);
		if (i < 8) {
			ut64 *st_u64 = (ut64 *)&fpregs.st_space[i * 4];
			ut8 *st_u8 = (ut8 *)&fpregs.st_space[i * 4];
			long double *st_ld = (long double *)&fpregs.st_space[i * 4];
			rz_cons_printf("mm%d = 0x%016" PFMT64x " | st%d = ", i, *st_u64, i);
			// print as hex TBYTE - always little endian
			for (int j = 9; j >= 0; j--) {
				rz_cons_printf("%02x", st_u8[j]);
			}
			// Using %Lf and %Le even though we do not show the extra precision to avoid another cast
			// %f with (double)*st_ld would also work
			rz_cons_printf(" %Le %Lf\n", *st_ld, *st_ld);
		} else {
			rz_cons_printf("\n");
		}
	}
#elif __i386__
	struct user_fpregs_struct fpregs = *(struct user_fpregs_struct *)f;
	rz_cons_printf("---- x86-32-noxmm ----\n");
	PRINT_FPU_NOXMM(fpregs);
	for (int i = 0; i < 8; i++) {
		ut64 *b = (ut64 *)(&fpregs.st_space[i * 4]);
		double *d = (double *)b;
		ut32 *c = (ut32 *)&fpregs.st_space;
		float *f = (float *)&fpregs.st_space;
		c = c + (i * 4);
		f = f + (i * 4);
		rz_cons_printf("st%d = %0.3lg (0x%016" PFMT64x ") | %0.3f (0x%08x) | "
			       "%0.3f (0x%08x)\n",
			i, d[0], b[0], f[0], c[0], f[1], c[1]);
	}
#endif
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
	case RZ_REG_TYPE_DRX: {
		int i;
		for (i = 0; i < 8; i++) { // DR0-DR7
			if (i == 4 || i == 5) {
				continue;
			}
			long ret = rz_debug_ptrace(dbg, PTRACE_PEEKUSER, pid,
				(void *)rz_offsetof(struct user, u_debugreg[i]), 0);
			if ((i + 1) * sizeof(ret) > size) {
				RZ_LOG_ERROR("linux_reg_get: Buffer too small %d\n", size);
				break;
			}
			memcpy(buf + (i * sizeof(ret)), &ret, sizeof(ret));
		}
		struct user a;
		return sizeof(a.u_debugreg);
	}
		return true;
		break;
	case RZ_REG_TYPE_FPU:
	case RZ_REG_TYPE_MMX:
	case RZ_REG_TYPE_XMM: {
		struct user_fpregs_struct fpregs;
		if (type == RZ_REG_TYPE_FPU) {
#if __x86_64__
			ret = rz_debug_ptrace(dbg, PTRACE_GETFPREGS, pid, NULL, &fpregs);
			if (ret != 0) {
				rz_sys_perror("PTRACE_GETFPREGS");
				return false;
			}
			if (showfpu) {
				print_fpu((void *)&fpregs);
			}
			size = RZ_MIN(sizeof(fpregs), size);
			memcpy(buf, &fpregs, size);
			return size;
#elif __i386__
			struct user_fpxregs_struct fpxregs;
			ret = rz_debug_ptrace(dbg, PTRACE_GETFPXREGS, pid, NULL, &fpxregs);
			if (ret == 0) {
				if (showfpu) {
					print_fpu((void *)&fpxregs);
				}
				size = RZ_MIN(sizeof(fpxregs), size);
				memcpy(buf, &fpxregs, size);
				return size;
			} else {
				ret = rz_debug_ptrace(dbg, PTRACE_GETFPREGS, pid, NULL, &fpregs);
				if (showfpu) {
					print_fpu((void *)&fpregs);
				}
				if (ret != 0) {
					rz_sys_perror("PTRACE_GETFPREGS");
					return false;
				}
				size = RZ_MIN(sizeof(fpregs), size);
				memcpy(buf, &fpregs, size);
				return size;
			}
#endif // __i386__
		}
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
#if HAVE_YMM && __x86_64__ && defined(PTRACE_GETREGSET)
		ut32 ymm_space[128]; // full ymm registers
		struct _xstate xstate;
		struct iovec iov;
		iov.iov_base = &xstate;
		iov.iov_len = sizeof(struct _xstate);
		ret = rz_debug_ptrace_get_x86_xstate(dbg, pid, &iov);
		if (ret == -1) {
			return false;
		}
		// stitch together xstate.fpstate._xmm and xstate.ymmh assuming LE
		int ri, rj;
		for (ri = 0; ri < 16; ri++) {
			for (rj = 0; rj < 4; rj++) {
				ymm_space[ri * 8 + rj] = xstate.fpstate._xmm[ri].element[rj];
			}
			for (rj = 0; rj < 4; rj++) {
				ymm_space[ri * 8 + (rj + 4)] = xstate.ymmh.ymmh_space[ri * 4 + rj];
			}
		}
		size = RZ_MIN(sizeof(ymm_space), size);
		memcpy(buf, &ymm_space, size);
		return size;
#endif
		return false;
	} break;
	}
	return false;
}

static int rz_debug_native_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	int pid = dbg->tid;
	switch (type) {
	case RZ_REG_TYPE_DRX: {
		int i;
		long *val = (long *)buf;
		for (i = 0; i < 8; i++) { // DR0-DR7
			if (i == 4 || i == 5) {
				continue;
			}
			if (rz_debug_ptrace(dbg, PTRACE_POKEUSER, pid,
				    (void *)rz_offsetof(struct user, u_debugreg[i]), (rz_ptrace_data_t)val[i])) {
				rz_sys_perror("ptrace POKEUSER");
			}
		}
		return sizeof(RZ_DEBUG_REG_T);
	}
	case RZ_REG_TYPE_GPR: {
		int ret = rz_debug_ptrace(dbg, PTRACE_SETREGS, pid, 0, (void *)buf);
		if (ret == -1) {
			rz_sys_perror("reg_write");
			return false;
		}
		return true;
	}
	case RZ_REG_TYPE_FPU: {
		int ret = rz_debug_ptrace(dbg, PTRACE_SETFPREGS, pid, 0, (void *)buf);
		return (ret == 0);
	}
	default:
		RZ_LOG_DEBUG("TODO: reg_write_non-gpr (%d)\n", type);
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

static void sync_drx_regs(RzDebug *dbg, drxt *regs, size_t num_regs) {
	/* sanity check, we rely on this assumption */
	if (num_regs != NUM_DRX_REGISTERS) {
		RZ_LOG_ERROR("drx: Unsupported number of registers for get_debug_regs\n");
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
		RZ_LOG_ERROR("drx: Unsupported number of registers for get_debug_regs\n");
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
		RZ_LOG_ERROR("drx: Unsupported api type in rz_debug_native_drx\n");
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

RzList /*<RzDebugDesc *>*/ *rz_debug_desc_native_list(int pid) {
	return linux_desc_list(pid);
}

static int rz_debug_native_map_protect(RzDebug *dbg, ut64 addr, int size, int perms) {
	return linux_map_protect(dbg, addr, size, perms);
}

static int rz_debug_desc_native_open(const char *path) {
	return 0;
}

static bool rz_debug_gcore(RzDebug *dbg, char *path, RzBuffer *dest) {
	(void)path;
	return linux_generate_corefile(dbg, dest);
}

struct rz_debug_desc_plugin_t rz_debug_desc_plugin_native = {
	.open = rz_debug_desc_native_open,
	.list = rz_debug_desc_native_list,
};

static bool rz_debug_native_init(RzDebug *dbg, void **user) {
	dbg->cur->desc = rz_debug_desc_plugin_native;
	return true;
}

static void rz_debug_native_fini(RzDebug *dbg, void *user) {
	if (!user) {
		return;
	}
	free(user);
}

RzDebugPlugin rz_debug_plugin_native = {
	.name = "native",
	.license = "LGPL3",
#if __i386__
	.bits = RZ_SYS_BITS_32,
	.arch = "x86",
	.canstep = 1,
#elif __x86_64__
	.bits = RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.arch = "x86",
	.canstep = 1, // XXX it's 1 on some platforms...
#endif
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