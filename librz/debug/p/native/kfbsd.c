// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <errno.h>
#if !defined(__HAIKU__) && !defined(__sun)
#include <sys/ptrace.h>
#endif
#include <sys/wait.h>
#include <signal.h>

#include "bsd/bsd_debug.h"
#include "procfs.h"

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

static int rz_debug_handle_signals(RzDebug *dbg) {
	return bsd_handle_signals(dbg);
}

#include "reg.c"

static bool rz_debug_native_step(RzDebug *dbg) {
	int ret = ptrace(PT_STEP, dbg->pid, (caddr_t)1, 0);
	if (ret != 0) {
		perror("native-singlestep");
		return false;
	}
	return true;
}

static int rz_debug_native_attach(RzDebug *dbg, int pid) {
	if (ptrace(PT_ATTACH, pid, 0, 0) != -1) {
		perror("ptrace (PT_ATTACH)");
	}
	return pid;
}

static int rz_debug_native_detach(RzDebug *dbg, int pid) {
	return ptrace(PT_DETACH, pid, NULL, 0);
}

static int rz_debug_native_continue_syscall(RzDebug *dbg, int pid, int num) {
	ut64 pc = rz_debug_reg_get(dbg, "PC");
	errno = 0;
	return ptrace(PTRACE_SYSCALL, pid, (void *)(size_t)pc, 0) == 0;
}

static int rz_debug_native_stop(RzDebug *dbg) {
	return 0;
}

static int rz_debug_native_continue(RzDebug *dbg, int pid, int tid, int sig) {
	void *data = (void *)(size_t)((sig != -1) ? sig : dbg->reason.signum);
	ut64 pc = rz_debug_reg_get(dbg, "PC");
	return ptrace(PTRACE_CONT, pid, (void *)(size_t)pc, (int)(size_t)data) == 0;
}

static RzDebugInfo *rz_debug_native_info(RzDebug *dbg, const char *arg) {
	return bsd_info(dbg, arg);
}

static RzDebugReasonType rz_debug_native_wait(RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;

	if (pid == -1) {
		eprintf("ERROR: rz_debug_native_wait called with pid -1\n");
		return RZ_DEBUG_REASON_ERROR;
	}
	int status = -1;
#ifdef WAIT_ON_ALL_CHILDREN
	int ret = waitpid(-1, &status, WAITPID_FLAGS);
#else
	int ret = waitpid(-1, &status, 0);
	if (ret != -1) {
		reason = RZ_DEBUG_REASON_TRAP;
	}
#endif
	if (ret == -1) {
		rz_sys_perror("waitpid");
		return RZ_DEBUG_REASON_ERROR;
	}

	// eprintf ("rz_debug_native_wait: status=%d (0x%x) (return=%d)\n", status, status, ret);
	if (reason == RZ_DEBUG_REASON_ERROR) {
		return reason;
	}
	/* we don't know what to do yet, let's try harder to figure it out. */
	if (reason == RZ_DEBUG_REASON_UNKNOWN) {
		if (WIFEXITED(status)) {
			eprintf("child exited with status %d\n", WEXITSTATUS(status));
			reason = RZ_DEBUG_REASON_DEAD;
		} else if (WIFSIGNALED(status)) {
			eprintf("child received signal %d\n", WTERMSIG(status));
			reason = RZ_DEBUG_REASON_SIGNAL;
		} else if (WIFSTOPPED(status)) {
			if (WSTOPSIG(status) != SIGTRAP &&
				WSTOPSIG(status) != SIGSTOP) {
				eprintf("Child stopped with signal %d\n", WSTOPSIG(status));
			}

			/* the ptrace documentation says GETSIGINFO is only necessary for
			 * differentiating the various stops.
			 *
			 * this might modify dbg->reason.signum
			 */
			if (rz_debug_handle_signals(dbg) != 0) {
				return RZ_DEBUG_REASON_ERROR;
			}
			reason = dbg->reason.type;
#ifdef WIFCONTINUED
		} else if (WIFCONTINUED(status)) {
			eprintf("child continued...\n");
			reason = RZ_DEBUG_REASON_NONE;
#endif
		} else if (status == 1) {
			/* XXX(jjd): does this actually happen? */
			eprintf("debugger is dead with status 1!\n");
			reason = RZ_DEBUG_REASON_DEAD;
		} else if (status == 0) {
			/* XXX(jjd): does this actually happen? */
			eprintf("debugger is dead with status 0\n");
			reason = RZ_DEBUG_REASON_DEAD;
		} else {
			if (ret != pid) {
				reason = RZ_DEBUG_REASON_NEW_PID;
			} else {
				/* ugh. still don't know :-/ */
				eprintf("returning from wait without knowing why...\n");
			}
		}
	}
	/* if we still don't know what to do, we have a problem... */
	if (reason == RZ_DEBUG_REASON_UNKNOWN) {
		eprintf("%s: no idea what happened...\n", __func__);
		reason = RZ_DEBUG_REASON_ERROR;
	}
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
	return bsd_pid_list(dbg, pid, list);
}

RZ_API RZ_OWN RzList /*<RzDebugPid *>*/ *rz_debug_native_threads(RzDebug *dbg, int pid) {
	RzList *list = rz_list_new();
	if (!list) {
		eprintf("No list?\n");
		return NULL;
	}
	return bsd_thread_list(dbg, pid, list);
}

RZ_API ut64 rz_debug_get_tls(RZ_NONNULL RzDebug *dbg, int tid) {
	rz_return_val_if_fail(dbg, 0);
	return 0;
}

static int bsd_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	int showfpu = false;
	int pid = dbg->pid;
	int ret;
	if (type < -1) {
		showfpu = true; // hack for debugging
		type = -type;
	}
	switch (type) {
	case RZ_REG_TYPE_DRX:
#if __i386__ || __x86_64__
	{
		// TODO
		struct dbreg dbr;
		ret = ptrace(PT_GETDBREGS, pid, (caddr_t)&dbr, sizeof(dbr));
		if (ret != 0)
			return false;
		// XXX: maybe the register map is not correct, must review
	}
#endif
		return true;
		break;
	case RZ_REG_TYPE_FPU:
	case RZ_REG_TYPE_MMX:
	case RZ_REG_TYPE_XMM:
		break;
	case RZ_REG_TYPE_SEG:
	case RZ_REG_TYPE_FLG:
	case RZ_REG_TYPE_GPR: {
		RZ_DEBUG_REG_T regs;
		memset(&regs, 0, sizeof(regs));
		memset(buf, 0, size);
		ret = ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0);
		// if perror here says 'no such process' and the
		// process exists still.. is because there's a
		// missing call to 'wait'. and the process is not
		// yet available to accept more ptrace queries.
		if (ret != 0)
			return false;
		if (sizeof(regs) < size)
			size = sizeof(regs);
		memcpy(buf, &regs, size);
		return sizeof(regs);
	} break;
	}
	return true;
}

static int rz_debug_native_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	if (size < 1) {
		return false;
	}
	return bsd_reg_read(dbg, type, buf, size);
}

static int rz_debug_native_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	// XXX use switch or so
	if (type == RZ_REG_TYPE_DRX) {
#if __i386__ || __x86_64__
		return bsd_reg_write(dbg, type, buf, size);
#else // i386/x86-64
		return false;
#endif
	} else if (type == RZ_REG_TYPE_GPR) {
		return bsd_reg_write(dbg, type, buf, size);
	} else if (type == RZ_REG_TYPE_FPU) {
		return bsd_reg_write(dbg, type, buf, size);
	} // else eprintf ("TODO: reg_write_non-gpr (%d)\n", type);
	return false;
}

static RzDebugMap *rz_debug_native_map_alloc(RzDebug *dbg, ut64 addr, int size, bool thp) {
	// malloc not implemented for this platform
	return NULL;
}

static int rz_debug_native_map_dealloc(RzDebug *dbg, ut64 addr, int size) {
	// mdealloc not implemented for this platform
	return false;
}

static void _map_free(RzDebugMap *map) {
	if (!map) {
		return;
	}
	free(map->name);
	free(map->file);
	free(map);
}

static RzList /*<RzDebugMap *>*/ *rz_debug_native_map_get(RzDebug *dbg) {
	RzList *list = NULL;
	int ign;
	char unkstr[PROC_UNKSTR_SZ + 1];
	RzDebugMap *map;
	int i, perm, unk = 0;
	char *pos_c;
	char path[1024], line[1024], name[PROC_NAME_SZ + 1];
	char region[PROC_REGION_SZ + 1], region2[PROC_REGION_SZ + 1], perms[PROC_PERM_SZ + 1];
	FILE *fd;
	if (dbg->pid == -1) {
		// eprintf ("rz_debug_native_map_get: No selected pid (-1)\n");
		return NULL;
	}
	/* prepend 0x prefix */
	region[0] = region2[0] = '0';
	region[1] = region2[1] = 'x';

	list = bsd_native_sysctl_map(dbg);
	if (list) {
		return list;
	}
	snprintf(path, sizeof(path), "/proc/%d/map", dbg->pid);
	fd = rz_sys_fopen(path, "r");
	if (!fd) {
		char *errmsg = rz_str_newf("Cannot open '%s'", path);
		perror(errmsg);
		free(errmsg);
		return NULL;
	}

	list = rz_list_new();
	if (!list) {
		fclose(fd);
		return NULL;
	}
	list->free = (RzListFree)_map_free;
	while (!feof(fd)) {
		size_t line_len;
		bool map_is_shared = false;
		ut64 map_start, map_end;

		if (!fgets(line, sizeof(line), fd)) {
			break;
		}
		/* kill the newline if we got one */
		line_len = strlen(line);
		if (line[line_len - 1] == '\n') {
			line[line_len - 1] = '\0';
			line_len--;
		}
		/* maps files should not have empty lines */
		if (line_len == 0) {
			break;
		}
		// 0x8070000 0x8072000 2 0 0xc1fde948 rw- 1 0 0x2180 COW NC vnode /usr/bin/gcc
		if (sscanf(line, "%" RZ_STR_DEF(PROC_REGION_LEFT_SZ) "s %" RZ_STR_DEF(PROC_REGION_LEFT_SZ) "s %d %d 0x%" RZ_STR_DEF(PROC_UNKSTR_SZ) "s %3s %d %d",
			    &region[2], &region2[2], &ign, &ign,
			    unkstr, perms, &ign, &ign) != 8) {
			eprintf("%s: Unable to parse \"%s\"\n", __func__, path);
			rz_list_free(list);
			return NULL;
		}

		/* snag the file name */
		pos_c = strchr(line, '/');
		if (pos_c) {
			strncpy(name, pos_c, sizeof(name) - 1);
		} else {
			name[0] = '\0';
		}

		if (!*name) {
			snprintf(name, sizeof(name), "unk%d", unk++);
		}
		perm = 0;
		for (i = 0; i < 5 && perms[i]; i++) {
			switch (perms[i]) {
			case 'r': perm |= RZ_PERM_R; break;
			case 'w': perm |= RZ_PERM_W; break;
			case 'x': perm |= RZ_PERM_X; break;
			case 'p': map_is_shared = false; break;
			case 's': map_is_shared = true; break;
			}
		}

		map_start = rz_num_get(NULL, region);
		map_end = rz_num_get(NULL, region2);
		if (map_start == map_end || map_end == 0) {
			eprintf("%s: ignoring invalid map size: %s - %s\n", __func__, region, region2);
			continue;
		}
		map = rz_debug_map_new(name, map_start, map_end, perm, 0);
		if (!map) {
			break;
		}
		map->file = rz_str_dup(name);
		rz_list_append(list, map);
	}
	fclose(fd);
	return list;
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

struct rz_debug_desc_plugin_t rz_debug_desc_plugin_native;
static bool rz_debug_native_init(RzDebug *dbg, void **user) {
	dbg->cur->desc = rz_debug_desc_plugin_native;
	return true;
}

static void rz_debug_native_fini(RzDebug *dbg, void *user) {
}

#if __i386__ || __x86_64__
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
#endif

#if __i386__ || __x86_64__
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
#endif

static int rz_debug_native_drx(RzDebug *dbg, int n, ut64 addr, int sz, int rwx, int g, int api_type) {
#if __i386__ || __x86_64__
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
#else
	eprintf("drx: Unsupported platform\n");
#endif
	return -1;
}

static int rz_debug_native_bp(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
	if (b && b->hw) {
#if __i386__ || __x86_64__
		return set
			? drx_add((RzDebug *)bp->user, bp, b)
			: drx_del((RzDebug *)bp->user, bp, b);
#endif
	}
	return false;
}

static RzList /*<RzDebugDesc *>*/ *rz_debug_desc_native_list(int pid) {
	return bsd_desc_list(pid);
}

static int rz_debug_native_map_protect(RzDebug *dbg, ut64 addr, int size, int perms) {
	return false;
}

static int rz_debug_desc_native_open(const char *path) {
	return 0;
}

static bool rz_debug_gcore(RzDebug *dbg, char *path, RzBuffer *dest) {
	return bsd_generate_corefile(dbg, path, dest);
}