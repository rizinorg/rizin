// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "windows/windows_debug.h"
// TODO: Move these onto windows.h?
RZ_API RzList *rz_w32_dbg_modules(RzDebug *); // ugly!
RZ_API RzList *rz_w32_dbg_maps(RzDebug *);
#define RZ_DEBUG_REG_T CONTEXT
#ifdef NTSTATUS
#undef NTSTATUS
#endif
#ifndef NTSTATUS
#define NTSTATUS int
#endif

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

#include "reg.c"

static bool rz_debug_native_step(RzDebug *dbg) {
	return w32_step(dbg);
}

static int rz_debug_native_attach(RzDebug *dbg, int pid) {
	return w32_attach(dbg, pid);
}

static int rz_debug_native_detach(RzDebug *dbg, int pid) {
	return w32_detach(dbg, pid);
}

static int rz_debug_native_select(RzDebug *dbg, int pid, int tid) {
	return w32_select(dbg, pid, tid);
}

static int rz_debug_native_continue_syscall(RzDebug *dbg, int pid, int num) {
	eprintf("TODO: continue syscall not implemented yet\n");
	return -1;
}

static int rz_debug_native_stop(RzDebug *dbg) {
	return 0;
}

static int rz_debug_native_continue(RzDebug *dbg, int pid, int tid, int sig) {
	return w32_continue(dbg, pid, tid, sig);
}

static RzDebugInfo *rz_debug_native_info(RzDebug *dbg, const char *arg) {
	return w32_info(dbg, arg);
}

static bool tracelib(RzDebug *dbg, const char *mode, PLIB_ITEM item) {
	const char *needle = NULL;
	int tmp = 0;
	if (mode) {
		switch (mode[0]) {
		case 'l': needle = dbg->glob_libs; break;
		case 'u': needle = dbg->glob_unlibs; break;
		}
	}
	rz_cons_printf("(%d) %sing library at 0x%p (%s) %s\n", item->pid, mode,
		item->BaseOfDll, item->Path, item->Name);
	rz_cons_flush();
	if (needle && strlen(needle)) {
		tmp = rz_str_glob(item->Name, needle);
	}
	return !mode || !needle || tmp;
}

static RzDebugReasonType rz_debug_native_wait(RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;
	// Store the original TID to attempt to switch back after handling events that
	// require switching to the event's thread that shouldn't bother the user
	int orig_tid = dbg->tid;
	bool restore_thread = false;
	W32DbgWInst *wrap = dbg->plugin_data;

	if (pid == -1) {
		RZ_LOG_ERROR("rz_debug_native_wait called with pid -1\n");
		return RZ_DEBUG_REASON_ERROR;
	}

	reason = w32_dbg_wait(dbg, pid);
	RzDebugInfo *native_info = rz_debug_native_info(dbg, "");
	if (reason == RZ_DEBUG_REASON_NEW_LIB) {
		if (native_info && native_info->lib) {
			/* Check if autoload PDB is set, and load PDB information if yes */
			RzCore *core = dbg->corebind.core;
			bool autoload_pdb = dbg->corebind.cfggeti(core, "pdb.autoload");
			if (autoload_pdb) {
				PLIB_ITEM lib = native_info->lib;
				if (rz_file_exists(lib->Path)) {
					if (tracelib(dbg, "load", native_info->lib)) {
						reason = RZ_DEBUG_REASON_TRAP;
					}
					RzBinOptions opts = { 0 };
					opts.obj_opts.baseaddr = (uintptr_t)lib->BaseOfDll;
					RzBinFile *cur = rz_bin_cur(core->bin);
					RzBinFile *bf = rz_bin_open(core->bin, lib->Path, &opts);
					if (bf) {
						const RzBinInfo *info = rz_bin_object_get_info(bf->o);
						if (RZ_STR_ISNOTEMPTY(info->debug_file_name)) {
							if (!rz_file_exists(info->debug_file_name)) {
								dbg->corebind.cmdf(core, "idpd");
							}
							dbg->corebind.cmd(core, "idp");
						}
						rz_bin_file_set_cur_binfile(core->bin, cur);
					}
				} else {
					RZ_LOG_ERROR("The library %s does not exist.\n", lib->Path);
				}
			}
		} else {
			RZ_LOG_WARN("Loading unknown library.\n");
		}
		restore_thread = true;
	} else if (reason == RZ_DEBUG_REASON_EXIT_LIB) {
		RzDebugInfo *r = rz_debug_native_info(dbg, "");
		if (r && r->lib) {
			if (tracelib(dbg, "unload", r->lib)) {
				reason = RZ_DEBUG_REASON_TRAP;
			}
		} else {
			RZ_LOG_WARN("Unloading unknown library.\n");
		}
		restore_thread = true;
	} else if (reason == RZ_DEBUG_REASON_NEW_PID) {
		if (native_info && native_info->thread) {
			PTHREAD_ITEM item = native_info->thread;
			RZ_LOG_INFO("(%d) Created process %d (start @ %p) (teb @ %p)\n", item->pid, item->tid, item->lpStartAddress, item->lpThreadLocalBase);
		}
	} else if (reason == RZ_DEBUG_REASON_NEW_TID) {
		if (native_info && native_info->thread) {
			PTHREAD_ITEM item = native_info->thread;
			RZ_LOG_INFO("(%d) Created thread %d (start @ %p) (teb @ %p)\n", item->pid, item->tid, item->lpStartAddress, item->lpThreadLocalBase);
		}
		restore_thread = true;
	} else if (reason == RZ_DEBUG_REASON_EXIT_TID) {
		PTHREAD_ITEM item = native_info->thread;
		if (native_info && native_info->thread) {
			RZ_LOG_INFO("(%d) Finished thread %d Exit code %lu\n", (ut32)item->pid, (ut32)item->tid, item->dwExitCode);
		}
		if (dbg->tid != orig_tid && item->tid != orig_tid) {
			restore_thread = true;
		}
	} else if (reason == RZ_DEBUG_REASON_DEAD) {
		if (native_info && native_info->thread) {
			PTHREAD_ITEM item = native_info->thread;
			RZ_LOG_INFO("(%d) Finished process with exit code %lu\n", dbg->main_pid, item->dwExitCode);
		}
		dbg->pid = -1;
		dbg->tid = -1;
	} else if (reason == RZ_DEBUG_REASON_USERSUSP && dbg->tid != orig_tid) {
		if (native_info && native_info->thread) {
			PTHREAD_ITEM item = native_info->thread;
			RZ_LOG_INFO("(%d) Created DebugBreak thread %d (start @ %p)\n", item->pid, item->tid, item->lpStartAddress);
		}
		// DebugProcessBreak creates a new thread that will trigger a breakpoint. We record the
		// tid here to ignore it once the breakpoint is hit.
		wrap->break_tid = dbg->tid;
		restore_thread = true;
	} else if (reason == RZ_DEBUG_REASON_BREAKPOINT && dbg->tid == wrap->break_tid) {
		wrap->break_tid = -2;
		reason = RZ_DEBUG_REASON_NONE;
		restore_thread = true;
	}
	rz_debug_info_free(native_info);

	if (restore_thread) {
		// Attempt to return to the original thread after handling the event
		dbg->tid = w32_select(dbg, dbg->pid, orig_tid);
		if (dbg->tid == -1) {
			dbg->pid = -1;
			reason = RZ_DEBUG_REASON_DEAD;
		} else {
			if (dbg->tid != orig_tid) {
				reason = RZ_DEBUG_REASON_UNKNOWN;
			}
		}
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
	return w32_pid_list(dbg, pid, list);
}

RZ_API RZ_OWN RzList /*<RzDebugPid *>*/ *rz_debug_native_threads(RzDebug *dbg, int pid) {
	RzList *list = rz_list_new();
	if (!list) {
		eprintf("No list?\n");
		return NULL;
	}
	return w32_thread_list(dbg, pid, list);
}

RZ_API ut64 rz_debug_get_tls(RZ_NONNULL RzDebug *dbg, int tid) {
	rz_return_val_if_fail(dbg, 0);
	return 0;
}

static int rz_debug_native_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	if (size < 1) {
		return false;
	}
	return w32_reg_read(dbg, type, buf, size);
}

static int rz_debug_native_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	// XXX use switch or so
	if (type == RZ_REG_TYPE_DRX) {
#if __i386__ || __x86_64__
		return w32_reg_write(dbg, type, buf, size);
#else // i386/x86-64
		return false;
#endif
	} else if (type == RZ_REG_TYPE_GPR) {
		return w32_reg_write(dbg, type, buf, size);
	} else if (type == RZ_REG_TYPE_FPU) {
		return false;
	} // else eprintf ("TODO: reg_write_non-gpr (%d)\n", type);
	return false;
}

static RzDebugMap *rz_debug_native_map_alloc(RzDebug *dbg, ut64 addr, int size, bool thp) {
	(void)thp;
	return w32_map_alloc(dbg, addr, size);
}

static int rz_debug_native_map_dealloc(RzDebug *dbg, ut64 addr, int size) {
	return w32_map_dealloc(dbg, addr, size);
}

static RzList /*<RzDebugMap *>*/ *rz_debug_native_map_get(RzDebug *dbg) {
	RzList *list = NULL;
	list = rz_w32_dbg_maps(dbg);
	return list;
}

static RzList /*<RzDebugMap *>*/ *rz_debug_native_modules_get(RzDebug *dbg) {
	char *lastname = NULL;
	RzDebugMap *map;
	RzListIter *iter, *iter2;
	RzList *list, *last;
	bool must_delete;
	list = rz_w32_dbg_modules(dbg);
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
	ret = w32_kill(dbg, pid, tid, sig);
	return ret;
}

struct rz_debug_desc_plugin_t rz_debug_desc_plugin_native;
static bool rz_debug_native_init(RzDebug *dbg, void **user) {
	dbg->cur->desc = rz_debug_desc_plugin_native;
	return w32_init(dbg);
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
#else
		return set
			? w32_hwbp_arm_add((RzDebug *)bp->user, bp, b)
			: w32_hwbp_arm_del((RzDebug *)bp->user, bp, b);
#endif
	}
	return false;
}

static RzList /*<RzDebugDesc *>*/ *rz_debug_desc_native_list(int pid) {
	return w32_desc_list(pid);
}

static int rz_debug_native_map_protect(RzDebug *dbg, ut64 addr, int size, int perms) {
	return w32_map_protect(dbg, addr, size, perms);
}

static int rz_debug_desc_native_open(const char *path) {
	return 0;
}

static bool rz_debug_gcore(RzDebug *dbg, char *path, RzBuffer *dest) {
	return false;
}