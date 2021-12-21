// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2018 jduck <github.jdrake@qoop.org>
// SPDX-FileCopyrightText: 2009-2018 LemonBoy <thatlemon@gmail.com>
// SPDX-FileCopyrightText: 2009-2018 saucec0de
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include <rz_drx.h>
#include <rz_core.h>
#include <signal.h>

RZ_LIB_VERSION(rz_debug);

// Size of the lookahead buffers used in rz_debug functions
#define DBG_BUF_SIZE 512

RZ_API RzDebugInfo *rz_debug_info(RzDebug *dbg, const char *arg) {
	if (!dbg || !dbg->cur || !dbg->cur->info) {
		return NULL;
	}
	if (dbg->pid < 0) {
		return NULL;
	}
	return dbg->cur->info(dbg, arg);
}

RZ_API void rz_debug_info_free(RzDebugInfo *rdi) {
	if (rdi) {
		free(rdi->cwd);
		free(rdi->exe);
		free(rdi->cmdline);
		free(rdi->libname);
		free(rdi->usr);
		free(rdi);
	}
}

RZ_API void rz_debug_bp_update(RzDebug *dbg) {
	/* update all bp->addr if they are named bps */
	RzBreakpointItem *bp;
	RzListIter *iter;
	rz_list_foreach (dbg->bp->bps, iter, bp) {
		if (bp->expr) {
			bp->addr = dbg->corebind.numGet(dbg->corebind.core, bp->expr);
		}
	}
}

static int rz_debug_drx_at(RzDebug *dbg, ut64 addr) {
	if (dbg && dbg->cur && dbg->cur->drx) {
		return dbg->cur->drx(dbg, 0, addr, 0, 0, 0, DRX_API_GET_BP);
	}
	return -1;
}

/*
 * Recoiling after a breakpoint has two stages:
 * 1. remove the breakpoint and fix the program counter.
 * 2. on resume, single step once and then replace the breakpoint.
 *
 * Thus, we have two functions to handle these situations.
 * rz_debug_bp_hit handles stage 1.
 * rz_debug_recoil handles stage 2.
 */
static int rz_debug_bp_hit(RzDebug *dbg, RzRegItem *pc_ri, ut64 pc, RzBreakpointItem **pb) {
	RzBreakpointItem *b;

	if (!pb) {
		eprintf("BreakpointItem is NULL!\n");
		return false;
	}
	/* initialize the output parameter */
	*pb = NULL;

	/* if we are tracing, update the tracing data */
	if (dbg->trace->enabled) {
		rz_debug_trace_pc(dbg, pc);
	}

	/* remove all sw breakpoints for now. we'll set them back in stage 2
	 *
	 * this is necessary because while stopped we don't want any breakpoints in
	 * the code messing up our analysis.
	 */
	rz_debug_bp_update(dbg);
	if (!rz_bp_restore(dbg->bp, false)) { // unset sw breakpoints
		return false;
	}

	/* if we are recoiling, tell rz_debug_step that we ignored a breakpoint
	 * event */
	if (!dbg->swstep && dbg->recoil_mode != RZ_DBG_RECOIL_NONE) {
		dbg->reason.bp_addr = 0;
		return true;
	}

	/* The MIPS ptrace has a different behaviour */
#if __mips__
	/* see if we really have a breakpoint here... */
	b = rz_bp_get_at(dbg->bp, pc);
	if (!b) { /* we don't. nothing left to do */
		return true;
	}
#else
	int pc_off = dbg->bpsize;
	/* see if we really have a breakpoint here... */
	if (!dbg->pc_at_bp_set) {
		b = rz_bp_get_at(dbg->bp, pc - dbg->bpsize);
		if (!b) { /* we don't. nothing left to do */
			/* Some targets set pc to breakpoint */
			b = rz_bp_get_at(dbg->bp, pc);
			if (!b) {
				/* handle the case of hw breakpoints - notify the user */
				int drx_reg_idx = rz_debug_drx_at(dbg, pc);
				if (drx_reg_idx != -1) {
					eprintf("hit hardware breakpoint %d at: %" PFMT64x "\n",
						drx_reg_idx, pc);
				}
				/* Couldn't find the break point. Nothing more to do... */
				return true;
			} else {
				dbg->pc_at_bp_set = true;
				dbg->pc_at_bp = true;
			}
		} else {
			dbg->pc_at_bp_set = true;
			dbg->pc_at_bp = false;
		}
	}

	if (!dbg->pc_at_bp_set) {
		eprintf("failed to determine position of pc after breakpoint");
	}

	if (dbg->pc_at_bp) {
		pc_off = 0;
		b = rz_bp_get_at(dbg->bp, pc);
	} else {
		b = rz_bp_get_at(dbg->bp, pc - dbg->bpsize);
	}

	if (!b) {
		return true;
	}

	b = rz_bp_get_at(dbg->bp, pc - dbg->bpsize);
	if (!b) { /* we don't. nothing left to do */
		/* Some targets set pc to breakpoint */
		b = rz_bp_get_at(dbg->bp, pc);
		if (!b) {
			return true;
		}
		pc_off = 0;
	}

	/* set the pc value back */
	if (pc_off) {
		pc -= pc_off;
		if (!rz_reg_set_value(dbg->reg, pc_ri, pc)) {
			eprintf("failed to set PC!\n");
			return false;
		}
		if (!rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, true)) {
			eprintf("cannot set registers!\n");
			return false;
		}
	}
#endif

	*pb = b;

	/* if we are on a software stepping breakpoint, we hide what is going on... */
	if (b->swstep) {
		dbg->reason.bp_addr = 0;
		return true;
	}

	/* setup our stage 2 */
	dbg->reason.bp_addr = b->addr;

	/* inform the user of what happened */
	if (dbg->hitinfo) {
		eprintf("hit %spoint at: 0x%" PFMT64x "\n",
			b->trace ? "trace" : "break", pc);
	}

	/* now that we've cleaned up after the breakpoint, call the other
	 * potential breakpoint handlers
	 */
	if (dbg->corebind.core && dbg->corebind.bphit) {
		dbg->corebind.bphit(dbg->corebind.core, b);
	}
	return true;
}

/* enable all software breakpoints */
static int rz_debug_bps_enable(RzDebug *dbg) {
	/* restore all sw breakpoints. we are about to step/continue so these need
	 * to be in place. */
	if (!rz_bp_restore(dbg->bp, true)) {
		return false;
	}
	/* done recoiling... */
	dbg->recoil_mode = RZ_DBG_RECOIL_NONE;
	return true;
}

/*
 * replace breakpoints before we continue execution
 *
 * this is called from rz_debug_step_hard or rz_debug_continue_kill
 *
 * this is a trick process because of breakpoints/tracepoints.
 *
 * if a breakpoint was just hit, we need step over that instruction before
 * allowing the caller to proceed as desired.
 *
 * if the user wants to step, the single step here does the job.
 */
static int rz_debug_recoil(RzDebug *dbg, RzDebugRecoilMode rc_mode) {
	/* if bp_addr is not set, we must not have actually hit a breakpoint */
	if (!dbg->reason.bp_addr) {
		return rz_debug_bps_enable(dbg);
	}

	/* don't do anything if we already are recoiling */
	if (dbg->recoil_mode != RZ_DBG_RECOIL_NONE) {
		/* the first time recoil is called with swstep, we just need to
		 * look up the bp and step past it.
		 * the second time it's called, the new sw breakpoint should exist
		 * so we just restore all except what we originally hit and reset.
		 */
		if (dbg->swstep) {
			if (!rz_bp_restore_except(dbg->bp, true, dbg->reason.bp_addr)) {
				return false;
			}
			return true;
		}

		/* otherwise, avoid recursion */
		return true;
	}

	/* we have entered recoil! */
	dbg->recoil_mode = rc_mode;

	/* step over the place with the breakpoint and let the caller resume */
	if (rz_debug_step(dbg, 1) != 1) {
		return false;
	}

	/* when stepping away from a breakpoint during recoil in stepping mode,
	 * the rz_debug_bp_hit function tells us that it was called
	 * innapropriately by setting bp_addr back to zero. however, recoil_mode
	 * is still set. we use this condition to know not to proceed but
	 * pretend as if we had.
	 */
	if (!dbg->reason.bp_addr && dbg->recoil_mode == RZ_DBG_RECOIL_STEP) {
		return true;
	}
	dbg->reason.bp_addr = 0;

	return rz_debug_bps_enable(dbg);
}

/* add a breakpoint with some typical values */
RZ_API RzBreakpointItem *rz_debug_bp_add(RzDebug *dbg, ut64 addr, int hw, bool watch, int rw, const char *module, st64 m_delta) {
	int bpsz = rz_bp_size(dbg->bp);
	RzBreakpointItem *bpi;
	const char *module_name = module;
	RzListIter *iter;
	RzDebugMap *map;
	if (!addr && module) {
		bool detect_module, valid = false;
		int perm;

		if (m_delta) {
			detect_module = false;
			RzList *list = rz_debug_modules_list(dbg);
			rz_list_foreach (list, iter, map) {
				if (strstr(map->file, module)) {
					addr = map->addr + m_delta;
					module_name = map->file;
					break;
				}
			}
			rz_list_free(list);
		} else {
			// module holds the address
			addr = (ut64)rz_num_math(dbg->num, module);
			if (!addr) {
				return NULL;
			}
			detect_module = true;
		}
		rz_debug_map_sync(dbg);
		rz_list_foreach (dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				valid = true;
				if (detect_module) {
					module_name = map->file;
					m_delta = addr - map->addr;
				}
				perm = ((map->perm & 1) << 2) | (map->perm & 2) | ((map->perm & 4) >> 2);
				if (!(perm & RZ_PERM_X)) {
					eprintf("WARNING: setting bp within mapped memory without exec perm\n");
				}
				break;
			}
		}
		if (!valid) {
			eprintf("WARNING: module's base addr + delta is not a valid address\n");
			return NULL;
		}
	}
	if (!module) {
		// express db breakpoints as dbm due to ASLR when saving into project
		rz_debug_map_sync(dbg);
		rz_list_foreach (dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				module_name = map->file;
				m_delta = addr - map->addr;
				break;
			}
		}
	}
	if (watch) {
		hw = 1; // XXX
		bpi = rz_bp_watch_add(dbg->bp, addr, bpsz, hw, rw);
	} else {
		bpi = hw
			? rz_bp_add_hw(dbg->bp, addr, bpsz, RZ_PERM_X)
			: rz_bp_add_sw(dbg->bp, addr, bpsz, RZ_PERM_X);
	}
	if (bpi) {
		if (module_name) {
			bpi->module_name = strdup(module_name);
			bpi->name = rz_str_newf("%s+0x%" PFMT64x, module_name, m_delta);
		}
		bpi->module_delta = m_delta;
	}
	return bpi;
}

static const char *rz_debug_str_callback(RzNum *userptr, ut64 off, int *ok) {
	// RzDebug *dbg = (RzDebug *)userptr;
	eprintf("rz_debug_str_callback has been called. this should not happen\n");
	return NULL;
}

void free_tracenodes_kv(HtUPKv *kv) {
	free(kv->value);
}

RZ_API RzDebug *rz_debug_new(int hard) {
	RzDebug *dbg = RZ_NEW0(RzDebug);
	if (!dbg) {
		return NULL;
	}
	// RZ_SYS_ARCH
	dbg->arch = strdup(RZ_SYS_ARCH);
	dbg->bits = RZ_SYS_BITS;
	dbg->trace_forks = 1;
	dbg->forked_pid = -1;
	dbg->main_pid = -1;
	dbg->n_threads = 0;
	dbg->trace_clone = 0;
	dbg->egg = rz_egg_new();
	rz_egg_setup(dbg->egg, RZ_SYS_ARCH, RZ_SYS_BITS, RZ_SYS_ENDIAN, RZ_SYS_OS);
	dbg->trace_aftersyscall = true;
	dbg->follow_child = false;
	RZ_FREE(dbg->btalgo);
	dbg->trace_execs = 0;
	dbg->analysis = NULL;
	dbg->pid = -1;
	dbg->bpsize = 1;
	dbg->tid = -1;
	dbg->tree = rz_tree_new();
	dbg->tracenodes = ht_up_new(NULL, free_tracenodes_kv, NULL);
	dbg->swstep = 0;
	dbg->stop_all_threads = false;
	dbg->trace = rz_debug_trace_new();
	dbg->cb_printf = (void *)printf;
	dbg->reg = rz_reg_new();
	dbg->num = rz_num_new(rz_debug_num_callback, rz_debug_str_callback, dbg);
	dbg->cur = NULL;
	dbg->plugin_data = NULL;
	dbg->threads = NULL;
	dbg->hitinfo = 1;
	/* TODO: needs a redesign? */
	dbg->maps = rz_debug_map_list_new();
	dbg->maps_user = rz_debug_map_list_new();
	dbg->q_regs = NULL;
	dbg->call_frames = NULL;
	dbg->main_arena_resolved = false;
	dbg->glibc_version = 231; /* default version ubuntu 20 */
	rz_debug_signal_init(dbg);
	if (hard) {
		dbg->bp = rz_bp_new();
		rz_debug_plugin_init(dbg);
		dbg->bp->iob.init = false;
		dbg->bp->baddr = 0;
	}
	return dbg;
}

RZ_API void rz_debug_tracenodes_reset(RzDebug *dbg) {
	ht_up_free(dbg->tracenodes);
	dbg->tracenodes = ht_up_new(NULL, free_tracenodes_kv, NULL);
}

RZ_API RzDebug *rz_debug_free(RzDebug *dbg) {
	if (dbg) {
		// TODO: free it correctly.. we must ensure this is an instance and not a reference..
		rz_bp_free(dbg->bp);
		// rz_reg_free(&dbg->reg);
		free(dbg->snap_path);
		rz_list_free(dbg->maps);
		rz_list_free(dbg->maps_user);
		rz_list_free(dbg->threads);
		rz_num_free(dbg->num);
		sdb_free(dbg->sgnls);
		rz_tree_free(dbg->tree);
		ht_up_free(dbg->tracenodes);
		rz_list_free(dbg->plugins);
		rz_list_free(dbg->call_frames);
		free(dbg->btalgo);
		rz_debug_trace_free(dbg->trace);
		rz_debug_session_free(dbg->session);
		rz_analysis_op_free(dbg->cur_op);
		dbg->trace = NULL;
		rz_egg_free(dbg->egg);
		free(dbg->arch);
		free(dbg->glob_libs);
		free(dbg->glob_unlibs);
		free(dbg);
	}
	return NULL;
}

RZ_API int rz_debug_attach(RzDebug *dbg, int pid) {
	int ret = false;
	if (dbg && dbg->cur && dbg->cur->attach) {
		ret = dbg->cur->attach(dbg, pid);
		if (ret != -1) {
			dbg->reason.type = RZ_DEBUG_REASON_NONE; // after a successful attach, the process is not dead
			rz_debug_select(dbg, pid, ret); // dbg->pid, dbg->tid);
		}
	}
	return ret;
}

/* stop execution of child process */
RZ_API int rz_debug_stop(RzDebug *dbg) {
	if (dbg && dbg->cur && dbg->cur->stop) {
		return dbg->cur->stop(dbg);
	}
	return false;
}

RZ_API bool rz_debug_set_arch(RzDebug *dbg, const char *arch, int bits) {
	if (arch && dbg && dbg->cur) {
		switch (bits) {
		case 16:
			if (dbg->cur->bits & RZ_SYS_BITS_16) {
				dbg->bits = RZ_SYS_BITS_16;
			}
			break;
		case 27:
			if (dbg->cur->bits == 27) {
				dbg->bits = 27;
			}
			break;
		case 32:
			if (dbg->cur->bits & RZ_SYS_BITS_32) {
				dbg->bits = RZ_SYS_BITS_32;
			}
			break;
		case 64:
			dbg->bits = RZ_SYS_BITS_64;
			break;
		}
		if (!dbg->cur->bits) {
			dbg->bits = dbg->cur->bits;
		} else if (!(dbg->cur->bits & dbg->bits)) {
			dbg->bits = dbg->cur->bits & RZ_SYS_BITS_64;
			if (!dbg->bits) {
				dbg->bits = dbg->cur->bits & RZ_SYS_BITS_32;
			}
			if (!dbg->bits) {
				dbg->bits = RZ_SYS_BITS_32;
			}
		}
		free(dbg->arch);
		dbg->arch = strdup(arch);
		return true;
	}
	return false;
}

/*
 * Save 4096 bytes from %esp
 * TODO: Add support for reverse stack architectures
 * Also known as rz_debug_inject()
 */
RZ_API ut64 rz_debug_execute(RzDebug *dbg, const ut8 *buf, int len, int restore) {
	int orig_sz;
	ut8 stackbackup[4096];
	ut8 *backup, *orig = NULL;
	RzRegItem *ri, *risp, *ripc;
	ut64 rsp, rpc, ra0 = 0LL;
	if (rz_debug_is_dead(dbg)) {
		return false;
	}
	ripc = rz_reg_get(dbg->reg, dbg->reg->name[RZ_REG_NAME_PC], RZ_REG_TYPE_GPR);
	risp = rz_reg_get(dbg->reg, dbg->reg->name[RZ_REG_NAME_SP], RZ_REG_TYPE_GPR);
	if (ripc) {
		rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false);
		orig = rz_reg_get_bytes(dbg->reg, RZ_REG_TYPE_ANY, &orig_sz);
		if (!orig) {
			eprintf("Cannot get register arena bytes\n");
			return 0LL;
		}
		rpc = rz_reg_get_value(dbg->reg, ripc);
		rsp = rz_reg_get_value(dbg->reg, risp);

		backup = malloc(len);
		if (!backup) {
			free(orig);
			return 0LL;
		}
		dbg->iob.read_at(dbg->iob.io, rpc, backup, len);
		dbg->iob.read_at(dbg->iob.io, rsp, stackbackup, len);

		rz_bp_add_sw(dbg->bp, rpc + len, dbg->bpsize, RZ_PERM_X);

		/* execute code here */
		dbg->iob.write_at(dbg->iob.io, rpc, buf, len);
		// rz_bp_add_sw (dbg->bp, rpc+len, 4, RZ_PERM_X);
		rz_debug_continue(dbg);
		// rz_bp_del (dbg->bp, rpc+len);
		/* TODO: check if stopped in breakpoint or not */

		rz_bp_del(dbg->bp, rpc + len);
		dbg->iob.write_at(dbg->iob.io, rpc, backup, len);
		if (restore) {
			dbg->iob.write_at(dbg->iob.io, rsp, stackbackup, len);
		}

		rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false);
		ri = rz_reg_get(dbg->reg, dbg->reg->name[RZ_REG_NAME_A0], RZ_REG_TYPE_GPR);
		ra0 = rz_reg_get_value(dbg->reg, ri);
		if (restore) {
			rz_reg_read_regs(dbg->reg, orig, orig_sz);
		} else {
			rz_reg_set_value(dbg->reg, ripc, rpc);
		}
		rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, true);
		free(backup);
		free(orig);
		eprintf("ra0=0x%08" PFMT64x "\n", ra0);
	} else {
		eprintf("rz_debug_execute: Cannot get program counter\n");
	}
	return (ra0);
}

RZ_API int rz_debug_startv(struct rz_debug_t *dbg, int argc, char **argv) {
	/* TODO : rz_debug_startv unimplemented */
	return false;
}

RZ_API int rz_debug_start(RzDebug *dbg, const char *cmd) {
	/* TODO: this argc/argv parser is done in rz_io */
	// TODO: parse cmd and generate argc and argv
	return false;
}

RZ_API int rz_debug_detach(RzDebug *dbg, int pid) {
	int ret = 0;
	if (dbg->cur && dbg->cur->detach) {
		ret = dbg->cur->detach(dbg, pid);
		if (dbg->pid == pid) {
			dbg->pid = -1;
			dbg->tid = -1;
		}
	}
	return ret;
}

RZ_API bool rz_debug_select(RzDebug *dbg, int pid, int tid) {
	ut64 pc = 0;
	int prev_pid = dbg->pid;
	int prev_tid = dbg->tid;

	if (pid < 0) {
		return false;
	}
	if (tid < 0) {
		tid = pid;
	}

	if ((pid != dbg->pid || tid != dbg->tid) && dbg->verbose) {
		eprintf("= attach %d %d\n", pid, tid);
	}

	if (dbg->cur && dbg->cur->select && !dbg->cur->select(dbg, pid, tid)) {
		return false;
	}

	// Don't change the pid/tid if the plugin already modified it due to internal constraints
	if (dbg->pid == prev_pid) {
		dbg->pid = pid;
	}
	if (dbg->tid == prev_tid) {
		dbg->tid = tid;
	}

	rz_io_system(dbg->iob.io, sdb_fmt("pid %d", dbg->tid));

	// Synchronize with the current thread's data
	if (dbg->corebind.core) {
		RzCore *core = (RzCore *)dbg->corebind.core;

		rz_reg_arena_swap(core->dbg->reg, true);
		rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);

		pc = rz_debug_reg_get(dbg, "PC");
		core->offset = pc;
	}

	return true;
}

RZ_API const char *rz_debug_reason_to_string(int type) {
	switch (type) {
	case RZ_DEBUG_REASON_DEAD: return "dead";
	case RZ_DEBUG_REASON_ABORT: return "abort";
	case RZ_DEBUG_REASON_SEGFAULT: return "segfault";
	case RZ_DEBUG_REASON_NONE: return "none";
	case RZ_DEBUG_REASON_SIGNAL: return "signal";
	case RZ_DEBUG_REASON_BREAKPOINT: return "breakpoint";
	case RZ_DEBUG_REASON_TRACEPOINT: return "tracepoint";
	case RZ_DEBUG_REASON_READERR: return "read-error";
	case RZ_DEBUG_REASON_WRITERR: return "write-error";
	case RZ_DEBUG_REASON_DIVBYZERO: return "div-by-zero";
	case RZ_DEBUG_REASON_ILLEGAL: return "illegal";
	case RZ_DEBUG_REASON_UNKNOWN: return "unknown";
	case RZ_DEBUG_REASON_ERROR: return "error";
	case RZ_DEBUG_REASON_NEW_PID: return "new-pid";
	case RZ_DEBUG_REASON_NEW_TID: return "new-tid";
	case RZ_DEBUG_REASON_NEW_LIB: return "new-lib";
	case RZ_DEBUG_REASON_EXIT_PID: return "exit-pid";
	case RZ_DEBUG_REASON_EXIT_TID: return "exit-tid";
	case RZ_DEBUG_REASON_EXIT_LIB: return "exit-lib";
	case RZ_DEBUG_REASON_TRAP: return "trap";
	case RZ_DEBUG_REASON_SWI: return "software-interrupt";
	case RZ_DEBUG_REASON_INT: return "interrupt";
	case RZ_DEBUG_REASON_FPU: return "fpu";
	case RZ_DEBUG_REASON_STEP: return "step";
	case RZ_DEBUG_REASON_USERSUSP: return "suspended-by-user";
	}
	return "unhandled";
}

RZ_API RzDebugReasonType rz_debug_stop_reason(RzDebug *dbg) {
	// TODO: return reason to stop debugging
	// - new process
	// - trap instruction
	// - illegal instruction
	// - fpu exception
	// return dbg->reason
	return dbg->reason.type;
}

/*
 * wait for an event to happen on the selected pid/tid
 *
 * Returns  RZ_DEBUG_REASON_*
 */
RZ_API RzDebugReasonType rz_debug_wait(RzDebug *dbg, RzBreakpointItem **bp) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_ERROR;
	if (!dbg) {
		return reason;
	}

	if (bp) {
		*bp = NULL;
	}
	/* default to unknown */
	dbg->reason.type = RZ_DEBUG_REASON_UNKNOWN;
	if (rz_debug_is_dead(dbg)) {
		return RZ_DEBUG_REASON_DEAD;
	}

	/* if our debugger plugin has wait */
	if (dbg->cur && dbg->cur->wait) {
		reason = dbg->cur->wait(dbg, dbg->pid);
		if (reason == RZ_DEBUG_REASON_DEAD) {
			eprintf("\n==> Process finished\n\n");
			RzEventDebugProcessFinished event = {
				.pid = dbg->pid
			};
			rz_event_send(dbg->ev, RZ_EVENT_DEBUG_PROCESS_FINISHED, &event);
			// XXX(jjd): TODO: handle fallback or something else
			// rz_debug_select (dbg, -1, -1);
			return RZ_DEBUG_REASON_DEAD;
		}

#if __linux__
		// Letting other threads running will cause ptrace commands to fail
		// when writing to the same process memory to set/unset breakpoints
		// and is problematic in Linux.
		if (dbg->continue_all_threads) {
			rz_debug_stop(dbg);
		}
#endif

		/* propagate errors from the plugin */
		if (reason == RZ_DEBUG_REASON_ERROR) {
			return RZ_DEBUG_REASON_ERROR;
		}

		/* read general purpose registers */
		if (!rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false)) {
			return RZ_DEBUG_REASON_ERROR;
		}

		bool libs_bp = (dbg->glob_libs || dbg->glob_unlibs) ? true : false;
		/* if the underlying stop reason is a breakpoint, call the handlers */
		if (reason == RZ_DEBUG_REASON_BREAKPOINT ||
			reason == RZ_DEBUG_REASON_STEP ||
			(libs_bp && ((reason == RZ_DEBUG_REASON_NEW_LIB) || (reason == RZ_DEBUG_REASON_EXIT_LIB)))) {
			RzRegItem *pc_ri;
			RzBreakpointItem *b = NULL;
			ut64 pc;

			/* get the program coounter */
			pc_ri = rz_reg_get(dbg->reg, dbg->reg->name[RZ_REG_NAME_PC], -1);
			if (!pc_ri) { /* couldn't find PC?! */
				eprintf("Couldn't find PC!\n");
				return RZ_DEBUG_REASON_ERROR;
			}

			/* get the value */
			pc = rz_reg_get_value(dbg->reg, pc_ri);

			if (!rz_debug_bp_hit(dbg, pc_ri, pc, &b)) {
				return RZ_DEBUG_REASON_ERROR;
			}

			if (bp) {
				*bp = b;
			}

			if (b && reason == RZ_DEBUG_REASON_STEP) {
				reason = RZ_DEBUG_REASON_BREAKPOINT;
			}
			/* if we hit a tracing breakpoint, we need to continue in
			 * whatever mode the user desired. */
			if (dbg->corebind.core && b && b->cond) {
				reason = RZ_DEBUG_REASON_COND;
			}
			if (b && b->trace) {
				reason = RZ_DEBUG_REASON_TRACEPOINT;
			}
		}

		dbg->reason.type = reason;
		if (reason == RZ_DEBUG_REASON_SIGNAL && dbg->reason.signum != -1) {
			/* handle signal on continuations here */
			int what = rz_debug_signal_what(dbg, dbg->reason.signum);
			const char *name = rz_signal_to_string(dbg->reason.signum);
			if (name && strcmp("SIGTRAP", name)) {
				rz_cons_printf("[+] signal %d aka %s received %d\n",
					dbg->reason.signum, name, what);
			}
		}
	}
	return reason;
}

RZ_API int rz_debug_step_soft(RzDebug *dbg) {
	ut8 buf[32];
	ut64 pc, sp, r;
	ut64 next[2];
	RzAnalysisOp op;
	int br, i, ret;
	union {
		ut64 r64;
		ut32 r32[2];
	} sp_top;
	union {
		ut64 r64;
		ut32 r32[2];
	} memval;

	if (dbg->recoil_mode == RZ_DBG_RECOIL_NONE) {
		dbg->recoil_mode = RZ_DBG_RECOIL_STEP;
	}

	if (rz_debug_is_dead(dbg)) {
		return false;
	}

	const bool has_lr_reg = rz_reg_get_name(dbg->reg, RZ_REG_NAME_LR);
	const bool arch_ret_is_pop = !strcmp(dbg->arch, "arm") && dbg->bits <= RZ_SYS_BITS_32;

	pc = rz_debug_reg_get(dbg, dbg->reg->name[RZ_REG_NAME_PC]);
	sp = rz_debug_reg_get(dbg, dbg->reg->name[RZ_REG_NAME_SP]);

	if (!dbg->iob.read_at) {
		return false;
	}
	if (!dbg->iob.read_at(dbg->iob.io, pc, buf, sizeof(buf))) {
		return false;
	}
	if (!rz_analysis_op(dbg->analysis, &op, pc, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC)) {
		return false;
	}
	if (op.type == RZ_ANALYSIS_OP_TYPE_ILL) {
		return false;
	}
	switch (op.type) {
	case RZ_ANALYSIS_OP_TYPE_RET:
		if (arch_ret_is_pop && op.stackop == RZ_ANALYSIS_STACK_INC) {
			dbg->iob.read_at(dbg->iob.io, sp - op.stackptr - 4, (ut8 *)&sp_top, 4);
			next[0] = sp_top.r32[0];
		} else if (has_lr_reg) {
			next[0] = rz_debug_reg_get(dbg, dbg->reg->name[RZ_REG_NAME_LR]);
		} else {
			dbg->iob.read_at(dbg->iob.io, sp, (ut8 *)&sp_top, 8);
			next[0] = (dbg->bits <= RZ_SYS_BITS_32) ? sp_top.r32[0] : sp_top.r64;
		}
		br = 1;
		break;
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_CCALL:
		next[0] = op.jump;
		next[1] = op.fail;
		br = 2;
		break;
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_JMP:
		next[0] = op.jump;
		br = 1;
		break;
	case RZ_ANALYSIS_OP_TYPE_RJMP:
	case RZ_ANALYSIS_OP_TYPE_RCALL:
		r = rz_debug_reg_get(dbg, op.reg);
		next[0] = r;
		br = 1;
		break;
	case RZ_ANALYSIS_OP_TYPE_IRCALL:
	case RZ_ANALYSIS_OP_TYPE_IRJMP:
		r = rz_debug_reg_get(dbg, op.reg);
		if (!dbg->iob.read_at(dbg->iob.io, r, (ut8 *)&memval, 8)) {
			next[0] = op.addr + op.size;
		} else {
			next[0] = (dbg->bits <= RZ_SYS_BITS_32) ? memval.r32[0] : memval.r64;
		}
		br = 1;
		break;
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_MJMP:
		if (op.ireg) {
			r = rz_debug_reg_get(dbg, op.ireg);
		} else {
			r = 0;
		}
		if (!dbg->iob.read_at(dbg->iob.io, r * op.scale + op.disp, (ut8 *)&memval, 8)) {
			next[0] = op.addr + op.size;
		} else {
			next[0] = (dbg->bits <= RZ_SYS_BITS_32) ? memval.r32[0] : memval.r64;
		}
		br = 1;
		break;
	default:
		next[0] = op.addr + op.size;
		br = 1;
		break;
	}

	const int align = rz_analysis_archinfo(dbg->analysis, RZ_ANALYSIS_ARCHINFO_ALIGN);
	for (i = 0; i < br; i++) {
		if (align > 1) {
			next[i] = next[i] - (next[i] % align);
		}
		RzBreakpointItem *bpi = rz_bp_add_sw(dbg->bp, next[i], dbg->bpsize, RZ_PERM_X);
		if (bpi) {
			bpi->swstep = true;
		}
	}

	ret = rz_debug_continue(dbg);

	for (i = 0; i < br; i++) {
		rz_bp_del(dbg->bp, next[i]);
	}

	return ret;
}

RZ_API int rz_debug_step_hard(RzDebug *dbg, RzBreakpointItem **pb) {
	RzDebugReasonType reason;

	dbg->reason.type = RZ_DEBUG_REASON_STEP;
	if (rz_debug_is_dead(dbg)) {
		return false;
	}

	/* only handle recoils when not already in recoil mode. */
	if (dbg->recoil_mode == RZ_DBG_RECOIL_NONE) {
		/* handle the stage-2 of breakpoints */
		if (!rz_debug_recoil(dbg, RZ_DBG_RECOIL_STEP)) {
			return false;
		}

		/* recoil already stepped once, so we don't step again. */
		if (dbg->recoil_mode == RZ_DBG_RECOIL_STEP) {
			dbg->recoil_mode = RZ_DBG_RECOIL_NONE;
			return true;
		}
	}

	if (!dbg->cur->step(dbg)) {
		return false;
	}

#if __linux__
	// Turn off continue_all_threads to make sure linux_dbg_wait
	// only waits for one target for a single-step or breakpoint trap
	bool prev_continue = dbg->continue_all_threads;
	dbg->continue_all_threads = false;
#endif
	reason = rz_debug_wait(dbg, pb);
#if __linux__
	dbg->continue_all_threads = prev_continue;
#endif

	if (reason == RZ_DEBUG_REASON_DEAD || rz_debug_is_dead(dbg)) {
		return false;
	}
	// Unset breakpoints before leaving
	if (reason != RZ_DEBUG_REASON_BREAKPOINT &&
		reason != RZ_DEBUG_REASON_COND &&
		reason != RZ_DEBUG_REASON_TRACEPOINT) {
		rz_bp_restore(dbg->bp, false);
	}
	/* TODO: handle better */
	if (reason == RZ_DEBUG_REASON_ERROR) {
		return false;
	}
	return true;
}

RZ_API int rz_debug_step(RzDebug *dbg, int steps) {
	RzBreakpointItem *bp = NULL;
	int ret, steps_taken = 0;

	/* who calls this without giving a positive number? */
	if (steps < 1) {
		steps = 1;
	}

	if (!dbg || !dbg->cur) {
		return steps_taken;
	}

	if (rz_debug_is_dead(dbg)) {
		return steps_taken;
	}

	dbg->reason.type = RZ_DEBUG_REASON_STEP;

	if (dbg->session) {
		if (dbg->session->cnum != dbg->session->maxcnum) {
			steps_taken = rz_debug_step_cnum(dbg, steps);
		}
	}

	for (; steps_taken < steps; steps_taken++) {
		if (dbg->session && dbg->recoil_mode == RZ_DBG_RECOIL_NONE) {
			dbg->session->cnum++;
			dbg->session->maxcnum++;
			dbg->session->bp = 0;
			if (!rz_debug_trace_ins_before(dbg)) {
				eprintf("trace_ins_before: failed\n");
			}
		}

		if (dbg->swstep) {
			ret = rz_debug_step_soft(dbg);
		} else {
			ret = rz_debug_step_hard(dbg, &bp);
		}
		if (!ret) {
			eprintf("Stepping failed!\n");
			return steps_taken;
		}

		if (dbg->session && dbg->recoil_mode == RZ_DBG_RECOIL_NONE) {
			if (!rz_debug_trace_ins_after(dbg)) {
				eprintf("trace_ins_after: failed\n");
			}
			dbg->session->reasontype = dbg->reason.type;
			dbg->session->bp = bp;
		}

		dbg->steps++;
		dbg->reason.type = RZ_DEBUG_REASON_STEP;
	}

	return steps_taken;
}

static bool isStepOverable(ut64 opType) {
	switch (opType & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_SWI:
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_RCALL:
		return true;
	}
	return false;
}

RZ_API int rz_debug_step_over(RzDebug *dbg, int steps) {
	RzAnalysisOp op;
	ut64 buf_pc, pc, ins_size;
	ut8 buf[DBG_BUF_SIZE];
	int steps_taken = 0;

	if (rz_debug_is_dead(dbg)) {
		return steps_taken;
	}

	if (steps < 1) {
		steps = 1;
	}

	if (dbg->cur && dbg->cur->step_over) {
		for (; steps_taken < steps; steps_taken++) {
			if (dbg->session && dbg->recoil_mode == RZ_DBG_RECOIL_NONE) {
				dbg->session->cnum++;
				dbg->session->maxcnum++;
				rz_debug_trace_ins_before(dbg);
			}
			if (!dbg->cur->step_over(dbg)) {
				return steps_taken;
			}
			if (dbg->session && dbg->recoil_mode == RZ_DBG_RECOIL_NONE) {
				rz_debug_trace_ins_after(dbg);
			}
		}
		return steps_taken;
	}

	if (!dbg->analysis || !dbg->reg) {
		return steps_taken;
	}

	// Initial refill
	buf_pc = rz_debug_reg_get(dbg, dbg->reg->name[RZ_REG_NAME_PC]);
	dbg->iob.read_at(dbg->iob.io, buf_pc, buf, sizeof(buf));

	for (; steps_taken < steps; steps_taken++) {
		pc = rz_debug_reg_get(dbg, dbg->reg->name[RZ_REG_NAME_PC]);
		// Try to keep the buffer full
		if (pc - buf_pc > sizeof(buf)) {
			buf_pc = pc;
			dbg->iob.read_at(dbg->iob.io, buf_pc, buf, sizeof(buf));
		}
		// Analyze the opcode
		if (!rz_analysis_op(dbg->analysis, &op, pc, buf + (pc - buf_pc), sizeof(buf) - (pc - buf_pc), RZ_ANALYSIS_OP_MASK_BASIC)) {
			eprintf("debug-step-over: Decode error at %" PFMT64x "\n", pc);
			return steps_taken;
		}
		if (op.fail == -1) {
			ins_size = pc + op.size;
		} else {
			// Use op.fail here instead of pc+op.size to enforce analysis backends to fill in this field
			ins_size = op.fail;
		}
		// Skip over all the subroutine calls
		if (isStepOverable(op.type)) {
			if (!rz_debug_continue_until(dbg, ins_size)) {
				eprintf("Could not step over call @ 0x%" PFMT64x "\n", pc);
				return steps_taken;
			}
		} else if ((op.prefix & (RZ_ANALYSIS_OP_PREFIX_REP | RZ_ANALYSIS_OP_PREFIX_REPNE | RZ_ANALYSIS_OP_PREFIX_LOCK))) {
			// eprintf ("REP: skip to next instruction...\n");
			if (!rz_debug_continue_until(dbg, ins_size)) {
				eprintf("step over failed over rep\n");
				return steps_taken;
			}
		} else {
			rz_debug_step(dbg, 1);
		}
	}

	return steps_taken;
}

RZ_API bool rz_debug_goto_cnum(RzDebug *dbg, ut32 cnum) {
	if (cnum > dbg->session->maxcnum) {
		eprintf("Error: out of cnum range\n");
		return false;
	}
	dbg->session->cnum = cnum;
	rz_debug_session_restore_reg_mem(dbg, cnum);

	return true;
}

RZ_API int rz_debug_step_back(RzDebug *dbg, int steps) {
	if (steps > dbg->session->cnum) {
		steps = dbg->session->cnum;
	}
	if (!rz_debug_goto_cnum(dbg, dbg->session->cnum - steps)) {
		return -1;
	}
	return steps;
}

RZ_API int rz_debug_step_cnum(RzDebug *dbg, int steps) {
	if (steps > dbg->session->maxcnum - dbg->session->cnum) {
		steps = dbg->session->maxcnum - dbg->session->cnum;
	}

	rz_debug_goto_cnum(dbg, dbg->session->cnum + steps);

	return steps;
}

RZ_API int rz_debug_continue_kill(RzDebug *dbg, int sig) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_NONE;
	int ret = 0;
	RzBreakpointItem *bp = NULL;

	if (!dbg) {
		return 0;
	}

	// If the debugger is not at the end of the changes
	// Go to the end or the next breakpoint in the changes
	if (dbg->session && dbg->session->cnum != dbg->session->maxcnum) {
		bool has_bp = false;
		RzRegItem *ripc = rz_reg_get(dbg->reg, dbg->reg->name[RZ_REG_NAME_PC], RZ_REG_TYPE_GPR);
		RzVector *vreg = ht_up_find(dbg->session->registers, ripc->offset | (ripc->arena << 16), NULL);
		RzDebugChangeReg *reg;
		rz_vector_foreach_prev(vreg, reg) {
			if (reg->cnum <= dbg->session->cnum) {
				continue;
			}
			has_bp = rz_bp_get_in(dbg->bp, reg->data, RZ_PERM_X) != NULL;
			if (has_bp) {
				eprintf("hit breakpoint at: 0x%" PFMT64x " cnum: %d\n", reg->data, reg->cnum);
				rz_debug_goto_cnum(dbg, reg->cnum);
				return dbg->tid;
			}
		}

		rz_debug_goto_cnum(dbg, dbg->session->maxcnum);
		return dbg->tid;
	}

repeat:
	if (rz_debug_is_dead(dbg)) {
		return 0;
	}
	if (dbg->session && dbg->trace_continue) {
		while (!rz_cons_is_breaked()) {
			if (rz_debug_step(dbg, 1) != 1) {
				break;
			}
			if (dbg->session->reasontype != RZ_DEBUG_REASON_STEP) {
				break;
			}
		}
		reason = dbg->session->reasontype;
		bp = dbg->session->bp;
	} else if (dbg->cur && dbg->cur->cont) {
		/* handle the stage-2 of breakpoints */
		if (!rz_debug_recoil(dbg, RZ_DBG_RECOIL_CONTINUE)) {
			return 0;
		}
		/* tell the inferior to go! */
		ret = dbg->cur->cont(dbg, dbg->pid, dbg->tid, sig);
		// XXX(jjd): why? //dbg->reason.signum = 0;
		reason = rz_debug_wait(dbg, &bp);
	} else {
		return 0;
	}

	if (dbg->corebind.core) {
		RzCore *core = (RzCore *)dbg->corebind.core;
		RzNum *num = core->num;
		if (reason == RZ_DEBUG_REASON_COND) {
			if (bp && bp->cond && dbg->corebind.cmd) {
				dbg->corebind.cmd(dbg->corebind.core, bp->cond);
			}
			if (num->value) {
				goto repeat;
			}
		}
	}
	if (reason == RZ_DEBUG_REASON_BREAKPOINT &&
		((bp && !bp->enabled) || (!bp && !rz_cons_is_breaked() && dbg->corebind.core && dbg->corebind.cfggeti(dbg->corebind.core, "dbg.bpsysign")))) {
		goto repeat;
	}

#if __linux__
	if (reason == RZ_DEBUG_REASON_NEW_PID && dbg->follow_child) {
#if DEBUGGER
		/// if the plugin is not compiled link fails, so better do runtime linking
		/// until this code gets fixed
		static bool (*linux_attach_new_process)(RzDebug * dbg, int pid) = NULL;
		if (!linux_attach_new_process) {
			linux_attach_new_process = rz_lib_dl_sym(NULL, "linux_attach_new_process");
		}
		if (linux_attach_new_process) {
			linux_attach_new_process(dbg, dbg->forked_pid);
		}
#endif
		goto repeat;
	}

	if (reason == RZ_DEBUG_REASON_NEW_TID) {
		ret = dbg->tid;
		if (!dbg->trace_clone) {
			goto repeat;
		}
	}

	if (reason == RZ_DEBUG_REASON_EXIT_TID) {
		goto repeat;
	}
#endif
	if (reason != RZ_DEBUG_REASON_DEAD) {
		ret = dbg->tid;
	}
#if __WINDOWS__
	if (reason == RZ_DEBUG_REASON_NEW_LIB ||
		reason == RZ_DEBUG_REASON_EXIT_LIB ||
		reason == RZ_DEBUG_REASON_NEW_TID ||
		reason == RZ_DEBUG_REASON_NONE ||
		reason == RZ_DEBUG_REASON_EXIT_TID) {
		goto repeat;
	}
#endif
	if (reason == RZ_DEBUG_REASON_EXIT_PID) {
#if __WINDOWS__
		dbg->pid = -1;
#elif __linux__
		rz_debug_bp_update(dbg);
		rz_bp_restore(dbg->bp, false); // (vdf) there has got to be a better way
#endif
	}

	/* if continuing killed the inferior, we won't be able to get
	 * the registers.. */
	if (reason == RZ_DEBUG_REASON_DEAD || rz_debug_is_dead(dbg)) {
		return 0;
	}

	/* if we hit a tracing breakpoint, we need to continue in
	 * whatever mode the user desired. */
	if (reason == RZ_DEBUG_REASON_TRACEPOINT) {
		rz_debug_step(dbg, 1);
		goto repeat;
	}

	/* choose the thread that was returned from the continue function */
	// XXX(jjd): there must be a cleaner way to do this...
	if (ret != dbg->tid) {
		rz_debug_select(dbg, dbg->pid, ret);
	}
	sig = 0; // clear continuation after signal if needed

	/* handle general signals here based on the return from the wait
	 * function */
	if (dbg->reason.signum != -1) {
		int what = rz_debug_signal_what(dbg, dbg->reason.signum);
		if (what & RZ_DBG_SIGNAL_CONT) {
			sig = dbg->reason.signum;
			eprintf("Continue into the signal %d handler\n", sig);
			goto repeat;
		} else if (what & RZ_DBG_SIGNAL_SKIP) {
			// skip signal. requires skipping one instruction
			ut8 buf[64];
			RzAnalysisOp op = { 0 };
			ut64 pc = rz_debug_reg_get(dbg, "PC");
			dbg->iob.read_at(dbg->iob.io, pc, buf, sizeof(buf));
			rz_analysis_op(dbg->analysis, &op, pc, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);
			if (op.size > 0) {
				const char *signame = rz_signal_to_string(dbg->reason.signum);
				rz_debug_reg_set(dbg, "PC", pc + op.size);
				eprintf("Skip signal %d handler %s\n",
					dbg->reason.signum, signame);
				goto repeat;
			} else {
				ut64 pc = rz_debug_reg_get(dbg, "PC");
				eprintf("Stalled with an exception at 0x%08" PFMT64x "\n", pc);
			}
		}
	}
#if __WINDOWS__
	rz_cons_break_pop();
#endif

	// Unset breakpoints before leaving
	if (reason != RZ_DEBUG_REASON_BREAKPOINT) {
		rz_bp_restore(dbg->bp, false);
	}

	// Add a checkpoint at stops
	if (dbg->session && !dbg->trace_continue) {
		dbg->session->cnum++;
		dbg->session->maxcnum++;
		rz_debug_add_checkpoint(dbg);
	}

	return ret;
}

RZ_API int rz_debug_continue(RzDebug *dbg) {
	return rz_debug_continue_kill(dbg, 0); // dbg->reason.signum);
}

#if __WINDOWS__
RZ_API int rz_debug_continue_pass_exception(RzDebug *dbg) {
	return rz_debug_continue_kill(dbg, DBG_EXCEPTION_NOT_HANDLED);
}
#endif

RZ_API int rz_debug_continue_until_nontraced(RzDebug *dbg) {
	eprintf("TODO\n");
	return false;
}

RZ_API int rz_debug_continue_until_optype(RzDebug *dbg, int type, int over) {
	int ret, n = 0;
	ut64 pc, buf_pc = 0;
	RzAnalysisOp op;
	ut8 buf[DBG_BUF_SIZE];

	if (rz_debug_is_dead(dbg)) {
		return false;
	}

	if (!dbg->analysis || !dbg->reg) {
		eprintf("Undefined pointer at dbg->analysis\n");
		return false;
	}

	rz_debug_step(dbg, 1);
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false);

	// Initial refill
	buf_pc = rz_debug_reg_get(dbg, dbg->reg->name[RZ_REG_NAME_PC]);
	dbg->iob.read_at(dbg->iob.io, buf_pc, buf, sizeof(buf));

	// step first, we don't want to check current optype
	for (;;) {
		if (!rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false)) {
			break;
		}

		pc = rz_debug_reg_get(dbg, dbg->reg->name[RZ_REG_NAME_PC]);
		// Try to keep the buffer full
		if (pc - buf_pc > sizeof(buf)) {
			buf_pc = pc;
			dbg->iob.read_at(dbg->iob.io, buf_pc, buf, sizeof(buf));
		}
		// Analyze the opcode
		if (!rz_analysis_op(dbg->analysis, &op, pc, buf + (pc - buf_pc), sizeof(buf) - (pc - buf_pc), RZ_ANALYSIS_OP_MASK_BASIC)) {
			eprintf("Decode error at %" PFMT64x "\n", pc);
			return false;
		}
		if (op.type == type) {
			break;
		}
		// Step over and repeat
		ret = over
			? rz_debug_step_over(dbg, 1)
			: rz_debug_step(dbg, 1);

		if (!ret) {
			eprintf("rz_debug_step: failed\n");
			break;
		}
		n++;
	}

	return n;
}

static int rz_debug_continue_until_internal(RzDebug *dbg, ut64 addr, bool block) {
	if (rz_debug_is_dead(dbg)) {
		return false;
	}
	// Check if there was another breakpoint set at addr
	bool has_bp = rz_bp_get_in(dbg->bp, addr, RZ_PERM_X) != NULL;
	if (!has_bp) {
		rz_bp_add_sw(dbg->bp, addr, dbg->bpsize, RZ_PERM_X);
	}

	// Continue until the bp is reached
	dbg->reason.type = 0;
	for (;;) {
		if (rz_debug_is_dead(dbg) || dbg->reason.type) {
			break;
		}
		ut64 pc = rz_debug_reg_get(dbg, dbg->reg->name[RZ_REG_NAME_PC]);
		if (pc == addr) {
			break;
		}
		if (block && rz_bp_get_at(dbg->bp, pc)) {
			break;
		}
		rz_debug_continue(dbg);
	}
	// Clean up if needed
	if (!has_bp) {
		rz_bp_del(dbg->bp, addr);
	}
	return true;
}

RZ_API int rz_debug_continue_until(RzDebug *dbg, ut64 addr) {
	return rz_debug_continue_until_internal(dbg, addr, true);
}

RZ_API int rz_debug_continue_until_nonblock(RzDebug *dbg, ut64 addr) {
	return rz_debug_continue_until_internal(dbg, addr, false);
}

RZ_API bool rz_debug_continue_back(RzDebug *dbg) {
	int cnum;
	bool has_bp = false;

	RzRegItem *ripc = rz_reg_get(dbg->reg, dbg->reg->name[RZ_REG_NAME_PC], RZ_REG_TYPE_GPR);
	RzVector *vreg = ht_up_find(dbg->session->registers, ripc->offset | (ripc->arena << 16), NULL);
	if (!vreg) {
		eprintf("Error: cannot find PC change vector");
		return false;
	}
	RzDebugChangeReg *reg;
	rz_vector_foreach_prev(vreg, reg) {
		if (reg->cnum >= dbg->session->cnum) {
			continue;
		}
		has_bp = rz_bp_get_in(dbg->bp, reg->data, RZ_PERM_X) != NULL;
		if (has_bp) {
			cnum = reg->cnum;
			eprintf("hit breakpoint at: 0x%" PFMT64x " cnum: %d\n", reg->data, reg->cnum);
			break;
		}
	}

	if (has_bp) {
		rz_debug_goto_cnum(dbg, cnum);
	} else {
		if (dbg->session->maxcnum > 0) {
			rz_debug_goto_cnum(dbg, 0);
		}
	}

	return true;
}

static int show_syscall(RzDebug *dbg, const char *sysreg) {
	const char *sysname;
	char regname[32];
	int reg, i, args;
	RzSyscallItem *si;
	reg = (int)rz_debug_reg_get(dbg, sysreg);
	si = rz_syscall_get(dbg->analysis->syscall, reg, -1);
	if (si) {
		sysname = si->name ? si->name : "unknown";
		args = si->args;
	} else {
		sysname = "unknown";
		args = 3;
	}
	eprintf("--> %s 0x%08" PFMT64x " syscall %d %s (", sysreg,
		rz_debug_reg_get(dbg, "PC"), reg, sysname);
	for (i = 0; i < args; i++) {
		ut64 val;
		snprintf(regname, sizeof(regname) - 1, "A%d", i);
		val = rz_debug_reg_get(dbg, regname);
		if (((st64)val < 0) && ((st64)val > -0xffff)) {
			eprintf("%" PFMT64d "%s", val, (i + 1 == args) ? "" : " ");
		} else {
			eprintf("0x%" PFMT64x "%s", val, (i + 1 == args) ? "" : " ");
		}
	}
	eprintf(")\n");
	rz_syscall_item_free(si);
	return reg;
}

RZ_API int rz_debug_continue_syscalls(RzDebug *dbg, int *sc, int n_sc) {
	int i, reg, ret = false;
	if (!dbg || !dbg->cur || rz_debug_is_dead(dbg)) {
		return false;
	}
	if (!dbg->cur->contsc) {
		/* user-level syscall tracing */
		rz_debug_continue_until_optype(dbg, RZ_ANALYSIS_OP_TYPE_SWI, 0);
		return show_syscall(dbg, "A0");
	}

	if (!rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false)) {
		eprintf("--> cannot read registers\n");
		return -1;
	}

	if (!rz_reg_get_by_role(dbg->reg, RZ_REG_NAME_SN)) {
		eprintf("Cannot find 'sn' register for current arch-os.\n");
		return -1;
	}
	for (;;) {
		RzDebugReasonType reason;

		if (rz_cons_singleton()->context->breaked) {
			break;
		}
#if __linux__
		// step is needed to avoid dupped contsc results
		/* XXX(jjd): actually one stop is before the syscall, the other is
		 * after.  this allows you to inspect the arguments before and the
		 * return value after... */
		rz_debug_step(dbg, 1);
#endif
		dbg->cur->contsc(dbg, dbg->pid, 0); // TODO handle return value
		// wait until continuation
		reason = rz_debug_wait(dbg, NULL);
		if (reason == RZ_DEBUG_REASON_DEAD || rz_debug_is_dead(dbg)) {
			break;
		}
#if 0
		if (reason != RZ_DEBUG_REASON_STEP) {
			eprintf ("astep\n");
			break;
		}
#endif
		if (!rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false)) {
			eprintf("--> cannot sync regs, process is probably dead\n");
			return -1;
		}
		reg = show_syscall(dbg, "SN");

		if (dbg->corebind.core && dbg->corebind.syshit) {
			dbg->corebind.syshit(dbg->corebind.core);
		}

		if (n_sc == -1) {
			continue;
		}
		if (n_sc == 0) {
			break;
		}
		for (i = 0; i < n_sc; i++) {
			if (sc[i] == reg) {
				return reg;
			}
		}
		// TODO: must use rz_core_cmd(as)..import code from rcore
	}
	return ret;
}

RZ_API int rz_debug_continue_syscall(RzDebug *dbg, int sc) {
	return rz_debug_continue_syscalls(dbg, &sc, 1);
}

// TODO: remove from here? this is code injection!
RZ_API int rz_debug_syscall(RzDebug *dbg, int num) {
	bool ret = true;
	if (dbg->cur->contsc) {
		ret = dbg->cur->contsc(dbg, dbg->pid, num);
	}
	eprintf("TODO: show syscall information\n");
	/* rz_testc task? ala inject? */
	return (int)ret;
}

/// check whether rz_debug_kill() will not definitely fail (for example because kill is unimplemented by the plugin)
RZ_API bool rz_debug_can_kill(RzDebug *dbg) {
	return !rz_debug_is_dead(dbg) && dbg->cur && dbg->cur->kill;
}

RZ_API int rz_debug_kill(RzDebug *dbg, int pid, int tid, int sig) {
	if (rz_debug_is_dead(dbg)) {
		return false;
	}
	if (dbg->cur && dbg->cur->kill) {
		if (pid > 0) {
			return dbg->cur->kill(dbg, pid, tid, sig);
		}
		return -1;
	}
	eprintf("Backend does not implement kill()\n");
	return false;
}

RZ_API RzList *rz_debug_frames(RzDebug *dbg, ut64 at) {
	if (dbg && dbg->cur && dbg->cur->frames) {
		return dbg->cur->frames(dbg, at);
	}
	return NULL;
}

/* TODO: Implement fork and clone */
RZ_API int rz_debug_child_fork(RzDebug *dbg) {
	// if (dbg && dbg->cur && dbg->cur->frames)
	// return dbg->cur->frames (dbg);
	return 0;
}

RZ_API int rz_debug_child_clone(RzDebug *dbg) {
	// if (dbg && dbg->cur && dbg->cur->frames)
	// return dbg->cur->frames (dbg);
	return 0;
}

RZ_API bool rz_debug_is_dead(RzDebug *dbg) {
	if (!dbg->cur) {
		return false;
	}
	// workaround for debug.io.. should be generic
	if (!strcmp(dbg->cur->name, "io")) {
		return false;
	}
	bool is_dead = (dbg->pid == -1 && strncmp(dbg->cur->name, "gdb", 3)) || (dbg->reason.type == RZ_DEBUG_REASON_DEAD);
	if (dbg->pid > 0 && dbg->cur && dbg->cur->kill) {
		is_dead = !dbg->cur->kill(dbg, dbg->pid, false, 0);
	}
#if 0
	if (!is_dead && dbg->cur && dbg->cur->kill) {
		is_dead = !dbg->cur->kill (dbg, dbg->pid, false, 0);
	}
#endif
	if (is_dead) {
		dbg->reason.type = RZ_DEBUG_REASON_DEAD;
	}
	return is_dead;
}

RZ_API int rz_debug_map_protect(RzDebug *dbg, ut64 addr, int size, int perms) {
	if (dbg && dbg->cur && dbg->cur->map_protect) {
		return dbg->cur->map_protect(dbg, addr, size, perms);
	}
	return false;
}

RZ_API void rz_debug_drx_list(RzDebug *dbg) {
	if (dbg && dbg->cur && dbg->cur->drx) {
		dbg->cur->drx(dbg, 0, 0, 0, 0, 0, DRX_API_LIST);
	}
}

RZ_API int rz_debug_drx_set(RzDebug *dbg, int idx, ut64 addr, int len, int rwx, int g) {
	if (dbg && dbg->cur && dbg->cur->drx) {
		return dbg->cur->drx(dbg, idx, addr, len, rwx, g, DRX_API_SET_BP);
	}
	return false;
}

RZ_API int rz_debug_drx_unset(RzDebug *dbg, int idx) {
	if (dbg && dbg->cur && dbg->cur->drx) {
		return dbg->cur->drx(dbg, idx, 0, -1, 0, 0, DRX_API_REMOVE_BP);
	}
	return false;
}

RZ_API ut64 rz_debug_get_baddr(RzDebug *dbg, const char *file) {
	if (!dbg || !dbg->iob.io || !dbg->iob.io->desc) {
		return 0LL;
	}
	if (!strcmp(dbg->iob.io->desc->plugin->name, "gdb")) { // this is very bad
		// Tell gdb that we want baddr, not full mem map
		dbg->iob.system(dbg->iob.io, "baddr");
	}
	int pid = rz_io_desc_get_pid(dbg->iob.io->desc);
	int tid = rz_io_desc_get_tid(dbg->iob.io->desc);
	if (pid < 0 || tid < 0) {
		return 0LL;
	}
	if (rz_debug_attach(dbg, pid) == -1) {
		return 0LL;
	}
#if __WINDOWS__
	ut64 base;
	bool ret = rz_io_desc_get_base(dbg->iob.io->desc, &base);
	if (ret) {
		return base;
	}
#endif
	RzListIter *iter;
	RzDebugMap *map;
	rz_debug_select(dbg, pid, tid);
	rz_debug_map_sync(dbg);
	char *abspath = rz_sys_pid_to_path(pid);
#if !__WINDOWS__
	if (!abspath) {
		abspath = rz_file_abspath(file);
	}
#endif
	if (!abspath) {
		abspath = strdup(file);
	}
	if (abspath) {
		rz_list_foreach (dbg->maps, iter, map) {
			if (!strcmp(abspath, map->name)) {
				free(abspath);
				return map->addr;
			}
		}
		free(abspath);
	}
	// fallback resolution (osx/w32?)
	// we assume maps to be loaded in order, so lower addresses come first
	rz_list_foreach (dbg->maps, iter, map) {
		if (map->perm == 5) { // r-x
			return map->addr;
		}
	}
	return 0LL;
}

RZ_API void rz_debug_bp_rebase(RzDebug *dbg, ut64 old_base, ut64 new_base) {
	RzBreakpointItem *bp;
	RzListIter *iter;
	ut64 diff = new_base - old_base;
	// update bp->baddr
	dbg->bp->baddr = new_base;

	// update bp's address
	rz_list_foreach (dbg->bp->bps, iter, bp) {
		bp->addr += diff;
		bp->delta = bp->addr - dbg->bp->baddr;
	}
}
