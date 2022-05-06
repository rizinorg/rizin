// SPDX-FileCopyrightText: 2014-2017 LemonBoy
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include <winkd.h>
#include <kd.h>
#include "common_winkd.h"

static KdCtx *kdctx = NULL;

static int rz_debug_winkd_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	int ret = winkd_read_reg(kdctx, buf, size);
	if (!ret || size != ret) {
		return -1;
	}
	rz_reg_read_regs(dbg->reg, buf, ret);
	// Report as if no register has been written as we've already updated the arena here
	return 0;
}

static int rz_debug_winkd_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	if (!dbg->reg) {
		return false;
	}
	int arena_size;
	ut8 *arena = rz_reg_get_bytes(dbg->reg, RZ_REG_TYPE_ANY, &arena_size);
	if (!arena) {
		eprintf("Could not retrieve the register arena!\n");
		return false;
	}
	int ret = winkd_write_reg(kdctx, arena, arena_size);
	free(arena);
	return ret;
}

static int rz_debug_winkd_continue(RzDebug *dbg, int pid, int tid, int sig) {
	return winkd_continue(kdctx);
}

static RzDebugReasonType rz_debug_winkd_wait(RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;
	kd_packet_t *pkt = NULL;
	kd_stc_64 *stc;
	winkd_lock_enter(kdctx);
	for (;;) {
		void *bed = rz_cons_sleep_begin();
		int ret = winkd_wait_packet(kdctx, KD_PACKET_TYPE_STATE_CHANGE64, &pkt);
		rz_cons_sleep_end(bed);
		if (ret != KD_E_OK || !pkt) {
			reason = RZ_DEBUG_REASON_ERROR;
			break;
		}
		stc = (kd_stc_64 *)pkt->data;
		dbg->reason.addr = stc->pc;
		dbg->reason.tid = stc->kthread;
		dbg->reason.signum = stc->state;
		winkd_set_cpu(kdctx, stc->cpu);
		if (stc->state == DbgKdExceptionStateChange) {
			dbg->reason.type = RZ_DEBUG_REASON_INT;
			reason = RZ_DEBUG_REASON_INT;
			break;
		} else if (stc->state == DbgKdLoadSymbolsStateChange) {
			dbg->reason.type = RZ_DEBUG_REASON_NEW_LIB;
			reason = RZ_DEBUG_REASON_NEW_LIB;
			break;
		}
		RZ_FREE(pkt);
	}
	winkd_lock_leave(kdctx);
	free(pkt);
	return reason;
}

static int rz_debug_winkd_attach(RzDebug *dbg, int pid) {
	RzIODesc *desc = dbg->iob.io->desc;

	if (!desc || !desc->plugin || !desc->plugin->name || !desc->data) {
		return false;
	}
	if (strncmp(desc->plugin->name, "winkd", 6)) {
		return false;
	}
	if (dbg->arch && strcmp(dbg->arch, "x86")) {
		return false;
	}
	kdctx = (KdCtx *)desc->data;

	// Handshake
	int ret = winkd_sync(kdctx);
	if (ret < 0) {
		RZ_LOG_ERROR("Could not connect to winkd\n");
		return false;
	} else if (!ret) {
		RZ_LOG_VERBOSE("Already synced\n");
		return true;
	}
	if (!winkd_read_ver(kdctx)) {
		return false;
	}

	// Load PDB for kernel
	RzList *modules = winkd_list_modules(&kdctx->windctx);
	RzListIter *it;
	WindModule *m, *mod = NULL;
	rz_list_foreach (modules, it, m) {
		RZ_LOG_DEBUG("%" PFMT64x " %s\n", m->addr, m->name);
		if (rz_str_endswith(m->name, "\\ntoskrnl.exe")) {
			mod = m;
			break;
		}
	}
	if (!mod) {
		RZ_LOG_ERROR("Failed to find ntoskrnl.exe module\n");
		rz_list_free(modules);
		return false;
	}
	char *exepath, *pdbpath;
	if (!winkd_download_module_and_pdb(mod,
		    dbg->corebind.cfgGet(dbg->corebind.core, "pdb.server"),
		    dbg->corebind.cfgGet(dbg->corebind.core, "pdb.symstore"),
		    &exepath, &pdbpath)) {
		RZ_LOG_ERROR("Failed to download module and pdb\n");
		rz_list_free(modules);
		return false;
	}
	dbg->corebind.cmdf(dbg->corebind.core, "e bin.baddr=0x%" PFMT64x "", mod->addr, pdbpath);
	dbg->corebind.cmdf(dbg->corebind.core, "idp %s", pdbpath);
	rz_list_free(modules);

	if (!kdctx->windctx.profile) {
		RZ_LOG_INFO("Trying to build profile dinamically by using the ntoskrnl.exe's PDB\n");
		winkd_build_profile(&kdctx->windctx, dbg->analysis->typedb);
	}
	dbg->bits = winkd_get_bits(&kdctx->windctx);
	// Make rz_debug_is_dead happy
	dbg->pid = 0;
	return true;
}

static int rz_debug_winkd_detach(RzDebug *dbg, int pid) {
	eprintf("Detaching...\n");
	kdctx->syncd = 0;
	return true;
}

static char *rz_debug_winkd_reg_profile(RzDebug *dbg) {
	if (!dbg) {
		return NULL;
	}
	if (dbg->arch && strcmp(dbg->arch, "x86")) {
		return NULL;
	}
	rz_debug_winkd_attach(dbg, 0);
	if (dbg->bits == RZ_SYS_BITS_32) {
#include "native/reg/windows-x86.h"
	} else if (dbg->bits == RZ_SYS_BITS_64) {
#include "native/reg/windows-x64.h"
	}
	return NULL;
}

static int rz_debug_winkd_breakpoint(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
	int *tag;
	if (!b) {
		return false;
	}
	// Use a 32 bit word here to keep this compatible with 32 bit hosts
	if (!b->data) {
		b->data = RZ_NEWS0(char, 4);
		if (!b->data) {
			return 0;
		}
	}
	tag = (int *)b->data;
	return winkd_bkpt(kdctx, b->addr, set, b->hw, tag);
}

static bool rz_debug_winkd_init(RzDebug *dbg, void **user) {
	return true;
}

static RzList *rz_debug_winkd_pids(RzDebug *dbg, int pid) {
	if (!kdctx || !kdctx->desc || !kdctx->syncd) {
		return NULL;
	}

	RzList *ret = rz_list_newf((RzListFree)rz_debug_pid_free);
	if (!ret) {
		return NULL;
	}

	RzList *pids = kdctx->plist_cache ? kdctx->plist_cache : winkd_list_process(&kdctx->windctx);
	if (!pids) {
		rz_list_free(ret);
		return NULL;
	}
	RzListIter *it;
	WindProc *p;
	rz_list_foreach (pids, it, p) {
		RzDebugPid *newpid = RZ_NEW0(RzDebugPid);
		if (!newpid) {
			rz_list_free(ret);
			rz_list_free(pids);
			return NULL;
		}
		newpid->path = strdup(p->name);
		newpid->pid = p->uniqueid;
		newpid->status = 's';
		newpid->runnable = true;
		rz_list_append(ret, newpid);
	}
	kdctx->plist_cache = pids;
	return ret;
}

static int rz_debug_winkd_select(RzDebug *dbg, int pid, int tid) {
	ut32 old = winkd_get_target(&kdctx->windctx);
	if (pid != old) {
		rz_list_free(kdctx->tlist_cache);
		kdctx->tlist_cache = NULL;
	}
	int ret = winkd_set_target(&kdctx->windctx, pid, tid);
	if (!ret) {
		return false;
	}
	ut64 base = winkd_get_target_base(&kdctx->windctx);
	if (!base) {
		winkd_set_target(&kdctx->windctx, old, tid);
		return false;
	}
	eprintf("Process base is 0x%" PFMT64x "\n", base);
	return true;
}

static RzList *rz_debug_winkd_threads(RzDebug *dbg, int pid) {
	if (!kdctx || !kdctx->desc || !kdctx->syncd) {
		return NULL;
	}

	RzList *ret = rz_list_newf(free);
	if (!ret) {
		return NULL;
	}
	RzList *threads = kdctx->tlist_cache ? kdctx->tlist_cache : winkd_list_threads(&kdctx->windctx);
	if (!threads) {
		rz_list_free(ret);
		return NULL;
	}
	RzListIter *it;
	WindThread *t;
	rz_list_foreach (threads, it, t) {
		RzDebugPid *newpid = RZ_NEW0(RzDebugPid);
		if (!newpid) {
			rz_list_free(ret);
			rz_list_free(threads);
			return NULL;
		}
		newpid->pid = t->uniqueid;
		newpid->status = t->status;
		newpid->runnable = t->runnable;
		rz_list_append(ret, newpid);
	}
	kdctx->tlist_cache = threads;
	return ret;
}

static RzList *rz_debug_winkd_modules(RzDebug *dbg) {
	if (!kdctx || !kdctx->desc || !kdctx->syncd) {
		return NULL;
	}
	RzList *ret = rz_list_newf((RzListFree)rz_debug_map_free);
	if (!ret) {
		return NULL;
	}
	RzList *modules = winkd_list_modules(&kdctx->windctx);
	RzListIter *it;
	WindModule *m;
	rz_list_foreach (modules, it, m) {
		RzDebugMap *mod = RZ_NEW0(RzDebugMap);
		if (!mod) {
			rz_list_free(modules);
			rz_list_free(ret);
			return NULL;
		}
		RZ_PTR_MOVE(mod->file, m->name);
		mod->size = m->size;
		mod->addr = m->addr;
		mod->addr_end = m->addr + m->size;
		rz_list_append(ret, mod);
	}
	rz_list_free(modules);
	return ret;
}

RzDebugPlugin rz_debug_plugin_winkd = {
	.name = "winkd",
	.license = "LGPL3",
	.arch = "x86",
	.bits = RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.init = &rz_debug_winkd_init,
	// TODO: .step = &rz_debug_winkd_step,
	.cont = &rz_debug_winkd_continue,
	.attach = &rz_debug_winkd_attach,
	.detach = &rz_debug_winkd_detach,
	.pids = &rz_debug_winkd_pids,
	.wait = &rz_debug_winkd_wait,
	.select = &rz_debug_winkd_select,
	.breakpoint = rz_debug_winkd_breakpoint,
	.reg_read = &rz_debug_winkd_reg_read,
	.reg_write = &rz_debug_winkd_reg_write,
	.reg_profile = &rz_debug_winkd_reg_profile,
	.threads = &rz_debug_winkd_threads,
	.modules_get = &rz_debug_winkd_modules
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_DBG,
	.data = &rz_debug_plugin_winkd,
	.version = RZ_VERSION
};
#endif
