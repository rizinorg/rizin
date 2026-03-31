// SPDX-FileCopyrightText: 2014-2017 LemonBoy
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include <winkd.h>
#include <kd.h>
#include "common_winkd.h"
#include "common_windows.h"
#include "mdmp_windefs.h"

#define O_(n) kdctx->windctx.profile->f[n]

static KdCtx *kdctx = NULL;

static int rz_debug_winkd_reg_read(RZ_BORROW RZ_NONNULL RzDebug *dbg, int type, ut8 *buf, int size) {
	int ret = winkd_read_reg(kdctx, buf, size);
	if (!ret) {
		return -1;
	}
	return ret;
}

static int rz_debug_winkd_reg_write(RZ_BORROW RZ_NONNULL RzDebug *dbg, int type, const ut8 *buf, int size) {
	if (!dbg->reg) {
		return false;
	}
	ut32 flags;
	if (kdctx->windctx.is_arm) {
		if (kdctx->windctx.is_64bit) {
			const struct context_type_arm64 *ctx = (void *)buf;
			flags = rz_read_le32(&ctx->ContextFlags);
		} else {
			const struct context_type_arm *ctx = (void *)buf;
			flags = rz_read_le32(&ctx->context_flags);
		}
	} else {
		if (kdctx->windctx.is_64bit) {
			const struct context_type_amd64 *ctx = (void *)buf;
			flags = rz_read_le32(&ctx->context_flags);
		} else {
			const struct context_type_i386 *ctx = (void *)buf;
			flags = rz_read_le32(&ctx->context_flags);
		}
	}
	return winkd_write_reg(kdctx, flags, buf, size);
}

static int rz_debug_winkd_continue(RZ_BORROW RZ_NONNULL RzDebug *dbg, int pid, int tid, int sig) {
	return winkd_continue(kdctx, !sig);
}

static void get_current_process_and_thread(RZ_BORROW RZ_NONNULL RzDebug *dbg, ut64 thread_address) {
	if (!O_(ET_ApcProcess)) {
		return;
	}
	WindThread *thread = winkd_get_thread_at(&kdctx->windctx, thread_address);
	if (!thread) {
		return;
	}
	// Read the process pointer from the current thread
	const ut64 address_process = winkd_read_ptr_at(&kdctx->windctx, kdctx->windctx.read_at_kernel_virtual, thread->ethread + O_(ET_ApcProcess));
	if (address_process && address_process != kdctx->windctx.target.eprocess) {
		// Then read the process
		WindProc *proc = winkd_get_process_at(&kdctx->windctx, address_process);
		if (proc) {
			kdctx->windctx.target = *proc;
			dbg->pid = kdctx->windctx.target.uniqueid;
			free(proc);
		}
	}

	kdctx->windctx.target_thread = *thread;
	dbg->tid = kdctx->windctx.target_thread.uniqueid;
	free(thread);
}

static RzDebugReasonType rz_debug_winkd_wait(RZ_BORROW RZ_NONNULL RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;
	kd_packet_t *pkt = NULL;
	kd_stc_64 *stc;
	if (!winkd_lock_enter(kdctx)) {
		return RZ_DEBUG_REASON_UNKNOWN;
	}
	for (;;) {
		void *bed = rz_cons_sleep_begin();
		int ret;
		do {
			ret = winkd_wait_packet(kdctx, KD_PACKET_TYPE_STATE_CHANGE64, &pkt);
		} while (ret == KD_E_BREAK || ret == KD_E_MALFORMED);
		rz_cons_sleep_end(bed);
		if (ret != KD_E_OK || !pkt) {
			reason = RZ_DEBUG_REASON_ERROR;
			break;
		}
		stc = (kd_stc_64 *)pkt->data;
		dbg->reason.addr = stc->pc;
		dbg->reason.tid = stc->kthread;
		dbg->reason.signum = stc->state;
		if (stc->kthread && stc->kthread != kdctx->windctx.target_thread.ethread) {
			get_current_process_and_thread(dbg, stc->kthread);
		}
		winkd_set_cpu(kdctx, stc->cpu);
		if (stc->state == DbgKdExceptionStateChange) {
			windows_print_exception_event(kdctx->windctx.target.uniqueid, kdctx->windctx.target_thread.uniqueid, stc->exception.code, stc->exception.flags);
			dbg->reason.type = windows_exception_to_reason(stc->exception.code);
			dbg->reason.addr = stc->exception.ex_addr;
			dbg->reason.signum = stc->exception.code;
			reason = dbg->reason.type;
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

static bool get_module_timestamp(ut64 addr, ut32 *timestamp, ut32 *sizeofimage) {
	ut8 mz[2];
	if (kdctx->windctx.read_at_kernel_virtual(kdctx->windctx.user, addr, mz, 2) != 2) {
		return false;
	}
	if (memcmp(mz, "MZ", 2)) {
		return false;
	}
	ut8 pe_off_buf[2];
	if (kdctx->windctx.read_at_kernel_virtual(kdctx->windctx.user, addr + 0x3c, pe_off_buf, 2) != 2) {
		return false;
	}
	const ut16 pe_off = rz_read_le16(pe_off_buf);
	ut8 pe[2];
	if (kdctx->windctx.read_at_kernel_virtual(kdctx->windctx.user, addr + pe_off, pe, 2) != 2) {
		return false;
	}
	if (memcmp(pe, "PE", 2)) {
		return false;
	}
	ut8 ts[4];
	if (kdctx->windctx.read_at_kernel_virtual(kdctx->windctx.user, addr + pe_off + 8, ts, 4) != 4) {
		return false;
	}
	ut8 sz[4];
	if (kdctx->windctx.read_at_kernel_virtual(kdctx->windctx.user, addr + pe_off + 0x50, sz, 4) != 4) {
		return false;
	};
	*timestamp = rz_read_le32(ts);
	*sizeofimage = rz_read_le32(sz);
	return true;
}

static int rz_debug_winkd_attach(RZ_BORROW RZ_NONNULL RzDebug *dbg, int pid) {
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
	WindModule *mod = &kdctx->kernel_module;
	RzList *modules = NULL;
	if (!mod->timestamp || !mod->size) {
		if (!get_module_timestamp(kdctx->kernel_module.addr, &kdctx->kernel_module.timestamp, &kdctx->kernel_module.size)) {
			RZ_LOG_ERROR("Could not get timestamp for kernel module\n");
			return false;
		}
	}
	if (!mod->name) {
		mod->name = rz_str_dup("\\ntoskrnl.exe");
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
	dbg->corebind.cfgSetI(dbg->corebind.core, "bin.baddr", mod->addr);
	// TODO: Convert to API call
	dbg->corebind.cmdf(dbg->corebind.core, "idp \"%s\"", pdbpath);
	rz_list_free(modules);

	if (!kdctx->windctx.profile) {
		RZ_LOG_INFO("Trying to build profile dinamically by using the ntoskrnl.exe's PDB\n");
		winkd_build_profile(&kdctx->windctx, dbg->analysis->typedb);
	}
	dbg->bits = winkd_get_bits(&kdctx->windctx);
	// Make rz_debug_is_dead happy
	dbg->pid = 0;
	ut8 buf[2];
	// Get structure offset of current process pointer inside a KTHREAD from the kd debugger data
	if (winkd_read_at(kdctx, kdctx->windctx.KdDebuggerDataBlock + K_OffsetKThreadApcProcess, buf, 2) == 2) {
		O_(ET_ApcProcess) = rz_read_le16(buf);
		get_current_process_and_thread(dbg, kdctx->windctx.target_thread.ethread);
	}

	// Mapping from the vad is unreliable so just tell core that its ok to put breakpoints everywhere
	dbg->corebind.cfgSetI(dbg->corebind.core, "dbg.bpinmaps", 0);
	return true;
}

static int rz_debug_winkd_detach(RZ_BORROW RZ_NONNULL RzDebug *dbg, int pid) {
	eprintf("Detaching...\n");
	kdctx->syncd = 0;
	return true;
}

static char *rz_debug_winkd_reg_profile(RZ_BORROW RZ_NONNULL RzDebug *dbg) {
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

static int rz_debug_winkd_breakpoint(RZ_BORROW RZ_NONNULL RzBreakpoint *bp, RZ_BORROW RZ_NULLABLE RzBreakpointItem *b, bool set) {
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

static bool rz_debug_winkd_init(RZ_BORROW RZ_NONNULL RzDebug *dbg, void **user) {
	return true;
}

static RzList /*<RzDebugPid *>*/ *rz_debug_winkd_pids(RZ_BORROW RZ_NONNULL RzDebug *dbg, int pid) {
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
		newpid->path = rz_str_dup(p->name);
		newpid->pid = p->uniqueid;
		newpid->status = 's';
		newpid->runnable = true;
		rz_list_append(ret, newpid);
	}
	kdctx->plist_cache = pids;
	return ret;
}

static int rz_debug_winkd_select(RZ_BORROW RZ_NONNULL RzDebug *dbg, int pid, int tid) {
	ut32 old = winkd_get_target(&kdctx->windctx);
	ut32 old_tid = winkd_get_target_thread(&kdctx->windctx);
	if (pid != old || tid != old_tid) {
		kdctx->context_cache_valid = false;
		if (pid != old) {
			rz_list_free(kdctx->tlist_cache);
			kdctx->tlist_cache = NULL;
		}
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

static RzList /*<RzDebugPid *>*/ *rz_debug_winkd_threads(RZ_BORROW RZ_NONNULL RzDebug *dbg, int pid) {
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

static RzList /*<RzDebugMap *>*/ *rz_debug_winkd_modules(RZ_BORROW RZ_NONNULL RzDebug *dbg) {
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

#include "native/bt/windows-x64.c"
#include "native/bt/generic-all.c"

static RzList /*<RzDebugFrame *>*/ *rz_debug_winkd_frames(RZ_BORROW RZ_NONNULL RzDebug *dbg, ut64 at) {
	if (!kdctx || !kdctx->desc || !kdctx->syncd) {
		return NULL;
	}
	RzList *ret = NULL;
	if (!kdctx->windctx.is_arm && kdctx->windctx.is_64bit) {
		struct context_type_amd64 context = { 0 };
		backtrace_windows_x64(dbg, &ret, &context);
	} else {
		ret = backtrace_generic(dbg);
	}
	return ret;
}

static RzList /*<RzDebugMap *>*/ *rz_debug_winkd_maps(RZ_BORROW RZ_NONNULL RzDebug *dbg) {
	RzList *maps = winkd_list_maps(&kdctx->windctx);
	RzListIter *it;
	WindMap *m;
	RzList *ret = rz_list_newf((RzListFree)rz_debug_map_free);
	if (!ret) {
		rz_list_free(maps);
		return NULL;
	}
	rz_list_foreach (maps, it, m) {
		RzDebugMap *map = RZ_NEW0(RzDebugMap);
		if (!map) {
			rz_list_free(maps);
			rz_list_free(ret);
			return NULL;
		}
		if (m->file) {
			RZ_PTR_MOVE(map->file, m->file);
			map->name = rz_str_dup(rz_file_dos_basename(map->file));
		}
		map->size = m->end - m->start;
		map->addr = m->start;
		map->addr_end = m->end;
		map->perm = m->perm;
		rz_list_append(ret, map);
	}
	rz_list_free(maps);
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
	.modules_get = &rz_debug_winkd_modules,
	.map_get = &rz_debug_winkd_maps,
	.frames = &rz_debug_winkd_frames,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_DBG,
	.data = &rz_debug_plugin_winkd,
	.version = RZ_VERSION
};
#endif
