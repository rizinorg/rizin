// SPDX-FileCopyrightText: 2022 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_debug.h>
#include <dmp_specs.h>
#include <dmp64.h>
#include <pe_specs.h>
#include <winkd.h>
#include "common_winkd.h"

static bool rz_debug_dmp_init(RzDebug *dbg, void **user) {
	RzCore *core = dbg->corebind.core;
	RzIODesc *desc = core->io->desc;
	if (!desc) {
		return false;
	}
	if (strcmp(desc->plugin->name, "dmp")) {
		RZ_LOG_ERROR("Open a file with dmp:// to use the 'dmp' debug plugin\n");
		return false;
	}

	dbg->plugin_data = core->io->desc->data;
	DmpCtx *ctx = dbg->plugin_data;

	int ret = rz_hex_str2bin(core->bin->cur->o->regstate, NULL);
	ctx->context = malloc(ret);
	if (!ctx->context) {
		return false;
	}
	ctx->context_sz = ret;
	rz_hex_str2bin(core->bin->cur->o->regstate, ctx->context);

	ut32 MachineImageType = 0; // Windows Architecture (IMAGE_FILE_MACHINE)
	ut32 MinorVersion = 0; // Windows Version
	ut32 ServicePackBuild = 0;
	ut32 ProcessOffset = 0;
	ut32 ThreadOffset = 0;
	ut32 CallStackOffset = 0;
	ut32 NumberProcessors = 0;
	ctx->target = TARGET_BACKEND;
	dbg->corebind.cmd(dbg->corebind.core, "e io.va=0");
	RzBuffer *b = rz_buf_new_with_io(&dbg->iob);
	rz_buf_read_le64_at(b, rz_offsetof(dmp64_header, DirectoryTableBase), &ctx->kernelDirectoryTable);
	rz_buf_read_le64_at(b, rz_offsetof(dmp64_header, PsActiveProcessHead), &ctx->windctx.PsActiveProcessHead);
	rz_buf_read_le64_at(b, rz_offsetof(dmp64_header, PsLoadedModuleList), &ctx->windctx.PsLoadedModuleList);
	rz_buf_read_le64_at(b, rz_offsetof(dmp64_header, KdDebuggerDataBlock), &ctx->windctx.KdDebuggerDataBlock);
	rz_buf_read_le32_at(b, rz_offsetof(dmp64_header, NumberProcessors), &NumberProcessors);
	rz_buf_read_le32_at(b, rz_offsetof(dmp64_header, DumpType), &ctx->type);
	rz_buf_read_le32_at(b, rz_offsetof(dmp64_header, MachineImageType), &MachineImageType);
	rz_buf_read_le32_at(b, rz_offsetof(dmp64_header, MinorVersion), &MinorVersion);
	rz_buf_read_le32_at(b, sizeof(dmp64_header) + rz_offsetof(dmp64_triage, ServicePackBuild), &ServicePackBuild);
	rz_buf_read_le32_at(b, sizeof(dmp64_header) + rz_offsetof(dmp64_triage, ProcessOffset), &ProcessOffset);
	rz_buf_read_le32_at(b, sizeof(dmp64_header) + rz_offsetof(dmp64_triage, ThreadOffset), &ThreadOffset);
	rz_buf_read_le32_at(b, sizeof(dmp64_header) + rz_offsetof(dmp64_triage, CallStackOffset), &CallStackOffset);
	rz_buf_free(b);

	RzIOMap *map = rz_io_map_get(core->io, 0);
	if (map) {
		// Remove file mapping
		rz_io_map_del(core->io, map->id);
	}
	if (ctx->type == DMP_DUMPTYPE_TRIAGE) {
		dbg->corebind.cmd(dbg->corebind.core, "e io.va=1");
		ctx->target = TARGET_BACKEND;
		ctx->kernelDirectoryTable = TARGET_BACKEND;
	} else {
		ctx->target = TARGET_KERNEL;
		ServicePackBuild = winkd_get_sp(&ctx->windctx);
	}

	switch (MachineImageType) {
	case PE_IMAGE_FILE_MACHINE_ARM64:
		ctx->windctx.is_arm = true;
		ctx->windctx.is_64bit = true;
		ctx->windctx.is_pae = true;
		break;
	case PE_IMAGE_FILE_MACHINE_ARMNT:
		ctx->windctx.is_arm = true;
		ctx->windctx.is_pae = true;
		break;
	case PE_IMAGE_FILE_MACHINE_AMD64:
		ctx->windctx.is_64bit = true;
		ctx->windctx.is_pae = true;
		break;
	default:
		return false;
	}

	ctx->windctx.profile = winkd_get_profile(dbg->bits * 8, MinorVersion, ServicePackBuild);

	// Find ntoskrnl.exe module
	RzListIter *it;
	WindModule mod = { 0 };
	if (ctx->type == DMP_DUMPTYPE_TRIAGE) {
		struct rz_bin_dmp64_obj_t *obj = core->bin->cur->o->bin_obj;
		dmp_driver_desc *driver;
		rz_list_foreach (obj->drivers, it, driver) {
			if (rz_str_endswith(driver->file, "\\ntoskrnl.exe")) {
				mod.name = driver->file;
				mod.addr = driver->base;
				mod.size = driver->size;
				mod.timestamp = driver->timestamp;
				break;
			}
		}
	} else {
		WindProc kernel = { .dir_base_table = ctx->kernelDirectoryTable, .uniqueid = 4 };
		ctx->windctx.target = kernel;
		RzList *modules = winkd_list_modules(&ctx->windctx);
		WindModule *m;
		rz_list_foreach (modules, it, m) {
			if (rz_str_endswith(m->name, "\\ntoskrnl.exe")) {
				mod = *m;
				break;
			}
		}
		ctx->windctx.target.uniqueid = 0;
	}

	if (mod.name) {
		core->bin->cur->o->opts.baseaddr = mod.addr;
		const char *server = dbg->corebind.cfgGet(dbg->corebind.core, "pdb.server");
		const char *symstore = dbg->corebind.cfgGet(dbg->corebind.core, "pdb.symstore");
		char *pdbpath, *exepath;
		if (winkd_download_module_and_pdb(&mod, server, symstore, &exepath, &pdbpath)) {
			dbg->corebind.cmdf(dbg->corebind.core, "idp %s", pdbpath);
			free(exepath);
			free(pdbpath);
			if (!ctx->windctx.profile) {
				winkd_build_profile(&ctx->windctx, dbg->analysis->typedb);
				if (ctx->windctx.profile) {
					ctx->windctx.profile->build = MinorVersion;
					ctx->windctx.profile->sp = ServicePackBuild;
				}
			}
		} else {
			RZ_LOG_WARN("Failed to download ntoskrnl.pdb, many things won't work.\n");
		}
	}

	if (!ctx->windctx.profile) {
		RZ_LOG_ERROR("Could not find a profile for this Windows: %s %" PFMT32d "-bit %" PFMT32u " SP %" PFMT32u "\n",
			ctx->windctx.is_arm ? "ARM" : "x86", dbg->bits * 8, MinorVersion, ServicePackBuild);
		return false;
	}

	ctx->kthread_process_offset = rz_type_db_struct_member_offset(dbg->analysis->typedb, "_KTHREAD", "Process");
	ctx->kprcb_context_offset = rz_type_db_struct_member_offset(dbg->analysis->typedb, "_KPRCB", "Context");
	if (ctx->windctx.is_arm) {
		const ut64 switch_frame_offset = rz_type_db_struct_member_offset(dbg->analysis->typedb, "_KTHREAD", "SwitchFrame");
		ctx->kthread_switch_frame_offset = switch_frame_offset + rz_type_db_struct_member_offset(dbg->analysis->typedb, "_KSWITCH_FRAME", "Fp");
	}

	const ut64 KiProcessorBlock = dbg->corebind.numGet(dbg->corebind.core, "pdb.KiProcessorBlock");
	ut64 i;
	for (i = 0; i < NumberProcessors; i++) {
		ut64 address = KiProcessorBlock + i * (ctx->windctx.is_64bit ? 8 : 4);
		ut64 kprcb = winkd_read_ptr_at(&ctx->windctx, ctx->windctx.read_at_kernel_virtual, address);
		rz_vector_push(&ctx->KiProcessorBlock, &kprcb);
	}

	if (ctx->type == DMP_DUMPTYPE_TRIAGE) {
		// Map ETHREAD into address space
		const ut64 address = 0x1000;
		map = rz_io_map_new(core->io, desc->fd, RZ_PERM_R, ThreadOffset, address, CallStackOffset - ThreadOffset);
		map->name = strdup("kernel.target.ethread");
		WindThread *target_thread = winkd_get_thread_at(&ctx->windctx, address);

		ctx->windctx.target_thread.ethread = address;
		const ut64 current_thread_offset = ctx->windctx.is_64bit ? 8 : 4;
		ut64 *kprcb;
		rz_vector_foreach(&ctx->KiProcessorBlock, kprcb) {
			const ut64 current_thread = winkd_read_ptr_at(&ctx->windctx, ctx->windctx.read_at_kernel_virtual, *kprcb + current_thread_offset);
			WindThread *thread = winkd_get_thread_at(&ctx->windctx, current_thread);
			if (thread && thread->uniqueid == target_thread->uniqueid) {
				// Map EPROCESS into address space
				const ut64 current_process = winkd_read_ptr_at(&ctx->windctx, ctx->windctx.read_at_kernel_virtual, thread->ethread + ctx->kthread_process_offset);
				RzIOMap *map = rz_io_map_new(core->io, desc->fd, RZ_PERM_R, ProcessOffset, current_process, ThreadOffset - ProcessOffset);
				map->name = strdup("kernel.target.eprocess");
				WindProc *process = winkd_get_process_at(&ctx->windctx, current_process);
				ctx->windctx.target = *process;
				ctx->windctx.target_thread = *thread;
				free(process);
				free(thread);
				break;
			}
			free(thread);
		}
		rz_io_map_remap(core->io, map->id, ctx->windctx.target_thread.ethread);
		free(target_thread);
	}

	return true;
}

static int rz_debug_dmp_attach(RzDebug *dbg, int pid) {
	DmpCtx *ctx = dbg->plugin_data;
	if (ctx->type == DMP_DUMPTYPE_TRIAGE) {
		dbg->pid = ctx->windctx.target.uniqueid;
		dbg->tid = ctx->windctx.target_thread.uniqueid;
		return dbg->pid;
	}
	const ut64 current_thread_offset = ctx->windctx.is_64bit ? 8 : 4;
	ut64 *kprcb;
	rz_vector_foreach_prev(&ctx->KiProcessorBlock, kprcb) {
		const ut64 current_thread = winkd_read_ptr_at(&ctx->windctx, ctx->windctx.read_at_kernel_virtual, *kprcb + current_thread_offset);
		WindThread *thread = winkd_get_thread_at(&ctx->windctx, current_thread);
		if (!thread) {
			continue;
		}
		const ut64 current_process = winkd_read_ptr_at(&ctx->windctx, ctx->windctx.read_at_kernel_virtual, thread->ethread + ctx->kthread_process_offset);
		WindProc *process = winkd_get_process_at(&ctx->windctx, current_process);
		if (!process || (!process->uniqueid && !strncmp(process->name, "Idle", sizeof(process->name)))) {
			free(thread);
			free(process);
			continue;
		}
		ctx->windctx.target = *process;
		ctx->windctx.target_thread = *thread;
		free(thread);
		free(process);
		break;
	}

	dbg->pid = ctx->windctx.target.uniqueid;
	dbg->tid = ctx->windctx.target_thread.uniqueid;
	return ctx->windctx.target.uniqueid;
}

static RzList *rz_debug_dmp_pids(RzDebug *dbg, int pid) {
	DmpCtx *ctx = dbg->plugin_data;
	RzList *ret = rz_list_newf((RzListFree)rz_debug_pid_free);
	if (!ret) {
		return NULL;
	}
	RzVector procs;
	rz_vector_init(&procs, sizeof(ut64), NULL, NULL);
	const ut64 current_thread_offset = ctx->windctx.is_64bit ? 8 : 4;
	ut64 *kprcb;
	// Get currently running processes
	rz_vector_foreach_prev(&ctx->KiProcessorBlock, kprcb) {
		const ut64 current_thread = winkd_read_ptr_at(&ctx->windctx, ctx->windctx.read_at_kernel_virtual, *kprcb + current_thread_offset);
		ut64 current_process = winkd_read_ptr_at(&ctx->windctx, ctx->windctx.read_at_kernel_virtual, current_thread + ctx->kthread_process_offset);
		rz_vector_push(&procs, &current_process);
	}

	RzList *pids = winkd_list_process(&ctx->windctx);
	RzListIter *it;
	WindProc *p;
	rz_list_foreach (pids, it, p) {
		RzDebugPid *newpid = RZ_NEW0(RzDebugPid);
		if (!newpid) {
			rz_vector_fini(&procs);
			rz_list_free(ret);
			rz_list_free(pids);
			return NULL;
		}
		newpid->path = strdup(p->name);
		newpid->pid = p->uniqueid;
		newpid->status = 's';
		newpid->runnable = true;
		ut64 *process;
		rz_vector_foreach(&procs, process) {
			if (*process == p->eprocess) {
				newpid->status = 'r';
			}
		}
		rz_list_append(ret, newpid);
	}
	rz_vector_fini(&procs);
	rz_list_free(pids);
	return ret;
}

static int rz_debug_dmp_select(RzDebug *dbg, int pid, int tid) {
	DmpCtx *ctx = dbg->plugin_data;
	if (ctx->type == DMP_DUMPTYPE_TRIAGE) {
		if (pid != ctx->windctx.target.uniqueid || tid != ctx->windctx.target_thread.uniqueid) {
			RZ_LOG_ERROR("Cannot select other targets on a triage dump\n");
		}
		dbg->pid = ctx->windctx.target.uniqueid;
		dbg->tid = ctx->windctx.target_thread.uniqueid;
		return ctx->windctx.target_thread.uniqueid;
	}

	if (winkd_set_target(&ctx->windctx, pid, tid)) {
		ctx->target = TARGET_VIRTUAL;
	} else {
		ctx->target = TARGET_PHYSICAL;
	}
	dbg->pid = ctx->windctx.target.uniqueid;
	dbg->tid = ctx->windctx.target_thread.uniqueid;
	return ctx->windctx.target_thread.uniqueid;
}

static inline bool is_kernel_address_present(WindCtx *ctx, ut64 at) {
	ut8 ptr_buf[8];
	if (!ctx->read_at_kernel_virtual(ctx->user, at, ptr_buf, ctx->is_64bit ? 8 : 4)) {
		return false;
	}
	return true;
}

static int rz_debug_dmp_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	DmpCtx *dmp = dbg->plugin_data;
	WindCtx *ctx = &dmp->windctx;
	if (!is_kernel_address_present(ctx, ctx->target_thread.ethread)) {
		return 0;
	}
	const ut64 current_thread_offset = ctx->is_64bit ? 8 : 4;
	ut64 *kprcb;
	rz_vector_foreach(&dmp->KiProcessorBlock, kprcb) {
		const ut64 current_thread = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, *kprcb + current_thread_offset);
		if (current_thread == ctx->target_thread.ethread) {
			const ut64 current_context = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, *kprcb + dmp->kprcb_context_offset);
			if (current_context) {
				return ctx->read_at_kernel_virtual(ctx->user, current_context, buf, size);
			}
			RZ_LOG_WARN("Failed to get KPRCB Context pointer at 0x%" PFMT64x "\n", current_context);
		}
	}
	if (dmp->type == DMP_DUMPTYPE_TRIAGE || !ctx->target_thread.uniqueid) {
		memcpy(buf, dmp->context, RZ_MIN(size, dmp->context_sz));
		return size;
	}
	const int kernel_stack_offset = ctx->is_64bit ? 0x58 : 0x48;
	if (ctx->is_arm) {
		if (ctx->is_64bit) {
			struct context_type_arm64 *regs = (struct context_type_arm64 *)buf;
			regs->Sp = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->target_thread.ethread + kernel_stack_offset);
			regs->Fp = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->target_thread.ethread + dmp->kthread_switch_frame_offset);
			regs->Pc = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->target_thread.ethread + dmp->kthread_switch_frame_offset + 8);
		} else {
			struct context_type_arm *regs = (struct context_type_arm *)buf;
			regs->sp = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->target_thread.ethread + kernel_stack_offset);
			regs->pc = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->target_thread.ethread + dmp->kthread_switch_frame_offset + 4);
		}
	} else {
		if (ctx->is_64bit) {
			struct context_type_amd64 *regs = (struct context_type_amd64 *)buf;
			regs->rsp = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->target_thread.ethread + kernel_stack_offset);
		} else {
			struct context_type_i386 *regs = (struct context_type_i386 *)buf;
			regs->esp = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->target_thread.ethread + kernel_stack_offset);
		}
	}
	return size;
}

static char *rz_debug_dmp_reg_profile(RzDebug *dbg) {
	DmpCtx *ctx = dbg->plugin_data;
	if (!ctx) {
#include "native/reg/windows-x64.h"
	}
	if (ctx->windctx.is_arm) {
		if (ctx->windctx.is_64bit) {
#include "native/reg/windows-arm64.h"
		}
#include "native/reg/windows-arm.h"
	}
	if (ctx->windctx.is_64bit) {
#include "native/reg/windows-x64.h"
	}
#include "native/reg/windows-x86.h"
	return NULL;
}

static RzList *rz_debug_dmp_threads(RzDebug *dbg, int pid) {
	DmpCtx *ctx = dbg->plugin_data;
	RzList *ret = rz_list_newf(free);
	if (!ret) {
		return NULL;
	}
	RzList *threads = winkd_list_threads(&ctx->windctx);
	RzListIter *it;
	WindThread *t;
	rz_list_foreach (threads, it, t) {
		RzDebugPid *newpid = RZ_NEW0(RzDebugPid);
		if (!newpid) {
			rz_list_free(threads);
			rz_list_free(ret);
			return NULL;
		}
		newpid->pid = t->uniqueid;
		newpid->status = t->status;
		newpid->runnable = t->runnable;
		rz_list_append(ret, newpid);
	}
	rz_list_free(threads);
	return ret;
}

static RzList *rz_debug_dmp_modules(RzDebug *dbg) {
	DmpCtx *ctx = dbg->plugin_data;
	RzList *ret = rz_list_newf((RzListFree)rz_debug_map_free);
	if (!ret) {
		return NULL;
	}
	RzList *modules = winkd_list_modules(&ctx->windctx);
	RzListIter *it;
	WindModule *m;
	rz_list_foreach (modules, it, m) {
		RzDebugMap *mod = RZ_NEW0(RzDebugMap);
		if (!mod) {
			rz_list_free(modules);
			rz_list_free(ret);
			return NULL;
		}
		mod->file = m->name;
		mod->size = m->size;
		mod->addr = m->addr;
		mod->addr_end = m->addr + m->size;
		rz_list_append(ret, mod);
	}
	rz_list_free(modules);
	return ret;
}

static RzList *rz_debug_dmp_maps(RzDebug *dbg) {
	return NULL;
}

static bool rz_debug_dmp_kill(RzDebug *dbg, int pid, int tid, int sig) {
	return true;
}

RzDebugPlugin rz_debug_plugin_dmp = {
	.name = "dmp",
	.license = "LGPL3",
	.arch = "x86,arm",
	.bits = RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.init = &rz_debug_dmp_init,
	.attach = &rz_debug_dmp_attach,
	.pids = &rz_debug_dmp_pids,
	.select = &rz_debug_dmp_select,
	.reg_read = &rz_debug_dmp_reg_read,
	.reg_profile = &rz_debug_dmp_reg_profile,
	.threads = &rz_debug_dmp_threads,
	.modules_get = &rz_debug_dmp_modules,
	.map_get = &rz_debug_dmp_maps,
	.kill = &rz_debug_dmp_kill,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_DBG,
	.data = &rz_debug_plugin_dmp,
	.version = RZ_VERSION
};
#endif
