// SPDX-FileCopyrightText: 2022 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_debug.h>
#include <dmp_specs.h>
#include <dmp64.h>
#include <pe_specs.h>
#include <winkd.h>
#include "common_winkd.h"

#include "native/bt/windows-x64.c"
#include "native/bt/generic-all.c"

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
	RzBinInfo *info = core->bin->cur->o->info;
	if (!info || !info->rclass || strcmp(info->rclass, "dmp64")) {
		RZ_LOG_ERROR("Open a Windows kernel dump file with dmp:// to use the 'dmp' debug plugin\n");
		return false;
	}

	dbg->plugin_data = core->io->desc->data;
	DmpCtx *ctx = dbg->plugin_data;
	ctx->bf = core->bin->cur;

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
	ut32 SizeOfCallStack = 0;
	ut64 TopOfStack = 0;
	ut32 NumberProcessors = 0;
	ctx->target = TARGET_BACKEND;

	struct rz_bin_dmp64_obj_t *obj = (struct rz_bin_dmp64_obj_t *)core->bin->cur->o->bin_obj;

	ctx->kernelDirectoryTable = obj->header->DirectoryTableBase;
	ctx->windctx.PsActiveProcessHead = obj->header->PsActiveProcessHead;
	ctx->windctx.PsLoadedModuleList = obj->header->PsLoadedModuleList;
	ctx->windctx.KdDebuggerDataBlock = obj->header->KdDebuggerDataBlock;
	NumberProcessors = obj->header->NumberProcessors;
	ctx->type = obj->header->DumpType;
	MachineImageType = obj->header->MachineImageType;
	MinorVersion = obj->header->MinorVersion;

	if (obj->triage64_header) {
		ServicePackBuild = obj->triage64_header->ServicePackBuild;
		ProcessOffset = obj->triage64_header->ProcessOffset;
		ThreadOffset = obj->triage64_header->ThreadOffset;
		CallStackOffset = obj->triage64_header->CallStackOffset;
		SizeOfCallStack = obj->triage64_header->SizeOfCallStack;
		TopOfStack = obj->triage64_header->TopOfStack;
	}

	dbg->corebind.cfgSetI(dbg->corebind.core, "io.va", 0);

	RzIOMap *map = rz_io_map_get(core->io, 0);
	if (map) {
		// Remove file mapping
		rz_io_map_del(core->io, map->id);
	}
	if (ctx->type == DMP_DUMPTYPE_TRIAGE) {
		dbg->corebind.cfgSetI(dbg->corebind.core, "io.va", 1);
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

	// dbg->bits is deprecated but unfortunately some things like dbt output formatting still depend on it
	dbg->bits = ctx->windctx.is_64bit ? RZ_SYS_BITS_64 : RZ_SYS_BITS_32;

	ut32 bits = ctx->windctx.is_64bit ? 64 : 32;

	ctx->windctx.profile = winkd_get_profile(bits, MinorVersion, ServicePackBuild);

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
	char *kernel_pdb = NULL;
	if (mod.name) {
		core->bin->cur->o->opts.baseaddr = mod.addr;
		const char *server = dbg->corebind.cfgGet(dbg->corebind.core, "pdb.server");
		const char *symstore = dbg->corebind.cfgGet(dbg->corebind.core, "pdb.symstore");
		char *pdbpath, *exepath;
		if (winkd_download_module_and_pdb(&mod, server, symstore, &exepath, &pdbpath)) {
			// TODO: Convert to API call
			dbg->corebind.cmdf(dbg->corebind.core, "idp \"%s\"", pdbpath);
			free(exepath);
			kernel_pdb = rz_str_dup(rz_file_basename(pdbpath));
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
			ctx->windctx.is_arm ? "ARM" : "x86", bits, MinorVersion, ServicePackBuild);
		return false;
	}

	ctx->kthread_process_offset = rz_type_db_struct_member_offset(dbg->analysis->typedb, "_KTHREAD", "Process");
	ctx->kprcb_context_offset = rz_type_db_struct_member_offset(dbg->analysis->typedb, "_KPRCB", "Context");
	if (ctx->windctx.is_arm) {
		const ut64 switch_frame_offset = rz_type_db_struct_member_offset(dbg->analysis->typedb, "_KTHREAD", "SwitchFrame");
		ctx->kthread_switch_frame_offset = switch_frame_offset + rz_type_db_struct_member_offset(dbg->analysis->typedb, "_KSWITCH_FRAME", "Fp");
	}
	char *kpb_flag_name;
	if (kernel_pdb) {
		rz_str_replace(kernel_pdb, ".pdb", "", 0);
		kpb_flag_name = rz_str_newf("pdb.%s.KiProcessorBlock", kernel_pdb);
		free(kernel_pdb);
	} else {
		kpb_flag_name = rz_str_dup("0");
	}
	const ut64 KiProcessorBlock = dbg->corebind.numGet(dbg->corebind.core, kpb_flag_name);
	free(kpb_flag_name);
	ut64 i;
	for (i = 0; i < NumberProcessors; i++) {
		ut64 address = KiProcessorBlock + i * (ctx->windctx.is_64bit ? 8 : 4);
		ut64 kprcb = winkd_read_ptr_at(&ctx->windctx, ctx->windctx.read_at_kernel_virtual, address);
		rz_vector_push(&ctx->KiProcessorBlock, &kprcb);
	}

	if (ctx->type == DMP_DUMPTYPE_TRIAGE) {
		// Map Call stack into address space
		map = rz_io_map_new(core->io, desc->fd, RZ_PERM_R, CallStackOffset, TopOfStack, SizeOfCallStack);

		// Map ETHREAD into address space
		const ut64 address = 0x1000;
		map = rz_io_map_new(core->io, desc->fd, RZ_PERM_R, ThreadOffset, address, CallStackOffset - ThreadOffset);
		map->name = rz_str_dup("kernel.target.ethread");
		WindThread *target_thread = winkd_get_thread_at(&ctx->windctx, address);

		ctx->windctx.target_thread.ethread = address;
		const ut64 current_thread_offset = ctx->windctx.is_64bit ? 8 : 4;
		ut64 *kprcb;
		rz_vector_foreach (&ctx->KiProcessorBlock, kprcb) {
			const ut64 current_thread = winkd_read_ptr_at(&ctx->windctx, ctx->windctx.read_at_kernel_virtual, *kprcb + current_thread_offset);
			WindThread *thread = winkd_get_thread_at(&ctx->windctx, current_thread);
			if (thread && thread->uniqueid == target_thread->uniqueid) {
				// Map EPROCESS into address space
				const ut64 current_process = winkd_read_ptr_at(&ctx->windctx, ctx->windctx.read_at_kernel_virtual, thread->ethread + ctx->kthread_process_offset);
				RzIOMap *map = rz_io_map_new(core->io, desc->fd, RZ_PERM_R, ProcessOffset, current_process, ThreadOffset - ProcessOffset);
				map->name = rz_str_dup("kernel.target.eprocess");
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
	rz_vector_foreach_prev (&ctx->KiProcessorBlock, kprcb) {
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

static RzList /*<RzDebugPid *>*/ *rz_debug_dmp_pids(RzDebug *dbg, int pid) {
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
	rz_vector_foreach_prev (&ctx->KiProcessorBlock, kprcb) {
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
		newpid->path = rz_str_dup(p->name);
		newpid->pid = p->uniqueid;
		newpid->status = 's';
		newpid->runnable = true;
		ut64 *process;
		rz_vector_foreach (&procs, process) {
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

#define reg_set(r, n, v) reg_set_bitv(r, n, (const ut8 *)&v)

static void reg_set_bitv(RzReg *reg, const char *name, const ut8 *buf) {
	RzRegItem *item = rz_reg_get(reg, name, -1);
	if (!item) {
		RZ_LOG_ERROR("debug: dmp: find register '%s'\n", name);
		return;
	}
	RzBitVector *bv = rz_bv_new_from_bytes_le(buf, 0, item->size);
	if (!bv) {
		RZ_LOG_ERROR("debug: dmp: Failed to allocate RzBitVector for register '%s'\n", name);
		return;
	}
	rz_reg_set_bv(reg, item, bv);
	rz_bv_free(bv);
}

static void debug_dmp_set_arm64_registers(RzReg *reg, struct context_type_arm64 *ctx) {
	reg_set(reg, "cpsr", ctx->Cpsr);
	reg_set(reg, "x0", ctx->X0);
	reg_set(reg, "x1", ctx->X1);
	reg_set(reg, "x2", ctx->X2);
	reg_set(reg, "x3", ctx->X3);
	reg_set(reg, "x4", ctx->X4);
	reg_set(reg, "x5", ctx->X5);
	reg_set(reg, "x6", ctx->X6);
	reg_set(reg, "x7", ctx->X7);
	reg_set(reg, "x8", ctx->X8);
	reg_set(reg, "x9", ctx->X9);
	reg_set(reg, "x10", ctx->X10);
	reg_set(reg, "x11", ctx->X11);
	reg_set(reg, "x12", ctx->X12);
	reg_set(reg, "x13", ctx->X13);
	reg_set(reg, "x14", ctx->X14);
	reg_set(reg, "x15", ctx->X15);
	reg_set(reg, "x16", ctx->X16);
	reg_set(reg, "x17", ctx->X17);
	reg_set(reg, "x18", ctx->X18);
	reg_set(reg, "x19", ctx->X19);
	reg_set(reg, "x20", ctx->X20);
	reg_set(reg, "x21", ctx->X21);
	reg_set(reg, "x22", ctx->X22);
	reg_set(reg, "x23", ctx->X23);
	reg_set(reg, "x24", ctx->X24);
	reg_set(reg, "x25", ctx->X25);
	reg_set(reg, "x26", ctx->X26);
	reg_set(reg, "x27", ctx->X27);
	reg_set(reg, "x28", ctx->X28);
	reg_set(reg, "fp", ctx->Fp);
	reg_set(reg, "lr", ctx->Lr);
	reg_set(reg, "sp", ctx->Sp);
	reg_set(reg, "pc", ctx->Pc);

	// floating point/neon registers
	reg_set(reg, "v0", ctx->V[0]);
	reg_set(reg, "v1", ctx->V[1]);
	reg_set(reg, "v2", ctx->V[2]);
	reg_set(reg, "v3", ctx->V[3]);
	reg_set(reg, "v4", ctx->V[4]);
	reg_set(reg, "v5", ctx->V[5]);
	reg_set(reg, "v6", ctx->V[6]);
	reg_set(reg, "v7", ctx->V[7]);
	reg_set(reg, "v8", ctx->V[8]);
	reg_set(reg, "v9", ctx->V[9]);
	reg_set(reg, "v10", ctx->V[10]);
	reg_set(reg, "v11", ctx->V[11]);
	reg_set(reg, "v12", ctx->V[12]);
	reg_set(reg, "v13", ctx->V[13]);
	reg_set(reg, "v14", ctx->V[14]);
	reg_set(reg, "v15", ctx->V[15]);
	reg_set(reg, "v16", ctx->V[16]);
	reg_set(reg, "v17", ctx->V[17]);
	reg_set(reg, "v18", ctx->V[18]);
	reg_set(reg, "v19", ctx->V[19]);
	reg_set(reg, "v20", ctx->V[20]);
	reg_set(reg, "v21", ctx->V[21]);
	reg_set(reg, "v22", ctx->V[22]);
	reg_set(reg, "v23", ctx->V[23]);
	reg_set(reg, "v24", ctx->V[24]);
	reg_set(reg, "v25", ctx->V[25]);
	reg_set(reg, "v26", ctx->V[26]);
	reg_set(reg, "v27", ctx->V[27]);
	reg_set(reg, "v28", ctx->V[28]);
	reg_set(reg, "v29", ctx->V[29]);
	reg_set(reg, "v30", ctx->V[30]);
	reg_set(reg, "v31", ctx->V[31]);
	reg_set(reg, "fpcr", ctx->Fpcr);
	reg_set(reg, "fpsr", ctx->Fpsr);

	// debug registers
	reg_set(reg, "bcr0", ctx->Bcr[0]);
	reg_set(reg, "bcr1", ctx->Bcr[1]);
	reg_set(reg, "bcr2", ctx->Bcr[2]);
	reg_set(reg, "bcr3", ctx->Bcr[3]);
	reg_set(reg, "bcr4", ctx->Bcr[4]);
	reg_set(reg, "bcr5", ctx->Bcr[5]);
	reg_set(reg, "bcr6", ctx->Bcr[6]);
	reg_set(reg, "bcr7", ctx->Bcr[7]);
	reg_set(reg, "bvr0", ctx->Bvr[0]);
	reg_set(reg, "bvr1", ctx->Bvr[1]);
	reg_set(reg, "bvr2", ctx->Bvr[2]);
	reg_set(reg, "bvr3", ctx->Bvr[3]);
	reg_set(reg, "bvr4", ctx->Bvr[4]);
	reg_set(reg, "bvr5", ctx->Bvr[5]);
	reg_set(reg, "bvr6", ctx->Bvr[6]);
	reg_set(reg, "bvr7", ctx->Bvr[7]);
	reg_set(reg, "wcr0", ctx->Wcr[0]);
	reg_set(reg, "wcr1", ctx->Wcr[1]);
	reg_set(reg, "wvr0", ctx->Wvr[0]);
	reg_set(reg, "wvr1", ctx->Wvr[1]);
}

static void debug_dmp_set_arm32_registers(RzReg *reg, struct context_type_arm *ctx) {
	reg_set(reg, "r0", ctx->r0);
	reg_set(reg, "r1", ctx->r1);
	reg_set(reg, "r2", ctx->r2);
	reg_set(reg, "r3", ctx->r3);
	reg_set(reg, "r4", ctx->r4);
	reg_set(reg, "r5", ctx->r5);
	reg_set(reg, "r6", ctx->r6);
	reg_set(reg, "r7", ctx->r7);
	reg_set(reg, "r8", ctx->r8);
	reg_set(reg, "r9", ctx->r9);
	reg_set(reg, "r10", ctx->r10);
	reg_set(reg, "r11", ctx->r11);
	reg_set(reg, "ip", ctx->r12); // ip = r12
	reg_set(reg, "sp", ctx->sp);
	reg_set(reg, "lr", ctx->lr);
	reg_set(reg, "pc", ctx->pc);
	reg_set(reg, "cpsr", ctx->cpsr);
	reg_set(reg, "fpscr", ctx->fpscr);

	// neon registers
	reg_set(reg, "q0", ctx->q[0]);
	reg_set(reg, "q1", ctx->q[1]);
	reg_set(reg, "q2", ctx->q[2]);
	reg_set(reg, "q3", ctx->q[3]);
	reg_set(reg, "q4", ctx->q[4]);
	reg_set(reg, "q5", ctx->q[5]);
	reg_set(reg, "q6", ctx->q[6]);
	reg_set(reg, "q7", ctx->q[7]);
	reg_set(reg, "q8", ctx->q[8]);
	reg_set(reg, "q9", ctx->q[9]);
	reg_set(reg, "q10", ctx->q[10]);
	reg_set(reg, "q11", ctx->q[11]);
	reg_set(reg, "q12", ctx->q[12]);
	reg_set(reg, "q13", ctx->q[13]);
	reg_set(reg, "q14", ctx->q[14]);
	reg_set(reg, "q15", ctx->q[15]);

	// debug registers
	reg_set(reg, "bcr0", ctx->bcr[0]);
	reg_set(reg, "bcr1", ctx->bcr[1]);
	reg_set(reg, "bcr2", ctx->bcr[2]);
	reg_set(reg, "bcr3", ctx->bcr[3]);
	reg_set(reg, "bcr4", ctx->bcr[4]);
	reg_set(reg, "bcr5", ctx->bcr[5]);
	reg_set(reg, "bcr6", ctx->bcr[6]);
	reg_set(reg, "bcr7", ctx->bcr[7]);
	reg_set(reg, "bvr0", ctx->bvr[0]);
	reg_set(reg, "bvr1", ctx->bvr[1]);
	reg_set(reg, "bvr2", ctx->bvr[2]);
	reg_set(reg, "bvr3", ctx->bvr[3]);
	reg_set(reg, "bvr4", ctx->bvr[4]);
	reg_set(reg, "bvr5", ctx->bvr[5]);
	reg_set(reg, "bvr6", ctx->bvr[6]);
	reg_set(reg, "bvr7", ctx->bvr[7]);
	reg_set(reg, "wcr0", ctx->wcr[0]);
	reg_set(reg, "wvr0", ctx->wvr[0]);
}

static void debug_dmp_set_amd64_registers(RzReg *reg, struct context_type_amd64 *ctx) {
	// segment + flags registers
	reg_set(reg, "mxcsr", ctx->mx_csr);
	reg_set(reg, "cs", ctx->seg_cs);
	reg_set(reg, "ds", ctx->seg_ds);
	reg_set(reg, "es", ctx->seg_es);
	reg_set(reg, "fs", ctx->seg_fs);
	reg_set(reg, "gs", ctx->seg_gs);
	reg_set(reg, "ss", ctx->seg_ss);
	reg_set(reg, "eflags", ctx->e_flags);

	// debug registers
	reg_set(reg, "dr0", ctx->dr0);
	reg_set(reg, "dr1", ctx->dr1);
	reg_set(reg, "dr2", ctx->dr2);
	reg_set(reg, "dr3", ctx->dr3);
	reg_set(reg, "dr6", ctx->dr6);
	reg_set(reg, "dr7", ctx->dr7);

	// gpr registers
	reg_set(reg, "rax", ctx->rax);
	reg_set(reg, "rcx", ctx->rcx);
	reg_set(reg, "rdx", ctx->rdx);
	reg_set(reg, "rbx", ctx->rbx);
	reg_set(reg, "rsp", ctx->rsp);
	reg_set(reg, "rbp", ctx->rbp);
	reg_set(reg, "rsi", ctx->rsi);
	reg_set(reg, "rdi", ctx->rdi);
	reg_set(reg, "r8", ctx->r8);
	reg_set(reg, "r9", ctx->r9);
	reg_set(reg, "r10", ctx->r10);
	reg_set(reg, "r11", ctx->r11);
	reg_set(reg, "r12", ctx->r12);
	reg_set(reg, "r13", ctx->r13);
	reg_set(reg, "r14", ctx->r14);
	reg_set(reg, "r15", ctx->r15);
	reg_set(reg, "rip", ctx->rip);
}

static void debug_dmp_set_i386_registers(RzReg *reg, struct context_type_i386 *ctx) {
	// debug registers
	reg_set(reg, "dr0", ctx->dr0);
	reg_set(reg, "dr1", ctx->dr1);
	reg_set(reg, "dr2", ctx->dr2);
	reg_set(reg, "dr3", ctx->dr3);
	reg_set(reg, "dr6", ctx->dr6);
	reg_set(reg, "dr7", ctx->dr7);

	// windows floating point save area
	reg_set(reg, "ctw", ctx->float_save.control_word);
	reg_set(reg, "stw", ctx->float_save.status_word);
	reg_set(reg, "tag", ctx->float_save.tag_word);
	reg_set(reg, "ero", ctx->float_save.error_offset);
	reg_set(reg, "ers", ctx->float_save.error_selector);
	reg_set(reg, "dao", ctx->float_save.data_offset);
	reg_set(reg, "das", ctx->float_save.data_selector);
	reg_set(reg, "st0", ctx->float_save.register_area[0]);
	reg_set(reg, "st1", ctx->float_save.register_area[10]);
	reg_set(reg, "st2", ctx->float_save.register_area[20]);
	reg_set(reg, "st3", ctx->float_save.register_area[30]);
	reg_set(reg, "st4", ctx->float_save.register_area[40]);
	reg_set(reg, "st5", ctx->float_save.register_area[50]);
	reg_set(reg, "st6", ctx->float_save.register_area[60]);
	reg_set(reg, "st7", ctx->float_save.register_area[70]);
	reg_set(reg, "spare", ctx->float_save.spare_0);

	// segment registers
	reg_set(reg, "gs", ctx->seg_gs);
	reg_set(reg, "fs", ctx->seg_fs);
	reg_set(reg, "es", ctx->seg_es);
	reg_set(reg, "ds", ctx->seg_ds);
	reg_set(reg, "cs", ctx->seg_cs);
	reg_set(reg, "ss", ctx->seg_ss);

	// gpr registers
	reg_set(reg, "edi", ctx->edi);
	reg_set(reg, "esi", ctx->esi);
	reg_set(reg, "ebx", ctx->ebx);
	reg_set(reg, "edx", ctx->edx);
	reg_set(reg, "ecx", ctx->ecx);
	reg_set(reg, "eax", ctx->eax);
	reg_set(reg, "ebp", ctx->ebp);
	reg_set(reg, "eip", ctx->eip);
	reg_set(reg, "esp", ctx->esp);
	reg_set(reg, "eflags", ctx->e_flags);

	// mmx regs
	reg_set(reg, "xmm0", ctx->extended_registers[0]);
	reg_set(reg, "xmm1", ctx->extended_registers[16]);
	reg_set(reg, "xmm2", ctx->extended_registers[32]);
	reg_set(reg, "xmm3", ctx->extended_registers[48]);
	reg_set(reg, "xmm4", ctx->extended_registers[64]);
	reg_set(reg, "xmm5", ctx->extended_registers[80]);
	reg_set(reg, "xmm6", ctx->extended_registers[96]);
	reg_set(reg, "xmm7", ctx->extended_registers[112]);
}

static void debug_dmp_set_current_context(WindCtx *ctx, RzReg *reg, ut8 *buf) {
	if (ctx->is_arm && ctx->is_64bit) {
		// ARM 64
		debug_dmp_set_arm64_registers(reg, (struct context_type_arm64 *)buf);
	} else if (ctx->is_arm && !ctx->is_64bit) {
		// ARM 32
		debug_dmp_set_arm32_registers(reg, (struct context_type_arm *)buf);
	} else if (ctx->is_64bit) {
		// AMD 64
		debug_dmp_set_amd64_registers(reg, (struct context_type_amd64 *)buf);
	} else {
		// i386
		debug_dmp_set_i386_registers(reg, (struct context_type_i386 *)buf);
	}
}

static size_t debug_dmp_get_current_context_size(WindCtx *ctx) {
	if (ctx->is_arm && ctx->is_64bit) {
		// ARM 64
		return sizeof(struct context_type_arm64);
	} else if (ctx->is_arm && !ctx->is_64bit) {
		// ARM 32
		return sizeof(struct context_type_arm);
	} else if (ctx->is_64bit) {
		// AMD 64
		return sizeof(struct context_type_amd64);
	}
	// i386
	return sizeof(struct context_type_i386);
}

static bool debug_dmp_sync_registers(RzDebug *dbg, RzReg *reg, bool to_debugger) {
	if (to_debugger) {
		// the dmp plugin does not allow to write to the debugger, since it is not a real debugger.
		return false;
	}

	DmpCtx *dmp = dbg->plugin_data;
	WindCtx *ctx = &dmp->windctx;
	if (!is_kernel_address_present(ctx, ctx->target_thread.ethread)) {
		return false;
	}

	const ut64 current_thread_offset = ctx->is_64bit ? 8 : 4;
	ut64 *kprcb;
	rz_vector_foreach (&dmp->KiProcessorBlock, kprcb) {
		const ut64 current_thread = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, *kprcb + current_thread_offset);
		if (current_thread != ctx->target_thread.ethread) {
			continue;
		}

		const ut64 current_context = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, *kprcb + dmp->kprcb_context_offset);
		if (!current_context) {
			RZ_LOG_WARN("debug: dmp: KPRCB context pointer is zero at 0x%" PFMT64x "\n", *kprcb + dmp->kprcb_context_offset);
			continue;
		}

		const size_t size = debug_dmp_get_current_context_size(ctx);
		ut8 *buffer = malloc(size);
		if (!buffer) {
			RZ_LOG_ERROR("debug: dmp: Failed to allocate buffer for setting rizin registers\n");
			return false;
		}

		bool success = false;
		if (ctx->read_at_kernel_virtual(ctx->user, current_context, buffer, size)) {
			debug_dmp_set_current_context(ctx, reg, buffer);
			success = true;
		}

		free(buffer);
		return success;
	}

	if (dmp->type == DMP_DUMPTYPE_TRIAGE || !ctx->target_thread.uniqueid) {
		debug_dmp_set_current_context(ctx, reg, dmp->context);
		return true;
	}

	const int kernel_stack_offset = ctx->is_64bit ? 0x58 : 0x48;
	if (ctx->is_arm && ctx->is_64bit) {
		// ARM 64
		ut64 Sp = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->target_thread.ethread + kernel_stack_offset);
		ut64 Fp = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->target_thread.ethread + dmp->kthread_switch_frame_offset);
		ut64 Pc = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->target_thread.ethread + dmp->kthread_switch_frame_offset + 8);
		reg_set(reg, "fp", Fp);
		reg_set(reg, "sp", Sp);
		reg_set(reg, "pc", Pc);
	} else if (ctx->is_arm && !ctx->is_64bit) {
		// ARM 32
		ut32 sp = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->target_thread.ethread + kernel_stack_offset);
		ut32 pc = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->target_thread.ethread + dmp->kthread_switch_frame_offset + 4);
		reg_set(reg, "sp", sp);
		reg_set(reg, "pc", pc);
	} else if (ctx->is_64bit) {
		// AMD 64
		ut64 rsp = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->target_thread.ethread + kernel_stack_offset);
		reg_set(reg, "rsp", rsp);
	} else {
		// i386
		ut32 esp = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->target_thread.ethread + kernel_stack_offset);
		reg_set(reg, "esp", esp);
	}
	return true;
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

static RzList /*<RzDebugPid *>*/ *rz_debug_dmp_threads(RzDebug *dbg, int pid) {
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

static RzList /*<WindModule *>*/ *dmp_get_modules(DmpCtx *ctx) {
	if (ctx->type != DMP_DUMPTYPE_TRIAGE) {
		return winkd_list_modules(&ctx->windctx);
	}
	RzList *ret = rz_list_newf(winkd_windmodule_free);
	if (!ret) {
		return NULL;
	}
	struct rz_bin_dmp64_obj_t *obj = (struct rz_bin_dmp64_obj_t *)((RzBinFile *)ctx->bf)->o->bin_obj;
	RzListIter *it;
	dmp_driver_desc *driver;
	rz_list_foreach (obj->drivers, it, driver) {
		WindModule *mod = RZ_NEW0(WindModule);
		if (!mod) {
			rz_list_free(ret);
			return NULL;
		}
		mod->name = rz_str_dup(driver->file);
		mod->size = driver->size;
		mod->addr = driver->base;
		mod->timestamp = driver->timestamp;
		rz_list_append(ret, mod);
	}
	return ret;
}

static RzList /*<RzDebugMap *>*/ *rz_debug_dmp_modules(RzDebug *dbg) {
	DmpCtx *ctx = dbg->plugin_data;
	RzList *ret = rz_list_newf((RzListFree)rz_debug_map_free);
	if (!ret) {
		return NULL;
	}
	RzList *modules = dmp_get_modules(ctx);
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
		mod->name = rz_str_dup(rz_file_dos_basename(mod->file));
		mod->size = m->size;
		mod->addr = m->addr;
		mod->addr_end = m->addr + m->size;
		rz_list_append(ret, mod);
	}
	rz_list_free(modules);
	return ret;
}

static RzList /*<RzDebugMap *>*/ *rz_debug_dmp_maps(RzDebug *dbg) {
	DmpCtx *ctx = dbg->plugin_data;
	RzList *maps = winkd_list_maps(&ctx->windctx);
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

static bool rz_debug_dmp_kill(RzDebug *dbg, int pid, int tid, int sig) {
	return true;
}

static int is_pc_inside_windmodule(const struct context_type_amd64 *context, const void *list_data, void *user) {
	const ut64 pc = context->rip;
	const WindModule *module = list_data;
	return !(pc >= module->addr && pc < (module->addr + module->size));
}

typedef RzList *(*RzDebugFrameCallback)(RzDebug *dbg, ut64 at);

RzList /*<RzDebugFrame *>*/ *rz_debug_dmp_frames(RzDebug *dbg, ut64 at) {
	RzCore *core = dbg->corebind.core;
	DmpCtx *ctx = dbg->plugin_data;
	RzList *ret = NULL;
	if (!ctx->windctx.is_arm && ctx->windctx.is_64bit) {
		RzList *modules = NULL;
		struct context_type_amd64 context = { 0 };
		const char *server = dbg->corebind.cfgGet(dbg->corebind.core, "pdb.server");
		const char *symstore = dbg->corebind.cfgGet(dbg->corebind.core, "pdb.symstore");
		ut64 last_rsp = 0;
		while (!backtrace_windows_x64(dbg, &ret, &context)) {
			if (last_rsp == context.rsp) {
				break;
			}
			last_rsp = context.rsp;
			if (!modules) {
				modules = dmp_get_modules(ctx);
			}
			RzListIter *it = rz_list_find(modules, &context, (RzListComparator)is_pc_inside_windmodule, NULL);
			if (!it) {
				break;
			}
			WindModule *module = rz_list_iter_get_data(it);
			char *exepath, *pdbpath;
			if (!winkd_download_module_and_pdb(module, server, symstore, &exepath, &pdbpath)) {
				break;
			}
			RzBinOptions opts = { 0 };
			opts.obj_opts.baseaddr = module->addr;
			RzBinFile *file = rz_bin_open(core->bin, exepath, &opts);
			if (!file) {
				free(exepath);
				free(pdbpath);
				break;
			}
			dbg->corebind.applyBinInfo(core, file, RZ_CORE_BIN_ACC_MAPS | RZ_CORE_BIN_ACC_SYMBOLS);
			dbg->corebind.cmdf(dbg->corebind.core, "idp %s", pdbpath);
			dbg->corebind.cmdf(dbg->corebind.core, "ompb %d", ((RzBinFile *)ctx->bf)->id);
			free(exepath);
			free(pdbpath);
		}
		rz_list_free(modules);
	} else {
		ret = backtrace_generic(dbg);
	}
	return ret;
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
	.sync_registers = &debug_dmp_sync_registers,
	.reg_profile = &rz_debug_dmp_reg_profile,
	.threads = &rz_debug_dmp_threads,
	.modules_get = &rz_debug_dmp_modules,
	.map_get = &rz_debug_dmp_maps,
	.kill = &rz_debug_dmp_kill,
	.frames = &rz_debug_dmp_frames,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_DBG,
	.data = &rz_debug_plugin_dmp,
	.version = RZ_VERSION
};
#endif
