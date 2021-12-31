// SPDX-FileCopyrightText: 2022 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_debug.h>
#include <dmp_specs.h>
#include <dmp64.h>
#include <pe_specs.h>
#include <winkd.h>

static bool rz_debug_dmp_init(RzDebug *dbg, void **user) {
	RzCore *core = dbg->corebind.core;
	if (!core->io->desc) {
		return false;
	}
	if (strcmp(core->io->desc->plugin->name, "dmp")) {
		eprintf("Open a file with dmp:// to use the 'dmp' debug plugin\n");
		return false;
	}
	dbg->plugin_data = core->io->desc->data;
	DmpCtx *ctx = dbg->plugin_data;
	int DumpType = 0;
	int MachineImageType = 0; // Windows Architecture (IMAGE_FILE_MACHINE)
	int MinorVersion = 0; // Windows Version
	RzBuffer *b = rz_buf_new_with_io(&dbg->iob, core->io->desc->fd);
	rz_buf_read_le64_at(b, offsetof(dmp64_header, DirectoryTableBase), &ctx->kernelDirectoryTable);
	rz_buf_read_le64_at(b, offsetof(dmp64_header, PsActiveProcessHead), &ctx->windctx.PsActiveProcessHead);
	rz_buf_read_le64_at(b, offsetof(dmp64_header, PsLoadedModuleList), &ctx->windctx.PsLoadedModuleList);
	rz_buf_read_le64_at(b, offsetof(dmp64_header, KdDebuggerDataBlock), &ctx->windctx.KdDebuggerDataBlock);
	rz_buf_read_le32_at(b, offsetof(dmp64_header, DumpType), &DumpType);
	rz_buf_read_le32_at(b, offsetof(dmp64_header, MachineImageType), &MachineImageType);
	rz_buf_read_le32_at(b, offsetof(dmp64_header, MinorVersion), &MinorVersion);
	rz_buf_free(b);

	if (DumpType == DMP_DUMPTYPE_TRIAGE) {
		dbg->corebind.cmd(dbg->corebind.core, "e io.va=1");
		ctx->target = TARGET_PHYSICAL;
		ctx->kernelDirectoryTable = TARGET_PHYSICAL;
	} else {
		ctx->target = TARGET_KERNEL;
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

	// Fix mapping
	RzIOMap *map = rz_io_map_get(core->io, 0);
	if (map) {
		rz_io_map_resize(core->io, map->id, UT64_MAX);
		rz_io_map_depriorize(core->io, map->id);
	}

	ctx->windctx.profile = winkd_get_profile(dbg->bits * 8, MinorVersion, winkd_get_sp(&ctx->windctx));
	RzListIter *it;
	WindModule mod = { 0 };
	if (DumpType == DMP_DUMPTYPE_TRIAGE) {
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
		ctx->windctx.target = &kernel;
		RzList *modules = winkd_list_modules(&ctx->windctx);
		WindModule *m;
		rz_list_foreach (modules, it, m) {
			if (rz_str_endswith(m->name, "\\ntoskrnl.exe")) {
				mod = *m;
				break;
			}
		}
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
		}
	}
	return true;
}

static int rz_debug_dmp_attach(RzDebug *dbg, int pid) {
	RzCore *core = dbg->corebind.core;
	DmpCtx *ctx = dbg->plugin_data;

	winkd_set_target(&ctx->windctx, 4, 0);
	return dbg->pid = 4;
}

static RzList *rz_debug_dmp_pids(RzDebug *dbg, int pid) {
	DmpCtx *ctx = dbg->plugin_data;
	RzList *ret = rz_list_newf((RzListFree)rz_debug_pid_free);
	if (!ret) {
		return NULL;
	}

	RzList *pids = winkd_list_process(&ctx->windctx);
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
	rz_list_free(pids);
	return ret;
}

static int rz_debug_dmp_select(RzDebug *dbg, int pid, int tid) {
	DmpCtx *ctx = dbg->plugin_data;
	if (pid == 0) {
		ctx->target = TARGET_PHYSICAL;
	} else if (pid == 4) {
		ctx->target = TARGET_KERNEL;
	} else if (winkd_set_target(&ctx->windctx, pid, tid)) {
		ctx->target = TARGET_VIRTUAL;
	}
	return tid;
}

static int rz_debug_dmp_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	RzCore *core = dbg->corebind.core;
	return rz_hex_str2bin(core->bin->cur->o->regstate, buf);
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
	RzList *ret = rz_list_newf(rz_debug_map_free);
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
