// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <stdlib.h>
#include <string.h>
#include "core_private.h"

#define UPDATE_TIME(a) (r->times->file_open_time = rz_time_now_mono() - (a))

static int rz_core_file_do_load_for_debug(RzCore *r, ut64 loadaddr, const char *filenameuri);
static int rz_core_file_do_load_for_io_plugin(RzCore *r, ut64 baseaddr, ut64 loadaddr);

static bool __isMips(RzAsm *a) {
	return a && a->cur && a->cur->arch && strstr(a->cur->arch, "mips");
}

static void loadGP(RzCore *core) {
	if (__isMips(core->rasm)) {
		ut64 gp = rz_num_math(core->num, "loc._gp");
		if (!gp || gp == UT64_MAX) {
			rz_config_set(core->config, "analysis.roregs", "zero");
			rz_core_cmd0(core, "10aes@entry0");
			rz_config_set(core->config, "analysis.roregs", "zero,gp");
			gp = rz_reg_getv(core->analysis->reg, "gp");
		}
		// eprintf ("[mips] gp: 0x%08"PFMT64x"\n", gp);
		rz_config_set_i(core->config, "analysis.gp", gp);
	}
}

static RzList *__save_old_sections(RzCore *core) {
	RzList *sections = rz_bin_get_sections(core->bin);
	RzListIter *it;
	RzBinSection *sec;
	RzList *old_sections = rz_list_new();

	// Return an empty list
	if (!sections) {
		eprintf("WARNING: No sections found, functions and flags won't be rebased");
		return old_sections;
	}

	old_sections->free = sections->free;
	rz_list_foreach (sections, it, sec) {
		RzBinSection *old_sec = RZ_NEW0(RzBinSection);
		if (!old_sec) {
			break;
		}
		*old_sec = *sec;
		old_sec->name = strdup(sec->name);
		old_sec->format = NULL;
		rz_list_append(old_sections, old_sec);
	}
	return old_sections;
}

struct __rebase_struct {
	RzCore *core;
	RzList *old_sections;
	ut64 old_base;
	ut64 diff;
	int type;
};

#define __is_inside_section(item_addr, section) \
	(item_addr >= old_base + section->vaddr && item_addr <= old_base + section->vaddr + section->vsize)

static bool __rebase_flags(RzFlagItem *flag, void *user) {
	struct __rebase_struct *reb = user;
	ut64 old_base = reb->old_base;
	RzListIter *it;
	RzBinSection *sec;
	// Only rebase flags that were in the rebased sections, otherwise it will take too long
	rz_list_foreach (reb->old_sections, it, sec) {
		if (__is_inside_section(flag->offset, sec)) {
			rz_flag_set(reb->core->flags, flag->name, flag->offset + reb->diff, flag->size);
			break;
		}
	}
	return true;
}

static bool __rebase_refs_i(void *user, const ut64 k, const void *v) {
	struct __rebase_struct *reb = (void *)user;
	RzAnalysisRef *ref = (RzAnalysisRef *)v;
	ref->addr += reb->diff;
	ref->at += reb->diff;
	if (reb->type) {
		rz_analysis_xrefs_set(reb->core->analysis, ref->addr, ref->at, ref->type);
	} else {
		rz_analysis_xrefs_set(reb->core->analysis, ref->at, ref->addr, ref->type);
	}
	return true;
}

static bool __rebase_refs(void *user, const ut64 k, const void *v) {
	HtUP *ht = (HtUP *)v;
	ht_up_foreach(ht, __rebase_refs_i, user);
	return true;
}

static void __rebase_everything(RzCore *core, RzList *old_sections, ut64 old_base) {
	RzListIter *it, *itit, *ititit;
	RzAnalysisFunction *fcn;
	ut64 new_base = core->bin->cur->o->baddr_shift;
	RzBinSection *old_section;
	ut64 diff = new_base - old_base;
	if (!diff) {
		return;
	}
	// FUNCTIONS
	rz_list_foreach (core->analysis->fcns, it, fcn) {
		rz_list_foreach (old_sections, itit, old_section) {
			if (!__is_inside_section(fcn->addr, old_section)) {
				continue;
			}
			rz_analysis_function_rebase_vars(core->analysis, fcn);
			rz_analysis_function_relocate(fcn, fcn->addr + diff);
			RzAnalysisBlock *bb;
			ut64 new_sec_addr = new_base + old_section->vaddr;
			rz_list_foreach (fcn->bbs, ititit, bb) {
				if (bb->addr >= new_sec_addr && bb->addr <= new_sec_addr + old_section->vsize) {
					// Todo: Find better way to check if bb was already rebased
					continue;
				}
				rz_analysis_block_relocate(bb, bb->addr + diff, bb->size);
				if (bb->jump != UT64_MAX) {
					bb->jump += diff;
				}
				if (bb->fail != UT64_MAX) {
					bb->fail += diff;
				}
			}
			break;
		}
	}

	// FLAGS
	struct __rebase_struct reb = {
		core,
		old_sections,
		old_base,
		diff
	};
	rz_flag_foreach(core->flags, __rebase_flags, &reb);

	// META
	rz_meta_rebase(core->analysis, diff);

	// REFS
	HtUP *old_refs = core->analysis->dict_refs;
	HtUP *old_xrefs = core->analysis->dict_xrefs;
	core->analysis->dict_refs = NULL;
	core->analysis->dict_xrefs = NULL;
	rz_analysis_xrefs_init(core->analysis);
	reb.type = 0;
	ht_up_foreach(old_refs, __rebase_refs, &reb);
	reb.type = 1;
	ht_up_foreach(old_xrefs, __rebase_refs, &reb);
	ht_up_free(old_refs);
	ht_up_free(old_xrefs);

	// BREAKPOINTS
	rz_debug_bp_rebase(core->dbg, old_base, new_base);
}

RZ_API void rz_core_file_reopen_remote_debug(RzCore *core, char *uri, ut64 addr) {
	RzCoreFile *ofile = core->file;
	RzIODesc *desc;
	RzCoreFile *file;
	int fd;

	if (!ofile || !(desc = rz_io_desc_get(core->io, ofile->fd)) || !desc->uri) {
		eprintf("No file open?\n");
		return;
	}

	RzList *old_sections = __save_old_sections(core);
	ut64 old_base = core->bin->cur->o->baddr_shift;
	int bits = core->rasm->bits;
	rz_config_set_i(core->config, "asm.bits", bits);
	rz_config_set_b(core->config, "cfg.debug", true);
	// Set referer as the original uri so we could return to it with `oo`
	desc->referer = desc->uri;
	desc->uri = strdup(uri);

	if ((file = rz_core_file_open(core, uri, RZ_PERM_R | RZ_PERM_W, addr))) {
		fd = file->fd;
		core->num->value = fd;
		// if no baddr is defined, use the one provided by the file
		if (addr == 0) {
			desc = rz_io_desc_get(core->io, file->fd);
			if (desc->plugin->isdbg) {
				addr = rz_debug_get_baddr(core->dbg, desc->name);
			} else {
				addr = rz_bin_get_baddr(file->binb.bin);
			}
		}
		rz_core_bin_load(core, uri, addr);
	} else {
		eprintf("cannot open file %s\n", uri);
		rz_list_free(old_sections);
		return;
	}
	rz_core_block_read(core);
	if (rz_config_get_i(core->config, "dbg.rebase")) {
		__rebase_everything(core, old_sections, old_base);
	}
	rz_list_free(old_sections);
	rz_core_seek_to_register(core, "PC", false);
}

RZ_API void rz_core_file_reopen_debug(RzCore *core, const char *args) {
	RzCoreFile *ofile = core->file;
	RzIODesc *desc;

	if (!ofile || !(desc = rz_io_desc_get(core->io, ofile->fd)) || !desc->uri) {
		eprintf("No file open?\n");
		return;
	}

	// Reopen the original file as read only since we can't open native debug while the
	// file is open with write permissions
	if (!(desc->plugin && desc->plugin->isdbg) && (desc->perm & RZ_PERM_W)) {
		eprintf("Cannot debug file (%s) with permissions set to 0x%x.\n"
			"Reopening the original file in read-only mode.\n",
			desc->name, desc->perm);
		rz_io_reopen(core->io, ofile->fd, RZ_PERM_R, 644);
		desc = rz_io_desc_get(core->io, ofile->fd);
	}

	RzBinFile *bf = rz_bin_file_find_by_fd(core->bin, ofile->fd);
	char *binpath = (bf && bf->file) ? strdup(bf->file) : NULL;
	if (!binpath) {
		if (rz_file_exists(desc->name)) {
			binpath = strdup(desc->name);
		}
	}
	if (!binpath) {
		/* fallback to oo */
		rz_core_io_file_open(core, core->io->desc->fd);
		return;
	}

	RzList *old_sections = __save_old_sections(core);
	ut64 old_base = core->bin->cur->o->baddr_shift;
	int bits = core->rasm->bits;
	char *bin_abspath = rz_file_abspath(binpath);
	char *escaped_path = rz_str_arg_escape(bin_abspath);
	char *newfile = rz_str_newf("dbg://%s %s", escaped_path, args);
	desc->uri = newfile;
	desc->referer = NULL;
	rz_config_set_i(core->config, "asm.bits", bits);
	rz_config_set_b(core->config, "cfg.debug", true);
	rz_core_file_reopen(core, newfile, 0, 2);
	if (rz_config_get_i(core->config, "dbg.rebase")) {
		__rebase_everything(core, old_sections, old_base);
	}
	rz_list_free(old_sections);
	rz_core_seek_to_register(core, "PC", false);
	free(bin_abspath);
	free(escaped_path);
	free(binpath);
}

RZ_API int rz_core_file_reopen(RzCore *core, const char *args, int perm, int loadbin) {
	int isdebug = rz_config_get_b(core->config, "cfg.debug");
	char *path;
	ut64 laddr = rz_config_get_i(core->config, "bin.laddr");
	RzCoreFile *file = NULL;
	RzCoreFile *ofile = core->file;
	RzBinFile *bf = ofile ? rz_bin_file_find_by_fd(core->bin, ofile->fd)
			      : NULL;
	RzIODesc *odesc = (core->io && ofile) ? rz_io_desc_get(core->io, ofile->fd) : NULL;
	char *ofilepath = NULL, *obinfilepath = (bf && bf->file) ? strdup(bf->file) : NULL;
	int ret = false;
	ut64 origoff = core->offset;
	if (odesc) {
		if (odesc->referer) {
			ofilepath = odesc->referer;
		} else if (odesc->uri) {
			ofilepath = odesc->uri;
		}
	}

	ut64 new_baddr = UT64_MAX;
	if (args) {
		new_baddr = rz_num_math(core->num, args);
		if (new_baddr && new_baddr != UT64_MAX) {
			rz_config_set_i(core->config, "bin.baddr", new_baddr);
		} else {
			new_baddr = UT64_MAX;
		}
	}
	if (new_baddr == UT64_MAX) {
		new_baddr = rz_config_get_i(core->config, "bin.baddr");
	}

	if (!core->file) {
		eprintf("No file opened to reopen\n");
		free(ofilepath);
		free(obinfilepath);
		return false;
	}
	int newpid = odesc ? odesc->fd : -1;

	if (isdebug) {
		rz_debug_kill(core->dbg, core->dbg->pid, core->dbg->tid, 9); // SIGKILL
		do {
			rz_debug_continue(core->dbg);
		} while (!rz_debug_is_dead(core->dbg));
		rz_debug_detach(core->dbg, core->dbg->pid);
		perm = 7;
	} else {
		if (!perm) {
			perm = 4; //RZ_PERM_R;
		}
	}
	if (!ofilepath) {
		eprintf("Unknown file path");
		free(obinfilepath);
		return false;
	}

	// HACK: move last mapped address to higher place
	// XXX - why does this hack work?
	// when the new memory maps are created.
	path = strdup(ofilepath);
	free(obinfilepath);
	obinfilepath = strdup(ofilepath);

	// rz_str_trim (path);
	file = rz_core_file_open(core, path, perm, laddr);

	if (isdebug) {
		int newtid = newpid;
		// XXX - select the right backend
		if (core->file) {
			newpid = rz_io_fd_get_pid(core->io, core->file->fd);
#if __linux__
			core->dbg->main_pid = newpid;
			newtid = newpid;
#else
			newtid = rz_io_fd_get_tid(core->io, core->file->fd);
#endif
		}

		// Reset previous pid and tid
		core->dbg->pid = -1;
		core->dbg->tid = -1;
		core->dbg->recoil_mode = RZ_DBG_RECOIL_NONE;
		memset(&core->dbg->reason, 0, sizeof(core->dbg->reason));
		// Reopen and attach
		rz_core_setup_debugger(core, "native", true);
		rz_debug_select(core->dbg, newpid, newtid);
	}

	if (file) {
		bool had_rbin_info = false;

		if (ofile && bf) {
			if (rz_bin_file_delete(core->bin, bf->id)) {
				had_rbin_info = true;
			}
		}
		rz_core_file_close(core, ofile);
		rz_core_file_set_by_file(core, file);
		ofile = NULL;
		odesc = NULL;
		//	core->file = file;
		eprintf("File %s reopened in %s mode\n", path,
			(perm & RZ_PERM_W) ? "read-write" : "read-only");

		if (loadbin && (loadbin == 2 || had_rbin_info)) {
			ut64 baddr;
			if (isdebug) {
				baddr = rz_debug_get_baddr(core->dbg, path);
			} else if (new_baddr != UT64_MAX) {
				baddr = new_baddr;
			} else {
				baddr = rz_config_get_i(core->config, "bin.baddr");
			}
			ret = rz_core_bin_load(core, obinfilepath, baddr);
			rz_core_bin_update_arch_bits(core);
			if (!ret) {
				eprintf("Error: Failed to reload rbin for: %s", path);
			}
			origoff = rz_num_math(core->num, "entry0");
		}

		if (core->bin->cur && core->io && rz_io_desc_get(core->io, file->fd) && !loadbin) {
			//force here NULL because is causing uaf look this better in future XXX @alvarofe
			core->bin->cur = NULL;
		}
		// close old file
	} else if (ofile) {
		eprintf("rz_core_file_reopen: Cannot reopen file: %s with perms 0x%x,"
			" attempting to open read-only.\n",
			path, perm);
		// lower it down back
		//ofile = rz_core_file_open (core, path, RZ_PERM_R, addr);
		rz_core_file_set_by_file(core, ofile);
	} else {
		eprintf("Cannot reopen\n");
	}
	if (core->file) {
		rz_io_use_fd(core->io, core->file->fd);
		core->switch_file_view = 1;
		rz_core_block_read(core);
#if 0
		else {
			const char *name = (cf && cf->desc)? cf->desc->name: "ERROR";
			eprintf ("Error: Unable to switch the view to file: %s\n", name);
		}
#endif
	}
	rz_core_seek(core, origoff, true);
	if (isdebug) {
		rz_core_cmd0(core, ".dm*");
		rz_core_debug_regs2flags(core, 0);
		rz_core_seek_to_register(core, "PC", false);
	} else {
		loadGP(core);
	}
	// update analysis io bind
	rz_io_bind(core->io, &(core->analysis->iob));
	if (core->file && core->file->fd >= 0) {
		rz_core_file_close_all_but(core);
	}
	rz_core_file_close_all_but(core);
	// This is done to ensure that the file is correctly
	// loaded into the view
	free(obinfilepath);
	//free (ofilepath);
	free(path);
	return ret;
}

static bool file_resize(RzCore *core, ut64 newsize, st64 delta) {
	int ret;
	ut64 oldsize = (core->file) ? rz_io_fd_size(core->io, core->file->fd) : 0;
	if (delta) {
		newsize = oldsize + delta;
	}
	bool grow = (newsize > oldsize);
	if (grow) {
		ret = rz_io_resize(core->io, newsize);
		if (ret < 1) {
			eprintf("rz_io_resize: cannot resize\n");
			return false;
		}
	}
	if (delta && core->offset < newsize) {
		rz_io_shift(core->io, core->offset, grow ? newsize : oldsize, delta);
	}
	if (!grow) {
		ret = rz_io_resize(core->io, newsize);
		if (ret < 1) {
			eprintf("rz_io_resize: cannot resize\n");
			return false;
		}
	}
	if (newsize < core->offset + core->blocksize || oldsize < core->offset + core->blocksize) {
		rz_core_block_read(core);
	}
	return true;
}

RZ_API bool rz_core_file_resize(RzCore *core, ut64 newsize) {
	return file_resize(core, newsize, 0);
}

RZ_API bool rz_core_file_resize_delta(RzCore *core, st64 delta) {
	return file_resize(core, 0, delta);
}

RZ_API void rz_core_sysenv_end(RzCore *core, const char *cmd) {
	// TODO: remove tmpfilez
	if (strstr(cmd, "RZ_BLOCK")) {
		// remove temporary BLOCK file
		char *f = rz_sys_getenv("RZ_BLOCK");
		if (f) {
			rz_file_rm(f);
			rz_sys_setenv("RZ_BLOCK", NULL);
			free(f);
		}
	}
	rz_sys_setenv("RZ_FILE", NULL);
	rz_sys_setenv("RZ_BYTES", NULL);
	rz_sys_setenv("RZ_OFFSET", NULL);

	// remove temporary RZ_CONFIG file
	char *rz_config = rz_sys_getenv("RZ_CONFIG");
	if (rz_config) {
		rz_file_rm(rz_config);
		rz_sys_setenv("RZ_CONFIG", NULL);
		free(rz_config);
	}
}

#if DISCUSS
EDITOR rz_sys_setenv("EDITOR", rz_config_get(core->config, "cfg.editor"));
CURSOR cursor position(offset from curseek)
	VERBOSE cfg.verbose
#endif

	RZ_API char *rz_core_sysenv_begin(RzCore *core, const char *cmd) {
	char *f, *ret = cmd ? strdup(cmd) : NULL;
	RzIODesc *desc = core->file ? rz_io_desc_get(core->io, core->file->fd) : NULL;
	if (cmd && strstr(cmd, "RZ_BYTES")) {
		char *s = rz_hex_bin2strdup(core->block, core->blocksize);
		rz_sys_setenv("RZ_BYTES", s);
		free(s);
	}
	rz_sys_setenv("RZ_BIN_PDBSERVER", rz_config_get(core->config, "pdb.server"));
	if (desc && desc->name) {
		rz_sys_setenv("RZ_FILE", desc->name);
		rz_sys_setenv("RZ_SIZE", sdb_fmt("%" PFMT64d, rz_io_desc_size(desc)));
		if (cmd && strstr(cmd, "RZ_BLOCK")) {
			// replace BLOCK in RET string
			if ((f = rz_file_temp("r2block"))) {
				if (rz_file_dump(f, core->block, core->blocksize, 0)) {
					rz_sys_setenv("RZ_BLOCK", f);
				}
				free(f);
			}
		}
	}
	rz_sys_setenv("RZ_OFFSET", sdb_fmt("%" PFMT64d, core->offset));
	rz_sys_setenv("RZ_XOFFSET", sdb_fmt("0x%08" PFMT64x, core->offset));
	rz_sys_setenv("RZ_ENDIAN", core->rasm->big_endian ? "big" : "little");
	rz_sys_setenv("RZ_BSIZE", sdb_fmt("%d", core->blocksize));

	// dump current config file so other r2 tools can use the same options
	char *config_sdb_path = NULL;
	int config_sdb_fd = rz_file_mkstemp(NULL, &config_sdb_path);
	if (config_sdb_fd >= 0) {
		close(config_sdb_fd);
	}

	Sdb *config_sdb = sdb_new(NULL, config_sdb_path, 0);
	rz_config_serialize(core->config, config_sdb);
	sdb_sync(config_sdb);
	sdb_free(config_sdb);
	rz_sys_setenv("RZ_CONFIG", config_sdb_path);

	rz_sys_setenv("RZ_BIN_LANG", rz_config_get(core->config, "bin.lang"));
	rz_sys_setenv("RZ_BIN_DEMANGLE", rz_config_get(core->config, "bin.demangle"));
	rz_sys_setenv("RZ_ARCH", rz_config_get(core->config, "asm.arch"));
	rz_sys_setenv("RZ_BITS", sdb_fmt("%" PFMT64u, rz_config_get_i(core->config, "asm.bits")));
	rz_sys_setenv("RZ_COLOR", rz_config_get_i(core->config, "scr.color") ? "1" : "0");
	rz_sys_setenv("RZ_DEBUG", rz_config_get_b(core->config, "cfg.debug") ? "1" : "0");
	rz_sys_setenv("RZ_IOVA", rz_config_get_i(core->config, "io.va") ? "1" : "0");
	free(config_sdb_path);
	return ret;
}

#if !__linux__ && !__WINDOWS__
static ut64 get_base_from_maps(RzCore *core, const char *file) {
	RzDebugMap *map;
	RzListIter *iter;
	ut64 b = 0LL;

	rz_debug_map_sync(core->dbg); // update process memory maps
	rz_list_foreach (core->dbg->maps, iter, map) {
		if ((map->perm & 5) == 5) {
			// TODO: make this more flexible
			// XXX - why "copy/" here?
			if (map->name && strstr(map->name, "copy/")) {
				return map->addr;
			}
			if (map->file && !strcmp(map->file, file)) {
				return map->addr;
			}
			if (map->name && !strcmp(map->name, file)) {
				return map->addr;
			}
			// XXX - Commented out, as this could unexpected results
			//b = map->addr;
		}
	}
	// fallback resolution copied from cmd_debug.c:rz_debug_get_baddr
	rz_list_foreach (core->dbg->maps, iter, map) {
		if (map->perm == 5) { // r-x
			return map->addr;
		}
	}

	return b;
}
#endif

#if __linux__ || __APPLE__
static bool setbpint(RzCore *r, const char *mode, const char *sym) {
	RzBreakpointItem *bp;
	RzFlagItem *fi = rz_flag_get(r->flags, sym);
	if (!fi) {
		return false;
	}
	bp = rz_bp_add_sw(r->dbg->bp, fi->offset, 1, RZ_BP_PROT_EXEC);
	if (bp) {
		bp->internal = true;
#if __linux__
		bp->data = rz_str_newf("?e %s: %s", mode, sym);
#else
		bp->data = rz_str_newf("?e %s: %s;ps@rdi", mode, sym);
#endif
		return true;
	}
	eprintf("Cannot set breakpoint at %s\n", sym);
	return false;
}
#endif

// XXX - need to handle index selection during debugging
static int rz_core_file_do_load_for_debug(RzCore *r, ut64 baseaddr, const char *filenameuri) {
	RzCoreFile *cf = rz_core_file_cur(r);
	RzIODesc *desc = cf ? rz_io_desc_get(r->io, cf->fd) : NULL;
	RzBinFile *binfile = NULL;
	RzBinPlugin *plugin;
	int xtr_idx = 0; // if 0, load all if xtr is used

	// TODO : Honor file.path eval var too?
	if (!strncmp("dbg://", filenameuri, 6)) {
		filenameuri += 6;
	}
	if (!desc) {
		return false;
	}
	if (cf) {
		rz_debug_select(r->dbg, rz_io_fd_get_pid(r->io, cf->fd),
			rz_io_fd_get_tid(r->io, cf->fd));
	}
#if !__linux__
#if !__WINDOWS__
	baseaddr = get_base_from_maps(r, filenameuri);
#endif
	if (baseaddr != UT64_MAX) {
		rz_config_set_i(r->config, "bin.baddr", baseaddr);
	}
#endif
	int fd = cf ? cf->fd : -1;
	RzBinOptions opt;
	rz_bin_options_init(&opt, fd, baseaddr, UT64_MAX, false);
	opt.xtr_idx = xtr_idx;
	if (!rz_bin_open(r->bin, filenameuri, &opt)) {
		eprintf("RzBinLoad: Cannot open %s\n", filenameuri);
		if (rz_config_get_i(r->config, "bin.rawstr")) {
			rz_bin_options_init(&opt, fd, baseaddr, UT64_MAX, true);
			opt.xtr_idx = xtr_idx;
			if (!rz_bin_open(r->bin, filenameuri, &opt)) {
				return false;
			}
		}
	}

	if (*rz_config_get(r->config, "dbg.libs")) {
		rz_core_cmd0(r, ".dmm*");
#if __linux__
		setbpint(r, "dbg.libs", "sym.imp.dlopen");
		setbpint(r, "dbg.libs", "sym.imp.dlmopen");
		setbpint(r, "dbg.unlibs", "sym.imp.dlclose");
#elif __APPLE__
		setbpint(r, "dbg.libs", "sym._dlopen");
		setbpint(r, "dbg.libs", "sym._dlclose");
#endif
	}
	binfile = rz_bin_cur(r->bin);
	rz_core_bin_set_env(r, binfile);
	plugin = rz_bin_file_cur_plugin(binfile);
	if (plugin && !strcmp(plugin->name, "any")) {
		// set use of raw strings
		// rz_config_set_i (r->config, "io.va", false);
		//\\ rz_config_set (r->config, "bin.rawstr", "true");
		// get bin.minstr
		r->bin->minstrlen = rz_config_get_i(r->config, "bin.minstr");
		r->bin->maxstrbuf = rz_config_get_i(r->config, "bin.maxstrbuf");
	} else if (binfile) {
		RzBinObject *obj = rz_bin_cur_object(r->bin);
		RzBinInfo *info = obj ? obj->info : NULL;
		if (plugin && info) {
			rz_core_bin_set_arch_bits(r, binfile->file, info->arch, info->bits);
		}
	}

	if (plugin && !strcmp(plugin->name, "dex")) {
		rz_core_cmd0(r, "\"(fix-dex,wx `ph sha1 $s-32 @32` @12 ; wx `ph adler32 $s-12 @12` @8)\"\n");
	}

	return true;
}

static int rz_core_file_do_load_for_io_plugin(RzCore *r, ut64 baseaddr, ut64 loadaddr) {
	RzCoreFile *cf = rz_core_file_cur(r);
	int fd = cf ? cf->fd : -1;
	RzBinFile *binfile = NULL;
	int xtr_idx = 0; // if 0, load all if xtr is used
	RzBinPlugin *plugin;

	if (fd < 0) {
		return false;
	}
	rz_io_use_fd(r->io, fd);
	RzBinOptions opt;
	rz_bin_options_init(&opt, fd, baseaddr, loadaddr, r->bin->rawstr);
	opt.xtr_idx = xtr_idx;
	if (!rz_bin_open_io(r->bin, &opt)) {
		//eprintf ("Failed to load the bin with an IO Plugin.\n");
		return false;
	}
	binfile = rz_bin_cur(r->bin);
	if (rz_core_bin_set_env(r, binfile)) {
		if (!r->analysis->sdb_cc->path) {
			RZ_LOG_WARN("No calling convention defined for this file, analysis may be inaccurate.\n");
		}
	}
	plugin = rz_bin_file_cur_plugin(binfile);
	if (plugin && !strcmp(plugin->name, "any")) {
		RzBinObject *obj = rz_bin_cur_object(r->bin);
		RzBinInfo *info = obj ? obj->info : NULL;
		if (!info) {
			return false;
		}
		info->bits = r->rasm->bits;
		// set use of raw strings
		rz_core_bin_set_arch_bits(r, binfile->file, info->arch, info->bits);
		// rz_config_set_i (r->config, "io.va", false);
		// rz_config_set (r->config, "bin.rawstr", "true");
		// get bin.minstr
		r->bin->minstrlen = rz_config_get_i(r->config, "bin.minstr");
		r->bin->maxstrbuf = rz_config_get_i(r->config, "bin.maxstrbuf");
	} else if (binfile) {
		RzBinObject *obj = rz_bin_cur_object(r->bin);
		RzBinInfo *info = obj ? obj->info : NULL;
		if (!info) {
			return false;
		}
		if (plugin && info) {
			rz_core_bin_set_arch_bits(r, binfile->file,
				info->arch, info->bits);
		}
	}

	if (plugin && !strcmp(plugin->name, "dex")) {
		rz_core_cmd0(r, "\"(fix-dex,wx `ph sha1 $s-32 @32` @12 ; wx `ph adler32 $s-12 @12` @8)\"\n");
	}
	return true;
}

static bool try_loadlib(RzCore *core, const char *lib, ut64 addr) {
	if (rz_core_file_open(core, lib, 0, addr) != NULL) {
		rz_core_bin_load(core, lib, addr);
		return true;
	}
	return false;
}

RZ_API bool rz_core_file_loadlib(RzCore *core, const char *lib, ut64 libaddr) {
	const char *dirlibs = rz_config_get(core->config, "dir.libs");
	bool free_libdir = true;
	char *libdir = rz_str_rz_prefix(RZ_LIBDIR);
	if (!libdir) {
		libdir = RZ_LIBDIR;
		free_libdir = false;
	}
	if (!dirlibs || !*dirlibs) {
		dirlibs = "." RZ_SYS_DIR;
	}
	const char *ldlibrarypath[] = {
		dirlibs,
		libdir,
#ifndef __WINDOWS__
		"/usr/local/lib",
		"/usr/lib",
		"/lib",
#endif
		"." RZ_SYS_DIR,
		NULL
	};
	const char **libpath = (const char **)&ldlibrarypath;

	bool ret = false;
#ifdef __WINDOWS__
	if (strlen(lib) >= 3 && lib[1] == ':' && lib[2] == '\\') {
#else
	if (*lib == '/') {
#endif
		if (try_loadlib(core, lib, libaddr)) {
			ret = true;
		}
	} else {
		while (*libpath) {
			char *s = rz_str_newf("%s" RZ_SYS_DIR "%s", *libpath, lib);
			if (try_loadlib(core, s, libaddr)) {
				ret = true;
			}
			free(s);
			if (ret) {
				break;
			}
			libpath++;
		}
	}
	if (free_libdir) {
		free(libdir);
	}
	return ret;
}

RZ_API int rz_core_bin_rebase(RzCore *core, ut64 baddr) {
	if (!core || !core->bin || !core->bin->cur) {
		return 0;
	}
	if (baddr == UT64_MAX) {
		return 0;
	}
	RzBinFile *bf = core->bin->cur;
	bf->o->baddr = baddr;
	bf->o->loadaddr = baddr;
	rz_bin_object_set_items(bf, bf->o);
	return 1;
}

static void load_scripts_for(RzCore *core, const char *name) {
	// TODO:
	char *file;
	RzListIter *iter;
	char *hdir = rz_str_newf(RZ_JOIN_2_PATHS(RZ_HOME_BINRC, "bin-%s"), name);
	char *path = rz_str_home(hdir);
	RzList *files = rz_sys_dir(path);
	if (!rz_list_empty(files)) {
		eprintf("[binrc] path: %s\n", path);
	}
	rz_list_foreach (files, iter, file) {
		if (*file && *file != '.') {
			eprintf("[binrc] loading %s\n", file);
			rz_core_cmdf(core, ". %s/%s", path, file);
		}
	}
	rz_list_free(files);
	free(path);
	free(hdir);
}

typedef struct {
	const char *name;
	bool found;
} RzCoreFileData;

static bool filecb(void *user, void *data, ut32 id) {
	RzCoreFileData *filedata = user;
	RzIODesc *desc = (RzIODesc *)data;
	if (!strcmp(desc->name, filedata->name)) {
		filedata->found = true;
	}
	return true;
}

static bool file_is_loaded(RzCore *core, const char *lib) {
	RzCoreFileData filedata = { lib, false };
	rz_id_storage_foreach(core->io->files, filecb, &filedata);
	return filedata.found;
}

typedef struct {
	const char *name;
	ut64 addr;
	RzBin *bin;
} RzCoreLinkData;

static bool linkcb(void *user, void *data, ut32 id) {
	RzCoreLinkData *ld = user;
	RzIODesc *desc = (RzIODesc *)data;

	RzBinFile *bf = rz_bin_file_find_by_fd(ld->bin, desc->fd);
	if (bf) {
		RzListIter *iter;
		RzBinSymbol *sym;
		RzList *symbols = rz_bin_file_get_symbols(bf);
		rz_list_foreach (symbols, iter, sym) {
			if (!strcmp(sym->name, ld->name)) {
				ld->addr = sym->vaddr;
				return false;
			}
		}
	}
	return true;
}

RZ_API bool rz_core_bin_load(RzCore *r, const char *filenameuri, ut64 baddr) {
	RzCoreFile *cf = rz_core_file_cur(r);
	RzIODesc *desc = cf ? rz_io_desc_get(r->io, cf->fd) : NULL;
	ut64 laddr = rz_config_get_i(r->config, "bin.laddr");
	RzBinFile *binfile = NULL;
	RzBinPlugin *plugin = NULL;
	bool is_io_load;
	const char *cmd_load;
	if (!cf) {
		return false;
	}
	// NULL deref guard
	if (desc) {
		is_io_load = desc && desc->plugin;
		if (!filenameuri || !*filenameuri) {
			filenameuri = desc->name;
		}
	} else {
		is_io_load = false;
	}

	if (!filenameuri) {
		eprintf("rz_core_bin_load: no file specified\n");
		return false;
	}

	r->bin->minstrlen = rz_config_get_i(r->config, "bin.minstr");
	r->bin->maxstrbuf = rz_config_get_i(r->config, "bin.maxstrbuf");
	if (is_io_load) {
		// TODO? necessary to restore the desc back?
		// Fix to select pid before trying to load the binary
		if ((desc->plugin && desc->plugin->isdbg) || rz_config_get_b(r->config, "cfg.debug")) {
			rz_core_file_do_load_for_debug(r, baddr, filenameuri);
		} else {
			rz_core_file_do_load_for_io_plugin(r, baddr, 0LL);
		}
		rz_io_use_fd(r->io, desc->fd);
		// Restore original desc
	}
	binfile = rz_bin_cur(r->bin);
	if (cf && binfile && desc) {
		binfile->fd = desc->fd;
	}
	//rz_core_bin_set_env (r, binfile);
	plugin = rz_bin_file_cur_plugin(binfile);
	if (plugin) {
		if (plugin->strfilter) {
			char msg[2];
			msg[0] = plugin->strfilter;
			msg[1] = 0;
			rz_config_set(r->config, "bin.str.filter", msg);
		}
		if (plugin->name) {
			load_scripts_for(r, plugin->name);
		}
	}

	cmd_load = rz_config_get(r->config, "cmd.load");
	if (cmd_load && *cmd_load) {
		rz_core_cmd(r, cmd_load, 0);
	}

	if (plugin && plugin->name) {
		if (!strcmp(plugin->name, "any")) {
			if (rz_str_startswith(desc->name, "rap") && strstr(desc->name, "://")) {
				rz_io_map_new(r->io, desc->fd, desc->perm, 0, laddr, UT64_MAX);
			} else {
				rz_io_map_new(r->io, desc->fd, desc->perm, 0, laddr, rz_io_desc_size(desc));
			}
			// set use of raw strings
			//rz_config_set (r->config, "bin.rawstr", "true");
			// rz_config_set_i (r->config, "io.va", false);
			// get bin.minstr
			r->bin->minstrlen = rz_config_get_i(r->config, "bin.minstr");
			r->bin->maxstrbuf = rz_config_get_i(r->config, "bin.maxstrbuf");
		} else if (binfile) {
			RzBinObject *obj = rz_bin_cur_object(r->bin);
			if (obj) {
				bool va = obj->info ? obj->info->has_va : 0;
				if (!va) {
					rz_config_set_i(r->config, "io.va", 0);
				}
				//workaround to map correctly malloc:// and raw binaries
				if (rz_io_desc_is_dbg(desc) || (!obj->sections || !va)) {
					rz_io_map_new(r->io, desc->fd, desc->perm, 0, laddr, rz_io_desc_size(desc));
				}
				RzBinInfo *info = obj->info;
				if (info) {
					rz_core_bin_set_arch_bits(r, binfile->file, info->arch, info->bits);
				} else {
					rz_core_bin_set_arch_bits(r, binfile->file,
						rz_config_get(r->config, "asm.arch"),
						rz_config_get_i(r->config, "asm.bits"));
				}
			}
		}
	} else {
		if (desc) {
			rz_io_map_new(r->io, desc->fd, desc->perm, 0, laddr, rz_io_desc_size(desc));
		}
		if (binfile) {
			rz_core_bin_set_arch_bits(r, binfile->file,
				rz_config_get(r->config, "asm.arch"),
				rz_config_get_i(r->config, "asm.bits"));
		}
	}
	if (desc && rz_config_get_i(r->config, "io.exec")) {
		desc->perm |= RZ_PERM_X;
	}
	if (plugin && plugin->name && !strcmp(plugin->name, "dex")) {
		rz_core_cmd0(r, "\"(fix-dex,wx `ph sha1 $s-32 @32` @12 ;"
				" wx `ph adler32 $s-12 @12` @8)\"\n");
	}
	if (!rz_config_get_b(r->config, "cfg.debug")) {
		loadGP(r);
	}
	if (rz_config_get_i(r->config, "bin.libs")) {
		const char *lib;
		RzListIter *iter;
		RzList *libs = rz_bin_get_libs(r->bin);
		rz_list_foreach (libs, iter, lib) {
			if (file_is_loaded(r, lib)) {
				continue;
			}
			eprintf("[bin.libs] Opening %s\n", lib);
			ut64 baddr = rz_io_map_location(r->io, 0x200000);
			if (baddr != UT64_MAX) {
				rz_core_file_loadlib(r, lib, baddr);
			}
		}
		rz_core_cmd0(r, "obb 0;s entry0");
		rz_config_set_i(r->config, "bin.at", true);
		eprintf("[bin.libs] Linking imports...\n");
		RzBinImport *imp;
		RzList *imports = rz_bin_get_imports(r->bin);
		rz_list_foreach (imports, iter, imp) {
			// PLT finding
			RzFlagItem *impsym = rz_flag_get(r->flags, sdb_fmt("sym.imp.%s", imp->name));
			if (!impsym) {
				//eprintf ("Cannot find '%s' import in the PLT\n", imp->name);
				continue;
			}
			ut64 imp_addr = impsym->offset;
			eprintf("Resolving %s... ", imp->name);
			RzCoreLinkData linkdata = { imp->name, UT64_MAX, r->bin };
			rz_id_storage_foreach(r->io->files, linkcb, &linkdata);
			if (linkdata.addr != UT64_MAX) {
				eprintf("0x%08" PFMT64x "\n", linkdata.addr);
				ut64 a = linkdata.addr;
				ut64 b = imp_addr;
				rz_analysis_xrefs_set(r->analysis, b, a, RZ_ANALYSIS_REF_TYPE_NULL);
			} else {
				eprintf("NO\n");
			}
		}
	}

	//If type == RZ_BIN_TYPE_CORE, we need to create all the maps
	if (plugin && binfile && plugin->file_type && plugin->file_type(binfile) == RZ_BIN_TYPE_CORE) {
		ut64 sp_addr = (ut64)-1;
		RzIOMap *stack_map = NULL;

		// Setting the right arch and bits, so regstate will be shown correctly
		if (plugin->info) {
			RzBinInfo *inf = plugin->info(binfile);
			eprintf("Setting up coredump arch-bits to: %s-%d\n", inf->arch, inf->bits);
			rz_config_set(r->config, "asm.arch", inf->arch);
			rz_config_set_i(r->config, "asm.bits", inf->bits);
			rz_bin_info_free(inf);
		}
		if (binfile->o->regstate) {
			if (rz_reg_arena_set_bytes(r->analysis->reg, binfile->o->regstate)) {
				eprintf("Setting up coredump: Problem while setting the registers\n");
			} else {
				eprintf("Setting up coredump: Registers have been set\n");
				const char *regname = rz_reg_get_name(r->analysis->reg, RZ_REG_NAME_SP);
				if (regname) {
					RzRegItem *reg = rz_reg_get(r->analysis->reg, regname, -1);
					if (reg) {
						sp_addr = rz_reg_get_value(r->analysis->reg, reg);
						stack_map = rz_io_map_get(r->io, sp_addr);
					}
				}
				regname = rz_reg_get_name(r->analysis->reg, RZ_REG_NAME_PC);
				if (regname) {
					RzRegItem *reg = rz_reg_get(r->analysis->reg, regname, -1);
					if (reg) {
						ut64 seek = rz_reg_get_value(r->analysis->reg, reg);
						rz_core_seek(r, seek, true);
					}
				}
			}
		}

		RzBinObject *o = binfile->o;
		int map = 0;
		if (o && o->maps) {
			RzList *maps = o->maps;
			RzListIter *iter;
			RzBinMap *mapcore;

			rz_list_foreach (maps, iter, mapcore) {
				RzIOMap *iomap = rz_io_map_get(r->io, mapcore->addr);
				if (iomap && (mapcore->file || stack_map == iomap)) {
					rz_io_map_set_name(iomap, mapcore->file ? mapcore->file : "[stack]");
				}
				map++;
			}
			rz_list_free(maps);
			o->maps = NULL;
		}
		eprintf("Setting up coredump: %d maps have been found and created\n", map);
		goto beach;
	}
beach:
	return true;
}

RZ_API RzCoreFile *rz_core_file_open_many(RzCore *r, const char *file, int perm, ut64 loadaddr) {
	const bool openmany = rz_config_get_i(r->config, "file.openmany");
	int opened_count = 0;
	RzListIter *fd_iter, *iter2;
	RzIODesc *fd;

	RzList *list_fds = rz_io_open_many(r->io, file, perm, 0644);

	if (!list_fds || rz_list_length(list_fds) == 0) {
		rz_list_free(list_fds);
		return NULL;
	}

	rz_list_foreach_safe (list_fds, fd_iter, iter2, fd) {
		opened_count++;
		if (openmany && opened_count > 1) {
			// XXX - Open Many should limit the number of files
			// loaded in io plugin area this needs to be more premptive
			// like down in the io plugin layer.
			// start closing down descriptors
			rz_list_delete(list_fds, fd_iter);
			continue;
		}
		RzCoreFile *fh = RZ_NEW0(RzCoreFile);
		if (fh) {
			fh->alive = 1;
			fh->core = r;
			fh->fd = fd->fd;
			r->file = fh;
			rz_bin_bind(r->bin, &(fh->binb));
			rz_list_append(r->files, fh);
			rz_core_bin_load(r, fd->name, loadaddr);
		}
	}
	return NULL;
}

/* loadaddr is r2 -m (mapaddr) */
RZ_API RzCoreFile *rz_core_file_open(RzCore *r, const char *file, int flags, ut64 loadaddr) {
	rz_return_val_if_fail(r && file, NULL);
	ut64 prev = rz_time_now_mono();
	const bool openmany = rz_config_get_i(r->config, "file.openmany");
	RzCoreFile *fh = NULL;

	if (!strcmp(file, "-")) {
		file = "malloc://512";
	}
	//if not flags was passed open it with -r--
	if (!flags) {
		flags = RZ_PERM_R;
	}
	r->io->bits = r->rasm->bits; // TODO: we need an api for this
	RzIODesc *fd = rz_io_open_nomap(r->io, file, flags, 0644);
	if (rz_cons_is_breaked()) {
		goto beach;
	}
	if (!fd && openmany) {
		// XXX - make this an actual option somewhere?
		fh = rz_core_file_open_many(r, file, flags, loadaddr);
		if (fh) {
			goto beach;
		}
	}
	if (!fd) {
		if (flags & RZ_PERM_W) {
			//	flags |= RZ_IO_CREAT;
			if (!(fd = rz_io_open_nomap(r->io, file, flags, 0644))) {
				goto beach;
			}
		} else {
			goto beach;
		}
	}
	if (rz_io_is_listener(r->io)) {
		rz_core_serve(r, fd);
		rz_io_desc_free(fd);
		goto beach;
	}

	fh = RZ_NEW0(RzCoreFile);
	if (!fh) {
		eprintf("core/file.c: rz_core_open failed to allocate RzCoreFile.\n");
		goto beach;
	}
	fh->alive = 1;
	fh->core = r;
	fh->fd = fd->fd;
	{
		const char *cp = rz_config_get(r->config, "cmd.open");
		if (cp && *cp) {
			rz_core_cmd(r, cp, 0);
		}
		char *absfile = rz_file_abspath(file);
		rz_config_set(r->config, "file.path", absfile);
		free(absfile);
	}
	// check load addr to make sure its still valid
	rz_bin_bind(r->bin, &(fh->binb));

	if (!r->files) {
		r->files = rz_list_newf((RzListFree)rz_core_file_free);
	}

	r->file = fh;
	rz_io_use_fd(r->io, fd->fd);

	rz_list_append(r->files, fh);
	if (rz_config_get_b(r->config, "cfg.debug")) {
		bool swstep = true;
		if (r->dbg->h && r->dbg->h->canstep) {
			swstep = false;
		}
		rz_config_set_i(r->config, "dbg.swstep", swstep);
		// Set the correct debug handle
		if (fd->plugin && fd->plugin->isdbg) {
			char *dh = rz_str_ndup(file, (strstr(file, "://") - file));
			if (dh) {
				rz_debug_use(r->dbg, dh);
				free(dh);
			}
		}
	}
	//used by rz_core_bin_load otherwise won't load correctly
	//this should be argument of rz_core_bin_load <shrug>
	if (loadaddr != UT64_MAX) {
		rz_config_set_i(r->config, "bin.laddr", loadaddr);
	}
	rz_core_cmd0(r, "=!");
beach:
	r->times->file_open_time = rz_time_now_mono() - prev;
	return fh;
}

RZ_API void rz_core_file_free(RzCoreFile *cf) {
	int res = 1;

	rz_return_if_fail(cf);

	if (!cf->core) {
		free(cf);
		return;
	}
	res = rz_list_delete_data(cf->core->files, cf);
	if (res && cf->alive) {
		// double free librz/io/io.c:70 performs free
		RzIO *io = cf->core->io;
		if (io) {
			RzBin *bin = cf->binb.bin;
			RzBinFile *bf = rz_bin_cur(bin);
			if (bf) {
				rz_bin_file_deref(bin, bf);
			}
			rz_io_fd_close(io, cf->fd);
			free(cf);
		}
	}
}

RZ_API int rz_core_file_close(RzCore *r, RzCoreFile *fh) {
	int ret;
	RzIODesc *desc = fh && r ? rz_io_desc_get(r->io, fh->fd) : NULL;
	RzCoreFile *prev_cf = r && r->file != fh ? r->file : NULL;

	// TODO: This is not correctly done. because map and iodesc are
	// still referenced // we need to fully clear all RZ_IO structs
	// related to a file as well as the ones needed for RzBin.
	//
	// XXX -these checks are intended to *try* and catch
	// stale objects.  Unfortunately, if the file handle
	// (fh) is stale and freed, and there is more than 1
	// fh in the r->files list, we are hosed. (design flaw)
	// TODO maybe using sdb to keep track of the allocated and
	// deallocated files might be a good solutions
	if (!r || !desc || rz_list_empty(r->files)) {
		return false;
	}

	if (fh == r->file) {
		r->file = NULL;
	}

	rz_core_file_set_by_fd(r, fh->fd);
	rz_core_bin_set_by_fd(r, fh->fd);

	/* delete filedescriptor from io descs here */
	// rz_io_desc_del (r->io, fh->fd);

	// AVOID DOUBLE FREE HERE
	r->files->free = NULL;

	ret = rz_list_delete_data(r->files, fh);
	if (ret) {
		if (!prev_cf && rz_list_length(r->files) > 0) {
			prev_cf = (RzCoreFile *)rz_list_get_n(r->files, 0);
		}

		if (prev_cf) {
			RzIODesc *desc = prev_cf && r ? rz_io_desc_get(r->io, prev_cf->fd) : NULL;
			if (!desc) {
				eprintf("Error: RzCoreFile's found with out a supporting RzIODesc.\n");
			}
			ret = rz_core_file_set_by_file(r, prev_cf);
		}
	}
	rz_io_desc_close(desc);
	rz_core_file_free(fh);
	return ret;
}

RZ_API RzCoreFile *rz_core_file_get_by_fd(RzCore *core, int fd) {
	RzCoreFile *file;
	RzListIter *iter;
	rz_list_foreach (core->files, iter, file) {
		if (file->fd == fd) {
			return file;
		}
	}
	return NULL;
}

RZ_API int rz_core_file_list(RzCore *core, int mode) {
	int count = 0;
	RzCoreFile *f;
	RzIODesc *desc;
	ut64 from;
	RzListIter *it;
	RzBinFile *bf;
	RzListIter *iter;
	PJ *pj;
	if (mode == 'j') {
		pj = pj_new();
		if (!pj) {
			return 0;
		}
		pj_a(pj);
	}
	rz_list_foreach (core->files, iter, f) {
		desc = rz_io_desc_get(core->io, f->fd);
		if (!desc) {
			// cannot find desc for this fd, RzCoreFile inconsistency!!!1
			continue;
		}
		from = 0LL;
		switch (mode) {
		case 'j': { // "oij"
			pj_o(pj);
			pj_kb(pj, "raised", core->io->desc->fd == f->fd);
			pj_ki(pj, "fd", f->fd);
			pj_ks(pj, "uri", desc->uri);
			pj_kn(pj, "from", (ut64)from);
			pj_kb(pj, "writable", desc->perm & RZ_PERM_W);
			pj_ki(pj, "size", (int)rz_io_desc_size(desc));
			pj_end(pj);
			break;
		}
		case '*':
		case 'r':
			// TODO: use a getter
			{
				bool fileHaveBin = false;
				char *absfile = rz_file_abspath(desc->uri);
				rz_list_foreach (core->bin->binfiles, it, bf) {
					if (bf->fd == f->fd) {
						rz_cons_printf("o %s 0x%" PFMT64x "\n", absfile, (ut64)from);
						fileHaveBin = true;
					}
				}
				if (!fileHaveBin && !strstr(absfile, "://")) {
					rz_cons_printf("o %s 0x%" PFMT64x "\n", absfile, (ut64)from);
				}
				free(absfile);
			}
			break;
		case 'n': {
			bool header_loaded = false;
			rz_list_foreach (core->bin->binfiles, it, bf) {
				if (bf->fd == f->fd) {
					header_loaded = true;
					break;
				}
			}
			if (!header_loaded) {
				RzList *maps = rz_io_map_get_for_fd(core->io, f->fd);
				RzListIter *iter;
				RzIOMap *current_map;
				char *absfile = rz_file_abspath(desc->uri);
				rz_list_foreach (maps, iter, current_map) {
					if (current_map) {
						rz_cons_printf("on %s 0x%" PFMT64x "\n", absfile, current_map->itv.addr);
					}
				}
				rz_list_free(maps);
				free(absfile);
			}
		} break;
		default: {
			ut64 sz = rz_io_desc_size(desc);
			const char *fmt;
			if (sz == UT64_MAX) {
				fmt = "%c %d %d %s @ 0x%" PFMT64x " ; %s size=%" PFMT64d "\n";
			} else {
				fmt = "%c %d %d %s @ 0x%" PFMT64x " ; %s size=%" PFMT64u "\n";
			}
			rz_cons_printf(fmt,
				core->io->desc->fd == f->fd ? '*' : '-',
				count,
				(int)f->fd, desc->uri, (ut64)from,
				desc->perm & RZ_PERM_W ? "rw" : "r",
				rz_io_desc_size(desc));
		} break;
		}
		count++;
	}
	if (mode == 'j') {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
	return count;
}

// XXX - needs to account for binfile index and bin object index
RZ_API bool rz_core_file_bin_raise(RzCore *core, ut32 bfid) {
	RzBin *bin = core->bin;
	RzBinFile *bf = rz_list_get_n(bin->binfiles, bfid);
	bool res = false;
	if (bf) {
		res = rz_bin_file_set_cur_binfile(bin, bf);
		if (res) {
			rz_io_use_fd(core->io, bf->fd);
		}
		res = res ? rz_core_file_set_by_fd(core, bf->fd) : res;
		if (res) {
			core->switch_file_view = 1;
		}
	}
	return res;
}

RZ_API int rz_core_file_binlist(RzCore *core) {
	int count = 0;
	RzListIter *iter;
	RzCoreFile *cur_cf = core->file, *cf = NULL;
	RzBinFile *binfile = NULL;
	RzIODesc *desc;
	RzBin *bin = core->bin;
	const RzList *binfiles = bin ? bin->binfiles : NULL;

	if (!binfiles) {
		return false;
	}
	rz_list_foreach (binfiles, iter, binfile) {
		int fd = binfile->fd;
		cf = rz_core_file_get_by_fd(core, fd);
		desc = rz_io_desc_get(core->io, fd);
		if (cf) {
			rz_cons_printf("%c %d %s ; %s\n",
				core->io->desc == desc ? '*' : '-',
				fd, desc->uri, desc->perm & RZ_PERM_W ? "rw" : "r");
		}
	}
	rz_core_file_set_by_file(core, cur_cf);
	//rz_core_bin_bind (core, cur_bf);
	return count;
}

static bool close_but_cb(void *user, void *data, ut32 id) {
	RzCore *core = (RzCore *)user;
	RzIODesc *desc = (RzIODesc *)data;
	if (core && desc && core->file) {
		if (desc->fd != core->file->fd) {
			if (!rz_core_file_close_fd(core, desc->fd)) {
				return false;
			}
		}
	}
	return true;
}

RZ_API bool rz_core_file_close_all_but(RzCore *core) {
	rz_id_storage_foreach(core->io->files, close_but_cb, core);
	return true;
}

RZ_API bool rz_core_file_close_fd(RzCore *core, int fd) {
	RzCoreFile *file;
	RzListIter *iter;
	if (fd == -1) {
		// FIXME: Only closes files known to the core!
		rz_list_free(core->files);
		core->files = NULL;
		core->file = NULL;
		return true;
	}
	rz_list_foreach (core->files, iter, file) {
		if (file->fd == fd) {
			rz_core_file_close(core, file);
			if (file == core->file) {
				core->file = NULL; // deref
			}
			return true;
		}
	}
	return rz_io_fd_close(core->io, fd);
}

RZ_API RzCoreFile *rz_core_file_find_by_fd(RzCore *core, ut64 fd) {
	RzListIter *iter;
	RzCoreFile *cf = NULL;
	rz_list_foreach (core->files, iter, cf) {
		if (cf && cf->fd == fd) {
			break;
		}
		cf = NULL;
	}
	return cf;
}

RZ_API RzCoreFile *rz_core_file_find_by_name(RzCore *core, const char *name) {
	RzListIter *iter;
	RzCoreFile *cf = NULL;
	RzIODesc *desc;

	if (!core) {
		return NULL;
	}

	rz_list_foreach (core->files, iter, cf) {
		desc = rz_io_desc_get(core->io, cf->fd);
		if (desc && !strcmp(desc->name, name)) {
			break;
		}
		cf = NULL;
	}
	return cf;
}

RZ_API int rz_core_file_set_by_fd(RzCore *core, ut64 fd) {
	if (core) {
		rz_io_use_fd(core->io, fd);
		rz_core_bin_set_by_fd(core, fd);
		return true;
	}
	return false;
}

RZ_API int rz_core_file_set_by_name(RzCore *core, const char *name) {
	RzCoreFile *cf = rz_core_file_find_by_name(core, name);
	return rz_core_file_set_by_file(core, cf);
}

RZ_API int rz_core_file_set_by_file(RzCore *core, RzCoreFile *cf) {
	if (core && cf) {
		if (!rz_core_file_set_by_fd(core, cf->fd)) {
			return false;
		}
		core->file = cf;
		return true;
	}
	return false;
}

RZ_API ut32 rz_core_file_cur_fd(RzCore *core) {
	if (core && core->file) {
		return core->file->fd;
	}
	return UT32_MAX;
}

RZ_API RzCoreFile *rz_core_file_cur(RzCore *r) {
	// Add any locks here
	return r->file;
}

/* --------------------------------------------------------------------------------- */

RZ_IPI void rz_core_io_file_open(RzCore *core, int fd) {
	if (rz_config_get_b(core->config, "cfg.debug")) {
		RzBinFile *bf = rz_bin_cur(core->bin);
		if (bf && rz_file_exists(bf->file)) {
			// Escape spaces so that o's argv parse will detect the path properly
			char *file = rz_str_path_escape(bf->file);
			// Backup the baddr and sections that were already rebased to
			// revert the rebase after the debug session is closed
			ut64 orig_baddr = core->bin->cur->o->baddr_shift;
			RzList *orig_sections = __save_old_sections(core);

			rz_core_cmd0(core, "ob-*");
			rz_io_close_all(core->io);
			rz_config_set_b(core->config, "cfg.debug", false);
			rz_core_cmdf(core, "o %s", file);

			rz_core_block_read(core);
			__rebase_everything(core, orig_sections, orig_baddr);
			rz_list_free(orig_sections);
			free(file);
		} else {
			eprintf("Nothing to do.\n");
		}
	} else {
		rz_io_reopen(core->io, fd, RZ_PERM_R, 644);
	}
}

RZ_IPI void rz_core_io_file_reopen(RzCore *core, int fd, int perms) {
	if (rz_io_reopen(core->io, fd, perms, 644)) {
		void **it;
		rz_pvector_foreach_prev(&core->io->maps, it) {
			RzIOMap *map = *it;
			if (map->fd == fd) {
				map->perm |= RZ_PERM_WX;
			}
		}
	}
}
