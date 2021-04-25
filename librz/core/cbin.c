// SPDX-FileCopyrightText: 2011-2020 earada <pkedurat@gmail.com>
// SPDX-FileCopyrightText: 2011-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_config.h>
#include "rz_util.h"
#include "rz_util/rz_time.h"

#define is_in_range(at, from, sz) ((at) >= (from) && (at) < ((from) + (sz)))

#define VA_FALSE    0
#define VA_TRUE     1
#define VA_NOREBASE 2

#define LOAD_BSS_MALLOC 0

#define IS_MODE_SET(mode)       ((mode)&RZ_MODE_SET)
#define IS_MODE_SIMPLE(mode)    ((mode)&RZ_MODE_SIMPLE)
#define IS_MODE_SIMPLEST(mode)  ((mode)&RZ_MODE_SIMPLEST)
#define IS_MODE_JSON(mode)      ((mode)&RZ_MODE_JSON)
#define IS_MODE_RZCMD(mode)     ((mode)&RZ_MODE_RIZINCMD)
#define IS_MODE_EQUAL(mode)     ((mode)&RZ_MODE_EQUAL)
#define IS_MODE_NORMAL(mode)    (!(mode))
#define IS_MODE_CLASSDUMP(mode) ((mode)&RZ_MODE_CLASSDUMP)

// dup from cmd_info
#define PAIR_WIDTH "9"

#define bprintf \
	if (binfile && binfile->rbin && binfile->rbin->verbose) \
	eprintf

static RZ_NULLABLE RZ_BORROW const RzList *core_bin_strings(RzCore *r, RzBinFile *file);

static void pair(const char *key, const char *val, RzList *row_list, RzTable *t) {
	if (!val || !*val) {
		return;
	}
	RzTableColumnType *typeString = rz_table_type("string");
	rz_table_add_column(t, typeString, key, 0);
	rz_list_append(row_list, strdup(val));
	val = NULL;
	key = NULL;
}

static char *get_coloured(const char *flag, bool use_color) {
	if (use_color == true) {
		if (strncmp(flag, "true", 5) == 0) {
			return rz_str_newf(Color_GREEN "true" Color_RESET);
		} else {
			return rz_str_newf(Color_RED "false" Color_RESET);
		}
	} else {
		return strncmp(flag, "true", 5) == 0 ? strdup("true") : strdup("false");
	}
}

static void pair_bool(bool use_color, RzTable *t, PJ *pj, const char *key, bool val, RzList *row_list) {
	if (pj) {
		pj_kb(pj, key, val);
	} else {
		RzTableColumnType *typeString = rz_table_type("bool");
		const char *b = val || typeString ? get_coloured(rz_str_bool(val), use_color) : "";
		pair(key, b, row_list, t);
	}
}

static void pair_int(RzTable *t, PJ *pj, const char *key, int val, RzList *row_list) {
	if (pj) {
		pj_ki(pj, key, val);
	} else {
		const char *fmt = rz_str_newf("%d", val);
		pair(key, fmt, row_list, t);
	}
}

static void pair_ut64(RzTable *t, PJ *pj, const char *key, ut64 val, RzList *row_list) {
	if (pj) {
		pj_kn(pj, key, val);
	} else {
		const char *fmt = rz_str_newf("%" PFMT64d, val);
		pair(key, fmt, row_list, t);
	}
}

static char *__filterQuotedShell(const char *arg) {
	rz_return_val_if_fail(arg, NULL);
	char *a = malloc(strlen(arg) + 1);
	if (!a) {
		return NULL;
	}
	char *b = a;
	while (*arg) {
		switch (*arg) {
		case ' ':
		case '=':
		case '"':
		case '\\':
		case '\r':
		case '\n':
			break;
		default:
			*b++ = *arg;
			break;
		}
		arg++;
	}
	*b = 0;
	return a;
}
// TODO: move into librz/util/name.c
static char *__filterShell(const char *arg) {
	rz_return_val_if_fail(arg, NULL);
	char *a = malloc(strlen(arg) + 1);
	if (!a) {
		return NULL;
	}
	char *b = a;
	while (*arg) {
		char ch = *arg;
		switch (ch) {
		case '@':
		case '`':
		case '|':
		case ';':
		case '=':
		case '\n':
			break;
		default:
			*b++ = ch;
			break;
		}
		arg++;
	}
	*b = 0;
	return a;
}

static void pair_ut64x(RzTable *t, PJ *pj, const char *key, ut64 val, RzList *row_list) {
	if (pj) {
		pair_ut64(t, pj, key, val, row_list);
	} else {
		const char *fmt = rz_str_newf("0x%" PFMT64x, val);
		pair(key, fmt, row_list, t);
	}
}

static void pair_str(RzTable *t, PJ *pj, const char *key, const char *val, RzList *row_list) {
	if (pj) {
		if (!val) {
			val = "";
		}
		pj_ks(pj, key, val);
	} else {
		pair(key, val, row_list, t);
	}
}

#define STR(x) (x) ? (x) : ""
RZ_API int rz_core_bin_set_cur(RzCore *core, RzBinFile *binfile);

static ut64 rva(RzBinObject *o, ut64 paddr, ut64 vaddr, int va) {
	if (va == VA_TRUE) {
		return rz_bin_object_get_vaddr(o, paddr, vaddr);
	}
	if (va == VA_NOREBASE) {
		return vaddr;
	}
	return paddr;
}

RZ_API void rz_core_bin_options_init(RzCore *core, RZ_OUT RzBinOptions *opts, int fd, ut64 baseaddr, ut64 loadaddr) {
	rz_return_if_fail(core && opts);
	rz_bin_options_init(opts, fd, baseaddr, loadaddr, rz_config_get_b(core->config, "bin.relocs"), core->bin->rawstr);
}

RZ_API int rz_core_bin_set_by_fd(RzCore *core, ut64 bin_fd) {
	if (rz_bin_file_set_cur_by_fd(core->bin, bin_fd)) {
		rz_core_bin_set_cur(core, rz_bin_cur(core->bin));
		return true;
	}
	return false;
}

RZ_API void rz_core_bin_export_info(RzCore *core, int mode) {
	char *flagname = NULL, *offset = NULL;
	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf) {
		return;
	}
	Sdb *db = sdb_ns(bf->sdb, "info", 0);
	;
	if (!db) {
		return;
	}
	SdbListIter *iter;
	SdbKv *kv;
	if (IS_MODE_RZCMD(mode)) {
		rz_cons_printf("fs format\n");
	} else if (IS_MODE_SET(mode)) {
		rz_flag_space_push(core->flags, "format");
	}
	// iterate over all keys
	SdbList *ls = sdb_foreach_list(db, false);
	ls_foreach (ls, iter, kv) {
		char *k = sdbkv_key(kv);
		char *v = sdbkv_value(kv);
		char *dup = strdup(k);
		//printf ("?e (%s) (%s)\n", k, v);
		if ((flagname = strstr(dup, ".offset"))) {
			*flagname = 0;
			flagname = dup;
			if (IS_MODE_RZCMD(mode)) {
				rz_cons_printf("f %s @ %s\n", flagname, v);
			} else if (IS_MODE_SET(mode)) {
				ut64 nv = rz_num_math(core->num, v);
				rz_flag_set(core->flags, flagname, nv, 0);
			}
			free(offset);
			offset = strdup(v);
		}
		if (strstr(dup, ".cparse")) {
			if (IS_MODE_RZCMD(mode)) {
				rz_cons_printf("td \"%s\"\n", v);
			} else if (IS_MODE_SET(mode)) {
				char *code = rz_str_newf("%s;", v);
				char *error_msg = NULL;
				int result = rz_type_parse_c_string(core->analysis->typedb, code, &error_msg);
				if (result && error_msg) {
					eprintf("%s", error_msg);
					free(error_msg);
				}
			}
		}
		free(dup);
	}
	RZ_FREE(offset);
	ls_foreach (ls, iter, kv) {
		char *k = sdbkv_key(kv);
		char *v = sdbkv_value(kv);
		char *dup = strdup(k);
		if ((flagname = strstr(dup, ".format"))) {
			*flagname = 0;
			if (!offset) {
				offset = strdup("0");
			}
			flagname = dup;
			if (IS_MODE_RZCMD(mode)) {
				rz_cons_printf("pf.%s %s\n", flagname, v);
			} else if (IS_MODE_SET(mode)) {
				rz_type_db_format_set(core->analysis->typedb, flagname, v);
			}
		}
		free(dup);
	}
	ls_foreach (ls, iter, kv) {
		char *k = sdbkv_key(kv);
		char *v = sdbkv_value(kv);
		char *dup = strdup(k);
		if ((flagname = strstr(dup, ".format"))) {
			*flagname = 0;
			if (!offset) {
				offset = strdup("0");
			}
			flagname = dup;
			int fmtsize = rz_type_format_struct_size(core->analysis->typedb, v, 0, 0);
			char *offset_key = rz_str_newf("%s.offset", flagname);
			const char *off = sdb_const_get(db, offset_key, 0);
			free(offset_key);
			if (off) {
				if (IS_MODE_RZCMD(mode)) {
					rz_cons_printf("Cf %d %s @ %s\n", fmtsize, v, off);
				} else if (IS_MODE_SET(mode)) {
					ut64 addr = rz_num_get(NULL, off);
					ut8 *buf = malloc(fmtsize);
					if (buf) {
						rz_io_read_at(core->io, addr, buf, fmtsize);
						char *format = rz_type_format_data(core->analysis->typedb, core->print, addr, buf,
							fmtsize, v, 0, NULL, NULL);
						free(buf);
						if (!format) {
							eprintf("Warning: Cannot register invalid format (%s)\n", v);
						} else {
							rz_cons_print(format);
							free(format);
						}
					}
				}
			}
		}
		if ((flagname = strstr(dup, ".size"))) {
			*flagname = 0;
			flagname = dup;
			if (IS_MODE_RZCMD(mode)) {
				rz_cons_printf("fl %s %s\n", flagname, v);
			} else if (IS_MODE_SET(mode)) {
				RzFlagItem *fi = rz_flag_get(core->flags, flagname);
				if (fi) {
					fi->size = rz_num_math(core->num, v);
				} else {
					eprintf("Cannot find flag named '%s'\n", flagname);
				}
			}
		}
		free(dup);
	}
	free(offset);
	if (IS_MODE_SET(mode)) {
		rz_flag_space_pop(core->flags);
	}
}

RZ_API bool rz_core_bin_load_structs(RzCore *core, const char *file) {
	rz_return_val_if_fail(core && file && core->io, false);
	if (!file) {
		int fd = rz_io_fd_get_current(core->io);
		RzIODesc *desc = rz_io_desc_get(core->io, fd);
		if (desc) {
			file = desc->name;
		}
		if (!file) {
			return false;
		}
	}
	if (strchr(file, '\"')) { // TODO: escape "?
		eprintf("Invalid char found in filename\n");
		return false;
	}
	RzBinOptions opt = { 0 };
	RzBinFile *bf = rz_bin_open(core->bin, file, &opt);
	if (!bf) {
		eprintf("Cannot open bin '%s'\n", file);
		return false;
	}
	if (!bf) {
		eprintf("Cannot open bin '%s'\n", file);
		return false;
	}
	rz_core_bin_export_info(core, RZ_MODE_SET);
	rz_bin_file_delete(core->bin, bf);
	return true;
}

RZ_API int rz_core_bin_set_by_name(RzCore *core, const char *name) {
	if (rz_bin_file_set_cur_by_name(core->bin, name)) {
		rz_core_bin_set_cur(core, rz_bin_cur(core->bin));
		return true;
	}
	return false;
}

RZ_API bool rz_core_bin_apply_info(RzCore *r, RzBinFile *binfile, ut32 mask) {
	rz_return_val_if_fail(r && binfile && mask, false);
	RzBinObject *binobj = binfile->o;
	RzBinInfo *info = binobj ? binobj->info : NULL;
	if (!info) {
		return false;
	}

	bool va = info->has_va;

	if (mask & RZ_CORE_BIN_ACC_STRINGS) {
		rz_core_bin_apply_strings(r, binfile);
	}
	if (mask & RZ_CORE_BIN_ACC_INFO) {
		rz_core_bin_apply_config(r, binfile);
	}
	if (mask & RZ_CORE_BIN_ACC_MAIN) {
		rz_core_bin_apply_main(r, binfile, va);
	}
	if (mask & RZ_CORE_BIN_ACC_DWARF) {
		rz_core_bin_apply_dwarf(r, binfile);
	}
	if (mask & RZ_CORE_BIN_ACC_ENTRIES) {
		rz_core_bin_apply_entry(r, binfile, va);
	}
	if (mask & RZ_CORE_BIN_ACC_MAPS) {
		rz_core_bin_apply_maps(r, binfile, va);
	}
	if (mask & RZ_CORE_BIN_ACC_SECTIONS) {
		rz_core_bin_apply_sections(r, binfile, va);
	}
	if (mask & RZ_CORE_BIN_ACC_RELOCS && rz_config_get_b(r->config, "bin.relocs")) {
		rz_core_bin_apply_relocs(r, binfile, va);
	}
	if (mask & RZ_CORE_BIN_ACC_IMPORTS) {
		rz_core_bin_apply_imports(r, binfile, va);
	}
	if (mask & RZ_CORE_BIN_ACC_SYMBOLS) {
		rz_core_bin_apply_symbols(r, binfile, va);
	}
	if (mask & RZ_CORE_BIN_ACC_CLASSES) {
		rz_core_bin_apply_classes(r, binfile);
	}
	if (mask & RZ_CORE_BIN_ACC_RESOURCES) {
		rz_core_bin_apply_resources(r, binfile);
	}

	return true;
}

RZ_API bool rz_core_bin_apply_all_info(RzCore *r, RzBinFile *binfile) {
	rz_return_val_if_fail(r && binfile, false);
	RzBinObject *binobj = binfile->o;
	RzBinInfo *info = binobj ? binobj->info : NULL;
	if (!info) {
		return false;
	}
	const char *arch = info->arch;
	ut16 bits = info->bits;
	ut64 baseaddr = rz_bin_get_baddr(r->bin);
	rz_config_set_i(r->config, "bin.baddr", baseaddr);
	sdb_num_add(r->sdb, "orig_baddr", baseaddr, 0);
	r->dbg->bp->baddr = baseaddr;
	rz_config_set(r->config, "asm.arch", arch);
	rz_config_set_i(r->config, "asm.bits", bits);
	rz_config_set(r->config, "analysis.arch", arch);
	if (info->cpu && *info->cpu) {
		rz_config_set(r->config, "analysis.cpu", info->cpu);
	} else {
		rz_config_set(r->config, "analysis.cpu", arch);
	}
	rz_asm_use(r->rasm, arch);

	rz_core_bin_apply_info(r, binfile, RZ_CORE_BIN_ACC_ALL);

	rz_core_bin_set_cur(r, binfile);
	return true;
}

RZ_API bool rz_core_bin_apply_strings(RzCore *r, RzBinFile *binfile) {
	rz_return_val_if_fail(r && binfile, false);
	RzBinObject *o = binfile->o;
	if (!o) {
		return false;
	}
	const RzList *l = core_bin_strings(r, binfile);
	if (!l) {
		return false;
	}
	int va = (binfile->o && binfile->o->info && binfile->o->info->has_va) ? VA_TRUE : VA_FALSE;
	rz_flag_space_set(r->flags, RZ_FLAGS_FS_STRINGS);
	rz_cons_break_push(NULL, NULL);
	RzListIter *iter;
	RzBinString *string;
	rz_list_foreach (l, iter, string) {
		ut64 vaddr = rva(o, string->paddr, string->vaddr, va);
		if (!rz_bin_string_filter(r->bin, string->string, string->length, vaddr)) {
			continue;
		}
		if (rz_cons_is_breaked()) {
			break;
		}
		rz_meta_set(r->analysis, RZ_META_TYPE_STRING, vaddr, string->size, string->string);
		char *f_name = strdup(string->string);
		rz_name_filter(f_name, -1, true);
		char *str;
		if (r->bin->prefix) {
			str = rz_str_newf("%s.str.%s", r->bin->prefix, f_name);
		} else {
			str = rz_str_newf("str.%s", f_name);
		}
		(void)rz_flag_set(r->flags, str, vaddr, string->size);
		free(str);
		free(f_name);
	}
	rz_cons_break_pop();
	return true;
}

static void sdb_concat_by_path(Sdb *s, const char *path) {
	Sdb *db = sdb_new(0, path, 0);
	sdb_merge(s, db);
	sdb_close(db);
	sdb_free(db);
}

RZ_API bool rz_core_bin_apply_config(RzCore *r, RzBinFile *binfile) {
	rz_return_val_if_fail(r && binfile, false);
	int v;
	char str[RZ_FLAG_NAME_SIZE];
	RzBinObject *obj = binfile->o;
	if (!obj) {
		return false;
	}
	RzBinInfo *info = obj->info;
	if (!info) {
		return false;
	}
	rz_config_set(r->config, "file.type", info->rclass);
	rz_config_set(r->config, "cfg.bigendian",
		info->big_endian ? "true" : "false");
	if (info->lang) {
		rz_config_set(r->config, "bin.lang", info->lang);
	}
	rz_config_set(r->config, "asm.os", info->os);
	if (info->rclass && !strcmp(info->rclass, "pe")) {
		rz_config_set(r->config, "analysis.cpp.abi", "msvc");
	} else {
		rz_config_set(r->config, "analysis.cpp.abi", "itanium");
	}
	rz_config_set(r->config, "asm.arch", info->arch);
	if (info->cpu && *info->cpu) {
		rz_config_set(r->config, "asm.cpu", info->cpu);
	}
	if (info->features && *info->features) {
		rz_config_set(r->config, "asm.features", info->features);
	}
	rz_config_set(r->config, "analysis.arch", info->arch);
	snprintf(str, RZ_FLAG_NAME_SIZE, "%i", info->bits);
	rz_config_set(r->config, "asm.bits", str);
	rz_config_set(r->config, "asm.dwarf",
		(RZ_BIN_DBG_STRIPPED & info->dbg_info) ? "false" : "true");
	v = rz_analysis_archinfo(r->analysis, RZ_ANALYSIS_ARCHINFO_ALIGN);
	if (v != -1) {
		rz_config_set_i(r->config, "asm.pcalign", v);
	}
	rz_core_analysis_type_init(r);
	rz_core_analysis_cc_init(r);
	if (info->default_cc && rz_analysis_cc_exist(r->analysis, info->default_cc)) {
		rz_config_set(r->config, "analysis.cc", info->default_cc);
	}
	const char *dir_prefix = rz_config_get(r->config, "dir.prefix");
	char *spath = rz_str_newf("%s/" RZ_SDB_FCNSIGN "/spec.sdb", dir_prefix);
	if (spath && rz_file_exists(spath)) {
		sdb_concat_by_path(r->analysis->sdb_fmts, spath);
	}
	free(spath);
	return true;
}

RZ_API bool rz_core_bin_apply_main(RzCore *r, RzBinFile *binfile, bool va) {
	rz_return_val_if_fail(r && binfile, false);
	RzBinObject *o = binfile->o;
	if (!o) {
		return false;
	}
	RzBinAddr *binmain = rz_bin_object_get_special_symbol(o, RZ_BIN_SPECIAL_SYMBOL_MAIN);
	if (!binmain) {
		return false;
	}
	ut64 addr = va ? rz_bin_object_addr_with_base(o, binmain->vaddr) : binmain->paddr;
	rz_flag_space_set(r->flags, RZ_FLAGS_FS_SYMBOLS);
	rz_flag_set(r->flags, "main", addr, r->blocksize);
	return true;
}

RZ_API bool rz_core_bin_apply_dwarf(RzCore *core, RzBinFile *binfile) {
	rz_return_val_if_fail(core && binfile, false);
	if (!rz_config_get_i(core->config, "bin.dbginfo") || !binfile->o) {
		return false;
	}
	RzBinObject *o = binfile->o;
	const RzBinSourceLineInfo *li = NULL;
	RzBinDwarfDebugAbbrev *da = rz_bin_dwarf_parse_abbrev(binfile);
	RzBinDwarfDebugInfo *info = da ? rz_bin_dwarf_parse_info(binfile, da) : NULL;
	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = rz_bin_dwarf_parse_loc(binfile, core->analysis->bits / 8);
	if (info) {
		RzAnalysisDwarfContext ctx = {
			.info = info,
			.loc = loc_table
		};
		rz_analysis_dwarf_process_info(core->analysis, &ctx);
	}
	if (loc_table) {
		rz_bin_dwarf_loc_free(loc_table);
	}
	RzBinDwarfLineInfo *lines = rz_bin_dwarf_parse_line(binfile, info, RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	rz_bin_dwarf_debug_info_free(info);
	if (lines) {
		// move all produced rows line info out (TODO: bin loading should do that)
		li = o->lines = lines->lines;
		lines->lines = NULL;
	}
	rz_bin_dwarf_debug_abbrev_free(da);
	if (!li) {
		return false;
	}
	return true;
}

static inline bool is_initfini(RzBinAddr *entry) {
	switch (entry->type) {
	case RZ_BIN_ENTRY_TYPE_INIT:
	case RZ_BIN_ENTRY_TYPE_FINI:
	case RZ_BIN_ENTRY_TYPE_PREINIT:
		return true;
	default:
		return false;
	}
}

RZ_API bool rz_core_bin_apply_entry(RzCore *core, RzBinFile *binfile, bool va) {
	rz_return_val_if_fail(core && binfile, false);
	RzBinObject *o = binfile->o;
	if (!o) {
		return false;
	}
	RzList *entries = o->entries;
	RzListIter *iter;
	RzBinAddr *entry = NULL;
	int i = 0, init_i = 0, fini_i = 0, preinit_i = 0;
	rz_list_foreach (entries, iter, entry) {
		ut64 paddr = entry->paddr;
		ut64 hpaddr = UT64_MAX;
		ut64 hvaddr = UT64_MAX;
		if (entry->hpaddr) {
			hpaddr = entry->hpaddr;
			if (entry->hvaddr) {
				hvaddr = rva(o, hpaddr, entry->hvaddr, va);
			}
		}
		ut64 at = rva(o, paddr, entry->vaddr, va);
		const char *type = rz_bin_entry_type_string(entry->type);
		if (!type) {
			type = "unknown";
		}
		rz_flag_space_set(core->flags, RZ_FLAGS_FS_SYMBOLS);
		char str[RZ_FLAG_NAME_SIZE];
		if (entry->type == RZ_BIN_ENTRY_TYPE_INIT) {
			snprintf(str, RZ_FLAG_NAME_SIZE, "entry.init%i", init_i++);
		} else if (entry->type == RZ_BIN_ENTRY_TYPE_FINI) {
			snprintf(str, RZ_FLAG_NAME_SIZE, "entry.fini%i", fini_i++);
		} else if (entry->type == RZ_BIN_ENTRY_TYPE_PREINIT) {
			snprintf(str, RZ_FLAG_NAME_SIZE, "entry.preinit%i", preinit_i++);
		} else {
			snprintf(str, RZ_FLAG_NAME_SIZE, "entry%i", i++);
		}
		rz_flag_set(core->flags, str, at, 1);
		if (is_initfini(entry) && hvaddr != UT64_MAX) {
			rz_meta_set(core->analysis, RZ_META_TYPE_DATA, hvaddr, entry->bits / 8, NULL);
		}
	}
	if (entry) {
		ut64 at = rva(o, entry->paddr, entry->vaddr, va);
		rz_core_seek(core, at, false);
	}
	return true;
}

static RzIODesc *find_reusable_file(RzIO *io, RzCoreFile *cf, const char *uri, int perm) {
	rz_return_val_if_fail(io && uri, NULL);
	if (!cf) {
		// valid case, but then we can't reuse anything
		return NULL;
	}
	void **it;
	rz_pvector_foreach (&cf->extra_files, it) {
		RzIODesc *desc = *it;
		if (desc->perm == perm && !strcmp(desc->uri, uri)) {
			return desc;
		}
	}
	return NULL;
}

/// Create null-map for excessive vsize over psize
static bool io_create_mem_map(RzIO *io, RZ_NULLABLE RzCoreFile *cf, RzBinMap *map, ut64 at) {
	rz_return_val_if_fail(io && map && map->vsize > map->psize, false);
	bool reused = false;
	ut64 gap = map->vsize - map->psize;
	char *uri = rz_str_newf("null://%" PFMT64u, gap);
	RzIOMap *iomap = NULL;
	RzIODesc *desc = find_reusable_file(io, cf, uri, map->perm);
	if (desc) {
		iomap = rz_io_map_add_batch(io, desc->fd, desc->perm, 0LL, at, gap);
		reused = true;
	} else {
		desc = rz_io_open_at(io, uri, map->perm, 0664, at, &iomap);
	}
	free(uri);
	if (!desc) {
		return false;
	}
	// check if the mapping failed
	if (!iomap) {
		if (!reused) {
			rz_io_desc_close(desc);
		}
		return false;
	}
	if (cf) {
		if (!reused) {
			rz_pvector_push(&cf->extra_files, desc);
		}
		rz_pvector_push(&cf->maps, iomap);
	}
	// update the io map's name to refer to the bin map
	if (map->name) {
		free(iomap->name);
		iomap->name = rz_str_newf("mmap.%s", map->name);
	}
	return true;
}

static void add_map(RzCore *core, RZ_NULLABLE RzCoreFile *cf, RzBinFile *bf, RzBinMap *map, ut64 addr, int fd) {
	RzIODesc *io_desc = rz_io_desc_get(core->io, fd);
	if (!io_desc || UT64_ADD_OVFCHK(map->psize, map->paddr) ||
		UT64_ADD_OVFCHK(map->vsize, addr) || !map->vsize) {
		return;
	}

	ut64 size = map->vsize;
	// if there is some part of the map that needs to be zeroed by the loader
	// we add a null map that takes care of it
	if (map->vsize > map->psize) {
		if (!io_create_mem_map(core->io, cf, map, addr + map->psize)) {
			return;
		}
		size = map->psize;
	}

	// It's a valid case to have vsize > 0 and psize == 0, which just creates a map of zeroes.
	if (!size) {
		return;
	}

	const char *prefix = "fmap";

	// open and use a different fd for virtual files
	if (map->vfile_name) {
		char *uri = rz_str_newf("vfile://%" PFMT32u "/%s", bf->id, map->vfile_name);
		if (!uri) {
			return;
		}
		ut32 perm = io_desc->perm;
		RzIODesc *desc = find_reusable_file(core->io, cf, uri, perm);
		if (!desc) {
			desc = rz_io_open_nomap(core->io, uri, perm, 0664);
			if (!desc) {
				free(uri);
				return;
			}
			if (cf) {
				rz_pvector_push(&cf->extra_files, desc);
			}
		}
		free(uri);
		fd = desc->fd;
		prefix = "vmap";
	}

	// then we map the part of the section that comes from the physical (or virtual) file
	char *map_name = map->name ? rz_str_newf("%s.%s", prefix, map->name) : rz_str_newf("%s.%d", prefix, fd);
	if (!map_name) {
		return;
	}

	int perm = map->perm;
	// workaround to force exec bit in text section
	if (map->name && strstr(map->name, "text")) {
		perm |= RZ_PERM_X;
	}

	if (size) {
		RzIOMap *iomap = rz_io_map_add_batch(core->io, fd, perm, map->paddr, addr, size);
		if (!iomap) {
			free(map_name);
			return;
		}
		free(iomap->name);
		iomap->name = map_name;
		if (cf) {
			rz_pvector_push(&cf->maps, iomap);
		}
	} else {
		free(map_name);
	}
	return;
}

RZ_API bool rz_core_bin_apply_maps(RzCore *core, RzBinFile *binfile, bool va) {
	rz_return_val_if_fail(core && binfile, false);
	RzIODesc *desc = rz_io_desc_get(core->io, binfile->fd);
	if (desc && rz_io_desc_is_dbg(desc)) {
		// In debug mode, mapping comes from the process, not the file
		return true;
	}
	RzBinObject *o = binfile->o;
	if (!o || !o->maps) {
		return false;
	}
	RzList *maps = o->maps;
	RzCoreFile *cf = rz_core_file_find_by_fd(core, binfile->fd);

	RzListIter *it;
	RzBinMap *map;
	// reverse because of the way io handles maps
	rz_list_foreach_prev(maps, it, map) {
		int va_map = va ? VA_TRUE : VA_FALSE;
		if (va && !(map->perm & RZ_PERM_R)) {
			va_map = VA_NOREBASE;
		}
		ut64 addr = rva(o, map->paddr, map->vaddr, va_map);
		add_map(core, cf, binfile, map, addr, binfile->fd);
	}
	rz_io_update(core->io);
	return true;
}

/**
 * \brief Write a section-specific permission string like srwx.
 * \param dst must be at least 5 bytes large
 */
static void section_perms_str(char *dst, int perms) {
	dst[0] = (perms & RZ_PERM_SHAR) ? 's' : '-';
	dst[1] = (perms & RZ_PERM_R) ? 'r' : '-';
	dst[2] = (perms & RZ_PERM_W) ? 'w' : '-';
	dst[3] = (perms & RZ_PERM_X) ? 'x' : '-';
	dst[4] = '\0';
}

RZ_API bool rz_core_bin_apply_sections(RzCore *core, RzBinFile *binfile, bool va) {
	rz_return_val_if_fail(core && binfile, false);
	RzBinObject *o = binfile->o;
	if (!o) {
		return false;
	}
	RzList *sections = o->sections;

	// make sure both flag spaces exist.
	rz_flag_space_set(core->flags, RZ_FLAGS_FS_SEGMENTS);
	rz_flag_space_set(core->flags, RZ_FLAGS_FS_SECTIONS);

	bool segments_only = true;
	RzListIter *iter;
	RzBinSection *section;
	rz_list_foreach (sections, iter, section) {
		if (!section->is_segment) {
			segments_only = false;
			break;
		}
	}

	int section_index = 0;
	rz_list_foreach (sections, iter, section) {
		int va_sect = va ? VA_TRUE : VA_FALSE;
		if (va && !(section->perm & RZ_PERM_R)) {
			va_sect = VA_NOREBASE;
		}
		ut64 addr = rva(o, section->paddr, section->vaddr, va_sect);

		rz_name_filter(section->name, strlen(section->name) + 1, false);

		char perms[5];
		section_perms_str(perms, section->perm);
		if (section->format) {
			// This is really slow if section vsize is HUGE
			if (section->vsize < 1024 * 1024 * 2) {
				rz_core_cmdf(core, "%s @ 0x%" PFMT64x, section->format, section->vaddr);
			}
		}
		const char *type;
		if (section->is_segment) {
			type = "segment";
			rz_flag_space_set(core->flags, RZ_FLAGS_FS_SEGMENTS);
		} else {
			type = "section";
			rz_flag_space_set(core->flags, RZ_FLAGS_FS_SECTIONS);
		}
		char *str;
		if (core->bin->prefix) {
			str = rz_str_newf("%s.%s.%s", core->bin->prefix, type, section->name);
		} else {
			str = rz_str_newf("%s.%s", type, section->name);
		}
		ut64 size = core->io->va ? section->vsize : section->size;
		rz_flag_set(core->flags, str, addr, size);
		RZ_FREE(str);

		if (!section->is_segment || segments_only) {
			char *pfx = core->bin->prefix;
			str = rz_str_newf("[%02d] %s %s size %" PFMT64d " named %s%s%s",
				section_index++, perms, type, size,
				pfx ? pfx : "", pfx ? "." : "", section->name);
			rz_meta_set(core->analysis, RZ_META_TYPE_COMMENT, addr, 1, str);
			RZ_FREE(str);
		}
	}

	return true;
}

/*
 * Decide whether a meta item should be created for the given reloc addr
 * and figure out what size it should have.
 * \return whether to put a meta item for the given reloc addr
 */
static bool meta_for_reloc(RzCore *r, RzBinObject *binobj, RzBinReloc *reloc, bool is_target, ut64 addr, RZ_OUT ut64 *size) {
	rz_return_val_if_fail(binobj, false);
	RzBinInfo *info = binobj ? binobj->info : NULL;

	int cdsz;
	if (is_target) {
		// target meta uses the bit size, these are the manually created ones
		cdsz = info ? (info->bits / 8) : 0;
	} else {
		// source meta uses the actual size of the reloc
		cdsz = rz_bin_reloc_size(reloc) / 8;
	}
	if (cdsz <= 0) {
		return false;
	}

	// only set meta if it's not in an executable section
	RzIOMap *map = rz_io_map_get(r->io, addr);
	if (!map || map->perm & RZ_PERM_X) {
		return false;
	}

	*size = cdsz;
	return true;
}

static bool is_section_symbol(RzBinSymbol *s) {
	/* workaround for some bin plugs (e.g. ELF) */
	if (!s || *s->name) {
		return false;
	}
	return (s->type && !strcmp(s->type, RZ_BIN_TYPE_SECTION_STR));
}

static bool is_special_symbol(RzBinSymbol *s) {
	return s->type && !strcmp(s->type, RZ_BIN_TYPE_SPECIAL_SYM_STR);
}

static bool is_file_symbol(RzBinSymbol *s) {
	/* workaround for some bin plugs (e.g. ELF) */
	return (s && s->type && !strcmp(s->type, RZ_BIN_TYPE_FILE_STR));
}

static bool is_section_reloc(RzBinReloc *r) {
	return is_section_symbol(r->symbol);
}

static bool is_file_reloc(RzBinReloc *r) {
	return is_file_symbol(r->symbol);
}

static ut8 bin_reloc_size(RzBinReloc *reloc) {
#define CASE(T) \
	case RZ_BIN_RELOC_##T: return (T) / 8
	switch (reloc->type) {
		CASE(8);
		CASE(16);
		CASE(32);
		CASE(64);
	}
	return 0;
#undef CASE
}

static char *resolveModuleOrdinal(Sdb *sdb, const char *module, int ordinal) {
	Sdb *db = sdb;
	char *foo = sdb_get(db, sdb_fmt("%d", ordinal), 0);
	return (foo && *foo) ? foo : NULL;
}

// name can be optionally used to explicitly set the used base name (for example for demangling), otherwise the import name will be used.
static char *construct_reloc_name(RZ_NONNULL RzBinReloc *reloc, RZ_NULLABLE const char *name) {
	RzStrBuf *buf = rz_strbuf_new("");

	// (optional) libname_
	if (reloc->import && reloc->import->libname) {
		rz_strbuf_appendf(buf, "%s_", reloc->import->libname);
	} else if (reloc->symbol && reloc->symbol->libname) {
		rz_strbuf_appendf(buf, "%s_", reloc->symbol->libname);
	}

	// actual name
	if (name) {
		rz_strbuf_append(buf, name);
	} else if (reloc->import && reloc->import->name && *reloc->import->name) {
		rz_strbuf_append(buf, reloc->import->name);
	} else if (reloc->symbol && reloc->symbol->name && *reloc->symbol->name) {
		rz_strbuf_appendf(buf, "%s", reloc->symbol->name);
	} else if (reloc->is_ifunc) {
		// addend is the function pointer for the resolving ifunc
		rz_strbuf_appendf(buf, "ifunc_%" PFMT64x, reloc->addend);
	} else {
		rz_strbuf_set(buf, "");
	}

	return rz_strbuf_drain(buf);
}

static void reloc_set_flag(RzCore *r, RzBinReloc *reloc, const char *prefix, ut64 flag_addr) {
	int bin_demangle = rz_config_get_i(r->config, "bin.demangle");
	bool keep_lib = rz_config_get_i(r->config, "bin.demangle.libs");
	const char *lang = rz_config_get(r->config, "bin.lang");
	char *reloc_name = construct_reloc_name(reloc, NULL);
	if (RZ_STR_ISEMPTY(reloc_name)) {
		free(reloc_name);
		return;
	}
	char flagname[RZ_FLAG_NAME_SIZE];
	if (r->bin->prefix) {
		snprintf(flagname, sizeof(flagname), "%s.%s.%s", r->bin->prefix, prefix, reloc_name);
	} else {
		snprintf(flagname, sizeof(flagname), "%s.%s", prefix, reloc_name);
	}
	char *demname = NULL;
	if (bin_demangle) {
		demname = rz_bin_demangle(r->bin->cur, lang, flagname, flag_addr, keep_lib);
		if (demname) {
			snprintf(flagname, sizeof(flagname), "reloc.%s", demname);
		}
	}
	rz_name_filter(flagname, 0, true);
	RzFlagItem *existing = rz_flag_get(r->flags, flagname);
	if (existing && existing->offset == flag_addr) {
		// Mostly important for target flags.
		// We don't want hundreds of reloc.target.<fcnname>.<xyz> flags at the same location
		return;
	}
	RzFlagItem *fi = rz_flag_set_next(r->flags, flagname, flag_addr, bin_reloc_size(reloc));
	if (demname) {
		rz_flag_item_set_realname(fi, demname);
		free(demname);
	} else {
		rz_flag_item_set_realname(fi, reloc_name);
	}
	free(reloc_name);
}

static void set_bin_relocs(RzCore *r, RzBinObject *o, RzBinReloc *reloc, bool va, Sdb **db, char **sdb_module) {
	bool is_pe = true;

	if (is_pe && reloc->import && reloc->import->name && reloc->import->libname && rz_str_startswith(reloc->import->name, "Ordinal_")) {
		char *module = reloc->import->libname;
		rz_str_case(module, false);

		// strip trailing ".dll"
		size_t module_len = strlen(module);
		if (module_len > 4 && !strcmp(module + module_len - 4, ".dll")) {
			module[module_len - 4] = '\0';
		}

		const char *import = reloc->import->name + strlen("Ordinal_");
		if (import) {
			char *filename = NULL;
			int ordinal = atoi(import);
			if (!*sdb_module || strcmp(module, *sdb_module)) {
				sdb_free(*db);
				*db = NULL;
				free(*sdb_module);
				*sdb_module = strdup(module);
				/* always lowercase */
				filename = sdb_fmt("%s.sdb", module);
				rz_str_case(filename, false);
				if (rz_file_exists(filename)) {
					*db = sdb_new(NULL, filename, 0);
				} else {
					const char *dirPrefix = rz_sys_prefix(NULL);
					filename = sdb_fmt(RZ_JOIN_4_PATHS("%s", RZ_SDB_FORMAT, "dll", "%s.sdb"),
						dirPrefix, module);
					if (rz_file_exists(filename)) {
						*db = sdb_new(NULL, filename, 0);
					}
				}
			}
			if (*db) {
				// ordinal-1 because we enumerate starting at 0
				char *symname = resolveModuleOrdinal(*db, module, ordinal - 1); // uses sdb_get
				if (symname) {
					if (r->bin->prefix) {
						reloc->import->name = rz_str_newf("%s.%s", r->bin->prefix, symname);
						RZ_FREE(symname);
					} else {
						reloc->import->name = symname;
					}
				}
			}
		}
		rz_analysis_hint_set_size(r->analysis, reloc->vaddr, 4);
		rz_meta_set(r->analysis, RZ_META_TYPE_DATA, reloc->vaddr, 4, NULL);
	}

	ut64 addr = rva(o, reloc->paddr, reloc->vaddr, va);
	reloc_set_flag(r, reloc, "reloc", addr);
	if (rz_bin_reloc_has_target(reloc)) {
		reloc_set_flag(r, reloc, "reloc.target", reloc->target_vaddr);
	}
}

RZ_API bool rz_core_bin_apply_relocs(RzCore *core, RzBinFile *binfile, bool va_bool) {
	rz_return_val_if_fail(core && binfile, false);
	RzBinObject *o = binfile->o;
	if (!o) {
		return false;
	}

	int va = VA_TRUE; // XXX relocs always vaddr?
	RzBinRelocStorage *relocs = rz_bin_object_patch_relocs(binfile, o);
	if (!relocs) {
		relocs = o->relocs;
		if (!relocs) {
			return false;
		}
	}

	rz_flag_space_set(core->flags, RZ_FLAGS_FS_RELOCS);

	Sdb *db = NULL;
	char *sdb_module = NULL;
	for (size_t i = 0; i < relocs->relocs_count; i++) {
		RzBinReloc *reloc = relocs->relocs[i];
		ut64 addr = rva(o, reloc->paddr, reloc->vaddr, va);
		if ((is_section_reloc(reloc) || is_file_reloc(reloc))) {
			/*
			 * Skip section reloc because they will have their own flag.
			 * Skip also file reloc because not useful for now.
			 */
			continue;
		}
		set_bin_relocs(core, o, reloc, va, &db, &sdb_module);
		ut64 meta_sz;
		if (meta_for_reloc(core, o, reloc, false, addr, &meta_sz)) {
			rz_meta_set(core->analysis, RZ_META_TYPE_DATA, addr, meta_sz, NULL);
		}
		if (va && rz_bin_reloc_has_target(reloc) && meta_for_reloc(core, o, reloc, true, reloc->target_vaddr, &meta_sz)) {
			rz_meta_set(core->analysis, RZ_META_TYPE_DATA, reloc->target_vaddr, meta_sz, NULL);
		}
	}
	RZ_FREE(sdb_module);
	sdb_free(db);

	return relocs != NULL;
}

RZ_API bool rz_core_bin_apply_imports(RzCore *core, RzBinFile *binfile, bool va) {
	rz_return_val_if_fail(core && binfile, false);
	RzBinObject *o = binfile->o;
	RzBinInfo *info = o ? o->info : NULL;
	if (!info) {
		return false;
	}
	int cdsz = info->bits / 8;
	if (cdsz <= 0) {
		return false;
	}
	RzListIter *iter;
	RzBinImport *import;
	RzList *imports = o->imports;
	rz_list_foreach (imports, iter, import) {
		if (!import->libname || !strstr(import->libname, ".dll")) {
			continue;
		}
		RzBinSymbol *sym = rz_bin_object_get_symbol_of_import(o, import);
		if (!sym) {
			continue;
		}
		ut64 addr = rva(o, sym->paddr, sym->vaddr, va ? VA_TRUE : VA_FALSE);
		rz_meta_set(core->analysis, RZ_META_TYPE_DATA, addr, cdsz, NULL);
	}
	return true;
}

static const char *get_prefix_for_sym(RzBinSymbol *sym) {
	if (sym) {
		// workaround for ELF
		if (sym->type) {
			if (!strcmp(sym->type, RZ_BIN_TYPE_NOTYPE_STR)) {
				return sym->is_imported ? "loc.imp" : "loc";
			}
			if (!strcmp(sym->type, RZ_BIN_TYPE_OBJECT_STR)) {
				return sym->is_imported ? "obj.imp" : "obj";
			}
		}
		return sym->is_imported ? "sym.imp" : "sym";
	}
	return "sym";
}

#define MAXFLAG_LEN_DEFAULT 128

static char *construct_symbol_flagname(const char *pfx, const char *libname, const char *symname, int len) {
	char *r = rz_str_newf("%s.%s%s%s", pfx, libname ? libname : "", libname ? "_" : "", symname);
	if (!r) {
		return NULL;
	}
	rz_name_filter(r, len, true); // maybe unnecessary..
	char *R = __filterQuotedShell(r);
	free(r);
	return R;
}

typedef struct {
	const char *pfx; // prefix for flags
	char *name; // raw symbol name
	char *libname; // name of the lib this symbol is specific to, if any
	char *nameflag; // flag name for symbol
	char *demname; // demangled raw symbol name
	char *demflag; // flag name for demangled symbol
	char *classname; // classname
	char *classflag; // flag for classname
	char *methname; // methods [class]::[method]
	char *methflag; // methods flag sym.[class].[method]
} SymName;

static void sym_name_init(RzCore *r, SymName *sn, RzBinSymbol *sym, const char *lang) {
	if (!r || !sym || !sym->name) {
		return;
	}
	int bin_demangle = lang != NULL;
	bool keep_lib = rz_config_get_i(r->config, "bin.demangle.libs");
	sn->name = rz_str_newf("%s%s", sym->is_imported ? "imp." : "", sym->name);
	sn->libname = sym->libname ? strdup(sym->libname) : NULL;
	const char *pfx = get_prefix_for_sym(sym);
	sn->nameflag = construct_symbol_flagname(pfx, sym->libname, rz_bin_symbol_name(sym), MAXFLAG_LEN_DEFAULT);
	if (sym->classname && sym->classname[0]) {
		sn->classname = strdup(sym->classname);
		sn->classflag = rz_str_newf("sym.%s.%s", sn->classname, sn->name);
		rz_name_filter(sn->classflag, MAXFLAG_LEN_DEFAULT, true);
		const char *name = sym->dname ? sym->dname : sym->name;
		sn->methname = rz_str_newf("%s::%s", sn->classname, name);
		sn->methflag = rz_str_newf("sym.%s.%s", sn->classname, name);
		rz_name_filter(sn->methflag, strlen(sn->methflag), true);
	} else {
		sn->classname = NULL;
		sn->classflag = NULL;
		sn->methname = NULL;
		sn->methflag = NULL;
	}
	sn->demname = NULL;
	sn->demflag = NULL;
	if (bin_demangle && sym->paddr) {
		sn->demname = rz_bin_demangle(r->bin->cur, lang, sn->name, sym->vaddr, keep_lib);
		if (sn->demname) {
			sn->demflag = construct_symbol_flagname(pfx, sym->libname, sn->demname, -1);
		}
	}
}

static void sym_name_fini(SymName *sn) {
	RZ_FREE(sn->name);
	RZ_FREE(sn->libname);
	RZ_FREE(sn->nameflag);
	RZ_FREE(sn->demname);
	RZ_FREE(sn->demflag);
	RZ_FREE(sn->classname);
	RZ_FREE(sn->classflag);
	RZ_FREE(sn->methname);
	RZ_FREE(sn->methflag);
}

static void handle_arm_special_symbol(RzCore *core, RzBinObject *o, RzBinSymbol *symbol, int va) {
	ut64 addr = rva(o, symbol->paddr, symbol->vaddr, va);
	if (!strcmp(symbol->name, "$a")) {
		rz_analysis_hint_set_bits(core->analysis, addr, 32);
	} else if (!strcmp(symbol->name, "$x")) {
		rz_analysis_hint_set_bits(core->analysis, addr, 64);
	} else if (!strcmp(symbol->name, "$t")) {
		rz_analysis_hint_set_bits(core->analysis, addr, 16);
	} else if (!strcmp(symbol->name, "$d")) {
		// TODO: we could add data meta type at addr, but sometimes $d
		// is in the middle of the code and it would make the code less
		// readable.
	} else {
		if (core->bin->verbose) {
			RZ_LOG_WARN("Special symbol %s not handled\n", symbol->name);
		}
	}
}

static void handle_arm_hint(RzCore *core, RzBinObject *o, ut64 paddr, ut64 vaddr, int bits, int va) {
	RzBinInfo *info = o->info;
	if (!info) {
		return;
	}
	if (info->bits > 32) { // we look at 16 or 32 bit only
		return;
	}

	int force_bits = 0;
	ut64 addr = rva(o, paddr, vaddr, va);
	if (paddr & 1 || bits == 16) {
		force_bits = 16;
	} else if (info->bits == 16 && bits == 32) {
		force_bits = 32;
	} else if (!(paddr & 1) && bits == 32) {
		force_bits = 32;
	}
	if (force_bits) {
		rz_analysis_hint_set_bits(core->analysis, addr, force_bits);
	}
}

static void handle_arm_symbol(RzCore *core, RzBinObject *o, RzBinSymbol *symbol, int va) {
	handle_arm_hint(core, o, symbol->paddr, symbol->vaddr, symbol->bits, va);
}

static void handle_arm_entry(RzCore *core, RzBinObject *o, RzBinAddr *entry, int va) {
	handle_arm_hint(core, o, entry->paddr, entry->vaddr, entry->bits, va);
}

static void select_flag_space(RzCore *core, RzBinSymbol *symbol) {
	if (symbol->is_imported) {
		rz_flag_space_push(core->flags, RZ_FLAGS_FS_IMPORTS);
	} else if (symbol->type && !strcmp(symbol->type, RZ_BIN_TYPE_SECTION_STR)) {
		rz_flag_space_push(core->flags, RZ_FLAGS_FS_SYMBOLS_SECTIONS);
	} else {
		rz_flag_space_push(core->flags, RZ_FLAGS_FS_SYMBOLS);
	}
}

RZ_API bool rz_core_bin_apply_symbols(RzCore *core, RzBinFile *binfile, bool va) {
	rz_return_val_if_fail(core && binfile, false);
	RzBinObject *o = binfile->o;
	if (!o || !o->info) {
		return false;
	}
	RzBinInfo *info = o->info;

	bool is_arm = info && info->arch && !strncmp(info->arch, "arm", 3);
	bool bin_demangle = rz_config_get_b(core->config, "bin.demangle");
	const char *lang = bin_demangle ? rz_config_get(core->config, "bin.lang") : NULL;

	rz_spaces_push(&core->analysis->meta_spaces, "bin");
	rz_flag_space_set(core->flags, RZ_FLAGS_FS_SYMBOLS);

	RzList *symbols = rz_bin_get_symbols(core->bin);
	size_t count = 0;
	RzListIter *iter;
	RzBinSymbol *symbol;
	rz_list_foreach (symbols, iter, symbol) {
		if (!symbol->name) {
			continue;
		}
		ut64 addr = rva(o, symbol->paddr, symbol->vaddr, va);
		SymName sn = { 0 };
		count++;
		sym_name_init(core, &sn, symbol, lang);
		char *rz_symbol_name = rz_str_escape_utf8(sn.name, false, true);

		if (is_section_symbol(symbol) || is_file_symbol(symbol)) {
			/*
			 * Skip section symbols because they will have their own flag.
			 * Skip also file symbols because not useful for now.
			 */
		} else if (is_special_symbol(symbol)) {
			if (is_arm) {
				handle_arm_special_symbol(core, o, symbol, va);
			}
		} else {
			// TODO: provide separate API in RzBinPlugin to let plugins handle analysis hints/metadata
			if (is_arm) {
				handle_arm_symbol(core, o, symbol, va);
			}
			select_flag_space(core, symbol);
			/* If that's a Classed symbol (method or so) */
			if (sn.classname) {
				RzFlagItem *fi = rz_flag_get(core->flags, sn.methflag);
				if (core->bin->prefix) {
					char *prname = rz_str_newf("%s.%s", core->bin->prefix, sn.methflag);
					rz_name_filter(sn.methflag, -1, true);
					free(sn.methflag);
					sn.methflag = prname;
				}
				if (fi) {
					rz_flag_item_set_realname(fi, sn.methname);
					if ((fi->offset - core->flags->base) == addr) {
						rz_flag_unset(core->flags, fi);
					}
				} else {
					fi = rz_flag_set(core->flags, sn.methflag, addr, symbol->size);
					char *comment = (fi && fi->comment) ? strdup(fi->comment) : NULL;
					if (comment) {
						rz_flag_item_set_comment(fi, comment);
						RZ_FREE(comment);
					}
				}
			} else {
				const char *n = sn.demname ? sn.demname : symbol->name;
				const char *fn = sn.demflag ? sn.demflag : sn.nameflag;
				char *fnp = (core->bin->prefix) ? rz_str_newf("%s.%s", core->bin->prefix, fn) : strdup(fn ? fn : "");
				RzFlagItem *fi = rz_flag_set(core->flags, fnp, addr, symbol->size);
				if (fi) {
					rz_flag_item_set_realname(fi, n);
					fi->demangled = (bool)(size_t)sn.demname;
				} else {
					if (fn) {
						eprintf("[Warning] Can't find flag (%s)\n", fn);
					}
				}
				free(fnp);
			}
			if (sn.demname) {
				ut64 size = symbol->size ? symbol->size : 1;
				rz_meta_set(core->analysis, RZ_META_TYPE_COMMENT, addr, size, sn.demname);
			}
			rz_flag_space_pop(core->flags);
		}
		sym_name_fini(&sn);
		free(rz_symbol_name);
	}

	//handle thumb and arm for entry point since they are not present in symbols
	if (is_arm) {
		RzBinAddr *entry;
		rz_list_foreach (o->entries, iter, entry) {
			handle_arm_entry(core, o, entry, va);
		}
	}

	rz_spaces_pop(&core->analysis->meta_spaces);
	return true;
}

RZ_API bool rz_core_bin_apply_classes(RzCore *core, RzBinFile *binfile) {
	rz_return_val_if_fail(core && binfile, false);
	RzBinObject *o = binfile->o;
	RzList *cs = o ? o->classes : NULL;
	if (!cs) {
		return false;
	}
	if (!rz_config_get_b(core->config, "bin.classes")) {
		return false;
	}

	rz_flag_space_set(core->flags, RZ_FLAGS_FS_CLASSES);

	RzListIter *iter;
	RzBinClass *c;
	rz_list_foreach (cs, iter, c) {
		if (!c || !c->name || !c->name[0]) {
			continue;
		}

		// set class flag
		char *classname = rz_str_newf("class.%s", c->name);
		if (!classname) {
			break;
		}
		rz_name_filter(classname, 0, true);
		rz_flag_set(core->flags, classname, c->addr, 1);
		free(classname);

		// set method flags
		RzBinSymbol *sym;
		RzListIter *iter2;
		rz_list_foreach (c->methods, iter2, sym) {
			char *fn = rz_core_bin_method_build_flag_name(c, sym);
			if (fn) {
				rz_flag_set(core->flags, fn, sym->vaddr, 1);
				free(fn);
			}
		}
	}

	return true;
}

RZ_API bool rz_core_bin_apply_resources(RzCore *core, RzBinFile *binfile) {
	rz_return_val_if_fail(core && binfile, false);
	RzBinObject *o = binfile->o;
	RzBinInfo *info = o ? o->info : NULL;
	if (!info || !info->rclass) {
		return false;
	}
	if (strncmp("pe", info->rclass, 2)) {
		// only pe will be applied for now
		return true;
	}
	Sdb *sdb = NULL;
	int index = 0;
	const char *pe_path = "bin/cur/info/pe_resource";
	if (!(sdb = sdb_ns_path(core->sdb, pe_path, 0))) {
		return false;
	}
	rz_flag_space_set(core->flags, RZ_FLAGS_FS_RESOURCES);
	while (true) {
		char key[64];
		char *timestr = sdb_get(sdb, rz_strf(key, "resource.%d.timestr", index), 0);
		if (!timestr) {
			break;
		}
		ut64 vaddr = sdb_num_get(sdb, rz_strf(key, "resource.%d.vaddr", index), 0);
		int size = (int)sdb_num_get(sdb, rz_strf(key, "resource.%d.size", index), 0);
		rz_flag_set(core->flags, rz_strf(key, "resource.%d", index), vaddr, size);
		index++;
	}
	return true;
}

RZ_API int rz_core_bin_set_cur(RzCore *core, RzBinFile *binfile) {
	if (!core->bin) {
		return false;
	}
	if (!binfile) {
		// Find first available binfile
		ut32 fd = rz_core_file_cur_fd(core);
		binfile = fd != (ut32)-1
			? rz_bin_file_find_by_fd(core->bin, fd)
			: NULL;
		if (!binfile) {
			return false;
		}
	}
	rz_bin_file_set_cur_binfile(core->bin, binfile);
	return true;
}

static void _print_strings(RzCore *r, RZ_NULLABLE const RzList *list, PJ *pj, int mode, int va) {
	bool b64str = rz_config_get_i(r->config, "bin.b64str");
	RzTable *table = rz_core_table(r);
	rz_return_if_fail(table);
	RzBin *bin = r->bin;
	RzBinObject *obj = rz_bin_cur_object(bin);
	RzListIter *iter;
	RzBinString *string;
	RzBinSection *section;

	if (IS_MODE_JSON(mode)) {
		pj_a(pj);
	} else if (IS_MODE_RZCMD(mode)) {
		rz_cons_println("fs strings");
	} else if (IS_MODE_NORMAL(mode)) {
		rz_cons_println("[Strings]");
		rz_table_set_columnsf(table, "nXXnnsss", "nth", "paddr", "vaddr", "len", "size", "section", "type", "string");
	}
	RzBinString b64 = { 0 };
	rz_list_foreach (list, iter, string) {
		const char *section_name, *type_string;
		ut64 paddr, vaddr;
		paddr = string->paddr;
		vaddr = obj ? rva(obj, paddr, string->vaddr, va) : paddr;
		if (!rz_bin_string_filter(bin, string->string, string->length, vaddr)) {
			continue;
		}

		section = obj ? rz_bin_get_section_at(obj, paddr, 0) : NULL;
		section_name = section ? section->name : "";
		type_string = rz_bin_string_type(string->type);
		if (b64str) {
			ut8 *s = rz_base64_decode_dyn(string->string, -1);
			if (s && *s && IS_PRINTABLE(*s)) {
				// TODO: add more checks
				free(b64.string);
				memcpy(&b64, string, sizeof(b64));
				b64.string = (char *)s;
				b64.size = strlen(b64.string);
				string = &b64;
			}
		}
		if (IS_MODE_SIMPLE(mode)) {
			rz_cons_printf("0x%" PFMT64x " %d %d %s\n", vaddr,
				string->size, string->length, string->string);
		} else if (IS_MODE_SIMPLEST(mode)) {
			rz_cons_println(string->string);
		} else if (IS_MODE_JSON(mode)) {
			int *block_list;
			pj_o(pj);
			pj_kn(pj, "vaddr", vaddr);
			pj_kn(pj, "paddr", paddr);
			pj_kn(pj, "ordinal", string->ordinal);
			pj_kn(pj, "size", string->size);
			pj_kn(pj, "length", string->length);
			pj_ks(pj, "section", section_name);
			pj_ks(pj, "type", type_string);
			// data itself may be encoded so use pj_ks
			pj_ks(pj, "string", string->string);

			switch (string->type) {
			case RZ_STRING_TYPE_UTF8:
			case RZ_STRING_TYPE_WIDE:
			case RZ_STRING_TYPE_WIDE32:
				block_list = rz_utf_block_list((const ut8 *)string->string, -1, NULL);
				if (block_list) {
					if (block_list[0] == 0 && block_list[1] == -1) {
						/* Don't include block list if
						   just Basic Latin (0x00 - 0x7F) */
						RZ_FREE(block_list);
						break;
					}
					int *block_ptr = block_list;
					pj_k(pj, "blocks");
					pj_a(pj);
					for (; *block_ptr != -1; block_ptr++) {
						const char *utfName = rz_utf_block_name(*block_ptr);
						pj_s(pj, utfName ? utfName : "");
					}
					pj_end(pj);
					RZ_FREE(block_list);
				}
			}
			pj_end(pj);
		} else if (IS_MODE_RZCMD(mode)) {
			char *f_name = strdup(string->string);
			rz_name_filter(f_name, RZ_FLAG_NAME_SIZE, true);
			char *str = (r->bin->prefix)
				? rz_str_newf("%s.str.%s", r->bin->prefix, f_name)
				: rz_str_newf("str.%s", f_name);
			rz_cons_printf("f %s %u 0x%08" PFMT64x "\n"
				       "Cs %u @ 0x%08" PFMT64x "\n",
				str, string->size, vaddr,
				string->size, vaddr);
			free(str);
			free(f_name);
		} else {
			int *block_list;
			char *str = string->string;
			char *no_dbl_bslash_str = NULL;
			if (!r->print->esc_bslash) {
				char *ptr;
				for (ptr = str; *ptr; ptr++) {
					if (*ptr != '\\') {
						continue;
					}
					if (*(ptr + 1) == '\\') {
						if (!no_dbl_bslash_str) {
							no_dbl_bslash_str = strdup(str);
							if (!no_dbl_bslash_str) {
								break;
							}
							ptr = no_dbl_bslash_str + (ptr - str);
						}
						memmove(ptr + 1, ptr + 2, strlen(ptr + 2) + 1);
					}
				}
				if (no_dbl_bslash_str) {
					str = no_dbl_bslash_str;
				}
			}

			RzStrBuf *buf = rz_strbuf_new(str);
			switch (string->type) {
			case RZ_STRING_TYPE_UTF8:
			case RZ_STRING_TYPE_WIDE:
			case RZ_STRING_TYPE_WIDE32:
				block_list = rz_utf_block_list((const ut8 *)string->string, -1, NULL);
				if (block_list) {
					if (block_list[0] == 0 && block_list[1] == -1) {
						/* Don't show block list if
						   just Basic Latin (0x00 - 0x7F) */
						break;
					}
					int *block_ptr = block_list;
					rz_strbuf_append(buf, " blocks=");
					for (; *block_ptr != -1; block_ptr++) {
						if (block_ptr != block_list) {
							rz_strbuf_append(buf, ",");
						}
						const char *name = rz_utf_block_name(*block_ptr);
						rz_strbuf_appendf(buf, "%s", name ? name : "");
					}
					free(block_list);
				}
				break;
			}
			char *bufstr = rz_strbuf_drain(buf);
			rz_table_add_rowf(table, "nXXddsss", (ut64)string->ordinal, paddr, vaddr,
				(int)string->length, (int)string->size, section_name,
				type_string, bufstr);
			free(bufstr);
			free(no_dbl_bslash_str);
		}
	}
	RZ_FREE(b64.string);
	if (IS_MODE_JSON(mode)) {
		pj_end(pj);
	} else if (IS_MODE_NORMAL(mode)) {
		if (r->table_query) {
			rz_table_query(table, r->table_query);
		}
		char *s = rz_table_tostring(table);
		if (s) {
			rz_cons_print(s);
			free(s);
		}
	}
	rz_table_free(table);
}

static bool bin_raw_strings(RzCore *r, PJ *pj, int mode, int va) {
	RzBinFile *bf = rz_bin_cur(r->bin);
	bool new_bf = false;
	if (bf && strstr(bf->file, "malloc://")) {
		//sync bf->buf to search string on it
		ut8 *tmp = RZ_NEWS(ut8, bf->size);
		if (!tmp) {
			return false;
		}
		rz_io_read_at(r->io, 0, tmp, bf->size);
		rz_buf_write_at(bf->buf, 0, tmp, bf->size);
	}
	if (!r->file) {
		eprintf("Core file not open\n");
		if (IS_MODE_JSON(mode)) {
			pj_a(pj);
			pj_end(pj);
			return true;
		}
		return false;
	}
	if (!bf) {
		// TODO: manually creating an RzBinFile like this is a hack and abuse of RzBin API
		// If we don't want to use an RzBinFile for searching strings, the raw strings search
		// should be refactored out of bin.
		bf = RZ_NEW0(RzBinFile);
		if (!bf) {
			return false;
		}
		RzIODesc *desc = rz_io_desc_get(r->io, r->file->fd);
		if (!desc) {
			free(bf);
			return false;
		}
		bf->file = strdup(desc->name);
		bf->size = rz_io_desc_size(desc);
		if (bf->size == UT64_MAX) {
			free(bf);
			return false;
		}
		bf->buf = rz_buf_new_with_io(&r->bin->iob, r->file->fd);
		bf->o = NULL;
		bf->rbin = r->bin;
		new_bf = true;
		va = false;
	}
	RzList *l = rz_bin_raw_strings(bf, 0);
	_print_strings(r, l, pj, mode, va);
	rz_list_free(l);
	if (new_bf) {
		rz_buf_free(bf->buf);
		free(bf->file);
		free(bf);
	}
	return true;
}

/**
 * Strings for the given file, respecting settings like bin.strings
 */
static RZ_NULLABLE RZ_BORROW const RzList *core_bin_strings(RzCore *r, RzBinFile *file) {
	rz_return_val_if_fail(r && file, false);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(file);
	if (!plugin || !rz_config_get_i(r->config, "bin.strings")) {
		return NULL;
	}
	if (plugin->name && !strcmp(plugin->name, "any") && !rz_config_get_i(r->config, "bin.rawstr")) {
		return NULL;
	}
	return rz_bin_get_strings(r->bin);
}

static const char *get_compile_time(Sdb *binFileSdb) {
	Sdb *info_ns = sdb_ns(binFileSdb, "info", false);
	const char *timeDateStamp_string = sdb_const_get(info_ns,
		"image_file_header.TimeDateStamp_string", 0);
	return timeDateStamp_string;
}

static bool is_executable(RzBinObject *obj) {
	RzListIter *it;
	RzBinSection *sec;
	rz_return_val_if_fail(obj, false);
	if (obj->info && obj->info->arch) {
		return true;
	}
	rz_list_foreach (obj->sections, it, sec) {
		if (sec->perm & RZ_PERM_X) {
			return true;
		}
	}
	return false;
}

static int bin_info(RzCore *r, PJ *pj, int mode, ut64 laddr) {
	int i, j, v;
	RzBinInfo *info = rz_bin_get_info(r->bin);
	RzBinFile *bf = rz_bin_cur(r->bin);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);
	bool use_color = rz_config_get_i(r->config, "scr.color");
	if (!bf) {
		if (IS_MODE_JSON(mode)) {
			pj_o(pj);
			pj_end(pj);
		}
		return false;
	}
	RzBinObject *obj = bf->o;
	const char *compiled = NULL;
	bool havecode;
	int bits;

	if (!info || !obj) {
		if (IS_MODE_JSON(mode)) {
			pj_o(pj);
			pj_end(pj);
			return true;
		}
		return false;
	}
	havecode = is_executable(obj) | (obj->entries != NULL);
	compiled = get_compile_time(bf->sdb);
	bits = (plugin && !strcmp(plugin->name, "any")) ? rz_config_get_i(r->config, "asm.bits") : info->bits;

	if (IS_MODE_SIMPLE(mode)) {
		rz_cons_printf("arch %s\n", info->arch);
		if (info->cpu && *info->cpu) {
			rz_cons_printf("cpu %s\n", info->cpu);
		}
		rz_cons_printf("bits %d\n", bits);
		rz_cons_printf("os %s\n", info->os);
		rz_cons_printf("endian %s\n", info->big_endian ? "big" : "little");
		v = rz_analysis_archinfo(r->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
		if (v != -1) {
			rz_cons_printf("minopsz %d\n", v);
		}
		v = rz_analysis_archinfo(r->analysis, RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE);
		if (v != -1) {
			rz_cons_printf("maxopsz %d\n", v);
		}
		v = rz_analysis_archinfo(r->analysis, RZ_ANALYSIS_ARCHINFO_ALIGN);
		if (v != -1) {
			rz_cons_printf("pcalign %d\n", v);
		}
	} else if (IS_MODE_RZCMD(mode)) {
		if (info->type && !strcmp(info->type, "fs")) {
			rz_cons_printf("e file.type=fs\n");
			rz_cons_printf("m /root %s 0\n", info->arch);
		} else {
			rz_cons_printf("e cfg.bigendian=%s\n"
				       "e asm.bits=%i\n"
				       "e asm.dwarf=%s\n",
				rz_str_bool(info->big_endian),
				bits,
				rz_str_bool(RZ_BIN_DBG_STRIPPED & info->dbg_info));
			if (info->lang && *info->lang) {
				rz_cons_printf("e bin.lang=%s\n", info->lang);
			}
			if (info->rclass && *info->rclass) {
				rz_cons_printf("e file.type=%s\n",
					info->rclass);
			}
			if (info->os) {
				rz_cons_printf("e asm.os=%s\n", info->os);
			}
			if (info->arch) {
				rz_cons_printf("e asm.arch=%s\n", info->arch);
			}
			if (info->cpu && *info->cpu) {
				rz_cons_printf("e asm.cpu=%s\n", info->cpu);
			}
			if (info->default_cc) {
				rz_cons_printf("e analysis.cc=%s", info->default_cc);
			}
			v = rz_analysis_archinfo(r->analysis, RZ_ANALYSIS_ARCHINFO_ALIGN);
			if (v != -1) {
				rz_cons_printf("e asm.pcalign=%d\n", v);
			}
		}
	} else {
		char *tmp_buf;
		RzTable *table = rz_core_table(r);
		RzList *row_list = rz_list_new();
		if (IS_MODE_JSON(mode)) {
			pj_o(pj);
		}
		pair_str(table, pj, "arch", info->arch, row_list);
		if (info->cpu && *info->cpu) {
			pair_str(table, pj, "cpu", info->cpu, row_list);
		}
		pair_ut64x(table, pj, "baddr", rz_bin_get_baddr(r->bin), row_list);
		pair_ut64(table, pj, "binsz", rz_bin_get_size(r->bin), row_list);
		pair_str(table, pj, "bintype", info->rclass, row_list);
		pair_int(table, pj, "bits", bits, row_list);
		if (info->has_retguard != -1) {
			pair_bool(use_color, table, pj, "retguard", info->has_retguard, row_list);
		}
		pair_str(table, pj, "class", info->bclass, row_list);
		if (info->actual_checksum) {
			/* computed checksum */
			pair_str(table, pj, "cmp.csum", info->actual_checksum, row_list);
		}
		pair_str(table, pj, "compiled", compiled, row_list);
		if (info->compiler) {
			pair_str(table, pj, "compiler", rz_str_newf("%s", info->compiler), row_list);
		}
		pair_str(table, pj, "dbg_file", info->debug_file_name, row_list);
		const char *endian = info->big_endian ? "BE" : "LE";
		pair_str(table, pj, "endian", endian, row_list);
		if (info->rclass && !strcmp(info->rclass, "mdmp")) {
			tmp_buf = sdb_get(bf->sdb, "mdmp.flags", 0);
			if (tmp_buf) {
				pair_str(table, pj, "flags", tmp_buf, row_list);
				free(tmp_buf);
			}
		}
		if (info->claimed_checksum) {
			/* checksum specified in header */
			pair_str(table, pj, "hdr.csum", info->claimed_checksum, row_list);
		}
		pair_str(table, pj, "guid", info->guid, row_list);
		pair_str(table, pj, "intrp", info->intrp, row_list);
		pair_ut64x(table, pj, "laddr", laddr, row_list);
		pair_str(table, pj, "lang", info->lang, row_list);
		pair_str(table, pj, "machine", info->machine, row_list);
		st32 u = rz_analysis_archinfo(r->analysis, RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE);
		if (u != -1) {
			pair_int(table, pj, "maxopsz", u, row_list);
		}
		st32 v = rz_analysis_archinfo(r->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
		if (v != -1) {
			pair_int(table, pj, "minopsz", v, row_list);
		}
		pair_str(table, pj, "os", info->os, row_list);
		if (info->rclass && !strcmp(info->rclass, "pe")) {
			pair_bool(use_color, table, pj, "overlay", info->pe_overlay, row_list);
		}
		pair_str(table, pj, "cc", info->default_cc, row_list);
		st32 uv = rz_analysis_archinfo(r->analysis, RZ_ANALYSIS_ARCHINFO_ALIGN);
		if (uv != -1) {
			pair_int(table, pj, "pcalign", uv, row_list);
		}

		Sdb *sdb_info = sdb_ns(obj->kv, "info", false);
		tmp_buf = sdb_get(sdb_info, "elf.relro", 0);
		if (tmp_buf) {
			pair_str(table, pj, "relro", tmp_buf, row_list);
			free(tmp_buf);
		}
		pair_str(table, pj, "rpath", info->rpath, row_list);
		if (info->rclass && !strcmp(info->rclass, "pe")) {
			//this should be moved if added to mach0 (or others)
			pair_bool(use_color, table, pj, "signed", info->signature, row_list);
		}

		if (info->rclass && !strcmp(info->rclass, "mdmp")) {
			v = sdb_num_get(bf->sdb, "mdmp.streams", 0);
			if (v != -1) {
				pair_int(table, pj, "streams", v, row_list);
			}
		}
		pair_str(table, pj, "subsys", info->subsystem, row_list);
		pair_bool(use_color, table, pj, "stripped", RZ_BIN_DBG_STRIPPED & info->dbg_info, row_list);
		pair_bool(use_color, table, pj, "crypto", info->has_crypto, row_list);
		pair_bool(use_color, table, pj, "havecode", havecode, row_list);
		pair_bool(use_color, table, pj, "va", info->has_va, row_list);
		pair_bool(use_color, table, pj, "sanitiz", info->has_sanitizers, row_list);
		pair_bool(use_color, table, pj, "static", rz_bin_is_static(r->bin), row_list);
		pair_bool(use_color, table, pj, "linenum", RZ_BIN_DBG_LINENUMS & info->dbg_info, row_list);
		pair_bool(use_color, table, pj, "lsyms", RZ_BIN_DBG_SYMS & info->dbg_info, row_list);
		pair_bool(use_color, table, pj, "canary", info->has_canary, row_list);
		pair_bool(use_color, table, pj, "PIE", info->has_pi, row_list);
		pair_bool(use_color, table, pj, "RELROCS", RZ_BIN_DBG_RELOCS & info->dbg_info, row_list);
		pair_bool(use_color, table, pj, "NX", info->has_nx, row_list);

		rz_table_add_row_list(table, row_list);

		if (!IS_MODE_JSON(mode)) {
			RzTable *transpose = rz_table_transpose(table);
			char *t = rz_table_tostring(transpose);
			rz_cons_print(t);
			rz_table_free(transpose);
			free(t);
		}
		if (IS_MODE_JSON(mode)) {
			pj_ko(pj, "checksums");
		}
		for (i = 0; info->sum[i].type; i++) {
			RzBinHash *h = &info->sum[i];
			if (IS_MODE_JSON(mode)) {
				pj_ko(pj, h->type);
				char *buf = malloc(2 * h->len + 1);
				if (!buf) {
					return false;
				}
				for (j = 0; j < h->len; j++) {
					snprintf(buf + 2 * j, 3, "%02x", h->buf[j]);
				}
				pj_ks(pj, "hex", buf);
				free(buf);
				pj_end(pj);
			} else {
				rz_cons_printf("%s  %" PFMT64u "-%" PFMT64u "c  ", h->type, h->from, h->to + h->from);
				for (j = 0; j < h->len; j++) {
					rz_cons_printf("%02x", h->buf[j]);
				}
				rz_cons_newline();
			}
		}
		if (IS_MODE_JSON(mode)) {
			pj_end(pj);
			pj_end(pj);
		}
		rz_table_free(table);
	}
	return true;
}

static bool bin_dwarf(RzCore *core, RzBinFile *binfile, PJ *pj, int mode) {
	rz_return_val_if_fail(core && binfile, false);
	if (!rz_config_get_i(core->config, "bin.dbginfo") || !binfile->o) {
		return false;
	}
	RzBinDwarfDebugAbbrev *da = rz_bin_dwarf_parse_abbrev(binfile);
	RzBinDwarfDebugInfo *info = da ? rz_bin_dwarf_parse_info(binfile, da) : NULL;
	if (mode == RZ_MODE_PRINT) {
		if (da) {
			rz_core_bin_dwarf_print_abbrev_section(da);
		}
		if (info) {
			rz_core_bin_dwarf_print_debug_info(info);
		}
	}
	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = rz_bin_dwarf_parse_loc(binfile, core->analysis->bits / 8);
	if (loc_table) {
		if (mode == RZ_MODE_PRINT) {
			rz_core_bin_dwarf_print_loc(loc_table, core->analysis->bits / 8);
		}
		rz_bin_dwarf_loc_free(loc_table);
	}
	if (mode == RZ_MODE_PRINT) {
		RzList *aranges = rz_bin_dwarf_parse_aranges(binfile);
		if (aranges) {
			rz_core_bin_dwarf_print_aranges(aranges);
			rz_list_free(aranges);
		}
	}
	bool ret = false;
	RzBinDwarfLineInfo *lines = rz_bin_dwarf_parse_line(binfile, info,
		RZ_BIN_DWARF_LINE_INFO_MASK_LINES | (mode == RZ_MODE_PRINT ? RZ_BIN_DWARF_LINE_INFO_MASK_OPS : 0));
	rz_bin_dwarf_debug_info_free(info);
	if (lines) {
		if (mode == RZ_MODE_PRINT) {
			rz_core_bin_dwarf_print_line_units(lines->units);
		}
		if (lines->lines) {
			ret = true;
			rz_core_bin_print_source_line_info(core, lines->lines, IS_MODE_JSON(mode) ? RZ_OUTPUT_MODE_JSON : RZ_OUTPUT_MODE_STANDARD, pj);
		}
		rz_bin_dwarf_line_info_free(lines);
	}
	rz_bin_dwarf_debug_abbrev_free(da);
	return ret;
}

RZ_API void rz_core_bin_print_source_line_sample(RzCore *core, const RzBinSourceLineSample *s, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(core && s && (mode != RZ_OUTPUT_MODE_JSON || pj));
	if (mode == RZ_OUTPUT_MODE_JSON) {
		bool chopPath = !rz_config_get_i(core->config, "dir.dwarf.abspath");
		char *file = s->file ? strdup(s->file) : NULL;
		if (chopPath && file) {
			const char *slash = rz_str_lchr(file, '/');
			if (slash) {
				memmove(file, slash + 1, strlen(slash));
			}
		}
		pj_o(pj);
		if (file) {
			pj_ks(pj, "file", file);
		}
		pj_kn(pj, "line", (ut64)s->line);
		if (s->column) {
			pj_kn(pj, "column", (ut64)s->column);
		}
		pj_kn(pj, "addr", s->address);
		pj_end(pj);
		free(file);
	} else {
		rz_cons_printf("0x%08" PFMT64x "\t%s\t",
			s->address, s->file ? s->file : "-");
		if (s->line) {
			rz_cons_printf("%" PFMT32u "\n", s->line);
		} else {
			rz_cons_print("-\n");
		}
	}
}

RZ_API void rz_core_bin_print_source_line_info(RzCore *core, const RzBinSourceLineInfo *li, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(li && (mode != RZ_OUTPUT_MODE_JSON || pj));
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(pj);
	}
	rz_cons_break_push(NULL, NULL);
	for (size_t i = 0; i < li->samples_count; i++) {
		if (rz_cons_is_breaked()) {
			break;
		}
		rz_core_bin_print_source_line_sample(core, &li->samples[i], mode, pj);
	}
	rz_cons_break_pop();
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
	}
}

RZ_API bool rz_core_pdb_info(RzCore *core, const char *file, PJ *pj, int mode) {
	rz_return_val_if_fail(core && file, false);

	ut64 baddr = rz_config_get_i(core->config, "bin.baddr");
	if (core->bin->cur && core->bin->cur->o && core->bin->cur->o->opts.baseaddr) {
		baddr = core->bin->cur->o->opts.baseaddr;
	} else {
		eprintf("Warning: Cannot find base address, flags will probably be misplaced\n");
	}

	RzPdb pdb = RZ_EMPTY;

	pdb.cb_printf = rz_cons_printf;
	if (!init_pdb_parser(&pdb, file)) {
		return false;
	}
	if (!pdb.pdb_parse(&pdb)) {
		eprintf("pdb was not parsed\n");
		pdb.finish_pdb_parse(&pdb);
		return false;
	}

	switch (mode) {
	case RZ_MODE_SET:
		rz_core_cmd0(core, ".iP*");
		return true;
	case RZ_MODE_JSON:
		mode = 'j';
		break;
	case '*':
	case 1:
		mode = 'r';
		break;
	default:
		mode = 'd'; // default
		break;
	}
	if (mode == 'j') {
		pj_o(pj);
	}

	pdb.print_types(&pdb, pj, mode);
	pdb.print_gvars(&pdb, baddr, pj, mode);
	// Save compound types into types database
	rz_parse_pdb_types(core->analysis->typedb, &pdb);
	pdb.finish_pdb_parse(&pdb);

	if (mode == 'j') {
		pj_end(pj);
	}
	return true;
}

static int bin_main(RzCore *r, RzBinFile *binfile, PJ *pj, int mode, int va) {
	if (!binfile) {
		return false;
	}
	RzBinObject *o = binfile->o;
	if (!o) {
		return false;
	}
	RzBinAddr *binmain = rz_bin_object_get_special_symbol(o, RZ_BIN_SPECIAL_SYMBOL_MAIN);
	if (!binmain) {
		return false;
	}
	ut64 addr = va ? rz_bin_object_addr_with_base(o, binmain->vaddr) : binmain->paddr;

	if (IS_MODE_SIMPLE(mode)) {
		rz_cons_printf("%" PFMT64d, addr);
	} else if (IS_MODE_RZCMD(mode)) {
		rz_cons_printf("fs symbols\n");
		rz_cons_printf("f main @ 0x%08" PFMT64x "\n", addr);
	} else if (IS_MODE_JSON(mode)) {
		pj_o(pj);
		pj_kn(pj, "vaddr", addr);
		pj_kn(pj, "paddr", binmain->paddr);
		pj_end(pj);
	} else {
		rz_cons_printf("[Main]\n");
		rz_cons_printf("vaddr=0x%08" PFMT64x " paddr=0x%08" PFMT64x "\n",
			addr, binmain->paddr);
	}
	return true;
}

static int bin_entry(RzCore *r, PJ *pj, int mode, ut64 laddr, int va, bool inifin) {
	RzBinFile *bf = r->bin->cur;
	RzBinObject *o = bf ? bf->o : NULL;
	RzList *entries = o ? o->entries : NULL;
	RzListIter *iter;
	RzBinAddr *entry = NULL;
	int i = 0, init_i = 0, fini_i = 0, preinit_i = 0;
	ut64 baddr = rz_bin_get_baddr(r->bin);

	if (IS_MODE_RZCMD(mode)) {
		rz_cons_printf("fs symbols\n");
	} else if (IS_MODE_JSON(mode)) {
		pj_a(pj);
	} else if (IS_MODE_NORMAL(mode)) {
		if (inifin) {
			rz_cons_printf("[Constructors]\n");
		} else {
			rz_cons_printf("[Entrypoints]\n");
		}
	}

	rz_list_foreach (entries, iter, entry) {
		ut64 paddr = entry->paddr;
		ut64 hpaddr = UT64_MAX;
		ut64 hvaddr = UT64_MAX;
		if (inifin) {
			if (entry->type == RZ_BIN_ENTRY_TYPE_PROGRAM) {
				continue;
			}
		} else {
			if (entry->type != RZ_BIN_ENTRY_TYPE_PROGRAM) {
				continue;
			}
		}
		if (entry->hpaddr) {
			hpaddr = entry->hpaddr;
			if (entry->hvaddr) {
				hvaddr = rva(o, hpaddr, entry->hvaddr, va);
			}
		}
		ut64 at = rva(o, paddr, entry->vaddr, va);
		const char *type = rz_bin_entry_type_string(entry->type);
		if (!type) {
			type = "unknown";
		}
		const char *hpaddr_key = (entry->type == RZ_BIN_ENTRY_TYPE_PROGRAM)
			? "haddr"
			: "hpaddr";
		if (IS_MODE_SIMPLE(mode)) {
			rz_cons_printf("0x%08" PFMT64x "\n", at);
		} else if (IS_MODE_JSON(mode)) {
			pj_o(pj);
			pj_kn(pj, "vaddr", at);
			pj_kn(pj, "paddr", paddr);
			pj_kn(pj, "baddr", baddr);
			pj_kn(pj, "laddr", laddr);
			if (hvaddr != UT64_MAX) {
				pj_kn(pj, "hvaddr", hvaddr);
			}
			pj_kn(pj, hpaddr_key, hpaddr);
			pj_ks(pj, "type", type);
			pj_end(pj);
		} else if (IS_MODE_RZCMD(mode)) {
			char *name = NULL;
			if (entry->type == RZ_BIN_ENTRY_TYPE_INIT) {
				name = rz_str_newf("entry.init%i", init_i);
			} else if (entry->type == RZ_BIN_ENTRY_TYPE_FINI) {
				name = rz_str_newf("entry.fini%i", fini_i);
			} else if (entry->type == RZ_BIN_ENTRY_TYPE_PREINIT) {
				name = rz_str_newf("entry.preinit%i", preinit_i);
			} else {
				name = rz_str_newf("entry%i", i);
			}
			char *n = __filterQuotedShell(name);
			rz_cons_printf("\"f %s 1 0x%08" PFMT64x "\"\n", n, at);
			rz_cons_printf("\"f %s_%s 1 0x%08" PFMT64x "\"\n", n, hpaddr_key, hpaddr);
			rz_cons_printf("\"s %s\"\n", n);
			free(n);
			free(name);
		} else {
			rz_cons_printf("vaddr=0x%08" PFMT64x " paddr=0x%08" PFMT64x, at, paddr);
			if (is_initfini(entry) && hvaddr != UT64_MAX) {
				rz_cons_printf(" hvaddr=0x%08" PFMT64x, hvaddr);
			}
			rz_cons_printf(" %s=", hpaddr_key);
			if (hpaddr == UT64_MAX) {
				rz_cons_printf("%" PFMT64d, hpaddr);
			} else {
				rz_cons_printf("0x%08" PFMT64x, hpaddr);
			}
			if (entry->type == RZ_BIN_ENTRY_TYPE_PROGRAM && hvaddr != UT64_MAX) {
				rz_cons_printf(" hvaddr=0x%08" PFMT64x, hvaddr);
			}
			rz_cons_printf(" type=%s\n", type);
		}
		if (entry->type == RZ_BIN_ENTRY_TYPE_INIT) {
			init_i++;
		} else if (entry->type == RZ_BIN_ENTRY_TYPE_FINI) {
			fini_i++;
		} else if (entry->type == RZ_BIN_ENTRY_TYPE_PREINIT) {
			preinit_i++;
		} else {
			i++;
		}
	}
	if (IS_MODE_JSON(mode)) {
		pj_end(pj);
	} else if (IS_MODE_NORMAL(mode)) {
		rz_cons_printf("\n%i entrypoints\n", init_i + fini_i + preinit_i + i);
	}
	return true;
}

static const char *bin_reloc_type_name(RzBinReloc *reloc) {
#define CASE(T) \
	case RZ_BIN_RELOC_##T: return reloc->additive ? "ADD_" #T : "SET_" #T
	switch (reloc->type) {
		CASE(8);
		CASE(16);
		CASE(32);
		CASE(64);
	}
	return "UNKNOWN";
#undef CASE
}

/**
 * \brief fetch relocs for the object and print them
 * \return the number of relocs or -1 on failure
 */
static int print_relocs_for_object(RzCore *r, RzBinFile *bf, RzBinObject *o, int va, int mode, PJ *pj, RzTable **table_out) {
	rz_return_val_if_fail(r && bf && o, -1);
	bool bin_demangle = rz_config_get_i(r->config, "bin.demangle");
	bool keep_lib = rz_config_get_i(r->config, "bin.demangle.libs");
	const char *lang = rz_config_get(r->config, "bin.lang");

	RzBinRelocStorage *relocs = rz_bin_object_patch_relocs(bf, o);
	if (!relocs) {
		relocs = o->relocs;
	}
	bool have_targets = relocs ? rz_bin_reloc_storage_targets_available(relocs) : false;
	RzTable *table = NULL;
	if (IS_MODE_NORMAL(mode)) {
		table = rz_core_table(r);
		if (have_targets) {
			rz_table_set_columnsf(table, "XXXss", "vaddr", "paddr", "target", "type", "name");
		} else {
			rz_table_set_columnsf(table, "XXss", "vaddr", "paddr", "type", "name");
		}
		*table_out = table;
	}
	if (!relocs) {
		return -1;
	}
	for (size_t i = 0; i < relocs->relocs_count; i++) {
		RzBinReloc *reloc = relocs->relocs[i];
		ut64 addr = rva(o, reloc->paddr, reloc->vaddr, va);
		if (IS_MODE_SIMPLE(mode)) {
			rz_cons_printf("0x%08" PFMT64x "  %s\n", addr, reloc->import ? reloc->import->name : "");
		} else if (IS_MODE_RZCMD(mode)) {
			char *name = reloc->import
				? strdup(reloc->import->name)
				: (reloc->symbol ? strdup(reloc->symbol->name) : NULL);
			if (name && bin_demangle) {
				char *mn = rz_bin_demangle(r->bin->cur, NULL, name, addr, keep_lib);
				if (mn) {
					free(name);
					name = mn;
				}
			}
			if (name) {
				int reloc_size = 4;
				char *n = __filterQuotedShell(name);
				rz_cons_printf("\"f %s%s%s %d 0x%08" PFMT64x "\"\n",
					r->bin->prefix ? r->bin->prefix : "reloc.",
					r->bin->prefix ? "." : "", n, reloc_size, addr);
				ut64 meta_sz;
				if (meta_for_reloc(r, o, reloc, false, addr, &meta_sz)) {
					rz_cons_printf("Cd %" PFMT64u " @ 0x%08" PFMT64x "\n", meta_sz, addr);
				}
				free(n);
				free(name);
			}
		} else if (IS_MODE_JSON(mode)) {
			pj_o(pj);
			char *mn = NULL;
			char *relname = NULL;

			// take care with very long symbol names! do not use sdb_fmt or similar
			if (reloc->import) {
				mn = rz_bin_demangle(r->bin->cur, lang, reloc->import->name, addr, keep_lib);
				relname = strdup(reloc->import->name);
			} else if (reloc->symbol) {
				mn = rz_bin_demangle(r->bin->cur, lang, reloc->symbol->name, addr, keep_lib);
				relname = strdup(reloc->symbol->name);
			}

			// check if name is available
			if (relname && *relname) {
				pj_ks(pj, "name", relname);
			}
			pj_ks(pj, "demname", mn ? mn : "");
			pj_ks(pj, "type", bin_reloc_type_name(reloc));
			pj_kn(pj, "vaddr", reloc->vaddr);
			pj_kn(pj, "paddr", reloc->paddr);
			if (rz_bin_reloc_has_target(reloc)) {
				pj_kn(pj, "target_vaddr", reloc->target_vaddr);
			}
			if (reloc->symbol) {
				pj_kn(pj, "sym_va", reloc->symbol->vaddr);
			}
			pj_kb(pj, "is_ifunc", reloc->is_ifunc);
			// end reloc item
			pj_end(pj);

			free(mn);
			if (relname) {
				free(relname);
			}
		} else if (IS_MODE_NORMAL(mode)) {
			char *name = reloc->import
				? strdup(reloc->import->name)
				: reloc->symbol ? strdup(reloc->symbol->name)
						: NULL;
			if (bin_demangle) {
				char *mn = rz_bin_demangle(r->bin->cur, NULL, name, addr, keep_lib);
				if (mn && *mn) {
					free(name);
					name = mn;
				}
			}
			char *reloc_name = construct_reloc_name(reloc, name);
			RzStrBuf *buf = rz_strbuf_new(reloc_name ? reloc_name : "");
			free(reloc_name);
			RZ_FREE(name);
			if (reloc->addend) {
				if ((reloc->import || reloc->symbol) && !rz_strbuf_is_empty(buf) && reloc->addend > 0) {
					rz_strbuf_append(buf, " +");
				}
				if (reloc->addend < 0) {
					rz_strbuf_appendf(buf, " - 0x%08" PFMT64x, -reloc->addend);
				} else {
					rz_strbuf_appendf(buf, " 0x%08" PFMT64x, reloc->addend);
				}
			}
			if (reloc->is_ifunc) {
				rz_strbuf_append(buf, " (ifunc)");
			}
			char *res = rz_strbuf_drain(buf);
			if (have_targets) {
				rz_table_add_rowf(table, "XXXss", addr, reloc->paddr, reloc->target_vaddr,
					bin_reloc_type_name(reloc), res);
			} else {
				rz_table_add_rowf(table, "XXss", addr, reloc->paddr,
					bin_reloc_type_name(reloc), res);
			}
			free(res);
		}
	}
	return relocs->relocs_count;
}

static int bin_relocs(RzCore *r, PJ *pj, int mode, int va) {
	va = VA_TRUE; // XXX relocs always vaddr?

	if (IS_MODE_RZCMD(mode)) {
		rz_cons_println("fs relocs");
	} else if (IS_MODE_NORMAL(mode)) {
		rz_cons_println("[Relocations]");
	} else if (IS_MODE_JSON(mode)) {
		pj_a(pj);
	}

	RzTable *table = NULL;
	int relocs_count = -1;
	if (r->bin->cur && r->bin->cur->o) {
		RzBinFile *bf = r->bin->cur;
		RzBinObject *o = bf->o;
		relocs_count = print_relocs_for_object(r, bf, o, va, mode, pj, &table);
	}

	if (IS_MODE_JSON(mode)) {
		pj_end(pj);
	}
	if (IS_MODE_NORMAL(mode) && table) {
		if (r->table_query) {
			rz_table_query(table, r->table_query);
		}
		char *s = rz_table_tostring(table);
		rz_cons_printf("\n%s\n", s);
		free(s);
		rz_cons_printf("\n%i relocations\n", relocs_count >= 0 ? relocs_count : 0);
	}

	rz_table_free(table);

	if (IS_MODE_JSON(mode)) {
		return true; // ignore relocs_count here
	}
	return relocs_count >= 0;
}

static int bin_imports(RzCore *r, PJ *pj, int mode, int va, const char *name) {
	int bin_demangle = rz_config_get_i(r->config, "bin.demangle");
	bool keep_lib = rz_config_get_i(r->config, "bin.demangle.libs");
	RzTable *table = rz_core_table(r);
	rz_return_val_if_fail(table, false);
	RzBinImport *import;
	RzListIter *iter;
	int i = 0;

	RzBinFile *bf = rz_bin_cur(r->bin);
	if (!bf || !bf->o || !bf->o->info) {
		if (IS_MODE_JSON(mode)) {
			pj_a(pj);
			pj_end(pj);
		}
		return false;
	}
	RzBinObject *o = bf->o;

	RzList *imports = rz_bin_get_imports(r->bin);
	if (IS_MODE_JSON(mode)) {
		pj_a(pj);
	} else if (IS_MODE_RZCMD(mode)) {
		rz_cons_println("fs imports");
	} else if (IS_MODE_NORMAL(mode)) {
		rz_cons_println("[Imports]");
		rz_table_set_columnsf(table, "nXssss", "nth", "vaddr", "bind", "type", "lib", "name");
	}
	rz_list_foreach (imports, iter, import) {
		if (!import->name || (name && strcmp(import->name, name))) {
			continue;
		}
		char *symname = import->name ? strdup(import->name) : NULL;
		char *libname = import->libname ? strdup(import->libname) : NULL;
		RzBinSymbol *sym = rz_bin_object_get_symbol_of_import(o, import);
		ut64 addr = sym ? rva(o, sym->paddr, sym->vaddr, va) : UT64_MAX;
		if (bin_demangle) {
			char *dname = rz_bin_demangle(r->bin->cur, NULL, symname, addr, keep_lib);
			if (dname) {
				free(symname);
				symname = rz_str_newf("sym.imp.%s", dname);
				free(dname);
			}
		}
		if (r->bin->prefix) {
			char *prname = rz_str_newf("%s.%s", r->bin->prefix, symname);
			free(symname);
			symname = prname;
		}
		if (IS_MODE_SIMPLE(mode)) {
			rz_cons_printf("%s%s%s\n",
				libname ? libname : "", libname ? " " : "", symname);
		} else if (IS_MODE_SIMPLEST(mode)) {
			rz_cons_println(symname);
		} else if (IS_MODE_JSON(mode)) {
			pj_o(pj);
			pj_ki(pj, "ordinal", import->ordinal);
			if (import->bind) {
				pj_ks(pj, "bind", import->bind);
			}
			if (import->type) {
				pj_ks(pj, "type", import->type);
			}
			if (import->classname && import->classname[0]) {
				pj_ks(pj, "classname", import->classname);
				pj_ks(pj, "descriptor", import->descriptor);
			}
			pj_ks(pj, "name", symname);
			if (libname) {
				pj_ks(pj, "libname", libname);
			}
			if (addr != UT64_MAX) {
				pj_kn(pj, "plt", addr);
			}
			pj_end(pj);
		} else if (IS_MODE_RZCMD(mode)) {
		} else {
			const char *bind = import->bind ? import->bind : "NONE";
			const char *type = import->type ? import->type : "NONE";
			if (import->classname && import->classname[0]) {
				rz_table_add_rowf(table, "nXssss", (ut64)import->ordinal, addr, bind, type, libname ? libname : "", sdb_fmt("%s.%s", import->classname, symname));
			} else {
				rz_table_add_rowf(table, "nXssss", (ut64)import->ordinal, addr, bind, type, libname ? libname : "", symname);
			}

			if (!IS_MODE_NORMAL(mode)) {
				rz_cons_newline();
			}
		}
		RZ_FREE(symname);
		RZ_FREE(libname);
		i++;
	}

	if (IS_MODE_JSON(mode)) {
		pj_end(pj);
	} else if (IS_MODE_NORMAL(mode)) {
		if (r->table_query) {
			rz_table_query(table, r->table_query);
		}
		char *s = rz_table_tostring(table);
		rz_cons_printf("%s\n", s);
		free(s);
	}

	rz_table_free(table);
	return true;
}

static bool isAnExport(RzBinSymbol *s) {
	/* workaround for some bin plugs */
	if (s->is_imported) {
		return false;
	}
	return (s->bind && !strcmp(s->bind, RZ_BIN_BIND_GLOBAL_STR));
}

static int bin_symbols(RzCore *r, PJ *pj, int mode, int va, ut64 at, const char *name, bool exponly, const char *args) {
	RzBinFile *bf = r->bin->cur;
	RzBinObject *o = bf ? bf->o : NULL;
	RzBinInfo *info = o ? o->info : NULL;
	RzBinSymbol *symbol;
	RzListIter *iter;
	bool firstexp = true;
	bool printHere = (args && *args == '.');
	bool none = true;

	int i = 0, lastfs = 's';
	RzTable *table = rz_core_table(r);
	bool bin_demangle = rz_config_get_i(r->config, "bin.demangle");
	if (IS_MODE_JSON(mode)) {
		if (!printHere) {
			pj_a(pj);
		}
	}
	if (!info) {
		if (IS_MODE_JSON(mode)) {
			if (printHere) {
				pj_o(pj);
			}
			pj_end(pj);
		}
		rz_table_free(table);
		return 0;
	}

	const char *lang = bin_demangle ? rz_config_get(r->config, "bin.lang") : NULL;

	RzList *symbols = rz_bin_get_symbols(r->bin);

	if (at == UT64_MAX && exponly) {
		if (IS_MODE_RZCMD(mode)) {
			rz_cons_printf("fs exports\n");
		} else if (IS_MODE_NORMAL(mode)) {
			rz_cons_printf(printHere ? "" : "[Exports]\n");
		}
	} else if (at == UT64_MAX && !exponly) {
		if (IS_MODE_RZCMD(mode)) {
			rz_cons_printf("fs symbols\n");
		} else if (IS_MODE_NORMAL(mode)) {
			rz_cons_printf(printHere ? "" : "[Symbols]\n");
		}
	}
	if (IS_MODE_NORMAL(mode)) {
		rz_table_set_columnsf(table, "dXXssdss", "nth", "paddr", "vaddr", "bind", "type", "size", "lib", "name");
	}

	size_t count = 0;
	rz_list_foreach (symbols, iter, symbol) {
		if (!symbol->name) {
			continue;
		}
		if (exponly && !isAnExport(symbol)) {
			continue;
		}
		if (name && strcmp(symbol->name, name)) {
			continue;
		}
		ut64 addr = rva(o, symbol->paddr, symbol->vaddr, va);
		ut32 len = symbol->size ? symbol->size : 32;
		if (at != UT64_MAX && (!symbol->size || !is_in_range(at, addr, symbol->size))) {
			continue;
		}
		if ((printHere && !is_in_range(r->offset, symbol->paddr, len)) && (printHere && !is_in_range(r->offset, addr, len))) {
			continue;
		}
		SymName sn = { 0 };
		count++;
		sym_name_init(r, &sn, symbol, lang);
		char *rz_symbol_name = rz_str_escape_utf8(sn.name, false, true);

		if (IS_MODE_JSON(mode)) {
			none = false;
			pj_o(pj);
			pj_ks(pj, "name", rz_symbol_name);
			if (sn.demname) {
				pj_ks(pj, "demname", sn.demname);
			}
			pj_ks(pj, "flagname", sn.nameflag);
			pj_ks(pj, "realname", symbol->name);
			pj_ki(pj, "ordinal", symbol->ordinal);
			pj_ks(pj, "bind", symbol->bind);
			pj_kn(pj, "size", (ut64)symbol->size);
			pj_ks(pj, "type", symbol->type);
			pj_kn(pj, "vaddr", addr);
			pj_kn(pj, "paddr", symbol->paddr);
			pj_kb(pj, "is_imported", symbol->is_imported);
			pj_end(pj);
		} else if (IS_MODE_SIMPLE(mode)) {
			const char *name = sn.demname ? sn.demname : rz_symbol_name;
			rz_cons_printf("0x%08" PFMT64x " %d %s%s%s\n",
				addr, (int)symbol->size,
				sn.libname ? sn.libname : "", sn.libname ? " " : "",
				name);
		} else if (IS_MODE_SIMPLEST(mode)) {
			const char *name = sn.demname ? sn.demname : rz_symbol_name;
			rz_cons_printf("%s\n", name);
		} else if (IS_MODE_RZCMD(mode)) {
			/* Skip special symbols because we do not flag them and
			 * they shouldn't be printed in the rad format either */
			if (is_special_symbol(symbol)) {
				goto next;
			}
			RzBinFile *binfile;
			RzBinPlugin *plugin;
			const char *name = sn.demname ? sn.demname : rz_symbol_name;
			if (!name) {
				goto next;
			}
			if (symbol->is_imported) {
				if (lastfs != 'i') {
					rz_cons_printf("fs imports\n");
				}
				lastfs = 'i';
			} else {
				if (lastfs != 's') {
					const char *fs = exponly ? "exports" : "symbols";
					rz_cons_printf("fs %s\n", fs);
				}
				lastfs = 's';
			}
			if (r->bin->prefix || *name) { // we don't want unnamed symbol flags
				char *flagname = construct_symbol_flagname("sym", sn.libname, name, MAXFLAG_LEN_DEFAULT);
				if (!flagname) {
					goto next;
				}
				rz_cons_printf("\"f %s%s%s %u 0x%08" PFMT64x "\"\n",
					r->bin->prefix ? r->bin->prefix : "", r->bin->prefix ? "." : "",
					flagname, symbol->size, addr);
				free(flagname);
			}
			binfile = rz_bin_cur(r->bin);
			plugin = rz_bin_file_cur_plugin(binfile);
			if (plugin && plugin->name) {
				if (rz_str_startswith(plugin->name, "pe")) {
					char *module = strdup(rz_symbol_name);
					char *p = strstr(module, ".dll_");
					if (p && symbol->is_imported) {
						char *symname = __filterShell(p + 5);
						char *m = __filterShell(module);
						*p = 0;
						if (r->bin->prefix) {
							rz_cons_printf("\"k bin/pe/%s/%d=%s.%s\"\n",
								module, symbol->ordinal, r->bin->prefix, symname);
						} else {
							rz_cons_printf("\"k bin/pe/%s/%d=%s\"\n",
								module, symbol->ordinal, symname);
						}
						free(symname);
						free(m);
					}
					free(module);
				}
			}
		} else {
			const char *bind = symbol->bind ? symbol->bind : "NONE";
			const char *type = symbol->type ? symbol->type : "NONE";
			const char *name = rz_str_get_null(sn.demname ? sn.demname : sn.name);
			// const char *fwd = rz_str_get_null(symbol->forwarder);
			rz_table_add_rowf(table, "dXXssdss",
				symbol->ordinal,
				symbol->paddr,
				addr,
				bind,
				type,
				symbol->size,
				symbol->libname ? symbol->libname : "", // for 'is' libname empty
				name);
		}
	next:
		sym_name_fini(&sn);
		i++;
		free(rz_symbol_name);
		if (exponly && firstexp) {
			firstexp = false;
		}
		if (printHere) {
			break;
		}
	}
	if (IS_MODE_NORMAL(mode)) {
		if (r->table_query) {
			rz_table_query(table, r->table_query);
		}
		char *s = rz_table_tostring(table);
		rz_cons_printf("\n%s", s);
		free(s);
	}

	if (IS_MODE_JSON(mode)) {
		if (!printHere) {
			pj_end(pj);
		} else if (none) {
			pj_o(pj);
			pj_end(pj);
		}
	}

	rz_table_free(table);
	return true;
}

static char *build_hash_string(PJ *pj, int mode, const char *chksum, ut8 *data, ut32 datalen) {
	char *chkstr = NULL, *aux = NULL, *ret = NULL;
	RzList *hashlist = rz_str_split_duplist(chksum, ",", true);
	RzListIter *iter;
	char *hashname;
	rz_list_foreach (hashlist, iter, hashname) {
		chkstr = rz_msg_digest_calculate_small_block_string(hashname, data, datalen, NULL, false);
		if (!chkstr) {
			continue;
		}
		if (IS_MODE_SIMPLE(mode) || IS_MODE_NORMAL(mode)) {
			aux = rz_str_newf(iter->n ? "%s " : "%s", chkstr);
		} else if (IS_MODE_JSON(mode)) {
			pj_ks(pj, hashname, chkstr);
		} else {
			aux = rz_str_newf("%s=%s ", hashname, chkstr);
		}
		ret = rz_str_append(ret, aux);
		free(chkstr);
		free(aux);
	}
	rz_list_free(hashlist);
	return ret;
}

static char *filter_hash_string(const char *chksum) {
	if (!chksum) {
		return NULL;
	}

	char *aux, *ret = NULL;
	bool isFirst = true;
	RzList *hashlist = rz_str_split_duplist(chksum, ",", true);
	RzListIter *iter;
	char *hashname;
	rz_list_foreach (hashlist, iter, hashname) {
		if (rz_msg_digest_plugin_by_name(hashname)) {
			aux = rz_str_newf(isFirst ? "%s" : ", %s", hashname);
			ret = rz_str_append(ret, aux);
			free(aux);
			if (isFirst) {
				isFirst = false;
			}
		}
	}
	rz_list_free(hashlist);
	return ret;
}

/* Map Sections to Segments https://github.com/rizinorg/rizin/issues/14647 */
static int bin_map_sections_to_segments(RzBin *bin, PJ *pj, int mode) {
	RzListIter *iter, *iter2;
	RzBinSection *section = NULL, *segment = NULL;
	RzList *sections = rz_list_new();
	RzList *segments = rz_list_new();
	RzList *tmp = rz_bin_get_sections(bin);
	RzTable *table = rz_table_new();
	RzTableColumnType *typeString = rz_table_type("string");

	rz_table_add_column(table, typeString, "Segment", 0);
	rz_table_add_column(table, typeString, "Section", 0);

	rz_list_foreach (tmp, iter, section) {
		RzList *list = section->is_segment ? segments : sections;
		rz_list_append(list, section);
	}

	if (IS_MODE_JSON(mode)) {
		pj_a(pj);
		pj_o(pj);
	}

	rz_list_foreach (segments, iter, segment) {
		RzInterval segment_itv = (RzInterval){ segment->vaddr, segment->size };
		char *tmp2 = rz_str_new("");
		rz_list_foreach (sections, iter2, section) {
			RzInterval section_itv = (RzInterval){ section->vaddr, section->size };
			if (rz_itv_begin(section_itv) >= rz_itv_begin(segment_itv) && rz_itv_end(section_itv) <= rz_itv_end(segment_itv) && section->name[0]) {
				tmp2 = rz_str_appendf(tmp2, "%s ", section->name);
			}
		}
		rz_table_add_row(table, segment->name, tmp2, 0);
		if (IS_MODE_JSON(mode)) {
			pj_ks(pj, segment->name, tmp2);
		}
		free(tmp2);
	}

	if (IS_MODE_JSON(mode)) {
		pj_end(pj);
		pj_end(pj);
	}

	if (IS_MODE_NORMAL(mode)) {
		rz_cons_printf("Section to Segment mapping:\n");
		char *s = rz_table_tostring(table);
		rz_cons_printf("%s\n", s);
		free(s);
	}
	rz_list_free(segments);
	rz_table_free(table);
	return true;
}

static int bin_sections(RzCore *r, PJ *pj, int mode, ut64 laddr, int va, ut64 at, const char *name, const char *chksum, bool print_segments) {
	RzBinSection *section;
	RzBinInfo *info = NULL;
	RzListIter *iter;
	RzTable *table = rz_core_table(r);
	RzBinFile *bf = r->bin->cur;
	RzBinObject *o = bf ? bf->o : NULL;
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);
	rz_return_val_if_fail(table, false);
	int i = 0;
	bool printHere = false;
	RzList *sections = o ? o->sections : NULL;
	HtPP *dup_chk_ht = ht_pp_new0();
	bool ret = false;
	const char *type = print_segments ? "segment" : "section";
	bool plugin_type_support = plugin && plugin->section_type_to_string;
	bool plugin_flags_support = plugin && plugin->section_flag_to_rzlist;
	bool print_align = false;
	rz_list_foreach (sections, iter, section) {
		if (section->align && section->is_segment == print_segments) {
			print_align = true;
			break;
		}
	}
	if (!dup_chk_ht) {
		return false;
	}

	if (chksum && *chksum == '.') {
		printHere = true;
		chksum++;
	}
	char *hashtypes = filter_hash_string(chksum);
	if (IS_MODE_EQUAL(mode)) {
		int cols = rz_cons_get_size(NULL);
		RzList *list = rz_list_newf((RzListFree)rz_listinfo_free);
		if (!list) {
			free(hashtypes);
			return false;
		}
		RzBinSection *s;
		rz_list_foreach (sections, iter, s) {
			char humansz[8];
			if (print_segments != s->is_segment) {
				continue;
			}
			RzInterval pitv = (RzInterval){ s->paddr, s->size };
			RzInterval vitv = (RzInterval){ s->vaddr, s->vsize };

			rz_num_units(humansz, sizeof(humansz), s->size);
			RzListInfo *info = rz_listinfo_new(s->name, pitv, vitv, s->perm, strdup(humansz));
			rz_list_append(list, info);
		}
		RzTable *table = rz_core_table(r);
		rz_table_visual_list(table, list, r->offset, -1, cols, r->io->va);
		if (r->table_query) {
			// TODO iS/iSS entropy,sha1,... <query>
			rz_table_query(table, hashtypes ? "" : r->table_query);
		}
		{
			char *s = rz_table_tostring(table);
			rz_cons_printf("\n%s\n", s);
			free(s);
		}
		rz_table_free(table);
		rz_list_free(list);
		goto out;
	}
	if (IS_MODE_JSON(mode)) {
		if (!printHere) {
			pj_a(pj);
		}
	} else if (IS_MODE_RZCMD(mode) && at == UT64_MAX) {
		rz_cons_printf("fs %ss\n", type);
	} else if (IS_MODE_NORMAL(mode) && at == UT64_MAX && !printHere) {
		rz_cons_printf("[%s]\n", print_segments ? "Segments" : "Sections");
	} else if (IS_MODE_NORMAL(mode) && printHere) {
		rz_cons_printf("Current section\n");
	}
	if (IS_MODE_NORMAL(mode)) {
		rz_table_set_columnsf(table, "dXxXxs", "nth", "paddr", "size", "vaddr", "vsize", "perm");
		if (hashtypes) {
			rz_table_set_columnsf(table, "s", hashtypes);
		}
		rz_table_add_column(table, rz_table_type("string"), "name", 0);
		if (plugin_type_support && !print_segments) {
			rz_table_set_columnsf(table, "s", "type");
		}
		if (plugin_flags_support && !print_segments) {
			rz_table_set_columnsf(table, "s", "flags");
		}
		if (print_align) {
			rz_table_set_columnsf(table, "x", "align");
		}
		rz_table_align(table, 2, RZ_TABLE_ALIGN_RIGHT);
		rz_table_align(table, 4, RZ_TABLE_ALIGN_RIGHT);
	}
	rz_list_foreach (sections, iter, section) {
		int va_sect = va;
		ut64 addr;

		if (va && !(section->perm & RZ_PERM_R)) {
			va_sect = VA_NOREBASE;
		}
		addr = rva(o, section->paddr, section->vaddr, va_sect);

		if (name && strcmp(section->name, name)) {
			continue;
		}

		if ((printHere && !(section->paddr <= r->offset && r->offset < (section->paddr + section->size))) && (printHere && !(addr <= r->offset && r->offset < (addr + section->size)))) {
			continue;
		}

		rz_name_filter(section->name, strlen(section->name) + 1, false);
		if (at != UT64_MAX && (!section->size || !is_in_range(at, addr, section->size))) {
			continue;
		}

		if (section->is_segment != print_segments) {
			continue;
		}

		char perms[5];
		section_perms_str(perms, section->perm);

		const char *arch = NULL;
		int bits = 0;
		if (section->arch || section->bits) {
			arch = section->arch;
			bits = section->bits;
		}
		if (info) {
			if (!arch) {
				arch = info->arch;
			}
			if (!bits) {
				bits = info->bits;
			}
		}
		if (!arch) {
			arch = rz_config_get(r->config, "asm.arch");
		}
		if (!bits) {
			bits = RZ_SYS_BITS;
		}
		if (IS_MODE_RZCMD(mode)) {
			char *n = __filterQuotedShell(section->name);
			rz_cons_printf("\"f %s.%s 1 0x%08" PFMT64x "\"\n", type, n, section->vaddr);
			free(n);
		} else if (IS_MODE_SIMPLE(mode)) {
			char *hashstr = NULL;
			if (hashtypes) {
				ut8 *data = malloc(section->size);
				if (!data) {
					goto out;
				}
				ut32 datalen = section->size;
				rz_io_pread_at(r->io, section->paddr, data, datalen);
				hashstr = build_hash_string(pj, mode, hashtypes, data, datalen);
				free(data);
			}
			rz_cons_printf("0x%" PFMT64x " 0x%" PFMT64x " %s %s%s%s\n",
				addr, addr + section->size,
				perms,
				hashstr ? hashstr : "", hashstr ? " " : "",
				section->name);
			free(hashstr);
		} else if (IS_MODE_JSON(mode)) {
			pj_o(pj);
			pj_ks(pj, "name", section->name);
			pj_kN(pj, "size", section->size);
			pj_kN(pj, "vsize", section->vsize);
			pj_ks(pj, "perm", perms);
			if (hashtypes && section->size > 0) {
				ut8 *data = malloc(section->size);
				if (!data) {
					goto out;
				}
				ut32 datalen = section->size;
				rz_io_pread_at(r->io, section->paddr, data, datalen);
				build_hash_string(pj, mode, hashtypes, data, datalen);
				free(data);
			}
			if (!print_segments && plugin_type_support) {
				char *section_type = rz_bin_section_type_to_string(r->bin, section->type);
				if (section_type) {
					pj_ks(pj, "type", section_type);
				}
				free(section_type);
			}
			if (!print_segments && plugin_flags_support) {
				RzList *flags = rz_bin_section_flag_to_list(r->bin, section->flags);
				char *pos;
				if (flags) {
					pj_ka(pj, "flags");
					RzListIter *it;
					rz_list_foreach (flags, it, pos) {
						pj_s(pj, pos);
					}
					pj_end(pj);
				}
				rz_list_free(flags);
			}
			pj_kN(pj, "paddr", section->paddr);
			pj_kN(pj, "vaddr", addr);
			if (section->align) {
				pj_kN(pj, "align", section->align);
			}
			pj_end(pj);
		} else {
			char *hashstr = NULL, str[128];
			if (hashtypes) {
				ut8 *data = malloc(section->size);
				if (!data) {
					goto out;
				}
				ut32 datalen = section->size;
				// VA READ IS BROKEN?
				if (datalen > 0) {
					rz_io_pread_at(r->io, section->paddr, data, datalen);
				}
				hashstr = build_hash_string(pj, mode, hashtypes, data, datalen);
				free(data);
			}
			if (section->arch || section->bits) {
				snprintf(str, sizeof(str), "arch=%s bits=%d ",
					rz_str_get(arch), bits);
			} else {
				str[0] = 0;
			}
			const char *section_name = (r->bin->prefix)
				? sdb_fmt("%s.%s", r->bin->prefix, section->name)
				: section->name;
			// seems like asm.bits is a bitmask that seems to be always 32,64
			// const char *asmbits = rz_str_sysbits (bits);

			RzList *row_list = rz_list_newf(free);
			if (!row_list) {
				goto out;
			}
			// Add common fields
			rz_list_append(row_list, rz_str_newf("%d", i));
			rz_list_append(row_list, rz_str_newf("0x%08" PFMT64x, section->paddr));
			rz_list_append(row_list, rz_str_newf("0x%" PFMT64x, section->size));
			rz_list_append(row_list, rz_str_newf("0x%08" PFMT64x, addr));
			rz_list_append(row_list, rz_str_newf("0x%" PFMT64x, section->vsize));
			rz_list_append(row_list, strdup(perms));

			if (hashtypes) {
				rz_list_append(row_list, hashstr);
			}

			rz_list_append(row_list, strdup(section_name));

			if (!print_segments && plugin_type_support) {
				char *section_type = rz_bin_section_type_to_string(r->bin, section->type);
				rz_list_append(row_list, section_type);
			}

			if (!print_segments && plugin_flags_support) {
				RzList *section_flags = rz_bin_section_flag_to_list(r->bin, section->flags);
				char *section_flags_str = rz_str_list_join(section_flags, ",");
				rz_list_append(row_list, section_flags_str);
				rz_list_free(section_flags);
			}

			if (section->align) {
				rz_list_append(row_list, rz_str_newf("0x%" PFMT64x, section->align));
			}

			rz_table_add_row_list(table, row_list);
		}
		i++;
		if (printHere) {
			break;
		}
	}
	if (IS_MODE_JSON(mode) && !printHere) {
		pj_end(pj);
	} else if (IS_MODE_NORMAL(mode) && at == UT64_MAX && !printHere) {
		// rz_cons_printf ("\n%i sections\n", i);
	}

	ret = true;
out:
	if (IS_MODE_NORMAL(mode)) {
		if (r->table_query) {
			// TODO iS/iSS entropy,sha1,... <query>
			rz_table_query(table, hashtypes ? "" : r->table_query);
		}
		char *s = rz_table_tostring(table);
		rz_cons_printf("\n%s\n", s);
		free(s);
	}
	free(hashtypes);
	rz_table_free(table);
	ht_pp_free(dup_chk_ht);
	return ret;
}

static int bin_fields(RzCore *r, PJ *pj, int mode, int va) {
	RzListIter *iter;
	RzBinField *field;
	int i = 0;
	RzBin *bin = r->bin;

	RzBinFile *bf = bin->cur;
	RzBinObject *o = bf ? bf->o : NULL;
	RzList *fields = o ? o->fields : NULL;
	if (!fields) {
		return false;
	}
	if (IS_MODE_JSON(mode)) {
		pj_a(pj);
	} else if (IS_MODE_RZCMD(mode)) {
		rz_cons_println("fs header");
	} else if (IS_MODE_NORMAL(mode)) {
		rz_cons_println("[Header fields]");
	}
	rz_list_foreach (fields, iter, field) {
		ut64 addr = rva(o, field->paddr, field->vaddr, va);

		if (IS_MODE_RZCMD(mode)) {
			char *n = __filterQuotedShell(field->name);
			rz_name_filter(n, -1, true);
			rz_cons_printf("\"f header.%s 1 0x%08" PFMT64x "\"\n", n, addr);
			if (field->comment && *field->comment) {
				char *e = sdb_encode((const ut8 *)field->comment, -1);
				rz_cons_printf("CCu %s @ 0x%" PFMT64x "\n", e, addr);
				free(e);
				char *f = __filterShell(field->format);
				rz_cons_printf("Cf %d %s @ 0x%" PFMT64x "\n", field->size, f, addr);
				free(f);
			}
			if (field->format && *field->format && !field->format_named) {
				rz_cons_printf("pf.%s %s\n", n, field->format);
			}
			free(n);
		} else if (IS_MODE_JSON(mode)) {
			pj_o(pj);
			pj_ks(pj, "name", field->name);
			pj_kN(pj, "vaddr", field->vaddr);
			pj_kN(pj, "paddr", field->paddr);
			if (field->comment && *field->comment) {
				// TODO: filter comment before json
				pj_ks(pj, "comment", field->comment);
			}
			if (field->format && *field->format) {
				// TODO: filter comment before json
				pj_ks(pj, "format", field->format);
			}
			char *o = rz_core_cmd_strf(r, "pfj%c%s@0x%" PFMT64x,
				field->format_named ? '.' : ' ', field->format, field->vaddr);
			if (o && *o) {
				rz_str_trim_tail(o);
				pj_k(pj, "pf");
				pj_j(pj, o);
			}
			free(o);
			pj_end(pj);
		} else if (IS_MODE_NORMAL(mode)) {
			const bool haveComment = (field->comment && *field->comment);
			rz_cons_printf("0x%08" PFMT64x " 0x%08" PFMT64x " %s%s%s\n",
				field->vaddr, field->paddr, field->name,
				haveComment ? "; " : "",
				haveComment ? field->comment : "");
		}
		i++;
	}
	if (IS_MODE_JSON(mode)) {
		pj_end(pj);
	} else if (IS_MODE_NORMAL(mode)) {
		rz_cons_printf("\n%i fields\n", i);
	}

	return true;
}

static char *get_rp(const char *rtype) {
	char *rp = NULL;
	switch (rtype[0]) {
	case 'v':
		rp = strdup("void");
		break;
	case 'c':
		rp = strdup("char");
		break;
	case 'i':
		rp = strdup("int");
		break;
	case 's':
		rp = strdup("short");
		break;
	case 'l':
		rp = strdup("long");
		break;
	case 'q':
		rp = strdup("long long");
		break;
	case 'C':
		rp = strdup("unsigned char");
		break;
	case 'I':
		rp = strdup("unsigned int");
		break;
	case 'S':
		rp = strdup("unsigned short");
		break;
	case 'L':
		rp = strdup("unsigned long");
		break;
	case 'Q':
		rp = strdup("unsigned long long");
		break;
	case 'f':
		rp = strdup("float");
		break;
	case 'd':
		rp = strdup("double");
		break;
	case 'D':
		rp = strdup("long double");
		break;
	case 'B':
		rp = strdup("bool");
		break;
	case '#':
		rp = strdup("CLASS");
		break;
	default:
		rp = strdup("unknown");
		break;
	}
	return rp;
}

static int bin_trycatch(RzCore *core, PJ *pj, int mode) {
	RzBinFile *bf = rz_bin_cur(core->bin);
	RzListIter *iter;
	RzBinTrycatch *tc;
	RzList *trycatch = rz_bin_file_get_trycatch(bf);
	int idx = 0;
	// FIXME: json mode
	rz_list_foreach (trycatch, iter, tc) {
		rz_cons_printf("f try.%d.%" PFMT64x ".from=0x%08" PFMT64x "\n", idx, tc->source, tc->from);
		rz_cons_printf("f try.%d.%" PFMT64x ".to=0x%08" PFMT64x "\n", idx, tc->source, tc->to);
		rz_cons_printf("f try.%d.%" PFMT64x ".catch=0x%08" PFMT64x "\n", idx, tc->source, tc->handler);
		idx++;
	}
	return true;
}

// https://nshipster.com/type-encodings/
static char *objc_type_toc(const char *objc_type) {
	if (!objc_type) {
		return strdup("void*");
	}
	if (*objc_type == '^' && objc_type[1] == '{') {
		char *a = strdup(objc_type + 2);
		char *b = strchr(a, '>');
		if (b) {
			*b = 0;
		}
		a[strlen(a) - 1] = 0;
		return a;
	}
	if (*objc_type == '<') {
		char *a = strdup(objc_type + 1);
		char *b = strchr(a, '>');
		if (b) {
			*b = 0;
		}
		return a;
	}
	if (!strcmp(objc_type, "f")) {
		return strdup("float");
	}
	if (!strcmp(objc_type, "d")) {
		return strdup("double");
	}
	if (!strcmp(objc_type, "i")) {
		return strdup("int");
	}
	if (!strcmp(objc_type, "s")) {
		return strdup("short");
	}
	if (!strcmp(objc_type, "l")) {
		return strdup("long");
	}
	if (!strcmp(objc_type, "L")) {
		return strdup("unsigned long");
	}
	if (!strcmp(objc_type, "*")) {
		return strdup("char*");
	}
	if (!strcmp(objc_type, "c")) {
		return strdup("bool");
	}
	if (!strcmp(objc_type, "v")) {
		return strdup("void");
	}
	if (!strcmp(objc_type, "#")) {
		return strdup("class");
	}
	if (!strcmp(objc_type, "B")) {
		return strdup("cxxbool");
	}
	if (!strcmp(objc_type, "Q")) {
		return strdup("uint64_t");
	}
	if (!strcmp(objc_type, "q")) {
		return strdup("long long");
	}
	if (!strcmp(objc_type, "C")) {
		return strdup("uint8_t");
	}
	if (strlen(objc_type) == 1) {
		eprintf("Unknown objc type '%s'\n", objc_type);
	}
	if (rz_str_startswith(objc_type, "@\"")) {
		char *s = rz_str_newf("struct %s", objc_type + 2);
		s[strlen(s) - 1] = '*';
		return s;
	}
	return strdup(objc_type);
}

static char *objc_name_toc(const char *objc_name) {
	const char *n = rz_str_lchr(objc_name, ')');
	char *s = strdup(n ? n + 1 : objc_name);
	char *p = strchr(s, '(');
	if (p) {
		*p = 0;
	}
	return s;
}

static void classdump_c(RzCore *r, RzBinClass *c) {
	rz_cons_printf("typedef struct class_%s {\n", c->name);
	RzListIter *iter2;
	RzBinField *f;
	rz_list_foreach (c->fields, iter2, f) {
		if (f->type && f->name) {
			char *n = objc_name_toc(f->name);
			char *t = objc_type_toc(f->type);
			rz_cons_printf("    %s %s; // %d\n", t, n, f->offset);
			free(t);
			free(n);
		}
	}
	rz_cons_printf("} %s;\n", c->name);
}

static void classdump_objc(RzCore *r, RzBinClass *c) {
	if (c->super) {
		rz_cons_printf("@interface %s : %s\n{\n", c->name, c->super);
	} else {
		rz_cons_printf("@interface %s\n{\n", c->name);
	}
	RzListIter *iter2, *iter3;
	RzBinField *f;
	RzBinSymbol *sym;
	rz_list_foreach (c->fields, iter2, f) {
		if (f->name && rz_regex_match("ivar", "e", f->name)) {
			rz_cons_printf("  %s %s\n", f->type, f->name);
		}
	}
	rz_cons_printf("}\n");
	rz_list_foreach (c->methods, iter3, sym) {
		if (sym->rtype && sym->rtype[0] != '@') {
			char *rp = get_rp(sym->rtype);
			rz_cons_printf("%s (%s) %s\n",
				strncmp(sym->type, RZ_BIN_TYPE_METH_STR, 4) ? "+" : "-",
				rp, sym->dname ? sym->dname : sym->name);
			free(rp);
		} else if (sym->type) {
			rz_cons_printf("%s (id) %s\n",
				strncmp(sym->type, RZ_BIN_TYPE_METH_STR, 4) ? "+" : "-",
				sym->dname ? sym->dname : sym->name);
		}
	}
	rz_cons_printf("@end\n");
}

static void classdump_java(RzCore *r, RzBinClass *c) {
	RzBinField *f;
	RzListIter *iter2, *iter3;
	RzBinSymbol *sym;
	char *pn = strdup(c->name);
	char *cn = (char *)rz_str_rchr(pn, NULL, '/');
	if (cn) {
		*cn = 0;
		cn++;
		rz_str_replace_char(pn, '/', '.');
	}
	rz_cons_printf("package %s;\n\n", pn);
	rz_cons_printf("public class %s {\n", cn);
	free(pn);
	rz_list_foreach (c->fields, iter2, f) {
		if (f->name && rz_regex_match("ivar", "e", f->name)) {
			rz_cons_printf("  public %s %s\n", f->type, f->name);
		}
	}
	rz_list_foreach (c->methods, iter3, sym) {
		const char *mn = sym->dname ? sym->dname : sym->name;
		const char *ms = strstr(mn, "method.");
		if (ms) {
			mn = ms + strlen("method.");
		}
		rz_cons_printf("  public %s ();\n", mn);
	}
	rz_cons_printf("}\n\n");
}

static int bin_classes(RzCore *r, PJ *pj, int mode) {
	RzListIter *iter, *iter2, *iter3;
	RzBinSymbol *sym;
	RzBinClass *c;
	RzBinField *f;
	char *name;
	RzList *cs = rz_bin_get_classes(r->bin);
	if (!cs) {
		if (IS_MODE_JSON(mode)) {
			pj_a(pj);
			pj_end(pj);
			return true;
		}
		return false;
	}
	// XXX: support for classes is broken and needs more love
	if (IS_MODE_JSON(mode)) {
		pj_a(pj);
	} else if (IS_MODE_RZCMD(mode) && !IS_MODE_CLASSDUMP(mode)) {
		rz_cons_println("fs classes");
	}

	rz_list_foreach (cs, iter, c) {
		if (!c || !c->name || !c->name[0]) {
			continue;
		}
		name = strdup(c->name);
		rz_name_filter(name, 0, true);
		ut64 at_min = UT64_MAX;
		ut64 at_max = 0LL;

		rz_list_foreach (c->methods, iter2, sym) {
			if (sym->vaddr) {
				if (sym->vaddr < at_min) {
					at_min = sym->vaddr;
				}
				if (sym->vaddr + sym->size > at_max) {
					at_max = sym->vaddr + sym->size;
				}
			}
		}
		if (at_min == UT64_MAX) {
			at_min = c->addr;
			at_max = c->addr; // XXX + size?
		}

		if (IS_MODE_SIMPLEST(mode)) {
			rz_cons_printf("%s\n", c->name);
		} else if (IS_MODE_SIMPLE(mode)) {
			rz_cons_printf("0x%08" PFMT64x " [0x%08" PFMT64x " - 0x%08" PFMT64x "] %s%s%s\n",
				c->addr, at_min, at_max, c->name, c->super ? " " : "",
				c->super ? c->super : "");
		} else if (IS_MODE_CLASSDUMP(mode)) {
			if (c) {
				RzBinFile *bf = rz_bin_cur(r->bin);
				if (bf && bf->o) {
					if (IS_MODE_RZCMD(mode)) {
						classdump_c(r, c);
					} else if (bf->o->lang == RZ_BIN_NM_JAVA || (bf->o->info && bf->o->info->lang && strstr(bf->o->info->lang, "dalvik"))) {
						classdump_java(r, c);
					} else {
						classdump_objc(r, c);
					}
				} else {
					classdump_objc(r, c);
				}
			}
		} else if (IS_MODE_RZCMD(mode)) {
			char *n = __filterShell(name);
			rz_cons_printf("\"f class.%s = 0x%" PFMT64x "\"\n", n, at_min);
			free(n);
			if (c->super) {
				char *cn = c->name; // __filterShell (c->name);
				char *su = c->super; // __filterShell (c->super);
				rz_cons_printf("\"f super.%s.%s = %d\"\n",
					cn, su, c->index);
				// free (cn);
				// free (su);
			}
			rz_list_foreach (c->methods, iter2, sym) {
				char *fn = rz_core_bin_method_build_flag_name(c, sym);
				if (fn) {
					rz_cons_printf("\"f %s = 0x%" PFMT64x "\"\n", fn, sym->vaddr);
					free(fn);
				}
			}
			rz_list_foreach (c->fields, iter2, f) {
				char *fn = rz_str_newf("field.%s.%s", c->name, f->name);
				ut64 at = f->vaddr; //  sym->vaddr + (f->vaddr &  0xffff);
				rz_cons_printf("\"f %s = 0x%08" PFMT64x "\"\n", fn, at);
				free(fn);
			}

			// C struct
			rz_cons_printf("td \"struct %s {", c->name);
			if (rz_list_empty(c->fields)) {
				// XXX workaround because we cant register empty structs yet
				// XXX https://github.com/rizinorg/rizin/issues/16342
				rz_cons_printf(" char empty[0];");
			} else {
				rz_list_foreach (c->fields, iter2, f) {
					char *n = objc_name_toc(f->name);
					char *t = objc_type_toc(f->type);
					rz_cons_printf(" %s %s;", t, n);
					free(t);
					free(n);
				}
			}
			rz_cons_printf("};\"\n");
		} else if (IS_MODE_JSON(mode)) {
			pj_o(pj);
			pj_ks(pj, "classname", c->name);
			pj_kN(pj, "addr", c->addr);
			pj_ki(pj, "index", c->index);
			if (c->super) {
				pj_ks(pj, "visibility", c->visibility_str ? c->visibility_str : "");
				pj_ks(pj, "super", c->super);
			}
			pj_ka(pj, "methods");
			rz_list_foreach (c->methods, iter2, sym) {
				pj_o(pj);
				pj_ks(pj, "name", sym->name);
				if (sym->method_flags) {
					char *mflags = rz_core_bin_method_flags_str(sym->method_flags, mode);
					pj_k(pj, "flags");
					pj_j(pj, mflags);
					free(mflags);
				}
				pj_kN(pj, "addr", sym->vaddr);
				pj_end(pj);
			}
			pj_end(pj);
			pj_ka(pj, "fields");
			rz_list_foreach (c->fields, iter3, f) {
				pj_o(pj);
				pj_ks(pj, "name", f->name);
				if (f->flags) {
					char *mflags = rz_core_bin_method_flags_str(f->flags, mode);
					pj_k(pj, "flags");
					pj_j(pj, mflags);
					free(mflags);
				}
				pj_kN(pj, "addr", f->vaddr);
				pj_end(pj);
			}
			pj_end(pj);
			pj_end(pj);
		} else {
			int m = 0;
			rz_cons_printf("0x%08" PFMT64x " [0x%08" PFMT64x " - 0x%08" PFMT64x "] %6" PFMT64d " class %d %s",
				c->addr, at_min, at_max, (at_max - at_min), c->index, c->name);
			if (c->super) {
				rz_cons_printf(" :: %s\n", c->super);
			} else {
				rz_cons_newline();
			}
			rz_list_foreach (c->methods, iter2, sym) {
				char *mflags = rz_core_bin_method_flags_str(sym->method_flags, mode);
				rz_cons_printf("0x%08" PFMT64x " method %d %s %s\n",
					sym->vaddr, m, mflags, sym->dname ? sym->dname : sym->name);
				RZ_FREE(mflags);
				m++;
			}
		}
		free(name);
	}
	if (IS_MODE_JSON(mode)) {
		pj_end(pj);
	}

	return true;
}

static int bin_size(RzCore *r, PJ *pj, int mode) {
	ut64 size = rz_bin_get_size(r->bin);
	if (IS_MODE_SIMPLE(mode)) {
		rz_cons_printf("%" PFMT64u "\n", size);
	} else if (IS_MODE_JSON(mode)) {
		pj_n(pj, size);
	} else if (IS_MODE_RZCMD(mode)) {
		rz_cons_printf("f bin_size @ %" PFMT64u "\n", size);
	} else {
		rz_cons_printf("%" PFMT64u "\n", size);
	}
	return true;
}

static int bin_libs(RzCore *r, PJ *pj, int mode) {
	RzListIter *iter;
	char *lib;
	int i = 0;

	RzList *libs = rz_bin_get_libs(r->bin);
	if (IS_MODE_JSON(mode)) {
		pj_a(pj);
	} else {
		if (!libs) {
			return false;
		}
		if (IS_MODE_NORMAL(mode)) {
			rz_cons_println("[Linked libraries]");
		}
	}
	rz_list_foreach (libs, iter, lib) {
		if (IS_MODE_RZCMD(mode)) {
			rz_cons_printf("\"CCa entry0 %s\"\n", lib);
		} else if (IS_MODE_JSON(mode)) {
			pj_s(pj, lib);
		} else {
			// simple and normal print mode
			rz_cons_println(lib);
		}
		i++;
	}
	if (IS_MODE_JSON(mode)) {
		pj_end(pj);
	} else if (IS_MODE_NORMAL(mode)) {
		const char *libstr = (i > 1) ? "libraries" : "library";
		rz_cons_printf("\n%i %s\n", i, libstr);
	}
	return true;
}

static void bin_mem_print(PJ *pj, RzList *mems, int perms, int depth, int mode) {
	RzBinMem *mem;
	RzListIter *iter;
	if (!mems) {
		return;
	}
	rz_list_foreach (mems, iter, mem) {
		if (IS_MODE_JSON(mode)) {
			pj_o(pj);
			pj_ks(pj, "name", mem->name);
			pj_ki(pj, "size", mem->size);
			pj_kn(pj, "address", mem->addr);
			pj_ks(pj, "flags", rz_str_rwx_i(mem->perms & perms));
			pj_end(pj);
		} else if (IS_MODE_SIMPLE(mode)) {
			rz_cons_printf("0x%08" PFMT64x "\n", mem->addr);
		} else {
			rz_cons_printf("0x%08" PFMT64x " +0x%04x %s %*s%-*s\n",
				mem->addr, mem->size, rz_str_rwx_i(mem->perms & perms),
				depth, "", 20 - depth, mem->name);
		}
		if (mem->mirrors) {
			bin_mem_print(pj, mem->mirrors, mem->perms & perms, depth + 1, mode);
		}
	}
}

static int bin_mem(RzCore *r, PJ *pj, int mode) {
	RzList *mem = NULL;
	if (!r) {
		return false;
	}
	if (!IS_MODE_JSON(mode)) {
		if (!(IS_MODE_RZCMD(mode) || IS_MODE_SET(mode))) {
			rz_cons_println("[Memory]\n");
		}
	}
	if (!(mem = rz_bin_get_mem(r->bin))) {
		if (IS_MODE_JSON(mode)) {
			pj_a(pj);
			pj_end(pj);
			return true;
		}
		return false;
	}
	if (IS_MODE_JSON(mode)) {
		pj_a(pj);
		bin_mem_print(pj, mem, 7, 0, RZ_MODE_JSON);
		pj_end(pj);
		return true;
	} else if (!IS_MODE_RZCMD(mode)) {
		bin_mem_print(NULL, mem, 7, 0, mode);
	}
	return true;
}

static void bin_pe_versioninfo(RzCore *r, PJ *pj, int mode) {
	Sdb *sdb = NULL;
	int num_version = 0;
	int num_stringtable = 0;
	int num_string = 0;
	const char *format_version = "bin/cur/info/vs_version_info/VS_VERSIONINFO%d";
	const char *format_stringtable = "%s/string_file_info/stringtable%d";
	const char *format_string = "%s/string%d";
	if (!IS_MODE_JSON(mode)) {
		rz_cons_printf("=== VS_VERSIONINFO ===\n\n");
	} else {
		pj_o(pj);
	}
	do {
		char *path_version = sdb_fmt(format_version, num_version);
		if (!sdb_ns_path(r->sdb, path_version, 0)) {
			break;
		}
		if (IS_MODE_JSON(mode)) {
			pj_ko(pj, "VS_FIXEDFILEINFO");
		} else {
			rz_cons_printf("# VS_FIXEDFILEINFO\n\n");
		}
		const char *path_fixedfileinfo = sdb_fmt("%s/fixed_file_info", path_version);
		if (!(sdb = sdb_ns_path(r->sdb, path_fixedfileinfo, 0))) {
			if (IS_MODE_JSON(mode)) {
				pj_end(pj);
			}
			break;
		}
		ut32 file_version_ms = sdb_num_get(sdb, "FileVersionMS", 0);
		ut32 file_version_ls = sdb_num_get(sdb, "FileVersionLS", 0);
		char *file_version = rz_str_newf("%u.%u.%u.%u", file_version_ms >> 16, file_version_ms & 0xFFFF,
			file_version_ls >> 16, file_version_ls & 0xFFFF);
		ut32 product_version_ms = sdb_num_get(sdb, "ProductVersionMS", 0);
		ut32 product_version_ls = sdb_num_get(sdb, "ProductVersionLS", 0);
		char *product_version = rz_str_newf("%u.%u.%u.%u", product_version_ms >> 16, product_version_ms & 0xFFFF,
			product_version_ls >> 16, product_version_ls & 0xFFFF);
		if (IS_MODE_JSON(mode)) {
			pj_kn(pj, "Signature", sdb_num_get(sdb, "Signature", 0));
			pj_kn(pj, "StrucVersion", sdb_num_get(sdb, "StrucVersion", 0));
			pj_ks(pj, "FileVersion", file_version);
			pj_ks(pj, "ProductVersion", product_version);
			pj_kn(pj, "FileFlagsMask", sdb_num_get(sdb, "FileFlagsMask", 0));
			pj_kn(pj, "FileFlags", sdb_num_get(sdb, "FileFlags", 0));
			pj_kn(pj, "FileOS", sdb_num_get(sdb, "FileOS", 0));
			pj_kn(pj, "FileType", sdb_num_get(sdb, "FileType", 0));
			pj_kn(pj, "FileSubType", sdb_num_get(sdb, "FileSubType", 0));
			pj_end(pj);
		} else {
			rz_cons_printf("  Signature: 0x%" PFMT64x "\n", sdb_num_get(sdb, "Signature", 0));
			rz_cons_printf("  StrucVersion: 0x%" PFMT64x "\n", sdb_num_get(sdb, "StrucVersion", 0));
			rz_cons_printf("  FileVersion: %s\n", file_version);
			rz_cons_printf("  ProductVersion: %s\n", product_version);
			rz_cons_printf("  FileFlagsMask: 0x%" PFMT64x "\n", sdb_num_get(sdb, "FileFlagsMask", 0));
			rz_cons_printf("  FileFlags: 0x%" PFMT64x "\n", sdb_num_get(sdb, "FileFlags", 0));
			rz_cons_printf("  FileOS: 0x%" PFMT64x "\n", sdb_num_get(sdb, "FileOS", 0));
			rz_cons_printf("  FileType: 0x%" PFMT64x "\n", sdb_num_get(sdb, "FileType", 0));
			rz_cons_printf("  FileSubType: 0x%" PFMT64x "\n", sdb_num_get(sdb, "FileSubType", 0));
			rz_cons_newline();
		}
		free(file_version);
		free(product_version);
#if 0
		rz_cons_printf ("  FileDate: %d.%d.%d.%d\n",
			sdb_num_get (sdb, "FileDateMS", 0) >> 16,
			sdb_num_get (sdb, "FileDateMS", 0) & 0xFFFF,
			sdb_num_get (sdb, "FileDateLS", 0) >> 16,
			sdb_num_get (sdb, "FileDateLS", 0) & 0xFFFF);
#endif
		if (IS_MODE_JSON(mode)) {
			pj_ko(pj, "StringTable");
		} else {
			rz_cons_printf("# StringTable\n\n");
		}
		for (num_stringtable = 0; sdb; num_stringtable++) {
			char *path_stringtable = rz_str_newf(format_stringtable, path_version, num_stringtable);
			sdb = sdb_ns_path(r->sdb, path_stringtable, 0);
			for (num_string = 0; sdb; num_string++) {
				char *path_string = rz_str_newf(format_string, path_stringtable, num_string);
				sdb = sdb_ns_path(r->sdb, path_string, 0);
				if (sdb) {
					int lenkey = 0;
					int lenval = 0;
					ut8 *key_utf16 = sdb_decode(sdb_const_get(sdb, "key", 0), &lenkey);
					ut8 *val_utf16 = sdb_decode(sdb_const_get(sdb, "value", 0), &lenval);
					ut8 *key_utf8 = calloc(lenkey * 2, 1);
					ut8 *val_utf8 = calloc(lenval * 2, 1);
					if (rz_str_utf16_to_utf8(key_utf8, lenkey * 2, key_utf16, lenkey, true) < 0 || rz_str_utf16_to_utf8(val_utf8, lenval * 2, val_utf16, lenval, true) < 0) {
						eprintf("Warning: Cannot decode utf16 to utf8\n");
					} else if (IS_MODE_JSON(mode)) {
						pj_ks(pj, (char *)key_utf8, (char *)val_utf8);
					} else {
						rz_cons_printf("  %s: %s\n", (char *)key_utf8, (char *)val_utf8);
					}
					free(key_utf8);
					free(val_utf8);
					free(key_utf16);
					free(val_utf16);
				}
				free(path_string);
			}
			free(path_stringtable);
		}
		if (IS_MODE_JSON(mode)) {
			pj_end(pj);
		}
		num_version++;
	} while (sdb);
	if (IS_MODE_JSON(mode)) {
		pj_end(pj);
	}
}

static void bin_elf_versioninfo_versym(RzCore *r, PJ *pj, int mode) {
	if (IS_MODE_JSON(mode)) {
		pj_o(pj);
		pj_ka(pj, "versym");
	}

	Sdb *sdb = sdb_ns_path(r->sdb, "bin/cur/info/versioninfo/versym", 0);
	if (!sdb) {
		return;
	}

	const ut64 addr = sdb_num_get(sdb, "addr", 0);
	const ut64 offset = sdb_num_get(sdb, "offset", 0);
	const ut64 num_entries = sdb_num_get(sdb, "num_entries", 0);

	if (IS_MODE_JSON(mode)) {
		pj_o(pj);
		pj_kn(pj, "address", addr);
		pj_kn(pj, "offset", offset);
		pj_ka(pj, "entries");
	} else {
		rz_cons_printf("Version symbols has %" PFMT64u " entries:\n", num_entries);
		rz_cons_printf(" Addr: 0x%08" PFMT64x "  Offset: 0x%08" PFMT64x "\n",
			(ut64)addr, (ut64)offset);
	}

	for (size_t i = 0; i < num_entries; i++) {
		const char *const key = sdb_fmt("entry%zu", i);
		const char *const value = sdb_const_get(sdb, key, 0);

		if (!value) {
			continue;
		}

		if (IS_MODE_JSON(mode)) {
			pj_o(pj);
			pj_kn(pj, "idx", (ut64)i);
			pj_ks(pj, "value", value);
			pj_end(pj);
		} else {
			rz_cons_printf("  0x%08" PFMT64x ": ", (ut64)i);
			rz_cons_printf("%s\n", value);
		}
	}

	if (IS_MODE_JSON(mode)) {
		pj_end(pj);
		pj_end(pj);
	} else {
		rz_cons_printf("\n\n");
	}
}

static void bin_elf_versioninfo_verneed(RzCore *r, PJ *pj, int mode) {
	if (IS_MODE_JSON(mode)) {
		pj_end(pj);
		pj_ka(pj, "verneed");
	}

	Sdb *sdb = sdb_ns_path(r->sdb, "bin/cur/info/versioninfo/verneed", 0);
	if (!sdb) {
		return;
	}

	const ut64 address = sdb_num_get(sdb, "addr", 0);
	const ut64 offset = sdb_num_get(sdb, "offset", 0);

	if (IS_MODE_JSON(mode)) {
		pj_o(pj);
		pj_kn(pj, "address", address);
		pj_kn(pj, "offset", offset);
		pj_ka(pj, "entries");
	} else {
		rz_cons_printf("Version need has %d entries:\n",
			(int)sdb_num_get(sdb, "num_entries", 0));

		rz_cons_printf(" Addr: 0x%08" PFMT64x, address);

		rz_cons_printf("  Offset: 0x%08" PFMT64x "\n", offset);
	}

	for (size_t num_version = 0;; num_version++) {
		const char *filename = NULL;
		int num_vernaux = 0;

		char *path_version = sdb_fmt("bin/cur/info/versioninfo/verneed/version%zu", num_version);
		sdb = sdb_ns_path(r->sdb, path_version, 0);

		if (!sdb) {
			break;
		}

		if (IS_MODE_JSON(mode)) {
			pj_o(pj);
			pj_kn(pj, "idx", sdb_num_get(sdb, "idx", 0));
			pj_ki(pj, "vn_version", (int)sdb_num_get(sdb, "vn_version", 0));
		} else {
			rz_cons_printf("  0x%08" PFMT64x ": Version: %d",
				sdb_num_get(sdb, "idx", 0), (int)sdb_num_get(sdb, "vn_version", 0));
		}

		if ((filename = sdb_const_get(sdb, "file_name", 0))) {
			if (IS_MODE_JSON(mode)) {
				pj_ks(pj, "file_name", filename);
			} else {
				rz_cons_printf("  File: %s", filename);
			}
		}

		const int cnt = (int)sdb_num_get(sdb, "cnt", 0);

		if (IS_MODE_JSON(mode)) {
			pj_ki(pj, "cnt", cnt);
		} else {
			rz_cons_printf("  Cnt: %d\n", cnt);
		}

		if (IS_MODE_JSON(mode)) {
			pj_ka(pj, "vernaux");
		}

		do {
			const char *const path_vernaux = sdb_fmt("%s/vernaux%d", path_version, num_vernaux++);

			sdb = sdb_ns_path(r->sdb, path_vernaux, 0);
			if (!sdb) {
				break;
			}

			const ut64 idx = sdb_num_get(sdb, "idx", 0);
			const char *const name = sdb_const_get(sdb, "name", 0);
			const char *const flags = sdb_const_get(sdb, "flags", 0);
			const int version = (int)sdb_num_get(sdb, "version", 0);

			if (IS_MODE_JSON(mode)) {
				pj_o(pj);
				pj_kn(pj, "idx", idx);
				pj_ks(pj, "name", name);
				pj_ks(pj, "flags", flags);
				pj_ki(pj, "version", version);
				pj_end(pj);
			} else {
				rz_cons_printf("  0x%08" PFMT64x ":   Name: %s", idx, name);
				rz_cons_printf("  Flags: %s Version: %d\n", flags, version);
			}
		} while (sdb);

		if (IS_MODE_JSON(mode)) {
			pj_end(pj);
			pj_end(pj);
		}
	}

	if (IS_MODE_JSON(mode)) {
		pj_end(pj);
		pj_end(pj);
	}

	if (IS_MODE_JSON(mode)) {
		pj_end(pj);
		pj_end(pj);
	}
}

static void bin_elf_versioninfo(RzCore *r, PJ *pj, int mode) {
	bin_elf_versioninfo_versym(r, pj, mode);
	bin_elf_versioninfo_verneed(r, pj, mode);
}

static void bin_mach0_versioninfo(RzCore *r) {
	/* TODO */
}

static void bin_pe_resources(RzCore *r, PJ *pj, int mode) {
	Sdb *sdb = NULL;
	int index = 0;
	const char *pe_path = "bin/cur/info/pe_resource";
	if (!(sdb = sdb_ns_path(r->sdb, pe_path, 0))) {
		return;
	}
	if (IS_MODE_RZCMD(mode)) {
		rz_cons_printf("fs resources\n");
	} else if (IS_MODE_JSON(mode)) {
		pj_a(pj);
	}
	while (true) {
		const char *timestrKey = sdb_fmt("resource.%d.timestr", index);
		const char *vaddrKey = sdb_fmt("resource.%d.vaddr", index);
		const char *sizeKey = sdb_fmt("resource.%d.size", index);
		const char *typeKey = sdb_fmt("resource.%d.type", index);
		const char *languageKey = sdb_fmt("resource.%d.language", index);
		const char *nameKey = sdb_fmt("resource.%d.name", index);
		char *timestr = sdb_get(sdb, timestrKey, 0);
		if (!timestr) {
			break;
		}
		ut64 vaddr = sdb_num_get(sdb, vaddrKey, 0);
		int size = (int)sdb_num_get(sdb, sizeKey, 0);
		char *name = sdb_get(sdb, nameKey, 0);
		char *type = sdb_get(sdb, typeKey, 0);
		char *lang = sdb_get(sdb, languageKey, 0);

		if (IS_MODE_RZCMD(mode)) {
			rz_cons_printf("f resource.%d %d 0x%08" PFMT64x "\n", index, size, vaddr);
		} else if (IS_MODE_JSON(mode)) {
			pj_o(pj);
			pj_ks(pj, "name", name);
			pj_ki(pj, "index", index);
			pj_ks(pj, "type", type);
			pj_kn(pj, "vaddr", vaddr);
			pj_ki(pj, "size", size);
			pj_ks(pj, "lang", lang);
			pj_ks(pj, "timestamp", timestr);
			pj_end(pj);
		} else {
			char humansz[8];
			rz_num_units(humansz, sizeof(humansz), size);
			rz_cons_printf("Resource %d\n", index);
			rz_cons_printf("  name: %s\n", name);
			rz_cons_printf("  timestamp: %s\n", timestr);
			rz_cons_printf("  vaddr: 0x%08" PFMT64x "\n", vaddr);
			rz_cons_printf("  size: %s\n", humansz);
			rz_cons_printf("  type: %s\n", type);
			rz_cons_printf("  language: %s\n", lang);
		}

		RZ_FREE(timestr);
		RZ_FREE(name);
		RZ_FREE(type);
		RZ_FREE(lang)

		index++;
	}
	if (IS_MODE_JSON(mode)) {
		pj_end(pj);
	} else if (IS_MODE_RZCMD(mode)) {
		rz_cons_println("fs *");
	}
}

static void bin_no_resources(RzCore *r, PJ *pj, int mode) {
	if (IS_MODE_JSON(mode)) {
		pj_a(pj);
		pj_end(pj);
	}
}

static int bin_resources(RzCore *r, PJ *pj, int mode) {
	const RzBinInfo *info = rz_bin_get_info(r->bin);
	if (!info || !info->rclass) {
		return false;
	}
	if (!strncmp("pe", info->rclass, 2)) {
		bin_pe_resources(r, pj, mode);
	} else {
		bin_no_resources(r, pj, mode);
	}
	return true;
}

static int bin_versioninfo(RzCore *r, PJ *pj, int mode) {
	const RzBinInfo *info = rz_bin_get_info(r->bin);
	if (!info || !info->rclass) {
		return false;
	}
	if (!strncmp("pe", info->rclass, 2)) {
		bin_pe_versioninfo(r, pj, mode);
	} else if (!strncmp("elf", info->rclass, 3)) {
		bin_elf_versioninfo(r, pj, mode);
	} else if (!strncmp("mach0", info->rclass, 5)) {
		bin_mach0_versioninfo(r);
	} else {
		rz_cons_println("Unknown format");
		return false;
	}
	return true;
}

static int bin_signature(RzCore *r, PJ *pj, int mode) {
	RzBinFile *cur = rz_bin_cur(r->bin);
	RzBinPlugin *plg = rz_bin_file_cur_plugin(cur);
	if (plg && plg->signature) {
		const char *signature = plg->signature(cur, IS_MODE_JSON(mode));
		if (!signature) {
			return false;
		}
		if (IS_MODE_JSON(mode)) {
			pj_o(pj);
			pj_k(pj, "signature");
			pj_j(pj, signature);
			pj_end(pj);
		} else {
			rz_cons_println(signature);
		}
		free((char *)signature);
		return true;
	}
	return false;
}

static int bin_header(RzCore *r, int mode) {
	RzBinFile *cur = rz_bin_cur(r->bin);
	RzBinPlugin *plg = rz_bin_file_cur_plugin(cur);
	if (plg && plg->header) {
		plg->header(cur);
		return true;
	}
	return false;
}

RZ_API int rz_core_bin_info(RzCore *core, int action, PJ *pj, int mode, int va, RzCoreBinFilter *filter, const char *chksum) {
	RzBinFile *binfile = rz_bin_cur(core->bin);
	int ret = true;
	const char *name = NULL;
	ut64 at = UT64_MAX, loadaddr = rz_bin_get_laddr(core->bin);
	if (filter && filter->offset) {
		at = filter->offset;
	}
	if (filter && filter->name) {
		name = filter->name;
	}

	// use our internal values for va
	va = va ? VA_TRUE : VA_FALSE;
#if 0
	if (rz_config_get_i (core->config, "analysis.strings")) {
		rz_core_cmd0 (core, "aar");
	}
#endif
	if ((action & RZ_CORE_BIN_ACC_RAW_STRINGS)) {
		ret &= bin_raw_strings(core, pj, mode, va);
	} else if ((action & RZ_CORE_BIN_ACC_STRINGS)) {
		const RzList *l = binfile ? core_bin_strings(core, binfile) : NULL;
		_print_strings(core, l, pj, mode, va);
		if (!l) {
			ret = false;
		}
	}
	if ((action & RZ_CORE_BIN_ACC_INFO)) {
		ret &= bin_info(core, pj, mode, loadaddr);
	}
	if ((action & RZ_CORE_BIN_ACC_MAIN)) {
		ret &= bin_main(core, binfile, pj, mode, va);
	}
	if ((action & RZ_CORE_BIN_ACC_DWARF)) {
		ret &= binfile ? bin_dwarf(core, binfile, pj, mode) : false;
	}
	if ((action & RZ_CORE_BIN_ACC_PDB)) {
		ret &= rz_core_pdb_info(core, core->bin->file, pj, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_ENTRIES)) {
		ret &= bin_entry(core, pj, mode, loadaddr, va, false);
	}
	if ((action & RZ_CORE_BIN_ACC_INITFINI)) {
		ret &= bin_entry(core, pj, mode, loadaddr, va, true);
	}
	if ((action & RZ_CORE_BIN_ACC_SECTIONS)) {
		ret &= bin_sections(core, pj, mode, loadaddr, va, at, name, chksum, false);
	}
	if ((action & RZ_CORE_BIN_ACC_SEGMENTS)) {
		ret &= bin_sections(core, pj, mode, loadaddr, va, at, name, chksum, true);
	}
	if ((action & RZ_CORE_BIN_ACC_SECTIONS_MAPPING)) {
		ret &= bin_map_sections_to_segments(core->bin, pj, mode);
	}
	if (rz_config_get_b(core->config, "bin.relocs")) {
		if ((action & RZ_CORE_BIN_ACC_RELOCS)) {
			ret &= bin_relocs(core, pj, mode, va);
		}
	}
	if ((action & RZ_CORE_BIN_ACC_LIBS)) {
		ret &= bin_libs(core, pj, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_IMPORTS)) { // 5s
		ret &= bin_imports(core, pj, mode, va, name);
	}
	if ((action & RZ_CORE_BIN_ACC_EXPORTS)) {
		ret &= bin_symbols(core, pj, mode, va, at, name, true, chksum);
	}
	if ((action & RZ_CORE_BIN_ACC_SYMBOLS)) { // 6s
		ret &= bin_symbols(core, pj, mode, va, at, name, false, chksum);
	}
	if ((action & RZ_CORE_BIN_ACC_CLASSES)) { // 6s
		ret &= bin_classes(core, pj, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_TRYCATCH)) {
		ret &= bin_trycatch(core, pj, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_SIZE)) {
		ret &= bin_size(core, pj, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_MEM)) {
		ret &= bin_mem(core, pj, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_VERSIONINFO)) {
		ret &= bin_versioninfo(core, pj, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_RESOURCES)) {
		ret &= bin_resources(core, pj, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_SIGNATURE)) {
		ret &= bin_signature(core, pj, mode);
	}
	if ((action & RZ_CORE_BIN_ACC_FIELDS)) {
		if (IS_MODE_SIMPLE(mode)) {
			if ((action & RZ_CORE_BIN_ACC_HEADER) || action & RZ_CORE_BIN_ACC_FIELDS) {
				/* ignore mode, just for quiet/simple here */
				ret &= bin_fields(core, NULL, 0, va);
			}
		} else {
			if (IS_MODE_NORMAL(mode)) {
				ret &= bin_header(core, mode);
			} else {
				if ((action & RZ_CORE_BIN_ACC_HEADER) || action & RZ_CORE_BIN_ACC_FIELDS) {
					ret &= bin_fields(core, pj, mode, va);
				}
			}
		}
	}
	return ret;
}

RZ_API int rz_core_bin_set_arch_bits(RzCore *r, const char *name, const char *arch, ut16 bits) {
	int fd = rz_io_fd_get_current(r->io);
	RzIODesc *desc = rz_io_desc_get(r->io, fd);
	RzBinFile *curfile, *binfile = NULL;
	if (!name) {
		if (!desc || !desc->name) {
			return false;
		}
		name = desc->name;
	}
	/* Check if the arch name is a valid name */
	if (!rz_asm_is_valid(r->rasm, arch)) {
		return false;
	}
	/* Find a file with the requested name/arch/bits */
	binfile = rz_bin_file_find_by_arch_bits(r->bin, arch, bits);
	if (!binfile) {
		return false;
	}
	if (!rz_bin_use_arch(r->bin, arch, bits, name)) {
		return false;
	}
	curfile = rz_bin_cur(r->bin);
	//set env if the binfile changed or we are dealing with xtr
	if (curfile != binfile || binfile->curxtr) {
		rz_core_bin_set_cur(r, binfile);
		return rz_core_bin_apply_all_info(r, binfile);
	}
	return true;
}

RZ_API int rz_core_bin_update_arch_bits(RzCore *r) {
	RzBinFile *binfile = NULL;
	const char *name = NULL, *arch = NULL;
	ut16 bits = 0;
	if (!r) {
		return 0;
	}
	if (r->rasm) {
		bits = r->rasm->bits;
		if (r->rasm->cur) {
			arch = r->rasm->cur->arch;
		}
	}
	binfile = rz_bin_cur(r->bin);
	name = binfile ? binfile->file : NULL;
	if (binfile && binfile->curxtr) {
		rz_analysis_hint_clear(r->analysis);
	}
	return rz_core_bin_set_arch_bits(r, name, arch, bits);
}

RZ_API bool rz_core_bin_raise(RzCore *core, ut32 bfid) {
	if (!rz_bin_select_bfid(core->bin, bfid)) {
		return false;
	}
	RzBinFile *bf = rz_bin_cur(core->bin);
	if (bf) {
		rz_io_use_fd(core->io, bf->fd);
	}
	// it should be 0 to use rz_io_use_fd in rz_core_block_read
	core->switch_file_view = 0;
	return bf && rz_core_bin_apply_all_info(core, bf) && rz_core_block_read(core);
}

RZ_API bool rz_core_bin_delete(RzCore *core, RzBinFile *bf) {
	rz_bin_file_delete(core->bin, bf);
	bf = rz_bin_file_at(core->bin, core->offset);
	if (bf) {
		rz_io_use_fd(core->io, bf->fd);
	}
	core->switch_file_view = 0;
	return bf && rz_core_bin_apply_all_info(core, bf) && rz_core_block_read(core);
}

static bool rz_core_bin_file_print(RzCore *core, RzBinFile *bf, PJ *pj, int mode) {
	rz_return_val_if_fail(core && bf && bf->o, false);
	const char *name = bf ? bf->file : NULL;
	(void)rz_bin_get_info(core->bin); // XXX is this necssary for proper iniitialization
	ut32 bin_sz = bf ? bf->size : 0;
	// TODO: handle mode to print in json and r2 commands

	switch (mode) {
	case '*': {
		char *n = __filterShell(name);
		rz_cons_printf("oba 0x%08" PFMT64x " %s # %d\n", bf->o->boffset, n, bf->id);
		free(n);
		break;
	}
	case 'q':
		rz_cons_printf("%d\n", bf->id);
		break;
	case 'j': {
		pj_o(pj);
		pj_ks(pj, "name", name ? name : "");
		pj_ki(pj, "iofd", bf->fd);
		pj_ki(pj, "bfid", bf->id);
		pj_ki(pj, "size", bin_sz);
		pj_ko(pj, "obj");
		RzBinObject *obj = bf->o;
		RzBinInfo *info = obj->info;
		ut8 bits = info ? info->bits : 0;
		const char *asmarch = rz_config_get(core->config, "asm.arch");
		const char *arch = info
			? info->arch
				? info->arch
				: asmarch
			: "unknown";
		pj_ks(pj, "arch", arch);
		pj_ki(pj, "bits", bits);
		pj_kN(pj, "binoffset", obj->boffset);
		pj_kN(pj, "objsize", obj->obj_size);
		pj_end(pj);
		pj_end(pj);
		break;
	}
	default: {
		RzBinInfo *info = bf->o->info;
		ut8 bits = info ? info->bits : 0;
		const char *asmarch = rz_config_get(core->config, "asm.arch");
		const char *arch = info ? info->arch ? info->arch : asmarch : "unknown";
		rz_cons_printf("%d %d %s-%d ba:0x%08" PFMT64x " sz:%" PFMT64d " %s\n",
			bf->id, bf->fd, arch, bits, bf->o->opts.baseaddr, bf->o->size, name);
	} break;
	}
	return true;
}

RZ_API int rz_core_bin_list(RzCore *core, int mode) {
	// list all binfiles and there objects and there archs
	int count = 0;
	RzListIter *iter;
	RzBinFile *binfile = NULL; //, *cur_bf = rz_bin_cur (core->bin) ;
	RzBin *bin = core->bin;
	const RzList *binfiles = bin ? bin->binfiles : NULL;
	if (!binfiles) {
		return false;
	}
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = pj_new();
		if (!pj) {
			return 0;
		}
		pj_a(pj);
	}
	rz_list_foreach (binfiles, iter, binfile) {
		rz_core_bin_file_print(core, binfile, pj, mode);
	}
	if (mode == 'j') {
		pj_end(pj);
		rz_cons_print(pj_string(pj));
		pj_free(pj);
	}
	return count;
}

RZ_API char *rz_core_bin_method_build_flag_name(RzBinClass *cls, RzBinSymbol *meth) {
	rz_return_val_if_fail(cls && meth, NULL);
	if (!cls->name || !meth->name) {
		return NULL;
	}

	RzStrBuf buf;
	rz_strbuf_initf(&buf, "method");

	ut64 flags = meth->method_flags;
	for (int i = 0; flags; flags >>= 1, i++) {
		if (!(flags & 1)) {
			continue;
		}
		const char *flag_string = rz_bin_get_meth_flag_string(1ULL << i, false);
		if (flag_string) {
			rz_strbuf_appendf(&buf, ".%s", flag_string);
		}
	}

	rz_strbuf_appendf(&buf, ".%s.%s", cls->name, meth->name);
	char *ret = rz_strbuf_drain_nofree(&buf);
	if (ret) {
		rz_name_filter(ret, -1, true);
	}
	return ret;
}

RZ_API char *rz_core_bin_method_flags_str(ut64 flags, int mode) {
	int i;

	RzStrBuf *buf = rz_strbuf_new("");
	if (IS_MODE_JSON(mode)) {
		if (!flags) {
			rz_strbuf_append(buf, "[]");
			goto out;
		}
		PJ *pj = pj_new();
		pj_a(pj);
		for (i = 0; i < 64; i++) {
			ut64 flag = flags & (1ULL << i);
			if (flag) {
				const char *flag_string = rz_bin_get_meth_flag_string(flag, false);
				if (flag_string) {
					pj_s(pj, flag_string);
				} else {
					pj_s(pj, sdb_fmt("0x%08" PFMT64x, flag));
				}
			}
		}
		pj_end(pj);
		rz_strbuf_append(buf, pj_string(pj));
		pj_free(pj);
	} else {
		int pad_len = 4; //TODO: move to a config variable
		int len = 0;
		if (!flags) {
			goto padding;
		}
		for (i = 0; i < 64; i++) {
			ut64 flag = flags & (1ULL << i);
			if (flag) {
				const char *flag_string = rz_bin_get_meth_flag_string(flag, true);
				if (flag_string) {
					rz_strbuf_append(buf, flag_string);
				} else {
					rz_strbuf_append(buf, "?");
				}
				len++;
			}
		}
	padding:
		for (; len < pad_len; len++) {
			rz_strbuf_append(buf, " ");
		}
	}
out:
	return rz_strbuf_drain(buf);
}

static RzCoreStringKind get_string_kind(const ut8 *buf, ut64 len) {
	rz_return_val_if_fail(buf && len, RZ_CORE_STRING_KIND_UNKNOWN);
	ut64 needle = 0;
	ut64 rc, i;
	RzCoreStringKind str_kind = RZ_CORE_STRING_KIND_UNKNOWN;

	while (needle < len) {
		rc = rz_utf8_decode(buf + needle, len - needle, NULL);
		if (!rc) {
			needle++;
			continue;
		}
		if (needle + rc + 2 < len &&
			buf[needle + rc + 0] == 0x00 &&
			buf[needle + rc + 1] == 0x00 &&
			buf[needle + rc + 2] == 0x00) {
			str_kind = RZ_CORE_STRING_KIND_WIDE16;
		} else {
			str_kind = RZ_CORE_STRING_KIND_ASCII;
		}
		for (i = 0; needle < len; i += rc) {
			RzRune r;
			if (str_kind == RZ_CORE_STRING_KIND_WIDE16) {
				if (needle + 1 < len) {
					r = buf[needle + 1] << 8 | buf[needle];
					rc = 2;
				} else {
					break;
				}
			} else {
				rc = rz_utf8_decode(buf + needle, len - needle, &r);
				if (rc > 1) {
					str_kind = RZ_CORE_STRING_KIND_UTF8;
				}
			}
			/*Invalid sequence detected*/
			if (!rc) {
				needle++;
				break;
			}
			needle += rc;
		}
	}
	return str_kind;
}

/**
 * \brief Returns the information about string given the offset and legnth
 *
 * \param core RzCore instance
 * \param block Pointer to the string
 * \param len Length of the string
 * \param type A type of the string to override autodetection
 */
RZ_OWN RZ_API RzCoreString *rz_core_string_information(RzCore *core, const char *block, ut32 len, RzCoreStringKind kind) {
	rz_return_val_if_fail(core && block && len, NULL);
	RzCoreString *cstring = RZ_NEW0(RzCoreString);
	if (!cstring) {
		return NULL;
	}
	const char *section_name = rz_core_get_section_name(core, core->offset);
	if (section_name && strlen(section_name) < 1) {
		section_name = "unknown";
	}
	cstring->section_name = section_name;
	cstring->string = block;
	cstring->offset = core->offset;
	cstring->size = len;
	if (kind != RZ_CORE_STRING_KIND_UNKNOWN) {
		cstring->kind = kind;
	} else {
		cstring->kind = get_string_kind((const ut8 *)block, len);
	}
	// FIXME: Add proper length calculation (see functions in librz/util/str.c)
	cstring->length = cstring->size;
	return cstring;
}

RZ_API RzCmdStatus rz_core_bin_plugin_print(RzBinPlugin *bp, RzCmdStateOutput *state) {
	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET: {
		rz_cons_printf("%s\n", bp->name);
		break;
	}
	case RZ_OUTPUT_MODE_JSON: {
		pj_o(pj);
		pj_ks(pj, "name", bp->name);
		pj_ks(pj, "description", bp->desc);
		pj_ks(pj, "license", bp->license ? bp->license : "???");
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD: {
		rz_cons_printf("bin  %-11s %s (%s) %s %s\n",
			bp->name, bp->desc, bp->license ? bp->license : "???",
			bp->version ? bp->version : "",
			bp->author ? bp->author : "");
		break;
	}
	default: {
		rz_warn_if_reached();
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_API RzCmdStatus rz_core_binxtr_plugin_print(RzBinXtrPlugin *bx, RzCmdStateOutput *state) {
	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET: {
		rz_cons_printf("%s\n", bx->name);
		break;
	}
	case RZ_OUTPUT_MODE_JSON: {
		pj_o(pj);
		pj_ks(pj, "name", bx->name);
		pj_ks(pj, "description", bx->desc);
		pj_ks(pj, "license", bx->license ? bx->license : "???");
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD: {
		const char *name = strncmp(bx->name, "xtr.", 4) ? bx->name : bx->name + 3;
		rz_cons_printf("xtr  %-11s %s (%s)\n", name,
			bx->desc, bx->license ? bx->license : "???");
		break;
	}
	default: {
		rz_warn_if_reached();
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_API RzCmdStatus rz_core_binldr_plugin_print(RzBinLdrPlugin *ld, RzCmdStateOutput *state) {
	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET: {
		rz_cons_printf("%s\n", ld->name);
		break;
	}
	case RZ_OUTPUT_MODE_JSON: {
		pj_o(pj);
		pj_ks(pj, "name", ld->name);
		pj_ks(pj, "description", ld->desc);
		pj_ks(pj, "license", ld->license ? ld->license : "???");
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD: {
		const char *name = strncmp(ld->name, "ldr.", 4) ? ld->name : ld->name + 3;
		rz_cons_printf("ldr  %-11s %s (%s)\n", name,
			ld->desc, ld->license ? ld->license : "???");
		break;
	}
	default: {
		rz_warn_if_reached();
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_API RzCmdStatus rz_core_bin_plugins_print(RzBin *bin, RzCmdStateOutput *state) {
	RzBinPlugin *bp;
	RzBinXtrPlugin *bx;
	RzBinLdrPlugin *ld;
	RzListIter *iter;
	RzCmdStatus status;
	if (!bin) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cmd_state_output_array_start(state);
	rz_list_foreach (bin->plugins, iter, bp) {
		status = rz_core_bin_plugin_print(bp, state);
		if (status != RZ_CMD_STATUS_OK) {
			return status;
		}
	}
	rz_list_foreach (bin->binxtrs, iter, bx) {
		status = rz_core_binxtr_plugin_print(bx, state);
		if (status != RZ_CMD_STATUS_OK) {
			return status;
		}
	}
	rz_list_foreach (bin->binldrs, iter, ld) {
		status = rz_core_binldr_plugin_print(ld, state);
		if (status != RZ_CMD_STATUS_OK) {
			return status;
		}
	}
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}
