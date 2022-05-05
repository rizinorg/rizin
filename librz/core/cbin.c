// SPDX-FileCopyrightText: 2011-2020 earada <pkedurat@gmail.com>
// SPDX-FileCopyrightText: 2011-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_config.h>
#include <rz_demangler.h>
#include <rz_util.h>
#include <rz_list.h>
#include <rz_util/rz_time.h>
#include <rz_basefind.h>

#include "core_private.h"

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

static void table_add_row_bool(RzTable *t, const char *key, bool val) {
	RzTableColumnType *typeString = rz_table_type("bool");
	const char *b = val || typeString ? rz_str_bool(val) : "";
	rz_table_add_rowf(t, "ss", key, b);
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

	bool patch_relocs = rz_config_get_b(core->config, "bin.relocs");

	rz_bin_options_init(opts, fd, baseaddr, loadaddr, patch_relocs);

	opts->obj_opts.elf_load_sections = rz_config_get_b(core->config, "elf.load.sections");
	opts->obj_opts.elf_checks_sections = rz_config_get_b(core->config, "elf.checks.sections");
	opts->obj_opts.elf_checks_segments = rz_config_get_b(core->config, "elf.checks.segments");
	opts->obj_opts.big_endian = rz_config_get_b(core->config, "cfg.bigendian");
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
		// printf ("?e (%s) (%s)\n", k, v);
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
				RzTypeDB *typedb = core->analysis->typedb;
				int result = rz_type_parse_string_stateless(typedb->parser, code, &error_msg);
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
				rz_cons_printf("fL %s %s\n", flagname, v);
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

RZ_API bool rz_core_bin_load_structs(RZ_NONNULL RzCore *core, RZ_NONNULL const char *file) {
	rz_return_val_if_fail(core && file && core->io, false);
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

static bool add_footer(RzCmdStateOutput *main_state, RzCmdStateOutput *state) {
	if (state->mode == RZ_OUTPUT_MODE_TABLE) {
		char *s = rz_table_tostring(state->d.t);
		if (!s) {
			return false;
		}
		rz_cons_printf("%s\n", s);
		free(s);
	} else if (state->mode == RZ_OUTPUT_MODE_JSON || state->mode == RZ_OUTPUT_MODE_LONG_JSON) {
		const char *state_json = pj_string(state->d.pj);
		pj_raw(main_state->d.pj, state_json);
	}
	rz_cmd_state_output_free(state);
	return true;
}

static RzCmdStateOutput *add_header(RzCmdStateOutput *main_state, RzOutputMode default_mode, const char *header) {
	RzCmdStateOutput *state = RZ_NEW(RzCmdStateOutput);
	rz_cmd_state_output_init(state, main_state->mode == RZ_OUTPUT_MODE_STANDARD ? default_mode : main_state->mode);
	if (state->mode == RZ_OUTPUT_MODE_TABLE || state->mode == RZ_OUTPUT_MODE_STANDARD) {
		rz_cons_printf("[%c%s]\n", toupper(header[0]), header + 1);
	} else if (state->mode == RZ_OUTPUT_MODE_JSON || state->mode == RZ_OUTPUT_MODE_LONG_JSON) {
		pj_k(main_state->d.pj, header);
	}
	return state;
}

/**
 * \brief Print (to RzCons or inside RzCmdStateOutput) the binary information specified in \p mask
 *
 * This function can be used to print information from the current binary file.
 * What type of information to print depends on the value of \p mask, which can
 * be a mix of RZ_CORE_BIN_ACC_ defines. When \p filter is NULL, all
 * informations are printed. When \p filter is not NULL some information (e.g.
 * symbols, sections, imports, etc.) are filtered by name and/or address.
 *
 * The argument \p state is used to specify the output mode you want the info.
 *
 * \param core RzCore instance
 * \param bf RzBinFile to consider
 * \param mask Mask of info you want to print, see RZ_CORE_BIN_ACC_ defines
 * \param filter When specified it filter some of the info by name and/or address
 * \param state RzCmdStateOutput instance specifying the output mode
 * \param hashes List of strings with name of hashes that RZ_CORE_BIN_ACC_SECTIONS/SEGMENTS should print
 * \return true if everything that was requested was printed well, false otherwise
 */
RZ_API bool rz_core_bin_print(RzCore *core, RzBinFile *bf, ut32 mask, RzCoreBinFilter *filter, RzCmdStateOutput *state, RzList *hashes) {
	rz_return_val_if_fail(core && state, false);

#define wrap_mode(header, default_mode, method) \
	do { \
		RzCmdStateOutput *st = add_header(state, default_mode, header); \
		res &= method; \
		add_footer(state, st); \
	} while (0)

	bool res = true;
	if (mask & RZ_CORE_BIN_ACC_INFO) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET)) {
			wrap_mode("info", RZ_OUTPUT_MODE_TABLE, rz_core_bin_info_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_IMPORTS) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET | RZ_OUTPUT_MODE_QUIETEST)) {
			wrap_mode("imports", RZ_OUTPUT_MODE_TABLE, rz_core_bin_imports_print(core, bf, st, filter));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_ENTRIES) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET)) {
			wrap_mode("entries", RZ_OUTPUT_MODE_TABLE, rz_core_bin_entries_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_EXPORTS) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET | RZ_OUTPUT_MODE_QUIETEST)) {
			wrap_mode("exports", RZ_OUTPUT_MODE_TABLE, rz_core_bin_exports_print(core, bf, st, filter));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_CLASSES) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET | RZ_OUTPUT_MODE_QUIETEST | RZ_OUTPUT_MODE_RIZIN)) {
			wrap_mode("classes", RZ_OUTPUT_MODE_TABLE, rz_core_bin_classes_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_SYMBOLS) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET | RZ_OUTPUT_MODE_QUIETEST)) {
			wrap_mode("symbols", RZ_OUTPUT_MODE_TABLE, rz_core_bin_symbols_print(core, bf, st, filter));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_SECTIONS) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET)) {
			wrap_mode("sections", RZ_OUTPUT_MODE_TABLE, rz_core_bin_sections_print(core, bf, st, filter, hashes));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_SEGMENTS) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET)) {
			wrap_mode("segments", RZ_OUTPUT_MODE_TABLE, rz_core_bin_segments_print(core, bf, st, filter, hashes));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_MEM) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET)) {
			wrap_mode("memory", RZ_OUTPUT_MODE_TABLE, rz_core_bin_memory_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_STRINGS) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET | RZ_OUTPUT_MODE_QUIETEST)) {
			wrap_mode("strings", RZ_OUTPUT_MODE_TABLE, rz_core_bin_strings_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_MAIN) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET)) {
			wrap_mode("main", RZ_OUTPUT_MODE_TABLE, rz_core_bin_main_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_DWARF) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON)) {
			wrap_mode("dwarf", RZ_OUTPUT_MODE_STANDARD, rz_core_bin_dwarf_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_RELOCS) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET)) {
			wrap_mode("relocs", RZ_OUTPUT_MODE_TABLE, rz_core_bin_relocs_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_RESOURCES) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON)) {
			wrap_mode("resources", RZ_OUTPUT_MODE_STANDARD, rz_core_bin_resources_print(core, bf, st, hashes));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_FIELDS) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET)) {
			wrap_mode("fields", RZ_OUTPUT_MODE_TABLE, rz_core_bin_fields_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_LIBS) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET)) {
			wrap_mode("libs", RZ_OUTPUT_MODE_TABLE, rz_core_bin_libs_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_SIZE) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_RIZIN)) {
			wrap_mode("size", RZ_OUTPUT_MODE_STANDARD, rz_core_bin_size_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_PDB) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_RIZIN)) {
			RzCmdStateOutput *st = add_header(state, RZ_OUTPUT_MODE_STANDARD, "pdb");
			RzPdb *pdb = rz_core_pdb_load_info(core, core->bin->file);
			if (!pdb) {
				rz_cmd_state_output_free(st);
				return false;
			}
			rz_core_pdb_info_print(core, core->analysis->typedb, pdb, st);
			rz_bin_pdb_free(pdb);
			add_footer(state, st);
		}
	}
	if (mask & RZ_CORE_BIN_ACC_VERSIONINFO) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON)) {
			wrap_mode("versioninfo", RZ_OUTPUT_MODE_STANDARD, rz_core_bin_versions_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_SIGNATURE) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_JSON)) {
			wrap_mode("signatures", RZ_OUTPUT_MODE_STANDARD, rz_core_bin_signatures_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_INITFINI) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE | RZ_OUTPUT_MODE_JSON | RZ_OUTPUT_MODE_QUIET)) {
			wrap_mode("initfini", RZ_OUTPUT_MODE_TABLE, rz_core_bin_initfini_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_TRYCATCH) {
		if (state->mode & RZ_OUTPUT_MODE_RIZIN) {
			wrap_mode("trycatch", RZ_OUTPUT_MODE_RIZIN, rz_core_bin_trycatch_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_SECTIONS_MAPPING) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE)) {
			wrap_mode("sections mapping", RZ_OUTPUT_MODE_TABLE, rz_core_bin_sections_mapping_print(core, bf, st));
		}
	}
	if (mask & RZ_CORE_BIN_ACC_BASEFIND) {
		if (state->mode & (RZ_OUTPUT_MODE_STANDARD | RZ_OUTPUT_MODE_TABLE)) {
			wrap_mode("basefind", RZ_OUTPUT_MODE_TABLE, rz_core_bin_basefind_print(core, 32, st));
		}
	}

#undef wrap_mode

	return res;
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
	rz_flag_space_push(r->flags, RZ_FLAGS_FS_STRINGS);
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
		rz_meta_set_with_subtype(r->analysis, RZ_META_TYPE_STRING, string->type, vaddr, string->size, string->string);
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
	rz_flag_space_pop(r->flags);
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
	rz_config_set(r->config, "file.type", rz_str_get(info->rclass));
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
	char *types_dir = rz_path_system(RZ_SDB_TYPES);
	char *spath = rz_file_path_join(types_dir, "spec.sdb");
	free(types_dir);
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
	const RzBinAddr *binmain = rz_bin_object_get_special_symbol(o, RZ_BIN_SPECIAL_SYMBOL_MAIN);
	if (!binmain) {
		return false;
	}
	ut64 addr = va ? rz_bin_object_addr_with_base(o, binmain->vaddr) : binmain->paddr;
	rz_flag_space_push(r->flags, RZ_FLAGS_FS_SYMBOLS);
	rz_flag_set(r->flags, "main", addr, r->blocksize);
	rz_flag_space_pop(r->flags);
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
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_SYMBOLS);
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
	rz_flag_space_pop(core->flags);
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
	if (!iomap->user) {
		iomap->user = rz_core_io_map_info_new(cf, map->perm);
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
			} else if (cf && !rz_pvector_push(&cf->extra_files, desc)) {
				free(uri);
				return;
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
		iomap->user = rz_core_io_map_info_new(cf, perm);
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
	rz_list_foreach (maps, it, map) {
		int va_map = va ? VA_TRUE : VA_FALSE;
		if (va && !(map->perm & RZ_PERM_R)) {
			va_map = VA_NOREBASE;
		}
		ut64 addr = rva(o, map->paddr, map->vaddr, va_map);
		add_map(core, cf, binfile, map, addr, binfile->fd);
	}
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
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_SEGMENTS);
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
	rz_flag_space_pop(core->flags);

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
		CASE(24);
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
				filename = rz_str_newf("%s.sdb", module);
				rz_str_case(filename, false);
				if (rz_file_exists(filename)) {
					*db = sdb_new(NULL, filename, 0);
				} else {
					char *formats_dir = rz_path_system(RZ_SDB_FORMAT);
					free(filename);
					filename = rz_str_newf(RZ_JOIN_3_PATHS("%s", "dll", "%s.sdb"), formats_dir, module);
					free(formats_dir);
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
			free(filename);
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

	rz_flag_space_push(core->flags, RZ_FLAGS_FS_RELOCS);

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
	rz_flag_space_pop(core->flags);

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

	bool demangle = rz_config_get_b(r->config, "bin.demangle");
	bool keep_lib = rz_config_get_b(r->config, "bin.demangle.libs");

	const char *name = sym->dname && demangle ? sym->dname : sym->name;
	sn->name = rz_str_newf("%s%s", sym->is_imported ? "imp." : "", name);
	sn->libname = sym->libname ? strdup(sym->libname) : NULL;
	const char *pfx = get_prefix_for_sym(sym);
	sn->nameflag = construct_symbol_flagname(pfx, sym->libname, rz_bin_symbol_name(sym), MAXFLAG_LEN_DEFAULT);
	if (sym->classname && sym->classname[0]) {
		sn->classname = strdup(sym->classname);
		sn->classflag = rz_str_newf("sym.%s.%s", sn->classname, sn->name);
		rz_name_filter(sn->classflag, MAXFLAG_LEN_DEFAULT, true);
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
	if (demangle && sym->paddr && lang) {
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
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_SYMBOLS);

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
		RzStrEscOptions opt = { 0 };
		opt.show_asciidot = false;
		opt.esc_bslash = true;
		char *rz_symbol_name = rz_str_escape_utf8(sn.name, &opt);

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

	// handle thumb and arm for entry point since they are not present in symbols
	if (is_arm) {
		RzBinAddr *entry;
		rz_list_foreach (o->entries, iter, entry) {
			handle_arm_entry(core, o, entry, va);
		}
	}

	rz_spaces_pop(&core->analysis->meta_spaces);
	rz_flag_space_pop(core->flags);
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

	rz_flag_space_push(core->flags, RZ_FLAGS_FS_CLASSES);

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
	rz_flag_space_pop(core->flags);
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
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_RESOURCES);
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
	rz_flag_space_pop(core->flags);
	return true;
}

static void digests_ht_free(HtPPKv *kv) {
	free(kv->key);
	free(kv->value);
}

/**
 * \brief Create a hashtable of digests
 *
 * Digest names are supplied as a list of `char *` strings.
 * Returns the hashtable with keys of digest names and values of
 * strings containing requested digests.
 * */
RZ_API RZ_OWN HtPP *rz_core_bin_create_digests(RzCore *core, ut64 paddr, ut64 size, RzList *digests) {
	rz_return_val_if_fail(size && digests, NULL);
	HtPP *r = ht_pp_new(NULL, digests_ht_free, NULL);
	if (!r) {
		return NULL;
	}
	RzListIter *it;
	char *digest;
	rz_list_foreach (digests, it, digest) {
		ut8 *data = malloc(size);
		if (!data) {
			ht_pp_free(r);
			return NULL;
		}
		rz_io_pread_at(core->io, paddr, data, size);
		char *chkstr = rz_msg_digest_calculate_small_block_string(digest, data, size, NULL, false);
		if (!chkstr) {
			continue;
		}
		ht_pp_insert(r, digest, chkstr);
		free(data);
	}

	return r;
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

/**
 * Strings for the given file, respecting settings like bin.strings
 */
static RZ_NULLABLE RZ_BORROW const RzList *core_bin_strings(RzCore *r, RzBinFile *file) {
	rz_return_val_if_fail(r && file, false);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(file);
	if (!plugin || !rz_config_get_i(r->config, "bin.strings")) {
		return NULL;
	}
	if (plugin->name && !strcmp(plugin->name, "any")) {
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

static bool bin_dwarf(RzCore *core, RzBinFile *binfile, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && binfile, false);
	if (!rz_config_get_i(core->config, "bin.dbginfo") || !binfile->o) {
		return false;
	}
	RzBinDwarfDebugAbbrev *da = rz_bin_dwarf_parse_abbrev(binfile);
	RzBinDwarfDebugInfo *info = da ? rz_bin_dwarf_parse_info(binfile, da) : NULL;
	if (state->mode == RZ_OUTPUT_MODE_STANDARD) {
		if (da) {
			rz_core_bin_dwarf_print_abbrev_section(da);
		}
		if (info) {
			rz_core_bin_dwarf_print_debug_info(info);
		}
	}
	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = rz_bin_dwarf_parse_loc(binfile, core->analysis->bits / 8);
	if (loc_table) {
		if (state->mode == RZ_OUTPUT_MODE_STANDARD) {
			rz_core_bin_dwarf_print_loc(loc_table, core->analysis->bits / 8);
		}
		rz_bin_dwarf_loc_free(loc_table);
	}
	if (state->mode == RZ_OUTPUT_MODE_STANDARD) {
		RzList *aranges = rz_bin_dwarf_parse_aranges(binfile);
		if (aranges) {
			rz_core_bin_dwarf_print_aranges(aranges);
			rz_list_free(aranges);
		}
	}
	bool ret = false;
	RzBinDwarfLineInfo *lines = rz_bin_dwarf_parse_line(binfile, info,
		RZ_BIN_DWARF_LINE_INFO_MASK_LINES | (state->mode == RZ_OUTPUT_MODE_STANDARD ? RZ_BIN_DWARF_LINE_INFO_MASK_OPS : 0));
	rz_bin_dwarf_debug_info_free(info);
	if (lines) {
		if (state->mode == RZ_OUTPUT_MODE_STANDARD) {
			rz_core_bin_dwarf_print_line_units(lines->units);
		}
		if (lines->lines) {
			ret = true;
			rz_core_bin_print_source_line_info(core, lines->lines, state);
		}
		rz_bin_dwarf_line_info_free(lines);
	}
	rz_bin_dwarf_debug_abbrev_free(da);
	return ret;
}

RZ_API void rz_core_bin_print_source_line_sample(RzCore *core, const RzBinSourceLineSample *s, RzCmdStateOutput *state) {
	rz_return_if_fail(core && s && state);
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		bool chopPath = !rz_config_get_i(core->config, "dir.dwarf.abspath");
		char *file = s->file ? strdup(s->file) : NULL;
		if (chopPath && file) {
			const char *slash = rz_str_lchr(file, '/');
			if (slash) {
				memmove(file, slash + 1, strlen(slash));
			}
		}
		pj_o(state->d.pj);
		if (file) {
			pj_ks(state->d.pj, "file", file);
		}
		pj_kn(state->d.pj, "line", (ut64)s->line);
		if (s->column) {
			pj_kn(state->d.pj, "column", (ut64)s->column);
		}
		pj_kn(state->d.pj, "addr", s->address);
		pj_end(state->d.pj);
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

RZ_API void rz_core_bin_print_source_line_info(RzCore *core, const RzBinSourceLineInfo *li, RzCmdStateOutput *state) {
	rz_return_if_fail(core && li && state);
	rz_cmd_state_output_array_start(state);
	rz_cons_break_push(NULL, NULL);
	for (size_t i = 0; i < li->samples_count; i++) {
		if (rz_cons_is_breaked()) {
			break;
		}
		rz_core_bin_print_source_line_sample(core, &li->samples[i], state);
	}
	rz_cons_break_pop();
	rz_cmd_state_output_array_end(state);
}

static const char *bin_reloc_type_name(RzBinReloc *reloc) {
#define CASE(T) \
	case RZ_BIN_RELOC_##T: return reloc->additive ? "ADD_" #T : "SET_" #T
	switch (reloc->type) {
		CASE(8);
		CASE(16);
		CASE(24);
		CASE(32);
		CASE(64);
	}
	return "UNKNOWN";
#undef CASE
}

static bool entries_initfini_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state, bool initfini) {
	RzBinObject *o = bf->o;
	const RzList *entries = rz_bin_object_get_entries(o);
	RzListIter *iter;
	RzBinAddr *entry = NULL;
	ut64 baddr = rz_bin_get_baddr(core->bin);
	ut64 laddr = rz_bin_get_laddr(core->bin);
	int va = (core->io->va || core->bin->is_debugger) ? VA_TRUE : VA_FALSE;

	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "XXXXs", "vaddr", "paddr", "hvaddr", "haddr", "type");

	rz_list_foreach (entries, iter, entry) {
		ut64 paddr = entry->paddr;
		ut64 hpaddr = UT64_MAX;
		ut64 hvaddr = UT64_MAX;
		if (!initfini && entry->type != RZ_BIN_ENTRY_TYPE_PROGRAM) {
			continue;
		} else if (initfini && entry->type == RZ_BIN_ENTRY_TYPE_PROGRAM) {
			continue;
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
		switch (state->mode) {
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("0x%08" PFMT64x "\n", at);
			break;
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_kn(state->d.pj, "vaddr", at);
			pj_kn(state->d.pj, "paddr", paddr);
			pj_kn(state->d.pj, "baddr", baddr);
			pj_kn(state->d.pj, "laddr", laddr);
			if (hvaddr != UT64_MAX) {
				pj_kn(state->d.pj, "hvaddr", hvaddr);
			}
			pj_kn(state->d.pj, "haddr", hpaddr);
			pj_ks(state->d.pj, "type", type);
			pj_end(state->d.pj);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			rz_table_add_rowf(state->d.t, "XXXXs", at, paddr, hvaddr, hpaddr, type);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}

	rz_cmd_state_output_array_end(state);
	return true;
}

RZ_API bool rz_core_bin_initfini_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state, false);

	return entries_initfini_print(core, bf, state, true);
}

RZ_API bool rz_core_bin_entries_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state, false);

	return entries_initfini_print(core, bf, state, false);
}

static bool isAnExport(RzBinSymbol *s) {
	/* workaround for some RzBinPlugins */
	if (s->is_imported) {
		return false;
	}
	return (s->bind && !strcmp(s->bind, RZ_BIN_BIND_GLOBAL_STR));
}

static bool is_in_symbol_range(ut64 sym_addr, ut64 sym_size, ut64 addr) {
	if (addr == sym_addr && sym_size == 0) {
		return true;
	}
	if (sym_size == 0) {
		return false;
	}
	return RZ_BETWEEN(sym_addr, addr, sym_addr + sym_size - 1);
}

static bool symbols_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state, RzCoreBinFilter *filter, bool only_export) {
	RzBinObject *o = bf->o;
	const RzList *symbols = rz_bin_object_get_symbols(o);
	bool bin_demangle = rz_config_get_i(core->config, "bin.demangle");
	const char *lang = bin_demangle ? rz_config_get(core->config, "bin.lang") : NULL;
	int va = (core->io->va || core->bin->is_debugger) ? VA_TRUE : VA_FALSE;
	RzBinSymbol *symbol;
	RzListIter *iter;

	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "dXXssnss", "nth", "paddr", "vaddr", "bind", "type", "size", "lib", "name");

	rz_list_foreach (symbols, iter, symbol) {
		if (!symbol->name) {
			continue;
		}
		if (only_export && !isAnExport(symbol)) {
			continue;
		}
		ut64 addr = rva(o, symbol->paddr, symbol->vaddr, va);

		if (filter && filter->offset != UT64_MAX) {
			if (!is_in_symbol_range(symbol->paddr, symbol->size, filter->offset) &&
				!is_in_symbol_range(addr, symbol->size, filter->offset)) {
				continue;
			}
		}
		if (filter && filter->name && strcmp(symbol->name, filter->name)) {
			continue;
		}

		SymName sn = { 0 };
		sym_name_init(core, &sn, symbol, lang);
		RzStrEscOptions opt = { 0 };
		opt.show_asciidot = false;
		opt.esc_bslash = true;
		char *rz_symbol_name = rz_str_escape_utf8(sn.demname ? sn.demname : sn.name, &opt);
		if (core->bin->prefix) {
			char *tmp = rz_str_newf("%s.%s", core->bin->prefix, rz_symbol_name);
			free(rz_symbol_name);
			rz_symbol_name = tmp;
		}
		ut64 size = symbol->size;

		switch (state->mode) {
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("0x%08" PFMT64x " %" PFMT64u " %s%s%s\n",
				addr, size,
				sn.libname ? sn.libname : "", sn.libname ? " " : "",
				rz_symbol_name);
			break;
		case RZ_OUTPUT_MODE_QUIETEST:
			rz_cons_printf("%s\n", rz_symbol_name);
			break;
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_ks(state->d.pj, "name", rz_symbol_name);
			if (sn.demname) {
				pj_ks(state->d.pj, "demname", sn.demname);
			}
			pj_ks(state->d.pj, "flagname", sn.nameflag);
			pj_ks(state->d.pj, "realname", symbol->name);
			pj_ki(state->d.pj, "ordinal", symbol->ordinal);
			pj_ks(state->d.pj, "bind", symbol->bind);
			pj_kn(state->d.pj, "size", size);
			pj_ks(state->d.pj, "type", symbol->type);
			pj_kn(state->d.pj, "vaddr", addr);
			pj_kn(state->d.pj, "paddr", symbol->paddr);
			pj_kb(state->d.pj, "is_imported", symbol->is_imported);
			pj_ks(state->d.pj, "lib", rz_str_get(symbol->libname));
			pj_end(state->d.pj);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			rz_table_add_rowf(state->d.t, "dXXssnss",
				symbol->ordinal,
				symbol->paddr,
				addr,
				symbol->bind ? symbol->bind : "NONE",
				symbol->type ? symbol->type : "NONE",
				size,
				rz_str_get(symbol->libname),
				rz_str_get_null(rz_symbol_name));
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		sym_name_fini(&sn);
		free(rz_symbol_name);
	}
	rz_cmd_state_output_array_end(state);
	return true;
}

RZ_API bool rz_core_bin_symbols_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state, RzCoreBinFilter *filter) {
	rz_return_val_if_fail(core && state, false);

	return symbols_print(core, bf, state, filter, false);
}

RZ_API bool rz_core_bin_cur_symbol_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state, false);

	RzCoreBinFilter filter = { 0 };
	filter.offset = core->offset;
	return symbols_print(core, bf, state, &filter, false);
}

RZ_API bool rz_core_bin_exports_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state, RzCoreBinFilter *filter) {
	rz_return_val_if_fail(core && state, false);

	return symbols_print(core, bf, state, filter, true);
}

RZ_API bool rz_core_bin_cur_export_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state, false);

	RzCoreBinFilter filter = { 0 };
	filter.offset = core->offset;
	return symbols_print(core, bf, state, &filter, true);
}

RZ_API bool rz_core_bin_imports_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state, RzCoreBinFilter *filter) {
	rz_return_val_if_fail(core && bf && bf->o && state, false);

	int bin_demangle = rz_config_get_i(core->config, "bin.demangle");
	bool keep_lib = rz_config_get_i(core->config, "bin.demangle.libs");
	int va = (core->io->va || core->bin->is_debugger) ? VA_TRUE : VA_FALSE;
	const RzList *imports = rz_bin_object_get_imports(bf->o);
	RzBinObject *o = bf->o;
	RzBinImport *import;
	RzListIter *iter;

	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "nXssss", "nth", "vaddr", "bind", "type", "lib", "name");

	rz_list_foreach (imports, iter, import) {
		if (!import->name) {
			continue;
		}

		char *symname = import->name ? strdup(import->name) : NULL;
		char *libname = import->libname ? strdup(import->libname) : NULL;
		RzBinSymbol *sym = rz_bin_object_get_symbol_of_import(o, import);
		ut64 addr = sym ? rva(o, sym->paddr, sym->vaddr, va) : UT64_MAX;

		if (filter && filter->offset != UT64_MAX) {
			if (!is_in_symbol_range(addr, 1, filter->offset)) {
				goto next;
			}
		}
		if (filter && filter->name && strcmp(import->name, filter->name)) {
			goto next;
		}

		if (RZ_STR_ISNOTEMPTY(import->classname)) {
			char *tmp = rz_str_newf("%s.%s", import->classname, symname);
			if (tmp) {
				free(symname);
				symname = tmp;
			}
		}

		if (bin_demangle) {
			char *dname = rz_bin_demangle(core->bin->cur, NULL, symname, addr, keep_lib);
			if (dname) {
				free(symname);
				symname = dname;
			}
		}

		if (core->bin->prefix) {
			char *prname = rz_str_newf("%s.%s", core->bin->prefix, symname);
			free(symname);
			symname = prname;
		}
		switch (state->mode) {
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("%s%s%s\n", libname ? libname : "", libname ? " " : "", symname);
			break;
		case RZ_OUTPUT_MODE_QUIETEST:
			rz_cons_println(symname);
			break;
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_ki(state->d.pj, "ordinal", import->ordinal);
			if (import->bind) {
				pj_ks(state->d.pj, "bind", import->bind);
			}
			if (import->type) {
				pj_ks(state->d.pj, "type", import->type);
			}
			if (import->classname && import->classname[0]) {
				pj_ks(state->d.pj, "classname", import->classname);
				pj_ks(state->d.pj, "descriptor", import->descriptor);
			}
			pj_ks(state->d.pj, "name", symname);
			if (libname) {
				pj_ks(state->d.pj, "libname", libname);
			}
			if (addr != UT64_MAX) {
				pj_kn(state->d.pj, "plt", addr);
			}
			pj_end(state->d.pj);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			rz_table_add_rowf(state->d.t, "nXssss",
				(ut64)import->ordinal,
				addr,
				import->bind ? import->bind : "NONE",
				import->type ? import->type : "NONE",
				libname ? libname : "",
				symname);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	next:
		RZ_FREE(symname);
		RZ_FREE(libname);
	}

	rz_cmd_state_output_array_end(state);
	return true;
}

RZ_API bool rz_core_bin_libs_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && bf && bf->o && state, false);

	const RzList *libs = rz_bin_object_get_libs(bf->o);
	RzListIter *iter;
	char *lib;

	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "s", "library");
	rz_list_foreach (libs, iter, lib) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_s(state->d.pj, lib);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			rz_table_add_rowf(state->d.t, "s", lib);
			break;
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("%s\n", lib);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_cmd_state_output_array_end(state);
	return true;
}

RZ_API bool rz_core_bin_main_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && bf && bf->o && state, false);

	int va = (core->io->va || core->bin->is_debugger) ? VA_TRUE : VA_FALSE;
	const RzBinAddr *binmain = rz_bin_object_get_special_symbol(bf->o, RZ_BIN_SPECIAL_SYMBOL_MAIN);
	if (!binmain) {
		return false;
	}

	ut64 addr = va ? rz_bin_object_addr_with_base(bf->o, binmain->vaddr) : binmain->paddr;
	rz_cmd_state_output_set_columnsf(state, "XX", "vaddr", "paddr");

	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("%" PFMT64d, addr);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_kn(state->d.pj, "vaddr", addr);
		pj_kn(state->d.pj, "paddr", binmain->paddr);
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "XX", addr, binmain->paddr);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	return true;
}

RZ_API bool rz_core_bin_relocs_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && bf && bf->o && state, false);

	RzBinObject *o = bf->o;

	bool bin_demangle = rz_config_get_i(core->config, "bin.demangle");
	bool keep_lib = rz_config_get_i(core->config, "bin.demangle.libs");
	const char *lang = rz_config_get(core->config, "bin.lang");
	int va = VA_TRUE; // XXX relocs always vaddr?
	char *name = NULL;

	RzBinRelocStorage *relocs = rz_bin_object_patch_relocs(bf, o);
	if (!relocs) {
		RZ_LOG_WARN("Could not get relocations for current bin file.\n");
		return false;
	}
	bool have_targets = rz_bin_reloc_storage_targets_available(relocs);
	if (have_targets) {
		rz_cmd_state_output_set_columnsf(state, "XXXss", "vaddr", "paddr", "target", "type", "name");
	} else {
		rz_cmd_state_output_set_columnsf(state, "XXss", "vaddr", "paddr", "type", "name");
	}

	rz_cmd_state_output_array_start(state);
	for (size_t i = 0; i < relocs->relocs_count; i++) {
		RzBinReloc *reloc = relocs->relocs[i];
		ut64 addr = rva(o, reloc->paddr, reloc->vaddr, va);

		switch (state->mode) {
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("0x%08" PFMT64x "  %s\n", addr, reloc->import ? reloc->import->name : "");
			break;
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			char *mn = NULL;
			char *relname = NULL;

			// take care with very long symbol names! do not use sdb_fmt or similar
			if (reloc->import) {
				mn = rz_bin_demangle(core->bin->cur, lang, reloc->import->name, addr, keep_lib);
				relname = strdup(reloc->import->name);
			} else if (reloc->symbol) {
				mn = rz_bin_demangle(core->bin->cur, lang, reloc->symbol->name, addr, keep_lib);
				relname = strdup(reloc->symbol->name);
			}

			// check if name is available
			if (!RZ_STR_ISEMPTY(relname)) {
				pj_ks(state->d.pj, "name", relname);
			}
			pj_ks(state->d.pj, "demname", rz_str_get(mn));
			pj_ks(state->d.pj, "type", bin_reloc_type_name(reloc));
			pj_kn(state->d.pj, "vaddr", reloc->vaddr);
			pj_kn(state->d.pj, "paddr", reloc->paddr);
			if (rz_bin_reloc_has_target(reloc)) {
				pj_kn(state->d.pj, "target_vaddr", reloc->target_vaddr);
			}
			if (reloc->symbol) {
				pj_kn(state->d.pj, "sym_va", reloc->symbol->vaddr);
			}
			pj_kb(state->d.pj, "is_ifunc", reloc->is_ifunc);
			pj_end(state->d.pj);

			free(mn);
			free(relname);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			name = reloc->import
				? strdup(reloc->import->name)
				: reloc->symbol ? strdup(reloc->symbol->name)
						: NULL;
			if (bin_demangle) {
				char *mn = rz_bin_demangle(core->bin->cur, NULL, name, addr, keep_lib);
				if (RZ_STR_ISNOTEMPTY(mn)) {
					free(name);
					name = mn;
				}
			}
			char *reloc_name = construct_reloc_name(reloc, name);
			RzStrBuf *buf = rz_strbuf_new(NULL);
			if (core->bin->prefix) {
				rz_strbuf_appendf(buf, "%s.", core->bin->prefix);
			}
			rz_strbuf_append(buf, rz_str_get(reloc_name));
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
				rz_table_add_rowf(state->d.t, "XXXss", addr, reloc->paddr, reloc->target_vaddr,
					bin_reloc_type_name(reloc), res);
			} else {
				rz_table_add_rowf(state->d.t, "XXss", addr, reloc->paddr,
					bin_reloc_type_name(reloc), res);
			}
			free(res);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_cmd_state_output_array_end(state);
	return true;
}

static ut64 get_section_addr(RzCore *core, RzBinObject *o, RzBinSection *section) {
	int va = (core->io->va || core->bin->is_debugger) ? VA_TRUE : VA_FALSE;
	if (va && !(section->perm & RZ_PERM_R)) {
		va = VA_NOREBASE;
	}
	return rva(o, section->paddr, section->vaddr, va);
}

static bool digests_pj_cb(void *user, const void *k, const void *v) {
	rz_return_val_if_fail(user && k && v, false);
	PJ *pj = user;
	pj_ks(pj, k, v);
	return true;
}

static void sections_print_json(RzCore *core, PJ *pj, RzBinObject *o, RzBinSection *section, RzList *hashes) {
	ut64 addr = get_section_addr(core, o, section);
	char perms[5];
	section_perms_str(perms, section->perm);

	pj_o(pj);
	pj_ks(pj, "name", section->name);
	pj_kN(pj, "size", section->size);
	pj_kN(pj, "vsize", section->vsize);
	pj_ks(pj, "perm", perms);
	if (!section->is_segment) {
		char *section_type = rz_bin_section_type_to_string(core->bin, section->type);
		if (section_type) {
			pj_ks(pj, "type", section_type);
		}
		free(section_type);
	}
	if (!section->is_segment) {
		RzList *flags = rz_bin_section_flag_to_list(core->bin, section->flags);
		if (!rz_list_empty(flags)) {
			RzListIter *it;
			char *pos;
			pj_ka(pj, "flags");
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
	if (hashes && section->size > 0) {
		HtPP *digests = rz_core_bin_create_digests(core, section->paddr, section->size, hashes);
		if (!digests) {
			pj_end(pj);
			return;
		}
		ht_pp_foreach(digests, digests_pj_cb, pj);
		ht_pp_free(digests);
	}
	pj_end(pj);
}

static bool sections_print_table(RzCore *core, RzTable *t, RzBinObject *o, RzBinSection *section, RzList *hashes) {
	ut64 addr = get_section_addr(core, o, section);
	char perms[5];
	section_perms_str(perms, section->perm);

	char *section_type = NULL;
	if (!section->is_segment) {
		section_type = rz_bin_section_type_to_string(core->bin, section->type);
	}
	char *section_flags_str = NULL;
	if (!section->is_segment) {
		RzList *section_flags = rz_bin_section_flag_to_list(core->bin, section->flags);
		if (section_flags) {
			section_flags_str = rz_str_list_join(section_flags, ",");
			rz_list_free(section_flags);
		}
	}

	char *section_name = section->name;
	if (core->bin->prefix) {
		section_name = rz_str_newf("%s.%s", core->bin->prefix, section_name);
	}

	rz_table_add_rowf(t, "XxXxxss", section->paddr, section->size, addr, section->vsize, section->align, perms, section_name);
	if (!section->is_segment) {
		rz_table_add_row_columnsf(t, "ss", section_type, section_flags_str);
	}
	bool result = false;
	if (hashes && section->size > 0) {
		HtPP *digests = rz_core_bin_create_digests(core, section->paddr, section->size, hashes);
		if (!digests) {
			goto cleanup;
		}
		RzListIter *it;
		char *hash;
		bool found = false;
		rz_list_foreach (hashes, it, hash) {
			char *digest = ht_pp_find(digests, hash, &found);
			if (found && t) {
				rz_table_add_row_columnsf(t, "s", digest);
			}
		}
		ht_pp_free(digests);
	}
	result = true;
cleanup:
	if (section_name != section->name) {
		free(section_name);
	}
	free(section_type);
	free(section_flags_str);
	return result;
}

static void sections_headers_setup(RzCore *core, RzCmdStateOutput *state, RzList *hashes) {
	RzListIter *iter;
	char *hashname;

	rz_cmd_state_output_set_columnsf(state, "XxXxssssx", "paddr", "size", "vaddr", "vsize", "align", "perm", "name", "type", "flags");

	rz_list_foreach (hashes, iter, hashname) {
		const RzMsgDigestPlugin *msg_plugin = rz_msg_digest_plugin_by_name(hashname);
		if (msg_plugin) {
			rz_cmd_state_output_set_columnsf(state, "s", msg_plugin->name);
		}
	}
}

RZ_API bool rz_core_bin_sections_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state, RzCoreBinFilter *filter, RzList *hashes) {
	rz_return_val_if_fail(core && bf && bf->o && state, false);

	RzBinObject *o = bf->o;
	RzList *sections = rz_bin_object_get_sections(o);
	if (!sections) {
		return false;
	}

	RzBinSection *section;
	RzListIter *iter;
	RzOutputMode mode = state->mode;
	bool res = true;

	if (state->mode == RZ_OUTPUT_MODE_QUIET) {
		state->mode = RZ_OUTPUT_MODE_TABLE;
		state->d.t = rz_table_new();
		if (!state->d.t) {
			res = false;
			goto err;
		}
	}

	rz_cmd_state_output_array_start(state);
	sections_headers_setup(core, state, hashes);

	rz_list_foreach (sections, iter, section) {
		if (filter && filter->offset != UT64_MAX) {
			if (!is_in_symbol_range(section->vaddr, section->vsize, filter->offset) &&
				!is_in_symbol_range(section->paddr, section->size, filter->offset)) {
				continue;
			}
		}
		if (filter && filter->name && section->name && strcmp(section->name, filter->name)) {
			continue;
		}
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			sections_print_json(core, state->d.pj, o, section, hashes);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			res &= sections_print_table(core, state->d.t, o, section, hashes);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}

	rz_cmd_state_output_array_end(state);

err:
	if (mode == RZ_OUTPUT_MODE_QUIET) {
		if (state->d.t) {
			rz_table_query(state->d.t, "vaddr/cols/vsize/perm/name");
			char *s = rz_table_tostring(state->d.t);
			if (s) {
				rz_cons_printf("%s", s);
				free(s);
			}
		}

		state->mode = mode;
		rz_table_free(state->d.t);
	}
	rz_list_free(sections);
	return res;
}

RZ_API bool rz_core_bin_cur_section_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state, RzList *hashes) {
	rz_return_val_if_fail(core && state, false);

	RzCoreBinFilter filter = { 0 };
	filter.offset = core->offset;
	return rz_core_bin_sections_print(core, bf, state, &filter, hashes);
}

RZ_API bool rz_core_bin_cur_segment_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state, RzList *hashes) {
	rz_return_val_if_fail(core && bf && state, false);

	RzCoreBinFilter filter = { 0 };
	filter.offset = core->offset;
	return rz_core_bin_segments_print(core, bf, state, &filter, hashes);
}

RZ_API bool rz_core_bin_basefind_print(RzCore *core, ut32 pointer_size, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state, false);
	RzListIter *it = NULL;
	RzBaseFindScore *pair = NULL;

	RzList *scores = rz_basefind(core, pointer_size);
	if (!scores) {
		return false;
	}

	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "nX", "score", "candidate");

	rz_list_foreach (scores, it, pair) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_kn(state->d.pj, "score", pair->score);
			pj_kn(state->d.pj, "candidate", pair->candidate);
			pj_end(state->d.pj);
			break;
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("%u 0x%" PFMT64x "\n", pair->score, pair->candidate);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			rz_table_add_rowf(state->d.t, "nX", pair->score, pair->candidate);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}

	rz_cmd_state_output_array_end(state);
	rz_list_free(scores);
	return true;
}

RZ_API bool rz_core_bin_segments_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state, RzCoreBinFilter *filter, RzList *hashes) {
	rz_return_val_if_fail(core && bf && bf->o && state, false);

	RzBinObject *o = bf->o;
	RzList *segments = rz_bin_object_get_segments(o);
	if (!segments) {
		return false;
	}

	RzBinSection *segment;
	RzListIter *iter;
	char *hashname;

	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "XxXxssx", "paddr", "size", "vaddr", "vsize", "align", "perm", "name");

	rz_list_foreach (hashes, iter, hashname) {
		const RzMsgDigestPlugin *msg_plugin = rz_msg_digest_plugin_by_name(hashname);
		if (msg_plugin) {
			rz_cmd_state_output_set_columnsf(state, "s", msg_plugin->name);
		}
	}

	rz_list_foreach (segments, iter, segment) {
		if (filter && filter->offset != UT64_MAX) {
			if (!is_in_symbol_range(segment->vaddr, segment->vsize, filter->offset) &&
				!is_in_symbol_range(segment->paddr, segment->size, filter->offset)) {
				continue;
			}
		}
		if (filter && filter->name && segment->name && strcmp(segment->name, filter->name)) {
			continue;
		}
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			sections_print_json(core, state->d.pj, o, segment, hashes);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			sections_print_table(core, state->d.t, o, segment, hashes);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}

	rz_cmd_state_output_array_end(state);
	rz_list_free(segments);
	return true;
}

static bool strings_print(RzCore *core, RzCmdStateOutput *state, const RzList *list) {
	bool b64str = rz_config_get_i(core->config, "bin.b64str");
	int va = (core->io->va || core->bin->is_debugger) ? VA_TRUE : VA_FALSE;
	RzBinObject *obj = rz_bin_cur_object(core->bin);

	RzListIter *iter;
	RzBinString *string;
	RzBinSection *section;

	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "nXXnnsss", "nth", "paddr", "vaddr", "len", "size", "section", "type", "string");

	RzBinString b64 = { 0 };
	rz_list_foreach (list, iter, string) {
		const char *section_name, *type_string;
		char quiet_val[20];
		ut64 paddr, vaddr;
		paddr = string->paddr;
		vaddr = obj ? rva(obj, paddr, string->vaddr, va) : paddr;
		if (!rz_bin_string_filter(core->bin, string->string, string->length, vaddr)) {
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

		RzStrEscOptions opt = { 0 };
		opt.show_asciidot = false;
		opt.esc_bslash = true;
		opt.esc_double_quotes = state->mode == RZ_OUTPUT_MODE_JSON || state->mode == RZ_OUTPUT_MODE_LONG_JSON;
		char *escaped_string = rz_str_escape_utf8_keep_printable(string->string, &opt);

		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON: {
			int *block_list;
			pj_o(state->d.pj);
			pj_kn(state->d.pj, "vaddr", vaddr);
			pj_kn(state->d.pj, "paddr", paddr);
			pj_kn(state->d.pj, "ordinal", string->ordinal);
			pj_kn(state->d.pj, "size", string->size);
			pj_kn(state->d.pj, "length", string->length);
			pj_ks(state->d.pj, "section", section_name);
			pj_ks(state->d.pj, "type", type_string);
			// data itself may be encoded so use pj_ks
			pj_ks(state->d.pj, "string", escaped_string);

			switch (string->type) {
			case RZ_BIN_STRING_ENC_UTF8:
			case RZ_BIN_STRING_ENC_MUTF8:
			case RZ_BIN_STRING_ENC_WIDE_LE:
			case RZ_BIN_STRING_ENC_WIDE32_LE:
				block_list = rz_utf_block_list((const ut8 *)string->string, -1, NULL);
				if (block_list) {
					if (block_list[0] == 0 && block_list[1] == -1) {
						/* Don't include block list if
						   just Basic Latin (0x00 - 0x7F) */
						RZ_FREE(block_list);
						break;
					}
					int *block_ptr = block_list;
					pj_k(state->d.pj, "blocks");
					pj_a(state->d.pj);
					for (; *block_ptr != -1; block_ptr++) {
						const char *utfName = rz_utf_block_name(*block_ptr);
						pj_s(state->d.pj, utfName ? utfName : "");
					}
					pj_end(state->d.pj);
					RZ_FREE(block_list);
				}
			}
			pj_end(state->d.pj);
			break;
		}
		case RZ_OUTPUT_MODE_TABLE: {
			int *block_list;
			char *str = escaped_string;
			char *no_dbl_bslash_str = NULL;
			if (!core->print->esc_bslash) {
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
			case RZ_BIN_STRING_ENC_UTF8:
			case RZ_BIN_STRING_ENC_MUTF8:
			case RZ_BIN_STRING_ENC_WIDE_LE:
			case RZ_BIN_STRING_ENC_WIDE32_LE:
				block_list = rz_utf_block_list((const ut8 *)string->string, -1, NULL);
				if (block_list) {
					if (block_list[0] == 0 && block_list[1] == -1) {
						/* Don't show block list if
						   just Basic Latin (0x00 - 0x7F) */
						free(block_list);
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
			rz_table_add_rowf(state->d.t, "nXXddsss", (ut64)string->ordinal, paddr, vaddr,
				(int)string->length, (int)string->size, section_name,
				type_string, bufstr);
			free(bufstr);
			free(no_dbl_bslash_str);
			break;
		}
		case RZ_OUTPUT_MODE_QUIET:
			if (vaddr == UT64_MAX) {
				rz_strf(quiet_val, "----------");
			} else {
				rz_strf(quiet_val, "0x%" PFMT64x, vaddr);
			}
			rz_cons_printf("%s %d %d %s\n", quiet_val,
				string->size, string->length, escaped_string);
			break;
		case RZ_OUTPUT_MODE_QUIETEST:
			rz_cons_printf("%s\n", escaped_string);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		free(escaped_string);
	}
	RZ_FREE(b64.string);
	rz_cmd_state_output_array_end(state);
	return true;
}

RZ_API bool rz_core_bin_strings_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && bf && state, false);

	const RzList *list = rz_bin_object_get_strings(bf->o);
	return strings_print(core, state, list);
}

RZ_API bool rz_core_bin_whole_strings_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state, false);

	bool new_bf = false;
	if (bf && strstr(bf->file, "malloc://")) {
		// sync bf->buf to search string on it
		ut8 *tmp = RZ_NEWS(ut8, bf->size);
		if (!tmp) {
			return false;
		}
		rz_io_read_at(core->io, 0, tmp, bf->size);
		rz_buf_write_at(bf->buf, 0, tmp, bf->size);
	}
	if (!core->file) {
		RZ_LOG_ERROR("Core file not open\n");
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
		RzIODesc *desc = rz_io_desc_get(core->io, core->file->fd);
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
		bf->buf = rz_buf_new_with_io_fd(&core->bin->iob, core->file->fd);
		bf->o = NULL;
		bf->rbin = core->bin;
		new_bf = true;
	}
	size_t min = rz_config_get_i(core->config, "bin.minstr");
	RzList *l = rz_bin_file_strings(bf, min, true);
	bool res = strings_print(core, state, l);
	rz_list_free(l);
	if (new_bf) {
		rz_buf_free(bf->buf);
		free(bf->file);
		free(bf);
	}
	return res;
}

static const char *get_filename(RzBinInfo *info, RzIODesc *desc) {
	if (info && info->file) {
		return info->file;
	}
	if (desc) {
		if (desc->name) {
			return desc->name;
		} else if (desc->uri) {
			return desc->uri;
		}
	}
	return "";
}

RZ_API bool rz_core_file_info_print(RzCore *core, RzBinFile *binfile, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && core->file && state, false);

	bool io_cache = rz_config_get_i(core->config, "io.cache");
	RzBinInfo *info = rz_bin_get_info(core->bin);
	int fd = rz_io_fd_get_current(core->io);
	RzIODesc *desc = rz_io_desc_get(core->io, fd);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(binfile);

	const char *filename = get_filename(info, desc);
	char *escaped = NULL;

	rz_cmd_state_output_set_columnsf(state, "ss", "field", "value");

	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		const char *file_tag = "file";
		if (rz_str_is_utf8(filename)) {
			pj_ks(state->d.pj, file_tag, filename);
		} else {
			pj_kr(state->d.pj, file_tag, (const ut8 *)filename, strlen(filename));
		}
		if (desc) {
			ut64 fsz = rz_io_desc_size(desc);
			pj_ki(state->d.pj, "fd", desc->fd);
			if (fsz != UT64_MAX) {
				char humansz[8];
				pj_kN(state->d.pj, "size", fsz);
				rz_num_units(humansz, sizeof(humansz), fsz);
				pj_ks(state->d.pj, "humansz", humansz);
			}
			pj_kb(state->d.pj, "iorw", io_cache || desc->perm & RZ_PERM_W);
			pj_ks(state->d.pj, "mode", rz_str_rwx_i(desc->perm & RZ_PERM_RWX));
			if (desc->referer && *desc->referer) {
				pj_ks(state->d.pj, "referer", desc->referer);
			}
		}
		pj_ki(state->d.pj, "block", core->blocksize);
		if (binfile) {
			if (binfile->curxtr) {
				pj_ks(state->d.pj, "packet", binfile->curxtr->name);
			}
			if (plugin) {
				pj_ks(state->d.pj, "format", plugin->name);
			}
		}
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_TABLE: {
		rz_table_hide_header(state->d.t);
		if (desc) {
			rz_table_add_rowf(state->d.t, "sd", "fd", desc->fd);
		}
		RzStrEscOptions opt = { 0 };
		opt.show_asciidot = false;
		opt.esc_bslash = false;
		escaped = rz_str_escape_utf8_keep_printable(filename, &opt);
		rz_table_add_rowf(state->d.t, "ss", "file", escaped);
		free(escaped);
		if (desc) {
			ut64 fsz = rz_io_desc_size(desc);
			if (fsz != UT64_MAX) {
				char humansz[8];
				rz_table_add_rowf(state->d.t, "sx", "size", fsz);
				rz_num_units(humansz, sizeof(humansz), fsz);
				rz_table_add_rowf(state->d.t, "ss", "humansz", humansz);
			}
			rz_table_add_rowf(state->d.t, "ss", "mode", rz_str_rwx_i(desc->perm & RZ_PERM_RWX));
		}
		if (plugin) {
			rz_table_add_rowf(state->d.t, "ss", "format", plugin->name);
		}
		if (desc) {
			table_add_row_bool(state->d.t, "iorw", io_cache || desc->perm & RZ_PERM_W);
		}
		rz_table_add_rowf(state->d.t, "sx", "block", core->blocksize);
		if (binfile && binfile->curxtr) {
			rz_table_add_rowf(state->d.t, "ss", "packet", binfile->curxtr->name);
		}
		if (desc && desc->referer && *desc->referer) {
			rz_table_add_rowf(state->d.t, "ss", "referer", desc->referer);
		}
		if (info) {
			rz_table_add_rowf(state->d.t, "ss", "type", info->type);
		}
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
	return true;
}

static const char *str2na(const char *s) {
	return RZ_STR_ISEMPTY(s) ? "N/A" : s;
}

RZ_API bool rz_core_bin_info_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state, false);

	RzBinInfo *info = rz_bin_get_info(core->bin);
	RzBinPlugin *plugin = rz_bin_file_cur_plugin(bf);
	ut64 laddr = rz_bin_get_laddr(core->bin);
	if (!bf) {
		return false;
	}
	RzBinObject *obj = bf->o;
	const char *compiled = NULL;
	bool havecode;
	int bits;

	havecode = is_executable(obj) | (obj->entries != NULL);
	compiled = get_compile_time(bf->sdb);
	bits = (plugin && !strcmp(plugin->name, "any")) ? rz_config_get_i(core->config, "asm.bits") : info->bits;
	const char *endian = info->big_endian ? "BE" : "LE";

	char *tmp_buf;
	PJ *pj = state->d.pj;
	RzTable *t = state->d.t;
	int i, j, u, v, uv;
	Sdb *sdb_info = sdb_ns(obj->kv, "info", false);

	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("arch %s\n", info->arch);
		rz_cons_printf("cpu %s\n", str2na(info->cpu));
		rz_cons_printf("bits %d\n", bits);
		rz_cons_printf("os %s\n", info->os);
		rz_cons_printf("endian %s\n", info->big_endian ? "big" : "little");
		v = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
		if (v != -1) {
			rz_cons_printf("minopsz %d\n", v);
		}
		v = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE);
		if (v != -1) {
			rz_cons_printf("maxopsz %d\n", v);
		}
		v = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_ALIGN);
		if (v != -1) {
			rz_cons_printf("pcalign %d\n", v);
		}
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(pj);
		if (RZ_STR_ISNOTEMPTY(info->arch)) {
			pj_ks(pj, "arch", info->arch);
		}
		if (RZ_STR_ISNOTEMPTY(info->cpu)) {
			pj_ks(pj, "cpu", info->cpu);
		}
		pj_kn(pj, "baddr", rz_bin_get_baddr(core->bin));
		pj_kn(pj, "binsz", rz_bin_get_size(core->bin));
		if (RZ_STR_ISNOTEMPTY(info->rclass)) {
			pj_ks(pj, "bintype", info->rclass);
		}
		pj_ki(pj, "bits", bits);
		if (info->has_retguard != -1) {
			pj_kb(pj, "retguard", info->has_retguard);
		}
		if (RZ_STR_ISNOTEMPTY(info->bclass)) {
			pj_ks(pj, "class", info->bclass);
		}
		if (info->actual_checksum) {
			/* computed checksum */
			pj_ks(pj, "cmp.csum", info->actual_checksum);
		}
		if (compiled) {
			pj_ks(pj, "compiled", compiled);
		}
		if (info->compiler) {
			pj_ks(pj, "compiler", info->compiler);
		}
		if (info->debug_file_name) {
			pj_ks(pj, "dbg_file", info->debug_file_name);
		}
		pj_ks(pj, "endian", endian);
		if (info->rclass && !strcmp(info->rclass, "mdmp")) {
			tmp_buf = sdb_get(bf->sdb, "mdmp.flags", 0);
			if (tmp_buf) {
				pj_ks(pj, "flags", tmp_buf);
				free(tmp_buf);
			}
		}
		if (info->claimed_checksum) {
			/* checksum specified in header */
			pj_ks(pj, "hdr.csum", info->claimed_checksum);
		}
		if (info->guid) {
			pj_ks(pj, "guid", info->guid);
		}
		if (info->intrp) {
			pj_ks(pj, "intrp", info->intrp);
		}
		pj_kn(pj, "laddr", laddr);
		if (RZ_STR_ISNOTEMPTY(info->lang)) {
			pj_ks(pj, "lang", info->lang);
		}
		if (RZ_STR_ISNOTEMPTY(info->machine)) {
			pj_ks(pj, "machine", info->machine);
		}
		u = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE);
		if (u != -1) {
			pj_ki(pj, "maxopsz", u);
		}
		v = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
		if (v != -1) {
			pj_ki(pj, "minopsz", v);
		}
		if (RZ_STR_ISNOTEMPTY(info->os)) {
			pj_ks(pj, "os", info->os);
		}
		if (info->rclass && !strcmp(info->rclass, "pe")) {
			pj_kb(pj, "overlay", info->pe_overlay);
		}
		if (info->default_cc) {
			pj_ks(pj, "cc", info->default_cc);
		}
		uv = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_ALIGN);
		if (uv != -1) {
			pj_ki(pj, "pcalign", uv);
		}

		tmp_buf = sdb_get(sdb_info, "elf.relro", 0);
		if (tmp_buf) {
			pj_ks(pj, "relro", tmp_buf);
			free(tmp_buf);
		}
		if (info->rpath) {
			pj_ks(pj, "rpath", info->rpath);
		}
		if (info->rclass && !strcmp(info->rclass, "pe")) {
			// this should be moved if added to mach0 (or others)
			pj_kb(pj, "signed", info->signature);
		}

		if (info->rclass && !strcmp(info->rclass, "mdmp")) {
			v = sdb_num_get(bf->sdb, "mdmp.streams", 0);
			if (v != -1) {
				pj_ki(pj, "streams", v);
			}
		}
		if (RZ_STR_ISNOTEMPTY(info->subsystem)) {
			pj_ks(pj, "subsys", info->subsystem);
		}
		pj_kb(pj, "stripped", RZ_BIN_DBG_STRIPPED & info->dbg_info);
		pj_kb(pj, "crypto", info->has_crypto);
		pj_kb(pj, "havecode", havecode);
		pj_kb(pj, "va", info->has_va);
		pj_kb(pj, "sanitiz", info->has_sanitizers);
		pj_kb(pj, "static", rz_bin_is_static(core->bin));
		pj_kb(pj, "linenum", RZ_BIN_DBG_LINENUMS & info->dbg_info);
		pj_kb(pj, "lsyms", RZ_BIN_DBG_SYMS & info->dbg_info);
		pj_kb(pj, "canary", info->has_canary);
		pj_kb(pj, "PIE", info->has_pi);
		pj_kb(pj, "RELROCS", RZ_BIN_DBG_RELOCS & info->dbg_info);
		pj_kb(pj, "NX", info->has_nx);
		for (i = 0; info->sum[i].type; i++) {
			RzBinHash *h = &info->sum[i];
			pj_ko(pj, h->type);
			char *buf = malloc(2 * h->len + 1);
			if (!buf) {
				pj_end(pj);
				break;
			}
			for (j = 0; j < h->len; j++) {
				snprintf(buf + 2 * j, 3, "%02x", h->buf[j]);
			}
			pj_ks(pj, "hex", buf);
			free(buf);
			pj_end(pj);
		}
		pj_end(pj);

		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_set_columnsf(t, "ss", "field", "value");
		rz_table_hide_header(t);

		rz_table_add_rowf(t, "ss", "arch", str2na(info->arch));
		rz_table_add_rowf(t, "ss", "cpu", str2na(info->cpu));
		rz_table_add_rowf(t, "sX", "baddr", rz_bin_get_baddr(core->bin));
		rz_table_add_rowf(t, "sX", "binsz", rz_bin_get_size(core->bin));
		rz_table_add_rowf(t, "ss", "bintype", str2na(info->rclass));
		rz_table_add_rowf(t, "sd", "bits", bits);
		if (info->has_retguard != -1) {
			table_add_row_bool(t, "retguard", info->has_retguard);
		}
		rz_table_add_rowf(t, "ss", "class", str2na(info->bclass));
		if (info->actual_checksum) {
			/* computed checksum */
			rz_table_add_rowf(t, "ss", "cmp.csum", info->actual_checksum);
		}
		if (compiled) {
			rz_table_add_rowf(t, "ss", "compiled", compiled);
		}
		rz_table_add_rowf(t, "ss", "compiler", str2na(info->compiler));
		rz_table_add_rowf(t, "ss", "dbg_file", str2na(info->debug_file_name));
		rz_table_add_rowf(t, "ss", "endian", str2na(endian));
		if (info->rclass && !strcmp(info->rclass, "mdmp")) {
			tmp_buf = sdb_get(bf->sdb, "mdmp.flags", 0);
			if (tmp_buf) {
				rz_table_add_rowf(t, "ss", "flags", tmp_buf);
				free(tmp_buf);
			}
		}
		/* checksum specified in header */
		rz_table_add_rowf(t, "ss", "hdr.csum", str2na(info->claimed_checksum));
		rz_table_add_rowf(t, "ss", "guid", str2na(info->guid));
		rz_table_add_rowf(t, "ss", "intrp", str2na(info->intrp));
		rz_table_add_rowf(t, "sX", "laddr", laddr);
		rz_table_add_rowf(t, "ss", "lang", str2na(info->lang));
		rz_table_add_rowf(t, "ss", "machine", str2na(info->machine));
		u = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE);
		if (u != -1) {
			rz_table_add_rowf(t, "sd", "maxopsz", u);
		}
		v = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
		if (v != -1) {
			rz_table_add_rowf(t, "sd", "minopsz", v);
		}
		rz_table_add_rowf(t, "ss", "os", str2na(info->os));
		if (info->rclass && !strcmp(info->rclass, "pe")) {
			table_add_row_bool(t, "overlay", info->pe_overlay);
		}
		rz_table_add_rowf(t, "ss", "cc", str2na(info->default_cc));
		uv = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_ALIGN);
		if (uv != -1) {
			rz_table_add_rowf(t, "sd", "pcalign", uv);
		}

		tmp_buf = sdb_get(sdb_info, "elf.relro", 0);
		if (tmp_buf) {
			rz_table_add_rowf(t, "ss", "relro", tmp_buf);
			free(tmp_buf);
		}
		rz_table_add_rowf(t, "ss", "rpath", str2na(info->rpath));
		if (info->rclass && !strcmp(info->rclass, "pe")) {
			// this should be moved if added to mach0 (or others)
			table_add_row_bool(t, "signed", info->signature);
		}

		if (info->rclass && !strcmp(info->rclass, "mdmp")) {
			v = sdb_num_get(bf->sdb, "mdmp.streams", 0);
			if (v != -1) {
				rz_table_add_rowf(t, "sd", "streams", v);
			}
		}
		rz_table_add_rowf(t, "ss", "subsys", info->subsystem);
		table_add_row_bool(t, "stripped", RZ_BIN_DBG_STRIPPED & info->dbg_info);
		table_add_row_bool(t, "crypto", info->has_crypto);
		table_add_row_bool(t, "havecode", havecode);
		table_add_row_bool(t, "va", info->has_va);
		table_add_row_bool(t, "sanitiz", info->has_sanitizers);
		table_add_row_bool(t, "static", rz_bin_is_static(core->bin));
		table_add_row_bool(t, "linenum", RZ_BIN_DBG_LINENUMS & info->dbg_info);
		table_add_row_bool(t, "lsyms", RZ_BIN_DBG_SYMS & info->dbg_info);
		table_add_row_bool(t, "canary", info->has_canary);
		table_add_row_bool(t, "PIE", info->has_pi);
		table_add_row_bool(t, "RELROCS", RZ_BIN_DBG_RELOCS & info->dbg_info);
		table_add_row_bool(t, "NX", info->has_nx);

		for (i = 0; info->sum[i].type; i++) {
			RzBinHash *h = &info->sum[i];
			char *buf = rz_hex_bin2strdup(h->buf, h->len);
			rz_table_add_rowf(t, "ss", h->type, buf);
			free(buf);
		}
		break;
	default:
		rz_warn_if_reached();
		break;
	}

	return true;
}

static void flags_to_json(PJ *pj, int flags) {
	int i;

	pj_ka(pj, "flags");
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

static inline bool is_known_namespace(const char *string) {
	if (!strcmp(string, "std")) {
		return true;
	}
	return false;
}

#define CXX_BIN_VISIBILITY_FLAGS (RZ_BIN_METH_PUBLIC | RZ_BIN_METH_PRIVATE | RZ_BIN_METH_PROTECTED)
static void classdump_cpp(RzCore *r, RzBinClass *c) {
	RzListIter *iter;
	RzBinField *f;
	RzBinSymbol *sym;
	ut64 used = UT64_MAX;
	bool has_methods = false;
	bool is_namespace = false;

	const char *visibility = "class";
	if (c->visibility_str) {
		visibility = c->visibility_str;
		is_namespace = !!strstr(visibility, "namespace");
	} else if (is_known_namespace(c->name)) {
		visibility = "namespace";
		is_namespace = true;
	}

	if (c->super) {
		rz_cons_printf("%s %s : public %s {\n", visibility, c->name, c->super);
	} else {
		rz_cons_printf("%s %s {\n", visibility, c->name);
	}

	if (rz_list_length(c->methods) > 0) {
		has_methods = true;
		rz_list_foreach (c->methods, iter, sym) {
			const char *type = sym->type ? sym->type : "void";
			const char *name = sym->dname ? sym->dname : sym->name;

			if (!is_namespace && used != (sym->method_flags & CXX_BIN_VISIBILITY_FLAGS)) {
				used = sym->method_flags & CXX_BIN_VISIBILITY_FLAGS;
				if (used & RZ_BIN_METH_PRIVATE) {
					rz_cons_print("  private:\n");
				} else if (used & RZ_BIN_METH_PROTECTED) {
					rz_cons_print("  protected:\n");
				} else {
					rz_cons_print("  public:\n");
				}
			}
			rz_cons_print("    ");
			if (sym->method_flags & RZ_BIN_METH_STATIC) {
				rz_cons_print("static ");
			}

			if (name[0] == '~' || strstr(name, c->name) == name) {
				rz_cons_print(name);
			} else {
				rz_cons_printf("%s %s", type, name);
			}
			if (sym->method_flags & RZ_BIN_METH_CONST) {
				rz_cons_print(" const");
			}
			if (sym->method_flags & RZ_BIN_METH_VIRTUAL) {
				rz_cons_print(" = 0;\n");
			} else {
				rz_cons_print(";\n");
			}
		}
	}

	if (rz_list_length(c->fields) > 0) {
		if (has_methods) {
			rz_cons_newline();
		}
		used = UT64_MAX;
		rz_list_foreach (c->fields, iter, f) {
			if (!is_namespace && used != (f->visibility & CXX_BIN_VISIBILITY_FLAGS)) {
				used = f->visibility & CXX_BIN_VISIBILITY_FLAGS;
				if (used & RZ_BIN_METH_PRIVATE) {
					rz_cons_print("    private:\n");
				} else if (used & RZ_BIN_METH_PUBLIC) {
					rz_cons_print("    public:\n");
				} else if (used & RZ_BIN_METH_PROTECTED) {
					rz_cons_print("    protected:\n");
				}
			}
			rz_cons_print("    ");
			if (f->visibility & RZ_BIN_METH_STATIC) {
				rz_cons_print("static ");
			}
			if (f->visibility & RZ_BIN_METH_CONST) {
				rz_cons_print("const ");
			}
			rz_cons_printf("%s %s;\n", f->type, f->name);
		}
	}
	rz_cons_printf("}\n");
}
#undef CXX_BIN_VISIBILITY_FLAGS

static inline char *demangle_class(const char *classname) {
	if (!classname || classname[0] != 'L') {
		return strdup(classname ? classname : "?");
	}
	char *demangled = strdup(classname + 1);
	if (!demangled) {
		return strdup(classname);
	}
	rz_str_replace_ch(demangled, '/', '.', 1);
	demangled[strlen(demangled) - 1] = 0;
	return demangled;
}

static inline char *demangle_type(const char *any) {
	if (!any) {
		return strdup("unknown");
	}
	switch (any[0]) {
	case 'L': return rz_demangler_java(any);
	case 'B': return strdup("byte");
	case 'C': return strdup("char");
	case 'D': return strdup("double");
	case 'F': return strdup("float");
	case 'I': return strdup("int");
	case 'J': return strdup("long");
	case 'S': return strdup("short");
	case 'V': return strdup("void");
	case 'Z': return strdup("boolean");
	default: return strdup("unknown");
	}
}

static inline const char *resolve_java_visibility(const char *v) {
	return v ? v : "public";
}

static void classdump_java(RzCore *r, RzBinClass *c) {
	RzBinField *f;
	RzListIter *iter2, *iter3;
	RzBinSymbol *sym;
	bool simplify = false;
	char *package = NULL, *classname = NULL;
	char *tmp = (char *)rz_str_rchr(c->name, NULL, '/');
	if (tmp) {
		package = demangle_class(c->name);
		classname = strdup(tmp + 1);
		classname[strlen(classname) - 1] = 0;
		simplify = true;
	} else {
		package = strdup("defpackage");
		classname = demangle_class(c->name);
	}

	rz_cons_printf("package %s;\n\n", package);

	const char *visibility = resolve_java_visibility(c->visibility_str);
	rz_cons_printf("%s class %s {\n", visibility, classname);
	rz_list_foreach (c->fields, iter2, f) {
		visibility = resolve_java_visibility(f->visibility_str);
		char *ftype = demangle_type(f->type);
		if (!ftype) {
			ftype = strdup(f->type);
		} else if (simplify && ftype && package && classname) {
			// hide the current package in the demangled value.
			ftype = rz_str_replace(ftype, package, classname, 1);
		}
		rz_cons_printf("  %s %s %s;\n", visibility, ftype, f->name);
		free(ftype);
	}
	if (!rz_list_empty(c->fields)) {
		rz_cons_newline();
	}

	rz_list_foreach (c->methods, iter3, sym) {
		const char *mn = sym->dname ? sym->dname : sym->name;
		visibility = resolve_java_visibility(sym->visibility_str);
		char *dem = rz_demangler_java(mn);
		if (!dem) {
			dem = strdup(mn);
		} else if (simplify && dem && package && classname) {
			// hide the current package in the demangled value.
			dem = rz_str_replace(dem, package, classname, 1);
		}
		// rename all <init> to class name
		dem = rz_str_replace(dem, "<init>", classname, 1);
		rz_cons_printf("  %s %s;\n", visibility, dem);
		free(dem);
	}
	free(package);
	free(classname);
	rz_cons_printf("}\n\n");
}

static void bin_class_print_rizin(RzCore *r, RzBinClass *c, ut64 at_min) {
	RzListIter *iter2;
	RzBinFile *bf = rz_bin_cur(r->bin);
	RzBinField *f;
	RzBinSymbol *sym;

	// class
	char *fn = rz_core_bin_class_build_flag_name(c);
	if (fn) {
		rz_cons_printf("\"f %s @ 0x%" PFMT64x "\"\n", fn, at_min);
		free(fn);
	}

	// super class
	fn = rz_core_bin_super_build_flag_name(c);
	if (fn) {
		rz_cons_printf("\"f %s @ %d\"\n", fn, c->index);
		free(fn);
	}

	// class fields
	rz_list_foreach (c->fields, iter2, f) {
		char *fn = rz_core_bin_field_build_flag_name(c, f);
		if (fn) {
			rz_cons_printf("\"f %s @ 0x%08" PFMT64x "\"\n", fn, f->vaddr);
			free(fn);
		}
	}

	// class methods
	rz_list_foreach (c->methods, iter2, sym) {
		char *fn = rz_core_bin_method_build_flag_name(c, sym);
		if (fn) {
			rz_cons_printf("\"f %s @ 0x%" PFMT64x "\"\n", fn, sym->vaddr);
			free(fn);
		}
	}

	// C struct
	if (bf->o->lang == RZ_BIN_LANGUAGE_C || bf->o->lang == RZ_BIN_LANGUAGE_CXX || bf->o->lang == RZ_BIN_LANGUAGE_OBJC) {
		rz_cons_printf("td \"struct %s {", c->name);
		rz_list_foreach (c->fields, iter2, f) {
			char *n = objc_name_toc(f->name);
			char *t = objc_type_toc(f->type);
			rz_cons_printf(" %s %s;", t, n);
			free(t);
			free(n);
		}
		rz_cons_printf("};\"\n");
	}
}

RZ_API bool rz_core_bin_class_as_source_print(RzCore *core, RzBinFile *bf, const char *class_name) {
	rz_return_val_if_fail(core && bf, false);

	RzBinClass *c;
	RzListIter *iter;

	const RzList *cs = rz_bin_object_get_classes(bf->o);
	if (!cs) {
		return false;
	}

	bool found = false;
	rz_list_foreach (cs, iter, c) {
		if (class_name && (!c->name || !strstr(c->name, class_name))) {
			continue;
		}
		found = true;
		switch (bf->o->lang & (~RZ_BIN_LANGUAGE_BLOCKS)) {
		case RZ_BIN_LANGUAGE_KOTLIN:
		case RZ_BIN_LANGUAGE_GROOVY:
		case RZ_BIN_LANGUAGE_DART:
		case RZ_BIN_LANGUAGE_JAVA:
			classdump_java(core, c);
			break;
		case RZ_BIN_LANGUAGE_SWIFT:
		case RZ_BIN_LANGUAGE_OBJC:
			classdump_objc(core, c);
			break;
		case RZ_BIN_LANGUAGE_CXX:
			classdump_cpp(core, c);
			break;
		case RZ_BIN_LANGUAGE_C:
			classdump_c(core, c);
			break;
		default:
			return false;
		}
	}
	return found;
}

RZ_API bool rz_core_bin_class_fields_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state, const char *class_name) {
	rz_return_val_if_fail(core && bf && bf->o && state, false);

	RzListIter *iter, *iter2;
	RzBinClass *c;
	RzBinField *f;
	int m = 0;

	const RzList *cs = rz_bin_object_get_classes(bf->o);
	if (!cs) {
		return false;
	}

	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "Xissss", "address", "index", "class", "flags", "name", "type", NULL);

	rz_list_foreach (cs, iter, c) {
		if (class_name && (!c->name || strcmp(c->name, class_name))) {
			continue;
		}

		switch (state->mode) {
		case RZ_OUTPUT_MODE_QUIET:
			rz_list_foreach (c->fields, iter2, f) {
				char *mflags = rz_core_bin_method_flags_str(f->flags, 0);
				rz_cons_printf("0x%08" PFMT64x " field  %d %s %s %s\n", f->vaddr, m, c->name, mflags, f->name);
				free(mflags);
				m++;
			}
			break;
		case RZ_OUTPUT_MODE_QUIETEST:
			rz_list_foreach (c->fields, iter2, f) {
				rz_cons_printf("%s\n", f->name);
			}
			break;
		case RZ_OUTPUT_MODE_JSON:
			rz_list_foreach (c->fields, iter2, f) {
				pj_o(state->d.pj);
				if (f->type) {
					pj_ks(state->d.pj, "type", f->type);
				}
				pj_ks(state->d.pj, "name", f->name);
				pj_ks(state->d.pj, "class", c->name);
				if (f->flags) {
					flags_to_json(state->d.pj, f->flags);
				}
				pj_kN(state->d.pj, "addr", f->vaddr);
				pj_end(state->d.pj);
			}
			break;
		case RZ_OUTPUT_MODE_TABLE:
			rz_list_foreach (c->fields, iter2, f) {
				char *mflags = rz_core_bin_method_flags_str(f->flags, 0);
				rz_table_add_rowf(state->d.t, "Xissss", f->vaddr, m, c->name, mflags, f->name, f->type);
				free(mflags);
				m++;
			}
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_cmd_state_output_array_end(state);
	return true;
}

RZ_API bool rz_core_bin_class_methods_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state, const char *class_name) {
	rz_return_val_if_fail(core && bf && bf->o && state, false);

	RzListIter *iter, *iter2;
	RzBinClass *c;
	RzBinSymbol *sym;
	int m = 0;

	const RzList *cs = rz_bin_object_get_classes(bf->o);
	if (!cs) {
		return false;
	}

	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "Xisss", "address", "index", "class", "flags", "name", NULL);

	rz_list_foreach (cs, iter, c) {
		if (class_name && (!c->name || strcmp(c->name, class_name))) {
			continue;
		}

		rz_list_foreach (c->methods, iter2, sym) {
			const char *name = sym->dname ? sym->dname : sym->name;
			char *mflags = rz_core_bin_method_flags_str(sym->method_flags, 0);

			switch (state->mode) {
			case RZ_OUTPUT_MODE_QUIET:
				rz_cons_printf("0x%08" PFMT64x " method %d %s %s %s\n", sym->vaddr, m, c->name, mflags, name);
				break;
			case RZ_OUTPUT_MODE_QUIETEST:
				rz_cons_printf("%s\n", name);
				break;
			case RZ_OUTPUT_MODE_JSON:
				pj_o(state->d.pj);
				pj_ks(state->d.pj, "name", name);
				pj_ks(state->d.pj, "class", c->name);
				if (sym->method_flags) {
					flags_to_json(state->d.pj, sym->method_flags);
				}
				pj_kN(state->d.pj, "addr", sym->vaddr);
				pj_end(state->d.pj);
				break;
			case RZ_OUTPUT_MODE_TABLE:
				rz_table_add_rowf(state->d.t, "Xisss", sym->vaddr, m, c->name, mflags, name);
				break;
			default:
				rz_warn_if_reached();
				break;
			}

			free(mflags);
			m++;
		}
	}
	rz_cmd_state_output_array_end(state);
	return true;
}

RZ_API bool rz_core_bin_classes_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && bf && bf->o && state, false);

	RzListIter *iter, *iter2, *iter3;
	RzBinSymbol *sym;
	RzBinClass *c;
	RzBinField *f;

	const RzList *cs = rz_bin_object_get_classes(bf->o);
	if (!cs) {
		return false;
	}

	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "XXXss", "address", "min", "max", "name", "super", NULL);

	if (state->mode == RZ_OUTPUT_MODE_RIZIN) {
		rz_cons_println("fs classes");
	}

	rz_list_foreach (cs, iter, c) {
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

		switch (state->mode) {
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("0x%08" PFMT64x " [0x%08" PFMT64x " - 0x%08" PFMT64x "] %s%s%s\n",
				c->addr, at_min, at_max, c->name, c->super ? " " : "",
				c->super ? c->super : "");
			break;
		case RZ_OUTPUT_MODE_QUIETEST:
			rz_cons_printf("%s\n", c->name);
			break;
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_ks(state->d.pj, "classname", c->name);
			pj_kN(state->d.pj, "addr", c->addr);
			pj_ki(state->d.pj, "index", c->index);
			if (c->super) {
				pj_ks(state->d.pj, "visibility", c->visibility_str ? c->visibility_str : "");
				pj_ks(state->d.pj, "super", c->super);
			}
			pj_ka(state->d.pj, "methods");
			rz_list_foreach (c->methods, iter2, sym) {
				pj_o(state->d.pj);
				pj_ks(state->d.pj, "name", sym->name);
				if (sym->method_flags) {
					flags_to_json(state->d.pj, sym->method_flags);
				}
				pj_kN(state->d.pj, "addr", sym->vaddr);
				pj_end(state->d.pj);
			}
			pj_end(state->d.pj);
			pj_ka(state->d.pj, "fields");
			rz_list_foreach (c->fields, iter3, f) {
				pj_o(state->d.pj);
				pj_ks(state->d.pj, "name", f->name);
				if (f->type) {
					pj_ks(state->d.pj, "type", f->type);
				}
				if (f->flags) {
					flags_to_json(state->d.pj, f->flags);
				}
				pj_kN(state->d.pj, "addr", f->vaddr);
				pj_end(state->d.pj);
			}
			pj_end(state->d.pj);
			pj_end(state->d.pj);
			break;
		case RZ_OUTPUT_MODE_RIZIN:
			bin_class_print_rizin(core, c, at_min);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			rz_table_add_rowf(state->d.t, "XXXss", c->addr, at_min, at_max, c->name, c->super);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_cmd_state_output_array_end(state);
	return true;
}

RZ_API bool rz_core_bin_signatures_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state, false);

	RzBinFile *cur = rz_bin_cur(core->bin);
	RzBinPlugin *plg = rz_bin_file_cur_plugin(cur);
	if (!plg || !plg->signature) {
		return false;
	}

	char *signature = plg->signature(cur, state->mode == RZ_OUTPUT_MODE_JSON);
	if (!signature) {
		return false;
	}

	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_k(state->d.pj, "signature");
		pj_raw(state->d.pj, signature);
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_println(signature);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	free(signature);
	return true;
}

RZ_API bool rz_core_bin_fields_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && bf && bf->o && state, false);

	const RzList *fields = rz_bin_object_get_fields(bf->o);
	RzListIter *iter;
	RzBinField *field;
	bool haveComment;

	rz_cmd_state_output_set_columnsf(state, "XsXs", "paddr", "name", "vaddr", "comment");
	rz_cmd_state_output_array_start(state);
	rz_list_foreach (fields, iter, field) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_ks(state->d.pj, "name", field->name);
			pj_kN(state->d.pj, "vaddr", field->vaddr);
			pj_kN(state->d.pj, "paddr", field->paddr);
			if (field->comment && *field->comment) {
				pj_ks(state->d.pj, "comment", field->comment);
			}
			if (field->format && *field->format) {
				pj_ks(state->d.pj, "format", field->format);
			}
			char *o = rz_core_cmd_strf(core, "pfj%c%s@ 0x%" PFMT64x,
				field->format_named ? '.' : ' ', field->format, field->vaddr);
			if (o && *o) {
				rz_str_trim_tail(o);
				pj_k(state->d.pj, "pf");
				pj_j(state->d.pj, o);
			}
			free(o);
			pj_end(state->d.pj);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			rz_table_add_rowf(state->d.t, "XsXs", field->paddr, field->name, field->vaddr, field->comment);
			break;
		case RZ_OUTPUT_MODE_QUIET:
			haveComment = RZ_STR_ISNOTEMPTY(field->comment);
			rz_cons_printf("0x%08" PFMT64x " 0x%08" PFMT64x " %s%s%s\n",
				field->vaddr, field->paddr, field->name,
				haveComment ? "; " : "",
				haveComment ? field->comment : "");
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_cmd_state_output_array_end(state);
	return true;
}

RZ_API bool rz_core_bin_headers_print(RzCore *core, RzBinFile *bf) {
	rz_return_val_if_fail(core, false);

	RzBinFile *cur = rz_bin_cur(core->bin);
	RzBinPlugin *plg = rz_bin_file_cur_plugin(cur);
	if (plg && plg->header) {
		plg->header(cur);
	}
	return true;
}

static int bin_trycatch(RzCore *core, PJ *pj, int mode) {
	RzBinFile *bf = rz_bin_cur(core->bin);
	RzListIter *iter;
	RzBinTrycatch *tc;
	RzList *trycatch = rz_bin_file_get_trycatch(bf);
	int idx = 0;
	// FIXME: json mode
	rz_list_foreach (trycatch, iter, tc) {
		rz_cons_printf("f+ try.%d.%" PFMT64x ".from @ 0x%08" PFMT64x "\n", idx, tc->source, tc->from);
		rz_cons_printf("f+ try.%d.%" PFMT64x ".to @ 0x%08" PFMT64x "\n", idx, tc->source, tc->to);
		rz_cons_printf("f+ try.%d.%" PFMT64x ".catch @ 0x%08" PFMT64x "\n", idx, tc->source, tc->handler);
		if (tc->filter) {
			rz_cons_printf("f+ try.%d.%" PFMT64x ".filter @ 0x%08" PFMT64x "\n", idx, tc->source, tc->filter);
		}
		idx++;
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
		if (mode != RZ_MODE_JSON) {
			rz_cons_println("Unknown format");
		}
		return false;
	}
	return true;
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
	// set env if the binfile changed or we are dealing with xtr
	if (curfile != binfile || binfile->curxtr) {
		rz_core_bin_set_cur(r, binfile);
		if (binfile->o && binfile->o->info) {
			free(binfile->o->info->arch);
			binfile->o->info->arch = strdup(arch);
			binfile->o->info->bits = bits;
		}
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
	return bf && rz_core_bin_apply_all_info(core, bf) && rz_core_block_read(core);
}

/**
 * \brief Close an opened binary file
 *
 * \param core Reference to RzCore instance
 * \param bf Reference to RzBinFile to delete
 * \return true if the file was closed, false otherwise
 */
RZ_API bool rz_core_binfiles_delete(RzCore *core, RzBinFile *bf) {
	rz_bin_file_delete(core->bin, bf);
	bf = rz_bin_file_at(core->bin, core->offset);
	if (bf) {
		rz_io_use_fd(core->io, bf->fd);
	}
	return bf && rz_core_bin_apply_all_info(core, bf) && rz_core_block_read(core);
}

static void core_bin_file_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_if_fail(core && bf && bf->o);

	const char *name = bf ? bf->file : NULL;
	(void)rz_bin_get_info(core->bin); // XXX is this necssary for proper iniitialization
	ut32 bin_sz = bf ? bf->size : 0;
	RzBinObject *obj = bf->o;
	RzBinInfo *info = obj->info;
	ut8 bits = info ? info->bits : 0;
	const char *asmarch = rz_config_get(core->config, "asm.arch");
	const char *arch = info ? info->arch ? info->arch : asmarch : "unknown";

	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("%d\n", bf->id);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_ks(state->d.pj, "name", name ? name : "");
		pj_ki(state->d.pj, "iofd", bf->fd);
		pj_ki(state->d.pj, "bfid", bf->id);
		pj_ki(state->d.pj, "size", bin_sz);
		pj_ko(state->d.pj, "obj");
		pj_ks(state->d.pj, "arch", arch);
		pj_ki(state->d.pj, "bits", bits);
		pj_kN(state->d.pj, "binoffset", obj->boffset);
		pj_kN(state->d.pj, "objsize", obj->obj_size);
		pj_end(state->d.pj);
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("%d %d %s-%d ba:0x%08" PFMT64x " sz:%" PFMT64d " %s\n",
			bf->id, bf->fd, arch, bits, bf->o->opts.baseaddr, bf->o->size, name);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "ddsXxs", bf->id, bf->fd,
			arch, bf->o->opts.baseaddr, bf->o->size, name);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

/**
 * \brief Print all the opened binary files according to \p state
 *
 * \param core Reference to RzCore instance
 * \param state Reference to RzCmdStateOutput containing all the data to print
 *              data in the right format
 * \return true if everything was alright, false otherwise
 */
RZ_API bool rz_core_binfiles_print(RzCore *core, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state, false);

	RzListIter *iter;
	RzBinFile *binfile = NULL;
	const RzList *binfiles = core->bin ? core->bin->binfiles : NULL;
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "ddsXxs", "id", "fd", "arch", "baddr", "size", "name");
	rz_list_foreach (binfiles, iter, binfile) {
		core_bin_file_print(core, binfile, state);
	}
	rz_cmd_state_output_array_end(state);
	return true;
}

static void resolve_method_flags(RzStrBuf *buf, ut64 flags) {
	for (int i = 0; flags; flags >>= 1, i++) {
		if (!(flags & 1)) {
			continue;
		}
		const char *flag_string = rz_bin_get_meth_flag_string(1ULL << i, false);
		if (flag_string) {
			rz_strbuf_appendf(buf, ".%s", flag_string);
		}
	}
}

/**
 * \brief Returns the flag name of a class
 *
 **/
RZ_API RZ_OWN char *rz_core_bin_class_build_flag_name(RZ_NONNULL RzBinClass *cls) {
	rz_return_val_if_fail(cls, NULL);
	char *ret = NULL;
	if (!cls->name) {
		return NULL;
	}

	if (cls->visibility_str) {
		char *copy = strdup(cls->visibility_str);
		rz_str_replace_ch(copy, ' ', '.', 1);
		ret = rz_str_newf("class.%s.%s", copy, cls->name);
		free(copy);
	} else {
		ret = rz_str_newf("class.public.%s", cls->name);
	}
	rz_name_filter(ret, -1, true);
	return ret;
}

/**
 * \brief Returns the flag name of a super class
 *
 **/
RZ_API RZ_OWN char *rz_core_bin_super_build_flag_name(RZ_NONNULL RzBinClass *cls) {
	rz_return_val_if_fail(cls, NULL);
	char *ret = NULL;
	if (!cls->name || !cls->super) {
		return NULL;
	}

	if (cls->visibility_str) {
		char *copy = strdup(cls->visibility_str);
		rz_str_replace_ch(copy, ' ', '.', 1);
		ret = rz_str_newf("super.%s.%s.%s", copy, cls->name, cls->super);
		free(copy);
	} else {
		ret = rz_str_newf("super.public.%s.%s", cls->name, cls->super);
	}
	rz_name_filter(ret, -1, true);
	return ret;
}

/**
 * \brief Returns the flag name of a class method
 *
 **/
RZ_API RZ_OWN char *rz_core_bin_method_build_flag_name(RZ_NONNULL RzBinClass *cls, RZ_NONNULL RzBinSymbol *meth) {
	rz_return_val_if_fail(cls && meth, NULL);
	if (!cls->name || !meth->name) {
		return NULL;
	}

	RzStrBuf buf;
	rz_strbuf_initf(&buf, "method");

	if (meth->visibility_str) {
		char *copy = strdup(meth->visibility_str);
		rz_str_replace_ch(copy, ' ', '.', 1);
		rz_strbuf_appendf(&buf, ".%s", copy);
		free(copy);
	} else {
		resolve_method_flags(&buf, meth->method_flags);
	}
	const char *mn = meth->dname ? meth->dname : meth->name;
	rz_strbuf_appendf(&buf, ".%s.%s", cls->name, mn);
	char *ret = rz_strbuf_drain_nofree(&buf);
	rz_name_filter(ret, -1, true);
	return ret;
}

/**
 * \brief Returns the flag name of a class field
 *
 **/
RZ_API RZ_OWN char *rz_core_bin_field_build_flag_name(RZ_NONNULL RzBinClass *cls, RZ_NONNULL RzBinField *field) {
	rz_return_val_if_fail(cls && field, NULL);
	if (!cls->name || !field->name) {
		return NULL;
	}

	RzStrBuf buf;
	rz_strbuf_initf(&buf, "field");

	if (field->visibility_str) {
		char *copy = strdup(field->visibility_str);
		rz_str_replace_ch(copy, ' ', '.', 1);
		rz_strbuf_appendf(&buf, ".%s", copy);
		free(copy);
	} else {
		resolve_method_flags(&buf, field->flags);
	}
	rz_strbuf_appendf(&buf, ".%s.%s", cls->name, field->name);
	char *ret = rz_strbuf_drain_nofree(&buf);
	rz_name_filter(ret, -1, true);
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
		int pad_len = 4; // TODO: move to a config variable
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

RZ_IPI RzCmdStatus rz_core_bin_plugin_print(const RzBinPlugin *bp, RzCmdStateOutput *state) {
	rz_return_val_if_fail(bp && state, RZ_CMD_STATUS_ERROR);

	rz_cmd_state_output_set_columnsf(state, "sss", "type", "name", "description");

	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("%s\n", bp->name);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_ks(state->d.pj, "name", bp->name);
		pj_ks(state->d.pj, "description", bp->desc);
		if (bp->license) {
			pj_ks(state->d.pj, "license", bp->license);
		}
		if (bp->version) {
			pj_ks(state->d.pj, "version", bp->version);
		}
		if (bp->license) {
			pj_ks(state->d.pj, "author", bp->license);
		}
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("bin  %-11s %s (%s) %s %s\n",
			bp->name, bp->desc, bp->license ? bp->license : "???",
			bp->version ? bp->version : "",
			bp->author ? bp->author : "");
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "sss", "bin", bp->name, bp->desc);
		break;
	default:
		rz_warn_if_reached();
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_core_binxtr_plugin_print(const RzBinXtrPlugin *bx, RzCmdStateOutput *state) {
	rz_return_val_if_fail(bx && state, RZ_CMD_STATUS_ERROR);

	const char *name = NULL;

	rz_cmd_state_output_set_columnsf(state, "sss", "type", "name", "description");
	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("%s\n", bx->name);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_ks(state->d.pj, "name", bx->name);
		pj_ks(state->d.pj, "description", bx->desc);
		pj_ks(state->d.pj, "license", bx->license ? bx->license : "???");
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		name = strncmp(bx->name, "xtr.", 4) ? bx->name : bx->name + 3;
		rz_cons_printf("xtr  %-11s %s (%s)\n", name,
			bx->desc, bx->license ? bx->license : "???");
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "sss", "xtr", bx->name, bx->desc);
		break;
	default:
		rz_warn_if_reached();
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_core_binldr_plugin_print(const RzBinLdrPlugin *ld, RzCmdStateOutput *state) {
	rz_return_val_if_fail(ld && state, RZ_CMD_STATUS_ERROR);

	const char *name;

	rz_cmd_state_output_set_columnsf(state, "sss", "type", "name", "description");
	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("%s\n", ld->name);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_ks(state->d.pj, "name", ld->name);
		pj_ks(state->d.pj, "description", ld->desc);
		pj_ks(state->d.pj, "license", ld->license ? ld->license : "???");
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		name = strncmp(ld->name, "ldr.", 4) ? ld->name : ld->name + 3;
		rz_cons_printf("ldr  %-11s %s (%s)\n", name,
			ld->desc, ld->license ? ld->license : "???");
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "sss", "ldr", ld->name, ld->desc);
		break;
	default:
		rz_warn_if_reached();
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_API RzCmdStatus rz_core_bin_plugins_print(RzBin *bin, RzCmdStateOutput *state) {
	rz_return_val_if_fail(bin && state, RZ_CMD_STATUS_ERROR);

	RzBinPlugin *bp;
	RzBinXtrPlugin *bx;
	RzBinLdrPlugin *ld;
	RzListIter *iter;
	RzCmdStatus status;

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

RZ_API bool rz_core_bin_dwarf_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state, false);

	return bin_dwarf(core, bf, state);
}

RZ_API char *rz_core_bin_pdb_get_filename(RzCore *core) {
	RzBinInfo *info = rz_bin_get_info(core->bin);
	/* Autodetect local file */
	if (!info || !info->debug_file_name) {
		return NULL;
	}
	// Check raw path for debug filename
	bool file_found = rz_file_exists(info->debug_file_name);
	if (file_found) {
		return strdup(info->debug_file_name);
	}
	// Check debug filename basename in current directory
	const char *basename = rz_file_dos_basename(info->debug_file_name);
	file_found = rz_file_exists(basename);
	if (file_found) {
		return strdup(basename);
	}
	// Check if debug file is in file directory
	char *dir = rz_file_dirname(core->bin->cur->file);
	char *filename = rz_str_newf("%s/%s", dir, basename);
	free(dir);
	file_found = rz_file_exists(filename);
	if (file_found) {
		return filename;
	}
	free(filename);

	// Last chance: Check if file is in downstream symbol store
	const char *symstore_path = rz_config_get(core->config, "pdb.symstore");
	return rz_str_newf("%s" RZ_SYS_DIR "%s" RZ_SYS_DIR "%s" RZ_SYS_DIR "%s",
		symstore_path, basename, info->guid, basename);
}

static void bin_memory_print_rec(RzCmdStateOutput *state, RzBinMem *mirror, const RzList *mems, int perms) {
	RzListIter *it;
	RzBinMem *mem;

	rz_list_foreach (mems, it, mem) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_ks(state->d.pj, "name", mem->name);
			pj_ki(state->d.pj, "size", mem->size);
			pj_kn(state->d.pj, "address", mem->addr);
			pj_ks(state->d.pj, "flags", rz_str_rwx_i(mem->perms & perms));
			if (mirror) {
				pj_ks(state->d.pj, "mirror", mirror->name);
			}
			pj_end(state->d.pj);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			rz_table_add_rowf(state->d.t, "sxXss", mem->name, mem->size,
				mem->addr, rz_str_rwx_i(mem->perms & perms),
				mirror ? mirror->name : "");
			break;
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("0x%08" PFMT64x "\n", mem->addr);
			break;
		default:
			rz_warn_if_reached();
			break;
		}

		if (mem->mirrors) {
			bin_memory_print_rec(state, mem, mem->mirrors, mem->perms & perms);
		}
	}
}

RZ_API bool rz_core_bin_memory_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && bf && bf->o && state, false);

	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "sxXss", "name", "size", "address", "flags", "mirror");

	const RzList *mems = rz_bin_object_get_mem(bf->o);
	bin_memory_print_rec(state, NULL, mems, 7);
	rz_cmd_state_output_array_end(state);
	return true;
}

static void bin_resources_print_standard(RzCore *core, RzList *hashes, RzBinResource *resource) {
	char humansz[8];
	rz_num_units(humansz, sizeof(humansz), resource->size);
	rz_cons_printf("Resource %zd\n", resource->index);
	rz_cons_printf("  name: %s\n", resource->name);
	rz_cons_printf("  timestamp: %s\n", resource->time);
	rz_cons_printf("  vaddr: 0x%08" PFMT64x "\n", resource->vaddr);
	rz_cons_printf("  size: %s\n", humansz);
	rz_cons_printf("  type: %s\n", resource->type);
	rz_cons_printf("  language: %s\n", resource->language);
	if (hashes && resource->size > 0) {
		HtPP *digests = rz_core_bin_create_digests(core, resource->vaddr, resource->size, hashes);
		if (!digests) {
			return;
		}
		RzListIter *it = NULL;
		char *hash = NULL;
		bool found = false;
		rz_list_foreach (hashes, it, hash) {
			char *digest = ht_pp_find(digests, hash, &found);
			if (found) {
				rz_cons_printf("  %s: %s\n", hash, digest);
			}
		}
		ht_pp_free(digests);
	}
}

static void bin_resources_print_table(RzCore *core, RzCmdStateOutput *state, RzList *hashes, RzBinResource *resource) {
	rz_table_add_rowf(state->d.t, "dssXxss", resource->index, resource->name,
		resource->type, resource->vaddr, resource->size, resource->language, resource->time);
	if (hashes && resource->size > 0) {
		HtPP *digests = rz_core_bin_create_digests(core, resource->vaddr, resource->size, hashes);
		if (!digests) {
			return;
		}
		RzListIter *it;
		char *hash;
		bool found = false;
		rz_list_foreach (hashes, it, hash) {
			char *digest = ht_pp_find(digests, hash, &found);
			if (found && state->d.t) {
				rz_table_add_row_columnsf(state->d.t, "s", digest);
			}
		}
		ht_pp_free(digests);
	}
}

static void bin_resources_print_json(RzCore *core, RzCmdStateOutput *state, RzList *hashes, RzBinResource *resource) {
	pj_o(state->d.pj);
	pj_ks(state->d.pj, "name", resource->name);
	pj_ki(state->d.pj, "index", resource->index);
	pj_ks(state->d.pj, "type", resource->type);
	pj_kn(state->d.pj, "vaddr", resource->vaddr);
	pj_ki(state->d.pj, "size", resource->size);
	pj_ks(state->d.pj, "lang", resource->language);
	pj_ks(state->d.pj, "timestamp", resource->time);
	if (hashes && resource->size > 0) {
		HtPP *digests = rz_core_bin_create_digests(core, resource->vaddr, resource->size, hashes);
		if (!digests) {
			goto end;
		}
		RzListIter *it;
		char *hash;
		bool found = false;
		rz_list_foreach (hashes, it, hash) {
			char *digest = ht_pp_find(digests, hash, &found);
			if (found && state->d.pj) {
				pj_ks(state->d.pj, hash, digest);
			}
		}
		ht_pp_free(digests);
	}
end:
	pj_end(state->d.pj);
}

RZ_API bool rz_core_bin_resources_print(RZ_NONNULL RzCore *core, RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzCmdStateOutput *state, RZ_NULLABLE RzList *hashes) {
	rz_return_val_if_fail(core && state && bf, false);
	RzBinResource *resource = NULL;
	RzListIter *it = NULL;
	char *hashname = NULL;

	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "dssXxss", "index", "name", "type", "vaddr", "size", "lang", "timestamp");

	rz_list_foreach (hashes, it, hashname) {
		const RzMsgDigestPlugin *msg_plugin = rz_msg_digest_plugin_by_name(hashname);
		if (msg_plugin) {
			rz_cmd_state_output_set_columnsf(state, "s", msg_plugin->name);
		}
	}

	const RzList *resources = rz_bin_object_get_resources(bf->o);

	rz_list_foreach (resources, it, resource) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_STANDARD:
			bin_resources_print_standard(core, hashes, resource);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			bin_resources_print_table(core, state, hashes, resource);
			break;
		case RZ_OUTPUT_MODE_JSON:
			bin_resources_print_json(core, state, hashes, resource);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}

	rz_cmd_state_output_array_end(state);
	return true;
}

RZ_API bool rz_core_bin_versions_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state, false);

	// TODO: add rz_bin_object_get_versions and switch to table + json output
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		bin_versioninfo(core, NULL, RZ_MODE_PRINT);
		break;
	case RZ_OUTPUT_MODE_JSON:
		bin_versioninfo(core, state->d.pj, RZ_MODE_JSON);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	return true;
}

RZ_API bool rz_core_bin_trycatch_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state, false);

	// TODO: add rz_bin_object_get_trycatch and switch to table + json output
	switch (state->mode) {
	case RZ_OUTPUT_MODE_RIZIN:
		bin_trycatch(core, NULL, RZ_MODE_PRINT);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	return true;
}

RZ_API bool rz_core_bin_sections_mapping_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && bf && bf->o && state, false);
	rz_warn_if_fail(state->mode == RZ_OUTPUT_MODE_TABLE);

	RzVector *maps = rz_bin_object_sections_mapping_list(bf->o);
	if (!maps) {
		return false;
	}

	rz_cmd_state_output_set_columnsf(state, "ss", "Segment", "Sections");
	rz_cmd_state_output_array_start(state);

	RzBinSectionMap *map;
	rz_vector_foreach(maps, map) {
		RzStrBuf *sb = rz_strbuf_new(NULL);
		const char *space = "";
		void **it;

		rz_table_add_rowf(state->d.t, "s", map->segment->name);

		rz_pvector_foreach (&map->sections, it) {
			RzBinSection *sect = *(RzBinSection **)it;
			rz_strbuf_appendf(sb, "%s%s", space, sect->name);
			space = " ";
		}
		rz_table_add_row_columnsf(state->d.t, "s", rz_strbuf_get(sb));
		rz_strbuf_free(sb);
	}
	rz_vector_free(maps);

	rz_cmd_state_output_array_end(state);
	return true;
}

RZ_API bool rz_core_bin_size_print(RzCore *core, RzBinFile *bf, RzCmdStateOutput *state) {
	rz_return_val_if_fail(core && state, false);

	ut64 size = rz_bin_get_size(core->bin);
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_n(state->d.pj, size);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		rz_cons_printf("f bin_size @ %" PFMT64u "\n", size);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("%" PFMT64u "\n", size);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	return true;
}

struct arch_ctx {
	ut64 offset;
	ut64 size;
	const char *arch;
	int bits;
	const char *machine;
};

static void print_arch(RzBin *bin, RzCmdStateOutput *state, struct arch_ctx *ctx, const char *flag, RzBinInfo *info) {
	char str_fmt[30];
	const char *fmt = "Xnss";

	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("%s\n", ctx->arch);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_ks(state->d.pj, "arch", ctx->arch);
		pj_ki(state->d.pj, "bits", ctx->bits);
		pj_kn(state->d.pj, "offset", ctx->offset);
		pj_kn(state->d.pj, "size", ctx->size);
		if (info && !strcmp(ctx->arch, "mips")) {
			pj_ks(state->d.pj, "isa", info->cpu);
			pj_ks(state->d.pj, "features", info->features);
		}
		if (ctx->machine) {
			pj_ks(state->d.pj, "machine", ctx->machine);
		}
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		if (flag && strcmp(flag, "unknown_flag")) {
			rz_strf(str_fmt, "%s_%i %s", ctx->arch, ctx->bits, flag);
		} else {
			rz_strf(str_fmt, "%s_%i", ctx->arch, ctx->bits);
		}
		rz_table_add_rowf(state->d.t, fmt, ctx->offset, ctx->size, str_fmt, ctx->machine);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_API bool rz_core_bin_archs_print(RzBin *bin, RzCmdStateOutput *state) {
	rz_return_val_if_fail(bin && state, false);

	RzBinFile *binfile = rz_bin_cur(bin);
	if (!binfile) {
		return false;
	}

	const char *fmt = "Xnss";
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, fmt, "offset", "size", "arch", "machine", NULL);

	if (binfile->curxtr) {
		RzListIter *iter_xtr;
		RzBinXtrData *xtr_data;
		rz_list_foreach (binfile->xtr_data, iter_xtr, xtr_data) {
			if (!xtr_data || !xtr_data->metadata ||
				!xtr_data->metadata->arch) {
				continue;
			}
			struct arch_ctx ctx = { 0 };
			ctx.offset = xtr_data->offset;
			ctx.size = xtr_data->size;
			ctx.arch = xtr_data->metadata->arch;
			ctx.bits = xtr_data->metadata->bits;
			ctx.machine = xtr_data->metadata->machine;

			print_arch(bin, state, &ctx, NULL, NULL);
		}
	} else {
		RzBinObject *obj = binfile->o;
		RzBinInfo *info = obj->info;
		struct arch_ctx ctx = { 0 };
		ctx.offset = obj->boffset;
		ctx.size = obj->obj_size;
		ctx.arch = info ? info->arch : "unk_0";
		ctx.bits = info ? info->bits : 0;
		ctx.machine = info ? info->machine : "unknown_machine";

		const char *h_flag = info ? info->head_flag : NULL;
		print_arch(bin, state, &ctx, h_flag, info);
	}

	rz_cmd_state_output_array_end(state);
	return true;
}

RZ_API bool rz_core_bin_pdb_load(RZ_NONNULL RzCore *core, RZ_NONNULL const char *filename) {
	rz_cons_push();
	RzPdb *pdb = rz_core_pdb_load_info(core, filename);
	if (!pdb) {
		return false;
	}
	rz_bin_pdb_free(pdb);
	const char *buf = rz_cons_get_buffer();
	if (!buf) {
		rz_cons_pop();
		return false;
	}
	char *s = strdup(buf);
	rz_cons_pop();
	if (!s) {
		return false;
	}

	RzCmdStatus status = rz_core_cmd_rzshell(core, s, 0);
	free(s);
	return status == RZ_CMD_STATUS_OK;
}
