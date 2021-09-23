// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include "rz_bin.h"
#include "rz_config.h"
#include "rz_cons.h"
#include "rz_core.h"
#include "../bin/pdb/pdb_downloader.h"

static bool demangle_internal(RzCore *core, const char *lang, const char *s) {
	char *res = NULL;
	int type = rz_bin_demangle_type(lang);
	switch (type) {
	case RZ_BIN_NM_CXX: res = rz_bin_demangle_cxx(core->bin->cur, s, 0); break;
	case RZ_BIN_NM_JAVA: res = rz_bin_demangle_java(s); break;
	case RZ_BIN_NM_OBJC: res = rz_bin_demangle_objc(NULL, s); break;
	case RZ_BIN_NM_SWIFT: res = rz_bin_demangle_swift(s, core->bin->demanglercmd); break;
	case RZ_BIN_NM_DLANG: res = rz_bin_demangle_plugin(core->bin, "dlang", s); break;
	case RZ_BIN_NM_MSVC: res = rz_bin_demangle_msvc(s); break;
	case RZ_BIN_NM_RUST: res = rz_bin_demangle_rust(core->bin->cur, s, 0); break;
	default:
		rz_bin_demangle_list(core->bin);
		return true;
	}
	if (res) {
		if (*res) {
			rz_cons_printf("%s\n", res);
		}
		free(res);
		return false;
	}
	return true;
}

static int bin_is_executable(RzBinObject *obj) {
	RzListIter *it;
	RzBinSection *sec;
	if (obj) {
		if (obj->info && obj->info->arch) {
			return true;
		}
		rz_list_foreach (obj->sections, it, sec) {
			if (sec->perm & RZ_PERM_X) {
				return true;
			}
		}
	}
	return false;
}

static bool is_equal_file_hashes(RzList *lfile_hashes, RzList *rfile_hashes, bool *equal) {
	rz_return_val_if_fail(lfile_hashes, false);
	rz_return_val_if_fail(rfile_hashes, false);
	rz_return_val_if_fail(equal, false);

	*equal = true;
	RzBinFileHash *fh_l, *fh_r;
	RzListIter *hiter_l, *hiter_r;
	rz_list_foreach (lfile_hashes, hiter_l, fh_l) {
		rz_list_foreach (rfile_hashes, hiter_r, fh_r) {
			if (strcmp(fh_l->type, fh_r->type)) {
				continue;
			}
			if (!!strcmp(fh_l->hex, fh_r->hex)) {
				*equal = false;
				return true;
			}
		}
	}
	return true;
}

static bool source_file_collect_cb(void *user, const void *k, const void *v) {
	RzPVector *r = user;
	char *f = strdup(k);
	if (f) {
		rz_pvector_push(r, f);
	}
	return true;
}

typedef enum {
	PRINT_SOURCE_INFO_LINES_ALL,
	PRINT_SOURCE_INFO_LINES_HERE,
	PRINT_SOURCE_INFO_FILES
} PrintSourceInfoType;

static bool print_source_info(RzCore *core, PrintSourceInfoType type, RzCmdStateOutput *state) {
	RzBinFile *binfile = core->bin->cur;
	if (!binfile || !binfile->o) {
		rz_cons_printf("No file loaded.\n");
		return false;
	}
	RzBinSourceLineInfo *li = binfile->o->lines;
	if (!li) {
		rz_cons_printf("No source info available.\n");
		return true;
	}
	switch (type) {
	case PRINT_SOURCE_INFO_FILES: {
		// collect all filenames uniquely
		HtPP *files = ht_pp_new0();
		if (!files) {
			return false;
		}
		for (size_t i = 0; i < li->samples_count; i++) {
			RzBinSourceLineSample *s = &li->samples[i];
			if (!s->line || !s->file) {
				continue;
			}
			ht_pp_insert(files, s->file, NULL);
		}
		// sort them alphabetically
		RzPVector sorter;
		rz_pvector_init(&sorter, free);
		ht_pp_foreach(files, source_file_collect_cb, &sorter);
		rz_pvector_sort(&sorter, (RzPVectorComparator)strcmp);
		ht_pp_free(files);
		// print them!
		if (state->mode == RZ_OUTPUT_MODE_JSON) {
			pj_a(state->d.pj);
			void **it;
			rz_pvector_foreach (&sorter, it) {
				pj_s(state->d.pj, *it);
			}
			pj_end(state->d.pj);
		} else {
			rz_cons_printf("[Source file]\n");
			void **it;
			rz_pvector_foreach (&sorter, it) {
				const char *file = *it;
				rz_cons_printf("%s\n", file);
			}
		}
		rz_pvector_fini(&sorter);
		break;
	}
	case PRINT_SOURCE_INFO_LINES_ALL:
		rz_core_bin_print_source_line_info(core, li, state);
		break;
	case PRINT_SOURCE_INFO_LINES_HERE:
		rz_cmd_state_output_array_start(state);
		for (const RzBinSourceLineSample *s = rz_bin_source_line_info_get_first_at(li, core->offset);
			s; s = rz_bin_source_line_info_get_next(li, s)) {
			rz_core_bin_print_source_line_sample(core, s, state);
		}
		rz_cmd_state_output_array_end(state);
		break;
	}
	return true;
}

RZ_IPI int rz_cmd_info_kuery(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	RzBinObject *o = rz_bin_cur_object(core->bin);
	Sdb *db = o ? o->kv : NULL;
	switch (input[0]) {
	case 'v':
		if (db) {
			char *o = sdb_querys(db, NULL, 0, input + 2);
			if (o && *o) {
				rz_cons_print(o);
			}
			free(o);
		}
		break;
	case '*':
		rz_core_bin_export_info(core, RZ_MODE_RIZINCMD);
		break;
	case '.':
	case ' ':
		if (db) {
			char *o = sdb_querys(db, NULL, 0, input + 1);
			if (o && *o) {
				rz_cons_print(o);
			}
			free(o);
		}
		break;
	case '\0':
		if (db) {
			char *o = sdb_querys(db, NULL, 0, "*");
			if (o && *o) {
				rz_cons_print(o);
			}
			free(o);
		}
		break;
	case '?':
	default:
		eprintf("Usage: ik [sdb-query]\n");
		eprintf("Usage: ik*    # load all header information\n");
		return 1;
	}
	return 0;
}

static RzCmdStatus bool2status(bool val) {
	return val ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

#define GET_CHECK_CUR_BINFILE(core) \
	RzBinFile *bf = rz_bin_cur(core->bin); \
	if (!bf) { \
		RZ_LOG_ERROR("No binary object currently selected.\n"); \
		return RZ_CMD_STATUS_ERROR; \
	}

RZ_IPI RzCmdStatus rz_cmd_info_archs_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return bool2status(rz_core_bin_archs_print(core->bin, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_all_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	ut32 mask = RZ_CORE_BIN_ACC_INFO;
	mask |= RZ_CORE_BIN_ACC_IMPORTS;
	mask |= RZ_CORE_BIN_ACC_ENTRIES;
	mask |= RZ_CORE_BIN_ACC_EXPORTS;
	mask |= RZ_CORE_BIN_ACC_CLASSES;
	mask |= RZ_CORE_BIN_ACC_SYMBOLS;
	mask |= RZ_CORE_BIN_ACC_SECTIONS;
	mask |= RZ_CORE_BIN_ACC_MEM;
	mask |= RZ_CORE_BIN_ACC_STRINGS;
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_o(state->d.pj);
	}
	bool res = rz_core_bin_print(core, bf, mask, NULL, state, NULL);
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(state->d.pj);
	}
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_info_entry_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_entries_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_entryexits_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_initfini_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_exports_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_exports_print(core, bf, state, NULL));
}

RZ_IPI RzCmdStatus rz_cmd_info_cur_export_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_cur_export_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_symbols_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_symbols_print(core, bf, state, NULL));
}

RZ_IPI RzCmdStatus rz_cmd_info_cur_symbol_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_cur_symbol_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_imports_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_imports_print(core, bf, state, NULL));
}

RZ_IPI RzCmdStatus rz_cmd_info_libs_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_libs_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_main_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_main_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_relocs_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_relocs_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_sections_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	RzList *hashes = rz_list_new_from_array((const void **)argv + 1, argc - 1);
	if (!hashes) {
		return RZ_CMD_STATUS_ERROR;
	}
	bool res = rz_core_bin_sections_print(core, bf, state, NULL, hashes);
	rz_list_free(hashes);
	return bool2status(res);
}

RZ_IPI RzCmdStatus rz_cmd_info_cur_section_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	RzList *hashes = rz_list_new_from_array((const void **)argv + 1, argc - 1);
	if (!hashes) {
		return RZ_CMD_STATUS_ERROR;
	}
	bool res = rz_core_bin_cur_section_print(core, bf, state, hashes);
	rz_list_free(hashes);
	return bool2status(res);
}

RZ_IPI RzCmdStatus rz_cmd_info_section_bars_handler(RzCore *core, int argc, const char **argv) {
	RzCmdStatus res = RZ_CMD_STATUS_ERROR;
	RzBinObject *o = rz_bin_cur_object(core->bin);
	if (!o) {
		RZ_LOG_ERROR("No binary object at current address\n");
		return RZ_CMD_STATUS_ERROR;
	}

	RzList *sections = rz_bin_object_get_sections(o);
	if (!sections) {
		RZ_LOG_ERROR("Cannot retrieve sections\n");
		return RZ_CMD_STATUS_ERROR;
	}

	int cols = rz_cons_get_size(NULL);
	RzList *list = rz_list_newf((RzListFree)rz_listinfo_free);
	if (!list) {
		goto sections_err;
	}

	RzListIter *iter;
	RzBinSection *section;
	rz_list_foreach (sections, iter, section) {
		char humansz[8];
		RzInterval pitv = (RzInterval){ section->paddr, section->size };
		RzInterval vitv = (RzInterval){ section->vaddr, section->vsize };

		rz_num_units(humansz, sizeof(humansz), section->size);
		RzListInfo *info = rz_listinfo_new(section->name, pitv, vitv, section->perm, humansz);
		if (!info) {
			RZ_LOG_ERROR("Cannot print section bars\n");
			goto list_err;
		}
		rz_list_append(list, info);
	}
	RzTable *table = rz_core_table(core);
	if (!table) {
		RZ_LOG_ERROR("Cannot print section bars\n");
		goto list_err;
	}
	rz_table_visual_list(table, list, core->offset, -1, cols, core->io->va);

	char *s = rz_table_tostring(table);
	if (!s) {
		RZ_LOG_ERROR("Cannot print section bars\n");
		goto table_err;
	}
	rz_cons_printf("%s\n", s);
	free(s);
	res = RZ_CMD_STATUS_OK;

table_err:
	rz_table_free(table);
list_err:
	rz_list_free(list);
sections_err:
	rz_list_free(sections);
	return res;
}

RZ_IPI RzCmdStatus rz_cmd_info_segments_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	RzList *hashes = rz_list_new_from_array((const void **)argv + 1, argc - 1);
	if (!hashes) {
		return RZ_CMD_STATUS_ERROR;
	}
	bool res = rz_core_bin_segments_print(core, bf, state, NULL, hashes);
	rz_list_free(hashes);
	return bool2status(res);
}

RZ_IPI RzCmdStatus rz_cmd_info_strings_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_strings_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_whole_strings_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzBinFile *bf = rz_bin_cur(core->bin);
	return bool2status(rz_core_bin_whole_strings_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_dump_strings_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	int min = rz_config_get_i(core->config, "bin.minstr");
	int strmode = bf->strmode;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		bf->strmode = RZ_MODE_JSON;
		break;
	case RZ_OUTPUT_MODE_TABLE:
		bf->strmode = RZ_MODE_PRINT;
		break;
	case RZ_OUTPUT_MODE_QUIET:
		bf->strmode = RZ_MODE_SIMPLE;
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	rz_bin_dump_strings(bf, min, 2);
	bf->strmode = strmode;
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_purge_string_handler(RzCore *core, int argc, const char **argv) {
	bool old_tmpseek = core->tmpseek;
	core->tmpseek = false;
	char *strpurge = core->bin->strpurge;
	rz_core_cmdf(core, "e bin.str.purge=%s%s0x%" PFMT64x, strpurge ? strpurge : "",
		strpurge && *strpurge ? "," : "", core->offset);
	core->tmpseek = old_tmpseek;
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (!core->file) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_o(state->d.pj);
		pj_k(state->d.pj, "core");
	}
	RzBinFile *bf = rz_bin_cur(core->bin);
	bool res = rz_core_file_info_print(core, bf, state);
	if (bf && bin_is_executable(bf->o)) {
		if (state->mode == RZ_OUTPUT_MODE_JSON) {
			pj_k(state->d.pj, "bin");
		}
		rz_core_bin_info_print(core, bf, state);
	}
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(state->d.pj);
	}
	return bool2status(res);
}

RZ_IPI RzCmdStatus rz_cmd_info_classes_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_classes_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_class_as_source_handler(RzCore *core, int argc, const char **argv) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_class_as_source_print(core, bf, argv[1]));
}

RZ_IPI RzCmdStatus rz_cmd_info_class_fields_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_class_fields_print(core, bf, state, argv[1]));
}

RZ_IPI RzCmdStatus rz_cmd_info_class_methods_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_class_methods_print(core, bf, state, argv[1]));
}

RZ_IPI RzCmdStatus rz_cmd_info_signature_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_signatures_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_fields_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_fields_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_headers_handler(RzCore *core, int argc, const char **argv) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_headers_print(core, bf));
}

RZ_IPI RzCmdStatus rz_cmd_info_binary_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_info_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_plugins_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (argc < 2) {
		rz_core_bin_plugins_print(core->bin, state);
		return RZ_CMD_STATUS_OK;
	}

	const char *plugin_name = argv[1];
	const RzBinPlugin *bp = rz_bin_plugin_get(core->bin, plugin_name);
	if (bp) {
		rz_core_bin_plugin_print(bp, state);
		return RZ_CMD_STATUS_OK;
	}

	const RzBinXtrPlugin *xbp = rz_bin_xtrplugin_get(core->bin, plugin_name);
	if (xbp) {
		rz_core_binxtr_plugin_print(xbp, state);
		return RZ_CMD_STATUS_OK;
	}

	const RzBinLdrPlugin *lbp = rz_bin_ldrplugin_get(core->bin, plugin_name);
	if (lbp) {
		rz_core_binldr_plugin_print(lbp, state);
		return RZ_CMD_STATUS_OK;
	}

	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_info_dwarf_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_dwarf_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_pdb_load_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	char *filename = argc > 1 ? strdup(argv[1]) : rz_core_bin_pdb_get_filename(core);
	if (!filename) {
		RZ_LOG_ERROR("Cannot find the right PDB file to load\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_file_exists(filename)) {
		RZ_LOG_ERROR("Cannot open file '%s'\n", filename);
		free(filename);
		return RZ_CMD_STATUS_ERROR;
	}

	RzCmdStatus status = bool2status(rz_core_bin_pdb_load(core, filename));
	free(filename);
	return status;
}

RZ_IPI RzCmdStatus rz_cmd_info_pdb_show_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	char *filename = argc > 1 ? strdup(argv[1]) : rz_core_bin_pdb_get_filename(core);
	if (!filename) {
		RZ_LOG_ERROR("Cannot find the right PDB file to load\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_file_exists(filename)) {
		RZ_LOG_ERROR("Cannot open file '%s'\n", filename);
		free(filename);
		return RZ_CMD_STATUS_ERROR;
	}

	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_core_pdb_info(core, filename, NULL, RZ_MODE_PRINT);
		break;
	case RZ_OUTPUT_MODE_JSON:
		rz_core_pdb_info(core, filename, state->d.pj, RZ_MODE_JSON);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		rz_core_pdb_info(core, filename, NULL, RZ_MODE_RIZINCMD);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	free(filename);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_pdb_download_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	SPDBOptions pdbopts;
	pdbopts.user_agent = rz_config_get(core->config, "pdb.useragent");
	pdbopts.extract = rz_config_get_i(core->config, "pdb.extract");
	pdbopts.symbol_store_path = rz_config_get(core->config, "pdb.symstore");
	pdbopts.symbol_server = rz_config_get(core->config, "pdb.server");
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_o(state->d.pj);
	}
	int r = rz_bin_pdb_download(core, state->mode == RZ_OUTPUT_MODE_JSON ? state->d.pj : NULL, state->mode == RZ_OUTPUT_MODE_JSON, &pdbopts);
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(state->d.pj);
	}
	if (r > 0) {
		eprintf("Error while downloading pdb file\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_demangle_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(demangle_internal(core, argv[1], argv[2]));
}

RZ_IPI RzCmdStatus rz_cmd_info_memory_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_memory_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_resources_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_resources_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_hashes_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut64 limit = rz_config_get_i(core->config, "bin.hashlimit");
	RzBinInfo *info = rz_bin_get_info(core->bin);
	if (!info) {
		eprintf("Cannot get bin info\n");
		return RZ_CMD_STATUS_ERROR;
	}

	GET_CHECK_CUR_BINFILE(core);

	RzList *new_hashes = rz_bin_file_compute_hashes(core->bin, bf, limit);
	RzList *old_hashes = rz_bin_file_set_hashes(core->bin, new_hashes);
	bool equal = true;
	if (!rz_list_empty(new_hashes) && !rz_list_empty(old_hashes)) {
		if (!is_equal_file_hashes(new_hashes, old_hashes, &equal)) {
			eprintf("Cannot compare file hashes\n");
			rz_list_free(old_hashes);
			return RZ_CMD_STATUS_ERROR;
		}
	}
	RzBinFileHash *fh_old, *fh_new;
	RzListIter *hiter_old, *hiter_new;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		rz_list_foreach (new_hashes, hiter_new, fh_new) {
			pj_ks(state->d.pj, fh_new->type, fh_new->hex);
		}
		if (!equal) {
			// print old hashes prefixed with `o` character like `omd5` and `isha1`
			rz_list_foreach (old_hashes, hiter_old, fh_old) {
				char *key = rz_str_newf("o%s", fh_old->type);
				pj_ks(state->d.pj, key, fh_old->hex);
				free(key);
			}
		}
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		if (!equal) {
			eprintf("File has been modified.\n");
			hiter_new = rz_list_iterator(new_hashes);
			hiter_old = rz_list_iterator(old_hashes);
			while (rz_list_iter_next(hiter_new) && rz_list_iter_next(hiter_old)) {
				fh_new = (RzBinFileHash *)rz_list_iter_get(hiter_new);
				fh_old = (RzBinFileHash *)rz_list_iter_get(hiter_old);
				if (strcmp(fh_new->type, fh_old->type)) {
					eprintf("Wrong file hashes structure");
				}
				if (!strcmp(fh_new->hex, fh_old->hex)) {
					eprintf("= %s %s\n", fh_new->type, fh_new->hex); // output one line because hash remains same `= hashtype hashval`
				} else {
					// output diff-like two lines, one with old hash val `- hashtype hashval` and one with new `+ hashtype hashval`
					eprintf("- %s %s\n+ %s %s\n",
						fh_old->type, fh_old->hex,
						fh_new->type, fh_new->hex);
				}
			}
		} else { // hashes are equal
			rz_list_foreach (new_hashes, hiter_new, fh_new) {
				rz_cons_printf("%s %s\n", fh_new->type, fh_new->hex);
			}
		}
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	rz_list_free(old_hashes);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_versions_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_versions_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_trycatch_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_trycatch_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_sourcelines_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return bool2status(print_source_info(core, PRINT_SOURCE_INFO_LINES_ALL, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_sourcelines_here_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return bool2status(print_source_info(core, PRINT_SOURCE_INFO_LINES_HERE, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_source_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return bool2status(print_source_info(core, PRINT_SOURCE_INFO_FILES, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_guess_size_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_o(state->d.pj);
		pj_k(state->d.pj, "size");
	}
	bool res = rz_core_bin_size_print(core, bf, state);
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(state->d.pj);
	}
	return bool2status(res);
}
