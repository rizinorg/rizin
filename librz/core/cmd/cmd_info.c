// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_bin.h>
#include <rz_config.h>
#include <rz_cons.h>
#include <rz_core.h>
#include <rz_demangler.h>
#include "../bin/pdb/pdb_downloader.h"
#include "../core_private.h"

static int bin_is_executable(RzBinObject *obj) {
	void **it;
	RzBinSection *sec;
	if (obj) {
		if (obj->info && obj->info->arch) {
			return true;
		}
		rz_pvector_foreach (obj->sections, it) {
			sec = *it;
			if (sec->perm & RZ_PERM_X) {
				return true;
			}
		}
	}
	return false;
}

static bool is_equal_file_hashes(RzPVector /*<RzBinFileHash *>*/ *lfile_hashes, RzPVector /*<RzBinFileHash *>*/ *rfile_hashes, bool *equal) {
	rz_return_val_if_fail(lfile_hashes, false);
	rz_return_val_if_fail(rfile_hashes, false);
	rz_return_val_if_fail(equal, false);

	*equal = true;
	RzBinFileHash *fh_l, *fh_r;
	void **hiter_l, **hiter_r;
	rz_pvector_foreach (lfile_hashes, hiter_l) {
		fh_l = *hiter_l;
		rz_pvector_foreach (rfile_hashes, hiter_r) {
			fh_r = *hiter_r;
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

static bool source_file_collect_cb(void *user, const char *k, const void *v) {
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

static int compare_string(const char *s1, const char *s2, void *user) {
	return strcmp(s1, s2);
}

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
		HtSP *files = ht_sp_new(HT_STR_DUP, NULL, NULL);
		if (!files) {
			return false;
		}
		for (size_t i = 0; i < li->samples_count; i++) {
			RzBinSourceLineSample *s = &li->samples[i];
			if (!s->line || !s->file) {
				continue;
			}
			ht_sp_insert(files, s->file, NULL);
		}
		// sort them alphabetically
		RzPVector sorter;
		rz_pvector_init(&sorter, free);
		ht_sp_foreach(files, source_file_collect_cb, &sorter);
		rz_pvector_sort(&sorter, (RzPVectorComparator)compare_string, NULL);
		ht_sp_free(files);
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
		RZ_LOG_ERROR("core: Usage: ik [sdb-query]\n");
		RZ_LOG_ERROR("core: Usage: ik*    # load all header information\n");
		return 1;
	}
	return 0;
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

	RzPVector *sections = rz_bin_object_get_sections(o);
	if (!sections) {
		RZ_LOG_ERROR("Cannot retrieve sections\n");
		return RZ_CMD_STATUS_ERROR;
	}

	int cols = rz_cons_get_size(NULL);
	RzList *list = rz_list_newf((RzListFree)rz_listinfo_free);
	if (!list) {
		goto sections_err;
	}

	void **iter;
	RzBinSection *section;
	rz_pvector_foreach (sections, iter) {
		section = *iter;
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
	rz_table_visual_list(table, list, core->offset, 1, cols, core->io->va);

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
	rz_pvector_free(sections);
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

RZ_IPI RzCmdStatus rz_cmd_info_cur_segment_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	RzList *hashes = rz_list_new_from_array((const void **)argv + 1, argc - 1);
	if (!hashes) {
		return RZ_CMD_STATUS_ERROR;
	}
	bool res = rz_core_bin_cur_segment_print(core, bf, state, hashes);
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

RZ_IPI RzCmdStatus rz_cmd_info_purge_string_handler(RzCore *core, int argc, const char **argv) {
	char *strpurge = core->bin->strpurge;
	char tmp[2048];
	rz_config_set(core->config, "bin.str.purge", rz_strf(tmp, "%s%s0x%" PFMT64x, strpurge ? strpurge : "", strpurge && *strpurge ? "," : "", core->offset));
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
	RzPdb *pdb = rz_core_pdb_load_info(core, filename);
	if (!pdb) {
		free(filename);
		return false;
	}
	rz_core_pdb_info_print(core, core->analysis->typedb, pdb, state);
	rz_bin_pdb_free(pdb);
	free(filename);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_pdb_download_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	SPDBOptions pdbopts;
	pdbopts.extract = rz_config_get_i(core->config, "pdb.extract");
	pdbopts.symbol_store_path = rz_config_get(core->config, "pdb.symstore");
	pdbopts.symbol_server = rz_config_get(core->config, "pdb.server");
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_o(state->d.pj);
	}
	int r = rz_bin_pdb_download(core->bin, state->mode == RZ_OUTPUT_MODE_JSON ? state->d.pj : NULL, state->mode == RZ_OUTPUT_MODE_JSON, &pdbopts);
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(state->d.pj);
	}
	if (r > 0 && state->mode != RZ_OUTPUT_MODE_JSON) {
		RZ_LOG_ERROR("Error while downloading pdb file\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_pdb_extract_handler(RzCore *core, int argc, const char **argv) {
	const char *file_cab = argv[1];
	const char *output_dir = argv[2];
	if (!rz_bin_pdb_extract_in_folder(file_cab, output_dir)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

static bool print_demangler_info(const RzDemanglerPlugin *plugin, RzDemanglerFlag flags, void *user) {
	if (!user) {
		rz_cons_printf("%-6s %-8s %s\n", plugin->language, plugin->license, plugin->author);
		return true;
	}
	RzCmdStateOutput *state = (RzCmdStateOutput *)user;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_println(plugin->language);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_ks(state->d.pj, "language", plugin->language);
		pj_ks(state->d.pj, "license", plugin->license);
		pj_ks(state->d.pj, "author", plugin->author);
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "sss", plugin->language, plugin->license, plugin->author);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	return true;
}

RZ_IPI char **rz_cmd_info_demangle_lang_choices(RzCore *core) {
	char **res = RZ_NEWS0(char *, rz_list_length(core->bin->demangler->plugins) + 1);
	if (!res) {
		return NULL;
	}
	const RzDemanglerPlugin *plugin;
	RzListIter *it;
	int i = 0;
	rz_list_foreach (core->bin->demangler->plugins, it, plugin) {
		res[i++] = strdup(plugin->language);
	}
	return res;
}

RZ_IPI RzCmdStatus rz_cmd_info_demangle_handler(RzCore *core, int argc, const char **argv) {
	char *output = NULL;
	if (!rz_demangler_resolve(core->bin->demangler, argv[2], argv[1], &output)) {
		rz_cons_printf("Language '%s' is unsupported\nList of supported languages:\n", argv[1]);
		rz_demangler_plugin_iterate(core->bin->demangler, (RzDemanglerIter)print_demangler_info, NULL);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(output ? output : argv[2]);
	free(output);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_demangle_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "sss", "language", "license", "author");
	rz_demangler_plugin_iterate(core->bin->demangler, (RzDemanglerIter)print_demangler_info, state);
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_info_memory_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	return bool2status(rz_core_bin_memory_print(core, bf, state));
}

RZ_IPI RzCmdStatus rz_cmd_info_resources_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GET_CHECK_CUR_BINFILE(core);
	RzList *hashes = rz_list_new_from_array((const void **)argv + 1, argc - 1);
	if (!hashes) {
		return RZ_CMD_STATUS_ERROR;
	}
	bool res = rz_core_bin_resources_print(core, bf, state, hashes);
	rz_list_free(hashes);
	return bool2status(res);
}

RZ_IPI RzCmdStatus rz_cmd_info_hashes_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut64 limit = rz_config_get_i(core->config, "bin.hashlimit");
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzBinInfo *info = obj ? (RzBinInfo *)rz_bin_object_get_info(obj) : NULL;
	if (!info) {
		RZ_LOG_ERROR("core: Cannot get bin info\n");
		return RZ_CMD_STATUS_ERROR;
	}

	GET_CHECK_CUR_BINFILE(core);

	RzPVector *new_hashes = rz_bin_file_compute_hashes(core->bin, bf, limit);
	if (!new_hashes) {
		RZ_LOG_ERROR("core: Computing file hashes failed\n")
		return RZ_CMD_STATUS_ERROR;
	}
	RzPVector *old_hashes = rz_bin_file_set_hashes(core->bin, new_hashes);
	bool equal = true;
	if (new_hashes && old_hashes && !rz_pvector_empty(new_hashes) && !rz_pvector_empty(old_hashes)) {
		if (!is_equal_file_hashes(new_hashes, old_hashes, &equal)) {
			RZ_LOG_ERROR("core: Cannot compare file hashes\n");
			rz_pvector_free(old_hashes);
			return RZ_CMD_STATUS_ERROR;
		}
	}
	RzBinFileHash *fh_old, *fh_new;
	void **hiter_old, **hiter_new;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		rz_pvector_foreach (new_hashes, hiter_new) {
			fh_new = *hiter_new;
			pj_ks(state->d.pj, fh_new->type, fh_new->hex);
		}
		if (!equal) {
			// print old hashes prefixed with `o` character like `omd5` and `isha1`
			rz_pvector_foreach (old_hashes, hiter_old) {
				fh_old = *hiter_old;
				char *key = rz_str_newf("o%s", fh_old->type);
				pj_ks(state->d.pj, key, fh_old->hex);
				free(key);
			}
		}
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		if (!equal) {
			size_t max_len = RZ_MAX(rz_pvector_len(old_hashes), rz_pvector_len(new_hashes));
			for (int i = 0; i < max_len; i++) {
				fh_new = i < rz_pvector_len(new_hashes) ? (RzBinFileHash *)rz_pvector_at(new_hashes, i) : NULL;
				fh_old = i < rz_pvector_len(old_hashes) ? (RzBinFileHash *)rz_pvector_at(old_hashes, i) : NULL;
				if (fh_new && fh_old && strcmp(fh_new->type, fh_old->type)) {
					RZ_LOG_ERROR("core: Wrong file hashes structure");
				}
				if (fh_new && fh_old && !strcmp(fh_new->hex, fh_old->hex)) {
					fprintf(stderr, "= %s %s\n", fh_new->type, fh_new->hex); // output one line because hash remains same `= hashtype hashval`
				} else {
					// output diff-like two lines, one with old hash val `- hashtype hashval` and one with new `+ hashtype hashval`
					if (fh_old) {
						fprintf(stderr, "- %s %s\n", fh_old->type, fh_old->hex);
					}
					if (fh_new) {
						fprintf(stderr, "+ %s %s\n", fh_new->type, fh_new->hex);
					}
				}
			}
		} else { // hashes are equal
			rz_pvector_foreach (new_hashes, hiter_new) {
				fh_new = *hiter_new;
				rz_cons_printf("%s %s\n", fh_new->type, fh_new->hex);
			}
		}
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	rz_pvector_free(old_hashes);
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
