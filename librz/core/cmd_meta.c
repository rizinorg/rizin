// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_analysis.h"
#include "rz_bin.h"
#include "rz_cons.h"
#include "rz_core.h"
#include "rz_util.h"
#include "rz_types.h"
#include <sdb.h>

#define META_NAME_LENGTH

char *getcommapath(RzCore *core);

RZ_IPI void rz_core_meta_comment_add(RzCore *core, const char *comment, ut64 addr) {
	const char *oldcomment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, addr);
	if (!oldcomment || (oldcomment && !strstr(oldcomment, comment))) {
		rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, addr, comment);
	}
}

inline const char *meta_get_flag(RzCore *core, ut64 addr) {
	RzFlagItem *fi;
	fi = rz_flag_get_i(core->flags, addr);
	return fi ? fi->name : NULL;
}

static void meta_format_print(RzCore *core, ut64 addr, ut64 size, const char *format) {
	const char *fmt = format;
	if (*fmt == '.') {
		const char *realformat = rz_type_db_format_get(core->analysis->typedb, fmt + 1);
		if (realformat) {
			fmt = (char *)realformat;
		} else {
			RZ_LOG_ERROR("Cannot resolve format '%s'\n", fmt + 1);
			return;
		}
	}
	if (size < 1) {
		size = rz_type_format_struct_size(core->analysis->typedb, fmt, 0, 0);
		if (size < 1) {
			eprintf("Warning: Cannot resolve struct size for '%s'\n", fmt);
			size = 32; //
		}
	}
	//make sure we do not overflow on rz_type_format
	if (size > core->blocksize) {
		size = core->blocksize;
	}
	char *fmtstring = rz_type_format_data(core->analysis->typedb, core->print, addr, core->block,
		size, fmt, 0, NULL, NULL);
	if (!fmtstring) {
		size = -1;
	} else {
		rz_cons_print(fmtstring);
		free(fmtstring);
	}
}

static void meta_variable_comment_print(RzCore *Core, RzAnalysisVar *var, RzCmdStateOutput *state) {
	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_o(pj);
		pj_ks(pj, "name", var->name);
		pj_ks(pj, "comment", var->comment);
		pj_end(pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("%s : %s\n", var->name, var->comment);
		break;
	case RZ_OUTPUT_MODE_RIZIN: {
		char *b64 = sdb_encode((const ut8 *)var->comment, strlen(var->comment));
		if (!b64) {
			return;
		}
		rz_cons_printf("\"Cv%c %s base64:%s @ 0x%08" PFMT64x "\"\n", var->kind, var->name, b64, var->fcn->addr);
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
}

static RzCmdStatus meta_variable_comment_list(RzCore *core, RzAnalysisVarKind kind, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		if (var->kind != kind || !var->comment) {
			continue;
		}
		meta_variable_comment_print(core, var, state);
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus meta_variable_comment_list_all(RzCore *core, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		meta_variable_comment_print(core, var, state);
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus meta_variable_comment_append(RzCore *core, const char *name, const char *comment) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	char *heap_comment = NULL;
	if (RZ_STR_ISNOTEMPTY(comment)) { // new comment given
		if (!strncmp(comment, "base64:", 7)) {
			heap_comment = (char *)sdb_decode(comment + 7, NULL);
			comment = heap_comment;
		}
	}
	RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, name);
	if (!var) {
		RZ_LOG_ERROR("Can't find variable named `%s`\n", name);
		return RZ_CMD_STATUS_ERROR;
	}
	if (var->comment) {
		if (comment && *comment) {
			char *text = rz_str_newf("%s\n%s", var->comment, comment);
			free(var->comment);
			var->comment = text;
		} else {
			rz_cons_println(var->comment);
		}
	} else {
		var->comment = strdup(comment);
	}
	free(heap_comment);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus meta_variable_comment_remove(RzCore *core, const char *name) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, name);
	if (!var) {
		RZ_LOG_ERROR("Can't find variable named `%s`\n", name);
		return RZ_CMD_STATUS_ERROR;
	}
	free(var->comment);
	var->comment = NULL;
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus meta_variable_comment_editor(RzCore *core, const char *name) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, name);
	if (!var) {
		RZ_LOG_ERROR("Can't find variable named `%s`\n", name);
		return RZ_CMD_STATUS_ERROR;
	}
	char *comment = rz_core_editor(core, NULL, var->comment);
	if (comment) {
		free(var->comment);
		var->comment = comment;
	}
	return RZ_CMD_STATUS_OK;
}

static bool meta_set_string(RzCore *core, RzAnalysisMetaType mtype, ut64 addr, ut64 size, const char *str) {
	return rz_meta_set(core->analysis, mtype, addr, size, str);
}

static bool meta_set_flag(RzCore *core, RzAnalysisMetaType mtype, ut64 addr, ut64 size, const char *str) {
	const char *flag = meta_get_flag(core, addr);
	return rz_meta_set(core->analysis, mtype, addr, size, flag ? flag : str);
}

static void meta_comment_append(RzCore *core, const char *newcomment, RzAnalysisMetaType mtype, ut64 addr) {
	const char *comment = rz_meta_get_string(core->analysis, mtype, addr);
	char *nc = strdup(newcomment);
	rz_str_unescape(nc);
	if (comment) {
		char *text = rz_str_newf("%s %s", comment, nc);
		if (text) {
			rz_meta_set_string(core->analysis, mtype, addr, text);
			free(text);
		} else {
			rz_sys_perror("malloc");
		}
	} else {
		rz_meta_set_string(core->analysis, mtype, addr, nc);
	}
	free(nc);
}

static void meta_editor(RzCore *core, RzAnalysisMetaType mtype, ut64 addr) {
	const char *comment = rz_meta_get_string(core->analysis, mtype, addr);
	char *out = rz_core_editor(core, NULL, comment);
	if (out) {
		rz_meta_del(core->analysis, mtype, addr, 1);
		rz_meta_set_string(core->analysis, mtype, addr, out);
		free(out);
	}
}

static void meta_remove_all(RzCore *core, RzAnalysisMetaType mtype) {
	rz_meta_del(core->analysis, mtype, 0, UT64_MAX);
}

static void meta_remove(RzCore *core, RzAnalysisMetaType mtype, ut64 addr) {
	rz_meta_del(core->analysis, mtype, addr, 1);
}

static void meta_remove_size(RzCore *core, RzAnalysisMetaType mtype, ut64 addr, ut64 size) {
	rz_meta_del(core->analysis, mtype, addr, size);
}

RZ_IPI RzCmdStatus rz_meta_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_meta_print_list_all(core, RZ_META_TYPE_ANY, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_list_at_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_meta_print_list_at(core, core->offset, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_remove_handler(RzCore *core, int argc, const char **argv) {
	rz_meta_del(core->analysis, RZ_META_TYPE_ANY, core->offset, 1);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_remove_all_handler(RzCore *core, int argc, const char **argv) {
	rz_meta_del(core->analysis, RZ_META_TYPE_ANY, 0, UT64_MAX);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_handler(RzCore *core, int argc, const char **argv) {
	meta_comment_append(core, argv[1], RZ_META_TYPE_COMMENT, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_meta_print_list_all(core, RZ_META_TYPE_COMMENT, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_at_handler(RzCore *core, int argc, const char **argv) {
	const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, core->offset);
	if (comment) {
		rz_cons_println(comment);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_append_handler(RzCore *core, int argc, const char **argv) {
	meta_comment_append(core, argv[1], RZ_META_TYPE_COMMENT, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_remove_handler(RzCore *core, int argc, const char **argv) {
	rz_meta_del(core->analysis, RZ_META_TYPE_COMMENT, core->offset, 1);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_remove_all_handler(RzCore *core, int argc, const char **argv) {
	rz_meta_del(core->analysis, RZ_META_TYPE_COMMENT, UT64_MAX, UT64_MAX);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_filelink_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 1) {
		const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, core->offset);
		if (RZ_STR_ISNOTEMPTY(comment)) {
			// Append filename to the current comment
			char *nc = rz_str_newf("%s ,(%s)", comment, argv[1]);
			rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, core->offset, nc);
			free(nc);
		} else {
			char *newcomment = rz_str_newf(",(%s)", argv[1]);
			rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, core->offset, newcomment);
			free(newcomment);
		}
	} else {
		const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, core->offset);
		if (RZ_STR_ISNOTEMPTY(comment)) {
			char *cmtfile = rz_str_between(comment, ",(", ")");
			if (cmtfile && *cmtfile) {
				char *cwd = getcommapath(core);
				rz_cons_printf("%s" RZ_SYS_DIR "%s\n", cwd, cmtfile);
				free(cwd);
			}
			free(cmtfile);
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_editor_handler(RzCore *core, int argc, const char **argv) {
	meta_editor(core, RZ_META_TYPE_COMMENT, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_function_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_meta_print_list_in_function(core, RZ_META_TYPE_COMMENT, core->offset, state);
	return RZ_CMD_STATUS_OK;
}

static void meta_function_comment_remove(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	RzListIter *iter;
	rz_list_foreach (fcn->bbs, iter, bb) {
		int i;
		for (i = 0; i < bb->size; i++) {
			ut64 addr = bb->addr + i;
			rz_meta_del(analysis, RZ_META_TYPE_COMMENT, addr, 1);
		}
	}
}

RZ_IPI RzCmdStatus rz_comment_function_remove_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	meta_function_comment_remove(core->analysis, fcn);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_function_remove_all_handler(RzCore *core, int argc, const char **argv) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (core->analysis->fcns, it, fcn) {
		meta_function_comment_remove(core->analysis, fcn);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_unique_handler(RzCore *core, int argc, const char **argv) {
	char *comment = NULL;
	if (!strncmp(argv[1], "base64:", 7)) {
		char *s = (char *)sdb_decode(argv[1] + 7, NULL);
		if (s) {
			comment = s;
		}
	} else {
		comment = strdup(argv[1]);
	}
	if (comment) {
		rz_core_meta_comment_add(core, comment, core->offset);
		free(comment);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_space_handler(RzCore *core, int argc, const char **argv) {
	RzSpaces *ms = &core->analysis->meta_spaces;
	rz_spaces_add(ms, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_space_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzSpaces *ms = &core->analysis->meta_spaces;
	spaces_list(ms, state->mode);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_space_rename_handler(RzCore *core, int argc, const char **argv) {
	RzSpaces *ms = &core->analysis->meta_spaces;
	rz_spaces_rename(ms, argv[1], argv[2]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_space_remove_handler(RzCore *core, int argc, const char **argv) {
	RzSpaces *ms = &core->analysis->meta_spaces;
	rz_spaces_unset(ms, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_space_remove_all_handler(RzCore *core, int argc, const char **argv) {
	RzSpaces *ms = &core->analysis->meta_spaces;
	rz_spaces_unset(ms, NULL);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_var_comment_append_handler(RzCore *core, int argc, const char **argv) {
	return meta_variable_comment_append(core, argv[1], argv[2]);
}

RZ_IPI RzCmdStatus rz_meta_var_comment_remove_handler(RzCore *core, int argc, const char **argv) {
	return meta_variable_comment_remove(core, argv[1]);
}

RZ_IPI RzCmdStatus rz_meta_var_comment_editor_handler(RzCore *core, int argc, const char **argv) {
	return meta_variable_comment_editor(core, argv[1]);
}

RZ_IPI RzCmdStatus rz_meta_var_comment_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return meta_variable_comment_list_all(core, state);
}

RZ_IPI RzCmdStatus rz_meta_var_reg_comment_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return meta_variable_comment_list(core, RZ_ANALYSIS_VAR_KIND_REG, state);
}

RZ_IPI RzCmdStatus rz_meta_var_bp_comment_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return meta_variable_comment_list(core, RZ_ANALYSIS_VAR_KIND_BPV, state);
}

RZ_IPI RzCmdStatus rz_meta_var_stack_comment_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return meta_variable_comment_list(core, RZ_ANALYSIS_VAR_KIND_SPV, state);
}

RZ_IPI RzCmdStatus rz_meta_type_current_handler(RzCore *core, int argc, const char **argv) {
	const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_VARTYPE, core->offset);
	if (comment) {
		rz_cons_println(comment);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_data_handler(RzCore *core, int argc, const char **argv) {
	ut64 i, addr = core->offset;
	ut64 size = rz_num_math(core->num, argv[1]);
	ut64 repeat = argc > 2 ? rz_num_math(core->num, argv[2]) : 1;
	if (size == 0 || repeat == 0) {
		RZ_LOG_ERROR("Data size or repeat count cannot be zero");
		return RZ_CMD_STATUS_ERROR;
	}
	for (i = 0; i < repeat; i++, addr += size) {
		meta_set_flag(core, RZ_META_TYPE_DATA, addr, size, argv[1]);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_data_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_meta_print_list_all(core, RZ_META_TYPE_DATA, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_data_at_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = 0;
	RzAnalysisMetaItem *mi = rz_meta_get_at(core->analysis, core->offset, RZ_META_TYPE_DATA, &size);
	if (mi) {
		rz_cons_printf("%" PFMT64u "\n", size);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_data_remove_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 1) {
		ut64 i, addr = core->offset;
		ut64 size = rz_num_math(core->num, argv[1]);
		ut64 repeat = argc > 2 ? rz_num_math(core->num, argv[2]) : 1;
		if (size == 0 || repeat == 0) {
			RZ_LOG_ERROR("Data size or repeat count cannot be zero");
			return RZ_CMD_STATUS_ERROR;
		}
		for (i = 0; i < repeat; i++, addr += size) {
			meta_remove_size(core, RZ_META_TYPE_DATA, addr, size);
		}
	} else {
		meta_remove(core, RZ_META_TYPE_DATA, core->offset);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_data_remove_all_handler(RzCore *core, int argc, const char **argv) {
	meta_remove_all(core, RZ_META_TYPE_DATA);
	return RZ_CMD_STATUS_OK;
}

static bool meta_string_ascii_add(RzCore *core, ut64 addr, size_t limit, ut8 **name, size_t *name_len) {
	rz_return_val_if_fail(limit && name && name_len, false);
	*name = malloc(limit + 1);
	if (!*name) {
		return false;
	}
	if (!rz_io_read_at(core->io, addr, *name, limit)) {
		free(*name);
		return false;
	}
	(*name)[limit] = '\0';
	*name_len = strlen((char *)*name);
	return true;
}

static bool meta_string_guess_add(RzCore *core, ut64 addr, size_t limit, ut8 **name, size_t *name_len, RzDetectedString **ds, RzStrEnc encoding) {
	rz_return_val_if_fail(limit && name && name_len && ds, false);
	*name = malloc(limit + 1);
	if (!*name) {
		return false;
	}
	RzBinFile *bf = rz_bin_cur(core->bin);
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	if (!bf || !obj) {
		free(*name);
		return false;
	}
	bool big_endian = obj ? rz_bin_object_is_big_endian(obj) : RZ_SYS_ENDIAN;
	RzUtilStrScanOptions scan_opt = {
		.buf_size = 2048,
		.max_uni_blocks = 4,
		.min_str_length = 4,
		.prefer_big_endian = big_endian
	};
	RzList *str_list = rz_list_new();
	if (!str_list) {
		free(*name);
		return false;
	}
	ut64 paddr = rz_io_v2p(core->io, addr);
	int count = rz_scan_strings(bf->buf, str_list, &scan_opt, paddr, paddr + limit, encoding);
	if (count <= 0) {
		rz_list_free(str_list);
		free(*name);
		return false;
	}
	*ds = rz_list_first(str_list);
	rz_list_free(str_list);
	rz_str_ncpy(*((char **)name), (*ds)->string, limit);
	(*name)[limit] = '\0';
	return true;
}

static bool meta_string_add(RzCore *core, ut64 addr, ut64 size, RzStrEnc encoding, RZ_NULLABLE const char *name) {
	char *guessname = NULL;
	size_t name_len = 0;
	ut64 limit = size ? size : core->blocksize;
	size_t n = 0;
	if (encoding == RZ_STRING_ENC_LATIN1 || encoding == RZ_STRING_ENC_UTF8) {
		if (!meta_string_ascii_add(core, addr, limit, (ut8 **)&guessname, &name_len)) {
			return false;
		}
		n = size == 0 ? name_len + 1 : size;
	} else {
		RzDetectedString *ds = NULL;
		if (!meta_string_guess_add(core, addr, limit, (ut8 **)&guessname, &name_len, &ds, encoding)) {
			return false;
		}
		if (!ds) {
			return false;
		}
		encoding = ds->type;
		n = ds->size;
	}
	if (!name) {
		return rz_meta_set_with_subtype(core->analysis, RZ_META_TYPE_STRING, encoding, addr, n, guessname);
	}
	return rz_meta_set_with_subtype(core->analysis, RZ_META_TYPE_STRING, encoding, addr, n, name);
}

RZ_IPI RzCmdStatus rz_meta_string_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	if (!meta_string_add(core, core->offset, size, RZ_STRING_ENC_GUESS, NULL)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_meta_print_list_all(core, RZ_META_TYPE_STRING, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_at_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut64 size = 0;
	RzAnalysisMetaItem *mi = rz_meta_get_at(core->analysis, core->offset, RZ_META_TYPE_STRING, &size);
	if (!mi) {
		return RZ_CMD_STATUS_OK;
	}
	rz_core_meta_print(core, mi, core->offset, size, false, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_utf8_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	if (!meta_string_add(core, core->offset, size, RZ_STRING_ENC_UTF8, NULL)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_ascii_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	if (!meta_string_add(core, core->offset, size, RZ_STRING_ENC_LATIN1, NULL)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_wide16_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	bool big_endian = obj ? rz_bin_object_is_big_endian(obj) : RZ_SYS_ENDIAN;
	RzStrEnc enc = big_endian ? RZ_STRING_ENC_UTF16BE : RZ_STRING_ENC_UTF16LE;
	if (!meta_string_add(core, core->offset, size, enc, NULL)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_wide32_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	bool big_endian = obj ? rz_bin_object_is_big_endian(obj) : RZ_SYS_ENDIAN;
	RzStrEnc enc = big_endian ? RZ_STRING_ENC_UTF32BE : RZ_STRING_ENC_UTF32LE;
	if (!meta_string_add(core, core->offset, size, enc, NULL)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_remove_handler(RzCore *core, int argc, const char **argv) {
	meta_remove(core, RZ_META_TYPE_STRING, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_remove_all_handler(RzCore *core, int argc, const char **argv) {
	meta_remove_all(core, RZ_META_TYPE_STRING);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_format_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = rz_num_math(core->num, argv[1]);
	return bool2status(meta_set_string(core, RZ_META_TYPE_FORMAT, core->offset, size, argv[2]));
}

RZ_IPI RzCmdStatus rz_meta_format_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_meta_print_list_all(core, RZ_META_TYPE_FORMAT, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_format_remove_handler(RzCore *core, int argc, const char **argv) {
	meta_remove(core, RZ_META_TYPE_FORMAT, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_format_remove_all_handler(RzCore *core, int argc, const char **argv) {
	meta_remove_all(core, RZ_META_TYPE_FORMAT);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_magic_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = rz_num_math(core->num, argv[1]);
	return bool2status(meta_set_string(core, RZ_META_TYPE_MAGIC, core->offset, size, argv[2]));
}

RZ_IPI RzCmdStatus rz_meta_magic_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_meta_print_list_all(core, RZ_META_TYPE_MAGIC, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_magic_remove_handler(RzCore *core, int argc, const char **argv) {
	meta_remove(core, RZ_META_TYPE_MAGIC, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_magic_remove_all_handler(RzCore *core, int argc, const char **argv) {
	meta_remove_all(core, RZ_META_TYPE_MAGIC);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_hidden_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = rz_num_math(core->num, argv[1]);
	return bool2status(meta_set_flag(core, RZ_META_TYPE_HIDE, core->offset, size, argv[1]));
}

RZ_IPI RzCmdStatus rz_meta_hidden_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_meta_print_list_all(core, RZ_META_TYPE_HIDE, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_hidden_remove_handler(RzCore *core, int argc, const char **argv) {
	meta_remove(core, RZ_META_TYPE_HIDE, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_hidden_remove_all_handler(RzCore *core, int argc, const char **argv) {
	meta_remove_all(core, RZ_META_TYPE_HIDE);
	return RZ_CMD_STATUS_OK;
}

// These commands follow the same pattern
#define RZ_META_COMMAND_DESCRIPTOR(name, type) \
	RZ_IPI RzCmdStatus rz_meta_##name##_handler(RzCore *core, int argc, const char **argv) { \
		meta_set_flag(core, type, core->offset, 1, argv[1]); \
		return RZ_CMD_STATUS_OK; \
	} \
	RZ_IPI RzCmdStatus rz_meta_##name##_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) { \
		rz_core_meta_print_list_all(core, type, state); \
		return RZ_CMD_STATUS_OK; \
	} \
	RZ_IPI RzCmdStatus rz_meta_##name##_remove_handler(RzCore *core, int argc, const char **argv) { \
		meta_remove(core, type, core->offset); \
		return RZ_CMD_STATUS_OK; \
	} \
	RZ_IPI RzCmdStatus rz_meta_##name##_remove_all_handler(RzCore *core, int argc, const char **argv) { \
		meta_remove_all(core, type); \
		return RZ_CMD_STATUS_OK; \
	} \
	RZ_IPI RzCmdStatus rz_meta_##name##_editor_handler(RzCore *core, int argc, const char **argv) { \
		meta_editor(core, type, core->offset); \
		return RZ_CMD_STATUS_OK; \
	}

RZ_META_COMMAND_DESCRIPTOR(type, RZ_META_TYPE_VARTYPE);
RZ_META_COMMAND_DESCRIPTOR(run, RZ_META_TYPE_RUN);
