// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_bin.h>
#include <rz_cons.h>
#include <rz_core.h>
#include <rz_util.h>
#include <rz_types.h>
#include <sdb.h>
#include "../core_private.h"

#define META_NAME_LENGTH

char *getcommapath(RzCore *core);

RZ_IPI void rz_core_meta_comment_add(RzCore *core, const char *comment, ut64 addr) {
	const char *oldcomment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, addr);
	if (!oldcomment || (oldcomment && !strstr(oldcomment, comment))) {
		rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, addr, comment);
	}
}

static const char *meta_get_flag(RzCore *core, ut64 addr) {
	RzFlagItem *fi;
	fi = rz_flag_get_i(core->flags, addr);
	return fi ? fi->name : NULL;
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
		rz_cons_printf("\"Cv%c %s base64:%s @ 0x%08" PFMT64x "\"\n",
			var->storage.type == RZ_ANALYSIS_VAR_STORAGE_REG ? 'r' : 's',
			var->name, b64, var->fcn->addr);
		free(b64);
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
}

static RzCmdStatus meta_variable_comment_list(RzCore *core, RzAnalysisVarStorageType kind, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		if (var->storage.type != kind || !var->comment) {
			continue;
		}
		meta_variable_comment_print(core, var, state);
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus meta_variable_comment_list_all(RzCore *core, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset\n", core->offset);
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
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset\n", core->offset);
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
		free(heap_comment);
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
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset\n", core->offset);
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
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset\n", core->offset);
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
	rz_core_meta_append(core, argv[1], RZ_META_TYPE_COMMENT, core->offset);
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
	rz_core_meta_append(core, argv[1], RZ_META_TYPE_COMMENT, core->offset);
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
	rz_core_meta_editor(core, RZ_META_TYPE_COMMENT, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_comment_function_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_meta_print_list_in_function(core, RZ_META_TYPE_COMMENT, core->offset, state);
	return RZ_CMD_STATUS_OK;
}

static void meta_function_comment_remove(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	void **iter;
	rz_pvector_foreach (fcn->bbs, iter) {
		bb = (RzAnalysisBlock *)*iter;
		for (size_t i = 0; i < bb->size; i++) {
			ut64 addr = bb->addr + i;
			rz_meta_del(analysis, RZ_META_TYPE_COMMENT, addr, 1);
		}
	}
}

RZ_IPI RzCmdStatus rz_comment_function_remove_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find the function at the 0x%08" PFMT64x " offset\n", core->offset);
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
	rz_core_spaces_print(core, ms, state);
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
	return meta_variable_comment_list(core, RZ_ANALYSIS_VAR_STORAGE_REG, state);
}

RZ_IPI RzCmdStatus rz_meta_var_stack_comment_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return meta_variable_comment_list(core, RZ_ANALYSIS_VAR_STORAGE_STACK, state);
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
		RZ_LOG_ERROR("Data size or repeat count cannot be zero\n");
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
			RZ_LOG_ERROR("Data size or repeat count cannot be zero\n");
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

RZ_IPI RzCmdStatus rz_meta_string_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	if (!rz_core_meta_string_add(core, core->offset, size, RZ_STRING_ENC_GUESS, NULL)) {
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

RZ_IPI RzCmdStatus rz_meta_string_pascal_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_core_meta_pascal_string_add(core, core->offset, RZ_STRING_ENC_UTF8, NULL)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_utf8_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	if (!rz_core_meta_string_add(core, core->offset, size, RZ_STRING_ENC_UTF8, NULL)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_8bit_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	if (!rz_core_meta_string_add(core, core->offset, size, RZ_STRING_ENC_8BIT, NULL)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_wide16_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	RzStrEnc enc = big_endian ? RZ_STRING_ENC_UTF16BE : RZ_STRING_ENC_UTF16LE;
	if (!rz_core_meta_string_add(core, core->offset, size, enc, NULL)) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_string_wide32_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	RzStrEnc enc = big_endian ? RZ_STRING_ENC_UTF32BE : RZ_STRING_ENC_UTF32LE;
	if (!rz_core_meta_string_add(core, core->offset, size, enc, NULL)) {
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

RZ_IPI RzCmdStatus rz_meta_type_handler(RzCore *core, int argc, const char **argv) {
	meta_set_flag(core, RZ_META_TYPE_VARTYPE, core->offset, 1, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_type_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_meta_print_list_all(core, RZ_META_TYPE_VARTYPE, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_type_remove_handler(RzCore *core, int argc, const char **argv) {
	meta_remove(core, RZ_META_TYPE_VARTYPE, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_type_remove_all_handler(RzCore *core, int argc, const char **argv) {
	meta_remove_all(core, RZ_META_TYPE_VARTYPE);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_meta_type_editor_handler(RzCore *core, int argc, const char **argv) {
	rz_core_meta_editor(core, RZ_META_TYPE_VARTYPE, core->offset);
	return RZ_CMD_STATUS_OK;
}
