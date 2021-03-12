// SPDX-FileCopyrightText: 2014-2020 dso
// SPDX-FileCopyrightText: 2014-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: Apache-2.0

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_cons.h>
#include <string.h>
#include <rz_analysis.h>

#include "../asm/arch/java/code.h"
#include "../format/java/class.h"
#include "../format/java/print.h"
#include "../format/java/json.h"

#define DO_THE_DBG 0
#undef IFDBG
#define IFDBG if (DO_THE_DBG)

typedef struct found_idx_t {
	ut16 idx;
	ut64 addr;
	const RzBinJavaCPTypeObj *obj;
} RzCmdJavaCPResult;

typedef RzCmdStatus (*RCMDJavaCmdHandler)(RzCore *core, int argc, const char **args);

static RzCmdStatus rz_cmd_java_reload_bin_from_buf(RzCore *core, RzBinJavaObj *obj, ut8 *buffer, ut64 len);

static RzCmdStatus rz_cmd_java_print_json_definitions(RzBinJavaObj *obj);
static RzCmdStatus rz_cmd_java_print_all_definitions(RzAnalysis *analysis);
static RzCmdStatus rz_cmd_java_print_class_definitions(RzBinJavaObj *obj);
static RzCmdStatus rz_cmd_java_print_field_definitions(RzBinJavaObj *obj);
static RzCmdStatus rz_cmd_java_print_method_definitions(RzBinJavaObj *obj);
static RzCmdStatus rz_cmd_java_print_import_definitions(RzBinJavaObj *obj);

static RzCmdStatus rz_cmd_java_resolve_cp_idx(RzBinJavaObj *obj, ut16 idx);
static RzCmdStatus rz_cmd_java_resolve_cp_type(RzBinJavaObj *obj, ut16 idx);
static RzCmdStatus rz_cmd_java_resolve_cp_idx_b64(RzBinJavaObj *obj, ut16 idx);
static RzCmdStatus rz_cmd_java_resolve_cp_address(RzBinJavaObj *obj, ut16 idx);
static RzCmdStatus rz_cmd_java_resolve_cp_to_key(RzBinJavaObj *obj, ut16 idx);
static RzCmdStatus rz_cmd_java_resolve_cp_summary(RzBinJavaObj *obj, ut16 idx);

static RzCmdStatus rz_cmd_java_print_class_access_flags_value(int argc, const char **argv);
static RzCmdStatus rz_cmd_java_print_field_access_flags_value(int argc, const char **argv);
static RzCmdStatus rz_cmd_java_print_method_access_flags_value(int argc, const char **argv);
static RzCmdStatus rz_cmd_java_get_all_access_flags_value(const char *cmd);

static RzCmdStatus rz_cmd_java_set_acc_flags(RzCore *core, ut64 addr, ut16 num_acc_flag);

static RzCmdStatus rz_cmd_java_print_field_summary(RzBinJavaObj *obj, ut16 idx);
static RzCmdStatus rz_cmd_java_print_field_name(RzBinJavaObj *obj, ut16 idx);
static RzCmdStatus rz_cmd_java_print_field_num_name(RzBinJavaObj *obj);
static RzCmdStatus rz_cmd_java_print_method_summary(RzBinJavaObj *obj, ut16 idx);
static RzCmdStatus rz_cmd_java_print_method_name(RzBinJavaObj *obj, ut16 idx);
static RzCmdStatus rz_cmd_java_print_method_num_name(RzBinJavaObj *obj);

static RzBinJavaObj *rz_cmd_java_get_bin_obj(RzAnalysis *analysis);
static RzList *rz_cmd_java_get_bin_obj_list(RzAnalysis *analysis);
static ut64 rz_cmd_java_get_input_num_value(RzCore *core, const char *input_value);
static bool rz_cmd_java_is_valid_input_num_value(RzCore *core, const char *input_value);

static RzCmdStatus rz_cmd_java_handle_help(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_set_flags(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_prototypes(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_resolve_cp(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_calc_flags(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_flags_str(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_flags_str_at(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_field_info(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_method_info(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_find_cp_const(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_summary_info(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_reload_bin(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_print_exceptions(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_isvalid(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_calc_class_sz(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_find_cp_value(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_replace_cp_value(RzCore *core, int argc, const char **argv);
static RzCmdStatus rz_cmd_java_handle_replace_classname_value(RzCore *core, int argc, const char **argv);

static RzList *cpfind_float(RzBinJavaObj *obj, const char *cmd);
static RzList *cpfind_double(RzBinJavaObj *obj, const char *cmd);
static RzList *cpfind_long(RzCore *core, RzBinJavaObj *obj, const char *cmd);
static RzList *cpfind_int(RzCore *core, RzBinJavaObj *obj, const char *cmd);
static RzList *cpfind_str(RzBinJavaObj *obj, const char *cmd);

static RzCmdStatus rz_cmd_java_get_cp_bytes_and_write(RzCore *core, RzBinJavaObj *obj, ut16 idx, ut64 addr, const ut8 *buf, const ut64 len);
static RzCmdStatus rz_cmd_java_handle_replace_cp_value_float(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static RzCmdStatus rz_cmd_java_handle_replace_cp_value_double(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static RzCmdStatus rz_cmd_java_handle_replace_cp_value_long(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static RzCmdStatus rz_cmd_java_handle_replace_cp_value_int(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static RzCmdStatus rz_cmd_java_handle_replace_cp_value_str(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);

static char *rz_cmd_replace_name_def(const char *s_new, ut32 replace_len, const char *s_old, ut32 match_len, const char *buffer, ut32 buf_len, ut32 *res_len);
static char *rz_cmd_replace_name(const char *s_new, ut32 replace_len, const char *s_old, ut32 match_len, const char *buffer, ut32 buf_len, ut32 *res_len);
static bool rz_cmd_is_object_descriptor(const char *name, ut32 name_len);
static ut32 rz_cmd_get_num_classname_str_occ(const char *str, const char *match_me);
static const char *rz_cmd_get_next_classname_str(const char *str, const char *match_me);

typedef struct rz_cmd_java_cms_t {
	const char *name;
	const char *args;
	const char *desc;
	const ut32 name_len;
	RCMDJavaCmdHandler handler;
} RzCmdJavaCmd;

#define SIZESTR(x) (sizeof(x) - 1)

#define CALC_SZ      "calc_sz"
#define CALC_SZ_ARGS " <addr>"
#define CALC_SZ_DESC "calculate class file size at location"
#define CALC_SZ_LEN  SIZESTR(CALC_SZ)

#define ISVALID      "is_valid"
#define ISVALID_ARGS " <addr> <sz>"
#define ISVALID_DESC "check buffer to see if it is a valid class file"
#define ISVALID_LEN  SIZESTR(ISVALID)

#define SET_ACC_FLAGS      "set_flags"
#define SET_ACC_FLAGS_ARGS " <addr> <cfm> <flag string>"
#define SET_ACC_FLAGS_DESC "set the access flags attributes for a field or method"
#define SET_ACC_FLAGS_LEN  SIZESTR(SET_ACC_FLAGS)

#define PROTOTYPES      "prototypes"
#define PROTOTYPES_ARGS " <jaicmf>"
#define PROTOTYPES_DESC "show in JSON, or All,Imports,Class,Methods,Fields"
#define PROTOTYPES_LEN  SIZESTR(PROTOTYPES)

#define RESOLVE_CP      "resolve_cp"
#define RESOLVE_CP_ARGS " <stecadg> <idx>"
#define RESOLVE_CP_DESC "cp type or value @ idx. Summary,Type,b64Encode,Const,Addr,Dump,Gsumarize"
#define RESOLVE_CP_LEN  SIZESTR(RESOLVE_CP)

#define CALC_FLAGS      "calc_flags"
#define CALC_FLAGS_ARGS " <lcfm> <visibility>"
#define CALC_FLAGS_DESC "value from access flags: ListAll, flags, Class, Field, Method"
#define CALC_FLAGS_LEN  SIZESTR(CALC_FLAGS)

#define FLAGS_STR_AT      "flags_str_at"
#define FLAGS_STR_AT_ARGS " <cfm> <addr>"
#define FLAGS_STR_AT_DESC "string value from access flags @ addr: Class, Field, Method"
#define FLAGS_STR_AT_LEN  SIZESTR(FLAGS_STR_AT)

#define FLAGS_STR      "flags_str"
#define FLAGS_STR_ARGS " <cfm> <access>"
#define FLAGS_STR_DESC "string value for the flags number: Class, Field, Method"
#define FLAGS_STR_LEN  SIZESTR(FLAGS_STR)

#define METHOD_INFO      "m_info"
#define METHOD_INFO_ARGS " [c | s <#idx> | n <#idx>]"
#define METHOD_INFO_DESC "method information at index (c:method+ord, s:metadata, n:method)"
#define METHOD_INFO_LEN  SIZESTR(METHOD_INFO)

#define FIELD_INFO      "f_info"
#define FIELD_INFO_ARGS " [c | s <#idx> | n <#idx>]"
#define FIELD_INFO_DESC "field information at index (c:field+ord, s:metadata, n:method)"
#define FIELD_INFO_LEN  SIZESTR(FIELD_INFO)

#define HELP      "help"
#define HELP_DESC "displays this message"
#define HELP_ARGS ""
#define HELP_LEN  SIZESTR(HELP)

#define FIND_CP_CONST      "find_cp_const"
#define FIND_CP_CONST_ARGS " [a | #idx]"
#define FIND_CP_CONST_DESC "find references to constant CP Object in code: AllReferences"
#define FIND_CP_CONST_LEN  SIZESTR(FIND_CP_CONST)

#define FIND_CP_VALUE      "find_cp_value"
#define FIND_CP_VALUE_ARGS " <silfd> <V>"
#define FIND_CP_VALUE_DESC "find references to CP constants by value"
#define FIND_CP_VALUE_LEN  SIZESTR(FIND_CP_VALUE)

#define REPLACE_CP_VALUE      "replace_cp_value"
#define REPLACE_CP_VALUE_ARGS " <idx> <V>"
#define REPLACE_CP_VALUE_DESC "replace CP constants with value if the no resizing is required"
#define REPLACE_CP_VALUE_LEN  SIZESTR(REPLACE_CP_VALUE)

#define REPLACE_CLASS_NAME      "replace_classname_value"
#define REPLACE_CLASS_NAME_ARGS " <c> <nc>"
#define REPLACE_CLASS_NAME_DESC "rename class name" //"replace CP constants with value if no resize needed"
#define REPLACE_CLASS_NAME_LEN  SIZESTR(REPLACE_CLASS_NAME)

#define RELOAD_BIN      "reload_bin"
#define RELOAD_BIN_ARGS " addr"
#define RELOAD_BIN_DESC "reload and reanalyze the Java class file starting at address"
#define RELOAD_BIN_LEN  SIZESTR(RELOAD_BIN)

#define SUMMARY_INFO      "summary"
#define SUMMARY_INFO_ARGS ""
#define SUMMARY_INFO_DESC "print summary information for the current java class file"
#define SUMMARY_INFO_LEN  SIZESTR(SUMMARY_INFO)

#define PRINT_EXC      "exc"
#define PRINT_EXC_ARGS " <addr>"
#define PRINT_EXC_DESC "list all exceptions to fields and methods in code sections"
#define PRINT_EXC_LEN  SIZESTR(PRINT_EXC)

#define END_CMDS (18)

static RzCmdJavaCmd JAVA_CMDS[END_CMDS] = {
	{ HELP, HELP_ARGS, HELP_DESC, HELP_LEN, rz_cmd_java_handle_help },
	{ SET_ACC_FLAGS, SET_ACC_FLAGS_ARGS, SET_ACC_FLAGS_DESC, SET_ACC_FLAGS_LEN, rz_cmd_java_handle_set_flags },
	{ PROTOTYPES, PROTOTYPES_ARGS, PROTOTYPES_DESC, PROTOTYPES_LEN, rz_cmd_java_handle_prototypes },
	{ RESOLVE_CP, RESOLVE_CP_ARGS, RESOLVE_CP_DESC, RESOLVE_CP_LEN, rz_cmd_java_handle_resolve_cp },
	{ CALC_FLAGS, CALC_FLAGS_ARGS, CALC_FLAGS_DESC, CALC_FLAGS_LEN, rz_cmd_java_handle_calc_flags },
	{ FLAGS_STR_AT, FLAGS_STR_AT_ARGS, FLAGS_STR_AT_DESC, FLAGS_STR_AT_LEN, rz_cmd_java_handle_flags_str_at },
	{ FLAGS_STR, FLAGS_STR_ARGS, FLAGS_STR_DESC, FLAGS_STR_LEN, rz_cmd_java_handle_flags_str },
	{ METHOD_INFO, METHOD_INFO_ARGS, METHOD_INFO_DESC, METHOD_INFO_LEN, rz_cmd_java_handle_method_info },
	{ FIELD_INFO, FIELD_INFO_ARGS, FIELD_INFO_DESC, FIELD_INFO_LEN, rz_cmd_java_handle_field_info },
	{ FIND_CP_CONST, FIND_CP_CONST_ARGS, FIND_CP_CONST_DESC, FIND_CP_CONST_LEN, rz_cmd_java_handle_find_cp_const },
	{ FIND_CP_VALUE, FIND_CP_VALUE_ARGS, FIND_CP_VALUE_DESC, FIND_CP_VALUE_LEN, rz_cmd_java_handle_find_cp_value },
	{ REPLACE_CP_VALUE, REPLACE_CP_VALUE_ARGS, REPLACE_CP_VALUE_DESC, REPLACE_CP_VALUE_LEN, rz_cmd_java_handle_replace_cp_value },
	{ REPLACE_CLASS_NAME, REPLACE_CLASS_NAME_ARGS, REPLACE_CLASS_NAME_DESC, REPLACE_CLASS_NAME_LEN, rz_cmd_java_handle_replace_classname_value },
	{ RELOAD_BIN, RELOAD_BIN_ARGS, RELOAD_BIN_DESC, RELOAD_BIN_LEN, rz_cmd_java_handle_reload_bin },
	{ SUMMARY_INFO, SUMMARY_INFO_ARGS, SUMMARY_INFO_DESC, SUMMARY_INFO_LEN, rz_cmd_java_handle_summary_info },
	{ PRINT_EXC, PRINT_EXC_ARGS, PRINT_EXC_DESC, PRINT_EXC_LEN, rz_cmd_java_handle_print_exceptions },
	{ CALC_SZ, CALC_SZ_ARGS, CALC_SZ_DESC, CALC_SZ_LEN, rz_cmd_java_handle_calc_class_sz },
	{ ISVALID, ISVALID_ARGS, ISVALID_DESC, ISVALID_LEN, rz_cmd_java_handle_isvalid }
};

static const char *rz_cmd_get_next_classname_str(const char *str, const char *match_me) {
	const char *result = NULL;
	ut32 len = match_me && *match_me ? strlen(match_me) : 0;
	if (len && str && *str) {
		result = str;
		while (result && *result && (result - str < len)) {
			result = strstr(result, match_me);
			if (result) {
				break;
			}
		}
	}
	return result;
}

static ut32 rz_cmd_get_num_classname_str_occ(const char *str, const char *match_me) {
	const char *result = NULL;
	ut32 len = match_me && *match_me ? strlen(match_me) : 0;
	ut32 occ = 0;

	if (len == 0 || !str || !*str) {
		return 0;
	}
	result = str;
	while (result && *result && (result - str < len)) {
		result = strstr(result, match_me);
		if (result) {
			IFDBG eprintf("result: %s\n", result);
			result += len;
			occ++;
		}
	}
	return occ;
}

static RzAnalysis *get_analysis(RzCore *core) {
	return core ? core->analysis : NULL;
}

const char *help_msg[] = {
	"Usage:", "java [<subcmd>=help [<arg0> [<arg1> ...]]]", "# Suite of java commands",
	HELP, HELP_ARGS, HELP_DESC,
	SET_ACC_FLAGS, SET_ACC_FLAGS_ARGS, SET_ACC_FLAGS_DESC,
	PROTOTYPES, PROTOTYPES_ARGS, PROTOTYPES_DESC,
	RESOLVE_CP, RESOLVE_CP_ARGS, RESOLVE_CP_DESC,
	CALC_FLAGS, CALC_FLAGS_ARGS, CALC_FLAGS_DESC,
	FLAGS_STR_AT, FLAGS_STR_AT_ARGS, FLAGS_STR_AT_DESC,
	FLAGS_STR, FLAGS_STR_ARGS, FLAGS_STR_DESC,
	METHOD_INFO, METHOD_INFO_ARGS, METHOD_INFO_DESC,
	FIELD_INFO, FIELD_INFO_ARGS, FIELD_INFO_DESC,
	FIND_CP_CONST, FIND_CP_CONST_ARGS, FIND_CP_CONST_DESC,
	FIND_CP_VALUE, FIND_CP_VALUE_ARGS, FIND_CP_VALUE_DESC,
	REPLACE_CP_VALUE, REPLACE_CP_VALUE_ARGS, REPLACE_CP_VALUE_DESC,
	REPLACE_CLASS_NAME, REPLACE_CLASS_NAME_ARGS, REPLACE_CLASS_NAME_DESC,
	RELOAD_BIN, RELOAD_BIN_ARGS, RELOAD_BIN_DESC,
	SUMMARY_INFO, SUMMARY_INFO_ARGS, SUMMARY_INFO_DESC,
	PRINT_EXC, PRINT_EXC_ARGS, PRINT_EXC_DESC,
	CALC_SZ, CALC_SZ_ARGS, CALC_SZ_DESC,
	ISVALID, ISVALID_ARGS, ISVALID_DESC,
	NULL
};

static RzCmdStatus rz_cmd_java_handle_help(RzCore *core, int argc, const char **argv) {
	rz_core_cmd_help(core, help_msg);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_handle_prototypes(RzCore *core, int argc, const char **argv) {
	if (!argv || argc != 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzAnalysis *analysis = get_analysis(core);
	RzBinJavaObj *obj = rz_cmd_java_get_bin_obj(analysis);

	if (!obj) {
		eprintf("[-] rz_cmd_java_handle_prototypes: no valid java bins found.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	switch (*(argv[0])) {
	case 'm': return rz_cmd_java_print_method_definitions(obj);
	case 'f': return rz_cmd_java_print_field_definitions(obj);
	case 'i': return rz_cmd_java_print_import_definitions(obj);
	case 'c': return rz_cmd_java_print_class_definitions(obj);
	case 'a': return rz_cmd_java_print_all_definitions(analysis);
	case 'j': return rz_cmd_java_print_json_definitions(obj);
	}
	return RZ_CMD_STATUS_WRONG_ARGS;
}

static RzCmdStatus rz_cmd_java_handle_summary_info(RzCore *core, int argc, const char **argv) {
	if (argv || argc != 0) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzAnalysis *analysis = get_analysis(core);
	RzBinJavaObj *obj = rz_cmd_java_get_bin_obj(analysis);

	if (!obj) {
		eprintf("[-] rz_cmd_java: no valid java bins found.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	rz_cons_printf("Summary for %s:\n", obj->file);
	rz_cons_printf("  Size 0x%d:\n", obj->size);
	rz_cons_printf("  Constants  size: 0x%x count: %d:\n", obj->cp_size, obj->cp_count);
	rz_cons_printf("  Methods    size: 0x%x count: %d:\n", obj->methods_size, obj->methods_count);
	rz_cons_printf("  Fields     size: 0x%x count: %d:\n", obj->fields_size, obj->fields_count);
	rz_cons_printf("  Attributes size: 0x%x count: %d:\n", obj->attrs_size, obj->attrs_count);
	rz_cons_printf("  Interfaces size: 0x%x count: %d:\n", obj->interfaces_size, obj->interfaces_count);

	return RZ_CMD_STATUS_OK;
}

/* Find stuff in the constant pool */
static RzList *cpfind_double(RzBinJavaObj *obj, const char *cmd) {
	double value = cmd && *cmd ? strtod(cmd, NULL) : 0.0;
	if (value == 0.0 && !(cmd && cmd[0] == '0' && cmd[1] == '.' && cmd[2] == '0')) {
		return rz_list_new();
	}
	return rz_bin_java_find_cp_const_by_val(obj, (const ut8 *)&value, 8, RZ_BIN_JAVA_CP_DOUBLE);
}

static RzList *cpfind_float(RzBinJavaObj *obj, const char *cmd) {
	float value = cmd && *cmd ? atof(cmd) : 0.0;
	if (value == 0.0 && !(cmd && cmd[0] == '0' && cmd[1] == '.' && cmd[2] == '0')) {
		return rz_list_new();
	}
	return rz_bin_java_find_cp_const_by_val(obj, (const ut8 *)&value, 4, RZ_BIN_JAVA_CP_FLOAT);
}

static RzList *cpfind_long(RzCore *core, RzBinJavaObj *obj, const char *cmd) {
	ut64 value = rz_cmd_java_get_input_num_value(core, cmd);
	if (!rz_cmd_java_is_valid_input_num_value(core, cmd)) {
		return rz_list_new();
	}
	return rz_bin_java_find_cp_const_by_val(obj, (const ut8 *)&value, 8, RZ_BIN_JAVA_CP_LONG);
}

static RzList *cpfind_int(RzCore *core, RzBinJavaObj *obj, const char *cmd) {
	ut32 value = (ut32)rz_cmd_java_get_input_num_value(core, cmd);
	if (!rz_cmd_java_is_valid_input_num_value(core, cmd)) {
		return rz_list_new();
	}
	return rz_bin_java_find_cp_const_by_val(obj, (const ut8 *)&value, 4, RZ_BIN_JAVA_CP_INTEGER);
}

static RzList *cpfind_str(RzBinJavaObj *obj, const char *cmd) {
	if (!cmd) {
		return rz_list_new();
	}
	IFDBG rz_cons_printf("Looking for str: %s (%zu)\n", cmd, strlen(cmd));
	return rz_bin_java_find_cp_const_by_val(obj, (const ut8 *)cmd, strlen(cmd), RZ_BIN_JAVA_CP_UTF8);
}

static bool is_valid_argument_silfd(const char *b) {
	return (b && (*b == 's' || *b == 'i' || *b == 'l' || *b == 'f' || *b == 'd'));
}

static RzCmdStatus rz_cmd_java_handle_find_cp_value(RzCore *core, int argc, const char **argv) {
	if (!argv || argc != 2 ||
		!is_valid_argument_silfd(argv[0])) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzAnalysis *analysis = get_analysis(core);
	RzBinJavaObj *obj = rz_cmd_java_get_bin_obj(analysis);

	if (!obj) {
		eprintf("[-] rz_cmd_java_handle_find_cp_value: no valid java bins found.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	char f_type = argv[0][0];
	RzList *find_list = NULL;

	switch (f_type) {
	case 's':
		find_list = cpfind_str(obj, argv[1]);
		break;
	case 'i':
		find_list = cpfind_int(core, obj, argv[1]);
		break;
	case 'l':
		find_list = cpfind_long(core, obj, argv[1]);
		break;
	case 'f':
		find_list = cpfind_float(obj, argv[1]);
		break;
	case 'd':
		find_list = cpfind_double(obj, argv[1]);
		break;
	default:
		eprintf("[-] rz_cmd_java: invalid java type to search for.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	if (!find_list) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzListIter *iter;
	ut32 *idx;
	rz_list_foreach (find_list, iter, idx) {
		ut64 addr = rz_bin_java_resolve_cp_idx_address(obj, (ut16)*idx);
		rz_cons_printf("Offset: 0x%" PFMT64x " idx: %d\n", addr, *idx);
	}
	rz_list_free(find_list);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_reload_bin_from_buf(RzCore *core, RzBinJavaObj *obj, ut8 *buffer, ut64 len) {
	if (!buffer || len < 10) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	if (rz_bin_java_load_bin(obj, buffer, len)) {
		RzBinPlugin *tmp;
		RzListIter *iter;
		rz_list_foreach (core->bin->plugins, iter, tmp) {
			if (!strncmp("java", tmp->name, 4)) {
				return RZ_CMD_STATUS_OK;
			}
		}
	}
	return RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus rz_cmd_java_get_cp_bytes_and_write(RzCore *core, RzBinJavaObj *obj, ut16 idx, ut64 addr, const ut8 *buf, const ut64 len) {
	if (!obj) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzBinJavaCPTypeObj *cp_obj = rz_bin_java_get_item_from_bin_cp_list(obj, idx);
	ut64 c_file_sz = rz_io_size(core->io);
	ut32 n_sz = 0, c_sz = rz_bin_java_cp_get_size(obj, idx);
	ut8 *bytes = NULL;

	bytes = rz_bin_java_cp_get_bytes(cp_obj->tag, &n_sz, buf, len);

	if (n_sz < c_sz) {
		if (!rz_core_shift_block(core, addr + c_sz, 0, (int)n_sz - (int)c_sz)) {
			RZ_FREE(bytes);
			return RZ_CMD_STATUS_ERROR;
		} else if (!rz_io_resize(core->io, c_file_sz + (int)n_sz - (int)c_sz)) {
			RZ_FREE(bytes);
			return RZ_CMD_STATUS_ERROR;
		}
	} else if (n_sz > c_sz) {
		if (!rz_core_extend_at(core, addr, (int)n_sz - (int)c_sz)) {
			RZ_FREE(bytes);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		eprintf("[X] rz_cmd_java_get_cp_bytes_and_write: Failed to resize the file correctly aborting.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	if (n_sz > 0 && bytes) {
		bool res = rz_core_write_at(core, addr, (const ut8 *)bytes, n_sz) && rz_core_seek(core, addr, true);
		if (!res) {
			eprintf("[X] rz_cmd_java_get_cp_bytes_and_write: Failed to write the bytes to the file correctly aborting.\n");
			return RZ_CMD_STATUS_ERROR;
		}
	}

	RZ_FREE(bytes);

	RzCmdStatus res = RZ_CMD_STATUS_OK;
	ut64 n_file_sz = 0;
	ut8 *bin_buffer = NULL;
	res = rz_io_use_fd(core->io, core->file->fd);
	n_file_sz = rz_io_size(core->io);
	bin_buffer = n_file_sz > 0 ? malloc(n_file_sz) : NULL;
	if (bin_buffer) {
		memset(bin_buffer, 0, n_file_sz);
		if (n_file_sz != rz_io_read_at(core->io, obj->loadaddr, bin_buffer, n_file_sz)) {
			eprintf("[X] rz_cmd_java_get_cp_bytes_and_write: Failed to read the file in aborted, bin reload.\n");
			res = RZ_CMD_STATUS_ERROR;
		} else if (rz_cmd_java_reload_bin_from_buf(core, obj, bin_buffer, n_file_sz) != RZ_CMD_STATUS_OK) {
			eprintf("[X] rz_cmd_java_get_cp_bytes_and_write: Failed to reload the binary.\n");
			res = RZ_CMD_STATUS_ERROR;
		}
		free(bin_buffer);
	}
	return res;
}

// TODO: fix endianness on these methods
static RzCmdStatus rz_cmd_java_handle_replace_cp_value_float(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	float value = cmd && *cmd ? atof(cmd) : 0.0;
	bool res = rz_cmd_java_get_cp_bytes_and_write(core, obj, idx, addr, (ut8 *)&value, 4);
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus rz_cmd_java_handle_replace_cp_value_double(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	double value = cmd && *cmd ? strtod(cmd, NULL) : 0.0;
	bool res = rz_cmd_java_get_cp_bytes_and_write(core, obj, idx, addr, (ut8 *)&value, 8);
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus rz_cmd_java_handle_replace_cp_value_long(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	ut64 value = rz_cmd_java_get_input_num_value(core, cmd);
	bool res = rz_cmd_java_get_cp_bytes_and_write(core, obj, idx, addr, (ut8 *)&value, 8);
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus rz_cmd_java_handle_replace_cp_value_int(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	ut32 value = (ut32)rz_cmd_java_get_input_num_value(core, cmd);
	bool res = rz_cmd_java_get_cp_bytes_and_write(core, obj, idx, addr, (ut8 *)&value, 4);
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus rz_cmd_java_handle_replace_cp_value_str(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	bool res = false;
	ut32 len = cmd && *cmd ? strlen(cmd) : 0;
	if (len > 0 && cmd && *cmd == '"') {
		cmd++;
		len = cmd && *cmd ? strlen(cmd) : 0;
	}
	if (cmd && len > 0) {
		res = rz_cmd_java_get_cp_bytes_and_write(core, obj, idx, addr, (ut8 *)cmd, len);
	}
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus rz_cmd_java_handle_replace_cp_value(RzCore *core, int argc, const char **argv) {
	if (!argv || argc != 2 || !rz_cmd_java_is_valid_input_num_value(core, argv[0])) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzAnalysis *analysis = get_analysis(core);
	RzBinJavaObj *obj = rz_cmd_java_get_bin_obj(analysis);

	if (!obj) {
		eprintf("[-] rz_cmd_java_handle_replace_cp_value: no valid java bins found.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	ut16 idx = rz_cmd_java_get_input_num_value(core, argv[0]);
	ut64 addr = 0;
	char cp_type = 0;

	cp_type = rz_bin_java_resolve_cp_idx_tag(obj, idx);
	addr = rz_bin_java_resolve_cp_idx_address(obj, idx);

	switch (cp_type) {
	case RZ_BIN_JAVA_CP_UTF8:
		return rz_cmd_java_handle_replace_cp_value_str(core, obj, argv[1], idx, addr);
	case RZ_BIN_JAVA_CP_INTEGER:
		return rz_cmd_java_handle_replace_cp_value_int(core, obj, argv[1], idx, addr);
	case RZ_BIN_JAVA_CP_LONG:
		return rz_cmd_java_handle_replace_cp_value_long(core, obj, argv[1], idx, addr);
	case RZ_BIN_JAVA_CP_FLOAT:
		return rz_cmd_java_handle_replace_cp_value_float(core, obj, argv[1], idx, addr);
	case RZ_BIN_JAVA_CP_DOUBLE:
		return rz_cmd_java_handle_replace_cp_value_double(core, obj, argv[1], idx, addr);
	default:
		eprintf("[-] rz_cmd_java: invalid java type to search for.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

static char *rz_cmd_replace_name_def(const char *s_new, ut32 replace_len, const char *s_old, ut32 match_len, const char *buffer, ut32 buf_len, ut32 *res_len) {
	const char *fmt = "L%s;";
	char *s_new_ref = s_new && replace_len > 0 ? malloc(3 + replace_len) : NULL;
	char *s_old_ref = s_old && match_len > 0 ? malloc(3 + match_len) : NULL;
	char *result = NULL;
	*res_len = 0;
	if (s_new_ref && s_old_ref) {
		snprintf(s_new_ref, replace_len + 3, fmt, s_new);
		snprintf(s_old_ref, match_len + 3, fmt, s_old);
		result = rz_cmd_replace_name(s_new_ref, replace_len + 2, s_old_ref, match_len + 2, buffer, buf_len, res_len);
	}
	free(s_new_ref);
	free(s_old_ref);
	return result;
}

static bool rz_cmd_is_object_descriptor(const char *name, ut32 name_len) {
	bool found_L = false, found_Semi = false;
	ut32 idx = 0, L_pos = 0, Semi_pos = 0;
	const char *p_name = name;

	for (idx = 0, L_pos = 0; idx < name_len; idx++, p_name++) {
		if (*p_name == 'L') {
			found_L = true;
			L_pos = idx;
			break;
		}
	}

	for (idx = 0, Semi_pos = 0; idx < name_len; idx++, p_name++) {
		if (*p_name == ';') {
			found_Semi = true;
			Semi_pos = idx;
			break;
		}
	}

	return found_L == found_Semi && found_L && L_pos < Semi_pos;
}

static char *rz_cmd_replace_name(const char *s_new, ut32 replace_len, const char *s_old, ut32 match_len, const char *buffer, ut32 buf_len, ut32 *res_len) {
	ut32 num_occurrences = 0, i = 0;
	char *result = NULL, *p_result = NULL;

	num_occurrences = rz_cmd_get_num_classname_str_occ(buffer, s_old);
	*res_len = 0;
	if (num_occurrences > 0 && replace_len > 0 && s_old) {
		ut32 consumed = 0;
		const char *next = rz_cmd_get_next_classname_str(buffer + consumed, s_old);
		IFDBG rz_cons_printf("Replacing \"%s\" with \"%s\" in: %s\n", s_old, s_new, buffer);
		result = malloc(num_occurrences * replace_len + buf_len);
		memset(result, 0, num_occurrences * replace_len + buf_len);
		p_result = result;
		while (next && consumed < buf_len) {
			// replace up to next
			IFDBG rz_cons_printf("next: \"%s\", len to: %" PFMTDPTR "\n", next, (ptrdiff_t)(next - buffer));
			for (; buffer + consumed < next && consumed < buf_len; consumed++, p_result++) {
				*p_result = *(buffer + consumed);
				(*res_len)++;
			}

			for (i = 0; i < replace_len; i++, p_result++) {
				*p_result = *(s_new + i);
				(*res_len)++;
			}
			consumed += match_len;
			next = rz_cmd_get_next_classname_str(buffer + consumed, s_old);
		}
		IFDBG rz_cons_printf("Found last occurrence of: \"%s\", remaining: %s\n", s_old, buffer + consumed);
		IFDBG rz_cons_printf("result is: \"%s\"\n", result);
		for (; consumed < buf_len; consumed++, p_result++, (*res_len)++) {
			*p_result = *(buffer + consumed);
		}
		IFDBG rz_cons_printf("Old: %s\nNew: %s\n", buffer, result);
	}
	return result;
}

static RzCmdStatus rz_cmd_java_handle_replace_classname_value(RzCore *core, int argc, const char **argv) {
	if (!argv || argc != 2) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	const char *old_class = argv[0];
	const char *new_class = argv[1];

	size_t old_size = strlen(old_class);
	size_t new_size = strlen(new_class);

	if (old_size < 1 || new_size < 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzAnalysis *analysis = get_analysis(core);
	RzBinJavaObj *obj = rz_cmd_java_get_bin_obj(analysis);

	if (!obj) {
		eprintf("[-] rz_cmd_java_handle_replace_classname_value: no valid java bins found.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	for (ut16 idx = 1; idx <= obj->cp_count; idx++) {
		RzBinJavaCPTypeObj *cp_obj = rz_bin_java_get_item_from_bin_cp_list(obj, idx);

		if (cp_obj && cp_obj->tag == RZ_BIN_JAVA_CP_UTF8 &&
			cp_obj->info.cp_utf8.length && cp_obj->info.cp_utf8.length >= old_size - 1) {
			ut32 num_occurrences = 0;
			ut64 addr = cp_obj->file_offset + cp_obj->loadaddr;
			ut32 buffer_sz = 0;
			ut8 *buffer = rz_bin_java_cp_get_idx_bytes(obj, idx, &buffer_sz);

			if (!buffer) {
				continue;
			}
			ut16 name_size = rz_read_at_be16(buffer, 1);
			char *name = malloc(name_size + 3);
			memcpy(name, buffer + 3, name_size);
			name[name_size] = 0;

			num_occurrences = rz_cmd_get_num_classname_str_occ(name, old_class);

			if (num_occurrences > 0) {
				// perform inplace replacement
				ut32 res_len = 0;
				char *result = NULL;

				if (rz_cmd_is_object_descriptor(name, name_size)) {
					result = rz_cmd_replace_name_def(new_class,
						new_size - 1, old_class,
						old_size - 1, name, name_size, &res_len);
				} else {
					result = rz_cmd_replace_name(new_class,
						new_size - 1, old_class,
						old_size - 1, name, name_size, &res_len);
				}
				if (result) {
					if (!rz_cmd_java_get_cp_bytes_and_write(core, obj, idx, addr,
						    (const ut8 *)result, res_len)) {
						eprintf("ERROR: rz_cmd_java: Failed to write bytes or reload the binary.\n");
					}
				}
				free(result);
			}
			free(buffer);
			free(name);
		}
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_handle_reload_bin(RzCore *core, int argc, const char **argv) {
	if (!argv || argc != 1 ||
		!rz_cmd_java_is_valid_input_num_value(core, argv[0])) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzAnalysis *analysis = get_analysis(core);
	RzBinJavaObj *obj = rz_cmd_java_get_bin_obj(analysis);
	if (!obj) {
		eprintf("[-] rz_cmd_java_handle_reload_bin: no valid java bins found.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	ut64 addr = 0LL;
	ut64 buf_size = 0;
	ut8 *buf = NULL;
	bool res = false;

	addr = rz_cmd_java_get_input_num_value(core, argv[0]);
	if (!rz_io_use_fd(core->io, core->file->fd)) {
		eprintf("ERROR: rz_cmd_java_handle_reload_bin: Failed to use rz_io_use_fd.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	buf_size = rz_io_size(core->io);
	buf = malloc(buf_size);
	if (!buf) {
		eprintf("ERROR: rz_cmd_java_handle_reload_bin: Failed buffer allocation.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	memset(buf, 0, buf_size);
	rz_io_read_at(core->io, addr, buf, buf_size);
	res = rz_cmd_java_reload_bin_from_buf(core, obj, buf, buf_size);
	free(buf);
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus rz_cmd_java_handle_find_cp_const(RzCore *core, int argc, const char **argv) {
	if (!argv || argc != 1 ||
		(!rz_cmd_java_is_valid_input_num_value(core, argv[0]) && argv[0][0] != 'a')) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzAnalysis *analysis = get_analysis(core);
	RzBinJavaObj *obj = rz_cmd_java_get_bin_obj(analysis);
	if (!obj) {
		eprintf("[-] rz_cmd_java_handle_find_cp_const: no valid java bins found.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	RzAnalysisFunction *fcn = NULL;
	RzAnalysisBlock *bb = NULL;
	RzListIter *bb_iter, *fn_iter, *iter;
	RzCmdJavaCPResult *cp_res = NULL;
	RzList *find_list;

	bool user_index = argv[0][0] != 'a';
	ut16 idx = 0, tmpidx = 0;

	if (user_index) {
		idx = rz_cmd_java_get_input_num_value(core, argv[0]);
		if (idx == 0) {
			eprintf("[-] rz_cmd_java_handle_find_cp_const: invalid CP Obj Index Supplied.\n");
			return RZ_CMD_STATUS_ERROR;
		}
	}

	find_list = rz_list_new();
	if (!find_list) {
		eprintf("[-] rz_cmd_java_handle_find_cp_const: Bad allocation of rz_list_new.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	find_list->free = free;

	rz_list_foreach (core->analysis->fcns, fn_iter, fcn) {
		rz_list_foreach (fcn->bbs, bb_iter, bb) {
			cp_res = NULL;
			switch (bb->op_bytes[0]) {
			case 0x12: // bytes: ldc index
				tmpidx = bb->op_bytes[1];
				break;
			case 0x13: // bytes: ldc_w  indexbyte1, indexbyte2
			case 0x14: // bytes: ldc2_w indexbyte1, indexbyte2
				tmpidx = rz_read_at_be16(bb->op_bytes, 1);
				break;
			default:
				break;
			}
			if (!user_index || tmpidx == idx) {
				cp_res = RZ_NEW0(RzCmdJavaCPResult);
				if (cp_res) {
					cp_res->idx = tmpidx;
					cp_res->addr = bb->addr;
					cp_res->obj = rz_bin_java_get_item_from_cp(obj, cp_res->idx);
					rz_list_append(find_list, cp_res);
				}
			}
		}
	}
	if (user_index) {
		rz_list_foreach (find_list, iter, cp_res) {
			const char *t = ((RzBinJavaCPTypeMetas *)cp_res->obj->metas->type_info)->name;
			rz_cons_printf("@0x%" PFMT64x " idx = %d Type = %s\n", cp_res->addr, cp_res->idx, t);
		}
	} else {
		rz_list_foreach (find_list, iter, cp_res) {
			rz_cons_printf("@0x%" PFMT64x "\n", cp_res->addr);
		}
	}
	rz_list_free(find_list);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_handle_field_info(RzCore *core, int argc, const char **argv) {
	if (!argv || (argc != 1 && argc != 2)) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	} else if (argc == 2 && !rz_cmd_java_is_valid_input_num_value(core, argv[0])) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzAnalysis *analysis = get_analysis(core);
	RzBinJavaObj *obj = rz_cmd_java_get_bin_obj(analysis);
	if (!obj) {
		eprintf("[-] rz_cmd_java_handle_field_info: no valid java bins found.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	ut16 idx = rz_cmd_java_get_input_num_value(core, argc > 1 ? argv[1] : NULL);

	switch (*(argv[0])) {
	case 'c':
		return rz_cmd_java_print_field_num_name(obj);
	case 's':
		return rz_cmd_java_print_field_summary(obj, idx);
	case 'n':
		return rz_cmd_java_print_field_name(obj, idx);
	default:
		break;
	}
	return RZ_CMD_STATUS_WRONG_ARGS;
}

static RzCmdStatus rz_cmd_java_handle_method_info(RzCore *core, int argc, const char **argv) {
	if (!argv || (argc != 1 && argc != 2)) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	} else if (argc == 2 && !rz_cmd_java_is_valid_input_num_value(core, argv[0])) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzAnalysis *analysis = get_analysis(core);
	RzBinJavaObj *obj = rz_cmd_java_get_bin_obj(analysis);
	if (!obj) {
		eprintf("[-] rz_cmd_java_handle_method_info: no valid java bins found.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	ut16 idx = rz_cmd_java_get_input_num_value(core, argc > 1 ? argv[1] : NULL);

	switch (*(argv[0])) {
	case 'c':
		return rz_cmd_java_print_method_num_name(obj);
	case 's':
		return rz_cmd_java_print_method_summary(obj, idx);
	case 'n':
		return rz_cmd_java_print_method_name(obj, idx);
	default:
		break;
	}
	return RZ_CMD_STATUS_WRONG_ARGS;
}

static RzCmdStatus rz_cmd_java_handle_calc_class_sz(RzCore *core, int argc, const char **argv) {
	if (!argv || argc != 1 ||
		!rz_cmd_java_is_valid_input_num_value(core, argv[0])) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	bool res = false;
	ut64 res_size = UT64_MAX;
	ut64 file_size = rz_io_fd_size(core->io, rz_core_file_cur(core)->fd);
	ut8 *tbuf = NULL;
	ut8 *buf = NULL;
	ut32 def_size = (1 << 16);
	ut64 addr = rz_cmd_java_get_input_num_value(core, argv[0]);
	ut64 alloc_size = file_size < def_size ? file_size : def_size;

	while (alloc_size <= file_size) {
		tbuf = realloc(buf, alloc_size);
		if (!tbuf) {
			eprintf("Memory allocation failed.\n");
			break;
		}
		buf = tbuf;
		ut64 read_size = rz_io_read_at(core->io, addr, buf, alloc_size) ? alloc_size : 0LL;
		// check the return read on the read
		if (!read_size) {
			break;
		}
		res_size = rz_bin_java_calc_class_size(buf, alloc_size);
		// if the data buffer contains a class starting
		// at address, then the res_size will be the size
		// if the read_size is less than the alloc_size,
		// then we are near the end of the core buffer,
		// and there is no need to continue trying to find
		// the class size.
		if (res_size != UT64_MAX || read_size < alloc_size) {
			res = read_size < alloc_size ? false : true;
			break;
		} else {
			alloc_size += def_size;
		}
	}
	free(buf);
	if (res) {
		rz_cons_printf("%" PFMT64d, res_size);
	} else {
		rz_cons_printf("-1\n");
	}
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus rz_cmd_java_handle_isvalid(RzCore *core, int argc, const char **argv) {
	if (!argv || argc != 2 ||
		!rz_cmd_java_is_valid_input_num_value(core, argv[0]) ||
		!rz_cmd_java_is_valid_input_num_value(core, argv[1])) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	ut64 res_size = UT64_MAX;
	ut64 file_size = rz_io_fd_size(core->io, rz_core_file_cur(core)->fd);
	ut64 addr = rz_cmd_java_get_input_num_value(core, argv[0]);
	ut64 alloc_size = rz_cmd_java_get_input_num_value(core, argv[0]);

	// The header of a java class is at least 10 bytes.
	if (alloc_size < 10) {
		eprintf("size has to be at least 10.\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	} else if (alloc_size > file_size) {
		eprintf("size (0x%" PFMT64x ") exceeds file size (0x%" PFMT64x ").\n", alloc_size, file_size);
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	ut8 *buf = malloc(alloc_size);
	if (!buf) {
		eprintf("Memory allocation failed.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	if (rz_io_read_at(core->io, addr, buf, alloc_size)) {
		res_size = rz_bin_java_calc_class_size(buf, alloc_size);
	}
	free(buf);
	rz_cons_printf("%s\n", rz_str_bool(res_size != UT64_MAX));
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_handle_resolve_cp(RzCore *core, int argc, const char **argv) {
	if (!argv || argc != 2) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	RzAnalysis *analysis = get_analysis(core);
	RzBinJavaObj *obj = rz_cmd_java_get_bin_obj(analysis);

	if (!obj) {
		eprintf("[-] rz_cmd_java_handle_resolve_cp: no valid java bins found.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	char c_type = *(argv[0]);
	ut32 idx = rz_cmd_java_get_input_num_value(core, argv[1]);

	IFDBG rz_cons_printf("Function call made: %s %s\n", argv[0], argv[1]);
	IFDBG rz_cons_printf("Ctype: %d (%c) RzBinJavaObj points to: %p and the idx is (%s): %d\n", c_type, c_type, obj, argv[1], idx);

	if (idx > 0) {
		switch (c_type) {
		case 't': return rz_cmd_java_resolve_cp_type(obj, idx);
		case 'c': return rz_cmd_java_resolve_cp_idx(obj, idx);
		case 'e': return rz_cmd_java_resolve_cp_idx_b64(obj, idx);
		case 'a': return rz_cmd_java_resolve_cp_address(obj, idx);
		case 's': return rz_cmd_java_resolve_cp_summary(obj, idx);
		case 'k': return rz_cmd_java_resolve_cp_to_key(obj, idx);
		}
	} else if (c_type == 'g') {
		for (idx = 1; idx <= obj->cp_count; idx++) {
			ut64 addr = rz_bin_java_resolve_cp_idx_address(obj, idx);
			char *str = rz_bin_java_resolve_cp_idx_type(obj, idx);
			if (str) {
				rz_cons_printf("CP_OBJ Type %d =  %s @ 0x%" PFMT64x "\n", idx, str, addr);
				free(str);
			}
		}
	} else if (c_type == 'd') {
		for (idx = 1; idx <= obj->cp_count; idx++) {
			rz_cmd_java_resolve_cp_summary(obj, idx);
		}
	} else {
		eprintf("[-] rz_cmd_java_handle_resolve_cp: invalid cp index given, must idx > 1.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_get_all_access_flags_value(const char *cmd) {
	RzList *list = NULL;
	char ccmd = *(cmd);

	switch (ccmd) {
	case 'f':
		list = retrieve_all_field_access_string_and_value();
		break;
	case 'm':
		list = retrieve_all_method_access_string_and_value();
		break;
	case 'c':
		list = retrieve_all_class_access_string_and_value();
		break;
	default:
		break;
	}

	if (!list) {
		eprintf("[-] rz_cmd_java_get_all_access_flags_value: incorrect syntax for the flags calculation.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	switch (ccmd) {
	case 'f':
		rz_cons_printf("[=] Fields Access Flags List\n");
		break;
	case 'm':
		rz_cons_printf("[=] Methods Access Flags List\n");
		break;
	case 'c':
		rz_cons_printf("[=] Class Access Flags List\n");
		break;
	}

	RzListIter *iter = NULL;
	char *str = NULL;
	rz_list_foreach (list, iter, str) {
		rz_cons_println(str);
	}
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_handle_calc_flags(RzCore *core, int argc, const char **argv) {
	if (argc < 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	switch (*(argv[0])) {
	case 'f':
		if (argc < 2) {
			return RZ_CMD_STATUS_WRONG_ARGS;
		}
		return rz_cmd_java_print_field_access_flags_value(argc - 1, &argv[1]);
	case 'm':
		if (argc < 2) {
			return RZ_CMD_STATUS_WRONG_ARGS;
		}
		return rz_cmd_java_print_method_access_flags_value(argc - 1, &argv[1]);
	case 'c':
		if (argc < 2) {
			return RZ_CMD_STATUS_WRONG_ARGS;
		}
		return rz_cmd_java_print_class_access_flags_value(argc - 1, &argv[1]);
	case 'l':
		if (argc > 1) {
			return rz_cmd_java_get_all_access_flags_value(argv[1]);
		} else {
			rz_cmd_java_get_all_access_flags_value("c");
			rz_cmd_java_get_all_access_flags_value("m");
			rz_cmd_java_get_all_access_flags_value("f");
		}
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus flags_str_address(const char *mcf, ut64 flag_value) {
	const char *flags_title = NULL;
	char *flags_string = NULL;

	switch (*(mcf)) {
	case 'm':
		flags_title = "Method Access Flags String:";
		flags_string = retrieve_method_access_string(flag_value);
		break;
	case 'f':
		flags_title = "Field Access Flags String:";
		flags_string = retrieve_field_access_string(flag_value);
		break;
	case 'c':
		flags_title = "Class Access Flags String:";
		flags_string = retrieve_class_method_access_string(flag_value);
		break;
	default:
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	if (!flags_string) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%s %s\n", flags_title, flags_string);
	free(flags_string);
	return RZ_CMD_STATUS_OK;
}

static bool is_valid_argument_mcf(const char *b) {
	return (b && (*b == 'c' || *b == 'f' || *b == 'm'));
}

static RzCmdStatus rz_cmd_java_handle_flags_str(RzCore *core, int argc, const char **argv) {
	if (!argv || argc != 2 ||
		!is_valid_argument_mcf(argv[0]) ||
		!rz_cmd_java_is_valid_input_num_value(core, argv[1])) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	ut64 flag_value = rz_cmd_java_get_input_num_value(core, argv[1]);
	return flags_str_address(argv[0], flag_value);
}

static RzCmdStatus rz_cmd_java_handle_flags_str_at(RzCore *core, int argc, const char **argv) {
	if (!argv || argc != 2 ||
		!is_valid_argument_mcf(argv[0]) ||
		!rz_cmd_java_is_valid_input_num_value(core, argv[1])) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	ut8 buffer[2] = { 0 };
	ut64 cur_offset = core->offset;
	ut64 flag_value_addr = rz_cmd_java_get_input_num_value(core, argv[1]);

	rz_io_read_at(core->io, flag_value_addr, buffer, 2);
	if (cur_offset != core->offset) {
		rz_core_seek(core, cur_offset - 2, true);
	}

	ut16 flag_value = rz_read_be16(buffer);
	return flags_str_address(argv[0], flag_value);
}

static RzCmdStatus rz_cmd_java_handle_set_flags(RzCore *core, int argc, const char **argv) {
	if (!argv || argc != 3 ||
		!rz_cmd_java_is_valid_input_num_value(core, argv[0]) ||
		!is_valid_argument_mcf(argv[1])) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	ut64 addr = rz_cmd_java_get_input_num_value(core, argv[0]);
	char f_type = *(argv[1]);
	ut16 flag_value = 0;

	eprintf("addr: %08llx f_type: %c flag_value %04x\n", addr, f_type, flag_value);
	if (!addr) {
		eprintf("[-] rz_cmd_java: invalid address.\n");
		return false;
	} else if (flag_value == 16 && f_type == 'f') {
		eprintf("[-] rz_cmd_java: invalid flag (%c) value (%04x).\n", f_type, flag_value);
		return false;
	}

	if (f_type) {
		switch (f_type) {
		case 'f':
			flag_value = rz_bin_java_calculate_field_access_value(argv[2]);
			break;
		case 'm':
			flag_value = rz_bin_java_calculate_method_access_value(argv[2]);
			break;
		case 'c':
			flag_value = rz_bin_java_calculate_class_access_value(argv[2]);
			break;
		default:
			return false;
		}
	}

	if (flag_value > 0) {
		return rz_cmd_java_set_acc_flags(core, addr, (ut16)flag_value);
	}
	eprintf("[-] rz_cmd_java: invalid flag value or type provided .\n");
	return RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus print_list_with_address(RzList *list, RzList *offsets, const char *padding) {
	if (!list || !offsets) {
		rz_list_free(list);
		rz_list_free(offsets);
		return RZ_CMD_STATUS_ERROR;
	}

	if (!padding) {
		padding = "";
	}

	char *str = NULL;
	ut32 end = rz_list_length(list);

	for (ut32 idx = 0; idx < end; idx++) {
		ut64 *addr = rz_list_get_n(offsets, idx);
		str = rz_list_get_n(list, idx);
		rz_cons_printf("%s%s; // @0x%04" PFMT64x "\n", padding, str, *addr);
	}

	rz_list_free(list);
	rz_list_free(offsets);

	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_print_method_definitions(RzBinJavaObj *obj) {
	RzList *list = rz_bin_java_get_method_definitions(obj);
	RzList *offsets = rz_bin_java_get_method_offsets(obj);

	return print_list_with_address(list, offsets, NULL);
}

static RzCmdStatus rz_cmd_java_print_field_definitions(RzBinJavaObj *obj) {
	RzList *list = rz_bin_java_get_field_definitions(obj);
	RzList *offsets = rz_bin_java_get_field_offsets(obj);

	return print_list_with_address(list, offsets, NULL);
}

static RzCmdStatus rz_cmd_java_print_import_definitions(RzBinJavaObj *obj) {
	RzList *list = rz_bin_java_get_import_definitions(obj);
	if (!list) {
		return RZ_CMD_STATUS_ERROR;
	}

	char *str = NULL;
	RzListIter *iter;
	rz_list_foreach (list, iter, str) {
		rz_cons_printf("import %s;\n", str);
	}
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_print_all_definitions(RzAnalysis *analysis) {
	RzList *list = rz_cmd_java_get_bin_obj_list(analysis);
	if (!list) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzListIter *iter;
	RzBinJavaObj *obj;
	rz_list_foreach (list, iter, obj) {
		rz_cmd_java_print_class_definitions(obj);
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_print_json_definitions(RzBinJavaObj *obj) {
	PJ *pj = pj_new();
	if (!pj || !rz_bin_java_get_bin_obj_json(obj, pj)) {
		pj_free(pj);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(pj_string(pj));
	pj_free(pj);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_print_class_definitions(RzBinJavaObj *obj) {
	RzList *fields = rz_bin_java_get_field_definitions(obj);
	RzList *methods = rz_bin_java_get_method_definitions(obj);
	RzList *moffsets = rz_bin_java_get_method_offsets(obj);
	RzList *foffsets = rz_bin_java_get_field_offsets(obj);
	char *class_name = rz_bin_java_get_this_class_name(obj);

	RzCmdStatus ret = RZ_CMD_STATUS_OK;

	if (!fields || !methods || !moffsets || !foffsets || !class_name) {
		ret = RZ_CMD_STATUS_ERROR;
		goto print_class_definitions_error;
	}

	ret = rz_cmd_java_print_import_definitions(obj);
	if (ret != RZ_CMD_STATUS_OK) {
		goto print_class_definitions_error;
	}

	rz_cons_printf("\nclass %s { // @0x%04" PFMT64x "\n", class_name, obj->loadaddr);

	if (rz_list_length(fields) > 0) {
		rz_cons_printf("\n  // Fields defined in the class\n");
		print_list_with_address(fields, foffsets, "  ");
	}

	if (rz_list_length(methods) > 0) {
		rz_cons_printf("\n  // Methods defined in the class\n");
		print_list_with_address(methods, moffsets, "  ");
	}
	rz_cons_printf("}\n");

	free(class_name);
	return RZ_CMD_STATUS_OK;

print_class_definitions_error:
	rz_list_free(fields);
	rz_list_free(methods);
	rz_list_free(foffsets);
	rz_list_free(moffsets);
	free(class_name);
	return ret;
}

static RzList *rz_cmd_java_get_bin_obj_list(RzAnalysis *analysis) {
	RzBinJavaObj *obj = rz_cmd_java_get_bin_obj(analysis);
	return rz_bin_java_get_bin_obj_list_thru_obj(obj);
}

static RzBinJavaObj *rz_cmd_java_get_bin_obj(RzAnalysis *analysis) {
	RzBin *b;
	RzBinPlugin *plugin;
	if (!analysis || !analysis->binb.bin) {
		return NULL;
	}
	b = analysis->binb.bin;
	if (!b->cur || !b->cur->o) {
		return NULL;
	}
	plugin = b->cur->o->plugin;
	return (plugin && strcmp(plugin->name, "java") == 0) ? b->cur->o->bin_obj : NULL;
}

static RzCmdStatus rz_cmd_java_resolve_cp_idx(RzBinJavaObj *obj, ut16 idx) {
	rz_return_val_if_fail(obj && idx, RZ_CMD_STATUS_ERROR);

	char *str = rz_bin_java_resolve_without_space(obj, idx);
	if (!str) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(str);
	free(str);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_resolve_cp_type(RzBinJavaObj *obj, ut16 idx) {
	rz_return_val_if_fail(obj && idx, RZ_CMD_STATUS_ERROR);

	char *str = rz_bin_java_resolve_cp_idx_type(obj, idx);
	if (!str) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(str);
	free(str);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_resolve_cp_idx_b64(RzBinJavaObj *obj, ut16 idx) {
	rz_return_val_if_fail(obj && idx, RZ_CMD_STATUS_ERROR);
	char *str = rz_bin_java_resolve_b64_encode(obj, idx);
	if (!str) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(str);
	free(str);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_resolve_cp_address(RzBinJavaObj *obj, ut16 idx) {
	rz_return_val_if_fail(obj && idx, RZ_CMD_STATUS_ERROR);
	ut64 addr = rz_bin_java_resolve_cp_idx_address(obj, idx);
	if (addr == (ut64)-1) {
		rz_cons_printf("Unable to resolve CP Object @ index: 0x%04x\n", idx);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("0x%" PFMT64x "\n", addr);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_resolve_cp_to_key(RzBinJavaObj *obj, ut16 idx) {
	rz_return_val_if_fail(obj && idx, RZ_CMD_STATUS_ERROR);
	char *str = rz_bin_java_resolve_cp_idx_to_string(obj, idx);
	if (!str) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(str);
	free(str);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_resolve_cp_summary(RzBinJavaObj *obj, ut16 idx) {
	rz_return_val_if_fail(obj && idx, RZ_CMD_STATUS_ERROR);
	bool res = rz_bin_java_summary_resolve_cp_idx_print(obj, idx);
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

static bool rz_cmd_java_is_valid_input_num_value(RzCore *core, const char *input_value) {
	ut64 value = input_value ? rz_num_math(core->num, input_value) : 0;
	return !(value == 0 && input_value && *input_value == '0');
}

static ut64 rz_cmd_java_get_input_num_value(RzCore *core, const char *input_value) {
	ut64 value = input_value ? rz_num_math(core->num, input_value) : 0;
	return value;
}

static RzCmdStatus rz_cmd_java_print_class_access_flags_value(int argc, const char **argv) {
	RzStrBuf *sb = rz_strbuf_new(argv[0]);
	if (!sb) {
		return RZ_CMD_STATUS_ERROR;
	}
	for (int i = 1; i < argc; ++i) {
		rz_strbuf_appendf(sb, " %s", argv[i]);
	}
	char *flags = rz_strbuf_drain(sb);
	ut16 result = rz_bin_java_calculate_class_access_value(flags);
	rz_cons_printf("Access Value for %s = 0x%04x\n", flags, result);
	free(flags);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_print_field_access_flags_value(int argc, const char **argv) {
	RzStrBuf *sb = rz_strbuf_new(argv[0]);
	if (!sb) {
		return RZ_CMD_STATUS_ERROR;
	}
	for (int i = 1; i < argc; ++i) {
		rz_strbuf_appendf(sb, " %s", argv[i]);
	}
	char *flags = rz_strbuf_drain(sb);
	ut16 result = rz_bin_java_calculate_field_access_value(flags);
	rz_cons_printf("Access Value for %s = 0x%04x\n", flags, result);
	free(flags);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_print_method_access_flags_value(int argc, const char **argv) {
	RzStrBuf *sb = rz_strbuf_new(argv[0]);
	if (!sb) {
		return RZ_CMD_STATUS_ERROR;
	}
	for (int i = 1; i < argc; ++i) {
		rz_strbuf_appendf(sb, " %s", argv[i]);
	}
	char *flags = rz_strbuf_drain(sb);
	ut16 result = rz_bin_java_calculate_method_access_value(flags);
	rz_cons_printf("Access Value for %s = 0x%04x\n", flags, result);
	free(flags);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_set_acc_flags(RzCore *core, ut64 addr, ut16 num_acc_flag) {
	num_acc_flag = rz_read_at_be16(((ut8 *)&num_acc_flag), 0);
	if (!rz_core_write_at(core, addr, (const ut8 *)&num_acc_flag, 2)) {
		eprintf("[X] rz_cmd_java_set_acc_flags: Failed to write.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

static inline RzCmdStatus print_list_newline(RzList *list) {
	if (!list) {
		return RZ_CMD_STATUS_ERROR;
	}
	char *str;
	RzListIter *iter = NULL;
	rz_list_foreach (list, iter, str) {
		rz_cons_println(str);
	}
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_print_field_num_name(RzBinJavaObj *obj) {
	RzList *list = rz_bin_java_get_field_num_name(obj);
	return print_list_newline(list);
}

static RzCmdStatus rz_cmd_java_print_method_num_name(RzBinJavaObj *obj) {
	RzList *list = rz_bin_java_get_method_num_name(obj);
	return print_list_newline(list);
}

static RzCmdStatus rz_cmd_java_print_field_summary(RzBinJavaObj *obj, ut16 idx) {
	if (!rz_bin_java_summary_print_field_idx(obj, idx)) {
		eprintf("Error: Field @ index (%d) not found in the RzBinJavaObj.\n", idx);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_print_field_name(RzBinJavaObj *obj, ut16 idx) {
	char *field_name = rz_bin_java_get_field_name(obj, idx);
	if (field_name) {
		rz_cons_println(field_name);
		free(field_name);
	} else {
		eprintf("Error: Field @ index (%d) not found in the RzBinJavaObj.\n", idx);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_print_method_summary(RzBinJavaObj *obj, ut16 idx) {
	if (!rz_bin_java_summary_print_method_idx(obj, idx)) {
		eprintf("Error: Method @ index (%d) not found in the RzBinJavaObj.\n", idx);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_print_method_name(RzBinJavaObj *obj, ut16 idx) {
	char *method_name = rz_bin_java_get_method_name(obj, idx);
	if (method_name) {
		rz_cons_println(method_name);
		free(method_name);
	} else {
		eprintf("Error: Method @ index (%d) not found in the RzBinJavaObj.\n", idx);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus rz_cmd_java_handle_print_exceptions(RzCore *core, int argc, const char **argv) {
	if (!argv || argc != 1 ||
		!rz_cmd_java_is_valid_input_num_value(core, argv[0])) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzAnalysis *analysis = get_analysis(core);
	RzBinJavaObj *obj = rz_cmd_java_get_bin_obj(analysis);

	if (!obj) {
		eprintf("[-] rz_cmd_java: no valid java bins found.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	RzListIter *exc_iter = NULL, *methods_iter = NULL;
	RzBinJavaField *method;
	RzList *exc_table = NULL;
	RzBinJavaExceptionEntry *exc_entry;
	ut64 func_addr = rz_cmd_java_get_input_num_value(core, argv[0]);

	rz_list_foreach (obj->methods_list, methods_iter, method) {
		ut64 start = rz_bin_java_get_method_start(obj, method);
		ut64 end = rz_bin_java_get_method_end(obj, method);

		ut8 do_this_one = start <= func_addr && func_addr <= end;
		if (!do_this_one) {
			continue;
		}
		exc_table = rz_bin_java_get_method_exception_table_with_addr(obj, start);

		if (rz_list_length(exc_table) == 0) {
			rz_cons_printf(" Exception table for %s @ 0x%" PFMT64x ":\n", method->name, start);
			rz_cons_printf(" [ NONE ]\n");
		} else {
			rz_cons_printf(" Exception table for %s (%d entries) @ 0x%" PFMT64x ":\n", method->name,
				rz_list_length(exc_table), start);
		}
		rz_list_foreach (exc_table, exc_iter, exc_entry) {
			char *class_info = rz_bin_java_resolve_without_space(obj, exc_entry->catch_type);
			rz_cons_printf("  Catch Type: %d, %s @ 0x%" PFMT64x "\n", exc_entry->catch_type,
				class_info, exc_entry->file_offset + 6);
			rz_cons_printf("  Start PC: (0x%x) 0x%" PFMT64x " @ 0x%" PFMT64x "\n",
				exc_entry->start_pc, exc_entry->start_pc + start, exc_entry->file_offset);
			rz_cons_printf("  End PC: (0x%x) 0x%" PFMT64x " 0x%" PFMT64x "\n",
				exc_entry->end_pc, exc_entry->end_pc + start, exc_entry->file_offset + 2);
			rz_cons_printf("  Handler PC: (0x%x) 0x%" PFMT64x " 0x%" PFMT64x "\n",
				exc_entry->handler_pc, exc_entry->handler_pc + start, exc_entry->file_offset + 4);
			free(class_info);
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_java_handler(RzCore *core, int argc, const char **argv) {
	if (argc < 2) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	for (int i = 0; i < END_CMDS; i++) {
		if (!strncmp(argv[1], JAVA_CMDS[i].name, JAVA_CMDS[i].name_len)) {
			return JAVA_CMDS[i].handler(core, argc - 2, argc > 2 ? &argv[2] : NULL);
		}
	}
	return RZ_CMD_STATUS_WRONG_ARGS;
}

static const char *cmd_java_subcmd_choices[] = { "help", "set_flags", "prototypes", "resolve_cp", "calc_flags", "flags_str_at", "flags_str", "m_info", "f_info", "find_cp_const", "find_cp_value", "replace_cp_value", "replace_classname_value", "reload_bin", "summary", "exc", "calc_sz", "is_valid", NULL };
static const RzCmdDescArg cmd_java_args[3] = {
	{
		.name = "subcmd",
		.type = RZ_CMD_ARG_TYPE_CHOICES,
		.default_value = "help",
		.choices = cmd_java_subcmd_choices,
	},
	{
		.name = "arg",
		.type = RZ_CMD_ARG_TYPE_STRING,
		.flags = RZ_CMD_ARG_FLAG_ARRAY,
		.optional = true,
	},
	{ 0 },
};

static const RzCmdDescHelp cmd_java_help = {
	.summary = "Suite of java commands",
	.description = "Type `java help` for more commands.",
	.args = cmd_java_args,
};

static bool rz_cmd_java_init_handler(RzCore *core) {
	RzCmd *cmd = core->rcmd;
	RzCmdDesc *root_cd = rz_cmd_get_root(cmd);
	if (!root_cd) {
		return false;
	}

	RzCmdDesc *cmd_java_cd = rz_cmd_desc_argv_new(cmd, root_cd, "java", rz_cmd_java_handler, &cmd_java_help);
	rz_warn_if_fail(cmd_java_cd);
	return cmd_java_cd != NULL;
}

// PLUGIN Definition Info
RzCorePlugin rz_core_plugin_java = {
	.name = "java",
	.desc = "Suite of java commands, java help for more info",
	.author = "RizinOrg",
	.license = "Apache",
	.init = rz_cmd_java_init_handler,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_java,
	.version = RZ_VERSION
};
#endif
