/* radare - Apache - Copyright 2014-2019 - dso, pancake */

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_cons.h>
#include <string.h>
#include <rz_anal.h>

#include "../../../shlr/java/ops.h"
#include "../../../shlr/java/class.h"
#include "../../../shlr/java/code.h"
#include "../../../shlr/java/dsojson.h"

#define DO_THE_DBG 0
#undef IFDBG
#define IFDBG if (DO_THE_DBG)


typedef struct found_idx_t {
	ut16 idx;
	ut64 addr;
	const RzBinJavaCPTypeObj *obj;
} RzCmdJavaCPResult;

typedef int (*RCMDJavaCmdHandler) (RzCore *core, const char *cmd);

static const char * rz_cmd_java_strtok (const char *str1, const char b, size_t len);
static const char * rz_cmd_java_consumetok (const char *str1, const char b, size_t len);
static int rz_cmd_java_reload_bin_from_buf (RzCore *core, RzBinJavaObj *obj, ut8* buffer, ut64 len);

static int rz_cmd_java_print_json_definitions( RzBinJavaObj *obj  );
static int rz_cmd_java_print_all_definitions( RzAnal *anal );
static int rz_cmd_java_print_class_definitions( RzBinJavaObj *obj );
static int rz_cmd_java_print_field_definitions( RzBinJavaObj *obj );
static int rz_cmd_java_print_method_definitions( RzBinJavaObj *obj );
static int rz_cmd_java_print_import_definitions( RzBinJavaObj *obj );

static int rz_cmd_java_resolve_cp_idx (RzBinJavaObj *obj, ut16 idx);
static int rz_cmd_java_resolve_cp_type (RzBinJavaObj *obj, ut16 idx);
static int rz_cmd_java_resolve_cp_idx_b64 (RzBinJavaObj *obj, ut16 idx);
static int rz_cmd_java_resolve_cp_address (RzBinJavaObj *obj, ut16 idx);
static int rz_cmd_java_resolve_cp_to_key (RzBinJavaObj *obj, ut16 idx);
static int rz_cmd_java_resolve_cp_summary (RzBinJavaObj *obj, ut16 idx);

static int rz_cmd_java_print_class_access_flags_value( const char * flags );
static int rz_cmd_java_print_field_access_flags_value( const char * flags );
static int rz_cmd_java_print_method_access_flags_value( const char * flags );
static int rz_cmd_java_get_all_access_flags_value (const char *cmd);

static int rz_cmd_java_set_acc_flags (RzCore *core, ut64 addr, ut16 num_acc_flag);

#define _(x) UNUSED_FUNCTION(x)
static int rz_cmd_java_print_field_summary (RzBinJavaObj *obj, ut16 idx);
static int _(rz_cmd_java_print_field_count) (RzBinJavaObj *obj);
static int rz_cmd_java_print_field_name (RzBinJavaObj *obj, ut16 idx);
static int rz_cmd_java_print_field_num_name (RzBinJavaObj *obj);
static int rz_cmd_java_print_method_summary (RzBinJavaObj *obj, ut16 idx);
static int _(rz_cmd_java_print_method_count) (RzBinJavaObj *obj);
static int rz_cmd_java_print_method_name (RzBinJavaObj *obj, ut16 idx);
static int rz_cmd_java_print_method_num_name (RzBinJavaObj *obj);

static RzBinJavaObj * rz_cmd_java_get_bin_obj(RzAnal *anal);
static RzList * rz_cmd_java_get_bin_obj_list(RzAnal *anal);
static ut64 rz_cmd_java_get_input_num_value(RzCore *core, const char *input_value);
static int rz_cmd_java_is_valid_input_num_value(RzCore *core, const char *input_value);


static int rz_cmd_java_call(void *user, const char *input);
static int rz_cmd_java_handle_help(RzCore * core, const char * input);
static int rz_cmd_java_handle_set_flags(RzCore *core, const char *cmd);
static int rz_cmd_java_handle_prototypes(RzCore *core, const char *cmd);
static int rz_cmd_java_handle_resolve_cp(RzCore *core, const char *cmd);
static int rz_cmd_java_handle_calc_flags(RzCore *core, const char *cmd);
static int rz_cmd_java_handle_flags_str(RzCore *core, const char *cmd);
static int rz_cmd_java_handle_flags_str_at(RzCore *core, const char *cmd);
static int rz_cmd_java_handle_field_info(RzCore *core, const char *cmd);
static int rz_cmd_java_handle_method_info(RzCore *core, const char *cmd);

static int rz_cmd_java_handle_find_cp_const(RzCore *core, const char *cmd);

static RzList *cpfind_float(RzBinJavaObj *obj, const char *cmd);
static RzList *cpfind_double(RzBinJavaObj *obj, const char *cmd);
static RzList *cpfind_long(RzCore *core, RzBinJavaObj *obj, const char *cmd);
static RzList *cpfind_int(RzCore *core, RzBinJavaObj *obj, const char *cmd);
static RzList *cpfind_str(RzBinJavaObj *obj, const char *cmd);

static int cpfind(RzCore *core, const char *cmd);

static int rz_cmd_java_get_cp_bytes_and_write(RzCore *core, RzBinJavaObj *obj, ut16 idx, ut64 addr, const ut8 *buf, const ut64 len);
static int rz_cmd_java_handle_replace_cp_value_float(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static int rz_cmd_java_handle_replace_cp_value_double(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static int rz_cmd_java_handle_replace_cp_value_long(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static int rz_cmd_java_handle_replace_cp_value_int(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static int rz_cmd_java_handle_replace_cp_value_str(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr);
static int rz_cmd_java_handle_replace_cp_value(RzCore *core, const char *cmd);

static int rz_cmd_java_handle_replace_classname_value(RzCore *core, const char *cmd);
static char *rz_cmd_replace_name_def(const char *s_new, ut32 replace_len, const char *s_old, ut32 match_len, const char *buffer, ut32 buf_len, ut32 *res_len);
static char *rz_cmd_replace_name(const char *s_new, ut32 replace_len, const char *s_old, ut32 match_len, const char *buffer, ut32 buf_len, ut32 *res_len);
static int rz_cmd_is_object_descriptor(const char *name, ut32 name_len);
static ut32 rz_cmd_get_num_classname_str_occ(const char *str, const char *match_me);
static const char *rz_cmd_get_next_classname_str(const char *str, const char *match_me);

static int rz_cmd_java_handle_summary_info(RzCore *core, const char *cmd);
static int rz_cmd_java_handle_reload_bin(RzCore *core, const char *cmd);

static int rz_cmd_java_handle_print_exceptions(RzCore *core, const char *input);
static int rz_cmd_java_handle_insert_method_ref(RzCore *core, const char *input);
static int rz_cmd_java_handle_yara_code_extraction_refs(RzCore *core, const char *input);

static int rz_cmd_java_handle_isvalid(RzCore *core, const char *cmd);
static int rz_cmd_java_handle_calc_class_sz(RzCore *core, const char *cmd);

typedef struct rz_cmd_java_cms_t {
	const char *name;
	const char *args;
	const char *desc;
	const ut32 name_len;
	RCMDJavaCmdHandler handler;
} RzCmdJavaCmd;

/* XXX : Most of those command arguments are absurd, must be reviewed + changed */

#define CALC_SZ "calc_sz"
#define CALC_SZ_ARGS " <addr>"
#define CALC_SZ_DESC "calculate class file size at location"
#define CALC_SZ_LEN 7

#define ISVALID "is_valid"
#define ISVALID_ARGS " <addr> <sz>"
#define ISVALID_DESC "check buffer to see if it is a valid class file"
#define ISVALID_LEN 8

#define SET_ACC_FLAGS "set_flags"
#define SET_ACC_FLAGS_ARGS " [addr cmf <value>]" //[<addr> <c | m | f> <num_flag_val>] | [<addr> < c | m | f> <flag value separated by space> ]"
#define SET_ACC_FLAGS_DESC "set the access flags attributes for a field or method"
#define SET_ACC_FLAGS_LEN 9

#define PROTOTYPES "prototypes"
#define PROTOTYPES_ARGS " <jaicmf>" // < j | a | i | c | m | f>
#define PROTOTYPES_DESC "show in JSON, or All,Imports,Class,Methods,Fields"
#define PROTOTYPES_LEN 10

#define RESOLVE_CP "resolve_cp"
#define RESOLVE_CP_ARGS " [<stecadg> idx]"
#define RESOLVE_CP_DESC "cp type or value @ idx. Summary,Type,b64Encode,Const,Addr,Dump,Gsumarize"
//d = dump all,  g = summarize all, s = summary, a = address, t = type, c = get value, e = base64 enode the result"
#define RESOLVE_CP_LEN 10

#define CALC_FLAGS "calc_flags"
#define CALC_FLAGS_ARGS " <lcfm> [visib.]"
//[ <l <[c|f|m]>> | <c [public,private,static...]>  | <f [public,private,static...]> | <m c [public,private,static...]>]"
#define CALC_FLAGS_DESC "value from access flags: ListAll, flags, Class, Field, Method"
#define CALC_FLAGS_LEN 10

#define FLAGS_STR_AT "flags_str_at"
#define FLAGS_STR_AT_ARGS " <cfm> [addr]"
#define FLAGS_STR_AT_DESC "string value from access flags @ addr: Class, Field, Method"
#define FLAGS_STR_AT_LEN 12

#define FLAGS_STR "flags_str"
#define FLAGS_STR_ARGS " [<cfm> <access>]" //acc_flags_value>]"
#define FLAGS_STR_DESC "string value for the flags number: Class, Field, Method"
#define FLAGS_STR_LEN 9

#define METHOD_INFO "m_info"
#define METHOD_INFO_ARGS " [<p,c,s idx> | <n idx>]"
//#define METHOD_INFO_DESC "method index info: c = dump methods and ord , s = dump of all meta-data, n = method"
#define METHOD_INFO_DESC "method information at index (c:method+ord, s:metadata)"
#define METHOD_INFO_LEN 6

#define FIELD_INFO "f_info"
#define FIELD_INFO_ARGS " [<p,c,s idx> | #idx]"
#define FIELD_INFO_DESC "field information at index (c:field+ord, s:metadata)"
// : c = dump field and ord , s = dump of all meta-data, n = method"
#define FIELD_INFO_LEN 6

#define HELP "help"
#define HELP_DESC "displays this message"
#define HELP_ARGS ""
#define HELP_LEN 4

#define FIND_CP_CONST "find_cp_const"
#define FIND_CP_CONST_ARGS " [a|#idx]"
#define FIND_CP_CONST_DESC "find references to constant CP Object in code: AllReferences"
#define FIND_CP_CONST_LEN 13

#define FIND_CP_VALUE "find_cp_value"
#define FIND_CP_VALUE_ARGS " [<silfd> V]"
#define FIND_CP_VALUE_DESC "find references to CP constants by value"
#define FIND_CP_VALUE_LEN 13

#define REPLACE_CP_VALUE "replace_cp_value"
#define REPLACE_CP_VALUE_ARGS " [<idx> V]"
#define REPLACE_CP_VALUE_DESC "replace CP constants with value if the no resizing is required"
#define REPLACE_CP_VALUE_LEN 16

#define REPLACE_CLASS_NAME "replace_classname_value"
#define REPLACE_CLASS_NAME_ARGS " <c> <nc>"
#define REPLACE_CLASS_NAME_DESC "rename class name" //"replace CP constants with value if no resize needed"
#define REPLACE_CLASS_NAME_LEN 23

#define RELOAD_BIN "reload_bin"
#define RELOAD_BIN_ARGS " addr [size]"
#define RELOAD_BIN_DESC "reload and reanalyze the Java class file starting at address"
#define RELOAD_BIN_LEN 10

#define SUMMARY_INFO "summary"
#define SUMMARY_INFO_ARGS ""
#define SUMMARY_INFO_DESC "print summary information for the current java class file"
#define SUMMARY_INFO_LEN 7

#define LIST_CODE_REFS "lcr"
#define LIST_CODE_REFS_ARGS " [addr]"
#define LIST_CODE_REFS_DESC "list all references to fields and methods in code sections"
#define LIST_CODE_REFS_LEN 3

#define PRINT_EXC "exc"
#define PRINT_EXC_ARGS " [<addr>]"
#define PRINT_EXC_DESC "list all exceptions to fields and methods in code sections"
#define PRINT_EXC_LEN 3

#define YARA_CODE_REFS "yc_w_refs"
#define YARA_CODE_REFS_ARGS " [name] [start] [count]"
#define YARA_CODE_REFS_DESC "yara code bytes extraction with a name starting at <start> to <count>"
#define YARA_CODE_REFS_LEN 9

#define INSERT_MREF "i_mref"
#define INSERT_MREF_ARGS " C M S" //<meth> <desc>" //descriptor in form of (Lpref;)Lref;"
#define INSERT_MREF_DESC "add Method to Class with given method signature" //append a method reference CP object to the end of the CP object array (creates all requisite objects)"
#define INSERT_MREF_LEN 6

static RzCmdJavaCmd JAVA_CMDS[] = {
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
	{ FIND_CP_VALUE, FIND_CP_VALUE_ARGS, FIND_CP_VALUE_DESC, FIND_CP_VALUE_LEN, cpfind },
	{ REPLACE_CP_VALUE, REPLACE_CP_VALUE_ARGS, REPLACE_CP_VALUE_DESC, REPLACE_CP_VALUE_LEN, rz_cmd_java_handle_replace_cp_value },
	{ REPLACE_CLASS_NAME, REPLACE_CLASS_NAME_ARGS, REPLACE_CLASS_NAME_DESC, REPLACE_CLASS_NAME_LEN, rz_cmd_java_handle_replace_classname_value },
	{ RELOAD_BIN, RELOAD_BIN_ARGS, RELOAD_BIN_DESC, RELOAD_BIN_LEN, rz_cmd_java_handle_reload_bin },
	{ SUMMARY_INFO, SUMMARY_INFO_ARGS, SUMMARY_INFO_DESC, SUMMARY_INFO_LEN, rz_cmd_java_handle_summary_info },
	{ PRINT_EXC, PRINT_EXC_ARGS, PRINT_EXC_DESC, PRINT_EXC_LEN, rz_cmd_java_handle_print_exceptions },
	{ YARA_CODE_REFS, YARA_CODE_REFS_ARGS, YARA_CODE_REFS_DESC, YARA_CODE_REFS_LEN, rz_cmd_java_handle_yara_code_extraction_refs },
	{ INSERT_MREF, INSERT_MREF_ARGS, INSERT_MREF_DESC, INSERT_MREF_LEN, rz_cmd_java_handle_insert_method_ref },
	{ CALC_SZ, CALC_SZ_ARGS, CALC_SZ_DESC, CALC_SZ_LEN, rz_cmd_java_handle_calc_class_sz },
	{ ISVALID, ISVALID_ARGS, ISVALID_DESC, ISVALID_LEN, rz_cmd_java_handle_isvalid },
};

enum {
	HELP_IDX = 0,
	SET_ACC_FLAGS_IDX = 1,
	PROTOTYPES_IDX = 2,
	RESOLVE_CP_IDX = 3,
	CALC_FLAGS_IDX = 4,
	FLAGS_STR_AT_IDX = 5,
	FLAGS_STR_IDX = 6,
	METHOD_INFO_IDX = 7,
	FIELD_INFO_IDX = 8,
	FIND_CP_CONST_IDX = 9,
	FIND_CP_VALUE_IDX = 10,
	REPLACE_CP_VALUE_IDX = 11,
	REPLACE_CLASS_NAME_IDX = 12,
	RELOAD_BIN_IDX = 13,
	SUMMARY_INFO_IDX = 14,
	LIST_CODE_REFS_IDX = 15,
	PRINT_EXC_IDX = 16,
	YARA_CODE_REFS_IDX = 17,
	INSERT_MREF_IDX = 18,
	CALC_SZ_IDX = 19,
	ISVALID_IDX = 20,
	END_CMDS = 21,
};

static ut8 _(rz_cmd_java_obj_ref)(const char *name, const char *class_name, ut32 len) {
	if (!name || !class_name) {
		return false;
	}
	if (strncmp (class_name, name, len)) {
		return false;
	}
	if (*(name - 1) == 'L' && *(name + len) == ';') {
		return true;
	}
	if (!strncmp (class_name, name, len) && !*(name + len)) {
		return true;
	}
	return false;
}

static const char *rz_cmd_get_next_classname_str(const char *str, const char *match_me) {
	const char *result = NULL;
	ut32 len = match_me && *match_me? strlen (match_me): 0;
	if (len && str && *str) {
		result = str;
		while (result && *result && (result - str < len)) {
			result = strstr (result, match_me);
			if (result) {
				break;
			}
		}
	}
	return result;
}

static ut32 rz_cmd_get_num_classname_str_occ(const char *str, const char *match_me) {
	const char *result = NULL;
	ut32 len = match_me && *match_me? strlen (match_me): 0;
	ut32 occ = 0;

	if (len == 0 || !str || !*str) {
		return 0;
	}
	result = str;
	while (result && *result && (result - str < len)) {
		result = strstr (result, match_me);
		if (result) {
			IFDBG eprintf ("result: %s\n", result);
			result += len;
			occ++;
		}
	}
	return occ;
}

static const char *rz_cmd_java_consumetok(const char *str1, const char b, size_t len) {
	const char *p = str1;
	size_t i = 0;
	if (!p) {
		return p;
	}
	if (len == (size_t)-1) {
		len = strlen (str1);
	}
	for (; i < len; i++, p++) {
		if (*p != b) {
			break;
		}
	}
	return p;
}

static const char *rz_cmd_java_strtok(const char *str1, const char b, size_t len) {
	const char *p = str1;
	size_t i = 0;
	if (!p || !*p) {
		return p;
	}
	if (len == (size_t)-1) {
		len = strlen (str1);
	}
	IFDBG rz_cons_printf ("Looking for char (%c) in (%s) up to %d\n", b, p, len);
	for (; i < len; i++, p++) {
		if (*p == b) {
			IFDBG rz_cons_printf ("Found? for char (%c) @ %d: (%s)\n", b, i, p);
			break;
		}
	}
	if (i == len) {
		p = NULL;
	}
	IFDBG rz_cons_printf ("Found? for char (%c) @ %d: (%s)\n", b, len, p);
	return p;
}

static RzAnal *get_anal(RzCore *core) {
	return core? core->anal: NULL;
}

static void rz_cmd_java_print_cmd_help(RzCmdJavaCmd *cmd) {
	eprintf ("[*] %s %s\n[+] %s\n\n", cmd->name, cmd->args, cmd->desc);
}

static int rz_cmd_java_handle_help(RzCore *core, const char *input) {
	ut32 i = 0;
	const char **help_msg = (const char **)malloc (sizeof (char *) * END_CMDS * 4);
	help_msg[0] = "Usage:";
	help_msg[1] = "java [cmd] [arg..] ";
	help_msg[2] = rz_core_plugin_java.desc;
	for (i = 0; i < END_CMDS; i++) {
		RzCmdJavaCmd *cmd = &JAVA_CMDS[i];
		help_msg[3 + (i * 3) + 0] = cmd->name;
		help_msg[3 + (i * 3) + 1] = cmd->args;
		help_msg[3 + (i * 3) + 2] = cmd->desc;
	}
	help_msg[3 + (i * 3)] = NULL;
	rz_core_cmd_help (core, help_msg);
	free (help_msg);
	return true;
}

static int rz_cmd_java_handle_prototypes(RzCore *core, const char *cmd) {
	RzAnal *anal = get_anal (core);
	RzBinJavaObj *obj = (RzBinJavaObj *)rz_cmd_java_get_bin_obj (anal);
	IFDBG rz_cons_printf ("Function call made: %s\n", cmd);

	if (!obj) {
		eprintf ("[-] rz_cmd_java: no valid java bins found.\n");
		return true;
	}

	switch (*(cmd)) {
	case 'm': return rz_cmd_java_print_method_definitions (obj);
	case 'f': return rz_cmd_java_print_field_definitions (obj);
	case 'i': return rz_cmd_java_print_import_definitions (obj);
	case 'c': return rz_cmd_java_print_class_definitions (obj);
	case 'a': return rz_cmd_java_print_all_definitions (anal);
	case 'j': return rz_cmd_java_print_json_definitions (obj);
	}
	return false;
}

static int rz_cmd_java_handle_summary_info(RzCore *core, const char *cmd) {
	RzAnal *anal = get_anal (core);
	RzBinJavaObj *obj = (RzBinJavaObj *)rz_cmd_java_get_bin_obj (anal);
	IFDBG rz_cons_printf ("Function call made: %s\n", cmd);

	if (!obj) {
		eprintf ("[-] rz_cmd_java: no valid java bins found.\n");
		return true;
	}

	rz_cons_printf ("Summary for %s:\n", obj->file);
	rz_cons_printf ("  Size 0x%" PFMT64x ":\n", obj->size);
	rz_cons_printf ("  Constants  size: 0x%" PFMT64x " count: %d:\n", obj->cp_size, obj->cp_count);
	rz_cons_printf ("  Methods    size: 0x%" PFMT64x " count: %d:\n", obj->methods_size, obj->methods_count);
	rz_cons_printf ("  Fields     size: 0x%" PFMT64x " count: %d:\n", obj->fields_size, obj->fields_count);
	rz_cons_printf ("  Attributes size: 0x%" PFMT64x " count: %d:\n", obj->attrs_size, obj->attrs_count);
	rz_cons_printf ("  Interfaces size: 0x%" PFMT64x " count: %d:\n", obj->interfaces_size, obj->interfaces_count);

	return true;
}

static int _(rz_cmd_java_check_op_idx)(const ut8 *op_bytes, ut16 idx) {
	return RZ_BIN_JAVA_USHORT (op_bytes, 0) == idx;
}

/* Find stuff in the constant pool */
static RzList *cpfind_double(RzBinJavaObj *obj, const char *cmd) {
	double value = cmd && *cmd? strtod (cmd, NULL): 0.0;
	if (value == 0.0 && !(cmd && cmd[0] == '0' && cmd[1] == '.' && cmd[2] == '0')) {
		return rz_list_new ();
	}
	return rz_bin_java_find_cp_const_by_val (obj, (const ut8 *)&value, 8, RZ_BIN_JAVA_CP_DOUBLE);
}

static RzList *cpfind_float(RzBinJavaObj *obj, const char *cmd) {
	float value = cmd && *cmd? atof (cmd): 0.0;
	if (value == 0.0 && !(cmd && cmd[0] == '0' && cmd[1] == '.' && cmd[2] == '0')) {
		return rz_list_new ();
	}
	return rz_bin_java_find_cp_const_by_val (obj, (const ut8 *)&value, 4, RZ_BIN_JAVA_CP_FLOAT);
}

static RzList *cpfind_long(RzCore *core, RzBinJavaObj *obj, const char *cmd) {
	ut64 value = rz_cmd_java_get_input_num_value (core, cmd);
	if (!rz_cmd_java_is_valid_input_num_value (core, cmd)) {
		return rz_list_new ();
	}
	return rz_bin_java_find_cp_const_by_val (obj, (const ut8 *)&value, 8, RZ_BIN_JAVA_CP_LONG);
}

static RzList *cpfind_int(RzCore *core, RzBinJavaObj *obj, const char *cmd) {
	ut32 value = (ut32)rz_cmd_java_get_input_num_value (core, cmd);
	if (!rz_cmd_java_is_valid_input_num_value (core, cmd)) {
		return rz_list_new ();
	}
	return rz_bin_java_find_cp_const_by_val (obj, (const ut8 *)&value, 4, RZ_BIN_JAVA_CP_INTEGER);
}

static RzList *cpfind_str(RzBinJavaObj *obj, const char *cmd) {
	if (!cmd) {
		return rz_list_new ();
	}
	IFDBG rz_cons_printf ("Looking for str: %s (%d)\n", cmd, strlen (cmd));
	return rz_bin_java_find_cp_const_by_val (obj, (const ut8 *)cmd, strlen (cmd), RZ_BIN_JAVA_CP_UTF8);
}

static int cpfind(RzCore *core, const char *cmd) {
	RzBinJavaObj *obj = (RzBinJavaObj *)rz_cmd_java_get_bin_obj (get_anal (core));
	const char *p = cmd;
	char f_type = 0;
	RzList *find_list = NULL;
	RzListIter *iter;
	ut32 *idx;

	if (!obj) {
		eprintf ("[-] rz_cmd_java: no valid java bins found.\n");
		return true;
	}
	IFDBG rz_cons_printf ("Function call made: %s\n", p);
	if (p && *p) {
		p = rz_cmd_java_consumetok (cmd, ' ', -1);
		f_type = *p;
		p += 2;
	}
	IFDBG rz_cons_printf ("Function call made: %s\n", p);
	switch (f_type) {
	case 's': find_list = cpfind_str (obj, p); break;
	case 'i': find_list = cpfind_int (core, obj, rz_cmd_java_consumetok (p, ' ', -1)); break;
	case 'l': find_list = cpfind_long (core, obj, rz_cmd_java_consumetok (p, ' ', -1)); break;
	case 'f': find_list = cpfind_float (obj, rz_cmd_java_consumetok (p, ' ', -1)); break;
	case 'd': find_list = cpfind_double (obj, rz_cmd_java_consumetok (p, ' ', -1)); break;
	default:
		eprintf ("[-] rz_cmd_java: invalid java type to search for.\n");
		return true;
	}

	rz_list_foreach (find_list, iter, idx) {
		ut64 addr = rz_bin_java_resolve_cp_idx_address (obj, (ut16)*idx);
		rz_cons_printf ("Offset: 0x%" PFMT64x " idx: %d\n", addr, *idx);
	}
	rz_list_free (find_list);
	return true;
}

static int rz_cmd_java_reload_bin_from_buf(RzCore *core, RzBinJavaObj *obj, ut8 *buffer, ut64 len) {
	if (!buffer || len < 10) {
		return false;
	}
	int res = rz_bin_java_load_bin (obj, buffer, len);

	if (res == true) {
		//RzBinPlugin *cp = NULL;
		RzBinPlugin *tmp;
		RzListIter *iter;
		rz_list_foreach (core->bin->plugins, iter, tmp) {
			if (!strncmp ("java", tmp->name, 4)) {
				//cp = tmp;
				break;
			}
		}
		// XXX - this API is no longer valid.
		// need a function that will re-read bin bytes
		// and parse the file
		//if (cp) rz_bin_update_items (core->bin, cp);
	}
	return res;
}

static int rz_cmd_java_get_cp_bytes_and_write(RzCore *core, RzBinJavaObj *obj, ut16 idx, ut64 addr, const ut8 *buf, const ut64 len) {
	int res = false;
	RzBinJavaCPTypeObj *cp_obj = rz_bin_java_get_item_from_bin_cp_list (obj, idx);
	ut64 c_file_sz = rz_io_size (core->io);
	ut32 n_sz = 0, c_sz = obj? rz_bin_java_cp_get_size (obj, idx): (ut32)-1;
	ut8 *bytes = NULL;

	if (c_sz == (ut32)-1) {
		return res;
	}

	bytes = rz_bin_java_cp_get_bytes (cp_obj->tag, &n_sz, buf, len);

	if (n_sz < c_sz) {
		res = rz_core_shift_block (core, addr + c_sz, 0, (int)n_sz - (int)c_sz) &&
			rz_io_resize (core->io, c_file_sz + (int)n_sz - (int)c_sz);
	} else if (n_sz > c_sz) {
		res = rz_core_extend_at (core, addr, (int)n_sz - (int)c_sz);
	} else {
		eprintf ("[X] rz_cmd_java_get_cp_bytes_and_write: Failed to resize the file correctly aborting.\n");
		return res;
	}

	if (n_sz > 0 && bytes) {
		res = rz_core_write_at (core, addr, (const ut8 *)bytes, n_sz) && rz_core_seek (core, addr, true);
	}

	if (res == false) {
		eprintf ("[X] rz_cmd_java_get_cp_bytes_and_write: Failed to write the bytes to the file correctly aborting.\n");
		return res;
	}

	RZ_FREE (bytes);

	if (res == true) {
		ut64 n_file_sz = 0;
		ut8 *bin_buffer = NULL;
		res = rz_io_use_fd (core->io, core->file->fd);
		n_file_sz = rz_io_size (core->io);
		bin_buffer = n_file_sz > 0? malloc (n_file_sz): NULL;
		if (bin_buffer) {
			memset (bin_buffer, 0, n_file_sz);
			res = n_file_sz == rz_io_read_at (core->io, obj->loadaddr, bin_buffer, n_file_sz)? true: false;
			if (res == true) {
				res = rz_cmd_java_reload_bin_from_buf (
					core, obj, bin_buffer, n_file_sz);
			} else {
				eprintf ("[X] rz_cmd_java_get_cp_bytes_and_write: Failed to read the file in aborted, bin reload.\n");
			}
			free (bin_buffer);
		}
	}
	return res;
}

static int rz_cmd_java_handle_replace_cp_value_float(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	float value = cmd && *cmd? atof (cmd): 0.0;
	int res = false;
	res = rz_cmd_java_get_cp_bytes_and_write (core, obj, idx, addr, (ut8 *)&value, 4);
	return res;
}

static int rz_cmd_java_handle_replace_cp_value_double(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	double value = cmd && *cmd? strtod (cmd, NULL): 0.0;
	int res = false;
	res = rz_cmd_java_get_cp_bytes_and_write (core, obj, idx, addr, (ut8 *)&value, 8);
	return res;
}

static int rz_cmd_java_handle_replace_cp_value_long(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	ut64 value = rz_cmd_java_get_input_num_value (core, cmd);
	int res = false;
	res = rz_cmd_java_get_cp_bytes_and_write (core, obj, idx, addr, (ut8 *)&value, 8);
	return res;
}

static int rz_cmd_java_handle_replace_cp_value_int(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	ut32 value = (ut32)rz_cmd_java_get_input_num_value (core, cmd);
	int res = false;
	res = rz_cmd_java_get_cp_bytes_and_write (core, obj, idx, addr, (ut8 *)&value, 4);
	return res;
}

static int rz_cmd_java_handle_replace_cp_value_str(RzCore *core, RzBinJavaObj *obj, const char *cmd, ut16 idx, ut64 addr) {
	int res = false;
	ut32 len = cmd && *cmd? strlen (cmd): 0;
	if (len > 0 && cmd && *cmd == '"') {
		cmd++;
		len = cmd && *cmd? strlen (cmd): 0;
	}
	if (cmd && len > 0) {
		res = rz_cmd_java_get_cp_bytes_and_write (core, obj, idx, addr, (ut8 *)cmd, len);
	}
	return res;
}

static int rz_cmd_java_handle_replace_cp_value(RzCore *core, const char *cmd) {
	RzBinJavaObj *obj = (RzBinJavaObj *)rz_cmd_java_get_bin_obj (get_anal (core));
	ut16 idx = -1;
	ut64 addr = 0;
	const char *p = cmd;
	char cp_type = 0;
	IFDBG rz_cons_printf ("Function call made: %s\n", p);
	if (p && *p) {
		p = rz_cmd_java_consumetok (cmd, ' ', -1);
		if (rz_cmd_java_is_valid_input_num_value (core, p)) {
			idx = rz_cmd_java_get_input_num_value (core, p);
			p = rz_cmd_java_strtok (p, ' ', strlen (p));
		}
	}
	if (idx == (ut16)-1) {
		eprintf ("[-] rz_cmd_java: Invalid index value.\n");
	} else if (!obj) {
		eprintf ("[-] rz_cmd_java: The current binary is not a Java Bin Object.\n");
	} else if (!p || (p && !*p)) {
		rz_cmd_java_print_cmd_help (JAVA_CMDS + REPLACE_CP_VALUE_IDX);
		return true;
	} else {
		cp_type = rz_bin_java_resolve_cp_idx_tag (obj, idx);
		addr = rz_bin_java_resolve_cp_idx_address (obj, idx);
		IFDBG rz_cons_printf ("Function call made: %s\n", p);
		switch (cp_type) {
		case RZ_BIN_JAVA_CP_UTF8: return rz_cmd_java_handle_replace_cp_value_str (
			core, obj, rz_cmd_java_consumetok (p, ' ', -1), idx, addr);
		case RZ_BIN_JAVA_CP_INTEGER: return rz_cmd_java_handle_replace_cp_value_int (
			core, obj, rz_cmd_java_consumetok (p, ' ', -1), idx, addr);
		case RZ_BIN_JAVA_CP_LONG: return rz_cmd_java_handle_replace_cp_value_long (
			core, obj, rz_cmd_java_consumetok (p, ' ', -1), idx, addr);
		case RZ_BIN_JAVA_CP_FLOAT: return rz_cmd_java_handle_replace_cp_value_float (
			core, obj, rz_cmd_java_consumetok (p, ' ', -1), idx, addr);
		case RZ_BIN_JAVA_CP_DOUBLE: return rz_cmd_java_handle_replace_cp_value_double (
			core, obj, rz_cmd_java_consumetok (p, ' ', -1), idx, addr);
		default:
			eprintf ("[-] rz_cmd_java: invalid java type to search for.\n");
			return false;
		}
		return true;
	}
	return false;
}

static char *rz_cmd_replace_name_def(const char *s_new, ut32 replace_len, const char *s_old, ut32 match_len, const char *buffer, ut32 buf_len, ut32 *res_len) {
	const char *fmt = "L%s;";
	char *s_new_ref = s_new && replace_len > 0? malloc (3 + replace_len): NULL;
	char *s_old_ref = s_old && match_len > 0? malloc (3 + match_len): NULL;
	char *result = NULL;
	*res_len = 0;
	if (s_new_ref && s_old_ref) {
		snprintf (s_new_ref, replace_len + 3, fmt, s_new);
		snprintf (s_old_ref, match_len + 3, fmt, s_old);
		result = rz_cmd_replace_name (s_new_ref, replace_len + 2, s_old_ref, match_len + 2, buffer, buf_len, res_len);
	}
	free (s_new_ref);
	free (s_old_ref);
	return result;
}

static int rz_cmd_is_object_descriptor(const char *name, ut32 name_len) {
	int found_L = false, found_Semi = false;
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

	return true? found_L == found_Semi && found_L == true && L_pos < Semi_pos: false;
}

static char *rz_cmd_replace_name(const char *s_new, ut32 replace_len, const char *s_old, ut32 match_len, const char *buffer, ut32 buf_len, ut32 *res_len) {
	ut32 num_occurrences = 0, i = 0;
	char *result = NULL, *p_result = NULL;

	num_occurrences = rz_cmd_get_num_classname_str_occ (buffer, s_old);
	*res_len = 0;
	if (num_occurrences > 0 && replace_len > 0 && s_old) {
		ut32 consumed = 0;
		const char *next = rz_cmd_get_next_classname_str (buffer + consumed, s_old);
		IFDBG rz_cons_printf ("Replacing \"%s\" with \"%s\" in: %s\n", s_old, s_new, buffer);
		result = malloc (num_occurrences * replace_len + buf_len);
		memset (result, 0, num_occurrences * replace_len + buf_len);
		p_result = result;
		while (next && consumed < buf_len) {
			// replace up to next
			IFDBG rz_cons_printf ("next: \"%s\", len to: %d\n", next, next - buffer);
			for (; buffer + consumed < next && consumed < buf_len; consumed++, p_result++) {
				*p_result = *(buffer + consumed);
				(*res_len)++;
			}

			for (i = 0; i < replace_len; i++, p_result++) {
				*p_result = *(s_new + i);
				(*res_len)++;
			}
			consumed += match_len;
			next = rz_cmd_get_next_classname_str (buffer + consumed, s_old);
		}
		IFDBG rz_cons_printf ("Found last occurrence of: \"%s\", remaining: %s\n", s_old, buffer + consumed);
		IFDBG rz_cons_printf ("result is: \"%s\"\n", result);
		for (; consumed < buf_len; consumed++, p_result++, (*res_len)++) {
			*p_result = *(buffer + consumed);
		}
		IFDBG rz_cons_printf ("Old: %s\nNew: %s\n", buffer, result);
	}
	return result;
}

static int rz_cmd_java_get_class_names_from_input(const char *input, char **class_name, ut32 *class_name_len, char **new_class_name, ut32 *new_class_name_len) {
	const char *p = input;

	ut32 cmd_sz = input && *input? strlen (input): 0;
	int res = false;

	if (!class_name || *class_name) {
		return res;
	} else if (!new_class_name || *new_class_name) {
		return res;
	} else if (!new_class_name_len || !class_name_len) {
		return res;
	}

	*new_class_name = NULL;
	*class_name_len = 0;

	if (p && *p && cmd_sz > 1) {
		const char *end;
		p = rz_cmd_java_consumetok (p, ' ', cmd_sz);
		end = p && *p? rz_cmd_java_strtok (p, ' ', -1): NULL;

		if (p && end && p != end) {
			*class_name_len = end - p + 1;
			*class_name = malloc (*class_name_len);
			snprintf (*class_name, *class_name_len, "%s", p);
			cmd_sz = *class_name_len - 1 < cmd_sz? cmd_sz - *class_name_len: 0;
		}

		if (*class_name && cmd_sz > 0) {
			p = rz_cmd_java_consumetok (end + 1, ' ', cmd_sz);
			end = p && *p? rz_cmd_java_strtok (p, ' ', -1): NULL;

			if (!end && p && *p) {
				end = p + cmd_sz;
			}

			if (p && end && p != end) {
				*new_class_name_len = end - p + 1;
				*new_class_name = malloc (*new_class_name_len);
				snprintf (*new_class_name, *new_class_name_len, "%s", p);
				res = true;
			}
		}
	}
	return res;
}

static int rz_cmd_java_handle_replace_classname_value(RzCore *core, const char *cmd) {
	RzBinJavaObj *obj;
	char *class_name = NULL, *new_class_name = NULL;
	ut32 class_name_len = 0, new_class_name_len = 0;
	RzAnal *anal = get_anal (core);
	const char *p = cmd;
	int res = false;
	ut32 idx = -1;

	if (!core || !anal || !cmd) {
		return false;
	}
	IFDBG rz_cons_printf ("Function call made: %s\n", p);
	obj = (RzBinJavaObj *)rz_cmd_java_get_bin_obj (anal);
	if (!obj) {
		eprintf ("The current binary is not a Java Bin Object.\n");
		return true;
	}
	res = rz_cmd_java_get_class_names_from_input (cmd, &class_name,
		&class_name_len, &new_class_name, &new_class_name_len);

	if (!res || !class_name || !new_class_name) {
		rz_cmd_java_print_cmd_help (JAVA_CMDS + REPLACE_CLASS_NAME_IDX);
		free (class_name);
		free (new_class_name);
		return true;
	}
	for (idx = 1; idx <= obj->cp_count; idx++) {
		RzBinJavaCPTypeObj *cp_obj = rz_bin_java_get_item_from_bin_cp_list (obj, idx);
		char *name = NULL;
		ut8 *buffer = NULL;
		ut32 buffer_sz = 0;
		ut16 len = 0;
		if (cp_obj && cp_obj->tag == RZ_BIN_JAVA_CP_UTF8 &&
			cp_obj->info.cp_utf8.length && cp_obj->info.cp_utf8.length >= class_name_len - 1) {
			ut32 num_occurrences = 0;
			ut64 addr = cp_obj->file_offset + cp_obj->loadaddr;
			buffer = rz_bin_java_cp_get_idx_bytes (obj, idx, &buffer_sz);

			if (!buffer) {
				continue;
			}
			len = RZ_BIN_JAVA_USHORT (buffer, 1);
			name = malloc (len + 3);
			memcpy (name, buffer + 3, len);
			name[len] = 0;

			num_occurrences = rz_cmd_get_num_classname_str_occ (name, class_name);

			if (num_occurrences > 0) {
				// perform inplace replacement
				ut32 res_len = 0;
				char *result = NULL;

				if (rz_cmd_is_object_descriptor (name, len) == true) {
					result = rz_cmd_replace_name_def (new_class_name,
						new_class_name_len - 1, class_name,
						class_name_len - 1, name, len, &res_len);
				} else {
					result = rz_cmd_replace_name (new_class_name,
						new_class_name_len - 1, class_name,
						class_name_len - 1, name, len, &res_len);
				}
				if (result) {
					res = rz_cmd_java_get_cp_bytes_and_write (
						core, obj, idx, addr,
						(const ut8 *)result, res_len);
					if (res == false) {
						eprintf ("ERROR: rz_cmd_java: Failed to write bytes or reload the binary.\n");
					}
				}
				free (result);
			}
			free (buffer);
			free (name);
		}
	}
	free (class_name);
	free (new_class_name);
	return true;
}

static int rz_cmd_java_handle_reload_bin(RzCore *core, const char *cmd) {
	RzAnal *anal = get_anal (core);
	RzBinJavaObj *obj = (RzBinJavaObj *)rz_cmd_java_get_bin_obj (anal);
	const char *p = cmd;
	ut64 addr = 0LL; //cur_offset = core->offset, addr = 0;
	ut64 buf_size = 0;
	ut8 *buf = NULL;
	int res = false;

	if (*cmd == ' ') {
		p = rz_cmd_java_consumetok (p, ' ', -1);
	}
	if (!*cmd) {
		rz_cmd_java_print_cmd_help (JAVA_CMDS + RELOAD_BIN_IDX);
		return true;
	}

	addr = rz_cmd_java_is_valid_input_num_value (core, p)? rz_cmd_java_get_input_num_value (core, p): (ut32)-1;
	if (*cmd == ' ') {
		p = rz_cmd_java_consumetok (p, ' ', -1);
	}
	buf_size = rz_cmd_java_is_valid_input_num_value (core, p)? rz_cmd_java_get_input_num_value (core, p): (ut32)-1;

	// XXX this may cause problems cause the file we are looking at may not be the bin we want.
	// lets pretend it is for now
	if (buf_size == 0) {
		res = rz_io_use_fd (core->io, core->file->fd);
		buf_size = rz_io_size (core->io);
		buf = malloc (buf_size);
		memset (buf, 0, buf_size);
		rz_io_read_at (core->io, addr, buf, buf_size);
	}
	if (buf && obj) {
		res = rz_cmd_java_reload_bin_from_buf (core, obj, buf, buf_size);
	}
	free (buf);
	return res;
}

static int rz_cmd_java_handle_find_cp_const(RzCore *core, const char *cmd) {
	const char *p = (cmd && *cmd == ' ')? rz_cmd_java_consumetok (cmd, ' ', -1): NULL;
	RzBinJavaObj *obj = (RzBinJavaObj *)rz_cmd_java_get_bin_obj (get_anal (core));
	RzAnalFunction *fcn = NULL;
	RzAnalBlock *bb = NULL;
	RzListIter *bb_iter, *fn_iter, *iter;
	RzCmdJavaCPResult *cp_res = NULL;
	ut16 idx = -1;
	RzList *find_list;

	if (p && *p == 'a') {
		idx = -1;
	} else {
		idx = rz_cmd_java_get_input_num_value (core, p);
	}

	IFDBG rz_cons_printf ("Function call made: %s\n", cmd);

	if (!obj) {
		eprintf ("[-] rz_cmd_java: no valid java bins found.\n");
		return true;
	}
	if (!cmd || !*cmd) {
		eprintf ("[-] rz_cmd_java: invalid command syntax.\n");
		rz_cmd_java_print_cmd_help (JAVA_CMDS + FIND_CP_CONST_IDX);
		return true;
	}
	if (idx == 0) {
		eprintf ("[-] rz_cmd_java: invalid CP Obj Index Supplied.\n");
		return true;
	}
	find_list = rz_list_new ();
	find_list->free = free;
	// XXX - this will break once RzAnal moves to sdb
	rz_list_foreach (core->anal->fcns, fn_iter, fcn) {
		rz_list_foreach (fcn->bbs, bb_iter, bb) {
			char op = bb->op_bytes[0];
			cp_res = NULL;
			switch (op) {
			case 0x12:
				cp_res = (idx == (ut16)-1) || (bb->op_bytes[1] == idx)? RZ_NEW0 (RzCmdJavaCPResult): NULL;
				if (cp_res) {
					cp_res->idx = bb->op_bytes[1];
				}
				break;
			case 0x13:
			case 0x14:
				cp_res = (idx == (ut16)-1) || (RZ_BIN_JAVA_USHORT (bb->op_bytes, 1) == idx)? RZ_NEW0 (RzCmdJavaCPResult): NULL;
				if (cp_res) {
					cp_res->idx = RZ_BIN_JAVA_USHORT (bb->op_bytes, 1);
				}
				break;
			}
			if (cp_res) {
				cp_res->addr = bb->addr;
				cp_res->obj = rz_bin_java_get_item_from_cp (obj, cp_res->idx);
				rz_list_append (find_list, cp_res);
			}
		}
	}
	if (idx == (ut16)-1) {
		rz_list_foreach (find_list, iter, cp_res) {
			const char *t = ((RzBinJavaCPTypeMetas *)cp_res->obj->metas->type_info)->name;
			rz_cons_printf ("@0x%" PFMT64x " idx = %d Type = %s\n", cp_res->addr, cp_res->idx, t);
		}

	} else {
		rz_list_foreach (find_list, iter, cp_res) {
			rz_cons_printf ("@0x%" PFMT64x "\n", cp_res->addr);
		}
	}
	rz_list_free (find_list);
	return true;
}

static int rz_cmd_java_handle_field_info(RzCore *core, const char *cmd) {
	RzAnal *anal = get_anal (core);
	RzBinJavaObj *obj = (RzBinJavaObj *)rz_cmd_java_get_bin_obj (anal);
	IFDBG rz_cons_printf ("Function call made: %s\n", cmd);
	ut16 idx = -1;

	if (!obj) {
		eprintf ("[-] rz_cmd_java: no valid java bins found.\n");
		return true;
	} else if (!cmd || !*cmd) {
		eprintf ("[-] rz_cmd_java: invalid command syntax.\n");
		rz_cmd_java_print_cmd_help (JAVA_CMDS + FIELD_INFO_IDX);
		return true;
	}

	if (*(cmd) == 's' || *(cmd) == 'n') {
		idx = rz_cmd_java_get_input_num_value (core, cmd + 1);
	}

	switch (*(cmd)) {
	case 'c': return rz_cmd_java_print_field_num_name (obj);
	case 's': return rz_cmd_java_print_field_summary (obj, idx);
	case 'n': return rz_cmd_java_print_field_name (obj, idx);
	}
	IFDBG rz_cons_printf ("Command is (%s)\n", cmd);
	eprintf ("[-] rz_cmd_java: invalid command syntax.\n");
	rz_cmd_java_print_cmd_help (JAVA_CMDS + FIELD_INFO_IDX);
	return false;
}

static int rz_cmd_java_handle_method_info(RzCore *core, const char *cmd) {
	RzAnal *anal = get_anal (core);
	RzBinJavaObj *obj = (RzBinJavaObj *)rz_cmd_java_get_bin_obj (anal);
	IFDBG rz_cons_printf ("Command is (%s)\n", cmd);
	ut16 idx = -1;

	if (!obj) {
		eprintf ("[-] rz_cmd_java: no valid java bins found.\n");
		return true;
	} else if (!cmd || !*cmd) {
		eprintf ("[-] rz_cmd_java: invalid command syntax.\n");
		rz_cmd_java_print_cmd_help (JAVA_CMDS + METHOD_INFO_IDX);
		return false;
	}

	if (*(cmd) == 's' || *(cmd) == 'n') {
		idx = rz_cmd_java_get_input_num_value (core, cmd + 1);
	}

	switch (*(cmd)) {
	case 'c': return rz_cmd_java_print_method_num_name (obj);
	case 's': return rz_cmd_java_print_method_summary (obj, idx);
	case 'n': return rz_cmd_java_print_method_name (obj, idx);
	}

	IFDBG rz_cons_printf ("Command is (%s)\n", cmd);
	eprintf ("[-] rz_cmd_java: invalid command syntax.\n");
	rz_cmd_java_print_cmd_help (JAVA_CMDS + METHOD_INFO_IDX);
	return false;
}

static int rz_cmd_java_handle_calc_class_sz(RzCore *core, const char *cmd) {
	int res = false;
	ut64 sz = UT64_MAX;
	ut64 addr = UT64_MAX;
	ut64 res_size = UT64_MAX,
	     cur_fsz = rz_io_fd_size (core->io, rz_core_file_cur (core)->fd);
	ut8 *tbuf, *buf = NULL;
	ut32 init_size = (1 << 16);
	const char *p = cmd? rz_cmd_java_consumetok (cmd, ' ', -1): NULL;
	addr = p && *p && rz_cmd_java_is_valid_input_num_value (core, p)? rz_cmd_java_get_input_num_value (core, p): UT64_MAX;

	// TODO add a size parameter to the command to skip the guessing part.

	if (addr != UT64_MAX && sz == UT64_MAX) {
		IFDBG rz_cons_printf ("Function call made: %s\n", cmd);
		IFDBG rz_cons_printf ("Attempting to calculate class file size @ : 0x%" PFMT64x ".\n", addr);
		sz = cur_fsz < init_size? cur_fsz: init_size;
		while (sz <= cur_fsz) {
			tbuf = realloc (buf, sz);
			if (!tbuf) {
				eprintf ("Memory allocation failed.\n");
				free (buf);
				break;
			}
			buf = tbuf;
			ut64 rz_sz = rz_io_read_at (core->io, addr, buf, sz)? sz: 0LL;
			// check the return read on the read
			if (rz_sz == 0) {
				break;
			}
			res_size = rz_bin_java_calc_class_size (buf, sz);
			// if the data buffer contains a class starting
			// at address, then the res_size will be the size
			// if the rz_sz is less than the sz, then we are near
			// the end of the core buffer, and there is no need
			// to continue trying to find the class size.
			if (res_size != UT64_MAX ||
				rz_sz < sz) {
				res = rz_sz < sz? false: true;
				free (buf);
				break;
			} else {
				sz += (1 << 16);
			}
		}
		if (res) {
			rz_cons_printf ("%" PFMT64d, res_size);
		} else {
			rz_cons_printf ("-1\n");
		}

		//snprintf (cmd_buf, 50, fmt, num_acc_flag, addr);
		//res = rz_core_cmd0(core, y);
	} else {
		rz_cmd_java_print_cmd_help (JAVA_CMDS + CALC_SZ_IDX);
	}
	return true;
}

static int rz_cmd_java_handle_isvalid(RzCore *core, const char *cmd) {
	int res = false;
	ut64 res_size = UT64_MAX;
	ut8 *tbuf, *buf = NULL;
	ut32 cur_fsz = rz_io_fd_size (core->io, rz_core_file_cur (core)->fd);
	ut64 sz = UT64_MAX;
	const char *p = cmd? rz_cmd_java_consumetok (cmd, ' ', -1): NULL;
	ut64 addr = UT64_MAX;
	addr = p && *p && rz_cmd_java_is_valid_input_num_value (core, p)? rz_cmd_java_get_input_num_value (core, p): UT64_MAX;

	// TODO add a size parameter to the command to skip the guessing part.

	if (addr != UT64_MAX && sz == UT64_MAX) {
		IFDBG rz_cons_printf ("Function call made: %s\n", cmd);
		IFDBG rz_cons_printf ("Attempting to calculate class file size @ : 0x%" PFMT64x ".\n", addr);

		while (sz <= cur_fsz) {
			tbuf = realloc (buf, sz);
			if (!tbuf) {
				eprintf ("Memory allocation failed.\n");
				free (buf);
				break;
			}
			buf = tbuf;
			ut64 rz_sz = rz_io_read_at (core->io, addr, buf, sz)? sz: 0LL;
			// check the return read on the read
			if (rz_sz == 0) {
				break;
			}
			res_size = rz_bin_java_calc_class_size (buf, sz);
			// if the data buffer contains a class starting
			// at address, then the res_size will be the size
			// if the rz_sz is less than the sz, then we are near
			// the end of the core buffer, and there is no need
			// to continue trying to find the class size.
			if (res_size != UT64_MAX ||
				rz_sz < sz) {
				res = rz_sz < sz? false: true;
				free (buf);
				break;
			} else {
				sz <<= 1;
			}
		}
		rz_cons_printf ("%s\n", rz_str_bool (res));
	} else {
		rz_cmd_java_print_cmd_help (JAVA_CMDS + ISVALID_IDX);
	}
	return true;
}

static int rz_cmd_java_handle_resolve_cp(RzCore *core, const char *cmd) {
	RzAnal *anal = get_anal (core);
	char c_type = cmd && *cmd? *cmd: 0;
	RzBinJavaObj *obj = rz_cmd_java_get_bin_obj (anal);
	ut32 idx = rz_cmd_java_get_input_num_value (core, cmd + 2);
	IFDBG rz_cons_printf ("Function call made: %s\n", cmd);
	IFDBG rz_cons_printf ("Ctype: %d (%c) RzBinJavaObj points to: %p and the idx is (%s): %d\n", c_type, c_type, obj, cmd + 2, idx);
	int res = false;
	if (idx > 0 && obj) {
		switch (c_type) {
		case 't': return rz_cmd_java_resolve_cp_type (obj, idx);
		case 'c': return rz_cmd_java_resolve_cp_idx (obj, idx);
		case 'e': return rz_cmd_java_resolve_cp_idx_b64 (obj, idx);
		case 'a': return rz_cmd_java_resolve_cp_address (obj, idx);
		case 's': return rz_cmd_java_resolve_cp_summary (obj, idx);
		case 'k': return rz_cmd_java_resolve_cp_to_key (obj, idx);
		}
	} else if (obj && c_type == 'g') {
		for (idx = 1; idx <= obj->cp_count; idx++) {
			ut64 addr = rz_bin_java_resolve_cp_idx_address (obj, idx);
			char *str = rz_bin_java_resolve_cp_idx_type (obj, idx);
			rz_cons_printf ("CP_OBJ Type %d =  %s @ 0x%" PFMT64x "\n", idx, str, addr);
			free (str);
		}
		res = true;
	} else if (obj && c_type == 'd') {
		for (idx = 1; idx <= obj->cp_count; idx++) {
			rz_cmd_java_resolve_cp_summary (obj, idx);
		}
		res = true;
	} else {
		if (!obj) {
			eprintf ("[-] rz_cmd_java: no valid java bins found.\n");
		} else {
			eprintf ("[-] rz_cmd_java: invalid cp index given, must idx > 1.\n");
			rz_cmd_java_print_cmd_help (JAVA_CMDS + RESOLVE_CP_IDX);
		}
		res = true;
	}
	return res;
}

static int rz_cmd_java_get_all_access_flags_value(const char *cmd) {
	RzList *the_list = NULL;
	RzListIter *iter = NULL;
	char *str = NULL;

	switch (*(cmd)) {
	case 'f': the_list = retrieve_all_field_access_string_and_value (); break;
	case 'm': the_list = retrieve_all_method_access_string_and_value (); break;
	case 'c': the_list = retrieve_all_class_access_string_and_value (); break;
	}
	if (!the_list) {
		eprintf ("[-] rz_cmd_java: incorrect syntax for the flags calculation.\n");
		rz_cmd_java_print_cmd_help (JAVA_CMDS + CALC_FLAGS_IDX);
		return false;
	}
	switch (*(cmd)) {
	case 'f': rz_cons_printf ("[=] Fields Access Flags List\n"); break;
	case 'm': rz_cons_printf ("[=] Methods Access Flags List\n"); break;
	case 'c':
		rz_cons_printf ("[=] Class Access Flags List\n");
		;
		break;
	}

	rz_list_foreach (the_list, iter, str) {
		rz_cons_println (str);
	}
	rz_list_free (the_list);
	return true;
}

static int rz_cmd_java_handle_calc_flags(RzCore *core, const char *cmd) {
	IFDBG rz_cons_printf ("Function call made: %s\n", cmd);
	int res = false;

	switch (*(cmd)) {
	case 'f': return rz_cmd_java_print_field_access_flags_value (cmd + 2);
	case 'm': return rz_cmd_java_print_method_access_flags_value (cmd + 2);
	case 'c': return rz_cmd_java_print_class_access_flags_value (cmd + 2);
	}

	if (*(cmd) == 'l') {
		const char *lcmd = *cmd + 1 == ' '? cmd + 2: cmd + 1;
		IFDBG eprintf ("Seeing %s and accepting %s\n", cmd, lcmd);
		switch (*(lcmd)) {
		case 'f':
		case 'm':
		case 'c': res = rz_cmd_java_get_all_access_flags_value (lcmd); break;
		}
		// Just print them all out
		if (res == false) {
			rz_cmd_java_get_all_access_flags_value ("c");
			rz_cmd_java_get_all_access_flags_value ("m");
			res = rz_cmd_java_get_all_access_flags_value ("f");
		}
	}
	if (res == false) {
		eprintf ("[-] rz_cmd_java: incorrect syntax for the flags calculation.\n");
		rz_cmd_java_print_cmd_help (JAVA_CMDS + CALC_FLAGS_IDX);
		res = true;
	}
	return res;
}

static int rz_cmd_java_handle_flags_str(RzCore *core, const char *cmd) {

	int res = false;
	ut32 flag_value = -1;
	const char f_type = cmd? *cmd: 0;
	const char *p = cmd? cmd + 2: NULL;
	char *flags_str = NULL;

	IFDBG rz_cons_printf ("rz_cmd_java_handle_flags_str: ftype = %c, idx = %s\n", f_type, p);
	if (p) {
		flag_value = rz_cmd_java_is_valid_input_num_value (core, p)? rz_cmd_java_get_input_num_value (core, p): (ut32)-1;
	}

	if (p && f_type) {
		switch (f_type) {
		case 'm': flags_str = retrieve_method_access_string ((ut16)flag_value); break;
		case 'f': flags_str = retrieve_field_access_string ((ut16)flag_value); break;
		case 'c': flags_str = retrieve_class_method_access_string ((ut16)flag_value); break;
		default: flags_str = NULL;
		}
	}

	if (flags_str) {
		switch (f_type) {
		case 'm': rz_cons_printf ("Method Access Flags String: "); break;
		case 'f': rz_cons_printf ("Field Access Flags String: "); break;
		case 'c': rz_cons_printf ("Class Access Flags String: "); break;
		}
		rz_cons_println (flags_str);
		free (flags_str);
		res = true;
	}
	if (res == false) {
		eprintf ("[-] rz_cmd_java: incorrect syntax for the flags calculation.\n");
		rz_cmd_java_print_cmd_help (JAVA_CMDS + FLAGS_STR_IDX);
		res = true;
	}
	return res;
}

static int rz_cmd_java_handle_flags_str_at(RzCore *core, const char *cmd) {

	int res = false;
	ut64 flag_value_addr = -1;
	ut32 flag_value = -1;
	const char f_type = cmd? *rz_cmd_java_consumetok (cmd, ' ', -1): 0;
	const char *p = cmd? cmd + 2: NULL;
	char *flags_str = NULL;

	IFDBG rz_cons_printf ("rz_cmd_java_handle_flags_str_at: ftype = 0x%02x, idx = %s\n", f_type, p);
	if (p) {
		flag_value = 0;
		ut64 cur_offset = core->offset;
		flag_value_addr = rz_cmd_java_is_valid_input_num_value (core, p)? rz_cmd_java_get_input_num_value (core, p): (ut32)-1;
		rz_io_read_at (core->io, flag_value_addr, (ut8 *)&flag_value, 2);
		IFDBG rz_cons_printf ("rz_cmd_java_handle_flags_str_at: read = 0x%04x\n", flag_value);
		if (cur_offset != core->offset) {
			rz_core_seek (core, cur_offset - 2, true);
		}
		flag_value = RZ_BIN_JAVA_USHORT (((ut8 *)&flag_value), 0);
	}

	if (p && f_type) {
		switch (f_type) {
		case 'm': flags_str = retrieve_method_access_string ((ut16)flag_value); break;
		case 'f': flags_str = retrieve_field_access_string ((ut16)flag_value); break;
		case 'c': flags_str = retrieve_class_method_access_string ((ut16)flag_value); break;
		default: flags_str = NULL;
		}
	}

	if (flags_str) {
		switch (f_type) {
		case 'm': rz_cons_printf ("Method Access Flags String: "); break;
		case 'f': rz_cons_printf ("Field Access Flags String: "); break;
		case 'c': rz_cons_printf ("Class Access Flags String: "); break;
		}
		rz_cons_println (flags_str);
		free (flags_str);
		res = true;
	}
	if (res == false) {
		eprintf ("[-] rz_cmd_java: incorrect syntax for the flags calculation.\n");
		rz_cmd_java_print_cmd_help (JAVA_CMDS + FLAGS_STR_IDX);
		res = true;
	}
	return res;
}

static char rz_cmd_java_is_valid_java_mcf(char b) {
	char c = 0;
	switch (b) {
	case 'c':
	case 'f':
	case 'm': c = b;
	}
	return c;
}

static int rz_cmd_java_handle_set_flags(RzCore *core, const char *input) {
	//#define SET_ACC_FLAGS_ARGS "< c | m | f> <addr> <d | <s <flag value separated by space> >"
	const char *p = rz_cmd_java_consumetok (input, ' ', -1);
	ut64 addr = p && rz_cmd_java_is_valid_input_num_value (core, p)
		? rz_cmd_java_get_input_num_value (core, p)
		: (ut64)-1;
	p = rz_cmd_java_strtok (p + 1, ' ', -1);
	if (!p || !*p) {
		rz_cmd_java_print_cmd_help (JAVA_CMDS + SET_ACC_FLAGS_IDX);
		return true;
	}
	const char f_type = p && *p? rz_cmd_java_is_valid_java_mcf (*(++p)): '?';

	int flag_value = rz_cmd_java_is_valid_input_num_value (core, p)? rz_cmd_java_get_input_num_value (core, p): -1;

	if (flag_value == 16 && f_type == 'f') {
		flag_value = -1;
	}
	IFDBG rz_cons_printf ("Converting %s to flags\n", p);

	if (p) {
		p += 2;
	}
	if (flag_value == -1) {
		flag_value = rz_cmd_java_is_valid_input_num_value (core, p)? rz_cmd_java_get_input_num_value (core, p): -1;
	}
	bool res = false;
	if (!input) {
		eprintf ("[-] rz_cmd_java: no address provided .\n");
		res = true;
	} else if (addr == (ut64)-1) {
		eprintf ("[-] rz_cmd_java: no address provided .\n");
		res = true;
	} else if (f_type == '?' && flag_value == -1) {
		eprintf ("[-] rz_cmd_java: no flag type provided .\n");
		res = true;
	}

	if (res) {
		rz_cmd_java_print_cmd_help (JAVA_CMDS + SET_ACC_FLAGS_IDX);
		return res;
	}

	IFDBG rz_cons_printf ("Writing ftype '%c' to 0x%" PFMT64x ", %s.\n", f_type, addr, p);

	// handling string based access flags (otherwise skip ahead)
	IFDBG rz_cons_printf ("Converting %s to flags\n", p);
	if (f_type && flag_value != -1) {
		switch (f_type) {
		case 'f': flag_value = rz_bin_java_calculate_field_access_value (p); break;
		case 'm': flag_value = rz_bin_java_calculate_method_access_value (p); break;
		case 'c': flag_value = rz_bin_java_calculate_class_access_value (p); break;
		default: flag_value = -1;
		}
	}
	IFDBG rz_cons_printf ("Current args: (flag_value: 0x%04x addr: 0x%" PFMT64x ")\n.", flag_value, addr, res);
	if (flag_value != -1) {
		res = rz_cmd_java_set_acc_flags (core, addr, ((ut16)flag_value) & 0xffff);
		IFDBG rz_cons_printf ("Writing 0x%04x to 0x%" PFMT64x ": %d.", flag_value, addr, res);
	} else {
		eprintf ("[-] rz_cmd_java: invalid flag value or type provided .\n");
		rz_cmd_java_print_cmd_help (JAVA_CMDS + SET_ACC_FLAGS_IDX);
		res = true;
	}
	return res;
}

static int rz_cmd_java_call(void *user, const char *input) {
	RzCore *core = (RzCore *)user;
	int res = false;
	ut32 i = 0;
	if (strncmp (input, "java", 4)) {
		return false;
	}
	if (input[4] != ' ') {
		return rz_cmd_java_handle_help (core, input);
	}
	for (; i < END_CMDS - 1; i++) {
		//IFDBG rz_cons_printf ("Checking cmd: %s %d %s\n", JAVA_CMDS[i].name, JAVA_CMDS[i].name_len, p);
		IFDBG rz_cons_printf ("Checking cmd: %s %d\n", JAVA_CMDS[i].name,
			strncmp (input + 5, JAVA_CMDS[i].name, JAVA_CMDS[i].name_len));
		if (!strncmp (input + 5, JAVA_CMDS[i].name, JAVA_CMDS[i].name_len)) {
			const char *cmd = input + 5 + JAVA_CMDS[i].name_len;
			if (*cmd && *cmd == ' ') {
				cmd++;
			}
			//IFDBG rz_cons_printf ("Executing cmd: %s (%s)\n", JAVA_CMDS[i].name, cmd+5+JAVA_CMDS[i].name_len );
			res = JAVA_CMDS[i].handler (core, cmd);
			break;
		}
	}
	if (!res) {
		return rz_cmd_java_handle_help (core, input);
	}
	return true;
}

static int rz_cmd_java_print_method_definitions(RzBinJavaObj *obj) {
	RzList *the_list = rz_bin_java_get_method_definitions (obj),
	      *off_list = rz_bin_java_get_method_offsets (obj);
	char *str = NULL;
	ut32 idx = 0, end = rz_list_length (the_list);

	while (idx < end) {
		ut64 *addr = rz_list_get_n (off_list, idx);
		str = rz_list_get_n (the_list, idx);
		rz_cons_printf ("%s; // @0x%04" PFMT64x "\n", str, *addr);
		idx++;
	}

	rz_list_free (the_list);
	rz_list_free (off_list);
	return true;
}

static int rz_cmd_java_print_field_definitions(RzBinJavaObj *obj) {
	RzList *the_list = rz_bin_java_get_field_definitions (obj),
	      *off_list = rz_bin_java_get_field_offsets (obj);
	char *str = NULL;
	ut32 idx = 0, end = rz_list_length (the_list);

	while (idx < end) {
		ut64 *addr = rz_list_get_n (off_list, idx);
		str = rz_list_get_n (the_list, idx);
		rz_cons_printf ("%s; // @0x%04" PFMT64x "\n", str, *addr);
		idx++;
	}

	rz_list_free (the_list);
	rz_list_free (off_list);
	return true;
}

static int rz_cmd_java_print_import_definitions(RzBinJavaObj *obj) {
	RzList *the_list = rz_bin_java_get_import_definitions (obj);
	char *str = NULL;
	RzListIter *iter;
	rz_list_foreach (the_list, iter, str) {
		rz_cons_printf ("import %s;\n", str);
	}
	rz_list_free (the_list);
	return true;
}

static int rz_cmd_java_print_all_definitions(RzAnal *anal) {
	RzList *obj_list = rz_cmd_java_get_bin_obj_list (anal);
	RzListIter *iter;
	RzBinJavaObj *obj;

	if (!obj_list) {
		return 1;
	}
	rz_list_foreach (obj_list, iter, obj) {
		rz_cmd_java_print_class_definitions (obj);
	}
	return true;
}

static int rz_cmd_java_print_json_definitions(RzBinJavaObj *obj) {
	DsoJsonObj *json_obj = rz_bin_java_get_bin_obj_json (obj);
	char *str = dso_json_obj_to_str (json_obj);
	dso_json_obj_del (json_obj); // XXX memleak
	rz_cons_println (str);
	return true;
}

static int rz_cmd_java_print_class_definitions(RzBinJavaObj *obj) {
	RzList *the_fields = rz_bin_java_get_field_definitions (obj),
	      *the_methods = rz_bin_java_get_method_definitions (obj),
	      *the_imports = rz_bin_java_get_import_definitions (obj),
	      *the_moffsets = rz_bin_java_get_method_offsets (obj),
	      *the_foffsets = rz_bin_java_get_field_offsets (obj);

	char *class_name = rz_bin_java_get_this_class_name (obj);
	char *str = NULL;

	rz_cmd_java_print_import_definitions (obj);
	rz_cons_printf ("\nclass %s { // @0x%04" PFMT64x "\n", class_name, obj->loadaddr);

	if (the_fields && the_foffsets && rz_list_length (the_fields) > 0) {
		rz_cons_printf ("\n  // Fields defined in the class\n");
		ut32 idx = 0, end = rz_list_length (the_fields);

		while (idx < end) {
			ut64 *addr = rz_list_get_n (the_foffsets, idx);
			str = rz_list_get_n (the_fields, idx);
			rz_cons_printf ("  %s; // @0x%04" PFMT64x "\n", str, *addr);
			idx++;
		}
	}

	if (the_methods && the_moffsets && rz_list_length (the_methods) > 0) {
		rz_cons_printf ("\n  // Methods defined in the class\n");
		ut32 idx = 0, end = rz_list_length (the_methods);

		while (idx < end) {
			ut64 *addr = rz_list_get_n (the_moffsets, idx);
			str = rz_list_get_n (the_methods, idx);
			rz_cons_printf ("  %s; // @0x%04" PFMT64x "\n", str, *addr);
			idx++;
		}
	}
	rz_cons_printf ("}\n");

	rz_list_free (the_imports);
	rz_list_free (the_fields);
	rz_list_free (the_methods);
	rz_list_free (the_foffsets);
	rz_list_free (the_moffsets);

	free (class_name);
	return true;
}

static RzList *rz_cmd_java_get_bin_obj_list(RzAnal *anal) {
	RzBinJavaObj *bin_obj = (RzBinJavaObj *)rz_cmd_java_get_bin_obj (anal);
	// See librz/bin/p/bin_java.c to see what is happening here.  The original intention
	// was to use a shared global db variable from shlr/java/class.c, but the
	// BIN_OBJS_ADDRS variable kept getting corrupted on Mac, so I (deeso) switched the
	// way the access to the db was taking place by using the bin_obj as a proxy back
	// to the BIN_OBJS_ADDRS which is instantiated in librz/bin/p/bin_java.c
	// not the easiest way to make sausage, but its getting made.
	return rz_bin_java_get_bin_obj_list_thru_obj (bin_obj);
}

static RzBinJavaObj *rz_cmd_java_get_bin_obj(RzAnal *anal) {
	RzBin *b;
	int is_java;
	RzBinPlugin *plugin;
	if (!anal || !anal->binb.bin) {
		return NULL;
	}
	b = anal->binb.bin;
	if (!b->cur || !b->cur->o) {
		return NULL;
	}
	plugin = b->cur->o->plugin;
	is_java = (plugin && strcmp (plugin->name, "java") == 0)? 1: 0;
	return is_java? b->cur->o->bin_obj: NULL;
}

static int rz_cmd_java_resolve_cp_idx(RzBinJavaObj *obj, ut16 idx) {
	if (obj && idx) {
		char *str = rz_bin_java_resolve_without_space (obj, idx);
		rz_cons_println (str);
		free (str);
	}
	return true;
}

static int rz_cmd_java_resolve_cp_type(RzBinJavaObj *obj, ut16 idx) {
	if (obj && idx) {
		char *str = rz_bin_java_resolve_cp_idx_type (obj, idx);
		rz_cons_println (str);
		free (str);
	}
	return true;
}

static int rz_cmd_java_resolve_cp_idx_b64(RzBinJavaObj *obj, ut16 idx) {
	if (obj && idx) {
		char *str = rz_bin_java_resolve_b64_encode (obj, idx);
		rz_cons_println (str);
		free (str);
	}
	return true;
}

static int rz_cmd_java_resolve_cp_address(RzBinJavaObj *obj, ut16 idx) {
	if (obj && idx) {
		ut64 addr = rz_bin_java_resolve_cp_idx_address (obj, idx);
		if (addr == (ut64)-1) {
			rz_cons_printf ("Unable to resolve CP Object @ index: 0x%04x\n", idx);
		} else {
			rz_cons_printf ("0x%" PFMT64x "\n", addr);
		}
	}
	return true;
}

static int rz_cmd_java_resolve_cp_to_key(RzBinJavaObj *obj, ut16 idx) {
	if (obj && idx) {
		char *str = rz_bin_java_resolve_cp_idx_to_string (obj, idx);
		rz_cons_println (str);
		free (str);
	}
	return true;
}
static int rz_cmd_java_resolve_cp_summary(RzBinJavaObj *obj, ut16 idx) {
	if (obj && idx) {
		rz_bin_java_resolve_cp_idx_print_summary (obj, idx);
	}
	return true;
}

static int rz_cmd_java_is_valid_input_num_value(RzCore *core, const char *input_value) {
	ut64 value = input_value? rz_num_math (core->num, input_value): 0;
	return !(value == 0 && input_value && *input_value == '0');
}

static ut64 rz_cmd_java_get_input_num_value(RzCore *core, const char *input_value) {
	ut64 value = input_value? rz_num_math (core->num, input_value): 0;
	return value;
}

static int rz_cmd_java_print_class_access_flags_value(const char *flags) {
	ut16 result = rz_bin_java_calculate_class_access_value (flags);
	rz_cons_printf ("Access Value for %s = 0x%04x\n", flags, result);
	return true;
}
static int rz_cmd_java_print_field_access_flags_value(const char *flags) {
	ut16 result = rz_bin_java_calculate_field_access_value (flags);
	rz_cons_printf ("Access Value for %s = 0x%04x\n", flags, result);
	return true;
}
static int rz_cmd_java_print_method_access_flags_value(const char *flags) {
	ut16 result = rz_bin_java_calculate_method_access_value (flags);
	rz_cons_printf ("Access Value for %s = 0x%04x\n", flags, result);
	return true;
}

static int rz_cmd_java_set_acc_flags(RzCore *core, ut64 addr, ut16 num_acc_flag) {
	char cmd_buf[50];

	int res = false;
	num_acc_flag = RZ_BIN_JAVA_USHORT (((ut8 *)&num_acc_flag), 0);
	res = rz_core_write_at (core, addr, (const ut8 *)&num_acc_flag, 2);
	if (!res) {
		eprintf ("[X] rz_cmd_java_set_acc_flags: Failed to write.\n");
		return res;
	}
	res = true;
	IFDBG rz_cons_printf ("Executed cmd: %s == %d\n", cmd_buf, res);
	return res;
}
static int rz_cmd_java_print_field_num_name(RzBinJavaObj *obj) {
	RzList *the_list = rz_bin_java_get_field_num_name (obj);
	char *str;
	RzListIter *iter = NULL;
	rz_list_foreach (the_list, iter, str) {
		rz_cons_println (str);
	}
	rz_list_free (the_list);
	return true;
}

static int rz_cmd_java_print_method_num_name(RzBinJavaObj *obj) {
	RzList *the_list = rz_bin_java_get_method_num_name (obj);
	char *str;
	RzListIter *iter = NULL;
	rz_list_foreach (the_list, iter, str) {
		rz_cons_println (str);
	}
	rz_list_free (the_list);
	return true;
}

static int rz_cmd_java_print_field_summary(RzBinJavaObj *obj, ut16 idx) {
	int res = rz_bin_java_print_field_idx_summary (obj, idx);
	if (res == false) {
		eprintf ("Error: Field or Method @ index (%d) not found in the RzBinJavaObj.\n", idx);
		res = true;
	}
	return res;
}

static int UNUSED_FUNCTION(rz_cmd_java_print_field_count)(RzBinJavaObj *obj) {
	ut32 res = rz_bin_java_get_field_count (obj);
	rz_cons_printf ("%d\n", res);
	rz_cons_flush ();
	return true;
}

static int rz_cmd_java_print_field_name(RzBinJavaObj *obj, ut16 idx) {
	char *res = rz_bin_java_get_field_name (obj, idx);
	if (res) {
		rz_cons_println (res);
	} else {
		eprintf ("Error: Field or Method @ index (%d) not found in the RzBinJavaObj.\n", idx);
	}
	free (res);
	return true;
}

static int rz_cmd_java_print_method_summary(RzBinJavaObj *obj, ut16 idx) {
	int res = rz_bin_java_print_method_idx_summary (obj, idx);
	if (res == false) {
		eprintf ("Error: Field or Method @ index (%d) not found in the RzBinJavaObj.\n", idx);
		res = true;
	}
	return res;
}

static int _(rz_cmd_java_print_method_count)(RzBinJavaObj *obj) {
	ut32 res = rz_bin_java_get_method_count (obj);
	rz_cons_printf ("%d\n", res);
	rz_cons_flush ();
	return true;
}

static int rz_cmd_java_print_method_name(RzBinJavaObj *obj, ut16 idx) {
	char *res = rz_bin_java_get_method_name (obj, idx);
	if (res) {
		rz_cons_println (res);
	} else {
		eprintf ("Error: Field or Method @ index (%d) not found in the RzBinJavaObj.\n", idx);
	}
	free (res);
	return true;
}

static int rz_cmd_java_handle_yara_code_extraction_refs(RzCore *core, const char *input) {
	RzAnal *anal = get_anal (core);
	RzBinJavaObj *bin = anal? (RzBinJavaObj *)rz_cmd_java_get_bin_obj (anal): NULL;
	const char *p = input? rz_cmd_java_consumetok (input, ' ', -1): NULL, *n = NULL;
	char *name = NULL;
	ut64 addr = -1, count = -1;
	int res = false;

	if (!bin) {
		return res;
	} else if (!anal || !anal->fcns || rz_list_length (anal->fcns) == 0) {
		eprintf ("Unable to access the current analysis, perform 'af' for function analysis.\n");
		return true;
	}

	if (!p) {
		return res;
	}

	n = *p? rz_cmd_java_strtok (p, ' ', -1): NULL;
	name = n && p && p != n? malloc (n - p + 2): NULL;

	if (!name) {
		return res;
	}

	memset (name, 0, n - p);
	memcpy (name, p, n - p);

	p = rz_cmd_java_strtok (p, ' ', -1);
	addr = p && *p && rz_cmd_java_is_valid_input_num_value (core, p)? rz_cmd_java_get_input_num_value (core, p): (ut64)-1;

	p = rz_cmd_java_strtok (p, ' ', -1);
	count = p && *p && rz_cmd_java_is_valid_input_num_value (core, p)? rz_cmd_java_get_input_num_value (core, p): (ut64)-1;

	if (name && count != (ut64)-1 && addr != (ut64)-1) {
		// find function at addr

		// find the start basic block

		// read the bytes

		// hexlify the bytes

		// set the name = bytes

		// print t
	}
	free (name);
	return res;
}

static int rz_cmd_java_handle_insert_method_ref(RzCore *core, const char *input) {
	RzAnal *anal = get_anal (core);
	RzBinJavaObj *bin = anal? (RzBinJavaObj *)rz_cmd_java_get_bin_obj (anal): NULL;
	const char *p = input? rz_cmd_java_consumetok (input, ' ', -1): NULL, *n = NULL;
	char *classname = NULL, *name = NULL, *descriptor = NULL;
	ut32 cn_sz = 0, n_sz = 0, d_sz = 0;
	int res = false;

	if (!bin) {
		return res;
	}
	if (!anal || !anal->fcns || rz_list_length (anal->fcns) == 0) {
		eprintf ("Unable to access the current analysis, perform 'af' for function analysis.\n");
		return true;
	}
	if (!p) {
		return res;
	}

	n = p && *p? rz_cmd_java_strtok (p, ' ', -1): NULL;
	classname = n && p && p != n? malloc (n - p + 1): NULL;
	cn_sz = n && p? n - p + 1: 0;
	if (!classname) {
		return res;
	}

	snprintf (classname, cn_sz, "%s", p);
	p = n + 1;
	n = p && *p? rz_cmd_java_strtok (p, ' ', -1): NULL;
	name = n && p && p != n? malloc (n - p + 1): NULL;
	n_sz = n && p? n - p + 1: 0;
	if (!name) {
		free (classname);
		return res;
	}
	snprintf (name, n_sz, "%s", p);

	p = n + 1;
	n = p && *p? rz_cmd_java_strtok (p, ' ', -1): NULL;
	if (n) {
		descriptor = n && p && p != n? malloc (n - p + 1): NULL;
		d_sz = n - p + 1;
	} else if (p && *p) {
		d_sz = strlen (p) + 1;
		descriptor = d_sz > 1? malloc (d_sz): NULL;
	}

	if (!descriptor) {
		free (classname);
		free (name);
		return res;
	}
	snprintf (descriptor, d_sz, "%s", p);

	rz_cons_printf ("Would be adding class name:%s, name: %s, descriptor: %s\n", classname, name, descriptor);
	free (classname);
	free (name);
	free (descriptor);
	res = true;
	return res;
}

static int rz_cmd_java_handle_print_exceptions(RzCore *core, const char *input) {
	RzAnal *anal = get_anal (core);
	RzBinJavaObj *bin = (RzBinJavaObj *) rz_cmd_java_get_bin_obj (anal);
	RzListIter *exc_iter = NULL, *methods_iter=NULL;
	RzBinJavaField *method;
	ut64 func_addr = -1;
	RzBinJavaExceptionEntry *exc_entry;

	const char *p = input? rz_cmd_java_consumetok (input, ' ', -1): NULL;
	func_addr = p && *p && rz_cmd_java_is_valid_input_num_value (core, p)? rz_cmd_java_get_input_num_value (core, p): -1;

	if (!bin) {
		return false;
	}

	rz_list_foreach (bin->methods_list, methods_iter, method) {
		ut64 start = rz_bin_java_get_method_start (bin, method),
		     end = rz_bin_java_get_method_end (bin, method);
		ut8 do_this_one = start <= func_addr && func_addr <= end;
		RzList *exc_table = NULL;
		do_this_one = func_addr == (ut64)-1? 1: do_this_one;
		if (!do_this_one) {
			continue;
		}
		exc_table = rz_bin_java_get_method_exception_table_with_addr (bin, start);

		if (rz_list_length (exc_table) == 0){
			rz_cons_printf (" Exception table for %s @ 0x%"PFMT64x":\n", method->name, start);
			rz_cons_printf (" [ NONE ]\n");
		} else {
			rz_cons_printf (" Exception table for %s (%d entries) @ 0x%"PFMT64x":\n", method->name,
				rz_list_length (exc_table) , start);
		}
		rz_list_foreach (exc_table, exc_iter, exc_entry) {
			char *class_info = rz_bin_java_resolve_without_space (bin, exc_entry->catch_type);
			rz_cons_printf ("  Catch Type: %d, %s @ 0x%"PFMT64x"\n", exc_entry->catch_type,
				class_info, exc_entry->file_offset+6);
			rz_cons_printf ("  Start PC: (0x%"PFMT64x") 0x%"PFMT64x" @ 0x%"PFMT64x"\n",
				exc_entry->start_pc, exc_entry->start_pc+start, exc_entry->file_offset);
			rz_cons_printf ("  End PC: (0x%"PFMT64x") 0x%"PFMT64x" 0x%"PFMT64x"\n",
				exc_entry->end_pc, exc_entry->end_pc+start, exc_entry->file_offset + 2);
			rz_cons_printf ("  Handler PC: (0x%"PFMT64x") 0x%"PFMT64x" 0x%"PFMT64x"\n",
				exc_entry->handler_pc, exc_entry->handler_pc+start, exc_entry->file_offset+4);
			free (class_info);
		}
	}
	return true;
}

// PLUGIN Definition Info
RzCorePlugin rz_core_plugin_java = {
	.name = "java",
	.desc = "Suite of java commands, java help for more info",
	.license = "Apache",
	.call = rz_cmd_java_call,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_java,
	.version = RZ_VERSION
};
#endif
