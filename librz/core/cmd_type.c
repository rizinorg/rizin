// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2009-2020 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 Jody Frankowski <jody.frankowski@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include "rz_analysis.h"
#include "rz_cons.h"
#include "rz_core.h"
#include <sdb.h>
#include "core_private.h"

// Calling conventions

static void types_cc_print(RzCore *core, const char *cc, RzOutputMode mode) {
	rz_return_if_fail(cc);
	if (strchr(cc, '(')) {
		if (!rz_analysis_cc_set(core->analysis, cc)) {
			eprintf("Invalid syntax in cc signature.");
		}
	} else {
		const char *ccname = rz_str_trim_head_ro(cc);
		char *result = rz_analysis_cc_get(core->analysis, ccname);
		if (result) {
			if (mode == RZ_OUTPUT_MODE_JSON) {
				PJ *pj = rz_core_pj_new(core);
				pj_a(pj);
				pj_ks(pj, "cc", result);
				pj_end(pj);
				rz_cons_println(pj_string(pj));
				pj_free(pj);
			} else {
				rz_cons_printf("%s\n", result);
			}
			free(result);
		}
	}
}

// Enums

static RzCmdStatus types_enum_member_find(RzCore *core, const char *enum_name, const char *enum_value) {
	rz_return_val_if_fail(enum_name || enum_value, RZ_CMD_STATUS_ERROR);
	Sdb *TDB = core->analysis->sdb_types;
	ut64 value = rz_num_math(core->num, enum_value);
	char *enum_member = rz_type_enum_member(TDB, enum_name, NULL, value);
	if (!enum_member) {
		eprintf("Cannot find matching enum member");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(enum_member);
	free(enum_member);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus types_enum_member_find_all(RzCore *core, const char *enum_value) {
	rz_return_val_if_fail(enum_value, RZ_CMD_STATUS_ERROR);
	Sdb *TDB = core->analysis->sdb_types;
	ut64 value = rz_num_math(core->num, enum_value);
	RzList *matches = rz_type_enum_find_member(TDB, value);
	if (!matches || rz_list_empty(matches)) {
		eprintf("Cannot find matching enum member");
		return RZ_CMD_STATUS_ERROR;
	}
	RzListIter *iter;
	char *match;
	rz_list_foreach (matches, iter, match) {
		rz_cons_println(match);
	}
	rz_list_free(matches);
	return RZ_CMD_STATUS_OK;
}

static bool print_type_c(RzCore *core, const char *ctype) {
	Sdb *TDB = core->analysis->sdb_types;
	const char *type = rz_str_trim_head_ro(ctype);
	const char *name = type ? strchr(type, '.') : NULL;
	if (name && type) {
		name++; // skip the '.'
		if (rz_str_startswith(type, "struct")) {
			rz_types_struct_print_c(TDB, name, true);
		} else if (rz_str_startswith(type, "union")) {
			rz_types_union_print_c(TDB, name, true);
		} else if (rz_str_startswith(type, "enum")) {
			rz_types_enum_print_c(TDB, name, true);
		} else if (rz_str_startswith(type, "typedef")) {
			rz_types_typedef_print_c(TDB, name);
		} else if (rz_str_startswith(type, "func")) {
			rz_types_function_print(TDB, name, RZ_OUTPUT_MODE_STANDARD, NULL);
		}
		return true;
	}
	return false;
}

static void type_list_c_all(RzCore *core) {
	Sdb *TDB = core->analysis->sdb_types;
	// List all unions in the C format with newlines
	rz_types_union_print_c(TDB, NULL, true);
	// List all structures in the C format with newlines
	rz_types_struct_print_c(TDB, NULL, true);
	// List all typedefs in the C format with newlines
	rz_types_typedef_print_c(TDB, NULL);
	// List all enums in the C format with newlines
	rz_types_enum_print_c(TDB, NULL, true);
}

static void type_list_c_all_nl(RzCore *core) {
	Sdb *TDB = core->analysis->sdb_types;
	// List all unions in the C format without newlines
	rz_types_union_print_c(TDB, NULL, false);
	// List all structures in the C format without newlines
	rz_types_struct_print_c(TDB, NULL, false);
	// List all typedefs in the C format without newlines
	rz_types_typedef_print_c(TDB, NULL);
	// List all enums in the C format without newlines
	rz_types_enum_print_c(TDB, NULL, false);
}

static RzCmdStatus type_format_print(RzCore *core, const char *type, ut64 address) {
	Sdb *TDB = core->analysis->sdb_types;
	char *fmt = rz_type_format(TDB, type);
	if (RZ_STR_ISEMPTY(fmt)) {
		eprintf("Cannot find type %s\n", type);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_cmdf(core, "pf %s @ 0x%08" PFMT64x "\n", fmt, address);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus type_format_print_variable(RzCore *core, const char *type, const char *varname) {
	Sdb *TDB = core->analysis->sdb_types;
	char *fmt = rz_type_format(TDB, type);
	if (RZ_STR_ISEMPTY(fmt)) {
		eprintf("Cannot find type \"%s\"\n", type);
		return RZ_CMD_STATUS_ERROR;
	}
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, -1);
	if (!fcn) {
		eprintf("Cannot find function at the current offset\n");
		return RZ_CMD_STATUS_ERROR;
	}
	RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, varname);
	if (!var) {
		eprintf("Cannot find variable \"%s\" in the current function\n", varname);
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 addr = rz_analysis_var_addr(var);
	rz_core_cmdf(core, "pf %s @ 0x%08" PFMT64x "\n", fmt, addr);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus type_format_print_value(RzCore *core, const char *type, ut64 val) {
	Sdb *TDB = core->analysis->sdb_types;
	char *fmt = rz_type_format(TDB, type);
	if (RZ_STR_ISEMPTY(fmt)) {
		eprintf("Cannot find type %s\n", type);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_cmdf(core, "pf %s @v:0x%08" PFMT64x "\n", fmt, val);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus type_format_print_hexstring(RzCore *core, const char *type, const char *hexpairs) {
	Sdb *TDB = core->analysis->sdb_types;
	char *fmt = rz_type_format(TDB, type);
	if (RZ_STR_ISEMPTY(fmt)) {
		eprintf("Cannot find type %s\n", type);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_cmdf(core, "pf %s @x:%s", fmt, hexpairs);
	return RZ_CMD_STATUS_OK;
}

static void types_xrefs(RzCore *core, const char *type) {
	char *type2;
	RzListIter *iter, *iter2;
	RzAnalysisFunction *fcn;
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		RzList *uniq = rz_analysis_types_from_fcn(core->analysis, fcn);
		rz_list_foreach (uniq, iter2, type2) {
			if (!strcmp(type2, type)) {
				rz_cons_printf("%s\n", fcn->name);
				break;
			}
		}
	}
}

static void types_xrefs_summary(RzCore *core) {
	char *type;
	RzListIter *iter, *iter2;
	RzAnalysisFunction *fcn;
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		RzList *uniq = rz_analysis_types_from_fcn(core->analysis, fcn);
		if (rz_list_length(uniq)) {
			rz_cons_printf("%s: ", fcn->name);
		}
		rz_list_foreach (uniq, iter2, type) {
			rz_cons_printf("%s%s", type, iter2->n ? "," : "\n");
		}
	}
}

static RzCmdStatus types_xrefs_function(RzCore *core, ut64 addr) {
	char *type;
	RzListIter *iter;
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, addr);
	if (!fcn) {
		eprintf("Cannot find function at 0x%08" PFMT64x "\n", addr);
		return RZ_CMD_STATUS_ERROR;
	}
	RzList *uniq = rz_analysis_types_from_fcn(core->analysis, fcn);
	rz_list_foreach (uniq, iter, type) {
		rz_cons_println(type);
	}
	rz_list_free(uniq);
	return RZ_CMD_STATUS_OK;
}

static void types_xrefs_graph(RzCore *core) {
	char *type;
	RzListIter *iter, *iter2;
	RzAnalysisFunction *fcn;
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		RzList *uniq = rz_analysis_types_from_fcn(core->analysis, fcn);
		if (rz_list_length(uniq)) {
			rz_cons_printf("agn %s\n", fcn->name);
		}
		rz_list_foreach (uniq, iter2, type) {
			char *myType = strdup(type);
			rz_str_replace_ch(myType, ' ', '_', true);
			rz_cons_printf("agn %s\n", myType);
			rz_cons_printf("age %s %s\n", myType, fcn->name);
			free(myType);
		}
	}
}

static void types_xrefs_all(RzCore *core) {
	char *type;
	RzListIter *iter, *iter2;
	RzAnalysisFunction *fcn;
	RzList *uniqList = rz_list_newf(free);
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		RzList *uniq = rz_analysis_types_from_fcn(core->analysis, fcn);
		rz_list_foreach (uniq, iter2, type) {
			if (!rz_list_find(uniqList, type, (RzListComparator)strcmp)) {
				rz_list_push(uniqList, strdup(type));
			}
		}
	}
	rz_list_sort(uniqList, (RzListComparator)strcmp);
	rz_list_foreach (uniqList, iter, type) {
		rz_cons_printf("%s\n", type);
	}
	rz_list_free(uniqList);
}

// =============================================================================
//                             DEPRECATED

static const char *help_msg_t[] = {
	"Usage: t", "", "# cparse types commands",
	"t", "", "List all loaded types",
	"tj", "", "List all loaded types as json",
	"t", " <type>", "Show type in 'pf' syntax",
	"t*", "", "List types info in rizin commands",
	"t-", " <name>", "Delete types by its name",
	"t-*", "", "Remove all types",
	"tc", " [type.name]", "List all/given types in C output format",
	"te", "[?]", "List all loaded enums",
	"td", "[?] <string>", "Load types from string",
	"tf", "", "List all loaded functions signatures",
	"tk", " <sdb-query>", "Perform sdb query",
	"tl", "[?]", "Show/Link type to an address",
	"tn", "[?] [-][addr]", "manage noreturn function attributes and marks",
	"to", " -", "Open cfg.editor to load types",
	"to", " <path>", "Load types from C header file",
	"toe", " [type.name]", "Open cfg.editor to edit types",
	"tos", " <path>", "Load types from parsed Sdb database",
	"tp", "  <type> [addr|varname]", "cast data at <address> to <type> and print it (XXX: type can contain spaces)",
	"tpv", " <type> @ [value]", "Show offset formatted for given type",
	"tpx", " <type> <hexpairs>", "Show value for type with specified byte sequence (XXX: type can contain spaces)",
	"ts", "[?]", "Print loaded struct types",
	"tu", "[?]", "Print loaded union types",
	"tx", "[f?]", "Type xrefs",
	"tt", "[?]", "List all loaded typedefs",
	NULL
};

static const char *help_msg_tcc[] = {
	"Usage: tcc", "[-name]", "# type function calling conventions",
	"tcc", "", "List all calling convcentions",
	"tcc", " r0 pascal(r0,r1,r2)", "Show signature for the 'pascal' calling convention",
	"tcc", "-pascal", "Remove the pascal cc",
	"tcc-*", "", "Unregister all the calling conventions",
	"tcck", "", "List calling conventions in k=v",
	"tccl", "", "List the cc signatures",
	"tccj", "", "List them in JSON",
	"tcc*", "", "List them as rizin commands",
	NULL
};

static const char *help_msg_t_minus[] = {
	"Usage: t-", " <type>", "Delete type by its name",
	NULL
};

static const char *help_msg_tf[] = {
	"Usage: tf[...]", "", "",
	"tf", "", "List all function definitions loaded",
	"tf", " <name>", "Show function signature in C syntax",
	"tfj", "", "List all function definitions in JSON",
	"tfj", " <name>", "Show function signature in JSON",
	"tfk", "", "List all function definitions in SDB format",
	"tfk", " <name>", "Show function signature in SDB format",
	NULL
};

static const char *help_msg_to[] = {
	"Usage: to[...]", "", "",
	"to", " -", "Open cfg.editor to load types",
	"to", " <path>", "Load types from C header file",
	"tos", " <path>", "Load types from parsed Sdb database",
	NULL
};

static const char *help_msg_tp[] = {
	"Usage: tp[...]", "", "",
	"tp", "  <type> [addr|varname]", "cast data at <address> to <type> and print it (XXX: type can contain spaces)",
	"tpv", " <type> @ [value]", "Show offset formatted for given type",
	"tpx", " <type> <hexpairs>", "Show value for type with specified byte sequence (XXX: type can contain spaces)",
	NULL
};

static const char *help_msg_tc[] = {
	"Usage: tc[...]", " [cctype]", "",
	"tc", " [type.name]", "List all/given loaded types in C output format with newlines",
	"tcd", "", "List all loaded types in C output format without newlines",
	"tcc", "?", "Manage calling conventions types",
	"tc?", "", "show this help",
	NULL
};

static const char *help_msg_td[] = {
	"Usage:", "td \"[...]\"", "",
	"td", "[string]", "Load types from string",
	NULL
};

static const char *help_msg_te[] = {
	"Usage: te[...]", "", "",
	"te", "", "List all loaded enums",
	"te", " <enum>", "Print all values of enum for given name",
	"tej", "", "List all loaded enums in json",
	"tej", " <enum>", "Show enum in json",
	"te", " <enum> <value>", "Show name for given enum number",
	"teb", " <enum> <name>", "Show matching enum bitfield for given name",
	"tec", "<name>", "List all/given loaded enums in C output format with newlines",
	"ted", "", "List all loaded enums in C output format without newlines",
	"tef", " <value>", "Find enum and member by the member value",
	"te?", "", "show this help",
	NULL
};

static const char *help_msg_tt[] = {
	"Usage: tt[...]", "", "",
	"tt", "", "List all loaded typedefs",
	"tt", " <typename>", "Show name for given type alias",
	"ttj", "", "Show typename and type alias in json",
	"ttc", "<name>", "Show typename and type alias in C output format",
	"tt?", "", "show this help",
	NULL
};

static const char *help_msg_tl[] = {
	"Usage: tl[...]", "[typename] [[=] address]", "# Type link commands",
	"tl", "", "list all links.",
	"tll", "", "list all links in readable format.",
	"tllj", "", "list all links in readable JSON format.",
	"tl", " [typename]", "link a type to current address.",
	"tl", " [typename] [address]", "link type to given address.",
	"tls", " [address]", "show link at given address.",
	"tl-*", "", "delete all links.",
	"tl-", " [address]", "delete link at given address.",
	"tl*", "", "list all links in rizin command format.",
	"tlj", "", "list all links in JSON format.",
	NULL
};

static const char *help_msg_tn[] = {
	"Usage:", "tn [-][0xaddr|symname]", " manage no-return marks",
	"tn[a]", " 0x3000", "stop function analysis if call/jmp to this address",
	"tn[n]", " sym.imp.exit", "same as above but for flag/fcn names",
	"tn-", " 0x3000 sym.imp.exit ...", "remove some no-return references",
	"tn-*", "", "remove all no-return references",
	"tn", "", "list them all",
	NULL
};

static const char *help_msg_ts[] = {
	"Usage: ts[...]", " [type]", "",
	"ts", "", "List all loaded structs",
	"ts", " [type]", "Show pf format string for given struct",
	"tsj", "", "List all loaded structs in json",
	"tsj", " [type]", "Show pf format string for given struct in json",
	"ts*", "", "Show pf.<name> format string for all loaded structs",
	"ts*", " [type]", "Show pf.<name> format string for given struct",
	"tsc", "<name>", "List all/given loaded structs in C output format with newlines",
	"tsd", "", "List all loaded structs in C output format without newlines",
	"tss", " [type]", "Display size of struct",
	"ts", "[?]", "show this help",
	NULL
};

static const char *help_msg_tu[] = {
	"Usage: tu[...]", "", "",
	"tu", "", "List all loaded unions",
	"tu", " [type]", "Show pf format string for given union",
	"tuj", "", "List all loaded unions in json",
	"tuj", " [type]", "Show pf format string for given union in json",
	"tu*", "", "Show pf.<name> format string for all loaded unions",
	"tu*", " [type]", "Show pf.<name> format string for given union",
	"tuc", "<name>", "List all/given loaded unions in C output format with newlines",
	"tud", "", "List all loaded unions in C output format without newlines",
	"tu?", "", "show this help",
	NULL
};

static void __core_cmd_tcc(RzCore *core, const char *input) {
	switch (*input) {
	case '?':
		rz_core_cmd_help(core, help_msg_tcc);
		break;
	case '-':
		if (input[1] == '*') {
			sdb_reset(core->analysis->sdb_cc);
		} else {
			rz_analysis_cc_del(core->analysis, rz_str_trim_head_ro(input + 1));
		}
		break;
	case 0:
		rz_core_types_calling_conventions_print(core, RZ_OUTPUT_MODE_STANDARD);
		break;
	case 'j':
		rz_core_types_calling_conventions_print(core, RZ_OUTPUT_MODE_JSON);
		break;
	case 'l':
		rz_core_types_calling_conventions_print(core, RZ_OUTPUT_MODE_LONG);
		break;
	case '*':
		rz_core_types_calling_conventions_print(core, RZ_OUTPUT_MODE_RIZIN);
		break;
	case 'k':
		rz_core_types_calling_conventions_print(core, RZ_OUTPUT_MODE_SDB);
		break;
	case ' ':
		types_cc_print(core, input + 1, RZ_OUTPUT_MODE_STANDARD);
		break;
	}
}

static void noreturn_del(RzCore *core, const char *s) {
	RzListIter *iter;
	char *k;
	RzList *list = rz_str_split_duplist(s, " ", false);
	rz_list_foreach (list, iter, k) {
		rz_analysis_noreturn_drop(core->analysis, k);
	}
	rz_list_free(list);
}

static void cmd_type_noreturn(RzCore *core, const char *input) {
	switch (input[0]) {
	case '-': // "tn-"
		if (input[1] == '*') {
			RzList *noretl = rz_types_function_noreturn(core->analysis->sdb_types);
			RzListIter *iter;
			char *name;
			rz_list_foreach (noretl, iter, name) {
				rz_analysis_noreturn_drop(core->analysis, name);
			}
		} else {
			char *s = strdup(rz_str_trim_head_ro(input + 1));
			noreturn_del(core, s);
			free(s);
		}
		break;
	case ' ': // "tn"
	{
		const char *arg = rz_str_trim_head_ro(input + 1);
		ut64 n = rz_num_math(core->num, arg);
		if (n) {
			rz_analysis_noreturn_add(core->analysis, arg, n);
		} else {
			rz_analysis_noreturn_add(core->analysis, arg, UT64_MAX);
		}
	} break;
	case 'a': // "tna"
		if (input[1] == ' ') {
			rz_analysis_noreturn_add(core->analysis, NULL,
				rz_num_math(core->num, input + 1));
		} else {
			rz_core_cmd_help(core, help_msg_tn);
		}
		break;
	case 'n': // "tnn"
		if (input[1] == ' ') {
			/* do nothing? */
			rz_analysis_noreturn_add(core->analysis, rz_str_trim_head_ro(input + 2), UT64_MAX);
		} else {
			rz_core_cmd_help(core, help_msg_tn);
		}
		break;
	case '*':
	case 'r': // "tn*"
		rz_core_types_function_noreturn_print(core, RZ_OUTPUT_MODE_RIZIN);
		break;
	case 'j': // "tnj"
		rz_core_types_function_noreturn_print(core, RZ_OUTPUT_MODE_JSON);
		break;
	case 0: // "tn"
		rz_core_types_function_noreturn_print(core, RZ_OUTPUT_MODE_STANDARD);
		break;
	default:
	case '?':
		rz_core_cmd_help(core, help_msg_tn);
		break;
	}
}

static void types_list(RzCore *core, int mode) {
	switch (mode) {
	case 1:
	case '*':
		rz_core_types_print_all(core, RZ_OUTPUT_MODE_RIZIN);
		break;
	case 'j':
		rz_core_types_print_all(core, RZ_OUTPUT_MODE_JSON);
		break;
	default:
		rz_core_types_print_all(core, RZ_OUTPUT_MODE_STANDARD);
		break;
	}
}

RZ_IPI int rz_cmd_type(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	Sdb *TDB = core->analysis->sdb_types;
	char *res;

	switch (input[0]) {
	case 'n': // "tn"
		cmd_type_noreturn(core, input + 1);
		break;
	// t [typename] - show given type in C syntax
	case 'u': { // "tu"
		switch (input[1]) {
		case '?':
			rz_core_cmd_help(core, help_msg_tu);
			break;
		case '*':
			if (input[2] == ' ') {
				rz_core_types_show_format(core, rz_str_trim_head_ro(input + 2), RZ_OUTPUT_MODE_RIZIN);
			} else {
				rz_core_types_union_print_format_all(core, TDB);
			}
			break;
		case 'j': // "tuj"
			if (input[2]) {
				rz_core_types_show_format(core, rz_str_trim_head_ro(input + 2), RZ_OUTPUT_MODE_JSON);
				rz_cons_newline();
			} else {
				rz_types_union_print_json(TDB);
			}
			break;
		case 'c': // "tuc"
			rz_types_union_print_c(TDB, rz_str_trim_head_ro(input + 2), true);
			break;
		case 'd': // "tud"
			rz_types_union_print_c(TDB, rz_str_trim_head_ro(input + 2), false);
			break;
		case ' ': // "tu "
			rz_core_types_show_format(core, rz_str_trim_head_ro(input + 1), RZ_OUTPUT_MODE_STANDARD);
			break;
		case 0:
			rz_types_union_print_sdb(TDB);
			break;
		}
	} break;
	case 'k': // "tk"
		res = (input[1] == ' ')
			? sdb_querys(TDB, NULL, -1, input + 2)
			: sdb_querys(TDB, NULL, -1, "*");
		if (res) {
			rz_cons_print(res);
			free(res);
		}
		break;
	case 'c': // "tc"
		switch (input[1]) {
		case 'c': // "tcc" -- calling conventions
			__core_cmd_tcc(core, input + 2);
			break;
		case '?': //"tc?"
			rz_core_cmd_help(core, help_msg_tc);
			break;
		case ' ':
			print_type_c(core, input + 1);
			break;
		case '*':
			rz_core_cmd0(core, "ts*");
			break;
		case 0:
			type_list_c_all(core);
			break;
		case 'd':
			type_list_c_all_nl(core);
			break;
		default:
			rz_core_cmd_help(core, help_msg_tc);
			break;
		}
		break;
	case 's': { // "ts"
		switch (input[1]) {
		case '?':
			rz_core_cmd_help(core, help_msg_ts);
			break;
		case '*':
			if (input[2] == ' ') {
				rz_core_types_show_format(core, rz_str_trim_head_ro(input + 1), RZ_OUTPUT_MODE_RIZIN);
			} else {
				rz_core_types_struct_print_format_all(core, TDB);
			}
			break;
		case ' ':
			rz_core_types_show_format(core, rz_str_trim_head_ro(input + 1), RZ_OUTPUT_MODE_STANDARD);
			break;
		case 's':
			if (input[2] == ' ') {
				rz_cons_printf("%" PFMT64u "\n", (rz_type_get_bitsize(TDB, input + 3) / 8));
			} else {
				rz_core_cmd_help(core, help_msg_ts);
			}
			break;
		case 0:
			rz_types_struct_print_sdb(TDB);
			break;
		case 'c': // "tsc"
			rz_types_struct_print_c(TDB, rz_str_trim_head_ro(input + 2), true);
			break;
		case 'd': // "tsd"
			rz_types_struct_print_c(TDB, rz_str_trim_head_ro(input + 2), false);
			break;
		case 'j': // "tsj"
			// TODO: current output is a bit poor, will be good to improve
			if (input[2]) {
				rz_core_types_show_format(core, rz_str_trim_head_ro(input + 2), RZ_OUTPUT_MODE_JSON);
				rz_cons_newline();
			} else {
				rz_types_struct_print_json(TDB);
			}
			break;
		}
	} break;
	case 'e': { // "te"
		char *res = NULL, *temp = strchr(input, ' ');
		Sdb *TDB = core->analysis->sdb_types;
		char *name = temp ? strdup(temp + 1) : NULL;
		char *member_value = name ? strchr(name, ' ') : NULL;

		if (member_value) {
			*member_value++ = 0;
		}
		if (name && (rz_type_kind(TDB, name) != RZ_TYPE_ENUM)) {
			eprintf("%s is not an enum\n", name);
			free(name);
			break;
		}
		switch (input[1]) {
		case '?':
			rz_core_cmd_help(core, help_msg_te);
			break;
		case 'j': // "tej"
			if (input[2] == 0) { // "tej"
				rz_core_types_enum_print_all(core, RZ_OUTPUT_MODE_JSON);
			} else { // "tej ENUM"
				if (member_value) {
					types_enum_member_find(core, name, member_value);
				} else {
					PJ *pj = rz_core_pj_new(core);
					rz_core_types_enum_print(core, name, RZ_OUTPUT_MODE_JSON, pj);
					pj_end(pj);
					rz_cons_println(pj_string(pj));
					pj_free(pj);
				}
			}
			break;
		case 'k': // "tek"
			if (input[2] == 0) { // "tek"
				rz_core_types_enum_print_all(core, RZ_OUTPUT_MODE_SDB);
			} else { // "tek ENUM"
				rz_core_types_enum_print(core, name, RZ_OUTPUT_MODE_SDB, NULL);
			}
			break;
		case 'b': // "teb"
			res = rz_type_enum_member(TDB, name, member_value, 0);
			break;
		case 'c': // "tec"
			rz_types_enum_print_c(TDB, rz_str_trim_head_ro(input + 2), true);
			break;
		case 'd': // "ted"
			rz_types_enum_print_c(TDB, rz_str_trim_head_ro(input + 2), false);
			break;
		case 'f': // "tef"
			if (member_value) {
				types_enum_member_find_all(core, member_value);
			}
			break;
		case ' ':
			if (member_value) {
				types_enum_member_find(core, name, member_value);
			} else {
				rz_core_types_enum_print(core, name, RZ_OUTPUT_MODE_STANDARD, NULL);
			}
			break;
		case '\0': {
			rz_core_types_enum_print_all(core, RZ_OUTPUT_MODE_QUIET);
		} break;
		}
		free(name);
		if (res) {
			rz_cons_println(res);
		} else if (member_value) {
			eprintf("Invalid enum member value\n");
		}
	} break;
	case ' ':
		rz_core_types_show_format(core, input + 1, RZ_OUTPUT_MODE_STANDARD);
		break;
	// t* - list all types in 'pf' syntax
	case 'j': // "tj"
	case '*': // "t*"
	case 0: // "t"
		types_list(core, input[0]);
		break;
	case 'o': // "to"
		if (input[1] == '?') {
			rz_core_cmd_help(core, help_msg_to);
			break;
		}
		if (input[1] == ' ') {
			rz_types_open_file(core, input + 2);
		} else if (input[1] == 's') { // "tos"
			rz_types_open_sdb(core, input + 3);
		} else if (input[1] == 'e') { // "toe"
			rz_types_open_editor(core, input + 2);
		}
		break;
	// td - parse string with cparse engine and load types from it
	case 'd': // "td"
		if (input[1] == '?') {
			// TODO #7967 help refactor: move to detail
			rz_core_cmd_help(core, help_msg_td);
			rz_cons_printf("Note: The td command should be put between double quotes\n"
				       "Example: td \"struct foo {int bar;int cow;};\""
				       "\nt");

		} else if (input[1] == ' ') {
			rz_types_define(core, input + 2);
		} else {
			eprintf("Invalid use of td. See td? for help\n");
		}
		break;
	case 'x': {
		char *type;
		switch (input[1]) {
		case '.': // "tx." type xrefs
		case 'f': // "txf" type xrefs
		{
			ut64 addr = core->offset;
			if (input[2] == ' ') {
				addr = rz_num_math(core->num, input + 2);
			}
			types_xrefs_function(core, addr);
		} break;
		case 0: // "tx"
			types_xrefs_summary(core);
			break;
		case 'g': // "txg"
			types_xrefs_graph(core);
			break;
		case 'l': // "txl"
			types_xrefs_all(core);
			break;
		case ' ': // "tx " -- show which function use given type
			type = (char *)rz_str_trim_head_ro(input + 2);
			types_xrefs(core, type);
			break;
		default:
			eprintf("Usage: tx[flg] [...]\n");
			eprintf(" txf | tx.      list all types used in this function\n");
			eprintf(" txf 0xaddr     list all types used in function at 0xaddr\n");
			eprintf(" txl            list all types used by any function\n");
			eprintf(" txg            render the type xrefs graph (usage .txg;aggv)\n");
			eprintf(" tx int32_t     list functions names using this type\n");
			eprintf(" tx             list functions and the types they use\n");
			break;
		}
	} break;
	// ta: moved to analysis hints (aht)- just for tail, at the moment
	// tl - link a type to an address
	case 'l': // "tl"
		switch (input[1]) {
		case '?':
			rz_core_cmd_help(core, help_msg_tl);
			break;
		case ' ': {
			char *type = strdup(input + 2);
			char *ptr = strchr(type, ' ');
			ut64 addr = core->offset;

			if (ptr) {
				*ptr++ = 0;
				rz_str_trim(ptr);
				if (ptr && *ptr) {
					addr = rz_num_math(core->num, ptr);
				} else {
					eprintf("tl: Address is unvalid\n");
					free(type);
					break;
				}
			}
			rz_str_trim(type);
			rz_core_types_link(core, type, addr);
			free(type);
			break;
		}
		case 's': {
			char *ptr = rz_str_trim_dup(input + 2);
			ut64 addr = rz_num_math(core->num, ptr);
			rz_core_types_link_show(core, addr);
			free(ptr);
			break;
		}
		case '-':
			switch (input[2]) {
			case '*':
				rz_type_unlink_all(TDB);
				break;
			case ' ': {
				const char *ptr = input + 3;
				ut64 addr = rz_num_math(core->num, ptr);
				rz_type_unlink(TDB, addr);
				break;
			}
			}
			break;
		case '*':
			rz_core_types_link_print_all(core, RZ_OUTPUT_MODE_RIZIN);
			break;
		case 'l':
			rz_core_types_link_print_all(core, RZ_OUTPUT_MODE_LONG);
			break;
		case 'j':
			rz_core_types_link_print_all(core, RZ_OUTPUT_MODE_JSON);
			break;
		case '\0':
			rz_core_types_link_print_all(core, RZ_OUTPUT_MODE_STANDARD);
			break;
		}
		break;
	case 'p': // "tp"
		if (input[1] == '?') { // "tp?"
			rz_core_cmd_help(core, help_msg_tp);
		} else if (input[1] == 'v') { // "tpv"
			const char *type_name = rz_str_trim_head_ro(input + 2);
			ut64 val = core->offset;
			type_format_print_value(core, type_name, val);
		} else if (input[1] == ' ' || input[1] == 'x' || !input[1]) {
			char *tmp = strdup(input);
			char *type_begin = strchr(tmp, ' ');
			if (type_begin) {
				rz_str_trim(type_begin);
				const char *type_end = rz_str_rchr(type_begin, NULL, ' ');
				int type_len = (type_end)
					? (int)(type_end - type_begin)
					: strlen(type_begin);
				char *type = strdup(type_begin);
				if (!type) {
					free(tmp);
					break;
				}
				snprintf(type, type_len + 1, "%s", type_begin);
				const char *arg = (type_end) ? type_end + 1 : NULL;
				if (input[1] == 'x') {
					type_format_print_hexstring(core, type, arg);
				} else {
					ut64 addr = arg ? rz_num_math(core->num, arg) : core->offset;
					if (!addr && arg) {
						type_format_print_variable(core, type, arg);
					} else {
						type_format_print(core, type, addr);
					}
				}
				free(type);
			} else {
				eprintf("Usage: tp?\n");
			}
			free(tmp);
		} else { // "tp"
			eprintf("Usage: tp?\n");
		}
		break;
	case '-': // "t-"
		if (input[1] == '?') {
			rz_core_cmd_help(core, help_msg_t_minus);
		} else if (input[1] == '*') {
			sdb_reset(TDB);
			rz_parse_c_reset(core->parser);
		} else {
			const char *name = rz_str_trim_head_ro(input + 1);
			if (*name) {
				rz_analysis_remove_parsed_type(core->analysis, name);
			} else {
				eprintf("Invalid use of t- . See t-? for help.\n");
			}
		}
		break;
	// tv - get/set type value linked to a given address
	case 'f': // "tf"
		switch (input[1]) {
		case 0: // "tf"
			rz_core_types_function_print_all(core, RZ_OUTPUT_MODE_STANDARD);
			break;
		case 'k': // "tfk"
			if (input[2] == ' ') {
				const char *name = rz_str_trim_head_ro(input + 3);
				rz_types_function_print(TDB, name, RZ_OUTPUT_MODE_SDB, NULL);
			} else {
				rz_core_types_function_print_all(core, RZ_OUTPUT_MODE_SDB);
			}
			break;
		case 'j': // "tfj"
			if (input[2] == ' ') {
				const char *name = rz_str_trim_head_ro(input + 2);
				PJ *pj = rz_core_pj_new(core);
				rz_types_function_print(TDB, name, RZ_OUTPUT_MODE_JSON, pj);
				pj_end(pj);
				rz_cons_println(pj_string(pj));
				pj_free(pj);
			} else {
				rz_core_types_function_print_all(core, RZ_OUTPUT_MODE_JSON);
			}
			break;
		case ' ': {
			const char *name = rz_str_trim_head_ro(input + 2);
			rz_types_function_print(TDB, name, RZ_OUTPUT_MODE_SDB, NULL);
			break;
		}
		default:
			rz_core_cmd_help(core, help_msg_tf);
			break;
		}
		break;
	case 't': { // "tt"
		RzOutputMode mode;
		if (input[1] == 'j') { // "ttj"
			mode = RZ_OUTPUT_MODE_JSON;
			rz_core_list_loaded_typedefs(core, mode);
			break;
		}
		if (input[1] == 'c') { // "ttc"
			rz_types_typedef_print_c(TDB, input + 2);
			break;
		}
		if (input[1] == '?') { // "tt?"
			rz_core_cmd_help(core, help_msg_tt);
			break;
		}
		if (!input[1]) { // "tt"
			rz_core_list_loaded_typedefs(core, RZ_OUTPUT_MODE_STANDARD);
			break;
		}
		char *s = strdup(input + 2);
		rz_core_types_typedef_info(core, s);
		free(s);
	} break;
	case '?':
		rz_core_cmd_help(core, help_msg_t);
		break;
	}
	return true;
}

// =============================================================================
//                        END    DEPRECATED

RZ_IPI RzCmdStatus rz_type_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *type = argc > 1 ? argv[1] : NULL;
	if (type) {
		rz_core_types_show_format(core, type, mode);
	} else {
		rz_core_types_print_all(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_del_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_remove_parsed_type(core->analysis, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_del_all_handler(RzCore *core, int argc, const char **argv) {
	sdb_reset(core->analysis->sdb_types);
	rz_parse_c_reset(core->parser);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_cc_list_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *cc = argc > 1 ? argv[1] : NULL;
	if (cc) {
		types_cc_print(core, cc, mode);
	} else {
		rz_core_types_calling_conventions_print(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_cc_del_handler(RzCore *core, int argc, const char **argv) {
	const char *cc = argc > 1 ? argv[1] : NULL;
	rz_analysis_cc_del(core->analysis, cc);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_cc_del_all_handler(RzCore *core, int argc, const char **argv) {
	sdb_reset(core->analysis->sdb_cc);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_c_handler(RzCore *core, int argc, const char **argv) {
	const char *ctype = argc > 1 ? argv[1] : NULL;
	if (!ctype) {
		type_list_c_all(core);
		return RZ_CMD_STATUS_OK;
	}
	if (!print_type_c(core, ctype)) {
		eprintf("Wrong type syntax");
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_c_nl_handler(RzCore *core, int argc, const char **argv) {
	type_list_c_all_nl(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_define_handler(RzCore *core, int argc, const char **argv) {
	const char *type = argc > 1 ? argv[1] : NULL;
	rz_types_define(core, type);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_enum_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *enum_name = argc > 1 ? argv[1] : NULL;
	// TODO: Reconsider the `te <enum_name> <member_value>` syntax change
	const char *member_value = argc > 2 ? argv[2] : NULL;
	if (enum_name) {
		if (member_value) {
			return types_enum_member_find(core, enum_name, member_value);
		} else {
			PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? rz_core_pj_new(core) : NULL;
			rz_core_types_enum_print(core, enum_name, mode, pj);
			if (mode == RZ_OUTPUT_MODE_JSON) {
				rz_cons_println(pj_string(pj));
				pj_free(pj);
			}
		}
	} else {
		// A special case, since by default `te` returns only the list of all enums
		if (mode == RZ_OUTPUT_MODE_STANDARD) {
			mode = RZ_OUTPUT_MODE_QUIET;
		}
		rz_core_types_enum_print_all(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_enum_bitfield_handler(RzCore *core, int argc, const char **argv) {
	const char *enum_name = argc > 1 ? argv[1] : NULL;
	const char *enum_member = argc > 2 ? argv[2] : NULL;
	Sdb *TDB = core->analysis->sdb_types;
	char *output = rz_type_enum_member(TDB, enum_name, enum_member, 0);
	if (!output) {
		eprintf("Cannot find anything matching the specified bitfield");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(output);
	free(output);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_enum_c_handler(RzCore *core, int argc, const char **argv) {
	const char *enum_name = argc > 1 ? argv[1] : NULL;
	Sdb *TDB = core->analysis->sdb_types;
	rz_types_enum_print_c(TDB, enum_name, true);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_enum_c_nl_handler(RzCore *core, int argc, const char **argv) {
	const char *enum_name = argc > 1 ? argv[1] : NULL;
	Sdb *TDB = core->analysis->sdb_types;
	rz_types_enum_print_c(TDB, enum_name, false);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_enum_find_handler(RzCore *core, int argc, const char **argv) {
	const char *enum_value = argc > 1 ? argv[1] : NULL;
	return types_enum_member_find_all(core, enum_value);
}

RZ_IPI RzCmdStatus rz_type_list_function_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *function = argc > 1 ? argv[1] : NULL;
	if (function) {
		PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? rz_core_pj_new(core) : NULL;
		rz_types_function_print(core->analysis->sdb_types, function, mode, pj);
		if (mode == RZ_OUTPUT_MODE_JSON) {
			rz_cons_println(pj_string(pj));
			pj_free(pj);
		}
	} else {
		rz_core_types_function_print_all(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_kuery_handler(RzCore *core, int argc, const char **argv) {
	const char *query = argc > 1 ? argv[1] : NULL;
	Sdb *TDB = core->analysis->sdb_types;
	char *output = NULL;
	if (query) {
		output = sdb_querys(TDB, NULL, -1, query);
	} else {
		output = sdb_querys(TDB, NULL, -1, "*");
	}
	if (!output) {
		eprintf("Cannot find anything matching your query");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_print(output);
	free(output);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_link_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *name = argc > 1 ? argv[1] : NULL;
	ut64 addr = argc > 2 ? rz_num_math(core->num, argv[2]) : core->offset;
	if (name) {
		rz_core_types_link(core, name, addr);
	} else {
		rz_core_types_link_print_all(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_link_show_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = rz_num_math(core->num, argv[1]);
	rz_core_types_link_show(core, addr);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_link_del_handler(RzCore *core, int argc, const char **argv) {
	Sdb *TDB = core->analysis->sdb_types;
	ut64 addr = rz_num_math(core->num, argv[1]);
	rz_type_unlink(TDB, addr);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_link_del_all_handler(RzCore *core, int argc, const char **argv) {
	Sdb *TDB = core->analysis->sdb_types;
	rz_type_unlink_all(TDB);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_noreturn_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *name = argc > 1 ? argv[1] : NULL;
	if (name) {
		ut64 n = rz_num_math(core->num, name);
		if (n) {
			rz_analysis_noreturn_add(core->analysis, name, n);
		} else {
			rz_analysis_noreturn_add(core->analysis, name, UT64_MAX);
		}
	} else {
		rz_core_types_function_noreturn_print(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_noreturn_del_handler(RzCore *core, int argc, const char **argv) {
	for (int i = 1; i < argc; i++) {
		rz_analysis_noreturn_drop(core->analysis, argv[i]);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_noreturn_del_all_handler(RzCore *core, int argc, const char **argv) {
	RzList *noretl = rz_types_function_noreturn(core->analysis->sdb_types);
	RzListIter *iter;
	char *name;
	rz_list_foreach (noretl, iter, name) {
		rz_analysis_noreturn_drop(core->analysis, name);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_open_file_handler(RzCore *core, int argc, const char **argv) {
	rz_types_open_file(core, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_open_editor_handler(RzCore *core, int argc, const char **argv) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	rz_types_open_editor(core, typename);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_open_sdb_handler(RzCore *core, int argc, const char **argv) {
	rz_types_open_sdb(core, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_print_handler(RzCore *core, int argc, const char **argv) {
	const char *addr_or_var = argc > 2 ? argv[2] : NULL;
	if (!addr_or_var) {
		return type_format_print(core, argv[1], core->offset);
	}
	ut64 addr = rz_num_math(core->num, addr_or_var);
	if (!addr) {
		return type_format_print_variable(core, argv[1], addr_or_var);
	}
	return type_format_print(core, argv[1], addr);
}

RZ_IPI RzCmdStatus rz_type_print_value_handler(RzCore *core, int argc, const char **argv) {
	const char *value = argc > 2 ? argv[2] : NULL;
	if (!value) {
		return type_format_print_value(core, argv[1], core->offset);
	}
	return type_format_print_value(core, argv[1], rz_num_math(core->num, value));
}

RZ_IPI RzCmdStatus rz_type_print_hexstring_handler(RzCore *core, int argc, const char **argv) {
	return type_format_print_hexstring(core, argv[1], argv[2]);
}

RZ_IPI RzCmdStatus rz_type_list_structure_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	Sdb *TDB = core->analysis->sdb_types;
	if (typename) {
		rz_core_types_show_format(core, typename, mode);
	} else {
		if (mode == RZ_OUTPUT_MODE_RIZIN) {
			rz_core_types_struct_print_format_all(core, TDB);
		} else if (mode == RZ_OUTPUT_MODE_JSON) {
			rz_types_struct_print_json(TDB);
		} else {
			rz_types_struct_print_sdb(TDB);
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_structure_c_handler(RzCore *core, int argc, const char **argv) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	Sdb *TDB = core->analysis->sdb_types;
	rz_types_struct_print_c(TDB, typename, true);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_structure_c_nl_handler(RzCore *core, int argc, const char **argv) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	Sdb *TDB = core->analysis->sdb_types;
	rz_types_struct_print_c(TDB, typename, false);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_typedef_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	if (typename) {
		if (!rz_core_types_typedef_info(core, typename)) {
			eprintf("Can't find typedef");
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		rz_core_list_loaded_typedefs(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_typedef_c_handler(RzCore *core, int argc, const char **argv) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	Sdb *TDB = core->analysis->sdb_types;
	if (!typename) {
		rz_types_typedef_print_c(TDB, NULL);
		return RZ_CMD_STATUS_OK;
	}
	rz_types_typedef_print_c(TDB, typename);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_union_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	Sdb *TDB = core->analysis->sdb_types;
	if (typename) {
		rz_core_types_show_format(core, typename, mode);
	} else {
		if (mode == RZ_OUTPUT_MODE_RIZIN) {
			rz_core_types_union_print_format_all(core, TDB);
		} else if (mode == RZ_OUTPUT_MODE_JSON) {
			rz_types_union_print_json(TDB);
		} else {
			rz_types_union_print_sdb(TDB);
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_union_c_handler(RzCore *core, int argc, const char **argv) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	Sdb *TDB = core->analysis->sdb_types;
	rz_types_union_print_c(TDB, typename, true);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_union_c_nl_handler(RzCore *core, int argc, const char **argv) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	Sdb *TDB = core->analysis->sdb_types;
	rz_types_union_print_c(TDB, typename, false);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_xrefs_list_handler(RzCore *core, int argc, const char **argv) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	if (typename) {
		types_xrefs(core, typename);
	} else {
		types_xrefs_summary(core);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_xrefs_function_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = argc > 1 ? rz_num_math(core->num, argv[1]) : core->offset;
	return types_xrefs_function(core, addr);
}

RZ_IPI RzCmdStatus rz_type_xrefs_graph_handler(RzCore *core, int argc, const char **argv) {
	types_xrefs_graph(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_xrefs_list_all_handler(RzCore *core, int argc, const char **argv) {
	types_xrefs_all(core);
	return RZ_CMD_STATUS_OK;
}
