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
				PJ *pj = pj_new();
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
	ut64 value = rz_num_math(core->num, enum_value);
	char *enum_member = rz_type_db_enum_member_by_val(core->analysis->typedb, enum_name, value);
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
	ut64 value = rz_num_math(core->num, enum_value);
	RzList *matches = rz_type_db_find_enums_by_val(core->analysis->typedb, value);
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
	const char *type = rz_str_trim_head_ro(ctype);
	const char *name = type ? strchr(type, '.') : NULL;
	if (name && type) {
		name++; // skip the '.'
		if (rz_str_startswith(type, "struct")) {
			rz_core_types_struct_print_c(core->analysis->typedb, name, true);
		} else if (rz_str_startswith(type, "union")) {
			rz_core_types_union_print_c(core->analysis->typedb, name, true);
		} else if (rz_str_startswith(type, "enum")) {
			rz_core_types_enum_print_c(core->analysis->typedb, name, true);
		} else if (rz_str_startswith(type, "typedef")) {
			rz_core_types_typedef_print_c(core->analysis->typedb, name);
		} else if (rz_str_startswith(type, "func")) {
			rz_types_function_print(core->analysis->typedb, name, RZ_OUTPUT_MODE_STANDARD, NULL);
		}
		return true;
	}
	return false;
}

static void type_list_c_all(RzCore *core) {
	// List all unions in the C format with newlines
	rz_core_types_union_print_c(core->analysis->typedb, NULL, true);
	// List all structures in the C format with newlines
	rz_core_types_struct_print_c(core->analysis->typedb, NULL, true);
	// List all typedefs in the C format with newlines
	rz_core_types_typedef_print_c(core->analysis->typedb, NULL);
	// List all enums in the C format with newlines
	rz_core_types_enum_print_c_all(core->analysis->typedb, true);
}

static void type_list_c_all_nl(RzCore *core) {
	// List all unions in the C format without newlines
	rz_core_types_union_print_c(core->analysis->typedb, NULL, false);
	// List all structures in the C format without newlines
	rz_core_types_struct_print_c(core->analysis->typedb, NULL, false);
	// List all typedefs in the C format without newlines
	rz_core_types_typedef_print_c(core->analysis->typedb, NULL);
	// List all enums in the C format without newlines
	rz_core_types_enum_print_c_all(core->analysis->typedb, false);
}

static RzCmdStatus type_format_print(RzCore *core, const char *type, ut64 address) {
	const char *fmt = rz_type_format(core->analysis->typedb, type);
	if (RZ_STR_ISEMPTY(fmt)) {
		eprintf("Cannot find type %s\n", type);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_cmdf(core, "pf %s @ 0x%08" PFMT64x "\n", fmt, address);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus type_format_print_variable(RzCore *core, const char *type, const char *varname) {
	const char *fmt = rz_type_format(core->analysis->typedb, type);
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
	const char *fmt = rz_type_format(core->analysis->typedb, type);
	if (RZ_STR_ISEMPTY(fmt)) {
		eprintf("Cannot find type %s\n", type);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_cmdf(core, "pf %s @v:0x%08" PFMT64x "\n", fmt, val);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus type_format_print_hexstring(RzCore *core, const char *type, const char *hexpairs) {
	const char *fmt = rz_type_format(core->analysis->typedb, type);
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
	rz_type_db_del(core->analysis->typedb, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_del_all_handler(RzCore *core, int argc, const char **argv) {
	rz_type_db_purge(core->analysis->typedb);
	rz_type_parse_reset(core->analysis->typedb);
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
			PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? pj_new() : NULL;
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
	int value = rz_type_db_enum_member_by_name(core->analysis->typedb, enum_name, enum_member);
	if (value == -1) {
		eprintf("Cannot find anything matching the specified bitfield");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("0x%x\n", value);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_enum_c_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 1) {
		rz_core_types_enum_print_c(core->analysis->typedb, argv[1], true);
	} else {
		rz_core_types_enum_print_c_all(core->analysis->typedb, true);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_enum_c_nl_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 1) {
		rz_core_types_enum_print_c(core->analysis->typedb, argv[1], false);
	} else {
		rz_core_types_enum_print_c_all(core->analysis->typedb, false);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_enum_find_handler(RzCore *core, int argc, const char **argv) {
	const char *enum_value = argc > 1 ? argv[1] : NULL;
	return types_enum_member_find_all(core, enum_value);
}

RZ_IPI RzCmdStatus rz_type_list_function_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *function = argc > 1 ? argv[1] : NULL;
	if (function) {
		PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? pj_new() : NULL;
		rz_types_function_print(core->analysis->typedb, function, mode, pj);
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
	char *output = rz_type_db_kuery(core->analysis->typedb, query);
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
	ut64 addr = rz_num_math(core->num, argv[1]);
	rz_analysis_type_unlink(core->analysis, addr);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_link_del_all_handler(RzCore *core, int argc, const char **argv) {
	rz_analysis_type_unlink_all(core->analysis);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_noreturn_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *name = argc > 1 ? argv[1] : NULL;
	if (name) {
		ut64 n = rz_num_math(core->num, name);
		if (n) {
			rz_analysis_noreturn_add(core->analysis, name, n);
		} else {
			rz_type_func_noreturn_add(core->analysis->typedb, name);
		}
	} else {
		rz_core_types_function_noreturn_print(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_noreturn_del_handler(RzCore *core, int argc, const char **argv) {
	for (int i = 1; i < argc; i++) {
		rz_type_func_noreturn_drop(core->analysis->typedb, argv[i]);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_noreturn_del_all_handler(RzCore *core, int argc, const char **argv) {
	RzList *noretl = rz_type_noreturn_functions(core->analysis->typedb);
	RzListIter *iter;
	char *name;
	rz_list_foreach (noretl, iter, name) {
		rz_type_func_noreturn_drop(core->analysis->typedb, name);
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
	rz_type_db_load_sdb(core->analysis->typedb, argv[1]);
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
	if (typename) {
		rz_core_types_show_format(core, typename, mode);
	} else {
		if (mode == RZ_OUTPUT_MODE_RIZIN) {
			rz_core_types_struct_print_format_all(core);
		} else {
			rz_core_types_struct_print_all(core, mode);
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_structure_c_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 1) {
		rz_core_types_struct_print_c(core->analysis->typedb, argv[1], true);
	} else {
		rz_core_types_struct_print_c_all(core->analysis->typedb, true);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_structure_c_nl_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 1) {
		rz_core_types_struct_print_c(core->analysis->typedb, argv[1], false);
	} else {
		rz_core_types_struct_print_c_all(core->analysis->typedb, false);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_typedef_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	if (typename) {
		PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? pj_new() : NULL;
		rz_core_types_typedef_print(core, typename, mode, pj);
		if (mode == RZ_OUTPUT_MODE_JSON) {
			rz_cons_println(pj_string(pj));
			pj_free(pj);
		}
	} else {
		rz_core_types_typedef_print_all(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_typedef_c_handler(RzCore *core, int argc, const char **argv) {
	RzTypeDB *typedb = core->analysis->typedb;
	if (argc > 1) {
		rz_core_types_typedef_print_c(typedb, argv[1]);
	} else {
		rz_core_types_typedef_print_c_all(typedb);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_union_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *typename = argc > 1 ? argv[1] : NULL;
	if (typename) {
		rz_core_types_show_format(core, typename, mode);
	} else {
		if (mode == RZ_OUTPUT_MODE_RIZIN) {
			rz_core_types_union_print_format_all(core);
		} else {
			rz_core_types_union_print_all(core, mode);
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_union_c_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 1) {
		rz_core_types_union_print_c(core->analysis->typedb, argv[1], true);
	} else {
		rz_core_types_union_print_c_all(core->analysis->typedb, true);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_union_c_nl_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 1) {
		rz_core_types_union_print_c(core->analysis->typedb, argv[1], false);
	} else {
		rz_core_types_union_print_c_all(core->analysis->typedb, false);
	}
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
