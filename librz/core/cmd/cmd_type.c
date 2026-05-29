// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2009-2020 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 Jody Frankowski <jody.frankowski@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_analysis.h>
#include <rz_cons.h>
#include <rz_core.h>
#include <sdb.h>
#include "../core_private.h"

// Calling conventions

static void types_cc_print(RzCore *core, const char *cc, RzOutputMode mode) {
	rz_return_if_fail(cc);
	if (strchr(cc, '(')) {
		if (!rz_analysis_cc_set(core->analysis, cc)) {
			RZ_LOG_ERROR("Invalid syntax in cc signature.\n");
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
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	const char *enum_member = rz_type_db_enum_member_by_val(typedb, enum_name, value);
	if (!enum_member) {
		RZ_LOG_ERROR("Cannot find matching enum member\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(enum_member);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus types_enum_member_find_all(RzCore *core, const char *enum_value) {
	rz_return_val_if_fail(enum_value, RZ_CMD_STATUS_ERROR);
	ut64 value = rz_num_math(core->num, enum_value);
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	RzList *matches = rz_type_db_find_enums_by_val(typedb, value);
	if (!matches || rz_list_empty(matches)) {
		RZ_LOG_ERROR("Cannot find matching enum member\n");
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

static void type_list_c_all(RzCore *core) {
	char *str = rz_core_types_as_c_all(core, true);
	if (str) {
		rz_cons_print(str);
		free(str);
	}
}

static void type_list_c_all_nl(RzCore *core) {
	char *str = rz_core_types_as_c_all(core, false);
	if (str) {
		rz_cons_print(str);
		free(str);
	}
}

static RzCmdStatus type_format_print(RzCore *core, const char *type, ut64 address) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	char *fmt = rz_type_format(typedb, type);
	if (RZ_STR_ISEMPTY(fmt)) {
		RZ_LOG_ERROR("Cannot find type %s\n", type);
		free(fmt);
		return RZ_CMD_STATUS_ERROR;
	}
	char *r = rz_core_print_format(core, fmt, RZ_PRINT_MUSTSEE, address);
	rz_cons_print(r);
	free(r);
	free(fmt);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus type_format_print_variable(RzCore *core, const char *type, const char *varname) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	char *fmt = rz_type_format(typedb, type);
	if (RZ_STR_ISEMPTY(fmt)) {
		RZ_LOG_ERROR("Cannot find type \"%s\"\n", type);
		free(fmt);
		return RZ_CMD_STATUS_ERROR;
	}
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, -1);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find function at the current offset\n");
		free(fmt);
		return RZ_CMD_STATUS_ERROR;
	}
	RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, varname);
	if (!var) {
		RZ_LOG_ERROR("Cannot find variable \"%s\" in the current function\n", varname);
		free(fmt);
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 addr = rz_core_analysis_var_addr(core, var);
	char *r = rz_core_print_format(core, fmt, RZ_PRINT_MUSTSEE, addr);
	rz_cons_print(r);
	free(r);
	free(fmt);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus type_format_print_value(RzCore *core, const char *type, ut64 val) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	char *fmt = rz_type_format(typedb, type);
	if (RZ_STR_ISEMPTY(fmt)) {
		RZ_LOG_ERROR("Cannot find type %s\n", type);
		free(fmt);
		return RZ_CMD_STATUS_ERROR;
	}
	// TODO: Convert to the API
	rz_core_cmdf(core, "pf %s @v:0x%08" PFMT64x "\n", fmt, val);
	free(fmt);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus type_format_print_hexstring(RzCore *core, const char *type, const char *hexpairs) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	char *fmt = rz_type_format(typedb, type);
	if (RZ_STR_ISEMPTY(fmt)) {
		RZ_LOG_ERROR("Cannot find type %s\n", type);
		free(fmt);
		return RZ_CMD_STATUS_ERROR;
	}
	// TODO: Convert to the API
	rz_core_cmdf(core, "pf %s @x:%s", fmt, hexpairs);
	free(fmt);
	return RZ_CMD_STATUS_OK;
}

static void types_xrefs(RzCore *core, const char *typestr) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	char *error_msg = NULL;
	RzType *type = rz_type_parse_string_single(typedb->parser, typestr, &error_msg);
	if (!type || error_msg) {
		if (error_msg) {
			RZ_LOG_ERROR("%s", error_msg);
			free(error_msg);
		}
		return;
	}
	RzType *type2;
	RzListIter *iter, *iter2;
	RzAnalysisFunction *fcn;
	RzList *fcns = rz_analysis_function_list(core->analysis);
	rz_list_foreach (fcns, iter, fcn) {
		RzList *uniq = rz_analysis_types_from_fcn(core->analysis, fcn);
		rz_list_foreach (uniq, iter2, type2) {
			if (rz_types_equal(type2, type)) {
				rz_cons_printf("%s\n", fcn->name);
				break;
			}
		}
		rz_list_free(uniq);
	}
	rz_type_free(type);
}

static void types_xrefs_summary(RzCore *core) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	RzType *type;
	RzListIter *iter, *iter2;
	RzAnalysisFunction *fcn;
	RzList *fcns = rz_analysis_function_list(core->analysis);
	rz_list_foreach (fcns, iter, fcn) {
		RzList *uniq = rz_analysis_types_from_fcn(core->analysis, fcn);
		if (rz_list_length(uniq)) {
			rz_cons_printf("%s: ", fcn->name);
		}
		rz_list_foreach (uniq, iter2, type) {
			char *str = rz_type_as_string(typedb, type);
			if (str) {
				rz_cons_printf("%s%s", str, rz_list_has_next(iter2) ? "," : "\n");
			}
			free(str);
		}
		rz_list_free(uniq);
	}
}

static RzCmdStatus types_xrefs_function(RzCore *core, ut64 addr) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	RzType *type;
	RzListIter *iter;
	RzAnalysis *analysis = core->analysis;
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(analysis, addr);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", addr);
		return RZ_CMD_STATUS_ERROR;
	}
	RzList *uniq = rz_analysis_types_from_fcn(analysis, fcn);
	rz_list_foreach (uniq, iter, type) {
		char *str = rz_type_as_string(typedb, type);
		rz_cons_println(str);
		free(str);
	}
	rz_list_free(uniq);
	return RZ_CMD_STATUS_OK;
}

static void types_xrefs_graph(RzCore *core) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	RzType *type;
	RzListIter *iter, *iter2;
	RzAnalysisFunction *fcn;
	RzList *fcns = rz_analysis_function_list(core->analysis);
	rz_list_foreach (fcns, iter, fcn) {
		RzList *uniq = rz_analysis_types_from_fcn(core->analysis, fcn);
		if (rz_list_length(uniq)) {
			rz_cons_printf("agn %s\n", fcn->name);
		}
		rz_list_foreach (uniq, iter2, type) {
			char *typestr = rz_type_as_string(typedb, type);
			rz_str_replace_ch(typestr, ' ', '_', true);
			rz_cons_printf("agn %s\n", typestr);
			rz_cons_printf("age %s %s\n", typestr, fcn->name);
			free(typestr);
		}
		rz_list_free(uniq);
	}
}

static void types_xrefs_all(RzCore *core) {
	RzType *type;
	RzListIter *iter, *iter2;
	RzAnalysisFunction *fcn;
	RzList *types_list = rz_list_newf(free);
	RzList *fcns = rz_analysis_function_list(core->analysis);
	rz_list_foreach (fcns, iter, fcn) {
		RzList *types = rz_analysis_types_from_fcn(core->analysis, fcn);
		rz_list_foreach (types, iter2, type) {
			const char *ident = rz_type_identifier(type);
			if (ident) {
				rz_list_push(types_list, rz_str_dup(ident));
			}
		}
		rz_list_free(types);
	}
	RzList *uniq_types = rz_list_uniq(types_list, (RzListComparator)strcmp, NULL);
	rz_list_sort(uniq_types, (RzListComparator)strcmp, NULL);
	char *typestr;
	rz_list_foreach (uniq_types, iter, typestr) {
		rz_cons_printf("%s\n", typestr);
	}
	rz_list_free(uniq_types);
	rz_list_free(types_list);
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
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_db_del(typedb, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_del_all_handler(RzCore *core, int argc, const char **argv) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_db_purge(typedb);
	rz_type_parse_reset(typedb);
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
	Sdb *sdb_cc = rz_analysis_get_sdb_cc(core->analysis);
	sdb_reset(sdb_cc);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_c_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 1) {
		char *str = rz_core_types_as_c(core, argv[1], true);
		if (!str) {
			RZ_LOG_ERROR("Type \"%s\" not found\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
	} else {
		type_list_c_all(core);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_c_nl_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 1) {
		char *str = rz_core_types_as_c(core, argv[1], false);
		if (!str) {
			RZ_LOG_ERROR("Type \"%s\" not found\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
	} else {
		type_list_c_all_nl(core);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_define_handler(RzCore *core, int argc, const char **argv) {
	const char *type = argc > 1 ? argv[1] : NULL;
	rz_types_define(core, type);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_define_from_format_handler(RzCore *core, int argc, const char **argv) {
	const char *name = argv[1];
	const char *format_arg = argv[2];
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);

	/* Resolve the second argument. It may be either the name of a
	 * format saved with pfn / pf.<name> or a literal `pf` format string.
	 * A saved name is looked up first (a pure read of the formats hash);
	 * otherwise the argument is parsed as a literal format. This is the
	 * "including from existing saved ones" half of the feature, and it
	 * deliberately uses rz_type_db_format_get rather than
	 * rz_pf_resolve_name so that nothing but `tdf` ever writes into the
	 * type database -- and only with the final registered type. */
	const char *fmt_str = rz_type_db_format_get(typedb, format_arg);
	if (!fmt_str) {
		fmt_str = format_arg;
	}

	char *error = NULL;
	char *c_decl = rz_type_format_to_c_declaration(name, fmt_str, &error);
	if (!c_decl) {
		RZ_LOG_ERROR("Cannot build a type from format \"%s\": %s\n",
			format_arg, error ? error : "unknown error");
		free(error);
		return RZ_CMD_STATUS_ERROR;
	}

	/* Register the synthesised declaration through the regular C type
	 * parser, exactly as `td` does, so the new type becomes a first-class
	 * RzBaseType that participates in type analysis. */
	char *parse_error = NULL;
	int rc = rz_type_parse_string_stateless(typedb->parser, c_decl, &parse_error);
	if (rc && parse_error) {
		rz_str_trim_tail(parse_error);
		RZ_LOG_ERROR("Failed to define type \"%s\": %s\n", name, parse_error);
		free(parse_error);
		free(c_decl);
		return RZ_CMD_STATUS_ERROR;
	}
	free(parse_error);

	/* Confirm the type actually landed in the database. */
	if (!rz_type_db_get_base_type(typedb, name)) {
		RZ_LOG_ERROR("Type \"%s\" was not registered (check the format)\n", name);
		free(c_decl);
		return RZ_CMD_STATUS_ERROR;
	}
	free(c_decl);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_enum_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (argc > 1) {
		if (argc > 2) {
			// TODO: Reconsider the `te <enum_name> <member_value>` syntax change
			return types_enum_member_find(core, argv[1], argv[2]);
		} else {
			PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? pj_new() : NULL;
			RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
			RzBaseType *btype = rz_type_db_get_enum(typedb, argv[1]);
			if (!btype) {
				RZ_LOG_ERROR("Cannot find \"%s\" enum type\n", argv[1]);
				pj_free(pj);
				return RZ_CMD_STATUS_ERROR;
			}
			rz_core_types_enum_print(core, btype, mode, pj);
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
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	int value = rz_type_db_enum_member_by_name(typedb, enum_name, enum_member);
	if (value == -1) {
		RZ_LOG_ERROR("Cannot find anything matching the specified bitfield\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("0x%x\n", value);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_enum_c_handler(RzCore *core, int argc, const char **argv) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	if (argc > 1) {
		RzBaseType *btype = rz_type_db_get_enum(typedb, argv[1]);
		if (!btype) {
			RZ_LOG_ERROR("Cannot find \"%s\" enum type\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		char *str = rz_core_types_enum_as_c(typedb, btype, true);
		if (!str) {
			RZ_LOG_ERROR("Cannot get C representation of \"%s\" enum type\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
	} else {
		char *str = rz_core_types_enum_as_c_all(typedb, true);
		if (!str) {
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_enum_c_nl_handler(RzCore *core, int argc, const char **argv) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	if (argc > 1) {
		RzBaseType *btype = rz_type_db_get_enum(typedb, argv[1]);
		if (!btype) {
			RZ_LOG_ERROR("Cannot find \"%s\" enum type\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		char *str = rz_core_types_enum_as_c(typedb, btype, false);
		if (!str) {
			RZ_LOG_ERROR("Cannot get C representation of \"%s\" enum type\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
	} else {
		char *str = rz_core_types_enum_as_c_all(typedb, false);
		if (!str) {
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
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
		RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
		rz_core_types_function_print(typedb, function, mode, pj);
		if (mode == RZ_OUTPUT_MODE_JSON) {
			rz_cons_println(pj_string(pj));
			pj_free(pj);
		}
	} else {
		rz_core_types_function_print_all(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_function_del_handler(RzCore *core, int argc, const char **argv) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_func_delete(typedb, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_function_del_all_handler(RzCore *core, int argc, const char **argv) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_func_delete_all(typedb);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_function_cc_handler(RzCore *core, int argc, const char **argv) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	if (argc > 2) {
		if (!rz_type_func_cc_set(typedb, argv[1], argv[2])) {
			RZ_LOG_ERROR("Cannot set function \"%s\" calling convention \"%s\"\n", argv[1], argv[2]);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		const char *cc = rz_type_func_cc(typedb, argv[1]);
		if (!cc) {
			RZ_LOG_ERROR("Cannot find function \"%s\" in types database\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_println(cc);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_noreturn_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *name = argc > 1 ? argv[1] : NULL;
	if (name) {
		ut64 n = rz_num_math(core->num, name);
		if (n) {
			rz_analysis_noreturn_add(core->analysis, name, n);
		} else {
			RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
			rz_type_func_noreturn_add(typedb, name);
		}
	} else {
		rz_core_types_function_noreturn_print(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_noreturn_del_handler(RzCore *core, int argc, const char **argv) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	for (int i = 1; i < argc; i++) {
		rz_type_func_noreturn_drop(typedb, argv[i]);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_noreturn_del_all_handler(RzCore *core, int argc, const char **argv) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	RzList *noretl = rz_type_noreturn_function_names(typedb);
	RzListIter *iter;
	char *name;
	rz_list_foreach (noretl, iter, name) {
		rz_type_func_noreturn_drop(typedb, name);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_open_file_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_types_open_file(core, argv[1])) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_open_editor_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_types_open_editor(core, argv[1])) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_open_sdb_handler(RzCore *core, int argc, const char **argv) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_db_load_sdb(typedb, argv[1]);
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
	if (argc > 1) {
		if (mode == RZ_OUTPUT_MODE_STANDARD) {
			rz_core_types_show_format(core, argv[1], mode);
		} else {
			PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? pj_new() : NULL;
			RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
			RzBaseType *btype = rz_type_db_get_struct(typedb, argv[1]);
			if (!btype) {
				RZ_LOG_ERROR("Cannot find \"%s\" struct type\n", argv[1]);
				pj_free(pj);
				return RZ_CMD_STATUS_ERROR;
			}
			rz_core_types_struct_print(core, btype, mode, pj);
			if (mode == RZ_OUTPUT_MODE_JSON) {
				rz_cons_println(pj_string(pj));
				pj_free(pj);
			}
		}
	} else {
		rz_core_types_struct_print_all(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_structure_c_handler(RzCore *core, int argc, const char **argv) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	if (argc > 1) {
		RzBaseType *btype = rz_type_db_get_struct(typedb, argv[1]);
		if (!btype) {
			RZ_LOG_ERROR("Cannot find \"%s\" struct type\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		char *str = rz_core_types_struct_as_c(typedb, btype, true);
		if (!str) {
			RZ_LOG_ERROR("Cannot get C representation of \"%s\" struct type\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
	} else {
		char *str = rz_core_types_struct_as_c_all(typedb, true);
		if (!str) {
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_structure_c_nl_handler(RzCore *core, int argc, const char **argv) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	if (argc > 1) {
		RzBaseType *btype = rz_type_db_get_struct(typedb, argv[1]);
		if (!btype) {
			RZ_LOG_ERROR("Cannot find \"%s\" struct type\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		char *str = rz_core_types_struct_as_c(typedb, btype, false);
		if (!str) {
			RZ_LOG_ERROR("Cannot get C representation of \"%s\" struct type\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
	} else {
		char *str = rz_core_types_struct_as_c_all(typedb, false);
		if (!str) {
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_typedef_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (argc > 1) {
		PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? pj_new() : NULL;
		RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
		RzBaseType *btype = rz_type_db_get_typedef(typedb, argv[1]);
		if (!btype) {
			RZ_LOG_ERROR("Cannot find \"%s\" typedef type\n", argv[1]);
			pj_free(pj);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_core_types_typedef_print(core, btype, mode, pj);
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
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	if (argc > 1) {
		RzBaseType *btype = rz_type_db_get_typedef(typedb, argv[1]);
		if (!btype) {
			RZ_LOG_ERROR("Cannot find \"%s\" typedef type\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		char *str = rz_core_types_typedef_as_c(typedb, btype);
		if (!str) {
			RZ_LOG_ERROR("Cannot get C representation of \"%s\" typedef type\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
	} else {
		char *str = rz_core_types_typedef_as_c_all(typedb);
		if (!str) {
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_list_union_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (argc > 1) {
		if (mode == RZ_OUTPUT_MODE_STANDARD) {
			rz_core_types_show_format(core, argv[1], mode);
		} else {
			PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? pj_new() : NULL;
			RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
			RzBaseType *btype = rz_type_db_get_union(typedb, argv[1]);
			if (!btype) {
				RZ_LOG_ERROR("Cannot find \"%s\" union type\n", argv[1]);
				pj_free(pj);
				return RZ_CMD_STATUS_ERROR;
			}
			rz_core_types_union_print(core, btype, mode, pj);
			if (mode == RZ_OUTPUT_MODE_JSON) {
				rz_cons_println(pj_string(pj));
				pj_free(pj);
			}
		}
	} else {
		rz_core_types_union_print_all(core, mode);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_union_c_handler(RzCore *core, int argc, const char **argv) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	if (argc > 1) {
		RzBaseType *btype = rz_type_db_get_union(typedb, argv[1]);
		if (!btype) {
			RZ_LOG_ERROR("Cannot find \"%s\" union type\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		char *str = rz_core_types_union_as_c(typedb, btype, true);
		if (!str) {
			RZ_LOG_ERROR("Cannot get C representation of \"%s\" union type\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
	} else {
		char *str = rz_core_types_union_as_c_all(typedb, true);
		if (!str) {
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_type_union_c_nl_handler(RzCore *core, int argc, const char **argv) {
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	if (argc > 1) {
		RzBaseType *btype = rz_type_db_get_union(typedb, argv[1]);
		if (!btype) {
			RZ_LOG_ERROR("Cannot find \"%s\" union type\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		char *str = rz_core_types_union_as_c(typedb, btype, false);
		if (!str) {
			RZ_LOG_ERROR("Cannot get C representation of \"%s\" union type\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
	} else {
		char *str = rz_core_types_union_as_c_all(typedb, false);
		if (!str) {
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_print(str);
		free(str);
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
