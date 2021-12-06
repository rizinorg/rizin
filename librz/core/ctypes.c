// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2009-2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 Jody Frankowski <jody.frankowski@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_types.h>
#include <rz_list.h>
#include <rz_core.h>
#include <rz_type.h>

#include "core_private.h"

// Calling conventions

// TODO: Technically it doesn't belong in types and `t` commands
RZ_IPI void rz_core_types_calling_conventions_print(RzCore *core, RzOutputMode mode) {
	RzList *list = rz_analysis_calling_conventions(core->analysis);
	RzListIter *iter;
	const char *cc;
	switch (mode) {
	case RZ_OUTPUT_MODE_STANDARD: {
		rz_list_foreach (list, iter, cc) {
			rz_cons_println(cc);
		}
	} break;
	case RZ_OUTPUT_MODE_JSON: {
		PJ *pj = pj_new();
		pj_a(pj);
		rz_list_foreach (list, iter, cc) {
			char *ccexpr = rz_analysis_cc_get(core->analysis, cc);
			// TODO: expose this as an object, not just an array of strings
			pj_s(pj, ccexpr);
			free(ccexpr);
		}
		pj_end(pj);
		rz_cons_printf("%s\n", pj_string(pj));
		pj_free(pj);
	} break;
	case RZ_OUTPUT_MODE_LONG: {
		rz_list_foreach (list, iter, cc) {
			char *ccexpr = rz_analysis_cc_get(core->analysis, cc);
			rz_cons_printf("%s\n", ccexpr);
			free(ccexpr);
		}
	} break;
	case RZ_OUTPUT_MODE_RIZIN: {
		rz_list_foreach (list, iter, cc) {
			char *ccexpr = rz_analysis_cc_get(core->analysis, cc);
			rz_cons_printf("tcc \"%s\"\n", ccexpr);
			free(ccexpr);
		}
	} break;
	case RZ_OUTPUT_MODE_SDB:
		rz_core_kuery_print(core, "analysis/cc/*");
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	rz_list_free(list);
}

// Enums

RZ_IPI void rz_core_types_enum_print(RzCore *core, const RzBaseType *btype, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(core && btype);
	rz_return_if_fail(btype->kind == RZ_BASE_TYPE_KIND_ENUM);

	switch (mode) {
	case RZ_OUTPUT_MODE_JSON: {
		rz_return_if_fail(pj);
		pj_o(pj);
		if (btype && !rz_vector_empty(&btype->enum_data.cases)) {
			pj_ks(pj, "name", btype->name);
			pj_k(pj, "values");
			pj_o(pj);
			RzTypeEnumCase *cas;
			rz_vector_foreach(&btype->enum_data.cases, cas) {
				pj_kn(pj, cas->name, cas->val);
			}
			pj_end(pj);
		}
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD: {
		if (btype && !rz_vector_empty(&btype->enum_data.cases)) {
			RzTypeEnumCase *cas;
			rz_vector_foreach(&btype->enum_data.cases, cas) {
				rz_cons_printf("%s = 0x%" PFMT64x "\n", cas->name, cas->val);
			}
		}
		break;
	}
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_println(btype->name);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_IPI void rz_core_types_enum_print_all(RzCore *core, RzOutputMode mode) {
	RzList *enumlist = rz_type_db_get_base_types_of_kind(core->analysis->typedb, RZ_BASE_TYPE_KIND_ENUM);
	RzListIter *it;
	PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? pj_new() : NULL;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(pj);
	}
	RzBaseType *btype;
	rz_list_foreach (enumlist, it, btype) {
		rz_core_types_enum_print(core, btype, mode, pj);
	}
	rz_list_free(enumlist);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

RZ_IPI RZ_OWN char *rz_core_types_enum_as_c(RzTypeDB *typedb, const RzBaseType *btype, bool multiline) {
	rz_return_val_if_fail(btype, NULL);
	rz_return_val_if_fail(btype->kind == RZ_BASE_TYPE_KIND_ENUM, NULL);

	unsigned int multiline_opt = 0;
	if (multiline) {
		multiline_opt = RZ_TYPE_PRINT_MULTILINE;
	}
	return rz_type_db_base_type_as_pretty_string(typedb, btype, multiline_opt | RZ_TYPE_PRINT_END_NEWLINE | RZ_TYPE_PRINT_ANONYMOUS, 1);
}

RZ_IPI RZ_OWN char *rz_core_types_enum_as_c_all(RzTypeDB *typedb, bool multiline) {
	RzList *enumlist = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_ENUM);
	RzListIter *it;
	RzBaseType *btype;
	RzStrBuf *buf = rz_strbuf_new("");
	rz_list_foreach (enumlist, it, btype) {
		char *str = rz_core_types_enum_as_c(typedb, btype, multiline);
		if (str) {
			rz_strbuf_append(buf, str);
		}
		free(str);
	}
	rz_list_free(enumlist);
	return rz_strbuf_drain(buf);
}

// Unions

RZ_IPI void rz_core_types_union_print(RzCore *core, const RzBaseType *btype, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(core && btype);
	rz_return_if_fail(btype->kind == RZ_BASE_TYPE_KIND_UNION);

	switch (mode) {
	case RZ_OUTPUT_MODE_JSON: {
		rz_return_if_fail(pj);
		pj_o(pj);
		if (btype && !rz_vector_empty(&btype->union_data.members)) {
			pj_ks(pj, "name", btype->name);
			pj_k(pj, "members");
			pj_o(pj);
			RzTypeUnionMember *memb;
			rz_vector_foreach(&btype->union_data.members, memb) {
				char *mtype = rz_type_as_string(core->analysis->typedb, memb->type);
				pj_ks(pj, memb->name, mtype);
				free(mtype);
			}
			pj_end(pj);
		}
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_LONG: {
		rz_cons_printf("union %s:\n", btype->name);
		if (btype && !rz_vector_empty(&btype->union_data.members)) {
			RzTypeUnionMember *memb;
			rz_vector_foreach(&btype->union_data.members, memb) {
				char *mtype = rz_type_as_string(core->analysis->typedb, memb->type);
				ut64 size = rz_type_db_get_bitsize(core->analysis->typedb, memb->type) / 8;
				rz_cons_printf("\t%s: %s (size = %" PFMT64d ")\n", memb->name, mtype, size);
				free(mtype);
			}
		}
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD:
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_println(btype->name);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_IPI void rz_core_types_union_print_all(RzCore *core, RzOutputMode mode) {
	RzList *unionlist = rz_type_db_get_base_types_of_kind(core->analysis->typedb, RZ_BASE_TYPE_KIND_UNION);
	RzListIter *it;
	PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? pj_new() : NULL;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(pj);
	}
	RzBaseType *btype;
	rz_list_foreach (unionlist, it, btype) {
		rz_core_types_union_print(core, btype, mode, pj);
	}
	rz_list_free(unionlist);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

RZ_IPI RZ_OWN char *rz_core_types_union_as_c(RzTypeDB *typedb, const RzBaseType *btype, bool multiline) {
	rz_return_val_if_fail(btype, NULL);
	rz_return_val_if_fail(btype->kind == RZ_BASE_TYPE_KIND_UNION, NULL);

	unsigned int multiline_opt = 0;
	if (multiline) {
		multiline_opt = RZ_TYPE_PRINT_MULTILINE;
	}
	return rz_type_db_base_type_as_pretty_string(typedb, btype, multiline_opt | RZ_TYPE_PRINT_END_NEWLINE | RZ_TYPE_PRINT_ANONYMOUS, 1);
}

RZ_IPI RZ_OWN char *rz_core_types_union_as_c_all(RzTypeDB *typedb, bool multiline) {
	RzList *unionlist = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_UNION);
	RzListIter *it;
	RzBaseType *btype;
	RzStrBuf *buf = rz_strbuf_new("");
	rz_list_foreach (unionlist, it, btype) {
		char *str = rz_core_types_union_as_c(typedb, btype, multiline);
		if (str) {
			rz_strbuf_append(buf, str);
		}
		free(str);
	}
	rz_list_free(unionlist);
	return rz_strbuf_drain(buf);
}

// Structures

RZ_IPI void rz_core_types_struct_print(RzCore *core, const RzBaseType *btype, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(core && btype);
	rz_return_if_fail(btype->kind == RZ_BASE_TYPE_KIND_STRUCT);

	switch (mode) {
	case RZ_OUTPUT_MODE_JSON: {
		rz_return_if_fail(pj);
		pj_o(pj);
		pj_ks(pj, "name", btype->name);
		pj_k(pj, "members");
		pj_o(pj);
		RzTypeStructMember *memb;
		rz_vector_foreach(&btype->struct_data.members, memb) {
			char *mtype = rz_type_as_string(core->analysis->typedb, memb->type);
			pj_ks(pj, memb->name, mtype);
			free(mtype);
		}
		pj_end(pj);
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_LONG: {
		rz_cons_printf("struct %s:\n", btype->name);
		if (btype && !rz_vector_empty(&btype->union_data.members)) {
			RzTypeStructMember *memb;
			ut64 offset = 0;
			rz_vector_foreach(&btype->struct_data.members, memb) {
				char *mtype = rz_type_as_string(core->analysis->typedb, memb->type);
				ut64 size = rz_type_db_get_bitsize(core->analysis->typedb, memb->type) / 8;
				rz_cons_printf("\t%s: %s (size = %" PFMT64d ", offset = %" PFMT64d ")\n",
					memb->name, mtype, size, offset);
				offset += size;
				free(mtype);
			}
		}
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD:
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_println(btype->name);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_IPI void rz_core_types_struct_print_all(RzCore *core, RzOutputMode mode) {
	RzList *structlist = rz_type_db_get_base_types_of_kind(core->analysis->typedb, RZ_BASE_TYPE_KIND_STRUCT);
	RzListIter *it;
	PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? pj_new() : NULL;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(pj);
	}
	RzBaseType *btype;
	rz_list_foreach (structlist, it, btype) {
		rz_core_types_struct_print(core, btype, mode, pj);
	}
	rz_list_free(structlist);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

RZ_IPI RZ_OWN char *rz_core_types_struct_as_c(RzTypeDB *typedb, const RzBaseType *btype, bool multiline) {
	rz_return_val_if_fail(btype, NULL);
	rz_return_val_if_fail(btype->kind == RZ_BASE_TYPE_KIND_STRUCT, NULL);

	unsigned int multiline_opt = multiline ? RZ_TYPE_PRINT_MULTILINE : 0;
	return rz_type_db_base_type_as_pretty_string(typedb, btype, multiline_opt | RZ_TYPE_PRINT_END_NEWLINE | RZ_TYPE_PRINT_ANONYMOUS, 1);
}

RZ_IPI RZ_OWN char *rz_core_types_struct_as_c_all(RzTypeDB *typedb, bool multiline) {
	RzList *structlist = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_STRUCT);
	RzListIter *it;
	RzBaseType *btype;
	RzStrBuf *buf = rz_strbuf_new("");
	rz_list_foreach (structlist, it, btype) {
		char *str = rz_core_types_struct_as_c(typedb, btype, multiline);
		if (str) {
			rz_strbuf_append(buf, str);
		}
		free(str);
	}
	rz_list_free(structlist);
	return rz_strbuf_drain(buf);
}

// Typedefs

RZ_IPI void rz_core_types_typedef_print(RzCore *core, const RzBaseType *btype, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(core && btype);
	rz_return_if_fail(btype->kind == RZ_BASE_TYPE_KIND_TYPEDEF);

	char *typestr = rz_type_as_string(core->analysis->typedb, btype->type);
	switch (mode) {
	case RZ_OUTPUT_MODE_JSON: {
		rz_return_if_fail(pj);
		pj_o(pj);
		pj_ks(pj, "name", btype->name);
		pj_ks(pj, "type", typestr);
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD: {
		rz_cons_printf("%s = %s\n", btype->name, typestr);
		break;
	}
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_println(btype->name);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	free(typestr);
}

RZ_IPI void rz_core_types_typedef_print_all(RzCore *core, RzOutputMode mode) {
	RzList *typedeflist = rz_type_db_get_base_types_of_kind(core->analysis->typedb, RZ_BASE_TYPE_KIND_TYPEDEF);
	RzListIter *it;
	PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? pj_new() : NULL;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(pj);
	}
	RzBaseType *btype;
	rz_list_foreach (typedeflist, it, btype) {
		rz_core_types_typedef_print(core, btype, mode, pj);
	}
	rz_list_free(typedeflist);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

RZ_IPI RZ_OWN char *rz_core_types_typedef_as_c(RzTypeDB *typedb, const RzBaseType *btype) {
	rz_return_val_if_fail(btype, NULL);
	rz_return_val_if_fail(btype->kind == RZ_BASE_TYPE_KIND_TYPEDEF, NULL);

	return rz_type_db_base_type_as_pretty_string(typedb, btype, RZ_TYPE_PRINT_END_NEWLINE | RZ_TYPE_PRINT_SHOW_TYPEDEF, 1);
}

RZ_IPI RZ_OWN char *rz_core_types_typedef_as_c_all(RzTypeDB *typedb) {
	RzList *typedeflist = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_TYPEDEF);
	RzListIter *it;
	RzBaseType *btype;
	RzStrBuf *buf = rz_strbuf_new("");
	rz_list_foreach (typedeflist, it, btype) {
		char *str = rz_core_types_typedef_as_c(typedb, btype);
		if (str) {
			rz_strbuf_append(buf, str);
		}
		free(str);
	}
	rz_list_free(typedeflist);
	return rz_strbuf_drain(buf);
}

RZ_IPI RZ_OWN char *rz_core_base_type_as_c(RzCore *core, RZ_NONNULL RzBaseType *type, bool multiline) {
	rz_return_val_if_fail(type, NULL);

	unsigned int multiline_opt = 0;
	if (multiline) {
		multiline_opt = RZ_TYPE_PRINT_MULTILINE;
	}
	return rz_type_db_base_type_as_pretty_string(core->analysis->typedb, type, multiline_opt | RZ_TYPE_PRINT_END_NEWLINE | RZ_TYPE_PRINT_ANONYMOUS, 1);
}

RZ_IPI RZ_OWN char *rz_core_types_as_c(RzCore *core, RZ_NONNULL const char *name, bool multiline) {
	rz_return_val_if_fail(name, NULL);

	RzBaseType *btype = rz_type_db_get_base_type(core->analysis->typedb, name);
	if (!btype) {
		return false;
	}
	return rz_core_base_type_as_c(core, btype, multiline);
}

// Function types

RZ_IPI void rz_core_types_function_print(RzTypeDB *typedb, const char *function, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(function);
	RzCallable *callable = rz_type_func_get(typedb, function);
	if (!callable) {
		return;
	}
	char *ret = callable->ret ? rz_type_as_string(typedb, callable->ret) : NULL;
	void **it;
	switch (mode) {
	case RZ_OUTPUT_MODE_JSON: {
		rz_return_if_fail(pj);
		pj_o(pj);
		pj_ks(pj, "name", function);
		pj_ks(pj, "ret", ret);
		pj_k(pj, "args");
		pj_a(pj);
		rz_pvector_foreach (callable->args, it) {
			RzCallableArg *arg = (RzCallableArg *)*it;
			char *typestr = rz_type_as_string(typedb, arg->type);
			pj_o(pj);
			pj_ks(pj, "type", rz_str_get_null(typestr));
			pj_ks(pj, "name", rz_str_get_null(arg->name));
			pj_end(pj);
			free(typestr);
		}
		pj_end(pj);
		pj_end(pj);
	} break;
	default: {
		char *str = rz_type_callable_as_string(typedb, callable);
		rz_cons_printf("%s;\n", str);
		free(str);
	} break;
	}
	free(ret);
}

RZ_IPI void rz_core_types_function_print_all(RzCore *core, RzOutputMode mode) {
	PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? pj_new() : NULL;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(pj);
	}
	RzList *l = rz_type_function_names(core->analysis->typedb);
	RzListIter *iter;
	char *name;
	rz_list_foreach (l, iter, name) {
		rz_core_types_function_print(core->analysis->typedb, name, mode, pj);
	}
	rz_list_free(l);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

// Noreturn function attributes

static bool nonreturn_print(RzCore *core, RzList *noretl) {
	RzListIter *it;
	char *s;
	rz_list_foreach (noretl, it, s) {
		rz_cons_println(s);
	}
	return true;
}

static bool nonreturn_print_json(RzCore *core, RzList *noretl) {
	RzListIter *it;
	char *s;
	PJ *pj = pj_new();
	pj_a(pj);
	rz_list_foreach (noretl, it, s) {
		pj_s(pj, s);
	}
	pj_end(pj);
	rz_cons_println(pj_string(pj));
	pj_free(pj);
	return true;
}

RZ_IPI void rz_core_types_function_noreturn_print(RzCore *core, RzOutputMode mode) {
	RzList *noretl = rz_type_noreturn_function_names(core->analysis->typedb);
	switch (mode) {
	case RZ_OUTPUT_MODE_JSON:
		nonreturn_print_json(core, noretl);
		break;
	default:
		nonreturn_print(core, noretl);
		break;
	}
	rz_list_free(noretl);
}

// Type formatting

RZ_IPI void rz_core_types_show_format(RzCore *core, const char *name, RzOutputMode mode) {
	char *fmt = rz_type_format(core->analysis->typedb, name);
	if (fmt) {
		switch (mode) {
		case RZ_OUTPUT_MODE_JSON: {
			PJ *pj = pj_new();
			if (!pj) {
				free(fmt);
				return;
			}
			pj_o(pj);
			pj_ks(pj, "name", name);
			pj_ks(pj, "format", fmt);
			pj_end(pj);
			rz_cons_printf("%s", pj_string(pj));
			pj_free(pj);
		} break;
		case RZ_OUTPUT_MODE_RIZIN: {
			rz_cons_printf("pf.%s %s\n", name, fmt);
		} break;
		case RZ_OUTPUT_MODE_STANDARD: {
			// FIXME: Not really a standard format
			// We should think about better representation by default here
			rz_cons_printf("pf %s\n", fmt);
		} break;
		default:
			break;
		}
		free(fmt);
	} else {
		eprintf("Cannot find '%s' type\n", name);
	}
}

RZ_IPI void rz_core_types_struct_print_format_all(RzCore *core) {
	RzTypeDB *typedb = core->analysis->typedb;
	RzList *structlist = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_STRUCT);
	RzListIter *it;
	RzBaseType *btype;
	rz_list_foreach (structlist, it, btype) {
		rz_core_types_show_format(core, btype->name, RZ_OUTPUT_MODE_RIZIN);
	}
	rz_list_free(structlist);
}

RZ_IPI void rz_core_types_union_print_format_all(RzCore *core) {
	RzTypeDB *typedb = core->analysis->typedb;
	RzList *unionlist = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_UNION);
	RzListIter *it;
	RzBaseType *btype;
	rz_list_foreach (unionlist, it, btype) {
		rz_core_types_show_format(core, btype->name, RZ_OUTPUT_MODE_RIZIN);
	}
	rz_list_free(unionlist);
}

// Type links

static void set_retval(RzCore *core, ut64 at) {
	RzAnalysis *analysis = core->analysis;
	RzAnalysisHint *hint = rz_analysis_hint_get(analysis, at);
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(analysis, at, 0);

	if (!hint || !fcn || !fcn->name) {
		goto beach;
	}
	if (hint->ret == UT64_MAX) {
		goto beach;
	}
	const char *cc = rz_analysis_cc_func(core->analysis, fcn->name);
	const char *regname = rz_analysis_cc_ret(analysis, cc);
	if (regname) {
		RzRegItem *reg = rz_reg_get(analysis->reg, regname, -1);
		if (reg) {
			rz_reg_set_value(analysis->reg, reg, hint->ret);
		}
	}
beach:
	rz_analysis_hint_free(hint);
	return;
}

static void set_offset_hint(RzCore *core, RzAnalysisOp *op, RZ_BORROW RzTypePath *tpath, ut64 laddr, ut64 at, int offimm) {
	rz_return_if_fail(core && op && tpath);
	if (tpath->typ->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return;
	}
	char *cmt = (offimm == 0) ? strdup(tpath->path) : rz_type_as_string(core->analysis->typedb, tpath->typ);
	if (offimm > 0) {
		// Set only the type path as the analysis hint
		// only and only if the types are the exact match between
		// possible member offset and the type linked to the laddr
		RzList *paths = rz_analysis_type_paths_by_address(core->analysis, laddr + offimm);
		if (paths && rz_list_length(paths)) {
			RzTypePath *link = rz_list_get_top(paths);
			rz_analysis_hint_set_offset(core->analysis, at, link->path);
		}
	} else if (cmt && rz_analysis_op_ismemref(op->type)) {
		rz_meta_set_string(core->analysis, RZ_META_TYPE_VARTYPE, at, cmt);
	}
	free(cmt);
}

struct TLAnalysisContext {
	RzAnalysisOp *aop;
	RzAnalysisVar *var;
	ut64 src_addr;
	ut64 dst_addr;
	ut64 src_imm;
	ut64 dst_imm;
};

// TODO: Handle multiple matches for every address and resolve conflicts between them
static void resolve_type_links(RzCore *core, ut64 at, struct TLAnalysisContext *ctx, int ret, bool *resolved) {
	// At first we check if there are links to the corresponding addresses
	RzList *slinks = rz_analysis_type_paths_by_address(core->analysis, ctx->src_addr);
	RzList *dlinks = rz_analysis_type_paths_by_address(core->analysis, ctx->dst_addr);
	RzList *vlinks = rz_analysis_type_paths_by_address(core->analysis, ctx->src_addr + ctx->src_imm);
	// TODO: Handle register based arg for struct offset propgation
	if (vlinks && rz_list_length(vlinks) && ctx->var && ctx->var->kind != 'r') {
		RzTypePath *vlink = rz_list_get_top(vlinks);
		// FIXME: For now we only propagate simple type identifiers,
		// no pointers or arrays
		if (vlink->typ->kind == RZ_TYPE_KIND_IDENTIFIER) {
			if (!vlink->typ->identifier.name) {
				rz_warn_if_reached();
				return;
			}
			RzBaseType *varbtype = rz_type_db_get_base_type(core->analysis->typedb, vlink->typ->identifier.name);
			if (varbtype) {
				// if a var addr matches with struct , change it's type and name
				// var int local_e0h --> var struct foo
				// if (strcmp(var->name, vlink) && !*resolved) {
				if (!*resolved) {
					*resolved = true;
					rz_analysis_var_set_type(ctx->var, vlink->typ);
					rz_analysis_var_rename(ctx->var, vlink->typ->identifier.name, false);
				}
			}
		}
	} else if (slinks && rz_list_length(slinks)) {
		RzTypePath *slink = rz_list_get_top(slinks);
		set_offset_hint(core, ctx->aop, slink, ctx->src_addr, at - ret, ctx->src_imm);
	} else if (dlinks && rz_list_length(dlinks)) {
		RzTypePath *dlink = rz_list_get_top(dlinks);
		set_offset_hint(core, ctx->aop, dlink, ctx->dst_addr, at - ret, ctx->dst_imm);
	}
}

RZ_API void rz_core_link_stroff(RzCore *core, RzAnalysisFunction *fcn) {
	rz_return_if_fail(core && core->analysis && fcn);
	RzAnalysisBlock *bb;
	RzListIter *it;
	RzAnalysisOp aop = { 0 };
	bool ioCache = rz_config_get_i(core->config, "io.cache");
	bool stack_set = false;
	bool resolved = false;
	int dbg_follow = rz_config_get_i(core->config, "dbg.follow");
	RzAnalysisEsil *esil;
	int iotrap = rz_config_get_i(core->config, "esil.iotrap");
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	unsigned int addrsize = rz_config_get_i(core->config, "esil.addr.size");
	const char *pc_name = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
	const char *sp_name = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SP);
	RzRegItem *pc = rz_reg_get(core->analysis->reg, pc_name, -1);

	if (!(esil = rz_analysis_esil_new(stacksize, iotrap, addrsize))) {
		return;
	}
	rz_analysis_esil_setup(esil, core->analysis, 0, 0, 0);
	int i, ret, bsize = RZ_MAX(64, core->blocksize);
	const int mininstrsz = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	const int maxinstrsz = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE);
	const int minopcode = RZ_MAX(1, mininstrsz);
	ut8 *buf = malloc(bsize);
	if (!buf) {
		free(buf);
		rz_analysis_esil_free(esil);
		return;
	}
	rz_reg_arena_push(core->analysis->reg);
	rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_ANY, true);
	ut64 spval = rz_reg_getv(esil->analysis->reg, sp_name);
	if (spval) {
		// reset stack pointer to initial value
		RzRegItem *sp = rz_reg_get(esil->analysis->reg, sp_name, -1);
		ut64 curpc = rz_reg_getv(esil->analysis->reg, pc_name);
		int stacksz = rz_core_get_stacksz(core, fcn->addr, curpc);
		if (stacksz > 0) {
			rz_reg_arena_zero(esil->analysis->reg, RZ_REG_TYPE_ANY); // clear prev reg values
			rz_reg_set_value(esil->analysis->reg, sp, spval + stacksz);
		}
	} else {
		// initialize stack
		rz_core_analysis_esil_init_mem(core, NULL, UT64_MAX, UT32_MAX);
		stack_set = true;
	}
	rz_config_set_i(core->config, "io.cache", 1);
	rz_config_set_i(core->config, "dbg.follow", 0);
	ut64 oldoff = core->offset;
	rz_cons_break_push(NULL, NULL);
	// TODO: The algorithm can be more accurate if blocks are followed by their jmp/fail, not just by address
	rz_list_sort(fcn->bbs, bb_cmpaddr);
	rz_list_foreach (fcn->bbs, it, bb) {
		ut64 at = bb->addr;
		ut64 to = bb->addr + bb->size;
		rz_reg_set_value(esil->analysis->reg, pc, at);
		for (i = 0; at < to; i++) {
			if (rz_cons_is_breaked()) {
				goto beach;
			}
			if (at < bb->addr) {
				break;
			}
			if (i >= (bsize - maxinstrsz)) {
				i = 0;
			}
			if (!i) {
				rz_io_read_at(core->io, at, buf, bsize);
			}
			ret = rz_analysis_op(core->analysis, &aop, at, buf + i, bsize - i, RZ_ANALYSIS_OP_MASK_VAL);
			if (ret <= 0) {
				i += minopcode;
				at += minopcode;
				rz_analysis_op_fini(&aop);
				continue;
			}
			i += ret - 1;
			at += ret;
			int j, src_imm = -1, dst_imm = -1;
			ut64 src_addr = UT64_MAX;
			ut64 dst_addr = UT64_MAX;
			for (j = 0; j < 3; j++) {
				if (aop.src[j]) {
					if (aop.src[j]->type == RZ_ANALYSIS_VAL_REG) {
						if (aop.src[j]->reg && aop.src[j]->reg->name) {
							src_addr = rz_reg_getv(esil->analysis->reg, aop.src[j]->reg->name);
						}
						src_imm = 0;
					} else if (aop.src[j]->type == RZ_ANALYSIS_VAL_MEM) {
						if (aop.src[j]->reg && aop.src[j]->reg->name) {
							src_addr = rz_reg_getv(esil->analysis->reg, aop.src[j]->reg->name);
							if (aop.src[j]->regdelta && aop.src[j]->regdelta->name) {
								src_addr += rz_reg_getv(esil->analysis->reg, aop.src[j]->regdelta->name) * aop.src[j]->mul;
							}
						}
						src_imm = aop.src[j]->base + aop.src[j]->delta;
					} else if (aop.src[j]->type == RZ_ANALYSIS_VAL_IMM) {
						src_addr = aop.src[j]->imm;
						src_imm = 0;
					}
				}
			}
			if (aop.dst) {
				if (aop.dst->type == RZ_ANALYSIS_VAL_REG) {
					if (aop.dst->reg && aop.dst->reg->name) {
						dst_addr = rz_reg_getv(esil->analysis->reg, aop.dst->reg->name);
					}
					dst_imm = 0;
				} else if (aop.dst->type == RZ_ANALYSIS_VAL_MEM) {
					if (aop.dst->reg && aop.dst->reg->name) {
						dst_addr = rz_reg_getv(esil->analysis->reg, aop.dst->reg->name);
						if (aop.dst->regdelta && aop.dst->regdelta->name) {
							dst_addr += rz_reg_getv(esil->analysis->reg, aop.dst->regdelta->name) * aop.dst->mul;
						}
					}
					dst_imm = aop.dst->base + aop.dst->delta;
				} else if (aop.dst->type == RZ_ANALYSIS_VAL_IMM) {
					dst_addr = aop.dst->imm;
					dst_imm = 0;
				}
			}
			RzAnalysisVar *var = rz_analysis_get_used_function_var(core->analysis, aop.addr);
			if (false) { // src_addr != UT64_MAX || dst_addr != UT64_MAX) {
				//  if (src_addr == UT64_MAX && dst_addr == UT64_MAX) {
				rz_analysis_op_fini(&aop);
				continue;
			}
			struct TLAnalysisContext ctx = {
				.aop = &aop,
				.var = var,
				.src_addr = src_addr,
				.dst_addr = dst_addr,
				.src_imm = src_imm,
				.dst_imm = dst_imm
			};
			resolve_type_links(core, at, &ctx, ret, &resolved);
			if (rz_analysis_op_nonlinear(aop.type)) {
				rz_reg_set_value(esil->analysis->reg, pc, at);
				set_retval(core, at - ret);
			} else {
				rz_core_esil_step(core, UT64_MAX, NULL, NULL, false);
			}
			rz_analysis_op_fini(&aop);
		}
	}
beach:
	rz_io_cache_reset(core->io, core->io->cached); // drop cache writes
	rz_config_set_i(core->config, "io.cache", ioCache);
	rz_config_set_i(core->config, "dbg.follow", dbg_follow);
	if (stack_set) {
		rz_core_analysis_esil_init_mem_del(core, NULL, UT64_MAX, UT32_MAX);
	}
	rz_core_seek(core, oldoff, true);
	rz_analysis_esil_free(esil);
	rz_reg_arena_pop(core->analysis->reg);
	rz_core_reg_update_flags(core);
	rz_cons_break_pop();
	free(buf);
}

RZ_IPI void rz_core_types_link_print(RzCore *core, RzType *type, ut64 addr, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(type);
	char *typestr = rz_type_as_string(core->analysis->typedb, type);
	if (!typestr) {
		return;
	}
	switch (mode) {
	case RZ_OUTPUT_MODE_JSON: {
		rz_return_if_fail(pj);
		pj_o(pj);
		char *saddr = rz_str_newf("0x%08" PFMT64x, addr);
		pj_ks(pj, saddr, typestr);
		pj_end(pj);
		free(saddr);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("0x%08" PFMT64x " = %s\n", addr, typestr);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		rz_cons_printf("tl \"%s\" 0x%" PFMT64x "\n", typestr, addr);
		break;
	case RZ_OUTPUT_MODE_LONG: {
		char *fmt = rz_type_as_format(core->analysis->typedb, type);
		if (!fmt) {
			eprintf("Can't fint type %s", typestr);
		}
		rz_cons_printf("(%s)\n", typestr);
		rz_core_cmdf(core, "pf %s @ 0x%" PFMT64x "\n", fmt, addr);
		free(fmt);
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
	free(typestr);
}

struct coremodepj {
	RzCore *core;
	RzOutputMode mode;
	PJ *pj;
};

static bool typelink_print_cb(void *user, ut64 k, const void *v) {
	rz_return_val_if_fail(user && v, false);
	struct coremodepj *c = user;
	rz_core_types_link_print(c->core, (RzType *)v, k, c->mode, c->pj);
	return true;
}

RZ_IPI void rz_core_types_link_print_all(RzCore *core, RzOutputMode mode) {
	PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? pj_new() : NULL;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(pj);
	}
	struct coremodepj c = { core, mode, pj };
	ht_up_foreach(core->analysis->type_links, typelink_print_cb, &c);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

/**
 * \brief Link an address \p addr to the type referenced by \p typestr
 *
 * NOTE: This is likely going to be deprecated with the use of global variables.
 *
 * \param core RzCore reference
 * \param typestr Name of the type that should be defined at \p addr
 * \param addr Address where the type should be used
 */
RZ_API void rz_core_types_link(RzCore *core, const char *typestr, ut64 addr) {
	char *error_msg = NULL;
	RzType *type = rz_type_parse_string_single(core->analysis->typedb->parser, typestr, &error_msg);
	if (!type || error_msg) {
		if (error_msg) {
			eprintf("%s", error_msg);
		}
		free(error_msg);
		return;
	}
	rz_analysis_type_set_link(core->analysis, type, addr);
	RzList *fcns = rz_analysis_get_functions_in(core->analysis, core->offset);
	if (rz_list_length(fcns) > 1) {
		eprintf("Multiple functions found in here.\n");
	} else if (rz_list_length(fcns) == 1) {
		RzAnalysisFunction *fcn = rz_list_first(fcns);
		rz_core_link_stroff(core, fcn);
	}
	rz_list_free(fcns);
}

RZ_IPI void rz_core_types_link_show(RzCore *core, ut64 addr) {
	RzType *link = rz_analysis_type_link_at(core->analysis, addr);
	if (link) {
		rz_core_types_link_print(core, link, addr, RZ_OUTPUT_MODE_LONG, NULL);
	}
}

// Everything

RZ_IPI void rz_core_types_print_all(RzCore *core, RzOutputMode mode) {
	RzListIter *it;
	RzBaseType *btype;
	RzList *types = rz_type_db_get_base_types(core->analysis->typedb);
	switch (mode) {
	case RZ_OUTPUT_MODE_JSON: {
		PJ *pj = pj_new();
		if (!pj) {
			return;
		}
		pj_a(pj);
		rz_list_foreach (types, it, btype) {
			pj_o(pj);
			// rz_str_trim(format_s);
			pj_ks(pj, "type", btype->name);
			pj_ki(pj, "size", btype->size);
			// pj_ks(pj, "format", format_s);
			pj_end(pj);
		}
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD:
		rz_list_foreach (types, it, btype) {
			rz_cons_println(btype->name);
		}
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		rz_list_foreach (types, it, btype) {
			char *fmt = rz_type_format(core->analysis->typedb, btype->name);
			if (fmt) {
				rz_cons_printf("pf.%s %s\n", btype->name, fmt);
				free(fmt);
			}
		}
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	rz_list_free(types);
}

RZ_IPI void rz_types_define(RzCore *core, const char *type) {
	// Add trailing semicolon to force the valid C syntax
	// It allows us to skip the trailing semicolon in the input
	// to reduce the unnecessary typing
	char *tmp = rz_str_newf("%s;", type);
	if (!tmp) {
		return;
	}
	char *error_msg = NULL;
	RzTypeDB *typedb = core->analysis->typedb;
	int result = rz_type_parse_string_stateless(typedb->parser, tmp, &error_msg);
	if (result && error_msg) {
		eprintf("%s", error_msg);
		free(error_msg);
	}
}

RZ_IPI bool rz_types_open_file(RzCore *core, const char *path) {
	const char *dir = rz_config_get(core->config, "dir.types");
	RzTypeDB *typedb = core->analysis->typedb;
	if (!strcmp(path, "-")) {
		char *tmp = rz_core_editor(core, "*.h", "");
		if (tmp) {
			char *error_msg = NULL;
			int result = rz_type_parse_string_stateless(typedb->parser, tmp, &error_msg);
			if (result && error_msg) {
				RZ_LOG_ERROR("%s", error_msg);
				free(error_msg);
			}
			free(tmp);
		}
	} else {
		if (!rz_file_exists(path)) {
			RZ_LOG_ERROR("File \"%s\" does not exist\n", path);
			return false;
		}
		char *error_msg = NULL;
		int result = rz_type_parse_file_stateless(typedb->parser, path, dir, &error_msg);
		if (result && error_msg) {
			RZ_LOG_ERROR("%s", error_msg);
			free(error_msg);
		}
	}
	return true;
}

RZ_IPI bool rz_types_open_editor(RzCore *core, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(name, false);
	RzTypeDB *typedb = core->analysis->typedb;
	RzBaseType *t = rz_type_db_get_compound_type(typedb, name);
	if (!t) {
		return false;
	}
	char *str = rz_core_base_type_as_c(core, t, true);
	if (!str) {
		RZ_LOG_ERROR("Cannot generate C representation of type \"%s\"\n", name);
		return false;
	}
	bool result = false;
	char *tmp = rz_core_editor(core, NULL, str);
	if (tmp) {
		result = rz_type_db_edit_base_type(typedb, t->name, tmp);
		free(tmp);
	}
	free(str);
	return result;
}
