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

static void kv_lines_print_sorted(char *kv_lines) {
	RzListIter *iter;
	char *k;
	RzList *list = rz_str_split_duplist(kv_lines, "\n", true);
	rz_list_sort(list, (RzListComparator)strcmp);
	rz_list_foreach (list, iter, k) {
		if (RZ_STR_ISNOTEMPTY(k)) {
			rz_cons_println(k);
		}
	}
	rz_list_free(list);
}

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

static void core_types_enum_print(RzCore *core, RzBaseType *btype, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(core && btype);
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

RZ_IPI void rz_core_types_enum_print(RzCore *core, const char *name, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(name);
	RzTypeDB *typedb = core->analysis->typedb;
	RzBaseType *btype = rz_type_db_get_enum(typedb, name);
	if (!btype) {
		return;
	}
	core_types_enum_print(core, btype, mode, pj);
	rz_type_base_type_free(btype);
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
		core_types_enum_print(core, btype, mode, pj);
	}
	rz_list_free(enumlist);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

static void core_types_enum_print_c(RzBaseType *btype, bool multiline) {
	char *separator;
	rz_cons_printf("enum %s {%s", btype->name, multiline ? "\n" : "");
	if (!rz_vector_empty(&btype->enum_data.cases)) {
		separator = multiline ? "\t" : "";
		RzTypeEnumCase *cas;
		rz_vector_foreach(&btype->enum_data.cases, cas) {
			rz_cons_printf("%s%s = %" PFMT64u, separator, cas->name, cas->val);
			separator = multiline ? ",\n\t" : ", ";
		}
		rz_cons_println(multiline ? "\n};" : "};");
	}
}

RZ_IPI void rz_core_types_enum_print_c(RzTypeDB *typedb, const char *name, bool multiline) {
	RzBaseType *btype = rz_type_db_get_enum(typedb, name);
	if (!btype) {
		return;
	}
	core_types_enum_print_c(btype, multiline);
	rz_type_base_type_free(btype);
}

RZ_IPI void rz_core_types_enum_print_c_all(RzTypeDB *typedb, bool multiline) {
	RzList *enumlist = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_ENUM);
	RzListIter *it;
	RzBaseType *btype;
	rz_list_foreach (enumlist, it, btype) {
		core_types_enum_print_c(btype, multiline);
	}
	rz_list_free(enumlist);
}

// Unions

static void core_types_union_print(RzCore *core, RzBaseType *btype, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(core && btype);
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
				const char *mtype = rz_type_as_string(core->analysis->typedb, memb->type);
				pj_ks(pj, memb->name, mtype);
			}
			pj_end(pj);
		}
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD: {
		if (btype && !rz_vector_empty(&btype->union_data.members)) {
			RzTypeUnionMember *memb;
			rz_vector_foreach(&btype->union_data.members, memb) {
				const char *mtype = rz_type_as_string(core->analysis->typedb, memb->type);
				rz_cons_printf("%s: %s\n", memb->name, mtype);
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

RZ_IPI void rz_core_types_union_print(RzCore *core, const char *name, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(name);
	RzTypeDB *typedb = core->analysis->typedb;
	RzBaseType *btype = rz_type_db_get_union(typedb, name);
	if (!btype) {
		return;
	}
	core_types_union_print(core, btype, mode, pj);
	rz_type_base_type_free(btype);
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
		core_types_union_print(core, btype, mode, pj);
	}
	rz_list_free(unionlist);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

static void core_types_union_print_c(RzTypeDB *typedb, RzBaseType *btype, bool multiline) {
	char *separator;
	rz_cons_printf("union %s {%s", btype->name, multiline ? "\n" : "");
	if (!rz_vector_empty(&btype->enum_data.cases)) {
		separator = multiline ? "\t" : "";
		RzTypeUnionMember *memb;
		rz_vector_foreach(&btype->union_data.members, memb) {
			const char *membtype = rz_type_as_string(typedb, memb->type);
			if (memb->type->kind == RZ_TYPE_KIND_ARRAY) {
				rz_cons_printf("%s%s %s[%" PFMT64d "]", separator, membtype,
					memb->name, memb->type->array.count);
			} else {
				rz_cons_printf("%s%s %s", separator, membtype, memb->name);
			}
			separator = multiline ? ";\n\t" : "; ";
		}
		rz_cons_println(multiline ? "\n};" : "};");
	}
}

RZ_IPI void rz_core_types_union_print_c(RzTypeDB *typedb, const char *name, bool multiline) {
	RzBaseType *btype = rz_type_db_get_union(typedb, name);
	if (!btype) {
		return;
	}
	core_types_union_print_c(typedb, btype, multiline);
	rz_type_base_type_free(btype);
}

RZ_IPI void rz_core_types_union_print_c_all(RzTypeDB *typedb, bool multiline) {
	RzList *unionlist = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_UNION);
	RzListIter *it;
	RzBaseType *btype;
	rz_list_foreach (unionlist, it, btype) {
		core_types_union_print_c(typedb, btype, multiline);
	}
	rz_list_free(unionlist);
}

// Structures

static void core_types_struct_print(RzCore *core, RzBaseType *btype, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(core && btype);
	switch (mode) {
	case RZ_OUTPUT_MODE_JSON: {
		rz_return_if_fail(pj);
		pj_o(pj);
		if (btype && !rz_vector_empty(&btype->struct_data.members)) {
			pj_ks(pj, "name", btype->name);
			pj_k(pj, "members");
			pj_o(pj);
			RzTypeStructMember *memb;
			rz_vector_foreach(&btype->struct_data.members, memb) {
				const char *mtype = rz_type_as_string(core->analysis->typedb, memb->type);
				pj_ks(pj, memb->name, mtype);
			}
			pj_end(pj);
		}
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD: {
		if (btype && !rz_vector_empty(&btype->union_data.members)) {
			RzTypeStructMember *memb;
			rz_vector_foreach(&btype->struct_data.members, memb) {
				const char *mtype = rz_type_as_string(core->analysis->typedb, memb->type);
				rz_cons_printf("%s: %s\n", memb->name, mtype);
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

RZ_IPI void rz_core_types_struct_print(RzCore *core, const char *name, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(name);
	RzTypeDB *typedb = core->analysis->typedb;
	RzBaseType *btype = rz_type_db_get_struct(typedb, name);
	if (!btype) {
		return;
	}
	core_types_struct_print(core, btype, mode, pj);
	rz_type_base_type_free(btype);
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
		core_types_enum_print(core, btype, mode, pj);
	}
	rz_list_free(structlist);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

static void core_types_struct_print_c(RzTypeDB *typedb, RzBaseType *btype, bool multiline) {
	char *separator;
	rz_cons_printf("struct %s {%s", btype->name, multiline ? "\n" : "");
	if (!rz_vector_empty(&btype->struct_data.members)) {
		separator = multiline ? "\t" : "";
		RzTypeStructMember *memb;
		rz_vector_foreach(&btype->struct_data.members, memb) {
			const char *membtype = rz_type_as_string(typedb, memb->type);
			if (memb->type->kind == RZ_TYPE_KIND_ARRAY) {
				rz_cons_printf("%s%s %s[%" PFMT64d "]", separator, membtype,
					memb->name, memb->type->array.count);
			} else {
				rz_cons_printf("%s%s %s", separator, membtype, memb->name);
			}
			separator = multiline ? ";\n\t" : "; ";
		}
		rz_cons_println(multiline ? "\n};" : "};");
	}
}

RZ_IPI void rz_core_types_struct_print_c(RzTypeDB *typedb, const char *name, bool multiline) {
	rz_return_if_fail(name);
	RzBaseType *btype = rz_type_db_get_struct(typedb, name);
	if (!btype) {
		return;
	}
	core_types_struct_print_c(typedb, btype, multiline);
	rz_type_base_type_free(btype);
}

RZ_IPI void rz_core_types_struct_print_c_all(RzTypeDB *typedb, bool multiline) {
	RzList *structlist = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_STRUCT);
	RzListIter *it;
	RzBaseType *btype;
	rz_list_foreach (structlist, it, btype) {
		core_types_struct_print_c(typedb, btype, multiline);
	}
	rz_list_free(structlist);
}

// Typedefs

static void core_types_typedef_print(RzCore *core, RzBaseType *btype, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(core && btype);
	const char *typestr = rz_type_as_string(core->analysis->typedb, btype->type);
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
}

RZ_IPI void rz_core_types_typedef_print(RzCore *core, const char *name, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(name);
	RzTypeDB *typedb = core->analysis->typedb;
	RzBaseType *btype = rz_type_db_get_typedef(typedb, name);
	if (!btype) {
		return;
	}
	core_types_typedef_print(core, btype, mode, pj);
	rz_type_base_type_free(btype);
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
		core_types_enum_print(core, btype, mode, pj);
	}
	rz_list_free(typedeflist);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

static void core_types_typedef_print_c(RzTypeDB *typedb, RzBaseType *btype) {
	const char *typestr = rz_type_as_string(typedb, btype->type);
	rz_cons_printf("typedef %s %s;", btype->name, typestr);
}

RZ_IPI void rz_core_types_typedef_print_c(RzTypeDB *typedb, const char *typedef_name) {
	RzBaseType *btype = rz_type_db_get_typedef(typedb, typedef_name);
	if (!btype) {
		return;
	}
	core_types_typedef_print_c(typedb, btype);
	rz_type_base_type_free(btype);
}

RZ_IPI void rz_core_types_typedef_print_c_all(RzTypeDB *typedb) {
	RzList *typedeflist = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_TYPEDEF);
	RzListIter *it;
	RzBaseType *btype;
	rz_list_foreach (typedeflist, it, btype) {
		core_types_typedef_print_c(typedb, btype);
	}
	rz_list_free(typedeflist);
}

// Function types

RZ_IPI void rz_types_function_print(RzTypeDB *typedb, const char *function, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(function);
	Sdb *TDB = typedb->sdb_types;
	char *res = sdb_querys(TDB, NULL, -1, sdb_fmt("func.%s.args", function));
	int i, args = sdb_num_get(TDB, sdb_fmt("func.%s.args", function), 0);
	const char *ret = sdb_const_get(TDB, sdb_fmt("func.%s.ret", function), 0);
	if (!ret) {
		ret = "void";
	}
	switch (mode) {
	case RZ_OUTPUT_MODE_JSON: {
		rz_return_if_fail(pj);
		pj_o(pj);
		pj_ks(pj, "name", function);
		pj_ks(pj, "ret", ret);
		pj_k(pj, "args");
		pj_a(pj);
		for (i = 0; i < args; i++) {
			char *type = sdb_get(TDB, sdb_fmt("func.%s.arg.%d", function, i), 0);
			if (!type) {
				continue;
			}
			char *name = strchr(type, ',');
			if (name) {
				*name++ = 0;
			}
			pj_o(pj);
			pj_ks(pj, "type", type);
			if (name) {
				pj_ks(pj, "name", name);
			} else {
				pj_ks(pj, "name", "(null)");
			}
			pj_end(pj);
		}
		pj_end(pj);
		pj_end(pj);
	} break;
	case RZ_OUTPUT_MODE_SDB: {
		char *keys = sdb_querys(TDB, NULL, -1, sdb_fmt("~~func.%s", function));
		if (keys) {
			kv_lines_print_sorted(keys);
			free(keys);
		}
	} break;
	default: {
		rz_cons_printf("%s %s (", ret, function);
		for (i = 0; i < args; i++) {
			char *type = sdb_get(TDB, sdb_fmt("func.%s.arg.%d", function, i), 0);
			char *name = strchr(type, ',');
			if (name) {
				*name++ = 0;
			}
			rz_cons_printf("%s%s %s", i == 0 ? "" : ", ", type, name);
		}
		rz_cons_printf(");\n");
	} break;
	}
	free(res);
}

RZ_IPI void rz_core_types_function_print_all(RzCore *core, RzOutputMode mode) {
	Sdb *TDB = core->analysis->typedb->sdb_types;
	SdbKv *kv;
	SdbListIter *iter;
	PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? pj_new() : NULL;
	SdbList *l = sdb_foreach_list(TDB, true);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(pj);
	}
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "func")) {
			const char *name = sdbkv_key(kv);
			rz_types_function_print(core->analysis->typedb, name, mode, pj);
		}
	}
	ls_free(l);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

// Noreturn function attributes

static bool nonreturn_print_rizin(void *p, const char *k, const char *v) {
	RzCore *core = (RzCore *)p;
	Sdb *TDB = core->analysis->typedb->sdb_types;
	if (!strncmp(v, "func", strlen("func") + 1)) {
		char *query = sdb_fmt("func.%s.noreturn", k);
		if (sdb_bool_get(TDB, query, NULL)) {
			rz_cons_printf("tnn %s\n", k);
		}
	}
	if (!strncmp(k, "addr.", 5)) {
		rz_cons_printf("tna 0x%s %s\n", k + 5, v);
	}
	return true;
}

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
		pj_k(pj, s);
	}
	pj_end(pj);
	rz_cons_println(pj_string(pj));
	pj_free(pj);
	return true;
}

RZ_IPI void rz_core_types_function_noreturn_print(RzCore *core, RzOutputMode mode) {
	RzList *noretl = rz_type_noreturn_functions(core->analysis->typedb);
	switch (mode) {
	case RZ_OUTPUT_MODE_RIZIN: {
		Sdb *TDB = core->analysis->typedb->sdb_types;
		sdb_foreach(TDB, nonreturn_print_rizin, core);
		break;
	}
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
		rz_str_trim(fmt);
		switch (mode) {
		case RZ_OUTPUT_MODE_JSON: {
			PJ *pj = pj_new();
			if (!pj) {
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

static void set_offset_hint(RzCore *core, RzAnalysisOp *op, const char *type, ut64 laddr, ut64 at, int offimm) {
	Sdb *TDB = core->analysis->typedb->sdb_types;
	char *res = rz_type_db_get_struct_member(core->analysis->typedb, type, offimm);
	const char *cmt = ((offimm == 0) && res) ? res : type;
	if (offimm > 0) {
		// set hint only if link is present
		char *query = sdb_fmt("link.%08" PFMT64x, laddr);
		if (res && sdb_const_get(TDB, query, 0)) {
			rz_analysis_hint_set_offset(core->analysis, at, res);
		}
	} else if (cmt && rz_analysis_op_ismemref(op->type)) {
		rz_meta_set_string(core->analysis, RZ_META_TYPE_VARTYPE, at, cmt);
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
	const char *varpfx;
	int dbg_follow = rz_config_get_i(core->config, "dbg.follow");
	RzTypeDB *typedb = core->analysis->typedb;
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
	rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_ALL, true);
	ut64 spval = rz_reg_getv(esil->analysis->reg, sp_name);
	if (spval) {
		// reset stack pointer to initial value
		RzRegItem *sp = rz_reg_get(esil->analysis->reg, sp_name, -1);
		ut64 curpc = rz_reg_getv(esil->analysis->reg, pc_name);
		int stacksz = rz_core_get_stacksz(core, fcn->addr, curpc);
		if (stacksz > 0) {
			rz_reg_arena_zero(esil->analysis->reg); // clear prev reg values
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
			int index = 0;
			if (aop.ireg) {
				index = rz_reg_getv(esil->analysis->reg, aop.ireg) * aop.scale;
			}
			int j, src_imm = -1, dst_imm = -1;
			ut64 src_addr = UT64_MAX;
			ut64 dst_addr = UT64_MAX;
			for (j = 0; j < 3; j++) {
				if (aop.src[j] && aop.src[j]->reg && aop.src[j]->reg->name) {
					src_addr = rz_reg_getv(esil->analysis->reg, aop.src[j]->reg->name) + index;
					src_imm = aop.src[j]->delta;
				}
			}
			if (aop.dst && aop.dst->reg && aop.dst->reg->name) {
				dst_addr = rz_reg_getv(esil->analysis->reg, aop.dst->reg->name) + index;
				dst_imm = aop.dst->delta;
			}
			RzAnalysisVar *var = rz_analysis_get_used_function_var(core->analysis, aop.addr);
			if (false) { // src_addr != UT64_MAX || dst_addr != UT64_MAX) {
				//  if (src_addr == UT64_MAX && dst_addr == UT64_MAX) {
				rz_analysis_op_fini(&aop);
				continue;
			}
			char *slink = rz_type_link_at(typedb, src_addr);
			char *vlink = rz_type_link_at(typedb, src_addr + src_imm);
			char *dlink = rz_type_link_at(typedb, dst_addr);
			//TODO: Handle register based arg for struct offset propgation
			if (vlink && var && var->kind != 'r') {
				if (rz_type_kind(typedb, vlink) == RZ_BASE_TYPE_KIND_UNION) {
					varpfx = "union";
				} else {
					varpfx = "struct";
				}
				// if a var addr matches with struct , change it's type and name
				// var int local_e0h --> var struct foo
				if (strcmp(var->name, vlink) && !resolved) {
					resolved = true;
					rz_analysis_var_set_type(var, varpfx);
					rz_analysis_var_rename(var, vlink, false);
				}
			} else if (slink) {
				set_offset_hint(core, &aop, slink, src_addr, at - ret, src_imm);
			} else if (dlink) {
				set_offset_hint(core, &aop, dlink, dst_addr, at - ret, dst_imm);
			}
			if (rz_analysis_op_nonlinear(aop.type)) {
				rz_reg_set_value(esil->analysis->reg, pc, at);
				set_retval(core, at - ret);
			} else {
				rz_core_esil_step(core, UT64_MAX, NULL, NULL, false);
			}
			free(dlink);
			free(vlink);
			free(slink);
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
	rz_core_regs2flags(core);
	rz_cons_break_pop();
	free(buf);
}

RZ_IPI void rz_core_types_link_print(RzCore *core, const char *type, ut64 addr, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(type);
	switch (mode) {
	case RZ_OUTPUT_MODE_JSON: {
		rz_return_if_fail(pj);
		pj_o(pj);
		char *saddr = rz_str_newf("0x%08" PFMT64x, addr);
		pj_ks(pj, saddr, type);
		pj_end(pj);
		free(saddr);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("0x%08" PFMT64x " = %s\n", addr, type);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		rz_cons_printf("tl %s 0x%" PFMT64x "\n", type, addr);
		break;
	case RZ_OUTPUT_MODE_LONG: {
		char *fmt = rz_type_format(core->analysis->typedb, type);
		if (!fmt) {
			eprintf("Can't fint type %s", type);
		}
		rz_cons_printf("(%s)\n", type);
		rz_core_cmdf(core, "pf %s @ 0x%" PFMT64x "\n", fmt, addr);
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_IPI void rz_core_types_link_print_all(RzCore *core, RzOutputMode mode) {
	Sdb *TDB = core->analysis->typedb->sdb_types;
	SdbKv *kv;
	SdbListIter *iter;
	PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? pj_new() : NULL;
	SdbList *l = sdb_foreach_list(TDB, true);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(pj);
	}
	ls_foreach (l, iter, kv) {
		if (!strncmp(sdbkv_key(kv), "link.", strlen("link."))) {
			const char *name = sdbkv_value(kv);
			char *saddr = rz_str_newf("0x%s", sdbkv_key(kv) + strlen("link."));
			ut64 addr = rz_num_math(core->num, saddr);
			rz_core_types_link_print(core, name, addr, mode, pj);
			free(saddr);
		}
	}
	ls_free(l);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

RZ_IPI void rz_core_types_link(RzCore *core, const char *type, ut64 addr) {
	Sdb *TDB = core->analysis->typedb->sdb_types;
	char *tmp = sdb_get(TDB, type, 0);
	if (RZ_STR_ISEMPTY(tmp)) {
		eprintf("unknown type %s\n", type);
		free(tmp);
		return;
	}
	rz_type_set_link(core->analysis->typedb, type, addr);
	RzList *fcns = rz_analysis_get_functions_in(core->analysis, core->offset);
	if (rz_list_length(fcns) > 1) {
		eprintf("Multiple functions found in here.\n");
	} else if (rz_list_length(fcns) == 1) {
		RzAnalysisFunction *fcn = rz_list_first(fcns);
		rz_core_link_stroff(core, fcn);
	}
	rz_list_free(fcns);
	free(tmp);
}

RZ_IPI void rz_core_types_link_show(RzCore *core, ut64 addr) {
	Sdb *TDB = core->analysis->typedb->sdb_types;
	const char *query = sdb_fmt("link.%08" PFMT64x, addr);
	const char *link = sdb_const_get(TDB, query, 0);
	if (link) {
		rz_core_types_link_print(core, link, addr, RZ_OUTPUT_MODE_LONG, NULL);
	}
}

// Everything

static bool sdb_if_type_cb(void *p, const char *k, const char *v) {
	return !strncmp(v, "type", strlen("type") + 1);
}

RZ_IPI void rz_core_types_print_all(RzCore *core, RzOutputMode mode) {
	SdbListIter *it;
	SdbKv *kv;
	Sdb *TDB = core->analysis->typedb->sdb_types;
	SdbList *l = sdb_foreach_list_filter(TDB, sdb_if_type_cb, true);
	switch (mode) {
	case RZ_OUTPUT_MODE_JSON: {
		PJ *pj = pj_new();
		if (!pj) {
			return;
		}
		pj_a(pj);
		// TODO: Make it more efficient
		ls_foreach (l, it, kv) {
			pj_o(pj);
			const char *k = sdbkv_key(kv);
			char *sizecmd = rz_str_newf("type.%s.size", k);
			char *size_s = sdb_querys(TDB, NULL, -1, sizecmd);
			char *formatcmd = rz_str_newf("type.%s", k);
			char *format_s = sdb_querys(TDB, NULL, -1, formatcmd);
			rz_str_trim(format_s);
			pj_ks(pj, "type", k);
			pj_ki(pj, "size", size_s ? atoi(size_s) : -1);
			pj_ks(pj, "format", format_s);
			free(size_s);
			free(format_s);
			free(sizecmd);
			free(formatcmd);
			pj_end(pj);
		}
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD:
		ls_foreach (l, it, kv) {
			rz_cons_println(sdbkv_key(kv));
		}
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		// This is a special case, we don't filter anything
		ls_free(l);
		l = sdb_foreach_list(TDB, true);
		ls_foreach (l, it, kv) {
			rz_cons_printf("tk %s=%s\n", sdbkv_key(kv), sdbkv_value(kv));
		}
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	ls_free(l);
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
	char *out = rz_type_parse_c_string(core->analysis->typedb, tmp, &error_msg);
	free(tmp);
	if (out) {
		rz_type_db_save_parsed_type(core->analysis->typedb, out);
		free(out);
	}
	if (error_msg) {
		eprintf("%s", error_msg);
		free(error_msg);
	}
}

RZ_IPI void rz_types_open_file(RzCore *core, const char *path) {
	const char *dir = rz_config_get(core->config, "dir.types");
	char *homefile = NULL;
	RzTypeDB *typedb = core->analysis->typedb;
	if (*path == '~') {
		if (path[1] && path[2]) {
			homefile = rz_str_home(path + 2);
			path = homefile;
		}
	}
	if (!strcmp(path, "-")) {
		char *tmp = rz_core_editor(core, "*.h", "");
		if (tmp) {
			char *error_msg = NULL;
			char *out = rz_type_parse_c_string(typedb, tmp, &error_msg);
			if (out) {
				rz_type_db_save_parsed_type(typedb, out);
				free(out);
			}
			if (error_msg) {
				fprintf(stderr, "%s", error_msg);
				free(error_msg);
			}
			free(tmp);
		}
	} else {
		char *error_msg = NULL;
		char *out = rz_type_parse_c_file(typedb, path, dir, &error_msg);
		if (out) {
			rz_type_db_save_parsed_type(typedb, out);
			free(out);
		}
		if (error_msg) {
			fprintf(stderr, "%s", error_msg);
			free(error_msg);
		}
	}
	free(homefile);
}

RZ_IPI void rz_types_open_editor(RzCore *core, const char *typename) {
	RzTypeDB *typedb = core->analysis->typedb;
	char *str = rz_core_cmd_strf(core, "tc %s", typename ? typename : "");
	char *tmp = rz_core_editor(core, "*.h", str);
	if (tmp) {
		char *error_msg = NULL;
		char *out = rz_type_parse_c_string(typedb, tmp, &error_msg);
		if (out) {
			// remove previous types and save new edited types
			rz_type_db_purge(typedb);
			rz_type_parse_c_reset(typedb);
			rz_type_db_save_parsed_type(typedb, out);
			free(out);
		}
		if (error_msg) {
			eprintf("%s\n", error_msg);
			free(error_msg);
		}
		free(tmp);
	}
	free(str);
}
