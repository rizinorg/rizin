// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2009-2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 Jody Frankowski <jody.frankowski@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_types.h>
#include <rz_list.h>
#include <rz_core.h>

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

RZ_IPI RzList *rz_types_calling_conventions(Sdb *db) {
	RzList *ccl = rz_list_new();
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(db, true);
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "cc")) {
			rz_list_append(ccl, strdup(sdbkv_key(kv)));
		}
	}
	ls_free(l);
	return ccl;
}

RZ_IPI void rz_core_types_calling_conventions_print(RzCore *core, RzOutputMode mode) {
	RzList *list = rz_types_calling_conventions(core->analysis->sdb_cc);
	RzListIter *iter;
	const char *cc;
	switch (mode) {
	case RZ_OUTPUT_MODE_STANDARD: {
		rz_list_foreach (list, iter, cc) {
			rz_cons_println(cc);
		}
	} break;
	case RZ_OUTPUT_MODE_JSON: {
		PJ *pj = rz_core_pj_new(core);
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

RZ_IPI RzList *rz_types_enums(Sdb *db) {
	RzList *ccl = rz_list_new();
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(db, true);
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "enum")) {
			rz_list_append(ccl, strdup(sdbkv_key(kv)));
		}
	}
	ls_free(l);
	return ccl;
}

RZ_IPI void rz_core_types_enum_print(RzCore *core, const char *enum_name, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(enum_name);
	Sdb *TDB = core->analysis->sdb_types;
	switch (mode) {
	case RZ_OUTPUT_MODE_JSON: {
		rz_return_if_fail(pj);
		RTypeEnum *member;
		RzListIter *iter;
		RzList *list = rz_type_get_enum(TDB, enum_name);
		pj_o(pj);
		if (list && !rz_list_empty(list)) {
			pj_ks(pj, "name", enum_name);
			pj_k(pj, "values");
			pj_o(pj);
			rz_list_foreach (list, iter, member) {
				pj_kn(pj, member->name, rz_num_math(NULL, member->val));
			}
			pj_end(pj);
		}
		pj_end(pj);
		rz_list_free(list);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD: {
		RzList *list = rz_type_get_enum(TDB, enum_name);
		RzListIter *iter;
		RTypeEnum *member;
		rz_list_foreach (list, iter, member) {
			rz_cons_printf("%s = %s\n", member->name, member->val);
		}
		rz_list_free(list);
		break;
	}
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_println(enum_name);
		break;
	case RZ_OUTPUT_MODE_SDB: {
		char *keys = sdb_querys(TDB, NULL, -1, sdb_fmt("~~enum.%s", enum_name));
		if (keys) {
			kv_lines_print_sorted(keys);
			free(keys);
		}
		break;
	}
	default:
		break;
	}
}

RZ_IPI void rz_core_types_enum_print_all(RzCore *core, RzOutputMode mode) {
	Sdb *TDB = core->analysis->sdb_types;
	RzList *enumlist = rz_types_enums(TDB);
	RzListIter *it;
	char *e;
	PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? rz_core_pj_new(core) : NULL;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(pj);
	}
	rz_list_foreach (enumlist, it, e) {
		rz_core_types_enum_print(core, e, mode, pj);
	}
	rz_list_free(enumlist);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

RZ_IPI void rz_types_enum_print_c(Sdb *TDB, const char *arg, bool multiline) {
	char *name = NULL;
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(TDB, true);
	const char *separator = "";
	bool match = false;
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "enum")) {
			if (!name || strcmp(sdbkv_value(kv), name)) {
				free(name);
				name = strdup(sdbkv_key(kv));
				if (name && (arg && *arg)) {
					if (!strcmp(arg, name)) {
						match = true;
					} else {
						continue;
					}
				}
				rz_cons_printf("%s %s {%s", sdbkv_value(kv), name, multiline ? "\n" : "");
				{
					RzList *list = rz_type_get_enum(TDB, name);
					if (list && !rz_list_empty(list)) {
						RzListIter *iter;
						RTypeEnum *member;
						separator = multiline ? "\t" : "";
						rz_list_foreach (list, iter, member) {
							rz_cons_printf("%s%s = %" PFMT64u, separator, member->name, rz_num_math(NULL, member->val));
							separator = multiline ? ",\n\t" : ", ";
						}
					}
					rz_list_free(list);
				}
				rz_cons_println(multiline ? "\n};" : "};");
				if (match) {
					break;
				}
			}
		}
	}
	free(name);
	ls_free(l);
}

// Structured types (structures and unions)

static bool sdb_if_union_cb(void *p, const char *k, const char *v) {
	return !strncmp(v, "union", strlen("union") + 1);
}

static bool sdb_if_struct_cb(void *user, const char *k, const char *v) {
	rz_return_val_if_fail(user, false);
	Sdb *TDB = (Sdb *)user;
	if (!strcmp(v, "struct") && !rz_str_startswith(k, "typedef")) {
		return true;
	}
	if (!strcmp(v, "typedef")) {
		const char *typedef_key = sdb_fmt("typedef.%s", k);
		const char *type = sdb_const_get(TDB, typedef_key, NULL);
		if (type && rz_str_startswith(type, "struct")) {
			return true;
		}
	}
	return false;
}

RZ_IPI void rz_types_structured_print_json(Sdb *TDB, SdbList *l) {
	SdbKv *kv;
	SdbListIter *it;
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}

	pj_a(pj); // [
	ls_foreach (l, it, kv) {
		const char *k = sdbkv_key(kv);
		if (!k || !*k) {
			continue;
		}
		pj_o(pj); // {
		pj_ks(pj, "type", k); // key value pair of string and string
		pj_end(pj); // }
	}
	pj_end(pj); // ]

	rz_cons_println(pj_string(pj));
	pj_free(pj);
}

RZ_IPI void rz_types_union_print_json(Sdb *TDB) {
	SdbList *l = sdb_foreach_list_filter(TDB, sdb_if_union_cb, true);
	rz_types_structured_print_json(TDB, l);
	ls_free(l);
}

RZ_IPI void rz_types_struct_print_json(Sdb *TDB) {
	SdbList *l = sdb_foreach_list_filter_user(TDB, sdb_if_struct_cb, true, TDB);
	rz_types_structured_print_json(TDB, l);
	ls_free(l);
}

RZ_IPI void rz_types_structured_print_sdb(Sdb *TDB, SdbList *l) {
	SdbKv *kv;
	SdbListIter *it;
	ls_foreach (l, it, kv) {
		rz_cons_println(sdbkv_key(kv));
	}
}

RZ_IPI void rz_types_union_print_sdb(Sdb *TDB) {
	SdbList *l = sdb_foreach_list_filter(TDB, sdb_if_union_cb, true);
	rz_types_structured_print_sdb(TDB, l);
	ls_free(l);
}

RZ_IPI void rz_types_struct_print_sdb(Sdb *TDB) {
	SdbList *l = sdb_foreach_list_filter_user(TDB, sdb_if_struct_cb, true, TDB);
	rz_types_structured_print_sdb(TDB, l);
	ls_free(l);
}

RZ_IPI void rz_types_structured_print_c(Sdb *TDB, SdbList *l, const char *arg, bool multiline) {
	char *name = NULL;
	SdbKv *kv;
	SdbListIter *iter;
	const char *space = "";
	bool match = false;

	ls_foreach (l, iter, kv) {
		if (name && !strcmp(sdbkv_value(kv), name)) {
			continue;
		}
		free(name);
		int n;
		name = strdup(sdbkv_key(kv));
		if (name && (arg && *arg)) {
			if (!strcmp(arg, name)) {
				match = true;
			} else {
				continue;
			}
		}
		rz_cons_printf("%s %s {%s", sdbkv_value(kv), name, multiline ? "\n" : "");
		char *p, *var = rz_str_newf("%s.%s", sdbkv_value(kv), name);
		for (n = 0; (p = sdb_array_get(TDB, var, n, NULL)); n++) {
			char *var2 = rz_str_newf("%s.%s", var, p);
			if (var2) {
				char *val = sdb_array_get(TDB, var2, 0, NULL);
				if (val) {
					char *arr = sdb_array_get(TDB, var2, 2, NULL);
					int arrnum = atoi(arr);
					free(arr);
					if (multiline) {
						rz_cons_printf("\t%s", val);
						if (p && p[0] != '\0') {
							rz_cons_printf("%s%s", strstr(val, " *") ? "" : " ", p);
							if (arrnum) {
								rz_cons_printf("[%d]", arrnum);
							}
						}
						rz_cons_println(";");
					} else {
						rz_cons_printf("%s%s %s", space, val, p);
						if (arrnum) {
							rz_cons_printf("[%d]", arrnum);
						}
						rz_cons_print(";");
						space = " ";
					}
					free(val);
				}
				free(var2);
			}
			free(p);
		}
		free(var);
		rz_cons_println("};");
		space = "";
		if (match) {
			break;
		}
	}
	free(name);
}

RZ_IPI void rz_types_union_print_c(Sdb *TDB, const char *name, bool multiline) {
	SdbList *l = sdb_foreach_list_filter(TDB, sdb_if_union_cb, true);
	rz_types_structured_print_c(TDB, l, name, multiline);
	ls_free(l);
}

RZ_IPI void rz_types_struct_print_c(Sdb *TDB, const char *name, bool multiline) {
	SdbList *l = sdb_foreach_list_filter_user(TDB, sdb_if_struct_cb, true, TDB);
	rz_types_structured_print_c(TDB, l, name, multiline);
	ls_free(l);
}

RZ_IPI RzList *rz_types_unions(Sdb *TDB) {
	SdbList *sl = sdb_foreach_list_filter_user(TDB, sdb_if_union_cb, true, TDB);
	RzList *l = rz_list_of_sdblist(sl);
	ls_free(sl);
	return l;
}

RZ_IPI RzList *rz_types_structs(Sdb *TDB) {
	SdbList *sl = sdb_foreach_list_filter_user(TDB, sdb_if_struct_cb, true, TDB);
	RzList *l = rz_list_of_sdblist(sl);
	ls_free(sl);
	return l;
}

// Typedefs

static bool sdb_if_typedef_cb(void *p, const char *k, const char *v) {
	return !strncmp(v, "typedef", strlen("typedef") + 1);
}

RZ_IPI bool rz_core_types_typedef_info(RzCore *core, const char *name) {
	const char *istypedef;
	Sdb *TDB = core->analysis->sdb_types;
	istypedef = sdb_const_get(TDB, name, 0);
	if (istypedef && !strncmp(istypedef, "typedef", 7)) {
		const char *q = sdb_fmt("typedef.%s", name);
		const char *res = sdb_const_get(TDB, q, 0);
		if (res) {
			rz_cons_println(res);
		} else {
			return false;
		}
	} else {
		eprintf("This is not an typedef\n");
		return false;
	}
	return true;
}

RZ_IPI void rz_core_list_loaded_typedefs(RzCore *core, RzOutputMode mode) {
	PJ *pj = NULL;
	Sdb *TDB = core->analysis->sdb_types;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj = rz_core_pj_new(core);
		if (!pj) {
			return;
		}
		pj_o(pj);
	}
	char *name = NULL;
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(TDB, true);
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "typedef")) {
			if (!name || strcmp(sdbkv_value(kv), name)) {
				free(name);
				name = strdup(sdbkv_key(kv));
				if (mode == RZ_OUTPUT_MODE_STANDARD) {
					rz_cons_println(name);
				} else {
					const char *q = sdb_fmt("typedef.%s", name);
					const char *res = sdb_const_get(TDB, q, 0);
					pj_ks(pj, name, res);
				}
			}
		}
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
	free(name);
	ls_free(l);
}

RZ_IPI void rz_types_typedef_print_c(Sdb *TDB, const char *typedef_name) {
	char *name = NULL;
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(TDB, true);
	bool match = false;
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "typedef")) {
			if (!name || strcmp(sdbkv_value(kv), name)) {
				free(name);
				name = strdup(sdbkv_key(kv));
				if (name && (typedef_name && *typedef_name)) {
					if (!strcmp(typedef_name, name)) {
						match = true;
					} else {
						continue;
					}
				}
				const char *q = sdb_fmt("typedef.%s", name);
				const char *res = sdb_const_get(TDB, q, 0);
				if (res) {
					rz_cons_printf("%s %s %s;\n", sdbkv_value(kv), res, name);
				}
				if (match) {
					break;
				}
			}
		}
	}
	free(name);
	ls_free(l);
}

RZ_IPI RzList *rz_types_typedefs(Sdb *TDB) {
	SdbList *sl = sdb_foreach_list_filter_user(TDB, sdb_if_typedef_cb, true, TDB);
	RzList *l = rz_list_of_sdblist(sl);
	ls_free(sl);
	return l;
}

// Function types

RZ_IPI void rz_types_function_print(Sdb *TDB, const char *function, RzOutputMode mode, PJ *pj) {
	rz_return_if_fail(function);
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
	Sdb *TDB = core->analysis->sdb_types;
	SdbKv *kv;
	SdbListIter *iter;
	PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? rz_core_pj_new(core) : NULL;
	SdbList *l = sdb_foreach_list(TDB, true);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(pj);
	}
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "func")) {
			const char *name = sdbkv_key(kv);
			rz_types_function_print(TDB, name, mode, pj);
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
	if (!strncmp(v, "func", strlen("func") + 1)) {
		char *query = sdb_fmt("func.%s.noreturn", k);
		if (sdb_bool_get(core->analysis->sdb_types, query, NULL)) {
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
	PJ *pj = rz_core_pj_new(core);
	pj_a(pj);
	rz_list_foreach (noretl, it, s) {
		pj_k(pj, s);
	}
	pj_end(pj);
	rz_cons_println(pj_string(pj));
	pj_free(pj);
	return true;
}

RZ_IPI RzList *rz_types_function_noreturn(Sdb *db) {
	RzList *noretl = rz_list_new();
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(db, true);
	ls_foreach (l, iter, kv) {
		const char *k = sdbkv_key(kv);
		if (!strncmp(k, "func.", 5) && strstr(k, ".noreturn")) {
			char *s = strdup(k + 5);
			char *d = strchr(s, '.');
			if (d) {
				*d = 0;
			}
			rz_list_append(noretl, strdup(s));
			free(s);
		}
		if (!strncmp(k, "addr.", 5)) {
			char *off;
			if (!(off = strdup(k + 5))) {
				break;
			}
			char *ptr = strstr(off, ".noreturn");
			if (ptr) {
				*ptr = 0;
				char *addr = rz_str_newf("0x%s", off);
				rz_list_append(noretl, addr);
			}
			free(off);
		}
	}
	ls_free(l);
	return noretl;
}

RZ_IPI void rz_core_types_function_noreturn_print(RzCore *core, RzOutputMode mode) {
	Sdb *TDB = core->analysis->sdb_types;
	RzList *noretl = rz_types_function_noreturn(TDB);
	switch (mode) {
	case RZ_OUTPUT_MODE_RIZIN:
		sdb_foreach(TDB, nonreturn_print_rizin, core);
		break;
	case RZ_OUTPUT_MODE_JSON:
		nonreturn_print_json(core, noretl);
		break;
	default:
		nonreturn_print(core, noretl);
		break;
	}
}

// Type formatting

RZ_IPI void rz_core_types_show_format(RzCore *core, const char *name, RzOutputMode mode) {
	const char *isenum = sdb_const_get(core->analysis->sdb_types, name, 0);
	if (isenum && !strcmp(isenum, "enum")) {
		eprintf("IS ENUM\n");
	} else {
		char *fmt = rz_type_format(core->analysis->sdb_types, name);
		if (fmt) {
			rz_str_trim(fmt);
			switch (mode) {
			case RZ_OUTPUT_MODE_JSON: {
				PJ *pj = rz_core_pj_new(core);
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
}

static void print_all_format(RzCore *core, Sdb *TDB, SdbForeachCallback sdbcb) {
	SdbList *l = sdb_foreach_list(TDB, true);
	SdbListIter *it;
	SdbKv *kv;
	ls_foreach (l, it, kv) {
		if (sdbcb(TDB, sdbkv_key(kv), sdbkv_value(kv))) {
			rz_core_types_show_format(core, sdbkv_key(kv), RZ_OUTPUT_MODE_RIZIN);
		}
	}
	ls_free(l);
}

RZ_IPI void rz_core_types_struct_print_format_all(RzCore *core, Sdb *TDB) {
	print_all_format(core, TDB, sdb_if_struct_cb);
}

RZ_IPI void rz_core_types_union_print_format_all(RzCore *core, Sdb *TDB) {
	print_all_format(core, TDB, sdb_if_union_cb);
}

// Type links

RZ_IPI RzList *rz_types_links(Sdb *db) {
	RzList *ccl = rz_list_new();
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(db, true);
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "link")) {
			rz_list_append(ccl, strdup(sdbkv_key(kv)));
		}
	}
	ls_free(l);
	return ccl;
}

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
	char *res = rz_type_get_struct_memb(core->analysis->sdb_types, type, offimm);
	const char *cmt = ((offimm == 0) && res) ? res : type;
	if (offimm > 0) {
		// set hint only if link is present
		char *query = sdb_fmt("link.%08" PFMT64x, laddr);
		if (res && sdb_const_get(core->analysis->sdb_types, query, 0)) {
			rz_analysis_hint_set_offset(core->analysis, at, res);
		}
	} else if (cmt && rz_analysis_op_ismemref(op->type)) {
		rz_meta_set_string(core->analysis, RZ_META_TYPE_VARTYPE, at, cmt);
	}
}

RZ_API void rz_core_link_stroff(RzCore *core, RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	RzListIter *it;
	RzAnalysisOp aop = { 0 };
	bool ioCache = rz_config_get_i(core->config, "io.cache");
	bool stack_set = false;
	bool resolved = false;
	const char *varpfx;
	int dbg_follow = rz_config_get_i(core->config, "dbg.follow");
	Sdb *TDB = core->analysis->sdb_types;
	RzAnalysisEsil *esil;
	int iotrap = rz_config_get_i(core->config, "esil.iotrap");
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	unsigned int addrsize = rz_config_get_i(core->config, "esil.addr.size");
	const char *pc_name = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
	const char *sp_name = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SP);
	RzRegItem *pc = rz_reg_get(core->analysis->reg, pc_name, -1);

	if (!fcn) {
		return;
	}
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
			char *slink = rz_type_link_at(TDB, src_addr);
			char *vlink = rz_type_link_at(TDB, src_addr + src_imm);
			char *dlink = rz_type_link_at(TDB, dst_addr);
			//TODO: Handle register based arg for struct offset propgation
			if (vlink && var && var->kind != 'r') {
				if (rz_type_kind(TDB, vlink) == RZ_TYPE_UNION) {
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
		char *fmt = rz_type_format(core->analysis->sdb_types, type);
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
	Sdb *TDB = core->analysis->sdb_types;
	SdbKv *kv;
	SdbListIter *iter;
	PJ *pj = (mode == RZ_OUTPUT_MODE_JSON) ? rz_core_pj_new(core) : NULL;
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
	Sdb *TDB = core->analysis->sdb_types;
	char *tmp = sdb_get(TDB, type, 0);
	if (RZ_STR_ISEMPTY(tmp)) {
		eprintf("unknown type %s\n", type);
		free(tmp);
		return;
	}
	rz_type_set_link(TDB, type, addr);
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
	Sdb *TDB = core->analysis->sdb_types;
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
	Sdb *TDB = core->analysis->sdb_types;
	SdbList *l = sdb_foreach_list_filter(TDB, sdb_if_type_cb, true);
	switch (mode) {
	case RZ_OUTPUT_MODE_JSON: {
		PJ *pj = rz_core_pj_new(core);
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

static bool sdb_if_c_type_cb(void *p, const char *k, const char *v) {
	return sdb_if_union_cb(p, k, v) || sdb_if_struct_cb(p, k, v) || sdb_if_type_cb(p, k, v);
}

RZ_IPI RzList *rz_types_all(Sdb *TDB) {
	SdbList *sl = sdb_foreach_list_filter_user(TDB, sdb_if_c_type_cb, true, TDB);
	RzList *l = rz_list_of_sdblist(sl);
	ls_free(sl);
	return l;
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
	char *out = rz_parse_c_string(core->analysis, tmp, &error_msg);
	free(tmp);
	if (out) {
		rz_analysis_save_parsed_type(core->analysis, out);
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
			char *out = rz_parse_c_string(core->analysis, tmp, &error_msg);
			if (out) {
				rz_analysis_save_parsed_type(core->analysis, out);
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
		char *out = rz_parse_c_file(core->analysis, path, dir, &error_msg);
		if (out) {
			rz_analysis_save_parsed_type(core->analysis, out);
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
	Sdb *TDB = core->analysis->sdb_types;
	char *str = rz_core_cmd_strf(core, "tc %s", typename ? typename : "");
	char *tmp = rz_core_editor(core, "*.h", str);
	if (tmp) {
		char *error_msg = NULL;
		char *out = rz_parse_c_string(core->analysis, tmp, &error_msg);
		if (out) {
			// remove previous types and save new edited types
			sdb_reset(TDB);
			rz_parse_c_reset(core->parser);
			rz_analysis_save_parsed_type(core->analysis, out);
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

RZ_IPI void rz_types_open_sdb(RzCore *core, const char *path) {
	Sdb *TDB = core->analysis->sdb_types;
	if (rz_file_exists(path)) {
		Sdb *db_tmp = sdb_new(0, path, 0);
		sdb_merge(TDB, db_tmp);
		sdb_close(db_tmp);
		sdb_free(db_tmp);
	}
}
