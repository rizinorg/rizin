// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2013-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2013-2020 sivaramaaa <sivaramaaa@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

RZ_API int rz_type_set(Sdb *TDB, ut64 at, const char *field, ut64 val) {
	const char *kind;
	char var[128];
	sprintf(var, "link.%08" PFMT64x, at);
	kind = sdb_const_get(TDB, var, NULL);
	if (kind) {
		const char *p = sdb_const_get(TDB, kind, NULL);
		if (p) {
			snprintf(var, sizeof(var), "%s.%s.%s", p, kind, field);
			int off = sdb_array_get_num(TDB, var, 1, NULL);
			//int siz = sdb_array_get_num (DB, var, 2, NULL);
			eprintf("wv 0x%08" PFMT64x " @ 0x%08" PFMT64x, val, at + off);
			return true;
		}
		eprintf("Invalid kind of type\n");
	}
	return false;
}

RZ_API int rz_type_kind(Sdb *TDB, const char *name) {
	if (!name) {
		return -1;
	}
	const char *type = sdb_const_get(TDB, name, 0);
	if (!type) {
		return -1;
	}
	if (!strcmp(type, "enum")) {
		return RZ_TYPE_ENUM;
	}
	if (!strcmp(type, "struct")) {
		return RZ_TYPE_STRUCT;
	}
	if (!strcmp(type, "union")) {
		return RZ_TYPE_UNION;
	}
	if (!strcmp(type, "type")) {
		return RZ_TYPE_BASIC;
	}
	if (!strcmp(type, "typedef")) {
		return RZ_TYPE_TYPEDEF;
	}
	return -1;
}

RZ_API RzList *rz_type_get_enum(Sdb *TDB, const char *name) {
	char *p, var[130];
	int n;

	if (rz_type_kind(TDB, name) != RZ_TYPE_ENUM) {
		return NULL;
	}
	RzList *res = rz_list_new();
	snprintf(var, sizeof(var), "enum.%s", name);
	for (n = 0; (p = sdb_array_get(TDB, var, n, NULL)); n++) {
		RTypeEnum *member = RZ_NEW0(RTypeEnum);
		if (member) {
			char *var2 = rz_str_newf("%s.%s", var, p);
			if (var2) {
				char *val = sdb_array_get(TDB, var2, 0, NULL);
				if (val) {
					member->name = p;
					member->val = val;
					rz_list_append(res, member);
				} else {
					free(member);
					free(var2);
				}
			} else {
				free(member);
			}
		}
	}
	return res;
}

RZ_API char *rz_type_enum_member(Sdb *TDB, const char *name, const char *member, ut64 val) {
	if (rz_type_kind(TDB, name) != RZ_TYPE_ENUM) {
		return NULL;
	}
	const char *q = member
		? sdb_fmt("enum.%s.%s", name, member)
		: sdb_fmt("enum.%s.0x%" PFMT64x, name, val);
	return sdb_get(TDB, q, 0);
}

RZ_API RzList *rz_type_enum_find_member(Sdb *TDB, ut64 val) {
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(TDB, true);
	RzList *res = rz_list_new();
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "enum")) {
			const char *name = sdbkv_key(kv);
			if (name) {
				const char *q = sdb_fmt("enum.%s.0x%" PFMT64x, name, val);
				char *member = sdb_get(TDB, q, 0);
				if (member) {
					char *pair = rz_str_newf("%s.%s", name, member);
					rz_list_append(res, pair);
					free(member);
				}
			}
		}
	}
	ls_free(l);
	return res;
}

RZ_API char *rz_type_enum_getbitfield(Sdb *TDB, const char *name, ut64 val) {
	char *q, *ret = NULL;
	const char *res;
	int i;

	if (rz_type_kind(TDB, name) != RZ_TYPE_ENUM) {
		return NULL;
	}
	bool isFirst = true;
	ret = rz_str_appendf(ret, "0x%08" PFMT64x " : ", val);
	for (i = 0; i < 32; i++) {
		ut32 n = 1ULL << i;
		if (!(val & n)) {
			continue;
		}
		q = sdb_fmt("enum.%s.0x%x", name, n);
		res = sdb_const_get(TDB, q, 0);
		if (isFirst) {
			isFirst = false;
		} else {
			ret = rz_str_append(ret, " | ");
		}
		if (res) {
			ret = rz_str_append(ret, res);
		} else {
			ret = rz_str_appendf(ret, "0x%x", n);
		}
	}
	return ret;
}

RZ_API ut64 rz_type_get_bitsize(Sdb *TDB, const char *type) {
	char *query;
	/* Filter out the structure keyword if type looks like "struct mystruc" */
	const char *tmptype;
	if (!strncmp(type, "struct ", 7)) {
		tmptype = type + 7;
	} else if (!strncmp(type, "union ", 6)) {
		tmptype = type + 6;
	} else {
		tmptype = type;
	}
	if ((strstr(type, "*(") || strstr(type, " *")) && strncmp(type, "char *", 7)) {
		return 32;
	}
	const char *t = sdb_const_get(TDB, tmptype, 0);
	if (!t) {
		if (!strncmp(tmptype, "enum ", 5)) {
			//XXX: Need a proper way to determine size of enum
			return 32;
		}
		return 0;
	}
	if (!strcmp(t, "type")) {
		query = rz_str_newf("type.%s.size", tmptype);
		ut64 r = sdb_num_get(TDB, query, 0); // returns size in bits
		free(query);
		return r;
	}
	if (!strcmp(t, "struct") || !strcmp(t, "union")) {
		query = rz_str_newf("%s.%s", t, tmptype);
		char *members = sdb_get(TDB, query, 0);
		char *next, *ptr = members;
		ut64 ret = 0;
		if (members) {
			do {
				char *name = sdb_anext(ptr, &next);
				if (!name) {
					break;
				}
				free(query);
				query = rz_str_newf("%s.%s.%s", t, tmptype, name);
				char *subtype = sdb_get(TDB, query, 0);
				RZ_FREE(query);
				if (!subtype) {
					break;
				}
				char *tmp = strchr(subtype, ',');
				if (tmp) {
					*tmp++ = 0;
					tmp = strchr(tmp, ',');
					if (tmp) {
						*tmp++ = 0;
					}
					int elements = rz_num_math(NULL, tmp);
					if (elements == 0) {
						elements = 1;
					}
					if (!strcmp(t, "struct")) {
						ret += rz_type_get_bitsize(TDB, subtype) * elements;
					} else {
						ut64 sz = rz_type_get_bitsize(TDB, subtype) * elements;
						ret = sz > ret ? sz : ret;
					}
				}
				free(subtype);
				ptr = next;
			} while (next);
			free(members);
		}
		free(query);
		return ret;
	}
	return 0;
}

RZ_API char *rz_type_get_struct_memb(Sdb *TDB, const char *type, int offset) {
	int i, cur_offset, next_offset = 0;
	char *res = NULL;

	if (offset < 0) {
		return NULL;
	}
	char *query = sdb_fmt("struct.%s", type);
	char *members = sdb_get(TDB, query, 0);
	if (!members) {
		//eprintf ("%s is not a struct\n", type);
		return NULL;
	}
	int nargs = rz_str_split(members, ',');
	for (i = 0; i < nargs; i++) {
		const char *name = rz_str_word_get0(members, i);
		if (!name) {
			break;
		}
		query = sdb_fmt("struct.%s.%s", type, name);
		char *subtype = sdb_get(TDB, query, 0);
		if (!subtype) {
			break;
		}
		int len = rz_str_split(subtype, ',');
		if (len < 3) {
			free(subtype);
			break;
		}
		cur_offset = rz_num_math(NULL, rz_str_word_get0(subtype, len - 2));
		if (cur_offset > 0 && cur_offset < next_offset) {
			free(subtype);
			break;
		}
		if (!cur_offset) {
			cur_offset = next_offset;
		}
		if (cur_offset == offset) {
			res = rz_str_newf("%s.%s", type, name);
			free(subtype);
			break;
		}
		int arrsz = rz_num_math(NULL, rz_str_word_get0(subtype, len - 1));
		int fsize = (rz_type_get_bitsize(TDB, subtype) * (arrsz ? arrsz : 1)) / 8;
		if (!fsize) {
			free(subtype);
			break;
		}
		next_offset = cur_offset + fsize;
		// Handle nested structs
		if (offset > cur_offset && offset < next_offset) {
			char *nested_type = (char *)rz_str_word_get0(subtype, 0);
			if (rz_str_startswith(nested_type, "struct ") && !rz_str_endswith(nested_type, " *")) {
				len = rz_str_split(nested_type, ' ');
				if (len < 2) {
					free(subtype);
					break;
				}
				nested_type = (char *)rz_str_word_get0(nested_type, 1);
				char *nested_res = rz_type_get_struct_memb(TDB, nested_type, offset - cur_offset);
				if (nested_res) {
					len = rz_str_split(nested_res, '.');
					res = rz_str_newf("%s.%s.%s", type, name, rz_str_word_get0(nested_res, len - 1));
					free(nested_res);
					free(subtype);
					break;
				}
			}
		}
		free(subtype);
	}
	free(members);
	return res;
}

// XXX this function is slow!
RZ_API RzList *rz_type_get_by_offset(Sdb *TDB, ut64 offset) {
	RzList *offtypes = rz_list_new();
	SdbList *ls = sdb_foreach_list(TDB, true);
	SdbListIter *lsi;
	SdbKv *kv;
	ls_foreach (ls, lsi, kv) {
		// TODO: Add unions support
		if (!strncmp(sdbkv_value(kv), "struct", 6) && strncmp(sdbkv_key(kv), "struct.", 7)) {
			char *res = rz_type_get_struct_memb(TDB, sdbkv_key(kv), offset);
			if (res) {
				rz_list_append(offtypes, res);
			}
		}
	}
	ls_free(ls);
	return offtypes;
}

// XXX 12 is the maxstructsizedelta
#define TYPE_RANGE_BASE(x) ((x) >> 16)

static RzList *types_range_list(Sdb *db, ut64 addr) {
	RzList *list = NULL;
	ut64 base = TYPE_RANGE_BASE(addr);
	char *s = rz_str_newf("range.%" PFMT64x, base);
	if (s) {
		char *r = sdb_get(db, s, 0);
		if (r) {
			list = rz_str_split_list(r, " ", -1);
		}
		free(s);
	}
	return list;
}

static void types_range_del(Sdb *db, ut64 addr) {
	ut64 base = TYPE_RANGE_BASE(addr);
	const char *k = sdb_fmt("range.%" PFMT64x, base);
	char valstr[SDB_NUM_BUFSZ];
	const char *v = sdb_itoa(addr, valstr, SDB_NUM_BASE);
	sdb_array_remove(db, k, v, 0);
}

static void types_range_add(Sdb *db, ut64 addr) {
	ut64 base = TYPE_RANGE_BASE(addr);
	const char *k = sdb_fmt("range.%" PFMT64x, base);
	(void)sdb_array_add_num(db, k, addr, 0);
}

RZ_API char *rz_type_link_at(Sdb *TDB, ut64 addr) {
	if (addr == UT64_MAX) {
		return NULL;
	}
	const char *query = sdb_fmt("link.%08" PFMT64x, addr);
	char *res = sdb_get(TDB, query, 0);
	if (!res) { // resolve struct memb if possible for given addr
		RzList *list = types_range_list(TDB, addr);
		RzListIter *iter;
		const char *s;
		rz_list_foreach (list, iter, s) {
			ut64 laddr = rz_num_get(NULL, s);
			if (addr > laddr) {
				int delta = addr - laddr;
				const char *lk = sdb_fmt("link.%08" PFMT64x, laddr);
				char *k = sdb_get(TDB, lk, 0);
				res = rz_type_get_struct_memb(TDB, k, delta);
				if (res) {
					break;
				}
				free(k);
			}
		}
	}
	return res;
}

RZ_API int rz_type_set_link(Sdb *TDB, const char *type, ut64 addr) {
	if (sdb_const_get(TDB, type, 0)) {
		char *laddr = rz_str_newf("link.%08" PFMT64x, addr);
		sdb_set(TDB, laddr, type, 0);
		types_range_add(TDB, addr);
		free(laddr);
		return true;
	}
	return false;
}

RZ_API int rz_type_link_offset(Sdb *TDB, const char *type, ut64 addr) {
	if (sdb_const_get(TDB, type, 0)) {
		char *laddr = rz_str_newf("offset.%08" PFMT64x, addr);
		sdb_set(TDB, laddr, type, 0);
		free(laddr);
		return true;
	}
	return false;
}

RZ_API int rz_type_unlink(Sdb *TDB, ut64 addr) {
	char *laddr = sdb_fmt("link.%08" PFMT64x, addr);
	sdb_unset(TDB, laddr, 0);
	types_range_del(TDB, addr);
	return true;
}

static bool sdbdeletelink(void *p, const char *k, const char *v) {
	Sdb *TDB = (Sdb *)p;
	if (!strncmp(k, "link.", strlen("link."))) {
		rz_type_del(TDB, k);
	}
	return true;
}

RZ_API int rz_type_unlink_all(Sdb *TDB) {
	sdb_foreach(TDB, sdbdeletelink, TDB);
	return true;
}

static char *fmt_struct_union(Sdb *TDB, char *var, bool is_typedef) {
	// assumes var list is sorted by offset.. should do more checks here
	char *p = NULL, *vars = NULL, var2[132], *fmt = NULL;
	size_t n;
	char *fields = rz_str_newf("%s.fields", var);
	char *nfields = (is_typedef) ? fields : var;
	for (n = 0; (p = sdb_array_get(TDB, nfields, n, NULL)); n++) {
		char *struct_name;
		const char *tfmt = NULL;
		bool isStruct = false;
		bool isEnum = false;
		bool isfp = false;
		snprintf(var2, sizeof(var2), "%s.%s", var, p);
		size_t alen = sdb_array_size(TDB, var2);
		int elements = sdb_array_get_num(TDB, var2, alen - 1, NULL);
		char *type = sdb_array_get(TDB, var2, 0, NULL);
		if (type) {
			char var3[128] = { 0 };
			// Handle general pointers except for char *
			if ((strstr(type, "*(") || strstr(type, " *")) && strncmp(type, "char *", 7)) {
				isfp = true;
			} else if (rz_str_startswith(type, "struct ")) {
				struct_name = type + 7;
				// TODO: iterate over all the struct fields, and format the format and vars
				snprintf(var3, sizeof(var3), "struct.%s", struct_name);
				tfmt = sdb_const_get(TDB, var3, NULL);
				isStruct = true;
			} else {
				// special case for char[]. Use char* format type without *
				if (!strcmp(type, "char") && elements > 0) {
					tfmt = sdb_const_get(TDB, "type.char *", NULL);
					if (tfmt && *tfmt == '*') {
						tfmt++;
					}
				} else {
					if (rz_str_startswith(type, "enum ")) {
						snprintf(var3, sizeof(var3), "%s", type + 5);
						isEnum = true;
					} else {
						snprintf(var3, sizeof(var3), "type.%s", type);
					}
					tfmt = sdb_const_get(TDB, var3, NULL);
				}
			}
			if (isfp) {
				// consider function pointer as void * for printing
				fmt = rz_str_append(fmt, "p");
				vars = rz_str_append(vars, p);
				vars = rz_str_append(vars, " ");
			} else if (tfmt) {
				(void)rz_str_replace_ch(type, ' ', '_', true);
				if (elements > 0) {
					fmt = rz_str_appendf(fmt, "[%d]", elements);
				}
				if (isStruct) {
					fmt = rz_str_append(fmt, "?");
					vars = rz_str_appendf(vars, "(%s)%s", struct_name, p);
					vars = rz_str_append(vars, " ");
				} else if (isEnum) {
					fmt = rz_str_append(fmt, "E");
					vars = rz_str_appendf(vars, "(%s)%s", type + 5, p);
					vars = rz_str_append(vars, " ");
				} else {
					fmt = rz_str_append(fmt, tfmt);
					vars = rz_str_append(vars, p);
					vars = rz_str_append(vars, " ");
				}
			} else {
				eprintf("Cannot resolve type '%s'\n", var3);
			}
			free(type);
		}
		free(p);
	}
	free(fields);
	fmt = rz_str_append(fmt, " ");
	fmt = rz_str_append(fmt, vars);
	free(vars);
	return fmt;
}

RZ_API char *rz_type_format(Sdb *TDB, const char *t) {
	char var[130], var2[132];
	const char *kind = sdb_const_get(TDB, t, NULL);
	if (!kind) {
		return NULL;
	}
	// only supports struct atm
	snprintf(var, sizeof(var), "%s.%s", kind, t);
	if (!strcmp(kind, "type")) {
		const char *fmt = sdb_const_get(TDB, var, NULL);
		if (fmt) {
			return strdup(fmt);
		}
	} else if (!strcmp(kind, "struct") || !strcmp(kind, "union")) {
		return fmt_struct_union(TDB, var, false);
	}
	if (!strcmp(kind, "typedef")) {
		snprintf(var2, sizeof(var2), "typedef.%s", t);
		const char *type = sdb_const_get(TDB, var2, NULL);
		// only supports struct atm
		if (type && !strcmp(type, "struct")) {
			return fmt_struct_union(TDB, var, true);
		}
	}
	return NULL;
}

RZ_API void rz_type_del(Sdb *TDB, const char *name) {
	const char *kind = sdb_const_get(TDB, name, 0);
	if (!kind) {
		return;
	}
	if (!strcmp(kind, "type")) {
		sdb_unset(TDB, sdb_fmt("type.%s", name), 0);
		sdb_unset(TDB, sdb_fmt("type.%s.size", name), 0);
		sdb_unset(TDB, sdb_fmt("type.%s.meta", name), 0);
		sdb_unset(TDB, name, 0);
	} else if (!strcmp(kind, "struct") || !strcmp(kind, "union")) {
		int i, n = sdb_array_length(TDB, sdb_fmt("%s.%s", kind, name));
		char *elements_key = rz_str_newf("%s.%s", kind, name);
		for (i = 0; i < n; i++) {
			char *p = sdb_array_get(TDB, elements_key, i, NULL);
			sdb_unset(TDB, sdb_fmt("%s.%s", elements_key, p), 0);
			free(p);
		}
		sdb_unset(TDB, elements_key, 0);
		sdb_unset(TDB, name, 0);
		free(elements_key);
	} else if (!strcmp(kind, "func")) {
		int i, n = sdb_num_get(TDB, sdb_fmt("func.%s.args", name), 0);
		for (i = 0; i < n; i++) {
			sdb_unset(TDB, sdb_fmt("func.%s.arg.%d", name, i), 0);
		}
		sdb_unset(TDB, sdb_fmt("func.%s.ret", name), 0);
		sdb_unset(TDB, sdb_fmt("func.%s.cc", name), 0);
		sdb_unset(TDB, sdb_fmt("func.%s.noreturn", name), 0);
		sdb_unset(TDB, sdb_fmt("func.%s.args", name), 0);
		sdb_unset(TDB, name, 0);
	} else if (!strcmp(kind, "enum")) {
		RzList *list = rz_type_get_enum(TDB, name);
		RTypeEnum *member;
		RzListIter *iter;
		rz_list_foreach (list, iter, member) {
			sdb_unset(TDB, sdb_fmt("enum.%s.%s", name, member->name), 0);
			sdb_unset(TDB, sdb_fmt("enum.%s.%s", name, member->val), 0);
		}
		sdb_unset(TDB, name, 0);
		rz_list_free(list);
	} else if (!strcmp(kind, "typedef")) {
		RzStrBuf buf;
		rz_strbuf_init(&buf);
		rz_strbuf_setf(&buf, "typedef.%s", name);
		sdb_unset(TDB, rz_strbuf_get(&buf), 0);
		rz_strbuf_fini(&buf);
		sdb_unset(TDB, name, 0);
	} else {
		eprintf("Unrecognized type kind \"%s\"\n", kind);
	}
}

// Function prototypes api
RZ_API int rz_type_func_exist(Sdb *TDB, const char *func_name) {
	const char *fcn = sdb_const_get(TDB, func_name, 0);
	return fcn && !strcmp(fcn, "func");
}

RZ_API const char *rz_type_func_ret(Sdb *TDB, const char *func_name) {
	const char *query = sdb_fmt("func.%s.ret", func_name);
	return sdb_const_get(TDB, query, 0);
}

RZ_API int rz_type_func_args_count(Sdb *TDB, const char *func_name) {
	const char *query = sdb_fmt("func.%s.args", func_name);
	return sdb_num_get(TDB, query, 0);
}

RZ_API RZ_OWN char *rz_type_func_args_type(Sdb *TDB, RZ_NONNULL const char *func_name, int i) {
	const char *query = sdb_fmt("func.%s.arg.%d", func_name, i);
	char *ret = sdb_get(TDB, query, 0);
	if (ret) {
		char *comma = strchr(ret, ',');
		if (comma) {
			*comma = 0;
			return ret;
		}
		free(ret);
	}
	return NULL;
}

RZ_API const char *rz_type_func_args_name(Sdb *TDB, RZ_NONNULL const char *func_name, int i) {
	const char *query = sdb_fmt("func.%s.arg.%d", func_name, i);
	const char *get = sdb_const_get(TDB, query, 0);
	if (get) {
		char *ret = strchr(get, ',');
		return ret == 0 ? ret : ret + 1;
	}
	return NULL;
}

#define MIN_MATCH_LEN 4

static inline bool is_function(const char *name) {
	return name && !strcmp("func", name);
}

static RZ_OWN char *type_func_try_guess(Sdb *TDB, RZ_NONNULL char *name) {
	if (strlen(name) < MIN_MATCH_LEN) {
		return NULL;
	}

	const char *res = sdb_const_get(TDB, name, NULL);
	if (is_function(res)) {
		return strdup(name);
	}

	return NULL;
}

static inline bool is_auto_named(char *func_name, size_t slen) {
	return slen > 4 && (rz_str_startswith(func_name, "fcn.") || rz_str_startswith(func_name, "loc."));
}

static inline bool has_rz_prefixes(char *func_name, int offset, size_t slen) {
	return slen > 4 && (offset + 3 < slen) && func_name[offset + 3] == '.';
}

static char *strip_rz_prefixes(char *func_name, size_t slen) {
	// strip r2 prefixes (sym, sym.imp, etc')
	int offset = 0;

	while (has_rz_prefixes(func_name, offset, slen)) {
		offset += 4;
	}

	return func_name + offset;
}

static char *strip_common_prefixes_stdlib(char *func_name) {
	// strip common prefixes from standard lib functions
	if (rz_str_startswith(func_name, "__isoc99_")) {
		func_name += 9;
	} else if (rz_str_startswith(func_name, "__libc_") && !strstr(func_name, "_main")) {
		func_name += 7;
	} else if (rz_str_startswith(func_name, "__GI_")) {
		func_name += 5;
	}

	return func_name;
}

static char *strip_dll_prefix(char *func_name) {
	char *tmp = strstr(func_name, "dll_");
	if (tmp) {
		return tmp + 3;
	}

	return func_name;
}

static void clean_function_name(char *func_name) {
	char *last = (char *)rz_str_lchr(func_name, '_');
	if (!last || !rz_str_isnumber(last + 1)) {
		return;
	}

	*last = '\0';
}

// TODO:
// - symbol names are long and noisy, some of them might not be matched due
//	 to additional information added around name
RZ_API RZ_OWN char *rz_type_func_guess(Sdb *TDB, RZ_NONNULL char *func_name) {
	char *str = func_name;
	char *result = NULL;
	rz_return_val_if_fail(TDB, false);
	rz_return_val_if_fail(func_name, false);

	size_t slen = strlen(str);
	if (slen < MIN_MATCH_LEN || is_auto_named(str, slen)) {
		return NULL;
	}

	str = strip_rz_prefixes(str, slen);
	str = strip_common_prefixes_stdlib(str);
	str = strip_dll_prefix(str);

	if ((result = type_func_try_guess(TDB, str))) {
		return result;
	}

	str = strdup(str);
	clean_function_name(str);

	if (*str == '_' && (result = type_func_try_guess(TDB, str + 1))) {
		free(str);
		return result;
	}

	free(str);
	return result;
}
