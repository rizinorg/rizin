// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2013-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2013-2020 sivaramaaa <sivaramaaa@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <sdb.h>
#include <rz_type.h>

RZ_API int rz_type_kind(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, -1);
	Sdb *TDB = typedb->sdb_types;
	const char *type = sdb_const_get(TDB, name, 0);
	if (!type) {
		return -1;
	}
	if (!strcmp(type, "enum")) {
		return RZ_BASE_TYPE_KIND_ENUM;
	}
	if (!strcmp(type, "struct")) {
		return RZ_BASE_TYPE_KIND_STRUCT;
	}
	if (!strcmp(type, "union")) {
		return RZ_BASE_TYPE_KIND_UNION;
	}
	if (!strcmp(type, "type")) {
		return RZ_BASE_TYPE_KIND_ATOMIC;
	}
	if (!strcmp(type, "typedef")) {
		return RZ_BASE_TYPE_KIND_TYPEDEF;
	}
	return -1;
}

RZ_API RzList *rz_type_db_get_enum(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);
	Sdb *TDB = typedb->sdb_types;
	char *p, var[130];
	int n;

	if (rz_type_kind(typedb, name) != RZ_BASE_TYPE_KIND_ENUM) {
		return NULL;
	}
	RzList *res = rz_list_new();
	snprintf(var, sizeof(var), "enum.%s", name);
	for (n = 0; (p = sdb_array_get(TDB, var, n, NULL)); n++) {
		RzTypeEnum *member = RZ_NEW0(RzTypeEnum);
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

RZ_API char *rz_type_db_enum_member(RzTypeDB *typedb, RZ_NONNULL const char *name, const char *member, ut64 val) {
	rz_return_val_if_fail(typedb && name, NULL);
	Sdb *TDB = typedb->sdb_types;
	if (rz_type_kind(typedb, name) != RZ_BASE_TYPE_KIND_ENUM) {
		return NULL;
	}
	const char *q = member
		? sdb_fmt("enum.%s.%s", name, member)
		: sdb_fmt("enum.%s.0x%" PFMT64x, name, val);
	return sdb_get(TDB, q, 0);
}

RZ_API RzList *rz_type_db_enum_find_member(RzTypeDB *typedb, ut64 val) {
	rz_return_val_if_fail(typedb, NULL);
	Sdb *TDB = typedb->sdb_types;
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

RZ_API char *rz_type_enum_getbitfield(RzTypeDB *typedb, RZ_NONNULL const char *name, ut64 val) {
	rz_return_val_if_fail(typedb && name, NULL);
	Sdb *TDB = typedb->sdb_types;
	char *q, *ret = NULL;
	const char *res;
	int i;

	if (rz_type_kind(typedb, name) != RZ_BASE_TYPE_KIND_ENUM) {
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

RZ_API ut64 rz_type_db_get_bitsize(RzTypeDB *typedb, RZ_NONNULL const char *type) {
	rz_return_val_if_fail(typedb && type, 0);
	Sdb *TDB = typedb->sdb_types;
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
						ret += rz_type_db_get_bitsize(typedb, subtype) * elements;
					} else {
						ut64 sz = rz_type_db_get_bitsize(typedb, subtype) * elements;
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

RZ_API char *rz_type_get_struct_memb(RzTypeDB *typedb, RZ_NONNULL const char *type, int offset) {
	rz_return_val_if_fail(typedb && type, NULL);
	Sdb *TDB = typedb->sdb_types;
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
		int fsize = (rz_type_db_get_bitsize(typedb, subtype) * (arrsz ? arrsz : 1)) / 8;
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
				char *nested_res = rz_type_get_struct_memb(typedb, nested_type, offset - cur_offset);
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
RZ_API RzList *rz_type_get_by_offset(RzTypeDB *typedb, ut64 offset) {
	rz_return_val_if_fail(typedb, NULL);
	Sdb *TDB = typedb->sdb_types;
	RzList *offtypes = rz_list_new();
	SdbList *ls = sdb_foreach_list(TDB, true);
	SdbListIter *lsi;
	SdbKv *kv;
	ls_foreach (ls, lsi, kv) {
		// TODO: Add unions support
		if (!strncmp(sdbkv_value(kv), "struct", 6) && strncmp(sdbkv_key(kv), "struct.", 7)) {
			char *res = rz_type_get_struct_memb(typedb, sdbkv_key(kv), offset);
			if (res) {
				rz_list_append(offtypes, res);
			}
		}
	}
	ls_free(ls);
	return offtypes;
}
