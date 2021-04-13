// SPDX-FileCopyrightText: 2013-2020 sivaramaaa <sivaramaaa@gmail.com>
// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2013-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2019-2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <string.h>
#include <sdb.h>

#include "type_internal.h"

RZ_API RzTypeDB *rz_type_db_new() {
	RzTypeDB *typedb = RZ_NEW0(RzTypeDB);
	if (!typedb) {
		return NULL;
	}
	typedb->target = RZ_NEW0(RzTypeTarget);
	if (!typedb->target) {
		free(typedb);
		return NULL;
	}
	typedb->sdb_types = sdb_new0();
	typedb->formats = sdb_new0();
	rz_io_bind_init(typedb->iob);
	return typedb;
}

RZ_API void rz_type_db_free(RzTypeDB *typedb) {
	sdb_free(typedb->sdb_types);
	sdb_free(typedb->formats);
	free(typedb->target);
	free(typedb);
}

// copypasta from core/cbin.c
static void sdb_concat_by_path(Sdb *s, const char *path) {
	Sdb *db = sdb_new(0, path, 0);
	sdb_merge(s, db);
	sdb_close(db);
	sdb_free(db);
}

RZ_API void rz_type_db_load_sdb(RzTypeDB *typedb, const char *path) {
	if (rz_file_exists(path)) {
		sdb_concat_by_path(typedb->sdb_types, path);
	}
}

RZ_API void rz_type_db_purge(RzTypeDB *typedb) {
	sdb_reset(typedb->sdb_types);
}

RZ_API void rz_type_db_set_bits(RzTypeDB *typedb, int bits) {
	typedb->target->bits = bits;
}

RZ_API void rz_type_db_set_os(RzTypeDB *typedb, const char *os) {
	typedb->target->os = os;
}

RZ_API void rz_type_db_set_cpu(RzTypeDB *typedb, const char *cpu) {
	typedb->target->cpu = cpu;
}

RZ_API void rz_type_db_set_endian(RzTypeDB *typedb, bool big_endian) {
	typedb->target->big_endian = big_endian;
}

RZ_API char *rz_type_db_kuery(RzTypeDB *typedb, const char *query) {
	char *output = NULL;
	if (query) {
		output = sdb_querys(typedb->sdb_types, NULL, -1, query);
	} else {
		output = sdb_querys(typedb->sdb_types, NULL, -1, "*");
	}
	return output;
}

static char *is_ctype(char *type) {
	char *name = NULL;
	if ((name = strstr(type, "=type")) ||
		(name = strstr(type, "=struct")) ||
		(name = strstr(type, "=union")) ||
		(name = strstr(type, "=enum")) ||
		(name = strstr(type, "=typedef")) ||
		(name = strstr(type, "=func"))) {
		return name;
	}
	return NULL;
}

RZ_API const char *rz_type_db_get(RzTypeDB *typedb, const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);
	Sdb *TDB = typedb->sdb_types;
	const char *query = sdb_fmt("type.%s", name);
	return sdb_const_get(TDB, query, 0);
}

RZ_API bool rz_type_db_set(RzTypeDB *typedb, ut64 at, RZ_NONNULL const char *field, ut64 val) {
	rz_return_val_if_fail(typedb && field, false);
	Sdb *TDB = typedb->sdb_types;
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

RZ_API bool rz_type_db_del(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, false);
	Sdb *TDB = typedb->sdb_types;
	const char *kind = sdb_const_get(TDB, name, 0);
	if (!kind) {
		return false;
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
		RzBaseType *e = rz_type_db_get_enum(typedb, name);
		if (!e || e->kind != RZ_BASE_TYPE_KIND_ENUM) {
			return false;
		}
		RzTypeEnumCase *cas;
		rz_vector_foreach(&e->enum_data.cases, cas) {
			sdb_unset(TDB, sdb_fmt("enum.%s.%s", name, cas->name), 0);
			sdb_unset(TDB, sdb_fmt("enum.%s.0x%x", name, cas->val), 0);
		}
		sdb_unset(TDB, name, 0);
		rz_type_base_type_free(e);
	} else if (!strcmp(kind, "typedef")) {
		RzStrBuf buf;
		rz_strbuf_init(&buf);
		rz_strbuf_setf(&buf, "typedef.%s", name);
		sdb_unset(TDB, rz_strbuf_get(&buf), 0);
		rz_strbuf_fini(&buf);
		sdb_unset(TDB, name, 0);
	} else {
		eprintf("Unrecognized type kind \"%s\"\n", kind);
		return false;
	}
	return true;
}

RZ_API void rz_type_db_remove_parsed_type(RzTypeDB *typedb, const char *name) {
	rz_return_if_fail(typedb && name);
	Sdb *TDB = typedb->sdb_types;
	SdbKv *kv;
	SdbListIter *iter;
	const char *type = sdb_const_get(TDB, name, 0);
	if (!type) {
		return;
	}
	int tmp_len = strlen(name) + strlen(type);
	char *tmp = malloc(tmp_len + 1);
	rz_type_db_del(typedb, name);
	if (tmp) {
		snprintf(tmp, tmp_len + 1, "%s.%s.", type, name);
		SdbList *l = sdb_foreach_list(TDB, true);
		ls_foreach (l, iter, kv) {
			if (!strncmp(sdbkv_key(kv), tmp, tmp_len)) {
				rz_type_db_del(typedb, sdbkv_key(kv));
			}
		}
		ls_free(l);
		free(tmp);
	}
}

RZ_API void rz_type_db_save_parsed_type(RzTypeDB *typedb, const char *parsed) {
	rz_return_if_fail(typedb && parsed);

	// First, if any parsed types exist, let's remove them.
	char *type = strdup(parsed);
	if (type) {
		char *cur = type;
		while (1) {
			cur = is_ctype(cur);
			if (!cur) {
				break;
			}
			char *name = cur++;
			*name = 0;
			while (name > type && *(name - 1) != '\n') {
				name--;
			}
			rz_type_db_remove_parsed_type(typedb, name);
		}
		free(type);
	}

	// Now add the type to sdb.
	sdb_query_lines(typedb->sdb_types, parsed);
}

RZ_API void rz_type_db_init(RzTypeDB *typedb, const char *dir_prefix, const char *arch, int bits, const char *os) {
	rz_return_if_fail(typedb);
	Sdb *TDB = typedb->sdb_types;

	// make sure they are empty this is initializing
	sdb_reset(TDB);

	const char *dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types.sdb"), dir_prefix);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types-%s.sdb"),
		dir_prefix, arch);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types-%s.sdb"),
		dir_prefix, os);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types-%d.sdb"),
		dir_prefix, bits);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types-%s-%d.sdb"),
		dir_prefix, os, bits);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types-%s-%d.sdb"),
		dir_prefix, arch, bits);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types-%s-%s.sdb"),
		dir_prefix, arch, os);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types-%s-%s-%d.sdb"),
		dir_prefix, arch, os, bits);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
}

// Listing all available types by category

RZ_API RzList *rz_type_db_enum_names(RzTypeDB *typedb) {
	RzList *ccl = rz_list_new();
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(typedb->sdb_types, true);
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "enum")) {
			rz_list_append(ccl, strdup(sdbkv_key(kv)));
		}
	}
	ls_free(l);
	return ccl;
}

static bool sdb_if_union_cb(void *p, const char *k, const char *v) {
	return !strncmp(v, "union", strlen("union") + 1);
}

RZ_API RzList *rz_type_db_union_names(RzTypeDB *typedb) {
	Sdb *TDB = typedb->sdb_types;
	SdbList *sl = sdb_foreach_list_filter_user(TDB, sdb_if_union_cb, true, TDB);
	RzList *l = rz_list_of_sdblist(sl);
	ls_free(sl);
	return l;
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

RZ_API RzList *rz_type_db_struct_names(RzTypeDB *typedb) {
	Sdb *TDB = typedb->sdb_types;
	SdbList *sl = sdb_foreach_list_filter_user(TDB, sdb_if_struct_cb, true, TDB);
	RzList *l = rz_list_of_sdblist(sl);
	ls_free(sl);
	return l;
}

static bool sdb_if_typedef_cb(void *p, const char *k, const char *v) {
	return !strncmp(v, "typedef", strlen("typedef") + 1);
}

RZ_API RzList *rz_type_db_typedef_names(RzTypeDB *typedb) {
	Sdb *TDB = typedb->sdb_types;
	SdbList *sl = sdb_foreach_list_filter_user(TDB, sdb_if_typedef_cb, true, TDB);
	RzList *l = rz_list_of_sdblist(sl);
	ls_free(sl);
	return l;
}

static bool sdb_if_type_cb(void *p, const char *k, const char *v) {
	return !strncmp(v, "type", strlen("type") + 1);
}

static bool sdb_if_c_type_cb(void *p, const char *k, const char *v) {
	return sdb_if_union_cb(p, k, v) || sdb_if_struct_cb(p, k, v) || sdb_if_type_cb(p, k, v);
}

RZ_API RzList *rz_type_db_all(RzTypeDB *typedb) {
	Sdb *TDB = typedb->sdb_types;
	SdbList *sl = sdb_foreach_list_filter_user(TDB, sdb_if_c_type_cb, true, TDB);
	RzList *l = rz_list_of_sdblist(sl);
	ls_free(sl);
	return l;
}

RZ_API RzList *rz_type_db_links(RzTypeDB *typedb) {
	RzList *ccl = rz_list_new();
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(typedb->sdb_types, true);
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "link")) {
			rz_list_append(ccl, strdup(sdbkv_key(kv)));
		}
	}
	ls_free(l);
	return ccl;
}

// Type-specific APIs
RZ_API int rz_type_kind(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, -1);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return -1;
	}
	return btype->kind;
}

// FIXME: this function is slow!
RZ_API RzList *rz_type_db_get_by_offset(RzTypeDB *typedb, ut64 offset) {
	rz_return_val_if_fail(typedb, NULL);
	Sdb *TDB = typedb->sdb_types;
	RzList *offtypes = rz_list_new();
	SdbList *ls = sdb_foreach_list(TDB, true);
	SdbListIter *lsi;
	SdbKv *kv;
	ls_foreach (ls, lsi, kv) {
		// TODO: Add unions support
		if (!strncmp(sdbkv_value(kv), "struct", 6) && strncmp(sdbkv_key(kv), "struct.", 7)) {
			char *res = rz_type_db_get_struct_member(typedb, sdbkv_key(kv), offset);
			if (res) {
				rz_list_append(offtypes, res);
			}
		}
	}
	ls_free(ls);
	return offtypes;
}

RZ_API RzBaseType *rz_type_db_get_enum(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	if (btype->kind != RZ_BASE_TYPE_KIND_ENUM) {
		return NULL;
	}
	return btype;
}

RZ_API char *rz_type_db_enum_member_by_val(RzTypeDB *typedb, RZ_NONNULL const char *name, ut64 val) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	if (btype->kind != RZ_BASE_TYPE_KIND_ENUM) {
		return NULL;
	}
	RzTypeEnumCase *cas;
	rz_vector_foreach(&btype->enum_data.cases, cas) {
		if (cas->val == val) {
			return cas->name;
		}
	}
	return NULL;
}

RZ_API int rz_type_db_enum_member_by_name(RzTypeDB *typedb, RZ_NONNULL const char *name, const char *member) {
	rz_return_val_if_fail(typedb && name, -1);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return -1;
	}
	if (btype->kind != RZ_BASE_TYPE_KIND_ENUM) {
		return -1;
	}
	RzTypeEnumCase *cas;
	int result = -1;
	rz_vector_foreach(&btype->enum_data.cases, cas) {
		if (!strcmp(cas->name, member)) {
			result = cas->val;
			break;
		}
	}
	return result;
}

RZ_API RZ_OWN RzList *rz_type_db_find_enums_by_val(RzTypeDB *typedb, ut64 val) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *enums = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_ENUM);
	RzList *result = rz_list_newf(free);
	RzListIter *iter;
	RzBaseType *e;
	rz_list_foreach (enums, iter, e) {
		RzTypeEnumCase *cas;
		rz_vector_foreach(&e->enum_data.cases, cas) {
			if (cas->val == val) {
				rz_list_append(result, rz_str_newf("%s.%s", e->name, cas->name));
			}
		}
	}
	rz_list_free(enums);
	return result;
}

RZ_API char *rz_type_db_enum_get_bitfield(RzTypeDB *typedb, RZ_NONNULL const char *name, ut64 val) {
	rz_return_val_if_fail(typedb && name, NULL);
	char *res = NULL;
	int i;
	bool isFirst = true;
	char *ret = rz_str_newf("0x%08" PFMT64x " : ", val);

	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	if (btype->kind != RZ_BASE_TYPE_KIND_ENUM) {
		return NULL;
	}
	for (i = 0; i < 32; i++) {
		ut32 n = 1ULL << i;
		if (!(val & n)) {
			continue;
		}
		RzTypeEnumCase *cas;
		rz_vector_foreach(&btype->enum_data.cases, cas) {
			if (cas->val == n) {
				res = cas->name;
				break;
			}
		}
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

RZ_API char *rz_type_db_get_struct_member(RzTypeDB *typedb, RZ_NONNULL const char *type, int offset) {
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
				char *nested_res = rz_type_db_get_struct_member(typedb, nested_type, offset - cur_offset);
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
