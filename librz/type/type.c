// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2019 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2019-2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <string.h>
#include <sdb.h>

#include "type_internal.h"

RZ_API RzType *rz_type_new() {
	RzType *type = RZ_NEW0(RzType);
	if (!type) {
		return NULL;
	}
	Sdb *sdb = sdb_new0();
	type->sdb_types = sdb_ns(sdb, "types", 1);
	return type;
}

RZ_API void rz_type_free(RzType *t) {
	sdb_free(t->sdb_types);
	free(t);
}

// copypasta from core/cbin.c
static void sdb_concat_by_path(Sdb *s, const char *path) {
	Sdb *db = sdb_new(0, path, 0);
	sdb_merge(s, db);
	sdb_close(db);
	sdb_free(db);
}

RZ_API void rz_type_load_sdb(RzType *t, const char *path) {
	if (rz_file_exists(path)) {
		sdb_concat_by_path(t->sdb_types, path);
	}
}

RZ_API void rz_type_purge(RzType *t) {
	sdb_reset(t->sdb_types);
}

RZ_API void rz_type_set_bits(RzType *t, int bits) {
	t->target->bits = bits;
}

RZ_API void rz_type_set_os(RzType *t, const char *os) {
	t->target->os = os;
}

RZ_API void rz_type_set_cpu(RzType *t, const char *cpu) {
	t->target->cpu = cpu;
}

RZ_API char *rz_type_kuery(RzType *t, const char *query) {
	char *output = NULL;
	if (query) {
		output = sdb_querys(t->sdb_types, NULL, -1, query);
	} else {
		output = sdb_querys(t->sdb_types, NULL, -1, "*");
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

RZ_API bool rz_type_del(RzType *t, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(t && name, false);
	Sdb *TDB = t->sdb_types;
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
		RzList *list = rz_type_get_enum(t, name);
		RzTypeEnum *member;
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
		return false;
	}
	return true;
}

RZ_API void rz_type_remove_parsed_type(RzType *t, const char *name) {
	rz_return_if_fail(t && name);
	Sdb *TDB = t->sdb_types;
	SdbKv *kv;
	SdbListIter *iter;
	const char *type = sdb_const_get(TDB, name, 0);
	if (!type) {
		return;
	}
	int tmp_len = strlen(name) + strlen(type);
	char *tmp = malloc(tmp_len + 1);
	rz_type_del(t, name);
	if (tmp) {
		snprintf(tmp, tmp_len + 1, "%s.%s.", type, name);
		SdbList *l = sdb_foreach_list(TDB, true);
		ls_foreach (l, iter, kv) {
			if (!strncmp(sdbkv_key(kv), tmp, tmp_len)) {
				rz_type_del(t, sdbkv_key(kv));
			}
		}
		ls_free(l);
		free(tmp);
	}
}

RZ_API void rz_type_save_parsed_type(RzType *t, const char *parsed) {
	rz_return_if_fail(t && parsed);

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
			rz_type_remove_parsed_type(t, name);
		}
		free(type);
	}

	// Now add the type to sdb.
	sdb_query_lines(t->sdb_types, parsed);
}

RZ_API void rz_type_db_init(RzType *types, const char *dir_prefix, const char *arch, int bits, const char *os) {
	rz_return_if_fail(types);
	Sdb *TDB = types->sdb_types;

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

RZ_API RzList *rz_type_enums(RzType *type) {
	RzList *ccl = rz_list_new();
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(type->sdb_types, true);
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "enum")) {
			rz_list_append(ccl, strdup(sdbkv_key(kv)));
		}
	}
	ls_free(l);
	return ccl;
}

static bool sdb_if_typedef_cb(void *p, const char *k, const char *v) {
	return !strncmp(v, "typedef", strlen("typedef") + 1);
}

RZ_API RzList *rz_type_typedefs(RzType *type) {
	Sdb *TDB = type->sdb_types;
	SdbList *sl = sdb_foreach_list_filter_user(TDB, sdb_if_typedef_cb, true, TDB);
	RzList *l = rz_list_of_sdblist(sl);
	ls_free(sl);
	return l;
}

RZ_API RzList *rz_type_links(RzType *type) {
	RzList *ccl = rz_list_new();
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(type->sdb_types, true);
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "link")) {
			rz_list_append(ccl, strdup(sdbkv_key(kv)));
		}
	}
	ls_free(l);
	return ccl;
}


