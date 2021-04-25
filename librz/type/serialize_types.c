// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_list.h>
#include <rz_vector.h>
#include <rz_type.h>
#include <sdb.h>

static char *get_type_data(Sdb *sdb, const char *type, const char *sname) {
	rz_return_val_if_fail(sdb && RZ_STR_ISNOTEMPTY(type) && RZ_STR_ISNOTEMPTY(sname), NULL);
	char *key = rz_str_newf("%s.%s", type, sname);
	if (!key) {
		return NULL;
	}
	char *members = sdb_get(sdb, key, NULL);
	free(key);
	return members;
}

static RzBaseType *get_enum_type(Sdb *sdb, const char *sname) {
	rz_return_val_if_fail(sdb && RZ_STR_ISNOTEMPTY(sname), NULL);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ENUM);
	if (!base_type) {
		return NULL;
	}

	char *members = get_type_data(sdb, "enum", sname);
	if (!members) {
		goto error;
	}

	base_type->name = strdup(sname);
	RzVector *cases = &base_type->enum_data.cases;
	if (!rz_vector_reserve(cases, (size_t)sdb_alen(members))) {
		goto error;
	}

	char *cur;
	sdb_aforeach(cur, members) {
		char *val_key = rz_str_newf("enum.%s.%s", sname, cur);
		if (!val_key) {
			goto error;
		}
		const char *value = sdb_const_get(sdb, val_key, NULL);
		free(val_key);

		if (!value) { // if nothing is found, ret NULL
			goto error;
		}

		RzTypeEnumCase cas = { .name = strdup(cur), .val = strtol(value, NULL, 16) };

		void *element = rz_vector_push(cases, &cas); // returns null if no space available
		if (!element) {
			goto error;
		}

		sdb_aforeach_next(cur);
	}
	free(members);

	return base_type;

error:
	free(members);
	rz_type_base_type_free(base_type);
	return NULL;
}

static RzBaseType *get_struct_type(RzTypeDB *typedb, Sdb *sdb, const char *sname) {
	rz_return_val_if_fail(typedb && sdb && RZ_STR_ISNOTEMPTY(sname), NULL);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_STRUCT);
	if (!base_type) {
		return NULL;
	}

	char *sdb_members = get_type_data(sdb, "struct", sname);
	if (!sdb_members) {
		goto error;
	}

	base_type->name = strdup(sname);
	RzVector *members = &base_type->struct_data.members;
	if (!rz_vector_reserve(members, (size_t)sdb_alen(sdb_members))) {
		goto error;
	}

	char *cur;
	sdb_aforeach(cur, sdb_members) {
		char *type_key = rz_str_newf("struct.%s.%s", sname, cur);
		if (!type_key) {
			goto error;
		}
		char *values = sdb_get(sdb, type_key, NULL);
		free(type_key);

		if (!values) {
			goto error;
		}
		char *offset = NULL;
		char *type = sdb_anext(values, &offset);
		if (!offset) { // offset is missing, malformed state
			free(values);
			goto error;
		}
		// Parse type as a C string
		RzType *ttype = rz_type_parse(typedb->parser, type, NULL);
		offset = sdb_anext(offset, NULL);
		RzTypeStructMember cas = {
			.name = strdup(cur),
			.type = ttype,
			.offset = strtol(offset, NULL, 10)
		};

		free(values);

		void *element = rz_vector_push(members, &cas); // returns null if no space available
		if (!element) {
			goto error;
		}

		sdb_aforeach_next(cur);
	}
	free(sdb_members);

	return base_type;

error:
	rz_type_base_type_free(base_type);
	free(sdb_members);
	return NULL;
}

static RzBaseType *get_union_type(RzTypeDB *typedb, Sdb *sdb, const char *sname) {
	rz_return_val_if_fail(typedb && sdb && RZ_STR_ISNOTEMPTY(sname), NULL);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_UNION);
	if (!base_type) {
		return NULL;
	}

	char *sdb_members = get_type_data(sdb, "union", sname);
	if (!sdb_members) {
		goto error;
	}

	base_type->name = strdup(sname);
	RzVector *members = &base_type->union_data.members;
	if (!rz_vector_reserve(members, (size_t)sdb_alen(sdb_members))) {
		goto error;
	}

	char *cur;
	sdb_aforeach(cur, sdb_members) {
		char *type_key = rz_str_newf("union.%s.%s", sname, cur);
		if (!type_key) {
			goto error;
		}
		char *values = sdb_get(sdb, type_key, NULL);
		free(type_key);

		if (!values) {
			goto error;
		}
		char *value = sdb_anext(values, NULL);
		RzType *ttype = rz_type_parse(typedb->parser, value, NULL);
		RzTypeUnionMember cas = {
			.name = strdup(cur),
			.type = ttype
		};
		free(values);

		void *element = rz_vector_push(members, &cas); // returns null if no space available
		if (!element) {
			goto error;
		}

		sdb_aforeach_next(cur);
	}
	free(sdb_members);

	return base_type;

error:
	rz_type_base_type_free(base_type);
	free(sdb_members);
	return NULL;
}

static RzBaseType *get_typedef_type(RzTypeDB *typedb, Sdb *sdb, const char *sname) {
	rz_return_val_if_fail(typedb && sdb && RZ_STR_ISNOTEMPTY(sname), NULL);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
	if (!base_type) {
		return NULL;
	}

	base_type->name = strdup(sname);
	char *type = get_type_data(sdb, "typedef", sname);
	RzType *ttype = rz_type_parse(typedb->parser, type, NULL);
	base_type->type = ttype;
	if (!base_type->type) {
		goto error;
	}
	return base_type;

error:
	rz_type_base_type_free(base_type);
	return NULL;
}

static RzBaseType *get_atomic_type(RzTypeDB *typedb, Sdb *sdb, const char *sname) {
	rz_return_val_if_fail(typedb && sdb && RZ_STR_ISNOTEMPTY(sname), NULL);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ATOMIC);
	if (!base_type) {
		return NULL;
	}

	char *type = get_type_data(sdb, "type", sname);
	RzType *ttype = rz_type_parse(typedb->parser, type, NULL);
	base_type->type = ttype;
	if (!base_type->type) {
		goto error;
	}

	RzStrBuf key;
	base_type->name = strdup(sname);
	base_type->size = sdb_num_get(sdb, rz_strbuf_initf(&key, "type.%s.size", sname), 0);
	rz_strbuf_fini(&key);

	return base_type;

error:
	rz_type_base_type_free(base_type);
	return NULL;
}

bool sdb_load_base_types(RzTypeDB *typedb, Sdb *sdb) {
	rz_return_val_if_fail(typedb && sdb, NULL);
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(sdb, true);
	ls_foreach (l, iter, kv) {
		RzBaseType *base_type = NULL;
		if (!strcmp(sdbkv_value(kv), "struct")) {
			base_type = get_struct_type(typedb, sdb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "enum")) {
			base_type = get_enum_type(sdb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "union")) {
			base_type = get_union_type(typedb, sdb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "typedef")) {
			base_type = get_typedef_type(typedb, sdb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "type")) {
			base_type = get_atomic_type(typedb, sdb, sdbkv_key(kv));
		}
		if (base_type) {
			ht_pp_insert(typedb->types, base_type->name, base_type);
		}
	}
	return true;
}

static void save_struct(const RzTypeDB *typedb, Sdb *sdb, const RzBaseType *type) {
	rz_return_if_fail(typedb && sdb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_STRUCT);
	char *kind = "struct";
	/*
		C:
		struct name {type param1; type param2; type paramN;};
		Sdb:
		name=struct
		struct.name=param1,param2,paramN
		struct.name.param1=type,0,0
		struct.name.param2=type,4,0
		struct.name.paramN=type,8,0
	*/
	char *sname = rz_str_sanitize_sdb_key(type->name);
	// name=struct
	sdb_set(sdb, sname, kind, 0);

	RzStrBuf arglist;
	RzStrBuf param_key;
	RzStrBuf param_val;
	rz_strbuf_init(&arglist);
	rz_strbuf_init(&param_key);
	rz_strbuf_init(&param_val);

	int i = 0;
	RzTypeStructMember *member;
	rz_vector_foreach(&type->struct_data.members, member) {
		// struct.name.param=type,offset,argsize
		char *member_sname = rz_str_sanitize_sdb_key(member->name);
		char *member_type = rz_type_as_string(typedb, member->type);
		sdb_set(sdb,
			rz_strbuf_setf(&param_key, "%s.%s.%s", kind, sname, member_sname),
			rz_strbuf_setf(&param_val, "%s,%zu,%u", member_type, member->offset, 0), 0ULL);
		free(member_type);
		free(member_sname);

		rz_strbuf_appendf(&arglist, (i++ == 0) ? "%s" : ",%s", member->name);
	}
	// struct.name=param1,param2,paramN
	char *key = rz_str_newf("%s.%s", kind, sname);
	sdb_set(sdb, key, rz_strbuf_get(&arglist), 0);
	free(key);

	free(sname);

	rz_strbuf_fini(&arglist);
	rz_strbuf_fini(&param_key);
	rz_strbuf_fini(&param_val);
}

static void save_union(const RzTypeDB *typedb, Sdb *sdb, const RzBaseType *type) {
	rz_return_if_fail(typedb && sdb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_UNION);
	const char *kind = "union";
	/*
	C:
	union name {type param1; type param2; type paramN;};
	Sdb:
	name=union
	union.name=param1,param2,paramN
	union.name.param1=type,0,0
	union.name.param2=type,0,0
	union.name.paramN=type,0,0
	*/
	char *sname = rz_str_sanitize_sdb_key(type->name);
	// name=union
	sdb_set(sdb, sname, kind, 0);

	RzStrBuf arglist;
	RzStrBuf param_key;
	RzStrBuf param_val;
	rz_strbuf_init(&arglist);
	rz_strbuf_init(&param_key);
	rz_strbuf_init(&param_val);

	int i = 0;
	RzTypeUnionMember *member;
	rz_vector_foreach(&type->union_data.members, member) {
		// union.name.arg1=type,offset,argsize
		char *member_sname = rz_str_sanitize_sdb_key(member->name);
		char *mtype = rz_type_as_string(typedb, member->type);
		sdb_set(sdb,
			rz_strbuf_setf(&param_key, "%s.%s.%s", kind, sname, member_sname),
			rz_strbuf_setf(&param_val, "%s,%zu,%u", mtype, member->offset, 0), 0ULL);
		free(member_sname);

		rz_strbuf_appendf(&arglist, (i++ == 0) ? "%s" : ",%s", member->name);
	}
	// union.name=arg1,arg2,argN
	char *key = rz_str_newf("%s.%s", kind, sname);
	sdb_set(sdb, key, rz_strbuf_get(&arglist), 0);
	free(key);

	free(sname);

	rz_strbuf_fini(&arglist);
	rz_strbuf_fini(&param_key);
	rz_strbuf_fini(&param_val);
}

static void save_enum(const RzTypeDB *typedb, Sdb *sdb, const RzBaseType *type) {
	rz_return_if_fail(typedb && sdb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_ENUM);
	/*
		C:
			enum name {case1 = 1, case2 = 2, caseN = 3};
		Sdb:
		name=enum
		enum.name=arg1,arg2,argN
		enum.MyEnum.0x1=arg1
		enum.MyEnum.0x3=arg2
		enum.MyEnum.0x63=argN
		enum.MyEnum.arg1=0x1
		enum.MyEnum.arg2=0x63
		enum.MyEnum.argN=0x3
	*/
	char *sname = rz_str_sanitize_sdb_key(type->name);
	sdb_set(sdb, sname, "enum", 0);

	RzStrBuf arglist;
	RzStrBuf param_key;
	RzStrBuf param_val;
	rz_strbuf_init(&arglist);
	rz_strbuf_init(&param_key);
	rz_strbuf_init(&param_val);

	int i = 0;
	RzTypeEnumCase *cas;
	rz_vector_foreach(&type->enum_data.cases, cas) {
		// enum.name.arg1=type,offset,???
		char *case_sname = rz_str_sanitize_sdb_key(cas->name);
		sdb_set(sdb,
			rz_strbuf_setf(&param_key, "enum.%s.%s", sname, case_sname),
			rz_strbuf_setf(&param_val, "0x%" PFMT64x "", cas->val), 0);

		sdb_set(sdb,
			rz_strbuf_setf(&param_key, "enum.%s.0x%" PFMT64x "", sname, cas->val),
			case_sname, 0);
		free(case_sname);

		rz_strbuf_appendf(&arglist, (i++ == 0) ? "%s" : ",%s", cas->name);
	}
	// enum.name=arg1,arg2,argN
	char *key = rz_str_newf("enum.%s", sname);
	sdb_set(sdb, key, rz_strbuf_get(&arglist), 0);
	free(key);

	free(sname);

	rz_strbuf_fini(&arglist);
	rz_strbuf_fini(&param_key);
	rz_strbuf_fini(&param_val);
}

static void save_atomic_type(const RzTypeDB *typedb, Sdb *sdb, const RzBaseType *type) {
	rz_return_if_fail(typedb && sdb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_ATOMIC);
	/*
		C: (cannot define a custom atomic type)
		Sdb:
		char=type
		type.char=c
		type.char.size=8
	*/
	char *sname = rz_str_sanitize_sdb_key(type->name);
	sdb_set(sdb, sname, "type", 0);

	RzStrBuf key;
	RzStrBuf val;
	rz_strbuf_init(&key);
	rz_strbuf_init(&val);

	sdb_set(sdb,
		rz_strbuf_setf(&key, "type.%s.size", sname),
		rz_strbuf_setf(&val, "%" PFMT64u "", type->size), 0);

	char *atype = rz_type_as_string(typedb, type->type);
	sdb_set(sdb,
		rz_strbuf_setf(&key, "type.%s", sname),
		atype, 0);

	free(sname);

	rz_strbuf_fini(&key);
	rz_strbuf_fini(&val);
}

static void save_typedef(const RzTypeDB *typedb, Sdb *sdb, const RzBaseType *type) {
	rz_return_if_fail(typedb && sdb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_TYPEDEF);
	/*
		C:
		typedef char byte;
		Sdb:
		byte=typedef
		typedef.byte=char
	*/
	char *sname = rz_str_sanitize_sdb_key(type->name);
	sdb_set(sdb, sname, "typedef", 0);

	RzStrBuf key;
	RzStrBuf val;
	rz_strbuf_init(&key);
	rz_strbuf_init(&val);

	char *ttype = rz_type_as_string(typedb, type->type);
	sdb_set(sdb,
		rz_strbuf_setf(&key, "typedef.%s", sname),
		rz_strbuf_setf(&val, "%s", ttype), 0);

	free(sname);
	free(ttype);

	rz_strbuf_fini(&key);
	rz_strbuf_fini(&val);
}

void sdb_save_base_type(const RzTypeDB *typedb, RZ_NONNULL Sdb *sdb, const RzBaseType *type) {
	rz_return_if_fail(typedb && sdb && type && type->name);

	switch (type->kind) {
	case RZ_BASE_TYPE_KIND_STRUCT:
		save_struct(typedb, sdb, type);
		break;
	case RZ_BASE_TYPE_KIND_ENUM:
		save_enum(typedb, sdb, type);
		break;
	case RZ_BASE_TYPE_KIND_UNION:
		save_union(typedb, sdb, type);
		break;
	case RZ_BASE_TYPE_KIND_TYPEDEF:
		save_typedef(typedb, sdb, type);
		break;
	case RZ_BASE_TYPE_KIND_ATOMIC:
		save_atomic_type(typedb, sdb, type);
		break;
	default:
		break;
	}
}

RZ_IPI bool types_load_sdb(RZ_NONNULL Sdb *db, RZ_NONNULL RzTypeDB *typedb) {
	return sdb_load_base_types(typedb, db);
}

struct base_type_sdb {
	RzTypeDB *typedb;
	Sdb *sdb;
};

static bool export_base_type_cb(void *user, const void *k, const void *v) {
	struct base_type_sdb *s = user;
	RzBaseType *btype = (RzBaseType *)v;
	sdb_save_base_type(s->typedb, s->sdb, btype);
	return true;
}

static bool types_export_sdb(RZ_NONNULL Sdb *db, RZ_NONNULL RzTypeDB *typedb) {
	struct base_type_sdb tdb = { typedb, db };
	ht_pp_foreach(typedb->types, export_base_type_cb, &tdb);
	return true;
}

static void sdb_load_by_path(RZ_NONNULL RzTypeDB *typedb, const char *path) {
	Sdb *db = sdb_new(0, path, 0);
	types_load_sdb(db, typedb);
	sdb_close(db);
	sdb_free(db);
}

RZ_API void rz_type_db_load_sdb(RzTypeDB *typedb, const char *path) {
	if (rz_file_exists(path)) {
		sdb_load_by_path(typedb, path);
	}
}

RZ_API void rz_serialize_types_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzTypeDB *typedb) {
	types_export_sdb(db, typedb);
}

RZ_API bool rz_serialize_types_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzTypeDB *typedb, RZ_NULLABLE RzSerializeResultInfo *res) {
	types_load_sdb(db, typedb);
	return true;
}
