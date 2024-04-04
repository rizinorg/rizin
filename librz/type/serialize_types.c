// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_list.h>
#include <rz_vector.h>
#include <rz_type.h>
#include <sdb.h>

typedef struct {
	RzBaseType *type;
	char *format;
} TypeFormatPair;

inline static RzTypeTypeclass get_base_type_typeclass(RZ_NONNULL const RzBaseType *type) {
	rz_return_val_if_fail(type, RZ_TYPE_TYPECLASS_INVALID);
	return type->attrs & RZ_TYPE_ATTRIBUTE_TYPECLASS_MASK;
}

inline static void set_base_type_typeclass(RZ_NONNULL RzBaseType *type, RzTypeTypeclass typeclass) {
	rz_return_if_fail(type && typeclass < RZ_TYPE_TYPECLASS_INVALID);
	type->attrs = typeclass;
}

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

static TypeFormatPair *get_enum_type(Sdb *sdb, const char *sname) {
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

	RzStrBuf key;
	char *format = sdb_get(sdb, rz_strbuf_initf(&key, "type.%s", sname), 0);
	rz_strbuf_fini(&key);

	TypeFormatPair *tpair = RZ_NEW0(TypeFormatPair);
	tpair->type = base_type;
	tpair->format = format;

	return tpair;

error:
	free(members);
	rz_type_base_type_free(base_type);
	return NULL;
}

static TypeFormatPair *get_struct_type(RzTypeDB *typedb, Sdb *sdb, const char *sname) {
	rz_return_val_if_fail(typedb && sdb && RZ_STR_ISNOTEMPTY(sname), NULL);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_STRUCT);
	if (!base_type) {
		return NULL;
	}
	base_type->name = strdup(sname);

	char *sdb_members = get_type_data(sdb, "struct", sname);
	if (sdb_members) {
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
			char *error_msg = NULL;
			RzType *ttype = rz_type_parse_string_single(typedb->parser, type, &error_msg);
			if (!ttype || error_msg) {
				free(error_msg);
				free(values);
				goto error;
			}

			RzTypeStructMember memb = {
				.name = strdup(cur),
				.type = ttype,
				.offset = strtol(offset, NULL, 10)
			};

			free(values);

			void *element = rz_vector_push(members, &memb); // returns null if no space available
			if (!element) {
				goto error;
			}

			sdb_aforeach_next(cur);
		}
		free(sdb_members);
	}

	RzStrBuf key;
	const char *format = sdb_get(sdb, rz_strbuf_initf(&key, "type.%s", sname), 0);
	rz_strbuf_fini(&key);

	TypeFormatPair *tpair = RZ_NEW0(TypeFormatPair);
	tpair->type = base_type;
	tpair->format = format ? strdup(format) : NULL;

	return tpair;

error:
	rz_type_base_type_free(base_type);
	free(sdb_members);
	return NULL;
}

static TypeFormatPair *get_union_type(RzTypeDB *typedb, Sdb *sdb, const char *sname) {
	rz_return_val_if_fail(typedb && sdb && RZ_STR_ISNOTEMPTY(sname), NULL);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_UNION);
	if (!base_type) {
		return NULL;
	}

	base_type->name = strdup(sname);

	char *sdb_members = get_type_data(sdb, "union", sname);
	if (sdb_members) {
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
			char *error_msg = NULL;
			RzType *ttype = rz_type_parse_string_single(typedb->parser, value, &error_msg);
			if (!ttype || error_msg) {
				free(values);
				goto error;
			}

			RzTypeUnionMember memb = {
				.name = strdup(cur),
				.type = ttype
			};
			free(values);

			void *element = rz_vector_push(members, &memb); // returns null if no space available
			if (!element) {
				goto error;
			}

			sdb_aforeach_next(cur);
		}
		free(sdb_members);
	}

	RzStrBuf key;
	const char *format = sdb_get(sdb, rz_strbuf_initf(&key, "type.%s", sname), 0);
	rz_strbuf_fini(&key);

	TypeFormatPair *tpair = RZ_NEW0(TypeFormatPair);
	tpair->type = base_type;
	tpair->format = format ? strdup(format) : NULL;

	return tpair;

error:
	rz_type_base_type_free(base_type);
	free(sdb_members);
	return NULL;
}

static TypeFormatPair *get_typedef_type(RzTypeDB *typedb, Sdb *sdb, const char *sname) {
	rz_return_val_if_fail(typedb && sdb && RZ_STR_ISNOTEMPTY(sname), NULL);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
	if (!base_type) {
		return NULL;
	}

	base_type->name = strdup(sname);
	char *type = get_type_data(sdb, "typedef", sname);
	char *error_msg = NULL;
	RzType *ttype = rz_type_parse_string_single(typedb->parser, type, &error_msg);
	if (!ttype || error_msg) {
		goto error;
	}
	free(type);

	base_type->type = ttype;
	if (!base_type->type) {
		goto error;
	}

	RzStrBuf key;
	char *format = sdb_get(sdb, rz_strbuf_initf(&key, "type.%s", sname), 0);
	rz_strbuf_fini(&key);

	TypeFormatPair *tpair = RZ_NEW0(TypeFormatPair);
	tpair->type = base_type;
	tpair->format = format;

	return tpair;

error:
	free(type);
	rz_type_base_type_free(base_type);
	return NULL;
}

static TypeFormatPair *get_atomic_type(RzTypeDB *typedb, Sdb *sdb, const char *sname) {
	rz_return_val_if_fail(typedb && sdb && RZ_STR_ISNOTEMPTY(sname), NULL);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ATOMIC);
	if (!base_type) {
		return NULL;
	}

	RzType *ttype = RZ_NEW0(RzType);
	if (!ttype) {
		goto error;
	}
	ttype->kind = RZ_TYPE_KIND_IDENTIFIER;
	ttype->identifier.name = strdup(sname);
	ttype->identifier.is_const = false; // We don't preload const types by default
	ttype->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
	base_type->type = ttype;

	base_type->name = strdup(sname);
	RzStrBuf key;
	base_type->size = sdb_num_get(sdb, rz_strbuf_initf(&key, "type.%s.size", sname), 0);
	RzTypeTypeclass typeclass = RZ_TYPE_TYPECLASS_NONE;
	const char *tclass = sdb_const_get(sdb, rz_strbuf_setf(&key, "type.%s.typeclass", sname), 0);
	if (tclass) {
		typeclass = rz_type_typeclass_from_string(tclass);
	}
	set_base_type_typeclass(base_type, typeclass);
	const char *format = sdb_const_get(sdb, rz_strbuf_setf(&key, "type.%s", sname), 0);
	rz_strbuf_fini(&key);

	TypeFormatPair *tpair = RZ_NEW0(TypeFormatPair);
	tpair->type = base_type;
	tpair->format = format ? strdup(format) : NULL;

	return tpair;

error:
	rz_type_base_type_free(base_type);
	return NULL;
}

bool sdb_load_base_types(RzTypeDB *typedb, Sdb *sdb) {
	rz_return_val_if_fail(typedb && sdb, false);
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(sdb, false);
	ls_foreach (l, iter, kv) {
		TypeFormatPair *tpair = NULL;
		if (!strcmp(sdbkv_value(kv), "struct")) {
			tpair = get_struct_type(typedb, sdb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "enum")) {
			tpair = get_enum_type(sdb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "union")) {
			tpair = get_union_type(typedb, sdb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "typedef")) {
			tpair = get_typedef_type(typedb, sdb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "type")) {
			tpair = get_atomic_type(typedb, sdb, sdbkv_key(kv));
		}
		if (tpair && tpair->type) {
			ht_sp_update(typedb->types, tpair->type->name, tpair->type);
			// If the SDB provided the preferred type format then we store it
			char *format = tpair->format ? tpair->format : NULL;
			// Format is not always defined, e.g. for types like "void" or anonymous types
			if (format) {
				ht_ss_update(typedb->formats, tpair->type->name, format);
				RZ_LOG_DEBUG("inserting the \"%s\" type & format: \"%s\"\n", tpair->type->name, format);
			} else {
				ht_ss_delete(typedb->formats, tpair->type->name);
			}
		} else if (tpair) {
			free(tpair->format);
		}
		free(tpair);
	}
	ls_free(l);
	return true;
}

static void save_struct(const RzTypeDB *typedb, Sdb *sdb, const RzBaseType *type) {
	rz_return_if_fail(typedb && sdb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_STRUCT);
	const char *kind = "struct";
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
	char *sname = type->name;
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
	char *sname = type->name;
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
		char *member_type = rz_type_as_string(typedb, member->type);
		sdb_set(sdb,
			rz_strbuf_setf(&param_key, "%s.%s.%s", kind, sname, member_sname),
			rz_strbuf_setf(&param_val, "%s,%zu,%u", member_type, member->offset, 0), 0ULL);
		free(member_type);
		free(member_sname);

		rz_strbuf_appendf(&arglist, (i++ == 0) ? "%s" : ",%s", member->name);
	}
	// union.name=arg1,arg2,argN
	char *key = rz_str_newf("%s.%s", kind, sname);
	sdb_set(sdb, key, rz_strbuf_get(&arglist), 0);
	free(key);

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
	char *sname = type->name;
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
		type.char.typeclass=Signed Integral
	*/
	char *sname = type->name;
	sdb_set(sdb, sname, "type", 0);

	RzStrBuf key;
	RzStrBuf val;
	rz_strbuf_init(&key);
	rz_strbuf_init(&val);

	sdb_set(sdb,
		rz_strbuf_setf(&key, "type.%s.size", sname),
		rz_strbuf_setf(&val, "%" PFMT64u "", type->size), 0);
	sdb_set(sdb,
		rz_strbuf_setf(&key, "type.%s.typeclass", sname),
		rz_type_typeclass_as_string(get_base_type_typeclass(type)), 0);

	const char *typefmt = rz_type_db_format_get(typedb, sname);
	sdb_set(sdb,
		rz_strbuf_setf(&key, "type.%s", sname),
		typefmt, 0);

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
	char *sname = type->name;
	sdb_set(sdb, sname, "typedef", 0);

	RzStrBuf key;
	RzStrBuf val;
	rz_strbuf_init(&key);
	rz_strbuf_init(&val);

	char *ttype = rz_type_as_string(typedb, type->type);
	sdb_set(sdb,
		rz_strbuf_setf(&key, "typedef.%s", sname),
		rz_strbuf_setf(&val, "%s", ttype), 0);

	free(ttype);

	rz_strbuf_fini(&key);
	rz_strbuf_fini(&val);
}

void sdb_save_base_type(const RzTypeDB *typedb, RZ_NONNULL Sdb *sdb, const RzBaseType *type) {
	rz_return_if_fail(typedb && sdb && type && type->name);

	switch (type->kind) {
	case RZ_BASE_TYPE_KIND_STRUCT:
		RZ_LOG_DEBUG("Serializing struct \"%s\"\n", type->name);
		save_struct(typedb, sdb, type);
		break;
	case RZ_BASE_TYPE_KIND_ENUM:
		RZ_LOG_DEBUG("Serializing enum \"%s\"\n", type->name);
		save_enum(typedb, sdb, type);
		break;
	case RZ_BASE_TYPE_KIND_UNION:
		RZ_LOG_DEBUG("Serializing union \"%s\"\n", type->name);
		save_union(typedb, sdb, type);
		break;
	case RZ_BASE_TYPE_KIND_TYPEDEF:
		RZ_LOG_DEBUG("Serializing type alias \"%s\"\n", type->name);
		save_typedef(typedb, sdb, type);
		break;
	case RZ_BASE_TYPE_KIND_ATOMIC:
		RZ_LOG_DEBUG("Serializing atomic type \"%s\"\n", type->name);
		save_atomic_type(typedb, sdb, type);
		break;
	default:
		break;
	}
}

RZ_IPI bool types_load_sdb(RZ_NONNULL Sdb *db, RZ_NONNULL RzTypeDB *typedb) {
	return sdb_load_base_types(typedb, db);
}

struct typedb_sdb {
	const RzTypeDB *typedb;
	Sdb *sdb;
};

static bool export_base_type_cb(void *user, RZ_UNUSED const char *k, const void *v) {
	struct typedb_sdb *s = user;
	RzBaseType *btype = (RzBaseType *)v;
	sdb_save_base_type(s->typedb, s->sdb, btype);
	return true;
}

static bool types_export_sdb(RZ_NONNULL Sdb *db, RZ_NONNULL const RzTypeDB *typedb) {
	struct typedb_sdb tdb = { typedb, db };
	ht_sp_foreach(typedb->types, export_base_type_cb, &tdb);
	return true;
}

static bool sdb_load_by_path(RZ_NONNULL RzTypeDB *typedb, RZ_NONNULL const char *path) {
	rz_return_val_if_fail(typedb && path, false);
	if (RZ_STR_ISEMPTY(path)) {
		return false;
	}
	Sdb *db = sdb_new(0, path, 0);
	bool result = types_load_sdb(db, typedb);
	sdb_close(db);
	sdb_free(db);
	return result;
}

static bool sdb_load_from_string(RZ_NONNULL RzTypeDB *typedb, RZ_NONNULL const char *string) {
	rz_return_val_if_fail(typedb && string, false);
	if (RZ_STR_ISEMPTY(string)) {
		return false;
	}
	Sdb *db = sdb_new0();
	sdb_query_lines(db, string);
	bool result = types_load_sdb(db, typedb);
	sdb_close(db);
	sdb_free(db);
	return result;
}

/**
 * \brief Loads the types from compiled SDB specified by path
 *
 * \param typedb RzTypeDB instance
 * \param path A path to the compiled SDB containing serialized types
 */
RZ_API bool rz_type_db_load_sdb(RzTypeDB *typedb, RZ_NONNULL const char *path) {
	rz_return_val_if_fail(typedb && path, false);
	if (!rz_file_exists(path)) {
		return false;
	}
	return sdb_load_by_path(typedb, path);
}

/**
 * \brief Loads the types from SDB KV string
 *
 * \param typedb RzTypeDB instance
 * \param str A string in Key-Value format as for non-compiled SDB
 */
RZ_API bool rz_type_db_load_sdb_str(RzTypeDB *typedb, RZ_NONNULL const char *str) {
	rz_return_val_if_fail(typedb && str, false);
	if (RZ_STR_ISEMPTY(str)) {
		return false;
	}
	return sdb_load_from_string(typedb, str);
}

/**
 * \brief Saves the types into SDB
 *
 * \param db A SDB database object
 * \param typedb RzTypeDB instance
 */
RZ_API void rz_serialize_types_save(RZ_NONNULL Sdb *db, RZ_NONNULL const RzTypeDB *typedb) {
	rz_return_if_fail(db && typedb);
	types_export_sdb(db, typedb);
}

/**
 * \brief Loads the types from SDB
 *
 * \param db A SDB database object
 * \param typedb RzTypeDB instance
 * \param res A structure where the result is stored
 */
RZ_API bool rz_serialize_types_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzTypeDB *typedb, RZ_NULLABLE RzSerializeResultInfo *res) {
	rz_return_val_if_fail(db && typedb, false);
	return types_load_sdb(db, typedb);
}
