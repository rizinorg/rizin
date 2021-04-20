// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <string.h>
#include <sdb.h>

#include "type_internal.h"

RZ_API void rz_type_base_enum_case_free(void *e, void *user) {
	(void)user;
	RzTypeEnumCase *cas = e;
	free((char *)cas->name);
}

RZ_API void rz_type_base_struct_member_free(void *e, void *user) {
	(void)user;
	RzTypeStructMember *member = e;
	free((char *)member->name);
	free((char *)member->type);
}

RZ_API void rz_type_base_union_member_free(void *e, void *user) {
	(void)user;
	RzTypeUnionMember *member = e;
	free((char *)member->name);
	free((char *)member->type);
}

static char *get_type_data(Sdb *sdb_types, const char *type, const char *sname) {
	char *key = rz_str_newf("%s.%s", type, sname);
	if (!key) {
		return NULL;
	}
	char *members = sdb_get(sdb_types, key, NULL);
	free(key);
	return members;
}

static RzBaseType *get_enum_type(RzTypeDB *typedb, const char *sname) {
	rz_return_val_if_fail(typedb && sname, NULL);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ENUM);
	if (!base_type) {
		return NULL;
	}

	char *members = get_type_data(typedb->sdb_types, "enum", sname);
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
		const char *value = sdb_const_get(typedb->sdb_types, val_key, NULL);
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

static RzBaseType *get_struct_type(RzTypeDB *typedb, const char *sname) {
	rz_return_val_if_fail(typedb && sname, NULL);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_STRUCT);
	if (!base_type) {
		return NULL;
	}

	char *sdb_members = get_type_data(typedb->sdb_types, "struct", sname);
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
		char *values = sdb_get(typedb->sdb_types, type_key, NULL);
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

static RzBaseType *get_union_type(RzTypeDB *typedb, const char *sname) {
	rz_return_val_if_fail(typedb && sname, NULL);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_UNION);
	if (!base_type) {
		return NULL;
	}

	char *sdb_members = get_type_data(typedb->sdb_types, "union", sname);
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
		char *values = sdb_get(typedb->sdb_types, type_key, NULL);
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

static RzBaseType *get_typedef_type(RzTypeDB *typedb, const char *sname) {
	rz_return_val_if_fail(typedb && RZ_STR_ISNOTEMPTY(sname), NULL);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
	if (!base_type) {
		return NULL;
	}

	base_type->name = strdup(sname);
	char *type = get_type_data(typedb->sdb_types, "typedef", sname);
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

static RzBaseType *get_atomic_type(RzTypeDB *typedb, const char *sname) {
	rz_return_val_if_fail(typedb && RZ_STR_ISNOTEMPTY(sname), NULL);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ATOMIC);
	if (!base_type) {
		return NULL;
	}

	char *type = get_type_data(typedb->sdb_types, "type", sname);
	RzType *ttype = rz_type_parse(typedb->parser, type, NULL);
	base_type->type = ttype;
	if (!base_type->type) {
		goto error;
	}

	RzStrBuf key;
	base_type->name = strdup(sname);
	base_type->size = sdb_num_get(typedb->sdb_types, rz_strbuf_initf(&key, "type.%s.size", sname), 0);
	rz_strbuf_fini(&key);

	return base_type;

error:
	rz_type_base_type_free(base_type);
	return NULL;
}

// returns NULL if name is not found or any failure happened
RZ_API RzBaseType *rz_type_db_get_base_type(RzTypeDB *typedb, const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);

	char *sname = rz_str_sanitize_sdb_key(name);
	const char *type = sdb_const_get(typedb->sdb_types, sname, NULL);
	if (!type) {
		free(sname);
		return NULL;
	}

	RzBaseType *base_type = NULL;
	if (!strcmp(type, "struct")) {
		base_type = get_struct_type(typedb, sname);
	} else if (!strcmp(type, "enum")) {
		base_type = get_enum_type(typedb, sname);
	} else if (!strcmp(type, "union")) {
		base_type = get_union_type(typedb, sname);
	} else if (!strcmp(type, "typedef")) {
		base_type = get_typedef_type(typedb, sname);
	} else if (!strcmp(type, "type")) {
		base_type = get_atomic_type(typedb, sname);
	}

	if (base_type) {
		free(base_type->name);
		base_type->name = sname;
	} else {
		free(sname);
	}

	return base_type;
}

static void delete_struct(const RzTypeDB *typedb, const RzBaseType *type) {
	rz_return_if_fail(typedb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_STRUCT);
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

	RzStrBuf param_key;
	RzStrBuf param_val;
	rz_strbuf_init(&param_key);
	rz_strbuf_init(&param_val);

	RzTypeStructMember *member;
	rz_vector_foreach(&type->struct_data.members, member) {
		// struct.name.param=type,offset,argsize
		char *member_sname = rz_str_sanitize_sdb_key(member->name);
		sdb_unset(typedb->sdb_types,
			rz_strbuf_setf(&param_key, "%s.%s.%s", kind, sname, member_sname), 0);
		free(member_sname);
	}
	// struct.name=param1,param2,paramN
	char *key = rz_str_newf("%s.%s", kind, sname);
	sdb_unset(typedb->sdb_types, key, 0);
	sdb_unset(typedb->sdb_types, sname, 0);
	free(key);
	free(sname);

	rz_strbuf_fini(&param_key);
	rz_strbuf_fini(&param_val);
}

static void delete_union(const RzTypeDB *typedb, const RzBaseType *type) {
	rz_return_if_fail(typedb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_UNION);
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
	RzStrBuf param_key;
	RzStrBuf param_val;
	rz_strbuf_init(&param_key);
	rz_strbuf_init(&param_val);

	RzTypeStructMember *member;
	rz_vector_foreach(&type->struct_data.members, member) {
		// struct.name.param=type,offset,argsize
		char *member_sname = rz_str_sanitize_sdb_key(member->name);
		sdb_unset(typedb->sdb_types,
			rz_strbuf_setf(&param_key, "%s.%s.%s", kind, sname, member_sname), 0);
		free(member_sname);
	}
	// struct.name=param1,param2,paramN
	char *key = rz_str_newf("%s.%s", kind, sname);
	sdb_unset(typedb->sdb_types, key, 0);
	sdb_unset(typedb->sdb_types, sname, 0);
	free(key);
	free(sname);

	rz_strbuf_fini(&param_key);
	rz_strbuf_fini(&param_val);
}

static void delete_enum(const RzTypeDB *typedb, const RzBaseType *type) {
	rz_return_if_fail(typedb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_ENUM);
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

	RzStrBuf param_key;
	rz_strbuf_init(&param_key);

	RzTypeEnumCase *cas;
	rz_vector_foreach(&type->enum_data.cases, cas) {
		// enum.name.arg1=type,offset,???
		char *case_sname = rz_str_sanitize_sdb_key(cas->name);
		sdb_unset(typedb->sdb_types,
			rz_strbuf_setf(&param_key, "enum.%s.%s", sname, case_sname), 0);
		sdb_unset(typedb->sdb_types,
			rz_strbuf_setf(&param_key, "enum.%s.0x%" PFMT64x "", sname, cas->val), 0);
		free(case_sname);
	}
	// enum.name=arg1,arg2,argN
	char *key = rz_str_newf("enum.%s", sname);
	sdb_unset(typedb->sdb_types, key, 0);
	sdb_unset(typedb->sdb_types, sname, 0);
	free(key);
	free(sname);
	rz_strbuf_fini(&param_key);
}

static void delete_atomic_type(const RzTypeDB *typedb, const RzBaseType *type) {
	rz_return_if_fail(typedb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_ATOMIC);
	/*
		C: (cannot define a custom atomic type)
		Sdb:
		char=type
		type.char=c
		type.char.size=8
	*/
	char *sname = rz_str_sanitize_sdb_key(type->name);
	sdb_set(typedb->sdb_types, sname, "type", 0);

	RzStrBuf key;
	rz_strbuf_init(&key);

	sdb_unset(typedb->sdb_types,
		rz_strbuf_setf(&key, "type.%s.size", sname), 0);
	sdb_unset(typedb->sdb_types,
		rz_strbuf_setf(&key, "type.%s.meta", sname), 0);
	sdb_unset(typedb->sdb_types,
		rz_strbuf_setf(&key, "type.%s", sname), 0);
	sdb_unset(typedb->sdb_types, sname, 0);

	free(sname);

	rz_strbuf_fini(&key);
}

static void delete_typedef(const RzTypeDB *typedb, const RzBaseType *type) {
	rz_return_if_fail(typedb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_TYPEDEF);
	/*
		C:
		typedef char byte;
		Sdb:
		byte=typedef
		typedef.byte=char
	*/
	char *sname = rz_str_sanitize_sdb_key(type->name);

	RzStrBuf key;
	rz_strbuf_init(&key);

	sdb_unset(typedb->sdb_types,
		rz_strbuf_setf(&key, "typedef.%s", sname), 0);
	sdb_unset(typedb->sdb_types, sname, 0);
	free(sname);

	rz_strbuf_fini(&key);
}

/**
 * \brief Removes RzBaseType from the Types DB
 *
 * \param typedb Type Database instance
 * \param type RzBaseType to remove
 */
RZ_API bool rz_type_db_delete_base_type(RzTypeDB *typedb, RZ_NONNULL RzBaseType *type) {
	rz_return_val_if_fail(typedb && type && type->name, NULL);

	// TODO, solve collisions, if there are 2 types with the same name and kind

	switch (type->kind) {
	case RZ_BASE_TYPE_KIND_STRUCT:
		delete_struct(typedb, type);
		break;
	case RZ_BASE_TYPE_KIND_ENUM:
		delete_enum(typedb, type);
		break;
	case RZ_BASE_TYPE_KIND_UNION:
		delete_union(typedb, type);
		break;
	case RZ_BASE_TYPE_KIND_TYPEDEF:
		delete_typedef(typedb, type);
		break;
	case RZ_BASE_TYPE_KIND_ATOMIC:
		delete_atomic_type(typedb, type);
		break;
	default:
		break;
	}
	return true;
}

/**
 * \brief Returns the list of all basic types of the chosen kind
 *
 * \param typedb Types Database instance
 * \param kind Kind of the types to list
 */
RZ_API RZ_OWN RzList /* RzBaseType */ *rz_type_db_get_base_types_of_kind(RzTypeDB *typedb, RzBaseTypeKind kind) {
	rz_return_val_if_fail(typedb, NULL);
	SdbKv *kv;
	SdbListIter *iter;
	RzList *types = rz_list_newf((RzListFree)rz_type_base_type_free);
	SdbList *l = sdb_foreach_list(typedb->sdb_types, true);
	ls_foreach (l, iter, kv) {
		RzBaseType *base_type = NULL;
		if (!strcmp(sdbkv_value(kv), "struct") && kind == RZ_BASE_TYPE_KIND_STRUCT) {
			base_type = get_struct_type(typedb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "enum") && kind == RZ_BASE_TYPE_KIND_ENUM) {
			base_type = get_enum_type(typedb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "union") && kind == RZ_BASE_TYPE_KIND_UNION) {
			base_type = get_union_type(typedb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "typedef") && kind == RZ_BASE_TYPE_KIND_TYPEDEF) {
			base_type = get_typedef_type(typedb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "type") && kind == RZ_BASE_TYPE_KIND_ATOMIC) {
			base_type = get_atomic_type(typedb, sdbkv_key(kv));
		}
		if (base_type) {
			rz_list_append(types, base_type);
		}
	}
	return types;
}

/**
 * \brief Returns the list of all basic types
 *
 * \param typedb Types Database instance
 */
RZ_API RZ_OWN RzList /* RzBaseType */ *rz_type_db_get_base_types(RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	SdbKv *kv;
	SdbListIter *iter;
	RzList *types = rz_list_newf((RzListFree)rz_type_base_type_free);
	SdbList *l = sdb_foreach_list(typedb->sdb_types, true);
	ls_foreach (l, iter, kv) {
		RzBaseType *base_type = NULL;
		if (!strcmp(sdbkv_value(kv), "struct")) {
			base_type = get_struct_type(typedb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "enum")) {
			base_type = get_enum_type(typedb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "union")) {
			base_type = get_union_type(typedb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "typedef")) {
			base_type = get_typedef_type(typedb, sdbkv_key(kv));
		} else if (!strcmp(sdbkv_value(kv), "type")) {
			base_type = get_atomic_type(typedb, sdbkv_key(kv));
		}
		if (base_type) {
			rz_list_append(types, base_type);
		}
	}
	return types;
}

static void save_struct(const RzTypeDB *typedb, const RzBaseType *type) {
	rz_return_if_fail(typedb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_STRUCT);
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
	sdb_set(typedb->sdb_types, sname, kind, 0);

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
		sdb_set(typedb->sdb_types,
			rz_strbuf_setf(&param_key, "%s.%s.%s", kind, sname, member_sname),
			rz_strbuf_setf(&param_val, "%s,%zu,%u", member_type, member->offset, 0), 0ULL);
		free(member_type);
		free(member_sname);

		rz_strbuf_appendf(&arglist, (i++ == 0) ? "%s" : ",%s", member->name);
	}
	// struct.name=param1,param2,paramN
	char *key = rz_str_newf("%s.%s", kind, sname);
	sdb_set(typedb->sdb_types, key, rz_strbuf_get(&arglist), 0);
	free(key);

	free(sname);

	rz_strbuf_fini(&arglist);
	rz_strbuf_fini(&param_key);
	rz_strbuf_fini(&param_val);
}

static void save_union(const RzTypeDB *typedb, const RzBaseType *type) {
	rz_return_if_fail(typedb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_UNION);
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
	sdb_set(typedb->sdb_types, sname, kind, 0);

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
		sdb_set(typedb->sdb_types,
			rz_strbuf_setf(&param_key, "%s.%s.%s", kind, sname, member_sname),
			rz_strbuf_setf(&param_val, "%s,%zu,%u", mtype, member->offset, 0), 0ULL);
		free(member_sname);

		rz_strbuf_appendf(&arglist, (i++ == 0) ? "%s" : ",%s", member->name);
	}
	// union.name=arg1,arg2,argN
	char *key = rz_str_newf("%s.%s", kind, sname);
	sdb_set(typedb->sdb_types, key, rz_strbuf_get(&arglist), 0);
	free(key);

	free(sname);

	rz_strbuf_fini(&arglist);
	rz_strbuf_fini(&param_key);
	rz_strbuf_fini(&param_val);
}

static void save_enum(const RzTypeDB *typedb, const RzBaseType *type) {
	rz_return_if_fail(typedb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_ENUM);
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
	sdb_set(typedb->sdb_types, sname, "enum", 0);

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
		sdb_set(typedb->sdb_types,
			rz_strbuf_setf(&param_key, "enum.%s.%s", sname, case_sname),
			rz_strbuf_setf(&param_val, "0x%" PFMT32x "", cas->val), 0);

		sdb_set(typedb->sdb_types,
			rz_strbuf_setf(&param_key, "enum.%s.0x%" PFMT32x "", sname, cas->val),
			case_sname, 0);
		free(case_sname);

		rz_strbuf_appendf(&arglist, (i++ == 0) ? "%s" : ",%s", cas->name);
	}
	// enum.name=arg1,arg2,argN
	char *key = rz_str_newf("enum.%s", sname);
	sdb_set(typedb->sdb_types, key, rz_strbuf_get(&arglist), 0);
	free(key);

	free(sname);

	rz_strbuf_fini(&arglist);
	rz_strbuf_fini(&param_key);
	rz_strbuf_fini(&param_val);
}

static void save_atomic_type(const RzTypeDB *typedb, const RzBaseType *type) {
	rz_return_if_fail(typedb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_ATOMIC);
	/*
		C: (cannot define a custom atomic type)
		Sdb:
		char=type
		type.char=c
		type.char.size=8
	*/
	char *sname = rz_str_sanitize_sdb_key(type->name);
	sdb_set(typedb->sdb_types, sname, "type", 0);

	RzStrBuf key;
	RzStrBuf val;
	rz_strbuf_init(&key);
	rz_strbuf_init(&val);

	sdb_set(typedb->sdb_types,
		rz_strbuf_setf(&key, "type.%s.size", sname),
		rz_strbuf_setf(&val, "%" PFMT64u "", type->size), 0);

	char *atype = rz_type_as_string(typedb, type->type);
	sdb_set(typedb->sdb_types,
		rz_strbuf_setf(&key, "type.%s", sname),
		atype, 0);

	free(sname);

	rz_strbuf_fini(&key);
	rz_strbuf_fini(&val);
}

static void save_typedef(const RzTypeDB *typedb, const RzBaseType *type) {
	rz_return_if_fail(typedb && type && type->name && type->kind == RZ_BASE_TYPE_KIND_TYPEDEF);
	/*
		C:
		typedef char byte;
		Sdb:
		byte=typedef
		typedef.byte=char
	*/
	char *sname = rz_str_sanitize_sdb_key(type->name);
	sdb_set(typedb->sdb_types, sname, "typedef", 0);

	RzStrBuf key;
	RzStrBuf val;
	rz_strbuf_init(&key);
	rz_strbuf_init(&val);

	char *ttype = rz_type_as_string(typedb, type->type);
	sdb_set(typedb->sdb_types,
		rz_strbuf_setf(&key, "typedef.%s", sname),
		rz_strbuf_setf(&val, "%s", ttype), 0);

	free(sname);
	free(ttype);

	rz_strbuf_fini(&key);
	rz_strbuf_fini(&val);
}

RZ_API void rz_type_base_type_free(RzBaseType *type) {
	rz_return_if_fail(type);
	RZ_FREE(type->name);
	RZ_FREE(type->type);

	switch (type->kind) {
	case RZ_BASE_TYPE_KIND_STRUCT:
		rz_vector_fini(&type->struct_data.members);
		break;
	case RZ_BASE_TYPE_KIND_UNION:
		rz_vector_fini(&type->union_data.members);
		break;
	case RZ_BASE_TYPE_KIND_ENUM:
		rz_vector_fini(&type->enum_data.cases);
		break;
	case RZ_BASE_TYPE_KIND_TYPEDEF:
	case RZ_BASE_TYPE_KIND_ATOMIC:
		break;
	default:
		break;
	}
	RZ_FREE(type);
}

RZ_API RzBaseType *rz_type_base_type_new(RzBaseTypeKind kind) {
	RzBaseType *type = RZ_NEW0(RzBaseType);
	if (!type) {
		return NULL;
	}
	type->kind = kind;
	switch (type->kind) {
	case RZ_BASE_TYPE_KIND_STRUCT:
		rz_vector_init(&type->struct_data.members, sizeof(RzTypeStructMember), rz_type_base_struct_member_free, NULL);
		break;
	case RZ_BASE_TYPE_KIND_ENUM:
		rz_vector_init(&type->enum_data.cases, sizeof(RzTypeEnumCase), rz_type_base_enum_case_free, NULL);
		break;
	case RZ_BASE_TYPE_KIND_UNION:
		rz_vector_init(&type->union_data.members, sizeof(RzTypeUnionMember), rz_type_base_union_member_free, NULL);
		break;
	default:
		break;
	}

	return type;
}

/**
 * \brief Saves RzBaseType into the Types DB
 *
 * \param typedb Type Database instance
 * \param type RzBaseType to save
 */
RZ_API void rz_type_db_save_base_type(const RzTypeDB *typedb, const RzBaseType *type) {
	rz_return_if_fail(typedb && type && type->name);

	// TODO, solve collisions, if there are 2 types with the same name and kind

	switch (type->kind) {
	case RZ_BASE_TYPE_KIND_STRUCT:
		save_struct(typedb, type);
		break;
	case RZ_BASE_TYPE_KIND_ENUM:
		save_enum(typedb, type);
		break;
	case RZ_BASE_TYPE_KIND_UNION:
		save_union(typedb, type);
		break;
	case RZ_BASE_TYPE_KIND_TYPEDEF:
		save_typedef(typedb, type);
		break;
	case RZ_BASE_TYPE_KIND_ATOMIC:
		save_atomic_type(typedb, type);
		break;
	default:
		break;
	}
}

/**
 * \brief Returns C representation as string of RzBaseType
 *
 * \param typedb Type Database instance
 * \param type RzBaseType to convert
 */
RZ_API RZ_OWN char *rz_type_db_base_type_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type) {
	rz_return_val_if_fail(typedb && type && type->name, NULL);

	RzStrBuf *buf = rz_strbuf_new("");
	switch (type->kind) {
	case RZ_BASE_TYPE_KIND_STRUCT: {
		rz_strbuf_appendf(buf, "struct %s { ", type->name);
		RzTypeStructMember *memb;
		rz_vector_foreach(&type->struct_data.members, memb) {
			const char *membtype = rz_type_as_string(typedb, memb->type);
			rz_strbuf_appendf(buf, "%s %s; ", membtype, memb->name);
		}
		rz_strbuf_append(buf, " };");
		break;
	}
	case RZ_BASE_TYPE_KIND_ENUM: {
		rz_strbuf_appendf(buf, "enum %s { ", type->name);
		RzTypeEnumCase *cas;
		rz_vector_foreach(&type->enum_data.cases, cas) {
			rz_strbuf_appendf(buf, "%s = 0x%" PFMT64x ", ", cas->name, cas->val);
		}
		rz_strbuf_append(buf, " };");
		break;
	}
	case RZ_BASE_TYPE_KIND_UNION: {
		rz_strbuf_appendf(buf, "union %s { ", type->name);
		RzTypeUnionMember *memb;
		rz_vector_foreach(&type->union_data.members, memb) {
			const char *membtype = rz_type_as_string(typedb, memb->type);
			rz_strbuf_appendf(buf, "%s %s; ", membtype, memb->name);
		}
		rz_strbuf_append(buf, " };");
		break;
	}
	case RZ_BASE_TYPE_KIND_TYPEDEF: {
		const char *ttype = rz_type_as_string(typedb, type->type);
		rz_strbuf_appendf(buf, "typedef %s %s;", ttype, type->name);
		break;
	}
	case RZ_BASE_TYPE_KIND_ATOMIC:
		rz_strbuf_append(buf, type->name);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	char *bufstr = rz_strbuf_drain(buf);
	return bufstr;
}
