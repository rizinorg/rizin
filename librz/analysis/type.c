// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2019 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2019 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <string.h>
#include <sdb.h>
#include "base_types.h"

static char *is_type(char *type) {
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

static char *get_type_data(Sdb *sdb_types, const char *type, const char *sname) {
	char *key = rz_str_newf("%s.%s", type, sname);
	if (!key) {
		return NULL;
	}
	char *members = sdb_get(sdb_types, key, NULL);
	free(key);
	return members;
}

RZ_API void rz_analysis_remove_parsed_type(RzAnalysis *analysis, const char *name) {
	rz_return_if_fail(analysis && name);
	Sdb *TDB = analysis->sdb_types;
	SdbKv *kv;
	SdbListIter *iter;
	const char *type = sdb_const_get(TDB, name, 0);
	if (!type) {
		return;
	}
	int tmp_len = strlen(name) + strlen(type);
	char *tmp = malloc(tmp_len + 1);
	rz_type_del(TDB, name);
	if (tmp) {
		snprintf(tmp, tmp_len + 1, "%s.%s.", type, name);
		SdbList *l = sdb_foreach_list(TDB, true);
		ls_foreach (l, iter, kv) {
			if (!strncmp(sdbkv_key(kv), tmp, tmp_len)) {
				rz_type_del(TDB, sdbkv_key(kv));
			}
		}
		ls_free(l);
		free(tmp);
	}
}

RZ_API void rz_analysis_save_parsed_type(RzAnalysis *analysis, const char *parsed) {
	rz_return_if_fail(analysis && parsed);

	// First, if any parsed types exist, let's remove them.
	char *type = strdup(parsed);
	if (type) {
		char *cur = type;
		while (1) {
			cur = is_type(cur);
			if (!cur) {
				break;
			}
			char *name = cur++;
			*name = 0;
			while (name > type && *(name - 1) != '\n') {
				name--;
			}
			rz_analysis_remove_parsed_type(analysis, name);
		}
		free(type);
	}

	// Now add the type to sdb.
	sdb_query_lines(analysis->sdb_types, parsed);
}

static int typecmp(const void *a, const void *b) {
	return strcmp(a, b);
}

RZ_API RzList *rz_analysis_types_from_fcn(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	RzListIter *iter;
	RzAnalysisVar *var;
	RzList *list = rz_analysis_var_all_list(analysis, fcn);
	RzList *type_used = rz_list_new();
	rz_list_foreach (list, iter, var) {
		rz_list_append(type_used, var->type);
	}
	RzList *uniq = rz_list_uniq(type_used, typecmp);
	rz_list_free(type_used);
	return uniq;
}

RZ_IPI void enum_type_case_free(void *e, void *user) {
	(void)user;
	RzAnalysisEnumCase *cas = e;
	free((char *)cas->name);
}

RZ_IPI void struct_type_member_free(void *e, void *user) {
	(void)user;
	RzAnalysisStructMember *member = e;
	free((char *)member->name);
	free((char *)member->type);
}

RZ_IPI void union_type_member_free(void *e, void *user) {
	(void)user;
	RzAnalysisUnionMember *member = e;
	free((char *)member->name);
	free((char *)member->type);
}

static RzAnalysisBaseType *get_enum_type(RzAnalysis *analysis, const char *sname) {
	rz_return_val_if_fail(analysis && sname, NULL);

	RzAnalysisBaseType *base_type = rz_analysis_base_type_new(RZ_ANALYSIS_BASE_TYPE_KIND_ENUM);
	if (!base_type) {
		return NULL;
	}

	char *members = get_type_data(analysis->sdb_types, "enum", sname);
	if (!members) {
		goto error;
	}

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
		const char *value = sdb_const_get(analysis->sdb_types, val_key, NULL);
		free(val_key);

		if (!value) { // if nothing is found, ret NULL
			goto error;
		}

		RzAnalysisEnumCase cas = { .name = strdup(cur), .val = strtol(value, NULL, 16) };

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
	rz_analysis_base_type_free(base_type);
	return NULL;
}

static RzAnalysisBaseType *get_struct_type(RzAnalysis *analysis, const char *sname) {
	rz_return_val_if_fail(analysis && sname, NULL);

	RzAnalysisBaseType *base_type = rz_analysis_base_type_new(RZ_ANALYSIS_BASE_TYPE_KIND_STRUCT);
	if (!base_type) {
		return NULL;
	}

	char *sdb_members = get_type_data(analysis->sdb_types, "struct", sname);
	if (!sdb_members) {
		goto error;
	}

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
		char *values = sdb_get(analysis->sdb_types, type_key, NULL);
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
		offset = sdb_anext(offset, NULL);
		RzAnalysisStructMember cas = {
			.name = strdup(cur),
			.type = strdup(type),
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
	rz_analysis_base_type_free(base_type);
	free(sdb_members);
	return NULL;
}

static RzAnalysisBaseType *get_union_type(RzAnalysis *analysis, const char *sname) {
	rz_return_val_if_fail(analysis && sname, NULL);

	RzAnalysisBaseType *base_type = rz_analysis_base_type_new(RZ_ANALYSIS_BASE_TYPE_KIND_UNION);
	if (!base_type) {
		return NULL;
	}

	char *sdb_members = get_type_data(analysis->sdb_types, "union", sname);
	if (!sdb_members) {
		goto error;
	}

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
		char *values = sdb_get(analysis->sdb_types, type_key, NULL);
		free(type_key);

		if (!values) {
			goto error;
		}
		char *value = sdb_anext(values, NULL);
		RzAnalysisUnionMember cas = { .name = strdup(cur), .type = strdup(value) };
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
	rz_analysis_base_type_free(base_type);
	free(sdb_members);
	return NULL;
}

static RzAnalysisBaseType *get_typedef_type(RzAnalysis *analysis, const char *sname) {
	rz_return_val_if_fail(analysis && RZ_STR_ISNOTEMPTY(sname), NULL);

	RzAnalysisBaseType *base_type = rz_analysis_base_type_new(RZ_ANALYSIS_BASE_TYPE_KIND_TYPEDEF);
	if (!base_type) {
		return NULL;
	}

	base_type->type = get_type_data(analysis->sdb_types, "typedef", sname);
	if (!base_type->type) {
		goto error;
	}
	return base_type;

error:
	rz_analysis_base_type_free(base_type);
	return NULL;
}

static RzAnalysisBaseType *get_atomic_type(RzAnalysis *analysis, const char *sname) {
	rz_return_val_if_fail(analysis && RZ_STR_ISNOTEMPTY(sname), NULL);

	RzAnalysisBaseType *base_type = rz_analysis_base_type_new(RZ_ANALYSIS_BASE_TYPE_KIND_ATOMIC);
	if (!base_type) {
		return NULL;
	}

	base_type->type = get_type_data(analysis->sdb_types, "type", sname);
	if (!base_type->type) {
		goto error;
	}

	RzStrBuf key;
	base_type->size = sdb_num_get(analysis->sdb_types, rz_strbuf_initf(&key, "type.%s.size", sname), 0);
	rz_strbuf_fini(&key);

	return base_type;

error:
	rz_analysis_base_type_free(base_type);
	return NULL;
}

// returns NULL if name is not found or any failure happened
RZ_API RzAnalysisBaseType *rz_analysis_get_base_type(RzAnalysis *analysis, const char *name) {
	rz_return_val_if_fail(analysis && name, NULL);

	char *sname = rz_str_sanitize_sdb_key(name);
	const char *type = sdb_const_get(analysis->sdb_types, sname, NULL);
	if (!type) {
		free(sname);
		return NULL;
	}

	RzAnalysisBaseType *base_type = NULL;
	if (!strcmp(type, "struct")) {
		base_type = get_struct_type(analysis, sname);
	} else if (!strcmp(type, "enum")) {
		base_type = get_enum_type(analysis, sname);
	} else if (!strcmp(type, "union")) {
		base_type = get_union_type(analysis, sname);
	} else if (!strcmp(type, "typedef")) {
		base_type = get_typedef_type(analysis, sname);
	} else if (!strcmp(type, "type")) {
		base_type = get_atomic_type(analysis, sname);
	}

	if (base_type) {
		base_type->name = sname;
	} else {
		free(sname);
	}

	return base_type;
}

static void save_struct(const RzAnalysis *analysis, const RzAnalysisBaseType *type) {
	rz_return_if_fail(analysis && type && type->name && type->kind == RZ_ANALYSIS_BASE_TYPE_KIND_STRUCT);
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
	sdb_set(analysis->sdb_types, sname, kind, 0);

	RzStrBuf arglist;
	RzStrBuf param_key;
	RzStrBuf param_val;
	rz_strbuf_init(&arglist);
	rz_strbuf_init(&param_key);
	rz_strbuf_init(&param_val);

	int i = 0;
	RzAnalysisStructMember *member;
	rz_vector_foreach(&type->struct_data.members, member) {
		// struct.name.param=type,offset,argsize
		char *member_sname = rz_str_sanitize_sdb_key(member->name);
		sdb_set(analysis->sdb_types,
			rz_strbuf_setf(&param_key, "%s.%s.%s", kind, sname, member_sname),
			rz_strbuf_setf(&param_val, "%s,%zu,%u", member->type, member->offset, 0), 0ULL);
		free(member_sname);

		rz_strbuf_appendf(&arglist, (i++ == 0) ? "%s" : ",%s", member->name);
	}
	// struct.name=param1,param2,paramN
	char *key = rz_str_newf("%s.%s", kind, sname);
	sdb_set(analysis->sdb_types, key, rz_strbuf_get(&arglist), 0);
	free(key);

	free(sname);

	rz_strbuf_fini(&arglist);
	rz_strbuf_fini(&param_key);
	rz_strbuf_fini(&param_val);
}

static void save_union(const RzAnalysis *analysis, const RzAnalysisBaseType *type) {
	rz_return_if_fail(analysis && type && type->name && type->kind == RZ_ANALYSIS_BASE_TYPE_KIND_UNION);
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
	sdb_set(analysis->sdb_types, sname, kind, 0);

	RzStrBuf arglist;
	RzStrBuf param_key;
	RzStrBuf param_val;
	rz_strbuf_init(&arglist);
	rz_strbuf_init(&param_key);
	rz_strbuf_init(&param_val);

	int i = 0;
	RzAnalysisUnionMember *member;
	rz_vector_foreach(&type->union_data.members, member) {
		// union.name.arg1=type,offset,argsize
		char *member_sname = rz_str_sanitize_sdb_key(member->name);
		sdb_set(analysis->sdb_types,
			rz_strbuf_setf(&param_key, "%s.%s.%s", kind, sname, member_sname),
			rz_strbuf_setf(&param_val, "%s,%zu,%u", member->type, member->offset, 0), 0ULL);
		free(member_sname);

		rz_strbuf_appendf(&arglist, (i++ == 0) ? "%s" : ",%s", member->name);
	}
	// union.name=arg1,arg2,argN
	char *key = rz_str_newf("%s.%s", kind, sname);
	sdb_set(analysis->sdb_types, key, rz_strbuf_get(&arglist), 0);
	free(key);

	free(sname);

	rz_strbuf_fini(&arglist);
	rz_strbuf_fini(&param_key);
	rz_strbuf_fini(&param_val);
}

static void save_enum(const RzAnalysis *analysis, const RzAnalysisBaseType *type) {
	rz_return_if_fail(analysis && type && type->name && type->kind == RZ_ANALYSIS_BASE_TYPE_KIND_ENUM);
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
	sdb_set(analysis->sdb_types, sname, "enum", 0);

	RzStrBuf arglist;
	RzStrBuf param_key;
	RzStrBuf param_val;
	rz_strbuf_init(&arglist);
	rz_strbuf_init(&param_key);
	rz_strbuf_init(&param_val);

	int i = 0;
	RzAnalysisEnumCase *cas;
	rz_vector_foreach(&type->enum_data.cases, cas) {
		// enum.name.arg1=type,offset,???
		char *case_sname = rz_str_sanitize_sdb_key(cas->name);
		sdb_set(analysis->sdb_types,
			rz_strbuf_setf(&param_key, "enum.%s.%s", sname, case_sname),
			rz_strbuf_setf(&param_val, "0x%" PFMT32x "", cas->val), 0);

		sdb_set(analysis->sdb_types,
			rz_strbuf_setf(&param_key, "enum.%s.0x%" PFMT32x "", sname, cas->val),
			case_sname, 0);
		free(case_sname);

		rz_strbuf_appendf(&arglist, (i++ == 0) ? "%s" : ",%s", cas->name);
	}
	// enum.name=arg1,arg2,argN
	char *key = rz_str_newf("enum.%s", sname);
	sdb_set(analysis->sdb_types, key, rz_strbuf_get(&arglist), 0);
	free(key);

	free(sname);

	rz_strbuf_fini(&arglist);
	rz_strbuf_fini(&param_key);
	rz_strbuf_fini(&param_val);
}

static void save_atomic_type(const RzAnalysis *analysis, const RzAnalysisBaseType *type) {
	rz_return_if_fail(analysis && type && type->name && type->kind == RZ_ANALYSIS_BASE_TYPE_KIND_ATOMIC);
	/*
		C: (cannot define a custom atomic type)
		Sdb:
		char=type
		type.char=c
		type.char.size=8
	*/
	char *sname = rz_str_sanitize_sdb_key(type->name);
	sdb_set(analysis->sdb_types, sname, "type", 0);

	RzStrBuf key;
	RzStrBuf val;
	rz_strbuf_init(&key);
	rz_strbuf_init(&val);

	sdb_set(analysis->sdb_types,
		rz_strbuf_setf(&key, "type.%s.size", sname),
		rz_strbuf_setf(&val, "%" PFMT64u "", type->size), 0);

	sdb_set(analysis->sdb_types,
		rz_strbuf_setf(&key, "type.%s", sname),
		type->type, 0);

	free(sname);

	rz_strbuf_fini(&key);
	rz_strbuf_fini(&val);
}
static void save_typedef(const RzAnalysis *analysis, const RzAnalysisBaseType *type) {
	rz_return_if_fail(analysis && type && type->name && type->kind == RZ_ANALYSIS_BASE_TYPE_KIND_TYPEDEF);
	/*
		C:
		typedef char byte;
		Sdb:
		byte=typedef
		typedef.byte=char
	*/
	char *sname = rz_str_sanitize_sdb_key(type->name);
	sdb_set(analysis->sdb_types, sname, "typedef", 0);

	RzStrBuf key;
	RzStrBuf val;
	rz_strbuf_init(&key);
	rz_strbuf_init(&val);

	sdb_set(analysis->sdb_types,
		rz_strbuf_setf(&key, "typedef.%s", sname),
		rz_strbuf_setf(&val, "%s", type->type), 0);

	free(sname);

	rz_strbuf_fini(&key);
	rz_strbuf_fini(&val);
}

RZ_API void rz_analysis_base_type_free(RzAnalysisBaseType *type) {
	rz_return_if_fail(type);
	RZ_FREE(type->name);
	RZ_FREE(type->type);

	switch (type->kind) {
	case RZ_ANALYSIS_BASE_TYPE_KIND_STRUCT:
		rz_vector_fini(&type->struct_data.members);
		break;
	case RZ_ANALYSIS_BASE_TYPE_KIND_UNION:
		rz_vector_fini(&type->union_data.members);
		break;
	case RZ_ANALYSIS_BASE_TYPE_KIND_ENUM:
		rz_vector_fini(&type->enum_data.cases);
		break;
	case RZ_ANALYSIS_BASE_TYPE_KIND_TYPEDEF:
	case RZ_ANALYSIS_BASE_TYPE_KIND_ATOMIC:
		break;
	default:
		break;
	}
	RZ_FREE(type);
}

RZ_API RzAnalysisBaseType *rz_analysis_base_type_new(RzAnalysisBaseTypeKind kind) {
	RzAnalysisBaseType *type = RZ_NEW0(RzAnalysisBaseType);
	if (!type) {
		return NULL;
	}
	type->kind = kind;
	switch (type->kind) {
	case RZ_ANALYSIS_BASE_TYPE_KIND_STRUCT:
		rz_vector_init(&type->struct_data.members, sizeof(RzAnalysisStructMember), struct_type_member_free, NULL);
		break;
	case RZ_ANALYSIS_BASE_TYPE_KIND_ENUM:
		rz_vector_init(&type->enum_data.cases, sizeof(RzAnalysisEnumCase), enum_type_case_free, NULL);
		break;
	case RZ_ANALYSIS_BASE_TYPE_KIND_UNION:
		rz_vector_init(&type->union_data.members, sizeof(RzAnalysisUnionMember), union_type_member_free, NULL);
		break;
	default:
		break;
	}

	return type;
}

/**
 * @brief Saves RzAnalysisBaseType into the SDB
 *
 * @param analysis
 * @param type RzAnalysisBaseType to save
 * @param name Name of the type
 */
RZ_API void rz_analysis_save_base_type(const RzAnalysis *analysis, const RzAnalysisBaseType *type) {
	rz_return_if_fail(analysis && type && type->name);

	// TODO, solve collisions, if there are 2 types with the same name and kind

	switch (type->kind) {
	case RZ_ANALYSIS_BASE_TYPE_KIND_STRUCT:
		save_struct(analysis, type);
		break;
	case RZ_ANALYSIS_BASE_TYPE_KIND_ENUM:
		save_enum(analysis, type);
		break;
	case RZ_ANALYSIS_BASE_TYPE_KIND_UNION:
		save_union(analysis, type);
		break;
	case RZ_ANALYSIS_BASE_TYPE_KIND_TYPEDEF:
		save_typedef(analysis, type);
		break;
	case RZ_ANALYSIS_BASE_TYPE_KIND_ATOMIC:
		save_atomic_type(analysis, type);
		break;
	default:
		break;
	}
}
