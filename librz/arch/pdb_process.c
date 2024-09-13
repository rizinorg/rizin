// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_core.h>
#include <rz_type.h>
#include <rz_pdb.h>
#include <rz_analysis.h>
#include "../bin/pdb/pdb.h"

static RzType *pdb_type_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type, char *name);
static RzType *modifier_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type);
static RzType *pointer_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type, char *name);
static RzType *procedure_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type, char *name);
static RzType *array_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type);
static void arglist_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *arglist, RzPVector /*<RzCallableArg *>*/ *vec);
static RzType *mfunction_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info, char *name);
static RzType *onemethod_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info);
static RzType *member_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info, char *name);
static RzType *nest_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *t, char *name);
static RzType *union_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type);
static RzTypeUnionMember *union_member_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info);
static RzType *class_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type);
static RzTypeStructMember *class_member_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *t);
static RzType *enum_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type);
static RzTypeEnumCase *enumerate_parse(RzPdbTpiType *type);
static RzType *pdb_simple_type_parse(const RzTypeDB *typedb, const RzPdbTpiType *type);

static bool is_parsable_type(const RzPdbTpiType *t) {
	const RzPDBTpiKind k = t->kind;
	return k == TpiKind_CLASS ||
		k == TpiKind_UNION ||
		k == TpiKind_ENUM;
}

/**
 * \brief Create a type name from offset
 *
 * \param offset
 * \return char* Name or NULL if error
 */
static char *create_type_name_from_offset(ut64 offset) {
	int offset_length = snprintf(NULL, 0, "type_0x%" PFMT64x, offset);
	char *str = malloc(offset_length + 1);
	snprintf(str, offset_length + 1, "type_0x%" PFMT64x, offset);
	return str;
}

static RzType *pdb_simple_type_parse(const RzTypeDB *typedb, const RzPdbTpiType *type) {
	rz_warn_if_fail(type->kind == TpiKind_SIMPLE_TYPE);
	const Tpi_LF_SimpleType *simple_type = type->data;
	char *error_msg = NULL;
	RzType *typ = rz_type_parse_string_single(typedb->parser, simple_type->type, &error_msg);
	if (error_msg) {
		RZ_LOG_ERROR("%s : Error parsing complex type member \"%s\" type:\n%s\n",
			__FUNCTION__, simple_type->type, error_msg);
		RZ_FREE(error_msg);
	}
	return typ;
}

static RzType *array_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type) {
	rz_return_val_if_fail(type && stream && typedb, NULL);
	Tpi_LF_Array *lf_array = type->data;
	RzPdbTpiType *element = rz_bin_pdb_get_type_by_index(stream, lf_array->element_type);
	if (!element) {
		return NULL;
	}
	RzType *element_type = pdb_type_parse(typedb, stream, element, NULL);
	if (!element_type) {
		return NULL;
	}
	RzType *typ = RZ_NEW0(RzType);
	if (!typ) {
		return NULL;
	}
	typ->kind = RZ_TYPE_KIND_ARRAY;
	typ->array.type = element_type;
	typ->array.count = rz_bin_pdb_get_type_val(type);
	return typ;
}

static RzType *modifier_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type) {
	rz_return_val_if_fail(type && stream && typedb, NULL);
	Tpi_LF_Modifier *lf_modifier = type->data;
	RzPdbTpiType *m_utype = rz_bin_pdb_get_type_by_index(stream, lf_modifier->modified_type);
	if (m_utype) {
		RzType *typ = pdb_type_parse(typedb, stream, m_utype, NULL);
		if (typ && lf_modifier->umodifier.const_) {
			switch (typ->kind) {
			case RZ_TYPE_KIND_IDENTIFIER:
				typ->identifier.is_const = true;
				break;
			case RZ_TYPE_KIND_POINTER:
				typ->pointer.is_const = true;
				break;
			default:
				break;
			}
		}
		return typ;
	}
	return NULL;
}

static RzType *pointer_parse(
	const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type, char *name) {
	rz_return_val_if_fail(type && typedb, NULL);
	Tpi_LF_Pointer *lf_pointer = type->data;
	RzType *typ = RZ_NEW0(RzType);
	if (!typ) {
		goto error;
	}
	typ->kind = RZ_TYPE_KIND_POINTER;
	RzPdbTpiType *p_utype = rz_bin_pdb_get_type_by_index(stream, lf_pointer->utype);
	if (p_utype) {
		RzType *tmp = pdb_type_parse(typedb, stream, p_utype, name);
		if (!tmp) {
			goto error;
		}
		typ->pointer.type = tmp;
		return typ;
	}
error:
	rz_type_free(typ);
	return NULL;
}

static void arglist_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *arglist, RzPVector /*<RzCallableArg *>*/ *vec) {
	rz_return_if_fail(arglist && typedb && vec);
	Tpi_LF_Arglist *lf_arglist = arglist->data;
	ut32 *ptr_types = lf_arglist->arg_type;
	for (int i = 0; i < lf_arglist->count; i++) {
		RzPdbTpiType *stype = rz_bin_pdb_get_type_by_index(stream, *ptr_types++);
		if (!stype) {
			continue;
		}
		RzType *type = pdb_type_parse(typedb, stream, stype, NULL);
		if (!type) {
			continue;
		}
		RzCallableArg *arg = RZ_NEW0(RzCallableArg);
		arg->name = rz_str_newf("arg%d", i);
		arg->type = type;
		rz_pvector_push(vec, arg);
	}
}

static RzType *procedure_parse(
	const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type, char *name) {
	rz_return_val_if_fail(type && stream && typedb, NULL);
	Tpi_LF_Procedure *lf_procedure = type->data;
	RzType *typ = RZ_NEW0(RzType);
	RzCallable *callable = RZ_NEW0(RzCallable);
	if (!typ || !callable) {
		free(typ);
		free(callable);
		return NULL;
	}
	typ->kind = RZ_TYPE_KIND_CALLABLE;
	typ->callable = callable;
	if (!name) {
		typ->callable->name = create_type_name_from_offset(type->index);
	} else {
		typ->callable->name = rz_str_dup(name);
	}

	typ->callable->cc = rz_bin_pdb_calling_convention_as_string(lf_procedure->func_attr.calling_convention);
	// parse return type
	RzPdbTpiType *ret_type = rz_bin_pdb_get_type_by_index(stream, lf_procedure->return_type);
	if (ret_type) {
		typ->callable->ret = pdb_type_parse(typedb, stream, ret_type, name);
		if (!typ->callable->ret) {
			typ->callable->noret = true;
		}
	}
	// parse parameter list
	typ->callable->args = rz_pvector_new((RzPVectorFree)rz_type_callable_arg_free);
	if (!typ->callable->args) {
		rz_type_free(typ);
		return NULL;
	}
	RzPdbTpiType *arglist = rz_bin_pdb_get_type_by_index(stream, lf_procedure->arg_list);
	if (arglist) {
		arglist_parse(typedb, stream, arglist, typ->callable->args);
	}
	rz_type_func_save((RzTypeDB *)typedb, callable);
	return typ;
}

static RzType *mfunction_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info, char *name) {
	rz_return_val_if_fail(type_info && stream && typedb, NULL);
	Tpi_LF_MFcuntion *lf_mfunction = type_info->data;
	RzType *type = RZ_NEW0(RzType);
	RzCallable *callable = RZ_NEW0(RzCallable);
	if (!type || !callable) {
		free(type);
		free(callable);
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_CALLABLE;
	type->callable = callable;
	type->callable->name = rz_str_dup(name);
	type->callable->cc = rz_bin_pdb_calling_convention_as_string(lf_mfunction->func_attr.calling_convention);
	// parse return type
	RzPdbTpiType *ret_type = rz_bin_pdb_get_type_by_index(stream, lf_mfunction->return_type);
	if (ret_type) {
		type->callable->ret = pdb_type_parse(typedb, stream, ret_type, name);
		if (!type->callable->ret) {
			type->callable->noret = true;
		}
	}
	// parse parameter list
	type->callable->args = rz_pvector_new((RzPVectorFree)rz_type_callable_arg_free);
	if (!type->callable->args) {
		rz_type_free(type);
		return NULL;
	}
	RzPdbTpiType *arglist = rz_bin_pdb_get_type_by_index(stream, lf_mfunction->arglist);
	if (arglist) {
		arglist_parse(typedb, stream, arglist, type->callable->args);
	}
	rz_type_func_save((RzTypeDB *)typedb, callable);
	return type;
}

static RzType *onemethod_parse(
	const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info) {
	rz_return_val_if_fail(type_info && typedb, NULL);
	Tpi_LF_OneMethod *lf_onemethod = type_info->data;
	char *name = rz_bin_pdb_get_type_name(type_info);
	RzPdbTpiType *utype = rz_bin_pdb_get_type_by_index(stream, lf_onemethod->index);
	if (!utype) {
		return NULL;
	}
	if (utype->kind == TpiKind_MFUNCTION) {
		return mfunction_parse(typedb, stream, utype, name);
	}
	return NULL;
}

static RzType *member_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info, char *name) {
	rz_return_val_if_fail(type_info && typedb, NULL);
	Tpi_LF_Member *lf_member = type_info->data;

	RzPdbTpiType *utype = rz_bin_pdb_get_type_by_index(stream, lf_member->field_type);
	if (!utype) {
		return NULL;
	}
	return pdb_type_parse(typedb, stream, utype, name);
}

static RzType *static_member_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info, char *name) {
	rz_return_val_if_fail(type_info && typedb, NULL);
	Tpi_LF_StaticMember *lf_stmember = type_info->data;
	RzPdbTpiType *utype = rz_bin_pdb_get_type_by_index(stream, lf_stmember->field_type);
	if (!utype) {
		return NULL;
	}
	return pdb_type_parse(typedb, stream, utype, name);
}

static RzType *type_new_identify(const char *name, RzTypeIdentifierKind k) {
	if (RZ_STR_ISEMPTY(name)) {
		return NULL;
	}
	RzType *t = RZ_NEW0(RzType);
	if (!t) {
		return NULL;
	}
	t->kind = RZ_TYPE_KIND_IDENTIFIER;
	t->identifier.name = rz_str_dup(name);
	t->identifier.kind = k;
	return t;
}

static RzTypeIdentifierKind iKind_from_bKind(RzBaseTypeKind k) {
	switch (k) {
	case RZ_BASE_TYPE_KIND_STRUCT: return RZ_TYPE_IDENTIFIER_KIND_STRUCT;
	case RZ_BASE_TYPE_KIND_UNION: return RZ_TYPE_IDENTIFIER_KIND_UNION;
	case RZ_BASE_TYPE_KIND_ENUM: return RZ_TYPE_IDENTIFIER_KIND_ENUM;
	case RZ_BASE_TYPE_KIND_TYPEDEF:
	case RZ_BASE_TYPE_KIND_ATOMIC: return RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
	}
	return RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
}

static RzType *nest_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info, char *name) {
	rz_return_val_if_fail(type_info && stream && typedb, NULL);
	Tpi_LF_NestType *lf_nest = type_info->data;
	RzPdbTpiType *utpi = rz_bin_pdb_get_type_by_index(stream, lf_nest->index);
	if (!utpi) {
		return NULL;
	}
	const char *uname = rz_bin_pdb_get_type_name(utpi);
	if (uname) {
		const RzBaseType *bt = rz_type_db_get_base_type(typedb, uname);
		if (bt) {
			return type_new_identify(bt->name, iKind_from_bKind(bt->kind));
		}
	}

	RzType *utype = pdb_type_parse(typedb, stream, utpi, NULL);
	if (!utype) {
		return NULL;
	}
	return rz_type_clone(utype);
}

/**
 * \brief Parses struct member
 *
 * \param typedb Types DB instance
 * \param stream TPI Stream
 * \param t Current RzPdbTpiType (member)
 * \return RzTypeStructMember* parsed member, NULL if fail
 */
static RzTypeStructMember *class_member_parse(
	const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *t) {
	rz_return_val_if_fail(t, NULL);
	char *name = NULL;
	ut64 offset = 0;
	RzType *type = NULL;
	switch (t->kind) {
	case TpiKind_ONEMETHOD: {
		name = rz_bin_pdb_get_type_name(t);
		type = onemethod_parse(typedb, stream, t);
		break;
	}
	case TpiKind_MEMBER: {
		offset = rz_bin_pdb_get_type_val(t);
		name = rz_bin_pdb_get_type_name(t);
		type = member_parse(typedb, stream, t, name);
		break;
	}
	case TpiKind_STMEMBER: {
		name = rz_bin_pdb_get_type_name(t);
		type = static_member_parse(typedb, stream, t, name);
		break;
	}
	case TpiKind_NESTTYPE: {
		name = rz_bin_pdb_get_type_name(t);
		type = nest_parse(typedb, stream, t, rz_str_dup(name));
		break;
	}
	case TpiKind_VBCLASS:
	case TpiKind_BCLASS:
		// For structure, we don't need base class for now
		goto cleanup;
	case TpiKind_METHOD:
		// TODO: need to handle overloaded methods here
		goto cleanup;
	case TpiKind_VFUNCTAB:
		// For structure, we don't need vtable for now
		goto cleanup;
	default:
		rz_warn_if_reached();
		RZ_LOG_ERROR("%s : unsupported leaf type 0x%x\n", __FUNCTION__, t->leaf);
		goto cleanup;
	}
	if (!type) {
		RZ_LOG_INFO("%s : couldn't parse structure member type!\n", __FUNCTION__);
		return NULL;
	}

	RzTypeStructMember *member = RZ_NEW0(RzTypeStructMember);
	if (!member) {
		goto cleanup;
	}
	member->name = rz_str_dup(name);
	member->type = type;
	member->offset = offset;
	return member;
cleanup:
	rz_type_free(type);
	return NULL;
}

static inline bool is_tpitype_unnamed(const char *name) {
	return !name || !strcmp(name, "<unnamed-tag>") || !strcmp(name, "<anonymous-tag>");
}

static inline RzBaseType *get_tpitype_basetype(const RzTypeDB *typedb, RzPdbTpiType *type, const char *name) {
	RzBaseType *base_type;
	if (is_tpitype_unnamed(name)) {
		char *tmp_name = create_type_name_from_offset(type->index);
		base_type = rz_type_db_get_base_type(typedb, tmp_name);
		free(tmp_name);
	} else {
		base_type = rz_type_db_get_base_type(typedb, name);
	}
	return base_type;
}

static RzType *create_rztype(RzPdbTpiType *type, RzTypeIdentifierKind kind, const char *name) {
	RzType *t = RZ_NEW0(RzType);
	if (!t) {
		return NULL;
	}
	t->kind = RZ_TYPE_KIND_IDENTIFIER;
	t->identifier.kind = kind;
	t->identifier.name = is_tpitype_unnamed(name) ? create_type_name_from_offset(type->index) : rz_str_dup(name);
	return t;
}

#define PDB_PROCESS_LF_INDEX \
	if (member_info->kind == TpiKind_INDEX) { \
		ut32 index = rz_bin_pdb_get_type_val(member_info); \
		if (index == type->index) { \
			break; \
		} \
		RzPdbTpiType *t = rz_bin_pdb_get_type_by_index(stream, index); \
		if (!t) { \
			continue; \
		} \
		RzPVector *t_members = rz_bin_pdb_get_type_members(stream, t); \
		if (!t_members) { \
			continue; \
		} \
		members = t_members; \
		goto foreach_members; \
	}

/**
 * \brief Parses structures into BaseType and saves them into hashtable
 *
 * \param t RzTypeDB instance
 * \param stream TPI Stream
 * \param type Current type
 */
static RzType *class_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type) {
	rz_return_val_if_fail(typedb && stream && type, NULL);

	RzBaseType *base_type = NULL;
	char *name = rz_bin_pdb_get_type_name(type);
	if (name) {
		base_type = get_tpitype_basetype(typedb, type, name);
		if (base_type) {
			if (base_type->kind != RZ_BASE_TYPE_KIND_STRUCT) {
				RZ_LOG_WARN("PDB: Type of %s (struct) conflicts with already defined type (%s), redefining it.\n",
					name, rz_type_base_type_kind_as_string(base_type->kind));
				rz_type_db_delete_base_type((RzTypeDB *)typedb, base_type);
				base_type = NULL;
			} else if (type->parsed || rz_bin_pdb_type_is_fwdref(type)) {
				return base_type->type ? rz_type_clone(base_type->type) : create_rztype(type, RZ_TYPE_IDENTIFIER_KIND_STRUCT, name);
			} else if (base_type->attrs != RZ_TYPE_TYPECLASS_INVALID) {
				RZ_LOG_INFO("%s : Redefining type %s.\n", __FUNCTION__, name);
			}
		}
	}

	if (!base_type) {
		base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_STRUCT);
		if (!base_type) {
			return NULL;
		}

		RzType *typ = create_rztype(type, RZ_TYPE_IDENTIFIER_KIND_STRUCT, name);
		if (!typ) {
			rz_type_base_type_free(base_type);
			return NULL;
		}
		base_type->type = typ;
		base_type->name = rz_str_dup(typ->identifier.name);
		base_type->attrs = RZ_TYPE_TYPECLASS_INVALID;
		if (!rz_type_db_save_base_type(typedb, base_type)) {
			return NULL;
		}

		if (rz_bin_pdb_type_is_fwdref(type)) {
			return rz_type_clone(base_type->type);
		}
	}
	rz_vector_clear(&base_type->struct_data.members);
	RzPVector *members = rz_bin_pdb_get_type_members(stream, type);
	void **it;
foreach_members:
	rz_pvector_foreach (members, it) {
		RzPdbTpiType *member_info = *it;
		PDB_PROCESS_LF_INDEX;
		RzTypeStructMember *struct_member = class_member_parse(typedb, stream, member_info);
		if (!struct_member) {
			continue; // skip the failure
		}
		void *element = rz_vector_push(&base_type->struct_data.members, struct_member);
		if (!element) {
			rz_warn_if_reached();
			rz_type_base_struct_member_free(struct_member, NULL);
			return NULL;
		}
		free(struct_member);
	}
	base_type->size = rz_bin_pdb_get_type_val(type);
	if (base_type->attrs == RZ_TYPE_TYPECLASS_INVALID) {
		base_type->attrs = RZ_TYPE_TYPECLASS_NONE;
		rz_list_append(stream->print_type, base_type);
	}
	type->parsed = true;
	return base_type->type ? rz_type_clone(base_type->type) : NULL;
}

/**
 * \brief Parses union member
 *
 * \param typedb Types DB instance
 * \param stream TPI Stream
 * \param type_info Current RzPdbTpiType (member)
 * \return RzTypeUnionMember* parsed member, NULL if fail
 */
static RzTypeUnionMember *union_member_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info) {
	rz_return_val_if_fail(type_info && stream && typedb, NULL);
	char *name = NULL;
	ut64 offset = 0;
	RzType *type = NULL;
	switch (type_info->kind) {
	case TpiKind_ONEMETHOD: {
		name = rz_bin_pdb_get_type_name(type_info);
		type = onemethod_parse(typedb, stream, type_info);
		break;
	}
	case TpiKind_MEMBER: {
		offset = rz_bin_pdb_get_type_val(type_info);
		name = rz_bin_pdb_get_type_name(type_info);
		type = member_parse(typedb, stream, type_info, name);
		break;
	}
	case TpiKind_NESTTYPE: {
		name = rz_bin_pdb_get_type_name(type_info);
		type = nest_parse(typedb, stream, type_info, rz_str_dup(name));
		break;
	}
	default:
		rz_warn_if_reached();
		RZ_LOG_ERROR("%s : unsupported leaf type 0x%x\n", __FUNCTION__, type_info->leaf);
		goto cleanup;
	}
	if (!type) {
		RZ_LOG_INFO("%s : couldn't parse union member type!\n", __FUNCTION__);
		return NULL;
	}

	RzTypeUnionMember *member = RZ_NEW0(RzTypeUnionMember);
	if (!member) {
		goto cleanup;
	}
	member->name = rz_str_dup(name);
	member->type = type;
	member->offset = offset;
	return member;
cleanup:
	rz_type_free(type);
	return NULL;
}

/**
 * \brief Parses union into BaseType and saves it into hashtable
 * \param typedb Types DB instance
 * \param stream TPI Stream
 * \param type_info Current RzPdbTpiType (enum case)
 */
static RzType *union_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type) {
	rz_return_val_if_fail(typedb && stream && type, NULL);

	RzBaseType *base_type = NULL;
	char *name = rz_bin_pdb_get_type_name(type);
	if (name) {
		base_type = get_tpitype_basetype(typedb, type, name);
		if (base_type) {
			if (base_type->kind != RZ_BASE_TYPE_KIND_UNION) {
				RZ_LOG_WARN("PDB: Type of %s (union) conflicts with already defined type (%s), redefining it.\n",
					name, rz_type_base_type_kind_as_string(base_type->kind));
				rz_type_db_delete_base_type((RzTypeDB *)typedb, base_type);
				base_type = NULL;
			} else if (type->parsed || rz_bin_pdb_type_is_fwdref(type)) {
				return base_type->type ? rz_type_clone(base_type->type) : create_rztype(type, RZ_TYPE_IDENTIFIER_KIND_UNION, name);
			} else if (base_type->attrs != RZ_TYPE_TYPECLASS_INVALID) {
				RZ_LOG_INFO("%s : Redefining type %s.\n", __FUNCTION__, name);
			}
		}
	}

	if (!base_type) {
		base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_UNION);
		if (!base_type) {
			return NULL;
		}

		RzType *typ = create_rztype(type, RZ_TYPE_IDENTIFIER_KIND_UNION, name);
		if (!typ) {
			rz_type_base_type_free(base_type);
			return NULL;
		}
		base_type->type = typ;
		base_type->name = rz_str_dup(typ->identifier.name);
		base_type->attrs = RZ_TYPE_TYPECLASS_INVALID;
		if (!rz_type_db_save_base_type(typedb, base_type)) {
			return NULL;
		}

		if (rz_bin_pdb_type_is_fwdref(type)) {
			return rz_type_clone(base_type->type);
		}
	}
	rz_vector_clear(&base_type->union_data.members);
	RzPVector *members = rz_bin_pdb_get_type_members(stream, type);
	void **it;
foreach_members:
	rz_pvector_foreach (members, it) {
		RzPdbTpiType *member_info = *it;
		PDB_PROCESS_LF_INDEX;
		RzTypeUnionMember *union_member = union_member_parse(typedb, stream, member_info);
		if (!union_member) {
			continue; // skip the failure
		}
		void *element = rz_vector_push(&base_type->union_data.members, union_member);
		if (!element) {
			rz_type_base_union_member_free(union_member, NULL);
			return NULL;
		}
		free(union_member);
	}
	base_type->size = rz_bin_pdb_get_type_val(type);
	if (base_type->attrs == RZ_TYPE_TYPECLASS_INVALID) {
		base_type->attrs = RZ_TYPE_TYPECLASS_NONE;
		rz_list_append(stream->print_type, base_type);
	}
	type->parsed = true;
	return base_type->type ? rz_type_clone(base_type->type) : NULL;
}

/**
 * \brief Parse enum case
 * \param type Current type info (enum case)
 * \return RzTypeEnumCase* parsed enum case, NULL if fail
 */
static RzTypeEnumCase *enumerate_parse(RzPdbTpiType *type) {
	rz_return_val_if_fail(type && type->kind == TpiKind_ENUMERATE, NULL);

	// sometimes, the type doesn't have get_val for some reason
	ut64 value = rz_bin_pdb_get_type_val(type);
	char *name = rz_bin_pdb_get_type_name(type);
	RzTypeEnumCase *cas = RZ_NEW0(RzTypeEnumCase);
	if (!cas) {
		goto cleanup;
	}
	cas->name = rz_str_dup(name);
	cas->val = value;
	return cas;
cleanup:
	return NULL;
}

/**
 * \brief Parses enum into BaseType and saves it into SDB
 *
 * \param t RzTypeDB instance
 * \param stream TPI Stream
 * \param type Current type
 */
static RzType *enum_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type) {
	rz_return_val_if_fail(typedb && type, NULL);
	Tpi_LF_Enum *lf_enum = type->data;
	// assert all member functions we need info from
	RzBaseType *base_type = NULL;
	char *name = rz_bin_pdb_get_type_name(type);
	if (name) {
		base_type = get_tpitype_basetype(typedb, type, name);
		if (base_type) {
			if (base_type->kind != RZ_BASE_TYPE_KIND_ENUM) {
				RZ_LOG_WARN("PDB: Type of %s (enum) conflicts with already defined type (%s), redefining it.\n",
					name, rz_type_base_type_kind_as_string(base_type->kind));
				rz_type_db_delete_base_type((RzTypeDB *)typedb, base_type);
				base_type = NULL;
			} else if (type->parsed || rz_bin_pdb_type_is_fwdref(type)) {
				return base_type->type ? rz_type_clone(base_type->type) : NULL;
			} else if (base_type->attrs != RZ_TYPE_TYPECLASS_INVALID) {
				RZ_LOG_INFO("%s : Redefining type %s.\n", __FUNCTION__, name);
			}
		}
	}

	if (!base_type) {
		base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ENUM);
		if (!base_type) {
			return NULL;
		}

		RzPdbTpiType *utype = rz_bin_pdb_get_type_by_index(stream, lf_enum->utype);
		if (!utype) {
			rz_type_base_type_free(base_type);
			return NULL;
		}
		RzType *btype = pdb_type_parse(typedb, stream, utype, NULL);
		if (!btype) {
			rz_type_base_type_free(base_type);
			return NULL;
		}
		base_type->name = is_tpitype_unnamed(name) ? create_type_name_from_offset(type->index) : rz_str_dup(name);
		base_type->size = rz_type_db_get_bitsize(typedb, btype);
		base_type->type = btype;
		base_type->attrs = RZ_TYPE_TYPECLASS_INVALID;
		if (!rz_type_db_save_base_type(typedb, base_type)) {
			return NULL;
		}

		if (rz_bin_pdb_type_is_fwdref(type)) {
			return rz_type_clone(base_type->type);
		}
	}
	rz_vector_clear(&base_type->enum_data.cases);
	RzPVector *members = rz_bin_pdb_get_type_members(stream, type);
	void **it;
foreach_members:
	rz_pvector_foreach (members, it) {
		RzPdbTpiType *member_info = *it;
		PDB_PROCESS_LF_INDEX;
		RzTypeEnumCase *enum_case = enumerate_parse(member_info);
		if (!enum_case) {
			continue; // skip it, move forward
		}
		void *element = rz_vector_push(&base_type->enum_data.cases, enum_case);
		if (!element) {
			rz_type_base_enum_case_free(enum_case, NULL);
			return NULL;
		}
		free(enum_case);
	}
	if (base_type->attrs == RZ_TYPE_TYPECLASS_INVALID) {
		base_type->attrs = RZ_TYPE_TYPECLASS_NONE;
		rz_list_append(stream->print_type, base_type);
	}
	type->parsed = true;
	return base_type->type ? rz_type_clone(base_type->type) : NULL;
}

static RzType *pdb_type_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type, char *name) {
	switch (type->kind) {
	case TpiKind_SIMPLE_TYPE:
		return pdb_simple_type_parse(typedb, type);
	case TpiKind_CLASS:
		return class_parse(typedb, stream, type);
	case TpiKind_UNION:
		return union_parse(typedb, stream, type);
	case TpiKind_ENUM:
		return enum_parse(typedb, stream, type);
	case TpiKind_MODIFIER:
		return modifier_parse(typedb, stream, type);
	case TpiKind_ARRAY:
		return array_parse(typedb, stream, type);
	case TpiKind_POINTER:
		return pointer_parse(typedb, stream, type, name);
	case TpiKind_PROCEDURE:
		return procedure_parse(typedb, stream, type, name);
	case TpiKind_MFUNCTION:
		return mfunction_parse(typedb, stream, type, name);
	case TpiKind_BITFIELD:
	case TpiKind_BCLASS:
	case TpiKind_FILEDLIST:
	case TpiKind_ENUMERATE:
	case TpiKind_ARGLIST:
	case TpiKind_METHODLIST:
	case TpiKind_VTSHAPE:
	case TpiKind_VFTABLE:
	case TpiKind_LABEL:
	case TpiKind_NESTTYPE:
	case TpiKind_MEMBER:
	case TpiKind_METHOD:
	case TpiKind_ONEMETHOD:
	case TpiKind_VFUNCTAB:
	case TpiKind_STMEMBER:
	case TpiKind_VBCLASS:
	case TpiKind_INDEX:
		return NULL;
	default:
		rz_warn_if_reached();
		RZ_LOG_DEBUG("Unknown type record: #0x%" PFMT32x ": leaf=0x%" PFMT32x "\n",
			type->index, type->leaf);
		break;
	}
	return NULL;
}

/**
 * \brief Delegate the type parsing to appropriate function
 *
 * \param t RzTypeDB instance
 * \param stream TPI Stream
 * \param type Current type
 */
RZ_API RzType *rz_type_db_pdb_parse(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type) {
	rz_return_val_if_fail(typedb && type, NULL);
	return pdb_type_parse(typedb, stream, type, NULL);
}

/**
 * \brief Saves PDB types from TPI stream into the type database
 *
 * \param t RzTypeDB instance
 * \param pdb PDB instance
 */
RZ_API void rz_type_db_pdb_load(const RzTypeDB *typedb, const RzPdb *pdb) {
	rz_return_if_fail(typedb && pdb);
	RzPdbTpiStream *stream = pdb->s_tpi;
	if (!stream) { // no TPI stream found
		return;
	}

	stream->print_type = rz_list_new();
	if (!stream->print_type) {
		return;
	}

	RBIter it;
	RzPdbTpiType *type;
	rz_rbtree_foreach (stream->types, it, type, RzPdbTpiType, rb) {
		if (type && is_parsable_type(type)) {
			rz_type_db_pdb_parse(typedb, stream, type);
		}
	}
}
