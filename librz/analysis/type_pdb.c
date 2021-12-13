// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_core.h>
#include <rz_type.h>
#include <rz_pdb.h>
#include <rz_analysis.h>
#include "../bin/pdb/pdb.h"

static RzType *parse_type(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type, char *name);
static RzType *parse_regular_type(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type, char *name);
static RzType *parse_type_modifier(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type);
static RzType *parse_type_pointer(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type, char *name);
static RzType *parse_type_procedure(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type, char *name);
static RzType *parse_type_array(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type);
static void parse_type_arglist(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *arglist, RzPVector *vec);
static RzType *parse_type_mfunction(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info, char *name);
static RzType *parse_type_onemethod(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info);
static RzType *parse_type_member(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info, char *name);
static RzType *parse_type_nest(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info);
static RzType *parse_union(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type);
static RzTypeUnionMember *parse_union_member(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info);
static RzType *parse_structure(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type);
static RzTypeStructMember *parse_struct_member(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info);
static RzType *parse_enum(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type);
static RzTypeEnumCase *parse_enumerate(RzPdbTpiType *type);

static bool is_parsable_type(const TpiLeafType type) {
	rz_return_val_if_fail(type, false);
	return (type == LF_STRUCTURE ||
		type == LF_UNION ||
		type == LF_ENUM ||
		type == LF_CLASS ||
		type == LF_CLASS_19 ||
		type == LF_STRUCTURE_19);
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

static RzType *parse_type_array(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type) {
	rz_return_val_if_fail(type && stream && typedb, NULL);
	Tpi_LF_Array *lf_array = type->type_data;
	RzPdbTpiType *element = rz_bin_pdb_get_type_by_index(stream, lf_array->element_type);
	if (!element) {
		return NULL;
	}
	RzType *element_type = parse_type(typedb, stream, element, NULL);
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

static RzType *parse_regular_type(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type, char *name) {
	rz_return_val_if_fail(type && stream && typedb, NULL);
	switch (type->leaf_type) {
	case LF_CLASS:
	case LF_CLASS_19:
		// TODO: https://github.com/rizinorg/rizin/issues/1205
		RZ_LOG_INFO("%s : LF_CLASS is not handled for now.\n", __FUNCTION__);
		break;
	case LF_STRUCTURE:
	case LF_STRUCTURE_19:
		return parse_structure(typedb, stream, type);
	case LF_MODIFIER:
		return parse_type_modifier(typedb, stream, type);
	case LF_ARRAY:
		return parse_type_array(typedb, stream, type);
	case LF_BITFIELD:
		// TODO: we don't have BITFIELD type for now https://github.com/rizinorg/rizin/issues/1240
		RZ_LOG_INFO("%s : LF_BITFIELD is not handled for now.\n", __FUNCTION__);
		break;
	case LF_POINTER:
		return parse_type_pointer(typedb, stream, type, name);
	case LF_PROCEDURE:
		return parse_type_procedure(typedb, stream, type, name);
	case LF_UNION:
		return parse_union(typedb, stream, type);
	case LF_ENUM:
		return parse_enum(typedb, stream, type);
	default:
		RZ_LOG_INFO("%s : unsupported leaf type 0x%x\n", __FUNCTION__, type->leaf_type);
		break;
	}
	return NULL;
}

static RzType *parse_type_modifier(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type) {
	rz_return_val_if_fail(type && stream && typedb, NULL);
	Tpi_LF_Modifier *lf_modifier = type->type_data;
	RzPdbTpiType *m_utype = rz_bin_pdb_get_type_by_index(stream, lf_modifier->modified_type);
	if (m_utype) {
		RzType *typ = parse_type(typedb, stream, m_utype, NULL);
		if (typ && lf_modifier->umodifier.bits.const_) {
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

static RzType *parse_type_pointer(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type, char *name) {
	rz_return_val_if_fail(type && typedb, NULL);
	Tpi_LF_Pointer *lf_pointer = type->type_data;
	RzType *typ = RZ_NEW0(RzType);
	if (!typ) {
		goto error;
	}
	typ->kind = RZ_TYPE_KIND_POINTER;
	RzPdbTpiType *p_utype = rz_bin_pdb_get_type_by_index(stream, lf_pointer->utype);
	if (p_utype) {
		RzType *tmp = parse_type(typedb, stream, p_utype, name);
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

static RzType *parse_type(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type, char *name) {
	rz_return_val_if_fail(type && typedb, NULL);
	RzType *typ;
	if (type->leaf_type == LF_SIMPLE_TYPE) {
		Tpi_LF_SimpleType *simple_type = type->type_data;
		char *error_msg = NULL;
		typ = rz_type_parse_string_single(typedb->parser, simple_type->type, &error_msg);
		if (error_msg) {
			eprintf("%s : Error parsing complex type member \"%s\" type:\n%s\n", __FUNCTION__, simple_type->type, error_msg);
			RZ_FREE(error_msg);
		}
		return typ;
	} else {
		if (type->leaf_type == LF_POINTER) {
			return parse_type_pointer(typedb, stream, type, name);
		} else {
			return parse_regular_type(typedb, stream, type, name);
		}
	}
}

static void parse_type_arglist(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *arglist, RzPVector *vec) {
	rz_return_if_fail(arglist && typedb && vec);
	Tpi_LF_Arglist *lf_arglist = arglist->type_data;
	if (!vec) {
		return;
	}
	ut32 *ptr_types = lf_arglist->arg_type;
	for (int i = 0; i < lf_arglist->count; i++) {
		RzPdbTpiType *stype = rz_bin_pdb_get_type_by_index(stream, *ptr_types++);
		if (!stype) {
			continue;
		}
		RzType *type = parse_type(typedb, stream, stype, NULL);
		if (!type) {
			continue;
		}
		RzCallableArg *arg = RZ_NEW0(RzCallableArg);
		arg->name = rz_str_newf("arg%d", i);
		arg->type = type;
		rz_pvector_push(vec, arg);
	}
}

static RzType *parse_type_procedure(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type, char *name) {
	rz_return_val_if_fail(type && stream && typedb, NULL);
	Tpi_LF_Procedure *lf_procedure = type->type_data;
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
		typ->callable->name = create_type_name_from_offset(type->type_index);
	} else {
		typ->callable->name = strdup(name);
	}

	typ->callable->cc = rz_bin_pdb_calling_convention_as_string(lf_procedure->call_conv);
	// parse return type
	RzPdbTpiType *ret_type = rz_bin_pdb_get_type_by_index(stream, lf_procedure->return_type);
	if (ret_type) {
		typ->callable->ret = parse_type(typedb, stream, ret_type, name);
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
		parse_type_arglist(typedb, stream, arglist, typ->callable->args);
	}
	rz_type_func_save((RzTypeDB *)typedb, callable);
	return typ;
}

static RzType *parse_type_mfunction(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info, char *name) {
	rz_return_val_if_fail(type_info && stream && typedb, NULL);
	Tpi_LF_MFcuntion *lf_mfunction = type_info->type_data;
	RzType *type = RZ_NEW0(RzType);
	RzCallable *callable = RZ_NEW0(RzCallable);
	if (!type || !callable) {
		free(type);
		free(callable);
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_CALLABLE;
	type->callable = callable;
	type->callable->name = strdup(name);
	type->callable->cc = rz_bin_pdb_calling_convention_as_string(lf_mfunction->call_conv);
	// parse return type
	RzPdbTpiType *ret_type = rz_bin_pdb_get_type_by_index(stream, lf_mfunction->return_type);
	if (ret_type) {
		type->callable->ret = parse_type(typedb, stream, ret_type, name);
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
		parse_type_arglist(typedb, stream, arglist, type->callable->args);
	}
	rz_type_func_save((RzTypeDB *)typedb, callable);
	return type;
}

static RzType *parse_type_onemethod(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info) {
	rz_return_val_if_fail(type_info && typedb, NULL);
	Tpi_LF_OneMethod *lf_onemethod = type_info->type_data;
	char *name = rz_bin_pdb_get_type_name(type_info);
	RzPdbTpiType *utype = rz_bin_pdb_get_type_by_index(stream, lf_onemethod->index);
	if (!utype) {
		return NULL;
	}
	if (utype->leaf_type == LF_MFUNCTION) {
		return parse_type_mfunction(typedb, stream, utype, name);
	}
	return NULL;
}

static RzType *parse_type_member(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info, char *name) {
	rz_return_val_if_fail(type_info && typedb, NULL);
	Tpi_LF_Member *lf_member = type_info->type_data;

	RzPdbTpiType *utype = rz_bin_pdb_get_type_by_index(stream, lf_member->index);
	if (!utype) {
		return NULL;
	}
	return parse_type(typedb, stream, utype, name);
}

static RzType *parse_type_static_member(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info, char *name) {
	rz_return_val_if_fail(type_info && typedb, NULL);
	Tpi_LF_StaticMember *lf_stmember = type_info->type_data;
	RzPdbTpiType *utype = rz_bin_pdb_get_type_by_index(stream, lf_stmember->index);
	if (!utype) {
		return NULL;
	}
	return parse_type(typedb, stream, utype, name);
}

static RzType *parse_type_nest(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info) {
	rz_return_val_if_fail(type_info && stream && typedb, NULL);
	Tpi_LF_NestType *lf_nest = type_info->type_data;
	RzPdbTpiType *utype = rz_bin_pdb_get_type_by_index(stream, lf_nest->index);
	if (!utype) {
		return NULL;
	}
	char *name = rz_bin_pdb_get_type_name(utype);
	if (name) {
		RzBaseType *b_type = rz_type_db_get_base_type(typedb, name);
		if (b_type && b_type->type) {
			if (b_type->type->kind == RZ_TYPE_KIND_IDENTIFIER) {
				return rz_type_clone(b_type->type);
			}
		}
		return NULL;
	}

	RzType *n_type = parse_type(typedb, stream, utype, NULL);
	if (!n_type) {
		return NULL;
	}
	RzBaseType *btype = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
	if (!btype) {
		return NULL;
	}
	btype->name = create_type_name_from_offset(lf_nest->index);
	btype->type = n_type;
	rz_type_db_save_base_type(typedb, btype);
	if (n_type->kind == RZ_TYPE_KIND_IDENTIFIER) {
		return rz_type_clone(n_type);
	}
	return NULL;
}

/**
 * \brief Parses struct member
 *
 * \param typedb Types DB instance
 * \param stream TPI Stream
 * \param type_info Current RzPdbTpiType (member)
 * \return RzTypeStructMember* parsed member, NULL if fail
 */
static RzTypeStructMember *parse_struct_member(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info) {
	rz_return_val_if_fail(type_info, NULL);
	char *name = NULL;
	ut64 offset = 0;
	RzType *type = NULL;
	switch (type_info->leaf_type) {
	case LF_ONEMETHOD: {
		name = rz_bin_pdb_get_type_name(type_info);
		type = parse_type_onemethod(typedb, stream, type_info);
		break;
	}
	case LF_MEMBER: {
		offset = rz_bin_pdb_get_type_val(type_info);
		name = rz_bin_pdb_get_type_name(type_info);
		type = parse_type_member(typedb, stream, type_info, name);
		break;
	}
	case LF_STMEMBER: {
		name = rz_bin_pdb_get_type_name(type_info);
		type = parse_type_static_member(typedb, stream, type_info, name);
		break;
	}
	case LF_NESTTYPE: {
		name = rz_bin_pdb_get_type_name(type_info);
		type = parse_type_nest(typedb, stream, type_info);
		break;
	}
	case LF_BCLASS:
		// For structure, we don't need base class for now
		goto cleanup;
	case LF_METHOD:
		// TODO: need to handle overloaded methods here
		goto cleanup;
	case LF_VFUNCTAB:
		// For structure, we don't need vtable for now
		goto cleanup;
	default:
		eprintf("%s : unsupported leaf type 0x%x\n", __FUNCTION__, type_info->leaf_type);
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
	member->name = strdup(name);
	member->type = type;
	member->offset = offset;
	return member;
cleanup:
	rz_type_free(type);
	return NULL;
}

/**
 * \brief Parses structures into BaseType and saves them into hashtable
 *
 * \param t RzTypeDB instance
 * \param stream TPI Stream
 * \param type Current type
 */
static RzType *parse_structure(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type) {
	rz_return_val_if_fail(typedb && stream && type, NULL);

	if (rz_bin_pdb_type_is_fwdref(type)) {
		return NULL;
	}
	RzBaseType *base_type;
	char *name = rz_bin_pdb_get_type_name(type);
	if (name) {
		base_type = rz_type_db_get_base_type(typedb, name);
		if (base_type && base_type->type) {
			return rz_type_clone(base_type->type);
		}
	}

	base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_STRUCT);
	if (!base_type) {
		return NULL;
	}
	bool to_free_name = false;
	if (!name) {
		name = create_type_name_from_offset(type->type_index);
		to_free_name = true;
	}
	RzType *typ = RZ_NEW0(RzType);
	if (!typ) {
		rz_type_base_type_free(base_type);
		base_type = NULL;
		goto cleanup;
	}
	typ->kind = RZ_TYPE_KIND_IDENTIFIER;
	typ->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_STRUCT;
	typ->identifier.name = strdup(name);
	base_type->type = typ;
	ut64 size = rz_bin_pdb_get_type_val(type);

	RzList *members = rz_bin_pdb_get_type_members(stream, type);
	if (!members) {
		rz_type_base_type_free(base_type);
		base_type = NULL;
		goto cleanup;
	}
	RzListIter *it;
	RzPdbTpiType *member_info;
	rz_list_foreach (members, it, member_info) {
		RzTypeStructMember *struct_member = parse_struct_member(typedb, stream, member_info);
		if (!struct_member) {
			continue; // skip the failure
		}
		void *element = rz_vector_push(&base_type->struct_data.members, struct_member);
		if (!element) {
			rz_type_base_struct_member_free(struct_member, NULL);
			rz_type_base_type_free(base_type);
			base_type = NULL;
			goto cleanup;
		}
	}
	base_type->name = strdup(name);
	base_type->size = size;
	rz_type_db_save_base_type(typedb, base_type);
	rz_list_append(stream->print_type, base_type);
cleanup:
	if (to_free_name) {
		RZ_FREE(name);
	}
	return base_type ? base_type->type : NULL;
}

/**
 * \brief Parses union member
 *
 * \param typedb Types DB instance
 * \param stream TPI Stream
 * \param type_info Current RzPdbTpiType (member)
 * \return RzTypeUnionMember* parsed member, NULL if fail
 */
static RzTypeUnionMember *parse_union_member(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type_info) {
	rz_return_val_if_fail(type_info && stream && typedb, NULL);
	char *name = NULL;
	ut64 offset = 0;
	RzType *type = NULL;
	switch (type_info->leaf_type) {
	case LF_ONEMETHOD: {
		name = rz_bin_pdb_get_type_name(type_info);
		type = parse_type_onemethod(typedb, stream, type_info);
		break;
	}
	case LF_MEMBER: {
		offset = rz_bin_pdb_get_type_val(type_info);
		name = rz_bin_pdb_get_type_name(type_info);
		type = parse_type_member(typedb, stream, type_info, name);
		break;
	}
	case LF_NESTTYPE: {
		name = rz_bin_pdb_get_type_name(type_info);
		type = parse_type_nest(typedb, stream, type_info);
		break;
	}
	default:
		eprintf("%s : unsupported leaf type 0x%x\n", __FUNCTION__, type_info->leaf_type);
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
	member->name = strdup(name);
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
static RzType *parse_union(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type) {
	rz_return_val_if_fail(typedb && stream && type, NULL);
	if (rz_bin_pdb_type_is_fwdref(type)) {
		return NULL;
	}

	RzBaseType *base_type;
	char *name = rz_bin_pdb_get_type_name(type);
	if (name) {
		base_type = rz_type_db_get_base_type(typedb, name);
		if (base_type && base_type->type) {
			return rz_type_clone(base_type->type);
		}
	}

	base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_UNION);
	if (!base_type) {
		free(name);
		return NULL;
	}
	bool to_free_name = false;
	if (!name) {
		name = create_type_name_from_offset(type->type_index);
		to_free_name = true;
	}
	RzType *typ = RZ_NEW0(RzType);
	if (!typ) {
		rz_type_base_type_free(base_type);
		base_type = NULL;
		goto cleanup;
	}
	typ->kind = RZ_TYPE_KIND_IDENTIFIER;
	typ->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNION;
	typ->identifier.name = strdup(name);
	base_type->type = typ;

	RzList *members = rz_bin_pdb_get_type_members(stream, type);
	if (!members) {
		rz_type_base_type_free(base_type);
		base_type = NULL;
		goto cleanup;
	}
	RzListIter *it;
	RzPdbTpiType *member_info;
	rz_list_foreach (members, it, member_info) {
		RzTypeUnionMember *union_member = parse_union_member(typedb, stream, member_info);
		if (!union_member) {
			continue; // skip the failure
		}
		void *element = rz_vector_push(&base_type->union_data.members, union_member);
		if (!element) {
			rz_type_base_union_member_free(union_member, NULL);
			rz_type_base_type_free(base_type);
			base_type = NULL;
			goto cleanup;
		}
	}
	base_type->name = strdup(name);
	ut64 size = rz_bin_pdb_get_type_val(type);
	base_type->size = size;
	rz_type_db_save_base_type(typedb, base_type);
	rz_list_append(stream->print_type, base_type);
cleanup:
	if (to_free_name) {
		RZ_FREE(name);
	}
	return base_type ? base_type->type : NULL;
}

/**
 * \brief Parse enum case
 * \param type_info Current type info (enum case)
 * \return RzTypeEnumCase* parsed enum case, NULL if fail
 */
static RzTypeEnumCase *parse_enumerate(RzPdbTpiType *type) {
	rz_return_val_if_fail(type && type->leaf_type == LF_ENUMERATE, NULL);

	char *name = NULL;
	ut64 value = 0;
	// sometimes, the type doesn't have get_val for some reason
	value = rz_bin_pdb_get_type_val(type);
	name = rz_bin_pdb_get_type_name(type);
	RzTypeEnumCase *cas = RZ_NEW0(RzTypeEnumCase);
	if (!cas) {
		goto cleanup;
	}
	cas->name = strdup(name);
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
static RzType *parse_enum(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type) {
	rz_return_val_if_fail(typedb && type, NULL);
	Tpi_LF_Enum *lf_enum = type->type_data;
	// assert all member functions we need info from
	RzBaseType *base_type;
	char *name = rz_bin_pdb_get_type_name(type);
	if (name) {
		base_type = rz_type_db_get_base_type(typedb, name);
		if (base_type && base_type->type) {
			return rz_type_clone(base_type->type);
		}
	}

	base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ENUM);
	if (!base_type) {
		return NULL;
	}

	bool to_free_name = false;
	if (!name) {
		name = create_type_name_from_offset(type->type_index);
		to_free_name = true;
	}
	RzPdbTpiType *utype = rz_bin_pdb_get_type_by_index(stream, lf_enum->utype);
	if (!utype) {
		goto cleanup;
	}
	RzType *btype = parse_type(typedb, stream, utype, NULL);
	if (!btype) {
		goto cleanup;
	}
	int size = rz_type_db_get_bitsize(typedb, btype);
	RzList *members = rz_bin_pdb_get_type_members(stream, type);
	if (!members) {
		rz_type_base_type_free(base_type);
		base_type = NULL;
		goto cleanup;
	}

	RzListIter *it;
	RzPdbTpiType *member_info;
	rz_list_foreach (members, it, member_info) {
		RzTypeEnumCase *enum_case = parse_enumerate(member_info);
		if (!enum_case) {
			continue; // skip it, move forward
		}
		void *element = rz_vector_push(&base_type->struct_data.members, enum_case);
		if (!element) {
			rz_type_base_enum_case_free(enum_case, NULL);
			rz_type_base_type_free(base_type);
			base_type = NULL;
			goto cleanup;
		}
	}
	base_type->name = strdup(name);
	base_type->size = size;
	base_type->type = btype;
	rz_type_db_save_base_type(typedb, base_type);
	rz_list_append(stream->print_type, base_type);
cleanup:
	if (to_free_name) {
		RZ_FREE(name);
	}
	return base_type ? base_type->type : NULL;
}

/**
 * \brief Delegate the type parsing to appropriate function
 *
 * \param t RzTypeDB instance
 * \param stream TPI Stream
 * \param type Current type
 */
static void parse_types(const RzTypeDB *typedb, RzPdbTpiStream *stream, RzPdbTpiType *type) {
	rz_return_if_fail(typedb && type);

	if (rz_bin_pdb_type_is_fwdref(type)) {
		return;
	}
	switch (type->leaf_type) {
	case LF_CLASS:
	case LF_CLASS_19:
		break;
	case LF_STRUCTURE:
	case LF_STRUCTURE_19:
		parse_structure(typedb, stream, type);
		break;
	case LF_UNION:
		parse_union(typedb, stream, type);
		break;
	case LF_ENUM:
		parse_enum(typedb, stream, type);
		break;
	default:
		// shouldn't happen, happens when someone modifies leafs that get here
		// but not how they should be parsed
		eprintf("Unknown type record");
		break;
	}
}

/**
 * \brief Saves PDB types from TPI stream into the type database
 *
 * \param t RzTypeDB instance
 * \param pdb PDB instance
 */
RZ_API void rz_parse_pdb_types(const RzTypeDB *typedb, const RzPdb *pdb) {
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
		if (type && is_parsable_type(type->leaf_type)) {
			parse_types(typedb, stream, type);
		}
	}
}
