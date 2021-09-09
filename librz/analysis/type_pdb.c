// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_core.h>
#include <rz_type.h>
#include <rz_analysis.h>

#include "../bin/pdb/types.h"
#include "../bin/pdb/tpi.h"

static RzType *parse_type(const RzTypeDB *typedb, SType *type);
static RzType *parse_regular_type(const RzTypeDB *typedb, SType *type);
static RzType *parse_type_modifier(const RzTypeDB *typedb, STypeInfo *type);
static RzType *parse_type_pointer(const RzTypeDB *typedb, SType *type);
static RzType *parse_type_procedure(const RzTypeDB *typedb, SType *type);
static RzType *parse_type_array(const RzTypeDB *typedb, STypeInfo *type);
static RzPVector *parse_type_arglist(const RzTypeDB *typedb, STypeInfo *arglist);
static RzType *parse_type_mfunction(const RzTypeDB *typedb, STypeInfo *type_info, char *name);
static RzType *parse_type_onemethod(const RzTypeDB *typedb, STypeInfo *type_info);
static RzType *parse_type_member(const RzTypeDB *typedb, STypeInfo *type_info);
static RzType *parse_type_nest(const RzTypeDB *typedb, STypeInfo *type_info);
static RzType *parse_union(const RzTypeDB *typedb, SType *type);
static RzTypeUnionMember *parse_union_member(const RzTypeDB *typedb, STypeInfo *type_info);
static RzType *parse_structure(const RzTypeDB *typedb, SType *type);
static RzTypeStructMember *parse_struct_member(const RzTypeDB *typedb, STypeInfo *type_info);
static RzType *parse_enum(const RzTypeDB *typedb, SType *type);
static RzTypeEnumCase *parse_enumerate(STypeInfo *type_info);

static bool is_parsable_type(const ELeafType type) {
	rz_return_val_if_fail(type, false);
	return (type == eLF_STRUCTURE ||
		type == eLF_UNION ||
		type == eLF_ENUM ||
		type == eLF_CLASS ||
		type == eLF_CLASS_19 ||
		type == eLF_STRUCTURE_19);
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

static RzType *parse_type_array(const RzTypeDB *typedb, STypeInfo *type) {
	rz_return_val_if_fail(type && typedb, NULL);
	SLF_ARRAY *lf_array = type->type_info;
	SType *element = rz_bin_pdb_stype_by_index(lf_array->element_type);
	if (!element) {
		return NULL;
	}
	RzType *element_type = parse_type(typedb, element);
	if (!element_type) {
		return NULL;
	}
	RzType *typ = RZ_NEW0(RzType);
	if (!typ) {
		return NULL;
	}
	typ->kind = RZ_TYPE_KIND_ARRAY;
	typ->array.type = element_type;
	typ->array.count = type->get_val(type);
	return typ;
}

static RzType *parse_regular_type(const RzTypeDB *typedb, SType *type) {
	rz_return_val_if_fail(type && typedb, NULL);
	STypeInfo *type_info = &type->type_data;
	switch (type_info->leaf_type) {
	case eLF_CLASS:
	case eLF_CLASS_19:
		// TODO: https://github.com/rizinorg/rizin/issues/1205
		RZ_LOG_INFO("%s : LF_CLASS is not handled for now.\n", __FUNCTION__);
		break;
	case eLF_STRUCTURE:
	case eLF_STRUCTURE_19:
		return parse_structure(typedb, type);
	case eLF_MODIFIER:
		return parse_type_modifier(typedb, type_info);
	case eLF_ARRAY:
		return parse_type_array(typedb, type_info);
	case eLF_BITFIELD:
		// TODO: we don't have BITFIELD type for now https://github.com/rizinorg/rizin/issues/1240
		RZ_LOG_INFO("%s : LF_BITFIELD is not handled for now.\n", __FUNCTION__);
		break;
	case eLF_POINTER:
		return parse_type_pointer(typedb, type);
	case eLF_PROCEDURE:
		return parse_type_procedure(typedb, type);
	case eLF_UNION:
		return parse_union(typedb, type);
	case eLF_ENUM:
		return parse_enum(typedb, type);
	default:
		RZ_LOG_INFO("%s : unsupported leaf type 0x%x\n", __FUNCTION__, type_info->leaf_type);
		break;
	}
	return NULL;
}

static RzType *parse_type_modifier(const RzTypeDB *typedb, STypeInfo *type) {
	rz_return_val_if_fail(type && typedb, NULL);
	SLF_MODIFIER *lf_modifier = type->type_info;
	SType *m_utype = rz_bin_pdb_stype_by_index(lf_modifier->modified_type);
	if (m_utype) {
		RzType *typ = parse_type(typedb, m_utype);
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

static RzType *parse_type_pointer(const RzTypeDB *typedb, SType *type) {
	rz_return_val_if_fail(type && typedb, NULL);
	STypeInfo *type_info = &type->type_data;
	SLF_POINTER *lf_pointer = type_info->type_info;
	RzType *typ = RZ_NEW0(RzType);
	if (!typ) {
		return NULL;
	}
	typ->kind = RZ_TYPE_KIND_POINTER;
	SType *p_utype = rz_bin_pdb_stype_by_index(lf_pointer->utype);
	if (p_utype) {
		RzType *tmp = parse_regular_type(typedb, p_utype);
		if (!tmp) {
			return NULL;
		}
		typ->pointer.type = tmp;
		return typ;
	}
	rz_type_free(typ);
	return NULL;
}

static RzType *parse_type(const RzTypeDB *typedb, SType *type) {
	rz_return_val_if_fail(type && typedb, NULL);
	RzType *typ;
	STypeInfo *type_info = &type->type_data;
	if (type_info->leaf_type == eLF_SIMPLE_TYPE) {
		SLF_SIMPLE_TYPE *simple_type = type_info->type_info;
		char *error_msg = NULL;
		typ = rz_type_parse_string_single(typedb->parser, simple_type->type, &error_msg);
		if (error_msg) {
			eprintf("%s : Error parsing complex type member \"%s\" type:\n%s\n", __FUNCTION__, simple_type->type, error_msg);
			RZ_FREE(error_msg);
		}
		return typ;
	} else {
		if (type_info->leaf_type == eLF_POINTER) {
			return parse_type_pointer(typedb, type);
		} else {
			return parse_regular_type(typedb, type);
		}
	}
}

static RzPVector *parse_type_arglist(const RzTypeDB *typedb, STypeInfo *arglist) {
	rz_return_val_if_fail(arglist && typedb, NULL);
	SLF_ARGLIST *lf_arglist = arglist->type_info;
	RzPVector *vec = rz_pvector_new((RzPVectorFree)rz_type_callable_arg_free);
	ut32 *ptr_types = lf_arglist->arg_type;
	int i = 0;
	for (; i < lf_arglist->count; i++, ptr_types++) {
		SType *stype = rz_bin_pdb_stype_by_index(*ptr_types);
		if (!stype) {
			continue;
		}
		RzType *type = parse_type(typedb, stype);
		if (!type) {
			continue;
		}
		RzCallableArg *arg = RZ_NEW0(RzCallableArg);
		arg->name = rz_str_newf("arg%d", i);
		arg->type = type;
		rz_pvector_push(vec, arg);
	}
	return vec;
}

static RzType *parse_type_procedure(const RzTypeDB *typedb, SType *type) {
	rz_return_val_if_fail(type && typedb, NULL);
	STypeInfo *type_info = &type->type_data;
	SLF_PROCEDURE *lf_procedure = type_info->type_info;
	RzType *typ = RZ_NEW0(RzType);
	RzCallable *callable = RZ_NEW0(RzCallable);
	if (!typ || !callable) {
		return NULL;
	}
	typ->kind = RZ_TYPE_KIND_CALLABLE;
	typ->callable = callable;
	typ->callable->name = create_type_name_from_offset(type->tpi_idx);
	typ->callable->cc = rz_bin_pdb_calling_convention_as_string(lf_procedure->call_conv);
	// parse return type
	SType *ret_type = rz_bin_pdb_stype_by_index(lf_procedure->return_type);
	if (ret_type) {
		typ->callable->ret = parse_type(typedb, ret_type);
		if (!typ->callable->ret) {
			typ->callable->noret = true;
		}
	}
	// parse parameter list
	SType *arglist = rz_bin_pdb_stype_by_index(lf_procedure->arg_list);
	if (arglist) {
		typ->callable->args = parse_type_arglist(typedb, &arglist->type_data);
	}
	return typ;
}

static RzType *parse_type_mfunction(const RzTypeDB *typedb, STypeInfo *type_info, char *name) {
	rz_return_val_if_fail(type_info && typedb, NULL);
	SLF_MFUNCTION *lf_mfunction = type_info->type_info;
	RzType *type = RZ_NEW0(RzType);
	RzCallable *callable = RZ_NEW0(RzCallable);
	if (!type || !callable) {
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_CALLABLE;
	type->callable = callable;
	type->callable->name = strdup(name);
	type->callable->cc = rz_bin_pdb_calling_convention_as_string(lf_mfunction->call_conv);
	// parse return type
	SType *ret_type = rz_bin_pdb_stype_by_index(lf_mfunction->return_type);
	if (ret_type) {
		type->callable->ret = parse_type(typedb, ret_type);
		if (!type->callable->ret) {
			type->callable->noret = true;
		}
	}
	// parse parameter list
	SType *arglist = rz_bin_pdb_stype_by_index(lf_mfunction->arglist);
	if (arglist) {
		type->callable->args = parse_type_arglist(typedb, &arglist->type_data);
	}
	return type;
}

static RzType *parse_type_onemethod(const RzTypeDB *typedb, STypeInfo *type_info) {
	rz_return_val_if_fail(type_info && typedb, NULL);
	SLF_ONEMETHOD *lf_onemethod = type_info->type_info;
	char *name = type_info->get_name(type_info);
	SType *utype = rz_bin_pdb_stype_by_index(lf_onemethod->index);
	if (!utype) {
		return NULL;
	}
	STypeInfo *utype_info = &utype->type_data;
	if (utype_info->leaf_type == eLF_MFUNCTION) {
		return parse_type_mfunction(typedb, &utype->type_data, name);
	}
	return NULL;
}

static RzType *parse_type_member(const RzTypeDB *typedb, STypeInfo *type_info) {
	rz_return_val_if_fail(type_info && typedb, NULL);
	SLF_MEMBER *lf_member = type_info->type_info;
	SType *utype = rz_bin_pdb_stype_by_index(lf_member->index);
	if (!utype) {
		return NULL;
	}
	return parse_type(typedb, utype);
}

static RzType *parse_type_nest(const RzTypeDB *typedb, STypeInfo *type_info) {
	rz_return_val_if_fail(type_info && typedb, NULL);
	SLF_NESTTYPE *lf_nest = type_info->type_info;
	SType *utype = rz_bin_pdb_stype_by_index(lf_nest->index);
	if (!utype) {
		return NULL;
	}
	if (utype->type_data.get_name) {
		char *name = utype->type_data.get_name(utype);
		if (name) {
			RzBaseType *b_type = rz_type_db_get_base_type(typedb, name);
			if (b_type && b_type->type) {
				if (b_type->type->kind == RZ_TYPE_KIND_IDENTIFIER) {
					return rz_type_clone(b_type->type);
				}
			}
			return NULL;
		}
	}

	RzType *n_type = parse_type(typedb, utype);
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
 * \param type_info Current type info (member)
 * \return RzTypeStructMember* parsed member, NULL if fail
 */
static RzTypeStructMember *parse_struct_member(const RzTypeDB *typedb, STypeInfo *type_info) {
	rz_return_val_if_fail(type_info, NULL);
	char *name = NULL;
	ut64 offset = 0;
	RzType *type = NULL;
	switch (type_info->leaf_type) {
	case eLF_ONEMETHOD: {
		name = type_info->get_name(type_info);
		type = parse_type_onemethod(typedb, type_info);
		break;
	}
	case eLF_MEMBER: {
		offset = type_info->get_val(type_info);
		name = type_info->get_name(type_info);
		type = parse_type_member(typedb, type_info);
		break;
	}
	case eLF_NESTTYPE: {
		name = type_info->get_name(type_info);
		type = parse_type_nest(typedb, type_info);
		break;
	}
	case eLF_BCLASS:
		// For structure, we don't need base class for now
		return NULL;
	case eLF_METHOD:
		// TODO: need to handle overloaded methods here
		return NULL;
	case eLF_VFUNCTAB:
		// For structure, we don't need vtable for now
		return NULL;
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
	return NULL;
}

/**
 * \brief Parses structures into BaseType and saves them into hashtable
 *
 * \param t RzTypeDB instance
 * \param type Current type
 */
static RzType *parse_structure(const RzTypeDB *typedb, SType *type) {
	rz_return_val_if_fail(typedb && type, NULL);
	STypeInfo *type_info = &type->type_data;
	// assert all member functions we need info from
	rz_return_val_if_fail(type_info->get_members &&
			type_info->is_fwdref &&
			type_info->get_name &&
			type_info->get_val,
		NULL);
	if (type_info->is_fwdref(type_info)) {
		return NULL;
	}

	RzBaseType *base_type;
	char *name = type_info->get_name(type_info);
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
		name = create_type_name_from_offset(type->tpi_idx);
		to_free_name = true;
	}
	ut64 size = type_info->get_val(type_info);

	RzList *members = type_info->get_members(type_info);
	if (!members) {
		rz_type_base_type_free(base_type);
		goto cleanup;
	}

	RzListIter *it;
	STypeInfo *member_info;
	rz_list_foreach (members, it, member_info) {
		RzTypeStructMember *struct_member = parse_struct_member(typedb, member_info);
		if (!struct_member) {
			continue; // skip the failure
		}
		void *element = rz_vector_push(&base_type->struct_data.members, struct_member);
		if (!element) {
			rz_type_base_type_free(base_type);
			goto cleanup;
		}
	}
	base_type->name = strdup(name);
	base_type->size = size;
	rz_type_db_save_base_type(typedb, base_type);
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
 * \param type_info Current type info (member)
 * \return RzTypeUnionMember* parsed member, NULL if fail
 */
static RzTypeUnionMember *parse_union_member(const RzTypeDB *typedb, STypeInfo *type_info) {
	rz_return_val_if_fail(type_info && typedb, NULL);
	char *name = NULL;
	ut64 offset = 0;
	RzType *type = NULL;
	switch (type_info->leaf_type) {
	case eLF_ONEMETHOD: {
		name = type_info->get_name(type_info);
		type = parse_type_onemethod(typedb, type_info);
		break;
	}
	case eLF_MEMBER: {
		offset = type_info->get_val(type_info);
		name = type_info->get_name(type_info);
		type = parse_type_member(typedb, type_info);
		break;
	}
	case eLF_NESTTYPE: {
		name = type_info->get_name(type_info);
		type = parse_type_nest(typedb, type_info);
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
	return NULL;
}

/**
 * \brief Parses union into BaseType and saves it into hashtable
 *
 * \param type_info Current type info (enum case)
 */
static RzType *parse_union(const RzTypeDB *typedb, SType *type) {
	rz_return_val_if_fail(typedb && type, NULL);
	STypeInfo *type_info = &type->type_data;
	// assert all member functions we need info from
	rz_return_val_if_fail(type_info->get_members &&
			type_info->is_fwdref &&
			type_info->get_name &&
			type_info->get_val,
		NULL);
	if (type_info->is_fwdref(type_info)) {
		return NULL;
	}

	RzBaseType *base_type;
	char *name = type_info->get_name(type_info);
	if (name) {
		base_type = rz_type_db_get_base_type(typedb, name);
		if (base_type && base_type->type) {
			return rz_type_clone(base_type->type);
		}
	}

	base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_UNION);
	if (!base_type) {
		return NULL;
	}
	bool to_free_name = false;
	if (!name) {
		name = create_type_name_from_offset(type->tpi_idx);
		to_free_name = true;
	}

	RzList *members = type_info->get_members(type_info);
	if (!members) {
		rz_type_base_type_free(base_type);
		goto cleanup;
	}
	RzListIter *it;
	STypeInfo *member_info;
	rz_list_foreach (members, it, member_info) {
		RzTypeUnionMember *union_member = parse_union_member(typedb, member_info);
		if (!union_member) {
			continue; // skip the failure
		}
		void *element = rz_vector_push(&base_type->union_data.members, union_member);
		if (!element) {
			rz_type_base_type_free(base_type);
			goto cleanup;
		}
	}
	base_type->name = strdup(name);
	ut64 size = type_info->get_val(type_info);
	base_type->size = size;
	rz_type_db_save_base_type(typedb, base_type);
cleanup:
	if (to_free_name) {
		RZ_FREE(name);
	}
	return base_type ? base_type->type : NULL;
}

/**
 * \brief Parse enum case
 *
 * \param type_info Current type info (enum case)
 * \return RzTypeEnumCase* parsed enum case, NULL if fail
 */
static RzTypeEnumCase *parse_enumerate(STypeInfo *type_info) {
	rz_return_val_if_fail(type_info && type_info->leaf_type == eLF_ENUMERATE, NULL);
	rz_return_val_if_fail(type_info->get_val && type_info->get_name, NULL);

	char *name = NULL;
	ut64 value = 0;
	// sometimes, the type doesn't have get_val for some reason
	value = type_info->get_val(type_info);
	name = type_info->get_name(type_info);
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
 * \param type Current type
 */
static RzType *parse_enum(const RzTypeDB *typedb, SType *type) {
	rz_return_val_if_fail(typedb && type, NULL);
	STypeInfo *type_info = &type->type_data;
	SLF_ENUM *lf_enum = type_info->type_info;
	// assert all member functions we need info from
	rz_return_val_if_fail(type_info->get_members &&
			type_info->get_name,
		NULL);

	RzBaseType *base_type;
	char *name = type_info->get_name(type_info);
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
		name = create_type_name_from_offset(type->tpi_idx);
		to_free_name = true;
	}
	SType *utype = rz_bin_pdb_stype_by_index(lf_enum->utype);
	if (!utype) {
		goto cleanup;
	}
	RzType *btype = parse_type(typedb, utype);
	if (!btype) {
		goto cleanup;
	}
	int size = rz_type_db_get_bitsize(typedb, btype);
	RzList *members = type_info->get_members(type_info);
	if (!members) {
		rz_type_base_type_free(base_type);
		goto cleanup;
	}

	RzListIter *it;
	STypeInfo *member_info;
	rz_list_foreach (members, it, member_info) {
		RzTypeEnumCase *enum_case = parse_enumerate(member_info);
		if (!enum_case) {
			continue; // skip it, move forward
		}
		void *element = rz_vector_push(&base_type->struct_data.members, enum_case);
		if (!element) {
			rz_type_base_type_free(base_type);
			goto cleanup;
		}
	}
	base_type->name = strdup(name);
	base_type->size = size;
	base_type->type = btype;

	rz_type_db_save_base_type(typedb, base_type);
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
 * \param type Current type
 */
static void parse_stypes(const RzTypeDB *typedb, SType *type) {
	rz_return_if_fail(typedb && type);

	if (type->type_data.is_fwdref) {
		if (type->type_data.is_fwdref(&type->type_data)) { // we skip those, atleast for now
			return;
		}
	}
	switch (type->type_data.leaf_type) {
	case eLF_CLASS:
	case eLF_CLASS_19:
		break;
	case eLF_STRUCTURE:
	case eLF_STRUCTURE_19:
		parse_structure(typedb, type);
		break;
	case eLF_UNION:
		parse_union(typedb, type);
		break;
	case eLF_ENUM:
		parse_enum(typedb, type);
		break;
	default:
		// shouldn't happen, happens when someone modifies leafs that get here
		// but not how they should be parsed
		eprintf("Unknown type record");
		break;
	}
}

/**
 * \brief Saves PDB types from TPI stream into the SDB
 *
 * \param t RzTypeDB instance
 * \param pdb PDB information
 */
RZ_API void rz_parse_pdb_types(const RzTypeDB *typedb, const RzPdb *pdb) {
	rz_return_if_fail(typedb && pdb);
	RzList *plist = pdb->pdb_streams;
	// getting the TPI stream from the streams list
	STpiStream *tpi_stream = rz_list_get_n(plist, ePDB_STREAM_TPI);
	if (!tpi_stream) { // no TPI stream found
		return;
	}
	// Types should be DAC - only references previous records
	RzListIter *it;
	SType *type;
	rz_list_foreach (tpi_stream->types, it, type) {
		if (type && is_parsable_type(type->type_data.leaf_type)) {
			parse_stypes(typedb, type);
		}
	}
}
