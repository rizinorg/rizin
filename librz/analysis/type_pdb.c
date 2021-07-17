// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_core.h>
#include <rz_type.h>
#include <rz_analysis.h>

#include "../bin/pdb/types.h"

static bool is_parsable_type(const ELeafType type) {
	return (type == eLF_STRUCTURE ||
		type == eLF_UNION ||
		type == eLF_ENUM ||
		type == eLF_CLASS);
}

/**
 * @brief Create a type name from offset
 *
 * @param offset
 * @return char* Name or NULL if error
 */
static char *create_type_name_from_offset(ut64 offset) {
	int offset_length = snprintf(NULL, 0, "type_0x%" PFMT64x, offset);
	char *str = malloc(offset_length + 1);
	snprintf(str, offset_length + 1, "type_0x%" PFMT64x, offset);
	return str;
}

/**
 * @brief Parses class/struct/union member
 *
 * @param typedb Types DB instance
 * @param type_info Current type info (member)
 * @param types List of all types
 * @return RzTypeStructMember* parsed member, NULL if fail
 */
static RzTypeStructMember *parse_member(const RzTypeDB *typedb, STypeInfo *type_info, RzList *types) {
	rz_return_val_if_fail(type_info && types, NULL);
	if (type_info->leaf_type != eLF_MEMBER) {
		return NULL;
	}
	rz_return_val_if_fail(type_info->get_name &&
			type_info->get_print_type && type_info->get_val,
		NULL);
	char *name = NULL;
	char *type = NULL;
	int offset = 0;

	type_info->get_val(type_info, &offset); // gets offset
	type_info->get_name(type_info, &name);
	type_info->get_print_type(type_info, &type);
	RzTypeStructMember *member = RZ_NEW0(RzTypeStructMember);
	if (!member) {
		goto cleanup;
	}
	char *sname = rz_str_sanitize_sdb_key(name);
	char *error_msg = NULL;
	RzType *mtype = rz_type_parse_string_single(typedb->parser, type, &error_msg);
	if (!mtype || error_msg) {
		eprintf("Error parsing complex type member \"%s\" type:\n%s\n", type, error_msg);
		goto cleanup;
	}
	member->name = sname;
	member->type = mtype;
	member->offset = offset;
	return member;
cleanup:
	return NULL;
}

/**
 * @brief Parse enum case
 *
 * @param type_info Current type info (enum case)
 * @param types List of all types
 * @return RzTypeEnumCase* parsed enum case, NULL if fail
 */
static RzTypeEnumCase *parse_enumerate(STypeInfo *type_info, RzList *types) {
	rz_return_val_if_fail(type_info && types && type_info->leaf_type == eLF_ENUMERATE, NULL);
	rz_return_val_if_fail(type_info->get_val && type_info->get_name, NULL);

	char *name = NULL;
	int value = 0;
	// sometimes, the type doesn't have get_val for some reason
	type_info->get_val(type_info, &value);
	type_info->get_name(type_info, &name);
	RzTypeEnumCase *cas = RZ_NEW0(RzTypeEnumCase);
	if (!cas) {
		goto cleanup;
	}
	char *sname = rz_str_sanitize_sdb_key(name);
	cas->name = sname;
	cas->val = value;
	return cas;
cleanup:
	return NULL;
}

/**
 * @brief Parses enum into BaseType and saves it into SDB
 *
 * @param t RzTypeDB instance
 * @param type Current type
 * @param types List of all types
 */
static void parse_enum(const RzTypeDB *typedb, SType *type, RzList *types) {
	rz_return_if_fail(typedb && type && types);
	STypeInfo *type_info = &type->type_data;
	// assert all member functions we need info from
	rz_return_if_fail(type_info->get_members &&
		type_info->get_name &&
		type_info->get_utype);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ENUM);
	if (!base_type) {
		return;
	}

	char *name = NULL;
	type_info->get_name(type_info, &name);
	bool to_free_name = false;
	if (!name) {
		name = create_type_name_from_offset(type->tpi_idx);
		to_free_name = true;
	}
	type_info->get_utype(type_info, (void **)&type);
	int size = 0;
	char *type_name = NULL;
	if (type && type->type_data.type_info) {
		SLF_SIMPLE_TYPE *base_type = type->type_data.type_info;
		type_name = base_type->type;
		size = base_type->size;
	}
	RzList *members;
	type_info->get_members(type_info, &members);

	RzListIter *it = rz_list_iterator(members);
	while (rz_list_iter_next(it)) {
		STypeInfo *member_info = rz_list_iter_get(it);
		RzTypeEnumCase *enum_case = parse_enumerate(member_info, types);
		if (!enum_case) {
			continue; // skip it, move forward
		}
		void *element = rz_vector_push(&base_type->struct_data.members, enum_case);
		if (!element) {
			rz_type_base_type_free(base_type);
			goto cleanup;
		}
	}
	char *sname = rz_str_sanitize_sdb_key(name);
	char *error_msg = NULL;
	RzType *btype = rz_type_parse_string_single(typedb->parser, type_name, &error_msg);
	if (!btype || error_msg) {
		eprintf("Error parsing enum \"%s\" type:\n%s\n", type_name, error_msg);
		rz_type_base_type_free(base_type);
		goto cleanup;
	}
	base_type->name = sname;
	base_type->size = size;
	base_type->type = btype;

	rz_type_db_save_base_type(typedb, base_type);
cleanup:
	if (to_free_name) {
		RZ_FREE(name);
	}
	return;
}

/**
 * @brief Parses classes, unions and structures into BaseType and saves them into SDB
 *
 * @param t RzTypeDB instance
 * @param type Current type
 * @param types List of all types
 */
static void parse_structure(const RzTypeDB *typedb, SType *type, RzList *types) {
	rz_return_if_fail(typedb && type && types);
	STypeInfo *type_info = &type->type_data;
	// assert all member functions we need info from
	rz_return_if_fail(type_info->get_members &&
		type_info->is_fwdref &&
		type_info->get_name &&
		type_info->get_val);

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_STRUCT);
	if (!base_type) {
		return;
	}

	char *name = NULL;
	type_info->get_name(type_info, &name);
	bool to_free_name = false;
	if (!name) {
		name = create_type_name_from_offset(type->tpi_idx);
		to_free_name = true;
	}
	int size;
	type_info->get_val(type_info, &size); // gets size

	RzList *members;
	type_info->get_members(type_info, &members);

	RzListIter *it = rz_list_iterator(members);
	while (rz_list_iter_next(it)) {
		STypeInfo *member_info = rz_list_iter_get(it);
		RzTypeStructMember *struct_member = parse_member(typedb, member_info, types);
		if (!struct_member) {
			continue; // skip the failure
		}
		void *element = rz_vector_push(&base_type->struct_data.members, struct_member);
		if (!element) {
			rz_type_base_type_free(base_type);
			goto cleanup;
		}
	}
	if (type_info->leaf_type == eLF_STRUCTURE || type_info->leaf_type == eLF_CLASS) {
		base_type->kind = RZ_BASE_TYPE_KIND_STRUCT;
	} else { // union
		base_type->kind = RZ_BASE_TYPE_KIND_UNION;
	}
	char *sname = rz_str_sanitize_sdb_key(name);
	base_type->name = sname;
	base_type->size = size;
	rz_type_db_save_base_type(typedb, base_type);
cleanup:
	if (to_free_name) {
		RZ_FREE(name);
	}
	return;
}

/**
 * @brief Delegate the type parsing to appropriate function
 *
 * @param t RzTypeDB instance
 * @param type Current type
 * @param types List of all types
 */
static void parse_type(const RzTypeDB *typedb, SType *type, RzList *types) {
	rz_return_if_fail(typedb && type && types);

	int is_forward_decl;
	if (type->type_data.is_fwdref) {
		type->type_data.is_fwdref(&type->type_data, &is_forward_decl);
		if (is_forward_decl) { // we skip those, atleast for now
			return;
		}
	}
	switch (type->type_data.leaf_type) {
	case eLF_CLASS:
	case eLF_STRUCTURE:
	case eLF_UNION:
		parse_structure(typedb, type, types);
		break;
	case eLF_ENUM:
		parse_enum(typedb, type, types);
		break;
	default:
		// shouldn't happen, happens when someone modifies leafs that get here
		// but not how they should be parsed
		eprintf("Unknown type record");
		break;
	}
}

/**
 * @brief Saves PDB types from TPI stream into the SDB
 *
 * @param t RzTypeDB instance
 * @param pdb PDB information
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
	RzListIter *iter = rz_list_iterator(tpi_stream->types);
	while (rz_list_iter_next(iter)) { // iterate all types
		SType *type = rz_list_iter_get(iter);
		if (type && is_parsable_type(type->type_data.leaf_type)) {
			parse_type(typedb, type, tpi_stream->types);
		}
	}
}
