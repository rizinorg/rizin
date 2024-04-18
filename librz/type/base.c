// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <string.h>

RZ_API void rz_type_base_enum_case_free(void *e, void *user) {
	(void)user;
	RzTypeEnumCase *cas = e;
	free((char *)cas->name);
}

RZ_API void rz_type_base_struct_member_free(void *e, void *user) {
	(void)user;
	RzTypeStructMember *member = e;
	rz_type_free(member->type);
	free((char *)member->name);
}

RZ_API void rz_type_base_union_member_free(void *e, void *user) {
	(void)user;
	RzTypeUnionMember *member = e;
	rz_type_free(member->type);
	free((char *)member->name);
}

/**
 * \brief Returns string representing the kind of base type
 *
 * \param kind RzBaseTypeKind to return string representation of
 */
RZ_API RZ_BORROW const char *rz_type_base_type_kind_as_string(RzBaseTypeKind kind) {
	switch (kind) {
	case RZ_BASE_TYPE_KIND_STRUCT:
		return "struct";
	case RZ_BASE_TYPE_KIND_UNION:
		return "union";
	case RZ_BASE_TYPE_KIND_ENUM:
		return "enum";
	case RZ_BASE_TYPE_KIND_TYPEDEF:
		return "typedef";
	case RZ_BASE_TYPE_KIND_ATOMIC:
		return "atomic";
	default:
		rz_warn_if_reached();
		return "unknown";
	}
}

/**
 * \brief Searches for the RzBaseType in the types database given the name
 *
 * \param typedb Type Database instance
 * \param name Name of the RzBaseType
 * 
 * \return RzPVector <RzBaseTypeWithMetadata*>
 */
RZ_API RZ_BORROW RzBaseType *rz_type_db_get_base_type(const RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);

	bool found = false;
	RzPVector /* <RzBaseTypeWithMetadata*> */ *btypes_by_name = ht_pp_find(typedb->types, name, &found);
	if (!found || !btypes_by_name || rz_pvector_empty(btypes_by_name)) {
		return NULL;
	}
	RzBaseTypeWithMetadata *btype_with_mdata = rz_pvector_head(btypes_by_name);
	return btype_with_mdata->base_type;
}
// RZ_API RZ_BORROW RzBaseType *rz_type_db_get_base_type(const RzTypeDB *typedb, RZ_NONNULL const char *name) {
// 	rz_return_val_if_fail(typedb && name, NULL);

// 	bool found = false;
// 	RzBaseType *btype = ht_pp_find(typedb->types, name, &found);
// 	if (!found || !btype) {
// 		return NULL;
// 	}
// 	return btype;
// }

/**
 * \brief Removes RzBaseType from the Types DB
 *
 * \param typedb Type Database instance
 * \param type RzBaseType to remove
 */
RZ_API bool rz_type_db_delete_base_type(RzTypeDB *typedb, RZ_NONNULL RzBaseType *type) {
	rz_return_val_if_fail(typedb && type && type->name, false);
	ht_pp_delete(typedb->types, type->name);
	return true;
}

struct list_kind {
	RzList /*<RzBaseType *>*/ *types;
	RzBaseTypeKind kind;
};

static bool base_type_kind_collect_cb(void *user, const void *k, const void *v) {
	struct list_kind *l = user;
	RzBaseType *btype = (RzBaseType *)v;
	if (l->kind == btype->kind) {
		rz_list_append(l->types, btype);
	}
	return true;
}

/**
 * \brief Returns the list of all basic types of the chosen kind
 *
 * \param typedb Types Database instance
 * \param kind Kind of the types to list
 */
RZ_API RZ_OWN RzList /*<RzBaseType *>*/ *rz_type_db_get_base_types_of_kind(const RzTypeDB *typedb, RzBaseTypeKind kind) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *types = rz_list_new();
	struct list_kind lk = { types, kind };
	ht_pp_foreach(typedb->types, base_type_kind_collect_cb, &lk);
	return types;
}

static bool base_type_collect_cb(void *user, const void *k, const void *v) {
	rz_return_val_if_fail(user && k && v, false);
	RzList *l = user;
	rz_list_append(l, (void *)v);
	return true;
}

/**
 * \brief Returns the list of all basic types
 *
 * \param typedb Types Database instance
 */
RZ_API RZ_OWN RzList /*<RzBaseType *>*/ *rz_type_db_get_base_types(const RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *types = rz_list_new();
	ht_pp_foreach(typedb->types, base_type_collect_cb, types);
	return types;
}

static void RzTypeStructMember_cpy(RzTypeStructMember *dst, RzTypeStructMember *src) {
	if (!(src && dst)) {
		return;
	}
	memcpy(dst, src, sizeof(RzTypeStructMember));
	dst->name = rz_str_dup(src->name);
	dst->type = rz_type_clone(src->type);
}

static void RzTypeEnumCase_cpy(RzTypeEnumCase *dst, RzTypeEnumCase *src) {
	if (!(src && dst)) {
		return;
	}
	memcpy(dst, src, sizeof(RzTypeEnumCase));
	dst->name = rz_str_dup(src->name);
}

static void RzTypeUnionMember_cpy(RzTypeUnionMember *dst, RzTypeUnionMember *src) {
	if (!(src && dst)) {
		return;
	}
	memcpy(dst, src, sizeof(RzTypeUnionMember));
	dst->name = rz_str_dup(src->name);
	dst->type = rz_type_clone(src->type);
}

/**
 * \brief Copy RzBaseType \p src into another RzBaseType \p dst
 * \param dst the destination RzBaseType
 * \param src the source RzBaseType
 * \return true if the copy was successful, false otherwise
 */
RZ_API bool rz_base_type_clone_into(
	RZ_NONNULL RZ_BORROW RZ_OUT RzBaseType *dst,
	RZ_NONNULL RZ_BORROW RZ_IN RzBaseType *src) {
	rz_return_val_if_fail(src && dst, false);
	rz_mem_copy(dst, sizeof(RzBaseType), src, sizeof(RzBaseType));
	dst->name = rz_str_dup(src->name);
	dst->type = src->type ? rz_type_clone(src->type) : NULL;

	switch (src->kind) {
	case RZ_BASE_TYPE_KIND_ENUM:
		rz_vector_clone_intof(&dst->enum_data.cases, &src->enum_data.cases,
			(RzVectorItemCpyFunc)RzTypeEnumCase_cpy);
		break;
	case RZ_BASE_TYPE_KIND_STRUCT:
		rz_vector_clone_intof(&dst->struct_data.members, &src->struct_data.members,
			(RzVectorItemCpyFunc)RzTypeStructMember_cpy);
		break;
	case RZ_BASE_TYPE_KIND_UNION:
		rz_vector_clone_intof(&dst->union_data.members, &src->union_data.members,
			(RzVectorItemCpyFunc)RzTypeUnionMember_cpy);
		break;
	default: break;
	}
	return true;
}

/**
 * \brief Copy the RzBaseType \p b and all its members
 * \param b the RzBaseType to copy
 * \return a copy of \p b
 */
RZ_API RZ_OWN RzBaseType *rz_base_type_clone(RZ_NULLABLE RZ_BORROW RzBaseType *b) {
	if (!b) {
		return NULL;
	}
	RzBaseType *type = RZ_NEW0(RzBaseType);
	if (!type) {
		return NULL;
	}
	if (!rz_base_type_clone_into(type, b)) {
		return NULL;
	}
	return type;
}

/**
 * \brief Frees the RzBaseType instance and all of its members
 *
 * \param type RzBaseType pointer
 */
RZ_API void rz_type_base_type_free(RzBaseType *type) {
	if (!type) {
		return;
	}
	RZ_FREE(type->name);
	rz_type_free(type->type);
	type->type = NULL;

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

/**
 * \brief Allocates a new instance of RzBaseType given the kind
 *
 * \param kind Kind of RzBaseType to create
 */
RZ_API RZ_OWN RzBaseType *rz_type_base_type_new(RzBaseTypeKind kind) {
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
 * \brief Allocates a new instance of RzBaseType given the kind
 *
 * \param kind Kind of RzBaseType to create
 * \param cu_name Name of compilation unit the type is defined in
 */
RZ_API RZ_OWN RzBaseTypeWithMetadata *rz_type_base_type_with_metadata_new(RzBaseTypeKind kind, char *cu_name) {
	RzBaseTypeWithMetadata *type = RZ_NEW0(RzBaseTypeWithMetadata);
	type->base_type = rz_type_base_type_new(kind);
	if (cu_name) {
		type->cu_name = rz_str_dup(cu_name);
	}

	return type;
}

/**
 * \brief Frees the RzBaseTypeWithMetadata instance and all of its members
 *
 * \param type RzBaseType pointer
 */
RZ_API void rz_type_base_type_with_metadata_free(RzBaseTypeWithMetadata *type) {
	rz_type_base_type_free(type->base_type);
	free(type->cu_name);
	free(type);
}

/**
 * \brief Saves RzBaseType into the Types DB
 *
 * \param typedb Type Database instance
 * \param type RzBaseType to save
 */
RZ_API bool rz_type_db_save_base_type(const RzTypeDB *typedb, RzBaseType *type) {
	rz_return_val_if_fail(typedb && type && type->name, false);
	if (!ht_pp_insert(typedb->types, type->name, (void *)type)) {
		rz_type_base_type_free(type);
		return false;
	}
	return true;
}

/**
 * \brief Updates the base type in the Types DB, frees the old one, frees the new one if it fails
 *
 * \param typedb Type Database instance
 * \param type RzBaseType to save
 */
RZ_API bool rz_type_db_update_base_type(const RzTypeDB *typedb, RzBaseType *type) {
	rz_return_val_if_fail(typedb && type && type->name, false);
	if (!ht_pp_update(typedb->types, type->name, (void *)type)) {
		rz_type_base_type_free(type);
		return false;
	}
	return true;
}

/**
 * \brief Updates the base type in the Types DB, frees the old one, frees the new one if it fails
 *
 * \param typedb Type Database instance
 * \param type RzBaseType to save
 */
RZ_API bool rz_type_db_update_base_type_with_metadata(const RzTypeDB *typedb, RzBaseTypeWithMetadata *btype_with_mdata) {
	rz_return_val_if_fail(typedb && btype_with_mdata && btype_with_mdata->base_type && btype_with_mdata->base_type->name, false);
	bool found;
	const char* typename = btype_with_mdata->base_type->name;
	RzPVector *btypes_by_name = ht_pp_find(typedb->types, typename, &found);
	if (found) {
		rz_pvector_push(btypes_by_name, btype_with_mdata);
	} else {
		btypes_by_name = rz_pvector_new(NULL); // TODO
		rz_pvector_push(btypes_by_name, btype_with_mdata);
		if (!ht_pp_insert(typedb->types, typename, btypes_by_name)) {
			rz_type_base_type_with_metadata_free(btype_with_mdata);
			return false;
		}
	}
	return true;
}

/**
 * \brief Returns C representation as string of RzBaseType (see rz_type_db_base_type_as_pretty_string for cusom print options)
 *
 * \param typedb type database instance
 * \param btype RzBaseType to convert
 * \return char* one line C representation of the string with no semicolon at the end and no unfolding of inner types
 */
RZ_API RZ_OWN char *rz_type_db_base_type_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *btype) {
	rz_return_val_if_fail(typedb && btype, NULL);

	RzType *type = rz_type_identifier_of_base_type(typedb, btype, false);
	char *ret = rz_type_as_pretty_string(typedb, type, NULL, RZ_TYPE_PRINT_NO_END_SEMICOLON | RZ_TYPE_PRINT_ZERO_VLA, 1);
	rz_type_free(type);
	return ret;
}

/**
 * \brief Returns C representation as string of RzBaseType
 *
 * \param typedb type database instance
 * \param btype RzBaseType to convert
 * \param opts options for pretty printing (see RzTypePrintOpts)
 * \param unfold_level level of unfolding to do in case of nested structures/unions (any negative number means maximum unfolding, i.e. INT32_MAX. 0 means no unfolding, just the typename and identifier, if any)
 * \return char* pretty printed form of the base string (similar to `rz_type_as_pretty_string`, but for RzBaseType)
 */
RZ_API RZ_OWN char *rz_type_db_base_type_as_pretty_string(RZ_NONNULL const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *btype, unsigned int opts, int unfold_level) {
	rz_return_val_if_fail(typedb && btype, NULL);

	RzType *type = rz_type_identifier_of_base_type(typedb, btype, false);
	return rz_type_as_pretty_string(typedb, type, NULL, opts, unfold_level);
}

/**
 * \brief Searches for the compound RzBaseType in the types database given the name
 *
 *	Returns all types except atomic - structures, unions, enums, typedefs
 *
 * \param typedb Type Database instance
 * \param name Name of the RzBaseType
 */
RZ_API RZ_BORROW RzBaseType *rz_type_db_get_compound_type(const RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(name, NULL);
	RzBaseType *t = rz_type_db_get_base_type(typedb, name);
	if (!t) {
		RZ_LOG_ERROR("Cannot find type \"%s\"\n", name);
		return NULL;
	}
	if (t->kind == RZ_BASE_TYPE_KIND_ATOMIC) {
		RZ_LOG_ERROR("Atomic type \"%s\"\n", name);
		return NULL;
	}
	return t;
}

/**
 * \brief Recursively resolve a typedef to its pointed-to type
 *
 * The case where the typedef chain contains a loop, meaning a typedef eventually points
 * to itself, is safely handled here and NULL is returned.
 *
 * \param btype a base type that must be of kind RZ_TYPE_KIND_TYPEDEF
 * \return the first non-typedef type in the chain started by \p btype, or NULL on error or if there is a loop
 */
RZ_API RZ_BORROW RzType *rz_type_db_base_type_unwrap_typedef(RZ_NONNULL const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *btype) {
	rz_return_val_if_fail(typedb && btype && btype->kind == RZ_BASE_TYPE_KIND_TYPEDEF, NULL);
	RzPVector visited_btypes; // for detecting self-referential typedefs (maybe in multiple steps)
	rz_pvector_init(&visited_btypes, NULL);
	RzType *ttype;
	while (true) {
		if (rz_pvector_contains(&visited_btypes, (void *)btype)) {
			// loop detected
			ttype = NULL;
			goto end;
		}
		ttype = btype->type;
		rz_return_val_if_fail(ttype, NULL);
		if (ttype->kind != RZ_TYPE_KIND_IDENTIFIER) {
			goto end;
		}
		RzBaseType *next_btype = rz_type_db_get_base_type(typedb, ttype->identifier.name);
		if (!next_btype || next_btype->kind != RZ_BASE_TYPE_KIND_TYPEDEF) {
			goto end;
		}
		// push to the vector as late as possible to avoid heap usage if possible
		if (!rz_pvector_push(&visited_btypes, (void *)btype)) {
			ttype = NULL;
			goto end;
		}
		btype = next_btype;
	}
end:
	rz_pvector_fini(&visited_btypes);
	return ttype;
}
