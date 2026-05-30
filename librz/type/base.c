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
 */
RZ_API RZ_BORROW RzBaseType *rz_type_db_get_base_type(const RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);

	bool found = false;
	RzBaseType *btype = ht_sp_find(typedb->types, name, &found);
	if (!found || !btype) {
		return NULL;
	}
	return btype;
}

/**
 * \brief Removes RzBaseType from the Types DB
 *
 * \param typedb Type Database instance
 * \param type RzBaseType to remove
 */
RZ_API bool rz_type_db_delete_base_type(RzTypeDB *typedb, RZ_NONNULL RzBaseType *type) {
	rz_return_val_if_fail(typedb && type && type->name, false);
	ht_sp_delete(typedb->types, type->name);
	return true;
}

struct list_kind {
	RzList /*<RzBaseType *>*/ *types;
	RzBaseTypeKind kind;
};

static bool base_type_kind_collect_cb(void *user, RZ_UNUSED const char *k, const void *v) {
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
	ht_sp_foreach(typedb->types, base_type_kind_collect_cb, &lk);
	return types;
}

static bool base_type_collect_cb(void *user, RZ_UNUSED const char *k, const void *v) {
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
	ht_sp_foreach(typedb->types, base_type_collect_cb, types);
	return types;
}

static void RzTypeStructMember_cpy(RzTypeStructMember *dst, RzTypeStructMember *src) {
	if (!(src && dst)) {
		return;
	}
	memcpy(dst, src, sizeof(RzTypeStructMember));
	dst->name = rz_str_dup(src->name);
	dst->type = rz_type_clone_shallow(src->type);
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
	dst->type = rz_type_clone_shallow(src->type);
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
	dst->type = src->type ? rz_type_clone_shallow(src->type) : NULL;

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
	RzBaseType *bt = RZ_NEW0(RzBaseType);
	if (!bt) {
		return NULL;
	}
	if (!rz_base_type_clone_into(bt, b)) {
		rz_type_base_type_free(bt);
		return NULL;
	}
	return bt;
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
 * \brief Saves RzBaseType into the Types DB
 *
 * \param typedb Type Database instance
 * \param type RzBaseType to save
 */
RZ_API bool rz_type_db_save_base_type(const RzTypeDB *typedb, RzBaseType *type) {
	rz_return_val_if_fail(typedb && type && type->name, false);
	if (!ht_sp_insert(typedb->types, type->name, (void *)type)) {
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
	if (!ht_sp_update(typedb->types, type->name, (void *)type)) {
		rz_type_base_type_free(type);
		return false;
	}
	return true;
}

/**
 * \brief Renames every reference to the type named \p from into \p to inside \p type
 *
 * Recurses through pointers, arrays and callables (return type and arguments),
 * updating the identifier name wherever it matches \p from. This is used to keep
 * type usages consistent after a base type has been renamed, both for the types
 * stored in the database and for type usages living elsewhere (e.g. the types of
 * analysis global variables).
 *
 * \param type Type expression to update in place (may be NULL)
 * \param from Old type name to look for
 * \param to New type name to set
 */
RZ_API void rz_type_rename_references(RZ_NULLABLE RzType *type, RZ_NONNULL const char *from, RZ_NONNULL const char *to) {
	rz_return_if_fail(from && to);
	if (!type) {
		return;
	}
	switch (type->kind) {
	case RZ_TYPE_KIND_IDENTIFIER:
		if (type->identifier.name && !strcmp(type->identifier.name, from)) {
			free(type->identifier.name);
			type->identifier.name = rz_str_dup(to);
		}
		break;
	case RZ_TYPE_KIND_POINTER:
		rz_type_rename_references(type->pointer.type, from, to);
		break;
	case RZ_TYPE_KIND_ARRAY:
		rz_type_rename_references(type->array.type, from, to);
		break;
	case RZ_TYPE_KIND_CALLABLE:
		if (!type->callable) {
			break;
		}
		rz_type_rename_references(type->callable->ret, from, to);
		void **it;
		rz_pvector_foreach (type->callable->args, it) {
			RzCallableArg *arg = *it;
			if (arg) {
				rz_type_rename_references(arg->type, from, to);
			}
		}
		break;
	}
}

struct base_type_rename_ctx {
	const char *from;
	const char *to;
};

static bool base_type_rename_refs_cb(void *user, RZ_UNUSED const char *k, const void *v) {
	struct base_type_rename_ctx *ctx = user;
	RzBaseType *btype = (RzBaseType *)v;
	switch (btype->kind) {
	case RZ_BASE_TYPE_KIND_STRUCT: {
		RzTypeStructMember *member;
		rz_vector_foreach (&btype->struct_data.members, member) {
			rz_type_rename_references(member->type, ctx->from, ctx->to);
		}
		break;
	}
	case RZ_BASE_TYPE_KIND_UNION: {
		RzTypeUnionMember *member;
		rz_vector_foreach (&btype->union_data.members, member) {
			rz_type_rename_references(member->type, ctx->from, ctx->to);
		}
		break;
	}
	case RZ_BASE_TYPE_KIND_ENUM:
	case RZ_BASE_TYPE_KIND_TYPEDEF:
	case RZ_BASE_TYPE_KIND_ATOMIC:
		rz_type_rename_references(btype->type, ctx->from, ctx->to);
		break;
	}
	return true;
}

static bool callable_rename_refs_cb(void *user, RZ_UNUSED const char *k, const void *v) {
	struct base_type_rename_ctx *ctx = user;
	RzCallable *callable = (RzCallable *)v;
	rz_type_rename_references(callable->ret, ctx->from, ctx->to);
	void **it;
	rz_pvector_foreach (callable->args, it) {
		RzCallableArg *arg = *it;
		if (arg) {
			rz_type_rename_references(arg->type, ctx->from, ctx->to);
		}
	}
	return true;
}

// Keep `pf` formats consistent with a base type rename: update references to the
// old name inside every stored format string (the "(name)" syntax) and re-key the
// format that was stored under the old type name, if any.
static void base_type_rename_formats(RzTypeDB *typedb, const char *from, const char *to) {
	char from_ref[256], to_ref[256];
	rz_strf(from_ref, "(%s)", from);
	rz_strf(to_ref, "(%s)", to);
	// rz_type_db_format_all returns shells with borrowed name/body pointers, so
	// snapshot the needed updates before mutating the formats hash table.
	RzList *formats = rz_type_db_format_all(typedb);
	formats->free = free;
	RzPVector renamed_names, renamed_bodies;
	rz_pvector_init(&renamed_names, free);
	rz_pvector_init(&renamed_bodies, free);
	RzListIter *it;
	RzTypeFormat *tf;
	rz_list_foreach (formats, it, tf) {
		if (tf->body && strstr(tf->body, from_ref)) {
			char *newbody = rz_str_replace(rz_str_dup(tf->body), from_ref, to_ref, 1);
			if (newbody) {
				rz_pvector_push(&renamed_names, rz_str_dup(tf->name));
				rz_pvector_push(&renamed_bodies, newbody);
			}
		}
	}
	rz_list_free(formats);
	for (size_t i = 0; i < rz_pvector_len(&renamed_names); i++) {
		const char *nm = rz_pvector_at(&renamed_names, i);
		const char *body = rz_pvector_at(&renamed_bodies, i);
		// rz_type_db_format_set does not overwrite, so delete first.
		rz_type_db_format_delete(typedb, nm);
		rz_type_db_format_set(typedb, nm, body);
	}
	rz_pvector_fini(&renamed_names);
	rz_pvector_fini(&renamed_bodies);
	const char *own_format = rz_type_db_format_get(typedb, from);
	if (own_format) {
		char *moved = rz_str_dup(own_format);
		rz_type_db_format_delete(typedb, from);
		rz_type_db_format_set(typedb, to, moved);
		free(moved);
	}
}

/**
 * \brief Renames the base type \p from into \p to in the Types DB
 *
 * Besides changing the name of the type itself, every other base type and
 * function type (callable) that references \p from by name is updated to use
 * \p to instead, so the database stays consistent after the rename. This
 * includes self-references of the renamed type, like a linked-list struct that
 * contains a pointer to itself, as well as the `pf` formats that mention the
 * type.
 *
 * \param typedb Type Database instance
 * \param from Current name of the base type to rename
 * \param to New name for the base type
 * \return true if the type was renamed, false if \p from does not exist or \p to is already in use
 */
RZ_API bool rz_type_db_rename_base_type(RzTypeDB *typedb, RZ_NONNULL const char *from, RZ_NONNULL const char *to) {
	rz_return_val_if_fail(typedb && from && to, false);
	if (RZ_STR_EQ(from, to)) {
		return true;
	}
	RzBaseType *type = rz_type_db_get_base_type(typedb, from);
	if (!type) {
		RZ_LOG_ERROR("Type \"%s\" does not exist\n", from);
		return false;
	}
	if (rz_type_db_get_base_type(typedb, to)) {
		RZ_LOG_ERROR("Type \"%s\" already exists\n", to);
		return false;
	}
	// The types hash table owns its values and frees them on deletion, so we
	// re-key the entry by inserting a clone under the new name and letting the
	// deletion of the old entry free the original.
	RzBaseType *renamed = rz_base_type_clone(type);
	if (!renamed) {
		return false;
	}
	free(renamed->name);
	renamed->name = rz_str_dup(to);
	if (!rz_type_db_save_base_type(typedb, renamed)) {
		// rz_type_db_save_base_type frees `renamed` on failure
		return false;
	}
	rz_type_db_delete_base_type(typedb, type);
	// Update every reference to the old name across all types and callables.
	struct base_type_rename_ctx ctx = { from, to };
	ht_sp_foreach(typedb->types, base_type_rename_refs_cb, &ctx);
	ht_sp_foreach(typedb->callables, callable_rename_refs_cb, &ctx);
	base_type_rename_formats(typedb, from, to);
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
	char *ret = rz_type_as_pretty_string(typedb, type, NULL, opts, unfold_level);
	rz_type_free(type);
	return ret;
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
