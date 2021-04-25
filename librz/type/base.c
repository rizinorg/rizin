// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <string.h>

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

// returns NULL if name is not found or any failure happened
RZ_API RZ_BORROW RzBaseType *rz_type_db_get_base_type(const RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);

	bool found = false;
	RzBaseType *btype = ht_pp_find(typedb->types, name, &found);
	if (!found || !btype) {
		eprintf("Cannot find type \"%s\"\n", name);
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
	rz_return_val_if_fail(typedb && type && type->name, NULL);
	ht_pp_delete(typedb->types, type->name);
	return true;
}

struct list_kind {
	RzList *types;
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
RZ_API RZ_OWN RzList /* RzBaseType */ *rz_type_db_get_base_types_of_kind(const RzTypeDB *typedb, RzBaseTypeKind kind) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *types = rz_list_new();
	struct list_kind lk = { types, kind };
	ht_pp_foreach(typedb->types, base_type_kind_collect_cb, &lk);
	return types;
}

static bool base_type_collect_cb(void *user, const void *k, const void *v) {
	rz_return_val_if_fail(user && k && v, false);
	RzList *l = user;
	rz_list_append(l, v);
	return true;
}

/**
 * \brief Returns the list of all basic types
 *
 * \param typedb Types Database instance
 */
RZ_API RZ_OWN RzList /* RzBaseType */ *rz_type_db_get_base_types(const RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *types = rz_list_new();
	ht_pp_foreach(typedb->types, base_type_collect_cb, types);
	return types;
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
	ht_pp_insert(typedb->types, type->name, type);
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
