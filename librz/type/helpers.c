// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <string.h>

/**
 * \brief Creates a new RzType indentifier from the given RzBaseType
 *
 * \param typedb Type Database instance
 * \param btype RzBaseType pointer
 * \param is_const Set the identifier to "const" if true
 */
RZ_API RZ_OWN RzType *rz_type_identifier_of_base_type(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *btype, bool is_const) {
	rz_return_val_if_fail(typedb && btype, NULL);
	RzType *type = RZ_NEW0(RzType);
	if (!type) {
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_IDENTIFIER;
	type->identifier.name = strdup(btype->name);
	type->identifier.is_const = is_const;
	switch (btype->kind) {
		case RZ_BASE_TYPE_KIND_STRUCT:
			type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_STRUCT;
			break;
		case RZ_BASE_TYPE_KIND_UNION:
			type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNION;
			break;
		case RZ_BASE_TYPE_KIND_ENUM:
			type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_ENUM;
			break;
		default:
			type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
			break;
	}
	return type;
}

/**
 * \brief Creates a new RzType indentifier from the given RzBaseType name
 *
 * \param typedb Type Database instance
 * \param name RzBaseType name
 */
RZ_API RZ_OWN RzType *rz_type_identifier_of_base_type_str(const RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	return rz_type_identifier_of_base_type(typedb, btype, false);
}

/**
 * \brief Creates a new pointer RzType from the given RzBaseType
 *
 * \param typedb Type Database instance
 * \param btype RzBaseType pointer
 * \param is_const Set the pointer to "const" if true
 */
RZ_API RZ_OWN RzType *rz_type_pointer_of_base_type(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *btype, bool is_const) {
	RzType *type = RZ_NEW0(RzType);
	if (!type) {
		return NULL;
	}
	RzType *t = rz_type_identifier_of_base_type(typedb, btype, false);
	if (!t) {
		rz_type_free(type);
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_POINTER;
	type->pointer.type = t;
	type->pointer.is_const = is_const;
	return type;
}

/**
 * \brief Creates a new pointer RzType from the given RzBaseType name
 *
 * \param typedb Type Database instance
 * \param name RzBaseType name
 * \param is_const Set the pointer to "const" if true
 */
RZ_API RZ_OWN RzType *rz_type_pointer_of_base_type_str(const RzTypeDB *typedb, RZ_NONNULL const char *name, bool is_const) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	return rz_type_pointer_of_base_type(typedb, btype, is_const);
}

/**
 * \brief Creates a new pointer RzType from the given RzType
 *
 * \param typedb Type Database instance
 * \param type RzType pointer
 * \param is_const Set the pointer to "const" if true
 */
RZ_API RZ_OWN RzType *rz_type_pointer_of_type(const RzTypeDB *typedb, RZ_NONNULL RzType *type, bool is_const) {
	rz_return_val_if_fail(typedb && type, NULL);
	if (type->kind == RZ_TYPE_KIND_IDENTIFIER) {
		return rz_type_pointer_of_base_type_str(typedb, type->identifier.name, is_const);
	}
	RzType *newtype = RZ_NEW0(RzType);
	if (!newtype) {
		return NULL;
	}
	newtype->kind = RZ_TYPE_KIND_POINTER;
	newtype->pointer.type = type;
	newtype->pointer.is_const = is_const;
	return newtype;
}

/**
 * \brief Creates a new array RzType from the given RzBaseType
 *
 * \param typedb Type Database instance
 * \param btype RzBaseType pointer
 * \param count The number of the array elements
 */
RZ_API RZ_OWN RzType *rz_type_array_of_base_type(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *btype, size_t count) {
	RzType *type = RZ_NEW0(RzType);
	if (!type) {
		return NULL;
	}
	RzType *t = rz_type_identifier_of_base_type(typedb, btype, false);
	if (!t) {
		rz_type_free(type);
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_ARRAY;
	type->array.type = t;
	type->array.count = count;
	return type;
}

/**
 * \brief Creates a new array RzType from the given RzBaseType name
 *
 * \param typedb Type Database instance
 * \param name RzBaseType name
 * \param count The number of the array elements
 */
RZ_API RZ_OWN RzType *rz_type_array_of_base_type_str(const RzTypeDB *typedb, RZ_NONNULL const char *name, size_t count) {
	rz_return_val_if_fail(typedb && name && count, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	return rz_type_array_of_base_type(typedb, btype, count);
}

/**
 * \brief Creates a new array RzType from the given RzType
 *
 * \param typedb Type Database instance
 * \param type RzType pointer
 * \param count The number of the array elements
 */
RZ_API RZ_OWN RzType *rz_type_array_of_type(const RzTypeDB *typedb, RZ_NONNULL RzType *type, size_t count) {
	RzType *newtype = RZ_NEW0(RzType);
	if (!newtype) {
		return NULL;
	}
	newtype->kind = RZ_TYPE_KIND_ARRAY;
	newtype->array.type = type;
	newtype->array.count = count;
	return type;
}

// Equivalence checking

/**
 * \brief Checks if two atomic RzTypes are equivalent
 *
 * \param typedb Type Database instance
 * \param typ1 First RzType type
 * \param typ2 Second RzType type
 */
RZ_API bool rz_type_atomic_eq(const RzTypeDB *typedb, RZ_NONNULL const RzType *typ1, RZ_NONNULL const RzType *typ2) {
	// We aim to compare only atomic types, we can't compare more complex ones for now
	rz_return_val_if_fail(typ1 && typ2, false);
	rz_return_val_if_fail(typ1->kind == RZ_TYPE_KIND_IDENTIFIER && typ2 == RZ_TYPE_KIND_IDENTIFIER, false);
	rz_return_val_if_fail(typ1->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED, false);
	rz_return_val_if_fail(typ2->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED, false);
	RzBaseType *btyp1 = rz_type_db_get_base_type(typedb, typ1->identifier.name);
	RzBaseType *btyp2 = rz_type_db_get_base_type(typedb, typ2->identifier.name);
	if (!btyp1 || !btyp2) {
		return NULL;
	}
	rz_return_val_if_fail(btyp1->kind == RZ_BASE_TYPE_KIND_ATOMIC && btyp2->kind == RZ_BASE_TYPE_KIND_ATOMIC, false);
	return btyp1->name == btyp2->name && btyp1->size == btyp2->size;
	// TODO: Should we also compare the btyp->type?
}

/**
 * \brief Checks if two atomic types (RzType and RzBaseType) are equivalent
 *
 * \param typedb Type Database instance
 * \param typ1 First RzType type
 * \param typ2 Second RzBaseType type name
 */
RZ_API bool rz_type_atomic_str_eq(const RzTypeDB *typedb, RZ_NONNULL const RzType *typ1, RZ_NONNULL const char *name) {
	// We aim to compare only atomic types, we can't compare more complex ones for now
	rz_return_val_if_fail(typ1 && name, false);
	rz_return_val_if_fail(typ1->kind == RZ_TYPE_KIND_IDENTIFIER, false);
	rz_return_val_if_fail(typ1->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED, false);
	RzBaseType *btyp1 = rz_type_db_get_base_type(typedb, typ1->identifier.name);
	RzBaseType *btyp2 = rz_type_db_get_base_type(typedb, name);
	if (!btyp1 || !btyp2) {
		return NULL;
	}
	rz_return_val_if_fail(btyp1->kind == RZ_BASE_TYPE_KIND_ATOMIC && btyp2->kind == RZ_BASE_TYPE_KIND_ATOMIC, false);
	return btyp1->name == btyp2->name && btyp1->size == btyp2->size;
	// TODO: Should we also compare the btyp->type?
}

// Here we provide helpers for some commonly used RzTypes for use within the analysis

/**
 * \brief Checks if the RzType is "void"
 *
 * \param typedb Type Database instance
 * \param type RzType type pointer
 */
RZ_API bool rz_type_atomic_is_void(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	return !strcmp(type->identifier.name, "void");
}

/**
 * \brief Checks if the RzType is signed
 *
 * \param typedb Type Database instance
 * \param type RzType type pointer
 */
RZ_API bool rz_type_atomic_is_signed(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	RzType *t = rz_type_identifier_of_base_type_str(typedb, type->identifier.name);
	if (!t) {
		return false;
	}
	return false;
}

/**
 * \brief Checks if the atomic RzType is "const"
 *
 * \param typedb Type Database instance
 * \param type RzType type pointer
 */
RZ_API bool rz_type_atomic_is_const(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	return type->identifier.is_const;
}

/**
 * \brief Checks if the atomic RzType is number
 *
 * \param typedb Type Database instance
 * \param type RzType type pointer
 */
RZ_API bool rz_type_atomic_is_num(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	RzType *t = rz_type_identifier_of_base_type_str(typedb, type->identifier.name);
	if (!t) {
		return false;
	}
	return false;
}

/**
 * \brief Checks if the pointer RzType is "const"
 *
 * \param typedb Type Database instance
 * \param type RzType type pointer
 */
RZ_API bool rz_type_pointer_is_const(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_POINTER) {
		return false;
	}
	return type->pointer.is_const;
}

static bool type_is_atomic_ptr(RZ_NONNULL const RzType *type, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(type && name, false);
	if (type->kind != RZ_TYPE_KIND_POINTER) {
		return false;
	}
	// There should not exist pointers to the empty types
	RzType *ptr = type->pointer.type;
	rz_return_val_if_fail(ptr, false);
	return ptr->kind == RZ_TYPE_KIND_IDENTIFIER && ptr->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED && !strcmp(ptr->identifier.name, name);
}

/**
 * \brief Checks if the pointer RzType is abstract pointer ("void *")
 *
 * \param type RzType type pointer
 */
RZ_API bool rz_type_is_void_ptr(RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	return type_is_atomic_ptr(type, "void");
}

/**
 * \brief Checks if the pointer RzType is a string ("char *" or "const char *")
 *
 * \param type RzType type pointer
 */
RZ_API bool rz_type_is_char_ptr(RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	return type_is_atomic_ptr(type, "char");
}

/**
 * \brief Checks if the RzType is identifier
 *
 * \param type RzType type pointer
 */
RZ_API bool rz_type_is_identifier(RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	return type->kind == RZ_TYPE_KIND_IDENTIFIER;
}

/**
 * \brief Checks if the RzType is atomic or derivative of it
 *
 * \param typedb Type Database instance
 * \param type RzType type pointer
 */
RZ_API bool rz_type_is_atomic(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	if (type->kind == RZ_TYPE_KIND_POINTER) {
		return rz_type_is_atomic(typedb, type->pointer.type);
	}
	if (type->kind == RZ_TYPE_KIND_ARRAY) {
		return rz_type_is_atomic(typedb, type->array.type);
	}
	if (type->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	if (type->identifier.kind != RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED) {
		return false;
	}
	RzBaseType *btyp = rz_type_db_get_base_type(typedb, type->identifier.name);
	if (!btyp) {
		return false;
	}
	return btyp->kind == RZ_BASE_TYPE_KIND_ATOMIC;
}

/**
 * \brief Checks if the RzType is default
 *
 * \param typedb Type Database instance
 * \param type RzType type pointer
 */
RZ_API bool rz_type_is_default(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	if (type->identifier.kind != RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED) {
		return false;
	}
	return !strcmp(type->identifier.name, typedb->target->default_type) && !type->identifier.is_const;
}

/**
 * \brief Creates a new instance of the default RzType type
 *
 * \param typedb Type Database instance
 */
RZ_API RZ_OWN RzType *rz_type_new_default(const RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, typedb->target->default_type);
	if (!btype) {
		return NULL;
	}
	return rz_type_identifier_of_base_type(typedb, btype, false);
}

/**
 * \brief If the type is unsigned it sets the sign
 *
 * \param typedb Type Database instance
 * \param type RzType type pointer
 */
RZ_API bool rz_type_atomic_set_sign(RzTypeDB *typedb, RzType *type, bool sign) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	return false;
}
