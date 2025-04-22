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
	type->identifier.name = rz_str_dup(btype->name);
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
	return newtype;
}

/**
 * \brief Creates a new callable RzType of the given callable
 *
 * \param callable ownership transferred into the returned type
 */
RZ_API RZ_OWN RzType *rz_type_callable(RZ_NONNULL RZ_OWN RzCallable *callable) {
	rz_return_val_if_fail(callable, NULL);
	RzType *newtype = RZ_NEW0(RzType);
	if (!newtype) {
		return NULL;
	}
	newtype->kind = RZ_TYPE_KIND_CALLABLE;
	newtype->callable = callable;
	return newtype;
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
	rz_return_val_if_fail(typ1->kind == RZ_TYPE_KIND_IDENTIFIER && typ2->kind == RZ_TYPE_KIND_IDENTIFIER, false);
	rz_return_val_if_fail(typ1->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED, false);
	rz_return_val_if_fail(typ2->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED, false);
	rz_return_val_if_fail(typ1->identifier.name, false);
	rz_return_val_if_fail(typ2->identifier.name, false);
	RzBaseType *btyp1 = rz_type_db_get_base_type(typedb, typ1->identifier.name);
	RzBaseType *btyp2 = rz_type_db_get_base_type(typedb, typ2->identifier.name);
	if (!btyp1 || !btyp2) {
		return false;
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
	rz_return_val_if_fail(typ1->identifier.name, false);
	RzBaseType *btyp1 = rz_type_db_get_base_type(typedb, typ1->identifier.name);
	RzBaseType *btyp2 = rz_type_db_get_base_type(typedb, name);
	if (!btyp1 || !btyp2) {
		return false;
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

static bool type_is_atomic_ptr_nested(RZ_NONNULL const RzType *type, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(type && name, false);
	if (type->kind != RZ_TYPE_KIND_POINTER) {
		return false;
	}
	// There should not exist pointers to the empty types
	RzType *ptr = type->pointer.type;
	rz_return_val_if_fail(ptr, false);
	if (ptr->kind == RZ_TYPE_KIND_POINTER) {
		return type_is_atomic_ptr_nested(ptr, name);
	}
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
 * \brief Checks if the pointer RzType is a nested abstract pointer ("void **", "vpod ***", etc)
 *
 * \param type RzType type pointer
 */
RZ_API bool rz_type_is_void_ptr_nested(RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	return type_is_atomic_ptr_nested(type, "void");
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
 * \brief Checks if the pointer RzType is a nested pointer of string ("char **", "char ***", etc)
 *
 * \param type RzType type pointer
 */
RZ_API bool rz_type_is_char_ptr_nested(RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	return type_is_atomic_ptr_nested(type, "char");
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
 * \brief Checks if the RzType is strictly atomic
 *
 * \param typedb Type Database instance
 * \param type RzType type pointer
 */
RZ_API bool rz_type_is_strictly_atomic(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	if (type->identifier.kind != RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED) {
		return false;
	}
	rz_return_val_if_fail(type->identifier.name, false);
	RzBaseType *btyp = rz_type_db_get_base_type(typedb, type->identifier.name);
	if (!btyp) {
		return false;
	}
	return btyp->kind == RZ_BASE_TYPE_KIND_ATOMIC;
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
	rz_return_val_if_fail(type->identifier.name, false);
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
RZ_API bool rz_type_integral_set_sign(const RzTypeDB *typedb, RZ_NONNULL RzType **type, bool sign) {
	rz_return_val_if_fail(type && *type, false);
	RzType *t = *type;
	if (t->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	if (rz_type_is_integral(typedb, t)) {
		const char *identifier = rz_type_identifier(t);
		if (!identifier) {
			return false;
		}
		RzBaseType *btype = rz_type_db_get_base_type(typedb, identifier);
		if (!btype) {
			return false;
		}
		RzTypeTypeclass typesubclass = sign ? RZ_TYPE_TYPECLASS_INTEGRAL_SIGNED : RZ_TYPE_TYPECLASS_INTEGRAL_UNSIGNED;
		// We only change typesubclass if it's different from the current one
		if (rz_base_type_typeclass(typedb, btype) == typesubclass) {
			return true;
		}
		size_t typesize = rz_type_db_base_get_bitsize(typedb, btype);
		RzBaseType *signedbtype = rz_type_typeclass_get_default_sized(typedb, typesubclass, typesize);
		if (!signedbtype) {
			return false;
		}
		RzType *signedtype = rz_type_identifier_of_base_type(typedb, signedbtype, false);
		if (!signedtype) {
			return false;
		}
		rz_type_free(t);
		*type = signedtype;
	}
	return false;
}

/**
 * \brief RzTypeCond enum to string
 *
 * \param cc RzTypeCond
 * \return const char *
 */
RZ_API RZ_BORROW const char *rz_type_cond_tostring(RzTypeCond cc) {
	switch (cc) {
	case RZ_TYPE_COND_EQ: return "eq";
	case RZ_TYPE_COND_NV: return "nv";
	case RZ_TYPE_COND_NE: return "ne";
	case RZ_TYPE_COND_HS: return "hs";
	case RZ_TYPE_COND_LO: return "lo";
	case RZ_TYPE_COND_MI: return "mi";
	case RZ_TYPE_COND_PL: return "pl";
	case RZ_TYPE_COND_VS: return "vs";
	case RZ_TYPE_COND_VC: return "vc";
	case RZ_TYPE_COND_HI: return "hi";
	case RZ_TYPE_COND_LS: return "ls";
	case RZ_TYPE_COND_GE: return "ge";
	case RZ_TYPE_COND_LT: return "lt";
	case RZ_TYPE_COND_GT: return "gt";
	case RZ_TYPE_COND_LE: return "le";
	case RZ_TYPE_COND_AL: return "al";
	case RZ_TYPE_COND_HEX_SCL_TRUE: return "scl-t";
	case RZ_TYPE_COND_HEX_SCL_FALSE: return "scl-f";
	case RZ_TYPE_COND_HEX_VEC_TRUE: return "vec-t";
	case RZ_TYPE_COND_HEX_VEC_FALSE: return "vec-f";
	case RZ_TYPE_COND_EXCEPTION: return "excptn";
	}
	return "??";
}

/**
 * \brief return the inverted condition
 *
 * \param cond RzTypeCond
 * \return RzTypeCond
 */
RZ_API RzTypeCond rz_type_cond_invert(RzTypeCond cond) {
	switch (cond) {
	case RZ_TYPE_COND_LE:
		return RZ_TYPE_COND_GT;
	case RZ_TYPE_COND_LT:
		return RZ_TYPE_COND_GE;
	case RZ_TYPE_COND_GE:
		return RZ_TYPE_COND_LT;
	case RZ_TYPE_COND_GT:
		return RZ_TYPE_COND_LE;
	case RZ_TYPE_COND_AL:
		return RZ_TYPE_COND_NV;
	case RZ_TYPE_COND_NE:
		return RZ_TYPE_COND_EQ;
	case RZ_TYPE_COND_EQ:
		return RZ_TYPE_COND_NE;
	default:
		rz_warn_if_reached();
		break;
	}
	return 0;
}
/**
 * \brief evaluate the type condition on the arguments and return a bool accordingly.
 *
 * \param cond RzTypeCond
 * \param arg0
 * \param arg1
 * \return bool
 */
RZ_API bool rz_type_cond_eval(RzTypeCond cond, st64 arg0, st64 arg1) {
	switch (cond) {
	case RZ_TYPE_COND_EQ: return arg0 == arg1;
	case RZ_TYPE_COND_NE: return arg0 != arg1;
	case RZ_TYPE_COND_GE: return arg0 >= arg1;
	case RZ_TYPE_COND_GT: return arg0 > arg1;
	case RZ_TYPE_COND_LE: return arg0 <= arg1;
	case RZ_TYPE_COND_LT: return arg0 < arg1;
	default: return false;
	}
	return false;
}

/**
 * \brief Same as rz_type_cond_eval, but it assumes \p arg1 to be 0.
 *
 * \param cond RzTypeCond
 * \param arg0
 * \return bool
 */
RZ_API bool rz_type_cond_eval_single(RzTypeCond cond, st64 arg0) {
	switch (cond) {
	case RZ_TYPE_COND_EQ: return !arg0;
	case RZ_TYPE_COND_NE: return arg0;
	case RZ_TYPE_COND_GT: return arg0 > 0;
	case RZ_TYPE_COND_GE: return arg0 >= 0;
	case RZ_TYPE_COND_LT: return arg0 < 0;
	case RZ_TYPE_COND_LE: return arg0 <= 0;
	default: return false;
	}
	return false;
}
