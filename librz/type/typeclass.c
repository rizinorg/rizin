// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <string.h>

/** \file typeclass.c
 *
 * Atomic types are split into the various type classes
 *
 * None < A default value and includes all types
 *   |
 *   + Num < Every numeric type
 *      |
 *      + Integral < Every integral (integer) type
 *      |    |
 *      |    - Signed Integral < Every signed integral type
 *      |    - Unsigned Integral < Every unsigned integral type
 *      |    - Address < Every integral type that used for memory addressing
 *      |
 *      + Floating < Every floating point type
 *
 */

inline static bool typeclass_is_num(RzTypeTypeclass t) {
	return t == RZ_TYPE_TYPECLASS_NUM || t == RZ_TYPE_TYPECLASS_INTEGRAL || t == RZ_TYPE_TYPECLASS_INTEGRAL_SIGNED || t == RZ_TYPE_TYPECLASS_INTEGRAL_UNSIGNED || t == RZ_TYPE_TYPECLASS_FLOATING || t == RZ_TYPE_TYPECLASS_ADDRESS;
}

inline static bool typeclass_is_integal(RzTypeTypeclass t) {
	return t == RZ_TYPE_TYPECLASS_INTEGRAL || t == RZ_TYPE_TYPECLASS_INTEGRAL_SIGNED || t == RZ_TYPE_TYPECLASS_INTEGRAL_UNSIGNED || t == RZ_TYPE_TYPECLASS_ADDRESS;
}

/**
 * \brief Returns the string representation of a typeclass
 *
 * \param typeclass A typeclass
 */
RZ_API RZ_BORROW const char *rz_type_typeclass_as_string(RzTypeTypeclass typeclass) {
	switch (typeclass) {
	case RZ_TYPE_TYPECLASS_NUM:
		return "Num";
	case RZ_TYPE_TYPECLASS_INTEGRAL:
		return "Integral";
	case RZ_TYPE_TYPECLASS_FLOATING:
		return "Floating";
	case RZ_TYPE_TYPECLASS_ADDRESS:
		return "Address";
	case RZ_TYPE_TYPECLASS_INTEGRAL_SIGNED:
		return "Signed Integral";
	case RZ_TYPE_TYPECLASS_INTEGRAL_UNSIGNED:
		return "Unsigned Integral";
	case RZ_TYPE_TYPECLASS_NONE:
		return "None";
	default:
		rz_warn_if_reached();
	}
	return "None";
}

/**
 * \brief Returns the typeclass from the string name of it
 *
 * \param typeclass A typeclass name
 */
RZ_API RzTypeTypeclass rz_type_typeclass_from_string(RZ_NONNULL const char *typeclass) {
	rz_return_val_if_fail(typeclass && RZ_STR_ISNOTEMPTY(typeclass), RZ_TYPE_TYPECLASS_NONE);

	if (!strcmp(typeclass, "Integral")) {
		return RZ_TYPE_TYPECLASS_INTEGRAL;
	} else if (!strcmp(typeclass, "Signed Integral")) {
		return RZ_TYPE_TYPECLASS_INTEGRAL_SIGNED;
	} else if (!strcmp(typeclass, "Unsigned Integral")) {
		return RZ_TYPE_TYPECLASS_INTEGRAL_UNSIGNED;
	} else if (!strcmp(typeclass, "Floating")) {
		return RZ_TYPE_TYPECLASS_FLOATING;
	} else if (!strcmp(typeclass, "Address")) {
		return RZ_TYPE_TYPECLASS_ADDRESS;
	} else if (!strcmp(typeclass, "Num")) {
		return RZ_TYPE_TYPECLASS_NUM;
	}
	return RZ_TYPE_TYPECLASS_NONE;
}

inline static bool get_base_type_typeclass(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type, RZ_NONNULL RzTypeTypeclass *typeclass) {
	rz_return_val_if_fail(type && typeclass, false);
	*typeclass = type->attrs & RZ_TYPE_ATTRIBUTE_TYPECLASS_MASK;
	if (*typeclass < RZ_TYPE_TYPECLASS_INVALID) {
		return true;
	}
	// If the type is typedef, we check the underlying type all the way down
	if (*typeclass == 0 && type->kind == RZ_BASE_TYPE_KIND_TYPEDEF) {
		// We do not treat pointers and arrays as the same typeclass
		if (type->type->kind != RZ_TYPE_KIND_IDENTIFIER) {
			return false;
		}
		const char *identifier = rz_type_identifier(type->type);
		if (!identifier) {
			return false;
		}
		RzBaseType *t = rz_type_db_get_base_type(typedb, identifier);
		if (!t) {
			return false;
		}
		return get_base_type_typeclass(typedb, t, typeclass);
	}
	return false;
}

inline static bool get_type_typeclass(const RzTypeDB *typedb, RZ_NONNULL const RzType *type, RzTypeTypeclass *typeclass) {
	rz_return_val_if_fail(type && typeclass, false);
	const char *identifier = rz_type_identifier(type);
	if (!identifier) {
		return false;
	}
	RzBaseType *t = rz_type_db_get_base_type(typedb, identifier);
	if (!t) {
		return false;
	}
	return get_base_type_typeclass(typedb, t, typeclass);
}

inline static bool check_base_type_typeclass(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type, RzTypeTypeclass typeclass) {
	rz_return_val_if_fail(type, false);
	RzTypeTypeclass tclass;
	if (!get_base_type_typeclass(typedb, type, &tclass)) {
		return false;
	}
	return tclass == typeclass;
}

inline static bool check_type_typeclass(const RzTypeDB *typedb, RZ_NONNULL const RzType *type, RzTypeTypeclass typeclass) {
	rz_return_val_if_fail(type, false);
	RzTypeTypeclass tclass;
	if (!get_type_typeclass(typedb, type, &tclass)) {
		return false;
	}
	return tclass == typeclass;
}

/**
 * \brief Gets the base type class
 *
 * \param typedb Type Database instance
 * \param type RzBaseType type pointer
 */
RZ_API RzTypeTypeclass rz_base_type_typeclass(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type) {
	rz_return_val_if_fail(type, false);
	RzTypeTypeclass tclass = RZ_TYPE_TYPECLASS_INVALID;
	get_base_type_typeclass(typedb, type, &tclass);
	return tclass;
}

/**
 * \brief Gets the type class
 *
 * \param typedb Type Database instance
 * \param type RzBaseType type pointer
 */
RZ_API RzTypeTypeclass rz_type_typeclass(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	RzTypeTypeclass tclass = RZ_TYPE_TYPECLASS_INVALID;
	get_type_typeclass(typedb, type, &tclass);
	return tclass;
}

/**
 * \brief Checks if the RzBaseType is Num typeclass
 *
 * \param typedb Type Database instance
 * \param type RzBaseType type pointer
 */
RZ_API bool rz_base_type_is_num(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type) {
	rz_return_val_if_fail(type, false);
	RzTypeTypeclass tclass;
	if (!get_base_type_typeclass(typedb, type, &tclass)) {
		return false;
	}
	return typeclass_is_num(tclass);
}

/**
 * \brief Checks if the RzType is Num typeclass
 *
 * \param typedb Type Database instance
 * \param type RzType type pointer
 */
RZ_API bool rz_type_is_num(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	RzTypeTypeclass tclass;
	if (!get_type_typeclass(typedb, type, &tclass)) {
		return false;
	}
	return typeclass_is_num(tclass);
}

/**
 * \brief Checks if the RzBaseType is Integral typeclass
 *
 * \param typedb Type Database instance
 * \param type RzBaseType type pointer
 */
RZ_API bool rz_base_type_is_integral(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type) {
	rz_return_val_if_fail(type, false);
	RzTypeTypeclass tclass;
	if (!get_base_type_typeclass(typedb, type, &tclass)) {
		return false;
	}
	return typeclass_is_integal(tclass);
}

/**
 * \brief Checks if the RzType is Integral typeclass
 *
 * \param typedb Type Database instance
 * \param type RzType type pointer
 */
RZ_API bool rz_type_is_integral(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	RzTypeTypeclass tclass;
	if (!get_type_typeclass(typedb, type, &tclass)) {
		return false;
	}
	return typeclass_is_integal(tclass);
}

/**
 * \brief Checks if the RzBaseType is Floating typeclass
 *
 * \param typedb Type Database instance
 * \param type RzBaseType type pointer
 */
RZ_API bool rz_base_type_is_floating(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type) {
	rz_return_val_if_fail(type, false);
	return check_base_type_typeclass(typedb, type, RZ_TYPE_TYPECLASS_FLOATING);
}

/**
 * \brief Checks if the RzType is Floating typeclass
 *
 * \param typedb Type Database instance
 * \param type RzType type pointer
 */
RZ_API bool rz_type_is_floating(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	return check_type_typeclass(typedb, type, RZ_TYPE_TYPECLASS_FLOATING);
}

/**
 * \brief Checks if the RzBaseType is Integral and Signed typeclass
 *
 * \param typedb Type Database instance
 * \param type RzBaseType type pointer
 */
RZ_API bool rz_base_type_is_integral_signed(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type) {
	rz_return_val_if_fail(type, false);
	return check_base_type_typeclass(typedb, type, RZ_TYPE_TYPECLASS_INTEGRAL_SIGNED);
}

/**
 * \brief Checks if the RzType is Integral and Signed typeclass
 *
 * \param typedb Type Database instance
 * \param type RzType type pointer
 */
RZ_API bool rz_type_is_integral_signed(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	return check_type_typeclass(typedb, type, RZ_TYPE_TYPECLASS_INTEGRAL_SIGNED);
}

/**
 * \brief Checks if the RzBaseType is Integral and Unsigned typeclass
 *
 * \param typedb Type Database instance
 * \param type RzBaseType type pointer
 */
RZ_API bool rz_base_type_is_integral_unsigned(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type) {
	rz_return_val_if_fail(type, false);
	return check_base_type_typeclass(typedb, type, RZ_TYPE_TYPECLASS_INTEGRAL_UNSIGNED);
}

/**
 * \brief Checks if the RzType is Integral and Unsigned typeclass
 *
 * \param typedb Type Database instance
 * \param type RzType type pointer
 */
RZ_API bool rz_type_is_integral_unsigned(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	return check_type_typeclass(typedb, type, RZ_TYPE_TYPECLASS_INTEGRAL_UNSIGNED);
}

struct list_typeclass {
	const RzTypeDB *typedb;
	RzList /*<RzBaseType *>*/ *types;
	RzTypeTypeclass typeclass;
};

static bool base_type_typeclass_collect_cb(void *user, RZ_UNUSED const char *k, const void *v) {
	struct list_typeclass *l = user;
	RzBaseType *btype = (RzBaseType *)v;
	RzTypeTypeclass typeclass;
	if (!get_base_type_typeclass(l->typedb, btype, &typeclass)) {
		return false;
	}
	if (l->typeclass == typeclass) {
		rz_list_append(l->types, btype);
	}
	return true;
}

struct list_typeclass_size {
	const RzTypeDB *typedb;
	RzList /*<RzBaseType *>*/ *types;
	RzTypeTypeclass typeclass;
	size_t size;
};

static bool base_type_typeclass_sized_collect_cb(void *user, RZ_UNUSED const char *k, const void *v) {
	struct list_typeclass_size *l = user;
	RzBaseType *btype = (RzBaseType *)v;
	RzTypeTypeclass typeclass;
	if (!get_base_type_typeclass(l->typedb, btype, &typeclass)) {
		return false;
	}
	if (l->typeclass == typeclass && l->size == btype->size) {
		rz_list_append(l->types, btype);
	}
	return true;
}

/**
 * \brief Returns the list of all base types given the typeclass
 *
 * \param typedb Type Database instance
 * \param typeclass typeclass (cannot be None)
 */
RZ_API RZ_OWN RzList /*<RzBaseType *>*/ *rz_type_typeclass_get_all(const RzTypeDB *typedb, RzTypeTypeclass typeclass) {
	rz_return_val_if_fail(typedb && typeclass != RZ_TYPE_TYPECLASS_NONE, NULL);
	rz_return_val_if_fail(typeclass < RZ_TYPE_TYPECLASS_INVALID, NULL);
	RzList *types = rz_list_new();
	struct list_typeclass lt = { typedb, types, typeclass };
	ht_sp_foreach_cb(typedb->types, base_type_typeclass_collect_cb, &lt);
	return types;
}

/**
 * \brief Returns the list of all base types given the typeclass and size
 *
 * \param typedb Type Database instance
 * \param typeclass typeclass (cannot be None)
 * \param size The bitsize of a type to select from
 */
RZ_API RZ_OWN RzList /*<RzBaseType *>*/ *rz_type_typeclass_get_all_sized(const RzTypeDB *typedb, RzTypeTypeclass typeclass, size_t size) {
	rz_return_val_if_fail(typedb && typeclass != RZ_TYPE_TYPECLASS_NONE, NULL);
	rz_return_val_if_fail(size && typeclass < RZ_TYPE_TYPECLASS_INVALID, NULL);
	RzList *types = rz_list_new();
	struct list_typeclass_size lt = { typedb, types, typeclass, size };
	ht_sp_foreach_cb(typedb->types, base_type_typeclass_sized_collect_cb, &lt);
	return types;
}

/**
 * \brief Returns the default base type given the typeclass and size
 *
 * \param typedb Type Database instance
 * \param typeclass typeclass (cannot be None)
 * \param size The bitsize of a type to select from
 */
RZ_API RZ_OWN RzBaseType *rz_type_typeclass_get_default_sized(const RzTypeDB *typedb, RzTypeTypeclass typeclass, size_t size) {
	rz_return_val_if_fail(typedb && typeclass != RZ_TYPE_TYPECLASS_NONE, NULL);
	rz_return_val_if_fail(size && typeclass < RZ_TYPE_TYPECLASS_INVALID, NULL);
	RzList *l = rz_type_typeclass_get_all_sized(typedb, typeclass, size);
	if (!l || rz_list_empty(l)) {
		return NULL;
	}
	RzBaseType *ret = rz_list_pop(l);
	rz_list_free(l);
	return ret;
}
