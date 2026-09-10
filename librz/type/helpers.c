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
		rz_type_callable_free(callable);
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
 * \brief Checks if the pointer RzType is a nested abstract pointer ("void **", "void ***", etc)
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
 * \brief Parse a type condition from its string form
 *
 * Accepts both the short mnemonic form returned by \ref rz_type_cond_tostring
 * (e.g. "eq", "ne", "ge", "gt", "le", "lt") and the usual comparison symbols
 * ("==", "!=", ">=", ">", "<=", "<").
 *
 * \param s the string to parse
 * \return the parsed RzTypeCond, or RZ_TYPE_COND_AL when \p s is not recognized
 */
RZ_API RzTypeCond rz_type_cond_fromstring(RZ_NONNULL const char *s) {
	rz_return_val_if_fail(s, RZ_TYPE_COND_AL);
	if (RZ_STR_EQ(s, "eq") || RZ_STR_EQ(s, "==") || RZ_STR_EQ(s, "=")) {
		return RZ_TYPE_COND_EQ;
	} else if (RZ_STR_EQ(s, "ne") || RZ_STR_EQ(s, "!=")) {
		return RZ_TYPE_COND_NE;
	} else if (RZ_STR_EQ(s, "ge") || RZ_STR_EQ(s, ">=")) {
		return RZ_TYPE_COND_GE;
	} else if (RZ_STR_EQ(s, "gt") || RZ_STR_EQ(s, ">")) {
		return RZ_TYPE_COND_GT;
	} else if (RZ_STR_EQ(s, "le") || RZ_STR_EQ(s, "<=")) {
		return RZ_TYPE_COND_LE;
	} else if (RZ_STR_EQ(s, "lt") || RZ_STR_EQ(s, "<")) {
		return RZ_TYPE_COND_LT;
	}
	return RZ_TYPE_COND_AL;
}

/**
 * \brief A single bounded interval being assembled from a list of constraints
 *
 * Each side is optional: an interval may have only a lower bound (e.g. "> 0"),
 * only an upper bound (e.g. "<= 9") or both. The \p incl flags record whether
 * the respective bound is inclusive (>=, <=) or exclusive (>, <).
 */
typedef struct {
	bool has_low; ///< a lower bound (>, >=) was seen
	bool low_incl; ///< the lower bound is inclusive (>=)
	ut64 low; ///< the lower bound value
	bool has_high; ///< an upper bound (<, <=) was seen
	bool high_incl; ///< the upper bound is inclusive (<=)
	ut64 high; ///< the upper bound value
} TypeInterval;

/**
 * \brief Append the textual form of a single interval to \p sb
 *
 * An empty interval is one that no value can satisfy (the lower bound is above
 * the upper bound, or equal to it while at least one side is exclusive). The
 * degenerate interval [x, x] (both bounds inclusive and equal) is rendered as
 * the equality "== x", matching \ref RZ_TYPE_COND_EQ.
 *
 * \param sb the string buffer to append to
 * \param iv the interval to render
 * \param first set to false once the first term has been written; used to
 *        insert the " || " separator between alternative intervals
 * \return false if the interval is empty and thus cannot be represented
 */
static bool type_interval_append(RzStrBuf *sb, RZ_NONNULL const TypeInterval *iv, bool *first) {
	if (!iv->has_low && !iv->has_high) {
		return true; // nothing pending
	}
	if (iv->has_low && iv->has_high) {
		if (iv->low > iv->high) {
			return false; // empty interval
		}
		if (iv->low == iv->high && !(iv->low_incl && iv->high_incl)) {
			return false; // empty interval, e.g. (x, x] or [x, x)
		}
	}
	if (!*first) {
		rz_strbuf_append(sb, " || ");
	}
	*first = false;
	if (iv->has_low && iv->has_high && iv->low != iv->high) {
		rz_strbuf_appendf(sb, "%c0x%" PFMT64x ", 0x%" PFMT64x "%c", iv->low_incl ? '[' : '(', iv->low, iv->high, iv->high_incl ? ']' : ')');
		return true;
	}
	if (iv->has_low && iv->has_high && iv->low == iv->high) {
		// a single allowed value, [x, x] is the same as == x
		rz_strbuf_appendf(sb, "== 0x%" PFMT64x, iv->low);
		return true;
	}
	if (iv->has_low) {
		rz_strbuf_appendf(sb, "%s 0x%" PFMT64x, iv->low_incl ? ">=" : ">", iv->low);
	}
	if (iv->has_high) {
		rz_strbuf_appendf(sb, "%s 0x%" PFMT64x, iv->high_incl ? "<=" : "<", iv->high);
	}
	return true;
}

/**
 * \brief Render a list of interval constraints into a human-readable string
 *
 * The constraints are interpreted as a disjunction (joined by "||") of bounded
 * intervals, where each interval is a conjunction (joined by "&&") of a lower
 * bound (>, >=) and/or an upper bound (<, <=). This matches the shape produced
 * by the variable type inference for range checks such as "x > 0 && x <= 9" or
 * several alternative ranges. An exact \ref RZ_TYPE_COND_EQ constraint, or an
 * interval that collapses to a single value [x, x], is rendered as "== x".
 *
 * Constraints that do not form consistent intervals (for example a variable
 * that is compared against many unrelated constants, as in a switch table, or
 * an interval whose lower bound is not below its upper bound) cannot be
 * represented as a meaningful range. In that case, and when there is no
 * interval-style constraint at all, NULL is returned so that callers do not
 * display misleading information.
 *
 * \param constraints vector of \ref RzTypeConstraint
 * \return an owned string, or NULL when there is nothing meaningful to show
 */
RZ_API RZ_OWN char *rz_type_interval_constraints_as_string(RZ_NONNULL const RzVector /*<RzTypeConstraint>*/ *constraints) {
	rz_return_val_if_fail(constraints, NULL);
	RzStrBuf sb = { 0 };
	bool first = true; // whether the first term still has to be written
	TypeInterval cur = { 0 }; // the interval currently being assembled
	RzVector /*<ut64>*/ eqs;
	rz_vector_init(&eqs, sizeof(ut64), NULL, NULL);

#define FLUSH_EQS() \
	do { \
		if (!rz_vector_empty(&eqs)) { \
			if (!first) rz_strbuf_append(&sb, " || "); \
			first = false; \
			rz_strbuf_append(&sb, "{"); \
			void *val_it; \
			bool first_eq = true; \
			rz_vector_foreach(&eqs, val_it) { \
				rz_strbuf_appendf(&sb, "%s0x%" PFMT64x, first_eq ? "" : ", ", *(ut64 *)val_it); \
				first_eq = false; \
			} \
			rz_strbuf_append(&sb, "}"); \
			rz_vector_clear(&eqs); \
		} \
	} while (0)

	RzTypeConstraint *c;
	rz_vector_foreach (constraints, c) {
		bool is_lower, incl;
		switch (c->cond) {
		case RZ_TYPE_COND_GE: is_lower = true, incl = true; break;
		case RZ_TYPE_COND_GT: is_lower = true, incl = false; break;
		case RZ_TYPE_COND_LE: is_lower = false, incl = true; break;
		case RZ_TYPE_COND_LT: is_lower = false, incl = false; break;
		case RZ_TYPE_COND_EQ:
			if (!type_interval_append(&sb, &cur, &first)) {
				goto invalid;
			}
			cur = (TypeInterval){ 0 };
			rz_vector_push(&eqs, &c->val);
			continue;
		default: continue; // not an interval bound, ignore
		}

		FLUSH_EQS();
		// A second bound on the same side cannot extend the current interval.
		// If the interval is already complete it opens a new alternative,
		// otherwise the constraints are inconsistent.
		bool *have_side = is_lower ? &cur.has_low : &cur.has_high;
		if (*have_side) {
			if (cur.has_low && cur.has_high) {
				if (!type_interval_append(&sb, &cur, &first)) {
					goto invalid;
				}
				cur = (TypeInterval){ 0 };
			} else {
				goto invalid;
			}
		}
		if (is_lower) {
			cur.has_low = true;
			cur.low_incl = incl;
			cur.low = c->val;
		} else {
			cur.has_high = true;
			cur.high_incl = incl;
			cur.high = c->val;
		}
	}
	if (!type_interval_append(&sb, &cur, &first)) {
		goto invalid;
	}
	FLUSH_EQS();

	if (first) {
		// no interval-style constraint produced any output
		rz_vector_fini(&eqs);
		rz_strbuf_fini(&sb);
		return NULL;
	}
	rz_vector_fini(&eqs);
	return rz_strbuf_drain_nofree(&sb);
invalid:
	rz_vector_fini(&eqs);
	rz_strbuf_fini(&sb);
	return NULL;
}

/**
 * \brief Parse a textual list of interval constraints into \p constraints
 *
 * This is the inverse of \ref rz_type_interval_constraints_as_string. The input
 * is a comma-separated list of comparisons, each one of the operators ==, !=,
 * <, <=, >, >= (in symbol form like ">=10" or mnemonic form like "ge 10", as
 * accepted by \ref rz_type_cond_fromstring) followed by a value. Values are
 * evaluated with \ref rz_num_math without a number environment, so they must be
 * literals or constant expressions. Any other operator makes the whole parse
 * fail. Note that while "== x" round-trips through
 * \ref rz_type_interval_constraints_as_string as the degenerate interval
 * [x, x], the inequality "!= x" is stored but is not part of the interval
 * rendering, as it does not describe a range.
 *
 * \param str the textual constraints, e.g. ">0,<=9", "gt 0, le 9" or "== 5"
 * \param constraints an initialized vector of \ref RzTypeConstraint to fill
 * \return true on success, false on a parse error (vector may be partially filled)
 */
static void skip_whitespace(const char **p) {
	while (**p && isspace((unsigned char)**p)) {
		(*p)++;
	}
}

static bool parse_value(const char **p, ut64 *val) {
	skip_whitespace(p);
	if (!**p) {
		return false;
	}
	const char *start = *p;
	int parens = 0;
	while (**p) {
		if (**p == '(') {
			parens++;
		} else if (**p == ')') {
			if (parens == 0) {
				break;
			}
			parens--;
		} else if (parens == 0 && (**p == ',' || **p == ']' || **p == '}' || strncmp(*p, "||", 2) == 0)) {
			break;
		}
		(*p)++;
	}
	if (*p == start) {
		return false;
	}
	char *valstr = rz_str_ndup(start, *p - start);
	if (!valstr) {
		return false;
	}
	*val = rz_num_math(NULL, valstr);
	free(valstr);
	return true;
}

static bool parse_set(const char **p, RZ_NONNULL RzVector /*<RzTypeConstraint>*/ *constraints) {
	(*p)++;
	while (**p) {
		ut64 val;
		if (!parse_value(p, &val)) {
			return false;
		}
		RzTypeConstraint c = { .cond = RZ_TYPE_COND_EQ, .val = val };
		rz_vector_push(constraints, &c);
		skip_whitespace(p);
		if (**p == '}') {
			(*p)++;
			break;
		} else if (**p == ',') {
			(*p)++;
		} else {
			return false;
		}
	}
	return true;
}

static bool parse_interval(const char **p, RZ_NONNULL RzVector /*<RzTypeConstraint>*/ *constraints) {
	char open_bracket = **p;
	(*p)++;
	ut64 val1, val2;
	if (!parse_value(p, &val1)) {
		return false;
	}
	skip_whitespace(p);
	if (**p != ',') {
		return false;
	}
	(*p)++;
	if (!parse_value(p, &val2)) {
		return false;
	}
	skip_whitespace(p);
	char close_bracket = **p;
	if (close_bracket != ']' && close_bracket != ')') {
		return false;
	}
	(*p)++;
	RzTypeConstraint c1 = { .cond = open_bracket == '[' ? RZ_TYPE_COND_GE : RZ_TYPE_COND_GT, .val = val1 };
	RzTypeConstraint c2 = { .cond = close_bracket == ']' ? RZ_TYPE_COND_LE : RZ_TYPE_COND_LT, .val = val2 };
	rz_vector_push(constraints, &c1);
	rz_vector_push(constraints, &c2);
	return true;
}

static bool parse_operator_constraint(const char **p, RZ_NONNULL RzVector /*<RzTypeConstraint>*/ *constraints) {
	const char *start = *p;
	if (**p == '<' || **p == '>' || **p == '=' || **p == '!') {
		while (**p == '<' || **p == '>' || **p == '=' || **p == '!') {
			(*p)++;
		}
	} else if (isalpha((unsigned char)**p)) {
		while (isalpha((unsigned char)**p)) {
			(*p)++;
		}
	}
	if (*p == start) {
		return false;
	}
	char *op = rz_str_ndup(start, *p - start);
	RzTypeCond cond = rz_type_cond_fromstring(op);
	free(op);
	if (cond != RZ_TYPE_COND_LE && cond != RZ_TYPE_COND_LT &&
		cond != RZ_TYPE_COND_GE && cond != RZ_TYPE_COND_GT &&
		cond != RZ_TYPE_COND_EQ && cond != RZ_TYPE_COND_NE) {
		return false;
	}
	ut64 val;
	if (!parse_value(p, &val)) {
		return false;
	}
	RzTypeConstraint c = { .cond = cond, .val = val };
	rz_vector_push(constraints, &c);
	return true;
}

RZ_API bool rz_type_interval_constraints_from_string(RZ_NONNULL const char *str, RZ_NONNULL RzVector /*<RzTypeConstraint>*/ *constraints) {
	rz_return_val_if_fail(str && constraints, false);

	bool ok = true;
	const char *p = str;
	while (*p && ok) {
		skip_whitespace(&p);
		if (!*p) {
			break;
		}
		if (strncmp(p, "||", 2) == 0) {
			p += 2;
			continue;
		}
		if (*p == ',') {
			p++;
			continue;
		}
		if (*p == '{') {
			if (!parse_set(&p, constraints)) {
				ok = false;
				break;
			}
		} else if (*p == '[' || *p == '(') {
			if (!parse_interval(&p, constraints)) {
				ok = false;
				break;
			}
		} else {
			if (!parse_operator_constraint(&p, constraints)) {
				ok = false;
				break;
			}
		}
	}
	return ok;
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
