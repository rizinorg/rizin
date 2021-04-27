// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <string.h>

RZ_API RZ_OWN RzType *rz_type_identifier_of_base_type(RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype) {
	rz_return_val_if_fail(typedb && btype, NULL);
	RzType *type = RZ_NEW0(RzType);
	if (!type) {
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_IDENTIFIER;
	type->identifier.name = btype->name;
	type->identifier.is_const = false; // not "const" by default
	return type;
}

RZ_API RZ_OWN RzType *rz_type_identifier_of_base_type_str(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	return rz_type_identifier_of_base_type(typedb, btype);
}

RZ_API RZ_OWN RzType *rz_type_pointer_of_base_type(RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype, bool is_const) {
	RzType *type = RZ_NEW0(RzType);
	if (!type) {
		return NULL;
	}
	RzType *t = rz_type_identifier_of_base_type(typedb, btype);
	if (!t) {
		rz_type_free(type);
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_POINTER;
	type->pointer.type = t;
	type->pointer.is_const = is_const;
	return type;
}

RZ_API RZ_OWN RzType *rz_type_pointer_of_base_type_str(RzTypeDB *typedb, RZ_NONNULL const char *name, bool is_const) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	return rz_type_pointer_of_base_type(typedb, btype, is_const);
}

RZ_API RZ_OWN RzType *rz_type_pointer_of_type(RzTypeDB *typedb, RZ_NONNULL RzType *type, bool is_const) {
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
	return NULL;
}

RZ_API RZ_OWN RzType *rz_type_array_of_base_type(RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype, size_t count) {
	RzType *type = RZ_NEW0(RzType);
	if (!type) {
		return NULL;
	}
	RzType *t = rz_type_identifier_of_base_type(typedb, btype);
	if (!t) {
		rz_type_free(type);
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_ARRAY;
	type->array.type = t;
	type->array.count = count;
	return type;
}

RZ_API RZ_OWN RzType *rz_type_array_of_base_type_str(RzTypeDB *typedb, RZ_NONNULL const char *name, size_t count) {
	rz_return_val_if_fail(typedb && name && count, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	return rz_type_array_of_base_type(typedb, btype, count);
}

RZ_API RZ_OWN RzType *rz_type_array_of_type(RzTypeDB *typedb, RZ_NONNULL RzType *type, size_t count) {
	RzType *newtype = RZ_NEW0(RzType);
	if (!newtype) {
		return NULL;
	}
	newtype->kind = RZ_TYPE_KIND_ARRAY;
	newtype->array.type = type;
	newtype->array.count = count;
	return type;
}

RZ_API bool rz_type_atomic_eq(RzTypeDB *typedb, RzType *typ1, RzType *typ2) {
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

RZ_API bool rz_type_atomic_str_eq(RzTypeDB *typedb, RzType *typ1, RZ_NONNULL const char *name) {
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

RZ_API bool rz_type_atomic_is_void(RzTypeDB *typedb, RzType *type) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	return !strcmp(type->identifier.name, "void");
}

RZ_API bool rz_type_atomic_is_signed(RzTypeDB *typedb, RzType *type) {
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

RZ_API bool rz_type_atomic_is_const(RzTypeDB *typedb, RzType *type) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	return type->identifier.is_const;
}

RZ_API bool rz_type_atomic_is_num(RzTypeDB *typedb, RzType *type) {
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

RZ_API bool rz_type_pointer_is_const(RzTypeDB *typedb, RzType *type) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_POINTER) {
		return false;
	}
	return type->pointer.is_const;
}

RZ_API bool rz_type_is_void_ptr(RzType *type) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_POINTER) {
		return false;
	}
	// There should not exist pointers to the empty types
	RzType *ptr = type->pointer.type;
	rz_return_val_if_fail(ptr, false);
	return ptr->kind == RZ_TYPE_KIND_IDENTIFIER && ptr->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED && !strcmp(ptr->identifier.name, "void");
}

RZ_API bool rz_type_is_default(RzTypeDB *typedb, RzType *type) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	if (type->identifier.kind != RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED) {
		return false;
	}
	return !strcmp(type->identifier.name, RZ_TYPE_DEFAULT) && !type->identifier.is_const;
}

RZ_API RZ_OWN RzType *rz_type_new_default(RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, RZ_TYPE_DEFAULT);
	if (!btype) {
		return NULL;
	}
	return rz_type_identifier_of_base_type(typedb, btype);
}

RZ_API bool rz_type_atomic_set_sign(RzTypeDB *typedb, RzType *type, bool sign) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	return false;
}
