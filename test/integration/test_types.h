// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef TEST_TYPES_H
#define TEST_TYPES_H

static inline bool has_enum_val(RzBaseType *btype, const char *name, int val) {
	int result = -1;
	RzTypeEnumCase *cas;
	rz_vector_foreach (&btype->enum_data.cases, cas) {
		if (!strcmp(cas->name, name)) {
			result = cas->val;
			break;
		}
	}
	return result != -1 && result == val;
}

static inline bool has_enum_case(RzBaseType *btype, const char *name) {
	RzTypeEnumCase *cas;
	rz_vector_foreach (&btype->enum_data.cases, cas) {
		if (!strcmp(cas->name, name)) {
			return true;
		}
	}
	return false;
}

static inline bool has_struct_member(RzBaseType *btype, const char *name) {
	RzTypeStructMember *memb;
	rz_vector_foreach (&btype->struct_data.members, memb) {
		if (!strcmp(memb->name, name)) {
			return true;
		}
	}
	return false;
}

static inline bool has_union_member(RzBaseType *btype, const char *name) {
	RzTypeUnionMember *memb;
	rz_vector_foreach (&btype->union_data.members, memb) {
		if (!strcmp(memb->name, name)) {
			return true;
		}
	}
	return false;
}

static inline bool has_union_member_type(const RzTypeDB *typedb, RzBaseType *btype, const char *name, const char *type) {
	RzTypeUnionMember *memb;
	rz_vector_foreach (&btype->union_data.members, memb) {
		if (!strcmp(memb->name, name)) {
			if (!strcmp(type, rz_type_as_string(typedb, memb->type))) {
				return true;
			}
		}
	}
	return false;
}

static inline bool has_struct_member_type(const RzTypeDB *typedb, RzBaseType *btype, const char *name, const char *type) {
	RzTypeStructMember *memb;
	rz_vector_foreach (&btype->struct_data.members, memb) {
		if (!strcmp(memb->name, name)) {
			if (!strcmp(type, rz_type_as_string(typedb, memb->type))) {
				return true;
			}
		}
	}
	return false;
}

#endif // TEST_TYPES_H
