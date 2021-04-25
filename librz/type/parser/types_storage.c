// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_list.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_assert.h>
#include <rz_type.h>
#include <tree_sitter/api.h>

#include <types_parser.h>

int c_parser_new_bitfield(CParserState *state, const char *name) {
	return 0;
}

RZ_OWN ParserTypePair *c_parser_new_structure(CParserState *state, const char *name, size_t members_count) {
	RzType *type = RZ_NEW0(RzType);
	type->kind = RZ_TYPE_KIND_IDENTIFIER;
	type->identifier.is_const = false; // FIXME: Does it make sense for enums?
	type->identifier.name = name;
	type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_STRUCT;
	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_STRUCT);
	if (!base_type) {
		return NULL;
	}
	base_type->name = name;
	base_type->type = type;
	ParserTypePair *tpair = RZ_NEW0(ParserTypePair);
	tpair->btype = base_type;
	tpair->type = type;
	RzVector *members = &base_type->struct_data.members;
	if (!rz_vector_reserve(members, members_count)) {
		rz_type_base_type_free(base_type);
		return NULL;
	}
	return tpair;
}

RZ_OWN ParserTypePair *c_parser_new_union(CParserState *state, const char *name, size_t members_count) {
	RzType *type = RZ_NEW0(RzType);
	type->kind = RZ_TYPE_KIND_IDENTIFIER;
	type->identifier.is_const = false; // FIXME: Does it make sense for enums?
	type->identifier.name = name;
	type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_STRUCT;
	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_STRUCT);
	if (!base_type) {
		return NULL;
	}
	base_type->name = name;
	base_type->type = type;
	ParserTypePair *tpair = RZ_NEW0(ParserTypePair);
	tpair->btype = base_type;
	tpair->type = type;
	RzVector *members = &base_type->struct_data.members;
	if (!rz_vector_reserve(members, members_count)) {
		rz_type_base_type_free(base_type);
		return NULL;
	}
	return tpair;
}

RZ_OWN ParserTypePair *c_parser_new_enum(CParserState *state, const char *name, size_t cases_count) {
	RzType *type = RZ_NEW0(RzType);
	type->kind = RZ_TYPE_KIND_IDENTIFIER;
	type->identifier.is_const = false; // FIXME: Does it make sense for enums?
	type->identifier.name = name;
	type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_ENUM;
	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ENUM);
	if (!base_type) {
		return NULL;
	}
	base_type->name = name;
	base_type->type = type;
	ParserTypePair *tpair = RZ_NEW0(ParserTypePair);
	tpair->btype = base_type;
	tpair->type = type;
	RzVector *cases = &base_type->enum_data.cases;
	if (!rz_vector_reserve(cases, cases_count)) {
		rz_type_base_type_free(base_type);
		return NULL;
	}
	return tpair;
}

RZ_OWN ParserTypePair *c_parser_new_typedef(CParserState *state, const char *name) {
	RzType *type = RZ_NEW0(RzType);
	type->kind = RZ_TYPE_KIND_IDENTIFIER;
	type->identifier.is_const = false;
	type->identifier.name = name;
	type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
	if (!base_type) {
		return NULL;
	}
	base_type->name = name;
	base_type->type = type;
	ParserTypePair *tpair = RZ_NEW0(ParserTypePair);
	tpair->btype = base_type;
	tpair->type = type;
	return tpair;
}

int c_parser_store_type(CParserState *state, const char *name, ParserTypePair *tpair) {
	// We store only RzBaseType part of the type pair
	// TODO: Handle the name conflicts
	ht_pp_insert(state->types, name, tpair->btype);
	return 0;
}
