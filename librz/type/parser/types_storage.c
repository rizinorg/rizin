// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_list.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_assert.h>
#include <rz_type.h>
#include <tree_sitter/api.h>

#include <types_parser.h>

// Searching and storing types in the context of the parser (types and callables hashables)

// Base types

RzBaseType *c_parser_base_type_find(CParserState *state, RZ_NONNULL const char *name) {
	bool found = false;
	RzBaseType *base_type = ht_pp_find(state->types, name, &found);
	if (!found || !base_type) {
		return NULL;
	}
	return base_type;
}

bool c_parser_base_type_is_forward_definition(CParserState *state, RZ_NONNULL const char *name) {
	bool found = false;
	ht_pp_find(state->forward, name, &found);
	return found;
}

bool c_parser_base_type_exists(CParserState *state, RZ_NONNULL const char *name) {
	return c_parser_base_type_find(state, name) != NULL;
}

bool c_parser_base_type_store(CParserState *state, RZ_NONNULL const char *name, ParserTypePair *tpair) {
	rz_return_val_if_fail(state && name && tpair && tpair->btype, -1);

	if (c_parser_base_type_exists(state, name)) {
		// We don't create the type if it exists already in the parser
		// state with the same name
		return false;
	}

	// We store only RzBaseType part of the type pair
	ht_pp_insert(state->types, name, tpair->btype);
	return true;
}

bool c_parser_forward_definition_store(CParserState *state, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(state && name, -1);

	if (c_parser_base_type_exists(state, name)) {
		// We don't create the forward definition if it exists already in the parser
		// types table state with the same name
		return false;
	}

	if (c_parser_base_type_is_forward_definition(state, name)) {
		// We don't create the forward definition if it already stored
		// as the forward definition with the same name
		return false;
	}

	// We store only the type name
	ht_pp_insert(state->forward, name, NULL);
	return true;
}

bool c_parser_forward_definition_remove(CParserState *state, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(state && name, -1);

	if (c_parser_base_type_exists(state, name)) {
		// We don't create the forward definition if it exists already in the parser
		// types table state with the same name
		return false;
	}

	ht_pp_delete(state->forward, name);
	return true;
}

// Callable types

RzCallable *c_parser_callable_type_find(CParserState *state, RZ_NONNULL const char *name) {
	bool found = false;
	RzCallable *callable = ht_pp_find(state->callables, name, &found);
	if (!found || !callable) {
		return NULL;
	}
	return callable;
}

bool c_parser_callable_type_exists(CParserState *state, RZ_NONNULL const char *name) {
	return c_parser_callable_type_find(state, name) != NULL;
}

bool c_parser_callable_type_store(CParserState *state, RZ_NONNULL const char *name, RzType *type) {
	rz_return_val_if_fail(state && name && type, -1);
	rz_return_val_if_fail(type->kind == RZ_TYPE_KIND_CALLABLE, -1);
	rz_return_val_if_fail(type->callable, -1);

	if (c_parser_callable_type_exists(state, name)) {
		// We don't create the type if it exists already in the parser
		// state with the same name
		return false;
	}

	ht_pp_insert(state->callables, name, type->callable);
	return 0;
}

/**
 * \brief Creates new primitive type based on the name
 *
 * \param state The parser state
 * \param name Name of the primitive C type to create
 * \param is_const If the primitive type is const
 */
RZ_OWN ParserTypePair *c_parser_new_primitive_type(CParserState *state, const char *name, bool is_const) {
	rz_return_val_if_fail(state && name, NULL);

	if (c_parser_base_type_exists(state, name)) {
		// We don't create the type if it exists already in the parser
		// state with the same name
		return NULL;
	}

	RzType *type = RZ_NEW0(RzType);
	if (!type) {
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_IDENTIFIER;
	type->identifier.is_const = is_const;
	type->identifier.name = strdup(name);
	type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ATOMIC);
	if (!base_type) {
		rz_type_free(type);
		return NULL;
	}

	ParserTypePair *tpair = RZ_NEW0(ParserTypePair);
	if (!tpair) {
		rz_type_free(type);
		return NULL;
	}
	tpair->btype = base_type;
	tpair->type = type;

	return tpair;
}

/**
 * \brief Returns the primitive type if matching in the types hashtable
 *
 * If the name matches with the name of one of the base types
 * that are in the hashtable of the existing types in the parser
 * state, then it creates new RzType with the found RzBaseType as a base.
 * Then it wraps boths in the "type pair"
 *
 * \param state The parser state
 * \param name Name of the primitive type to fetch
 */
RZ_OWN ParserTypePair *c_parser_get_primitive_type(CParserState *state, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(state && name, NULL);

	RzBaseType *base_type = c_parser_base_type_find(state, name);
	if (!base_type || base_type->kind != RZ_BASE_TYPE_KIND_ATOMIC) {
		return NULL;
	}

	RzType *type = RZ_NEW0(RzType);
	if (!type) {
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_IDENTIFIER;
	type->identifier.is_const = false;
	type->identifier.name = strdup(name);
	type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;

	ParserTypePair *tpair = RZ_NEW0(ParserTypePair);
	if (!tpair) {
		rz_type_free(type);
		return NULL;
	}
	tpair->btype = base_type;
	tpair->type = type;
	return tpair;
}

/**
 * \brief Creates new structure naked type (without base type) based on the name
 *
 * \param state The parser state
 * \param name Name of the structure C type to create
 */
RZ_OWN ParserTypePair *c_parser_new_structure_naked_type(CParserState *state, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(state && name, NULL);

	RzType *type = RZ_NEW0(RzType);
	if (!type) {
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_IDENTIFIER;
	type->identifier.is_const = false;
	type->identifier.name = strdup(name);
	type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_STRUCT;

	ParserTypePair *tpair = RZ_NEW0(ParserTypePair);
	if (!tpair) {
		rz_type_free(type);
		return NULL;
	}
	tpair->btype = NULL;
	tpair->type = type;
	return tpair;
}

/**
 * \brief Creates new structure "type + base type" pair based on the name
 *
 * \param state The parser state
 * \param name Name of the structure C type to create
 * \param members_count The count of the structure members
 */
RZ_OWN ParserTypePair *c_parser_new_structure_type(CParserState *state, RZ_NONNULL const char *name, size_t members_count) {
	rz_return_val_if_fail(state && name, NULL);

	if (c_parser_base_type_exists(state, name)) {
		// We don't create the structure if it exists already in the parser
		// state with the same name
		return NULL;
	}

	ParserTypePair *tpair = c_parser_new_structure_naked_type(state, name);
	if (!tpair) {
		return NULL;
	}

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_STRUCT);
	if (!base_type) {
		rz_type_free(tpair->type);
		free(tpair);
		return NULL;
	}
	base_type->name = strdup(name);
	base_type->type = NULL;
	tpair->btype = base_type;

	RzVector *members = &base_type->struct_data.members;
	if (members_count > 0 && !rz_vector_reserve(members, members_count)) {
		rz_type_free(tpair->type);
		rz_type_base_type_free(tpair->btype);
		free(tpair);
		return NULL;
	}
	return tpair;
}

/**
 * \brief Returns the structure type if matching in the types hashtable
 *
 * If the name matches with the name of one of the base types
 * that are in the hashtable of the existing types in the parser
 * state, then it creates new RzType with the found RzBaseType as a base.
 * Then it wraps boths in the "type pair"
 *
 * \param state The parser state
 * \param name Name of the structure type to fetch
 */
RZ_OWN ParserTypePair *c_parser_get_structure_type(CParserState *state, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(state && name, NULL);

	RzBaseType *base_type = c_parser_base_type_find(state, name);
	if (!base_type || base_type->kind != RZ_BASE_TYPE_KIND_STRUCT) {
		return NULL;
	}

	ParserTypePair *tpair = c_parser_new_structure_naked_type(state, name);
	if (!tpair) {
		return NULL;
	}

	tpair->btype = base_type;
	return tpair;
}

/**
 * \brief Creates new structure forward definition
 *
 * \param state The parser state
 * \param name Name of the structure C type to create
 */
RZ_OWN ParserTypePair *c_parser_new_structure_forward_definition(CParserState *state, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(state && name, NULL);

	if (c_parser_base_type_exists(state, name)) {
		// We don't create the structure if it exists already in the parser
		// state with the same name
		return NULL;
	}

	if (c_parser_base_type_is_forward_definition(state, name)) {
		// We don't create the structure if it exists already in the forward
		// definitions table with the same name
		return NULL;
	}

	ParserTypePair *tpair = c_parser_new_structure_naked_type(state, name);
	if (!tpair) {
		return NULL;
	}

	return tpair;
}


/**
 * \brief Creates new union naked type (without base type) based on the name
 *
 * \param state The parser state
 * \param name Name of the union C type to create
 */
RZ_OWN ParserTypePair *c_parser_new_union_naked_type(CParserState *state, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(state && name, NULL);

	RzType *type = RZ_NEW0(RzType);
	if (!type) {
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_IDENTIFIER;
	type->identifier.is_const = false;
	type->identifier.name = strdup(name);
	type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNION;

	ParserTypePair *tpair = RZ_NEW0(ParserTypePair);
	if (!tpair) {
		rz_type_free(type);
		return NULL;
	}
	tpair->btype = NULL;
	tpair->type = type;
	return tpair;
}

/**
 * \brief Creates new union "type + base type" pair based on the name
 *
 * \param state The parser state
 * \param name Name of the union C type to create
 * \param members_count The count of the union members
 */
RZ_OWN ParserTypePair *c_parser_new_union_type(CParserState *state, RZ_NONNULL const char *name, size_t members_count) {
	rz_return_val_if_fail(state && name, NULL);

	if (c_parser_base_type_exists(state, name)) {
		// We don't create the structure if it exists already in the parser
		// state with the same name
		return NULL;
	}

	ParserTypePair *tpair = c_parser_new_union_naked_type(state, name);
	if (!tpair) {
		return NULL;
	}

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_UNION);
	if (!base_type) {
		rz_type_free(tpair->type);
		free(tpair);
		return NULL;
	}

	base_type->name = strdup(name);
	base_type->type = NULL;
	tpair->btype = base_type;

	RzVector *members = &base_type->union_data.members;
	if (members_count > 0 && !rz_vector_reserve(members, members_count)) {
		rz_type_free(tpair->type);
		rz_type_base_type_free(tpair->btype);
		free(tpair);
		return NULL;
	}
	return tpair;
}

/**
 * \brief Returns the union type if matching in the types hashtable
 *
 * If the name matches with the name of one of the base types
 * that are in the hashtable of the existing types in the parser
 * state, then it creates new RzType with the found RzBaseType as a base.
 * Then it wraps boths in the "type pair"
 *
 * \param state The parser state
 * \param name Name of the union type to fetch
 */
RZ_OWN ParserTypePair *c_parser_get_union_type(CParserState *state, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(state && name, NULL);

	RzBaseType *base_type = c_parser_base_type_find(state, name);
	if (!base_type || base_type->kind != RZ_BASE_TYPE_KIND_UNION) {
		return NULL;
	}

	ParserTypePair *tpair = c_parser_new_structure_naked_type(state, name);
	if (!tpair) {
		return NULL;
	}

	tpair->btype = base_type;
	return tpair;
}

/**
 * \brief Creates new union forward definition
 *
 * \param state The parser state
 * \param name Name of the union C type to create
 */
RZ_OWN ParserTypePair *c_parser_new_union_forward_definition(CParserState *state, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(state && name, NULL);

	if (c_parser_base_type_exists(state, name)) {
		// We don't create the union if it exists already in the parser
		// state with the same name
		return NULL;
	}

	if (c_parser_base_type_is_forward_definition(state, name)) {
		// We don't create the union if it exists already in the forward
		// definitions table with the same name
		return NULL;
	}

	ParserTypePair *tpair = c_parser_new_union_naked_type(state, name);
	if (!tpair) {
		return NULL;
	}

	return tpair;
}

/**
 * \brief Creates new enum naked type (without base type) based on the name
 *
 * \param state The parser state
 * \param name Name of the enum C type to create
 */
RZ_OWN ParserTypePair *c_parser_new_enum_naked_type(CParserState *state, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(state && name, NULL);

	RzType *type = RZ_NEW0(RzType);
	if (!type) {
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_IDENTIFIER;
	type->identifier.is_const = false;
	type->identifier.name = strdup(name);
	type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_ENUM;

	ParserTypePair *tpair = RZ_NEW0(ParserTypePair);
	if (!tpair) {
		rz_type_free(type);
		return NULL;
	}
	tpair->btype = NULL;
	tpair->type = type;
	return tpair;
}

/**
 * \brief Creates new enumeration type based on the name
 *
 * \param state The parser state
 * \param name Name of the primitive C type to create
 * \param cases_count The count of the enum cases
 */
RZ_OWN ParserTypePair *c_parser_new_enum_type(CParserState *state, RZ_NONNULL const char *name, size_t cases_count) {
	rz_return_val_if_fail(state && name, NULL);

	if (c_parser_base_type_exists(state, name)) {
		// We don't create the structure if it exists already in the parser
		// state with the same name
		return NULL;
	}

	ParserTypePair *tpair = c_parser_new_union_naked_type(state, name);
	if (!tpair) {
		return NULL;
	}

	RzBaseType *base_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ENUM);
	if (!base_type) {
		rz_type_free(tpair->type);
		free(tpair);
		return NULL;
	}

	base_type->name = strdup(name);
	base_type->type = NULL;
	tpair->btype = base_type;

	RzVector *cases = &base_type->enum_data.cases;
	if (cases_count > 0 && !rz_vector_reserve(cases, cases_count)) {
		rz_type_free(tpair->type);
		rz_type_base_type_free(tpair->btype);
		free(tpair);
		return NULL;
	}
	return tpair;
}

/**
 * \brief Returns the enum type if matching in the types hashtable
 *
 * If the name matches with the name of one of the base types
 * that are in the hashtable of the existing types in the parser
 * state, then it creates new RzType with the found RzBaseType as a base.
 * Then it wraps boths in the "type pair"
 *
 * \param state The parser state
 * \param name Name of the enum type to fetch
 */
RZ_OWN ParserTypePair *c_parser_get_enum_type(CParserState *state, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(state && name, NULL);

	RzBaseType *base_type = c_parser_base_type_find(state, name);
	if (!base_type || base_type->kind != RZ_BASE_TYPE_KIND_ENUM) {
		return NULL;
	}

	ParserTypePair *tpair = c_parser_new_structure_naked_type(state, name);
	if (!tpair) {
		return NULL;
	}

	tpair->btype = base_type;
	return tpair;
}

/**
 * \brief Creates new enum forward definition
 *
 * \param state The parser state
 * \param name Name of the enum C type to create
 */
RZ_OWN ParserTypePair *c_parser_new_enum_forward_definition(CParserState *state, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(state && name, NULL);

	if (c_parser_base_type_exists(state, name)) {
		// We don't create the enum if it exists already in the parser
		// state with the same name
		return NULL;
	}

	if (c_parser_base_type_is_forward_definition(state, name)) {
		// We don't create the enum if it exists already in the forward
		// definitions table with the same name
		return NULL;
	}

	ParserTypePair *tpair = c_parser_new_enum_naked_type(state, name);
	if (!tpair) {
		return NULL;
	}

	return tpair;
}

/**
 * \brief Creates new type alias based on the name
 *
 * If the name matches with the name of one of the base types
 * that are in the hashtable of the existing types in the parser
 * state, then it creates new RzType with the found RzBaseType as a base.
 * Then it wraps boths in the "type pair"
 *
 * In case of the base type found in the hashtable the ownership transfer
 * doesn't happen. If not - it does.
 *
 * \param state The parser state
 * \param name Name of the type alias to create
 * \param name Name of the base type for the alias
 */
RZ_OWN ParserTypePair *c_parser_new_typedef(CParserState *state, RZ_NONNULL const char *name, RZ_NONNULL const char *base) {
	rz_return_val_if_fail(state && name, NULL);
	RzType *type = RZ_NEW0(RzType);
	type->kind = RZ_TYPE_KIND_IDENTIFIER;
	type->identifier.is_const = false;
	type->identifier.name = strdup(name);
	type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;

	// We check if there is already a typedef in the hashtable with the same name
	bool found = false;
	RzBaseType *alias_type = ht_pp_find(state->types, name, &found);
	if (!found || !alias_type) {
		// At first we try to search if the base type is available in our context already
		RzBaseType *base_type = ht_pp_find(state->types, base, &found);
		if (!found || !base_type) {
			parser_debug(state, "Missing base type for aliasing: \"%s\"\n", base);
			// If not found - we still should create an alias
			// This scenario is oftenly used for "forward definitions" both in C and our databases
			// Thus we store the name in the "forward" hashtable so it could be set later
			if (!c_parser_forward_definition_store(state, base)) {
				parser_error(state, "Cannot create forward definition for aliasing: \"%s\"\n", base);
				rz_type_free(type);
				return NULL;
			}
		}
		// If not found in the context - create a new one
		alias_type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
		if (!alias_type) {
			rz_type_free(type);
			return NULL;
		}
		alias_type->name = strdup(name);
		// Here we don't set the alias type itself since it will
		// happen later in the parser, once the complete declarator is parsed
		// It is important for type aliases to pointers, arrays, etc
		alias_type->type = NULL;
	}

	ParserTypePair *tpair = RZ_NEW0(ParserTypePair);
	tpair->btype = alias_type;
	tpair->type = type;
	return tpair;
}

/**
 * \brief Returns the type if matching in the types hashtable
 *
 * If the name matches with the name of one of the type aliases
 * that are in the hashtable of the existing types in the parser
 * state, then it creates new RzType with the found RzBaseType as a base.
 * Then it wraps boths in the "type pair"
 *
 * \param state The parser state
 * \param name Name of the type alias to fetch
 */
RZ_OWN ParserTypePair *c_parser_get_typedef(CParserState *state, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(state && name, NULL);

	RzBaseType *base_type = c_parser_base_type_find(state, name);
	if (!base_type || base_type->kind != RZ_BASE_TYPE_KIND_TYPEDEF) {
		return NULL;
	}

	RzType *type = RZ_NEW0(RzType);
	if (!type) {
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_IDENTIFIER;
	type->identifier.is_const = false;
	type->identifier.name = strdup(name);
	type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;

	ParserTypePair *tpair = RZ_NEW0(ParserTypePair);
	if (!tpair) {
		rz_type_free(type);
		return NULL;
	}
	tpair->btype = base_type;
	tpair->type = type;
	return tpair;
}

/**
 * \brief Creates new callable based on the name
 *
 * If the name matches with the name of one of the base types
 * that are in the hashtable of the existing types in the parser
 * state, then it creates new RzType with the found RzCallable as a base.
 *
 * In case of the callable found in the hashtable the ownership transfer
 * doesn't happen. If not - it does.
 *
 * \param state The parser state
 * \param name Name of the callable type to create
 */
RZ_OWN RzType *c_parser_new_callable(CParserState *state, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(state && name, NULL);
	RzType *type = RZ_NEW0(RzType);
	if (!type) {
		return NULL;
	}
	// We check if there is already a callable in the hashtable with the same name
	bool found = false;
	RzCallable *callable = ht_pp_find(state->callables, name, &found);
	if (!found || !callable) {
		// If not found - create a new one
		RzCallable *callable = RZ_NEW0(RzCallable);
		if (!callable) {
			return NULL;
		}
		callable->name = strdup(name);
		callable->args = rz_pvector_new((RzPVectorFree)rz_type_func_arg_free);
	}
	type->kind = RZ_TYPE_KIND_CALLABLE;
	type->callable = callable;
	return type;
}

// Helpers to wrap the ParserTypePair into the pointer or the array complex types

RZ_OWN ParserTypePair *c_parser_type_wrap_to_pointer(CParserState *state, ParserTypePair *tpair, bool is_const) {
	rz_return_val_if_fail(state && tpair, NULL);
	RzType *type = RZ_NEW0(RzType);
	type->kind = RZ_TYPE_KIND_POINTER;
	type->pointer.is_const = is_const;
	type->pointer.type = tpair->type;
	ParserTypePair *newtpair = RZ_NEW0(ParserTypePair);
	newtpair->btype = tpair->btype;
	newtpair->type = type;
	return tpair;
}

RZ_OWN ParserTypePair *c_parser_type_wrap_to_array(CParserState *state, ParserTypePair *tpair, size_t size) {
	rz_return_val_if_fail(state && tpair, NULL);
	RzType *type = RZ_NEW0(RzType);
	type->kind = RZ_TYPE_KIND_ARRAY;
	type->array.count = size;
	type->array.type = tpair->type;
	ParserTypePair *newtpair = RZ_NEW0(ParserTypePair);
	newtpair->btype = tpair->btype;
	newtpair->type = type;
	return tpair;
}

bool c_parser_pointer_set_subtype(CParserState *state, ParserTypePair *tpair, ParserTypePair *subpair) {
	rz_return_val_if_fail(state && tpair, false);
	rz_return_val_if_fail(tpair->type->kind == RZ_TYPE_KIND_POINTER, false);
	tpair->type->pointer.type = subpair->type;
	tpair->btype = subpair->btype;
	return true;
}

bool c_parser_array_set_subtype(CParserState *state, ParserTypePair *tpair, ParserTypePair *subpair) {
	rz_return_val_if_fail(state && tpair, false);
	rz_return_val_if_fail(tpair->type->kind == RZ_TYPE_KIND_ARRAY, false);
	tpair->type->array.type = subpair->type;
	tpair->btype = subpair->btype;
	return true;
}

RZ_OWN char *c_parser_new_anonymous_structure_name(CParserState *state) {
	char *name = rz_str_newf("anonymous struct %zu", state->anon.structs);
	state->anon.structs++;
	return name;
}

RZ_OWN char *c_parser_new_anonymous_union_name(CParserState *state) {
	char *name = rz_str_newf("anonymous union %zu", state->anon.unions);
	state->anon.unions++;
	return name;
}

RZ_OWN char *c_parser_new_anonymous_enum_name(CParserState *state) {
	char *name = rz_str_newf("anonymous enum %zu", state->anon.enums);
	state->anon.enums++;
	return name;
}

RZ_OWN char *c_parser_new_anonymous_callable_name(CParserState *state) {
	char *name = rz_str_newf("anonymous function %zu", state->anon.callables);
	state->anon.enums++;
	return name;
}

