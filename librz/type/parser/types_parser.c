// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_types.h>
#include <rz_list.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_file.h>
#include <rz_util/rz_assert.h>
#include <rz_type.h>
#include <tree_sitter/api.h>

#include <types_parser.h>

#define TS_START_END(node, start, end) \
	do { \
		start = ts_node_start_byte(node); \
		end = ts_node_end_byte(node); \
	} while (0)

static char *ts_node_sub_string(TSNode node, const char *cstr) {
	ut32 start, end;
	TS_START_END(node, start, end);
	return rz_str_newf("%.*s", end - start, cstr + start);
}

void node_malformed_error(CParserState *state, TSNode node, const char *text, const char *nodetype) {
	rz_return_if_fail(nodetype);
	char *string = ts_node_is_null(node) ? NULL : ts_node_string(node);
	char *piece = ts_node_is_null(node) ? NULL : ts_node_sub_string(node, text);
	rz_strbuf_appendf(state->errors, "Wrongly formed \"(%s)\": \"%s\"\n", nodetype, rz_str_get_null(string));
	rz_strbuf_appendf(state->errors, "\"(%s)\": \"%s\"\n", nodetype, rz_str_get_null(piece));
	free(piece);
	free(string);
}

void parser_debug(CParserState *state, const char *fmt, ...) {
	rz_return_if_fail(state && fmt);
	if (state->verbose) {
		va_list ap;
		va_start(ap, fmt);
		rz_strbuf_vappendf(state->debug, fmt, ap);
		va_end(ap);
	}
}

void parser_error(CParserState *state, const char *fmt, ...) {
	rz_return_if_fail(state && fmt);
	va_list ap;
	va_start(ap, fmt);
	rz_strbuf_vappendf(state->errors, fmt, ap);
	va_end(ap);
}

void parser_warning(CParserState *state, const char *fmt, ...) {
	rz_return_if_fail(state && fmt);
	va_list ap;
	va_start(ap, fmt);
	rz_strbuf_vappendf(state->warnings, fmt, ap);
	va_end(ap);
}

static bool is_abstract_declarator(const char *declarator) {
	return !strcmp(declarator, "abstract_pointer_declarator") ||
		!strcmp(declarator, "abstract_array_declarator") ||
		!strcmp(declarator, "abstract_function_declarator");
}

static bool is_declarator(const char *declarator) {
	return !strcmp(declarator, "pointer_declarator") ||
		!strcmp(declarator, "array_declarator") ||
		!strcmp(declarator, "function_declarator") ||
		!strcmp(declarator, "identifier") ||
		!strcmp(declarator, "field_identifier");
}

static bool is_function_declarator(const char *declarator) {
	return !strcmp(declarator, "parenthesized_declarator") ||
		!strcmp(declarator, "identifier");
}

static bool is_bitfield_clause(const char *name) {
	return !strcmp(name, "bitfield_clause");
}

static bool is_type_declarator(const char *declarator) {
	return !strcmp(declarator, "pointer_declarator") ||
		!strcmp(declarator, "array_declarator") ||
		!strcmp(declarator, "function_declarator") ||
		!strcmp(declarator, "type_identifier");
}

// Parses primitive type - like "int", "char", "size_t"
int parse_primitive_type(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair, bool is_const) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	rz_return_val_if_fail(ts_node_is_named(node), -1);

	parser_debug(state, "parse_primitive_type(): %s\n", is_const ? "const" : "not const");
	if (strcmp(ts_node_type(node), "primitive_type")) {
		node_malformed_error(state, node, text, "not primitive type");
		return -1;
	}
	char *real_type = ts_node_sub_string(node, text);
	if (!real_type) {
		node_malformed_error(state, node, text, "primitive type");
		parser_error(state, "Primitive type name cannot be NULL\n");
		return -1;
	}
	// At first we search if the type is already presented in the state
	if ((*tpair = c_parser_get_primitive_type(state, real_type, is_const))) {
		parser_debug(state, "Fetched primitive type: \"%s\"\n", real_type);
		free(real_type);
		return 0;
	}
	// If not - we form both RzType and RzBaseType to store in the Types database
	ParserTypePair *type_pair = c_parser_new_primitive_type(state, real_type, is_const);
	if (!type_pair) {
		parser_error(state, "Error forming RzType and RzBaseType pair out of primitive type\n");
		free(real_type);
		return -1;
	}
	c_parser_base_type_store(state, real_type, type_pair);
	*tpair = type_pair;
	free(real_type);
	return 0;
}

// Parses sized primitive type - like "long int", "unsigned char", "short", "unsigned long long", etc
int parse_sized_primitive_type(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair, bool is_const) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	rz_return_val_if_fail(ts_node_is_named(node), -1);

	if (strcmp(ts_node_type(node), "sized_type_specifier")) {
		node_malformed_error(state, node, text, "not sized primitive type");
		return -1;
	}
	char *real_type = ts_node_sub_string(node, text);
	if (!real_type) {
		node_malformed_error(state, node, text, "primitive type");
		parser_error(state, "Primitive type name cannot be NULL\n");
		free(real_type);
		return -1;
	}
	// At first we search if the type is already presented in the state
	if ((*tpair = c_parser_get_primitive_type(state, real_type, is_const))) {
		parser_debug(state, "Fetched primitive type: \"%s\"\n", real_type);
		free(real_type);
		return 0;
	}
	// If not - we form both RzType and RzBaseType to store in the Types database
	ParserTypePair *type_pair = c_parser_new_primitive_type(state, real_type, is_const);
	if (!type_pair) {
		parser_error(state, "Error forming RzType and RzBaseType pair out of primitive type\n");
		free(real_type);
		return -1;
	}
	c_parser_base_type_store(state, real_type, type_pair);
	*tpair = type_pair;
	free(real_type);
	return 0;
}

// Parses primitive type or type alias mention - like "socklen_t", etc
int parse_sole_type_name(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair, bool is_const) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	rz_return_val_if_fail(ts_node_is_named(node), -1);

	if (strcmp(ts_node_type(node), "type_identifier")) {
		node_malformed_error(state, node, text, "just a type name");
		return -1;
	}
	char *real_type = ts_node_sub_string(node, text);
	// At first we search if the type is already presented in the state and is a primitive one
	if ((*tpair = c_parser_get_primitive_type(state, real_type, is_const))) {
		parser_debug(state, "Fetched type: \"%s\"\n", real_type);
		free(real_type);
		return 0;
	}
	// After that we search if the type is already presented in the state and is a type alias
	if ((*tpair = c_parser_get_typedef(state, real_type))) {
		parser_debug(state, "Fetched type: \"%s\"\n", real_type);
		free(real_type);
		return 0;
	}
	// Then we check if the type is already forward-defined
	if (c_parser_base_type_is_forward_definition(state, real_type)) {
		parser_debug(state, "Already has forward definition of type: \"%s\"\n", real_type);
		*tpair = c_parser_new_unspecified_naked_type(state, real_type, is_const);
		if (!*tpair) {
			parser_error(state, "Error forming naked RzType pair out of simple forward-looking type: \"%s\"\n", real_type);
			free(real_type);
			return -1;
		}
		free(real_type);
		return 0;
	}
	// Before resorting to create a new forward type, check if there is some union or struct with the same name already.
	// This will e.g. catch cases like referring to `struct MyStruct` by just `MyStruct`.
	if ((*tpair = c_parser_get_structure_type(state, real_type))) {
		parser_debug(state, "Fetched type as struct: \"%s\"\n", real_type);
		free(real_type);
		return 0;
	}
	if ((*tpair = c_parser_get_union_type(state, real_type))) {
		parser_debug(state, "Fetched type as union: \"%s\"\n", real_type);
		free(real_type);
		return 0;
	}
	// If not - we form both RzType and RzBaseType to store in the Types database
	// as a forward-looking definition
	*tpair = c_parser_new_primitive_type(state, real_type, is_const);
	if (!*tpair) {
		parser_error(state, "Error forming RzType and RzBaseType pair out of simple forward-looking type\n");
		free(real_type);
		return -1;
	}
	// Do allow forward-looking definitions we just add the type into the forward hashtable
	if (c_parser_forward_definition_store(state, real_type)) {
		parser_debug(state, "Added forward definition of type: \"%s\"\n", real_type);
		rz_type_base_type_free((*tpair)->btype);
		(*tpair)->btype = NULL;
		free(real_type);
		return 0;
	}
	rz_type_free((*tpair)->type);
	rz_type_base_type_free((*tpair)->btype);
	RZ_FREE(*tpair);
	free(real_type);
	return -1;
}

// Parses parameter declarations - they are part of the parameter list, e.g.
// in the function definition/type as arguments
int parse_parameter_declaration_node(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair, char **identifier) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	rz_return_val_if_fail(ts_node_is_named(node), -1);

	const char *param_type = ts_node_type(node);
	parser_debug(state, "parameter type: %s\n", param_type);

	// Type descriptor has three fields:
	// 0. type qualifier (optional)
	// 1. type itself (optional)
	// 2. declarator (can be concrete or an abstract one)

	// Parse the type qualifier first (if present)
	// FIXME: There could be multiple different type qualifiers in one declaration
	bool is_const = false;
	TSNode first_leaf = ts_node_named_child(node, 0);
	if (!ts_node_is_null(first_leaf)) {
		const char *leaf_type = ts_node_type(first_leaf);
		// If we have type qualifier in this position it is related to
		// the type itself
		if (!strcmp(leaf_type, "type_qualifier")) {
			char *qualifier = ts_node_sub_string(first_leaf, text);
			parser_debug(state, "has qualifier %s\n", qualifier);
			if (!strcmp(qualifier, "const")) {
				is_const = true;
			}
			free(qualifier);
		}
	}

	// Ever parameter should have at least type field
	TSNode parameter_type = ts_node_child_by_field_name(node, "type", 4);
	if (ts_node_is_null(parameter_type)) {
		parser_error(state, "ERROR: Parameter AST should contain at least one node!\n");
		node_malformed_error(state, node, text, "parameter type");
		return -1;
	}

	if (parse_type_node_single(state, parameter_type, text, tpair, is_const)) {
		parser_error(state, "Cannot parse type_descriptor's type field");
		return -1;
	}
	if (!*tpair) {
		parser_error(state, "Failed to parse type_descriptor's type field");
		return -1;
	}

	// Ever parameter could have a declarator field but it's optional
	TSNode parameter_declarator = ts_node_child_by_field_name(node, "declarator", 10);
	if (ts_node_is_null(parameter_declarator)) {
		// In the case it's null it means the sole type name which was
		// already parsed in "parse_type_node_single()"
		return 0;
	}

	// Check if it's abstract or a concrete node
	const char *declarator_type = ts_node_type(parameter_declarator);
	if (!declarator_type) {
		node_malformed_error(state, parameter_declarator, text, "parameter declarator");
		return -1;
	}
	parser_debug(state, "declarator type: \"%s\"\n", declarator_type);
	if (is_abstract_declarator(declarator_type)) {
		return parse_type_abstract_declarator_node(state, parameter_declarator, text, tpair);
	} else if (is_declarator(declarator_type)) {
		return parse_type_declarator_node(state, parameter_declarator, text, tpair, identifier);
	}
	node_malformed_error(state, parameter_declarator, text, "parameter declarator");
	return -1;
}

// Types can be
// - struct (struct_specifier)
// - union (union_specifier)
// - enum (enum_specifier) (usually prepended by declaration)
// - typedef (type_definition)
// - atomic type (primitive_type)

// Parses the struct definitions - concrete or an abstract ones
int parse_struct_node(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair, bool is_const) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	rz_return_val_if_fail(ts_node_is_named(node), -1);

	parser_debug(state, "parse_struct_node()\n");

	int struct_node_child_count = ts_node_named_child_count(node);
	if (struct_node_child_count < 1 || struct_node_child_count > 3) {
		node_malformed_error(state, node, text, "struct");
		return -1;
	}
	int result = 0;
	// Name is optional, in abstract definitions or as the member of nested types
	char *name = NULL;
	TSNode struct_name = ts_node_child_by_field_name(node, "name", 4);
	if (ts_node_is_null(struct_name)) {
		parser_debug(state, "Anonymous struct\n");
		name = c_parser_new_anonymous_structure_name(state);
	} else {
		name = ts_node_sub_string(struct_name, text);
		if (!name) {
			parser_error(state, "ERROR: Struct name should not be NULL!\n");
			node_malformed_error(state, node, text, "struct");
			return -1;
		}
		parser_debug(state, "struct name: %s\n", name);
	}

	// Parsing the structure body
	// If the structure doesn't have body but has a name
	// it means that it uses the type predefined before
	// e.g. "const struct tm* a;"
	TSNode struct_body = ts_node_child_by_field_name(node, "body", 4);
	if (ts_node_is_null(struct_body) && !ts_node_is_null(struct_name)) {
		parser_debug(state, "Fetching predefined structure: \"%s\"\n", name);
		if (!(*tpair = c_parser_get_structure_type(state, name))) {
			parser_warning(state, "Cannot find \"%s\" structure in the context\n", name);
			// At first we check if there is a forward definion already
			if (c_parser_base_type_is_forward_definition(state, name)) {
				parser_debug(state, "Structure \"%s\" was forward-defined before\n", name);
				if (!(*tpair = c_parser_new_structure_naked_type(state, name))) {
					parser_error(state, "Cannot create \"%s\" naked structure type in the context\n", name);
					result = -1;
					goto snexit;
				}
				goto snexit;
			}
			// We still could create the "forward looking struct declaration"
			// The parser then can augment the definition
			if (!(*tpair = c_parser_new_structure_forward_definition(state, name))) {
				parser_error(state, "Cannot create \"%s\" forward structure definition in the context\n", name);
				result = -1;
				goto snexit;
			}
			goto snexit;
		} else {
			goto snexit;
		}
	}

	// If it's the type definition - we proceed further
	int body_child_count = ts_node_named_child_count(struct_body);

	// Structures could lack BOTH name and body, e.g. as a member of another struct:
	// struct a {
	//	  struct {} b;
	// }

	// Now we form both RzType and RzBaseType to store in the Types database
	ParserTypePair *struct_pair = c_parser_new_structure_type(state, name, body_child_count);
	if (!struct_pair) {
		parser_error(state, "Error forming RzType and RzBaseType pair out of struct: \"%s\"\n", name);
		result = -1;
		goto snexit;
	}

	char *real_type = NULL;
	char *real_identifier = NULL;
	int i;
	for (i = 0; i < body_child_count; i++) {
		parser_debug(state, "struct: processing %d field...\n", i);
		TSNode child = ts_node_named_child(struct_body, i);
		const char *node_type = ts_node_type(child);

		// Skip comments
		if (!strcmp(node_type, "comment")) {
			continue;
		}

		// Parse the type qualifier first (if present)
		// FIXME: There could be multiple different type qualifiers in one declaration
		bool is_const = false;
		TSNode first_leaf = ts_node_named_child(child, 0);
		if (ts_node_is_null(first_leaf)) {
			node_malformed_error(state, child, text, "field_declaration");
			result = -1;
			goto srnexit;
		}
		const char *leaf_type = ts_node_type(first_leaf);
		// If we have type qualifier in this position it is related to
		// the declarator itself, not the type, e.g. constant pointer,
		// not pointer to the constant
		if (!strcmp(leaf_type, "type_qualifier")) {
			char *qualifier = ts_node_sub_string(first_leaf, text);
			parser_debug(state, "has qualifier %s\n", qualifier);
			if (!strcmp(qualifier, "const")) {
				is_const = true;
			}
			free(qualifier);
		}

		// Every field should have (field_declaration) AST clause
		if (strcmp(node_type, "field_declaration")) {
			parser_error(state, "ERROR: Struct field AST should contain (field_declaration) node!\n");
			node_malformed_error(state, child, text, "struct field");
			result = -1;
			goto srnexit;
		}

		// Every field node should have type and at least one declarator:
		TSNode field_type = ts_node_child_by_field_name(child, "type", 4);
		if (ts_node_is_null(field_type)) {
			parser_error(state, "ERROR: Struct field AST should contain type");
			node_malformed_error(state, child, text, "struct field");
			result = -1;
			goto srnexit;
		}

		// Every field can be:
		// - atomic: "int a;" or "char b[20]"
		// - bitfield: int a:7;"
		// - nested: "struct { ... } a;" or "union { ... } a;"
		// - all these but with multiple declarators in one line
		if (state->verbose) {
			char *fieldtext = ts_node_sub_string(child, text);
			char *nodeast = ts_node_string(child);
			if (fieldtext && nodeast) {
				parser_debug(state, "field text: %s\n", fieldtext);
				parser_debug(state, "field ast: %s\n", nodeast);
			}
			free(fieldtext);
			free(nodeast);
		}

		// Parse types first
		free(real_type);
		real_type = ts_node_sub_string(field_type, text);
		if (!real_type) {
			parser_error(state, "ERROR: Struct member type should not be NULL!\n");
			node_malformed_error(state, child, text, "struct field");
			result = -1;
			goto srnexit;
		}

		ParserTypePair *membtpair = NULL;
		// At first, we parse the type field
		if (parse_type_node_single(state, field_type, text, &membtpair, is_const)) {
			parser_error(state, "ERROR: parsing struct member type\n");
			node_malformed_error(state, child, text, "struct field");
			result = -1;
			goto srnexit;
		}

		TSNode field_declarator = ts_node_child_by_field_name(child, "declarator", 10);
		if (ts_node_is_null(field_declarator)) {
			parser_error(state, "ERROR: Struct field AST should contain at least one declarator item");
			node_malformed_error(state, child, text, "struct field");
			result = -1;
			goto srnexit;
		}

		// We could have multiple declarator members of the same type
		do {
			// First we extract the identifier
			free(real_identifier);
			real_identifier = ts_node_sub_string(field_declarator, text);
			if (!real_identifier) {
				parser_error(state, "ERROR: Struct declarator should not be NULL!\n");
				node_malformed_error(state, child, text, "struct field");
				result = -1;
				goto srnexit;
			}
			parser_debug(state, "field type: %s field_declarator: %s\n", real_type, real_identifier);
			// 1st case, bitfield
			// AST looks like
			// type: (primitive_type) declarator: (field_identifier) (bitfield_clause (number_literal))
			// or type: (primitive_type) declarator: (...) declarator (...)

			// If it has the additional node after the declarator - it's bitfield
			TSNode next_sibling = ts_node_next_named_sibling(field_declarator);
			if (!ts_node_is_null(next_sibling) && is_bitfield_clause(ts_node_type(next_sibling))) {
				const char *bfnode_type = ts_node_type(field_type);
				// As per C standard bitfields are defined only for atomic types, particularly "int"
				if (strcmp(bfnode_type, "primitive_type") && strcmp(bfnode_type, "type_identifier")) {
					parser_error(state, "ERROR: Struct bitfield cannot contain non-primitive bitfield!\n");
					node_malformed_error(state, child, text, "struct field");
					result = -1;
					goto srnexit;
				}
				if (ts_node_named_child_count(next_sibling) < 1) {
					node_malformed_error(state, child, text, "struct field");
					result = -1;
					goto srnexit;
				}
				TSNode field_bits = ts_node_named_child(next_sibling, 0);
				if (ts_node_is_null(field_bits)) {
					parser_error(state, "ERROR: Struct bitfield bits AST node should not be NULL!\n");
					node_malformed_error(state, child, text, "struct field");
					result = -1;
					goto srnexit;
				}
				const char *bits_str = ts_node_sub_string(field_bits, text);
				int bits = rz_num_get(NULL, bits_str);
				parser_debug(state, "field type: %s field_identifier: %s bits: %d\n", real_type, real_identifier, bits);
				// Then we augment resulting type field with the data from parsed declarator
				char *membname = NULL;
				if (parse_type_declarator_node(state, field_declarator, text, &membtpair, &membname)) {
					parser_error(state, "ERROR: parsing bitfield struct member declarator\n");
					node_malformed_error(state, child, text, "struct field");
					result = -1;
					goto srnexit;
				}
				// Add a struct member
				RzVector *members = &struct_pair->btype->struct_data.members;
				RzTypeStructMember memb = {
					.name = membname,
					.type = rz_type_clone(membtpair->type),
					.offset = 0, // FIXME
					.size = 0, // FIXME
				};
				void *element = rz_vector_push(members, &memb); // returns null if no space available
				if (!element) {
					parser_error(state, "Error appending bitfield struct member to the base type\n");
					result = -1;
					goto srnexit;
				}
			} else if (is_declarator(ts_node_type(field_declarator))) {
				// 2nd case, normal structure
				// AST looks like
				// type: (primitive_type) declarator: (field_identifier)
				// or type: (primitive_type) declarator: (...) declarator (...)
				// Augment resulting type field with the data from parsed declarator
				char *membname = NULL;
				if (parse_type_declarator_node(state, field_declarator, text, &membtpair, &membname)) {
					parser_error(state, "ERROR: parsing struct member declarator\n");
					node_malformed_error(state, child, text, "struct field");
					result = -1;
					goto srnexit;
				}
				// Add a struct member
				RzVector *members = &struct_pair->btype->struct_data.members;
				RzTypeStructMember memb = {
					.name = membname,
					.type = rz_type_clone(membtpair->type),
					.offset = 0, // FIXME
					.size = 0, // FIXME
				};
				void *element = rz_vector_push(members, &memb); // returns null if no space available
				if (!element) {
					parser_error(state, "Error appending struct member to the base type\n");
					result = -1;
					goto srnexit;
				}
				parser_debug(state, "Appended member \"%s\" into struct \"%s\"\n", membname, name);
			} else {
				parser_debug(state, "Struct field wrong: \"%s\"\n", ts_node_sub_string(field_declarator, text));
			}
			field_declarator = ts_node_next_named_sibling(field_declarator);
		} while (!ts_node_is_null(field_declarator));
		free(membtpair);
	}
	// If parsing successfull completed - we store the state
	if (struct_pair) {
		c_parser_base_type_store(state, name, struct_pair);
		// If it was a forward definition previously - remove it
		if (c_parser_base_type_is_forward_definition(state, name)) {
			c_parser_forward_definition_remove(state, name);
		}
	}
	*tpair = struct_pair;

srnexit:
	free(real_type);
	free(real_identifier);
snexit:
	free(name);
	return result;
}

// Parses the union definitions - concrete or an abstract ones
// Quite similar to structures but the size and offset calculation is different
int parse_union_node(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair, bool is_const) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	rz_return_val_if_fail(ts_node_is_named(node), -1);

	parser_debug(state, "parse_union_node()\n");

	int union_node_child_count = ts_node_named_child_count(node);
	if (union_node_child_count < 1 || union_node_child_count > 2) {
		node_malformed_error(state, node, text, "union");
		return -1;
	}
	int result = 0;
	// Name is optional, in abstract definitions or as the member of nested types
	char *name = NULL;
	TSNode union_name = ts_node_child_by_field_name(node, "name", 4);
	if (ts_node_is_null(union_name)) {
		parser_debug(state, "Anonymous union\n");
		name = c_parser_new_anonymous_union_name(state);
	} else {
		name = ts_node_sub_string(union_name, text);
		if (!name) {
			parser_error(state, "ERROR: Union name should not be NULL!\n");
			node_malformed_error(state, node, text, "union");
			return -1;
		}
		parser_debug(state, "union name: %s\n", name);
	}

	// Parsing the union body
	// If the union doesn't have body but has a name
	// it means that it uses the type predefined before
	// e.g. "const union tm* a;"
	TSNode union_body = ts_node_child_by_field_name(node, "body", 4);
	if (ts_node_is_null(union_body) && !ts_node_is_null(union_name)) {
		parser_debug(state, "Fetching predefined union: \"%s\"\n", name);
		if (!(*tpair = c_parser_get_union_type(state, name))) {
			parser_warning(state, "Cannot find \"%s\" union in the context\n", name);
			// At first we check if there is a forward definion already
			if (c_parser_base_type_is_forward_definition(state, name)) {
				parser_debug(state, "Union \"%s\" was forward-defined before\n", name);
				if (!(*tpair = c_parser_new_union_naked_type(state, name))) {
					parser_error(state, "Cannot create \"%s\" naked union type in the context\n", name);
					result = -1;
					goto unexit;
				}
				goto unexit;
			}
			// We still could create the "forward looking union declaration"
			// The parser then can augment the definition
			if (!(*tpair = c_parser_new_union_forward_definition(state, name))) {
				parser_error(state, "Cannot create \"%s\" forward union definition in the context\n", name);
				result = -1;
				goto unexit;
			}
			goto unexit;
		} else {
			goto unexit;
		}
	}

	// If it's the type definition - we proceed further
	int body_child_count = ts_node_named_child_count(union_body);

	// Unions could lack BOTH name and body, e.g. as a member of another struct or union:
	// struct a {
	//	  union {} b;
	// }

	// Now we form both RzType and RzBaseType to store in the Types database
	ParserTypePair *union_pair = c_parser_new_union_type(state, name, body_child_count);
	if (!union_pair) {
		parser_error(state, "Error forming RzType and RzBaseType pair out of union\n");
		return -1;
	}

	char *real_type = NULL;
	char *real_identifier = NULL;
	int i;
	for (i = 0; i < body_child_count; i++) {
		parser_debug(state, "union: processing %d field...\n", i);
		TSNode child = ts_node_named_child(union_body, i);
		const char *node_type = ts_node_type(child);

		// Skip comments
		if (!strcmp(node_type, "comment")) {
			continue;
		}

		// Parse the type qualifier first (if present)
		// FIXME: There could be multiple different type qualifiers in one declaration
		bool is_const = false;
		TSNode first_leaf = ts_node_named_child(child, 0);
		if (ts_node_is_null(first_leaf)) {
			node_malformed_error(state, child, text, "field_declaration");
			result = -1;
			goto urnexit;
		}
		const char *leaf_type = ts_node_type(first_leaf);
		// If we have type qualifier in this position it is related to
		// the declarator itself, not the type, e.g. constant pointer,
		// not pointer to the constant
		if (!strcmp(leaf_type, "type_qualifier")) {
			char *qualifier = ts_node_sub_string(first_leaf, text);
			parser_debug(state, "has qualifier %s\n", qualifier);
			if (!strcmp(qualifier, "const")) {
				is_const = true;
			}
			free(qualifier);
		}

		// Every field should have (field_declaration) AST clause
		if (strcmp(node_type, "field_declaration")) {
			parser_error(state, "ERROR: Union field AST should contain (field_declaration) node!\n");
			node_malformed_error(state, child, text, "union field");
			result = -1;
			goto urnexit;
		}

		// Every field node should have at least type and declarator:
		TSNode field_type = ts_node_child_by_field_name(child, "type", 4);
		if (ts_node_is_null(field_type)) {
			parser_error(state, "ERROR: Union field AST shoudl contain type");
			node_malformed_error(state, child, text, "union field");
			result = -1;
			goto urnexit;
		}

		// Every field can be:
		// - atomic: "int a;" or "char b[20]"
		// - bitfield: int a:7;"
		// - nested: "struct { ... } a;" or "union { ... } a;"
		if (state->verbose) {
			char *fieldtext = ts_node_sub_string(child, text);
			char *nodeast = ts_node_string(child);
			if (fieldtext && nodeast) {
				parser_debug(state, "field text: %s\n", fieldtext);
				parser_debug(state, "field ast: %s\n", nodeast);
			}
			free(fieldtext);
			free(nodeast);
		}

		// Parse types first
		free(real_type);
		real_type = ts_node_sub_string(field_type, text);
		if (!real_type) {
			parser_error(state, "ERROR: Union bitfield type should not be NULL!\n");
			node_malformed_error(state, child, text, "union field");
			result = -1;
			goto urnexit;
		}

		ParserTypePair *membtpair = NULL;
		// At first, we parse the type field
		if (parse_type_node_single(state, field_type, text, &membtpair, is_const)) {
			parser_error(state, "ERROR: parsing union member type\n");
			node_malformed_error(state, child, text, "union field");
			result = -1;
			goto urnexit;
		}

		TSNode field_declarator = ts_node_child_by_field_name(child, "declarator", 10);
		if (ts_node_is_null(field_declarator)) {
			parser_error(state, "ERROR: Union field AST should contain at least one declarator item");
			node_malformed_error(state, child, text, "union field");
			result = -1;
			goto urnexit;
		}

		// We could have multiple declarator members of the same type
		do {
			// First we extract the identifier
			free(real_identifier);
			real_identifier = ts_node_sub_string(field_declarator, text);
			if (!real_identifier) {
				parser_error(state, "ERROR: Union declarator should not be NULL!\n");
				node_malformed_error(state, child, text, "union field");
				result = -1;
				goto urnexit;
			}
			parser_debug(state, "field type: %s field_declarator: %s\n", real_type, real_identifier);

			// 1st case, bitfield
			// AST looks like
			// type: (primitive_type) declarator: (field_identifier) (bitfield_clause (number_literal))
			// Thus it has the additional node after the declarator
			TSNode next_sibling = ts_node_next_named_sibling(field_declarator);
			if (!ts_node_is_null(next_sibling) && is_bitfield_clause(ts_node_type(next_sibling))) {
				const char *bfnode_type = ts_node_type(field_type);
				// As per C standard bitfields are defined only for atomic types, particularly "int"
				if (strcmp(bfnode_type, "primitive_type") && strcmp(bfnode_type, "type_identifier")) {
					parser_error(state, "ERROR: Union bitfield cannot contain non-primitive bitfield!\n");
					node_malformed_error(state, child, text, "union field");
					result = -1;
					goto urnexit;
				}
				if (ts_node_named_child_count(next_sibling) != 1) {
					node_malformed_error(state, child, text, "union field");
					result = -1;
					goto urnexit;
				}
				TSNode field_bits = ts_node_named_child(next_sibling, 0);
				if (ts_node_is_null(field_bits)) {
					parser_error(state, "ERROR: Union bitfield bits AST node should not be NULL!\n");
					node_malformed_error(state, child, text, "union field");
					result = -1;
					goto urnexit;
				}
				const char *bits_str = ts_node_sub_string(field_bits, text);
				int bits = rz_num_get(NULL, bits_str);
				parser_debug(state, "field type: %s field_identifier: %s bits: %d\n", real_type, real_identifier, bits);
				// Then we augment resulting type field with the data from parsed declarator
				char *membname = NULL;
				if (parse_type_declarator_node(state, field_declarator, text, &membtpair, &membname)) {
					parser_error(state, "ERROR: parsing union member declarator\n");
					node_malformed_error(state, child, text, "union field");
					result = -1;
					goto urnexit;
				}
				// Add a union member
				RzVector *members = &union_pair->btype->union_data.members;
				RzTypeUnionMember memb = {
					.name = membname,
					.type = rz_type_clone(membtpair->type),
					.offset = 0, // Always 0 for unions
					.size = 0, // FIXME
				};
				void *element = rz_vector_push(members, &memb); // returns null if no space available
				if (!element) {
					parser_error(state, "Error appending union member to the base type\n");
					result = -1;
					goto urnexit;
				}
			} else if (is_declarator(ts_node_type(field_declarator))) {
				// 2nd case, normal union
				// AST looks like
				// type: (primitive_type) declarator: (field_identifier)
				// Then we augment resulting type field with the data from parsed declarator
				char *membname = NULL;
				if (parse_type_declarator_node(state, field_declarator, text, &membtpair, &membname)) {
					parser_error(state, "ERROR: parsing union member declarator\n");
					node_malformed_error(state, child, text, "union field");
					result = -1;
					goto urnexit;
				}
				// Add a union member
				RzVector *members = &union_pair->btype->union_data.members;
				RzTypeUnionMember memb = {
					.name = membname,
					.type = rz_type_clone(membtpair->type),
					.offset = 0, // Always 0 for unions
					.size = 0, // FIXME
				};
				void *element = rz_vector_push(members, &memb); // returns null if no space available
				if (!element) {
					parser_error(state, "Error appending union member to the base type\n");
					result = -1;
					goto urnexit;
				}
				parser_debug(state, "Appended member \"%s\" into union \"%s\"\n", membname, name);
			}
			field_declarator = ts_node_next_named_sibling(field_declarator);
		} while (!ts_node_is_null(field_declarator));
		free(membtpair);
	}
	// If parsing successfull completed - we store the state
	if (union_pair) {
		c_parser_base_type_store(state, name, union_pair);
		// If it was a forward definition previously - remove it
		if (c_parser_base_type_is_forward_definition(state, name)) {
			c_parser_forward_definition_remove(state, name);
		}
	}
	*tpair = union_pair;
urnexit:
	free(real_type);
	free(real_identifier);
unexit:
	free(name);
	return result;
}

// Parsing enum definitions - concrete and abstract ones
int parse_enum_node(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair, bool is_const) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	rz_return_val_if_fail(ts_node_is_named(node), -1);

	parser_debug(state, "parse_enum_node()\n");

	int enum_node_child_count = ts_node_named_child_count(node);
	// Possible nodes are "name", "underlying_type", "body"
	if (enum_node_child_count < 1 || enum_node_child_count > 3) {
		node_malformed_error(state, node, text, "enum");
		return -1;
	}
	int result = 0;
	// Name is optional, in abstract definitions or as the member of nested types
	char *name = NULL;
	TSNode enum_name = ts_node_child_by_field_name(node, "name", 4);
	if (ts_node_is_null(enum_name)) {
		parser_debug(state, "Anonymous enum\n");
		name = c_parser_new_anonymous_enum_name(state);
	} else {
		name = ts_node_sub_string(enum_name, text);
		if (!name) {
			parser_error(state, "ERROR: Enum name should not be NULL!\n");
			node_malformed_error(state, node, text, "enum");
			return -1;
		}
		parser_debug(state, "enum name: %s\n", name);
	}

	// Parsing the enum body
	// If the enum doesn't have body but has a name
	// it means that it uses the type predefined before
	// e.g. "const enum FOO a;"
	TSNode enum_body = ts_node_child_by_field_name(node, "body", 4);
	if (ts_node_is_null(enum_body) && !ts_node_is_null(enum_name)) {
		parser_debug(state, "Fetching predefined enum: \"%s\"\n", name);
		if (!(*tpair = c_parser_get_enum_type(state, name))) {
			parser_warning(state, "Cannot find \"%s\" enum in the context\n", name);
			// At first we check if there is a forward definion already
			if (c_parser_base_type_is_forward_definition(state, name)) {
				parser_debug(state, "Enum \"%s\" was forward-defined before\n", name);
				if (!(*tpair = c_parser_new_enum_naked_type(state, name))) {
					parser_error(state, "Cannot create \"%s\" naked enum type in the context\n", name);
					result = -1;
					goto rexit;
				}
				goto rexit;
			}
			// We still could create the "forward looking enum declaration"
			// The parser then can augment the definition
			if (!(*tpair = c_parser_new_enum_forward_definition(state, name))) {
				parser_error(state, "Cannot create \"%s\" forward enum definition in the context\n", name);
				result = -1;
				goto rexit;
			}
			goto rexit;
		} else {
			goto rexit;
		}
	}

	parser_debug(state, "enum name: %s\n", name);

	int body_child_count = ts_node_named_child_count(enum_body);
	// Now we form both RzType and RzBaseType to store in the Types database
	ParserTypePair *enum_pair = c_parser_new_enum_type(state, name, body_child_count);
	if (!enum_pair) {
		parser_error(state, "Error forming RzType and RzBaseType pair out of enum: \"%s\"\n", name);
		result = -1;
		goto rexit;
	}
	// Then we process all enumeration cases and add one by one
	int i;
	for (i = 0; i < body_child_count; i++) {
		parser_debug(state, "enum: processing %d field...\n", i);
		TSNode child = ts_node_named_child(enum_body, i);
		const char *node_type = ts_node_type(child);

		// Skip comments
		if (!strcmp(node_type, "comment")) {
			continue;
		}

		// Every field should have (field_declaration) AST clause
		if (strcmp(node_type, "enumerator")) {
			parser_error(state, "ERROR: Enum member AST should contain (enumerator) node!\n");
			node_malformed_error(state, child, text, "enum field");
			free(enum_pair);
			result = -1;
			goto rexit;
		}
		// Every member node should have at least 1 child!
		int member_child_count = ts_node_named_child_count(child);
		if (member_child_count < 1 || member_child_count > 2) {
			parser_error(state, "ERROR: enum member AST cannot contain less than 1 or more than 2 items");
			node_malformed_error(state, child, text, "enum field");
			free(enum_pair);
			result = -1;
			goto rexit;
		}
		// Every member can be:
		// - empty
		// - atomic: "1"
		// - expression: "1 << 2"
		if (state->verbose) {
			char *membertext = ts_node_sub_string(child, text);
			char *nodeast = ts_node_string(child);
			if (membertext && nodeast) {
				parser_debug(state, "member text: %s\n", membertext);
				parser_debug(state, "member ast: %s\n", nodeast);
			}
			free(nodeast);
			free(membertext);
		}
		if (member_child_count == 1) {
			// It's an empty field, like just "A,"
			TSNode member_identifier = ts_node_child_by_field_name(child, "name", 4);
			if (ts_node_is_null(member_identifier)) {
				parser_error(state, "ERROR: Enum case identifier should not be NULL!\n");
				node_malformed_error(state, child, text, "enum case");
				free(enum_pair);
				result = -1;
				goto rexit;
			}
			char *real_identifier = ts_node_sub_string(member_identifier, text);
			parser_debug(state, "enum member: %s\n", real_identifier);
			// Add an enum case
			RzVector *cases = &enum_pair->btype->enum_data.cases;
			// In this case we just increment previous value by 1
			st64 derived_val = 0;
			if (!rz_vector_empty(cases)) {
				RzTypeEnumCase *lastcase = rz_vector_tail(cases);
				derived_val = lastcase->val + 1;
			}
			RzTypeEnumCase cas = {
				.name = real_identifier,
				.val = derived_val
			};
			void *element = rz_vector_push(cases, &cas); // returns null if no space available
			if (!element) {
				parser_error(state, "Error appending enum case to the base type\n");
				free(cas.name);
				free(enum_pair);
				result = -1;
				goto rexit;
			}
		} else {
			// It's a proper field, like "A = 1,"
			TSNode member_identifier = ts_node_child_by_field_name(child, "name", 4);
			TSNode member_value = ts_node_child_by_field_name(child, "value", 5);
			if (ts_node_is_null(member_identifier) || ts_node_is_null(member_value)) {
				parser_error(state, "ERROR: Enum case identifier and value should not be NULL!\n");
				node_malformed_error(state, child, text, "enum case");
				free(enum_pair);
				result = -1;
				goto rexit;
			}
			char *real_identifier = ts_node_sub_string(member_identifier, text);
			char *real_value = ts_node_sub_string(member_value, text);
			// FIXME: Use RzNum to calculate complex expressions
			parser_debug(state, "enum member: %s value: %s\n", real_identifier, real_value);
			// Add an enum case
			RzVector *cases = &enum_pair->btype->enum_data.cases;
			RzTypeEnumCase cas = {
				.name = real_identifier,
				.val = rz_num_get(NULL, real_value)
			};
			free(real_value);
			void *element = rz_vector_push(cases, &cas); // returns null if no space available
			if (!element) {
				parser_error(state, "Error appending enum case to the base type\n");
				free(cas.name);
				free(enum_pair);
				result = -1;
				goto rexit;
			}
		}
	}
	// If parsing successfull completed - we store the state
	if (enum_pair) {
		c_parser_base_type_store(state, name, enum_pair);
		// If it was a forward definition previously - remove it
		if (c_parser_base_type_is_forward_definition(state, name)) {
			c_parser_forward_definition_remove(state, name);
		}
	}
	*tpair = enum_pair;
rexit:
	free(name);
	return result;
}

// Parsing typedefs - these are ALWAYS concrete due to the syntax specifics
int parse_typedef_node(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	rz_return_val_if_fail(ts_node_is_named(node), -1);

	parser_debug(state, "parse_typedef_node()\n");

	int typedef_node_child_count = ts_node_named_child_count(node);
	if (typedef_node_child_count < 2) {
		node_malformed_error(state, node, text, "typedef");
		return -1;
	}
	// Parse the type qualifier first
	// FIXME: There could be multiple different type qualifiers in one declaration
	bool is_const = false;

	TSNode first_leaf = ts_node_named_child(node, 0);
	if (ts_node_is_null(first_leaf)) {
		node_malformed_error(state, node, text, "typedef");
		return -1;
	}
	const char *leaf_type = ts_node_type(first_leaf);
	if (!strcmp(leaf_type, "type_qualifier")) {
		char *qualifier = ts_node_sub_string(first_leaf, text);
		parser_debug(state, "has qualifier %s\n", qualifier);
		if (!strcmp(qualifier, "const")) {
			is_const = true;
		}
		free(qualifier);
	}

	TSNode typedef_type = ts_node_child_by_field_name(node, "type", 4);
	if (ts_node_is_null(typedef_type)) {
		parser_error(state, "ERROR: Typedef type node should not be NULL!\n");
		node_malformed_error(state, node, text, "typedef");
		return -1;
	}
	// Every typedef type can be:
	// - atomic: "int", "uint64_t", etc
	// - some type name - any identificator
	// - complex type like struct, union, or enum
	if (state->verbose) {
		char *typetext = ts_node_sub_string(typedef_type, text);
		char *nodeast = ts_node_string(typedef_type);
		if (typetext && nodeast) {
			parser_debug(state, "type text: %s\n", typetext);
			parser_debug(state, "type ast: %s\n", nodeast);
		}
		free(typetext);
		free(nodeast);
	}
	ParserTypePair *type_pair = NULL;
	if (parse_type_node_single(state, typedef_type, text, &type_pair, is_const)) {
		parser_error(state, "ERROR: parsing typedef type identifier\n");
		node_malformed_error(state, typedef_type, text, "typedef type");
		return -1;
	}
	// Every typedef node could have multiple declarators
	TSNode typedef_declarator = ts_node_child_by_field_name(node, "declarator", 10);
	if (ts_node_is_null(typedef_declarator)) {
		parser_error(state, "ERROR: Typedef should have at least one declarator node!\n");
		node_malformed_error(state, node, text, "typedef");
		return -1;
	}

	do {
		// Then we augment resulting type field with the data from parsed declarator
		char *typedef_name = NULL;
		if (parse_type_declarator_node(state, typedef_declarator, text, &type_pair, &typedef_name)) {
			parser_error(state, "ERROR: parsing typedef declarator\n");
			node_malformed_error(state, typedef_declarator, text, "typedef declarator");
			return -1;
		}

		// Now we form both RzType and RzBaseType to store in the Types database
		// Note, that if base type is NULL then it's forward definition and we should
		// use the RzType identifier instead;
		const char *base_type_name = rz_type_identifier(type_pair->type);
		parser_debug(state, "typedef \"%s\" -> \"%s\"\n", typedef_name, base_type_name);
		ParserTypePair *typedef_pair = c_parser_new_typedef(state, typedef_name, base_type_name);
		if (!typedef_pair) {
			parser_error(state, "Error forming RzType and RzBaseType pair out of typedef: \"%s\"\n", typedef_name);
			return -1;
		}
		// If parsing successfull completed - we store the state
		if (typedef_pair) {
			typedef_pair->btype->type = rz_type_clone(type_pair->type);
			parser_debug(state, "storing typedef \"%s\" -> \"%s\"\n", typedef_name, base_type_name);
			c_parser_base_type_store(state, typedef_name, typedef_pair);
			// If it was a forward definition previously - remove it
			if (c_parser_base_type_is_forward_definition(state, typedef_name)) {
				c_parser_forward_definition_remove(state, typedef_name);
			}
		}
		// FIXME: We should return multiple types at once
		*tpair = typedef_pair;
		typedef_declarator = ts_node_next_named_sibling(typedef_declarator);
	} while (!ts_node_is_null(typedef_declarator) && is_type_declarator(ts_node_type(typedef_declarator)));

	return 0;
}

// Parses the node that represents just one type
// Despite the name could parse multiple types at once, if the share the type definition
int parse_type_node_single(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair, bool is_const) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	// We skip simple nodes (e.g. conditions and braces)
	if (!ts_node_is_named(node)) {
		return 0;
	}

	const char *node_type = ts_node_type(node);
	int result = -1;

	parser_debug(state, "parse_type_node_single(\"%s\")\n", node_type);

	if (!strcmp(node_type, "struct_specifier")) {
		result = parse_struct_node(state, node, text, tpair, is_const);
		if (result || !*tpair) {
			return -1;
		}
	} else if (!strcmp(node_type, "union_specifier")) {
		result = parse_union_node(state, node, text, tpair, is_const);
		if (result || !*tpair) {
			return -1;
		}
	} else if (!strcmp(node_type, "enum_specifier")) {
		result = parse_enum_node(state, node, text, tpair, is_const);
		if (result || !*tpair) {
			return -1;
		}
	} else if (!strcmp(node_type, "type_definition")) {
		result = parse_typedef_node(state, node, text, tpair);
		if (result || !*tpair) {
			return -1;
		}
	} else if (!strcmp(node_type, "sized_type_specifier")) {
		result = parse_sized_primitive_type(state, node, text, tpair, is_const);
		if (result || !*tpair) {
			return -1;
		}
	} else if (!strcmp(node_type, "primitive_type")) {
		result = parse_primitive_type(state, node, text, tpair, is_const);
		if (result || !*tpair) {
			return -1;
		}
	} else if (!strcmp(node_type, "type_identifier")) {
		result = parse_sole_type_name(state, node, text, tpair, is_const);
		if (result || !*tpair) {
			return -1;
		}
	}
	// Another case where there is a declaration clause
	// In this case we should drop the declaration itself
	// and parse only the corresponding type
	// In case of anonymous type we could use identifier as a name for this type?
	//
	return result;
}

// Parses the parameter list, e.g. in the function types/definition like arguments list
int parse_parameter_list(CParserState *state, TSNode paramlist, const char *text, ParserTypePair **tpair) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(paramlist), -1);
	// We skip simple nodes (e.g. conditions and braces)
	if (!ts_node_is_named(paramlist)) {
		return 0;
	}

	if ((*tpair)->type->kind != RZ_TYPE_KIND_CALLABLE) {
		parser_error(state, "ERROR: Parameter description only acceptable as part of function definition!\n");
		return -1;
	}
	parser_debug(state, "parse_parameter_list()\n");

	const char *node_type = ts_node_type(paramlist);
	if (strcmp(node_type, "parameter_list")) {
		node_malformed_error(state, paramlist, text, "parameter_list");
		return -1;
	}
	int paramlist_child_count = ts_node_named_child_count(paramlist);
	if (paramlist_child_count < 1) {
		node_malformed_error(state, paramlist, text, "parameter_list");
		return -1;
	}
	int i;
	for (i = 0; i < paramlist_child_count; i++) {
		parser_debug(state, "parameter_list: processing %d field...\n", i);
		TSNode child = ts_node_named_child(paramlist, i);
		const char *node_type = ts_node_type(child);
		// Every field should have (parameter_declaration) AST clause
		if (strcmp(node_type, "parameter_declaration") && strcmp(node_type, "variadic_parameter")) {
			parser_error(state, "ERROR: Parameter field AST should contain (parameter_declaration|variadic_parameter) node!\n");
			node_malformed_error(state, child, text, "parameter_declaration|variadic_parameter");
			return -1;
		}
		if (!strcmp(node_type, "variadic_parameter")) {
			// This is a variadic parameter "...", let's ignore it for now
			parser_debug(state, "Processing variadic parameter, ignoring for now...\n", i);
			continue;
		}
		char *identifier = NULL;
		// Create new TypePair here
		ParserTypePair *argtpair = NULL;
		if (parse_parameter_declaration_node(state, child, text, &argtpair, &identifier)) {
			parser_error(state, "ERROR: Parsing parameter declarator!\n");
			return -1;
		}
		if (!argtpair || !argtpair->type) {
			free(argtpair);
			return -1;
		}
		// Store the parameters if available
		// If the name is not available just name it as "argN" where N is argument index
		if (!identifier) {
			identifier = rz_str_newf("arg%d", i);
		}
		parser_debug(state, "Adding \"%s\" parameter\n", identifier);
		RzType *argtp = argtpair->type;
		free(argtpair);
		if (!c_parser_new_callable_argument(state, (*tpair)->type->callable, identifier, argtp)) {
			parser_error(state, "ERROR: Cannot add the parameter to the function!\n");
			free(identifier);
			return -1;
		}
		free(identifier);
	}
	return 0;
}

// Parses abstract declarator node - i.e. the type without the identifier
int parse_type_abstract_declarator_node(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	rz_return_val_if_fail(ts_node_is_named(node), -1);

	parser_debug(state, "parse_type_abstract_declarator_node()\n");

	// Parse the type qualifier first (if present)
	// FIXME: There could be multiple different type qualifiers in one declaration
	bool is_const = false;
	bool has_qualifiers = false;

	int node_child_count = ts_node_named_child_count(node);
	if (node_child_count > 0) {
		TSNode first_leaf = ts_node_named_child(node, 0);
		if (ts_node_is_null(first_leaf)) {
			node_malformed_error(state, node, text, "type_declarator_node");
			return -1;
		}
		const char *leaf_type = ts_node_type(first_leaf);
		// If we have type qualifier in this position it is related to
		// the declarator itself, not the type, e.g. constant pointer,
		// not pointer to the constant
		if (!strcmp(leaf_type, "type_qualifier")) {
			char *qualifier = ts_node_sub_string(first_leaf, text);
			parser_debug(state, "has qualifier %s\n", qualifier);
			if (!strcmp(qualifier, "const")) {
				is_const = true;
			}
			has_qualifiers = true;
			free(qualifier);
		}
	}

	const char *node_type = ts_node_type(node);
	int result = -1;
	if (!strcmp(node_type, "abstract_pointer_declarator")) {
		parser_debug(state, "abstract pointer declarator\n");

		// Now we wrap the existing type into the new one
		// The base type in the type pair remains the same
		RzType *type = RZ_NEW0(RzType);
		if (!type) {
			return -1;
		}
		type->kind = RZ_TYPE_KIND_POINTER;
		type->pointer.is_const = is_const;
		type->pointer.type = (*tpair)->type;
		(*tpair)->type = type;

		// It can contain additional children as:
		// - "abstract_array_declarator"
		// - "abstract_pointer_declarator"
		// - "abstract_function_declarator"
		// - Or multiple "type qualifiers"
		int pointer_node_child_count = ts_node_named_child_count(node);
		if (pointer_node_child_count > 0) {
			TSNode pointer_declarator = ts_node_child_by_field_name(node, "declarator", 10);
			if (ts_node_is_null(pointer_declarator) && !has_qualifiers) {
				parser_error(state, "ERROR: Abstract pointer declarator AST should contain at least one node!\n");
				node_malformed_error(state, node, text, "pointer declarator");
				free(type);
				(*tpair)->type = NULL;
				return -1;
			}
			if (!ts_node_is_null(pointer_declarator)) {
				const char *declarator_type = ts_node_type(pointer_declarator);
				if (!declarator_type) {
					node_malformed_error(state, pointer_declarator, text, "pointer declarator");
					free(type);
					(*tpair)->type = NULL;
					return -1;
				}
				if (is_abstract_declarator(declarator_type)) {
					result = parse_type_abstract_declarator_node(state, pointer_declarator, text, tpair);
				} else {
					result = 0;
				}
			} else {
				result = 0;
			}
		} else {
			parser_debug(state, "abstract pointer declarator has no children\n");
			result = 0;
		}
	} else if (!strcmp(node_type, "abstract_array_declarator")) {
		// It can have two states - with and without number literal
		int array_node_child_count = ts_node_named_child_count(node);
		if (array_node_child_count < 0 || array_node_child_count > 2) {
			node_malformed_error(state, node, text, "abstract_array_declarator");
			return -1;
		}
		// Now we wrap the existing type into the new one
		// The base type in the type pair remains the same
		RzType *type = RZ_NEW0(RzType);
		if (!type) {
			return -1;
		}

		type->kind = RZ_TYPE_KIND_ARRAY;
		// Optional number_literal node
		TSNode array_size = ts_node_child_by_field_name(node, "size", 4);
		if (ts_node_is_null(array_size)) {
			type->array.count = 0;
		} else {
			char *real_array_size = ts_node_sub_string(array_size, text);
			if (!real_array_size) {
				node_malformed_error(state, array_size, text, "abstract array size");
				free(type);
				return -1;
			}
			int array_sz = rz_num_get(NULL, real_array_size);
			type->array.count = array_sz;
			free(real_array_size);
		}
		type->array.type = (*tpair)->type;
		(*tpair)->type = type;

		// It also can contain the following abstract declarators as a child:
		// - abstract_array_declarator
		// - abstract_pointer_declarator
		TSNode array_declarator = ts_node_child_by_field_name(node, "declarator", 10);
		if (!ts_node_is_null(array_declarator)) {
			const char *declarator_type = ts_node_type(array_declarator);
			if (!declarator_type) {
				node_malformed_error(state, array_declarator, text, "declarator");
				return -1;
			}
			if (is_abstract_declarator(declarator_type)) {
				result = parse_type_abstract_declarator_node(state, array_declarator, text, tpair);
			} else {
				result = 0;
			}
		} else {
			result = 0;
		}
	} else if (!strcmp(node_type, "abstract_function_declarator")) {
		// It can only contain two nodes:
		// - abstract_parenthesized_declarator (usually empty)
		// - parameter_list
		int function_node_child_count = ts_node_named_child_count(node);
		if (function_node_child_count != 1) {
			node_malformed_error(state, node, text, "abstract_function_declarator");
			return -1;
		}
		TSNode parenthesized_declarator = ts_node_child_by_field_name(node, "declarator", 10);
		if (ts_node_is_null(parenthesized_declarator) || !ts_node_is_named(parenthesized_declarator)) {
			node_malformed_error(state, parenthesized_declarator, text, "parenthesized_declarator");
			return -1;
		}
		const char *declarator_type = ts_node_type(parenthesized_declarator);
		if (strcmp(declarator_type, "parenthesized_declarator")) {
			node_malformed_error(state, parenthesized_declarator, text, "parenthesized_declarator");
			return -1;
		}
		// Parsing parameters list
		TSNode parameter_list = ts_node_child_by_field_name(node, "parameters", 10);
		if (ts_node_is_null(parameter_list) || !ts_node_is_named(parameter_list)) {
			node_malformed_error(state, parameter_list, text, "parameter_list");
			return -1;
		}
		const char *param_list_type = ts_node_type(parameter_list);
		if (strcmp(param_list_type, "parameter_list")) {
			node_malformed_error(state, parameter_list, text, "parameter_list");
			return -1;
		}
		// Generate a sequential function type name if it's not specified
		const char *name = c_parser_new_anonymous_callable_name(state);
		RzType *parent_type = (*tpair)->type;
		(*tpair)->type = c_parser_new_callable(state, name);
		if (!(*tpair)->type) {
			parser_error(state, "ERROR: creating new callable type: \"%s\"\n", name);
			return -1;
		}

		result = parse_parameter_list(state, parameter_list, text, tpair);
		if (result) {
			parser_error(state, "ERROR: parsing parameters for callable type: \"%s\"\n", name);
			return -1;
		}
		// The previously fetched type in this case is the callable return type
		(*tpair)->type->callable->ret = parent_type;
		if (!c_parser_callable_type_store(state, name, (*tpair)->type)) {
			parser_error(state, "ERROR: storing the new callable type: \"%s\"\n", name);
			return -1;
		}
	}
	return result;
}

static bool is_identifier(const char *type) {
	return (!strcmp(type, "identifier") || !strcmp(type, "field_identifier") || !strcmp(type, "type_identifier"));
}

// Parses the concrete type declarator - i.e. type with the identifier
// It doesn't allocate a new ParserTypePair, but augments already existing one
// Also it returns the identifier name
int parse_type_declarator_node(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair, char **identifier) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	rz_return_val_if_fail(ts_node_is_named(node), -1);

	parser_debug(state, "parse_type_declarator_node()\n");
	// Parse the type qualifier first
	// FIXME: There could be multiple different type qualifiers in one declaration
	bool is_const = false;

	int node_child_count = ts_node_named_child_count(node);
	if (node_child_count > 0) {
		TSNode first_leaf = ts_node_named_child(node, 0);
		if (ts_node_is_null(first_leaf)) {
			node_malformed_error(state, node, text, "type_declarator_node");
			return -1;
		}
		const char *leaf_type = ts_node_type(first_leaf);
		if (!strcmp(leaf_type, "type_qualifier")) {
			char *qualifier = ts_node_sub_string(first_leaf, text);
			parser_debug(state, "has qualifier %s\n", qualifier);
			if (!strcmp(qualifier, "const")) {
				is_const = true;
			}
			free(qualifier);
		}
	}

	const char *node_type = ts_node_type(node);
	int result = -1;

	if (is_identifier(node_type)) {
		// Identifier, usually the last leaf of the AST tree
		char *real_ident = ts_node_sub_string(node, text);
		parser_debug(state, "identifier: %s\n", real_ident);
		*identifier = real_ident;
		result = 0;
	} else if (!strcmp(node_type, "pointer_declarator")) {
		char *real_ident = ts_node_sub_string(node, text);
		parser_debug(state, "pointer declarator: %s\n", real_ident);
		// It can contain additional children recursively
		// - "array_declarator"
		// - "pointer_declarator"
		// - "function_declarator"
		// - "identifier"
		// Every pointer declarator should have at least declarator field
		TSNode pointer_declarator = ts_node_child_by_field_name(node, "declarator", 10);
		if (ts_node_is_null(pointer_declarator)) {
			parser_error(state, "ERROR: Pointer declarator AST should contain at least one node!\n");
			node_malformed_error(state, node, text, "pointer declarator");
			free(real_ident);
			return -1;
		}
		const char *declarator_type = ts_node_type(pointer_declarator);
		if (!declarator_type) {
			node_malformed_error(state, pointer_declarator, text, "pointer declarator");
			free(real_ident);
			return -1;
		}

		// Now we wrap the existing type into the new one
		// The base type in the type pair remains the same
		RzType *type = RZ_NEW0(RzType);
		if (!type) {
			free(real_ident);
			return -1;
		}
		type->kind = RZ_TYPE_KIND_POINTER;
		type->pointer.is_const = is_const;
		type->pointer.type = (*tpair)->type;
		(*tpair)->type = type;

		if (is_declarator(declarator_type) || is_identifier(declarator_type)) {
			result = parse_type_declarator_node(state, pointer_declarator, text, tpair, identifier);
		} else {
			result = 0;
		}
		free(real_ident);
	} else if (!strcmp(node_type, "array_declarator")) {
		char *real_ident = ts_node_sub_string(node, text);
		parser_debug(state, "array declarator: %s\n", real_ident);
		free(real_ident);

		// Every array declarator should have at least declarator field
		// The size field is optional
		TSNode array_declarator = ts_node_child_by_field_name(node, "declarator", 10);
		TSNode array_size = ts_node_child_by_field_name(node, "size", 4);
		if (ts_node_is_null(array_declarator)) {
			parser_error(state, "ERROR: Array declarator AST should contain at least one node!\n");
			node_malformed_error(state, node, text, "array declarator");
			return -1;
		}

		const char *declarator_type = ts_node_type(array_declarator);
		if (!declarator_type) {
			node_malformed_error(state, array_declarator, text, "array declarator");
			return -1;
		}
		// Now we wrap the existing type into the new one
		// The base type in the type pair remains the same
		RzType *type = RZ_NEW0(RzType);
		if (!type) {
			return -1;
		}
		type->kind = RZ_TYPE_KIND_ARRAY;
		if (ts_node_is_null(array_size)) {
			type->array.count = 0;
		} else {
			// number_literal node
			char *real_array_size = ts_node_sub_string(array_size, text);
			if (!real_array_size) {
				node_malformed_error(state, array_size, text, "array size");
				free(type);
				return -1;
			}
			int array_sz = rz_num_get(NULL, real_array_size);
			type->array.count = array_sz;
			free(real_array_size);
		}
		type->array.type = (*tpair)->type;
		(*tpair)->type = type;

		parser_debug(state, "array declarator type: %s\n", declarator_type);
		if (is_declarator(declarator_type) || is_identifier(declarator_type)) {
			result = parse_type_declarator_node(state, array_declarator, text, tpair, identifier);
		} else {
			return 0;
		}
	} else if (!strcmp(node_type, "function_declarator")) {
		char *real_ident = ts_node_sub_string(node, text);
		parser_debug(state, "function declarator: %s\n", real_ident);
		free(real_ident);
		// It can only contain two nodes:
		// - declarator
		// - parameters
		int function_node_child_count = ts_node_named_child_count(node);
		if (function_node_child_count > 2) {
			node_malformed_error(state, node, text, "function_declarator");
			return -1;
		}
		TSNode declarator = ts_node_child_by_field_name(node, "declarator", 10);
		if (ts_node_is_null(declarator) || !ts_node_is_named(declarator)) {
			node_malformed_error(state, declarator, text, "declarator");
			return -1;
		}
		const char *declarator_type = ts_node_type(declarator);
		// Declarator could be either parenthesized_declarator or identifier
		if (!is_function_declarator(declarator_type)) {
			node_malformed_error(state, declarator, text, "function declarator or identifier");
			return -1;
		}
		RzType *parent_type = (*tpair)->type;
		// At first we create "freestanding" unnamed callable
		RzType *naked_callable = c_parser_new_naked_callable(state);
		if (!naked_callable) {
			parser_error(state, "ERROR: creating naked callable type\n");
			return -1;
		}
		// The previously fetched type in this case is the callable return type
		naked_callable->callable->ret = parent_type;
		(*tpair)->type = naked_callable;

		// Declarator can be either "identifier" directly or have children
		if (is_identifier(declarator_type)) {
			parser_debug(state, "function declarator: simple identifier\n");
			if (parse_type_declarator_node(state, declarator, text, tpair, identifier)) {
				parser_error(state, "ERROR: parsing function declarator\n");
				node_malformed_error(state, declarator, text, "function identifier");
				return -1;
			}
		} else {
			TSNode function_declarator = ts_node_named_child(declarator, 0);
			const char *function_declarator_type = ts_node_type(function_declarator);
			if (!function_declarator_type) {
				node_malformed_error(state, function_declarator, text, "function declarator");
				return -1;
			}

			// Declarator can contain either "identifier" directly
			// Or the pointer_declarator instead (or multiple of them nested in each other)
			if (is_declarator(function_declarator_type) || is_identifier(function_declarator_type)) {
				if (parse_type_declarator_node(state, function_declarator, text, tpair, identifier)) {
					parser_error(state, "ERROR: parsing function declarator\n");
					node_malformed_error(state, function_declarator, text, "function declarator");
					return -1;
				}
			} else {
				parser_error(state, "ERROR: missing function declarator\n");
				node_malformed_error(state, function_declarator, text, "function declarator");
				return -1;
			}
		}

		// Parsing parameters list
		TSNode parameter_list = ts_node_child_by_field_name(node, "parameters", 10);
		if (ts_node_is_null(parameter_list) || !ts_node_is_named(parameter_list)) {
			node_malformed_error(state, parameter_list, text, "parameter_list");
			return -1;
		}
		const char *param_list_type = ts_node_type(parameter_list);
		if (strcmp(param_list_type, "parameter_list")) {
			node_malformed_error(state, parameter_list, text, "parameter_list");
			return -1;
		}
		naked_callable->callable->name = rz_str_dup(*identifier);
		// Preserve the parent callable type
		parent_type = (*tpair)->type;
		// Then override with the naked callable type to proceed with parameter parsing
		(*tpair)->type = naked_callable;
		result = parse_parameter_list(state, parameter_list, text, tpair);
		if (result) {
			parser_error(state, "ERROR: parsing parameters for callable type: \"%s\"\n", *identifier);
			return -1;
		}
		// Restore the true parent type
		(*tpair)->type = parent_type;
		if (!c_parser_callable_type_store(state, *identifier, naked_callable)) {
			parser_error(state, "ERROR: storing the new callable type: \"%s\"\n", *identifier);
			return -1;
		}
	}
	return result;
}

// Parses the single type descriptor - it can be either concrete or an abstract one
// In the case of concrete descriptor it calls "parse_type_declarator_node()"
// In the case of abstract descriptor it calls "parse_type_abstract_declarator_node()"
int parse_type_descriptor_single(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	// We skip simple nodes (e.g. conditions and braces)
	if (!ts_node_is_named(node)) {
		return 0;
	}
	const char *node_type = ts_node_type(node);
	int result = -1;
	if (strcmp(node_type, "type_descriptor")) {
		return -1;
	}
	parser_debug(state, "parse_type_descriptor_single()\n");

	int typedesc_node_child_count = ts_node_named_child_count(node);
	if (typedesc_node_child_count < 1) {
		node_malformed_error(state, node, text, "type_descriptor");
		return -1;
	}
	// Type descriptor has three fields:
	// 0. type qualifier (optional)
	// 1. type itself
	// 2. declarator field (optional)

	// Parse the type qualifier first
	// FIXME: There could be multiple different type qualifiers in one declaration
	bool is_const = false;
	TSNode first_leaf = ts_node_named_child(node, 0);
	if (ts_node_is_null(first_leaf)) {
		node_malformed_error(state, node, text, "type_descriptor");
		return -1;
	}
	const char *leaf_type = ts_node_type(first_leaf);
	if (!strcmp(leaf_type, "type_qualifier")) {
		char *qualifier = ts_node_sub_string(first_leaf, text);
		parser_debug(state, "has qualifier \"%s\"\n", qualifier);
		if (!strcmp(qualifier, "const")) {
			parser_debug(state, "set const\n");
			is_const = true;
		}
		free(qualifier);
	}

	TSNode type_node = ts_node_child_by_field_name(node, "type", 4);
	if (ts_node_is_null(type_node)) {
		node_malformed_error(state, node, text, "type_descriptor");
		parser_error(state, "type_descriptor's type field cannot be NULL\n");
		return -1;
	}
	if (parse_type_node_single(state, type_node, text, tpair, is_const)) {
		node_malformed_error(state, node, text, "type_descriptor");
		parser_error(state, "Cannot parse type_descriptor's type field\n");
		return -1;
	}
	if (!*tpair) {
		parser_error(state, "Failed to parse type_descriptor's type field\n");
		return -1;
	}
	// 2. Optional declarator field
	TSNode type_declarator = ts_node_child_by_field_name(node, "declarator", 10);
	if (!ts_node_is_null(type_declarator)) {
		return parse_type_abstract_declarator_node(state, type_declarator, text, tpair);
	} else {
		result = 0;
	}
	return result;
}

// Parses the declaration node
int parse_declaration_node(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	// We skip simple nodes (e.g. conditions and braces)
	if (!ts_node_is_named(node)) {
		return 0;
	}
	const char *node_type = ts_node_type(node);
	int result = -1;
	if (strcmp(node_type, "declaration")) {
		return -1;
	}
	parser_debug(state, "parse_type_declaration_node()\n");

	int declaration_node_child_count = ts_node_named_child_count(node);
	if (declaration_node_child_count < 1) {
		node_malformed_error(state, node, text, "declaration");
		return -1;
	}
	// Type declaration has three fields:
	// 0. type qualifier (optional)
	// 1. type itself
	// 2. declarator field (optional)

	// Parse the type qualifier first
	// FIXME: There could be multiple different type qualifiers in one declaration
	bool is_const = false;
	TSNode first_leaf = ts_node_named_child(node, 0);
	if (ts_node_is_null(first_leaf)) {
		node_malformed_error(state, node, text, "declaration");
		return -1;
	}
	const char *leaf_type = ts_node_type(first_leaf);
	if (!strcmp(leaf_type, "type_qualifier")) {
		char *qualifier = ts_node_sub_string(first_leaf, text);
		parser_debug(state, "has qualifier \"%s\"\n", qualifier);
		if (!strcmp(qualifier, "const")) {
			parser_debug(state, "set const\n");
			is_const = true;
		}
		free(qualifier);
	}

	TSNode type_node = ts_node_child_by_field_name(node, "type", 4);
	if (ts_node_is_null(type_node)) {
		node_malformed_error(state, node, text, "declaration");
		parser_error(state, "declaration's type field cannot be NULL\n");
		return -1;
	}
	if (parse_type_node_single(state, type_node, text, tpair, is_const)) {
		node_malformed_error(state, node, text, "declaration");
		parser_error(state, "Cannot parse declaration's type field\n");
		return -1;
	}
	if (!*tpair) {
		parser_error(state, "Failed to parse declaration's type field\n");
		return -1;
	}
	// 2. Optional declarator field
	TSNode type_declarator = ts_node_child_by_field_name(node, "declarator", 10);
	if (!ts_node_is_null(type_declarator)) {
		char *identifier = NULL;
		return parse_type_declarator_node(state, type_declarator, text, tpair, &identifier);
	} else {
		result = 0;
	}
	return result;
}

// Types can be
// - struct (struct_specifier)
// - union (union_specifier)
// - enum (enum_specifier) (usually prepended by declaration)
// - typedef (type_definition)
// - atomic type (primitive_type)
// - declaration ()

// Parses the node and saves the resulting RzBaseTypes in the state hashtables
int parse_type_nodes_save(CParserState *state, TSNode node, const char *text) {
	rz_return_val_if_fail(state && text, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	// We skip simple nodes (e.g. conditions and braces)
	if (!ts_node_is_named(node)) {
		return 0;
	}
	const char *node_type = ts_node_type(node);
	int result = -1;
	ParserTypePair *tpair = NULL;
	if (!strcmp(node_type, "struct_specifier")) {
		result = parse_struct_node(state, node, text, &tpair, false);
		if (result || !tpair) {
			return -1;
		}
	} else if (!strcmp(node_type, "union_specifier")) {
		result = parse_union_node(state, node, text, &tpair, false);
		if (result || !tpair) {
			return -1;
		}
	} else if (!strcmp(node_type, "enum_specifier")) {
		result = parse_enum_node(state, node, text, &tpair, false);
		if (result || !tpair) {
			return -1;
		}
	} else if (!strcmp(node_type, "type_definition")) {
		result = parse_typedef_node(state, node, text, &tpair);
		if (result || !tpair) {
			return -1;
		}
	}

	// Another case where there is a declaration clause
	// In this case we should drop the declaration itself
	// and parse only the corresponding type. An exception for this
	// rule is the function declaration.
	if (!strcmp(node_type, "declaration")) {
		result = parse_declaration_node(state, node, text, &tpair);
		if (result || !tpair) {
			return -1;
		}
	}

	if (tpair) {
		rz_type_free(tpair->type);
		free(tpair);
	}

	if (result) {
		char *typetext = ts_node_sub_string(node, text);
		parser_error(state, "Unsupported type definition: %s\n", typetext);
		free(typetext);
	}

	// In case of anonymous type we could use identifier as a name for this type?
	return result;
}
