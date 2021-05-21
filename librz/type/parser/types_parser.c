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
	rz_return_if_fail(nodetype && !ts_node_is_null(node));
	char *string = ts_node_string(node);
	char *piece = ts_node_sub_string(node, text);
	rz_strbuf_appendf(state->errors, "Wrongly formed \"(%s)\": \"%s\"\n", nodetype, string);
	rz_strbuf_appendf(state->errors, "\"(%s)\": \"%s\"\n", nodetype, piece);
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
	const char *real_type = ts_node_sub_string(node, text);
	if (!real_type) {
		node_malformed_error(state, node, text, "primitive type");
		parser_error(state, "Primitive type name cannot be NULL\n");
		return -1;
	}
	// At first we search if the type is already presented in the state
	if ((*tpair = c_parser_get_primitive_type(state, real_type, is_const))) {
		parser_debug(state, "Fetched primitive type: \"%s\"\n", real_type);
		return 0;
	}
	// If not - we form both RzType and RzBaseType to store in the Types database
	ParserTypePair *type_pair = c_parser_new_primitive_type(state, real_type, is_const);
	if (!type_pair) {
		parser_error(state, "Error forming RzType and RzBaseType pair out of primitive type\n");
		return -1;
	}
	c_parser_base_type_store(state, real_type, type_pair);
	*tpair = type_pair;
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
	const char *real_type = ts_node_sub_string(node, text);
	if (!real_type) {
		node_malformed_error(state, node, text, "primitive type");
		parser_error(state, "Primitive type name cannot be NULL\n");
		return -1;
	}
	// At first we search if the type is already presented in the state
	if ((*tpair = c_parser_get_primitive_type(state, real_type, is_const))) {
		parser_debug(state, "Fetched primitive type: \"%s\"\n", real_type);
		return 0;
	}
	// If not - we form both RzType and RzBaseType to store in the Types database
	ParserTypePair *type_pair = c_parser_new_primitive_type(state, real_type, is_const);
	if (!type_pair) {
		parser_error(state, "Error forming RzType and RzBaseType pair out of primitive type\n");
		return -1;
	}
	c_parser_base_type_store(state, real_type, type_pair);
	*tpair = type_pair;
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
	const char *real_type = ts_node_sub_string(node, text);
	// At first we search if the type is already presented in the state and is a primitive one
	if ((*tpair = c_parser_get_primitive_type(state, real_type, is_const))) {
		parser_debug(state, "Fetched type: \"%s\"\n", real_type);
		return 0;
	}
	// After that we search if the type is already presented in the state and is a type alias
	if ((*tpair = c_parser_get_typedef(state, real_type))) {
		parser_debug(state, "Fetched type: \"%s\"\n", real_type);
		return 0;
	}
	parser_error(state, "Cannot find type \"%s\" in the state\n", real_type);
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
			const char *qualifier = ts_node_sub_string(first_leaf, text);
			parser_debug(state, "has qualifier %s\n", qualifier);
			if (!strcmp(qualifier, "const")) {
				is_const = true;
			}
		}
	}

	// Ever parameter should have at least declarator field
	TSNode parameter_declarator = ts_node_child_by_field_name(node, "declarator", 10);
	if (ts_node_is_null(parameter_declarator)) {
		parser_error(state, "ERROR: Parameter AST should contain at least one node!\n");
		node_malformed_error(state, node, text, "parameter declarator");
		return -1;
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

	// Check if it's abstract or a concrete node
	const char *declarator_type = ts_node_type(parameter_declarator);
	if (!declarator_type) {
		node_malformed_error(state, parameter_declarator, text, "parameter declarator");
		return -1;
	}
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

	parser_error(state, "parse_struct_node()\n");

	int struct_node_child_count = ts_node_named_child_count(node);
	if (struct_node_child_count < 1 || struct_node_child_count > 2) {
		node_malformed_error(state, node, text, "struct");
		return -1;
	}
	// Name is optional, in abstract definitions or as the member of nested types
	const char *name = NULL;
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
			parser_error(state, "Cannot find \"%s\" structure in the context\n", name);
			// We still could create the "forward looking struct declaration"
			// The parser then can augment the definition
			if (!(*tpair = c_parser_new_structure_forward_definition(state, name))) {
				parser_error(state, "Cannot create \"%s\" forward structure definition in the context\n", name);
				return -1;
			}
			return 0;
		} else {
			return 0;
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
		parser_error(state, "Error forming RzType and RzBaseType pair out of struct\n");
		return -1;
	}
	int i;
	for (i = 0; i < body_child_count; i++) {
		parser_debug(state, "struct: processing %d field...\n", i);
		TSNode child = ts_node_named_child(struct_body, i);
		const char *node_type = ts_node_type(child);

		// Parse the type qualifier first (if present)
		// FIXME: There could be multiple different type qualifiers in one declaration
		bool is_const = false;
		TSNode first_leaf = ts_node_named_child(child, 0);
		if (ts_node_is_null(first_leaf)) {
			node_malformed_error(state, child, text, "field_declaration");
			return -1;
		}
		const char *leaf_type = ts_node_type(first_leaf);
		// If we have type qualifier in this position it is related to
		// the declarator itself, not the type, e.g. constant pointer,
		// not pointer to the constant
		if (!strcmp(leaf_type, "type_qualifier")) {
			const char *qualifier = ts_node_sub_string(first_leaf, text);
			parser_debug(state, "has qualifier %s\n", qualifier);
			if (!strcmp(qualifier, "const")) {
				is_const = true;
			}
		}

		// Every field should have (field_declaration) AST clause
		if (strcmp(node_type, "field_declaration")) {
			parser_error(state, "ERROR: Struct field AST should contain (field_declaration) node!\n");
			node_malformed_error(state, child, text, "struct field");
			return -1;
		}

		// Every field node should have at least type and declarator:
		TSNode field_type = ts_node_child_by_field_name(child, "type", 4);
		TSNode field_declarator = ts_node_child_by_field_name(child, "declarator", 10);
		if (ts_node_is_null(field_type) || ts_node_is_null(field_declarator)) {
			parser_error(state, "ERROR: Struct field AST shoudl contain type and declarator items");
			node_malformed_error(state, child, text, "struct field");
			return -1;
		}
		// Every field can be:
		// - atomic: "int a;" or "char b[20]"
		// - bitfield: int a:7;"
		// - nested: "struct { ... } a;" or "union { ... } a;"
		if (state->verbose) {
			const char *fieldtext = ts_node_sub_string(child, text);
			char *nodeast = ts_node_string(child);
			if (fieldtext && nodeast) {
				parser_debug(state, "field text: %s\n", fieldtext);
				parser_debug(state, "field ast: %s\n", nodeast);
			}
			free(nodeast);
		}
		// 1st case, bitfield
		// AST looks like
		// type: (primitive_type) declarator: (field_identifier) (bitfield_clause (number_literal))
		// Thus it has the additional node after the declarator
		TSNode bitfield_clause = ts_node_next_named_sibling(field_declarator);
		if (!ts_node_is_null(bitfield_clause)) {
			// As per C standard bitfields are defined only for atomic types, particularly "int"
			if (strcmp(ts_node_type(field_type), "primitive_type")) {
				parser_error(state, "ERROR: Struct bitfield cannot contain non-primitive bitfield!\n");
				node_malformed_error(state, child, text, "struct field");
				return -1;
			}
			const char *real_type = ts_node_sub_string(field_type, text);
			if (!real_type) {
				parser_error(state, "ERROR: Struct bitfield type should not be NULL!\n");
				node_malformed_error(state, child, text, "struct field");
				return -1;
			}
			const char *real_identifier = ts_node_sub_string(field_declarator, text);
			if (!real_identifier) {
				parser_error(state, "ERROR: Struct bitfield identifier should not be NULL!\n");
				node_malformed_error(state, child, text, "struct field");
				return -1;
			}
			if (ts_node_named_child_count(bitfield_clause) != 1) {
				node_malformed_error(state, child, text, "struct field");
				return -1;
			}
			TSNode field_bits = ts_node_named_child(bitfield_clause, 0);
			if (ts_node_is_null(field_bits)) {
				parser_error(state, "ERROR: Struct bitfield bits AST node should not be NULL!\n");
				node_malformed_error(state, child, text, "struct field");
				return -1;
			}
			const char *bits_str = ts_node_sub_string(field_bits, text);
			int bits = rz_num_get(NULL, bits_str);
			parser_debug(state, "field type: %s field_identifier: %s bits: %d\n", real_type, real_identifier, bits);
			ParserTypePair *membtpair = NULL;
			if (parse_type_node_single(state, field_type, text, &membtpair, is_const)) {
				parser_error(state, "ERROR: parsing bitfield struct member identifier\n");
				node_malformed_error(state, child, text, "struct field");
				return -1;
			}
			// Then we augment resulting type field with the data from parsed declarator
			char *membname = NULL;
			if (parse_type_declarator_node(state, field_declarator, text, &membtpair, &membname)) {
				parser_error(state, "ERROR: parsing bitfield struct member declarator\n");
				node_malformed_error(state, child, text, "struct field");
				return -1;
			}
			// Add a struct member
			RzVector *members = &struct_pair->btype->struct_data.members;
			RzTypeStructMember memb = {
				.name = membname,
				.type = membtpair->type,
				.offset = 0, // FIXME
				.size = 0, // FIXME
			};
			void *element = rz_vector_push(members, &memb); // returns null if no space available
			if (!element) {
				parser_error(state, "Error appending bitfield struct member to the base type\n");
				return -1;
			}
		} else {
			// 2nd case, normal structure
			// AST looks like
			// type: (primitive_type) declarator: (field_identifier)
			const char *real_type = ts_node_sub_string(field_type, text);
			if (!real_type) {
				parser_error(state, "ERROR: Struct field type should not be NULL!\n");
				node_malformed_error(state, child, text, "struct field");
				return -1;
			}
			const char *real_identifier = ts_node_sub_string(field_declarator, text);
			if (!real_identifier) {
				parser_error(state, "ERROR: Struct declarator should not be NULL!\n");
				node_malformed_error(state, child, text, "struct field");
				return -1;
			}
			parser_debug(state, "field type: %s field_declarator: %s\n", real_type, real_identifier);
			ParserTypePair *membtpair = NULL;
			// At first, we parse the type field
			if (parse_type_node_single(state, field_type, text, &membtpair, is_const)) {
				parser_error(state, "ERROR: parsing struct member type\n");
				node_malformed_error(state, child, text, "struct field");
				return -1;
			}
			// Then we augment resulting type field with the data from parsed declarator
			char *membname = NULL;
			if (parse_type_declarator_node(state, field_declarator, text, &membtpair, &membname)) {
				parser_error(state, "ERROR: parsing struct member declarator\n");
				node_malformed_error(state, child, text, "struct field");
				return -1;
			}
			// Add a struct member
			RzVector *members = &struct_pair->btype->struct_data.members;
			RzTypeStructMember memb = {
				.name = membname,
				.type = membtpair->type,
				.offset = 0, // FIXME
				.size = 0, // FIXME
			};
			void *element = rz_vector_push(members, &memb); // returns null if no space available
			if (!element) {
				parser_error(state, "Error appending struct member to the base type\n");
				return -1;
			}
			parser_debug(state, "Appended member \"%s\" into struct \"%s\"\n", membname, name);
		}
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
	return 0;
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
	// Name is optional, in abstract definitions or as the member of nested types
	const char *name = NULL;
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
			parser_error(state, "Cannot find \"%s\" union in the context\n", name);
			// We still could create the "forward looking union declaration"
			// The parser then can augment the definition
			if (!(*tpair = c_parser_new_union_forward_definition(state, name))) {
				parser_error(state, "Cannot create \"%s\" forward union definition in the context\n", name);
				return -1;
			}
			return 0;
		} else {
			return 0;
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
	int i;
	for (i = 0; i < body_child_count; i++) {
		parser_debug(state, "union: processing %d field...\n", i);
		TSNode child = ts_node_named_child(union_body, i);
		const char *node_type = ts_node_type(child);

		// Parse the type qualifier first (if present)
		// FIXME: There could be multiple different type qualifiers in one declaration
		bool is_const = false;
		TSNode first_leaf = ts_node_named_child(child, 0);
		if (ts_node_is_null(first_leaf)) {
			node_malformed_error(state, child, text, "field_declaration");
			return -1;
		}
		const char *leaf_type = ts_node_type(first_leaf);
		// If we have type qualifier in this position it is related to
		// the declarator itself, not the type, e.g. constant pointer,
		// not pointer to the constant
		if (!strcmp(leaf_type, "type_qualifier")) {
			const char *qualifier = ts_node_sub_string(first_leaf, text);
			parser_debug(state, "has qualifier %s\n", qualifier);
			if (!strcmp(qualifier, "const")) {
				is_const = true;
			}
		}

		// Every field should have (field_declaration) AST clause
		if (strcmp(node_type, "field_declaration")) {
			parser_error(state, "ERROR: Union field AST should contain (field_declaration) node!\n");
			node_malformed_error(state, child, text, "union field");
			return -1;
		}

		// Every field node should have at least type and declarator:
		TSNode field_type = ts_node_child_by_field_name(child, "type", 4);
		TSNode field_declarator = ts_node_child_by_field_name(child, "declarator", 10);
		if (ts_node_is_null(field_type) || ts_node_is_null(field_declarator)) {
			parser_error(state, "ERROR: Union field AST shoudl contain type and declarator items");
			node_malformed_error(state, child, text, "union field");
			return -1;
		}
		// Every field can be:
		// - atomic: "int a;" or "char b[20]"
		// - bitfield: int a:7;"
		// - nested: "struct { ... } a;" or "union { ... } a;"
		if (state->verbose) {
			const char *fieldtext = ts_node_sub_string(child, text);
			char *nodeast = ts_node_string(child);
			if (fieldtext && nodeast) {
				parser_debug(state, "field text: %s\n", fieldtext);
				parser_debug(state, "field ast: %s\n", nodeast);
			}
			free(nodeast);
		}
		// 1st case, bitfield
		// AST looks like
		// type: (primitive_type) declarator: (field_identifier) (bitfield_clause (number_literal))
		// Thus it has the additional node after the declarator
		TSNode bitfield_clause = ts_node_next_named_sibling(field_declarator);
		if (!ts_node_is_null(bitfield_clause)) {
			// As per C standard bitfields are defined only for atomic types, particularly "int"
			if (strcmp(ts_node_type(field_type), "primitive_type")) {
				parser_error(state, "ERROR: Union bitfield cannot contain non-primitive bitfield!\n");
				node_malformed_error(state, child, text, "union field");
				return -1;
			}
			const char *real_type = ts_node_sub_string(field_type, text);
			if (!real_type) {
				parser_error(state, "ERROR: Union bitfield type should not be NULL!\n");
				node_malformed_error(state, child, text, "union field");
				return -1;
			}
			const char *real_identifier = ts_node_sub_string(field_declarator, text);
			if (!real_identifier) {
				parser_error(state, "ERROR: Union bitfield identifier should not be NULL!\n");
				node_malformed_error(state, child, text, "union field");
				return -1;
			}
			if (ts_node_named_child_count(bitfield_clause) != 1) {
				node_malformed_error(state, child, text, "union field");
				return -1;
			}
			TSNode field_bits = ts_node_named_child(bitfield_clause, 0);
			if (ts_node_is_null(field_bits)) {
				parser_error(state, "ERROR: Union bitfield bits AST node should not be NULL!\n");
				node_malformed_error(state, child, text, "union field");
				return -1;
			}
			const char *bits_str = ts_node_sub_string(field_bits, text);
			int bits = rz_num_get(NULL, bits_str);
			parser_debug(state, "field type: %s field_identifier: %s bits: %d\n", real_type, real_identifier, bits);
			ParserTypePair *membtpair = NULL;
			if (parse_type_node_single(state, field_type, text, &membtpair, is_const)) {
				parser_error(state, "ERROR: parsing union member identifier\n");
				node_malformed_error(state, child, text, "union field");
				return -1;
			}
			// Then we augment resulting type field with the data from parsed declarator
			char *membname = NULL;
			if (parse_type_declarator_node(state, field_declarator, text, &membtpair, &membname)) {
				parser_error(state, "ERROR: parsing union member declarator\n");
				node_malformed_error(state, child, text, "union field");
				return -1;
			}
			// Add a union member
			RzVector *members = &union_pair->btype->union_data.members;
			RzTypeUnionMember memb = {
				.name = membname,
				.type = membtpair->type,
				.offset = 0, // Always 0 for unions
				.size = 0, // FIXME
			};
			void *element = rz_vector_push(members, &memb); // returns null if no space available
			if (!element) {
				parser_error(state, "Error appending union member to the base type\n");
				return -1;
			}
		} else {
			// 2nd case, normal union
			// AST looks like
			// type: (primitive_type) declarator: (field_identifier)
			const char *real_type = ts_node_sub_string(field_type, text);
			if (!real_type) {
				parser_error(state, "ERROR: Union field type should not be NULL!\n");
				node_malformed_error(state, child, text, "union field");
				return -1;
			}
			const char *real_identifier = ts_node_sub_string(field_declarator, text);
			if (!real_identifier) {
				parser_error(state, "ERROR: Union declarator should not be NULL!\n");
				node_malformed_error(state, child, text, "union field");
				return -1;
			}
			parser_debug(state, "field type: %s field_declarator: %s\n", real_type, real_identifier);
			ParserTypePair *membtpair = NULL;
			// At first, we parse the type field
			if (parse_type_node_single(state, field_type, text, &membtpair, is_const)) {
				parser_error(state, "ERROR: parsing union member type\n");
				node_malformed_error(state, child, text, "union field");
				return -1;
			}
			// Then we augment resulting type field with the data from parsed declarator
			char *membname = NULL;
			if (parse_type_declarator_node(state, field_declarator, text, &membtpair, &membname)) {
				parser_error(state, "ERROR: parsing union member declarator\n");
				node_malformed_error(state, child, text, "union field");
				return -1;
			}
			// Add a union member
			RzVector *members = &union_pair->btype->union_data.members;
			RzTypeUnionMember memb = {
				.name = membname,
				.type = membtpair->type,
				.offset = 0, // Always 0 for unions
				.size = 0, // FIXME
			};
			void *element = rz_vector_push(members, &memb); // returns null if no space available
			if (!element) {
				parser_error(state, "Error appending union member to the base type\n");
				return -1;
			}
		}
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
	return 0;
}

// Parsing enum definitions - concrete and abstract ones
int parse_enum_node(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair, bool is_const) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	rz_return_val_if_fail(ts_node_is_named(node), -1);

	parser_debug(state, "parse_enum_node()\n");

	int enum_node_child_count = ts_node_named_child_count(node);
	if (enum_node_child_count < 1 || enum_node_child_count > 2) {
		node_malformed_error(state, node, text, "enum");
		return -1;
	}
	// Name is optional, in abstract definitions or as the member of nested types
	const char *name = NULL;
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
			parser_error(state, "Cannot find \"%s\" enum in the context\n", name);
			// We still could create the "forward looking enum declaration"
			// The parser then can augment the definition
			if (!(*tpair = c_parser_new_enum_forward_definition(state, name))) {
				parser_error(state, "Cannot create \"%s\" forward enum definition in the context\n", name);
				return -1;
			}
			return 0;
		} else {
			return 0;
		}
	}

	parser_debug(state, "enum name: %s\n", name);

	int body_child_count = ts_node_named_child_count(enum_body);
	// Now we form both RzType and RzBaseType to store in the Types database
	ParserTypePair *enum_pair = c_parser_new_enum_type(state, name, body_child_count);
	if (!enum_pair) {
		parser_error(state, "Error forming RzType and RzBaseType pair out of enum\n");
		return -1;
	}
	// Then we process all enumeration cases and add one by one
	int i;
	for (i = 0; i < body_child_count; i++) {
		parser_debug(state, "enum: processing %d field...\n", i);
		TSNode child = ts_node_named_child(enum_body, i);
		const char *node_type = ts_node_type(child);
		// Every field should have (field_declaration) AST clause
		if (strcmp(node_type, "enumerator")) {
			parser_error(state, "ERROR: Enum member AST should contain (enumerator) node!\n");
			node_malformed_error(state, child, text, "enum field");
			return -1;
		}
		// Every member node should have at least 1 child!
		int member_child_count = ts_node_named_child_count(child);
		if (member_child_count < 1 || member_child_count > 2) {
			parser_error(state, "ERROR: enum member AST cannot contain less than 1 or more than 2 items");
			node_malformed_error(state, child, text, "enum field");
			return -1;
		}
		// Every member can be:
		// - empty
		// - atomic: "1"
		// - expression: "1 << 2"
		if (state->verbose) {
			const char *membertext = ts_node_sub_string(child, text);
			char *nodeast = ts_node_string(child);
			if (membertext && nodeast) {
				parser_debug(state, "member text: %s\n", membertext);
				parser_debug(state, "member ast: %s\n", nodeast);
			}
			free(nodeast);
		}
		if (member_child_count == 1) {
			// It's an empty field, like just "A,"
			TSNode member_identifier = ts_node_child_by_field_name(child, "name", 4);
			if (ts_node_is_null(member_identifier)) {
				parser_error(state, "ERROR: Enum case identifier should not be NULL!\n");
				node_malformed_error(state, child, text, "enum case");
				return -1;
			}
			const char *real_identifier = ts_node_sub_string(member_identifier, text);
			parser_debug(state, "enum member: %s\n", real_identifier);
		} else {
			// It's a proper field, like "A = 1,"
			TSNode member_identifier = ts_node_child_by_field_name(child, "name", 4);
			TSNode member_value = ts_node_child_by_field_name(child, "value", 5);
			if (ts_node_is_null(member_identifier) || ts_node_is_null(member_value)) {
				parser_error(state, "ERROR: Enum case identifier and value should not be NULL!\n");
				node_malformed_error(state, child, text, "enum case");
				return -1;
			}
			const char *real_identifier = ts_node_sub_string(member_identifier, text);
			const char *real_value = ts_node_sub_string(member_value, text);
			// FIXME: Use RzNum to calculate complex expressions
			parser_debug(state, "enum member: %s value: %s\n", real_identifier, real_value);
			// Add an enum case
			RzVector *cases = &enum_pair->btype->enum_data.cases;
			RzTypeEnumCase cas = {
				.name = strdup(real_identifier),
				.val = rz_num_get(NULL, real_value)
			};
			void *element = rz_vector_push(cases, &cas); // returns null if no space available
			if (!element) {
				parser_error(state, "Error appending enum case to the base type\n");
				return -1;
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
	return 0;
}

// Parsing typedefs - these are ALWAYS concrete due to the syntax specifics
int parse_typedef_node(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair, bool is_const) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	rz_return_val_if_fail(ts_node_is_named(node), -1);

	parser_debug(state, "parse_typedef_node()\n");

	int typedef_node_child_count = ts_node_named_child_count(node);
	if (typedef_node_child_count != 2) {
		node_malformed_error(state, node, text, "typedef");
		return -1;
	}

	TSNode typedef_type = ts_node_child_by_field_name(node, "type", 4);
	TSNode typedef_declarator = ts_node_child_by_field_name(node, "declarator", 10);
	if (ts_node_is_null(typedef_type) || ts_node_is_null(typedef_declarator)) {
		parser_error(state, "ERROR: Typedef type and declarator nodes should not be NULL!\n");
		node_malformed_error(state, node, text, "typedef");
		return -1;
	}
	// Every typedef type can be:
	// - atomic: "int", "uint64_t", etc
	// - some type name - any identificator
	// - complex type like struct, union, or enum
	if (state->verbose) {
		const char *typetext = ts_node_sub_string(typedef_type, text);
		char *nodeast = ts_node_string(typedef_type);
		if (typetext && nodeast) {
			parser_debug(state, "type text: %s\n", typetext);
			parser_debug(state, "type ast: %s\n", nodeast);
		}
		free(nodeast);
	}
	ParserTypePair *type_pair = NULL;
	if (parse_type_node_single(state, typedef_type, text, &type_pair, is_const)) {
		parser_error(state, "ERROR: parsing typedef type identifier\n");
		node_malformed_error(state, typedef_type, text, "typedef type");
		return -1;
	}
	// Then we augment resulting type field with the data from parsed declarator
	char *typedef_name = NULL;
	if (parse_type_declarator_node(state, typedef_declarator, text, &type_pair, &typedef_name)) {
		parser_error(state, "ERROR: parsing typedef declarator\n");
		node_malformed_error(state, typedef_declarator, text, "typedef declarator");
		return -1;
	}

	// Now we form both RzType and RzBaseType to store in the Types database
	char *base_type_name = type_pair->btype->name;
	parser_debug(state, "typedef \"%s\" -> \"%s\"\n", typedef_name, base_type_name);
	ParserTypePair *typedef_pair = c_parser_new_typedef(state, typedef_name, base_type_name);
	if (!typedef_pair) {
		parser_error(state, "Error forming RzType and RzBaseType pair out of typedef\n");
		return -1;
	}
	// If parsing successfull completed - we store the state
	if (typedef_pair) {
		typedef_pair->btype->type = type_pair->type;
		parser_debug(state, "storing typedef \"%s\" -> \"%s\"\n", typedef_name, base_type_name);
		c_parser_base_type_store(state, typedef_name, typedef_pair);
	}

	*tpair = typedef_pair;
	return 0;
}

// Parses the node that represents just one type
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
		result = parse_typedef_node(state, node, text, tpair, is_const);
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
		if (strcmp(node_type, "parameter_declaration")) {
			parser_error(state, "ERROR: Parameter field AST should contain (parameter_declaration) node!\n");
			node_malformed_error(state, child, text, "parameter_declaration");
			return -1;
		}
		char *identifier = NULL;
		// Create new TypePair here
		ParserTypePair *argtpair = NULL;
		if (parse_parameter_declaration_node(state, child, text, &argtpair, &identifier)) {
			parser_error(state, "ERROR: Parsing parameter declarator!\n");
			return -1;
		}
		if (!argtpair || !argtpair->type) {
			return -1;
		}
		// Store the parameters if available
		// If the name is not available just name it as "argN" where N is argument index
		if (!identifier) {
			identifier = rz_str_newf("arg%d", i);
		}
		parser_debug(state, "Adding \"%s\" parameter\n", identifier);
		if (!c_parser_new_callable_argument(state, (*tpair)->type->callable, identifier, argtpair->type)) {
			parser_error(state, "ERROR: Cannot add the parameter to the function!\n");
			return -1;
		}
	}
	return 0;
}

// Parses abstract declarator node - i.e. the type without the identifier
int parse_type_abstract_declarator_node(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	rz_return_val_if_fail(ts_node_is_named(node), -1);

	parser_debug(state, "parse_type_abstract_descriptor_single()\n");

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
			const char *qualifier = ts_node_sub_string(first_leaf, text);
			parser_debug(state, "has qualifier %s\n", qualifier);
			if (!strcmp(qualifier, "const")) {
				is_const = true;
			}
			has_qualifiers = true;
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
				return -1;
			}
			if (!ts_node_is_null(pointer_declarator)) {
				const char *declarator_type = ts_node_type(pointer_declarator);
				if (!declarator_type) {
					node_malformed_error(state, pointer_declarator, text, "pointer declarator");
					free(type);
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
			const char *real_array_size = ts_node_sub_string(array_size, text);
			if (!real_array_size) {
				node_malformed_error(state, array_size, text, "abstract array size");
				return -1;
			}
			int array_sz = rz_num_get(NULL, real_array_size);
			type->array.count = array_sz;
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
			const char *qualifier = ts_node_sub_string(first_leaf, text);
			parser_debug(state, "has qualifier %s\n", qualifier);
			if (!strcmp(qualifier, "const")) {
				is_const = true;
			}
		}
	}

	const char *node_type = ts_node_type(node);
	int result = -1;

	if (is_identifier(node_type)) {
		// Identifier, usually the last leaf of the AST tree
		const char *real_ident = ts_node_sub_string(node, text);
		parser_debug(state, "identifier: %s\n", real_ident);
		*identifier = strdup(real_ident);
		result = 0;
	} else if (!strcmp(node_type, "pointer_declarator")) {
		const char *real_ident = ts_node_sub_string(node, text);
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
			return -1;
		}
		const char *declarator_type = ts_node_type(pointer_declarator);
		if (!declarator_type) {
			node_malformed_error(state, pointer_declarator, text, "pointer declarator");
			return -1;
		}

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

		if (is_declarator(declarator_type) || is_identifier(declarator_type)) {
			result = parse_type_declarator_node(state, pointer_declarator, text, tpair, identifier);
		} else {
			result = 0;
		}
	} else if (!strcmp(node_type, "array_declarator")) {
		const char *real_ident = ts_node_sub_string(node, text);
		parser_debug(state, "array declarator: %s\n", real_ident);

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
			const char *real_array_size = ts_node_sub_string(array_size, text);
			if (!real_array_size) {
				node_malformed_error(state, array_size, text, "array size");
				return -1;
			}
			int array_sz = rz_num_get(NULL, real_array_size);
			type->array.count = array_sz;
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
		const char *real_ident = ts_node_sub_string(node, text);
		parser_debug(state, "function declarator: %s\n", real_ident);
		// It can only contain two nodes:
		// - declarator
		// - parameter_list
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
			// Or the pointer_declarator instead
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
		RzType *parent_type = (*tpair)->type;
		(*tpair)->type = c_parser_new_callable(state, *identifier);
		if (!(*tpair)->type) {
			parser_error(state, "ERROR: creating new callable type: \"%s\"\n", *identifier);
			return -1;
		}
		result = parse_parameter_list(state, parameter_list, text, tpair);
		if (result) {
			parser_error(state, "ERROR: parsing parameters for callable type: \"%s\"\n", *identifier);
			return -1;
		}
		// The previously fetched type in this case is the callable return type
		(*tpair)->type->callable->ret = parent_type;
		if (!c_parser_callable_type_store(state, *identifier, (*tpair)->type)) {
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
		const char *qualifier = ts_node_sub_string(first_leaf, text);
		parser_debug(state, "has qualifier \"%s\"\n", qualifier);
		if (!strcmp(qualifier, "const")) {
			parser_debug(state, "set const\n");
			is_const = true;
		}
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
		const char *qualifier = ts_node_sub_string(first_leaf, text);
		parser_debug(state, "has qualifier \"%s\"\n", qualifier);
		if (!strcmp(qualifier, "const")) {
			parser_debug(state, "set const\n");
			is_const = true;
		}
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
		result = parse_typedef_node(state, node, text, &tpair, false);
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
	// In case of anonymous type we could use identifier as a name for this type?
	return result;
}
