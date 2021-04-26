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

void node_malformed_error(CParserState *state, TSNode node, const char *nodetype) {
	rz_return_if_fail(nodetype && !ts_node_is_null(node));
	char *string = ts_node_string(node);
	rz_strbuf_appendf(state->errors, "Wrongly formed %s:\n%s\n", nodetype, string);
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

// Identifiers can be simple or arrays or pointers or both

int parse_identifier_node(CParserState *state, TSNode identnode, const char *text, RzType **type) {
	rz_return_val_if_fail(state && text && type, -1);
	rz_return_val_if_fail(!ts_node_is_null(identnode), -1);
	rz_return_val_if_fail(ts_node_is_named(identnode), -1);
	int ident_node_child_count = ts_node_named_child_count(identnode);
	if (ident_node_child_count > 2) {
		node_malformed_error(state, identnode, "identifier");
		return -1;
	}
	const char *ident_type = ts_node_type(identnode);
	parser_debug(state, "ident type: %s\n", ident_type);
	RzType *newtype = RZ_NEW0(RzType);
	if (ident_node_child_count == 0) {
		// Simple identifier
		const char *real_ident = ts_node_sub_string(identnode, text);
		parser_debug(state, "simple identifier: %s\n", real_ident);
		newtype->kind = RZ_TYPE_KIND_IDENTIFIER;
		newtype->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
		newtype->identifier.name = strdup(real_ident);
		newtype->identifier.is_const = false; // FIXME: Add const identifier parsing
	} else {
		TSNode ident_type1 = ts_node_named_child(identnode, 0);
		const char *ident_subtype = ts_node_type(ident_type1);
		parser_debug(state, "ident subtype: %s\n", ident_subtype);
		// Check if it's a pointer
		// e.g. "float *b;"
		if (!strcmp(ident_type, "pointer_declarator")) {
			// Pointer node could ALSO contain array node inside
			// e.g. "char *arr[20];"
			if (!strcmp(ident_subtype, "array_declarator")) {
				int ident_node_child_count = ts_node_named_child_count(ident_type1);
				if (ident_node_child_count != 2) {
					node_malformed_error(state, ident_type1, "identifier");
					return -1;
				}
				TSNode array_ident = ts_node_named_child(ident_type1, 0);
				TSNode array_size = ts_node_named_child(ident_type1, 1);
				if (ts_node_is_null(array_ident) || ts_node_is_null(array_size)) {
					node_malformed_error(state, identnode, "ptr array identifier");
					return -1;
				}
				const char *real_array_ident = ts_node_sub_string(array_ident, text);
				const char *real_array_size = ts_node_sub_string(array_size, text);
				if (!real_array_ident || !real_array_size) {
					node_malformed_error(state, identnode, "ptr array identifier");
					return -1;
				}
				int array_sz = atoi(real_array_size);
				parser_debug(state, "array of pointers to %s size %d\n", real_array_ident, array_sz);
				newtype->kind = RZ_TYPE_KIND_ARRAY;
				newtype->array.count = array_sz;
				RzType *subtype = RZ_NEW0(RzType);
				if (!subtype) {
					return -1;
				}
				subtype->kind = RZ_TYPE_KIND_POINTER;
				subtype->pointer.is_const = false; // FIXME: Add const pointer parsing
				RzType *subsubtype = RZ_NEW0(RzType);
				if (!subsubtype) {
					return -1;
				}
				subsubtype->kind = RZ_TYPE_KIND_IDENTIFIER;
				subsubtype->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
				subsubtype->identifier.name = strdup(real_array_ident);
				subsubtype->identifier.is_const = false; // FIXME: Add const identifier parsing
				subtype->pointer.type = subsubtype;
				newtype->array.type = subtype;
			} else if (!strcmp(ident_subtype, "field_identifier")) {
				const char *ptr_ident = ts_node_sub_string(ident_type1, text);
				parser_debug(state, "simple pointer to %s\n", ptr_ident);
				newtype->kind = RZ_TYPE_KIND_POINTER;
				newtype->pointer.is_const = false; // FIXME: Add const pointer parsing
				RzType *subtype = RZ_NEW0(RzType);
				if (!subtype) {
					return -1;
				}
				subtype->kind = RZ_TYPE_KIND_IDENTIFIER;
				subtype->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
				subtype->identifier.name = strdup(ptr_ident);
				subtype->identifier.is_const = false; // FIXME: Add const identifier parsing
				newtype->pointer.type = subtype;
			} else {
				node_malformed_error(state, identnode, "identifier");
				return -1;
			}
			// Or an array
			// e.g. "int a[10];"
		} else if (!strcmp(ident_type, "array_declarator")) {
			int array_node_child_count = ts_node_named_child_count(identnode);
			if (array_node_child_count != 2) {
				node_malformed_error(state, identnode, "array identifier");
				return -1;
			}
			TSNode array_ident = ts_node_named_child(identnode, 0);
			TSNode array_size = ts_node_named_child(identnode, 1);
			if (ts_node_is_null(array_ident) || ts_node_is_null(array_size)) {
				node_malformed_error(state, identnode, "array identifier");
				return -1;
			}
			const char *real_array_ident = ts_node_sub_string(array_ident, text);
			const char *real_array_size = ts_node_sub_string(array_size, text);
			if (!real_array_ident || !real_array_size) {
				node_malformed_error(state, identnode, "array identifier");
				return -1;
			}
			int array_sz = atoi(real_array_size);
			parser_debug(state, "simple array of %s size %d\n", real_array_ident, array_sz);
			newtype->kind = RZ_TYPE_KIND_ARRAY;
			newtype->array.count = array_sz;
			RzType *subtype = RZ_NEW0(RzType);
			if (!subtype) {
				return -1;
			}
			subtype->kind = RZ_TYPE_KIND_IDENTIFIER;
			subtype->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
			subtype->identifier.name = strdup(real_array_ident);
			subtype->identifier.is_const = false; // FIXME: Add const identifier parsing
			newtype->array.type = subtype;
		}
	}
	*type = newtype;
	return 0;
}

// Types can be
// - struct (struct_specifier)
// - union (union_specifier)
// - enum (enum_specifier) (usually prepended by declaration)
// - typedef (type_definition)
// - atomic type

int parse_struct_node(CParserState *state, TSNode structnode, const char *text, ParserTypePair **tpair) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(structnode), -1);
	rz_return_val_if_fail(ts_node_is_named(structnode), -1);
	int struct_node_child_count = ts_node_named_child_count(structnode);
	if (struct_node_child_count < 1 || struct_node_child_count > 2) {
		node_malformed_error(state, structnode, "struct");
		return -1;
	}
	if (struct_node_child_count < 2) {
		// Anonymous or forward declaration struct
		TSNode child = ts_node_child(structnode, 1);
		if (!ts_node_is_null(child) && ts_node_is_named(child)) {
			const char *node_type = ts_node_type(child);
			if (!node_type) {
				node_malformed_error(state, structnode, "struct");
				return -1;
			}
			// "struct bla;"
			if (!strcmp(node_type, "type_identifier")) {
				// We really skip such declarations since they don't
				// make sense for our goal
				// Anonymous struct, "struct { int a; int b; };"
			} else if (!strcmp(node_type, "field_declaration_list")) {
				// FIXME: Support anonymous structures
				parser_error(state, "Anonymous structs aren't supported yet!\n");
				return -1;
			} else {
				node_malformed_error(state, structnode, "struct");
				return -1;
			}
		} else {
			node_malformed_error(state, structnode, "struct");
			return -1;
		}
	}
	TSNode struct_name = ts_node_named_child(structnode, 0);
	TSNode struct_body = ts_node_named_child(structnode, 1);
	int body_child_count = ts_node_named_child_count(struct_body);
	const char *realname = ts_node_sub_string(struct_name, text);
	if (!realname || !body_child_count) {
		parser_error(state, "ERROR: Struct name should not be NULL!\n");
		node_malformed_error(state, structnode, "struct");
		return -1;
	}
	parser_debug(state, "struct name: %s\n", realname);
	// Now we form both RzType and RzBaseType to store in the Types database
	ParserTypePair *struct_pair = c_parser_new_structure(state, realname, body_child_count);
	if (!struct_pair) {
		parser_error(state, "Error forming RzType and RzBaseType pair out of enum\n");
		return -1;
	}
	int i;
	for (i = 0; i < body_child_count; i++) {
		parser_debug(state, "struct: processing %d field...\n", i);
		TSNode child = ts_node_named_child(struct_body, i);
		const char *node_type = ts_node_type(child);
		// Every field should have (field_declaration) AST clause
		if (strcmp(node_type, "field_declaration")) {
			parser_error(state, "ERROR: Struct field AST should contain (field_declaration) node!\n");
			node_malformed_error(state, child, "struct field");
			return -1;
		}
		// Every field node should have at least 2 children!
		int field_child_count = ts_node_named_child_count(child);
		if (field_child_count < 2 || field_child_count > 3) {
			parser_error(state, "ERROR: Struct field AST cannot contain less than 2 or more than 3 items");
			node_malformed_error(state, child, "struct field");
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
		// Thus it has exactly 3 children
		if (field_child_count == 3) {
			TSNode field_type = ts_node_named_child(child, 0);
			TSNode field_identifier = ts_node_named_child(child, 1);
			TSNode field_bitfield = ts_node_named_child(child, 2);
			if (ts_node_is_null(field_type) || ts_node_is_null(field_identifier) || ts_node_is_null(field_bitfield)) {
				parser_error(state, "ERROR: Struct bitfield type should not be NULL!\n");
				node_malformed_error(state, child, "struct field");
				return -1;
			}
			// As per C standard bitfields are defined only for atomic types, particularly "int"
			if (strcmp(ts_node_type(field_type), "primitive_type")) {
				parser_error(state, "ERROR: Struct bitfield cannot contain non-primitive bitfield!\n");
				node_malformed_error(state, child, "struct field");
				return -1;
			}
			const char *real_type = ts_node_sub_string(field_type, text);
			if (!real_type) {
				parser_error(state, "ERROR: Struct bitfield type should not be NULL!\n");
				node_malformed_error(state, child, "struct field");
				return -1;
			}
			const char *real_identifier = ts_node_sub_string(field_identifier, text);
			if (!real_identifier) {
				parser_error(state, "ERROR: Struct bitfield identifier should not be NULL!\n");
				node_malformed_error(state, child, "struct field");
				return -1;
			}
			if (ts_node_named_child_count(field_bitfield) != 1) {
				node_malformed_error(state, child, "struct field");
				return -1;
			}
			TSNode field_bits = ts_node_named_child(field_bitfield, 0);
			if (ts_node_is_null(field_bits)) {
				parser_error(state, "ERROR: Struct bitfield bits AST node should not be NULL!\n");
				node_malformed_error(state, child, "struct field");
				return -1;
			}
			const char *bits_str = ts_node_sub_string(field_bits, text);
			int bits = atoi(bits_str);
			parser_debug(state, "field type: %s field_identifier: %s bits: %d\n", real_type, real_identifier, bits);
			// TODO: Support bitfields
		} else {
			parser_debug(state, "field children: %d\n", field_child_count);
			TSNode field_type = ts_node_named_child(child, 0);
			TSNode field_identifier = ts_node_named_child(child, 1);
			if (ts_node_is_null(field_type) || ts_node_is_null(field_identifier)) {
				parser_error(state, "ERROR: Struct field type and identifier should not be NULL!\n");
				node_malformed_error(state, child, "struct field");
				return -1;
			}
			if (!strcmp(ts_node_type(field_type), "primitive_type")) {
				// 2nd case, atomic field
				// AST looks like
				// type: (primitive_type) declarator: (field_identifier)
				const char *real_type = ts_node_sub_string(field_type, text);
				if (!real_type) {
					parser_error(state, "ERROR: Struct field type should not be NULL!\n");
					node_malformed_error(state, child, "struct field");
					return -1;
				}
				const char *real_identifier = ts_node_sub_string(field_identifier, text);
				if (!real_identifier) {
					parser_error(state, "ERROR: Struct bitfield identifier should not be NULL!\n");
					node_malformed_error(state, child, "struct field");
					return -1;
				}
				parser_debug(state, "field type: %s field_identifier: %s\n", real_type, real_identifier);
				RzType *membtype = NULL;
				if (parse_identifier_node(state, field_identifier, text, &membtype)) {
					parser_error(state, "ERROR: parsing struct member identifier\n");
					node_malformed_error(state, child, "struct field");
					return -1;
				}
				// Add a struct member
				RzVector *members = &struct_pair->btype->struct_data.members;
				RzTypeStructMember memb = {
					.name = strdup(real_identifier),
					.type = membtype,
					.offset = 0, // FIXME
					.size = 0, // FIXME
				};
				void *element = rz_vector_push(members, &memb); // returns null if no space available
				if (!element) {
					parser_error(state, "Error appending struct member to the base type\n");
					return -1;
				}
			} else {
				// 3rd case, complex type
				// AST looks like
				// type: (struct_specifier ...) declarator: (field_identifier)
				// TODO: Go recursively
			}
		}
	}
	*tpair = struct_pair;
	return 0;
}

// Union is almost exact copy of struct but size computation is different
int parse_union_node(CParserState *state, TSNode unionnode, const char *text, ParserTypePair **tpair) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(unionnode), -1);
	rz_return_val_if_fail(ts_node_is_named(unionnode), -1);
	int union_node_child_count = ts_node_named_child_count(unionnode);
	if (union_node_child_count < 1 || union_node_child_count > 2) {
		node_malformed_error(state, unionnode, "union");
		return -1;
	}
	if (union_node_child_count < 2) {
		// Anonymous or forward declaration union
		TSNode child = ts_node_child(unionnode, 1);
		if (!ts_node_is_null(child) && ts_node_is_named(child)) {
			const char *node_type = ts_node_type(child);
			if (!node_type) {
				node_malformed_error(state, unionnode, "union");
				return -1;
			}
			// "union bla;"
			if (!strcmp(node_type, "type_identifier")) {
				// We really skip such declarations since they don't
				// make sense for our goal
				// Anonymous union, "union { int a; float b; };"
			} else if (!strcmp(node_type, "field_declaration_list")) {
				// FIXME: Support anonymous unions
				parser_error(state, "Anonymous unions aren't supported yet!\n");
				return -1;
			} else {
				node_malformed_error(state, unionnode, "union");
				return -1;
			}
		} else {
			node_malformed_error(state, unionnode, "union");
			return -1;
		}
	}
	TSNode union_name = ts_node_named_child(unionnode, 0);
	TSNode union_body = ts_node_named_child(unionnode, 1);
	int body_child_count = ts_node_named_child_count(union_body);
	const char *realname = ts_node_sub_string(union_name, text);
	if (!realname || !body_child_count) {
		parser_error(state, "ERROR: union name should not be NULL!\n");
		node_malformed_error(state, unionnode, "union");
		return -1;
	}
	parser_debug(state, "union name: %s\n", realname);
	// Now we form both RzType and RzBaseType to store in the Types database
	ParserTypePair *union_pair = c_parser_new_union(state, realname, body_child_count);
	if (!union_pair) {
		parser_error(state, "Error forming RzType and RzBaseType pair out of union\n");
		return -1;
	}
	int i;
	for (i = 0; i < body_child_count; i++) {
		parser_debug(state, "union: processing %d field...\n", i);
		TSNode child = ts_node_named_child(union_body, i);
		const char *node_type = ts_node_type(child);
		// Every field should have (field_declaration) AST clause
		if (strcmp(node_type, "field_declaration")) {
			parser_error(state, "ERROR: union field AST should contain (field_declaration) node!\n");
			node_malformed_error(state, child, "union field");
			return -1;
		}
		// Every field node should have at least 2 children!
		int field_child_count = ts_node_named_child_count(child);
		if (field_child_count < 2 || field_child_count > 3) {
			parser_error(state, "ERROR: union field AST cannot contain less than 2 or more than 3 items");
			node_malformed_error(state, child, "union field");
			return -1;
		}
		// Every field can be:
		// - atomic: "int a;" or "char b[20]"
		// - bitfield: int a:7;"
		// - nested: "union { ... } a;" or "union { ... } a;"
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
		// Thus it has exactly 3 children
		if (field_child_count == 3) {
			// Note, this case is very tricky to compute allocation in memory
			// and very rare in practice
			TSNode field_type = ts_node_named_child(child, 0);
			TSNode field_identifier = ts_node_named_child(child, 1);
			TSNode field_bitfield = ts_node_named_child(child, 2);
			if (ts_node_is_null(field_type) || ts_node_is_null(field_identifier) || ts_node_is_null(field_bitfield)) {
				parser_error(state, "ERROR: union bitfield type should not be NULL!\n");
				node_malformed_error(state, child, "union field");
				return -1;
			}
			// As per C standard bitfields are defined only for atomic types, particularly "int"
			if (strcmp(ts_node_type(field_type), "primitive_type")) {
				parser_error(state, "ERROR: union bitfield cannot contain non-primitive bitfield!\n");
				node_malformed_error(state, child, "union field");
				return -1;
			}
			const char *real_type = ts_node_sub_string(field_type, text);
			if (!real_type) {
				parser_error(state, "ERROR: union bitfield type should not be NULL!\n");
				node_malformed_error(state, child, "union field");
				return -1;
			}
			const char *real_identifier = ts_node_sub_string(field_identifier, text);
			if (!real_identifier) {
				parser_error(state, "ERROR: union bitfield identifier should not be NULL!\n");
				node_malformed_error(state, child, "union field");
				return -1;
			}
			if (ts_node_named_child_count(field_bitfield) != 1) {
				node_malformed_error(state, child, "union field");
				return -1;
			}
			TSNode field_bits = ts_node_named_child(field_bitfield, 0);
			if (ts_node_is_null(field_bits)) {
				parser_error(state, "ERROR: union bitfield bits AST node should not be NULL!\n");
				node_malformed_error(state, child, "union field");
				return -1;
			}
			const char *bits_str = ts_node_sub_string(field_bits, text);
			int bits = atoi(bits_str);
			parser_debug(state, "field type: %s field_identifier: %s bits: %d\n", real_type, real_identifier, bits);
		} else {
			parser_debug(state, "field children: %d\n", field_child_count);
			TSNode field_type = ts_node_named_child(child, 0);
			TSNode field_identifier = ts_node_named_child(child, 1);
			if (ts_node_is_null(field_type) || ts_node_is_null(field_identifier)) {
				parser_error(state, "ERROR: union field type and identifier should not be NULL!\n");
				node_malformed_error(state, child, "union field");
				return -1;
			}
			if (!strcmp(ts_node_type(field_type), "primitive_type")) {
				// 2nd case, atomic field
				// AST looks like
				// type: (primitive_type) declarator: (field_identifier)
				const char *real_type = ts_node_sub_string(field_type, text);
				if (!real_type) {
					parser_error(state, "ERROR: union field type should not be NULL!\n");
					node_malformed_error(state, child, "union field");
					return -1;
				}
				const char *real_identifier = ts_node_sub_string(field_identifier, text);
				if (!real_identifier) {
					parser_error(state, "ERROR: union bitfield identifier should not be NULL!\n");
					node_malformed_error(state, child, "union field");
					return -1;
				}
				parser_debug(state, "field type: %s field_identifier: %s\n", real_type, real_identifier);
				RzType *membtype = NULL;
				if (parse_identifier_node(state, field_identifier, text, &membtype)) {
					parser_error(state, "ERROR: parsing union member identifier\n");
					node_malformed_error(state, child, "union field");
					return -1;
				}
				// Add a union member
				RzVector *members = &union_pair->btype->union_data.members;
				RzTypeUnionMember memb = {
					.name = strdup(real_identifier),
					.type = membtype,
					.offset = 0, // Always 0 for unions
					.size = 0, // FIXME
				};
				void *element = rz_vector_push(members, &memb); // returns null if no space available
				if (!element) {
					parser_error(state, "Error appending union member to the base type\n");
					return -1;
				}
			} else {
				// 3rd case, complex type
				// AST looks like
				// type: (union_specifier ...) declarator: (field_identifier)
				// TODO: Go recursively
			}
		}
	}
	*tpair = union_pair;
	return 0;
}

// Parsing enum
int parse_enum_node(CParserState *state, TSNode enumnode, const char *text, ParserTypePair **tpair) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(enumnode), -1);
	rz_return_val_if_fail(ts_node_is_named(enumnode), -1);
	int enum_node_child_count = ts_node_named_child_count(enumnode);
	if (enum_node_child_count < 1 || enum_node_child_count > 2) {
		node_malformed_error(state, enumnode, "enum");
		return -1;
	}
	if (enum_node_child_count < 2) {
		// Anonymous or forward declaration enum
		TSNode child = ts_node_child(enumnode, 1);
		if (!ts_node_is_null(child) && ts_node_is_named(child)) {
			const char *node_type = ts_node_type(child);
			if (!node_type) {
				node_malformed_error(state, enumnode, "enum");
				return -1;
			}
			// "enum bla;"
			if (!strcmp(node_type, "type_identifier")) {
				// We really skip such declarations since they don't
				// make sense for our goal
				// Anonymous enum, "enum { A = 1, B = 2 };"
			} else if (!strcmp(node_type, "enumerator_list")) {
				// FIXME: Handle anonymous enums
				parser_error(state, "Anonymous enums aren't supported yet!\n");
				return -1;
			} else {
				node_malformed_error(state, enumnode, "enum");
				return -1;
			}
		} else {
			node_malformed_error(state, enumnode, "enum");
			return -1;
		}
	}
	TSNode enum_name = ts_node_named_child(enumnode, 0);
	TSNode enum_body = ts_node_named_child(enumnode, 1);
	if (ts_node_is_null(enum_name) || ts_node_is_null(enum_body)) {
		parser_error(state, "ERROR: Enum name and body nodes should not be NULL!\n");
		node_malformed_error(state, enumnode, "enum");
		return -1;
	}
	int body_child_count = ts_node_named_child_count(enum_body);
	const char *realname = ts_node_sub_string(enum_name, text);
	if (!realname || !body_child_count) {
		parser_error(state, "ERROR: Enum name should not be NULL!\n");
		node_malformed_error(state, enumnode, "enum");
		return -1;
	}
	parser_debug(state, "enum name: %s\n", realname);
	// Now we form both RzType and RzBaseType to store in the Types database
	ParserTypePair *enum_pair = c_parser_new_enum(state, realname, body_child_count);
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
			node_malformed_error(state, child, "enum field");
			return -1;
		}
		// Every member node should have at least 1 child!
		int member_child_count = ts_node_named_child_count(child);
		if (member_child_count < 1 || member_child_count > 2) {
			parser_error(state, "ERROR: enum member AST cannot contain less than 1 or more than 2 items");
			node_malformed_error(state, child, "enum field");
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
			TSNode member_identifier = ts_node_named_child(child, 0);
			if (ts_node_is_null(member_identifier)) {
				parser_error(state, "ERROR: Enum member identifier should not be NULL!\n");
				node_malformed_error(state, child, "struct field");
				return -1;
			}
			const char *real_identifier = ts_node_sub_string(member_identifier, text);
			parser_debug(state, "enum member: %s\n", real_identifier);
		} else {
			// It's a proper field, like "A = 1,"
			TSNode member_identifier = ts_node_named_child(child, 0);
			TSNode member_value = ts_node_named_child(child, 1);
			if (ts_node_is_null(member_identifier) || ts_node_is_null(member_value)) {
				parser_error(state, "ERROR: Enum member identifier and value should not be NULL!\n");
				node_malformed_error(state, child, "struct field");
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
				.val = strtol(real_value, NULL, 10)
			};
			void *element = rz_vector_push(cases, &cas); // returns null if no space available
			if (!element) {
				parser_error(state, "Error appending enum case to the base type\n");
				return -1;
			}
		}
	}
	*tpair = enum_pair;
	return 0;
}

// Parsing typedefs
int parse_typedef_node(CParserState *state, TSNode typedefnode, const char *text, ParserTypePair **tpair) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(typedefnode), -1);
	rz_return_val_if_fail(ts_node_is_named(typedefnode), -1);
	int typedef_node_child_count = ts_node_named_child_count(typedefnode);
	if (typedef_node_child_count != 2) {
		node_malformed_error(state, typedefnode, "typedef");
		return -1;
	}
	TSNode typedef_type = ts_node_named_child(typedefnode, 0);
	TSNode typedef_alias = ts_node_named_child(typedefnode, 1);
	if (ts_node_is_null(typedef_type) || ts_node_is_null(typedef_alias)) {
		parser_error(state, "ERROR: Typedef type and alias nodes should not be NULL!\n");
		node_malformed_error(state, typedefnode, "typedef");
		return -1;
	}
	const char *aliasname = ts_node_sub_string(typedef_alias, text);
	if (!aliasname) {
		parser_error(state, "ERROR: Typedef alias name should not be NULL!\n");
		node_malformed_error(state, typedefnode, "typedef");
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
	int type_child_count = ts_node_named_child_count(typedef_type);
	if (!type_child_count) {
		const char *node_type = ts_node_type(typedef_type);
		if (!strcmp(node_type, "primitive_type")) {
			const char *real_type = ts_node_sub_string(typedef_type, text);
			parser_debug(state, "typedef type: %s alias: %s\n", real_type, aliasname);
		} else if (!strcmp(node_type, "type_identifier")) {
			const char *real_type = ts_node_sub_string(typedef_type, text);
			parser_debug(state, "typedef type: %s alias: %s\n", real_type, aliasname);
		} else {
			parser_error(state, "ERROR: Typedef type AST should contain (primitive_type) or (identifier) node!\n");
			node_malformed_error(state, typedef_type, "typedef type");
			return -1;
		}
	} else {
		const char *real_type = ts_node_sub_string(typedef_type, text);
		parser_debug(state, "complex typedef type: %s alias: %s\n", real_type, aliasname);
	}
	// FIXME
	*tpair = NULL;
	return 0;
}

// Types can be
// - struct (struct_specifier)
// - union (union_specifier)
// - enum (enum_specifier) (usually prepended by declaration)
// - typedef (type_definition)
// - atomic type

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
		result = parse_struct_node(state, node, text, &tpair);
		if (result || !tpair) {
			return -1;
		}
		// Now we store the parsed type in the hashtable
		result = c_parser_store_type(state, tpair->btype->name, tpair);
	} else if (!strcmp(node_type, "union_specifier")) {
		result = parse_union_node(state, node, text, &tpair);
		if (result || !tpair) {
			return -1;
		}
		// Now we store the parsed type in the hashtable
		result = c_parser_store_type(state, tpair->btype->name, tpair);
	} else if (!strcmp(node_type, "enum_specifier")) {
		result = parse_enum_node(state, node, text, &tpair);
		if (result || !tpair) {
			return -1;
		}
		// Now we store the parsed type in the hashtable
		result = c_parser_store_type(state, tpair->btype->name, tpair);
	} else if (!strcmp(node_type, "type_definition")) {
		result = parse_typedef_node(state, node, text, &tpair);
		if (result || !tpair) {
			return -1;
		}
		// Now we store the parsed type in the hashtable
		result = c_parser_store_type(state, tpair->btype->name, tpair);
	}

	// Another case where there is a declaration clause
	// In this case we should drop the declaration itself
	// and parse only the corresponding type
	// In case of anonymous type we could use identifier as a name for this type?
	//
	return result;
}

int parse_type_node_single(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair) {
	rz_return_val_if_fail(state && text && tpair, -1);
	rz_return_val_if_fail(!ts_node_is_null(node), -1);
	// We skip simple nodes (e.g. conditions and braces)
	if (!ts_node_is_named(node)) {
		return 0;
	}
	const char *node_type = ts_node_type(node);
	int result = -1;
	if (!strcmp(node_type, "struct_specifier")) {
		result = parse_struct_node(state, node, text, tpair);
		if (result || !tpair) {
			return -1;
		}
	} else if (!strcmp(node_type, "union_specifier")) {
		result = parse_union_node(state, node, text, tpair);
		if (result || !tpair) {
			return -1;
		}
	} else if (!strcmp(node_type, "enum_specifier")) {
		result = parse_enum_node(state, node, text, tpair);
		if (result || !tpair) {
			return -1;
		}
	} else if (!strcmp(node_type, "type_definition")) {
		result = parse_typedef_node(state, node, text, tpair);
		if (result || !tpair) {
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
