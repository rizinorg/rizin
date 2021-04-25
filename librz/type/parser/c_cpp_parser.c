// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_types.h>
#include <rz_list.h>
#include <rz_util/rz_file.h>
#include <rz_type.h>
#include <tree_sitter/api.h>

#include <types_parser.h>

// Declare the `tree_sitter_c` function, which is
// implemented by the `tree-sitter-c` library.
TSLanguage *tree_sitter_c();

// Declare the `tree_sitter_cpp` function, which is
// implemented by the `tree-sitter-cpp` library.
//TSLanguage *tree_sitter_cpp();

CParserState *c_parser_state_new(HtPP *ht) {
	CParserState *state = RZ_NEW0(CParserState);
	if (!ht) {
		state->types = ht_pp_new0();
	} else {
		state->types = ht;
	}
	state->errors = rz_strbuf_new("");
	state->warnings = rz_strbuf_new("");
	state->debug = rz_strbuf_new("");
	return state;
}

void c_parser_state_free(CParserState *state) {
	ht_pp_free(state->types);
	rz_strbuf_free(state->debug);
	rz_strbuf_free(state->warnings);
	rz_strbuf_free(state->errors);
	free(state);
	return;
}

void c_parser_state_free_keep_ht(CParserState *state) {
	free(state);
	return;
}

RZ_API int rz_type_parse_c_file(RzTypeDB *typedb, const char *path, const char *dir, char **error_msg) {
	size_t read_bytes = 0;
	const char *source_code = rz_file_slurp(path, &read_bytes);
	if (!source_code || !read_bytes) {
		return -1;
	}
	ut64 file_size = rz_file_size(path);
	printf("File size is %" PFMT64d " bytes, read %zu bytes\n", file_size, read_bytes);
	return rz_type_parse_c_string(typedb, source_code, NULL);
}

RZ_API int rz_type_parse_c_string(RzTypeDB *typedb, const char *code, char **error_msg) {
	bool verbose = true;
	// Create a parser.
	TSParser *parser = ts_parser_new();
	// Set the parser's language (C in this case)
	ts_parser_set_language(parser, tree_sitter_c());

	TSTree *tree = ts_parser_parse_string(parser, NULL, code, strlen(code));

	// Create new C parser state
	CParserState *state = c_parser_state_new(typedb->types);
	if (!state) {
		eprintf("CParserState initialization error!\n");
		ts_tree_delete(tree);
		return -1;
	}
	state->verbose = verbose;

	// Get the root node of the syntax tree.
	TSNode root_node = ts_tree_root_node(tree);
	int root_node_child_count = ts_node_named_child_count(root_node);
	if (!root_node_child_count) {
		parser_warning(state, "Root node is empty!\n");
		ts_tree_delete(tree);
		ts_parser_delete(parser);
		return 0;
	}

	// Some debugging
	if (verbose) {
		parser_debug(state, "root_node (%d children): %s\n", root_node_child_count, ts_node_type(root_node));
		// Print the syntax tree as an S-expression.
		char *string = ts_node_string(root_node);
		parser_debug(state, "Syntax tree: %s\n", string);
		free(string);
	}

	// At first step we should handle defines
	// #define
	// #if / #ifdef
	// #else
	// #endif
	// After that, we should process include files and #error/#warning/#pragma
	// Temporarily we could just run preprocessing step using tccpp code
	//
	// And only after that - run the normal C/C++ syntax parsing

	// Filter types function prototypes and start parsing
	int i = 0, result = 0;
	for (i = 0; i < root_node_child_count; i++) {
		parser_debug(state, "Processing %d child...\n", i);
		TSNode child = ts_node_named_child(root_node, i);
		result += filter_type_nodes(state, child, code);
	}

	// If there were errors during the parser then the result is different from 0
	if (result) {
		const char *error_msgs = rz_strbuf_drain_nofree(state->errors);
		eprintf("Errors:\n");
		eprintf(error_msgs);
		const char *warning_msgs = rz_strbuf_drain_nofree(state->warnings);
		eprintf("Warnings:\n");
		eprintf(warning_msgs);
		*error_msg = strdup(error_msgs);
	}
	if (verbose) {
		const char *debug_msgs = rz_strbuf_drain_nofree(state->debug);
		eprintf(debug_msgs);
	}

	// After everything parsed, we should preserve the base type database
	c_parser_state_free_keep_ht(state);
	ts_tree_delete(tree);
	ts_parser_delete(parser);
	return result;
}

RZ_API void rz_type_parse_c_reset(RzTypeDB *typedb) {
	/* nothing */
}
