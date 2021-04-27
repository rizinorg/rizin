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

CParserState *c_parser_state_new(HtPP *base_types, HtPP *callable_types) {
	CParserState *state = RZ_NEW0(CParserState);
	if (!base_types) {
		state->types = ht_pp_new0();
	} else {
		state->types = base_types;
	}
	if (!callable_types) {
		state->callables = ht_pp_new0();
	} else {
		state->callables = callable_types;
	}
	// Forward definitions require to have a special hashtable
	state->forward = ht_pp_new0();
	state->errors = rz_strbuf_new("");
	state->warnings = rz_strbuf_new("");
	state->debug = rz_strbuf_new("");
	return state;
}

void c_parser_state_free(CParserState *state) {
	ht_pp_free(state->forward);
	ht_pp_free(state->types);
	ht_pp_free(state->callables);
	rz_strbuf_free(state->debug);
	rz_strbuf_free(state->warnings);
	rz_strbuf_free(state->errors);
	free(state);
	return;
}

void c_parser_state_free_keep_ht(CParserState *state) {
	rz_strbuf_free(state->debug);
	rz_strbuf_free(state->warnings);
	rz_strbuf_free(state->errors);
	free(state);
	return;
}

struct rz_type_parser_t {
	CParserState *state;
};

RZ_API RZ_OWN RzTypeParser *rz_type_parser_new() {
	RzTypeParser *parser = RZ_NEW0(RzTypeParser);
	if (!parser) {
		return NULL;
	}
	parser->state = c_parser_state_new(NULL, NULL);
	return parser;
}

RZ_API RZ_OWN RzTypeParser *rz_type_parser_init(HtPP *types, HtPP *callables) {
	RzTypeParser *parser = RZ_NEW0(RzTypeParser);
	if (!parser) {
		return NULL;
	}
	parser->state = c_parser_state_new(types, callables);
	return parser;
}

RZ_API void rz_type_parser_free(RZ_NONNULL RzTypeParser *parser) {
	// We do not destroy HT by default since it might be used after
	c_parser_state_free_keep_ht(parser->state);
	free(parser);
}

RZ_API void rz_type_parser_free_purge(RZ_NONNULL RzTypeParser *parser) {
	c_parser_state_free(parser->state);
	free(parser);
}

static int type_parse_string(CParserState *state, const char *code, char **error_msg) {
	// Create a parser.
	TSParser *parser = ts_parser_new();
	// Set the parser's language (C in this case)
	ts_parser_set_language(parser, tree_sitter_c());

	TSTree *tree = ts_parser_parse_string(parser, NULL, code, strlen(code));

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
	if (state->verbose) {
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
		TSNode child = ts_node_named_child(root_node, i);
		// We skip ";" or "," - empty expressions
		const char *node_type = ts_node_type(child);
		if (!strcmp(node_type, "expression_statement")) {
			continue;
		}
		parser_debug(state, "Processing %d child...\n", i);
		result += parse_type_nodes_save(state, child, code);
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
	if (state->verbose) {
		const char *debug_msgs = rz_strbuf_drain_nofree(state->debug);
		eprintf(debug_msgs);
	}

	// After everything parsed, we should preserve the base type database
	c_parser_state_free_keep_ht(state);
	ts_tree_delete(tree);
	ts_parser_delete(parser);
	return result;
}

RZ_API int rz_type_parse_string_stateless(RzTypeParser *parser, const char *code, char **error_msg) {
	return type_parse_string(parser->state, code, error_msg);
}

RZ_API int rz_type_parse_file_stateless(RzTypeParser *parser, const char *path, const char *dir, char **error_msg) {
	size_t read_bytes = 0;
	const char *source_code = rz_file_slurp(path, &read_bytes);
	if (!source_code || !read_bytes) {
		return -1;
	}
	ut64 file_size = rz_file_size(path);
	RZ_LOG_DEBUG("File size is %" PFMT64d " bytes, read %zu bytes\n", file_size, read_bytes);
	return rz_type_parse_string_stateless(parser, source_code, error_msg);
}

RZ_API int rz_type_parse_file(RzTypeDB *typedb, const char *path, const char *dir, char **error_msg) {
	size_t read_bytes = 0;
	const char *source_code = rz_file_slurp(path, &read_bytes);
	if (!source_code || !read_bytes) {
		return -1;
	}
	ut64 file_size = rz_file_size(path);
	RZ_LOG_DEBUG("File size is %" PFMT64d " bytes, read %zu bytes\n", file_size, read_bytes);
	return rz_type_parse_string(typedb, source_code, error_msg);
}

RZ_API int rz_type_parse_string(RzTypeDB *typedb, const char *code, char **error_msg) {
	bool verbose = true;
	// Create new C parser state
	CParserState *state = c_parser_state_new(typedb->types, typedb->callables);
	if (!state) {
		eprintf("CParserState initialization error!\n");
		return -1;
	}
	state->verbose = verbose;
	return type_parse_string(state, code, error_msg);
}

RZ_API void rz_type_parse_reset(RzTypeDB *typedb) {
	rz_type_parser_free(typedb->parser);
	typedb->parser = rz_type_parser_new();
}

// Parses only single statement (the first one) and ignores everything else
RZ_API RZ_OWN RzType *rz_type_parse_string_single(RzTypeParser *parser, const char *code, char **error_msg) {
	// Create a parser.
	TSParser *tsparser = ts_parser_new();
	// Set the parser's language (C in this case)
	ts_parser_set_language(tsparser, tree_sitter_c());

	// Note, that the original C grammar doesn't have support for alternate roots,
	// see:
	// - https://github.com/tree-sitter/tree-sitter-c/issues/65
	// - https://github.com/tree-sitter/tree-sitter/issues/1105
	// Thus, we use our own patched C grammar that has an additional rule
	// for type descriptor, but we use the `__TYPE_EXPRESSION` prefix for every
	// such type descriptor expression.
	char *patched_code = rz_str_newf("__TYPE_EXPRESSION %s", code);

	TSTree *tree = ts_parser_parse_string(tsparser, NULL, patched_code, strlen(patched_code));

	// Get the root node of the syntax tree.
	TSNode root_node = ts_tree_root_node(tree);
	int root_node_child_count = ts_node_named_child_count(root_node);
	if (!root_node_child_count) {
		parser_warning(parser->state, "Root node is empty!\n");
		ts_tree_delete(tree);
		ts_parser_delete(tsparser);
		free(patched_code);
		return NULL;
	}

	// Some debugging
	if (parser->state->verbose) {
		parser_debug(parser->state, "root_node (%d children): %s\n", root_node_child_count, ts_node_type(root_node));
		// Print the syntax tree as an S-expression.
		char *string = ts_node_string(root_node);
		parser_debug(parser->state, "Syntax tree: %s\n", string);
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
	ParserTypePair *tpair = NULL;
	for (i = 0; i < root_node_child_count; i++) {
		parser_debug(parser->state, "Processing %d child...\n", i);
		TSNode child = ts_node_named_child(root_node, i);
		if (!parse_type_descriptor_single(parser->state, child, patched_code, &tpair)) {
			break;
		}
	}

	// If there were errors during the parser then the result is different from 0
	if (result || !tpair) {
		const char *error_msgs = rz_strbuf_drain_nofree(parser->state->errors);
		eprintf("Errors:\n");
		eprintf(error_msgs);
		const char *warning_msgs = rz_strbuf_drain_nofree(parser->state->warnings);
		eprintf("Warnings:\n");
		eprintf(warning_msgs);
		*error_msg = strdup(error_msgs);
	}
	if (parser->state->verbose) {
		const char *debug_msgs = rz_strbuf_drain_nofree(parser->state->debug);
		eprintf(debug_msgs);
	}

	// After everything parsed, we should preserve the base type database
	//c_parser_state_free_keep_ht(parser->state);
	ts_tree_delete(tree);
	ts_parser_delete(tsparser);
	free(patched_code);
	return tpair ? tpair->type : NULL;
}
