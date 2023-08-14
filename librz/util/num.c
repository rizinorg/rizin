// SPDX-FileCopyrightText: 2023 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_types.h>
#include <rz_list.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_file.h>
#include <rz_util/rz_assert.h>
#include <tree_sitter/api.h>

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

TSLanguage *tree_sitter_rznum();

static int parse_string(NumParserState *state, const char *code, char **error_msg) {
	// Create a parser.
	TSParser *parser = ts_parser_new();
	// Set the parser's language (RzNum in this case)
	ts_parser_set_language(parser, tree_sitter_rznum());

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

	// Filter types function prototypes and start parsing
	int i = 0, result = 0;
	for (i = 0; i < root_node_child_count; i++) {
		TSNode child = ts_node_named_child(root_node, i);
		// We skip ";" or "," - empty expressions
		char *node_code = ts_node_sub_string(child, code);
		if (!strcmp(node_code, ";") || !strcmp(node_code, ",")) {
			free(node_code);
			continue;
		}
		free(node_code);
		parser_debug(state, "Processing %d child...\n", i);
		result += parse_type_nodes_save(state, child, code);
	}

	// If there were errors during the parser then the result is different from 0
	if (result) {
		char *error_msgs = rz_strbuf_drain_nofree(state->errors);
		RZ_LOG_DEBUG("Errors:\n");
		RZ_LOG_DEBUG("%s", error_msgs);
		char *warning_msgs = rz_strbuf_drain_nofree(state->warnings);
		RZ_LOG_DEBUG("Warnings:\n");
		RZ_LOG_DEBUG("%s", warning_msgs);
		if (error_msg) {
			*error_msg = strdup(error_msgs);
		}
		free(error_msgs);
		free(warning_msgs);
	}
	if (state->verbose) {
		char *debug_msgs = rz_strbuf_drain_nofree(state->debug);
		RZ_LOG_DEBUG("%s", debug_msgs);
		free(debug_msgs);
	}

	// After everything parsed, we should preserve the base type database
	// And the state of the parser - anonymous structs, forward declarations, etc
	ts_tree_delete(tree);
	ts_parser_delete(parser);
	return result;
}
