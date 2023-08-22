// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Tree-sitter glue for the RzNum expression parser.
 *
 * Wraps the rizin-math-parser tree-sitter grammar in a small
 * RzNumParseResult handle that owns the parser, the parsed tree, and
 * a copy of the source text. The evaluator (evaluator.c) walks
 * the tree this module produces.
 */

#include <rz_types.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_assert.h>
#include <tree_sitter/api.h>

#include "parser.h"

// Provided by the rizin-math-parser subproject's generated parser.c.
TSLanguage *tree_sitter_rznum(void);

/**
 * Recursively walk the parse tree to find the first ERROR or MISSING
 * node and report its position. Returns true if the tree is clean.
 */
static bool tree_is_clean(TSNode node, char **out_err) {
	if (!ts_node_has_error(node)) {
		return true;
	}
	if (ts_node_is_missing(node) || ts_node_is_error(node)) {
		if (out_err && !*out_err) {
			TSPoint p = ts_node_start_point(node);
			const char *kind = ts_node_is_missing(node) ? "missing token" : "syntax error";
			*out_err = rz_str_newf("%s at line %u column %u",
				kind, (unsigned)p.row + 1, (unsigned)p.column + 1);
		}
		return false;
	}
	uint32_t n = ts_node_child_count(node);
	for (uint32_t i = 0; i < n; i++) {
		TSNode child = ts_node_child(node, i);
		if (!tree_is_clean(child, out_err)) {
			return false;
		}
	}
	return true;
}

/**
 * \brief Parse a numerical expression.
 *
 * Returns an RzNumParseResult that the caller must release with
 * rz_num_parse_result_free(). If parsing produced any ERROR or MISSING
 * nodes, has_error is true and error_msg carries a one-line
 * diagnostic (the first parse error encountered, line/column based).
 *
 * Returns NULL only on allocation failure.
 */
RZ_API RZ_OWN RzNumParseResult *rz_num_parse(RZ_NONNULL const char *expr) {
	rz_return_val_if_fail(expr, NULL);
	RzNumParseResult *r = RZ_NEW0(RzNumParseResult);
	if (!r) {
		return NULL;
	}
	r->source = rz_str_dup(expr);
	if (!r->source) {
		free(r);
		return NULL;
	}
	r->source_len = strlen(r->source);

	r->parser = ts_parser_new();
	if (!r->parser) {
		rz_num_parse_result_free(r);
		return NULL;
	}
	ts_parser_set_language(r->parser, tree_sitter_rznum());
	r->tree = ts_parser_parse_string(r->parser, NULL, r->source, (uint32_t)r->source_len);
	if (!r->tree) {
		r->has_error = true;
		r->error_msg = rz_str_dup("parser returned no tree");
		return r;
	}
	TSNode root = ts_tree_root_node(r->tree);
	if (ts_node_named_child_count(root) == 0) {
		r->has_error = true;
		r->error_msg = rz_str_dup("empty expression");
		return r;
	}
	char *err = NULL;
	if (!tree_is_clean(root, &err)) {
		r->has_error = true;
		r->error_msg = err ? err : rz_str_dup("parse error");
	}
	return r;
}

/**
 * \brief Release an RzNumParseResult and all the resources it owns.
 */
RZ_API void rz_num_parse_result_free(RZ_NULLABLE RzNumParseResult *r) {
	if (!r) {
		return;
	}
	if (r->tree) {
		ts_tree_delete(r->tree);
	}
	if (r->parser) {
		ts_parser_delete(r->parser);
	}
	free(r->source);
	free(r->error_msg);
	free(r);
}

/**
 * \brief Return the root TSNode of the parsed tree.
 *
 * For a syntactically valid input the root is named "source_file"
 * with one named child of type "expression".
 */
RZ_API TSNode rz_num_parse_root(RZ_NONNULL const RzNumParseResult *r) {
	rz_return_val_if_fail(r && r->tree, (TSNode){ 0 });
	return ts_tree_root_node(r->tree);
}

/**
 * \brief Return the source text that the tree refers into.
 *
 * The returned pointer is borrowed from the RzNumParseResult and is
 * valid until rz_num_parse_result_free() is called.
 */
RZ_API RZ_BORROW const char *rz_num_parse_source(RZ_NONNULL const RzNumParseResult *r) {
	rz_return_val_if_fail(r, NULL);
	return r->source;
}
