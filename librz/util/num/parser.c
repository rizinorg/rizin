// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
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

// Shared grammar symbol cache. Lazily initialised on first use; the
// evaluator and the RzNumExpression builder both dispatch on its IDs so
// the grammar's node vocabulary is defined in exactly one place.
static RzNumSymCache g_num_syms;

// Look up a symbol ID by name in the language. Returns 0 (the special
// "no symbol" value) when the name is not in the grammar, which lets a
// stale-grammar mismatch surface here rather than as a silent misparse.
static TSSymbol sym_lookup(TSLanguage *lang, const char *name) {
	return ts_language_symbol_for_name(lang, name, (uint32_t)strlen(name), true);
}

/**
 * \brief Return the lazily-initialised RzNum grammar symbol cache.
 * \return Borrowed pointer to the shared symbol cache; never NULL.
 *
 * Populated on first call from the compiled grammar and shared by every
 * consumer in the num directory. tree_sitter_rznum() returns a
 * process-wide singleton language whose symbol table is immutable, so
 * two threads racing to populate the cache write identical values; the
 * worst case is duplicate work, not corruption, and no platform-specific
 * primitive is needed - only plain C99 accesses.
 */
RZ_API RZ_BORROW const RzNumSymCache *rz_num_parse_syms(void) {
	if (g_num_syms.ready) {
		return &g_num_syms;
	}
	TSLanguage *lang = tree_sitter_rznum();
	g_num_syms.sym_number = sym_lookup(lang, "number");
	g_num_syms.sym_variable = sym_lookup(lang, "variable");
	g_num_syms.sym_special_variable = sym_lookup(lang, "special_variable");
	g_num_syms.sym_address_typed = sym_lookup(lang, "address_typed");
	g_num_syms.sym_string_bytes = sym_lookup(lang, "string_bytes");
	g_num_syms.sym_function = sym_lookup(lang, "function");
	g_num_syms.sym_parenthesized_expression = sym_lookup(lang, "parenthesized_expression");
	g_num_syms.sym_source_file = sym_lookup(lang, "source_file");
	g_num_syms.sym_argument = sym_lookup(lang, "argument");
	g_num_syms.sym_expression = sym_lookup(lang, "expression");
	g_num_syms.sym_sum = sym_lookup(lang, "sum");
	g_num_syms.sym_subtraction = sym_lookup(lang, "subtraction");
	g_num_syms.sym_product = sym_lookup(lang, "product");
	g_num_syms.sym_division = sym_lookup(lang, "division");
	g_num_syms.sym_signed_division = sym_lookup(lang, "signed_division");
	g_num_syms.sym_modulo = sym_lookup(lang, "modulo");
	g_num_syms.sym_signed_modulo = sym_lookup(lang, "signed_modulo");
	g_num_syms.sym_exponent = sym_lookup(lang, "exponent");
	g_num_syms.sym_logarithm = sym_lookup(lang, "logarithm");
	g_num_syms.sym_logical_and = sym_lookup(lang, "logical_and");
	g_num_syms.sym_logical_or = sym_lookup(lang, "logical_or");
	g_num_syms.sym_logical_xor = sym_lookup(lang, "logical_xor");
	g_num_syms.sym_logical_shl = sym_lookup(lang, "logical_shl");
	g_num_syms.sym_logical_shr = sym_lookup(lang, "logical_shr");
	g_num_syms.sym_arith_shr = sym_lookup(lang, "arith_shr");
	g_num_syms.sym_logical_rol = sym_lookup(lang, "logical_rol");
	g_num_syms.sym_logical_ror = sym_lookup(lang, "logical_ror");
	g_num_syms.sym_less_than = sym_lookup(lang, "less_than");
	g_num_syms.sym_less_equal = sym_lookup(lang, "less_equal");
	g_num_syms.sym_greater_than = sym_lookup(lang, "greater_than");
	g_num_syms.sym_greater_equal = sym_lookup(lang, "greater_equal");
	g_num_syms.sym_equal = sym_lookup(lang, "equal");
	g_num_syms.sym_not_equal = sym_lookup(lang, "not_equal");
	g_num_syms.sym_conditional = sym_lookup(lang, "conditional");
	g_num_syms.sym_logical_negation = sym_lookup(lang, "logical_negation");
	g_num_syms.sym_logical_not = sym_lookup(lang, "logical_not");
	g_num_syms.sym_increment = sym_lookup(lang, "increment");
	g_num_syms.sym_decrement = sym_lookup(lang, "decrement");
	g_num_syms.sym_unary_plus = sym_lookup(lang, "unary_plus");
	g_num_syms.sym_unary_minus = sym_lookup(lang, "unary_minus");
	g_num_syms.sym_assignment = sym_lookup(lang, "assignment");
	g_num_syms.sym_let_assignment = sym_lookup(lang, "let_assignment");
	g_num_syms.ready = true;
	return &g_num_syms;
}

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
 * Valid until rz_num_parse_result_free() is called.
 */
RZ_API RZ_BORROW const char *rz_num_parse_source(RZ_NONNULL const RzNumParseResult *r) {
	rz_return_val_if_fail(r, NULL);
	return r->source;
}
