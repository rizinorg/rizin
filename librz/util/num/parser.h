// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Internal interface to the RzNum tree-sitter parser.
 *
 * Declares the RzNumParseResult handle and the parse/root/source
 * accessors used by the evaluator. This header is private to the
 * num directory and is not installed.
 */

#ifndef RZ_NUM_PARSER_H
#define RZ_NUM_PARSER_H

#include <rz_types.h>
#include <tree_sitter/api.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Opaque result of a single parse.
 *
 * Owns the underlying TSTree, TSParser and a copy of the source text.
 * The source text is kept because tree-sitter nodes refer back to byte
 * offsets in the original buffer; consumers (e.g. the evaluator) read
 * literal text via rz_num_parse_source().
 */
typedef struct rz_num_parse_result_t {
	TSParser *parser;
	TSTree *tree;
	char *source;
	size_t source_len;
	bool has_error;
	char *error_msg;
} RzNumParseResult;

RZ_API RZ_OWN RzNumParseResult *rz_num_parse(RZ_NONNULL const char *expr);

RZ_API void rz_num_parse_result_free(RZ_NULLABLE RzNumParseResult *r);

RZ_API TSNode rz_num_parse_root(RZ_NONNULL const RzNumParseResult *r);

RZ_API RZ_BORROW const char *rz_num_parse_source(RZ_NONNULL const RzNumParseResult *r);

/**
 * \brief Cached tree-sitter symbol IDs for the RzNum grammar nodes.
 *
 * The grammar names a distinct node for every operator (sum, product,
 * signed_division, ...) and for the structural wrappers (expression,
 * parenthesized_expression, argument). Both the evaluator and the
 * RzNumExpression builder dispatch on these integer symbol IDs rather
 * than re-deriving node kinds from their string names, so the grammar's
 * vocabulary has a single definition: a grammar rename shows up as a
 * zeroed symbol here (see rz_num_parse_syms()) instead of silently
 * diverging between the two walkers.
 */
typedef struct rz_num_sym_cache_t {
	bool ready;
	// Operand-bearing nodes.
	TSSymbol sym_number;
	TSSymbol sym_variable;
	TSSymbol sym_special_variable;
	TSSymbol sym_address_typed;
	TSSymbol sym_string_bytes;
	TSSymbol sym_function;
	TSSymbol sym_parenthesized_expression;
	TSSymbol sym_source_file;
	TSSymbol sym_argument;
	TSSymbol sym_expression;
	// Binary operators.
	TSSymbol sym_sum;
	TSSymbol sym_subtraction;
	TSSymbol sym_product;
	TSSymbol sym_division;
	TSSymbol sym_signed_division;
	TSSymbol sym_modulo;
	TSSymbol sym_signed_modulo;
	TSSymbol sym_exponent;
	TSSymbol sym_logarithm;
	TSSymbol sym_logical_and;
	TSSymbol sym_logical_or;
	TSSymbol sym_logical_xor;
	TSSymbol sym_logical_shl;
	TSSymbol sym_logical_shr;
	TSSymbol sym_arith_shr;
	TSSymbol sym_logical_rol;
	TSSymbol sym_logical_ror;
	TSSymbol sym_less_than;
	TSSymbol sym_less_equal;
	TSSymbol sym_greater_than;
	TSSymbol sym_greater_equal;
	TSSymbol sym_equal;
	TSSymbol sym_not_equal;
	// Ternary.
	TSSymbol sym_conditional;
	// Unary operators.
	TSSymbol sym_logical_negation;
	TSSymbol sym_logical_not;
	TSSymbol sym_increment;
	TSSymbol sym_decrement;
	TSSymbol sym_unary_plus;
	TSSymbol sym_unary_minus;
	// Assignment forms.
	TSSymbol sym_assignment;
	TSSymbol sym_let_assignment;
} RzNumSymCache;

RZ_API RZ_BORROW const RzNumSymCache *rz_num_parse_syms(void);

#ifdef __cplusplus
}
#endif

#endif
