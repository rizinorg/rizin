// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
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

#ifdef __cplusplus
}
#endif

#endif
