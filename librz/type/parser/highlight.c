// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_type.h>
#include <tree_sitter/api.h>

const TSLanguage *tree_sitter_c(void);

static bool is_function_declarator(TSNode node) {
	TSNode parent = ts_node_parent(node);
	while (!ts_node_is_null(parent)) {
		const char *type = ts_node_type(parent);
		if (!strcmp(type, "function_declarator")) {
			return ts_node_eq(node, ts_node_child_by_field_name(parent, "declarator", 10));
		}
		if (strcmp(type, "pointer_declarator") && strcmp(type, "parenthesized_declarator") &&
			strcmp(type, "attributed_declarator")) {
			return false;
		}
		node = parent;
		parent = ts_node_parent(node);
	}
	return false;
}

static bool c_node_highlight(TSNode node, RSyntaxHighlightType *highlight) {
	const char *type = ts_node_type(node);
	if (!strcmp(type, "primitive_type") || !strcmp(type, "type_identifier") ||
		!strcmp(type, "sized_type_specifier")) {
		*highlight = RZ_SYNTAX_HIGHLIGHT_TYPE_DATATYPE;
		return true;
	}
	if (!strcmp(type, "comment")) {
		*highlight = RZ_SYNTAX_HIGHLIGHT_TYPE_COMMENT;
		return true;
	}
	if (!strcmp(type, "number_literal") || !strcmp(type, "char_literal") ||
		!strcmp(type, "string_literal") || !strcmp(type, "null")) {
		*highlight = RZ_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE;
		return true;
	}
	if (!strcmp(type, "identifier") || !strcmp(type, "field_identifier")) {
		if (is_function_declarator(node)) {
			*highlight = RZ_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME;
			return true;
		}
		TSNode parent = ts_node_parent(node);
		if (!ts_node_is_null(parent) && !strcmp(ts_node_type(parent), "enumerator")) {
			*highlight = RZ_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE;
			return true;
		}
	}
	static const char *const keywords[] = {
		"struct",
		"union",
		"enum",
		"typedef",
		"type_qualifier",
		"storage_class_specifier",
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(keywords); i++) {
		if (!strcmp(type, keywords[i])) {
			*highlight = RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD;
			return true;
		}
	}
	return false;
}

/**
 * \brief Annotate C declarations for display without changing the type database.
 *
 * The annotations use byte offsets into an owned copy of \p source, in source
 * order and without overlaps. Tree-sitter's error recovery also permits partial
 * declarations, as used when displaying a member's type. No semantic type lookup
 * is performed, and the source text is preserved even when it is incomplete.
 *
 * \param source NUL-terminated C source, at most UT32_MAX bytes.
 * \return Annotated source, or NULL on allocation/parser failure or excessive length.
 */
RZ_API RZ_OWN RzAnnotatedCode *rz_type_c_highlight(RZ_NONNULL RZ_BORROW const char *source) {
	rz_return_val_if_fail(source, NULL);
	size_t len = strlen(source);
	if (len > UT32_MAX) {
		return NULL;
	}
	TSParser *parser = ts_parser_new();
	if (!parser) {
		return NULL;
	}
	if (!ts_parser_set_language(parser, tree_sitter_c())) {
		ts_parser_delete(parser);
		return NULL;
	}
	TSTree *tree = ts_parser_parse_string(parser, NULL, source, (ut32)len);
	ts_parser_delete(parser);
	if (!tree) {
		return NULL;
	}
	char *copy = rz_str_dup(source);
	RzAnnotatedCode *code = copy ? rz_annotated_code_new(copy) : NULL;
	if (!code) {
		free(copy);
		ts_tree_delete(tree);
		return NULL;
	}
	TSTreeCursor cursor = ts_tree_cursor_new(ts_tree_root_node(tree));
	for (;;) {
		TSNode node = ts_tree_cursor_current_node(&cursor);
		RSyntaxHighlightType highlight;
		bool colored = c_node_highlight(node, &highlight);
		if (colored && ts_node_end_byte(node) > ts_node_start_byte(node)) {
			RzCodeAnnotation annotation = { 0 };
			annotation.start = ts_node_start_byte(node);
			annotation.end = ts_node_end_byte(node);
			annotation.type = RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT;
			annotation.syntax_highlight.type = highlight;
			if (!rz_vector_push(&code->annotations, &annotation)) {
				rz_annotated_code_free(code);
				code = NULL;
				break;
			}
		}
		// A colored node already covers its children. Use a cursor to avoid
		// consuming the C stack on deeply nested declarations.
		if (!colored && ts_tree_cursor_goto_first_child(&cursor)) {
			continue;
		}
		while (!ts_tree_cursor_goto_next_sibling(&cursor)) {
			if (!ts_tree_cursor_goto_parent(&cursor)) {
				goto cleanup;
			}
		}
	}
cleanup:
	ts_tree_cursor_delete(&cursor);
	ts_tree_delete(tree);
	return code;
}
