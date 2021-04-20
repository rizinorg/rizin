// SPDX-FileCopyrightText: 2019 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_list.h>
#include <rz_type.h>

#include <mpc.h>

struct rz_ast_parser_t {
	mpc_parser_t *integerlit;
	mpc_parser_t *identifier;
	mpc_parser_t *qualifier;
	mpc_parser_t *pointer;
	mpc_parser_t *array;
	mpc_parser_t *type;
};

#define ALL_PARSERS(cparser) cparser->integerlit, cparser->identifier, cparser->qualifier, cparser->pointer, cparser->array, cparser->type
#define ALL_PARSERS_COUNT    6

static const char *lang =
	"integerlit : /0x[0-9A-Fa-f]+/ | /[0-9]+/;"
	"identifier : (\"struct\" | \"union\" | \"enum\")? /[a-zA-Z_][0-9a-zA-Z_]+/;"
	"qualifier  : \"const\";"
	"pointer    : <qualifier>? '*';"
	"array      : '[' <integerlit> ']';"
	"type       : <qualifier>? <identifier> (<pointer> | <array>)*;";

RZ_API RzASTParser *rz_ast_parser_new(void) {
	RzASTParser *cparser = RZ_NEW(RzASTParser);
	if (!cparser) {
		return NULL;
	}

	cparser->integerlit = mpc_new("integerlit");
	cparser->identifier = mpc_new("identifier");
	cparser->qualifier = mpc_new("qualifier");
	cparser->pointer = mpc_new("pointer");
	cparser->array = mpc_new("array");
	cparser->type = mpc_new("type");

	mpc_err_t *err = mpca_lang(MPCA_LANG_DEFAULT, lang, ALL_PARSERS(cparser), NULL);
	if (err) {
		mpc_err_print(err);
		mpc_err_delete(err);
		rz_ast_parser_free(cparser);
		return NULL;
	}

	return cparser;
}

RZ_API void rz_ast_parser_free(RzASTParser *cparser) {
	if (!cparser) {
		return;
	}
	mpc_cleanup(ALL_PARSERS_COUNT, ALL_PARSERS(cparser));
	free(cparser);
}

static bool is_qualifier_const(mpc_ast_t *a) {
	return strcmp(a->tag, "qualifier|string") == 0 && a->contents && strcmp(a->contents, "const") == 0;
}

static bool is_identifier_string(mpc_ast_t *a) {
	return strcmp(a->tag, "identifier|regex") == 0 && a->contents;
}

static bool is_identifier_kind(mpc_ast_t *a) {
	return strcmp(a->tag, "identifier|>") == 0 && a->children_num == 2 && strcmp(a->children[0]->tag, "string") == 0 && a->children[0]->contents && strcmp(a->children[1]->tag, "regex") == 0 && a->children[1]->contents;
}

static bool is_non_const_pointer(mpc_ast_t *a) {
	return strcmp(a->tag, "pointer|char") == 0 && a->contents && strcmp(a->contents, "*") == 0;
}

static bool is_const_pointer(mpc_ast_t *a) {
	return strcmp(a->tag, "pointer|>") == 0 && a->children_num == 2 && is_qualifier_const(a->children[0]) && strcmp(a->children[1]->tag, "char") == 0 && a->children[1]->contents && strcmp(a->children[1]->contents, "*") == 0;
}

static bool is_array(mpc_ast_t *a) {
	return strcmp(a->tag, "array|>") == 0 && a->children_num == 3 && strcmp(a->children[0]->tag, "char") == 0 && a->children[0]->contents && strcmp(a->children[0]->contents, "[") == 0 && strcmp(a->children[1]->tag, "integerlit|regex") == 0 && a->children[1]->contents && strcmp(a->children[2]->tag, "char") == 0 && a->children[2]->contents && strcmp(a->children[2]->contents, "]") == 0;
}

static RzType *ctype_convert_ast(mpc_ast_t *a) {
	bool is_const = false;
	RzType *cur = NULL;
	int i;
	for (i = 0; i < a->children_num; i++) {
		mpc_ast_t *child = a->children[i];

		// const
		if (is_qualifier_const(child)) {
			is_const = true;
		}

		// (struct|union|enum)? <identifier>
		else if (rz_str_startswith(child->tag, "identifier|")) {
			if (cur) {
				// identifier should always be the innermost type
				goto beach;
			}
			cur = RZ_NEW0(RzType);
			if (!cur) {
				goto beach;
			}
			cur->kind = RZ_TYPE_KIND_IDENTIFIER;
			cur->identifier.is_const = is_const;
			cur->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
			if (is_identifier_string(child)) {
				cur->identifier.name = strdup(child->contents);
			} else if (is_identifier_kind(child)) {
				if (strcmp(child->children[0]->contents, "struct") == 0) {
					cur->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_STRUCT;
				} else if (strcmp(child->children[0]->contents, "union") == 0) {
					cur->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNION;
				} else if (strcmp(child->children[0]->contents, "enum") == 0) {
					cur->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_ENUM;
				}
				cur->identifier.name = strdup(child->children[1]->contents);
			} else {
				goto beach;
			}
			if (!cur->identifier.name) {
				goto beach;
			}
			is_const = false;
		}

		// <identifier>
		else if (is_identifier_string(child)) {
			if (cur) {
				// identifier should always be the innermost type
				goto beach;
			}
			cur = RZ_NEW0(RzType);
			if (!cur) {
				goto beach;
			}
			cur->kind = RZ_TYPE_KIND_IDENTIFIER;
			cur->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
			cur->identifier.is_const = is_const;
			cur->identifier.name = strdup(child->contents);
			if (!cur->identifier.name) {
				goto beach;
			}
			is_const = false;
		}

		// *
		else if (is_non_const_pointer(child)) {
			RzType *pointer = RZ_NEW0(RzType);
			if (!pointer) {
				goto beach;
			}
			pointer->kind = RZ_TYPE_KIND_POINTER;
			pointer->pointer.is_const = false;
			pointer->pointer.type = cur;
			cur = pointer;
		}

		// const *
		else if (is_const_pointer(child)) {
			RzType *pointer = RZ_NEW0(RzType);
			if (!pointer) {
				goto beach;
			}
			pointer->kind = RZ_TYPE_KIND_POINTER;
			pointer->pointer.is_const = true;
			pointer->pointer.type = cur;
			cur = pointer;
		}

		// <array>
		else if (is_array(child)) {
			RzType *array = RZ_NEW0(RzType);
			if (!array) {
				goto beach;
			}
			array->kind = RZ_TYPE_KIND_ARRAY;
			array->array.count = strtoull(child->children[1]->contents, NULL, 0);
			array->array.type = cur;
			cur = array;
		}

		else {
			goto beach;
		}
	}

	return cur;
beach:
	rz_type_free(cur);
	return NULL;
}

RZ_API RzType *rz_type_parse(RzASTParser *cparser, const char *str, char **error) {
	mpc_result_t r;
	if (mpc_parse("<string>", str, cparser->type, &r)) {
		RzType *ret = ctype_convert_ast(r.output);
		if (error) {
			*error = !ret ? strdup("internal error") : NULL;
		}
		mpc_ast_delete(r.output);
		return ret;
	} else {
		if (error) {
			*error = mpc_err_string(r.error);
		}
		mpc_err_delete(r.error);
		return NULL;
	}
}

RZ_API RZ_OWN char *rz_type_as_string(RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(typedb && type, NULL);

	RzStrBuf *buf = rz_strbuf_new("");
	switch (type->kind) {
	case RZ_TYPE_KIND_IDENTIFIER: {
		// Here it can be any of the RzBaseType
		RzBaseType *btype = rz_type_db_get_base_type(typedb, type->identifier.name);
		if (!btype) {
			return NULL;
		}
		const char *btypestr = rz_type_db_base_type_as_string(typedb, btype);
		rz_strbuf_append(buf, btypestr);
		break;
	}
	case RZ_TYPE_KIND_POINTER: {
		const char *typestr = rz_type_as_string(typedb, type->pointer.type);
		if (type->pointer.is_const) {
			rz_strbuf_appendf(buf, "const %s *", typestr);
		} else {
			rz_strbuf_appendf(buf, "%s *", typestr);
		}
		break;
	}
	case RZ_TYPE_KIND_ARRAY: {
		const char *typestr = rz_type_as_string(typedb, type->array.type);
		rz_strbuf_appendf(buf, "%s[%" PFMT64d "]", typestr, type->array.count);
		break;
	}
	case RZ_TYPE_KIND_CALLABLE:
		// FIXME: Implement it
		rz_warn_if_reached();
		break;
	}
	char *result = rz_strbuf_drain(buf);
	return result;
}

RZ_API void rz_type_free(RzType *type) {
	if (!type) {
		return;
	}
	switch (type->kind) {
	case RZ_TYPE_KIND_IDENTIFIER:
		free(type->identifier.name);
		break;
	case RZ_TYPE_KIND_POINTER:
		rz_type_free(type->pointer.type);
		break;
	case RZ_TYPE_KIND_ARRAY:
		rz_type_free(type->array.type);
		break;
	case RZ_TYPE_KIND_CALLABLE:
		rz_warn_if_reached();
		break;
	}
	free(type);
}
