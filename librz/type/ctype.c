// SPDX-FileCopyrightText: 2019 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_list.h>
#include <rz_type.h>

struct rz_ast_parser_t {
};

RZ_API RzASTParser *rz_ast_parser_new(void) {
	RzASTParser *cparser = RZ_NEW(RzASTParser);
	if (!cparser) {
		return NULL;
	}

	return cparser;
}

RZ_API void rz_ast_parser_free(RzASTParser *cparser) {
	if (!cparser) {
		return;
	}
	free(cparser);
}

RZ_API RzType *rz_type_parse(RzASTParser *cparser, const char *str, char **error) {
	// TODO: Support both C and C++ types
	return NULL;
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
