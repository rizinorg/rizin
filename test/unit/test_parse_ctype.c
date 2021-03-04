// SPDX-FileCopyrightText: 2019 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_parse.h>
#include "minunit.h"

bool test_rz_parse_ctype(void) {
	RzParseCType *ctype = rz_parse_ctype_new();
	mu_assert_notnull(ctype, "rz_parse_ctype_new");
	char *error;
	RzParseCTypeType *type = rz_parse_ctype_parse(ctype, "const char * [0x42] const * [23]", &error);
	if (error) {
		eprintf("%s\n", error);
		free(error);
	}
	mu_assert_notnull(type, "rz_parse_ctype_parse");

	RzParseCTypeType *cur = type;

	mu_assert_eq(cur->kind, RZ_PARSE_CTYPE_TYPE_KIND_ARRAY, "array");
	mu_assert_eq(cur->array.count, 23, "array count (dec)");
	cur = cur->array.type;

	mu_assert_eq(cur->kind, RZ_PARSE_CTYPE_TYPE_KIND_POINTER, "pointer");
	mu_assert_eq(cur->pointer.is_const, true, "pointer const");
	cur = cur->pointer.type;

	mu_assert_eq(cur->kind, RZ_PARSE_CTYPE_TYPE_KIND_ARRAY, "array");
	mu_assert_eq(cur->array.count, 0x42, "array count (hex)");
	cur = cur->array.type;

	mu_assert_eq(cur->kind, RZ_PARSE_CTYPE_TYPE_KIND_POINTER, "pointer");
	mu_assert_eq(cur->pointer.is_const, false, "pointer non-const");
	cur = cur->pointer.type;

	mu_assert_eq(cur->kind, RZ_PARSE_CTYPE_TYPE_KIND_IDENTIFIER, "identifier");
	mu_assert_eq(cur->identifier.kind, RZ_PARSE_CTYPE_IDENTIFIER_KIND_UNSPECIFIED, "identifier kind");
	mu_assert_eq(cur->identifier.is_const, true, "identifier const");
	mu_assert_streq(cur->identifier.name, "char", "identifier name");

	rz_parse_ctype_type_free(type);
	rz_parse_ctype_free(ctype);
	mu_end;
}

bool test_rz_parse_ctype_identifier_kind(void) {
	RzParseCType *ctype = rz_parse_ctype_new();
	mu_assert_notnull(ctype, "rz_parse_ctype_new");
	char *error;
	RzParseCTypeType *type = rz_parse_ctype_parse(ctype, "struct ulu", &error);
	if (error) {
		eprintf("%s\n", error);
		free(error);
	}
	mu_assert_notnull(type, "rz_parse_ctype_parse(\"struct ulu\")");
	mu_assert_eq(type->kind, RZ_PARSE_CTYPE_TYPE_KIND_IDENTIFIER, "identifier");
	mu_assert_eq(type->identifier.kind, RZ_PARSE_CTYPE_IDENTIFIER_KIND_STRUCT, "identifier kind");
	mu_assert_eq(type->identifier.is_const, false, "identifier const");
	mu_assert_streq(type->identifier.name, "ulu", "identifier name");
	rz_parse_ctype_type_free(type);

	type = rz_parse_ctype_parse(ctype, "union mulu", &error);
	if (error) {
		eprintf("%s\n", error);
		free(error);
	}
	mu_assert_notnull(type, "rz_parse_ctype_parse(\"union mulu\")");
	mu_assert_eq(type->kind, RZ_PARSE_CTYPE_TYPE_KIND_IDENTIFIER, "identifier");
	mu_assert_eq(type->identifier.kind, RZ_PARSE_CTYPE_IDENTIFIER_KIND_UNION, "identifier kind");
	mu_assert_eq(type->identifier.is_const, false, "identifier const");
	mu_assert_streq(type->identifier.name, "mulu", "identifier name");
	rz_parse_ctype_type_free(type);

	type = rz_parse_ctype_parse(ctype, "enum urshak", &error);
	if (error) {
		eprintf("%s\n", error);
		free(error);
	}
	mu_assert_notnull(type, "rz_parse_ctype_parse(\"enum urshak\")");
	mu_assert_eq(type->kind, RZ_PARSE_CTYPE_TYPE_KIND_IDENTIFIER, "identifier");
	mu_assert_eq(type->identifier.kind, RZ_PARSE_CTYPE_IDENTIFIER_KIND_ENUM, "identifier kind");
	mu_assert_eq(type->identifier.is_const, false, "identifier const");
	mu_assert_streq(type->identifier.name, "urshak", "identifier name");
	rz_parse_ctype_type_free(type);

	rz_parse_ctype_free(ctype);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_parse_ctype);
	mu_run_test(test_rz_parse_ctype_identifier_kind);
	return tests_passed != tests_run;
}

mu_main(all_tests)