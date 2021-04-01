// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_parse.h>

#include "minunit.h"
#include "test_sdb.h"

static void setup_sdb_for_struct(Sdb *res) {
	// td "struct kappa {int bar;int cow;};"
	sdb_set(res, "kappa", "struct", 0);
	sdb_set(res, "struct.kappa", "bar,cow", 0);
	sdb_set(res, "struct.kappa.bar", "int32_t,0,0", 0);
	sdb_set(res, "struct.kappa.cow", "int32_t,4,0", 0);
}

static void setup_sdb_for_union(Sdb *res) {
	// td "union kappa {int bar;int cow;};"
	sdb_set(res, "kappa", "union", 0);
	sdb_set(res, "union.kappa", "bar,cow", 0);
	sdb_set(res, "union.kappa.bar", "int32_t,0,0", 0);
	sdb_set(res, "union.kappa.cow", "int32_t,0,0", 0);
}

static void setup_sdb_for_enum(Sdb *res) {
	// td "enum foo { firstCase=1, secondCase=2,};"
	sdb_set(res, "foo", "enum", 0);
	sdb_set(res, "enum.foo", "firstCase,secondCase", 0);
	sdb_set(res, "enum.foo.firstCase", "0x1", 0);
	sdb_set(res, "enum.foo.secondCase", "0x2", 0);
	sdb_set(res, "enum.foo.0x1", "firstCase", 0);
	sdb_set(res, "enum.foo.0x2", "secondCase", 0);
}

static void setup_sdb_for_typedef(Sdb *res) {
	// td typedef char *string;
	sdb_set(res, "string", "typedef", 0);
	sdb_set(res, "typedef.string", "char *", 0);
}

static void setup_sdb_for_atomic(Sdb *res) {
	sdb_set(res, "char", "type", 0);
	sdb_set(res, "type.char.size", "8", 0);
	sdb_set(res, "type.char", "c", 0);
}

static void setup_sdb_for_not_found(Sdb *res) {
	// malformed type states
	sdb_set(res, "foo", "enum", 0);
	sdb_set(res, "bar", "struct", 0);
	sdb_set(res, "quax", "union", 0);
	sdb_set(res, "enum.foo", "aa,bb", 0);
	sdb_set(res, "struct.bar", "cc,dd", 0);
	sdb_set(res, "union.quax", "ee,ff", 0);

	sdb_set(res, "omega", "struct", 0);
	sdb_set(res, "struct.omega", "ee,ff,gg", 0);
	sdb_set(res, "struct.omega.ee", "0,1", 0);
	sdb_set(res, "struct.omega.ff", "", 0);
}

static bool test_analysis_get_base_type_struct(void) {
	RzAnalysis *analysis = rz_analysis_new();
	mu_assert_notnull(analysis, "Couldn't create new RzAnalysis");
	mu_assert_notnull(analysis->sdb_types, "Couldn't create new RzAnalysis.sdb_types");

	setup_sdb_for_struct(analysis->sdb_types);

	RzAnalysisBaseType *base = rz_analysis_get_base_type(analysis, "kappa");
	mu_assert_notnull(base, "Couldn't create get base type of struct \"kappa\"");

	mu_assert_eq(RZ_ANALYSIS_BASE_TYPE_KIND_STRUCT, base->kind, "Wrong base type");
	mu_assert_streq(base->name, "kappa", "type name");

	RzAnalysisStructMember *member;

	member = rz_vector_index_ptr(&base->struct_data.members, 0);
	mu_assert_eq(member->offset, 0, "Incorrect offset for struct member");
	mu_assert_streq(member->type, "int32_t", "Incorrect type for struct member");
	mu_assert_streq(member->name, "bar", "Incorrect name for struct member");

	member = rz_vector_index_ptr(&base->struct_data.members, 1);
	mu_assert_eq(member->offset, 4, "Incorrect offset for struct member");
	mu_assert_streq(member->type, "int32_t", "Incorrect type for struct member");
	mu_assert_streq(member->name, "cow", "Incorrect name for struct member");

	rz_analysis_base_type_free(base);
	rz_analysis_free(analysis);
	mu_end;
}

static bool test_analysis_save_base_type_struct(void) {
	RzAnalysis *analysis = rz_analysis_new();
	mu_assert_notnull(analysis, "Couldn't create new RzAnalysis");
	mu_assert_notnull(analysis->sdb_types, "Couldn't create new RzAnalysis.sdb_types");

	RzAnalysisBaseType *base = rz_analysis_base_type_new(RZ_ANALYSIS_BASE_TYPE_KIND_STRUCT);
	base->name = strdup("kappa");

	RzAnalysisStructMember member = {
		.offset = 0,
		.type = strdup("int32_t"),
		.name = strdup("bar")
	};
	rz_vector_push(&base->struct_data.members, &member);

	member.offset = 4;
	member.type = strdup("int32_t");
	member.name = strdup("cow");
	rz_vector_push(&base->struct_data.members, &member);

	rz_analysis_save_base_type(analysis, base);
	rz_analysis_base_type_free(base);

	Sdb *reg = sdb_new0();
	setup_sdb_for_struct(reg);
	assert_sdb_eq(analysis->sdb_types, reg, "save struct type");
	sdb_free(reg);

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_analysis_get_base_type_union(void) {
	RzAnalysis *analysis = rz_analysis_new();
	mu_assert_notnull(analysis, "Couldn't create new RzAnalysis");
	mu_assert_notnull(analysis->sdb_types, "Couldn't create new RzAnalysis.sdb_types");

	setup_sdb_for_union(analysis->sdb_types);

	RzAnalysisBaseType *base = rz_analysis_get_base_type(analysis, "kappa");
	mu_assert_notnull(base, "Couldn't create get base type of union \"kappa\"");

	mu_assert_eq(RZ_ANALYSIS_BASE_TYPE_KIND_UNION, base->kind, "Wrong base type");
	mu_assert_streq(base->name, "kappa", "type name");

	RzAnalysisUnionMember *member;

	member = rz_vector_index_ptr(&base->union_data.members, 0);
	mu_assert_streq(member->type, "int32_t", "Incorrect type for union member");
	mu_assert_streq(member->name, "bar", "Incorrect name for union member");

	member = rz_vector_index_ptr(&base->union_data.members, 1);
	mu_assert_streq(member->type, "int32_t", "Incorrect type for union member");
	mu_assert_streq(member->name, "cow", "Incorrect name for union member");

	rz_analysis_base_type_free(base);
	rz_analysis_free(analysis);
	mu_end;
}

static bool test_analysis_save_base_type_union(void) {
	RzAnalysis *analysis = rz_analysis_new();
	mu_assert_notnull(analysis, "Couldn't create new RzAnalysis");
	mu_assert_notnull(analysis->sdb_types, "Couldn't create new RzAnalysis.sdb_types");

	RzAnalysisBaseType *base = rz_analysis_base_type_new(RZ_ANALYSIS_BASE_TYPE_KIND_UNION);
	base->name = strdup("kappa");

	RzAnalysisUnionMember member = {
		.offset = 0,
		.type = strdup("int32_t"),
		.name = strdup("bar")
	};
	rz_vector_push(&base->union_data.members, &member);

	member.offset = 0;
	member.type = strdup("int32_t");
	member.name = strdup("cow");
	rz_vector_push(&base->union_data.members, &member);

	rz_analysis_save_base_type(analysis, base);
	rz_analysis_base_type_free(base);

	Sdb *reg = sdb_new0();
	setup_sdb_for_union(reg);
	assert_sdb_eq(analysis->sdb_types, reg, "save union type");
	sdb_free(reg);

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_analysis_get_base_type_enum(void) {
	RzAnalysis *analysis = rz_analysis_new();
	mu_assert_notnull(analysis, "Couldn't create new RzAnalysis");
	mu_assert_notnull(analysis->sdb_types, "Couldn't create new RzAnalysis.sdb_types");

	setup_sdb_for_enum(analysis->sdb_types);

	RzAnalysisBaseType *base = rz_analysis_get_base_type(analysis, "foo");
	mu_assert_notnull(base, "Couldn't create get base type of enum \"foo\"");

	mu_assert_eq(RZ_ANALYSIS_BASE_TYPE_KIND_ENUM, base->kind, "Wrong base type");
	mu_assert_streq(base->name, "foo", "type name");

	RzAnalysisEnumCase *cas = rz_vector_index_ptr(&base->enum_data.cases, 0);
	mu_assert_eq(cas->val, 1, "Incorrect value for enum case");
	mu_assert_streq(cas->name, "firstCase", "Incorrect name for enum case");

	cas = rz_vector_index_ptr(&base->enum_data.cases, 1);
	mu_assert_eq(cas->val, 2, "Incorrect value for enum case");
	mu_assert_streq(cas->name, "secondCase", "Incorrect name for enum case");

	rz_analysis_base_type_free(base);
	rz_analysis_free(analysis);
	mu_end;
}

static bool test_analysis_save_base_type_enum(void) {
	RzAnalysis *analysis = rz_analysis_new();
	mu_assert_notnull(analysis, "Couldn't create new RzAnalysis");
	mu_assert_notnull(analysis->sdb_types, "Couldn't create new RzAnalysis.sdb_types");

	RzAnalysisBaseType *base = rz_analysis_base_type_new(RZ_ANALYSIS_BASE_TYPE_KIND_ENUM);
	base->name = strdup("foo");

	RzAnalysisEnumCase cas = {
		.name = strdup("firstCase"),
		.val = 1
	};
	rz_vector_push(&base->enum_data.cases, &cas);

	cas.name = strdup("secondCase");
	cas.val = 2;
	rz_vector_push(&base->enum_data.cases, &cas);

	rz_analysis_save_base_type(analysis, base);
	rz_analysis_base_type_free(base);

	Sdb *reg = sdb_new0();
	setup_sdb_for_enum(reg);
	assert_sdb_eq(analysis->sdb_types, reg, "save enum type");
	sdb_free(reg);

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_analysis_get_base_type_typedef(void) {
	RzAnalysis *analysis = rz_analysis_new();
	mu_assert_notnull(analysis, "Couldn't create new RzAnalysis");
	mu_assert_notnull(analysis->sdb_types, "Couldn't create new RzAnalysis.sdb_types");

	setup_sdb_for_typedef(analysis->sdb_types);

	RzAnalysisBaseType *base = rz_analysis_get_base_type(analysis, "string");
	mu_assert_notnull(base, "Couldn't create get base type of typedef \"string\"");

	mu_assert_eq(RZ_ANALYSIS_BASE_TYPE_KIND_TYPEDEF, base->kind, "Wrong base type");
	mu_assert_streq(base->name, "string", "type name");
	mu_assert_streq(base->type, "char *", "typedefd type");

	rz_analysis_base_type_free(base);
	rz_analysis_free(analysis);
	mu_end;
}

static bool test_analysis_save_base_type_typedef(void) {
	RzAnalysis *analysis = rz_analysis_new();
	mu_assert_notnull(analysis, "Couldn't create new RzAnalysis");
	mu_assert_notnull(analysis->sdb_types, "Couldn't create new RzAnalysis.sdb_types");

	RzAnalysisBaseType *base = rz_analysis_base_type_new(RZ_ANALYSIS_BASE_TYPE_KIND_TYPEDEF);
	base->name = strdup("string");
	base->type = strdup("char *");

	rz_analysis_save_base_type(analysis, base);
	rz_analysis_base_type_free(base);

	Sdb *reg = sdb_new0();
	setup_sdb_for_typedef(reg);
	assert_sdb_eq(analysis->sdb_types, reg, "save typedef type");
	sdb_free(reg);

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_analysis_get_base_type_atomic(void) {
	RzAnalysis *analysis = rz_analysis_new();
	mu_assert_notnull(analysis, "Couldn't create new RzAnalysis");
	mu_assert_notnull(analysis->sdb_types, "Couldn't create new RzAnalysis.sdb_types");

	setup_sdb_for_atomic(analysis->sdb_types);

	RzAnalysisBaseType *base = rz_analysis_get_base_type(analysis, "char");
	mu_assert_notnull(base, "Couldn't create get base type of atomic type \"char\"");

	mu_assert_eq(RZ_ANALYSIS_BASE_TYPE_KIND_ATOMIC, base->kind, "Wrong base type");
	mu_assert_streq(base->name, "char", "type name");
	mu_assert_streq(base->type, "c", "atomic type type");
	mu_assert_eq(base->size, 8, "atomic type size");

	rz_analysis_base_type_free(base);
	rz_analysis_free(analysis);
	mu_end;
}

static bool test_analysis_save_base_type_atomic(void) {
	RzAnalysis *analysis = rz_analysis_new();
	mu_assert_notnull(analysis, "Couldn't create new RzAnalysis");
	mu_assert_notnull(analysis->sdb_types, "Couldn't create new RzAnalysis.sdb_types");

	RzAnalysisBaseType *base = rz_analysis_base_type_new(RZ_ANALYSIS_BASE_TYPE_KIND_ATOMIC);
	base->name = strdup("char");
	base->type = strdup("c");
	base->size = 8;

	rz_analysis_save_base_type(analysis, base);
	rz_analysis_base_type_free(base);

	Sdb *reg = sdb_new0();
	setup_sdb_for_atomic(reg);
	assert_sdb_eq(analysis->sdb_types, reg, "save atomic type");
	sdb_free(reg);

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_analysis_get_base_type_not_found(void) {
	RzAnalysis *analysis = rz_analysis_new();
	setup_sdb_for_not_found(analysis->sdb_types);

	mu_assert_notnull(analysis, "Couldn't create new RzAnalysis");
	mu_assert_notnull(analysis->sdb_types, "Couldn't create new RzAnalysis.sdb_types");

	RzAnalysisBaseType *base = rz_analysis_get_base_type(analysis, "non_existant23321312___");
	mu_assert_null(base, "Should find nothing");
	base = rz_analysis_get_base_type(analysis, "foo");
	mu_assert_null(base, "Should find nothing");
	base = rz_analysis_get_base_type(analysis, "bar");
	mu_assert_null(base, "Should find nothing");
	base = rz_analysis_get_base_type(analysis, "quax");
	mu_assert_null(base, "Should find nothing");
	base = rz_analysis_get_base_type(analysis, "omega");
	mu_assert_null(base, "Should find nothing");

	rz_analysis_free(analysis);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_analysis_get_base_type_struct);
	mu_run_test(test_analysis_save_base_type_struct);
	mu_run_test(test_analysis_get_base_type_union);
	mu_run_test(test_analysis_save_base_type_union);
	mu_run_test(test_analysis_get_base_type_enum);
	mu_run_test(test_analysis_save_base_type_enum);
	mu_run_test(test_analysis_get_base_type_typedef);
	mu_run_test(test_analysis_save_base_type_typedef);
	mu_run_test(test_analysis_get_base_type_atomic);
	mu_run_test(test_analysis_save_base_type_atomic);
	mu_run_test(test_analysis_get_base_type_not_found);
	return tests_passed != tests_run;
}

mu_main(all_tests)