// SPDX-FileCopyrightText: 2018 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>

#include "test_config.h"
#include "minunit.h"
#include "test_sdb.h"

static void setup_sdb_for_struct(Sdb *res) {
	// td "struct kappa {int bar;int cow;};"
	sdb_set(res, "kappa", "struct");
	sdb_set(res, "struct.kappa", "bar,cow");
	sdb_set(res, "struct.kappa.bar", "int32_t,0,0");
	sdb_set(res, "struct.kappa.cow", "int32_t,4,0");

	sdb_set(res, "lappa", "struct");
	sdb_set(res, "struct.lappa", "bar,cow");
	sdb_set(res, "struct.lappa.bar", "int32_t,0,0");
	sdb_set(res, "struct.lappa.cow", "struct kappa,4,0");
}

static void setup_sdb_for_union(Sdb *res) {
	// td "union kappa {int bar;int cow;};"
	sdb_set(res, "kappa", "union");
	sdb_set(res, "union.kappa", "bar,cow");
	sdb_set(res, "union.kappa.bar", "int32_t,0,0");
	sdb_set(res, "union.kappa.cow", "int32_t,0,0");

	sdb_set(res, "lappa", "union");
	sdb_set(res, "union.lappa", "bar,cow");
	sdb_set(res, "union.lappa.bar", "int32_t,0,0");
	sdb_set(res, "union.lappa.cow", "union kappa,0,0");
}

static void setup_sdb_for_enum(Sdb *res) {
	// td "enum foo { firstCase=1, secondCase=2,};"
	sdb_set(res, "foo", "enum");
	sdb_set(res, "enum.foo", "firstCase,secondCase");
	sdb_set(res, "enum.foo.firstCase", "0x1");
	sdb_set(res, "enum.foo.secondCase", "0x2");
	sdb_set(res, "enum.foo.0x1", "firstCase");
	sdb_set(res, "enum.foo.0x2", "secondCase");
}

static void setup_sdb_for_typedef(Sdb *res) {
	// td "typedef char *string;"
	sdb_set(res, "string", "typedef");
	sdb_set(res, "typedef.string", "char *");
}

static void setup_sdb_for_atomic(Sdb *res) {
	sdb_set(res, "char", "type");
	sdb_set(res, "type.char.size", "8");
	sdb_set(res, "type.char", "c");
}

static void setup_sdb_for_not_found(Sdb *res) {
	// malformed type states
	sdb_set(res, "foo", "enum");
	sdb_set(res, "bar", "struct");
	sdb_set(res, "quax", "union");
	sdb_set(res, "enum.foo", "aa,bb");
	sdb_set(res, "struct.bar", "cc,dd");
	sdb_set(res, "union.quax", "ee,ff");

	sdb_set(res, "omega", "struct");
	sdb_set(res, "struct.omega", "ee,ff,gg");
	sdb_set(res, "struct.omega.ee", "0,1");
	sdb_set(res, "struct.omega.ff", "");
}

static bool test_types_get_base_type_struct(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");

	Sdb *sdb = sdb_new0();
	setup_sdb_for_struct(sdb);
	rz_serialize_types_load(sdb, typedb, NULL);
	sdb_free(sdb);

	RzBaseType *base = rz_type_db_get_base_type(typedb, "kappa");
	mu_assert_notnull(base, "Couldn't create get base type of struct \"kappa\"");

	mu_assert_eq(RZ_BASE_TYPE_KIND_STRUCT, base->kind, "Wrong base type");
	mu_assert_streq(base->name, "kappa", "type name");

	RzTypeStructMember *member;

	member = rz_vector_index_ptr(&base->struct_data.members, 0);
	mu_assert_eq(member->offset, 0, "Incorrect offset for struct member");
	mu_assert_true(rz_type_atomic_str_eq(typedb, member->type, "int32_t"), "Incorrect type for struct member");
	mu_assert_streq(member->name, "bar", "Incorrect name for struct member");

	member = rz_vector_index_ptr(&base->struct_data.members, 1);
	mu_assert_eq(member->offset, 4, "Incorrect offset for struct member");
	mu_assert_true(rz_type_atomic_str_eq(typedb, member->type, "int32_t"), "Incorrect type for struct member");
	mu_assert_streq(member->name, "cow", "Incorrect name for struct member");

	mu_assert_streq_free(rz_type_db_base_type_as_string(typedb, base), "struct kappa { int32_t bar; int32_t cow; }", "Incorrect conversion of struct to string");

	RzBaseType *base2 = rz_type_db_get_base_type(typedb, "lappa");
	mu_assert_notnull(base2, "Couldn't create get base type of struct \"lappa\"");

	mu_assert_eq(RZ_BASE_TYPE_KIND_STRUCT, base2->kind, "Wrong base type");
	mu_assert_streq(base2->name, "lappa", "type name");
	mu_assert_streq_free(rz_type_db_base_type_as_string(typedb, base2), "struct lappa { int32_t bar; struct kappa cow; }", "Incorrect conversion of struct to string");

	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_get_base_type_union(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");

	Sdb *sdb = sdb_new0();
	setup_sdb_for_union(sdb);
	rz_serialize_types_load(sdb, typedb, NULL);
	sdb_free(sdb);

	RzBaseType *base = rz_type_db_get_base_type(typedb, "kappa");
	mu_assert_notnull(base, "Couldn't create get base type of union \"kappa\"");

	mu_assert_eq(RZ_BASE_TYPE_KIND_UNION, base->kind, "Wrong base type");
	mu_assert_streq(base->name, "kappa", "type name");

	RzTypeUnionMember *member;

	member = rz_vector_index_ptr(&base->union_data.members, 0);
	mu_assert_true(rz_type_atomic_str_eq(typedb, member->type, "int32_t"), "Incorrect type for union member");
	mu_assert_streq(member->name, "bar", "Incorrect name for union member");

	member = rz_vector_index_ptr(&base->union_data.members, 1);
	mu_assert_true(rz_type_atomic_str_eq(typedb, member->type, "int32_t"), "Incorrect type for union member");
	mu_assert_streq(member->name, "cow", "Incorrect name for union member");

	mu_assert_streq_free(rz_type_db_base_type_as_string(typedb, base), "union kappa { int32_t bar; int32_t cow; }", "Incorrect conversion of union to string");

	RzBaseType *base2 = rz_type_db_get_base_type(typedb, "lappa");
	mu_assert_notnull(base2, "Couldn't create get base type of union \"lappa\"");
	mu_assert_eq(RZ_BASE_TYPE_KIND_UNION, base2->kind, "Wrong base type");
	mu_assert_streq(base2->name, "lappa", "type name");
	mu_assert_streq_free(rz_type_db_base_type_as_string(typedb, base2), "union lappa { int32_t bar; union kappa cow; }", "Incorrect conversion of union to string");

	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_get_base_type_enum(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");

	Sdb *sdb = sdb_new0();
	setup_sdb_for_enum(sdb);
	rz_serialize_types_load(sdb, typedb, NULL);
	sdb_free(sdb);

	RzBaseType *base = rz_type_db_get_base_type(typedb, "foo");
	mu_assert_notnull(base, "Couldn't create get base type of enum \"foo\"");

	mu_assert_eq(RZ_BASE_TYPE_KIND_ENUM, base->kind, "Wrong base type");
	mu_assert_streq(base->name, "foo", "type name");

	RzTypeEnumCase *cas = rz_vector_index_ptr(&base->enum_data.cases, 0);
	mu_assert_eq(cas->val, 1, "Incorrect value for enum case");
	mu_assert_streq(cas->name, "firstCase", "Incorrect name for enum case");

	cas = rz_vector_index_ptr(&base->enum_data.cases, 1);
	mu_assert_eq(cas->val, 2, "Incorrect value for enum case");
	mu_assert_streq(cas->name, "secondCase", "Incorrect name for enum case");

	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_get_base_type_typedef(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");

	Sdb *sdb = sdb_new0();
	setup_sdb_for_typedef(sdb);
	rz_serialize_types_load(sdb, typedb, NULL);
	sdb_free(sdb);

	RzBaseType *base = rz_type_db_get_base_type(typedb, "string");
	mu_assert_notnull(base, "Couldn't create get base type of typedef \"string\"");

	mu_assert_eq(RZ_BASE_TYPE_KIND_TYPEDEF, base->kind, "Wrong base type");
	mu_assert_streq(base->name, "string", "type name");
	mu_assert_eq(base->type->kind, RZ_TYPE_KIND_POINTER, "typedefd type");
	mu_assert_false(base->type->pointer.is_const, "typedefd type");
	mu_assert_true(rz_type_atomic_str_eq(typedb, base->type->pointer.type, "char"), "typedefd type");

	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_get_base_type_atomic(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");

	Sdb *sdb = sdb_new0();
	setup_sdb_for_atomic(sdb);
	rz_serialize_types_load(sdb, typedb, NULL);
	sdb_free(sdb);

	RzBaseType *base = rz_type_db_get_base_type(typedb, "char");
	mu_assert_notnull(base, "Couldn't create get base type of atomic type \"char\"");

	mu_assert_eq(RZ_BASE_TYPE_KIND_ATOMIC, base->kind, "Wrong base type");
	mu_assert_streq(base->name, "char", "type name");
	mu_assert_eq(base->size, 8, "atomic type size");

	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_get_base_type_not_found(void) {
	RzTypeDB *typedb = rz_type_db_new();

	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");

	Sdb *sdb = sdb_new0();
	setup_sdb_for_not_found(sdb);
	rz_serialize_types_load(sdb, typedb, NULL);
	sdb_free(sdb);

	RzBaseType *base = rz_type_db_get_base_type(typedb, "non_existant23321312___");
	mu_assert_null(base, "Should find nothing");
	base = rz_type_db_get_base_type(typedb, "foo");
	mu_assert_null(base, "Should find nothing");
	base = rz_type_db_get_base_type(typedb, "bar");
	mu_assert_null(base, "Should find nothing");
	base = rz_type_db_get_base_type(typedb, "quax");
	mu_assert_null(base, "Should find nothing");
	base = rz_type_db_get_base_type(typedb, "omega");
	mu_assert_null(base, "Should find nothing");

	rz_type_db_free(typedb);
	mu_end;
}

static void setup_sdb_for_base_types_all(Sdb *res) {
	// td "struct kappa {int bar;int cow;};"
	sdb_set(res, "kappa", "struct");
	sdb_set(res, "struct.kappa", "bar,cow");
	sdb_set(res, "struct.kappa.bar", "int32_t,0,0");
	sdb_set(res, "struct.kappa.cow", "int32_t,4,0");
	// td "struct theta {long foo;double *bar[5];};"
	sdb_set(res, "theta", "struct");
	sdb_set(res, "struct.theta", "foo,bar");
	sdb_set(res, "struct.theta.foo", "int64_t,0,0");
	sdb_set(res, "struct.theta.bar", "double *,8,5");
	// td "union omega {int bar;int cow;};"
	sdb_set(res, "omega", "union");
	sdb_set(res, "union.omega", "bar,cow");
	sdb_set(res, "union.omega.bar", "int32_t,0,0");
	sdb_set(res, "union.omega.cow", "int32_t,0,0");
	// td "union omicron {char foo;float bar;};"
	sdb_set(res, "omicron", "union");
	sdb_set(res, "union.omicron", "foo,bar");
	sdb_set(res, "union.omicron.bar", "float,0,0");
	sdb_set(res, "union.omicron.foo", "char,0,0");
	// td "enum foo { firstCase=1, secondCase=2,};"
	sdb_set(res, "foo", "enum");
	sdb_set(res, "enum.foo", "firstCase,secondCase");
	sdb_set(res, "enum.foo.firstCase", "0x1");
	sdb_set(res, "enum.foo.secondCase", "0x2");
	sdb_set(res, "enum.foo.0x1", "firstCase");
	sdb_set(res, "enum.foo.0x2", "secondCase");
	// td "enum bla { minusFirstCase=0x100, minusSecondCase=0xf000,};"
	sdb_set(res, "bla", "enum");
	sdb_set(res, "enum.bla", "minusFirstCase,minusSecondCase");
	sdb_set(res, "enum.bla.minusFirstCase", "0x100");
	sdb_set(res, "enum.bla.minusSecondCase", "0xf000");
	sdb_set(res, "enum.bla.0x100", "minusFirstCase");
	sdb_set(res, "enum.bla.0xf000", "minusSecondCase");
	// td typedef char *string;
	sdb_set(res, "char", "type");
	sdb_set(res, "type.char.size", "8");
	sdb_set(res, "type.char", "c");
	sdb_set(res, "string", "typedef");
	sdb_set(res, "typedef.string", "char *");
}

// RzBaseType name comparator
static int basetypenamecmp(const void *a, const void *b, void *user) {
	const char *name = (const char *)a;
	const RzBaseType *btype = (const RzBaseType *)b;
	return !(btype->name && !strcmp(name, btype->name));
}

static bool typelist_has(RzList *types, const char *name) {
	return (rz_list_find(types, name, basetypenamecmp, NULL) != NULL);
}

static bool test_types_get_base_types(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");

	Sdb *sdb = sdb_new0();
	setup_sdb_for_base_types_all(sdb);
	rz_serialize_types_load(sdb, typedb, NULL);
	sdb_free(sdb);

	RzList *types = rz_type_db_get_base_types(typedb);
	mu_assert_notnull(types, "Couldn't get list of all base types");
	// Additional are `char`, `int32_t`, `int` as a target for `string` typedef
	mu_assert_eq(rz_list_length(types), 12, "get all base types");
	mu_assert_true(typelist_has(types, "kappa"), "has kappa");
	mu_assert_true(typelist_has(types, "theta"), "has theta");
	mu_assert_true(typelist_has(types, "omega"), "has omega");
	mu_assert_true(typelist_has(types, "omicron"), "has omicron");
	mu_assert_true(typelist_has(types, "foo"), "has foo");
	mu_assert_true(typelist_has(types, "bla"), "has bla");
	mu_assert_true(typelist_has(types, "string"), "has string");

	mu_assert_false(typelist_has(types, "dsgdfg"), "has dsgdfg");

	rz_list_free(types);
	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_get_base_types_of_kind(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");

	Sdb *sdb = sdb_new0();
	setup_sdb_for_base_types_all(sdb);
	rz_serialize_types_load(sdb, typedb, NULL);
	sdb_free(sdb);

	RzList *structs = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_STRUCT);
	mu_assert_notnull(structs, "Couldn't get list of all struct types");
	mu_assert_eq(rz_list_length(structs), 2, "get all struct types");
	mu_assert_true(typelist_has(structs, "kappa"), "has kappa");
	mu_assert_true(typelist_has(structs, "theta"), "has theta");
	rz_list_free(structs);

	RzList *unions = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_UNION);
	mu_assert_notnull(unions, "Couldn't get list of all union types");
	mu_assert_eq(rz_list_length(unions), 2, "get all union types");
	mu_assert_true(typelist_has(unions, "omega"), "has omega");
	mu_assert_true(typelist_has(unions, "omicron"), "has omicron");
	rz_list_free(unions);

	RzList *enums = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_ENUM);
	mu_assert_notnull(enums, "Couldn't get list of all enum types");
	mu_assert_eq(rz_list_length(enums), 2, "get all enum types");
	mu_assert_true(typelist_has(enums, "foo"), "has foo");
	mu_assert_true(typelist_has(enums, "bla"), "has bla");
	rz_list_free(enums);

	RzList *typedefs = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_TYPEDEF);
	mu_assert_notnull(typedefs, "Couldn't get list of all typedefs");
	mu_assert_eq(rz_list_length(typedefs), 1, "get all typedefs");
	mu_assert_true(typelist_has(typedefs, "string"), "has string");
	rz_list_free(typedefs);

	rz_type_db_free(typedb);
	mu_end;
}

static char *test_enum = "enum BLA { FOO = 0x1, BOO, GOO = 0xFFFF }";
static char *test_enum_output = "enum BLA { FOO = 0x1, BOO = 0x2, GOO = 0xffff }";

static bool test_enum_types(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

	char *error_msg = NULL;
	RzType *ttype = rz_type_parse_string_single(typedb->parser, test_enum, &error_msg);
	mu_assert_notnull(ttype, "type parse successfull");
	mu_assert_true(ttype->kind == RZ_TYPE_KIND_IDENTIFIER, "is identifier");
	mu_assert_false(ttype->identifier.is_const, "identifier not const");
	mu_assert_streq(ttype->identifier.name, "BLA", "BLA enum");

	RzBaseType *base = rz_type_db_get_base_type(typedb, "BLA");
	mu_assert_eq(RZ_BASE_TYPE_KIND_ENUM, base->kind, "not enum");
	mu_assert_streq(base->name, "BLA", "type name");
	mu_assert_streq_free(rz_type_db_base_type_as_string(typedb, base), test_enum_output, "enum type as string");

	RzTypeEnumCase *cas;

	cas = rz_vector_index_ptr(&base->enum_data.cases, 0);
	mu_assert_streq(cas->name, "FOO", "Incorrect name for enum case 0");
	mu_assert_eq(cas->val, 1, "Incorrect value for enum case 0");

	cas = rz_vector_index_ptr(&base->enum_data.cases, 1);
	mu_assert_streq(cas->name, "BOO", "Incorrect name for enum case 1");
	mu_assert_eq(cas->val, 2, "Incorrect value for enum case 1");

	cas = rz_vector_index_ptr(&base->enum_data.cases, 2);
	mu_assert_streq(cas->name, "GOO", "Incorrect name for enum case 2");
	mu_assert_eq(cas->val, 0xFFFF, "Incorrect value for enum case 2");

	mu_assert_eq(rz_type_db_base_get_bitsize(typedb, base), 32, "bitsize");

	rz_type_free(ttype);
	rz_type_db_free(typedb);
	mu_end;
}

static bool test_const_types(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

	char *error_msg = NULL;
	// Const identifier but not pointer
	RzType *ttype = rz_type_parse_string_single(typedb->parser, "const char*", &error_msg);
	mu_assert_notnull(ttype, "\"const char*\" type parse successfull");
	mu_assert_true(ttype->kind == RZ_TYPE_KIND_POINTER, "is pointer");
	mu_assert_false(ttype->pointer.is_const, "pointer not const");
	mu_assert_notnull(ttype->pointer.type, "pointer type is not null");
	mu_assert_true(ttype->pointer.type->kind == RZ_TYPE_KIND_IDENTIFIER, "pointer type is identifier");
	mu_assert_true(ttype->pointer.type->identifier.is_const, "identifer is const");
	rz_type_free(ttype);

	// Const pointer but not identifier
	ttype = rz_type_parse_string_single(typedb->parser, "char* const", &error_msg);
	mu_assert_notnull(ttype, "\"const char*\" type parse successfull");
	mu_assert_true(ttype->kind == RZ_TYPE_KIND_POINTER, "is pointer");
	mu_assert_true(ttype->pointer.is_const, "pointer is const");
	mu_assert_notnull(ttype->pointer.type, "pointer type is not null");
	mu_assert_true(ttype->pointer.type->kind == RZ_TYPE_KIND_IDENTIFIER, "pointer type is identifier");
	mu_assert_false(ttype->pointer.type->identifier.is_const, "identifier is not const");
	rz_type_free(ttype);

	// Const pointer and identifier
	ttype = rz_type_parse_string_single(typedb->parser, "const char* const", &error_msg);
	mu_assert_notnull(ttype, "\"const char*\" type parse successfull");
	mu_assert_true(ttype->kind == RZ_TYPE_KIND_POINTER, "is pointer");
	mu_assert_true(ttype->pointer.is_const, "pointer is const");
	mu_assert_notnull(ttype->pointer.type, "pointer type is not null");
	mu_assert_true(ttype->pointer.type->kind == RZ_TYPE_KIND_IDENTIFIER, "pointer type is identifier");
	mu_assert_true(ttype->pointer.type->identifier.is_const, "identifier is const");
	rz_type_free(ttype);

	rz_type_db_free(typedb);
	mu_end;
}

static char *array = "int a[65][5][0]";
static char *array_exp1 = "int [65][5][0]";
static char *array_ptr = "int * const *a[][][][9]";
static char *array_ptr_exp1 = "int * const *[0][0][0][9]";
static char *array_ptr_exp2 = "int * const *a[0][0][0][9]";
static char *struct_array_ptr = "struct alb { const char *b; int * const *a[][][][9]; }";
static char *struct_array_ptr_exp1 = "struct alb";
static char *struct_array_ptr_exp2 = "struct alb { const char *b; int * const *a[0][0][0][9]; }";
static char *struct_array_ptr_exp3 = "struct alb a";

static bool test_type_as_string(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

	char *error_msg = NULL;
	RzType *ttype = rz_type_parse_string_single(typedb->parser, array, &error_msg);
	mu_assert_notnull(ttype, "array type parse successfull");
	mu_assert_true(ttype->kind == RZ_TYPE_KIND_ARRAY, "is array");

	char *array_str1 = rz_type_as_string(typedb, ttype);
	char *array_str2 = rz_type_declaration_as_string(typedb, ttype);
	char *array_str3 = rz_type_identifier_declaration_as_string(typedb, ttype, "a");
	mu_assert_streq_free(array_str1, array_exp1, "rz_type_as_string");
	mu_assert_streq_free(array_str2, array_exp1, "rz_type_declaration_as_string");
	mu_assert_streq_free(array_str3, array, "rz_type_identifier_declaration_as_string");
	rz_type_free(ttype);

	ttype = rz_type_parse_string_single(typedb->parser, array_ptr, &error_msg);
	mu_assert_notnull(ttype, "array type parse successfull");
	mu_assert_true(ttype->kind == RZ_TYPE_KIND_ARRAY, "is array");

	array_str1 = rz_type_as_string(typedb, ttype);
	array_str2 = rz_type_declaration_as_string(typedb, ttype);
	array_str3 = rz_type_identifier_declaration_as_string(typedb, ttype, "a");
	mu_assert_streq_free(array_str1, array_ptr_exp1, "rz_type_as_string");
	mu_assert_streq_free(array_str2, array_ptr_exp1, "rz_type_declaration_as_string");
	mu_assert_streq_free(array_str3, array_ptr_exp2, "rz_type_identifier_declaration_as_string");
	rz_type_free(ttype);

	ttype = rz_type_parse_string_single(typedb->parser, struct_array_ptr, &error_msg);
	mu_assert_notnull(ttype, "struct type parse successfull");

	array_str1 = rz_type_as_string(typedb, ttype);
	array_str2 = rz_type_declaration_as_string(typedb, ttype);
	array_str3 = rz_type_identifier_declaration_as_string(typedb, ttype, "a");
	mu_assert_streq_free(array_str1, struct_array_ptr_exp1, "rz_type_as_string");
	mu_assert_streq_free(array_str2, struct_array_ptr_exp2, "rz_type_declaration_as_string");
	mu_assert_streq_free(array_str3, struct_array_ptr_exp3, "rz_type_identifier_declaration_as_string");
	rz_type_free(ttype);

	rz_type_db_free(typedb);
	mu_end;
}

static char *pretty_complex_const_pointer = "const char ** const * const c[4];";
static char *pretty_struct_array_ptr_func_ptr = "struct alb { const char *b; int * const *a[][][][9]; wchar_t (*funk)(int a, const char *b); time_t t; };";
static char *pretty_struct_array_ptr_func_ptr_multiline = "struct alb {\n"
							  "\tconst char *b;\n"
							  "\tint * const *a[][][][9];\n"
							  "\twchar_t (*funk)(int a, const char *b);\n"
							  "\ttime_t t;\n"
							  "} leet;";
static char *pretty_struct_in_struct = "struct joy { int a; char c; struct alb ania; int j; };";
static char *pretty_struct_in_struct_multiline = "struct joy {\n"
						 "\tint a;\n"
						 "\tchar c;\n"
						 "\tstruct alb ania;\n"
						 "\tint j;\n"
						 "} mult;";
static char *pretty_struct_in_struct_multiline_unfold = "struct joy {\n"
							"\tint a;\n"
							"\tchar c;\n"
							"\tstruct alb {\n"
							"\t\tconst char *b;\n"
							"\t\tint * const *a[][][][9];\n"
							"\t\twchar_t (*funk)(int a, const char *b);\n"
							"\t\ttime_t t;\n"
							"\t} ania;\n"
							"\tint j;\n"
							"} multunfold;";
static char *pretty_union_of_struct = "union alpha { struct joy bla; struct { int foo; char bar; } baz; };";
static char *pretty_union_of_struct_multiline1 = "union alpha {\n"
						 "\tstruct joy {\n"
						 "\t\tint a;\n"
						 "\t\tchar c;\n"
						 "\t\tstruct alb ania;\n"
						 "\t\tint j;\n"
						 "\t} bla;\n"
						 "\tstruct {\n"
						 "\t\tint foo;\n"
						 "\t\tchar bar;\n"
						 "\t} baz;\n"
						 "} mult1;";
static char *pretty_union_of_struct_anon_multiline = "union alpha {\n"
						     "\tstruct joy bla;\n"
						     "\tstruct {\n"
						     "\t\tint foo;\n"
						     "\t\tchar bar;\n"
						     "\t} baz;\n"
						     "} anonmult;";
static char *pretty_union_of_struct_max_multiline = "union alpha {\n"
						    "\tstruct joy {\n"
						    "\t\tint a;\n"
						    "\t\tchar c;\n"
						    "\t\tstruct alb {\n"
						    "\t\t\tconst char *b;\n"
						    "\t\t\tint * const *a[][][][9];\n"
						    "\t\t\twchar_t (*funk)(int a, const char *b);\n"
						    "\t\t\ttime_t t;\n"
						    "\t\t} ania;\n"
						    "\t\tint j;\n"
						    "\t} bla;\n"
						    "\tstruct {\n"
						    "\t\tint foo;\n"
						    "\t\tchar bar;\n"
						    "\t} baz;\n"
						    "} maxmult;";
static char *pretty_enum = "enum MCU { IRON = 0x1001, HAWK = 0x337, DOCS = 0x1337, CAPM = 0x2077 };";
static char *pretty_enum_multiline = "enum MCU {\n"
				     "\tIRON = 0x1001,\n"
				     "\tHAWK = 0x337,\n"
				     "\tDOCS = 0x1337,\n"
				     "\tCAPM = 0x2077\n"
				     "} enumult;";
static char *pretty_simple_typedef = "typedef long time_t;";

static bool test_type_as_pretty_string(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

	char *error_msg = NULL;
	RzType *ttype = rz_type_parse_string_single(typedb->parser, pretty_complex_const_pointer, &error_msg);
	mu_assert_notnull(ttype, "complex const pointer type parse unsuccessfull");
	mu_assert_null(error_msg, "parsing errors");
	char *pretty_str = rz_type_as_pretty_string(typedb, ttype, "c", RZ_TYPE_PRINT_NO_OPTS, 1);
	mu_assert_streq(pretty_str, pretty_complex_const_pointer, "complex const pointer type is ugly");
	free(pretty_str);
	rz_type_free(ttype);

	error_msg = NULL;
	ttype = rz_type_parse_string_single(typedb->parser, pretty_struct_array_ptr_func_ptr, &error_msg);
	mu_assert_notnull(ttype, "struct array ptr func ptr type parse unsuccessfull");
	mu_assert_null(error_msg, "parsing errors");
	pretty_str = rz_type_as_pretty_string(typedb, ttype, NULL, RZ_TYPE_PRINT_NO_OPTS, 2); // use unfold level 2 to check whether "over-unfolding" is handled without any problems
	mu_assert_streq(pretty_str, pretty_struct_array_ptr_func_ptr, "struct array ptr func ptr type is ugly");
	free(pretty_str);
	pretty_str = rz_type_as_pretty_string(typedb, ttype, "leet", RZ_TYPE_PRINT_MULTILINE, 1);
	mu_assert_streq(pretty_str, pretty_struct_array_ptr_func_ptr_multiline, "struct array ptr func ptr type multiline is ugly");
	free(pretty_str);
	rz_type_free(ttype);

	error_msg = NULL;
	ttype = rz_type_parse_string_single(typedb->parser, pretty_struct_in_struct, &error_msg);
	mu_assert_notnull(ttype, "struct in struct type parse unsuccessfull");
	mu_assert_null(error_msg, "parsing errors");
	pretty_str = rz_type_as_pretty_string(typedb, ttype, NULL, RZ_TYPE_PRINT_NO_OPTS, 1);
	mu_assert_streq(pretty_str, pretty_struct_in_struct, "struct in struct type is ugly");
	free(pretty_str);
	pretty_str = rz_type_as_pretty_string(typedb, ttype, "mult", RZ_TYPE_PRINT_MULTILINE, 1);
	mu_assert_streq(pretty_str, pretty_struct_in_struct_multiline, "struct in struct type multiline is ugly");
	free(pretty_str);
	pretty_str = rz_type_as_pretty_string(typedb, ttype, "multunfold", RZ_TYPE_PRINT_MULTILINE, 2);
	mu_assert_streq(pretty_str, pretty_struct_in_struct_multiline_unfold, "struct in struct type multiline unfold is ugly");
	free(pretty_str);
	pretty_str = rz_type_as_pretty_string(typedb, ttype, "multunfold", RZ_TYPE_PRINT_MULTILINE, 7);
	mu_assert_streq(pretty_str, pretty_struct_in_struct_multiline_unfold, "struct in struct type multiline 7 unfold is ugly");
	free(pretty_str);
	pretty_str = rz_type_as_pretty_string(typedb, ttype, "multunfold", RZ_TYPE_PRINT_MULTILINE, -1);
	mu_assert_streq(pretty_str, pretty_struct_in_struct_multiline_unfold, "struct in struct type multiline max unfold is ugly");
	free(pretty_str);
	pretty_str = rz_type_as_pretty_string(typedb, ttype, "mult", RZ_TYPE_PRINT_MULTILINE | RZ_TYPE_PRINT_UNFOLD_ANON_ONLY, 5);
	mu_assert_streq(pretty_str, pretty_struct_in_struct_multiline, "struct in struct type multiline anon unfold is ugly");
	free(pretty_str);
	pretty_str = rz_type_as_pretty_string(typedb, ttype, NULL, RZ_TYPE_PRINT_UNFOLD_ANON_ONLY, -1);
	mu_assert_streq(pretty_str, pretty_struct_in_struct, "struct in struct type anon unfold is ugly");
	free(pretty_str);
	rz_type_free(ttype);

	error_msg = NULL;
	ttype = rz_type_parse_string_single(typedb->parser, pretty_union_of_struct, &error_msg);
	mu_assert_notnull(ttype, "union of struct type parse unsuccessfull");
	mu_assert_null(error_msg, "parsing errors");
	pretty_str = rz_type_as_pretty_string(typedb, ttype, NULL, RZ_TYPE_PRINT_UNFOLD_ANON_ONLY, 2);
	mu_assert_streq(pretty_str, pretty_union_of_struct, "union of struct type is ugly");
	free(pretty_str);
	pretty_str = rz_type_as_pretty_string(typedb, ttype, "mult1", RZ_TYPE_PRINT_MULTILINE, 2);
	mu_assert_streq(pretty_str, pretty_union_of_struct_multiline1, "union of struct type multiline 1 is ugly");
	free(pretty_str);
	pretty_str = rz_type_as_pretty_string(typedb, ttype, "anonmult", RZ_TYPE_PRINT_MULTILINE | RZ_TYPE_PRINT_UNFOLD_ANON_ONLY, 10);
	mu_assert_streq(pretty_str, pretty_union_of_struct_anon_multiline, "union of struct type anon multiline is ugly");
	free(pretty_str);
	pretty_str = rz_type_as_pretty_string(typedb, ttype, "maxmult", RZ_TYPE_PRINT_MULTILINE, -3);
	mu_assert_streq(pretty_str, pretty_union_of_struct_max_multiline, "union of struct type max multiline is ugly");
	free(pretty_str);
	rz_type_free(ttype);

	error_msg = NULL;
	ttype = rz_type_parse_string_single(typedb->parser, pretty_enum, &error_msg);
	mu_assert_notnull(ttype, "enum type parse unsuccessfull");
	mu_assert_null(error_msg, "parsing errors");
	pretty_str = rz_type_as_pretty_string(typedb, ttype, NULL, RZ_TYPE_PRINT_NO_OPTS, 10);
	mu_assert_streq(pretty_str, pretty_enum, "enum type is ugly");
	free(pretty_str);
	pretty_str = rz_type_as_pretty_string(typedb, ttype, "enumult", RZ_TYPE_PRINT_MULTILINE, -2);
	mu_assert_streq(pretty_str, pretty_enum_multiline, "enum type multiline is ugly");
	free(pretty_str);
	rz_type_free(ttype);

	error_msg = NULL;
	ttype = rz_type_parse_string_single(typedb->parser, "time_t;", &error_msg);
	mu_assert_notnull(ttype, "simple typedef type parse unsuccessfull");
	mu_assert_null(error_msg, "parsing errors");
	pretty_str = rz_type_as_pretty_string(typedb, ttype, NULL, RZ_TYPE_PRINT_SHOW_TYPEDEF, 10);
	mu_assert_streq(pretty_str, pretty_simple_typedef, "simple typedef type is ugly");
	free(pretty_str);
	rz_type_free(ttype);

	error_msg = NULL;
	ttype = rz_type_parse_string_single(typedb->parser, "non_t existent;", &error_msg);
	mu_assert_notnull(ttype, "unknown type parse unsuccessfull");
	mu_assert_null(error_msg, "parsing errors");
	pretty_str = rz_type_as_pretty_string(typedb, ttype, NULL, RZ_TYPE_PRINT_SHOW_TYPEDEF, 10);
	mu_assert_streq_free(pretty_str, "unknown_t;", "non-existent type in database");
	pretty_str = rz_type_as_pretty_string(typedb, ttype, NULL, RZ_TYPE_PRINT_SHOW_TYPEDEF | RZ_TYPE_PRINT_ALLOW_NON_EXISTENT_BASE_TYPE, 10);
	mu_assert_streq_free(pretty_str, "non_t;", "non-existent type in database");
	rz_type_free(ttype);

	rz_type_db_free(typedb);
	mu_end;
}

static bool test_array_types(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");
	rz_type_db_set_bits(typedb, 64);

	char *error_msg = NULL;
	// Zero-sized array
	RzType *ttype = rz_type_parse_string_single(typedb->parser, "int32_t arr[]", &error_msg);
	mu_assert_notnull(ttype, "\"int32 arr[]\" type parse successfull");
	mu_assert_true(ttype->kind == RZ_TYPE_KIND_ARRAY, "is array");
	mu_assert_eq(ttype->array.count, 0, "zero-sized array");
	mu_assert_notnull(ttype->array.type, "array type is not null");
	mu_assert_true(ttype->array.type->kind == RZ_TYPE_KIND_IDENTIFIER, "array type is identifier");
	mu_assert_streq("int32_t", ttype->array.type->identifier.name, "identifer is \"int32_t\"");
	mu_assert_eq(rz_type_db_get_bitsize(typedb, ttype), 0, "bitsize");
	rz_type_free(ttype);

	// Real-sized array of arrays
	ttype = rz_type_parse_string_single(typedb->parser, "unsigned short [6][7]", &error_msg);
	mu_assert_notnull(ttype, "\"unsigned short arr[6][7]\" type parse successfull");
	mu_assert_true(ttype->kind == RZ_TYPE_KIND_ARRAY, "is array");
	mu_assert_eq(ttype->array.count, 6, "6-sized array");
	mu_assert_notnull(ttype->array.type, "array type is not null");
	mu_assert_true(ttype->array.type->kind == RZ_TYPE_KIND_ARRAY, "array type is array");
	mu_assert_eq(ttype->array.type->array.count, 7, "7-sized array");
	mu_assert_notnull(ttype->array.type->array.type, "array's array type is not null");
	mu_assert_true(ttype->array.type->array.type->kind == RZ_TYPE_KIND_IDENTIFIER, "array's array type is identifier");
	mu_assert_streq("unsigned short", ttype->array.type->array.type->identifier.name, "identifer is \"unsigned short\"");
	mu_assert_eq(rz_type_db_get_bitsize(typedb, ttype), 6 * 7 * 2 * 8, "bitsize");
	rz_type_free(ttype);

	// Real-sized array of pointers
	ttype = rz_type_parse_string_single(typedb->parser, "float * arr[5]", &error_msg);
	mu_assert_notnull(ttype, "\"float * arr[5]\" type parse successfull");
	mu_assert_true(ttype->kind == RZ_TYPE_KIND_ARRAY, "is array");
	mu_assert_eq(ttype->array.count, 5, "real-sized array");
	mu_assert_notnull(ttype->array.type, "array type is not null");
	mu_assert_true(ttype->array.type->kind == RZ_TYPE_KIND_POINTER, "array type is pointer");
	mu_assert_false(ttype->array.type->pointer.is_const, "pointer is not const");
	mu_assert_notnull(ttype->array.type->pointer.type, "pointer type is not null");
	mu_assert_true(ttype->array.type->pointer.type->kind == RZ_TYPE_KIND_IDENTIFIER, "pointer type is identifier");
	mu_assert_false(ttype->array.type->pointer.type->identifier.is_const, "identifer is not const");

	int sz = rz_type_db_get_bitsize(typedb, ttype);
	mu_assert_eq(sz, 8 * 5 * 8, "bitsize");

	mu_assert_streq("float", ttype->array.type->pointer.type->identifier.name, "identifer is \"float\"");
	rz_type_free(ttype);

	rz_type_db_free(typedb);
	mu_end;
}

static char *func_ptr_struct = "struct bla { int a; wchar_t (*func)(int a, const char *b); }";
static char *func_double_ptr_struct = "struct blabla { int a; wchar_t (**funk)(int a, const char *b); }";

static bool test_struct_func_types(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");
	rz_type_db_set_bits(typedb, 64);

	char *error_msg = NULL;
	// Sturcture type with a function pointer
	RzType *ttype = rz_type_parse_string_single(typedb->parser, func_ptr_struct, &error_msg);
	mu_assert_notnull(ttype, "type parse successfull");
	mu_assert_true(ttype->kind == RZ_TYPE_KIND_IDENTIFIER, "is identifier");
	mu_assert_false(ttype->identifier.is_const, "identifier not const");
	mu_assert_streq(ttype->identifier.name, "bla", "bla struct");

	RzBaseType *base = rz_type_db_get_base_type(typedb, "bla");
	mu_assert_eq(RZ_BASE_TYPE_KIND_STRUCT, base->kind, "not struct");
	mu_assert_streq(base->name, "bla", "type name");
	mu_assert_streq_free(rz_type_db_base_type_as_string(typedb, base), func_ptr_struct, "type as string with fcn ptr string");

	RzTypeStructMember *member;

	member = rz_vector_index_ptr(&base->struct_data.members, 0);
	mu_assert_true(rz_type_atomic_str_eq(typedb, member->type, "int"), "Incorrect type for struct member");
	mu_assert_streq(member->name, "a", "Incorrect name for struct member");
	mu_assert_eq(RZ_TYPE_KIND_IDENTIFIER, member->type->kind, "not struct");

	member = rz_vector_index_ptr(&base->struct_data.members, 1);
	mu_assert_streq(member->name, "func", "Incorrect name for struct member");
	mu_assert_eq(RZ_TYPE_KIND_POINTER, member->type->kind, "not function pointer");
	mu_assert_eq(RZ_TYPE_KIND_CALLABLE, member->type->pointer.type->kind, "not function pointer");

	RzCallable *call = member->type->pointer.type->callable;
	mu_assert_streq_free(rz_type_as_string(typedb, call->ret), "wchar_t", "function return type");

	RzCallableArg *arg;
	arg = rz_pvector_at(call->args, 0);
	mu_assert_streq(arg->name, "a", "argument \"a\"");
	mu_assert_streq_free(rz_type_as_string(typedb, arg->type), "int", "argument \"a\" type");

	arg = rz_pvector_at(call->args, 1);
	mu_assert_streq(arg->name, "b", "argument \"b\"");
	mu_assert_streq_free(rz_type_as_string(typedb, arg->type), "const char *", "argument \"b\" type");

	mu_assert_eq(rz_type_db_get_bitsize(typedb, ttype), (4 + 8) * 8, "bitsize");

	rz_type_free(ttype);

	// Structure type with a pointer to a function pointer
	ttype = rz_type_parse_string_single(typedb->parser, func_double_ptr_struct, &error_msg);
	mu_assert_notnull(ttype, "type parse successfull");
	mu_assert_true(ttype->kind == RZ_TYPE_KIND_IDENTIFIER, "is identifier");
	mu_assert_false(ttype->identifier.is_const, "identifier not const");
	mu_assert_streq(ttype->identifier.name, "blabla", "blabla struct");

	base = rz_type_db_get_base_type(typedb, "blabla");
	mu_assert_eq(RZ_BASE_TYPE_KIND_STRUCT, base->kind, "not struct");
	mu_assert_streq(base->name, "blabla", "type name");
	mu_assert_streq_free(rz_type_db_base_type_as_string(typedb, base), func_double_ptr_struct, "type as string with fcn ptr string");

	member = rz_vector_index_ptr(&base->struct_data.members, 0);
	mu_assert_true(rz_type_atomic_str_eq(typedb, member->type, "int"), "Incorrect type for struct member");
	mu_assert_streq(member->name, "a", "Incorrect name for struct member");
	mu_assert_eq(RZ_TYPE_KIND_IDENTIFIER, member->type->kind, "not integer");

	member = rz_vector_index_ptr(&base->struct_data.members, 1);
	mu_assert_streq(member->name, "funk", "Incorrect name for struct member");
	mu_assert_eq(RZ_TYPE_KIND_POINTER, member->type->kind, "not function pointer's pointer");
	mu_assert_eq(RZ_TYPE_KIND_POINTER, member->type->pointer.type->kind, "not function pointer's pointer");
	mu_assert_eq(RZ_TYPE_KIND_CALLABLE, member->type->pointer.type->pointer.type->kind, "not function pointer's pointer");

	call = member->type->pointer.type->pointer.type->callable;
	mu_assert_streq_free(rz_type_as_string(typedb, call->ret), "wchar_t", "function return type");

	arg = rz_pvector_at(call->args, 0);
	mu_assert_streq(arg->name, "a", "argument \"a\"");
	mu_assert_streq_free(rz_type_as_string(typedb, arg->type), "int", "argument \"a\" type");

	arg = rz_pvector_at(call->args, 1);
	mu_assert_streq(arg->name, "b", "argument \"b\"");
	mu_assert_streq_free(rz_type_as_string(typedb, arg->type), "const char *", "argument \"b\" type");

	mu_assert_eq(rz_type_db_get_bitsize(typedb, ttype), (4 + 8) * 8, "bitsize");

	rz_type_free(ttype);
	rz_type_db_free(typedb);
	mu_end;
}

static char *array_struct = "struct albalb { int a[65][5][]; }";
static char *array_struct_test = "struct albalb { int a[65][5][0]; }";
static char *array_ptr_struct = "struct alb { const char *b; int * const *a[][][][9]; }";
static char *array_ptr_struct_test = "struct alb { const char *b; int * const *a[0][0][0][9]; }";

static bool test_struct_array_types(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");
	rz_type_db_set_bits(typedb, 64);

	char *error_msg = NULL;
	// Structure type with a pointer to a function pointer and array
	RzType *ttype = rz_type_parse_string_single(typedb->parser, array_struct, &error_msg);
	mu_assert_notnull(ttype, "type parse successfull");
	mu_assert_true(ttype->kind == RZ_TYPE_KIND_IDENTIFIER, "is identifier");
	mu_assert_false(ttype->identifier.is_const, "identifier not const");
	mu_assert_streq(ttype->identifier.name, "albalb", "albalb struct");
	mu_assert_eq(rz_type_db_get_bitsize(typedb, ttype), 0, "bitsize");
	rz_type_free(ttype);

	RzBaseType *base = rz_type_db_get_base_type(typedb, "albalb");
	mu_assert_eq(RZ_BASE_TYPE_KIND_STRUCT, base->kind, "not struct");
	mu_assert_streq(base->name, "albalb", "type name");
	mu_assert_streq_free(rz_type_db_base_type_as_string(typedb, base), array_struct_test, "type as string with an array");

	RzTypeStructMember *member = rz_vector_index_ptr(&base->struct_data.members, 0);
	mu_assert_streq(member->name, "a", "Incorrect name for struct member");
	mu_assert_eq(RZ_TYPE_KIND_ARRAY, member->type->kind, "not array level 0");
	mu_assert_eq(65, member->type->array.count, "array level 0 size");
	mu_assert_eq(RZ_TYPE_KIND_ARRAY, member->type->array.type->kind, "not array level 1");
	mu_assert_eq(5, member->type->array.type->array.count, "array level 1 size");
	mu_assert_eq(RZ_TYPE_KIND_ARRAY, member->type->array.type->array.type->kind, "not array level 2");
	mu_assert_eq(0, member->type->array.type->array.type->array.count, "array level 2 size");
	mu_assert_eq(RZ_TYPE_KIND_IDENTIFIER, member->type->array.type->array.type->array.type->kind, "not integer");
	mu_assert_true(rz_type_atomic_str_eq(typedb, member->type->array.type->array.type->array.type, "int"), "Incorrect type for struct member");

	// Structure type with a multidimensional array of pointers
	ttype = rz_type_parse_string_single(typedb->parser, array_ptr_struct, &error_msg);
	mu_assert_notnull(ttype, "type parse successfull");
	mu_assert_true(ttype->kind == RZ_TYPE_KIND_IDENTIFIER, "is identifier");
	mu_assert_false(ttype->identifier.is_const, "identifier not const");
	mu_assert_streq(ttype->identifier.name, "alb", "albalb struct");
	mu_assert_eq(rz_type_db_get_bitsize(typedb, ttype), 8 * 8, "bitsize");
	rz_type_free(ttype);

	base = rz_type_db_get_base_type(typedb, "alb");
	mu_assert_eq(RZ_BASE_TYPE_KIND_STRUCT, base->kind, "not struct");
	mu_assert_streq(base->name, "alb", "type name");
	mu_assert_streq_free(rz_type_db_base_type_as_string(typedb, base), array_ptr_struct_test, "type as string with multidimensional array of pointers");

	rz_type_db_free(typedb);
	mu_end;
}

static bool test_struct_identifier_without_specifier(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");
	rz_type_db_set_bits(typedb, 64);

	char *error_msg = NULL;
	int r = rz_type_parse_string(typedb, "struct bla { int a; };", &error_msg);
	mu_assert_eq(r, 0, "parse struct definition");

	// After defining a struct `struct bla` we also want to be able to refer to
	// it by just `bla` rather than `struct bla`

	RzType *ttype = rz_type_parse_string_single(typedb->parser, "bla *", &error_msg);
	mu_assert_notnull(ttype, "type parse successfull");
	mu_assert_eq(ttype->kind, RZ_TYPE_KIND_POINTER, "is pointer");
	mu_assert_notnull(ttype->pointer.type, "pointed type");
	mu_assert_eq(ttype->pointer.type->kind, RZ_TYPE_KIND_IDENTIFIER, "pointing to identifier");
	mu_assert_false(ttype->pointer.type->identifier.is_const, "identifier not const");
	mu_assert_streq(ttype->pointer.type->identifier.name, "bla", "bla struct");
	mu_assert_eq(rz_type_db_get_bitsize(typedb, ttype), 8 * 8, "bitsize");
	mu_assert_eq(rz_type_db_get_bitsize(typedb, ttype->pointer.type), 4 * 8, "bitsize of struct");
	ttype->pointer.type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED; // operations should still work without the specifier
	mu_assert_eq(rz_type_db_get_bitsize(typedb, ttype), 8 * 8, "bitsize");
	mu_assert_eq(rz_type_db_get_bitsize(typedb, ttype->pointer.type), 4 * 8, "bitsize of struct");

	rz_type_free(ttype);

	rz_type_db_free(typedb);
	mu_end;
}

static bool test_union_identifier_without_specifier(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");
	rz_type_db_set_bits(typedb, 64);

	char *error_msg = NULL;
	int r = rz_type_parse_string(typedb, "union bla { int a; };", &error_msg);
	mu_assert_eq(r, 0, "parse union definition");

	// After defining a union `union bla` we also want to be able to refer to
	// it by just `bla` rather than `union bla`

	RzType *ttype = rz_type_parse_string_single(typedb->parser, "bla *", &error_msg);
	mu_assert_notnull(ttype, "type parse successfull");
	mu_assert_eq(ttype->kind, RZ_TYPE_KIND_POINTER, "is pointer");
	mu_assert_notnull(ttype->pointer.type, "pointed type");
	mu_assert_eq(ttype->pointer.type->kind, RZ_TYPE_KIND_IDENTIFIER, "pointing to identifier");
	mu_assert_false(ttype->pointer.type->identifier.is_const, "identifier not const");
	mu_assert_streq(ttype->pointer.type->identifier.name, "bla", "bla union");
	mu_assert_eq(rz_type_db_get_bitsize(typedb, ttype), 8 * 8, "bitsize");
	mu_assert_eq(rz_type_db_get_bitsize(typedb, ttype->pointer.type), 4 * 8, "bitsize of struct");
	ttype->pointer.type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED; // operations should still work without the specifier
	mu_assert_eq(rz_type_db_get_bitsize(typedb, ttype), 8 * 8, "bitsize");
	mu_assert_eq(rz_type_db_get_bitsize(typedb, ttype->pointer.type), 4 * 8, "bitsize of struct");

	rz_type_free(ttype);

	rz_type_db_free(typedb);
	mu_end;
}

static char *edit_array_old = "int a[65][5][0]";
static char *edit_struct_array_ptr_old = "struct alb { const char *b; int * const *a[0][0][0][9]; }";
static char *edit_struct_array_ptr_new = "struct alb { wchar_t * const b; int ***a[8][8][8]; float c; }";

static bool test_edit_types(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

	char *error_msg = NULL;
	RzType *ttype = rz_type_parse_string_single(typedb->parser, edit_array_old, &error_msg);
	mu_assert_notnull(ttype, "array type parse successfull");
	const char *id1 = rz_type_identifier(ttype);
	mu_assert_false(rz_type_db_edit_base_type(typedb, id1, edit_array_old), "edit atomic base type");
	rz_type_free(ttype);

	ttype = rz_type_parse_string_single(typedb->parser, edit_struct_array_ptr_old, &error_msg);
	mu_assert_notnull(ttype, "struct type parse successfull");
	char *struct_str1 = rz_type_declaration_as_string(typedb, ttype);
	mu_assert_streq_free(struct_str1, edit_struct_array_ptr_old, "rz_type_declaration_as_string");
	const char *id2 = rz_type_identifier(ttype);
	mu_assert_true(rz_type_db_edit_base_type(typedb, id2, edit_struct_array_ptr_new), "edit struct base type");
	char *struct_str2 = rz_type_declaration_as_string(typedb, ttype);
	mu_assert_streq_free(struct_str2, edit_struct_array_ptr_new, "rz_type_declaration_as_string (new)");

	rz_type_free(ttype);

	rz_type_db_free(typedb);
	mu_end;
}

/* references */
typedef struct {
	const char *name;
	RZ_REF_TYPE;
} TypeTest;

static TypeTest *rz_type_test_new(const char *name) {
	TypeTest *tt = RZ_NEW0(TypeTest);
	if (tt) {
		rz_ref_init(tt);
		tt->name = name;
	}
	return tt;
}

static void rz_type_test_free(TypeTest *tt) {
	tt->name = "";
}

RZ_REF_FUNCTIONS(TypeTest, rz_type_test);

bool test_references(void) {
	TypeTest *tt = rz_type_test_new("foo");
	mu_assert_eq(tt->refcount, 1, "reference count issue");
	rz_type_test_ref(tt);
	mu_assert_eq(tt->refcount, 2, "reference count issue");
	rz_type_test_unref(tt);
	mu_assert_streq(tt->name, "foo", "typetest name should be foo");
	mu_assert_eq(tt->refcount, 1, "reference count issue");
	rz_type_test_unref(tt); // tt becomes invalid
	mu_assert_eq(tt->refcount, 0, "reference count issue");
	mu_assert_streq(tt->name, "", "typetest name should be foo");
	free(tt);
	mu_end;
}

bool test_addr_bits(void) {
	RzTypeDB *typedb = rz_type_db_new();
	rz_type_db_set_bits(typedb, 32);
	mu_assert_eq(rz_type_db_pointer_size(typedb), 32, "ptr size");
	rz_type_db_set_bits(typedb, 64);
	mu_assert_eq(rz_type_db_pointer_size(typedb), 64, "ptr size");
	rz_type_db_set_address_bits(typedb, 32); // overrided bits
	mu_assert_eq(rz_type_db_pointer_size(typedb), 32, "ptr size");
	rz_type_db_set_bits(typedb, 16);
	mu_assert_eq(rz_type_db_pointer_size(typedb), 32, "ptr size");
	rz_type_db_free(typedb);
	mu_end;
}

bool test_typedef_loop(void) {
	RzTypeDB *typedb = rz_type_db_new();
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

	// Test typedefs with loops. This makes no sense in practice, but
	// it is hard to guarantee that it will never happen.
	//
	// Test case:
	//
	// La --> Te --> Ra --> Lus
	//        ^               |
	//        |               |
	//        \_______________/

	RzBaseType *btype = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
	btype->name = strdup("Lus");
	btype->type = RZ_NEW0(RzType);
	btype->type->kind = RZ_TYPE_KIND_IDENTIFIER;
	btype->type->identifier.name = strdup("Te");
	rz_type_db_save_base_type(typedb, btype);
	RzBaseType *prev = btype;

	btype = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
	btype->name = strdup("Ra");
	btype->type = rz_type_identifier_of_base_type(typedb, prev, false);
	rz_type_db_save_base_type(typedb, btype);
	prev = btype;

	btype = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
	btype->name = strdup("Te");
	btype->type = rz_type_identifier_of_base_type(typedb, prev, false);
	rz_type_db_save_base_type(typedb, btype);
	prev = btype;

	btype = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
	btype->name = strdup("La");
	btype->type = rz_type_identifier_of_base_type(typedb, prev, false);
	rz_type_db_save_base_type(typedb, btype);

	RzType *ttype = rz_type_identifier_of_base_type(typedb, btype, false);
	mu_assert_notnull(ttype, "identifier");

	// -- try all kinds of operations that may have issues with the loop created above

	ut64 sz = rz_type_db_base_get_bitsize(typedb, btype);
	mu_assert_eq(sz, 0, "no size");

	char *str = rz_type_as_pretty_string(typedb, ttype, NULL, RZ_TYPE_PRINT_SHOW_TYPEDEF, -1);
	mu_assert_streq_free(str, "typedef Te La;", "pretty str");

	str = rz_base_type_as_format(typedb, btype);
	mu_assert_streq_free(str, "", "format");

	RzList *paths = rz_type_path_by_offset(typedb, ttype, 0, INT_MAX);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	rz_type_free(ttype);

	rz_type_db_free(typedb);
	mu_end;
}

static void struct_union_add_member(RzTypeDB *typedb, RzBaseType *btype, const char *member_name, RzType *member_type) {
	if (btype->kind == RZ_BASE_TYPE_KIND_STRUCT) {
		RzTypeStructMember *memb = rz_vector_push(&btype->struct_data.members, NULL);
		memb->type = member_type;
		memb->name = strdup(member_name);
		memb->offset = 0;
		memb->size = 0;
	} else { // if (btype->kind == RZ_BASE_TYPE_KIND_UNION)
		RzTypeUnionMember *memb = rz_vector_push(&btype->union_data.members, NULL);
		memb->type = member_type;
		memb->name = strdup(member_name);
		memb->offset = 0;
		memb->size = 0;
	}
}

bool test_struct_union_loop(RzBaseTypeKind kind) {
	mu_assert_true(kind == RZ_BASE_TYPE_KIND_STRUCT || kind == RZ_BASE_TYPE_KIND_UNION, "test param");
	RzTypeDB *typedb = rz_type_db_new();
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

	// Test structs or unions with loops in their members. This makes no sense in practice, but
	// it is hard to guarantee that it will never happen.
	//
	// Test case:
	//
	// La --> Te -typedef+array-> Ra --> Lus
	//        ^                            |
	//        |                            |
	//        \____________________________/

	RzBaseType *la = rz_type_base_type_new(kind);
	la->name = strdup("La");
	rz_type_db_save_base_type(typedb, la);
	RzBaseType *te = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
	te->name = strdup("Te");
	te->type = RZ_NEW0(RzType);
	te->type->kind = RZ_TYPE_KIND_ARRAY;
	te->type->array.count = 3;
	te->type->array.type = RZ_NEW0(RzType);
	te->type->array.type->kind = RZ_TYPE_KIND_IDENTIFIER;
	te->type->array.type->identifier.name = strdup("Ra");
	rz_type_db_save_base_type(typedb, te);
	RzBaseType *ra = rz_type_base_type_new(kind);
	ra->name = strdup("Ra");
	rz_type_db_save_base_type(typedb, ra);
	RzBaseType *lus = rz_type_base_type_new(kind);
	lus->name = strdup("Lus");
	rz_type_db_save_base_type(typedb, lus);

	struct_union_add_member(typedb, la, "member", rz_type_identifier_of_base_type_str(typedb, "Te"));
	struct_union_add_member(typedb, ra, "member", rz_type_identifier_of_base_type_str(typedb, "Lus"));
	struct_union_add_member(typedb, lus, "member", rz_type_identifier_of_base_type_str(typedb, "int"));

	// No loop at this point, still ok

	ut64 sz = rz_type_db_base_get_bitsize(typedb, la);
	mu_assert_eq(sz, 3 * 4 * 8, "size");

	// Now close the loop
	struct_union_add_member(typedb, lus, "closure", rz_type_identifier_of_base_type_str(typedb, "Te"));

	// -- try all kinds of operations that may have issues with the loop created above

	sz = rz_type_db_base_get_bitsize(typedb, la);
	// the actual size returned here is less important than the fact that it does not
	// recurse infinitely.
	mu_assert_eq(sz, 3 * 4 * 8, "size");

	rz_type_db_free(typedb);
	mu_end;
}

bool test_path_by_offset_struct(void) {
	RzTypeDB *typedb = rz_type_db_new();
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

	// -- simple

	char *error_msg = NULL;
	RzType *ttype = rz_type_parse_string_single(typedb->parser, "struct Hello { int a; uint32_t b; };", &error_msg);
	mu_assert_notnull(ttype, "type parse successful");
	mu_assert_eq(ttype->kind, RZ_TYPE_KIND_IDENTIFIER, "parsed type");
	mu_assert_streq(ttype->identifier.name, "Hello", "parsed type");

	RzList *paths = rz_type_path_by_offset(typedb, ttype, 0, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 1, "paths");
	RzTypePath *path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".a", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 2, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 4, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 1, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".b", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "uint32_t", "paths");
	rz_list_free(paths);

	rz_type_free(ttype);

	// -- recursive

	ttype = rz_type_parse_string_single(typedb->parser, "struct World { uint64_t ulu; Hello mulu; int32_t urshak; };", &error_msg);
	mu_assert_notnull(ttype, "type parse successful");
	mu_assert_eq(ttype->kind, RZ_TYPE_KIND_IDENTIFIER, "parsed type");
	mu_assert_streq(ttype->identifier.name, "World", "parsed type");

	paths = rz_type_path_by_offset(typedb, ttype, 0, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 1, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".ulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "uint64_t", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 8, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 2, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".mulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "Hello", "paths");
	path = rz_list_get_n(paths, 1);
	mu_assert_streq(path->path, ".mulu.a", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 10, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 12, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 1, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".mulu.b", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "uint32_t", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 8, 2);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 2, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".mulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "Hello", "paths");
	path = rz_list_get_n(paths, 1);
	mu_assert_streq(path->path, ".mulu.a", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 8, 1);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 1, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".mulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "Hello", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 8, 0);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	rz_type_free(ttype);

	// -- base type

	RzBaseType *btype = rz_type_db_get_base_type(typedb, "World");
	mu_assert_notnull(btype, "get base type");

	paths = rz_base_type_path_by_offset(typedb, btype, 8, 2);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 2, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".mulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "Hello", "paths");
	path = rz_list_get_n(paths, 1);
	mu_assert_streq(path->path, ".mulu.a", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int", "paths");
	rz_list_free(paths);

	paths = rz_base_type_path_by_offset(typedb, btype, 8, 1);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 1, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".mulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "Hello", "paths");
	rz_list_free(paths);

	paths = rz_base_type_path_by_offset(typedb, btype, 8, 0);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	rz_type_db_free(typedb);
	mu_end;
}

bool test_path_by_offset_union(void) {
	RzTypeDB *typedb = rz_type_db_new();
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

	// -- simple

	char *error_msg = NULL;
	RzType *ttype = rz_type_parse_string_single(typedb->parser, "union Card { int fish; uint32_t senf; };", &error_msg);
	mu_assert_notnull(ttype, "type parse successful");
	mu_assert_eq(ttype->kind, RZ_TYPE_KIND_IDENTIFIER, "parsed type");
	mu_assert_streq(ttype->identifier.name, "Card", "parsed type");

	RzList *paths = rz_type_path_by_offset(typedb, ttype, 0, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 2, "paths");
	RzTypePath *path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".fish", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int", "paths");
	path = rz_list_get_n(paths, 1);
	mu_assert_streq(path->path, ".senf", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "uint32_t", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 2, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 4, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	rz_type_free(ttype);

	// -- recursive

	ttype = rz_type_parse_string_single(typedb->parser, "struct Hello { int a; uint32_t b; };", &error_msg);
	mu_assert_notnull(ttype, "type parse successful");
	mu_assert_eq(ttype->kind, RZ_TYPE_KIND_IDENTIFIER, "parsed type");
	mu_assert_streq(ttype->identifier.name, "Hello", "parsed type");
	rz_type_free(ttype);
	ttype = rz_type_parse_string_single(typedb->parser, "union World { uint64_t ulu; Hello mulu; int32_t urshak; };", &error_msg);
	mu_assert_notnull(ttype, "type parse successful");
	mu_assert_eq(ttype->kind, RZ_TYPE_KIND_IDENTIFIER, "parsed type");
	mu_assert_streq(ttype->identifier.name, "World", "parsed type");

	paths = rz_type_path_by_offset(typedb, ttype, 0, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 4, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".ulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "uint64_t", "paths");
	path = rz_list_get_n(paths, 1);
	mu_assert_streq(path->path, ".mulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "Hello", "paths");
	path = rz_list_get_n(paths, 2);
	mu_assert_streq(path->path, ".mulu.a", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int", "paths");
	path = rz_list_get_n(paths, 3);
	mu_assert_streq(path->path, ".urshak", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int32_t", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 8, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 4, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 1, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".mulu.b", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "uint32_t", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 0, 2);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 4, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".ulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "uint64_t", "paths");
	path = rz_list_get_n(paths, 1);
	mu_assert_streq(path->path, ".mulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "Hello", "paths");
	path = rz_list_get_n(paths, 2);
	mu_assert_streq(path->path, ".mulu.a", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int", "paths");
	path = rz_list_get_n(paths, 3);
	mu_assert_streq(path->path, ".urshak", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int32_t", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 0, 1);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 3, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".ulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "uint64_t", "paths");
	path = rz_list_get_n(paths, 1);
	mu_assert_streq(path->path, ".mulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "Hello", "paths");
	path = rz_list_get_n(paths, 2);
	mu_assert_streq(path->path, ".urshak", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int32_t", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 0, 0);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	rz_type_free(ttype);

	// -- base type

	RzBaseType *btype = rz_type_db_get_base_type(typedb, "World");
	mu_assert_notnull(btype, "get base type");

	paths = rz_base_type_path_by_offset(typedb, btype, 0, 2);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 4, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".ulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "uint64_t", "paths");
	path = rz_list_get_n(paths, 1);
	mu_assert_streq(path->path, ".mulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "Hello", "paths");
	path = rz_list_get_n(paths, 2);
	mu_assert_streq(path->path, ".mulu.a", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int", "paths");
	path = rz_list_get_n(paths, 3);
	mu_assert_streq(path->path, ".urshak", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int32_t", "paths");
	rz_list_free(paths);

	paths = rz_base_type_path_by_offset(typedb, btype, 0, 1);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 3, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".ulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "uint64_t", "paths");
	path = rz_list_get_n(paths, 1);
	mu_assert_streq(path->path, ".mulu", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "Hello", "paths");
	path = rz_list_get_n(paths, 2);
	mu_assert_streq(path->path, ".urshak", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int32_t", "paths");
	rz_list_free(paths);

	paths = rz_base_type_path_by_offset(typedb, btype, 0, 0);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	rz_type_db_free(typedb);
	mu_end;
}

bool test_path_by_offset_array(void) {
	RzTypeDB *typedb = rz_type_db_new();
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

	// -- simple

	char *error_msg = NULL;
	RzType *ttype = rz_type_parse_string_single(typedb->parser, "int [5]", &error_msg);
	mu_assert_notnull(ttype, "type parse successful");
	mu_assert_eq(ttype->kind, RZ_TYPE_KIND_ARRAY, "parsed type");

	RzList *paths = rz_type_path_by_offset(typedb, ttype, 0, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 1, "paths");
	RzTypePath *path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, "[0]", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 1, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 4, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 1, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, "[1]", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 16, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 1, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, "[4]", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 19, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 20, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	rz_type_free(ttype);

	// -- recursive

	ttype = rz_type_parse_string_single(typedb->parser, "struct Hello { int a; uint32_t b; };", &error_msg);
	mu_assert_notnull(ttype, "type parse successful");
	mu_assert_eq(ttype->kind, RZ_TYPE_KIND_IDENTIFIER, "parsed type");
	mu_assert_streq(ttype->identifier.name, "Hello", "parsed type");
	rz_type_free(ttype);

	ttype = rz_type_parse_string_single(typedb->parser, "Hello [5]", &error_msg);
	mu_assert_notnull(ttype, "type parse successful");
	mu_assert_eq(ttype->kind, RZ_TYPE_KIND_ARRAY, "parsed type");

	paths = rz_type_path_by_offset(typedb, ttype, 0, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 2, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, "[0]", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "Hello", "paths");
	path = rz_list_get_n(paths, 1);
	mu_assert_streq(path->path, "[0].a", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 12, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 1, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, "[1].b", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "uint32_t", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 0, 2);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 2, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, "[0]", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "Hello", "paths");
	path = rz_list_get_n(paths, 1);
	mu_assert_streq(path->path, "[0].a", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 0, 1);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 1, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, "[0]", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "Hello", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 0, 0);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	rz_type_free(ttype);

	rz_type_db_free(typedb);
	mu_end;
}

bool test_path_by_offset_typedef(void) {
	RzTypeDB *typedb = rz_type_db_new();
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

	char *error_msg = NULL;
	RzType *ttype = rz_type_parse_string_single(typedb->parser, "struct Card { int fish; uint32_t senf; };", &error_msg);
	mu_assert_notnull(ttype, "type parse successful");
	mu_assert_eq(ttype->kind, RZ_TYPE_KIND_IDENTIFIER, "parsed type");
	mu_assert_streq(ttype->identifier.name, "Card", "parsed type");

	RzBaseType *btype = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
	btype->name = strdup("Alias");
	btype->type = RZ_NEW0(RzType);
	btype->type->kind = RZ_TYPE_KIND_IDENTIFIER;
	btype->type->identifier.name = strdup("Card");
	rz_type_db_save_base_type(typedb, btype);

	RzList *paths = rz_type_path_by_offset(typedb, ttype, 0, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 1, "paths");
	RzTypePath *path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".fish", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "int", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 1, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 4, 5);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 1, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".senf", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "uint32_t", "paths");
	rz_list_free(paths);

	// Resolving a typedef should not count as a depth step as we
	// can't observe it in the path.
	paths = rz_type_path_by_offset(typedb, ttype, 4, 1);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 1, "paths");
	path = rz_list_get_n(paths, 0);
	mu_assert_streq(path->path, ".senf", "paths");
	mu_assert_eq(path->typ->kind, RZ_TYPE_KIND_IDENTIFIER, "paths");
	mu_assert_streq(path->typ->identifier.name, "uint32_t", "paths");
	rz_list_free(paths);

	paths = rz_type_path_by_offset(typedb, ttype, 4, 0);
	mu_assert_notnull(paths, "paths");
	mu_assert_eq(rz_list_length(paths), 0, "paths");
	rz_list_free(paths);

	rz_type_free(ttype);

	rz_type_db_free(typedb);
	mu_end;
}

bool test_offset_by_path_struct(void) {
	RzTypeDB *typedb = rz_type_db_new();
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

	char *error_msg = NULL;
	RzType *ttype = rz_type_parse_string_single(typedb->parser, "struct Hello { int32_t a; uint32_t b; };", &error_msg);
	mu_assert_notnull(ttype, "type parse successful");
	mu_assert_eq(ttype->kind, RZ_TYPE_KIND_IDENTIFIER, "parsed type");
	mu_assert_streq(ttype->identifier.name, "Hello", "parsed type");

	RzBaseType *btype = rz_type_get_base_type(typedb, ttype);
	mu_assert_notnull(btype, "btype get successful");
	RzTypeStructMember *memb_it;
	rz_vector_foreach (&btype->struct_data.members, memb_it) {
		if (!strcmp(memb_it->name, "a")) {
			memb_it->offset = 0;
		} else if (!strcmp(memb_it->name, "b")) {
			memb_it->offset = 4;
		}
	}

	long long offset;
	offset = rz_type_offset_by_path(typedb, "Hello.a");
	mu_assert_eq(offset, 0, "offset");
	offset = rz_type_offset_by_path(typedb, "Hello.b");
	mu_assert_eq(offset, 32, "offset");
	rz_type_free(ttype);

	ttype = rz_type_parse_string_single(typedb->parser, "union World { uint64_t ulu; Hello mulu; int32_t urshak; };", &error_msg);
	mu_assert_notnull(ttype, "type parse successful");
	mu_assert_eq(ttype->kind, RZ_TYPE_KIND_IDENTIFIER, "parsed type");
	mu_assert_streq(ttype->identifier.name, "World", "parsed type");

	btype = rz_type_get_base_type(typedb, ttype);
	mu_assert_notnull(btype, "btype get successful");

	offset = rz_type_offset_by_path(typedb, "World.ulu");
	mu_assert_eq(offset, 0, "offset");
	offset = rz_type_offset_by_path(typedb, "World.mulu");
	mu_assert_eq(offset, 0, "offset");
	offset = rz_type_offset_by_path(typedb, "World.urshak");
	mu_assert_eq(offset, 0, "offset");

	offset = rz_type_offset_by_path(typedb, "World.mulu.a");
	mu_assert_eq(offset, 0, "offset");
	offset = rz_type_offset_by_path(typedb, "World.mulu.b");
	mu_assert_eq(offset, 32, "offset");
	rz_type_free(ttype);

	rz_type_db_free(typedb);
	mu_end;
}

bool test_offset_by_path_array(void) {
	RzTypeDB *typedb = rz_type_db_new();
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");
	RzBaseType *btype;
	RzType *ttype;

	char *error_msg = NULL;
	ttype = rz_type_parse_string_single(typedb->parser, "struct Hello { int32_t a; uint32_t b; };", &error_msg);
	mu_assert_notnull(ttype, "type parse successful");
	mu_assert_eq(ttype->kind, RZ_TYPE_KIND_IDENTIFIER, "parsed type");
	mu_assert_streq(ttype->identifier.name, "Hello", "parsed type");

	btype = rz_type_get_base_type(typedb, ttype);
	mu_assert_notnull(btype, "btype get successful");
	RzTypeStructMember *memb_it;
	rz_vector_foreach (&btype->struct_data.members, memb_it) {
		if (!strcmp(memb_it->name, "b")) {
			memb_it->offset = 4;
		}
	}
	btype->size = 64;
	rz_type_free(ttype);

	ttype = rz_type_parse_string_single(typedb->parser, "struct HelloWrap { int32_t a; Hello harr[20]; };", &error_msg);
	mu_assert_notnull(ttype, "type parse successful");
	mu_assert_eq(ttype->kind, RZ_TYPE_KIND_IDENTIFIER, "parsed type");
	mu_assert_streq(ttype->identifier.name, "HelloWrap", "parsed type");

	btype = rz_type_get_base_type(typedb, ttype);
	mu_assert_notnull(btype, "btype get successful");
	rz_vector_foreach (&btype->struct_data.members, memb_it) {
		if (!strcmp(memb_it->name, "harr")) {
			memb_it->offset = 4;
		}
	}

	long long offset;
	offset = rz_type_offset_by_path(typedb, "HelloWrap.harr");
	mu_assert_eq(offset, 4 * 8, "offset HelloWrap.harr");

	eprintf("===\n");
	offset = rz_type_offset_by_path(typedb, "HelloWrap.harr[3]");
	mu_assert_eq(offset, 28 * 8, "offset HelloWrap.harr[3]");

	offset = rz_type_offset_by_path(typedb, "HelloWrap.harr[3].a");
	mu_assert_eq(offset, 28 * 8, "offset HelloWrap.harr[3].a");

	offset = rz_type_offset_by_path(typedb, "HelloWrap.harr[3].b");
	mu_assert_eq(offset, 32 * 8, "offset HelloWrap.harr[3].b");
	rz_type_free(ttype);

	rz_type_db_free(typedb);

	mu_end;
}

bool test_callable_unspecified_parameters(void) {
	RzTypeDB *typedb = rz_type_db_new();
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

	RzCallable *callable = NULL;

	callable = rz_type_func_new(typedb, "test_fn", NULL);
	mu_assert_streq_free(rz_type_callable_as_string(typedb, callable), "void test_fn()", "callable as string");
	callable->has_unspecified_parameters = true;
	mu_assert_streq_free(rz_type_callable_as_string(typedb, callable), "void test_fn(...)", "callable with unspecified_parameters as string");

	callable->has_unspecified_parameters = false;
	RzType *type = rz_type_identifier_of_base_type_str(typedb, "void *");
	RzCallableArg *arg = rz_type_callable_arg_new(typedb, "a", type);
	rz_type_callable_arg_add(callable, arg);
	mu_assert_streq_free(rz_type_callable_as_string(typedb, callable), "void test_fn(void * a)", "callable a arg as string");
	callable->has_unspecified_parameters = true;
	mu_assert_streq_free(rz_type_callable_as_string(typedb, callable), "void test_fn(void * a, ...)", "callable with unspecified_parameters and arg as string");

	rz_type_callable_free(callable);
	rz_type_db_free(typedb);
	mu_end;
}

int all_tests() {
	mu_run_test(test_types_get_base_type_struct);
	mu_run_test(test_types_get_base_type_union);
	mu_run_test(test_types_get_base_type_enum);
	mu_run_test(test_types_get_base_type_typedef);
	mu_run_test(test_types_get_base_type_atomic);
	mu_run_test(test_types_get_base_type_not_found);
	mu_run_test(test_types_get_base_types);
	mu_run_test(test_types_get_base_types_of_kind);
	mu_run_test(test_type_as_string);
	mu_run_test(test_type_as_pretty_string);
	mu_run_test(test_enum_types);
	mu_run_test(test_const_types);
	mu_run_test(test_array_types);
	mu_run_test(test_struct_func_types);
	mu_run_test(test_struct_array_types);
	mu_run_test(test_struct_identifier_without_specifier);
	mu_run_test(test_union_identifier_without_specifier);
	mu_run_test(test_edit_types);
	mu_run_test(test_references);
	mu_run_test(test_addr_bits);
	mu_run_test(test_typedef_loop);
	mu_run_test(test_struct_union_loop, RZ_BASE_TYPE_KIND_STRUCT);
	mu_run_test(test_struct_union_loop, RZ_BASE_TYPE_KIND_UNION);
	mu_run_test(test_path_by_offset_struct);
	mu_run_test(test_path_by_offset_union);
	mu_run_test(test_path_by_offset_array);
	mu_run_test(test_path_by_offset_typedef);
	mu_run_test(test_offset_by_path_struct);
	mu_run_test(test_offset_by_path_array);
	mu_run_test(test_callable_unspecified_parameters);
	return tests_passed != tests_run;
}

mu_main(all_tests)
