// SPDX-FileCopyrightText: 2018 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>

#include "minunit.h"
#include "test_sdb.h"

static void setup_sdb_for_struct(Sdb *res) {
	// td "struct kappa {int bar;int cow;};"
	sdb_set(res, "kappa", "struct", 0);
	sdb_set(res, "struct.kappa", "bar,cow", 0);
	sdb_set(res, "struct.kappa.bar", "int32_t,0,0", 0);
	sdb_set(res, "struct.kappa.cow", "int32_t,4,0", 0);

	sdb_set(res, "lappa", "struct", 0);
	sdb_set(res, "struct.lappa", "bar,cow", 0);
	sdb_set(res, "struct.lappa.bar", "int32_t,0,0", 0);
	sdb_set(res, "struct.lappa.cow", "struct kappa,4,0", 0);
}

static void setup_sdb_for_union(Sdb *res) {
	// td "union kappa {int bar;int cow;};"
	sdb_set(res, "kappa", "union", 0);
	sdb_set(res, "union.kappa", "bar,cow", 0);
	sdb_set(res, "union.kappa.bar", "int32_t,0,0", 0);
	sdb_set(res, "union.kappa.cow", "int32_t,0,0", 0);

	sdb_set(res, "lappa", "union", 0);
	sdb_set(res, "union.lappa", "bar,cow", 0);
	sdb_set(res, "union.lappa.bar", "int32_t,0,0", 0);
	sdb_set(res, "union.lappa.cow", "union kappa,0,0", 0);
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
	// td "typedef char *string;"
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

	mu_assert_streq(rz_type_db_base_type_as_string(typedb, base), "struct kappa { int32_t bar; int32_t cow; }", "Incorrect conversion of struct to string");

	RzBaseType *base2 = rz_type_db_get_base_type(typedb, "lappa");
	mu_assert_notnull(base2, "Couldn't create get base type of struct \"lappa\"");

	mu_assert_eq(RZ_BASE_TYPE_KIND_STRUCT, base2->kind, "Wrong base type");
	mu_assert_streq(base2->name, "lappa", "type name");
	mu_assert_streq(rz_type_db_base_type_as_string(typedb, base2), "struct lappa { int32_t bar; struct kappa cow; }", "Incorrect conversion of struct to string");

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

	mu_assert_streq(rz_type_db_base_type_as_string(typedb, base), "union kappa { int32_t bar; int32_t cow; }", "Incorrect conversion of union to string");

	RzBaseType *base2 = rz_type_db_get_base_type(typedb, "lappa");
	mu_assert_notnull(base2, "Couldn't create get base type of union \"lappa\"");
	mu_assert_eq(RZ_BASE_TYPE_KIND_UNION, base2->kind, "Wrong base type");
	mu_assert_streq(base2->name, "lappa", "type name");
	mu_assert_streq(rz_type_db_base_type_as_string(typedb, base2), "union lappa { int32_t bar; union kappa cow; }", "Incorrect conversion of union to string");

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
	sdb_set(res, "kappa", "struct", 0);
	sdb_set(res, "struct.kappa", "bar,cow", 0);
	sdb_set(res, "struct.kappa.bar", "int32_t,0,0", 0);
	sdb_set(res, "struct.kappa.cow", "int32_t,4,0", 0);
	// td "struct theta {long foo;double *bar[5];};"
	sdb_set(res, "theta", "struct", 0);
	sdb_set(res, "struct.theta", "foo,bar", 0);
	sdb_set(res, "struct.theta.foo", "int64_t,0,0", 0);
	sdb_set(res, "struct.theta.bar", "double *,8,5", 0);
	// td "union omega {int bar;int cow;};"
	sdb_set(res, "omega", "union", 0);
	sdb_set(res, "union.omega", "bar,cow", 0);
	sdb_set(res, "union.omega.bar", "int32_t,0,0", 0);
	sdb_set(res, "union.omega.cow", "int32_t,0,0", 0);
	// td "union omicron {char foo;float bar;};"
	sdb_set(res, "omicron", "union", 0);
	sdb_set(res, "union.omicron", "foo,bar", 0);
	sdb_set(res, "union.omicron.bar", "float,0,0", 0);
	sdb_set(res, "union.omicron.foo", "char,0,0", 0);
	// td "enum foo { firstCase=1, secondCase=2,};"
	sdb_set(res, "foo", "enum", 0);
	sdb_set(res, "enum.foo", "firstCase,secondCase", 0);
	sdb_set(res, "enum.foo.firstCase", "0x1", 0);
	sdb_set(res, "enum.foo.secondCase", "0x2", 0);
	sdb_set(res, "enum.foo.0x1", "firstCase", 0);
	sdb_set(res, "enum.foo.0x2", "secondCase", 0);
	// td "enum bla { minusFirstCase=0x100, minusSecondCase=0xf000,};"
	sdb_set(res, "bla", "enum", 0);
	sdb_set(res, "enum.bla", "minusFirstCase,minusSecondCase", 0);
	sdb_set(res, "enum.bla.minusFirstCase", "0x100", 0);
	sdb_set(res, "enum.bla.minusSecondCase", "0xf000", 0);
	sdb_set(res, "enum.bla.0x100", "minusFirstCase", 0);
	sdb_set(res, "enum.bla.0xf000", "minusSecondCase", 0);
	// td typedef char *string;
	sdb_set(res, "char", "type", 0);
	sdb_set(res, "type.char.size", "8", 0);
	sdb_set(res, "type.char", "c", 0);
	sdb_set(res, "string", "typedef", 0);
	sdb_set(res, "typedef.string", "char *", 0);
}

// RzBaseType name comparator
static int basetypenamecmp(const void *a, const void *b) {
	const char *name = (const char *)a;
	const RzBaseType *btype = (const RzBaseType *)b;
	return !(btype->name && !strcmp(name, btype->name));
}

static bool typelist_has(RzList *types, const char *name) {
	return (rz_list_find(types, name, basetypenamecmp) != NULL);
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
static char *test_enum_output = "enum BLA { FOO = 0x1, BOO = 0x2, GOO = 0xffff, }";

static bool test_enum_types(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");
	const char *dir_prefix = rz_sys_prefix(NULL);
	rz_type_db_init(typedb, dir_prefix, "x86", 64, "linux");

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

	rz_type_free(ttype);
	rz_type_db_free(typedb);
	mu_end;
}

static bool test_const_types(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");
	const char *dir_prefix = rz_sys_prefix(NULL);
	rz_type_db_init(typedb, dir_prefix, "x86", 64, "linux");

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
	const char *dir_prefix = rz_sys_prefix(NULL);
	rz_type_db_init(typedb, dir_prefix, "x86", 64, "linux");

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

static bool test_array_types(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");
	const char *dir_prefix = rz_sys_prefix(NULL);
	rz_type_db_init(typedb, dir_prefix, "x86", 64, "linux");

	char *error_msg = NULL;
	// Zero-sized array
	RzType *ttype = rz_type_parse_string_single(typedb->parser, "int32_t arr[]", &error_msg);
	mu_assert_notnull(ttype, "\"int32 arr[]\" type parse successfull");
	mu_assert_true(ttype->kind == RZ_TYPE_KIND_ARRAY, "is array");
	mu_assert_eq(ttype->array.count, 0, "zero-sized array");
	mu_assert_notnull(ttype->array.type, "array type is not null");
	mu_assert_true(ttype->array.type->kind == RZ_TYPE_KIND_IDENTIFIER, "array type is identifier");
	mu_assert_streq("int32_t", ttype->array.type->identifier.name, "identifer is \"int32_t\"");
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
	const char *dir_prefix = rz_sys_prefix(NULL);
	rz_type_db_init(typedb, dir_prefix, "x86", 64, "linux");

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
	mu_assert_streq(rz_type_as_string(typedb, call->ret), "wchar_t", "function return type");

	RzCallableArg *arg;
	arg = *rz_pvector_index_ptr(call->args, 0);
	mu_assert_streq(arg->name, "a", "argument \"a\"");
	mu_assert_streq_free(rz_type_as_string(typedb, arg->type), "int", "argument \"a\" type");

	arg = *rz_pvector_index_ptr(call->args, 1);
	mu_assert_streq(arg->name, "b", "argument \"b\"");
	mu_assert_streq_free(rz_type_as_string(typedb, arg->type), "const char *", "argument \"b\" type");

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

	arg = *rz_pvector_index_ptr(call->args, 0);
	mu_assert_streq(arg->name, "a", "argument \"a\"");
	mu_assert_streq_free(rz_type_as_string(typedb, arg->type), "int", "argument \"a\" type");

	arg = *rz_pvector_index_ptr(call->args, 1);
	mu_assert_streq(arg->name, "b", "argument \"b\"");
	mu_assert_streq_free(rz_type_as_string(typedb, arg->type), "const char *", "argument \"b\" type");

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
	const char *dir_prefix = rz_sys_prefix(NULL);
	rz_type_db_init(typedb, dir_prefix, "x86", 64, "linux");

	char *error_msg = NULL;
	// Structure type with a pointer to a function pointer and array
	RzType *ttype = rz_type_parse_string_single(typedb->parser, array_struct, &error_msg);
	mu_assert_notnull(ttype, "type parse successfull");
	mu_assert_true(ttype->kind == RZ_TYPE_KIND_IDENTIFIER, "is identifier");
	mu_assert_false(ttype->identifier.is_const, "identifier not const");
	mu_assert_streq(ttype->identifier.name, "albalb", "albalb struct");

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

	base = rz_type_db_get_base_type(typedb, "alb");
	mu_assert_eq(RZ_BASE_TYPE_KIND_STRUCT, base->kind, "not struct");
	mu_assert_streq(base->name, "alb", "type name");
	mu_assert_streq_free(rz_type_db_base_type_as_string(typedb, base), array_ptr_struct_test, "type as string with multidimensional array of pointers");

	rz_type_free(ttype);
	rz_type_db_free(typedb);
	mu_end;
}

static bool test_struct_identifier_without_specifier(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");
	const char *dir_prefix = rz_sys_prefix(NULL);
	rz_type_db_init(typedb, dir_prefix, "x86", 64, "linux");

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

	rz_type_free(ttype);

	rz_type_db_free(typedb);
	mu_end;
}

static bool test_union_identifier_without_specifier(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->types, "Couldn't create new types hashtable");
	const char *dir_prefix = rz_sys_prefix(NULL);
	rz_type_db_init(typedb, dir_prefix, "x86", 64, "linux");

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
	const char *dir_prefix = rz_sys_prefix(NULL);
	rz_type_db_init(typedb, dir_prefix, "x86", 64, "linux");

	char *error_msg = NULL;
	RzType *ttype = rz_type_parse_string_single(typedb->parser, edit_array_old, &error_msg);
	mu_assert_notnull(ttype, "array type parse successfull");
	const char *id1 = rz_type_identifier(ttype);
	mu_assert_false(rz_type_db_edit_base_type(typedb, id1, edit_array_old), "edit atomic base type");

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
	mu_run_test(test_enum_types);
	mu_run_test(test_const_types);
	mu_run_test(test_array_types);
	mu_run_test(test_struct_func_types);
	mu_run_test(test_struct_array_types);
	mu_run_test(test_struct_identifier_without_specifier);
	mu_run_test(test_union_identifier_without_specifier);
	mu_run_test(test_edit_types);
	mu_run_test(test_references);
	return tests_passed != tests_run;
}

mu_main(all_tests)
