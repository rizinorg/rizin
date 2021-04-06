// SPDX-FileCopyrightText: 2018 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>

#include "minunit.h"
#include "test_sdb.h"

static void setup_sdb_for_function(Sdb *res) {
	sdb_set(res, "ExitProcess", "func", 0);
	sdb_set(res, "ReadFile", "func", 0);
	sdb_set(res, "memcpy", "func", 0);
	sdb_set(res, "strchr", "func", 0);
	sdb_set(res, "__stack_chk_fail", "func", 0);
	sdb_set(res, "WSAStartup", "func", 0);
}

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

static bool test_types_get_base_type_struct(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypeDB.sdb_types");

	setup_sdb_for_struct(typedb->sdb_types);

	RzBaseType *base = rz_type_db_get_base_type(typedb, "kappa");
	mu_assert_notnull(base, "Couldn't create get base type of struct \"kappa\"");

	mu_assert_eq(RZ_BASE_TYPE_KIND_STRUCT, base->kind, "Wrong base type");
	mu_assert_streq(base->name, "kappa", "type name");

	RzTypeStructMember *member;

	member = rz_vector_index_ptr(&base->struct_data.members, 0);
	mu_assert_eq(member->offset, 0, "Incorrect offset for struct member");
	mu_assert_streq(member->type, "int32_t", "Incorrect type for struct member");
	mu_assert_streq(member->name, "bar", "Incorrect name for struct member");

	member = rz_vector_index_ptr(&base->struct_data.members, 1);
	mu_assert_eq(member->offset, 4, "Incorrect offset for struct member");
	mu_assert_streq(member->type, "int32_t", "Incorrect type for struct member");
	mu_assert_streq(member->name, "cow", "Incorrect name for struct member");

	rz_type_base_type_free(base);
	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_save_base_type_struct(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypeDB.sdb_types");

	RzBaseType *base = rz_type_base_type_new(RZ_BASE_TYPE_KIND_STRUCT);
	base->name = strdup("kappa");

	RzTypeStructMember member = {
		.offset = 0,
		.type = strdup("int32_t"),
		.name = strdup("bar")
	};
	rz_vector_push(&base->struct_data.members, &member);

	member.offset = 4;
	member.type = strdup("int32_t");
	member.name = strdup("cow");
	rz_vector_push(&base->struct_data.members, &member);

	rz_type_db_save_base_type(typedb, base);
	rz_type_base_type_free(base);

	Sdb *reg = sdb_new0();
	setup_sdb_for_struct(reg);
	assert_sdb_eq(typedb->sdb_types, reg, "save struct type");
	sdb_free(reg);

	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_get_base_type_union(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypeDB.sdb_types");

	setup_sdb_for_union(typedb->sdb_types);

	RzBaseType *base = rz_type_db_get_base_type(typedb, "kappa");
	mu_assert_notnull(base, "Couldn't create get base type of union \"kappa\"");

	mu_assert_eq(RZ_BASE_TYPE_KIND_UNION, base->kind, "Wrong base type");
	mu_assert_streq(base->name, "kappa", "type name");

	RzTypeUnionMember *member;

	member = rz_vector_index_ptr(&base->union_data.members, 0);
	mu_assert_streq(member->type, "int32_t", "Incorrect type for union member");
	mu_assert_streq(member->name, "bar", "Incorrect name for union member");

	member = rz_vector_index_ptr(&base->union_data.members, 1);
	mu_assert_streq(member->type, "int32_t", "Incorrect type for union member");
	mu_assert_streq(member->name, "cow", "Incorrect name for union member");

	rz_type_base_type_free(base);
	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_save_base_type_union(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypeDB.sdb_types");

	RzBaseType *base = rz_type_base_type_new(RZ_BASE_TYPE_KIND_UNION);
	base->name = strdup("kappa");

	RzTypeUnionMember member = {
		.offset = 0,
		.type = strdup("int32_t"),
		.name = strdup("bar")
	};
	rz_vector_push(&base->union_data.members, &member);

	member.offset = 0;
	member.type = strdup("int32_t");
	member.name = strdup("cow");
	rz_vector_push(&base->union_data.members, &member);

	rz_type_db_save_base_type(typedb, base);
	rz_type_base_type_free(base);

	Sdb *reg = sdb_new0();
	setup_sdb_for_union(reg);
	assert_sdb_eq(typedb->sdb_types, reg, "save union type");
	sdb_free(reg);

	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_get_base_type_enum(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypeDB.sdb_types");

	setup_sdb_for_enum(typedb->sdb_types);

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

	rz_type_base_type_free(base);
	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_save_base_type_enum(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypeDB.sdb_types");

	RzBaseType *base = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ENUM);
	base->name = strdup("foo");

	RzTypeEnumCase cas = {
		.name = strdup("firstCase"),
		.val = 1
	};
	rz_vector_push(&base->enum_data.cases, &cas);

	cas.name = strdup("secondCase");
	cas.val = 2;
	rz_vector_push(&base->enum_data.cases, &cas);

	rz_type_db_save_base_type(typedb, base);
	rz_type_base_type_free(base);

	Sdb *reg = sdb_new0();
	setup_sdb_for_enum(reg);
	assert_sdb_eq(typedb->sdb_types, reg, "save enum type");
	sdb_free(reg);

	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_get_base_type_typedef(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypeDB.sdb_types");

	setup_sdb_for_typedef(typedb->sdb_types);

	RzBaseType *base = rz_type_db_get_base_type(typedb, "string");
	mu_assert_notnull(base, "Couldn't create get base type of typedef \"string\"");

	mu_assert_eq(RZ_BASE_TYPE_KIND_TYPEDEF, base->kind, "Wrong base type");
	mu_assert_streq(base->name, "string", "type name");
	mu_assert_streq(base->type, "char *", "typedefd type");

	rz_type_base_type_free(base);
	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_save_base_type_typedef(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypeDB.sdb_types");

	RzBaseType *base = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
	base->name = strdup("string");
	base->type = strdup("char *");

	rz_type_db_save_base_type(typedb, base);
	rz_type_base_type_free(base);

	Sdb *reg = sdb_new0();
	setup_sdb_for_typedef(reg);
	assert_sdb_eq(typedb->sdb_types, reg, "save typedef type");
	sdb_free(reg);

	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_get_base_type_atomic(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypeDB.sdb_types");

	setup_sdb_for_atomic(typedb->sdb_types);

	RzBaseType *base = rz_type_db_get_base_type(typedb, "char");
	mu_assert_notnull(base, "Couldn't create get base type of atomic type \"char\"");

	mu_assert_eq(RZ_BASE_TYPE_KIND_ATOMIC, base->kind, "Wrong base type");
	mu_assert_streq(base->name, "char", "type name");
	mu_assert_streq(base->type, "c", "atomic type type");
	mu_assert_eq(base->size, 8, "atomic type size");

	rz_type_base_type_free(base);
	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_save_base_type_atomic(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypes");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypes.sdb_types");

	RzBaseType *base = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ATOMIC);
	base->name = strdup("char");
	base->type = strdup("c");
	base->size = 8;

	rz_type_db_save_base_type(typedb, base);
	rz_type_base_type_free(base);

	Sdb *reg = sdb_new0();
	setup_sdb_for_atomic(reg);
	assert_sdb_eq(typedb->sdb_types, reg, "save atomic type");
	sdb_free(reg);

	rz_type_db_free(typedb);
	mu_end;
}

static bool test_types_get_base_type_not_found(void) {
	RzTypeDB *typedb = rz_type_db_new();
	setup_sdb_for_not_found(typedb->sdb_types);

	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypeDB.sdb_types");

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

bool test_dll_names(void) {
	RzTypeDB *typedb = rz_type_db_new();
	setup_sdb_for_function(typedb->sdb_types);
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypeDB.sdb_types");

	char *s;

	s = rz_type_func_guess(typedb, "sub.KERNEL32.dll_ExitProcess");
	mu_assert_notnull(s, "dll_ should be ignored");
	mu_assert_streq(s, "ExitProcess", "dll_ should be ignored");
	free(s);

	s = rz_type_func_guess(typedb, "sub.dll_ExitProcess_32");
	mu_assert_notnull(s, "number should be ignored");
	mu_assert_streq(s, "ExitProcess", "number should be ignored");
	free(s);

	s = rz_type_func_guess(typedb, "sym.imp.KERNEL32.dll_ReadFile");
	mu_assert_notnull(s, "dll_ and number should be ignored case 1");
	mu_assert_streq(s, "ReadFile", "dll_ and number should be ignored case 1");
	free(s);

	s = rz_type_func_guess(typedb, "sub.VCRUNTIME14.dll_memcpy");
	mu_assert_notnull(s, "dll_ and number should be ignored case 2");
	mu_assert_streq(s, "memcpy", "dll_ and number should be ignored case 2");
	free(s);

	s = rz_type_func_guess(typedb, "sub.KERNEL32.dll_ExitProcess_32");
	mu_assert_notnull(s, "dll_ and number should be ignored case 3");
	mu_assert_streq(s, "ExitProcess", "dll_ and number should be ignored case 3");
	free(s);

	s = rz_type_func_guess(typedb, "WS2_32.dll_WSAStartup");
	mu_assert_notnull(s, "dll_ and number should be ignored case 4");
	mu_assert_streq(s, "WSAStartup", "dll_ and number should be ignored case 4");
	free(s);

	rz_type_db_free(typedb);
	mu_end;
}

bool test_ignore_prefixes(void) {
	RzTypeDB *typedb = rz_type_db_new();
	setup_sdb_for_function(typedb->sdb_types);
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypeDB.sdb_types");

	char *s;

	s = rz_type_func_guess(typedb, "fcn.KERNEL32.dll_ExitProcess_32");
	mu_assert_null(s, "fcn. names should be ignored");
	free(s);

	s = rz_type_func_guess(typedb, "loc.KERNEL32.dll_ExitProcess_32");
	mu_assert_null(s, "loc. names should be ignored");
	free(s);

	rz_type_db_free(typedb);
	mu_end;
}

bool test_remove_rz_prefixes(void) {
	RzTypeDB *typedb = rz_type_db_new();
	setup_sdb_for_function(typedb->sdb_types);
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypeDB.sdb_types");

	char *s;

	s = rz_type_func_guess(typedb, "sym.imp.ExitProcess");
	mu_assert_notnull(s, "sym.imp should be ignored");
	mu_assert_streq(s, "ExitProcess", "sym.imp should be ignored");
	free(s);

	s = rz_type_func_guess(typedb, "sym.imp.fcn.ExitProcess");
	mu_assert_notnull(s, "sym.imp.fcn should be ignored");
	mu_assert_streq(s, "ExitProcess", "sym.imp.fcn should be ignored");
	free(s);

	s = rz_type_func_guess(typedb, "longprefix.ExitProcess");
	mu_assert_null(s, "prefixes longer than 3 should not be ignored");
	free(s);

	rz_type_db_free(typedb);
	mu_end;
}

bool test_autonames(void) {
	RzTypeDB *typedb = rz_type_db_new();
	setup_sdb_for_function(typedb->sdb_types);
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypeDB.sdb_types");

	char *s;

	s = rz_type_func_guess(typedb, "sub.strchr_123");
	mu_assert_null(s, "function that calls common fcns shouldn't be identified as such");
	free(s);

	s = rz_type_func_guess(typedb, "sub.__strchr_123");
	mu_assert_null(s, "initial _ should not confuse the api");
	free(s);

	s = rz_type_func_guess(typedb, "sub.__stack_chk_fail_740");
	mu_assert_null(s, "initial _ should not confuse the api");
	free(s);

	s = rz_type_func_guess(typedb, "sym.imp.strchr");
	mu_assert_notnull(s, "sym.imp. should be ignored");
	mu_assert_streq(s, "strchr", "strchr should be identified");
	free(s);

	rz_type_db_free(typedb);
	mu_end;
}

bool test_initial_underscore(void) {
	RzTypeDB *typedb = rz_type_db_new();
	setup_sdb_for_function(typedb->sdb_types);
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");
	mu_assert_notnull(typedb->sdb_types, "Couldn't create new RzTypeDB.sdb_types");

	char *s;

	s = rz_type_func_guess(typedb, "sym._strchr");
	mu_assert_notnull(s, "sym._ should be ignored");
	mu_assert_streq(s, "strchr", "strchr should be identified");
	free(s);

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
	mu_run_test(test_types_save_base_type_struct);
	mu_run_test(test_types_get_base_type_union);
	mu_run_test(test_types_save_base_type_union);
	mu_run_test(test_types_get_base_type_enum);
	mu_run_test(test_types_save_base_type_enum);
	mu_run_test(test_types_get_base_type_typedef);
	mu_run_test(test_types_save_base_type_typedef);
	mu_run_test(test_types_get_base_type_atomic);
	mu_run_test(test_types_save_base_type_atomic);
	mu_run_test(test_types_get_base_type_not_found);
	mu_run_test(test_ignore_prefixes);
	mu_run_test(test_remove_rz_prefixes);
	mu_run_test(test_dll_names);
	mu_run_test(test_references);
	mu_run_test(test_autonames);
	mu_run_test(test_initial_underscore);
	return tests_passed != tests_run;
}

mu_main(all_tests)
