// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_list.h>
#include <rz_vector.h>
#include <rz_util/rz_serialize.h>
#include <rz_type.h>
#include <rz_sign.h>
#include "minunit.h"
#include "test_sdb.h"

Sdb *types_ref_db() {
	Sdb *db = sdb_new0();
	sdb_set(db, "snatcher", "union", 0);
	sdb_set(db, "struct.junker.gillian", "char *,0,0", 0);
	sdb_set(db, "junker", "struct", 0);
	sdb_set(db, "typedef.human", "union snatcher", 0);
	sdb_set(db, "union.snatcher.random", "int,0,0", 0);
	sdb_set(db, "human", "typedef", 0);
	sdb_set(db, "struct.junker.seed", "uint64_t,8,0", 0);
	sdb_set(db, "union.snatcher", "random,hajile", 0);
	sdb_set(db, "struct.junker", "gillian,seed", 0);
	sdb_set(db, "union.snatcher.hajile", "uint32_t,0,0", 0);
	sdb_set(db, "badchar", "type", 0);
	sdb_set(db, "type.badchar.size", "16", 0);
	sdb_set(db, "type.badchar", "c", 0);
	sdb_set(db, "enum.mika", "ELIJAH,MODNAR", 0);
	sdb_set(db, "enum.mika.MODNAR", "0x539", 0);
	sdb_set(db, "enum.mika.ELIJAH", "0x2a", 0);
	sdb_set(db, "enum.mika.0x2a", "ELIJAH", 0);
	sdb_set(db, "mika", "enum", 0);
	sdb_set(db, "enum.mika.0x539", "MODNAR", 0);
	return db;
}

bool test_types_save() {
	RzTypeDB *typedb = rz_type_db_new();

	// struct
	RzBaseType *type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_STRUCT);
	type->name = strdup("junker");

	RzTypeStructMember member;
	member.name = strdup("gillian");
	member.offset = 0;
	RzType *mtype = rz_type_parse(typedb->parser, "char *", NULL);
	mu_assert_notnull(mtype, "member type parsing");
	member.type = mtype;
	rz_vector_push(&type->struct_data.members, &member);

	member.name = strdup("seed");
	member.offset = 8;
	mtype = rz_type_parse(typedb->parser, "uint64_t", NULL);
	mu_assert_notnull(mtype, "member type parsing");
	member.type = mtype;
	rz_vector_push(&type->struct_data.members, &member);

	rz_type_db_save_base_type(typedb, type);
	rz_type_base_type_free(type);

	// union
	type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_UNION);
	type->name = strdup("snatcher");

	RzTypeUnionMember mumber;
	mumber.name = strdup("random");
	mumber.offset = 0;
	mtype = rz_type_parse(typedb->parser, "int", NULL);
	mu_assert_notnull(mtype, "member type parsing");
	member.type = mtype;
	rz_vector_push(&type->union_data.members, &mumber);

	mumber.name = strdup("hajile");
	mumber.offset = 0;
	mtype = rz_type_parse(typedb->parser, "uint32_t", NULL);
	mu_assert_notnull(mtype, "member type parsing");
	member.type = mtype;
	rz_vector_push(&type->union_data.members, &mumber);

	rz_type_db_save_base_type(typedb, type);
	rz_type_base_type_free(type);

	// enum
	type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ENUM);
	type->name = strdup("mika");

	RzTypeEnumCase cas;
	cas.name = strdup("ELIJAH");
	cas.val = 42;
	rz_vector_push(&type->enum_data.cases, &cas);

	cas.name = strdup("MODNAR");
	cas.val = 1337;
	rz_vector_push(&type->enum_data.cases, &cas);

	rz_type_db_save_base_type(typedb, type);
	rz_type_base_type_free(type);

	// typedef
	type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
	type->name = strdup("human");
	mtype = rz_type_parse(typedb->parser, "union snatcher", NULL);
	mu_assert_notnull(mtype, "typedef type parsing");
	type->type = mtype;
	rz_type_db_save_base_type(typedb, type);
	rz_type_base_type_free(type);

	// atomic
	type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ATOMIC);
	type->name = strdup("badchar");
	type->size = 16;
	mtype = rz_type_parse(typedb->parser, "c", NULL);
	mu_assert_notnull(mtype, "atomic type parsing");
	type->type = mtype;
	rz_type_db_save_base_type(typedb, type);
	rz_type_base_type_free(type);

	Sdb *db = sdb_new0();
	rz_serialize_types_save(db, typedb);

	Sdb *expected = types_ref_db();
	assert_sdb_eq(db, expected, "types save");
	sdb_free(db);
	sdb_free(expected);
	rz_type_db_free(typedb);
	mu_end;
}

bool test_types_load() {
	RzTypeDB *typedb = rz_type_db_new();
	Sdb *db = types_ref_db();
	bool succ = rz_serialize_types_load(db, typedb, NULL);
	sdb_free(db);
	mu_assert("load success", succ);

	// struct
	RzBaseType *type = rz_type_db_get_base_type(typedb, "junker");
	mu_assert_notnull(type, "get type");
	mu_assert_eq(type->kind, RZ_BASE_TYPE_KIND_STRUCT, "type kind");
	mu_assert_eq(type->struct_data.members.len, 2, "members count");

	RzTypeStructMember *member = rz_vector_index_ptr(&type->struct_data.members, 0);
	mu_assert_streq(member->name, "gillian", "member name");
	mu_assert_eq(member->offset, 0, "member offset");
	mu_assert_eq(member->type->kind, RZ_TYPE_KIND_POINTER, "member type pointer");
	mu_assert_streq(member->type->identifier.name, "char", "member type");

	member = rz_vector_index_ptr(&type->struct_data.members, 1);
	mu_assert_streq(member->name, "seed", "member name");
	mu_assert_eq(member->offset, 8, "member offset");
	mu_assert_eq(member->type->kind, RZ_TYPE_KIND_IDENTIFIER, "member type");
	mu_assert_streq(member->type->identifier.name, "uint64_t", "member type");

	rz_type_base_type_free(type);

	// union
	type = rz_type_db_get_base_type(typedb, "snatcher");
	mu_assert_notnull(type, "get type");
	mu_assert_eq(type->kind, RZ_BASE_TYPE_KIND_UNION, "type kind");
	mu_assert_eq(type->union_data.members.len, 2, "members count");

	RzTypeUnionMember *mumber = rz_vector_index_ptr(&type->union_data.members, 0);
	mu_assert_streq(mumber->name, "random", "member name");
	mu_assert_eq(mumber->type->kind, RZ_TYPE_KIND_IDENTIFIER, "member type");
	mu_assert_streq(mumber->type->identifier.name, "int", "member type");

	mumber = rz_vector_index_ptr(&type->union_data.members, 1);
	mu_assert_streq(mumber->name, "hajile", "member name");
	mu_assert_eq(mumber->type->kind, RZ_TYPE_KIND_IDENTIFIER, "member type");
	mu_assert_streq(mumber->type->identifier.name, "uint32_t", "member type");

	rz_type_base_type_free(type);

	// enum
	type = rz_type_db_get_base_type(typedb, "mika");
	mu_assert_notnull(type, "get type");
	mu_assert_eq(type->kind, RZ_BASE_TYPE_KIND_ENUM, "type kind");
	mu_assert_eq(type->enum_data.cases.len, 2, "cases count");

	RzTypeEnumCase *cas = rz_vector_index_ptr(&type->enum_data.cases, 0);
	mu_assert_streq(cas->name, "ELIJAH", "case name");
	mu_assert_eq(cas->val, 42, "case value");

	cas = rz_vector_index_ptr(&type->enum_data.cases, 1);
	mu_assert_streq(cas->name, "MODNAR", "case name");
	mu_assert_eq(cas->val, 1337, "case value");

	rz_type_base_type_free(type);

	// typedef
	type = rz_type_db_get_base_type(typedb, "human");
	mu_assert_notnull(type, "get type");
	mu_assert_eq(type->kind, RZ_BASE_TYPE_KIND_TYPEDEF, "type kind");
	mu_assert_eq(type->type->kind, RZ_TYPE_KIND_IDENTIFIER, "type identifier kind");
	RzBaseType *btype = rz_type_db_get_base_type(typedb, type->type->identifier.name);
	mu_assert_notnull(btype, "get union type");
	mu_assert_eq(btype->kind, RZ_BASE_TYPE_KIND_UNION, "union type kind");
	rz_type_base_type_free(btype);
	rz_type_base_type_free(type);

	// atomic
	type = rz_type_db_get_base_type(typedb, "badchar");
	mu_assert_notnull(type, "get type");
	mu_assert_eq(type->kind, RZ_BASE_TYPE_KIND_ATOMIC, "type kind");
	mu_assert_eq(type->size, 16, "atomic type size");
	rz_type_base_type_free(type);

	rz_type_db_free(typedb);
	mu_end;
}

int all_tests() {
	mu_run_test(test_types_save);
	mu_run_test(test_types_load);
	return tests_passed != tests_run;
}

mu_main(all_tests)
