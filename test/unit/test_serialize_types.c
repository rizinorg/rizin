// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_list.h>
#include <rz_vector.h>
#include <rz_util/rz_serialize.h>
#include <rz_type.h>
#include <rz_util/rz_path.h>
#include "test_config.h"
#include "minunit.h"
#include "test_sdb.h"

Sdb *types_ref_db() {
	Sdb *db = sdb_new0();
	sdb_set(db, "junker", "struct");
	sdb_set(db, "struct.junker", "gillian,seed");
	sdb_set(db, "struct.junker.gillian", "char *,0,0");
	sdb_set(db, "struct.junker.seed", "uint64_t,8,0");
	sdb_set(db, "snatcher", "union");
	sdb_set(db, "union.snatcher", "random,hajile");
	sdb_set(db, "union.snatcher.random", "int,0,0");
	sdb_set(db, "union.snatcher.hajile", "uint32_t,0,0");
	sdb_set(db, "human", "typedef");
	sdb_set(db, "typedef.human", "union snatcher");
	sdb_set(db, "mika", "enum");
	sdb_set(db, "enum.mika", "ELIJAH,MODNAR");
	sdb_set(db, "enum.mika.MODNAR", "0x539");
	sdb_set(db, "enum.mika.ELIJAH", "0x2a");
	sdb_set(db, "enum.mika.0x2a", "ELIJAH");
	sdb_set(db, "enum.mika.0x539", "MODNAR");
	sdb_set(db, "my_sint_t", "type");
	sdb_set(db, "type.my_sint_t", "d");
	sdb_set(db, "type.my_sint_t.size", "32");
	sdb_set(db, "type.my_sint_t.typeclass", "Signed Integral");
	sdb_set(db, "my_float_t", "type");
	sdb_set(db, "type.my_float_t.size", "16");
	sdb_set(db, "type.my_float_t.typeclass", "Floating");
	return db;
}

bool sdb_has_record(Sdb *db, const char *key, const char *value) {
	const char *result = sdb_get(db, key);
	if (!result) {
		return false;
	}
	return !strcmp(result, value);
}

bool test_types_save() {
	char *error_msg;
	RzTypeDB *typedb = rz_type_db_new();
	rz_type_db_set_cpu(typedb, "x86");
	rz_type_db_set_bits(typedb, 64);
	rz_type_db_set_os(typedb, "linux");
	// Load predefined types
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

	// struct.junker
	RzBaseType *type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_STRUCT);
	type->name = strdup("junker");

	// struct.junker.gillian
	RzTypeStructMember member;
	member.name = strdup("gillian");
	member.offset = 0;
	RzType *mtype = rz_type_parse_string_single(typedb->parser, "char *", &error_msg);
	mu_assert_notnull(mtype, "member type parsing");
	member.type = mtype;
	ut64 gillian_bitsize = rz_type_db_get_bitsize(typedb, mtype);
	mu_assert_eq(gillian_bitsize, 64, "member type size");
	member.size = 0;
	rz_vector_push(&type->struct_data.members, &member);

	// struct.junker.seed
	member.name = strdup("seed");
	member.offset = gillian_bitsize / 8;
	mtype = rz_type_parse_string_single(typedb->parser, "uint64_t", &error_msg);
	mu_assert_notnull(mtype, "member type parsing");
	member.type = mtype;
	mu_assert_eq(rz_type_db_get_bitsize(typedb, mtype), 64, "member type size");
	member.size = 0;
	rz_vector_push(&type->struct_data.members, &member);

	rz_type_db_save_base_type(typedb, type);

	// union.snatcher
	type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_UNION);
	type->name = strdup("snatcher");

	// union.snatcher.random
	RzTypeUnionMember mumber;
	mumber.name = strdup("random");
	mumber.offset = 0;
	mtype = rz_type_parse_string_single(typedb->parser, "int", &error_msg);
	mu_assert_notnull(mtype, "\"random\" member type parsing");
	mumber.type = mtype;
	mumber.size = 0;
	rz_vector_push(&type->union_data.members, &mumber);

	// union.snatcher.hajile
	mumber.name = strdup("hajile");
	mumber.offset = 0;
	mtype = rz_type_parse_string_single(typedb->parser, "uint32_t", &error_msg);
	mu_assert_notnull(mtype, "\"hajile\" member type parsing");
	mumber.type = mtype;
	mumber.size = 0;
	rz_vector_push(&type->union_data.members, &mumber);

	rz_type_db_save_base_type(typedb, type);

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

	// typedef
	type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_TYPEDEF);
	type->name = strdup("human");
	mtype = rz_type_parse_string_single(typedb->parser, "union snatcher", &error_msg);
	mu_assert_notnull(mtype, "typedef type parsing");
	type->type = mtype;
	rz_type_db_save_base_type(typedb, type);

	// atomic
	type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ATOMIC);
	type->name = strdup("my_sint_t");
	type->attrs = RZ_TYPE_TYPECLASS_INTEGRAL_SIGNED;
	type->size = 32;
	rz_type_db_save_base_type(typedb, type);
	rz_type_db_format_set(typedb, "my_sint_t", "d");

	type = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ATOMIC);
	type->name = strdup("my_float_t");
	type->attrs = RZ_TYPE_TYPECLASS_FLOATING;
	type->size = 16;
	rz_type_db_save_base_type(typedb, type);

	Sdb *db = sdb_new0();
	rz_serialize_types_save(db, typedb);

	mu_assert_true(sdb_has_record(db, "snatcher", "union"), "snatcher union");
	mu_assert_true(sdb_has_record(db, "junker", "struct"), "junker struct");
	mu_assert_true(sdb_has_record(db, "struct.junker.gillian", "char *,0,0"), "junker.gillian");
	mu_assert_true(sdb_has_record(db, "typedef.human", "union snatcher"), "typedef human");
	mu_assert_true(sdb_has_record(db, "union.snatcher.random", "int,0,0"), "snatcher.random");
	mu_assert_true(sdb_has_record(db, "human", "typedef"), "human typedef");
	mu_assert_true(sdb_has_record(db, "struct.junker.seed", "uint64_t,8,0"), "junker.seed");
	mu_assert_true(sdb_has_record(db, "union.snatcher", "random,hajile"), "random,hajile");
	mu_assert_true(sdb_has_record(db, "struct.junker", "gillian,seed"), "gillian,seed");
	mu_assert_true(sdb_has_record(db, "union.snatcher.hajile", "uint32_t,0,0"), "snatcher.hajile");
	mu_assert_true(sdb_has_record(db, "mika", "enum"), "mika enum");
	mu_assert_true(sdb_has_record(db, "enum.mika", "ELIJAH,MODNAR"), "enum.mika");
	mu_assert_true(sdb_has_record(db, "enum.mika.MODNAR", "0x539"), "mika.MODNAR");
	mu_assert_true(sdb_has_record(db, "enum.mika.ELIJAH", "0x2a"), "mika.ELIJAH");
	mu_assert_true(sdb_has_record(db, "enum.mika.0x2a", "ELIJAH"), "mika.0x2a");
	mu_assert_true(sdb_has_record(db, "enum.mika.0x539", "MODNAR"), "mika.0x539");
	mu_assert_true(sdb_has_record(db, "my_sint_t", "type"), "atomic type");
	mu_assert_true(sdb_has_record(db, "type.my_sint_t", "d"), "atomic type");
	mu_assert_true(sdb_has_record(db, "type.my_sint_t.size", "32"), "atomic type");
	mu_assert_true(sdb_has_record(db, "type.my_sint_t.typeclass", "Signed Integral"), "atomic type");
	mu_assert_true(sdb_has_record(db, "my_float_t", "type"), "atomic type");
	mu_assert_null(sdb_get(db, "type.my_float_t"), "atomic type");
	mu_assert_true(sdb_has_record(db, "type.my_float_t.size", "16"), "atomic type");
	mu_assert_true(sdb_has_record(db, "type.my_float_t.typeclass", "Floating"), "atomic type");

	sdb_free(db);
	rz_type_db_free(typedb);
	mu_end;
}

bool test_types_load() {
	RzTypeDB *typedb = rz_type_db_new();
	rz_type_db_set_cpu(typedb, "x86");
	rz_type_db_set_bits(typedb, 64);
	rz_type_db_set_os(typedb, "linux");
	// Load predefined types
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

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
	mu_assert_eq(member->type->pointer.type->kind, RZ_TYPE_KIND_IDENTIFIER, "member type pointer kind");
	mu_assert_streq(member->type->pointer.type->identifier.name, "char", "member type");

	member = rz_vector_index_ptr(&type->struct_data.members, 1);
	mu_assert_streq(member->name, "seed", "member name");
	mu_assert_eq(member->offset, 8, "member offset");
	mu_assert_eq(member->type->kind, RZ_TYPE_KIND_IDENTIFIER, "member type");
	mu_assert_streq(member->type->identifier.name, "uint64_t", "member type");

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

	// typedef
	type = rz_type_db_get_base_type(typedb, "human");
	mu_assert_notnull(type, "get type");
	mu_assert_eq(type->kind, RZ_BASE_TYPE_KIND_TYPEDEF, "type kind");
	mu_assert_eq(type->type->kind, RZ_TYPE_KIND_IDENTIFIER, "type identifier kind");
	RzBaseType *btype = rz_type_db_get_base_type(typedb, type->type->identifier.name);
	mu_assert_notnull(btype, "get union type");
	mu_assert_eq(btype->kind, RZ_BASE_TYPE_KIND_UNION, "union type kind");

	// atomic
	type = rz_type_db_get_base_type(typedb, "my_sint_t");
	mu_assert_notnull(type, "get type");
	mu_assert_eq(type->kind, RZ_BASE_TYPE_KIND_ATOMIC, "type kind");
	mu_assert_eq(type->size, 32, "type size");
	mu_assert_eq(rz_base_type_typeclass(typedb, type), RZ_TYPE_TYPECLASS_INTEGRAL_SIGNED, "type typeclass");

	type = rz_type_db_get_base_type(typedb, "my_float_t");
	mu_assert_notnull(type, "get type");
	mu_assert_eq(type->kind, RZ_BASE_TYPE_KIND_ATOMIC, "type kind");
	mu_assert_eq(type->size, 16, "type size");
	mu_assert_eq(rz_base_type_typeclass(typedb, type), RZ_TYPE_TYPECLASS_FLOATING, "type typeclass");

	rz_type_db_free(typedb);
	mu_end;
}

bool test_types_load_enum_underlying_forward() {
	// Regression test for the PR #6433 review concern: an enum may fix its
	// underlying type ("enum E : T"), serialized as "enum.<name>.@type". Base
	// types are read from the sdb in an arbitrary (hash) order, so T may not have
	// been loaded yet when the enum is deserialized. The underlying type must be
	// kept as a lazily-resolved identifier (not dropped) and must resolve once the
	// referenced type is available.
	RzTypeDB *typedb = rz_type_db_new();
	rz_type_db_set_cpu(typedb, "x86");
	rz_type_db_set_bits(typedb, 64);
	rz_type_db_set_os(typedb, "linux");
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(typedb, types_dir, "x86", 64, "linux");

	Sdb *db = sdb_new0();
	// An enum whose underlying type is a user typedef defined in the same sdb.
	// Whichever of the two records is deserialized first, the underlying type must
	// end up resolved to the typedef's width.
	sdb_set(db, "narciso", "enum");
	sdb_set(db, "enum.narciso", "GILLIAN,JAMIE");
	sdb_set(db, "enum.narciso.GILLIAN", "0x1");
	sdb_set(db, "enum.narciso.JAMIE", "0x2");
	sdb_set(db, "enum.narciso.0x1", "GILLIAN");
	sdb_set(db, "enum.narciso.0x2", "JAMIE");
	sdb_set(db, "enum.narciso.@type", "metal_gear_t");
	sdb_set(db, "metal_gear_t", "typedef");
	sdb_set(db, "typedef.metal_gear_t", "int64_t");
	// An enum whose underlying type is absent from the sdb entirely: the strongest
	// form of "not loaded yet". The underlying must still be kept as an identifier.
	sdb_set(db, "raiden", "enum");
	sdb_set(db, "enum.raiden", "SNAKE");
	sdb_set(db, "enum.raiden.SNAKE", "0x0");
	sdb_set(db, "enum.raiden.0x0", "SNAKE");
	sdb_set(db, "enum.raiden.@type", "ghost_t");

	mu_assert_true(rz_serialize_types_load(db, typedb, NULL), "types load");

	// enum referencing a typedef present in the same sdb: underlying kept and
	// resolved, independent of the deserialization order of the two records.
	RzBaseType *narciso = rz_type_db_get_base_type(typedb, "narciso");
	mu_assert_notnull(narciso, "narciso loaded");
	mu_assert_eq(narciso->kind, RZ_BASE_TYPE_KIND_ENUM, "narciso is an enum");
	mu_assert_notnull(narciso->type, "narciso keeps its underlying type");
	mu_assert_eq(rz_type_db_get_bitsize(typedb, narciso->type), 64, "underlying resolves to 64-bit");
	mu_assert_eq(rz_type_db_base_get_bitsize(typedb, narciso), 64, "enum sized from its underlying type");

	// enum referencing a type that is not in the sdb at all: the underlying type is
	// still kept as an (as-yet-unresolved) identifier, not dropped.
	RzBaseType *raiden = rz_type_db_get_base_type(typedb, "raiden");
	mu_assert_notnull(raiden, "raiden loaded");
	mu_assert_eq(raiden->kind, RZ_BASE_TYPE_KIND_ENUM, "raiden is an enum");
	mu_assert_notnull(raiden->type, "raiden keeps its underlying type even when unresolved");
	mu_assert_eq(raiden->type->kind, RZ_TYPE_KIND_IDENTIFIER, "underlying kept as identifier");
	mu_assert_streq(raiden->type->identifier.name, "ghost_t", "underlying identifier name kept");

	sdb_free(db);
	rz_type_db_free(typedb);
	mu_end;
}

int all_tests() {
	mu_run_test(test_types_save);
	mu_run_test(test_types_load);
	mu_run_test(test_types_load_enum_underlying_forward);
	return tests_passed != tests_run;
}

mu_main(all_tests)
