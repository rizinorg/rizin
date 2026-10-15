// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_bin.h>
#include <rz_core.h>
#include <rz_pdb.h>
#include <rz_util/rz_path.h>
#include "test_types.h"
#include "../../librz/bin/pdb/pdb.h"
#include "../unit/minunit.h"

bool pdb_info_save_types(RzAnalysis *analysis, const char *file) {
	RzPdb *pdb = rz_bin_pdb_parse_from_file(file);
	if (!pdb) {
		return false;
	}

	RzTypeDB *typedb = rz_analysis_get_type_db(analysis);
	rz_type_db_pdb_load(typedb, pdb);
	rz_bin_pdb_free(pdb);
	return true;
}

#define STREAMS_CHECK(x) \
	mu_assert_notnull(pdb->streams, "NULL streams"); \
	mu_assert_eq(rz_pvector_len(pdb->streams), (x), "Incorrect number of streams");

#define MEMBER_INIT_AND_CHECK_LEN(x) \
	RzPVector *members = rz_bin_pdb_get_type_members(stream, type); \
	mu_assert_notnull(members, "NULL members"); \
	mu_assert_eq(rz_pvector_len(members), (x), "wrong union member count");

bool test_pdb_tpi_cpp(void) {

	RzPdb *pdb = rz_bin_pdb_parse_from_file("bins/pdb/Project1.pdb");
	mu_assert_notnull(pdb, "PDB parse failed.");
	STREAMS_CHECK(50);

	RzPdbTpiStream *stream = pdb->s_tpi;
	mu_assert_notnull(stream, "TPIs stream not found in current PDB");
	mu_assert_eq(stream->header.HeaderSize + stream->header.TypeRecordBytes, 117156, "Wrong TPI size");
	mu_assert_eq(stream->header.TypeIndexBegin, 0x1000, "Wrong beginning index");
	RBIter it;
	RzPdbTpiType *type;
	rz_rbtree_foreach (stream->types, it, type, RzPdbTpiType, rb) {
		mu_assert_notnull(type, "RzPdbTpiType is null in RBTree.");
		if (type->index == 0x1028) {
			mu_assert_eq(type->leaf, LF_PROCEDURE, "Incorrect data type");
			Tpi_LF_Procedure *procedure = type->data;
			RzPdbTpiType *arglist;
			arglist = rz_bin_pdb_get_type_by_index(stream, procedure->arg_list);
			mu_assert_eq(arglist->index, 0x1027, "Wrong type index");
			RzPdbTpiType *return_type;
			return_type = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Procedure *)(type->data))->return_type);
			mu_assert_eq(return_type->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = return_type->data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
		} else if (type->index == 0x1161) {
			mu_assert_eq(type->leaf, LF_POINTER, "Incorrect data type");
		} else if (type->index == 0x1004) {
			mu_assert_eq(type->leaf, LF_STRUCTURE, "Incorrect data type");
			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_true(forward_ref, "Wrong fwdref");
		} else if (type->index == 0x113F) {
			mu_assert_eq(type->leaf, LF_ARRAY, "Incorrect data type");
			RzPdbTpiType *dump;
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->data))->index_type);
			mu_assert_eq(dump->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "uint32_t", "Incorrect return type");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->data))->element_type);
			mu_assert_eq(dump->index, 0x113E, "Wrong element type index");
			ut64 size = rz_bin_pdb_get_type_val(type);
			mu_assert_eq(size, 20, "Wrong array size");
		} else if (type->index == 0x145A) {
			mu_assert_eq(type->leaf, LF_ENUM, "Incorrect data type");
			RzPdbTpiType *dump;
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "EXCEPTION_DEBUGGER_ENUM", "wrong enum name");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Enum *)(type->data))->utype);
			mu_assert_eq(dump->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
			MEMBER_INIT_AND_CHECK_LEN(6);
		} else if (type->index == 0x1414) {
			mu_assert_eq(type->leaf, LF_VTSHAPE, "Incorrect data type");
		} else if (type->index == 0x1421) {
			mu_assert_eq(type->leaf, LF_MODIFIER, "Incorrect data type");
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Modifier *)(type->data))->modified_type);
			mu_assert_eq(stype->index, 0x120F, "Incorrect modified type");
		} else if (type->index == 0x1003) {
			mu_assert_eq(type->leaf, LF_UNION, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "R2_TEST_UNION", "wrong union name");
			MEMBER_INIT_AND_CHECK_LEN(2);
		} else if (type->index == 0x100B) {
			mu_assert_eq(type->leaf, LF_CLASS, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "TEST_CLASS", "wrong class name");
			MEMBER_INIT_AND_CHECK_LEN(2);
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->data))->vshape);
			mu_assert_null(stype, "wrong class vshape");
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->data))->derived);
			mu_assert_null(stype, "wrong class derived");
		} else if (type->index == 0x1258) {
			mu_assert_eq(type->leaf, LF_METHODLIST, "Incorrect data type");
			// Nothing from methodlist is currently being parsed
		} else if (type->index == 0x107A) {
			mu_assert_eq(type->leaf, LF_MFUNCTION, "Incorrect data type");
			RzPdbTpiType *typ;
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->data))->return_type);
			mu_assert_eq(typ->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = typ->data;
			mu_assert_eq(simple_type->size, 1, "Incorrect return type");
			mu_assert_streq(simple_type->type, "bool", "Incorrect return type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->data))->class_type);
			mu_assert_eq(typ->index, 0x1079, "incorrect mfunction class type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->data))->arglist);
			mu_assert_eq(typ->index, 0x1027, "incorrect mfunction arglist");
		} else if (type->index == 0x113F) {
			mu_assert_eq(type->leaf, LF_FIELDLIST, "Incorrect data type");
			MEMBER_INIT_AND_CHECK_LEN(2725);
			void **it;
			int i = 0;
			rz_pvector_foreach (members, it) {
				RzPdbTpiType *t = *it;
				mu_assert_eq(t->leaf, LF_ENUMERATE, "Incorrect data type");
				if (i == 0) {
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(t);
					mu_assert_streq(name, "CV_ALLREG_ERR", "Wrong enum name");
					ut64 value = rz_bin_pdb_get_type_val(t);

					mu_assert_eq(value, 30000, "Wrong enumerate value");
				}
				if (i == 2724) {
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(t);
					mu_assert_streq(name, "CV_AMD64_YMM15D3", "Wrong enum name");
					ut64 value = rz_bin_pdb_get_type_val(t);

					mu_assert_eq(value, 687, "Wrong enumerate value");
				}
				i++;
			}
		} else if (type->index == 0x1231) {
			mu_assert_eq(type->leaf, LF_ARGLIST, "Incorrect data type");
		} else if (type->index == 0x101A) {
			mu_assert_eq(type->leaf, LF_STRUCTURE, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "threadlocaleinfostruct", "Wrong name");
			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_false(forward_ref, "Wrong fwdref");
			MEMBER_INIT_AND_CHECK_LEN(18);
			int i = 0;
			void **it;
			rz_pvector_foreach (members, it) {
				RzPdbTpiType *t = *it;
				if (i == 0) {
					mu_assert_eq(t->leaf, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(t);
					mu_assert_streq(name, "refcount", "Wrong member name");
				}
				if (i == 1) {
					mu_assert_eq(t->leaf, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(t);
					mu_assert_streq(name, "lc_codepage", "Wrong member name");
				}
				if (i == 17) {
					mu_assert_eq(t->leaf, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(t);
					mu_assert_streq(name, "locale_name", "Wrong method name");
				}
				i++;
			}
		}
	}
	rz_bin_pdb_free(pdb);
	mu_end;
}

bool test_pdb_tpi_rust(void) {

	RzPdb *pdb = rz_bin_pdb_parse_from_file("bins/pdb/ghidra_rust_pdb_bug.pdb");
	mu_assert_notnull(pdb, "PDB parse failed.");
	STREAMS_CHECK(88);

	RzPdbTpiStream *stream = pdb->s_tpi;
	mu_assert_notnull(stream, "TPIs stream not found in current PDB");
	mu_assert_eq(stream->header.HeaderSize + stream->header.TypeRecordBytes, 305632, "Wrong TPI size");
	mu_assert_eq(stream->header.TypeIndexBegin, 0x1000, "Wrong beginning index");
	RBIter it;
	RzPdbTpiType *type;

	rz_rbtree_foreach (stream->types, it, type, RzPdbTpiType, rb) {
		if (type->index == 0x101B) {
			mu_assert_eq(type->leaf, LF_PROCEDURE, "Incorrect data type");
			RzPdbTpiType *arglist;
			arglist = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Procedure *)(type->data))->arg_list);
			mu_assert_eq(arglist->index, 0x101A, "Wrong type index");
			RzPdbTpiType *return_type;
			return_type = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Procedure *)(type->data))->return_type);
			mu_assert_eq(return_type->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = return_type->data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
		} else if (type->index == 0x1163) {
			mu_assert_eq(type->leaf, LF_POINTER, "Incorrect data type");
			Tpi_LF_Pointer *pointer = type->data;
			mu_assert_eq(pointer->utype, 0x1162, "Incorrect pointer type");
		} else if (type->index == 0x1005) {
			mu_assert_eq(type->leaf, LF_STRUCTURE, "Incorrect data type");
			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_true(forward_ref, "Wrong fwdref");
		} else if (type->index == 0x114A) {
			mu_assert_eq(type->leaf, LF_ARRAY, "Incorrect data type");
			RzPdbTpiType *dump;
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->data))->index_type);
			mu_assert_eq(dump->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->data;
			mu_assert_eq(simple_type->size, 8, "Incorrect return type");
			mu_assert_streq(simple_type->type, "uint64_t", "Incorrect return type");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->data))->element_type);
			mu_assert_eq(dump->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			simple_type = dump->data;
			mu_assert_eq(simple_type->size, 1, "Incorrect return type");
			mu_assert_streq(simple_type->type, "unsigned char", "Incorrect return type");

			ut64 size = rz_bin_pdb_get_type_val(type);
			mu_assert_eq(size, 16, "Wrong array size");
		} else if (type->index == 0x1FB4) {
			mu_assert_eq(type->leaf, LF_ENUM, "Incorrect data type");
			RzPdbTpiType *dump;
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "ISA_AVAILABILITY", "wrong enum name");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Enum *)(type->data))->utype);
			mu_assert_eq(dump->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
			MEMBER_INIT_AND_CHECK_LEN(10);
		} else if (type->index == 0x1E31) {
			mu_assert_eq(type->leaf, LF_VTSHAPE, "Incorrect data type");
		} else if (type->index == 0x1FB7) {
			mu_assert_eq(type->leaf, LF_MODIFIER, "Incorrect data type");
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Modifier *)(type->data))->modified_type);
			mu_assert_eq(stype->leaf, LF_SIMPLE_TYPE, "Incorrect modified type");
		} else if (type->index == 0x1EA9) {
			mu_assert_eq(type->leaf, LF_CLASS, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "std::bad_typeid", "wrong class name");
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->data))->vshape);
			mu_assert_notnull(stype, "wrong class vshape");
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->data))->derived);
			mu_assert_null(stype, "wrong class derived");
		} else if (type->index == 0x1E27) {
			mu_assert_eq(type->leaf, LF_METHODLIST, "Incorrect data type");
			// Nothing from methodlist is currently being parsed
		} else if (type->index == 0x181C) {
			mu_assert_eq(type->leaf, LF_MFUNCTION, "Incorrect data type");
			RzPdbTpiType *typ;
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->data))->return_type);
			mu_assert_eq(typ->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = typ->data;
			mu_assert_eq(simple_type->size, 0, "Incorrect return type");
			mu_assert_streq(simple_type->type, "void", "Incorrect return type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->data))->class_type);
			mu_assert_eq(typ->index, 0x107F, "incorrect mfunction class type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->data))->arglist);
			mu_assert_eq(typ->index, 0x1000, "incorrect mfunction arglist");
		} else if (type->index == 0x13BF) {
			mu_assert_eq(type->leaf, LF_FIELDLIST, "Incorrect data type");
			// check size
			MEMBER_INIT_AND_CHECK_LEN(3);
			void **it;
			int i = 0;
			rz_pvector_foreach (members, it) {
				RzPdbTpiType *t = *it;
				mu_assert_eq(t->leaf, LF_MEMBER, "Incorrect data type");
				if (i == 0) {
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(t);
					mu_assert_streq(name, "RUST$ENUM$DISR", "Wrong member name");
				}
				if (i == 2) {
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(t);
					mu_assert_streq(name, "__0", "Wrong member name");
				}
				i++;
			}
		} else if (type->index == 0x1164) {
			mu_assert_eq(type->leaf, LF_ARGLIST, "Incorrect data type");
		} else if (type->index == 0x1058) {
			mu_assert_eq(type->leaf, LF_STRUCTURE, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "std::thread::local::fast::Key<core::cell::Cell<core::option::Option<core::ptr::non_null::NonNull<core::task::wake::Context>>>>", "Wrong name");

			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_false(forward_ref, "Wrong fwdref");
			ut64 size = rz_bin_pdb_get_type_val(type);

			mu_assert_eq(size, 24, "Wrong struct size");

			MEMBER_INIT_AND_CHECK_LEN(2);

			int i = 0;
			void **it;
			rz_pvector_foreach (members, it) {
				RzPdbTpiType *t = *it;
				if (i == 0) {
					mu_assert_eq(t->leaf, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(t);
					mu_assert_streq(name, "inner", "Wrong member name");
				}
				if (i == 1) {
					mu_assert_eq(t->leaf, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(t);
					mu_assert_streq(name, "dtor_state", "Wrong member name");
				}
				i++;
			}
		}
	}
	rz_bin_pdb_free(pdb);
	mu_end;
}

bool test_pdb_type_save(void) {
	RzAnalysis *analysis = rz_analysis_new(NULL);
	RzTypeDB *typedb = rz_analysis_get_type_db(analysis);
	const char *sdb_types_path = rz_analysis_get_sdb_types_path(analysis);
	rz_type_db_init(typedb, sdb_types_path, "x86", 32, "windows");

	mu_assert_true(pdb_info_save_types(analysis, "bins/pdb/Project1.pdb"), "pdb parsing failed");

	// Check the enum presence and validity
	RzBaseType *test_enum = rz_type_db_get_base_type(typedb, "R2_TEST_ENUM");
	mu_assert_notnull(test_enum, "NULL type");
	mu_assert_eq(test_enum->kind, RZ_BASE_TYPE_KIND_ENUM, "R2_TEST_ENUM is enum");
	mu_assert_true(has_enum_val(test_enum, "eENUM1_R2", 0x10), "eNUM1_R2 = 0x10");
	mu_assert_true(has_enum_val(test_enum, "eENUM2_R2", 0x20), "eNUM2_R2 = 0x20");
	mu_assert_true(has_enum_val(test_enum, "eENUM_R2_MAX", 0x21), "eNUM2_R2 = 0x21");

	mu_assert_false(has_enum_case(test_enum, "no_case"), "no such enum case");

	// Check the union presence and validity
	RzBaseType *test_union = rz_type_db_get_base_type(typedb, "R2_TEST_UNION");
	mu_assert_notnull(test_union, "NULL type");
	mu_assert_eq(test_union->kind, RZ_BASE_TYPE_KIND_UNION, "R2_TEST_UNION is union");
	mu_assert_true(has_union_member(test_union, "r2_union_var_1"), "r2_union_var_1");
	mu_assert_true(has_union_member(test_union, "r2_union_var_2"), "r2_union_var_2");
	// Test member types also
	mu_assert_true(has_union_member_type(typedb, test_union, "r2_union_var_1", "int32_t"), "r2_union_var_1 type");
	mu_assert_true(has_union_member_type(typedb, test_union, "r2_union_var_2", "double"), "rz_union_var_2 type");
	mu_assert_false(has_union_member(test_union, "noSuchMember"), "no such struct member");

	RzBaseType *m64_union = rz_type_db_get_base_type(typedb, "__m64");
	mu_assert_notnull(m64_union, "NULL type");
	mu_assert_eq(m64_union->kind, RZ_BASE_TYPE_KIND_UNION, "__m64 is union");
	mu_assert_true(has_union_member(m64_union, "m64_f32"), "m64_f32");
	mu_assert_true(has_union_member(m64_union, "m64_i8"), "m64_i8");
	mu_assert_true(has_union_member(m64_union, "m64_i16"), "m64_i16");
	mu_assert_true(has_union_member(m64_union, "m64_i32"), "m64_i32");
	mu_assert_true(has_union_member(m64_union, "m64_i64"), "m64_i64");
	mu_assert_true(has_union_member(m64_union, "m64_u8"), "m64_u8");
	mu_assert_true(has_union_member(m64_union, "m64_u16"), "m64_u16");
	mu_assert_true(has_union_member(m64_union, "m64_u32"), "m64_u32");
	mu_assert_true(has_union_member(m64_union, "m64_u64"), "m64_u64");
	// Test member types also
	mu_assert_true(has_union_member_type(typedb, m64_union, "m64_u64", "uint64_t"), "m64_u64 type");
	mu_assert_true(has_union_member_type(typedb, m64_union, "m64_f32", "float [8]"), "m64_f32 type");
	mu_assert_true(has_union_member_type(typedb, m64_union, "m64_i8", "char [8]"), "m64_i8 type");
	mu_assert_true(has_union_member_type(typedb, m64_union, "m64_i32", "int32_t [8]"), "m64_i32 type");
	mu_assert_true(has_union_member_type(typedb, m64_union, "m64_i16", "int16_t [8]"), "m64_i16 type");
	mu_assert_true(has_union_member_type(typedb, m64_union, "m64_i64", "int64_t"), "m64_i64 type");
	mu_assert_true(has_union_member_type(typedb, m64_union, "m64_u8", "unsigned char [8]"), "m64_u8 type");
	mu_assert_true(has_union_member_type(typedb, m64_union, "m64_u16", "uint16_t [8]"), "m64_u16 type");
	mu_assert_true(has_union_member_type(typedb, m64_union, "m64_u32", "uint32_t [8]"), "m64_u32 type");

	mu_assert_false(has_union_member(m64_union, "noSuchMember"), "no such union member");
	// We dont handle class integration for now, so disable the following unit test.
	// Check the structure presence and validity
	// RzBaseType *test_class = rz_type_db_get_base_type(typedb, "TEST_CLASS");
	// mu_assert_eq(test_class->kind, RZ_BASE_TYPE_KIND_STRUCT, "TEST_CLASS is struct");
	// mu_assert_true(has_struct_member(test_class, "class_var1"), "class_var1");
	// mu_assert_true(has_struct_member(test_class, "calss_var2"), "calss_var2");
	// TODO: test member types also
	// check_kv("struct.TEST_CLASS.class_var1", "int32_t,0,0");
	// check_kv("struct.TEST_CLASS.calss_var2", "uint16_t,4,0");

	// mu_assert_false(has_struct_member(test_class, "noSuchMember"), "no such struct member");
	// Check the structure presence and validity

	// Forward defined structure
	RzBaseType *localeinfo = rz_type_db_get_base_type(typedb, "localeinfo_struct");
	mu_assert_notnull(localeinfo, "NULL type");
	mu_assert_eq(localeinfo->kind, RZ_BASE_TYPE_KIND_STRUCT, "localeinfo_struct is struct");
	mu_assert_true(has_struct_member(localeinfo, "locinfo"), "locinfo");
	mu_assert_true(has_struct_member(localeinfo, "mbcinfo"), "mbcinfo");
	// Test member types also
	mu_assert_true(has_struct_member_type(typedb, localeinfo, "locinfo", "struct threadlocaleinfostruct *"), "locinfo type");
	mu_assert_true(has_struct_member_type(typedb, localeinfo, "mbcinfo", "struct threadmbcinfostruct *"), "mbcinfo type");

	mu_assert_false(has_struct_member(localeinfo, "noSuchMember"), "no such struct member");

	rz_analysis_free(analysis);
	mu_end;
}

bool test_pdb_tpi_cpp_vs2019(void) {
	RzPdb *pdb = rz_bin_pdb_parse_from_file("bins/pdb/vs2019_cpp_override.pdb");
	mu_assert_notnull(pdb, "PDB parse failed.");
	STREAMS_CHECK(75);

	RzPdbTpiStream *stream = pdb->s_tpi;
	mu_assert_notnull(stream, "TPIs stream not found in current PDB");
	mu_assert_eq(stream->header.HeaderSize + stream->header.TypeRecordBytes, 233588, "Wrong TPI size");
	mu_assert_eq(stream->header.TypeIndexBegin, 0x1000, "Wrong beginning index");
	RBIter it;
	RzPdbTpiType *type;

	rz_rbtree_foreach (stream->types, it, type, RzPdbTpiType, rb) {
		if (type->index == 0x1A5F) {
			mu_assert_eq(type->leaf, LF_PROCEDURE, "Incorrect data type");
			RzPdbTpiType *arglist;
			arglist = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Procedure *)(type->data))->arg_list);
			mu_assert_eq(arglist->index, 0x1A5E, "Wrong type index");
			RzPdbTpiType *return_type;
			return_type = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Procedure *)(type->data))->return_type);
			mu_assert_eq(return_type->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = return_type->data;
			mu_assert_eq(simple_type->size, 0, "Incorrect return type");
			mu_assert_streq(simple_type->type, "void", "Incorrect return type");
		} else if (type->index == 0x1A64) {
			mu_assert_eq(type->leaf, LF_POINTER, "Incorrect data type");
			Tpi_LF_Pointer *pointer = type->data;
			mu_assert_eq(pointer->utype, 0x1A63, "Incorrect pointer type");
		} else if (type->index == 0x1ACD) {
			mu_assert_eq(type->leaf, LF_STRUCTURE, "Incorrect data type");
			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_false(forward_ref, "Wrong fwdref");
		} else if (type->index == 0x1B3C) {
			mu_assert_eq(type->leaf, LF_ARRAY, "Incorrect data type");
			RzPdbTpiType *dump;
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->data))->index_type);
			mu_assert_eq(dump->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "uint32_t", "Incorrect return type");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->data))->element_type);
			mu_assert_eq(dump->index, 0x7A, "Wrong element type index");
			ut64 size = rz_bin_pdb_get_type_val(type);
			mu_assert_eq(size, 16, "Wrong array size");
		} else if (type->index == 0x20D6) {
			mu_assert_eq(type->leaf, LF_ENUM, "Incorrect data type");
			RzPdbTpiType *dump;
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "ReplacesCorHdrNumericDefines", "wrong enum name");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Enum *)(type->data))->utype);
			mu_assert_eq(dump->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
			MEMBER_INIT_AND_CHECK_LEN(25);
		} else if (type->index == 0x1A5A) {
			mu_assert_eq(type->leaf, LF_VTSHAPE, "Incorrect data type");
		} else if (type->index == 0x2163) {
			mu_assert_eq(type->leaf, LF_MODIFIER, "Incorrect data type");
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Modifier *)(type->data))->modified_type);
			mu_assert_eq(stype->index, 0x22, "Incorrect modified type");
		} else if (type->leaf == 0x2151) {
			mu_assert_eq(type->leaf, LF_UNION, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "__m64", "wrong union name");
			MEMBER_INIT_AND_CHECK_LEN(9);
		} else if (type->index == 0x239B) {
			mu_assert_eq(type->leaf, LF_CLASS, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "CTest1", "wrong class name");
			MEMBER_INIT_AND_CHECK_LEN(5);
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->data))->vshape);
			mu_assert_notnull(stype, "wrong class vshape");
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->data))->derived);
			mu_assert_null(stype, "wrong class derived");
		} else if (type->index == 0x23DC) {
			mu_assert_eq(type->leaf, LF_CLASS, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "CTest2", "wrong class name");
			MEMBER_INIT_AND_CHECK_LEN(4);
			int i = 0;
			void **it;
			rz_pvector_foreach (members, it) {
				RzPdbTpiType *stype = *it;
				if (i == 0) {
					mu_assert_eq(stype->leaf, LF_BCLASS, "Incorrect data type");
				} else if (i == 1) {
					mu_assert_eq(stype->leaf, LF_ONEMETHOD, "Incorrect data type");
					name = rz_bin_pdb_get_type_name(stype);
					mu_assert_streq(name, "Bar", "wrong member name");
				} else if (i == 2) {
					mu_assert_eq(stype->leaf, LF_METHOD, "Incorrect data type");
					name = rz_bin_pdb_get_type_name(stype);
					mu_assert_streq(name, "CTest2", "wrong member name");
				}
				i++;
			}
			RzPdbTpiType *stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->data))->vshape);
			mu_assert_eq(stype->index, 0x11E8, "wrong class vshape");
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->data))->derived);
			mu_assert_null(stype, "wrong class derived");
		} else if (type->index == 0x2299) {
			mu_assert_eq(type->leaf, LF_CLASS_19, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "type_info", "wrong class name");
			MEMBER_INIT_AND_CHECK_LEN(12);
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->data))->vshape);
			mu_assert_notnull(stype, "wrong class vshape");
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->data))->derived);
			mu_assert_null(stype, "wrong class derived");
		} else if (type->index == 0x2147) {
			mu_assert_eq(type->leaf, LF_BITFIELD, "Incorrect data type");
			RzPdbTpiType *base_type = NULL;
			base_type = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Bitfield *)(type->data))->base_type);
			mu_assert_notnull(base_type, "Bitfield base type is NULL");
		} else if (type->index == 0x2209) {
			mu_assert_eq(type->leaf, LF_METHODLIST, "Incorrect data type");
			// Nothing from methodlist is currently being parsed
		} else if (type->index == 0x224F) {
			mu_assert_eq(type->leaf, LF_MFUNCTION, "Incorrect data type");
			RzPdbTpiType *typ;
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->data))->return_type);
			mu_assert_eq(typ->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = typ->data;
			mu_assert_eq(simple_type->size, 0, "Incorrect return type");
			mu_assert_streq(simple_type->type, "void", "Incorrect return type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->data))->class_type);
			mu_assert_eq(typ->index, 0x2247, "incorrect mfunction class type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->data))->this_type);
			mu_assert_eq(typ->index, 0x2248, "incorrect mfunction this type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->data))->arglist);
			mu_assert_eq(typ->index, 0x224E, "incorrect mfunction arglist");
		} else if (type->index == 0x239A) {
			mu_assert_eq(type->leaf, LF_FIELDLIST, "Incorrect data type");
			MEMBER_INIT_AND_CHECK_LEN(5);
			int i = 0;
			void **it;
			rz_pvector_foreach (members, it) {
				RzPdbTpiType *type_info = *it;
				if (i == 1) {
					mu_assert_eq(type_info->leaf, LF_ONEMETHOD, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_info);
					mu_assert_streq(name, "Foo", "Wrong enum name");
				}
				if (i == 3) {
					mu_assert_eq(type_info->leaf, LF_METHOD, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_info);
					mu_assert_streq(name, "CTest1", "Wrong enum name");
				}
				i++;
			}
		} else if (type->index == 0x2392) {
			mu_assert_eq(type->leaf, LF_ARGLIST, "Incorrect data type");
		} else if (type->index == 0x208F) {
			mu_assert_eq(type->leaf, LF_STRUCTURE, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "_s__RTTICompleteObjectLocator", "Wrong name");
			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_false(forward_ref, "Wrong fwdref");

			MEMBER_INIT_AND_CHECK_LEN(5)
			int i = 0;
			void **it;
			rz_pvector_foreach (members, it) {
				RzPdbTpiType *type_structure = *it;
				if (i == 0) {
					mu_assert_eq(type_structure->leaf, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure);
					mu_assert_streq(name, "signature", "Wrong member name");
				}
				if (i == 1) {
					mu_assert_eq(type_structure->leaf, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure);
					mu_assert_streq(name, "offset", "Wrong member name");
				}
				if (i == 4) {
					mu_assert_eq(type_structure->leaf, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure);
					mu_assert_streq(name, "pClassDescriptor", "Wrong method name");
				}
				i++;
			}
		} else if (type->index == 0x2184) {
			mu_assert_eq(type->leaf, LF_STRUCTURE_19, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "_RS5_IMAGE_LOAD_CONFIG_DIRECTORY32", "Wrong name");
			bool forward_ref;
			forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_false(forward_ref, "Wrong fwdref");
			MEMBER_INIT_AND_CHECK_LEN(48);
			int i = 0;
			void **it;
			rz_pvector_foreach (members, it) {
				RzPdbTpiType *type_structure_19 = *it;
				if (i == 0) {
					mu_assert_eq(type_structure_19->leaf, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure_19);
					mu_assert_streq(name, "Size", "Wrong member name");
				}
				if (i == 1) {
					mu_assert_eq(type_structure_19->leaf, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure_19);
					mu_assert_streq(name, "TimeDateStamp", "Wrong member name");
				}
				if (i == 17) {
					mu_assert_eq(type_structure_19->leaf, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure_19);
					mu_assert_streq(name, "SecurityCookie", "Wrong method name");
				}
				i++;
			}
		}
	}
	rz_bin_pdb_free(pdb);
	mu_end;
}

bool test_pdb_tpi_arm(void) {
	RzPdb *pdb = rz_bin_pdb_parse_from_file("bins/pe/hello_world_arm/hello_world_arm_ZiZoO2.pdb");
	mu_assert_notnull(pdb, "PDB parse failed.");
	STREAMS_CHECK(399);

	RzPdbTpiStream *stream = pdb->s_tpi;
	mu_assert_notnull(stream, "TPIs stream not found in current PDB");
	mu_assert_eq(stream->header.HeaderSize + stream->header.TypeRecordBytes, 454428, "Wrong TPI size");
	mu_assert_eq(stream->header.TypeIndexBegin, 0x1000, "Wrong beginning index");
	RBIter it;
	RzPdbTpiType *type;
	rz_rbtree_foreach (stream->types, it, type, RzPdbTpiType, rb) {
		if (type->index == 0x1A56) {
			mu_assert_eq(type->leaf, LF_PROCEDURE, "Incorrect data type");
			RzPdbTpiType *arglist;
			arglist = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Procedure *)(type->data))->arg_list);
			mu_assert_eq(arglist->index, 0x1A54, "Wrong type index");
			RzPdbTpiType *return_type;
			return_type = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Procedure *)(type->data))->return_type);
			mu_assert_eq(return_type->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = return_type->data;
			mu_assert_eq(simple_type->size, 0, "Incorrect return type");
			mu_assert_streq(simple_type->type, "void", "Incorrect return type");
		} else if (type->index == 0x1A5B) {
			mu_assert_eq(type->leaf, LF_POINTER, "Incorrect data type");
			Tpi_LF_Pointer *pointer = type->data;
			mu_assert_eq(pointer->utype, 0x1A4C, "Incorrect pointer type");
		} else if (type->index == 0x1A2B) {
			mu_assert_eq(type->leaf, LF_STRUCTURE, "Incorrect data type");
			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_false(forward_ref, "Wrong fwdref");
		} else if (type->index == 0x1B2B) {
			mu_assert_eq(type->leaf, LF_ARRAY, "Incorrect data type");
			RzPdbTpiType *dump;
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->data))->index_type);
			mu_assert_eq(dump->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "uint32_t", "Incorrect return type");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->data))->element_type);
			mu_assert_eq(dump->index, 0x1242, "Wrong element type index");
			ut64 size = rz_bin_pdb_get_type_val(type);
			mu_assert_eq(size, 16, "Wrong array size");
		} else if (type->index == 0x1B9C) {
			mu_assert_eq(type->leaf, LF_ENUM, "Incorrect data type");
			RzPdbTpiType *dump;
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "__crt_lowio_text_mode", "wrong enum name");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Enum *)(type->data))->utype);
			mu_assert_eq(dump->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->data;
			mu_assert_eq(simple_type->size, 1, "Incorrect return type");
			mu_assert_streq(simple_type->type, "char", "Incorrect return type");
			MEMBER_INIT_AND_CHECK_LEN(3)
		} else if (type->index == 0x1126) {
			mu_assert_eq(type->leaf, LF_VTSHAPE, "Incorrect data type");
		} else if (type->index == 0x113C) {
			mu_assert_eq(type->leaf, LF_MODIFIER, "Incorrect data type");
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Modifier *)(type->data))->modified_type);
			mu_assert_eq(stype->index, 0x112D, "Incorrect modified type");
		} else if (type->leaf == 0x2151) {
			mu_assert_eq(type->leaf, LF_UNION, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "_IMAGE_SECTION_HEADER::<unnamed-type-Misc>", "wrong union name");
			MEMBER_INIT_AND_CHECK_LEN(2)
		} else if (type->index == 0x121D) {
			mu_assert_eq(type->leaf, LF_CLASS, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "std::bad_alloc", "wrong class name");
			MEMBER_INIT_AND_CHECK_LEN(6)
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->data))->vshape);
			mu_assert_notnull(stype, "wrong class vshape");
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->data))->derived);
			mu_assert_null(stype, "wrong class derived");
		} else if (type->index == 0x150A) {
			mu_assert_eq(type->leaf, LF_CLASS, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "FH4::TryBlockMap4::iterator", "wrong class name");
			MEMBER_INIT_AND_CHECK_LEN(9)
			int i = 0;
			void **it;
			rz_pvector_foreach (members, it) {
				RzPdbTpiType *stype = *it;
				if (i == 0) {
					mu_assert_eq(stype->leaf, LF_ONEMETHOD, "Incorrect data type");
					name = rz_bin_pdb_get_type_name(stype);
					mu_assert_notnull(name, "name is null");
					mu_assert_streq(name, "iterator", "wrong member name");
				} else if (i == 1) {
					mu_assert_eq(stype->leaf, LF_ONEMETHOD, "Incorrect data type");
					name = rz_bin_pdb_get_type_name(stype);
					mu_assert_notnull(name, "name is null");
					mu_assert_streq(name, "operator++", "wrong member name");
				} else if (i == 8) {
					mu_assert_eq(stype->leaf, LF_MEMBER, "Incorrect data type");
					name = rz_bin_pdb_get_type_name(stype);
					mu_assert_notnull(name, "name is null");
					mu_assert_streq(name, "_currBlock", "wrong member name");
				}
				i++;
			}
			RzPdbTpiType *stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->data))->vshape);
			mu_assert_null(stype, "vtshape is not null");
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->data))->derived);
			mu_assert_null(stype, "wrong class derived");
		} else if (type->index == 0x1638) {
			mu_assert_eq(type->leaf, LF_BITFIELD, "Incorrect data type");
			RzPdbTpiType *base_type = NULL;
			base_type = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Bitfield *)(type->data))->base_type);
			mu_assert_notnull(base_type, "Bitfield base type is NULL");
		} else if (type->index == 0x167F) {
			mu_assert_eq(type->leaf, LF_METHODLIST, "Incorrect data type");
		} else if (type->index == 0x168C) {
			mu_assert_eq(type->leaf, LF_MFUNCTION, "Incorrect data type");
			RzPdbTpiType *typ;
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->data))->return_type);
			mu_assert_eq(typ->leaf, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = typ->data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->data))->class_type);
			mu_assert_eq(typ->index, 0x165B, "incorrect mfunction class type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->data))->this_type);
			mu_assert_null(typ, "incorrect mfunction this type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->data))->arglist);
			mu_assert_eq(typ->index, 0x168A, "incorrect mfunction arglist");
		} else if (type->index == 0x16A1) {
			mu_assert_eq(type->leaf, LF_FIELDLIST, "Incorrect data type");
			MEMBER_INIT_AND_CHECK_LEN(100);

			int i = 0;
			void **it;
			rz_pvector_foreach (members, it) {
				RzPdbTpiType *type_info = *it;
				if (i == 3) {
					mu_assert_eq(type_info->leaf, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_info);
					mu_assert_streq(name, "ZNameList", "Wrong enum name");
				}
				if (i == 11) {
					mu_assert_eq(type_info->leaf, LF_ONEMETHOD, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_info);
					mu_assert_streq(name, "getDecoratedName", "Wrong enum name");
				}
				i++;
			}
		} else if (type->index == 0x16A7) {
			mu_assert_eq(type->leaf, LF_ARGLIST, "Incorrect data type");
		} else if (type->index == 0x16E6) {
			mu_assert_eq(type->leaf, LF_STRUCTURE, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "std::_Num_base", "Wrong name");
			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_false(forward_ref, "Wrong fwdref");
			MEMBER_INIT_AND_CHECK_LEN(23)
			int i = 0;
			void **it;
			rz_pvector_foreach (members, it) {
				RzPdbTpiType *type_structure = *it;
				if (i == 0) {
					mu_assert_eq(type_structure->leaf, LF_STMEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure);
					mu_assert_streq(name, "has_denorm", "Wrong member name");
				}
				if (i == 6) {
					mu_assert_eq(type_structure->leaf, LF_STMEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure);
					mu_assert_streq(name, "is_exact", "Wrong member name");
				}
				if (i == 13) {
					mu_assert_eq(type_structure->leaf, LF_STMEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure);
					mu_assert_streq(name, "traps", "Wrong method name");
				}
				i++;
			}
		}
	}
	rz_bin_pdb_free(pdb);
	mu_end;
}

int test_tpi_type_node_cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 ia = *(ut64 *)incoming;
	ut64 ta = container_of(in_tree, const RzPdbTpiType, rb)->index;
	if (ia < ta) {
		return -1;
	} else if (ia > ta) {
		return 1;
	}
	return 0;
}

// Binary reproducer for the NULL deref on a malformed TPI type record.
//
// A record whose leaf is a known aggregate but whose body is too short makes
// the per leaf parser fail and return NULL. Such a record used to be stored
// with its known kind and no data, and the public accessors then dereferenced
// that data by kind and crashed. The file below is the smallest input that
// reaches it: it is built field by field instead of being shipped as a blob,
// both so the layout stays readable and so it needs no entry in the test bins.
//
// MSF layout (block size 512, 8 blocks):
//   0  MSF superblock
//   1  free block map 1
//   2  free block map 2
//   3  block map: the blocks holding the stream directory
//   4  stream 1, PDB information stream
//   5  stream 2, TPI stream, holds the truncated LF_STRUCTURE record
//   6  stream 3, DBI stream
//   7  stream directory
#define PDB_BLOCK_SIZE 512
#define PDB_NUM_BLOCKS 8
#define PDB_FILE_SIZE  (PDB_BLOCK_SIZE * PDB_NUM_BLOCKS)

#define BLOCK_BLOCK_MAP  3
#define BLOCK_STREAM_PDB 4
#define BLOCK_STREAM_TPI 5
#define BLOCK_STREAM_DBI 6
#define BLOCK_DIRECTORY  7

#define STREAM_PDB_SIZE     28
#define TPI_HEADER_SIZE     ((ut32)sizeof(RzPdbTpiStreamHeader)) // the parser requires this exact value
#define TPI_RECORD_SIZE     6 // ut16 length + the 4 record bytes
#define STREAM_TPI_SIZE     (TPI_HEADER_SIZE + TPI_RECORD_SIZE)
#define DBI_HEADER_SIZE     64
#define DBI_DBG_HEADER_SIZE 22 // 11 stream indices
#define STREAM_DBI_SIZE     (DBI_HEADER_SIZE + DBI_DBG_HEADER_SIZE)

// NumStreams + one size per stream + one block index per stream block
#define DIRECTORY_SIZE (4 + 4 * 4 + 4 * 3)

#define TPI_TYPE_INDEX 0x1000

static ut8 *malformed_pdb_bytes(void) {
	ut8 *f = RZ_NEWS0(ut8, PDB_FILE_SIZE);
	if (!f) {
		return NULL;
	}
	ut8 *p;

	// MSF superblock
	memcpy(f, PDB_SIGNATURE, PDB_SIGNATURE_LEN);
	p = f + PDB_SIGNATURE_LEN;
	rz_write_le32(p + 0, PDB_BLOCK_SIZE);
	rz_write_le32(p + 4, 1); // free_block_map_block
	rz_write_le32(p + 8, PDB_NUM_BLOCKS);
	rz_write_le32(p + 12, DIRECTORY_SIZE); // num_directory_bytes
	rz_write_le32(p + 16, 0); // unknown
	rz_write_le32(p + 20, BLOCK_BLOCK_MAP);

	// Both free block maps mark every block as used.
	memset(f + PDB_BLOCK_SIZE, 0xff, 2 * PDB_BLOCK_SIZE);

	// Block map: the single block the stream directory lives in.
	rz_write_le32(f + BLOCK_BLOCK_MAP * PDB_BLOCK_SIZE, BLOCK_DIRECTORY);

	// Stream directory: stream count, then sizes, then the block of each stream.
	// Stream 0 (the old directory) is empty and therefore owns no block.
	p = f + BLOCK_DIRECTORY * PDB_BLOCK_SIZE;
	rz_write_le32(p + 0, 4);
	rz_write_le32(p + 4, 0);
	rz_write_le32(p + 8, STREAM_PDB_SIZE);
	rz_write_le32(p + 12, STREAM_TPI_SIZE);
	rz_write_le32(p + 16, STREAM_DBI_SIZE);
	rz_write_le32(p + 20, BLOCK_STREAM_PDB);
	rz_write_le32(p + 24, BLOCK_STREAM_TPI);
	rz_write_le32(p + 28, BLOCK_STREAM_DBI);

	// PDB information stream, the unique id stays zeroed.
	p = f + BLOCK_STREAM_PDB * PDB_BLOCK_SIZE;
	rz_write_le32(p + 0, VC70); // version
	rz_write_le32(p + 4, 0); // signature
	rz_write_le32(p + 8, 1); // age

	// TPI stream header, one type record in [TypeIndexBegin, TypeIndexEnd).
	p = f + BLOCK_STREAM_TPI * PDB_BLOCK_SIZE;
	rz_write_le32(p + 0, V70); // Version
	rz_write_le32(p + 4, TPI_HEADER_SIZE);
	rz_write_le32(p + 8, TPI_TYPE_INDEX); // TypeIndexBegin
	rz_write_le32(p + 12, TPI_TYPE_INDEX + 1); // TypeIndexEnd
	rz_write_le32(p + 16, TPI_RECORD_SIZE); // TypeRecordBytes
	rz_write_le16(p + 20, 0xffff); // HashStreamIndex, absent
	rz_write_le16(p + 22, 0xffff); // HashAuxStreamIndex, absent
	rz_write_le32(p + 24, 4); // HashKeySize
	rz_write_le32(p + 28, 0x3ffff); // NumHashBuckets
	// The hash, index offset and hash adjuster buffers are all empty.

	// The malformed record. The leaf says LF_STRUCTURE, but the body stops
	// right after `count`: property, field list, derived, vshape and size are
	// all missing, so class_parse() fails and yields no data.
	p += TPI_HEADER_SIZE;
	rz_write_le16(p + 0, TPI_RECORD_SIZE - 2); // record length
	rz_write_le16(p + 2, LF_STRUCTURE);
	rz_write_le16(p + 4, 1); // count

	// DBI stream: a header with no substreams, plus the optional debug header.
	p = f + BLOCK_STREAM_DBI * PDB_BLOCK_SIZE;
	rz_write_le32(p + 0, UT32_MAX); // version_signature
	rz_write_le32(p + 4, DSV_V70); // version_header
	rz_write_le32(p + 8, 1); // age
	rz_write_le16(p + 12, 0xffff); // global_stream_index, absent
	rz_write_le16(p + 16, 0xffff); // public_stream_index, absent
	rz_write_le16(p + 20, 0xffff); // sym_record_stream, absent
	rz_write_le32(p + 48, DBI_DBG_HEADER_SIZE); // optional_dbg_header_size
	rz_write_le16(p + 58, 0x8664); // machine, IMAGE_FILE_MACHINE_AMD64
	// Optional debug header: every one of the 11 streams is absent.
	memset(p + DBI_HEADER_SIZE, 0xff, DBI_DBG_HEADER_SIZE);

	return f;
}

// Before the fix this segfaulted inside rz_bin_pdb_type_is_fwdref(), the same
// way `rz-bin -P <file>` and `idp <file>` did on the crafted file.
bool test_pdb_parse_malformed_tpi_record(void) {
	ut8 *bytes = malformed_pdb_bytes();
	mu_assert_notnull(bytes, "build the pdb bytes");
	char *path = rz_file_temp("tpi-null-data.pdb");
	mu_assert_notnull(path, "temp file path");
	bool dumped = rz_file_dump(path, bytes, PDB_FILE_SIZE, false);
	free(bytes);
	mu_assert_true(dumped, "write the pdb file");

	RzPdb *pdb = rz_bin_pdb_parse_from_file(path);
	mu_assert_notnull(pdb, "the container is well formed, only the type record is not");
	mu_assert_notnull(pdb->s_tpi, "TPI stream is parsed");
	STREAMS_CHECK(4);

	RzPdbTpiType *t = rz_bin_pdb_get_type_by_index(pdb->s_tpi, TPI_TYPE_INDEX);
	mu_assert_notnull(t, "the record is kept so the type indices stay contiguous");
	mu_assert_null(t->data, "class_parse failed, so the record carries no data");

	// Every one of these used to read t->data by kind. They come before the
	// kind check on purpose: against an unfixed library this segfaults here,
	// which is the behaviour worth catching. Asserting the kind first would
	// stop the test early and hide it.
	mu_assert_false(rz_bin_pdb_type_is_fwdref(t), "no data means no fwdref");
	mu_assert_null(rz_bin_pdb_get_type_members(pdb->s_tpi, t), "no data means no members");
	mu_assert_null(rz_bin_pdb_get_type_name(t), "no data means no name");
	mu_assert_eq(rz_bin_pdb_get_type_val(t), 0, "no data means the neutral value");
	mu_assert_eq(t->kind, TpiKind_INVALID, "a record without data must not keep a known kind");

	rz_bin_pdb_free(pdb);
	rz_file_rm(path);
	free(path);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_pdb_tpi_cpp);
	mu_run_test(test_pdb_tpi_rust);
	mu_run_test(test_pdb_type_save);
	mu_run_test(test_pdb_tpi_cpp_vs2019);
	mu_run_test(test_pdb_tpi_arm);
	mu_run_test(test_pdb_parse_malformed_tpi_record);
	return tests_passed != tests_run;
}

mu_main(all_tests)
