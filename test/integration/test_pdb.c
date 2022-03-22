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

	rz_parse_pdb_types(analysis->typedb, pdb);
	rz_bin_pdb_free(pdb);
	return true;
}

bool test_pdb_tpi_cpp(void) {

	RzPdb *pdb = rz_bin_pdb_parse_from_file("bins/pdb/Project1.pdb");
	mu_assert_notnull(pdb, "PDB parse failed.");

	RzList *plist = pdb->streams;
	mu_assert_notnull(plist, "PDB streams is NULL");

	mu_assert_eq(pdb->streams->length, 50, "Incorrect number of streams");

	RzPdbTpiStream *stream = pdb->s_tpi;
	mu_assert_notnull(stream, "TPIs stream not found in current PDB");
	mu_assert_eq(stream->header.HeaderSize + stream->header.TypeRecordBytes, 117156, "Wrong TPI size");
	mu_assert_eq(stream->header.TypeIndexBegin, 0x1000, "Wrong beginning index");
	RBIter it;
	RzPdbTpiType *type;

	rz_rbtree_foreach (stream->types, it, type, RzPdbTpiType, rb) {
		mu_assert_notnull(type, "RzPdbTpiType is null in RBTree.");
		if (type->type_index == 0x1028) {
			mu_assert_eq(type->leaf_type, LF_PROCEDURE, "Incorrect data type");
			RzPdbTpiType *arglist;
			arglist = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Procedure *)(type->type_data))->arg_list);
			mu_assert_eq(arglist->type_index, 0x1027, "Wrong type index");
			RzPdbTpiType *return_type;
			return_type = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Procedure *)(type->type_data))->return_type);
			mu_assert_eq(return_type->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = return_type->type_data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
		} else if (type->type_index == 0x1161) {
			mu_assert_eq(type->leaf_type, LF_POINTER, "Incorrect data type");
		} else if (type->type_index == 0x1004) {
			mu_assert_eq(type->leaf_type, LF_STRUCTURE, "Incorrect data type");
			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_true(forward_ref, "Wrong fwdref");
		} else if (type->type_index == 0x113F) {
			mu_assert_eq(type->leaf_type, LF_ARRAY, "Incorrect data type");
			RzPdbTpiType *dump;
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->type_data))->index_type);
			mu_assert_eq(dump->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->type_data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "uint32_t", "Incorrect return type");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->type_data))->element_type);
			mu_assert_eq(dump->type_index, 0x113E, "Wrong element type index");
			ut64 size = rz_bin_pdb_get_type_val(type);
			mu_assert_eq(size, 20, "Wrong array size");
		} else if (type->type_index == 0x145A) {
			mu_assert_eq(type->leaf_type, LF_ENUM, "Incorrect data type");
			RzPdbTpiType *dump;
			RzList *members;
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "EXCEPTION_DEBUGGER_ENUM", "wrong enum name");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Enum *)(type->type_data))->utype);
			mu_assert_eq(dump->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->type_data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 6, "wrong enum members length");
		} else if (type->type_index == 0x1414) {
			mu_assert_eq(type->leaf_type, LF_VTSHAPE, "Incorrect data type");
		} else if (type->type_index == 0x1421) {
			mu_assert_eq(type->leaf_type, LF_MODIFIER, "Incorrect data type");
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Modifier *)(type->type_data))->modified_type);
			mu_assert_eq(stype->type_index, 0x120F, "Incorrect modified type");
		} else if (type->type_index == 0x1003) {
			mu_assert_eq(type->leaf_type, LF_UNION, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "R2_TEST_UNION", "wrong union name");
			RzList *members;
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 2, "wrong union member count");
		} else if (type->type_index == 0x100B) {
			mu_assert_eq(type->leaf_type, LF_CLASS, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "TEST_CLASS", "wrong class name");
			RzList *members;
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 2, "wrong class member count");
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->type_data))->vshape);
			mu_assert_null(stype, "wrong class vshape");
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->type_data))->derived);
			mu_assert_null(stype, "wrong class derived");
		} else if (type->type_index == 0x1258) {
			mu_assert_eq(type->leaf_type, LF_METHODLIST, "Incorrect data type");
			// Nothing from methodlist is currently being parsed
		} else if (type->type_index == 0x107A) {
			mu_assert_eq(type->leaf_type, LF_MFUNCTION, "Incorrect data type");
			RzPdbTpiType *typ;
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->type_data))->return_type);
			mu_assert_eq(typ->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = typ->type_data;
			mu_assert_eq(simple_type->size, 1, "Incorrect return type");
			mu_assert_streq(simple_type->type, "bool", "Incorrect return type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->type_data))->class_type);
			mu_assert_eq(typ->type_index, 0x1079, "incorrect mfunction class type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->type_data))->arglist);
			mu_assert_eq(typ->type_index, 0x1027, "incorrect mfunction arglist");
		} else if (type->type_index == 0x113F) {
			mu_assert_eq(type->leaf_type, LF_FIELDLIST, "Incorrect data type");
			RzList *members = rz_list_new();
			mu_assert_notnull(members, "Failed at allocating list");
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 2725, "Incorrect members length");
			RzListIter *it;
			RzPdbTpiType *t;
			int i = 0;
			rz_list_foreach (members, it, t) {
				mu_assert_eq(t->leaf_type, LF_ENUMERATE, "Incorrect data type");
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
		} else if (type->type_index == 0x1231) {
			mu_assert_eq(type->leaf_type, LF_ARGLIST, "Incorrect data type");
		} else if (type->type_index == 0x101A) {
			mu_assert_eq(type->leaf_type, LF_STRUCTURE, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "threadlocaleinfostruct", "Wrong name");
			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_false(forward_ref, "Wrong fwdref");
			RzList *members = rz_list_new();
			mu_assert_notnull(members, "Failed at allocating list.");
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_notnull(members, "Coudn't get type members.");
			mu_assert_eq(members->length, 18, "Incorrect members count");
			RzListIter *it;
			RzPdbTpiType *t;
			int i = 0;
			rz_list_foreach (members, it, t) {
				if (i == 0) {
					mu_assert_eq(t->leaf_type, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(t);
					mu_assert_streq(name, "refcount", "Wrong member name");
				}
				if (i == 1) {
					mu_assert_eq(t->leaf_type, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(t);
					mu_assert_streq(name, "lc_codepage", "Wrong member name");
				}
				if (i == 17) {
					mu_assert_eq(t->leaf_type, LF_MEMBER, "Incorrect data type");
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

	RzList *plist = pdb->streams;
	mu_assert_notnull(plist, "PDB streams is NULL");

	mu_assert_eq(pdb->streams->length, 88, "Incorrect number of streams");

	RzPdbTpiStream *stream = pdb->s_tpi;
	mu_assert_notnull(stream, "TPIs stream not found in current PDB");
	mu_assert_eq(stream->header.HeaderSize + stream->header.TypeRecordBytes, 305632, "Wrong TPI size");
	mu_assert_eq(stream->header.TypeIndexBegin, 0x1000, "Wrong beginning index");
	RBIter it;
	RzPdbTpiType *type;

	rz_rbtree_foreach (stream->types, it, type, RzPdbTpiType, rb) {
		if (type->type_index == 0x101B) {
			mu_assert_eq(type->leaf_type, LF_PROCEDURE, "Incorrect data type");
			RzPdbTpiType *arglist;
			arglist = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Procedure *)(type->type_data))->arg_list);
			mu_assert_eq(arglist->type_index, 0x101A, "Wrong type index");
			RzPdbTpiType *return_type;
			return_type = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Procedure *)(type->type_data))->return_type);
			mu_assert_eq(return_type->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = return_type->type_data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
		} else if (type->type_index == 0x1163) {
			mu_assert_eq(type->leaf_type, LF_POINTER, "Incorrect data type");
			Tpi_LF_Pointer *pointer = type->type_data;
			mu_assert_eq(pointer->utype, 0x1162, "Incorrect pointer type");
		} else if (type->type_index == 0x1005) {
			mu_assert_eq(type->leaf_type, LF_STRUCTURE, "Incorrect data type");
			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_true(forward_ref, "Wrong fwdref");
		} else if (type->type_index == 0x114A) {
			mu_assert_eq(type->leaf_type, LF_ARRAY, "Incorrect data type");
			RzPdbTpiType *dump;
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->type_data))->index_type);
			mu_assert_eq(dump->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->type_data;
			mu_assert_eq(simple_type->size, 8, "Incorrect return type");
			mu_assert_streq(simple_type->type, "uint64_t", "Incorrect return type");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->type_data))->element_type);
			mu_assert_eq(dump->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			simple_type = dump->type_data;
			mu_assert_eq(simple_type->size, 1, "Incorrect return type");
			mu_assert_streq(simple_type->type, "unsigned char", "Incorrect return type");

			ut64 size = rz_bin_pdb_get_type_val(type);
			mu_assert_eq(size, 16, "Wrong array size");
		} else if (type->type_index == 0x1FB4) {
			mu_assert_eq(type->leaf_type, LF_ENUM, "Incorrect data type");
			RzPdbTpiType *dump;
			RzList *members;
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "ISA_AVAILABILITY", "wrong enum name");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Enum *)(type->type_data))->utype);
			mu_assert_eq(dump->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->type_data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 10, "wrong enum members length");
		} else if (type->type_index == 0x1E31) {
			mu_assert_eq(type->leaf_type, LF_VTSHAPE, "Incorrect data type");
		} else if (type->type_index == 0x1FB7) {
			mu_assert_eq(type->leaf_type, LF_MODIFIER, "Incorrect data type");
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Modifier *)(type->type_data))->modified_type);
			mu_assert_eq(stype->leaf_type, LF_SIMPLE_TYPE, "Incorrect modified type");
		} else if (type->type_index == 0x1EA9) {
			mu_assert_eq(type->leaf_type, LF_CLASS, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "std::bad_typeid", "wrong class name");
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->type_data))->vshape);
			mu_assert_notnull(stype, "wrong class vshape");
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->type_data))->derived);
			mu_assert_null(stype, "wrong class derived");
		} else if (type->type_index == 0x1E27) {
			mu_assert_eq(type->leaf_type, LF_METHODLIST, "Incorrect data type");
			// Nothing from methodlist is currently being parsed
		} else if (type->type_index == 0x181C) {
			mu_assert_eq(type->leaf_type, LF_MFUNCTION, "Incorrect data type");
			RzPdbTpiType *typ;
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->type_data))->return_type);
			mu_assert_eq(typ->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = typ->type_data;
			mu_assert_eq(simple_type->size, 0, "Incorrect return type");
			mu_assert_streq(simple_type->type, "void", "Incorrect return type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->type_data))->class_type);
			mu_assert_eq(typ->type_index, 0x107F, "incorrect mfunction class type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->type_data))->arglist);
			mu_assert_eq(typ->type_index, 0x1000, "incorrect mfunction arglist");
		} else if (type->type_index == 0x13BF) {
			mu_assert_eq(type->leaf_type, LF_FIELDLIST, "Incorrect data type");
			// check size
			RzList *members = rz_list_new();
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 3, "Incorrect members length");
			RzListIter *it = rz_list_iterator(members);
			RzPdbTpiType *t;
			int i = 0;
			rz_list_foreach (members, it, t) {
				mu_assert_eq(t->leaf_type, LF_MEMBER, "Incorrect data type");
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
		} else if (type->type_index == 0x1164) {
			mu_assert_eq(type->leaf_type, LF_ARGLIST, "Incorrect data type");
		} else if (type->type_index == 0x1058) {
			mu_assert_eq(type->leaf_type, LF_STRUCTURE, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "std::thread::local::fast::Key<core::cell::Cell<core::option::Option<core::ptr::non_null::NonNull<core::task::wake::Context>>>>", "Wrong name");

			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_false(forward_ref, "Wrong fwdref");
			ut64 size = rz_bin_pdb_get_type_val(type);

			mu_assert_eq(size, 24, "Wrong struct size");

			RzList *members = rz_list_new();
			mu_assert_notnull(members, "Couldn't allocate list");
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_notnull(members, "Type members is NULL");
			mu_assert_eq(members->length, 2, "Incorrect members count");

			RzListIter *it = rz_list_iterator(members);
			RzPdbTpiType *t;
			int i = 0;
			rz_list_foreach (members, it, t) {
				if (i == 0) {
					mu_assert_eq(t->leaf_type, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(t);
					mu_assert_streq(name, "inner", "Wrong member name");
				}
				if (i == 1) {
					mu_assert_eq(t->leaf_type, LF_MEMBER, "Incorrect data type");
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
	RzAnalysis *analysis = rz_analysis_new();
	char *types_dir = rz_path_system(RZ_SDB_TYPES);
	rz_type_db_init(analysis->typedb, types_dir, "x86", 32, "windows");
	free(types_dir);

	mu_assert_true(pdb_info_save_types(analysis, "bins/pdb/Project1.pdb"), "pdb parsing failed");

	// Check the enum presence and validity
	RzBaseType *test_enum = rz_type_db_get_base_type(analysis->typedb, "R2_TEST_ENUM");
	mu_assert_eq(test_enum->kind, RZ_BASE_TYPE_KIND_ENUM, "R2_TEST_ENUM is enum");
	mu_assert_true(has_enum_val(test_enum, "eENUM1_R2", 0x10), "eNUM1_R2 = 0x10");
	mu_assert_true(has_enum_val(test_enum, "eENUM2_R2", 0x20), "eNUM2_R2 = 0x20");
	mu_assert_true(has_enum_val(test_enum, "eENUM_R2_MAX", 0x21), "eNUM2_R2 = 0x21");

	mu_assert_false(has_enum_case(test_enum, "no_case"), "no such enum case");

	// Check the union presence and validity
	RzBaseType *test_union = rz_type_db_get_base_type(analysis->typedb, "R2_TEST_UNION");
	mu_assert_eq(test_union->kind, RZ_BASE_TYPE_KIND_UNION, "R2_TEST_UNION is union");
	mu_assert_true(has_union_member(test_union, "r2_union_var_1"), "r2_union_var_1");
	mu_assert_true(has_union_member(test_union, "r2_union_var_2"), "r2_union_var_2");
	// Test member types also
	mu_assert_true(has_union_member_type(analysis->typedb, test_union, "r2_union_var_1", "int32_t"), "r2_union_var_1 type");
	mu_assert_true(has_union_member_type(analysis->typedb, test_union, "r2_union_var_2", "double"), "rz_union_var_2 type");
	mu_assert_false(has_union_member(test_union, "noSuchMember"), "no such struct member");

	RzBaseType *m64_union = rz_type_db_get_base_type(analysis->typedb, "__m64");
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
	mu_assert_true(has_union_member_type(analysis->typedb, m64_union, "m64_u64", "uint64_t"), "m64_u64 type");
	mu_assert_true(has_union_member_type(analysis->typedb, m64_union, "m64_f32", "float [8]"), "m64_f32 type");
	mu_assert_true(has_union_member_type(analysis->typedb, m64_union, "m64_i8", "char [8]"), "m64_i8 type");
	mu_assert_true(has_union_member_type(analysis->typedb, m64_union, "m64_i32", "int32_t [8]"), "m64_i32 type");
	mu_assert_true(has_union_member_type(analysis->typedb, m64_union, "m64_i16", "int16_t [8]"), "m64_i16 type");
	mu_assert_true(has_union_member_type(analysis->typedb, m64_union, "m64_i64", "int64_t"), "m64_i64 type");
	mu_assert_true(has_union_member_type(analysis->typedb, m64_union, "m64_u8", "unsigned char [8]"), "m64_u8 type");
	mu_assert_true(has_union_member_type(analysis->typedb, m64_union, "m64_u16", "uint16_t [8]"), "m64_u16 type");
	mu_assert_true(has_union_member_type(analysis->typedb, m64_union, "m64_u32", "uint32_t [8]"), "m64_u32 type");

	mu_assert_false(has_union_member(m64_union, "noSuchMember"), "no such union member");
	// We dont handle class integration for now, so disable the following unit test.
	// Check the structure presence and validity
	// RzBaseType *test_class = rz_type_db_get_base_type(analysis->typedb, "TEST_CLASS");
	// mu_assert_eq(test_class->kind, RZ_BASE_TYPE_KIND_STRUCT, "TEST_CLASS is struct");
	// mu_assert_true(has_struct_member(test_class, "class_var1"), "class_var1");
	// mu_assert_true(has_struct_member(test_class, "calss_var2"), "calss_var2");
	// TODO: test member types also
	// check_kv("struct.TEST_CLASS.class_var1", "int32_t,0,0");
	// check_kv("struct.TEST_CLASS.calss_var2", "uint16_t,4,0");

	// mu_assert_false(has_struct_member(test_class, "noSuchMember"), "no such struct member");
	// Check the structure presence and validity

	// Forward defined structure
	RzBaseType *localeinfo = rz_type_db_get_base_type(analysis->typedb, "localeinfo_struct");
	mu_assert_eq(localeinfo->kind, RZ_BASE_TYPE_KIND_STRUCT, "localeinfo_struct is struct");
	mu_assert_true(has_struct_member(localeinfo, "locinfo"), "locinfo");
	mu_assert_true(has_struct_member(localeinfo, "mbcinfo"), "mbcinfo");
	// Test member types also
	mu_assert_true(has_struct_member_type(analysis->typedb, localeinfo, "locinfo", "struct threadlocaleinfostruct *"), "locinfo type");
	mu_assert_true(has_struct_member_type(analysis->typedb, localeinfo, "mbcinfo", "struct threadmbcinfostruct *"), "mbcinfo type");

	mu_assert_false(has_struct_member(localeinfo, "noSuchMember"), "no such struct member");

	rz_analysis_free(analysis);
	mu_end;
}

bool test_pdb_tpi_cpp_vs2019(void) {
	RzPdb *pdb = rz_bin_pdb_parse_from_file("bins/pdb/vs2019_cpp_override.pdb");
	mu_assert_notnull(pdb, "PDB parse failed.");

	RzList *plist = pdb->streams;
	mu_assert_notnull(plist, "PDB streams is NULL");

	mu_assert_eq(pdb->streams->length, 75, "Incorrect number of streams");

	RzPdbTpiStream *stream = pdb->s_tpi;
	mu_assert_notnull(stream, "TPIs stream not found in current PDB");
	mu_assert_eq(stream->header.HeaderSize + stream->header.TypeRecordBytes, 233588, "Wrong TPI size");
	mu_assert_eq(stream->header.TypeIndexBegin, 0x1000, "Wrong beginning index");
	RBIter it;
	RzPdbTpiType *type;

	rz_rbtree_foreach (stream->types, it, type, RzPdbTpiType, rb) {
		if (type->type_index == 0x1A5F) {
			mu_assert_eq(type->leaf_type, LF_PROCEDURE, "Incorrect data type");
			RzPdbTpiType *arglist;
			arglist = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Procedure *)(type->type_data))->arg_list);
			mu_assert_eq(arglist->type_index, 0x1A5E, "Wrong type index");
			RzPdbTpiType *return_type;
			return_type = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Procedure *)(type->type_data))->return_type);
			mu_assert_eq(return_type->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = return_type->type_data;
			mu_assert_eq(simple_type->size, 0, "Incorrect return type");
			mu_assert_streq(simple_type->type, "void", "Incorrect return type");
		} else if (type->type_index == 0x1A64) {
			mu_assert_eq(type->leaf_type, LF_POINTER, "Incorrect data type");
			Tpi_LF_Pointer *pointer = type->type_data;
			mu_assert_eq(pointer->utype, 0x1A63, "Incorrect pointer type");
		} else if (type->type_index == 0x1ACD) {
			mu_assert_eq(type->leaf_type, LF_STRUCTURE, "Incorrect data type");
			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_false(forward_ref, "Wrong fwdref");
		} else if (type->type_index == 0x1B3C) {
			mu_assert_eq(type->leaf_type, LF_ARRAY, "Incorrect data type");
			RzPdbTpiType *dump;
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->type_data))->index_type);
			mu_assert_eq(dump->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->type_data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "uint32_t", "Incorrect return type");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->type_data))->element_type);
			mu_assert_eq(dump->type_index, 0x7A, "Wrong element type index");
			ut64 size = rz_bin_pdb_get_type_val(type);
			mu_assert_eq(size, 16, "Wrong array size");
		} else if (type->type_index == 0x20D6) {
			mu_assert_eq(type->leaf_type, LF_ENUM, "Incorrect data type");
			RzPdbTpiType *dump;
			RzList *members;
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "ReplacesCorHdrNumericDefines", "wrong enum name");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Enum *)(type->type_data))->utype);
			mu_assert_eq(dump->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->type_data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 25, "wrong enum members length");
		} else if (type->type_index == 0x1A5A) {
			mu_assert_eq(type->leaf_type, LF_VTSHAPE, "Incorrect data type");
		} else if (type->type_index == 0x2163) {
			mu_assert_eq(type->leaf_type, LF_MODIFIER, "Incorrect data type");
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Modifier *)(type->type_data))->modified_type);
			mu_assert_eq(stype->type_index, 0x22, "Incorrect modified type");
		} else if (type->leaf_type == 0x2151) {
			mu_assert_eq(type->leaf_type, LF_UNION, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "__m64", "wrong union name");
			RzList *members;
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 9, "wrong union member count");
		} else if (type->type_index == 0x239B) {
			mu_assert_eq(type->leaf_type, LF_CLASS, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "CTest1", "wrong class name");
			RzList *members;
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 5, "wrong class member count");
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->type_data))->vshape);
			mu_assert_notnull(stype, "wrong class vshape");
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->type_data))->derived);
			mu_assert_null(stype, "wrong class derived");
		} else if (type->type_index == 0x23DC) {
			mu_assert_eq(type->leaf_type, LF_CLASS, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "CTest2", "wrong class name");
			RzList *members;
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 4, "wrong class member count");
			RzListIter *it_ctest2;
			RzPdbTpiType *stype;
			int i = 0;
			rz_list_foreach (members, it_ctest2, stype) {
				if (i == 0) {
					mu_assert_eq(stype->leaf_type, LF_BCLASS, "Incorrect data type");
				} else if (i == 1) {
					mu_assert_eq(stype->leaf_type, LF_ONEMETHOD, "Incorrect data type");
					name = rz_bin_pdb_get_type_name(stype);
					mu_assert_streq(name, "Bar", "wrong member name");
				} else if (i == 2) {
					mu_assert_eq(stype->leaf_type, LF_METHOD, "Incorrect data type");
					name = rz_bin_pdb_get_type_name(stype);
					mu_assert_streq(name, "CTest2", "wrong member name");
				}
				i++;
			}
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->type_data))->vshape);
			mu_assert_eq(stype->type_index, 0x11E8, "wrong class vshape");
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->type_data))->derived);
			mu_assert_null(stype, "wrong class derived");
		} else if (type->type_index == 0x2299) {
			mu_assert_eq(type->leaf_type, LF_CLASS_19, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "type_info", "wrong class name");
			RzList *members;
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 12, "wrong class member count");
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->type_data))->vshape);
			mu_assert_notnull(stype, "wrong class vshape");
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->type_data))->derived);
			mu_assert_null(stype, "wrong class derived");
		} else if (type->type_index == 0x2147) {
			mu_assert_eq(type->leaf_type, LF_BITFIELD, "Incorrect data type");
			RzPdbTpiType *base_type = NULL;
			base_type = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Bitfield *)(type->type_data))->base_type);
			mu_assert_notnull(base_type, "Bitfield base type is NULL");
		} else if (type->type_index == 0x2209) {
			mu_assert_eq(type->leaf_type, LF_METHODLIST, "Incorrect data type");
			// Nothing from methodlist is currently being parsed
		} else if (type->type_index == 0x224F) {
			mu_assert_eq(type->leaf_type, LF_MFUNCTION, "Incorrect data type");
			RzPdbTpiType *typ;
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->type_data))->return_type);
			mu_assert_eq(typ->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = typ->type_data;
			mu_assert_eq(simple_type->size, 0, "Incorrect return type");
			mu_assert_streq(simple_type->type, "void", "Incorrect return type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->type_data))->class_type);
			mu_assert_eq(typ->type_index, 0x2247, "incorrect mfunction class type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->type_data))->this_type);
			mu_assert_eq(typ->type_index, 0x2248, "incorrect mfunction this type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->type_data))->arglist);
			mu_assert_eq(typ->type_index, 0x224E, "incorrect mfunction arglist");
		} else if (type->type_index == 0x239A) {
			mu_assert_eq(type->leaf_type, LF_FIELDLIST, "Incorrect data type");
			RzList *members = rz_list_new();
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 5, "Incorrect members length");
			RzListIter *it_fieldlist;
			RzPdbTpiType *type_info;
			int i = 0;
			rz_list_foreach (members, it_fieldlist, type_info) {
				if (i == 1) {
					mu_assert_eq(type_info->leaf_type, LF_ONEMETHOD, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_info);
					mu_assert_streq(name, "Foo", "Wrong enum name");
				}
				if (i == 3) {
					mu_assert_eq(type_info->leaf_type, LF_METHOD, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_info);
					mu_assert_streq(name, "CTest1", "Wrong enum name");
				}
				i++;
			}
		} else if (type->type_index == 0x2392) {
			mu_assert_eq(type->leaf_type, LF_ARGLIST, "Incorrect data type");
		} else if (type->type_index == 0x208F) {
			mu_assert_eq(type->leaf_type, LF_STRUCTURE, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "_s__RTTICompleteObjectLocator", "Wrong name");
			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_false(forward_ref, "Wrong fwdref");
			RzList *members = rz_list_new();
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 5, "Incorrect members count");
			RzListIter *it_structure;
			RzPdbTpiType *type_structure;
			int i = 0;
			rz_list_foreach (members, it_structure, type_structure) {
				if (i == 0) {
					mu_assert_eq(type_structure->leaf_type, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure);
					mu_assert_streq(name, "signature", "Wrong member name");
				}
				if (i == 1) {
					mu_assert_eq(type_structure->leaf_type, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure);
					mu_assert_streq(name, "offset", "Wrong member name");
				}
				if (i == 4) {
					mu_assert_eq(type_structure->leaf_type, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure);
					mu_assert_streq(name, "pClassDescriptor", "Wrong method name");
				}
				i++;
			}
		} else if (type->type_index == 0x2184) {
			mu_assert_eq(type->leaf_type, LF_STRUCTURE_19, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "_RS5_IMAGE_LOAD_CONFIG_DIRECTORY32", "Wrong name");
			bool forward_ref;
			forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_false(forward_ref, "Wrong fwdref");
			RzList *members = rz_list_new();
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 48, "Incorrect members count");
			RzListIter *it_structure_19;
			RzPdbTpiType *type_structure_19;
			int i = 0;
			rz_list_foreach (members, it_structure_19, type_structure_19) {
				if (i == 0) {
					mu_assert_eq(type_structure_19->leaf_type, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure_19);
					mu_assert_streq(name, "Size", "Wrong member name");
				}
				if (i == 1) {
					mu_assert_eq(type_structure_19->leaf_type, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure_19);
					mu_assert_streq(name, "TimeDateStamp", "Wrong member name");
				}
				if (i == 17) {
					mu_assert_eq(type_structure_19->leaf_type, LF_MEMBER, "Incorrect data type");
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

	RzList *plist = pdb->streams;
	mu_assert_notnull(plist, "PDB streams is NULL");

	mu_assert_eq(pdb->streams->length, 399, "Incorrect number of streams");

	RzPdbTpiStream *stream = pdb->s_tpi;
	mu_assert_notnull(stream, "TPIs stream not found in current PDB");
	mu_assert_eq(stream->header.HeaderSize + stream->header.TypeRecordBytes, 454428, "Wrong TPI size");
	mu_assert_eq(stream->header.TypeIndexBegin, 0x1000, "Wrong beginning index");
	RBIter it;
	RzPdbTpiType *type;

	rz_rbtree_foreach (stream->types, it, type, RzPdbTpiType, rb) {
		if (type->type_index == 0x1A56) {
			mu_assert_eq(type->leaf_type, LF_PROCEDURE, "Incorrect data type");
			RzPdbTpiType *arglist;
			arglist = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Procedure *)(type->type_data))->arg_list);
			mu_assert_eq(arglist->type_index, 0x1A54, "Wrong type index");
			RzPdbTpiType *return_type;
			return_type = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Procedure *)(type->type_data))->return_type);
			mu_assert_eq(return_type->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = return_type->type_data;
			mu_assert_eq(simple_type->size, 0, "Incorrect return type");
			mu_assert_streq(simple_type->type, "void", "Incorrect return type");
		} else if (type->type_index == 0x1A5B) {
			mu_assert_eq(type->leaf_type, LF_POINTER, "Incorrect data type");
			Tpi_LF_Pointer *pointer = type->type_data;
			mu_assert_eq(pointer->utype, 0x1A4C, "Incorrect pointer type");
		} else if (type->type_index == 0x1A2B) {
			mu_assert_eq(type->leaf_type, LF_STRUCTURE, "Incorrect data type");
			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_false(forward_ref, "Wrong fwdref");
		} else if (type->type_index == 0x1B2B) {
			mu_assert_eq(type->leaf_type, LF_ARRAY, "Incorrect data type");
			RzPdbTpiType *dump;
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->type_data))->index_type);
			mu_assert_eq(dump->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->type_data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "uint32_t", "Incorrect return type");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Array *)(type->type_data))->element_type);
			mu_assert_eq(dump->type_index, 0x1242, "Wrong element type index");
			ut64 size = rz_bin_pdb_get_type_val(type);
			mu_assert_eq(size, 16, "Wrong array size");
		} else if (type->type_index == 0x1B9C) {
			mu_assert_eq(type->leaf_type, LF_ENUM, "Incorrect data type");
			RzPdbTpiType *dump;
			RzList *members;
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "__crt_lowio_text_mode", "wrong enum name");
			dump = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Enum *)(type->type_data))->utype);
			mu_assert_eq(dump->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = dump->type_data;
			mu_assert_eq(simple_type->size, 1, "Incorrect return type");
			mu_assert_streq(simple_type->type, "char", "Incorrect return type");
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 3, "wrong enum members length");
		} else if (type->type_index == 0x1126) {
			mu_assert_eq(type->leaf_type, LF_VTSHAPE, "Incorrect data type");
		} else if (type->type_index == 0x113C) {
			mu_assert_eq(type->leaf_type, LF_MODIFIER, "Incorrect data type");
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Modifier *)(type->type_data))->modified_type);
			mu_assert_eq(stype->type_index, 0x112D, "Incorrect modified type");
		} else if (type->leaf_type == 0x2151) {
			mu_assert_eq(type->leaf_type, LF_UNION, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "_IMAGE_SECTION_HEADER::<unnamed-type-Misc>", "wrong union name");
			RzList *members;
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 2, "wrong union member count");
		} else if (type->type_index == 0x121D) {
			mu_assert_eq(type->leaf_type, LF_CLASS, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "std::bad_alloc", "wrong class name");
			RzList *members;
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 6, "wrong class member count");
			RzPdbTpiType *stype = NULL;
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->type_data))->vshape);
			mu_assert_notnull(stype, "wrong class vshape");
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->type_data))->derived);
			mu_assert_null(stype, "wrong class derived");
		} else if (type->type_index == 0x150A) {
			mu_assert_eq(type->leaf_type, LF_CLASS, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "FH4::TryBlockMap4::iterator", "wrong class name");
			RzList *members;
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 9, "wrong class member count");
			RzListIter *it_ctest2;
			RzPdbTpiType *stype;
			int i = 0;
			rz_list_foreach (members, it_ctest2, stype) {
				if (i == 0) {
					mu_assert_eq(stype->leaf_type, LF_ONEMETHOD, "Incorrect data type");
					name = rz_bin_pdb_get_type_name(stype);
					mu_assert_notnull(name, "name is null");
					mu_assert_streq(name, "iterator", "wrong member name");
				} else if (i == 1) {
					mu_assert_eq(stype->leaf_type, LF_ONEMETHOD, "Incorrect data type");
					name = rz_bin_pdb_get_type_name(stype);
					mu_assert_notnull(name, "name is null");
					mu_assert_streq(name, "operator++", "wrong member name");
				} else if (i == 8) {
					mu_assert_eq(stype->leaf_type, LF_MEMBER, "Incorrect data type");
					name = rz_bin_pdb_get_type_name(stype);
					mu_assert_notnull(name, "name is null");
					mu_assert_streq(name, "_currBlock", "wrong member name");
				}
				i++;
			}
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->type_data))->vshape);
			mu_assert_null(stype, "vtshape is not null");
			stype = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Class *)(type->type_data))->derived);
			mu_assert_null(stype, "wrong class derived");
		} else if (type->type_index == 0x1638) {
			mu_assert_eq(type->leaf_type, LF_BITFIELD, "Incorrect data type");
			RzPdbTpiType *base_type = NULL;
			base_type = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_Bitfield *)(type->type_data))->base_type);
			mu_assert_notnull(base_type, "Bitfield base type is NULL");
		} else if (type->type_index == 0x167F) {
			mu_assert_eq(type->leaf_type, LF_METHODLIST, "Incorrect data type");
		} else if (type->type_index == 0x168C) {
			mu_assert_eq(type->leaf_type, LF_MFUNCTION, "Incorrect data type");
			RzPdbTpiType *typ;
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->type_data))->return_type);
			mu_assert_eq(typ->leaf_type, LF_SIMPLE_TYPE, "Incorrect return type");
			Tpi_LF_SimpleType *simple_type = typ->type_data;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->type_data))->class_type);
			mu_assert_eq(typ->type_index, 0x165B, "incorrect mfunction class type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->type_data))->this_type);
			mu_assert_null(typ, "incorrect mfunction this type");
			typ = rz_bin_pdb_get_type_by_index(stream, ((Tpi_LF_MFcuntion *)(type->type_data))->arglist);
			mu_assert_eq(typ->type_index, 0x168A, "incorrect mfunction arglist");
		} else if (type->type_index == 0x16A1) {
			mu_assert_eq(type->leaf_type, LF_FIELDLIST, "Incorrect data type");
			RzList *members = rz_list_new();
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 100, "Incorrect members length");
			RzListIter *it_fieldlist;
			RzPdbTpiType *type_info;
			int i = 0;
			rz_list_foreach (members, it_fieldlist, type_info) {
				if (i == 3) {
					mu_assert_eq(type_info->leaf_type, LF_MEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_info);
					mu_assert_streq(name, "ZNameList", "Wrong enum name");
				}
				if (i == 11) {
					mu_assert_eq(type_info->leaf_type, LF_ONEMETHOD, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_info);
					mu_assert_streq(name, "getDecoratedName", "Wrong enum name");
				}
				i++;
			}
		} else if (type->type_index == 0x16A7) {
			mu_assert_eq(type->leaf_type, LF_ARGLIST, "Incorrect data type");
		} else if (type->type_index == 0x16E6) {
			mu_assert_eq(type->leaf_type, LF_STRUCTURE, "Incorrect data type");
			char *name;
			name = rz_bin_pdb_get_type_name(type);
			mu_assert_streq(name, "std::_Num_base", "Wrong name");
			bool forward_ref = rz_bin_pdb_type_is_fwdref(type);
			mu_assert_false(forward_ref, "Wrong fwdref");
			RzList *members = rz_list_new();
			members = rz_bin_pdb_get_type_members(stream, type);
			mu_assert_eq(members->length, 23, "Incorrect members count");
			RzListIter *it_structure;
			RzPdbTpiType *type_structure;
			int i = 0;
			rz_list_foreach (members, it_structure, type_structure) {
				if (i == 0) {
					mu_assert_eq(type_structure->leaf_type, LF_STMEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure);
					mu_assert_streq(name, "has_denorm", "Wrong member name");
				}
				if (i == 6) {
					mu_assert_eq(type_structure->leaf_type, LF_STMEMBER, "Incorrect data type");
					char *name = NULL;
					name = rz_bin_pdb_get_type_name(type_structure);
					mu_assert_streq(name, "is_exact", "Wrong member name");
				}
				if (i == 13) {
					mu_assert_eq(type_structure->leaf_type, LF_STMEMBER, "Incorrect data type");
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
	ut64 ta = container_of(in_tree, const RzPdbTpiType, rb)->type_index;
	if (ia < ta) {
		return -1;
	} else if (ia > ta) {
		return 1;
	}
	return 0;
}

bool all_tests() {
	mu_run_test(test_pdb_tpi_cpp);
	mu_run_test(test_pdb_tpi_rust);
	mu_run_test(test_pdb_type_save);
	mu_run_test(test_pdb_tpi_cpp_vs2019);
	mu_run_test(test_pdb_tpi_arm);
	return tests_passed != tests_run;
}

mu_main(all_tests)
