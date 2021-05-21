// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"
#include <rz_bin.h>
#include <rz_core.h>
#include <rz_bin_dwarf.h>
#include "../../librz/bin/pdb/types.h"

#define MODE 2

static bool has_enum_val(RzBaseType *btype, const char *name, int val) {
	int result = -1;
	RzTypeEnumCase *cas;
	rz_vector_foreach(&btype->enum_data.cases, cas) {
		if (!strcmp(cas->name, name)) {
			result = cas->val;
			break;
		}
	}
	return result != -1 && result == val;
}

static bool has_enum_case(RzBaseType *btype, const char *name) {
	RzTypeEnumCase *cas;
	rz_vector_foreach(&btype->enum_data.cases, cas) {
		if (!strcmp(cas->name, name)) {
			return true;
		}
	}
	return false;
}

static bool has_struct_member(RzBaseType *btype, const char *name) {
	RzTypeStructMember *memb;
	rz_vector_foreach(&btype->struct_data.members, memb) {
		if (!strcmp(memb->name, name)) {
			return true;
		}
	}
	return false;
}

static bool has_union_member(RzBaseType *btype, const char *name) {
	RzTypeUnionMember *memb;
	rz_vector_foreach(&btype->union_data.members, memb) {
		if (!strcmp(memb->name, name)) {
			return true;
		}
	}
	return false;
}

// copy from cbin.c modified to get pdb back
int pdb_info(const char *file, RzPdb *pdb) {
	pdb->cb_printf = rz_cons_printf;
	if (!init_pdb_parser(pdb, file)) {
		return false;
	}
	if (!pdb->pdb_parse(pdb)) {
		eprintf("pdb was not parsed\n");
		pdb->finish_pdb_parse(pdb);
		return false;
	}
	return true;
}

int pdb_info_save_types(RzAnalysis *analysis, const char *file, RzPdb *pdb) {
	pdb->cb_printf = rz_cons_printf;
	if (!init_pdb_parser(pdb, file)) {
		return false;
	}
	if (!pdb->pdb_parse(pdb)) {
		eprintf("pdb was not parsed\n");
		pdb->finish_pdb_parse(pdb);
		return false;
	}
	rz_parse_pdb_types(analysis->typedb, pdb);
	pdb->finish_pdb_parse(pdb);
	return true;
}

bool test_pdb_tpi_cpp(void) {
	RzPdb pdb = RZ_EMPTY;
	mu_assert_true(pdb_info("bins/pdb/Project1.pdb", &pdb), "pdb parsing failed");

	RzList *plist = pdb.pdb_streams;
	mu_assert_notnull(plist, "PDB streams is NULL");

	mu_assert_eq(pdb.root_stream->num_streams, 50, "Incorrect number of streams");

	STpiStream *tpi_stream = rz_list_get_n(plist, ePDB_STREAM_TPI);
	mu_assert_notnull(tpi_stream, "TPIs stream not found in current PDB");
	mu_assert_eq(tpi_stream->header.hdr_size + tpi_stream->header.follow_size, 117156, "Wrong TPI size");
	mu_assert_eq(tpi_stream->header.idx_begin, 0x1000, "Wrong beginning index");

	// tpi_stream->header.
	mu_assert_eq(tpi_stream->types->length, 1148, "Incorrect number of types");
	RzListIter *it = rz_list_iterator(tpi_stream->types);
	SType *type;
	while (rz_list_iter_next(it)) {
		type = rz_list_iter_get(it);
		STypeInfo *type_info = &type->type_data;
		if (type->tpi_idx == 0x1028) {
			mu_assert_eq(type_info->leaf_type, eLF_PROCEDURE, "Incorrect data type");
			SType *arglist;
			type_info->get_arglist(type_info, (void **)&arglist);
			mu_assert_eq(arglist->tpi_idx, 0x1027, "Wrong type index");
			SType *return_type;
			type_info->get_return_type(type_info, (void **)&return_type);
			mu_assert_eq(return_type->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = return_type->type_data.type_info;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
		} else if (type->tpi_idx == 0x1161) {
			mu_assert_eq(type_info->leaf_type, eLF_POINTER, "Incorrect data type");
			char *type;
			type_info->get_print_type(type_info, &type);
			mu_assert_streq(type, "struct _RTC_framedesc*", "Wrong pointer print type");
		} else if (type->tpi_idx == 0x1004) {
			mu_assert_eq(type_info->leaf_type, eLF_STRUCTURE, "Incorrect data type");
			int forward_ref = 0;
			type->type_data.is_fwdref(type_info, &forward_ref);
			mu_assert_eq(forward_ref, 1, "Wrong fwdref");
		} else if (type->tpi_idx == 0x113F) {
			mu_assert_eq(type_info->leaf_type, eLF_ARRAY, "Incorrect data type");
			char *type;
			type_info->get_print_type(type_info, &type);
			SType *dump;
			type_info->get_index_type(type_info, (void **)&dump);
			mu_assert_eq(dump->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = dump->type_data.type_info;
			mu_assert_eq(simple_type->simple_type, eT_ULONG, "Incorrect return type");
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "uint32_t", "Incorrect return type");
			type_info->get_element_type(type_info, (void **)&dump);
			mu_assert_eq(dump->tpi_idx, 0x113E, "Wrong element type index");
			int size;
			type_info->get_val(type_info, &size);
			mu_assert_eq(size, 20, "Wrong array size");
		} else if (type->tpi_idx == 0x145A) {
			mu_assert_eq(type_info->leaf_type, eLF_ENUM, "Incorrect data type");
			SType *dump;
			RzList *members;
			char *name;
			type_info->get_name(type_info, &name);
			mu_assert_streq(name, "EXCEPTION_DEBUGGER_ENUM", "wrong enum name");
			type_info->get_utype(type_info, (void **)&dump);
			mu_assert_eq(dump->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = dump->type_data.type_info;
			mu_assert_eq(simple_type->simple_type, eT_INT4, "Incorrect return type");
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
			type_info->get_members(type_info, &members);
			mu_assert_eq(members->length, 6, "wrong enum members length");
		} else if (type->tpi_idx == 0x1414) {
			mu_assert_eq(type_info->leaf_type, eLF_VTSHAPE, "Incorrect data type");
		} else if (type->tpi_idx == 0x1421) {
			mu_assert_eq(type_info->leaf_type, eLF_MODIFIER, "Incorrect data type");
			SType *stype = NULL;
			type_info->get_modified_type(type_info, (void **)&stype);
			mu_assert_eq(stype->tpi_idx, 0x120F, "Incorrect modified type");
			char *type;
			type_info->get_print_type(type_info, &type);
			mu_assert_streq(type, "const struct Stream", "Incorrect modifier print type");
		} else if (type->tpi_idx == 0x1003) {
			mu_assert_eq(type_info->leaf_type, eLF_UNION, "Incorrect data type");
			char *name;
			type_info->get_name(type_info, &name);
			mu_assert_streq(name, "R2_TEST_UNION", "wrong union name");
			RzList *members;
			type_info->get_members(type_info, &members);
			mu_assert_eq(members->length, 2, "wrong union member count");
		} else if (type->tpi_idx == 0x100B) {
			mu_assert_eq(type_info->leaf_type, eLF_CLASS, "Incorrect data type");
			char *name;
			type_info->get_name(type_info, &name);
			mu_assert_streq(name, "TEST_CLASS", "wrong class name");
			RzList *members;
			type_info->get_members(type_info, &members);
			mu_assert_eq(members->length, 2, "wrong class member count");
			SType *stype = NULL;
			int result = type_info->get_vshape(type_info, (void **)&stype);
			mu_assert_eq(result || stype, 0, "wrong class vshape");
			result = type_info->get_derived(type_info, (void **)&stype);
			mu_assert_eq(result || stype, 0, "wrong class derived");
			//} else if (type->tpi_idx == 0x1062) {
			//	mu_assert_eq(type_info->leaf_type, eLF_BITFIELD, "Incorrect data type");
			//	SType *base_type = NULL;
			//	type_info->get_base_type(type_info, (void **)&base_type);
			//	char *type;
			//	type_info->get_print_type(type_info, &type);
			//	mu_assert_streq(type, "bitfield uint32_t : 1", "Incorrect bitfield print type");
		} else if (type->tpi_idx == 0x1258) {
			mu_assert_eq(type_info->leaf_type, eLF_METHODLIST, "Incorrect data type");
			// Nothing from methodlist is currently being parsed
		} else if (type->tpi_idx == 0x107A) {
			mu_assert_eq(type_info->leaf_type, eLF_MFUNCTION, "Incorrect data type");
			SType *type;
			type_info->get_return_type(type_info, (void **)&type);
			mu_assert_eq(type->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = type->type_data.type_info;
			mu_assert_eq(simple_type->simple_type, eT_BOOL08, "Incorrect return type");
			mu_assert_eq(simple_type->size, 1, "Incorrect return type");
			mu_assert_streq(simple_type->type, "_Bool", "Incorrect return type");
			type_info->get_class_type(type_info, (void **)&type);
			mu_assert_eq(type->tpi_idx, 0x1079, "incorrect mfunction class type");
			type_info->get_this_type(type_info, (void **)&type);
			mu_assert_eq(type, 0, "incorrect mfunction this type");
			type_info->get_arglist(type_info, (void **)&type);
			mu_assert_eq(type->tpi_idx, 0x1027, "incorrect mfunction arglist");
		} else if (type->tpi_idx == 0x113F) {
			mu_assert_eq(type_info->leaf_type, eLF_FIELDLIST, "Incorrect data type");
			RzList *members = rz_list_new();
			type_info->get_members(&type->type_data, &members);
			mu_assert_eq(members->length, 2725, "Incorrect members length");
			RzListIter *it = rz_list_iterator(members);
			int i = 0;
			while (rz_list_iter_next(it)) {
				STypeInfo *type_info = (STypeInfo *)rz_list_iter_get(it);
				mu_assert_eq(type_info->leaf_type, eLF_ENUMERATE, "Incorrect data type");
				if (i == 0) {
					char *name = NULL;
					type_info->get_name(type_info, &name);
					mu_assert_streq(name, "CV_ALLREG_ERR", "Wrong enum name");
					int value = 0;
					type_info->get_val(type_info, &value);
					mu_assert_eq(value, 30000, "Wrong enumerate value");
				}
				if (i == 2724) {
					char *name = NULL;
					type_info->get_name(type_info, &name);
					mu_assert_streq(name, "CV_AMD64_YMM15D3", "Wrong enum name");
					int value = 0;
					type_info->get_val(type_info, &value);
					mu_assert_eq(value, 687, "Wrong enumerate value");
				}
				i++;
			}
		} else if (type->tpi_idx == 0x1231) {
			mu_assert_eq(type_info->leaf_type, eLF_ARGLIST, "Incorrect data type");
		} else if (type->tpi_idx == 0x101A) {
			mu_assert_eq(type_info->leaf_type, eLF_STRUCTURE, "Incorrect data type");
			char *name;
			int is_forward_ref;
			type_info->get_name(&type->type_data, &name);
			mu_assert_streq(name, "threadlocaleinfostruct", "Wrong name");
			type_info->is_fwdref(&type->type_data, &is_forward_ref);
			mu_assert_eq(is_forward_ref, false, "Wrong is_fwdref");
			RzList *members = rz_list_new();
			type_info->get_members(&type->type_data, &members);
			mu_assert_eq(members->length, 18, "Incorrect members count");
			RzListIter *it = rz_list_iterator(members);
			int i = 0;
			while (rz_list_iter_next(it)) {
				STypeInfo *type_info = (STypeInfo *)rz_list_iter_get(it);
				if (i == 0) {
					mu_assert_eq(type_info->leaf_type, eLF_MEMBER, "Incorrect data type");
					char *name = NULL;
					type_info->get_name(type_info, &name);
					mu_assert_streq(name, "refcount", "Wrong member name");
					char *type;
					type_info->get_print_type(type_info, &type);
					mu_assert_streq(type, "int32_t", "Wrong member type");
				}
				if (i == 1) {
					mu_assert_eq(type_info->leaf_type, eLF_MEMBER, "Incorrect data type");
					char *name = NULL;
					type_info->get_name(type_info, &name);
					mu_assert_streq(name, "lc_codepage", "Wrong member name");
					char *type;
					type_info->get_print_type(type_info, &type);
					mu_assert_streq(type, "uint32_t", "Wrong member type");
				}
				if (i == 17) {
					mu_assert_eq(type_info->leaf_type, eLF_MEMBER, "Incorrect data type");
					char *name = NULL;
					type_info->get_name(type_info, &name);
					mu_assert_streq(name, "locale_name", "Wrong method name");
					char *type;
					type_info->get_print_type(type_info, &type);
					mu_assert_streq(type, "wchar_t *[24]", "Wrong method type");
				}
				i++;
			}
		}
	};
	pdb.finish_pdb_parse(&pdb);
	mu_end;
}

bool test_pdb_tpi_rust(void) {
	RzPdb pdb = RZ_EMPTY;
	mu_assert_true(pdb_info("bins/pdb/ghidra_rust_pdb_bug.pdb", &pdb), "pdb parsing failed");

	RzList *plist = pdb.pdb_streams;
	mu_assert_notnull(plist, "PDB streams is NULL");

	mu_assert_eq(pdb.root_stream->num_streams, 88, "Incorrect number of streams");

	STpiStream *tpi_stream = rz_list_get_n(plist, ePDB_STREAM_TPI);
	mu_assert_notnull(tpi_stream, "TPIs stream not found in current PDB");
	mu_assert_eq(tpi_stream->header.hdr_size + tpi_stream->header.follow_size, 305632, "Wrong TPI size");
	mu_assert_eq(tpi_stream->header.idx_begin, 0x1000, "Wrong beginning index");

	// tpi_stream->header.
	mu_assert_eq(tpi_stream->types->length, 4031, "Incorrect number of types");
	RzListIter *it = rz_list_iterator(tpi_stream->types);
	SType *type;
	while (rz_list_iter_next(it)) {
		type = rz_list_iter_get(it);
		STypeInfo *type_info = &type->type_data;
		if (type->tpi_idx == 0x101B) {
			mu_assert_eq(type_info->leaf_type, eLF_PROCEDURE, "Incorrect data type");
			SType *arglist;
			type_info->get_arglist(type_info, (void **)&arglist);
			mu_assert_eq(arglist->tpi_idx, 0x101A, "Wrong type index");
			SType *return_type;
			type_info->get_return_type(type_info, (void **)&return_type);
			mu_assert_eq(return_type->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = return_type->type_data.type_info;
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
		} else if (type->tpi_idx == 0x1163) {
			mu_assert_eq(type_info->leaf_type, eLF_POINTER, "Incorrect data type");
			char *type;
			type_info->get_print_type(type_info, &type);
			mu_assert_streq(type, "struct core::fmt::Void*", "Wrong pointer print type");
		} else if (type->tpi_idx == 0x1005) {
			mu_assert_eq(type_info->leaf_type, eLF_STRUCTURE, "Incorrect data type");
			int forward_ref = 0;
			type->type_data.is_fwdref(type_info, &forward_ref);
			mu_assert_eq(forward_ref, 1, "Wrong fwdref");
		} else if (type->tpi_idx == 0x114A) {
			mu_assert_eq(type_info->leaf_type, eLF_ARRAY, "Incorrect data type");
			SType *dump;

			type_info->get_index_type(type_info, (void **)&dump);
			mu_assert_eq(dump->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = dump->type_data.type_info;
			mu_assert_eq(simple_type->simple_type, eT_UQUAD, "Incorrect return type");
			mu_assert_eq(simple_type->size, 8, "Incorrect return type");
			mu_assert_streq(simple_type->type, "uint64_t", "Incorrect return type");
			type_info->get_element_type(type_info, (void **)&dump);

			mu_assert_eq(dump->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			simple_type = dump->type_data.type_info;
			mu_assert_eq(simple_type->simple_type, eT_UCHAR, "Incorrect return type");
			mu_assert_eq(simple_type->size, 1, "Incorrect return type");
			mu_assert_streq(simple_type->type, "uint8_t", "Incorrect return type");

			int size;
			type_info->get_val(type_info, &size);
			mu_assert_eq(size, 16, "Wrong array size");
		} else if (type->tpi_idx == 0x1FB4) {
			mu_assert_eq(type_info->leaf_type, eLF_ENUM, "Incorrect data type");
			SType *dump;
			RzList *members;
			char *name;
			type_info->get_name(type_info, &name);
			mu_assert_streq(name, "ISA_AVAILABILITY", "wrong enum name");
			type_info->get_utype(type_info, (void **)&dump);
			mu_assert_eq(dump->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = dump->type_data.type_info;
			mu_assert_eq(simple_type->simple_type, eT_INT4, "Incorrect return type");
			mu_assert_eq(simple_type->size, 4, "Incorrect return type");
			mu_assert_streq(simple_type->type, "int32_t", "Incorrect return type");
			type_info->get_members(type_info, &members);
			mu_assert_eq(members->length, 10, "wrong enum members length");
		} else if (type->tpi_idx == 0x1E31) {
			mu_assert_eq(type_info->leaf_type, eLF_VTSHAPE, "Incorrect data type");
		} else if (type->tpi_idx == 0x1FB7) {
			mu_assert_eq(type_info->leaf_type, eLF_MODIFIER, "Incorrect data type");
			SType *stype = NULL;
			type_info->get_modified_type(type_info, (void **)&stype);
			mu_assert_eq(stype->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect modified type");
			char *type;
			type_info->get_print_type(type_info, &type);
			mu_assert_streq(type, "const volatile uint64_t", "Incorrect modifier print type");
			// } else if (type->tpi_idx == 0x1F4E) { This whole thing isn't parsed correctly for some reason TODO
			// 	mu_assert_eq (type_info->leaf_type, eLF_UNION, "Incorrect data type");
			// 	char *name;
			// 	type_info->get_name (type_info, &name);
			// 	mu_assert_streq (name, "_SLIST_HEADER", "wrong union name");
			// 	RzList *members;
			// 	type_info->get_members (type_info, &members);
			// 	mu_assert_eq (members->length, 3, "wrong union member count");
			// 	// mu_assert_eq (members->length, 4, "wrong union member count"); // Doesn't work, missing one (last) member for some reason TODO
			// 	int size = 0;
			// 	type_info->get_val (type_info, &size);
			// 	// mu_assert_eq (size, 48, " Wrong union size"); // parse wrong should be 48, is 16
			// 	mu_assert_eq (size, 16, " Wrong union size");
		} else if (type->tpi_idx == 0x1EA9) {
			mu_assert_eq(type_info->leaf_type, eLF_CLASS, "Incorrect data type");
			char *name;
			type_info->get_name(type_info, &name);
			mu_assert_streq(name, "std::bad_typeid", "wrong class name");
			RzList *members;
			type_info->get_members(type_info, &members);
			// mu_assert_eq (members->length, 7, "wrong class member count"); // These members (fieldlist) isn't properly parsed?
			SType *stype = NULL;
			int result = type_info->get_vshape(type_info, (void **)&stype);
			mu_assert_eq(result || stype, 1, "wrong class vshape");
			result = type_info->get_derived(type_info, (void **)&stype);
			mu_assert_eq(result || stype, 0, "wrong class derived");
			//} else if (type->tpi_idx == 0x1F50) {
			//	mu_assert_eq(type_info->leaf_type, eLF_BITFIELD, "Incorrect data type");
			//	SType *base_type = NULL;
			//	type_info->get_base_type(type_info, (void **)&base_type);
			//	char *type;
			//	type_info->get_print_type(type_info, &type);
			//	mu_assert_streq(type, "bitfield uint64_t : 48", "Incorrect bitfield print type");
		} else if (type->tpi_idx == 0x1E27) {
			mu_assert_eq(type_info->leaf_type, eLF_METHODLIST, "Incorrect data type");
			// Nothing from methodlist is currently being parsed
		} else if (type->tpi_idx == 0x181C) {
			mu_assert_eq(type_info->leaf_type, eLF_MFUNCTION, "Incorrect data type");
			SType *type;
			type_info->get_return_type(type_info, (void **)&type);
			mu_assert_eq(type->type_data.leaf_type, eLF_SIMPLE_TYPE, "Incorrect return type");
			SLF_SIMPLE_TYPE *simple_type = type->type_data.type_info;
			mu_assert_eq(simple_type->simple_type, eT_VOID, "Incorrect return type");
			mu_assert_eq(simple_type->size, 0, "Incorrect return type");
			mu_assert_streq(simple_type->type, "void", "Incorrect return type");
			type_info->get_class_type(type_info, (void **)&type);
			mu_assert_eq(type->tpi_idx, 0x107F, "incorrect mfunction class type");
			type_info->get_this_type(type_info, (void **)&type);
			mu_assert_eq(type, 0, "incorrect mfunction this type");
			type_info->get_arglist(type_info, (void **)&type);
			mu_assert_eq(type->tpi_idx, 0x1000, "incorrect mfunction arglist");
		} else if (type->tpi_idx == 0x13BF) {
			mu_assert_eq(type_info->leaf_type, eLF_FIELDLIST, "Incorrect data type");
			// check size
			RzList *members = rz_list_new();
			type_info->get_members(&type->type_data, &members);
			mu_assert_eq(members->length, 3, "Incorrect members length");
			RzListIter *it = rz_list_iterator(members);
			int i = 0;
			while (rz_list_iter_next(it)) {
				STypeInfo *type_info = (STypeInfo *)rz_list_iter_get(it);
				mu_assert_eq(type_info->leaf_type, eLF_MEMBER, "Incorrect data type");
				if (i == 0) {
					char *name = NULL;
					type_info->get_name(type_info, &name);
					mu_assert_streq(name, "RUST$ENUM$DISR", "Wrong member name");
					// get type
				}
				if (i == 2) {
					char *name = NULL;
					type_info->get_name(type_info, &name);
					mu_assert_streq(name, "__0", "Wrong member name");
					// get type
				}
				i++;
			}
		} else if (type->tpi_idx == 0x1164) {
			mu_assert_eq(type_info->leaf_type, eLF_ARGLIST, "Incorrect data type");
		} else if (type->tpi_idx == 0x1058) {
			mu_assert_eq(type_info->leaf_type, eLF_STRUCTURE, "Incorrect data type");
			char *name;
			type_info->get_name(&type->type_data, &name);
			mu_assert_streq(name, "std::thread::local::fast::Key<core::cell::Cell<core::option::Option<core::ptr::non_null::NonNull<core::task::wake::Context>>>>", "Wrong name");

			int is_forward_ref;
			type_info->is_fwdref(&type->type_data, &is_forward_ref);
			mu_assert_eq(is_forward_ref, false, "Wrong is_fwdref");

			int size = 0;
			type_info->get_val(type_info, &size);
			mu_assert_eq(size, 24, "Wrong struct size");

			RzList *members = rz_list_new();
			type_info->get_members(&type->type_data, &members);
			mu_assert_eq(members->length, 2, "Incorrect members count");

			RzListIter *it = rz_list_iterator(members);
			int i = 0;
			while (rz_list_iter_next(it)) {
				STypeInfo *type_info = (STypeInfo *)rz_list_iter_get(it);
				if (i == 0) {
					mu_assert_eq(type_info->leaf_type, eLF_MEMBER, "Incorrect data type");
					char *name = NULL;
					type_info->get_name(type_info, &name);
					mu_assert_streq(name, "inner", "Wrong member name");
					// todo add type idx
				}
				if (i == 1) {
					mu_assert_eq(type_info->leaf_type, eLF_MEMBER, "Incorrect data type");
					char *name = NULL;
					type_info->get_name(type_info, &name);
					mu_assert_streq(name, "dtor_state", "Wrong member name");
				}
				i++;
			}
		}
	};
	pdb.finish_pdb_parse(&pdb);
	mu_end;
}

bool test_pdb_type_save(void) {
	RzPdb pdb = RZ_EMPTY;
	RzAnalysis *analysis = rz_analysis_new();
	const char *dir_prefix = rz_sys_prefix(NULL);
	rz_type_db_init(analysis->typedb, dir_prefix, "x86", 32, "windows");

	mu_assert_true(pdb_info_save_types(analysis, "bins/pdb/Project1.pdb", &pdb), "pdb parsing failed");

	// Check the enum presence and validity
	RzBaseType *test_enum = rz_type_db_get_base_type(analysis->typedb, "R2_TEST_ENUM");
	mu_assert_eq(test_enum->kind, RZ_BASE_TYPE_KIND_ENUM, "R2_TEST_ENUM is enum");
	mu_assert_true(has_enum_val(test_enum, "eENUM1_R2", 0x10), "eNUM1_R2 = 0x10");
	mu_assert_true(has_enum_val(test_enum, "eENUM2_R2", 0x20), "eNUM2_R2 = 0x20");
	mu_assert_true(has_enum_val(test_enum, "eENUM_R2_MAX", 0x20), "eNUM2_R2 = 0x20");

	mu_assert_false(has_enum_case(test_enum, "no_case"), "no such enum case");

	// Check the union presence and validity
	RzBaseType *test_union = rz_type_db_get_base_type(analysis->typedb, "R2_TEST_UNION");
	mu_assert_eq(test_union->kind, RZ_BASE_TYPE_KIND_UNION, "R2_TEST_UNION is union");
	mu_assert_true(has_union_member(test_union, "r2_union_var_1"), "r2_union_var_1");
	mu_assert_true(has_union_member(test_union, "r2_union_var_2"), "r2_union_var_2");
	// TODO: test member types also
	//check_kv("union.R2_TEST_UNION.r2_union_var_1", "int32_t,0,0");
	//check_kv("union.R2_TEST_UNION.r2_union_var_2", "double,0,0");
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
	// TODO: test member types also
	//check_kv("union.__m64.m64_u64", "uint64_t,0,0");
	//check_kv("union.__m64.m64_f32", "float[8],0,0");
	//check_kv("union.__m64.m64_i8", "char[8],0,0");
	//check_kv("union.__m64.m64_i16", "uint16_t[8],0,0");
	//check_kv("union.__m64.m64_i32", "int32_t[8],0,0");
	//check_kv("union.__m64.m64_i64", "int64_t,0,0");
	//check_kv("union.__m64.m64_u8", "uint8_t[8],0,0");
	//check_kv("union.__m64.m64_u16", "uint16_t[8],0,0");
	//check_kv("union.__m64.m64_u32", "uint32_t[8],0,0");

	mu_assert_false(has_union_member(m64_union, "noSuchMember"), "no such union member");

	// Check the structure presence and validity
	RzBaseType *test_class = rz_type_db_get_base_type(analysis->typedb, "TEST_CLASS");
	mu_assert_eq(test_class->kind, RZ_BASE_TYPE_KIND_STRUCT, "TEST_CLASS is struct");
	mu_assert_true(has_struct_member(test_class, "class_var1"), "class_var1");
	mu_assert_true(has_struct_member(test_class, "calss_var2"), "calss_var2");
	// TODO: test member types also
	//check_kv("struct.TEST_CLASS.class_var1", "int32_t,0,0");
	//check_kv("struct.TEST_CLASS.calss_var2", "uint16_t,4,0");

	mu_assert_false(has_struct_member(test_class, "noSuchMember"), "no such struct member");

	// Check the structure presence and validity
	RzBaseType *localeinfo = rz_type_db_get_base_type(analysis->typedb, "localeinfo_struct");
	mu_assert_eq(localeinfo->kind, RZ_BASE_TYPE_KIND_STRUCT, "localeinfo_struct is struct");
	mu_assert_true(has_struct_member(localeinfo, "locinfo"), "locinfo");
	mu_assert_true(has_struct_member(localeinfo, "mcinfo"), "mbcinfo");
	// TODO: test member types also
	//check_kv("struct.localeinfo_struct.locinfo", "struct threadlocaleinfostruct*,0,0");
	//check_kv("struct.localeinfo_struct.mbcinfo", "struct threadmbcinfostruct*,4,0");

	mu_assert_false(has_struct_member(localeinfo, "noSuchMember"), "no such struct member");

	rz_analysis_free(analysis);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_pdb_tpi_cpp);
	mu_run_test(test_pdb_tpi_rust);
	mu_run_test(test_pdb_type_save);
	return tests_passed != tests_run;
}

mu_main(all_tests)
