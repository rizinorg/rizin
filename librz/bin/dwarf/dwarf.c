// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

#define DW_(x) \
	case x: return #x;

static const char *indent_tbl[] = {
	"",
	"\t",
	"\t\t",
	"\t\t\t",
	"\t\t\t\t",
	"\t\t\t\t\t",
	"\t\t\t\t\t\t",
};

RZ_IPI const char *indent_str(int indent) {
	if (indent < 0) {
		return "";
	}
	if (indent >= RZ_ARRAY_SIZE(indent_tbl)) {
		indent = 6;
	}
	return indent_tbl[indent];
}

static const char *dwarf_tag_name_encodings[] = {
	[DW_TAG_null_entry] = "DW_TAG_null_entry",
	[DW_TAG_array_type] = "DW_TAG_array_type",
	[DW_TAG_class_type] = "DW_TAG_class_type",
	[DW_TAG_entry_point] = "DW_TAG_entry_point",
	[DW_TAG_enumeration_type] = "DW_TAG_enumeration_type",
	[DW_TAG_formal_parameter] = "DW_TAG_formal_parameter",
	[DW_TAG_imported_declaration] = "DW_TAG_imported_declaration",
	[DW_TAG_label] = "DW_TAG_label",
	[DW_TAG_lexical_block] = "DW_TAG_lexical_block",
	[DW_TAG_member] = "DW_TAG_member",
	[DW_TAG_pointer_type] = "DW_TAG_pointer_type",
	[DW_TAG_reference_type] = "DW_TAG_reference_type",
	[DW_TAG_compile_unit] = "DW_TAG_compile_unit",
	[DW_TAG_string_type] = "DW_TAG_string_type",
	[DW_TAG_structure_type] = "DW_TAG_structure_type",
	[DW_TAG_subroutine_type] = "DW_TAG_subroutine_type",
	[DW_TAG_typedef] = "DW_TAG_typedef",
	[DW_TAG_union_type] = "DW_TAG_union_type",
	[DW_TAG_unspecified_parameters] = "DW_TAG_unspecified_parameters",
	[DW_TAG_variant] = "DW_TAG_variant",
	[DW_TAG_common_block] = "DW_TAG_common_block",
	[DW_TAG_common_inclusion] = "DW_TAG_common_inclusion",
	[DW_TAG_inheritance] = "DW_TAG_inheritance",
	[DW_TAG_inlined_subroutine] = "DW_TAG_inlined_subroutine",
	[DW_TAG_module] = "DW_TAG_module",
	[DW_TAG_ptr_to_member_type] = "DW_TAG_ptr_to_member_type",
	[DW_TAG_set_type] = "DW_TAG_set_type",
	[DW_TAG_subrange_type] = "DW_TAG_subrange_type",
	[DW_TAG_with_stmt] = "DW_TAG_with_stmt",
	[DW_TAG_access_declaration] = "DW_TAG_access_declaration",
	[DW_TAG_base_type] = "DW_TAG_base_type",
	[DW_TAG_catch_block] = "DW_TAG_catch_block",
	[DW_TAG_const_type] = "DW_TAG_const_type",
	[DW_TAG_constant] = "DW_TAG_constant",
	[DW_TAG_enumerator] = "DW_TAG_enumerator",
	[DW_TAG_file_type] = "DW_TAG_file_type",
	[DW_TAG_friend] = "DW_TAG_friend",
	[DW_TAG_namelist] = "DW_TAG_namelist",
	[DW_TAG_namelist_item] = "DW_TAG_namelist_item",
	[DW_TAG_packed_type] = "DW_TAG_packed_type",
	[DW_TAG_subprogram] = "DW_TAG_subprogram",
	[DW_TAG_template_type_param] = "DW_TAG_template_type_param",
	[DW_TAG_template_value_param] = "DW_TAG_template_value_param",
	[DW_TAG_thrown_type] = "DW_TAG_thrown_type",
	[DW_TAG_try_block] = "DW_TAG_try_block",
	[DW_TAG_variant_part] = "DW_TAG_variant_part",
	[DW_TAG_variable] = "DW_TAG_variable",
	[DW_TAG_volatile_type] = "DW_TAG_volatile_type",
	[DW_TAG_dwarf_procedure] = "DW_TAG_dwarf_procedure",
	[DW_TAG_restrict_type] = "DW_TAG_restrict_type",
	[DW_TAG_interface_type] = "DW_TAG_interface_type",
	[DW_TAG_namespace] = "DW_TAG_namespace",
	[DW_TAG_imported_module] = "DW_TAG_imported_module",
	[DW_TAG_unspecified_type] = "DW_TAG_unspecified_type",
	[DW_TAG_partial_unit] = "DW_TAG_partial_unit",
	[DW_TAG_imported_unit] = "DW_TAG_imported_unit",
	[DW_TAG_mutable_type] = "DW_TAG_mutable_type",
	[DW_TAG_condition] = "DW_TAG_condition",
	[DW_TAG_shared_type] = "DW_TAG_shared_type",
	[DW_TAG_type_unit] = "DW_TAG_type_unit",
	[DW_TAG_rvalue_reference_type] = "DW_TAG_rvalue_reference_type",
	[DW_TAG_template_alias] = "DW_TAG_template_alias",
	// DWARF 5.
	[DW_TAG_coarray_type] = "DW_TAG_coarray_type",
	[DW_TAG_generic_subrange] = "DW_TAG_generic_subrange",
	[DW_TAG_dynamic_type] = "DW_TAG_dynamic_type",
	[DW_TAG_atomic_type] = "DW_TAG_atomic_type",
	[DW_TAG_call_site] = "DW_TAG_call_site",
	[DW_TAG_call_site_parameter] = "DW_TAG_call_site_parameter",
	[DW_TAG_skeleton_unit] = "DW_TAG_skeleton_unit",
	[DW_TAG_immutable_type] = "DW_TAG_immutable_type",
};

static const char *dwarf_attr_encodings[] = {
	[DW_AT_sibling] = "DW_AT_siblings",
	[DW_AT_location] = "DW_AT_location",
	[DW_AT_name] = "DW_AT_name",
	[DW_AT_ordering] = "DW_AT_ordering",
	[DW_AT_byte_size] = "DW_AT_byte_size",
	[DW_AT_bit_size] = "DW_AT_bit_size",
	[DW_AT_stmt_list] = "DW_AT_stmt_list",
	[DW_AT_low_pc] = "DW_AT_low_pc",
	[DW_AT_high_pc] = "DW_AT_high_pc",
	[DW_AT_language] = "DW_AT_language",
	[DW_AT_discr] = "DW_AT_discr",
	[DW_AT_discr_value] = "DW_AT_discr_value",
	[DW_AT_visibility] = "DW_AT_visibility",
	[DW_AT_import] = "DW_AT_import",
	[DW_AT_string_length] = "DW_AT_string_length",
	[DW_AT_common_reference] = "DW_AT_common_reference",
	[DW_AT_comp_dir] = "DW_AT_comp_dir",
	[DW_AT_const_value] = "DW_AT_const_value",
	[DW_AT_containing_type] = "DW_AT_containing_type",
	[DW_AT_default_value] = "DW_AT_default_value",
	[DW_AT_inline] = "DW_AT_inline",
	[DW_AT_is_optional] = "DW_AT_is_optional",
	[DW_AT_lower_bound] = "DW_AT_lower_bound",
	[DW_AT_producer] = "DW_AT_producer",
	[DW_AT_prototyped] = "DW_AT_prototyped",
	[DW_AT_return_addr] = "DW_AT_return_addr",
	[DW_AT_start_scope] = "DW_AT_start_scope",
	[DW_AT_stride_size] = "DW_AT_stride_size",
	[DW_AT_upper_bound] = "DW_AT_upper_bound",
	[DW_AT_abstract_origin] = "DW_AT_abstract_origin",
	[DW_AT_accessibility] = "DW_AT_accessibility",
	[DW_AT_address_class] = "DW_AT_address_class",
	[DW_AT_artificial] = "DW_AT_artificial",
	[DW_AT_base_types] = "DW_AT_base_types",
	[DW_AT_calling_convention] = "DW_AT_calling_convention",
	[DW_AT_count] = "DW_AT_count",
	[DW_AT_data_member_location] = "DW_AT_data_member_location",
	[DW_AT_decl_column] = "DW_AT_decl_column",
	[DW_AT_decl_file] = "DW_AT_decl_file",
	[DW_AT_decl_line] = "DW_AT_decl_line",
	[DW_AT_declaration] = "DW_AT_declaration",
	[DW_AT_discr_list] = "DW_AT_discr_list",
	[DW_AT_encoding] = "DW_AT_encoding",
	[DW_AT_external] = "DW_AT_external",
	[DW_AT_frame_base] = "DW_AT_frame_base",
	[DW_AT_friend] = "DW_AT_friend",
	[DW_AT_identifier_case] = "DW_AT_identifier_case",
	[DW_AT_macro_info] = "DW_AT_macro_info",
	[DW_AT_namelist_item] = "DW_AT_namelist_item",
	[DW_AT_priority] = "DW_AT_priority",
	[DW_AT_segment] = "DW_AT_segment",
	[DW_AT_specification] = "DW_AT_specification",
	[DW_AT_static_link] = "DW_AT_static_link",
	[DW_AT_type] = "DW_AT_type",
	[DW_AT_use_location] = "DW_AT_use_location",
	[DW_AT_variable_parameter] = "DW_AT_variable_parameter",
	[DW_AT_virtuality] = "DW_AT_virtuality",
	[DW_AT_vtable_elem_location] = "DW_AT_vtable_elem_location",
	[DW_AT_allocated] = "DW_AT_allocated",
	[DW_AT_associated] = "DW_AT_associated",
	[DW_AT_data_location] = "DW_AT_data_location",
	[DW_AT_byte_stride] = "DW_AT_byte_stride",
	[DW_AT_entry_pc] = "DW_AT_entry_pc",
	[DW_AT_use_UTF8] = "DW_AT_use_UTF8",
	[DW_AT_extension] = "DW_AT_extension",
	[DW_AT_ranges] = "DW_AT_ranges",
	[DW_AT_trampoline] = "DW_AT_trampoline",
	[DW_AT_call_column] = "DW_AT_call_column",
	[DW_AT_call_file] = "DW_AT_call_file",
	[DW_AT_call_line] = "DW_AT_call_line",
	[DW_AT_description] = "DW_AT_description",
	[DW_AT_binary_scale] = "DW_AT_binary_scale",
	[DW_AT_decimal_scale] = "DW_AT_decimal_scale",
	[DW_AT_small] = "DW_AT_small",
	[DW_AT_decimal_sign] = "DW_AT_decimal_sign",
	[DW_AT_digit_count] = "DW_AT_digit_count",
	[DW_AT_picture_string] = "DW_AT_picture_string",
	[DW_AT_mutable] = "DW_AT_mutable",
	[DW_AT_threads_scaled] = "DW_AT_threads_scaled",
	[DW_AT_explicit] = "DW_AT_explicit",
	[DW_AT_object_pointer] = "DW_AT_object_pointer",
	[DW_AT_endianity] = "DW_AT_endianity",
	[DW_AT_elemental] = "DW_AT_elemental",
	[DW_AT_pure] = "DW_AT_pure",
	[DW_AT_recursive] = "DW_AT_recursive",
	[DW_AT_signature] = "DW_AT_signature",
	[DW_AT_main_subprogram] = "DW_AT_main_subprogram",
	[DW_AT_data_bit_offset] = "DW_AT_data_big_offset",
	[DW_AT_const_expr] = "DW_AT_const_expr",
	[DW_AT_enum_class] = "DW_AT_enum_class",
	[DW_AT_linkage_name] = "DW_AT_linkage_name",
	[DW_AT_string_length_bit_size] = "DW_AT_string_length_bit_size",
	[DW_AT_string_length_byte_size] = "DW_AT_string_length_byte_size",
	[DW_AT_rank] = "DW_AT_rank",
	[DW_AT_str_offsets_base] = "DW_AT_str_offsets_base",
	[DW_AT_addr_base] = "DW_AT_addr_base",
	[DW_AT_rnglists_base] = "DW_AT_rnglists_base",
	[DW_AT_dwo_name] = "DW_AT_dwo_name",
	[DW_AT_reference] = "DW_AT_reference",
	[DW_AT_rvalue_reference] = "DW_AT_rvalue_reference",
	[DW_AT_macros] = "DW_AT_macros",
	[DW_AT_call_all_calls] = "DW_AT_call_all_calls",
	[DW_AT_call_all_source_calls] = "DW_AT_call_all_source_calls",
	[DW_AT_call_all_tail_calls] = "DW_AT_call_all_tail_calls",
	[DW_AT_call_return_pc] = "DW_AT_call_return_pc",
	[DW_AT_call_value] = "DW_AT_call_value",
	[DW_AT_call_origin] = "DW_AT_call_origin",
	[DW_AT_call_parameter] = "DW_AT_call_parameter",
	[DW_AT_call_pc] = "DW_AT_call_pc",
	[DW_AT_call_tail_call] = "DW_AT_call_tail_call",
	[DW_AT_call_target] = "DW_AT_call_target",
	[DW_AT_call_target_clobbered] = "DW_AT_call_target_clobbered",
	[DW_AT_call_data_location] = "DW_AT_call_data_location",
	[DW_AT_call_data_value] = "DW_AT_call_data_value",
	[DW_AT_noreturn] = "DW_AT_noreturn",
	[DW_AT_alignment] = "DW_AT_alignment",
	[DW_AT_export_symbols] = "DW_AT_export_symbols",
	[DW_AT_deleted] = "DW_AT_deleted",
	[DW_AT_defaulted] = "DW_AT_defaulted",
	[DW_AT_loclists_base] = "DW_AT_loclists_base"
};

static const char *dwarf_attr_form_encodings[] = {
	[DW_FORM_addr] = "DW_FORM_addr",
	[DW_FORM_block2] = "DW_FORM_block2",
	[DW_FORM_block4] = "DW_FORM_block4",
	[DW_FORM_data2] = "DW_FORM_data2",
	[DW_FORM_data4] = "DW_FORM_data4",
	[DW_FORM_data8] = "DW_FORM_data8",
	[DW_FORM_string] = "DW_FORM_string",
	[DW_FORM_block] = "DW_FORM_block",
	[DW_FORM_block1] = "DW_FORM_block1",
	[DW_FORM_data1] = "DW_FORM_data1",
	[DW_FORM_flag] = "DW_FORM_flag",
	[DW_FORM_sdata] = "DW_FORM_sdata",
	[DW_FORM_strp] = "DW_FORM_strp",
	[DW_FORM_udata] = "DW_FORM_udata",
	[DW_FORM_ref_addr] = "DW_FORM_ref_addr",
	[DW_FORM_ref1] = "DW_FORM_ref1",
	[DW_FORM_ref2] = "DW_FORM_ref2",
	[DW_FORM_ref4] = "DW_FORM_ref4",
	[DW_FORM_ref8] = "DW_FORM_ref8",
	[DW_FORM_ref_udata] = "DW_FORM_ref_udata",
	[DW_FORM_indirect] = "DW_FORM_indirect",
	[DW_FORM_sec_offset] = "DW_FORM_sec_offset",
	[DW_FORM_exprloc] = "DW_FORM_exprloc",
	[DW_FORM_flag_present] = "DW_FORM_flag_present",
	[DW_FORM_strx] = "DW_FORM_strx",
	[DW_FORM_addrx] = "DW_FORM_addrx",
	[DW_FORM_ref_sup4] = "DW_FORM_ref_sup4",
	[DW_FORM_strp_sup] = "DW_FORM_strp_sup",
	[DW_FORM_data16] = "DW_FORM_data16",
	[DW_FORM_line_ptr] = "DW_FORM_line_ptr",
	[DW_FORM_ref_sig8] = "DW_FORM_ref_sig8",
	[DW_FORM_implicit_const] = "DW_FORM_implicit_const",
	[DW_FORM_loclistx] = "DW_FORM_loclistx",
	[DW_FORM_rnglistx] = "DW_FORM_rnglistx",
	[DW_FORM_ref_sup8] = "DW_FORM_ref_sup8",
	[DW_FORM_strx1] = "DW_FORM_strx1",
	[DW_FORM_strx2] = "DW_FORM_strx2",
	[DW_FORM_strx3] = "DW_FORM_strx3",
	[DW_FORM_strx4] = "DW_FORM_strx4",
	[DW_FORM_addrx1] = "DW_FORM_addrx1",
	[DW_FORM_addrx2] = "DW_FORM_addrx2",
	[DW_FORM_addrx3] = "DW_FORM_addrx3",
	[DW_FORM_addrx4] = "DW_FORM_addrx4",
	[DW_FORM_GNU_addr_index] = "DW_FORM_GNU_addr_index",
	[DW_FORM_GNU_str_index] = "DW_FORM_GNU_str_index",
	[DW_FORM_GNU_ref_alt] = "DW_FORM_GNU_ref_alt",
	[DW_FORM_GNU_strp_alt] = "DW_FORM_GNU_strp_alt",
};

static const char *dwarf_langs[] = {
	[DW_LANG_C89] = "C89",
	[DW_LANG_C] = "C",
	[DW_LANG_Ada83] = "Ada83",
	[DW_LANG_C_plus_plus] = "C++",
	[DW_LANG_Cobol74] = "Cobol74",
	[DW_LANG_Cobol85] = "Cobol85",
	[DW_LANG_Fortran77] = "Fortran77",
	[DW_LANG_Fortran90] = "Fortran90",
	[DW_LANG_Pascal83] = "Pascal83",
	[DW_LANG_Modula2] = "Modula2",
	[DW_LANG_Java] = "Java",
	[DW_LANG_C99] = "C99",
	[DW_LANG_Ada95] = "Ada95",
	[DW_LANG_Fortran95] = "Fortran95",
	[DW_LANG_PLI] = "PLI",
	[DW_LANG_ObjC] = "ObjC",
	[DW_LANG_ObjC_plus_plus] = "ObjC_plus_plus",
	[DW_LANG_UPC] = "UPC",
	[DW_LANG_D] = "D",
	[DW_LANG_Python] = "Python",
	[DW_LANG_Rust] = "Rust",
	[DW_LANG_C11] = "C11",
	[DW_LANG_Swift] = "Swift",
	[DW_LANG_Julia] = "Julia",
	[DW_LANG_Dylan] = "Dylan",
	[DW_LANG_C_plus_plus_14] = "C++14",
	[DW_LANG_Fortran03] = "Fortran03",
	[DW_LANG_Fortran08] = "Fortran08",
	[DW_LANG_RenderScript] = "RenderScript",
	[DW_LANG_BLISS] = "BLISS",
	[DW_LANG_Kotlin] = "Kotlin",
	[DW_LANG_Zig] = "Zig",
	[DW_LANG_Crystal] = "Crystal",
	[DW_LANG_C_plus_plus_17] = "C_plus_plus_17",
	[DW_LANG_C_plus_plus_20] = "C_plus_plus_20",
	[DW_LANG_C17] = "C17",
	[DW_LANG_Fortran18] = "Fortran18",
	[DW_LANG_Ada2005] = "Ada2005",
	[DW_LANG_Ada2012] = "Ada2012",
	[DW_LANG_HIP] = "HIP",
	[DW_LANG_Assembly] = "Assembly",
	[DW_LANG_C_sharp] = "C_sharp",
	[DW_LANG_Mojo] = "Mojo",
};

static const char *dwarf_langs_for_demangle[] = {
	[DW_LANG_C89] = "c",
	[DW_LANG_C] = "c",
	[DW_LANG_Ada83] = "ada",
	[DW_LANG_C_plus_plus] = "cxx",
	[DW_LANG_Cobol74] = "cobol",
	[DW_LANG_Cobol85] = "cobol",
	[DW_LANG_Fortran77] = "fortran",
	[DW_LANG_Fortran90] = "fortran",
	[DW_LANG_Pascal83] = "pascal",
	[DW_LANG_Modula2] = "modula2",
	[DW_LANG_Java] = "java",
	[DW_LANG_C99] = "c",
	[DW_LANG_Ada95] = "ada",
	[DW_LANG_Fortran95] = "fortran",
	[DW_LANG_PLI] = "PLI",
	[DW_LANG_ObjC] = "ObjC",
	[DW_LANG_ObjC_plus_plus] = "ObjC_plus_plus",
	[DW_LANG_UPC] = "UPC",
	[DW_LANG_D] = "dlang",
	[DW_LANG_Python] = "python",
	[DW_LANG_Rust] = "rust",
	[DW_LANG_C11] = "cxx",
	[DW_LANG_Swift] = "swift",
	[DW_LANG_Julia] = "julia",
	[DW_LANG_Dylan] = "Dylan",
	[DW_LANG_C_plus_plus_14] = "cxx",
	[DW_LANG_Fortran03] = "fortran",
	[DW_LANG_Fortran08] = "fortran",
	[DW_LANG_RenderScript] = "RenderScript",
	[DW_LANG_BLISS] = "BLISS",
	[DW_LANG_Kotlin] = "kotlin",
	[DW_LANG_Zig] = "zig",
	[DW_LANG_Crystal] = "crystal",
	[DW_LANG_C_plus_plus_17] = "cxx",
	[DW_LANG_C_plus_plus_20] = "cxx",
	[DW_LANG_C17] = "c",
	[DW_LANG_Fortran18] = "fortran",
	[DW_LANG_Ada2005] = "ada",
	[DW_LANG_Ada2012] = "ada",
	[DW_LANG_HIP] = "HIP",
	[DW_LANG_Assembly] = "assembly",
	[DW_LANG_C_sharp] = "csharp",
	[DW_LANG_Mojo] = "mojo",
};

static const char *dwarf_unit_types[] = {
	[DW_UT_compile] = "DW_UT_compile",
	[DW_UT_type] = "DW_UT_type",
	[DW_UT_partial] = "DW_UT_partial",
	[DW_UT_skeleton] = "DW_UT_skeleton",
	[DW_UT_split_compile] = "DW_UT_split_compile",
	[DW_UT_split_type] = "DW_UT_split_type",
};

RZ_API const char *rz_bin_dwarf_tag(enum DW_TAG tag) {
	if (tag < RZ_ARRAY_SIZE(dwarf_tag_name_encodings)) {
		return dwarf_tag_name_encodings[tag];
	}

	switch (tag) {
		DW_(DW_TAG_MIPS_loop);
		DW_(DW_TAG_HP_array_descriptor);
		DW_(DW_TAG_HP_Bliss_field);
		DW_(DW_TAG_HP_Bliss_field_set);
		DW_(DW_TAG_format_label);
		DW_(DW_TAG_function_template);
		DW_(DW_TAG_class_template);
		DW_(DW_TAG_GNU_BINCL);
		DW_(DW_TAG_GNU_EINCL);
		DW_(DW_TAG_GNU_template_template_param);
		DW_(DW_TAG_GNU_template_parameter_pack);
		DW_(DW_TAG_GNU_formal_parameter_pack);
		DW_(DW_TAG_GNU_call_site);
		DW_(DW_TAG_GNU_call_site_parameter);
		DW_(DW_TAG_APPLE_property);
		DW_(DW_TAG_SUN_function_template);
		DW_(DW_TAG_SUN_class_template);
		DW_(DW_TAG_SUN_struct_template);
		DW_(DW_TAG_SUN_union_template);
		DW_(DW_TAG_SUN_indirect_inheritance);
		DW_(DW_TAG_SUN_codeflags);
		DW_(DW_TAG_SUN_memop_info);
		DW_(DW_TAG_SUN_omp_child_func);
		DW_(DW_TAG_SUN_rtti_descriptor);
		DW_(DW_TAG_SUN_dtor_info);
		DW_(DW_TAG_SUN_dtor);
		DW_(DW_TAG_SUN_f90_interface);
		DW_(DW_TAG_SUN_fortran_vax_structure);
		DW_(DW_TAG_ALTIUM_circ_type);
		DW_(DW_TAG_ALTIUM_mwa_circ_type);
		DW_(DW_TAG_ALTIUM_rev_carry_type);
		DW_(DW_TAG_ALTIUM_rom);
		DW_(DW_TAG_upc_shared_type);
		DW_(DW_TAG_upc_strict_type);
		DW_(DW_TAG_upc_relaxed_type);
		DW_(DW_TAG_PGI_kanji_type);
		DW_(DW_TAG_PGI_interface_block);
		DW_(DW_TAG_BORLAND_property);
		DW_(DW_TAG_BORLAND_Delphi_string);
		DW_(DW_TAG_BORLAND_Delphi_dynamic_array);
		DW_(DW_TAG_BORLAND_Delphi_set);
		DW_(DW_TAG_BORLAND_Delphi_variant);
	default:
		return NULL;
	};
}

RZ_API const char *rz_bin_dwarf_attr(enum DW_AT attr_code) {
	if (attr_code < RZ_ARRAY_SIZE(dwarf_attr_encodings)) {
		return dwarf_attr_encodings[attr_code];
	}

	// the below codes are much sparser, so putting them in an array would require a lot of
	// unused memory
	switch (attr_code) {
		DW_(DW_AT_MIPS_fde);
		DW_(DW_AT_MIPS_loop_begin);
		DW_(DW_AT_MIPS_tail_loop_begin);
		DW_(DW_AT_MIPS_epilog_begin);
		DW_(DW_AT_MIPS_loop_unroll_factor);
		DW_(DW_AT_MIPS_software_pipeline_depth);
		DW_(DW_AT_MIPS_linkage_name);
		DW_(DW_AT_MIPS_stride);
		DW_(DW_AT_MIPS_abstract_name);
		DW_(DW_AT_MIPS_clone_origin);
		DW_(DW_AT_MIPS_has_inlines);
		DW_(DW_AT_MIPS_stride_byte);
		DW_(DW_AT_MIPS_stride_elem);
		DW_(DW_AT_MIPS_ptr_dopetype);
		DW_(DW_AT_MIPS_allocatable_dopetype);
		DW_(DW_AT_MIPS_assumed_shape_dopetype);
		DW_(DW_AT_MIPS_assumed_size);
		DW_(DW_AT_sf_names);
		DW_(DW_AT_src_info);
		DW_(DW_AT_mac_info);
		DW_(DW_AT_src_coords);
		DW_(DW_AT_body_begin);
		DW_(DW_AT_body_end);
		DW_(DW_AT_GNU_vector);
		DW_(DW_AT_GNU_guarded_by);
		DW_(DW_AT_GNU_pt_guarded_by);
		DW_(DW_AT_GNU_guarded);
		DW_(DW_AT_GNU_pt_guarded);
		DW_(DW_AT_GNU_locks_excluded);
		DW_(DW_AT_GNU_exclusive_locks_required);
		DW_(DW_AT_GNU_shared_locks_required);
		DW_(DW_AT_GNU_odr_signature);
		DW_(DW_AT_GNU_template_name);
		DW_(DW_AT_GNU_call_site_value);
		DW_(DW_AT_GNU_call_site_data_value);
		DW_(DW_AT_GNU_call_site_target);
		DW_(DW_AT_GNU_call_site_target_clobbered);
		DW_(DW_AT_GNU_tail_call);
		DW_(DW_AT_GNU_all_tail_call_sites);
		DW_(DW_AT_GNU_all_call_sites);
		DW_(DW_AT_GNU_all_source_call_sites);
		DW_(DW_AT_GNU_macros);
		DW_(DW_AT_GNU_deleted);
		DW_(DW_AT_GNU_dwo_name);
		DW_(DW_AT_GNU_dwo_id);
		DW_(DW_AT_GNU_ranges_base);
		DW_(DW_AT_GNU_addr_base);
		DW_(DW_AT_GNU_pubnames);
		DW_(DW_AT_GNU_pubtypes);
		DW_(DW_AT_GNU_discriminator);
		DW_(DW_AT_GNU_locviews);
		DW_(DW_AT_GNU_entry_view);
		DW_(DW_AT_SUN_template);
		DW_(DW_AT_SUN_alignment);
		DW_(DW_AT_SUN_vtable);
		DW_(DW_AT_SUN_count_guarantee);
		DW_(DW_AT_SUN_command_line);
		DW_(DW_AT_SUN_vbase);
		DW_(DW_AT_SUN_compile_options);
		DW_(DW_AT_SUN_language);
		DW_(DW_AT_SUN_browser_file);
		DW_(DW_AT_SUN_vtable_abi);
		DW_(DW_AT_SUN_func_offsets);
		DW_(DW_AT_SUN_cf_kind);
		DW_(DW_AT_SUN_vtable_index);
		DW_(DW_AT_SUN_omp_tpriv_addr);
		DW_(DW_AT_SUN_omp_child_func);
		DW_(DW_AT_SUN_func_offset);
		DW_(DW_AT_SUN_memop_type_ref);
		DW_(DW_AT_SUN_profile_id);
		DW_(DW_AT_SUN_memop_signature);
		DW_(DW_AT_SUN_obj_dir);
		DW_(DW_AT_SUN_obj_file);
		DW_(DW_AT_SUN_original_name);
		DW_(DW_AT_SUN_hwcprof_signature);
		DW_(DW_AT_SUN_amd64_parmdump);
		DW_(DW_AT_SUN_part_link_name);
		DW_(DW_AT_SUN_link_name);
		DW_(DW_AT_SUN_pass_with_const);
		DW_(DW_AT_SUN_return_with_const);
		DW_(DW_AT_SUN_import_by_name);
		DW_(DW_AT_SUN_f90_pointer);
		DW_(DW_AT_SUN_pass_by_ref);
		DW_(DW_AT_SUN_f90_allocatable);
		DW_(DW_AT_SUN_f90_assumed_shape_array);
		DW_(DW_AT_SUN_c_vla);
		DW_(DW_AT_SUN_return_value_ptr);
		DW_(DW_AT_SUN_dtor_start);
		DW_(DW_AT_SUN_dtor_length);
		DW_(DW_AT_SUN_dtor_state_initial);
		DW_(DW_AT_SUN_dtor_state_final);
		DW_(DW_AT_SUN_dtor_state_deltas);
		DW_(DW_AT_SUN_import_by_lname);
		DW_(DW_AT_SUN_f90_use_only);
		DW_(DW_AT_SUN_namelist_spec);
		DW_(DW_AT_SUN_is_omp_child_func);
		DW_(DW_AT_SUN_fortran_main_alias);
		DW_(DW_AT_SUN_fortran_based);
		DW_(DW_AT_ALTIUM_loclist);
		DW_(DW_AT_use_GNAT_descriptive_type);
		DW_(DW_AT_GNAT_descriptive_type);
		DW_(DW_AT_GNU_numerator);
		DW_(DW_AT_GNU_denominator);
		DW_(DW_AT_GNU_bias);
		DW_(DW_AT_upc_threads_scaled);
		DW_(DW_AT_PGI_lbase);
		DW_(DW_AT_PGI_soffset);
		DW_(DW_AT_PGI_lstride);
		DW_(DW_AT_BORLAND_property_read);
		DW_(DW_AT_BORLAND_property_write);
		DW_(DW_AT_BORLAND_property_implements);
		DW_(DW_AT_BORLAND_property_index);
		DW_(DW_AT_BORLAND_property_default);
		DW_(DW_AT_BORLAND_Delphi_unit);
		DW_(DW_AT_BORLAND_Delphi_class);
		DW_(DW_AT_BORLAND_Delphi_record);
		DW_(DW_AT_BORLAND_Delphi_metaclass);
		DW_(DW_AT_BORLAND_Delphi_constructor);
		DW_(DW_AT_BORLAND_Delphi_destructor);
		DW_(DW_AT_BORLAND_Delphi_anonymous_method);
		DW_(DW_AT_BORLAND_Delphi_interface);
		DW_(DW_AT_BORLAND_Delphi_ABI);
		DW_(DW_AT_BORLAND_Delphi_return);
		DW_(DW_AT_BORLAND_Delphi_frameptr);
		DW_(DW_AT_BORLAND_closure);
		DW_(DW_AT_LLVM_include_path);
		DW_(DW_AT_LLVM_config_macros);
		DW_(DW_AT_LLVM_isysroot);
		DW_(DW_AT_APPLE_optimized);
		DW_(DW_AT_APPLE_flags);
		DW_(DW_AT_APPLE_isa);
		DW_(DW_AT_APPLE_block);
		DW_(DW_AT_APPLE_major_runtime_vers);
		DW_(DW_AT_APPLE_runtime_class);
		DW_(DW_AT_APPLE_omit_frame_ptr);
		DW_(DW_AT_APPLE_property_name);
		DW_(DW_AT_APPLE_property_getter);
		DW_(DW_AT_APPLE_property_setter);
		DW_(DW_AT_APPLE_property_attribute);
		DW_(DW_AT_APPLE_objc_complete_type);
		DW_(DW_AT_APPLE_property);
	default:
		return NULL;
	}
}

RZ_API const char *rz_bin_dwarf_form(enum DW_FORM form_code) {
	if (form_code < RZ_ARRAY_SIZE(dwarf_attr_form_encodings)) {
		return dwarf_attr_form_encodings[form_code];
	}
	switch (form_code) {
		DW_(DW_FORM_GNU_addr_index);
		DW_(DW_FORM_GNU_str_index);
		DW_(DW_FORM_GNU_ref_alt);
		DW_(DW_FORM_GNU_strp_alt);
	default: return NULL;
	}
}

RZ_API const char *rz_bin_dwarf_unit_type(enum DW_UT unit_type) {
	if (!unit_type || unit_type > DW_UT_split_type) {
		return NULL;
	}
	return dwarf_unit_types[unit_type];
}

RZ_API const char *rz_bin_dwarf_lang(enum DW_LANG lang) {
	if (lang <= RZ_ARRAY_SIZE(dwarf_langs)) {
		return dwarf_langs[lang];
	}

	switch (lang) {
		DW_(DW_LANG_Mips_Assembler);
		DW_(DW_LANG_GOOGLE_RenderScript);
		DW_(DW_LANG_SUN_Assembler);
		DW_(DW_LANG_ALTIUM_Assembler);
		DW_(DW_LANG_BORLAND_Delphi);
	default: return NULL;
	}
}

RZ_API const char *rz_bin_dwarf_lang_for_demangle(enum DW_LANG lang) {
	if (!(lang >= RZ_ARRAY_SIZE(dwarf_langs_for_demangle)))
		return dwarf_langs_for_demangle[lang];
	return NULL;
}

static const char *dwarf_children[] = {
	[DW_CHILDREN_yes] = "DW_CHILDREN_yes",
	[DW_CHILDREN_no] = "DW_CHILDREN_no",
};

RZ_API const char *rz_bin_dwarf_children(enum DW_CHILDREN children) {
	if (children >= RZ_ARRAY_SIZE(dwarf_children)) {
		return NULL;
	}
	return dwarf_children[children];
}

static const char *dwarf_lns[] = {
	[DW_LNS_copy] = "DW_LNS_copy",
	[DW_LNS_advance_pc] = "DW_LNS_advance_pc",
	[DW_LNS_advance_line] = "DW_LNS_advance_line",
	[DW_LNS_set_file] = "DW_LNS_set_file",
	[DW_LNS_set_column] = "DW_LNS_set_column",
	[DW_LNS_negate_stmt] = "DW_LNS_negate_stmt",
	[DW_LNS_set_basic_block] = "DW_LNS_set_basic_block",
	[DW_LNS_const_add_pc] = "DW_LNS_const_add_pc",
	[DW_LNS_fixed_advance_pc] = "DW_LNS_fixed_advance_pc",
	[DW_LNS_set_prologue_end] = "DW_LNS_set_prologue_end",
	[DW_LNS_set_epilogue_begin] = "DW_LNS_set_epilogue_begin",
	[DW_LNS_set_isa] = "DW_LNS_set_isa",
};

RZ_API const char *rz_bin_dwarf_lns(enum DW_LNS lns) {
	if (lns >= RZ_ARRAY_SIZE(dwarf_lns)) {
		return NULL;
	}
	return dwarf_lns[lns];
}

static const char *dwarf_lne[] = {
	[DW_LNE_end_sequence] = "DW_LNE_end_sequence",
	[DW_LNE_set_address] = "DW_LNE_set_address",
	[DW_LNE_define_file] = "DW_LNE_define_file",
	[DW_LNE_set_discriminator] = "DW_LNE_set_discriminator",
};

RZ_API const char *rz_bin_dwarf_lne(enum DW_LNE lne) {
	if (lne >= RZ_ARRAY_SIZE(dwarf_lne)) {
		return NULL;
	}
	return dwarf_lne[lne];
}

static const char *dwarf_lnct[] = {
	[DW_LNCT_path] = "DW_LNCT_path",
	[DW_LNCT_directory_index] = "DW_LNCT_directory_index",
	[DW_LNCT_timestamp] = "DW_LNCT_timestamp",
	[DW_LNCT_size] = "DW_LNCT_size",
	[DW_LNCT_MD5] = "DW_LNCT_MD5",
};

RZ_API const char *rz_bin_dwarf_lnct(enum DW_LNCT lnct) {
	if (lnct >= RZ_ARRAY_SIZE(dwarf_lnct)) {
		return NULL;
	}
	return dwarf_lnct[lnct];
}

static const char *dwarf_op[] = {
	[DW_OP_addr] = "DW_OP_addr",
	[DW_OP_deref] = "DW_OP_deref",
	[DW_OP_const1u] = "DW_OP_const1u",
	[DW_OP_const1s] = "DW_OP_const1s",
	[DW_OP_const2u] = "DW_OP_const2u",
	[DW_OP_const2s] = "DW_OP_const2s",
	[DW_OP_const4u] = "DW_OP_const4u",
	[DW_OP_const4s] = "DW_OP_const4s",
	[DW_OP_const8u] = "DW_OP_const8u",
	[DW_OP_const8s] = "DW_OP_const8s",
	[DW_OP_constu] = "DW_OP_constu",
	[DW_OP_consts] = "DW_OP_consts",
	[DW_OP_dup] = "DW_OP_dup",
	[DW_OP_drop] = "DW_OP_drop",
	[DW_OP_over] = "DW_OP_over",
	[DW_OP_pick] = "DW_OP_pick",
	[DW_OP_swap] = "DW_OP_swap",
	[DW_OP_rot] = "DW_OP_rot",
	[DW_OP_xderef] = "DW_OP_xderef",
	[DW_OP_abs] = "DW_OP_abs",
	[DW_OP_and] = "DW_OP_and",
	[DW_OP_div] = "DW_OP_div",
	[DW_OP_minus] = "DW_OP_minus",
	[DW_OP_mod] = "DW_OP_mod",
	[DW_OP_mul] = "DW_OP_mul",
	[DW_OP_neg] = "DW_OP_neg",
	[DW_OP_not] = "DW_OP_not",
	[DW_OP_or] = "DW_OP_or",
	[DW_OP_plus] = "DW_OP_plus",
	[DW_OP_plus_uconst] = "DW_OP_plus_uconst",
	[DW_OP_shl] = "DW_OP_shl",
	[DW_OP_shr] = "DW_OP_shr",
	[DW_OP_shra] = "DW_OP_shra",
	[DW_OP_xor] = "DW_OP_xor",
	[DW_OP_skip] = "DW_OP_skip",
	[DW_OP_bra] = "DW_OP_bra",
	[DW_OP_eq] = "DW_OP_eq",
	[DW_OP_ge] = "DW_OP_ge",
	[DW_OP_gt] = "DW_OP_gt",
	[DW_OP_le] = "DW_OP_le",
	[DW_OP_lt] = "DW_OP_lt",
	[DW_OP_ne] = "DW_OP_ne",
	[DW_OP_lit0] = "DW_OP_lit0",
	[DW_OP_lit1] = "DW_OP_lit1",
	[DW_OP_lit2] = "DW_OP_lit2",
	[DW_OP_lit3] = "DW_OP_lit3",
	[DW_OP_lit4] = "DW_OP_lit4",
	[DW_OP_lit5] = "DW_OP_lit5",
	[DW_OP_lit6] = "DW_OP_lit6",
	[DW_OP_lit7] = "DW_OP_lit7",
	[DW_OP_lit8] = "DW_OP_lit8",
	[DW_OP_lit9] = "DW_OP_lit9",
	[DW_OP_lit10] = "DW_OP_lit10",
	[DW_OP_lit11] = "DW_OP_lit11",
	[DW_OP_lit12] = "DW_OP_lit12",
	[DW_OP_lit13] = "DW_OP_lit13",
	[DW_OP_lit14] = "DW_OP_lit14",
	[DW_OP_lit15] = "DW_OP_lit15",
	[DW_OP_lit16] = "DW_OP_lit16",
	[DW_OP_lit17] = "DW_OP_lit17",
	[DW_OP_lit18] = "DW_OP_lit18",
	[DW_OP_lit19] = "DW_OP_lit19",
	[DW_OP_lit20] = "DW_OP_lit20",
	[DW_OP_lit21] = "DW_OP_lit21",
	[DW_OP_lit22] = "DW_OP_lit22",
	[DW_OP_lit23] = "DW_OP_lit23",
	[DW_OP_lit24] = "DW_OP_lit24",
	[DW_OP_lit25] = "DW_OP_lit25",
	[DW_OP_lit26] = "DW_OP_lit26",
	[DW_OP_lit27] = "DW_OP_lit27",
	[DW_OP_lit28] = "DW_OP_lit28",
	[DW_OP_lit29] = "DW_OP_lit29",
	[DW_OP_lit30] = "DW_OP_lit30",
	[DW_OP_lit31] = "DW_OP_lit31",
	[DW_OP_reg0] = "DW_OP_reg0",
	[DW_OP_reg1] = "DW_OP_reg1",
	[DW_OP_reg2] = "DW_OP_reg2",
	[DW_OP_reg3] = "DW_OP_reg3",
	[DW_OP_reg4] = "DW_OP_reg4",
	[DW_OP_reg5] = "DW_OP_reg5",
	[DW_OP_reg6] = "DW_OP_reg6",
	[DW_OP_reg7] = "DW_OP_reg7",
	[DW_OP_reg8] = "DW_OP_reg8",
	[DW_OP_reg9] = "DW_OP_reg9",
	[DW_OP_reg10] = "DW_OP_reg10",
	[DW_OP_reg11] = "DW_OP_reg11",
	[DW_OP_reg12] = "DW_OP_reg12",
	[DW_OP_reg13] = "DW_OP_reg13",
	[DW_OP_reg14] = "DW_OP_reg14",
	[DW_OP_reg15] = "DW_OP_reg15",
	[DW_OP_reg16] = "DW_OP_reg16",
	[DW_OP_reg17] = "DW_OP_reg17",
	[DW_OP_reg18] = "DW_OP_reg18",
	[DW_OP_reg19] = "DW_OP_reg19",
	[DW_OP_reg20] = "DW_OP_reg20",
	[DW_OP_reg21] = "DW_OP_reg21",
	[DW_OP_reg22] = "DW_OP_reg22",
	[DW_OP_reg23] = "DW_OP_reg23",
	[DW_OP_reg24] = "DW_OP_reg24",
	[DW_OP_reg25] = "DW_OP_reg25",
	[DW_OP_reg26] = "DW_OP_reg26",
	[DW_OP_reg27] = "DW_OP_reg27",
	[DW_OP_reg28] = "DW_OP_reg28",
	[DW_OP_reg29] = "DW_OP_reg29",
	[DW_OP_reg30] = "DW_OP_reg30",
	[DW_OP_reg31] = "DW_OP_reg31",
	[DW_OP_breg0] = "DW_OP_breg0",
	[DW_OP_breg1] = "DW_OP_breg1",
	[DW_OP_breg2] = "DW_OP_breg2",
	[DW_OP_breg3] = "DW_OP_breg3",
	[DW_OP_breg4] = "DW_OP_breg4",
	[DW_OP_breg5] = "DW_OP_breg5",
	[DW_OP_breg6] = "DW_OP_breg6",
	[DW_OP_breg7] = "DW_OP_breg7",
	[DW_OP_breg8] = "DW_OP_breg8",
	[DW_OP_breg9] = "DW_OP_breg9",
	[DW_OP_breg10] = "DW_OP_breg10",
	[DW_OP_breg11] = "DW_OP_breg11",
	[DW_OP_breg12] = "DW_OP_breg12",
	[DW_OP_breg13] = "DW_OP_breg13",
	[DW_OP_breg14] = "DW_OP_breg14",
	[DW_OP_breg15] = "DW_OP_breg15",
	[DW_OP_breg16] = "DW_OP_breg16",
	[DW_OP_breg17] = "DW_OP_breg17",
	[DW_OP_breg18] = "DW_OP_breg18",
	[DW_OP_breg19] = "DW_OP_breg19",
	[DW_OP_breg20] = "DW_OP_breg20",
	[DW_OP_breg21] = "DW_OP_breg21",
	[DW_OP_breg22] = "DW_OP_breg22",
	[DW_OP_breg23] = "DW_OP_breg23",
	[DW_OP_breg24] = "DW_OP_breg24",
	[DW_OP_breg25] = "DW_OP_breg25",
	[DW_OP_breg26] = "DW_OP_breg26",
	[DW_OP_breg27] = "DW_OP_breg27",
	[DW_OP_breg28] = "DW_OP_breg28",
	[DW_OP_breg29] = "DW_OP_breg29",
	[DW_OP_breg30] = "DW_OP_breg30",
	[DW_OP_breg31] = "DW_OP_breg31",
	[DW_OP_regx] = "DW_OP_regx",
	[DW_OP_fbreg] = "DW_OP_fbreg",
	[DW_OP_bregx] = "DW_OP_bregx",
	[DW_OP_piece] = "DW_OP_piece",
	[DW_OP_deref_size] = "DW_OP_deref_size",
	[DW_OP_xderef_size] = "DW_OP_xderef_size",
	[DW_OP_nop] = "DW_OP_nop",
	[DW_OP_push_object_address] = "DW_OP_push_object_address",
	[DW_OP_call2] = "DW_OP_call2",
	[DW_OP_call4] = "DW_OP_call4",
	[DW_OP_call_ref] = "DW_OP_call_ref",
	[DW_OP_form_tls_address] = "DW_OP_form_tls_address",
	[DW_OP_call_frame_cfa] = "DW_OP_call_frame_cfa",
	[DW_OP_bit_piece] = "DW_OP_bit_piece",
	[DW_OP_implicit_value] = "DW_OP_implicit_value",
	[DW_OP_stack_value] = "DW_OP_stack_value",
	[DW_OP_implicit_pointer] = "DW_OP_implicit_pointer",
	[DW_OP_addrx] = "DW_OP_addrx",
	[DW_OP_constx] = "DW_OP_constx",
	[DW_OP_entry_value] = "DW_OP_entry_value",
	[DW_OP_const_type] = "DW_OP_const_type",
	[DW_OP_regval_type] = "DW_OP_regval_type",
	[DW_OP_deref_type] = "DW_OP_deref_type",
	[DW_OP_xderef_type] = "DW_OP_xderef_type",
	[DW_OP_convert] = "DW_OP_convert",
	[DW_OP_reinterpret] = "DW_OP_reinterpret",
	[DW_OP_GNU_push_tls_address] = "DW_OP_GNU_push_tls_address",
	[DW_OP_GNU_implicit_pointer] = "DW_OP_GNU_implicit_pointer",
	[DW_OP_GNU_entry_value] = "DW_OP_GNU_entry_value",
	[DW_OP_GNU_const_type] = "DW_OP_GNU_const_type",
	[DW_OP_GNU_regval_type] = "DW_OP_GNU_regval_type",
	[DW_OP_GNU_deref_type] = "DW_OP_GNU_deref_type",
	[DW_OP_GNU_convert] = "DW_OP_GNU_convert",
	[DW_OP_GNU_reinterpret] = "DW_OP_GNU_reinterpret",
	[DW_OP_GNU_parameter_ref] = "DW_OP_GNU_parameter_ref",
	[DW_OP_GNU_addr_index] = "DW_OP_GNU_addr_index",
	[DW_OP_GNU_const_index] = "DW_OP_GNU_const_index",
	[DW_OP_WASM_location] = "DW_OP_WASM_location",
};

RZ_API const char *rz_bin_dwarf_op(enum DW_OP op) {
	if (op >= RZ_ARRAY_SIZE(dwarf_op)) {
		return NULL;
	}
	return dwarf_op[op];
}

RZ_IPI bool ListsHeader_parse(RzBinDwarfListsHeader *hdr, RzBuffer *buffer, bool big_endian) {
	bool is_64bit = false;
	ut64 length = 0;
	RET_FALSE_IF_FAIL(buf_read_initial_length(buffer, &is_64bit, &length, big_endian));

	ut16 version = 0;
	U16_OR_RET_FALSE(version);
	if (version != 5) {
		RZ_LOG_ERROR("Invalid version: %d", version);
	}
	ut8 address_size = 0;
	U8_OR_RET_FALSE(address_size);
	ut8 segment_selector_size;
	U8_OR_RET_FALSE(segment_selector_size);
	if (segment_selector_size != 0) {
		RZ_LOG_ERROR("Segment selector size not supported: %d", segment_selector_size);
	}
	ut32 offset_entry_count = 0;
	U32_OR_RET_FALSE(offset_entry_count);

	memset(hdr, 0, sizeof(RzBinDwarfListsHeader));
	hdr->encoding.big_endian = big_endian;
	hdr->encoding.is_64bit = is_64bit;
	hdr->encoding.version = version;
	hdr->encoding.address_size = address_size;
	hdr->unit_length = length;
	hdr->segment_selector_size = segment_selector_size;
	hdr->offset_entry_count = offset_entry_count;

	if (hdr->offset_entry_count > 0) {
		ut64 byte_size = sizeof(ut64) * hdr->offset_entry_count;
		hdr->location_offsets = malloc(byte_size);
		for (ut32 i = 0; i < hdr->offset_entry_count; ++i) {
			if (is_64bit) {
				rz_buf_read_ble64(buffer, &hdr->location_offsets[i], big_endian);
			} else {
				ut32 out = 0;
				rz_buf_read_ble32(buffer, &out, big_endian);
				hdr->location_offsets[i] = (ut64)out;
			}
		}
	}
	return true;
}

RZ_IPI RzBinDwarfBlock *RzBinDwarfBlock_clone(RzBinDwarfBlock *self) {
	RzBinDwarfBlock *clone = rz_new_copy(sizeof(RzBinDwarfBlock), self);
	if (!clone) {
		return NULL;
	}
	if (self->data == NULL) {
		return clone;
	}
	clone->data = RZ_NEWS0(ut8, self->length);
	if (!clone->data) {
		free(clone);
		return NULL;
	}
	memcpy(clone->data, self->data, self->length);
	return clone;
}

RZ_IPI void RzBinDwarfBlock_dump(RzBinDwarfBlock *self, RzStrBuf *sb) {
	rz_strbuf_appendf(sb, " %" PFMT64u, self->length);
	char *data = rz_hex_bin2strdup(self->data, (int)self->length);
	if (data) {
		rz_strbuf_appendf(sb, " %s", data);
		free(data);
	}
}

RZ_IPI void RzBinDwarfBlock_fini(RzBinDwarfBlock *self) {
	if (!self) {
		return;
	}
	free(self->data);
}

RZ_IPI void RzBinDwarfBlock_free(RzBinDwarfBlock *self) {
	if (!self) {
		return;
	}
	free(self->data);
	free(self);
}

/**
 * \brief Read an "initial length" value, as specified by dwarf.
 * This also determines whether it is 64bit or 32bit and reads 4 or 12 bytes respectively.
 */
RZ_IPI bool buf_read_initial_length(RzBuffer *buffer, RZ_OUT bool *is_64bit, ut64 *out, bool big_endian) {
	static const ut64 DWARF32_UNIT_LENGTH_MAX = 0xfffffff0;
	static const ut64 DWARF64_UNIT_LENGTH_INI = 0xffffffff;
	ut32 x32;
	if (!rz_buf_read_ble32(buffer, &x32, big_endian)) {
		return false;
	}
	if (x32 <= DWARF32_UNIT_LENGTH_MAX) {
		*is_64bit = false;
		*out = x32;
	} else if (x32 == DWARF64_UNIT_LENGTH_INI) {
		ut64 x64;
		if (!rz_buf_read_ble64(buffer, &x64, big_endian)) {
			return false;
		}
		*is_64bit = true;
		*out = x64;
	} else {
		RZ_LOG_ERROR("Invalid initial length: 0x%" PFMT32x "\n", x32);
	}
	return true;
}

/**
 * \brief Reads 64/32 bit unsigned based on format
 *
 * \param is_64bit Format of the comp unit
 * \return ut64 Read value
 */
RZ_IPI inline bool buf_read_offset(RzBuffer *buffer, ut64 *out, bool is_64bit, bool big_endian) {
	if (is_64bit) {
		ut64 result;
		U64_OR_RET_FALSE(result);
		*out = result;
	} else {
		ut32 result;
		U32_OR_RET_FALSE(result);
		*out = result;
	}
	return true;
}

RZ_IPI bool buf_read_block(RzBuffer *buffer, RzBinDwarfBlock *block) {
	if (block->length == 0) {
		return true;
	}
	block->data = calloc(sizeof(ut8), block->length);
	RET_FALSE_IF_FAIL(block->data);
	ut16 len = rz_buf_read(buffer, block->data, block->length);
	if (len != block->length) {
		RZ_FREE(block->data);
		return false;
	}
	return true;
}

/**
 * This function is quite incomplete and requires lot of work
 * With parsing various new FORM values
 * \brief Parses attribute value based on its definition
 *        and stores it into `value`
 */
RZ_IPI bool attr_parse(RzBuffer *buffer, RzBinDwarfAttr *value, DwAttrOption *in) {
	rz_return_val_if_fail(in && value && buffer, NULL);

	enum DW_AT name = 0;
	enum DW_FORM form = 0;
	enum DW_LNCT lnct = 0;
	ut8 address_size = 0;
	bool is_64bit = false;
	ut64 unit_offset = 0;
	if (in->type == DW_ATTR_TYPE_DEF) {
		name = in->def->name;
		form = in->def->form;
		address_size = in->comp_unit_hdr->encoding.address_size;
		is_64bit = in->comp_unit_hdr->encoding.is_64bit;
		unit_offset = in->comp_unit_hdr->unit_offset;
	} else if (in->type == DW_ATTR_TYPE_FILE_ENTRY_FORMAT) {
		lnct = in->format->content_type;
		form = in->format->form;
		address_size = in->line_hdr->address_size;
		is_64bit = in->line_hdr->is_64bit;
		unit_offset = in->line_hdr->offset;
	}

	bool big_endian = in->encoding.big_endian;
	RzBuffer *str_buffer = in->str_buffer;

	value->form = form;
	value->name = name;
	value->block.data = NULL;
	value->string.content = NULL;
	value->string.offset = 0;

	// http://www.dwarfstd.org/doc/DWARF4.pdf#page=161&zoom=100,0,560
	switch (form) {
	case DW_FORM_addr:
		value->kind = DW_AT_KIND_ADDRESS;
		UX_OR_RET_FALSE(value->address, address_size);
		break;
	case DW_FORM_data1:
		value->kind = DW_AT_KIND_UCONSTANT;
		U8_OR_RET_FALSE(value->uconstant);
		break;
	case DW_FORM_data2:
		value->kind = DW_AT_KIND_UCONSTANT;
		U16_OR_RET_FALSE(value->uconstant);
		break;
	case DW_FORM_data4:
		value->kind = DW_AT_KIND_UCONSTANT;
		U32_OR_RET_FALSE(value->uconstant);
		break;
	case DW_FORM_data8:
		value->kind = DW_AT_KIND_UCONSTANT;
		U64_OR_RET_FALSE(value->uconstant);
		break;
	case DW_FORM_data16:
		value->kind = DW_AT_KIND_UCONSTANT;
		if (big_endian) {
			U64_OR_RET_FALSE(value->uconstant128.High);
			U64_OR_RET_FALSE(value->uconstant128.Low);
		} else {
			U64_OR_RET_FALSE(value->uconstant128.Low);
			U64_OR_RET_FALSE(value->uconstant128.High);
		}
		break;
	case DW_FORM_sdata:
		value->kind = DW_AT_KIND_CONSTANT;
		SLE128_OR_RET_FALSE(value->sconstant);
		break;
	case DW_FORM_udata:
		value->kind = DW_AT_KIND_UCONSTANT;
		ULE128_OR_RET_FALSE(value->uconstant);
		break;
	case DW_FORM_string:
		value->kind = DW_AT_KIND_STRING;
		value->string.content = buf_get_string(buffer);
#define CHECK_STRING \
	if (!value->string.content) { \
		const char *tag_str = in->type == DW_ATTR_TYPE_DEF ? rz_bin_dwarf_attr(name) : (in->type == DW_ATTR_TYPE_FILE_ENTRY_FORMAT ? rz_bin_dwarf_lnct(lnct) : "unknown"); \
		RZ_LOG_ERROR("Failed to read string %s [%s]\n", tag_str, rz_bin_dwarf_form(form)); \
		return false; \
	}
		CHECK_STRING;
		break;
	case DW_FORM_block1:
		value->kind = DW_AT_KIND_BLOCK;
		U8_OR_RET_FALSE(value->block.length);
		RET_FALSE_IF_FAIL(buf_read_block(buffer, &value->block));
		break;
	case DW_FORM_block2:
		value->kind = DW_AT_KIND_BLOCK;
		U16_OR_RET_FALSE(value->block.length);
		RET_FALSE_IF_FAIL(buf_read_block(buffer, &value->block));
		break;
	case DW_FORM_block4:
		value->kind = DW_AT_KIND_BLOCK;
		U32_OR_RET_FALSE(value->block.length);
		RET_FALSE_IF_FAIL(buf_read_block(buffer, &value->block));
		break;
	case DW_FORM_block: // variable length ULEB128
		value->kind = DW_AT_KIND_BLOCK;
		ULE128_OR_RET_NULL(value->block.length);
		RET_FALSE_IF_FAIL(buf_read_block(buffer, &value->block));
		break;
	case DW_FORM_flag:
		value->kind = DW_AT_KIND_FLAG;
		U8_OR_RET_FALSE(value->flag);
		break;
		// offset in .debug_str
	case DW_FORM_strp:
		value->kind = DW_AT_KIND_STRING;
		RET_FALSE_IF_FAIL(buf_read_offset(buffer, &value->string.offset, is_64bit, big_endian));
		if (str_buffer && value->string.offset < rz_buf_size(str_buffer)) {
			value->string.content = rz_buf_get_string(str_buffer, value->string.offset);
		}
		CHECK_STRING;
		break;
		// offset in .debug_info
	case DW_FORM_ref_addr:
		value->kind = DW_AT_KIND_REFERENCE;
		RET_FALSE_IF_FAIL(buf_read_offset(buffer, &value->reference, is_64bit, big_endian));
		break;
		// This type of reference is an offset from the first byte of the compilation
		// header for the compilation unit containing the reference
	case DW_FORM_ref1:
		value->kind = DW_AT_KIND_REFERENCE;
		U8_OR_RET_FALSE(value->reference);
		value->reference += unit_offset;
		break;
	case DW_FORM_ref2:
		value->kind = DW_AT_KIND_REFERENCE;
		U16_OR_RET_FALSE(value->reference);
		value->reference += unit_offset;
		break;
	case DW_FORM_ref4:
		value->kind = DW_AT_KIND_REFERENCE;
		U32_OR_RET_FALSE(value->reference);
		value->reference += unit_offset;
		break;
	case DW_FORM_ref8:
		value->kind = DW_AT_KIND_REFERENCE;
		U64_OR_RET_FALSE(value->reference);
		value->reference += unit_offset;
		break;
	case DW_FORM_ref_udata:
		value->kind = DW_AT_KIND_REFERENCE;
		ULE128_OR_RET_FALSE(value->reference);
		value->reference += unit_offset;
		break;
		// offset in a section other than .debug_info or .debug_str
	case DW_FORM_sec_offset:
		value->kind = DW_AT_KIND_REFERENCE;
		RET_FALSE_IF_FAIL(buf_read_offset(buffer, &value->reference, is_64bit, big_endian));
		break;
	case DW_FORM_exprloc:
		value->kind = DW_AT_KIND_BLOCK;
		ULE128_OR_RET_FALSE(value->block.length);
		RET_FALSE_IF_FAIL(buf_read_block(buffer, &value->block));
		break;
		// this means that the flag is present, nothing is read
	case DW_FORM_flag_present:
		value->kind = DW_AT_KIND_FLAG;
		value->flag = true;
		break;
	case DW_FORM_ref_sig8:
		value->kind = DW_AT_KIND_REFERENCE;
		U64_OR_RET_NULL(value->reference);
		break;
		// offset into .debug_line_str section, can't parse the section now, so we just skip
	case DW_FORM_strx:
		value->kind = DW_AT_KIND_STRING;
		RET_FALSE_IF_FAIL(buf_read_offset(buffer, &value->string.offset, is_64bit, big_endian));
		// TODO: .debug_line_str
		RZ_LOG_ERROR("TODO: .debug_line_str\n");
		break;
	case DW_FORM_strx1:
		value->kind = DW_AT_KIND_STRING;
		U8_OR_RET_FALSE(value->string.offset);
		break;
	case DW_FORM_strx2:
		value->kind = DW_AT_KIND_STRING;
		U16_OR_RET_FALSE(value->string.offset);
		break;
	case DW_FORM_strx3:
		value->kind = DW_AT_KIND_STRING;
		// TODO: DW_FORM_strx3
		rz_buf_seek(buffer, 3, RZ_BUF_CUR);
		RZ_LOG_ERROR("TODO: DW_FORM_strx3\n");
		break;
	case DW_FORM_strx4:
		value->kind = DW_AT_KIND_STRING;
		U32_OR_RET_FALSE(value->string.offset);
		break;
	case DW_FORM_implicit_const:
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = in->type == DW_ATTR_TYPE_DEF ? in->def->special : 0;
		break;
		/*  addrx* forms : The index is relative to the value of the
			DW_AT_addr_base attribute of the associated compilation unit.
		    index into an array of addresses in the .debug_addr section.*/
	case DW_FORM_addrx:
		value->kind = DW_AT_KIND_ADDRESS;
		ULE128_OR_RET_FALSE(value->address);
		break;
	case DW_FORM_addrx1:
		value->kind = DW_AT_KIND_ADDRESS;
		U8_OR_RET_FALSE(value->address);
		break;
	case DW_FORM_addrx2:
		value->kind = DW_AT_KIND_ADDRESS;
		U16_OR_RET_FALSE(value->address);
		break;
	case DW_FORM_addrx3:
		// TODO: .DW_FORM_addrx3
		value->kind = DW_AT_KIND_ADDRESS;
		rz_buf_seek(buffer, 3, RZ_BUF_CUR);
		RZ_LOG_ERROR("TODO: DW_FORM_addrx3\n");
		break;
	case DW_FORM_addrx4:
		value->kind = DW_AT_KIND_ADDRESS;
		U32_OR_RET_FALSE(value->address);
		break;
	case DW_FORM_line_ptr: // offset in a section .debug_line_str
	case DW_FORM_strp_sup: // offset in a section .debug_line_str
		value->kind = DW_AT_KIND_STRING;
		RET_FALSE_IF_FAIL(buf_read_offset(buffer, &value->string.offset, is_64bit, big_endian));
		// TODO: .debug_line_str
		RZ_LOG_ERROR("TODO: .debug_line_str\n");
		break;
		// offset in the supplementary object file
	case DW_FORM_ref_sup4:
		value->kind = DW_AT_KIND_REFERENCE;
		U32_OR_RET_FALSE(value->reference);
		break;
	case DW_FORM_ref_sup8:
		value->kind = DW_AT_KIND_REFERENCE;
		U64_OR_RET_FALSE(value->reference);
		break;
		// An index into the .debug_loc
	case DW_FORM_loclistx:
		value->kind = DW_AT_KIND_LOCLISTPTR;
		RET_FALSE_IF_FAIL(buf_read_offset(buffer, &value->reference, is_64bit, big_endian));
		break;
		// An index into the .debug_rnglists
	case DW_FORM_rnglistx:
		value->kind = DW_AT_KIND_ADDRESS;
		ULE128_OR_RET_FALSE(value->address);
		break;
	default:
		RZ_LOG_ERROR("Unknown DW_FORM 0x%02" PFMT32x "\n", form);
		value->uconstant = 0;
		return false;
	}
	return true;
}

RZ_IPI void attr_fini(RzBinDwarfAttr *val) {
	if (!val) {
		return;
	}
	switch (val->kind) {
	case DW_AT_KIND_STRING:
		RZ_FREE(val->string.content);
		break;
	case DW_AT_KIND_BLOCK:
		RZ_FREE(val->block.data);
		break;
	default:
		break;
	};
}

RZ_IPI char *attr_to_string(RzBinDwarfAttr *attr) {
	switch (attr->name) {
	case DW_AT_language: return rz_str_new(rz_bin_dwarf_lang(attr->uconstant));
	default: break;
	}
	switch (attr->kind) {
	case DW_AT_KIND_ADDRESS: return rz_str_newf("0x%" PFMT64x, attr->address);
	case DW_AT_KIND_BLOCK: return rz_str_newf("0x%" PFMT64x, attr->block.length);
	case DW_AT_KIND_CONSTANT:
		return rz_str_newf("0x%" PFMT64x, attr->uconstant);
	case DW_AT_KIND_FLAG: return rz_str_newf("true");
	case DW_AT_KIND_REFERENCE:
	case DW_AT_KIND_LOCLISTPTR: return rz_str_newf("ref: 0x%" PFMT64x, attr->reference);
	case DW_AT_KIND_STRING: return attr->string.offset > 0 ? rz_str_newf(".debug_str[0x%" PFMT64x "] = \"%s\"", attr->string.offset, attr->string.content) : rz_str_newf("\"%s\"", attr->string.content);
	case DW_AT_KIND_RANGELISTPTR:
	case DW_AT_KIND_MACPTR:
	case DW_AT_KIND_LINEPTR:
	case DW_AT_KIND_EXPRLOC:
	default: return NULL;
	}
}

RZ_IPI RzBinSection *get_section(RzBinFile *binfile, const char *sn) {
	rz_return_val_if_fail(binfile && sn, NULL);
	RzListIter *iter;
	RzBinSection *section = NULL;
	RzBinObject *o = binfile->o;
	if (!o || !o->sections) {
		return NULL;
	}
	rz_list_foreach (o->sections, iter, section) {
		if (!section->name) {
			continue;
		}
		if (strstr(section->name, sn)) {
			return section;
		}
	}
	return NULL;
}

RZ_IPI RzBuffer *get_section_buf(RzBinFile *binfile, const char *sect_name) {
	rz_return_val_if_fail(binfile && sect_name, NULL);
	RzBinSection *section = get_section(binfile, sect_name);
	if (!section) {
		return NULL;
	}
	if (section->paddr >= binfile->size) {
		return NULL;
	}
	ut64 len = RZ_MIN(section->size, binfile->size - section->paddr);
	return rz_buf_new_slice(binfile->buf, section->paddr, len);
}

RZ_API RZ_OWN RzBinDwarf *rz_bin_dwarf_parse(RZ_BORROW RZ_NONNULL RzBinFile *bf, RZ_BORROW RZ_NONNULL const RzBinDwarfParseOptions *opt) {
	rz_return_val_if_fail(bf && opt, NULL);
	RzBinDwarf *dw = RZ_NEW0(RzBinDwarf);
	if (!dw) {
		return NULL;
	}
	dw->encoding.big_endian = opt->big_endian;
	dw->addr = DebugAddr_parse(bf);
	if (opt->flags & RZ_BIN_DWARF_PARSE_ABBREVS) {
		RZ_LOG_DEBUG(".debug_abbrev\n");
		dw->abbrevs = rz_bin_dwarf_abbrev_parse(bf);
	}
	if (opt->flags & RZ_BIN_DWARF_PARSE_INFO && dw->abbrevs) {
		RZ_LOG_DEBUG(".debug_info\n");
		dw->info = rz_bin_dwarf_info_parse(bf, dw->abbrevs);
		RzBinDwarfCompUnit *unit = rz_vector_head(&dw->info->units);
		dw->encoding = unit->hdr.encoding;
	}

	dw->loc = rz_bin_dwarf_loclists_new(bf, dw);
	if (opt->flags & RZ_BIN_DWARF_PARSE_LOC && dw->loc && dw->info) {
		RZ_LOG_DEBUG(dw->encoding.version == 5 ? ".debug_loclists\n" : ".debug_loc\n");
		rz_bin_dwarf_loclist_table_parse_all(dw->loc, &dw->encoding);
	}
	dw->rnglists = rz_bin_dwarf_rnglists_new(bf, dw);
	if (opt->flags & RZ_BIN_DWARF_PARSE_RNGLISTS && dw->loc && dw->info) {
		RZ_LOG_DEBUG(dw->encoding.version == 5 ? ".debug_rnglists\n" : ".debug_ranges\n");
		rz_bin_dwarf_rnglist_table_parse_all(dw->rnglists, &dw->encoding);
	}

	if (opt->flags & RZ_BIN_DWARF_PARSE_LINES && dw->info) {
		RZ_LOG_DEBUG(".debug_line\n");
		dw->lines = rz_bin_dwarf_parse_line(bf, dw->info, opt->line_mask);
	}
	if (opt->flags & RZ_BIN_DWARF_PARSE_ARANGES) {
		RZ_LOG_DEBUG(".debug_aranges\n");
		dw->aranges = rz_bin_dwarf_aranges_parse(bf);
	}
	return dw;
}

RZ_API void rz_bin_dwarf_free(RZ_OWN RZ_NULLABLE RzBinDwarf *dw) {
	if (!dw) {
		return;
	}
	rz_bin_dwarf_abbrev_free(dw->abbrevs);
	rz_bin_dwarf_info_free(dw->info);

	rz_bin_dwarf_line_info_free(dw->lines);
	rz_list_free(dw->aranges);
	free(dw);
}
