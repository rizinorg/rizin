// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>

#define DW_(x) \
	case x: return #x;

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
	[DW_AT_sibling] = "DW_AT_sibling",
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

static const char *dwarf_children[] = {
	[DW_CHILDREN_yes] = "DW_CHILDREN_yes",
	[DW_CHILDREN_no] = "DW_CHILDREN_no",
};

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

static const char *dwarf_lne[] = {
	[DW_LNE_end_sequence] = "DW_LNE_end_sequence",
	[DW_LNE_set_address] = "DW_LNE_set_address",
	[DW_LNE_define_file] = "DW_LNE_define_file",
	[DW_LNE_set_discriminator] = "DW_LNE_set_discriminator",
};

static const char *dwarf_lnct[] = {
	[DW_LNCT_path] = "DW_LNCT_path",
	[DW_LNCT_directory_index] = "DW_LNCT_directory_index",
	[DW_LNCT_timestamp] = "DW_LNCT_timestamp",
	[DW_LNCT_size] = "DW_LNCT_size",
	[DW_LNCT_MD5] = "DW_LNCT_MD5",
};

static const char *dwarf_ate[] = {
	[DW_ATE_address] = "DW_ATE_address",
	[DW_ATE_boolean] = "DW_ATE_boolean",
	[DW_ATE_complex_float] = "DW_ATE_complex_float",
	[DW_ATE_float] = "DW_ATE_float",
	[DW_ATE_signed] = "DW_ATE_signed",
	[DW_ATE_signed_char] = "DW_ATE_signed_char",
	[DW_ATE_unsigned] = "DW_ATE_unsigned",
	[DW_ATE_unsigned_char] = "DW_ATE_unsigned_char",
	[DW_ATE_imaginary_float] = "DW_ATE_imaginary_float",
	[DW_ATE_packed_decimal] = "DW_ATE_packed_decimal",
	[DW_ATE_numeric_string] = "DW_ATE_numeric_string",
	[DW_ATE_edited] = "DW_ATE_edited",
	[DW_ATE_signed_fixed] = "DW_ATE_signed_fixed",
	[DW_ATE_unsigned_fixed] = "DW_ATE_unsigned_fixed",
	[DW_ATE_decimal_float] = "DW_ATE_decimal_float",
	[DW_ATE_UTF] = "DW_ATE_UTF",
};

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
	[DW_OP_GNU_uninit] = "DW_OP_GNU_uninit",
	[DW_OP_GNU_encoded_addr] = "DW_OP_GNU_encoded_addr",
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

#define DW_ENUM_TO_STRING(to_string_const, index) \
	if ((index) >= 0 && (index) < RZ_ARRAY_SIZE((to_string_const))) { \
		return (to_string_const)[(index)]; \
	}

#define DW_ENUM_TO_STRING_IMPL(name, dw_enum, to_string_const) \
	RZ_API const char *rz_bin_dwarf_##name(dw_enum index) { \
		DW_ENUM_TO_STRING(to_string_const, index) \
		return NULL; \
	}

DW_ENUM_TO_STRING_IMPL(unit_type, DW_UT, dwarf_unit_types);
DW_ENUM_TO_STRING_IMPL(lang_for_demangle, DW_LANG, dwarf_langs_for_demangle);
DW_ENUM_TO_STRING_IMPL(children, DW_CHILDREN, dwarf_children);
DW_ENUM_TO_STRING_IMPL(lns, DW_LNS, dwarf_lns);
DW_ENUM_TO_STRING_IMPL(lne, DW_LNE, dwarf_lne);
DW_ENUM_TO_STRING_IMPL(lnct, DW_LNCT, dwarf_lnct);
DW_ENUM_TO_STRING_IMPL(op, DW_OP, dwarf_op);
DW_ENUM_TO_STRING_IMPL(ate, DW_ATE, dwarf_ate);

RZ_API const char *rz_bin_dwarf_tag(DW_TAG tag) {
	DW_ENUM_TO_STRING(dwarf_tag_name_encodings, tag);
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

RZ_API const char *rz_bin_dwarf_attr(DW_AT attr_code) {
	DW_ENUM_TO_STRING(dwarf_attr_encodings, attr_code);
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
		DW_(DW_AT_LLVM_tag_offset);
		DW_(DW_AT_LLVM_ptrauth_key);
		DW_(DW_AT_LLVM_ptrauth_address_discriminated);
		DW_(DW_AT_LLVM_ptrauth_extra_discriminator);
		DW_(DW_AT_LLVM_apinotes);
		DW_(DW_AT_LLVM_ptrauth_isa_pointer);
		DW_(DW_AT_LLVM_ptrauth_authenticates_null_values);
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
		DW_(DW_AT_APPLE_objc_direct);
		DW_(DW_AT_APPLE_sdk);
		DW_(DW_AT_APPLE_origin);
	default:
		return NULL;
	}
}

RZ_API const char *rz_bin_dwarf_form(DW_FORM form_code) {
	DW_ENUM_TO_STRING(dwarf_attr_form_encodings, form_code);
	switch (form_code) {
		DW_(DW_FORM_GNU_addr_index);
		DW_(DW_FORM_GNU_str_index);
		DW_(DW_FORM_GNU_ref_alt);
		DW_(DW_FORM_GNU_strp_alt);
	default: return NULL;
	}
}

RZ_API const char *rz_bin_dwarf_lang(DW_LANG lang) {
	DW_ENUM_TO_STRING(dwarf_langs, lang);
	switch (lang) {
		DW_(DW_LANG_Mips_Assembler);
		DW_(DW_LANG_GOOGLE_RenderScript);
		DW_(DW_LANG_SUN_Assembler);
		DW_(DW_LANG_ALTIUM_Assembler);
		DW_(DW_LANG_BORLAND_Delphi);
	default: return NULL;
	}
}
