// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#define D0 if (1)
#define D1 if (1)

#include <errno.h>

#define DWARF_DUMP 0

#if DWARF_DUMP
#define DBGFD stdout
#else
#define DBGFD NULL
#endif

#include <rz_bin.h>
#include <rz_bin_dwarf.h>
#include <rz_core.h>

#define STANDARD_OPERAND_COUNT_DWARF2 9
#define STANDARD_OPERAND_COUNT_DWARF3 12
#define RZ_BIN_DWARF_INFO             1

#define READ8(buf) \
	(((buf) + 1 < buf_end) ? *((ut8 *)(buf)) : 0); \
	(buf)++
#define READ16(buf) \
	(((buf) + sizeof(ut16) < buf_end) ? rz_read_ble16(buf, big_endian) : 0); \
	(buf) += sizeof(ut16)
#define READ32(buf) \
	(((buf) + sizeof(ut32) < buf_end) ? rz_read_ble32(buf, big_endian) : 0); \
	(buf) += sizeof(ut32)
#define READ64(buf) \
	(((buf) + sizeof(ut64) < buf_end) ? rz_read_ble64(buf, big_endian) : 0); \
	(buf) += sizeof(ut64)

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
	[DW_TAG_LAST] = "DW_TAG_LAST",
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
	[DW_LANG_Fortran08] = "Fortran08"
};

static const char *dwarf_unit_types[] = {
	[DW_UT_compile] = "DW_UT_compile",
	[DW_UT_type] = "DW_UT_type",
	[DW_UT_partial] = "DW_UT_partial",
	[DW_UT_skeleton] = "DW_UT_skeleton",
	[DW_UT_split_compile] = "DW_UT_split_compile",
	[DW_UT_split_type] = "DW_UT_split_type",
	[DW_UT_lo_user] = "DW_UT_lo_user",
	[DW_UT_hi_user] = "DW_UT_hi_user",
};

RZ_API const char *rz_bin_dwarf_get_tag_name(ut64 tag) {
	if (tag >= DW_TAG_LAST) {
		return NULL;
	}
	return dwarf_tag_name_encodings[tag];
}

RZ_API const char *rz_bin_dwarf_get_attr_name(ut64 attr_code) {
	if (attr_code < RZ_ARRAY_SIZE(dwarf_attr_encodings)) {
		return dwarf_attr_encodings[attr_code];
	}
	// the below codes are much sparser, so putting them in an array would require a lot of
	// unused memory
	switch (attr_code) {
	case DW_AT_lo_user:
		return "DW_AT_lo_user";
	case DW_AT_MIPS_linkage_name:
		return "DW_AT_MIPS_linkage_name";
	case DW_AT_GNU_call_site_value:
		return "DW_AT_GNU_call_site_value";
	case DW_AT_GNU_call_site_data_value:
		return "DW_AT_GNU_call_site_data_value";
	case DW_AT_GNU_call_site_target:
		return "DW_AT_GNU_call_site_target";
	case DW_AT_GNU_call_site_target_clobbered:
		return "DW_AT_GNU_call_site_target_clobbered";
	case DW_AT_GNU_tail_call:
		return "DW_AT_GNU_tail_call";
	case DW_AT_GNU_all_tail_call_sites:
		return "DW_AT_GNU_all_tail_call_sites";
	case DW_AT_GNU_all_call_sites:
		return "DW_AT_GNU_all_call_sites";
	case DW_AT_GNU_all_source_call_sites:
		return "DW_AT_GNU_all_source_call_sites";
	case DW_AT_GNU_macros:
		return "DW_AT_GNU_macros";
	case DW_AT_GNU_deleted:
		return "DW_AT_GNU_deleted";
	case DW_AT_GNU_dwo_name:
		return "DW_AT_GNU_dwo_name";
	case DW_AT_GNU_dwo_id:
		return "DW_AT_GNU_dwo_id";
	case DW_AT_GNU_ranges_base:
		return "DW_AT_GNU_ranges_base";
	case DW_AT_GNU_addr_base:
		return "DW_AT_GNU_addr_base";
	case DW_AT_GNU_pubnames:
		return "DW_AT_GNU_pubnames";
	case DW_AT_GNU_pubtypes:
		return "DW_AT_GNU_pubtypes";
	case DW_AT_hi_user:
		return "DW_AT_hi_user";
	default:
		return NULL;
	}
}

RZ_API const char *rz_bin_dwarf_get_attr_form_name(ut64 form_code) {
	if (form_code < DW_FORM_addr || form_code > DW_FORM_addrx4) {
		return NULL;
	}
	return dwarf_attr_form_encodings[form_code];
}

RZ_API const char *rz_bin_dwarf_get_unit_type_name(ut64 unit_type) {
	if (!unit_type || unit_type > DW_UT_split_type) {
		return NULL;
	}
	return dwarf_unit_types[unit_type];
}

RZ_API const char *rz_bin_dwarf_get_lang_name(ut64 lang) {
	if (lang >= RZ_ARRAY_SIZE(dwarf_langs)) {
		return NULL;
	}
	return dwarf_langs[lang];
}

static int abbrev_cmp(const void *a, const void *b) {
	const RzBinDwarfAbbrevDecl *first = a;
	const RzBinDwarfAbbrevDecl *second = b;

	if (first->offset > second->offset) {
		return 1;
	} else if (first->offset < second->offset) {
		return -1;
	} else {
		return 0;
	}
}

/**
 * \brief Read an "initial length" value, as specified by dwarf.
 * This also determines whether it is 64bit or 32bit and reads 4 or 12 bytes respectively.
 */
static inline ut64 dwarf_read_initial_length(RZ_OUT bool *is_64bit, bool big_endian, const ut8 **buf, const ut8 *buf_end) {
	ut64 r = READ32(*buf);
	if (r == DWARF_INIT_LEN_64) {
		r = READ64(*buf);
		*is_64bit = true;
	} else {
		*is_64bit = false;
	}
	return r;
}

/**
 * @brief Reads 64/32 bit unsigned based on format
 *
 * @param is_64bit Format of the comp unit
 * @param buf Pointer to the buffer to read from, to update after read
 * @param buf_end To check the boundary /for READ macro/
 * @return ut64 Read value
 */
static inline ut64 dwarf_read_offset(bool is_64bit, bool big_endian, const ut8 **buf, const ut8 *buf_end) {
	ut64 result;
	if (is_64bit) {
		result = READ64(*buf);
	} else {
		result = READ32(*buf);
	}
	return result;
}

static inline ut64 dwarf_read_address(size_t size, bool big_endian, const ut8 **buf, const ut8 *buf_end) {
	ut64 result;
	switch (size) {
	case 2:
		result = READ16(*buf);
		break;
	case 4:
		result = READ32(*buf);
		break;
	case 8:
		result = READ64(*buf);
		break;
	default:
		result = 0;
		*buf += size;
		eprintf("Weird dwarf address size: %zu.", size);
	}
	return result;
}

static void line_header_fini(RzBinDwarfLineHeader *hdr) {
	if (hdr) {
		for (size_t i = 0; i < hdr->file_names_count; i++) {
			free(hdr->file_names[i].name);
		}

		free(hdr->std_opcode_lengths);
		free(hdr->file_names);

		if (hdr->include_dirs) {
			for (size_t i = 0; i < hdr->include_dirs_count; i++) {
				free(hdr->include_dirs[i]);
			}
			free(hdr->include_dirs);
		}
	}
}

// Parses source file header of DWARF version <= 4
static const ut8 *parse_line_header_source(RzBinFile *bf, const ut8 *buf, const ut8 *buf_end, RzBinDwarfLineHeader *hdr) {
	RzPVector incdirs;
	rz_pvector_init(&incdirs, free);
	while (buf + 1 < buf_end) {
		size_t maxlen = RZ_MIN((size_t)(buf_end - buf) - 1, 0xfff);
		size_t len = rz_str_nlen((const char *)buf, maxlen);
		char *str = rz_str_ndup((const char *)buf, len);
		if (len < 1 || len >= 0xfff || !str) {
			buf += 1;
			free(str);
			break;
		}
		rz_pvector_push(&incdirs, str);
		buf += len + 1;
	}
	hdr->include_dirs_count = rz_pvector_len(&incdirs);
	hdr->include_dirs = (char **)rz_pvector_flush(&incdirs);
	rz_pvector_fini(&incdirs);

	RzVector file_names;
	rz_vector_init(&file_names, sizeof(RzBinDwarfLineFileEntry), NULL, NULL);
	while (buf + 1 < buf_end) {
		const char *filename = (const char *)buf;
		size_t maxlen = RZ_MIN((size_t)(buf_end - buf - 1), 0xfff);
		ut64 id_idx, mod_time, file_len;
		size_t len = rz_str_nlen(filename, maxlen);

		if (!len) {
			buf++;
			break;
		}
		buf += len + 1;
		if (buf >= buf_end) {
			buf = NULL;
			goto beach;
		}
		buf = rz_uleb128(buf, buf_end - buf, &id_idx, NULL);
		if (buf >= buf_end) {
			buf = NULL;
			goto beach;
		}
		buf = rz_uleb128(buf, buf_end - buf, &mod_time, NULL);
		if (buf >= buf_end) {
			buf = NULL;
			goto beach;
		}
		buf = rz_uleb128(buf, buf_end - buf, &file_len, NULL);
		if (buf >= buf_end) {
			buf = NULL;
			goto beach;
		}
		RzBinDwarfLineFileEntry *entry = rz_vector_push(&file_names, NULL);
		entry->name = strdup(filename);
		entry->id_idx = id_idx;
		entry->mod_time = mod_time;
		entry->file_len = file_len;
	}
	hdr->file_names_count = rz_vector_len(&file_names);
	hdr->file_names = rz_vector_flush(&file_names);
	rz_vector_fini(&file_names);

beach:
	return buf;
}

/**
 * \param info if not NULL, filenames can get resolved to absolute paths using the compilation unit dirs from it
 */
RZ_API char *rz_bin_dwarf_line_header_get_full_file_path(RZ_NULLABLE const RzBinDwarfDebugInfo *info, const RzBinDwarfLineHeader *header, ut64 file_index) {
	rz_return_val_if_fail(header, NULL);
	if (file_index >= header->file_names_count) {
		return NULL;
	}
	RzBinDwarfLineFileEntry *file = &header->file_names[file_index];
	if (!file->name) {
		return NULL;
	}

	/*
	 * Dwarf standard does not seem to specify the exact separator (slash/backslash) of paths
	 * so apparently it is target-dependent. However we have yet to see a Windows binary that
	 * also contains dwarf and contains backslashes. The ones we have seen from MinGW have regular
	 * slashes.
	 * And since there seems to be no way to reliable check whether the target uses slashes
	 * or backslashes anyway, we will simply use slashes always here.
	 */

	const char *comp_dir = info ? ht_up_find(info->line_info_offset_comp_dir, header->offset, NULL) : NULL;
	const char *include_dir = NULL;
	char *own_str = NULL;
	if (file->id_idx > 0 && file->id_idx - 1 < header->include_dirs_count) {
		include_dir = header->include_dirs[file->id_idx - 1];
		if (include_dir && include_dir[0] != '/' && comp_dir) {
			include_dir = own_str = rz_str_newf("%s/%s/", comp_dir, include_dir);
		}
	} else {
		include_dir = comp_dir;
	}
	if (!include_dir) {
		include_dir = "./";
	}
	char *r = rz_str_newf("%s/%s", include_dir, file->name);
	free(own_str);
	return r;
}

RZ_API RzBinDwarfLineFileCache rz_bin_dwarf_line_header_new_file_cache(const RzBinDwarfLineHeader *hdr) {
	return RZ_NEWS0(char *, hdr->file_names_count);
}

RZ_API void rz_bin_dwarf_line_header_free_file_cache(const RzBinDwarfLineHeader *hdr, RzBinDwarfLineFileCache fnc) {
	if (!fnc) {
		return;
	}
	for (size_t i = 0; i < hdr->file_names_count; i++) {
		free(fnc[i]);
	}
	free(fnc);
}

static const char *get_full_file_path(const RzBinDwarfDebugInfo *info, const RzBinDwarfLineHeader *header,
	RZ_NULLABLE RzBinDwarfLineFileCache cache, ut64 file_index) {
	if (file_index >= header->file_names_count) {
		return NULL;
	}
	if (!cache) {
		return header->file_names[file_index].name;
	}
	if (!cache[file_index]) {
		cache[file_index] = rz_bin_dwarf_line_header_get_full_file_path(info, header, file_index);
	}
	return cache[file_index];
}

RZ_API ut64 rz_bin_dwarf_line_header_get_adj_opcode(const RzBinDwarfLineHeader *header, ut8 opcode) {
	rz_return_val_if_fail(header, 0);
	return opcode - header->opcode_base;
}

RZ_API ut64 rz_bin_dwarf_line_header_get_spec_op_advance_pc(const RzBinDwarfLineHeader *header, ut8 opcode) {
	rz_return_val_if_fail(header, 0);
	if (!header->line_range) {
		// to dodge division by zero
		return 0;
	}
	ut8 adj_opcode = rz_bin_dwarf_line_header_get_adj_opcode(header, opcode);
	return (adj_opcode / header->line_range) * header->min_inst_len;
}

RZ_API st64 rz_bin_dwarf_line_header_get_spec_op_advance_line(const RzBinDwarfLineHeader *header, ut8 opcode) {
	rz_return_val_if_fail(header, 0);
	if (!header->line_range) {
		// to dodge division by zero
		return 0;
	}
	ut8 adj_opcode = rz_bin_dwarf_line_header_get_adj_opcode(header, opcode);
	return header->line_base + (adj_opcode % header->line_range);
}

static const ut8 *parse_line_header(
	RzBinFile *bf, const ut8 *buf, const ut8 *buf_end,
	RzBinDwarfLineHeader *hdr, ut64 offset_cur, bool big_endian) {
	rz_return_val_if_fail(hdr && bf && buf && buf_end, NULL);

	hdr->offset = offset_cur;
	hdr->is_64bit = false;
	hdr->unit_length = dwarf_read_initial_length(&hdr->is_64bit, big_endian, &buf, buf_end);
	hdr->version = READ16(buf);

	if (hdr->version == 5) {
		hdr->address_size = READ8(buf);
		hdr->segment_selector_size = READ8(buf);
	}

	hdr->header_length = dwarf_read_offset(hdr->is_64bit, big_endian, &buf, buf_end);

	const ut8 *tmp_buf = buf; // So I can skip parsing DWARF 5 headers for now

	if (buf_end - buf < 8) {
		return NULL;
	}
	hdr->min_inst_len = READ8(buf);
	if (hdr->version >= 4) {
		hdr->max_ops_per_inst = READ8(buf);
	}
	hdr->default_is_stmt = READ8(buf);
	hdr->line_base = (st8)READ8(buf);
	hdr->line_range = READ8(buf);
	hdr->opcode_base = READ8(buf);

	hdr->file_names = NULL;

	if (hdr->opcode_base > 1) {
		hdr->std_opcode_lengths = calloc(sizeof(ut8), hdr->opcode_base - 1);
		for (size_t i = 1; i < hdr->opcode_base; i++) {
			if (buf + 2 > buf_end) {
				hdr->opcode_base = i;
				break;
			}
			hdr->std_opcode_lengths[i - 1] = READ8(buf);
		}
	} else {
		hdr->std_opcode_lengths = NULL;
	}
	// TODO finish parsing of source files out of DWARF 5 header
	// for now we skip
	if (hdr->version == 5) {
		tmp_buf += hdr->header_length;
		return tmp_buf;
	}

	if (hdr->version <= 4) {
		buf = parse_line_header_source(bf, buf, buf_end, hdr);
	} else {
		buf = NULL;
	}

	return buf;
}

RZ_API void rz_bin_dwarf_line_op_fini(RzBinDwarfLineOp *op) {
	rz_return_if_fail(op);
	if (op->type == RZ_BIN_DWARF_LINE_OP_TYPE_EXT && op->opcode == DW_LNE_define_file) {
		free(op->args.define_file.filename);
	}
}

static const ut8 *parse_ext_opcode(RzBinDwarfLineOp *op, const RzBinDwarfLineHeader *hdr, const ut8 *obuf, size_t len,
	bool big_endian, ut8 target_addr_size) {
	rz_return_val_if_fail(op && hdr && obuf, NULL);
	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + len;

	ut64 op_len;
	buf = rz_uleb128(buf, len, &op_len, NULL);
	// op_len must fit and be at least 1 (for the opcode byte)
	if (!buf || buf >= buf_end || !op_len || buf_end - buf < op_len) {
		return NULL;
	}

	ut8 opcode = *buf++;
	op->type = RZ_BIN_DWARF_LINE_OP_TYPE_EXT;
	op->opcode = opcode;

	switch (opcode) {
	case DW_LNE_set_address: {
		ut8 addr_size = hdr->address_size;
		if (hdr->version < 5) { // address_size in header only starting with Dwarf 5
			addr_size = target_addr_size;
		}
		op->args.set_address = dwarf_read_address(addr_size, big_endian, &buf, buf_end);
		break;
	}
	case DW_LNE_define_file: {
		size_t fn_len = rz_str_nlen((const char *)buf, buf_end - buf);
		char *fn = malloc(fn_len + 1);
		if (!fn) {
			return NULL;
		}
		memcpy(fn, buf, fn_len);
		fn[fn_len] = 0;
		op->args.define_file.filename = fn;
		buf += fn_len + 1;
		if (buf + 1 < buf_end) {
			buf = rz_uleb128(buf, buf_end - buf, &op->args.define_file.dir_index, NULL);
		}
		if (buf && buf + 1 < buf_end) {
			buf = rz_uleb128(buf, buf_end - buf, NULL, NULL);
		}
		if (buf && buf + 1 < buf_end) {
			buf = rz_uleb128(buf, buf_end - buf, NULL, NULL);
		}
		break;
	}
	case DW_LNE_set_discriminator:
		buf = rz_uleb128(buf, buf_end - buf, &op->args.set_discriminator, NULL);
		break;
	case DW_LNE_end_sequence:
	default:
		buf += op_len - 1;
		break;
	}
	return buf;
}

/**
 * \return the number of leb128 args the std opcode takes, EXCEPT for DW_LNS_fixed_advance_pc! (see Dwarf spec)
 */
static size_t std_opcode_args_count(const RzBinDwarfLineHeader *hdr, ut8 opcode) {
	if (!opcode || opcode > hdr->opcode_base - 1 || !hdr->std_opcode_lengths) {
		return 0;
	}
	return hdr->std_opcode_lengths[opcode - 1];
}

static const ut8 *parse_std_opcode(RzBinDwarfLineOp *op, const RzBinDwarfLineHeader *hdr, const ut8 *obuf, size_t len, ut8 opcode, bool big_endian) {
	rz_return_val_if_fail(op && hdr && obuf, NULL);
	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + len;

	op->type = RZ_BIN_DWARF_LINE_OP_TYPE_STD;
	op->opcode = opcode;
	switch (opcode) {
	case DW_LNS_advance_pc:
		buf = rz_uleb128(buf, buf_end - buf, &op->args.advance_pc, NULL);
		break;
	case DW_LNS_advance_line:
		buf = rz_leb128(buf, buf_end - buf, &op->args.advance_line);
		break;
	case DW_LNS_set_file:
		buf = rz_uleb128(buf, buf_end - buf, &op->args.set_file, NULL);
		break;
	case DW_LNS_set_column:
		buf = rz_uleb128(buf, buf_end - buf, &op->args.set_column, NULL);
		break;
	case DW_LNS_fixed_advance_pc:
		op->args.fixed_advance_pc = READ16(buf);
		break;
	case DW_LNS_set_isa:
		buf = rz_uleb128(buf, buf_end - buf, &op->args.set_isa, NULL);
		break;

	// known opcodes that take no args
	case DW_LNS_copy:
	case DW_LNS_negate_stmt:
	case DW_LNS_set_basic_block:
	case DW_LNS_const_add_pc:
	case DW_LNS_set_prologue_end:
	case DW_LNS_set_epilogue_begin:
		break;

	// unknown operands, skip the number of args given in the header.
	default: {
		size_t args_count = std_opcode_args_count(hdr, opcode);
		for (size_t i = 0; i < args_count; i++) {
			buf = rz_uleb128(buf, buf_end - buf, &op->args.advance_pc, NULL);
			if (!buf) {
				break;
			}
		}
	}
	}
	return buf;
}

RZ_API void rz_bin_dwarf_line_header_reset_regs(const RzBinDwarfLineHeader *hdr, RzBinDwarfSMRegisters *regs) {
	rz_return_if_fail(hdr && regs);
	regs->address = 0;
	regs->file = 1;
	regs->line = 1;
	regs->column = 0;
	regs->is_stmt = hdr->default_is_stmt;
	regs->basic_block = DWARF_FALSE;
	regs->end_sequence = DWARF_FALSE;
	regs->prologue_end = DWARF_FALSE;
	regs->epilogue_begin = DWARF_FALSE;
	regs->isa = 0;
}

static void store_line_sample(RzBinSourceLineInfoBuilder *bob, const RzBinDwarfLineHeader *hdr, RzBinDwarfSMRegisters *regs,
	RZ_NULLABLE RzBinDwarfDebugInfo *info, RZ_NULLABLE RzBinDwarfLineFileCache fnc) {
	const char *file = NULL;
	if (regs->file) {
		file = get_full_file_path(info, hdr, fnc, regs->file - 1);
	}
	rz_bin_source_line_info_builder_push_sample(bob, regs->address, (ut32)regs->line, (ut32)regs->column, file);
}

/**
 * \brief Execute a single line op on regs and optionally store the resulting line info in bob
 * \param fnc if not null, filenames will be resolved to their full paths using this cache.
 */
RZ_API bool rz_bin_dwarf_line_op_run(const RzBinDwarfLineHeader *hdr, RzBinDwarfSMRegisters *regs, RzBinDwarfLineOp *op,
	RZ_NULLABLE RzBinSourceLineInfoBuilder *bob, RZ_NULLABLE RzBinDwarfDebugInfo *info, RZ_NULLABLE RzBinDwarfLineFileCache fnc) {
	rz_return_val_if_fail(hdr && regs && op, false);
	switch (op->type) {
	case RZ_BIN_DWARF_LINE_OP_TYPE_STD:
		switch (op->opcode) {
		case DW_LNS_copy:
			if (bob) {
				store_line_sample(bob, hdr, regs, info, fnc);
			}
			regs->basic_block = DWARF_FALSE;
			break;
		case DW_LNS_advance_pc:
			regs->address += op->args.advance_pc * hdr->min_inst_len;
			break;
		case DW_LNS_advance_line:
			regs->line += op->args.advance_line;
			break;
		case DW_LNS_set_file:
			regs->file = op->args.set_file;
			break;
		case DW_LNS_set_column:
			regs->column = op->args.set_column;
			break;
		case DW_LNS_negate_stmt:
			regs->is_stmt = regs->is_stmt ? DWARF_FALSE : DWARF_TRUE;
			break;
		case DW_LNS_set_basic_block:
			regs->basic_block = DWARF_TRUE;
			break;
		case DW_LNS_const_add_pc:
			regs->address += rz_bin_dwarf_line_header_get_spec_op_advance_pc(hdr, 255);
			break;
		case DW_LNS_fixed_advance_pc:
			regs->address += op->args.fixed_advance_pc;
			break;
		case DW_LNS_set_prologue_end:
			regs->prologue_end = ~0;
			break;
		case DW_LNS_set_epilogue_begin:
			regs->epilogue_begin = ~0;
			break;
		case DW_LNS_set_isa:
			regs->isa = op->args.set_isa;
			break;
		default:
			return false;
		}
		break;
	case RZ_BIN_DWARF_LINE_OP_TYPE_EXT:
		switch (op->opcode) {
		case DW_LNE_end_sequence:
			regs->end_sequence = DWARF_TRUE;
			if (bob) {
				// closing entry
				rz_bin_source_line_info_builder_push_sample(bob, regs->address, 0, 0, NULL);
			}
			rz_bin_dwarf_line_header_reset_regs(hdr, regs);
			break;
		case DW_LNE_set_address:
			regs->address = op->args.set_address;
			break;
		case DW_LNE_define_file:
			break;
		case DW_LNE_set_discriminator:
			regs->discriminator = op->args.set_discriminator;
			break;
		default:
			return false;
		}
		break;
	case RZ_BIN_DWARF_LINE_OP_TYPE_SPEC:
		regs->address += rz_bin_dwarf_line_header_get_spec_op_advance_pc(hdr, op->opcode);
		regs->line += rz_bin_dwarf_line_header_get_spec_op_advance_line(hdr, op->opcode);
		if (bob) {
			store_line_sample(bob, hdr, regs, info, fnc);
		}
		regs->basic_block = DWARF_FALSE;
		regs->prologue_end = DWARF_FALSE;
		regs->epilogue_begin = DWARF_FALSE;
		regs->discriminator = 0;
		break;
	default:
		return false;
	}
	return true;
}

static size_t parse_opcodes(const ut8 *obuf,
	size_t len, const RzBinDwarfLineHeader *hdr, RzVector *ops_out,
	RzBinDwarfSMRegisters *regs, RZ_NULLABLE RzBinSourceLineInfoBuilder *bob, RZ_NULLABLE RzBinDwarfDebugInfo *info,
	RZ_NULLABLE RzBinDwarfLineFileCache fnc, bool big_endian, ut8 target_addr_size) {
	const ut8 *buf, *buf_end;
	ut8 opcode;

	if (!obuf || !len) {
		return 0;
	}
	buf = obuf;
	buf_end = obuf + len;

	while (buf < buf_end) {
		opcode = *buf++;
		RzBinDwarfLineOp op = { 0 };
		if (!opcode) {
			buf = parse_ext_opcode(&op, hdr, buf, (buf_end - buf), big_endian, target_addr_size);
		} else if (opcode >= hdr->opcode_base) {
			// special opcode without args, no further parsing needed
			op.type = RZ_BIN_DWARF_LINE_OP_TYPE_SPEC;
			op.opcode = opcode;
		} else {
			buf = parse_std_opcode(&op, hdr, buf, (buf_end - buf), opcode, big_endian);
		}
		if (!buf) {
			break;
		}
		if (bob) {
			rz_bin_dwarf_line_op_run(hdr, regs, &op, bob, info, fnc);
		}
		if (ops_out) {
			rz_vector_push(ops_out, &op);
		} else {
			rz_bin_dwarf_line_op_fini(&op);
		}
	}
	if (!buf) {
		return 0;
	}
	return (size_t)(buf - obuf); // number of bytes we've moved by
}

static void line_unit_free(RzBinDwarfLineUnit *unit) {
	if (!unit) {
		return;
	}
	line_header_fini(&unit->header);
	if (unit->ops) {
		for (size_t i = 0; i < unit->ops_count; i++) {
			rz_bin_dwarf_line_op_fini(&unit->ops[i]);
		}
		free(unit->ops);
	}
	free(unit);
}

static RzBinDwarfLineInfo *parse_line_raw(RzBinFile *binfile, const ut8 *obuf,
	ut64 len, RzBinDwarfLineInfoMask mask, bool big_endian, RZ_NULLABLE RzBinDwarfDebugInfo *info) {
	// Dwarf 3 Standard 6.2 Line Number Information
	rz_return_val_if_fail(binfile && obuf, NULL);

	const ut8 *buf = obuf;
	const ut8 *buf_start = buf;
	const ut8 *buf_end = obuf + len;
	const ut8 *tmpbuf = NULL;
	ut64 buf_size;

	// Dwarf < 5 needs this size to be supplied from outside
	RzBinObject *o = binfile->o;
	ut8 target_addr_size = o && o->info && o->info->bits ? o->info->bits / 8 : 4;

	RzBinDwarfLineInfo *li = RZ_NEW0(RzBinDwarfLineInfo);
	if (!li) {
		return NULL;
	}
	li->units = rz_list_newf((RzListFree)line_unit_free);
	if (!li->units) {
		free(li);
		return NULL;
	}

	RzBinSourceLineInfoBuilder bob;
	if (mask & RZ_BIN_DWARF_LINE_INFO_MASK_LINES) {
		rz_bin_source_line_info_builder_init(&bob);
	}

	// each iteration we read one header AKA comp. unit
	while (buf <= buf_end) {
		RzBinDwarfLineUnit *unit = RZ_NEW0(RzBinDwarfLineUnit);
		if (!unit) {
			break;
		}

		// How much did we read from the compilation unit
		size_t bytes_read = 0;
		// calculate how much we've read by parsing header
		// because header unit_length includes itself
		buf_size = buf_end - buf;

		tmpbuf = buf;
		buf = parse_line_header(binfile, buf, buf_end, &unit->header, buf - buf_start, big_endian);
		if (!buf) {
			line_unit_free(unit);
			break;
		}

		bytes_read = buf - tmpbuf;

		RzBinDwarfSMRegisters regs;
		rz_bin_dwarf_line_header_reset_regs(&unit->header, &regs);

		// If there is more bytes in the buffer than size of the header
		// It means that there has to be another header/comp.unit
		buf_size = RZ_MIN(buf_size, unit->header.unit_length + (unit->header.is_64bit * 8 + 4)); // length field + rest of the unit
		if (buf_size <= bytes_read) {
			// no info or truncated
			line_unit_free(unit);
			continue;
		}
		if (buf_size > (buf_end - buf) + bytes_read || buf > buf_end) {
			line_unit_free(unit);
			break;
		}
		size_t tmp_read = 0;

		RzVector ops;
		if (mask & RZ_BIN_DWARF_LINE_INFO_MASK_OPS) {
			rz_vector_init(&ops, sizeof(RzBinDwarfLineOp), NULL, NULL);
		}

		RzBinDwarfLineFileCache fnc = NULL;
		if (mask & RZ_BIN_DWARF_LINE_INFO_MASK_LINES) {
			fnc = rz_bin_dwarf_line_header_new_file_cache(&unit->header);
		}

		// we read the whole compilation unit (that might be composed of more sequences)
		do {
			// reads one whole sequence
			tmp_read = parse_opcodes(buf, buf_size - bytes_read, &unit->header,
				(mask & RZ_BIN_DWARF_LINE_INFO_MASK_OPS) ? &ops : NULL, &regs,
				(mask & RZ_BIN_DWARF_LINE_INFO_MASK_LINES) ? &bob : NULL,
				info, fnc, big_endian, target_addr_size);
			bytes_read += tmp_read;
			buf += tmp_read; // Move in the buffer forward
		} while (bytes_read < buf_size && tmp_read != 0); // if nothing is read -> error, exit

		rz_bin_dwarf_line_header_free_file_cache(&unit->header, fnc);

		if (mask & RZ_BIN_DWARF_LINE_INFO_MASK_OPS) {
			unit->ops_count = rz_vector_len(&ops);
			unit->ops = rz_vector_flush(&ops);
			rz_vector_fini(&ops);
		}

		if (!tmp_read) {
			line_unit_free(unit);
			break;
		}
		rz_list_push(li->units, unit);
	}
	if (mask & RZ_BIN_DWARF_LINE_INFO_MASK_LINES) {
		li->lines = rz_bin_source_line_info_builder_build_and_fini(&bob);
	}
	return li;
}

RZ_API void rz_bin_dwarf_arange_set_free(RzBinDwarfARangeSet *set) {
	if (!set) {
		return;
	}
	free(set->aranges);
	free(set);
}

static RzList /*<RzBinDwarfARangeSet>*/ *parse_aranges_raw(const ut8 *obuf, size_t obuf_sz, bool big_endian) {
	rz_return_val_if_fail(obuf, NULL);
	const ut8 *buf = obuf;
	const ut8 *buf_end = buf + obuf_sz;

	RzList *r = rz_list_newf((RzListFree)rz_bin_dwarf_arange_set_free);
	if (!r) {
		return NULL;
	}

	// DWARF 3 Standard Section 6.1.2 Lookup by Address
	// also useful to grep for display_debug_aranges in binutils
	while (buf < buf_end) {
		const ut8 *start = buf;
		bool is_64bit;
		ut64 unit_length = dwarf_read_initial_length(&is_64bit, big_endian, &buf, buf_end);
		// Sanity check: length must be at least the minimal size of the remaining header fields
		// and at maximum the remaining buffer size.
		size_t header_rest_size = 2 + (is_64bit ? 8 : 4) + 1 + 1;
		if (unit_length < header_rest_size || unit_length > buf_end - buf) {
			break;
		}
		const ut8 *next_set_buf = buf + unit_length;
		RzBinDwarfARangeSet *set = RZ_NEW(RzBinDwarfARangeSet);
		if (!set) {
			break;
		}
		set->unit_length = unit_length;
		set->is_64bit = is_64bit;
		set->version = READ16(buf);
		set->debug_info_offset = dwarf_read_offset(set->is_64bit, big_endian, &buf, buf_end);
		set->address_size = READ8(buf);
		set->segment_size = READ8(buf);
		unit_length -= header_rest_size;
		if (!set->address_size) {
			free(set);
			break;
		}

		// align to 2*addr_size
		size_t off = buf - start;
		size_t pad = rz_num_align_delta(off, 2 * set->address_size);
		if (pad > unit_length || pad > buf_end - buf) {
			free(set);
			break;
		}
		buf += pad;
		unit_length -= pad;

		size_t arange_size = 2 * set->address_size;
		set->aranges_count = unit_length / arange_size;
		if (!set->aranges_count) {
			free(set);
			break;
		}
		set->aranges = RZ_NEWS0(RzBinDwarfARange, set->aranges_count);
		if (!set->aranges) {
			free(set);
			break;
		}
		size_t i;
		for (i = 0; i < set->aranges_count; i++) {
			set->aranges[i].addr = dwarf_read_address(set->address_size, big_endian, &buf, buf_end);
			set->aranges[i].length = dwarf_read_address(set->address_size, big_endian, &buf, buf_end);
			if (!set->aranges[i].addr && !set->aranges[i].length) {
				// last entry has two 0s
				i++; // so i will be the total count of read entries
				break;
			}
		}
		set->aranges_count = i;
		buf = next_set_buf;
		rz_list_push(r, set);
	}

	return r;
}

static void free_ht_comp_dir(HtUPKv *kv) {
	free(kv->value);
}

static bool init_debug_info(RzBinDwarfDebugInfo *inf) {
	inf->comp_units = RZ_NEWS0(RzBinDwarfCompUnit, DEBUG_INFO_CAPACITY);
	if (!inf->comp_units) {
		return false;
	}
	inf->lookup_table = ht_up_new0();
	if (!inf->lookup_table) {
		goto wurzelbert_comp_units;
	}
	inf->line_info_offset_comp_dir = ht_up_new(NULL, free_ht_comp_dir, NULL);
	if (!inf->line_info_offset_comp_dir) {
		goto wurzelbert_lookup_table;
	}
	inf->capacity = DEBUG_INFO_CAPACITY;
	inf->count = 0;
	return true;
wurzelbert_lookup_table:
	ht_up_free(inf->lookup_table);
wurzelbert_comp_units:
	free(inf->comp_units);
	return false;
}

static int init_die(RzBinDwarfDie *die, ut64 abbr_code, ut64 attr_count) {
	if (!die) {
		return -1;
	}
	die->attr_values = calloc(sizeof(RzBinDwarfAttrValue), attr_count);
	if (!die->attr_values) {
		return -1;
	}
	die->abbrev_code = abbr_code;
	die->capacity = attr_count;
	die->count = 0;
	return 0;
}

static int init_comp_unit(RzBinDwarfCompUnit *cu) {
	if (!cu) {
		return -EINVAL;
	}
	cu->dies = calloc(sizeof(RzBinDwarfDie), COMP_UNIT_CAPACITY);
	if (!cu->dies) {
		return -ENOMEM;
	}
	cu->capacity = COMP_UNIT_CAPACITY;
	cu->count = 0;
	return 0;
}

static int expand_cu(RzBinDwarfCompUnit *cu) {
	RzBinDwarfDie *tmp;

	if (!cu || cu->capacity == 0 || cu->capacity != cu->count) {
		return -EINVAL;
	}

	tmp = (RzBinDwarfDie *)realloc(cu->dies,
		cu->capacity * 2 * sizeof(RzBinDwarfDie));
	if (!tmp) {
		return -ENOMEM;
	}

	memset((ut8 *)tmp + cu->capacity * sizeof(RzBinDwarfDie),
		0, cu->capacity * sizeof(RzBinDwarfDie));
	cu->dies = tmp;
	cu->capacity *= 2;

	return 0;
}

static int init_abbrev_decl(RzBinDwarfAbbrevDecl *ad) {
	if (!ad) {
		return -EINVAL;
	}
	ad->defs = calloc(sizeof(RzBinDwarfAttrDef), ABBREV_DECL_CAP);

	if (!ad->defs) {
		return -ENOMEM;
	}

	ad->capacity = ABBREV_DECL_CAP;
	ad->count = 0;

	return 0;
}

static int expand_abbrev_decl(RzBinDwarfAbbrevDecl *ad) {
	RzBinDwarfAttrDef *tmp;

	if (!ad || !ad->capacity || ad->capacity != ad->count) {
		return -EINVAL;
	}

	tmp = (RzBinDwarfAttrDef *)realloc(ad->defs,
		ad->capacity * 2 * sizeof(RzBinDwarfAttrDef));

	if (!tmp) {
		return -ENOMEM;
	}

	// Set the area in the buffer past the length to 0
	memset((ut8 *)tmp + ad->capacity * sizeof(RzBinDwarfAttrDef),
		0, ad->capacity * sizeof(RzBinDwarfAttrDef));
	ad->defs = tmp;
	ad->capacity *= 2;

	return 0;
}

static int init_debug_abbrev(RzBinDwarfDebugAbbrev *da) {
	if (!da) {
		return -EINVAL;
	}
	da->decls = calloc(sizeof(RzBinDwarfAbbrevDecl), DEBUG_ABBREV_CAP);
	if (!da->decls) {
		return -ENOMEM;
	}
	da->capacity = DEBUG_ABBREV_CAP;
	da->count = 0;

	return 0;
}

static int expand_debug_abbrev(RzBinDwarfDebugAbbrev *da) {
	RzBinDwarfAbbrevDecl *tmp;

	if (!da || da->capacity == 0 || da->capacity != da->count) {
		return -EINVAL;
	}

	tmp = (RzBinDwarfAbbrevDecl *)realloc(da->decls,
		da->capacity * 2 * sizeof(RzBinDwarfAbbrevDecl));

	if (!tmp) {
		return -ENOMEM;
	}
	memset((ut8 *)tmp + da->capacity * sizeof(RzBinDwarfAbbrevDecl),
		0, da->capacity * sizeof(RzBinDwarfAbbrevDecl));

	da->decls = tmp;
	da->capacity *= 2;

	return 0;
}

RZ_API void rz_bin_dwarf_debug_abbrev_free(RzBinDwarfDebugAbbrev *da) {
	size_t i;
	if (!da) {
		return;
	}
	for (i = 0; i < da->count; i++) {
		RZ_FREE(da->decls[i].defs);
	}
	RZ_FREE(da->decls);
	free(da);
}

RZ_API void rz_bin_dwarf_line_info_free(RzBinDwarfLineInfo *li) {
	if (!li) {
		return;
	}
	rz_list_free(li->units);
	rz_bin_source_line_info_free(li->lines);
	free(li);
}

static void free_attr_value(RzBinDwarfAttrValue *val) {
	// TODO adjust to new forms, now we're leaking
	if (!val) {
		return;
	}
	switch (val->attr_form) {
	case DW_FORM_strp:
	case DW_FORM_string:
		RZ_FREE(val->string.content);
		break;
	case DW_FORM_exprloc:
	case DW_FORM_block:
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
		RZ_FREE(val->block.data);
		break;
	default:
		break;
	};
}

static void free_die(RzBinDwarfDie *die) {
	size_t i;
	if (!die) {
		return;
	}
	for (i = 0; i < die->count; i++) {
		free_attr_value(&die->attr_values[i]);
	}
	RZ_FREE(die->attr_values);
}

static void free_comp_unit(RzBinDwarfCompUnit *cu) {
	size_t i;
	if (!cu) {
		return;
	}
	for (i = 0; i < cu->count; i++) {
		if (cu->dies) {
			free_die(&cu->dies[i]);
		}
	}
	RZ_FREE(cu->dies);
}

RZ_API void rz_bin_dwarf_debug_info_free(RzBinDwarfDebugInfo *inf) {
	if (!inf) {
		return;
	}
	for (size_t i = 0; i < inf->count; i++) {
		free_comp_unit(&inf->comp_units[i]);
	}
	ht_up_free(inf->line_info_offset_comp_dir);
	ht_up_free(inf->lookup_table);
	free(inf->comp_units);
	free(inf);
}

static const ut8 *fill_block_data(const ut8 *buf, const ut8 *buf_end, RzBinDwarfBlock *block) {
	block->data = calloc(sizeof(ut8), block->length);
	if (!block->data) {
		return NULL;
	}
	/* Maybe unroll this as an optimization in future? */
	if (block->data) {
		size_t j = 0;
		for (j = 0; j < block->length; j++) {
			block->data[j] = READ8(buf);
		}
	}
	return buf;
}

/**
 * This function is quite incomplete and requires lot of work
 * With parsing various new FORM values
 * @brief Parses attribute value based on its definition
 *        and stores it into `value`
 *
 * @param obuf
 * @param obuf_len Buffer max capacity
 * @param def Attribute definition
 * @param value Parsed value storage
 * @param hdr Current unit header
 * @param debug_str Ptr to string section start
 * @param debug_str_len Length of the string section
 * @return const ut8* Updated buffer
 */
static const ut8 *parse_attr_value(const ut8 *obuf, int obuf_len,
	RzBinDwarfAttrDef *def, RzBinDwarfAttrValue *value,
	const RzBinDwarfCompUnitHdr *hdr,
	const ut8 *debug_str, size_t debug_str_len,
	bool big_endian) {

	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + obuf_len;
	size_t j;

	rz_return_val_if_fail(def && value && hdr && obuf && obuf_len >= 1, NULL);

	value->attr_form = def->attr_form;
	value->attr_name = def->attr_name;
	value->block.data = NULL;
	value->string.content = NULL;
	value->string.offset = 0;

	// http://www.dwarfstd.org/doc/DWARF4.pdf#page=161&zoom=100,0,560
	switch (def->attr_form) {
	case DW_FORM_addr:
		value->kind = DW_AT_KIND_ADDRESS;
		switch (hdr->address_size) {
		case 1:
			value->address = READ8(buf);
			break;
		case 2:
			value->address = READ16(buf);
			break;
		case 4:
			value->address = READ32(buf);
			break;
		case 8:
			value->address = READ64(buf);
			break;
		default:
			eprintf("DWARF: Unexpected pointer size: %u\n", (unsigned)hdr->address_size);
			return NULL;
		}
		break;
	case DW_FORM_data1:
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = READ8(buf);
		break;
	case DW_FORM_data2:
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = READ16(buf);
		break;
	case DW_FORM_data4:
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = READ32(buf);
		break;
	case DW_FORM_data8:
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = READ64(buf);
		break;
	case DW_FORM_data16: // TODO Fix this, right now I just read the data, but I need to make storage for it
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = READ64(buf);
		value->uconstant = READ64(buf);
		break;
	case DW_FORM_sdata:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = rz_leb128(buf, buf_end - buf, &value->sconstant);
		break;
	case DW_FORM_udata:
		value->kind = DW_AT_KIND_CONSTANT;
		buf = rz_uleb128(buf, buf_end - buf, &value->uconstant, NULL);
		break;
	case DW_FORM_string:
		value->kind = DW_AT_KIND_STRING;
		value->string.content = *buf ? strdup((const char *)buf) : NULL;
		buf += (strlen((const char *)buf) + 1);
		break;
	case DW_FORM_block1:
		value->kind = DW_AT_KIND_BLOCK;
		value->block.length = READ8(buf);
		buf = fill_block_data(buf, buf_end, &value->block);
		break;
	case DW_FORM_block2:
		value->kind = DW_AT_KIND_BLOCK;
		value->block.length = READ16(buf);
		if (value->block.length > 0) {
			value->block.data = calloc(sizeof(ut8), value->block.length);
			if (!value->block.data) {
				return NULL;
			}
			for (j = 0; j < value->block.length; j++) {
				value->block.data[j] = READ8(buf);
			}
		}
		break;
	case DW_FORM_block4:
		value->kind = DW_AT_KIND_BLOCK;
		value->block.length = READ32(buf);
		buf = fill_block_data(buf, buf_end, &value->block);
		break;
	case DW_FORM_block: // variable length ULEB128
		value->kind = DW_AT_KIND_BLOCK;
		buf = rz_uleb128(buf, buf_end - buf, &value->block.length, NULL);
		if (!buf || buf >= buf_end) {
			return NULL;
		}
		buf = fill_block_data(buf, buf_end, &value->block);
		break;
	case DW_FORM_flag:
		value->kind = DW_AT_KIND_FLAG;
		value->flag = READ8(buf);
		break;
	// offset in .debug_str
	case DW_FORM_strp:
		value->kind = DW_AT_KIND_STRING;
		value->string.offset = dwarf_read_offset(hdr->is_64bit, big_endian, &buf, buf_end);
		if (debug_str && value->string.offset < debug_str_len) {
			value->string.content =
				strdup((const char *)(debug_str + value->string.offset));
		} else {
			value->string.content = NULL; // Means malformed DWARF, should we print error message?
		}
		break;
	// offset in .debug_info
	case DW_FORM_ref_addr:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = dwarf_read_offset(hdr->is_64bit, big_endian, &buf, buf_end);
		break;
	// This type of reference is an offset from the first byte of the compilation
	// header for the compilation unit containing the reference
	case DW_FORM_ref1:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = hdr->unit_offset + READ8(buf);
		break;
	case DW_FORM_ref2:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = hdr->unit_offset + READ16(buf);
		break;
	case DW_FORM_ref4:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = hdr->unit_offset + READ32(buf);
		break;
	case DW_FORM_ref8:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = hdr->unit_offset + READ64(buf);
		break;
	case DW_FORM_ref_udata:
		value->kind = DW_AT_KIND_REFERENCE;
		// uleb128 is enough to fit into ut64?
		buf = rz_uleb128(buf, buf_end - buf, &value->reference, NULL);
		value->reference += hdr->unit_offset;
		break;
	// offset in a section other than .debug_info or .debug_str
	case DW_FORM_sec_offset:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = dwarf_read_offset(hdr->is_64bit, big_endian, &buf, buf_end);
		break;
	case DW_FORM_exprloc:
		value->kind = DW_AT_KIND_BLOCK;
		buf = rz_uleb128(buf, buf_end - buf, &value->block.length, NULL);
		if (!buf || buf >= buf_end) {
			return NULL;
		}
		buf = fill_block_data(buf, buf_end, &value->block);
		break;
	// this means that the flag is present, nothing is read
	case DW_FORM_flag_present:
		value->kind = DW_AT_KIND_FLAG;
		value->flag = true;
		break;
	case DW_FORM_ref_sig8:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = READ64(buf);
		break;
	// offset into .debug_line_str section, can't parse the section now, so we just skip
	case DW_FORM_strx:
		value->kind = DW_AT_KIND_STRING;
		// value->string.offset = dwarf_read_offset (hdr->is_64bit, big_endian, &buf, buf_end);
		// if (debug_str && value->string.offset < debug_line_str_len) {
		// 	value->string.content =
		// 		strdup ((const char *)(debug_str + value->string.offset));
		// } else {
		// 	value->string.content = NULL; // Means malformed DWARF, should we print error message?
		// }
		break;
	case DW_FORM_strx1:
		value->kind = DW_AT_KIND_STRING;
		value->string.offset = READ8(buf);
		break;
	case DW_FORM_strx2:
		value->kind = DW_AT_KIND_STRING;
		value->string.offset = READ16(buf);
		break;
	case DW_FORM_strx3: // TODO Add 3 byte int read
		value->kind = DW_AT_KIND_STRING;
		buf += 3;
		break;
	case DW_FORM_strx4:
		value->kind = DW_AT_KIND_STRING;
		value->string.offset = READ32(buf);
		break;
	case DW_FORM_implicit_const:
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = def->special;
		break;
	/*  addrx* forms : The index is relative to the value of the
		DW_AT_addr_base attribute of the associated compilation unit.
	    index into an array of addresses in the .debug_addr section.*/
	case DW_FORM_addrx:
		value->kind = DW_AT_KIND_ADDRESS;
		buf = rz_uleb128(buf, buf_end - buf, &value->address, NULL);
		break;
	case DW_FORM_addrx1:
		value->kind = DW_AT_KIND_ADDRESS;
		value->address = READ8(buf);
		break;
	case DW_FORM_addrx2:
		value->kind = DW_AT_KIND_ADDRESS;
		value->address = READ16(buf);
		break;
	case DW_FORM_addrx3:
		// I need to add 3byte endianess free read here TODO
		value->kind = DW_AT_KIND_ADDRESS;
		buf += 3;
		break;
	case DW_FORM_addrx4:
		value->kind = DW_AT_KIND_ADDRESS;
		value->address = READ32(buf);
		break;
	case DW_FORM_line_ptr: // offset in a section .debug_line_str
	case DW_FORM_strp_sup: // offset in a section .debug_line_str
		value->kind = DW_AT_KIND_STRING;
		value->string.offset = dwarf_read_offset(hdr->is_64bit, big_endian, &buf, buf_end);
		// if (debug_str && value->string.offset < debug_line_str_len) {
		// 	value->string.content =
		// 		strdupsts
		break;
	// offset in the supplementary object file
	case DW_FORM_ref_sup4:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = READ32(buf);
		break;
	case DW_FORM_ref_sup8:
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference = READ64(buf);
		break;
	// An index into the .debug_loc
	case DW_FORM_loclistx:
		value->kind = DW_AT_KIND_LOCLISTPTR;
		value->reference = dwarf_read_offset(hdr->is_64bit, big_endian, &buf, buf_end);
		break;
		// An index into the .debug_rnglists
	case DW_FORM_rnglistx:
		value->kind = DW_AT_KIND_ADDRESS;
		buf = rz_uleb128(buf, buf_end - buf, &value->address, NULL);
		break;
	default:
		eprintf("Unknown DW_FORM 0x%02" PFMT64x "\n", def->attr_form);
		value->uconstant = 0;
		return NULL;
	}
	return buf;
}

/**
 * \param buf Start of the DIE data
 * \param buf_end
 * \param info debug info where the line_info_offset_comp_dir will be populated if such an entry is found
 * \param abbrev Abbreviation of the DIE
 * \param hdr Unit header
 * \param die DIE to store the parsed info into
 * \param debug_str Ptr to string section start
 * \param debug_str_len Length of the string section
 * \return const ut8* Updated buffer
 */
static const ut8 *parse_die(const ut8 *buf, const ut8 *buf_end, RzBinDwarfDebugInfo *info, RzBinDwarfAbbrevDecl *abbrev,
	RzBinDwarfCompUnitHdr *hdr, RzBinDwarfDie *die, const ut8 *debug_str, size_t debug_str_len, bool big_endian) {
	size_t i;
	const char *comp_dir = NULL;
	ut64 line_info_offset = UT64_MAX;
	for (i = 0; i < abbrev->count - 1; i++) {
		memset(&die->attr_values[i], 0, sizeof(die->attr_values[i]));

		buf = parse_attr_value(buf, buf_end - buf, &abbrev->defs[i],
			&die->attr_values[i], hdr, debug_str, debug_str_len, big_endian);

		RzBinDwarfAttrValue *attribute = &die->attr_values[i];

		if (attribute->attr_name == DW_AT_comp_dir && (attribute->attr_form == DW_FORM_strp || attribute->attr_form == DW_FORM_string) && attribute->string.content) {
			comp_dir = attribute->string.content;
		}
		if (attribute->attr_name == DW_AT_stmt_list) {
			if (attribute->kind == DW_AT_KIND_CONSTANT) {
				line_info_offset = attribute->uconstant;
			} else if (attribute->kind == DW_AT_KIND_REFERENCE) {
				line_info_offset = attribute->reference;
			}
		}
		die->count++;
	}

	// If this is a compilation unit dir attribute, we want to cache it so the line info parsing
	// which will need this info can quickly look it up.
	if (comp_dir && line_info_offset != UT64_MAX) {
		char *name = strdup(comp_dir);
		if (name) {
			if (!ht_up_insert(info->line_info_offset_comp_dir, line_info_offset, name)) {
				free(name);
			}
		}
	}

	return buf;
}

/**
 * @brief Reads throught comp_unit buffer and parses all its DIEntries
 *
 * @param buf_start Start of the compilation unit data
 * @param unit Unit to store the newly parsed information
 * @param abbrevs Parsed abbrev section info of *all* abbreviations
 * @param first_abbr_idx index for first abbrev of the current comp unit in abbrev array
 * @param debug_str Ptr to string section start
 * @param debug_str_len Length of the string section
 *
 * @return const ut8* Update buffer
 */
static const ut8 *parse_comp_unit(RzBinDwarfDebugInfo *info, const ut8 *buf_start,
	RzBinDwarfCompUnit *unit, const RzBinDwarfDebugAbbrev *abbrevs,
	size_t first_abbr_idx, const ut8 *debug_str, size_t debug_str_len, bool big_endian) {

	const ut8 *buf = buf_start;
	const ut8 *buf_end = buf_start + unit->hdr.length - unit->hdr.header_size;

	while (buf && buf < buf_end && buf >= buf_start) {
		if (unit->count && unit->capacity == unit->count) {
			expand_cu(unit);
		}
		RzBinDwarfDie *die = &unit->dies[unit->count];
		// add header size to the offset;
		die->offset = buf - buf_start + unit->hdr.header_size + unit->offset;
		die->offset += unit->hdr.is_64bit ? 12 : 4;

		// DIE starts with ULEB128 with the abbreviation code
		ut64 abbr_code;
		buf = rz_uleb128(buf, buf_end - buf, &abbr_code, NULL);

		if (abbr_code > abbrevs->count || !buf) { // something invalid
			return NULL;
		}

		if (buf >= buf_end) {
			unit->count++; // we wanna store this entry too, usually the last one is null_entry
			return buf; // return the buffer to parse next compilation units
		}
		// there can be "null" entries that have abbr_code == 0
		if (!abbr_code) {
			unit->count++;
			continue;
		}
		ut64 abbr_idx = first_abbr_idx + abbr_code;

		if (abbrevs->count < abbr_idx) {
			return NULL;
		}
		RzBinDwarfAbbrevDecl *abbrev = &abbrevs->decls[abbr_idx - 1];

		if (init_die(die, abbr_code, abbrev->count)) {
			return NULL; // error
		}
		die->tag = abbrev->tag;
		die->has_children = abbrev->has_children;

		buf = parse_die(buf, buf_end, info, abbrev, &unit->hdr, die, debug_str, debug_str_len, big_endian);
		if (!buf) {
			return NULL;
		}

		unit->count++;
	}
	return buf;
}

/**
 * @brief Reads all information about compilation unit header
 *
 * @param buf Start of the buffer
 * @param buf_end Upper bound of the buffer
 * @param unit Unit to read information into
 * @return ut8* Advanced position in a buffer
 */
static const ut8 *info_comp_unit_read_hdr(const ut8 *buf, const ut8 *buf_end, RzBinDwarfCompUnitHdr *hdr, bool big_endian) {
	// 32-bit vs 64-bit dwarf formats
	// http://www.dwarfstd.org/doc/Dwarf3.pdf section 7.4
	hdr->length = READ32(buf);
	if (hdr->length == (ut32)DWARF_INIT_LEN_64) { // then its 64bit
		hdr->length = READ64(buf);
		hdr->is_64bit = true;
	}
	const ut8 *tmp = buf; // to calculate header size
	hdr->version = READ16(buf);
	if (hdr->version == 5) {
		hdr->unit_type = READ8(buf);
		hdr->address_size = READ8(buf);
		hdr->abbrev_offset = dwarf_read_offset(hdr->is_64bit, big_endian, &buf, buf_end);

		if (hdr->unit_type == DW_UT_skeleton || hdr->unit_type == DW_UT_split_compile) {
			hdr->dwo_id = READ8(buf);
		} else if (hdr->unit_type == DW_UT_type || hdr->unit_type == DW_UT_split_type) {
			hdr->type_sig = READ64(buf);
			hdr->type_offset = dwarf_read_offset(hdr->is_64bit, big_endian, &buf, buf_end);
		}
	} else {
		hdr->abbrev_offset = dwarf_read_offset(hdr->is_64bit, big_endian, &buf, buf_end);
		hdr->address_size = READ8(buf);
	}
	hdr->header_size = buf - tmp; // header size excluding length field
	return buf;
}
static int expand_info(RzBinDwarfDebugInfo *info) {
	rz_return_val_if_fail(info && info->capacity == info->count, -1);

	RzBinDwarfCompUnit *tmp = realloc(info->comp_units,
		info->capacity * 2 * sizeof(RzBinDwarfCompUnit));
	if (!tmp) {
		return -1;
	}

	memset((ut8 *)tmp + info->capacity * sizeof(RzBinDwarfCompUnit),
		0, info->capacity * sizeof(RzBinDwarfCompUnit));

	info->comp_units = tmp;
	info->capacity *= 2;

	return 0;
}

/**
 * @brief Parses whole .debug_info section
 *
 * @param da Parsed Abbreviations
 * @param obuf .debug_info section buffer start
 * @param len length of the section buffer
 * @param debug_str start of the .debug_str section
 * @param debug_str_len length of the debug_str section
 * @param big_endian
 * @return RZ_API* parse_info_raw Parsed information
 */
static RzBinDwarfDebugInfo *parse_info_raw(RzBinDwarfDebugAbbrev *da,
	const ut8 *obuf, size_t len,
	const ut8 *debug_str, size_t debug_str_len, bool big_endian) {

	rz_return_val_if_fail(da && obuf, false);

	const ut8 *buf = obuf;
	const ut8 *buf_end = obuf + len;

	RzBinDwarfDebugInfo *info = RZ_NEW0(RzBinDwarfDebugInfo);
	if (!info) {
		return NULL;
	}
	if (!init_debug_info(info)) {
		goto cleanup;
	}
	int unit_idx = 0;

	while (buf < buf_end) {
		if (info->count >= info->capacity) {
			if (expand_info(info)) {
				break;
			}
		}

		RzBinDwarfCompUnit *unit = &info->comp_units[unit_idx];
		if (init_comp_unit(unit) < 0) {
			unit_idx--;
			goto cleanup;
		}
		info->count++;

		unit->offset = buf - obuf;
		// small redundancy, because it was easiest solution at a time
		unit->hdr.unit_offset = buf - obuf;

		buf = info_comp_unit_read_hdr(buf, buf_end, &unit->hdr, big_endian);

		if (unit->hdr.length > len) {
			goto cleanup;
		}

		if (da->decls->count >= da->capacity) {
			eprintf("WARNING: malformed dwarf have not enough buckets for decls.\n");
		}
		rz_warn_if_fail(da->count <= da->capacity);

		// find abbrev start for current comp unit
		// we could also do naive, ((char *)da->decls) + abbrev_offset,
		// but this is more bulletproof to invalid DWARF
		RzBinDwarfAbbrevDecl key = { .offset = unit->hdr.abbrev_offset };
		RzBinDwarfAbbrevDecl *abbrev_start = bsearch(&key, da->decls, da->count, sizeof(key), abbrev_cmp);
		if (!abbrev_start) {
			goto cleanup;
		}
		// They point to the same array object, so should be def. behaviour
		size_t first_abbr_idx = abbrev_start - da->decls;

		buf = parse_comp_unit(info, buf, unit, da, first_abbr_idx, debug_str, debug_str_len, big_endian);

		if (!buf) {
			goto cleanup;
		}

		unit_idx++;
	}

	return info;

cleanup:
	rz_bin_dwarf_debug_info_free(info);
	return NULL;
}

static RzBinDwarfDebugAbbrev *parse_abbrev_raw(const ut8 *obuf, size_t len) {
	const ut8 *buf = obuf, *buf_end = obuf + len;
	ut64 tmp, attr_code, attr_form, offset;
	st64 special;
	ut8 has_children;
	RzBinDwarfAbbrevDecl *tmpdecl;

	// XXX - Set a suitable value here.
	if (!obuf || len < 3) {
		return NULL;
	}
	RzBinDwarfDebugAbbrev *da = RZ_NEW0(RzBinDwarfDebugAbbrev);

	init_debug_abbrev(da);

	while (buf && buf + 1 < buf_end) {
		offset = buf - obuf;
		buf = rz_uleb128(buf, (size_t)(buf_end - buf), &tmp, NULL);
		if (!buf || !tmp || buf >= buf_end) {
			continue;
		}
		if (da->count == da->capacity) {
			expand_debug_abbrev(da);
		}
		tmpdecl = &da->decls[da->count];
		init_abbrev_decl(tmpdecl);

		tmpdecl->code = tmp;
		buf = rz_uleb128(buf, (size_t)(buf_end - buf), &tmp, NULL);
		tmpdecl->tag = tmp;

		tmpdecl->offset = offset;
		if (buf >= buf_end) {
			break;
		}
		has_children = READ8(buf);
		tmpdecl->has_children = has_children;
		do {
			if (tmpdecl->count == tmpdecl->capacity) {
				expand_abbrev_decl(tmpdecl);
			}
			buf = rz_uleb128(buf, (size_t)(buf_end - buf), &attr_code, NULL);
			if (buf >= buf_end) {
				break;
			}
			buf = rz_uleb128(buf, (size_t)(buf_end - buf), &attr_form, NULL);
			// http://www.dwarfstd.org/doc/DWARF5.pdf#page=225
			if (attr_form == DW_FORM_implicit_const) {
				buf = rz_leb128(buf, (size_t)(buf_end - buf), &special);
				tmpdecl->defs[tmpdecl->count].special = special;
			}
			tmpdecl->defs[tmpdecl->count].attr_name = attr_code;
			tmpdecl->defs[tmpdecl->count].attr_form = attr_form;
			tmpdecl->count++;
		} while (attr_code && attr_form);

		da->count++;
	}
	return da;
}

RzBinSection *getsection(RzBinFile *binfile, const char *sn) {
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

static ut8 *get_section_bytes(RzBinFile *binfile, const char *sect_name, size_t *len) {
	rz_return_val_if_fail(binfile && sect_name && len, NULL);
	RzBinSection *section = getsection(binfile, sect_name);
	if (!section) {
		return NULL;
	}
	if (section->size > binfile->size) {
		return NULL;
	}
	*len = section->size;
	ut8 *buf = calloc(1, *len);
	rz_buf_read_at(binfile->buf, section->paddr, buf, *len);
	return buf;
}

/**
 * @brief Parses .debug_info section
 *
 * @param da Parsed abbreviations
 * @param bin
 * @return RzBinDwarfDebugInfo* Parsed information, NULL if error
 */
RZ_API RzBinDwarfDebugInfo *rz_bin_dwarf_parse_info(RzBinFile *binfile, RzBinDwarfDebugAbbrev *da) {
	rz_return_val_if_fail(binfile && da, NULL);
	RzBinSection *section = getsection(binfile, "debug_info");
	if (!section) {
		return NULL;
	}

	RzBinDwarfDebugInfo *info = NULL;
	ut64 debug_str_len = 0;
	ut8 *debug_str_buf = NULL;

	RzBinSection *debug_str = debug_str = getsection(binfile, "debug_str");
	if (debug_str) {
		debug_str_len = debug_str->size;
		debug_str_buf = RZ_NEWS0(ut8, debug_str_len + 1);
		if (!debug_str_buf) {
			goto cave;
		}
		st64 ret = rz_buf_read_at(binfile->buf, debug_str->paddr,
			debug_str_buf, debug_str_len);
		if (!ret) {
			goto cave_debug_str_buf;
		}
	}

	ut64 len = section->size;
	if (!len) {
		goto cave_debug_str_buf;
	}
	ut8 *buf = RZ_NEWS0(ut8, len);
	if (!buf) {
		goto cave_debug_str_buf;
	}
	if (!rz_buf_read_at(binfile->buf, section->paddr, buf, len)) {
		goto cave_buf;
	}
	info = parse_info_raw(da, buf, len, debug_str_buf, debug_str_len,
		binfile->o && binfile->o->info && binfile->o->info->big_endian);
	if (!info) {
		goto cave_buf;
	}

	// build hashtable after whole parsing because of possible relocations
	if (info) {
		size_t i, j;
		for (i = 0; i < info->count; i++) {
			RzBinDwarfCompUnit *unit = &info->comp_units[i];
			for (j = 0; j < unit->count; j++) {
				RzBinDwarfDie *die = &unit->dies[j];
				ht_up_insert(info->lookup_table, die->offset, die); // optimization for further processing}
			}
		}
	}
cave_buf:
	free(buf);
cave_debug_str_buf:
	free(debug_str_buf);
cave:
	return info;
}

/**
 * \param info if not NULL, filenames can get resolved to absolute paths using the compilation unit dirs from it
 */
RZ_API RzBinDwarfLineInfo *rz_bin_dwarf_parse_line(RzBinFile *binfile, RZ_NULLABLE RzBinDwarfDebugInfo *info, RzBinDwarfLineInfoMask mask) {
	rz_return_val_if_fail(binfile, NULL);
	RzBinSection *section = getsection(binfile, "debug_line");
	if (!section) {
		return NULL;
	}
	ut64 len = section->size;
	if (len < 1) {
		return NULL;
	}
	ut8 *buf = RZ_NEWS0(ut8, len + 1);
	if (!buf) {
		return NULL;
	}
	int ret = rz_buf_read_at(binfile->buf, section->paddr, buf, len);
	if (ret != len) {
		free(buf);
		return NULL;
	}
	// Actually parse the section
	RzBinDwarfLineInfo *r = parse_line_raw(binfile, buf, len, mask, binfile->o && binfile->o->info && binfile->o->info->big_endian, info);
	free(buf);
	return r;
}

RZ_API RzList /*<RzBinDwarfARangeSet>*/ *rz_bin_dwarf_parse_aranges(RzBinFile *binfile) {
	rz_return_val_if_fail(binfile, NULL);
	RzBinSection *section = getsection(binfile, "debug_aranges");
	if (!section) {
		return NULL;
	}
	size_t len = section->size;
	if (!len) {
		return NULL;
	}
	ut8 *buf = RZ_NEWS0(ut8, len);
	int ret = rz_buf_read_at(binfile->buf, section->paddr, buf, len);
	if (!ret) {
		free(buf);
		return NULL;
	}
	RzList *r = parse_aranges_raw(buf, len, binfile->o && binfile->o->info && binfile->o->info->big_endian);
	free(buf);
	return r;
}

RZ_API RzBinDwarfDebugAbbrev *rz_bin_dwarf_parse_abbrev(RzBinFile *binfile) {
	rz_return_val_if_fail(binfile, NULL);
	size_t len = 0;
	ut8 *buf = get_section_bytes(binfile, "debug_abbrev", &len);
	if (!buf) {
		return NULL;
	}
	RzBinDwarfDebugAbbrev *abbrevs = parse_abbrev_raw(buf, len);
	free(buf);
	return abbrevs;
}

static inline ut64 get_max_offset(size_t addr_size) {
	switch (addr_size) {
	case 2:
		return UT16_MAX;
	case 4:
		return UT32_MAX;
	case 8:
		return UT64_MAX;
	}
	return 0;
}

static inline RzBinDwarfLocList *create_loc_list(ut64 offset) {
	RzBinDwarfLocList *list = RZ_NEW0(RzBinDwarfLocList);
	if (list) {
		list->list = rz_list_new();
		list->offset = offset;
	}
	return list;
}

static inline RzBinDwarfLocRange *create_loc_range(ut64 start, ut64 end, RzBinDwarfBlock *block) {
	RzBinDwarfLocRange *range = RZ_NEW0(RzBinDwarfLocRange);
	if (range) {
		range->start = start;
		range->end = end;
		range->expression = block;
	}
	return range;
}

static void free_loc_table_list(RzBinDwarfLocList *loc_list) {
	RzListIter *iter;
	RzBinDwarfLocRange *range;
	rz_list_foreach (loc_list->list, iter, range) {
		free(range->expression->data);
		free(range->expression);
		free(range);
	}
	rz_list_free(loc_list->list);
	free(loc_list);
}

static HtUP *parse_loc_raw(HtUP /*<offset, List *<LocListEntry>*/ *loc_table, const ut8 *buf, size_t len, size_t addr_size,
	bool big_endian) {
	/* GNU has their own extensions GNU locviews that we can't parse */
	const ut8 *const buf_start = buf;
	const ut8 *buf_end = buf + len;
	/* for recognizing Base address entry */
	ut64 max_offset = get_max_offset(addr_size);

	ut64 address_base = 0; /* remember base of the loclist */
	ut64 list_offset = 0;

	RzBinDwarfLocList *loc_list = NULL;
	RzBinDwarfLocRange *range = NULL;
	while (buf && buf < buf_end) {
		ut64 start_addr = dwarf_read_address(addr_size, big_endian, &buf, buf_end);
		ut64 end_addr = dwarf_read_address(addr_size, big_endian, &buf, buf_end);

		if (start_addr == 0 && end_addr == 0) { /* end of list entry: 0, 0 */
			if (loc_list) {
				ht_up_insert(loc_table, loc_list->offset, loc_list);
				list_offset = buf - buf_start;
				loc_list = NULL;
			}
			address_base = 0;
			continue;
		} else if (start_addr == max_offset && end_addr != max_offset) {
			/* base address, DWARF2 doesn't have this type of entry, these entries shouldn't
			   be in the list, they are just informational entries for further parsing (address_base) */
			address_base = end_addr;
		} else { /* location list entry: */
			if (!loc_list) {
				loc_list = create_loc_list(list_offset);
			}
			/* TODO in future parse expressions to better structure in dwarf.c and not in dwarf_process.c */
			RzBinDwarfBlock *block = RZ_NEW0(RzBinDwarfBlock);
			block->length = READ16(buf);
			buf = fill_block_data(buf, buf_end, block);
			range = create_loc_range(start_addr + address_base, end_addr + address_base, block);
			if (!range) {
				free(block);
			}
			rz_list_append(loc_list->list, range);
			range = NULL;
		}
	}
	/* if for some reason end of list is missing, then loc_list would leak */
	if (loc_list) {
		free_loc_table_list(loc_list);
	}
	return loc_table;
}

/**
 * @brief Parses out the .debug_loc section into a table that maps each list as
 *        offset of a list -> LocationList
 *
 * @param binfile
 * @param addr_size machine address size used in executable (necessary for parsing)
 * @return RZ_API*
 */
RZ_API HtUP /*<offset, RzBinDwarfLocList*/ *rz_bin_dwarf_parse_loc(RzBinFile *binfile, int addr_size) {
	rz_return_val_if_fail(binfile, NULL);
	/* The standarparse_loc_raw_frame, not sure why is that */
	size_t len = 0;
	ut8 *buf = get_section_bytes(binfile, "debug_loc", &len);
	if (!buf) {
		return NULL;
	}
	HtUP /*<offset, RzBinDwarfLocList*/ *loc_table = ht_up_new0();
	if (!loc_table) {
		free(buf);
		return NULL;
	}
	loc_table = parse_loc_raw(loc_table, buf, len, addr_size, binfile->o && binfile->o->info && binfile->o->info->big_endian);
	free(buf);
	return loc_table;
}

static void free_loc_table_entry(HtUPKv *kv) {
	if (kv) {
		free_loc_table_list(kv->value);
	}
}

RZ_API void rz_bin_dwarf_loc_free(HtUP /*<offset, RzBinDwarfLocList*>*/ *loc_table) {
	rz_return_if_fail(loc_table);
	loc_table->opt.freefn = free_loc_table_entry;
	ht_up_free(loc_table);
}
