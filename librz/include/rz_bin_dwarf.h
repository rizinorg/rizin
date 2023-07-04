#ifndef RZ_BIN_DWARF_H
#define RZ_BIN_DWARF_H

#include <rz_types.h>
#include <rz_bin.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rz_bin_source_line_info_builder_t;

enum DW_LNS {
	DW_LNS_copy = 0x01,
	DW_LNS_advance_pc = 0x02,
	DW_LNS_advance_line = 0x03,
	DW_LNS_set_file = 0x04,
	DW_LNS_set_column = 0x05,
	DW_LNS_negate_stmt = 0x06,
	DW_LNS_set_basic_block = 0x07,
	DW_LNS_const_add_pc = 0x08,
	DW_LNS_fixed_advance_pc = 0x09,
	DW_LNS_set_prologue_end = 0x0a, /* DWARF3 */
	DW_LNS_set_epilogue_begin = 0x0b, /* DWARF3 */
	DW_LNS_set_isa = 0x0c, /* DWARF3 */
};

/* Line number extended opcode name. */
enum DW_LNE {
	DW_LNE_end_sequence = 0x01,
	DW_LNE_set_address = 0x02,
	DW_LNE_define_file = 0x03,
	DW_LNE_set_discriminator = 0x04, /* DWARF4 */
	DW_LNE_lo_user = 0x80, /* DWARF3 */
	DW_LNE_hi_user = 0xff, /* DWARF3 */
	/* HP extensions. */
	DW_LNE_HP_negate_is_UV_update = 0x11, /* 17 HP */
	DW_LNE_HP_push_context = 0x12, /* 18 HP */
	DW_LNE_HP_pop_context = 0x13, /* 19 HP */
	DW_LNE_HP_set_file_line_column = 0x14, /* 20 HP */
	DW_LNE_HP_set_routine_name = 0x15, /* 21 HP */
	DW_LNE_HP_set_sequence = 0x16, /* 22 HP */
	DW_LNE_HP_negate_post_semantics = 0x17, /* 23 HP */
	DW_LNE_HP_negate_function_exit = 0x18, /* 24 HP */
	DW_LNE_HP_negate_front_end_logical = 0x19, /* 25 HP */
	DW_LNE_HP_define_proc = 0x20, /* 32 HP */
};

/* debug_info tags */
// this is not a real dwarf named entry, but I wanted to give it
// a name so it's more obvious and readable that it's just a type of entry
enum DW_TAG {
	DW_TAG_null_entry = 0x00,
	DW_TAG_array_type = 0x01,
	DW_TAG_class_type = 0x02,
	DW_TAG_entry_point = 0x03,
	DW_TAG_enumeration_type = 0x04,
	DW_TAG_formal_parameter = 0x05,
	DW_TAG_imported_declaration = 0x08,
	DW_TAG_label = 0x0a,
	DW_TAG_lexical_block = 0x0b,
	DW_TAG_member = 0x0d,
	DW_TAG_pointer_type = 0x0f,
	DW_TAG_reference_type = 0x10,
	DW_TAG_compile_unit = 0x11, //
	DW_TAG_string_type = 0x12,
	DW_TAG_structure_type = 0x13,
	DW_TAG_subroutine_type = 0x15,
	DW_TAG_typedef = 0x16,
	DW_TAG_union_type = 0x17,
	DW_TAG_unspecified_parameters = 0x18,
	DW_TAG_variant = 0x19,
	DW_TAG_common_block = 0x1a,
	DW_TAG_common_inclusion = 0x1b,
	DW_TAG_inheritance = 0x1c,
	DW_TAG_inlined_subroutine = 0x1d,
	DW_TAG_module = 0x1e,
	DW_TAG_ptr_to_member_type = 0x1f,
	DW_TAG_set_type = 0x20,
	DW_TAG_subrange_type = 0x21,
	DW_TAG_with_stmt = 0x22,
	DW_TAG_access_declaration = 0x23,
	DW_TAG_base_type = 0x24,
	DW_TAG_catch_block = 0x25,
	DW_TAG_const_type = 0x26,
	DW_TAG_constant = 0x27,
	DW_TAG_enumerator = 0x28,
	DW_TAG_file_type = 0x29,
	DW_TAG_friend = 0x2a,
	DW_TAG_namelist = 0x2b,
	/*  Early releases of this header had the following
		    misspelled with a trailing 's' */
	DW_TAG_namelist_item = 0x2c, /* DWARF3/2 spelling */
	DW_TAG_namelist_items = 0x2c, /* SGI misspelling/typo */
	DW_TAG_packed_type = 0x2d,
	DW_TAG_subprogram = 0x2e,
	/*  The DWARF2 document had two spellings of the following
		    two TAGs, DWARF3 specifies the longer spelling. */
	DW_TAG_template_type_parameter = 0x2f, /* DWARF3/2 spelling*/
	DW_TAG_template_type_param = 0x2f, /* DWARF2   spelling*/
	DW_TAG_template_value_parameter = 0x30, /* DWARF3/2 spelling*/
	DW_TAG_template_value_param = 0x30, /* DWARF2   spelling*/
	DW_TAG_thrown_type = 0x31,
	DW_TAG_try_block = 0x32,
	DW_TAG_variant_part = 0x33,
	DW_TAG_variable = 0x34,
	DW_TAG_volatile_type = 0x35,
	DW_TAG_dwarf_procedure = 0x36, /* DWARF3 */
	DW_TAG_restrict_type = 0x37, /* DWARF3 */
	DW_TAG_interface_type = 0x38, /* DWARF3 */
	DW_TAG_namespace = 0x39, /* DWARF3 */
	DW_TAG_imported_module = 0x3a, /* DWARF3 */
	DW_TAG_unspecified_type = 0x3b, /* DWARF3 */
	DW_TAG_partial_unit = 0x3c, /* DWARF3 */
	DW_TAG_imported_unit = 0x3d, /* DWARF3 */
	/*  Do not use DW_TAG_mutable_type */
	DW_TAG_mutable_type = 0x3e, /* Withdrawn from DWARF3 by DWARF3f. */
	DW_TAG_condition = 0x3f, /* DWARF3f */
	DW_TAG_shared_type = 0x40, /* DWARF3f */
	DW_TAG_type_unit = 0x41, /* DWARF4 */
	DW_TAG_rvalue_reference_type = 0x42, /* DWARF4 */
	DW_TAG_template_alias = 0x43, /* DWARF4 */
	DW_TAG_LAST = 0x44, // correct ?
	/* <_lo_user ; _hi_user> Interval is reserved for vendor extensions */
	DW_TAG_lo_user = 0x4080,
	DW_TAG_hi_user = 0xffff,
};

enum DW_CHILDREN {
	DW_CHILDREN_no = 0x00,
	DW_CHILDREN_yes = 0x01,
};

enum DW_AT {
	DW_AT_sibling = 0x01,
	DW_AT_location = 0x02,
	DW_AT_name = 0x03,
	DW_AT_ordering = 0x09,
	DW_AT_byte_size = 0x0b,
	DW_AT_bit_offset = 0x0c,
	DW_AT_bit_size = 0x0d,
	DW_AT_stmt_list = 0x10,
	DW_AT_low_pc = 0x11,
	DW_AT_high_pc = 0x12,
	DW_AT_language = 0x13,
	DW_AT_discr = 0x15,
	DW_AT_discr_value = 0x16,
	DW_AT_visibility = 0x17,
	DW_AT_import = 0x18,
	DW_AT_string_length = 0x19,
	DW_AT_common_reference = 0x1a,
	DW_AT_comp_dir = 0x1b,
	DW_AT_const_value = 0x1c,
	DW_AT_containing_type = 0x1d,
	DW_AT_default_value = 0x1e,
	DW_AT_inline = 0x20,
	DW_AT_is_optional = 0x21,
	DW_AT_lower_bound = 0x22,
	DW_AT_producer = 0x25,
	DW_AT_prototyped = 0x27,
	DW_AT_return_addr = 0x2a,
	DW_AT_start_scope = 0x2c,
	DW_AT_stride_size = 0x2e,
	DW_AT_upper_bound = 0x2f,
	DW_AT_abstract_origin = 0x31,
	DW_AT_accessibility = 0x32,
	DW_AT_address_class = 0x33,
	DW_AT_artificial = 0x34,
	DW_AT_base_types = 0x35,
	DW_AT_calling_convention = 0x36,
	DW_AT_count = 0x37,
	DW_AT_data_member_location = 0x38,
	DW_AT_decl_column = 0x39,
	DW_AT_decl_file = 0x3a,
	DW_AT_decl_line = 0x3b,
	DW_AT_declaration = 0x3c,
	DW_AT_discr_list = 0x3d,
	DW_AT_encoding = 0x3e,
	DW_AT_external = 0x3f,
	DW_AT_frame_base = 0x40,
	DW_AT_friend = 0x41,
	DW_AT_identifier_case = 0x42,
	DW_AT_macro_info = 0x43,
	DW_AT_namelist_item = 0x44,
	DW_AT_priority = 0x45,
	DW_AT_segment = 0x46,
	DW_AT_specification = 0x47,
	DW_AT_static_link = 0x48,
	DW_AT_type = 0x49,
	DW_AT_use_location = 0x4a,
	DW_AT_variable_parameter = 0x4b,
	DW_AT_virtuality = 0x4c,
	DW_AT_vtable_elem_location = 0x4d,
	DW_AT_allocated = 0x4e, // DWARF 3 additions start
	DW_AT_associated = 0x4f,
	DW_AT_data_location = 0x50,
	DW_AT_byte_stride = 0x51,
	DW_AT_entry_pc = 0x52,
	DW_AT_use_UTF8 = 0x53,
	DW_AT_extension = 0x54,
	DW_AT_ranges = 0x55,
	DW_AT_trampoline = 0x56,
	DW_AT_call_column = 0x57,
	DW_AT_call_file = 0x58,
	DW_AT_call_line = 0x59,
	DW_AT_description = 0x5a,
	DW_AT_binary_scale = 0x5b,
	DW_AT_decimal_scale = 0x5c,
	DW_AT_small = 0x5d,
	DW_AT_decimal_sign = 0x5e,
	DW_AT_digit_count = 0x5f,
	DW_AT_picture_string = 0x60,
	DW_AT_mutable = 0x61,
	DW_AT_threads_scaled = 0x62,
	DW_AT_explicit = 0x63,
	DW_AT_object_pointer = 0x64,
	DW_AT_endianity = 0x65,
	DW_AT_elemental = 0x66,
	DW_AT_pure = 0x67,
	DW_AT_recursive = 0x68, // DWARF 3 additions end
	DW_AT_signature = 0x69,
	DW_AT_main_subprogram = 0x6a,
	DW_AT_data_bit_offset = 0x6b,
	DW_AT_const_expr = 0x6c,
	DW_AT_enum_class = 0x6d,
	DW_AT_linkage_name = 0x6e,
	DW_AT_string_length_bit_size = 0x6f,
	DW_AT_string_length_byte_size = 0x70,
	DW_AT_rank = 0x71,
	DW_AT_str_offsets_base = 0x72,
	DW_AT_addr_base = 0x73,
	DW_AT_rnglists_base = 0x74,
	DW_AT_reserved = 0x75,
	DW_AT_dwo_name = 0x76,
	DW_AT_reference = 0x77,
	DW_AT_rvalue_reference = 0x78,
	DW_AT_macros = 0x79,
	DW_AT_call_all_calls = 0x7a,
	DW_AT_call_all_source_calls = 0x7b,
	DW_AT_call_all_tail_calls = 0x7c,
	DW_AT_call_return_pc = 0x7d,
	DW_AT_call_value = 0x7e,
	DW_AT_call_origin = 0x7f,
	DW_AT_call_parameter = 0x80,
	DW_AT_call_pc = 0x81,
	DW_AT_call_tail_call = 0x82,
	DW_AT_call_target = 0x83,
	DW_AT_call_target_clobbered = 0x84,
	DW_AT_call_data_location = 0x85,
	DW_AT_call_data_value = 0x86,
	DW_AT_noreturn = 0x87,
	DW_AT_alignment = 0x88,
	DW_AT_export_symbols = 0x89,
	DW_AT_deleted = 0x8a,
	DW_AT_defaulted = 0x8b,
	DW_AT_loclists_base = 0x8c,
	/* <_lo_user ; _hi_user> Interval is reserved for vendor extensions */
	DW_AT_lo_user = 0x2000,
	// extensions:
	DW_AT_MIPS_linkage_name = 0x2007, // Same as DWARF4 DW_AT_linkage_name
	DW_AT_GNU_call_site_value = 0x2111,
	DW_AT_GNU_call_site_data_value = 0x2112,
	DW_AT_GNU_call_site_target = 0x2113,
	DW_AT_GNU_call_site_target_clobbered = 0x2114,
	DW_AT_GNU_tail_call = 0x2115,
	DW_AT_GNU_all_tail_call_sites = 0x2116,
	DW_AT_GNU_all_call_sites = 0x2117,
	DW_AT_GNU_all_source_call_sites = 0x2118,
	DW_AT_GNU_macros = 0x2119,
	DW_AT_GNU_deleted = 0x211a,
	DW_AT_GNU_dwo_name = 0x2130,
	DW_AT_GNU_dwo_id = 0x2131,
	DW_AT_GNU_ranges_base = 0x2132,
	DW_AT_GNU_addr_base = 0x2133,
	DW_AT_GNU_pubnames = 0x2134,
	DW_AT_GNU_pubtypes = 0x2135,
	DW_AT_hi_user = 0x3fff,
};

enum DW_FORM {
	DW_FORM_addr = 0x01,
	DW_FORM_block2 = 0x03,
	DW_FORM_block4 = 0x04,
	DW_FORM_data2 = 0x05,
	DW_FORM_data4 = 0x06,
	DW_FORM_data8 = 0x07,
	DW_FORM_string = 0x08,
	DW_FORM_block = 0x09,
	DW_FORM_block1 = 0x0a,
	DW_FORM_data1 = 0x0b,
	DW_FORM_flag = 0x0c,
	DW_FORM_sdata = 0x0d,
	DW_FORM_strp = 0x0e,
	DW_FORM_udata = 0x0f,
	DW_FORM_ref_addr = 0x10,
	DW_FORM_ref1 = 0x11,
	DW_FORM_ref2 = 0x12,
	DW_FORM_ref4 = 0x13,
	DW_FORM_ref8 = 0x14,
	DW_FORM_ref_udata = 0x15,
	DW_FORM_indirect = 0x16,
	DW_FORM_sec_offset = 0x17, // DWARF 4 new attribute for section offset
	DW_FORM_exprloc = 0x18,
	DW_FORM_flag_present = 0x19,
	DW_FORM_strx = 0x1a,
	DW_FORM_addrx = 0x1b,
	DW_FORM_ref_sup4 = 0x1c,
	DW_FORM_strp_sup = 0x1d,
	DW_FORM_data16 = 0x1e,
	DW_FORM_line_ptr = 0x1f,
	DW_FORM_ref_sig8 = 0x20,
	DW_FORM_implicit_const = 0x21,
	DW_FORM_loclistx = 0x22,
	DW_FORM_rnglistx = 0x23,
	DW_FORM_ref_sup8 = 0x24,
	DW_FORM_strx1 = 0x25,
	DW_FORM_strx2 = 0x26,
	DW_FORM_strx3 = 0x27,
	DW_FORM_strx4 = 0x28,
	DW_FORM_addrx1 = 0x29,
	DW_FORM_addrx2 = 0x2a,
	DW_FORM_addrx3 = 0x2b,
	DW_FORM_addrx4 = 0x2c,
};

enum DW_OP {
	DW_OP_addr = 0x03,
	DW_OP_deref = 0x06,
	DW_OP_const1u = 0x08,
	DW_OP_const1s = 0x09,
	DW_OP_const2u = 0x0a,
	DW_OP_const2s = 0x0b,
	DW_OP_const4u = 0x0c,
	DW_OP_const4s = 0x0d,
	DW_OP_const8u = 0x0e,
	DW_OP_const8s = 0x0f,
	DW_OP_constu = 0x10,
	DW_OP_consts = 0x11,
	DW_OP_dup = 0x12,
	DW_OP_drop = 0x13,
	DW_OP_over = 0x14,
	DW_OP_pick = 0x15,
	DW_OP_swap = 0x16,
	DW_OP_rot = 0x17,
	DW_OP_xderef = 0x18,
	DW_OP_abs = 0x19,
	DW_OP_and = 0x1a,
	DW_OP_div = 0x1b,
	DW_OP_minus = 0x1c,
	DW_OP_mod = 0x1d,
	DW_OP_mul = 0x1e,
	DW_OP_neg = 0x1f,
	DW_OP_not = 0x20,
	DW_OP_or = 0x21,
	DW_OP_plus = 0x22,
	DW_OP_plus_uconst = 0x23,
	DW_OP_shl = 0x24,
	DW_OP_shr = 0x25,
	DW_OP_shra = 0x26,
	DW_OP_xor = 0x27,
	DW_OP_skip = 0x2f,
	DW_OP_bra = 0x28,
	DW_OP_eq = 0x29,
	DW_OP_ge = 0x2a,
	DW_OP_gt = 0x2b,
	DW_OP_le = 0x2c,
	DW_OP_lt = 0x2d,
	DW_OP_ne = 0x2e,
	DW_OP_lit0 = 0x30,
	DW_OP_lit1 = 0x31,
	DW_OP_lit2 = 0x32,
	DW_OP_lit3 = 0x33,
	DW_OP_lit4 = 0x34,
	DW_OP_lit5 = 0x35,
	DW_OP_lit6 = 0x36,
	DW_OP_lit7 = 0x37,
	DW_OP_lit8 = 0x38,
	DW_OP_lit9 = 0x39,
	DW_OP_lit10 = 0x3a,
	DW_OP_lit11 = 0x3b,
	DW_OP_lit12 = 0x3c,
	DW_OP_lit13 = 0x3d,
	DW_OP_lit14 = 0x3e,
	DW_OP_lit15 = 0x3f,
	DW_OP_lit16 = 0x40,
	DW_OP_lit17 = 0x41,
	DW_OP_lit18 = 0x42,
	DW_OP_lit19 = 0x43,
	DW_OP_lit20 = 0x44,
	DW_OP_lit21 = 0x45,
	DW_OP_lit22 = 0x46,
	DW_OP_lit23 = 0x47,
	DW_OP_lit24 = 0x48,
	DW_OP_lit25 = 0x49,
	DW_OP_lit26 = 0x4a,
	DW_OP_lit27 = 0x4b,
	DW_OP_lit28 = 0x4c,
	DW_OP_lit29 = 0x4d,
	DW_OP_lit30 = 0x4e,
	DW_OP_lit31 = 0x4f,
	DW_OP_reg0 = 0x50,
	DW_OP_reg1 = 0x51,
	DW_OP_reg2 = 0x52,
	DW_OP_reg3 = 0x53,
	DW_OP_reg4 = 0x54,
	DW_OP_reg5 = 0x55,
	DW_OP_reg6 = 0x56,
	DW_OP_reg7 = 0x57,
	DW_OP_reg8 = 0x58,
	DW_OP_reg9 = 0x59,
	DW_OP_reg10 = 0x5a,
	DW_OP_reg11 = 0x5b,
	DW_OP_reg12 = 0x5c,
	DW_OP_reg13 = 0x5d,
	DW_OP_reg14 = 0x5e,
	DW_OP_reg15 = 0x5f,
	DW_OP_reg16 = 0x60,
	DW_OP_reg17 = 0x61,
	DW_OP_reg18 = 0x62,
	DW_OP_reg19 = 0x63,
	DW_OP_reg20 = 0x64,
	DW_OP_reg21 = 0x65,
	DW_OP_reg22 = 0x66,
	DW_OP_reg23 = 0x67,
	DW_OP_reg24 = 0x68,
	DW_OP_reg25 = 0x69,
	DW_OP_reg26 = 0x6a,
	DW_OP_reg27 = 0x6b,
	DW_OP_reg28 = 0x6c,
	DW_OP_reg29 = 0x6d,
	DW_OP_reg30 = 0x6e,
	DW_OP_reg31 = 0x6f,
	DW_OP_breg0 = 0x70,
	DW_OP_breg1 = 0x71,
	DW_OP_breg2 = 0x72,
	DW_OP_breg3 = 0x73,
	DW_OP_breg4 = 0x74,
	DW_OP_breg5 = 0x75,
	DW_OP_breg6 = 0x76,
	DW_OP_breg7 = 0x77,
	DW_OP_breg8 = 0x78,
	DW_OP_breg9 = 0x79,
	DW_OP_breg10 = 0x7a,
	DW_OP_breg11 = 0x7b,
	DW_OP_breg12 = 0x7c,
	DW_OP_breg13 = 0x7d,
	DW_OP_breg14 = 0x7e,
	DW_OP_breg15 = 0x7f,
	DW_OP_breg16 = 0x80,
	DW_OP_breg17 = 0x81,
	DW_OP_breg18 = 0x82,
	DW_OP_breg19 = 0x83,
	DW_OP_breg20 = 0x84,
	DW_OP_breg21 = 0x85,
	DW_OP_breg22 = 0x86,
	DW_OP_breg23 = 0x87,
	DW_OP_breg24 = 0x88,
	DW_OP_breg25 = 0x89,
	DW_OP_breg26 = 0x8a,
	DW_OP_breg27 = 0x8b,
	DW_OP_breg28 = 0x8c,
	DW_OP_breg29 = 0x8d,
	DW_OP_breg30 = 0x8e,
	DW_OP_breg31 = 0x8f,
	DW_OP_regx = 0x90,
	DW_OP_fbreg = 0x91,
	DW_OP_bregx = 0x92,
	DW_OP_piece = 0x93,
	DW_OP_deref_size = 0x94,
	DW_OP_xderef_size = 0x95,
	DW_OP_nop = 0x96,
	DW_OP_push_object_address = 0x97,
	DW_OP_call2 = 0x98,
	DW_OP_call4 = 0x99,
	DW_OP_call_ref = 0x9a,
	DW_OP_form_tls_address = 0x9b,
	DW_OP_call_frame_cfa = 0x9c,
	DW_OP_bit_piece = 0x9d,
	DW_OP_implicit_value = 0x9e,
	DW_OP_stack_value = 0x9f,
	DW_OP_implicit_pointer = 0xa0,
	DW_OP_addrx = 0xa1,
	DW_OP_constx = 0xa2,
	DW_OP_entry_value = 0xa3,
	DW_OP_const_type = 0xa4,
	DW_OP_regval_type = 0xa5,
	DW_OP_deref_type = 0xa6,
	DW_OP_xderef_type = 0xa7,
	DW_OP_convert = 0xa8,
	DW_OP_reinterpret = 0xa9,

	// GNU extensions
	DW_OP_GNU_push_tls_address = 0xe0,
	DW_OP_GNU_implicit_pointer = 0xf2,
	DW_OP_GNU_entry_value = 0xf3,
	DW_OP_GNU_const_type = 0xf4,
	DW_OP_GNU_regval_type = 0xf5,
	DW_OP_GNU_deref_type = 0xf6,
	DW_OP_GNU_convert = 0xf7,
	DW_OP_GNU_reinterpret = 0xf9,
	DW_OP_GNU_parameter_ref = 0xfa,
	DW_OP_GNU_addr_index = 0xfb,
	DW_OP_GNU_const_index = 0xfc,

	// Wasm extensions
	DW_OP_WASM_location = 0xed,
	/* <_lo_user ; _hi_user> Interval is reserved for vendor extensions */
	DW_OP_lo_user = 0xe0,
	DW_OP_hi_user = 0xff,
};

enum DW_ATE {
	DW_ATE_address = 0x01,
	DW_ATE_boolean = 0x02,
	DW_ATE_complex_float = 0x03,
	DW_ATE_float = 0x04,
	DW_ATE_signed = 0x05,
	DW_ATE_signed_char = 0x06,
	DW_ATE_unsigned = 0x07,
	DW_ATE_unsigned_char = 0x08,
	DW_ATE_imaginary_float = 0x09,
	DW_ATE_packed_decimal = 0x0a,
	DW_ATE_numeric_string = 0x0b,
	DW_ATE_edited = 0x0c,
	DW_ATE_signed_fixed = 0x0d,
	DW_ATE_unsigned_fixed = 0x0e,
	DW_ATE_decimal_float = 0x0f,
	DW_ATE_UTF = 0x10,
	/* <_lo_user ; _hi_user> Interval is reserved for vendor extensions */
	DW_ATE_lo_user = 0x80,
	DW_ATE_hi_user = 0xff,
};

/// Range list entry encoding values.
///
/// See Section 7.25, Table 7.30.
enum DW_RLE {
	DW_RLE_end_of_list = 0x00,
	DW_RLE_base_addressx = 0x01,
	DW_RLE_startx_endx = 0x02,
	DW_RLE_startx_length = 0x03,
	DW_RLE_offset_pair = 0x04,
	DW_RLE_base_address = 0x05,
	DW_RLE_start_end = 0x06,
	DW_RLE_start_length = 0x07,
};

/// The encodings of the constants used in location list entries.
///
/// See Section 7.7.3, Table 7.10.
enum DW_LLE {
	DW_LLE_end_of_list = 0x00,
	DW_LLE_base_addressx = 0x01,
	DW_LLE_startx_endx = 0x02,
	DW_LLE_startx_length = 0x03,
	DW_LLE_offset_pair = 0x04,
	DW_LLE_default_location = 0x05,
	DW_LLE_base_address = 0x06,
	DW_LLE_start_end = 0x07,
	DW_LLE_start_length = 0x08,
	DW_LLE_GNU_view_pair = 0x09,
};

enum DW_DS {
	DW_DS_unsigned = 0x01,
	DW_DS_leading_overpunch = 0x02,
	DW_DS_trailing_overpunch = 0x03,
	DW_DS_leading_separate = 0x04,
	DW_DS_trailing_separate = 0x05,
};

enum DW_END {
	DW_END_default = 0x00,
	DW_END_big = 0x01,
	DW_END_little = 0x02,
	/* <_lo_user ; _hi_user> Interval is reserved for vendor extensions */
	DW_END_lo_user = 0x40,
	DW_END_hi_user = 0xff,
};

enum DW_ACCESS {
	DW_ACCESS_public = 0x01,
	DW_ACCESS_protected = 0x02,
	DW_ACCESS_private = 0x03,
};

enum DW_VIS {
	DW_VIS_local = 0x01,
	DW_VIS_exported = 0x02,
	DW_VIS_qualified = 0x03,
};

enum DW_VIRTUALITY {
	DW_VIRTUALITY_none = 0x00,
	DW_VIRTUALITY_virtual = 0x01,
	DW_VIRTUALITY_pure_virtual = 0x02,
};

enum DW_LANG {
	DW_LANG_C89 = 0x0001,
	DW_LANG_C = 0x0002,
	DW_LANG_Ada83 = 0x0003,
	DW_LANG_C_plus_plus = 0x0004,
	DW_LANG_Cobol74 = 0x0005,
	DW_LANG_Cobol85 = 0x0006,
	DW_LANG_Fortran77 = 0x0007,
	DW_LANG_Fortran90 = 0x0008,
	DW_LANG_Pascal83 = 0x0009,
	DW_LANG_Modula2 = 0x000a,
	DW_LANG_Java = 0x000b,
	DW_LANG_C99 = 0x000c,
	DW_LANG_Ada95 = 0x000d,
	DW_LANG_Fortran95 = 0x000e,
	DW_LANG_PLI = 0x000f,
	DW_LANG_ObjC = 0x0010,
	DW_LANG_ObjC_plus_plus = 0x0011,
	DW_LANG_UPC = 0x0012,
	DW_LANG_D = 0x0013,
	DW_LANG_Python = 0x0014,
	DW_LANG_Rust = 0x001c,
	DW_LANG_C11 = 0x001d,
	DW_LANG_Swift = 0x001e,
	DW_LANG_Julia = 0x001f,
	DW_LANG_Dylan = 0x0020,
	DW_LANG_C_plus_plus_14 = 0x0021,
	DW_LANG_Fortran03 = 0x0022,
	DW_LANG_Fortran08 = 0x0023,
	DW_LANG_lo_user = 0x8000,
	DW_LANG_hi_user = 0xffff,

	DW_LANG_Mips_Assembler = 0x8001,
	DW_LANG_GOOGLE_RenderScript = 0x8e57,
	DW_LANG_SUN_Assembler = 0x9001,
	DW_LANG_ALTIUM_Assembler = 0x9101,
	DW_LANG_BORLAND_Delphi = 0xb000,
};

enum DW_ID {
	DW_ID_case_sensitive = 0x00,
	DW_ID_up_case = 0x01,
	DW_ID_down_case = 0x02,
	DW_ID_case_insensitive = 0x03,
};

enum DW_CC {
	DW_CC_normal = 0x01,
	DW_CC_program = 0x02,
	DW_CC_nocall = 0x03,
	DW_CC_lo_user = 0x40,
	DW_CC_hi_user = 0xff,
};

enum DW_INL {
	DW_INL_not_inlined = 0x00,
	DW_INL_inlined = 0x01,
	DW_INL_declared_not_inlined = 0x02,
	DW_INL_declared_inlined = 0x03,
};

enum DW_ORD {
	DW_ORD_row_major = 0x00,
	DW_ORD_col_major = 0x01,
};

enum DW_DSC {
	DW_DSC_label = 0x00,
	DW_DSC_range = 0x01,
};

enum DW_MACINFO {
	DW_MACINFO_define = 0x01,
	DW_MACINFO_undef = 0x02,
	DW_MACINFO_start_file = 0x03,
	DW_MACINFO_end_file = 0x04,
	DW_MACINFO_vendor_ext = 0xff,
};

enum DW_CFA {
	DW_CFA_advance_loc = 0x40,
	DW_CFA_offset = 0x80,
	DW_CFA_restore = 0xc0,
	DW_CFA_nop = 0x00,
	DW_CFA_set_loc = 0x01,
	DW_CFA_advance_loc1 = 0x02,
	DW_CFA_advance_loc2 = 0x03,
	DW_CFA_advance_loc4 = 0x04,
	DW_CFA_offse_extended = 0x05,
	DW_CFA_restore_extended = 0x06,
	DW_CFA_undefined = 0x07,
	DW_CFA_same_value = 0x08,
	DW_CFA_register = 0x09,
	DW_CFA_remember_state = 0x0a,
	DW_CFA_restore_state = 0x0b,
	DW_CFA_def_cfa = 0x0c,
	DW_CFA_def_cfa_register = 0x0d,
	DW_CFA_def_cfa_offset = 0x0e,
	DW_CFA_def_cfa_expression = 0x0f,
	DW_CFA_expression = 0x10,
	DW_CFA_offset_extended_sf = 0x11,
	DW_CFA_def_cfa_sf = 0x12,
	DW_CFA_def_cfa_offset_sf = 0x13,
	DW_CFA_val_offset = 0x14,
	DW_CFA_val_offset_sf = 0x15,
	DW_CFA_val_expression = 0x16,
	DW_CFA_lo_user = 0x1c,
	DW_CFA_hi_user = 0x3f,
};

enum DW_UT {
	DW_UT_compile = 0x01,
	DW_UT_type = 0x02,
	DW_UT_partial = 0x03,
	DW_UT_skeleton = 0x04,
	DW_UT_split_compile = 0x05,
	DW_UT_split_type = 0x06,
	DW_UT_lo_user = 0x80,
	DW_UT_hi_user = 0xff,
};

/// The encodings for the line number header entry formats.
///
/// See Section 7.22, Table 7.27.
enum DW_LNCT {
	DW_LNCT_path = 0x1,
	DW_LNCT_directory_index = 0x2,
	DW_LNCT_timestamp = 0x3,
	DW_LNCT_size = 0x4,
	DW_LNCT_MD5 = 0x5,
	DW_LNCT_lo_user = 0x2000,
	DW_LNCT_hi_user = 0x3fff,
};

typedef struct {
	ut32 total_length;
	ut16 version;
	ut32 plen;
	ut8 mininstlen;
	ut8 is_stmt;
	char line_base;
	ut8 line_range;
	ut8 opcode_base;
	ut32 oplentable[12];
	const char **incdirs;
	const char *file[128];
} RzBinDwarfInfoHeader;
#define RZ_BIN_DWARF_INFO_HEADER_FILE_LENGTH(x) (sizeof(x->file) / sizeof(*(x->file)))

typedef struct {
	ut64 address;
	unsigned int file;
	unsigned int line;
	unsigned int column;
	int is_stmt;
	int basic_block;
	int end_sequence;
} RzBinDwarfState;

typedef union {
	ut32 offset32;
	ut64 offset64;
} section_offset;

typedef struct {
	ut64 unit_length;
	ut16 version;
	section_offset debug_abbrev_offset;
	ut8 address_size;
	ut64 type_signature;
	section_offset type_offset;
} RzBinDwarfTypeUnitHeader;

typedef struct {
	ut64 unit_length;
	ut16 version;
	section_offset debug_info_offset;
	ut8 address_size;
	ut8 segment_size;
} RzBinDwarfAddressRangeTable;

typedef struct {
	enum DW_AT name;
	enum DW_FORM form;
	st64 special; // Used for values coded directly into abbrev
} RzBinDwarfAttrDef;

typedef struct {
	ut8 *data;
	ut64 length;
} RzBinDwarfBlock;

// http://www.dwarfstd.org/doc/DWARF4.pdf#page=29&zoom=100,0,0
typedef enum DW_AT_KIND {
	DW_AT_KIND_ADDRESS,
	DW_AT_KIND_BLOCK,
	DW_AT_KIND_CONSTANT,
	DW_AT_KIND_UCONSTANT,
	DW_AT_KIND_EXPRLOC,
	DW_AT_KIND_FLAG,
	DW_AT_KIND_LINEPTR,
	DW_AT_KIND_LOCLISTPTR,
	DW_AT_KIND_MACPTR,
	DW_AT_KIND_RANGELISTPTR,
	DW_AT_KIND_REFERENCE,
	DW_AT_KIND_STRING,
} RzBinDwarfAttrKind;

typedef struct dwarf_attr_t {
	enum DW_AT name;
	enum DW_FORM form;
	RzBinDwarfAttrKind kind;
	/* This is subideal, as dw_form_data can be anything
	   we could lose information example: encoding signed
	   2 byte int into ut64 and then interpreting it as st64 TODO*/
	union {
		ut64 address;
		RzBinDwarfBlock block;
		ut64 uconstant;
		ut128 uconstant128;
		st64 sconstant;
		ut8 flag;
		ut64 reference;
		struct {
			char *content;
			ut64 offset;
		} string;
	};
} RzBinDwarfAttr;

/**
 * \brief Safely get the string content from an RzBinDwarfAttrValue if it has one.
 */
static inline const char *rz_bin_dwarf_attr_value_get_string_content(const RzBinDwarfAttr *val) {
	rz_return_val_if_fail(val, NULL);
	return val->kind == DW_AT_KIND_STRING ? val->string.content : NULL;
}

typedef struct {
	// A 4-byte (or 8 byte for 64bit dwarf) unsigned length of the .debug_info contribution
	// for that compilation unit, not including the length field itself.
	ut64 length;
	ut16 version;
	// A 4-byte unsigned offset into the .debug_abbrev section.
	ut64 abbrev_offset;
	// A 1 - byte size of an address on the target architecture.If the system uses
	//  segmented addressing, this value represents the size of the offset portion of an address.
	ut8 address_size;
	enum DW_UT unit_type; // DWARF 5 addition
	ut8 dwo_id; // DWARF 5 addition
	ut64 type_sig; // DWARF 5 addition
	ut64 type_offset; // DWARF 5 addition
	ut64 header_size; // excluding length field
	ut64 unit_offset;
	bool is_64bit;
} RzBinDwarfCompUnitHdr;

typedef struct {
	ut64 offset; // important for parsing types
	enum DW_TAG tag;
	ut64 abbrev_code;
	enum DW_CHILDREN has_children; // important for parsing types
	RzVector /*<RzBinDwarfAttrValue>*/ attrs;
	size_t unit_offset;
	size_t index;
	size_t depth;
} RzBinDwarfDie;

typedef struct rz_bin_dwarf_comp_unit_t {
	ut64 offset;
	RzBinDwarfCompUnitHdr hdr;
	RzVector /*<RzBinDwarfDie>*/ dies;
} RzBinDwarfCompUnit;

typedef struct {
	RzVector /*<RzBinDwarfCompUnit>*/ units;
	HtUP /*<ut64, DwarfDie *>*/ *die_tbl;
	HtUP /*<ut64, RzBinDwarfCompUnit *>*/ *unit_tbl;
	size_t die_count;
	/**
	 * Cache mapping from an offset in the debug_line section to a string
	 * representing the DW_AT_comp_dir attribute of the compilation unit
	 * that references this particular line information.
	 */
	HtUP /*<ut64, char *>*/ *line_info_offset_comp_dir;
} RzBinDwarfDebugInfo;

typedef struct {
	ut64 code;
	enum DW_TAG tag;
	ut64 offset;
	enum DW_CHILDREN has_children;
	RzVector /*<RzBinDwarfAttrDef>*/ defs;
} RzBinDwarfAbbrevDecl;

typedef struct {
	RzVector /*<RzBinDwarfAbbrevDecl>*/ abbrevs;
	size_t offset;
} RzBinDwarfAbbrevTable;

typedef struct {
	HtUP /*<size_t,RzBinDwarfDebugAbbrevTable*>*/ *tbl;
	size_t count;
} RzBinDwarfDebugAbbrevs;

#define DWARF_FALSE 0
#define DWARF_TRUE  1

typedef struct {
	ut64 address;
	ut64 op_index;
	ut64 file;
	ut64 line;
	ut64 column;
	ut8 is_stmt;
	ut8 basic_block;
	ut8 end_sequence;
	ut8 prologue_end;
	ut8 epilogue_begin;
	ut64 isa;
	ut64 discriminator;
} RzBinDwarfSMRegisters;

typedef struct rz_bin_dwarf_line_file_entry_format_t {
	enum DW_LNCT content_type;
	enum DW_FORM form;
} RzBinDwarfFileEntryFormat;

typedef struct {
	char *path_name;
	ut64 directory_index;
	ut64 timestamp;
	ut64 size;
	ut8 md5[16];
} RzBinDwarfFileEntry;

typedef struct {
	ut64 offset; //< offset inside the debug_line section, for references from outside
	ut64 unit_length;
	ut16 version;
	ut64 header_length;
	ut8 min_inst_len;
	ut8 max_ops_per_inst;
	ut8 default_is_stmt;
	st32 line_base;
	ut8 line_range;
	ut8 opcode_base;
	ut8 address_size;
	ut8 segment_selector_size;
	bool is_64bit;

	/**
	 * \brief The number of LEB128 operands for each of the standard opcodes
	 * From standard_opcode_lengths in DWARF 3 standard:
	 * The first element of the array corresponds to the opcode whose value is 1,
	 * and the last element corresponds to the opcode whose value is opcode_base - 1.
	 * Thus, the size of this array is opcode_base - 1.
	 */
	ut8 *std_opcode_lengths;

	RzVector /*<RzBinDwarfFileEntryFormat>*/ directory_entry_formats;
	RzPVector /*<char *>*/ directories;
	RzVector /*<RzBinDwarfFileEntryFormat>*/ file_name_entry_formats;
	RzVector /*<RzBinDwarfFileEntry>*/ file_names;
} RzBinDwarfLineHeader;

typedef enum {
	RZ_BIN_DWARF_LINE_OP_TYPE_SPEC, //< single byte op, no args
	RZ_BIN_DWARF_LINE_OP_TYPE_STD, //< fixed-size op, 0 or more leb128 args (except DW_LNS_fixed_advance_pc)
	RZ_BIN_DWARF_LINE_OP_TYPE_EXT, //< variable-size op, arbitrary format of args
	RZ_BIN_DWARF_LINE_OP_TYPE_EXT_UNKNOWN, //< variable-size op, arbitrary format of args
} RzBinDwarfLineOpType;

typedef struct {
	ut64 offset;
	RzBinDwarfLineOpType type;
	union {
		enum DW_LNS opcode;
		enum DW_LNE ext_opcode;
	};
	struct {
		union {
			ut64 advance_pc; //< DW_LNS_advance_pc
			st64 advance_line; //< DW_LNS_advance_line
			ut64 set_file; //< DW_LNS_set_file
			ut64 set_column; //< DW_LNS_set_column
			ut64 fixed_advance_pc; //< DW_LNS_fixed_advance_pc
			ut64 set_isa; //< DW_LNS_set_isa
			ut64 set_address; //< DW_LNE_set_address
			struct {
				char *filename;
				ut64 dir_index;
			} define_file; //< DW_LNE_define_file
			ut64 set_discriminator; //< DW_LNE_set_discriminator
		};
	} args;
} RzBinDwarfLineOp;

/**
 * \brief DWARF 3 Standard Section 6.2 Line Number Information
 * This contains the entire raw line info for one compilation unit.
 */
typedef struct {
	RzBinDwarfLineHeader header;
	RzVector /*<RzBinDwarfLineOp>*/ ops;
} RzBinDwarfLineUnit;

/**
 * \brief Line info of all compilation units from the entire debug_line section
 */
typedef struct {
	RzList /*<RzBinDwarfLineUnit *>*/ *units;
	struct rz_bin_source_line_info_t *lines;
} RzBinDwarfLineInfo;

typedef enum {
	RZ_BIN_DWARF_LINE_INFO_MASK_BASIC = 0x0, //< parse just the headers
	RZ_BIN_DWARF_LINE_INFO_MASK_OPS = 0x1, //< decode and output all instructions
	RZ_BIN_DWARF_LINE_INFO_MASK_LINES = 0x2 //< run instructions and output the resulting line infos
} RzBinDwarfLineInfoMask;

typedef struct rz_bin_dwarf_arange_t {
	ut64 addr;
	ut64 length;
} RzBinDwarfARange;

/**
 * \brief DWARF 3 Standard Section 6.1.2 Lookup by Address
 */
typedef struct rz_bin_dwarf_arange_set_t {
	ut64 unit_length;
	bool is_64bit;
	ut16 version;
	ut64 debug_info_offset;
	ut8 address_size;
	ut8 segment_size;
	size_t aranges_count;
	RzBinDwarfARange *aranges;
} RzBinDwarfARangeSet;

typedef struct {
	ut8 address_size;
	bool big_endian;
	ut16 version;
	bool is_64bit;
} RzBinDwarfEncoding;

typedef struct {
	RzBinDwarfEncoding encoding;
	ut64 unit_length;
	ut32 offset_entry_count;
	ut8 segment_selector_size;
	ut64 *location_offsets;
} RzBinDwarfListsHeader;

/// A raw address range from the `.debug_ranges` section.
typedef struct {
	/// The beginning address of the range.
	ut64 begin;
	/// The first address past the end of the range.
	ut64 end;
} RzBinDwarfRange;

enum RzBinDwarfRangeListsFormat {
	/// The bare range list format used before DWARF 5.
	RangeListsFormat_Bare,
	/// The DW_RLE encoded range list format used in DWARF 5.
	RangeListsFormat_Rle,
};

/// A raw entry in .debug_rnglists
typedef struct {
	enum DW_RLE encoding;
	bool is_address_or_offset_pair;
	union {
		/// A range from DWARF version <= 4.
		struct {
			ut64 begin; /// Start of range. May be an address or an offset.
			ut64 end; /// End of range. May be an address or an offset.
		} address_or_offset_pair;
		/// DW_RLE_base_address
		struct {
			ut64 addr; /// base address
		} base_address;
		/// DW_RLE_base_addressx
		struct {
			ut64 addr; /// base address
		} base_addressx;
		/// DW_RLE_startx_endx
		struct {
			ut64 begin; /// Start of range.
			ut64 end; /// End of range.
		} startx_endx;
		/// DW_RLE_startx_length
		struct {
			ut64 begin; /// start of range
			ut64 length; /// length of range
		} startx_length;
		/// DW_RLE_offset_pair
		struct {
			ut64 begin; /// Start of range.
			ut64 end; /// End of range.
		} offset_pair;
		/// DW_RLE_start_end
		struct {
			ut64 begin; /// Start of range.
			ut64 end; /// End of range.
		} start_end;
		/// DW_RLE_start_length
		struct {
			ut64 begin; /// Start of range.
			ut64 length; /// Length of range.
		} start_length;
	};
} RzBinDwarfRawRngListEntry;

/// The raw contents of the `.debug_addr` section.
typedef struct {
	RzBuffer *buffer;
} RzBinDwarfDebugAddr;

typedef enum {
	/// The bare location list format used before DWARF 5.
	LOCLISTSFORMAT_BARE,
	/// The DW_LLE encoded range list format used in DWARF 5 and the non-standard GNU
	/// split dwarf extension.
	LOCLISTSFORMAT_LLE,
} RzBinDwarfLocListsFormat;

typedef struct {
	enum DW_LLE encoding;
	bool is_address_or_offset_pair;
	union {
		/// A location from DWARF version <= 4.
		struct {
			ut64 begin; /// Start of range. May be an address or an offset.
			ut64 end; /// End of range. May be an address or an offset.
			RzBinDwarfBlock data; /// expression
		} address_or_offset_pair;
		/// DW_LLE_base_address
		struct {
			ut64 addr; /// base address
		} base_address;
		/// DW_LLE_base_addressx
		struct {
			ut64 addr; /// base address
		} base_addressx;
		/// DW_LLE_startx_endx
		struct {
			ut64 begin; /// Start of range.
			ut64 end; /// End of range.
			RzBinDwarfBlock data; /// expression
		} startx_endx;
		/// DW_LLE_startx_length
		struct {
			ut64 begin; /// start of range
			ut64 length; /// length of range
			RzBinDwarfBlock data; /// expression
		} startx_length;
		/// DW_LLE_offset_pair
		struct {
			ut64 begin; /// Start of range.
			ut64 end; /// End of range.
			RzBinDwarfBlock data; /// expression
		} offset_pair;
		/// DW_LLE_default_location
		struct {
			RzBinDwarfBlock data; /// expression
		} default_location;
		/// DW_LLE_start_end
		struct {
			ut64 begin; /// Start of range.
			ut64 end; /// End of range.
			RzBinDwarfBlock data; /// expression
		} start_end;
		/// DW_LLE_start_length
		struct {
			ut64 begin; /// Start of range.
			ut64 length; /// Length of range.
			RzBinDwarfBlock data; /// expression
		} start_length;
	};
} RzBinDwarfRawLocListEntry;

typedef struct {
	RzBinDwarfRange *range;
	RzBinDwarfBlock *data;
} RzBinDwarfLocationListEntry;

typedef struct {
	RzBuffer *debug_loc;
	RzBuffer *debug_loclists;
	ut64 base_address;
	const RzBinDwarfDebugAddr *debug_addr;
	RzBinDwarfListsHeader hdr;
	RzBinDwarfEncoding encoding;
	RzVector /*<LocationListEntry>*/ entries;
	RzVector /*<RawLocListEntry>*/ raw_entries;
	HtUP /*<ut64, RawLocListEntry>*/ *entry_by_offset;
} RzBinDwarfLocListTable;

typedef RzList /*<RzBinDwarfARangeSet *>*/ RzBinDwarfARangeSets;

RZ_API const char *rz_bin_dwarf_tag(enum DW_TAG tag);
RZ_API const char *rz_bin_dwarf_attr(enum DW_AT attr_code);
RZ_API const char *rz_bin_dwarf_form(enum DW_FORM form_code);
RZ_API const char *rz_bin_dwarf_unit_type(enum DW_UT unit_type);
RZ_API const char *rz_bin_dwarf_lang(enum DW_LANG lang);
RZ_API const char *rz_bin_dwarf_children(enum DW_CHILDREN children);
RZ_API const char *rz_bin_dwarf_lns(enum DW_LNS lns);
RZ_API const char *rz_bin_dwarf_lne(enum DW_LNE lne);
RZ_API const char *rz_bin_dwarf_lnct(enum DW_LNCT lnct);

RZ_API RzList /*<RzBinDwarfARangeSet *>*/ *rz_bin_dwarf_aranges_parse(RzBinFile *binfile);
RZ_API RzBinDwarfDebugAbbrevs *rz_bin_dwarf_abbrev_parse(RzBinFile *binfile);
RZ_API RzBinDwarfDebugInfo *rz_bin_dwarf_info_parse(RzBinFile *binfile, RzBinDwarfDebugAbbrevs *abbrevs);
RZ_API void rz_bin_dwarf_arange_set_free(RzBinDwarfARangeSet *set);
RZ_API void rz_bin_dwarf_info_free(RzBinDwarfDebugInfo *info);
RZ_API void rz_bin_dwarf_abbrev_free(RzBinDwarfDebugAbbrevs *abbrevs);
RZ_API size_t rz_bin_dwarf_abbrev_count(RZ_NONNULL const RzBinDwarfDebugAbbrevs *da);
RZ_API RzBinDwarfAbbrevDecl *rz_bin_dwarf_abbrev_get(RZ_NONNULL const RzBinDwarfAbbrevTable *tbl, size_t idx);
RZ_API size_t rz_bin_dwarf_abbrev_decl_count(RZ_NONNULL const RzBinDwarfAbbrevDecl *decl);

RZ_API RzBinDwarfAttr *rz_bin_dwarf_die_get_attr(const RzBinDwarfDie *die, enum DW_AT name);
RZ_API RzBinDwarfAttrDef *rz_bin_dwarf_abbrev_get_attr(RZ_NONNULL const RzBinDwarfAbbrevDecl *abbrev, enum DW_AT name);

/**
 * \brief Opaque cache for fully resolved filenames during Dwarf Line Info Generation
 * This cache stores full file paths to be optionally used in rz_bin_dwarf_line_op_run().
 * It is strictly associated with the RzBinDwarfLineHeader it has been created with in rz_bin_dwarf_line_header_new_file_cache()
 * and must be freed with the same header in rz_bin_dwarf_line_header_free_file_cache().
 */
typedef RzPVector /*<char *>*/ RzBinDwarfLineFileCache;

RZ_API RzBinDwarfLineInfo *rz_bin_dwarf_parse_line(RzBinFile *binfile, RZ_NULLABLE RzBinDwarfDebugInfo *info, RzBinDwarfLineInfoMask mask);
RZ_API char *rz_bin_dwarf_line_header_get_full_file_path(RZ_NULLABLE const RzBinDwarfDebugInfo *info, const RzBinDwarfLineHeader *header, ut64 file_index);
RZ_API ut64 rz_bin_dwarf_line_header_get_adj_opcode(const RzBinDwarfLineHeader *header, ut8 opcode);
RZ_API ut64 rz_bin_dwarf_line_header_get_spec_op_advance_pc(const RzBinDwarfLineHeader *header, ut8 opcode);
RZ_API st64 rz_bin_dwarf_line_header_get_spec_op_advance_line(const RzBinDwarfLineHeader *header, ut8 opcode);
RZ_API void rz_bin_dwarf_line_header_reset_regs(const RzBinDwarfLineHeader *hdr, RzBinDwarfSMRegisters *regs);
RZ_API bool rz_bin_dwarf_line_op_run(const RzBinDwarfLineHeader *hdr, RzBinDwarfSMRegisters *regs, RzBinDwarfLineOp *op,
	RZ_NULLABLE struct rz_bin_source_line_info_builder_t *bob, RZ_NULLABLE RzBinDwarfDebugInfo *info, RZ_NULLABLE RzBinDwarfLineFileCache *fnc);
RZ_API void rz_bin_dwarf_line_op_fini(RzBinDwarfLineOp *op);
RZ_API void rz_bin_dwarf_line_info_free(RzBinDwarfLineInfo *li);

typedef struct rz_core_bin_dwarf_t {
	RzBinDwarfEncoding encoding;

	RzBinDwarfARangeSets *aranges;
	RzBinDwarfLineInfo *lines;
	RzBinDwarfLocListTable *loc;
	RzBinDwarfDebugInfo *info;
	RzBinDwarfDebugAbbrevs *abbrevs;
	RzBinDwarfDebugAddr *addr;
} RzBinDwarf;

typedef enum {
	RZ_BIN_DWARF_PARSE_ABBREVS = 1 << 1,
	RZ_BIN_DWARF_PARSE_INFO = (1 << 2) | RZ_BIN_DWARF_PARSE_ABBREVS,
	RZ_BIN_DWARF_PARSE_LOC = 1 << 3 | RZ_BIN_DWARF_PARSE_INFO,
	RZ_BIN_DWARF_PARSE_LINES = (1 << 4) | RZ_BIN_DWARF_PARSE_INFO,
	RZ_BIN_DWARF_PARSE_ARANGES = 1 << 5,
	RZ_BIN_DWARF_PARSE_ALL = RZ_BIN_DWARF_PARSE_ABBREVS | RZ_BIN_DWARF_PARSE_INFO | RZ_BIN_DWARF_PARSE_LOC | RZ_BIN_DWARF_PARSE_LINES | RZ_BIN_DWARF_PARSE_ARANGES,
} RzBinDwarfParseFlags;

typedef struct {
	ut8 addr_size;
	bool big_endian;
	RzBinDwarfLineInfoMask line_mask;
	RzBinDwarfParseFlags flags;
} RzBinDwarfParseOptions;

RZ_API RZ_OWN RzBinDwarf *rz_bin_dwarf_parse(RZ_BORROW RZ_NONNULL RzBinFile *bf, RZ_BORROW RZ_NONNULL const RzBinDwarfParseOptions *opt);
RZ_API void rz_bin_dwarf_free(RZ_OWN RzBinDwarf *dw);

// Assuming ValueType is an enum defined elsewhere
typedef enum {
	RzBinDwarfValueType_GENERIC,
	RzBinDwarfValueType_I8,
	RzBinDwarfValueType_U8,
	RzBinDwarfValueType_I16,
	RzBinDwarfValueType_U16,
	RzBinDwarfValueType_I32,
	RzBinDwarfValueType_U32,
	RzBinDwarfValueType_F32,
	RzBinDwarfValueType_I64,
	RzBinDwarfValueType_U64,
	RzBinDwarfValueType_F64,
	RzBinDwarfValueType_LOCATION,
} RzBinDwarfValueType;

struct dw_location_t;

typedef struct {
	RzBinDwarfValueType type;
	union {
		ut64 generic;
		ut8 u8;
		st8 i8;
		ut16 u16;
		st16 i16;
		ut32 u32;
		st32 i32;
		ut64 u64;
		st64 i64;
		float f32;
		double f64;
		struct dw_location_t *location;
	};
} RzBinDwarfValue;

typedef ut64 UnitOffset;
typedef ut64 DebugInfoOffset;

typedef enum {
	RzBinDwarfLocationKind_EMPTY,
	RzBinDwarfLocationKind_REGISTER,
	RzBinDwarfLocationKind_REGISTER_OFFSET,
	RzBinDwarfLocationKind_ADDRESS,
	RzBinDwarfLocationKind_VALUE,
	RzBinDwarfLocationKind_BYTES,
	RzBinDwarfLocationKind_IMPLICIT_POINTER,
} RzBinDwarfLocationKind;

typedef struct dw_location_t {
	RzBinDwarfLocationKind kind;

	union {
		ut64 register_number;
		struct {
			ut64 register_number;
			st64 offset;
		} register_offset;
		uint64_t address;
		RzBinDwarfValue value;
		struct { // BYTES
			RzBinDwarfBlock value;
		} bytes;
		struct { // IMPLICIT_POINTER
			DebugInfoOffset value;
			int64_t byte_offset;
		} implicit_pointer;
	};
} RzBinDwarfLocation;

typedef struct {
	bool has_bit_offset;
	ut64 bit_offset;
	RzBinDwarfLocation *location;
	bool has_size_in_bits;
	ut64 size_in_bits;
} RzBinDwarfPiece;

RZ_API RzVector *rz_bin_dwarf_evaluate(RzBinDwarf *dw, RzBuffer *expr, const RzBinDwarfDie *fn);

/// loclists
RZ_API bool rz_bin_dwarf_loclist_table_parse_at(RzBinDwarfLocListTable *self, RzBinDwarfEncoding *encoding, ut64 offset);
RZ_API RzBinDwarfLocListTable *rz_bin_dwarf_loclist_table_parse_all(RzBinFile *bf, RzBinDwarf *dw);
RZ_API RzBinDwarfLocListTable *rz_bin_dwarf_loclists_new(RzBinFile *bf, RzBinDwarf *dw);

#ifdef __cplusplus
}
#endif

#endif
