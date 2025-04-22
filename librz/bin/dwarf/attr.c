// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"
/**
 * \brief Parses attribute value based on its definition
 *        and stores it into `value`
 */
RZ_IPI bool RzBinDwarfAttr_parse(
	RzBinEndianReader *R, RzBinDwarfAttr *attr, AttrOption *opt) {
	rz_return_val_if_fail(opt && opt->encoding && attr && R, false);
	ut64 unit_offset = opt->unit_offset;
	attr->at = opt->at;
	attr->form = opt->form;
	ut8 address_size = opt->encoding->address_size;
	bool is_64bit = opt->encoding->is_64bit;
	RzBinDwarfAttrValue *value = &attr->value;

	// http://www.dwarfstd.org/doc/DWARF4.pdf#page=161&zoom=100,0,560
	switch (attr->form) {
	case DW_FORM_addr:
		value->kind = RzBinDwarfAttr_Addr;
		RET_FALSE_IF_FAIL(R_read_address(R, &value->u64, address_size));
		break;
	case DW_FORM_data1:
		value->kind = RzBinDwarfAttr_UConstant;
		U8_OR_RET_FALSE(value->u64);
		break;
	case DW_FORM_data2:
		value->kind = RzBinDwarfAttr_UConstant;
		U_OR_RET_FALSE(16, value->u64);
		break;
	case DW_FORM_data4:
		value->kind = RzBinDwarfAttr_UConstant;
		U_OR_RET_FALSE(32, value->u64);
		break;
	case DW_FORM_data8:
		value->kind = RzBinDwarfAttr_UConstant;
		U_OR_RET_FALSE(64, value->u64);
		break;
	case DW_FORM_data16:
		value->kind = RzBinDwarfAttr_UConstant;
		if (!R_read128(R, &value->u128)) {
			return false;
		}
		break;
	case DW_FORM_sdata:
		value->kind = RzBinDwarfAttr_Constant;
		SLE128_OR_RET_FALSE(value->s64);
		break;
	case DW_FORM_udata:
		value->kind = RzBinDwarfAttr_UConstant;
		ULE128_OR_RET_FALSE(value->u64);
		break;
	case DW_FORM_string:
		value->kind = RzBinDwarfAttr_String;
		RET_FALSE_IF_FAIL(R_read_cstring(R, &value->string));
		break;
	case DW_FORM_block1:
		value->kind = RzBinDwarfAttr_Block;
		U8_OR_RET_FALSE(value->block.length);
		RET_FALSE_IF_FAIL(R_read_block(R, &value->block));
		break;
	case DW_FORM_block2:
		value->kind = RzBinDwarfAttr_Block;
		U_OR_RET_FALSE(16, value->block.length);
		RET_FALSE_IF_FAIL(R_read_block(R, &value->block));
		break;
	case DW_FORM_block4:
		value->kind = RzBinDwarfAttr_Block;
		U_OR_RET_FALSE(32, value->block.length);
		RET_FALSE_IF_FAIL(R_read_block(R, &value->block));
		break;
	case DW_FORM_block: // variable length ULEB128
		value->kind = RzBinDwarfAttr_Block;
		ULE128_OR_RET_FALSE(value->block.length);
		RET_FALSE_IF_FAIL(R_read_block(R, &value->block));
		break;
	case DW_FORM_flag:
		value->kind = RzBinDwarfAttr_Flag;
		U8_OR_RET_FALSE(value->flag);
		break;
		// offset in .debug_str
	case DW_FORM_strp:
		value->kind = RzBinDwarfAttr_StrRef;
		RET_FALSE_IF_FAIL(R_read_offset(R, &value->u64, is_64bit));
		break;
		// offset in .debug_info
	case DW_FORM_ref_addr:
		value->kind = RzBinDwarfAttr_Reference;
		if (opt->encoding->version == 2) {
			RET_FALSE_IF_FAIL(R_read_address(R, &value->u64, opt->encoding->address_size));
		} else {
			RET_FALSE_IF_FAIL(R_read_offset(R, &value->u64, is_64bit));
		}
		break;
		// This type of u64 is an offset from the first byte of the compilation
		// header for the compilation unit containing the u64
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8: {
		value->kind = RzBinDwarfAttr_UnitRef;
		static const int index_sizes[] = { 1, 2, 4, 8 };
		RET_FALSE_IF_FAIL(R_read_address(R, &value->u64, index_sizes[attr->form - DW_FORM_ref1]));
		value->u64 += unit_offset;
		break;
	}
	case DW_FORM_ref_udata:
		value->kind = RzBinDwarfAttr_UnitRef;
		ULE128_OR_RET_FALSE(value->u64);
		value->u64 += unit_offset;
		break;
		// offset in a section other than .debug_info or .debug_str
	case DW_FORM_sec_offset:
		value->kind = RzBinDwarfAttr_SecOffset;
		RET_FALSE_IF_FAIL(R_read_offset(R, &value->u64, is_64bit));
		break;
	case DW_FORM_exprloc:
		value->kind = RzBinDwarfAttr_Block;
		ULE128_OR_RET_FALSE(value->block.length);
		RET_FALSE_IF_FAIL(R_read_block(R, &value->block));
		break;
		// this means that the flag is present, nothing is read
	case DW_FORM_flag_present:
		value->kind = RzBinDwarfAttr_Flag;
		value->flag = true;
		break;
	case DW_FORM_ref_sig8:
		value->kind = RzBinDwarfAttr_Reference;
		U_OR_RET_FALSE(64, value->u64);
		break;
	/// offset into .debug_str_offsets section
	case DW_FORM_strx:
		value->kind = RzBinDwarfAttr_StrOffsetIndex;
		ULE128_OR_RET_FALSE(value->u64);
		break;
	case DW_FORM_strx1:
		value->kind = RzBinDwarfAttr_StrOffsetIndex;
		U8_OR_RET_FALSE(value->u64);
		break;
	case DW_FORM_strx2:
		value->kind = RzBinDwarfAttr_StrOffsetIndex;
		U_OR_RET_FALSE(16, value->u64);
		break;
	case DW_FORM_strx3:
		value->kind = RzBinDwarfAttr_StrOffsetIndex;
		READ24_OR(ut64, value->u64, return false);
		break;
	case DW_FORM_strx4:
		value->kind = RzBinDwarfAttr_StrOffsetIndex;
		U_OR_RET_FALSE(32, value->u64);
		break;
	case DW_FORM_implicit_const:
		value->kind = RzBinDwarfAttr_Constant;
		value->u64 = opt->implicit_const;
		break;
	/**  addrx* forms : The index is relative to the value of the
		DW_AT_addr_base attribute of the associated compilation unit.
	    index into an array of addresses in the .debug_addr section.*/
	case DW_FORM_addrx:
		value->kind = RzBinDwarfAttr_AddrIndex;
		ULE128_OR_RET_FALSE(value->u64);
		break;
	case DW_FORM_addrx1:
		value->kind = RzBinDwarfAttr_AddrIndex;
		U8_OR_RET_FALSE(value->u64);
		break;
	case DW_FORM_addrx2:
		value->kind = RzBinDwarfAttr_AddrIndex;
		U_OR_RET_FALSE(16, value->u64);
		break;
	case DW_FORM_addrx3:
		value->kind = RzBinDwarfAttr_AddrIndex;
		READ24_OR(ut64, value->u64, return false);
		break;
	case DW_FORM_addrx4:
		value->kind = RzBinDwarfAttr_AddrIndex;
		U_OR_RET_FALSE(32, value->u64);
		break;
	case DW_FORM_line_ptr: // offset in a section .debug_line_str
		value->kind = RzBinDwarfAttr_LineStrRef;
		RET_FALSE_IF_FAIL(R_read_offset(R, &value->u64, is_64bit));
		break;
	case DW_FORM_strp_sup:
		value->kind = RzBinDwarfAttr_StrRef;
		RET_FALSE_IF_FAIL(R_read_offset(R, &value->u64, is_64bit));
		break;
		// offset in the supplementary object file
	case DW_FORM_ref_sup4:
		value->kind = RzBinDwarfAttr_Reference;
		U_OR_RET_FALSE(32, value->u64);
		break;
	case DW_FORM_ref_sup8:
		value->kind = RzBinDwarfAttr_Reference;
		U_OR_RET_FALSE(64, value->u64);
		break;
		// An index into the .debug_loc
	case DW_FORM_loclistx:
		value->kind = RzBinDwarfAttr_LoclistPtr;
		ULE128_OR_RET_FALSE(value->u64);
		break;
		// An index into the .debug_rnglists
	case DW_FORM_rnglistx:
		value->kind = RzBinDwarfAttr_RangelistPtr;
		ULE128_OR_RET_FALSE(value->u64);
		break;
	default:
		RZ_LOG_ERROR("Unknown DW_FORM 0x%02" PFMT32x "\n", attr->form);
		value->u64 = 0;
		return false;
	}
	return true;
}

/**
 * \brief Safely get the string from an RzBinDwarfAttrValue if it has one.
 */
RZ_API const char *rz_bin_dwarf_attr_string(
	RZ_BORROW RZ_NONNULL const RzBinDwarfAttr *attr,
	RZ_BORROW RZ_NULLABLE const RzBinDWARF *dw,
	ut64 str_offsets_base) {
	rz_return_val_if_fail(attr, NULL);

	const RzBinDwarfAttrValue *v = &attr->value;
	const char *orig = NULL;
	if (v->kind == RzBinDwarfAttr_String) {
		orig = v->string;
	} else if (v->kind == RzBinDwarfAttr_StrRef && dw) {
		orig = rz_bin_dwarf_str_get(dw->str, v->u64);
	} else if (v->kind == RzBinDwarfAttr_StrOffsetIndex && dw) {
		orig = rz_bin_dwarf_str_offsets_get(dw->str, dw->str_offsets, str_offsets_base, v->u64);
	} else if (v->kind == RzBinDwarfAttr_LineStrRef && dw) {
		orig = rz_bin_dwarf_line_str_get(rz_bin_dwarf_line_str(dw), v->u64);
	}
	return orig;
}

RZ_API RZ_OWN char *rz_bin_dwarf_attr_string_escaped(
	RZ_BORROW RZ_NONNULL const RzBinDwarfAttr *attr,
	RZ_BORROW RZ_NULLABLE const RzBinDWARF *dw,
	ut64 str_offsets_base) {
	const char *str_ref = rz_bin_dwarf_attr_string(attr, dw, str_offsets_base);
	if (!str_ref) {
		return NULL;
	}
	return str_escape_utf8_copy(str_ref);
}

RZ_API void rz_bin_dwarf_attr_dump(
	RZ_NONNULL RZ_BORROW const RzBinDwarfAttr *attr,
	RZ_BORROW RZ_NULLABLE RzBinDWARF *dw,
	ut64 str_offsets_base,
	RZ_NONNULL RZ_BORROW RzStrBuf *sb) {
	rz_return_if_fail(attr && sb);

	const char *attr_name = rz_bin_dwarf_attr(attr->at);
	if (attr_name) {
		rz_strbuf_appendf(sb, "\t%s ", attr_name);
	} else {
		rz_strbuf_appendf(sb, "\tAT_unk [0x%-3" PFMT32x "]\t ", attr->at);
	}
	rz_strbuf_appendf(sb, "[%s]\t: ", rz_str_get_null(rz_bin_dwarf_form(attr->form)));

	switch (attr->at) {
	case DW_AT_language:
		rz_strbuf_append(sb, rz_str_get_null(rz_bin_dwarf_lang(attr->value.u64)));
		rz_strbuf_append(sb, ", raw: ");
		break;
	case DW_AT_encoding:
		rz_strbuf_append(sb, rz_str_get_null(rz_bin_dwarf_ate(attr->value.u64)));
		rz_strbuf_append(sb, ", raw: ");
		break;
	default: break;
	}

	switch (attr->form) {
	case DW_FORM_block:
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
	case DW_FORM_exprloc:
		rz_strbuf_appendf(sb, "%" PFMT64u " byte block:",
			rz_bin_dwarf_attr_block(attr)->length);
		rz_bin_dwarf_block_dump(rz_bin_dwarf_attr_block(attr), sb);
		break;
	case DW_FORM_data1:
	case DW_FORM_data2:
	case DW_FORM_data4:
	case DW_FORM_data8:
	case DW_FORM_data16:
		rz_strbuf_appendf(sb, "%" PFMT64u "", rz_bin_dwarf_attr_udata(attr));
		break;
	case DW_FORM_flag:
		rz_strbuf_appendf(sb, "%u", rz_bin_dwarf_attr_flag(attr));
		break;
	case DW_FORM_sdata:
		rz_strbuf_appendf(sb, "%" PFMT64d "", rz_bin_dwarf_attr_sdata(attr));
		break;
	case DW_FORM_udata:
		rz_strbuf_appendf(sb, "%" PFMT64u "", rz_bin_dwarf_attr_udata(attr));
		break;
	case DW_FORM_ref_addr:
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
	case DW_FORM_ref_sig8:
	case DW_FORM_ref_udata:
	case DW_FORM_ref_sup4:
	case DW_FORM_ref_sup8:
	case DW_FORM_sec_offset:
		rz_strbuf_appendf(sb, "<0x%" PFMT64x ">", rz_bin_dwarf_attr_udata(attr));
		break;
	case DW_FORM_flag_present:
		rz_strbuf_append(sb, "1");
		break;
	case DW_FORM_string:
	case DW_FORM_strx:
	case DW_FORM_strx1:
	case DW_FORM_strx2:
	case DW_FORM_strx3:
	case DW_FORM_strx4:
	case DW_FORM_line_ptr:
	case DW_FORM_strp_sup:
	case DW_FORM_strp: {
		switch (attr->value.kind) {
		case RzBinDwarfAttr_String:
			break;
		case RzBinDwarfAttr_StrOffsetIndex:
			rz_strbuf_appendf(sb, "(index 0x%" PFMT64x "): ", attr->value.u64);
			break;
		case RzBinDwarfAttr_StrRef:
			rz_strbuf_appendf(sb, "(.debug_str+0x%" PFMT64x "): ", attr->value.u64);
			break;
		case RzBinDwarfAttr_LineStrRef:
			rz_strbuf_appendf(sb, "(.debug_line_str+0x%" PFMT64x "): ", attr->value.u64);
			break;
		default:
			break;
		}
		strbuf_append_string_own(sb, rz_bin_dwarf_attr_string_escaped(attr, dw, str_offsets_base));
		break;
	}
	case DW_FORM_addr:
	case DW_FORM_addrx:
	case DW_FORM_addrx1:
	case DW_FORM_addrx2:
	case DW_FORM_addrx3:
	case DW_FORM_addrx4:
	case DW_FORM_loclistx:
	case DW_FORM_rnglistx:
		rz_strbuf_appendf(sb, "0x%" PFMT64x "", rz_bin_dwarf_attr_udata(attr));
		break;
	case DW_FORM_implicit_const:
		rz_strbuf_appendf(sb, "0x%" PFMT64d "", rz_bin_dwarf_attr_udata(attr));
		break;
	default:
		rz_strbuf_appendf(sb, "Unknown attr value form %s\n", rz_bin_dwarf_form(attr->form));
		break;
	}
}
