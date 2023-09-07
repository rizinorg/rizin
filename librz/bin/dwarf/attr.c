// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

#define CHECK_STRING \
	if (!attr->string.content) { \
		const char *tag_str = opt->type == DW_ATTR_TYPE_DEF \
			? rz_bin_dwarf_attr(attr->name) \
			: (opt->type == DW_ATTR_TYPE_FILE_ENTRY_FORMAT \
					  ? rz_bin_dwarf_lnct(opt->format->content_type) \
					  : "unknown"); \
		RZ_LOG_ERROR("Failed to read string [0x%" PFMT64x "] %s [%s]\n", \
			attr->string.offset, tag_str, rz_bin_dwarf_form(attr->form)); \
		return false; \
	}

/**
 * This function is quite incomplete and requires lot of work
 * With parsing various new FORM values
 * \brief Parses attribute value based on its definition
 *        and stores it into `value`
 */
RZ_IPI bool RzBinDwarfAttr_parse(
	RzBuffer *buffer, RzBinDwarfAttr *attr, AttrOption *opt) {
	rz_return_val_if_fail(opt && attr && buffer, false);
	ut8 address_size = 0;
	bool is_64bit = false;
	ut64 unit_offset = 0;
	if (opt->type == DW_ATTR_TYPE_DEF) {
		attr->name = opt->def->name;
		attr->form = opt->def->form;
		address_size = opt->cu->hdr.encoding.address_size;
		is_64bit = opt->cu->hdr.encoding.is_64bit;
		unit_offset = opt->cu->offset;
	} else if (opt->type == DW_ATTR_TYPE_FILE_ENTRY_FORMAT) {
		attr->form = opt->format->form;
		address_size = opt->line_hdr->address_size;
		is_64bit = opt->line_hdr->is_64bit;
		unit_offset = opt->line_hdr->offset;
	} else {
		rz_warn_if_reached();
		return false;
	}

	bool big_endian = opt->big_endian;

	// http://www.dwarfstd.org/doc/DWARF4.pdf#page=161&zoom=100,0,560
	switch (attr->form) {
	case DW_FORM_addr:
		attr->kind = DW_AT_KIND_ADDRESS;
		UX_OR_RET_FALSE(address_size, attr->address);
		break;
	case DW_FORM_data1:
		attr->kind = DW_AT_KIND_UCONSTANT;
		U8_OR_RET_FALSE(attr->uconstant);
		break;
	case DW_FORM_data2:
		attr->kind = DW_AT_KIND_UCONSTANT;
		U_OR_RET_FALSE(16, attr->uconstant);
		break;
	case DW_FORM_data4:
		attr->kind = DW_AT_KIND_UCONSTANT;
		U_OR_RET_FALSE(32, attr->uconstant);
		break;
	case DW_FORM_data8:
		attr->kind = DW_AT_KIND_UCONSTANT;
		U_OR_RET_FALSE(64, attr->uconstant);
		break;
	case DW_FORM_data16:
		attr->kind = DW_AT_KIND_UCONSTANT;
		if (big_endian) {
			U_OR_RET_FALSE(64, attr->uconstant128.High);
			U_OR_RET_FALSE(64, attr->uconstant128.Low);
		} else {
			U_OR_RET_FALSE(64, attr->uconstant128.Low);
			U_OR_RET_FALSE(64, attr->uconstant128.High);
		}
		break;
	case DW_FORM_sdata:
		attr->kind = DW_AT_KIND_CONSTANT;
		SLE128_OR_RET_FALSE(attr->sconstant);
		break;
	case DW_FORM_udata:
		attr->kind = DW_AT_KIND_UCONSTANT;
		ULE128_OR_RET_FALSE(attr->uconstant);
		break;
	case DW_FORM_string:
		attr->kind = DW_AT_KIND_STRING;
		attr->string.content = read_string(buffer);
		CHECK_STRING;
		break;
	case DW_FORM_block1:
		attr->kind = DW_AT_KIND_BLOCK;
		U8_OR_RET_FALSE(attr->block.length);
		RET_FALSE_IF_FAIL(read_block(buffer, &attr->block));
		break;
	case DW_FORM_block2:
		attr->kind = DW_AT_KIND_BLOCK;
		U_OR_RET_FALSE(16, attr->block.length);
		RET_FALSE_IF_FAIL(read_block(buffer, &attr->block));
		break;
	case DW_FORM_block4:
		attr->kind = DW_AT_KIND_BLOCK;
		U_OR_RET_FALSE(32, attr->block.length);
		RET_FALSE_IF_FAIL(read_block(buffer, &attr->block));
		break;
	case DW_FORM_block: // variable length ULEB128
		attr->kind = DW_AT_KIND_BLOCK;
		ULE128_OR_RET_FALSE(attr->block.length);
		RET_FALSE_IF_FAIL(read_block(buffer, &attr->block));
		break;
	case DW_FORM_flag:
		attr->kind = DW_AT_KIND_FLAG;
		U8_OR_RET_FALSE(attr->flag);
		break;
		// offset in .debug_str
	case DW_FORM_strp:
		attr->kind = DW_AT_KIND_STRING;
		RET_FALSE_IF_FAIL(read_offset(buffer, &attr->string.offset, is_64bit, big_endian));
		if (opt->dw->str) {
			attr->string.content = RzBinDwarfStr_get(opt->dw->str, attr->string.offset);
		}
		CHECK_STRING;
		break;
		// offset in .debug_info
	case DW_FORM_ref_addr:
		attr->kind = DW_AT_KIND_REFERENCE;
		RET_FALSE_IF_FAIL(read_offset(buffer, &attr->reference, is_64bit, big_endian));
		break;
		// This type of reference is an offset from the first byte of the compilation
		// header for the compilation unit containing the reference
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8: {
		static const int index_sizes[] = { 1, 2, 4, 8 };
		UX_OR_RET_FALSE(index_sizes[attr->form - DW_FORM_ref1], attr->reference);
		attr->kind = DW_AT_KIND_REFERENCE;
		attr->reference += unit_offset;
		break;
	}
	case DW_FORM_ref_udata:
		attr->kind = DW_AT_KIND_REFERENCE;
		ULE128_OR_RET_FALSE(attr->reference);
		attr->reference += unit_offset;
		break;
		// offset in a section other than .debug_info or .debug_str
	case DW_FORM_sec_offset:
		attr->kind = DW_AT_KIND_REFERENCE;
		RET_FALSE_IF_FAIL(read_offset(buffer, &attr->reference, is_64bit, big_endian));
		break;
	case DW_FORM_exprloc:
		attr->kind = DW_AT_KIND_BLOCK;
		ULE128_OR_RET_FALSE(attr->block.length);
		RET_FALSE_IF_FAIL(read_block(buffer, &attr->block));
		break;
		// this means that the flag is present, nothing is read
	case DW_FORM_flag_present:
		attr->kind = DW_AT_KIND_FLAG;
		attr->flag = true;
		break;
	case DW_FORM_ref_sig8:
		attr->kind = DW_AT_KIND_REFERENCE;
		U_OR_RET_FALSE(64, attr->reference);
		break;
	/// offset into .debug_str_offsets section
	case DW_FORM_strx:
		attr->kind = DW_AT_KIND_STRING;
		RET_FALSE_IF_FAIL(read_offset(buffer, &attr->string.offset, is_64bit, big_endian));
		if (opt->cu && opt->dw->str && opt->dw->str_offsets) {
			attr->string.content = rz_bin_dwarf_str_offsets_get(
				opt->dw->str, opt->dw->str_offsets,
				opt->cu->str_offsets_base, attr->string.offset);
		}
		break;
	case DW_FORM_strx1:
		attr->kind = DW_AT_KIND_STRING;
		U8_OR_RET_FALSE(attr->string.offset);
		if (opt->cu && opt->dw->str && opt->dw->str_offsets) {
			attr->string.content = rz_bin_dwarf_str_offsets_get(
				opt->dw->str, opt->dw->str_offsets,
				opt->cu->str_offsets_base, attr->string.offset);
		}
		break;
	case DW_FORM_strx2:
		attr->kind = DW_AT_KIND_STRING;
		U_OR_RET_FALSE(16, attr->string.offset);
		if (opt->cu && opt->dw->str && opt->dw->str_offsets) {
			attr->string.content = rz_bin_dwarf_str_offsets_get(
				opt->dw->str, opt->dw->str_offsets,
				opt->cu->str_offsets_base, attr->string.offset);
		}
		break;
	case DW_FORM_strx3:
		attr->kind = DW_AT_KIND_STRING;
		// TODO: DW_FORM_strx3
		rz_buf_seek(buffer, 3, RZ_BUF_CUR);
		RZ_LOG_ERROR("TODO: DW_FORM_strx3\n");
		break;
	case DW_FORM_strx4:
		attr->kind = DW_AT_KIND_STRING;
		U_OR_RET_FALSE(32, attr->string.offset);
		if (opt->cu && opt->dw->str && opt->dw->str_offsets) {
			attr->string.content = rz_bin_dwarf_str_offsets_get(
				opt->dw->str, opt->dw->str_offsets,
				opt->cu->str_offsets_base, attr->string.offset);
		}
		break;
	case DW_FORM_implicit_const:
		attr->kind = DW_AT_KIND_CONSTANT;
		attr->uconstant = opt->type == DW_ATTR_TYPE_DEF ? opt->def->special : 0;
		break;
	/**  addrx* forms : The index is relative to the value of the
		DW_AT_addr_base attribute of the associated compilation unit.
	    index into an array of addresses in the .debug_addr section.*/
	case DW_FORM_addrx:
		attr->kind = DW_AT_KIND_ADDRESS;
		ULE128_OR_RET_FALSE(attr->address);
		break;
	case DW_FORM_addrx1:
		attr->kind = DW_AT_KIND_ADDRESS;
		U8_OR_RET_FALSE(attr->address);
		break;
	case DW_FORM_addrx2:
		attr->kind = DW_AT_KIND_ADDRESS;
		U_OR_RET_FALSE(16, attr->address);
		break;
	case DW_FORM_addrx3:
		// TODO: .DW_FORM_addrx3
		attr->kind = DW_AT_KIND_ADDRESS;
		rz_buf_seek(buffer, 3, RZ_BUF_CUR);
		RZ_LOG_ERROR("TODO: DW_FORM_addrx3\n");
		break;
	case DW_FORM_addrx4:
		attr->kind = DW_AT_KIND_ADDRESS;
		U_OR_RET_FALSE(32, attr->address);
		break;
	case DW_FORM_line_ptr: // offset in a section .debug_line_str
	case DW_FORM_strp_sup: // offset in a section .debug_line_str
		attr->kind = DW_AT_KIND_STRING;
		RET_FALSE_IF_FAIL(read_offset(buffer, &attr->string.offset, is_64bit, big_endian));
		// TODO: .debug_line_str
		RZ_LOG_ERROR("TODO: .debug_line_str\n");
		break;
		// offset in the supplementary object file
	case DW_FORM_ref_sup4:
		attr->kind = DW_AT_KIND_REFERENCE;
		U_OR_RET_FALSE(32, attr->reference);
		break;
	case DW_FORM_ref_sup8:
		attr->kind = DW_AT_KIND_REFERENCE;
		U_OR_RET_FALSE(64, attr->reference);
		break;
		// An index into the .debug_loc
	case DW_FORM_loclistx:
		attr->kind = DW_AT_KIND_LOCLISTPTR;
		RET_FALSE_IF_FAIL(read_offset(buffer, &attr->reference, is_64bit, big_endian));
		break;
		// An index into the .debug_rnglists
	case DW_FORM_rnglistx:
		attr->kind = DW_AT_KIND_ADDRESS;
		ULE128_OR_RET_FALSE(attr->address);
		break;
	default:
		RZ_LOG_ERROR("Unknown DW_FORM 0x%02" PFMT32x "\n", attr->form);
		attr->uconstant = 0;
		return false;
	}
	return true;
}

RZ_IPI void RzBinDwarfAttr_fini(RzBinDwarfAttr *val) {
	if (!val) {
		return;
	}
	switch (val->kind) {
	case DW_AT_KIND_BLOCK:
		RzBinDwarfBlock_fini(&val->block);
		break;
	default:
		break;
	};
}

RZ_IPI char *RzBinDwarfAttr_to_string(RzBinDwarfAttr *attr) {
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
