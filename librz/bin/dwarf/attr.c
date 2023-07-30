// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

/**
 * This function is quite incomplete and requires lot of work
 * With parsing various new FORM values
 * \brief Parses attribute value based on its definition
 *        and stores it into `value`
 */
RZ_IPI bool RzBinDwarfAttr_parse(RzBuffer *buffer, RzBinDwarfAttr *value, DwAttrOption *in) {
	rz_return_val_if_fail(in && value && buffer, false);
	ut8 address_size = 0;
	bool is_64bit = false;
	ut64 unit_offset = 0;
	if (in->type == DW_ATTR_TYPE_DEF) {
		value->name = in->def->name;
		value->form = in->def->form;
		address_size = in->comp_unit_hdr->encoding.address_size;
		is_64bit = in->comp_unit_hdr->encoding.is_64bit;
		unit_offset = in->comp_unit_hdr->unit_offset;
	} else if (in->type == DW_ATTR_TYPE_FILE_ENTRY_FORMAT) {
		value->form = in->format->form;
		address_size = in->line_hdr->address_size;
		is_64bit = in->line_hdr->is_64bit;
		unit_offset = in->line_hdr->offset;
	} else {
		rz_warn_if_reached();
		return false;
	}

	bool big_endian = in->encoding.big_endian;
	RzBuffer *str_buffer = in->str_buffer;

	// http://www.dwarfstd.org/doc/DWARF4.pdf#page=161&zoom=100,0,560
	switch (value->form) {
	case DW_FORM_addr:
		value->kind = DW_AT_KIND_ADDRESS;
		UX_OR_RET_FALSE(address_size, value->address);
		break;
	case DW_FORM_data1:
		value->kind = DW_AT_KIND_UCONSTANT;
		U8_OR_RET_FALSE(value->uconstant);
		break;
	case DW_FORM_data2:
		value->kind = DW_AT_KIND_UCONSTANT;
		U_OR_RET_FALSE(16, value->uconstant);
		break;
	case DW_FORM_data4:
		value->kind = DW_AT_KIND_UCONSTANT;
		U_OR_RET_FALSE(32, value->uconstant);
		break;
	case DW_FORM_data8:
		value->kind = DW_AT_KIND_UCONSTANT;
		U_OR_RET_FALSE(64, value->uconstant);
		break;
	case DW_FORM_data16:
		value->kind = DW_AT_KIND_UCONSTANT;
		if (big_endian) {
			U_OR_RET_FALSE(64, value->uconstant128.High);
			U_OR_RET_FALSE(64, value->uconstant128.Low);
		} else {
			U_OR_RET_FALSE(64, value->uconstant128.Low);
			U_OR_RET_FALSE(64, value->uconstant128.High);
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
		const char *tag_str = in->type == DW_ATTR_TYPE_DEF \
			? rz_bin_dwarf_attr(value->name) \
			: (in->type == DW_ATTR_TYPE_FILE_ENTRY_FORMAT \
					  ? rz_bin_dwarf_lnct(in->format->content_type) \
					  : "unknown"); \
		RZ_LOG_ERROR("Failed to read string %s [%s]\n", tag_str, rz_bin_dwarf_form(value->form)); \
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
		U_OR_RET_FALSE(16, value->block.length);
		RET_FALSE_IF_FAIL(buf_read_block(buffer, &value->block));
		break;
	case DW_FORM_block4:
		value->kind = DW_AT_KIND_BLOCK;
		U_OR_RET_FALSE(32, value->block.length);
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
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8: {
		static const int index_sizes[] = { 1, 2, 4, 8 };
		UX_OR_RET_FALSE(index_sizes[value->form - DW_FORM_ref1], value->reference);
		value->kind = DW_AT_KIND_REFERENCE;
		value->reference += unit_offset;
		break;
	}
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
		U_OR_RET_FALSE(64, value->reference);
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
		U_OR_RET_FALSE(16, value->string.offset);
		break;
	case DW_FORM_strx3:
		value->kind = DW_AT_KIND_STRING;
		// TODO: DW_FORM_strx3
		rz_buf_seek(buffer, 3, RZ_BUF_CUR);
		RZ_LOG_ERROR("TODO: DW_FORM_strx3\n");
		break;
	case DW_FORM_strx4:
		value->kind = DW_AT_KIND_STRING;
		U_OR_RET_FALSE(32, value->string.offset);
		break;
	case DW_FORM_implicit_const:
		value->kind = DW_AT_KIND_CONSTANT;
		value->uconstant = in->type == DW_ATTR_TYPE_DEF ? in->def->special : 0;
		break;
	/**  addrx* forms : The index is relative to the value of the
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
		U_OR_RET_FALSE(16, value->address);
		break;
	case DW_FORM_addrx3:
		// TODO: .DW_FORM_addrx3
		value->kind = DW_AT_KIND_ADDRESS;
		rz_buf_seek(buffer, 3, RZ_BUF_CUR);
		RZ_LOG_ERROR("TODO: DW_FORM_addrx3\n");
		break;
	case DW_FORM_addrx4:
		value->kind = DW_AT_KIND_ADDRESS;
		U_OR_RET_FALSE(32, value->address);
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
		U_OR_RET_FALSE(32, value->reference);
		break;
	case DW_FORM_ref_sup8:
		value->kind = DW_AT_KIND_REFERENCE;
		U_OR_RET_FALSE(64, value->reference);
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
		RZ_LOG_ERROR("Unknown DW_FORM 0x%02" PFMT32x "\n", value->form);
		value->uconstant = 0;
		return false;
	}
	return true;
}

RZ_IPI void RzBinDwarfAttr_fini(RzBinDwarfAttr *val) {
	if (!val) {
		return;
	}
	switch (val->kind) {
	case DW_AT_KIND_STRING:
		RZ_FREE(val->string.content);
		break;
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
