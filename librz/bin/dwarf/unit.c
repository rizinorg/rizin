// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

typedef struct {
	bool big_endian;
	RzBinDwarfDebugInfo *debug_info;
	RzBinDWARF *dw;
} DebugInfoContext;

static void CUDie_fini(RzBinDwarfDie *die) {
	if (!die) {
		return;
	}
	rz_vector_fini(&die->attrs);
}

static inline ut64 attr_get_uconstant_or_reference(const RzBinDwarfAttr *attr) {
	rz_warn_if_fail(attr->kind == DW_AT_KIND_UCONSTANT || attr->kind == DW_AT_KIND_REFERENCE);
	return attr->kind == DW_AT_KIND_UCONSTANT ? attr->uconstant : attr->reference;
}

static bool CU_attrs_parse(
	DebugInfoContext *ctx,
	RzBinDwarfDie *die,
	RzBinDwarfCompUnit *cu,
	RzBinDwarfAbbrevDecl *abbrev_decl) {
	RzBuffer *buffer = ctx->debug_info->buffer;

	RZ_LOG_SILLY("0x%" PFMT64x ":\t%s%s [%" PFMT64d "] %s\n",
		die->offset, rz_str_indent(die->depth), rz_bin_dwarf_tag(die->tag),
		die->abbrev_code, rz_bin_dwarf_children(die->has_children));
	RzBinDwarfAttrDef *def = NULL;
	rz_vector_foreach(&abbrev_decl->defs, def) {
		RzBinDwarfAttr attr = { 0 };
		AttrOption opt = {
			.type = DW_ATTR_TYPE_DEF,
			.def = def,
			.encoding = {
				.address_size = cu->hdr.encoding.address_size,
			},
			.dw = ctx->dw,
			.big_endian = ctx->big_endian,
			.cu = cu,
		};
		if (!RzBinDwarfAttr_parse(buffer, &attr, &opt)) {
			RZ_LOG_ERROR("0x%" PFMT64x ":\tfailed die attr: 0x%" PFMT64x " %s [%s]\n ",
				rz_buf_tell(buffer), die->offset, rz_bin_dwarf_attr(def->name), rz_bin_dwarf_form(def->form));
			continue;
		}

#if RZ_BUILD_DEBUG
		char *data = RzBinDwarfAttr_to_string(&attr);
		RZ_LOG_SILLY("0x%" PFMT64x ":\t%s\t%s [%s] (%s)\n",
			rz_buf_tell(buffer), rz_str_indent(die->depth), rz_bin_dwarf_attr(def->name),
			rz_bin_dwarf_form(def->form), rz_str_get(data));
		free(data);
#endif

		switch (attr.name) {
		case DW_AT_sibling:
			die->sibling = attr_get_uconstant_or_reference(&attr);
			break;
		default:
			break;
		}

		rz_vector_push(&die->attrs, &attr);
	}
	return true;
}

/**
 * \brief Initializes a RzBinDwarfCompUnit
 * \param unit The RzBinDwarfCompUnit to initialize
 * \return 0 on success, -EINVAL on error
 */
static int CU_init(RzBinDwarfCompUnit *unit) {
	if (!unit) {
		return -EINVAL;
	}
	rz_vector_init(&unit->dies, sizeof(RzBinDwarfDie), (RzVectorFree)CUDie_fini, NULL);
	return 0;
}

static void CU_fini(RzBinDwarfCompUnit *unit, void *user) {
	if (!unit) {
		return;
	}
	rz_vector_fini(&unit->dies);
}

static inline ut64 CU_next(RzBinDwarfCompUnit *unit) {
	return unit->offset + unit->hdr.length + (unit->hdr.encoding.is_64bit ? 12 : 4);
}

/**
 * \brief Reads throught comp_unit buffer and parses all its DIEntries*
 */
static bool CU_dies_parse(
	DebugInfoContext *ctx,
	RzBinDwarfCompUnit *unit,
	const RzBinDwarfAbbrevTable *tbl) {
	st64 depth = 0;
	RzBuffer *buffer = ctx->debug_info->buffer;
	while (true) {
		ut64 offset = rz_buf_tell(buffer);
		if (offset >= CU_next(unit)) {
			break;
		}
		// DIE starts with ULEB128 with the abbreviation code
		// we wanna store this entry too, usually the last one is null_entry
		// return the buffer to parse next compilation units
		ut64 abbrev_code = 0;
		if (rz_buf_uleb128(buffer, &abbrev_code) < 0) {
			break;
		}

		RzBinDwarfDie die = {
			.offset = offset,
			.unit_offset = unit->offset,
			.index = rz_vector_len(&unit->dies),
			.depth = depth,
			.abbrev_code = abbrev_code,
		};
		// there can be "null" entries that have abbr_code == 0
		if (!abbrev_code) {
			RZ_LOG_SILLY("0x%" PFMT64x ":\t%sNULL\n", offset, rz_str_indent(die.depth));
			rz_vector_push(&unit->dies, &die);
			depth--;
			if (depth <= 0) {
				break;
			} else {
				continue;
			}
		}

		RzBinDwarfAbbrevDecl *abbrev_decl = rz_bin_dwarf_abbrev_get(tbl, die.abbrev_code);
		if (!abbrev_decl) {
			break;
		}

		ut64 attr_count = rz_bin_dwarf_abbrev_decl_count(abbrev_decl);
		if (attr_count) {
			rz_vector_init(&die.attrs, sizeof(RzBinDwarfAttr), (RzVectorFree)RzBinDwarfAttr_fini, NULL);
			rz_vector_reserve(&die.attrs, attr_count);
		}
		if (abbrev_decl->code != 0) {
			die.tag = abbrev_decl->tag;
			die.has_children = abbrev_decl->has_children;
			if (die.has_children) {
				depth++;
			}
			GOTO_IF_FAIL(CU_attrs_parse(ctx, &die, unit, abbrev_decl), err);
		}
		rz_vector_push(&unit->dies, &die);
	}
	return true;
err:
	return false;
}

/**
 * \brief Reads all information about compilation unit header
 */
static bool CUHdr_parse(DebugInfoContext *ctx, RzBinDwarfCompUnitHdr *hdr) {
	bool big_endian = ctx->big_endian;
	RzBuffer *buffer = ctx->debug_info->buffer;
	RET_FALSE_IF_FAIL(read_initial_length(buffer, &hdr->encoding.is_64bit, &hdr->length, big_endian));
	RET_FALSE_IF_FAIL(hdr->length <= rz_buf_size(buffer) - rz_buf_tell(buffer));
	ut64 offset_start = rz_buf_tell(buffer);
	U_OR_RET_FALSE(16, hdr->encoding.version);

	if (hdr->encoding.version == 5) {
		U8_OR_RET_FALSE(hdr->ut);
		U8_OR_RET_FALSE(hdr->encoding.address_size);
		RET_FALSE_IF_FAIL(read_offset(buffer, &hdr->abbrev_offset, hdr->encoding.is_64bit, big_endian));

		if (hdr->ut == DW_UT_skeleton || hdr->ut == DW_UT_split_compile) {
			U_OR_RET_FALSE(64, hdr->dwo_id);
		} else if (hdr->ut == DW_UT_type || hdr->ut == DW_UT_split_type) {
			U_OR_RET_FALSE(64, hdr->type_sig);
			RET_FALSE_IF_FAIL(read_offset(buffer, &hdr->type_offset, hdr->encoding.is_64bit, big_endian));
		}
	} else {
		RET_FALSE_IF_FAIL(read_offset(buffer, &hdr->abbrev_offset, hdr->encoding.is_64bit, big_endian));
		U8_OR_RET_FALSE(hdr->encoding.address_size);
	}
	hdr->header_size = rz_buf_tell(buffer) - offset_start; // header size excluding length field
	return true;
}

static void CU_apply(DebugInfoContext *ctx, RzBinDwarfCompUnit *unit, RzBinDwarfDie *die) {
	RzBinDwarfAttr *attr = NULL;
	rz_vector_foreach(&die->attrs, attr) {
		switch (attr->name) {
		case DW_AT_name:
			unit->name = rz_bin_dwarf_attr_get_string_const(attr);
			break;
		case DW_AT_comp_dir:
			unit->comp_dir = rz_bin_dwarf_attr_get_string_const(attr);
			break;
		case DW_AT_producer:
			unit->producer = rz_bin_dwarf_attr_get_string_const(attr);
			break;
		case DW_AT_GNU_dwo_name:
		case DW_AT_dwo_name:
			unit->dwo_name = rz_bin_dwarf_attr_get_string_const(attr);
			break;
		case DW_AT_language:
			unit->language = attr->uconstant;
			break;
		case DW_AT_low_pc:
			unit->low_pc = attr->address;
			break;
		case DW_AT_high_pc:
			unit->high_pc = attr->address;
			break;
		case DW_AT_stmt_list:
			unit->stmt_list = attr_get_uconstant_or_reference(attr);
			break;
		case DW_AT_str_offsets_base:
			unit->str_offsets_base = attr->uconstant;
			break;
		case DW_AT_GNU_addr_base:
		case DW_AT_addr_base:
			unit->addr_base = attr->uconstant;
			break;
		case DW_AT_loclists_base:
			unit->loclists_base = attr->uconstant;
			break;
		case DW_AT_rnglists_base:
			unit->rnglists_base = attr->uconstant;
			break;
		default:
			break;
		}
	}
	ut64 stmt = unit->stmt_list;
	if (stmt < UT64_MAX && unit->comp_dir) {
		ht_up_insert(ctx->debug_info->line_info_offset_comp_dir,
			stmt, (void *)unit->comp_dir);
	}
}

/**
 * \brief Parses whole .debug_info section
 */
static bool CU_parse_all(DebugInfoContext *ctx) {
	RzBuffer *buffer = ctx->debug_info->buffer;
	while (true) {
		ut64 offset = rz_buf_tell(buffer);
		if (offset >= rz_buf_size(buffer)) {
			break;
		}

		RzBinDwarfCompUnit unit = {
			.offset = offset,
			.hdr = {
				.unit_offset = offset,
			}
		};
		if (CU_init(&unit) < 0) {
			goto cleanup;
		}
		if (!CUHdr_parse(ctx, &unit.hdr)) {
			break;
		}
		if (unit.hdr.length > rz_buf_size(buffer)) {
			goto cleanup;
		}

		RzBinDwarfAbbrevTable *tbl = ht_up_find(
			ctx->dw->abbrev->tbl_by_offset, unit.hdr.abbrev_offset, NULL);
		if (!tbl) {
			goto cleanup;
		}

		RZ_LOG_DEBUG("0x%" PFMT64x ":\tcompile unit length = 0x%" PFMT64x ", abbr_offset: 0x%" PFMT64x "\n",
			unit.offset, unit.hdr.length, unit.hdr.abbrev_offset);
		CU_dies_parse(ctx, &unit, tbl);

		ut64 die_count = rz_vector_len(&unit.dies);
		if (die_count > 0) {
			ctx->debug_info->die_count += die_count;
			RzBinDwarfDie *die = rz_vector_head(&unit.dies);
			if (die) {
				CU_apply(ctx, &unit, die);
			}
		}

		rz_vector_push(&ctx->debug_info->units, &unit);
	}
	return true;
cleanup:
	return false;
}

RZ_API RZ_BORROW RzBinDwarfAttr *rz_bin_dwarf_die_get_attr(RZ_BORROW RZ_NONNULL const RzBinDwarfDie *die, DW_AT name) {
	rz_return_val_if_fail(die, NULL);
	RzBinDwarfAttr *attr = NULL;
	rz_vector_foreach(&die->attrs, attr) {
		if (attr->name == name) {
			return attr;
		}
	}
	return NULL;
}

static bool RzBinDwarfDebugInfo_init(RzBinDwarfDebugInfo *info) {
	rz_vector_init(&info->units, sizeof(RzBinDwarfCompUnit), (RzVectorFree)CU_fini, NULL);
	info->line_info_offset_comp_dir = ht_up_new(NULL, NULL, NULL);
	if (!info->line_info_offset_comp_dir) {
		goto beach;
	}
	return true;
beach:
	rz_vector_fini(&info->units);
	return false;
}

static inline void RzBinDwarfDebugInfo_free(RzBinDwarfDebugInfo *info) {
	if (!info) {
		return;
	}
	rz_vector_fini(&info->units);
	ht_up_free(info->line_info_offset_comp_dir);
	ht_up_free(info->die_by_offset);
	ht_up_free(info->unit_by_offset);
	rz_buf_free(info->buffer);
	free(info);
}

RZ_API void rz_bin_dwarf_info_free(RZ_OWN RZ_NULLABLE RzBinDwarfDebugInfo *info) {
	RzBinDwarfDebugInfo_free(info);
}

RZ_API RZ_OWN RzBinDwarfDebugInfo *rz_bin_dwarf_info_from_buf(
	RZ_OWN RZ_NONNULL RzBuffer *buffer,
	bool big_endian,
	RZ_BORROW RZ_NONNULL RzBinDWARF *dw) {
	rz_return_val_if_fail(buffer && dw && dw->abbrev, NULL);
	if (rz_buf_size(buffer) <= 0) {
		rz_buf_free(buffer);
		return NULL;
	}
	RzBinDwarfDebugInfo *info = RZ_NEW0(RzBinDwarfDebugInfo);
	RET_NULL_IF_FAIL(info);
	ERR_IF_FAIL(RzBinDwarfDebugInfo_init(info));
	info->buffer = buffer;

	DebugInfoContext ctx = {
		.big_endian = big_endian,
		.debug_info = info,
		.dw = dw,
	};
	ERR_IF_FAIL(CU_parse_all(&ctx));

	info->die_by_offset = ht_up_new_size(info->die_count, NULL, NULL, NULL);
	ERR_IF_FAIL(info->die_by_offset);
	info->unit_by_offset = ht_up_new(NULL, NULL, NULL);
	ERR_IF_FAIL(info->unit_by_offset);

	// build hashtable after whole parsing because of possible relocations
	RzBinDwarfCompUnit *unit = NULL;
	rz_vector_foreach(&info->units, unit) {
		ht_up_insert(info->unit_by_offset, unit->offset, unit);
		switch (unit->hdr.ut) {
		case DW_UT_skeleton: {
			RzBinDwarfDie *die = rz_vector_head(&unit->dies);
			if (!die) {
				RZ_LOG_ERROR("Invalid DW_UT_skeleton [0x%" PFMT64x "]\n", unit->offset);
				break;
			}

			break;
		}
		case DW_UT_compile:
		case DW_UT_type:
		case DW_UT_partial:
		case DW_UT_split_compile:
		case DW_UT_split_type:
		case DW_UT_lo_user:
		case DW_UT_hi_user:
		default: break;
		}

		RzBinDwarfDie *die = NULL;
		rz_vector_foreach(&unit->dies, die) {
			ht_up_insert(info->die_by_offset, die->offset, die); // optimization for further processing
		}
	}
	return info;
err:
	RzBinDwarfDebugInfo_free(info);
	return NULL;
}

/**
 * \brief Parses .debug_info section
 * \param bin RzBinFile instance
 * \param dw RzBinDWARF instance
 * \return RzBinDwarfDebugInfo* Parsed information, NULL if error
 */
RZ_API RZ_OWN RzBinDwarfDebugInfo *rz_bin_dwarf_info_from_file(
	RZ_BORROW RZ_NONNULL RzBinFile *bf,
	RZ_BORROW RZ_NONNULL RzBinDWARF *dw) {
	rz_return_val_if_fail(bf && dw && dw->abbrev, NULL);
	RzBuffer *buf = get_section_buf(bf, "debug_info");
	RET_NULL_IF_FAIL(buf);
	return rz_bin_dwarf_info_from_buf(buf, bf_bigendian(bf), dw);
}
