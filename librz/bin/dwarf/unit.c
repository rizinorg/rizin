// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

typedef struct {
	RzBinDwarfInfo *info;
	RzBinDWARF *dw;
} DebugInfoContext;

static void Die_fini(RzBinDwarfDie *die) {
	if (!die) {
		return;
	}
	rz_vector_fini(&die->attrs);
}

static void CU_attr_apply(DebugInfoContext *ctx, RzBinDwarfCompUnit *cu, RzBinDwarfAttr *attr) {
	rz_return_if_fail(attr);
	switch (attr->at) {
	case DW_AT_name:
		cu->name = rz_bin_dwarf_attr_string(attr, ctx->dw, cu->str_offsets_base);
		break;
	case DW_AT_comp_dir:
		cu->comp_dir = rz_bin_dwarf_attr_string(attr, ctx->dw, cu->str_offsets_base);
		goto offset_comp_dir;
	case DW_AT_producer:
		cu->producer = rz_bin_dwarf_attr_string(attr, ctx->dw, cu->str_offsets_base);
		break;
	case DW_AT_GNU_dwo_name:
	case DW_AT_dwo_name:
		cu->dwo_name = rz_bin_dwarf_attr_string(attr, ctx->dw, cu->str_offsets_base);
		break;
	case DW_AT_language:
		cu->language = rz_bin_dwarf_attr_udata(attr);
		break;
	case DW_AT_low_pc:
		cu->low_pc = rz_bin_dwarf_attr_addr(attr, ctx->dw, cu->hdr.encoding.address_size, cu->addr_base);
		break;
	case DW_AT_high_pc:
		cu->high_pc = rz_bin_dwarf_attr_addr(attr, ctx->dw, cu->hdr.encoding.address_size, cu->addr_base);
		break;
	case DW_AT_stmt_list:
		cu->stmt_list = rz_bin_dwarf_attr_udata(attr);
		goto offset_comp_dir;
	case DW_AT_str_offsets_base:
		cu->str_offsets_base = rz_bin_dwarf_attr_udata(attr);
		break;
	case DW_AT_GNU_addr_base:
	case DW_AT_addr_base:
		cu->addr_base = rz_bin_dwarf_attr_udata(attr);
		break;
	case DW_AT_loclists_base:
		cu->loclists_base = rz_bin_dwarf_attr_udata(attr);
		break;
	case DW_AT_rnglists_base:
		cu->rnglists_base = rz_bin_dwarf_attr_udata(attr);
		break;
	default:
		break;
	}

	return;
offset_comp_dir:
	if (cu->stmt_list < UT64_MAX && cu->comp_dir) {
		ht_up_insert(ctx->info->offset_comp_dir, cu->stmt_list, (void *)cu->comp_dir);
	}
}

static void apply_attr_opt(DebugInfoContext *ctx, RzBinDwarfCompUnit *cu, RzBinDwarfDie *die, DW_AT at) {
	RzBinDwarfAttr *attr = rz_bin_dwarf_die_get_attr(die, at);
	if (attr) {
		CU_attr_apply(ctx, cu, attr);
	}
}

static bool CU_attrs_parse(
	DebugInfoContext *ctx,
	RzBinDwarfDie *die,
	RzBinDwarfCompUnit *cu,
	RzBinDwarfAbbrevDecl *abbrev_decl) {

	RZ_LOG_SILLY("0x%" PFMT64x ":\t%s%s [%" PFMT64d "] %s\n",
		die->offset, rz_str_indent(die->depth), rz_bin_dwarf_tag(die->tag),
		die->abbrev_code, rz_bin_dwarf_children(die->has_children));
	RzBinDwarfAttrSpec *spec = NULL;
	rz_vector_foreach(&abbrev_decl->defs, spec) {
		RzBinDwarfAttr attr = { 0 };
		AttrOption opt = {
			.dw = ctx->dw,
			.implicit_const = spec->special,
			.form = spec->form,
			.at = spec->at,
			.unit_offset = cu->offset,
			.encoding = &cu->hdr.encoding,
		};
		if (!RzBinDwarfAttr_parse(ctx->info->R, &attr, &opt)) {
			RZ_LOG_ERROR("DWARF: failed attr: 0x%" PFMT64x " %s [%s]\n ",
				die->offset, rz_bin_dwarf_attr(spec->at), rz_bin_dwarf_form(spec->form));
			continue;
		}

		switch (attr.at) {
		case DW_AT_sibling:
			die->sibling = rz_bin_dwarf_attr_udata(&attr);
			break;
		case DW_AT_location: {
			if (attr.value.kind == RzBinDwarfAttr_LoclistPtr ||
				attr.value.kind == RzBinDwarfAttr_Reference ||
				attr.value.kind == RzBinDwarfAttr_UConstant ||
				attr.value.kind == RzBinDwarfAttr_SecOffset) {
				ut64 offset = rz_bin_dwarf_attr_udata(&attr);
				ht_up_insert(ctx->info->location_encoding,
					offset, &cu->hdr.encoding);
			}
		}
		default:
			break;
		}

		rz_vector_push(&die->attrs, &attr);
	}

	if (die->tag == DW_TAG_compile_unit ||
		die->tag == DW_TAG_skeleton_unit) {
		apply_attr_opt(ctx, cu, die, DW_AT_str_offsets_base);
		apply_attr_opt(ctx, cu, die, DW_AT_addr_base);
		apply_attr_opt(ctx, cu, die, DW_AT_GNU_addr_base);
		apply_attr_opt(ctx, cu, die, DW_AT_GNU_ranges_base);
		apply_attr_opt(ctx, cu, die, DW_AT_loclists_base);
		apply_attr_opt(ctx, cu, die, DW_AT_rnglists_base);
		RzBinDwarfAttr *attr;
		rz_vector_foreach(&die->attrs, attr) {
			CU_attr_apply(ctx, cu, attr);
		}
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
	rz_vector_init(&unit->dies, sizeof(RzBinDwarfDie), (RzVectorFree)Die_fini, NULL);
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
	RzBinEndianReader *R = ctx->info->R;
	while (true) {
		ut64 offset = R_tell(R);
		if (offset >= CU_next(unit)) {
			break;
		}
		// DIE starts with ULEB128 with the abbreviation code
		// we wanna store this entry too, usually the last one is null_entry
		// return the buffer to parse next compilation units
		ut64 abbrev_code = 0;
		if (!R_read_ule128(R, &abbrev_code)) {
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
			rz_vector_init(&die.attrs, sizeof(RzBinDwarfAttr), NULL, NULL);
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
static bool CU_Hdr_parse(DebugInfoContext *ctx, RzBinDwarfCompUnitHdr *hdr) {
	RzBinEndianReader *R = ctx->info->R;
	RET_FALSE_IF_FAIL(R_read_initial_length(R, &hdr->encoding.is_64bit, &hdr->length));
	RET_FALSE_IF_FAIL(hdr->length <= R_remain(R));
	ut64 offset_start = R_tell(R);
	U_OR_RET_FALSE(16, hdr->encoding.version);

	if (hdr->encoding.version == 5) {
		U8_OR_RET_FALSE(hdr->ut);
		U8_OR_RET_FALSE(hdr->encoding.address_size);
		RET_FALSE_IF_FAIL(R_read_offset(R, &hdr->abbrev_offset, hdr->encoding.is_64bit));

		if (hdr->ut == DW_UT_skeleton || hdr->ut == DW_UT_split_compile) {
			U_OR_RET_FALSE(64, hdr->dwo_id);
		} else if (hdr->ut == DW_UT_type || hdr->ut == DW_UT_split_type) {
			U_OR_RET_FALSE(64, hdr->type_sig);
			RET_FALSE_IF_FAIL(R_read_offset(R, &hdr->type_offset, hdr->encoding.is_64bit));
		}
	} else {
		RET_FALSE_IF_FAIL(R_read_offset(R, &hdr->abbrev_offset, hdr->encoding.is_64bit));
		U8_OR_RET_FALSE(hdr->encoding.address_size);
	}
	hdr->header_size = R_tell(R) - offset_start; // header size excluding length field
	return true;
}

/**
 * \brief Parses whole .debug_info section
 */
static bool CU_parse_all(DebugInfoContext *ctx) {
	RzBinEndianReader *buffer = ctx->info->R;
	while (true) {
		ut64 offset = R_tell(buffer);
		if (offset >= R_size(buffer)) {
			break;
		}

		RzBinDwarfCompUnit unit = {
			.offset = offset,
		};
		if (CU_init(&unit) < 0) {
			goto cleanup;
		}
		if (!CU_Hdr_parse(ctx, &unit.hdr)) {
			break;
		}
		if (unit.hdr.length > R_size(buffer)) {
			goto cleanup;
		}

		RzBinDwarfAbbrevTable *tbl = ht_up_find(
			ctx->dw->abbrev->by_offset, unit.hdr.abbrev_offset, NULL);
		if (!tbl) {
			goto cleanup;
		}

		RZ_LOG_DEBUG("0x%" PFMT64x ":\tcompile unit length = 0x%" PFMT64x ", abbr_offset: 0x%" PFMT64x "\n",
			unit.offset, unit.hdr.length, unit.hdr.abbrev_offset);
		CU_dies_parse(ctx, &unit, tbl);
		ctx->info->die_count += rz_vector_len(&unit.dies);
		rz_vector_push(&ctx->info->units, &unit);
	}
	return true;
cleanup:
	return false;
}

RZ_API RZ_BORROW RzBinDwarfAttr *rz_bin_dwarf_die_get_attr(
	RZ_BORROW RZ_NONNULL const RzBinDwarfDie *die, DW_AT name) {
	rz_return_val_if_fail(die, NULL);
	RzBinDwarfAttr *attr = NULL;
	rz_vector_foreach(&die->attrs, attr) {
		if (attr->at == name) {
			return attr;
		}
	}
	return NULL;
}

static bool info_init(RzBinDwarfInfo *info) {
	rz_vector_init(&info->units, sizeof(RzBinDwarfCompUnit), (RzVectorFree)CU_fini, NULL);
	info->offset_comp_dir = ht_up_new(NULL, NULL);
	info->location_encoding = ht_up_new(NULL, NULL);
	if (!info->offset_comp_dir) {
		goto beach;
	}
	return true;
beach:
	rz_vector_fini(&info->units);
	return false;
}

static inline void info_free(RzBinDwarfInfo *info) {
	if (!info) {
		return;
	}
	R_free(info->R);
	rz_vector_fini(&info->units);
	ht_up_free(info->offset_comp_dir);
	ht_up_free(info->die_by_offset);
	ht_up_free(info->unit_by_offset);
	ht_up_free(info->location_encoding);
	free(info);
}

RZ_API void rz_bin_dwarf_info_free(RZ_OWN RZ_NULLABLE RzBinDwarfInfo *info) {
	info_free(info);
}

RZ_API RZ_OWN RzBinDwarfInfo *rz_bin_dwarf_info_from_buf(
	RZ_OWN RZ_NONNULL RzBinEndianReader *R,
	RZ_BORROW RZ_NONNULL RzBinDWARF *dw) {
	rz_return_val_if_fail(R && dw && dw->abbrev, NULL);
	if (R_size(R) <= 0) {
		R_free(R);
		return NULL;
	}
	RzBinDwarfInfo *info = RZ_NEW0(RzBinDwarfInfo);
	RET_NULL_IF_FAIL(info);
	ERR_IF_FAIL(info_init(info));
	info->R = R;

	DebugInfoContext ctx = {
		.info = info,
		.dw = dw,
	};
	ERR_IF_FAIL(CU_parse_all(&ctx));

	info->die_by_offset = ht_up_new_size(info->die_count, NULL, NULL);
	ERR_IF_FAIL(info->die_by_offset);
	info->unit_by_offset = ht_up_new_size(rz_vector_len(&info->units), NULL, NULL);
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
	info_free(info);
	return NULL;
}

/**
 * \brief Parses .debug_info section
 * \param bin RzBinFile instance
 * \param dw RzBinDWARF instance
 * \return RzBinDwarfDebugInfo* Parsed information, NULL if error
 */
RZ_API RZ_OWN RzBinDwarfInfo *rz_bin_dwarf_info_from_file(
	RZ_BORROW RZ_NONNULL RzBinFile *bf,
	RZ_BORROW RZ_NONNULL RzBinDWARF *dw,
	bool is_dwo) {
	rz_return_val_if_fail(bf && dw && dw->abbrev, NULL);
	RzBinEndianReader *R = RzBinEndianReader_from_file(
		bf, ".debug_info", is_dwo);
	RET_NULL_IF_FAIL(R);
	return rz_bin_dwarf_info_from_buf(R, dw);
}

RZ_API void rz_bin_dwarf_debug_info_dump(
	RZ_NONNULL RZ_BORROW const RzBinDwarfInfo *info,
	RZ_NONNULL RZ_BORROW const RzBinDWARF *dw,
	RZ_NONNULL RZ_BORROW RzStrBuf *sb) {
	rz_return_if_fail(info && sb);
	if (!rz_vector_empty(&info->units)) {
		rz_strbuf_append(sb, "\n.debug_info content:\n");
	}
	RzBinDwarfCompUnit *unit = NULL;
	rz_vector_foreach(&info->units, unit) {
		const char *ut = rz_bin_dwarf_unit_type(unit->hdr.ut ? unit->hdr.ut : DW_UT_compile);
		rz_strbuf_appendf(sb, "0x%08" PFMT64x ":\t%s\n", unit->offset, ut);
		rz_strbuf_appendf(sb, "\tLength\t0x%" PFMT64x "\n", unit->hdr.length);
		rz_strbuf_appendf(sb, "\tVersion\t%d\n", unit->hdr.encoding.version);
		rz_strbuf_appendf(sb, "\tAbbrev Offset\t0x%" PFMT64x "\n", unit->hdr.abbrev_offset);
		rz_strbuf_appendf(sb, "\tPointer Size\t%d\n", unit->hdr.encoding.address_size);
		rz_strbuf_append(sb, "\n");

		RzBinDwarfDie *die = NULL;
		rz_vector_foreach(&unit->dies, die) {
			rz_strbuf_appendf(sb, "%#08" PFMT64x ": %s [%" PFMT64u "]\n",
				die->offset, rz_bin_dwarf_tag(die->tag), die->abbrev_code);
			if (die->abbrev_code) {
				RzBinDwarfAttr *attr = NULL;
				rz_vector_foreach(&die->attrs, attr) {
					if (!attr->at) {
						continue;
					}
					rz_bin_dwarf_attr_dump(attr, (RzBinDWARF *)dw, unit->str_offsets_base, sb);
					rz_strbuf_append(sb, "\n");
				}
			}
			rz_strbuf_append(sb, "\n");
		}
	}
}
