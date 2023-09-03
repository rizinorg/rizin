// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

typedef struct {
	bool big_endian;
	ut64 depth;
	RzList /*<RzBinDwarfDie*>*/ *parents;
	RzBinDwarfDebugAbbrevs *abbrevs;
	RzBinDwarfDebugInfo *info;
	RzBinDwarfDebugStr *str;
} DebugInfo_Context;

static void RzBinDwarfDie_free(RzBinDwarfDie *die) {
	if (!die) {
		return;
	}
	rz_vector_fini(&die->attrs);
	free(die);
}

static inline ut64 attr_get_uconstant_or_reference(const RzBinDwarfAttr *attr) {
	rz_warn_if_fail(attr->kind == DW_AT_KIND_UCONSTANT || attr->kind == DW_AT_KIND_REFERENCE);
	return attr->kind == DW_AT_KIND_UCONSTANT ? attr->uconstant : attr->reference;
}

static bool RzBinDwarfDie_attrs_parse(
	DebugInfo_Context *ctx,
	RzBinDwarfDie *die,
	RzBinDwarfCompUnit *cu,
	RzBinDwarfAbbrevDecl *abbrev_decl) {
	RzBuffer *buffer = ctx->info->buffer;

	RZ_LOG_SILLY("0x%" PFMT64x ":\t%s%s [%" PFMT64d "] %s\n",
		die->offset, rz_str_indent(ctx->depth), rz_bin_dwarf_tag(die->tag),
		die->abbrev_code, rz_bin_dwarf_children(die->has_children));
	RzBinDwarfAttrDef *def = NULL;
	rz_vector_foreach(&abbrev_decl->defs, def) {
		RzBinDwarfAttr attr = { 0 };
		DwAttrOption opt = {
			.type = DW_ATTR_TYPE_DEF,
			.def = def,
			.encoding = {
				.address_size = cu->hdr.encoding.address_size,
			},
			.cu = cu,
			.debug_str = ctx->str,
			.big_endian = ctx->big_endian,
		};
		if (!RzBinDwarfAttr_parse(buffer, &attr, &opt)) {
			RZ_LOG_ERROR("0x%" PFMT64x ":\tfailed die: 0x%" PFMT64x " %s [%s]\n ",
				rz_buf_tell(buffer), die->offset, rz_bin_dwarf_attr(def->name), rz_bin_dwarf_form(def->form));
			continue;
		}

#if RZ_BUILD_DEBUG
		char *data = RzBinDwarfAttr_to_string(&attr);
		RZ_LOG_SILLY("0x%" PFMT64x ":\t%s\t%s [%s] (%s)\n",
			rz_buf_tell(buffer), rz_str_indent(ctx->depth), rz_bin_dwarf_attr(def->name),
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
static int RzBinDwarfCompUnit_init(RzBinDwarfCompUnit *unit) {
	if (!unit) {
		return -EINVAL;
	}
	rz_pvector_init(&unit->dies, (RzPVectorFree)RzBinDwarfDie_free);
	return 0;
}

static void RzBinDwarfCompUnit_free(RzBinDwarfCompUnit *unit) {
	if (!unit) {
		return;
	}
	rz_pvector_fini(&unit->dies);
	free(unit);
}

static inline ut64 RzBinDwarfCompUnit_next(RzBinDwarfCompUnit *unit) {
	return unit->offset + unit->hdr.length + (unit->hdr.encoding.is_64bit ? 12 : 4);
}

static bool add_die(
	DebugInfo_Context *ctx,
	RzBinDwarfCompUnit *unit,
	RzBinDwarfDie *die) {

	ERR_IF_FAIL(rz_pvector_push(&unit->dies, die));

	ht_up_insert(ctx->info->die_by_offset, die->offset, die);

	if (!rz_list_empty(ctx->parents)) {
		RzBinDwarfDie *parent = (RzBinDwarfDie *)rz_list_last(ctx->parents);
		ERR_IF_FAIL(parent);
		ERR_IF_FAIL(rz_pvector_push(parent->children, die));
	}
	if (die->has_children) {
		ERR_IF_FAIL(rz_list_append(ctx->parents, die));
	}
	return true;
err:
	return false;
}

/**
 * \brief Reads throught comp_unit buffer and parses all its DIEntries*
 */
static bool RzBinDwarfCompUnit_dies_parse(
	DebugInfo_Context *ctx,
	RzBinDwarfCompUnit *unit,
	const RzBinDwarfAbbrevTable *tbl) {
	RzBuffer *buffer = ctx->info->buffer;
	DIE *die = NULL;
	ctx->depth = 0;
	while (true) {
		ut64 offset = rz_buf_tell(buffer);
		if (offset >= RzBinDwarfCompUnit_next(unit)) {
			break;
		}
		// DIE starts with ULEB128 with the abbreviation code
		// we wanna store this entry too, usually the last one is null_entry
		// return the buffer to parse next compilation units
		ut64 abbrev_code = 0;
		if (rz_buf_uleb128(buffer, &abbrev_code) < 0) {
			break;
		}

		die = RZ_NEW0(DIE);
		ERR_IF_FAIL(die);
		die->offset = offset;
		die->abbrev_code = abbrev_code;
		die->parent = rz_list_last(ctx->parents);

		// there can be "null" entries that have abbr_code == 0
		if (!abbrev_code) {
			RZ_LOG_SILLY("0x%" PFMT64x ":\t%sNULL\n", offset, rz_str_indent(ctx->depth));
			ERR_IF_FAIL(add_die(ctx, unit, die));
			ctx->depth--;
			rz_list_pop(ctx->parents);
			if (ctx->depth <= 0) {
				break;
			} else {
				continue;
			}
		}

		RzBinDwarfAbbrevDecl *decl = rz_bin_dwarf_abbrev_get(tbl, die->abbrev_code);
		if (!decl) {
			break;
		}

		ut64 attr_count = rz_bin_dwarf_abbrev_decl_count(decl);
		if (attr_count) {
			rz_vector_init(&die->attrs, sizeof(RzBinDwarfAttr), (RzVectorFree)RzBinDwarfAttr_fini, NULL);
			rz_vector_reserve(&die->attrs, attr_count);
		}
		if (decl->code != 0) {
			die->tag = decl->tag;
			die->has_children = decl->has_children;
			if (die->has_children) {
				ctx->depth++;
				die->children = rz_pvector_new(NULL);
			}
			GOTO_IF_FAIL(RzBinDwarfDie_attrs_parse(ctx, die, unit, decl), err);
		}
		ERR_IF_FAIL(add_die(ctx, unit, die));
	}
	return true;
err:
	RzBinDwarfDie_free(die);
	return false;
}

/**
 * \brief Reads all information about compilation unit header
 */
static bool RzBinDwarfCompUnitHdr_parse(DebugInfo_Context *ctx, RzBinDwarfCompUnitHdr *hdr) {
	bool big_endian = ctx->big_endian;
	RzBuffer *buffer = ctx->info->buffer;
	RET_FALSE_IF_FAIL(buf_read_initial_length(buffer, &hdr->encoding.is_64bit, &hdr->length, big_endian));
	RET_FALSE_IF_FAIL(hdr->length <= rz_buf_size(buffer) - rz_buf_tell(buffer));
	ut64 offset_start = rz_buf_tell(buffer);
	U_OR_RET_FALSE(16, hdr->encoding.version);

	if (hdr->encoding.version == 5) {
		U8_OR_RET_FALSE(hdr->unit_type);
		U8_OR_RET_FALSE(hdr->encoding.address_size);
		RET_FALSE_IF_FAIL(buf_read_offset(buffer, &hdr->abbrev_offset, hdr->encoding.is_64bit, big_endian));

		if (hdr->unit_type == DW_UT_skeleton || hdr->unit_type == DW_UT_split_compile) {
			U8_OR_RET_FALSE(hdr->dwo_id);
		} else if (hdr->unit_type == DW_UT_type || hdr->unit_type == DW_UT_split_type) {
			U_OR_RET_FALSE(64, hdr->type_sig);
			RET_FALSE_IF_FAIL(buf_read_offset(buffer, &hdr->type_offset, hdr->encoding.is_64bit, big_endian));
		}
	} else {
		RET_FALSE_IF_FAIL(buf_read_offset(buffer, &hdr->abbrev_offset, hdr->encoding.is_64bit, big_endian));
		U8_OR_RET_FALSE(hdr->encoding.address_size);
	}
	hdr->header_size = rz_buf_tell(buffer) - offset_start; // header size excluding length field
	return true;
}

static void RzBinDwarfCompUnit_apply_attrs(RzBinDwarfCompUnit *unit, RzBinDwarfDie *die) {
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
}

/**
 * \brief Parses whole .debug_info section
 */
static bool RzBinDwarfCompUnit_parse(DebugInfo_Context *ctx) {
	RzBuffer *buffer = ctx->info->buffer;
	CU *unit = NULL;
	while (true) {
		ut64 offset = rz_buf_tell(buffer);
		if (offset >= rz_buf_size(buffer)) {
			break;
		}

		unit = RZ_NEW0(CU);
		ERR_IF_FAIL(unit);
		unit->offset = offset;

		ERR_IF_FAIL(RzBinDwarfCompUnit_init(unit) < 0);
		if (!RzBinDwarfCompUnitHdr_parse(ctx, &unit->hdr)) {
			break;
		}
		ERR_IF_FAIL(unit->hdr.length > rz_buf_size(buffer));

		RzBinDwarfAbbrevTable *tbl = ht_up_find(
			ctx->abbrevs->tbl_by_offset, unit->hdr.abbrev_offset, NULL);
		ERR_IF_FAIL(tbl);

		RZ_LOG_DEBUG("0x%" PFMT64x ":\tcompile unit length = 0x%" PFMT64x ", "
			     "abbr_offset: 0x%" PFMT64x "\n",
			unit->offset, unit->hdr.length, unit->hdr.abbrev_offset);
		RzBinDwarfCompUnit_dies_parse(ctx, unit, tbl);

		ut64 unit_die_count = rz_pvector_len(&unit->dies);
		if (unit_die_count > 0) {
			ctx->info->die_count += unit_die_count;
			RzBinDwarfDie *die = rz_pvector_head(&unit->dies);
			if (die->tag == DW_TAG_compile_unit) {
				RzBinDwarfCompUnit_apply_attrs(unit, die);
				if (unit->stmt_list >= 0 && unit->stmt_list < UT64_MAX && unit->comp_dir) {
					ht_up_insert(ctx->info->line_info_offset_comp_dir,
						unit->stmt_list, (void *)unit->comp_dir);
				}
			}
		}

		ERR_IF_FAIL(rz_pvector_push(&ctx->info->units, unit));
		ht_up_insert(ctx->info->unit_by_offset, unit->offset, unit);
	}
	return true;
err:
	RzBinDwarfCompUnit_free(unit);
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
	rz_pvector_init(&info->units, (RzPVectorFree)RzBinDwarfCompUnit_free);
	info->line_info_offset_comp_dir = ht_up_new(NULL, NULL, NULL);
	ERR_IF_FAIL(info->line_info_offset_comp_dir);
	info->die_by_offset = ht_up_new_size(info->die_count, NULL, NULL, NULL);
	ERR_IF_FAIL(info->die_by_offset);
	info->unit_by_offset = ht_up_new(NULL, NULL, NULL);
	ERR_IF_FAIL(info->unit_by_offset);
	return true;
err:
	rz_pvector_fini(&info->units);
	return false;
}

static inline void RzBinDwarfDebugInfo_free(RzBinDwarfDebugInfo *info) {
	if (!info) {
		return;
	}
	rz_pvector_fini(&info->units);
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
	RZ_BORROW RZ_NONNULL RzBinDwarfDebugAbbrevs *debug_abbrevs,
	RZ_BORROW RZ_NULLABLE RzBinDwarfDebugStr *debug_str) {
	rz_return_val_if_fail(buffer && debug_abbrevs, NULL);
	RzBinDwarfDebugInfo *info = RZ_NEW0(RzBinDwarfDebugInfo);
	RET_NULL_IF_FAIL(info);
	ERR_IF_FAIL(RzBinDwarfDebugInfo_init(info));
	info->buffer = buffer;

	DebugInfo_Context ctx = {
		.big_endian = big_endian,
		.parents = rz_list_new(),
		.abbrevs = debug_abbrevs,
		.info = info,
		.str = debug_str,
	};
	ERR_IF_FAIL(ctx.parents && RzBinDwarfCompUnit_parse(&ctx));

	rz_list_first(ctx.parents);
	return info;
err:
	rz_list_first(ctx.parents);
	RzBinDwarfDebugInfo_free(info);
	return NULL;
}

/**
 * \brief Parses .debug_info section
 *
 * \param abbrevs Parsed abbreviations
 * \param bin RzBinFile instance
 * \return RzBinDwarfDebugInfo* Parsed information, NULL if error
 */
RZ_API RZ_OWN RzBinDwarfDebugInfo *rz_bin_dwarf_info_from_file(
	RZ_BORROW RZ_NONNULL RzBinFile *bf,
	RZ_BORROW RZ_NONNULL RzBinDwarfDebugAbbrevs *debug_abbrevs,
	RZ_BORROW RZ_NULLABLE RzBinDwarfDebugStr *debug_str) {
	rz_return_val_if_fail(bf && debug_abbrevs, NULL);
	RzBuffer *buf = get_section_buf(bf, "debug_info");
	RET_NULL_IF_FAIL(buf);
	return rz_bin_dwarf_info_from_buf(buf, bf_bigendian(bf), debug_abbrevs, debug_str);
}
