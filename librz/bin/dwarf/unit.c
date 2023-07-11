// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

static void die_fini(RzBinDwarfDie *die) {
	if (!die) {
		return;
	}
	rz_vector_fini(&die->attrs);
}

static int unit_init(RzBinDwarfCompUnit *unit) {
	if (!unit) {
		return -EINVAL;
	}
	rz_vector_init(&unit->dies, sizeof(RzBinDwarfDie), (RzVectorFree)die_fini, NULL);
	return 0;
}

static void unit_fini(RzBinDwarfCompUnit *unit, void *user) {
	if (!unit) {
		return;
	}
	rz_vector_fini(&unit->dies);
	free(unit->comp_dir);
	free(unit->producer);
	free(unit->name);
}

static void ht_kv_value_free(HtUPKv *kv) {
	free(kv->value);
}

static bool debug_info_init(RzBinDwarfDebugInfo *info) {
	rz_vector_init(&info->units, sizeof(RzBinDwarfCompUnit), (RzVectorFree)unit_fini, NULL);
	info->line_info_offset_comp_dir = ht_up_new(NULL, ht_kv_value_free, NULL);
	if (!info->line_info_offset_comp_dir) {
		goto beach;
	}
	return true;
beach:
	rz_vector_fini(&info->units);
	return false;
}

static bool die_attr_parse(RzBuffer *buffer, RzBinDwarfDie *die, RzBinDwarfDebugInfo *info, RzBinDwarfAbbrevDecl *abbrev,
	RzBinDwarfCompUnitHdr *hdr, RzBuffer *str_buffer, bool big_endian) {
	const char *comp_dir = NULL;
	ut64 line_info_offset = UT64_MAX;

	RZ_LOG_DEBUG("0x%" PFMT64x ":\t%s%s [%" PFMT64d "] %s\n", die->offset, indent_str(die->depth), rz_bin_dwarf_tag(die->tag), die->abbrev_code, rz_bin_dwarf_children(die->has_children));
	RzBinDwarfAttrDef *def = NULL;
	rz_vector_foreach(&abbrev->defs, def) {
		RzBinDwarfAttr attr = { 0 };
		DwAttrOption opt = {
			.type = DW_ATTR_TYPE_DEF,
			.def = def,
			.encoding = {
				.big_endian = big_endian,
				.address_size = hdr->encoding.address_size,
			},
			.comp_unit_hdr = hdr,
			.str_buffer = str_buffer,
		};
		if (!attr_parse(buffer, &attr, &opt)) {
			RZ_LOG_ERROR("0x%" PFMT64x ":\tfailed die: 0x%" PFMT64x " %s [%s]\n ", rz_buf_tell(buffer), die->offset, rz_bin_dwarf_attr(def->name), rz_bin_dwarf_form(def->form));
			continue;
		}

		char *data = attr_to_string(&attr);
		RZ_LOG_DEBUG("0x%" PFMT64x ":\t%s\t%s [%s] (%s)\n", rz_buf_tell(buffer), indent_str(die->depth), rz_bin_dwarf_attr(def->name), rz_bin_dwarf_form(def->form), rz_str_get(data));
		free(data);

		enum DW_AT name = attr.name;
		enum DW_FORM form = attr.form;
		RzBinDwarfAttrKind kind = attr.kind;
		if (name == DW_AT_comp_dir && (form == DW_FORM_strp || form == DW_FORM_string) && attr.string.content) {
			comp_dir = attr.string.content;
		}
		if (name == DW_AT_stmt_list) {
			if (kind == DW_AT_KIND_CONSTANT) {
				line_info_offset = attr.uconstant;
			} else if (kind == DW_AT_KIND_REFERENCE) {
				line_info_offset = attr.reference;
			}
		}
		rz_vector_push(&die->attrs, &attr);
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
	return true;
}

static inline ut64 get_next_unit_offset(RzBinDwarfCompUnit *unit) {
	return unit->offset + unit->hdr.length + (unit->hdr.encoding.is_64bit ? 12 : 4);
}

/**
 * \brief Reads throught comp_unit buffer and parses all its DIEntries*
 */
static bool comp_unit_die_parse(RzBuffer *buffer, RzBinDwarfCompUnit *unit, RzBinDwarfDebugInfo *info, const RzBinDwarfAbbrevTable *tbl, RzBuffer *str_buffer, bool big_endian) {
	st64 depth = 0;
	while (true) {
		ut64 offset = rz_buf_tell(buffer);
		if (offset >= get_next_unit_offset(unit)) {
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
			RZ_LOG_DEBUG("0x%" PFMT64x ":\t%sNULL\n", offset, indent_str(die.depth));
			rz_vector_push(&unit->dies, &die);
			depth--;
			if (depth <= 0) {
				break;
			} else {
				continue;
			}
		}

		RzBinDwarfAbbrevDecl *abbrev = rz_bin_dwarf_abbrev_get(tbl, die.abbrev_code);
		if (!abbrev) {
			break;
		}

		ut64 attr_count = rz_bin_dwarf_abbrev_decl_count(abbrev);
		if (attr_count) {
			rz_vector_init(&die.attrs, sizeof(RzBinDwarfAttr), (RzVectorFree)attr_fini, NULL);
			rz_vector_reserve(&die.attrs, attr_count);
		}
		if (abbrev->code != 0) {
			die.tag = abbrev->tag;
			die.has_children = abbrev->has_children;
			if (die.has_children) {
				depth++;
			}
			GOTO_IF_FAIL(die_attr_parse(buffer, &die, info, abbrev, &unit->hdr, str_buffer, big_endian), err);
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
static bool comp_unit_hdr_parse(RzBuffer *buffer, RzBinDwarfCompUnitHdr *hdr, bool big_endian) {
	RET_FALSE_IF_FAIL(buf_read_initial_length(buffer, &hdr->encoding.is_64bit, &hdr->length, big_endian));
	RET_FALSE_IF_FAIL(hdr->length <= rz_buf_size(buffer) - rz_buf_tell(buffer));
	ut64 offset_start = rz_buf_tell(buffer);
	U16_OR_RET_FALSE(hdr->encoding.version);

	if (hdr->encoding.version == 5) {
		U8_OR_RET_FALSE(hdr->unit_type);
		U8_OR_RET_FALSE(hdr->encoding.address_size);
		RET_FALSE_IF_FAIL(read_offset(buffer, &hdr->abbrev_offset, hdr->encoding.is_64bit, big_endian));

		if (hdr->unit_type == DW_UT_skeleton || hdr->unit_type == DW_UT_split_compile) {
			U8_OR_RET_FALSE(hdr->dwo_id);
		} else if (hdr->unit_type == DW_UT_type || hdr->unit_type == DW_UT_split_type) {
			U64_OR_RET_FALSE(hdr->type_sig);
			RET_FALSE_IF_FAIL(read_offset(buffer, &hdr->type_offset, hdr->encoding.is_64bit, big_endian));
		}
	} else {
		RET_FALSE_IF_FAIL(read_offset(buffer, &hdr->abbrev_offset, hdr->encoding.is_64bit, big_endian));
		U8_OR_RET_FALSE(hdr->encoding.address_size);
	}
	hdr->header_size = rz_buf_tell(buffer) - offset_start; // header size excluding length field
	return true;
}

static void comp_unit_apply(RzBinDwarfCompUnit *unit, RzBinDwarfDie *die) {
	RzBinDwarfAttr *attr = NULL;
	rz_vector_foreach(&die->attrs, attr) {
		switch (attr->name) {
		case DW_AT_name:
			unit->name = rz_str_new(rz_bin_dwarf_attr_value_get_string_content(attr));
			break;
		case DW_AT_comp_dir:
			unit->comp_dir = rz_str_new(rz_bin_dwarf_attr_value_get_string_content(attr));
			break;
		case DW_AT_producer:
			unit->producer = rz_str_new(rz_bin_dwarf_attr_value_get_string_content(attr));
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
			unit->stmt_list = attr->uconstant;
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
static bool comp_unit_parse(RzBuffer *buffer, RzBinDwarfDebugInfo *info, RzBinDwarfDebugAbbrevs *abbrevs, RzBuffer *str_buffer, bool big_endian) {
	if (!info) {
		return NULL;
	}
	if (!debug_info_init(info)) {
		goto cleanup;
	}

	while (true) {
		ut64 offset = rz_buf_tell(buffer);
		if (offset >= rz_buf_size(buffer)) {
			break;
		}

		RzBinDwarfCompUnit unit = {
			.offset = offset,
			.hdr.unit_offset = unit.offset,
		};
		if (unit_init(&unit) < 0) {
			goto cleanup;
		}
		if (!comp_unit_hdr_parse(buffer, &unit.hdr, big_endian)) {
			break;
		}
		if (unit.hdr.length > rz_buf_size(buffer)) {
			goto cleanup;
		}

		RzBinDwarfAbbrevTable *tbl = ht_up_find(abbrevs->tbl_by_offset, unit.hdr.abbrev_offset, NULL);
		if (!tbl) {
			goto cleanup;
		}

		RZ_LOG_DEBUG("0x%" PFMT64x ":\tcompile unit length = 0x%" PFMT64x ", abbr_offset: 0x%" PFMT64x "\n", unit.offset, unit.hdr.length, unit.hdr.abbrev_offset);
		comp_unit_die_parse(buffer, &unit, info, tbl, str_buffer, big_endian);

		ut64 unit_die_count = rz_vector_len(&unit.dies);
		if (unit_die_count > 0) {
			info->die_count += unit_die_count;
			RzBinDwarfDie *die = rz_vector_head(&unit.dies);
			if (die->tag == DW_TAG_compile_unit) {
				comp_unit_apply(&unit, die);
			}
		}

		rz_vector_push(&info->units, &unit);
	}

	return true;
cleanup:
	return false;
}

RZ_API RzBinDwarfAttr *rz_bin_dwarf_die_get_attr(const RzBinDwarfDie *die, enum DW_AT name) {
	rz_return_val_if_fail(die, NULL);
	RzBinDwarfAttr *attr = NULL;
	rz_vector_foreach(&die->attrs, attr) {
		if (attr->name == name) {
			return attr;
		}
	}
	return NULL;
}

/**
 * \brief Parses .debug_info section
 *
 * \param abbrevs Parsed abbreviations
 * \param bin
 * \return RzBinDwarfDebugInfo* Parsed information, NULL if error
 */
RZ_API RzBinDwarfDebugInfo *rz_bin_dwarf_info_parse(RzBinFile *binfile, RzBinDwarfDebugAbbrevs *abbrevs) {
	rz_return_val_if_fail(binfile && abbrevs, NULL);
	RzBuffer *debug_str_buf = get_section_buf(binfile, "debug_str");
	RzBuffer *buf = get_section_buf(binfile, "debug_info");
	RzBinDwarfDebugInfo *info = NULL;
	GOTO_IF_FAIL(buf, cave_debug_str_buf);

	info = RZ_NEW0(RzBinDwarfDebugInfo);
	GOTO_IF_FAIL(comp_unit_parse(buf, info, abbrevs, debug_str_buf, binfile->o && binfile->o->info && binfile->o->info->big_endian), cave_buf);

	info->die_tbl = ht_up_new_size(info->die_count, NULL, NULL, NULL);
	GOTO_IF_FAIL(info->die_tbl, cave_info);
	info->unit_tbl = ht_up_new(NULL, NULL, NULL);
	GOTO_IF_FAIL(info->unit_tbl, cave_info);

	// build hashtable after whole parsing because of possible relocations
	RzBinDwarfCompUnit *unit = NULL;
	rz_vector_foreach(&info->units, unit) {
		ht_up_insert(info->unit_tbl, unit->offset, unit);
		RzBinDwarfDie *die = NULL;
		rz_vector_foreach(&unit->dies, die) {
			ht_up_insert(info->die_tbl, die->offset, die); // optimization for further processing
		}
	}

cave_buf:
	rz_buf_free(buf);
cave_debug_str_buf:
	rz_buf_free(debug_str_buf);
	return info;
cave_info:
	rz_bin_dwarf_info_free(info);
	info = NULL;
	goto cave_buf;
}
