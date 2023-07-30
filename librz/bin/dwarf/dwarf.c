// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_IPI RzBinSection *get_section(RzBinFile *binfile, const char *sn) {
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

RZ_IPI RzBuffer *get_section_buf(RzBinFile *binfile, const char *sect_name) {
	rz_return_val_if_fail(binfile && sect_name, NULL);
	RzBinSection *section = get_section(binfile, sect_name);
	if (!section) {
		return NULL;
	}
	if (section->paddr >= binfile->size) {
		return NULL;
	}
	ut64 len = RZ_MIN(section->size, binfile->size - section->paddr);
	return rz_buf_new_slice(binfile->buf, section->paddr, len);
}

RZ_API RZ_OWN RzBinDwarf *rz_bin_dwarf_parse(RZ_BORROW RZ_NONNULL RzBinFile *bf, RZ_BORROW RZ_NONNULL const RzBinDwarfParseOptions *opt) {
	rz_return_val_if_fail(bf && opt, NULL);
	RzBinDwarf *dw = RZ_NEW0(RzBinDwarf);
	if (!dw) {
		return NULL;
	}
	dw->encoding.big_endian = opt->big_endian;
	dw->addr = DebugAddr_parse(bf);
	if (opt->flags & RZ_BIN_DWARF_PARSE_ABBREVS) {
		RZ_LOG_DEBUG(".debug_abbrev\n");
		dw->abbrevs = rz_bin_dwarf_abbrev_parse(bf);
	}
	if (opt->flags & RZ_BIN_DWARF_PARSE_INFO && dw->abbrevs) {
		RZ_LOG_DEBUG(".debug_info\n");
		dw->info = rz_bin_dwarf_info_parse(bf, dw->abbrevs);
		if (rz_vector_len(&dw->info->units) > 0) {
			RzBinDwarfCompUnit *unit = rz_vector_head(&dw->info->units);
			dw->encoding = unit->hdr.encoding;
		}
	}

	dw->loc = rz_bin_dwarf_loclists_new(bf, dw);
	if (opt->flags & RZ_BIN_DWARF_PARSE_LOC && dw->loc && dw->info) {
		RZ_LOG_DEBUG(dw->encoding.version == 5 ? ".debug_loclists\n" : ".debug_loc\n");
		rz_bin_dwarf_loclist_table_parse_all(dw->loc, &dw->encoding);
	}
	dw->rnglists = rz_bin_dwarf_rnglists_new(bf, dw);
	if (opt->flags & RZ_BIN_DWARF_PARSE_RNGLISTS && dw->loc && dw->info) {
		RZ_LOG_DEBUG(dw->encoding.version == 5 ? ".debug_rnglists\n" : ".debug_ranges\n");
		rz_bin_dwarf_rnglist_table_parse_all(dw->rnglists, &dw->encoding);
	}

	if (opt->flags & RZ_BIN_DWARF_PARSE_LINES && dw->info) {
		RZ_LOG_DEBUG(".debug_line\n");
		dw->lines = rz_bin_dwarf_parse_line(bf, dw->info, opt->line_mask);
	}
	if (opt->flags & RZ_BIN_DWARF_PARSE_ARANGES) {
		RZ_LOG_DEBUG(".debug_aranges\n");
		dw->aranges = rz_bin_dwarf_aranges_parse(bf);
	}
	return dw;
}

RZ_API void rz_bin_dwarf_free(RZ_OWN RZ_NULLABLE RzBinDwarf *dw) {
	if (!dw) {
		return;
	}
	rz_bin_dwarf_abbrev_free(dw->abbrevs);
	rz_bin_dwarf_info_free(dw->info);
	rz_bin_dwarf_line_info_free(dw->lines);
	rz_bin_dwarf_loclists_free(dw->loc);
	RzBinDwarfRngListTable_free(dw->rnglists);
	rz_list_free(dw->aranges);
	DebugAddr_free(dw->addr);
	free(dw);
}
