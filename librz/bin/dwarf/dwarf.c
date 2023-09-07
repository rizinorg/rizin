// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_IPI bool RzBinDwarfEncoding_from_file(RzBinDwarfEncoding *encoding, RzBinFile *bf) {
	if (!(encoding && bf)) {
		return false;
	}
	RzBinInfo *binfo = bf->o && bf->o->info ? bf->o->info : NULL;
	encoding->address_size = binfo->bits ? binfo->bits / 8 : 4;
	return true;
}

RZ_API RZ_OWN RzBinDWARF *rz_bin_dwarf_from_file(
	RZ_BORROW RZ_NONNULL RzBinFile *bf,
	RZ_BORROW RZ_NONNULL const RzBinDWARFOption *opt) {
	rz_return_val_if_fail(bf && opt, NULL);
	RzBinDWARF *dw = RZ_NEW0(RzBinDWARF);
	RET_NULL_IF_FAIL(dw);
	dw->addr = DebugAddr_from_file(bf);
	dw->str = RzBinDwarfStr_from_file(bf);
	dw->str_offsets = RzBinDwarfStrOffsets_from_file(bf);

	if (opt->flags & RZ_BIN_DWARF_ABBREVS) {
		dw->abbrev = rz_bin_dwarf_abbrev_from_file(bf);
	}
	if (opt->flags & RZ_BIN_DWARF_ARANGES) {
		dw->aranges = rz_bin_dwarf_aranges_from_file(bf);
	}

	if (opt->flags & RZ_BIN_DWARF_INFO && dw->abbrev) {
		dw->info = rz_bin_dwarf_info_from_file(bf, dw);
	}

	if (opt->flags & RZ_BIN_DWARF_LOC && dw->info) {
		dw->loclists = rz_bin_dwarf_loclists_new_from_file(bf);
	}
	if (opt->flags & RZ_BIN_DWARF_RNG && dw->info) {
		dw->rnglists = rz_bin_dwarf_rnglists_new_from_file(bf);
	}

	if (opt->flags & RZ_BIN_DWARF_LINES && dw->info) {
		dw->line = rz_bin_dwarf_line_from_file(bf, dw->info, opt->line_mask);
	}
	return dw;
}

RZ_API void rz_bin_dwarf_free(RZ_OWN RZ_NULLABLE RzBinDWARF *dw) {
	if (!dw) {
		return;
	}
	rz_bin_dwarf_abbrev_free(dw->abbrev);
	rz_bin_dwarf_info_free(dw->info);
	rz_bin_dwarf_line_free(dw->line);
	rz_bin_dwarf_loclists_free(dw->loclists);
	DebugRngLists_free(dw->rnglists);
	rz_bin_dwarf_aranges_free(dw->aranges);
	DebugAddr_free(dw->addr);
	RzBinDwarfStr_free(dw->str);
	free(dw);
}
