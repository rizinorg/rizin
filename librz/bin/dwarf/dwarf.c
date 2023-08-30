// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"
#include "../format/elf/elf.h"

RZ_IPI bool RzBinDwarfEncoding_from_file(RzBinDwarfEncoding *encoding, RzBinFile *bf) {
	if (!(encoding && bf)) {
		return false;
	}
	RzBinInfo *binfo = bf->o && bf->o->info ? bf->o->info : NULL;
	encoding->address_size = binfo->bits ? binfo->bits / 8 : 4;
	return true;
}

static inline RZ_OWN RzBinDWARF *dwarf_from_file(
	RZ_BORROW RZ_NONNULL RzBinFile *bf, bool is_dwo) {
	rz_return_val_if_fail(bf, NULL);
	RzBinDWARF *dw = RZ_NEW0(RzBinDWARF);
	RET_NULL_IF_FAIL(dw);

	dw->addr = DebugAddr_from_file(bf);
	dw->line_str = rz_bin_dwarf_line_str_from_file(bf);
	dw->aranges = rz_bin_dwarf_aranges_from_file(bf);

	dw->str = rz_bin_dwarf_str_from_file(bf, is_dwo);
	dw->str_offsets = rz_bin_dwarf_str_offsets_from_file(bf, is_dwo);
	dw->loclists = rz_bin_dwarf_loclists_new_from_file(bf, is_dwo);
	dw->rnglists = rz_bin_dwarf_rnglists_new_from_file(bf, is_dwo);
	dw->abbrev = rz_bin_dwarf_abbrev_from_file(bf, is_dwo);

	if (dw->abbrev) {
		dw->info = rz_bin_dwarf_info_from_file(bf, dw, is_dwo);
	}
	if (dw->info) {
		dw->line = rz_bin_dwarf_line_from_file(bf, dw, is_dwo);
	}
	return dw;
}

static inline char *read_debuglink(RzCore *core, RzBinFile *binfile) {
	RzBinSection *sect = rz_bin_dwarf_section_by_name(binfile, ".gnu_debuglink", false);
	RET_NULL_IF_FAIL(sect);
	RzBuffer *buffer = rz_bin_dwarf_section_buf(binfile, sect);
	RET_NULL_IF_FAIL(buffer);
	char *name = rz_buf_get_string(buffer, 0);
	// TODO: Verification the CRC
	rz_buf_free(buffer);
	return name;
}

static inline char *read_build_id(RzCore *core, RzBinFile *binfile) {
	RzBinSection *sect = rz_bin_dwarf_section_by_name(binfile, ".note.gnu.build-id", false);
	RET_NULL_IF_FAIL(sect);
	RzBuffer *buffer = rz_bin_dwarf_section_buf(binfile, sect);
	RET_NULL_IF_FAIL(buffer);

	char *build_id = NULL;
	/**
	 * struct build_id_note {
	 *   Elf_Nhdr nhdr;
	 *   char name[4];
	 *   uint8_t buf[0];
	 * };
	 */
	size_t nhdr_sz = binfile->o->info->bits == 64 ? sizeof(Elf64_Nhdr) : sizeof(Elf32_Nhdr);
	size_t begin = nhdr_sz + 4;
	size_t sz = rz_buf_size(buffer) - begin;
	ut8 *buf = RZ_NEWS0(ut8, sz);
	if (!buf) {
		goto beach;
	}
	if (rz_buf_read_at(buffer, begin, buf, sz) != sz) {
		goto beach;
	}
	build_id = rz_hex_bin2strdup(buf, (int)sz);

beach:
	rz_buf_free(buffer);
	free(buf);
	return build_id;
}

/**
 * \brief Load DWARF from split DWARF file
 * \param bin The RzBin instance
 * \param opt The RzBinDWARFOption reference
 * \param filepath The file path
 * \return RzBinDWARF pointer or NULL if failed
 */
RZ_API RZ_OWN RzBinDWARF *rz_bin_dwarf_dwo_from_file(
	RZ_BORROW RZ_NONNULL RzBin *bin,
	RZ_BORROW RZ_NONNULL const char *filepath) {
	rz_return_val_if_fail(bin && filepath, NULL);

	RzBinDWARF *dwo = NULL;
	RzIO *io_tmp = rz_io_new();
	RzBin *bin_tmp = rz_bin_new();
	rz_io_bind(io_tmp, &bin_tmp->iob);

	RzBinOptions bopt = { 0 };
	rz_bin_options_init(&bopt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin_tmp, filepath, &bopt);
	if (!bf) {
		goto beach;
	}
	dwo = dwarf_from_file(bf, true);

beach:
	rz_bin_free(bin_tmp);
	rz_io_free(io_tmp);
	return dwo;
}

RZ_API RZ_OWN RzBinDWARF *rz_bin_dwarf_from_file(
	RZ_BORROW RZ_NONNULL RzBinFile *bf) {
	return dwarf_from_file(bf, false);
}

RZ_API void rz_bin_dwarf_free(RZ_OWN RZ_NULLABLE RzBinDWARF *dw) {
	if (!dw) {
		return;
	}
	rz_bin_dwarf_free(dw->dwo_parent);

	DebugRngLists_free(dw->rnglists);
	DebugAddr_free(dw->addr);
	rz_bin_dwarf_str_free(dw->str);
	rz_bin_dwarf_str_offsets_free(dw->str_offsets);

	rz_bin_dwarf_abbrev_free(dw->abbrev);
	rz_bin_dwarf_info_free(dw->info);
	rz_bin_dwarf_line_free(dw->line);
	rz_bin_dwarf_loclists_free(dw->loclists);
	rz_bin_dwarf_aranges_free(dw->aranges);
	free(dw);
}
