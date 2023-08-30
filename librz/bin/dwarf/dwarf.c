// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <zstd.h>
#include <rz_bin_dwarf.h>
#include "dwarf_private.h"
#include "../format/elf/elf.h"

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
	if (!(section->flags & SHF_COMPRESSED)) {
		return rz_buf_new_slice(binfile->buf, section->paddr, len);
	}

	bool is_64bit = binfile->o->info->bits == 64;
	bool bigendian = bf_bigendian(binfile);
	ut64 Elf_Chdr_size = is_64bit ? sizeof(Elf64_Chdr) : sizeof(Elf32_Chdr);
	if (len < Elf_Chdr_size) {
		RZ_LOG_ERROR("corrupted compressed section header\n");
		return NULL;
	}

	RzBuffer *buffer = NULL;
	ut8 *sh_buf = malloc(len);
	if (!sh_buf) {
		goto err;
	}
	if (rz_buf_read_at(binfile->buf, section->paddr, sh_buf, len) != len) {
		goto err;
	}
	ut32 ch_type = rz_read_at_ble32(sh_buf, 0, bigendian);

	const ut8 *src = sh_buf + Elf_Chdr_size;
	ut64 src_len = len - Elf_Chdr_size;
	ut64 uncompressed_len = 0;
	ut8 *uncompressed = NULL;
	RZ_LOG_VERBOSE("Section %s is compressed\n", section->name);
	if (ch_type == ELFCOMPRESS_ZLIB) {
		uncompressed = rz_inflate(
			src, (int)src_len, NULL, (int *)&uncompressed_len);
	} else if (ch_type == ELFCOMPRESS_ZSTD) {
		uncompressed_len = ZSTD_getFrameContentSize(src, src_len);
		if (uncompressed_len == ZSTD_CONTENTSIZE_UNKNOWN) {
			RZ_LOG_ERROR("ZSTD_CONTENTSIZE_UNKNOWN\n");
			goto err;
		}
		if (uncompressed_len == ZSTD_CONTENTSIZE_ERROR) {
			RZ_LOG_ERROR("ZSTD_CONTENTSIZE_ERROR\n");
			goto err;
		}
		uncompressed = malloc(uncompressed_len);
		if (!uncompressed) {
			goto err;
		}
		if (ZSTD_isError(ZSTD_decompress(uncompressed, uncompressed_len, src, src_len))) {
			free(uncompressed);
			goto err;
		}
	} else {
		RZ_LOG_WARN("Unsupported compression type: %d\n", ch_type);
	}

	if (!uncompressed || uncompressed_len <= 0) {
		RZ_LOG_ERROR("section [%s] uncompress failed\n", section->name);
		goto err;
	}
	buffer = rz_buf_new_with_pointers(uncompressed, uncompressed_len, true);
	free(sh_buf);

	return buffer;
err:
	free(sh_buf);
	rz_buf_free(buffer);
	return NULL;
}

RZ_IPI bool RzBinDwarfEncoding_from_file(RzBinDwarfEncoding *encoding, RzBinFile *bf) {
	if (!(encoding && bf)) {
		return false;
	}
	RzBinInfo *binfo = bf->o && bf->o->info ? bf->o->info : NULL;
	encoding->address_size = binfo->bits ? binfo->bits / 8 : 4;
	encoding->big_endian = binfo->big_endian;
	return true;
}

RZ_API RZ_OWN RzBinDWARF *rz_bin_dwarf_from_file(
	RZ_BORROW RZ_NONNULL RzBinFile *bf,
	RZ_BORROW RZ_NONNULL const RzBinDWARFOption *opt) {
	rz_return_val_if_fail(bf && opt, NULL);
	RzBinDWARF *dw = RZ_NEW0(RzBinDWARF);
	RET_NULL_IF_FAIL(dw);
	dw->addr = DebugAddr_from_file(bf);
	dw->str = RzBinDwarfDebugStr_from_file(bf);

	if (opt->flags & RZ_BIN_DWARF_ABBREVS) {
		dw->abbrev = rz_bin_dwarf_abbrev_from_file(bf);
	}
	if (opt->flags & RZ_BIN_DWARF_ARANGES) {
		dw->aranges = rz_bin_dwarf_aranges_from_file(bf);
	}

	if (opt->flags & RZ_BIN_DWARF_INFO && dw->abbrev) {
		dw->info = rz_bin_dwarf_info_from_file(bf, dw->abbrev, dw->str);
		if (rz_vector_len(&dw->info->units) > 0) {
			RzBinDwarfCompUnit *unit = rz_vector_head(&dw->info->units);
			dw->encoding = unit->hdr.encoding;
		}
	}

	dw->loc = rz_bin_dwarf_loclists_new_from_file(bf, dw->addr);
	if (opt->flags & RZ_BIN_DWARF_LOC && dw->loc && dw->info) {
		rz_bin_dwarf_loclist_table_parse_all(dw->loc, &dw->encoding);
	}
	dw->rng = rz_bin_dwarf_rnglists_new_from_file(bf, dw->addr);
	if (opt->flags & RZ_BIN_DWARF_RNG && dw->loc && dw->info) {
		rz_bin_dwarf_rnglist_table_parse_all(dw->rng, &dw->encoding);
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
	rz_bin_dwarf_line_info_free(dw->line);
	rz_bin_dwarf_loclists_free(dw->loc);
	RzBinDwarfRngListTable_free(dw->rng);
	rz_bin_dwarf_aranges_free(dw->aranges);
	DebugAddr_free(dw->addr);
	RzBinDwarfDebugStr_free(dw->str);
	free(dw);
}
