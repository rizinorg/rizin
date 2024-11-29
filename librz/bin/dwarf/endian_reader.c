// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <zstd.h>
#include <rz_bin_dwarf.h>
#include "dwarf_private.h"
#include "../format/elf/elf.h"

typedef struct {
	const char *name;
	const char *alias[8];
} SectionAlias;

static const SectionAlias section_alias[] = {
	{ .name = ".debug_str_offsets", .alias = { ".__DWARF.__debug_str_offs", ".debug_str_offsets.dwo", NULL } },
	{ .name = ".debug_str", .alias = { ".debug_str.dwo", NULL } },
	{ .name = ".debug_addr", .alias = { ".debug_addr.dwo", NULL } },
	{ .name = ".debug_line_str", .alias = { ".debug_line_str.dwo", NULL } },
	{ .name = ".debug_aranges", .alias = { ".debug_aranges.dwo", NULL } },
	{ .name = ".debug_loclists", .alias = { ".debug_loclists.dwo", NULL } },
	{ .name = ".debug_loc", .alias = { ".debug_loc.dwo", NULL } },
	{ .name = ".debug_rnglists", .alias = { ".debug_rnglists.dwo", NULL } },
	{ .name = ".debug_ranges", .alias = { ".debug_ranges.dwo", NULL } },
	{ .name = ".debug_abbrev", .alias = { ".debug_abbrev.dwo", NULL } },
	{ .name = ".debug_info", .alias = { ".debug_info.dwo", NULL } },
	{ .name = ".debug_line", .alias = { ".debug_line.dwo", NULL } },

};

RZ_IPI RzBinSection *rz_bin_dwarf_section_by_name(RzBinFile *binfile, const char *sn) {
	rz_return_val_if_fail(binfile && sn, NULL);
	void **iter = NULL;
	RzBinSection *section = NULL;
	RzBinSection *result_section = NULL;
	RzBinObject *o = binfile->o;
	if (!o || !o->sections || RZ_STR_ISEMPTY(sn)) {
		return NULL;
	}
	rz_pvector_foreach (o->sections, iter) {
		section = *iter;
		if (!section->name) {
			continue;
		}
		if (!rz_str_endswith(section->name, sn + 1)) {
			continue;
		}
		result_section = section;
		goto beach;
	}
	for (int i = 0; i < RZ_ARRAY_SIZE(section_alias); ++i) {
		const SectionAlias *alias = section_alias + i;
		if (RZ_STR_NE(sn, alias->name)) {
			continue;
		}
		rz_pvector_foreach (o->sections, iter) {
			section = *iter;
			for (const char **x = (const char **)alias->alias; RZ_STR_ISNOTEMPTY(*x); ++x) {
				if (rz_str_endswith(section->name, *x)) {
					result_section = section;
					goto beach;
				}
			}
		}
	}

beach:
	return result_section;
}

typedef struct {
	ut8 gch_magic[4]; /* [ 'Z', 'L', 'I', 'B'] */
	ut8 gch_size[8]; /* unaligned 64-bit ELFDATAMSB integer */
} Chdr_GNU;

RZ_IPI RZ_OWN RzBinEndianReader *rz_bin_dwarf_section_reader(
	RZ_BORROW RZ_NONNULL RzBinFile *binfile,
	RZ_BORROW RZ_NONNULL RzBinSection *section) {
	rz_return_val_if_fail(binfile && section, NULL);
	if (section->paddr >= binfile->size) {
		return NULL;
	}
	RzBinEndianReader *R = NULL;

	ut64 len = RZ_MIN(section->size, binfile->size - section->paddr);
	bool is_zlib_gnu = rz_str_startswith(section->name, ".zdebug");

	ut8 *sh_buf = malloc(len);
	if (!(sh_buf && (rz_buf_read_at(binfile->buf, section->paddr, sh_buf, len) == len))) {
		goto err;
	}
	bool bigendian = bf_bigendian(binfile);
	if (!(section->flags & SHF_COMPRESSED || is_zlib_gnu)) {
		R = RzBinEndianReader_new(sh_buf, len, bigendian, true, NULL);
		if (!R) {
			free(sh_buf);
		}
		return R;
	}

	bool is_64bit = binfile->o->info->bits == 64;
	ut64 Chdr_size = is_zlib_gnu ? sizeof(Chdr_GNU) : (is_64bit ? sizeof(Elf64_Chdr) : sizeof(Elf32_Chdr));
	if (len < Chdr_size) {
		RZ_LOG_ERROR("corrupted compressed section header\n");
		goto err;
	}

	ut32 ch_type = is_zlib_gnu ? ELFCOMPRESS_ZLIB
				   : rz_read_at_ble32(sh_buf, 0, bigendian);

	const ut8 *src = sh_buf + Chdr_size;
	ut64 src_len = len - Chdr_size;
	ut64 uncompressed_len = 0;
	ut8 *uncompressed = NULL;
	RZ_LOG_VERBOSE("Section %s is compressed, type %d%s\n", section->name, ch_type,
		is_zlib_gnu ? " (GNU)" : "");
	if (ch_type == ELFCOMPRESS_ZLIB) {
		int len_tmp = 0;
		uncompressed = rz_inflate(
			src, (int)src_len, NULL, &len_tmp);
		uncompressed_len = len_tmp;
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

	if (!uncompressed || uncompressed_len == 0) {
		RZ_LOG_ERROR("section [%s] uncompress failed\n", section->name);
		goto err;
	}
	free(sh_buf);
	R = RzBinEndianReader_new(uncompressed, uncompressed_len, bigendian, true, NULL);
	if (!R) {
		free(uncompressed);
	}

	return R;

err:
	free(sh_buf);
	R_free(R);
	return NULL;
}

static inline void add_relocations(
	RzBinFile *bf,
	HtUP *relocations,
	RzBinSection *section) {
	rz_return_if_fail(relocations && section);
	for (size_t i = 0; i < bf->o->relocs->relocs_count; ++i) {
		RzBinReloc *reloc = bf->o->relocs->relocs[i];
		if (reloc->section_vaddr != section->vaddr) {
			continue;
		}
		ut64 offset = reloc->vaddr - section->vaddr;
		ht_up_insert(relocations, offset, reloc);
	}
}

RZ_IPI RzBinEndianReader *RzBinEndianReader_from_file(RzBinFile *binfile, const char *sect_name) {
	rz_return_val_if_fail(binfile && sect_name, NULL);
	RzBinSection *section = rz_bin_dwarf_section_by_name(binfile, sect_name);
	OK_OR(section, return NULL);
	RzBinEndianReader *R = rz_bin_dwarf_section_reader(binfile, section);
	OK_OR(R, return NULL);

	HtUP *relocations = ht_up_new(NULL, NULL);
	OK_OR(relocations, R_free(R); return NULL);
	add_relocations(binfile, relocations, section);

	R->relocations = relocations;
	return R;
}

RZ_IPI ut64 R_relocate(RzBinEndianReader *R, ut64 offset, ut64 value) {
	rz_return_val_if_fail(R, value);
	if (!R->relocations) {
		return value;
	}
	const RzBinReloc *reloc = ht_up_find(R->relocations, offset, NULL);
	if (reloc) {
		RZ_LOG_DEBUG("Relocating 0x%" PFMT64x "\n", offset);
		return reloc->addend;
	}
	return value;
}
