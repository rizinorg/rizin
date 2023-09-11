// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"
#include <zstd.h>
#include "../format/elf/elf.h"

RZ_IPI RzBinSection *get_section(RzBinFile *binfile, const char *sn) {
	rz_return_val_if_fail(binfile && sn, NULL);
	RzListIter *iter;
	RzBinSection *section = NULL;
	RzBinObject *o = binfile->o;
	if (!o || !o->sections || RZ_STR_ISEMPTY(sn)) {
		return NULL;
	}
	rz_list_foreach (o->sections, iter, section) {
		if (!section->name) {
			continue;
		}
		if (RZ_STR_EQ(section->name, sn) ||
			rz_str_endswith(section->name, sn + 1)) {
			return section;
		}
	}
	return NULL;
}

typedef struct {
	ut8 gch_magic[4]; /* [ 'Z', 'L', 'I', 'B'] */
	ut8 gch_size[8]; /* unaligned 64-bit ELFDATAMSB integer */
} Chdr_GNU;

RZ_IPI RzBuffer *get_section_buf(RzBinFile *binfile, RzBinSection *section) {
	rz_return_val_if_fail(binfile && section, NULL);
	if (section->paddr >= binfile->size) {
		return NULL;
	}
	ut64 len = RZ_MIN(section->size, binfile->size - section->paddr);
	bool is_zlib_gnu = rz_str_startswith(section->name, ".zdebug");
	if (!(section->flags & SHF_COMPRESSED || is_zlib_gnu)) {
		return rz_buf_new_slice(binfile->buf, section->paddr, len);
	}

	bool is_64bit = binfile->o->info->bits == 64;
	ut64 Chdr_size = is_zlib_gnu ? sizeof(Chdr_GNU) : (is_64bit ? sizeof(Elf64_Chdr) : sizeof(Elf32_Chdr));
	if (len < Chdr_size) {
		RZ_LOG_ERROR("corrupted compressed section header\n");
		return NULL;
	}
	RzBuffer *buffer = NULL;
	ut8 *sh_buf = malloc(len);
	if (!(sh_buf && (rz_buf_read_at(binfile->buf, section->paddr, sh_buf, len) == len))) {
		goto err;
	}
	bool bigendian = bf_bigendian(binfile);
	ut32 ch_type = is_zlib_gnu ? ELFCOMPRESS_ZLIB
				   : rz_read_at_ble32(sh_buf, 0, bigendian);

	const ut8 *src = sh_buf + Chdr_size;
	ut64 src_len = len - Chdr_size;
	ut64 uncompressed_len = 0;
	ut8 *uncompressed = NULL;
	RZ_LOG_VERBOSE("Section %s is compressed\n", section->name);
	if (ch_type == ELFCOMPRESS_ZLIB) {
		int len_tmp;
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

void add_relocations(
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
	RzBinSection *section = get_section(binfile, sect_name);
	OK_OR(section, return NULL);
	RzBuffer *buf = get_section_buf(binfile, section);
	OK_OR(buf, return NULL);

	HtUP *relocations = ht_up_new0();
	OK_OR(relocations, rz_buf_free(buf); return NULL);
	add_relocations(binfile, relocations, section);

	RzBinEndianReader *reader = RZ_NEW0(RzBinEndianReader);
	OK_OR(reader, rz_buf_free(buf); ht_up_free(relocations); return NULL);

	reader->buffer = buf;
	reader->big_endian = bf_bigendian(binfile);
	reader->section = section;
	reader->relocations = relocations;
	return reader;
}

static ut64 relocate(RzBinEndianReader *reader, ut64 offset, ut64 value) {
	const RzBinReloc *reloc = ht_up_find(reader->relocations, offset, NULL);
	if (reloc) {
		RZ_LOG_DEBUG("Relocating 0x%" PFMT64x "\n", offset);
		return reloc->addend;
	}
	return value;
}

/**
 * \brief Read an "initial length" value, as specified by dwarf.
 * This also determines whether it is 64bit or 32bit and reads 4 or 12 bytes respectively.
 */
RZ_IPI bool read_initial_length(RzBinEndianReader *reader, RZ_OUT bool *is_64bit, ut64 *out) {
	static const ut64 DWARF32_UNIT_LENGTH_MAX = 0xfffffff0;
	static const ut64 DWARF64_UNIT_LENGTH_INI = 0xffffffff;
	ut32 x32;
	if (!rz_buf_read_ble32(reader->buffer, &x32, reader->big_endian)) {
		return false;
	}
	if (x32 <= DWARF32_UNIT_LENGTH_MAX) {
		*is_64bit = false;
		*out = x32;
	} else if (x32 == DWARF64_UNIT_LENGTH_INI) {
		ut64 x64;
		if (!rz_buf_read_ble64(reader->buffer, &x64, reader->big_endian)) {
			return false;
		}
		*is_64bit = true;
		*out = x64;
	} else {
		RZ_LOG_ERROR("Invalid initial length: 0x%" PFMT32x "\n", x32);
	}
	return true;
}

/**
 * \brief Reads 64/32 bit unsigned based on format
 *
 * \param is_64bit Format of the comp unit
 * \return ut64 Read value
 */
RZ_IPI bool read_offset(RzBinEndianReader *reader, ut64 *out, bool is_64bit) {
	ut64 offset = rz_buf_tell(reader->buffer);
	if (is_64bit) {
		U_OR_RET_FALSE(64, *out);
	} else {
		U_OR_RET_FALSE(32, *out);
	}
	*out = relocate(reader, offset, *out);
	return true;
}

RZ_IPI bool read_block(RzBinEndianReader *reader, RzBinDwarfBlock *block) {
	if (block->length == 0) {
		return true;
	}
	if (block->length >= RZ_ARRAY_SIZE(block->data)) {
		block->ptr = RZ_NEWS0(ut8, block->length);
		RET_FALSE_IF_FAIL(block->ptr);
		ut16 len = rz_buf_read(reader->buffer, block->ptr, block->length);
		if (len != block->length) {
			RZ_FREE(block->ptr);
			return false;
		}
		return true;
	}
	return rz_buf_read(reader->buffer, block->data, block->length) == block->length;
}

RZ_IPI char *read_string(RzBinEndianReader *reader) {
	st64 offset = (st64)rz_buf_tell(reader->buffer);
	RET_NULL_IF_FAIL(offset != -1);
	char *x = rz_buf_get_string(reader->buffer, offset);
	RET_NULL_IF_FAIL(x);
	ut64 len = strlen(x) + 1;
	rz_buf_seek(reader->buffer, (st64)len, SEEK_CUR);
	return x;
}

RZ_IPI char *read_string_not_empty(RzBinEndianReader *reader) {
	char *str = read_string(reader);
	if (RZ_STR_ISEMPTY(str)) {
		RZ_FREE(str);
	}
	return str;
}

RZ_IPI void RzBinEndianReader_free(RzBinEndianReader *r) {
	if (r == NULL) {
		return;
	}
	rz_buf_free(r->buffer);
	ht_up_free(r->relocations);
	free(r);
}

RZ_IPI RzBinEndianReader *RzBinEndianReader_clone(RzBinEndianReader *x) {
	RET_NULL_IF_FAIL(x);
	RzBinEndianReader *r = RZ_NEW0(RzBinEndianReader);
	RET_NULL_IF_FAIL(r);
	MEM_CPY(RzBinEndianReader, r, x);
	r->buffer = rz_buf_new_with_buf(x->buffer);
	return r;
}
