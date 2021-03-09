// SPDX-FileCopyrightText: 2020 mrmacete <mrmacete@protonmail.ch>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_hash.h>
#include "coresymbolication.h"

#define RZ_CS_EL_OFF_SEGS     0x58
#define RZ_CS_EL_SIZE_SEG     0x20
#define RZ_CS_EL_SIZE_SECT_64 0x18
#define RZ_CS_EL_SIZE_SECT_32 0x10
#define RZ_CS_EL_SIZE_SYM     0x18
#define RZ_CS_EL_SIZE_LSYM    0x24
#define RZ_CS_EL_SIZE_LINFO   0x14

static RzCoreSymCacheElementHdr *rz_coresym_cache_element_header_new(RzBuffer *buf, size_t off, int bits) {
	RzCoreSymCacheElementHdr *hdr = RZ_NEW0(RzCoreSymCacheElementHdr);
	if (hdr && rz_buf_fread_at(buf, off, (ut8 *)hdr, "13i16c5i", 1) == sizeof(RzCoreSymCacheElementHdr)) {
		return hdr;
	}
	free(hdr);
	return NULL;
}

static void rz_coresym_cache_element_segment_fini(RzCoreSymCacheElementSegment *seg) {
	if (seg) {
		free(seg->name);
	}
}

static void rz_coresym_cache_element_section_fini(RzCoreSymCacheElementSection *sec) {
	if (sec) {
		free(sec->name);
	}
}

static void rz_coresym_cache_element_flc_fini(RzCoreSymCacheElementFLC *flc) {
	if (flc) {
		free(flc->file);
	}
}

static void rz_coresym_cache_element_symbol_fini(RzCoreSymCacheElementSymbol *sym) {
	if (sym) {
		free(sym->name);
		free(sym->mangled_name);
	}
}

static void rz_coresym_cache_element_lined_symbol_fini(RzCoreSymCacheElementLinedSymbol *sym) {
	if (sym) {
		rz_coresym_cache_element_symbol_fini(&sym->sym);
		rz_coresym_cache_element_flc_fini(&sym->flc);
	}
}

static void rz_coresym_cache_element_line_info_fini(RzCoreSymCacheElementLineInfo *line) {
	if (line) {
		rz_coresym_cache_element_flc_fini(&line->flc);
	}
}

void rz_coresym_cache_element_free(RzCoreSymCacheElement *element) {
	if (!element) {
		return;
	}
	size_t i;
	if (element->segments) {
		for (i = 0; i < element->hdr->n_segments; i++) {
			rz_coresym_cache_element_segment_fini(&element->segments[i]);
		}
	}
	if (element->sections) {
		for (i = 0; i < element->hdr->n_sections; i++) {
			rz_coresym_cache_element_section_fini(&element->sections[i]);
		}
	}
	if (element->symbols) {
		for (i = 0; i < element->hdr->n_symbols; i++) {
			rz_coresym_cache_element_symbol_fini(&element->symbols[i]);
		}
	}
	if (element->lined_symbols) {
		for (i = 0; i < element->hdr->n_lined_symbols; i++) {
			rz_coresym_cache_element_lined_symbol_fini(&element->lined_symbols[i]);
		}
	}
	if (element->line_info) {
		for (i = 0; i < element->hdr->n_line_info; i++) {
			rz_coresym_cache_element_line_info_fini(&element->line_info[i]);
		}
	}
	free(element->segments);
	free(element->sections);
	free(element->symbols);
	free(element->lined_symbols);
	free(element->line_info);
	free(element->hdr);
	free(element->file_name);
	free(element->binary_version);
	free(element);
}

ut64 rz_coresym_cache_element_pa2va(RzCoreSymCacheElement *element, ut64 pa) {
	size_t i;
	for (i = 0; i < element->hdr->n_segments; i++) {
		RzCoreSymCacheElementSegment *seg = &element->segments[i];
		if (seg->size == 0) {
			continue;
		}
		if (seg->paddr < pa && pa < seg->paddr + seg->size) {
			return pa - seg->paddr + seg->vaddr;
		}
	}
	return pa;
}

static void meta_add_fileline(RzBinFile *bf, ut64 vaddr, ut32 size, RzCoreSymCacheElementFLC *flc) {
	Sdb *s = bf->sdb_addrinfo;
	if (!s) {
		return;
	}
	char aoffset[64];
	ut64 cursor = vaddr;
	ut64 end = cursor + RZ_MAX(size, 1);
	char *fileline = rz_str_newf("%s:%d", flc->file, flc->line);
	while (cursor < end) {
		char *aoffsetptr = sdb_itoa(cursor, aoffset, 16);
		if (!aoffsetptr) {
			break;
		}
		sdb_set(s, aoffsetptr, fileline, 0);
		sdb_set(s, fileline, aoffsetptr, 0);
		cursor += 2;
	}
	free(fileline);
}

static char *str_dup_safe(const ut8 *b, const ut8 *str, const ut8 *end) {
	if (str >= b && str < end) {
		int len = rz_str_nlen((const char *)str, end - str);
		if (len) {
			return rz_str_ndup((const char *)str, len);
		}
	}
	return NULL;
}

static char *str_dup_safe_fixed(const ut8 *b, const ut8 *str, ut64 len, const ut8 *end) {
	if (str >= b && str + len < end) {
		char *result = calloc(1, len + 1);
		if (result) {
			rz_str_ncpy(result, (const char *)str, len);
			return result;
		}
	}
	return NULL;
}

RzCoreSymCacheElement *rz_coresym_cache_element_new(RzBinFile *bf, RzBuffer *buf, ut64 off, int bits) {
	RzCoreSymCacheElement *result = NULL;
	ut8 *b = NULL;
	RzCoreSymCacheElementHdr *hdr = rz_coresym_cache_element_header_new(buf, off, bits);
	if (!hdr) {
		return NULL;
	}
	if (hdr->version != 1) {
		eprintf("Unsupported CoreSymbolication cache version (%d)\n", hdr->version);
		goto beach;
	}
	if (hdr->size == 0 || hdr->size > rz_buf_size(buf) - off) {
		eprintf("Corrupted CoreSymbolication header: size out of bounds (0x%x)\n", hdr->size);
		goto beach;
	}
	result = RZ_NEW0(RzCoreSymCacheElement);
	if (!result) {
		goto beach;
	}
	result->hdr = hdr;
	b = malloc(hdr->size);
	if (!b) {
		goto beach;
	}
	if (rz_buf_read_at(buf, off, b, hdr->size) != hdr->size) {
		goto beach;
	}
	ut8 *end = b + hdr->size;
	if (hdr->file_name_off) {
		result->file_name = str_dup_safe(b, b + (size_t)hdr->file_name_off, end);
	}
	if (hdr->version_off) {
		result->binary_version = str_dup_safe(b, b + (size_t)hdr->version_off, end);
	}
	const size_t word_size = bits / 8;
	ut64 page_zero_size = 0;
	size_t page_zero_idx = 0;
	if (hdr->n_segments > 0) {
		result->segments = RZ_NEWS0(RzCoreSymCacheElementSegment, hdr->n_segments);
		if (!result->segments) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + RZ_CS_EL_OFF_SEGS;
		for (i = 0; i < hdr->n_segments && cursor < end; i++) {
			RzCoreSymCacheElementSegment *seg = &result->segments[i];
			seg->paddr = seg->vaddr = rz_read_le64(cursor);
			cursor += 8;
			if (cursor >= end) {
				break;
			}
			seg->size = seg->vsize = rz_read_le64(cursor);
			cursor += 8;
			if (cursor >= end) {
				break;
			}
			seg->name = str_dup_safe_fixed(b, cursor, 16, end);
			cursor += 16;
			if (!seg->name) {
				continue;
			}

			if (!strcmp(seg->name, "__PAGEZERO")) {
				page_zero_size = seg->size;
				page_zero_idx = i;
				seg->paddr = seg->vaddr = 0;
				seg->size = 0;
			}
		}
		for (i = 0; i < hdr->n_segments && page_zero_size > 0; i++) {
			if (i == page_zero_idx) {
				continue;
			}
			RzCoreSymCacheElementSegment *seg = &result->segments[i];
			if (seg->vaddr < page_zero_size) {
				seg->vaddr += page_zero_size;
			}
		}
	}
	const ut64 start_of_sections = (ut64)hdr->n_segments * RZ_CS_EL_SIZE_SEG + RZ_CS_EL_OFF_SEGS;
	if (hdr->n_sections > 0) {
		result->sections = RZ_NEWS0(RzCoreSymCacheElementSection, hdr->n_sections);
		if (!result->sections) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + start_of_sections;
		for (i = 0; i < hdr->n_sections && cursor < end; i++) {
			ut8 *sect_start = cursor;
			RzCoreSymCacheElementSection *sect = &result->sections[i];
			sect->vaddr = sect->paddr = rz_read_ble(cursor, false, bits);
			if (sect->vaddr < page_zero_size) {
				sect->vaddr += page_zero_size;
			}
			cursor += word_size;
			if (cursor >= end) {
				break;
			}
			sect->size = rz_read_ble(cursor, false, bits);
			cursor += word_size;
			if (cursor >= end) {
				break;
			}
			ut64 sect_name_off = rz_read_ble(cursor, false, bits);
			cursor += word_size;
			if (bits == 32) {
				cursor += word_size;
			}
			sect->name = str_dup_safe(b, sect_start + (size_t)sect_name_off, end);
		}
	}
	const ut64 sect_size = (bits == 32) ? RZ_CS_EL_SIZE_SECT_32 : RZ_CS_EL_SIZE_SECT_64;
	const ut64 start_of_symbols = start_of_sections + (ut64)hdr->n_sections * sect_size;
	if (hdr->n_symbols) {
		result->symbols = RZ_NEWS0(RzCoreSymCacheElementSymbol, hdr->n_symbols);
		if (!result->symbols) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + start_of_symbols;
		for (i = 0; i < hdr->n_symbols && cursor + RZ_CS_EL_SIZE_SYM <= end; i++) {
			RzCoreSymCacheElementSymbol *sym = &result->symbols[i];
			sym->paddr = rz_read_le32(cursor);
			sym->size = rz_read_le32(cursor + 0x4);
			sym->unk1 = rz_read_le32(cursor + 0x8);
			size_t name_off = rz_read_le32(cursor + 0xc);
			size_t mangled_name_off = rz_read_le32(cursor + 0x10);
			sym->unk2 = (st32)rz_read_le32(cursor + 0x14);
			sym->name = str_dup_safe(b, cursor + name_off, end);
			if (!sym->name) {
				cursor += RZ_CS_EL_SIZE_SYM;
				continue;
			}
			sym->mangled_name = str_dup_safe(b, cursor + mangled_name_off, end);
			if (!sym->mangled_name) {
				cursor += RZ_CS_EL_SIZE_SYM;
				continue;
			}
			cursor += RZ_CS_EL_SIZE_SYM;
		}
	}
	const ut64 start_of_lined_symbols = start_of_symbols + (ut64)hdr->n_symbols * RZ_CS_EL_SIZE_SYM;
	if (hdr->n_lined_symbols) {
		result->lined_symbols = RZ_NEWS0(RzCoreSymCacheElementLinedSymbol, hdr->n_lined_symbols);
		if (!result->lined_symbols) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + start_of_lined_symbols;
		for (i = 0; i < hdr->n_lined_symbols && cursor + RZ_CS_EL_SIZE_LSYM <= end; i++) {
			RzCoreSymCacheElementLinedSymbol *lsym = &result->lined_symbols[i];
			lsym->sym.paddr = rz_read_le32(cursor);
			lsym->sym.size = rz_read_le32(cursor + 0x4);
			lsym->sym.unk1 = rz_read_le32(cursor + 0x8);
			size_t name_off = rz_read_le32(cursor + 0xc);
			size_t mangled_name_off = rz_read_le32(cursor + 0x10);
			lsym->sym.unk2 = (st32)rz_read_le32(cursor + 0x14);
			size_t file_name_off = rz_read_le32(cursor + 0x18);
			lsym->flc.line = rz_read_le32(cursor + 0x1c);
			lsym->flc.col = rz_read_le32(cursor + 0x20);
			lsym->sym.name = str_dup_safe(b, cursor + name_off, end);
			if (!lsym->sym.name) {
				cursor += RZ_CS_EL_SIZE_LSYM;
				continue;
			}
			lsym->sym.mangled_name = str_dup_safe(b, cursor + mangled_name_off, end);
			if (!lsym->sym.mangled_name) {
				cursor += RZ_CS_EL_SIZE_LSYM;
				continue;
			}
			lsym->flc.file = str_dup_safe(b, cursor + file_name_off, end);
			if (!lsym->flc.file) {
				cursor += RZ_CS_EL_SIZE_LSYM;
				continue;
			}
			cursor += RZ_CS_EL_SIZE_LSYM;
			meta_add_fileline(bf, rz_coresym_cache_element_pa2va(result, lsym->sym.paddr), lsym->sym.size, &lsym->flc);
		}
	}
	const ut64 start_of_line_info = start_of_lined_symbols + (ut64)hdr->n_lined_symbols * RZ_CS_EL_SIZE_LSYM;
	if (hdr->n_line_info) {
		result->line_info = RZ_NEWS0(RzCoreSymCacheElementLineInfo, hdr->n_line_info);
		if (!result->line_info) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + start_of_line_info;
		for (i = 0; i < hdr->n_line_info && cursor + RZ_CS_EL_SIZE_LINFO <= end; i++) {
			RzCoreSymCacheElementLineInfo *info = &result->line_info[i];
			info->paddr = rz_read_le32(cursor);
			info->size = rz_read_le32(cursor + 4);
			size_t file_name_off = rz_read_le32(cursor + 8);
			info->flc.line = rz_read_le32(cursor + 0xc);
			info->flc.col = rz_read_le32(cursor + 0x10);
			info->flc.file = str_dup_safe(b, cursor + file_name_off, end);
			if (!info->flc.file) {
				break;
			}
			cursor += RZ_CS_EL_SIZE_LINFO;
			meta_add_fileline(bf, rz_coresym_cache_element_pa2va(result, info->paddr), info->size, &info->flc);
		}
	}

	/*
	 * TODO:
	 * Figure out the meaning of the 2 arrays of hdr->n_symbols
	 * 32-bit integers located at the end of line info.
	 * Those are the last info before the strings at the end.
	 */

beach:
	free(b);
	return result;
}
