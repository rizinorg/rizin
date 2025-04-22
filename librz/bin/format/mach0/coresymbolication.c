// SPDX-FileCopyrightText: 2020 mrmacete <mrmacete@protonmail.ch>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
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

RZ_API void rz_coresym_cache_element_free(RzCoreSymCacheElement *element) {
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

RZ_API ut64 rz_coresym_cache_element_pa2va(RzCoreSymCacheElement *element, ut64 pa) {
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

static char *str_dup_safe(const ut8 *b, const ut8 *str, const ut8 *end) {
	if (str >= b && str < end) {
		return rz_str_ndup((const char *)str, end - str);
	}
	return NULL;
}

static char *str_ndup_safe(const ut8 *b, const ut8 *str, ut64 len, const ut8 *end) {
	if (str >= b && str + len < end) {
		return rz_str_ndup((const char *)str, len);
	}
	return NULL;
}

RZ_API RzCoreSymCacheElement *rz_coresym_cache_element_new(RzBinFile *bf, RzBuffer *buf, ut64 off, int bits, RZ_OWN char *file_name) {
	RzCoreSymCacheElement *result = NULL;
	ut8 *b = NULL;
	RzCoreSymCacheElementHdr *hdr = rz_coresym_cache_element_header_new(buf, off, bits);
	if (!hdr) {
		return NULL;
	}
	if (hdr->version != 1) {
		RZ_LOG_ERROR("Unsupported CoreSymbolication cache version (%d)\n", hdr->version);
		goto beach;
	}
	if (hdr->size == 0 || hdr->size > rz_buf_size(buf) - off) {
		RZ_LOG_ERROR("Corrupted CoreSymbolication header: size out of bounds (0x%x)\n", hdr->size);
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
	if (file_name) {
		result->file_name = rz_str_dup(file_name);
	} else if (hdr->file_name_off) {
		result->file_name = str_dup_safe(b, b + (size_t)hdr->file_name_off, end);
	}
	if (hdr->version_off) {
		result->binary_version = str_dup_safe(b, b + (size_t)hdr->version_off, end);
	}
	const size_t word_size = bits / 8;
	const ut64 start_of_sections = (ut64)hdr->n_segments * RZ_CS_EL_SIZE_SEG + RZ_CS_EL_OFF_SEGS;
	const ut64 sect_size = (bits == 32) ? RZ_CS_EL_SIZE_SECT_32 : RZ_CS_EL_SIZE_SECT_64;
	const ut64 start_of_symbols = start_of_sections + (ut64)hdr->n_sections * sect_size;
	const ut64 start_of_lined_symbols = start_of_symbols + (ut64)hdr->n_symbols * RZ_CS_EL_SIZE_SYM;
	const ut64 start_of_line_info = start_of_lined_symbols + (ut64)hdr->n_lined_symbols * RZ_CS_EL_SIZE_LSYM;
	const ut64 start_of_unknown_pairs = start_of_line_info + (ut64)hdr->n_line_info * RZ_CS_EL_SIZE_LINFO;
	const ut64 start_of_strings = start_of_unknown_pairs + (ut64)hdr->n_symbols * 8;

	ut64 page_zero_size = 0;
	size_t page_zero_idx = 0;

	if (UT32_MUL_OVFCHK(hdr->n_segments, sizeof(RzCoreSymCacheElementSegment))) {
		goto beach;
	} else if (UT32_MUL_OVFCHK(hdr->n_sections, sizeof(RzCoreSymCacheElementSection))) {
		goto beach;
	} else if (UT32_MUL_OVFCHK(hdr->n_symbols, sizeof(RzCoreSymCacheElementSymbol))) {
		goto beach;
	} else if (UT32_MUL_OVFCHK(hdr->n_lined_symbols, sizeof(RzCoreSymCacheElementLinedSymbol))) {
		goto beach;
	} else if (UT32_MUL_OVFCHK(hdr->n_line_info, sizeof(RzCoreSymCacheElementLineInfo))) {
		goto beach;
	}
	if (hdr->n_segments > 0) {
		result->segments = RZ_NEWS0(RzCoreSymCacheElementSegment, hdr->n_segments);
		if (!result->segments) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + RZ_CS_EL_OFF_SEGS;
		for (i = 0; i < hdr->n_segments && (cursor + 8) <= end; i++) {
			RzCoreSymCacheElementSegment *seg = &result->segments[i];
			seg->paddr = seg->vaddr = rz_read_le64(cursor);
			cursor += 8;
			if ((cursor + 8) >= end) {
				goto beach;
			}
			seg->size = seg->vsize = rz_read_le64(cursor);
			cursor += 8;
			if (cursor >= end) {
				goto beach;
			}
			seg->name = str_ndup_safe(b, cursor, 16, end);
			cursor += 16;
			if (!seg->name) {
				goto beach;
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
	bool relative_to_strings = false;
	ut8 *string_origin;
	if (hdr->n_sections > 0) {
		result->sections = RZ_NEWS0(RzCoreSymCacheElementSection, hdr->n_sections);
		if (!result->sections) {
			goto beach;
		}
		size_t i;
		ut8 *cursor = b + start_of_sections;
		ut8 *upper_boundary = end - word_size;
		for (i = 0; i < hdr->n_sections && cursor < upper_boundary; i++) {
			ut8 *sect_start = cursor;
			RzCoreSymCacheElementSection *sect = &result->sections[i];
			sect->vaddr = sect->paddr = rz_read_ble(cursor, false, bits);
			if (sect->vaddr < page_zero_size) {
				sect->vaddr += page_zero_size;
			}
			cursor += word_size;
			if (cursor >= upper_boundary) {
				goto beach;
			}
			sect->size = rz_read_ble(cursor, false, bits);
			cursor += word_size;
			if (cursor >= upper_boundary) {
				goto beach;
			}
			size_t sect_name_off = rz_read_ble(cursor, false, bits);
			if (!i && !sect_name_off) {
				relative_to_strings = true;
			}
			cursor += word_size;
			if (bits == 32) {
				cursor += word_size;
			}
			string_origin = relative_to_strings ? b + start_of_strings : sect_start;
			if (string_origin + sect_name_off >= end) {
				goto beach;
			}
			sect->name = str_dup_safe(b, string_origin + sect_name_off, end);
		}
	}
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
			string_origin = relative_to_strings ? b + start_of_strings : cursor;
			sym->name = str_dup_safe(b, string_origin + name_off, end);
			if (!sym->name) {
				cursor += RZ_CS_EL_SIZE_SYM;
				goto beach;
			}
			string_origin = relative_to_strings ? b + start_of_strings : cursor;
			sym->mangled_name = str_dup_safe(b, string_origin + mangled_name_off, end);
			if (!sym->mangled_name) {
				cursor += RZ_CS_EL_SIZE_SYM;
				goto beach;
			}
			cursor += RZ_CS_EL_SIZE_SYM;
		}
		if (i < hdr->n_symbols) {
			hdr->n_symbols = i;
		}
	}
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
			string_origin = relative_to_strings ? b + start_of_strings : cursor;
			lsym->sym.name = str_dup_safe(b, string_origin + name_off, end);
			if (!lsym->sym.name) {
				goto beach;
			}
			string_origin = relative_to_strings ? b + start_of_strings : cursor;
			lsym->sym.mangled_name = str_dup_safe(b, string_origin + mangled_name_off, end);
			if (!lsym->sym.mangled_name) {
				goto beach;
			}
			string_origin = relative_to_strings ? b + start_of_strings : cursor;
			lsym->flc.file = str_dup_safe(b, string_origin + file_name_off, end);
			if (!lsym->flc.file) {
				goto beach;
			}
			cursor += RZ_CS_EL_SIZE_LSYM;
		}
		if (i < hdr->n_lined_symbols) {
			hdr->n_lined_symbols = i;
		}
	}
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
			string_origin = relative_to_strings ? b + start_of_strings : cursor;
			info->flc.file = str_dup_safe(b, string_origin + file_name_off, end);
			if (!info->flc.file) {
				goto beach;
			}
			cursor += RZ_CS_EL_SIZE_LINFO;
		}
		if (i < hdr->n_line_info) {
			hdr->n_line_info = i;
		}
	}

	/*
	 * TODO:
	 * Figure out the meaning of the 2 arrays of hdr->n_symbols
	 * 32-bit integers located at the end of line info.
	 * Those are the last info before the strings at the end.
	 */
	free(b);
	return result;

beach:
	free(b);
	rz_coresym_cache_element_free(result);
	return NULL;
}
