// SPDX-FileCopyrightText: 2026 Stefan Bisti <stefbisti@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util/rz_buf.h"
#include "rz_vector.h"
#include <rz_bin.h>
#include <rz_lib.h>

/*
 * Hunk file format
 *
 * File structure
 * 1. Hunk Header
 * - Magic cookie
 * - Resident library names (skip this part)
 * - Number of hunks
 * - First hunk index (0)
 * - Last hunk index (number of hunks - 1)
 * - Each hunk's size + memory flags (first 2 bits)
 *
 * 2. Sequence of hunks, each hunk structured as:
 * - Type (HUNK_CODE, HUNK_DATA, HUNK_BSS)
 * - Size (number of 32-bit longwords)
 * - Payload (Size * 4)
 * - Metadata like HUNK_RELOC32 or HUNK_SYMBOL
 * - HUNK_END (0x3F2)
 *
 * Hunk Relocs (0x3EC)
 * - count (when count is 0, the relocs have ended)
 * - target_hunk
 * - offset (size count)
 *
 * Hunk Symbols (0x3F0)
 * - symbol_name_length (when length is 0, the relocs have ended)
 * - the actual name
 * - the offset
 */

#define HUNK_HEADER 0x3F3
#define HUNK_CODE   0x3E9
#define HUNK_DATA   0x3EA
#define HUNK_BSS    0x3EB
#define HUNK_END    0x3F2

#define HUNK_RELOC32 0x3EC
#define HUNK_SYMBOL  0x3F0
#define HUNK_DEBUG   0x3F1

#define ANY_MEMORY  0x00
#define CHIP_MEMORY 0x40 // needed for graphics, audio
#define FAST_MEMORY 0x80 // standard RAM

#define VADDR_START 0x8000

typedef struct hunk_reloc {
	ut32 target_hunk_index;
	ut32 offset;
} HunkReloc;

typedef struct hunk_symbol {
	char *name;
	ut32 offset;
} HunkSymbol;

typedef struct hunk_data {
	ut32 type;
	ut64 paddr;
	ut64 psize;
	ut64 vaddr;
	ut64 vsize;
	ut32 relocs_count;
	RzVector /*<HunkReloc *>*/ *relocs;
	ut32 symbols_count;
	RzVector /*<HunkSymbol *>*/ *symbols;
	ut32 debug_size;
	ut8 *debug_data;
} HunkData;

typedef struct program_data {
	ut32 hunks_count;
	RzVector /*<HunkData *>*/ *hunks;
} ProgramData;

static inline const char *hunk_get_name_from_type(ut32 type) {
	switch (type) {
	case HUNK_HEADER:
		return "header";
	case HUNK_CODE:
		return "code";
	case HUNK_DATA:
		return "data";
	case HUNK_BSS:
		return "bss";
	case HUNK_END:
		return "end";
	case HUNK_RELOC32:
		return "reloc";
	case HUNK_SYMBOL:
		return "symbol";
	case HUNK_DEBUG:
		return "debug";
	default:
		return "";
	}
}

static void hunk_data_free(HunkData *hd) {
	rz_return_if_fail(hd);
	rz_vector_free(hd->relocs);
	rz_vector_free(hd->symbols);
	if (hd->debug_data) {
		free(hd->debug_data);
	}
}

static void hunk_destroy(RzBinFile *bf) {
	rz_return_if_fail(bf && bf->o);

	ProgramData *program_data = bf->o->bin_obj;

	if (program_data) {
		rz_vector_free(program_data->hunks);
		free(program_data);
		bf->o->bin_obj = NULL;
	}
}

static void hunk_symbol_free(HunkSymbol *hunk_symbol) {
	if (hunk_symbol && hunk_symbol->name) {
		free(hunk_symbol->name);
	}
}

static bool hunk_handle_code_data_bss(RzBinFile *bf, ProgramData *program_data,
	ut32 current_hunk_index, ut64 *paddr, ut32 hunk_type, ut64 *vaddr) {
	HunkData *hunk_data = (HunkData *)rz_vector_index_ptr(program_data->hunks, current_hunk_index);
	if (!hunk_data) {
		return false;
	}

	ut32 hunk_size;
	if (!rz_buf_read_be32_offset(bf->buf, paddr, &hunk_size)) {
		return false;
	}
	ut32 actual_size = (hunk_size & 0x3FFFFFFF) * 4; /* mask the first 2 bits */

	hunk_data->type = hunk_type;
	hunk_data->paddr = *paddr;
	hunk_data->vaddr = *vaddr;
	hunk_data->psize = hunk_type == HUNK_BSS ? 0 : actual_size;
	hunk_data->vsize = actual_size;

	*vaddr += hunk_data->vsize;
	if (hunk_type != HUNK_BSS) {
		*paddr += actual_size;
	}

	return true;
}

static bool hunk_handle_reloc(RzBinFile *bf, ProgramData *program_data,
	ut32 current_hunk_index, ut64 *paddr) {
	/* prevent current_hunk_index from overflowing */
	ut32 target_index = current_hunk_index;
	if (target_index >= program_data->hunks_count) {
		if (program_data->hunks_count > 0) {
			target_index = program_data->hunks_count - 1;
		} else {
			return false;
		}
	}

	HunkData *hunk_data = (HunkData *)rz_vector_index_ptr(program_data->hunks, target_index);
	if (!hunk_data) {
		return false;
	}

	ut32 relocs_count;
	if (!rz_buf_read_be32_offset(bf->buf, paddr, &relocs_count)) {
		return false;
	}

	while (relocs_count > 0) {
		ut32 target_hunk_index;
		if (!rz_buf_read_be32_offset(bf->buf, paddr, &target_hunk_index)) {
			return false;
		}

		ut32 i;
		for (i = 0; i < relocs_count; i++) {
			ut32 offset;
			if (!rz_buf_read_be32_offset(bf->buf, paddr, &offset)) {
				return false;
			}

			HunkReloc hunk_reloc = { 0 };
			hunk_reloc.target_hunk_index = target_hunk_index;
			hunk_reloc.offset = offset;
			rz_vector_push(hunk_data->relocs, &hunk_reloc); /* uses memcpy to assign */
			hunk_data->relocs_count++;
		}
		if (i != relocs_count) {
			return false;
		}

		if (!rz_buf_read_be32_offset(bf->buf, paddr, &relocs_count)) {
			return false;
		}
	}

	return true;
}

static bool hunk_handle_symbol(RzBinFile *bf, ProgramData *program_data,
	ut32 current_hunk_index, ut64 *paddr) {
	/* prevent current_hunk_index from overflowing */
	ut32 target_index = current_hunk_index;
	if (target_index >= program_data->hunks_count) {
		if (program_data->hunks_count > 0) {
			target_index = program_data->hunks_count - 1;
		} else {
			return false;
		}
	}

	HunkData *hunk_data = (HunkData *)rz_vector_index_ptr(program_data->hunks, target_index);
	if (!hunk_data) {
		return false;
	}

	ut32 symbol_length;
	if (!rz_buf_read_be32_offset(bf->buf, paddr, &symbol_length)) {
		return false;
	}
	while (symbol_length > 0) {
		HunkSymbol hunk_symbol = { 0 };

		hunk_data->symbols_count++;

		char *symbol_name = rz_mem_alloc(symbol_length * 4 + 1);
		rz_return_val_if_fail(symbol_name, false);
		if (rz_buf_read_at(bf->buf, *paddr, (ut8 *)symbol_name, symbol_length * 4) < symbol_length * 4) {
			return false;
		}
		symbol_name[symbol_length * 4] = 0;
		*paddr += symbol_length * 4;

		ut32 symbol_offset;
		if (!rz_buf_read_be32_offset(bf->buf, paddr, &symbol_offset)) {
			return false;
		}

		hunk_symbol.name = symbol_name;
		hunk_symbol.offset = symbol_offset;
		rz_vector_push(hunk_data->symbols, &hunk_symbol); /* uses memcpy to assign */

		if (!rz_buf_read_be32_offset(bf->buf, paddr, &symbol_length)) {
			return false;
		}
	}

	return true;
}

static bool hunk_handle_debug(RzBinFile *bf, ProgramData *program_data,
	ut32 current_hunk_index, ut64 *paddr) {

	/* prevent current_hunk_index from overflowing */
	ut32 target_index = current_hunk_index;
	if (target_index >= program_data->hunks_count && program_data->hunks_count > 0) {
		target_index = program_data->hunks_count - 1;
	}

	HunkData *hunk_data = (HunkData *)rz_vector_index_ptr(program_data->hunks, target_index);
	rz_return_val_if_fail(hunk_data, false);

	ut32 debug_raw_size;
	if (!rz_buf_read_be32_offset(bf->buf, paddr, &debug_raw_size)) {
		return false;
	}
	ut32 debug_size = (debug_raw_size & 0x3FFFFFFF) * 4; /* mask the first 2 bits */

	hunk_data->debug_size = debug_size;
	hunk_data->debug_data = rz_mem_alloc(debug_size);
	if (hunk_data->debug_data) {
		if (rz_buf_read_at(bf->buf, *paddr, hunk_data->debug_data, debug_size) < debug_size) {
			return false;
		}
	}
	*paddr += debug_size;

	ut32 next_tag;
	if (rz_buf_read_be32_offset(bf->buf, paddr, &next_tag)) {
		if (next_tag != HUNK_END) {
			*paddr -= 4;
		}
	}

	return true;
}

static bool hunk_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	rz_return_val_if_fail(bf, false);

	ProgramData *program_data = RZ_NEW0(ProgramData);
	rz_return_val_if_fail(program_data, false);
	obj->bin_obj = program_data;

	ut64 paddr = 0;
	ut64 vaddr = VADDR_START;
	paddr += 4; /* skip the header */

	ut32 strings_length;
	while (rz_buf_read_be32_offset(bf->buf, &paddr, &strings_length) && strings_length > 0) {
		paddr += strings_length * 4; /* skip the strings */
	}

	ut32 hunks_count;
	if (!rz_buf_read_be32_offset(bf->buf, &paddr, &hunks_count)) {
		return false;
	}
	program_data->hunks_count = hunks_count;
	program_data->hunks = rz_vector_new(sizeof(HunkData), (RzVectorFree)hunk_data_free, NULL);

	for (ut32 i = 0; i < hunks_count; i++) {
		HunkData hunk_data = { 0 };
		hunk_data.relocs = rz_vector_new(sizeof(HunkReloc), NULL, NULL);
		hunk_data.symbols = rz_vector_new(sizeof(HunkSymbol), (RzVectorFree)hunk_symbol_free, NULL);
		rz_vector_push(program_data->hunks, &hunk_data); // uses memcpy to assign
	}

	paddr += 4; /* skip the first hunk index (0) */
	paddr += 4; /* skip the last hunk index (hunks_count - 1) */
	paddr += hunks_count * 4; /* skip the sizes */

	ut32 current_hunk_index = 0;
	ut32 hunk_type;
	while (paddr < bf->size) {
		if (!rz_buf_read_be32_offset(bf->buf, &paddr, &hunk_type)) {
			break;
		}

		ut8 executed_correctly = 1;
		switch (hunk_type) {
		case HUNK_CODE:
		case HUNK_DATA:
		case HUNK_BSS:
			if (!hunk_handle_code_data_bss(bf, program_data, current_hunk_index, &paddr, hunk_type, &vaddr)) {
				executed_correctly = 0;
			}
			break;
		case HUNK_RELOC32:
			if (!hunk_handle_reloc(bf, program_data, current_hunk_index, &paddr)) {
				executed_correctly = 0;
			}
			break;
		case HUNK_SYMBOL:
			if (!hunk_handle_symbol(bf, program_data, current_hunk_index, &paddr)) {
				executed_correctly = 0;
			}
			break;
		case HUNK_DEBUG:
			if (!hunk_handle_debug(bf, program_data, current_hunk_index, &paddr)) {
				executed_correctly = 0;
			}
			break;
		case HUNK_END:
			if (current_hunk_index < program_data->hunks_count) {
				current_hunk_index++;
			}
			break;
		default:
			executed_correctly = 0;
			break;
		}

		if (!executed_correctly) {
			break;
		}
	}
	return current_hunk_index == hunks_count;
}

static bool hunk_check_buffer(RzBuffer *buf) {
	rz_return_val_if_fail(buf, false);

	ut32 magic = 0;
	if (rz_buf_read_at(buf, 0, (ut8 *)&magic, 4) < 4) {
		return false;
	}
	magic = rz_read_be32(&magic);
	return magic == HUNK_HEADER;
}

static RzPVector /*<RzBinMap *>*/ *hunk_maps(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	rz_return_val_if_fail(ret, NULL);

	ProgramData *program_data = bf->o->bin_obj;

	for (ut32 i = 0; i < program_data->hunks_count; i++) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			break;
		}
		rz_pvector_push(ret, map);

		HunkData *hunk_data = (HunkData *)rz_vector_index_ptr(program_data->hunks, i);
		if (!hunk_data) {
			continue;
		}

		map->name = rz_str_newf("hunk_%d_%s", i, hunk_get_name_from_type(hunk_data->type));
		map->paddr = hunk_data->paddr;
		map->psize = hunk_data->psize;
		map->vaddr = hunk_data->vaddr;
		map->vsize = hunk_data->vsize;

		if (hunk_data->type == HUNK_CODE) {
			map->perm = RZ_PERM_R | RZ_PERM_X;
		} else {
			map->perm = RZ_PERM_R | RZ_PERM_W;
		}
	}

	return ret;
}

/* finds the first HUNK_CODE segment */
static RzPVector /*<RzBinAddr *>*/ *hunk_entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	RzPVector *ret = rz_pvector_new((RzPVectorFree)free);
	rz_return_val_if_fail(ret, NULL);

	ProgramData *program_data = bf->o->bin_obj;

	for (ut32 i = 0; i < program_data->hunks_count; i++) {
		HunkData *hunk_data = (HunkData *)rz_vector_index_ptr(program_data->hunks, i);
		if (!hunk_data) {
			continue;
		}
		if (hunk_data->type == HUNK_CODE) {
			RzBinAddr *entry = RZ_NEW0(RzBinAddr);
			if (!entry) {
				break;
			}
			rz_pvector_push(ret, entry);

			entry->vaddr = hunk_data->vaddr;
			entry->paddr = hunk_data->paddr;
			entry->hpaddr = hunk_data->paddr;
			entry->type = RZ_BIN_ENTRY_TYPE_PROGRAM;
			break;
		}
	}

	return ret;
}

static RzPVector /*<RzBinSection *>*/ *hunk_sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	rz_return_val_if_fail(ret, NULL);

	ProgramData *program_data = bf->o->bin_obj;

	for (ut32 i = 0; i < program_data->hunks_count; i++) {
		HunkData *hunk_data = (HunkData *)rz_vector_index_ptr(program_data->hunks, i);
		rz_return_val_if_fail(program_data, ret);

		RzBinSection *section = RZ_NEW0(RzBinSection);
		rz_return_val_if_fail(section, ret);
		rz_pvector_push(ret, section);

		section->name = rz_str_newf("hunk_%d_%s", i, hunk_get_name_from_type(hunk_data->type));
		section->paddr = hunk_data->paddr;
		section->vaddr = hunk_data->vaddr;
		section->size = hunk_data->psize;
		section->vsize = hunk_data->vsize;

		if (hunk_data->type == HUNK_CODE) {
			section->perm = RZ_PERM_R | RZ_PERM_X;
			section->is_data = false;
		} else {
			section->perm = RZ_PERM_RW;
			section->is_data = true;
		}

		section->is_segment = false;
		section->bits = 32;
	}
	return ret;
}

static bool hunk_handle_symbols_for_hunk_data(HunkData *hunk_data, RzPVector /*<RzBinSymbol *>*/ *ret) {
	for (ut32 j = 0; j < hunk_data->symbols_count; j++) {
		HunkSymbol *hunk_symbol = (HunkSymbol *)rz_vector_index_ptr(hunk_data->symbols, j);
		if (!hunk_symbol) {
			return false;
		}

		RzBinSymbol *symbol = RZ_NEW0(RzBinSymbol);
		if (!symbol) {
			return false;
		}
		rz_pvector_push(ret, symbol);

		symbol->name = rz_str_dup(hunk_symbol->name);
		symbol->vaddr = hunk_data->vaddr + hunk_symbol->offset;
		symbol->paddr = hunk_data->paddr + hunk_symbol->offset;
		symbol->size = 0;
		symbol->type = hunk_data->type == HUNK_CODE ? rz_str_dup("FUNC") : rz_str_dup("OBJ");
	}
	return true;
}

static RzPVector /*<RzBinSymbol *>*/ *hunk_symbols(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	rz_return_val_if_fail(ret, NULL);

	ProgramData *program_data = bf->o->bin_obj;

	for (ut32 i = 0; i < program_data->hunks_count; i++) {
		HunkData *hunk_data = (HunkData *)rz_vector_index_ptr(program_data->hunks, i);
		rz_return_val_if_fail(hunk_data, ret);
		if (!hunk_data) {
			return ret;
		}
		if (!hunk_handle_symbols_for_hunk_data(hunk_data, ret)) {
			return ret;
		}
	}
	return ret;
}

static RzBinInfo *hunk_info(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);

	RzBinInfo *info = RZ_NEW0(RzBinInfo);
	rz_return_val_if_fail(info, NULL);

	info->file = rz_str_dup(bf->file);
	info->type = rz_str_dup("Amiga Hunk");
	info->os = rz_str_dup("AmigaOS");
	info->arch = rz_str_dup("m68k");
	info->machine = rz_str_dup("68000");
	info->bits = 32;
	info->big_endian = true;
	info->has_va = true;

	return info;
}

static bool hunk_handle_relocs_for_hunk_data(HunkData *hunk_data, RzPVector /*<RzBinReloc *>*/ *ret) {
	for (ut32 j = 0; j < hunk_data->relocs_count; j++) {
		HunkReloc *hunk_reloc = (HunkReloc *)rz_vector_index_ptr(hunk_data->relocs, j);
		if (!hunk_reloc) {
			return false;
		}

		RzBinReloc *reloc = RZ_NEW0(RzBinReloc);
		if (!reloc) {
			return false;
		}
		rz_pvector_push(ret, reloc);

		reloc->vaddr = hunk_data->vaddr + hunk_reloc->offset;
		reloc->paddr = hunk_data->paddr + hunk_reloc->offset;
		reloc->type = 32;
		reloc->additive = hunk_reloc->target_hunk_index;
	}
	return true;
}

static RzPVector /*<RzBinReloc *>*/ *hunk_relocs(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_reloc_free);
	rz_return_val_if_fail(ret, NULL);

	ProgramData *program_data = bf->o->bin_obj;

	for (ut32 i = 0; i < program_data->hunks_count; i++) {
		HunkData *hunk_data = (HunkData *)rz_vector_index_ptr(program_data->hunks, i);
		if (!hunk_data) {
			return ret;
		}
		if (!hunk_handle_relocs_for_hunk_data(hunk_data, ret)) {
			return ret;
		}
	}
	return ret;
}

RzBinPlugin rz_bin_plugin_hunk = {
	.name = "hunk",
	.desc = "Amiga Hunk file format",
	.author = "Stefan Bisti",
	.license = "LGPL3",
	.load_buffer = &hunk_load_buffer,
	.destroy = &hunk_destroy,
	.check_buffer = &hunk_check_buffer,
	.maps = &hunk_maps,
	.entries = &hunk_entries,
	.sections = &hunk_sections,
	.symbols = &hunk_symbols,
	.info = &hunk_info,
	.relocs = &hunk_relocs,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_hunk,
	.version = RZ_VERSION
};
#endif
