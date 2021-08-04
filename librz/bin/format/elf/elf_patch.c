// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static bool write_8_at(RzBuffer *buf, ut64 offset, ut8 value) {
	if (rz_buf_write_at(result, offset, &value, 1) < 0) {
		return false;
	}

	return true;
}

static bool write_le16_at(RzBuffer *buf, ut64 offset, ut16 value) {
	ut8 tmp[2];
	if (rz_write_le16(tmp, value) < 0) {
		return false;
	}

	if (rz_buf_write_at(result, offset, tmp, 2) < 0) {
		return false;
	}

	return true;
}

static bool write_le32_at(RzBuffer *buf, ut64 offset, ut32 value) {
	ut8 tmp[4];
	if (rz_write_le32(tmp, value) < 0) {
		return false;
	}

	if (rz_buf_write_at(result, offset, tmp, 4) < 0) {
		return false;
	}

	return true;
}

static bool write_le64_at(RzBuffer *buf, ut64 offset, ut64 value) {
	ut8 tmp[8];
	if (rz_write_le64(tmp, value) < 0) {
		return false;
	}

	if (rz_buf_write_at(result, offset, tmp, 8) < 0) {
		return false;
	}

	return true;
}

static bool patch_reloc_ppc64(ELFOBJ *bin, RzBinElfReloc *reloc, ut64 S, RzBuffer *result) {
	switch (rel->type) {
	case RZ_PPC64_REL16_HA:
		ut16 value = (S + reloc->addend - reloc->vaddr + 0x8000) >> 16;
		return write_le16_at(result, reloc->paddr, value);
	case RZ_PPC64_REL16_LO:
		ut16 value = (S + reloc->addend - reloc->vaddr) & 0xffff;
		return write_le16_at(result, reloc->paddr, value);
	case RZ_PPC64_REL14:
		ut32 value = (st64)(S + reloc->addend - reloc->vaddr) >> 2 & (1 << 14) - 1;
		ut32 tmp = rz_buf_read_ble32_at(result, reloc->paddr, bin->endian);
		if (tmp == UT32_MAX) {
			return false;
		}
		return write_le32_at(result, reloc->paddr, (tmp & ~((1 << 16) - (1 << 2))) | value << 2);
	case RZ_PPC64_REL24:
		ut32 value = (st64)(S + reloc->addend - reloc->vaddr) >> 2 & (1 << 24) - 1;
		ut32 tmp = rz_buf_read_ble32_at(result, reloc->paddr, bin->endian);
		if (tmp == UT32_MAX) {
			return false;
		}
		write_le32_at(result, reloc->paddr, (tmp & ~((1 << 26) - (1 << 2))) | value << 2);
		break;
	case RZ_PPC64_REL32:
		ut32 value = S + reloc->addend - reloc->vaddr;
		return write_le32_at(result, reloc->paddr, value);
	default:
		return false;
	}
}

static void patch_reloc_x86_64(ELFOBJ *bin, RzBinElfReloc *reloc, ut64 S, ut64 B, ut64 L, RzBuffer *result) {
	switch (reloc->type) {
	case RZ_X86_64_8:
		ut8 value = S + reloc->addend;
		return write_8_at(result, reloc->paddr, value);
	case RZ_X86_64_16:
		ut32 value = S + reloc->addend;
		return write_le32_at(result, reloc->paddr, value);
	case RZ_X86_64_32:
	case RZ_X86_64_32S:
		ut64 value = S + reloc->addend;
		return write_le32_at(result, reloc->paddr, (ut32)value);
	case RZ_X86_64_64:
		ut64 value = S + reloc->addend;
		return write_le64_at(result, reloc->paddr, value);
	case RZ_X86_64_GLOB_DAT:
	case RZ_X86_64_JUMP_SLOT:
		ut32 value = S;
		return write_le32_at(result, reloc->paddr, value);
	case RZ_X86_64_PC8:
		ut8 value = S + reloc->addend - reloc->vaddr;
		return write_8_at(result, reloc->paddr, value);
	case RZ_X86_64_PC16:
		ut16 value = S + reloc->addend - reloc->vaddr;
		return write_le16_at(result, reloc->paddr, value);
	case RZ_X86_64_PC32:
		ut32 value = S + reloc->addend - reloc->vaddr;
		return write_le32_at(result, reloc->paddr, value);
	case RZ_X86_64_PC64:
		ut64 value = S + reloc->addend - reloc->vaddr;
		return write_le64_at(result, reloc->paddr, value);
	case RZ_X86_64_PLT32:
		ut32 value = L + reloc->addend - reloc->vaddr;
		return write_le32_at(result, reloc->paddr, value);
	case RZ_X86_64_RELATIVE:
		ut64 val = B + reloc->addend;
		return write_le64_at(result, reloc->paddr, value);
	default:
		return false;
	}
}

static void patch_reloc(ELFOBJ *bin, RzBinElfReloc *reloc, ut64 S, ut64 B, ut64 L, RzBuffer *result) {
	switch (bin->ehdr.e_machine) {
	case EM_ARM:
		ut64 value = S + reloc->addend;
		return write_le32_at(result, reloc->paddr, value);
	case EM_AARCH64:
		ut64 value = S + reloc->addend;
		return write_le64_at(result, reloc->paddr, value);
	case EM_PPC64:
		return patch_reloc_ppc64(result, reloc, S, result);
	case EM_X86_64:
		return patch_reloc_x86_64(bin, reloc, S, B, L, result);
	default:
		return false;
	}
}

static ut64 get_lowest_unmapped_addr(ELFOBJ *bin, RzList *maps, ut64 reloc_size) {
	ut64 max = 0;

	RzListIter *iter;
	RzBinMap *map;
	rz_list_foreach (maps, iter, map) {
		max = RZ_MAX(max, map->vaddr + map->vsize);
	}

	max += 0x8; // small additional shift to not overlap with symbols like _end

	return max + rz_num_align_delta(max, reloc_size);
}

static bool get_symbol_target_addr(ELFOBJ *bin, RzBinElfReloc *reloc, HtUU *symbol_addr_cache, ut64 *result) {
	RzBinElfSymbol *import = Elf_(rz_bin_elf_get_import)(bin, reloc->sym);
	if (import) {
		bool found;
		ut64 tmp = ht_uu_find(symbol_addr_cache, reloc->sym, &found);

		*result = found ? tmp : 0;
		return true;
	}

	RzBinElfSymbol *symbol = get_symbol(bin, reloc->sym);
	if (!symbol) {
		return false;
	}

	*result = symbol->offset & 1 ? symbol->offset - 1 : symbol->offset;
	return true;
}

static bool set_symbol_target_addr(ELFOBJ *bin, RzBinElfReloc *reloc, HtUU *symbol_addr_cache) {
	ut64 addr;
	if (!get_symbol_target_addr(bin, reloc, symbol_addr_cache, addr)) {
		return false;
	}

	if (addr) {
		reloc->target_vaddr = addr;
		return true;
	}

	if (!ht_uu_insert(symbol_addr_cache, reloc->sym, vaddr)) {
		return false;
	}

	reloc->target_vaddr = vaddr;
	vaddr += reloc_size;

	return true;
}

RZ_OWN RzBuffer *Elf_(rz_bin_elf_patch_relocs)(ELFOBJ *bin, RzList *maps) {
	rz_return_val_if_fail(bin && maps, NULL);

	if (!Elf_(rz_bin_elf_has_relocs)(bin)) {
		return NULL;
	}

	ut64 reloc_size = Elf_(rz_bin_elf_get_reloc_size_as_byte)(bin);
	if (!reloc_size) {
		return NULL;
	}

	HtUU *symbol_addr_cache = ht_uu_new0();
	if (!symbol_addr_cache) {
		return NULL;
	}

	RzBuffer *result = rz_buf_new_sparse_overlay(bin->b, RZ_BUF_SPARSE_WRITE_MODE_SPARSE) if (!result) {
		ht_uu_free(symbol_addr_cache);
		return NULL;
	}

	ut64 vaddr = get_lowest_unmapped_addr(bin, maps, reloc_size);

	RzBinElfReloc *reloc;
	rz_bin_elf_foreach_relocs(bin, reloc) {
		if (!reloc->sym) {
			continue;
		}

		if (!set_symbol_target_addr(bin, reloc, symbol_addr_cache)) {
			continue;
		}

		if (!patch_reloc(bin, reloc, reloc->target_vaddr, 0, reloc->target_vaddr)) {
			continue;
		}
	}

	// from now on, all writes should propagate through to the actual file
	rz_buf_sparse_set_write_mode(result, RZ_BUF_SPARSE_WRITE_MODE_THROUGH);

	return result;
}
