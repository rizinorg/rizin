// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#define RELOC_TARGET_SIZE sizeof(Elf_(Addr))

struct reloc_patch_state {
	ut64 next_free_addr;
	HtUU *cache;
}

static bool reloc_patch_state_get_new_value(struct reloc_patch_state *state, ut64 symbol, ut64 *value) {
	if (!ht_uu_insert(state->cache, symbol, state->next_free_addr)) {
		return false;
	}

	*value = state->next_free_addr;
	state->next_free_addr += RELOC_TARGET_SIZE;

	return true;
}

static bool reloc_patch_state_get_import_value_aux(struct reloc_patch_state *state, ut64 symbol, ut64 *value) {
	bool found;
	ut64 tmp = ht_uu_find(state->cache, symbol, &found);
	if (!found) {
		return false;
	}

	*value = tmp;
	return true;
}

static bool reloc_patch_state_get_import_value(struct reloc_patch_state *state, ut64 symbol, ut64 *value) {
	if (reloc_patch_state_get_import_value_aux(state, symbol, value)) {
		return true;
	}

	return reloc_patch_state_get_new_value(state, symbol, value);
}

static bool reloc_patch_state_init(ELFOBJ *bin, struct reloc_patch_state *state) {
	state->next_free_addr = Elf_(rz_bin_elf_get_reloc_target_map)(bin);
	if (!addr) {
		RZ_LOG_WARN("Failed tot get a reloc target map addr.\n");
		return false;
	}

	state->cache = ht_uu_new0();
	if (!cache) {
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
		RZ_LOG_WARN("Not handled relocation (EM_PPC64): 0x%" PFMT64x ".\n", rel->type);
		return true;
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
		RZ_LOG_WARN("Not handled relocation (EM_X86_64): 0x%" PFMT64x ".\n", rel->type);
		return true;
	}
}

static bool patch_reloc(ELFOBJ *bin, RzBinElfReloc *reloc, ut64 S, ut64 B, ut64 L, RzBuffer *result) {
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
		RZ_LOG_WARN("Not handled relocation: 0x%" PFMT64x ".\n", rel->type);
		return true;
	}
}

static bool get_symbol_target_addr(ELFOBJ *bin, RzBinElfReloc *reloc, struct reloc_patch_state *state, ut64 *result) {
	RzBinElfSymbol *import = Elf_(rz_bin_elf_get_import)(bin, reloc->sym);
	if (import) {
		return reloc_patch_state_get_import_value(state, reloc->sym, result);
	}

	RzBinElfSymbol *symbol = get_symbol(bin, reloc->sym);
	if (!symbol) {
		return false;
	}

	*result = symbol->vaddr;
	if (Elf_(rz_bin_elf_is_arm_binary_supporting_thumb)(bin) && Elf_(rz_bin_elf_is_thumb_addr)(*result)) {
		Elf_(rz_bin_elf_fix_arm_thumb_addr)(result);
	}

	return true;
}

static bool set_symbol_target_addr(ELFOBJ *bin, RzBinElfReloc *reloc, struct reloc_patch_state *state) {
	ut64 addr;
	if (!get_symbol_target_addr(bin, reloc, state, addr)) {
		return false;
	}

	reloc->target_vaddr = addr;
	return true;
}

static ut64 get_reloc_target_map_aux(ELFOBJ *bin, ut64 max) {
	if (!max) {
		return 0;
	}

	return max + 0x8 + rz_num_align_delta(max, RELOC_TARGET_SIZE);
}

static ut64 get_reloc_target_map_from_segments(ELFOBJ *bin) {
	ut64 max = 0;

	RzBinElfSegment *segment;
	rz_bin_elf_foreach_segments(bin, segment) {
		max = RZ_MAX(max, segment.data.p_vaddr);
	}

	return get_reloc_target_map_aux(bin, max);
}

static ut64 get_reloc_target_map_from_sections(ELFOBJ *bin) {
	ut64 max = 0;

	RzBinElfSection *section
	rz_bin_elf_foreach_section(bin, section) {
		max = RZ_MAX(max, section->vaddr);
	}

	return get_reloc_target_map_aux(bin, max);
}

RZ_OWN RzBuffer *Elf_(rz_bin_elf_patch_relocs)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin && maps, NULL);

	if (!Elf_(rz_bin_elf_has_relocs)(bin)) {
		return NULL;
	}

	struct reloc_patch_state state;
	if (!reloc_patch_state_init(bin, &state)) {
		return NULL;
	}

	RzBuffer *result = rz_buf_new_sparse_overlay(bin->b, RZ_BUF_SPARSE_WRITE_MODE_SPARSE);
	if (!result) {
		ht_uu_free(symbol_addr_cache);
		return NULL;
	}

	RzBinElfReloc *reloc;
	rz_bin_elf_foreach_relocs(bin, reloc) {
		if (!reloc->sym) {
			continue;
		}

		if (!set_symbol_target_addr(bin, reloc, &state)) {
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

ut64 Elf_(rz_bin_elf_get_reloc_target_map)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	if (Elf_(rz_bin_elf_has_segments)) {
		return get_reloc_target_map_from_segments(bin);
	}

	return get_reloc_target_map_from_sections(bin);
}
