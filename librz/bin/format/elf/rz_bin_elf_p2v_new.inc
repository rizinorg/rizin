// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static bool is_in_pphdr(Elf_(Phdr) * p, ut64 addr) {
	return addr >= p->p_offset && addr < p->p_offset + p->p_filesz;
}

/* Deprecated temporarily. Use rz_bin_elf_p2v_new in new code for now. */
ut64 Elf_(rz_bin_elf_p2v)(RZ_NONNULL ELFOBJ *bin, ut64 paddr) {
	size_t i;

	rz_return_val_if_fail(bin, 0);
	if (!bin->phdr) {
		if (Elf_(rz_bin_elf_is_relocatable)(bin)) {
			return bin->baddr + paddr;
		}
		return paddr;
	}
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		Elf_(Phdr) *p = &bin->phdr[i];
		if (p->p_type == PT_LOAD && is_in_pphdr(p, paddr)) {
			if (!p->p_vaddr && !p->p_offset) {
				continue;
			}
			return p->p_vaddr + paddr - p->p_offset;
		}
	}

	return paddr;
}

/**
 * \brief Convert a physical address to the virtual address
 * \param elf binary
 * \return virtual addr
 *
 * Converts a physical address to the virtual address, looking
 * at the program headers in the binary bin
 */
ut64 Elf_(rz_bin_elf_p2v_new)(RZ_NONNULL ELFOBJ *bin, ut64 paddr) {
	rz_return_val_if_fail(bin, UT64_MAX);

	if (!bin->phdr) {
		if (Elf_(rz_bin_elf_is_relocatable)(bin)) {
			return bin->baddr + paddr;
		}

		return UT64_MAX;
	}

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		Elf_(Phdr) *segment = bin->phdr + i;

		if (segment->p_type == PT_LOAD && is_in_pphdr(segment, paddr)) {
			return segment->p_vaddr + paddr - segment->p_offset;
		}
	}

	return UT64_MAX;
}
