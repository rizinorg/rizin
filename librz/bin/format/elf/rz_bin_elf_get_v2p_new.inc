// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static bool is_in_vphdr(Elf_(Phdr) * p, ut64 addr) {
	return addr >= p->p_vaddr && addr < p->p_vaddr + p->p_filesz;
}

/* Deprecated temporarily. Use rz_bin_elf_v2p_new in new code for now. */
ut64 Elf_(rz_bin_elf_v2p)(RZ_NONNULL ELFOBJ *bin, ut64 vaddr) {
	rz_return_val_if_fail(bin, 0);
	if (!bin->phdr) {
		if (Elf_(rz_bin_elf_is_relocatable)(bin)) {
			return vaddr - bin->baddr;
		}
		return vaddr;
	}

	size_t i;
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		Elf_(Phdr) *p = &bin->phdr[i];
		if (p->p_type == PT_LOAD && is_in_vphdr(p, vaddr)) {
			if (!p->p_offset && !p->p_vaddr) {
				continue;
			}
			return p->p_offset + vaddr - p->p_vaddr;
		}
	}
	return vaddr;
}

/**
 * \brief Convert a virtual address to the physical address
 * \param elf binary
 * \return virtual addr
 *
 * Converts a virtual address to the relative physical address, looking
 * at the program headers in the binary bin
 */

ut64 Elf_(rz_bin_elf_v2p_new)(RZ_NONNULL ELFOBJ *bin, ut64 vaddr) {
	rz_return_val_if_fail(bin, UT64_MAX);

	if (!bin->phdr) {
		if (Elf_(rz_bin_elf_is_relocatable)(bin)) {
			return vaddr - bin->baddr;
		}

		return UT64_MAX;
	}

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		Elf_(Phdr) *segment = &bin->phdr[i];

		if (segment->p_type == PT_LOAD && is_in_vphdr(segment, vaddr)) {
			return segment->p_offset + vaddr - segment->p_vaddr;
		}
	}

	return UT64_MAX;
}
