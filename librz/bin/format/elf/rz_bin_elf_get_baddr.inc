// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static ut64 compute_baddr_from_phdr(ELFOBJ *bin) {
	ut64 base = UT64_MAX;

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_LOAD) {
			base = RZ_MIN(base, bin->phdr[i].p_vaddr);
		}
	}

	return base == UT64_MAX ? 0 : base;
}

/**
 * \brief Compute the base address of the binary
 * \param elf binary
 * \return the base address
 *
 * To compute the base address, one determines the memory
 * address associated with the lowest p_vaddr value for a
 * PT_LOAD segment.
 */
ut64 Elf_(rz_bin_elf_get_baddr)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	if (Elf_(rz_bin_elf_is_relocatable)(bin)) {
		return 0x08000000;
	}

	if (bin->phdr) {
		return compute_baddr_from_phdr(bin);
	}

	return 0;
}
