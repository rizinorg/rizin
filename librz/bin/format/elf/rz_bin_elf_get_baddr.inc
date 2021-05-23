// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Compute the base address of the binary
 * \param elf binary
 * \return the base address
 *
 * To compute the base address, one determines the memory
 * address associated with the lowest p_vaddr value for a
 * PT_LOAD segment. One then obtains the base address by
 * truncating the memory address to the nearest multiple
 * of the maximum page size
 */
ut64 Elf_(rz_bin_elf_get_baddr)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	ut64 tmp, base = UT64_MAX;
	if (bin->phdr) {
		size_t i;
		for (i = 0; i < bin->ehdr.e_phnum; i++) {
			if (bin->phdr[i].p_type == PT_LOAD) {
				tmp = (ut64)bin->phdr[i].p_vaddr & ELF_PAGE_MASK;
				tmp = tmp - (tmp % (1 << ELF_PAGE_SIZE));
				if (tmp < base) {
					base = tmp;
				}
			}
		}
	}
	if (base == UT64_MAX && Elf_(rz_bin_elf_is_relocatable)(bin)) {
		//we return our own base address for ET_REL type
		//we act as a loader for ELF
		return 0x08000000;
	}
	return base == UT64_MAX ? 0 : base;
}
