// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static ut64 compute_boffset_from_phdr(ELFOBJ *bin) {
	ut64 base = UT64_MAX;

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_LOAD) {
			base = RZ_MIN(base, bin->phdr[i].p_offset);
		}
	}

	return base == UT64_MAX ? 0 : base;
}

/**
 * \brief Compute the base offset of the binary
 * \param elf binary
 * \return the base offset
 *
 * To compute the base address, one determines the memory
 * address associated with the lowest p_offset value for a
 * PT_LOAD segment.
 */
ut64 Elf_(rz_bin_elf_get_boffset)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	if (bin->phdr) {
		return compute_boffset_from_phdr(bin);
	}

	return 0;
}
