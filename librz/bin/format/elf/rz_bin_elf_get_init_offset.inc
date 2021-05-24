// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Compute the init offset of the binary
 * \param elf binary
 * \return the init offset
 *
 * Get the offset from the vaddr store in the dynamic section (dt_init)
 */
ut64 Elf_(rz_bin_elf_get_init_offset)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	if (!bin->dyn_info.dt_init) {
		return 0;
	}

	return Elf_(rz_bin_elf_v2p)(bin, bin->dyn_info.dt_init);
}
