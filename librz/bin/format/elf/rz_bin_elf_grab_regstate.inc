// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Return register state
 * \param elf type
 * \return a borrowed array of ut8
 *
 * ...
 */
RZ_BORROW const ut8 *Elf_(rz_bin_elf_grab_regstate)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL size_t *size) {
	rz_return_val_if_fail(bin && size, NULL);

	RzBinElfNotePrStatus *pr_status = Elf_(rz_bin_elf_get_prstatus)(bin);
	if (!pr_status) {
		return NULL;
	}

	*size = pr_status->regstate_size;
	return pr_status->regstate;
}
