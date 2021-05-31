// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Get the stack pointer value
 * \param elf binary
 * \return allocated string
 *
 * Get the value of the stack pointer register in a core file from NT_PRSTATUS
 */
ut64 Elf_(rz_bin_elf_get_sp_val)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, UT64_MAX);

	RzBinElfPrStatusLayout *layout = Elf_(rz_bin_elf_get_prstatus_layout)(bin);
	RzBinElfNotePrStatus *prs = Elf_(rz_bin_elf_get_prstatus)(bin);

	if (!layout || !prs) {
		return UT64_MAX;
	}

	if (layout->sp_offset + layout->sp_size / 8 > prs->regstate_size || !prs->regstate) {
		return UT64_MAX;
	}

	return rz_read_ble(prs->regstate + layout->sp_offset, bin->endian, layout->sp_size);
}
