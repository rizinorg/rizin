// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"
#include "elf/glibc_elf.h"
#include "rz_util/rz_assert.h"

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
	if (!layout) {
		return UT64_MAX;
	}

	RzVector *notes;
	rz_bin_elf_foreach_notes_segment(bin, notes) {
		RzBinElfNote *tmp;
		rz_vector_foreach (notes, tmp) {
			const ut8 *buf;
			size_t size;
			switch (tmp->type) {
			default:
				continue;
			case NT_PRSTATUS:
			case NT_OPENBSD_REGS: {
				RzBinElfNotePrStatus *note = &tmp->prstatus;
				if (layout->sp_offset + layout->sp_size / 8 > note->regstate_size) {
					rz_warn_if_reached();
					return UT64_MAX;
				}
				buf = note->regstate + layout->sp_offset;
				size = layout->sp_size;
				break;
			}
			}
			return rz_read_ble(buf, bin->big_endian, size);
		}
	}

	return UT64_MAX;
}
