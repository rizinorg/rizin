// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Get the entry offset
 * \param elf binary
 * \return the entry offset
 *
 * Get the entry offset from the elf header (e_entry), and if the information
 * isn't defined section header will be used.
 */
ut64 Elf_(rz_bin_elf_get_entry_offset)(ELFOBJ *bin) {
	rz_return_val_if_fail(bin, UT64_MAX);
	ut64 entry = bin->ehdr.e_entry;
	if (!entry) {
		if (!Elf_(rz_bin_elf_is_executable)(bin)) {
			return UT64_MAX;
		}
		entry = Elf_(rz_bin_elf_get_section_offset)(bin, ".init.text");
		if (entry != UT64_MAX) {
			return entry;
		}
		entry = Elf_(rz_bin_elf_get_section_offset)(bin, ".text");
		if (entry != UT64_MAX) {
			return entry;
		}
		return Elf_(rz_bin_elf_get_section_offset)(bin, ".init");
	}
	return Elf_(rz_bin_elf_v2p)(bin, entry);
}
