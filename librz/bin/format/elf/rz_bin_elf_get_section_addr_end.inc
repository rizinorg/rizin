// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Return the section end real virtual address with the specified name
 * \param elf binary
 * \param section name
 * \return section offset
 *
 * Search a specific section in the g_sections structure and return the section end real virtual address
 */
ut64 Elf_(rz_bin_elf_get_section_addr_end)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL const char *section_name) {
	rz_return_val_if_fail(bin && section_name, UT64_MAX);

	RzBinElfSection *section = Elf_(rz_bin_elf_get_section)(bin, section_name);
	return section ? section->rva + section->size : UT64_MAX;
}
