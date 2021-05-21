// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Return the section with the specified name
 * \param elf binary
 * \param section name
 * \return a ptr to the section with the specified name
 *
 * Search a specific section in the g_sections structure
 */
RZ_BORROW RzBinElfSection *Elf_(rz_bin_elf_get_section)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL const char *section_name) {
	rz_return_val_if_fail(bin && section_name, NULL);

	if (bin->g_sections) {
		size_t i;
		for (i = 0; !bin->g_sections[i].last; i++) {
			if (!strncmp(bin->g_sections[i].name, section_name, ELF_STRING_LENGTH - 1)) {
				return &bin->g_sections[i];
			}
		}
	}

	return NULL;
}
