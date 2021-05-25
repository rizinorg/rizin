// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

struct class_translation {
	unsigned char class;
	const char *name;
};

static const struct class_translation class_translation_table[] = {
	{ ELFCLASSNONE, "none" },
	{ ELFCLASS32, "ELF32" },
	{ ELFCLASS64, "ELF64" }
};

/**
 * \brief Return a string representing the elf class
 * \param elf binary
 * \return allocated string
 *
 * Check the elf header (e_ident) to deduce the elf class
 */
RZ_OWN char *Elf_(rz_bin_elf_get_elf_class)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	for (size_t i = 0; i < RZ_ARRAY_SIZE(class_translation_table); i++) {
		if (bin->ehdr.e_ident[EI_CLASS] == class_translation_table[i].class) {
			return strdup(class_translation_table[i].name);
		}
	}

	return rz_str_newf("<unknown: %x>", bin->ehdr.e_ident[EI_CLASS]);
}
