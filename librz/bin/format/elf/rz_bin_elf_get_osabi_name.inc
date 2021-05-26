// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

struct section_note_osabi_translation {
	const char *note_name;
	const char *os_name;
};

static const struct section_note_osabi_translation section_note_osabi_translation_table[] = {
	{ ".note.openbsd.ident", "openbsd" },
	{ ".note.minix.ident", "minix" },
	{ ".note.netbsd.ident", "netbsd" },
	{ ".note.android.ident", "android" }
};

static bool is_valid_section_note(ELFOBJ *bin, Elf_(Shdr) * section) {
	return section->sh_type == SHT_NOTE && section->sh_name < bin->shstrtab_size;
}

static char *get_osabi_name_from_section_note(ELFOBJ *bin, Elf_(Shdr) * section) {
	if (!is_valid_section_note(bin, section)) {
		return NULL;
	}

	const char *section_name = bin->shstrtab + section->sh_name;
	for (size_t i = 0; i < RZ_ARRAY_SIZE(section_note_osabi_translation_table); i++) {
		if (!strcmp(section_name, section_note_osabi_translation_table[i].note_name)) {
			return strdup(section_note_osabi_translation_table[i].os_name);
		}
	}

	return NULL;
}

static char *get_osabi_name_from_shdr(ELFOBJ *bin) {
	if (!bin->shdr || !bin->shstrtab) {
		return NULL;
	}

	for (size_t i = 0; i < bin->ehdr.e_shnum; i++) {
		char *tmp = get_osabi_name_from_section_note(bin, bin->shdr + i);
		if (tmp) {
			return tmp;
		}
	}

	return NULL;
}

static char *get_osabi_name_from_ehdr(ELFOBJ *bin) {
	switch (bin->ehdr.e_ident[EI_OSABI]) {
	case ELFOSABI_LINUX:
		return strdup("linux");
	case ELFOSABI_SOLARIS:
		return strdup("solaris");
	case ELFOSABI_FREEBSD:
		return strdup("freebsd");
	case ELFOSABI_HPUX:
		return strdup("hpux");
	}

	return NULL;
}

/**
 * \brief Return the os application binary interface name
 * \param elf binary
 * \return an allocated string
 *
 * Check the ehdr or the shdr to get the os name
 */
RZ_OWN char *Elf_(rz_bin_elf_get_osabi_name)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	char *name = get_osabi_name_from_ehdr(bin);
	if (name) {
		return name;
	}

	name = get_osabi_name_from_shdr(bin);
	if (name) {
		return name;
	}

	return strdup("linux");
}
