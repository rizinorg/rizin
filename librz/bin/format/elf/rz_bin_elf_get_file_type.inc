// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static bool file_type_is_processor_specific(ELFOBJ *bin) {
	return bin->ehdr.e_type >= ET_LOPROC && bin->ehdr.e_type <= ET_HIPROC;
}

static bool file_type_is_os_specific(ELFOBJ *bin) {
	return bin->ehdr.e_type >= ET_LOOS && bin->ehdr.e_type <= ET_HIOS;
}

static char *get_file_type_basic(RZ_NONNULL ELFOBJ *bin) {
	switch (bin->ehdr.e_type) {
	case ET_NONE:
		return strdup("NONE (None)");
	case ET_REL:
		return strdup("REL (Relocatable file)");
	case ET_EXEC:
		return strdup("EXEC (Executable file)");
	case ET_DYN:
		return strdup("DYN (Shared object file)");
	case ET_CORE:
		return strdup("CORE (Core file)");
	}

	return NULL;
}

/**
 * \brief Return a string representing the file type
 * \param elf binary
 * \return allocated string
 *
 * Use the elf header (e_type) to deduce the file type
 */
RZ_OWN char *Elf_(rz_bin_elf_get_file_type)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	char *result = get_file_type_basic(bin);
	if (result) {
		return result;
	}

	if (file_type_is_processor_specific(bin)) {
		return rz_str_newf("Processor Specific: %x", bin->ehdr.e_type);
	}

	if (file_type_is_os_specific(bin)) {
		return rz_str_newf("OS Specific: %x", bin->ehdr.e_type);
	}

	return rz_str_newf("<unknown>: %x", bin->ehdr.e_type);
}
