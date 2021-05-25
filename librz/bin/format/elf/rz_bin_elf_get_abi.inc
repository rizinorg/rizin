// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#define EF_MIPS_ABI_O32 0x00001000 /* O32 ABI.  */
#define EF_MIPS_ABI_O64 0x00002000 /* O32 extended for 64 bit.  */
#define EF_MIPS_ABI     0x0000f000

static bool is_elf_class64(ELFOBJ *bin) {
	return bin->ehdr.e_ident[EI_CLASS] == ELFCLASS64;
}

static bool is_mips_o32(ELFOBJ *bin) {
	if (bin->ehdr.e_ident[EI_CLASS] != ELFCLASS32) {
		return false;
	}

	if ((bin->ehdr.e_flags & EF_MIPS_ABI2) != 0) {
		return false;
	}

	if ((bin->ehdr.e_flags & EF_MIPS_ABI) != 0 && (bin->ehdr.e_flags & EF_MIPS_ABI) != EF_MIPS_ABI_O32) {
		return false;
	}

	return true;
}

static bool is_mips_n32(ELFOBJ *bin) {
	if (bin->ehdr.e_ident[EI_CLASS] != ELFCLASS32) {
		return false;
	}

	if ((bin->ehdr.e_flags & EF_MIPS_ABI2) == 0 || (bin->ehdr.e_flags & EF_MIPS_ABI) != 0) {
		return false;
	}

	return true;
}

static char *get_abi_mips(ELFOBJ *bin) {
	if (is_elf_class64(bin)) {
		return strdup("n64");
	}

	if (is_mips_n32(bin)) {
		return strdup("n32");
	}

	if (is_mips_o32(bin)) {
		return strdup("o32");
	}

	return NULL;
}

/**
 * \brief Return a string representing the application binary interface
 * \param elf type
 * \return allocated string
 *
 * Only work on mips right now. Use the elf header to deduce the application
 * binary interface
 */
RZ_OWN char *Elf_(rz_bin_elf_get_abi)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (bin->ehdr.e_machine == EM_MIPS) {
		return get_abi_mips(bin);
	}

	return NULL;
}
