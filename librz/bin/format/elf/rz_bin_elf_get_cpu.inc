// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Return a string representing the cpu
 * \param elf type
 * \return allocated string
 *
 * Only work on mips right now. Use the elf header to deduce the cpu
 */
RZ_OWN char *Elf_(rz_bin_elf_get_cpu)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (bin->phdr && bin->ehdr.e_machine == EM_MIPS) {
		const ut32 mipsType = bin->ehdr.e_flags & EF_MIPS_ARCH;
		switch (mipsType) {
		case EF_MIPS_ARCH_1: return strdup("mips1");
		case EF_MIPS_ARCH_2: return strdup("mips2");
		case EF_MIPS_ARCH_3: return strdup("mips3");
		case EF_MIPS_ARCH_4: return strdup("mips4");
		case EF_MIPS_ARCH_5: return strdup("mips5");
		case EF_MIPS_ARCH_32: return strdup("mips32");
		case EF_MIPS_ARCH_64: return strdup("mips64");
		case EF_MIPS_ARCH_32R2: return strdup("mips32r2");
		case EF_MIPS_ARCH_64R2: return strdup("mips64r2");
		default: return strdup(" Unknown mips ISA");
		}
	}
	return NULL;
}
