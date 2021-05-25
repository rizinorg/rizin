// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

struct cpu_mips_translation {
	Elf_(Word) arch;
	const char *name;
};

static const struct cpu_mips_translation cpu_mips_translation_table[] = {
	{ EF_MIPS_ARCH_1, "mips1" },
	{ EF_MIPS_ARCH_2, "mips2" },
	{ EF_MIPS_ARCH_3, "mips3" },
	{ EF_MIPS_ARCH_4, "mips4" },
	{ EF_MIPS_ARCH_5, "mips5" },
	{ EF_MIPS_ARCH_32, "mips32" },
	{ EF_MIPS_ARCH_64, "mips64" },
	{ EF_MIPS_ARCH_32R2, "mips32r2" },
	{ EF_MIPS_ARCH_64R2, "mips64r2" },
};

static char *get_cpu_mips(ELFOBJ *bin) {
	Elf_(Word) mips_arch = bin->ehdr.e_flags & EF_MIPS_ARCH;

	for (size_t i = 0; i < RZ_ARRAY_SIZE(cpu_mips_translation_table); i++) {
		if (mips_arch == cpu_mips_translation_table[i].arch) {
			return strdup(cpu_mips_translation_table[i].name);
		}
	}

	return strdup(" Unknown mips ISA");
}

/**
 * \brief Return a string representing the cpu
 * \param elf type
 * \return allocated string
 *
 * Only work on mips right now. Use the elf header to deduce the cpu
 */
RZ_OWN char *Elf_(rz_bin_elf_get_cpu)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!bin->phdr) {
		return NULL;
	}

	if (bin->ehdr.e_machine == EM_MIPS) {
		return get_cpu_mips(bin);
	}

	return NULL;
}
