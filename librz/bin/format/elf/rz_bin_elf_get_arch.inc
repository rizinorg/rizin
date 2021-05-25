// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

struct arch_translation {
	Elf_(Half) arch;
	const char *name;
};

static const struct arch_translation arch_translation_table[] = {
	{ EM_ARC, "arc" },
	{ EM_ARC_A5, "arc" },
	{ EM_AVR, "avr" },
	{ EM_BA2_NON_STANDARD, "ba2" },
	{ EM_BA2, "ba2" },
	{ EM_CRIS, "cris" },
	{ EM_68K, "m68k" },
	{ EM_MIPS, "mips" },
	{ EM_MIPS_RS3_LE, "mips" },
	{ EM_MIPS_X, "mips" },
	{ EM_MCST_ELBRUS, "elbrus" },
	{ EM_TRICORE, "tricore" },
	{ EM_RCE, "mcore" },
	{ EM_ARM, "arm" },
	{ EM_AARCH64, "arm" },
	{ EM_QDSP6, "hexagon" },
	{ EM_BLACKFIN, "blackfin" },
	{ EM_SPARC, "sparc" },
	{ EM_SPARC32PLUS, "sparc" },
	{ EM_SPARCV9, "sparc" },
	{ EM_PPC, "ppc" },
	{ EM_PPC64, "ppc" },
	{ EM_PARISC, "hppa" },
	{ EM_PROPELLER, "propeller" },
	{ EM_MICROBLAZE, "microblaze.gnu" },
	{ EM_RISCV, "riscv" },
	{ EM_VAX, "vax" },
	{ EM_XTENSA, "xtensa" },
	{ EM_LANAI, "lanai" },
	{ EM_VIDEOCORE3, "vc4" },
	{ EM_VIDEOCORE4, "vc4" },
	{ EM_MSP430, "msp430" },
	{ EM_SH, "sh" },
	{ EM_V800, "v850" },
	{ EM_V850, "v850" },
	{ EM_IA_64, "ia64" },
	{ EM_S390, "sysz" },
};

/**
 * \brief Get the elf binary architecture
 * \param elf binary
 * \return an allocated string
 *
 * With the elf header (e_machine) deduce the elf architecture
 */
RZ_OWN char *Elf_(rz_bin_elf_get_arch)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	for (size_t i = 0; i < RZ_ARRAY_SIZE(arch_translation_table); i++) {
		if (bin->ehdr.e_machine == arch_translation_table[i].arch) {
			return strdup(arch_translation_table[i].name);
		}
	}

	return strdup("x86");
}
