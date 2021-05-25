// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Get the elf binary architecture
 * \param elf binary
 * \return an allocated string
 *
 * With the elf header (e_machine) deduce the elf architecture
 */
RZ_OWN char *Elf_(rz_bin_elf_get_arch)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	switch (bin->ehdr.e_machine) {
	case EM_ARC:
	case EM_ARC_A5:
		return strdup("arc");
	case EM_AVR: return strdup("avr");
	case EM_BA2_NON_STANDARD:
	case EM_BA2: return strdup("ba2");
	case EM_CRIS: return strdup("cris");
	case EM_68K: return strdup("m68k");
	case EM_MIPS:
	case EM_MIPS_RS3_LE:
	case EM_MIPS_X:
		return strdup("mips");
	case EM_MCST_ELBRUS:
		return strdup("elbrus");
	case EM_TRICORE:
		return strdup("tricore");
	case EM_RCE:
		return strdup("mcore");
	case EM_ARM:
	case EM_AARCH64:
		return strdup("arm");
	case EM_QDSP6: // EM_HEXAGON
		return strdup("hexagon");
	case EM_BLACKFIN:
		return strdup("blackfin");
	case EM_SPARC:
	case EM_SPARC32PLUS:
	case EM_SPARCV9:
		return strdup("sparc");
	case EM_PPC:
	case EM_PPC64:
		return strdup("ppc");
	case EM_PARISC:
		return strdup("hppa");
	case EM_PROPELLER:
		return strdup("propeller");
	case EM_MICROBLAZE:
		return strdup("microblaze.gnu");
	case EM_RISCV:
		return strdup("riscv");
	case EM_VAX:
		return strdup("vax");
	case EM_XTENSA:
		return strdup("xtensa");
	case EM_LANAI:
		return strdup("lanai");
	case EM_VIDEOCORE3:
	case EM_VIDEOCORE4:
		return strdup("vc4");
	case EM_MSP430:
		return strdup("msp430");
	case EM_SH:
		return strdup("sh");
	case EM_V800:
		return strdup("v850");
	case EM_V850:
		return strdup("v850");
	case EM_IA_64:
		return strdup("ia64");
	case EM_S390:
		return strdup("sysz");
	default: return strdup("x86");
	}
}
