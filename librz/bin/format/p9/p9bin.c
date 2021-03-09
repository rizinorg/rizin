// SPDX-FileCopyrightText: 2011 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "p9bin.h"
#include <rz_asm.h>

int rz_bin_p9_get_arch(RzBuffer *b, int *bits, int *big_endian) {
	st32 a = (st32)rz_buf_read_be32_at(b, 0);
	if (bits) {
		*bits = 32;
	}
	if (big_endian) {
		*big_endian = 0;
	}
	switch (a) {
	case I_MAGIC:
		return RZ_ASM_ARCH_X86;
	case T_MAGIC:
		if (bits) {
			*bits = 64;
		}
		return RZ_ASM_ARCH_PPC;
	case S_MAGIC:
		if (bits) {
			*bits = 64;
		}
		return RZ_ASM_ARCH_X86;
	case K_MAGIC:
		return RZ_ASM_ARCH_SPARC;
	case U_MAGIC:
		if (bits) {
			*bits = 64;
		}
		return RZ_ASM_ARCH_SPARC;
	case V_MAGIC:
	case M_MAGIC:
	case N_MAGIC:
	case P_MAGIC:
		return RZ_ASM_ARCH_MIPS;
	case E_MAGIC:
		return RZ_ASM_ARCH_ARM;
	case Q_MAGIC:
		return RZ_ASM_ARCH_PPC;
		//case A_MAGIC: // 68020
	}
	return 0;
}
