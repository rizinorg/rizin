// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_FLOAT_REG_NAMES_H
#define RISCV_IL_FLOAT_REG_NAMES_H

#include <capstone/riscv.h>
#include <stdint.h>

static const char *riscv_freg_names[] = {
	/* f0  */ "ft0",
	/* f1  */ "ft1",
	/* f2  */ "ft2",
	/* f3  */ "ft3",
	/* f4  */ "ft4",
	/* f5  */ "ft5",
	/* f6  */ "ft6",
	/* f7  */ "ft7",
	/* f8  */ "fs0",
	/* f9  */ "fs1",
	/* f10 */ "fa0",
	/* f11 */ "fa1",
	/* f12 */ "fa2",
	/* f13 */ "fa3",
	/* f14 */ "fa4",
	/* f15 */ "fa5",
	/* f16 */ "fa6",
	/* f17 */ "fa7",
	/* f18 */ "fs2",
	/* f19 */ "fs3",
	/* f20 */ "fs4",
	/* f21 */ "fs5",
	/* f22 */ "fs6",
	/* f23 */ "fs7",
	/* f24 */ "fs8",
	/* f25 */ "fs9",
	/* f26 */ "fs10",
	/* f27 */ "fs11",
	/* f28 */ "ft8",
	/* f29 */ "ft9",
	/* f30 */ "ft10",
	/* f31 */ "ft11",
};

// Resolve any RISC-V FP register enum value (F or D variant) to its ABI name.
// RISCV_REG_F0_D = 74, RISCV_REG_F0_F = 106.  Both ranges are 32 wide and
// map physical register index n to riscv_freg_names[n].
static inline const char *riscv_freg_name(uint32_t reg) {
	if (reg >= RISCV_REG_F0_D && reg <= RISCV_REG_F31_D) {
		return riscv_freg_names[reg - RISCV_REG_F0_D];
	}
	if (reg >= RISCV_REG_F0_F && reg <= RISCV_REG_F31_F) {
		return riscv_freg_names[reg - RISCV_REG_F0_F];
	}
	return "<invalid_fp_reg>";
}

#endif // RISCV_IL_FLOAT_REG_NAMES_H
