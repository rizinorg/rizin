// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_INTEGER_REG_NAMES_H
#define RISCV_IL_INTEGER_REG_NAMES_H

#include <capstone/riscv.h>
#include <stdint.h>

static const char *riscv_integer_reg_names[] = {
	/* x0  */ "zero",
	/* x1  */ "ra",
	/* x2  */ "sp",
	/* x3  */ "gp",
	/* x4  */ "tp",
	/* x5  */ "t0",
	/* x6  */ "t1",
	/* x7  */ "t2",
	/* x8  */ "s0",
	/* x9  */ "s1",
	/* x10 */ "a0",
	/* x11 */ "a1",
	/* x12 */ "a2",
	/* x13 */ "a3",
	/* x14 */ "a4",
	/* x15 */ "a5",
	/* x16 */ "a6",
	/* x17 */ "a7",
	/* x18 */ "s2",
	/* x19 */ "s3",
	/* x20 */ "s4",
	/* x21 */ "s5",
	/* x22 */ "s6",
	/* x23 */ "s7",
	/* x24 */ "s8",
	/* x25 */ "s9",
	/* x26 */ "s10",
	/* x27 */ "s11",
	/* x28 */ "t3",
	/* x29 */ "t4",
	/* x30 */ "t5",
	/* x31 */ "t6",
};

static inline const char *riscv_integer_reg_name(uint32_t reg) {
	int idx = (int)reg - RISCV_REG_X0;
	if (idx < 0 || idx >= 32) {
		return "";
	}
	return riscv_integer_reg_names[idx];
}

#endif // RISCV_IL_INTEGER_REG_NAMES_H
