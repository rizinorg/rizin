// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "sh_il.h"
#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * \file sh_il.c
 *
 * Converts SuperH-4 instructions to RzIL statements
 * References:
 *  - https://www.st.com/resource/en/user_manual/cd00147165-sh-4-32-bit-cpu-core-architecture-stmicroelectronics.pdf (SH-4 32-bit architecture manual)
 */

#define SH_REG_SIZE   32
#define SH_ADDR_SIZE  32
#define SH_INSTR_SIZE 16

#define SH_ADDR(x)         UNSIGNED(SH_ADDR_SIZE, x)
#define SH_PC(x)           UN(SH_ADDR_SIZE, x)
#define SH_IMM(imm)        UN(SH_REG_SIZE, (imm))
#define SH_REG(reg)        VARG(sh_registers[reg])
#define SH_REG_SET(reg, x) SETG(sh_registers[reg], x)
#define SH_ONE()           UN(SH_REG_SIZE, 1)
#define SH_ZERO()          UN(SH_REG_SIZE, 0)

#define sh_return_val_if_invalid_gpr(x, v) \
	if (x >= 16) { \
		RZ_LOG_ERROR("RzIL: SH: invalid register R%u\n", x); \
		return v; \
	}

 /**
 * Registers available as global variables in the IL
 */
static char *sh_global_registers[] = {
	"r0b0", "r1b0", "r2b0", "r3b0", "r4b0", "r5b0", "r6b0", "r7b0", ///< bank 0 registers
	"r0b1", "r1b1", "r2b1", "r3b1", "r4b1", "r5b1", "r6b1", "r7b1", ///< bank 1 registers
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "pc",
	"sr", "gbr", "ssr", "spc", "sgr", "dbr", "vbr", "mach", "macl",
	"pr", "fpul", "pc", "fpscr",
	"fr0", "fr1", "fr2", "fr3", "fr4", "fr5", "fr6", "fr7",
	"fr8", "fr9", "fr10", "fr11", "fr12", "fr13", "fr14", "fr15",
	"xf0", "xf1", "xf2", "xf3", "xf4", "xf5", "xf6", "xf7",
	"xf8", "xf9", "xf10", "xf11", "xf12", "xf13", "xf14", "xf15"
};

/**
 * All registers
 */
static char *sh_registers[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "pc",
	"sr", "gbr", "ssr", "spc", "sgr", "dbr", "vbr", "mach", "macl",
	"pr", "fpul", "pc", "fpscr",
	"fr0", "fr1", "fr2", "fr3", "fr4", "fr5", "fr6", "fr7",
	"fr8", "fr9", "fr10", "fr11", "fr12", "fr13", "fr14", "fr15",
	"xf0", "xf1", "xf2", "xf3", "xf4", "xf5", "xf6", "xf7",
	"xf8", "xf9", "xf10", "xf11", "xf12", "xf13", "xf14", "xf15"
};

/* Utilities */

static inline RzILOpEffect *sh_il_assign_imm(const char *reg, ut16 imm) {
	RzILOpBitVector *_bv = UN(SH_REG_SIZE, imm);
	return SETG(reg, _bv);
}

/* Instruction implementations */

/**
 * Unknown instruction
 */
static RzILOpEffect *sh_il_unk(SHOp *op, SHOp *next_op, ut64 pc, RzAnalysis *analysis) {
	return NULL; // rz_il_op_new_nop();
}

/**
 * MOV	#imm, Rn
 * imm -> sign extension -> Rn
 * 1110nnnniiiiiiii
 */
static RzILOpEffect *sh_il_mov(SHOp *op, SHOp *next_op, ut64 pc, RzAnalysis *analysis) {
	ut16 reg = op->param[1];
	sh_return_val_if_invalid_gpr(reg, NULL);

	return sh_il_assign_imm(sh_registers[reg], op->param[0]);
}

#include <rz_il/rz_il_opbuilder_end.h>

typedef RzILOpEffect *(*sh_il_op)(SHOp *aop, SHOp *next_op, ut64 pc, RzAnalysis *analysis);

static sh_il_op sh_ops[SH_OP_SIZE] = {
	sh_il_unk,
	sh_il_mov
};
