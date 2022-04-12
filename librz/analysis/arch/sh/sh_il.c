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
 *  - https://www.renesas.com/in/en/document/mas/sh-4-software-manual?language=en (SH-4 manual by Renesas)
 *
 * Both the above references are almost the same
 */

#define SH_REG_SIZE         32
#define SH_ADDR_SIZE        32
#define SH_INSTR_SIZE       16
#define SH_GPR_COUNT        16
#define SH_BANKED_REG_COUNT 8
#define BITS_PER_BYTE       8

#define SH_U_ADDR(x) UN(SH_ADDR_SIZE, x)
#define SH_S_ADDR(x) SN(SH_ADDR_SIZE, x)
#define SH_U_REG(x)  UN(SH_REG_SIZE, (x))
#define SH_S_REG(x)  SN(SH_REG_SIZE, (x))
#define SH_BIT(x)    UN(1, x)

// SR register in SH
// SR = x|D|R|B|xxxxxxxxxxxx|F|xxxxx|M|Q|IIII|xx|S|T
// x are the reserved bits
#define SH_SR_T_BIT 1u << 0
#define SH_SR_T     "sr_t" ///< SR.T: True/False condition or carry/borrow bit
#define SH_SR_S_BIT 1u << 1
#define SH_SR_S     "sr_s" ///< SR.S: Specifies a saturation operation for a MAC instruction
#define SH_SR_Q_BIT 1u << 8
#define SH_SR_Q     "sr_q" ///< SR.Q: State for divide step (Used by the DIV0S, DIV0U and DIV1 instructions)
#define SH_SR_M_BIT 1u << 9
#define SH_SR_M     "sr_m" ///< SR.M: State for divide step (Used by the DIV0S, DIV0U and DIV1 instructions)
#define SH_SR_F_BIT 1u << 15
#define SH_SR_F     "sr_f" ///< SR.FD: FPU disable bit (cleared to 0 by a reset)
#define SH_SR_B_BIT 1u << 28
#define SH_SR_B     "sr_b" ///< SR.BL: Exception/interrupt block bit (set to 1 by a reset, exception, or interrupt)
#define SH_SR_R_BIT 1u << 29
#define SH_SR_R     "sr_r" ///< SR.RB: General register bank specifier in privileged mode (set to 1 by a reset, exception or interrupt)
#define SH_SR_D_BIT 1u << 30
#define SH_SR_D     "sr_d" ///< SR.MD: Processor mode

#define sh_return_val_if_invalid_gpr(x, v) \
	if (x >= SH_GPR_COUNT) { \
		RZ_LOG_ERROR("RzIL: SH: invalid register R%u\n", x); \
		return v; \
	}

#define sh_il_get_pure_param(x) \
	sh_il_get_param(op->param[x], op->scaling).pure

#define sh_il_set_pure_param(x, val) \
	sh_il_set_param(op->param[x], val, op->scaling)

/**
 * Registers available as global variables in the IL
 */
static const char *sh_global_registers[] = {
	"r0b0", "r1b0", "r2b0", "r3b0", "r4b0", "r5b0", "r6b0", "r7b0", ///< bank 0 registers
	"r0b1", "r1b1", "r2b1", "r3b1", "r4b1", "r5b1", "r6b1", "r7b1", ///< bank 1 registers
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "pc",
	"sr", "gbr", "ssr", "spc", "sgr", "dbr", "vbr", "mach", "macl",
	"pr", "fpul", "fpscr",
	"fr0", "fr1", "fr2", "fr3", "fr4", "fr5", "fr6", "fr7",
	"fr8", "fr9", "fr10", "fr11", "fr12", "fr13", "fr14", "fr15",
	"xf0", "xf1", "xf2", "xf3", "xf4", "xf5", "xf6", "xf7",
	"xf8", "xf9", "xf10", "xf11", "xf12", "xf13", "xf14", "xf15"
};

/**
 * All registers
 */
static const char *sh_registers[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "pc",
	"sr", "gbr", "ssr", "spc", "sgr", "dbr", "vbr", "mach", "macl",
	"pr", "fpul", "fpscr",
	"fr0", "fr1", "fr2", "fr3", "fr4", "fr5", "fr6", "fr7",
	"fr8", "fr9", "fr10", "fr11", "fr12", "fr13", "fr14", "fr15",
	"xf0", "xf1", "xf2", "xf3", "xf4", "xf5", "xf6", "xf7",
	"xf8", "xf9", "xf10", "xf11", "xf12", "xf13", "xf14", "xf15"
};

/**
 * Status bit registers
 */
static const char *sh_status_bit_registers[] = {
	SH_SR_T, SH_SR_S, SH_SR_Q, SH_SR_M, SH_SR_F, SH_SR_B, SH_SR_R, SH_SR_D
};

/* Utilities */

static inline bool sh_valid_gpr(ut16 reg) {
	return reg < SH_REG_SIZE;
}

static inline bool sh_banked_reg(ut16 reg) {
	return reg < SH_BANKED_REG_COUNT;
}

static const char *sh_get_banked_reg(ut16 reg, ut8 bank) {
	if (!sh_banked_reg(reg) || bank > 1) {
		return NULL;
	}
	return sh_global_registers[reg + bank * SH_BANKED_REG_COUNT];
}

static inline RzILOpPure *sh_il_get_reg(ut16 reg) {
	sh_return_val_if_invalid_gpr(reg, NULL);
	if (!sh_banked_reg(reg)) {
		return VARG(sh_registers[reg]);
	}

	// check if both SR.MD = 1 and SR.RB = 1
	RzILOpPure *condition = AND(VARG(SH_SR_D), VARG(SH_SR_R));
	return ITE(condition, VARG(sh_get_banked_reg(reg, 1)), VARG(sh_get_banked_reg(reg, 0)));
}

static inline RzILOpEffect *sh_il_set_reg(ut16 reg, RzILOpPure *val) {
	sh_return_val_if_invalid_gpr(reg, NULL);
	if (!sh_banked_reg(reg)) {
		return SETG(sh_registers[reg], val);
	}

	RzILOpPure *condition = AND(VARG(SH_SR_D), VARG(SH_SR_R));
	return BRANCH(condition, SETG(sh_get_banked_reg(reg, 1), val), SETG(sh_get_banked_reg(reg, 0), val));
}

typedef struct sh_param_helper_t {
	RzILOpEffect *pre;
	RzILOpPure *pure;
	RzILOpEffect *post;
} SHParamHelper;

static inline RzILOpPure *sh_il_get_effective_addr(SHParam param, SHScaling scaling) {
	switch (param.mode) {
	case SH_REG_INDIRECT:
	case SH_REG_INDIRECT_I:
	case SH_REG_INDIRECT_D:
		return sh_il_get_reg(param.param[0]);
	case SH_REG_INDIRECT_DISP:
		return ADD(sh_il_get_reg(param.param[0]), MUL(SH_U_ADDR(param.param[1]), SH_U_ADDR(sh_scaling_size[scaling])));
	case SH_REG_INDIRECT_INDEXED:
		return ADD(sh_il_get_reg(param.param[0]), sh_il_get_reg(param.param[1]));
	case SH_GBR_INDIRECT_DISP:
		return ADD(VARG("gbr"), MUL(SH_U_ADDR(param.param[0]), SH_U_ADDR(sh_scaling_size[scaling])));
	case SH_GBR_INDIRECT_INDEXED:
		return ADD(VARG("gbr"), sh_il_get_reg(param.param[0]));
	case SH_PC_RELATIVE_DISP: {
		RzILOpBitVector *pc = VARG("pc");
		// mask lower 2 bits if sh_scaling_size[scaling] == 4
		pc = ITE(EQ(SH_U_ADDR(sh_scaling_size[scaling]), SH_U_ADDR(4)), LOGAND(pc, SH_U_ADDR(0xfffffffc)), pc);
		pc = ADD(pc, SH_U_ADDR(4));
		return ADD(pc, MUL(SH_U_ADDR(param.param[0]), SH_U_ADDR(sh_scaling_size[scaling])));
	}
	case SH_PC_RELATIVE: {
		RzILOpBitVector *relative = MUL(SH_S_ADDR(param.param[0]), SH_S_ADDR(2)); // sign-extended
		return ADD(ADD(VARG("pc"), SH_U_ADDR(4)), relative);
	}
	case SH_PC_RELATIVE_REG:
		return ADD(ADD(VARG("pc"), SH_U_ADDR(4)), sh_il_get_reg(param.param[0]));
	default:
		RZ_LOG_WARN("RzIL: SH: No effective address for this mode: %u", param.mode);
	}

	return NULL;
}

static inline SHParamHelper sh_il_get_param(SHParam param, SHScaling scaling) {
	SHParamHelper ret = {
		.pre = NULL,
		.pure = NULL,
		.post = NULL
	};
	switch (param.mode) {
	case SH_REG_DIRECT:
		ret.pure = sh_il_get_reg(param.param[0]);
		break;
	case SH_REG_INDIRECT:
		ret.pure = sh_il_get_effective_addr(param, sh_scaling_size[scaling]);
		break;
	case SH_REG_INDIRECT_I:
		ret.pure = sh_il_get_effective_addr(param, sh_scaling_size[scaling]);
		ret.post = sh_il_set_reg(param.param[0], ADD(sh_il_get_reg(param.param[0]), SH_U_ADDR(sh_scaling_size[scaling])));
		break;
	case SH_REG_INDIRECT_D:
		ret.pre = sh_il_set_reg(param.param[0], SUB(sh_il_get_reg(param.param[0]), SH_U_ADDR(sh_scaling_size[scaling])));
		ret.pure = sh_il_get_effective_addr(param, sh_scaling_size[scaling]);
		break;
	case SH_REG_INDIRECT_DISP:
		ret.pure = LOADW(BITS_PER_BYTE * sh_scaling_size[scaling], sh_il_get_effective_addr(param, sh_scaling_size[scaling]));
		break;
	case SH_REG_INDIRECT_INDEXED:
		ret.pure = LOADW(BITS_PER_BYTE * sh_scaling_size[scaling], sh_il_get_effective_addr(param, sh_scaling_size[scaling]));
		break;
	case SH_GBR_INDIRECT_DISP: {
		ret.pure = LOADW(BITS_PER_BYTE * sh_scaling_size[scaling], sh_il_get_effective_addr(param, sh_scaling_size[scaling]));
		break;
	}
	case SH_GBR_INDIRECT_INDEXED:
		ret.pure = LOADW(BITS_PER_BYTE * sh_scaling_size[scaling], sh_il_get_effective_addr(param, sh_scaling_size[scaling]));
		break;
	case SH_PC_RELATIVE_DISP:
		ret.pure = sh_il_get_effective_addr(param, sh_scaling_size[scaling]);
		break;
	case SH_PC_RELATIVE:
		ret.pure = sh_il_get_effective_addr(param, sh_scaling_size[scaling]);
		break;
	case SH_PC_RELATIVE_REG:
		ret.pure = sh_il_get_effective_addr(param, sh_scaling_size[scaling]);
		break;
	case SH_IMM_U:
		ret.pure = SH_U_REG(param.param[0]);
		break;
	case SH_IMM_S:
		ret.pure = SH_S_REG(param.param[0]);
		break;
	default:
		RZ_LOG_ERROR("RzIL: SH: Invalid addressing mode");
	}

	return ret;
}

static inline RzILOpEffect *sh_apply_effects(RzILOpEffect *target, RzILOpEffect *pre, RzILOpEffect *post) {
	if (!target) {
		if (pre) {
			target = pre;
			goto append;
		} else if (post) {
			return post;
		}
		return NULL;
	}

	if (pre) {
		target = SEQ2(pre, target);
	}
append:
	if (post) {
		target = SEQ2(target, post);
	}

	return target;
}

static inline RzILOpEffect *sh_il_set_param(SHParam param, RzILOpPure *val, SHScaling scaling) {
	RzILOpEffect *ret = NULL, *pre = NULL, *post = NULL;
	switch (param.mode) {
	case SH_REG_DIRECT:
		ret = sh_il_set_reg(param.param[0], val);
		break;
	case SH_REG_INDIRECT:
	case SH_REG_INDIRECT_I:
	case SH_REG_INDIRECT_D:
	case SH_REG_INDIRECT_DISP:
	case SH_REG_INDIRECT_INDEXED:
	case SH_GBR_INDIRECT_DISP:
	case SH_GBR_INDIRECT_INDEXED:
	case SH_PC_RELATIVE_DISP:
	case SH_PC_RELATIVE:
	case SH_PC_RELATIVE_REG:
		break;
	case SH_IMM_U:
	case SH_IMM_S:
	default:
		RZ_LOG_ERROR("RzIL: SH: Cannot set value for addressing mode: %u", param.mode);
	}

	if (!ret) {
		SHParamHelper ret_h = sh_il_get_param(param, sh_scaling_size[scaling]);
		rz_il_op_pure_free(ret_h.pure);
		ret = STOREW(sh_il_get_effective_addr(param, sh_scaling_size[scaling]), val);
		pre = ret_h.pre;
		post = ret_h.post;
	}

	return sh_apply_effects(ret, pre, post);
}

static inline RzILOpBool *sh_il_is_add_carry(RzILOpPure *res, RzILOpPure *x, RzILOpPure *y) {
	// res = x + y
	// x & y
	RzILOpPure *xy = LOGAND(x, y);

	RzILOpPure *nres = LOGNOT(res);
	// !res & y
	RzILOpPure *ry = LOGAND(nres, y);
	// x & !res
	RzILOpPure *xr = LOGAND(x, nres);

	// bit = xy | ry | xr
	RzILOpPure * or = LOGOR(xy, ry);
	or = LOGOR(or, xr);

	RzILOpPure *mask = SH_U_REG(1u << 31);
	mask = LOGAND(mask, or);
	return NON_ZERO(mask);
}

static inline RzILOpBool *sh_il_is_sub_carry(RzILOpPure *res, RzILOpPure *x, RzILOpPure *y) {
	// res = x - y
	// !x & y
	RzILOpPure *nx = LOGNOT(x);
	RzILOpPure *nxy = LOGAND(nx, y);

	// y & res
	RzILOpPure *rny = LOGAND(y, res);
	// res & !x
	RzILOpPure *rnx = LOGAND(res, nx);

	// bit = nxy | rny | rnx
	RzILOpPure * or = LOGOR(nxy, rny);
	or = LOGOR(or, rnx);

	RzILOpPure *mask = SH_U_REG(1u << 31);
	mask = LOGAND(mask, or);
	return NON_ZERO(mask);
}

static inline RzILOpBool *sh_il_is_add_overflow(RzILOpPure *res, RzILOpPure *x, RzILOpPure *y) {
	// res = x + y
	// !res & x & y
	RzILOpPure *nrxy = LOGAND(LOGAND(LOGNOT(res), x), y);
	// res & !x & !y
	RzILOpPure *rnxny = LOGAND(LOGAND(res, LOGNOT(x)), LOGNOT(y));
	// or = nrxy | rnxny
	RzILOpPure * or = LOGOR(nrxy, rnxny);

	RzILOpPure *mask = SH_U_REG(1u << 31);
	mask = LOGAND(mask, or);
	return NON_ZERO(mask);
}

static inline RzILOpBool *sh_il_is_sub_overflow(RzILOpPure *res, RzILOpPure *x, RzILOpPure *y) {
	// res = x - y
	// !res & x & !y
	RzILOpPure *nrxny = LOGAND(LOGAND(LOGNOT(res), x), LOGNOT(y));
	// res & !x & y
	RzILOpPure *rnxy = LOGAND(LOGAND(res, LOGNOT(x)), y);
	// or = nrxny | rnxy
	RzILOpPure * or = LOGOR(nrxny, rnxy);

	RzILOpPure *mask = SH_U_REG(1u << 31);
	mask = LOGAND(mask, or);
	return NON_ZERO(mask);
}

/* Instruction implementations */

/**
 * Unknown instruction
 */
static RzILOpEffect *sh_il_unk(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return NULL; // rz_il_op_new_nop();
}

/**
 * MOV family instructions
 */
static RzILOpEffect *sh_il_mov(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *ret = NULL;
	SHParamHelper shp = sh_il_get_param(op->param[0], op->scaling);
	sh_apply_effects(ret, shp.pre, shp.post);
	return SEQ2(ret, sh_il_set_param(op->param[1], shp.pure, op->scaling));
}

/**
 * MOVT	Rn
 * T -> Rn
 * 0000nnnn00101001
 */
static RzILOpEffect *sh_il_movt(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return sh_il_set_param(op->param[0], VARG(SH_SR_T), op->scaling);
}

/**
 * SWAP.B Rm, Rn
 * Rm -> swap lower 2 bytes -> REG
 * 0110nnnnmmmm1000
 *
 * SWAP.W Rm, Rn
 * Rm -> swap upper/lower words -> Rn
 * 0110nnnnmmmm1001
 */
static RzILOpEffect *sh_il_swap(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	if (op->scaling == SH_SCALING_B) {
		// swap lower two bytes
		RzILOpEffect *r0 = SETL("swap_r0", sh_il_get_reg(op->param->param[0]));
		RzILOpEffect *r1 = SETL("swap_r1", sh_il_get_reg(op->param->param[1]));
		RzILOpPure *r0_low = LOGAND(SH_U_REG(0xffff), VARL("swap_r0"));
		RzILOpPure *r1_low = LOGAND(SH_U_REG(0xffff), VARL("swap_r1"));
		RzILOpPure *r0_high = LOGAND(SH_U_REG(0xffff0000), VARL("swap_r0"));
		RzILOpPure *r1_high = LOGAND(SH_U_REG(0xffff0000), VARL("swap_r1"));
		RzILOpPure *r0_new = LOGOR(r0_high, r1_low);
		RzILOpPure *r1_new = LOGOR(r1_high, r0_low);
		return SEQ4(r0, r1, sh_il_set_reg(op->param->param[0], r0_new), sh_il_set_reg(op->param->param[1], r1_new));
	} else if (op->scaling == SH_SCALING_W) {
		// swap upper and lower words and store in dst
		RzILOpPure *high = SHIFTL0(sh_il_get_reg(op->param->param[0]), SH_U_REG(BITS_PER_BYTE * 2));
		RzILOpPure *low = SHIFTR0(sh_il_get_reg(op->param->param[0]), SH_U_REG(BITS_PER_BYTE * 2));
		return sh_il_set_reg(op->param->param[1], LOGOR(high, low));
	}

	return NULL;
}

/**
 * XTRCT Rm, Rn
 * Rm:Rn middle 32 bits -> Rn
 * 0010nnnnmmmm1101
 */
static RzILOpEffect *sh_il_xtrct(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *high = SHIFTL0(sh_il_get_reg(op->param->param[0]), SH_U_REG(BITS_PER_BYTE * 2));
	RzILOpPure *low = SHIFTR0(sh_il_get_reg(op->param->param[1]), SH_U_REG(BITS_PER_BYTE * 2));
	return sh_il_set_reg(op->param->param[1], LOGOR(high, low));
}

#include <rz_il/rz_il_opbuilder_end.h>

typedef RzILOpEffect *(*sh_il_op)(SHOp *aop, ut64 pc, RzAnalysis *analysis);

static sh_il_op sh_ops[SH_OP_SIZE] = {
	sh_il_unk,
	sh_il_mov,
	sh_il_movt,
	sh_il_swap,
	sh_il_xtrct
};
