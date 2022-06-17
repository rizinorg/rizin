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

#define BITS_PER_BYTE       8
#define SH_REG_SIZE         4 * BITS_PER_BYTE
#define SH_ADDR_SIZE        4 * BITS_PER_BYTE
#define SH_INSTR_SIZE       2 * BITS_PER_BYTE
#define SH_GPR_COUNT        16
#define SH_BANKED_REG_COUNT 8

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
#define SH_SR_I_BIT 1u << 4
#define SH_SR_I     "sr_i" ///< SR.I: Interrupt mask level: External interrupts of a lower level than IMASK are masked.
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
	if (!sh_valid_gpr(x)) { \
		RZ_LOG_ERROR("RzIL: SuperH: invalid register R%u\n", x); \
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
	"gbr", "ssr", "spc", "sgr", "dbr", "vbr", "mach", "macl",
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
	return reg < SH_GPR_COUNT;
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

static inline RzILOpPure *sh_il_get_status_reg() {
	RzILOpPure *val = SH_U_REG(0);
	val = LOGOR(VARG(SH_SR_D), val);
	val = SHIFTL0(DUP(val), SH_U_REG(1));
	val = LOGOR(VARG(SH_SR_R), val);
	val = SHIFTL0(DUP(val), SH_U_REG(1));
	val = LOGOR(VARG(SH_SR_B), val);
	val = SHIFTL0(DUP(val), SH_U_REG(13));
	val = LOGOR(VARG(SH_SR_F), val);
	val = SHIFTL0(DUP(val), SH_U_REG(6));
	val = LOGOR(VARG(SH_SR_M), val);
	val = SHIFTL0(DUP(val), SH_U_REG(1));
	val = LOGOR(VARG(SH_SR_Q), val);
	val = SHIFTL0(DUP(val), SH_U_REG(4));
	val = LOGOR(VARG(SH_SR_I), val);
	val = SHIFTL0(DUP(val), SH_U_REG(3));
	val = LOGOR(VARG(SH_SR_S), val);
	val = SHIFTL0(DUP(val), SH_U_REG(1));
	val = LOGOR(VARG(SH_SR_T), val);

	return val;
}

static inline RzILOpEffect *sh_il_set_status_reg(RzILOpPure *val) {
	RzILOpEffect *eff = SETG(SH_SR_T, LOGAND(SH_U_REG(0b1), val));
	val = SHIFTR0(DUP(val), SH_U_REG(1));
	eff = SEQ2(eff, SETG(SH_SR_S, LOGAND(SH_U_REG(0b1), val)));
	val = SHIFTR0(DUP(val), SH_U_REG(3));
	eff = SEQ2(eff, SETG(SH_SR_I, LOGAND(SH_U_REG(0b1111), val)));
	val = SHIFTR0(DUP(val), SH_U_REG(4));
	eff = SEQ2(eff, SETG(SH_SR_Q, LOGAND(SH_U_REG(0b1), val)));
	val = SHIFTR0(DUP(val), SH_U_REG(1));
	eff = SEQ2(eff, SETG(SH_SR_M, LOGAND(SH_U_REG(0b1), val)));
	val = SHIFTR0(DUP(val), SH_U_REG(6));
	eff = SEQ2(eff, SETG(SH_SR_F, LOGAND(SH_U_REG(0b1), val)));
	val = SHIFTR0(DUP(val), SH_U_REG(13));
	eff = SEQ2(eff, SETG(SH_SR_B, LOGAND(SH_U_REG(0b1), val)));
	val = SHIFTR0(DUP(val), SH_U_REG(1));
	eff = SEQ2(eff, SETG(SH_SR_R, LOGAND(SH_U_REG(0b1), val)));
	val = SHIFTR0(DUP(val), SH_U_REG(1));
	eff = SEQ2(eff, SETG(SH_SR_D, LOGAND(SH_U_REG(0b1), val)));

	return eff;
}

static inline RzILOpPure *sh_il_get_reg(ut16 reg) {
	sh_return_val_if_invalid_gpr(reg, NULL);
	if (!sh_banked_reg(reg)) {
		if (reg == SH_REG_IND_SR) {
			return sh_il_get_status_reg();
		}
		return VARG(sh_registers[reg]);
	}

	// check if both SR.MD = 1 and SR.RB = 1
	RzILOpPure *condition = AND(VARG(SH_SR_D), VARG(SH_SR_R));
	return ITE(condition, VARG(sh_get_banked_reg(reg, 1)), VARG(sh_get_banked_reg(reg, 0)));
}

static inline RzILOpEffect *sh_il_set_reg(ut16 reg, RZ_OWN RzILOpPure *val) {
	sh_return_val_if_invalid_gpr(reg, NULL);
	if (!sh_banked_reg(reg)) {
		if (reg == SH_REG_IND_SR) {
			return sh_il_set_status_reg(val);
		}
		return SETG(sh_registers[reg], val);
	}

	RzILOpPure *condition = AND(VARG(SH_SR_D), VARG(SH_SR_R));
	return BRANCH(condition, SETG(sh_get_banked_reg(reg, 1), val), SETG(sh_get_banked_reg(reg, 0), DUP(val)));
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
		return ADD(sh_il_get_reg(SH_REG_IND_R0), sh_il_get_reg(param.param[0]));
	case SH_GBR_INDIRECT_DISP:
		return ADD(VARG("gbr"), MUL(SH_U_ADDR(param.param[0]), SH_U_ADDR(sh_scaling_size[scaling])));
	case SH_GBR_INDIRECT_INDEXED:
		return ADD(VARG("gbr"), sh_il_get_reg(SH_REG_IND_R0));
	case SH_PC_RELATIVE_DISP: {
		RzILOpBitVector *pc = VARG("pc");
		// mask lower 2 bits if sh_scaling_size[scaling] == 4
		pc = ITE(EQ(SH_U_ADDR(sh_scaling_size[scaling]), SH_U_ADDR(4)), LOGAND(pc, SH_U_ADDR(0xfffffffc)), DUP(pc));
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
		RZ_LOG_WARN("RzIL: SuperH: No effective address for this mode: %u", param.mode);
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
		ret.pure = UNSIGNED(BITS_PER_BYTE * sh_scaling_size[scaling], sh_il_get_reg(param.param[0]));
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
		RZ_LOG_ERROR("RzIL: SuperH: Invalid addressing mode");
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

static inline RzILOpEffect *sh_il_set_param(SHParam param, RZ_OWN RzILOpPure *val, SHScaling scaling) {
	RzILOpEffect *ret = NULL, *pre = NULL, *post = NULL;
	switch (param.mode) {
	case SH_REG_DIRECT:
		ret = sh_il_set_reg(param.param[0], UNSIGNED(SH_REG_SIZE, val));
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
		RZ_LOG_ERROR("RzIL: SuperH: Cannot set value for addressing mode: %u", param.mode);
		return NULL;
	}

	if (!ret) {
		SHParamHelper ret_h = sh_il_get_param(param, sh_scaling_size[scaling]);
		ret = STOREW(ret_h.pure, UNSIGNED(sh_scaling_size[scaling], val));
		pre = ret_h.pre;
		post = ret_h.post;
	}

	return sh_apply_effects(ret, pre, post);
}

static inline RzILOpBool *sh_il_is_add_carry(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y) {
	// res = x + y
	// x & y
	RzILOpPure *xy = LOGAND(x, y);

	RzILOpPure *nres = LOGNOT(res);
	// !res & y
	RzILOpPure *ry = LOGAND(nres, DUP(y));
	// x & !res
	RzILOpPure *xr = LOGAND(DUP(x), nres);

	// bit = xy | ry | xr
	RzILOpPure * or = LOGOR(xy, ry);
	or = LOGOR(or, xr);

	RzILOpPure *mask = SH_U_REG(1u << 31);
	mask = LOGAND(mask, DUP(or));
	return NON_ZERO(mask);
}

static inline RzILOpBool *sh_il_is_sub_borrow(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y) {
	// res = x - y
	// !x & y
	RzILOpPure *nx = LOGNOT(x);
	RzILOpPure *nxy = LOGAND(nx, y);

	// y & res
	RzILOpPure *rny = LOGAND(DUP(y), res);
	// res & !x
	RzILOpPure *rnx = LOGAND(DUP(res), nx);

	// bit = nxy | rny | rnx
	RzILOpPure * or = LOGOR(nxy, rny);
	or = LOGOR(or, rnx);

	RzILOpPure *mask = SH_U_REG(1u << 31);
	mask = LOGAND(mask, DUP(or));
	return NON_ZERO(mask);
}

static inline RzILOpBool *sh_il_is_add_overflow(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y) {
	// res = x + y
	// !res & x & y
	RzILOpPure *nrxy = LOGAND(LOGAND(LOGNOT(res), x), y);
	// res & !x & !y
	RzILOpPure *rnxny = LOGAND(LOGAND(DUP(res), LOGNOT(DUP(x))), LOGNOT(DUP(y)));
	// or = nrxy | rnxny
	RzILOpPure * or = LOGOR(nrxy, rnxny);

	RzILOpPure *mask = SH_U_REG(1u << 31);
	mask = LOGAND(mask, or);
	return NON_ZERO(mask);
}

static inline RzILOpBool *sh_il_is_sub_underflow(RZ_OWN RzILOpPure *res, RZ_OWN RzILOpPure *x, RZ_OWN RzILOpPure *y) {
	// res = x - y
	// !res & x & !y
	RzILOpPure *nrxny = LOGAND(LOGAND(LOGNOT(res), x), LOGNOT(y));
	// res & !x & y
	RzILOpPure *rnxy = LOGAND(LOGAND(DUP(res), LOGNOT(DUP(x))), DUP(y));
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
	return NULL;
}

/**
 * MOV family instructions
 */
static RzILOpEffect *sh_il_mov(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	SHParamHelper shp = sh_il_get_param(op->param[0], op->scaling);
	return sh_apply_effects(sh_il_set_pure_param(1, shp.pure), shp.pre, shp.post);
}

/**
 * MOVT	 Rn
 * T -> Rn
 * 0000nnnn00101001
 */
static RzILOpEffect *sh_il_movt(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return sh_il_set_pure_param(0, UNSIGNED(SH_REG_SIZE, VARG(SH_SR_T)));
}

/**
 * SWAP.B  Rm, Rn
 * Rm -> swap lower 2 bytes -> REG
 * 0110nnnnmmmm1000
 *
 * SWAP.W  Rm, Rn
 * Rm -> swap upper/lower words -> Rn
 * 0110nnnnmmmm1001
 */
static RzILOpEffect *sh_il_swap(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	if (op->scaling == SH_SCALING_B) {
		// swap lower two bytes
		RzILOpPure *lower_byte = AND(sh_il_get_pure_param(0), SH_U_REG(0xff));
		RzILOpPure *new_lower_byte = AND(SHIFTR0(sh_il_get_pure_param(0), SH_U_REG(BITS_PER_BYTE)), SH_U_REG(0xff));
		RzILOpPure *new_upper_byte = SHIFTL0(lower_byte, SH_U_REG(BITS_PER_BYTE));
		RzILOpPure *upper_word = LOGAND(sh_il_get_pure_param(0), SH_U_REG(0xffff0000));
		return sh_il_set_pure_param(1, LOGOR(upper_word, LOGOR(new_upper_byte, new_lower_byte)));
	} else if (op->scaling == SH_SCALING_W) {
		// swap upper and lower words and store in dst
		RzILOpPure *high = SHIFTL0(sh_il_get_pure_param(0), SH_U_REG(BITS_PER_BYTE * 2));
		RzILOpPure *low = SHIFTR0(sh_il_get_pure_param(0), SH_U_REG(BITS_PER_BYTE * 2));
		return sh_il_set_pure_param(1, LOGOR(high, low));
	}

	return NULL;
}

/**
 * XTRCT  Rm, Rn
 * Rm:Rn middle 32 bits -> Rn
 * 0010nnnnmmmm1101
 */
static RzILOpEffect *sh_il_xtrct(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *high = SHIFTL0(sh_il_get_pure_param(0), SH_U_REG(BITS_PER_BYTE * 2));
	RzILOpPure *low = SHIFTR0(sh_il_get_pure_param(1), SH_U_REG(BITS_PER_BYTE * 2));
	return sh_il_set_pure_param(1, LOGOR(high, low));
}

/**
 * ADD  Rm, Rn
 * Rn + Rm -> Rn
 * 0011nnnnmmmm1100
 *
 * ADD #imm, Rn
 * Rn + imm -> Rn
 * 0111nnnniiiiiiii
 */
static RzILOpEffect *sh_il_add(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return sh_il_set_pure_param(1, ADD(sh_il_get_pure_param(0), sh_il_get_pure_param(1)));
}

/**
 * ADDC  Rm, Rn
 * Rn + Rm + T -> Rn
 * carry -> T
 * 0011nnnnmmmm1110
 */
static RzILOpEffect *sh_il_addc(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *sum = ADD(sh_il_get_pure_param(0), sh_il_get_pure_param(1));
	sum = ADD(sum, UNSIGNED(SH_REG_SIZE, VARG(SH_SR_T)));

	RzILOpEffect *ret = sh_il_set_pure_param(1, sum);
	RzILOpEffect *tbit = SETG(SH_SR_T, sh_il_is_add_carry(DUP(sum), sh_il_get_pure_param(0), sh_il_get_pure_param(1)));
	return SEQ2(ret, tbit);
}

/**
 * ADDV  Rm, Rn
 * Rn + Rm -> Rn
 * overflow -> T
 * 0011nnnnmmmm1111
 */
static RzILOpEffect *sh_il_addv(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *sum = ADD(sh_il_get_pure_param(0), sh_il_get_pure_param(1));

	RzILOpEffect *ret = sh_il_set_pure_param(1, sum);
	RzILOpEffect *tbit = SETG(SH_SR_T, sh_il_is_add_overflow(DUP(sum), sh_il_get_pure_param(0), sh_il_get_pure_param(1)));
	return SEQ2(ret, tbit);
}

/**
 * CMP/EQ  #imm, R0
 * When R0 = imm, 1 -> T ; Otherwise, 0 -> T
 * 10001000iiiiiiii
 *
 * CMP/EQ  Rm, Rn
 * When Rn = Rm, 1 -> T ; Otherwise, 0 -> T
 * 0011nnnnmmmm0000
 */
static RzILOpEffect *sh_il_cmp_eq(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SETG(SH_SR_T, EQ(sh_il_get_pure_param(0), sh_il_get_pure_param(1)));
}

/**
 * CMP/HS  Rm, Rn
 * When Rn >= Rm (unsigned), 1 -> T ; Otherwise, 0 -> T
 * 0011nnnnmmmm0010
 */
static RzILOpEffect *sh_il_cmp_hs(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SETG(SH_SR_T, UGE(sh_il_get_pure_param(1), sh_il_get_pure_param(0)));
}

/**
 * CMP/GE  Rm, Rn
 * When Rn >= Rm (signed), 1 -> T ; Otherwise, 0 -> T
 * 0011nnnnmmmm0011
 */
static RzILOpEffect *sh_il_cmp_ge(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SETG(SH_SR_T, SGE(sh_il_get_pure_param(1), sh_il_get_pure_param(0)));
}

/**
 * CMP/HI  Rm, Rn
 * When Rn > Rm (unsigned), 1 -> T ; Otherwise, 0 -> T
 * 0011nnnnmmmm0110
 */
static RzILOpEffect *sh_il_cmp_hi(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SETG(SH_SR_T, UGT(sh_il_get_pure_param(1), sh_il_get_pure_param(0)));
}

/**
 * CMP/GT  Rm, Rn
 * When Rn > Rm (signed), 1 -> T ; Otherwise, 0 -> T
 * 0011nnnnmmmm0111
 */
static RzILOpEffect *sh_il_cmp_gt(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SETG(SH_SR_T, SGT(sh_il_get_pure_param(1), sh_il_get_pure_param(0)));
}

/**
 * CMP/PZ  Rn
 * When Rn >= 0, 1 -> T ; Otherwise, 0 -> T
 * 0100nnnn00010001
 */
static RzILOpEffect *sh_il_cmp_pz(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SETG(SH_SR_T, SGE(sh_il_get_pure_param(0), SH_S_REG(0)));
}

/**
 * CMP/PL  Rn
 * When Rn > 0, 1 -> T ; Otherwise, 0 -> T
 * 0100nnnn00010101
 */
static RzILOpEffect *sh_il_cmp_pl(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SETG(SH_SR_T, SGT(sh_il_get_pure_param(0), SH_S_REG(0)));
}

/**
 * CMP/STR  Rm, Rn
 * When any bytes are equal, 1 -> T ; Otherwise, 0 -> T
 * 0010nnnnmmmm1100
 */
static RzILOpEffect *sh_il_cmp_str(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure * xor = XOR(sh_il_get_pure_param(0), sh_il_get_pure_param(1));

	RzILOpPure *eq = EQ(LOGAND(xor, SH_U_REG(0xff)), SH_U_REG(0x0));
	xor = SHIFTR0(DUP(xor), SH_U_REG(BITS_PER_BYTE));
	eq = OR(eq, EQ(LOGAND(xor, SH_U_REG(0xff)), SH_U_REG(0x0)));
	xor = SHIFTR0(DUP(xor), SH_U_REG(BITS_PER_BYTE));
	eq = OR(eq, EQ(LOGAND(xor, SH_U_REG(0xff)), SH_U_REG(0x0)));
	xor = SHIFTR0(DUP(xor), SH_U_REG(BITS_PER_BYTE));
	eq = OR(eq, EQ(LOGAND(xor, SH_U_REG(0xff)), SH_U_REG(0x0)));

	return SETG(SH_SR_T, eq);
}

/**
 * DIV1  Rm, Rn
 * 1-step division (Rn ÷ Rm) ; Calculation result -> T
 * 0011nnnnmmmm0100
 *
 * Implementation details at page 162 (of 512) in https://www.renesas.com/eu/en/document/mah/sh-1sh-2sh-dsp-software-manual?language=en
 */
static RzILOpEffect *sh_il_div1(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *old_q = SETL("old_q", VARG(SH_SR_Q));
	RzILOpEffect *q = SETG(SH_SR_Q, MSB(sh_il_get_pure_param(1)));
	RzILOpEffect *shl = sh_il_set_pure_param(1, SHIFTL0(sh_il_get_pure_param(1), SH_U_REG(1)));
	RzILOpEffect *ort = sh_il_set_pure_param(1, OR(sh_il_get_pure_param(1), UNSIGNED(SH_REG_SIZE, VARG(SH_SR_T))));
	RzILOpEffect *init = SEQ4(old_q, q, shl, ort);

	RzILOpEffect *tmp0 = SETL("tmp0", sh_il_get_pure_param(1));
	RzILOpEffect *sub = sh_il_set_pure_param(1, SUB(sh_il_get_pure_param(1), sh_il_get_pure_param(0)));
	RzILOpEffect *tmp1 = SETL("tmp1", UGT(sh_il_get_pure_param(1), VARL("tmp0")));
	RzILOpEffect *q_bit = BRANCH(VARG(SH_SR_Q), SETG(SH_SR_Q, IS_ZERO(VARL("tmp1"))), SETG(SH_SR_Q, VARL("tmp1")));
	RzILOpEffect *q0m0 = SEQ4(tmp0, sub, tmp1, q_bit);

	tmp0 = SETL("tmp0", sh_il_get_pure_param(1));
	RzILOpEffect *add = sh_il_set_pure_param(1, ADD(sh_il_get_pure_param(1), sh_il_get_pure_param(0)));
	tmp1 = SETL("tmp1", ULT(sh_il_get_pure_param(1), VARL("tmp0")));
	q_bit = BRANCH(VARG(SH_SR_Q), SETG(SH_SR_Q, VARL("tmp1")), SETG(SH_SR_Q, IS_ZERO(VARL("tmp1"))));
	RzILOpEffect *q0m1 = SEQ4(tmp0, add, tmp1, q_bit);

	tmp0 = SETL("tmp0", sh_il_get_pure_param(1));
	add = sh_il_set_pure_param(1, ADD(sh_il_get_pure_param(1), sh_il_get_pure_param(0)));
	tmp1 = SETL("tmp1", ULT(sh_il_get_pure_param(1), VARL("tmp0")));
	q_bit = BRANCH(VARG(SH_SR_Q), SETG(SH_SR_Q, IS_ZERO(VARL("tmp1"))), SETG(SH_SR_Q, VARL("tmp1")));
	RzILOpEffect *q1m0 = SEQ4(tmp0, add, tmp1, q_bit);

	tmp0 = SETL("tmp0", sh_il_get_pure_param(1));
	sub = sh_il_set_pure_param(1, SUB(sh_il_get_pure_param(1), sh_il_get_pure_param(0)));
	tmp1 = SETL("tmp1", UGT(sh_il_get_pure_param(1), VARL("tmp0")));
	q_bit = BRANCH(VARG(SH_SR_Q), SETG(SH_SR_Q, VARL("tmp1")), SETG(SH_SR_Q, IS_ZERO(VARL("tmp1"))));
	RzILOpEffect *q1m1 = SEQ4(tmp0, sub, tmp1, q_bit);

	RzILOpEffect *q0 = BRANCH(VARG(SH_SR_M), q0m1, q0m0);
	RzILOpEffect *q1 = BRANCH(VARG(SH_SR_M), q1m1, q1m0);
	RzILOpEffect *q_switch = BRANCH(VARL("old_q"), q1, q0);

	return SEQ3(init, q_switch, SETG(SH_SR_T, EQ(VARG(SH_SR_Q), VARG(SH_SR_M))));
}

/**
 * DIV0S  Rm, Rn
 * MSB of Rn -> Q ; MSB of Rm -> M, M^Q -> T
 * 0010nnnnmmmm0111
 */
static RzILOpEffect *sh_il_div0s(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *setm = SETG(SH_SR_M, MSB(sh_il_get_pure_param(0)));
	RzILOpEffect *setq = SETG(SH_SR_Q, MSB(sh_il_get_pure_param(1)));
	RzILOpEffect *sett = SETG(SH_SR_T, XOR(MSB(sh_il_get_pure_param(0)), MSB(sh_il_get_pure_param(1))));

	return SEQ3(setm, setq, sett);
}

/**
 * DIV0U  Rm, Rn
 * 0 -> M/Q/T
 * 0000000000011001
 */
static RzILOpEffect *sh_il_div0u(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SEQ3(SETG(SH_SR_M, SH_BIT(0)), SETG(SH_SR_Q, SH_BIT(0)), SETG(SH_SR_T, SH_BIT(0)));
}

/**
 * DMULS.L  Rm, Rn
 * Signed, Rn * Rm -> MAC ; 32 * 32 -> 64 bits
 * 0011nnnnmmmm1101
 */
static RzILOpEffect *sh_il_dmuls(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *eff = SETL("res_wide", MUL(SIGNED(2 * SH_REG_SIZE, sh_il_get_pure_param(0)), SIGNED(2 * SH_REG_SIZE, sh_il_get_pure_param(1))));
	RzILOpPure *lower_bits = UNSIGNED(SH_REG_SIZE, LOGAND(VARL("res_wide"), UN(2 * SH_REG_SIZE, 0xffffffff)));
	RzILOpPure *higher_bits = UNSIGNED(SH_REG_SIZE, SHIFTR0(VARL("res_wide"), SH_U_REG(SH_REG_SIZE)));
	return SEQ3(eff, SETG("macl", lower_bits), SETG("mach", higher_bits));
}

/**
 * DMULU.L  Rm, Rn
 * Unsigned, Rn * Rm -> MAC ; 32 * 32 -> 64 bits
 * 0011nnnnmmmm0101
 */
static RzILOpEffect *sh_il_dmulu(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *eff = SETL("res_wide", MUL(UNSIGNED(2 * SH_REG_SIZE, sh_il_get_pure_param(0)), UNSIGNED(2 * SH_REG_SIZE, sh_il_get_pure_param(1))));
	RzILOpPure *lower_bits = UNSIGNED(SH_REG_SIZE, LOGAND(VARL("res_wide"), UN(2 * SH_REG_SIZE, 0xffffffff)));
	RzILOpPure *higher_bits = UNSIGNED(SH_REG_SIZE, SHIFTR0(VARL("res_wide"), SH_U_REG(SH_REG_SIZE)));
	return SEQ3(eff, SETG("macl", lower_bits), SETG("mach", higher_bits));
}

/**
 * DT  Rn
 * Rn - 1 -> Rn ; When Rn = 0, 1 -> T ; Otherwise 0 -> T
 * 0100nnnn00010000
 */
static RzILOpEffect *sh_il_dt(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SEQ2(sh_il_set_pure_param(0, SUB(sh_il_get_pure_param(0), SH_U_REG(1))), SETG(SH_SR_T, NON_ZERO(sh_il_get_pure_param(0))));
}

/**
 * EXTS.B  Rm, Rn
 * Rm sign-extended from byte -> Rn
 * 0110nnnnmmmm1110
 *
 * EXTS.W  Rm, Rn
 * Rm sign-extended from word -> Rn
 * 0110nnnnmmmm1111
 */
static RzILOpEffect *sh_il_exts(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *eff = NULL;
	if (op->scaling == SH_SCALING_B) {
		RzILOpPure *byte = LOGAND(sh_il_get_pure_param(0), SH_U_REG(0xff));
		RzILOpBool *msb = MSB(byte);
		eff = BRANCH(msb, sh_il_set_pure_param(1, LOGOR(DUP(byte), SH_U_REG(0xffffff00))), sh_il_set_pure_param(1, DUP(byte)));
	} else if (op->scaling == SH_SCALING_W) {
		RzILOpPure *word = LOGAND(sh_il_get_pure_param(0), SH_U_REG(0xffff));
		RzILOpBool *msb = MSB(word);
		eff = BRANCH(msb, sh_il_set_pure_param(1, LOGOR(DUP(word), SH_U_REG(0xffff0000))), sh_il_set_pure_param(1, DUP(word)));
	}

	return eff;
}

/**
 * EXTU.B  Rm, Rn
 * Rm zero-extended from byte -> Rn
 * 0110nnnnmmmm1100
 *
 * EXTU.W  Rm, Rn
 * Rm zero-extended from word -> Rn
 * 0110nnnnmmmm1101
 */
static RzILOpEffect *sh_il_extu(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *eff = NULL;
	if (op->scaling == SH_SCALING_B) {
		eff = sh_il_set_pure_param(1, LOGAND(sh_il_get_pure_param(0), SH_U_REG(0xff)));
	} else if (op->scaling == SH_SCALING_W) {
		eff = sh_il_set_pure_param(1, LOGAND(sh_il_get_pure_param(0), SH_U_REG(0xffff)));
	}

	return eff;
}

/**
 * MAC.L  @Rm+, @Rn+
 * Rn * Rm + MAC -> MAC (Signed) (32 * 32 + 64 -> 64 bits)
 * Rn + 4 -> Rn ; Rm + 4 -> Rm
 * 0000nnnnmmmm1111
 *
 * When S bit is enabled, the MAC addition is a saturation operation of 48 bits
 * So only the lower 48 bits of result and MAC are considered
 *
 * MAC.W  @Rm+, @Rn+
 * Rn * Rm + MAC -> MAC (Signed) (16 * 16 + 64 -> 64 bits)
 * Rn + 2 -> Rn ; Rm + 2 -> Rm
 * 0000nnnnmmmm1111
 *
 * When S bit is enabled, the MAC addition is a saturation operation of 32 bits
 * So only the lower 32 bits of result and MAC are considered (which is basically MACL register)
 */
static RzILOpEffect *sh_il_mac(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	SHParamHelper shp_rm = sh_il_get_param(op->param[0], op->scaling);
	SHParamHelper shp_rn = sh_il_get_param(op->param[1], op->scaling);
	RzILOpEffect *eff = NULL;

	if (op->scaling == SH_SCALING_L) {
		RzILOpEffect *mac = SETL("mac", LOGOR(SHIFTL0((UNSIGNED(2 * SH_REG_SIZE, VARG("mach"))), SH_U_REG(SH_REG_SIZE)), UNSIGNED(2 * SH_REG_SIZE, VARG("macl"))));
		RzILOpPure *mul = MUL(SIGNED(2 * SH_REG_SIZE, shp_rm.pure), SIGNED(2 * SH_REG_SIZE, shp_rn.pure));
		RzILOpPure *add = ADD(mul, VARL("mac"));
		RzILOpPure *low = UNSIGNED(48, LOGAND(add, UN(2 * SH_REG_SIZE, 0xffffffffffff)));
		RzILOpPure *sat = SIGNED(2 * SH_REG_SIZE, low);

		eff = SEQ2(mac, BRANCH(VARG(SH_SR_S), SETL("mac", sat), SETG("mac", DUP(add))));
		RzILOpPure *lower_bits = UNSIGNED(SH_REG_SIZE, LOGAND(VARL("mac"), UN(2 * SH_REG_SIZE, 0xffffffff)));
		RzILOpPure *higher_bits = UNSIGNED(SH_REG_SIZE, SHIFTR0(VARL("mac"), SH_U_REG(SH_REG_SIZE)));
		eff = SEQ3(eff, SETG("macl", lower_bits), SETG("mach", higher_bits));
	} else if (op->scaling == SH_SCALING_W) {
		RzILOpEffect *mac = SETL("mac", LOGOR(SHIFTL0((UNSIGNED(2 * SH_REG_SIZE, VARG("mach"))), SH_U_REG(SH_REG_SIZE)), UNSIGNED(2 * SH_REG_SIZE, VARG("macl"))));
		RzILOpPure *mul = UNSIGNED(2 * SH_REG_SIZE, MUL(SIGNED(SH_REG_SIZE, shp_rm.pure), SIGNED(SH_REG_SIZE, shp_rn.pure)));
		RzILOpPure *add = ADD(mul, VARG("mac"));
		RzILOpPure *sat_add = ADD(UNSIGNED(SH_REG_SIZE, DUP(mul)), VARG("macl"));
		RzILOpPure *lower_bits = UNSIGNED(SH_REG_SIZE, LOGAND(add, UN(2 * SH_REG_SIZE, 0xffffffff)));
		RzILOpPure *higher_bits = UNSIGNED(SH_REG_SIZE, SHIFTR0(DUP(add), SH_U_REG(SH_REG_SIZE)));

		eff = SEQ2(mac, BRANCH(VARG(SH_SR_S), SETG("macl", sat_add), SEQ2(SETG("macl", lower_bits), SETG("mach", higher_bits))));
	}

	eff = SEQ3(eff, shp_rn.post, shp_rm.post);
	return eff;
}

/**
 * MUL.L  Rm, Rn
 * Rn * Rm -> MACL (32 * 32 -> 32 bits)
 * 0000nnnnmmmm0111
 */
static RzILOpEffect *sh_il_mul(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SETG("macl", MUL(sh_il_get_pure_param(0), sh_il_get_pure_param(1)));
}

/**
 * MULS.W  Rm, Rn
 * Rn * Rm -> MACL (Signed) (16 * 16 -> 32 bits)
 * 0010nnnnmmmm1111
 */
static RzILOpEffect *sh_il_muls(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *m = SIGNED(SH_REG_SIZE, SIGNED(16, sh_il_get_pure_param(0)));
	RzILOpPure *n = SIGNED(SH_REG_SIZE, SIGNED(16, sh_il_get_pure_param(1)));
	return SETG("macl", MUL(m, n));
}

/**
 * MULU.W  Rm, Rn
 * Rn * Rm -> MACL (Unsigned) (16 * 16 -> 32 bits)
 * 0010nnnnmmmm1110
 */
static RzILOpEffect *sh_il_mulu(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *m = UNSIGNED(SH_REG_SIZE, UNSIGNED(16, sh_il_get_pure_param(0)));
	RzILOpPure *n = UNSIGNED(SH_REG_SIZE, UNSIGNED(16, sh_il_get_pure_param(1)));
	return SETG("macl", MUL(m, n));
}

/**
 * NEG  Rm, Rn
 * 0 - Rm -> Rn
 * 0110nnnnmmmm1011
 */
static RzILOpEffect *sh_il_neg(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *sub = SUB(UNSIGNED(SH_REG_SIZE, 0), sh_il_get_pure_param(0));
	return sh_il_set_pure_param(1, sub);
}

/**
 * NEGC  Rm, Rn
 * 0 - Rm - T -> Rn ; borrow -> T
 * 0110nnnnmmmm1010
 */
static RzILOpEffect *sh_il_negc(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *sub = SUB(UNSIGNED(SH_REG_SIZE, 0), sh_il_get_pure_param(0));
	sub = SUB(sub, UNSIGNED(SH_REG_SIZE, VARG(SH_SR_T)));
	return SEQ2(sh_il_set_pure_param(1, sub), SETG(SH_SR_T, sh_il_is_sub_borrow(sub, UNSIGNED(SH_REG_SIZE, 0), sh_il_get_pure_param(0))));
}

/**
 * SUB  Rm, Rn
 * Rn - Rm -> Rn
 * 0011nnnnmmmm1000
 */
static RzILOpEffect *sh_il_sub(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return sh_il_set_pure_param(1, SUB(sh_il_get_pure_param(0), sh_il_get_pure_param(1)));
}

/**
 * SUBC  Rm, Rn
 * Rn - Rm - T -> Rn ; borrow -> T
 * 0011nnnnmmmm1010
 */
static RzILOpEffect *sh_il_subc(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *dif = ADD(sh_il_get_pure_param(0), sh_il_get_pure_param(1));
	dif = SUB(dif, UNSIGNED(SH_REG_SIZE, VARG(SH_SR_T)));

	RzILOpEffect *ret = sh_il_set_pure_param(1, dif);
	RzILOpEffect *tbit = SETG(SH_SR_T, sh_il_is_sub_borrow(DUP(dif), sh_il_get_pure_param(0), sh_il_get_pure_param(1)));
	return SEQ2(ret, tbit);
}

/**
 * SUBV  Rm, Rn
 * Rn - Rm -> Rn ; underflow -> T
 * 0011nnnnmmmm1011
 */
static RzILOpEffect *sh_il_subv(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *dif = SUB(sh_il_get_pure_param(0), sh_il_get_pure_param(1));

	RzILOpEffect *ret = sh_il_set_pure_param(1, dif);
	RzILOpEffect *tbit = SETG(SH_SR_T, sh_il_is_sub_underflow(DUP(dif), sh_il_get_pure_param(0), sh_il_get_pure_param(1)));
	return SEQ2(ret, tbit);
}

/**
 * AND  Rm, Rn
 * Rn & Rm -> Rn
 * 0010nnnnmmmm1001
 *
 * AND  #imm, R0
 * R0 & imm -> R0
 * 11001001iiiiiiii
 *
 * AND.B  #imm, @(R0, GBR)
 * (R0 + GBR) & imm -> (R0 + GBR)
 * 11001101iiiiiiii
 */
static RzILOpEffect *sh_il_and(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return sh_il_set_pure_param(1, LOGAND(sh_il_get_pure_param(0), sh_il_get_pure_param(1)));
}

/**
 * NOT  Rm, Rn
 * ~Rm -> Rn
 * 0110nnnnmmmm0111
 */
static RzILOpEffect *sh_il_not(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return sh_il_set_pure_param(1, LOGNOT(sh_il_get_pure_param(0)));
}

/**
 * OR  Rm, Rn
 * Rn | Rm -> Rn
 * 0010nnnnmmmm1011
 *
 * OR  #imm, R0
 * R0 | imm -> R0
 * 11001011iiiiiiii
 *
 * OR.B  #imm, @(R0, GBR)
 * (R0 + GBR) | imm -> (R0 + GBR)
 * 11001111iiiiiiii
 */
static RzILOpEffect *sh_il_or(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return sh_il_set_pure_param(1, LOGOR(sh_il_get_pure_param(0), sh_il_get_pure_param(1)));
}

/**
 * TAS.B  @Rn
 * If (Rn) = 0, 1 -> T ; Otherwise 0 -> T
 * 1 -> MSB of (Rn)
 * 0110nnnnmmmm0111
 */
static RzILOpEffect *sh_il_tas(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *mem = sh_il_get_pure_param(0);
	RzILOpEffect *tbit = SETG(SH_SR_T, IS_ZERO(mem));
	return SEQ2(tbit, sh_il_set_pure_param(0, LOGOR(DUP(mem), UN(8, 0x80))));
}

/**
 * TST  Rm, Rn
 * If Rn & Rm = 0, 1 -> T ; Otherwise 0 -> T
 * 0010nnnnmmmm1000
 *
 * TST  #imm, R0
 * If R0 & imm = 0, 1 -> T ; Otherwise 0 -> T
 * 11001000iiiiiiii
 *
 * TST.B  #imm, @(R0, GBR)
 * If (R0 + GBR) & imm = 0, 1 -> T ; Otherwise 0 -> T
 * 11001100iiiiiiii
 */
static RzILOpEffect *sh_il_tst(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SETG(SH_SR_T, IS_ZERO(LOGAND(sh_il_get_pure_param(0), sh_il_get_pure_param(1))));
}

/**
 * XOR  Rm, Rn
 * Rn ^ Rm -> Rn
 * 0010nnnnmmmm1010
 *
 * XOR  #imm, R0
 * R0 ^ imm -> R0
 * 11001010iiiiiiii
 *
 * XOR.B  #imm, @(R0, GBR)
 * (R0 + GBR) ^ imm -> (R0 + GBR)
 * 11001110iiiiiiii
 */
static RzILOpEffect *sh_il_xor(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return sh_il_set_pure_param(1, LOGXOR(sh_il_get_pure_param(0), sh_il_get_pure_param(1)));
}

/**
 * ROTL  Rn
 * T <- Rn <- MSB
 * 0100nnnn00000100
 */
static RzILOpEffect *sh_il_rotl(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpBool *msb = MSB(sh_il_get_pure_param(0));
	RzILOpEffect *tbit = SETG(SH_SR_T, msb);
	RzILOpPure *shl = SHIFTL0(sh_il_get_pure_param(0), SH_U_REG(1));
	RzILOpPure *lsb = ITE(DUP(msb), OR(shl, SH_U_REG(1)), AND(DUP(shl), SH_U_REG(0xfffffffe)));
	return SEQ2(tbit, sh_il_set_pure_param(0, lsb));
}

/**
 * ROTR  Rn
 * LSB -> Rn -> T
 * 0100nnnn00000101
 */
static RzILOpEffect *sh_il_rotr(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpBool *lsb = LSB(sh_il_get_pure_param(0));
	RzILOpEffect *tbit = SETG(SH_SR_T, lsb);
	RzILOpPure *shr = SHIFTR0(sh_il_get_pure_param(0), SH_U_REG(1));
	RzILOpPure *msb = ITE(DUP(lsb), OR(shr, SH_U_REG(0x80000000)), AND(DUP(shr), SH_U_REG(0x7fffffff)));
	return SEQ2(tbit, sh_il_set_pure_param(0, msb));
}

/**
 * ROTCL  Rn
 * T <- Rn <- T
 * 0100nnnn00100100
 */
static RzILOpEffect *sh_il_rotcl(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *msb = SETL("msb", MSB(sh_il_get_pure_param(0)));
	RzILOpPure *shl = SHIFTL0(sh_il_get_pure_param(0), SH_U_REG(1));
	RzILOpPure *lsb = ITE(VARG(SH_SR_T), OR(shl, SH_U_REG(1)), AND(DUP(shl), SH_U_REG(0xfffffffe)));
	RzILOpEffect *tbit = SETG(SH_SR_T, VARL("msb"));
	return SEQ3(msb, sh_il_set_pure_param(0, lsb), tbit);
}

/**
 * ROTCR  Rn
 * T -> Rn -> T
 * 0100nnnn00100101
 */
static RzILOpEffect *sh_il_rotcr(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *lsb = SETL("lsb", LSB(sh_il_get_pure_param(0)));
	RzILOpPure *shr = SHIFTR0(sh_il_get_pure_param(0), SH_U_REG(1));
	RzILOpPure *msb = ITE(VARG(SH_SR_T), OR(shr, SH_U_REG(0x80000000)), AND(DUP(shr), SH_U_REG(0x7fffffff)));
	RzILOpEffect *tbit = SETG(SH_SR_T, VARL("lsb"));
	return SEQ3(lsb, sh_il_set_pure_param(0, msb), tbit);
}

/**
 * SHAD  Rm, Rn
 * If Rn >= 0, Rn << Rm -> Rn
 * If Rn < 0, Rn >> Rm -> [MSB -> Rn]
 * MSB -> Rn
 * 0100nnnnmmmm1100
 */
static RzILOpEffect *sh_il_shad(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *op1 = SETL("op1", SIGNED(32, sh_il_get_pure_param(0)));
	RzILOpEffect *op2 = SETL("op2", SIGNED(32, sh_il_get_pure_param(1)));
	RzILOpPure *shift_amount = UNSIGNED(5, VARL("op1"));

	RzILOpPure *shl = SHIFTL0(VARL("op2"), shift_amount);
	RzILOpPure *shr = SHIFTRA(VARL("op2"), SUB(UN(5, 32), DUP(shift_amount)));

	return SEQ3(op1, op2, BRANCH(SGE(VARL("op1"), SN(32, 0)), sh_il_set_pure_param(1, shl), sh_il_set_pure_param(1, shr)));
}

/**
 * SHAL  RN
 * T <- Rn <- 0
 * 0100nnnn00100000
 */
static RzILOpEffect *sh_il_shal(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *msb = MSB(sh_il_get_pure_param(0));
	RzILOpPure *shl = SHIFTL0(sh_il_get_pure_param(0), SH_U_REG(1));
	return SEQ2(SETG(SH_SR_T, msb), sh_il_set_pure_param(0, shl));
}

/**
 * SHLD  Rm, Rn
 * If Rn >= 0, Rn << Rm -> Rn
 * If Rn < 0, Rn >> Rm -> [0 -> Rn]
 * MSB -> Rn
 * 0100nnnnmmmm1101
 */
static RzILOpEffect *sh_il_shld(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpEffect *op1 = SETL("op1", SIGNED(32, sh_il_get_pure_param(0)));
	RzILOpEffect *op2 = SETL("op2", UNSIGNED(32, sh_il_get_pure_param(1)));
	RzILOpPure *shift_amount = UNSIGNED(5, VARL("op1"));

	RzILOpPure *shl = SHIFTL0(VARL("op2"), shift_amount);
	RzILOpPure *shr = SHIFTR0(VARL("op2"), SUB(UN(5, 32), DUP(shift_amount)));

	return SEQ3(op1, op2, BRANCH(SGE(VARL("op1"), SN(32, 0)), sh_il_set_pure_param(1, shl), sh_il_set_pure_param(1, shr)));
}

/**
 * SHLL  Rn
 * T <- Rn <- 0
 * 0100nnnn00000000
 */
static RzILOpEffect *sh_il_shll(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *msb = MSB(sh_il_get_pure_param(0));
	RzILOpPure *shl = SHIFTL0(sh_il_get_pure_param(0), SH_U_REG(1));
	return SEQ2(SETG(SH_SR_T, msb), sh_il_set_pure_param(0, shl));
}

/**
 * SHLR  Rn
 * 0 -> Rn -> T
 * 0100nnnn00000001
 */
static RzILOpEffect *sh_il_shlr(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *lsb = LSB(sh_il_get_pure_param(0));
	RzILOpPure *shr = SHIFTR0(sh_il_get_pure_param(0), SH_U_REG(1));
	return SEQ2(SETG(SH_SR_T, lsb), sh_il_set_pure_param(0, shr));
}

/**
 * SHLL2  Rn
 * Rn << 2 -> Rn
 * 0100nnnn00001000
 */
static RzILOpEffect *sh_il_shll2(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return sh_il_set_pure_param(0, SHIFTL0(sh_il_get_pure_param(0), SH_U_REG(2)));
}

/**
 * SHLR2  Rn
 * Rn >> 2 -> Rn
 * 0100nnnn00001001
 */
static RzILOpEffect *sh_il_shlr2(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return sh_il_set_pure_param(0, SHIFTR0(sh_il_get_pure_param(0), SH_U_REG(2)));
}

/**
 * SHLL8  Rn
 * Rn << 8 -> Rn
 * 0100nnnn00011000
 */
static RzILOpEffect *sh_il_shll8(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return sh_il_set_pure_param(0, SHIFTL0(sh_il_get_pure_param(0), SH_U_REG(8)));
}

/**
 * SHLR8  Rn
 * Rn >> 8 -> Rn
 * 0100nnnn00011001
 */
static RzILOpEffect *sh_il_shlr8(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return sh_il_set_pure_param(0, SHIFTR0(sh_il_get_pure_param(0), SH_U_REG(8)));
}

/**
 * SHLL16  Rn
 * Rn << 16 -> Rn
 * 0100nnnn00101000
 */
static RzILOpEffect *sh_il_shll16(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return sh_il_set_pure_param(0, SHIFTL0(sh_il_get_pure_param(0), SH_U_REG(16)));
}

/**
 * SHLR16  Rn
 * Rn >> 16 -> Rn
 * 0100nnnn00101001
 */
static RzILOpEffect *sh_il_shlr16(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return sh_il_set_pure_param(0, SHIFTR0(sh_il_get_pure_param(0), SH_U_REG(16)));
}

/**
 * CLRMAC
 * 0 -> MACH, MACL
 * 0000000000101000
 */
static RzILOpEffect *sh_il_clrmac(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SEQ2(SETG("mach", UN(SH_REG_SIZE, 0)), SETG("macl", UN(SH_REG_SIZE, 0)));
}

/**
 * CLRS
 * 0 -> S
 * 0000000001001000
 */
static RzILOpEffect *sh_il_clrs(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SETG(SH_SR_S, IL_FALSE);
}

/**
 * CLRT
 * 0 -> T
 * 0000000000001000
 */
static RzILOpEffect *sh_il_clrt(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SETG(SH_SR_T, IL_FALSE);
}

// TODO: This needs to be fixed for banked register LDC
/**
 * LDC  Rm, REG
 * REG := SR/GBR/VBR/SSR/SPC/DBR/Rn_BANK
 * Rm -> REG
 * PRIVILEGED (Only GBR is not privileged)
 *
 * LDC.L  @Rm+, REG
 * REG := SR/GBR/VBR/SSR/SPC/DBR/Rn_BANK
 * (Rm) -> REG ; Rm + 4 -> Rm
 * PRIVILEGED (Only GBR is not privileged)
 */
static RzILOpEffect *sh_il_ldc(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzBitVector *priv_bit = rz_il_evaluate_bitv(analysis->il_vm->vm, VARG(SH_SR_D));
	ut8 state = priv_bit->bits.small_u == 0 ? 0b1 : 0b0;
	state += op->param[1].param[0] != SH_REG_IND_GBR ? 0b10 : 0b00;
	if ((state & 0x11) == 0x11) {
		rz_il_vm_event_add(analysis->il_vm->vm, rz_il_event_exception_new("SuperH: RESINST"));
	}
	if (op->scaling == SH_SCALING_INVALID) {
		if (state & 0b10) {
			return BRANCH(VARG(SH_SR_D), sh_il_set_pure_param(1, sh_il_get_pure_param(0)), NOP());
		} else {
			return sh_il_set_pure_param(1, sh_il_get_pure_param(0));
		}
	} else if (op->scaling == SH_SCALING_L) {
		SHParamHelper rm = sh_il_get_param(op->param[0], op->scaling);
		if (state & 0b10) {
			return BRANCH(VARG(SH_SR_D), SEQ2(sh_il_set_pure_param(1, rm.pure), rm.post), NOP());
		} else {
			return SEQ2(sh_il_set_pure_param(1, rm.pure), rm.post);
		}
	}
	return NOP();
}

/**
 * LDS  Rm, REG
 * REG := MACH/MACL/PR
 * Rm -> REG
 *
 * LDS.L  @Rm+, REG
 * REG := MACH/MACL/PR
 * (Rm) -> REG ; Rm + 4 -> Rm
 */
static RzILOpEffect *sh_il_lds(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	if (op->scaling == SH_SCALING_INVALID) {
		return sh_il_set_pure_param(1, sh_il_get_pure_param(0));
	} else if (op->scaling == SH_SCALING_L) {
		SHParamHelper rm = sh_il_get_param(op->param[0], op->scaling);
		return SEQ2(sh_il_set_pure_param(1, rm.pure), rm.post);
	}
	return NOP();
}

// TODO: Implement LDTLB, MOVCA.L, OCBI, OCBP, OCBWB, PREF

/**
 * NOP
 * No operation
 * 0000000000001001
 */
static RzILOpEffect *sh_il_nop(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return NOP();
}

/**
 * SETS
 * 1 -> S
 * 0000000001011000
 */
static RzILOpEffect *sh_il_sets(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SETG(SH_SR_S, IL_TRUE);
}

/**
 * SETT
 * 1 -> T
 * 0000000000011000
 */
static RzILOpEffect *sh_il_sett(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	return SETG(SH_SR_T, IL_TRUE);
}

// TODO: This needs to be fixed for banked register STC
/**
 * STC  REG, Rn
 * REG := SR/GBR/VBR/SSR/SPC/DBR/Rn_BANK
 * REG -> Rn
 * PRIVILEGED (Only GBR is not privileged)
 *
 * STC.L  REG, @-Rn
 * REG := SR/GBR/VBR/SSR/SPC/DBR/Rn_BANK
 * Rn - 4 -> Rn ; REG -> (Rn)
 * PRIVILEGED (Only GBR is not privileged)
 */
static RzILOpEffect *sh_il_stc(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RzBitVector *priv_bit = rz_il_evaluate_bitv(analysis->il_vm->vm, VARG(SH_SR_D));
	ut8 state = priv_bit->bits.small_u == 0 ? 0b1 : 0b0;
	state += op->param[0].param[0] != SH_REG_IND_GBR ? 0b10 : 0b00;
	if ((state & 0x11) == 0x11) {
		rz_il_vm_event_add(analysis->il_vm->vm, rz_il_event_exception_new("SuperH: RESINST"));
	}
	if (op->scaling == SH_SCALING_INVALID) {
		if (state & 0b10) {
			return BRANCH(VARG(SH_SR_D), sh_il_set_pure_param(1, sh_il_get_pure_param(0)), NOP());
		} else {
			return sh_il_set_pure_param(1, sh_il_get_pure_param(0));
		}
	} else if (op->scaling == SH_SCALING_L) {
		RzILOpEffect *set = sh_il_set_pure_param(1, sh_il_get_pure_param(0));
		if (state & 0b10) {
			return BRANCH(VARG(SH_SR_D), set, NOP());
		} else {
			return set;
		}
	}
	return NOP();
}

/**
 * STS  REG, Rn
 * REG := MACH/MACL/PR
 * REG -> Rn
 *
 * STS.L  REG, @-Rn
 * REG := MACH/MACL/PR
 * Rn + 4 -> Rn ; REG -> (Rn)
 */
static RzILOpEffect *sh_il_sts(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	if (op->scaling == SH_SCALING_INVALID) {
		return sh_il_set_pure_param(1, sh_il_get_pure_param(0));
	} else if (op->scaling == SH_SCALING_L) {
		return sh_il_set_pure_param(1, sh_il_get_pure_param(0));
	}
	return NOP();
}

static RzILOpEffect *sh_il_unimpl(SHOp *op, ut64 pc, RzAnalysis *analysis) {
	RZ_LOG_WARN("SuperH: Instruction with opcode %#04x is unimplemented", op->opcode);
	return EMPTY();
}

#include <rz_il/rz_il_opbuilder_end.h>

typedef RzILOpEffect *(*sh_il_op)(SHOp *aop, ut64 pc, RzAnalysis *analysis);

static sh_il_op sh_ops[SH_OP_SIZE] = {
	sh_il_unk,
	sh_il_mov,
	sh_il_movt,
	sh_il_swap,
	sh_il_xtrct,
	sh_il_add,
	sh_il_addc,
	sh_il_addv,
	sh_il_cmp_eq,
	sh_il_cmp_hs,
	sh_il_cmp_ge,
	sh_il_cmp_hi,
	sh_il_cmp_gt,
	sh_il_cmp_pz,
	sh_il_cmp_pl,
	sh_il_cmp_str,
	sh_il_div1,
	sh_il_div0s,
	sh_il_div0u,
	sh_il_dmuls,
	sh_il_dmulu,
	sh_il_dt,
	sh_il_exts,
	sh_il_extu,
	sh_il_mac,
	sh_il_mul,
	sh_il_muls,
	sh_il_mulu,
	sh_il_neg,
	sh_il_negc,
	sh_il_sub,
	sh_il_subc,
	sh_il_subv,
	sh_il_and,
	sh_il_not,
	sh_il_or,
	sh_il_tas,
	sh_il_tst,
	sh_il_xor,
	sh_il_rotl,
	sh_il_rotr,
	sh_il_rotcl,
	sh_il_rotcr,
	sh_il_shad,
	sh_il_shal,
	sh_il_shld,
	sh_il_shll,
	sh_il_shlr,
	sh_il_shll2,
	sh_il_shlr2,
	sh_il_shll8,
	sh_il_shlr8,
	sh_il_shll16,
	sh_il_shlr16,
	sh_il_clrmac,
	sh_il_clrs,
	sh_il_clrt,
	sh_il_ldc,
	sh_il_lds,
	sh_il_nop,
	sh_il_sets,
	sh_il_sett,
	sh_il_stc,
	sh_il_sts,
	sh_il_unimpl
};
