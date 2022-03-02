// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <capstone.h>

#include "arm_cs.h"

#include "arm_accessors64.h"
// This source file is 64-bit specific, so avoid having to type 64 all the time:
#define IMM     IMM64
#define REGID   REGID64
#define ISIMM   ISIMM64
#define ISREG   ISREG64
#define ISMEM   ISMEM64
#define OPCOUNT OPCOUNT64
#undef MEMDISP64 // the original one casts to ut64 which we don't want here
#define MEMDISP(x) insn->detail->arm64.operands[x].mem.disp

#include <rz_il/rz_il_opbuilder_begin.h>

#include "arm_il_common.inc"

/**
 * All regs available as global IL variables
 */
static const char *regs_bound[] = {
	"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
	"x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp",
	"nf", "zf", "cf", "vf",
	NULL
};

/**
 * IL for arm64 condition
 * unconditional is returned as NULL (rather than true), for simpler code
 */
static RzILOpBool *cond(arm64_cc c) {
	switch (c) {
	case ARM64_CC_EQ:
		return VARG("zf");
	case ARM64_CC_NE:
		return INV(VARG("zf"));
	case ARM64_CC_HS:
		return VARG("cf");
	case ARM64_CC_LO:
		return INV(VARG("cf"));
	case ARM64_CC_MI:
		return VARG("nf");
	case ARM64_CC_PL:
		return INV(VARG("nf"));
	case ARM64_CC_VS:
		return VARG("vf");
	case ARM64_CC_VC:
		return INV(VARG("vf"));
	case ARM64_CC_HI:
		return AND(VARG("vf"), INV(VARG("zf")));
	case ARM64_CC_LS:
		return OR(INV(VARG("vf")), VARG("zf"));
	case ARM64_CC_GE:
		return INV(XOR(VARG("nf"), VARG("vf")));
	case ARM64_CC_LT:
		return XOR(VARG("nf"), VARG("vf"));
	case ARM64_CC_GT:
		return INV(OR(XOR(VARG("nf"), VARG("vf")), VARG("zf")));
	case ARM64_CC_LE:
		return OR(XOR(VARG("nf"), VARG("vf")), VARG("zf"));
	default:
		return NULL;
	}
}

static arm64_reg xreg(ut8 idx) {
	// for some reason, the ARM64_REG_X0...ARM64_REG_X30 enum values are not contiguous,
	// so use switch here and let the compiler optimize:
	switch (idx) {
	case 0: return ARM64_REG_X0;
	case 1: return ARM64_REG_X1;
	case 2: return ARM64_REG_X2;
	case 3: return ARM64_REG_X3;
	case 4: return ARM64_REG_X4;
	case 5: return ARM64_REG_X5;
	case 6: return ARM64_REG_X6;
	case 7: return ARM64_REG_X7;
	case 8: return ARM64_REG_X8;
	case 9: return ARM64_REG_X9;
	case 10: return ARM64_REG_X10;
	case 11: return ARM64_REG_X11;
	case 12: return ARM64_REG_X12;
	case 13: return ARM64_REG_X13;
	case 14: return ARM64_REG_X14;
	case 15: return ARM64_REG_X15;
	case 16: return ARM64_REG_X16;
	case 17: return ARM64_REG_X17;
	case 18: return ARM64_REG_X18;
	case 19: return ARM64_REG_X19;
	case 20: return ARM64_REG_X20;
	case 21: return ARM64_REG_X21;
	case 22: return ARM64_REG_X22;
	case 23: return ARM64_REG_X23;
	case 24: return ARM64_REG_X24;
	case 25: return ARM64_REG_X25;
	case 26: return ARM64_REG_X26;
	case 27: return ARM64_REG_X27;
	case 28: return ARM64_REG_X28;
	case 29: return ARM64_REG_X29;
	case 30: return ARM64_REG_X30;
	case 31: return ARM64_REG_SP;
	default:
		rz_warn_if_reached();
		return ARM64_REG_INVALID;
	}
}

static bool is_xreg(arm64_reg reg) {
	switch (reg) {
	case ARM64_REG_X0:
	case ARM64_REG_X1:
	case ARM64_REG_X2:
	case ARM64_REG_X3:
	case ARM64_REG_X4:
	case ARM64_REG_X5:
	case ARM64_REG_X6:
	case ARM64_REG_X7:
	case ARM64_REG_X8:
	case ARM64_REG_X9:
	case ARM64_REG_X10:
	case ARM64_REG_X11:
	case ARM64_REG_X12:
	case ARM64_REG_X13:
	case ARM64_REG_X14:
	case ARM64_REG_X15:
	case ARM64_REG_X16:
	case ARM64_REG_X17:
	case ARM64_REG_X18:
	case ARM64_REG_X19:
	case ARM64_REG_X20:
	case ARM64_REG_X21:
	case ARM64_REG_X22:
	case ARM64_REG_X23:
	case ARM64_REG_X24:
	case ARM64_REG_X25:
	case ARM64_REG_X26:
	case ARM64_REG_X27:
	case ARM64_REG_X28:
	case ARM64_REG_X29:
	case ARM64_REG_X30:
	case ARM64_REG_SP:
		return true;
	default:
		return false;
	}
}

static ut8 xreg_idx(arm64_reg reg) {
	switch (reg) {
	case ARM64_REG_X0: return 0;
	case ARM64_REG_X1: return 1;
	case ARM64_REG_X2: return 2;
	case ARM64_REG_X3: return 3;
	case ARM64_REG_X4: return 4;
	case ARM64_REG_X5: return 5;
	case ARM64_REG_X6: return 6;
	case ARM64_REG_X7: return 7;
	case ARM64_REG_X8: return 8;
	case ARM64_REG_X9: return 9;
	case ARM64_REG_X10: return 10;
	case ARM64_REG_X11: return 11;
	case ARM64_REG_X12: return 12;
	case ARM64_REG_X13: return 13;
	case ARM64_REG_X14: return 14;
	case ARM64_REG_X15: return 15;
	case ARM64_REG_X16: return 16;
	case ARM64_REG_X17: return 17;
	case ARM64_REG_X18: return 18;
	case ARM64_REG_X19: return 19;
	case ARM64_REG_X20: return 20;
	case ARM64_REG_X21: return 21;
	case ARM64_REG_X22: return 22;
	case ARM64_REG_X23: return 23;
	case ARM64_REG_X24: return 24;
	case ARM64_REG_X25: return 25;
	case ARM64_REG_X26: return 26;
	case ARM64_REG_X27: return 27;
	case ARM64_REG_X28: return 28;
	case ARM64_REG_X29: return 29;
	case ARM64_REG_X30: return 30;
	case ARM64_REG_SP: return 31;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

static arm64_reg wreg(ut8 idx) {
	rz_return_val_if_fail(idx <= 31, ARM64_REG_INVALID);
	return idx == 31 ? ARM64_REG_WSP : ARM64_REG_W0 + idx;
}

static ut8 wreg_idx(arm64_reg reg) {
	if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) {
		return reg - ARM64_REG_W0;
	}
	if (reg == ARM64_REG_WSP) {
		return 31;
	}
	rz_warn_if_reached();
	return 0;
}

static bool is_wreg(arm64_reg reg) {
	return (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) || reg == ARM64_REG_WSP;
}

static arm64_reg xreg_of_reg(arm64_reg reg) {
	if (is_wreg(reg)) {
		return xreg(wreg_idx(reg));
	}
	return reg;
}

/**
 * Variable name for a register given by cs
 */
static const char *reg_var_name(arm64_reg reg) {
	reg = xreg_of_reg(reg);
	switch (reg) {
	case ARM64_REG_X0: return "x0";
	case ARM64_REG_X1: return "x1";
	case ARM64_REG_X2: return "x2";
	case ARM64_REG_X3: return "x3";
	case ARM64_REG_X4: return "x4";
	case ARM64_REG_X5: return "x5";
	case ARM64_REG_X6: return "x6";
	case ARM64_REG_X7: return "x7";
	case ARM64_REG_X8: return "x8";
	case ARM64_REG_X9: return "x9";
	case ARM64_REG_X10: return "x10";
	case ARM64_REG_X11: return "x11";
	case ARM64_REG_X12: return "x12";
	case ARM64_REG_X13: return "x13";
	case ARM64_REG_X14: return "x14";
	case ARM64_REG_X15: return "x15";
	case ARM64_REG_X16: return "x16";
	case ARM64_REG_X17: return "x17";
	case ARM64_REG_X18: return "x18";
	case ARM64_REG_X19: return "x19";
	case ARM64_REG_X20: return "x20";
	case ARM64_REG_X21: return "x21";
	case ARM64_REG_X22: return "x22";
	case ARM64_REG_X23: return "x23";
	case ARM64_REG_X24: return "x24";
	case ARM64_REG_X25: return "x25";
	case ARM64_REG_X26: return "x26";
	case ARM64_REG_X27: return "x27";
	case ARM64_REG_X28: return "x28";
	case ARM64_REG_X29: return "x29";
	case ARM64_REG_X30: return "x30";
	case ARM64_REG_SP: return "sp";
	default: return NULL;
	}
}

static ut32 reg_bits(arm64_reg reg) {
	if (is_xreg(reg) || reg == ARM64_REG_XZR) {
		return 64;
	}
	if (is_wreg(reg) || reg == ARM64_REG_WZR) {
		return 32;
	}
	return 0;
}

/**
 * IL to read the given capstone reg
 */
static RzILOpBitVector *read_reg(/*ut64 pc, */ arm64_reg reg) {
	// if (reg == ARM64_REG_PC) {
	// 	return U32(pc);
	// }
	if (reg == ARM64_REG_XZR) {
		return U64(0);
	}
	if (reg == ARM64_REG_WZR) {
		return U32(0);
	}
	const char *var = reg_var_name(reg);
	if (!var) {
		return NULL;
	}
	if (is_wreg(reg)) {
		return UNSIGNED(32, VARG(var));
	}
	return VARG(var);
}

/**
 * Perform an unsigned cast of v or adjust an already existing one
 */
static RzILOpBitVector *adjust_unsigned(ut32 bits, RZ_OWN RzILOpBitVector *v) {
	if (v->code == RZ_IL_OP_CAST) {
		// reuse any existing cast
		v->op.cast.length = bits;
	} else if (v->code != RZ_IL_OP_BITV || rz_bv_len(v->op.bitv.value) != bits) {
		v = UNSIGNED(bits, v);
	}
	return v;
}

static RzILOpBitVector *extend(ut32 dst_bits, arm64_extender ext, RZ_OWN RzILOpBitVector *v, ut32 v_bits) {
	bool is_signed = false;
	ut32 src_bits;
	switch (ext) {
	case ARM64_EXT_SXTB:
		is_signed = true;
	case ARM64_EXT_UXTB:
		src_bits = 8;
		break;

	case ARM64_EXT_SXTH:
		is_signed = true;
	case ARM64_EXT_UXTH:
		src_bits = 16;
		break;

	case ARM64_EXT_SXTW:
		is_signed = true;
	case ARM64_EXT_UXTW:
		src_bits = 32;
		break;

	case ARM64_EXT_SXTX:
		is_signed = true;
	case ARM64_EXT_UXTX:
		src_bits = 64;
		break;

	default:
		if (dst_bits == v_bits) {
			return v;
		} else {
			return adjust_unsigned(dst_bits, v);
		}
	}

	v = adjust_unsigned(src_bits, v);
	return is_signed ? SIGNED(dst_bits, v) : UNSIGNED(dst_bits, v);
}

static RzILOpBitVector *apply_shift(arm64_shifter sft, ut32 dist, RZ_OWN RzILOpBitVector *v) {
	if (!dist) {
		return v;
	}
	switch (sft) {
	case ARM64_SFT_LSL:
		return SHIFTL0(v, UN(6, dist));
	case ARM64_SFT_LSR:
		return SHIFTR0(v, UN(6, dist));
	case ARM64_SFT_ASR:
		return SHIFTRA(v, UN(6, dist));
	default:
		return v;
	}
}

// #define PC(addr)      (addr)
#define REG_VAL(id)  read_reg(/*PC(insn->address), */ id)
#define REG(n)       REG_VAL(REGID(n))
#define REGBITS(n)   reg_bits(REGID(n))
#define MEMBASEID(x) insn->detail->arm64.operands[x].mem.base
#define MEMBASE(x)   REG_VAL(MEMBASEID(x))

/**
 * IL to write a value to the given capstone reg
 */
static RzILOpEffect *write_reg(arm64_reg reg, RZ_OWN RZ_NONNULL RzILOpBitVector *v) {
	rz_return_val_if_fail(v, NULL);
	const char *var = reg_var_name(reg);
	if (!var) {
		rz_il_op_pure_free(v);
		return NULL;
	}
	if (is_wreg(reg)) {
		v = UNSIGNED(64, v);
	}
	return SETG(var, v);
}

static RzILOpBitVector *arg_mem(RzILOpBitVector *base_plus_disp, cs_arm64_op *op) {
	if (op->mem.index != ARM64_REG_INVALID) {
		RzILOpBitVector *index = read_reg(op->mem.index);
		index = extend(64, op->ext, index, reg_bits(op->mem.index));
		index = apply_shift(op->shift.type, op->shift.value, index);
		return ADD(base_plus_disp, index);
	}
	return base_plus_disp;
}

/**
 * IL to retrieve the value of the \p n -th arg of \p insn
 */
static RzILOpBitVector *arg(cs_insn *insn, int n, ut32 *bits_inout) {
	ut32 bits_requested = bits_inout ? *bits_inout : 0;
	cs_arm64_op *op = &insn->detail->arm64.operands[n];
	switch (op->type) {
	case ARM64_OP_REG: {
		if (!bits_requested) {
			bits_requested = REGBITS(n);
			if (bits_inout) {
				*bits_inout = bits_requested;
			}
		}
		RzILOpBitVector *r = REG(n);
		if (!r) {
			return NULL;
		}
		return apply_shift(op->shift.type, op->shift.value, extend(bits_requested, op->ext, r, REGBITS(n)));
	}
	case ARM64_OP_IMM: {
		if (!bits_requested) {
			return NULL;
		}
		return UN(bits_requested, IMM(n));
	}
	case ARM64_OP_MEM: {
		RzILOpBitVector *addr = MEMBASE(n);
		st64 disp = MEMDISP(n);
		if (disp > 0) {
			addr = ADD(addr, U64(disp));
		} else if (disp < 0) {
			addr = SUB(addr, U64(-disp));
		}
		return arg_mem(addr, &insn->detail->arm64.operands[n]);
	}
	default:
		break;
	}
	return NULL;
}

#define ARG(n, bits) arg(insn, n, bits)

/**
 * zf := v == 0
 * nf := msb v
 */
static RzILOpEffect *update_flags_zn(RzILOpBitVector *v) {
	return SEQ2(
		SETG("zf", IS_ZERO(v)),
		SETG("nf", MSB(DUP(v))));
}

/**
 * zf := v == 0
 * nf := msb v
 * cf := 0
 * vf := 0
 */
static RzILOpEffect *update_flags_zn00(RzILOpBitVector *v) {
	return SEQ3(
		update_flags_zn(v),
		SETG("cf", IL_FALSE),
		SETG("vf", IL_FALSE));
}

/**
 * Capstone: ARM64_INS_ADD, ARM64_INS_ADC, ARM64_INS_SUB, ARM64_INS_SBC
 * ARM: add, adds, adc, adcs, sub, subs, sbc
 */
static RzILOpEffect *add_sub(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
#if 0
	if ((insn->id == ARM64_INS_ADD || insn->id == ARM64_INS_SUB) &&
		!insn->detail->arm.update_flags && OPCOUNT() == 3 && REGID(1) == ARM64_REG_PC && ISIMM(2)) {
		// alias for adr
		return adr(insn, is_thumb);
	}
#endif
	bool is_sub = insn->id == ARM64_INS_SUB || insn->id == ARM64_INS_SBC
#if CS_API_MAJOR > 4
		|| insn->id == ARM64_INS_SUBS || insn->id == ARM64_INS_SBCS
#endif
		;
	ut32 bits = REGBITS(0);
	RzILOpBitVector *a = ARG(1, &bits);
	RzILOpBitVector *b = ARG(2, &bits);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	RzILOpBitVector *res = is_sub ? SUB(a, b) : ADD(a, b);
	bool with_carry = false;
	if (insn->id == ARM64_INS_ADC
#if CS_API_MAJOR > 4
		|| insn->id == ARM64_INS_ADCS
#endif
	) {
		res = ADD(res, ITE(VARG("cf"), UN(bits, 1), UN(bits, 0)));
		with_carry = true;
	} else if (insn->id == ARM64_INS_SBC
#if CS_API_MAJOR > 4
		|| insn->id == ARM64_INS_SBCS
#endif
	) {
		res = SUB(res, ITE(VARG("cf"), UN(bits, 0), UN(bits, 1)));
		with_carry = true;
	}
	RzILOpEffect *set = write_reg(REGID(0), res);
	bool update_flags = insn->detail->arm64.update_flags;
	if (update_flags) {
		return SEQ6(
			SETL("a", DUP(a)),
			SETL("b", DUP(b)),
			set,
			SETG("cf", is_sub ? sub_carry(VARL("a"), VARL("b"), with_carry) : add_carry(VARL("a"), VARL("b"), with_carry)),
			SETG("vf", (is_sub ? sub_overflow : add_overflow)(VARL("a"), VARL("b"), REG(0))),
			update_flags_zn(REG(0)));
	}
	return set;
}

/**
 * Capstone: ARM64_INS_ADR, ARM64_INS_ADRP
 * ARM: adr, adrp
 */
static RzILOpEffect *adr(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	return write_reg(REGID(0), U64(IMM(1)));
}

/**
 * Capstone: ARM64_INS_AND, ARM64_INS_EON, ARM64_INS_EOR
 * ARM: and, eon, eor
 */
static RzILOpEffect *bitwise(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	RzILOpBitVector *a = ARG(1, &bits);
	RzILOpBitVector *b = ARG(2, &bits);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	RzILOpBitVector *res;
	switch (insn->id) {
	case ARM64_INS_EOR:
		res = LOGXOR(a, b);
		break;
	case ARM64_INS_EON:
		res = LOGXOR(a, LOGNOT(b));
		break;
	default: // ARM64_INS_AND
		res = LOGAND(a, b);
		break;
	}
	RzILOpEffect *eff = write_reg(REGID(0), res);
	if (!eff) {
		return NULL;
	}
	if (insn->detail->arm64.update_flags) {
		return SEQ2(eff, update_flags_zn00(REG(0)));
	}
	return eff;
}

/**
 * Capstone: ARM64_INS_ASR, ARM64_INS_LSL, ARM64_INS_LSR
 * ARM: asr, asrv, lsl, lslv, lsr, lsrv
 */
static RzILOpEffect *shift(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	RzILOpBitVector *a = ARG(1, &bits);
	if (!a) {
		return NULL;
	}
	bits = bits == 32 ? 5 : 6; // cast to log2(bits) to perform exactly mod bits
	RzILOpBitVector *b = ARG(2, &bits);
	if (!b) {
		rz_il_op_pure_free(a);
		return NULL;
	}
	RzILOpBitVector *res;
	switch (insn->id) {
	case ARM64_INS_ASR:
		res = SHIFTRA(a, b);
		break;
	case ARM64_INS_LSR:
		res = SHIFTR0(a, b);
		break;
	default: // ARM64_INS_LSL
		res = SHIFTL0(a, b);
		break;
	}
	return write_reg(REGID(0), res);
}

/**
 * Capstone: ARM64_INS_B
 * ARM: b, b.cond
 */
static RzILOpEffect *branch(cs_insn *insn) {
	ut32 bits = 64;
	RzILOpBitVector *a = ARG(0, &bits);
	if (!a) {
		return NULL;
	}
	RzILOpBool *c = cond(insn->detail->arm64.cc);
	if (c) {
		return BRANCH(c, JMP(a), NOP);
	}
	return JMP(a);
}

/**
 * Capstone: ARM64_INS_BL, ARM64_INS_BLR, ARM64_INS_BLRAA, ARM64_INS_BLRAAZ, ARM64_INS_BLRAB, ARM64_INS_BLRABZ
 * ARM: bl, blr, blraa, blraaz, blrab, blrabz
 */
static RzILOpEffect *bl(cs_insn *insn) {
	ut32 bits = 64;
	RzILOpBitVector *a = ARG(0, &bits);
	if (!a) {
		return NULL;
	}
	return SEQ2(
		SETG("x30", U64(insn->address + 4)),
		JMP(a));
}

/**
 * Capstone: ARM64_INS_BFM, ARM64_INS_BFI, ARM64_INS_BFXIL
 * ARM: bfm, bfc, bfi, bfxil
 */
static RzILOpEffect *bfm(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = 0;
	RzILOpBitVector *a = ARG(0, &bits);
	if (!a) {
		return NULL;
	}
	if (ISIMM(1) && ISIMM(2)) {
		// bfc
		ut64 mask = rz_num_bitmask(IMM(2)) << RZ_MIN(63, IMM(1));
		return write_reg(REGID(0), LOGAND(a, UN(bits, mask)));
	}
	RzILOpBitVector *b = ARG(1, &bits);
	if (!b) {
		return NULL;
	}
	ut64 mask_base = rz_num_bitmask(IMM(3));
	ut64 mask = mask_base << RZ_MIN(63, IMM(2));
	if (insn->id == ARM64_INS_BFI) {
		return write_reg(REGID(0), LOGOR(LOGAND(a, UN(bits, ~mask)), SHIFTL0(LOGAND(b, UN(bits, mask_base)), UN(6, IMM(2)))));
	}
	// insn->id == ARM64_INS_BFXIL
	return write_reg(REGID(0), LOGOR(LOGAND(a, UN(bits, ~mask_base)), SHIFTR0(LOGAND(b, UN(bits, mask)), UN(6, IMM(2)))));
}

/**
 * Capstone: ARM64_INS_BIC, ARM64_INS_BICS
 * ARM: bic, bics
 */
static RzILOpEffect *bic(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	RzILOpBitVector *a = ARG(1, &bits);
	RzILOpBitVector *b = ARG(2, &bits);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	RzILOpEffect *eff = write_reg(REGID(0), LOGAND(a, LOGNOT(b)));
	if (!eff) {
		return NULL;
	}
	if (insn->detail->arm64.update_flags) {
		return SEQ2(eff, update_flags_zn00(REG(0)));
	}
	return eff;
}

#if CS_API_MAJOR > 4
/**
 * Capstone: ARM64_INS_CAS, ARM64_INS_CASA, ARM64_INS_CASAL, ARM64_INS_CASL,
 *           ARM64_INS_CASB, ARM64_INS_CASAB, ARM64_INS_CASALB, ARM64_INS_CASLB,
 *           ARM64_INS_CASH, ARM64_INS_CASAH, ARM64_INS_CASALH, ARM64_INS_CASLH:
 * ARM: cas, casa, casal, casl, casb, casab, casalb, caslb, cash, casah, casalh, caslh
 */
static RzILOpEffect *cas(cs_insn *insn) {
	if (!ISREG(0) || !ISMEM(2)) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	switch (insn->id) {
	case ARM64_INS_CASB:
	case ARM64_INS_CASAB:
	case ARM64_INS_CASALB:
	case ARM64_INS_CASLB:
		bits = 8;
		break;
	case ARM64_INS_CASH:
	case ARM64_INS_CASAH:
	case ARM64_INS_CASALH:
	case ARM64_INS_CASLH:
		bits = 16;
		break;
	default:
		break;
	}
	RzILOpBitVector *addr = ARG(2, NULL);
	RzILOpBitVector *cmpval = ARG(0, &bits);
	RzILOpBitVector *newval = ARG(1, &bits);
	RzILOpEffect *write_old_eff = write_reg(REGID(0), VARL("old"));
	if (!addr || !cmpval || !newval || !write_old_eff) {
		rz_il_op_pure_free(addr);
		rz_il_op_pure_free(cmpval);
		rz_il_op_pure_free(newval);
		rz_il_op_effect_free(write_old_eff);
		return NULL;
	}
	return SEQ3(
		SETL("old", bits == 8 ? LOAD(addr) : LOADW(bits, addr)),
		BRANCH(EQ(VARL("old"), cmpval), bits == 8 ? STORE(DUP(addr), newval) : STOREW(DUP(addr), newval), NULL),
		write_old_eff);
}

/**
 * Capstone: ARM64_INS_CASP, ARM64_INS_CASPA, ARM64_INS_CASPAL, ARM64_INS_CASPL
 * ARM: casp, caspa, caspal, caspl
 */
static RzILOpEffect *casp(cs_insn *insn) {
	if (!ISREG(0) || !ISREG(1) || !ISMEM(4)) {
		return NULL;
	}
	RzILOpBitVector *addr = ARG(4, NULL);
	ut32 bits = 0;
	RzILOpBitVector *cmpval0 = ARG(0, &bits);
	RzILOpBitVector *cmpval1 = ARG(1, &bits);
	RzILOpBitVector *newval0 = ARG(2, &bits);
	RzILOpBitVector *newval1 = ARG(3, &bits);
	RzILOpEffect *write_old0_eff = write_reg(REGID(0), VARL("old0"));
	RzILOpEffect *write_old1_eff = write_reg(REGID(1), VARL("old1"));
	if (!addr || !cmpval0 || !cmpval1 || !newval0 || !newval1 || !write_old0_eff || !write_old1_eff) {
		rz_il_op_pure_free(addr);
		rz_il_op_pure_free(cmpval0);
		rz_il_op_pure_free(cmpval1);
		rz_il_op_pure_free(newval0);
		rz_il_op_pure_free(newval1);
		rz_il_op_effect_free(write_old0_eff);
		rz_il_op_effect_free(write_old1_eff);
		return NULL;
	}
	return SEQ5(
		SETL("old0", LOADW(bits, addr)),
		SETL("old1", LOADW(bits, ADD(DUP(addr), U64(bits / 8)))),
		BRANCH(AND(EQ(VARL("old0"), cmpval0), EQ(VARL("old1"), cmpval1)),
			SEQ2(
				STOREW(DUP(addr), newval0),
				STOREW(ADD(DUP(addr), U64(bits / 8)), newval1)),
			NULL),
		write_old0_eff,
		write_old1_eff);
}
#endif

/**
 * Capstone: ARM64_INS_CBZ, ARM64_INS_CBNZ
 * ARM: cbz, cbnz
 */
static RzILOpEffect *cbz(cs_insn *insn) {
	RzILOpBitVector *v = ARG(0, NULL);
	ut32 bits = 64;
	RzILOpBitVector *tgt = ARG(1, &bits);
	if (!v || !tgt) {
		rz_il_op_pure_free(v);
		rz_il_op_pure_free(tgt);
		return NULL;
	}
	return BRANCH(insn->id == ARM64_INS_CBNZ ? INV(IS_ZERO(v)) : IS_ZERO(v), JMP(tgt), NULL);
}

/**
 * Capstone: ARM64_INS_CMP, ARM64_INS_CMN, ARM64_INS_CCMP, ARM64_INS_CCMN
 * ARM: cmp, cmn, ccmp, ccmn
 */
static RzILOpEffect *cmp(cs_insn *insn) {
	ut32 bits = 0;
	RzILOpBitVector *a = ARG(0, &bits);
	RzILOpBitVector *b = ARG(1, &bits);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	bool is_neg = insn->id == ARM64_INS_CMN || insn->id == ARM64_INS_CCMN;
	RzILOpEffect *eff = SEQ6(
		SETL("a", DUP(a)),
		SETL("b", DUP(b)),
		SETL("r", is_neg ? ADD(VARL("a"), VARL("b")) : SUB(VARL("a"), VARL("b"))),
		SETG("cf", (is_neg ? add_carry : sub_carry)(VARL("a"), VARL("b"), false)),
		SETG("vf", (is_neg ? add_overflow : sub_overflow)(VARL("a"), VARL("b"), VARL("r"))),
		update_flags_zn(VARL("r")));
	RzILOpBool *c = cond(insn->detail->arm64.cc);
	if (c) {
		ut64 imm = IMM(2);
		return BRANCH(c,
			eff,
			SEQ4(
				SETG("nf", imm & (1 << 3) ? IL_TRUE : IL_FALSE),
				SETG("zf", imm & (1 << 2) ? IL_TRUE : IL_FALSE),
				SETG("cf", imm & (1 << 1) ? IL_TRUE : IL_FALSE),
				SETG("vf", imm & (1 << 0) ? IL_TRUE : IL_FALSE)));
	}
	return eff;
}

/**
 * Capstone: ARM64_INS_CINC, ARM64_INS_CSINC, ARM64_INS_CINV, ARM64_INS_CSINV, ARM64_INS_CNEG, ARM64_INS_CSNEG, ARM64_INS_CSEL
 * ARM: cinc, csinc, cinv, csinv, cneg, csneg, csel
 */
static RzILOpEffect *csinc(cs_insn *insn) {
	size_t dst_idx = 0;
	size_t src0_idx = 1;
	size_t src1_idx = OPCOUNT() > 2 ? 2 : 1;
	if (!ISREG(dst_idx)) {
		return NULL;
	}
	ut32 bits = REGBITS(dst_idx);
	RzILOpBitVector *src0 = ARG(src0_idx, &bits);
	if (!src0) {
		return NULL;
	}
	RzILOpBool *c = cond(insn->detail->arm64.cc);
	if (!c) {
		// al/nv conditions, only possible in cs(inc|inv|neg)
		return write_reg(REGID(dst_idx), src0);
	}
	RzILOpBitVector *src1 = ARG(src1_idx, &bits);
	if (!src1) {
		rz_il_op_pure_free(src0);
		rz_il_op_pure_free(c);
		return NULL;
	}
	RzILOpBitVector *res;
	bool invert_cond = false;
	switch (insn->id) {
	case ARM64_INS_CSEL:
		invert_cond = true;
		res = src1;
		break;
	case ARM64_INS_CSINV:
		invert_cond = true;
	case ARM64_INS_CINV:
		res = LOGNOT(src1);
		break;
	case ARM64_INS_CSNEG:
		invert_cond = true;
	case ARM64_INS_CNEG:
		res = NEG(src1);
		break;
	case ARM64_INS_CSINC:
		invert_cond = true;
	default: // ARM64_INS_CINC, ARM64_INS_CSINC
		res = ADD(src1, UN(bits, 1));
		break;
	}
	return write_reg(REGID(dst_idx), invert_cond ? ITE(c, src0, res) : ITE(c, res, src0));
}

/**
 * Capstone: ARM64_INS_CSET, ARM64_INS_CSETM
 * ARM: cset, csetm
 */
static RzILOpEffect *cset(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBool *c = cond(insn->detail->arm64.cc);
	if (!c) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	return write_reg(REGID(0), ITE(c, SN(bits, insn->id == ARM64_INS_CSETM ? -1 : 1), SN(bits, 0)));
}

/**
 * Capstone: ARM64_INS_CLS
 * ARM: cls
 */
static RzILOpEffect *cls(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = 0;
	RzILOpBitVector *v = ARG(1, &bits);
	if (!v) {
		return NULL;
	}
	return SEQ5(
		SETL("v", v),
		SETL("i", SN(bits, -1)),
		SETL("msb", MSB(VARL("v"))),
		REPEAT(INV(XOR(MSB(VARL("v")), VARL("msb"))),
			SEQ2(
				SETL("v", SHIFTL(INV(VARL("msb")), VARL("v"), UN(6, 1))),
				SETL("i", ADD(VARL("i"), UN(bits, 1))))),
		write_reg(REGID(0), VARL("i")));
}

/**
 * Capstone: ARM64_INS_CLZ
 * ARM: clz
 */
static RzILOpEffect *clz(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = 0;
	RzILOpBitVector *v = ARG(1, &bits);
	if (!v) {
		return NULL;
	}
	return SEQ4(
		SETL("v", v),
		SETL("i", UN(bits, bits)),
		REPEAT(INV(IS_ZERO(VARL("v"))),
			SEQ2(
				SETL("v", SHIFTR0(VARL("v"), UN(6, 1))),
				SETL("i", SUB(VARL("i"), UN(bits, 1))))),
		write_reg(REGID(0), VARL("i")));
}

/**
 * Capstone: ARM64_INS_EXTR
 * ARM: extr
 */
static RzILOpEffect *extr(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	RzILOpBitVector *h = ARG(1, &bits);
	RzILOpBitVector *l = ARG(2, &bits);
	ut32 dist_bits = 6;
	RzILOpBitVector *dist = ARG(3, &dist_bits);
	if (!h || !l || !dist) {
		rz_il_op_pure_free(h);
		rz_il_op_pure_free(l);
		rz_il_op_pure_free(dist);
		return NULL;
	}
	return write_reg(REGID(0), UNSIGNED(bits, SHIFTR0(APPEND(h, l), dist)));
}

/**
 * Capstone: ARM_INS_SVC
 * ARM: svc
 */
static RzILOpEffect *svc(cs_insn *insn) {
	return GOTO("svc");
}

static void label_svc(RzILVM *vm, RzILOpEffect *op) {
	// stub, nothing to do here
}

/**
 * Capstone: ARM64_INS_HVC
 * ARM: hvc
 */
static RzILOpEffect *hvc(cs_insn *insn) {
	return GOTO("hvc");
}

static void label_hvc(RzILVM *vm, RzILOpEffect *op) {
	// stub, nothing to do here
}

static RzILOpEffect *load_effect(ut32 bits, bool is_signed, arm64_reg dst_reg, RZ_OWN RzILOpBitVector *addr) {
	RzILOpBitVector *val = bits == 8 ? LOAD(addr) : LOADW(bits, addr);
	if (bits != 64) {
		if (is_signed) {
			if (is_wreg(dst_reg)) {
				val = UNSIGNED(64, SIGNED(32, val));
			} else {
				val = SIGNED(64, val);
			}
		} else {
			val = UNSIGNED(64, val);
		}
	}
	dst_reg = xreg_of_reg(dst_reg);
	return write_reg(dst_reg, val);
}

/**
 * Capstone: ARM64_INS_LDR, ARM64_INS_LDRB, ARM64_INS_LDRH, ARM64_INS_LDRU, ARM64_INS_LDRUB, ARM64_INS_LDRUH,
 *           ARM64_INS_LDRSW, ARM64_INS_LDRSB, ARM64_INS_LDRSH, ARM64_INS_LDURSW, ARM64_INS_LDURSB, ARM64_INS_LDURSH,
 *           ARM64_INS_LDAPR, ARM64_INS_LDAPRB, ARM64_INS_LDAPRH, ARM64_INS_LDAPUR, ARM64_INS_LDAPURB, ARM64_INS_LDAPURH,
 *           ARM64_INS_LDAPURSB, ARM64_INS_LDAPURSH, ARM64_INS_LDAPURSW, ARM64_INS_LDAR, ARM64_INS_LDARB, ARM64_INS_LDARH,
 *           ARM64_INS_LDAXP, ARM64_INS_LDXP, ARM64_INS_LDAXR, ARM64_INS_LDAXRB, ARM64_INS_LDAXRH,
 *           ARM64_INS_LDLAR, ARM64_INS_LDLARB, ARM64_INS_LDLARH,
 *           ARM64_INS_LDP, ARM64_INS_LDNP, ARM64_INS_LDPSW,
 *           ARM64_INS_LDRAA, ARM64_INS_LDRAB,
 *           ARM64_INS_LDTR, ARM64_INS_LDTRB, ARM64_INS_LDTRH, ARM64_INS_LDTRSW, ARM64_INS_LDTRSB, ARM64_INS_LDTRSH,
 *           ARM64_INS_LDXR, ARM64_INS_LDXRB, ARM64_INS_LDXRH
 * ARM: ldr, ldrb, ldrh, ldru, ldrub, ldruh, ldrsw, ldrsb, ldrsh, ldursw, ldurwb, ldursh,
 *      ldapr, ldaprb, ldaprh, ldapur, ldapurb, ldapurh, ldapursb, ldapursh, ldapursw,
 *      ldaxp, ldxp, ldaxr, ldaxrb, ldaxrh, ldar, ldarb, ldarh,
 *      ldp, ldnp,
 *      ldtr, ldtrb, ldtrh, ldtrsw, ldtrsb, ldtrsh, ldxr, ldxrb, ldxrh
 */
static RzILOpEffect *ldr(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	bool pair = insn->id == ARM64_INS_LDAXP || insn->id == ARM64_INS_LDXP ||
		insn->id == ARM64_INS_LDP || insn->id == ARM64_INS_LDNP || insn->id == ARM64_INS_LDPSW;
	if (pair && !ISREG(1)) {
		return NULL;
	}
	ut32 bits = 64;
	size_t addr_op = pair ? 2 : 1;
	RzILOpBitVector *addr = ARG(addr_op, &bits);
	if (!addr) {
		return NULL;
	}
	arm64_reg dst_reg = REGID(0);
	ut64 loadsz;
	bool is_signed = false;
	switch (insn->id) {
	case ARM64_INS_LDRSB:
	case ARM64_INS_LDURSB:
	case ARM64_INS_LDTRSB:
#if CS_API_MAJOR > 4
	case ARM64_INS_LDAPURSB:
#endif
		is_signed = true;
	case ARM64_INS_LDRB:
	case ARM64_INS_LDURB:
	case ARM64_INS_LDARB:
	case ARM64_INS_LDAXRB:
	case ARM64_INS_LDTRB:
	case ARM64_INS_LDXRB:
#if CS_API_MAJOR > 4
	case ARM64_INS_LDLARB:
	case ARM64_INS_LDAPRB:
	case ARM64_INS_LDAPURB:
#endif
		loadsz = 8;
		break;
	case ARM64_INS_LDRSH:
	case ARM64_INS_LDURSH:
	case ARM64_INS_LDTRSH:
#if CS_API_MAJOR > 4
	case ARM64_INS_LDAPURSH:
#endif
		is_signed = true;
	case ARM64_INS_LDRH:
	case ARM64_INS_LDURH:
	case ARM64_INS_LDARH:
	case ARM64_INS_LDAXRH:
	case ARM64_INS_LDTRH:
	case ARM64_INS_LDXRH:
#if CS_API_MAJOR > 4
	case ARM64_INS_LDAPRH:
	case ARM64_INS_LDAPURH:
	case ARM64_INS_LDLARH:
#endif
		loadsz = 16;
		break;
	case ARM64_INS_LDRSW:
	case ARM64_INS_LDURSW:
	case ARM64_INS_LDPSW:
	case ARM64_INS_LDTRSW:
#if CS_API_MAJOR > 4
	case ARM64_INS_LDAPURSW:
#endif
		is_signed = true;
		loadsz = 32;
		break;
	default:
		// ARM64_INS_LDR, ARM64_INS_LDRU, ARM64_INS_LDAPR, ARM64_INS_LDAPUR, ARM64_INS_LDAR, ARM64_INS_LDAXR, ARM64_INS_LDLAR,
		// ARM64_INS_LDP, ARM64_INS_LDNP, ARM64_INS_LDRAA, ARM64_INS_LDRAB, ARM64_INS_LDTR, ARM64_INS_LDXR
		loadsz = is_wreg(dst_reg) ? 32 : 64;
		break;
	}
	RzILOpEffect *eff = load_effect(loadsz, is_signed, dst_reg, addr);
	if (!eff) {
		return NULL;
	}
	if (pair) {
		RzILOpEffect *eff1 = load_effect(loadsz, is_signed, REGID(1), ADD(DUP(addr), U64(loadsz / 8)));
		if (!eff1) {
			rz_il_op_effect_free(eff);
			return NULL;
		}
		eff = SEQ2(eff, eff1);
	}
	bool writeback = insn->detail->arm64.writeback;
	if (writeback && is_xreg(MEMBASEID(addr_op))) {
		RzILOpBitVector *wbaddr = DUP(addr);
		if (ISIMM(addr_op + 1)) {
			// post-index
			st64 disp = IMM(addr_op + 1);
			if (disp > 0) {
				wbaddr = ADD(wbaddr, U64(disp));
			} else if (disp < 0) {
				wbaddr = SUB(wbaddr, U64(-disp));
			}
		}
		RzILOpEffect *wb_eff = write_reg(MEMBASEID(addr_op), wbaddr);
		if (!wb_eff) {
			rz_il_op_effect_free(eff);
			return NULL;
		}
		eff = SEQ2(eff, wb_eff);
	}
	return eff;
}

#if CS_API_MAJOR > 4
/**
 * Capstone: ARM64_INS_LDADD, ARM64_INS_LDADDA, ARM64_INS_LDADDAL, ARM64_INS_LDADDL,
 *           ARM64_INS_LDADDB, ARM64_INS_LDADDAB, ARM64_INS_LDADDALB, ARM64_INS_LDADDLB,
 *           ARM64_INS_LDADDH, ARM64_INS_LDADDAH, ARM64_INS_LDADDALH, ARM64_INS_LDADDLH,
 *           ARM64_INS_STADD, ARM64_INS_STADDL, ARM64_INS_STADDB, ARM64_INS_STADDLB, ARM64_INS_STADDH, ARM64_INS_STADDLH,
 *           ARM64_INS_LDCLRB, ARM64_INS_LDCLRAB, ARM64_INS_LDCLRALB, ARM64_INS_LDCLRLB,
 *           ARM64_INS_LDCLRH, ARM64_INS_LDCLRAH, ARM64_INS_LDCLRALH, ARM64_INS_LDCLRLH
 *           ARM64_INS_LDCLR, ARM64_INS_LDCLRA, ARM64_INS_LDCLRAL, ARM64_INS_LDCLRL,
 *           ARM64_INS_STSETB, ARM64_INS_STSETLB, ARM64_INS_STSETH, ARM64_INS_STSETLH, ARM64_INS_STSET, ARM64_INS_STSETL,
 *           ARM64_INS_LDSETB, ARM64_INS_LDSETAB, ARM64_INS_LDSETALB, ARM64_INS_LDSETLB,
 *           ARM64_INS_LDSETH, ARM64_INS_LDSETAH, ARM64_INS_LDSETALH, ARM64_INS_LDSETLH
 *           ARM64_INS_LDSET, ARM64_INS_LDSETA, ARM64_INS_LDSETAL, ARM64_INS_LDSETL,
 *           ARM64_INS_STSETB, ARM64_INS_STSETLB, ARM64_INS_STSETH, ARM64_INS_STSETLH, ARM64_INS_STSET, ARM64_INS_STSETL,
 *           ARM64_INS_LDSMAXB, ARM64_INS_LDSMAXAB, ARM64_INS_LDSMAXALB, ARM64_INS_LDSMAXLB,
 *           ARM64_INS_LDSMAXH, ARM64_INS_LDSMAXAH, ARM64_INS_LDSMAXALH, ARM64_INS_LDSMAXLH
 *           ARM64_INS_LDSMAX, ARM64_INS_LDSMAXA, ARM64_INS_LDSMAXAL, ARM64_INS_LDSMAXL,
 *           ARM64_INS_STSMAXB, ARM64_INS_STSMAXLB, ARM64_INS_STSMAXH, ARM64_INS_STSMAXLH, ARM64_INS_STSMAX, ARM64_INS_STSMAXL,
 *           ARM64_INS_LDSMINB, ARM64_INS_LDSMINAB, ARM64_INS_LDSMINALB, ARM64_INS_LDSMINLB,
 *           ARM64_INS_LDSMINH, ARM64_INS_LDSMINAH, ARM64_INS_LDSMINALH, ARM64_INS_LDSMINLH
 *           ARM64_INS_LDSMIN, ARM64_INS_LDSMINA, ARM64_INS_LDSMINAL, ARM64_INS_LDSMINL,
 *           ARM64_INS_STSMINB, ARM64_INS_STSMINLB, ARM64_INS_STSMINH, ARM64_INS_STSMINLH, ARM64_INS_STSMIN, ARM64_INS_STSMINL,
 *           ARM64_INS_LDUMAXB, ARM64_INS_LDUMAXAB, ARM64_INS_LDUMAXALB, ARM64_INS_LDUMAXLB,
 *           ARM64_INS_LDUMAXH, ARM64_INS_LDUMAXAH, ARM64_INS_LDUMAXALH, ARM64_INS_LDUMAXLH
 *           ARM64_INS_LDUMAX, ARM64_INS_LDUMAXA, ARM64_INS_LDUMAXAL, ARM64_INS_LDUMAXL,
 *           ARM64_INS_STUMAXB, ARM64_INS_STUMAXLB, ARM64_INS_STUMAXH, ARM64_INS_STUMAXLH, ARM64_INS_STUMAX, ARM64_INS_STUMAXL,
 *           ARM64_INS_LDUMINB, ARM64_INS_LDUMINAB, ARM64_INS_LDUMINALB, ARM64_INS_LDUMINLB,
 *           ARM64_INS_LDUMINH, ARM64_INS_LDUMINAH, ARM64_INS_LDUMINALH, ARM64_INS_LDUMINLH
 *           ARM64_INS_LDUMIN, ARM64_INS_LDUMINA, ARM64_INS_LDUMINAL, ARM64_INS_LDUMINL,
 *           ARM64_INS_STUMINB, ARM64_INS_STUMINLB, ARM64_INS_STUMINH, ARM64_INS_STUMINLH, ARM64_INS_STUMIN, ARM64_INS_STUMINL
 * ARM: ldadd, ldadda, ldaddal, ldaddl, ldaddb, ldaddab, ldaddalb, ldaddlb, ldaddh, ldaddah, ldaddalh, ldaddlh,
 *      stadd, staddl, staddb, staddlb, stadd,
 *      ldclr, ldclra, ldclral, ldclrl, ldclrb, ldclrab, ldclralb, ldclrlb, ldclrh, ldclrah, ldclralh, ldclrlh,
 *      stclr, stclrl, stclrb, stclrlb, stclr,
 *      ldset, ldseta, ldsetal, ldsetl, ldsetb, ldsetab, ldsetalb, ldsetlb, ldseth, ldsetah, ldsetalh, ldsetlh,
 *      stset, stsetl, stsetb, stsetlb, stset,
 *      ldsmax, ldsmaxa, ldsmaxal, ldsmaxl, ldsmaxb, ldsmaxab, ldsmaxalb, ldsmaxlb, ldsmaxh, ldsmaxah, ldsmaxalh, ldsmaxlh,
 *      stsmax, stsmaxl, stsmaxb, stsmaxlb, stsmax,
 *      ldsmin, ldsmina, ldsminal, ldsminl, ldsminb, ldsminab, ldsminalb, ldsminlb, ldsminh, ldsminah, ldsminalh, ldsminlh,
 *      stsmin, stsminl, stsminb, stsminlb, stsmin,
 *      ldumax, ldumaxa, ldumaxal, ldumaxl, ldumaxb, ldumaxab, ldumaxalb, ldumaxlb, ldumaxh, ldumaxah, ldumaxalh, ldumaxlh,
 *      stumax, stumaxl, stumaxb, stumaxlb, stumax,
 *      ldumin, ldumina, lduminal, lduminl, lduminb, lduminab, lduminalb, lduminlb, lduminh, lduminah, lduminalh, lduminlh,
 *      stumin, stuminl, stuminb, stuminlb, stumin
 */
static RzILOpEffect *ldadd(cs_insn *insn) {
	size_t addr_op = OPCOUNT() == 3 ? 2 : 1;
	if (!ISMEM(addr_op)) {
		return NULL;
	}
	arm64_reg addend_reg = REGID(0);
	ut64 loadsz;
	enum {
		OP_ADD,
		OP_CLR,
		OP_EOR,
		OP_SET,
		OP_SMAX,
		OP_SMIN,
		OP_UMAX,
		OP_UMIN
	} op = OP_ADD;
	switch (insn->id) {
	case ARM64_INS_LDCLRB:
	case ARM64_INS_LDCLRAB:
	case ARM64_INS_LDCLRALB:
	case ARM64_INS_LDCLRLB:
	case ARM64_INS_STCLRB:
	case ARM64_INS_STCLRLB:
		op = OP_CLR;
		loadsz = 8;
		break;
	case ARM64_INS_LDEORB:
	case ARM64_INS_LDEORAB:
	case ARM64_INS_LDEORALB:
	case ARM64_INS_LDEORLB:
	case ARM64_INS_STEORB:
	case ARM64_INS_STEORLB:
		op = OP_EOR;
		loadsz = 8;
		break;
	case ARM64_INS_LDSETB:
	case ARM64_INS_LDSETAB:
	case ARM64_INS_LDSETALB:
	case ARM64_INS_LDSETLB:
	case ARM64_INS_STSETB:
	case ARM64_INS_STSETLB:
		op = OP_SET;
		loadsz = 8;
		break;
	case ARM64_INS_LDSMAXB:
	case ARM64_INS_LDSMAXAB:
	case ARM64_INS_LDSMAXALB:
	case ARM64_INS_LDSMAXLB:
	case ARM64_INS_STSMAXB:
	case ARM64_INS_STSMAXLB:
		op = OP_SMAX;
		loadsz = 8;
		break;
	case ARM64_INS_LDSMINB:
	case ARM64_INS_LDSMINAB:
	case ARM64_INS_LDSMINALB:
	case ARM64_INS_LDSMINLB:
	case ARM64_INS_STSMINB:
	case ARM64_INS_STSMINLB:
		op = OP_SMIN;
		loadsz = 8;
		break;
	case ARM64_INS_LDUMAXB:
	case ARM64_INS_LDUMAXAB:
	case ARM64_INS_LDUMAXALB:
	case ARM64_INS_LDUMAXLB:
	case ARM64_INS_STUMAXB:
	case ARM64_INS_STUMAXLB:
		op = OP_UMAX;
		loadsz = 8;
		break;
	case ARM64_INS_LDUMINB:
	case ARM64_INS_LDUMINAB:
	case ARM64_INS_LDUMINALB:
	case ARM64_INS_LDUMINLB:
	case ARM64_INS_STUMINB:
	case ARM64_INS_STUMINLB:
		op = OP_UMIN;
		loadsz = 8;
		break;
	case ARM64_INS_LDADDB:
	case ARM64_INS_LDADDAB:
	case ARM64_INS_LDADDALB:
	case ARM64_INS_LDADDLB:
	case ARM64_INS_STADDB:
	case ARM64_INS_STADDLB:
		loadsz = 8;
		break;

	case ARM64_INS_LDCLRH:
	case ARM64_INS_LDCLRAH:
	case ARM64_INS_LDCLRALH:
	case ARM64_INS_LDCLRLH:
	case ARM64_INS_STCLRH:
	case ARM64_INS_STCLRLH:
		op = OP_CLR;
		loadsz = 16;
		break;
	case ARM64_INS_LDEORH:
	case ARM64_INS_LDEORAH:
	case ARM64_INS_LDEORALH:
	case ARM64_INS_LDEORLH:
	case ARM64_INS_STEORH:
	case ARM64_INS_STEORLH:
		op = OP_EOR;
		loadsz = 16;
		break;
	case ARM64_INS_LDSETH:
	case ARM64_INS_LDSETAH:
	case ARM64_INS_LDSETALH:
	case ARM64_INS_LDSETLH:
	case ARM64_INS_STSETH:
	case ARM64_INS_STSETLH:
		op = OP_SET;
		loadsz = 16;
		break;
	case ARM64_INS_LDSMAXH:
	case ARM64_INS_LDSMAXAH:
	case ARM64_INS_LDSMAXALH:
	case ARM64_INS_LDSMAXLH:
	case ARM64_INS_STSMAXH:
	case ARM64_INS_STSMAXLH:
		op = OP_SMAX;
		loadsz = 16;
		break;
	case ARM64_INS_LDSMINH:
	case ARM64_INS_LDSMINAH:
	case ARM64_INS_LDSMINALH:
	case ARM64_INS_LDSMINLH:
	case ARM64_INS_STSMINH:
	case ARM64_INS_STSMINLH:
		op = OP_SMIN;
		loadsz = 16;
		break;
	case ARM64_INS_LDUMAXH:
	case ARM64_INS_LDUMAXAH:
	case ARM64_INS_LDUMAXALH:
	case ARM64_INS_LDUMAXLH:
	case ARM64_INS_STUMAXH:
	case ARM64_INS_STUMAXLH:
		op = OP_UMAX;
		loadsz = 16;
		break;
	case ARM64_INS_LDUMINH:
	case ARM64_INS_LDUMINAH:
	case ARM64_INS_LDUMINALH:
	case ARM64_INS_LDUMINLH:
	case ARM64_INS_STUMINH:
	case ARM64_INS_STUMINLH:
		op = OP_UMIN;
		loadsz = 16;
		break;
	case ARM64_INS_LDADDH:
	case ARM64_INS_LDADDAH:
	case ARM64_INS_LDADDALH:
	case ARM64_INS_LDADDLH:
	case ARM64_INS_STADDH:
	case ARM64_INS_STADDLH:
		loadsz = 16;
		break;

	case ARM64_INS_LDCLR:
	case ARM64_INS_LDCLRA:
	case ARM64_INS_LDCLRAL:
	case ARM64_INS_LDCLRL:
	case ARM64_INS_STCLR:
	case ARM64_INS_STCLRL:
		op = OP_CLR;
		goto size_from_reg;
	case ARM64_INS_LDEOR:
	case ARM64_INS_LDEORA:
	case ARM64_INS_LDEORAL:
	case ARM64_INS_LDEORL:
	case ARM64_INS_STEOR:
	case ARM64_INS_STEORL:
		op = OP_EOR;
		goto size_from_reg;
	case ARM64_INS_LDSET:
	case ARM64_INS_LDSETA:
	case ARM64_INS_LDSETAL:
	case ARM64_INS_LDSETL:
	case ARM64_INS_STSET:
	case ARM64_INS_STSETL:
		op = OP_SET;
		goto size_from_reg;
	case ARM64_INS_LDSMAX:
	case ARM64_INS_LDSMAXA:
	case ARM64_INS_LDSMAXAL:
	case ARM64_INS_LDSMAXL:
	case ARM64_INS_STSMAX:
	case ARM64_INS_STSMAXL:
		op = OP_SMAX;
		goto size_from_reg;
	case ARM64_INS_LDSMIN:
	case ARM64_INS_LDSMINA:
	case ARM64_INS_LDSMINAL:
	case ARM64_INS_LDSMINL:
	case ARM64_INS_STSMIN:
	case ARM64_INS_STSMINL:
		op = OP_SMIN;
		goto size_from_reg;
	case ARM64_INS_LDUMAX:
	case ARM64_INS_LDUMAXA:
	case ARM64_INS_LDUMAXAL:
	case ARM64_INS_LDUMAXL:
	case ARM64_INS_STUMAX:
	case ARM64_INS_STUMAXL:
		op = OP_UMAX;
		goto size_from_reg;
	case ARM64_INS_LDUMIN:
	case ARM64_INS_LDUMINA:
	case ARM64_INS_LDUMINAL:
	case ARM64_INS_LDUMINL:
	case ARM64_INS_STUMIN:
	case ARM64_INS_STUMINL:
		op = OP_UMIN;
	size_from_reg:
	default: // ARM64_INS_LDADD, ARM64_INS_LDADDA, ARM64_INS_LDADDAL, ARM64_INS_LDADDL, ARM64_INS_STADD, ARM64_INS_STADDL
		loadsz = is_wreg(addend_reg) ? 32 : 64;
		break;
	}
	ut32 bits = 64;
	RzILOpBitVector *addr = ARG(addr_op, &bits);
	if (!addr) {
		return NULL;
	}
	addend_reg = xreg_of_reg(addend_reg);
	RzILOpEffect *ld_eff = NULL;
	if (OPCOUNT() == 3) {
		// LDADD... instead of STADD, which does not have a dst reg
		if (!ISREG(1)) {
			rz_il_op_pure_free(addr);
			return NULL;
		}
		arm64_reg dst_reg = REGID(1);
		dst_reg = xreg_of_reg(dst_reg);
		ld_eff = write_reg(dst_reg, loadsz != 64 ? UNSIGNED(64, VARL("old")) : VARL("old"));
		if (!ld_eff) {
			rz_il_op_pure_free(addr);
			return NULL;
		}
	}
	RzILOpBitVector *res = read_reg(addend_reg);
	if (!res) {
		rz_il_op_effect_free(ld_eff);
		return NULL;
	}
	if (loadsz != 64) {
		res = UNSIGNED(loadsz, res);
	}
	switch (op) {
	case OP_CLR:
		res = LOGAND(VARL("old"), LOGNOT(res));
		break;
	case OP_EOR:
		res = LOGXOR(VARL("old"), res);
		break;
	case OP_SET:
		res = LOGOR(VARL("old"), res);
		break;
	case OP_SMAX:
		res = LET("r", res, ITE(SLE(VARL("old"), VARLP("r")), VARLP("r"), VARL("old")));
		break;
	case OP_SMIN:
		res = LET("r", res, ITE(SLE(VARL("old"), VARLP("r")), VARL("old"), VARLP("r")));
		break;
	case OP_UMAX:
		res = LET("r", res, ITE(ULE(VARL("old"), VARLP("r")), VARLP("r"), VARL("old")));
		break;
	case OP_UMIN:
		res = LET("r", res, ITE(ULE(VARL("old"), VARLP("r")), VARL("old"), VARLP("r")));
		break;
	default: // OP_ADD
		res = ADD(VARL("old"), res);
		break;
	}
	RzILOpEffect *eff = SEQ2(
		SETL("old", loadsz == 8 ? LOAD(addr) : LOADW(loadsz, addr)),
		loadsz == 8 ? STORE(DUP(addr), res) : STOREW(DUP(addr), res));
	if (ld_eff) {
		eff = SEQ2(eff, ld_eff);
	}
	return eff;
}
#endif

/**
 * Lift an AArch64 instruction to RzIL
 *
 * Currently unimplemented:
 *
 * FEAT_MTE/FEAT_MTE2/FEAT_MTE3: Memory Tagging Extension
 * ------------------------------------------------------
 * Plausible to represent by adding another memory with a 60bit keys and 4bit values to hold the memory tags.
 * Instructions:
 * - ADDG
 * - CMPP
 * - SUBPS
 * - GMI
 * - IRG
 * - LDG
 * - LDGM
 *
 * FEAT_PAuth: Pointer Authentication
 * ----------------------------------
 * Extremely complex internal calculations. Different options to implement it include:
 * - Fully implementing it in IL (probably theoretically possible, but may not be worth it)
 * - Implementing the complex parts in uninterpreted functions and the simpler ones (e.g. stripping of auth bits) in IL.
 *   Might be a very good final solution since all data flow is correctly represented.
 * - Implementing only stripping in IL and leaving everything else as nop.
 *   Might be useful as an interims solution to be able to strip pointers, but always unconditionally succeed authentication.
 * Unimplemented Instructions:
 * - AUTDA, AUTDZA
 * - AUTDB, AUTDZB
 * - AUTIA, AUTIA1716, AUTIASP, AUTIAZ, AUTIZA
 * - AUTIB, AUTIB1716, AUTIBSP, AUTIBZ, AUTIZB
 * - PACDA, PACDZA
 * - PACDB, PACDZB
 * - PACGA
 * - PACIA, PACIA1716, PACIASP, PACIAZ, PACIZA
 * - PACIB, PACIB1716, PACIBSP, PACIBZ, PACIZB
 * - BLRAA, BLRAAZ, BLRAB, BLRABZ
 * - BRAA, BRAAZ, BRAB, BRABZ
 * Stub-implemented Instructions:
 * - LDRAA, LDRAB: currently behave like regular ldr
 *
 * Cache maintenance, tlb maintenance and address translation
 * ----------------------------------------------------------
 * - AT
 * - CFP
 * - CPP
 * - SYS
 * - DC
 * - DVP
 * - IC
 *
 * Miscellaneous
 * -------------
 * - BRK: causes a breakpoint instruction exception
 * - BTI: FEAT_BTI/Branch Target Identification
 * - CLREX: clears the local monitor
 * - CRC32B, CRC32H, CRC32W, CRC32X, CRC32CB, CRC32CH, CRC32CW, CRC32CX: does crc32
 * - CSDB, DMB, DSB, ESB, ISB: synchronization, memory barriers
 * - DCPS1, DCPS2, DCPS3, DRPS, HLT: debug
 * - ERET, ERETAA, ERETAB: exception return
 *
 * Not supported by capstone
 * -------------------------
 * - AXFLAG
 * - FEAT_MTE (see above)
 * - DGH
 * - LD64B
 */
RZ_IPI RzILOpEffect *rz_arm_cs_64_il(csh *handle, cs_insn *insn) {
	switch (insn->id) {
	case ARM64_INS_ADD:
	case ARM64_INS_ADC:
	case ARM64_INS_SUB:
	case ARM64_INS_SBC:
#if CS_API_MAJOR > 4
	case ARM64_INS_ADDS:
	case ARM64_INS_SUBS:
	case ARM64_INS_ADCS:
	case ARM64_INS_SBCS:
#endif
		return add_sub(insn);
	case ARM64_INS_ADR:
	case ARM64_INS_ADRP:
		return adr(insn);
	case ARM64_INS_AND:
#if CS_API_MAJOR > 4
	case ARM64_INS_ANDS:
#endif
	case ARM64_INS_EOR:
	case ARM64_INS_EON:
		return bitwise(insn);
	case ARM64_INS_ASR:
	case ARM64_INS_LSL:
	case ARM64_INS_LSR:
		return shift(insn);
	case ARM64_INS_B:
	case ARM64_INS_BR:
#if CS_API_MAJOR > 4
	case ARM64_INS_BRAA:
	case ARM64_INS_BRAAZ:
	case ARM64_INS_BRAB:
	case ARM64_INS_BRABZ:
#endif
		return branch(insn);
	case ARM64_INS_BL:
	case ARM64_INS_BLR:
#if CS_API_MAJOR > 4
	case ARM64_INS_BLRAA:
	case ARM64_INS_BLRAAZ:
	case ARM64_INS_BLRAB:
	case ARM64_INS_BLRABZ:
#endif
		return bl(insn);
	case ARM64_INS_BFM:
	case ARM64_INS_BFI:
	case ARM64_INS_BFXIL:
		return bfm(insn);
	case ARM64_INS_BIC:
#if CS_API_MAJOR > 4
	case ARM64_INS_BICS:
#endif
		return bic(insn);
#if CS_API_MAJOR > 4
	case ARM64_INS_CAS:
	case ARM64_INS_CASA:
	case ARM64_INS_CASAL:
	case ARM64_INS_CASL:
	case ARM64_INS_CASB:
	case ARM64_INS_CASAB:
	case ARM64_INS_CASALB:
	case ARM64_INS_CASLB:
	case ARM64_INS_CASH:
	case ARM64_INS_CASAH:
	case ARM64_INS_CASALH:
	case ARM64_INS_CASLH:
		return cas(insn);
	case ARM64_INS_CASP:
	case ARM64_INS_CASPA:
	case ARM64_INS_CASPAL:
	case ARM64_INS_CASPL:
		return casp(insn);
#endif
	case ARM64_INS_CBZ:
	case ARM64_INS_CBNZ:
		return cbz(insn);
	case ARM64_INS_CMP:
	case ARM64_INS_CMN:
	case ARM64_INS_CCMP:
	case ARM64_INS_CCMN:
		return cmp(insn);
#if CS_API_MAJOR > 4
	case ARM64_INS_CFINV:
		return SETG("cf", INV(VARG("cf")));
#endif
	case ARM64_INS_CINC:
	case ARM64_INS_CSINC:
	case ARM64_INS_CINV:
	case ARM64_INS_CSINV:
	case ARM64_INS_CNEG:
	case ARM64_INS_CSNEG:
	case ARM64_INS_CSEL:
		return csinc(insn);
	case ARM64_INS_CSET:
	case ARM64_INS_CSETM:
		return cset(insn);
	case ARM64_INS_CLS:
		return cls(insn);
	case ARM64_INS_CLZ:
		return clz(insn);
	case ARM64_INS_EXTR:
		return extr(insn);
	case ARM64_INS_HINT:
		return NOP;
	case ARM64_INS_HVC:
		return hvc(insn);
	case ARM64_INS_SVC:
		return svc(insn);
	case ARM64_INS_LDR:
	case ARM64_INS_LDRB:
	case ARM64_INS_LDRH:
	case ARM64_INS_LDUR:
	case ARM64_INS_LDURB:
	case ARM64_INS_LDURH:
	case ARM64_INS_LDRSW:
	case ARM64_INS_LDRSB:
	case ARM64_INS_LDRSH:
	case ARM64_INS_LDURSW:
	case ARM64_INS_LDURSB:
	case ARM64_INS_LDURSH:
	case ARM64_INS_LDAR:
	case ARM64_INS_LDARB:
	case ARM64_INS_LDARH:
	case ARM64_INS_LDAXP:
	case ARM64_INS_LDXP:
	case ARM64_INS_LDAXR:
	case ARM64_INS_LDAXRB:
	case ARM64_INS_LDAXRH:
	case ARM64_INS_LDP:
	case ARM64_INS_LDNP:
	case ARM64_INS_LDPSW:
	case ARM64_INS_LDTR:
	case ARM64_INS_LDTRB:
	case ARM64_INS_LDTRH:
	case ARM64_INS_LDTRSW:
	case ARM64_INS_LDTRSB:
	case ARM64_INS_LDTRSH:
	case ARM64_INS_LDXR:
	case ARM64_INS_LDXRB:
	case ARM64_INS_LDXRH:
#if CS_API_MAJOR > 4
	case ARM64_INS_LDAPR:
	case ARM64_INS_LDAPRB:
	case ARM64_INS_LDAPRH:
	case ARM64_INS_LDAPUR:
	case ARM64_INS_LDAPURB:
	case ARM64_INS_LDAPURH:
	case ARM64_INS_LDAPURSB:
	case ARM64_INS_LDAPURSH:
	case ARM64_INS_LDAPURSW:
	case ARM64_INS_LDLAR:
	case ARM64_INS_LDLARB:
	case ARM64_INS_LDLARH:
	case ARM64_INS_LDRAA:
	case ARM64_INS_LDRAB:
#endif
		return ldr(insn);
#if CS_API_MAJOR > 4
	case ARM64_INS_LDADD:
	case ARM64_INS_LDADDA:
	case ARM64_INS_LDADDAL:
	case ARM64_INS_LDADDL:
	case ARM64_INS_LDADDB:
	case ARM64_INS_LDADDAB:
	case ARM64_INS_LDADDALB:
	case ARM64_INS_LDADDLB:
	case ARM64_INS_LDADDH:
	case ARM64_INS_LDADDAH:
	case ARM64_INS_LDADDALH:
	case ARM64_INS_LDADDLH:
	case ARM64_INS_STADD:
	case ARM64_INS_STADDL:
	case ARM64_INS_STADDB:
	case ARM64_INS_STADDLB:
	case ARM64_INS_STADDH:
	case ARM64_INS_STADDLH:
	case ARM64_INS_LDCLRB:
	case ARM64_INS_LDCLRAB:
	case ARM64_INS_LDCLRALB:
	case ARM64_INS_LDCLRLB:
	case ARM64_INS_LDCLRH:
	case ARM64_INS_LDCLRAH:
	case ARM64_INS_LDCLRALH:
	case ARM64_INS_LDCLRLH:
	case ARM64_INS_LDCLR:
	case ARM64_INS_LDCLRA:
	case ARM64_INS_LDCLRAL:
	case ARM64_INS_LDCLRL:
	case ARM64_INS_STCLR:
	case ARM64_INS_STCLRL:
	case ARM64_INS_STCLRB:
	case ARM64_INS_STCLRLB:
	case ARM64_INS_STCLRH:
	case ARM64_INS_STCLRLH:
	case ARM64_INS_LDEORB:
	case ARM64_INS_LDEORAB:
	case ARM64_INS_LDEORALB:
	case ARM64_INS_LDEORLB:
	case ARM64_INS_LDEORH:
	case ARM64_INS_LDEORAH:
	case ARM64_INS_LDEORALH:
	case ARM64_INS_LDEORLH:
	case ARM64_INS_LDEOR:
	case ARM64_INS_LDEORA:
	case ARM64_INS_LDEORAL:
	case ARM64_INS_LDEORL:
	case ARM64_INS_STEOR:
	case ARM64_INS_STEORL:
	case ARM64_INS_STEORB:
	case ARM64_INS_STEORLB:
	case ARM64_INS_STEORH:
	case ARM64_INS_STEORLH:
	case ARM64_INS_LDSETB:
	case ARM64_INS_LDSETAB:
	case ARM64_INS_LDSETALB:
	case ARM64_INS_LDSETLB:
	case ARM64_INS_LDSETH:
	case ARM64_INS_LDSETAH:
	case ARM64_INS_LDSETALH:
	case ARM64_INS_LDSETLH:
	case ARM64_INS_LDSET:
	case ARM64_INS_LDSETA:
	case ARM64_INS_LDSETAL:
	case ARM64_INS_LDSETL:
	case ARM64_INS_STSET:
	case ARM64_INS_STSETL:
	case ARM64_INS_STSETB:
	case ARM64_INS_STSETLB:
	case ARM64_INS_STSETH:
	case ARM64_INS_STSETLH:
	case ARM64_INS_LDSMAXB:
	case ARM64_INS_LDSMAXAB:
	case ARM64_INS_LDSMAXALB:
	case ARM64_INS_LDSMAXLB:
	case ARM64_INS_LDSMAXH:
	case ARM64_INS_LDSMAXAH:
	case ARM64_INS_LDSMAXALH:
	case ARM64_INS_LDSMAXLH:
	case ARM64_INS_LDSMAX:
	case ARM64_INS_LDSMAXA:
	case ARM64_INS_LDSMAXAL:
	case ARM64_INS_LDSMAXL:
	case ARM64_INS_STSMAX:
	case ARM64_INS_STSMAXL:
	case ARM64_INS_STSMAXB:
	case ARM64_INS_STSMAXLB:
	case ARM64_INS_STSMAXH:
	case ARM64_INS_STSMAXLH:
	case ARM64_INS_LDSMINB:
	case ARM64_INS_LDSMINAB:
	case ARM64_INS_LDSMINALB:
	case ARM64_INS_LDSMINLB:
	case ARM64_INS_LDSMINH:
	case ARM64_INS_LDSMINAH:
	case ARM64_INS_LDSMINALH:
	case ARM64_INS_LDSMINLH:
	case ARM64_INS_LDSMIN:
	case ARM64_INS_LDSMINA:
	case ARM64_INS_LDSMINAL:
	case ARM64_INS_LDSMINL:
	case ARM64_INS_STSMIN:
	case ARM64_INS_STSMINL:
	case ARM64_INS_STSMINB:
	case ARM64_INS_STSMINLB:
	case ARM64_INS_STSMINH:
	case ARM64_INS_STSMINLH:
	case ARM64_INS_LDUMAXB:
	case ARM64_INS_LDUMAXAB:
	case ARM64_INS_LDUMAXALB:
	case ARM64_INS_LDUMAXLB:
	case ARM64_INS_LDUMAXH:
	case ARM64_INS_LDUMAXAH:
	case ARM64_INS_LDUMAXALH:
	case ARM64_INS_LDUMAXLH:
	case ARM64_INS_LDUMAX:
	case ARM64_INS_LDUMAXA:
	case ARM64_INS_LDUMAXAL:
	case ARM64_INS_LDUMAXL:
	case ARM64_INS_STUMAX:
	case ARM64_INS_STUMAXL:
	case ARM64_INS_STUMAXB:
	case ARM64_INS_STUMAXLB:
	case ARM64_INS_STUMAXH:
	case ARM64_INS_STUMAXLH:
	case ARM64_INS_LDUMINB:
	case ARM64_INS_LDUMINAB:
	case ARM64_INS_LDUMINALB:
	case ARM64_INS_LDUMINLB:
	case ARM64_INS_LDUMINH:
	case ARM64_INS_LDUMINAH:
	case ARM64_INS_LDUMINALH:
	case ARM64_INS_LDUMINLH:
	case ARM64_INS_LDUMIN:
	case ARM64_INS_LDUMINA:
	case ARM64_INS_LDUMINAL:
	case ARM64_INS_LDUMINL:
	case ARM64_INS_STUMIN:
	case ARM64_INS_STUMINL:
	case ARM64_INS_STUMINB:
	case ARM64_INS_STUMINLB:
	case ARM64_INS_STUMINH:
	case ARM64_INS_STUMINLH:
		return ldadd(insn);
#endif
	default:
		break;
	}
	return NULL;
}

#include <rz_il/rz_il_opbuilder_end.h>

RZ_IPI RzAnalysisILConfig *rz_arm_cs_64_il_config(bool big_endian) {
	RzAnalysisILConfig *r = rz_analysis_il_config_new(64, big_endian, 64);
	r->reg_bindings = regs_bound;
	RzILEffectLabel *svc_label = rz_il_effect_label_new("svc", EFFECT_LABEL_SYSCALL);
	svc_label->hook = label_svc;
	rz_analysis_il_config_add_label(r, svc_label);
	RzILEffectLabel *hvc_label = rz_il_effect_label_new("hvc", EFFECT_LABEL_SYSCALL);
	hvc_label->hook = label_hvc;
	rz_analysis_il_config_add_label(r, hvc_label);
	return r;
}
