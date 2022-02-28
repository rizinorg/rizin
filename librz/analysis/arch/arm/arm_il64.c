// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <capstone.h>

#include "arm_cs.h"

#include "arm_accessors64.h"
// This source file is 64-bit specific, so avoid having to type 64 all the time:
#define IMM   IMM64
#define REGID REGID64
#define ISIMM ISIMM64
#define ISREG ISREG64
#define ISMEM ISMEM64
#define OPCOUNT OPCOUNT64

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

/**
 * Variable name for a register given by cs
 */
static const char *reg_var_name(arm64_reg reg) {
	if (is_wreg(reg)) {
		reg = xreg(wreg_idx(reg));
	}
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
	if (is_xreg(reg)) {
		return 64;
	}
	if (is_wreg(reg)) {
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
	} else {
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

static RzILOpBitVector *shift(arm64_shifter sft, ut32 dist, RZ_OWN RzILOpBitVector *v) {
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
#define REG_VAL(id) read_reg(/*PC(insn->address), */ id)
#define REG(n)      REG_VAL(REGID(n))
#define REGBITS(n)  reg_bits(REGID(n))
#define MEMBASE(x)  REG_VAL(insn->detail->arm64.operands[x].mem.base)

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
		return shift(op->shift.type, op->shift.value, extend(bits_requested, op->ext, r, REGBITS(n)));
	}
	case ARM64_OP_IMM: {
		if (!bits_requested) {
			return NULL;
		}
		return UN(bits_requested, IMM(n));
	}
	case ARM64_OP_MEM: {
		RzILOpBitVector *addr = MEMBASE(n);
		return addr;
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
 * Capstone: ARM64_INS_AND
 * ARM: and
 */
static RzILOpEffect * and (cs_insn * insn) {
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
	RzILOpEffect *eff = write_reg(REGID(0), LOGAND(a, b));
	if (!eff) {
		return NULL;
	}
	if (insn->detail->arm64.update_flags) {
		return SEQ2(eff, update_flags_zn00(REG(0)));
	}
	return eff;
}

/**
 * Capstone: ARM64_INS_ASR
 * ARM: asr, asrv
 */
static RzILOpEffect *asr(cs_insn *insn) {
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
	return write_reg(REGID(0), SHIFTRA(a, b));
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
 * Capstone: ARM64_INS_CINC, ARM64_INS_CSINC, ARM64_INS_CINV, ARM64_INS_CSINV, ARM64_INS_CNEG, ARM64_INS_CSNEG
 * ARM: cinc, csinc, cinv, csinv, cneg, csneg
 */
static RzILOpEffect *csinc(cs_insn *insn) {
	size_t dst_idx = 0;
	size_t src0_idx = 1;
	size_t src1_idx = OPCOUNT() > 2 ? 2 : 1;
	if (!ISREG(dst_idx)) {
		return NULL;
	}
	ut32 bits = REGBITS(dst_idx);
	RzILOpBitVector *src1 = ARG(src1_idx, &bits);
	if (!src1) {
		return NULL;
	}
	RzILOpBitVector *res;
	switch (insn->id) {
	case ARM64_INS_CINV:
	case ARM64_INS_CSINV:
		res = LOGNOT(src1);
		break;
	case ARM64_INS_CNEG:
	case ARM64_INS_CSNEG:
		res = NEG(src1);
		break;
	default: // ARM64_INS_CINC, ARM64_INS_CSINC
		res = ADD(src1, UN(bits, 1));
		break;
	}
	RzILOpBool *c = cond(insn->detail->arm64.cc);
	if (!c) {
		return write_reg(REGID(dst_idx), res);
	}
	RzILOpBitVector *src0 = ARG(src0_idx, &bits);
	if (!src0) {
		rz_il_op_pure_free(res);
		rz_il_op_pure_free(c);
		return NULL;
	}
	return write_reg(REGID(dst_idx), ITE(c, res, src0));
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
 * Lift an AArch64 instruction to RzIL
 *
 * Currently unimplemented:
 *
 * FEAT_MTE/FEAT_MTE2/FEAT_MTE3: Memory Tagging Extension
 * ------------------------------------------------------
 * Plausible to represent by adding another memory with a 60bit keys and 4bit values to hold the memory tags.
 * Instructions:
 * - ADDG
 *
 * FEAT_PAuth: Pointer Authentication
 * ----------------------------------
 * Extremely complex internal calculations. Different options to implement it include:
 * - Fully implementing it in IL (probably theoretically possible, but may not be worth it)
 * - Implementing the complex parts in uninterpreted functions and the simpler ones (e.g. stripping of auth bits) in IL.
 *   Might be a very good final solution since all data flow is correctly represented.
 * - Implementing only stripping in IL and leaving everything else as nop.
 *   Might be useful as an interims solution to be able to strip pointers, but always unconditionally succeed authentication.
 * Instructions:
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
 *
 * Cache maintenance, tlb maintenance and address translation
 * ----------------------------------------------------------
 * - AT
 * - CFP
 * - SYS
 *
 * Miscellaneous
 * -------------
 * - BRK: causes a breakpoint instruction exception
 * - BTI: FEAT_BTI/Branch Target Identification
 * - CLREX: clears the local monitor
 *
 * Not supported by capstone
 * -------------------------
 * - AXFLAG
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
		return and(insn);
	case ARM64_INS_ASR:
		return asr(insn);
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
	case ARM64_INS_CBZ:
	case ARM64_INS_CBNZ:
		return cbz(insn);
	case ARM64_INS_CMP:
	case ARM64_INS_CMN:
	case ARM64_INS_CCMP:
	case ARM64_INS_CCMN:
		return cmp(insn);
	case ARM64_INS_CFINV:
		return SETG("cf", INV(VARG("cf")));
	case ARM64_INS_CINC:
	case ARM64_INS_CSINC:
	case ARM64_INS_CINV:
	case ARM64_INS_CSINV:
	case ARM64_INS_CNEG:
	case ARM64_INS_CSNEG:
		return csinc(insn);
	case ARM64_INS_CLS:
		return cls(insn);
	case ARM64_INS_CLZ:
		return clz(insn);
	default:
		break;
	}
	return NULL;
}

#include <rz_il/rz_il_opbuilder_end.h>

RZ_IPI RzAnalysisILConfig *rz_arm_cs_64_il_config(bool big_endian) {
	RzAnalysisILConfig *r = rz_analysis_il_config_new(64, big_endian, 64);
	r->reg_bindings = regs_bound;
	return r;
}
