// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <capstone.h>

#include "arm_cs.h"

#include "arm_accessors64.h"
// This source file is 64-bit specific, so avoid having to type 64 all the time:
#define IMM IMM64
#define REGID REGID64
#define ISIMM ISIMM64
#define ISREG ISREG64
#define ISMEM ISMEM64

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
static RzILOpBitVector *read_reg(/*ut64 pc, */arm64_reg reg) {
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

static RzILOpBitVector *extend(ut32 dst_bits, arm64_extender ext, RZ_OWN RzILOpBitVector *v) {
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
		return v;
	}

	if (v->code == RZ_IL_OP_CAST) {
		// coming from UNSIGNED(32, ... in read_reg, reuse the existing cast
		v->op.cast.length = src_bits;
	} else {
		v = UNSIGNED(src_bits, v);
	}
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
#define REG_VAL(id)   read_reg(/*PC(insn->address), */id)
#define REG(n)        REG_VAL(REGID(n))
#define REGBITS(n)    reg_bits(REGID(n))
// #define MEMBASE(x)    REG_VAL(insn->detail->arm64.operands[x].mem.base)

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
		if (bits_requested && op->ext == ARM64_SFT_INVALID && REGBITS(n) != bits_requested) {
			return NULL;
		}
		RzILOpBitVector *r = REG(n);
		if (!r || !bits_requested) {
			return NULL;
		}
		return shift(op->shift.type, op->shift.value, extend(bits_requested, op->ext, r));
	}
	case ARM64_OP_IMM: {
		if (!bits_requested) {
			return NULL;
		}
		return UN(bits_requested, IMM(n));
	}
	case ARM64_OP_MEM: {
		return NULL;
	}
	default:
		break;
	}
	return NULL;
}

#define ARG(n, bits)          arg(insn, n, bits)

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
	bool is_sub = insn->id == ARM64_INS_SUB || insn->id == ARM64_INS_SBC;
	ut32 bits = REGBITS(0);
	RzILOpBitVector *a = ARG(1, &bits);
	RzILOpBitVector *b = ARG(2, &bits);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	RzILOpBitVector *res = is_sub ? SUB(a, b) : ADD(a, b);
	bool with_carry = false;
	if (insn->id == ARM64_INS_ADC) {
		res = ADD(res, ITE(VARG("cf"), UN(bits, 1), UN(bits, 0)));
		with_carry = true;
	} else if (insn->id == ARM64_INS_SBC) {
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
 * Lift an AArch64 instruction to RzIL
 *
 * Currently unimplemented:
 *
 * - FEAT_MTE/FEAT_MTE2/FEAT_MTE3: Memory Tagging Extension
 *   Plausible to represent by adding another memory with a 60bit keys and 4bit values to hold the memory tags.
 *   Instructions:
 *   - ADDG
 *
 */
RZ_IPI RzILOpEffect *rz_arm_cs_64_il(csh *handle, cs_insn *insn) {
	switch (insn->id) {
	case ARM64_INS_ADD:
	case ARM64_INS_ADC:
	case ARM64_INS_SUB:
	case ARM64_INS_SBC:
		return add_sub(insn);
	case ARM64_INS_ADR:
	case ARM64_INS_ADRP:
		return adr(insn);
	default:
		break;
	}
	return NULL;
}

#include <rz_il/rz_il_opbuilder_end.h>

RZ_IPI RzAnalysisILConfig *rz_arm_cs_64_il_config(bool big_endian) {
	RzAnalysisILConfig *r = rz_analysis_il_config_new(32, big_endian, 32);
	r->reg_bindings = regs_bound;
	return r;
}
