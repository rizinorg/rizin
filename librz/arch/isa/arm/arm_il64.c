// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <capstone/capstone.h>

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
#define MEMDISP(x) insn->detail->CS_aarch64_.operands[x].mem.disp

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
static RzILOpBool *cond(CS_aarch64_cc() c) {
	switch (c) {
	case CS_AARCH64CC(_EQ):
		return VARG("zf");
	case CS_AARCH64CC(_NE):
		return INV(VARG("zf"));
	case CS_AARCH64CC(_HS):
		return VARG("cf");
	case CS_AARCH64CC(_LO):
		return INV(VARG("cf"));
	case CS_AARCH64CC(_MI):
		return VARG("nf");
	case CS_AARCH64CC(_PL):
		return INV(VARG("nf"));
	case CS_AARCH64CC(_VS):
		return VARG("vf");
	case CS_AARCH64CC(_VC):
		return INV(VARG("vf"));
	case CS_AARCH64CC(_HI):
		return AND(VARG("cf"), INV(VARG("zf")));
	case CS_AARCH64CC(_LS):
		return OR(INV(VARG("cf")), VARG("zf"));
	case CS_AARCH64CC(_GE):
		return INV(XOR(VARG("nf"), VARG("vf")));
	case CS_AARCH64CC(_LT):
		return XOR(VARG("nf"), VARG("vf"));
	case CS_AARCH64CC(_GT):
		return INV(OR(XOR(VARG("nf"), VARG("vf")), VARG("zf")));
	case CS_AARCH64CC(_LE):
		return OR(XOR(VARG("nf"), VARG("vf")), VARG("zf"));
	default:
		return NULL;
	}
}

static CS_aarch64_reg() xreg(ut8 idx) {
	// for some reason, the CS_AARCH64(_REG_X0)...CS_AARCH64(_REG_X30) enum values are not contiguous,
	// so use switch here and let the compiler optimize:
	switch (idx) {
	case 0: return CS_AARCH64(_REG_X0);
	case 1: return CS_AARCH64(_REG_X1);
	case 2: return CS_AARCH64(_REG_X2);
	case 3: return CS_AARCH64(_REG_X3);
	case 4: return CS_AARCH64(_REG_X4);
	case 5: return CS_AARCH64(_REG_X5);
	case 6: return CS_AARCH64(_REG_X6);
	case 7: return CS_AARCH64(_REG_X7);
	case 8: return CS_AARCH64(_REG_X8);
	case 9: return CS_AARCH64(_REG_X9);
	case 10: return CS_AARCH64(_REG_X10);
	case 11: return CS_AARCH64(_REG_X11);
	case 12: return CS_AARCH64(_REG_X12);
	case 13: return CS_AARCH64(_REG_X13);
	case 14: return CS_AARCH64(_REG_X14);
	case 15: return CS_AARCH64(_REG_X15);
	case 16: return CS_AARCH64(_REG_X16);
	case 17: return CS_AARCH64(_REG_X17);
	case 18: return CS_AARCH64(_REG_X18);
	case 19: return CS_AARCH64(_REG_X19);
	case 20: return CS_AARCH64(_REG_X20);
	case 21: return CS_AARCH64(_REG_X21);
	case 22: return CS_AARCH64(_REG_X22);
	case 23: return CS_AARCH64(_REG_X23);
	case 24: return CS_AARCH64(_REG_X24);
	case 25: return CS_AARCH64(_REG_X25);
	case 26: return CS_AARCH64(_REG_X26);
	case 27: return CS_AARCH64(_REG_X27);
	case 28: return CS_AARCH64(_REG_X28);
	case 29: return CS_AARCH64(_REG_X29);
	case 30: return CS_AARCH64(_REG_X30);
	case 31: return CS_AARCH64(_REG_SP);
	case 32: return CS_AARCH64(_REG_XZR);
	default:
		rz_warn_if_reached();
		return CS_AARCH64(_REG_INVALID);
	}
}

static bool is_xreg(CS_aarch64_reg() reg) {
	switch (reg) {
	case CS_AARCH64(_REG_X0):
	case CS_AARCH64(_REG_X1):
	case CS_AARCH64(_REG_X2):
	case CS_AARCH64(_REG_X3):
	case CS_AARCH64(_REG_X4):
	case CS_AARCH64(_REG_X5):
	case CS_AARCH64(_REG_X6):
	case CS_AARCH64(_REG_X7):
	case CS_AARCH64(_REG_X8):
	case CS_AARCH64(_REG_X9):
	case CS_AARCH64(_REG_X10):
	case CS_AARCH64(_REG_X11):
	case CS_AARCH64(_REG_X12):
	case CS_AARCH64(_REG_X13):
	case CS_AARCH64(_REG_X14):
	case CS_AARCH64(_REG_X15):
	case CS_AARCH64(_REG_X16):
	case CS_AARCH64(_REG_X17):
	case CS_AARCH64(_REG_X18):
	case CS_AARCH64(_REG_X19):
	case CS_AARCH64(_REG_X20):
	case CS_AARCH64(_REG_X21):
	case CS_AARCH64(_REG_X22):
	case CS_AARCH64(_REG_X23):
	case CS_AARCH64(_REG_X24):
	case CS_AARCH64(_REG_X25):
	case CS_AARCH64(_REG_X26):
	case CS_AARCH64(_REG_X27):
	case CS_AARCH64(_REG_X28):
	case CS_AARCH64(_REG_X29):
	case CS_AARCH64(_REG_X30):
	case CS_AARCH64(_REG_SP):
	case CS_AARCH64(_REG_XZR):
		return true;
	default:
		return false;
	}
}

static ut8 wreg_idx(CS_aarch64_reg() reg) {
	if (reg >= CS_AARCH64(_REG_W0) && reg <= CS_AARCH64(_REG_W30)) {
		return reg - CS_AARCH64(_REG_W0);
	}
	if (reg == CS_AARCH64(_REG_WSP)) {
		return 31;
	}
	if (reg == CS_AARCH64(_REG_WZR)) {
		return 32;
	}
	rz_warn_if_reached();
	return 0;
}

static bool is_wreg(CS_aarch64_reg() reg) {
	return (reg >= CS_AARCH64(_REG_W0) && reg <= CS_AARCH64(_REG_W30)) || reg == CS_AARCH64(_REG_WSP) || reg == CS_AARCH64(_REG_WZR);
}

static CS_aarch64_reg() xreg_of_reg(CS_aarch64_reg() reg) {
	if (is_wreg(reg)) {
		return xreg(wreg_idx(reg));
	}
	return reg;
}

/**
 * Variable name for a register given by cs
 */
static const char *reg_var_name(CS_aarch64_reg() reg) {
	reg = xreg_of_reg(reg);
	switch (reg) {
	case CS_AARCH64(_REG_X0): return "x0";
	case CS_AARCH64(_REG_X1): return "x1";
	case CS_AARCH64(_REG_X2): return "x2";
	case CS_AARCH64(_REG_X3): return "x3";
	case CS_AARCH64(_REG_X4): return "x4";
	case CS_AARCH64(_REG_X5): return "x5";
	case CS_AARCH64(_REG_X6): return "x6";
	case CS_AARCH64(_REG_X7): return "x7";
	case CS_AARCH64(_REG_X8): return "x8";
	case CS_AARCH64(_REG_X9): return "x9";
	case CS_AARCH64(_REG_X10): return "x10";
	case CS_AARCH64(_REG_X11): return "x11";
	case CS_AARCH64(_REG_X12): return "x12";
	case CS_AARCH64(_REG_X13): return "x13";
	case CS_AARCH64(_REG_X14): return "x14";
	case CS_AARCH64(_REG_X15): return "x15";
	case CS_AARCH64(_REG_X16): return "x16";
	case CS_AARCH64(_REG_X17): return "x17";
	case CS_AARCH64(_REG_X18): return "x18";
	case CS_AARCH64(_REG_X19): return "x19";
	case CS_AARCH64(_REG_X20): return "x20";
	case CS_AARCH64(_REG_X21): return "x21";
	case CS_AARCH64(_REG_X22): return "x22";
	case CS_AARCH64(_REG_X23): return "x23";
	case CS_AARCH64(_REG_X24): return "x24";
	case CS_AARCH64(_REG_X25): return "x25";
	case CS_AARCH64(_REG_X26): return "x26";
	case CS_AARCH64(_REG_X27): return "x27";
	case CS_AARCH64(_REG_X28): return "x28";
	case CS_AARCH64(_REG_X29): return "x29";
	case CS_AARCH64(_REG_X30): return "x30";
	case CS_AARCH64(_REG_SP): return "sp";
	default: return NULL;
	}
}

/**
 * Get the bits of the given register or 0, if it is not known (e.g. not implemented yet)
 */
static ut32 reg_bits(CS_aarch64_reg() reg) {
	if (is_xreg(reg) || reg == CS_AARCH64(_REG_XZR)) {
		return 64;
	}
	if (is_wreg(reg) || reg == CS_AARCH64(_REG_WZR)) {
		return 32;
	}
	return 0;
}

/**
 * IL to read the given capstone reg
 */
static RzILOpBitVector *read_reg(CS_aarch64_reg() reg) {
	if (reg == CS_AARCH64(_REG_XZR)) {
		return U64(0);
	}
	if (reg == CS_AARCH64(_REG_WZR)) {
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

static RzILOpBitVector *reg_extend(ut32 dst_bits, CS_aarch64_extender() ext, RZ_OWN RzILOpBitVector *reg, ut32 v_bits) {
	bool is_signed = false;
	ut32 src_bits = v_bits;
	switch (ext) {
	case CS_AARCH64(_EXT_SXTB):
		is_signed = true;
		// fallthrough
	case CS_AARCH64(_EXT_UXTB):
		src_bits = 8;
		break;

	case CS_AARCH64(_EXT_SXTH):
		is_signed = true;
		// fallthrough
	case CS_AARCH64(_EXT_UXTH):
		src_bits = 16;
		break;

	case CS_AARCH64(_EXT_SXTW):
		is_signed = true;
		// fallthrough
	case CS_AARCH64(_EXT_UXTW):
		src_bits = 32;
		break;

	case CS_AARCH64(_EXT_SXTX):
		is_signed = true;
		// fallthrough
	case CS_AARCH64(_EXT_UXTX):
		src_bits = 64;
		break;

	default:
		break;
	}
	if (dst_bits < src_bits && src_bits <= v_bits) {
		// Just cast it down once.
		if (reg->code == RZ_IL_OP_CAST) {
			// Already a casted down register. Set new width.
			reg->op.cast.length = dst_bits;
			return reg;
		}
		return UNSIGNED(dst_bits, reg);
	}
	if (src_bits != v_bits) {
		reg = adjust_unsigned(src_bits, reg);
	}
	if (dst_bits != src_bits) {
		return is_signed ? SIGNED(dst_bits, reg) : UNSIGNED(dst_bits, reg);
	}
	return is_signed ? SIGNED(dst_bits, reg) : reg;
}

static RzILOpBitVector *apply_shift(CS_aarch64_shifter() sft, ut32 dist, RZ_OWN RzILOpBitVector *v) {
	if (!dist) {
		return v;
	}
	switch (sft) {
	case CS_AARCH64(_SFT_LSL):
		return SHIFTL0(v, UN(6, dist));
	case CS_AARCH64(_SFT_LSR):
		return SHIFTR0(v, UN(6, dist));
	case CS_AARCH64(_SFT_ASR):
		return SHIFTRA(v, UN(6, dist));
	default:
		return v;
	}
}

#define REG(n)       read_reg(REGID(n))
#define REGBITS(n)   reg_bits(REGID(n))
#define MEMBASEID(x) insn->detail->CS_aarch64_.operands[x].mem.base
#define MEMBASE(x)   read_reg(MEMBASEID(x))

/**
 * IL to write a value to the given capstone reg
 */
static RzILOpEffect *write_reg(CS_aarch64_reg() reg, RZ_OWN RZ_NONNULL RzILOpBitVector *v) {
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

static RzILOpBitVector *arg_mem(RzILOpBitVector *base_plus_disp, CS_aarch64_op() * op) {
	if (op->mem.index == CS_AARCH64(_REG_INVALID)) {
		return base_plus_disp;
	}
	RzILOpBitVector *index = read_reg(op->mem.index);
	index = reg_extend(64, op->ext, index, reg_bits(op->mem.index));
	index = apply_shift(op->shift.type, op->shift.value, index);
	return ADD(base_plus_disp, index);
}

/**
 * IL to retrieve the value of the \p n -th arg of \p insn
 * \p bits_inout Setting the backing variable to non-0 indicates that the result must have this bitness.
 *               This is necessary for immediate operands for example.
 *               In any case, if a value is returned, its bitness is written back into this storage.
 */
static RzILOpBitVector *arg(RZ_BORROW cs_insn *insn, size_t n, RZ_OUT ut32 *bits_inout) {
	ut32 bits_requested = bits_inout ? *bits_inout : 0;
	CS_aarch64_op() *op = &insn->detail->CS_aarch64_.operands[n];
	switch (op->type) {
	case CS_AARCH64(_OP_REG): {
		if (!bits_requested) {
			bits_requested = REGBITS(n);
			if (!bits_requested) {
				return NULL;
			}
			if (bits_inout) {
				*bits_inout = bits_requested;
			}
		}
		RzILOpBitVector *r = REG(n);
		if (!r) {
			return NULL;
		}
		return apply_shift(op->shift.type, op->shift.value, reg_extend(bits_requested, op->ext, r, REGBITS(n)));
	}
	case CS_AARCH64(_OP_IMM): {
		if (!bits_requested) {
			return NULL;
		}
		ut64 val = IMM(n);
		if (op->shift.type == CS_AARCH64(_SFT_LSL)) {
			val <<= op->shift.value;
		}
		return UN(bits_requested, val);
	}
	case CS_AARCH64(_OP_MEM): {
		RzILOpBitVector *addr = MEMBASE(n);
#if CS_NEXT_VERSION >= 6
		if (ISPOSTINDEX64()) {
			return addr;
		}
#endif
		st64 disp = MEMDISP(n);
		if (disp > 0) {
			addr = ADD(addr, U64(disp));
		} else if (disp < 0) {
			addr = SUB(addr, U64(-disp));
		}
		return arg_mem(addr, &insn->detail->CS_aarch64_.operands[n]);
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
 * Capstone: CS_AARCH64(_INS_ADD), CS_AARCH64(_INS_ADC), CS_AARCH64(_INS_SUB), CS_AARCH64(_INS_SBC)
 * ARM: add, adds, adc, adcs, sub, subs, sbc, sbcs
 */
static RzILOpEffect *add_sub(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	bool is_sub = insn->id == CS_AARCH64(_INS_SUB) || insn->id == CS_AARCH64(_INS_SBC)
#if CS_API_MAJOR > 4
		|| insn->id == CS_AARCH64(_INS_SUBS) || insn->id == CS_AARCH64(_INS_SBCS)
#endif
		;
	ut32 bits = REGBITS(0);
	if (!bits) {
		return NULL;
	}
	RzILOpBitVector *a = ARG(1, &bits);
	RzILOpBitVector *b = ARG(2, &bits);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	RzILOpBitVector *res = is_sub ? SUB(a, b) : ADD(a, b);
	bool with_carry = false;
	if (insn->id == CS_AARCH64(_INS_ADC)
#if CS_API_MAJOR > 4
		|| insn->id == CS_AARCH64(_INS_ADCS)
#endif
	) {
		res = ADD(res, ITE(VARG("cf"), UN(bits, 1), UN(bits, 0)));
		with_carry = true;
	} else if (insn->id == CS_AARCH64(_INS_SBC)
#if CS_API_MAJOR > 4
		|| insn->id == CS_AARCH64(_INS_SBCS)
#endif
	) {
		res = SUB(res, ITE(VARG("cf"), UN(bits, 0), UN(bits, 1)));
		with_carry = true;
	}
	RzILOpEffect *set = write_reg(REGID(0), res);
	bool update_flags = insn->detail->CS_aarch64_.update_flags;
	if (update_flags) {
		return SEQ6(
			SETL("a", DUP(a)),
			SETL("b", DUP(b)),
			set,
			SETG("cf", (is_sub ? sub_carry : add_carry)(VARL("a"), VARL("b"), with_carry, bits)),
			SETG("vf", (is_sub ? sub_overflow : add_overflow)(VARL("a"), VARL("b"), REG(0))),
			update_flags_zn(REG(0)));
	}
	return set;
}

/**
 * Capstone: CS_AARCH64(_INS_ADR), CS_AARCH64(_INS_ADRP)
 * ARM: adr, adrp
 */
static RzILOpEffect *adr(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	return write_reg(REGID(0), U64(IMM(1)));
}

/**
 * Capstone: CS_AARCH64(_INS_AND), CS_AARCH64(_INS_EON), CS_AARCH64(_INS_EOR), CS_AARCH64(_INS_ORN), CS_AARCH64(_INS_AORR)
 * ARM: and, eon, eor, orn, orr
 */
static RzILOpEffect *bitwise(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	if (!bits) {
		return NULL;
	}
	RzILOpBitVector *a = ARG(1, &bits);
	RzILOpBitVector *b = ARG(2, &bits);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	RzILOpBitVector *res;
	switch (insn->id) {
	case CS_AARCH64(_INS_EOR):
		res = LOGXOR(a, b);
		break;
	case CS_AARCH64(_INS_EON):
		res = LOGXOR(a, LOGNOT(b));
		break;
	case CS_AARCH64(_INS_ORN):
		res = LOGOR(a, LOGNOT(b));
		break;
	case CS_AARCH64(_INS_ORR):
		res = LOGOR(a, b);
		break;
	default: // CS_AARCH64(_INS_AND)
		res = LOGAND(a, b);
		break;
	}
	RzILOpEffect *eff = write_reg(REGID(0), res);
	if (!eff) {
		return NULL;
	}
	if (insn->detail->CS_aarch64_.update_flags) {
		return SEQ2(eff, update_flags_zn00(REG(0)));
	}
	return eff;
}

/**
 * Capstone: CS_AARCH64(_INS_ASR), CS_AARCH64(_INS_LSL), CS_AARCH64(_INS_LSR), CS_AARCH64(_INS_ROR)
 * ARM: asr, asrv, lsl, lslv, lsr, lsrv, ror, rorv
 */
static RzILOpEffect *shift(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	if (!bits) {
		return NULL;
	}
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
	case CS_AARCH64(_INS_ASR):
		res = SHIFTRA(a, b);
		break;
	case CS_AARCH64(_INS_LSR):
		res = SHIFTR0(a, b);
		break;
	case CS_AARCH64(_INS_ROR):
		res = LOGOR(SHIFTR0(a, b), SHIFTL0(DUP(a), NEG(DUP(b))));
		break;
#if CS_NEXT_VERSION >= 6
	case AARCH64_INS_EXTR:
		if (insn->alias_id != AARCH64_INS_ALIAS_ROR) {
			return NULL;
		}
		b = ARG(3, &bits);
		res = LOGOR(SHIFTR0(a, b), SHIFTL0(DUP(a), NEG(DUP(b))));
		break;
#endif
	default: // CS_AARCH64(_INS_LSL)
		res = SHIFTL0(a, b);
		break;
	}
	return write_reg(REGID(0), res);
}

/**
 * Capstone: CS_AARCH64(_INS_B), CS_AARCH64(_INS_RET), CS_AARCH64(_INS_RETAA), CS_AARCH64(_INS_RETAB)
 * ARM: b, b.cond, ret, retaa, retab
 */
static RzILOpEffect *branch(cs_insn *insn) {
	RzILOpBitVector *a;
	if (OPCOUNT() == 0) {
		// for CS_AARCH64(_INS_RET) and similar
		a = read_reg(CS_AARCH64(_REG_LR));
	} else {
		ut32 bits = 64;
		a = ARG(0, &bits);
	}
	if (!a) {
		return NULL;
	}
	RzILOpBool *c = cond(insn->detail->CS_aarch64_.cc);
	if (c) {
		return BRANCH(c, JMP(a), NOP());
	}
	return JMP(a);
}

/**
 * Capstone: CS_AARCH64(_INS_BL), CS_AARCH64(_INS_BLR), CS_AARCH64(_INS_BLRAA), CS_AARCH64(_INS_BLRAAZ), CS_AARCH64(_INS_BLRAB), CS_AARCH64(_INS_BLRABZ)
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
 * Capstone: CS_AARCH64(_INS_BFM), CS_AARCH64(_INS_BFI), CS_AARCH64(_INS_BFXIL)
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
#if CS_NEXT_VERSION < 6
	ut64 mask_base = rz_num_bitmask(IMM(3));
	ut64 mask = mask_base << RZ_MIN(63, IMM(2));
	if (insn->id == CS_AARCH64(_INS_BFI)) {
		return write_reg(REGID(0), LOGOR(LOGAND(a, UN(bits, ~mask)), SHIFTL0(LOGAND(b, UN(bits, mask_base)), UN(6, IMM(2)))));
	}
	// insn->id == CS_AARCH64(_INS_BFXIL)
	return write_reg(REGID(0), LOGOR(LOGAND(a, UN(bits, ~mask_base)), SHIFTR0(LOGAND(b, UN(bits, mask)), UN(6, IMM(2)))));
#else
	ut64 lsb = IMM(2);
	ut64 width = IMM(3);
	if (insn->alias_id == AARCH64_INS_ALIAS_BFI) {
		width += 1;
		// TODO Mod depends on (sf && N) bits
		lsb = -lsb % 32;
		ut64 mask_base = rz_num_bitmask(width);
		ut64 mask = mask_base << RZ_MIN(63, lsb);
		return write_reg(REGID(0), LOGOR(LOGAND(a, UN(bits, ~mask)), SHIFTL0(LOGAND(b, UN(bits, mask_base)), UN(6, lsb))));
	} else if (insn->alias_id == AARCH64_INS_ALIAS_BFXIL) {
		width = width - lsb + 1;
		ut64 mask_base = rz_num_bitmask(width);
		ut64 mask = mask_base << RZ_MIN(63, lsb);
		return write_reg(REGID(0), LOGOR(LOGAND(a, UN(bits, ~mask_base)), SHIFTR0(LOGAND(b, UN(bits, mask)), UN(6, lsb))));
	}
	return NULL;
#endif
}

/**
 * Capstone: CS_AARCH64(_INS_BIC), CS_AARCH64(_INS_BICS)
 * ARM: bic, bics
 */
static RzILOpEffect *bic(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	if (!bits) {
		return NULL;
	}
	RzILOpBitVector *a = ARG(1, &bits);
	RzILOpBitVector *b = ARG(2, &bits);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	RzILOpBitVector *res = LOGAND(a, LOGNOT(b));
	RzILOpEffect *eff = NULL;
	if (REGID(0) != CS_AARCH64(_REG_XZR) && REGID(0) != CS_AARCH64(_REG_WZR)) {
		eff = write_reg(REGID(0), res);
		if (!eff) {
			return NULL;
		}
		res = NULL;
	}
	if (insn->detail->CS_aarch64_.update_flags) {
		RzILOpEffect *eff1 = update_flags_zn00(res ? res : REG(0));
		return eff ? SEQ2(eff, eff1) : eff1;
	}
	if (!eff) {
		rz_il_op_pure_free(res);
	}
	return eff;
}

#if CS_API_MAJOR > 4
/**
 * Capstone: CS_AARCH64(_INS_CAS), CS_AARCH64(_INS_CASA), CS_AARCH64(_INS_CASAL), CS_AARCH64(_INS_CASL),
 *           CS_AARCH64(_INS_CASB), CS_AARCH64(_INS_CASAB), CS_AARCH64(_INS_CASALB), CS_AARCH64(_INS_CASLB),
 *           CS_AARCH64(_INS_CASH), CS_AARCH64(_INS_CASAH), CS_AARCH64(_INS_CASALH), CS_AARCH64(_INS_CASLH):
 * ARM: cas, casa, casal, casl, casb, casab, casalb, caslb, cash, casah, casalh, caslh
 */
static RzILOpEffect *cas(cs_insn *insn) {
	if (!ISREG(0) || !ISMEM(2)) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	if (!bits) {
		return NULL;
	}
	switch (insn->id) {
	case CS_AARCH64(_INS_CASB):
	case CS_AARCH64(_INS_CASAB):
	case CS_AARCH64(_INS_CASALB):
	case CS_AARCH64(_INS_CASLB):
		bits = 8;
		break;
	case CS_AARCH64(_INS_CASH):
	case CS_AARCH64(_INS_CASAH):
	case CS_AARCH64(_INS_CASALH):
	case CS_AARCH64(_INS_CASLH):
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
 * Capstone: CS_AARCH64(_INS_CASP), CS_AARCH64(_INS_CASPA), CS_AARCH64(_INS_CASPAL), CS_AARCH64(_INS_CASPL)
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
 * Capstone: CS_AARCH64(_INS_CBZ), CS_AARCH64(_INS_CBNZ)
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
	return BRANCH(insn->id == CS_AARCH64(_INS_CBNZ) ? INV(IS_ZERO(v)) : IS_ZERO(v), JMP(tgt), NULL);
}

/**
 * Capstone: CS_AARCH64(_INS_CMP), CS_AARCH64(_INS_CMN), CS_AARCH64(_INS_CCMP), CS_AARCH64(_INS_CCMN)
 * ARM: cmp, cmn, ccmp, ccmn
 */
static RzILOpEffect *cmp(cs_insn *insn) {
	ut32 bits = 0;
#if CS_NEXT_VERSION < 6
	RzILOpBitVector *a = ARG(0, &bits);
	RzILOpBitVector *b = ARG(1, &bits);

#else
	RzILOpBitVector *a;
	RzILOpBitVector *b;
	if (insn->alias_id == AARCH64_INS_ALIAS_CMP ||
		insn->alias_id == AARCH64_INS_ALIAS_CMN) {
		// Reg at 0 is zero register
		a = ARG(1, &bits);
		b = ARG(2, &bits);
	} else {
		a = ARG(0, &bits);
		b = ARG(1, &bits);
	}
#endif
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
#if CS_NEXT_VERSION < 6
	bool is_neg = insn->id == CS_AARCH64(_INS_CMN) || insn->id == CS_AARCH64(_INS_CCMN);
#else
	bool is_neg = insn->alias_id == AARCH64_INS_ALIAS_CMN || insn->id == CS_AARCH64(_INS_CCMN);
#endif
	RzILOpEffect *eff = SEQ6(
		SETL("a", a),
		SETL("b", b),
		SETL("r", is_neg ? ADD(VARL("a"), VARL("b")) : SUB(VARL("a"), VARL("b"))),
		SETG("cf", (is_neg ? add_carry : sub_carry)(VARL("a"), VARL("b"), false, bits)),
		SETG("vf", (is_neg ? add_overflow : sub_overflow)(VARL("a"), VARL("b"), VARL("r"))),
		update_flags_zn(VARL("r")));
	RzILOpBool *c = cond(insn->detail->CS_aarch64_.cc);
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
 * Capstone: CS_AARCH64(_INS_CINC), CS_AARCH64(_INS_CSINC), CS_AARCH64(_INS_CINV), CS_AARCH64(_INS_CSINV), CS_AARCH64(_INS_CNEG), CS_AARCH64(_INS_CSNEG), CS_AARCH64(_INS_CSEL)
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
	if (!bits) {
		return NULL;
	}
	RzILOpBitVector *src0 = ARG(src0_idx, &bits);
	if (!src0) {
		return NULL;
	}
#if CS_NEXT_VERSION < 6
	RzILOpBool *c = cond(insn->detail->CS_aarch64_.cc);
#else
	AArch64CC_CondCode cc;
	if (insn->alias_id == AARCH64_INS_ALIAS_CINV ||
		insn->alias_id == AARCH64_INS_ALIAS_CNEG ||
		insn->alias_id == AARCH64_INS_ALIAS_CINC) {
		cc = AArch64CC_getInvertedCondCode(insn->detail->CS_aarch64_.cc);
	} else {
		cc = insn->detail->CS_aarch64_.cc;
	}
	RzILOpBool *c = cond(cc);
#endif
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
	case CS_AARCH64(_INS_CSEL):
		invert_cond = true;
		res = src1;
		break;
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_CSINV):
		invert_cond = true;
		// fallthrough
	case CS_AARCH64(_INS_CINV):
		res = LOGNOT(src1);
		break;
	case CS_AARCH64(_INS_CSNEG):
		invert_cond = true;
		// fallthrough
	case CS_AARCH64(_INS_CNEG):
		res = NEG(src1);
		break;
	case CS_AARCH64(_INS_CSINC):
		invert_cond = true;
#else
	case CS_AARCH64(_INS_CSINV):
		if (!insn->is_alias) {
			invert_cond = true;
		}
		res = LOGNOT(src1);
		break;
	case CS_AARCH64(_INS_CSNEG):
		if (!insn->is_alias) {
			invert_cond = true;
		}
		res = NEG(src1);
		break;
	case CS_AARCH64(_INS_CSINC):
		if (!insn->is_alias) {
			invert_cond = true;
		}
#endif
		// fallthrough
	default: // CS_AARCH64(_INS_CINC), CS_AARCH64(_INS_CSINC)
		res = ADD(src1, UN(bits, 1));
		break;
	}
	return write_reg(REGID(dst_idx), invert_cond ? ITE(c, src0, res) : ITE(c, res, src0));
}

/**
 * Capstone: CS_AARCH64(_INS_CSET), CS_AARCH64(_INS_CSETM)
 * ARM: cset, csetm
 */
static RzILOpEffect *cset(cs_insn *insn) {
	if (!ISREG(0) || !REGBITS(0)) {
		return NULL;
	}
	RzILOpBool *c = NULL;
#if CS_NEXT_VERSION < 6
	c = cond(insn->detail->CS_aarch64_.cc);
#else
	if (insn->alias_id == AARCH64_INS_ALIAS_CSET ||
		insn->alias_id == AARCH64_INS_ALIAS_CSETM) {
		c = cond(AArch64CC_getInvertedCondCode(insn->detail->CS_aarch64_.cc));
	} else {
		c = cond(insn->detail->CS_aarch64_.cc);
	}
#endif
	if (!c) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
#if CS_NEXT_VERSION < 6
	return write_reg(REGID(0), ITE(c, SN(bits, insn->id == CS_AARCH64(_INS_CSETM) ? -1 : 1), SN(bits, 0)));
#else
	return write_reg(REGID(0), ITE(c, SN(bits, insn->alias_id == AARCH64_INS_ALIAS_CSETM ? -1 : 1), SN(bits, 0)));
#endif
}

/**
 * Capstone: CS_AARCH64(_INS_CLS)
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
 * Capstone: CS_AARCH64(_INS_CLZ)
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
 * Capstone: CS_AARCH64(_INS_EXTR)
 * ARM: extr
 */
static RzILOpEffect *extr(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	if (!bits) {
		return NULL;
	}
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
 * Capstone: CS_AARCH64(_INS_HVC)
 * ARM: hvc
 */
static RzILOpEffect *hvc(cs_insn *insn) {
	return GOTO("hvc");
}

static void label_hvc(RzILVM *vm, RzILOpEffect *op) {
	// stub, nothing to do here
}

static RzILOpEffect *load_effect(ut32 bits, bool is_signed, CS_aarch64_reg() dst_reg, RZ_OWN RzILOpBitVector *addr) {
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

static RzILOpEffect *writeback(cs_insn *insn, size_t addr_op, RZ_BORROW RzILOpBitVector *addr) {
#if CS_NEXT_VERSION < 6
	if (!insn->detail->CS_aarch64_.writeback || !is_xreg(MEMBASEID(addr_op))) {
#else
	if (!insn->detail->writeback || !is_xreg(MEMBASEID(addr_op))) {
#endif
		return NULL;
	}
	RzILOpBitVector *wbaddr = DUP(addr);
	if (ISPOSTINDEX64()) {
		// post-index
		st64 disp = MEMDISP(addr_op);
		if (disp > 0) {
			wbaddr = ADD(wbaddr, U64(disp));
		} else if (disp < 0) {
			wbaddr = SUB(wbaddr, U64(-disp));
		}
	}
	return write_reg(MEMBASEID(addr_op), wbaddr);
}

/**
 * Capstone: CS_AARCH64(_INS_LDR), CS_AARCH64(_INS_LDRB), CS_AARCH64(_INS_LDRH), CS_AARCH64(_INS_LDRU), CS_AARCH64(_INS_LDRUB), CS_AARCH64(_INS_LDRUH),
 *           CS_AARCH64(_INS_LDRSW), CS_AARCH64(_INS_LDRSB), CS_AARCH64(_INS_LDRSH), CS_AARCH64(_INS_LDURSW), CS_AARCH64(_INS_LDURSB), CS_AARCH64(_INS_LDURSH),
 *           CS_AARCH64(_INS_LDAPR), CS_AARCH64(_INS_LDAPRB), CS_AARCH64(_INS_LDAPRH), CS_AARCH64(_INS_LDAPUR), CS_AARCH64(_INS_LDAPURB), CS_AARCH64(_INS_LDAPURH),
 *           CS_AARCH64(_INS_LDAPURSB), CS_AARCH64(_INS_LDAPURSH), CS_AARCH64(_INS_LDAPURSW), CS_AARCH64(_INS_LDAR), CS_AARCH64(_INS_LDARB), CS_AARCH64(_INS_LDARH),
 *           CS_AARCH64(_INS_LDAXP), CS_AARCH64(_INS_LDXP), CS_AARCH64(_INS_LDAXR), CS_AARCH64(_INS_LDAXRB), CS_AARCH64(_INS_LDAXRH),
 *           CS_AARCH64(_INS_LDLAR), CS_AARCH64(_INS_LDLARB), CS_AARCH64(_INS_LDLARH),
 *           CS_AARCH64(_INS_LDP), CS_AARCH64(_INS_LDNP), CS_AARCH64(_INS_LDPSW),
 *           CS_AARCH64(_INS_LDRAA), CS_AARCH64(_INS_LDRAB),
 *           CS_AARCH64(_INS_LDTR), CS_AARCH64(_INS_LDTRB), CS_AARCH64(_INS_LDTRH), CS_AARCH64(_INS_LDTRSW), CS_AARCH64(_INS_LDTRSB), CS_AARCH64(_INS_LDTRSH),
 *           CS_AARCH64(_INS_LDXR), CS_AARCH64(_INS_LDXRB), CS_AARCH64(_INS_LDXRH)
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
	bool pair = insn->id == CS_AARCH64(_INS_LDAXP) || insn->id == CS_AARCH64(_INS_LDXP) ||
		insn->id == CS_AARCH64(_INS_LDP) || insn->id == CS_AARCH64(_INS_LDNP) || insn->id == CS_AARCH64(_INS_LDPSW);
	if (pair && !ISREG(1)) {
		return NULL;
	}
	ut32 bits = 64;
	size_t addr_op = pair ? 2 : 1;
	RzILOpBitVector *addr = ARG(addr_op, &bits);
	if (!addr) {
		return NULL;
	}
	CS_aarch64_reg() dst_reg = REGID(0);
	ut64 loadsz;
	bool is_signed = false;
	switch (insn->id) {
	case CS_AARCH64(_INS_LDRSB):
	case CS_AARCH64(_INS_LDURSB):
	case CS_AARCH64(_INS_LDTRSB):
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_LDAPURSB):
#endif
		is_signed = true;
		// fallthrough
	case CS_AARCH64(_INS_LDRB):
	case CS_AARCH64(_INS_LDURB):
	case CS_AARCH64(_INS_LDARB):
	case CS_AARCH64(_INS_LDAXRB):
	case CS_AARCH64(_INS_LDTRB):
	case CS_AARCH64(_INS_LDXRB):
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_LDLARB):
	case CS_AARCH64(_INS_LDAPRB):
	case CS_AARCH64(_INS_LDAPURB):
#endif
		loadsz = 8;
		break;
	case CS_AARCH64(_INS_LDRSH):
	case CS_AARCH64(_INS_LDURSH):
	case CS_AARCH64(_INS_LDTRSH):
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_LDAPURSH):
#endif
		is_signed = true;
		// fallthrough
	case CS_AARCH64(_INS_LDRH):
	case CS_AARCH64(_INS_LDURH):
	case CS_AARCH64(_INS_LDARH):
	case CS_AARCH64(_INS_LDAXRH):
	case CS_AARCH64(_INS_LDTRH):
	case CS_AARCH64(_INS_LDXRH):
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_LDAPRH):
	case CS_AARCH64(_INS_LDAPURH):
	case CS_AARCH64(_INS_LDLARH):
#endif
		loadsz = 16;
		break;
	case CS_AARCH64(_INS_LDRSW):
	case CS_AARCH64(_INS_LDURSW):
	case CS_AARCH64(_INS_LDPSW):
	case CS_AARCH64(_INS_LDTRSW):
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_LDAPURSW):
#endif
		is_signed = true;
		loadsz = 32;
		break;
	default:
		// CS_AARCH64(_INS_LDR), CS_AARCH64(_INS_LDRU), CS_AARCH64(_INS_LDAPR), CS_AARCH64(_INS_LDAPUR), CS_AARCH64(_INS_LDAR), CS_AARCH64(_INS_LDAXR), CS_AARCH64(_INS_LDLAR),
		// CS_AARCH64(_INS_LDP), CS_AARCH64(_INS_LDNP), CS_AARCH64(_INS_LDRAA), CS_AARCH64(_INS_LDRAB), CS_AARCH64(_INS_LDTR), CS_AARCH64(_INS_LDXR)
		loadsz = is_wreg(dst_reg) ? 32 : 64;
		break;
	}
	RzILOpEffect *eff = NULL;
	if (pair) {
		eff = SETL("addr", addr);
		addr = VARL("addr");
	}
	RzILOpEffect *eff1 = load_effect(loadsz, is_signed, dst_reg, addr);
	if (!eff1) {
		return NULL;
	}
	eff = eff ? SEQ2(eff, eff1) : eff1;
	if (pair) {
		RzILOpEffect *eff1 = load_effect(loadsz, is_signed, REGID(1), ADD(DUP(addr), U64(loadsz / 8)));
		if (!eff1) {
			rz_il_op_effect_free(eff);
			return NULL;
		}
		eff = SEQ2(eff, eff1);
	}
	RzILOpEffect *wb_eff = writeback(insn, addr_op, addr);
	if (wb_eff) {
		eff = SEQ2(eff, wb_eff);
	}
	return eff;
}

/**
 * Capstone: CS_AARCH64(_INS_STR), CS_AARCH64(_INS_STUR), CS_AARCH64(_INS_STRB), CS_AARCH64(_INS_STURB), CS_AARCH64(_INS_STRH), CS_AARCH64(_INS_STURH),
 *           CS_AARCH64(_INS_STLLR), CS_AARCH64(_INS_STLLRB), CS_AARCH64(_INS_STLLRH), CS_AARCH64(_INS_STLR), CS_AARCH64(_INS_STLRB), CS_AARCH64(_INS_STLRH),
 *           CS_AARCH64(_INS_STLUR), CS_AARCH64(_INS_STLURB), CS_AARCH64(_INS_STLURH), CS_AARCH64(_INS_STP), CS_AARCH64(_INS_STXR), CS_AARCH64(_INS_STXRB),
 *           CS_AARCH64(_INS_STXRH), CS_AARCH64(_INS_STXP), CS_AARCH64(_INS_STLXR), CS_AARCH64(_INS_STLXRB). CS_AARCH64(_INS_STLXRH), CS_AARCH64(_INS_STLXP),
 *           CS_AARCH64(_INS_STNP), CS_AARCH64(_INS_STTR), CS_AARCH64(_INS_STTRB), CS_AARCH64(_INS_STTRH)
 * ARM: str, stur, strb, sturb, strh, sturh, stllr, stllrb, stllrh, stlr, stlrb, stlrh, stlur, stlurb, stlurh, stp, stxr, stxrb,
 *           stxrh, stxp, stlxr, stlxrb. stlxrh, stlxp, stnp, sttr, sttrb, sttrh
 */
static RzILOpEffect *str(cs_insn *insn) {
	if (!ISREG(0) || !REGBITS(0)) {
		return NULL;
	}
	bool result = insn->id == CS_AARCH64(_INS_STXR) || insn->id == CS_AARCH64(_INS_STXRB) || insn->id == CS_AARCH64(_INS_STXRH) || insn->id == CS_AARCH64(_INS_STXP) ||
		insn->id == CS_AARCH64(_INS_STLXR) || insn->id == CS_AARCH64(_INS_STLXRB) || insn->id == CS_AARCH64(_INS_STLXRH) || insn->id == CS_AARCH64(_INS_STLXP);
	bool pair = insn->id == CS_AARCH64(_INS_STP) || insn->id == CS_AARCH64(_INS_STNP) || insn->id == CS_AARCH64(_INS_STXP) || insn->id == CS_AARCH64(_INS_STLXP);
	size_t src_op = result ? 1 : 0;
	size_t addr_op = (result ? 1 : 0) + 1 + (pair ? 1 : 0);
	ut32 addr_bits = 64;
	RzILOpBitVector *addr = ARG(addr_op, &addr_bits);
	if (!addr) {
		return NULL;
	}
	ut32 bits;
	switch (insn->id) {
	case CS_AARCH64(_INS_STRB):
	case CS_AARCH64(_INS_STURB):
	case CS_AARCH64(_INS_STLRB):
	case CS_AARCH64(_INS_STXRB):
	case CS_AARCH64(_INS_STLXRB):
	case CS_AARCH64(_INS_STTRB):
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_STLLRB):
	case CS_AARCH64(_INS_STLURB):
#endif
		bits = 8;
		break;
	case CS_AARCH64(_INS_STRH):
	case CS_AARCH64(_INS_STURH):
	case CS_AARCH64(_INS_STLRH):
	case CS_AARCH64(_INS_STXRH):
	case CS_AARCH64(_INS_STLXRH):
	case CS_AARCH64(_INS_STTRH):
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_STLLRH):
	case CS_AARCH64(_INS_STLURH):
#endif
		bits = 16;
		break;
	default:
		// CS_AARCH64(_INS_STR), CS_AARCH64(_INS_STUR), CS_AARCH64(_INS_STLLR), CS_AARCH64(_INS_STLR), CS_AARCH64(_INS_STLUR), CS_AARCH64(_INS_STP),
		// CS_AARCH64(_INS_STXR), CS_AARCH64(_INS_STXP), CS_AARCH64(_INS_STLXR), CS_AARCH64(_INS_STLXP), CS_AARCH64(_INS_STNP), CS_AARCH64(_INS_STTR)
		bits = REGBITS(src_op);
		if (!bits) {
			rz_il_op_pure_free(addr);
			return NULL;
		}
		break;
	}
	RzILOpBitVector *val = ARG(src_op, &bits);
	if (!val) {
		rz_il_op_pure_free(addr);
		return NULL;
	}
	RzILOpBitVector *val2 = NULL;
	if (pair) {
		val2 = ARG(src_op + 1, &bits);
		if (!val2) {
			rz_il_op_pure_free(val);
			rz_il_op_pure_free(addr);
			return NULL;
		}
	}
	RzILOpEffect *eff = bits == 8 ? STORE(addr, val) : STOREW(addr, val);
	if (pair) {
		RzILOpBitVector *addr2 = ADD(DUP(addr), U64(bits / 8));
		eff = SEQ2(eff, bits == 8 ? STORE(addr2, val2) : STOREW(addr2, val2));
	}
	RzILOpEffect *wb_eff = writeback(insn, addr_op, addr);
	if (wb_eff) {
		eff = SEQ2(eff, wb_eff);
	}
	if (result) {
		// always successful
		RzILOpEffect *res_eff = write_reg(REGID(0), UN(REGBITS(0), 0));
		if (!res_eff) {
			rz_il_op_effect_free(eff);
			return NULL;
		}
		eff = SEQ2(eff, res_eff);
	}
	return eff;
}

#if CS_API_MAJOR > 4
/**
 * Capstone: CS_AARCH64(_INS_LDADD), CS_AARCH64(_INS_LDADDA), CS_AARCH64(_INS_LDADDAL), CS_AARCH64(_INS_LDADDL),
 *           CS_AARCH64(_INS_LDADDB), CS_AARCH64(_INS_LDADDAB), CS_AARCH64(_INS_LDADDALB), CS_AARCH64(_INS_LDADDLB),
 *           CS_AARCH64(_INS_LDADDH), CS_AARCH64(_INS_LDADDAH), CS_AARCH64(_INS_LDADDALH), CS_AARCH64(_INS_LDADDLH),
 *           CS_AARCH64(_INS_STADD), CS_AARCH64(_INS_STADDL), CS_AARCH64(_INS_STADDB), CS_AARCH64(_INS_STADDLB), CS_AARCH64(_INS_STADDH), CS_AARCH64(_INS_STADDLH),
 *           CS_AARCH64(_INS_LDCLRB), CS_AARCH64(_INS_LDCLRAB), CS_AARCH64(_INS_LDCLRALB), CS_AARCH64(_INS_LDCLRLB),
 *           CS_AARCH64(_INS_LDCLRH), CS_AARCH64(_INS_LDCLRAH), CS_AARCH64(_INS_LDCLRALH), CS_AARCH64(_INS_LDCLRLH)
 *           CS_AARCH64(_INS_LDCLR), CS_AARCH64(_INS_LDCLRA), CS_AARCH64(_INS_LDCLRAL), CS_AARCH64(_INS_LDCLRL),
 *           CS_AARCH64(_INS_STSETB), CS_AARCH64(_INS_STSETLB), CS_AARCH64(_INS_STSETH), CS_AARCH64(_INS_STSETLH), CS_AARCH64(_INS_STSET), CS_AARCH64(_INS_STSETL),
 *           CS_AARCH64(_INS_LDSETB), CS_AARCH64(_INS_LDSETAB), CS_AARCH64(_INS_LDSETALB), CS_AARCH64(_INS_LDSETLB),
 *           CS_AARCH64(_INS_LDSETH), CS_AARCH64(_INS_LDSETAH), CS_AARCH64(_INS_LDSETALH), CS_AARCH64(_INS_LDSETLH)
 *           CS_AARCH64(_INS_LDSET), CS_AARCH64(_INS_LDSETA), CS_AARCH64(_INS_LDSETAL), CS_AARCH64(_INS_LDSETL),
 *           CS_AARCH64(_INS_STSETB), CS_AARCH64(_INS_STSETLB), CS_AARCH64(_INS_STSETH), CS_AARCH64(_INS_STSETLH), CS_AARCH64(_INS_STSET), CS_AARCH64(_INS_STSETL),
 *           CS_AARCH64(_INS_LDSMAXB), CS_AARCH64(_INS_LDSMAXAB), CS_AARCH64(_INS_LDSMAXALB), CS_AARCH64(_INS_LDSMAXLB),
 *           CS_AARCH64(_INS_LDSMAXH), CS_AARCH64(_INS_LDSMAXAH), CS_AARCH64(_INS_LDSMAXALH), CS_AARCH64(_INS_LDSMAXLH)
 *           CS_AARCH64(_INS_LDSMAX), CS_AARCH64(_INS_LDSMAXA), CS_AARCH64(_INS_LDSMAXAL), CS_AARCH64(_INS_LDSMAXL),
 *           CS_AARCH64(_INS_STSMAXB), CS_AARCH64(_INS_STSMAXLB), CS_AARCH64(_INS_STSMAXH), CS_AARCH64(_INS_STSMAXLH), CS_AARCH64(_INS_STSMAX), CS_AARCH64(_INS_STSMAXL),
 *           CS_AARCH64(_INS_LDSMINB), CS_AARCH64(_INS_LDSMINAB), CS_AARCH64(_INS_LDSMINALB), CS_AARCH64(_INS_LDSMINLB),
 *           CS_AARCH64(_INS_LDSMINH), CS_AARCH64(_INS_LDSMINAH), CS_AARCH64(_INS_LDSMINALH), CS_AARCH64(_INS_LDSMINLH)
 *           CS_AARCH64(_INS_LDSMIN), CS_AARCH64(_INS_LDSMINA), CS_AARCH64(_INS_LDSMINAL), CS_AARCH64(_INS_LDSMINL),
 *           CS_AARCH64(_INS_STSMINB), CS_AARCH64(_INS_STSMINLB), CS_AARCH64(_INS_STSMINH), CS_AARCH64(_INS_STSMINLH), CS_AARCH64(_INS_STSMIN), CS_AARCH64(_INS_STSMINL),
 *           CS_AARCH64(_INS_LDUMAXB), CS_AARCH64(_INS_LDUMAXAB), CS_AARCH64(_INS_LDUMAXALB), CS_AARCH64(_INS_LDUMAXLB),
 *           CS_AARCH64(_INS_LDUMAXH), CS_AARCH64(_INS_LDUMAXAH), CS_AARCH64(_INS_LDUMAXALH), CS_AARCH64(_INS_LDUMAXLH)
 *           CS_AARCH64(_INS_LDUMAX), CS_AARCH64(_INS_LDUMAXA), CS_AARCH64(_INS_LDUMAXAL), CS_AARCH64(_INS_LDUMAXL),
 *           CS_AARCH64(_INS_STUMAXB), CS_AARCH64(_INS_STUMAXLB), CS_AARCH64(_INS_STUMAXH), CS_AARCH64(_INS_STUMAXLH), CS_AARCH64(_INS_STUMAX), CS_AARCH64(_INS_STUMAXL),
 *           CS_AARCH64(_INS_LDUMINB), CS_AARCH64(_INS_LDUMINAB), CS_AARCH64(_INS_LDUMINALB), CS_AARCH64(_INS_LDUMINLB),
 *           CS_AARCH64(_INS_LDUMINH), CS_AARCH64(_INS_LDUMINAH), CS_AARCH64(_INS_LDUMINALH), CS_AARCH64(_INS_LDUMINLH)
 *           CS_AARCH64(_INS_LDUMIN), CS_AARCH64(_INS_LDUMINA), CS_AARCH64(_INS_LDUMINAL), CS_AARCH64(_INS_LDUMINL),
 *           CS_AARCH64(_INS_STUMINB), CS_AARCH64(_INS_STUMINLB), CS_AARCH64(_INS_STUMINH), CS_AARCH64(_INS_STUMINLH), CS_AARCH64(_INS_STUMIN), CS_AARCH64(_INS_STUMINL)
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
	CS_aarch64_reg() addend_reg = REGID(0);
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
	case CS_AARCH64(_INS_LDCLRB):
	case CS_AARCH64(_INS_LDCLRAB):
	case CS_AARCH64(_INS_LDCLRALB):
	case CS_AARCH64(_INS_LDCLRLB):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STCLRB):
	case CS_AARCH64(_INS_STCLRLB):
#endif
		op = OP_CLR;
		loadsz = 8;
		break;
	case CS_AARCH64(_INS_LDEORB):
	case CS_AARCH64(_INS_LDEORAB):
	case CS_AARCH64(_INS_LDEORALB):
	case CS_AARCH64(_INS_LDEORLB):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STEORB):
	case CS_AARCH64(_INS_STEORLB):
#endif
		op = OP_EOR;
		loadsz = 8;
		break;
	case CS_AARCH64(_INS_LDSETB):
	case CS_AARCH64(_INS_LDSETAB):
	case CS_AARCH64(_INS_LDSETALB):
	case CS_AARCH64(_INS_LDSETLB):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STSETB):
	case CS_AARCH64(_INS_STSETLB):
#endif
		op = OP_SET;
		loadsz = 8;
		break;
	case CS_AARCH64(_INS_LDSMAXB):
	case CS_AARCH64(_INS_LDSMAXAB):
	case CS_AARCH64(_INS_LDSMAXALB):
	case CS_AARCH64(_INS_LDSMAXLB):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STSMAXB):
	case CS_AARCH64(_INS_STSMAXLB):
#endif
		op = OP_SMAX;
		loadsz = 8;
		break;
	case CS_AARCH64(_INS_LDSMINB):
	case CS_AARCH64(_INS_LDSMINAB):
	case CS_AARCH64(_INS_LDSMINALB):
	case CS_AARCH64(_INS_LDSMINLB):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STSMINB):
	case CS_AARCH64(_INS_STSMINLB):
#endif
		op = OP_SMIN;
		loadsz = 8;
		break;
	case CS_AARCH64(_INS_LDUMAXB):
	case CS_AARCH64(_INS_LDUMAXAB):
	case CS_AARCH64(_INS_LDUMAXALB):
	case CS_AARCH64(_INS_LDUMAXLB):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STUMAXB):
	case CS_AARCH64(_INS_STUMAXLB):
#endif
		op = OP_UMAX;
		loadsz = 8;
		break;
	case CS_AARCH64(_INS_LDUMINB):
	case CS_AARCH64(_INS_LDUMINAB):
	case CS_AARCH64(_INS_LDUMINALB):
	case CS_AARCH64(_INS_LDUMINLB):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STUMINB):
	case CS_AARCH64(_INS_STUMINLB):
#endif
		op = OP_UMIN;
		loadsz = 8;
		break;
	case CS_AARCH64(_INS_LDADDB):
	case CS_AARCH64(_INS_LDADDAB):
	case CS_AARCH64(_INS_LDADDALB):
	case CS_AARCH64(_INS_LDADDLB):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STADDB):
	case CS_AARCH64(_INS_STADDLB):
#endif
		loadsz = 8;
		break;

	case CS_AARCH64(_INS_LDCLRH):
	case CS_AARCH64(_INS_LDCLRAH):
	case CS_AARCH64(_INS_LDCLRALH):
	case CS_AARCH64(_INS_LDCLRLH):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STCLRH):
	case CS_AARCH64(_INS_STCLRLH):
#endif
		op = OP_CLR;
		loadsz = 16;
		break;
	case CS_AARCH64(_INS_LDEORH):
	case CS_AARCH64(_INS_LDEORAH):
	case CS_AARCH64(_INS_LDEORALH):
	case CS_AARCH64(_INS_LDEORLH):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STEORH):
	case CS_AARCH64(_INS_STEORLH):
#endif
		op = OP_EOR;
		loadsz = 16;
		break;
	case CS_AARCH64(_INS_LDSETH):
	case CS_AARCH64(_INS_LDSETAH):
	case CS_AARCH64(_INS_LDSETALH):
	case CS_AARCH64(_INS_LDSETLH):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STSETH):
	case CS_AARCH64(_INS_STSETLH):
#endif
		op = OP_SET;
		loadsz = 16;
		break;
	case CS_AARCH64(_INS_LDSMAXH):
	case CS_AARCH64(_INS_LDSMAXAH):
	case CS_AARCH64(_INS_LDSMAXALH):
	case CS_AARCH64(_INS_LDSMAXLH):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STSMAXH):
	case CS_AARCH64(_INS_STSMAXLH):
#endif
		op = OP_SMAX;
		loadsz = 16;
		break;
	case CS_AARCH64(_INS_LDSMINH):
	case CS_AARCH64(_INS_LDSMINAH):
	case CS_AARCH64(_INS_LDSMINALH):
	case CS_AARCH64(_INS_LDSMINLH):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STSMINH):
	case CS_AARCH64(_INS_STSMINLH):
#endif
		op = OP_SMIN;
		loadsz = 16;
		break;
	case CS_AARCH64(_INS_LDUMAXH):
	case CS_AARCH64(_INS_LDUMAXAH):
	case CS_AARCH64(_INS_LDUMAXALH):
	case CS_AARCH64(_INS_LDUMAXLH):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STUMAXH):
	case CS_AARCH64(_INS_STUMAXLH):
#endif
		op = OP_UMAX;
		loadsz = 16;
		break;
	case CS_AARCH64(_INS_LDUMINH):
	case CS_AARCH64(_INS_LDUMINAH):
	case CS_AARCH64(_INS_LDUMINALH):
	case CS_AARCH64(_INS_LDUMINLH):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STUMINH):
	case CS_AARCH64(_INS_STUMINLH):
#endif
		op = OP_UMIN;
		loadsz = 16;
		break;
	case CS_AARCH64(_INS_LDADDH):
	case CS_AARCH64(_INS_LDADDAH):
	case CS_AARCH64(_INS_LDADDALH):
	case CS_AARCH64(_INS_LDADDLH):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STADDH):
	case CS_AARCH64(_INS_STADDLH):
#endif
		loadsz = 16;
		break;

	case CS_AARCH64(_INS_LDCLR):
	case CS_AARCH64(_INS_LDCLRA):
	case CS_AARCH64(_INS_LDCLRAL):
	case CS_AARCH64(_INS_LDCLRL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STCLR):
	case CS_AARCH64(_INS_STCLRL):
#endif
		op = OP_CLR;
		goto size_from_reg;
	case CS_AARCH64(_INS_LDEOR):
	case CS_AARCH64(_INS_LDEORA):
	case CS_AARCH64(_INS_LDEORAL):
	case CS_AARCH64(_INS_LDEORL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STEOR):
	case CS_AARCH64(_INS_STEORL):
#endif
		op = OP_EOR;
		goto size_from_reg;
	case CS_AARCH64(_INS_LDSET):
	case CS_AARCH64(_INS_LDSETA):
	case CS_AARCH64(_INS_LDSETAL):
	case CS_AARCH64(_INS_LDSETL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STSET):
	case CS_AARCH64(_INS_STSETL):
#endif
		op = OP_SET;
		goto size_from_reg;
	case CS_AARCH64(_INS_LDSMAX):
	case CS_AARCH64(_INS_LDSMAXA):
	case CS_AARCH64(_INS_LDSMAXAL):
	case CS_AARCH64(_INS_LDSMAXL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STSMAX):
	case CS_AARCH64(_INS_STSMAXL):
#endif
		op = OP_SMAX;
		goto size_from_reg;
	case CS_AARCH64(_INS_LDSMIN):
	case CS_AARCH64(_INS_LDSMINA):
	case CS_AARCH64(_INS_LDSMINAL):
	case CS_AARCH64(_INS_LDSMINL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STSMIN):
	case CS_AARCH64(_INS_STSMINL):
#endif
		op = OP_SMIN;
		goto size_from_reg;
	case CS_AARCH64(_INS_LDUMAX):
	case CS_AARCH64(_INS_LDUMAXA):
	case CS_AARCH64(_INS_LDUMAXAL):
	case CS_AARCH64(_INS_LDUMAXL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STUMAX):
	case CS_AARCH64(_INS_STUMAXL):
#endif
		op = OP_UMAX;
		goto size_from_reg;
	case CS_AARCH64(_INS_LDUMIN):
	case CS_AARCH64(_INS_LDUMINA):
	case CS_AARCH64(_INS_LDUMINAL):
	case CS_AARCH64(_INS_LDUMINL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STUMIN):
	case CS_AARCH64(_INS_STUMINL):
#endif
		op = OP_UMIN;
		// fallthrough
	size_from_reg:
	default: // CS_AARCH64(_INS_LDADD), CS_AARCH64(_INS_LDADDA), CS_AARCH64(_INS_LDADDAL), CS_AARCH64(_INS_LDADDL), CS_AARCH64(_INS_STADD), CS_AARCH64(_INS_STADDL)
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
		CS_aarch64_reg() dst_reg = REGID(1);
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
 * Capstone: CS_AARCH64(_INS_MADD), CS_AARCH64(_INS_MSUB)
 * ARM: madd, msub
 */
static RzILOpEffect *madd(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	if (!bits) {
		return NULL;
	}
	RzILOpBitVector *ma = ARG(1, &bits);
	RzILOpBitVector *mb = ARG(2, &bits);
	RzILOpBitVector *addend = ARG(3, &bits);
	if (!ma || !mb || !addend) {
		return NULL;
	}
	RzILOpBitVector *res;
	if (insn->id == CS_AARCH64(_INS_MSUB)) {
		res = SUB(addend, MUL(ma, mb));
	} else {
		res = ADD(MUL(ma, mb), addend);
	}
	return write_reg(REGID(0), res);
}

/**
 * Capstone: CS_AARCH64(_INS_MUL), CS_AARCH64(_INS_MNEG)
 * ARM: mul, mneg
 */
static RzILOpEffect *mul(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	if (!bits) {
		return NULL;
	}
	RzILOpBitVector *ma = ARG(1, &bits);
	RzILOpBitVector *mb = ARG(2, &bits);
	if (!ma || !mb) {
		rz_il_op_pure_free(ma);
		rz_il_op_pure_free(mb);
		return NULL;
	}
	RzILOpBitVector *res = MUL(ma, mb);
#if CS_NEXT_VERSION < 6
	if (insn->id == CS_AARCH64(_INS_MNEG)) {
		res = NEG(res);
	}
#else
	if (insn->alias_id == AARCH64_INS_ALIAS_MNEG) {
		res = NEG(res);
	}
#endif
	return write_reg(REGID(0), res);
}

static RzILOpEffect *movn(cs_insn *insn);

/**
 * Capstone: CS_AARCH64(_INS_MOV), CS_AARCH64(_INS_MOVZ)
 * ARM: mov, movz
 */
static RzILOpEffect *mov(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
#if CS_NEXT_VERSION < 6
	if (ISIMM(1) && IMM(1) == 0 && !strcmp(insn->mnemonic, "movn")) {
		// Capstone bug making 0000a012 indistinguishable from 0000a052
		// https://github.com/capstone-engine/capstone/issues/1857
		return movn(insn);
	}
#endif
	ut32 bits = REGBITS(0);
	if (!bits) {
		return NULL;
	}
#if CS_NEXT_VERSION < 6
	RzILOpBitVector *src = ARG(1, &bits);
#else
	RzILOpBitVector *src = NULL;
	if ((insn->alias_id == AARCH64_INS_ALIAS_MOV || insn->alias_id == AARCH64_INS_ALIAS_MOVZ) &&
		(REGID(1) == AARCH64_REG_XZR || REGID(1) == AARCH64_REG_WZR)) {
		// Sometimes regs are ORed with the zero register for the MOV alias.
		// Sometimes not.
		src = ARG(2, &bits);
	} else {
		src = ARG(1, &bits);
	}
#endif
	if (!src) {
		return NULL;
	}
	return write_reg(REGID(0), src);
}

/**
 * Capstone: CS_AARCH64(_INS_MOVK)
 * ARM: movk
 */
static RzILOpEffect *movk(cs_insn *insn) {
	if (!ISREG(0) || !ISIMM(1)) {
		return NULL;
	}
	ut32 bits = 0;
	RzILOpBitVector *src = ARG(0, &bits);
	if (!src) {
		return NULL;
	}
	CS_aarch64_op() *op = &insn->detail->CS_aarch64_.operands[1];
	ut32 shift = op->shift.type == CS_AARCH64(_SFT_LSL) ? op->shift.value : 0;
	return write_reg(REGID(0), LOGOR(LOGAND(src, UN(bits, ~(0xffffull << shift))), UN(bits, ((ut64)op->imm) << shift)));
}

/**
 * Capstone: CS_AARCH64(_INS_MOVN)
 * ARM: movn
 */
static RzILOpEffect *movn(cs_insn *insn) {
	if (!ISREG(0) || !ISIMM(1)) {
		return NULL;
	}
	// The only case where the movn encoding should be disassembled as "movn" is
	// when (IsZero(imm16) && hw != '00'), according to the "alias conditions" in the reference manual.
	// Unfortunately, capstone v4 seems to always disassemble as movn, so we still have to implement this.
	CS_aarch64_op() *op = &insn->detail->CS_aarch64_.operands[1];
	ut32 shift = op->shift.type == CS_AARCH64(_SFT_LSL) ? op->shift.value : 0;
	ut32 bits = REGBITS(0);
	if (!bits) {
		return NULL;
	}
	return write_reg(REGID(0), UN(bits, ~(((ut64)op->imm) << shift)));
}

/**
 * Capstone: CS_AARCH64(_INS_MSR)
 * ARM: msr
 */
static RzILOpEffect *msr(cs_insn *insn) {
	CS_aarch64_op() *op = &insn->detail->CS_aarch64_.operands[0];
#if CS_NEXT_VERSION >= 6
	if (op->type != CS_AARCH64(_OP_SYSREG) || (ut64)op->sysop.reg.sysreg != (ut64)CS_AARCH64(_SYSREG_NZCV)) {
		return NULL;
	}
#elif CS_API_MAJOR > 4 && CS_NEXT_VERSION < 6
	if (op->type != CS_AARCH64(_OP_SYS) || (ut64)op->sys != (ut64)ARM64_SYSREG_NZCV) {
		return NULL;
	}
#else
	if (op->type != CS_AARCH64(_OP_REG_MSR) || op->reg != 0xda10) {
		return NULL;
	}
#endif
	ut32 bits = 0;
	RzILOpBitVector *val = ARG(1, &bits);
	if (!val) {
		return NULL;
	}
	return SEQ4(
		SETG("nf", INV(IS_ZERO(LOGAND(val, UN(bits, 1ull << 31))))),
		SETG("zf", INV(IS_ZERO(LOGAND(DUP(val), UN(bits, 1ull << 30))))),
		SETG("cf", INV(IS_ZERO(LOGAND(DUP(val), UN(bits, 1ull << 29))))),
		SETG("vf", INV(IS_ZERO(LOGAND(DUP(val), UN(bits, 1ull << 28))))));
}

#if CS_API_MAJOR > 4
/**
 * Capstone: CS_AARCH64(_INS_RMIF)
 * ARM: rmif
 */
static RzILOpEffect *rmif(cs_insn *insn) {
	if (!ISIMM(1) || !ISIMM(2)) {
		return NULL;
	}
	ut32 bits = 64;
	RzILOpBitVector *val = ARG(0, &bits);
	if (!val) {
		return NULL;
	}
	ut64 lsb = IMM(1);
	ut64 mask = IMM(2);
	RzILOpEffect *eff = NULL;
	const char *flags[] = { "vf", "cf", "zf", "nf" };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(flags); i++) {
		if (!(mask & (1ull << i))) {
			continue;
		}
		if (eff) {
			val = DUP(val);
		}
		RzILOpEffect *set = SETG(flags[i], INV(IS_ZERO(LOGAND(val, UN(bits, 1ull << ((i + lsb) % 64))))));
		eff = eff ? SEQ2(set, eff) : set;
	}
	if (!eff) {
		rz_il_op_pure_free(val);
	}
	return eff ? eff : NOP();
}
#endif

/**
 * Capstone: CS_AARCH64(_INS_SBFX), CS_AARCH64(_INS_SBFIZ), CS_AARCH64(_INS_UBFX), CS_AARCH64(_INS_UBFIZ)
 * ARM: sbfx, sbfiz, ubfx, ubfiz
 */
static RzILOpEffect *usbfm(cs_insn *insn) {
	if (!ISREG(0) || !ISIMM(2) || !ISIMM(3)) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	if (!bits) {
		return NULL;
	}
	RzILOpBitVector *src = ARG(1, &bits);
	if (!src) {
		return NULL;
	}
	ut64 lsb = IMM(2);
	ut64 width = IMM(3);
	RzILOpBitVector *res;
#if CS_NEXT_VERSION < 6
	if (insn->id == CS_AARCH64(_INS_SBFIZ) || insn->id == CS_AARCH64(_INS_UBFIZ)) {
		res = SHIFTL0(UNSIGNED(width + lsb, src), UN(6, lsb));
	} else {
		// CS_AARCH64(_INS_SBFX), CS_AARCH64(_INS_UBFX)
		res = UNSIGNED(width, SHIFTR0(src, UN(6, lsb)));
	}
	bool is_signed = insn->id == CS_AARCH64(_INS_SBFX) || insn->id == CS_AARCH64(_INS_SBFIZ);
#else
	if (insn->alias_id == AARCH64_INS_ALIAS_SBFIZ || insn->alias_id == AARCH64_INS_ALIAS_UBFIZ) {
		// TODO: modulo usage depends on N and SF bit.
		// sf == 0 && N == 0 => mod 32.
		// sf == 1 && N == 1 => mod 64.
		width += 1;
		lsb = -lsb % 64;
		res = SHIFTL0(UNSIGNED(width + lsb, src), UN(6, lsb));
	} else if (insn->alias_id == AARCH64_INS_ALIAS_SBFX || insn->alias_id == AARCH64_INS_ALIAS_UBFX) {
		width = width - lsb + 1;
		res = UNSIGNED(width, SHIFTR0(src, UN(6, lsb)));
	} else if (insn->alias_id == AARCH64_INS_ALIAS_LSL) {
		// imms != 0x1f => mod 32
		// imms != 0x3f => mod 64
		ut32 m = IMM(3) != 0x1f ? 32 : 64;
		return write_reg(REGID(0), SHIFTL0(src, UN(6, -IMM(2) % m)));
	} else if (insn->alias_id == AARCH64_INS_ALIAS_LSR) {
		return write_reg(REGID(0), SHIFTR0(src, UN(6, IMM(2))));
	} else if (insn->alias_id == AARCH64_INS_ALIAS_ASR) {
		return write_reg(REGID(0), SHIFTR(MSB(src), DUP(src), UN(6, IMM(2))));
	} else {
		return NULL;
	}
	bool is_signed = insn->alias_id == AARCH64_INS_ALIAS_SBFX || insn->alias_id == AARCH64_INS_ALIAS_SBFIZ;
#endif
	res = LET("res", res, is_signed ? SIGNED(bits, VARLP("res")) : UNSIGNED(bits, VARLP("res")));
	return write_reg(REGID(0), res);
}

/**
 * Capstone: CS_AARCH64(_INS_MRS)
 * ARM: mrs
 */
static RzILOpEffect *mrs(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	CS_aarch64_op() *op = &insn->detail->CS_aarch64_.operands[1];
#if CS_NEXT_VERSION >= 6
	if (op->type != CS_AARCH64(_OP_SYSREG) || (ut64)op->sysop.reg.sysreg != (ut64)CS_AARCH64(_SYSREG_NZCV)) {
		return NULL;
	}
#elif CS_API_MAJOR > 4 && CS_NEXT_VERSION < 6
	if (op->type != CS_AARCH64(_OP_SYS) || (ut64)op->sys != (ut64)ARM64_SYSREG_NZCV) {
		return NULL;
	}
#else
	if (op->type != CS_AARCH64(_OP_REG_MRS) || op->reg != 0xda10) {
		return NULL;
	}
#endif
	ut32 bits = REGBITS(0);
	if (!bits) {
		return NULL;
	}
	return write_reg(REGID(0),
		LOGOR(ITE(VARG("nf"), UN(bits, 1ull << 31), UN(bits, 0)),
			LOGOR(ITE(VARG("zf"), UN(bits, 1ull << 30), UN(bits, 0)),
				LOGOR(ITE(VARG("cf"), UN(bits, 1ull << 29), UN(bits, 0)),
					ITE(VARG("vf"), UN(bits, 1ull << 28), UN(bits, 0))))));
}

/**
 * Capstone: CS_AARCH64(_INS_MVN), CS_AARCH64(_INS_NEG), CS_AARCH64(_INS_NEGS), CS_AARCH64(_INS_NGC), CS_AARCH64(_INS_NGCS)
 * ARM: mvn, neg, negs, ngc, ngcs
 */
static RzILOpEffect *mvn(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = 0;
#if CS_NEXT_VERSION < 6
	RzILOpBitVector *val = ARG(1, &bits);
#else
	// Reg at 1 is zero register
	RzILOpBitVector *val = ARG(2, &bits);
#endif
	if (!val) {
		return NULL;
	}
	RzILOpBitVector *res;
#if CS_NEXT_VERSION < 6
	switch (insn->id) {
	case CS_AARCH64(_INS_NEG):
	case CS_AARCH64(_INS_NEGS):
		res = NEG(val);
		break;
	case CS_AARCH64(_INS_NGC):
	case CS_AARCH64(_INS_NGCS):
		res = NEG(ADD(val, ITE(VARG("cf"), UN(bits, 0), UN(bits, 1))));
		break;
	default: // CS_AARCH64(_INS_MVN)
		res = LOGNOT(val);
		break;
	}
#else
	switch (insn->alias_id) {
	case AARCH64_INS_ALIAS_NEG:
	case AARCH64_INS_ALIAS_NEGS:
		res = NEG(val);
		break;
	case AARCH64_INS_ALIAS_NGC:
	case AARCH64_INS_ALIAS_NGCS:
		res = NEG(ADD(val, ITE(VARG("cf"), UN(bits, 0), UN(bits, 1))));
		break;
	case AARCH64_INS_ALIAS_MVN:
		res = LOGNOT(val);
		break;
	default:
		return NULL;
	}
#endif
	RzILOpEffect *set = write_reg(REGID(0), res);
	if (!set) {
		return NULL;
	}
	if (insn->detail->CS_aarch64_.update_flags) {
		// MSVC pre-processor can't parse "#if CS_NEXT... SETG(...) ..." if it is inlined.
		// So we define a variable here. Otherwise we get "error C2121".
#if CS_NEXT_VERSION < 6
		RzILOpEffect *set_cf = SETG("cf", sub_carry(UN(bits, 0), VARL("b"), insn->id == CS_AARCH64(_INS_NGC), bits));
#else
		RzILOpEffect *set_cf = SETG("cf", sub_carry(UN(bits, 0), VARL("b"), insn->alias_id == AARCH64_INS_ALIAS_NGC, bits));
#endif
		return SEQ5(
			SETL("b", DUP(val)),
			set,
			set_cf,
			SETG("vf", sub_overflow(UN(bits, 0), VARL("b"), REG(0))),
			update_flags_zn(REG(0)));
	}
	return set;
}

/**
 * Capstone: CS_AARCH64(_INS_RBIT)
 * ARM: rbit
 */
static RzILOpEffect *rbit(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = 0;
	RzILOpBitVector *v = ARG(1, &bits);
	if (!v) {
		return NULL;
	}
	RzILOpEffect *eff = write_reg(REGID(0), VARL("r"));
	if (!eff) {
		return NULL;
	}
	return SEQ5(
		SETL("v", v),
		SETL("i", UN(6, bits)),
		SETL("r", UN(bits, 0x0)),
		REPEAT(INV(IS_ZERO(VARL("v"))),
			SEQ3(
				SETL("i", SUB(VARL("i"), UN(6, 1))),
				SETL("r", LOGOR(VARL("r"), ITE(LSB(VARL("v")), SHIFTL0(UN(bits, 1), VARL("i")), UN(bits, 0)))),
				SETL("v", SHIFTR0(VARL("v"), UN(6, 1))))),
		eff);
}

/**
 * Capstone: CS_AARCH64(_INS_REV), CS_AARCH64(_INS_REV32), CS_AARCH64(_INS_REV16)
 * ARM: rev, rev32, rev16
 */
static RzILOpEffect *rev(cs_insn *insn) {
	if (!ISREG(0) || !ISREG(1)) {
		return NULL;
	}
	ut32 dst_bits = REGBITS(0);
	if (!dst_bits) {
		return NULL;
	}
	CS_aarch64_reg() src_reg = xreg_of_reg(REGID(1));
	ut32 container_bits = dst_bits;
	if (insn->id == CS_AARCH64(_INS_REV32)) {
		container_bits = 32;
	} else if (insn->id == CS_AARCH64(_INS_REV16)) {
		container_bits = 16;
	}
	RzILOpBitVector *src = read_reg(src_reg);
	if (!src) {
		return NULL;
	}
	RzILOpBitVector *res;
	if (container_bits == 16) {
		res = APPEND(
			APPEND(
				UNSIGNED(8, SHIFTR0(src, UN(6, 0x10))),
				UNSIGNED(8, SHIFTR0(DUP(src), UN(6, 0x18)))),
			APPEND(
				UNSIGNED(8, DUP(src)),
				UNSIGNED(8, SHIFTR0(DUP(src), UN(6, 0x8)))));
	} else {
		res = APPEND(
			APPEND(
				UNSIGNED(8, src),
				UNSIGNED(8, SHIFTR0(DUP(src), UN(6, 0x8)))),
			APPEND(
				UNSIGNED(8, SHIFTR0(DUP(src), UN(6, 0x10))),
				UNSIGNED(8, SHIFTR0(DUP(src), UN(6, 0x18)))));
	}
	if (dst_bits == 64) {
		if (container_bits == 16) {
			res = APPEND(
				APPEND(
					APPEND(
						UNSIGNED(8, SHIFTR0(DUP(src), UN(6, 0x30))),
						UNSIGNED(8, SHIFTR0(DUP(src), UN(6, 0x38)))),
					APPEND(
						UNSIGNED(8, SHIFTR0(DUP(src), UN(6, 0x20))),
						UNSIGNED(8, SHIFTR0(DUP(src), UN(6, 0x28))))),
				res);
		} else {
			RzILOpBitVector *high = APPEND(
				APPEND(
					UNSIGNED(8, SHIFTR0(DUP(src), UN(6, 0x20))),
					UNSIGNED(8, SHIFTR0(DUP(src), UN(6, 0x28)))),
				APPEND(
					UNSIGNED(8, SHIFTR0(DUP(src), UN(6, 0x30))),
					UNSIGNED(8, SHIFTR0(DUP(src), UN(6, 0x38)))));
			res = container_bits == 32 ? APPEND(high, res) : APPEND(res, high);
		}
	}
	return write_reg(REGID(0), res);
}

/**
 * Capstone: CS_AARCH64(_INS_SDIV)
 * ARM: sdiv
 */
static RzILOpEffect *sdiv(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	if (!bits) {
		return NULL;
	}
	RzILOpBitVector *a = ARG(1, &bits);
	RzILOpBitVector *b = ARG(2, &bits);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	return write_reg(REGID(0),
		ITE(EQ(b, UN(bits, 0)), UN(bits, 0),
			ITE(AND(EQ(a, UN(bits, 1ull << (bits - 1))), EQ(DUP(b), UN(bits, -1))),
				UN(bits, 1ull << (bits - 1)),
				SDIV(DUP(a), DUP(b)))));
}

/**
 * Capstone: CS_AARCH64(_INS_UDIV)
 * ARM: udiv
 */
static RzILOpEffect *udiv(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	ut32 bits = REGBITS(0);
	if (!bits) {
		return NULL;
	}
	RzILOpBitVector *a = ARG(1, &bits);
	RzILOpBitVector *b = ARG(2, &bits);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	return write_reg(REGID(0),
		ITE(EQ(b, UN(bits, 0)), UN(bits, 0), DIV(a, DUP(b))));
}

#if CS_API_MAJOR > 4
/**
 * Capstone: CS_AARCH64(_INS_SETF8), CS_AARCH64(_INS_SETF16)
 * ARM: setf8, setf16
 */
static RzILOpEffect *setf(cs_insn *insn) {
	if (!ISREG(0)) {
		return NULL;
	}
	RzILOpBitVector *val = read_reg(xreg_of_reg(REGID(0)));
	if (!val) {
		return NULL;
	}
	ut32 bits = insn->id == CS_AARCH64(_INS_SETF16) ? 16 : 8;
	return SEQ2(
		SETG("vf", XOR(MSB(UNSIGNED(bits + 1, val)), MSB(UNSIGNED(bits, DUP(val))))),
		update_flags_zn(UNSIGNED(bits, DUP(val))));
}
#endif

/**
 * Capstone: CS_AARCH64(_INS_SMADDL), CS_AARCH64(_INS_SMSUBL), CS_AARCH64(_INS_UMADDL), CS_AARCH64(_INS_UMSUBL)
 * ARM: smaddl, smsubl, umaddl, umsubl
 */
static RzILOpEffect *smaddl(cs_insn *insn) {
	if (!ISREG(0) || REGBITS(0) != 64) {
		return NULL;
	}
	ut32 bits = 32;
	RzILOpBitVector *x = ARG(1, &bits);
	RzILOpBitVector *y = ARG(2, &bits);
	bits = 64;
	RzILOpBitVector *addend = ARG(3, &bits);
	if (!x || !y || !addend) {
		rz_il_op_pure_free(x);
		rz_il_op_pure_free(y);
		rz_il_op_pure_free(addend);
		return NULL;
	}
	bool is_signed = insn->id == CS_AARCH64(_INS_SMADDL) || insn->id == CS_AARCH64(_INS_SMSUBL);
	RzILOpBitVector *res = MUL(is_signed ? SIGNED(64, x) : UNSIGNED(64, x), is_signed ? SIGNED(64, y) : UNSIGNED(64, y));
	if (insn->id == CS_AARCH64(_INS_SMSUBL) || insn->id == CS_AARCH64(_INS_UMSUBL)) {
		res = SUB(addend, res);
	} else {
		res = ADD(addend, res);
	}
	return write_reg(REGID(0), res);
}

/**
 * Capstone: CS_AARCH64(_INS_SMULL), CS_AARCH64(_INS_SMNEGL), CS_AARCH64(_INS_UMULL), CS_AARCH64(_INS_UMNEGL)
 * ARM: smull, smnegl, umull, umnegl
 */
static RzILOpEffect *smull(cs_insn *insn) {
	if (!ISREG(0) || REGBITS(0) != 64) {
		return NULL;
	}
	ut32 bits = 32;
	RzILOpBitVector *x = ARG(1, &bits);
	RzILOpBitVector *y = ARG(2, &bits);
	if (!x || !y) {
		rz_il_op_pure_free(x);
		rz_il_op_pure_free(y);
		return NULL;
	}
#if CS_NEXT_VERSION < 6
	bool is_signed = insn->id == CS_AARCH64(_INS_SMULL) || insn->id == CS_AARCH64(_INS_SMNEGL);
#else
	bool is_signed = insn->alias_id == AARCH64_INS_ALIAS_SMULL || insn->alias_id == AARCH64_INS_ALIAS_SMNEGL;
#endif
	RzILOpBitVector *res = MUL(is_signed ? SIGNED(64, x) : UNSIGNED(64, x), is_signed ? SIGNED(64, y) : UNSIGNED(64, y));
#if CS_NEXT_VERSION < 6
	if (insn->id == CS_AARCH64(_INS_SMNEGL) || insn->id == CS_AARCH64(_INS_UMNEGL)) {
		res = NEG(res);
	}
#else
	if (insn->alias_id == AARCH64_INS_ALIAS_SMNEGL || insn->alias_id == AARCH64_INS_ALIAS_UMNEGL) {
		res = NEG(res);
	}
#endif
	return write_reg(REGID(0), res);
}

/**
 * Capstone: CS_AARCH64(_INS_SMULH), CS_AARCH64(_INS_UMULH)
 * ARM: smulh, umulh
 */
static RzILOpEffect *smulh(cs_insn *insn) {
	if (!ISREG(0) || REGBITS(0) != 64) {
		return NULL;
	}
	ut32 bits = 64;
	RzILOpBitVector *x = ARG(1, &bits);
	RzILOpBitVector *y = ARG(2, &bits);
	if (!x || !y) {
		rz_il_op_pure_free(x);
		rz_il_op_pure_free(y);
		return NULL;
	}
	bool is_signed = insn->id == CS_AARCH64(_INS_SMULH);
	RzILOpBitVector *res = MUL(is_signed ? SIGNED(128, x) : UNSIGNED(128, x), is_signed ? SIGNED(128, y) : UNSIGNED(128, y));
	return write_reg(REGID(0), UNSIGNED(64, SHIFTR0(res, UN(7, 64))));
}

#if CS_API_MAJOR > 4
/**
 * Capstone: CS_AARCH64(_INS_SWP), CS_AARCH64(_INS_SWPA), CS_AARCH64(_INS_SWPAL), CS_AARCH64(_INS_SWPL),
 *           CS_AARCH64(_INS_SWPB), CS_AARCH64(_INS_SWPAB), CS_AARCH64(_INS_SWPALB), CS_AARCH64(_INS_SWPLB)
 *           CS_AARCH64(_INS_SWPH), CS_AARCH64(_INS_SWPAH), CS_AARCH64(_INS_SWPALH), CS_AARCH64(_INS_SWPLH)
 * ARM: swp, swpa, swpal, swpl, swpb, swpab, swpalb, swplb, swph, swpah, swpalh, swplh
 */
static RzILOpEffect *swp(cs_insn *insn) {
	if (!ISREG(0) || !ISREG(1)) {
		return NULL;
	}
	ut32 bits;
	switch (insn->id) {
	case CS_AARCH64(_INS_SWPB):
	case CS_AARCH64(_INS_SWPAB):
	case CS_AARCH64(_INS_SWPALB):
	case CS_AARCH64(_INS_SWPLB):
		bits = 8;
		break;
	case CS_AARCH64(_INS_SWPH):
	case CS_AARCH64(_INS_SWPAH):
	case CS_AARCH64(_INS_SWPALH):
	case CS_AARCH64(_INS_SWPLH):
		bits = 16;
		break;
	default: // CS_AARCH64(_INS_SWP), CS_AARCH64(_INS_SWPA), CS_AARCH64(_INS_SWPAL), CS_AARCH64(_INS_SWPL):
		bits = REGBITS(0);
		if (!bits) {
			return NULL;
		}
		break;
	}
	ut32 addr_bits = 64;
	RzILOpBitVector *addr = ARG(2, &addr_bits);
	if (!addr) {
		return NULL;
	}
	RzILOpBitVector *store_val = ARG(0, &bits);
	if (!addr || !store_val) {
		rz_il_op_pure_free(addr);
		rz_il_op_pure_free(store_val);
		return NULL;
	}
	RzILOpEffect *store_eff = bits == 8 ? STORE(addr, store_val) : STOREW(addr, store_val);
	CS_aarch64_reg() ret_reg = xreg_of_reg(REGID(1));
	if (ret_reg == CS_AARCH64(_REG_XZR)) {
		return store_eff;
	}
	RzILOpEffect *ret_eff = write_reg(ret_reg, bits != 64 ? UNSIGNED(64, VARL("ret")) : VARL("ret"));
	if (!ret_eff) {
		rz_il_op_effect_free(store_eff);
		return NULL;
	}
	return SEQ3(
		SETL("ret", bits == 8 ? LOAD(DUP(addr)) : LOADW(bits, DUP(addr))),
		store_eff,
		ret_eff);
}
#endif

/**
 * Capstone: CS_AARCH64(_INS_SXTB), CS_AARCH64(_INS_SXTH), CS_AARCH64(_INS_SXTW), CS_AARCH64(_INS_UXTB), CS_AARCH64(_INS_UXTH)
 * ARM: sxtb, sxth, sxtw, uxtb, uxth
 */
static RzILOpEffect *sxt(cs_insn *insn) {
	if (!ISREG(0) || !REGBITS(0)) {
		return NULL;
	}
	ut32 bits;
	bool is_signed = true;
#if CS_NEXT_VERSION < 6
	switch (insn->id) {
	case CS_AARCH64(_INS_UXTB):
		is_signed = false;
		// fallthrough
	case CS_AARCH64(_INS_SXTB):
		bits = 8;
		break;
	case CS_AARCH64(_INS_UXTH):
		is_signed = false;
		// fallthrough
	case CS_AARCH64(_INS_SXTH):
		bits = 16;
		break;
	default: // CS_AARCH64(_INS_SXTW)
		bits = 32;
		break;
	}
#else
	switch (insn->alias_id) {
	default:
		return NULL;
	case AARCH64_INS_ALIAS_UXTB:
		is_signed = false;
		// fallthrough
	case AARCH64_INS_ALIAS_SXTB:
		bits = 8;
		break;
	case AARCH64_INS_ALIAS_UXTH:
		is_signed = false;
		// fallthrough
	case AARCH64_INS_ALIAS_SXTH:
		bits = 16;
		break;
	case AARCH64_INS_ALIAS_SXTW:
		bits = 32;
		break;
	}
#endif
	RzILOpBitVector *src = ARG(1, &bits);
	if (!src) {
		return NULL;
	}
	return write_reg(REGID(0), is_signed ? SIGNED(REGBITS(0), src) : UNSIGNED(REGBITS(0), src));
}

/**
 * Capstone: CS_AARCH64(_INS_TBNZ), ARM64_TBZ
 * ARM: tbnz, tbz
 */
static RzILOpEffect *tbz(cs_insn *insn) {
	if (!ISIMM(1)) {
		return NULL;
	}
	ut32 bits = 64;
	RzILOpBitVector *src = ARG(0, &bits);
	RzILOpBitVector *tgt = ARG(2, &bits);
	if (!src || !tgt) {
		rz_il_op_pure_free(src);
		rz_il_op_pure_free(tgt);
		return NULL;
	}
	RzILOpBool *c = LSB(SHIFTR0(src, UN(6, IMM(1))));
	return insn->id == CS_AARCH64(_INS_TBNZ)
		? BRANCH(c, JMP(tgt), NULL)
		: BRANCH(c, NULL, JMP(tgt));
}

/**
 * Capstone: CS_AARCH64(_INS_TST)
 * ARM: tst
 */
static RzILOpEffect *tst(cs_insn *insn) {
	ut32 bits = 0;
#if CS_NEXT_VERSION < 6
	RzILOpBitVector *a = ARG(0, &bits);
	RzILOpBitVector *b = ARG(1, &bits);
#else
	// Operand 0 is the zero register the result is written to.
	RzILOpBitVector *a = ARG(1, &bits);
	RzILOpBitVector *b = ARG(2, &bits);
#endif
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	return update_flags_zn00(LOGAND(a, b));
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
 * - ADDG, SUBG, SUBP, SUBPS
 * - CMPP
 * - GMI
 * - IRG
 * - LDG, LDGM
 * - ST2G, STZ2G
 * - STG, STGM, STGP, STZG, STZGM
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
 * - XPACD, XPACI, XPACLRI
 * Stub-implemented Instructions:
 * - LDRAA, LDRAB: currently behave like regular ldr
 *
 * Cache maintenance, tlb maintenance and address translation
 * ----------------------------------------------------------
 * - AT
 * - CFP
 * - CPP
 * - SYS, SYSL
 * - DC
 * - DVP
 * - IC
 * - TLBI
 *
 * Miscellaneous
 * -------------
 * - BRK: causes a breakpoint instruction exception
 * - BTI: FEAT_BTI/Branch Target Identification
 * - CLREX: clears the local monitor
 * - CRC32B, CRC32H, CRC32W, CRC32X, CRC32CB, CRC32CH, CRC32CW, CRC32CX: does crc32
 * - CSDB, DMB, DSB, ESB, ISB, PSB CSYNC, PSSBB, SB, SSBB, TSB CSYNC: synchronization, memory barriers
 * - DCPS1, DCPS2, DCPS3, DRPS, HLT: debug
 * - ERET, ERETAA, ERETAB: exception return
 * - SMC: secure monitor call
 * - UDF: permanently undefined
 *
 * Not supported by capstone v4 or v5 at the time of writing
 * ---------------------------------------------------------
 * - AXFLAG, XAFLAG
 * - FEAT_MTE (see above)
 * - DGH
 * - LD64B
 * - ST64B
 * - ST64BV
 * - ST64BV0
 * - WFET
 */
RZ_IPI RzILOpEffect *rz_arm_cs_64_il(csh *handle, cs_insn *insn) {
	switch (insn->id) {
	case CS_AARCH64(_INS_HINT):
	case CS_AARCH64(_INS_PRFM):
	case CS_AARCH64(_INS_PRFUM):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_NOP):
	case CS_AARCH64(_INS_SEV):
	case CS_AARCH64(_INS_SEVL):
	case CS_AARCH64(_INS_WFE):
	case CS_AARCH64(_INS_WFI):
	case CS_AARCH64(_INS_YIELD):
#endif
		return NOP();
	case CS_AARCH64(_INS_ADD):
	case CS_AARCH64(_INS_ADC):
	case CS_AARCH64(_INS_SUB):
	case CS_AARCH64(_INS_SBC):
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_ADDS):
	case CS_AARCH64(_INS_SUBS):
	case CS_AARCH64(_INS_ADCS):
	case CS_AARCH64(_INS_SBCS):
#endif
#if CS_NEXT_VERSION >= 6
		if (insn->alias_id == AARCH64_INS_ALIAS_MOV ||
			insn->alias_id == AARCH64_INS_ALIAS_MOVZ) {
			return mov(insn);
		} else if (insn->alias_id == AARCH64_INS_ALIAS_CMP ||
			insn->alias_id == AARCH64_INS_ALIAS_CMN) {
			return cmp(insn);
		} else if (insn->alias_id == AARCH64_INS_ALIAS_NEG ||
			insn->alias_id == AARCH64_INS_ALIAS_NGC ||
			insn->alias_id == AARCH64_INS_ALIAS_NEGS ||
			insn->alias_id == AARCH64_INS_ALIAS_NGCS) {
			return mvn(insn);
		}
#endif
		return add_sub(insn);
	case CS_AARCH64(_INS_ADR):
	case CS_AARCH64(_INS_ADRP):
		return adr(insn);
	case CS_AARCH64(_INS_AND):
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_ANDS):
#endif
	case CS_AARCH64(_INS_EOR):
	case CS_AARCH64(_INS_EON):
	case CS_AARCH64(_INS_ORN):
	case CS_AARCH64(_INS_ORR):
#if CS_NEXT_VERSION >= 6
		if (insn->alias_id == AARCH64_INS_ALIAS_MOV ||
			insn->alias_id == AARCH64_INS_ALIAS_MOVZ) {
			return mov(insn);
		} else if (insn->alias_id == AARCH64_INS_ALIAS_TST) {
			return tst(insn);
		} else if (insn->alias_id == AARCH64_INS_ALIAS_MVN) {
			return mvn(insn);
		}
#endif
		return bitwise(insn);
	case CS_AARCH64(_INS_ASR):
	case CS_AARCH64(_INS_LSL):
	case CS_AARCH64(_INS_LSR):
	case CS_AARCH64(_INS_ROR):
		return shift(insn);
	case CS_AARCH64(_INS_B):
	case CS_AARCH64(_INS_BR):
	case CS_AARCH64(_INS_RET):
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_BRAA):
	case CS_AARCH64(_INS_BRAAZ):
	case CS_AARCH64(_INS_BRAB):
	case CS_AARCH64(_INS_BRABZ):
	case CS_AARCH64(_INS_RETAA):
	case CS_AARCH64(_INS_RETAB):
#endif
		return branch(insn);
	case CS_AARCH64(_INS_BL):
	case CS_AARCH64(_INS_BLR):
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_BLRAA):
	case CS_AARCH64(_INS_BLRAAZ):
	case CS_AARCH64(_INS_BLRAB):
	case CS_AARCH64(_INS_BLRABZ):
#endif
		return bl(insn);
	case CS_AARCH64(_INS_BFM):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_BFI):
	case CS_AARCH64(_INS_BFXIL):
#endif
		return bfm(insn);
	case CS_AARCH64(_INS_BIC):
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_BICS):
#endif
		return bic(insn);
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_CAS):
	case CS_AARCH64(_INS_CASA):
	case CS_AARCH64(_INS_CASAL):
	case CS_AARCH64(_INS_CASL):
	case CS_AARCH64(_INS_CASB):
	case CS_AARCH64(_INS_CASAB):
	case CS_AARCH64(_INS_CASALB):
	case CS_AARCH64(_INS_CASLB):
	case CS_AARCH64(_INS_CASH):
	case CS_AARCH64(_INS_CASAH):
	case CS_AARCH64(_INS_CASALH):
	case CS_AARCH64(_INS_CASLH):
		return cas(insn);
	case CS_AARCH64(_INS_CASP):
	case CS_AARCH64(_INS_CASPA):
	case CS_AARCH64(_INS_CASPAL):
	case CS_AARCH64(_INS_CASPL):
		return casp(insn);
#endif
	case CS_AARCH64(_INS_CBZ):
	case CS_AARCH64(_INS_CBNZ):
		return cbz(insn);
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_CMP):
	case CS_AARCH64(_INS_CMN):
#endif
	case CS_AARCH64(_INS_CCMP):
	case CS_AARCH64(_INS_CCMN):
		return cmp(insn);
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_CFINV):
		return SETG("cf", INV(VARG("cf")));
#endif
	case CS_AARCH64(_INS_CSINC):
	case CS_AARCH64(_INS_CSINV):
	case CS_AARCH64(_INS_CSNEG):
	case CS_AARCH64(_INS_CSEL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_CINC):
	case CS_AARCH64(_INS_CINV):
	case CS_AARCH64(_INS_CNEG):
#else
		if (insn->alias_id == AARCH64_INS_ALIAS_CSET ||
			insn->alias_id == AARCH64_INS_ALIAS_CSETM) {
			return cset(insn);
		}
#endif
		return csinc(insn);
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_CSET):
	case CS_AARCH64(_INS_CSETM):
		return cset(insn);
#endif
	case CS_AARCH64(_INS_CLS):
		return cls(insn);
	case CS_AARCH64(_INS_CLZ):
		return clz(insn);
	case CS_AARCH64(_INS_EXTR):
#if CS_NEXT_VERSION >= 6
		if (insn->alias_id == AARCH64_INS_ALIAS_ROR) {
			return shift(insn);
		}
#endif
		return extr(insn);
	case CS_AARCH64(_INS_HVC):
		return hvc(insn);
	case CS_AARCH64(_INS_SVC):
		return svc(insn);
	case CS_AARCH64(_INS_LDR):
	case CS_AARCH64(_INS_LDRB):
	case CS_AARCH64(_INS_LDRH):
	case CS_AARCH64(_INS_LDUR):
	case CS_AARCH64(_INS_LDURB):
	case CS_AARCH64(_INS_LDURH):
	case CS_AARCH64(_INS_LDRSW):
	case CS_AARCH64(_INS_LDRSB):
	case CS_AARCH64(_INS_LDRSH):
	case CS_AARCH64(_INS_LDURSW):
	case CS_AARCH64(_INS_LDURSB):
	case CS_AARCH64(_INS_LDURSH):
	case CS_AARCH64(_INS_LDAR):
	case CS_AARCH64(_INS_LDARB):
	case CS_AARCH64(_INS_LDARH):
	case CS_AARCH64(_INS_LDAXP):
	case CS_AARCH64(_INS_LDXP):
	case CS_AARCH64(_INS_LDAXR):
	case CS_AARCH64(_INS_LDAXRB):
	case CS_AARCH64(_INS_LDAXRH):
	case CS_AARCH64(_INS_LDP):
	case CS_AARCH64(_INS_LDNP):
	case CS_AARCH64(_INS_LDPSW):
	case CS_AARCH64(_INS_LDTR):
	case CS_AARCH64(_INS_LDTRB):
	case CS_AARCH64(_INS_LDTRH):
	case CS_AARCH64(_INS_LDTRSW):
	case CS_AARCH64(_INS_LDTRSB):
	case CS_AARCH64(_INS_LDTRSH):
	case CS_AARCH64(_INS_LDXR):
	case CS_AARCH64(_INS_LDXRB):
	case CS_AARCH64(_INS_LDXRH):
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_LDAPR):
	case CS_AARCH64(_INS_LDAPRB):
	case CS_AARCH64(_INS_LDAPRH):
	case CS_AARCH64(_INS_LDAPUR):
	case CS_AARCH64(_INS_LDAPURB):
	case CS_AARCH64(_INS_LDAPURH):
	case CS_AARCH64(_INS_LDAPURSB):
	case CS_AARCH64(_INS_LDAPURSH):
	case CS_AARCH64(_INS_LDAPURSW):
	case CS_AARCH64(_INS_LDLAR):
	case CS_AARCH64(_INS_LDLARB):
	case CS_AARCH64(_INS_LDLARH):
	case CS_AARCH64(_INS_LDRAA):
	case CS_AARCH64(_INS_LDRAB):
#endif
		return ldr(insn);
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_LDADD):
	case CS_AARCH64(_INS_LDADDA):
	case CS_AARCH64(_INS_LDADDAL):
	case CS_AARCH64(_INS_LDADDL):
	case CS_AARCH64(_INS_LDADDB):
	case CS_AARCH64(_INS_LDADDAB):
	case CS_AARCH64(_INS_LDADDALB):
	case CS_AARCH64(_INS_LDADDLB):
	case CS_AARCH64(_INS_LDADDH):
	case CS_AARCH64(_INS_LDADDAH):
	case CS_AARCH64(_INS_LDADDALH):
	case CS_AARCH64(_INS_LDADDLH):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STADD):
	case CS_AARCH64(_INS_STADDL):
	case CS_AARCH64(_INS_STADDB):
	case CS_AARCH64(_INS_STADDLB):
	case CS_AARCH64(_INS_STADDH):
	case CS_AARCH64(_INS_STADDLH):
#endif
	case CS_AARCH64(_INS_LDCLRB):
	case CS_AARCH64(_INS_LDCLRAB):
	case CS_AARCH64(_INS_LDCLRALB):
	case CS_AARCH64(_INS_LDCLRLB):
	case CS_AARCH64(_INS_LDCLRH):
	case CS_AARCH64(_INS_LDCLRAH):
	case CS_AARCH64(_INS_LDCLRALH):
	case CS_AARCH64(_INS_LDCLRLH):
	case CS_AARCH64(_INS_LDCLR):
	case CS_AARCH64(_INS_LDCLRA):
	case CS_AARCH64(_INS_LDCLRAL):
	case CS_AARCH64(_INS_LDCLRL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STCLR):
	case CS_AARCH64(_INS_STCLRL):
	case CS_AARCH64(_INS_STCLRB):
	case CS_AARCH64(_INS_STCLRLB):
	case CS_AARCH64(_INS_STCLRH):
	case CS_AARCH64(_INS_STCLRLH):
#endif
	case CS_AARCH64(_INS_LDEORB):
	case CS_AARCH64(_INS_LDEORAB):
	case CS_AARCH64(_INS_LDEORALB):
	case CS_AARCH64(_INS_LDEORLB):
	case CS_AARCH64(_INS_LDEORH):
	case CS_AARCH64(_INS_LDEORAH):
	case CS_AARCH64(_INS_LDEORALH):
	case CS_AARCH64(_INS_LDEORLH):
	case CS_AARCH64(_INS_LDEOR):
	case CS_AARCH64(_INS_LDEORA):
	case CS_AARCH64(_INS_LDEORAL):
	case CS_AARCH64(_INS_LDEORL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STEOR):
	case CS_AARCH64(_INS_STEORL):
	case CS_AARCH64(_INS_STEORB):
	case CS_AARCH64(_INS_STEORLB):
	case CS_AARCH64(_INS_STEORH):
	case CS_AARCH64(_INS_STEORLH):
#endif
	case CS_AARCH64(_INS_LDSETB):
	case CS_AARCH64(_INS_LDSETAB):
	case CS_AARCH64(_INS_LDSETALB):
	case CS_AARCH64(_INS_LDSETLB):
	case CS_AARCH64(_INS_LDSETH):
	case CS_AARCH64(_INS_LDSETAH):
	case CS_AARCH64(_INS_LDSETALH):
	case CS_AARCH64(_INS_LDSETLH):
	case CS_AARCH64(_INS_LDSET):
	case CS_AARCH64(_INS_LDSETA):
	case CS_AARCH64(_INS_LDSETAL):
	case CS_AARCH64(_INS_LDSETL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STSET):
	case CS_AARCH64(_INS_STSETL):
	case CS_AARCH64(_INS_STSETB):
	case CS_AARCH64(_INS_STSETLB):
	case CS_AARCH64(_INS_STSETH):
	case CS_AARCH64(_INS_STSETLH):
#endif
	case CS_AARCH64(_INS_LDSMAXB):
	case CS_AARCH64(_INS_LDSMAXAB):
	case CS_AARCH64(_INS_LDSMAXALB):
	case CS_AARCH64(_INS_LDSMAXLB):
	case CS_AARCH64(_INS_LDSMAXH):
	case CS_AARCH64(_INS_LDSMAXAH):
	case CS_AARCH64(_INS_LDSMAXALH):
	case CS_AARCH64(_INS_LDSMAXLH):
	case CS_AARCH64(_INS_LDSMAX):
	case CS_AARCH64(_INS_LDSMAXA):
	case CS_AARCH64(_INS_LDSMAXAL):
	case CS_AARCH64(_INS_LDSMAXL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STSMAX):
	case CS_AARCH64(_INS_STSMAXL):
	case CS_AARCH64(_INS_STSMAXB):
	case CS_AARCH64(_INS_STSMAXLB):
	case CS_AARCH64(_INS_STSMAXH):
	case CS_AARCH64(_INS_STSMAXLH):
#endif
	case CS_AARCH64(_INS_LDSMINB):
	case CS_AARCH64(_INS_LDSMINAB):
	case CS_AARCH64(_INS_LDSMINALB):
	case CS_AARCH64(_INS_LDSMINLB):
	case CS_AARCH64(_INS_LDSMINH):
	case CS_AARCH64(_INS_LDSMINAH):
	case CS_AARCH64(_INS_LDSMINALH):
	case CS_AARCH64(_INS_LDSMINLH):
	case CS_AARCH64(_INS_LDSMIN):
	case CS_AARCH64(_INS_LDSMINA):
	case CS_AARCH64(_INS_LDSMINAL):
	case CS_AARCH64(_INS_LDSMINL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STSMIN):
	case CS_AARCH64(_INS_STSMINL):
	case CS_AARCH64(_INS_STSMINB):
	case CS_AARCH64(_INS_STSMINLB):
	case CS_AARCH64(_INS_STSMINH):
	case CS_AARCH64(_INS_STSMINLH):
#endif
	case CS_AARCH64(_INS_LDUMAXB):
	case CS_AARCH64(_INS_LDUMAXAB):
	case CS_AARCH64(_INS_LDUMAXALB):
	case CS_AARCH64(_INS_LDUMAXLB):
	case CS_AARCH64(_INS_LDUMAXH):
	case CS_AARCH64(_INS_LDUMAXAH):
	case CS_AARCH64(_INS_LDUMAXALH):
	case CS_AARCH64(_INS_LDUMAXLH):
	case CS_AARCH64(_INS_LDUMAX):
	case CS_AARCH64(_INS_LDUMAXA):
	case CS_AARCH64(_INS_LDUMAXAL):
	case CS_AARCH64(_INS_LDUMAXL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STUMAX):
	case CS_AARCH64(_INS_STUMAXL):
	case CS_AARCH64(_INS_STUMAXB):
	case CS_AARCH64(_INS_STUMAXLB):
	case CS_AARCH64(_INS_STUMAXH):
	case CS_AARCH64(_INS_STUMAXLH):
#endif
	case CS_AARCH64(_INS_LDUMINB):
	case CS_AARCH64(_INS_LDUMINAB):
	case CS_AARCH64(_INS_LDUMINALB):
	case CS_AARCH64(_INS_LDUMINLB):
	case CS_AARCH64(_INS_LDUMINH):
	case CS_AARCH64(_INS_LDUMINAH):
	case CS_AARCH64(_INS_LDUMINALH):
	case CS_AARCH64(_INS_LDUMINLH):
	case CS_AARCH64(_INS_LDUMIN):
	case CS_AARCH64(_INS_LDUMINA):
	case CS_AARCH64(_INS_LDUMINAL):
	case CS_AARCH64(_INS_LDUMINL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_STUMIN):
	case CS_AARCH64(_INS_STUMINL):
	case CS_AARCH64(_INS_STUMINB):
	case CS_AARCH64(_INS_STUMINLB):
	case CS_AARCH64(_INS_STUMINH):
	case CS_AARCH64(_INS_STUMINLH):
#endif
		return ldadd(insn);
#endif
	case CS_AARCH64(_INS_MADD):
	case CS_AARCH64(_INS_MSUB):
#if CS_NEXT_VERSION >= 6
		if (insn->alias_id == AARCH64_INS_ALIAS_MUL ||
			insn->alias_id == AARCH64_INS_ALIAS_MNEG) {
			return mul(insn);
		}
#endif
		return madd(insn);
	case CS_AARCH64(_INS_MUL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_MNEG):
#endif
		return mul(insn);
	case CS_AARCH64(_INS_MOV):
	case CS_AARCH64(_INS_MOVZ):
		return mov(insn);
	case CS_AARCH64(_INS_MOVK):
		return movk(insn);
	case CS_AARCH64(_INS_MOVN):
		return movn(insn);
	case CS_AARCH64(_INS_MSR):
		return msr(insn);
	case CS_AARCH64(_INS_MRS):
		return mrs(insn);
	case CS_AARCH64(_INS_NEG):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_MVN):
	case CS_AARCH64(_INS_NGC):
	case CS_AARCH64(_INS_NEGS):
	case CS_AARCH64(_INS_NGCS):
#endif
		return mvn(insn);
	case CS_AARCH64(_INS_RBIT):
		return rbit(insn);
	case CS_AARCH64(_INS_REV):
	case CS_AARCH64(_INS_REV32):
	case CS_AARCH64(_INS_REV16):
		return rev(insn);
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_RMIF):
		return rmif(insn);
#endif
	case CS_AARCH64(_INS_SBFM):
	case CS_AARCH64(_INS_UBFM):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_SBFIZ):
	case CS_AARCH64(_INS_SBFX):
	case CS_AARCH64(_INS_UBFIZ):
	case CS_AARCH64(_INS_UBFX):
#else
		if (insn->alias_id == AARCH64_INS_ALIAS_UXTH ||
			insn->alias_id == AARCH64_INS_ALIAS_UXTB ||
			insn->alias_id == AARCH64_INS_ALIAS_SXTH ||
			insn->alias_id == AARCH64_INS_ALIAS_SXTB ||
			insn->alias_id == AARCH64_INS_ALIAS_SXTW) {
			return sxt(insn);
		}
#endif
		return usbfm(insn);
	case CS_AARCH64(_INS_SDIV):
		return sdiv(insn);
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_SETF8):
	case CS_AARCH64(_INS_SETF16):
		return setf(insn);
#endif
	case CS_AARCH64(_INS_SMADDL):
	case CS_AARCH64(_INS_SMSUBL):
	case CS_AARCH64(_INS_UMADDL):
	case CS_AARCH64(_INS_UMSUBL):
#if CS_NEXT_VERSION >= 6
		if (insn->alias_id == AARCH64_INS_ALIAS_SMULL ||
			insn->alias_id == AARCH64_INS_ALIAS_UMULL ||
			insn->alias_id == AARCH64_INS_ALIAS_SMNEGL ||
			insn->alias_id == AARCH64_INS_ALIAS_UMNEGL) {
			return smull(insn);
		}
#endif
		return smaddl(insn);
	case CS_AARCH64(_INS_SMULL):
	case CS_AARCH64(_INS_UMULL):
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_SMNEGL):
	case CS_AARCH64(_INS_UMNEGL):
#endif
		return smull(insn);
	case CS_AARCH64(_INS_SMULH):
	case CS_AARCH64(_INS_UMULH):
		return smulh(insn);
	case CS_AARCH64(_INS_STR):
	case CS_AARCH64(_INS_STUR):
	case CS_AARCH64(_INS_STRB):
	case CS_AARCH64(_INS_STURB):
	case CS_AARCH64(_INS_STRH):
	case CS_AARCH64(_INS_STURH):
	case CS_AARCH64(_INS_STLR):
	case CS_AARCH64(_INS_STLRB):
	case CS_AARCH64(_INS_STLRH):
	case CS_AARCH64(_INS_STP):
	case CS_AARCH64(_INS_STNP):
	case CS_AARCH64(_INS_STXR):
	case CS_AARCH64(_INS_STXRB):
	case CS_AARCH64(_INS_STXRH):
	case CS_AARCH64(_INS_STXP):
	case CS_AARCH64(_INS_STLXR):
	case CS_AARCH64(_INS_STLXRB):
	case CS_AARCH64(_INS_STLXRH):
	case CS_AARCH64(_INS_STLXP):
	case CS_AARCH64(_INS_STTR):
	case CS_AARCH64(_INS_STTRB):
	case CS_AARCH64(_INS_STTRH):
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_STLLR):
	case CS_AARCH64(_INS_STLLRB):
	case CS_AARCH64(_INS_STLLRH):
	case CS_AARCH64(_INS_STLUR):
	case CS_AARCH64(_INS_STLURB):
	case CS_AARCH64(_INS_STLURH):
#endif
		return str(insn);
#if CS_API_MAJOR > 4
	case CS_AARCH64(_INS_SWP):
	case CS_AARCH64(_INS_SWPA):
	case CS_AARCH64(_INS_SWPAL):
	case CS_AARCH64(_INS_SWPL):
	case CS_AARCH64(_INS_SWPB):
	case CS_AARCH64(_INS_SWPAB):
	case CS_AARCH64(_INS_SWPALB):
	case CS_AARCH64(_INS_SWPLB):
	case CS_AARCH64(_INS_SWPH):
	case CS_AARCH64(_INS_SWPAH):
	case CS_AARCH64(_INS_SWPALH):
	case CS_AARCH64(_INS_SWPLH):
		return swp(insn);
#endif
	case CS_AARCH64(_INS_SXTB):
	case CS_AARCH64(_INS_SXTH):
	case CS_AARCH64(_INS_SXTW):
	case CS_AARCH64(_INS_UXTB):
	case CS_AARCH64(_INS_UXTH):
		return sxt(insn);
	case CS_AARCH64(_INS_TBNZ):
	case CS_AARCH64(_INS_TBZ):
		return tbz(insn);
#if CS_NEXT_VERSION < 6
	case CS_AARCH64(_INS_TST):
		return tst(insn);
#endif
	case CS_AARCH64(_INS_UDIV):
		return udiv(insn);
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
