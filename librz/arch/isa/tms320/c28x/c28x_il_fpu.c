// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/*
 * RzIL for the C28x FPU (SPRUHS1C chapters 1 and 2).
 *
 * The FPU computes the way TI's FPU primer (SPRAAN9A) describes: a denormal
 * operand counts as zero and a NaN as infinity, results never come out
 * denormal or NaN, and ADDF32, SUBF32 and MPYF32 round to zero or to nearest
 * even as STF.RND32 selects (SPRUHS1C table 1-2).
 */

#include "c28x_il.h"

#include <rz_il/rz_il_opbuilder_begin.h>

typedef RzILOpEffect *(*C28xFpuLifter)(const C28xInsn *insn);

static const char *c28x_fpu_regs[] = { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7" };
static const char *c28x_fpu_shadows[] = { "r0s", "r1s", "r2s", "r3s", "r4s", "r5s", "r6s", "r7s" };

/**
 * \brief STF flags by bit (SPRUHS1C figures 1-3 and 2-3); SHDWS, bit 31, is
 * left to SAVE and RESTORE.
 */
static const char *c28x_stf_bits[] = {
	[0] = "lvf",
	[1] = "luf",
	[2] = "nf",
	[3] = "zf",
	[4] = "ni",
	[5] = "zi",
	[6] = "tf",
	[9] = "rnd32",
	[10] = "rnd64",
};

/**
 * \brief The 64-bit IL global behind FPU register operand \p o, and in
 * \p high whether \p o names its RnH half (else its RnL half).
 */
static const char *c28x_fpu_name(const C28xOperand *o, bool *high) {
	if (o->kind != C28X_OP_REG) {
		return NULL;
	}
	if (o->reg >= C28X_REG_R0H && o->reg <= C28X_REG_R7H) {
		*high = true;
		return c28x_fpu_regs[o->reg - C28X_REG_R0H];
	}
	if (o->reg >= C28X_REG_R0L && o->reg <= C28X_REG_R7L) {
		*high = false;
		return c28x_fpu_regs[o->reg - C28X_REG_R0L];
	}
	return NULL;
}

// The 64-bit IL global of operand \p o when it names all of Ra (R0-R7).
static const char *c28x_fpu_name64(const C28xOperand *o) {
	if (o->kind != C28X_OP_REG || o->reg < C28X_REG_R0 || o->reg > C28X_REG_R7) {
		return NULL;
	}
	return c28x_fpu_regs[o->reg - C28X_REG_R0];
}

static RzILOpPure *c28x_fpu_read(const C28xOperand *o) {
	bool high;
	const char *n = c28x_fpu_name(o, &high);
	if (!n) {
		return NULL;
	}
	RzILOpPure *v = VARG(n);
	return UNSIGNED(32, high ? SHIFTR0(v, UN(8, 32)) : v);
}

// RnH and RnL are one register on FPU64 parts, so a write keeps the other half.
static RzILOpEffect *c28x_fpu_write(const C28xOperand *o, RzILOpPure *val) {
	bool high;
	const char *n = c28x_fpu_name(o, &high);
	if (!n) {
		rz_il_op_pure_free(val);
		return NULL;
	}
	RzILOpPure *v = UNSIGNED(64, val);
	if (high) {
		RzILOpPure *low = LOGAND(VARG(n), UN(64, 0xffffffffULL));
		return SETG(n, LOGOR(low, SHIFTL0(v, UN(8, 32))));
	}
	return SETG(n, LOGOR(LOGAND(VARG(n), UN(64, 0xffffffff00000000ULL)), v));
}

/**
 * \brief A binary format the FPU computes in: binary32 in RnH or RnL for FPU32
 * and binary64 in Rn for FPU64.
 */
typedef struct {
	RzFloatFormat format;
	ut32 bits;
	ut32 man; ///< mantissa width, where the exponent starts
	ut64 emax; ///< the exponent field of infinity and NaN
	const char *rnd; ///< the STF flag that rounds to nearest rather than truncating
} C28xFloat;

static const C28xFloat c28x_bin32 = { RZ_FLOAT_IEEE754_BIN_32, 32, 23, 0xff, "rnd32" };
static const C28xFloat c28x_bin64 = { RZ_FLOAT_IEEE754_BIN_64, 64, 52, 0x7ff, "rnd64" };

static ut64 c28x_fp_mask(const C28xFloat *f) {
	return f->bits == 64 ? UT64_MAX : UT32_MAX;
}

static ut64 c28x_fp_mant(const C28xFloat *f) {
	return (1ULL << f->man) - 1;
}

// The sign and exponent fields: a value's infinity of the same sign, as a mask.
static ut64 c28x_fp_top(const C28xFloat *f) {
	return ~c28x_fp_mant(f) & c28x_fp_mask(f);
}

static RzILOpPure *c28x_fp_read(const C28xFloat *f, const C28xOperand *o) {
	if (f->bits == 32) {
		return c28x_fpu_read(o);
	}
	const char *n = c28x_fpu_name64(o);
	return n ? VARG(n) : NULL;
}

static RzILOpEffect *c28x_fp_write(const C28xFloat *f, const C28xOperand *o, RzILOpPure *v) {
	if (f->bits == 32) {
		return c28x_fpu_write(o, v);
	}
	const char *n = c28x_fpu_name64(o);
	if (!n) {
		rz_il_op_pure_free(v);
		return NULL;
	}
	return SETG(n, v);
}

/**
 * \brief The bits of operand \p o: an FPU register, a #16FHi immediate (the
 * value's top 16 bits) or #0.0.
 */
static RzILOpPure *c28x_fp_operand(const C28xFloat *f, const C28xOperand *o) {
	if (o->kind == C28X_OP_IMM) {
		return UN(f->bits, (ut64)(o->imm & 0xffff) << (f->bits - 16));
	}
	if (o->kind == C28X_OP_FZERO) {
		return UN(f->bits, 0);
	}
	return c28x_fp_read(f, o);
}

static RzILOpPure *c28x_fp_exp(const C28xFloat *f, const char *local) {
	return LOGAND(SHIFTR0(VARL(local), UN(8, f->man)), UN(f->bits, f->emax));
}

/**
 * \brief The value in \p local as the FPU computes with it: zeros and
 * denormals as +0, NaN as the infinity of its sign.
 */
static RzILOpFloat *c28x_fp_in(const C28xFloat *f, const char *local) {
	RzILOpPure *inf = LOGAND(VARL(local), UN(f->bits, c28x_fp_top(f)));
	RzILOpPure *big = ITE(EQ(c28x_fp_exp(f, local), UN(f->bits, f->emax)), inf, VARL(local));
	return BV2F(f->format, ITE(IS_ZERO(c28x_fp_exp(f, local)), UN(f->bits, 0), big));
}

/**
 * \brief The IL locals of one binary32 operation: operand bits and their FPU
 * views, the result's bits, exponent, nonzero mantissa and flush, and the
 * exact result in binary64. Parallel forms run two operations, a set each.
 */
typedef struct {
	const char *xa, *xb, *fa, *fb, *fr, *fe, *fm, *ft, *fw;
} C28xFpLocals;

static const C28xFpLocals c28x_fp_one = { "xa", "xb", "fa", "fb", "fr", "fe", "fm", "ft", "fw" };
static const C28xFpLocals c28x_fp_two = { "ya", "yb", "ga", "gb", "gr", "ge", "gm", "gt", "gw" };

// Latch \p a and \p b and their FPU views.
static RzILOpEffect *c28x_fp_operands(const C28xFpLocals *l, const C28xFloat *f, RzILOpPure *a,
	RzILOpPure *b) {
	return SEQ4(SETL(l->xa, a), SETL(l->xb, b), SETL(l->fa, c28x_fp_in(f, l->xa)),
		SETL(l->fb, c28x_fp_in(f, l->xb)));
}

// A dynamic rounding mode is a 32-bit RzFloatRMode value.
static RzILOpBitVector *c28x_fp_rnd(const C28xFloat *f) {
	return ITE(VARG(f->rnd), UN(32, RZ_FLOAT_RMODE_RNE), UN(32, RZ_FLOAT_RMODE_RTZ));
}

/**
 * \brief Deliver the binary32 result \p res of the operands in \p l to \p dst.
 *
 * A denormal result flushes to +0 and latches LUF, as does a zero product of
 * nonzero factors when \p product; \p overflow latches LVF. The FPU never
 * delivers NaN, and SPRAAN9A doesn't say what it delivers for one, so
 * +infinity stands in.
 */
static RzILOpEffect *c28x_fp_out(const C28xFpLocals *l, const C28xFloat *f, const C28xOperand *dst,
	RzILOpFloat *res, bool product, RzILOpBool *overflow) {
	RzILOpBool *tiny = AND(IS_ZERO(VARL(l->fe)), VARL(l->fm));
	if (product) {
		RzILOpBool *factors = AND(INV(IS_FZERO(VARL(l->fa))), INV(IS_FZERO(VARL(l->fb))));
		RzILOpBool *zero = IS_ZERO(LOGAND(VARL(l->fr), UN(f->bits, c28x_fp_mask(f) >> 1)));
		tiny = OR(tiny, AND(zero, factors));
	}
	RzILOpPure *nan = AND(EQ(VARL(l->fe), UN(f->bits, f->emax)), VARL(l->fm));
	RzILOpPure *inf = UN(f->bits, f->emax << f->man);
	RzILOpPure *val = ITE(VARL(l->ft), UN(f->bits, 0), ITE(nan, inf, VARL(l->fr)));
	RzILOpEffect *wr = c28x_fp_write(f, dst, val);
	if (!wr) {
		rz_il_op_pure_free(res);
		rz_il_op_pure_free(tiny);
		rz_il_op_pure_free(overflow);
		return NULL;
	}
	RzILOpPure *mant = LOGAND(VARL(l->fr), UN(f->bits, c28x_fp_mant(f)));
	RzILOpEffect *luf = SETG("luf", OR(VARG("luf"), VARL(l->ft)));
	RzILOpEffect *lvf = SETG("lvf", OR(VARG("lvf"), overflow));
	return SEQ7(SETL(l->fr, F2BV(res)), SETL(l->fe, c28x_fp_exp(f, l->fr)),
		SETL(l->fm, NON_ZERO(mant)), SETL(l->ft, tiny), luf, lvf, wr);
}

/**
 * \brief NF and ZF from the binary32 value in \p local; negative zero and
 * denormals count as +0 (SPRUHS1C table 1-2).
 */
static RzILOpEffect *c28x_fp_nz(const C28xFloat *f, const char *local) {
	RzILOpBool *zero = IS_ZERO(LOGAND(VARL(local), UN(f->bits, f->emax << f->man)));
	RzILOpBool *neg = AND(MSB(VARL(local)), INV(DUP(zero)));
	return SEQ2(SETG("zf", zero), SETG("nf", neg));
}

// The binary32 value in \p local with a denormal as +0 and NaN as infinity.
static RzILOpPure *c28x_fp_flush(const C28xFloat *f, const char *local) {
	RzILOpPure *mant = NON_ZERO(LOGAND(VARL(local), UN(f->bits, c28x_fp_mant(f))));
	RzILOpPure *tiny = AND(IS_ZERO(c28x_fp_exp(f, local)), mant);
	RzILOpPure *nan = AND(EQ(c28x_fp_exp(f, local), UN(f->bits, f->emax)), DUP(mant));
	RzILOpPure *inf = LOGAND(VARL(local), UN(f->bits, c28x_fp_top(f)));
	return ITE(tiny, UN(f->bits, 0), ITE(nan, inf, VARL(local)));
}

static bool c28x_is_stf(const C28xOperand *o) {
	return o->kind == C28X_OP_REG && o->reg == C28X_REG_STF;
}

// NF, ZF, NI and ZI as MOV32 sets them from the word in \p local.
static RzILOpEffect *c28x_fp_movflags(const C28xFloat *f, const char *local) {
	RzILOpEffect *ni = SETG("ni", MSB(VARL(local)));
	return SEQ3(c28x_fp_nz(f, local), ni, SETG("zi", IS_ZERO(VARL(local))));
}

// STF as a word.
static RzILOpPure *c28x_stf_word(void) {
	RzILOpPure *w = ITE(VARG("shdws"), UN(32, 0x80000000), UN(32, 0));
	for (size_t i = 0; i < RZ_ARRAY_SIZE(c28x_stf_bits); i++) {
		if (c28x_stf_bits[i]) {
			w = LOGOR(w, ITE(VARG(c28x_stf_bits[i]), UN(32, 1U << i), UN(32, 0)));
		}
	}
	return w;
}

// Load STF from the word in \p local; SHDWS keeps its value (SPRUHS1C table 1-2).
static RzILOpEffect *c28x_stf_load(const char *local) {
	RzILOpEffect *eff = NOP();
	for (size_t i = 0; i < RZ_ARRAY_SIZE(c28x_stf_bits); i++) {
		if (c28x_stf_bits[i]) {
			RzILOpBool *bit = NON_ZERO(LOGAND(VARL(local), UN(32, 1U << i)));
			eff = SEQ2(eff, SETG(c28x_stf_bits[i], bit));
		}
	}
	return eff;
}

/**
 * \brief An FPU condition (SPRUHS1C table 1-7); NULL for reserved codes.
 *
 * The table prints LEQ as "ZF == 1 AND NF == 1", which no compare produces;
 * it reads as OR, like the C28x LEQ.
 */
static RzILOpBool *c28x_fcond(ut32 cond) {
	switch (cond) {
	case 0: return INV(VARG("zf"));
	case 1: return VARG("zf");
	case 2: return AND(INV(VARG("zf")), INV(VARG("nf")));
	case 3: return INV(VARG("nf"));
	case 4: return VARG("nf");
	case 5: return OR(VARG("zf"), VARG("nf"));
	case 10: return VARG("tf");
	case 11: return INV(VARG("tf"));
	case 12: return VARG("luf");
	case 13: return VARG("lvf");
	case 14:
	case 15: return IL_TRUE;
	default: return NULL;
	}
}

/**
 * \brief Run \p body with the latched address of mem32 operand \p m.
 *
 * mem32 is a 32-bit access, stepping pointers by two, even where the row
 * renders it as loc16, as dis2000 does for the conditional MOV32 loads.
 */
static RzILOpEffect *c28x_with_mem32(const C28xOperand *m, RzILOpEffect *body) {
	C28xOperand wide = *m;
	wide.wide = true;
	return c28x_with_ea(&wide, body);
}

// The binary64 view of the float in \p local: exact for binary32.
static RzILOpFloat *c28x_fp_widen(const C28xFloat *f, const char *local) {
	if (f->bits == 64) {
		return VARL(local);
	}
	return FCONVERT(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE, VARL(local));
}

// The FPU64 instructions, which compute in binary64 on whole registers.
static const bool c28x_fpu64[] = {
	[C28X_INS_ADDF64] = true,
	[C28X_INS_SUBF64] = true,
	[C28X_INS_MPYF64] = true,
	[C28X_INS_MACF64] = true,
	[C28X_INS_CMPF64] = true,
	[C28X_INS_MAXF64] = true,
	[C28X_INS_MINF64] = true,
	[C28X_INS_NEGF64] = true,
	[C28X_INS_ABSF64] = true,
	[C28X_INS_FRACF64] = true,
	[C28X_INS_MOV64] = true,
};

static const C28xFloat *c28x_fp_of(C28xInsnId id) {
	return (size_t)id < RZ_ARRAY_SIZE(c28x_fpu64) && c28x_fpu64[id] ? &c28x_bin64 : &c28x_bin32;
}

/**
 * \brief ADDF32/64, SUBF32/64 or MPYF32/64 (\p id) of \p a and \p b into
 * \p dst, as \p in, which reads the operands, and \p out, which writes the
 * result, so parallel forms can read every operand before writing anything.
 *
 * binary32 overflow is past the largest finite value plus half an ulp when
 * rounding to nearest and at 2^128 when truncating, which binary64 decides
 * exactly. binary64 results have no wider format here: overflow is taken as
 * the result rounded to nearest being infinite, which for truncation also
 * counts results within half an ulp below 2^1024.
 */
static bool c28x_fp_arith(const C28xFpLocals *l, const C28xFloat *f, C28xInsnId id,
	const C28xOperand *dst, RzILOpPure *a, RzILOpPure *b, RzILOpEffect **in,
	RzILOpEffect **out) {
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return false;
	}
	const bool add = id == C28X_INS_ADDF32 || id == C28X_INS_ADDF64;
	const bool sub = id == C28X_INS_SUBF32 || id == C28X_INS_SUBF64;
	RzILOpFloat *res;
	RzILOpFloat *x = c28x_fp_widen(f, l->fa);
	RzILOpFloat *y = c28x_fp_widen(f, l->fb);
	// binary32 results are also taken exactly in binary64, truncated, and binary64
	// ones rounded to nearest, where overflow gives infinity
	RzFloatRMode wide_mode = f->bits == 32 ? RZ_FLOAT_RMODE_RTZ : RZ_FLOAT_RMODE_RNE;
	RzILOpFloat *wide;
	if (add) {
		res = FADD_DYN_RMODE(c28x_fp_rnd(f), VARL(l->fa), VARL(l->fb));
		wide = FADD(wide_mode, x, y);
	} else if (sub) {
		res = FSUB_DYN_RMODE(c28x_fp_rnd(f), VARL(l->fa), VARL(l->fb));
		wide = FSUB(wide_mode, x, y);
	} else {
		res = FMUL_DYN_RMODE(c28x_fp_rnd(f), VARL(l->fa), VARL(l->fb));
		wide = FMUL(wide_mode, x, y);
	}
	RzILOpBool *finite = AND(IS_FINITE(VARL(l->fa)), IS_FINITE(VARL(l->fb)));
	RzILOpBool *overflow;
	if (f->bits == 32) {
		RzILOpFloat *limit = ITE(VARG("rnd32"), F64(0x1p128 - 0x1p103), F64(0x1p128));
		overflow = AND(finite, INV(FORDER(FABS(VARL(l->fw)), limit)));
	} else {
		overflow = AND(finite, IS_FINF(VARL(l->fw)));
	}
	RzILOpEffect *o = c28x_fp_out(l, f, dst, res, !add && !sub, overflow);
	if (!o) {
		rz_il_op_pure_free(wide);
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return false;
	}
	*in = c28x_fp_operands(l, f, a, b);
	*out = SEQ2(SETL(l->fw, wide), o);
	return true;
}

// The MOV32 half of a parallel form: MOV32 mem32,RaH, or MOV32 RaH,mem32 with its flags.
static RzILOpEffect *c28x_fpu_par_mov32(const C28xOperand *first, const C28xOperand *second) {
	if (c28x_is_mem(first)) {
		RzILOpPure *v = c28x_fpu_read(second);
		return v ? c28x_with_mem32(first, c28x_ea_store(v)) : NULL;
	}
	RzILOpEffect *wr = c28x_is_mem(second) ? c28x_fpu_write(first, VARL("mv")) : NULL;
	if (!wr) {
		return NULL;
	}
	RzILOpEffect *load = SETL("mv", c28x_ea_load(32));
	return c28x_with_mem32(second, SEQ3(load, wr, c28x_fp_movflags(&c28x_bin32, "mv")));
}

/**
 * \brief ADDF32, SUBF32 and MPYF32 with register and #16FHi operands, with a
 * parallel MOV32, and MPYF32 with a parallel ADDF32 or SUBF32.
 *
 * Parallel halves read their operands before either writes.
 */
static RzILOpEffect *c28x_fpu_arith(const C28xInsn *insn) {
	const C28xFloat *f = c28x_fp_of(insn->id);
	const C28xOperand *op = insn->ops;
	const bool par = insn->nops > 3 && op[3].kind == C28X_OP_PAR;
	if (insn->nops != 3 && !par) {
		return NULL;
	}
	RzILOpEffect *in;
	RzILOpEffect *out;
	RzILOpPure *a = c28x_fp_operand(f, &op[1]);
	RzILOpPure *b = c28x_fp_operand(f, &op[2]);
	if (!c28x_fp_arith(&c28x_fp_one, f, insn->id, &op[0], a, b, &in, &out)) {
		return NULL;
	}
	if (!par) {
		return SEQ2(in, out);
	}
	if (op[3].imm == C28X_INS_MOV32 && insn->nops == 6) {
		RzILOpEffect *mv = c28x_fpu_par_mov32(&op[4], &op[5]);
		if (mv) {
			return SEQ3(in, mv, out);
		}
	} else if (insn->nops == 7) {
		RzILOpEffect *in2;
		RzILOpEffect *out2;
		RzILOpPure *e = c28x_fp_read(f, &op[5]);
		RzILOpPure *g = c28x_fp_read(f, &op[6]);
		const C28xInsnId id = (C28xInsnId)op[3].imm;
		if (c28x_fp_arith(&c28x_fp_two, f, id, &op[4], e, g, &in2, &out2)) {
			return SEQ4(in, in2, out, out2);
		}
	}
	rz_il_op_effect_free(in);
	rz_il_op_effect_free(out);
	return NULL;
}

/**
 * \brief MACF32 R3H,R2H,RdH,ReH,RfH || MOV32 RaH,mem32 (or R7H,R6H), its
 * MACF64 counterpart on whole registers, and MACF32 R7H,R3H,mem32,*XAR7++.
 *
 * The first adds the previous product, R3H += R2H, while RdH = ReH * RfH;
 * the second on its own is R3H += R2H with R2H = [mem32] * [XAR7++]. Under
 * RPT the second alternates with R7H and R6H, which one instruction's IL
 * can't show.
 */
static RzILOpEffect *c28x_fpu_macf32(const C28xInsn *insn) {
	const C28xFloat *f = c28x_fp_of(insn->id);
	const bool single = insn->id == C28X_INS_MACF32 && insn->nops == 4;
	const C28xOperand *op = insn->ops;
	const C28xFpLocals *l1 = &c28x_fp_one;
	const C28xFpLocals *l2 = &c28x_fp_two;
	RzILOpEffect *in = NULL;
	RzILOpEffect *out = NULL;
	RzILOpEffect *in2 = NULL;
	RzILOpEffect *out2 = NULL;
	if (insn->nops == 8 && op[5].kind == C28X_OP_PAR) {
		RzILOpPure *acc = c28x_fp_read(f, &op[0]);
		RzILOpPure *prod = c28x_fp_read(f, &op[1]);
		RzILOpEffect *mv = NULL;
		if (c28x_fp_arith(l1, f, C28X_INS_ADDF32, &op[0], acc, prod, &in, &out)) {
			RzILOpPure *e = c28x_fp_read(f, &op[3]);
			RzILOpPure *g = c28x_fp_read(f, &op[4]);
			if (c28x_fp_arith(l2, f, C28X_INS_MPYF32, &op[2], e, g, &in2, &out2)) {
				mv = c28x_fpu_par_mov32(&op[6], &op[7]);
			}
		}
		if (mv) {
			return SEQ5(in, in2, mv, out, out2);
		}
	} else if (single && op[0].reg == C28X_REG_R7H && op[1].reg == C28X_REG_R3H &&
		c28x_is_mem(&op[2]) && c28x_is_mem(&op[3])) {
		const C28xOperand r2 = { .kind = C28X_OP_REG, .reg = C28X_REG_R0H + 2 };
		RzILOpPure *acc = c28x_fpu_read(&op[1]);
		RzILOpPure *prod = c28x_fpu_read(&r2);
		RzILOpPure *ma = VARL("ma");
		RzILOpPure *mb = VARL("mb");
		if (!c28x_fp_arith(l1, f, C28X_INS_ADDF32, &op[1], acc, prod, &in, &out)) {
			rz_il_op_pure_free(ma);
			rz_il_op_pure_free(mb);
		} else if (c28x_fp_arith(l2, f, C28X_INS_MPYF32, &r2, ma, mb, &in2, &out2)) {
			RzILOpEffect *b = c28x_with_mem32(&op[3], SETL("mb", c28x_ea_load(32)));
			RzILOpEffect *a = SETL("ma", c28x_ea_load(32));
			RzILOpEffect *loads = c28x_with_mem32(&op[2], SEQ2(a, b));
			return SEQ5(in, loads, in2, out, out2);
		}
	}
	rz_il_op_effect_free(in);
	rz_il_op_effect_free(out);
	rz_il_op_effect_free(in2);
	rz_il_op_effect_free(out2);
	return NULL;
}

/** \brief CMPF32 and CMPF64: ZF for equal, NF for less, on the FPU views of both. */
static RzILOpEffect *c28x_fpu_cmpf32(const C28xInsn *insn) {
	const C28xFloat *f = c28x_fp_of(insn->id);
	if (insn->nops != 2) {
		return NULL;
	}
	RzILOpPure *a = c28x_fp_operand(f, &insn->ops[0]);
	RzILOpPure *b = c28x_fp_operand(f, &insn->ops[1]);
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	RzILOpBool *lt = FORDER(VARL("fa"), VARL("fb"));
	RzILOpBool *eq = AND(INV(DUP(lt)), INV(FORDER(VARL("fb"), VARL("fa"))));
	return SEQ3(c28x_fp_operands(&c28x_fp_one, f, a, b), SETG("zf", eq), SETG("nf", lt));
}

/**
 * \brief MOV32 ACC/P/XT/XARn,RaH: only ACC as destination sets N and Z.
 */
static RzILOpEffect *c28x_fpu_to_cpu(const C28xOperand *dst, const C28xOperand *src) {
	const char *reg = c28x_reg32(dst);
	RzILOpPure *v = reg ? c28x_fpu_read(src) : NULL;
	if (!v) {
		return NULL;
	}
	RzILOpEffect *set = SETG(reg, v);
	if (dst->reg != C28X_REG_ACC) {
		return set;
	}
	return SEQ3(set, SETG("n", MSB(VARG("acc"))), SETG("z", IS_ZERO(VARG("acc"))));
}

/**
 * \brief The MOV32 forms: RaH,mem32{,CNDF}, RaH,RbH{,CNDF}, mem32,RaH and
 * the moves between CPU and FPU registers.
 *
 * Only UNCF, the default condition, sets NF/ZF from the float and NI/ZI from
 * the integer; negative zero and denormals count as +0 for NF and ZF. MOV32
 * RaH,RbL and RaL,RbH, which dis2000 decodes but SPRUHS1C doesn't document,
 * stay unlifted: MOV32's flags depend on the form.
 */
static RzILOpEffect *c28x_fpu_mov32(const C28xInsn *insn) {
	bool high;
	const C28xOperand *dst = &insn->ops[0];
	const C28xOperand *src = &insn->ops[1];
	if (insn->nops == 2 && c28x_fpu_name(src, &high)) {
		if (c28x_is_mem(dst)) {
			return c28x_with_mem32(dst, c28x_ea_store(c28x_fpu_read(src)));
		}
		return c28x_fpu_to_cpu(dst, src);
	}
	if (insn->nops == 2 && c28x_fpu_name(dst, &high)) {
		if (c28x_is_mem(src)) {
			return c28x_with_mem32(src, c28x_fpu_write(dst, c28x_ea_load(32)));
		}
		const char *reg = c28x_reg32(src);
		return reg ? c28x_fpu_write(dst, VARG(reg)) : NULL;
	}
	if (insn->nops == 2 && c28x_is_stf(src) && c28x_is_mem(dst)) {
		return c28x_with_mem32(dst, c28x_ea_store(c28x_stf_word()));
	}
	if (insn->nops == 2 && c28x_is_stf(dst) && c28x_is_mem(src)) {
		RzILOpEffect *load = SETL("sw", c28x_ea_load(32));
		return c28x_with_mem32(src, SEQ2(load, c28x_stf_load("sw")));
	}
	if (insn->nops != 3 || insn->ops[2].kind != C28X_OP_FCOND || !c28x_fpu_name(dst, &high)) {
		return NULL;
	}
	const ut32 cond = (ut32)insn->ops[2].imm;
	RzILOpBool *take = c28x_fcond(cond);
	if (!take) {
		return NULL;
	}
	RzILOpEffect *eff = c28x_fpu_write(dst, VARL("mv"));
	if (cond == 15) {
		eff = SEQ2(eff, c28x_fp_movflags(&c28x_bin32, "mv"));
	}
	eff = BRANCH(take, eff, NOP());
	if (c28x_is_mem(src)) {
		return c28x_with_mem32(src, SEQ2(SETL("mv", c28x_ea_load(32)), eff));
	}
	RzILOpPure *v = c28x_fpu_read(src);
	if (!v) {
		rz_il_op_effect_free(eff);
		return NULL;
	}
	return SEQ2(SETL("mv", v), eff);
}

/**
 * \brief A conversion between an FPU float and an integer: the float's format,
 * the integer's width and signedness, and whether it rounds to nearest (the
 * R forms) rather than truncating.
 */
typedef struct {
	const C28xFloat *fmt;
	ut8 ibits;
	bool sgn;
	bool round;
} C28xFpuConv;

static const C28xFpuConv c28x_fpu_convs[] = {
	[C28X_INS_I32TOF32] = { &c28x_bin32, 32, true, false },
	[C28X_INS_UI32TOF32] = { &c28x_bin32, 32, false, false },
	[C28X_INS_I16TOF32] = { &c28x_bin32, 16, true, false },
	[C28X_INS_UI16TOF32] = { &c28x_bin32, 16, false, false },
	[C28X_INS_I32TOF64] = { &c28x_bin64, 32, true, false },
	[C28X_INS_UI32TOF64] = { &c28x_bin64, 32, false, false },
	[C28X_INS_I64TOF64] = { &c28x_bin64, 64, true, false },
	[C28X_INS_UI64TOF64] = { &c28x_bin64, 64, false, false },
	[C28X_INS_F32TOI32] = { &c28x_bin32, 32, true, false },
	[C28X_INS_F32TOUI32] = { &c28x_bin32, 32, false, false },
	[C28X_INS_F32TOI16] = { &c28x_bin32, 16, true, false },
	[C28X_INS_F32TOI16R] = { &c28x_bin32, 16, true, true },
	[C28X_INS_F32TOUI16] = { &c28x_bin32, 16, false, false },
	[C28X_INS_F32TOUI16R] = { &c28x_bin32, 16, false, true },
	[C28X_INS_F64TOI32] = { &c28x_bin64, 32, true, false },
	[C28X_INS_F64TOUI32] = { &c28x_bin64, 32, false, false },
	[C28X_INS_F64TOI64] = { &c28x_bin64, 64, true, false },
	[C28X_INS_F64TOUI64] = { &c28x_bin64, 64, false, false },
};

static const C28xFpuConv *c28x_fpu_conv(const C28xInsn *insn) {
	if ((size_t)insn->id >= RZ_ARRAY_SIZE(c28x_fpu_convs) || !c28x_fpu_convs[insn->id].fmt) {
		return NULL;
	}
	return insn->nops == 2 ? &c28x_fpu_convs[insn->id] : NULL;
}

/**
 * \brief Latch the \p c->ibits integer in \p src as "xa": the low half of RbH
 * or all of it, all of Rb, or memory, whose row renders mem16 as dis2000 does.
 */
static RzILOpEffect *c28x_fpu_int_in(const C28xFpuConv *c, const C28xOperand *src,
	RzILOpEffect *body) {
	if (c28x_is_mem(src)) {
		RzILOpEffect *load = SETL("xa", c28x_ea_load(c->ibits == 16 ? 16 : 32));
		return c28x_with_mem(src, c->ibits != 16, SEQ2(load, body));
	}
	RzILOpPure *v = c->ibits == 64 ? c28x_fp_read(&c28x_bin64, src) : c28x_fpu_read(src);
	if (!v) {
		rz_il_op_effect_free(body);
		return NULL;
	}
	return SEQ2(SETL("xa", c->ibits == 16 ? UNSIGNED(16, v) : v), body);
}

/**
 * \brief The integer-to-float conversions, from a register or memory.
 *
 * SPRUHS1C documents RND32 and RND64 for multiplication, addition and
 * subtraction only; conversions round to nearest even.
 */
static RzILOpEffect *c28x_fpu_itof(const C28xInsn *insn) {
	const C28xFpuConv *c = c28x_fpu_conv(insn);
	if (!c) {
		return NULL;
	}
	RzILOpFloat *f;
	if (c->sgn) {
		f = SINT2F(c->fmt->format, RZ_FLOAT_RMODE_RNE, VARL("xa"));
	} else {
		f = INT2F(c->fmt->format, RZ_FLOAT_RMODE_RNE, VARL("xa"));
	}
	RzILOpEffect *wr = c28x_fp_write(c->fmt, &insn->ops[0], F2BV(f));
	return wr ? c28x_fpu_int_in(c, &insn->ops[1], wr) : NULL;
}

/**
 * \brief The float-to-integer conversions: the R forms round to nearest even,
 * the others truncate, as TI's compiler relies on when it casts with them.
 *
 * SPRUHS1C documents saturation for F32TOUI16(R) only; the others saturate the
 * same way here. The range's bounds are converted toward zero, since 2^31 - 1,
 * 2^32 - 1, 2^63 - 1 and 2^64 - 1 needn't be representable. 16-bit results
 * fill RaH by sign or zero extension.
 */
static RzILOpEffect *c28x_fpu_ftoi(const C28xInsn *insn) {
	const C28xFpuConv *c = c28x_fpu_conv(insn);
	RzILOpPure *src = c ? c28x_fp_read(c->fmt, &insn->ops[1]) : NULL;
	if (!src) {
		return NULL;
	}
	const ut32 bits = c->ibits;
	const ut64 umax = bits == 64 ? UT64_MAX : (1ULL << bits) - 1;
	const ut64 hi_bits = c->sgn ? umax >> 1 : umax;
	const ut64 lo_bits = c->sgn ? hi_bits + 1 : 0;
	RzILOpFloat *hi_f;
	RzILOpFloat *lo_f;
	RzILOpPure *in_range;
	if (c->sgn) {
		hi_f = SINT2F(c->fmt->format, RZ_FLOAT_RMODE_RTZ, UN(bits, hi_bits));
		lo_f = SINT2F(c->fmt->format, RZ_FLOAT_RMODE_RTZ, UN(bits, lo_bits));
		in_range = F2SINT(bits, RZ_FLOAT_RMODE_RTZ, VARL("fr"));
	} else {
		hi_f = INT2F(c->fmt->format, RZ_FLOAT_RMODE_RTZ, UN(bits, hi_bits));
		lo_f = INT2F(c->fmt->format, RZ_FLOAT_RMODE_RTZ, UN(bits, lo_bits));
		in_range = F2INT(bits, RZ_FLOAT_RMODE_RTZ, VARL("fr"));
	}
	RzILOpBool *over = FORDER(hi_f, VARL("fr"));
	RzILOpBool *under = FORDER(VARL("fr"), lo_f);
	RzILOpPure *v = ITE(over, UN(bits, hi_bits), ITE(under, UN(bits, lo_bits), in_range));
	RzILOpEffect *wr;
	if (bits == 64) {
		wr = c28x_fp_write(&c28x_bin64, &insn->ops[0], v);
	} else {
		if (bits == 16) {
			v = c->sgn ? SIGNED(32, v) : UNSIGNED(32, v);
		}
		wr = c28x_fpu_write(&insn->ops[0], v);
	}
	if (!wr) {
		rz_il_op_pure_free(src);
		return NULL;
	}
	RzFloatRMode mode = c->round ? RZ_FLOAT_RMODE_RNE : RZ_FLOAT_RMODE_RTZ;
	RzILOpEffect *in = SEQ2(SETL("xa", src), SETL("fa", c28x_fp_in(c->fmt, "xa")));
	return SEQ3(in, SETL("fr", FROUND(mode, VARL("fa"))), wr);
}

/**
 * \brief F32TOF64 Ra,RbH/mem32 and F32DTOF64 Ra,mem32 widen exactly and set
 * NF/ZF from the double; F32DTOF64 also copies mem32 two words up. F64TOF32
 * RaH,Rb rounds as RND32 says, flushes a denormal to +0 and sets no flags.
 */
static RzILOpEffect *c28x_fpu_ftof(const C28xInsn *insn) {
	if (insn->nops != 2) {
		return NULL;
	}
	const C28xOperand *dst = &insn->ops[0];
	const C28xOperand *src = &insn->ops[1];
	if (insn->id == C28X_INS_F64TOF32) {
		RzILOpPure *v = c28x_fp_read(&c28x_bin64, src);
		RzILOpEffect *wr = v ? c28x_fpu_write(dst, c28x_fp_flush(&c28x_bin32, "xr")) : NULL;
		if (!wr) {
			rz_il_op_pure_free(v);
			return NULL;
		}
		RzILOpBitVector *mode = c28x_fp_rnd(&c28x_bin32);
		RzILOpFloat *n = FCONVERT_DYN_RMODE(RZ_FLOAT_IEEE754_BIN_32, mode, VARL("fa"));
		RzILOpEffect *in = SEQ2(SETL("xa", v), SETL("fa", c28x_fp_in(&c28x_bin64, "xa")));
		return SEQ3(in, SETL("xr", F2BV(n)), wr);
	}
	RzILOpFloat *narrow = c28x_fp_in(&c28x_bin32, "xa");
	RzILOpFloat *w = FCONVERT(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE, narrow);
	RzILOpEffect *wr = c28x_fp_write(&c28x_bin64, dst, VARL("xr"));
	if (!wr) {
		rz_il_op_pure_free(w);
		return NULL;
	}
	RzILOpEffect *body = SEQ3(SETL("xr", F2BV(w)), wr, c28x_fp_nz(&c28x_bin64, "xr"));
	if (c28x_is_mem(src)) {
		if (insn->id == C28X_INS_F32DTOF64) {
			RzILOpPure *above = c28x_byte(ADD(VARL(C28X_EA_LOCAL), UN(32, 2)));
			body = SEQ2(STOREW(above, VARL("xa")), body);
		}
		return c28x_with_mem32(src, SEQ2(SETL("xa", c28x_ea_load(32)), body));
	}
	RzILOpPure *v = insn->id == C28X_INS_F32TOF64 ? c28x_fpu_read(src) : NULL;
	if (!v) {
		rz_il_op_effect_free(body);
		return NULL;
	}
	return SEQ2(SETL("xa", v), body);
}

/**
 * \brief FRACF32 and FRACF64: Rb less its integer part, which is exact; affect
 * no flags.
 */
static RzILOpEffect *c28x_fpu_fracf32(const C28xInsn *insn) {
	const C28xFloat *f = c28x_fp_of(insn->id);
	RzILOpPure *src = insn->nops == 2 ? c28x_fp_read(f, &insn->ops[1]) : NULL;
	if (!src) {
		return NULL;
	}
	RzILOpFloat *ip = FROUND(RZ_FLOAT_RMODE_RTZ, VARL("fa"));
	RzILOpPure *frac = F2BV(FSUB(RZ_FLOAT_RMODE_RNE, VARL("fa"), ip));
	RzILOpEffect *wr = c28x_fp_write(f, &insn->ops[0], c28x_fp_flush(f, "xr"));
	if (!wr) {
		rz_il_op_pure_free(src);
		rz_il_op_pure_free(frac);
		return NULL;
	}
	return SEQ4(SETL("xa", src), SETL("fa", c28x_fp_in(f, "xa")), SETL("xr", frac), wr);
}

/**
 * \brief MOVIZ Ra,#16FHiHex, MOVXI RaH/RaL,#16FLoHex, MOVIX RaL,#16I and ZERO Ra.
 *
 * SPRUHS1C describes MOVIZ and ZERO on RaH alone, but dis2000 names all of Ra
 * and TI's FPU64 compiler returns the double 0.0 as ZERO R0 and 2.5 as MOVIZ
 * R0,#0x4004 alone: both clear the rest of the 64-bit register.
 */
static RzILOpEffect *c28x_fpu_movi(const C28xInsn *insn) {
	const C28xOperand *dst = &insn->ops[0];
	if (insn->id == C28X_INS_ZERO) {
		const char *n = c28x_fpu_name64(dst);
		return n ? SETG(n, UN(64, 0)) : NULL;
	}
	if (insn->nops != 2 || insn->ops[1].kind != C28X_OP_IMM) {
		return NULL;
	}
	const ut64 imm = insn->ops[1].imm & 0xffff;
	if (insn->id == C28X_INS_MOVIZ) {
		const char *n = c28x_fpu_name64(dst);
		return n ? SETG(n, UN(64, imm << 48)) : NULL;
	}
	RzILOpPure *cur = c28x_fpu_read(dst);
	if (!cur) {
		return NULL;
	}
	RzILOpPure *v;
	if (insn->id == C28X_INS_MOVXI) {
		v = LOGOR(LOGAND(cur, UN(32, 0xffff0000)), UN(32, imm));
	} else {
		v = LOGOR(LOGAND(cur, UN(32, 0xffff)), UN(32, imm << 16));
	}
	return c28x_fpu_write(dst, v);
}

/**
 * \brief ZEROA: SPRUHS1C lists R0H-R7H, as its ZERO page lists only RaH,
 * which TI's compiler shows clears all of Ra; ZEROA clears all of each alike.
 */
static RzILOpEffect *c28x_fpu_zeroa(RZ_UNUSED const C28xInsn *insn) {
	RzILOpEffect *eff = SETG(c28x_fpu_regs[0], UN(64, 0));
	for (size_t i = 1; i < RZ_ARRAY_SIZE(c28x_fpu_regs); i++) {
		eff = SEQ2(eff, SETG(c28x_fpu_regs[i], UN(64, 0)));
	}
	return eff;
}

/**
 * \brief NEGF32/NEGF64 Ra,Rb{,CNDF} and ABSF32/ABSF64 Ra,Rb: only the sign bit
 * changes, and NF/ZF follow the stored value; NEGF sets them only for UNCF,
 * its default condition (SPRUHS1C's CNDF note).
 */
static RzILOpEffect *c28x_fpu_negabs(const C28xInsn *insn) {
	const C28xFloat *f = c28x_fp_of(insn->id);
	RzILOpPure *v = insn->nops >= 2 ? c28x_fp_read(f, &insn->ops[1]) : NULL;
	if (!v) {
		return NULL;
	}
	RzILOpPure *res;
	bool flags = true;
	if (insn->id == C28X_INS_ABSF32 || insn->id == C28X_INS_ABSF64) {
		res = LOGAND(VARL("xa"), UN(f->bits, c28x_fp_mask(f) >> 1));
	} else {
		const ut32 cond = insn->nops == 3 ? (ut32)insn->ops[2].imm : 0;
		RzILOpBool *take = insn->nops == 3 ? c28x_fcond(cond) : NULL;
		if (!take) {
			rz_il_op_pure_free(v);
			return NULL;
		}
		res = ITE(take, LOGXOR(VARL("xa"), UN(f->bits, 1ULL << (f->bits - 1))), VARL("xa"));
		flags = cond == 15;
	}
	RzILOpEffect *wr = c28x_fp_write(f, &insn->ops[0], VARL("xr"));
	if (!wr) {
		rz_il_op_pure_free(v);
		rz_il_op_pure_free(res);
		return NULL;
	}
	if (!flags) {
		return SEQ3(SETL("xa", v), SETL("xr", res), wr);
	}
	return SEQ4(SETL("xa", v), SETL("xr", res), wr, c28x_fp_nz(f, "xr"));
}

/**
 * \brief MAXF32/MAXF64 and MINF32/MINF64, on a register or #16FHi, and with the
 * parallel MOV32/MOV64 that moves only when Ra is replaced.
 *
 * They compare like CMPF32 and set ZF/NF on RaH against the other operand; a
 * NaN result becomes infinity and a denormal one +0.
 */
static RzILOpEffect *c28x_fpu_maxmin(const C28xInsn *insn) {
	const C28xFloat *f = c28x_fp_of(insn->id);
	const bool par = insn->nops == 5 && insn->ops[2].kind == C28X_OP_PAR;
	if (insn->nops != 2 && !par) {
		return NULL;
	}
	RzILOpPure *a = c28x_fp_read(f, &insn->ops[0]);
	RzILOpPure *b = c28x_fp_operand(f, &insn->ops[1]);
	RzILOpPure *d = par ? c28x_fp_read(f, &insn->ops[4]) : NULL;
	RzILOpEffect *mv = par ? c28x_fp_write(f, &insn->ops[3], VARL("pd")) : NULL;
	RzILOpEffect *wr = c28x_fp_write(f, &insn->ops[0], c28x_fp_flush(f, "xr"));
	if (!a || !b || !wr || (par && (!d || !mv))) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		rz_il_op_pure_free(d);
		rz_il_op_effect_free(mv);
		rz_il_op_effect_free(wr);
		return NULL;
	}
	RzILOpBool *lt = FORDER(VARL("fa"), VARL("fb"));
	RzILOpBool *gt = FORDER(VARL("fb"), VARL("fa"));
	const bool max = insn->id == C28X_INS_MAXF32 || insn->id == C28X_INS_MAXF64;
	RzILOpBool *take = max ? DUP(lt) : DUP(gt);
	RzILOpBool *below = FORDER(VARL("fa"), VARL("fb"));
	RzILOpEffect *flags = SEQ2(SETG("zf", AND(INV(lt), INV(gt))), SETG("nf", below));
	RzILOpEffect *set = SEQ2(SETL("xr", ITE(VARL("mt"), VARL("xb"), VARL("xa"))), wr);
	RzILOpEffect *in = c28x_fp_operands(&c28x_fp_one, f, a, b);
	RzILOpEffect *eff = SEQ4(in, SETL("mt", take), flags, set);
	if (par) {
		eff = SEQ3(SETL("pd", d), eff, BRANCH(VARL("mt"), mv, NOP()));
	}
	return eff;
}

// SETFLG FLAG,VALUE: the flags with a FLAG bit take their VALUE bit.
static RzILOpEffect *c28x_fpu_setflg_op(const C28xOperand *o) {
	RzILOpEffect *eff = NOP();
	for (size_t i = 0; i < RZ_ARRAY_SIZE(c28x_stf_bits); i++) {
		if (c28x_stf_bits[i] && (o->mask >> i) & 1) {
			RzILOpBool *v = (o->imm >> i) & 1 ? IL_TRUE : IL_FALSE;
			eff = SEQ2(eff, SETG(c28x_stf_bits[i], v));
		}
	}
	return eff;
}

static RzILOpEffect *c28x_fpu_setflg(const C28xInsn *insn) {
	if (insn->nops != 1 || insn->ops[0].kind != C28X_OP_FSETFLG) {
		return NULL;
	}
	return c28x_fpu_setflg_op(&insn->ops[0]);
}

/**
 * \brief SAVE FLAG,VALUE copies R0-R7 and STF to their shadows, then works as
 * SETFLG and sets SHDWS.
 *
 * SPRUHS1C names R0H-R7H, but TI's FPU64 compiler brackets code that
 * clobbers R0L and R1L with SAVE and RESTORE alone, so the shadows hold all
 * of each register.
 */
static RzILOpEffect *c28x_fpu_save(const C28xInsn *insn) {
	if (insn->nops != 1 || insn->ops[0].kind != C28X_OP_FSETFLG) {
		return NULL;
	}
	RzILOpEffect *eff = SETG("stfs", c28x_stf_word());
	for (size_t i = 0; i < RZ_ARRAY_SIZE(c28x_fpu_regs); i++) {
		eff = SEQ2(eff, SETG(c28x_fpu_shadows[i], VARG(c28x_fpu_regs[i])));
	}
	return SEQ3(eff, c28x_fpu_setflg_op(&insn->ops[0]), SETG("shdws", IL_TRUE));
}

// RESTORE: R0-R7 and STF from their shadows, SHDWS cleared.
static RzILOpEffect *c28x_fpu_restore(RZ_UNUSED const C28xInsn *insn) {
	RzILOpEffect *eff = SEQ2(SETL("sw", VARG("stfs")), c28x_stf_load("sw"));
	for (size_t i = 0; i < RZ_ARRAY_SIZE(c28x_fpu_regs); i++) {
		eff = SEQ2(eff, SETG(c28x_fpu_regs[i], VARG(c28x_fpu_shadows[i])));
	}
	return SEQ2(eff, SETG("shdws", IL_FALSE));
}

// The flags a MOVST0 FLAG bit selects: SPRUHS1C shows only the field's width.
enum {
	C28X_MOVST0_LVF = 1 << 0,
	C28X_MOVST0_LUF = 1 << 1,
	C28X_MOVST0_NF = 1 << 2,
	C28X_MOVST0_NI = 1 << 3,
	C28X_MOVST0_ZF = 1 << 4,
	C28X_MOVST0_ZI = 1 << 5,
	C28X_MOVST0_TF = 1 << 7,
};

// OR of the flags \p a and \p b among those \p f selects.
static RzILOpBool *c28x_movst0_any(ut32 f, ut32 sel_a, const char *a, ut32 sel_b, const char *b) {
	RzILOpBool *va = f & sel_a ? VARG(a) : IL_FALSE;
	return OR(va, f & sel_b ? VARG(b) : IL_FALSE);
}

/**
 * \brief MOVST0 FLAG copies selected STF flags into ST0 and clears a copied
 * LVF or LUF (SPRUHS1C table 1-2).
 *
 * FLAG orders its bits as TI's assembler encodes them: LVF, LUF, NF, NI, ZF,
 * ZI, CI and TF. SPRUHS1C documents no CI flag, so that bit changes nothing.
 */
static RzILOpEffect *c28x_fpu_movst0(const C28xInsn *insn) {
	if (insn->nops != 1 || insn->ops[0].kind != C28X_OP_FFLAGS) {
		return NULL;
	}
	const ut32 f = (ut32)insn->ops[0].imm;
	RzILOpEffect *eff = NOP();
	if (f & (C28X_MOVST0_LVF | C28X_MOVST0_LUF)) {
		RzILOpBool *v = c28x_movst0_any(f, C28X_MOVST0_LVF, "lvf", C28X_MOVST0_LUF, "luf");
		eff = SEQ2(eff, SETG("v", v));
		if (f & C28X_MOVST0_LVF) {
			eff = SEQ2(eff, SETG("lvf", IL_FALSE));
		}
		if (f & C28X_MOVST0_LUF) {
			eff = SEQ2(eff, SETG("luf", IL_FALSE));
		}
	}
	if (f & (C28X_MOVST0_NF | C28X_MOVST0_NI)) {
		RzILOpBool *n = c28x_movst0_any(f, C28X_MOVST0_NF, "nf", C28X_MOVST0_NI, "ni");
		eff = SEQ2(eff, SETG("n", n));
	}
	if (f & (C28X_MOVST0_ZF | C28X_MOVST0_ZI)) {
		RzILOpBool *z = c28x_movst0_any(f, C28X_MOVST0_ZF, "zf", C28X_MOVST0_ZI, "zi");
		eff = SEQ2(eff, SETG("z", z));
	}
	if (f & C28X_MOVST0_TF) {
		eff = SEQ3(eff, SETG("c", VARG("tf")), SETG("tc", VARG("tf")));
	}
	return eff;
}

// TESTTF CNDF: TF becomes the condition.
static RzILOpEffect *c28x_fpu_testtf(const C28xInsn *insn) {
	RzILOpBool *c = insn->nops == 1 ? c28x_fcond((ut32)insn->ops[0].imm) : NULL;
	return c ? SETG("tf", c) : NULL;
}

// SWAPF Ra,Rb{,CNDF}: dis2000 names whole registers, and the swap moves them whole.
static RzILOpEffect *c28x_fpu_swapf(const C28xInsn *insn) {
	const char *a = insn->nops == 3 ? c28x_fpu_name64(&insn->ops[0]) : NULL;
	const char *b = a ? c28x_fpu_name64(&insn->ops[1]) : NULL;
	RzILOpBool *c = b ? c28x_fcond((ut32)insn->ops[2].imm) : NULL;
	if (!c) {
		return NULL;
	}
	return BRANCH(c, SEQ3(SETL("sa", VARG(a)), SETG(a, VARG(b)), SETG(b, VARL("sa"))), NOP());
}

// MOV16 mem16,RaH stores RaH[15:0].
static RzILOpEffect *c28x_fpu_mov16(const C28xInsn *insn) {
	if (insn->nops != 2 || !c28x_is_mem(&insn->ops[0])) {
		return NULL;
	}
	RzILOpPure *v = c28x_fpu_read(&insn->ops[1]);
	return v ? c28x_with_mem(&insn->ops[0], false, c28x_ea_store(UNSIGNED(16, v))) : NULL;
}

/**
 * \brief MOVD32 and MOVDD32 RaH,mem32 load like MOV32 and copy the value two
 * (MOVD32) or four (MOVDD32) words up, for delay lines.
 *
 * The MOVDD32 RaL page repeats the RaH form's description and contradicts
 * its own flag table, so that form stays unlifted.
 */
static RzILOpEffect *c28x_fpu_movd32(const C28xInsn *insn) {
	bool high;
	const C28xOperand *dst = &insn->ops[0];
	const C28xOperand *src = &insn->ops[1];
	if (insn->nops != 2 || !c28x_fpu_name(dst, &high) || !high || !c28x_is_mem(src)) {
		return NULL;
	}
	const ut32 up = insn->id == C28X_INS_MOVD32 ? 2 : 4;
	RzILOpPure *above = c28x_byte(ADD(VARL(C28X_EA_LOCAL), UN(32, up)));
	RzILOpEffect *body = SEQ4(SETL("mv", c28x_ea_load(32)), c28x_fpu_write(dst, VARL("mv")),
		STOREW(above, VARL("mv")), c28x_fp_movflags(&c28x_bin32, "mv"));
	return c28x_with_mem32(src, body);
}

// PUSH RB and POP RB move RB as MOVL *SP++ and MOVL *--SP would.
static RzILOpEffect *c28x_fpu_rb(const C28xInsn *insn) {
	const C28xOperand *o = &insn->ops[0];
	if (insn->nops != 1 || o->kind != C28X_OP_REG || o->reg != C28X_REG_RB) {
		return NULL;
	}
	const bool push = insn->id == C28X_INS_PUSH;
	C28xOperand sp = { .kind = C28X_OP_MEM, .wide = true };
	sp.mode = push ? C28X_AM_SP_POSTINC : C28X_AM_SP_PREDEC;
	if (push) {
		return c28x_with_ea(&sp, c28x_ea_store(VARG("rb")));
	}
	return c28x_with_ea(&sp, SETG("rb", c28x_ea_load(32)));
}

/*
 * TMU (SPRUHS1C chapter 7): operands follow the FPU's rules, results are never
 * denormal, NaN or negative zero, and RND32 is ignored. SPRUHS1C calls the
 * TMU's rounding inherent in its implementation; results here are the exact
 * values rounded to nearest, which hardware may differ from in the last bit.
 */

static RzILOpFloat *c28x_f64_of(const char *local) {
	return FCONVERT(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE, VARL(local));
}

// The infinity of the sign \p neg, as bits.
static RzILOpPure *c28x_f32_inf(RzILOpBool *neg) {
	return ITE(neg, UN(32, 0xff800000), UN(32, 0x7f800000));
}

/**
 * \brief DIVF32 RaH,RbH,RcH with SPRUHS1C's boundary table: 0/0 is 0 with LVF,
 * x/Inf is 0 with LUF (Inf/Inf Inf with LUF), Inf/y and x/0 are Inf with LVF.
 *
 * Otherwise the TMU tests the exact quotient's exponent: at 2^128 and above
 * it gives Inf with LVF, below 2^-126 +0 with LUF. A binary64 quotient holds
 * that exponent.
 */
static RzILOpEffect *c28x_tmu_divf32(const C28xInsn *insn) {
	if (insn->nops != 3) {
		return NULL;
	}
	RzILOpPure *a = c28x_fpu_read(&insn->ops[1]);
	RzILOpPure *b = c28x_fpu_read(&insn->ops[2]);
	RzILOpEffect *wr = c28x_fpu_write(&insn->ops[0], VARL("dv"));
	if (!a || !b || !wr) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		rz_il_op_effect_free(wr);
		return NULL;
	}
	// za/ia: the dividend is zero/infinite, zb/ib: the divisor is;
	// na: the dividend is neither
	RzILOpEffect *cls = SEQ5(SETL("za", IS_FZERO(VARL("fa"))), SETL("zb", IS_FZERO(VARL("fb"))),
		SETL("ia", IS_FINF(VARL("fa"))), SETL("ib", IS_FINF(VARL("fb"))),
		SETL("na", AND(INV(VARL("za")), INV(VARL("ia")))));
	RzILOpBool *finite = AND(VARL("na"), AND(INV(VARL("zb")), INV(VARL("ib"))));
	RzILOpFloat *q = FDIV(RZ_FLOAT_RMODE_RNE, c28x_f64_of("fa"), c28x_f64_of("fb"));
	RzILOpBool *ov = AND(VARL("fin"), INV(FORDER(FABS(VARL("dq")), F64(0x1p128))));
	RzILOpBool *un = AND(VARL("fin"), FORDER(FABS(VARL("dq")), F64(0x1p-126)));
	RzILOpEffect *quot = SEQ2(SETL("fin", finite), SETL("dq", q));
	RzILOpEffect *range = SEQ3(quot, SETL("dov", ov), SETL("dun", un));
	RzILOpBool *neg = XOR(IS_FNEG(VARL("fa")), IS_FNEG(VARL("fb")));
	RzILOpPure *q32 = F2BV(FDIV(RZ_FLOAT_RMODE_RNE, VARL("fa"), VARL("fb")));
	RzILOpPure *normal = ITE(VARL("dun"), UN(32, 0), ITE(VARL("dov"), c28x_f32_inf(neg), q32));
	RzILOpPure *by_inf = ITE(VARL("ib"), UN(32, 0), normal);
	RzILOpPure *big = ITE(OR(VARL("ia"), VARL("zb")), c28x_f32_inf(DUP(neg)), by_inf);
	RzILOpPure *val = ITE(VARL("za"), UN(32, 0), big);
	RzILOpBool *lvf = OR(OR(AND(VARL("za"), VARL("zb")), AND(VARL("ia"), INV(VARL("ib")))),
		OR(AND(VARL("na"), VARL("zb")), VARL("dov")));
	RzILOpBool *luf = OR(VARL("ib"), VARL("dun"));
	RzILOpEffect *set_lvf = SETG("lvf", OR(VARG("lvf"), lvf));
	RzILOpEffect *set_luf = SETG("luf", OR(VARG("luf"), luf));
	RzILOpEffect *in = c28x_fp_operands(&c28x_fp_one, &c28x_bin32, a, b);
	return SEQ7(in, cls, range, SETL("dv", val), wr, set_lvf, set_luf);
}

/**
 * \brief SQRTF32 RaH,RbH: a negative operand gives +0 and +Inf gives +Inf,
 * both with LVF (SPRUHS1C).
 */
static RzILOpEffect *c28x_tmu_sqrtf32(const C28xInsn *insn) {
	RzILOpPure *a = insn->nops == 2 ? c28x_fpu_read(&insn->ops[1]) : NULL;
	RzILOpEffect *wr = a ? c28x_fpu_write(&insn->ops[0], VARL("dv")) : NULL;
	if (!wr) {
		rz_il_op_pure_free(a);
		return NULL;
	}
	RzILOpPure *root = F2BV(FSQRT(RZ_FLOAT_RMODE_RNE, VARL("fa")));
	RzILOpPure *val = ITE(VARL("dneg"), UN(32, 0), ITE(VARL("dinf"), UN(32, 0x7f800000), root));
	RzILOpEffect *cls = SEQ2(SETL("dneg", IS_FNEG(VARL("fa"))),
		SETL("dinf", AND(IS_FINF(VARL("fa")), INV(VARL("dneg")))));
	RzILOpBool *lvf = OR(VARG("lvf"), OR(VARL("dneg"), VARL("dinf")));
	RzILOpEffect *in = SEQ2(SETL("xa", a), SETL("fa", c28x_fp_in(&c28x_bin32, "xa")));
	return SEQ5(in, cls, SETL("dv", val), wr, SETG("lvf", lvf));
}

/**
 * \brief MPY2PIF32 and DIV2PIF32: RbH times 2pi or 1/2pi. MPY2PIF32 can only
 * overflow, to Inf with LVF, and DIV2PIF32 only underflow, to +0 with LUF.
 *
 * SPRUHS1C gives the constants' precision no more than the rounding; the
 * product here takes them in binary64 and rounds to nearest.
 */
static RzILOpEffect *c28x_tmu_2pi(const C28xInsn *insn) {
	RzILOpPure *a = insn->nops == 2 ? c28x_fpu_read(&insn->ops[1]) : NULL;
	RzILOpEffect *wr = a ? c28x_fpu_write(&insn->ops[0], VARL("dv")) : NULL;
	if (!wr) {
		rz_il_op_pure_free(a);
		return NULL;
	}
	const bool mpy = insn->id == C28X_INS_MPY2PIF32;
	RzILOpFloat *k = F64(mpy ? 0x1.921fb54442d18p+2 : 0x1.45f306dc9c883p-3);
	RzILOpFloat *p = FMUL(RZ_FLOAT_RMODE_RNE, c28x_f64_of("fa"), k);
	RzILOpPure *p32 = F2BV(FCONVERT(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE, VARL("dp")));
	RzILOpBool *out;
	RzILOpPure *val;
	const char *flag;
	if (mpy) {
		// past the largest finite value plus half an ulp, rounding to nearest overflows
		out = INV(FORDER(FABS(VARL("dp")), F64(0x1p128 - 0x1p103)));
		val = ITE(VARL("dx"), c28x_f32_inf(IS_FNEG(VARL("dp"))), p32);
		flag = "lvf";
	} else {
		out = AND(INV(IS_FZERO(VARL("dp"))), FORDER(FABS(VARL("dp")), F64(0x1p-126)));
		val = ITE(VARL("dx"), UN(32, 0), p32);
		flag = "luf";
	}
	RzILOpEffect *in = SEQ2(SETL("xa", a), SETL("fa", c28x_fp_in(&c28x_bin32, "xa")));
	RzILOpEffect *latch = SETG(flag, OR(VARG(flag), VARL("dx")));
	return SEQ6(in, SETL("dp", p), SETL("dx", out), SETL("dv", val), wr, latch);
}

/**
 * \brief MOV64 Ra,Rb{,CNDF}: only UNCF, the default condition, sets NF/ZF from
 * the double and NI/ZI from all 64 bits.
 */
static RzILOpEffect *c28x_fpu_mov64(const C28xInsn *insn) {
	const char *a = insn->nops == 3 ? c28x_fpu_name64(&insn->ops[0]) : NULL;
	const char *b = a ? c28x_fpu_name64(&insn->ops[1]) : NULL;
	const ut32 cond = b ? (ut32)insn->ops[2].imm : 0;
	RzILOpBool *take = b ? c28x_fcond(cond) : NULL;
	if (!take) {
		return NULL;
	}
	RzILOpEffect *eff = SETG(a, VARL("mv"));
	if (cond == 15) {
		eff = SEQ2(eff, c28x_fp_movflags(&c28x_bin64, "mv"));
	}
	return SEQ2(SETL("mv", VARG(b)), BRANCH(take, eff, NOP()));
}

/*
 * Fast integer division (SPRUHS1C chapter 6): ABSI*DIV* keeps the operands'
 * signs in NI and TF and makes them unsigned, SUBC4UI32 and SUBC2UI64 run a
 * restoring division, and NEGI*, ENEGI* and MNEGI* sign the quotient and
 * remainder for truncated, euclidean and floored division. The numerator and
 * quotient live in R1H or R1H:R0H, the remainder in R2H or R2H:R4H and the
 * denominator in R3H or R3H:R5H, the first register holding the high half.
 */

typedef enum {
	C28X_FD_ABS,
	C28X_FD_SUBC,
	C28X_FD_NEG,
	C28X_FD_ENEG,
	C28X_FD_MNEG,
} C28xFintdivStep;

/**
 * \brief A FINTDIV instruction: its step, the numerator's and denominator's
 * widths (the quotient's and remainder's), and for ABSI whether the
 * denominator is signed.
 */
typedef struct {
	C28xFintdivStep step;
	ut8 num;
	ut8 den;
	bool sgn;
} C28xFintdiv;

static const C28xFintdiv c28x_fintdivs[] = {
	[C28X_INS_ABSI32DIV32] = { C28X_FD_ABS, 32, 32, true },
	[C28X_INS_ABSI32DIV32U] = { C28X_FD_ABS, 32, 32, false },
	[C28X_INS_ABSI64DIV32] = { C28X_FD_ABS, 64, 32, true },
	[C28X_INS_ABSI64DIV32U] = { C28X_FD_ABS, 64, 32, false },
	[C28X_INS_ABSI64DIV64] = { C28X_FD_ABS, 64, 64, true },
	[C28X_INS_ABSI64DIV64U] = { C28X_FD_ABS, 64, 64, false },
	[C28X_INS_SUBC4UI32] = { C28X_FD_SUBC, 32, 32, false },
	[C28X_INS_SUBC2UI64] = { C28X_FD_SUBC, 64, 64, false },
	[C28X_INS_NEGI32DIV32] = { C28X_FD_NEG, 32, 32, false },
	[C28X_INS_NEGI64DIV32] = { C28X_FD_NEG, 64, 32, false },
	[C28X_INS_NEGI64DIV64] = { C28X_FD_NEG, 64, 64, false },
	[C28X_INS_ENEGI32DIV32] = { C28X_FD_ENEG, 32, 32, false },
	[C28X_INS_ENEGI64DIV32] = { C28X_FD_ENEG, 64, 32, false },
	[C28X_INS_ENEGI64DIV64] = { C28X_FD_ENEG, 64, 64, false },
	[C28X_INS_MNEGI32DIV32] = { C28X_FD_MNEG, 32, 32, false },
	[C28X_INS_MNEGI64DIV32] = { C28X_FD_MNEG, 64, 32, false },
	[C28X_INS_MNEGI64DIV64] = { C28X_FD_MNEG, 64, 64, false },
};

// RhiH, or the pair RhiH:RloH when \p bits is 64.
static RzILOpPure *c28x_fd_read(ut32 bits, ut32 hi, ut32 lo) {
	const C28xOperand h = { .kind = C28X_OP_REG, .reg = C28X_REG_R0H + hi };
	const C28xOperand l = { .kind = C28X_OP_REG, .reg = C28X_REG_R0H + lo };
	RzILOpPure *vh = c28x_fpu_read(&h);
	return bits == 32 ? vh : APPEND(vh, c28x_fpu_read(&l));
}

static RzILOpEffect *c28x_fd_write(ut32 bits, ut32 hi, ut32 lo, const char *local) {
	const C28xOperand h = { .kind = C28X_OP_REG, .reg = C28X_REG_R0H + hi };
	const C28xOperand l = { .kind = C28X_OP_REG, .reg = C28X_REG_R0H + lo };
	if (bits == 32) {
		return c28x_fpu_write(&h, VARL(local));
	}
	RzILOpEffect *high = c28x_fpu_write(&h, UNSIGNED(32, SHIFTR0(VARL(local), UN(8, 32))));
	return SEQ2(high, c28x_fpu_write(&l, UNSIGNED(32, VARL(local))));
}

static RzILOpPure *c28x_fd_neg_if(RzILOpBool *c, const char *local) {
	return ITE(c, NEG(VARL(local)), VARL(local));
}

/**
 * \brief One restoring-division step of SUBC4UI32/SUBC2UI64 on "dr" (the
 * remainder, \p w bits) and "dn" (the numerator becoming the quotient).
 *
 * The page's temp is (w + 1) bits wide and the step subtracts when it's
 * non-negative as a signed value.
 */
static RzILOpEffect *c28x_fd_subc_step(ut32 w, ut32 nw) {
	RzILOpPure *next = ITE(MSB(VARL("dn")), UN(w + 1, 1), UN(w + 1, 0));
	RzILOpPure *twice = SHIFTL0(UNSIGNED(w + 1, VARL("dr")), UN(8, 1));
	RzILOpPure *temp = SUB(ADD(twice, next), UNSIGNED(w + 1, VARL("dd")));
	RzILOpPure *bit = ITE(MSB(VARL("dn")), UN(w, 1), UN(w, 0));
	RzILOpPure *shifted = LOGOR(SHIFTL0(VARL("dr"), UN(8, 1)), bit);
	RzILOpPure *rem = ITE(MSB(VARL("dt")), shifted, UNSIGNED(w, VARL("dt")));
	RzILOpPure *num_shift = SHIFTL0(VARL("dn"), UN(8, 1));
	RzILOpPure *num = ITE(MSB(VARL("dt")), num_shift, LOGOR(DUP(num_shift), UN(nw, 1)));
	return SEQ4(SETL("dt", temp), SETL("dq", rem), SETL("dn", num), SETL("dr", VARL("dq")));
}

/** \brief The FINTDIV instructions, each as its SPRUHS1C page defines it. */
static RzILOpEffect *c28x_fpu_fintdiv(const C28xInsn *insn) {
	if ((size_t)insn->id >= RZ_ARRAY_SIZE(c28x_fintdivs) || !c28x_fintdivs[insn->id].num) {
		return NULL;
	}
	const C28xFintdiv *d = &c28x_fintdivs[insn->id];
	const ut32 nb = d->num;
	const ut32 db = d->den;
	RzILOpEffect *num_in = SETL("dn", c28x_fd_read(nb, 1, 0));
	RzILOpEffect *den_in = SETL("dd", c28x_fd_read(db, 3, 5));
	RzILOpEffect *in = SEQ3(num_in, den_in, SETL("dr", c28x_fd_read(db, 2, 4)));
	RzILOpEffect *num_out = c28x_fd_write(nb, 1, 0, "dn");
	RzILOpEffect *rem_out = c28x_fd_write(db, 2, 4, "dr");
	RzILOpEffect *body;
	switch (d->step) {
	case C28X_FD_ABS: {
		RzILOpBool *tf = MSB(VARL("dn"));
		RzILOpBool *min = EQ(VARL("dn"), UN(nb, 1ULL << (nb - 1)));
		if (d->sgn) {
			tf = XOR(tf, MSB(VARL("dd")));
			min = OR(min, EQ(VARL("dd"), UN(db, 1ULL << (db - 1))));
		}
		RzILOpEffect *lvf = SETG("lvf", OR(VARG("lvf"), min));
		RzILOpEffect *flags = SEQ3(SETG("ni", MSB(VARL("dn"))), SETG("tf", tf), lvf);
		RzILOpEffect *num = SETL("dn", c28x_fd_neg_if(MSB(VARL("dn")), "dn"));
		body = SEQ3(flags, SETL("dr", UN(db, 0)), num);
		if (d->sgn) {
			RzILOpEffect *den = SETL("dd", c28x_fd_neg_if(MSB(VARL("dd")), "dd"));
			body = SEQ3(body, den, c28x_fd_write(db, 3, 5, "dd"));
		}
		break;
	}
	case C28X_FD_SUBC: {
		RzILOpEffect *lvf = SETG("lvf", OR(VARG("lvf"), IS_ZERO(VARL("dd"))));
		body = SEQ2(SETG("zi", IL_FALSE), lvf);
		const ut32 steps = db == 32 ? 4 : 2;
		for (ut32 i = 0; i < steps; i++) {
			body = SEQ2(body, c28x_fd_subc_step(db, nb));
		}
		body = SEQ2(body, SETG("zi", IS_ZERO(VARL("dr"))));
		break;
	}
	case C28X_FD_NEG: {
		RzILOpEffect *q = SETL("dn", c28x_fd_neg_if(VARG("tf"), "dn"));
		body = SEQ2(q, SETL("dr", c28x_fd_neg_if(VARG("ni"), "dr")));
		break;
	}
	case C28X_FD_ENEG:
	case C28X_FD_MNEG: {
		// with a nonzero remainder, the quotient moves one away from zero
		RzILOpBool *when = d->step == C28X_FD_ENEG ? VARG("ni") : VARG("tf");
		RzILOpPure *q1 = ITE(VARL("da"), ADD(VARL("dn"), UN(nb, 1)), VARL("dn"));
		RzILOpPure *r1 = ITE(VARL("da"), SUB(VARL("dd"), VARL("dr")), VARL("dr"));
		RzILOpEffect *adj = SETL("da", AND(when, INV(VARG("zi"))));
		RzILOpEffect *fix = SEQ3(adj, SETL("dn", q1), SETL("dr", r1));
		body = SEQ2(fix, SETL("dn", c28x_fd_neg_if(VARG("tf"), "dn")));
		if (d->step == C28X_FD_MNEG) {
			RzILOpBool *flip = XOR(VARG("ni"), VARG("tf"));
			body = SEQ2(body, SETL("dr", c28x_fd_neg_if(flip, "dr")));
		}
		break;
	}
	default:
		rz_il_op_effect_free(in);
		rz_il_op_effect_free(num_out);
		rz_il_op_effect_free(rem_out);
		return NULL;
	}
	return SEQ4(in, body, num_out, rem_out);
}

// PREDIVF64, SUBC3F64 and POSTDIVF64, TI's compiler's double division steps,
// appear nowhere in SPRUHS1C: what each step leaves in R1-R3 is unknown, so
// they stay unlifted.
static const C28xFpuLifter c28x_fpu_lifters[] = {
	[C28X_INS_ADDF32] = c28x_fpu_arith,
	[C28X_INS_SUBF32] = c28x_fpu_arith,
	[C28X_INS_MPYF32] = c28x_fpu_arith,
	[C28X_INS_CMPF32] = c28x_fpu_cmpf32,
	[C28X_INS_MOV32] = c28x_fpu_mov32,
	[C28X_INS_I32TOF32] = c28x_fpu_itof,
	[C28X_INS_UI32TOF32] = c28x_fpu_itof,
	[C28X_INS_I16TOF32] = c28x_fpu_itof,
	[C28X_INS_UI16TOF32] = c28x_fpu_itof,
	[C28X_INS_F32TOI32] = c28x_fpu_ftoi,
	[C28X_INS_F32TOUI32] = c28x_fpu_ftoi,
	[C28X_INS_F32TOI16] = c28x_fpu_ftoi,
	[C28X_INS_F32TOI16R] = c28x_fpu_ftoi,
	[C28X_INS_F32TOUI16] = c28x_fpu_ftoi,
	[C28X_INS_F32TOUI16R] = c28x_fpu_ftoi,
	[C28X_INS_FRACF32] = c28x_fpu_fracf32,
	[C28X_INS_MOVIZ] = c28x_fpu_movi,
	[C28X_INS_MOVXI] = c28x_fpu_movi,
	[C28X_INS_MOVIX] = c28x_fpu_movi,
	[C28X_INS_ZERO] = c28x_fpu_movi,
	[C28X_INS_ZEROA] = c28x_fpu_zeroa,
	[C28X_INS_NEGF32] = c28x_fpu_negabs,
	[C28X_INS_ABSF32] = c28x_fpu_negabs,
	[C28X_INS_MAXF32] = c28x_fpu_maxmin,
	[C28X_INS_MINF32] = c28x_fpu_maxmin,
	[C28X_INS_MACF32] = c28x_fpu_macf32,
	[C28X_INS_DIVF32] = c28x_tmu_divf32,
	[C28X_INS_ADDF64] = c28x_fpu_arith,
	[C28X_INS_SUBF64] = c28x_fpu_arith,
	[C28X_INS_MPYF64] = c28x_fpu_arith,
	[C28X_INS_MACF64] = c28x_fpu_macf32,
	[C28X_INS_CMPF64] = c28x_fpu_cmpf32,
	[C28X_INS_MAXF64] = c28x_fpu_maxmin,
	[C28X_INS_MINF64] = c28x_fpu_maxmin,
	[C28X_INS_NEGF64] = c28x_fpu_negabs,
	[C28X_INS_ABSF64] = c28x_fpu_negabs,
	[C28X_INS_FRACF64] = c28x_fpu_fracf32,
	[C28X_INS_MOV64] = c28x_fpu_mov64,
	[C28X_INS_I32TOF64] = c28x_fpu_itof,
	[C28X_INS_UI32TOF64] = c28x_fpu_itof,
	[C28X_INS_I64TOF64] = c28x_fpu_itof,
	[C28X_INS_UI64TOF64] = c28x_fpu_itof,
	[C28X_INS_F64TOI32] = c28x_fpu_ftoi,
	[C28X_INS_F64TOUI32] = c28x_fpu_ftoi,
	[C28X_INS_F64TOI64] = c28x_fpu_ftoi,
	[C28X_INS_F64TOUI64] = c28x_fpu_ftoi,
	[C28X_INS_F32TOF64] = c28x_fpu_ftof,
	[C28X_INS_F32DTOF64] = c28x_fpu_ftof,
	[C28X_INS_F64TOF32] = c28x_fpu_ftof,
	[C28X_INS_ABSI32DIV32] = c28x_fpu_fintdiv,
	[C28X_INS_ABSI32DIV32U] = c28x_fpu_fintdiv,
	[C28X_INS_ABSI64DIV32] = c28x_fpu_fintdiv,
	[C28X_INS_ABSI64DIV32U] = c28x_fpu_fintdiv,
	[C28X_INS_ABSI64DIV64] = c28x_fpu_fintdiv,
	[C28X_INS_ABSI64DIV64U] = c28x_fpu_fintdiv,
	[C28X_INS_SUBC4UI32] = c28x_fpu_fintdiv,
	[C28X_INS_SUBC2UI64] = c28x_fpu_fintdiv,
	[C28X_INS_NEGI32DIV32] = c28x_fpu_fintdiv,
	[C28X_INS_NEGI64DIV32] = c28x_fpu_fintdiv,
	[C28X_INS_NEGI64DIV64] = c28x_fpu_fintdiv,
	[C28X_INS_ENEGI32DIV32] = c28x_fpu_fintdiv,
	[C28X_INS_ENEGI64DIV32] = c28x_fpu_fintdiv,
	[C28X_INS_ENEGI64DIV64] = c28x_fpu_fintdiv,
	[C28X_INS_MNEGI32DIV32] = c28x_fpu_fintdiv,
	[C28X_INS_MNEGI64DIV32] = c28x_fpu_fintdiv,
	[C28X_INS_MNEGI64DIV64] = c28x_fpu_fintdiv,
	[C28X_INS_SQRTF32] = c28x_tmu_sqrtf32,
	[C28X_INS_MPY2PIF32] = c28x_tmu_2pi,
	[C28X_INS_DIV2PIF32] = c28x_tmu_2pi,
	[C28X_INS_SETFLG] = c28x_fpu_setflg,
	[C28X_INS_SAVE] = c28x_fpu_save,
	[C28X_INS_RESTORE] = c28x_fpu_restore,
	[C28X_INS_MOVST0] = c28x_fpu_movst0,
	[C28X_INS_TESTTF] = c28x_fpu_testtf,
	[C28X_INS_SWAPF] = c28x_fpu_swapf,
	[C28X_INS_MOV16] = c28x_fpu_mov16,
	[C28X_INS_MOVD32] = c28x_fpu_movd32,
	[C28X_INS_MOVDD32] = c28x_fpu_movd32,
	[C28X_INS_PUSH] = c28x_fpu_rb,
	[C28X_INS_POP] = c28x_fpu_rb,
};

/** \brief Lift the FPU instruction \p insn; NULL while it has no IL yet. */
RZ_IPI RzILOpEffect *c28x_lift_fpu(const C28xInsn *insn, RZ_UNUSED ut64 pc) {
	if ((size_t)insn->id >= RZ_ARRAY_SIZE(c28x_fpu_lifters) || !c28x_fpu_lifters[insn->id]) {
		return NULL;
	}
	return c28x_fpu_lifters[insn->id](insn);
}
