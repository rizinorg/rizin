// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file c6x_il.c
 * TMS320C6000 RzIL lifting.
 *
 * Lifts a decoded \ref C6xInsn (from c6x_decode.c) to RzIL: the register / IL-VM
 * configuration and the per-instruction lifter wired into the analysis op via
 * op->il_op. Kept separate from the disassembler so decode and IL are
 * independent. The scalar move / ALU / shift / multiply / load / store core is
 * lifted; forms not yet handled return NULL and simply leave op->il_op unset.
 *
 * An instruction is lifted as if it ran alone and wrote its results at once.
 * When they land, and what the rest of its execute packet and the packets
 * after it see meanwhile, is c6x_il_window.c's business.
 */

#include <rz_util.h>
#include "c6x.h"

/* RzIL VM */

// IL-VM register bindings: the general-purpose registers, then the control
// registers MVC reaches -- the set common to every C6000, the C64x+ extension
// and the floating-point configuration registers, each where the variant has
// them, since binding a register the profile does not declare fails the VM
// setup. PCE1 is left to the VM's own program counter: bound as a variable it
// would be written back over the profile's PC after every run of steps.
//
// The 32+32 table doubles as the name lookup for a general-register operand:
// side A occupies indices 0-31 and side B 32-63, so c6x_reg_name(side, num)
// indexes it directly and never reaches the control registers past it.
// clang-format off
#define C6X_IL_A_LO "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", \
	"a8", "a9", "a10", "a11", "a12", "a13", "a14", "a15"
#define C6X_IL_A_HI "a16", "a17", "a18", "a19", "a20", "a21", "a22", "a23", \
	"a24", "a25", "a26", "a27", "a28", "a29", "a30", "a31"
#define C6X_IL_B_LO "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", \
	"b8", "b9", "b10", "b11", "b12", "b13", "b14", "b15"
#define C6X_IL_B_HI "b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23", \
	"b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31"
#define C6X_IL_CTRL "amr", "csr", "gfpgfr", "icr", "ier", "ifr", "irp", "isr", "istp", "nrp"
#define C6X_IL_CTRL_C64XP "dier", "dnum", "ecr", "efr", "gplya", "gplyb", "ierr", "ilc", "itsr", \
	"ntsr", "rep", "rilc", "ssr", "tsch", "tscl", "tsr"
#define C6X_IL_CTRL_FP "fadcr", "faucr", "fmcr"

static const char *const c6x_il_regs[] = {
	C6X_IL_A_LO, C6X_IL_A_HI, C6X_IL_B_LO, C6X_IL_B_HI, C6X_IL_CTRL, C6X_IL_CTRL_C64XP, NULL
};

static const char *const c6x_il_regs_fp[] = {
	C6X_IL_A_LO, C6X_IL_A_HI, C6X_IL_B_LO, C6X_IL_B_HI, C6X_IL_CTRL, C6X_IL_CTRL_C64XP, C6X_IL_CTRL_FP, NULL
};

// C62x/C67x have 16 registers per side and no C64x+ extension
static const char *const c6x_il_regs16[] = {
	C6X_IL_A_LO, C6X_IL_B_LO, C6X_IL_CTRL, NULL
};

static const char *const c6x_il_regs16_fp[] = {
	C6X_IL_A_LO, C6X_IL_B_LO, C6X_IL_CTRL, C6X_IL_CTRL_FP, NULL
};
// clang-format on

// Predicate registers by creg code; 0 and 7 are reserved.
static const char *const c6x_pred_regs[8] = { NULL, "b0", "b1", "b2", "a1", "a2", "a0", NULL };

/** RzIL configuration (register bindings, PC/memory widths) for the C6000 VM. */
RZ_IPI RzAnalysisILConfig *tms320_c6x_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	// 32-bit PC over a byte-addressed space, little-endian.
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(32, false, 32);
	if (!cfg) {
		return NULL;
	}
	const C6xArchDesc *desc = c6x_desc_from_cpu(rz_analysis_get_cpu(analysis));
	bool fp = desc && (desc->features & C6X_FEAT_FP);
	if (desc && desc->num_regs <= 16) {
		cfg->reg_bindings = (const char **)(fp ? c6x_il_regs16_fp : c6x_il_regs16);
	} else {
		cfg->reg_bindings = (const char **)(fp ? c6x_il_regs_fp : c6x_il_regs);
	}
	return cfg;
}

#include <rz_il/rz_il_opbuilder_begin.h>

// Global-variable name of register `num` on side `side` (0 = A, 1 = B).
static const char *c6x_reg_name(ut8 side, ut8 num) {
	return c6x_il_regs[(side & 1) * 32 + (num & 31)];
}

/** The IL variable of general-purpose register \p num on side \p side (0 = A, 1 = B). */
RZ_IPI const char *c6x_il_reg(ut8 side, ut8 num) {
	return c6x_reg_name(side, num);
}

// Predicate register named by the creg field (SPRU733 Table 3-9), or NULL when
// unconditional. Mirrors the disassembler's pred_reg().
static const char *c6x_pred_name(ut8 creg) {
	return c6x_pred_regs[creg & 7];
}

/**
 * Every architectural register read and write goes through one of these, so
 * that the register traffic of a lifted instruction is in one place rather than
 * spread over the opcode handlers.
 */
static RzILOpPure *c6x_reg_read(const char *name) {
	return VARG(name);
}

static RzILOpEffect *c6x_reg_write(const char *name, RzILOpPure *v) {
	return SETG(name, v);
}

// 32-bit value of a register or immediate source operand, or NULL for kinds
// this core does not model as a scalar (pairs, quads, control regs, memory).
// NULL is not an error: it leaves a form this core does not lift unlifted.
static RzILOpPure *c6x_src(const C6xOperand *o) {
	switch (o->kind) {
	case C6X_OP_REG:
		return c6x_reg_read(c6x_reg_name(o->v.reg.side, o->v.reg.num));
	case C6X_OP_IMM:
		return S32(o->v.imm.value);
	default:
		return NULL;
	}
}

// Write `v` to a register destination, or free it and fail for other kinds.
static RzILOpEffect *c6x_wr(const C6xOperand *o, RzILOpPure *v) {
	if (o->kind == C6X_OP_REG) {
		return c6x_reg_write(c6x_reg_name(o->v.reg.side, o->v.reg.num), v);
	}
	rz_il_op_pure_free(v);
	return NULL;
}

static RzILOpBitVector *c6x_pair64(const C6xOperand *o);
static RzILOpBitVector *c6x_long40(const C6xOperand *o);
static RzILOpEffect *c6x_wr_pair64(const C6xOperand *o, RzILOpBitVector *v);

/** The 40 bits a long keeps (SPRUFE8B 2.1). */
#define C6X_LONG_MASK 0xffffffffffULL

// Whether \p insn has a register-pair operand, which in the integer forms
// means a 40-bit long source or result.
static bool c6x_has_pair(const C6xInsn *insn) {
	for (ut8 i = 0; i < insn->nops; i++) {
		if (OP(i).kind == C6X_OP_REGPAIR) {
			return true;
		}
	}
	return false;
}

// A source of 40-bit long arithmetic, widened to 64 bits: a pair is read as a
// long, which ignores the 24 MSBs of its odd register, and a 32-bit source is
// widened by the signedness of the form.
static RzILOpBitVector *c6x_long_src(const C6xOperand *o, bool sgn) {
	if (o->kind == C6X_OP_REGPAIR) {
		return sgn ? c6x_long40(o) : LOGAND(c6x_pair64(o), U64(C6X_LONG_MASK));
	}
	RzILOpPure *s = c6x_src(o);
	if (!s) {
		return NULL;
	}
	return sgn ? SIGNED(64, s) : UNSIGNED(64, s);
}

// Write the low 40 bits of \p v as a long; the 24 MSBs of the odd register are
// zero-filled.
static RzILOpEffect *c6x_wr_long40(const C6xOperand *o, RzILOpBitVector *v) {
	return c6x_wr_pair64(o, LOGAND(v, U64(C6X_LONG_MASK)));
}

// dst = src1 OP src2, the shared shape of the register/immediate ALU ops. `mk`
// builds the value from the two decoded sources. ADD and SUB also have long
// forms, signed but for ADDU and SUBU.
static RzILOpEffect *c6x_alu3(const C6xInsn *insn, rz_il_pure_2args_op *mk) {
	bool lng = c6x_has_pair(insn);
	bool sgn = insn->id != C6X_INS_ADDU && insn->id != C6X_INS_SUBU;
	RzILOpPure *s1 = lng ? c6x_long_src(&OP(0), sgn) : c6x_src(&OP(0));
	RzILOpPure *s2 = lng ? c6x_long_src(&OP(1), sgn) : c6x_src(&OP(1));
	if (!s1 || !s2) {
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	return lng ? c6x_wr_long40(&OP(2), mk(s1, s2)) : c6x_wr(&OP(2), mk(s1, s2));
}

// dst = (src1 CMP src2) ? 1 : 0, the shared shape of the compare ops. A long
// src2 is compared at 40 bits, unsigned for CMPGTU and CMPLTU.
static RzILOpEffect *c6x_cmp(const C6xInsn *insn, rz_il_bool_2args_op *mk) {
	bool lng = c6x_has_pair(insn);
	bool sgn = insn->id != C6X_INS_CMPGTU && insn->id != C6X_INS_CMPLTU;
	RzILOpPure *s1 = lng ? c6x_long_src(&OP(0), sgn) : c6x_src(&OP(0));
	RzILOpPure *s2 = lng ? c6x_long_src(&OP(1), sgn) : c6x_src(&OP(1));
	if (!s1 || !s2) {
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	return c6x_wr(&OP(2), ITE(mk(s1, s2), U32(1), U32(0)));
}

// Low 16 bits of `v`, sign-extended back to 32 -- the operand form shared by
// the 16x16 multiplies and the *L half selectors.
static RzILOpPure *c6x_low16s(RzILOpPure *v) {
	return SIGNED(32, UNSIGNED(16, v));
}

// High 16 bits of `v`, sign-extended to 32.
static RzILOpPure *c6x_high16s(RzILOpPure *v) {
	return SIGNED(32, UNSIGNED(16, SHIFTR0(v, U32(16))));
}

// The multiply-accumulate forms all take their halfword operands sign-extended
// into 64 bits, and the normalise forms all test whether a high part is empty.
#define SLO(x)          SIGNED(64, c6x_low16s(VARLP(x)))
#define SHI(x)          SIGNED(64, c6x_high16s(VARLP(x)))
#define HI_ZERO(vn, sh) IS_ZERO(SHIFTR0(VARLP(vn), U32(sh)))

// Clamp a 32-bit signed value to the signed n-bit range, returned as n bits --
// the saturation shared by the saturating packed ops. The wide value is bound
// once so both bound checks and the pass-through see the same operand.
static RzILOpBitVector *c6x_sat_s(RzILOpPure *x, ut8 n) {
	st64 hi = (1LL << (n - 1)) - 1;
	st64 lo = -(1LL << (n - 1));
	return LET("_sat", x,
		ITE(SGT(VARLP("_sat"), S32(hi)), SN(n, hi),
			ITE(SLT(VARLP("_sat"), S32(lo)), SN(n, lo),
				UNSIGNED(n, VARLP("_sat")))));
}

// Absolute value of one signed 16-bit lane, saturating 0x8000 to 0x7fff (it is
// its own negation). The lane is bound once so the sign test, the endpoint test
// and the negation all see it.
static RzILOpBitVector *c6x_abs16(RzILOpBitVector *lane) {
	return LET("_h", lane,
		ITE(SGE(VARLP("_h"), SN(16, 0)), VARLP("_h"),
			ITE(EQ(VARLP("_h"), UN(16, 0x8000)), UN(16, 0x7fff), NEG(VARLP("_h")))));
}

// Packed add/sub (ADD2/SUB2 over two halfwords, ADD4/SUB4 over four bytes):
// `lanes` equal-width lanes computed independently, with no carry across a lane
// boundary -- RzIL ADD/SUB is modular at the operand width, so each lane wraps
// on its own. APPEND stacks the lanes back with the highest on top.
static RzILOpEffect *c6x_packed(const C6xInsn *insn, ut8 lanes, bool sub) {
	ut8 width = 32 / lanes;
	RzILOpBitVector *acc = NULL;
	for (ut8 i = 0; i < lanes; i++) {
		RzILOpPure *a = c6x_src(&OP(0));
		RzILOpPure *b = c6x_src(&OP(1));
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			rz_il_op_pure_free(acc);
			return NULL;
		}
		RzILOpBitVector *la = UNSIGNED(width, i ? SHIFTR0(a, U32(i * width)) : a);
		RzILOpBitVector *lb = UNSIGNED(width, i ? SHIFTR0(b, U32(i * width)) : b);
		RzILOpBitVector *lane = sub ? SUB(la, lb) : ADD(la, lb);
		acc = acc ? APPEND(lane, acc) : lane;
	}
	return c6x_wr(&OP(2), acc);
}

// Packed signed saturating add/sub (SADD2/SSUB2): each 16-bit lane is summed in
// 32-bit signed and clamped back to the signed 16-bit range, so a lane that
// overflows sticks at the endpoint instead of wrapping.
static RzILOpEffect *c6x_sat_packed(const C6xInsn *insn, ut8 lanes, bool sub) {
	ut8 width = 32 / lanes;
	RzILOpBitVector *acc = NULL;
	for (ut8 i = 0; i < lanes; i++) {
		RzILOpPure *a = c6x_src(&OP(0));
		RzILOpPure *b = c6x_src(&OP(1));
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			rz_il_op_pure_free(acc);
			return NULL;
		}
		RzILOpBitVector *la = SIGNED(32, UNSIGNED(width, i ? SHIFTR0(a, U32(i * width)) : a));
		RzILOpBitVector *lb = SIGNED(32, UNSIGNED(width, i ? SHIFTR0(b, U32(i * width)) : b));
		RzILOpBitVector *lane = c6x_sat_s(sub ? SUB(la, lb) : ADD(la, lb), width);
		acc = acc ? APPEND(lane, acc) : lane;
	}
	return c6x_wr(&OP(2), acc);
}

// Packed per-lane min/max (MIN2/MAX2 signed halfwords, MINU4/MAXU4 unsigned
// bytes). Each lane compares src1 against src2 (signed or unsigned) and keeps
// the smaller or larger; the compared value is duplicated so the winning lane
// is still available to write.
static RzILOpEffect *c6x_minmax(const C6xInsn *insn, ut8 lanes, bool sgned, bool is_min) {
	ut8 width = 32 / lanes;
	RzILOpBitVector *acc = NULL;
	for (ut8 i = 0; i < lanes; i++) {
		RzILOpPure *a = c6x_src(&OP(0));
		RzILOpPure *b = c6x_src(&OP(1));
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			rz_il_op_pure_free(acc);
			return NULL;
		}
		RzILOpBitVector *la = UNSIGNED(width, i ? SHIFTR0(a, U32(i * width)) : a);
		RzILOpBitVector *lb = UNSIGNED(width, i ? SHIFTR0(b, U32(i * width)) : b);
		RzILOpBool *le = sgned ? SLE(DUP(la), DUP(lb)) : ULE(DUP(la), DUP(lb));
		// min keeps src1 when src1 <= src2; max keeps src2 in that case
		RzILOpBitVector *lane = is_min ? ITE(le, la, lb) : ITE(le, lb, la);
		acc = acc ? APPEND(lane, acc) : lane;
	}
	return c6x_wr(&OP(2), acc);
}

// Four-way byte dot product: sum of the four byte-lane products into a 32-bit
// result. `s1_signed` sign-extends src1's bytes (DOTPSU4); src2's bytes are
// always unsigned, as is DOTPU4's src1.
static RzILOpEffect *c6x_dotp4(const C6xInsn *insn, bool s1_signed) {
	RzILOpBitVector *acc = NULL;
	for (ut8 i = 0; i < 4; i++) {
		RzILOpPure *a = c6x_src(&OP(0));
		RzILOpPure *b = c6x_src(&OP(1));
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			rz_il_op_pure_free(acc);
			return NULL;
		}
		RzILOpBitVector *ba = UNSIGNED(8, i ? SHIFTR0(a, U32(i * 8)) : a);
		RzILOpBitVector *bb = UNSIGNED(8, i ? SHIFTR0(b, U32(i * 8)) : b);
		RzILOpBitVector *prod = MUL(s1_signed ? SIGNED(32, ba) : UNSIGNED(32, ba), UNSIGNED(32, bb));
		acc = acc ? ADD(acc, prod) : prod;
	}
	return c6x_wr(&OP(2), acc);
}

// DOTPRSU2 / DOTPNRSU2: dot product of a signed-halfword src1 and an
// unsigned-halfword src2, rounded (+0x8000) then arithmetic-shifted right by 16
// and sign-extended into dst. DOTPNRSU2 subtracts the low-halfword product
// instead of adding it. The intermediate stays 64-bit so neither ~32-bit
// product nor the rounding term can overflow before the shift (SPRUFE8B's
// 33-bit precision note).
static RzILOpEffect *c6x_dotprs2(const C6xInsn *insn, bool negate) {
	RzILOpPure *s1a = c6x_src(&OP(0));
	RzILOpPure *s1b = c6x_src(&OP(0));
	RzILOpPure *s2a = c6x_src(&OP(1));
	RzILOpPure *s2b = c6x_src(&OP(1));
	if (!s1a || !s1b || !s2a || !s2b) {
		rz_il_op_pure_free(s1a);
		rz_il_op_pure_free(s1b);
		rz_il_op_pure_free(s2a);
		rz_il_op_pure_free(s2b);
		return NULL;
	}
	RzILOpBitVector *phi = MUL(SIGNED(64, UNSIGNED(16, SHIFTR0(s1a, U32(16)))), UNSIGNED(64, UNSIGNED(16, SHIFTR0(s2a, U32(16)))));
	RzILOpBitVector *plo = MUL(SIGNED(64, UNSIGNED(16, s1b)), UNSIGNED(64, UNSIGNED(16, s2b)));
	RzILOpBitVector *sum = ADD(negate ? SUB(phi, plo) : ADD(phi, plo), U64(0x8000));
	return c6x_wr(&OP(2), UNSIGNED(32, SHIFTRA(sum, U32(16))));
}

// Packed compare to a bit-per-lane mask (CMPEQ2/CMPGT2 halfwords, CMPEQ4/CMPGTU4
// bytes): lane i sets bit i when it satisfies `mk`, and the mask is
// zero-extended to 32 bits. The comparison reads each lane at its own width, so
// SGT/UGT there give the signed or unsigned relation the mnemonic wants.
static RzILOpEffect *c6x_cmp_packed(const C6xInsn *insn, ut8 lanes, rz_il_bool_2args_op *mk) {
	ut8 width = 32 / lanes;
	RzILOpBitVector *mask = NULL;
	for (ut8 i = 0; i < lanes; i++) {
		RzILOpPure *a = c6x_src(&OP(0));
		RzILOpPure *b = c6x_src(&OP(1));
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			rz_il_op_pure_free(mask);
			return NULL;
		}
		RzILOpBitVector *la = UNSIGNED(width, i ? SHIFTR0(a, U32(i * width)) : a);
		RzILOpBitVector *lb = UNSIGNED(width, i ? SHIFTR0(b, U32(i * width)) : b);
		RzILOpBitVector *bit = ITE(mk(la, lb), UN(1, 1), UN(1, 0));
		mask = mask ? APPEND(bit, mask) : bit;
	}
	return c6x_wr(&OP(2), UNSIGNED(32, mask));
}

// A binary single-precision float constructor (fadd/fsub/fmul), mirroring the
// pure/bool 2-arg op typedefs for the shared shape of the float arithmetic.
typedef RzILOpFloat *(c6x_fbin_op)(RzFloatRMode, RzILOpFloat *, RzILOpFloat *);

// Single-precision float op: read src1/src2 as binary32, apply `mk` rounding to
// nearest-even (the C6000 reset default), and write the result's bits back.
static RzILOpEffect *c6x_fsp(const C6xInsn *insn, c6x_fbin_op *mk) {
	RzILOpPure *s1 = c6x_src(&OP(0));
	RzILOpPure *s2 = c6x_src(&OP(1));
	if (!s1 || !s2) {
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	return c6x_wr(&OP(2), F2BV(mk(RZ_FLOAT_RMODE_RNE, FLOATV32(s1), FLOATV32(s2))));
}

// Read a register pair as one 64-bit value: the even member is the low word and
// the odd member the high word, matching how LDDW loads a doubleword.
static RzILOpBitVector *c6x_pair64(const C6xOperand *o) {
	if (o->kind != C6X_OP_REGPAIR) {
		return NULL;
	}
	return APPEND(c6x_reg_read(c6x_reg_name(o->v.reg.side, o->v.reg.num + 1)), c6x_reg_read(c6x_reg_name(o->v.reg.side, o->v.reg.num)));
}

// Write a 64-bit value into a register pair (low word -> even, high -> odd),
// binding it to a local so both halves read the same result.
static RzILOpEffect *c6x_wr_pair64(const C6xOperand *o, RzILOpBitVector *v) {
	if (o->kind != C6X_OP_REGPAIR) {
		rz_il_op_pure_free(v);
		return NULL;
	}
	return SEQ3(SETL("_d", v),
		c6x_reg_write(c6x_reg_name(o->v.reg.side, o->v.reg.num), UNSIGNED(32, VARL("_d"))),
		c6x_reg_write(c6x_reg_name(o->v.reg.side, o->v.reg.num + 1), UNSIGNED(32, SHIFTR0(VARL("_d"), U32(32)))));
}

// Read a 40-bit long from a register pair, sign-extended from bit 39 to 64 bits
// (the even register holds bits [31:0], the odd register bits [39:32]).
static RzILOpBitVector *c6x_long40(const C6xOperand *o) {
	RzILOpBitVector *p = c6x_pair64(o);
	if (!p) {
		return NULL;
	}
	return SHIFTRA(SHIFTL0(p, U32(24)), U32(24));
}

// The even (low) or odd (high) register of a pair operand.
static RzILOpPure *c6x_pair_reg(const C6xOperand *o, bool odd) {
	return o->kind == C6X_OP_REGPAIR ? c6x_reg_read(c6x_reg_name(o->v.reg.side, o->v.reg.num + odd)) : NULL;
}

// A 32-bit operand that may be a constant applied to both halves of a pair, or
// one register of a pair: the lane \p odd of a double-word source.
static RzILOpPure *c6x_dw_lane(const C6xOperand *o, bool odd) {
	return o->kind == C6X_OP_REGPAIR ? c6x_pair_reg(o, odd) : c6x_src(o);
}

// Write \p odd and \p even into the pair dst, as the parallel halves of the
// dual-result forms.
static RzILOpEffect *c6x_wr_dual(const C6xOperand *o, RzILOpBitVector *odd, RzILOpBitVector *even) {
	if (!odd || !even) {
		rz_il_op_pure_free(odd);
		rz_il_op_pure_free(even);
		return NULL;
	}
	return c6x_wr_pair64(o, APPEND(odd, even));
}

// Double-precision float op over register pairs (binary64, round to nearest
// even).
static RzILOpEffect *c6x_fdp(const C6xInsn *insn, c6x_fbin_op *mk) {
	RzILOpBitVector *a = c6x_pair64(&OP(0));
	RzILOpBitVector *b = c6x_pair64(&OP(1));
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	return c6x_wr_pair64(&OP(2), F2BV(mk(RZ_FLOAT_RMODE_RNE, FLOATV64(a), FLOATV64(b))));
}

// The high or low halfword of a source, as a 16-bit value -- the halfword
// selector shared by the PACK2 family.
static RzILOpBitVector *c6x_half(const C6xOperand *o, bool high) {
	RzILOpPure *s = c6x_src(o);
	return s ? UNSIGNED(16, high ? SHIFTR0(s, U32(16)) : s) : NULL;
}

// dst = (halfword of src1) : (halfword of src2); PACK2/PACKH2/PACKLH2/PACKHL2
// differ only in which halfword each source contributes.
static RzILOpEffect *c6x_pack(const C6xInsn *insn, bool hi_from_high, bool lo_from_high) {
	RzILOpBitVector *hi = c6x_half(&OP(0), hi_from_high);
	RzILOpBitVector *lo = c6x_half(&OP(1), lo_from_high);
	if (!hi || !lo) {
		rz_il_op_pure_free(hi);
		rz_il_op_pure_free(lo);
		return NULL;
	}
	return c6x_wr(&OP(2), APPEND(hi, lo));
}

// Byte `idx` of a source, zero-extended to 16 bits -- the lane selector shared
// by the UNPK*U4 unpacks.
static RzILOpBitVector *c6x_byte_zx16(const C6xOperand *o, ut8 idx) {
	RzILOpPure *s = c6x_src(o);
	return s ? UNSIGNED(16, UNSIGNED(8, idx ? SHIFTR0(s, U32(idx * 8)) : s)) : NULL;
}

// Byte `idx` of an operand, sign-extended to 16 bits (the signed source lane of
// MPYSU4 and friends).
static RzILOpBitVector *c6x_byte_sx16(const C6xOperand *o, ut8 idx) {
	RzILOpPure *s = c6x_src(o);
	return s ? SIGNED(16, UNSIGNED(8, idx ? SHIFTR0(s, U32(idx * 8)) : s)) : NULL;
}

// dst = zero-extend two bytes of src to two halfwords. UNPKLU4 takes bytes 0,1;
// UNPKHU4 takes bytes 2,3. The lower byte lands in the lower halfword.
static RzILOpEffect *c6x_unpku4(const C6xInsn *insn, bool high) {
	ut8 base = high ? 2 : 0;
	RzILOpBitVector *hw0 = c6x_byte_zx16(&OP(0), base);
	RzILOpBitVector *hw1 = c6x_byte_zx16(&OP(0), base + 1);
	if (!hw0 || !hw1) {
		rz_il_op_pure_free(hw0);
		rz_il_op_pure_free(hw1);
		return NULL;
	}
	return c6x_wr(&OP(1), APPEND(hw1, hw0));
}

// MPYU4/MPYSU4: four independent 8x8 products packed into a 64-bit register pair
// (byte i of each source drives halfword i of the result). src2 is unsigned;
// src1 is unsigned for MPYU4 and signed for MPYSU4. A byte-by-byte product fits
// a halfword, so a 16-bit multiply is exact and the lanes just stack.
static RzILOpEffect *c6x_mpy4(const C6xInsn *insn, bool src1_signed) {
	RzILOpBitVector *lane[4];
	for (ut8 i = 0; i < 4; i++) {
		RzILOpBitVector *a = src1_signed ? c6x_byte_sx16(&OP(0), i) : c6x_byte_zx16(&OP(0), i);
		RzILOpBitVector *b = c6x_byte_zx16(&OP(1), i);
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			while (i--) {
				rz_il_op_pure_free(lane[i]);
			}
			return NULL;
		}
		lane[i] = MUL(a, b);
	}
	return c6x_wr_pair64(&OP(2), APPEND(lane[3], APPEND(lane[2], APPEND(lane[1], lane[0]))));
}

// Effective address of a memory operand. When the mode modifies the base
// register, *wb receives that update and *pre says whether it applies before
// the access (pre-increment) or after it (post-increment). `bytes` scales a
// register/constant offset written with the scaled (bracket) syntax.
static RzILOpPure *c6x_ea(const C6xOperand *m, ut8 bytes, RzILOpEffect **wb, bool *pre) {
	*wb = NULL;
	*pre = false;
	const char *base = c6x_reg_name(m->v.mem.base_side, m->v.mem.base);
	ut32 scale = m->v.mem.scaled ? bytes : 1;
	bool reg_off = false, dec = false, modify = false, ispre = false;
	switch (m->v.mem.mode) {
	case C6X_AM_NEG_REG:
		reg_off = true;
		dec = true;
		break;
	case C6X_AM_POS_REG: reg_off = true; break;
	case C6X_AM_NEG_CST: dec = true; break;
	case C6X_AM_POS_CST:
	case C6X_AM_BASE_LONG: break;
	case C6X_AM_PREDEC_REG:
		reg_off = true;
		dec = true;
		modify = true;
		ispre = true;
		break;
	case C6X_AM_PREINC_REG:
		reg_off = true;
		modify = true;
		ispre = true;
		break;
	case C6X_AM_POSTDEC_REG:
		reg_off = true;
		dec = true;
		modify = true;
		break;
	case C6X_AM_POSTINC_REG:
		reg_off = true;
		modify = true;
		break;
	case C6X_AM_PREDEC_CST:
		dec = true;
		modify = true;
		ispre = true;
		break;
	case C6X_AM_PREINC_CST:
		modify = true;
		ispre = true;
		break;
	case C6X_AM_POSTDEC_CST:
		dec = true;
		modify = true;
		break;
	case C6X_AM_POSTINC_CST:
		modify = true;
		break;
	default:
		rz_warn_if_reached();
		return NULL;
	}
	// The scaled displacement widens before it multiplies: a ucst15 by an
	// eight-byte access cannot overflow today, but computing in 64 bits keeps
	// that true independently of the offset field widths.
	RzILOpPure *off = reg_off
		? (scale > 1 ? MUL(c6x_reg_read(c6x_reg_name(m->v.mem.base_side, m->v.mem.off_reg)), U32(scale)) : c6x_reg_read(c6x_reg_name(m->v.mem.base_side, m->v.mem.off_reg)))
		: U32((ut64)m->v.mem.off_cst * scale);
	if (modify) {
		// pre/post modify: base <- base +/- off; EA reads the base, before the
		// update for pre-modify and (unchanged) after it for post-modify.
		*wb = c6x_reg_write(base, dec ? SUB(c6x_reg_read(base), off) : ADD(c6x_reg_read(base), off));
		*pre = ispre;
		return c6x_reg_read(base);
	}
	return dec ? SUB(c6x_reg_read(base), off) : ADD(c6x_reg_read(base), off);
}

// Order a memory access against its base write-back: pre-modify updates first,
// post-modify updates after, and a plain offset has no write-back.
static RzILOpEffect *c6x_mem_seq(RzILOpEffect *access, RzILOpEffect *wb, bool pre) {
	if (!wb) {
		return access;
	}
	return pre ? SEQ2(wb, access) : SEQ2(access, wb);
}

// Whether the mode of \p m writes its base register back.
static bool c6x_ea_modifies(const C6xOperand *m) {
	switch (m->v.mem.mode) {
	case C6X_AM_PREDEC_CST:
	case C6X_AM_PREINC_CST:
	case C6X_AM_POSTDEC_CST:
	case C6X_AM_POSTINC_CST:
	case C6X_AM_PREDEC_REG:
	case C6X_AM_PREINC_REG:
	case C6X_AM_POSTDEC_REG:
	case C6X_AM_POSTINC_REG:
		return true;
	default:
		return false;
	}
}

// Whether the address of \p m is computed from register \p num of file \p side.
static bool c6x_ea_reads(const C6xOperand *m, C6xSide side, ut8 num) {
	if (m->v.mem.base_side != side) {
		return false;
	}
	switch (m->v.mem.mode) {
	case C6X_AM_NEG_REG:
	case C6X_AM_POS_REG:
	case C6X_AM_PREDEC_REG:
	case C6X_AM_PREINC_REG:
	case C6X_AM_POSTDEC_REG:
	case C6X_AM_POSTINC_REG:
		return m->v.mem.base == num || m->v.mem.off_reg == num;
	default:
		return m->v.mem.base == num;
	}
}

// Whether a load into \p d has to read its address before it writes: the
// post-modify update reads its registers as the instruction found them.
static bool c6x_load_clobbers_ea(const C6xOperand *m, const C6xOperand *d, bool pre) {
	if (pre || !c6x_ea_modifies(m)) {
		return false;
	}
	return c6x_ea_reads(m, d->v.reg.side, d->v.reg.num) ||
		(d->kind == C6X_OP_REGPAIR && c6x_ea_reads(m, d->v.reg.side, d->v.reg.num + 1));
}

// Whether a store from \p r reads a register the pre-modify update has
// written by then: it stores what the instruction found there.
static bool c6x_store_reads_wb(const C6xOperand *m, const C6xOperand *r, bool pre) {
	if (!pre || !c6x_ea_modifies(m) || m->v.mem.base_side != r->v.reg.side) {
		return false;
	}
	return m->v.mem.base == r->v.reg.num || (r->kind == C6X_OP_REGPAIR && m->v.mem.base == r->v.reg.num + 1);
}

// Load: dst = extend(mem[EA]). `sign` selects sign- vs zero-extension to 32.
static RzILOpEffect *c6x_load(const C6xInsn *insn, ut8 bytes, bool sign) {
	// single-register widths only; pairs go through c6x_load_pair
	rz_return_val_if_fail(OP(1).kind == C6X_OP_REG && bytes <= 4, NULL);
	RzILOpEffect *wb = NULL;
	bool pre;
	RzILOpPure *ea = c6x_ea(&OP(0), bytes, &wb, &pre);
	if (!ea) {
		return NULL;
	}
	bool early = c6x_load_clobbers_ea(&OP(0), &OP(1), pre);
	RzILOpPure *at = early ? VARL("ea") : ea;
	RzILOpPure *val = bytes == 4 ? LOADW(32, at) : (sign ? SIGNED(32, LOADW(bytes * 8, at)) : UNSIGNED(32, LOADW(bytes * 8, at)));
	RzILOpEffect *set = c6x_reg_write(c6x_reg_name(OP(1).v.reg.side, OP(1).v.reg.num), val);
	return early ? SEQ3(SETL("ea", ea), wb, set) : c6x_mem_seq(set, wb, pre);
}

// Store: mem[EA] = truncate(src). Pairs use c6x_store_pair.
static RzILOpEffect *c6x_store(const C6xInsn *insn, ut8 bytes) {
	rz_return_val_if_fail(OP(0).kind == C6X_OP_REG && bytes <= 4, NULL);
	RzILOpEffect *wb = NULL;
	bool pre;
	RzILOpPure *ea = c6x_ea(&OP(1), bytes, &wb, &pre);
	if (!ea) {
		return NULL;
	}
	bool early = c6x_store_reads_wb(&OP(1), &OP(0), pre);
	RzILOpPure *src = c6x_reg_read(c6x_reg_name(OP(0).v.reg.side, OP(0).v.reg.num));
	RzILOpPure *val = early ? VARL("_v") : src;
	RzILOpEffect *st = bytes == 4 ? STOREW(ea, val) : STOREW(ea, UNSIGNED(bytes * 8, val));
	return early ? SEQ3(SETL("_v", src), wb, st) : c6x_mem_seq(st, wb, pre);
}

// Doubleword load into a register pair: the even member gets mem[EA] and the
// odd member mem[EA+4] (little-endian keeps the low word at the lower address).
// The address is bound to a local so both accesses share one base computation.
// LDNDW behaves the same here; only its alignment requirement differs.
static RzILOpEffect *c6x_load_pair(const C6xInsn *insn) {
	rz_return_val_if_fail(OP(1).kind == C6X_OP_REGPAIR, NULL);
	RzILOpEffect *wb = NULL;
	bool pre;
	RzILOpPure *ea = c6x_ea(&OP(0), 8, &wb, &pre);
	if (!ea) {
		return NULL;
	}
	const char *lo = c6x_reg_name(OP(1).v.reg.side, OP(1).v.reg.num);
	const char *hi = c6x_reg_name(OP(1).v.reg.side, OP(1).v.reg.num + 1);
	RzILOpEffect *set_lo = c6x_reg_write(lo, LOADW(32, VARL("ea")));
	RzILOpEffect *set_hi = c6x_reg_write(hi, LOADW(32, ADD(VARL("ea"), U32(4))));
	if (c6x_load_clobbers_ea(&OP(0), &OP(1), pre)) {
		return SEQ4(SETL("ea", ea), wb, set_lo, set_hi);
	}
	return c6x_mem_seq(SEQ3(SETL("ea", ea), set_lo, set_hi), wb, pre);
}

// Doubleword store from a register pair: mem[EA] <- even member, mem[EA+4] <-
// odd member. STDW and the non-aligned STNDW share this data path.
static RzILOpEffect *c6x_store_pair(const C6xInsn *insn) {
	rz_return_val_if_fail(OP(0).kind == C6X_OP_REGPAIR, NULL);
	RzILOpEffect *wb = NULL;
	bool pre;
	RzILOpPure *ea = c6x_ea(&OP(1), 8, &wb, &pre);
	if (!ea) {
		return NULL;
	}
	const char *lo = c6x_reg_name(OP(0).v.reg.side, OP(0).v.reg.num);
	const char *hi = c6x_reg_name(OP(0).v.reg.side, OP(0).v.reg.num + 1);
	if (c6x_store_reads_wb(&OP(1), &OP(0), pre)) {
		return SEQ6(SETL("_v", c6x_reg_read(lo)), SETL("_w", c6x_reg_read(hi)), wb, SETL("ea", ea),
			STOREW(VARL("ea"), VARL("_v")),
			STOREW(ADD(VARL("ea"), U32(4)), VARL("_w")));
	}
	RzILOpEffect *body = SEQ3(SETL("ea", ea),
		STOREW(VARL("ea"), c6x_reg_read(lo)),
		STOREW(ADD(VARL("ea"), U32(4)), c6x_reg_read(hi)));
	return c6x_mem_seq(body, wb, pre);
}

// One 16-bit half of `v` widened to 32 bits: the high or low halfword, sign- or
// zero-extended per the multiply variant.
static RzILOpPure *c6x_half16(RzILOpPure *v, bool high, bool sign) {
	RzILOpBitVector *h = UNSIGNED(16, high ? SHIFTR0(v, U32(16)) : v);
	return sign ? SIGNED(32, h) : UNSIGNED(32, h);
}

// dst = half16(src1) x half16(src2), the shared shape of the 16x16 multiplies.
// Each half is widened to 32 bits by its own signedness; the true product fits
// in 32 bits, so the modular MUL yields the exact result for every sign mix.
static RzILOpEffect *c6x_mpy16(const C6xInsn *insn, bool s1_hi, bool s1_sgn, bool s2_hi, bool s2_sgn) {
	RzILOpPure *s1 = c6x_src(&OP(0));
	RzILOpPure *s2 = c6x_src(&OP(1));
	if (!s1 || !s2) {
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	return c6x_wr(&OP(2), MUL(c6x_half16(s1, s1_hi, s1_sgn), c6x_half16(s2, s2_hi, s2_sgn)));
}

// dst = sat((signed half16(src1) x signed half16(src2)) << 1). The doubled
// product overflows 32-bit signed only for (-0x8000)^2, whose product is
// 0x40000000; that one case saturates to 0x7fffffff, every other doubles in place.
static RzILOpEffect *c6x_smpy(const C6xInsn *insn, bool s1_hi, bool s2_hi) {
	RzILOpPure *s1 = c6x_src(&OP(0));
	RzILOpPure *s2 = c6x_src(&OP(1));
	if (!s1 || !s2) {
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	RzILOpBitVector *p = MUL(c6x_half16(s1, s1_hi, true), c6x_half16(s2, s2_hi, true));
	return c6x_wr(&OP(2),
		LET("_p", p,
			ITE(EQ(VARLP("_p"), U32(0x40000000)), U32(0x7fffffff), SHIFTL0(VARLP("_p"), U32(1)))));
}

// 32x32 multiply, signedness per source. A pair dst takes the full 64-bit
// product (each source widened to 64 by its signedness); a single dst keeps the
// low 32 bits, which are signedness-independent.
static RzILOpEffect *c6x_mpy32(const C6xInsn *insn, bool s1_sgn, bool s2_sgn) {
	RzILOpPure *s1 = c6x_src(&OP(0));
	RzILOpPure *s2 = c6x_src(&OP(1));
	if (!s1 || !s2) {
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	const C6xOperand *dst = &OP(2);
	if (dst->kind == C6X_OP_REGPAIR) {
		RzILOpBitVector *w1 = s1_sgn ? SIGNED(64, s1) : UNSIGNED(64, s1);
		RzILOpBitVector *w2 = s2_sgn ? SIGNED(64, s2) : UNSIGNED(64, s2);
		return c6x_wr_pair64(dst, MUL(w1, w2));
	}
	return c6x_wr(dst, MUL(s1, s2));
}

// Clamp a 64-bit signed intermediate to the 32-bit signed range and return the
// 32-bit result -- the saturation shared by SADD/SSUB/SSHL, which compute the
// exact result in 64 bits first so the overflow the 32-bit op would hide is
// visible to the bound checks.
static RzILOpBitVector *c6x_sats32(RzILOpBitVector *x) {
	return LET("_s", x,
		ITE(SGT(VARLP("_s"), SN(64, 0x7fffffff)), U32(0x7fffffff),
			ITE(SLT(VARLP("_s"), SN(64, -0x80000000LL)), U32(0x80000000),
				UNSIGNED(32, VARLP("_s")))));
}

// CMPY: complex multiply of two signed packed-16-bit pairs into a register
// pair. dst_e (even) = sat32(lo1*hi2 + hi1*lo2); dst_o (odd) = hi1*hi2 - lo1*lo2.
// Only dst_e saturates (SPRUFE8B's all-8000h note); dst_o keeps the low 32 bits.
// The products and the dst_e sum are formed in 64 bits so the overflow the
// saturation must catch is visible.
static RzILOpEffect *c6x_cmpy(const C6xInsn *insn) {
	RzILOpPure *s1 = c6x_src(&OP(0));
	RzILOpPure *s2 = c6x_src(&OP(1));
	if (!s1 || !s2) {
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	RzILOpBitVector *dst_e = c6x_sats32(ADD(MUL(SLO("_a"), SHI("_b")), MUL(SHI("_a"), SLO("_b"))));
	RzILOpBitVector *dst_o = UNSIGNED(32, SUB(MUL(SHI("_a"), SHI("_b")), MUL(SLO("_a"), SLO("_b"))));
	return c6x_wr_pair64(&OP(2), LET("_a", s1, LET("_b", s2, APPEND(dst_o, dst_e))));
}

// One rounded, packed half of a CMPYR/CMPYR1 result. `sum` is the 64-bit
// product sum; it is saturated to signed 32-bit, rounded, and the top 16 bits
// are returned. CMPYR rounds by 0x8000; CMPYR1 rounds by 0x4000 and then
// left-shifts by one with saturation (the extra guard bit of "31-bit" rounding).
static RzILOpBitVector *c6x_cmpyr_half(RzILOpBitVector *sum, bool r1) {
	RzILOpBitVector *tmp = SIGNED(64, c6x_sats32(sum));
	RzILOpBitVector *rnd = r1
		? c6x_sats32(SHIFTL0(ADD(tmp, U64(0x4000)), U32(1)))
		: c6x_sats32(ADD(tmp, U64(0x8000)));
	return UNSIGNED(16, SHIFTR0(rnd, U32(16)));
}

// CMPYR / CMPYR1: complex multiply of two signed packed-16-bit pairs, each
// component rounded and packed into one 32-bit dst -- the real part
// (hi1*hi2 - lo1*lo2) in the upper half, the imaginary part (lo1*hi2 + hi1*lo2)
// in the lower half. Both product sums saturate to signed 32-bit before the
// rounding step (SPRUFE8B's tmp_e/tmp_o).
static RzILOpEffect *c6x_cmpyr(const C6xInsn *insn, bool r1) {
	RzILOpPure *s1 = c6x_src(&OP(0));
	RzILOpPure *s2 = c6x_src(&OP(1));
	if (!s1 || !s2) {
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	RzILOpBitVector *lo = c6x_cmpyr_half(ADD(MUL(SLO("_a"), SHI("_b")), MUL(SHI("_a"), SLO("_b"))), r1);
	RzILOpBitVector *hi = c6x_cmpyr_half(SUB(MUL(SHI("_a"), SHI("_b")), MUL(SLO("_a"), SLO("_b"))), r1);
	return c6x_wr(&OP(2), LET("_a", s1, LET("_b", s2, APPEND(hi, lo))));
}

// DDOTPL2 / DDOTPH2: two sliding-window dot products of signed packed-16-bit
// values (SPRUFE8B). src1_o:src1_e is read as four contiguous halfwords d3..d0
// and src2 as c1,c0; each dst half is sat32 of a two-tap dot product with src2,
// the window shifted one halfword between dst_e and dst_o. DDOTPL2 takes the low
// windows ([d1,d0] -> dst_e, [d2,d1] -> dst_o); DDOTPH2 the high windows
// ([d2,d1] -> dst_e, [d3,d2] -> dst_o). Products are formed in 64 bits so the
// overflow the saturation must catch stays visible.
static RzILOpEffect *c6x_ddotp2(const C6xInsn *insn, bool high) {
	const C6xOperand *s1 = &OP(0);
	rz_return_val_if_fail(s1->kind == C6X_OP_REGPAIR, NULL);
	RzILOpPure *e = c6x_reg_read(c6x_reg_name(s1->v.reg.side, s1->v.reg.num)); // src1_e (even)
	RzILOpPure *o = c6x_reg_read(c6x_reg_name(s1->v.reg.side, s1->v.reg.num + 1)); // src1_o (odd)
	RzILOpPure *c = c6x_src(&OP(1));
	if (!c) {
		rz_il_op_pure_free(e);
		rz_il_op_pure_free(o);
		return NULL;
	}
	// [d2,d1].[c1,c0] -- the middle window shared by DDOTPL2 dst_o and DDOTPH2 dst_e.
	RzILOpBitVector *mid = c6x_sats32(ADD(MUL(SLO("_o"), SHI("_c")), MUL(SHI("_e"), SLO("_c"))));
	RzILOpBitVector *dst_e, *dst_o;
	if (high) {
		dst_e = mid;
		dst_o = c6x_sats32(ADD(MUL(SHI("_o"), SHI("_c")), MUL(SLO("_o"), SLO("_c")))); // [d3,d2]
	} else {
		dst_e = c6x_sats32(ADD(MUL(SHI("_e"), SHI("_c")), MUL(SLO("_e"), SLO("_c")))); // [d1,d0]
		dst_o = mid;
	}
	return c6x_wr_pair64(&OP(2), LET("_e", e, LET("_o", o, LET("_c", c, APPEND(dst_o, dst_e)))));
}

// Count leading zero bits of \p x into the local \p out, which the caller reads
// afterwards. \p width is 32 or 64, and clz(0) == width. Shifting left until the
// top bit is set expresses this in one loop rather than an unrolled binary
// search, at the cost of being an effect rather than a pure expression. The
// shifted copy is named by its width, since one lift may count both.
static RzILOpEffect *c6x_clz_into(const char *out, RzILOpPure *x, ut32 width) {
	const char *v = width == 64 ? "_clzv64" : "_clzv";
	return SEQ3(
		SETL(v, x),
		SETL(out, U32(0)),
		REPEAT(AND(ULT(VARL(out), U32(width)), INV(MSB(VARL(v)))),
			SEQ2(SETL(v, SHIFTL0(VARL(v), UN(width, 1))),
				SETL(out, ADD(VARL(out), U32(1))))));
}

// Byte-address arithmetic (ADDA*/SUBA*). The addressing syntax lists the base
// (src2) first, so ops[0] is the base and ops[1] the index; scale is 0/1/2/3.
static RzILOpEffect *c6x_addr(const C6xInsn *insn, bool sub, ut8 scale) {
	RzILOpPure *base = c6x_src(&OP(0));
	RzILOpPure *off = c6x_src(&OP(1));
	if (!base || !off) {
		rz_il_op_pure_free(base);
		rz_il_op_pure_free(off);
		return NULL;
	}
	if (scale) {
		off = SHIFTL0(off, U32(scale));
	}
	return c6x_wr(&OP(2), sub ? SUB(base, off) : ADD(base, off));
}

// Where a branch goes: a register, or a displacement off the address of the
// fetch packet holding the branch (PCE1).
static RzILOpBitVector *c6x_branch_target(const C6xInsn *insn, ut64 pc) {
	const C6xOperand *t = &OP(0);
	switch (t->kind) {
	case C6X_OP_PCREL:
		return U32((ut32)(c6x_packet_base(pc) + t->v.imm.value));
	case C6X_OP_REG:
		return c6x_reg_read(c6x_reg_name(t->v.reg.side, t->v.reg.num));
	case C6X_OP_CTRLREG:
		return c6x_reg_read(t->v.ctrl); // e.g. b irp / b nrp (return from interrupt)
	default:
		return NULL;
	}
}

// Control transfer, no-ops and the return-address helper.
static RzILOpEffect *c6x_lift_control(const C6xInsn *insn, ut64 pc) {
	switch (insn->id) {
	case C6X_INS_NOP:
	case C6X_INS_IDLE: {
		return NOP();
	}
	case C6X_INS_B:
	case C6X_INS_BNOP: {
		// the transfer alone: c6x_lift_il() in analysis_tms320.c places it
		// after the delay slots
		RzILOpBitVector *tgt = c6x_branch_target(insn, pc);
		return tgt ? JMP(tgt) : NULL;
	}
	case C6X_INS_CALLP:
		// without its execute packet, the word after the call is the best
		// guess at where it returns to
		return c6x_lift_call(insn, pc, pc + insn->size);
	case C6X_INS_BPOS:
	case C6X_INS_BDEC: {
		// Conditional branch on the sign of the counter register in ops[1]:
		// taken when it is non-negative. BDEC additionally decrements that
		// register, but (like the branch) only when the counter was >= 0. The
		// PC-relative target is resolved off PCE1 exactly as for B.
		const C6xOperand *r = &OP(1);
		if (r->kind != C6X_OP_REG || OP(0).kind != C6X_OP_PCREL) {
			return NULL;
		}
		const char *reg = c6x_reg_name(r->v.reg.side, r->v.reg.num);
		RzILOpBitVector *tgt = U32((ut32)(c6x_packet_base(pc) + OP(0).v.imm.value));
		RzILOpEffect *taken = insn->id == C6X_INS_BDEC
			? SEQ2(c6x_reg_write(reg, SUB(c6x_reg_read(reg), U32(1))), JMP(tgt))
			: JMP(tgt);
		return BRANCH(SGE(c6x_reg_read(reg), S32(0)), taken, NOP());
	}
	case C6X_INS_ADDKPC: {
		// dst = PCE1 (the fetch-packet-aligned address) + displacement; a pure
		// address computation, no control transfer
		return c6x_wr(&OP(1), U32((ut32)(c6x_packet_base(pc) + OP(0).v.imm.value)));
	}
	case C6X_INS_DINT: {
		// TSR.SGIE (bit 1) takes TSR.GIE (bit 0); GIE is then cleared in TSR and
		// in CSR, where it is the same physical bit
		RzILOpPure *gie = SHIFTL0(LOGAND(VARG("tsr"), U32(1)), U32(1));
		return SEQ2(c6x_reg_write("tsr", LOGOR(LOGAND(VARG("tsr"), U32(~3u)), gie)),
			c6x_reg_write("csr", LOGAND(VARG("csr"), U32(~1u))));
	}
	case C6X_INS_RINT: {
		// GIE in TSR and CSR takes TSR.SGIE, which is then cleared
		RzILOpPure *sgie = LOGAND(SHIFTR0(VARG("tsr"), U32(1)), U32(1));
		return SEQ2(c6x_reg_write("csr", LOGOR(LOGAND(VARG("csr"), U32(~1u)), DUP(sgie))),
			c6x_reg_write("tsr", LOGOR(LOGAND(VARG("tsr"), U32(~3u)), sgie)));
	}
	default:
		break;
	}
	return NULL;
}

// Register, constant and control-register moves.
static RzILOpEffect *c6x_lift_move(const C6xInsn *insn, ut64 pc) {
	switch (insn->id) {
	case C6X_INS_MV: {
		RzILOpPure *s = c6x_src(&OP(0));
		return s ? c6x_wr(&OP(1), s) : NULL;
	}
	case C6X_INS_MVD: {
		// the .M-unit move; its extra latency is timing, not data flow
		RzILOpPure *s = c6x_src(&OP(0));
		return s ? c6x_wr(&OP(1), s) : NULL;
	}
	case C6X_INS_MVK: {
		// sign-extended 16-bit move (imm already extended by the decoder)
		return c6x_wr(&OP(1), S32(OP(0).v.imm.value));
	}
	case C6X_INS_MVKH: {
		// replace the top 16 bits, keep the low 16
		const C6xOperand *d = &OP(1);
		RzILOpPure *hi = U32(((ut64)(OP(0).v.imm.value & 0xffff)) << 16);
		RzILOpPure *lo = LOGAND(c6x_reg_read(c6x_reg_name(d->v.reg.side, d->v.reg.num)), U32(0xffff));
		return c6x_wr(d, LOGOR(lo, hi));
	}
	case C6X_INS_MVC: {
		// move between a control register (named by the decoder) and a general
		// register; a plain copy, so status-register side effects are not modelled
		const C6xOperand *s = &OP(0);
		const C6xOperand *d = &OP(1);
		if (s->kind == C6X_OP_CTRLREG && s->v.ctrl && RZ_STR_EQ(s->v.ctrl, "pce1")) {
			// PCE1 is the address of the fetch packet; it is the VM's program
			// counter rather than a variable, and read-only
			return c6x_wr(d, U32((ut32)c6x_packet_base(pc)));
		}
		const char *sn = s->kind == C6X_OP_CTRLREG ? s->v.ctrl : (s->kind == C6X_OP_REG ? c6x_reg_name(s->v.reg.side, s->v.reg.num) : NULL);
		const char *dn = d->kind == C6X_OP_CTRLREG ? d->v.ctrl : (d->kind == C6X_OP_REG ? c6x_reg_name(d->v.reg.side, d->v.reg.num) : NULL);
		if (dn && RZ_STR_EQ(dn, "pce1")) {
			return NULL;
		}
		return sn && dn ? c6x_reg_write(dn, c6x_reg_read(sn)) : NULL;
	}
	default:
		break;
	}
	return NULL;
}

// The C66x double-word AND, ANDN, OR and XOR: the operation on each register
// of the pairs, a scst5 src1 applying to both.
static RzILOpEffect *c6x_dw_logic(const C6xInsn *insn) {
	RzILOpBitVector *r[2] = { NULL, NULL };
	for (ut8 i = 0; i < 2; i++) {
		RzILOpPure *a = c6x_dw_lane(&OP(0), i);
		RzILOpPure *b = c6x_dw_lane(&OP(1), i);
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			rz_il_op_pure_free(r[0]);
			return NULL;
		}
		switch (insn->id) {
		case C6X_INS_AND: r[i] = LOGAND(a, b); break;
		case C6X_INS_ANDN: r[i] = LOGAND(a, LOGNOT(b)); break;
		case C6X_INS_OR: r[i] = LOGOR(a, b); break;
		default: r[i] = LOGXOR(a, b); break;
		}
	}
	return c6x_wr_dual(&OP(2), r[1], r[0]);
}

// Integer add/subtract, bitwise and compare.
static RzILOpEffect *c6x_lift_alu(const C6xInsn *insn, ut64 pc) {
	bool logic = insn->id == C6X_INS_AND || insn->id == C6X_INS_ANDN || insn->id == C6X_INS_OR || insn->id == C6X_INS_XOR;
	if (logic && insn->nops == 3 && OP(2).kind == C6X_OP_REGPAIR) {
		return c6x_dw_logic(insn);
	}
	switch (insn->id) {
	case C6X_INS_ADD:
	case C6X_INS_ADDU: {
		return c6x_alu3(insn, rz_il_op_new_add);
	}
	case C6X_INS_SUB:
	case C6X_INS_SUBU: {
		return c6x_alu3(insn, rz_il_op_new_sub);
	}
	case C6X_INS_AND: {
		return c6x_alu3(insn, rz_il_op_new_log_and);
	}
	case C6X_INS_ANDN: {
		// dst = src1 & ~src2, as SPRUFE8B's example and cl6x's code for a & ~b have it
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		return c6x_wr(&OP(2), LOGAND(s1, LOGNOT(s2)));
	}
	case C6X_INS_OR: {
		return c6x_alu3(insn, rz_il_op_new_log_or);
	}
	case C6X_INS_XOR: {
		return c6x_alu3(insn, rz_il_op_new_log_xor);
	}
	case C6X_INS_CMPEQ: {
		return c6x_cmp(insn, rz_il_op_new_eq);
	}
	case C6X_INS_CMPGT: {
		return c6x_cmp(insn, rz_il_op_new_sgt);
	}
	case C6X_INS_CMPGTU: {
		return c6x_cmp(insn, rz_il_op_new_ugt);
	}
	case C6X_INS_CMPLT: {
		return c6x_cmp(insn, rz_il_op_new_slt);
	}
	case C6X_INS_CMPLTU: {
		return c6x_cmp(insn, rz_il_op_new_ult);
	}
	case C6X_INS_CMPEQ2: {
		return c6x_cmp_packed(insn, 2, rz_il_op_new_eq);
	}
	case C6X_INS_CMPGT2: {
		return c6x_cmp_packed(insn, 2, rz_il_op_new_sgt);
	}
	case C6X_INS_CMPEQ4: {
		return c6x_cmp_packed(insn, 4, rz_il_op_new_eq);
	}
	case C6X_INS_CMPGTU4: {
		return c6x_cmp_packed(insn, 4, rz_il_op_new_ugt);
	}
	default:
		break;
	}
	return NULL;
}

// Unary, saturation, field and bit-manipulation forms.
static RzILOpEffect *c6x_lift_bitop(const C6xInsn *insn, ut64 pc) {
	switch (insn->id) {
	case C6X_INS_ZERO: {
		// clear a register or a register pair
		const C6xOperand *d = &OP(0);
		if (d->kind == C6X_OP_REG) {
			return c6x_reg_write(c6x_reg_name(d->v.reg.side, d->v.reg.num), U32(0));
		}
		if (d->kind == C6X_OP_REGPAIR) {
			return SEQ2(c6x_reg_write(c6x_reg_name(d->v.reg.side, d->v.reg.num), U32(0)),
				c6x_reg_write(c6x_reg_name(d->v.reg.side, d->v.reg.num + 1), U32(0)));
		}
		return NULL;
	}
	case C6X_INS_NEG: {
		if (OP(0).kind == C6X_OP_REGPAIR) {
			RzILOpBitVector *v = c6x_long40(&OP(0));
			return v ? c6x_wr_long40(&OP(1), NEG(v)) : NULL;
		}
		RzILOpPure *s = c6x_src(&OP(0));
		return s ? c6x_wr(&OP(1), NEG(s)) : NULL;
	}
	case C6X_INS_NOT: {
		RzILOpPure *s = c6x_src(&OP(0));
		return s ? c6x_wr(&OP(1), LOGNOT(s)) : NULL;
	}
	case C6X_INS_ABS: {
		// dst = |src|, saturating INT_MIN (0x80000000) to INT_MAX (0x7fffffff).
		// The 40-bit long form saturates -2^39 to 2^39-1 over a register pair.
		if (OP(0).kind == C6X_OP_REGPAIR) {
			RzILOpBitVector *v = c6x_long40(&OP(0));
			if (!v) {
				return NULL;
			}
			return c6x_wr_pair64(&OP(1),
				LET("_a", v,
					ITE(SGE(VARLP("_a"), SN(64, 0)), VARLP("_a"),
						ITE(EQ(VARLP("_a"), SN(64, -0x8000000000LL)), SN(64, 0x7fffffffffLL), NEG(VARLP("_a"))))));
		}
		RzILOpPure *s = c6x_src(&OP(0));
		if (!s) {
			return NULL;
		}
		return c6x_wr(&OP(1), LET("_a", s, ITE(SGE(VARLP("_a"), S32(0)), VARLP("_a"), ITE(EQ(VARLP("_a"), U32(0x80000000)), U32(0x7fffffff), NEG(VARLP("_a"))))));
	}
	case C6X_INS_SAT: {
		// saturate a 40-bit long in a register pair to a signed 32-bit int
		RzILOpBitVector *v = c6x_long40(&OP(0));
		if (!v) {
			return NULL;
		}
		return c6x_wr(&OP(1), c6x_sats32(v));
	}
	case C6X_INS_ABSSP: {
		// single-precision float abs: clear the sign bit
		RzILOpPure *s = c6x_src(&OP(0));
		if (!s) {
			return NULL;
		}
		return c6x_wr(&OP(1), LOGAND(s, U32(0x7fffffff)));
	}
	case C6X_INS_ABSDP: {
		// double-precision float abs: clear the sign bit of the 64-bit pair
		RzILOpBitVector *s = c6x_pair64(&OP(0));
		if (!s) {
			return NULL;
		}
		return c6x_wr_pair64(&OP(1), LOGAND(s, SN(64, 0x7fffffffffffffffLL)));
	}
	case C6X_INS_ABS2: {
		// per-halfword absolute value with 0x8000 -> 0x7fff saturation
		RzILOpPure *slo = c6x_src(&OP(0));
		RzILOpPure *shi = c6x_src(&OP(0));
		if (!slo || !shi) {
			rz_il_op_pure_free(slo);
			rz_il_op_pure_free(shi);
			return NULL;
		}
		RzILOpBitVector *lo = c6x_abs16(UNSIGNED(16, slo));
		RzILOpBitVector *hi = c6x_abs16(UNSIGNED(16, SHIFTR0(shi, U32(16))));
		return c6x_wr(&OP(1), APPEND(hi, lo));
	}
	case C6X_INS_EXTU:
	case C6X_INS_EXT: {
		// field extract: dst = (src << csta) >> cstb, right shift logical for
		// extu and arithmetic (sign-extending) for ext
		if (insn->nops == 3) {
			// register form: csta in src1[9:5], cstb in src1[4:0]
			RzILOpPure *s = c6x_src(&OP(0));
			RzILOpPure *f = c6x_src(&OP(1));
			if (!s || !f) {
				rz_il_op_pure_free(s);
				rz_il_op_pure_free(f);
				return NULL;
			}
			RzILOpPure *shl = SHIFTL0(s, LOGAND(SHIFTR0(VARLP("_f"), U32(5)), U32(0x1f)));
			RzILOpPure *n = LOGAND(VARLP("_f"), U32(0x1f));
			return c6x_wr(&OP(2), LET("_f", f, insn->id == C6X_INS_EXTU ? SHIFTR0(shl, n) : SHIFTRA(shl, n)));
		}
		if (OP(1).kind != C6X_OP_IMM || OP(2).kind != C6X_OP_IMM) {
			return NULL;
		}
		RzILOpPure *s = c6x_src(&OP(0));
		if (!s) {
			return NULL;
		}
		RzILOpPure *shl = SHIFTL0(s, U32((ut32)OP(1).v.imm.value));
		RzILOpPure *v = insn->id == C6X_INS_EXTU
			? SHIFTR0(shl, U32((ut32)OP(2).v.imm.value))
			: SHIFTRA(shl, U32((ut32)OP(2).v.imm.value));
		return c6x_wr(&OP(3), v);
	}
	case C6X_INS_SET:
	case C6X_INS_CLR: {
		// bit field set/clear: dst = src2 set/cleared over bits [csta, cstb];
		// for cstb < csta src2 is copied
		bool set = insn->id == C6X_INS_SET;
		if (insn->nops == 3) {
			// register form: csta in src1[9:5], cstb in src1[4:0]
			RzILOpPure *s = c6x_src(&OP(0));
			RzILOpPure *f = c6x_src(&OP(1));
			if (!s || !f) {
				rz_il_op_pure_free(s);
				rz_il_op_pure_free(f);
				return NULL;
			}
			// the field cstb - csta + 1 bits wide, shifted to csta
			RzILOpPure *mask = SHIFTL0(SHIFTR0(U32(0xffffffff), SUB(U32(31), SUB(VARLP("_cb"), VARLP("_ca")))), VARLP("_ca"));
			RzILOpPure *v = set ? LOGOR(VARLP("_s"), mask) : LOGAND(VARLP("_s"), LOGNOT(mask));
			return c6x_wr(&OP(2), LET("_s", s, LET("_f", f, LET("_ca", LOGAND(SHIFTR0(VARLP("_f"), U32(5)), U32(0x1f)), LET("_cb", LOGAND(VARLP("_f"), U32(0x1f)), ITE(UGE(VARLP("_cb"), VARLP("_ca")), v, VARLP("_s")))))));
		}
		if (OP(1).kind != C6X_OP_IMM || OP(2).kind != C6X_OP_IMM) {
			return NULL;
		}
		ut32 csta = (ut32)OP(1).v.imm.value & 0x1f;
		ut32 cstb = (ut32)OP(2).v.imm.value & 0x1f;
		if (cstb < csta) {
			RzILOpPure *s = c6x_src(&OP(0));
			return s ? c6x_wr(&OP(3), s) : NULL;
		}
		ut32 width = cstb - csta + 1;
		ut32 mask = width >= 32 ? 0xffffffff : (((ut32)1 << width) - 1) << csta;
		RzILOpPure *s = c6x_src(&OP(0));
		if (!s) {
			return NULL;
		}
		RzILOpPure *v = set ? LOGOR(s, U32(mask)) : LOGAND(s, U32(~mask));
		return c6x_wr(&OP(3), v);
	}
	case C6X_INS_LMBD: {
		// leftmost bit detection: src1[0] selects whether to find the leftmost 1
		// (count leading zeros of src2) or the leftmost 0 (count leading zeros of
		// its complement); dst is that count.
		RzILOpPure *src1 = c6x_src(&OP(0));
		RzILOpPure *src2 = c6x_src(&OP(1));
		if (!src1 || !src2) {
			rz_il_op_pure_free(src1);
			rz_il_op_pure_free(src2);
			return NULL;
		}
		RzILOpPure *arg = LET("_lm", src2,
			ITE(IS_ZERO(LOGAND(src1, U32(1))), LOGNOT(VARLP("_lm")), VARLP("_lm")));
		return SEQ2(c6x_clz_into("_n", arg, 32), c6x_wr(&OP(2), VARL("_n")));
	}
	case C6X_INS_NORM: {
		// redundant sign bits: clz(src2 ^ (src2 >>a 31)) - 1. XOR by the sign turns
		// the leading run of sign bits into leading zeros; subtract the sign bit.
		// The 40-bit long form uses the sign-extended value and a 64-bit count.
		if (OP(0).kind == C6X_OP_REGPAIR) {
			RzILOpBitVector *v = c6x_long40(&OP(0));
			if (!v) {
				return NULL;
			}
			RzILOpPure *arg = LET("_nl", v, LOGXOR(VARLP("_nl"), SHIFTRA(VARLP("_nl"), U32(63))));
			return SEQ2(c6x_clz_into("_n", arg, 64), c6x_wr(&OP(1), SUB(VARL("_n"), U32(25))));
		}
		RzILOpPure *src = c6x_src(&OP(0));
		if (!src) {
			return NULL;
		}
		RzILOpPure *arg = LET("_nm", src, LOGXOR(VARLP("_nm"), SHIFTRA(VARLP("_nm"), U32(31))));
		return SEQ2(c6x_clz_into("_n", arg, 32), c6x_wr(&OP(1), SUB(VARL("_n"), U32(1))));
	}
	case C6X_INS_DEAL: {
		// dst = src2 deinterleaved: even bits to the low halfword, odd to the high
		RzILOpPure *s = c6x_src(&OP(0));
		if (!s) {
			return NULL;
		}
		return c6x_wr(&OP(1), rz_il_deinterleave32(s));
	}
	case C6X_INS_SHFL: {
		// dst = src2 interleaved: low halfword to even bits, high to odd
		RzILOpPure *s = c6x_src(&OP(0));
		if (!s) {
			return NULL;
		}
		return c6x_wr(&OP(1), rz_il_interleave32(s));
	}
	case C6X_INS_BITR: {
		// dst = src2 with its 32 bits reversed
		RzILOpPure *s = c6x_src(&OP(0));
		if (!s) {
			return NULL;
		}
		return c6x_wr(&OP(1), rz_il_bitrev32(s));
	}
	case C6X_INS_BITC4: {
		// dst = per-byte population count of src2
		RzILOpPure *s = c6x_src(&OP(0));
		if (!s) {
			return NULL;
		}
		return c6x_wr(&OP(1), rz_il_popcount_bytes32(s));
	}
	case C6X_INS_XPND2: {
		// expand src2[1:0] into two halfword masks: bit 0 fills the lower
		// halfword, bit 1 the upper, each 0x0000 or 0xffff
		RzILOpPure *s = c6x_src(&OP(0));
		if (!s) {
			return NULL;
		}
		RzILOpPure *v = LET("_x", s,
			LOGOR(SHIFTL0(MUL(LOGAND(SHIFTR0(VARLP("_x"), U32(1)), U32(1)), U32(0xffff)), U32(16)),
				MUL(LOGAND(VARLP("_x"), U32(1)), U32(0xffff))));
		return c6x_wr(&OP(1), v);
	}
	case C6X_INS_XPND4: {
		// expand src2[3:0] into four byte masks, each 0x00 or 0xff
		RzILOpPure *s = c6x_src(&OP(0));
		if (!s) {
			return NULL;
		}
		RzILOpPure *v = LET("_x",
			s,
			LOGOR(LOGOR(SHIFTL0(MUL(LOGAND(SHIFTR0(VARLP("_x"), U32(3)), U32(1)), U32(0xff)), U32(24)),
				      SHIFTL0(MUL(LOGAND(SHIFTR0(VARLP("_x"), U32(2)), U32(1)), U32(0xff)), U32(16))),
				LOGOR(SHIFTL0(MUL(LOGAND(SHIFTR0(VARLP("_x"), U32(1)), U32(1)), U32(0xff)), U32(8)),
					MUL(LOGAND(VARLP("_x"), U32(1)), U32(0xff)))));
		return c6x_wr(&OP(1), v);
	}
	default:
		break;
	}
	return NULL;
}

// Packed arithmetic, averaging, saturating shifts and address arithmetic.
static RzILOpEffect *c6x_lift_packed(const C6xInsn *insn, ut64 pc) {
	switch (insn->id) {
	case C6X_INS_SUBC: {
		// subtract-conditional divide step: dst = ((src1 - src2) << 1) | 1 when
		// src1 - src2 >= 0, else src1 << 1. Both operands are uint, so the
		// difference is not negative when src1 >= src2 unsigned, though its 32
		// bits read as a negative int when the operands are 2^31 or more apart.
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpPure *v = LET("_s1", s1,
			LET("_s2", s2,
				ITE(UGE(VARLP("_s1"), VARLP("_s2")),
					LOGOR(SHIFTL0(SUB(VARLP("_s1"), VARLP("_s2")), U32(1)), U32(1)),
					SHIFTL0(VARLP("_s1"), U32(1)))));
		return c6x_wr(&OP(2), v);
	}
	case C6X_INS_RPACK2: {
		// shift src1 and src2 left by 1 with saturation, then pack their 16 MSBs
		// into the upper and lower halfword of dst
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpPure *hi = SHIFTR0(c6x_sats32(SHIFTL0(SIGNED(64, s1), U32(1))), U32(16));
		RzILOpPure *lo = SHIFTR0(c6x_sats32(SHIFTL0(SIGNED(64, s2), U32(1))), U32(16));
		return c6x_wr(&OP(2), LOGOR(SHIFTL0(LOGAND(hi, U32(0xffff)), U32(16)), LOGAND(lo, U32(0xffff))));
	}
	case C6X_INS_AVG2: {
		// signed packed 16-bit rounding average: (a + b + 1) >>a 1 per halfword
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpPure *v = LET("_a", s1,
			LET("_b", s2,
				LOGOR(SHIFTL0(LOGAND(SHIFTRA(ADD(ADD(c6x_high16s(VARLP("_a")), c6x_high16s(VARLP("_b"))), U32(1)), U32(1)), U32(0xffff)), U32(16)),
					LOGAND(SHIFTRA(ADD(ADD(c6x_low16s(VARLP("_a")), c6x_low16s(VARLP("_b"))), U32(1)), U32(1)), U32(0xffff)))));
		return c6x_wr(&OP(2), v);
	}
	case C6X_INS_AVGU4: {
		// unsigned packed 8-bit rounding average: (a + b + 1) >> 1 per byte
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
#define AVGU4_BYTE(sh) \
	SHIFTL0(LOGAND(SHIFTR0(ADD(ADD(LOGAND(SHIFTR0(VARLP("_a"), U32(sh)), U32(0xff)), LOGAND(SHIFTR0(VARLP("_b"), U32(sh)), U32(0xff))), U32(1)), U32(1)), U32(0xff)), U32(sh))
		RzILOpPure *v = LET("_a", s1,
			LET("_b", s2,
				LOGOR(LOGOR(AVGU4_BYTE(24), AVGU4_BYTE(16)), LOGOR(AVGU4_BYTE(8), AVGU4_BYTE(0)))));
#undef AVGU4_BYTE
		return c6x_wr(&OP(2), v);
	}
	case C6X_INS_SADDU4: {
		// packed 8-bit unsigned saturating add: min(a + b, 255) per byte
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
#define SADDU4_SUM(sh)  ADD(LOGAND(SHIFTR0(VARLP("_a"), U32(sh)), U32(0xff)), LOGAND(SHIFTR0(VARLP("_b"), U32(sh)), U32(0xff)))
#define SADDU4_BYTE(sh) SHIFTL0(ITE(UGT(SADDU4_SUM(sh), U32(0xff)), U32(0xff), SADDU4_SUM(sh)), U32(sh))
		RzILOpPure *v = LET("_a", s1,
			LET("_b", s2,
				LOGOR(LOGOR(SADDU4_BYTE(24), SADDU4_BYTE(16)), LOGOR(SADDU4_BYTE(8), SADDU4_BYTE(0)))));
#undef SADDU4_BYTE
#undef SADDU4_SUM
		return c6x_wr(&OP(2), v);
	}
	case C6X_INS_SADDUS2: {
		// per halfword: clamp(u16(src1) + s16(src2), 0, 65535); src1 unsigned,
		// src2 signed
		RzILOpPure *a_lo = c6x_src(&OP(0));
		RzILOpPure *b_lo = c6x_src(&OP(1));
		RzILOpPure *a_hi = c6x_src(&OP(0));
		RzILOpPure *b_hi = c6x_src(&OP(1));
		if (!a_lo || !b_lo || !a_hi || !b_hi) {
			rz_il_op_pure_free(a_lo);
			rz_il_op_pure_free(b_lo);
			rz_il_op_pure_free(a_hi);
			rz_il_op_pure_free(b_hi);
			return NULL;
		}
		RzILOpPure *lo = LET("_lo", ADD(LOGAND(a_lo, U32(0xffff)), c6x_low16s(b_lo)),
			ITE(SLT(VARLP("_lo"), S32(0)), U32(0), ITE(SGT(VARLP("_lo"), S32(0xffff)), U32(0xffff), VARLP("_lo"))));
		RzILOpPure *hi = LET("_hi", ADD(LOGAND(SHIFTR0(a_hi, U32(16)), U32(0xffff)), c6x_high16s(b_hi)),
			ITE(SLT(VARLP("_hi"), S32(0)), U32(0), ITE(SGT(VARLP("_hi"), S32(0xffff)), U32(0xffff), VARLP("_hi"))));
		return c6x_wr(&OP(2), LOGOR(SHIFTL0(hi, U32(16)), lo));
	}
	case C6X_INS_SSHVL:
	case C6X_INS_SSHVR: {
		// variable shift of src2 by src1, clamped to [-31, 31]. SSHVL shifts left
		// for a positive count (saturating) and arithmetic-right for a negative
		// one; SSHVR is the mirror. src2 is ops[0], the count src1 is ops[1].
		bool left = insn->id == C6X_INS_SSHVL;
		RzILOpPure *v = c6x_src(&OP(0));
		RzILOpPure *s = c6x_src(&OP(1));
		if (!v || !s) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(s);
			return NULL;
		}
		// n >= 0 and n < 0 halves; the shift-left half saturates to 32 bits
		RzILOpPure *pos = left
			? c6x_sats32(SHIFTL0(SIGNED(64, VARLP("_v")), VARLP("_n")))
			: SHIFTRA(VARLP("_v"), VARLP("_n"));
		RzILOpPure *neg = left
			? SHIFTRA(VARLP("_v"), NEG(VARLP("_n")))
			: c6x_sats32(SHIFTL0(SIGNED(64, VARLP("_v")), NEG(VARLP("_n"))));
		return c6x_wr(&OP(2),
			LET("_v", v,
				LET("_sc", s,
					LET("_n", ITE(SGT(VARLP("_sc"), S32(31)), S32(31), ITE(SLT(VARLP("_sc"), S32(-31)), S32(-31), VARLP("_sc"))),
						ITE(SGE(VARLP("_n"), S32(0)), pos, neg)))));
	}
	case C6X_INS_ADDK: {
		// dst += sign-extended 16-bit constant (dst is also src)
		const C6xOperand *d = &OP(1);
		return c6x_wr(d, ADD(c6x_reg_read(c6x_reg_name(d->v.reg.side, d->v.reg.num)), S32(OP(0).v.imm.value)));
	}
	case C6X_INS_SHL: {
		// only the six LSBs of a register count shift (SPRUFE8B SHL)
		RzILOpPure *n = c6x_src(&OP(1));
		if (n && OP(1).kind == C6X_OP_REG) {
			n = LOGAND(n, U32(0x3f));
		}
		if (OP(2).kind == C6X_OP_REGPAIR) {
			// a 40-bit long, or a zero-extended 32-bit value, shifted left by
			// src1 and truncated back to 40 bits
			bool lng = OP(0).kind == C6X_OP_REGPAIR;
			RzILOpBitVector *v = lng ? c6x_long40(&OP(0)) : c6x_src(&OP(0));
			if (!v || !n) {
				rz_il_op_pure_free(v);
				rz_il_op_pure_free(n);
				return NULL;
			}
			return c6x_wr_pair64(&OP(2), LOGAND(SHIFTL0(lng ? v : UNSIGNED(64, v), n), SN(64, 0xffffffffffLL)));
		}
		RzILOpPure *v = c6x_src(&OP(0));
		if (!v || !n) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(n);
			return NULL;
		}
		return c6x_wr(&OP(2), SHIFTL0(v, n));
	}
	case C6X_INS_SHR:
	case C6X_INS_SHRU: {
		// shr is arithmetic (sign-propagating); shru is logical
		bool lng = OP(0).kind == C6X_OP_REGPAIR;
		RzILOpPure *v = lng ? c6x_long_src(&OP(0), insn->id == C6X_INS_SHR) : c6x_src(&OP(0));
		RzILOpPure *n = c6x_src(&OP(1));
		if (n && OP(1).kind == C6X_OP_REG) {
			n = LOGAND(n, U32(0x3f)); // the six LSBs of a register count
		}
		if (!v || !n) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(n);
			return NULL;
		}
		RzILOpPure *r = insn->id == C6X_INS_SHRU ? SHIFTR0(v, n) : SHIFTRA(v, n);
		return lng ? c6x_wr_long40(&OP(2), r) : c6x_wr(&OP(2), r);
	}
	case C6X_INS_ADDAB: {
		return c6x_addr(insn, false, 0);
	}
	case C6X_INS_ADDAH: {
		return c6x_addr(insn, false, 1);
	}
	case C6X_INS_ADDAW: {
		return c6x_addr(insn, false, 2);
	}
	case C6X_INS_ADDAD: {
		return c6x_addr(insn, false, 3);
	}
	case C6X_INS_SUBAB: {
		return c6x_addr(insn, true, 0);
	}
	case C6X_INS_SUBAH: {
		return c6x_addr(insn, true, 1);
	}
	case C6X_INS_SUBAW: {
		return c6x_addr(insn, true, 2);
	}
	case C6X_INS_SADD:
	case C6X_INS_SSUB: {
		// signed add/subtract saturating to the 32-bit range, or to the 40-bit
		// range for the long forms (src1 - src2 for ssub, matching the SUB
		// operand order)
		bool lng = c6x_has_pair(insn);
		RzILOpBitVector *w1 = c6x_long_src(&OP(0), true);
		RzILOpBitVector *w2 = c6x_long_src(&OP(1), true);
		if (!w1 || !w2) {
			rz_il_op_pure_free(w1);
			rz_il_op_pure_free(w2);
			return NULL;
		}
		RzILOpBitVector *r = insn->id == C6X_INS_SSUB ? SUB(w1, w2) : ADD(w1, w2);
		if (lng) {
			return c6x_wr_long40(&OP(2),
				LET("_s", r,
					ITE(SGT(VARLP("_s"), SN(64, 0x7fffffffffLL)), SN(64, 0x7fffffffffLL),
						ITE(SLT(VARLP("_s"), SN(64, -0x8000000000LL)), SN(64, -0x8000000000LL), VARLP("_s")))));
		}
		return c6x_wr(&OP(2), c6x_sats32(r));
	}
	case C6X_INS_SSHL: {
		// dst = saturate32(src2 << (src1 & 0x1f)); the shift is done in 64 bits
		// so an overflow past bit 31 saturates instead of being dropped
		RzILOpPure *v = c6x_src(&OP(0));
		RzILOpPure *n = c6x_src(&OP(1));
		if (!v || !n) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(n);
			return NULL;
		}
		return c6x_wr(&OP(2), c6x_sats32(SHIFTL0(SIGNED(64, v), LOGAND(n, U32(0x1f)))));
	}
	case C6X_INS_ROTL: {
		// rotate src2 left by src1[4:0]: (v << n) | (v >>u (32 - n)); both forms
		// decode src2 (the value) into ops[0] and src1 (the count) into ops[1]
		RzILOpPure *v = c6x_src(&OP(0));
		RzILOpPure *cnt = c6x_src(&OP(1));
		if (!v || !cnt) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(cnt);
			return NULL;
		}
		return c6x_wr(&OP(2),
			LET("_rv", v, LET("_rn", LOGAND(cnt, U32(0x1f)), LOGOR(SHIFTL0(VARLP("_rv"), VARLP("_rn")), SHIFTR0(VARLP("_rv"), SUB(U32(32), VARLP("_rn")))))));
	}
	case C6X_INS_SHLMB:
	case C6X_INS_SHRMB: {
		// shift src2 by one byte and merge the adjacent byte of src1 into the
		// vacated end: left brings src1's msb into the lsb, right the reverse
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpBitVector *v = insn->id == C6X_INS_SHLMB
			? LOGOR(SHIFTL0(s2, U32(8)), LOGAND(SHIFTR0(s1, U32(24)), U32(0xff)))
			: LOGOR(SHIFTR0(s2, U32(8)), SHIFTL0(LOGAND(s1, U32(0xff)), U32(24)));
		return c6x_wr(&OP(2), v);
	}
	case C6X_INS_SHR2:
	case C6X_INS_SHRU2: {
		// per-halfword shift right by src1[4:0], arithmetic for shr2 and logical
		// (zero-extended) for shru2, lanes independent; counts of 16 to 31 fill
		// each lane with its sign or with zeros
		RzILOpPure *v = c6x_src(&OP(0));
		RzILOpPure *cnt = c6x_src(&OP(1));
		if (!v || !cnt) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(cnt);
			return NULL;
		}
		bool ar = insn->id == C6X_INS_SHR2;
		return c6x_wr(&OP(2),
			LET("_sv", v, LET("_sn", UNSIGNED(16, LOGAND(cnt, U32(0x1f))), APPEND(ar ? SHIFTRA(UNSIGNED(16, SHIFTR0(VARLP("_sv"), U32(16))), VARLP("_sn")) : SHIFTR0(UNSIGNED(16, SHIFTR0(VARLP("_sv"), U32(16))), VARLP("_sn")), ar ? SHIFTRA(UNSIGNED(16, VARLP("_sv")), VARLP("_sn")) : SHIFTR0(UNSIGNED(16, VARLP("_sv")), VARLP("_sn"))))));
	}
	case C6X_INS_SWAP4: {
		// exchange the two bytes within each halfword
		RzILOpPure *v = c6x_src(&OP(0));
		if (!v) {
			return NULL;
		}
		return c6x_wr(&OP(1),
			LET("_w4", v,
				LOGOR(SHIFTL0(LOGAND(VARLP("_w4"), U32(0x00ff00ff)), U32(8)),
					LOGAND(SHIFTR0(VARLP("_w4"), U32(8)), U32(0x00ff00ff)))));
	}
	case C6X_INS_PACKL4:
	case C6X_INS_PACKH4: {
		// gather one byte from each of the four halfwords of src1:src2 -- the low
		// byte of each for packl4, the high byte for packh4 -- src1 to the top
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		ut32 sh = insn->id == C6X_INS_PACKH4 ? 8 : 0; // byte offset within each halfword
		return c6x_wr(&OP(2),
			LET("_q1", s1, LET("_q2", s2, LOGOR(LOGOR(SHIFTL0(LOGAND(SHIFTR0(VARLP("_q1"), U32(16 + sh)), U32(0xff)), U32(24)), SHIFTL0(LOGAND(SHIFTR0(VARLP("_q1"), U32(sh)), U32(0xff)), U32(16))), LOGOR(SHIFTL0(LOGAND(SHIFTR0(VARLP("_q2"), U32(16 + sh)), U32(0xff)), U32(8)), LOGAND(SHIFTR0(VARLP("_q2"), U32(sh)), U32(0xff)))))));
	}
	default:
		break;
	}
	return NULL;
}

// The plain multiply family.
static RzILOpEffect *c6x_lift_mpy(const C6xInsn *insn, ut64 pc) {
	switch (insn->id) {
	case C6X_INS_MPY: {
		return c6x_mpy16(insn, false, true, false, true);
	}
	case C6X_INS_MPYH: {
		return c6x_mpy16(insn, true, true, true, true);
	}
	case C6X_INS_MPYHL: {
		return c6x_mpy16(insn, true, true, false, true);
	}
	case C6X_INS_MPYLH: {
		return c6x_mpy16(insn, false, true, true, true);
	}
	case C6X_INS_MPYU: {
		return c6x_mpy16(insn, false, false, false, false);
	}
	case C6X_INS_MPYUS: {
		return c6x_mpy16(insn, false, false, false, true);
	}
	case C6X_INS_MPYSU: {
		return c6x_mpy16(insn, false, true, false, false);
	}
	case C6X_INS_MPYHU: {
		return c6x_mpy16(insn, true, false, true, false);
	}
	case C6X_INS_MPYHUS: {
		return c6x_mpy16(insn, true, false, true, true);
	}
	case C6X_INS_MPYHSU: {
		return c6x_mpy16(insn, true, true, true, false);
	}
	case C6X_INS_MPYLHU: {
		return c6x_mpy16(insn, false, false, true, false);
	}
	case C6X_INS_MPYHLU: {
		return c6x_mpy16(insn, true, false, false, false);
	}
	case C6X_INS_MPYLUHS: {
		return c6x_mpy16(insn, false, false, true, true);
	}
	case C6X_INS_MPYHULS: {
		return c6x_mpy16(insn, true, false, false, true);
	}
	case C6X_INS_MPYLSHU: {
		return c6x_mpy16(insn, false, true, true, false);
	}
	case C6X_INS_MPYHSLU: {
		return c6x_mpy16(insn, true, true, false, false);
	}
	case C6X_INS_SMPY: {
		return c6x_smpy(insn, false, false);
	}
	case C6X_INS_SMPYH: {
		return c6x_smpy(insn, true, true);
	}
	case C6X_INS_SMPYHL: {
		return c6x_smpy(insn, true, false);
	}
	case C6X_INS_SMPYLH: {
		return c6x_smpy(insn, false, true);
	}
	case C6X_INS_MPYI:
	case C6X_INS_MPYID:
	case C6X_INS_MPY32: {
		return c6x_mpy32(insn, true, true);
	}
	case C6X_INS_MPY32U: {
		return c6x_mpy32(insn, false, false);
	}
	case C6X_INS_MPY32SU: {
		return c6x_mpy32(insn, true, false);
	}
	case C6X_INS_MPY32US: {
		return c6x_mpy32(insn, false, true);
	}
	default:
		break;
	}
	return NULL;
}

// Packed add/subtract and pack/unpack.
static RzILOpEffect *c6x_lift_pack(const C6xInsn *insn, ut64 pc) {
	switch (insn->id) {
	case C6X_INS_ADD2: {
		return c6x_packed(insn, 2, false);
	}
	case C6X_INS_SUB2: {
		return c6x_packed(insn, 2, true);
	}
	case C6X_INS_ADD4: {
		return c6x_packed(insn, 4, false);
	}
	case C6X_INS_SUB4: {
		return c6x_packed(insn, 4, true);
	}
	case C6X_INS_PACK2: {
		return c6x_pack(insn, false, false); // low(src1):low(src2)
	}
	case C6X_INS_PACKH2: {
		return c6x_pack(insn, true, true); // high(src1):high(src2)
	}
	case C6X_INS_PACKLH2: {
		return c6x_pack(insn, false, true); // low(src1):high(src2)
	}
	case C6X_INS_PACKHL2: {
		return c6x_pack(insn, true, false); // high(src1):low(src2)
	}
	case C6X_INS_UNPKLU4: {
		return c6x_unpku4(insn, false);
	}
	case C6X_INS_UNPKHU4: {
		return c6x_unpku4(insn, true);
	}
	case C6X_INS_SADD2: {
		return c6x_sat_packed(insn, 2, false);
	}
	case C6X_INS_SSUB2: {
		return c6x_sat_packed(insn, 2, true);
	}
	case C6X_INS_SPACK2: {
		// saturate two 32-bit signed sources to signed 16 bits and pack
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		return c6x_wr(&OP(2), APPEND(c6x_sat_s(s1, 16), c6x_sat_s(s2, 16)));
	}
	default:
		break;
	}
	return NULL;
}

// Complex multiply, dot products and the SIMD multiplies.
static RzILOpEffect *c6x_lift_dotp(const C6xInsn *insn, ut64 pc) {
	switch (insn->id) {
	case C6X_INS_MPY2:
	case C6X_INS_SMPY2: {
		// two signed 16x16 products into a register pair: even reg = lsb*lsb,
		// odd reg = msb*msb. SMPY2 additionally shifts each product left by 1
		// with saturation.
		bool sat = insn->id == C6X_INS_SMPY2;
		RzILOpPure *a_lo = c6x_src(&OP(0));
		RzILOpPure *b_lo = c6x_src(&OP(1));
		RzILOpPure *a_hi = c6x_src(&OP(0));
		RzILOpPure *b_hi = c6x_src(&OP(1));
		if (!a_lo || !b_lo || !a_hi || !b_hi) {
			rz_il_op_pure_free(a_lo);
			rz_il_op_pure_free(b_lo);
			rz_il_op_pure_free(a_hi);
			rz_il_op_pure_free(b_hi);
			return NULL;
		}
		RzILOpBitVector *lo = MUL(c6x_low16s(a_lo), c6x_low16s(b_lo));
		RzILOpBitVector *hi = MUL(c6x_high16s(a_hi), c6x_high16s(b_hi));
		if (sat) {
			lo = c6x_sats32(SHIFTL0(SIGNED(64, lo), U32(1)));
			hi = c6x_sats32(SHIFTL0(SIGNED(64, hi), U32(1)));
		}
		return c6x_wr_pair64(&OP(2), APPEND(hi, lo));
	}
	case C6X_INS_MPYHI:
	case C6X_INS_MPYLI: {
		// signed 16x32 multiply into a register pair (the 48-bit product,
		// sign-extended): MPYHI uses src1's msb16, MPYLI its lsb16
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpPure *h = insn->id == C6X_INS_MPYHI ? c6x_high16s(s1) : c6x_low16s(s1);
		return c6x_wr_pair64(&OP(2), MUL(SIGNED(64, h), SIGNED(64, s2)));
	}
	case C6X_INS_MPYHIR:
	case C6X_INS_MPYLIR: {
		// signed 16x32 multiply, rounded: (h16(src1) * src2 + 0x4000) >> 15
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpPure *h = insn->id == C6X_INS_MPYHIR ? c6x_high16s(s1) : c6x_low16s(s1);
		RzILOpBitVector *prod = ADD(MUL(SIGNED(64, h), SIGNED(64, s2)), SN(64, 0x4000));
		return c6x_wr(&OP(2), UNSIGNED(32, SHIFTRA(prod, U32(15))));
	}
	case C6X_INS_SPACKU4: {
		// saturate four signed 16-bit values to unsigned bytes and pack them:
		// {satu8(src1_h), satu8(src1_l), satu8(src2_h), satu8(src2_l)}
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
#define CLAMP8(vn) ITE(SLT(VARLP(vn), S32(0)), U32(0), ITE(SGT(VARLP(vn), S32(0xff)), U32(0xff), VARLP(vn)))
		RzILOpPure *v = LET("_a", s1,
			LET("_b", s2,
				LET("_h3", c6x_high16s(VARLP("_a")),
					LET("_h2", c6x_low16s(VARLP("_a")),
						LET("_h1", c6x_high16s(VARLP("_b")),
							LET("_h0", c6x_low16s(VARLP("_b")),
								LOGOR(LOGOR(SHIFTL0(CLAMP8("_h3"), U32(24)), SHIFTL0(CLAMP8("_h2"), U32(16))),
									LOGOR(SHIFTL0(CLAMP8("_h1"), U32(8)), CLAMP8("_h0")))))))));
#undef CLAMP8
		return c6x_wr(&OP(2), v);
	}
	case C6X_INS_DOTP2:
	case C6X_INS_DOTPN2: {
		// DOTP2: lo*lo + hi*hi; DOTPN2: hi*hi - lo*lo (signed 16x16 products)
		bool neg = insn->id == C6X_INS_DOTPN2;
		RzILOpPure *s1lo = c6x_src(&OP(0));
		RzILOpPure *s2lo = c6x_src(&OP(1));
		RzILOpPure *s1hi = c6x_src(&OP(0));
		RzILOpPure *s2hi = c6x_src(&OP(1));
		if (!s1lo || !s2lo || !s1hi || !s2hi) {
			rz_il_op_pure_free(s1lo);
			rz_il_op_pure_free(s2lo);
			rz_il_op_pure_free(s1hi);
			rz_il_op_pure_free(s2hi);
			return NULL;
		}
		if (OP(2).kind == C6X_OP_REGPAIR) {
			// the long DOTP2: the sum sign-extended into a pair
			RzILOpBitVector *lo = MUL(SIGNED(64, c6x_low16s(s1lo)), SIGNED(64, c6x_low16s(s2lo)));
			RzILOpBitVector *hi = MUL(SIGNED(64, c6x_high16s(s1hi)), SIGNED(64, c6x_high16s(s2hi)));
			return c6x_wr_pair64(&OP(2), neg ? SUB(hi, lo) : ADD(lo, hi));
		}
		RzILOpBitVector *lo = MUL(c6x_low16s(s1lo), c6x_low16s(s2lo));
		RzILOpBitVector *hi = MUL(c6x_high16s(s1hi), c6x_high16s(s2hi));
		return c6x_wr(&OP(2), neg ? SUB(hi, lo) : ADD(lo, hi));
	}
	case C6X_INS_DOTPU4: {
		return c6x_dotp4(insn, false); // unsigned x unsigned bytes
	}
	case C6X_INS_DOTPRSU2: {
		return c6x_dotprs2(insn, false); // signed x unsigned halfwords, round+shift
	}
	case C6X_INS_DOTPNRSU2: {
		return c6x_dotprs2(insn, true); // as dotprsu2 but the low product is negated
	}
	case C6X_INS_DDOTPL2: {
		return c6x_ddotp2(insn, false); // low sliding windows into a pair
	}
	case C6X_INS_DDOTPH2: {
		return c6x_ddotp2(insn, true); // high sliding windows into a pair
	}
	case C6X_INS_CMPY: {
		return c6x_cmpy(insn);
	}
	case C6X_INS_CMPYR: {
		return c6x_cmpyr(insn, false);
	}
	case C6X_INS_CMPYR1: {
		return c6x_cmpyr(insn, true);
	}
	case C6X_INS_DOTPSU4: {
		return c6x_dotp4(insn, true); // signed src1 x unsigned src2 bytes
	}
	case C6X_INS_MPYU4: {
		return c6x_mpy4(insn, false); // unsigned x unsigned bytes
	}
	case C6X_INS_MPYSU4: {
		return c6x_mpy4(insn, true); // signed src1 x unsigned src2 bytes
	}
	default:
		break;
	}
	return NULL;
}

// The 16-bit lane \p high of a 32-bit value, sign-extended to 64 bits.
static RzILOpBitVector *c6x_h16s64(RzILOpPure *v, bool high) {
	return SIGNED(64, UNSIGNED(16, high ? SHIFTR0(v, U32(16)) : v));
}

// Two 16-bit lanes of a and b combined by \p sub, saturating when \p sat, as
// ADD2/SUB2 or SADD2/SSUB2 do; a and b are bound to locals by the caller.
static RzILOpBitVector *c6x_lanes2(const char *a, const char *b, bool sub, bool sat) {
	RzILOpBitVector *lanes[2];
	for (ut8 i = 0; i < 2; i++) {
		RzILOpBitVector *la = UNSIGNED(16, i ? SHIFTR0(VARLP(a), U32(16)) : VARLP(a));
		RzILOpBitVector *lb = UNSIGNED(16, i ? SHIFTR0(VARLP(b), U32(16)) : VARLP(b));
		lanes[i] = sat ? c6x_sat_s(sub ? SUB(SIGNED(32, la), SIGNED(32, lb)) : ADD(SIGNED(32, la), SIGNED(32, lb)), 16)
			       : (sub ? SUB(la, lb) : ADD(la, lb));
	}
	return APPEND(lanes[1], lanes[0]);
}

// msb16(sat32(p + q + 0x8000)), the rounded halves DDOTPH2R and DDOTPL2R pack.
static RzILOpBitVector *c6x_rnd_hi16(RzILOpBitVector *p, RzILOpBitVector *q) {
	return UNSIGNED(16, SHIFTR0(c6x_sats32(ADD(ADD(p, q), SN(64, 0x8000))), U32(16)));
}

// The dual-result and double-word forms: two results computed side by side
// from the same sources, one per register of a pair or per half of a word.
static RzILOpEffect *c6x_lift_dual(const C6xInsn *insn, ut64 pc) {
	switch (insn->id) {
	case C6X_INS_ADDSUB:
	case C6X_INS_SADDSUB: {
		// dst_o = src1 + src2, dst_e = src1 - src2, saturated for SADDSUB
		bool sat = insn->id == C6X_INS_SADDSUB;
		RzILOpPure *a = c6x_src(&OP(0));
		RzILOpPure *b = c6x_src(&OP(1));
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			return NULL;
		}
		RzILOpBitVector *sum = sat ? c6x_sats32(ADD(SIGNED(64, VARLP("_a")), SIGNED(64, VARLP("_b")))) : ADD(VARLP("_a"), VARLP("_b"));
		RzILOpBitVector *dif = sat ? c6x_sats32(SUB(SIGNED(64, VARLP("_a")), SIGNED(64, VARLP("_b")))) : SUB(VARLP("_a"), VARLP("_b"));
		return c6x_wr_pair64(&OP(2), LET("_a", a, LET("_b", b, APPEND(sum, dif))));
	}
	case C6X_INS_ADDSUB2:
	case C6X_INS_SADDSUB2: {
		// ADD2 into dst_o and SUB2 into dst_e, per halfword, saturated for SADDSUB2
		bool sat = insn->id == C6X_INS_SADDSUB2;
		RzILOpPure *a = c6x_src(&OP(0));
		RzILOpPure *b = c6x_src(&OP(1));
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			return NULL;
		}
		return c6x_wr_pair64(&OP(2), LET("_a", a, LET("_b", b, APPEND(c6x_lanes2("_a", "_b", false, sat), c6x_lanes2("_a", "_b", true, sat)))));
	}
	case C6X_INS_DMV: {
		// dst_o = src1, dst_e = src2
		return c6x_wr_dual(&OP(2), c6x_src(&OP(0)), c6x_src(&OP(1)));
	}
	case C6X_INS_DPACK2: {
		// dst_o = PACKH2(src1, src2), dst_e = PACK2(src1, src2)
		return c6x_wr_dual(&OP(2), APPEND(c6x_half(&OP(0), true), c6x_half(&OP(1), true)),
			APPEND(c6x_half(&OP(0), false), c6x_half(&OP(1), false)));
	}
	case C6X_INS_DPACKX2: {
		// dst_o = PACKLH2(src2, src1), dst_e = PACKLH2(src1, src2)
		return c6x_wr_dual(&OP(2), APPEND(c6x_half(&OP(1), false), c6x_half(&OP(0), true)),
			APPEND(c6x_half(&OP(0), false), c6x_half(&OP(1), true)));
	}
	case C6X_INS_SHFL3: {
		// interleave src2[15:0], src1[15:0] and src1[31:16] bit by bit into a
		// 48-bit result, OR-ed as a balanced tree to keep the IL shallow
		RzILOpPure *a = c6x_src(&OP(0));
		RzILOpPure *b = c6x_src(&OP(1));
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			return NULL;
		}
		RzILOpBitVector *t[48];
		for (ut8 i = 0; i < 16; i++) {
			static const char *const src[3] = { "_b", "_a", "_a" };
			for (ut8 k = 0; k < 3; k++) {
				ut8 bit = i + (k == 2 ? 16 : 0);
				RzILOpBitVector *v = LOGAND(SHIFTR0(UNSIGNED(64, VARLP(src[k])), U32(bit)), U64(1));
				t[3 * i + k] = SHIFTL0(v, U32(3 * i + k));
			}
		}
		for (size_t n = 48; n > 1; n = (n + 1) / 2) {
			for (size_t j = 0; j < n / 2; j++) {
				t[j] = LOGOR(t[2 * j], t[2 * j + 1]);
			}
			if (n & 1) {
				t[n / 2] = t[n - 1];
			}
		}
		return c6x_wr_pair64(&OP(2), LET("_a", a, LET("_b", b, t[0])));
	}
	case C6X_INS_MPY2IR: {
		// each halfword of src1 times src2, rounded and shifted right by 15;
		// 8000h times 8000 0000h saturates to 7FFF FFFFh
		RzILOpBitVector *r[2];
		for (ut8 i = 0; i < 2; i++) {
			RzILOpPure *a = c6x_src(&OP(0));
			RzILOpPure *b = c6x_src(&OP(1));
			if (!a || !b) {
				rz_il_op_pure_free(a);
				rz_il_op_pure_free(b);
				rz_il_op_pure_free(i ? r[0] : NULL);
				return NULL;
			}
			RzILOpBitVector *h = UNSIGNED(16, i ? a : SHIFTR0(a, U32(16)));
			r[i] = LET("_h", h, LET("_v", b, ITE(AND(EQ(VARLP("_h"), UN(16, 0x8000)), EQ(VARLP("_v"), U32(0x80000000))), U32(0x7fffffff), UNSIGNED(32, SHIFTRA(ADD(MUL(SIGNED(64, VARLP("_h")), SIGNED(64, VARLP("_v"))), SN(64, 0x4000)), U32(15))))));
		}
		return c6x_wr_dual(&OP(2), r[0], r[1]);
	}
	case C6X_INS_DDOTP4: {
		// two DOTP2s of src1's halfwords with the sign-extended bytes of each
		// halfword of src2: the low halfword into dst_e, the high into dst_o
		RzILOpBitVector *r[2];
		for (ut8 i = 0; i < 2; i++) {
			RzILOpPure *a1 = c6x_src(&OP(0));
			RzILOpPure *a2 = c6x_src(&OP(0));
			RzILOpPure *b1 = c6x_src(&OP(1));
			RzILOpPure *b2 = c6x_src(&OP(1));
			if (!a1 || !a2 || !b1 || !b2) {
				rz_il_op_pure_free(a1);
				rz_il_op_pure_free(a2);
				rz_il_op_pure_free(b1);
				rz_il_op_pure_free(b2);
				rz_il_op_pure_free(i ? r[0] : NULL);
				return NULL;
			}
			ut8 sh = i ? 16 : 0;
			RzILOpBitVector *hb = SIGNED(32, UNSIGNED(8, SHIFTR0(b1, U32(sh + 8))));
			RzILOpBitVector *lb = SIGNED(32, UNSIGNED(8, sh ? SHIFTR0(b2, U32(sh)) : b2));
			r[i] = ADD(MUL(c6x_high16s(a1), hb), MUL(c6x_low16s(a2), lb));
		}
		return c6x_wr_dual(&OP(2), r[1], r[0]);
	}
	case C6X_INS_DDOTPH2R:
	case C6X_INS_DDOTPL2R: {
		// two rounded dot products of src2 with windows of the src1 pair, each
		// saturated to 32 bits and packed by its high halfword
		bool h2 = insn->id == C6X_INS_DDOTPH2R;
		RzILOpPure *o1 = c6x_pair_reg(&OP(0), true);
		RzILOpPure *o2 = c6x_pair_reg(&OP(0), true);
		RzILOpPure *e1 = c6x_pair_reg(&OP(0), false);
		RzILOpPure *e2 = c6x_pair_reg(&OP(0), false);
		RzILOpPure *b[4];
		for (ut8 i = 0; i < 4; i++) {
			b[i] = c6x_src(&OP(1));
		}
		if (!o1 || !o2 || !e1 || !e2 || !b[0] || !b[1] || !b[2] || !b[3]) {
			rz_il_op_pure_free(o1);
			rz_il_op_pure_free(o2);
			rz_il_op_pure_free(e1);
			rz_il_op_pure_free(e2);
			for (ut8 i = 0; i < 4; i++) {
				rz_il_op_pure_free(b[i]);
			}
			return NULL;
		}
		// the window shared by both: lsb16(src1_o) x msb16(src2) + msb16(src1_e) x lsb16(src2)
		RzILOpBitVector *mid = c6x_rnd_hi16(MUL(c6x_h16s64(o1, false), c6x_h16s64(b[0], true)), MUL(c6x_h16s64(e1, true), c6x_h16s64(b[1], false)));
		// DDOTPH2R adds the halves of src1_o, DDOTPL2R those of src1_e
		RzILOpPure *w = h2 ? o2 : e2;
		rz_il_op_pure_free(h2 ? e2 : o2);
		RzILOpBitVector *own = LET("_w", w, c6x_rnd_hi16(MUL(c6x_h16s64(VARLP("_w"), true), c6x_h16s64(b[2], true)), MUL(c6x_h16s64(VARLP("_w"), false), c6x_h16s64(b[3], false))));
		return c6x_wr(&OP(2), h2 ? APPEND(own, mid) : APPEND(mid, own));
	}
	case C6X_INS_SMPY32: {
		// msb32(sat(src1 x src2 << 1)): only 8000 0000h squared overflows
		RzILOpPure *a = c6x_src(&OP(0));
		RzILOpPure *b = c6x_src(&OP(1));
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			return NULL;
		}
		return c6x_wr(&OP(2), LET("_a", a, LET("_b", b, ITE(AND(EQ(VARLP("_a"), U32(0x80000000)), EQ(VARLP("_b"), U32(0x80000000))), U32(0x7fffffff), UNSIGNED(32, SHIFTRA(MUL(SIGNED(64, VARLP("_a")), SIGNED(64, VARLP("_b"))), U32(31)))))));
	}
	case C6X_INS_SUBABS4: {
		// |src1 - src2| per unsigned byte
		RzILOpBitVector *acc = NULL;
		for (ut8 i = 0; i < 4; i++) {
			RzILOpPure *a = c6x_src(&OP(0));
			RzILOpPure *b = c6x_src(&OP(1));
			if (!a || !b) {
				rz_il_op_pure_free(a);
				rz_il_op_pure_free(b);
				rz_il_op_pure_free(acc);
				return NULL;
			}
			RzILOpBitVector *la = UNSIGNED(8, i ? SHIFTR0(a, U32(8 * i)) : a);
			RzILOpBitVector *lb = UNSIGNED(8, i ? SHIFTR0(b, U32(8 * i)) : b);
			RzILOpBitVector *lane = LET("_x", la, LET("_y", lb, ITE(UGE(VARLP("_x"), VARLP("_y")), SUB(VARLP("_x"), VARLP("_y")), SUB(VARLP("_y"), VARLP("_x")))));
			acc = acc ? APPEND(lane, acc) : lane;
		}
		return c6x_wr(&OP(2), acc);
	}
	case C6X_INS_DADD:
	case C6X_INS_DSUB: {
		// two 32-bit adds or subtracts, one per register of the pairs; a scst5
		// src1 applies to both
		bool sub = insn->id == C6X_INS_DSUB;
		RzILOpBitVector *r[2];
		for (ut8 i = 0; i < 2; i++) {
			RzILOpPure *a = c6x_dw_lane(&OP(0), i);
			RzILOpPure *b = c6x_dw_lane(&OP(1), i);
			if (!a || !b) {
				rz_il_op_pure_free(a);
				rz_il_op_pure_free(b);
				rz_il_op_pure_free(i ? r[0] : NULL);
				return NULL;
			}
			r[i] = sub ? SUB(a, b) : ADD(a, b);
		}
		return c6x_wr_dual(&OP(2), r[1], r[0]);
	}
	default:
		break;
	}
	return NULL;
}

// One step of SPRUFE8B's gmpy(): src1 (local _ga) added to the partial product
// \p pp when bit \p bit of src2 (local _gb) is set, then the product shifted,
// the polynomial (local _gp) added when bit 31 shifts out. Each step binds its
// own _gs; the previous one is out of scope by then.
static RzILOpBitVector *c6x_gmpy_step(RzILOpBitVector *pp, ut8 bit, bool poly) {
	RzILOpBitVector *v = LOGXOR(pp, ITE(LSB(SHIFTR0(VARLP("_gb"), U32(bit))), VARLP("_ga"), U32(0)));
	if (!poly) {
		return SHIFTL0(v, U32(1));
	}
	return LET("_gs", v, ITE(MSB(VARLP("_gs")), LOGXOR(SHIFTL0(VARLP("_gs"), U32(1)), VARLP("_gp")), SHIFTL0(VARLP("_gs"), U32(1))));
}

// Byte \p i of GMPY4: Horner's rule over the bits of src2's byte (local _gb), in
// the field of size _gm (SIZE + 1) whose generator, x^m included, is _gg.
static RzILOpBitVector *c6x_gmpy4_byte(ut8 i) {
	RzILOpBitVector *a = LOGAND(SHIFTR0(VARLP("_ga"), U32(8 * i)), U32(0xff));
	RzILOpBitVector *pp = ITE(LSB(SHIFTR0(VARLP("_gb"), U32(8 * i + 7))), a, U32(0));
	for (int bit = 6; bit >= 0; bit--) {
		RzILOpBitVector *t = LET("_g4", SHIFTL0(pp, U32(1)), ITE(LSB(SHIFTR0(VARLP("_g4"), VARLP("_gm"))), LOGXOR(VARLP("_g4"), VARLP("_gg")), VARLP("_g4")));
		a = LOGAND(SHIFTR0(VARLP("_ga"), U32(8 * i)), U32(0xff));
		pp = LOGXOR(t, ITE(LSB(SHIFTR0(VARLP("_gb"), U32(8 * i + bit))), a, U32(0)));
	}
	return UNSIGNED(8, pp);
}

// The Galois-field multiplies: GMPY and XORMPY of 32 bits by 9 (SPRUFE8B's
// gmpy(), the polynomial from GPLYA or GPLYB for GMPY, none for XORMPY), and
// GMPY4 per byte in the field GFPGFR sets. GMPY4 is exact for elements of the
// field; SPRUFE8B does not say what the hardware does with bytes above it.
static RzILOpEffect *c6x_lift_gf(const C6xInsn *insn, ut64 pc) {
	RzILOpPure *a = c6x_src(&OP(0));
	RzILOpPure *b = c6x_src(&OP(1));
	if (!a || !b) {
		rz_il_op_pure_free(a);
		rz_il_op_pure_free(b);
		return NULL;
	}
	if (insn->id == C6X_INS_GMPY4) {
		RzILOpBitVector *r = APPEND(APPEND(c6x_gmpy4_byte(3), c6x_gmpy4_byte(2)), APPEND(c6x_gmpy4_byte(1), c6x_gmpy4_byte(0)));
		RzILOpPure *size = ADD(LOGAND(SHIFTR0(c6x_reg_read("gfpgfr"), U32(24)), U32(7)), U32(1));
		RzILOpPure *gen = LOGOR(LOGAND(c6x_reg_read("gfpgfr"), U32(0xff)), SHIFTL0(U32(1), VARLP("_gm")));
		return c6x_wr(&OP(2), LET("_ga", a, LET("_gb", b, LET("_gm", size, LET("_gg", gen, r)))));
	}
	bool poly = insn->id == C6X_INS_GMPY;
	// bits 8 to 1 of src2 each add src1 before a shift, bit 0 after the last
	RzILOpBitVector *pp = U32(0);
	for (int bit = 8; bit >= 1; bit--) {
		pp = c6x_gmpy_step(pp, bit, poly);
	}
	pp = LOGXOR(pp, ITE(LSB(VARLP("_gb")), VARLP("_ga"), U32(0)));
	if (poly) {
		pp = LET("_gp", c6x_reg_read(insn->unit_side ? "gplyb" : "gplya"), pp);
	}
	return c6x_wr(&OP(2), LET("_ga", a, LET("_gb", b, pp)));
}

// What a C66x double-word form does to each register of its pairs: the C64x+
// single-word operation of the same name, or one only the double-word forms have.
typedef enum {
	C6X_DW_ADD2,
	C6X_DW_SUB2,
	C6X_DW_SADD,
	C6X_DW_SADD2,
	C6X_DW_SSUB,
	C6X_DW_SSUB2,
	C6X_DW_APYS2,
	C6X_DW_MAX2,
	C6X_DW_MIN2,
	C6X_DW_MAXU4,
	C6X_DW_MINU4,
	C6X_DW_AVG2,
	C6X_DW_AVGNR2,
	C6X_DW_AVGU4,
	C6X_DW_AVGNRU4,
	C6X_DW_PACK2,
	C6X_DW_PACKH2,
	C6X_DW_PACKHL2,
	C6X_DW_PACKLH2,
	C6X_DW_PACKH4,
	C6X_DW_PACKL4,
	C6X_DW_SPACKU4,
} C6xDwOp;

// The negation of a signed 16-bit lane, 8000h saturating to 7FFFh.
static RzILOpBitVector *c6x_satneg16(RzILOpBitVector *h) {
	return LET("_n", h, ITE(EQ(VARLP("_n"), UN(16, 0x8000)), UN(16, 0x7fff), NEG(VARLP("_n"))));
}

// Lane x of src1 and y of src2 combined by \p op, a 16-bit or an 8-bit lane.
static RzILOpBitVector *c6x_dw_lane_op(C6xDwOp op, RzILOpBitVector *x, RzILOpBitVector *y) {
	switch (op) {
	case C6X_DW_ADD2: return ADD(x, y);
	case C6X_DW_SUB2: return SUB(x, y);
	case C6X_DW_SADD2: return c6x_sat_s(ADD(SIGNED(32, x), SIGNED(32, y)), 16);
	case C6X_DW_SSUB2: return c6x_sat_s(SUB(SIGNED(32, x), SIGNED(32, y)), 16);
	case C6X_DW_AVG2: return UNSIGNED(16, SHIFTRA(ADD(ADD(SIGNED(32, x), SIGNED(32, y)), U32(1)), U32(1)));
	case C6X_DW_AVGNR2: return UNSIGNED(16, SHIFTRA(ADD(SIGNED(32, x), SIGNED(32, y)), U32(1)));
	case C6X_DW_AVGU4: return UNSIGNED(8, SHIFTR0(ADD(ADD(UNSIGNED(16, x), UNSIGNED(16, y)), UN(16, 1)), U32(1)));
	case C6X_DW_AVGNRU4: return UNSIGNED(8, SHIFTR0(ADD(UNSIGNED(16, x), UNSIGNED(16, y)), U32(1)));
	default: break;
	}
	RzILOpBitVector *r;
	switch (op) {
	case C6X_DW_APYS2:
		// src1's sign negates src2's lane
		r = ITE(MSB(VARLP("_lx")), c6x_satneg16(VARLP("_ly")), VARLP("_ly"));
		break;
	case C6X_DW_MAX2: r = ITE(SGE(VARLP("_lx"), VARLP("_ly")), VARLP("_lx"), VARLP("_ly")); break;
	case C6X_DW_MIN2: r = ITE(SLE(VARLP("_lx"), VARLP("_ly")), VARLP("_lx"), VARLP("_ly")); break;
	case C6X_DW_MAXU4: r = ITE(UGE(VARLP("_lx"), VARLP("_ly")), VARLP("_lx"), VARLP("_ly")); break;
	default: r = ITE(ULE(VARLP("_lx"), VARLP("_ly")), VARLP("_lx"), VARLP("_ly")); break;
	}
	return LET("_lx", x, LET("_ly", y, r));
}

// Byte \p i of the 32-bit local \p v.
static RzILOpBitVector *c6x_byte_of(const char *v, ut8 i) {
	return UNSIGNED(8, i ? SHIFTR0(VARLP(v), U32(8 * i)) : VARLP(v));
}

// Halfword \p high of the 32-bit local \p v.
static RzILOpBitVector *c6x_half_of(const char *v, bool high) {
	return UNSIGNED(16, high ? SHIFTR0(VARLP(v), U32(16)) : VARLP(v));
}

// A signed 16-bit halfword of the local \p v clamped to an unsigned byte.
static RzILOpBitVector *c6x_satu8_of(const char *v, bool high) {
	return LET("_h", c6x_half_of(v, high),
		ITE(MSB(VARLP("_h")), UN(8, 0), ITE(UGT(VARLP("_h"), UN(16, 0xff)), UN(8, 0xff), UNSIGNED(8, VARLP("_h")))));
}

// The 32-bit result of \p op on the words \p a of src1 and \p b of src2.
static RzILOpBitVector *c6x_dw_word(C6xDwOp op, RzILOpPure *a, RzILOpPure *b) {
	RzILOpBitVector *r;
	switch (op) {
	case C6X_DW_SADD: return c6x_sats32(ADD(SIGNED(64, a), SIGNED(64, b)));
	case C6X_DW_SSUB: return c6x_sats32(SUB(SIGNED(64, a), SIGNED(64, b)));
	case C6X_DW_PACK2: r = APPEND(c6x_half_of("_wa", false), c6x_half_of("_wb", false)); break;
	case C6X_DW_PACKH2: r = APPEND(c6x_half_of("_wa", true), c6x_half_of("_wb", true)); break;
	case C6X_DW_PACKHL2: r = APPEND(c6x_half_of("_wa", true), c6x_half_of("_wb", false)); break;
	case C6X_DW_PACKLH2: r = APPEND(c6x_half_of("_wa", false), c6x_half_of("_wb", true)); break;
	case C6X_DW_PACKH4:
		r = APPEND(APPEND(c6x_byte_of("_wa", 3), c6x_byte_of("_wa", 1)), APPEND(c6x_byte_of("_wb", 3), c6x_byte_of("_wb", 1)));
		break;
	case C6X_DW_PACKL4:
		r = APPEND(APPEND(c6x_byte_of("_wa", 2), c6x_byte_of("_wa", 0)), APPEND(c6x_byte_of("_wb", 2), c6x_byte_of("_wb", 0)));
		break;
	case C6X_DW_SPACKU4:
		r = APPEND(APPEND(c6x_satu8_of("_wa", true), c6x_satu8_of("_wa", false)), APPEND(c6x_satu8_of("_wb", true), c6x_satu8_of("_wb", false)));
		break;
	default: {
		ut8 width = op == C6X_DW_MAXU4 || op == C6X_DW_MINU4 || op == C6X_DW_AVGU4 || op == C6X_DW_AVGNRU4 ? 8 : 16;
		r = NULL;
		for (ut8 i = 0; i < 32 / width; i++) {
			RzILOpBitVector *x = UNSIGNED(width, i ? SHIFTR0(VARLP("_wa"), U32(i * width)) : VARLP("_wa"));
			RzILOpBitVector *y = UNSIGNED(width, i ? SHIFTR0(VARLP("_wb"), U32(i * width)) : VARLP("_wb"));
			RzILOpBitVector *lane = c6x_dw_lane_op(op, x, y);
			r = r ? APPEND(lane, r) : lane;
		}
		break;
	}
	}
	return LET("_wa", a, LET("_wb", b, r));
}

// \p op_e on the even registers of the pairs, or on two singles, into dst_e, and
// \p op_o on the odd ones into dst_o.
static RzILOpEffect *c6x_dw_apply(const C6xInsn *insn, C6xDwOp op_e, C6xDwOp op_o) {
	RzILOpBitVector *r[2] = { NULL, NULL };
	for (ut8 i = 0; i < 2; i++) {
		RzILOpPure *a = c6x_dw_lane(&OP(0), i);
		RzILOpPure *b = c6x_dw_lane(&OP(1), i);
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			rz_il_op_pure_free(r[0]);
			return NULL;
		}
		r[i] = c6x_dw_word(i ? op_o : op_e, a, b);
	}
	return c6x_wr_dual(&OP(2), r[1], r[0]);
}

// \p v shifted left, right arithmetically (\p ar) or right logically by \p c.
static RzILOpBitVector *c6x_shift_by(RzILOpPure *v, RzILOpPure *c, bool left, bool ar) {
	if (left) {
		return SHIFTL0(v, c);
	}
	return ar ? SHIFTRA(v, c) : SHIFTR0(v, c);
}

// The shift of a word, or of each halfword, of \p v by \p n, as SHL, SHR, SHRU, SHR2
// and SHRU2 do: a register count keeps its six LSBs for a word and five for a
// halfword, and a shift by the width or more leaves zeros or the sign.
static RzILOpBitVector *c6x_shift_word(C6xInsnId id, RzILOpPure *v, RzILOpPure *n, bool reg) {
	bool halves = id == C6X_INS_DSHL2 || id == C6X_INS_DSHR2 || id == C6X_INS_DSHRU2 || id == C6X_INS_SHL2;
	bool left = id == C6X_INS_DSHL || id == C6X_INS_DSHL2 || id == C6X_INS_SHL2;
	bool ar = id == C6X_INS_DSHR || id == C6X_INS_DSHR2;
	if (!halves) {
		return c6x_shift_by(v, reg ? LOGAND(n, U32(0x3f)) : n, left, ar);
	}
	RzILOpBitVector *lanes[2];
	for (ut8 i = 0; i < 2; i++) {
		RzILOpBitVector *h = UNSIGNED(16, i ? SHIFTR0(VARLP("_sv"), U32(16)) : VARLP("_sv"));
		lanes[i] = c6x_shift_by(h, VARLP("_sn"), left, ar);
	}
	return LET("_sv", v, LET("_sn", UNSIGNED(16, LOGAND(n, U32(0x1f))), APPEND(lanes[1], lanes[0])));
}

// A packed compare of src1 and src2 into a bit per lane, those of src1_e and
// src2_e in the low bits of dst, those of the odd registers above them.
static RzILOpEffect *c6x_dw_cmp(const C6xInsn *insn, ut8 width, rz_il_bool_2args_op *mk) {
	RzILOpBitVector *mask = NULL;
	for (ut8 w = 0; w < 2; w++) {
		for (ut8 i = 0; i < 32 / width; i++) {
			RzILOpPure *a = c6x_pair_reg(&OP(0), w);
			RzILOpPure *b = c6x_pair_reg(&OP(1), w);
			if (!a || !b) {
				rz_il_op_pure_free(a);
				rz_il_op_pure_free(b);
				rz_il_op_pure_free(mask);
				return NULL;
			}
			RzILOpBitVector *x = UNSIGNED(width, i ? SHIFTR0(a, U32(i * width)) : a);
			RzILOpBitVector *y = UNSIGNED(width, i ? SHIFTR0(b, U32(i * width)) : b);
			RzILOpBitVector *bit = ITE(mk(x, y), UN(1, 1), UN(1, 0));
			mask = mask ? APPEND(bit, mask) : bit;
		}
	}
	return c6x_wr(&OP(2), UNSIGNED(32, mask));
}

// CROT90 (\p rot90) multiplies a packed complex value by j, CROT270 by -j: the
// real part is the upper halfword, and the part negated saturates.
static RzILOpBitVector *c6x_crot(RzILOpPure *v, bool rot90) {
	RzILOpBitVector *r = rot90 ? APPEND(c6x_satneg16(c6x_half_of("_c", false)), c6x_half_of("_c", true))
				   : APPEND(c6x_half_of("_c", false), c6x_satneg16(c6x_half_of("_c", true)));
	return LET("_c", v, r);
}

// Bits \p first and \p first + 1 of \p v, each widened to a halfword mask (XPND2).
static RzILOpBitVector *c6x_xpnd2_of(RzILOpPure *v, ut8 first) {
	RzILOpBitVector *h[2];
	for (ut8 i = 0; i < 2; i++) {
		h[i] = ITE(LSB(SHIFTR0(VARLP("_x"), U32(first + i))), UN(16, 0xffff), UN(16, 0));
	}
	return LET("_x", v, APPEND(h[1], h[0]));
}

// Bits \p first to \p first + 3 of \p v, each widened to a byte mask (XPND4).
static RzILOpBitVector *c6x_xpnd4_of(RzILOpPure *v, ut8 first) {
	RzILOpBitVector *b[4];
	for (ut8 i = 0; i < 4; i++) {
		b[i] = ITE(LSB(SHIFTR0(VARLP("_x"), U32(first + i))), UN(8, 0xff), UN(8, 0));
	}
	return LET("_x", v, APPEND(APPEND(b[3], b[2]), APPEND(b[1], b[0])));
}

// The C66x double-word integer forms, their shifts and compares, and the
// rotations, unpacks and logical operations C66x adds.
static RzILOpEffect *c6x_lift_c66x(const C6xInsn *insn, ut64 pc) {
	switch (insn->id) {
	case C6X_INS_DADD2: return c6x_dw_apply(insn, C6X_DW_ADD2, C6X_DW_ADD2);
	case C6X_INS_DSUB2: return c6x_dw_apply(insn, C6X_DW_SUB2, C6X_DW_SUB2);
	case C6X_INS_DSADD: return c6x_dw_apply(insn, C6X_DW_SADD, C6X_DW_SADD);
	case C6X_INS_DSADD2: return c6x_dw_apply(insn, C6X_DW_SADD2, C6X_DW_SADD2);
	case C6X_INS_DSSUB: return c6x_dw_apply(insn, C6X_DW_SSUB, C6X_DW_SSUB);
	case C6X_INS_DSSUB2: return c6x_dw_apply(insn, C6X_DW_SSUB2, C6X_DW_SSUB2);
	case C6X_INS_DAPYS2: return c6x_dw_apply(insn, C6X_DW_APYS2, C6X_DW_APYS2);
	case C6X_INS_DMAX2: return c6x_dw_apply(insn, C6X_DW_MAX2, C6X_DW_MAX2);
	case C6X_INS_DMIN2: return c6x_dw_apply(insn, C6X_DW_MIN2, C6X_DW_MIN2);
	case C6X_INS_DMAXU4: return c6x_dw_apply(insn, C6X_DW_MAXU4, C6X_DW_MAXU4);
	case C6X_INS_DMINU4: return c6x_dw_apply(insn, C6X_DW_MINU4, C6X_DW_MINU4);
	case C6X_INS_DAVG2: return c6x_dw_apply(insn, C6X_DW_AVG2, C6X_DW_AVG2);
	case C6X_INS_DAVGNR2: return c6x_dw_apply(insn, C6X_DW_AVGNR2, C6X_DW_AVGNR2);
	case C6X_INS_DAVGU4: return c6x_dw_apply(insn, C6X_DW_AVGU4, C6X_DW_AVGU4);
	case C6X_INS_DAVGNRU4: return c6x_dw_apply(insn, C6X_DW_AVGNRU4, C6X_DW_AVGNRU4);
	case C6X_INS_DPACKL2: return c6x_dw_apply(insn, C6X_DW_PACK2, C6X_DW_PACK2);
	case C6X_INS_DPACKH2: return c6x_dw_apply(insn, C6X_DW_PACKH2, C6X_DW_PACKH2);
	case C6X_INS_DPACKHL2: return c6x_dw_apply(insn, C6X_DW_PACKHL2, C6X_DW_PACKHL2);
	case C6X_INS_DPACKLH2: return c6x_dw_apply(insn, C6X_DW_PACKLH2, C6X_DW_PACKLH2);
	case C6X_INS_DPACKH4: return c6x_dw_apply(insn, C6X_DW_PACKH4, C6X_DW_PACKH4);
	case C6X_INS_DPACKL4: return c6x_dw_apply(insn, C6X_DW_PACKL4, C6X_DW_PACKL4);
	case C6X_INS_DPACKLH4: return c6x_dw_apply(insn, C6X_DW_PACKL4, C6X_DW_PACKH4);
	case C6X_INS_DSPACKU4: return c6x_dw_apply(insn, C6X_DW_SPACKU4, C6X_DW_SPACKU4);
	case C6X_INS_DMVD: {
		// DMV that lands later: dst_o = src1, dst_e = src2
		return c6x_wr_dual(&OP(2), c6x_src(&OP(0)), c6x_src(&OP(1)));
	}
	case C6X_INS_DSHL:
	case C6X_INS_DSHR:
	case C6X_INS_DSHRU:
	case C6X_INS_DSHL2:
	case C6X_INS_DSHR2:
	case C6X_INS_DSHRU2: {
		// each register of the src2 pair shifted by the one count of src1
		bool reg = OP(1).kind == C6X_OP_REG;
		RzILOpBitVector *r[2] = { NULL, NULL };
		for (ut8 i = 0; i < 2; i++) {
			RzILOpPure *v = c6x_pair_reg(&OP(0), i);
			RzILOpPure *n = c6x_src(&OP(1));
			if (!v || !n) {
				rz_il_op_pure_free(v);
				rz_il_op_pure_free(n);
				rz_il_op_pure_free(r[0]);
				return NULL;
			}
			r[i] = c6x_shift_word(insn->id, v, n, reg);
		}
		return c6x_wr_dual(&OP(2), r[1], r[0]);
	}
	case C6X_INS_SHL2: {
		RzILOpPure *v = c6x_src(&OP(0));
		RzILOpPure *n = c6x_src(&OP(1));
		if (!v || !n) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(n);
			return NULL;
		}
		return c6x_wr(&OP(2), c6x_shift_word(insn->id, v, n, true));
	}
	case C6X_INS_DCMPEQ2: return c6x_dw_cmp(insn, 16, rz_il_op_new_eq);
	case C6X_INS_DCMPGT2: return c6x_dw_cmp(insn, 16, rz_il_op_new_sgt);
	case C6X_INS_DCMPEQ4: return c6x_dw_cmp(insn, 8, rz_il_op_new_eq);
	case C6X_INS_DCMPGTU4: return c6x_dw_cmp(insn, 8, rz_il_op_new_ugt);
	case C6X_INS_CROT90:
	case C6X_INS_CROT270: {
		RzILOpPure *v = c6x_src(&OP(0));
		return v ? c6x_wr(&OP(1), c6x_crot(v, insn->id == C6X_INS_CROT90)) : NULL;
	}
	case C6X_INS_DCROT90:
	case C6X_INS_DCROT270: {
		bool rot90 = insn->id == C6X_INS_DCROT90;
		RzILOpPure *o = c6x_pair_reg(&OP(0), true);
		RzILOpPure *e = c6x_pair_reg(&OP(0), false);
		return c6x_wr_dual(&OP(1), o ? c6x_crot(o, rot90) : NULL, e ? c6x_crot(e, rot90) : NULL);
	}
	case C6X_INS_UNPKBU4: {
		// each byte of src2 zero-extended to a halfword, bytes 1:0 into dst_e
		RzILOpPure *o = c6x_src(&OP(0));
		RzILOpPure *e = c6x_src(&OP(0));
		RzILOpBitVector *ro = o ? LET("_u", o, APPEND(UNSIGNED(16, c6x_byte_of("_u", 3)), UNSIGNED(16, c6x_byte_of("_u", 2)))) : NULL;
		RzILOpBitVector *re = e ? LET("_u", e, APPEND(UNSIGNED(16, c6x_byte_of("_u", 1)), UNSIGNED(16, c6x_byte_of("_u", 0)))) : NULL;
		return c6x_wr_dual(&OP(1), ro, re);
	}
	case C6X_INS_UNPKH2:
	case C6X_INS_UNPKHU2: {
		// each halfword of src2 widened to a word, the lower into dst_e
		bool sgn = insn->id == C6X_INS_UNPKH2;
		RzILOpPure *o = c6x_src(&OP(0));
		RzILOpPure *e = c6x_src(&OP(0));
		RzILOpBitVector *ho = o ? UNSIGNED(16, SHIFTR0(o, U32(16))) : NULL;
		RzILOpBitVector *he = e ? UNSIGNED(16, e) : NULL;
		return c6x_wr_dual(&OP(1), ho ? (sgn ? SIGNED(32, ho) : UNSIGNED(32, ho)) : NULL, he ? (sgn ? SIGNED(32, he) : UNSIGNED(32, he)) : NULL);
	}
	case C6X_INS_DXPND2:
	case C6X_INS_DXPND4: {
		// the four (eight) LSBs of src2 widened to halfword (byte) masks, the
		// lower ones into dst_e
		bool x2 = insn->id == C6X_INS_DXPND2;
		RzILOpPure *o = c6x_src(&OP(0));
		RzILOpPure *e = c6x_src(&OP(0));
		RzILOpBitVector *ro = o ? (x2 ? c6x_xpnd2_of(o, 2) : c6x_xpnd4_of(o, 4)) : NULL;
		RzILOpBitVector *re = e ? (x2 ? c6x_xpnd2_of(e, 0) : c6x_xpnd4_of(e, 0)) : NULL;
		return c6x_wr_dual(&OP(1), ro, re);
	}
	case C6X_INS_LAND:
	case C6X_INS_LANDN:
	case C6X_INS_LOR: {
		// the sources as truth values; LANDN takes src2's negation
		RzILOpPure *a = c6x_src(&OP(0));
		RzILOpPure *b = c6x_src(&OP(1));
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			return NULL;
		}
		RzILOpBool *c;
		if (insn->id == C6X_INS_LOR) {
			c = OR(NON_ZERO(a), NON_ZERO(b));
		} else if (insn->id == C6X_INS_LAND) {
			c = AND(NON_ZERO(a), NON_ZERO(b));
		} else {
			c = AND(NON_ZERO(a), IS_ZERO(b));
		}
		return c6x_wr(&OP(2), ITE(c, U32(1), U32(0)));
	}
	case C6X_INS_MFENCE:
		// the VM's memory accesses complete in order
		return NOP();
	default:
		break;
	}
	return NULL;
}

// Register \p i of a quad operand, the least significant first.
static RzILOpPure *c6x_quad_reg(const C6xOperand *o, ut8 i) {
	return o->kind == C6X_OP_REGQUAD ? c6x_reg_read(c6x_reg_name(o->v.reg.side, o->v.reg.num + i)) : NULL;
}

// Write the four words \p r into the quad dst, the least significant first, all
// computed before any register is written.
static RzILOpEffect *c6x_wr_quad(const C6xOperand *o, RzILOpBitVector *r[4]) {
	if (o->kind != C6X_OP_REGQUAD || !r[0] || !r[1] || !r[2] || !r[3]) {
		for (ut8 i = 0; i < 4; i++) {
			rz_il_op_pure_free(r[i]);
		}
		return NULL;
	}
	static const char *const tmp[4] = { "_q0", "_q1", "_q2", "_q3" };
	RzILOpEffect *e = NULL;
	for (int i = 3; i >= 0; i--) {
		RzILOpEffect *w = c6x_reg_write(c6x_reg_name(o->v.reg.side, o->v.reg.num + i), VARL(tmp[i]));
		e = e ? SEQ2(w, e) : w;
	}
	for (int i = 3; i >= 0; i--) {
		e = SEQ2(SETL(tmp[i], r[i]), e);
	}
	return e;
}

// The 16x16 product of halfword \p high of words \p a and \p b, signed or unsigned.
static RzILOpBitVector *c6x_mpy_half(RzILOpPure *a, RzILOpPure *b, bool high, bool sgn) {
	return MUL(c6x_half16(a, high, sgn), c6x_half16(b, high, sgn));
}

// The doubled product SMPY2 keeps, 8000h squared saturating.
static RzILOpBitVector *c6x_smpy_half(RzILOpPure *a, RzILOpPure *b, bool high) {
	return LET("_p", c6x_mpy_half(a, b, high, true), ITE(EQ(VARLP("_p"), U32(0x40000000)), U32(0x7fffffff), SHIFTL0(VARLP("_p"), U32(1))));
}

// Two halfword products of byte \p i and \p i + 1 of \p a (signed when \p sgn) and \p b,
// packed into a word as MPYU4 and MPYSU4 do.
static RzILOpBitVector *c6x_mpy4_pair(RzILOpPure *a, RzILOpPure *b, ut8 i, bool sgn) {
	RzILOpBitVector *p[2];
	for (ut8 k = 0; k < 2; k++) {
		RzILOpBitVector *x = c6x_byte_of("_ma", i + k);
		p[k] = MUL(sgn ? SIGNED(16, x) : UNSIGNED(16, x), UNSIGNED(16, c6x_byte_of("_mb", i + k)));
	}
	return LET("_ma", a, LET("_mb", b, APPEND(p[1], p[0])));
}

// The product of the packed complex words \p a and \p b, or of \p a and the
// conjugate of \p b, as 64-bit real and imaginary sums of 16x16 products. The
// conjugate is exact: SPRUGH7's examples of DCCMPYR1 do not saturate its 8000h.
static RzILOpBitVector *c6x_cplx_sum(bool imag, bool conj) {
	if (conj) {
		return imag ? SUB(MUL(SLO("_a"), SHI("_b")), MUL(SHI("_a"), SLO("_b"))) : ADD(MUL(SHI("_a"), SHI("_b")), MUL(SLO("_a"), SLO("_b")));
	}
	return imag ? ADD(MUL(SLO("_a"), SHI("_b")), MUL(SHI("_a"), SLO("_b"))) : SUB(MUL(SHI("_a"), SHI("_b")), MUL(SLO("_a"), SLO("_b")));
}

// CMPY of the words \p a and \p b: real (hi1 x hi2 - lo1 x lo2) in the upper word,
// the imaginary part, saturated, in the lower. With \p b conjugated the real part
// is the one 8000h can overflow, and saturates instead.
static RzILOpBitVector *c6x_cmpy_word(RzILOpPure *a, RzILOpPure *b, bool conj) {
	RzILOpBitVector *im = conj ? UNSIGNED(32, c6x_cplx_sum(true, true)) : c6x_sats32(c6x_cplx_sum(true, false));
	RzILOpBitVector *re = conj ? c6x_sats32(c6x_cplx_sum(false, true)) : UNSIGNED(32, c6x_cplx_sum(false, false));
	return LET("_a", a, LET("_b", b, APPEND(re, im)));
}

// CMPYR1 of the words \p a and \p b (\p b conjugated when \p conj), rounded into
// one word, the real part above.
static RzILOpBitVector *c6x_cmpyr1_word(RzILOpPure *a, RzILOpPure *b, bool conj) {
	RzILOpBitVector *lo = c6x_cmpyr_half(c6x_cplx_sum(true, conj), true);
	RzILOpBitVector *hi = c6x_cmpyr_half(c6x_cplx_sum(false, conj), true);
	return LET("_a", a, LET("_b", b, APPEND(hi, lo)));
}

// The four-way dot product of the halfwords of the pairs (or quad halves) \p a
// and \p b, 64 bits wide; src2's halfwords unsigned when \p su.
static RzILOpBitVector *c6x_dotp4h_sum(RzILOpPure *a[2], RzILOpPure *b[2], bool su) {
	RzILOpBitVector *acc = NULL;
	for (ut8 w = 0; w < 2; w++) {
		for (ut8 h = 0; h < 2; h++) {
			RzILOpPure *x = h ? DUP(a[w]) : a[w];
			RzILOpPure *y = h ? DUP(b[w]) : b[w];
			RzILOpBitVector *hx = SIGNED(64, UNSIGNED(16, h ? SHIFTR0(x, U32(16)) : x));
			RzILOpBitVector *hy = UNSIGNED(16, h ? SHIFTR0(y, U32(16)) : y);
			RzILOpBitVector *p = MUL(hx, su ? UNSIGNED(64, hy) : SIGNED(64, hy));
			acc = acc ? ADD(acc, p) : p;
		}
	}
	return acc;
}

// The Q31 product sum \p p + \p q rounded and shifted right by 31, saturated,
// computed at 96 bits since two 32x32 products overflow 64.
static RzILOpBitVector *c6x_q31_round(RzILOpBitVector *p, RzILOpBitVector *q) {
	RzILOpBitVector *s = SHIFTRA(ADD(q ? ADD(p, q) : p, SN(96, 1LL << 30)), U32(31));
	return LET("_r", s,
		ITE(SGT(VARLP("_r"), SN(96, 0x7fffffff)), U32(0x7fffffff),
			ITE(SLT(VARLP("_r"), SN(96, -0x80000000LL)), U32(0x80000000), UNSIGNED(32, VARLP("_r")))));
}

// A signed 32x32 product at 96 bits.
static RzILOpBitVector *c6x_mul96(RzILOpPure *a, RzILOpPure *b) {
	return MUL(SIGNED(96, a), SIGNED(96, b));
}

// CMPY32R1 and CCMPY32R1 (\p conj, src2 conjugated) of the Q31 complex pairs, the
// real part in the odd register.
static RzILOpEffect *c6x_cmpy32r1(const C6xInsn *insn, bool conj) {
	RzILOpPure *ar[2], *ai[2], *br[2], *bi[2];
	for (ut8 i = 0; i < 2; i++) {
		ar[i] = c6x_pair_reg(&OP(0), true);
		ai[i] = c6x_pair_reg(&OP(0), false);
		br[i] = c6x_pair_reg(&OP(1), true);
		bi[i] = c6x_pair_reg(&OP(1), false);
	}
	if (!ar[0] || !br[0]) {
		for (ut8 i = 0; i < 2; i++) {
			rz_il_op_pure_free(ar[i]);
			rz_il_op_pure_free(ai[i]);
			rz_il_op_pure_free(br[i]);
			rz_il_op_pure_free(bi[i]);
		}
		return NULL;
	}
	// a x b = (ar br - ai bi) + j (ar bi + ai br); a x conj(b) = (ar br + ai bi) + j (ai br - ar bi)
	RzILOpBitVector *re_p = c6x_mul96(ar[0], br[0]);
	RzILOpBitVector *re_q = c6x_mul96(ai[0], bi[0]);
	RzILOpBitVector *re = c6x_q31_round(conj ? ADD(re_p, re_q) : SUB(re_p, re_q), NULL);
	RzILOpBitVector *im = conj ? c6x_q31_round(SUB(c6x_mul96(ai[1], br[1]), c6x_mul96(ar[1], bi[1])), NULL)
				   : c6x_q31_round(c6x_mul96(ar[1], bi[1]), c6x_mul96(ai[1], br[1]));
	return c6x_wr_dual(&OP(2), re, im);
}

// The real or imaginary part of CMATMPY's row \p k: src1_e x src2_k + src1_o x
// src2_(k + 2), src1 conjugated when \p conj, exact as the 34 bits the manual keeps.
static RzILOpBitVector *c6x_cmat_sum(const C6xInsn *insn, ut8 k, bool imag, bool conj) {
	RzILOpBitVector *sum = NULL;
	for (ut8 w = 0; w < 2; w++) {
		RzILOpPure *v = c6x_pair_reg(&OP(0), w);
		RzILOpPure *m = c6x_quad_reg(&OP(1), k + 2 * w);
		if (!v || !m) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(m);
			rz_il_op_pure_free(sum);
			return NULL;
		}
		// m x conj(v) is conj(v) x m
		RzILOpBitVector *t = LET("_a", m, LET("_b", v, c6x_cplx_sum(imag, conj)));
		sum = sum ? ADD(sum, t) : t;
	}
	return sum;
}

// CMATMPY and CMATMPYR1, and CCMATMPY and CCMATMPYR1 (\p conj): the src1 vector
// times the src2 matrix, saturated once at the end, or rounded (\p r1) into one
// word a row.
static RzILOpEffect *c6x_cmatmpy(const C6xInsn *insn, bool conj, bool r1) {
	RzILOpBitVector *re[2], *im[2];
	for (ut8 k = 0; k < 2; k++) {
		re[k] = c6x_cmat_sum(insn, k, false, conj);
		im[k] = c6x_cmat_sum(insn, k, true, conj);
	}
	if (!re[0] || !re[1] || !im[0] || !im[1]) {
		for (ut8 k = 0; k < 2; k++) {
			rz_il_op_pure_free(re[k]);
			rz_il_op_pure_free(im[k]);
		}
		return NULL;
	}
	if (r1) {
		RzILOpBitVector *w[2];
		for (ut8 k = 0; k < 2; k++) {
			w[k] = APPEND(c6x_cmpyr_half(re[k], true), c6x_cmpyr_half(im[k], true));
		}
		return c6x_wr_dual(&OP(2), w[1], w[0]);
	}
	RzILOpBitVector *r[4] = { c6x_sats32(im[0]), c6x_sats32(re[0]), c6x_sats32(im[1]), c6x_sats32(re[1]) };
	return c6x_wr_quad(&OP(2), r);
}

// The C66x multiplies of halfword and byte lanes, dot products and complex forms.
static RzILOpEffect *c6x_lift_c66x_mpy(const C6xInsn *insn, ut64 pc) {
	switch (insn->id) {
	case C6X_INS_MPYU2: {
		// the unsigned products of the low halfwords into dst_e, of the high into dst_o
		RzILOpPure *a = c6x_src(&OP(0));
		RzILOpPure *b = c6x_src(&OP(1));
		RzILOpPure *a2 = c6x_src(&OP(0));
		RzILOpPure *b2 = c6x_src(&OP(1));
		if (!a || !b || !a2 || !b2) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			rz_il_op_pure_free(a2);
			rz_il_op_pure_free(b2);
			return NULL;
		}
		return c6x_wr_dual(&OP(2), c6x_mpy_half(a, b, true, false), c6x_mpy_half(a2, b2, false, false));
	}
	case C6X_INS_DMPY2:
	case C6X_INS_DMPYU2:
	case C6X_INS_DSMPY2:
	case C6X_INS_DMPYU4:
	case C6X_INS_DMPYSU4: {
		// two MPY2s (MPYU2, SMPY2, MPYU4, MPYSU4), the even registers' into the low pair
		RzILOpBitVector *r[4];
		for (ut8 i = 0; i < 4; i++) {
			RzILOpPure *a = c6x_pair_reg(&OP(0), i / 2);
			RzILOpPure *b = c6x_pair_reg(&OP(1), i / 2);
			if (!a || !b) {
				rz_il_op_pure_free(a);
				rz_il_op_pure_free(b);
				r[i] = NULL;
				continue;
			}
			switch (insn->id) {
			case C6X_INS_DMPY2: r[i] = c6x_mpy_half(a, b, i & 1, true); break;
			case C6X_INS_DMPYU2: r[i] = c6x_mpy_half(a, b, i & 1, false); break;
			case C6X_INS_DSMPY2: r[i] = c6x_smpy_half(a, b, i & 1); break;
			default: r[i] = c6x_mpy4_pair(a, b, 2 * (i & 1), insn->id == C6X_INS_DMPYSU4); break;
			}
		}
		return c6x_wr_quad(&OP(2), r);
	}
	case C6X_INS_DOTP4H:
	case C6X_INS_DOTPSU4H: {
		// four halfword products of the pairs summed, saturated into a word or
		// whole into a pair
		bool su = insn->id == C6X_INS_DOTPSU4H;
		RzILOpPure *a[2] = { c6x_pair_reg(&OP(0), false), c6x_pair_reg(&OP(0), true) };
		RzILOpPure *b[2] = { c6x_pair_reg(&OP(1), false), c6x_pair_reg(&OP(1), true) };
		if (!a[0] || !a[1] || !b[0] || !b[1]) {
			for (ut8 i = 0; i < 2; i++) {
				rz_il_op_pure_free(a[i]);
				rz_il_op_pure_free(b[i]);
			}
			return NULL;
		}
		RzILOpBitVector *sum = c6x_dotp4h_sum(a, b, su);
		return OP(2).kind == C6X_OP_REGPAIR ? c6x_wr_pair64(&OP(2), sum) : c6x_wr(&OP(2), c6x_sats32(sum));
	}
	case C6X_INS_DDOTP4H:
	case C6X_INS_DDOTPSU4H: {
		// DOTP4H of the low pairs of the quads into dst_e, of the high into dst_o
		bool su = insn->id == C6X_INS_DDOTPSU4H;
		RzILOpBitVector *r[2] = { NULL, NULL };
		for (ut8 w = 0; w < 2; w++) {
			RzILOpPure *a[2] = { c6x_quad_reg(&OP(0), 2 * w), c6x_quad_reg(&OP(0), 2 * w + 1) };
			RzILOpPure *b[2] = { c6x_quad_reg(&OP(1), 2 * w), c6x_quad_reg(&OP(1), 2 * w + 1) };
			if (!a[0] || !a[1] || !b[0] || !b[1]) {
				for (ut8 i = 0; i < 2; i++) {
					rz_il_op_pure_free(a[i]);
					rz_il_op_pure_free(b[i]);
				}
				rz_il_op_pure_free(r[0]);
				return NULL;
			}
			r[w] = c6x_sats32(c6x_dotp4h_sum(a, b, su));
		}
		return c6x_wr_dual(&OP(2), r[1], r[0]);
	}
	case C6X_INS_DCMPY:
	case C6X_INS_DCCMPY: {
		// CMPY of each register of the pairs, src2 conjugated for DCCMPY
		bool conj = insn->id == C6X_INS_DCCMPY;
		RzILOpBitVector *r[4] = { NULL, NULL, NULL, NULL };
		RzILOpBitVector *p[2] = { NULL, NULL };
		for (ut8 w = 0; w < 2; w++) {
			RzILOpPure *a = c6x_pair_reg(&OP(0), w);
			RzILOpPure *b = c6x_pair_reg(&OP(1), w);
			if (!a || !b) {
				rz_il_op_pure_free(a);
				rz_il_op_pure_free(b);
				rz_il_op_pure_free(p[0]);
				return NULL;
			}
			p[w] = c6x_cmpy_word(a, b, conj);
		}
		static const char *const pv[2] = { "_ce", "_co" };
		for (ut8 i = 0; i < 4; i++) {
			r[i] = UNSIGNED(32, (i & 1) ? SHIFTR0(VARL(pv[i / 2]), U32(32)) : VARL(pv[i / 2]));
		}
		RzILOpEffect *wr = c6x_wr_quad(&OP(2), r);
		if (!wr) {
			rz_il_op_pure_free(p[0]);
			rz_il_op_pure_free(p[1]);
			return NULL;
		}
		return SEQ3(SETL("_ce", p[0]), SETL("_co", p[1]), wr);
	}
	case C6X_INS_DCMPYR1:
	case C6X_INS_DCCMPYR1: {
		// CMPYR1 of each register of the pairs, src2 conjugated for DCCMPYR1
		bool conj = insn->id == C6X_INS_DCCMPYR1;
		RzILOpBitVector *r[2] = { NULL, NULL };
		for (ut8 w = 0; w < 2; w++) {
			RzILOpPure *a = c6x_pair_reg(&OP(0), w);
			RzILOpPure *b = c6x_pair_reg(&OP(1), w);
			if (!a || !b) {
				rz_il_op_pure_free(a);
				rz_il_op_pure_free(b);
				rz_il_op_pure_free(r[0]);
				return NULL;
			}
			r[w] = c6x_cmpyr1_word(a, b, conj);
		}
		return c6x_wr_dual(&OP(2), r[1], r[0]);
	}
	case C6X_INS_CMPY32R1:
	case C6X_INS_CCMPY32R1:
		return c6x_cmpy32r1(insn, insn->id == C6X_INS_CCMPY32R1);
	case C6X_INS_CMATMPY: return c6x_cmatmpy(insn, false, false);
	case C6X_INS_CCMATMPY: return c6x_cmatmpy(insn, true, false);
	case C6X_INS_CMATMPYR1: return c6x_cmatmpy(insn, false, true);
	case C6X_INS_CCMATMPYR1: return c6x_cmatmpy(insn, true, true);
	case C6X_INS_QMPY32:
	case C6X_INS_QSMPY32R1: {
		// four MPY32s keeping the low word, or Q31 products rounded
		bool q31 = insn->id == C6X_INS_QSMPY32R1;
		RzILOpBitVector *r[4];
		for (ut8 i = 0; i < 4; i++) {
			RzILOpPure *a = c6x_quad_reg(&OP(0), i);
			RzILOpPure *b = c6x_quad_reg(&OP(1), i);
			if (!a || !b) {
				rz_il_op_pure_free(a);
				rz_il_op_pure_free(b);
				r[i] = NULL;
				continue;
			}
			r[i] = q31 ? c6x_q31_round(c6x_mul96(a, b), NULL) : MUL(a, b);
		}
		return c6x_wr_quad(&OP(2), r);
	}
	default:
		break;
	}
	return NULL;
}

// The C66x floating-point forms: those that are older ones landing sooner, and
// two- and four-way ones.
static RzILOpEffect *c6x_lift_c66x_fp(const C6xInsn *insn, ut64 pc) {
	switch (insn->id) {
	case C6X_INS_FADDSP: return c6x_fsp(insn, rz_il_op_new_fadd);
	case C6X_INS_FSUBSP: return c6x_fsp(insn, rz_il_op_new_fsub);
	case C6X_INS_FADDDP: return c6x_fdp(insn, rz_il_op_new_fadd);
	case C6X_INS_FSUBDP: return c6x_fdp(insn, rz_il_op_new_fsub);
	case C6X_INS_FMPYDP: return c6x_fdp(insn, rz_il_op_new_fmul);
	case C6X_INS_DADDSP:
	case C6X_INS_DSUBSP:
	case C6X_INS_DMPYSP: {
		// ADDSP, SUBSP or MPYSP of each register of the pairs
		c6x_fbin_op *mk = rz_il_op_new_fmul;
		if (insn->id != C6X_INS_DMPYSP) {
			mk = insn->id == C6X_INS_DADDSP ? rz_il_op_new_fadd : rz_il_op_new_fsub;
		}
		RzILOpBitVector *r[2] = { NULL, NULL };
		for (ut8 w = 0; w < 2; w++) {
			RzILOpPure *a = c6x_pair_reg(&OP(0), w);
			RzILOpPure *b = c6x_pair_reg(&OP(1), w);
			if (!a || !b) {
				rz_il_op_pure_free(a);
				rz_il_op_pure_free(b);
				rz_il_op_pure_free(r[0]);
				return NULL;
			}
			r[w] = F2BV(mk(RZ_FLOAT_RMODE_RNE, FLOATV32(a), FLOATV32(b)));
		}
		return c6x_wr_dual(&OP(2), r[1], r[0]);
	}
	case C6X_INS_QMPYSP: {
		RzILOpBitVector *r[4];
		for (ut8 i = 0; i < 4; i++) {
			RzILOpPure *a = c6x_quad_reg(&OP(0), i);
			RzILOpPure *b = c6x_quad_reg(&OP(1), i);
			if (!a || !b) {
				rz_il_op_pure_free(a);
				rz_il_op_pure_free(b);
				r[i] = NULL;
				continue;
			}
			r[i] = F2BV(rz_il_op_new_fmul(RZ_FLOAT_RMODE_RNE, FLOATV32(a), FLOATV32(b)));
		}
		return c6x_wr_quad(&OP(2), r);
	}
	case C6X_INS_CMPYSP: {
		// the four products of a complex multiply, the one that is subtracted
		// negated: dst_0 = e1 x o2, dst_1 = -(e1 x e2), dst_2 = o1 x e2, dst_3 = o1 x o2
		static const ut8 w1[4] = { 0, 0, 1, 1 };
		static const ut8 w2[4] = { 1, 0, 0, 1 };
		RzILOpBitVector *r[4];
		for (ut8 i = 0; i < 4; i++) {
			RzILOpPure *a = c6x_pair_reg(&OP(0), w1[i]);
			RzILOpPure *b = c6x_pair_reg(&OP(1), w2[i]);
			if (!a || !b) {
				rz_il_op_pure_free(a);
				rz_il_op_pure_free(b);
				r[i] = NULL;
				continue;
			}
			RzILOpFloat *p = rz_il_op_new_fmul(RZ_FLOAT_RMODE_RNE, FLOATV32(a), FLOATV32(b));
			r[i] = F2BV(i == 1 ? FNEG(p) : p);
		}
		return c6x_wr_quad(&OP(2), r);
	}
	case C6X_INS_DINTSP:
	case C6X_INS_DINTSPU:
	case C6X_INS_DSPINT: {
		// INTSP, INTSPU or SPINT of each register of the pair
		RzILOpBitVector *r[2] = { NULL, NULL };
		for (ut8 w = 0; w < 2; w++) {
			RzILOpPure *v = c6x_pair_reg(&OP(0), w);
			if (!v) {
				rz_il_op_pure_free(r[0]);
				return NULL;
			}
			switch (insn->id) {
			case C6X_INS_DINTSP: r[w] = F2BV(SINT2F(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE, v)); break;
			case C6X_INS_DINTSPU: r[w] = F2BV(INT2F(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE, v)); break;
			default: r[w] = F2SINT(32, RZ_FLOAT_RMODE_RNE, FLOATV32(v)); break;
			}
		}
		return c6x_wr_dual(&OP(1), r[1], r[0]);
	}
	case C6X_INS_DINTHSP:
	case C6X_INS_DINTHSPU: {
		// each halfword of src2 as a float, the lower into dst_e
		bool sgn = insn->id == C6X_INS_DINTHSP;
		RzILOpBitVector *r[2] = { NULL, NULL };
		for (ut8 w = 0; w < 2; w++) {
			RzILOpPure *v = c6x_src(&OP(0));
			if (!v) {
				rz_il_op_pure_free(r[0]);
				return NULL;
			}
			RzILOpBitVector *h = c6x_half16(v, w, sgn);
			r[w] = F2BV(sgn ? SINT2F(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE, h) : INT2F(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE, h));
		}
		return c6x_wr_dual(&OP(1), r[1], r[0]);
	}
	case C6X_INS_DSPINTH: {
		// SPINT of each register of the pair saturated to a halfword, dst_e's below
		RzILOpBitVector *h[2] = { NULL, NULL };
		for (ut8 w = 0; w < 2; w++) {
			RzILOpPure *v = c6x_pair_reg(&OP(0), w);
			if (!v) {
				rz_il_op_pure_free(h[0]);
				return NULL;
			}
			h[w] = c6x_sat_s(F2SINT(32, RZ_FLOAT_RMODE_RNE, FLOATV32(v)), 16);
		}
		return c6x_wr(&OP(1), APPEND(h[1], h[0]));
	}
	default:
		break;
	}
	return NULL;
}

// Floating-point arithmetic, compares and conversions.
static RzILOpEffect *c6x_lift_fp(const C6xInsn *insn, ut64 pc) {
	switch (insn->id) {
	case C6X_INS_ADDSP: {
		return c6x_fsp(insn, rz_il_op_new_fadd);
	}
	case C6X_INS_SUBSP: {
		return c6x_fsp(insn, rz_il_op_new_fsub);
	}
	case C6X_INS_MPYSP: {
		return c6x_fsp(insn, rz_il_op_new_fmul);
	}
	case C6X_INS_INTSP: {
		// signed 32-bit integer -> single-precision float
		RzILOpPure *s = c6x_src(&OP(0));
		return s ? c6x_wr(&OP(1), F2BV(SINT2F(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE, s))) : NULL;
	}
	case C6X_INS_INTSPU: {
		// unsigned 32-bit integer -> single-precision float
		RzILOpPure *s = c6x_src(&OP(0));
		return s ? c6x_wr(&OP(1), F2BV(INT2F(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE, s))) : NULL;
	}
	case C6X_INS_SPINT: {
		// single-precision float -> signed 32-bit integer, round to nearest even
		RzILOpPure *s = c6x_src(&OP(0));
		return s ? c6x_wr(&OP(1), F2SINT(32, RZ_FLOAT_RMODE_RNE, FLOATV32(s))) : NULL;
	}
	case C6X_INS_SPTRUNC: {
		// single-precision float -> signed 32-bit integer, truncating (round to zero)
		RzILOpPure *s = c6x_src(&OP(0));
		return s ? c6x_wr(&OP(1), F2SINT(32, RZ_FLOAT_RMODE_RTZ, FLOATV32(s))) : NULL;
	}
	case C6X_INS_CMPEQSP: {
		// single-precision float equality -> 1/0
		RzILOpPure *a = c6x_src(&OP(0));
		RzILOpPure *b = c6x_src(&OP(1));
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			return NULL;
		}
		return c6x_wr(&OP(2), ITE(FEQ(FLOATV32(a), FLOATV32(b)), U32(1), U32(0)));
	}
	case C6X_INS_CMPGTSP:
	case C6X_INS_CMPLTSP: {
		// single-precision ordered compare -> 1/0. FORDER is an ordered less-than,
		// so GT swaps the operands.
		bool gt = insn->id == C6X_INS_CMPGTSP;
		RzILOpPure *a = c6x_src(&OP(0));
		RzILOpPure *b = c6x_src(&OP(1));
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			return NULL;
		}
		RzILOpBool *cmp = gt ? FORDER(FLOATV32(b), FLOATV32(a)) : FORDER(FLOATV32(a), FLOATV32(b));
		return c6x_wr(&OP(2), ITE(cmp, U32(1), U32(0)));
	}
	case C6X_INS_CMPEQDP: {
		// double-precision float equality over register pairs -> 1/0
		RzILOpBitVector *a = c6x_pair64(&OP(0));
		RzILOpBitVector *b = c6x_pair64(&OP(1));
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			return NULL;
		}
		return c6x_wr(&OP(2), ITE(FEQ(FLOATV64(a), FLOATV64(b)), U32(1), U32(0)));
	}
	case C6X_INS_CMPGTDP:
	case C6X_INS_CMPLTDP: {
		// double-precision ordered compare over register pairs -> 1/0
		bool gt = insn->id == C6X_INS_CMPGTDP;
		RzILOpBitVector *a = c6x_pair64(&OP(0));
		RzILOpBitVector *b = c6x_pair64(&OP(1));
		if (!a || !b) {
			rz_il_op_pure_free(a);
			rz_il_op_pure_free(b);
			return NULL;
		}
		RzILOpBool *cmp = gt ? FORDER(FLOATV64(b), FLOATV64(a)) : FORDER(FLOATV64(a), FLOATV64(b));
		return c6x_wr(&OP(2), ITE(cmp, U32(1), U32(0)));
	}
	case C6X_INS_MPYSP2DP: {
		// two single-precision sources widened to double and multiplied into a pair
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpFloat *a = FCONVERT(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE, FLOATV32(s1));
		RzILOpFloat *b = FCONVERT(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE, FLOATV32(s2));
		return c6x_wr_pair64(&OP(2), F2BV(rz_il_op_new_fmul(RZ_FLOAT_RMODE_RNE, a, b)));
	}
	case C6X_INS_MPYSPDP: {
		// single-precision src1 widened to double, multiplied by double src2
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpBitVector *s2 = c6x_pair64(&OP(1));
		if (!s1 || !s2) {
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpFloat *a = FCONVERT(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE, FLOATV32(s1));
		return c6x_wr_pair64(&OP(2), F2BV(rz_il_op_new_fmul(RZ_FLOAT_RMODE_RNE, a, FLOATV64(s2))));
	}
	case C6X_INS_ADDDP: {
		return c6x_fdp(insn, rz_il_op_new_fadd);
	}
	case C6X_INS_SUBDP: {
		return c6x_fdp(insn, rz_il_op_new_fsub);
	}
	case C6X_INS_MPYDP: {
		return c6x_fdp(insn, rz_il_op_new_fmul);
	}
	case C6X_INS_INTDP: {
		// signed 32-bit integer -> double-precision float (into a pair)
		RzILOpPure *s = c6x_src(&OP(0));
		return s ? c6x_wr_pair64(&OP(1), F2BV(SINT2F(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE, s))) : NULL;
	}
	case C6X_INS_INTDPU: {
		// unsigned 32-bit integer -> double-precision float (into a pair), exact
		RzILOpPure *s = c6x_src(&OP(0));
		return s ? c6x_wr_pair64(&OP(1), F2BV(INT2F(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE, s))) : NULL;
	}
	case C6X_INS_SPDP: {
		// single-precision -> double-precision (into a pair)
		RzILOpPure *s = c6x_src(&OP(0));
		return s ? c6x_wr_pair64(&OP(1), F2BV(FCONVERT(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE, FLOATV32(s)))) : NULL;
	}
	case C6X_INS_DPINT:
	case C6X_INS_DPTRUNC: {
		// double-precision float (pair src2) -> signed 32-bit integer. DPINT
		// rounds to nearest even, DPTRUNC rounds toward zero.
		RzILOpBitVector *s = c6x_pair64(&OP(0));
		if (!s) {
			return NULL;
		}
		RzFloatRMode rmode = insn->id == C6X_INS_DPINT ? RZ_FLOAT_RMODE_RNE : RZ_FLOAT_RMODE_RTZ;
		return c6x_wr(&OP(1), F2SINT(32, rmode, FLOATV64(s)));
	}
	case C6X_INS_DPSP: {
		// double-precision (pair src2) -> single-precision
		RzILOpBitVector *s = c6x_pair64(&OP(0));
		return s ? c6x_wr(&OP(1), F2BV(FCONVERT(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE, FLOATV64(s)))) : NULL;
	}
	default:
		break;
	}
	return NULL;
}

// Min/max and the load/store forms.
static RzILOpEffect *c6x_lift_ldst(const C6xInsn *insn, ut64 pc) {
	switch (insn->id) {
	case C6X_INS_MIN2: {
		return c6x_minmax(insn, 2, true, true);
	}
	case C6X_INS_MAX2: {
		return c6x_minmax(insn, 2, true, false);
	}
	case C6X_INS_MINU4: {
		return c6x_minmax(insn, 4, false, true);
	}
	case C6X_INS_MAXU4: {
		return c6x_minmax(insn, 4, false, false);
	}
	case C6X_INS_LDW:
	case C6X_INS_LDNW: {
		// LDNW is a word load with no alignment requirement; byte-addressed
		// RzIL memory imposes none either, so it lifts like LDW.
		return c6x_load(insn, 4, false);
	}
	case C6X_INS_LDB: {
		return c6x_load(insn, 1, true);
	}
	case C6X_INS_LDBU: {
		return c6x_load(insn, 1, false);
	}
	case C6X_INS_LDH: {
		return c6x_load(insn, 2, true);
	}
	case C6X_INS_LDHU: {
		return c6x_load(insn, 2, false);
	}
	case C6X_INS_STW:
	case C6X_INS_STNW: {
		return c6x_store(insn, 4);
	}
	case C6X_INS_STB: {
		return c6x_store(insn, 1);
	}
	case C6X_INS_STH: {
		return c6x_store(insn, 2);
	}
	case C6X_INS_LDDW:
	case C6X_INS_LDNDW: {
		return c6x_load_pair(insn);
	}
	case C6X_INS_STDW:
	case C6X_INS_STNDW: {
		return c6x_store_pair(insn);
	}
	default:
		break;
	}
	return NULL;
}

// Dispatch on the opcode identity; each group lifts a family of related forms.
static RzILOpEffect *c6x_lift_core(const C6xInsn *insn, ut64 pc) {
	switch (insn->id) {
	case C6X_INS_ADDKPC:
	case C6X_INS_B:
	case C6X_INS_BDEC:
	case C6X_INS_BNOP:
	case C6X_INS_BPOS:
	case C6X_INS_CALLP:
	case C6X_INS_DINT:
	case C6X_INS_IDLE:
	case C6X_INS_NOP:
	case C6X_INS_RINT:
		return c6x_lift_control(insn, pc);
	case C6X_INS_MV:
	case C6X_INS_MVC:
	case C6X_INS_MVD:
	case C6X_INS_MVK:
	case C6X_INS_MVKH:
		return c6x_lift_move(insn, pc);
	case C6X_INS_ADD:
	case C6X_INS_ADDU:
	case C6X_INS_AND:
	case C6X_INS_ANDN:
	case C6X_INS_CMPEQ:
	case C6X_INS_CMPEQ2:
	case C6X_INS_CMPEQ4:
	case C6X_INS_CMPGT:
	case C6X_INS_CMPGT2:
	case C6X_INS_CMPGTU:
	case C6X_INS_CMPGTU4:
	case C6X_INS_CMPLT:
	case C6X_INS_CMPLTU:
	case C6X_INS_OR:
	case C6X_INS_SUB:
	case C6X_INS_SUBU:
	case C6X_INS_XOR:
		return c6x_lift_alu(insn, pc);
	case C6X_INS_ABS:
	case C6X_INS_ABS2:
	case C6X_INS_ABSDP:
	case C6X_INS_ABSSP:
	case C6X_INS_BITC4:
	case C6X_INS_BITR:
	case C6X_INS_CLR:
	case C6X_INS_DEAL:
	case C6X_INS_EXT:
	case C6X_INS_EXTU:
	case C6X_INS_LMBD:
	case C6X_INS_NEG:
	case C6X_INS_NORM:
	case C6X_INS_NOT:
	case C6X_INS_SAT:
	case C6X_INS_SET:
	case C6X_INS_SHFL:
	case C6X_INS_XPND2:
	case C6X_INS_XPND4:
	case C6X_INS_ZERO:
		return c6x_lift_bitop(insn, pc);
	case C6X_INS_ADDAB:
	case C6X_INS_ADDAD:
	case C6X_INS_ADDAH:
	case C6X_INS_ADDAW:
	case C6X_INS_ADDK:
	case C6X_INS_AVG2:
	case C6X_INS_AVGU4:
	case C6X_INS_PACKH4:
	case C6X_INS_PACKL4:
	case C6X_INS_ROTL:
	case C6X_INS_RPACK2:
	case C6X_INS_SADD:
	case C6X_INS_SADDU4:
	case C6X_INS_SADDUS2:
	case C6X_INS_SHL:
	case C6X_INS_SHLMB:
	case C6X_INS_SHR:
	case C6X_INS_SHR2:
	case C6X_INS_SHRMB:
	case C6X_INS_SHRU:
	case C6X_INS_SHRU2:
	case C6X_INS_SSHL:
	case C6X_INS_SSHVL:
	case C6X_INS_SSHVR:
	case C6X_INS_SSUB:
	case C6X_INS_SUBAB:
	case C6X_INS_SUBAH:
	case C6X_INS_SUBAW:
	case C6X_INS_SUBC:
	case C6X_INS_SWAP4:
		return c6x_lift_packed(insn, pc);
	case C6X_INS_MPY:
	case C6X_INS_MPY32:
	case C6X_INS_MPY32SU:
	case C6X_INS_MPY32U:
	case C6X_INS_MPY32US:
	case C6X_INS_MPYH:
	case C6X_INS_MPYHL:
	case C6X_INS_MPYHLU:
	case C6X_INS_MPYHSLU:
	case C6X_INS_MPYHSU:
	case C6X_INS_MPYHU:
	case C6X_INS_MPYHULS:
	case C6X_INS_MPYHUS:
	case C6X_INS_MPYI:
	case C6X_INS_MPYID:
	case C6X_INS_MPYLH:
	case C6X_INS_MPYLHU:
	case C6X_INS_MPYLSHU:
	case C6X_INS_MPYLUHS:
	case C6X_INS_MPYSU:
	case C6X_INS_MPYU:
	case C6X_INS_MPYUS:
	case C6X_INS_SMPY:
	case C6X_INS_SMPYH:
	case C6X_INS_SMPYHL:
	case C6X_INS_SMPYLH:
		return c6x_lift_mpy(insn, pc);
	case C6X_INS_ADD2:
	case C6X_INS_ADD4:
	case C6X_INS_PACK2:
	case C6X_INS_PACKH2:
	case C6X_INS_PACKHL2:
	case C6X_INS_PACKLH2:
	case C6X_INS_SADD2:
	case C6X_INS_SPACK2:
	case C6X_INS_SSUB2:
	case C6X_INS_SUB2:
	case C6X_INS_SUB4:
	case C6X_INS_UNPKHU4:
	case C6X_INS_UNPKLU4:
		return c6x_lift_pack(insn, pc);
	case C6X_INS_CMPY:
	case C6X_INS_CMPYR:
	case C6X_INS_CMPYR1:
	case C6X_INS_DDOTPH2:
	case C6X_INS_DDOTPL2:
	case C6X_INS_DOTP2:
	case C6X_INS_DOTPN2:
	case C6X_INS_DOTPNRSU2:
	case C6X_INS_DOTPRSU2:
	case C6X_INS_DOTPSU4:
	case C6X_INS_DOTPU4:
	case C6X_INS_MPY2:
	case C6X_INS_MPYHI:
	case C6X_INS_MPYHIR:
	case C6X_INS_MPYLI:
	case C6X_INS_MPYLIR:
	case C6X_INS_MPYSU4:
	case C6X_INS_MPYU4:
	case C6X_INS_SMPY2:
	case C6X_INS_SPACKU4:
		return c6x_lift_dotp(insn, pc);
	case C6X_INS_ADDSUB:
	case C6X_INS_ADDSUB2:
	case C6X_INS_DADD:
	case C6X_INS_DDOTP4:
	case C6X_INS_DDOTPH2R:
	case C6X_INS_DDOTPL2R:
	case C6X_INS_DMV:
	case C6X_INS_DPACK2:
	case C6X_INS_DPACKX2:
	case C6X_INS_DSUB:
	case C6X_INS_MPY2IR:
	case C6X_INS_SADDSUB:
	case C6X_INS_SADDSUB2:
	case C6X_INS_SHFL3:
	case C6X_INS_SMPY32:
	case C6X_INS_SUBABS4:
		return c6x_lift_dual(insn, pc);
	case C6X_INS_GMPY:
	case C6X_INS_GMPY4:
	case C6X_INS_XORMPY:
		return c6x_lift_gf(insn, pc);
	case C6X_INS_CROT270:
	case C6X_INS_CROT90:
	case C6X_INS_DADD2:
	case C6X_INS_DAPYS2:
	case C6X_INS_DAVG2:
	case C6X_INS_DAVGNR2:
	case C6X_INS_DAVGNRU4:
	case C6X_INS_DAVGU4:
	case C6X_INS_DCMPEQ2:
	case C6X_INS_DCMPEQ4:
	case C6X_INS_DCMPGT2:
	case C6X_INS_DCMPGTU4:
	case C6X_INS_DCROT270:
	case C6X_INS_DCROT90:
	case C6X_INS_DMAX2:
	case C6X_INS_DMAXU4:
	case C6X_INS_DMIN2:
	case C6X_INS_DMINU4:
	case C6X_INS_DMVD:
	case C6X_INS_DPACKH2:
	case C6X_INS_DPACKH4:
	case C6X_INS_DPACKHL2:
	case C6X_INS_DPACKL2:
	case C6X_INS_DPACKL4:
	case C6X_INS_DPACKLH2:
	case C6X_INS_DPACKLH4:
	case C6X_INS_DSADD:
	case C6X_INS_DSADD2:
	case C6X_INS_DSHL:
	case C6X_INS_DSHL2:
	case C6X_INS_DSHR:
	case C6X_INS_DSHR2:
	case C6X_INS_DSHRU:
	case C6X_INS_DSHRU2:
	case C6X_INS_DSPACKU4:
	case C6X_INS_DSSUB:
	case C6X_INS_DSSUB2:
	case C6X_INS_DSUB2:
	case C6X_INS_DXPND2:
	case C6X_INS_DXPND4:
	case C6X_INS_LAND:
	case C6X_INS_LANDN:
	case C6X_INS_LOR:
	case C6X_INS_MFENCE:
	case C6X_INS_SHL2:
	case C6X_INS_UNPKBU4:
	case C6X_INS_UNPKH2:
	case C6X_INS_UNPKHU2:
		return c6x_lift_c66x(insn, pc);
	case C6X_INS_CCMATMPY:
	case C6X_INS_CCMATMPYR1:
	case C6X_INS_CCMPY32R1:
	case C6X_INS_CMATMPY:
	case C6X_INS_CMATMPYR1:
	case C6X_INS_CMPY32R1:
	case C6X_INS_DCCMPY:
	case C6X_INS_DCCMPYR1:
	case C6X_INS_DCMPY:
	case C6X_INS_DCMPYR1:
	case C6X_INS_DDOTP4H:
	case C6X_INS_DDOTPSU4H:
	case C6X_INS_DMPY2:
	case C6X_INS_DMPYSU4:
	case C6X_INS_DMPYU2:
	case C6X_INS_DMPYU4:
	case C6X_INS_DOTP4H:
	case C6X_INS_DOTPSU4H:
	case C6X_INS_DSMPY2:
	case C6X_INS_MPYU2:
	case C6X_INS_QMPY32:
	case C6X_INS_QSMPY32R1:
		return c6x_lift_c66x_mpy(insn, pc);
	case C6X_INS_CMPYSP:
	case C6X_INS_DADDSP:
	case C6X_INS_DINTHSP:
	case C6X_INS_DINTHSPU:
	case C6X_INS_DINTSP:
	case C6X_INS_DINTSPU:
	case C6X_INS_DMPYSP:
	case C6X_INS_DSPINT:
	case C6X_INS_DSPINTH:
	case C6X_INS_DSUBSP:
	case C6X_INS_FADDDP:
	case C6X_INS_FADDSP:
	case C6X_INS_FMPYDP:
	case C6X_INS_FSUBDP:
	case C6X_INS_FSUBSP:
	case C6X_INS_QMPYSP:
		return c6x_lift_c66x_fp(insn, pc);
	case C6X_INS_ADDDP:
	case C6X_INS_ADDSP:
	case C6X_INS_CMPEQDP:
	case C6X_INS_CMPEQSP:
	case C6X_INS_CMPGTDP:
	case C6X_INS_CMPGTSP:
	case C6X_INS_CMPLTDP:
	case C6X_INS_CMPLTSP:
	case C6X_INS_DPINT:
	case C6X_INS_DPSP:
	case C6X_INS_DPTRUNC:
	case C6X_INS_INTDP:
	case C6X_INS_INTDPU:
	case C6X_INS_INTSP:
	case C6X_INS_INTSPU:
	case C6X_INS_MPYDP:
	case C6X_INS_MPYSP:
	case C6X_INS_MPYSP2DP:
	case C6X_INS_MPYSPDP:
	case C6X_INS_SPDP:
	case C6X_INS_SPINT:
	case C6X_INS_SPTRUNC:
	case C6X_INS_SUBDP:
	case C6X_INS_SUBSP:
		return c6x_lift_fp(insn, pc);
	case C6X_INS_LDB:
	case C6X_INS_LDBU:
	case C6X_INS_LDDW:
	case C6X_INS_LDH:
	case C6X_INS_LDHU:
	case C6X_INS_LDNDW:
	case C6X_INS_LDNW:
	case C6X_INS_LDW:
	case C6X_INS_MAX2:
	case C6X_INS_MAXU4:
	case C6X_INS_MIN2:
	case C6X_INS_MINU4:
	case C6X_INS_STB:
	case C6X_INS_STDW:
	case C6X_INS_STH:
	case C6X_INS_STNDW:
	case C6X_INS_STNW:
	case C6X_INS_STW:
		return c6x_lift_ldst(insn, pc);
	default:
		// Reached by design: the fetch-packet header is not an instruction, and
		// a SPLOOP and its buffer controls are lifted with the whole loop by
		// c6x_lift_window(). Returning nothing leaves the caller to fall back,
		// which is not a bug to warn on.
		return NULL;
	}
}

// Run \p eff, which is consumed, only when the predicate of \p insn holds:
// z = 1 tests the register for zero, z = 0 for not being zero.
static RzILOpEffect *c6x_predicated(const C6xInsn *insn, RZ_NULLABLE RzILOpEffect *eff) {
	if (!eff) {
		return NULL;
	}
	const char *pred = c6x_pred_name(insn->creg);
	if (!pred) {
		return eff; // unconditional
	}
	RzILOpBool *cond = insn->z ? IS_ZERO(c6x_reg_read(pred)) : NON_ZERO(c6x_reg_read(pred));
	return BRANCH(cond, eff, NOP());
}

// The bytes a load reads, which scale its offset.
static ut8 c6x_load_bytes(const C6xInsn *insn) {
	switch (insn->id) {
	case C6X_INS_LDB:
	case C6X_INS_LDBU:
		return 1;
	case C6X_INS_LDH:
	case C6X_INS_LDHU:
		return 2;
	case C6X_INS_LDDW:
	case C6X_INS_LDNDW:
		return 8;
	default:
		return 4;
	}
}

/** Lift a decoded instruction to RzIL, or NULL when the form is not yet lifted.
 *  \p pc is the instruction address (for PC-relative results). */
RZ_IPI RZ_OWN RzILOpEffect *c6x_lift(const C6xInsn *insn, ut64 pc) {
	rz_return_val_if_fail(insn, NULL);
	return c6x_predicated(insn, c6x_lift_core(insn, pc));
}

/**
 * \brief Whether \p insn loads into the register its address mode updates.
 *
 * It writes that register twice: the address in its own cycle and, after its
 * delay slots, what it loaded (SPRUFE8B, LDW: baseR is written in E1, dst in
 * E5; no delay slots for the address modification, four for the loaded value).
 */
RZ_IPI bool c6x_load_into_base(const C6xInsn *insn) {
	rz_return_val_if_fail(insn, false);
	switch (insn->id) {
	case C6X_INS_LDB:
	case C6X_INS_LDBU:
	case C6X_INS_LDH:
	case C6X_INS_LDHU:
	case C6X_INS_LDW:
	case C6X_INS_LDNW:
	case C6X_INS_LDDW:
	case C6X_INS_LDNDW:
		break;
	default:
		return false;
	}
	if (insn->nops != 2 || OP(0).kind != C6X_OP_MEM || !c6x_ea_modifies(&OP(0)) || OP(0).v.mem.base_side != OP(1).v.reg.side) {
		return false;
	}
	return OP(1).v.reg.num == OP(0).v.mem.base || (OP(1).kind == C6X_OP_REGPAIR && OP(1).v.reg.num + 1 == OP(0).v.mem.base);
}

/**
 * \brief Lift one of the two writes of a load into its own address register.
 *
 * Both read the registers as the instruction found them.
 *
 * \param insn A load c6x_load_into_base() holds for.
 * \param pc Its address.
 * \param update The address update rather than the load.
 */
RZ_IPI RZ_OWN RzILOpEffect *c6x_lift_load_part(const C6xInsn *insn, ut64 pc, bool update) {
	rz_return_val_if_fail(insn && c6x_load_into_base(insn), NULL);
	if (update) {
		RzILOpEffect *wb = NULL;
		bool pre;
		rz_il_op_pure_free(c6x_ea(&OP(0), c6x_load_bytes(insn), &wb, &pre));
		return c6x_predicated(insn, wb);
	}
	// the same access with its address computed and not written back
	C6xInsn load = *insn;
	C6xOperand *m = &load.ops[0];
	switch (m->v.mem.mode) {
	case C6X_AM_PREDEC_CST: m->v.mem.mode = C6X_AM_NEG_CST; break;
	case C6X_AM_PREINC_CST: m->v.mem.mode = C6X_AM_POS_CST; break;
	case C6X_AM_PREDEC_REG: m->v.mem.mode = C6X_AM_NEG_REG; break;
	case C6X_AM_PREINC_REG: m->v.mem.mode = C6X_AM_POS_REG; break;
	default:
		// post-modify reads at the base
		m->v.mem.mode = C6X_AM_POS_CST;
		m->v.mem.off_cst = 0;
		break;
	}
	return c6x_lift(&load, pc);
}

/**
 * \brief Lift CALLP: write the return address to the link register, then jump.
 *
 * CALLP returns to the execute packet after its own (SPRUFE8B, CALLP), which
 * only a view of the packet gives.
 *
 * \param insn The CALLP.
 * \param pc Its own address; the displacement counts from its fetch packet.
 * \param ret The return address.
 */
RZ_IPI RZ_OWN RzILOpEffect *c6x_lift_call(const C6xInsn *insn, ut64 pc, ut64 ret) {
	rz_return_val_if_fail(insn, NULL);
	RzILOpBitVector *tgt = c6x_branch_target(insn, pc);
	if (!tgt) {
		return NULL;
	}
	if (insn->nops < 2 || OP(1).kind != C6X_OP_REG) {
		return JMP(tgt);
	}
	const char *link = c6x_reg_name(OP(1).v.reg.side, OP(1).v.reg.num);
	return SEQ2(c6x_reg_write(link, U32((ut32)ret)), JMP(tgt));
}

#include <rz_il/rz_il_opbuilder_end.h>
