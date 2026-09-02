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
 * Two architectural notes bound what is modelled here. C6000 is a VLIW: every
 * instruction of an execute packet reads its sources at the packet start and
 * writes at its end, so within a packet an instruction never sees another's
 * result. The RzIL VM steps sequentially, so a "|| mv a,b || mv b,a" swap is
 * not modelled exactly; ordinary (non-swapping) parallel code lifts correctly.
 * Branches have five delay slots and are left unlifted for now, so IL covers
 * straight-line data flow.
 */

#include <rz_util.h>
#include "c6x.h"

/* RzIL VM */

// IL-VM register bindings: the 32+32 general-purpose registers (a0-a31,
// b0-b31), pce1 (the program counter, named as the register profile does), then
// the control registers MVC reaches -- the set common to every C6000, followed
// by the C64x+ extension. A single flat table doubles as the name lookup for a
// general-register operand: side A occupies indices 0-31 and side B 32-63, so
// c6x_reg_name(side, num) indexes it directly and never reaches pce1 or the
// control registers past it.
// Predicate registers by creg code; 0 and 7 are reserved.
static const char *const c6x_pred_regs[8] = { NULL, "b0", "b1", "b2", "a1", "a2", "a0", NULL };

static const char *const c6x_il_regs[] = {
	"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
	"a8", "a9", "a10", "a11", "a12", "a13", "a14", "a15",
	"a16", "a17", "a18", "a19", "a20", "a21", "a22", "a23",
	"a24", "a25", "a26", "a27", "a28", "a29", "a30", "a31",
	"b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
	"b8", "b9", "b10", "b11", "b12", "b13", "b14", "b15",
	"b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23",
	"b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31",
	"pce1",
	// control registers common to all C6000 variants
	"amr", "csr", "gfpgfr", "icr", "ier", "ifr", "irp", "isr", "istp", "nrp",
	// C64x+ control-register extension
	"dier", "dnum", "ecr", "efr", "gplya", "gplyb", "ierr", "ilc", "itsr",
	"ntsr", "rep", "rilc", "ssr", "tsch", "tscl", "tsr",
	NULL
};

// C62x/C67x expose only the low 16 registers per side and lack the C64x+
// control-register extension; their register profile omits a16-a31/b16-b31 and
// that extension, so bind only the matching subset -- the IL-VM setup fails if
// asked to bind a register the profile never declares.
static const char *const c6x_il_regs16[] = {
	"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
	"a8", "a9", "a10", "a11", "a12", "a13", "a14", "a15",
	"b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
	"b8", "b9", "b10", "b11", "b12", "b13", "b14", "b15",
	"pce1",
	"amr", "csr", "gfpgfr", "icr", "ier", "ifr", "irp", "isr", "istp", "nrp",
	NULL
};

/** RzIL configuration (register bindings, PC/memory widths) for the C6000 VM. */
RZ_IPI RzAnalysisILConfig *tms320_c6x_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	// 32-bit PC over a byte-addressed space, little-endian.
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(32, false, 32);
	if (!cfg) {
		return NULL;
	}
	const C6xArchDesc *desc = c6x_desc_from_cpu(rz_analysis_get_cpu(analysis));
	cfg->reg_bindings = (const char **)((desc && desc->num_regs <= 16) ? c6x_il_regs16 : c6x_il_regs);
	return cfg;
}

#include <rz_il/rz_il_opbuilder_begin.h>

// Global-variable name of register `num` on side `side` (0 = A, 1 = B).
static const char *c6x_reg_name(ut8 side, ut8 num) {
	return c6x_il_regs[(side & 1) * 32 + (num & 31)];
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
 *
 * They are the plain global accessors. Packet semantics -- every instruction in
 * an execute packet seeing the register file as it stood when the packet issued
 * -- are reached instead by running each slot against restored state and
 * applying the captured results together, which leaves these untouched.
 */
static RzILOpPure *c6x_reg_read(const char *name) {
	return VARG(name);
}

static RzILOpEffect *c6x_reg_write(const char *name, RzILOpPure *v) {
	return SETG(name, v);
}

// 32-bit value of a register or immediate source operand, or NULL for kinds
// this core does not model as a scalar (pairs, quads, control regs, memory).
static RzILOpPure *c6x_src(const C6xOperand *o) {
	switch (o->kind) {
	case C6X_OP_REG:
		return c6x_reg_read(c6x_reg_name(o->v.reg.side, o->v.reg.num));
	case C6X_OP_IMM:
		return S32(o->v.imm.value);
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

// Write `v` to a register destination, or free it and fail for other kinds.
static RzILOpEffect *c6x_wr(const C6xOperand *o, RzILOpPure *v) {
	if (o->kind == C6X_OP_REG) {
		return c6x_reg_write(c6x_reg_name(o->v.reg.side, o->v.reg.num), v);
	}
	rz_warn_if_reached();
	rz_il_op_pure_free(v);
	return NULL;
}

// dst = src1 OP src2, the shared shape of the register/immediate ALU ops. `mk`
// builds the value from the two decoded sources.
static RzILOpEffect *c6x_alu3(const C6xInsn *insn, rz_il_pure_2args_op *mk) {
	RzILOpPure *s1 = c6x_src(&OP(0));
	RzILOpPure *s2 = c6x_src(&OP(1));
	if (!s1 || !s2) {
		rz_warn_if_reached();
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	return c6x_wr(&OP(2), mk(s1, s2));
}

// dst = (src1 CMP src2) ? 1 : 0, the shared shape of the compare ops.
static RzILOpEffect *c6x_cmp(const C6xInsn *insn, rz_il_bool_2args_op *mk) {
	RzILOpPure *s1 = c6x_src(&OP(0));
	RzILOpPure *s2 = c6x_src(&OP(1));
	if (!s1 || !s2) {
		rz_warn_if_reached();
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
		rz_warn_if_reached();
		rz_il_op_pure_free(s1);
		rz_il_op_pure_free(s2);
		return NULL;
	}
	return c6x_wr(&OP(2), F2BV(mk(RZ_FLOAT_RMODE_RNE, FLOATV32(s1), FLOATV32(s2))));
}

// Read a register pair as one 64-bit value: the even member is the low word and
// the odd member the high word, matching how LDDW loads a doubleword.
static RzILOpBitVector *c6x_pair64(const C6xOperand *o) {
	rz_return_val_if_fail(o->kind == C6X_OP_REGPAIR, NULL);
	return APPEND(c6x_reg_read(c6x_reg_name(o->v.reg.side, o->v.reg.num + 1)), c6x_reg_read(c6x_reg_name(o->v.reg.side, o->v.reg.num)));
}

// Write a 64-bit value into a register pair (low word -> even, high -> odd),
// binding it to a local so both halves read the same result.
static RzILOpEffect *c6x_wr_pair64(const C6xOperand *o, RzILOpBitVector *v) {
	if (o->kind != C6X_OP_REGPAIR) {
		rz_warn_if_reached();
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

// Load: dst = extend(mem[EA]). `sign` selects sign- vs zero-extension to 32.
static RzILOpEffect *c6x_load(const C6xInsn *insn, ut8 bytes, bool sign) {
	// single-register widths only; pairs go through c6x_load_pair
	rz_return_val_if_fail(OP(1).kind == C6X_OP_REG && bytes <= 4, NULL);
	RzILOpEffect *wb;
	bool pre;
	RzILOpPure *ea = c6x_ea(&OP(0), bytes, &wb, &pre);
	if (!ea) {
		return NULL;
	}
	RzILOpPure *val = bytes == 4 ? LOADW(32, ea) : (sign ? SIGNED(32, LOADW(bytes * 8, ea)) : UNSIGNED(32, LOADW(bytes * 8, ea)));
	RzILOpEffect *set = c6x_reg_write(c6x_reg_name(OP(1).v.reg.side, OP(1).v.reg.num), val);
	return c6x_mem_seq(set, wb, pre);
}

// Store: mem[EA] = truncate(src). Pairs use c6x_store_pair.
static RzILOpEffect *c6x_store(const C6xInsn *insn, ut8 bytes) {
	rz_return_val_if_fail(OP(0).kind == C6X_OP_REG && bytes <= 4, NULL);
	RzILOpEffect *wb;
	bool pre;
	RzILOpPure *ea = c6x_ea(&OP(1), bytes, &wb, &pre);
	if (!ea) {
		return NULL;
	}
	RzILOpPure *src = c6x_reg_read(c6x_reg_name(OP(0).v.reg.side, OP(0).v.reg.num));
	RzILOpEffect *st = bytes == 4 ? STOREW(ea, src) : STOREW(ea, UNSIGNED(bytes * 8, src));
	return c6x_mem_seq(st, wb, pre);
}

// Doubleword load into a register pair: the even member gets mem[EA] and the
// odd member mem[EA+4] (little-endian keeps the low word at the lower address).
// The address is bound to a local so both accesses share one base computation.
// LDNDW behaves the same here; only its alignment requirement differs.
static RzILOpEffect *c6x_load_pair(const C6xInsn *insn) {
	rz_return_val_if_fail(OP(1).kind == C6X_OP_REGPAIR, NULL);
	RzILOpEffect *wb;
	bool pre;
	RzILOpPure *ea = c6x_ea(&OP(0), 8, &wb, &pre);
	if (!ea) {
		return NULL;
	}
	const char *lo = c6x_reg_name(OP(1).v.reg.side, OP(1).v.reg.num);
	const char *hi = c6x_reg_name(OP(1).v.reg.side, OP(1).v.reg.num + 1);
	RzILOpEffect *body = SEQ3(SETL("ea", ea),
		c6x_reg_write(lo, LOADW(32, VARL("ea"))),
		c6x_reg_write(hi, LOADW(32, ADD(VARL("ea"), U32(4)))));
	return c6x_mem_seq(body, wb, pre);
}

// Doubleword store from a register pair: mem[EA] <- even member, mem[EA+4] <-
// odd member. STDW and the non-aligned STNDW share this data path.
static RzILOpEffect *c6x_store_pair(const C6xInsn *insn) {
	rz_return_val_if_fail(OP(0).kind == C6X_OP_REGPAIR, NULL);
	RzILOpEffect *wb;
	bool pre;
	RzILOpPure *ea = c6x_ea(&OP(1), 8, &wb, &pre);
	if (!ea) {
		return NULL;
	}
	const char *lo = c6x_reg_name(OP(0).v.reg.side, OP(0).v.reg.num);
	const char *hi = c6x_reg_name(OP(0).v.reg.side, OP(0).v.reg.num + 1);
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
// search, at the cost of being an effect rather than a pure expression.
static RzILOpEffect *c6x_clz_into(const char *out, RzILOpPure *x, ut32 width) {
	return SEQ3(
		SETL("_clzv", x),
		SETL(out, U32(0)),
		REPEAT(AND(ULT(VARL(out), U32(width)), INV(MSB(VARL("_clzv")))),
			SEQ2(SETL("_clzv", SHIFTL0(VARL("_clzv"), UN(width, 1))),
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

// Control transfer, no-ops and the return-address helper.
static RzILOpEffect *c6x_lift_control(const C6xInsn *insn, ut64 pc) {
	switch (insn->id) {
	case C6X_INS_NOP:
	case C6X_INS_IDLE: {
		return NOP();
	}
	case C6X_INS_B:
	case C6X_INS_BNOP:
	case C6X_INS_CALLP: {
		// Control transfer. The target is either a register or a PC-relative
		// displacement off the fetch-packet-aligned address (PCE1). The five
		// delay slots are not modelled -- the sequential VM takes the branch at
		// once -- but the target is exact. Call forms (a link register in
		// ops[1]) also record the return address, the word after the branch.
		const C6xOperand *t = &OP(0);
		RzILOpBitVector *tgt;
		if (t->kind == C6X_OP_PCREL) {
			tgt = U32((ut32)(c6x_packet_base(pc) + t->v.imm.value));
		} else if (t->kind == C6X_OP_REG) {
			tgt = c6x_reg_read(c6x_reg_name(t->v.reg.side, t->v.reg.num));
		} else if (t->kind == C6X_OP_CTRLREG) {
			tgt = c6x_reg_read(t->v.ctrl); // e.g. b irp / b nrp (return from interrupt)
		} else {
			return NULL;
		}
		if (insn->nops > 1 && OP(1).kind == C6X_OP_REG) {
			return SEQ2(c6x_reg_write(c6x_reg_name(OP(1).v.reg.side, OP(1).v.reg.num), U32((ut32)(pc + insn->size))), JMP(tgt));
		}
		return JMP(tgt);
	}
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
		const char *sn = s->kind == C6X_OP_CTRLREG ? s->v.ctrl : (s->kind == C6X_OP_REG ? c6x_reg_name(s->v.reg.side, s->v.reg.num) : NULL);
		const char *dn = d->kind == C6X_OP_CTRLREG ? d->v.ctrl : (d->kind == C6X_OP_REG ? c6x_reg_name(d->v.reg.side, d->v.reg.num) : NULL);
		return sn && dn ? c6x_reg_write(dn, c6x_reg_read(sn)) : NULL;
	}
	default:
		break;
	}
	return NULL;
}

// Integer add/subtract, bitwise and compare.
static RzILOpEffect *c6x_lift_alu(const C6xInsn *insn, ut64 pc) {
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
		// dst = src2 & ~src1 (src1 is the complemented operand)
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_warn_if_reached();
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		return c6x_wr(&OP(2), LOGAND(s2, LOGNOT(s1)));
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
	case C6X_INS_CMPGT:
	case C6X_INS_CMPGTU: {
		bool uns = insn->id == C6X_INS_CMPGTU;
		if (OP(1).kind == C6X_OP_REGPAIR) {
			// long form: a 32-bit src1 compared against a 40-bit long src2
			RzILOpPure *s1 = c6x_src(&OP(0));
			if (!s1) {
				return NULL;
			}
			RzILOpBool *cmp = uns
				? UGT(UNSIGNED(64, s1), LOGAND(c6x_pair64(&OP(1)), SN(64, 0xffffffffffLL)))
				: SGT(SIGNED(64, s1), c6x_long40(&OP(1)));
			return c6x_wr(&OP(2), ITE(cmp, U32(1), U32(0)));
		}
		return c6x_cmp(insn, uns ? rz_il_op_new_ugt : rz_il_op_new_sgt);
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
			rz_warn_if_reached();
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
		// bit field set/clear: dst = src2 set/cleared over bits [csta, cstb].
		// Only the constant form is modeled; the register form takes the field
		// bounds from src1 at run time.
		if (OP(1).kind != C6X_OP_IMM || OP(2).kind != C6X_OP_IMM) {
			return NULL;
		}
		ut32 csta = (ut32)OP(1).v.imm.value & 0x1f;
		ut32 cstb = (ut32)OP(2).v.imm.value & 0x1f;
		if (cstb < csta) {
			return NULL;
		}
		ut32 width = cstb - csta + 1;
		ut32 mask = width >= 32 ? 0xffffffff : (((ut32)1 << width) - 1) << csta;
		RzILOpPure *s = c6x_src(&OP(0));
		if (!s) {
			return NULL;
		}
		RzILOpPure *v = insn->id == C6X_INS_SET ? LOGOR(s, U32(mask)) : LOGAND(s, U32(~mask));
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
		// subtract-conditional divide step: d = src1 - src2;
		// dst = d >= 0 ? (d << 1) | 1 : src1 << 1
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_warn_if_reached();
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpPure *v = LET("_s1", s1,
			LET("_df", SUB(VARLP("_s1"), s2),
				ITE(SGE(VARLP("_df"), S32(0)),
					LOGOR(SHIFTL0(VARLP("_df"), U32(1)), U32(1)),
					SHIFTL0(VARLP("_s1"), U32(1)))));
		return c6x_wr(&OP(2), v);
	}
	case C6X_INS_RPACK2: {
		// shift src1 and src2 left by 1 with saturation, then pack their 16 MSBs
		// into the upper and lower halfword of dst
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_warn_if_reached();
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
			rz_warn_if_reached();
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
			rz_warn_if_reached();
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
			rz_warn_if_reached();
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
		if (OP(0).kind == C6X_OP_REGPAIR) {
			// 40-bit long shifted left by src1, truncated back to 40 bits
			RzILOpBitVector *v = c6x_long40(&OP(0));
			RzILOpPure *n = c6x_src(&OP(1));
			if (!v || !n) {
				rz_il_op_pure_free(v);
				rz_il_op_pure_free(n);
				return NULL;
			}
			return c6x_wr_pair64(&OP(2), LOGAND(SHIFTL0(v, n), SN(64, 0xffffffffffLL)));
		}
		RzILOpPure *v = c6x_src(&OP(0));
		RzILOpPure *n = c6x_src(&OP(1));
		if (!v || !n) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(n);
			return NULL;
		}
		return c6x_wr(&OP(2), SHIFTL0(v, n));
	}
	case C6X_INS_SHR:
	case C6X_INS_SHRU: {
		RzILOpPure *v = c6x_src(&OP(0));
		RzILOpPure *n = c6x_src(&OP(1));
		if (!v || !n) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(n);
			return NULL;
		}
		// shr is arithmetic (sign-propagating); shru is logical
		return c6x_wr(&OP(2), insn->id == C6X_INS_SHRU ? SHIFTR0(v, n) : SHIFTRA(v, n));
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
		// signed add/subtract saturating to the 32-bit range (src1 - src2 for
		// ssub, matching the SUB operand order)
		RzILOpPure *s1 = c6x_src(&OP(0));
		RzILOpPure *s2 = c6x_src(&OP(1));
		if (!s1 || !s2) {
			rz_warn_if_reached();
			rz_il_op_pure_free(s1);
			rz_il_op_pure_free(s2);
			return NULL;
		}
		RzILOpBitVector *w1 = SIGNED(64, s1);
		RzILOpBitVector *w2 = SIGNED(64, s2);
		return c6x_wr(&OP(2), c6x_sats32(insn->id == C6X_INS_SSUB ? SUB(w1, w2) : ADD(w1, w2)));
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
		// rotate src2 left by src1[4:0]: (v << n) | (v >>u (32 - n)); this .M-unit
		// form decodes src1 (the count) into ops[0] and src2 (the value) into ops[1]
		RzILOpPure *v = c6x_src(&OP(1));
		RzILOpPure *cnt = c6x_src(&OP(0));
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
			rz_warn_if_reached();
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
		// per-halfword shift right by src1[3:0], arithmetic for shr2 and logical
		// (zero-extended) for shru2, lanes independent
		RzILOpPure *v = c6x_src(&OP(0));
		RzILOpPure *cnt = c6x_src(&OP(1));
		if (!v || !cnt) {
			rz_il_op_pure_free(v);
			rz_il_op_pure_free(cnt);
			return NULL;
		}
		bool ar = insn->id == C6X_INS_SHR2;
		return c6x_wr(&OP(2),
			LET("_sv", v, LET("_sn", UNSIGNED(16, LOGAND(cnt, U32(0xf))), APPEND(ar ? SHIFTRA(UNSIGNED(16, SHIFTR0(VARLP("_sv"), U32(16))), VARLP("_sn")) : SHIFTR0(UNSIGNED(16, SHIFTR0(VARLP("_sv"), U32(16))), VARLP("_sn")), ar ? SHIFTRA(UNSIGNED(16, VARLP("_sv")), VARLP("_sn")) : SHIFTR0(UNSIGNED(16, VARLP("_sv")), VARLP("_sn"))))));
	}
	case C6X_INS_SWAP4: {
		// exchange the two bytes within each halfword
		RzILOpPure *v = c6x_src(&OP(0));
		if (!v) {
			rz_warn_if_reached();
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
			rz_warn_if_reached();
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
			rz_warn_if_reached();
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
			rz_warn_if_reached();
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
			rz_warn_if_reached();
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
			rz_warn_if_reached();
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
			rz_warn_if_reached();
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
			rz_warn_if_reached();
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
	case C6X_INS_IDLE:
	case C6X_INS_NOP:
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
	case C6X_INS_INTSP:
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
		// the SPLOOP buffer controls are deliberately not modelled. Returning
		// nothing leaves the caller to fall back, which is not a bug to warn on.
		return NULL;
	}
}

// RzIL keeps a variable name as a const char * and never copies it, so every
// name a lifted packet mentions has to outlive the effect. They are drawn from a
// bounded set -- one snapshot per staged register, one capture per register per
// slot -- so the whole set is a table of string literals rather than anything
// built at run time.
// clang-format off
static const char *const c6x_snapshot_names[C6X_PK_REGS] = {
	"_pk0", "_pk1", "_pk2", "_pk3", "_pk4", "_pk5", "_pk6", "_pk7",
	"_pk8", "_pk9", "_pk10", "_pk11", "_pk12", "_pk13", "_pk14", "_pk15"
};

static const char *const c6x_capture_names[C6X_FP_SLOTS][C6X_PK_REGS] = {
#define C6X_CAP_ROW(s) \
	{ "_c" #s "_0", "_c" #s "_1", "_c" #s "_2", "_c" #s "_3", \
		"_c" #s "_4", "_c" #s "_5", "_c" #s "_6", "_c" #s "_7", \
		"_c" #s "_8", "_c" #s "_9", "_c" #s "_10", "_c" #s "_11", \
		"_c" #s "_12", "_c" #s "_13", "_c" #s "_14", "_c" #s "_15" }
	C6X_CAP_ROW(0), C6X_CAP_ROW(1), C6X_CAP_ROW(2), C6X_CAP_ROW(3),
	C6X_CAP_ROW(4), C6X_CAP_ROW(5), C6X_CAP_ROW(6), C6X_CAP_ROW(7),
	C6X_CAP_ROW(8), C6X_CAP_ROW(9), C6X_CAP_ROW(10), C6X_CAP_ROW(11),
	C6X_CAP_ROW(12), C6X_CAP_ROW(13), C6X_CAP_ROW(14)
#undef C6X_CAP_ROW
};
// clang-format on

// Whether a slot writes memory, i.e. is a store.
static bool c6x_writes_memory(const C6xInsn *insn) {
	return insn->nops && OP(insn->nops - 1).kind == C6X_OP_MEM;
}

// Registers an instruction writes.
//
// The ISA does not promise that the last operand is the destination -- a branch
// ends in its target, BNOP in its NOP count, MVC in a control register -- so
// this is a recogniser rather than a rule: it reports only the shapes it is sure
// of and returns false for everything else, leaving the caller to lift the
// packet the plain way. Being wrong here would stage the wrong register, so the
// bar for adding a shape is knowing which operand it writes.
static bool c6x_writes(const C6xInsn *insn, const char **out, size_t *n) {
	*n = 0;
	if (!insn->nops) {
		return true; // nothing written, e.g. nop
	}
	const C6xOperand *dst = &OP(insn->nops - 1);
	switch (dst->kind) {
	case C6X_OP_REG: {
		const char *r = c6x_reg_name(dst->v.reg.side, dst->v.reg.num);
		if (!r) {
			return false;
		}
		out[(*n)++] = r;
		return true;
	}
	case C6X_OP_REGPAIR: {
		const char *lo = c6x_reg_name(dst->v.reg.side, dst->v.reg.num);
		const char *hi = c6x_reg_name(dst->v.reg.side, dst->v.reg.num + 1);
		if (!lo || !hi) {
			return false;
		}
		out[(*n)++] = lo;
		out[(*n)++] = hi;
		return true;
	}
	case C6X_OP_MEM:
		// a store writes memory, and the base too when it writes back
		if (dst->v.mem.mode != C6X_AM_POS_CST && dst->v.mem.mode != C6X_AM_NEG_CST &&
			dst->v.mem.mode != C6X_AM_POS_REG && dst->v.mem.mode != C6X_AM_NEG_REG) {
			const char *base = c6x_reg_name(dst->v.mem.base_side, dst->v.mem.base);
			if (!base) {
				return false;
			}
			out[(*n)++] = base;
		}
		return true;
	default:
		return false;
	}
}

/**
 * \brief Lift a whole execute packet.
 *
 * Every instruction in a C6000 execute packet reads the register file as it
 * stood when the packet issued, so a packet may swap two registers without a
 * temporary and no ordering of the writes reproduces that. Rather than redirect
 * every read inside the lifters, each slot is run against the packet's starting
 * state and its result captured, and the captured results are applied together
 * at the end:
 *
 *     save the packet-start value of every register the packet writes
 *     for each slot: restore those registers, run the slot, capture its writes
 *     apply the captured writes
 *
 * Restoring before each slot is what makes the reads see packet-start state; the
 * lifters themselves are untouched.
 *
 * \param insns The decoded slots, in address order.
 * \param n How many, at least two.
 * \param pc Address of the packet.
 * \param skip Slots to hold back, by bit index, for the caller to emit later.
 *
 * \return The packet's effect, or NULL if a slot has a shape this cannot model.
 */
RZ_IPI RZ_OWN RzILOpEffect *c6x_lift_packet(const C6xInsn *insns, size_t n, ut64 pc, ut32 skip) {
	rz_return_val_if_fail(insns && n >= 1, NULL);
	const char *written[C6X_MAX_OPS * 8];
	size_t nw = 0;
	for (size_t i = 0; i < n; i++) {
		if (skip & (1u << i)) {
			continue;
		}
		const char *w[C6X_MAX_OPS];
		size_t k = 0;
		if (!c6x_writes(&insns[i], w, &k)) {
			return NULL;
		}
		for (size_t j = 0; j < k && nw < RZ_ARRAY_SIZE(written); j++) {
			bool seen = false;
			for (size_t m = 0; m < nw; m++) {
				seen |= RZ_STR_EQ(written[m], w[j]);
			}
			if (!seen) {
				written[nw++] = w[j];
			}
		}
	}
	if (!nw) {
		return NULL; // nothing to stage; sequential lifting is already correct
	}
	// the folded chain takes ownership of the steps, so the vector frees nothing
	RzPVector *steps = rz_pvector_new(NULL);
	if (!steps) {
		return NULL;
	}
	// names for the staging locals, taken from the tables above
	const char *snap[RZ_ARRAY_SIZE(written)];
	const char *cap[C6X_FP_SLOTS][RZ_ARRAY_SIZE(written)];
	for (size_t j = 0; j < nw; j++) {
		snap[j] = j < C6X_PK_REGS ? c6x_snapshot_names[j] : NULL;
		for (size_t i = 0; i < n; i++) {
			cap[i][j] = (i < C6X_FP_SLOTS && j < C6X_PK_REGS) ? c6x_capture_names[i][j] : NULL;
		}
		if (!snap[j] || !cap[n - 1][j]) {
			rz_pvector_free(steps);
			return NULL;
		}
	}
	for (size_t j = 0; j < nw; j++) {
		rz_pvector_push(steps, SETL(snap[j], VARG(written[j])));
	}
	// A load and a store to the same location in one packet load the old value
	// and then store the new one (SPRUFE8B 4.2), so every slot that reads memory
	// has to run before any slot that writes it. Registers are unaffected by the
	// order, since each slot is restored to the packet's starting state and the
	// result applied by original slot index.
	size_t order[C6X_FP_SLOTS];
	size_t nord = 0;
	for (size_t i = 0; i < n; i++) {
		if (!c6x_writes_memory(&insns[i])) {
			order[nord++] = i;
		}
	}
	for (size_t i = 0; i < n; i++) {
		if (c6x_writes_memory(&insns[i])) {
			order[nord++] = i;
		}
	}
	for (size_t o = 0; o < nord; o++) {
		size_t i = order[o];
		if (skip & (1u << i)) {
			continue; // emitted by the caller, later in the window
		}
		// restore packet-start state so this slot reads what the hardware would
		for (size_t j = 0; j < nw; j++) {
			rz_pvector_push(steps, SETG(written[j], VARL(snap[j])));
		}
		RzILOpEffect *body = c6x_lift(&insns[i], pc);
		if (!body) {
			void **it;
			rz_pvector_foreach (steps, it) {
				rz_il_op_effect_free(*it);
			}
			rz_pvector_free(steps);
			return NULL;
		}
		rz_pvector_push(steps, body);
		// capture what this slot produced before the next restore wipes it
		for (size_t j = 0; j < nw; j++) {
			rz_pvector_push(steps, SETL(cap[i][j], VARG(written[j])));
		}
	}
	// apply the last slot that actually wrote each register
	for (size_t j = 0; j < nw; j++) {
		size_t last = 0;
		for (size_t i = 0; i < n; i++) {
			const char *w[C6X_MAX_OPS];
			size_t k = 0;
			c6x_writes(&insns[i], w, &k);
			for (size_t m = 0; m < k; m++) {
				if (RZ_STR_EQ(w[m], written[j])) {
					last = i;
				}
			}
		}
		rz_pvector_push(steps, SETG(written[j], VARL(cap[last][j])));
	}
	// there is no vector form of SEQN, so fold the steps into a chain
	RzILOpEffect *seq = NULL;
	void **it;
	rz_pvector_foreach (steps, it) {
		RzILOpEffect *step = *it;
		seq = seq ? SEQ2(seq, step) : step;
	}
	rz_pvector_free(steps);
	return seq;
}

/** Lift a decoded instruction to RzIL, or NULL when the form is not yet lifted.
 *  \p pc is the instruction address (for PC-relative results). */
RZ_IPI RZ_OWN RzILOpEffect *c6x_lift(const C6xInsn *insn, ut64 pc) {
	rz_return_val_if_fail(insn, NULL);
	RzILOpEffect *eff = c6x_lift_core(insn, pc);
	if (!eff) {
		return NULL;
	}
	const char *pred = c6x_pred_name(insn->creg);
	if (!pred) {
		return eff; // unconditional
	}
	// predicated: run the effect only when the predicate register satisfies the
	// z sense (z = 1 tests == 0, z = 0 tests != 0).
	RzILOpBool *cond = insn->z ? IS_ZERO(c6x_reg_read(pred)) : NON_ZERO(c6x_reg_read(pred));
	return BRANCH(cond, eff, NOP());
}

/**
 * \brief Sample a branch's predicate into a local, for a transfer emitted later.
 *
 * A branch deferred past its delay slots is emitted after instructions that may
 * have overwritten the register it tests, so the test has to be taken when the
 * branch issues and the result carried to the transfer. Unconditional branches
 * need nothing.
 *
 * \return NULL when \p insn is unconditional.
 */
RZ_IPI RZ_OWN RzILOpEffect *c6x_sample_predicate(const C6xInsn *insn) {
	const char *pred = c6x_pred_name(insn->creg);
	if (!pred) {
		return NULL;
	}
	return SETL(C6X_PRED_TAKEN, insn->z ? IS_ZERO(VARG(pred)) : NON_ZERO(VARG(pred)));
}

/**
 * \brief The transfer of a branch whose predicate was sampled earlier.
 *
 * \param insn The branch.
 * \param pc Address the branch issued from.
 * \param sampled Whether c6x_sample_predicate() ran for it.
 */
RZ_IPI RZ_OWN RzILOpEffect *c6x_deferred_transfer(const C6xInsn *insn, ut64 pc, bool sampled,
	ut64 fallthrough) {
	// lift the branch unconditionally, then re-apply the sampled predicate
	C6xInsn bare = *insn;
	bare.creg = 0;
	bare.z = 0;
	RzILOpEffect *xfer = c6x_lift(&bare, pc);
	if (!xfer || !sampled) {
		return xfer;
	}
	// The window already ran the delay slots, so a branch that is not taken has
	// to leave the program counter past them; otherwise the VM steps back into
	// the window and walks it again.
	return BRANCH(VARL(C6X_PRED_TAKEN), xfer, JMP(U32(fallthrough)));
}

/** Whether \p o names the same architectural register as \p other. */
RZ_IPI bool c6x_same_reg(const C6xOperand *o, const C6xOperand *other) {
	if (o->kind != C6X_OP_REG || other->kind != C6X_OP_REG) {
		return false;
	}
	return o->v.reg.side == other->v.reg.side && o->v.reg.num == other->v.reg.num;
}

/** A bare jump to \p addr, for leaving the pc past a window. */
RZ_IPI RZ_OWN RzILOpEffect *c6x_jump_to(ut64 addr) {
	return JMP(U32(addr));
}

#include <rz_il/rz_il_opbuilder_end.h>
