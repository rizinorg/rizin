// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <capstone.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_util/rz_assert.h>

#include "rz_il/rz_il_opbuilder_begin.h"
#include "rz_types.h"
#include "sparc.h"
#include "sparc_il.h"

#if CS_API_MAJOR >= 6
static RzILOpEffect *arithmetic_int_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	RzILOpPure *src0 = CAST_UA(rz_sparc_cs_get_operand(handle, insn, mode, 0, 0));
	RzILOpPure *src1 = CAST_UA(rz_sparc_cs_get_operand(handle, insn, mode, 1, 0));
	const char *dst = cs_reg_name(handle, INSOP(2).reg);
	RzSparcCCRBits bits = { 0 };

	switch (insn->id) {
	case SPARC_INS_ADD:
		return SSETG(dst, ADD(src0, src1));
	case SPARC_INS_SUB:
		return SSETG(dst, SUB(src0, src1));
	case SPARC_INS_TADDCC:
	case SPARC_INS_TADDCCTV:
	case SPARC_INS_ADDCC: {
		RzILOpEffect *arith_op = SEQ2(rz_sparc_2args_ccr(RZ_SPARC_CCR_OP_ADD, src0, src1, NULL, &bits), SSETG(dst, CAST_UA(VARL("res128"))));
		if (insn->id == SPARC_INS_ADDCC) {
			return arith_op;
		} else if (insn->id == SPARC_INS_TADDCC) {
			RzILOpPure *tagged_overflow = ITE(OR(OR(NON_ZERO(LOGAND(DUP(src0), UA(3))), NON_ZERO(LOGAND(DUP(src1), UA(3)))), ICC_V()), IL_TRUE, IL_FALSE);
			return SEQ2(arith_op, rz_sparc_set_ccr_flags(NULL, tagged_overflow, NULL, NULL, NULL, NULL, NULL, NULL));
		}
		RzILOpPure *tagged_overflow = ITE(OR(OR(NON_ZERO(LOGAND(DUP(src0), UA(3))), NON_ZERO(LOGAND(DUP(src1), UA(3)))),
							  add_overflow(UNSIGNED(32, DUP(src0)), UNSIGNED(32, DUP(src1)), ADD(DUP(src0), DUP(src0)))),
			IL_TRUE, IL_FALSE);
		return BRANCH(tagged_overflow, GOTO("trap"), arith_op);
	}
	case SPARC_INS_TSUBCC:
	case SPARC_INS_TSUBCCTV:
	case SPARC_INS_SUBCC: {
		RzILOpEffect *arith_op = SEQ2(rz_sparc_2args_ccr(RZ_SPARC_CCR_OP_SUB, src0, src1, NULL, &bits), SSETG(dst, CAST_UA(VARL("res128"))));
		if (insn->id == SPARC_INS_SUBCC) {
			return arith_op;
		} else if (insn->id == SPARC_INS_TSUBCC) {
			RzILOpPure *tagged_overflow = ITE(OR(OR(NON_ZERO(LOGAND(DUP(src0), UA(3))), NON_ZERO(LOGAND(DUP(src1), UA(3)))), ICC_V()), IL_TRUE, IL_FALSE);
			return SEQ2(arith_op, rz_sparc_set_ccr_flags(NULL, tagged_overflow, NULL, NULL, NULL, NULL, NULL, NULL));
		}
		RzILOpPure *tagged_overflow = ITE(OR(OR(NON_ZERO(LOGAND(DUP(src0), UA(3))), NON_ZERO(LOGAND(DUP(src1), UA(3)))),
							  sub_overflow(UNSIGNED(32, DUP(src0)), UNSIGNED(32, DUP(src1)), SUB(DUP(src0), DUP(src0)))),
			IL_TRUE, IL_FALSE);
		return BRANCH(tagged_overflow, GOTO("trap"), arith_op);
	}
	case SPARC_INS_ADDX: // a.k.a ADDC
		return SSETG(dst, ADD(ADD(src0, src1), ITE(ICC_C(), UA(1), UA(0))));
	case SPARC_INS_SUBX: // a.k.a SUBC
		return SSETG(dst, SUB(SUB(src0, src1), ITE(ICC_C(), UA(1), UA(0))));
	case SPARC_INS_ADDXCC: // a.k.a ADDCCC
		return SEQ2(rz_sparc_2args_ccr(RZ_SPARC_CCR_OP_ADD, src0, src1, ICC_C(), &bits), SSETG(dst, CAST_UA(VARL("res128"))));
	case SPARC_INS_SUBXCC: // a.k.a SUBCCC
		return SEQ2(rz_sparc_2args_ccr(RZ_SPARC_CCR_OP_SUB, src0, src1, ICC_C(), &bits), SSETG(dst, CAST_UA(VARL("res128"))));
	case SPARC_INS_ADDXC:
		return SSETG(dst, ADD(ADD(src0, src1), ITE(XCC_C(), UA(1), UA(0))));
	case SPARC_INS_ADDXCCC:
		return SEQ2(rz_sparc_2args_ccr(RZ_SPARC_CCR_OP_ADD, src0, src1, XCC_C(), &bits), SSETG(dst, CAST_UA(VARL("res128"))));
	case SPARC_INS_UDIV:
	case SPARC_INS_UDIVCC: {
		RzILOpPure *dividend = APPEND(UNSIGNED(32, VARG("y")), UNSIGNED(32, src0));
		RzILOpPure *divisor = UNSIGNED(64, src1);
		RzILOpEffect *quotient = NULL;
		RzILOpEffect *set_dst = NULL;
		set_dst = SSETG(dst, ITE(SGE(VARL("res128"), UN(128, 0x80000000)), UA(0x7fffffff), CAST_UA(VARL("res128"))));

		if (insn->id == SPARC_INS_UDIV) {
			quotient = SETL("res128", UNSIGNED(128, DIV(dividend, divisor)));
			return SEQ3(quotient, SSETG(dst, CAST_UA(VARL("res128"))), set_dst);
		}
		bits.icc_c = RZ_SPARC_CC_UNSET;
		bits.xcc_v = RZ_SPARC_CC_UNSET;
		bits.xcc_c = RZ_SPARC_CC_UNSET;
		quotient = rz_sparc_2args_ccr(RZ_SPARC_CCR_OP_UDIV, dividend, divisor, NULL, &bits);
		return SEQ2(quotient, set_dst);
	}
	case SPARC_INS_SDIV:
	case SPARC_INS_SDIVCC: {
		RzILOpPure *dividend = APPEND(UNSIGNED(32, VARG("y")), UNSIGNED(32, src0));
		RzILOpPure *divisor = SIGNED(64, UNSIGNED(32, src1));
		RzILOpEffect *quotient = NULL;
		RzILOpEffect *set_dst = NULL;
		set_dst = SSETG(dst, ITE(SGE(VARL("res128"), SN(128, 0x80000000)), UA(0x7fffffff), ITE(SLE(VARL("res128"), SN(128, -0x7fffffff)), UA(0xffffffff80000000ull), CAST_SA(VARL("res128")))));

		if (insn->id == SPARC_INS_UDIV || insn->id == SPARC_INS_SDIV) {
			quotient = SETL("res128", SIGNED(128, SDIV(dividend, divisor)));
			return SEQ3(quotient, SSETG(dst, CAST_SA(VARL("res128"))), set_dst);
		}
		bits.icc_c = RZ_SPARC_CC_UNSET;
		bits.xcc_v = RZ_SPARC_CC_UNSET;
		bits.xcc_c = RZ_SPARC_CC_UNSET;
		quotient = rz_sparc_2args_ccr(RZ_SPARC_CCR_OP_SDIV, dividend, divisor, NULL, &bits);
		return SEQ2(quotient, set_dst);
	}
	case SPARC_INS_UMUL:
	case SPARC_INS_UMULCC:
	case SPARC_INS_SMUL:
	case SPARC_INS_SMULCC: {
		RzILOpPure *fac0 = NULL;
		RzILOpPure *fac1 = NULL;
		RzSparcCCROp ccr_op = RZ_SPARC_CCR_OP_SMUL;
		if (insn->id == SPARC_INS_UMUL || insn->id == SPARC_INS_UMULCC) {
			ccr_op = RZ_SPARC_CCR_OP_SMUL;
		}

		if (insn->id == SPARC_INS_UMUL || insn->id == SPARC_INS_UMULCC) {
			fac0 = UNSIGNED(64, UNSIGNED(32, src0));
			fac1 = UNSIGNED(64, UNSIGNED(32, src1));
		} else {
			fac0 = SIGNED(64, SIGNED(32, src0));
			fac1 = SIGNED(64, SIGNED(32, src1));
		}
		RzILOpEffect *prod = NULL;
		if (insn->id == SPARC_INS_UMULCC || insn->id == SPARC_INS_SMULCC) {
			bits.icc_v = RZ_SPARC_CC_UNSET;
			bits.icc_c = RZ_SPARC_CC_UNSET;
			bits.xcc_v = RZ_SPARC_CC_UNSET;
			bits.xcc_c = RZ_SPARC_CC_UNSET;
			prod = rz_sparc_2args_ccr(ccr_op, fac0, fac1, NULL, &bits);
		} else {
			prod = SETL("res128", MUL(fac0, fac1));
		}
		return SEQ3(prod, SSETG(dst, CAST_UA(VARL("res128"))), SETG("y", CAST_UA(SHIFTR0(VARL("res128"), U8(32)))));
	}
	case SPARC_INS_MULSCC: {
		RzILOpPure *multiplier = SHIFTR(XOR(ICC_N(), ICC_V()), VARL("rs1"), U8(1));
		RzILOpEffect *mul_step = rz_sparc_2args_ccr(RZ_SPARC_CCR_OP_ADD, ITE(LSB(VARG("y")), UNSIGNED(32, src1), U32(0)), multiplier, NULL, &bits);
		RzILOpEffect *compute_dst = SEQ2(mul_step, SSETG(dst, CAST_UA(VARL("res128"))));
		RzILOpEffect *update_y = SETG("y", CAST_UA(SHIFTR(LSB(VARL("rs1")), UNSIGNED(32, VARG("y")), U8(1))));
		return SEQ3(SETL("rs1", UNSIGNED(32, src0)), compute_dst, update_y);
	}
	case SPARC_INS_UMULXHI:
		return SEQ2(SETL("res128", MUL(UNSIGNED(128, src0), UNSIGNED(128, src1))), SSETG(dst, CAST_UA(SHIFTR0(VARL("res128"), U8(64)))));
	case SPARC_INS_UDIVX:
		return SSETG(dst, CAST_UA(DIV(src0, src1)));
	case SPARC_INS_SDIVX:
		return SSETG(dst, CAST_UA(SDIV(src0, src1)));
	case SPARC_INS_MULX:
		return SSETG(dst, CAST_UA(MUL(src0, src1)));
	case SPARC_INS_XMULX:
	case SPARC_INS_XMULXHI: {
		RzILOpEffect *setup_args = SEQ4(SETL("res128", UN(128, 0)), SETL("rs1", UNSIGNED(128, src0)), SETL("rs2", UNSIGNED(128, src1)), SETL("i", U8(0)));
		RzILOpEffect *multiply = REPEAT(
			ULT(VARL("i"), U8(64)),
			SEQ2(
				SETL("res128", LOGXOR(VARL("res128"), ITE(LSB(SHIFTR0(VARL("rs2"), VARL("i"))), SHIFTL0(VARL("rs1"), VARL("i")), UN(128, 0)))),
				SETL("i", ADD(VARL("i"), U8(1)))));
		if (insn->id == SPARC_INS_XMULX) {
			return SEQ3(setup_args, multiply, SSETG(dst, UNSIGNED(64, VARL("res128"))));
		}
		return SEQ3(setup_args, multiply, SSETG(dst, UNSIGNED(64, SHIFTR0(VARL("res128"), U8(64)))));
	}
	}
	rz_warn_if_reached();
	NOT_IMPLEMENTED;
}

static size_t fload_dst_width_bits(const cs_insn *insn) {
	rz_return_val_if_fail(insn, 0);
	switch (insn->id) {
	case SPARC_INS_FDTOI:
	case SPARC_INS_FQTOI:
	case SPARC_INS_FSTOI:
	case SPARC_INS_FDTOS:
	case SPARC_INS_FITOS:
	case SPARC_INS_FQTOS:
	case SPARC_INS_FXTOS:
	case SPARC_INS_FPADD16S:
	case SPARC_INS_FPSUB16S:
	case SPARC_INS_FPADD32S:
	case SPARC_INS_FPSUB32S:
	case SPARC_INS_FPACK16:
	case SPARC_INS_FPACKFIX:
		return SPARC_WORD;
	case SPARC_INS_FCHKSM16:
	case SPARC_INS_BSHUFFLE:
	case SPARC_INS_FSMULD:
	case SPARC_INS_FDTOX:
	case SPARC_INS_FQTOX:
	case SPARC_INS_FSTOX:
	case SPARC_INS_FITOD:
	case SPARC_INS_FQTOD:
	case SPARC_INS_FSTOD:
	case SPARC_INS_FXTOD:
	case SPARC_INS_FPADD16:
	case SPARC_INS_FPSUB16:
	case SPARC_INS_FPADD32:
	case SPARC_INS_FPSUB32:
	case SPARC_INS_FPADD64:
	case SPARC_INS_FMUL8X16:
	case SPARC_INS_FMUL8SUX16:
	case SPARC_INS_FMUL8ULX16:
	case SPARC_INS_FMUL8X16AL:
	case SPARC_INS_FMUL8X16AU:
	case SPARC_INS_FMULD8SUX16:
	case SPARC_INS_FMULD8ULX16:
	case SPARC_INS_FPMERGE:
	case SPARC_INS_FEXPAND:
	case SPARC_INS_FMEAN16:
	case SPARC_INS_FPACK32:
		return SPARC_DOUBLE_WORD;
	case SPARC_INS_FDMULQ:
	case SPARC_INS_FDTOQ:
	case SPARC_INS_FITOQ:
	case SPARC_INS_FSTOQ:
	case SPARC_INS_FXTOQ:
		return SPARC_QUAD_WORD;
	}
	rz_warn_if_reached();
	return 0;
}

static size_t fload_operands_width_bits(const cs_insn *insn) {
	rz_return_val_if_fail(insn, 0);
	switch (insn->id) {
	case SPARC_INS_FXTOS:
	case SPARC_INS_FXTOD:
	case SPARC_INS_FXTOQ:
	case SPARC_INS_FITOS:
	case SPARC_INS_FITOD:
	case SPARC_INS_FITOQ:
		// Input operands are not floats but bitvectors in float registers.
		// Hence have a float width of 0.
		return 0;
	case SPARC_INS_FCMPEQ16:
	case SPARC_INS_FCMPGT16:
	case SPARC_INS_FCMPLE16:
	case SPARC_INS_FCMPNE16:
	case SPARC_INS_FLCMPD:
	case SPARC_INS_FLCMPS:
		return SPARC_HALF_WORD;
	case SPARC_INS_MOVSTOSW:
	case SPARC_INS_MOVSTOUW:
	case SPARC_INS_FSRC1S:
	case SPARC_INS_FSRC2S:
	case SPARC_INS_FCMPS:
	case SPARC_INS_FCMPES:
	case SPARC_INS_FCMPEQ32:
	case SPARC_INS_FCMPGT32:
	case SPARC_INS_FCMPLE32:
	case SPARC_INS_FCMPNE32:
	case SPARC_INS_FSTOD:
	case SPARC_INS_FSTOI:
	case SPARC_INS_FSTOQ:
	case SPARC_INS_FSTOX:
	case SPARC_INS_FADDS:
	case SPARC_INS_FDIVS:
	case SPARC_INS_FHADDS:
	case SPARC_INS_FHSUBS:
	case SPARC_INS_FMULS:
	case SPARC_INS_FNADDS:
	case SPARC_INS_FNHADDS:
	case SPARC_INS_FPADD16S:
	case SPARC_INS_FPSUB16S:
	case SPARC_INS_FPADD32S:
	case SPARC_INS_FPSUB32S:
	case SPARC_INS_FSUBS:
	case SPARC_INS_FNANDS:
	case SPARC_INS_FNORS:
	case SPARC_INS_FANDNOT1S:
	case SPARC_INS_FANDNOT2S:
	case SPARC_INS_FANDS:
	case SPARC_INS_FXNORS:
	case SPARC_INS_FXORS:
	case SPARC_INS_FORNOT1S:
	case SPARC_INS_FORNOT2S:
	case SPARC_INS_FORS:
	case SPARC_INS_FNOT1S:
	case SPARC_INS_FNOT2S:
	case SPARC_INS_FNEGS:
	case SPARC_INS_FABSS:
	case SPARC_INS_FONES:
	case SPARC_INS_FZEROS:
	case SPARC_INS_FMOVRS:
	case SPARC_INS_FMOVS:
	case SPARC_INS_FSQRTS:
	case SPARC_INS_FSMULD:
		return SPARC_WORD;
	case SPARC_INS_FPADD16:
	case SPARC_INS_FPSUB16:
	case SPARC_INS_FPADD32:
	case SPARC_INS_FPSUB32:
	case SPARC_INS_FPADD64:
	case SPARC_INS_MOVDTOX:
	case SPARC_INS_FSLAS16:
	case SPARC_INS_FSLAS32:
	case SPARC_INS_FSLL16:
	case SPARC_INS_FSLL32:
	case SPARC_INS_FSRA16:
	case SPARC_INS_FSRA32:
	case SPARC_INS_FSRL16:
	case SPARC_INS_FSRL32:
	case SPARC_INS_FSRC1:
	case SPARC_INS_FSRC2:
	case SPARC_INS_FCMPD:
	case SPARC_INS_FCMPED:
	case SPARC_INS_FDTOS:
	case SPARC_INS_FDTOX:
	case SPARC_INS_FDTOI:
	case SPARC_INS_FDTOQ:
	case SPARC_INS_FADDD:
	case SPARC_INS_FDIVD:
	case SPARC_INS_FHADDD:
	case SPARC_INS_FHSUBD:
	case SPARC_INS_FMULD:
	case SPARC_INS_FNADDD:
	case SPARC_INS_FNHADDD:
	case SPARC_INS_FSUBD:
	case SPARC_INS_FNAND:
	case SPARC_INS_FNOR:
	case SPARC_INS_FAND:
	case SPARC_INS_FANDNOT1:
	case SPARC_INS_FANDNOT2:
	case SPARC_INS_FXNOR:
	case SPARC_INS_FXOR:
	case SPARC_INS_FOR:
	case SPARC_INS_FORNOT1:
	case SPARC_INS_FORNOT2:
	case SPARC_INS_FNOT1:
	case SPARC_INS_FNOT2:
	case SPARC_INS_FNEGD:
	case SPARC_INS_FABSD:
	case SPARC_INS_FONE:
	case SPARC_INS_FZERO:
	case SPARC_INS_FMOVRD:
	case SPARC_INS_FMOVD:
	case SPARC_INS_FSQRTD:
	case SPARC_INS_FDMULQ:
		return SPARC_DOUBLE_WORD;
	case SPARC_INS_FCMPEQ:
	case SPARC_INS_FCMPQ:
	case SPARC_INS_FQTOS:
	case SPARC_INS_FQTOD:
	case SPARC_INS_FQTOI:
	case SPARC_INS_FQTOX:
	case SPARC_INS_FADDQ:
	case SPARC_INS_FDIVQ:
	case SPARC_INS_FMULQ:
	case SPARC_INS_FSUBQ:
	case SPARC_INS_FNEGQ:
	case SPARC_INS_FABSQ:
	case SPARC_INS_FMOVRQ:
	case SPARC_INS_FMOVQ:
	case SPARC_INS_FSQRTQ:
		return SPARC_QUAD_WORD;
	case SPARC_INS_FMUL8SUX16:
	case SPARC_INS_FMUL8ULX16:
	case SPARC_INS_FMUL8X16:
	case SPARC_INS_FMUL8X16AL:
	case SPARC_INS_FMUL8X16AU:
	case SPARC_INS_FMULD8SUX16:
	case SPARC_INS_FMULD8ULX16:
		// Input operand widths vary from instruction to instruction.
		return 0;
	}
	rz_warn_if_reached();
	return 0;
}

static RzILOpEffect *simd_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	size_t dst_width = fload_dst_width_bits(insn);

	RzILOpEffect *simd_op = NULL;
	RzILOpPure *src0 = NULL;
	RzILOpPure *src1 = NULL;
	sparc_reg dst = 0;
	switch (insn->id) {
	default:
		rz_warn_if_reached();
		return NULL;
	case SPARC_INS_FEXPAND:
		dst = INSOP(1).reg;
		src0 = rz_sparc_cs_get_operand(handle, insn, mode, 0, SPARC_WORD);
		simd_op = SEQ2(SETL("res", UN(64, 0)), SETL("rs2", UNSIGNED(64, F2BV(src0))));
		for (size_t i = 0; i < 4; ++i) {
			RzILOpPure *rs2_block = SHIFTL0(LOGAND(SHIFTR0(VARL("rs2"), U8(8 * i)), U64(0xff)), U8((16 * i) + 4));
			simd_op = SEQ2(simd_op, SETL("res", LOGOR(VARL("res"), rs2_block)));
		}
		return SEQ2(simd_op, rz_sparc_bv_to_consec_regs(handle, mode, dst, VARL("res"), dst_width));
	case SPARC_INS_FPMERGE:
		dst = INSOP(2).reg;
		src0 = rz_sparc_cs_get_operand(handle, insn, mode, 0, SPARC_WORD);
		src1 = rz_sparc_cs_get_operand(handle, insn, mode, 1, SPARC_WORD);
		simd_op = SEQ3(SETL("res", UN(64, 0)), SETL("rs1", UNSIGNED(64, F2BV(src0))), SETL("rs2", UNSIGNED(64, F2BV(src1))));
		for (size_t i = 0; i < 4; ++i) {
			RzILOpPure *rs1_block = SHIFTL0(LOGAND(SHIFTR0(VARL("rs1"), U8(8 * i)), U64(0xff)), U8((16 * i) + 8));
			RzILOpPure *rs2_block = SHIFTL0(LOGAND(SHIFTR0(VARL("rs2"), U8(8 * i)), U64(0xff)), U8(16 * i));
			simd_op = SEQ2(simd_op, SETL("res", LOGOR(LOGOR(VARL("res"), rs1_block), rs2_block)));
		}
		return SEQ2(simd_op, rz_sparc_bv_to_consec_regs(handle, mode, dst, VARL("res"), dst_width));
	}
	rz_warn_if_reached();
	NOT_IMPLEMENTED;
}

static RzILOpEffect *simd_mul_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	size_t dst_width = fload_dst_width_bits(insn);

	RzILOpPure *src1 = NULL;
	RzILOpPure *src2 = NULL;
	sparc_reg dst = INSOP(2).reg;

#define MS16B(x, y)    UNSIGNED(64, SHIFTRA(ADD(MUL(x, y), U32(0x80)), U8(8)))
#define SE_MS16B(x, y) UNSIGNED(64, SHIFTRA(ADD(SIGNED(32, MUL(x, y)), U32(0x8000)), U8(16)))

	switch (insn->id) {
	default:
		break;
	case SPARC_INS_FMUL8X16: {
		src1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, SPARC_WORD);
		src2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, SPARC_DOUBLE_WORD);
		RzILOpEffect *simd_op = SEQ3(SETL("res", U64(0)), SETL("rs1", F2BV(src1)), SETL("rs2", F2BV(src2)));
		for (size_t i = 0; i < 4; ++i) {
			RzILOpPure *op1 = UNSIGNED(32, UNSIGNED(8, SHIFTR0(VARL("rs1"), U8(8 * i))));
			RzILOpPure *op2 = SIGNED(32, SIGNED(16, SHIFTR0(VARL("rs2"), U8(16 * i))));
			RzILOpEffect *mul_step = SETL("m", MS16B(op1, op2));
			RzILOpEffect *assign = SETL("res", DEPOSIT64(VARL("res"), U8(16 * i), U32(16), VARL("m")));
			simd_op = SEQ3(simd_op, mul_step, assign);
		}
		return SEQ2(simd_op, rz_sparc_bv_to_consec_regs(handle, mode, dst, VARL("res"), dst_width));
	}
	case SPARC_INS_FMUL8X16AL:
	case SPARC_INS_FMUL8X16AU:
		src1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, SPARC_WORD);
		src2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, SPARC_WORD);
		RzILOpEffect *inc_i = SETL("i", ADD(VARL("i"), U8(1)));
		RzILOpEffect *rs2 = NULL;
		if (insn->id == SPARC_INS_FMUL8X16AU) {
			rs2 = SETL("rs2", SIGNED(32, SIGNED(16, SHIFTR0(F2BV(src2), U8(16)))));
		} else {
			rs2 = SETL("rs2", SIGNED(32, SIGNED(16, F2BV(src2))));
		}
		RzILOpPure *op1 = LOGAND(U32(0xff), SHIFTR0(VARL("rs1"), MUL(U8(8), VARL("i"))));
		RzILOpPure *op2 = VARL("rs2");
		RzILOpEffect *mul_step = SETL("m", MS16B(op1, op2));
		RzILOpEffect *assign = SETL("res", DEPOSIT64(VARL("res"), MUL(U8(16), VARL("i")), U32(16), VARL("m")));
		RzILOpEffect *simd_op = REPEAT(ULT(VARL("i"), U8(4)), SEQ3(mul_step, assign, inc_i));
		return SEQ6(
			SETL("i", U8(0)),
			SETL("res", U64(0)),
			SETL("rs1", UNSIGNED(32, F2BV(src1))),
			rs2,
			simd_op,
			rz_sparc_bv_to_consec_regs(handle, mode, dst, VARL("res"), dst_width));
	case SPARC_INS_FMUL8SUX16:
	case SPARC_INS_FMUL8ULX16: {
		src1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, SPARC_DOUBLE_WORD);
		src2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, SPARC_DOUBLE_WORD);
		RzILOpEffect *inc_i = SETL("i", ADD(VARL("i"), U8(1)));
		RzILOpPure *op1 = NULL;
		RzILOpEffect *mul_step = NULL;
		RzILOpPure *op2 = SIGNED(32, SIGNED(16, SHIFTR0(VARL("rs2"), MUL(U8(16), VARL("i")))));
		if (insn->id == SPARC_INS_FMUL8ULX16) {
			op1 = UNSIGNED(32, LOGAND(U64(0xff), SHIFTR0(VARL("rs1"), MUL(U8(16), VARL("i")))));
			mul_step = SETL("m", SE_MS16B(op1, op2));
		} else {
			op1 = UNSIGNED(32, LOGAND(U64(0xff), SHIFTR0(VARL("rs1"), ADD(U8(8), MUL(U8(16), VARL("i"))))));
			mul_step = SETL("m", MS16B(op1, op2));
		}
		RzILOpEffect *assign = SETL("res", DEPOSIT64(VARL("res"), MUL(U8(16), VARL("i")), U32(16), VARL("m")));
		RzILOpEffect *simd_op = REPEAT(ULT(VARL("i"), U8(4)), SEQ3(mul_step, assign, inc_i));
		return SEQ6(
			SETL("i", U8(0)),
			SETL("res", U64(0)),
			SETL("rs1", F2BV(src1)),
			SETL("rs2", F2BV(src2)),
			simd_op,
			rz_sparc_bv_to_consec_regs(handle, mode, dst, VARL("res"), dst_width));
	}
	case SPARC_INS_FMULD8SUX16:
	case SPARC_INS_FMULD8ULX16: {
		src1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, SPARC_WORD);
		src2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, SPARC_WORD);
		RzILOpEffect *inc_i = SETL("i", ADD(VARL("i"), U8(1)));
		RzILOpPure *op1 = NULL;
		RzILOpEffect *mul_step = NULL;
		RzILOpPure *op2 = SIGNED(32, SIGNED(16, SHIFTR0(VARL("rs2"), MUL(U8(16), VARL("i")))));
		if (insn->id == SPARC_INS_FMULD8SUX16) {
			op1 = LOGAND(U32(0xff), SHIFTR0(VARL("rs1"), ADD(U8(8), MUL(U8(16), VARL("i")))));
			mul_step = SETL("m", SHIFTL0(MUL(op1, op2), U8(8)));
		} else {
			op1 = LOGAND(U32(0xff), SHIFTR0(VARL("rs1"), MUL(U8(16), VARL("i"))));
			mul_step = SETL("m", MUL(op1, op2));
		}
		RzILOpEffect *assign = SETL("res", DEPOSIT64(VARL("res"), MUL(U8(32), VARL("i")), U32(32), UNSIGNED(64, VARL("m"))));
		RzILOpEffect *simd_op = REPEAT(ULT(VARL("i"), U8(2)), SEQ3(mul_step, assign, inc_i));
		return SEQ6(
			SETL("i", U8(0)),
			SETL("res", U64(0)),
			SETL("rs1", F2BV(src1)),
			SETL("rs2", F2BV(src2)),
			simd_op,
			rz_sparc_bv_to_consec_regs(handle, mode, dst, VARL("res"), dst_width));
	}
	}

	size_t width = fload_operands_width_bits(insn);
	src1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, width);
	src2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, width);
	rz_il_pure_2args_op *arith_op = rz_il_op_new_add;
	if (insn->id == SPARC_INS_FPSUB16 ||
		insn->id == SPARC_INS_FPSUB16S ||
		insn->id == SPARC_INS_FPSUB32 ||
		insn->id == SPARC_INS_FPSUB32S) {
		arith_op = rz_il_op_new_sub;
	}
	if (!src1 || !src2) {
		rz_warn_if_reached();
		return NULL;
	}
	size_t chunks = 1;
	size_t chunk_width = 64;
	switch (insn->id) {
	default:
		rz_warn_if_reached();
		NOT_IMPLEMENTED;
	case SPARC_INS_FPADD16:
	case SPARC_INS_FPSUB16:
		chunks *= 2;
		// fallthrough
	case SPARC_INS_FPADD16S:
	case SPARC_INS_FPSUB16S:
		chunk_width /= 2;
		// fallthrough
	case SPARC_INS_FPADD32:
	case SPARC_INS_FPSUB32:
		chunks *= 2;
		// fallthrough
	case SPARC_INS_FPADD32S:
	case SPARC_INS_FPSUB32S:
		chunk_width /= 2;
		// fallthrough
	case SPARC_INS_FPADD64: {
		RzILOpEffect *arith_ops = SEQ3(SETL("res", UN(dst_width, 0)), SETL("rs1", F2BV(src1)), SETL("rs2", F2BV(src2)));
		for (size_t i = 0; i < chunks; ++i) {
			RzILOpPure *calc = arith_op(SHIFTR0(VARL("rs1"), U8(chunk_width * i)), SHIFTR0(VARL("rs2"), U8(chunk_width * i)));
			arith_ops = SEQ2(arith_ops, SETL("res", LOGOR(VARL("res"), SHIFTL0(UNSIGNED(dst_width, UNSIGNED(chunk_width, calc)), U8(chunk_width * i)))));
		}
		return SEQ2(arith_ops, rz_sparc_bv_to_consec_regs(handle, mode, dst, VARL("res"), dst_width));
	}
	}
	rz_warn_if_reached();
	NOT_IMPLEMENTED;
}

static RzILOpEffect *arithmetic_float_op_3(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	size_t width = fload_operands_width_bits(insn);
	RzILOpPure *src0 = rz_sparc_cs_get_operand(handle, insn, mode, 0, width);
	RzILOpPure *src1 = rz_sparc_cs_get_operand(handle, insn, mode, 1, width);
	sparc_reg dst = INSOP(2).reg;
	if (!src0 || !src1) {
		rz_warn_if_reached();
		return NULL;
	}

	switch (insn->id) {
	default:
		rz_warn_if_reached();
		NOT_IMPLEMENTED;
	case SPARC_INS_FADDS:
	case SPARC_INS_FADDD:
	case SPARC_INS_FADDQ:
	case SPARC_INS_FNADDD:
	case SPARC_INS_FNADDS: {
		RzILOpPure *res = FADD(SPARC_RMODE(), src0, src1);
		if (insn->id == SPARC_INS_FNADDD || insn->id == SPARC_INS_FNADDS) {
			// Exceptions and overflows are ignored as long as FSR.cexc and FSR.aexc
			// are not modeled yet.
			res = FNEG(res);
		}
		return rz_sparc_fpure_to_freg(handle, mode, dst, res, width);
	}
	case SPARC_INS_FHADDS:
	case SPARC_INS_FHADDD:
	case SPARC_INS_FNHADDS:
	case SPARC_INS_FNHADDD: {
		RzILOpPure *divisor = (insn->id == SPARC_INS_FNHADDS || insn->id == SPARC_INS_FHADDS) ? INT2F(RZ_FLOAT_IEEE754_BIN_32, SPARC_RMODE(), U32(2)) : INT2F(RZ_FLOAT_IEEE754_BIN_64, SPARC_RMODE(), U64(2));
		RzILOpPure *res = FDIV(SPARC_RMODE(), FADD(SPARC_RMODE(), src0, src1), divisor);
		if (insn->id == SPARC_INS_FNHADDS || insn->id == SPARC_INS_FNHADDD) {
			res = FNEG(res);
		}
		return rz_sparc_fpure_to_freg(handle, mode, dst, res, width);
	}
	case SPARC_INS_FHSUBS:
	case SPARC_INS_FHSUBD: {
		RzILOpPure *divisor = insn->id == SPARC_INS_FHSUBS ? INT2F(RZ_FLOAT_IEEE754_BIN_32, SPARC_RMODE(), U32(2)) : INT2F(RZ_FLOAT_IEEE754_BIN_64, SPARC_RMODE(), U64(2));
		return rz_sparc_fpure_to_freg(handle, mode, dst, FDIV(SPARC_RMODE(), FSUB(SPARC_RMODE(), src0, src1), divisor), width);
	}
	case SPARC_INS_FDIVS:
	case SPARC_INS_FDIVD:
	case SPARC_INS_FDIVQ:
		return rz_sparc_fpure_to_freg(handle, mode, dst, FDIV(SPARC_RMODE(), src0, src1), width);
	case SPARC_INS_FSUBS:
	case SPARC_INS_FSUBD:
	case SPARC_INS_FSUBQ:
		return rz_sparc_fpure_to_freg(handle, mode, dst, FSUB(SPARC_RMODE(), src0, src1), width);
	case SPARC_INS_FMULS:
	case SPARC_INS_FMULD:
	case SPARC_INS_FMULQ:
		return rz_sparc_fpure_to_freg(handle, mode, dst, FMUL(SPARC_RMODE(), src0, src1), width);
	case SPARC_INS_FDMULQ:
	case SPARC_INS_FSMULD: {
		size_t dst_width = fload_dst_width_bits(insn);
		RzFloatFormat fmt = insn->id == SPARC_INS_FSMULD ? RZ_FLOAT_IEEE754_BIN_64 : RZ_FLOAT_IEEE754_BIN_128;
		return rz_sparc_fpure_to_freg(handle, mode, dst, FMUL(SPARC_RMODE(), FCONVERT(fmt, SPARC_RMODE(), src0), FCONVERT(fmt, SPARC_RMODE(), src1)), dst_width);
	}
	}
	NOT_IMPLEMENTED;
}

static RzILOpEffect *arithmetic_float_op_2(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	size_t width = fload_operands_width_bits(insn);
	RzILOpPure *src0 = rz_sparc_cs_get_operand(handle, insn, mode, 0, width);
	sparc_reg dst = INSOP(1).reg;
	if (!src0) {
		rz_warn_if_reached();
		return NULL;
	}

	switch (insn->id) {
	default:
		rz_warn_if_reached();
		NOT_IMPLEMENTED;
	case SPARC_INS_FMOVS:
	case SPARC_INS_FMOVD:
	case SPARC_INS_FMOVQ:
	case SPARC_INS_FSRC1:
	case SPARC_INS_FSRC2:
	case SPARC_INS_FSRC1S:
	case SPARC_INS_FSRC2S:
		return rz_sparc_fpure_to_freg(handle, mode, dst, src0, width);
	case SPARC_INS_FNEGD:
	case SPARC_INS_FNEGQ:
	case SPARC_INS_FNEGS:
		return rz_sparc_fpure_to_freg(handle, mode, dst, FNEG(src0), width);
	case SPARC_INS_FABSS:
	case SPARC_INS_FABSD:
	case SPARC_INS_FABSQ:
		return rz_sparc_fpure_to_freg(handle, mode, dst, FABS(src0), width);
	}
}

static RzILOpEffect *convert_float_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	size_t src_width = fload_operands_width_bits(insn);
	RzILOpPure *src0 = rz_sparc_cs_get_operand(handle, insn, mode, 0, src_width);
	size_t dst_width = fload_dst_width_bits(insn);
	sparc_reg dst = INSOP(1).reg;
	if (!src0) {
		rz_warn_if_reached();
		return NULL;
	}

	switch (insn->id) {
	default:
		rz_warn_if_reached();
		NOT_IMPLEMENTED;
	// Float to BitVector
	case SPARC_INS_FDTOI:
	case SPARC_INS_FQTOI:
	case SPARC_INS_FSTOI:
	case SPARC_INS_FDTOX:
	case SPARC_INS_FQTOX:
	case SPARC_INS_FSTOX:
		return rz_sparc_bv_to_consec_regs(handle, mode, dst, F2INT(dst_width, SPARC_RMODE(), src0), dst_width);
	// BitVector to Float
	case SPARC_INS_FITOS:
	case SPARC_INS_FXTOS:
		return rz_sparc_bv_to_consec_regs(handle, mode, dst, F2BV(SINT2F(RZ_FLOAT_IEEE754_BIN_32, SPARC_RMODE(), src0)), dst_width);
	case SPARC_INS_FXTOD:
	case SPARC_INS_FITOD:
		return rz_sparc_bv_to_consec_regs(handle, mode, dst, F2BV(SINT2F(RZ_FLOAT_IEEE754_BIN_64, SPARC_RMODE(), src0)), dst_width);
	case SPARC_INS_FITOQ:
	case SPARC_INS_FXTOQ:
		return rz_sparc_bv_to_consec_regs(handle, mode, dst, F2BV(SINT2F(RZ_FLOAT_IEEE754_BIN_128, SPARC_RMODE(), src0)), dst_width);
	// Float to Float
	case SPARC_INS_FDTOS:
	case SPARC_INS_FQTOS:
		return rz_sparc_fpure_to_freg(handle, mode, dst, FCONVERT(RZ_FLOAT_IEEE754_BIN_32, SPARC_RMODE(), src0), dst_width);
	case SPARC_INS_FQTOD:
	case SPARC_INS_FSTOD:
		return rz_sparc_fpure_to_freg(handle, mode, dst, FCONVERT(RZ_FLOAT_IEEE754_BIN_64, SPARC_RMODE(), src0), dst_width);
	case SPARC_INS_FDTOQ:
	case SPARC_INS_FSTOQ:
		return rz_sparc_fpure_to_freg(handle, mode, dst, FCONVERT(RZ_FLOAT_IEEE754_BIN_128, SPARC_RMODE(), src0), dst_width);
	}
}

static RzILOpEffect *compare_float_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	size_t src_width = fload_operands_width_bits(insn);
	RzILOpPure *src0 = rz_sparc_cs_get_operand(handle, insn, mode, 0, src_width);
	RzILOpPure *src1 = rz_sparc_cs_get_operand(handle, insn, mode, 1, src_width);
	if (!src0 || !src1) {
		rz_warn_if_reached();
		return NULL;
	}
	size_t fcc = 4;
	switch (INSDETAIL().cc_field) {
	default:
		rz_warn_if_reached();
		return NULL;
	case SPARC_CC_FIELD_NONE:
		break;
	case SPARC_CC_FIELD_FCC0:
	case SPARC_CC_FIELD_FCC1:
	case SPARC_CC_FIELD_FCC2:
	case SPARC_CC_FIELD_FCC3:
		fcc = INSDETAIL().cc_field;
		break;
	}

	switch (insn->id) {
	case SPARC_INS_FCMPS:
	case SPARC_INS_FCMPD:
	case SPARC_INS_FCMPQ: {
		RzILOpEffect *get_v =
			SETL("fcc_v",
				ITE(OR(IS_FNAN(VARL("flx")), IS_FNAN(VARL("fly"))), UA(3),
					ITE(FEQ(VARL("flx"), VARL("fly")), UA(0),
						ITE(FLT(VARL("flx"), VARL("fly")), UA(1),
							UA(2)))));
		RzILOpEffect *set_v = SET_FCC(fcc, VARL("fcc_v"));
		return SEQ3(SETL("flx", src0),
			SETL("fly", src1),
			SEQ2(get_v, set_v));
	}
	case SPARC_INS_FCMPES:
	case SPARC_INS_FCMPED:
	case SPARC_INS_FCMPEQ: {
		RzILOpEffect *get_v = SETL("fcc_v",
			ITE(FEQ(VARL("flx"), VARL("fly")), UA(0),
				ITE(FLT(VARL("flx"), VARL("fly")), UA(1),
					UA(2))));
		RzILOpEffect *set_v = SET_FCC(fcc, VARL("fcc_v"));
		return SEQ3(SETL("flx", src0),
			SETL("fly", src1),
			BRANCH(OR(IS_FNAN(VARL("flx")), IS_FNAN(VARL("fly"))),
				SEQ2(SET_FCC(fcc, UA(3)), GOTO("fp_exception")),
				SEQ2(get_v, set_v)));
	}
	case SPARC_INS_FLCMPD:
	case SPARC_INS_FLCMPS: {
		RzILOpEffect *get_v =
			SETL("fcc_v",
				ITE(IS_FNAN(VARL("fly")), UA(3),
					ITE(IS_FNAN(VARL("flx")), UA(2),
						ITE(FLT(VARL("flx"), VARL("fly")), UA(1), UA(0)))));
		RzILOpEffect *set_v = SET_FCC(fcc, VARL("fcc_v"));
		return SEQ3(SETL("flx", src0),
			SETL("fly", src1),
			SEQ2(get_v, set_v));
	}
	}

	rz_il_op_pure_free(src0);
	rz_il_op_pure_free(src1);
	// Input registers are always 64 bit wide, but the chunks to compare are
	// src_width wide.
	src0 = rz_sparc_cs_get_operand(handle, insn, mode, 0, SPARC_DOUBLE_WORD);
	src1 = rz_sparc_cs_get_operand(handle, insn, mode, 1, SPARC_DOUBLE_WORD);
	src0 = F2BV(src0);
	src1 = F2BV(src1);
	const char *dst = cs_reg_name(handle, INSOP(2).reg);
	if (!dst) {
		rz_warn_if_reached();
		return NULL;
	}
	rz_il_bool_2args_op *cmp;
	switch (insn->id) {
	default:
		rz_warn_if_reached();
		NOT_IMPLEMENTED;
	case SPARC_INS_FCMPEQ16:
	case SPARC_INS_FCMPEQ32:
		cmp = rz_il_op_new_eq;
		break;
	case SPARC_INS_FCMPGT16:
	case SPARC_INS_FCMPGT32:
		cmp = rz_il_op_new_sgt;
		break;
	case SPARC_INS_FCMPLE16:
	case SPARC_INS_FCMPLE32:
		cmp = rz_il_op_new_sle;
		break;
	case SPARC_INS_FCMPNE16:
	case SPARC_INS_FCMPNE32:
		cmp = rz_il_op_new_ne;
		break;
	}
	// Compare each chunk
	RzILOpEffect *seq = NULL;
	for (size_t i = 0; i < SPARC_DOUBLE_WORD; i += src_width) {
		RzILOpEffect *cmp_set = BRANCH(cmp(
						       SIGNED(src_width, SHIFTR0(VARL("left"), U8(i))),
						       SIGNED(src_width, SHIFTR0(VARL("right"), U8(i)))),
			SET_BIT(i / src_width, dst, SPARC_ARCH_BITS), EMPTY());
		seq = !seq ? cmp_set : SEQ2(seq, cmp_set);
	}
	return SEQ4(SSETG(dst, UA(0)), SETL("left", src0), SETL("right", src1), seq);
}

static RzILOpEffect *arithmetic_float_op_1(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	size_t width = fload_operands_width_bits(insn);
	RzILOpPure *src0 = rz_sparc_cs_get_operand(handle, insn, mode, 0, width);
	if (!src0) {
		rz_warn_if_reached();
		return NULL;
	}

	switch (insn->id) {
	default:
		rz_il_op_pure_free(src0);
		rz_warn_if_reached();
		NOT_IMPLEMENTED;
	case SPARC_INS_FONE:
	case SPARC_INS_FONES:
		rz_il_op_pure_free(src0);
		return rz_sparc_bv_to_consec_regs(handle, mode, INSOP(0).reg, width == SPARC_WORD ? U32(UT32_MAX) : U64(UT64_MAX), width);
	case SPARC_INS_FZERO:
	case SPARC_INS_FZEROS:
		rz_il_op_pure_free(src0);
		return rz_sparc_bv_to_consec_regs(handle, mode, INSOP(0).reg, width == SPARC_WORD ? U32(0) : U64(0), width);
	case SPARC_INS_FSQRTS:
	case SPARC_INS_FSQRTD:
	case SPARC_INS_FSQRTQ:
		return rz_sparc_fpure_to_freg(handle, mode, INSOP(1).reg, FSQRT(SPARC_RMODE(), src0), width);
	}
}

static RzILOpEffect *logic_float_op_3(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	size_t width = fload_operands_width_bits(insn);
	RzILOpPure *src0 = rz_sparc_cs_get_operand(handle, insn, mode, 0, width);
	RzILOpPure *src1 = rz_sparc_cs_get_operand(handle, insn, mode, 1, width);
	sparc_reg dst = INSOP(2).reg;
	if (!src0 || !src1) {
		rz_warn_if_reached();
		return NULL;
	}

	switch (insn->id) {
	default:
		rz_warn_if_reached();
		NOT_IMPLEMENTED;
	case SPARC_INS_FAND:
	case SPARC_INS_FANDS:
		return rz_sparc_bv_to_consec_regs(handle, mode, dst, LOGAND(F2BV(src0), F2BV(src1)), width);
	case SPARC_INS_FNAND:
	case SPARC_INS_FNANDS:
		return rz_sparc_bv_to_consec_regs(handle, mode, dst, LOGNOT(LOGAND(F2BV(src0), F2BV(src1))), width);
	case SPARC_INS_FOR:
	case SPARC_INS_FORS:
		return rz_sparc_bv_to_consec_regs(handle, mode, dst, LOGOR(F2BV(src0), F2BV(src1)), width);
	case SPARC_INS_FNOR:
	case SPARC_INS_FNORS:
		return rz_sparc_bv_to_consec_regs(handle, mode, dst, LOGNOT(LOGOR(F2BV(src0), F2BV(src1))), width);
	case SPARC_INS_FXOR:
	case SPARC_INS_FXORS:
		return rz_sparc_bv_to_consec_regs(handle, mode, dst, LOGXOR(F2BV(src0), F2BV(src1)), width);
	case SPARC_INS_FXNOR:
	case SPARC_INS_FXNORS:
		return rz_sparc_bv_to_consec_regs(handle, mode, dst, LOGNOT(LOGXOR(F2BV(src0), F2BV(src1))), width);
	case SPARC_INS_FANDNOT1:
	case SPARC_INS_FANDNOT1S:
		return rz_sparc_bv_to_consec_regs(handle, mode, dst, LOGAND(LOGNOT(F2BV(src0)), F2BV(src1)), width);
	case SPARC_INS_FANDNOT2:
	case SPARC_INS_FANDNOT2S:
		return rz_sparc_bv_to_consec_regs(handle, mode, dst, LOGAND(F2BV(src0), LOGNOT(F2BV(src1))), width);
	case SPARC_INS_FORNOT1:
	case SPARC_INS_FORNOT1S:
		return rz_sparc_bv_to_consec_regs(handle, mode, dst, LOGOR(LOGNOT(F2BV(src0)), F2BV(src1)), width);
	case SPARC_INS_FORNOT2:
	case SPARC_INS_FORNOT2S:
		return rz_sparc_bv_to_consec_regs(handle, mode, dst, LOGOR(F2BV(src0), LOGNOT(F2BV(src1))), width);
	}
}

static RzILOpEffect *logic_float_op_1(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	size_t width = fload_operands_width_bits(insn);
	RzILOpPure *src0 = rz_sparc_cs_get_operand(handle, insn, mode, 0, width);
	sparc_reg dst = INSOP(1).reg;
	if (!src0) {
		rz_warn_if_reached();
		return NULL;
	}

	switch (insn->id) {
	default:
		rz_warn_if_reached();
		NOT_IMPLEMENTED;
	case SPARC_INS_FNOT1:
	case SPARC_INS_FNOT1S:
	case SPARC_INS_FNOT2:
	case SPARC_INS_FNOT2S:
		return rz_sparc_bv_to_consec_regs(handle, mode, dst, LOGNOT(F2BV(src0)), width);
	}
	NOT_IMPLEMENTED;
}

static RzILOpEffect *logical_int_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	RzILOpPure *src0 = CAST_UA(rz_sparc_cs_get_operand(handle, insn, mode, 0, 0));
	RzILOpPure *src1 = CAST_UA(rz_sparc_cs_get_operand(handle, insn, mode, 1, 0));
	const char *dst = cs_reg_name(handle, INSOP(2).reg);
	RzSparcCCRBits bits = { 0 };
	bits.icc_v = RZ_SPARC_CC_UNSET;
	bits.icc_c = RZ_SPARC_CC_UNSET;
	bits.xcc_v = RZ_SPARC_CC_UNSET;
	bits.xcc_c = RZ_SPARC_CC_UNSET;

	switch (insn->id) {
	case SPARC_INS_ANDCC:
		return SEQ2(rz_sparc_2args_ccr(RZ_SPARC_CCR_OP_AND, src0, src1, NULL, &bits), SSETG(dst, CAST_UA(VARL("res128"))));
	case SPARC_INS_ANDNCC:
		return SEQ2(rz_sparc_2args_ccr(RZ_SPARC_CCR_OP_AND, src0, LOGNOT(src1), NULL, &bits), SSETG(dst, CAST_UA(VARL("res128"))));
	case SPARC_INS_ORCC:
		return SEQ2(rz_sparc_2args_ccr(RZ_SPARC_CCR_OP_OR, src0, src1, NULL, &bits), SSETG(dst, CAST_UA(VARL("res128"))));
	case SPARC_INS_ORNCC:
		return SEQ2(rz_sparc_2args_ccr(RZ_SPARC_CCR_OP_OR, src0, LOGNOT(src1), NULL, &bits), SSETG(dst, CAST_UA(VARL("res128"))));
	case SPARC_INS_XORCC:
		return SEQ2(rz_sparc_2args_ccr(RZ_SPARC_CCR_OP_XOR, src0, src1, NULL, &bits), SSETG(dst, CAST_UA(VARL("res128"))));
	case SPARC_INS_XNORCC:
		return SEQ2(rz_sparc_2args_ccr(RZ_SPARC_CCR_OP_XOR, src0, LOGNOT(src1), NULL, &bits), SSETG(dst, CAST_UA(VARL("res128"))));
	case SPARC_INS_AND:
		return SSETG(dst, CAST_UA(LOGAND(src0, src1)));
	case SPARC_INS_ANDN:
		return SSETG(dst, CAST_UA(LOGAND(src0, LOGNOT(src1))));
	case SPARC_INS_OR:
		return SSETG(dst, CAST_UA(LOGOR(src0, src1)));
	case SPARC_INS_ORN:
		return SSETG(dst, CAST_UA(LOGOR(src0, LOGNOT(src1))));
	case SPARC_INS_XOR:
		return SSETG(dst, CAST_UA(LOGXOR(src0, src1)));
	case SPARC_INS_XNOR:
		return SSETG(dst, CAST_UA(LOGNOT(LOGXOR(src0, src1))));
	}
	rz_warn_if_reached();
	NOT_IMPLEMENTED;
}

static size_t get_cmask_part(sparc_insn id, size_t part, bool bit_set) {
	switch (id) {
	default:
		break;
	case SPARC_INS_CMASK8:
		switch (part) {
		default:
			break;
		case 0:
			return bit_set ? 0x7 : 0xf;
		case 1:
			return bit_set ? 0x6 : 0xe;
		case 2:
			return bit_set ? 0x5 : 0xd;
		case 3:
			return bit_set ? 0x4 : 0xc;
		case 4:
			return bit_set ? 0x3 : 0xb;
		case 5:
			return bit_set ? 0x2 : 0xa;
		case 6:
			return bit_set ? 0x1 : 0x9;
		case 7:
			return bit_set ? 0x0 : 0x8;
		}
		break;
	case SPARC_INS_CMASK16:
		switch (part) {
		default:
			break;
		case 0:
			return bit_set ? 0x67 : 0xef;
		case 1:
			return bit_set ? 0x45 : 0xcd;
		case 2:
			return bit_set ? 0x23 : 0xab;
		case 3:
			return bit_set ? 0x01 : 0x89;
		}
		break;
	case SPARC_INS_CMASK32:
		if (part == 0) {
			return bit_set ? 0x4567 : 0xcdef;
		} else if (part == 1) {
			return bit_set ? 0x0123 : 0x89ab;
		}
		break;
	}
	rz_warn_if_reached();
	return 0;
}

/**
 * \brief Get the address space identifier (ASI) for the given instruction.
 *
 * NOTE: This function always returns 0, except for SAVE and RESTORE.
 * Technically this is incorrect.
 * But RzIL currently doesn't allow for multiple memories which can be switched during runtime.
 */
static inline sparc_asi get_insn_asi(const cs_insn *insn) {
	rz_return_val_if_fail(insn, SPARC_ASITAG_ASI_INVALID);
	switch (insn->id) {
	default:
		// Runtime memory index calculation is not implemented yet. Default to
		// single memory address space.
		return 0;
	case SPARC_INS_SAVE:
	case SPARC_INS_RESTORE:
	case SPARC_INS_RETT:
		return SPARC_ASI_INDEX_RW;
	}
}

static char *backed_up_regs[] = {
	// clang-format off
	"l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7",
	"i0", "i1", "i2", "i3", "i4", "i5", "fp", "i7"
	// clang-format on
};

static char *unset_regs[] = {
	// clang-format off
	"l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7",
	"o0", "o1", "o2", "o3", "o4", "o5", "sp", "o7"
	// clang-format on
};

static char *shared_regs_out[] = {
	// clang-format off
	"o0", "o1", "o2", "o3", "o4", "o5", "sp", "o7",
	// clang-format on
};

static char *shared_regs_in[] = {
	// clang-format off
	"i0", "i1", "i2", "i3", "i4", "i5", "fp", "i7",
	// clang-format on
};

static RzILOpEffect *save_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	const char *dst = cs_reg_name(handle, INSOP(2).reg);
	RzILOpPure *src0 = CAST_UA(rz_sparc_cs_get_operand(handle, insn, mode, 0, 0));
	RzILOpPure *src1 = CAST_UA(rz_sparc_cs_get_operand(handle, insn, mode, 1, 0));
	if (!dst || !src0 || !src1) {
		rz_il_op_pure_free(src0);
		rz_il_op_pure_free(src1);
		rz_warn_if_reached();
		return NULL;
	}

	sparc_asi asi = get_insn_asi(insn);

	RzILOpEffect *operand_add = SETL("add_result", ADD(src0, src1));

	RzILOpEffect *backup_regs = SETL("reg_window_base", MUL(VARG("cwp"), UA(SPARC_REG_WINDOW_SIZE)));
	for (size_t i = 0; i < RZ_ARRAY_SIZE(backed_up_regs); ++i) {
		RzILOpEffect *store_reg = STOREWI(asi, ADD(VARL("reg_window_base"), UA(i * SPARC_ARCH_BITS)), VARG(backed_up_regs[i]));
		backup_regs = SEQ2(backup_regs, store_reg);
	}
	RzILOpEffect *update_cwp = IN_64BIT_MODE ? SETG("cwp", MOD(ADD(VARG("cwp"), UA(1)), UA(SPARC_NWINDOWS))) : SETG("cwp", MOD(SUB(VARG("cwp"), UA(1)), UA(SPARC_NWINDOWS)));
	RzILOpEffect *copy_out_to_in = NULL;
	for (size_t i = 0; i < RZ_ARRAY_SIZE(shared_regs_out); ++i) {
		RzILOpEffect *copy_reg = SETG(shared_regs_in[i], VARG(shared_regs_out[i]));
		copy_out_to_in = copy_out_to_in ? SEQ2(copy_out_to_in, copy_reg) : copy_reg;
	}
	RzILOpEffect *unset_lo = NULL;
	for (size_t i = 0; i < RZ_ARRAY_SIZE(unset_regs); ++i) {
		RzILOpEffect *unset_reg = SETG(unset_regs[i], UA(0));
		unset_lo = unset_lo ? SEQ2(unset_lo, unset_reg) : unset_reg;
	}
	RzILOpEffect *store_add_res = SSETG(dst, VARL("add_result"));
	return SEQ6(operand_add, backup_regs, update_cwp, copy_out_to_in, unset_lo, store_add_res);
}

static RzILOpEffect *restore_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	bool is_rett = insn->id == SPARC_INS_RETT;
	const char *dst = is_rett ? NULL : cs_reg_name(handle, INSOP(2).reg);
	RzILOpPure *src0 = is_rett ? NULL : CAST_UA(rz_sparc_cs_get_operand(handle, insn, mode, 0, 0));
	RzILOpPure *src1 = is_rett ? NULL : CAST_UA(rz_sparc_cs_get_operand(handle, insn, mode, 1, 0));
	if ((!dst || !src0 || !src1) && !is_rett) {
		rz_il_op_pure_free(src0);
		rz_il_op_pure_free(src1);
		rz_warn_if_reached();
		return NULL;
	}

	sparc_asi asi = get_insn_asi(insn);

	RzILOpEffect *operand_add = is_rett ? EMPTY() : SETL("add_result", ADD(src0, src1));
	RzILOpEffect *update_cwp = IN_64BIT_MODE ? SETG("cwp", MOD(SUB(VARG("cwp"), UA(1)), UA(SPARC_NWINDOWS))) : SETG("cwp", MOD(ADD(VARG("cwp"), UA(1)), UA(SPARC_NWINDOWS)));

	RzILOpEffect *copy_in_to_out = NULL;
	for (size_t i = 0; i < RZ_ARRAY_SIZE(shared_regs_out); ++i) {
		RzILOpEffect *copy_reg = SSETG(shared_regs_out[i], VARG(shared_regs_in[i]));
		copy_in_to_out = copy_in_to_out ? SEQ2(copy_in_to_out, copy_reg) : copy_reg;
	}

	RzILOpEffect *restore_regs = SETL("reg_window_base", MUL(VARG("cwp"), UA(SPARC_REG_WINDOW_SIZE)));
	for (size_t i = 0; i < RZ_ARRAY_SIZE(backed_up_regs); ++i) {
		RzILOpPure *reg_val = LOADWI(asi, SPARC_ARCH_BITS, ADD(VARL("reg_window_base"), UA(i * SPARC_ARCH_BITS)));
		restore_regs = SEQ2(restore_regs, SETG(backed_up_regs[i], reg_val));
	}

	RzILOpEffect *store_add_res = is_rett ? EMPTY() : SSETG(dst, VARL("add_result"));
	return SEQ5(operand_add, update_cwp, copy_in_to_out, restore_regs, store_add_res);
}

static RzILOpEffect *read_write_regs_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	switch (insn->id) {
	default:
		rz_warn_if_reached();
		return NULL;
	case SPARC_INS_WR: {
		RzILOpPure *rs1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
		RzILOpPure *src2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, 0);
		const char *dst = cs_reg_name(handle, INSOP(2).reg);
		if (!rs1 || !src2 || !dst) {
			rz_warn_if_reached();
			rz_il_op_pure_free(rs1);
			rz_il_op_pure_free(src2);
			return NULL;
		}
		RzILOpPure *res = LOGXOR(rs1, src2);
		if (INSOP(2).reg == SPARC_REG_ASR2) { // ccr
			res = UNSIGNED(8, res);
		} else if (INSOP(2).reg == SPARC_REG_ASR6) {
			// FPRS is 3 bits wide.
			res = UNSIGNED(3, res);
		}
		return SSETG(dst, res);
	}
	case SPARC_INS_RD: {
		RzILOpPure *src1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
		const char *dst = cs_reg_name(handle, INSOP(1).reg);
		if (!src1 || !dst) {
			rz_warn_if_reached();
			rz_il_op_pure_free(src1);
			return NULL;
		}
		RzILOpPure *res = src1;
		if (INSOP(0).reg == SPARC_REG_ASR2) {
			res = CAST_UA(res);
		} else if (INSOP(0).reg == SPARC_REG_ASR6) {
			// FPRS is 3 bits wide.
			res = CAST_UA(res);
		}
		return SSETG(dst, res);
	}
	}
	rz_warn_if_reached();
	NOT_IMPLEMENTED;
}

static RzILOpEffect *misc_insn(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	switch (insn->id) {
	default:
		rz_warn_if_reached();
		return NULL;
	case SPARC_INS_LZCNT: {
		RzILOpPure *rs1 = UNSIGNED(64, rz_sparc_cs_get_operand(handle, insn, mode, 0, 0));
		const char *dst = cs_reg_name(handle, INSOP(1).reg);
		RzILOpEffect *count = REPEAT(AND(INV(MSB(VARL("rs1"))), ULT(VARL("c"), U64(64))), SEQ2(SETL("c", ADD(VARL("c"), U64(1))), SETL("rs1", SHIFTL0(VARL("rs1"), U8(1)))));
		return SEQ4(SETL("c", U64(0)), SETL("rs1", rs1), count, SSETG(dst, CAST_UA(VARL("c"))));
	}
	case SPARC_INS_POPC: {
		RzILOpPure *rs1 = UNSIGNED(64, rz_sparc_cs_get_operand(handle, insn, mode, 0, 0));
		const char *dst = cs_reg_name(handle, INSOP(1).reg);
		RzILOpEffect *count = REPEAT(ULT(VARL("i"), U8(64)), SEQ3(SETL("i", ADD(VARL("i"), U8(1))), SETL("c", ADD(VARL("c"), ITE(LSB(VARL("rs1")), U64(1), U64(0)))), SETL("rs1", SHIFTR0(VARL("rs1"), U8(1)))));
		return SEQ5(SETL("i", U8(0)), SETL("c", U64(0)), SETL("rs1", rs1), count, SSETG(dst, CAST_UA(VARL("c"))));
	}
	case SPARC_INS_ALIGNADDR:
	case SPARC_INS_ALIGNADDRL: {
		RzILOpPure *rs1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
		RzILOpPure *rs2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, 0);
		const char *dst = cs_reg_name(handle, INSOP(2).reg);
		RzILOpPure *align_bits = LOGAND(VARL("addr"), U64(7));
		if (insn->id == SPARC_INS_ALIGNADDRL) {
			align_bits = LOGAND(NEG(align_bits), U64(7));
		}
		return SEQ3(SETL("addr", ADD(rs1, rs2)), SSETG("gsr", LOGOR(LOGAND(VARG("gsr"), U64(-8)), align_bits)), SSETG(dst, LOGAND(VARL("addr"), U64(-8))));
	}
	case SPARC_INS_FALIGNDATA: {
		RzILOpPure *rs1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, SPARC_DOUBLE_WORD);
		RzILOpPure *rs2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, SPARC_DOUBLE_WORD);
		const char *dst = cs_reg_name(handle, INSOP(2).reg);
		return SEQ2(SETL("data", APPEND(F2BV(rs1), F2BV(rs2))), SETG(dst, UNSIGNED(64, SHIFTR0(VARL("data"), MUL(SUB(U8(8), UNSIGNED(8, UNSIGNED(3, VARG("gsr")))), U8(8))))));
	}
	case SPARC_INS_PDIST:
	case SPARC_INS_PDISTN: {
		RzILOpPure *rs1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, SPARC_DOUBLE_WORD);
		RzILOpPure *rs2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, SPARC_DOUBLE_WORD);
		RzILOpPure *dst_val = insn->id == SPARC_INS_PDIST ? F2BV(rz_sparc_cs_get_operand(handle, insn, mode, 2, SPARC_DOUBLE_WORD)) : U64(0);
		size_t dst = INSOP(2).reg;
		RzILOpEffect *inc_c = SETL("c", ADD(VARL("c"), U8(1)));
		RzILOpEffect *sub = SETL("sub", SUB(LOGAND(U64(0xff), SHIFTR0(VARL("rs1"), MUL(U8(8), VARL("c")))), LOGAND(U64(0xff), SHIFTR0(VARL("rs2"), MUL(U8(8), VARL("c"))))));
		RzILOpEffect *dist = REPEAT(ULT(VARL("c"), U8(8)),
			SEQ3(sub, SETL("dst", ADD(VARL("dst"), ITE(SLT(VARL("sub"), U64(0)), NEG(VARL("sub")), VARL("sub")))), inc_c));
		return SEQ6(
			SETL("dst", dst_val),
			SETL("c", U8(0)),
			SETL("rs1", F2BV(rs1)),
			SETL("rs2", F2BV(rs2)),
			dist,
			rz_sparc_bv_to_consec_regs(handle, mode, dst, VARL("dst"), SPARC_DOUBLE_WORD));
	}
	case SPARC_INS_BMASK: {
		RzILOpPure *rs1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
		RzILOpPure *rs2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, 0);
		const char *dst = cs_reg_name(handle, INSOP(2).reg);
		return SEQ3(SETL("res", ADD(rs1, rs2)), SSETG(dst, VARL("res")), SETG("gsr", LOGOR(LOGAND(VARG("gsr"), U64(0xffffffff)), SHIFTL0(VARL("res"), U8(32)))));
	}
	case SPARC_INS_BSHUFFLE: {
		RzILOpPure *rs1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, SPARC_DOUBLE_WORD);
		RzILOpPure *rs2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, SPARC_DOUBLE_WORD);
		size_t dst = INSOP(2).reg;
		// c is the destination byte index.
		// Counting from 0 (most significant byte index) to 7 (least significant byte index).
		RzILOpEffect *inc_c = SETL("i", ADD(VARL("i"), U8(1)));
		// Get the byte index of the sourse value from GSR.mask. Byte index is between 0-15.
		RzILOpEffect *set_src_byte_idx = SETL("src_byte_idx", UNSIGNED(8, LOGAND(U64(0xf), SHIFTR0(VARL("mask"), SUB(U8(28), MUL(VARL("i"), U8(4)))))));
		// Get the source byte.
		RzILOpEffect *set_src_byte = SETL("src_byte", UNSIGNED(8, SHIFTR0(VARL("src"), SUB(U8(120), MUL(VARL("src_byte_idx"), U8(8))))));
		// Set the src byte at index c in the destination value.
		RzILOpEffect *set_dst_byte = SETL("dst", DEPOSIT64(VARL("dst"), MUL(VARL("i"), U8(8)), U32(8), UNSIGNED(64, VARL("src_byte"))));
		RzILOpEffect *shuffle = REPEAT(ULT(VARL("i"), U8(8)), SEQ4(set_src_byte_idx, set_src_byte, set_dst_byte, inc_c));
		size_t dst_width = fload_dst_width_bits(insn);
		return SEQ6(
			SETL("dst", U64(0)),
			SETL("mask", SHIFTR0(VARG("gsr"), U8(32))),
			SETL("i", U8(0)),
			SETL("src", APPEND(F2BV(rs1), F2BV(rs2))),
			shuffle,
			rz_sparc_bv_to_consec_regs(handle, mode, dst, VARL("dst"), dst_width));
	}
	case SPARC_INS_FMEAN16: {
		size_t dst_width = fload_dst_width_bits(insn);
		RzILOpPure *rs1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, SPARC_DOUBLE_WORD);
		RzILOpPure *rs2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, SPARC_DOUBLE_WORD);
		size_t dst = INSOP(2).reg;
		RzILOpEffect *inc_c = SETL("c", ADD(VARL("c"), U8(1)));
		RzILOpEffect *set_operands = SEQ2(SETL("op1", SIGNED(16, SHIFTR0(VARL("rs1"), MUL(VARL("c"), U8(16))))),
			SETL("op2", SIGNED(16, SHIFTR0(VARL("rs2"), MUL(VARL("c"), U8(16))))));
		RzILOpEffect *mean_part = SETL("part_res", UNSIGNED(16, SHIFTR0(ADD(ADD(SIGNED(17, VARL("op1")), SIGNED(17, VARL("op2"))), UN(17, 1)), U8(1))));
		RzILOpEffect *set_mean_part = SETL("res", LOGOR(VARL("res"), SHIFTL0(UNSIGNED(64, VARL("part_res")), MUL(VARL("c"), U8(16)))));
		RzILOpEffect *mean = REPEAT(ULT(VARL("c"), U8(4)), SEQ4(set_operands, mean_part, set_mean_part, inc_c));
		return SEQ6(
			SETL("res", U64(0)),
			SETL("c", U8(0)),
			SETL("rs1", F2BV(rs1)),
			SETL("rs2", F2BV(rs2)),
			mean,
			rz_sparc_bv_to_consec_regs(handle, mode, dst, VARL("res"), dst_width));
	}
	case SPARC_INS_FCHKSM16: {
		size_t dst_width = fload_dst_width_bits(insn);
		RzILOpPure *rs1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, SPARC_DOUBLE_WORD);
		RzILOpPure *rs2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, SPARC_DOUBLE_WORD);
		size_t dst = INSOP(2).reg;
		RzILOpEffect *inc_c = SETL("c", ADD(VARL("c"), U8(1)));
		RzILOpEffect *set_operands = SEQ2(SETL("op1", UNSIGNED(16, SHIFTR0(VARL("rs1"), MUL(VARL("c"), U8(16))))),
			SETL("op2", UNSIGNED(16, SHIFTR0(VARL("rs2"), MUL(VARL("c"), U8(16))))));
		RzILOpEffect *interm_sum = SETL("interm_sum", ADD(UNSIGNED(17, VARL("op1")), UNSIGNED(17, VARL("op2"))));
		RzILOpEffect *sum = SETL("sum", ITE(MSB(VARL("interm_sum")), UNSIGNED(16, ADD(VARL("interm_sum"), UN(17, 1))), UNSIGNED(16, VARL("interm_sum"))));
		RzILOpEffect *set_sum = SETL("res", LOGOR(VARL("res"), SHIFTL0(UNSIGNED(64, VARL("sum")), MUL(VARL("c"), U8(16)))));
		RzILOpEffect *chksum = REPEAT(ULT(VARL("c"), U8(4)), SEQ5(set_operands, interm_sum, sum, set_sum, inc_c));
		return SEQ6(
			SETL("res", U64(0)),
			SETL("c", U8(0)),
			SETL("rs1", F2BV(rs1)),
			SETL("rs2", F2BV(rs2)),
			chksum,
			rz_sparc_bv_to_consec_regs(handle, mode, dst, VARL("res"), dst_width));
	}
	case SPARC_INS_FPACK16: {
		size_t dst_width = fload_dst_width_bits(insn);
		RzILOpPure *rs2 = rz_sparc_cs_get_operand(handle, insn, mode, 0, SPARC_DOUBLE_WORD);
		size_t dst = INSOP(1).reg;
		RzILOpEffect *inc_c = SETL("c", ADD(VARL("c"), U8(1)));
		RzILOpEffect *set_part = SETL("part", SIGNED(16, SHIFTR0(VARL("rs2"), MUL(VARL("c"), U8(16)))));
		RzILOpEffect *scale_part = SETL("scaled_part", SHIFTRA(SHIFTL0(SIGNED(32, VARL("part")), VARL("scale")), U8(7)));
		RzILOpEffect *truncate = SETL("truncated", LOGAND(
								   // Negative case
								   ITE(SLT(VARL("scaled_part"), S32(0)), U32(0),
									   // >255 case
									   ITE(SGT(VARL("scaled_part"), U32(255)), U32(255),
										   // Else use the 8bits from the scaled value.
										   VARL("scaled_part"))),
								   U32(0xff)));
		RzILOpEffect *set_tval = SETL("res", DEPOSIT32(VARL("res"), MUL(VARL("c"), U8(8)), U32(8), VARL("truncated")));
		RzILOpEffect *pack = REPEAT(ULT(VARL("c"), U8(4)), SEQ5(set_part, scale_part, truncate, set_tval, inc_c));
		return SEQ6(
			SETL("res", U32(0)),
			SETL("c", U8(0)),
			// Bit 4 is ignored by FPACK16. So cast it to a 4bit not 5bit value.
			SETL("scale", UNSIGNED(8, UNSIGNED(4, SHIFTR0(VARG("gsr"), U8(3))))),
			SETL("rs2", F2BV(rs2)),
			pack,
			rz_sparc_bv_to_consec_regs(handle, mode, dst, VARL("res"), dst_width));
	}
	case SPARC_INS_FPACK32: {
		size_t dst_width = fload_dst_width_bits(insn);
		RzILOpPure *rs1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, SPARC_DOUBLE_WORD);
		RzILOpPure *rs2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, SPARC_DOUBLE_WORD);
		size_t dst = INSOP(2).reg;
		RzILOpEffect *inc_c = SETL("c", ADD(VARL("c"), U8(1)));
		RzILOpEffect *set_part = SETL("part", SIGNED(32, SHIFTR0(VARL("rs2"), MUL(VARL("c"), U8(32)))));
		RzILOpEffect *scale_part = SETL("scaled_part", SHIFTRA(SHIFTL0(SIGNED(64, VARL("part")), VARL("scale")), U8(23)));
		RzILOpEffect *truncate = SETL("truncated", LOGAND(
								   // Negative case
								   ITE(SLT(VARL("scaled_part"), S64(0)), U64(0),
									   // >255 case
									   ITE(UGT(VARL("scaled_part"), U64(255)), U64(255),
										   // Else use the 8bits from the scaled value.
										   VARL("scaled_part"))),
								   U64(0xff)));
		RzILOpEffect *set_tval = SETL("res", DEPOSIT64(VARL("res"), MUL(VARL("c"), U8(32)), U32(8), VARL("truncated")));
		RzILOpEffect *set_rs1_parts = SETL("res", DEPOSIT64(VARL("res"), ADD(MUL(VARL("c"), U8(32)), U8(8)), U32(24), EXTRACT64(VARL("rs1"), MUL(VARL("c"), U8(32)), U32(24))));
		RzILOpEffect *pack = REPEAT(ULT(VARL("c"), U8(2)), SEQ6(set_part, scale_part, truncate, set_tval, set_rs1_parts, inc_c));
		return SEQ7(
			SETL("res", U64(0)),
			SETL("c", U8(0)),
			SETL("scale", UNSIGNED(8, UNSIGNED(5, SHIFTR0(VARG("gsr"), U8(3))))),
			SETL("rs1", F2BV(rs1)),
			SETL("rs2", F2BV(rs2)),
			pack,
			rz_sparc_bv_to_consec_regs(handle, mode, dst, VARL("res"), dst_width));
	}
	case SPARC_INS_FPACKFIX: {
		size_t dst_width = fload_dst_width_bits(insn);
		RzILOpPure *rs2 = rz_sparc_cs_get_operand(handle, insn, mode, 0, SPARC_DOUBLE_WORD);
		size_t dst = INSOP(1).reg;
		RzILOpEffect *inc_c = SETL("c", ADD(VARL("c"), U8(1)));
		RzILOpEffect *set_part = SETL("part", SIGNED(32, SHIFTR0(VARL("rs2"), MUL(VARL("c"), U8(32)))));
		RzILOpEffect *scale_part = SETL("scaled_signed_part", SHIFTRA(SHIFTL0(SIGNED(64, VARL("part")), VARL("scale")), U8(16)));
		RzILOpEffect *truncate = SETL("truncated", UNSIGNED(32, LOGAND(
										// Negative case
										ITE(SLT(VARL("scaled_signed_part"), S64(-32768)), S64(-32768),
											// >32767 case
											ITE(SGT(VARL("scaled_signed_part"), S64(32767)), S64(32767),
												// Else use the 16bits from the scaled value.
												VARL("scaled_signed_part"))),
										U64(0xffff))));
		RzILOpEffect *set_tval = SETL("res", DEPOSIT32(VARL("res"), MUL(VARL("c"), U8(16)), U32(16), VARL("truncated")));
		RzILOpEffect *pack = REPEAT(ULT(VARL("c"), U8(2)), SEQ5(set_part, scale_part, truncate, set_tval, inc_c));
		return SEQ6(
			SETL("res", U32(0)),
			SETL("c", U8(0)),
			SETL("scale", UNSIGNED(8, UNSIGNED(5, SHIFTR0(VARG("gsr"), U8(3))))),
			SETL("rs2", F2BV(rs2)),
			pack,
			rz_sparc_bv_to_consec_regs(handle, mode, dst, VARL("res"), dst_width));
	}
	}
}

static RzILOpEffect *array_insn(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	RzILOpPure *rs1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
	RzILOpPure *rs2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, 0);
	RzILOpEffect *set_shift;
	RzILOpEffect *convert;
	const char *dst = cs_reg_name(handle, INSOP(2).reg);
	size_t shift = 0;
	switch (insn->id) {
	default:
		rz_warn_if_reached();
		rz_il_op_pure_free(rs1);
		rz_il_op_pure_free(rs2);
		return NULL;
	case SPARC_INS_ARRAY32:
		shift++;
		// fall-through
	case SPARC_INS_ARRAY16:
		shift++;
		// fall-through
	case SPARC_INS_ARRAY8: {
		set_shift = SETL("shft", U8(shift));
		convert = SEQ9(
			SETL("res", DEPOSIT64(VARL("res"), U8(0), U32(2), EXTRACT64(VARL("src"), U8(11), U32(2)))),
			SETL("res", DEPOSIT64(VARL("res"), U8(2), U32(2), EXTRACT64(VARL("src"), U8(33), U32(2)))),
			SETL("res", DEPOSIT64(VARL("res"), U8(4), U32(1), EXTRACT64(VARL("src"), U8(55), U32(1)))),
			SETL("res", DEPOSIT64(VARL("res"), U8(5), U32(3), EXTRACT64(VARL("src"), U8(13), U32(3)))),
			SETL("res", DEPOSIT64(VARL("res"), U8(9), U32(4), EXTRACT64(VARL("src"), U8(35), U32(4)))),
			SETL("res", DEPOSIT64(VARL("res"), U8(13), U32(4), EXTRACT64(VARL("src"), U8(56), U32(4)))),
			// Z_integer{8:5}
			SETL("res", DEPOSIT64(VARL("res"), ADD(U8(17), MUL(U8(2), VARL("n"))), U32(4), EXTRACT64(VARL("src"), U8(60), U32(4)))),
			// The following two are undefined for n = 0
			BRANCH(IS_ZERO(VARL("n")), EMPTY(), SEQ2(
								    // X_integer{6+n-1:6}
								    SETL("res", LET("len", UNSIGNED(32, VARL("n")), DEPOSIT64(VARL("res"), U8(17), VARLP("len"), EXTRACT64(VARL("src"), U8(17), VARLP("len"))))),
								    // Y_integer{6+n-1:6}
								    SETL("res", LET("len", UNSIGNED(32, VARL("n")), DEPOSIT64(VARL("res"), ADD(U8(17), VARL("n")), VARLP("len"), EXTRACT64(VARL("src"), U8(39), VARLP("len"))))))),
			// Lastly, shift result for ARRAY16 and ARRAY32
			SETL("res", SHIFTL0(VARL("res"), VARL("shft"))));
		return SEQ6(
			SETL("res", U64(0)),
			SETL("src", rs1),
			SETL("n", UNSIGNED(8, rs2)),
			set_shift,
			convert,
			SSETG(dst, VARL("res")));
	}
	}
}

static RzILOpEffect *cmask_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	RzILOpPure *rs2 = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
	size_t parts = 0;
	size_t part_width = 0;
	switch (insn->id) {
	default:
		rz_warn_if_reached();
		return NULL;
	case SPARC_INS_CMASK8:
		parts = 8;
		part_width = 4;
		break;
	case SPARC_INS_CMASK16:
		parts = 4;
		part_width = 8;
		break;
	case SPARC_INS_CMASK32:
		parts = 2;
		part_width = 16;
		break;
	}
	RzILOpEffect *set_mask = SEQ2(SETL("rs2", rs2), SETL("mask", U32(0x0)));
	for (size_t i = 0; i < parts; ++i) {
		// clang-format off
		set_mask = SEQ2(set_mask, SETL("mask",
		                               LOGOR(VARL("mask"),
		                                     SHIFTL0(ITE(BIT(i, VARL("rs2")),
		                                                 U32(get_cmask_part(insn->id, i, true)),
		                                                 U32(get_cmask_part(insn->id, i, false))),
		                                            U8(i * part_width)))));
		// clang-format on
	}
	return SEQ3(set_mask, SETG("gsr", LOGAND(VARG("gsr"), U64(UT32_MAX))), SETG("gsr", LOGOR(VARG("gsr"), APPEND(VARL("mask"), U32(0x0)))));
}

static RzILOpEffect *shift_float_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	size_t src_width = fload_operands_width_bits(insn);
	RzILOpPure *src0 = F2BV(rz_sparc_cs_get_operand(handle, insn, mode, 0, src_width));
	RzILOpPure *src1 = F2BV(rz_sparc_cs_get_operand(handle, insn, mode, 1, src_width));
	if (!src0 || !src1) {
		rz_warn_if_reached();
		return NULL;
	}
	size_t part_width = 0;
	size_t shft_amt_width = 0;
	switch (insn->id) {
	default:
		rz_warn_if_reached();
		NOT_IMPLEMENTED;
	case SPARC_INS_FSLL16:
	case SPARC_INS_FSRA16:
	case SPARC_INS_FSRL16:
	case SPARC_INS_FSLAS16:
		part_width = 16;
		shft_amt_width = 4;
		break;
	case SPARC_INS_FSLL32:
	case SPARC_INS_FSRA32:
	case SPARC_INS_FSRL32:
	case SPARC_INS_FSLAS32:
		part_width = 32;
		shft_amt_width = 5;
		break;
	}

	RzILOpEffect *shft_seq = SEQ3(SETL("res", UN(src_width, 0)), SETL("rs1", src0), SETL("rs2", src1));
	if (part_width == 16) {
		shft_seq = SEQ3(shft_seq, SETL("sat_min", UN(part_width, ST16_MIN)), SETL("sat_max", UN(part_width, ST16_MAX)));
	} else if (part_width == 32) {
		shft_seq = SEQ3(shft_seq, SETL("sat_min", UN(part_width, ST32_MIN)), SETL("sat_max", UN(part_width, ST32_MAX)));
	} else {
		rz_warn_if_reached();
		return NULL;
	}
	for (size_t i = 0; i < src_width / part_width; ++i) {
		RzILOpPure *part = UNSIGNED(part_width, SHIFTR0(VARL("rs1"), U8(i * part_width)));
		RzILOpPure *shft_amt = UNSIGNED(shft_amt_width, SHIFTR0(VARL("rs2"), U8(i * part_width)));
		switch (insn->id) {
		case SPARC_INS_FSLL16:
		case SPARC_INS_FSLL32:
			shft_seq = SEQ2(shft_seq, SETL("res", LOGOR(VARL("res"), SHIFTL0(UNSIGNED(src_width, SHIFTL0(part, shft_amt)), U8(i * part_width)))));
			break;
		case SPARC_INS_FSRL16:
		case SPARC_INS_FSRL32:
			shft_seq = SEQ2(shft_seq, SETL("res", LOGOR(VARL("res"), SHIFTL0(UNSIGNED(src_width, SHIFTR0(part, shft_amt)), U8(i * part_width)))));
			break;
		case SPARC_INS_FSRA16:
		case SPARC_INS_FSRA32:
			shft_seq = SEQ2(shft_seq, SETL("res", LOGOR(VARL("res"), SHIFTL0(UNSIGNED(src_width, SHIFTRA(part, shft_amt)), U8(i * part_width)))));
			break;
		case SPARC_INS_FSLAS16:
		case SPARC_INS_FSLAS32: {
			// Saturated shift of partitions
			// clang-format off
			shft_seq = SEQ6(shft_seq,
			                SETL("part", part),
			                SETL("orig_sign", MSB(VARL("part"))),
			                SETL("shft_res", SHIFTL0(VARL("part"), shft_amt)),
			                SETL("new_part", ITE(INV(XOR(VARL("orig_sign"), MSB(VARL("shft_res")))), VARL("part"), // Sign bits match. No saturation.
			                                      ITE(VARL("orig_sign"),
			                                          VARL("sat_min"),
			                                          VARL("sat_max")))),
			                SETL("res", LOGOR(VARL("res"), SHIFTL0(UNSIGNED(src_width, VARL("new_part")), U8(i * part_width)))));
			// clang-format on
			break;
		}
		}
	}
	return shft_seq;
}

/**
 * \brief Builds the RzIL op to get the mask.
 * The bits rs1[2:0] and rs2[2:0] effectively are the shift amount
 * to shift 0x3 (for EDGE32), 0xf (for EDGE16), or 0xff (for EDGE8) to the right or left
 * (depending on endianess).
 */
static RzILOpEffect *get_edge_mask(sparc_insn id, cs_mode mode, RzILOpPure *rs1, RzILOpPure *rs2, bool left) {
	RzILOpEffect *get_mask = left ? SETL("rs1", rs1) : SETL("rs2", rs2);
	switch (id) {
	default:
		rz_warn_if_reached();
		return NULL;
	case SPARC_INS_EDGE32:
	case SPARC_INS_EDGE32N:
	case SPARC_INS_EDGE32L:
	case SPARC_INS_EDGE32LN:
		// clang-format off
		get_mask = SEQ2(get_mask, left ?
		                SETL("shft_amt", SHIFTR0(LOGAND(UA(0x4), VARL("rs1")), U8(2))) :
		                SETL("shft_amt", SHIFTR0(LOGAND(UA(0x4), VARL("rs2")), U8(2))));
		// clang-format on
		break;
	case SPARC_INS_EDGE16:
	case SPARC_INS_EDGE16N:
	case SPARC_INS_EDGE16L:
	case SPARC_INS_EDGE16LN:
		// clang-format off
		get_mask = SEQ2(get_mask, left ?
		                SETL("shft_amt", SHIFTR0(LOGAND(UA(0x6), VARL("rs1")), U8(1))) :
		                SETL("shft_amt", SHIFTR0(LOGAND(UA(0x6), VARL("rs2")), U8(1))));
		// clang-format on
		break;
	case SPARC_INS_EDGE8:
	case SPARC_INS_EDGE8N:
	case SPARC_INS_EDGE8L:
	case SPARC_INS_EDGE8LN:
		// clang-format off
		get_mask = SEQ2(get_mask, left ?
		                SETL("shft_amt", LOGAND(UA(0x7), VARL("rs1"))) :
		                SETL("shft_amt", LOGAND(UA(0x7), VARL("rs2"))));
		// clang-format on
		break;
	}

	rz_il_pure_3args_op *shft_op = NULL;
	size_t mask_width = 0;
	size_t mask_init = 0;
	RzILOpBool *fill_bit = left ? IL_FALSE : IL_TRUE;
	switch (id) {
	default:
		return NULL;
	case SPARC_INS_EDGE8:
	case SPARC_INS_EDGE8N:
		shft_op = &rz_il_op_new_shiftr;
		mask_init = left ? 0xff : 0x80;
		mask_width = 8;
		break;
	case SPARC_INS_EDGE8L:
	case SPARC_INS_EDGE8LN:
		shft_op = &rz_il_op_new_shiftl;
		mask_init = left ? 0xff : 0x01;
		mask_width = 8;
		break;
	case SPARC_INS_EDGE16:
	case SPARC_INS_EDGE16N:
		shft_op = &rz_il_op_new_shiftr;
		mask_init = left ? 0xf : 0x8;
		mask_width = 4;
		break;
	case SPARC_INS_EDGE16L:
	case SPARC_INS_EDGE16LN:
		shft_op = &rz_il_op_new_shiftl;
		mask_init = left ? 0xf : 0x1;
		mask_width = 4;
		break;
	case SPARC_INS_EDGE32:
	case SPARC_INS_EDGE32N:
		shft_op = &rz_il_op_new_shiftr;
		mask_init = left ? 0x3 : 0x2;
		mask_width = 2;
		break;
	case SPARC_INS_EDGE32L:
	case SPARC_INS_EDGE32LN:
		shft_op = &rz_il_op_new_shiftl;
		mask_init = left ? 0x3 : 0x1;
		mask_width = 2;
		break;
	}
	return SEQ2(get_mask, SETL(left ? "lmask" : "rmask", CAST_UA(shft_op(fill_bit, UN(mask_width, mask_init), VARL("shft_amt")))));
}

static RzILOpEffect *edge_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	RzILOpPure *rs1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
	RzILOpPure *rs2 = rz_sparc_cs_get_operand(handle, insn, mode, 1, 0);
	const char *dst = cs_reg_name(handle, INSOP(2).reg);
	if (!rs1 || !rs2 || !dst) {
		rz_il_op_pure_free(rs1);
		rz_il_op_pure_free(rs2);
		rz_warn_if_reached();
		return NULL;
	}
	RzILOpEffect *set_left_mask = get_edge_mask(insn->id, mode, rs1, rs2, true);
	RzILOpEffect *set_right_mask = get_edge_mask(insn->id, mode, rs1, rs2, false);
	// clang-format off
	RzILOpEffect *edge = SEQ3(set_left_mask, set_right_mask,
	                          BRANCH(EQ(SHIFTR0(VARL("rs1"), U8(3)), SHIFTR0(VARL("rs2"), U8(3))),
	                                 SSETG(dst, LOGAND(VARL("rmask"), VARL("lmask"))),
	                                 SSETG(dst, VARL("lmask"))));
	// clang-format on
	switch (insn->id) {
	default:
		break;
	case SPARC_INS_EDGE8:
	case SPARC_INS_EDGE8L:
	case SPARC_INS_EDGE16:
	case SPARC_INS_EDGE16L:
	case SPARC_INS_EDGE32:
	case SPARC_INS_EDGE32L: {
		RzSparcCCRBits bits = { 0 };
		edge = SEQ2(edge, rz_sparc_2args_ccr(RZ_SPARC_CCR_OP_SUB, VARL("rs1"), VARL("rs2"), NULL, &bits));
	}
	}
	return edge;
}

static RzILOpPure *get_reg_condition(sparc_cc cc, RzILOpPure *reg_val) {
	rz_return_val_if_fail(reg_val && (cc & SPARC_CC_REG_BEGIN), NULL);
	switch (cc) {
	default:
		rz_warn_if_reached();
		return NULL;
	case SPARC_CC_REG_NZ:
		return NON_ZERO(reg_val);
	case SPARC_CC_REG_Z:
		return IS_ZERO(reg_val);
	case SPARC_CC_REG_LEZ:
		return SLE(reg_val, U64(0));
	case SPARC_CC_REG_LZ:
		return SLT(reg_val, U64(0));
	case SPARC_CC_REG_GZ:
		return SGT(reg_val, U64(0));
	case SPARC_CC_REG_GEZ:
		return SGE(reg_val, U64(0));
	}
	return NULL;
}

static RzILOpPure *get_fcc_condition(sparc_cc cc, sparc_cc_field cc_field, cs_mode mode) {
	switch (cc_field) {
	default:
	case SPARC_CC_FIELD_ICC:
	case SPARC_CC_FIELD_XCC:
		rz_warn_if_reached();
		return NULL;
	case SPARC_CC_FIELD_FCC0:
	case SPARC_CC_FIELD_FCC1:
	case SPARC_CC_FIELD_FCC2:
	case SPARC_CC_FIELD_FCC3:
		break;
	}
	if (!(cc & SPARC_CC_FCC_BEGIN)) {
		rz_warn_if_reached();
		return NULL;
	}

	switch (cc) {
	default:
		rz_warn_if_reached();
		return NULL;
	case SPARC_CC_FCC_A:
		return IL_TRUE;
	case SPARC_CC_FCC_N:
		return IL_FALSE;
	case SPARC_CC_FCC_U:
		return GET_FCC_UN(cc_field);
	case SPARC_CC_FCC_G:
		return GET_FCC_GT(cc_field);
	case SPARC_CC_FCC_UG:
		return OR(GET_FCC_GT(cc_field), GET_FCC_UN(cc_field));
	case SPARC_CC_FCC_L:
		return GET_FCC_LT(cc_field);
	case SPARC_CC_FCC_UL:
		return OR(GET_FCC_LT(cc_field), GET_FCC_UN(cc_field));
	case SPARC_CC_FCC_LG:
		return OR(GET_FCC_LT(cc_field), GET_FCC_GT(cc_field));
	case SPARC_CC_FCC_NE:
		return OR(OR(GET_FCC_LT(cc_field), GET_FCC_GT(cc_field)), GET_FCC_UN(cc_field));
	case SPARC_CC_FCC_E:
		return GET_FCC_EQ(cc_field);
	case SPARC_CC_FCC_UE:
		return OR(GET_FCC_EQ(cc_field), GET_FCC_UN(cc_field));
	case SPARC_CC_FCC_GE:
		return OR(GET_FCC_EQ(cc_field), GET_FCC_GT(cc_field));
	case SPARC_CC_FCC_UGE:
		return OR(OR(GET_FCC_EQ(cc_field), GET_FCC_GT(cc_field)), GET_FCC_UN(cc_field));
	case SPARC_CC_FCC_LE:
		return OR(GET_FCC_EQ(cc_field), GET_FCC_LT(cc_field));
	case SPARC_CC_FCC_ULE:
		return OR(OR(GET_FCC_EQ(cc_field), GET_FCC_LT(cc_field)), GET_FCC_UN(cc_field));
	case SPARC_CC_FCC_O:
		return OR(OR(GET_FCC_EQ(cc_field), GET_FCC_LT(cc_field)), GET_FCC_GT(cc_field));
	}
}

static RzILOpPure *get_cc_condition(sparc_cc cc, sparc_cc_field cc_field) {
	RzILOpPure *ccf = NULL;
	switch (cc_field) {
	default:
		rz_warn_if_reached();
		return NULL;
	case SPARC_CC_FIELD_ICC:
		ccf = ICC();
		break;
	case SPARC_CC_FIELD_XCC:
		ccf = XCC();
		break;
	}

	switch (cc & ~(SPARC_CC_FCC_BEGIN | SPARC_CC_CPCC_BEGIN)) {
	default:
		rz_warn_if_reached();
		return NULL;
	case SPARC_CC_ICC_A: // Always
		rz_il_op_pure_free(ccf);
		return IL_TRUE;
	case SPARC_CC_ICC_N: // Never
		rz_il_op_pure_free(ccf);
		return IL_FALSE;
	case SPARC_CC_ICC_NE: // Not Equal
		return INV(BIT_Z(ccf));
	case SPARC_CC_ICC_E: // Equal
		return BIT_Z(ccf);
	case SPARC_CC_ICC_G: // Greater
		return LET("ccf", ccf, INV(OR(BIT_Z(VARLP("ccf")), XOR(BIT_N(VARLP("ccf")), BIT_V(VARLP("ccf"))))));
	case SPARC_CC_ICC_LE: // Less or Equal
		return LET("ccf", ccf, OR(BIT_Z(VARLP("ccf")), XOR(BIT_N(VARLP("ccf")), BIT_V(VARLP("ccf")))));
	case SPARC_CC_ICC_GE: // Greater or Equal
		return LET("ccf", ccf, INV(XOR(BIT_N(VARLP("ccf")), BIT_V(VARLP("ccf")))));
	case SPARC_CC_ICC_L: // Less
		return LET("ccf", ccf, XOR(BIT_N(VARLP("ccf")), BIT_V(VARLP("ccf"))));
	case SPARC_CC_ICC_GU: // Greater Unsigned
		return LET("ccf", ccf, INV(OR(BIT_C(VARLP("ccf")), BIT_Z(VARLP("ccf")))));
	case SPARC_CC_ICC_LEU: // Less or Equal Unsigned
		return LET("ccf", ccf, OR(BIT_C(VARLP("ccf")), BIT_Z(VARLP("ccf"))));
	case SPARC_CC_ICC_CC: // Carry Clear/Great or Equal Unsigned
		return INV(BIT_C(ccf));
	case SPARC_CC_ICC_CS: // Carry Set/Less Unsigned
		return BIT_C(ccf);
	case SPARC_CC_ICC_POS: // Positive
		return INV(BIT_N(ccf));
	case SPARC_CC_ICC_NEG: // Negative
		return BIT_N(ccf);
	case SPARC_CC_ICC_VC: // Overflow Clear
		return INV(BIT_V(ccf));
	case SPARC_CC_ICC_VS: // Overflow Set
		return BIT_V(ccf);
	}
	return NULL;
}

static RzILOpPure *get_branch_condition(csh handle, const cs_insn *insn, const cs_mode mode) {
	sparc_cc_field field = INSDETAIL().cc_field;
	switch (insn->id) {
	default:
		rz_warn_if_reached();
		return NULL;
	case SPARC_INS_B:
		return get_cc_condition(INSCC_NORM(), field);
	case SPARC_INS_BR: {
		RzILOpPure *rs1 = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
		return get_reg_condition(INSCC_RAW(), rs1);
	}
	case SPARC_INS_FB:
		return get_fcc_condition(INSCC_RAW(), field, mode);
	}
}

static inline void set_delayed_slot(HtUP *dl_table,
	ut64 address,
	RzILOpEffect *set_ea,
	RzILOpEffect *jmp,
	RZ_NULLABLE RzILOpEffect *fail_jmp,
	RZ_NULLABLE RzILOpPure *cond,
	bool annulled_bit) {
	bool found;
	RzSparcDelatedBranchOp *bop = RZ_NEW(RzSparcDelatedBranchOp);
	if (!bop) {
		rz_warn_if_reached();
		return;
	}
	RzSparcDelatedBranchOp *eff = ht_up_find(dl_table, address, &found);
	if (found) {
		// Faulty disassembly or same address disassembled again.
		rz_il_op_pure_free(eff->cond);
		rz_il_op_effect_free(eff->perform_fail_jmp);
		rz_il_op_effect_free(eff->perform_jmp);
		rz_il_op_effect_free(eff->set_ea);
		free(eff);
	}
	bop->cond = cond;
	bop->annulled_bit = annulled_bit;
	bop->perform_fail_jmp = fail_jmp;
	bop->perform_jmp = jmp;
	bop->set_ea = set_ea;
	ht_up_update(dl_table, address, bop);
}

static RzILOpEffect *branch_op(const csh handle, const cs_insn *insn, const cs_mode mode, RzAnalysisValueSPARC *state) {
	rz_return_val_if_fail(insn, NULL);
	if (!state) {
		rz_warn_if_reached();
		return NULL;
	}
	switch (insn->id) {
	case SPARC_INS_JMPL: {
		const char *link_reg = cs_reg_name(handle, INSOP(1).reg);
		RzILOpPure *ea = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
		set_delayed_slot(state->delayed_branch, insn->address + SPARC_INSN_SIZE, SETL("EA", CAST_UA(ea)), JMP(VARL("EA")), NULL, NULL, false);
		return SSETG(link_reg, UA(insn->address));
	}
	case SPARC_INS_CALL: {
		RzILOpPure *ea = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
		set_delayed_slot(state->delayed_branch, insn->address + SPARC_INSN_SIZE, SETL("EA", CAST_UA(ea)), JMP(VARL("EA")), NULL, NULL, false);
		return SETG("o7", UA(insn->address));
	}
	case SPARC_INS_B:
	case SPARC_INS_BR:
	case SPARC_INS_FB: {
		RzILOpPure *ea = CAST_UA(rz_sparc_cs_get_operand(handle, insn, mode, insn->id == SPARC_INS_BR ? 1 : 0, 0));
		bool annul_delay_slot = INSHINT() & SPARC_HINT_A;
		if (annul_delay_slot && INSCC_RAW() == SPARC_CC_ICC_A) {
			return JMP(ea);
		}
		RzILOpPure *cond = get_branch_condition(handle, insn, mode);
		if (!cond) {
			rz_il_op_pure_free(ea);
			return NULL;
		}
		ut64 failed_addr = annul_delay_slot ? insn->address + (SPARC_INSN_SIZE * 2) : insn->address + SPARC_INSN_SIZE;
		set_delayed_slot(state->delayed_branch, insn->address + SPARC_INSN_SIZE, SETL("EA", CAST_UA(ea)), JMP(VARL("EA")), JMP(UA(failed_addr)), cond, annul_delay_slot);
		return NOP();
	}
	case SPARC_INS_RETT: {
		// RETT is a little funny.
		// Technically it shouldn't be used anymore in Sparc v9.
		// In practice my gcc cross compiler doesn't care and builds
		// nostdlib binaries with it anyways.
		// rett is effectively used as replacement for `ret ; restore`.
		// The window_underflow/window_overflow cases are not handled here.
		// Because Rizin doesn't model traps for now.
		RzILOpPure *ea = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
		set_delayed_slot(state->delayed_branch, insn->address + SPARC_INSN_SIZE, EMPTY(), JMP(VARG("tnpc")), NULL, NULL, false);
		RzILOpEffect *restore = restore_op(handle, insn, mode);
		return SEQ2(SETG("tnpc", CAST_UA(ea)), restore);
	}
	case SPARC_INS_CB:
		// Co-processors are not modeled currently.
		NOT_IMPLEMENTED;
	}
	rz_warn_if_reached();
	NOT_IMPLEMENTED;
}

static size_t mem_access_width_bits(const cs_insn *insn) {
	rz_return_val_if_fail(insn, 0);
	switch (insn->id) {
	case SPARC_INS_STB:
	case SPARC_INS_STBA:
	case SPARC_INS_LDSB:
	case SPARC_INS_LDUB:
	case SPARC_INS_LDSBA:
	case SPARC_INS_LDUBA:
	case SPARC_INS_LDSTUB:
	case SPARC_INS_LDSTUBA:
		return SPARC_BYTE;
	case SPARC_INS_STH:
	case SPARC_INS_STHA:
	case SPARC_INS_LDSH:
	case SPARC_INS_LDSHA:
	case SPARC_INS_LDUHA:
	case SPARC_INS_LDUH:
		return SPARC_HALF_WORD;
	case SPARC_INS_ST:
	case SPARC_INS_STA:
	case SPARC_INS_LD:
	case SPARC_INS_LDA:
	case SPARC_INS_LDSW:
	case SPARC_INS_LDSWA:
		return SPARC_WORD;
	case SPARC_INS_STX:
	case SPARC_INS_STXA:
	case SPARC_INS_STD:
	case SPARC_INS_STDA:
	case SPARC_INS_LDX:
	case SPARC_INS_LDXA:
	case SPARC_INS_LDDA:
	case SPARC_INS_LDD:
		return SPARC_DOUBLE_WORD;
	case SPARC_INS_STQ:
	case SPARC_INS_STQA:
	case SPARC_INS_LDQ:
	case SPARC_INS_LDQA:
		return SPARC_QUAD_WORD;
	}
	rz_warn_if_reached();
	return 0;
}

static bool mem_signed_ldst(const cs_insn *insn) {
	rz_return_val_if_fail(insn, false);
	switch (insn->id) {
	case SPARC_INS_LDUB:
	case SPARC_INS_LDUBA:
	case SPARC_INS_LDUHA:
	case SPARC_INS_LDUH:
	case SPARC_INS_LD:
	case SPARC_INS_LDA:
	case SPARC_INS_LDX:
	case SPARC_INS_LDXA:
	case SPARC_INS_LDDA:
	case SPARC_INS_LDD:
	case SPARC_INS_LDQ:
	case SPARC_INS_LDQA:
	case SPARC_INS_LDSTUB:
	case SPARC_INS_LDSTUBA:
		return false;
	case SPARC_INS_LDSB:
	case SPARC_INS_LDSBA:
	case SPARC_INS_LDSH:
	case SPARC_INS_LDSHA:
	case SPARC_INS_LDSW:
	case SPARC_INS_LDSWA:
		return true;
	}
	rz_warn_if_reached();
	return false;
}

static RzILOpEffect *load_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	size_t dst_idx = INSDETAIL().op_count == 3 ? 2 : 1;
	bool is_float_load = is_float_reg(INSOP(dst_idx).reg);
	bool is_v8_freg_dst = is_v8_reg(INSOP(dst_idx).reg);
	const char *dst = cs_reg_name(handle, INSOP(dst_idx).reg);
	if (!dst) {
		rz_warn_if_reached();
		return NULL;
	}
	RzILOpPure *addr = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
	RzILOpPure *load = NULL;
	size_t width = mem_access_width_bits(insn);
	if (width == 0 || !addr) {
		return NULL;
	}
	sparc_asi asi = get_insn_asi(insn);

	switch (insn->id) {
	default:
		rz_warn_if_reached();
		rz_il_op_pure_free(addr);
		return NULL;
	case SPARC_INS_LDSB:
	case SPARC_INS_LDUB:
	case SPARC_INS_LDSBA:
	case SPARC_INS_LDUBA:
	case SPARC_INS_LDUH:
	case SPARC_INS_LDSH:
	case SPARC_INS_LDSHA:
	case SPARC_INS_LDUHA:
	case SPARC_INS_LD:
	case SPARC_INS_LDA:
	case SPARC_INS_LDSW:
	case SPARC_INS_LDSWA:
	case SPARC_INS_LDX:
	case SPARC_INS_LDXA:
		load = LOADWI(asi, width, addr);
		if (is_float_load) {
			return SSETG(dst, UNSIGNED(is_v8_freg_dst ? 32 : 64, load));
		} else if (mem_signed_ldst(insn)) {
			load = CAST_SA(load);
		} else {
			load = CAST_UA(load);
		}
		return SSETG(dst, load);
	case SPARC_INS_LDD:
	case SPARC_INS_LDDA:
		load = LOADWI(asi, width, addr);
		if (!is_v8_freg_dst && is_float_load) {
			return SSETG(dst, load);
		}

		const char *dst2 = rz_sparc_get_next_reg_name(handle, INSOP(dst_idx).reg, 1);
		if (!dst2) {
			rz_il_op_pure_free(load);
			rz_il_op_pure_free(addr);
			rz_warn_if_reached();
			return NULL;
		}

		if (is_float_load) {
			return SEQ3(SETL("load", load),
				SSETG(dst2, UNSIGNED(32, VARL("load"))),
				SSETG(dst, UNSIGNED(32, SHIFTR0(VARL("load"), U8(32)))));
		}
		return SEQ3(SETL("load", load),
			SSETG(dst2, CAST_UA(LOGAND(VARL("load"), U64(0xffffffff)))),
			SSETG(dst, CAST_UA(SHIFTR0(VARL("load"), U8(32)))));
	case SPARC_INS_LDQ:
	case SPARC_INS_LDQA: {
		if (is_v8_freg_dst) {
			const char *dst2 = rz_sparc_get_next_reg_name(handle, INSOP(dst_idx).reg, 1);
			const char *dst3 = rz_sparc_get_next_reg_name(handle, INSOP(dst_idx).reg, 2);
			const char *dst4 = rz_sparc_get_next_reg_name(handle, INSOP(dst_idx).reg, 3);
			if (!dst2 || !dst3 || !dst4) {
				rz_il_op_pure_free(load);
				rz_il_op_pure_free(addr);
				rz_warn_if_reached();
				return NULL;
			}
			load = LOADWI(asi, width, addr);
			return SEQ5(SETL("load", load),
				SSETG(dst4, UNSIGNED(32, VARL("load"))),
				SSETG(dst3, UNSIGNED(32, SHIFTR0(VARL("load"), U8(32)))),
				SSETG(dst2, UNSIGNED(32, SHIFTR0(VARL("load"), U8(64)))),
				SSETG(dst, UNSIGNED(32, SHIFTR0(VARL("load"), U8(96)))));
		}
		// Quad word floating point.
		const char *dst2 = rz_sparc_get_next_reg_name(handle, INSOP(dst_idx).reg, 2);
		if (!dst2) {
			rz_il_op_pure_free(load);
			rz_il_op_pure_free(addr);
			rz_warn_if_reached();
			return NULL;
		}
		load = LOADWI(asi, width, addr);
		return SEQ3(SETL("load", load),
			SSETG(dst2, UNSIGNED(64, VARL("load"))),
			SSETG(dst, UNSIGNED(64, SHIFTR0(VARL("load"), U8(64)))));
	}
	case SPARC_INS_LDSTUBA:
	case SPARC_INS_LDSTUB:
		load = CAST_UA(LOADWI(asi, width, DUP(addr)));
		return SEQ2(SSETG(dst, load), STOREWI(asi, addr, U8(0xff)));
	}
	NOT_IMPLEMENTED;
}

static RzILOpEffect *store_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	bool is_v8_register = is_v8_reg(INSOP(0).reg);
	RzILOpPure *addr = rz_sparc_cs_get_operand(handle, insn, mode, 1, 0);
	size_t width = mem_access_width_bits(insn);
	if (width == 0 || !addr) {
		return NULL;
	}
	sparc_asi asi = get_insn_asi(insn);

	switch (insn->id) {
	default:
		rz_warn_if_reached();
		rz_il_op_pure_free(addr);
		return NULL;
	case SPARC_INS_STB:
	case SPARC_INS_STBA:
	case SPARC_INS_STH:
	case SPARC_INS_STHA:
	case SPARC_INS_ST:
	case SPARC_INS_STA:
	case SPARC_INS_STX:
	case SPARC_INS_STXA: {
		RzILOpPure *val = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
		return STOREWI(asi, addr, UNSIGNED(width, val));
	}
	case SPARC_INS_STD:
	case SPARC_INS_STDA:
	case SPARC_INS_STQ:
	case SPARC_INS_STQA: {
		RzILOpPure *val = NULL;
		// Append registers to final value.
		size_t limit = (width / SPARC_WORD);
		size_t decrement = is_v8_register ? 1 : 2;
		for (int i = limit - decrement; i >= 0; i -= decrement) {
			const char *reg = rz_sparc_get_next_reg_name(handle, INSOP(0).reg, i);
			if (!reg) {
				rz_il_op_pure_free(addr);
				return NULL;
			}
			RzILOpPure *rval = NULL;
			if (is_v8_register && (insn->id == SPARC_INS_STD || insn->id == SPARC_INS_STDA)) {
				rval = UNSIGNED(32, VARG(reg));
			} else {
				rval = VARG(reg);
			}
			val = !val ? rval : APPEND(rval, val);
		}
		return STOREWI(asi, addr, val);
	}
	}
	NOT_IMPLEMENTED;
}

static RzILOpEffect *shift_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	const char *dst = cs_reg_name(handle, INSOP(2).reg);
	RzILOpPure *src = CAST_UA(rz_sparc_cs_get_operand(handle, insn, mode, 0, 0));
	RzILOpPure *sh = rz_sparc_cs_get_operand(handle, insn, mode, 1, 0);
	if (!dst || !src || !sh) {
		rz_il_op_pure_free(src);
		rz_il_op_pure_free(sh);
		return NULL;
	}

	switch (insn->id) {
	default:
		rz_warn_if_reached();
		rz_il_op_pure_free(src);
		rz_il_op_pure_free(sh);
		return NULL;
	case SPARC_INS_SLL:
		sh = UNSIGNED(5, sh);
		return SSETG(dst, CAST_UA(SHIFTL0(UNSIGNED(32, src), sh)));
	case SPARC_INS_SRL:
		sh = UNSIGNED(5, sh);
		return SSETG(dst, CAST_UA(SHIFTR0(UNSIGNED(32, src), sh)));
	case SPARC_INS_SRA:
		sh = UNSIGNED(5, sh);
		return SSETG(dst, CAST_UA(SHIFTRA(UNSIGNED(32, src), sh)));
	case SPARC_INS_SLLX:
		sh = UNSIGNED(6, sh);
		return SSETG(dst, CAST_UA(SHIFTL0(src, sh)));
	case SPARC_INS_SRLX:
		sh = UNSIGNED(6, sh);
		return SSETG(dst, CAST_UA(SHIFTR0(src, sh)));
	case SPARC_INS_SRAX:
		sh = UNSIGNED(6, sh);
		return SSETG(dst, CAST_UA(SHIFTRA(src, sh)));
	}
	NOT_IMPLEMENTED;
}

static RzILOpEffect *sethi_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	if ((INSOP(0).type == SPARC_OP_REG && INSOP(0).reg == SPARC_REG_G0) ||
		(INSOP(0).type == SPARC_OP_IMM && INSOP(0).imm == 0)) {
		return NOP();
	}
	RzILOpPure *imm22 = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
	const char *dst = cs_reg_name(handle, INSOP(1).reg);
	if (!imm22 || !dst) {
		rz_il_op_pure_free(imm22);
		return NULL;
	}
	return SSETG(dst, CAST_UA(SHIFTL0(imm22, U8(10))));
}

static RzILOpEffect *swap_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	sparc_asi asi = get_insn_asi(insn);
	RzILOpPure *ea = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
	if (!ea) {
		return NULL;
	}

	switch (insn->id) {
	default:
		rz_warn_if_reached();
		return NULL;
	case SPARC_INS_SWAPA:
	case SPARC_INS_SWAP: {
		size_t dst_idx = INSDETAIL().op_count == 3 ? 2 : 1;
		const char *dst = cs_reg_name(handle, INSOP(dst_idx).reg);
		if (!dst) {
			rz_il_op_pure_free(ea);
			return NULL;
		}
		return SEQ3(SETL("mem_val", LOADWI(asi, SPARC_WORD, DUP(ea))), STOREWI(asi, ea, UNSIGNED(32, VARG(dst))), SSETG(dst, CAST_UA(VARL("mem_val"))));
	}
	case SPARC_INS_CASA:
	case SPARC_INS_CASXA: {
		const char *dst = cs_reg_name(handle, INSOP(3).reg);
		if (!dst) {
			rz_il_op_pure_free(ea);
			return NULL;
		}
		if (insn->id == SPARC_INS_CASA) {
			RzILOpPure *rs = UNSIGNED(32, rz_sparc_cs_get_operand(handle, insn, mode, 2, 0));
			RzILOpEffect *swap = SEQ2(STOREWI(asi, ea, UNSIGNED(32, VARG(dst))), SSETG(dst, CAST_UA(VARL("mem_val"))));
			RzILOpEffect *set = SSETG(dst, CAST_UA(VARL("mem_val")));
			return SEQ2(SETL("mem_val", LOADWI(asi, SPARC_WORD, DUP(ea))), BRANCH(EQ(VARL("mem_val"), rs), swap, set));
		}
		RzILOpPure *rs = rz_sparc_cs_get_operand(handle, insn, mode, 2, 0);
		RzILOpEffect *swap = SEQ2(STOREWI(asi, ea, VARG(dst)), SSETG(dst, VARL("mem_val")));
		RzILOpEffect *set = SSETG(dst, VARL("mem_val"));
		return SEQ2(SETL("mem_val", LOADWI(asi, SPARC_DOUBLE_WORD, DUP(ea))), BRANCH(EQ(VARL("mem_val"), rs), swap, set));
	}
	}
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mov_op(const csh handle, const cs_insn *insn, const cs_mode mode) {
	rz_return_val_if_fail(insn, NULL);
	sparc_cc_field field = INSDETAIL().cc_field;

	switch (insn->id) {
	default:
		break;
	case SPARC_INS_MOV: {
		sparc_cc cc = INSCC_RAW();
		const char *dst = cs_reg_name(handle, INSOP(1).reg);
		RzILOpPure *src = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
		if (!dst || !src) {
			rz_il_op_pure_free(src);
			return NULL;
		}
		// This is the conditional move from Sparc V9.
		// In V8 MOV is only an alias for OR. Conditional mov doesn't exist.
		RzILOpPure *cond;
		switch (field) {
		default:
			rz_warn_if_reached();
			return NULL;
		case SPARC_CC_FIELD_FCC0:
		case SPARC_CC_FIELD_FCC1:
		case SPARC_CC_FIELD_FCC2:
		case SPARC_CC_FIELD_FCC3:
			cond = get_fcc_condition(cc, field, mode);
			break;
		case SPARC_CC_FIELD_ICC:
		case SPARC_CC_FIELD_XCC:
			cond = get_cc_condition(cc, field);
			break;
		}
		if (!cond) {
			return NULL;
		}
		return BRANCH(cond, SSETG(dst, src), NOP());
	}
	case SPARC_INS_MOVR: {
		sparc_cc cc = INSCC_RAW();
		const char *dst = cs_reg_name(handle, INSOP(2).reg);
		RzILOpPure *src = rz_sparc_cs_get_operand(handle, insn, mode, 1, 0);
		RzILOpPure *cmp = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
		if (!dst || !src || !cmp) {
			rz_il_op_pure_free(cmp);
			rz_il_op_pure_free(src);
			return NULL;
		}
		RzILOpPure *cond = get_reg_condition(cc, cmp);
		if (!cond) {
			return NULL;
		}
		return BRANCH(cond, SSETG(dst, src), NOP());
	}
	case SPARC_INS_FMOVRS:
	case SPARC_INS_FMOVRD:
	case SPARC_INS_FMOVRQ: {
		sparc_reg dst = INSOP(2).reg;
		size_t width = fload_operands_width_bits(insn);

		RzILOpPure *src = rz_sparc_cs_get_operand(handle, insn, mode, 1, width);
		RzILOpPure *cmp = rz_sparc_cs_get_operand(handle, insn, mode, 0, 0);
		if (!src || !cmp) {
			rz_il_op_pure_free(cmp);
			rz_il_op_pure_free(src);
			return NULL;
		}
		sparc_cc cc = INSCC_RAW();
		RzILOpPure *cond = get_reg_condition(cc, cmp);
		if (!cond) {
			rz_il_op_pure_free(cmp);
			rz_il_op_pure_free(src);
			return NULL;
		}
		return BRANCH(cond, rz_sparc_fpure_to_freg(handle, mode, dst, src, width), NOP());
	}
	}

	size_t src_width = fload_operands_width_bits(insn);
	const char *dst = cs_reg_name(handle, INSOP(1).reg);
	RzILOpPure *src = rz_sparc_cs_get_operand(handle, insn, mode, 0, src_width);
	switch (insn->id) {
	default:
		rz_warn_if_reached();
		rz_il_op_pure_free(src);
		return NULL;
	case SPARC_INS_MOVDTOX:
		return SSETG(dst, F2BV(src));
	case SPARC_INS_MOVSTOSW:
		return SSETG(dst, SIGNED(64, F2BV(src)));
	case SPARC_INS_MOVSTOUW:
		return SSETG(dst, UNSIGNED(64, F2BV(src)));
	}
	NOT_IMPLEMENTED;
}
#endif

/**
 * \brief Returns the RZIL implementation of a given capstone instruction.
 *
 * \param handle The capstone handle.
 * \param insn The capstone instruction.
 * \param mode The capstone mode.
 * \param state The Sparc plugin state. Used for delayed branch management.
 *
 * \return RzILOpEffect* Sequence of effects which emulate the instruction.
 * Or NULL in case of error or if it isn't implemented.
 */
RZ_IPI RzILOpEffect *rz_sparc_cs_get_il_op(const csh handle, const cs_insn *insn, const cs_mode mode, RZ_NULLABLE RzAnalysisValueSPARC *state) {
	rz_return_val_if_fail(insn, NULL);
#if CS_API_MAJOR >= 6
	switch (insn->id) {
	default:
		RZ_LOG_WARN("Capstone instruction with id = %" PFMT32d " not handled.\n", insn->id);
		return NULL;
	case SPARC_INS_NOP:
		return NOP();
	case SPARC_INS_ADDCC:
	case SPARC_INS_ADDX:
	case SPARC_INS_ADDXCC:
	case SPARC_INS_ADDXC:
	case SPARC_INS_ADDXCCC:
	case SPARC_INS_ADD:
	case SPARC_INS_SUBCC:
	case SPARC_INS_SUBX:
	case SPARC_INS_SUBXCC:
	case SPARC_INS_SUB:
	case SPARC_INS_UDIVCC:
	case SPARC_INS_UDIVX:
	case SPARC_INS_UDIV:
	case SPARC_INS_SDIV:
	case SPARC_INS_SDIVCC:
	case SPARC_INS_SDIVX:
	case SPARC_INS_MULSCC:
	case SPARC_INS_MULX:
	case SPARC_INS_UMULCC:
	case SPARC_INS_UMULXHI:
	case SPARC_INS_UMUL:
	case SPARC_INS_SMULCC:
	case SPARC_INS_SMUL:
	case SPARC_INS_XMULX:
	case SPARC_INS_XMULXHI:
	case SPARC_INS_TADDCCTV:
	case SPARC_INS_TADDCC:
	case SPARC_INS_TSUBCCTV:
	case SPARC_INS_TSUBCC:
		return arithmetic_int_op(handle, insn, mode);
	case SPARC_INS_ANDCC:
	case SPARC_INS_ANDNCC:
	case SPARC_INS_ANDN:
	case SPARC_INS_AND:
	case SPARC_INS_ORCC:
	case SPARC_INS_ORNCC:
	case SPARC_INS_ORN:
	case SPARC_INS_OR:
	case SPARC_INS_XNORCC:
	case SPARC_INS_XNOR:
	case SPARC_INS_XORCC:
	case SPARC_INS_XOR:
		return logical_int_op(handle, insn, mode);
	case SPARC_INS_CALL:
	case SPARC_INS_B:
	case SPARC_INS_CB:
	case SPARC_INS_JMPL:
	case SPARC_INS_FB:
	case SPARC_INS_BR:
	case SPARC_INS_RETT:
		return branch_op(handle, insn, mode, state);
	case SPARC_INS_LDX:
	case SPARC_INS_LD:
	case SPARC_INS_LDA:
	case SPARC_INS_LDDA:
	case SPARC_INS_LDD:
	case SPARC_INS_LDQA:
	case SPARC_INS_LDQ:
	case SPARC_INS_LDSBA:
	case SPARC_INS_LDSB:
	case SPARC_INS_LDSHA:
	case SPARC_INS_LDSH:
	case SPARC_INS_LDSTUBA:
	case SPARC_INS_LDSTUB:
	case SPARC_INS_LDSWA:
	case SPARC_INS_LDSW:
	case SPARC_INS_LDUBA:
	case SPARC_INS_LDUB:
	case SPARC_INS_LDUHA:
	case SPARC_INS_LDUH:
	case SPARC_INS_LDXA:
		return load_op(handle, insn, mode);
	case SPARC_INS_STA:
	case SPARC_INS_STBA:
	case SPARC_INS_STB:
	case SPARC_INS_ST:
	case SPARC_INS_STDA:
	case SPARC_INS_STD:
	case SPARC_INS_STHA:
	case SPARC_INS_STH:
	case SPARC_INS_STQA:
	case SPARC_INS_STQ:
	case SPARC_INS_STXA:
	case SPARC_INS_STX:
		return store_op(handle, insn, mode);
	case SPARC_INS_SLL:
	case SPARC_INS_SRL:
	case SPARC_INS_SRA:
	case SPARC_INS_SLLX:
	case SPARC_INS_SRLX:
	case SPARC_INS_SRAX:
		return shift_op(handle, insn, mode);
	case SPARC_INS_SETHI:
		return sethi_op(handle, insn, mode);
	case SPARC_INS_CASA:
	case SPARC_INS_CASXA:
	case SPARC_INS_SWAPA:
	case SPARC_INS_SWAP:
		return swap_op(handle, insn, mode);
	case SPARC_INS_MOVDTOX:
	case SPARC_INS_MOVSTOSW:
	case SPARC_INS_MOVSTOUW:
	case SPARC_INS_MOV:
	case SPARC_INS_MOVR:
	case SPARC_INS_FMOVRS:
	case SPARC_INS_FMOVRD:
	case SPARC_INS_FMOVRQ:
		return mov_op(handle, insn, mode);
	case SPARC_INS_FADDD:
	case SPARC_INS_FADDQ:
	case SPARC_INS_FADDS:
	case SPARC_INS_FDIVD:
	case SPARC_INS_FDIVQ:
	case SPARC_INS_FDIVS:
	case SPARC_INS_FDMULQ:
	case SPARC_INS_FHADDD:
	case SPARC_INS_FHADDS:
	case SPARC_INS_FHSUBD:
	case SPARC_INS_FHSUBS:
	case SPARC_INS_FMULD:
	case SPARC_INS_FMULQ:
	case SPARC_INS_FMULS:
	case SPARC_INS_FNADDD:
	case SPARC_INS_FNADDS:
	case SPARC_INS_FNHADDD:
	case SPARC_INS_FNHADDS:
	case SPARC_INS_FSMULD:
	case SPARC_INS_FSUBD:
	case SPARC_INS_FSUBQ:
	case SPARC_INS_FSUBS:
		return arithmetic_float_op_3(handle, insn, mode);
	case SPARC_INS_FMUL8SUX16:
	case SPARC_INS_FMUL8ULX16:
	case SPARC_INS_FMUL8X16:
	case SPARC_INS_FMUL8X16AL:
	case SPARC_INS_FMUL8X16AU:
	case SPARC_INS_FMULD8SUX16:
	case SPARC_INS_FMULD8ULX16:
	case SPARC_INS_FPADD16:
	case SPARC_INS_FPADD16S:
	case SPARC_INS_FPADD32:
	case SPARC_INS_FPADD32S:
	case SPARC_INS_FPADD64:
	case SPARC_INS_FPSUB16:
	case SPARC_INS_FPSUB16S:
	case SPARC_INS_FPSUB32:
	case SPARC_INS_FPSUB32S:
		return simd_mul_op(handle, insn, mode);
	case SPARC_INS_FPMERGE:
	case SPARC_INS_FEXPAND:
		return simd_op(handle, insn, mode);
	case SPARC_INS_FNAND:
	case SPARC_INS_FNANDS:
	case SPARC_INS_FNOR:
	case SPARC_INS_FNORS:
	case SPARC_INS_FAND:
	case SPARC_INS_FANDNOT1:
	case SPARC_INS_FANDNOT1S:
	case SPARC_INS_FANDNOT2:
	case SPARC_INS_FANDNOT2S:
	case SPARC_INS_FANDS:
	case SPARC_INS_FXNOR:
	case SPARC_INS_FXNORS:
	case SPARC_INS_FXOR:
	case SPARC_INS_FXORS:
	case SPARC_INS_FOR:
	case SPARC_INS_FORNOT1:
	case SPARC_INS_FORNOT1S:
	case SPARC_INS_FORNOT2:
	case SPARC_INS_FORNOT2S:
	case SPARC_INS_FORS:
		return logic_float_op_3(handle, insn, mode);
	case SPARC_INS_FNOT1:
	case SPARC_INS_FNOT1S:
	case SPARC_INS_FNOT2:
	case SPARC_INS_FNOT2S:
		return logic_float_op_1(handle, insn, mode);
	case SPARC_INS_FNEGD:
	case SPARC_INS_FNEGQ:
	case SPARC_INS_FNEGS:
	case SPARC_INS_FABSS:
	case SPARC_INS_FABSD:
	case SPARC_INS_FABSQ:
	case SPARC_INS_FMOVS:
	case SPARC_INS_FMOVD:
	case SPARC_INS_FMOVQ:
	case SPARC_INS_FSRC1:
	case SPARC_INS_FSRC2:
	case SPARC_INS_FSRC1S:
	case SPARC_INS_FSRC2S:
		return arithmetic_float_op_2(handle, insn, mode);
	case SPARC_INS_FONE:
	case SPARC_INS_FONES:
	case SPARC_INS_FZERO:
	case SPARC_INS_FZEROS:
	case SPARC_INS_FSQRTS:
	case SPARC_INS_FSQRTD:
	case SPARC_INS_FSQRTQ:
		return arithmetic_float_op_1(handle, insn, mode);
	case SPARC_INS_FDTOI:
	case SPARC_INS_FDTOQ:
	case SPARC_INS_FDTOS:
	case SPARC_INS_FDTOX:
	case SPARC_INS_FITOD:
	case SPARC_INS_FITOQ:
	case SPARC_INS_FITOS:
	case SPARC_INS_FQTOD:
	case SPARC_INS_FQTOI:
	case SPARC_INS_FQTOS:
	case SPARC_INS_FQTOX:
	case SPARC_INS_FSTOD:
	case SPARC_INS_FSTOI:
	case SPARC_INS_FSTOQ:
	case SPARC_INS_FSTOX:
	case SPARC_INS_FXTOD:
	case SPARC_INS_FXTOQ:
	case SPARC_INS_FXTOS:
		return convert_float_op(handle, insn, mode);
	case SPARC_INS_FCMPD:
	case SPARC_INS_FCMPED:
	case SPARC_INS_FCMPEQ:
	case SPARC_INS_FCMPES:
	case SPARC_INS_FCMPQ:
	case SPARC_INS_FCMPS:
	case SPARC_INS_FCMPEQ16:
	case SPARC_INS_FCMPEQ32:
	case SPARC_INS_FCMPGT16:
	case SPARC_INS_FCMPGT32:
	case SPARC_INS_FCMPLE16:
	case SPARC_INS_FCMPLE32:
	case SPARC_INS_FCMPNE16:
	case SPARC_INS_FCMPNE32:
	case SPARC_INS_FLCMPD:
	case SPARC_INS_FLCMPS:
		return compare_float_op(handle, insn, mode);
	case SPARC_INS_EDGE16:
	case SPARC_INS_EDGE16L:
	case SPARC_INS_EDGE16LN:
	case SPARC_INS_EDGE16N:
	case SPARC_INS_EDGE32:
	case SPARC_INS_EDGE32L:
	case SPARC_INS_EDGE32LN:
	case SPARC_INS_EDGE32N:
	case SPARC_INS_EDGE8:
	case SPARC_INS_EDGE8L:
	case SPARC_INS_EDGE8LN:
	case SPARC_INS_EDGE8N:
		return edge_op(handle, insn, mode);
	case SPARC_INS_FSLAS16:
	case SPARC_INS_FSLAS32:
	case SPARC_INS_FSLL16:
	case SPARC_INS_FSLL32:
	case SPARC_INS_FSRA16:
	case SPARC_INS_FSRA32:
	case SPARC_INS_FSRL16:
	case SPARC_INS_FSRL32:
		return shift_float_op(handle, insn, mode);
	case SPARC_INS_CMASK8:
	case SPARC_INS_CMASK16:
	case SPARC_INS_CMASK32:
		return cmask_op(handle, insn, mode);
	case SPARC_INS_RESTORE:
		return restore_op(handle, insn, mode);
	case SPARC_INS_SAVE:
		return save_op(handle, insn, mode);
	case SPARC_INS_WR:
	case SPARC_INS_RD:
		return read_write_regs_op(handle, insn, mode);
	case SPARC_INS_ALIGNADDR:
	case SPARC_INS_ALIGNADDRL:
	case SPARC_INS_FALIGNDATA:
	case SPARC_INS_POPC:
	case SPARC_INS_LZCNT:
	case SPARC_INS_PDIST:
	case SPARC_INS_PDISTN:
	case SPARC_INS_BSHUFFLE:
	case SPARC_INS_BMASK:
	case SPARC_INS_FMEAN16:
	case SPARC_INS_FCHKSM16:
	case SPARC_INS_FPACK16:
	case SPARC_INS_FPACK32:
	case SPARC_INS_FPACKFIX:
		return misc_insn(handle, insn, mode);
	case SPARC_INS_ARRAY16:
	case SPARC_INS_ARRAY32:
	case SPARC_INS_ARRAY8:
		return array_insn(handle, insn, mode);
	case SPARC_INS_SIAM:
		// Float rounding.
		// Sets FP rounding mode in the GSR register.
		// Currently not modeled as long as we can't
		// derive the rounding mode during runtime.
		NOT_IMPLEMENTED;
	case SPARC_INS_PWR:
	case SPARC_INS_SMAC:
	case SPARC_INS_UMAC:
		// Couldn't find them in OSA 2015.
		// Likely part of (not public?) OSA 2017.
		NOT_IMPLEMENTED;
	case SPARC_INS_SET:
	case SPARC_INS_SETX:
		// Intrinsics/synthetic instructions.
		// Used for assembly only.
		rz_warn_if_reached();
		NOT_IMPLEMENTED;
	case SPARC_INS_T: {
		sparc_cc cc = INSCC_NORM();
		sparc_cc_field field = INSDETAIL().cc_field;
		RzILOpPure *cond = get_cc_condition(cc, field);
		return BRANCH(cond, GOTO("trap"), NOP());
	}
	case SPARC_INS_WRPR:
	case SPARC_INS_RDPR:
	case SPARC_INS_TA:
	case SPARC_INS_SIR:
	case SPARC_INS_DONE:
	case SPARC_INS_RETRY:
	case SPARC_INS_FLUSH:
	case SPARC_INS_FLUSHW:
	case SPARC_INS_UNIMP:
		// Traps and others which are not modeled,
		// but their absence should be notable to the user.
		return GOTO("trap");
	case SPARC_INS_RESTORED:
	case SPARC_INS_SAVED:
	case SPARC_INS_SHUTDOWN:
	case SPARC_INS_PREFETCH:
	case SPARC_INS_MEMBAR:
	case SPARC_INS_STBAR:
		// Not modeled.
		return NOP();
	}
#endif
	NOT_IMPLEMENTED;
}

#undef SSETG

#include "rz_il/rz_il_opbuilder_end.h"
