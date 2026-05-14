// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_D_H
#define RISCV_IL_D_H

#include "riscv_il_base.h"

#include "riscv_il_f.h"

#include <rz_il/rz_il_opbuilder_begin.h>

// -----------------------------------------------------------------------
// D extension: register access (RISCV_REG_F0_D = 74, _D suffix)
//
// When the D extension is present the FP register file is 64 bits wide.
// The IL global variables for ft0-ft11 / fs0-fs11 / fa0-fa7 must be
// declared with width 64 in the IL config (rz_riscv_il_config).
//
// Single-precision values written by F instructions are NaN-boxed:
// the upper 32 bits are all 1s so that D instructions treating the
// register as float64 see a canonical quiet NaN for any narrower value.
// -----------------------------------------------------------------------
#define RISCV_FREG_D_NAME(reg)          riscv_freg_name(reg)
// Read a D register as a float64 IL value.
#define RISCV_GET_FREG_D(reg)           FLOATV64(VARG(RISCV_FREG_D_NAME(reg)))
// Read a D register as a raw 64-bit bitvector (sign-injection, fmv, store).
#define RISCV_GET_FREG_D_BV(reg)        VARG(RISCV_FREG_D_NAME(reg))
// Read a D register's lower 32 bits as a float32 IL value (fcvt.d.s source).
#define RISCV_GET_FREG_D_AS_F32(reg)    FLOATV32(CAST(32, IL_FALSE, VARG(RISCV_FREG_D_NAME(reg))))
// Write a float64 IL value into a D register.
#define RISCV_SET_FREG_D(reg, fl)       SETG(RISCV_FREG_D_NAME(reg), F2BV(fl))
// Write a raw 64-bit bitvector into a D register.
#define RISCV_SET_FREG_D_BV(reg, bv)    SETG(RISCV_FREG_D_NAME(reg), bv)
// Write a float32 IL value into a D register, NaN-boxed to 64 bits.
// Upper 32 bits are set to 0xFFFFFFFF per the RISC-V NaN-boxing rule.
#define RISCV_SET_FREG_D_F32(reg, fl32) SETG(RISCV_FREG_D_NAME(reg), APPEND(UN(32, 0xFFFFFFFF), F2BV(fl32)))

// riscv_rm_to_rz is defined in riscv_il_f.h (included above).
#define D_RM riscv_rm_to_rz(insn->detail->riscv.rounding_mode)

// -----------------------------------------------------------------------
// Lifter templates
// -----------------------------------------------------------------------

// float64 result → D register, with fflags/fcsr update
#define DEFINE_D_LIFTER(name, decoder, fl_result) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		return SEQ3( \
			SETL("_r", fl_result), \
			RISCV_SET_FREG_D(frd, VARL("_r")), \
			RISCV_ACCUMULATE_FFLAGS()); \
	}

// raw 64-bit bitvector → D register (sign injection, fmv.d.x)
#define DEFINE_D_LIFTER_BV_TO_FREG(name, decoder, bv_result) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		return RISCV_SET_FREG_D_BV(frd, bv_result); \
	}

// float32 NaN-boxed result → D register (fcvt.s.d)
#define DEFINE_D_LIFTER_F32_TO_FREG(name, decoder, fl32_result) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		return RISCV_SET_FREG_D_F32(frd, fl32_result); \
	}

// -----------------------------------------------------------------------
// Decoders
// -----------------------------------------------------------------------

// frd=DReg[0], frs1=float64(DReg[1]), frs2=float64(DReg[2])
#define DECODE_D_FD_FS_FS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	REQUIRE_OP(2, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_GET_FREG_D(insn->detail->riscv.operands[1].reg); \
	RzILOpFloat *frs2 = RISCV_GET_FREG_D(insn->detail->riscv.operands[2].reg);

// frd=DReg[0], raw 64-bit bitvectors (sign injection)
#define DECODE_D_FD_BV_BV(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	REQUIRE_OP(2, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *bvrs1 = RISCV_GET_FREG_D_BV(insn->detail->riscv.operands[1].reg); \
	RzILOpBitVector *bvrs2 = RISCV_GET_FREG_D_BV(insn->detail->riscv.operands[2].reg);

// frd=DReg[0], frs1=float64(DReg[1])
#define DECODE_D_FD_FS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_GET_FREG_D(insn->detail->riscv.operands[1].reg);

// rd=IntReg[0], frs1=float64(DReg[1]), frs2=float64(DReg[2])  (feq/flt/fle)
#define DECODE_D_RD_FS_FS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	REQUIRE_OP(2, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_GET_FREG_D(insn->detail->riscv.operands[1].reg); \
	RzILOpFloat *frs2 = RISCV_GET_FREG_D(insn->detail->riscv.operands[2].reg);

// rd=IntReg[0], frs1=float64(DReg[1])  (fcvt.w.d, fclass.d)
#define DECODE_D_RD_FS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_GET_FREG_D(insn->detail->riscv.operands[1].reg);

// rd=IntReg[0], bvrs1=raw64(DReg[1])  (fmv.x.d, fclass.d bit path)
#define DECODE_D_RD_FS_BV(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *bvrs1 = RISCV_GET_FREG_D_BV(insn->detail->riscv.operands[1].reg);

// frd=DReg[0], rs1=IntReg[1]  (fcvt.d.w, fmv.d.x)
#define DECODE_D_FD_RS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs1 = RISCV_GET_REG(insn->detail->riscv.operands[1].reg);

// frd=DReg[0], MEM base+offset  (fld)
#define DECODE_D_FD_MEM(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_MEM); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs = RISCV_GET_REG(insn->detail->riscv.operands[1].mem.base); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[1].mem.disp);

// DReg[0] source, MEM base+offset  (fsd)
#define DECODE_D_FS_MEM(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_MEM); \
	RzILOpBitVector *bvrs1 = RISCV_GET_FREG_D_BV(insn->detail->riscv.operands[0].reg); \
	RzILOpBitVector *rs = RISCV_GET_REG(insn->detail->riscv.operands[1].mem.base); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[1].mem.disp);

// frd=DReg[0], frs1=float64, frs2=float64, frs3=float64
#define DECODE_D_FD_FS_FS_FS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	REQUIRE_OP(2, RISCV_OP_REG); \
	REQUIRE_OP(3, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_GET_FREG_D(insn->detail->riscv.operands[1].reg); \
	RzILOpFloat *frs2 = RISCV_GET_FREG_D(insn->detail->riscv.operands[2].reg); \
	RzILOpFloat *frs3 = RISCV_GET_FREG_D(insn->detail->riscv.operands[3].reg);

// frd=DReg[0], frs1=float32 from lower 32 bits of FReg[1]  (fcvt.d.s)
// capstone encodes the source with the _F suffix; riscv_freg_name() handles both.
#define DECODE_D_FD_FS_F32(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = FLOATV32(CAST(32, IL_FALSE, VARG(riscv_freg_name(insn->detail->riscv.operands[1].reg))));

// frd=DReg[0], frs1=float64 from DReg[1]  (fcvt.s.d — dest also a D register)
#define DECODE_D_FD_FS_F64(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_GET_FREG_D(insn->detail->riscv.operands[1].reg);

// -----------------------------------------------------------------------
// D Extension: Memory
// -----------------------------------------------------------------------

// fld fd, offset(rs1)  — load 64-bit double from memory
DEFINE_D_LIFTER_BV_TO_FREG(fld, DECODE_D_FD_MEM, LOADW(64, ADD(rs, imm)))

// fsd fs2, offset(rs1)  — store 64-bit double to memory
DEFINE_LIFTER_WITH_EFFECT(fsd, DECODE_D_FS_MEM, STOREW(ADD(rs, imm), bvrs1))

// -----------------------------------------------------------------------
// Arithmetic
// -----------------------------------------------------------------------
DEFINE_D_LIFTER(fadd_d, DECODE_D_FD_FS_FS, FADD(D_RM, frs1, frs2))
DEFINE_D_LIFTER(fsub_d, DECODE_D_FD_FS_FS, FSUB(D_RM, frs1, frs2))
DEFINE_D_LIFTER(fmul_d, DECODE_D_FD_FS_FS, FMUL(D_RM, frs1, frs2))
DEFINE_D_LIFTER(fdiv_d, DECODE_D_FD_FS_FS, FDIV(D_RM, frs1, frs2))
DEFINE_D_LIFTER(fsqrt_d, DECODE_D_FD_FS, FSQRT(D_RM, frs1))

// -----------------------------------------------------------------------
// Fused Multiply-Add
// -----------------------------------------------------------------------
DEFINE_D_LIFTER(fmadd_d, DECODE_D_FD_FS_FS_FS, FMAD(D_RM, frs1, frs2, frs3))
DEFINE_D_LIFTER(fmsub_d, DECODE_D_FD_FS_FS_FS, FMAD(D_RM, frs1, frs2, FNEG(frs3)))
DEFINE_D_LIFTER(fnmadd_d, DECODE_D_FD_FS_FS_FS, FNEG(FMAD(D_RM, frs1, frs2, frs3)))
DEFINE_D_LIFTER(fnmsub_d, DECODE_D_FD_FS_FS_FS, FMAD(D_RM, FNEG(frs1), frs2, frs3))

// -----------------------------------------------------------------------
// Sign Injection (bit-level)
// Bit 63 of float64 is the sign bit.
// -----------------------------------------------------------------------
DEFINE_D_LIFTER_BV_TO_FREG(fsgnj_d, DECODE_D_FD_BV_BV,
	LOGOR(LOGAND(bvrs1, UN(64, 0x7FFFFFFFFFFFFFFF)),
		LOGAND(bvrs2, UN(64, 0x8000000000000000))))

DEFINE_D_LIFTER_BV_TO_FREG(fsgnjn_d, DECODE_D_FD_BV_BV,
	LOGOR(LOGAND(bvrs1, UN(64, 0x7FFFFFFFFFFFFFFF)),
		LOGAND(LOGNOT(bvrs2), UN(64, 0x8000000000000000))))

DEFINE_D_LIFTER_BV_TO_FREG(fsgnjx_d, DECODE_D_FD_BV_BV,
	LOGOR(LOGAND(DUP(bvrs1), UN(64, 0x7FFFFFFFFFFFFFFF)),
		LOGAND(LOGXOR(bvrs1, bvrs2), UN(64, 0x8000000000000000))))

// -----------------------------------------------------------------------
// D Extension: Min / Max
//
// IEEE 754-201x minimumNumber / maximumNumber (RISC-V D spec >= 2.2):
//   - signaling NaN operand  → raise NV, return canonical qNaN
//   - exactly one quiet NaN  → return the non-NaN operand
//   - both quiet NaN         → return canonical qNaN
//   - otherwise              → normal min / max
//
// Float64 layout: sign[63], exponent[62:52] (11 bits), mantissa[51:0] (52 bits),
//                 quiet bit[51].
// A value is sNaN iff exponent==0x7FF && mantissa!=0 && quiet_bit==0.
// cond(a, b): FLE for fmin_d, FGE for fmax_d.
// -----------------------------------------------------------------------
#define DEFINE_LIFTER_MINMAX(name, cond) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		REQUIRE_OP(0, RISCV_OP_REG); \
		REQUIRE_OP(1, RISCV_OP_REG); \
		REQUIRE_OP(2, RISCV_OP_REG); \
		uint32_t frd = insn->detail->riscv.operands[0].reg; \
		uint32_t frs1_reg = insn->detail->riscv.operands[1].reg; \
		uint32_t frs2_reg = insn->detail->riscv.operands[2].reg; \
		return SEQN(10, \
			/* _bva: raw 64-bit bitvector of frs1, needed for bit-level sNaN inspection */ \
			SETL("_bva", RISCV_GET_FREG_D_BV(frs1_reg)), \
			/* _bvb: raw 64-bit bitvector of frs2, needed for bit-level sNaN inspection */ \
			SETL("_bvb", RISCV_GET_FREG_D_BV(frs2_reg)), \
			/* _a: frs1 reinterpreted as float64 for IL float comparisons */ \
			SETL("_a", FLOATV64(VARL("_bva"))), \
			/* _b: frs2 reinterpreted as float64 for IL float comparisons */ \
			SETL("_b", FLOATV64(VARL("_bvb"))), \
			/* _na: true if frs1 is any NaN (exponent==0x7FF and mantissa!=0) */ \
			SETL("_na", AND(EQ(EXTRACT64(VARL("_bva"), UN(64, 52), UN(64, 11)), UN(11, 0x7FF)), \
				NON_ZERO(EXTRACT64(VARL("_bva"), UN(64, 0), UN(64, 52))))), \
			/* _nb: true if frs2 is any NaN */ \
			SETL("_nb", AND(EQ(EXTRACT64(VARL("_bvb"), UN(64, 52), UN(64, 11)), UN(11, 0x7FF)), \
				NON_ZERO(EXTRACT64(VARL("_bvb"), UN(64, 0), UN(64, 52))))), \
			/* _sa: true if frs1 is a signaling NaN (NaN with quiet bit[51]==0) */ \
			SETL("_sa", AND(VARL("_na"), INV(NON_ZERO(EXTRACT64(VARL("_bva"), UN(64, 51), UN(64, 1)))))), \
			/* _sb: true if frs2 is a signaling NaN */ \
			SETL("_sb", AND(VARL("_nb"), INV(NON_ZERO(EXTRACT64(VARL("_bvb"), UN(64, 51), UN(64, 1)))))), \
			/* raise NV (invalid operation, bit 4) in fcsr when either operand is sNaN */ \
			SETG("fcsr", LOGOR(VARG("fcsr"), ITE(OR(VARL("_sa"), VARL("_sb")), UN(64, 0x10), UN(64, 0)))), \
			RISCV_SET_FREG_D(frd, \
				ITE(OR(VARL("_sa"), VARL("_sb")), IL_FQNAN(RZ_FLOAT_IEEE754_BIN_64), \
					ITE(VARL("_na"), VARL("_b"), \
						ITE(VARL("_nb"), VARL("_a"), \
							ITE(cond(VARL("_a"), VARL("_b")), VARL("_a"), VARL("_b"))))))); \
	}

DEFINE_LIFTER_MINMAX(fmin_d, FLE)
DEFINE_LIFTER_MINMAX(fmax_d, FGE)

// -----------------------------------------------------------------------
// D Extension: Comparison  (result in integer register)
// -----------------------------------------------------------------------
DEFINE_LIFTER(feq_d, DECODE_D_RD_FS_FS, BOOL_TO_BV(FEQ(frs1, frs2), analysis->bits))
DEFINE_LIFTER(flt_d, DECODE_D_RD_FS_FS, BOOL_TO_BV(FLT(frs1, frs2), analysis->bits))
DEFINE_LIFTER(fle_d, DECODE_D_RD_FS_FS, BOOL_TO_BV(FLE(frs1, frs2), analysis->bits))

// -----------------------------------------------------------------------
// D Extension: fclass.d
//
// Same 10-bit one-hot classification as fclass.s, applied to float64.
//
// Float64 layout: sign[63], exponent[62:52] (11 bits), mantissa[51:0] (52 bits),
//                 quiet bit[51].
// Exponent 0x7FF indicates NaN or infinity.
// -----------------------------------------------------------------------
static RzILOpEffect *rz_riscv_lift_fclass_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	DECODE_D_RD_FS_BV(analysis, insn);
	int xlen = analysis->bits;
#define FBIT_D(n, cond) SHIFTL0(BOOL_TO_BV(cond, xlen), UN(xlen, (n)))
	return SEQN(14,
		SETL("_b", bvrs1),
		SETL("_ex", EXTRACT64(VARL("_b"), UN(64, 52), UN(64, 11))),
		SETL("_mn", EXTRACT64(VARL("_b"), UN(64, 0), UN(64, 52))),
		SETL("_sg", NON_ZERO(EXTRACT64(VARL("_b"), UN(64, 63), UN(64, 1)))),
		SETL("_qt", NON_ZERO(EXTRACT64(VARL("_b"), UN(64, 51), UN(64, 1)))),
		SETL("_xff", EQ(VARL("_ex"), UN(11, 0x7FF))),
		SETL("_xz", IS_ZERO(VARL("_ex"))),
		SETL("_mz", IS_ZERO(VARL("_mn"))),
		SETL("_na", AND(VARL("_xff"), INV(VARL("_mz")))),
		SETL("_in", AND(VARL("_xff"), VARL("_mz"))),
		SETL("_su", AND(VARL("_xz"), INV(VARL("_mz")))),
		SETL("_ze", AND(VARL("_xz"), VARL("_mz"))),
		SETL("_no", AND(INV(VARL("_xz")), INV(VARL("_xff")))),
		RISCV_SET_REG(rd,
			LOGOR(FBIT_D(0, AND(VARL("_sg"), VARL("_in"))),
			LOGOR(FBIT_D(1, AND(VARL("_sg"), VARL("_no"))),
			LOGOR(FBIT_D(2, AND(VARL("_sg"), VARL("_su"))),
			LOGOR(FBIT_D(3, AND(VARL("_sg"), VARL("_ze"))),
			LOGOR(FBIT_D(4, AND(INV(VARL("_sg")), VARL("_ze"))),
			LOGOR(FBIT_D(5, AND(INV(VARL("_sg")), VARL("_su"))),
			LOGOR(FBIT_D(6, AND(INV(VARL("_sg")), VARL("_no"))),
			LOGOR(FBIT_D(7, AND(INV(VARL("_sg")), VARL("_in"))),
			LOGOR(FBIT_D(8, AND(VARL("_na"), INV(VARL("_qt")))),
			      FBIT_D(9, AND(VARL("_na"), VARL("_qt"))))))))))))));
#undef FBIT_D
}

// -----------------------------------------------------------------------
// D Extension: Conversions  float64 → integer
// -----------------------------------------------------------------------

// fcvt.w.d rd, fs1  — float64 → signed int32, sign-extended to XLEN
DEFINE_LIFTER(fcvt_w_d, DECODE_D_RD_FS,
	SIGNED(analysis->bits, F2SINT(32, D_RM, frs1)))

// fcvt.wu.d rd, fs1  — float64 → unsigned int32, sign-extended to XLEN
DEFINE_LIFTER(fcvt_wu_d, DECODE_D_RD_FS,
	SIGNED(analysis->bits, F2INT(32, D_RM, frs1)))

// fcvt.l.d rd, fs1  — float64 → signed int64 (RV64D only)
static RzILOpEffect *rz_riscv_lift_fcvt_l_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	REQUIRE_64_BIT(analysis);
	DECODE_D_RD_FS(analysis, insn);
	return RISCV_SET_REG(rd, F2SINT(64, D_RM, frs1));
}

// fcvt.lu.d rd, fs1  — float64 → unsigned int64 (RV64D only)
static RzILOpEffect *rz_riscv_lift_fcvt_lu_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	REQUIRE_64_BIT(analysis);
	DECODE_D_RD_FS(analysis, insn);
	return RISCV_SET_REG(rd, F2INT(64, D_RM, frs1));
}

// -----------------------------------------------------------------------
// D Extension: Conversions  integer → float64
// -----------------------------------------------------------------------

// fcvt.d.w fd, rs1  — signed int32 → float64
DEFINE_D_LIFTER(fcvt_d_w, DECODE_D_FD_RS,
	SINT2F(RZ_FLOAT_IEEE754_BIN_64, D_RM, CAST(32, IL_FALSE, rs1)))

// fcvt.d.wu fd, rs1  — unsigned int32 → float64
DEFINE_D_LIFTER(fcvt_d_wu, DECODE_D_FD_RS,
	INT2F(RZ_FLOAT_IEEE754_BIN_64, D_RM, CAST(32, IL_FALSE, rs1)))

// fcvt.d.l fd, rs1  — signed int64 → float64 (RV64D only)
static RzILOpEffect *rz_riscv_lift_fcvt_d_l(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	REQUIRE_64_BIT(analysis);
	DECODE_D_FD_RS(analysis, insn);
	return RISCV_SET_FREG_D(frd, SINT2F(RZ_FLOAT_IEEE754_BIN_64, D_RM, rs1));
}

// fcvt.d.lu fd, rs1  — unsigned int64 → float64 (RV64D only)
static RzILOpEffect *rz_riscv_lift_fcvt_d_lu(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	REQUIRE_64_BIT(analysis);
	DECODE_D_FD_RS(analysis, insn);
	return RISCV_SET_FREG_D(frd, INT2F(RZ_FLOAT_IEEE754_BIN_64, D_RM, rs1));
}

// -----------------------------------------------------------------------
// D Extension: Precision conversions
//
// NaN-boxing note
// ---------------
// When the D extension is present the FP register file is 64 bits wide.
// A float32 result stored into an FP register must be NaN-boxed: the upper
// 32 bits are forced to 0xFFFFFFFF.  RISCV_SET_FREG_D_F32 handles this.
//
// When reading a float32 source from a D register the lower 32 bits
// are used; the upper NaN-box bits are discarded by CAST(32, IL_FALSE, ...).
// -----------------------------------------------------------------------

// fcvt.d.s fd, fs1  — float32 (NaN-boxed in D reg) → float64
// capstone encodes fs1 with the _F suffix; DECODE_D_FD_FS_F32 reads the
// lower 32 bits of the 64-bit register and reinterprets as float32.
DEFINE_D_LIFTER(fcvt_d_s, DECODE_D_FD_FS_F32,
	FCONVERT(RZ_FLOAT_IEEE754_BIN_64, D_RM, frs1))

// fcvt.s.d fd, fs1  — float64 → float32, NaN-boxed into D register
DEFINE_D_LIFTER_F32_TO_FREG(fcvt_s_d, DECODE_D_FD_FS_F64,
	FCONVERT(RZ_FLOAT_IEEE754_BIN_32, D_RM, frs1))

// -----------------------------------------------------------------------
// D Extension: Bit-level Move (RV64D only)
// -----------------------------------------------------------------------

// fmv.x.d rd, fs1  — copy float64 bits to integer register (RV64D)
static RzILOpEffect *rz_riscv_lift_fmv_x_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	REQUIRE_64_BIT(analysis);
	DECODE_D_RD_FS_BV(analysis, insn);
	return RISCV_SET_REG(rd, bvrs1);
}

// fmv.d.x fd, rs1  — copy integer register bits to float64 register (RV64D)
static RzILOpEffect *rz_riscv_lift_fmv_d_x(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	REQUIRE_64_BIT(analysis);
	DECODE_D_FD_RS(analysis, insn);
	return RISCV_SET_FREG_D_BV(frd, rs1);
}

#include <rz_il/rz_il_opbuilder_end.h>

#endif // RISCV_IL_D_H
