// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_D_H
#define RISCV_IL_D_H

#include "riscv_il_base.h"
#include "riscv_il_f.h"

// -----------------------------------------------------------------------
// D extension: register access (RISCV_REG_F0_D = 74, _D suffix)
//
// When the D extension is present the FP register file is 64 bits wide.
// Single-precision values written by F instructions are NaN-boxed:
// the upper 32 bits are all 1s so that D instructions treating the
// register as float64 see a canonical quiet NaN for any narrower value.
// -----------------------------------------------------------------------
#define RISCV_FREG_D_NAME(reg)          riscv_freg_name(reg)
#define RISCV_GET_FREG_D(reg)           FLOATV64(VARG(RISCV_FREG_D_NAME(reg)))
#define RISCV_GET_FREG_D_BV(reg)        VARG(RISCV_FREG_D_NAME(reg))
#define RISCV_GET_FREG_D_AS_F32(reg)    FLOATV32(CAST(32, IL_FALSE, VARG(RISCV_FREG_D_NAME(reg))))
#define RISCV_SET_FREG_D(reg, fl)       SETG(RISCV_FREG_D_NAME(reg), F2BV(fl))
#define RISCV_SET_FREG_D_BV(reg, bv)    SETG(RISCV_FREG_D_NAME(reg), bv)
#define RISCV_SET_FREG_D_F32(reg, fl32) SETG(RISCV_FREG_D_NAME(reg), APPEND(UN(32, 0xFFFFFFFF), F2BV(fl32)))

#define D_RM riscv_rm_to_rz(insn->detail->riscv.rounding_mode)

// -----------------------------------------------------------------------
// D extension: specialization of the riscv_il_fd_common.h interface
// Float64 IEEE 754: sign[63], exponent[62:52] (11 bits), mantissa[51:0] (52 bits)
// -----------------------------------------------------------------------
#define RISCV_FD_REG_GETTER(reg)           RISCV_GET_FREG_D(reg)
#define RISCV_FD_REG_SETTER(reg, fl)       RISCV_SET_FREG_D(reg, fl)
#define RISCV_FD_REG_GETTER_BV(reg)        RISCV_GET_FREG_D_BV(reg)
#define RISCV_FD_REG_SETTER_BV(reg, bv)    RISCV_SET_FREG_D_BV(reg, bv)
#define RISCV_FD_GET_MANTISSA(bv)          EXTRACT64(bv, UN(64, 0), UN(32, 52))
#define RISCV_FD_GET_EXPONENT(bv)          EXTRACT64(bv, UN(64, 52), UN(32, 11))
#define RISCV_FD_GET_SIGN(bv)              EXTRACT64(bv, UN(64, 63), UN(32, 1))
#define RISCV_FD_IS_NAN(bv)                AND(EQ(RISCV_FD_GET_EXPONENT(bv), UN(64, 0x7FF)), NON_ZERO(RISCV_FD_GET_MANTISSA(bv)))
#define RISCV_FD_IS_S_NAN(bv)              AND(RISCV_FD_IS_NAN(bv), EQ(EXTRACT64(bv, UN(64, 51), UN(32, 1)), UN(64, 0)))
#define RISCV_FD_IS_MAX_EXP(bv)            EQ(bv, UN(64, 0x7FF))
#define RISCV_FD_IS_EXP_OVERFLOW_INT(bv)   UGE(bv, UN(64, 1054))
#define RISCV_FD_IS_EXP_OVERFLOW_UINT(bv)  UGE(bv, UN(64, 1055))
#define RISCV_FD_IS_EXP_OVERFLOW_LONG(bv)  UGE(bv, UN(64, 1086))
#define RISCV_FD_IS_EXP_OVERFLOW_ULONG(bv) UGE(bv, UN(64, 1087))

#include <rz_il/rz_il_opbuilder_begin.h>

// -----------------------------------------------------------------------
// Memory
// -----------------------------------------------------------------------
DEF_LOAD(fld, 64)
DEF_STORE(fsd)

// -----------------------------------------------------------------------
// Arithmetic
// -----------------------------------------------------------------------
DEF_ADD(fadd_d)
DEF_SUB(fsub_d)
DEF_MUL(fmul_d)
DEF_DIV(fdiv_d)
DEF_SQRT(fsqrt_d)

// -----------------------------------------------------------------------
// Fused Multiply-Add
// -----------------------------------------------------------------------
DEF_FMADD(fmadd_d)
DEF_FMSUB(fmsub_d)
DEF_FNMADD(fnmadd_d)
DEF_FNMSUB(fnmsub_d)

// -----------------------------------------------------------------------
// Sign Injection (bit-level, no rounding)
// -----------------------------------------------------------------------
DEF_FSGNJ(fsgnj_d, 64)
DEF_FSGNJN(fsgnjn_d, 64)
DEF_FSGNJX(fsgnjx_d, 64)

// -----------------------------------------------------------------------
// Min/Max
// -----------------------------------------------------------------------
DEF_FMIN(fmin_d, 64)
DEF_FMAX(fmax_d, 64)

// -----------------------------------------------------------------------
// Comparison (result in integer register)
// -----------------------------------------------------------------------
DEF_FEQ(feq_d, 64)
DEF_FLT(flt_d, 64)
DEF_FLE(fle_d, 64)

// -----------------------------------------------------------------------
// Classification
// -----------------------------------------------------------------------
DEF_FCLASS(fclass_d)

// -----------------------------------------------------------------------
// Conversions  float64 → integer
// -----------------------------------------------------------------------
DEF_FCVT_W(fcvt_w_d, 64)
DEF_FCVT_WU(fcvt_wu_d, 64)
DEF_FCVT_L(fcvt_l_d, 64)
DEF_FCVT_LU(fcvt_lu_d, 64)

// -----------------------------------------------------------------------
// D-exclusive decoders (cross-precision and bit-move instructions)
// -----------------------------------------------------------------------

// frd=DReg[0], frs1=float32 from lower 32 bits of FReg[1]  (fcvt.d.s)
// capstone encodes the source with the _F suffix; riscv_freg_name() handles both.
#define DECODE_D_FD_FS_F32(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = FLOATV32(CAST(32, IL_FALSE, VARG(riscv_freg_name(insn->detail->riscv.operands[1].reg))));

// frd=DReg[0], frs1=float64 from DReg[1]  (fcvt.s.d)
#define DECODE_D_FD_FS_F64(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_GET_FREG_D(insn->detail->riscv.operands[1].reg);

// frd=DReg[0], rs1=IntReg[1]  (fcvt.d.w, fcvt.d.l, fmv.d.x)
#define DECODE_D_FD_RS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs1 = RISCV_GET_REG(insn->detail->riscv.operands[1].reg);

// rd=IntReg[0], bvrs1=raw64(DReg[1])  (fmv.x.d)
#define DECODE_D_RD_FS_BV(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *bvrs1 = RISCV_GET_FREG_D_BV(insn->detail->riscv.operands[1].reg);

// -----------------------------------------------------------------------
// D Extension: Precision conversions
// -----------------------------------------------------------------------

// fcvt.d.s fd, fs1  — float32 (NaN-boxed in D reg) → float64
static RzILOpEffect *rz_riscv_lift_fcvt_d_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	DECODE_D_FD_FS_F32(analysis, insn);
	return SEQ3(
		SETL("_r", FCONVERT(RZ_FLOAT_IEEE754_BIN_64, D_RM, frs1)),
		RISCV_SET_FREG_D(frd, VARL("_r")),
		RISCV_FD_UPDATE_FFLAGS());
}

// fcvt.s.d fd, fs1  — float64 → float32, NaN-boxed into D register
static RzILOpEffect *rz_riscv_lift_fcvt_s_d(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	DECODE_D_FD_FS_F64(analysis, insn);
	return SEQ3(
		SETL("_r", FCONVERT(RZ_FLOAT_IEEE754_BIN_32, D_RM, frs1)),
		RISCV_SET_FREG_D_F32(frd, VARL("_r")),
		RISCV_FD_UPDATE_FFLAGS());
}

// -----------------------------------------------------------------------
// D Extension: Conversions  integer → float64
// -----------------------------------------------------------------------

// fcvt.d.w fd, rs1  — signed int32 → float64
static RzILOpEffect *rz_riscv_lift_fcvt_d_w(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	DECODE_D_FD_RS(analysis, insn);
	return SEQ3(
		SETL("_r", SINT2F(RZ_FLOAT_IEEE754_BIN_64, D_RM, SIGNED(64, CAST(32, IL_FALSE, rs1)))),
		RISCV_SET_FREG_D(frd, VARL("_r")),
		RISCV_FD_UPDATE_FFLAGS());
}

// fcvt.d.wu fd, rs1  — unsigned int32 → float64
static RzILOpEffect *rz_riscv_lift_fcvt_d_wu(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	DECODE_D_FD_RS(analysis, insn);
	return SEQ3(
		SETL("_r", INT2F(RZ_FLOAT_IEEE754_BIN_64, D_RM, CAST(64, IL_FALSE, CAST(32, IL_FALSE, rs1)))),
		RISCV_SET_FREG_D(frd, VARL("_r")),
		RISCV_FD_UPDATE_FFLAGS());
}

// fcvt.d.l fd, rs1  — signed int64 → float64 (RV64D only)
// NX is raised when the integer cannot be represented exactly in float64 (more than
// 53 significant bits).  Saving to _r lets RISCV_FD_UPDATE_FFLAGS query the result.
static RzILOpEffect *rz_riscv_lift_fcvt_d_l(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	REQUIRE_64_BIT(analysis);
	DECODE_D_FD_RS(analysis, insn);
	return SEQ3(
		SETL("_r", SINT2F(RZ_FLOAT_IEEE754_BIN_64, D_RM, rs1)),
		RISCV_SET_FREG_D(frd, VARL("_r")),
		RISCV_FD_UPDATE_FFLAGS());
}

// fcvt.d.lu fd, rs1  — unsigned int64 → float64 (RV64D only)
static RzILOpEffect *rz_riscv_lift_fcvt_d_lu(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	REQUIRE_64_BIT(analysis);
	DECODE_D_FD_RS(analysis, insn);
	return SEQ3(
		SETL("_r", INT2F(RZ_FLOAT_IEEE754_BIN_64, D_RM, rs1)),
		RISCV_SET_FREG_D(frd, VARL("_r")),
		RISCV_FD_UPDATE_FFLAGS());
}

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

// -----------------------------------------------------------------------
// Clean up D interface macros
// -----------------------------------------------------------------------
#undef RISCV_FD_REG_GETTER
#undef RISCV_FD_REG_SETTER
#undef RISCV_FD_REG_GETTER_BV
#undef RISCV_FD_REG_SETTER_BV
#undef RISCV_FD_GET_MANTISSA
#undef RISCV_FD_GET_EXPONENT
#undef RISCV_FD_GET_SIGN
#undef RISCV_FD_IS_NAN
#undef RISCV_FD_IS_S_NAN
#undef RISCV_FD_IS_MAX_EXP
#undef RISCV_FD_IS_EXP_OVERFLOW_INT
#undef RISCV_FD_IS_EXP_OVERFLOW_UINT
#undef RISCV_FD_IS_EXP_OVERFLOW_LONG
#undef RISCV_FD_IS_EXP_OVERFLOW_ULONG

#endif // RISCV_IL_D_H
