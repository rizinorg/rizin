// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "analysis_private.h"

#define RISCV_FREG_F_NAME(reg) riscv_freg_name(reg)

// The register is 64-bit (NaN-boxed); hence extracting the lower 32 bits.
#define RISCV_GET_FREG_RAW(reg) CAST(32, IL_FALSE, VARG(RISCV_FREG_F_NAME(reg)))
// Write a raw 32-bit bitvector into a float register, NaN-boxing to 64 bits.
#define RISCV_SET_FREG_RAW(reg, val) SETG(RISCV_FREG_F_NAME(reg), APPEND(UN(32, 0xFFFFFFFF), val))

// Read a float register as a float32 IL value
#define RISCV_FD_REG_GETTER(reg) FLOATV32(RISCV_GET_FREG_RAW(reg))
// Read a float register as a raw 32-bit bitvector
#define RISCV_FD_REG_GETTER_BV(reg) RISCV_GET_FREG_RAW(reg)
// Write a float32 IL value into a float register
#define RISCV_FD_REG_SETTER(reg, fl) RISCV_SET_FREG_RAW(reg, F2BV(fl))
// Write a raw 32-bit bitvector into a float register
#define RISCV_FD_REG_SETTER_BV(reg, bv) RISCV_SET_FREG_RAW(reg, bv)
// destructure a float into its 3 IEEE 754 fields
#define RISCV_FD_GET_EXPONENT(bv) EXTRACT32(bv, UN(32, 23), UN(32, 8))
#define RISCV_FD_GET_MANTISSA(bv) EXTRACT32(bv, UN(32, 0), UN(32, 23))
#define RISCV_FD_GET_SIGN(bv) EXTRACT32(bv, UN(32, 31), UN(32, 1))
// NAN API
#define RISCV_FD_IS_NAN(bv) AND(EQ(RISCV_FD_GET_EXPONENT(bv), UN(32, 0xFF)), NON_ZERO(RISCV_FD_GET_MANTISSA(bv)))
#define RISCV_FD_IS_S_NAN(bv) AND(RISCV_FD_IS_NAN(bv), EQ(EXTRACT32(bv, UN(32, 22), UN(32, 1)), UN(32, 0)))
#define RISCV_FD_CANONICAL_QNAN() UN(32, 0x7FC00000)
// Exponent API
#define RISCV_FD_IS_MAX_EXP(bv) EQ(bv, UN(32, 0xFF))
#define RISCV_FD_IS_EXP_OVERFLOW_INT(bv) UGE(bv, UN(32, 158))
#define RISCV_FD_IS_EXP_OVERFLOW_UINT(bv) UGE(bv, UN(32, 159))
#define RISCV_FD_IS_EXP_OVERFLOW_LONG(bv) UGE(bv, UN(32, 190))
#define RISCV_FD_IS_EXP_OVERFLOW_ULONG(bv) UGE(bv, UN(32, 191))

// -----------------------------------------------------------------------
// F Extension: rounding mode, decoders, and lifter templates
// -----------------------------------------------------------------------
#define F_RM riscv_rm_to_rz(insn->detail->riscv.rounding_mode)

// frd=FReg[0], rs1=IntReg[1]  (fcvt.s.w, fcvt.s.wu, fcvt.s.l, fcvt.s.lu, fmv.w.x)
#define DECODE_F_FD_RS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs1 = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[1].reg);

// rd=IntReg[0], bvrs1=raw32(FReg[1])  (fmv.x.w)
#define DECODE_F_RD_FS_BV(analysis, insn) DECODE_FD_RD_FS_BV(analysis, insn)

// integer→float32 lifter: compute expr, store to freg, update fflags
#define DEFINE_F_LIFTER(name, decoder, expr) \
	RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		return SEQ3( \
			SETL("_r", expr), \
			RISCV_FD_REG_SETTER(frd, VARL("_r")), \
			RISCV_FD_UPDATE_FFLAGS()); \
	}

// bitvector→float register lifter (no rounding, no fflags update)
#define DEFINE_F_LIFTER_BV_TO_FREG(name, decoder, bv_expr) \
	RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		return RISCV_FD_REG_SETTER_BV(frd, bv_expr); \
	}

// ---------------------------- Instantiate FP definition generators ----------------------------
#include "riscv_il_fd_common.h"

#include <rz_il/rz_il_opbuilder_begin.h>

// -----------------------------------------------------------------------
// Memory
// -----------------------------------------------------------------------

// flw fd, offset(rs1) — load 32-bit float from memory
DEF_LOAD(flw, 32)
// fsw fs2, offset(rs1) — store 32-bit float to memory
DEF_STORE(fsw)

// -----------------------------------------------------------------------
// Arithmetic
// -----------------------------------------------------------------------
DEF_ADD(fadd_s)
DEF_SUB(fsub_s)
DEF_MUL(fmul_s)
DEF_DIV(fdiv_s)
DEF_SQRT(fsqrt_s)

// -----------------------------------------------------------------------
// Fused Multiply-Add
// -----------------------------------------------------------------------
DEF_FMADD(fmadd_s)
DEF_FMSUB(fmsub_s)
DEF_FNMADD(fnmadd_s)
DEF_FNMSUB(fnmsub_s)

// -----------------------------------------------------------------------
// Sign Injection (bit-level, no rounding)
// -----------------------------------------------------------------------
DEF_FSGNJ(fsgnj_s, 32)
DEF_FSGNJN(fsgnjn_s, 32)
DEF_FSGNJX(fsgnjx_s, 32)

// -----------------------------------------------------------------------
// Min/Max
// -----------------------------------------------------------------------
DEF_FMIN(fmin_s, 32)
DEF_FMAX(fmax_s, 32)
// -----------------------------------------------------------------------
// Comparison and equality
// -----------------------------------------------------------------------
DEF_FEQ(feq_s, 32)
DEF_FLT(flt_s, 32)
DEF_FLE(fle_s, 32)

DEF_FCLASS(fclass_s)

// -----------------------------------------------------------------------
// Conversions  float32 → integer
// -----------------------------------------------------------------------
// 
DEF_FCVT_W(fcvt_w_s, 32)
DEF_FCVT_WU(fcvt_wu_s, 32)
DEF_FCVT_L(fcvt_l_s, 32)
DEF_FCVT_LU(fcvt_lu_s, 32)

// -----------------------------------------------------------------------
// F Extension: Conversions  integer → float32
// -----------------------------------------------------------------------

// fcvt.s.w fd, rs1  — signed int32 to float32
// CAST(32, IL_FALSE, rs1) truncates XLEN-bit rs1 to 32 bits for the conversion.
DEFINE_F_LIFTER(fcvt_s_w, DECODE_F_FD_RS,
	SINT2F(RZ_FLOAT_IEEE754_BIN_32, F_RM, CAST(32, IL_FALSE, rs1)))

// fcvt.s.wu fd, rs1  — unsigned int32 to float32
DEFINE_F_LIFTER(fcvt_s_wu, DECODE_F_FD_RS,
	INT2F(RZ_FLOAT_IEEE754_BIN_32, F_RM, CAST(32, IL_FALSE, rs1)))

// fcvt.s.l fd, rs1  — signed int64 to float32 (RV64F only)
// NX is raised when the integer cannot be represented exactly in float32 (more than
// 24 significant bits).  Saving to _r lets RISCV_FD_UPDATE_FFLAGS query the result.
RzILOpEffect *rz_riscv_lift_fcvt_s_l(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	REQUIRE_64_BIT(analysis);
	DECODE_F_FD_RS(analysis, insn);
	return SEQ3(
		SETL("_r", SINT2F(RZ_FLOAT_IEEE754_BIN_32, F_RM, rs1)),
		RISCV_FD_REG_SETTER(frd, VARL("_r")),
		RISCV_FD_UPDATE_FFLAGS());
}

// fcvt.s.lu fd, rs1  — unsigned int64 to float32 (RV64F only)
RzILOpEffect *rz_riscv_lift_fcvt_s_lu(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	REQUIRE_64_BIT(analysis);
	DECODE_F_FD_RS(analysis, insn);
	return SEQ3(
		SETL("_r", INT2F(RZ_FLOAT_IEEE754_BIN_32, F_RM, rs1)),
		RISCV_FD_REG_SETTER(frd, VARL("_r")),
		RISCV_FD_UPDATE_FFLAGS());
}

// -----------------------------------------------------------------------
// F Extension: Bit-level Move (no float conversion, no rounding)
// -----------------------------------------------------------------------

// fmv.x.w rd, fs1  — copy float32 bits to integer register, sign-extended to XLEN
DEFINE_LIFTER(fmv_x_w, DECODE_F_RD_FS_BV,
	SIGNED(analysis->bits, bvrs1))

// fmv.w.x fd, rs1  — copy integer register bits (lower 32) to float register
DEFINE_F_LIFTER_BV_TO_FREG(fmv_w_x, DECODE_F_FD_RS,
	CAST(32, IL_FALSE, rs1))

#include <rz_il/rz_il_opbuilder_end.h>

#undef RISCV_FD_REG_GETTER
#undef RISCV_FD_REG_SETTER
#undef RISCV_FD_REG_GETTER_BV
#undef RISCV_FD_REG_SETTER_BV
#undef RISCV_FD_GET_MANTISSA
#undef RISCV_FD_GET_EXPONENT
#undef RISCV_FD_GET_SIGN
#undef RISCV_FD_IS_NAN
#undef RISCV_FD_IS_S_NAN
#undef RISCV_FD_CANONICAL_QNAN
#undef RISCV_FD_IS_MAX_EXP
#undef RISCV_FD_IS_EXP_OVERFLOW_INT
#undef RISCV_FD_IS_EXP_OVERFLOW_UINT
#undef RISCV_FD_IS_EXP_OVERFLOW_LONG
#undef RISCV_FD_IS_EXP_OVERFLOW_ULONG
#undef F_RM
#undef RISCV_FD_REG_SETTER
#undef DECODE_F_FD_RS
#undef DECODE_F_RD_FS_BV
#undef DEFINE_F_LIFTER
#undef DEFINE_F_LIFTER_BV_TO_FREG

