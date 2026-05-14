// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_F_H
#define RISCV_IL_F_H

#include "riscv_il_base.h"

#include <rz_il/rz_il_opbuilder_begin.h>
#include <stddef.h>

#include "riscv_il_float_reg_names.h"

// -----------------------------------------------------------------------
// F extension: register access (RISCV_REG_F0_F = 106, _F suffix)
//
// In an F-only implementation the FP registers are 32-bit IL global
// variables whose raw bits hold the IEEE 754 binary32 value.
// -----------------------------------------------------------------------
#define RISCV_FREG_F_NAME(reg) riscv_freg_names[(reg) - RISCV_REG_F0_F]

// The register is 64-bit (NaN-boxed); hence extracting the lower 32 bits.
#define RISCV_GET_FREG_RAW(reg) CAST(32, IL_FALSE, VARG(RISCV_FREG_F_NAME(reg)))
// Write a raw 32-bit bitvector into a float register, NaN-boxing to 64 bits.
#define RISCV_SET_FREG_RAW(reg, val) SETG(RISCV_FREG_F_NAME(reg), APPEND(UN(32, 0xFFFFFFFF), val))

// Read a float register as a float32 IL value
#define RISCV_GET_FREG_F(reg) FLOATV32(RISCV_GET_FREG_RAW(reg))
// Read a float register as a raw 32-bit bitvector
#define RISCV_GET_FREG_F_BV(reg) RISCV_GET_FREG_RAW(reg)
// Write a float32 IL value into a float register
#define RISCV_SET_FREG_F(reg, fl) RISCV_SET_FREG_RAW(reg, F2BV(fl))
// Write a raw 32-bit bitvector into a float register
#define RISCV_SET_FREG_F_BV(reg, bv) RISCV_SET_FREG_RAW(reg, bv)

// Map Capstone's RISC-V rounding mode to RzFloat's rounding mode.

// RzIL float operations (FADD, FMUL, F2SINT, ...) accept a RzFloatRMode enum
// value that is baked into the IL expression at lift time — it is a
// compile-time constant in the IL tree, not a runtime value.  There is
// currently no RzIL mechanism to pass a variable (e.g. VARG("fcsr")) as the
// rounding mode of a float operation, so RISCV_RM_DYN cannot be faithfully
// represented.  Instructions that use dynamic rounding are lifted with RNE as
// a fallback, which is architecturally incorrect whenever frm != RNE at
// runtime but is the best approximation available without changes to the RzIL
// float layer.
static inline RzFloatRMode riscv_rm_to_rz(riscv_rounding_mode rm) {
	switch (rm) {
	case RISCV_RM_RNE: return RZ_FLOAT_RMODE_RNE;
	case RISCV_RM_RTZ: return RZ_FLOAT_RMODE_RTZ;
	case RISCV_RM_RDN: return RZ_FLOAT_RMODE_RTN;
	case RISCV_RM_RUP: return RZ_FLOAT_RMODE_RTP;
	case RISCV_RM_RMM: return RZ_FLOAT_RMODE_RNA;
	default: return RZ_FLOAT_RMODE_RNE; // RISCV_RM_DYN / RISCV_RM_INVALID: see above
	}
}

#define F_RM riscv_rm_to_rz(insn->detail->riscv.rounding_mode)

// fflags / fcsr helpers
// RISC-V fflags layout (bits 4:0 of fcsr):
//   bit 0  NX  inexact           RZ_FLOAT_E_INEXACT
//   bit 1  UF  underflow         RZ_FLOAT_E_UNDERFLOW
//   bit 2  OF  overflow          RZ_FLOAT_E_OVERFLOW
//   bit 3  DZ  divide-by-zero    RZ_FLOAT_E_DIV_ZERO
//   bit 4  NV  invalid           RZ_FLOAT_E_INVALID_OP
//
// Usage: set local float variable "_r" to the result, then call
// RISCV_ACCUMULATE_FFLAGS() to sticky-OR exceptions into "fflags"
// and keep "fcsr" in sync.
#define RISCV_F_EXC(riscv_bit, rz_exc) \
	ITE(FEXCEPT(rz_exc, VARL("_r")), UN(64, riscv_bit), UN(64, 0))

#define RISCV_ACCUMULATE_FFLAGS() \
	SETG("fcsr", LOGOR(VARG("fcsr"), \
		LOGOR(RISCV_F_EXC(0x01, RZ_FLOAT_E_INEXACT), \
		LOGOR(RISCV_F_EXC(0x02, RZ_FLOAT_E_UNDERFLOW), \
		LOGOR(RISCV_F_EXC(0x04, RZ_FLOAT_E_OVERFLOW), \
		LOGOR(RISCV_F_EXC(0x08, RZ_FLOAT_E_DIV_ZERO), \
		      RISCV_F_EXC(0x10, RZ_FLOAT_E_INVALID_OP)))))))

// -----------------------------------------------------------------------
// Lifter templates
// -----------------------------------------------------------------------

// float32 result → float destination register, with fflags/fcsr update
#define DEFINE_F_LIFTER(name, decoder, fl_result) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		return SEQ3( \
			SETL("_r", fl_result), \
			RISCV_SET_FREG_F(frd, VARL("_r")), \
			RISCV_ACCUMULATE_FFLAGS()); \
	}

// raw 32-bit bitvector → float destination register
#define DEFINE_F_LIFTER_BV_TO_FREG(name, decoder, bv_result) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		return RISCV_SET_FREG_F_BV(frd, bv_result); \
	}

// -----------------------------------------------------------------------
// Decoders
// -----------------------------------------------------------------------

#define DECODE_F_FD_FS_FS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	REQUIRE_OP(2, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_GET_FREG_F(insn->detail->riscv.operands[1].reg); \
	RzILOpFloat *frs2 = RISCV_GET_FREG_F(insn->detail->riscv.operands[2].reg);

#define DECODE_F_FD_BV_BV(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	REQUIRE_OP(2, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *bvrs1 = RISCV_GET_FREG_F_BV(insn->detail->riscv.operands[1].reg); \
	RzILOpBitVector *bvrs2 = RISCV_GET_FREG_F_BV(insn->detail->riscv.operands[2].reg);

#define DECODE_F_FD_FS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_GET_FREG_F(insn->detail->riscv.operands[1].reg);

#define DECODE_F_RD_FS_FS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	REQUIRE_OP(2, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_GET_FREG_F(insn->detail->riscv.operands[1].reg); \
	RzILOpFloat *frs2 = RISCV_GET_FREG_F(insn->detail->riscv.operands[2].reg);

#define DECODE_F_RD_FS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_GET_FREG_F(insn->detail->riscv.operands[1].reg);

#define DECODE_F_RD_FS_BV(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *bvrs1 = RISCV_GET_FREG_F_BV(insn->detail->riscv.operands[1].reg);

#define DECODE_F_FD_RS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs1 = RISCV_GET_REG(insn->detail->riscv.operands[1].reg);

#define DECODE_F_FD_MEM(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_MEM); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs = RISCV_GET_REG(insn->detail->riscv.operands[1].mem.base); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[1].mem.disp);

#define DECODE_F_FS_MEM(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_MEM); \
	RzILOpBitVector *bvrs1 = RISCV_GET_FREG_F_BV(insn->detail->riscv.operands[0].reg); \
	RzILOpBitVector *rs = RISCV_GET_REG(insn->detail->riscv.operands[1].mem.base); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[1].mem.disp);

#define DECODE_F_FD_FS_FS_FS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	REQUIRE_OP(2, RISCV_OP_REG); \
	REQUIRE_OP(3, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_GET_FREG_F(insn->detail->riscv.operands[1].reg); \
	RzILOpFloat *frs2 = RISCV_GET_FREG_F(insn->detail->riscv.operands[2].reg); \
	RzILOpFloat *frs3 = RISCV_GET_FREG_F(insn->detail->riscv.operands[3].reg);

// -----------------------------------------------------------------------
// F Extension: Memory
// -----------------------------------------------------------------------

// flw fd, offset(rs1)  — load 32-bit float from memory
DEFINE_F_LIFTER_BV_TO_FREG(flw, DECODE_F_FD_MEM, LOADW(32, ADD(rs, imm)))

// fsw fs2, offset(rs1)  — store 32-bit float to memory
DEFINE_LIFTER_WITH_EFFECT(fsw, DECODE_F_FS_MEM, STOREW(ADD(rs, imm), bvrs1))

// -----------------------------------------------------------------------
// Arithmetic
// -----------------------------------------------------------------------
DEFINE_F_LIFTER(fadd_s, DECODE_F_FD_FS_FS, FADD(F_RM, frs1, frs2))
DEFINE_F_LIFTER(fsub_s, DECODE_F_FD_FS_FS, FSUB(F_RM, frs1, frs2))
DEFINE_F_LIFTER(fmul_s, DECODE_F_FD_FS_FS, FMUL(F_RM, frs1, frs2))
DEFINE_F_LIFTER(fdiv_s, DECODE_F_FD_FS_FS, FDIV(F_RM, frs1, frs2))
DEFINE_F_LIFTER(fsqrt_s, DECODE_F_FD_FS, FSQRT(F_RM, frs1))

// -----------------------------------------------------------------------
// Fused Multiply-Add
//
//   fmadd.s:  fd =  (rs1 × rs2) + rs3
//   fmsub.s:  fd =  (rs1 × rs2) - rs3
//   fnmadd.s: fd = -(rs1 × rs2) - rs3
//   fnmsub.s: fd = -(rs1 × rs2) + rs3
// -----------------------------------------------------------------------
DEFINE_F_LIFTER(fmadd_s, DECODE_F_FD_FS_FS_FS, FMAD(F_RM, frs1, frs2, frs3))
DEFINE_F_LIFTER(fmsub_s, DECODE_F_FD_FS_FS_FS, FMAD(F_RM, frs1, frs2, FNEG(frs3)))
DEFINE_F_LIFTER(fnmadd_s, DECODE_F_FD_FS_FS_FS, FNEG(FMAD(F_RM, frs1, frs2, frs3)))
DEFINE_F_LIFTER(fnmsub_s, DECODE_F_FD_FS_FS_FS, FMAD(F_RM, FNEG(frs1), frs2, frs3))

// -----------------------------------------------------------------------
// Sign Injection (bit-level, no rounding)
//
//   fsgnj.s:  fd = |rs1| with sign of rs2
//   fsgnjn.s: fd = |rs1| with negated sign of rs2
//   fsgnjx.s: fd = |rs1| with sign = sign(rs1) XOR sign(rs2)
//
// Bit 31 of float32 is the sign bit.
// -----------------------------------------------------------------------
DEFINE_F_LIFTER_BV_TO_FREG(fsgnj_s, DECODE_F_FD_BV_BV,
	LOGOR(LOGAND(bvrs1, UN(32, 0x7FFFFFFF)),
		LOGAND(bvrs2, UN(32, 0x80000000))))

DEFINE_F_LIFTER_BV_TO_FREG(fsgnjn_s, DECODE_F_FD_BV_BV,
	LOGOR(LOGAND(bvrs1, UN(32, 0x7FFFFFFF)),
		LOGAND(LOGNOT(bvrs2), UN(32, 0x80000000))))

// DUP bvrs1 to avoid shared AST nodes.
DEFINE_F_LIFTER_BV_TO_FREG(fsgnjx_s, DECODE_F_FD_BV_BV,
	LOGOR(LOGAND(DUP(bvrs1), UN(32, 0x7FFFFFFF)),
		LOGAND(LOGXOR(bvrs1, bvrs2), UN(32, 0x80000000))))

// -----------------------------------------------------------------------
// Min / Max
//
// IEEE 754-201x minimumNumber / maximumNumber (RISC-V F spec >= 2.2):
//   - signaling NaN operand  → raise NV, return canonical qNaN
//   - exactly one quiet NaN  → return the non-NaN operand
//   - both quiet NaN         → return canonical qNaN
//   - otherwise              → normal min / max
//
// Float32 layout: sign[31], exponent[30:23], mantissa[22:0], quiet[22].
// A value is sNaN iff exponent==0xFF && mantissa!=0 && quiet_bit==0.
// cond(a, b): FLE for fmin_s, FGE for fmax_s.
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
			/* raw 32-bit bitvector of frs1, needed for bit-level sNaN inspection */ \
			SETL("_bva", RISCV_GET_FREG_F_BV(frs1_reg)), \
			/* raw 32-bit bitvector of frs2, needed for bit-level sNaN inspection */ \
			SETL("_bvb", RISCV_GET_FREG_F_BV(frs2_reg)), \
			/* ordinary float32 interpetation of operand 1 for IL float comparisons */ \
			SETL("_a", FLOATV32(VARL("_bva"))), \
			/* ordinary float32 interpetation of operand 2 for IL float comparisons */ \
			SETL("_b", FLOATV32(VARL("_bvb"))), \
			/* true if operand 1 is any NaN (exponent==0xFF and mantissa!=0) */ \
			SETL("_na", AND(EQ(EXTRACT32(VARL("_bva"), UN(32, 23), UN(32, 8)), UN(8, 0xFF)), \
				NON_ZERO(EXTRACT32(VARL("_bva"), UN(32, 0), UN(32, 23))))), \
			/* true if operand 2 is any NaN */ \
			SETL("_nb", AND(EQ(EXTRACT32(VARL("_bvb"), UN(32, 23), UN(32, 8)), UN(8, 0xFF)), \
				NON_ZERO(EXTRACT32(VARL("_bvb"), UN(32, 0), UN(32, 23))))), \
			/* true if operand 1 is a signaling NaN (NaN with quiet bit[22]==0) */ \
			SETL("_sa", AND(VARL("_na"), INV(NON_ZERO(EXTRACT32(VARL("_bva"), UN(32, 22), UN(32, 1)))))), \
			/* true if operand 2 is a signaling NaN */ \
			SETL("_sb", AND(VARL("_nb"), INV(NON_ZERO(EXTRACT32(VARL("_bvb"), UN(32, 22), UN(32, 1)))))), \
			/* raise NV (invalid operation, bit 4) in fcsr when either operand is sNaN */ \
			SETG("fcsr", LOGOR(VARG("fcsr"), ITE(OR(VARL("_sa"), VARL("_sb")), UN(64, 0x10), UN(64, 0)))), \
			RISCV_SET_FREG_F(frd, \
				ITE(OR(VARL("_sa"), VARL("_sb")), IL_FQNAN(RZ_FLOAT_IEEE754_BIN_32), \
					ITE(VARL("_na"), VARL("_b"), \
						ITE(VARL("_nb"), VARL("_a"), \
							ITE(cond(VARL("_a"), VARL("_b")), VARL("_a"), VARL("_b"))))))); \
	}

DEFINE_LIFTER_MINMAX(fmin_s, FLE)
DEFINE_LIFTER_MINMAX(fmax_s, FGE)

// -----------------------------------------------------------------------
// Comparison  (result in integer register)
// -----------------------------------------------------------------------
DEFINE_LIFTER(feq_s, DECODE_F_RD_FS_FS, BOOL_TO_BV(FEQ(frs1, frs2), analysis->bits))
DEFINE_LIFTER(flt_s, DECODE_F_RD_FS_FS, BOOL_TO_BV(FLT(frs1, frs2), analysis->bits))
DEFINE_LIFTER(fle_s, DECODE_F_RD_FS_FS, BOOL_TO_BV(FLE(frs1, frs2), analysis->bits))

// -----------------------------------------------------------------------
// F Extension: fclass.s
//
// Classifies the float32 value in fs1 into one of 10 categories, placing
// a one-hot 10-bit mask into rd (zero-extended to XLEN).
//
//   bit 0  -infinity
//   bit 1  negative normal
//   bit 2  negative subnormal
//   bit 3  -0
//   bit 4  +0
//   bit 5  positive subnormal
//   bit 6  positive normal
//   bit 7  +infinity
//   bit 8  signaling NaN
//   bit 9  quiet NaN
//
// Float32 layout: sign[31], exponent[30:23], mantissa[22:0], quiet[22].
// -----------------------------------------------------------------------
#define FBIT_S(n, cond) SHIFTL0(BOOL_TO_BV(cond, xlen), UN(xlen, (n)))

static RzILOpEffect *rz_riscv_lift_fclass_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	DECODE_F_RD_FS_BV(analysis, insn);
	int xlen = analysis->bits;
	return SEQN(14,
		SETL("_b", bvrs1),
		SETL("_ex", EXTRACT32(VARL("_b"), UN(32, 23), UN(32, 8))),
		SETL("_mn", EXTRACT32(VARL("_b"), UN(32, 0), UN(32, 23))),
		SETL("_sg", NON_ZERO(EXTRACT32(VARL("_b"), UN(32, 31), UN(32, 1)))),
		SETL("_qt", NON_ZERO(EXTRACT32(VARL("_b"), UN(32, 22), UN(32, 1)))),
		SETL("_xff", EQ(VARL("_ex"), UN(8, 0xFF))),
		SETL("_xz", IS_ZERO(VARL("_ex"))),
		SETL("_mz", IS_ZERO(VARL("_mn"))),
		SETL("_na", AND(VARL("_xff"), INV(VARL("_mz")))),
		SETL("_in", AND(VARL("_xff"), VARL("_mz"))),
		SETL("_su", AND(VARL("_xz"), INV(VARL("_mz")))),
		SETL("_ze", AND(VARL("_xz"), VARL("_mz"))),
		SETL("_no", AND(INV(VARL("_xz")), INV(VARL("_xff")))),
		RISCV_SET_REG(rd,
			LOGOR(FBIT_S(0, AND(VARL("_sg"), VARL("_in"))),
			LOGOR(FBIT_S(1, AND(VARL("_sg"), VARL("_no"))),
			LOGOR(FBIT_S(2, AND(VARL("_sg"), VARL("_su"))),
			LOGOR(FBIT_S(3, AND(VARL("_sg"), VARL("_ze"))),
			LOGOR(FBIT_S(4, AND(INV(VARL("_sg")), VARL("_ze"))),
			LOGOR(FBIT_S(5, AND(INV(VARL("_sg")), VARL("_su"))),
			LOGOR(FBIT_S(6, AND(INV(VARL("_sg")), VARL("_no"))),
			LOGOR(FBIT_S(7, AND(INV(VARL("_sg")), VARL("_in"))),
			LOGOR(FBIT_S(8, AND(VARL("_na"), INV(VARL("_qt")))),
			      FBIT_S(9, AND(VARL("_na"), VARL("_qt"))))))))))))));
}
#undef FBIT_S

// -----------------------------------------------------------------------
// F Extension: Conversions  float32 → integer
//
// RISC-V: in RV64 the 32-bit integer results of fcvt.w.s / fcvt.wu.s are
// sign-extended to 64 bits regardless of signedness (per spec §11.4).
// -----------------------------------------------------------------------

// fcvt.w.s rd, fs1  — float32 → signed int32, sign-extended to XLEN
DEFINE_LIFTER(fcvt_w_s, DECODE_F_RD_FS,
	SIGNED(analysis->bits, F2SINT(32, F_RM, frs1)))

// fcvt.wu.s rd, fs1  — float32 → unsigned int32, sign-extended to XLEN
DEFINE_LIFTER(fcvt_wu_s, DECODE_F_RD_FS,
	SIGNED(analysis->bits, F2INT(32, F_RM, frs1)))

// fcvt.l.s rd, fs1  — float32 → signed int64 (RV64F only)
static RzILOpEffect *rz_riscv_lift_fcvt_l_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	REQUIRE_64_BIT(analysis);
	DECODE_F_RD_FS(analysis, insn);
	return RISCV_SET_REG(rd, F2SINT(64, F_RM, frs1));
}

// fcvt.lu.s rd, fs1  — float32 → unsigned int64 (RV64F only)
static RzILOpEffect *rz_riscv_lift_fcvt_lu_s(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	REQUIRE_64_BIT(analysis);
	DECODE_F_RD_FS(analysis, insn);
	return RISCV_SET_REG(rd, F2INT(64, F_RM, frs1));
}

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
static RzILOpEffect *rz_riscv_lift_fcvt_s_l(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	REQUIRE_64_BIT(analysis);
	DECODE_F_FD_RS(analysis, insn);
	return RISCV_SET_FREG_F(frd, SINT2F(RZ_FLOAT_IEEE754_BIN_32, F_RM, rs1));
}

// fcvt.s.lu fd, rs1  — unsigned int64 to float32 (RV64F only)
static RzILOpEffect *rz_riscv_lift_fcvt_s_lu(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	REQUIRE_64_BIT(analysis);
	DECODE_F_FD_RS(analysis, insn);
	return RISCV_SET_FREG_F(frd, INT2F(RZ_FLOAT_IEEE754_BIN_32, F_RM, rs1));
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

#endif // RISCV_IL_F_H
