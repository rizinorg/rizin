#ifndef RISCV_IL_FD_COMMON_H
#define RISCV_IL_FD_COMMON_H

/**
 * This file provides width-agnostic common definitions for floating-point instructions in RISC-V.
 * 
 * The file MUST be specialized by defining ALL the following macros BEFORE including it:
 * - RISCV_FD_REG_SETTER: set a floating-point register.
 * - RISCV_FD_REG_GETTER: get a floating-point register.
 * - RISCV_FD_REG_SETTER_BV: set a floating-point register to a raw bitvector.
 * - RISCV_FD_REG_GETTER_BV: get a floating-point register as a raw bitvector.
 * - RISCV_FD_GET_MANTISSA: get the mantissa of a floating-point number.
 * - RISCV_FD_GET_EXPONENT: get the exponent of a floating-point number.
 * - RISCV_FD_GET_SIGN: get the sign bit of a floating-point number.
 * - RISCV_FD_IS_NAN: check if a floating-point number is NaN.
 * - RISCV_FD_IS_S_NAN: check if a floating-point number is a signaling NaN.
 * - RISCV_FD_IS_MAX_EXP: check if a floating-point number has the maximum exponent.
 * - RISCV_FD_IS_EXP_OVERFLOW_INT: check if a floating-point number has an exponent that would overflow an integer.
 * - RISCV_FD_IS_EXP_OVERFLOW_UINT: check if a floating-point number has an exponent that would overflow an unsigned integer.
 * - RISCV_FD_IS_EXP_OVERFLOW_LONG: check if a floating-point number has an exponent that would overflow a long integer.
 * - RISCV_FD_IS_EXP_OVERFLOW_ULONG: check if a floating-point number has an exponent that would overflow an unsigned long integer.

 * Once this low-level API is fixed, the instruction definitions are generic on FP width.

 * After inclusion, all the DEF_* macros defined by this file must be called with a concrete name and sometimes
 * also with a bit width in order to instantiate the actual instruction definition.
*/

#include "riscv_il_base.h"

#include <stddef.h>

#include "riscv_il_float_reg_names.h"

#include <rz_il/rz_il_opbuilder_begin.h>
// ------------------------------------------- API -------------------------------------------
// -------------------------------------- Register API --------------------------------------
#ifndef RISCV_FD_REG_SETTER
#error "RISCV_FD_REG_SETTER must be defined before including this file"
#endif // RISCV_FD_REG_SETTER

#ifndef RISCV_FD_REG_GETTER
#error "RISCV_FD_REG_GETTER must be defined before including this file"
#endif // RISCV_FD_REG_GETTER

#ifndef RISCV_FD_REG_SETTER_BV
#error "RISCV_FD_REG_SETTER_BV must be defined before including this file"
#endif // RISCV_FD_REG_SETTER_BV

#ifndef RISCV_FD_REG_GETTER_BV
#error "RISCV_FD_REG_GETTER_BV must be defined before including this file"
#endif // RISCV_FD_REG_GETTER_BV

// -------------------------------------- Destructuring API -----------------------------------
#ifndef RISCV_FD_GET_MANTISSA
#error "RISCV_FD_GET_MANTISSA must be defined before including this file"
#endif // RISCV_FD_GET_MANTISSA

#ifndef RISCV_FD_GET_EXPONENT
#error "RISCV_FD_GET_EXPONENT must be defined before including this file"
#endif // RISCV_FD_GET_EXPONENT

#ifndef RISCV_FD_GET_SIGN
#error "RISCV_FD_GET_SIGN must be defined before including this file"
#endif // RISCV_FD_GET_SIGN

// -------------------------------------- NAN Query API --------------------------------------
#ifndef RISCV_FD_IS_NAN
#error "RISCV_FD_IS_NAN must be defined before including this file"
#endif // RISCV_FD_IS_NAN

#ifndef RISCV_FD_IS_S_NAN
#error "RISCV_FD_IS_S_NAN must be defined before including this file"
#endif // RISCV_FD_IS_S_NAN

// -------------------------------------- Exponent Query API --------------------------------------
#ifndef RISCV_FD_IS_MAX_EXP
#error "RISCV_FD_IS_MAX_EXP must be defined before including this file"
#endif // RISCV_FD_IS_MAX_EXP

#ifndef RISCV_FD_IS_EXP_OVERFLOW_INT
#error "RISCV_FD_IS_EXP_OVERFLOW_INT must be defined before including this file"
#endif // RISCV_FD_IS_EXP_OVERFLOW_INT

#ifndef RISCV_FD_IS_EXP_OVERFLOW_UINT
#error "RISCV_FD_IS_EXP_OVERFLOW_UINT must be defined before including this file"
#endif // RISCV_FD_IS_EXP_OVERFLOW_UINT

#ifndef RISCV_FD_IS_EXP_OVERFLOW_LONG
#error "RISCV_FD_IS_EXP_OVERFLOW_LONG must be defined before including this file"
#endif // RISCV_FD_IS_EXP_OVERFLOW_LONG

#ifndef RISCV_FD_IS_EXP_OVERFLOW_ULONG
#error "RISCV_FD_IS_EXP_OVERFLOW_ULONG must be defined before including this file"
#endif // RISCV_FD_IS_EXP_OVERFLOW_ULONG

// --------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------

// Map Capstone's RISC-V static rounding mode to RzFloat's rounding mode.
// RISCV_RM_DYN must never be passed here; use RISCV_FD_FRM_DISPATCH instead.
static inline RzFloatRMode riscv_rm_to_rz(riscv_rounding_mode rm) {
	switch (rm) {
	case RISCV_RM_RNE: return RZ_FLOAT_RMODE_RNE;
	case RISCV_RM_RTZ: return RZ_FLOAT_RMODE_RTZ;
	case RISCV_RM_RDN: return RZ_FLOAT_RMODE_RTN;
	case RISCV_RM_RUP: return RZ_FLOAT_RMODE_RTP;
	case RISCV_RM_RMM: return RZ_FLOAT_RMODE_RNA;
	default: return RZ_FLOAT_RMODE_RNE;
	}
}

// FD_ROUNDING_MODE: static rounding mode for the current instruction (never DYN).
#define FD_ROUNDING_MODE riscv_rm_to_rz(insn->detail->riscv.rounding_mode)

#define RISCV_FD_EXC(riscv_bit, rz_exc) \
	ITE(FEXCEPT(rz_exc, VARL("_r")), UN(64, riscv_bit), UN(64, 0)) // CSR is always 64-bit wide in QEMU

#define RISCV_FD_UPDATE_FFLAGS() \
	SETG("fcsr", LOGOR(VARG("fcsr"), \
		LOGOR(RISCV_FD_EXC(0x01, RZ_FLOAT_E_INEXACT), \
		LOGOR(RISCV_FD_EXC(0x02, RZ_FLOAT_E_UNDERFLOW), \
		LOGOR(RISCV_FD_EXC(0x04, RZ_FLOAT_E_OVERFLOW), \
		LOGOR(RISCV_FD_EXC(0x08, RZ_FLOAT_E_DIV_ZERO), \
		      RISCV_FD_EXC(0x10, RZ_FLOAT_E_INVALID_OP)))))))

#define RISCV_SET_FRM() \
	SETL("_frm", EXTRACT64(VARG("fcsr"), UN(64, 5), UN(32, 3)))

// -----------------------------------------------------------------------
// Dynamic rounding mode dispatch
//
// When an instruction encodes rm=111 (DYN), the actual rounding mode is
// read at runtime from fcsr.frm (bits [7:5]).  Because RzIL float ops
// take a compile-time RzFloatRMode enum, we enumerate all five valid frm
// values in an ITE tree so the right mode is chosen at emulation time.
#define RISCV_FD_FRM_DISPATCH(fn, ...) \
	ITE(EQ(VARL("_frm"), UN(64, 0)), fn(RZ_FLOAT_RMODE_RNE, __VA_ARGS__), \
	ITE(EQ(VARL("_frm"), UN(64, 1)), fn(RZ_FLOAT_RMODE_RTZ, __VA_ARGS__), \
	ITE(EQ(VARL("_frm"), UN(64, 2)), fn(RZ_FLOAT_RMODE_RTN, __VA_ARGS__), \
	ITE(EQ(VARL("_frm"), UN(64, 3)), fn(RZ_FLOAT_RMODE_RTP, __VA_ARGS__), \
	                                  fn(RZ_FLOAT_RMODE_RNA, __VA_ARGS__)))))

#define DEFINE_FD_LIFTER(name, decoder, fl_result) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		return SEQ3( \
			SETL("_r", fl_result), \
			RISCV_FD_REG_SETTER(frd, VARL("_r")), \
			RISCV_FD_UPDATE_FFLAGS()); \
	}

#define DEFINE_FD_LIFTER_BV_TO_FREG(name, decoder, bv_result) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		return RISCV_FD_REG_SETTER_BV(frd, bv_result); \
	}

#define DEFINE_FD_LIFTER_UNARY(name, decoder, fn) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		if (insn->detail->riscv.rounding_mode == RISCV_RM_DYN) { \
			return SEQN(5, \
				RISCV_SET_FRM(), \
				SETL("_x", frs1), \
				SETL("_r", RISCV_FD_FRM_DISPATCH(fn, VARL("_x"))), \
				RISCV_FD_REG_SETTER(frd, VARL("_r")), \
				RISCV_FD_UPDATE_FFLAGS()); \
		} \
		return SEQ3( \
			SETL("_r", fn(FD_ROUNDING_MODE, frs1)), \
			RISCV_FD_REG_SETTER(frd, VARL("_r")), \
			RISCV_FD_UPDATE_FFLAGS()); \
	}

// Binary float op (fadd.s, fsub.s, fmul.s, fdiv.s) with DYN support.
#define DEFINE_FD_LIFTER_BINARY(name, decoder, fn) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		if (insn->detail->riscv.rounding_mode == RISCV_RM_DYN) { \
			return SEQN(6, \
				RISCV_SET_FRM(), \
				SETL("_x", frs1), \
				SETL("_y", frs2), \
				SETL("_r", RISCV_FD_FRM_DISPATCH(fn, VARL("_x"), VARL("_y"))), \
				RISCV_FD_REG_SETTER(frd, VARL("_r")), \
				RISCV_FD_UPDATE_FFLAGS()); \
		} \
		return SEQ3( \
			SETL("_r", fn(FD_ROUNDING_MODE, frs1, frs2)), \
			RISCV_FD_REG_SETTER(frd, VARL("_r")), \
			RISCV_FD_UPDATE_FFLAGS()); \
	}

// Fused multiply-add variants with DYN support.
// a, b, c are the three float operand IL expressions (may include FNEG).
// negate_result: pass true for fnmadd (result = -(a*b+c)).
// Exception flags are always checked on the un-negated FMAD result.
#define DEFINE_FD_LIFTER_MAD(name, decoder, a, b, c, negate_result) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		if (insn->detail->riscv.rounding_mode == RISCV_RM_DYN) { \
			return SEQN(7, \
				RISCV_SET_FRM(), \
				SETL("_x", a), \
				SETL("_y", b), \
				SETL("_z", c), \
				SETL("_r", RISCV_FD_FRM_DISPATCH(FMAD, VARL("_x"), VARL("_y"), VARL("_z"))), \
				RISCV_FD_REG_SETTER(frd, (negate_result) ? FNEG(VARL("_r")) : VARL("_r")), \
				RISCV_FD_UPDATE_FFLAGS()); \
		} \
		return SEQ3( \
			SETL("_r", FMAD(FD_ROUNDING_MODE, a, b, c)), \
			RISCV_FD_REG_SETTER(frd, (negate_result) ? FNEG(VARL("_r")) : VARL("_r")), \
			RISCV_FD_UPDATE_FFLAGS()); \
	}

#define DECODE_FD_FD_FS_FS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	REQUIRE_OP(2, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_FD_REG_GETTER(insn->detail->riscv.operands[1].reg); \
	RzILOpFloat *frs2 = RISCV_FD_REG_GETTER(insn->detail->riscv.operands[2].reg);

#define DECODE_FD_FD_BV_BV(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	REQUIRE_OP(2, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *bvrs1 = RISCV_FD_REG_GETTER_BV(insn->detail->riscv.operands[1].reg); \
	RzILOpBitVector *bvrs2 = RISCV_FD_REG_GETTER_BV(insn->detail->riscv.operands[2].reg);

#define DECODE_FD_FD_FS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_FD_REG_GETTER(insn->detail->riscv.operands[1].reg);

#define DECODE_FD_RD_FS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_FD_REG_GETTER(insn->detail->riscv.operands[1].reg);

#define DECODE_FD_RD_FS_BV(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *bvrs1 = RISCV_FD_REG_GETTER_BV(insn->detail->riscv.operands[1].reg);

#define DECODE_FD_FD_MEM(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_MEM); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs = RISCV_GET_REG(insn->detail->riscv.operands[1].mem.base); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[1].mem.disp);

#define DECODE_FD_FS_MEM(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_MEM); \
	RzILOpBitVector *bvrs1 = RISCV_FD_REG_GETTER_BV(insn->detail->riscv.operands[0].reg); \
	RzILOpBitVector *rs = RISCV_GET_REG(insn->detail->riscv.operands[1].mem.base); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[1].mem.disp);

#define DECODE_FD_FD_FS_FS_FS(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	REQUIRE_OP(2, RISCV_OP_REG); \
	REQUIRE_OP(3, RISCV_OP_REG); \
	uint32_t frd = insn->detail->riscv.operands[0].reg; \
	RzILOpFloat *frs1 = RISCV_FD_REG_GETTER(insn->detail->riscv.operands[1].reg); \
	RzILOpFloat *frs2 = RISCV_FD_REG_GETTER(insn->detail->riscv.operands[2].reg); \
	RzILOpFloat *frs3 = RISCV_FD_REG_GETTER(insn->detail->riscv.operands[3].reg);

// -----------------------------------------------------------------------
// Memory
// -----------------------------------------------------------------------
// load size-bit float from memory
#define DEF_LOAD(name, size) DEFINE_FD_LIFTER_BV_TO_FREG(name, DECODE_FD_FD_MEM, LOADW(size, ADD(rs, imm)))

// store float to memory
#define DEF_STORE(name) DEFINE_LIFTER_WITH_EFFECT(name, DECODE_FD_FS_MEM, STOREW(ADD(rs, imm), bvrs1))

// -----------------------------------------------------------------------
// Arithmetic
// -----------------------------------------------------------------------
#define DEF_ADD(name) DEFINE_FD_LIFTER_BINARY(name, DECODE_FD_FD_FS_FS, FADD)
#define DEF_SUB(name) DEFINE_FD_LIFTER_BINARY(name, DECODE_FD_FD_FS_FS, FSUB)
#define DEF_MUL(name) DEFINE_FD_LIFTER_BINARY(name, DECODE_FD_FD_FS_FS, FMUL)
#define DEF_DIV(name) DEFINE_FD_LIFTER_BINARY(name, DECODE_FD_FD_FS_FS, FDIV)
#define DEF_SQRT(name) DEFINE_FD_LIFTER_UNARY(name, DECODE_FD_FD_FS, FSQRT)

// -----------------------------------------------------------------------
// Fused Multiply-Add
//
//   fmadd.s:  fd =  (rs1 × rs2) + rs3
//   fmsub.s:  fd =  (rs1 × rs2) - rs3
//   fnmadd.s: fd = -(rs1 × rs2) - rs3
//   fnmsub.s: fd = -(rs1 × rs2) + rs3
// -----------------------------------------------------------------------
#define DEF_FMADD(name) DEFINE_FD_LIFTER_MAD(name,  DECODE_FD_FD_FS_FS_FS, frs1,        frs2, frs3,        false)
#define DEF_FMSUB(name) DEFINE_FD_LIFTER_MAD(name,  DECODE_FD_FD_FS_FS_FS, frs1,        frs2, FNEG(frs3),  false)
#define DEF_FNMADD(name) DEFINE_FD_LIFTER_MAD(name, DECODE_FD_FD_FS_FS_FS, frs1,        frs2, frs3,        true)
#define DEF_FNMSUB(name) DEFINE_FD_LIFTER_MAD(name, DECODE_FD_FD_FS_FS_FS, FNEG(frs1),  frs2, frs3,        false)

// -----------------------------------------------------------------------
// Sign Injection (bit-level, no rounding)
//
//   fsgnj.s:  fd = |rs1| with sign of rs2
//   fsgnjn.s: fd = |rs1| with negated sign of rs2
//   fsgnjx.s: fd = |rs1| with sign = sign(rs1) XOR sign(rs2)
//
// Bit 31 of float32 is the sign bit.
// IMPLEMENTATION NOTE: The result is simply the OR combination of 
//      (1) All bits but the sign from rs1 (i.e. AND with 0x7FFFFFFF....)
//      (2) The sign-bit from rs2 (i.e.AND with 0x80000000....)
// -----------------------------------------------------------------------
#define SIGN_MASK(size) UN(size, (1ULL << (size - 1)))
#define MAGNITUDE_MASK(size) UN(size, ~(1ULL << (size - 1)))
#define DEF_FSGNJ(name, size) DEFINE_FD_LIFTER_BV_TO_FREG(name, DECODE_FD_FD_BV_BV, \
	LOGOR(                                     \
        LOGAND(bvrs1, MAGNITUDE_MASK(size)),   \
		LOGAND(bvrs2, SIGN_MASK(size))         \
    ))

#define DEF_FSGNJN(name, size) DEFINE_FD_LIFTER_BV_TO_FREG(name, DECODE_FD_FD_BV_BV, \
	LOGOR(                                     \
        LOGAND(bvrs1, MAGNITUDE_MASK(size)),   \
		LOGAND(LOGNOT(bvrs2), SIGN_MASK(size)) \
    ))

// DUP bvrs1 to avoid shared AST nodes.
#define DEF_FSGNJX(name, size) DEFINE_FD_LIFTER_BV_TO_FREG(name, DECODE_FD_FD_BV_BV, \
	LOGOR(                                             \
        LOGAND(DUP(bvrs1), MAGNITUDE_MASK(size)),      \
		LOGAND(LOGXOR(bvrs1, bvrs2), SIGN_MASK(size))  \
    ))


// -----------------------------------------------------------------------
// Min / Max
// -----------------------------------------------------------------------
// IEEE 754-201x minimumNumber / maximumNumber (RISC-V F spec >= 2.2):
//   - signaling NaN operand  → raise NV, return canonical qNaN
//   - exactly one quiet NaN  → return the non-NaN operand
//   - both quiet NaN         → return canonical qNaN
//   - otherwise              → normal min / max
// -----------------------------------------------------------------------
#define DEFINE_LIFTER_MINMAX(name, cond, sz) \
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
			SETL("_bva", RISCV_FD_REG_GETTER_BV(frs1_reg)), \
			/* raw 32-bit bitvector of frs2, needed for bit-level sNaN inspection */ \
			SETL("_bvb", RISCV_FD_REG_GETTER_BV(frs2_reg)), \
			/* ordinary float interpetation for IL float comparisons */ \
			SETL("_a", FLOATV##sz(VARL("_bva"))), \
			/* ordinary float interpetation for IL float comparisons */ \
			SETL("_b", FLOATV##sz(VARL("_bvb"))), \
			/* true if operand 1 is any NaN (exponent==0xFF and mantissa!=0) */ \
			SETL("_na", RISCV_FD_IS_NAN(VARL("_bva"))), \
			/* true if operand 2 is any NaN */ \
			SETL("_nb", RISCV_FD_IS_NAN(VARL("_bvb"))), \
			/* true if operand 1 is a signaling NaN (NaN with quiet bit[22]==0) */ \
			SETL("_sa", RISCV_FD_IS_S_NAN(VARL("_bva"))), \
			/* true if operand 2 is a signaling NaN */ \
			SETL("_sb", RISCV_FD_IS_S_NAN(VARL("_bvb"))), \
			/* raise NV (invalid operation, bit 4) in fcsr when either operand is sNaN */ \
			SETG("fcsr", LOGOR(VARG("fcsr"), ITE(OR(VARL("_sa"), VARL("_sb")), UN(64, 0x10), UN(64, 0)))), \
			RISCV_FD_REG_SETTER(frd, \
				ITE(OR(VARL("_sa"), VARL("_sb")), IL_FQNAN(RZ_FLOAT_IEEE754_BIN_##sz), \
					ITE(VARL("_na"), VARL("_b"), \
						ITE(VARL("_nb"), VARL("_a"), \
							ITE(cond(VARL("_a"), VARL("_b")), VARL("_a"), VARL("_b"))))))); \
	}

#define DEF_FMIN(name, size) DEFINE_LIFTER_MINMAX(name, FLE, size)
#define DEF_FMAX(name, size) DEFINE_LIFTER_MINMAX(name, FGE, size)

// -----------------------------------------------------------------------
// Comparison  (result in integer register)
//
// flt.s / fle.s raise NV (bit 4 of fflags) when either operand is NaN.
// Float32 NaN: exponent[30:23] == 0xFF AND mantissa[22:0] != 0.
// -----------------------------------------------------------------------
#define DEFINE_FCMP_LIFTER(name, cmp_fn, sz) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		REQUIRE_OP(0, RISCV_OP_REG); \
		REQUIRE_OP(1, RISCV_OP_REG); \
		REQUIRE_OP(2, RISCV_OP_REG); \
		uint32_t rd = insn->detail->riscv.operands[0].reg; \
		uint32_t frs1_reg = insn->detail->riscv.operands[1].reg; \
		uint32_t frs2_reg = insn->detail->riscv.operands[2].reg; \
		return SEQN(8, \
			SETL("_bva", RISCV_FD_REG_GETTER_BV(frs1_reg)), \
			SETL("_bvb", RISCV_FD_REG_GETTER_BV(frs2_reg)), \
			SETL("_a", FLOATV##sz(VARL("_bva"))), \
			SETL("_b", FLOATV##sz(VARL("_bvb"))), \
			SETL("_na", RISCV_FD_IS_NAN(VARL("_bva"))), \
			SETL("_nb", RISCV_FD_IS_NAN(VARL("_bvb"))), \
			SETG("fcsr", LOGOR(VARG("fcsr"), ITE(OR(VARL("_na"), VARL("_nb")), UN(64, 0x10), UN(64, 0)))), \
			RISCV_SET_REG(rd, BOOL_TO_BV(cmp_fn(VARL("_a"), VARL("_b")), analysis->bits))); \
	}

#define DEF_FLT(name, size) DEFINE_FCMP_LIFTER(name, FLT, size)
#define DEF_FLE(name, size) DEFINE_FCMP_LIFTER(name, FLE, size)

// feq*: quiet NaN gives 0 result with no exception; signaling NaN gives 0 and raises NV.
#define DEF_FEQ(name, sz) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	REQUIRE_OP(2, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	uint32_t frs1_reg = insn->detail->riscv.operands[1].reg; \
	uint32_t frs2_reg = insn->detail->riscv.operands[2].reg; \
	return SEQN(8, \
		SETL("_bva", RISCV_FD_REG_GETTER_BV(frs1_reg)), \
		SETL("_bvb", RISCV_FD_REG_GETTER_BV(frs2_reg)), \
		SETL("_a", FLOATV##sz(VARL("_bva"))), \
		SETL("_b", FLOATV##sz(VARL("_bvb"))), \
		SETL("_sa", RISCV_FD_IS_S_NAN(VARL("_bva"))), \
		SETL("_sb", RISCV_FD_IS_S_NAN(VARL("_bvb"))), \
		SETG("fcsr", LOGOR(VARG("fcsr"), ITE(OR(VARL("_sa"), VARL("_sb")), UN(64, 0x10), UN(64, 0)))), \
		RISCV_SET_REG(rd, BOOL_TO_BV(FEQ(VARL("_a"), VARL("_b")), analysis->bits))); \
}

// -----------------------------------------------------------------------
// fclass*
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
// -----------------------------------------------------------------------
#define CLASSIFICATION_BIT(n, cond) SHIFTL0(BOOL_TO_BV(cond, xlen), UN(xlen, (n)))

#define DEF_FCLASS(name) static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
	DECODE_FD_RD_FS_BV(analysis, insn); \
	uint32_t xlen = analysis->bits; \
	return SEQN(13, \
		SETL("_b", bvrs1), \
		SETL("_ex", RISCV_FD_GET_EXPONENT(VARL("_b"))), \
		SETL("_mn", RISCV_FD_GET_MANTISSA(VARL("_b"))), \
		SETL("_sg", NON_ZERO(RISCV_FD_GET_SIGN(VARL("_b")))), \
		SETL("_xff", RISCV_FD_IS_MAX_EXP(VARL("_ex"))), \
		SETL("_xz", IS_ZERO(VARL("_ex"))), \
		SETL("_mz", IS_ZERO(VARL("_mn"))), \
		SETL("_na", AND(VARL("_xff"), INV(VARL("_mz")))), \
		SETL("_in", AND(VARL("_xff"), VARL("_mz"))), \
		SETL("_su", AND(VARL("_xz"), INV(VARL("_mz")))), \
		SETL("_ze", AND(VARL("_xz"), VARL("_mz"))), \
		SETL("_no", AND(INV(VARL("_xz")), INV(VARL("_xff")))), \
		RISCV_SET_REG(rd, \
			LOGOR(CLASSIFICATION_BIT(0, AND(VARL("_sg"), VARL("_in"))), \
			LOGOR(CLASSIFICATION_BIT(1, AND(VARL("_sg"), VARL("_no"))), \
			LOGOR(CLASSIFICATION_BIT(2, AND(VARL("_sg"), VARL("_su"))), \
			LOGOR(CLASSIFICATION_BIT(3, AND(VARL("_sg"), VARL("_ze"))), \
			LOGOR(CLASSIFICATION_BIT(4, AND(INV(VARL("_sg")), VARL("_ze"))), \
			LOGOR(CLASSIFICATION_BIT(5, AND(INV(VARL("_sg")), VARL("_su"))), \
			LOGOR(CLASSIFICATION_BIT(6, AND(INV(VARL("_sg")), VARL("_no"))), \
			LOGOR(CLASSIFICATION_BIT(7, AND(INV(VARL("_sg")), VARL("_in"))), \
			LOGOR(CLASSIFICATION_BIT(8, RISCV_FD_IS_S_NAN(VARL("_b"))), \
			      CLASSIFICATION_BIT(9, AND(VARL("_na"), INV(RISCV_FD_IS_S_NAN(VARL("_b")))))))))))))))); \
}

// -----------------------------------------------------------------------
// F Extension: Conversions  float32 → integer
//
// NORE: in RV64 the 32-bit integer results of fcvt.w.s / fcvt.wu.s are
// sign-extended to 64 bits regardless of signedness (per spec §11.4).
// -----------------------------------------------------------------------

// fcvt.w* rd, fs1  — float32 → signed int32, sign-extended to XLEN
// NV: biased exponent >= BIG THRESHOLD 
// 		32-bit F: 158 (covers NaN, ±∞, and |value| >= 2^31).
// 		64-bit F: 1054 (covers NaN, ±∞, and |value| >= 2^31).
// NX: source has a fractional part (detected via FROUND); mutually exclusive with NV.
// Saturation (RISC-V spec §11.4):
//   NaN (any) or positive overflow → INT32_MAX (0x7FFFFFFF)
//   -Inf or negative overflow      → INT32_MIN (0x80000000)
#define DEF_FCVT_W(name, sz) static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
	DECODE_FD_RD_FS_BV(analysis, insn); \
	return SEQN(8, \
		SETL("_bv", bvrs1), \
		SETL("_ex", RISCV_FD_GET_EXPONENT(VARL("_bv"))), \
		SETL("_mn", RISCV_FD_GET_MANTISSA(VARL("_bv"))), \
		SETL("_sg", NON_ZERO(RISCV_FD_GET_SIGN(VARL("_bv")))), \
		SETL("_f", FLOATV##sz(VARL("_bv"))), \
		SETL("_nv", RISCV_FD_IS_EXP_OVERFLOW_INT(VARL("_ex"))), \
		RISCV_SET_REG(rd, SIGNED(analysis->bits, \
			ITE(VARL("_nv"), \
				ITE(AND(VARL("_sg"), INV(AND(RISCV_FD_IS_MAX_EXP(VARL("_ex")), NON_ZERO(VARL("_mn"))))), \
					UN(32, 0x80000000), \
					UN(32, 0x7FFFFFFF)), \
				F2SINT(32, FD_ROUNDING_MODE, VARL("_f"))))), \
		SETG("fcsr", LOGOR(VARG("fcsr"), \
			LOGOR( \
				ITE(VARL("_nv"), UN(64, 0x10), UN(64, 0)), \
				ITE(AND(INV(VARL("_nv")), FEXCEPT(RZ_FLOAT_E_INEXACT, FROUND(FD_ROUNDING_MODE, VARL("_f")))), \
					UN(64, 0x01), UN(64, 0)))))); \
}

// fcvt.wu.s rd, fs1  — float32 → unsigned int32, sign-extended to XLEN
// NV: biased exponent >= 159 (|value| >= 2^32) OR negative non-zero value.
// NX: source has a fractional part AND not NV.  The NV guard prevents double-flagging
// negative fractional values such as -0.5.
// Saturation (RISC-V spec §11.4):
//   NaN (any) or positive overflow → UINT32_MAX (0xFFFFFFFF)
//   negative non-zero (incl. −Inf) → 0x00000000
#define DEF_FCVT_WU(name, sz) static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
	DECODE_FD_RD_FS_BV(analysis, insn); \
	return SEQN(8, \
		SETL("_bv", bvrs1), \
		SETL("_ex", RISCV_FD_GET_EXPONENT(VARL("_bv"))), \
		SETL("_mn", RISCV_FD_GET_MANTISSA(VARL("_bv"))), \
		SETL("_sg", NON_ZERO(RISCV_FD_GET_SIGN(VARL("_bv")))), \
		SETL("_f", FLOATV##sz(VARL("_bv"))), \
		SETL("_nv", \
			OR(RISCV_FD_IS_EXP_OVERFLOW_UINT(VARL("_ex")), \
				AND(VARL("_sg"), OR(NON_ZERO(VARL("_ex")), NON_ZERO(VARL("_mn")))))), \
		RISCV_SET_REG(rd, SIGNED(analysis->bits, \
			ITE(VARL("_nv"), \
				ITE(OR(AND(RISCV_FD_IS_MAX_EXP(VARL("_ex")), NON_ZERO(VARL("_mn"))), INV(VARL("_sg"))), \
					UN(32, 0xFFFFFFFF), \
					UN(32, 0x00000000)), \
				F2INT(32, FD_ROUNDING_MODE, VARL("_f"))))), \
		SETG("fcsr", LOGOR(VARG("fcsr"), \
			LOGOR( \
				ITE(VARL("_nv"), UN(64, 0x10), UN(64, 0)), \
				ITE(AND(INV(VARL("_nv")), FEXCEPT(RZ_FLOAT_E_INEXACT, FROUND(FD_ROUNDING_MODE, VARL("_f")))), \
					UN(64, 0x01), UN(64, 0)))))); \
}

// fcvt.l.s rd, fs1  — float32 → signed int64 (RV64F only)
// NV: biased exponent >= 190 (= 127+63; covers NaN, ±∞, and |value| >= 2^63).
// NX: source has a fractional part (detected via FROUND); mutually exclusive with NV
// since E >= 190 > 149 (no fractional bits in the float representation at that range).
// Saturation (RISC-V spec §11.4):
//   NaN (any) or positive overflow → INT64_MAX (0x7FFFFFFFFFFFFFFF)
//   -Inf or negative overflow      → INT64_MIN (0x8000000000000000)
#define DEF_FCVT_L(name, sz) static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
	REQUIRE_64_BIT(analysis); \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	uint32_t fsrc = insn->detail->riscv.operands[1].reg; \
	return SEQN(8, \
		SETL("_bv", RISCV_FD_REG_GETTER_BV(fsrc)), \
		SETL("_ex", RISCV_FD_GET_EXPONENT(VARL("_bv"))), \
		SETL("_mn", RISCV_FD_GET_MANTISSA(VARL("_bv"))), \
		SETL("_sg", NON_ZERO(RISCV_FD_GET_SIGN(VARL("_bv")))), \
		SETL("_f", FLOATV##sz(VARL("_bv"))), \
		SETL("_nv", RISCV_FD_IS_EXP_OVERFLOW_LONG(VARL("_ex"))), \
		RISCV_SET_REG(rd, \
			ITE(VARL("_nv"), \
				ITE(AND(VARL("_sg"), INV(AND(RISCV_FD_IS_MAX_EXP(VARL("_ex")), NON_ZERO(VARL("_mn"))))), \
					UN(64, 0x8000000000000000ULL), \
					UN(64, 0x7FFFFFFFFFFFFFFFULL)), \
				F2SINT(64, FD_ROUNDING_MODE, VARL("_f")))), \
		SETG("fcsr", LOGOR(VARG("fcsr"), \
			LOGOR( \
				ITE(VARL("_nv"), UN(64, 0x10), UN(64, 0)), \
				ITE(AND(INV(VARL("_nv")), FEXCEPT(RZ_FLOAT_E_INEXACT, FROUND(FD_ROUNDING_MODE, VARL("_f")))), \
					UN(64, 0x01), UN(64, 0)))))); \
}

// fcvt.lu.s rd, fs1  — float32 → unsigned int64 (RV64F only)
// NV: biased exponent >= 191 (= 127+64) OR negative non-zero value.
// NX: source has a fractional part AND not NV (guard prevents double-flagging
// negative fractional values such as -0.5).
// Saturation (RISC-V spec §11.4):
//   NaN (any) or positive overflow → UINT64_MAX (0xFFFFFFFFFFFFFFFF)
//   negative non-zero (incl. −Inf) → 0x0000000000000000
#define DEF_FCVT_LU(name, sz) static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
	REQUIRE_64_BIT(analysis); \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	uint32_t fsrc = insn->detail->riscv.operands[1].reg; \
	return SEQN(8, \
		SETL("_bv", RISCV_FD_REG_GETTER_BV(fsrc)), \
		SETL("_ex", RISCV_FD_GET_EXPONENT(VARL("_bv"))), \
		SETL("_mn", RISCV_FD_GET_MANTISSA(VARL("_bv"))), \
		SETL("_sg", NON_ZERO(RISCV_FD_GET_SIGN(VARL("_bv")))), \
		SETL("_f", FLOATV##sz(VARL("_bv"))), \
		SETL("_nv", \
			OR(RISCV_FD_IS_EXP_OVERFLOW_ULONG(VARL("_ex")), \
				AND(VARL("_sg"), OR(NON_ZERO(VARL("_ex")), NON_ZERO(VARL("_mn")))))), \
		RISCV_SET_REG(rd, \
			ITE(VARL("_nv"), \
				ITE(OR(AND(RISCV_FD_IS_MAX_EXP(VARL("_ex")), NON_ZERO(VARL("_mn"))), INV(VARL("_sg"))), \
					UN(64, 0xFFFFFFFFFFFFFFFFULL), \
					UN(64, 0x0000000000000000ULL)), \
				F2INT(64, FD_ROUNDING_MODE, VARL("_f")))), \
		SETG("fcsr", LOGOR(VARG("fcsr"), \
			LOGOR( \
				ITE(VARL("_nv"), UN(64, 0x10), UN(64, 0)), \
				ITE(AND(INV(VARL("_nv")), FEXCEPT(RZ_FLOAT_E_INEXACT, FROUND(FD_ROUNDING_MODE, VARL("_f")))), \
					UN(64, 0x01), UN(64, 0)))))); \
}

#include <rz_il/rz_il_opbuilder_end.h>

#endif // RISCV_IL_FD_COMMON_H