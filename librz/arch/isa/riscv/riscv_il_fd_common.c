// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "analysis_private.h"
#include "riscv_il_base.h"
#include "riscv_il_fd_common.h"
#include "riscv_il_float_reg_names.h"
#include "rz_il/rz_il_opcodes.h"

#include <rz_il/rz_il_opbuilder_begin.h>

typedef enum {
	FD_BINARY_ADD,
	FD_BINARY_SUB,
	FD_BINARY_MUL,
	FD_BINARY_DIV,
} FDBinaryOperation;

typedef enum {
	FD_MAD_ADD,
	FD_MAD_SUB,
	FD_MAD_NEGATED_ADD,
	FD_MAD_NEGATED_SUB,
} FDMadOperation;

typedef enum {
	FD_SIGN_COPY,
	FD_SIGN_NEGATE,
	FD_SIGN_XOR,
} FDSignOperation;

typedef enum {
	FD_COMPARE_EQ,
	FD_COMPARE_LT,
	FD_COMPARE_LE,
} FDCompareOperation;

typedef enum {
	FD_INT32_SIGNED,
	FD_INT32_UNSIGNED,
	FD_INT64_SIGNED,
	FD_INT64_UNSIGNED,
} FDIntegerSource;

enum {
	FD_REGISTER_STORAGE_WIDTH = 64,
};

static RZ_INLINE ut32 fd_value_width(RzFloatFormat format) {
	return rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
}

static RZ_INLINE ut32 fd_mantissa_width(RzFloatFormat format) {
	return rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
}

static RZ_INLINE ut32 fd_exponent_width(RzFloatFormat format) {
	return rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
}

static RZ_INLINE ut32 fd_exponent_offset(RzFloatFormat format) {
	return fd_mantissa_width(format);
}

static RZ_INLINE ut32 fd_sign_offset(RzFloatFormat format) {
	return fd_value_width(format) - 1;
}

static RZ_INLINE ut32 fd_quiet_nan_offset(RzFloatFormat format) {
	return fd_exponent_offset(format) - 1;
}

static RZ_INLINE ut64 fd_max_exponent(RzFloatFormat format) {
	return (1ULL << fd_exponent_width(format)) - 1;
}

static RZ_INLINE ut32 fd_exponent_bias(RzFloatFormat format) {
	return rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
}

static RZ_INLINE RzILOpBitVector *fd_constant(RzFloatFormat format, ut64 value) {
	return UN(fd_value_width(format), value);
}

static RZ_INLINE RzILOpBitVector *fd_extract(RzFloatFormat format,
	RzILOpBitVector *value, ut32 offset, ut32 width) {
	if (fd_value_width(format) == 32) {
		return EXTRACT32(value, UN(32, offset), UN(32, width));
	}
	return EXTRACT64(value, UN(64, offset), UN(32, width));
}

/**
 * The canonical value is the derived all-ones exponent plus the derived quiet
 * bit, with sign and all remaining mantissa bits clear.
 */
static RZ_INLINE RzILOpBitVector *fd_canonical_qnan(RzFloatFormat format) {
	ut64 exponent = fd_max_exponent(format) << fd_exponent_offset(format);
	ut64 quiet = 1ULL << fd_quiet_nan_offset(format);
	return fd_constant(format, exponent | quiet);
}

/** Transfer operations ignore the upper bits of a narrower value. */
static RZ_INLINE RzILOpBitVector *fd_get_reg_bv_transfer(RzFloatFormat format, uint32_t reg) {
	RzILOpBitVector *value = VARG(riscv_freg_name(reg));
	ut32 value_width = fd_value_width(format);
	if (value_width < FD_REGISTER_STORAGE_WIDTH) {
		return CAST(value_width, IL_FALSE, value);
	}
	return value;
}

/**
 * Non-transfer operations on a narrower value must consume canonical qNaN
 * when the register's upper FLEN-value_width bits are not all ones.
 */
static RZ_INLINE RzILOpBitVector *fd_get_reg_bv_format(RzFloatFormat format, uint32_t reg) {
	RzILOpBitVector *value = VARG(riscv_freg_name(reg));
	ut32 value_width = fd_value_width(format);
	if (value_width < FD_REGISTER_STORAGE_WIDTH) {
		ut32 upper_width = FD_REGISTER_STORAGE_WIDTH - value_width;
		ut64 upper_mask = (1ULL << upper_width) - 1;
		RzILOpBool *properly_boxed = EQ(
			EXTRACT64(DUP(value), UN(64, value_width), UN(32, upper_width)),
			UN(64, upper_mask));
		return ITE(properly_boxed,
			CAST(value_width, IL_FALSE, value), fd_canonical_qnan(format));
	}
	return value;
}

static RZ_INLINE RzILOpBitVector *fd_get_reg_bv(RzFloatFormat format, uint32_t reg) {
	return fd_get_reg_bv_format(format, reg);
}

static RZ_INLINE RzILOpFloat *fd_get_reg_format(RzFloatFormat format, uint32_t reg) {
	return BV2F(format, fd_get_reg_bv_format(format, reg));
}

static RZ_INLINE RzILOpFloat *fd_get_reg(RzFloatFormat format, uint32_t reg) {
	return fd_get_reg_format(format, reg);
}

/**
 * With fixed 64-bit register storage, value_width < 64 is exactly the RISC-V
 * NaN-boxing condition. The derived difference is the all-ones prefix width.
 */
static RZ_INLINE RzILOpEffect *fd_set_reg_bv_format(RzFloatFormat format, uint32_t reg, RzILOpBitVector *value) {
	ut32 value_width = fd_value_width(format);
	if (value_width < FD_REGISTER_STORAGE_WIDTH) {
		ut32 upper_width = FD_REGISTER_STORAGE_WIDTH - value_width;
		value = APPEND(UN(upper_width, UT64_MAX), value);
	}
	return SETG(riscv_freg_name(reg), value);
}

static RZ_INLINE RzILOpEffect *fd_set_reg_bv(RzFloatFormat format,
	uint32_t reg, RzILOpBitVector *value) {
	return fd_set_reg_bv_format(format, reg, value);
}

/**
 * RzIL has no signaling-NaN predicate: an sNaN is a NaN whose quiet bit (the
 * mantissa MSB) is clear.
 */
static RZ_INLINE RzILOpBool *fd_is_s_nan(RzFloatFormat format, RzILOpFloat *value) {
	return AND(IS_FNAN(DUP(value)),
		IS_ZERO(fd_extract(format, F2BV(value), fd_quiet_nan_offset(format), 1)));
}

/** 2^exponent with an unbiased exponent; exact in binary32 and binary64. */
static RZ_INLINE RzILOpFloat *fd_power_of_two(RzFloatFormat format, st32 exponent) {
	ut64 bits = (ut64)(fd_exponent_bias(format) + exponent) << fd_exponent_offset(format);
	return BV2F(format, fd_constant(format, bits));
}

/**
 * Writes a computed result. RISC-V never propagates NaN sign or payload: any
 * NaN result is the canonical NaN, so the NaN chosen by the float backend
 * (e.g. SoftFloat's x86 default NaN) never reaches the register.
 * \p value is duplicated, so pass a variable (or a cheap op over one).
 */
static RZ_INLINE RzILOpEffect *fd_set_reg_canonical(RzFloatFormat format, uint32_t reg, RzILOpFloat *value) {
	return fd_set_reg_bv(format, reg,
		ITE(IS_FNAN(DUP(value)), fd_canonical_qnan(format), F2BV(value)));
}

/** Accrues the invalid-operation flag (fflags.NV) when \p condition holds. */
static RZ_INLINE RzILOpEffect *fd_raise_invalid_if(RzILOpBool *condition) {
	return SETG("fcsr", LOGOR(VARG("fcsr"), ITE(condition, UN(32, 0x10), UN(32, 0))));
}

/** Maps a statically encoded Capstone rounding mode at lift time. */
static RZ_INLINE RzFloatRMode fd_rounding_mode(riscv_rounding_mode mode) {
	static const RzFloatRMode modes[] = {
		RZ_FLOAT_RMODE_RNE,
		RZ_FLOAT_RMODE_RTZ,
		RZ_FLOAT_RMODE_RTN,
		RZ_FLOAT_RMODE_RTP,
		RZ_FLOAT_RMODE_RNA,
	};
	if (mode < RISCV_RM_RNE || mode > RISCV_RM_RMM) {
		rz_warn_if_reached();
		return RZ_FLOAT_RMODE_RNE;
	}
	return modes[mode - RISCV_RM_RNE];
}

static RZ_INLINE RzILOpBitVector *fd_fflags_mask_from_exception(ut64 riscv_bit,
	RzFloatException exception, const char *result_name) {
	return ITE(FEXCEPT(exception, VARL(result_name)), UN(32, riscv_bit), UN(32, 0));
}

static RZ_INLINE RzILOpEffect *fd_update_fflags(const char *fcsr_name, const char *result_name) {
	RzILOpBitVector *fflags = VARG(fcsr_name);
	fflags = LOGOR(fflags, fd_fflags_mask_from_exception(0x01, RZ_FLOAT_E_INEXACT, result_name));
	fflags = LOGOR(fflags, fd_fflags_mask_from_exception(0x02, RZ_FLOAT_E_UNDERFLOW, result_name));
	fflags = LOGOR(fflags, fd_fflags_mask_from_exception(0x04, RZ_FLOAT_E_OVERFLOW, result_name));
	fflags = LOGOR(fflags, fd_fflags_mask_from_exception(0x08, RZ_FLOAT_E_DIV_ZERO, result_name));
	fflags = LOGOR(fflags, fd_fflags_mask_from_exception(0x10, RZ_FLOAT_E_INVALID_OP, result_name));
	return SETG(fcsr_name, fflags);
}

/**
 * Maps the architectural fcsr.frm encoding to RzFloatRMode at IL run time.
 * The lift-time mapping of fd_rounding_mode is packed into one constant of
 * 4-bit entries indexed by frm; reserved frm values 5-7 fall back to RNE.
 * Dynamic RzIL rounding modes are represented by 32-bit bitvectors.
 */
static RZ_INLINE RzILOpBitVector *fd_dynamic_rounding_mode(const char *fcsr_name) {
	ut32 table = 0;
	for (ut32 frm = 0; frm < 8; frm++) {
		RzFloatRMode mode = frm <= RISCV_RM_RMM - RISCV_RM_RNE
			? fd_rounding_mode((riscv_rounding_mode)(RISCV_RM_RNE + frm))
			: RZ_FLOAT_RMODE_RNE;
		table |= (ut32)mode << (4 * frm);
	}
	RzILOpBitVector *frm = EXTRACT32(VARG(fcsr_name), UN(32, 5), UN(32, 3));
	return EXTRACT32(UN(32, table), SHIFTL0(frm, UN(32, 2)), UN(32, 4));
}

static RZ_INLINE RzILOpEffect *fd_set_dynamic_rounding_mode(const char *rounding_mode_name,
	const char *fcsr_name) {
	return SETL(rounding_mode_name, fd_dynamic_rounding_mode(fcsr_name));
}

static RZ_INLINE RzILOpFloat *fd_binary_result(FDBinaryOperation operation,
	RzFloatRMode mode, RzILOpFloat *left, RzILOpFloat *right) {
	switch (operation) {
	case FD_BINARY_ADD: return FADD(mode, left, right);
	case FD_BINARY_SUB: return FSUB(mode, left, right);
	case FD_BINARY_MUL: return FMUL(mode, left, right);
	case FD_BINARY_DIV: return FDIV(mode, left, right);
	default:
		rz_warn_if_reached();
		rz_il_op_pure_free(left);
		rz_il_op_pure_free(right);
		return NULL;
	}
}

static RZ_INLINE RzILOpFloat *fd_dynamic_binary_result(FDBinaryOperation operation,
	const char *rounding_mode_name, RzILOpFloat *left, RzILOpFloat *right) {
	switch (operation) {
	case FD_BINARY_ADD: return FADD_DYN_RMODE(VARL(rounding_mode_name), left, right);
	case FD_BINARY_SUB: return FSUB_DYN_RMODE(VARL(rounding_mode_name), left, right);
	case FD_BINARY_MUL: return FMUL_DYN_RMODE(VARL(rounding_mode_name), left, right);
	case FD_BINARY_DIV: return FDIV_DYN_RMODE(VARL(rounding_mode_name), left, right);
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

/**
 * Binds a rounded result to _r, writes it (optionally negated, NaNs
 * canonicalized) to frd, and accumulates its exceptions into fflags. Dynamic
 * rounding first binds the fcsr.frm mode to _rmode, which the result
 * expression is expected to use.
 */
static RZ_INLINE RzILOpEffect *fd_commit_rounded_result(RzFloatFormat format,
	uint32_t frd, bool dynamic, RzILOpFloat *result, bool negate) {
	RzILOpEffect *effect = SEQ3(
		SETL("_r", result),
		fd_set_reg_canonical(format, frd, negate ? FNEG(VARL("_r")) : VARL("_r")),
		fd_update_fflags("fcsr", "_r"));
	return dynamic ? SEQ2(fd_set_dynamic_rounding_mode("_rmode", "fcsr"), effect) : effect;
}

static RZ_INLINE RzILOpEffect *fd_lift_load(RzFloatFormat format,
	RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_FD_MEM(analysis, insn);
	return fd_set_reg_bv(format, frd, LOADW(fd_value_width(format), ADD(base, offset)));
}

static RZ_INLINE RzILOpEffect *fd_lift_store(RzFloatFormat format,
	RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_FS_MEM(format, analysis, insn);
	return STOREW(ADD(base, offset), value);
}

static RZ_INLINE RzILOpEffect *fd_lift_binary(RzFloatFormat format,
	FDBinaryOperation operation, RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_FD_FS_FS(format, insn);
	bool dynamic = insn->detail->riscv.rounding_mode == RISCV_RM_DYN;
	RzILOpFloat *result = dynamic
		? fd_dynamic_binary_result(operation, "_rmode", left, right)
		: fd_binary_result(operation, fd_rounding_mode(insn->detail->riscv.rounding_mode), left, right);
	return fd_commit_rounded_result(format, frd, dynamic, result, false);
}

static RZ_INLINE RzILOpEffect *fd_lift_sqrt(RzFloatFormat format,
	RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_FD_FS(format, insn);
	bool dynamic = insn->detail->riscv.rounding_mode == RISCV_RM_DYN;
	RzILOpFloat *result = dynamic
		? FSQRT_DYN_RMODE(VARL("_rmode"), source)
		: FSQRT(fd_rounding_mode(insn->detail->riscv.rounding_mode), source);
	return fd_commit_rounded_result(format, frd, dynamic, result, false);
}

static RZ_INLINE RzILOpEffect *fd_lift_mad(RzFloatFormat format,
	FDMadOperation operation, RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_FD_FS_FS_FS(format, insn);
	bool negate_result = operation == FD_MAD_NEGATED_ADD;
	if (operation == FD_MAD_SUB) {
		addend = FNEG(addend);
	} else if (operation == FD_MAD_NEGATED_SUB) {
		left = FNEG(left);
	}
	bool dynamic = insn->detail->riscv.rounding_mode == RISCV_RM_DYN;
	RzILOpFloat *result = dynamic
		? FMAD_DYN_RMODE(VARL("_rmode"), left, right, addend)
		: FMAD(fd_rounding_mode(insn->detail->riscv.rounding_mode), left, right, addend);
	return fd_commit_rounded_result(format, frd, dynamic, result, negate_result);
}

static RZ_INLINE RzILOpEffect *fd_lift_sign_injection(RzFloatFormat format,
	FDSignOperation operation, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_FD_BV_BV(format, insn);
	ut64 sign_mask = 1ULL << fd_sign_offset(format);
	RzILOpBitVector *magnitude = left;
	RzILOpBitVector *sign;
	if (operation == FD_SIGN_COPY) {
		sign = LOGAND(right, fd_constant(format, sign_mask));
	} else if (operation == FD_SIGN_NEGATE) {
		sign = LOGAND(LOGNOT(right), fd_constant(format, sign_mask));
	} else {
		magnitude = DUP(left);
		sign = LOGAND(LOGXOR(left, right), fd_constant(format, sign_mask));
	}
	return fd_set_reg_bv(format, frd,
		LOGOR(LOGAND(magnitude, fd_constant(format, ~sign_mask)), sign));
}

/**
 * Floating-point minimum-number and maximum-number instructions FMIN.S and FMAX.S write, respectively,
 * the smaller or larger of rs1 and rs2 to rd.
 * For the purposes of these instructions only, the value -0.0 is considered to be less than the value +0.0.
 * If both inputs are NaNs, the result is the canonical NaN.
 * If only one operand is a NaN, the result is the non-NaN operand.
 * Signaling NaN inputs set the invalid operation exception flag, even when the result is not NaN.
 *
 * rs1 is picked when it wins the comparison, when both are zeros and rs1 has
 * the preferred sign (comparisons treat -0.0 and +0.0 as equal; any other
 * equal pair has identical bits), or when rs2 is NaN. A NaN rs1 loses every
 * comparison, so rs2 is picked; when both are NaN, rs1 is picked and
 * canonicalized on write.
 */
static RZ_INLINE RzILOpEffect *fd_lift_minmax(RzFloatFormat format,
	bool maximum, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_FD_FREGS(insn);
	RzILOpBool *zero_tie = AND(IS_FZERO(VARL("_a")), IS_FZERO(VARL("_b")));
	RzILOpBool *a_wins = maximum
		? OR(FGT(VARL("_a"), VARL("_b")), AND(zero_tie, IS_FPOS(VARL("_a"))))
		: OR(FLT(VARL("_a"), VARL("_b")), AND(zero_tie, IS_FNEG(VARL("_a"))));
	return SEQ5(
		SETL("_a", fd_get_reg(format, frs1)),
		SETL("_b", fd_get_reg(format, frs2)),
		fd_raise_invalid_if(OR(fd_is_s_nan(format, VARL("_a")), fd_is_s_nan(format, VARL("_b")))),
		SETL("_r", ITE(OR(IS_FNAN(VARL("_b")), a_wins), VARL("_a"), VARL("_b"))),
		fd_set_reg_canonical(format, frd, VARL("_r")));
}

/**
 * FLT.S and FLE.S perform what the IEEE 754-2008 standard refers to as signaling comparisons:
 * that is, they set the invalid operation exception flag if either input is NaN.
 * FEQ.S performs a quiet comparison: it only sets the invalid operation exception flag if either input is a signaling NaN.
 * The RzIL comparisons are already false for unordered operands.
 */
static RZ_INLINE RzILOpEffect *fd_lift_compare(RzFloatFormat format,
	FDCompareOperation operation, RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_RD_FREGS(insn);
	RzILOpBool *comparison =
		// ==
		(operation == FD_COMPARE_EQ) ? FEQ(VARL("_a"), VARL("_b"))
		// <
		: (operation == FD_COMPARE_LT) ? FLT(VARL("_a"), VARL("_b"))
					       // <=
					       : FLE(VARL("_a"), VARL("_b"));
	RzILOpBool *invalid = operation == FD_COMPARE_EQ
		? OR(fd_is_s_nan(format, VARL("_a")), fd_is_s_nan(format, VARL("_b")))
		: OR(IS_FNAN(VARL("_a")), IS_FNAN(VARL("_b")));
	return SEQ4(
		SETL("_a", fd_get_reg(format, frs1)),
		SETL("_b", fd_get_reg(format, frs2)),
		fd_raise_invalid_if(invalid),
		riscv_il_set_reg(rd, BOOL_TO_BV(comparison, analysis->bits)));
}

static RZ_INLINE RzILOpBitVector *fd_classification_bit(ut32 bit, RzILOpBool *condition, ut32 xlen) {
	return SHIFTL0(BOOL_TO_BV(condition, xlen), UN(xlen, bit));
}

/**
 * Classifies with the RzIL float predicates. Zero and subnormal magnitudes are
 * exactly those below the smallest normal number 2^(1-bias); NaN compares
 * false and is therefore never "tiny".
 */
static RZ_INLINE RzILOpEffect *fd_lift_class(RzFloatFormat format,
	RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_RD_FS_BV(format, insn);
	ut32 xlen = analysis->bits;
	RzILOpBool *classes[] = {
		/* 0: -inf       */ AND(VARL("_neg"), IS_FINF(VARL("_f"))),
		/* 1: -normal    */ AND(VARL("_neg"), VARL("_normal")),
		/* 2: -subnormal */ AND(VARL("_neg"), VARL("_subnormal")),
		/* 3: -0         */ AND(VARL("_neg"), IS_FZERO(VARL("_f"))),
		/* 4: +0         */ AND(INV(VARL("_neg")), IS_FZERO(VARL("_f"))),
		/* 5: +subnormal */ AND(INV(VARL("_neg")), VARL("_subnormal")),
		/* 6: +normal    */ AND(INV(VARL("_neg")), VARL("_normal")),
		/* 7: +inf       */ AND(INV(VARL("_neg")), IS_FINF(VARL("_f"))),
		/* 8: sNaN       */ fd_is_s_nan(format, VARL("_f")),
		/* 9: qNaN       */ AND(IS_FNAN(VARL("_f")), INV(fd_is_s_nan(format, VARL("_f")))),
	};
	RzILOpBitVector *classification = fd_classification_bit(0, classes[0], xlen);
	for (ut32 bit = 1; bit < RZ_ARRAY_SIZE(classes); bit++) {
		classification = LOGOR(classification, fd_classification_bit(bit, classes[bit], xlen));
	}
	st32 min_normal_exponent = 1 - (st32)fd_exponent_bias(format);
	return SEQ6(
		SETL("_f", BV2F(format, value)),
		SETL("_neg", IS_FNEG(VARL("_f"))),
		SETL("_tiny", FLT(FABS(VARL("_f")), fd_power_of_two(format, min_normal_exponent))),
		SETL("_subnormal", AND(VARL("_tiny"), INV(IS_FZERO(VARL("_f"))))),
		SETL("_normal", INV(OR(VARL("_tiny"), OR(IS_FINF(VARL("_f")), IS_FNAN(VARL("_f")))))),
		riscv_il_set_reg(rd, classification));
}

/**
 * Converts to a width-bit integer. The rounded value converts exactly when it
 * lies in [lower, upper); the bounds are zero or powers of two, exact in
 * binary32 and binary64. NaN fails both comparisons and is thus invalid too.
 * Invalid conversions saturate: values below the range yield the minimum,
 * NaN and positive overflow yield the maximum.
 * 32-bit results are sign-extended to XLEN, as required for RV64.
 */
static RZ_INLINE RzILOpEffect *fd_lift_fcvt_int(RzFloatFormat format,
	bool unsigned_result, ut32 width, RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	if (width == 64) {
		REQUIRE_64_BIT(analysis);
	}
	DECODE_FD_RD_FS_BV(format, insn);
	bool dynamic = insn->detail->riscv.rounding_mode == RISCV_RM_DYN;
	RzFloatRMode mode = dynamic
		? RZ_FLOAT_RMODE_RNE
		: fd_rounding_mode(insn->detail->riscv.rounding_mode);
	ut64 signed_min = 1ULL << (width - 1);
	ut64 int_max = unsigned_result ? UT64_MAX >> (64 - width) : signed_min - 1;
	ut64 int_min = unsigned_result ? 0 : signed_min;
	RzILOpFloat *lower = unsigned_result
		? BV2F(format, fd_constant(format, 0))
		: FNEG(fd_power_of_two(format, width - 1));
	RzILOpFloat *upper = fd_power_of_two(format, unsigned_result ? width : width - 1);
	RzILOpFloat *rounded = dynamic
		? FROUND_DYN_RMODE(VARL("_rmode"), VARL("_f"))
		: FROUND(mode, VARL("_f"));
	RzILOpBitVector *converted;
	if (unsigned_result) {
		converted = dynamic
			? F2INT_DYN_RMODE(width, VARL("_rmode"), VARL("_rounded"))
			: F2INT(width, mode, VARL("_rounded"));
	} else {
		converted = dynamic
			? F2SINT_DYN_RMODE(width, VARL("_rmode"), VARL("_rounded"))
			: F2SINT(width, mode, VARL("_rounded"));
	}
	RzILOpBitVector *saturated = ITE(FLT(VARL("_rounded"), DUP(lower)),
		UN(width, int_min), UN(width, int_max));
	RzILOpBitVector *result = VARL("_int");
	if (width == 32) {
		result = SIGNED(analysis->bits, result);
	}
	RzILOpEffect *effect = SEQ6(
		SETL("_f", BV2F(format, value)),
		SETL("_rounded", rounded),
		SETL("_nv", INV(AND(FGE(VARL("_rounded"), lower), FLT(VARL("_rounded"), upper)))),
		SETL("_int", ITE(VARL("_nv"), saturated, converted)),
		riscv_il_set_reg(rd, result),
		SETG("fcsr", LOGOR(VARG("fcsr"), ITE(VARL("_nv"), UN(32, 0x10), ITE(FNE(VARL("_rounded"), VARL("_f")), UN(32, 0x01), UN(32, 0))))));
	return dynamic ? SEQ2(fd_set_dynamic_rounding_mode("_rmode", "fcsr"), effect) : effect;
}

static RZ_INLINE RzILOpEffect *fd_lift_fcvt_from_int(RzFloatFormat format,
	FDIntegerSource operation, RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	bool from_long = operation == FD_INT64_SIGNED || operation == FD_INT64_UNSIGNED;
	bool unsigned_source = operation == FD_INT32_UNSIGNED || operation == FD_INT64_UNSIGNED;
	if (from_long) {
		REQUIRE_64_BIT(analysis);
	}
	DECODE_FD_FD_RS(analysis, insn);
	if (!from_long) {
		source = CAST(32, IL_FALSE, source);
		if (fd_value_width(format) == 64) {
			source = unsigned_source ? CAST(64, IL_FALSE, source) : SIGNED(64, source);
		}
	}
	bool dynamic = insn->detail->riscv.rounding_mode == RISCV_RM_DYN;
	RzFloatRMode mode = dynamic
		? RZ_FLOAT_RMODE_RNE
		: fd_rounding_mode(insn->detail->riscv.rounding_mode);
	RzILOpFloat *result;
	if (unsigned_source) {
		result = dynamic
			? INT2F_DYN_RMODE(format, VARL("_rmode"), source)
			: INT2F(format, mode, source);
	} else {
		result = dynamic
			? SINT2F_DYN_RMODE(format, VARL("_rmode"), source)
			: SINT2F(format, mode, source);
	}
	return fd_commit_rounded_result(format, frd, dynamic, result, false);
}

static RZ_INLINE RzILOpEffect *fd_lift_fcvt_format(RzFloatFormat destination_format,
	RzFloatFormat source_format, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_FD_FS_FORMAT(source_format, insn);
	bool dynamic = insn->detail->riscv.rounding_mode == RISCV_RM_DYN;
	RzILOpFloat *result = dynamic
		? FCONVERT_DYN_RMODE(destination_format, VARL("_rmode"), source)
		: FCONVERT(destination_format, fd_rounding_mode(insn->detail->riscv.rounding_mode), source);
	return fd_commit_rounded_result(destination_format, frd, dynamic, result, false);
}

static RZ_INLINE RzILOpEffect *fd_lift_fmv_to_x(RzFloatFormat format,
	RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	if (fd_value_width(format) == 64) {
		REQUIRE_64_BIT(analysis);
	}
	DECODE_FD_RD_FS_BV_TRANSFER(format, insn);
	if (fd_value_width(format) == 32) {
		value = SIGNED(analysis->bits, value);
	}
	return riscv_il_set_reg(rd, value);
}

static RZ_INLINE RzILOpEffect *fd_lift_fmv_from_x(RzFloatFormat format,
	RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	if (fd_value_width(format) == 64) {
		REQUIRE_64_BIT(analysis);
	}
	DECODE_FD_FD_RS(analysis, insn);
	RzILOpBitVector *value = source;
	if (fd_value_width(format) == 32) {
		value = CAST(32, IL_FALSE, value);
	}
	return fd_set_reg_bv(format, frd, value);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_load(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_load(format, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_store(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_store(format, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_add(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_binary(format, FD_BINARY_ADD, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_sub(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_binary(format, FD_BINARY_SUB, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_mul(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_binary(format, FD_BINARY_MUL, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_div(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_binary(format, FD_BINARY_DIV, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_sqrt(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_sqrt(format, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmadd(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_mad(format, FD_MAD_ADD, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmsub(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_mad(format, FD_MAD_SUB, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fnmadd(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_mad(format, FD_MAD_NEGATED_ADD, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fnmsub(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_mad(format, FD_MAD_NEGATED_SUB, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fsgnj(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_sign_injection(format, FD_SIGN_COPY, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fsgnjn(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_sign_injection(format, FD_SIGN_NEGATE, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fsgnjx(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_sign_injection(format, FD_SIGN_XOR, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmin(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_minmax(format, false, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmax(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_minmax(format, true, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_feq(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_compare(format, FD_COMPARE_EQ, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_flt(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_compare(format, FD_COMPARE_LT, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fle(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_compare(format, FD_COMPARE_LE, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fclass(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_class(format, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_w(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_fcvt_int(format, false, 32, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_wu(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_fcvt_int(format, true, 32, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_l(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_fcvt_int(format, false, 64, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_lu(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_fcvt_int(format, true, 64, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_from_w(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_fcvt_from_int(format, FD_INT32_SIGNED, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_from_wu(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_fcvt_from_int(format, FD_INT32_UNSIGNED, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_from_l(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_fcvt_from_int(format, FD_INT64_SIGNED, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_from_lu(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_fcvt_from_int(format, FD_INT64_UNSIGNED, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_format(RzFloatFormat destination_format,
	RzFloatFormat source_format, RzAnalysis *analysis, RzAnalysisOp *op,
	cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_fcvt_format(destination_format, source_format, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmv_to_x(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_fmv_to_x(format, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmv_from_x(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	return fd_lift_fmv_from_x(format, analysis, insn, current_addr);
}

#include <rz_il/rz_il_opbuilder_end.h>
