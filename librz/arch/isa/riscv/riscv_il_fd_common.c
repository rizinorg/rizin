// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "analysis_private.h"
#include "riscv_il_base.h"
#include "riscv_il_fd_common.h"
#include "riscv_il_float_reg_names.h"

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

static RZ_INLINE ut32 fd_mantissa_offset(RzFloatFormat format) {
	(void)format;
	return 0;
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
 * Replaces RISCV_FD_REG_GETTER_BV.
 *
 * F had: CAST(32, IL_FALSE, VARG(riscv_freg_name(reg)))
 * D had: VARG(riscv_freg_name(reg))
 *
 * RzFloat metadata gives value_width as 32 or 64. Floating-register storage is
 * fixed at 64 bits, so only a narrower format needs the low-bit cast.
 */
static RZ_INLINE RzILOpBitVector *fd_get_reg_bv_format(RzFloatFormat format, uint32_t reg) {
	RzILOpBitVector *value = VARG(riscv_freg_name(reg));
	ut32 value_width = fd_value_width(format);
	if (value_width < FD_REGISTER_STORAGE_WIDTH) {
		return CAST(value_width, IL_FALSE, value);
	}
	return value;
}

static RZ_INLINE RzILOpBitVector *fd_get_reg_bv(RzFloatFormat format, uint32_t reg) {
	return fd_get_reg_bv_format(format, reg);
}

/**
 * Replaces RISCV_FD_REG_GETTER.
 *
 * F had: FLOATV32(RISCV_FD_REG_GETTER_BV(reg))
 * D had: FLOATV64(RISCV_FD_REG_GETTER_BV(reg))
 *
 * FLOATV32/FLOATV64 are the same constructor specialized by RzFloatFormat, so
 * the format itself selects both the float interpretation and raw value width.
 */
static RZ_INLINE RzILOpFloat *fd_get_reg_format(RzFloatFormat format, uint32_t reg) {
	return BV2F(format, fd_get_reg_bv_format(format, reg));
}

static RZ_INLINE RzILOpFloat *fd_get_reg(RzFloatFormat format, uint32_t reg) {
	return fd_get_reg_format(format, reg);
}

/**
 * Replaces RISCV_FD_REG_SETTER_BV.
 *
 * F had: SETG(name, APPEND(UN(32, 0xffffffff), bv))
 * D had: SETG(name, bv)
 *
 * With fixed 64-bit register storage, value_width < 64 is exactly the RISC-V
 * NaN-boxing condition. The derived difference is the all-ones prefix width.
 */
static RZ_INLINE RzILOpEffect *fd_set_reg_bv_format(RzFloatFormat format,
	uint32_t reg, RzILOpBitVector *value) {
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
 * Replaces RISCV_FD_REG_SETTER.
 *
 * F had: RISCV_FD_REG_SETTER_BV(reg, F2BV(fl)), which NaN-boxed the result.
 * D had: SETG(name, F2BV(fl)), which stored all 64 bits directly.
 *
 * Float-to-bits is common; fd_set_reg_bv_format derives whether the resulting
 * format is narrower than the fixed register storage and boxes only then.
 */
static RZ_INLINE RzILOpEffect *fd_set_reg_format(RzFloatFormat format,
	uint32_t reg, RzILOpFloat *value) {
	return fd_set_reg_bv_format(format, reg, F2BV(value));
}

static RZ_INLINE RzILOpEffect *fd_set_reg(RzFloatFormat format,
	uint32_t reg, RzILOpFloat *value) {
	return fd_set_reg_format(format, reg, value);
}

/**
 * Replaces RISCV_FD_GET_MANTISSA.
 *
 * F had: EXTRACT32(bv, 0, 23)
 * D had: EXTRACT64(bv, 0, 52)
 *
 * RzFloat places the mantissa at bit zero and reports its width as MAN_LEN.
 */
static RZ_INLINE RzILOpBitVector *fd_get_mantissa(RzFloatFormat format,
	RzILOpBitVector *value) {
	return fd_extract(format, value, fd_mantissa_offset(format), fd_mantissa_width(format));
}

/**
 * Replaces RISCV_FD_GET_EXPONENT.
 *
 * F had: EXTRACT32(bv, 23, 8)
 * D had: EXTRACT64(bv, 52, 11)
 *
 * RzFloat places the exponent immediately after its MAN_LEN-bit mantissa and
 * reports the exponent width as EXP_LEN.
 */
static RZ_INLINE RzILOpBitVector *fd_get_exponent(RzFloatFormat format,
	RzILOpBitVector *value) {
	return fd_extract(format, value, fd_exponent_offset(format), fd_exponent_width(format));
}

/**
 * Replaces RISCV_FD_GET_SIGN.
 *
 * F had: EXTRACT32(bv, 31, 1)
 * D had: EXTRACT64(bv, 63, 1)
 *
 * RzFloat stores the sign in TOTAL_LEN - 1, yielding bit 31 or bit 63.
 */
static RZ_INLINE RzILOpBitVector *fd_get_sign(RzFloatFormat format,
	RzILOpBitVector *value) {
	return fd_extract(format, value, fd_sign_offset(format), 1);
}

/**
 * Replaces RISCV_FD_IS_NAN.
 *
 * F had: exponent == 0xff && mantissa != 0
 * D had: exponent == 0x7ff && mantissa != 0
 *
 * EXP_LEN derives an all-ones maximum exponent of (1 << EXP_LEN) - 1; field
 * extraction is derived from the same format metadata.
 */
static RZ_INLINE RzILOpBool *fd_is_nan(RzFloatFormat format,
	RzILOpBitVector *value) {
	return AND(
		EQ(fd_get_exponent(format, DUP(value)), fd_constant(format, fd_max_exponent(format))),
		NON_ZERO(fd_get_mantissa(format, value)));
}

/**
 * Replaces RISCV_FD_IS_S_NAN.
 *
 * F had: IS_NAN(bv) && bit 22 == 0
 * D had: IS_NAN(bv) && bit 51 == 0
 *
 * For RISC-V binary32/binary64, the quiet bit is the highest mantissa bit,
 * immediately below the derived exponent offset.
 */
static RZ_INLINE RzILOpBool *fd_is_s_nan(RzFloatFormat format,
	RzILOpBitVector *value) {
	return AND(
		fd_is_nan(format, DUP(value)),
		IS_ZERO(fd_extract(format, value, fd_quiet_nan_offset(format), 1)));
}

/**
 * Replaces RISCV_FD_CANONICAL_QNAN.
 *
 * F had: UN(32, 0x7fc00000)
 * D had: UN(64, 0x7ff8000000000000)
 *
 * The canonical value is the derived all-ones exponent plus the derived quiet
 * bit, with sign and all remaining mantissa bits clear.
 */
static RZ_INLINE RzILOpBitVector *fd_canonical_qnan(RzFloatFormat format) {
	ut64 exponent = fd_max_exponent(format) << fd_exponent_offset(format);
	ut64 quiet = 1ULL << fd_quiet_nan_offset(format);
	return fd_constant(format, exponent | quiet);
}

/**
 * Replaces RISCV_FD_IS_MAX_EXP.
 *
 * F had: EQ(exponent, UN(32, 0xff))
 * D had: EQ(exponent, UN(64, 0x7ff))
 *
 * EXP_LEN derives 0xff or 0x7ff, and TOTAL_LEN derives the IL constant width.
 */
static RZ_INLINE RzILOpBool *fd_is_max_exp(RzFloatFormat format,
	RzILOpBitVector *exponent) {
	return EQ(exponent, fd_constant(format, fd_max_exponent(format)));
}

static RZ_INLINE RzILOpFloat *fd_power_of_two(RzFloatFormat format, ut32 exponent) {
	ut64 bits = (ut64)(fd_exponent_bias(format) + exponent) << fd_exponent_offset(format);
	return BV2F(format, fd_constant(format, bits));
}

/**
 * A floating-point-to-integer conversion is invalid exactly when the rounded
 * integral value is outside the destination range, or when the source is NaN.
 * The exclusive upper bounds are powers of two and are therefore represented
 * exactly in both binary32 and binary64.
 */
static RZ_INLINE RzILOpBool *fd_fcvt_is_invalid(RzFloatFormat format,
	bool unsigned_result, ut32 width) {
	RzILOpFloat *lower = unsigned_result
		? BV2F(format, fd_constant(format, 0))
		: FNEG(fd_power_of_two(format, width - 1));
	RzILOpFloat *upper = fd_power_of_two(format,
		unsigned_result ? width : width - 1);
	return OR(fd_is_nan(format, VARL("_bv")),
		OR(FLT(VARL("_rounded"), lower), FGE(VARL("_rounded"), upper)));
}

static RZ_INLINE RzFloatRMode fd_rounding_mode(riscv_rounding_mode mode) {
	switch (mode) {
	case RISCV_RM_RNE: return RZ_FLOAT_RMODE_RNE;
	case RISCV_RM_RTZ: return RZ_FLOAT_RMODE_RTZ;
	case RISCV_RM_RDN: return RZ_FLOAT_RMODE_RTN;
	case RISCV_RM_RUP: return RZ_FLOAT_RMODE_RTP;
	case RISCV_RM_RMM: return RZ_FLOAT_RMODE_RNA;
	default: return RZ_FLOAT_RMODE_RNE;
	}
}

static RZ_INLINE RzILOpBitVector *fd_exception(ut64 riscv_bit, RzFloatException exception) {
	return ITE(FEXCEPT(exception, VARL("_r")), UN(64, riscv_bit), UN(64, 0));
}

static RZ_INLINE RzILOpEffect *fd_update_fflags(void) {
	return SETG("fcsr", LOGOR(VARG("fcsr"), LOGOR(fd_exception(0x01, RZ_FLOAT_E_INEXACT), LOGOR(fd_exception(0x02, RZ_FLOAT_E_UNDERFLOW), LOGOR(fd_exception(0x04, RZ_FLOAT_E_OVERFLOW), LOGOR(fd_exception(0x08, RZ_FLOAT_E_DIV_ZERO), fd_exception(0x10, RZ_FLOAT_E_INVALID_OP)))))));
}

static RZ_INLINE RzILOpEffect *fd_set_frm(void) {
	return SETL("_frm", EXTRACT64(VARG("fcsr"), UN(64, 5), UN(32, 3)));
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

static RZ_INLINE RzILOpFloat *fd_dynamic_binary_result(FDBinaryOperation operation) {
	return ITE(EQ(VARL("_frm"), UN(64, 0)), fd_binary_result(operation, RZ_FLOAT_RMODE_RNE, VARL("_x"), VARL("_y")),
		ITE(EQ(VARL("_frm"), UN(64, 1)), fd_binary_result(operation, RZ_FLOAT_RMODE_RTZ, VARL("_x"), VARL("_y")),
			ITE(EQ(VARL("_frm"), UN(64, 2)), fd_binary_result(operation, RZ_FLOAT_RMODE_RTN, VARL("_x"), VARL("_y")),
				ITE(EQ(VARL("_frm"), UN(64, 3)), fd_binary_result(operation, RZ_FLOAT_RMODE_RTP, VARL("_x"), VARL("_y")),
					fd_binary_result(operation, RZ_FLOAT_RMODE_RNA, VARL("_x"), VARL("_y"))))));
}

static RZ_INLINE RzILOpFloat *fd_dynamic_sqrt_result(void) {
	return ITE(EQ(VARL("_frm"), UN(64, 0)), FSQRT(RZ_FLOAT_RMODE_RNE, VARL("_x")),
		ITE(EQ(VARL("_frm"), UN(64, 1)), FSQRT(RZ_FLOAT_RMODE_RTZ, VARL("_x")),
			ITE(EQ(VARL("_frm"), UN(64, 2)), FSQRT(RZ_FLOAT_RMODE_RTN, VARL("_x")),
				ITE(EQ(VARL("_frm"), UN(64, 3)), FSQRT(RZ_FLOAT_RMODE_RTP, VARL("_x")),
					FSQRT(RZ_FLOAT_RMODE_RNA, VARL("_x"))))));
}

static RZ_INLINE RzILOpFloat *fd_dynamic_mad_result(void) {
	return ITE(EQ(VARL("_frm"), UN(64, 0)), FMAD(RZ_FLOAT_RMODE_RNE, VARL("_x"), VARL("_y"), VARL("_z")),
		ITE(EQ(VARL("_frm"), UN(64, 1)), FMAD(RZ_FLOAT_RMODE_RTZ, VARL("_x"), VARL("_y"), VARL("_z")),
			ITE(EQ(VARL("_frm"), UN(64, 2)), FMAD(RZ_FLOAT_RMODE_RTN, VARL("_x"), VARL("_y"), VARL("_z")),
				ITE(EQ(VARL("_frm"), UN(64, 3)), FMAD(RZ_FLOAT_RMODE_RTP, VARL("_x"), VARL("_y"), VARL("_z")),
					FMAD(RZ_FLOAT_RMODE_RNA, VARL("_x"), VARL("_y"), VARL("_z"))))));
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
	if (insn->detail->riscv.rounding_mode == RISCV_RM_DYN) {
		return SEQN(6,
			fd_set_frm(),
			SETL("_x", left),
			SETL("_y", right),
			SETL("_r", fd_dynamic_binary_result(operation)),
			fd_set_reg(format, frd, VARL("_r")),
			fd_update_fflags());
	}
	return SEQ3(
		SETL("_r", fd_binary_result(operation, fd_rounding_mode(insn->detail->riscv.rounding_mode), left, right)),
		fd_set_reg(format, frd, VARL("_r")),
		fd_update_fflags());
}

static RZ_INLINE RzILOpEffect *fd_lift_sqrt(RzFloatFormat format,
	RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_FD_FS(format, insn);
	if (insn->detail->riscv.rounding_mode == RISCV_RM_DYN) {
		return SEQN(5,
			fd_set_frm(),
			SETL("_x", source),
			SETL("_r", fd_dynamic_sqrt_result()),
			fd_set_reg(format, frd, VARL("_r")),
			fd_update_fflags());
	}
	return SEQ3(
		SETL("_r", FSQRT(fd_rounding_mode(insn->detail->riscv.rounding_mode), source)),
		fd_set_reg(format, frd, VARL("_r")),
		fd_update_fflags());
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
	if (insn->detail->riscv.rounding_mode == RISCV_RM_DYN) {
		return SEQN(7,
			fd_set_frm(),
			SETL("_x", left),
			SETL("_y", right),
			SETL("_z", addend),
			SETL("_r", fd_dynamic_mad_result()),
			fd_set_reg(format, frd, negate_result ? FNEG(VARL("_r")) : VARL("_r")),
			fd_update_fflags());
	}
	return SEQ3(
		SETL("_r", FMAD(fd_rounding_mode(insn->detail->riscv.rounding_mode), left, right, addend)),
		fd_set_reg(format, frd, negate_result ? FNEG(VARL("_r")) : VARL("_r")),
		fd_update_fflags());
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

static RZ_INLINE RzILOpBool *fd_is_zero(RzFloatFormat format,
	RzILOpBitVector *value) {
	return AND(IS_ZERO(fd_get_exponent(format, DUP(value))),
		IS_ZERO(fd_get_mantissa(format, value)));
}

static RZ_INLINE RzILOpEffect *fd_lift_minmax(RzFloatFormat format,
	bool maximum, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_FD_FREGS(insn);
	RzILOpFloat *zero_result = ITE(maximum
			? IS_ZERO(fd_get_sign(format, VARL("_bva")))
			: NON_ZERO(fd_get_sign(format, VARL("_bva"))),
		VARL("_a"), VARL("_b"));
	RzILOpFloat *unordered_result = ITE(VARL("_a_is_nan"),
		ITE(VARL("_b_is_nan"), BV2F(format, fd_canonical_qnan(format)), VARL("_b")),
		ITE(VARL("_b_is_nan"), VARL("_a"), VARL("_b")));
	RzILOpFloat *ordinary_result = ITE(
		maximum ? FGE(VARL("_a"), VARL("_b")) : FLE(VARL("_a"), VARL("_b")),
		VARL("_a"), unordered_result);
	RzILOpFloat *result = ITE(
		AND(VARL("_a_is_zero"), VARL("_b_is_zero")), zero_result, ordinary_result);
	return SEQN(12,
		SETL("_bva", fd_get_reg_bv(format, frs1)),
		SETL("_bvb", fd_get_reg_bv(format, frs2)),
		SETL("_a", BV2F(format, VARL("_bva"))),
		SETL("_b", BV2F(format, VARL("_bvb"))),
		SETL("_a_is_nan", fd_is_nan(format, VARL("_bva"))),
		SETL("_b_is_nan", fd_is_nan(format, VARL("_bvb"))),
		SETL("_a_is_zero", fd_is_zero(format, VARL("_bva"))),
		SETL("_b_is_zero", fd_is_zero(format, VARL("_bvb"))),
		SETL("_a_is_snan", fd_is_s_nan(format, VARL("_bva"))),
		SETL("_b_is_snan", fd_is_s_nan(format, VARL("_bvb"))),
		SETG("fcsr", LOGOR(VARG("fcsr"), ITE(OR(VARL("_a_is_snan"), VARL("_b_is_snan")), UN(64, 0x10), UN(64, 0)))),
		fd_set_reg(format, frd, result));
}

static RZ_INLINE RzILOpEffect *fd_lift_compare(RzFloatFormat format,
	FDCompareOperation operation, RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_RD_FREGS(insn);
	bool quiet = operation == FD_COMPARE_EQ;
	RzILOpBool *comparison;
	if (operation == FD_COMPARE_EQ) {
		comparison = FEQ(VARL("_a"), VARL("_b"));
	} else if (operation == FD_COMPARE_LT) {
		comparison = FLT(VARL("_a"), VARL("_b"));
	} else {
		comparison = FLE(VARL("_a"), VARL("_b"));
	}
	return SEQN(8,
		SETL("_bva", fd_get_reg_bv(format, frs1)),
		SETL("_bvb", fd_get_reg_bv(format, frs2)),
		SETL("_a", BV2F(format, VARL("_bva"))),
		SETL("_b", BV2F(format, VARL("_bvb"))),
		SETL("_na", quiet ? fd_is_s_nan(format, VARL("_bva")) : fd_is_nan(format, VARL("_bva"))),
		SETL("_nb", quiet ? fd_is_s_nan(format, VARL("_bvb")) : fd_is_nan(format, VARL("_bvb"))),
		SETG("fcsr", LOGOR(VARG("fcsr"), ITE(OR(VARL("_na"), VARL("_nb")), UN(64, 0x10), UN(64, 0)))),
		riscv_il_set_reg(rd, BOOL_TO_BV(comparison, analysis->bits)));
}

static RZ_INLINE RzILOpBitVector *fd_classification_bit(ut32 bit, RzILOpBool *condition, ut32 xlen) {
	return SHIFTL0(BOOL_TO_BV(condition, xlen), UN(xlen, bit));
}

static RZ_INLINE RzILOpEffect *fd_lift_class(RzFloatFormat format,
	RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_RD_FS_BV(format, insn);
	ut32 xlen = analysis->bits;
	RzILOpBitVector *classification = fd_classification_bit(9,
		AND(VARL("_na"), INV(fd_is_s_nan(format, VARL("_b")))), xlen);
	classification = LOGOR(fd_classification_bit(8, fd_is_s_nan(format, VARL("_b")), xlen), classification);
	classification = LOGOR(fd_classification_bit(7, AND(INV(VARL("_sg")), VARL("_in")), xlen), classification);
	classification = LOGOR(fd_classification_bit(6, AND(INV(VARL("_sg")), VARL("_no")), xlen), classification);
	classification = LOGOR(fd_classification_bit(5, AND(INV(VARL("_sg")), VARL("_su")), xlen), classification);
	classification = LOGOR(fd_classification_bit(4, AND(INV(VARL("_sg")), VARL("_ze")), xlen), classification);
	classification = LOGOR(fd_classification_bit(3, AND(VARL("_sg"), VARL("_ze")), xlen), classification);
	classification = LOGOR(fd_classification_bit(2, AND(VARL("_sg"), VARL("_su")), xlen), classification);
	classification = LOGOR(fd_classification_bit(1, AND(VARL("_sg"), VARL("_no")), xlen), classification);
	classification = LOGOR(fd_classification_bit(0, AND(VARL("_sg"), VARL("_in")), xlen), classification);
	return SEQN(13,
		SETL("_b", value),
		SETL("_ex", fd_get_exponent(format, VARL("_b"))),
		SETL("_mn", fd_get_mantissa(format, VARL("_b"))),
		SETL("_sg", NON_ZERO(fd_get_sign(format, VARL("_b")))),
		SETL("_xff", fd_is_max_exp(format, VARL("_ex"))),
		SETL("_xz", IS_ZERO(VARL("_ex"))),
		SETL("_mz", IS_ZERO(VARL("_mn"))),
		SETL("_na", AND(VARL("_xff"), INV(VARL("_mz")))),
		SETL("_in", AND(VARL("_xff"), VARL("_mz"))),
		SETL("_su", AND(VARL("_xz"), INV(VARL("_mz")))),
		SETL("_ze", AND(VARL("_xz"), VARL("_mz"))),
		SETL("_no", AND(INV(VARL("_xz")), INV(VARL("_xff")))),
		riscv_il_set_reg(rd, classification));
}

static RZ_INLINE RzILOpEffect *fd_lift_fcvt_w(RzFloatFormat format,
	bool unsigned_result, RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_RD_FS_BV(format, insn);
	RzFloatRMode mode = fd_rounding_mode(insn->detail->riscv.rounding_mode);
	RzILOpBitVector *saturated;
	RzILOpBitVector *converted;
	if (unsigned_result) {
		saturated = ITE(OR(AND(fd_is_max_exp(format, VARL("_ex")), NON_ZERO(VARL("_mn"))), INV(VARL("_sg"))),
			UN(32, 0xffffffff), UN(32, 0));
		converted = F2INT(32, mode, VARL("_rounded"));
	} else {
		saturated = ITE(AND(VARL("_sg"), INV(AND(fd_is_max_exp(format, VARL("_ex")), NON_ZERO(VARL("_mn"))))),
			UN(32, 0x80000000), UN(32, 0x7fffffff));
		converted = F2SINT(32, mode, VARL("_rounded"));
	}
	return SEQN(9,
		SETL("_bv", value),
		SETL("_ex", fd_get_exponent(format, VARL("_bv"))),
		SETL("_mn", fd_get_mantissa(format, VARL("_bv"))),
		SETL("_sg", NON_ZERO(fd_get_sign(format, VARL("_bv")))),
		SETL("_f", BV2F(format, VARL("_bv"))),
		SETL("_rounded", FROUND(mode, VARL("_f"))),
		SETL("_nv", fd_fcvt_is_invalid(format, unsigned_result, 32)),
		riscv_il_set_reg(rd, SIGNED(analysis->bits, ITE(VARL("_nv"), saturated, converted))),
		SETG("fcsr", LOGOR(VARG("fcsr"), ITE(VARL("_nv"), UN(64, 0x10), ITE(FNE(VARL("_rounded"), VARL("_f")), UN(64, 0x01), UN(64, 0))))));
}

static RZ_INLINE RzILOpEffect *fd_lift_fcvt_l(RzFloatFormat format,
	bool unsigned_result, RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	REQUIRE_64_BIT(analysis);
	DECODE_FD_RD_FS_BV(format, insn);
	RzFloatRMode mode = fd_rounding_mode(insn->detail->riscv.rounding_mode);
	RzILOpBitVector *saturated;
	RzILOpBitVector *converted;
	if (unsigned_result) {
		saturated = ITE(OR(AND(fd_is_max_exp(format, VARL("_ex")), NON_ZERO(VARL("_mn"))), INV(VARL("_sg"))),
			UN(64, UT64_MAX), UN(64, 0));
		converted = F2INT(64, mode, VARL("_rounded"));
	} else {
		saturated = ITE(AND(VARL("_sg"), INV(AND(fd_is_max_exp(format, VARL("_ex")), NON_ZERO(VARL("_mn"))))),
			UN(64, 0x8000000000000000ULL), UN(64, 0x7fffffffffffffffULL));
		converted = F2SINT(64, mode, VARL("_rounded"));
	}
	return SEQN(9,
		SETL("_bv", value),
		SETL("_ex", fd_get_exponent(format, VARL("_bv"))),
		SETL("_mn", fd_get_mantissa(format, VARL("_bv"))),
		SETL("_sg", NON_ZERO(fd_get_sign(format, VARL("_bv")))),
		SETL("_f", BV2F(format, VARL("_bv"))),
		SETL("_rounded", FROUND(mode, VARL("_f"))),
		SETL("_nv", fd_fcvt_is_invalid(format, unsigned_result, 64)),
		riscv_il_set_reg(rd, ITE(VARL("_nv"), saturated, converted)),
		SETG("fcsr", LOGOR(VARG("fcsr"), ITE(VARL("_nv"), UN(64, 0x10), ITE(FNE(VARL("_rounded"), VARL("_f")), UN(64, 0x01), UN(64, 0))))));
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
	RzFloatRMode mode = fd_rounding_mode(insn->detail->riscv.rounding_mode);
	RzILOpFloat *result = unsigned_source
		? INT2F(format, mode, source)
		: SINT2F(format, mode, source);
	return SEQ3(
		SETL("_r", result),
		fd_set_reg(format, frd, VARL("_r")),
		fd_update_fflags());
}

static RZ_INLINE RzILOpEffect *fd_lift_fcvt_format(RzFloatFormat destination_format,
	RzFloatFormat source_format, cs_insn *insn, ut64 current_addr) {
	DECODE_FD_FD_FS_FORMAT(source_format, insn);
	return SEQ3(
		SETL("_r", FCONVERT(destination_format, fd_rounding_mode(insn->detail->riscv.rounding_mode), source)),
		fd_set_reg_format(destination_format, frd, VARL("_r")),
		fd_update_fflags());
}

static RZ_INLINE RzILOpEffect *fd_lift_fmv_to_x(RzFloatFormat format,
	RzAnalysis *analysis, cs_insn *insn, ut64 current_addr) {
	if (fd_value_width(format) == 64) {
		REQUIRE_64_BIT(analysis);
	}
	DECODE_FD_RD_FS_BV(format, insn);
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
	(void)op;
	(void)size;
	return fd_lift_load(format, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_store(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_store(format, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_add(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_binary(format, FD_BINARY_ADD, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_sub(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_binary(format, FD_BINARY_SUB, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_mul(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_binary(format, FD_BINARY_MUL, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_div(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_binary(format, FD_BINARY_DIV, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_sqrt(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_sqrt(format, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmadd(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_mad(format, FD_MAD_ADD, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmsub(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_mad(format, FD_MAD_SUB, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fnmadd(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_mad(format, FD_MAD_NEGATED_ADD, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fnmsub(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_mad(format, FD_MAD_NEGATED_SUB, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fsgnj(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)analysis;
	(void)op;
	(void)size;
	return fd_lift_sign_injection(format, FD_SIGN_COPY, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fsgnjn(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)analysis;
	(void)op;
	(void)size;
	return fd_lift_sign_injection(format, FD_SIGN_NEGATE, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fsgnjx(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)analysis;
	(void)op;
	(void)size;
	return fd_lift_sign_injection(format, FD_SIGN_XOR, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmin(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)analysis;
	(void)op;
	(void)size;
	return fd_lift_minmax(format, false, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmax(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)analysis;
	(void)op;
	(void)size;
	return fd_lift_minmax(format, true, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_feq(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_compare(format, FD_COMPARE_EQ, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_flt(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_compare(format, FD_COMPARE_LT, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fle(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_compare(format, FD_COMPARE_LE, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fclass(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_class(format, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_w(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_fcvt_w(format, false, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_wu(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_fcvt_w(format, true, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_l(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_fcvt_l(format, false, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_lu(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_fcvt_l(format, true, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_from_w(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_fcvt_from_int(format, FD_INT32_SIGNED, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_from_wu(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_fcvt_from_int(format, FD_INT32_UNSIGNED, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_from_l(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_fcvt_from_int(format, FD_INT64_SIGNED, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_from_lu(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_fcvt_from_int(format, FD_INT64_UNSIGNED, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_format(RzFloatFormat destination_format,
	RzFloatFormat source_format, RzAnalysis *analysis, RzAnalysisOp *op,
	cs_insn *insn, ut64 current_addr, size_t size) {
	(void)analysis;
	(void)op;
	(void)size;
	return fd_lift_fcvt_format(destination_format, source_format, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmv_to_x(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_fmv_to_x(format, analysis, insn, current_addr);
}

RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmv_from_x(RzFloatFormat format,
	RzAnalysis *analysis, RzAnalysisOp *op, cs_insn *insn, ut64 current_addr, size_t size) {
	(void)op;
	(void)size;
	return fd_lift_fmv_from_x(format, analysis, insn, current_addr);
}

#include <rz_il/rz_il_opbuilder_end.h>
