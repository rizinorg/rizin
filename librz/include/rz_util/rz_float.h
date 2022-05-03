#ifndef RZ_FLOAT_H
#define RZ_FLOAT_H
#include <rz_types.h>

/**
 * Given the format
 * IEEE 754 only for now
 */
typedef enum float_format_enum {
	RZ_FLOAT_IEEE754_BIN_32,
	RZ_FLOAT_IEEE754_BIN_64,
	RZ_FLOAT_IEEE754_BIN_128,
	RZ_FLOAT_IEEE754_DEC_64,
	RZ_FLOAT_IEEE754_DEC_128,
	RZ_FLOAT_UNK
} RzFloatFormat;

typedef enum float_format_info {
	RZ_FLOAT_INFO_BASE,
	RZ_FLOAT_INFO_EXP_LEN, ///< info about width of exponent field, in bits
	RZ_FLOAT_INFO_MAN_LEN, ///< info about width of mantissa field, in bits
	RZ_FLOAT_INFO_TOTAL_LEN, ///< info of length of format bv
	RZ_FLOAT_INFO_BIAS ///< exponent bias
} RzFloatInfo;

typedef enum float_round_enum {
	RZ_FLOAT_RMODE_RNE, ///< rounding to nearest, ties to even
	RZ_FLOAT_RMODE_RNA, ///< rounding to nearest, ties away
	RZ_FLOAT_RMODE_RTP, ///< rounding towards positive
	RZ_FLOAT_RMODE_RTN, ///< rounding towards negative
	RZ_FLOAT_RMODE_RTZ, ///< rounding towards zero
	RZ_FLOAT_RMODE_UNK ///< end
} RzFloatRMode; ///< Rounding Mode

typedef enum float_exception_enum {
	RZ_FLOAT_E_INVALID_OP = 1,
	RZ_FLOAT_E_DIV_ZERO = 2,
	RZ_FLOAT_E_OVERFLOW = 4,
	RZ_FLOAT_E_UNDERFLOW = 8,
	RZ_FLOAT_E_INEXACT = 16
} RzFloatException;

/// IEEE-754-2008
/// A : MSB of the mantissa. is_quiet flag
/// quiet_NaN : A == 1
/// signaling_NaN : A == 0
/// PA-RISC and MIPS, use A as is_signal flag. Should reverse the case
typedef enum float_speciality_enum {
	RZ_FLOAT_SPEC_NOT = 0, ///< not a special num
	RZ_FLOAT_SPEC_ZERO = 1,
	RZ_FLOAT_SPEC_PINF = 2,
	RZ_FLOAT_SPEC_NINF = 3,
	RZ_FLOAT_SPEC_QNAN = 4, ///< Quiet NaN
	RZ_FLOAT_SPEC_SNAN = 5, ///< Signaling NaN
} RzFloatSpec;

typedef struct float_t {
	RzFloatFormat r; ///< An interpretation of bitvector
	RzBitVector *s; ///< The bitvector of float
	RzFloatException exception; ///< exception of float algorithm
} RzFloat;

RZ_API ut32 rz_float_get_format_info(RzFloatFormat format, RzFloatInfo which_info);
RZ_API void rz_float_fini(RZ_NONNULL RzFloat *f);
RZ_API void rz_float_free(RZ_NULLABLE RzFloat *f);
RZ_API bool rz_float_init(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzFloat *rz_float_new(RzFloatFormat format);
RZ_API RZ_OWN RzFloat *rz_float_dup(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzFloat *rz_float_new_from_single(float value);
RZ_API bool rz_float_set_from_double(RZ_NONNULL RzFloat *f, double value);
RZ_API RZ_OWN RzBitVector *rz_float_get_exponent_squashed(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzBitVector *rz_float_get_mantissa_squashed(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzBitVector *rz_float_get_mantissa_stretched(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzBitVector *rz_float_get_exponent(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzBitVector *rz_float_get_mantissa(RZ_NONNULL RzFloat *f);
RZ_API bool rz_float_get_sign(RZ_NONNULL RzFloat *f);
RZ_API RzFloatSpec rz_float_detect_spec(RZ_NONNULL RzFloat *f);
RZ_API bool rz_float_is_inf(RZ_NONNULL RzFloat *f);
RZ_API bool rz_float_is_nan(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzFloat *rz_float_add_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_sub_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_mul_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_div_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_rem_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_fma_ieee_bin(RZ_NONNULL RzFloat *a, RZ_NONNULL RzFloat *b, RZ_NONNULL RzFloat *c, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_sqrt_ieee_bin(RZ_NONNULL RzFloat *n, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_trunc(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzFloat *rz_float_abs(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzFloat *rz_float_new_from_hex_as_f64(ut64 hex_value);
RZ_API RZ_OWN RzFloat *rz_float_new_from_hex_as_f32(ut64 hex_value);
RZ_API RZ_OWN char *rz_float_as_string(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN char *rz_float_bv_as_string(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN char *rz_float_bv_as_hex_string(RZ_NONNULL RzFloat *f, bool use_pad);
RZ_API RZ_OWN RzFloat *rz_float_new_inf(RzFloatFormat format, bool sign);
RZ_API RZ_OWN RzFloat *rz_float_new_zero(RzFloatFormat format);
RZ_API RZ_OWN RzFloat *rz_float_new_qnan(RzFloatFormat format);

#endif // RZ_FLOAT_H
