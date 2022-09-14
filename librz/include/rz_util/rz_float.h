/**
 * \file rz_float.h
 * rizin's float representation based on bitvector
 * current design targets the IEEE-754 float format implementation
 * take berkeley softfloat algorithm as a ref
 * ref : http://www.jhauser.us/arithmetic/SoftFloat.html
 */

#ifndef RZ_FLOAT_H
#define RZ_FLOAT_H
#include <rz_types.h>

typedef enum float_format_enum {
	/// basic IEEE 754 float format enums
	/// ref : https://en.wikipedia.org/wiki/IEEE_754#Basic_and_interchange_formats
	/// 1. IEEE binary representations, use binary digits to represent float. machine-friendly
	RZ_FLOAT_IEEE754_BIN_32, ///< IEEE-754 binary 32 format (single)
	RZ_FLOAT_IEEE754_BIN_64, ///< IEEE-754 binary64 format (double)
	RZ_FLOAT_IEEE754_BIN_128, ///< IEEE-754 binary128 format

	/// 2. IEEE decimal representations, use decimal digits to represent float precisely
	/// the standard doesn't give an encoding to store decimal digits in binary.
	/// two encoding ways in real-world : Binary integer decimal (BID) and Densely packed decimal (DPD)
	RZ_FLOAT_IEEE754_DEC_64, ///< IEEE-754 decimal64 format, not implemented
	RZ_FLOAT_IEEE754_DEC_128, ///< IEEE-754 decimal128 format, not implemented

	/// may add others in the future
	RZ_FLOAT_UNK ///< End of enums
} RzFloatFormat;

typedef enum float_format_info {
	RZ_FLOAT_INFO_BASE, ///< base of float representation, 2 for binary, 10 for decimal representation
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
	RZ_FLOAT_E_INVALID_OP = 1, ///< Invalid operation
	RZ_FLOAT_E_DIV_ZERO = 2, ///< Divide zero
	RZ_FLOAT_E_OVERFLOW = 4, ///< overflow exception
	RZ_FLOAT_E_UNDERFLOW = 8, ///< underflow exception
	RZ_FLOAT_E_INEXACT = 16 ///< calculated result is inexact
} RzFloatException;

/** IEEE-754-2008 special num in float (NaN, Infinity)
 * A : MSB of the mantissa, represents `is_quiet` flag
 * quiet_NaN : A == 1, signaling_NaN : A == 0
 * PA-RISC and MIPS, use A as is_signal flag. Should reverse the case
 */
typedef enum float_speciality_enum {
	RZ_FLOAT_SPEC_NOT = 0, ///< not a special num
	RZ_FLOAT_SPEC_ZERO = 1, ///< zero float
	RZ_FLOAT_SPEC_PINF = 2, ///< positive infinity
	RZ_FLOAT_SPEC_NINF = 3, ///< negative infinity
	RZ_FLOAT_SPEC_QNAN = 4, ///< Quiet NaN
	RZ_FLOAT_SPEC_SNAN = 5, ///< Signaling NaN
} RzFloatSpec;

typedef struct float_t {
	RzFloatFormat r; ///< An interpretation of bitvector
	RzBitVector *s; ///< The bitvector of float
	RzFloatException exception; ///< exception of float operations
} RzFloat;

RZ_IPI ut32 rz_float_get_format_info(RzFloatFormat format, RzFloatInfo which_info);
RZ_API void rz_float_fini(RZ_NONNULL RzFloat *f);
RZ_API void rz_float_free(RZ_NULLABLE RzFloat *f);
RZ_API bool rz_float_init(RZ_NONNULL RzFloat *f, RzFloatFormat format);
RZ_API RZ_OWN RzFloat *rz_float_new(RzFloatFormat format);
RZ_API RZ_OWN RzFloat *rz_float_dup(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzFloat *rz_float_new_from_single(float value);
RZ_API RZ_OWN RzFloat *rz_float_new_from_double(double value);
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

RZ_IPI RZ_OWN RzFloat *rz_float_add_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_IPI RZ_OWN RzFloat *rz_float_sub_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_IPI RZ_OWN RzFloat *rz_float_mul_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_IPI RZ_OWN RzFloat *rz_float_div_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_IPI RZ_OWN RzFloat *rz_float_rem_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_IPI RZ_OWN RzFloat *rz_float_mod_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_IPI RZ_OWN RzFloat *rz_float_fma_ieee_bin(RZ_NONNULL RzFloat *a, RZ_NONNULL RzFloat *b, RZ_NONNULL RzFloat *c, RzFloatRMode mode);
RZ_IPI RZ_OWN RzFloat *rz_float_sqrt_ieee_bin(RZ_NONNULL RzFloat *n, RzFloatRMode mode);

RZ_API RZ_OWN RzFloat *rz_float_add(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_sub(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_mul(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_div(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_rem(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_mod(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_fma(RZ_NONNULL RzFloat *a, RZ_NONNULL RzFloat *b, RZ_NONNULL RzFloat *c, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_sqrt(RZ_NONNULL RzFloat *n, RzFloatRMode mode);

RZ_API RZ_OWN RzFloat *rz_float_trunc(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzFloat *rz_float_abs(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzFloat *rz_float_new_from_hex_as_f64(ut64 hex_value);
RZ_API RZ_OWN RzFloat *rz_float_new_from_hex_as_f32(ut32 hex_value);
RZ_API RZ_OWN char *rz_float_as_string(RZ_NULLABLE RzFloat *f);
RZ_API RZ_OWN char *rz_float_as_bit_string(RZ_NULLABLE RzFloat *f);
RZ_API RZ_OWN char *rz_float_as_hex_string(RZ_NULLABLE RzFloat *f, bool use_pad);
RZ_API RZ_OWN RzFloat *rz_float_new_inf(RzFloatFormat format, bool sign);
RZ_API RZ_OWN RzFloat *rz_float_new_zero(RzFloatFormat format);
RZ_API RZ_OWN RzFloat *rz_float_new_qnan(RzFloatFormat format);
RZ_API RZ_OWN RzFloat *rz_float_new_snan(RzFloatFormat format);

#endif // RZ_FLOAT_H
