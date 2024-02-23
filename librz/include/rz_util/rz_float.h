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
#include <rz_util/rz_bitvector.h>

/**
 *
 * Portable float nums in C
 */
RZ_API float rz_types_gen_f32_nan(void);
RZ_API float rz_types_gen_f32_inf(void);
RZ_API double rz_types_gen_f64_nan(void);
RZ_API double rz_types_gen_f64_inf(void);
RZ_API long double rz_types_gen_f128_nan(void);
RZ_API long double rz_types_gen_f128_inf(void);

#define F32_NAN   (rz_types_gen_f32_nan())
#define F32_PINF  (rz_types_gen_f32_inf())
#define F32_NINF  (-rz_types_gen_f32_inf())
#define F64_NAN   (rz_types_gen_f64_nan())
#define F64_PINF  (rz_types_gen_f64_inf())
#define F64_NINF  (-rz_types_gen_f64_inf())
#define F80_NAN   (rz_types_gen_f128_nan())
#define F80_PINF  (rz_types_gen_f128_inf())
#define F80_NINF  (-rz_types_gen_f128_inf())
#define F128_NAN  (rz_types_gen_f128_nan())
#define F128_PINF (rz_types_gen_f128_inf())
#define F128_NINF (-rz_types_gen_f128_inf())

typedef enum rz_float_format_enum {
	/// basic IEEE 754 float format enums
	/// ref : https://en.wikipedia.org/wiki/IEEE_754#Basic_and_interchange_formats
	/// 1. IEEE binary representations, use binary digits to represent float. machine-friendly
	RZ_FLOAT_IEEE754_BIN_32, ///< IEEE-754 binary 32 format (single)
	RZ_FLOAT_IEEE754_BIN_64, ///< IEEE-754 binary64 format (double)
	RZ_FLOAT_IEEE754_BIN_80, ///< IEEE-754 binary80 format
	RZ_FLOAT_IEEE754_BIN_128, ///< IEEE-754 binary128 format
	RZ_FLOAT_IEEE754_BIN_16, ///< half precision

	/// 2. IEEE decimal representations, use decimal digits to represent float precisely
	/// the standard doesn't give an encoding to store decimal digits in binary.
	/// two encoding ways in real-world : Binary integer decimal (BID) and Densely packed decimal (DPD)
	RZ_FLOAT_IEEE754_DEC_64, ///< IEEE-754 decimal64 format, not implemented
	RZ_FLOAT_IEEE754_DEC_128, ///< IEEE-754 decimal128 format, not implemented

	/// may add others in the future
	RZ_FLOAT_UNK ///< End of enums
} RzFloatFormat;

typedef enum rz_float_format_info {
	RZ_FLOAT_INFO_BASE, ///< base of float representation, 2 for binary, 10 for decimal representation
	RZ_FLOAT_INFO_EXP_LEN, ///< info about width of exponent field, in bits
	RZ_FLOAT_INFO_MAN_LEN, ///< info about width of mantissa field, in bits
	RZ_FLOAT_INFO_TOTAL_LEN, ///< info of length of format bv
	RZ_FLOAT_INFO_BIAS ///< exponent bias
} RzFloatInfo;

typedef enum rz_float_round_enum {
	RZ_FLOAT_RMODE_RNE, ///< rounding to nearest, ties to even
	RZ_FLOAT_RMODE_RNA, ///< rounding to nearest, ties away
	RZ_FLOAT_RMODE_RTP, ///< rounding towards positive
	RZ_FLOAT_RMODE_RTN, ///< rounding towards negative
	RZ_FLOAT_RMODE_RTZ, ///< rounding towards zero
	RZ_FLOAT_RMODE_UNK ///< end
} RzFloatRMode; ///< Rounding Mode

typedef enum rz_float_exception_enum {
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
typedef enum rz_float_speciality_enum {
	RZ_FLOAT_SPEC_NOT = 0, ///< not a special num
	RZ_FLOAT_SPEC_ZERO = 1, ///< zero float
	RZ_FLOAT_SPEC_PINF = 2, ///< positive infinity
	RZ_FLOAT_SPEC_NINF = 3, ///< negative infinity
	RZ_FLOAT_SPEC_QNAN = 4, ///< Quiet NaN
	RZ_FLOAT_SPEC_SNAN = 5, ///< Signaling NaN
} RzFloatSpec;

typedef struct rz_float_t {
	RzFloatFormat r; ///< An interpretation of bitvector
	RzBitVector *s; ///< The bitvector of float
	RzFloatException exception; ///< exception of float operations
} RzFloat;

RZ_API ut32 rz_float_get_format_info(RzFloatFormat format, RzFloatInfo which_info);
RZ_API void rz_float_fini(RZ_NONNULL RzFloat *f);
RZ_API void rz_float_free(RZ_NULLABLE RzFloat *f);
RZ_API bool rz_float_init(RZ_NONNULL RzFloat *f, RzFloatFormat format);
RZ_API RZ_OWN RzFloat *rz_float_new(RzFloatFormat format);
RZ_API RZ_OWN RzFloat *rz_float_dup(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzFloat *rz_float_new_from_f32(float value);
RZ_API RZ_OWN RzFloat *rz_float_new_from_f64(double value);
RZ_API RZ_OWN RzFloat *rz_float_new_from_f80(long double value);
RZ_API RZ_OWN RzFloat *rz_float_new_from_f128(long double value);
RZ_API RZ_OWN RzFloat *rz_float_new_from_bv(RZ_NONNULL const RzBitVector *bv);
RZ_API bool rz_float_set_from_f32(RZ_NONNULL RzFloat *f, float value);
RZ_API bool rz_float_set_from_f64(RZ_NONNULL RzFloat *f, double value);
RZ_API bool rz_float_set_from_f80(RZ_NONNULL RzFloat *f, long double value);
RZ_API bool rz_float_set_from_f128(RZ_NONNULL RzFloat *f, long double value);
RZ_API RZ_OWN RzBitVector *rz_float_get_exponent_squashed(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzBitVector *rz_float_get_mantissa_squashed(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzBitVector *rz_float_get_mantissa_stretched(RZ_NONNULL RzFloat *f);
RZ_API bool rz_float_get_sign(RZ_NONNULL RzFloat *f);
RZ_API bool rz_float_set_sign(RZ_NONNULL RzFloat *f, bool new_sign);
RZ_API RZ_OWN RzBitVector *rz_float_get_exponent(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN ut32 rz_float_get_exponent_val(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN st32 rz_float_get_exponent_val_no_bias(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzBitVector *rz_float_get_mantissa(RZ_NONNULL RzFloat *f);
RZ_API bool rz_float_is_negative(RZ_NONNULL RzFloat *f);
RZ_API RzFloatSpec rz_float_detect_spec(RZ_NONNULL RzFloat *f);
RZ_API bool rz_float_is_inf(RZ_NONNULL RzFloat *f);
RZ_API bool rz_float_is_nan(RZ_NONNULL RzFloat *f);
RZ_API bool rz_float_is_zero(RZ_NONNULL RzFloat *f);
RZ_API bool rz_float_is_equal(RZ_NONNULL RzFloat *x, RZ_NONNULL RzFloat *y);
RZ_API RZ_OWN RzFloat *rz_float_neg(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzFloat *rz_float_succ(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzFloat *rz_float_pred(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN st32 rz_float_cmp(RZ_NONNULL RzFloat *x, RZ_NONNULL RzFloat *y);

RZ_API RZ_OWN RzFloat *rz_float_add_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_sub_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_mul_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_div_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_rem_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_mod_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_fma_ieee_bin(RZ_NONNULL RzFloat *a, RZ_NONNULL RzFloat *b, RZ_NONNULL RzFloat *c, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_sqrt_ieee_bin(RZ_NONNULL RzFloat *n, RzFloatRMode mode);

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
RZ_API RZ_OWN RzFloat *rz_float_round_to_integral(RZ_NONNULL RzFloat *f, RzFloatRMode mode);
RZ_API RZ_OWN RzBitVector *rz_float_round_significant(bool sign, RzBitVector *sig, ut32 precision, RzFloatRMode mode, bool *should_inc);
RZ_API RZ_OWN RzFloat *rz_float_round_bv_and_pack(bool sign, st32 exp, RzBitVector *sig, RzFloatFormat format, RzFloatRMode mode);

RZ_API RZ_OWN RzFloat *rz_float_new_from_ut64_as_f64(ut64 value);
RZ_API RZ_OWN RzFloat *rz_float_new_from_ut32_as_f32(ut32 value);
RZ_API RZ_OWN char *rz_float_as_string(RZ_NULLABLE RzFloat *f);
RZ_API RZ_OWN char *rz_float_as_dec_string(RZ_NULLABLE RzFloat *f);
RZ_API RZ_OWN char *rz_float_as_bit_string(RZ_NULLABLE RzFloat *f);
RZ_API RZ_OWN char *rz_float_as_hex_string(RZ_NULLABLE RzFloat *f, bool use_pad);
RZ_API bool rz_float_set_from_inf(RZ_NONNULL RzFloat *f, bool is_negative);
RZ_API bool rz_float_set_from_zero(RZ_NONNULL RzFloat *f);
RZ_API bool rz_float_set_from_qnan(RZ_NONNULL RzFloat *f);
RZ_API bool rz_float_set_from_snan(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzFloat *rz_float_new_inf(RzFloatFormat format, bool is_negative);
RZ_API RZ_OWN RzFloat *rz_float_new_zero(RzFloatFormat format);
RZ_API RZ_OWN RzFloat *rz_float_new_qnan(RzFloatFormat format);
RZ_API RZ_OWN RzFloat *rz_float_new_snan(RzFloatFormat format);

RZ_API RZ_OWN RzFloat *rz_float_cast_float(RZ_NONNULL RzBitVector *bv, RzFloatFormat format, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_cast_sfloat(RZ_NONNULL RzBitVector *bv, RzFloatFormat format, RzFloatRMode mode);
RZ_API RZ_OWN RzBitVector *rz_float_cast_int(RZ_NONNULL RzFloat *f, ut32 length, RzFloatRMode mode);
RZ_API RZ_OWN RzBitVector *rz_float_cast_sint(RZ_NONNULL RzFloat *f, ut32 length, RzFloatRMode mode);
RZ_API RZ_OWN RzFloat *rz_float_convert(RZ_NONNULL RzFloat *f, RzFloatFormat format, RzFloatRMode mode);
#endif // RZ_FLOAT_H
