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
    RZ_FLOAT_INFO_EXP_LEN,  ///< info about length of exponent field, in bits
    RZ_FLOAT_INFO_MAN_LEN, ///< info about length of mantissa field, in bits
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
/// A : MSB of the significand. is_quiet flag
/// quiet_NaN : A == 1
/// signaling_NaN : A == 0
/// PA-RISC and MIPS, use A as is_signal flag. Should reverse the case
typedef enum float_nan_type {
    RZ_FLOAT_NAN_NOT,   ///< not an NaN
    RZ_FLOAT_NAN_QUIET, ///< Quiet NaN
    RZ_FLOAT_NAN_SIG    ///< Signaling NaN
} RzFloatNaNType;

typedef struct float_t {
    RzFloatFormat r; ///< An interpretation of bitvector
    RzBitVector *s; ///< The bitvector of float
    RzFloatException exception; ///< exception of float algorithm
} RzFloat;

RZ_API void test_internal_in_develop(void);
RZ_API ut32 rz_float_get_format_info(RzFloatFormat format, RzFloatInfo which_info);

#endif //RZ_FLOAT_H
