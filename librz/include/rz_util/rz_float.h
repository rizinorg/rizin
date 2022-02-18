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

typedef struct float_t {
    RzFloatFormat r; ///< An interpretation of bitvector
    RzBitVector *s; ///< The bitvector of float
} RzFloat;

RZ_API void test_internal_in_develop(void);
RZ_API ut32 rz_float_get_format_info(RzFloatFormat format, RzFloatInfo which_info);

#endif //RZ_FLOAT_H
