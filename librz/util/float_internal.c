#include "rz_util.h"
/**
 * \file : Internal implementation of float
 * \brief : Should be included directly in float.c
 */

typedef struct rz_internal_float_t {
    RzFloatFormat format;
    bool sign;
    RzBitVector *exp;
    RzBitVector *mantissa;
} RzInternalFloat;
typedef RzInternalFloat Infloat;

// Conversion between internal float and rz_float
static RZ_OWN RzFloat *rzi_pack_float(RZ_NONNULL RzInternalFloat *internal_f, RzFloatFormat format);
static RZ_OWN RzInternalFloat *rzi_unpack_float(RZ_NONNULL RzFloat *rz_float);

// TODO : init
// ......
// TODO : remove these two
static RZ_OWN RzBitVector *rzi_single_to_bv(float value) {
    // sizeof float == 4
    RzBitVector *bv = rz_bv_new_from_bytes_le((ut8 *)&value, 0, 32);
    return bv;
}

static RZ_OWN RzBitVector *rzi_doblue_to_bv(double value) {
    RzBitVector *bv = rz_bv_new_from_bytes_le((ut8 *)&value, 0, 64);
    return bv;
}

static void rzi_float_fini(RZ_NONNULL Infloat *f) {
    rz_return_if_fail(f);
    rz_bv_free(f->exp);
    rz_bv_free(f->mantissa);
    memset(f, 0, sizeof(Infloat));
}

static void rzi_float_free(RZ_NULLABLE Infloat *f) {
    if (!f) {
        return;
    }
    rzi_float_fini(f);
    free(f);
}

static bool rzi_float_init(RZ_NONNULL Infloat *f) {
    rz_return_val_if_fail(f, false);
    RzFloatFormat format = f->format;
    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);

    f->exp = rz_bv_new(exp_len);
    f->mantissa = rz_bv_new(man_len);
    if (!f->exp || !f->mantissa) {
        rzi_float_fini(f);
        return false;
    }

    f->sign = 0;
    return true;
}

static RZ_OWN Infloat *rzi_float_new(RzFloatFormat format) {
    Infloat *f = RZ_NEW(Infloat);
    if (!f) {
        return NULL;
    }
    f->format = format;

    if (!rzi_float_init(f)) {
        free(f);
        return NULL;
    }

    return f;
}

static bool rzi_float_set_from_single(RZ_NONNULL Infloat *f, float value) {
    rz_return_val_if_fail(f, false);

    ut32 exponent_len = rz_float_get_format_info(f->format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 mantissa_len = rz_float_get_format_info(f->format, RZ_FLOAT_INFO_MAN_LEN);

    f->sign = value < 0 ? 1 : 0;
    rz_bv_set_from_bytes_le(f->exp, (ut8 *)&value, mantissa_len, exponent_len);
    rz_bv_set_from_bytes_le(f->mantissa, (ut8 *)&value, 0, mantissa_len);

    return f;
}

static Infloat *rzi_float_new_from_single(float value) {
    Infloat *infloat = rzi_float_new(RZ_FLOAT_IEEE754_BIN_32);
    if (!infloat) {
        RZ_LOG_ERROR("Error in new single float\n");
        return NULL;
    }

    if (!rzi_float_set_from_single(infloat, value)){
        RZ_LOG_ERROR("Failed to set float from single type\n");
        rzi_float_free(infloat);
        return NULL;
    }
    return infloat;
}

static float rzi_float_as_single(RZ_NONNULL Infloat *f);

// arithmetic operations
static RZ_OWN Infloat *rzi_float_add(RZ_NONNULL Infloat *left, RZ_NONNULL Infloat *right, RzFloatRMode rmode);
static RZ_OWN Infloat *rzi_float_sub(RZ_NONNULL Infloat *left, RZ_NONNULL Infloat *right, RzFloatRMode rmode);
static RZ_OWN Infloat *rzi_float_mul(RZ_NONNULL Infloat *left, RZ_NONNULL Infloat *right, RzFloatRMode rmode);
static RZ_OWN Infloat *rzi_float_div(RZ_NONNULL Infloat *left, RZ_NONNULL Infloat *right, RzFloatRMode rmode);


RZ_API void test_internal_in_develop(void) {
    float val = 1.5f;
    double dval = 1.5;

    Infloat *f = rzi_float_new_from_single(1.5f);
    char *exponent_str = rz_bv_as_string(f->exp);
    char *mantissa_str = rz_bv_as_string(f->mantissa);
    bool sign = f->sign;

    RzBitVector *bv = rz_bv_new(32);
    rz_bv_set_from_bytes_le(bv, (ut8 *)&val, 29, 1);
    char *compare_str = rz_bv_as_string(bv);

    /// should be +|0|01111111|10000000000000000000000
    printf("[FLOAT]1.5f is : %c|%c|%s|%s\n",
           sign ? '-' : '+',
           sign ? '1' : '0',
           exponent_str,
           mantissa_str
           );

    printf("[FLOAT]1.5f compare str : %s\n",
           compare_str);

    free(exponent_str);
    free(mantissa_str);
    free(compare_str);

    rzi_float_free(f);
}
