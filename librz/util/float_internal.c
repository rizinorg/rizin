#include "rz_util.h"
/**
 * \file : Internal implementation of float
 * \brief : Should be included directly in float.c
 */

typedef struct rz_internal_float_t {
    RzFloatFormat r;
    bool sign;
    RzBitVector *exp;
    RzBitVector *mantissa;
} RzInternalFloat;

typedef RzInternalFloat Infloat;

// Conversion between internal float and rz_float
static RZ_OWN RzFloat *rzi_pack_float(RZ_NONNULL RzInternalFloat *internal_f);
static RZ_OWN RzInternalFloat *rzi_unpack_float(RZ_NONNULL RzFloat *rz_float);

// TODO : init
// ......
static RZ_OWN Infloat *rzi_float_new(RzFloatFormat format);
static void rzi_float_free(RZ_NULLABLE Infloat *f);
static bool rzi_float_init(RZ_NONNULL Infloat *f);
static void rzi_float_fini(RZ_NONNULL Infloat *f);
static bool rzi_float_set_from_single(RZ_NONNULL Infloat *f, float value);
static bool rzi_new_from_single(RzFloatFormat format, float value);
static float rzi_float_as_single(RZ_NONNULL Infloat *f);

static RZ_OWN RzBitVector *rzi_single_to_bv(float value) {
    // sizeof float == 4
    RzBitVector *bv = rz_bv_new_from_bytes_le((ut8 *)&value, 0, 32);
    return bv;
}

static RZ_OWN RzBitVector *rzi_doblue_to_bv(double value) {
    RzBitVector *bv = rz_bv_new_from_bytes_le((ut8 *)&value, 0, 64);
    return bv;
}

// getter
static bool rzi_get_sign(Infloat *f);
static RZ_BORROW RzBitVector *rzi_get_exp(Infloat *f);
static RZ_BORROW RzBitVector *rzi_get_mantissa(Infloat *f);

// arithmetic operations
static RZ_OWN Infloat *rzi_float_add(RZ_NONNULL Infloat *left, RZ_NONNULL Infloat *right, RzFloatRMode rmode);
static RZ_OWN Infloat *rzi_float_sub(RZ_NONNULL Infloat *left, RZ_NONNULL Infloat *right, RzFloatRMode rmode);
static RZ_OWN Infloat *rzi_float_mul(RZ_NONNULL Infloat *left, RZ_NONNULL Infloat *right, RzFloatRMode rmode);
static RZ_OWN Infloat *rzi_float_div(RZ_NONNULL Infloat *left, RZ_NONNULL Infloat *right, RzFloatRMode rmode);


RZ_API void test_internal_in_develop(void) {
    float val = 1.5f;
    double dval = 1.5;
    RzBitVector *bv = rzi_single_to_bv(val);
    RzBitVector *d_bv = rzi_doblue_to_bv(dval);
    char *str = rz_bv_as_string(bv);
    char *dstr = rz_bv_as_string(d_bv);
    printf("[FLOAT]1.5f is : %s\n", str);
    printf("[FLOAT]1.5d is : %s\n", dstr);
    free(str);
    free(dstr);
    rz_bv_free(bv);
    rz_bv_free(d_bv);
}
