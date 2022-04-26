#include <rz_util.h>
#include "minunit.h"

bool f32_ieee_format_test(void) {
    float val = 1.5f;
    RzFloat *f = rz_float_new_from_single(val);

    char *str = rz_bv_as_string(f->s);
    RzBitVector *exp = rz_float_get_exponent_squashed(f);
    RzBitVector *mantissa = rz_float_get_mantissa_squashed(f);
    char *exp_s = rz_bv_as_string(exp);
    char *m_s = rz_bv_as_string(mantissa);
    bool sign = rz_float_get_sign(f);

    printf("[FLOAT] 1.5f : %s\n", str);
    printf("[FLOAT] pack : 1.5f : %c | %s | %s\n",
           sign ? '1' : '0',
           exp_s,
           m_s);

    rz_bv_free(exp);
    rz_bv_free(mantissa);
    free(exp_s);
    free(m_s);
    free(str);
    rz_float_free(f);
    mu_end;
}

bool f32_ieee_add_test(void) {
    float a = 1.5f;
    float b = 0.25f;
    RzFloat *fa = rz_float_new_from_single(a);
    RzFloat *fb = rz_float_new_from_single(b);
    RzFloat *fz = rz_float_new_from_single(a + b);

    printf("[FLOAT] =========== ADD ============\n");
    /// test precisely add
    RzFloat *fz_calc = rz_float_add_ieee_bin(fa, fb, RZ_FLOAT_RMODE_RNE);
    printf("[DEBUG]After add\n");
    char *fz_str = rz_bv_as_string(fz->s);
    char *fz_calc_str = rz_bv_as_string(fz_calc->s);

    printf("[FLOAT]1.5f + 0.25f : %s\n", fz_str);
    printf("[FLOAT]1.75f : %s\n", fz_calc_str);

    rz_float_free(fa);
    rz_float_free(fb);
    rz_float_free(fz);
    rz_float_free(fz_calc);
    free(fz_str);
    free(fz_calc_str);

    mu_end;
};

bool all_tests() {
    f32_ieee_format_test();
    f32_ieee_add_test();
    mu_end;
}

mu_main(all_tests)
