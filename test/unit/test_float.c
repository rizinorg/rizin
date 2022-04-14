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
}

bool all_tests() {
    f32_ieee_format_test();
    mu_end;
}

mu_main(all_tests)
