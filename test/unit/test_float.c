// SPDX-FileCopyrightText: 2022 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

#define is_equal_bv(x, y)    (!rz_bv_cmp(x, y))
#define is_equal_float(x, y) (!rz_bv_cmp((x)->s, (y)->s))

void print_float(RzFloat *f) {
	char *str = rz_float_as_string(f);
	puts(str);
	free(str);
}

bool f32_ieee_format_test(void) {
	float val = 1.5f;
	RzFloat *f = rz_float_new_from_f32(val);

	RzBitVector *exp_squashed = rz_float_get_exponent_squashed(f);
	RzBitVector *exp = rz_float_get_exponent(f);
	RzBitVector *mantissa_squashed = rz_float_get_mantissa_squashed(f);
	RzBitVector *mantissa = rz_float_get_mantissa(f);
	RzBitVector *mantissa_stretched = rz_float_get_mantissa_stretched(f);
	bool is_neg = rz_float_is_negative(f);

	// 1.5f, 32-bit float
	mu_assert_streq_free(rz_bv_as_string(f->s), "00111111110000000000000000000000", "string bit value of 32-bit float");

	mu_assert_streq_free(rz_bv_as_string(exp_squashed), "01111111", "string bit value of exponent field only");
	mu_assert_streq_free(rz_bv_as_string(exp), "00000000000000000000000001111111", "string bit value (32-bit) of exponent");

	mu_assert_streq_free(rz_bv_as_string(mantissa_squashed), "10000000000000000000000", "string bit value of mantissa field only");
	mu_assert_streq_free(rz_bv_as_string(mantissa), "00000000010000000000000000000000", "string bit value (32-bit) of mantissa");
	mu_assert_streq_free(rz_bv_as_string(mantissa_stretched), "0000000000000000000000000000000000000000010000000000000000000000",
		"string bit value of mantissa, double the length");

	mu_assert_false(is_neg, "negative sign bit of 32-bit float");

	rz_bv_free(exp_squashed);
	rz_bv_free(exp);
	rz_bv_free(mantissa);
	rz_bv_free(mantissa_squashed);
	rz_bv_free(mantissa_stretched);
	rz_float_free(f);
	mu_end;
}

bool rz_float_detect_spec_test(void) {
	RzFloatFormat format = RZ_FLOAT_IEEE754_BIN_64;
	RzFloat *qnan = rz_float_new_qnan(format);
	RzFloat *pinf = rz_float_new_inf(format, false);
	RzFloat *ninf = rz_float_new_inf(format, true);
	RzFloat *zero = rz_float_new_zero(format);
	RzFloat *snan = rz_float_new_snan(format);
	RzFloat *cst = rz_float_new_from_f64(42.0);

	RzFloatSpec qnan_type = rz_float_detect_spec(qnan);
	RzFloatSpec pinf_type = rz_float_detect_spec(pinf);
	RzFloatSpec ninf_type = rz_float_detect_spec(ninf);
	RzFloatSpec zero_type = rz_float_detect_spec(zero);
	RzFloatSpec cst_type = rz_float_detect_spec(cst);
	RzFloatSpec snan_type = rz_float_detect_spec(snan);

	mu_assert_true(qnan_type == RZ_FLOAT_SPEC_QNAN, "detect quiet NaN test");
	mu_assert_true(pinf_type == RZ_FLOAT_SPEC_PINF, "detect positive infinity test");
	mu_assert_true(ninf_type == RZ_FLOAT_SPEC_NINF, "detect negative infinity test");
	mu_assert_true(zero_type == RZ_FLOAT_SPEC_ZERO, "detect zero test");
	mu_assert_true(cst_type == RZ_FLOAT_SPEC_NOT, "detect normal float num test");
	mu_assert_true(snan_type == RZ_FLOAT_SPEC_SNAN, "detect signal NaN test");

	rz_float_free(qnan);
	rz_float_free(pinf);
	rz_float_free(ninf);
	rz_float_free(zero);
	rz_float_free(cst);
	rz_float_free(snan);

	mu_end;
}

bool f32_ieee_add_test(void) {

	RzFloat *f0 = rz_float_new_from_f32(1.5f);

	// no rounding needed 1.5f + 0.25f -> precise result
	RzFloat *f1 = rz_float_new_from_f32(0.25f);
	RzFloat *f2 = rz_float_new_from_f32(1.5f + 0.25f);
	RzFloat *f2_calc = rz_float_add(f0, f1, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(f2->s, f2_calc->s), "test calculating bv value of 1.5f + 0.25f");

	RzFloat *f3 = rz_float_new_from_f32(0.3f);
	RzFloat *f4 = rz_float_new_from_f32(1.5f + 0.3f);
	RzFloat *f4_calc = rz_float_add(f0, f3, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(f4->s, f4_calc->s), "test calculating bv value of 1.5f + 0.3f");

	RzFloat *f5 = rz_float_new_from_f32(1.7f);
	RzFloat *f6 = rz_float_new_from_f32(1.7f + 0.3f);
	RzFloat *f6_calc = rz_float_add(f3, f5, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(f6->s, f6_calc->s), "test calculating bv value of 1.7f + 0.3f");

	RzFloat *f7 = rz_float_new_from_f32(0.3f + 0.25f);
	RzFloat *f7_calc = rz_float_add(f1, f3, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(f7->s, f7_calc->s), "test calculating bv value of 0.25f + 0.3f");

	RzFloat *subf1 = rz_float_new_from_f32(6.8881E-41f);
	RzFloat *subf2 = rz_float_new_from_f32(7.29e-43f);
	RzFloat *subf3 = rz_float_new_from_f32(1.14514f);

	// subf1 + subf2 = 6.961E-41f
	RzFloat *res1 = rz_float_new_from_f32(6.961E-41f);
	RzFloat *res1_calc = rz_float_add(subf1, subf2, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(res1->s, res1_calc->s), "test subnormal add 6.8881E-41f + 7.29e-43f");

	RzFloat *res2 = rz_float_new_from_f32(1.14514f);
	RzFloat *res2_calc = rz_float_add(subf1, subf3, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(res2->s, res2_calc->s), "test subnormal and normal 1.14514f + 6.8881E-41f");

	rz_float_free(f0);
	rz_float_free(f1);
	rz_float_free(f2);
	rz_float_free(f2_calc);
	rz_float_free(f3);
	rz_float_free(f4);
	rz_float_free(f4_calc);
	rz_float_free(f5);
	rz_float_free(f6);
	rz_float_free(f6_calc);
	rz_float_free(f7);
	rz_float_free(f7_calc);
	rz_float_free(subf1);
	rz_float_free(subf2);
	rz_float_free(subf3);
	rz_float_free(res1);
	rz_float_free(res1_calc);
	rz_float_free(res2);
	rz_float_free(res2_calc);

	mu_end;
}

bool f32_ieee_sub_test(void) {
	RzFloat *f0 = rz_float_new_from_f32(1.5f);

	// no rounding needed 1.5f + 0.25f -> precise result
	RzFloat *f1 = rz_float_new_from_f32(0.25f);
	RzFloat *f2 = rz_float_new_from_f32(1.5f - 0.25f);
	RzFloat *f2_calc = rz_float_sub(f0, f1, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(f2->s, f2_calc->s), "test calculating bv value of 1.5f - 0.25f");

	RzFloat *f3 = rz_float_new_from_f32(1.3f);
	RzFloat *f4 = rz_float_new_from_f32(1.7f);
	RzFloat *f5 = rz_float_new_from_f32(1.3f - 1.7f);
	RzFloat *f5_calc = rz_float_sub(f3, f4, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(f5->s, f5_calc->s), "test calculating bv value of 1.3f - 1.7f");
	RzFloat *f6 = rz_float_new_from_f32(1.7f - 1.3f);
	RzFloat *f6_calc = rz_float_sub(f4, f3, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(f6->s, f6_calc->s), "test calculating bv value of 1.7f - 1.3f");

	RzFloat *f7 = rz_float_new_from_f32(0.3f);
	RzFloat *f8 = rz_float_new_from_f32(1.5f - 0.3f);
	RzFloat *f8_calc = rz_float_sub(f0, f7, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(f8->s, f8_calc->s), "test calculating bv value of 1.5f - 0.3f");

	RzFloat *subf1 = rz_float_new_from_f32(6.8881E-41f);
	RzFloat *subf2 = rz_float_new_from_f32(7.29e-43f);
	RzFloat *subf3 = rz_float_new_from_f32(1.14514f);

	// subf1 + subf2 = 6.961E-41f
	RzFloat *res1 = rz_float_new_from_f32(6.8152E-41f);
	RzFloat *res1_calc = rz_float_sub(subf1, subf2, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(res1->s, res1_calc->s), "test subnormal add 6.8881E-41f - 7.29e-43f");

	RzFloat *res2 = rz_float_new_from_f32(1.14514f);
	RzFloat *res2_calc = rz_float_sub(subf3, subf1, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(res2->s, res2_calc->s), "test subnormal and normal 1.14514f - 6.8881E-41f");

	rz_float_free(f0);
	rz_float_free(f1);
	rz_float_free(f2);
	rz_float_free(f2_calc);
	rz_float_free(f3);
	rz_float_free(f4);
	rz_float_free(f5);
	rz_float_free(f5_calc);
	rz_float_free(f6);
	rz_float_free(f6_calc);
	rz_float_free(f7);
	rz_float_free(f8);
	rz_float_free(f8_calc);
	rz_float_free(subf1);
	rz_float_free(subf2);
	rz_float_free(subf3);
	rz_float_free(res1);
	rz_float_free(res1_calc);
	rz_float_free(res2);
	rz_float_free(res2_calc);
	mu_end;
}

bool f32_ieee_mul_test(void) {
	RzFloat *f1 = rz_float_new_from_f32(11.1f);
	RzFloat *f2 = rz_float_new_from_f32(2.37f);
	RzFloat *f1f2 = rz_float_new_from_f32(26.307f);
	RzFloat *calc_f1f2 = rz_float_mul(f1, f2, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(f1f2->s, calc_f1f2->s), "Compare Mul of 11.1 * 2.37 == 26.307 ?");

	RzFloat *subf1 = rz_float_new_from_f32(4.555041E-39f);
	RzFloat *subf2 = rz_float_new_from_f32(2.350989E-39f);
	RzFloat *f2subf1 = rz_float_new_from_f32(1.0795446E-38f);
	RzFloat *calc_f2subf1 = rz_float_mul(subf1, f2, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(f2subf1->s, calc_f2subf1->s), "Normal * Sub-normal");

	RzFloat *subf1subf2 = rz_float_new_from_f32(0.0f);
	RzFloat *calc_subf1subf2 = rz_float_mul(subf1, subf2, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(subf1subf2->s, calc_subf1subf2->s), "Sub-normal * Sub-normal");

	rz_float_free(f1);
	rz_float_free(f2);
	rz_float_free(f1f2);
	rz_float_free(calc_f1f2);
	rz_float_free(subf1);
	rz_float_free(subf2);
	rz_float_free(f2subf1);
	rz_float_free(calc_f2subf1);
	rz_float_free(subf1subf2);
	rz_float_free(calc_subf1subf2);
	mu_end;
}

bool f32_ieee_div_test(void) {
	RzFloat *f1 = rz_float_new_from_f32(11.1f);
	RzFloat *f2 = rz_float_new_from_f32(2.37f);
	RzFloat *div1 = rz_float_new_from_f32(4.6835446f);
	RzFloat *calc_div1 = rz_float_div(f1, f2, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(div1->s, calc_div1->s), "Compare Div of 11.1 / 2.37 == 4.6835446 ?");

	RzFloat *f3 = rz_float_new_from_f32(1111.1f);
	RzFloat *div2 = rz_float_new_from_f32(2.1330214E-3f);
	RzFloat *calc_div2 = rz_float_div(f2, f3, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(div2->s, calc_div2->s), "Div 2.37 / 1111.1 == 2.1330214E-3 ?");

	RzFloat *subf1 = rz_float_new_from_f32(4.555041E-39f);
	RzFloat *subf2 = rz_float_new_from_f32(2.350989E-39f);
	RzFloat *div3 = rz_float_new_from_f32(1.9374998f);
	RzFloat *calc_div3 = rz_float_div(subf1, subf2, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(div3->s, calc_div3->s), "Div sub-normal test 1");

	RzFloat *div4 = rz_float_new_from_f32(0.5161291f);
	RzFloat *calc_div4 = rz_float_div(subf2, subf1, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_bv(div4->s, calc_div4->s), "Div sub-normal test 2");

	rz_float_free(f1);
	rz_float_free(f2);
	rz_float_free(div1);
	rz_float_free(calc_div1);
	rz_float_free(f3);
	rz_float_free(div2);
	rz_float_free(calc_div2);
	rz_float_free(subf1);
	rz_float_free(subf2);
	rz_float_free(div3);
	rz_float_free(div4);
	rz_float_free(calc_div3);
	rz_float_free(calc_div4);
	mu_end;
}

bool f80_ieee_div_test(void) {
#if (__i386__ || __x86_64__) && !__WINDOWS__
	RzFloat *x_f80 = rz_float_new_from_f80(1.l);
	RzFloat *y_f80 = rz_float_new_from_f80(-0.384677154767621320985l);
	RzFloat *quot_f80 = rz_float_div(x_f80, y_f80, RZ_FLOAT_RMODE_RNE);
	RzFloat *expected_f80 = rz_float_new_from_f80(-2.59958250082224806804l);
	mu_assert_false(rz_float_cmp(quot_f80, expected_f80), "Divide 80-bit floats");

	rz_float_free(x_f80);
	rz_float_free(y_f80);
	rz_float_free(quot_f80);
	rz_float_free(expected_f80);
#endif
	mu_end;
}

bool rz_float_trunc_test(void) {
	RzFloat *f1 = rz_float_new_from_f32(1.111f);
	RzFloat *f2 = rz_float_new_from_f32(234.12345f);
	RzFloat *f3 = rz_float_new_from_f32(2.9998f);
	RzFloat *f4 = rz_float_new_from_f32(0.9754f);
	RzFloat *f5 = rz_float_new_from_f32(3.4028236E25f);

	RzFloat *expect1 = rz_float_new_from_f32(1.0f);
	RzFloat *expect2 = rz_float_new_from_f32(234.0f);
	RzFloat *expect3 = rz_float_new_from_f32(2.0f);
	RzFloat *expect4 = rz_float_new_from_f32(0.0f);
	RzFloat *expect5 = rz_float_new_from_f32(3.4028236E25f);

	RzFloat *trunc1 = rz_float_trunc(f1);
	RzFloat *trunc2 = rz_float_trunc(f2);
	RzFloat *trunc3 = rz_float_trunc(f3);
	RzFloat *trunc4 = rz_float_trunc(f4);
	RzFloat *trunc5 = rz_float_trunc(f5);

	mu_assert_true(is_equal_bv(expect1->s, trunc1->s), "Truncate Test 1");
	mu_assert_true(is_equal_bv(expect2->s, trunc2->s), "Truncate Test 2");
	mu_assert_true(is_equal_bv(expect3->s, trunc3->s), "Truncate Test 3");
	mu_assert_true(is_equal_bv(expect4->s, trunc4->s), "Truncate Test 4");
	mu_assert_true(is_equal_bv(expect5->s, trunc5->s), "Truncate Test 5");

	rz_float_free(f1);
	rz_float_free(f2);
	rz_float_free(f3);
	rz_float_free(f4);
	rz_float_free(f5);

	rz_float_free(expect1);
	rz_float_free(expect2);
	rz_float_free(expect3);
	rz_float_free(expect4);
	rz_float_free(expect5);

	rz_float_free(trunc1);
	rz_float_free(trunc2);
	rz_float_free(trunc3);
	rz_float_free(trunc4);
	rz_float_free(trunc5);

	mu_end;
}

bool rz_float_abs_test(void) {
	RzFloat *pf = rz_float_new_from_f32(+1.1123f);
	RzFloat *nf = rz_float_new_from_f32(-1.1123f);
	RzFloat *pf_abs = rz_float_abs(pf);
	RzFloat *nf_abs = rz_float_abs(nf);

	mu_assert_true(is_equal_bv(pf->s, pf_abs->s), "make abs test for positive");
	mu_assert_true(is_equal_bv(nf_abs->s, pf->s), "make abs test for negative");

	rz_float_free(pf);
	rz_float_free(nf);
	rz_float_free(pf_abs);
	rz_float_free(nf_abs);
	mu_end;
}

bool rz_float_new_from_hex_test() {
	RzFloat *hex1 = rz_float_new_from_ut32_as_f32(0xC00007EF);
	RzFloat *expect1 = rz_float_new_from_f32(-2.0004842f);
	RzFloat *hex2 = rz_float_new_from_ut32_as_f32(0x3DFFF7BF);
	RzFloat *expect2 = rz_float_new_from_f32(0.12498426f);

	mu_assert_true(is_equal_float(hex1, expect1), "new from hex 1");
	mu_assert_true(is_equal_float(hex2, expect2), "new from hex 1");

	rz_float_free(hex1);
	rz_float_free(expect1);
	rz_float_free(hex2);
	rz_float_free(expect2);

	mu_end;
}

bool f32_ieee_fma_test(void) {
	RzFloat *a1, *b1, *c1, *expect1, *z1;
	a1 = rz_float_new_from_ut32_as_f32(0x2B6C2D9D);
	b1 = rz_float_new_from_ut32_as_f32(0xCB800000);
	c1 = rz_float_new_from_ut32_as_f32(0x4C440D9E);
	expect1 = rz_float_new_from_ut32_as_f32(0x4C440D9E);
	z1 = rz_float_fma(a1, b1, c1, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_float(expect1, z1), "Fused Mul Add test 1");

	RzFloat *a2, *b2, *c2, *expect2, *z2;
	a2 = rz_float_new_from_ut32_as_f32(0xBD0134F8);
	b2 = rz_float_new_from_ut32_as_f32(0x3F7FFFFE);
	c2 = rz_float_new_from_ut32_as_f32(0xC1C800D3);
	expect2 = rz_float_new_from_ut32_as_f32(0xC1C8416D);
	z2 = rz_float_fma(a2, b2, c2, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_float(expect2, z2), "Fused Mul Add test 2");

	RzFloat *a3, *b3, *c3, *expect3, *z3;
	a3 = rz_float_new_from_ut32_as_f32(0x6F7FFF7C);
	b3 = rz_float_new_from_ut32_as_f32(0x3F1DD0B8);
	c3 = rz_float_new_from_ut32_as_f32(0x81000000);
	expect3 = rz_float_new_from_ut32_as_f32(0x6F1DD067);
	z3 = rz_float_fma(a3, b3, c3, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_float(expect3, z3), "Fused Mul Add test 3");

	RzFloat *a4, *b4, *c4, *expect4, *z4;
	a4 = rz_float_new_from_f32(-1.5f);
	b4 = rz_float_new_from_f32(2.0f);
	c4 = rz_float_new_from_f32(4.0f);
	expect4 = rz_float_new_from_f32(1.0f);
	z4 = rz_float_fma(a4, b4, c4, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_float(expect4, z4), "Fused Mul Add test 4");

	rz_float_free(a1);
	rz_float_free(b1);
	rz_float_free(c1);
	rz_float_free(z1);
	rz_float_free(expect1);

	rz_float_free(a2);
	rz_float_free(b2);
	rz_float_free(c2);
	rz_float_free(z2);
	rz_float_free(expect2);

	rz_float_free(a3);
	rz_float_free(b3);
	rz_float_free(c3);
	rz_float_free(z3);
	rz_float_free(expect3);

	rz_float_free(a4);
	rz_float_free(b4);
	rz_float_free(c4);
	rz_float_free(z4);
	rz_float_free(expect4);
	mu_end;
}

bool f32_ieee_round_test(void) {
	RzFloat *a = rz_float_new_from_ut32_as_f32(0xC00007EF);
	RzFloat *b = rz_float_new_from_ut32_as_f32(0x3DFFF7BF);

	RzFloat *expect_rne_rna_rtp_rtz = rz_float_new_from_ut32_as_f32(0xBFF01062);
	RzFloat *expect_rtn = rz_float_new_from_ut32_as_f32(0xBFF01063);

	RzFloat *rne = rz_float_add(a, b, RZ_FLOAT_RMODE_RNE);
	RzFloat *rna = rz_float_add(a, b, RZ_FLOAT_RMODE_RNA);
	RzFloat *rtp = rz_float_add(a, b, RZ_FLOAT_RMODE_RTP);
	RzFloat *rtn = rz_float_add(a, b, RZ_FLOAT_RMODE_RTN);
	RzFloat *rtz = rz_float_add(a, b, RZ_FLOAT_RMODE_RTZ);

	mu_assert_true(is_equal_float(rne, expect_rne_rna_rtp_rtz), "RNE test");
	mu_assert_true(is_equal_float(rna, expect_rne_rna_rtp_rtz), "RNA test");
	mu_assert_true(is_equal_float(rtp, expect_rne_rna_rtp_rtz), "RTP test");
	mu_assert_true(is_equal_float(rtz, expect_rne_rna_rtp_rtz), "RTZ test");
	mu_assert_true(is_equal_float(rtn, expect_rtn), "RTN test");

	rz_float_free(rne);
	rz_float_free(rna);
	rz_float_free(rtp);
	rz_float_free(rtz);
	rz_float_free(rtn);
	rz_float_free(expect_rne_rna_rtp_rtz);
	rz_float_free(expect_rtn);
	rz_float_free(a);
	rz_float_free(b);
	mu_end;
}

bool f32_ieee_sqrt_test(void) {
	RzFloat *a1, *z1, *expect1;
	a1 = rz_float_new_from_f32(4.0f);
	expect1 = rz_float_new_from_f32(2.0f);
	z1 = rz_float_sqrt(a1, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_float(z1, expect1), "test sqrt 1");
	rz_float_free(a1);
	rz_float_free(z1);
	rz_float_free(expect1);

	RzFloat *a2, *z2, *expect2;
	a2 = rz_float_new_from_f32(0.0144f);
	expect2 = rz_float_new_from_f32(0.12f);
	z2 = rz_float_sqrt(a2, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_float(z2, expect2), "test sqrt 2");
	rz_float_free(a2);
	rz_float_free(z2);
	rz_float_free(expect2);

	RzFloat *a3, *z3, *expect3;
	a3 = rz_float_new_from_f32(42.0f);
	expect3 = rz_float_new_from_f32(6.480740547180176f);
	z3 = rz_float_sqrt(a3, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_float(z3, expect3), "test sqrt 3");
	rz_float_free(a3);
	rz_float_free(z3);
	rz_float_free(expect3);
	mu_end;
}

bool f32_ieee_special_num_test(void) {
	// TODO : consider NaN in more cases and don't forget sign.
	RzFloat *nan = rz_float_new_qnan(RZ_FLOAT_IEEE754_BIN_32);
	RzFloat *pinf = rz_float_new_inf(RZ_FLOAT_IEEE754_BIN_32, false);
	RzFloat *ninf = rz_float_new_inf(RZ_FLOAT_IEEE754_BIN_32, true);
	RzFloat *zero = rz_float_new_zero(RZ_FLOAT_IEEE754_BIN_32);
	RzFloat *cst_num = rz_float_new_from_f32(2.0f);

	// Basic Operations
	// 1. Add
	RzFloat *add1 = rz_float_add(nan, cst_num, RZ_FLOAT_RMODE_RNE);
	RzFloat *add2 = rz_float_add(pinf, cst_num, RZ_FLOAT_RMODE_RNE);
	RzFloat *add3 = rz_float_add(nan, pinf, RZ_FLOAT_RMODE_RNE);
	RzFloat *add4 = rz_float_add(pinf, ninf, RZ_FLOAT_RMODE_RNE);
	RzFloat *add5 = rz_float_add(zero, cst_num, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(rz_float_is_nan(add1), "Add NaN and Const");
	mu_assert_true(rz_float_is_inf(add2), "Add Inf and Const");
	mu_assert_true(rz_float_is_nan(add3), "Add NaN and Inf");
	mu_assert_true(rz_float_is_nan(add4), "Add +Inf and -Inf");
	mu_assert_true(is_equal_float(add5, cst_num), "Add 0 and Const");

	rz_float_free(add1);
	rz_float_free(add2);
	rz_float_free(add3);
	rz_float_free(add4);
	rz_float_free(add5);

	// 2. Sub
	RzFloat *sub1 = rz_float_sub(nan, cst_num, RZ_FLOAT_RMODE_RNE);
	RzFloat *sub2 = rz_float_sub(pinf, cst_num, RZ_FLOAT_RMODE_RNE);
	RzFloat *sub3 = rz_float_sub(nan, pinf, RZ_FLOAT_RMODE_RNE);
	RzFloat *sub4 = rz_float_sub(ninf, ninf, RZ_FLOAT_RMODE_RNE);
	RzFloat *sub5 = rz_float_sub(cst_num, zero, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(rz_float_is_nan(sub1), "Sub NaN and Const");
	mu_assert_true(rz_float_is_inf(sub2), "Sub Inf and Const");
	mu_assert_true(rz_float_is_nan(sub3), "Sub NaN and Inf");
	mu_assert_true(rz_float_is_nan(sub4), "Sub +Inf and +Inf");
	mu_assert_true(is_equal_float(sub5, cst_num), "Sub Const and 0");

	rz_float_free(sub1);
	rz_float_free(sub2);
	rz_float_free(sub3);
	rz_float_free(sub4);
	rz_float_free(sub5);

	// 3. MUL
	RzFloat *mul1 = rz_float_mul(nan, cst_num, RZ_FLOAT_RMODE_RNE);
	RzFloat *mul2 = rz_float_mul(pinf, cst_num, RZ_FLOAT_RMODE_RNE);
	RzFloat *mul3 = rz_float_mul(zero, cst_num, RZ_FLOAT_RMODE_RNE);
	RzFloat *mul4 = rz_float_mul(pinf, zero, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(rz_float_is_nan(mul1), "Mul NaN and Const");
	mu_assert_true(rz_float_is_inf(mul2), "Mul Inf and Const");
	mu_assert_true(is_equal_float(mul3, zero), "Mul Zero and Const");
	mu_assert_true(rz_float_is_nan(mul4), "Mul +Inf and 0");

	rz_float_free(mul1);
	rz_float_free(mul2);
	rz_float_free(mul3);
	rz_float_free(mul4);

	// 4. DIV
	RzFloat *div1 = rz_float_div(pinf, cst_num, RZ_FLOAT_RMODE_RNE);
	RzFloat *div2 = rz_float_div(pinf, ninf, RZ_FLOAT_RMODE_RNE);
	RzFloat *div3 = rz_float_div(zero, zero, RZ_FLOAT_RMODE_RNE);
	RzFloat *div4 = rz_float_div(zero, cst_num, RZ_FLOAT_RMODE_RNE);
	RzFloat *div5 = rz_float_div(cst_num, zero, RZ_FLOAT_RMODE_RNE);
	RzFloat *div6 = rz_float_div(cst_num, pinf, RZ_FLOAT_RMODE_RNE);

	mu_assert_true(rz_float_is_inf(div1), "Inf / Non-inf => Inf ");
	mu_assert_true(rz_float_is_nan(div2) && (div2->exception & RZ_FLOAT_E_INVALID_OP),
		"Inf / Inf => invalid");
	mu_assert_true(rz_float_is_nan(div3) && (div3->exception & RZ_FLOAT_E_INVALID_OP),
		"0 / 0 => invalid");
	mu_assert_true(is_equal_float(div4, zero), "0 / Non-zero => 0");
	mu_assert_true(rz_float_is_inf(div5), "Non-zero / 0 => Inf");
	mu_assert_true(is_equal_float(div6, zero), "Non-inf / Inf => zero");

	rz_float_free(div1);
	rz_float_free(div2);
	rz_float_free(div3);
	rz_float_free(div4);
	rz_float_free(div5);
	rz_float_free(div6);

	rz_float_free(cst_num);
	rz_float_free(zero);
	rz_float_free(nan);
	rz_float_free(pinf);
	rz_float_free(ninf);
	mu_end;
}

bool f32_ieee_rem_test(void) {
	RzFloat *a1 = rz_float_new_from_f32(4.0f);
	RzFloat *b1 = rz_float_new_from_f32(1.5f);
	RzFloat *expect1 = rz_float_new_from_f32(1.0f);
	RzFloat *rem1 = rz_float_rem(a1, b1, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_float(rem1, expect1), "rem test 1");
	rz_float_free(a1);
	rz_float_free(b1);
	rz_float_free(expect1);
	rz_float_free(rem1);

	RzFloat *a2 = rz_float_new_from_ut32_as_f32(0xCBF83FFF);
	RzFloat *b2 = rz_float_new_from_ut32_as_f32(0x44801003);
	RzFloat *expect2 = rz_float_new_from_ut32_as_f32(0xC3F52F40);
	RzFloat *rem2 = rz_float_rem(a2, b2, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_float(rem2, expect2), "rem test 2");
	rz_float_free(a2);
	rz_float_free(b2);
	rz_float_free(expect2);
	rz_float_free(rem2);

	RzFloat *a3 = rz_float_new_from_ut32_as_f32(0x3F7FFF3F);
	RzFloat *b3 = rz_float_new_from_ut32_as_f32(0x957CE0B6);
	RzFloat *expect3 = rz_float_new_from_ut32_as_f32(0x145F53B0);
	RzFloat *rem3 = rz_float_rem(a3, b3, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(is_equal_float(rem3, expect3), "rem test 3");
	rz_float_free(a3);
	rz_float_free(b3);
	rz_float_free(expect3);
	rz_float_free(rem3);

	mu_end;
}

bool float_load_from_bitvector(void) {
	RzBitVector *bv = rz_bv_new_from_ut64(32, 0x3fc00000);
	RzFloat *f0 = rz_float_new_from_bv(bv);
	rz_bv_free(bv);

	RzFloat *f1 = rz_float_new_from_f32(1.5f);
	mu_assert_true(is_equal_bv(f0->s, f1->s), "test load from RzBitVector");

	rz_float_free(f0);
	rz_float_free(f1);
	mu_end;
}

bool float_print_num(void) {
	RzFloat *f32 = rz_float_new_from_f32(4.123f);
	mu_assert_streq_free(rz_float_as_hex_string(f32, true), "0x4083ef9e", "float32 hex value");
	mu_assert_streq_free(rz_float_as_string(f32), "+10000001|00000111110111110011110", "float32 bit value");
	mu_assert_streq_free(rz_float_as_dec_string(f32), "4.123", "float32 numeric value");
	rz_float_free(f32);

	RzFloat *f64 = rz_float_new_from_f64(1.55678);
	mu_assert_streq_free(rz_float_as_hex_string(f64, true), "0x3ff8e892253111f1", "float64 hex value");
	mu_assert_streq_free(rz_float_as_string(f64), "+01111111111|1000111010001001001000100101001100010001000111110001", "float64 bit value");
	mu_assert_streq_free(rz_float_as_dec_string(f64), "1.55678", "float64 numeric value");
	rz_float_free(f64);

	RzFloat *f80 = rz_float_new_from_f80(13.0335l);
	// Need the check since 80-bit long double is an x86 speciality and MSVC ignores it.
#if (__i386__ || __x86_64__) && !__WINDOWS__
	mu_assert_streq_free(rz_float_as_hex_string(f80, true), "0x4002d089374bc6a7ef9e", "float80 hex value");
	mu_assert_streq_free(rz_float_as_string(f80), "+100000000000010|1101000010001001001101110100101111000110101001111110111110011110", "float80 bit value");
#else
	char *str = rz_float_as_hex_string(f80, true);
	if (str && strlen(str) == 22) {
		// Mask away anything beyond 64-bit influence because it differs between sparc and arm for example.
		memset(str + 18, 'x', 4);
	}
	mu_assert_streq_free(str, "0x4002d089374bc6a7xxxx", "float80 hex value");
	str = rz_float_as_string(f80);
	if (str && strlen(str) == 81) {
		// Mask away anything beyond 64-bit influence because it differs between sparc and arm for example.
		memset(str + 60, 'x', 81 - 60);
	}
	mu_assert_streq_free(str, "+100000000000010|1101000010001001001101110100101111000110101xxxxxxxxxxxxxxxxxxxxx", "float80 bit value");
#endif
	mu_assert_streq_free(rz_float_as_dec_string(f80), "13.0335", "float80 numeric value");
	rz_float_free(f80);

	RzFloat *f128 = rz_float_new_from_f128(3.125);
	mu_assert_streq_free(rz_float_as_hex_string(f128, true), "0x40009000000000000000000000000000", "float128 hex value");
	mu_assert_streq_free(rz_float_as_string(f128), "+100000000000000|1001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "float128 bit value");
	mu_assert_streq_free(rz_float_as_dec_string(f128), "3.125", "float128 numeric value");
	rz_float_free(f128);

	RzFloat *tmp = rz_float_new_zero(RZ_FLOAT_IEEE754_BIN_32);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "0.0", "float32 zero");
	rz_float_free(tmp);

	tmp = rz_float_new_inf(RZ_FLOAT_IEEE754_BIN_32, false);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "+inf", "float32 +inf");
	rz_float_free(tmp);

	tmp = rz_float_new_inf(RZ_FLOAT_IEEE754_BIN_32, true);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "-inf", "float32 -inf");
	rz_float_free(tmp);

	tmp = rz_float_new_qnan(RZ_FLOAT_IEEE754_BIN_32);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "nan", "float32 qnan");
	rz_float_free(tmp);

	tmp = rz_float_new_snan(RZ_FLOAT_IEEE754_BIN_32);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "nan", "float32 snan");
	rz_float_free(tmp);

	tmp = rz_float_new_from_f32(F32_NAN);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "nan", "float32 nan");
	rz_float_free(tmp);

	tmp = rz_float_new_from_f64(F64_NAN);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "nan", "float64 nan");
	rz_float_free(tmp);

	tmp = rz_float_new_from_f80(F128_NAN);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "nan", "float80 nan");
	rz_float_free(tmp);

	tmp = rz_float_new_from_f128(F128_NAN);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "nan", "float128 nan");
	rz_float_free(tmp);

	tmp = rz_float_new_from_f32(F32_PINF);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "+inf", "float32 +inf");
	rz_float_free(tmp);

	tmp = rz_float_new_from_f64(F64_PINF);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "+inf", "float64 +inf");
	rz_float_free(tmp);

	tmp = rz_float_new_from_f80(F128_PINF);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "+inf", "float80 +inf");
	rz_float_free(tmp);

	tmp = rz_float_new_from_f128(F128_PINF);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "+inf", "float128 +inf");
	rz_float_free(tmp);

	tmp = rz_float_new_from_f32(F32_NINF);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "-inf", "float32 -inf");
	rz_float_free(tmp);

	tmp = rz_float_new_from_f64(F64_NINF);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "-inf", "float64 -inf");
	rz_float_free(tmp);

	tmp = rz_float_new_from_f80(F128_NINF);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "-inf", "float80 -inf");
	rz_float_free(tmp);

	tmp = rz_float_new_from_f128(F128_NINF);
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "-inf", "float128 -inf");
	rz_float_free(tmp);

	tmp = rz_float_new_from_f32(1.0795446E-38f);
	mu_assert_streq_free(rz_float_as_hex_string(tmp, true), "0x00758d50", "float32 denormalized hex");
	mu_assert_streq_free(rz_float_as_string(tmp), "+00000000|11101011000110101010000", "float32 denormalized bits");
	mu_assert_streq_free(rz_float_as_dec_string(tmp), "1.07954e-38", "float32 denormalized decimal");
	rz_float_free(tmp);

	mu_end;
}

bool f32_ieee_format_extra_test(void) {
	// normal float
	RzFloat *a = rz_float_new_from_f32(12.24f);
	RzFloat *b = rz_float_new_from_f32(0.02f);
	RzFloat *c = rz_float_new_from_f32(7.890332E9f);
	ut32 exp_a = rz_float_get_exponent_val(a);
	ut32 exp_b = rz_float_get_exponent_val(b);
	ut32 exp_c = rz_float_get_exponent_val(c);

	mu_assert_eq(exp_a, 130, "test float exponent value: normal");
	mu_assert_eq(exp_b, 121, "test float exponent value: small");
	mu_assert_eq(exp_c, 159, "test float exponent value: huge");

	st32 nexp_a = rz_float_get_exponent_val_no_bias(a);
	st32 nexp_b = rz_float_get_exponent_val_no_bias(b);
	st32 nexp_c = rz_float_get_exponent_val_no_bias(c);

	mu_assert_eq(nexp_a, 3, "test float exponent value no bias: normal");
	mu_assert_eq(nexp_b, -6, "test float exponent value no bias: small");
	mu_assert_eq(nexp_c, 32, "test float exponent value no bias: huge");

	// sub-normal -> -126
	RzFloat *s = rz_float_new_from_f32(9.892046E-39f);
	ut32 exp_s = rz_float_get_exponent_val(s);
	st32 nexp_s = rz_float_get_exponent_val_no_bias(s);
	mu_assert_eq(exp_s, 0, "test float exponent value: sub normal");
	mu_assert_eq(nexp_s, -126, "test float exponent value no bias: sub normal");

	// get sign and set sign to float
	rz_float_set_sign(a, true);
	mu_assert_true(rz_float_is_negative(a), "test float set sign");
	mu_assert_true(rz_float_get_sign(a) == true, "test float get sign");

	rz_float_free(a);
	rz_float_free(b);
	rz_float_free(c);
	rz_float_free(s);
	mu_end;
}

bool f32_ieee_cmp_test(void) {
	RzFloat *a = rz_float_new_from_f32(1.12f);
	RzFloat *b = rz_float_new_from_f32(1.11f);
	RzFloat *c = rz_float_new_from_f32(-0.07f);
	RzFloat *d = rz_float_new_from_f32(-1111.1f);
	RzFloat *e = rz_float_new_from_ut32_as_f32(0x3F8F5C29); // 1.12f

	mu_assert_true(rz_float_cmp(a, b) > 0, "test float cmp transitivity 1");
	mu_assert_true(rz_float_cmp(b, c) > 0, "test float cmp transitivity 2");
	mu_assert_true(rz_float_cmp(a, c) > 0, "test float cmp transitivity 3");

	mu_assert_true(rz_float_cmp(b, a) < 0, "test float cmp reverse");

	mu_assert_true(rz_float_cmp(c, d) > 0, "test float cmp in negative");

	mu_assert_true(rz_float_cmp(a, e) == 0, "test float cmp equality");

	RzFloat *pinf = rz_float_new_inf(RZ_FLOAT_IEEE754_BIN_32, false);
	RzFloat *ninf = rz_float_new_inf(RZ_FLOAT_IEEE754_BIN_32, true);
	mu_assert_true(rz_float_cmp(pinf, a) > 0, "test positive inf");
	mu_assert_true(rz_float_cmp(ninf, b) < 0, "test negative inf");

	rz_float_free(a);
	rz_float_free(b);
	rz_float_free(c);
	rz_float_free(d);
	rz_float_free(e);
	rz_float_free(pinf);
	rz_float_free(ninf);

	mu_end;
}

bool f32_ieee_generating_op_test(void) {
	RzFloat *pi = rz_float_new_from_f32(3.1415925f);
	RzFloat *pi_next = rz_float_succ(pi);
	RzFloat *pi_pred = rz_float_pred(pi);
	RzFloat *pi_neg = rz_float_neg(pi);

	mu_assert_streq_free(rz_float_as_hex_string(pi, true), "0x40490fda", "test pi");
	mu_assert_streq_free(rz_float_as_hex_string(pi_next, true), "0x40490fdb", "test next float number of pi");
	mu_assert_streq_free(rz_float_as_hex_string(pi_pred, true), "0x40490fd9", "test previous float number of pi");
	mu_assert_streq_free(rz_float_as_hex_string(pi_neg, true), "0xc0490fda", "test neg pi");

	rz_float_free(pi);
	rz_float_free(pi_next);
	rz_float_free(pi_pred);
	rz_float_free(pi_neg);

	RzFloat *ne = rz_float_new_from_f32(-2.7182817f);
	RzFloat *ne_next = rz_float_succ(ne);
	RzFloat *ne_pred = rz_float_pred(ne);
	RzFloat *ne_neg = rz_float_neg(ne);

	mu_assert_streq_free(rz_float_as_hex_string(ne, true), "0xc02df854", "test euler");
	mu_assert_streq_free(rz_float_as_hex_string(ne_next, true), "0xc02df853", "test euler");
	mu_assert_streq_free(rz_float_as_hex_string(ne_pred, true), "0xc02df855", "test euler");
	mu_assert_streq_free(rz_float_as_hex_string(ne_neg, true), "0x402df854", "test euler");

	rz_float_free(ne);
	rz_float_free(ne_next);
	rz_float_free(ne_pred);
	rz_float_free(ne_neg);

	// boundary test 0x43FFFFFF and 0x48000000
	// fpred(x) < x < fsucc(x)
	RzFloat *carry_case = rz_float_new_from_f32(511.99997f);
	RzFloat *borrow_case = rz_float_new_from_f32(131072.0f);
	RzFloat *succ = rz_float_succ(carry_case);
	RzFloat *pred = rz_float_pred(borrow_case);

	mu_assert_streq_free(rz_float_as_hex_string(succ, true), "0x44000000", "test carry case");
	mu_assert_streq_free(rz_float_as_hex_string(pred, true), "0x47ffffff", "test borrow case");

	RzFloat *neg_carry_case = rz_float_neg(carry_case);
	RzFloat *neg_borrow_case = rz_float_neg(borrow_case);
	RzFloat *neg_pred = rz_float_pred(neg_carry_case);
	RzFloat *neg_succ = rz_float_succ(neg_borrow_case);

	mu_assert_streq_free(rz_float_as_hex_string(neg_pred, true), "0xc4000000", "test pred of neg carry");
	mu_assert_streq_free(rz_float_as_hex_string(neg_succ, true), "0xc7ffffff", "test succ of neg borrow");

	rz_float_free(carry_case);
	rz_float_free(borrow_case);
	rz_float_free(succ);
	rz_float_free(pred);
	rz_float_free(neg_carry_case);
	rz_float_free(neg_borrow_case);
	rz_float_free(neg_pred);
	rz_float_free(neg_succ);

	mu_end;
}

bool f32_new_round_test(void) {
	// test round_significant
	// 1. round 12-bit to 8-bit precision: 1 MMMM MMMM MMMM -> 1 PPPP PPPP
	// round 0001 0101 0011 1000 to 8-bit precision
	// XXXX 1PPP PPPP PGRS (shift to align, P: precision bit, G: guard, R: round, S: sticky
	// 0000 1010 1001 1100
	unsigned char buffer[8] = { 0x15, 0x38 };
	RzBitVector *sig;
	RzBitVector *round_sig;
	bool should_inc = false;

	sig = rz_bv_new_from_bytes_be(buffer, 0, 16);
	mu_assert_streq_free(rz_bv_as_string(sig), "0001010100111000", "test sig from bytes");

	// rne, ties case, round to even
	// 0001 0101 0011 1000 -> 0001 0101 0011, should_inc
	round_sig = rz_float_round_significant(false, sig, 8, RZ_FLOAT_RMODE_RNE, &should_inc);
	mu_assert_true(should_inc, "test rne should not increase case");
	mu_assert_streq_free(rz_bv_as_string(round_sig), "000101010011", "test round sig to 12-bit, rne");
	rz_bv_free(round_sig);

	// rna, ties case, round up when ties
	round_sig = rz_float_round_significant(false, sig, 8, RZ_FLOAT_RMODE_RNA, &should_inc);
	mu_assert_true(should_inc, "test rna, always round up (increase abs) when ties");
	mu_assert_streq_free(rz_bv_as_string(round_sig), "000101010011", "test round sig to 12-bit, rna");
	rz_bv_free(round_sig);

	// rtz
	round_sig = rz_float_round_significant(false, sig, 8, RZ_FLOAT_RMODE_RTZ, &should_inc);
	mu_assert_false(should_inc, "test rtz, always drop, no need to increase");
	mu_assert_streq_free(rz_bv_as_string(round_sig), "000101010011", "test round sig to 12-bit, rtz");
	rz_bv_free(round_sig);

	// rtp
	round_sig = rz_float_round_significant(false, sig, 8, RZ_FLOAT_RMODE_RTP, &should_inc);
	mu_assert_true(should_inc, "test rtp, always inc if positive");
	mu_assert_streq_free(rz_bv_as_string(round_sig), "000101010011", "test round sig to 12-bit, rtp");
	rz_bv_free(round_sig);

	// rtn
	round_sig = rz_float_round_significant(false, sig, 8, RZ_FLOAT_RMODE_RTN, &should_inc);
	mu_assert_false(should_inc, "test rtn, always drop if negative");
	mu_assert_streq_free(rz_bv_as_string(round_sig), "000101010011", "test round sig to 12-bit, rtn");
	rz_bv_free(round_sig);

	// neg case, ties, rne, should not increase abs value
	round_sig = rz_float_round_significant(true, sig, 8, RZ_FLOAT_RMODE_RNE, &should_inc);
	mu_assert_true(should_inc, "test rne in negative");
	rz_bv_free(round_sig);

	// neg case, ties, rna, should increase
	round_sig = rz_float_round_significant(true, sig, 8, RZ_FLOAT_RMODE_RNA, &should_inc);
	mu_assert_true(should_inc, "test rna in negative");
	rz_bv_free(round_sig);

	// neg case, rtz, should not increase
	round_sig = rz_float_round_significant(true, sig, 8, RZ_FLOAT_RMODE_RTZ, &should_inc);
	mu_assert_false(should_inc, "test rtz in negative");
	rz_bv_free(round_sig);

	// neg case, rtp, should not increase since it's negative
	round_sig = rz_float_round_significant(true, sig, 8, RZ_FLOAT_RMODE_RTP, &should_inc);
	mu_assert_false(should_inc, "test rtp in negative");
	rz_bv_free(round_sig);

	// neg case, rtn, should increase
	round_sig = rz_float_round_significant(true, sig, 8, RZ_FLOAT_RMODE_RTN, &should_inc);
	mu_assert_true(should_inc, "test rtn in negative");
	rz_bv_free(round_sig);

	// basic test end
	rz_bv_free(sig);

	// test rne, when it's odd, should increse
	// 0001 0101 0010 1000
	buffer[1] = 0x28;
	sig = rz_bv_new_from_bytes_be(buffer, 0, 16);
	mu_assert_streq_free(rz_bv_as_string(sig), "0001010100101000", "test sig from bytes be, odd significant");

	// rne, inc
	round_sig = rz_float_round_significant(false, sig, 8, RZ_FLOAT_RMODE_RNE, &should_inc);
	mu_assert_false(should_inc, "test rne, already even");
	mu_assert_streq_free(rz_bv_as_string(round_sig), "000101010010", "test rne when significant is odd");
	rz_bv_free(round_sig);

	// rna, should inc
	round_sig = rz_float_round_significant(false, sig, 8, RZ_FLOAT_RMODE_RNA, &should_inc);
	mu_assert_true(should_inc, "test rna, always should round up");
	rz_bv_free(round_sig);

	// 2. test round to 0-bit precision (1.MMM... -> round to integer)
	// rne, 0001 0101 0010 1000 -> 0001 011(GRS) -> 0001, should not inc
	round_sig = rz_float_round_significant(false, sig, 0, RZ_FLOAT_RMODE_RNE, &should_inc);
	mu_assert_false(should_inc, "test round to 0-bit, rne");
	rz_bv_free(round_sig);

	// rna, not ties, round down, not increase
	round_sig = rz_float_round_significant(false, sig, 0, RZ_FLOAT_RMODE_RNA, &should_inc);
	mu_assert_false(should_inc, "test round to 0-bit, rna");
	rz_bv_free(round_sig);

	// rtz, not increase
	round_sig = rz_float_round_significant(false, sig, 0, RZ_FLOAT_RMODE_RTZ, &should_inc);
	mu_assert_false(should_inc, "test round to 0-bit, rtz");
	rz_bv_free(round_sig);

	// rtp, increase
	round_sig = rz_float_round_significant(false, sig, 0, RZ_FLOAT_RMODE_RTP, &should_inc);
	mu_assert_true(should_inc, "test round to 0-bit, rtp");
	rz_bv_free(round_sig);

	// rtn, not increase
	round_sig = rz_float_round_significant(false, sig, 0, RZ_FLOAT_RMODE_RTN, &should_inc);
	mu_assert_false(should_inc, "test round to 0-bit, rtn");
	rz_bv_free(round_sig);

	// 3. test precision > mantissa length
	// round 0001 0101 0010 1000 (12-bit precision) to 23-bit precision
	// 0001 0101 0010 1000 0000 0000 000
	round_sig = rz_float_round_significant(false, sig, 23, RZ_FLOAT_RMODE_RNE, &should_inc);
	mu_assert_false(should_inc, "test round to higher precision, no need to increase");
	mu_assert_streq_free(rz_bv_as_string(round_sig), "000101010010100000000000000", "test round to higher prec");
	rz_bv_free(round_sig);
	rz_bv_free(sig);

	// 4. test round_bv_and_pack
	RzFloat *expected_fval, *round_fval;
	// 0101 1100 0000 0000 0000 0000 1100 -> 26-bit precision round to 23-bit precision
	buffer[0] = 0x5C;
	buffer[1] = 0x00;
	buffer[2] = 0x00;
	buffer[3] = 0xC0;
	sig = rz_bv_new_from_bytes_be(buffer, 0, 28);
	mu_assert_streq_free(rz_bv_as_string(sig), "0101110000000000000000001100", "test pack float : init significant as expected");

	// rne, rna and rtp, round up
	// note that cmp == 0 is equal
	expected_fval = rz_float_new_from_f32(11.500002f);
	round_fval = rz_float_round_bv_and_pack(
		false,
		3 + 127,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test round and pack to 11.500002, rne");
	rz_float_free(round_fval);

	round_fval = rz_float_round_bv_and_pack(
		false,
		3 + 127,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RNA);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test round and pack to 11.500002, rna");
	rz_float_free(round_fval);

	round_fval = rz_float_round_bv_and_pack(
		false,
		3 + 127,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RTP);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test round and pack to 11.500002, rtp");
	rz_float_free(round_fval);
	rz_float_free(expected_fval);

	// rne, rtz and rtn
	expected_fval = rz_float_new_from_f32(11.500001f);
	round_fval = rz_float_round_bv_and_pack(
		false,
		3 + 127,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RTZ);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test round and pack to 11.500001, rtz");
	rz_float_free(round_fval);

	round_fval = rz_float_round_bv_and_pack(
		false,
		3 + 127,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RTN);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test round and pack to 11.500001, rtn");
	rz_float_free(round_fval);
	rz_float_free(expected_fval);

	// 5. test round and pack, in negative
	// rne, rna, rtn
	expected_fval = rz_float_new_from_f32(-11.500002f);
	round_fval = rz_float_round_bv_and_pack(
		true,
		3 + 127,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test negative round and pack to -11.500002, rne");
	rz_float_free(round_fval);

	round_fval = rz_float_round_bv_and_pack(
		true,
		3 + 127,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RNA);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test negative round and pack to -11.500002, rna");
	rz_float_free(round_fval);

	round_fval = rz_float_round_bv_and_pack(
		true,
		3 + 127,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RTN);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test negative round and pack to -11.500002, rtn");
	rz_float_free(round_fval);
	rz_float_free(expected_fval);

	// rtp, rtz
	expected_fval = rz_float_new_from_f32(-11.500001f);
	round_fval = rz_float_round_bv_and_pack(
		true,
		3 + 127,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RTP);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test negative round and pack to -11.500002, rtp");
	rz_float_free(round_fval);

	round_fval = rz_float_round_bv_and_pack(
		true,
		3 + 127,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RTZ);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test negative round and pack to -11.500002, rtz");
	rz_float_free(round_fval);
	rz_float_free(expected_fval);
	rz_bv_free(sig);

	// 6. another test to rne and rna
	// 0101 1100 0000 0000 0000 0000 0100 -> 28-bit vector round to 23-bit precision
	// already even case
	buffer[3] = 0x40;
	sig = rz_bv_new_from_bytes_be(buffer, 0, 28);
	mu_assert_streq_free(rz_bv_as_string(sig), "0101110000000000000000000100", "test another rne : init significant as expected");

	expected_fval = rz_float_new_from_f32(11.5f);
	round_fval = rz_float_round_bv_and_pack(
		false,
		3 + 127,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test another rne 1");
	rz_float_free(round_fval);
	rz_float_free(expected_fval);

	expected_fval = rz_float_new_from_f32(11.500001f);
	round_fval = rz_float_round_bv_and_pack(
		false,
		3 + 127,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RNA);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test another rna 1");
	rz_float_free(round_fval);
	rz_float_free(expected_fval);
	rz_bv_free(sig);

	// 7. test significant carry to exponent case
	// 1111 1111 1111 1111 1111 1111 100(GRS) = 15.999999f, exp = 3
	buffer[0] = 0xFF;
	buffer[1] = 0xFF;
	buffer[2] = 0xFF;
	buffer[3] = 0x80;
	sig = rz_bv_new_from_bytes_be(buffer, 0, 27);
	mu_assert_streq_free(rz_bv_as_string(sig), "111111111111111111111111100", "test sig carry : init significant as expected");
	expected_fval = rz_float_new_from_f32(16.0f);
	round_fval = rz_float_round_bv_and_pack(
		false,
		3 + 127,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test round sig carry, rne");
	rz_float_free(round_fval);
	rz_float_free(expected_fval);

	expected_fval = rz_float_new_from_f32(15.999999f);
	round_fval = rz_float_round_bv_and_pack(
		false,
		3 + 127,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RTZ);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test round sig carry, rtz");
	rz_float_free(round_fval);
	rz_float_free(expected_fval);
	rz_bv_free(sig);

	// 8. test sub-normal case
	// 0101 1100 0000 0000 0000 0000 1100 -> 26-bit precision round to 23-bit precision
	buffer[0] = 0x5C;
	buffer[1] = 0x00;
	buffer[2] = 0x00;
	buffer[3] = 0xC0;
	sig = rz_bv_new_from_bytes_be(buffer, 0, 27);
	expected_fval = rz_float_new_from_f32(5.14279E-39f);
	round_fval = rz_float_round_bv_and_pack(
		false,
		0,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test round to sub-normal, rne");
	rz_float_free(round_fval);
	rz_float_free(expected_fval);
	rz_bv_free(sig);

	// test sub-normal carry, 1.1754942E-38 round to 1.1754944E-38
	buffer[0] = 0xFF;
	buffer[1] = 0xFF;
	buffer[2] = 0xFF;
	buffer[3] = 0x80;
	sig = rz_bv_new_from_bytes_be(buffer, 0, 27);
	expected_fval = rz_float_new_from_f32(1.1754944E-38f);
	round_fval = rz_float_round_bv_and_pack(
		false,
		0,
		sig,
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expected_fval, round_fval), "test round to sub-normal carry case, rne");
	rz_float_free(round_fval);
	rz_float_free(expected_fval);
	rz_bv_free(sig);

	mu_end;
}

bool f32_ieee_fround_test(void) {
	// test round to interal
	RzFloat *expect, *round, *val;
	val = rz_float_new_from_f32(1.1111f);
	expect = rz_float_new_from_f32(1.0f);
	round = rz_float_round_to_integral(val, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect, round), "test round to integral 1.0f");
	rz_float_free(val);
	rz_float_free(expect);
	rz_float_free(round);

	val = rz_float_new_from_f32(42.131432f);
	expect = rz_float_new_from_f32(42.0f);
	round = rz_float_round_to_integral(val, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect, round), "test round to integral 42.0f");
	rz_float_free(val);
	rz_float_free(expect);
	rz_float_free(round);

	val = rz_float_new_from_f32(1.2345679E8f);
	expect = rz_float_new_from_f32(1.2345679E8f);
	round = rz_float_round_to_integral(val, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect, round), "test round to integral 1.2345679E8f");
	rz_float_free(val);
	rz_float_free(expect);
	rz_float_free(round);

	val = rz_float_new_from_f32(0.23751f);
	expect = rz_float_new_from_f32(0.0f);
	round = rz_float_round_to_integral(val, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect, round), "test round to integral 0.23751f, rne");
	rz_float_free(expect);
	rz_float_free(round);

	expect = rz_float_new_from_f32(1.0f);
	round = rz_float_round_to_integral(val, RZ_FLOAT_RMODE_RTP);
	mu_assert_false(rz_float_cmp(expect, round), "test round to integral 0.23751f, rtp");
	rz_float_free(val);
	rz_float_free(expect);
	rz_float_free(round);

	val = rz_float_new_from_f32(-5.11234f);
	expect = rz_float_new_from_f32(-5.0f);
	round = rz_float_round_to_integral(val, RZ_FLOAT_RMODE_RTP);
	mu_assert_false(rz_float_cmp(expect, round), "test round to integral -5.11234f");
	rz_float_free(val);
	rz_float_free(expect);
	rz_float_free(round);

	mu_end;
}

bool f32_ieee_cast_test(void) {
	// cast and convert
	RzFloat *expect, *cast_val;
	RzBitVector *val;

	// 1. cast to float
	// 1-1. simple
	val = rz_bv_new_one(10);
	expect = rz_float_new_from_f32(1.0f);
	cast_val = rz_float_cast_float(val, RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect, cast_val), "test (cast-float 1)");
	rz_float_free(cast_val);

	cast_val = rz_float_cast_sfloat(val, RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect, cast_val), "test (cast-sfloat 1)");
	rz_float_free(cast_val);
	rz_float_free(expect);
	rz_bv_free(val);

	// 1-2. normal
	val = rz_bv_new_from_ut64(32, 12345678);
	expect = rz_float_new_from_f32(12345678.0f);
	cast_val = rz_float_cast_float(val, RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect, cast_val), "test (cast-float 12345678)");
	rz_float_free(cast_val);

	cast_val = rz_float_cast_sfloat(val, RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect, cast_val), "test (cast-sfloat 12345678)");
	rz_float_free(cast_val);
	rz_float_free(expect);
	rz_bv_free(val);

	// 1-3. big num, inexact
	val = rz_bv_new_from_ut64(32, 123456789);
	expect = rz_float_new_from_f32(1.2345679E8f);
	cast_val = rz_float_cast_float(val, RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect, cast_val), "test (cast-float 123456789)");
	rz_float_free(cast_val);

	cast_val = rz_float_cast_sfloat(val, RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect, cast_val), "test (cast-sfloat 123456789)");
	rz_float_free(cast_val);
	rz_float_free(expect);
	rz_bv_free(val);

	// 1-4. cast-float negative
	// 1111 1111 1111 1111 -> unsigned : 2^16 - 1 = 65535, signed : -1
	val = rz_bv_new_from_st64(16, -1);
	expect = rz_float_new_from_f32(-1.0f);
	cast_val = rz_float_cast_sfloat(val, RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect, cast_val), "test (cast-sfloat -1)");
	rz_float_free(cast_val);
	rz_float_free(expect);

	expect = rz_float_new_from_f32(65535.0f);
	cast_val = rz_float_cast_float(val, RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect, cast_val), "test (cast-float -1)");
	rz_float_free(cast_val);
	rz_float_free(expect);
	rz_bv_free(val);

	// 2. test cast to integer
	// 2-1. simple
	RzFloat *fval;
	RzBitVector *expect_bv, *cast_bv;

	// test cast_sint only, since cast_int is a wrapper of cast_sint
	fval = rz_float_new_from_f32(1.0f);
	expect_bv = rz_bv_new_one(32);
	cast_bv = rz_float_cast_sint(fval, 32, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(rz_bv_eq(expect_bv, cast_bv), "test (cast-sint 1.0f)");
	rz_float_free(fval);
	rz_bv_free(cast_bv);
	rz_bv_free(expect_bv);

	// 2-2. normal
	fval = rz_float_new_from_f32(12345678.0f);
	expect_bv = rz_bv_new_from_ut64(32, 12345678);
	cast_bv = rz_float_cast_sint(fval, 32, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(rz_bv_eq(expect_bv, cast_bv), "test (cast-sint 12345678.0f)");
	rz_float_free(fval);
	rz_bv_free(cast_bv);
	rz_bv_free(expect_bv);

	// 2-3. huge
	fval = rz_float_new_from_f32(1.2345679E8f);
	expect_bv = rz_bv_new_from_ut64(32, 123456792);
	cast_bv = rz_float_cast_sint(fval, 32, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(rz_bv_eq(expect_bv, cast_bv), "test (cast-sint 1.2345679E8)");
	rz_float_free(fval);
	rz_bv_free(cast_bv);
	rz_bv_free(expect_bv);

	// 2-4. negative
	fval = rz_float_new_from_f32(-1.0f);
	expect_bv = rz_bv_new_from_ut64(32, 0xFFFFFFFF);
	cast_bv = rz_float_cast_sint(fval, 32, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(rz_bv_eq(expect_bv, cast_bv), "test (cast-sint -1.0f)");
	rz_float_free(fval);
	rz_bv_free(cast_bv);
	rz_bv_free(expect_bv);

	// 2-5 normal negative
	fval = rz_float_new_from_f32(-1234.0f);
	expect_bv = rz_bv_new_from_ut64(64, 0xFFFFFFFFFFFFFB2E);
	cast_bv = rz_float_cast_sint(fval, 64, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(rz_bv_eq(expect_bv, cast_bv), "test (cast-sint -1234.0f)");
	rz_float_free(fval);
	rz_bv_free(cast_bv);
	rz_bv_free(expect_bv);

	// 2-6 pure small number
	fval = rz_float_new_from_f32(0.119823f);
	expect_bv = rz_bv_new_zero(16);
	cast_bv = rz_float_cast_sint(fval, 16, RZ_FLOAT_RMODE_RNE);
	mu_assert_true(rz_bv_eq(expect_bv, cast_bv), "test (cast-sint 0.119823f), rne");
	rz_float_free(fval);
	rz_bv_free(cast_bv);
	rz_bv_free(expect_bv);

	fval = rz_float_new_from_f32(0.119823f);
	expect_bv = rz_bv_new_one(16);
	cast_bv = rz_float_cast_sint(fval, 16, RZ_FLOAT_RMODE_RTP);
	mu_assert_true(rz_bv_eq(expect_bv, cast_bv), "test (cast-sint 0.119823f), rtp");
	rz_float_free(fval);
	rz_bv_free(cast_bv);
	rz_bv_free(expect_bv);

	// round to -1 in 2's complement
	fval = rz_float_new_from_f32(-0.119823f);
	expect_bv = rz_bv_new_zero(16);
	rz_bv_toggle_all(expect_bv);
	cast_bv = rz_float_cast_sint(fval, 16, RZ_FLOAT_RMODE_RTN);
	mu_assert_true(rz_bv_eq(expect_bv, cast_bv), "test (cast-sint -0.119823f)");
	rz_float_free(fval);
	rz_bv_free(cast_bv);
	rz_bv_free(expect_bv);

	// 3. convert
	RzFloat *old_f = rz_float_new_from_f32(42.0f);
	RzFloat *expect_f = rz_float_new_from_f64(42.0);
	RzFloat *new_cast = rz_float_convert(old_f, RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect_f, new_cast), "test convert 42.0f to 42.0 double");
	rz_float_free(old_f);
	rz_float_free(expect_f);
	rz_float_free(new_cast);

	old_f = rz_float_new_from_f64(42.0);
	expect_f = rz_float_new_from_f32(42.0f);
	new_cast = rz_float_convert(old_f, RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect_f, new_cast), "test convert 42.0d to 42.0f ");
	rz_float_free(old_f);
	rz_float_free(expect_f);
	rz_float_free(new_cast);

	old_f = rz_float_new_from_f64(3.1415926535);
	expect_f = rz_float_new_from_f32(3.1415927f);
	new_cast = rz_float_convert(old_f, RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect_f, new_cast), "test convert pi from double to float");
	rz_float_free(old_f);
	rz_float_free(expect_f);
	rz_float_free(new_cast);
	mu_end;
}

bool f80_round_test(void) {
	/* To 80-bit */
	RzFloat *old_f = rz_float_new_from_f64(14.285714285714286);
	RzFloat *expect_f = rz_float_new_from_f80(14.2857142857142864756l);
	RzFloat *new_cast = rz_float_convert(old_f, RZ_FLOAT_IEEE754_BIN_80, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect_f, new_cast), "test convert 14.285714285714286d to 14.2857142857142864756l");
	rz_float_free(old_f);
	rz_float_free(expect_f);
	rz_float_free(new_cast);

	/* From 80-bit */
	old_f = rz_float_new_from_f80(13.37l);
	expect_f = rz_float_new_from_f32(13.37f);
	new_cast = rz_float_convert(old_f, RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect_f, new_cast), "test convert 13.37l to 13.37f");
	rz_float_free(old_f);
	rz_float_free(expect_f);
	rz_float_free(new_cast);

	/* From 80-bit to 80-bit (should lead to the same value) */
	old_f = rz_float_new_from_f80(66668466788774.6870804l);
	expect_f = rz_float_new_from_f80(66668466788774.6870804l);
	new_cast = rz_float_convert(old_f, RZ_FLOAT_IEEE754_BIN_80, RZ_FLOAT_RMODE_RNE);
	mu_assert_false(rz_float_cmp(expect_f, new_cast), "test convert 66668466788774.6870804l to itself");
	rz_float_free(old_f);
	rz_float_free(expect_f);
	rz_float_free(new_cast);
	mu_end;
}

bool all_tests() {
	mu_run_test(rz_float_new_from_hex_test);
	mu_run_test(f32_ieee_format_test);
	mu_run_test(rz_float_detect_spec_test);
	mu_run_test(f32_ieee_add_test);
	mu_run_test(f32_ieee_sub_test);
	mu_run_test(f32_ieee_mul_test);
	mu_run_test(f32_ieee_div_test);
	mu_run_test(f32_ieee_fma_test);
	mu_run_test(rz_float_trunc_test);
	mu_run_test(rz_float_abs_test);
	mu_run_test(f32_ieee_round_test);
	mu_run_test(f32_ieee_sqrt_test);
	mu_run_test(f32_ieee_rem_test);
	mu_run_test(f32_ieee_special_num_test);
	mu_run_test(float_load_from_bitvector);
	mu_run_test(float_print_num);
	mu_run_test(f32_ieee_format_extra_test);
	mu_run_test(f32_ieee_cmp_test);
	mu_run_test(f32_ieee_generating_op_test);
	mu_run_test(f32_new_round_test);
	mu_run_test(f32_ieee_fround_test);
	mu_run_test(f32_ieee_cast_test);
	mu_run_test(f80_round_test);
#if (__i386__ || __x86_64__) && !__WINDOWS__
	mu_run_test(f80_ieee_div_test);
#endif
	return tests_passed != tests_run;
}

mu_main(all_tests)
