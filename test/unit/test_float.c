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

	RzFloat *f80 = rz_float_new_from_f80(13.0335);
	mu_assert_streq_free(rz_float_as_hex_string(f80, true), "0x4002a1126e978d4fe000", "float80 hex value");
	mu_assert_streq_free(rz_float_as_string(f80), "+100000000000010|1010000100010010011011101001011110001101010011111110000000000000", "float80 bit value");
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
	return tests_passed != tests_run;
}

mu_main(all_tests)
