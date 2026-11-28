// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file float_mp.h
 * Internal multiple-precision binary floating-point arithmetic used to
 * evaluate the IEEE 754 recommended operations (IEEE 754-2019 9.2) with
 * correct rounding. Numbers are finite: specials are handled by callers.
 *
 * A nonzero MpFloat with precision p holds (-1)^sign * 0.d * 2^exp, where
 * d is a p-bit significand stored left aligned in mp_nlimbs(p) 32-bit
 * limbs (least significant limb first) with the bits below p cleared, so
 * that 2^(exp - 1) <= |x| < 2^exp. Operations round their exact result to
 * the precision of the destination and return a ternary value: 0 when
 * exact, positive when the result is above the exact value and negative
 * when below.
 */

#ifndef RZ_FLOAT_MP_H
#define RZ_FLOAT_MP_H

#include <rz_types.h>
#include <rz_util/rz_float.h>

#define MP_LIMB_BITS 32
#define MP_MAX_PREC  2048
#define MP_MAX_LIMBS (MP_MAX_PREC / MP_LIMB_BITS)

typedef ut32 MpLimb;

typedef struct {
	ut32 prec; ///< significand precision in bits, 2 .. MP_MAX_PREC
	bool sign; ///< true if negative
	bool zero; ///< true for a (signed) zero
	st64 exp; ///< 2^(exp - 1) <= |x| < 2^exp unless zero
	MpLimb d[MP_MAX_LIMBS]; ///< significand, left aligned, least significant limb first
} MpFloat;

static inline ut32 mp_nlimbs(ut32 prec) {
	return (prec + MP_LIMB_BITS - 1) / MP_LIMB_BITS;
}

RZ_IPI void rz_mp_init(MpFloat *x, ut32 prec);
RZ_IPI void rz_mp_set_zero(MpFloat *x, bool sign);
RZ_IPI int rz_mp_set(MpFloat *r, const MpFloat *a, RzFloatRMode rnd);
RZ_IPI int rz_mp_set_si(MpFloat *r, st64 v, RzFloatRMode rnd);
RZ_IPI int rz_mp_set_ui(MpFloat *r, ut64 v, RzFloatRMode rnd);
RZ_IPI int rz_mp_set_2exp(MpFloat *r, st64 v, st64 e, RzFloatRMode rnd);
RZ_IPI int rz_mp_add(MpFloat *r, const MpFloat *a, const MpFloat *b, RzFloatRMode rnd);
RZ_IPI int rz_mp_sub(MpFloat *r, const MpFloat *a, const MpFloat *b, RzFloatRMode rnd);
RZ_IPI int rz_mp_mul(MpFloat *r, const MpFloat *a, const MpFloat *b, RzFloatRMode rnd);
RZ_IPI int rz_mp_div(MpFloat *r, const MpFloat *a, const MpFloat *b, RzFloatRMode rnd);
RZ_IPI int rz_mp_sqrt(MpFloat *r, const MpFloat *a, RzFloatRMode rnd);
RZ_IPI int rz_mp_add_si(MpFloat *r, const MpFloat *a, st64 v, RzFloatRMode rnd);
RZ_IPI int rz_mp_mul_si(MpFloat *r, const MpFloat *a, st64 v, RzFloatRMode rnd);
RZ_IPI int rz_mp_div_si(MpFloat *r, const MpFloat *a, st64 v, RzFloatRMode rnd);
RZ_IPI void rz_mp_mul_2si(MpFloat *x, st64 k);
RZ_IPI void rz_mp_neg(MpFloat *x);
RZ_IPI void rz_mp_abs(MpFloat *x);
RZ_IPI int rz_mp_cmp(const MpFloat *a, const MpFloat *b);
RZ_IPI int rz_mp_cmp_abs(const MpFloat *a, const MpFloat *b);
RZ_IPI int rz_mp_cmp_si(const MpFloat *a, st64 v);
RZ_IPI bool rz_mp_is_integer(const MpFloat *a);
RZ_IPI int rz_mp_round_int(MpFloat *r, const MpFloat *a, RzFloatRMode rnd);
RZ_IPI st64 rz_mp_get_si(const MpFloat *a);
RZ_IPI void rz_mp_const_pi(MpFloat *r);
RZ_IPI void rz_mp_const_ln2(MpFloat *r);
RZ_IPI void rz_mp_const_ln10(MpFloat *r);
RZ_IPI ut64 rz_mp_trailing_zeros(const MpFloat *a);
RZ_IPI bool rz_mp_two_over_pi_window(MpLimb *out, ut32 nlimbs, st64 first_bit);

RZ_IPI ut32 rz_mp_format_prec(RzFloatFormat format);
RZ_IPI bool rz_mp_set_float(MpFloat *r, const RzFloat *f);
RZ_IPI RZ_OWN RzFloat *rz_mp_get_float(const MpFloat *x, RzFloatFormat format, RzFloatRMode rnd);

#endif
