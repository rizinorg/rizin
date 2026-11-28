// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file float_trans.h
 * Internal helpers shared by the implementations of the IEEE 754-2019 9.2
 * recommended operations (float_trans*.c).
 *
 * Each operation handles NaN, infinity, zero and the other special operands
 * of IEEE 754-2019 9.2.1 (as restated by ISO/IEC 9899:2024 F.10) directly,
 * and evaluates every other operand with an MpFloat approximation that is
 * refined until it determines the correctly rounded result (Ziv's strategy).
 * Operands whose exact result is representable, or lies on a rounding
 * boundary, are recognized before the loop and computed exactly.
 */

#ifndef RZ_FLOAT_TRANS_H
#define RZ_FLOAT_TRANS_H

#include "float_mp.h"

/** Precision of the exact operand copies in TransCtx. */
#define TRANS_OPERAND_PREC 128

typedef struct {
	RzFloatFormat format; ///< format of the operands and the result
	ut32 p; ///< significand precision of the format
	st64 emin; ///< exponent of the smallest normal number, 2^emin
	st64 emax; ///< the largest finite number is below 2^(emax + 1)
	MpFloat x; ///< first operand, exact
	MpFloat y; ///< second floating-point operand, exact (binary operations)
	st64 n; ///< integer operand (pown, rootn, compound)
} TransCtx;

/**
 * Evaluates the operation at working precision \p w. On return either
 * *exact is true and \p r holds the exact result, or a value that rounds
 * exactly like it in every mode and format (a proxy for results that
 * overflow, underflow or sit next to a representable number), or r is an
 * approximation with |r - f| <= 2^(r.exp - w). r has precision >= w.
 */
typedef void (*TransEval)(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact);

RZ_IPI void rz_float_trans_ctx_init(TransCtx *ctx, RzFloatFormat format);
RZ_IPI RZ_OWN RzFloat *rz_float_trans_round(TransCtx *ctx, TransEval eval, RzFloatRMode mode);
RZ_IPI RZ_OWN RzFloat *rz_float_trans_from_mp(TransCtx *ctx, const MpFloat *v, RzFloatRMode mode);
RZ_IPI RZ_OWN RzFloat *rz_float_trans_si(RzFloatFormat format, st64 v);
RZ_IPI RZ_OWN RzFloat *rz_float_trans_zero(RzFloatFormat format, bool sign);
RZ_IPI RZ_OWN RzFloat *rz_float_trans_inf(RzFloatFormat format, bool sign);
RZ_IPI RZ_OWN RzFloat *rz_float_trans_invalid(RzFloatFormat format);
RZ_IPI RZ_OWN RzFloat *rz_float_trans_div_zero(RzFloatFormat format, bool sign);
RZ_IPI RZ_OWN RzFloat *rz_float_trans_nan(const RzFloat *a, const RzFloat *b);
RZ_IPI bool rz_float_trans_is_nan(const RzFloat *f);
RZ_IPI bool rz_float_trans_is_inf(const RzFloat *f);
RZ_IPI bool rz_float_trans_is_zero(const RzFloat *f);
RZ_IPI bool rz_float_trans_is_snan(const RzFloat *f);
RZ_IPI RZ_OWN RzFloat *rz_float_trans_unary(RzFloat *x, RzFloatRMode mode, TransEval eval);

/* Proxies (see float_trans.c): values that round like the exact result in
 * every mode, for results that overflow, underflow below half of the
 * smallest subnormal, or lie within |v| 2^-(p + 4) of a representable v
 * (nudge moves v by |v| 2^-(p + 3) towards +inf when up, else -inf). */
RZ_IPI void rz_float_trans_proxy_overflow(MpFloat *r, TransCtx *ctx, bool sign);
RZ_IPI void rz_float_trans_proxy_underflow(MpFloat *r, TransCtx *ctx, bool sign);
RZ_IPI void rz_float_trans_proxy_nudge(MpFloat *r, TransCtx *ctx, const MpFloat *v, bool up);

/* Cores shared between the families, at working precision w. */
RZ_IPI void rz_float_trans_expm1_small(MpFloat *r, const MpFloat *t, ut32 w);
RZ_IPI void rz_float_trans_exp(MpFloat *r, const MpFloat *x, ut32 w);
RZ_IPI void rz_float_trans_expm1(MpFloat *r, const MpFloat *x, ut32 w);
RZ_IPI void rz_float_trans_log(MpFloat *r, const MpFloat *x, ut32 w);
RZ_IPI void rz_float_trans_log1p(MpFloat *r, const MpFloat *x, ut32 w);
RZ_IPI void rz_float_trans_atan(MpFloat *r, const MpFloat *x, ut32 w);

#endif
