// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_MATH_H
#define RZ_MATH_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief A Welford Sums of Squares implementation take from
 * https://www.johndcook.com/blog/standard_deviation/
 * doi: http://dx.doi.org/10.1080/00401706.1962.10490022
 */
typedef struct {
	ut64 n; ///< Number of variables
	double amean; ///< The arithmetic mean of the variables.
	double asums; ///< Sum of squares.
	double gmean; ///< Geometric mean
	double ln_v_sums; ///< Geometric sum of ln(x_i)
	double gsums; ///< Geometric sums of squares
	double geo_repl; ///< The replacement value for geometric calculations if the given var <= 0.0.
} RzMathWelfordSums;

RZ_API void rz_math_welford_init(RZ_BORROW RzMathWelfordSums *wf, double geo_repl);
RZ_API void rz_math_welford_clear(RZ_BORROW RzMathWelfordSums *wf);
RZ_API void rz_math_welford_push(RZ_BORROW RzMathWelfordSums *wf, double var);
RZ_API ut64 rz_math_welford_n(const RzMathWelfordSums *wf);
RZ_API double rz_math_welford_amean(const RzMathWelfordSums *wf);
RZ_API double rz_math_welford_avar(const RzMathWelfordSums *wf);
RZ_API double rz_math_welford_astddev(const RzMathWelfordSums *wf);
RZ_API double rz_math_welford_asums(const RzMathWelfordSums *wf);

RZ_API double rz_math_welford_gmean(const RzMathWelfordSums *wf);
RZ_API double rz_math_welford_gvar(const RzMathWelfordSums *wf);
RZ_API double rz_math_welford_gstddev(const RzMathWelfordSums *wf);

#ifdef __cplusplus
}
#endif

#endif // RZ_MATH_H
