// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_MATH_H
#define RZ_MATH_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief A Welford Variance implementation take from
 * https://www.johndcook.com/blog/standard_deviation/
 */
typedef struct {
	ut64 n; ///< Number of variables
	double old_mean; ///< The mean before a variable is added.
	double new_mean; ///< The mean after a variable was added.
	double oldS; ///< Sum of squares before a variable is added.
	double newS; ///< Sum of squares after a variable was added.
} RzMathWelfordSums;

RZ_API void rz_math_welford_init(RZ_BORROW RzMathWelfordSums *wf);
RZ_API void rz_math_welford_clear(RZ_BORROW RzMathWelfordSums *wf);
RZ_API void rz_math_welford_push(RZ_BORROW RzMathWelfordSums *wf, double var);
RZ_API ut64 rz_math_welford_n(const RzMathWelfordSums *wf);
RZ_API double rz_math_welford_mean(const RzMathWelfordSums *wf);
RZ_API double rz_math_welford_variance(const RzMathWelfordSums *wf);
RZ_API double rz_math_welford_std_deviation(const RzMathWelfordSums *wf);
RZ_API double rz_math_welford_sum_of_squares(const RzMathWelfordSums *wf);

#ifdef __cplusplus
}
#endif

#endif // RZ_MATH_H
