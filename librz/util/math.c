// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

RZ_API void rz_math_welford_init(RZ_BORROW RzMathWelfordSums *wf) {
	rz_return_if_fail(wf);
	memset(wf, 0, sizeof(RzMathWelfordSums));
}

RZ_API void rz_math_welford_clear(RZ_BORROW RzMathWelfordSums *wf) {
	rz_return_if_fail(wf);
	memset(wf, 0, sizeof(RzMathWelfordSums));
}

RZ_API void rz_math_welford_push(RZ_BORROW RzMathWelfordSums *wf, double var) {
	rz_return_if_fail(wf);
	wf->n++;

	// See Knuth TAOCP vol 2, 3rd edition, page 232
	if (wf->n == 1) {
		wf->old_mean = wf->new_mean = var;
		wf->oldS = 0.0;
	} else {
		wf->new_mean = wf->old_mean + (var - wf->old_mean) / wf->n;
		wf->newS = wf->oldS + (var - wf->old_mean) * (var - wf->new_mean);

		// set up for next iteration
		wf->old_mean = wf->new_mean;
		wf->oldS = wf->newS;
	}
}

RZ_API ut64 rz_math_welford_n(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0);
	return wf->n;
}

RZ_API double rz_math_welford_mean(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0.0);
	return (wf->n > 0) ? wf->new_mean : 0.0;
}

RZ_API double rz_math_welford_variance(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0.0);
	return ((wf->n > 1) ? wf->newS / (wf->n - 1) : 0.0);
}

RZ_API double rz_math_welford_std_deviation(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0.0);
	return sqrt(rz_math_welford_variance(wf));
}

RZ_API double rz_math_welford_sum_of_squares(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0.0);
	return wf->newS;
}
