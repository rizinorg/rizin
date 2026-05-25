// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

RZ_API void rz_math_welford_init(RZ_BORROW RzMathWelfordSums *wf, double geo_repl) {
	rz_return_if_fail(wf);
	memset(wf, 0, sizeof(RzMathWelfordSums));
	wf->geo_repl = geo_repl;
}

RZ_API void rz_math_welford_clear(RZ_BORROW RzMathWelfordSums *wf) {
	rz_return_if_fail(wf);
	memset(wf, 0, sizeof(RzMathWelfordSums));
}

RZ_API void rz_math_welford_push(RZ_BORROW RzMathWelfordSums *wf, double var) {
	rz_return_if_fail(wf);
	if (var <= (double)0.0 && wf->geo_repl) {
		var = wf->geo_repl;
	}
	wf->n++;

	// See Knuth TAOCP vol 2, 3rd edition, page 232
	if (wf->n == 1) {
		wf->amean = var;
		wf->asums = 0.0;
		wf->gmean = var;
		wf->ln_v_sums = log(var);
		wf->gsums = 0.0;
	} else {
		// Arithmetic
		double old_amean = wf->amean;
		wf->amean = old_amean + (var - old_amean) / wf->n;
		wf->asums += (var - old_amean) * (var - wf->amean);

		// Geometric
		double old_gmean = wf->gmean;
		wf->ln_v_sums += log(var);
		wf->gmean = exp(wf->ln_v_sums / wf->n);
		wf->gsums += log(var / old_gmean) * log(var / wf->gmean);
	}
}

RZ_API ut64 rz_math_welford_n(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0);
	return wf->n;
}

RZ_API double rz_math_welford_amean(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0.0);
	return (wf->n > 0) ? wf->amean : 0.0;
}

RZ_API double rz_math_welford_gmean(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0.0);
	return (wf->n > 0) ? wf->gmean : 0.0;
}

RZ_API double rz_math_welford_avar(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0.0);
	return ((wf->n > 1) ? wf->asums / wf->n : 0.0);
}

RZ_API double rz_math_welford_astddev(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0.0);
	return sqrt(rz_math_welford_avar(wf));
}

RZ_API double rz_math_welford_gstddev(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0.0);
	return (wf->n > 1) ? exp(sqrt(wf->gsums / (wf->n - 1))) : 0.0;
}
