// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

/**
 * \brief Initialize a Welford Sums object.
 *
 * \param wf Pointer to the WelfordSums object to initialize.
 * \param gep_repl The geometric calculations are not valid for variables <= 0.0.
 *        If even a single one of them is used, the whole calculation becomes invalid.
 *        \p geo_repl can be set to define a value to replace these invalid ones with.
 *        So the end result is still usable.
 */
RZ_API void rz_math_welford_init(RZ_BORROW RzMathWelfordSums *wf, double geo_repl) {
	rz_return_if_fail(wf);
	memset(wf, 0, sizeof(RzMathWelfordSums));
	wf->geo_repl = geo_repl;
}

/**
 * \brief Sets \p wf to zero.
 */
RZ_API void rz_math_welford_clear(RZ_BORROW RzMathWelfordSums *wf) {
	rz_return_if_fail(wf);
	memset(wf, 0, sizeof(RzMathWelfordSums));
}

/**
 * \brief Adds a variable to the sums.
 *
 * \param wf The WelfodSums to add the variable to.
 * \param var The variable to add.
 */
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

/**
 * \brief Returns the number of variables added.
 */
RZ_API ut64 rz_math_welford_n(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0);
	return wf->n;
}

/**
 * \brief Get the arithmetic mean.
 *
 * \param wf The WelfordSums to get the arithmetic mean from.
 *
 * \return The arithmetic mean, or 0.0 in case of failure or if n == 0.
 */
RZ_API double rz_math_welford_amean(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0.0);
	return (wf->n > 0) ? wf->amean : 0.0;
}

/**
 * \brief Get the geometric mean.
 *
 * \param wf The WelfordSums to get the geometric mean from.
 *
 * \return The geometric mean, or 0.0 in case of failure or if n == 0.
 */
RZ_API double rz_math_welford_gmean(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0.0);
	return (wf->n > 0) ? wf->gmean : 0.0;
}

/**
 * \brief Get the arithmetic variance.
 *
 * \param wf The WelfordSums to get the arithmetic variance from.
 *
 * \return The arithmetic variance, or 0.0 in case of failure or if n == 0.
 */
RZ_API double rz_math_welford_avar(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0.0);
	return ((wf->n > 1) ? wf->asums / wf->n : 0.0);
}

/**
 * \brief Get the arithmetic standard deviation.
 * Note: This is not the sample standard deviation!
 *
 * \param wf The WelfordSums to get the arithmetic standard deviation from.
 *
 * \return The arithmetic standard deviation, or 0.0 in case of failure or if n <= 1.
 */
RZ_API double rz_math_welford_astddev(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0.0);
	return sqrt(rz_math_welford_avar(wf));
}

/**
 * \brief Get the geometric **sample** standard deviation.
 *
 * \param wf The WelfordSums to get the geometric standard deviation from.
 *
 * \return The geometric sample standard deviation, or 0.0 in case of failure or if n <= 1.
 */
RZ_API double rz_math_welford_gstddev(const RzMathWelfordSums *wf) {
	rz_return_val_if_fail(wf, 0.0);
	return (wf->n > 1) ? exp(sqrt(wf->gsums / (wf->n - 1))) : 0.0;
}

/**
 * \brief Calculates softmax probability for \p zi in respect to the elements in \p zjs.
 *
 * \param zi An element from the the input tuple \p zjs to determine the softmax probability for.
 * \param zjs All elements of the input tuple.
 *
 * \return The softmax for \p zi, or a negative number in case of failure.
 */
RZ_API double rz_math_softmax_p_zi_st64(st64 zi, RZ_BORROW RZ_NONNULL RzIterator /*<st64 *>*/ *zjs) {
	rz_return_val_if_fail(zjs, -1.0);

	double numerator = exp(zi);
	double den = 0.0;
	st64 *zj;
	rz_iterator_foreach(zjs, zj) {
		den += exp(*zj);
	}
	return numerator / den;
}

/**
 * \brief Calculates softmax over the iterator \p zjs.
 * In case of an error, a warning is printed and it returns ST64_MIN.
 * Since ST64_MIN is theoretically a valid return value, the user
 * should ensure to pass valid iterators here.
 *
 * \param zjs Iterator over all elements of the input tuple.
 * \param zp The probabilities for each element in \p zjs. Pushed into it in order of the iterator.
 *
 * \return The softmax for \p zi.
 */
RZ_API st64 rz_math_softmax_st64(RZ_BORROW RZ_NONNULL RzIterator /*<st64 *>*/ *zjs, RZ_NULLABLE RZ_OUT RzVector /*double*/ *zp) {
	rz_return_val_if_fail(zjs, ST64_MIN);

	st64 *z;
	double den = 0.0;
	size_t c = 0;
	rz_iterator_foreach(zjs, z) {
		c++;
		den += exp(*z);
	}
	if (!c) {
		rz_warn_if_reached();
		return ST64_MIN;
	}

	if (!rz_iterator_reset(zjs)) {
		rz_warn_if_reached();
		return ST64_MIN;
	}
	double max_p = 0.0;
	st64 max_z = 0;
	rz_iterator_foreach(zjs, z) {
		double p = exp(*z) / den;
		if (zp) {
			rz_vector_push(zp, &p);
		}
		if (p > max_p) {
			max_p = p;
			max_z = *z;
		}
	}
	return max_z;
}
