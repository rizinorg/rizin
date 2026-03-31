// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_vector.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_itv.h>
#include <rz_util/rz_num.h>
#include <rz_util/rz_regex.h>

/**
 * \brief Parses a string to a bounded interval.
 *
 * \param itv_str The string describing the interval.
 * \param out_itv The output interval to write the result into. It is not written in case of error.
 *
 * \return True if parsing was a success, false otherwise.
 *
 * Example
 *
 * ```c
 * rz_itv_str_to_bounded_itv_ut64("[0,1)", &itv);
 * assert(itv.a == 0);
 * assert(itv.b == 1);
 * assert(itv.bound == RZ_INTERVAL_BOUND_RIGHT_OPEN);
 *
 * rz_itv_str_to_bounded_itv_ut64("0x8", &itv);
 * assert(itv.a == 8);
 * assert(itv.b == 8);
 * assert(itv.bound == RZ_INTERVAL_BOUND_CLOSED);
 * ```
 */
RZ_API bool rz_itv_str_to_bounded_itv_ut64(RZ_NONNULL const char *itv_str, RZ_OUT RzIntervalBoundedUt64 *out_itv) {
	rz_return_val_if_fail(itv_str && out_itv, false);
	if (!itv_str[0]) {
		return false;
	}

	RzRegex *re_interval = rz_regex_new("(?<left_bound>[([])\\s*(?<a>(0x[a-fA-F0-9]+|[0-9]+))\\s*,\\s*(?<b>(0x[a-fA-F0-9]+|[0-9]+))\\s*(?<right_bound>[])])", RZ_REGEX_EXTENDED, 0, NULL);
	if (!re_interval) {
		RZ_LOG_ERROR("Could not build interval regex pattern.\n");
		return false;
	}
	RzPVector *matches = rz_regex_match_first(re_interval, itv_str, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	if (!matches || rz_pvector_empty(matches)) {
		ut64 num = rz_num_get(NULL, itv_str);
		if (num == 0 && itv_str[0] != '0') {
			RZ_LOG_ERROR("Failed to parse: '%s'.\n", itv_str);
			rz_pvector_free(matches);
			return false;
		}
		out_itv->a = num;
		out_itv->b = num;
		out_itv->bound = RZ_INTERVAL_BOUND_CLOSED;
		return true;
	}
	int lb_group = rz_regex_get_group_idx_by_name(re_interval, "left_bound");
	int rb_group = rz_regex_get_group_idx_by_name(re_interval, "right_bound");
	int a_group = rz_regex_get_group_idx_by_name(re_interval, "a");
	int b_group = rz_regex_get_group_idx_by_name(re_interval, "b");
	RzRegexMatch *match;
	if (!(match = rz_pvector_at(matches, lb_group))) {
		rz_warn_if_reached();
		goto error;
	}
	bool left_open = itv_str[match->start] == '(';

	if (!(match = rz_pvector_at(matches, rb_group))) {
		rz_warn_if_reached();
		goto error;
	}
	bool right_open = itv_str[match->start] == ')';

	if (!(match = rz_pvector_at(matches, a_group))) {
		rz_warn_if_reached();
		goto error;
	}
	ut64 a = rz_num_math(NULL, itv_str + match->start);

	if (!(match = rz_pvector_at(matches, b_group))) {
		rz_warn_if_reached();
		goto error;
	}
	ut64 b = rz_num_math(NULL, itv_str + match->start);

	if (a > b) {
		RZ_LOG_ERROR("a > b is not defined.\n");
		goto error;
	}

	out_itv->a = a;
	out_itv->b = b;
	out_itv->bound = RZ_INTERVAL_BOUND_CLOSED;
	out_itv->bound |= left_open ? RZ_INTERVAL_BOUND_LEFT_OPEN : 0;
	out_itv->bound |= right_open ? RZ_INTERVAL_BOUND_RIGHT_OPEN : 0;
	rz_pvector_free(matches);
	rz_regex_free(re_interval);
	return true;

error:
	rz_pvector_free(matches);
	rz_regex_free(re_interval);
	return false;
}
