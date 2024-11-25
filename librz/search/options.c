// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include "search_internal.h"

RZ_API bool rz_search_opt_set_backwards(RZ_NONNULL RzSearchOpt *opt, bool backwards) {
	opt->backwards = backwards;
	return true;
}

RZ_API bool rz_search_opt_set_allow_overlaps(RZ_NONNULL RzSearchOpt *opt, bool allow_overlaps) {
	opt->allow_overlaps = allow_overlaps;
	return true;
}

RZ_API bool rz_search_opt_set_inverse_match(RZ_NONNULL RzSearchOpt *opt, bool inverse_match) {
	opt->inverse_match = inverse_match;
	return true;
}

RZ_API bool rz_search_opt_set_buffer_size(RZ_NONNULL RzSearchOpt *opt, size_t buffer_size) {
	if (buffer_size < RZ_SEARCH_MIN_BUFFER_SIZE) {
		RZ_LOG_ERROR("search: buffer size is less than %u bytes.\n", RZ_SEARCH_MIN_BUFFER_SIZE);
		return false;
	}
	opt->buffer_size = buffer_size;
	return true;
}

RZ_API bool rz_search_opt_set_max_threads(RZ_NONNULL RzSearchOpt *opt, size_t max_threads) {
	opt->max_threads = max_threads;
	return true;
}

RZ_API bool rz_search_opt_set_cancel_cb(RZ_NONNULL RzSearchOpt *opt, RzSearchCancelCallback callback, void *user) {
	return true;
}
