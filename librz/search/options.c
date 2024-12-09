// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include "search_internal.h"

RZ_API RZ_OWN RzSearchOpt *rz_search_opt_new() {
	RzSearchOpt *opt = RZ_NEW0(RzSearchOpt);
	if (!opt) {
		return NULL;
	}
	opt->max_threads = RZ_THREAD_N_CORES_ALL_AVAILABLE;
	opt->buffer_size = RZ_SEARCH_MIN_BUFFER_SIZE;
	return opt;
}

RZ_API void rz_search_opt_free(RZ_NULLABLE RzSearchOpt *opt) {
	free(opt);
}

RZ_API bool rz_search_opt_set_inverse_match(RZ_NONNULL RzSearchOpt *opt, bool inverse_match) {
	rz_return_val_if_fail(opt, false);
	opt->inverse_match = inverse_match;
	return true;
}

RZ_API bool rz_search_opt_set_buffer_size(RZ_NONNULL RzSearchOpt *opt, size_t buffer_size) {
	rz_return_val_if_fail(opt, false);
	if (buffer_size < RZ_SEARCH_MIN_BUFFER_SIZE) {
		RZ_LOG_ERROR("search: buffer size is less than %u bytes.\n", RZ_SEARCH_MIN_BUFFER_SIZE);
		return false;
	}
	opt->buffer_size = buffer_size;
	return true;
}

RZ_API bool rz_search_opt_set_max_hits(RZ_NONNULL RzSearchOpt *opt, size_t max_hits) {
	rz_return_val_if_fail(opt, false);
	opt->max_hits = max_hits;
	return true;
}

RZ_API bool rz_search_opt_set_max_threads(RZ_NONNULL RzSearchOpt *opt, RzThreadNCores max_threads) {
	rz_return_val_if_fail(opt, false);
	opt->max_threads = max_threads;
	return true;
}

RZ_API bool rz_search_opt_set_cancel_cb(RZ_NONNULL RzSearchOpt *opt, RzSearchCancelCallback callback, void *user) {
	rz_return_val_if_fail(opt, false);
	opt->cancel_cb = callback;
	opt->cancel_usr = user;
	return true;
}
