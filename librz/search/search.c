// SPDX-FileCopyrightText: 2024-2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024-2025 Rot127 <rot127@posteo.com>
// SPDX-FileCopyrightText: 2024-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_list.h>
#include <rz_th.h>
#include <rz_util/rz_buf.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_mem.h>
#include <rz_util/rz_strbuf.h>
#include <rz_search.h>
#include "search_internal.h"

// Experimental search engine (fails, because stops at first hit of every block read
#define USE_BMH 0

RZ_LIB_VERSION(rz_search);

typedef struct {
	ut64 end;
	int len;
	ut8 data[];
} RzSearchLeftover;

RZ_API RzSearch *rz_search_new(int mode) {
	RzSearch *s = RZ_NEW0(RzSearch);
	if (!s) {
		return NULL;
	}
	if (!rz_search_set_mode(s, mode)) {
		free(s);
		eprintf("Cannot init search for mode %d\n", mode);
		return false;
	}
	s->inverse = false;
	s->data = NULL;
	s->user = NULL;
	s->callback = NULL;
	s->align = 1;
	s->distance = 0;
	s->contiguous = 0;
	s->overlap = false;
	s->pattern_size = 0;
	s->string_max = 255;
	s->string_min = 3;
	s->hits = rz_list_newf(free);
	s->maxhits = 0;
	// TODO: review those mempool sizes. ensure never gets NULL
	s->kws = rz_list_newf(free);
	if (!s->kws) {
		rz_search_free(s);
		return NULL;
	}
	s->kws->free = (RzListFree)rz_search_keyword_free;
	return s;
}

RZ_API RzSearch *rz_search_free(RzSearch *s) {
	if (!s) {
		return NULL;
	}
	rz_list_free(s->hits);
	rz_list_free(s->kws);
	// rz_io_free(s->iob.io); this is supposed to be a weak reference
	free(s->data);
	free(s);
	return NULL;
}

RZ_API int rz_search_set_string_limits(RzSearch *s, ut32 min, ut32 max) {
	if (max < min) {
		return false;
	}
	s->string_min = min;
	s->string_max = max;
	return true;
}

RZ_API int rz_search_strings_update(RzSearch *s, ut64 from, const ut8 *buf, int len) {
	rz_return_val_if_fail(s && buf && len, -1);

	RzUtilStrScanOptions scan_opt = {
		.max_str_length = len,
		.min_str_length = s->string_min,
		.prefer_big_endian = false,
	};
	RzList *str_list = rz_list_new();
	if (!str_list) {
		return 0;
	}

	int count = rz_scan_strings_raw(buf, str_list, &scan_opt, from, from + len, RZ_STRING_ENC_GUESS);
	if (count <= 0) {
		rz_list_free(str_list);
		return false;
	}

	RzListIter *iter, *iter2;
	RzSearchKeyword *kw;

	int matches = 0;
	rz_list_foreach (s->kws, iter, kw) {
		RzDetectedString *dstr;
		rz_list_foreach (str_list, iter2, dstr) {
			if (rz_search_legacy_hit_new(s, kw, dstr->addr) != 1) {
				// Max hits or error
				break;
			}
			matches++;
		}
	}
	RZ_FREE_CUSTOM(str_list, rz_list_free);
	return matches;
}

RZ_API int rz_search_magic_update(RzSearch *s, ut64 from, const ut8 *buf, int len) {
	eprintf("TODO: import librz/core/cmd_search.c /m implementation into rsearch\n");
	return false;
}

RZ_API int rz_search_set_mode(RzSearch *s, int mode) {
	s->update = NULL;
	switch (mode) {
	case RZ_SEARCH_KEYWORD: s->update = rz_search_mybinparse_update; break;
	case RZ_SEARCH_REGEXP: s->update = rz_search_regexp_update; break;
	case RZ_SEARCH_STRING: s->update = rz_search_strings_update; break;
	case RZ_SEARCH_DELTAKEY: s->update = rz_search_deltakey_update; break;
	case RZ_SEARCH_MAGIC: s->update = rz_search_magic_update; break;
	}
	if (s->update || mode == RZ_SEARCH_PATTERN) {
		s->mode = mode;
		return true;
	}
	return false;
}

RZ_API int rz_search_begin(RzSearch *s) {
	RzListIter *iter;
	RzSearchKeyword *kw;
	rz_list_foreach (s->kws, iter, kw) {
		kw->count = 0;
		kw->last = 0;
	}
	return true;
}

// Returns 2 if search.maxhits is reached, 0 on error, otherwise 1
RZ_API int rz_search_legacy_hit_new(RzSearch *s, RzSearchKeyword *kw, ut64 addr) {
	if (s->align > 1 && (addr % s->align)) {
		eprintf("0x%08" PFMT64x " unaligned\n", addr);
		return 1;
	}
	if (!s->contiguous) {
		if (kw->last && addr == kw->last) {
			kw->count--;
			kw->last = addr + kw->keyword_length;
			eprintf("0x%08" PFMT64x " Sequential hit ignored.\n", addr);
			return 1;
		}
	}
	// kw->last is used by string search, the right endpoint of last match (forward search), to honor search.overlap
	kw->last = addr + kw->keyword_length;

	if (s->callback) {
		int ret = s->callback(kw, s->user, addr);
		kw->count++;
		s->nhits++;
		// If callback returns 0 or larger than 1, forwards it; otherwise returns 2 if search.maxhits is reached
		return !ret || ret > 1 ? ret : s->maxhits && s->nhits >= s->maxhits ? 2
										    : 1;
	}
	kw->count++;
	s->nhits++;
	RzSearchLegacyHit *hit = RZ_NEW0(RzSearchLegacyHit);
	if (hit) {
		hit->kw = kw;
		hit->addr = addr;
		rz_list_append(s->hits, hit);
	}
	return s->maxhits && s->nhits >= s->maxhits ? 2 : 1;
}

// TODO support search across block boundaries
// Supported search variants: backward, overlap
RZ_API int rz_search_deltakey_update(RzSearch *s, ut64 from, const ut8 *buf, int len) {
	RzListIter *iter;
	int longest = 0, i, j;
	RzSearchKeyword *kw;
	RzSearchLeftover *left;
	const int old_nhits = s->nhits;
	rz_list_foreach (s->kws, iter, kw) {
		longest = RZ_MAX(longest, kw->keyword_length + 1);
	}
	if (!longest) {
		return 0;
	}
	if (s->data) {
		left = s->data;
		if (left->end != from) {
			left->len = 0;
		}
	} else {
		left = malloc(sizeof(RzSearchLeftover) + (size_t)2 * (longest - 1));
		if (!left) {
			return -1;
		}
		s->data = left;
		left->len = 0;
	}

	ut64 len1 = left->len + RZ_MIN(longest - 1, len);
	memcpy(left->data + left->len, buf, len1 - left->len);
	rz_list_foreach (s->kws, iter, kw) {
		ut8 *a = kw->bin_keyword;
		i = s->overlap ||
				!kw->count
			? 0
			: from - kw->last < left->len ? kw->last + left->len - from
						      : 0;
		for (; i + kw->keyword_length < len1 && i < left->len; i++) {
			if ((ut8)(left->data[i + 1] - left->data[i]) == a[0]) {
				j = 1;
				while (j < kw->keyword_length && (ut8)(left->data[i + j + 1] - left->data[i + j]) == a[j]) {
					j++;
				}
				if (j == kw->keyword_length) {
					int t = rz_search_legacy_hit_new(s, kw, from + i - left->len);
					kw->last += 1;
					if (!t) {
						return -1;
					}
					if (t > 1) {
						return s->nhits - old_nhits;
					}
					if (!s->overlap) {
						i += kw->keyword_length;
					}
				}
			}
		}
		i = s->overlap || !kw->count ? 0 : from < kw->last ? kw->last - from
								   : 0;
		for (; i + kw->keyword_length < len; i++) {
			if ((ut8)(buf[i + 1] - buf[i]) == a[0]) {
				j = 1;
				while (j < kw->keyword_length && (ut8)(buf[i + j + 1] - buf[i + j]) == a[j]) {
					j++;
				}
				if (j == kw->keyword_length) {
					int t = rz_search_legacy_hit_new(s, kw, from + i);
					kw->last += 1;
					if (!t) {
						return -1;
					}
					if (t > 1) {
						return s->nhits - old_nhits;
					}
					if (!s->overlap) {
						i += kw->keyword_length;
					}
				}
			}
		}
	}
	if (len < longest - 1) {
		if (len1 < longest) {
			left->len = len1;
		} else {
			left->len = longest - 1;
			memmove(left->data, left->data + len1 - longest + 1, longest - 1);
		}
	} else {
		left->len = longest - 1;
		memcpy(left->data, buf + len - longest + 1, longest - 1);
	}
	left->end = from + len;

	return s->nhits - old_nhits;
}

static bool brute_force_match(RzSearch *s, RzSearchKeyword *kw, const ut8 *buf, int i) {
	int j = 0;
	if (s->distance) { // slow path, more work in the loop
		int dist = 0;
		if (kw->binmask_length > 0) {
			for (; j < kw->keyword_length; j++) {
				int k = j % kw->binmask_length;
				ut8 a = buf[i + j], b = kw->bin_keyword[j];
				if (kw->icase) {
					a = tolower(a);
					b = tolower(b);
				}
				if ((a & kw->bin_binmask[k]) != (b & kw->bin_binmask[k])) {
					dist++;
				}
			}
		} else if (kw->icase) {
			for (; j < kw->keyword_length; j++) {
				if (tolower(buf[i + j]) != tolower(kw->bin_keyword[j])) {
					dist++;
				}
			}
		} else {
			for (; j < kw->keyword_length; j++) {
				if (buf[i + j] != kw->bin_keyword[j]) {
					dist++;
				}
			}
		}
		return dist <= s->distance;
	}

	if (kw->binmask_length > 0) {
		for (; j < kw->keyword_length; j++) {
			int k = j % kw->binmask_length;
			ut8 a = buf[i + j], b = kw->bin_keyword[j];
			if (kw->icase) {
				a = tolower(a);
				b = tolower(b);
			}
			if ((a & kw->bin_binmask[k]) != (b & kw->bin_binmask[k])) {
				break;
			}
		}
	} else if (kw->icase) {
		while (j < kw->keyword_length &&
			tolower(buf[i + j]) == tolower(kw->bin_keyword[j])) {
			j++;
		}
	} else {
		while (j < kw->keyword_length && buf[i + j] == kw->bin_keyword[j]) {
			j++;
		}
	}
	return j == kw->keyword_length;
}

// Supported search variants: backward, binmask, icase, inverse, overlap
RZ_API int rz_search_mybinparse_update(RzSearch *s, ut64 from, const ut8 *buf, int len) {
	RzSearchKeyword *kw;
	RzListIter *iter;
	RzSearchLeftover *left;
	int longest = 0, i;
	const int old_nhits = s->nhits;

	rz_list_foreach (s->kws, iter, kw) {
		longest = RZ_MAX(longest, kw->keyword_length);
	}
	if (!longest) {
		return 0;
	}
	if (s->data) {
		left = s->data;
		if (left->end != from) {
			left->len = 0;
		}
	} else {
		left = malloc(sizeof(RzSearchLeftover) + (size_t)2 * (longest - 1));
		if (!left) {
			return -1;
		}
		s->data = left;
		left->len = 0;
	}

	ut64 len1 = left->len + RZ_MIN(longest - 1, len);
	memcpy(left->data + left->len, buf, len1 - left->len);
	rz_list_foreach (s->kws, iter, kw) {
		i = s->overlap || !kw->count ? 0 : from - kw->last < left->len ? kw->last + left->len - from
									       : 0;
		for (; i + kw->keyword_length <= len1 && i < left->len; i++) {
			if (brute_force_match(s, kw, left->data, i) != s->inverse) {
				int t = rz_search_legacy_hit_new(s, kw, from + i - left->len);
				if (!t) {
					return -1;
				}
				if (t > 1) {
					return s->nhits - old_nhits;
				}
				if (!s->overlap) {
					i += kw->keyword_length - 1;
				}
			}
		}
		i = s->overlap || !kw->count ? 0 : from < kw->last ? kw->last - from
								   : 0;
		for (; i + kw->keyword_length <= len; i++) {
			if (brute_force_match(s, kw, buf, i) != s->inverse) {
				int t = rz_search_legacy_hit_new(s, kw, from + i);
				if (!t) {
					return -1;
				}
				if (t > 1) {
					return s->nhits - old_nhits;
				}
				if (!s->overlap) {
					i += kw->keyword_length - 1;
				}
			}
		}
	}
	if (len < longest - 1) {
		if (len1 < longest) {
			left->len = len1;
		} else {
			left->len = longest - 1;
			memmove(left->data, left->data + len1 - longest + 1, longest - 1);
		}
	} else {
		left->len = longest - 1;
		memcpy(left->data, buf + len - longest + 1, longest - 1);
	}
	left->end = from + len;

	return s->nhits - old_nhits;
}

RZ_API void rz_search_set_distance(RzSearch *s, int dist) {
	if (dist >= RZ_SEARCH_DISTANCE_MAX) {
		eprintf("Invalid distance\n");
		s->distance = 0;
	} else {
		s->distance = (dist > 0) ? dist : 0;
	}
}

// deprecate? or standarize with ->align ??
RZ_API void rz_search_pattern_size(RzSearch *s, int size) {
	s->pattern_size = size;
}

RZ_API void rz_search_set_callback(RzSearch *s, RzSearchCallback(callback), void *user) {
	s->callback = callback;
	s->user = user;
}

// backward search: from points to the right endpoint
// forward search: from points to the left endpoint
RZ_API int rz_search_update(RzSearch *s, ut64 from, const ut8 *buf, long len) {
	int ret = -1;
	if (s->update) {
		if (s->maxhits && s->nhits >= s->maxhits) {
			return 0;
		}
		ret = s->update(s, from, buf, len);
	} else {
		eprintf("rz_search_update: No search method defined\n");
	}
	return ret;
}

RZ_API int rz_search_update_i(RzSearch *s, ut64 from, const ut8 *buf, long len) {
	return rz_search_update(s, from, buf, len);
}

static int listcb(RzSearchKeyword *k, void *user, ut64 addr) {
	RzSearchLegacyHit *hit = RZ_NEW0(RzSearchLegacyHit);
	if (!hit) {
		return 0;
	}
	hit->kw = k;
	hit->addr = addr;
	rz_list_append(user, hit);
	return 1;
}

RZ_API RzList /*<RzSearchHit *>*/ *rz_search_find(RzSearch *s, ut64 addr, const ut8 *buf, int len) {
	RzList *ret = rz_list_new();
	rz_search_set_callback(s, listcb, ret);
	rz_search_update(s, addr, buf, len);
	return ret;
}

/* --- keywords --- */
RZ_API int rz_search_kw_add(RzSearch *s, RzSearchKeyword *kw) {
	if (!kw || !kw->keyword_length) {
		return false;
	}
	kw->kwidx = s->n_kws++;
	rz_list_append(s->kws, kw);
	return true;
}

RZ_API void rz_search_reset(RzSearch *s, int mode) {
	s->nhits = 0;
	if (!rz_search_set_mode(s, mode)) {
		eprintf("Cannot init search for mode %d\n", mode);
	}
}

RZ_API void rz_search_kw_reset(RzSearch *s) {
	rz_list_purge(s->kws);
	rz_list_purge(s->hits);
	RZ_FREE(s->data);
}

//
// NEW SEARCH BEGIN
// Everything above is only there to not break the build.
//

#include "search_internal.h"

// RZ_LIB_VERSION(rz_search);

typedef struct search_ctx {
	RzIO *io; ///< the RzIO struct to use
	RzThreadLock *io_lock;
	RzBuffer *buffer; ///< RzBuffer to search in. If this is set, io should be NULL.
	RzThreadLock *buffer_lock;
	RzSearchCollection *col; ///< collection to use
	RzSearchOpt *opt; ///< User options
	RzThreadQueue /* RzSearchHits */ *hits; ///< Hits list
	RzAtomicBool *loop; ///< If set, the execution will continue until it terminates. If unset, the execution cancels.
	RzThreadQueue /* RzSearchInterval */ *finished_intervals; ///< Interval queue
} search_ctx_t;

static void print_intervals(RZ_NONNULL RzThreadQueue *intervals) {
	rz_return_if_fail(intervals);

	void *data = NULL;
	while (rz_th_queue_pop(intervals, false, &data) && data) {
		RzSearchInterval *search_interval = (RzSearchInterval *)data;
		RzInterval *itv = &search_interval->interval;
		eprintf("[0x%" PFMT64x ", 0x%" PFMT64x "): %" PFMTSZu "\n", itv->addr, itv->addr + itv->size,
			search_interval->n_hits);
		data = NULL;
	}
}

static void *search_cancel_th(void *user) {
	search_ctx_t *ctx = (search_ctx_t *)user;
	RzSearchOpt *opt = ctx->opt;

	while (true) {
		rz_sys_usleep(RZ_SEARCH_CANCEL_CHECK_INTERVAL_USEC);
		if (!rz_atomic_bool_get(ctx->loop)) {
			break;
		}
		print_intervals(ctx->finished_intervals);
		size_t n_hits = rz_th_queue_size(ctx->hits);
		if (opt->cancel_cb(opt->cancel_usr, n_hits, RZ_SEARCH_CANCEL_REGULAR_CHECK)) {
			rz_atomic_bool_set(ctx->loop, false);
			break;
		}
	}
	print_intervals(ctx->finished_intervals);

	return NULL;
}

static bool search_iterator_io_map_cb(void *element, void *user) {
	search_ctx_t *ctx = (search_ctx_t *)user;
	RzInterval *window = (RzInterval *)element;
	if (!window) {
		return rz_atomic_bool_get(ctx->loop);
	}
	if (!ctx->opt) {
		RZ_LOG_ERROR("No search options given.\n");
		return false;
	}

	RzSearchCollection *col = ctx->col;

	ut64 at = window->addr;
	ut64 size = window->size;

	RzBuffer *buffer = NULL;
	if (ctx->io) {
		rz_th_lock_enter(ctx->io_lock);
		buffer = rz_io_nread_at_new_buf(ctx->io, at, size);
		if (!buffer || rz_buf_size(buffer) != size) {
			RZ_LOG_ERROR("search: failed to read at 0x%08" PFMT64x " (0x%08" PFMT64x " bytes)\n", at, size);
			rz_th_lock_leave(ctx->io_lock);
			goto failure;
		}
		rz_th_lock_leave(ctx->io_lock);
	} else {
		ut8 *window_data = RZ_NEWS(ut8, size);
		rz_th_lock_enter(ctx->buffer_lock);
		size = rz_buf_read_at(ctx->buffer, at, window_data, size);
		rz_th_lock_leave(ctx->buffer_lock);
		buffer = rz_buf_new_with_bytes(window_data, size);
		free(window_data);
		if (!buffer) {
			RZ_LOG_ERROR("search: failed to read at 0x%08" PFMT64x " (0x%08" PFMT64x " bytes)\n", at, size);
			goto failure;
		}
	}

	size_t n_hits = 0;
	RzSearchFindBytesCallback find = col->find;
	if (!find(ctx->opt->find_opts, col->user, at, buffer, ctx->hits, &n_hits)) {
		RZ_LOG_ERROR("search: failed search at 0x%08" PFMT64x "\n", at);
		goto failure;
	} else if (ctx->opt->show_progress == RZ_SEARCH_PROGRESS_INTERVALS) {
		RzSearchInterval *interval = rz_search_interval_new(*window, n_hits);
		if (!interval || !rz_th_queue_push(ctx->finished_intervals, interval, true)) {
			RZ_LOG_ERROR("search: failed to push search interval to queue\n");
			free(interval);
			goto failure;
		}
	}

	rz_buf_free(buffer);
	return rz_atomic_bool_get(ctx->loop);

failure:
	rz_buf_free(buffer);
	rz_atomic_bool_set(ctx->loop, false);
	return false;
}

static RzList /*<RzInterval *>*/ *assemble_search_window_list(RzList /*<RzIOMap *>*/ *search_in, RzSearchOpt *opt) {
	rz_return_val_if_fail(search_in && opt && opt->element_size, NULL);
	RzList *list = rz_list_newf(free);
	if (!list) {
		return NULL;
	}

	RzIOMap *map;
	RzListIter *iter;
	rz_list_foreach (search_in, iter, map) {
		ut64 start = map->itv.addr;
		ut64 end = start + map->itv.size;
		for (size_t chunk_begin = start; chunk_begin < end; chunk_begin += opt->chunk_size) {
			ut64 window_size = opt->chunk_size + opt->element_size - 1;
			if (chunk_begin + window_size > end) {
				window_size = end - chunk_begin;
			}

			RzInterval *window = RZ_NEW0(RzInterval);
			window->addr = chunk_begin;
			window->size = window_size;
			rz_list_append(list, window);
		}
	}
	return list;
}

static bool perform_sanity_checks(
	RZ_BORROW RZ_NONNULL RzSearchOpt *opt,
	RZ_BORROW RZ_NONNULL RzSearchCollection *col) {
	if (!rz_search_collection_on_bytes_space(col)) {
		RZ_LOG_ERROR("search: The search collection is not initialized for byte space.\n");
		return false;
	}

	if (opt->chunk_size < RZ_SEARCH_MIN_CHUNK_SIZE) {
		RZ_LOG_ERROR("search: cannot search when buffer size is less than %#" PFMT64x " bytes.\n", RZ_SEARCH_MIN_CHUNK_SIZE);
		return false;
	}

	if (rz_search_collection_is_empty(col)) {
		RZ_LOG_ERROR("search: cannot perform the search when the search collection is empty.\n");
		return false;
	}
	return true;
}

/**
 * \brief      Perform a search within the given search maps of a collection
 *
 * \param      opt        The RzSearchOpt to use
 * \param      col        The RzSearchCollection to use
 * \param      io         The RzIO layer to use
 * \param      search_in  The search maps for the boundaries
 *
 * \return     On success returns all the hits.
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_search_on_io(
	RZ_BORROW RZ_NONNULL RzSearchOpt *opt,
	RZ_BORROW RZ_NONNULL RzSearchCollection *col,
	RZ_BORROW RZ_NONNULL RzIO *io,
	RZ_BORROW RZ_NONNULL RzList /*<RzIOMap *>*/ *search_in) {
	rz_return_val_if_fail(opt && col && io && search_in, NULL);
	search_ctx_t ctx = { 0 };
	RzList *results = NULL;
	RzThreadQueue *hits = NULL;
	RzThreadQueue *intervals = NULL;
	RzList /* RzInterval */ *windows = NULL;
	RzThread *cancel_th = NULL;

	if (!perform_sanity_checks(opt, col)) {
		return NULL;
	}

	if (rz_list_empty(search_in)) {
		RZ_LOG_ERROR("search: cannot search in an empty RzIOMap list.\n");
		return NULL;
	}

	hits = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, (RzListFree)rz_search_hit_free);
	if (!hits) {
		RZ_LOG_ERROR("search: cannot allocate RzSearchHit queue.\n");
		return NULL;
	}

	intervals = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, (RzListFree)rz_search_interval_free);
	if (!intervals) {
		RZ_LOG_ERROR("search: cannot allocate RzSearchInterval queue.\n");
		rz_th_queue_free(hits);
		return NULL;
	}

	windows = assemble_search_window_list(search_in, opt);
	if (!windows) {
		RZ_LOG_ERROR("search: Could not prepare search window queue.\n");
		rz_th_queue_free(hits);
		rz_th_queue_free(intervals);
		return NULL;
	}

	ctx.col = col;
	ctx.opt = opt;
	ctx.io = io;
	ctx.io_lock = rz_th_lock_new(false);
	ctx.loop = rz_atomic_bool_new(true);
	ctx.hits = hits;
	ctx.finished_intervals = intervals;

	if (opt->cancel_cb) {
		// create cancel thread
		cancel_th = rz_th_new(search_cancel_th, &ctx);
		if (!cancel_th) {
			RZ_LOG_ERROR("search: cannot allocate cancel thread.\n");
			rz_th_queue_free(hits);
			rz_th_queue_free(intervals);
			rz_atomic_bool_free(ctx.loop);
			rz_list_free(windows);
			return NULL;
		}
	}

	if (!rz_th_iterate_list(windows, search_iterator_io_map_cb, opt->max_threads, &ctx)) {
		RZ_LOG_ERROR("search: cannot iterate over list.\n");
	} else {
		results = rz_th_queue_pop_all(hits);
	}

	if (cancel_th) {
		// stop & free cancel thread.
		rz_atomic_bool_set(ctx.loop, false);
		rz_th_queue_close_when_empty(intervals);
		rz_th_wait(cancel_th);
		rz_th_free(cancel_th);
		rz_atomic_bool_free(ctx.loop);
	}

	rz_th_lock_free(ctx.io_lock);
	rz_list_free(windows);
	rz_th_queue_free(hits);
	rz_th_queue_free(intervals);

	rz_list_sort(results, (RzListComparator)rz_search_hit_cmp, NULL);
	rz_list_sorted_uniq(results, (RzListComparator)rz_search_hit_cmp, NULL);
	return results;
}

/**
 * \brief      Perform a search within the given search maps of a collection
 *
 * \param      opt        The RzSearchOpt to use
 * \param      col        The RzSearchCollection to use
 * \param      buffer     The RzBuffer to search in.
 * \param      ranges     An optional list of ranges to search in. The whole
 *                        buffer is searched if NULL.
 *
 * \return     On success returns all the hits.
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_search_on_buffer(
	RZ_BORROW RZ_NONNULL RzSearchOpt *opt,
	RZ_BORROW RZ_NONNULL RzSearchCollection *col,
	RZ_BORROW RZ_NONNULL RzBuffer *buffer,
	RZ_NULLABLE const RzList /*<RzInterval *>*/ *ranges) {
	rz_return_val_if_fail(opt && col && buffer, NULL);
	search_ctx_t ctx = { 0 };
	RzList *results = NULL;
	RzThreadQueue *hits = NULL;
	RzThreadQueue *intervals = NULL;
	RzList /* RzInterval */ *windows = NULL;
	RzThread *cancel_th = NULL;

	if (!perform_sanity_checks(opt, col)) {
		return NULL;
	}

	hits = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, (RzListFree)rz_search_hit_free);
	if (!hits) {
		RZ_LOG_ERROR("search: cannot allocate RzSearchHit queue.\n");
		return NULL;
	}

	intervals = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, (RzListFree)rz_search_interval_free);
	if (!intervals) {
		RZ_LOG_ERROR("search: cannot allocate RzSearchInterval queue.\n");
		rz_th_queue_free(hits);
		return NULL;
	}

	RzList *search_in = rz_list_new();
	if (ranges) {
		RzListIter *it;
		RzInterval *itv;
		rz_list_foreach (ranges, it, itv) {
			RzIOMap *map = RZ_NEW0(RzIOMap);
			map->itv.addr = itv->addr;
			map->itv.size = itv->size;
			rz_list_append(search_in, map);
		}
	} else {
		RzIOMap *map = RZ_NEW0(RzIOMap);
		map->itv.addr = 0;
		map->itv.size = rz_buf_size(buffer);
		rz_list_append(search_in, map);
	}
	windows = assemble_search_window_list(search_in, opt);
	RzIOMap *map;
	RzListIter *iter;
	rz_list_foreach (search_in, iter, map) {
		RZ_FREE(map);
	}
	rz_list_free(search_in);

	if (!windows) {
		RZ_LOG_ERROR("search: Could not prepare search window queue.\n");
		rz_th_queue_free(hits);
		rz_th_queue_free(intervals);
		return NULL;
	}

	ctx.col = col;
	ctx.opt = opt;
	ctx.buffer = buffer;
	ctx.buffer_lock = rz_th_lock_new(false);
	ctx.loop = rz_atomic_bool_new(true);
	ctx.hits = hits;
	ctx.finished_intervals = intervals;

	if (opt->cancel_cb) {
		// create cancel thread
		cancel_th = rz_th_new(search_cancel_th, &ctx);
		if (!cancel_th) {
			RZ_LOG_ERROR("search: cannot allocate cancel thread.\n");
			rz_th_queue_free(hits);
			rz_th_queue_free(intervals);
			rz_atomic_bool_free(ctx.loop);
			rz_list_free(windows);
			return NULL;
		}
	}

	if (!rz_th_iterate_list(windows, search_iterator_io_map_cb, opt->max_threads, &ctx)) {
		RZ_LOG_ERROR("search: cannot iterate over list.\n");
	} else {
		results = rz_th_queue_pop_all(hits);
	}

	if (cancel_th) {
		// stop & free cancel thread.
		rz_atomic_bool_set(ctx.loop, false);
		rz_th_wait(cancel_th);
		rz_th_free(cancel_th);
		rz_atomic_bool_free(ctx.loop);
	}

	rz_th_lock_free(ctx.io_lock);
	rz_list_free(windows);
	rz_th_queue_free(hits);
	rz_th_queue_free(intervals);
	rz_atomic_bool_free(ctx.loop);
	rz_th_lock_free(ctx.buffer_lock);

	rz_list_sort(results, (RzListComparator)rz_search_hit_cmp, NULL);
	rz_list_sorted_uniq(results, (RzListComparator)rz_search_hit_cmp, NULL);
	return results;
}

RZ_IPI int rz_search_hit_cmp(RZ_NULLABLE RzSearchHit *a, RZ_NULLABLE RzSearchHit *b, void *user) {
	if (!a && !b) {
		return 0;
	} else if (!a) {
		return -1;
	} else if (!b) {
		return 1;
	}
	if (a->address < b->address) {
		return -1;
	} else if (a->address > b->address) {
		return 1;
	}

	if (a->size == b->size) {
		return 0;
	} else if (a->size < b->size) {
		return -1;
	}
	return 1;
}

/**
 * \brief      Allocate and initialize a new RzSearchHit
 *
 * \param[in]  hit_desc    The hit description linked to the hit (can be NULL)
 * \param[in]  address     The address where the hit happened
 * \param[in]  size        The size of the hit data (can be 0)
 * \param[in]  hit_detail  Contains additional information about the hit (can be NULL)
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_IPI RZ_OWN RzSearchHit *rz_search_hit_new(RZ_NULLABLE const char *hit_desc, ut64 address, size_t size, RZ_NULLABLE RZ_OWN RzSearchHitDetail *hit_detail) {
	RzSearchHit *hit = RZ_NEW0(RzSearchHit);
	if (!hit) {
		rz_search_hit_detail_free(hit_detail);
		return NULL;
	}
	hit->hit_desc = rz_str_dup(hit_desc);
	hit->detail = hit_detail;
	hit->address = address;
	hit->size = size;
	return hit;
}

/**
 * \brief      Frees a RzSearchHit structure
 *
 * \param      hit  The RzSearchHit pointer to free
 */
RZ_IPI void rz_search_hit_free(RZ_NULLABLE RzSearchHit *hit) {
	if (!hit) {
		return;
	}
	free(hit->hit_desc);
	rz_search_hit_detail_free(hit->detail);
	free(hit);
}

/**
 * \brief Get a flag name describing the hit. The flag name can be customized.
 *
 * \param hit    The RzSearchHit to build the flag name for.
 * \param hit_id The id number of the hit.
 * \param prefix An optional prefix for the flag. Defaults to "hit".
 *
 * Example:
 *
 * hit       = { address = 0x110, hit_desc = "bytes", size = 0x10 }
 * prefix    = "sb"
 *
 * Result    = sb.bytes.0

 * hit       = { address = 0x110, hit_desc = NULL, size = 0x10 }
 * prefix    = NULL
 *
 * Result    = hit.0
 *
 * \return A flag of \p hit, or NULL in case of failure.
 */
RZ_API RZ_OWN char *rz_search_hit_flag_name(RZ_NONNULL const RzSearchHit *hit, size_t hit_id, RZ_NULLABLE const char *prefix) {
	rz_return_val_if_fail(hit, NULL);
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		return NULL;
	}
	rz_strbuf_appendf(buf, "%s", prefix ? prefix : "hit");
	if (hit->hit_desc) {
		rz_strbuf_appendf(buf, ".%s", hit->hit_desc);
	}
	rz_strbuf_appendf(buf, ".%" PFMTSZd, hit_id);

	return rz_strbuf_drain(buf);
}

/**
 * \brief      Returns the detail as a null-terminated string
 *
 * \param[in]  hit   The RzSearchHit to use
 *
 * \return     On success a valid string, otherwise null.
 */
RZ_API RZ_OWN char *rz_search_hit_detail_as_string(RZ_NONNULL const RzSearchHit *hit) {
	rz_return_val_if_fail(hit, NULL);
	if (!hit->detail) {
		return NULL;
	}
	RzSearchHitDetail *detail = hit->detail;
	switch (detail->type) {
	case RZ_SEARCH_HIT_DETAIL_STRING:
		return rz_str_ndup(detail->string, detail->length);
	case RZ_SEARCH_HIT_DETAIL_UNSIGNED:
		if (detail->u64 < 128) {
			return rz_str_newf("%" PFMT64u, detail->u64);
		}
		return rz_str_newf("%" PFMT64x, detail->u64);
	case RZ_SEARCH_HIT_DETAIL_SIGNED:
		return rz_str_newf("%" PFMT64d, detail->s64);
	case RZ_SEARCH_HIT_DETAIL_DOUBLE:
		return rz_str_newf("%.4f", detail->f64);
	case RZ_SEARCH_HIT_DETAIL_BYTES:
		return rz_hex_bin2strdup(detail->bytes, detail->length);
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

/**
 * \brief      Adds the detail to a gives PJ (json) structure.
 *
 * \param[in]  hit   The RzSearchHit to use
 * \param      json  The json where to add the detail
 */
RZ_API void rz_search_hit_detail_as_json(RZ_NONNULL const RzSearchHit *hit, RZ_NONNULL PJ *json) {
	rz_return_if_fail(hit && json);
	if (!hit->detail) {
		return;
	}

	RzSearchHitDetail *detail = hit->detail;
	switch (detail->type) {
	case RZ_SEARCH_HIT_DETAIL_STRING:
		pj_ks(json, "detail", detail->string);
		return;
	case RZ_SEARCH_HIT_DETAIL_UNSIGNED:
		pj_kn(json, "detail", detail->u64);
		return;
	case RZ_SEARCH_HIT_DETAIL_SIGNED:
		pj_kN(json, "detail", detail->s64);
		return;
	case RZ_SEARCH_HIT_DETAIL_DOUBLE:
		pj_kd(json, "detail", detail->f64);
		return;
	case RZ_SEARCH_HIT_DETAIL_BYTES: {
		char *hex = rz_hex_bin2strdup(detail->bytes, detail->length);
		pj_ks(json, "detail", hex);
		free(hex);
		return;
	}
	default:
		rz_warn_if_reached();
		return;
	}
}

RZ_IPI RZ_OWN RzSearchHitDetail *rz_search_hit_detail_string_new(const char *string) {
	if (RZ_STR_ISEMPTY(string)) {
		return NULL;
	}

	size_t length = strlen(string);
	if (length < 1) {
		return NULL;
	}

	RzSearchHitDetail *detail = RZ_NEW0(RzSearchHitDetail);
	if (!detail) {
		return NULL;
	}

	detail->string = rz_str_ndup(string, length);
	if (!detail->string) {
		free(detail);
		return NULL;
	}
	detail->type = RZ_SEARCH_HIT_DETAIL_STRING;
	detail->length = length;
	return detail;
}

RZ_IPI RZ_OWN RzSearchHitDetail *rz_search_hit_detail_unsigned_new(const ut64 u64) {
	RzSearchHitDetail *detail = RZ_NEW0(RzSearchHitDetail);
	if (!detail) {
		return NULL;
	}
	detail->type = RZ_SEARCH_HIT_DETAIL_UNSIGNED;
	detail->u64 = u64;
	return detail;
}

RZ_IPI RZ_OWN RzSearchHitDetail *rz_search_hit_detail_signed_new(const st64 s64) {
	RzSearchHitDetail *detail = RZ_NEW0(RzSearchHitDetail);
	if (!detail) {
		return NULL;
	}
	detail->type = RZ_SEARCH_HIT_DETAIL_SIGNED;
	detail->s64 = s64;
	return detail;
}

RZ_IPI RZ_OWN RzSearchHitDetail *rz_search_hit_detail_double_new(const double f64) {
	RzSearchHitDetail *detail = RZ_NEW0(RzSearchHitDetail);
	if (!detail) {
		return NULL;
	}

	detail->type = RZ_SEARCH_HIT_DETAIL_DOUBLE;
	detail->f64 = f64;
	return detail;
}

RZ_IPI RZ_OWN RzSearchHitDetail *rz_search_hit_detail_bytes_new(const ut8 *bytes, size_t length) {
	if (length < 1) {
		return NULL;
	}

	RzSearchHitDetail *detail = RZ_NEW0(RzSearchHitDetail);
	if (!detail) {
		return NULL;
	}

	detail->bytes = malloc(length);
	if (!detail->bytes) {
		free(detail);
		return NULL;
	}
	memcpy(detail->bytes, bytes, length);

	detail->type = RZ_SEARCH_HIT_DETAIL_BYTES;
	detail->length = length;
	return detail;
}

RZ_API bool rz_search_hit_detail_get_type(RZ_NULLABLE RzSearchHitDetail *detail, RZ_NONNULL RZ_OUT RzSearchHitDetailType *type) {
	rz_return_val_if_fail(type, false);
	if (!detail) {
		return false;
	}
	*type = detail->type;
	return true;
}

RZ_API bool rz_search_hit_detail_get_string(RZ_NULLABLE RzSearchHitDetail *detail, RZ_NONNULL RZ_OUT char **string) {
	rz_return_val_if_fail(string, false);
	if (!detail || detail->type != RZ_SEARCH_HIT_DETAIL_STRING) {
		return false;
	}
	char *copy = rz_str_ndup(detail->string, detail->length);
	if (!copy) {
		RZ_LOG_ERROR("search: failed to duplicate string.\n");
		return false;
	}
	*string = copy;
	return true;
}

RZ_API bool rz_search_hit_detail_get_unsigned(RZ_NULLABLE RzSearchHitDetail *detail, RZ_NONNULL RZ_OUT ut64 *u64) {
	rz_return_val_if_fail(u64, false);
	if (!detail || detail->type != RZ_SEARCH_HIT_DETAIL_UNSIGNED) {
		return false;
	}
	*u64 = detail->u64;
	return true;
}

RZ_API bool rz_search_hit_detail_get_signed(RZ_NULLABLE RzSearchHitDetail *detail, RZ_NONNULL RZ_OUT st64 *s64) {
	rz_return_val_if_fail(s64, false);
	if (!detail || detail->type != RZ_SEARCH_HIT_DETAIL_SIGNED) {
		return false;
	}
	*s64 = detail->s64;
	return true;
}

RZ_API bool rz_search_hit_detail_get_double(RZ_NULLABLE RzSearchHitDetail *detail, RZ_NONNULL RZ_OUT double *f64) {
	rz_return_val_if_fail(f64, false);
	if (!detail || detail->type != RZ_SEARCH_HIT_DETAIL_DOUBLE) {
		return false;
	}
	*f64 = detail->f64;
	return true;
}

RZ_API bool rz_search_hit_detail_get_bytes(RZ_NULLABLE RzSearchHitDetail *detail, RZ_NONNULL RZ_OUT ut8 **bytes, RZ_NONNULL RZ_OUT size_t *length) {
	rz_return_val_if_fail(bytes && length, false);
	if (!detail || detail->type != RZ_SEARCH_HIT_DETAIL_BYTES) {
		return false;
	}
	ut8 *b = malloc(detail->length);
	if (!b) {
		RZ_LOG_ERROR("search: failed to allocate byte buffer for copy.\n");
		return false;
	}
	memcpy(b, detail->bytes, detail->length);

	*bytes = b;
	*length = detail->length;
	return true;
}

RZ_IPI void rz_search_hit_detail_free(RZ_NULLABLE RzSearchHitDetail *detail) {
	if (!detail) {
		return;
	}

	switch (detail->type) {
	case RZ_SEARCH_HIT_DETAIL_STRING:
		free(detail->string);
		break;
	case RZ_SEARCH_HIT_DETAIL_BYTES:
		free(detail->bytes);
		break;
	default:
		break;
	}
	free(detail);
}

RZ_IPI RZ_OWN RzSearchInterval *rz_search_interval_new(RzInterval interval, size_t n_hits) {
	RzSearchInterval *search_interval = RZ_NEW0(RzSearchInterval);
	if (!search_interval) {
		return NULL;
	}
	search_interval->interval = interval;
	search_interval->n_hits = n_hits;
	return search_interval;
}

RZ_IPI void rz_search_interval_free(RZ_NULLABLE RzSearchInterval *search_interval) {
	if (!search_interval) {
		return;
	}
	free(search_interval);
}
