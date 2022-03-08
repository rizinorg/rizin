// SPDX-FileCopyrightText: 2008-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_list.h>
#include <ctype.h>

// Experimental search engine (fails, because stops at first hit of every block read
#define USE_BMH 0

RZ_LIB_VERSION(rz_search);

typedef struct {
	ut64 end;
	int len;
	ut8 data[];
} RzSearchLeftover;

RZ_API RzSearchParams *rz_search_params_new(RzSearchMode mode) {
	RzSearchParams *params = RZ_NEW0(RzSearchParams);
	if (!params) {
		return NULL;
	}
	if (!rz_search_params_set_mode(params, mode)) {
		free(params);
		eprintf("Cannot init search params for mode %d\n", mode);
		return false;
	}

	params->pattern_size = 0;
	params->aes_search = false;
	params->privkey_search = false;
	params->inverse = false;
	params->backwards = false;

	params->search_align = 0;
	params->search_distance = 0;
	params->search_contiguous = false;
	params->search_overlap = false;
	params->search_maxlength = 255;
	params->search_minlength = 0;
	params->search_maxhits = 0;

	params->itv.addr = params->search_from;
	params->itv.size = params->search_from - params->search_to;
	params->kws = rz_list_newf((RzListFree)rz_search_keyword_free);
	if (!params->kws) {
		goto bad;
	}
	params->n_kws = 0;

	return params;

bad:
	rz_search_params_free(params);
	return NULL;
}

RZ_API void rz_search_params_free(RzSearchParams *params) {
	if (!params) {
		return;
	}
	rz_list_free(params->boundaries);
	rz_list_free(params->kws);
}

RZ_API RzSearch *rz_search_new(RZ_NONNULL RzSearchParams *params) {
	RzSearch *s = RZ_NEW0(RzSearch);
	if (!s) {
		return NULL;
	}
	s->data = NULL;
	s->user = NULL;
	s->callback = NULL;
	s->hits = rz_list_newf(free);
	s->params = params;
	return s;
}

RZ_API RzSearch *rz_search_free(RzSearch *s) {
	if (!s) {
		return NULL;
	}
	rz_list_free(s->hits);
	rz_search_params_free(s->params);
	// rz_io_free(s->iob.io); this is supposed to be a weak reference
	free(s->data);
	free(s);
	return NULL;
}

RZ_API int rz_search_set_string_limits(RzSearch *s, ut32 min, ut32 max) {
	if (max < min) {
		return false;
	}
	s->params->search_minlength = min;
	s->params->search_maxlength = max;
	return true;
}

RZ_API int rz_search_magic_update(RzSearch *s, ut64 from, const ut8 *buf, int len) {
	eprintf("TODO: import librz/core/cmd_search.c /m implementation into rsearch\n");
	return false;
}

RZ_API int rz_search_params_set_mode(RzSearchParams *params, RzSearchMode mode) {
	switch (mode) {
	case RZ_SEARCH_KEYWORD: params->update = rz_search_mybinparse_update; break;
	case RZ_SEARCH_REGEXP: params->update = rz_search_regexp_update; break;
	case RZ_SEARCH_AES: params->update = rz_search_aes_update; break;
	case RZ_SEARCH_PRIV_KEY: params->update = rz_search_privkey_update; break;
	case RZ_SEARCH_STRING: params->update = rz_search_strings_update; break;
	case RZ_SEARCH_DELTAKEY: params->update = rz_search_deltakey_update; break;
	case RZ_SEARCH_MAGIC: params->update = rz_search_magic_update; break;
	default: params->update = NULL;
	}
	if (params->update || mode == RZ_SEARCH_PATTERN) {
		params->mode = mode;
		return true;
	}
	return false;
}

RZ_API int rz_search_begin(RzSearch *s) {
	RzListIter *iter;
	RzSearchKeyword *kw;
	rz_list_foreach (s->params->kws, iter, kw) {
		kw->count = 0;
		kw->last = 0;
	}
	return true;
}

// Returns 2 if search.maxhits is reached, 0 on error, otherwise 1
RZ_API int rz_search_hit_new(RzSearch *s, RzSearchKeyword *kw, ut64 addr) {
	if (s->params->inverse && (addr % s->params->inverse)) {
		eprintf("0x%08" PFMT64x " unaligned\n", addr);
		return 1;
	}
	if (!s->params->search_contiguous) {
		if (kw->last && addr == kw->last) {
			kw->count--;
			kw->last = s->params->backwards ? addr : addr + kw->keyword_length;
			eprintf("0x%08" PFMT64x " Sequential hit ignored.\n", addr);
			return 1;
		}
	}
	// kw->last is used by string search, the right endpoint of last match (forward search), to honor search.overlap
	kw->last = s->params->backwards ? addr : addr + kw->keyword_length;

	if (s->callback) {
		int ret = s->callback(kw, s->user, addr);
		kw->count++;
		s->nhits++;
		// If callback returns 0 or larger than 1, forwards it; otherwise returns 2 if search.maxhits is reached
		return !ret || ret > 1 ? ret : s->params->search_maxhits && s->nhits >= s->params->search_maxhits ? 2
														  : 1;
	}
	kw->count++;
	s->nhits++;
	RzSearchHit *hit = RZ_NEW0(RzSearchHit);
	if (hit) {
		hit->kw = kw;
		hit->addr = addr;
		rz_list_append(s->hits, hit);
	}
	return s->params->search_maxhits && s->nhits >= s->params->search_maxhits ? 2 : 1;
}

// TODO support search across block boundaries
// Supported search variants: backward, overlap
RZ_API int rz_search_deltakey_update(RzSearch *s, ut64 from, const ut8 *buf, int len) {
	RzListIter *iter;
	int longest = 0, i, j;
	RzSearchKeyword *kw;
	RzSearchLeftover *left;
	const int old_nhits = s->nhits;
	rz_list_foreach (s->params->kws, iter, kw) {
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
		if (s->params->backwards) {
			rz_list_foreach (s->params->kws, iter, kw) {
				ut8 *i = kw->bin_keyword, *j = kw->bin_keyword + kw->keyword_length;
				for (; i < j; i++) {
					*i = -*i;
				}
			}
		}
	}
	if (s->params->backwards) {
		// XXX Change function signature from const ut8 * to ut8 *
		ut8 *i = (ut8 *)buf, *j = i + len;
		while (i < j) {
			ut8 t = *i;
			*i++ = *--j;
			*j = t;
		}
	}

	ut64 len1 = left->len + RZ_MIN(longest - 1, len);
	memcpy(left->data + left->len, buf, len1 - left->len);
	rz_list_foreach (s->params->kws, iter, kw) {
		ut8 *a = kw->bin_keyword;
		i = s->params->search_overlap || !kw->count ? 0 : s->params->backwards ? kw->last - from < left->len ? from + left->len - kw->last : 0
			: from - kw->last < left->len                                  ? kw->last + left->len - from
										       : 0;
		for (; i + kw->keyword_length < len1 && i < left->len; i++) {
			if ((ut8)(left->data[i + 1] - left->data[i]) == a[0]) {
				j = 1;
				while (j < kw->keyword_length && (ut8)(left->data[i + j + 1] - left->data[i + j]) == a[j]) {
					j++;
				}
				if (j == kw->keyword_length) {
					int t = rz_search_hit_new(s, kw, s->params->backwards ? from - kw->keyword_length - 1 - i + left->len : from + i - left->len);
					kw->last += s->params->backwards ? 0 : 1;
					if (!t) {
						return -1;
					}
					if (t > 1) {
						return s->nhits - old_nhits;
					}
					if (!s->params->search_overlap) {
						i += kw->keyword_length;
					}
				}
			}
		}
		i = s->params->search_overlap || !kw->count ? 0 : s->params->backwards ? from > kw->last ? from - kw->last : 0
			: from < kw->last                                              ? kw->last - from
										       : 0;
		for (; i + kw->keyword_length < len; i++) {
			if ((ut8)(buf[i + 1] - buf[i]) == a[0]) {
				j = 1;
				while (j < kw->keyword_length && (ut8)(buf[i + j + 1] - buf[i + j]) == a[j]) {
					j++;
				}
				if (j == kw->keyword_length) {
					int t = rz_search_hit_new(s, kw, s->params->backwards ? from - kw->keyword_length - 1 - i : from + i);
					kw->last += s->params->backwards ? 0 : 1;
					if (!t) {
						return -1;
					}
					if (t > 1) {
						return s->nhits - old_nhits;
					}
					if (!s->params->search_overlap) {
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
	left->end = s->params->backwards ? from - len : from + len;

	return s->nhits - old_nhits;
}

#if 0
// Boyer-Moore-Horspool pattern matching
// Supported search variants: icase, overlap
static int rz_search_horspool(RzSearch *s, RzSearchKeyword *kw, ut64 from, const ut8 *buf, int len) {
	ut64 bad_char_shift[UT8_MAX + 1];
	int i, j, m = kw->keyword_length - 1, count = 0;
	ut8 ch;

	for (i = 0; i < RZ_ARRAY_SIZE (bad_char_shift); i++) {
		bad_char_shift[i] = kw->keyword_length;
	}
	for (i = 0; i < m; i++) {
		ch = kw->bin_keyword[i];
		bad_char_shift[kw->icase ? tolower (ch) : ch] = m - i;
	}

	for (i = 0; i + m < len; ) {
	next:
		for (j = m; ; j--) {
			ut8 a = buf[i + j], b = kw->bin_keyword[j];
			if (kw->icase) {
				a = tolower (a);
				b = tolower (b);
			}
			if (a != b) break;
			if (i == 0) {
				if (!rz_search_hit_new (s, kw, from + i)) {
					return -1;
				}
				kw->count++;
				count++;
				if (!s->params->overlap) {
					i += kw->keyword_length;
					goto next;
				}
			}
		}
		ch = buf[i + m];
		i += bad_char_shift[kw->icase ? tolower (ch) : ch];
	}

	return false;
}
#endif

static bool brute_force_match(RzSearch *s, RzSearchKeyword *kw, const ut8 *buf, int i) {
	int j = 0;
	if (s->params->search_distance) { // slow path, more work in the loop
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
		return dist <= s->params->search_distance;
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

	rz_list_foreach (s->params->kws, iter, kw) {
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
	if (s->params->backwards) {
		// XXX Change function signature from const ut8 * to ut8 *
		ut8 *i = (ut8 *)buf, *j = i + len;
		while (i < j) {
			ut8 t = *i;
			*i++ = *--j;
			*j = t;
		}
	}

	ut64 len1 = left->len + RZ_MIN(longest - 1, len);
	memcpy(left->data + left->len, buf, len1 - left->len);
	rz_list_foreach (s->params->kws, iter, kw) {
		i = s->params->search_overlap || !kw->count ? 0 : s->params->backwards ? kw->last - from < left->len ? from + left->len - kw->last : 0
			: from - kw->last < left->len                                  ? kw->last + left->len - from
										       : 0;
		for (; i + kw->keyword_length <= len1 && i < left->len; i++) {
			if (brute_force_match(s, kw, left->data, i) != s->params->inverse) {
				int t = rz_search_hit_new(s, kw, s->params->backwards ? from - kw->keyword_length - i + left->len : from + i - left->len);
				if (!t) {
					return -1;
				}
				if (t > 1) {
					return s->nhits - old_nhits;
				}
				if (!s->params->search_overlap) {
					i += kw->keyword_length - 1;
				}
			}
		}
		i = s->params->search_overlap || !kw->count ? 0 : s->params->backwards ? from > kw->last ? from - kw->last : 0
			: from < kw->last                                              ? kw->last - from
										       : 0;
		for (; i + kw->keyword_length <= len; i++) {
			if (brute_force_match(s, kw, buf, i) != s->params->inverse) {
				int t = rz_search_hit_new(s, kw, s->params->backwards ? from - kw->keyword_length - i : from + i);
				if (!t) {
					return -1;
				}
				if (t > 1) {
					return s->nhits - old_nhits;
				}
				if (!s->params->search_overlap) {
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
	left->end = s->params->backwards ? from - len : from + len;

	return s->nhits - old_nhits;
}

RZ_API void rz_search_params_set_distance(RzSearchParams *params, int dist) {
	if (dist >= RZ_SEARCH_DISTANCE_MAX) {
		eprintf("Invalid distance\n");
		params->search_distance = 0;
	} else {
		params->search_distance = (dist > 0) ? dist : 0;
	}
}

// deprecate? or standarize with ->params->inverse ??
RZ_API void rz_search_pattern_size(RzSearch *s, int size) {
	s->params->pattern_size = size;
}

RZ_API void rz_search_set_callback(RzSearch *s, RzSearchCallback(callback), void *user) {
	s->callback = callback;
	s->user = user;
}

// backward search: from points to the right endpoint
// forward search: from points to the left endpoint
RZ_API int rz_search_update(RzSearch *s, ut64 from, const ut8 *buf, long len) {
	int ret = -1;
	if (s->params->update) {
		if (s->params->search_maxhits && s->nhits >= s->params->search_maxhits) {
			return 0;
		}
		ret = s->params->update(s, from, buf, len);
	} else {
		eprintf("rz_search_update: No search method defined\n");
	}
	return ret;
}

RZ_API int rz_search_update_i(RzSearch *s, ut64 from, const ut8 *buf, long len) {
	return rz_search_update(s, from, buf, len);
}

static int listcb(RzSearchKeyword *k, void *user, ut64 addr) {
	RzSearchHit *hit = RZ_NEW0(RzSearchHit);
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
	if (!s->callback) {
		rz_search_set_callback(s, listcb, ret);
	} else {
		rz_search_set_callback(s, s->callback, ret);
	}
	rz_search_update(s, addr, buf, len);
	return ret;
}

/* --- keywords --- */
RZ_API int rz_search_params_kw_add(RzSearchParams *params, RzSearchKeyword *kw) {
	if (!kw || !kw->keyword_length) {
		return false;
	}
	kw->kwidx = params->n_kws++;
	rz_list_append(params->kws, kw);
	return true;
}

// Reverse bin_keyword & bin_binmask for backward search
RZ_API void rz_search_string_prepare_backward(RzSearchParams *params) {
	RzListIter *iter;
	RzSearchKeyword *kw;
	// Precondition: !kw->binmask_length || kw->keyword_length % kw->binmask_length == 0
	rz_list_foreach (params->kws, iter, kw) {
		ut8 *i = kw->bin_keyword, *j = kw->bin_keyword + kw->keyword_length;
		while (i < j) {
			ut8 t = *i;
			*i++ = *--j;
			*j = t;
		}
		i = kw->bin_binmask;
		j = kw->bin_binmask + kw->binmask_length;
		while (i < j) {
			ut8 t = *i;
			*i++ = *--j;
			*j = t;
		}
	}
}

RZ_API void rz_search_reset(RzSearch *s, int mode) {
	s->nhits = 0;
	if (!rz_search_params_set_mode(s->params, mode)) {
		eprintf("Cannot init search for mode %d\n", mode);
	}
}

RZ_API void rz_search_kw_reset(RzSearch *s) {
	rz_list_purge(s->params->kws);
	rz_list_purge(s->hits);
	RZ_FREE(s->data);
}
