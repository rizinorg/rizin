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
} SearchLeftover;

/**
 * \param   s  The RzSearch structure to initialize
 *
 * \return  True on correct initialization
 */
RZ_API bool rz_search_init(RZ_NONNULL RzSearch *s) {
	rz_return_val_if_fail(s, false);

	s->mode = RZ_SEARCH_MODE_LAST; // ensures it is always invalid
	s->string_max = RZ_SEARCH_DEFAULT_STRING_MAX;
	s->string_min = RZ_SEARCH_DEFAULT_STRING_MIN;
	s->hits = rz_list_newf(free);
	s->kws = rz_list_newf((RzListFree)rz_search_keyword_free);
	return s->kws && s->hits;
}

/**
 * \param   s  The RzSearch structure to finalize
 */
RZ_API void rz_search_fini(RZ_NONNULL RzSearch *s) {
	rz_return_if_fail(s);

	RZ_FREE_CUSTOM(s->hits, rz_list_free);
	RZ_FREE_CUSTOM(s->kws, rz_list_free);
	// iob.io is supposed to be a weak reference
	// RZ_FREE_CUSTOM(s->iob.io, rz_io_free);
	RZ_FREE(s->data);
	RZ_FREE(s->prefix);
}

/**
 * \brief      Allocates and initialize RzSearch
 *
 * \param      mode  The RzSearch mode
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN RzSearch *rz_search_new(rz_search_mode mode) {
	RzSearch *s = RZ_NEW0(RzSearch);
	if (!s ||
		!rz_search_init(s) ||
		!rz_search_set_mode(s, mode)) {
		rz_search_free(s);
		return NULL;
	}
	return s;
}

/**
 * \brief      Deallocates a RzSearch struct.
 *
 * \param      s     The struct to deallocate
 */
RZ_API void rz_search_free(RZ_NULLABLE RzSearch *s) {
	if (!s) {
		return;
	}
	rz_list_free(s->hits);
	rz_list_free(s->kws);
	// rz_io_free(s->iob.io); this is supposed to be a weak reference
	free(s->data);
	free(s);
}

RZ_API int rz_search_strings_update(RzSearch *s, ut64 from, const ut8 *buf, int len) {
	rz_return_val_if_fail(s && buf && len, -1);

	RzUtilStrScanOptions scan_opt = {
		.buf_size = len,
		.max_uni_blocks = s->string_max,
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
			rz_search_hit_new(s, kw, dstr->addr);
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
RZ_API int rz_search_hit_new(RzSearch *s, RzSearchKeyword *kw, ut64 addr) {
	if (s->align && (addr % s->align)) {
		eprintf("0x%08" PFMT64x " unaligned\n", addr);
		return 1;
	}
	if (!s->contiguous) {
		if (kw->last && addr == kw->last) {
			kw->count--;
			kw->last = s->backwards ? addr : addr + kw->keyword_length;
			eprintf("0x%08" PFMT64x " Sequential hit ignored.\n", addr);
			return 1;
		}
	}
	// kw->last is used by string search, the right endpoint of last match (forward search), to honor search.overlap
	kw->last = s->backwards ? addr : addr + kw->keyword_length;

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
	RzSearchHit *hit = RZ_NEW0(RzSearchHit);
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
	SearchLeftover *left;
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
		left = malloc(sizeof(SearchLeftover) + (size_t)2 * (longest - 1));
		if (!left) {
			return -1;
		}
		s->data = left;
		left->len = 0;
		if (s->backwards) {
			rz_list_foreach (s->kws, iter, kw) {
				ut8 *i = kw->bin_keyword, *j = kw->bin_keyword + kw->keyword_length;
				for (; i < j; i++) {
					*i = -*i;
				}
			}
		}
	}
	if (s->backwards) {
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
	rz_list_foreach (s->kws, iter, kw) {
		ut8 *a = kw->bin_keyword;
		i = s->overlap || !kw->count ? 0 : s->backwards ? kw->last - from < left->len ? from + left->len - kw->last : 0
			: from - kw->last < left->len           ? kw->last + left->len - from
								: 0;
		for (; i + kw->keyword_length < len1 && i < left->len; i++) {
			if ((ut8)(left->data[i + 1] - left->data[i]) == a[0]) {
				j = 1;
				while (j < kw->keyword_length && (ut8)(left->data[i + j + 1] - left->data[i + j]) == a[j]) {
					j++;
				}
				if (j == kw->keyword_length) {
					int t = rz_search_hit_new(s, kw, s->backwards ? from - kw->keyword_length - 1 - i + left->len : from + i - left->len);
					kw->last += s->backwards ? 0 : 1;
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
		i = s->overlap || !kw->count ? 0 : s->backwards ? from > kw->last ? from - kw->last : 0
			: from < kw->last                       ? kw->last - from
								: 0;
		for (; i + kw->keyword_length < len; i++) {
			if ((ut8)(buf[i + 1] - buf[i]) == a[0]) {
				j = 1;
				while (j < kw->keyword_length && (ut8)(buf[i + j + 1] - buf[i + j]) == a[j]) {
					j++;
				}
				if (j == kw->keyword_length) {
					int t = rz_search_hit_new(s, kw, s->backwards ? from - kw->keyword_length - 1 - i : from + i);
					kw->last += s->backwards ? 0 : 1;
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
	left->end = s->backwards ? from - len : from + len;

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
	SearchLeftover *left;
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
		left = malloc(sizeof(SearchLeftover) + (size_t)2 * (longest - 1));
		if (!left) {
			return -1;
		}
		s->data = left;
		left->len = 0;
	}
	if (s->backwards) {
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
	rz_list_foreach (s->kws, iter, kw) {
		i = s->overlap || !kw->count ? 0 : s->backwards ? kw->last - from < left->len ? from + left->len - kw->last : 0
			: from - kw->last < left->len           ? kw->last + left->len - from
								: 0;
		for (; i + kw->keyword_length <= len1 && i < left->len; i++) {
			if (brute_force_match(s, kw, left->data, i) != s->inverse) {
				int t = rz_search_hit_new(s, kw, s->backwards ? from - kw->keyword_length - i + left->len : from + i - left->len);
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
		i = s->overlap || !kw->count ? 0 : s->backwards ? from > kw->last ? from - kw->last : 0
			: from < kw->last                       ? kw->last - from
								: 0;
		for (; i + kw->keyword_length <= len; i++) {
			if (brute_force_match(s, kw, buf, i) != s->inverse) {
				int t = rz_search_hit_new(s, kw, s->backwards ? from - kw->keyword_length - i : from + i);
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
	left->end = s->backwards ? from - len : from + len;

	return s->nhits - old_nhits;
}

/**
 * \brief      Sets the search mode.
 *
 * \param      s    The RzSearch structure to use
 * \param      mode The search mode to set
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_mode(RZ_NONNULL RzSearch *s, rz_search_mode mode) {
	rz_return_val_if_fail(s, false);

	switch (mode) {
	case RZ_SEARCH_MODE_PATTERN:
		s->update = NULL;
		break;
	case RZ_SEARCH_MODE_KEYWORD:
		s->update = rz_search_mybinparse_update;
		break;
	case RZ_SEARCH_MODE_REGEXP:
		s->update = rz_search_regexp_update;
		break;
	case RZ_SEARCH_MODE_STRING:
		s->update = rz_search_strings_update;
		break;
	case RZ_SEARCH_MODE_XREFS:
		s->update = NULL;
		break;
	case RZ_SEARCH_MODE_AES:
		s->update = rz_search_aes_update;
		break;
	case RZ_SEARCH_MODE_PRIV_KEY:
		s->update = rz_search_privkey_update;
		break;
	case RZ_SEARCH_MODE_DELTAKEY:
		s->update = rz_search_deltakey_update;
		break;
	case RZ_SEARCH_MODE_MAGIC:
		s->update = NULL;
		break;
	case RZ_SEARCH_MODE_ESIL:
		s->update = NULL;
		break;
	default:
		RZ_LOG_ERROR("search: cannot set mode: unknown %d\n", mode);
		return false;
	}

	s->mode = mode;
	return true;
}

/**
 * \brief      Sets the max pattern size.
 *
 * \param      s            The RzSearch structure to use
 * \param      pattern_size The pattern size variable to set
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_pattern_size(RZ_NONNULL RzSearch *s, ut32 pattern_size) {
	rz_return_val_if_fail(s, false);
	s->pattern_size = pattern_size;
	return true;
}

/**
 * \brief      Sets the string limits.
 *
 * \param      s   The RzSearch structure to use
 * \param      min The min variable to set
 * \param      max The max variable to set
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_string_limits(RZ_NONNULL RzSearch *s, ut32 min, ut32 max) {
	rz_return_val_if_fail(s, false);
	if (max < min) {
		RZ_LOG_ERROR("search: cannot set string limits: max < min\n");
		return false;
	}
	s->string_min = min;
	s->string_max = max;
	return true;
}

/**
 * \brief      Sets the max hits variable.
 *
 * \param      s       The RzSearch structure to use
 * \param      maxhits The max hits variable to set
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_maxhits(RZ_NONNULL RzSearch *s, ut64 maxhits) {
	rz_return_val_if_fail(s, false);
	s->maxhits = maxhits;
	return true;
}

/**
 * \brief      Sets the max distance.
 *
 * \param      s        The RzSearch structure to use
 * \param      distance The distance variable to set
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_distance(RZ_NONNULL RzSearch *s, ut32 distance) {
	rz_return_val_if_fail(s, false);

	if (distance >= RZ_SEARCH_DISTANCE_MAX) {
		RZ_LOG_ERROR("search: cannot set distance: exeeds max (%d)\n", RZ_SEARCH_DISTANCE_MAX);
		return false;
	}
	s->distance = distance;
	return true;
}

/**
 * \brief      Sets the inverse variable.
 *
 * \param      s       The RzSearch structure to use
 * \param      inverse The inverse variable to set
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_inverse(RZ_NONNULL RzSearch *s, bool inverse) {
	rz_return_val_if_fail(s, false);
	s->inverse = inverse;
	return true;
}

/**
 * \brief      Sets the overlap variable.
 *
 * \param      s       The RzSearch structure to use
 * \param      overlap The overlap variable to set
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_overlap(RZ_NONNULL RzSearch *s, bool overlap) {
	rz_return_val_if_fail(s, false);
	s->overlap = overlap;
	return true;
}

/**
 * \brief      Sets the contiguous variable.
 *
 * \param      s          The RzSearch structure to use
 * \param      contiguous The contiguous variable to set
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_contiguous(RZ_NONNULL RzSearch *s, bool contiguous) {
	rz_return_val_if_fail(s, false);
	s->contiguous = contiguous;
	return true;
}

/**
 * \brief      Sets the align variable.
 *
 * \param      s     The RzSearch structure to use
 * \param      align The align variable to set
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_align(RZ_NONNULL RzSearch *s, ut64 align) {
	rz_return_val_if_fail(s, false);
	s->align = align;
	return true;
}

/**
 * \brief      Sets the backwards variable.
 *
 * \param      s         The RzSearch structure to use
 * \param      backwards The backwards variable to set
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_backwards(RZ_NONNULL RzSearch *s, bool backwards) {
	rz_return_val_if_fail(s, false);
	s->backwards = backwards;
	return true;
}

/**
 * \brief      Sets the flags variable.
 *
 * \param      s     The RzSearch structure to use
 * \param      flags The flags variable to set
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_flags(RZ_NONNULL RzSearch *s, bool flags) {
	rz_return_val_if_fail(s, false);
	s->flags = flags;
	return true;
}

/**
 * \brief      Sets the show variable.
 *
 * \param      s    The RzSearch structure to use
 * \param      show The show variable to set
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_show(RZ_NONNULL RzSearch *s, bool show) {
	rz_return_val_if_fail(s, false);
	s->show = show;
	return true;
}

/**
 * \brief      Sets the from address.
 *
 * \param      s         The RzSearch structure to use
 * \param      from_addr The from address to set (must be > to address)
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_from_addr(RZ_NONNULL RzSearch *s, ut64 from_addr) {
	rz_return_val_if_fail(s, false);

	if (from_addr > s->to_addr) {
		RZ_LOG_ERROR("search: cannot set from address; 'search.from' is greater than 'search.to'.\n");
		return false;
	}
	s->from_addr = from_addr;
	return true;
}

/**
 * \brief      Sets the to address.
 *
 * \param      s       The RzSearch structure to use
 * \param      to_addr The to address to set (must be < from address)
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_to_addr(RZ_NONNULL RzSearch *s, ut64 to_addr) {
	rz_return_val_if_fail(s, false);

	if (s->from_addr > to_addr) {
		RZ_LOG_ERROR("search: cannot set to address; 'search.to' is less than 'search.from'.\n");
		return false;
	}
	s->to_addr = to_addr;
	return true;
}

/**
 * \brief      Sets the prefix keyword of the flag created on hit.
 *
 * \param      s      The RzSearch structure to use
 * \param      prefix The prefix to use (when NULL, prefix is set to "hit")
 *
 * \return     True when the string is correctly allocated.
 */
RZ_API bool rz_search_set_prefix(RZ_NONNULL RzSearch *s, RZ_NULLABLE const char *prefix) {
	rz_return_val_if_fail(s, false);
	free(s->prefix);
	s->prefix = rz_str_dup(prefix ? prefix : "hit");
	return s->prefix != NULL;
}

/**
 * \brief      Sets the command to execute on hit.
 *
 * \param      s       The RzSearch structure to use
 * \param      command The command to use
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_command(RZ_NONNULL RzSearch *s, RZ_NULLABLE const char *command) {
	rz_return_val_if_fail(s, false);
	free(s->command);
	s->command = rz_str_dup(command);
	return true;
}

/**
 * \brief      Sets the prefix keyword of the flag created on hit.
 *
 * \param      s        The RzSearch structure to use
 * \param      callback The callback pointer to set
 * \param      user     The user pointer to set
 *
 * \return     True on success
 */
RZ_API bool rz_search_set_callback(RZ_NONNULL RzSearch *s, RZ_NULLABLE RzSearchCallback(callback), RZ_NULLABLE void *user) {
	rz_return_val_if_fail(s, false);
	s->callback = callback;
	s->user = user;
	return true;
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

static bool listcb(RzSearchKeyword *k, void *user, ut64 addr) {
	RzSearchHit *hit = RZ_NEW0(RzSearchHit);
	if (!hit) {
		return false;
	}
	hit->kw = k;
	hit->addr = addr;
	rz_list_append(user, hit);
	return true;
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

// Reverse bin_keyword & bin_binmask for backward search
RZ_API void rz_search_string_prepare_backward(RzSearch *s) {
	RzListIter *iter;
	RzSearchKeyword *kw;
	// Precondition: !kw->binmask_length || kw->keyword_length % kw->binmask_length == 0
	rz_list_foreach (s->kws, iter, kw) {
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

/**
 * \brief      Resets the search nhits and mode.
 *
 * \param      s      The RzSearch structure to use
 */
RZ_API void rz_search_reset(RZ_NONNULL RzSearch *s, rz_search_mode mode) {
	rz_return_if_fail(s);
	s->nhits = 0;
	rz_search_set_mode(s, mode);
}

RZ_API void rz_search_kw_reset(RzSearch *s) {
	rz_list_purge(s->kws);
	rz_list_purge(s->hits);
	RZ_FREE(s->data);
}
