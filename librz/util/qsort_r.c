// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_types.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_qsort_r.h"
#include "rz_util/rz_bits.h"

#include <stdlib.h>
#include <string.h>

/*
 * \file portable quicksort wrapper to allow context-dependent comparator
 */

/* Public unified signature: GNU-style (arg last). */

#if HAVE_QSORT_R_GNU

RZ_API void rz_qsort_r(void *base, size_t nmemb, size_t size,
	RzQsortRCmp cmp, void *user) {
	qsort_r(base, nmemb, size, cmp, user);
}

#elif HAVE_QSORT_R_BSD

typedef struct {
	RzQsortRCmp cmp;
	void *user;
} rz_qsort_thunk_t;

static int rz_qsort_bsd_trampoline(void *thunk, const void *a, const void *b) {
	rz_qsort_thunk_t *t = thunk;
	return t->cmp(a, b, t->user);
}

RZ_API void rz_qsort_r(void *base, size_t nmemb, size_t size,
	RzQsortRCmp cmp, void *user) {
	rz_qsort_thunk_t t = { cmp, user };
	qsort_r(base, nmemb, size, &t, rz_qsort_bsd_trampoline);
}

#elif HAVE_QSORT_S_MS

typedef struct {
	RzQsortRCmp cmp;
	void *user;
} rz_qsort_thunk_t;

static int __cdecl rz_qsort_ms_trampoline(void *ctx, const void *a, const void *b) {
	rz_qsort_thunk_t *t = ctx;
	return t->cmp(a, b, t->user);
}

RZ_API void rz_qsort_r(void *base, size_t nmemb, size_t size,
	RzQsortRCmp cmp, void *user) {
	rz_qsort_thunk_t t = { cmp, user };
	qsort_s(base, nmemb, size, rz_qsort_ms_trampoline, &t);
}

#else

/* ------------------------------------------------------------------
 * Portable fallback: in-place introsort with a context pointer.
 *
 * Used on systems whose libc lacks any qsort_r/qsort_s variant
 * (e.g. OpenBSD, older Haiku, older Solaris).
 *
 * Algorithm: quicksort with median-of-three pivot selection, switching
 * to heapsort when recursion depth exceeds 2*floor(log2(n)) (Musser's
 * introsort), and to insertion sort for small partitions.
 * Worst case: O(n log n). Stack usage: O(log n).
 * ------------------------------------------------------------------ */

#define RZ_QSORT_ISORT_THRESHOLD 16

static inline void rz_qsort_swap(void *a, void *b, size_t size) {
	ut8 *pa = a, *pb = b, tmp;
	while (size--) {
		tmp = *pa;
		*pa++ = *pb;
		*pb++ = tmp;
	}
}

static void rz_qsort_isort(ut8 *base, size_t nmemb, size_t size,
	RzQsortRCmp cmp, void *user) {
	for (size_t i = 1; i < nmemb; i++) {
		for (size_t j = i; j > 0; j--) {
			ut8 *a = base + (j - 1) * size;
			ut8 *b = base + j * size;
			if (cmp(a, b, user) <= 0) {
				break;
			}
			rz_qsort_swap(a, b, size);
		}
	}
}

static void rz_qsort_sift(ut8 *base, size_t root, size_t end,
	size_t size, RzQsortRCmp cmp, void *user) {
	while (root * 2 + 1 <= end) {
		size_t child = root * 2 + 1;
		if (child + 1 <= end &&
			cmp(base + child * size, base + (child + 1) * size, user) < 0) {
			child++;
		}
		if (cmp(base + root * size, base + child * size, user) >= 0) {
			return;
		}
		rz_qsort_swap(base + root * size, base + child * size, size);
		root = child;
	}
}

static void rz_qsort_hsort(ut8 *base, size_t nmemb, size_t size,
	RzQsortRCmp cmp, void *user) {
	if (nmemb < 2) {
		return;
	}
	for (size_t start = nmemb / 2; start-- > 0;) {
		rz_qsort_sift(base, start, nmemb - 1, size, cmp, user);
	}
	for (size_t end = nmemb - 1; end > 0; end--) {
		rz_qsort_swap(base, base + end * size, size);
		rz_qsort_sift(base, 0, end - 1, size, cmp, user);
	}
}

static RZ_INLINE unsigned int ilog2(size_t n) {
	return 63 - rz_bits_leading_zeros(n);
}

static void rz_qsort_intro(ut8 *base, size_t nmemb, size_t size,
	RzQsortRCmp cmp, void *user, unsigned int depth) {
	while (nmemb > RZ_QSORT_ISORT_THRESHOLD) {
		if (depth == 0) {
			rz_qsort_hsort(base, nmemb, size, cmp, user);
			return;
		}
		depth--;

		/* Median-of-three: order lo, mid, hi; place pivot at hi-1. */
		ut8 *lo = base;
		ut8 *mid = base + (nmemb / 2) * size;
		ut8 *hi = base + (nmemb - 1) * size;
		if (cmp(lo, mid, user) > 0)
			rz_qsort_swap(lo, mid, size);
		if (cmp(lo, hi, user) > 0)
			rz_qsort_swap(lo, hi, size);
		if (cmp(mid, hi, user) > 0)
			rz_qsort_swap(mid, hi, size);
		rz_qsort_swap(mid, hi - size, size);
		ut8 *pivot = hi - size;

		/* Hoare-style partition with sentinels at lo and pivot. */
		ut8 *i = lo;
		ut8 *j = pivot;
		for (;;) {
			do {
				i += size;
			} while (cmp(i, pivot, user) < 0);
			do {
				j -= size;
			} while (cmp(j, pivot, user) > 0);
			if (i >= j) {
				break;
			}
			rz_qsort_swap(i, j, size);
		}
		rz_qsort_swap(i, pivot, size);

		/* Recurse on the smaller side, iterate on the larger one
		 * to bound stack usage to O(log n). */
		size_t left_n = (size_t)(i - base) / size;
		size_t right_n = nmemb - left_n - 1;
		if (left_n < right_n) {
			rz_qsort_intro(base, left_n, size, cmp, user, depth);
			base = i + size;
			nmemb = right_n;
		} else {
			rz_qsort_intro(i + size, right_n, size, cmp, user, depth);
			nmemb = left_n;
		}
	}
	rz_qsort_isort(base, nmemb, size, cmp, user);
}

RZ_API void rz_qsort_r(void *base, size_t nmemb, size_t size,
	RzQsortRCmp cmp, void *user) {
	if (!base || nmemb < 2 || size == 0 || !cmp) {
		return;
	}
	rz_qsort_intro((ut8 *)base, nmemb, size, cmp, user,
		2 * ilog2(nmemb));
}

#endif
