// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file cdc.c
 * \brief Content-Defined Chunking (CDC) accelerated byte-distance for large files.
 *
 * For large inputs the exact distance algorithms in distance.c are expensive:
 * Levenshtein is O(N*M) and Myers' exploration cost grows with the square of
 * the edit distance. This file splits each buffer into content-defined chunks
 * whose boundaries re-synchronise after localized edits, using the FastCDC
 * algorithm (Gear rolling hash, normalized chunking, cut-point skipping;
 * Xia et al., USENIX ATC'16).
 *
 * rz_diff_cdc_distance() chunks both inputs, finds in-order anchor chunks that
 * are byte-identical between the two streams (hash match confirmed with a
 * memcmp, so a hash collision can never fabricate an anchor), and then runs the
 * exact distance routine ONLY inside the gaps between consecutive anchors,
 * summing the per-gap edit distances. The anchors contribute zero edits, so the
 * sum is a tight upper bound on the true edit distance while the work collapses
 * from one huge problem to many tiny ones.
 *
 * Inputs below RZ_DIFF_CDC_THRESHOLD are diffed directly with the exact
 * algorithm, so results are byte-identical to rz_diff_{myers,levenshtein} on
 * small files and only the large-file path takes the accelerated route.
 */

#include <rz_diff.h>
#include <rz_util.h>

#define RZ_DIFF_CDC_THRESHOLD (1u << 20) /* 1 MiB: below this, diff directly  */
#define RZ_DIFF_CDC_TARGET    2048        /* target average chunk size (bytes) */

/* Gear table (256 random 64-bit values) for the FastCDC rolling hash. */
static ut64 cdc_gear[256];
static bool cdc_gear_ready = false;

static inline ut64 splitmix64(ut64 *s) {
	ut64 z = (*s += 0x9E3779B97F4A7C15ULL);
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return z ^ (z >> 31);
}

static void cdc_gear_init(void) {
	if (cdc_gear_ready) {
		return;
	}
	ut64 s = 0xdeadbeefcafebabeULL;
	for (int i = 0; i < 256; i++) {
		cdc_gear[i] = splitmix64(&s);
	}
	cdc_gear_ready = true;
}

static ut64 cdc_fnv1a(const ut8 *p, ut64 n) {
	ut64 h = 0xcbf29ce484222325ULL;
	for (ut64 i = 0; i < n; i++) {
		h ^= p[i];
		h *= 0x100000001b3ULL;
	}
	return h;
}

/* murmur3 finalizer, used to scatter chunk hashes across the anchor index */
static inline ut64 cdc_mix(ut64 k) {
	k ^= k >> 33;
	k *= 0xff51afd7ed558ccdULL;
	k ^= k >> 33;
	k *= 0xc4ceb9fe1a85ec53ULL;
	k ^= k >> 33;
	return k;
}

/* 64-bit mask with `bits` 1-bits in the high half (canonical FastCDC values
 * for the common bit counts, generated deterministically otherwise). */
static ut64 cdc_spread_mask(ut32 bits) {
	if (bits == 15) {
		return 0x0003590703530000ULL;
	}
	if (bits == 11) {
		return 0x0000d90003530000ULL;
	}
	if (bits == 13) {
		return 0x0000d93003530000ULL;
	}
	ut64 m = 0, s = 0x1234567ULL + bits;
	ut32 set = 0;
	while (set < bits) {
		int b = 16 + (int)(splitmix64(&s) % 48);
		ut64 bit = 1ULL << b;
		if (!(m & bit)) {
			m |= bit;
			set++;
		}
	}
	return m;
}

typedef struct cdc_params_t {
	ut32 min_size, avg_size, max_size;
	ut64 mask_s, mask_l;
} CdcParams;

static void cdc_params(ut32 avg, CdcParams *o) {
	memset(o, 0, sizeof(*o));
	if (!avg) {
		avg = 2048;
	}
	o->avg_size = avg;
	o->min_size = avg / 4;
	o->max_size = avg * 8;
	ut32 b = 0, t = avg;
	while (t > 1) {
		t >>= 1;
		b++;
	}
	o->mask_s = cdc_spread_mask(b + 2);
	o->mask_l = cdc_spread_mask(b > 2 ? b - 2 : 1);
}

/* ================================================================== */
/* FastCDC                                                            */
/* ================================================================== */
static ut64 fastcdc_next(const ut8 *p, ut64 n, const CdcParams *cp) {
	if (n <= cp->min_size) {
		return n;
	}
	ut64 end = n < cp->max_size ? n : cp->max_size;
	ut64 normal = cp->avg_size;
	if (normal > end) {
		normal = end;
	}
	ut64 fp = 0, i = cp->min_size;
	for (; i < normal; i++) {
		fp = (fp << 1) + cdc_gear[p[i]];
		if (!(fp & cp->mask_s)) {
			return i;
		}
	}
	for (; i < end; i++) {
		fp = (fp << 1) + cdc_gear[p[i]];
		if (!(fp & cp->mask_l)) {
			return i;
		}
	}
	return end;
}

/* ================================================================== */
/* chunk record + whole-buffer chunking                               */
/* ================================================================== */
typedef struct {
	ut64 offset, length, hash;
} CdcChunk;

/* Chunk the whole buffer, storing offset/length/FNV-1a-hash per chunk.
 * Returns a malloc'd array (caller frees) and writes the count to *out_n. */
static CdcChunk *cdc_chunk_all(const ut8 *buf, ut64 n, const CdcParams *cp, ut64 *out_n) {
	ut64 cap = n / (cp->min_size ? cp->min_size : 1) + 8;
	CdcChunk *out = RZ_NEWS0(CdcChunk, cap);
	if (!out) {
		return NULL;
	}
	ut64 pos = 0, count = 0;
	while (pos < n && count < cap) {
		const ut8 *p = buf + pos;
		ut64 rem = n - pos, len = fastcdc_next(p, rem, cp);
		if (!len) {
			len = 1;
		}
		if (len > rem) {
			len = rem;
		}
		out[count].offset = pos;
		out[count].length = len;
		out[count].hash = cdc_fnv1a(p, len);
		count++;
		pos += len;
	}
	*out_n = count;
	return out;
}

/* ================================================================== */
/* anchor index: hash -> ascending list of B-chunk indices            */
/* ================================================================== */
typedef struct {
	ut64 key;
	ut32 *idx;
	ut32 n, cap;
} HBucket;
typedef struct {
	HBucket *b;
	ut64 cap, mask;
} HIndex;

static bool hidx_init(HIndex *h, ut64 n) {
	ut64 cap = 16;
	while (cap < n * 2) {
		cap <<= 1;
	}
	h->cap = cap;
	h->mask = cap - 1;
	h->b = RZ_NEWS0(HBucket, cap);
	return h->b != NULL;
}
static void hidx_fini(HIndex *h) {
	for (ut64 i = 0; i < h->cap; i++) {
		free(h->b[i].idx);
	}
	free(h->b);
}
static void hidx_push(HIndex *h, ut64 key, ut32 v) {
	ut64 i = cdc_mix(key) & h->mask;
	while (h->b[i].idx && h->b[i].key != key) {
		i = (i + 1) & h->mask;
	}
	HBucket *bk = &h->b[i];
	bk->key = key;
	if (bk->n == bk->cap) {
		ut32 nc = bk->cap ? bk->cap * 2 : 4;
		ut32 *ni = realloc(bk->idx, nc * sizeof(ut32));
		if (!ni) {
			return;
		}
		bk->idx = ni;
		bk->cap = nc;
	}
	bk->idx[bk->n++] = v; /* ascending by construction */
}
static HBucket *hidx_get(HIndex *h, ut64 key) {
	ut64 i = cdc_mix(key) & h->mask;
	while (h->b[i].idx) {
		if (h->b[i].key == key) {
			return &h->b[i];
		}
		i = (i + 1) & h->mask;
	}
	return NULL;
}
static long cdc_lower_bound(const ut32 *v, ut32 n, ut32 lo) {
	long a = 0, b = n;
	while (a < b) {
		long m = (a + b) / 2;
		if (v[m] < lo) {
			a = m + 1;
		} else {
			b = m;
		}
	}
	return a < (long)n ? a : -1;
}

/* ================================================================== */
/* public entry point                                                 */
/* ================================================================== */

/**
 * \brief Edit distance between two buffers, accelerated for large inputs via CDC.
 *
 * Buffers larger than RZ_DIFF_CDC_THRESHOLD are split into content-defined
 * chunks; the exact algorithm (Myers when \p substitution is false, Levenshtein
 * when true) runs only inside the gaps between byte-identical anchor chunks.
 * Smaller buffers are diffed directly, giving results identical to
 * rz_diff_myers_distance / rz_diff_levenshtein_distance.
 *
 * \param a,size_a     first buffer and its length
 * \param b,size_b     second buffer and its length
 * \param substitution use Levenshtein (with substitution) in gaps if true, else Myers
 * \param distance     [out, nullable] summed edit distance (upper bound on the exact value)
 * \param similarity   [out, nullable] 1 - distance/length, matching the chosen algorithm
 * \return true on success, false on allocation failure or NULL inputs
 */
RZ_API bool rz_diff_cdc_distance(RZ_NONNULL const ut8 *a, ut32 size_a,
	RZ_NONNULL const ut8 *b, ut32 size_b, bool substitution,
	RZ_NULLABLE ut32 *distance, RZ_NULLABLE double *similarity) {
	rz_return_val_if_fail(a && b, false);

	ut32 big = size_a > size_b ? size_a : size_b;
	if (big <= RZ_DIFF_CDC_THRESHOLD) {
		/* small inputs: exact, identical to the non-CDC tools */
		return substitution
			? rz_diff_levenshtein_distance(a, size_a, b, size_b, distance, similarity)
			: rz_diff_myers_distance(a, size_a, b, size_b, distance, similarity);
	}

	cdc_gear_init();
	CdcParams cp;
	cdc_params(RZ_DIFF_CDC_TARGET, &cp);

	ut64 na = 0, nb = 0;
	CdcChunk *ca = cdc_chunk_all(a, size_a, &cp, &na);
	CdcChunk *cb = cdc_chunk_all(b, size_b, &cp, &nb);
	if (!ca || !cb) {
		free(ca);
		free(cb);
		return false;
	}

	HIndex hi;
	if (!hidx_init(&hi, nb ? nb : 1)) {
		free(ca);
		free(cb);
		return false;
	}
	for (ut64 j = 0; j < nb; j++) {
		hidx_push(&hi, cb[j].hash, (ut32)j);
	}

	bool ok = true;
	ut64 prev_a = 0, prev_b = 0, bj_min = 0, total = 0;
	for (ut64 ai = 0; ai < na && ok; ai++) {
		HBucket *bk = hidx_get(&hi, ca[ai].hash);
		if (!bk) {
			continue;
		}
		long p = cdc_lower_bound(bk->idx, bk->n, (ut32)bj_min);
		long hit = -1;
		for (; p >= 0 && p < (long)bk->n; p++) {
			ut32 j = bk->idx[p];
			if (ca[ai].length == cb[j].length &&
				!memcmp(a + ca[ai].offset, b + cb[j].offset, ca[ai].length)) {
				hit = j;
				break;
			}
		}
		if (hit < 0) {
			continue;
		}
		ut64 ga = ca[ai].offset - prev_a, gb = cb[hit].offset - prev_b;
		if (ga || gb) {
			ut32 d = 0;
			ok = substitution
				? rz_diff_levenshtein_distance(a + prev_a, (ut32)ga, b + prev_b, (ut32)gb, &d, NULL)
				: rz_diff_myers_distance(a + prev_a, (ut32)ga, b + prev_b, (ut32)gb, &d, NULL);
			total += d;
		}
		prev_a = ca[ai].offset + ca[ai].length;
		prev_b = cb[hit].offset + cb[hit].length;
		bj_min = (ut64)hit + 1;
	}
	if (ok) { /* tail gap after the last anchor */
		ut64 ga = size_a - prev_a, gb = size_b - prev_b;
		if (ga || gb) {
			ut32 d = 0;
			ok = substitution
				? rz_diff_levenshtein_distance(a + prev_a, (ut32)ga, b + prev_b, (ut32)gb, &d, NULL)
				: rz_diff_myers_distance(a + prev_a, (ut32)ga, b + prev_b, (ut32)gb, &d, NULL);
			total += d;
		}
	}

	hidx_fini(&hi);
	free(ca);
	free(cb);
	if (!ok) {
		return false;
	}

	if (distance) {
		*distance = total > UT32_MAX ? UT32_MAX : (ut32)total;
	}
	if (similarity) {
		double denom = substitution ? (double)big : (double)size_a + (double)size_b;
		*similarity = denom > 0 ? 1.0 - (double)total / denom : 1.0;
	}
	return true;
}
