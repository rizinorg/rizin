// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file cdc.c
 * \brief Content-defined-chunking accelerated edit distance (FastCDC + Myers).
 *
 * rz_diff_myers_distance() runs an exact O(ND) edit distance over the whole
 * buffer, so its cost grows with the square of the edit distance and it becomes
 * impractical on large, substantially different inputs.
 *
 * rz_diff_cdc_distance() keeps the exact result tight while collapsing the work:
 * for inputs above \ref RZ_DIFF_CDC_THRESHOLD it splits both buffers into
 * content-defined chunks with the FastCDC algorithm (Gear rolling hash,
 * normalized chunking with cut-point skipping; Xia et al., USENIX ATC'16), finds
 * chunks that are byte-identical between the two streams (a hash match is always
 * reconfirmed with memcmp, so a collision can never fabricate an anchor), and
 * runs Myers only inside the gaps between consecutive in-order anchors, summing
 * the per-gap distances. Content-defined boundaries re-synchronise after a
 * localized edit, so an edit only disturbs the chunk(s) it lands in and the rest
 * of the file stays anchored at zero cost.
 *
 * The anchors are verified-identical and the gap edit-scripts compose into a
 * valid edit script for the whole buffer, so the returned value is an exact sum
 * of per-gap distances and a tight upper bound on the global edit distance.
 * Below the threshold the call forwards directly to rz_diff_myers_distance(), so
 * small-file results are byte-identical to the non-accelerated path.
 */

#include <rz_diff.h>
#include <rz_util.h>

#define RZ_DIFF_CDC_THRESHOLD (1u << 20) ///< below this, run exact Myers directly
#define RZ_DIFF_CDC_TARGET    2048u ///< target average chunk size, in bytes

/**
 * \brief Gear rolling-hash table: one random 64-bit value per byte value.
 *
 * A precomputed static const table keeps the chunker thread-safe by
 * construction and avoids regenerating 256 values on every call. The entries
 * only need a good bit spread (they shape the chunk-size distribution, not
 * correctness, since every candidate anchor is reconfirmed with memcmp); these
 * were produced with SplitMix64.
 */
// clang-format off
static const ut64 cdc_gear[256] = {
	0x0d7d93560d1929d2ULL, 0x491dfb740e50d43fULL, 0x42722bf4473e5e7dULL, 0xd6ca8a0790fffc45ULL,
	0xb2d3ab004cdb504bULL, 0xb75625fc4e9510a6ULL, 0x099454b898764be2ULL, 0x796b308a7fe49981ULL,
	0xdf8a2671627e719fULL, 0xfe3ea9bc89c83321ULL, 0x9e0add3f6a971fb8ULL, 0x6b2e326567617027ULL,
	0xb18a43da4a6148e8ULL, 0xf5f78123ca1a4c77ULL, 0x5dcb97ffbbf77061ULL, 0x00eea1eb2182f563ULL,
	0x1d61f1b130806e8dULL, 0x4f9fbe2b2328caa4ULL, 0x819cf9282a16663bULL, 0xc2aa2ef45c975a25ULL,
	0x7d37f5ca6062a353ULL, 0x36e8a56226a8cdadULL, 0x941c5b57a3f8c92eULL, 0x29ff1b370717c9edULL,
	0x78e01b054c8844dcULL, 0x9e7d3ac29f10db62ULL, 0x8521c11531cef188ULL, 0xe03b5f6e65af233aULL,
	0x25a7f588768d5789ULL, 0xfddb39a6a7eaa696ULL, 0x9ceb4f47b8e5f92eULL, 0xbac24fb94294f197ULL,
	0x9a6958f7609b216fULL, 0xadf91e509d87552aULL, 0x809c5997f5515babULL, 0xb40c79e6ea9256b3ULL,
	0x8ae64cfbced9a601ULL, 0xf792dc21b732d223ULL, 0xffa0305c17db80caULL, 0x7c824753baa7f5b4ULL,
	0x98a3f119a97a9ae2ULL, 0x12d64b490424a9e5ULL, 0x82780af10fe266b5ULL, 0xa8defd259ce43675ULL,
	0xe5613d4aeeb1d1bcULL, 0x13b5a4221264ef57ULL, 0xdfc287a7509b6ba3ULL, 0x0158749360da2354ULL,
	0xf715e51cc1f27b8bULL, 0x6523eff3b464a6bfULL, 0xc37746a8e235f719ULL, 0xeec88bb7e657bb11ULL,
	0x7449a940cafb0d41ULL, 0xe7811c70176fa945ULL, 0x5667e4812a7575b3ULL, 0x74fb1b3800119318ULL,
	0x9b6312ed0c2ba884ULL, 0x6fc5b2496b26b7d1ULL, 0x249cc0e12b3d56eeULL, 0xe34e333f136e7b2bULL,
	0x0a4f0eb30582fdd9ULL, 0x936e9692d84c880dULL, 0xf945d10e6e21cf10ULL, 0x161ee5c8e361b38fULL,
	0x6e0c7135d083627bULL, 0xcd433bf3f233072cULL, 0xdf665a75ab912515ULL, 0x655acb14e90e6cb8ULL,
	0x200cdf22290a7284ULL, 0xd5f8d1de6bad27ccULL, 0xec0ba69f212bc401ULL, 0x172fba882fdf093eULL,
	0x80c8fb4bbaaaa286ULL, 0x4e9d1d9fd0da8fa5ULL, 0x4ef1ebe79bab5ec6ULL, 0x748b59a4e774f7ffULL,
	0x87c99f54450cd7a0ULL, 0xd661fa6c15716985ULL, 0x9d4621d06a666ac7ULL, 0xa833ed7f845c3188ULL,
	0xfc78ebc1c31f2c90ULL, 0xcd164aa683c51676ULL, 0xaab2680105b8ca66ULL, 0xa43b52c76dc996d8ULL,
	0x0f9fcbfd43b96c68ULL, 0xe3047289a11d9510ULL, 0x31ec466d3445eb41ULL, 0x57f2b6b95a468686ULL,
	0x3e44fa53705aacd1ULL, 0x0e834f7873daa9e0ULL, 0x9f295d9d962de27bULL, 0xca05f4c4c421099cULL,
	0xbee57faf147c296fULL, 0x16a0e4ea86dc3e50ULL, 0x55519728916db0f1ULL, 0xca7a64c180f03b32ULL,
	0x0b7454d5eda5a3e3ULL, 0xf5374423b0223a95ULL, 0x65d97a787cce2aadULL, 0x3c6ae04f18e12fe3ULL,
	0x8b8e01d7db818201ULL, 0x302aa902db358fecULL, 0xd42f2b5f5b080954ULL, 0x3a81e13528b6a532ULL,
	0x57ff38e48c71db82ULL, 0x6c82eb515a3b71f9ULL, 0x82f26bf7168b4de5ULL, 0x4d62d0747fd209e1ULL,
	0x0b6733930c511f7aULL, 0x820f70e8a3739cc7ULL, 0xebe031a70d74f24fULL, 0x7846a11e7b7d1af0ULL,
	0x37d3e4c595dd0251ULL, 0x976010c6135f7b60ULL, 0x843d8613a24b24e0ULL, 0xf5e9bc3fe6d1a3b4ULL,
	0x35594a1fd5f7115dULL, 0x4e87788213eda2a7ULL, 0x8a28d14a177453b0ULL, 0xee3f84420c444111ULL,
	0xfcf46e7a8a448d48ULL, 0xb793752ee76d8528ULL, 0xf70ad88a1fe01665ULL, 0xa9aa11cb22906d6dULL,
	0x3c66c2cdd95baf9fULL, 0x0fd3c7f71370054dULL, 0x2abad2957ab7e0f1ULL, 0x615d74f1c6b97372ULL,
	0x4fd59c68b2c5c08eULL, 0x64e632f6092cd066ULL, 0x832df4dcf66ad766ULL, 0x73a14d275303ae7eULL,
	0x71f914fafbd72ee4ULL, 0xb121f7bc8223b811ULL, 0x70cb984e22ce3e78ULL, 0xb02518f59baae931ULL,
	0x6c8428dc7c7cd2f2ULL, 0x0874581f07d6e4b2ULL, 0xc2b397d6fa96cf12ULL, 0x4022eeccba827c2cULL,
	0x3a2f46ed807bd2aaULL, 0x24c45f4593bd30a4ULL, 0xc488a24d971efac0ULL, 0x9c7c9288ecd86aebULL,
	0xd3796280db253449ULL, 0x6f1fb491f09f04b6ULL, 0x70568028d6e154e9ULL, 0x8f5c5570c866fa3cULL,
	0x592efd442f6390e5ULL, 0x59166b3a7dacabb4ULL, 0x7558d050dbfe4482ULL, 0x5885d041b7105e4eULL,
	0x01e795bc1f4b30aeULL, 0x0a40d50ca8cbca87ULL, 0x11e1a2b4cefc53dfULL, 0x18e3e1650721eafbULL,
	0xcdef8709bb9e8f56ULL, 0x5dd3e9126b098560ULL, 0x193387965ed33ce4ULL, 0xc331a570c71e7e2eULL,
	0x87be554e6c868a1fULL, 0xb411acf3e180e331ULL, 0xbc7e8b76e95962deULL, 0xc64442d245ced911ULL,
	0x30f1b05936e53fafULL, 0x43408fda565c9813ULL, 0x717a9af475c0c581ULL, 0x99259067c338db16ULL,
	0x78a6699feb38a136ULL, 0xcb1edfbd2be54611ULL, 0x2d965761fd650e80ULL, 0xf6b946760afe4abfULL,
	0xe03379af0f5332baULL, 0x4f5728f4db5e83a5ULL, 0x39176bac8b38dca8ULL, 0x4f2877b5b1907b47ULL,
	0x2d9302e785652915ULL, 0x0b20dcef62f41474ULL, 0xa14e9c2f5876ce78ULL, 0xb04992726efe658bULL,
	0xb162c958148b2fb5ULL, 0x466bacf46b96e6ebULL, 0x63e67629671055afULL, 0xb35830246ddc67b4ULL,
	0xcdd9b139fabf8129ULL, 0xf644564b34ee91a8ULL, 0x8caad15787d167a9ULL, 0x08204e0aec2e9a70ULL,
	0x564997b7f132ea65ULL, 0x4583085cbaf1baa3ULL, 0x067202c5615e1b63ULL, 0x7d99a98bbc9b4e4fULL,
	0xc94465180c6260a8ULL, 0x0ae2c7ffd29870fbULL, 0xc402b5053771ef9cULL, 0x6a1893a720e309deULL,
	0x2529d483815a111eULL, 0x39d9ec9269cea2f7ULL, 0x5d6709c9787b321bULL, 0x44ca27bf3765898eULL,
	0x2903fdd05d587978ULL, 0xb68270812182eb5cULL, 0xc388096630203f20ULL, 0x3379b43a1880bf01ULL,
	0xd73c82a4f0c1c194ULL, 0x9dc65d9ab7af613dULL, 0xf160290c20bed092ULL, 0xa53523f9bc78d6f8ULL,
	0x18a6a73fe14f1321ULL, 0x581e460722cf5e08ULL, 0xd499f30fc3f759c8ULL, 0x8dbc560fb231898aULL,
	0x3980251709771d61ULL, 0x991c137f8f3bba75ULL, 0xdefb9d049f5517f4ULL, 0x7d53adeb13cd1673ULL,
	0x7d1883c9fe7a3496ULL, 0x87049285b4601d95ULL, 0xcdaf3aef795e5595ULL, 0x1f29b2b16f9c2d8cULL,
	0x3a23d7085573b66cULL, 0xdcf8d6cdf9be1471ULL, 0x266ce5af0c7e03ddULL, 0x352c3d2a1a624a9fULL,
	0x16fd6e56a467933cULL, 0xffe2db4315d60a5aULL, 0x5ab4e7758bb3bc92ULL, 0x2cd2c91108cf65a0ULL,
	0xdd7e69525de8613bULL, 0x03d97a8729f050f1ULL, 0x4c664b78412a5107ULL, 0x6baacff09fba5e92ULL,
	0xcb47cb1f71bf1de4ULL, 0x58457c983973fe63ULL, 0x43e44f210f3a4f3bULL, 0x12d8396d4bd94661ULL,
	0xe8f3660934e23f01ULL, 0xe8ef6e1335c8b598ULL, 0x74b587acf09a3c42ULL, 0xa398137ebdcecb9aULL,
	0xf75c7dd1da80b3e4ULL, 0x6c81e3af7f9f3f4dULL, 0xdea64f24fc08029aULL, 0x33e7b56e9e47ae5dULL,
	0x4c6fe2e14b55dcb5ULL, 0x33e9024d6f0c5d5eULL, 0x2c124c85ca8159e2ULL, 0x51e4466b9cb12346ULL,
	0x980bc719a060f9ddULL, 0xb8b0a14e10470684ULL, 0x6f3aaaa88f63d587ULL, 0xafd2e85caeb43649ULL,
	0xd06c8f4bdad99009ULL, 0x51e169b0a90f9014ULL, 0x149046d897b950acULL, 0xf4858b398b944bd9ULL,
};
// clang-format on

/** \brief FastCDC configuration: chunk-size bounds and judging masks. */
typedef struct cdc_config_t {
	ut32 min_size; ///< never cut before this many bytes
	ut32 avg_size; ///< point at which the looser mask takes over
	ut32 max_size; ///< force a cut at this many bytes
	ut64 mask_s; ///< stricter mask, used in [min_size, avg_size)
	ut64 mask_l; ///< looser mask, used in [avg_size, max_size)
} CdcConfig;

/** \brief SplitMix64, used to derive the judging masks (and the Gear table above). */
static inline ut64 cdc_splitmix64(ut64 *state) {
	ut64 z = (*state += 0x9e3779b97f4a7c15ULL);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

/**
 * \brief FNV-1a hash of a chunk, used only to bucket candidate anchors.
 *
 * Hits are always reconfirmed with memcmp, so the hash never needs to be
 * collision-free for correctness.
 */
static ut64 cdc_fnv1a(const ut8 *p, ut64 n) {
	ut64 h = 0xcbf29ce484222325ULL;
	for (ut64 i = 0; i < n; i++) {
		h = (h ^ p[i]) * 0x100000001b3ULL;
	}
	return h;
}

/**
 * \brief Build a 64-bit judging mask with \p bits one-bits in the upper half.
 *
 * FastCDC cuts when (fingerprint & mask) == 0, so the number of set bits sets
 * the expected chunk length (~2^bits). The exact bit positions only shape the
 * chunk-size distribution, not correctness, so they are produced deterministically.
 */
static ut64 cdc_mask(ut32 bits) {
	ut64 mask = 0, state = 0x1234567ULL + bits;
	for (ut32 set = 0; set < bits;) {
		ut64 bit = 1ULL << (16 + (cdc_splitmix64(&state) % 48));
		if (!(mask & bit)) {
			mask |= bit;
			set++;
		}
	}
	return mask;
}

/** \brief Initialise a FastCDC configuration for the given average chunk size. */
static void cdc_config_init(CdcConfig *cfg, ut32 avg) {
	if (!avg) {
		avg = RZ_DIFF_CDC_TARGET;
	}
	cfg->avg_size = avg;
	cfg->min_size = avg / 4;
	cfg->max_size = avg * 8;
	ut32 bits = 0;
	for (ut32 t = avg; t > 1; t >>= 1) {
		bits++;
	}
	// normalized chunking: stricter mask before the average point, looser after
	cfg->mask_s = cdc_mask(bits + 2);
	cfg->mask_l = cdc_mask(bits > 2 ? bits - 2 : 1);
}

/**
 * \brief Length of the next FastCDC chunk in \p p[0..n).
 *
 * Returns a value in [min(min_size, n), min(max_size, n)] using normalized
 * chunking: scan with the strict mask until \ref CdcConfig::avg_size, then with
 * the loose mask up to \ref CdcConfig::max_size, falling back to the hard cap.
 */
static ut64 cdc_next(const ut8 *p, ut64 n, const CdcConfig *cfg) {
	if (n <= cfg->min_size) {
		return n;
	}
	ut64 end = RZ_MIN(n, cfg->max_size);
	ut64 normal = RZ_MIN(end, cfg->avg_size);
	ut64 fp = 0, i = cfg->min_size;
	for (; i < normal; i++) {
		fp = (fp << 1) + cdc_gear[p[i]];
		if (!(fp & cfg->mask_s)) {
			return i;
		}
	}
	for (; i < end; i++) {
		fp = (fp << 1) + cdc_gear[p[i]];
		if (!(fp & cfg->mask_l)) {
			return i;
		}
	}
	return end;
}

typedef struct cdc_chunk_t {
	ut64 offset; ///< start of the chunk inside its buffer
	ut64 length; ///< chunk length in bytes
	ut64 hash; ///< FNV-1a of the chunk content
} CdcChunk;

/**
 * \brief Split the whole buffer into FastCDC chunks.
 * \return malloc'd array of \p *count chunks (caller frees), or NULL on failure.
 */
static CdcChunk *cdc_chunk_all(const ut8 *buf, ut64 n, const CdcConfig *cfg, ut64 *count) {
	// every chunk but the last is >= min_size, so this bounds the count
	ut64 cap = n / (cfg->min_size ? cfg->min_size : 1) + 2;
	CdcChunk *chunks = RZ_NEWS0(CdcChunk, cap);
	if (!chunks) {
		return NULL;
	}
	ut64 pos = 0, used = 0;
	while (pos < n && used < cap) {
		ut64 len = cdc_next(buf + pos, n - pos, cfg);
		if (!len) {
			len = 1;
		}
		chunks[used].offset = pos;
		chunks[used].length = len;
		chunks[used].hash = cdc_fnv1a(buf + pos, len);
		used++;
		pos += len;
	}
	*count = used;
	return chunks;
}

typedef struct cdc_ref_t {
	ut64 hash; ///< chunk hash
	ut32 index; ///< chunk index in its buffer
} CdcRef;

/** \brief Order anchor candidates by (hash, index) so equal-hash runs stay sorted by index. */
static int cdc_ref_cmp(const void *a, const void *b) {
	const CdcRef *x = a, *y = b;
	if (x->hash != y->hash) {
		return x->hash < y->hash ? -1 : 1;
	}
	return x->index < y->index ? -1 : (x->index > y->index ? 1 : 0);
}

/** \brief First ref with (hash, index) >= (\p hash, \p min_index), or \p n if none. */
static st64 cdc_ref_lower_bound(const CdcRef *refs, st64 n, ut64 hash, ut32 min_index) {
	st64 lo = 0, hi = n;
	while (lo < hi) {
		st64 mid = lo + (hi - lo) / 2;
		if (refs[mid].hash < hash || (refs[mid].hash == hash && refs[mid].index < min_index)) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	return lo;
}

/** \brief Exact Myers over a single gap, accumulated into \p total. */
static bool cdc_gap(const ut8 *a, ut64 la, const ut8 *b, ut64 lb, ut64 *total) {
	if (!la && !lb) {
		return true;
	}
	ut32 d = 0;
	if (!rz_diff_myers_distance(a, (ut32)la, b, (ut32)lb, &d, NULL)) {
		return false;
	}
	*total += d;
	return true;
}

/**
 * \brief Edit distance between two buffers, FastCDC-accelerated for large inputs.
 *
 * For inputs above \ref RZ_DIFF_CDC_THRESHOLD the buffers are split into
 * content-defined chunks and Myers runs only inside the gaps between
 * byte-identical anchor chunks; the result is the exact sum of the per-gap
 * distances (a tight upper bound on the global Myers distance). Smaller inputs
 * are diffed directly, yielding results identical to rz_diff_myers_distance().
 *
 * \param a First buffer.
 * \param size_a Length of the first buffer.
 * \param b Second buffer.
 * \param size_b Length of the second buffer.
 * \param distance Optional output: the summed edit distance.
 * \param similarity Optional output: 1 - distance / (size_a + size_b).
 * \return true on success, false on NULL inputs or allocation failure.
 */
RZ_API bool rz_diff_cdc_distance(RZ_NONNULL const ut8 *a, ut32 size_a, RZ_NONNULL const ut8 *b, ut32 size_b, RZ_NULLABLE ut32 *distance, RZ_NULLABLE double *similarity) {
	rz_return_val_if_fail(a && b, false);

	if (RZ_MAX(size_a, size_b) <= RZ_DIFF_CDC_THRESHOLD) {
		// small inputs: exact and identical to the non-accelerated tool
		return rz_diff_myers_distance(a, size_a, b, size_b, distance, similarity);
	}

	CdcConfig cfg;
	cdc_config_init(&cfg, RZ_DIFF_CDC_TARGET);

	ut64 na = 0, nb = 0;
	CdcChunk *ca = cdc_chunk_all(a, size_a, &cfg, &na);
	CdcChunk *cb = cdc_chunk_all(b, size_b, &cfg, &nb);
	CdcRef *refs = nb ? RZ_NEWS0(CdcRef, nb) : NULL;
	if (!ca || !cb || (nb && !refs)) {
		goto err;
	}
	for (ut64 j = 0; j < nb; j++) {
		refs[j].hash = cb[j].hash;
		refs[j].index = (ut32)j;
	}
	qsort(refs, nb, sizeof(CdcRef), cdc_ref_cmp);

	ut64 prev_a = 0, prev_b = 0, total = 0;
	ut32 bj_min = 0;
	for (ut64 ai = 0; ai < na; ai++) {
		// earliest still-available B chunk that is byte-identical to ca[ai]
		st64 hit = -1;
		for (st64 k = cdc_ref_lower_bound(refs, nb, ca[ai].hash, bj_min);
			k < (st64)nb && refs[k].hash == ca[ai].hash; k++) {
			ut32 j = refs[k].index;
			if (ca[ai].length == cb[j].length &&
				!memcmp(a + ca[ai].offset, b + cb[j].offset, ca[ai].length)) {
				hit = j;
				break;
			}
		}
		if (hit < 0) {
			continue;
		}
		if (!cdc_gap(a + prev_a, ca[ai].offset - prev_a, b + prev_b, cb[hit].offset - prev_b, &total)) {
			goto err;
		}
		prev_a = ca[ai].offset + ca[ai].length;
		prev_b = cb[hit].offset + cb[hit].length;
		bj_min = (ut32)hit + 1;
	}
	// tail gap after the last anchor
	if (!cdc_gap(a + prev_a, size_a - prev_a, b + prev_b, size_b - prev_b, &total)) {
		goto err;
	}

	free(ca);
	free(cb);
	free(refs);
	if (distance) {
		*distance = total > UT32_MAX ? UT32_MAX : (ut32)total;
	}
	if (similarity) {
		double denom = (double)size_a + (double)size_b;
		*similarity = denom > 0 ? 1.0 - (double)total / denom : 1.0;
	}
	return true;

err:
	free(ca);
	free(cb);
	free(refs);
	return false;
}
