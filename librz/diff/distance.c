// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2017 Fangrui Song <i@maskray.me>
// SPDX-FileCopyrightText: 2016 NikolaiHampton <nikolaih@3583bytesready.net>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_diff.h>
#include <rz_util/rz_assert.h>

#include "diff_internal.h"

static ut32 chunk_lcs(const FastCDCChunk *a, const FastCDCChunk *b) {
	if (!a->data || !b->data) {
		return 0;
	}

	ut32 distance = 0;
	rz_diff_myers_distance(a->data, a->length, b->data, b->length, &distance, NULL);
	return (a->length + b->length - distance) / 2;
}

/**
 * \brief      Calculates the distance between two buffers using the LCS (Myers) + rolling hash (FastCDC)
 *
 * \param[in]  a           Buffer A to compare
 * \param[in]  la          Length of buffer A
 * \param[in]  a           Buffer B to compare
 * \param[in]  la          Length of buffer B
 * \param[in]  block_size  The block size, must be a power of 2 and within [64B, 1GiB].
 * \param      distance    The output of the calculated distance
 * \param      similarity  The output of the calculated similarity
 *
 * \return     On error returns false, otherwise true.
 */
RZ_API bool rz_diff_lcs_rolling_distance(RZ_NONNULL const ut8 *a, ut32 la, RZ_NONNULL const ut8 *b, ut32 lb, ut32 block_size, RZ_NULLABLE ut32 *distance, RZ_NULLABLE double *similarity) {
	rz_return_val_if_fail(a && b, false);

	size_t diff_lcs = 0;
	size_t diff_length = 0;
	FastCDCChunker a_in = { 0 }, b_in = { 0 };
	FastCDCChunk a_chunk = { 0 }, b_chunk = { 0 };

	if (!rz_fastcdc_chunker_init2(&a_in, block_size, a, la) ||
		!rz_fastcdc_chunker_init2(&b_in, block_size, b, lb)) {
		rz_fastcdc_chunker_fini(&a_in);
		rz_fastcdc_chunker_fini(&b_in);

		return false;
	}

	while (1) {
		bool a_eof = !rz_fastcdc_chunker_next_chunk(&a_in, &a_chunk);
		bool b_eof = !rz_fastcdc_chunker_next_chunk(&b_in, &b_chunk);
		if (a_eof || b_eof) {
			diff_lcs += chunk_lcs(&a_chunk, &b_chunk);
			diff_length += a_chunk.length + b_chunk.length;
			break;
		} else if (a_chunk.fingerprint == b_chunk.fingerprint) {
			continue;
		}

		diff_lcs += chunk_lcs(&a_chunk, &b_chunk);
		diff_length += a_chunk.length + b_chunk.length;
	}

	rz_fastcdc_chunker_fini(&a_in);
	rz_fastcdc_chunker_fini(&b_in);

	if (distance) {
		*distance = diff_lcs;
	}
	if (similarity) {
		*similarity = diff_length ? 1.0 - (double)diff_lcs / diff_length : 1.0;
	}

	return true;
}

/**
 * \brief      Calculates the distance between two buffers using the Eugene W. Myers' O(ND) algorithm
 *
 * \param[in]  a           Buffer A to compare
 * \param[in]  la          Length of buffer A
 * \param[in]  a           Buffer B to compare
 * \param[in]  la          Length of buffer B
 * \param      distance    The output of the minimum number of edits needed to transform A into B
 * \param      similarity  The output of the calculated similarity
 *
 * \return     On error returns false, otherwise true.
 */
RZ_API bool rz_diff_myers_distance(RZ_NONNULL const ut8 *a, ut32 la, RZ_NONNULL const ut8 *b, ut32 lb, RZ_NULLABLE ut32 *distance, RZ_NULLABLE double *similarity) {
	rz_return_val_if_fail(a && b, false);

	const ut32 length = la + lb;
	const ut8 *ea = a + la, *eb = b + lb;

	for (; a < ea && b < eb && *a == *b; a++, b++) {
		// find the first mismatch from the left
	}
	for (; a < ea && b < eb && ea[-1] == eb[-1]; ea--, eb--) {
		// find the first mismatch from the right
	}
	la = ea - a;
	lb = eb - b;
	ut32 *v0, *v;
	st64 m = (st64)la + lb, di = 0, low, high, i, x, y;
	if (m + 2 > SIZE_MAX / sizeof(st64) || !(v0 = malloc((m + 2) * sizeof(ut32)))) {
		return false;
	}
	v = v0 + lb;
	v[1] = 0;
	for (di = 0; di <= m; di++) {
		low = -di + 2 * RZ_MAX(0, di - (st64)lb);
		high = di - 2 * RZ_MAX(0, di - (st64)la);
		for (i = low; i <= high; i += 2) {
			x = i == -di || (i != di && v[i - 1] < v[i + 1]) ? v[i + 1] : v[i - 1] + 1;
			y = x - i;
			while (x < la && y < lb && a[x] == b[y]) {
				x++;
				y++;
			}
			v[i] = x;
			if (x == la && y == lb) {
				goto out;
			}
		}
	}

out:
	free(v0);
	if (distance) {
		*distance = di;
	}
	if (similarity) {
		*similarity = length ? 1.0 - (double)di / length : 1.0;
	}
	return true;
}

/**
 * \brief      Calculates the distance between two buffers using the Levenshtein algorithm
 *
 * \param[in]  a           Buffer A to compare
 * \param[in]  la          Length of buffer A
 * \param[in]  a           Buffer B to compare
 * \param[in]  la          Length of buffer B
 * \param      distance    The output of the minimum number of edits needed to transform A into B
 * \param      similarity  The output of the calculated similarity
 *
 * \return     On error returns false, otherwise true.
 */
RZ_API bool rz_diff_levenshtein_distance(RZ_NONNULL const ut8 *a, ut32 la, RZ_NONNULL const ut8 *b, ut32 lb, RZ_NULLABLE ut32 *distance, RZ_NULLABLE double *similarity) {
	rz_return_val_if_fail(a && b, false);

	const ut32 length = RZ_MAX(la, lb);
	const ut8 *ea = a + la, *eb = b + lb, *t;
	ut32 *d, i, j;

	for (; a < ea && b < eb && *a == *b; a++, b++) {
		// find the first mismatch from the left
	}
	for (; a < ea && b < eb && ea[-1] == eb[-1]; ea--, eb--) {
		// find the first mismatch from the right
	}
	la = ea - a;
	lb = eb - b;
	if (la < lb) {
		i = la;
		la = lb;
		lb = i;
		t = a;
		a = b;
		b = t;
	}

	if (sizeof(ut32) > SIZE_MAX / (lb + 1) || !(d = malloc((lb + 1) * sizeof(ut32)))) {
		return false;
	}
	for (i = 0; i <= lb; i++) {
		d[i] = i;
	}
	for (i = 0; i < la; i++) {
		ut32 ul = d[0];
		d[0] = i + 1;
		for (j = 0; j < lb; j++) {
			ut32 u = d[j + 1];
			d[j + 1] = a[i] == b[j] ? ul : RZ_MIN(ul, RZ_MIN(d[j], u)) + 1;
			ul = u;
		}
	}

	if (distance) {
		*distance = d[lb];
	}
	if (similarity) {
		*similarity = length ? 1.0 - (double)d[lb] / length : 1.0;
	}
	free(d);
	return true;
}
