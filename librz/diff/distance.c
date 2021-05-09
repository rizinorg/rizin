// SPDX-FileCopyrightText: 2017 Fangrui Song <i@maskray.me>
// SPDX-FileCopyrightText: 2016 NikolaiHampton <nikolaih@3583bytesready.net>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_diff.h>
#include <rz_util/rz_assert.h>

// Eugene W. Myers' O(ND) diff algorithm
// Returns edit distance with costs: insertion=1, deletion=1, no substitution
RZ_API bool rz_diff_myers_distance(const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity) {
	rz_return_val_if_fail(a && b, false);

	const ut32 length = la + lb;
	const ut8 *ea = a + la, *eb = b + lb;
	// Strip prefix
	for (; a < ea && b < eb && *a == *b; a++, b++) {
	}
	// Strip suffix
	for (; a < ea && b < eb && ea[-1] == eb[-1]; ea--, eb--) {
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
	//Clean up output on loop exit (purely aesthetic)
	if (distance) {
		*distance = di;
	}
	if (similarity) {
		*similarity = length ? 1.0 - (double)di / length : 1.0;
	}
	return true;
}

RZ_API bool rz_diff_levenstein_distance(const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity) {
	rz_return_val_if_fail(a && b, false);

	const ut32 length = RZ_MAX(la, lb);
	const ut8 *ea = a + la, *eb = b + lb, *t;
	ut32 *d, i, j;
	// Strip prefix
	for (; a < ea && b < eb && *a == *b; a++, b++) {
	}
	// Strip suffix
	for (; a < ea && b < eb && ea[-1] == eb[-1]; ea--, eb--) {
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
