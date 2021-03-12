// SPDX-FileCopyrightText: 2007-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#if 0

From Wikipedia, the free encyclopedia

In information theory, the Hamming distance between two strings of equal
length is the number of positions for which the corresponding symbols
are different. Put another way, it measures the minimum number of
substitutions required to change one into the other, or the number of
errors that transformed one string into the other.

#endif

#include "rz_types.h"

static int hamdist(int x, int y) {
	int dist = 0, val = x ^ y;
	while (val) {
		dist++;
		val &= val - 1;
	}
	return dist;
}

RZ_API ut8 rz_hash_hamdist(const ut8 *buf, int len) {
	int i, x, y;
	x = 0;
	for (i = 0; i < len; i++) {
		y = buf[i];
		x = hamdist(x, y);
	}
	return x;
}
