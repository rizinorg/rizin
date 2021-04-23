// SPDX-FileCopyrightText: 2009 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdlib.h>
#include <math.h>
#include "rz_types.h"

RZ_API double rz_hash_entropy(const ut8 *data, ut64 size) {
	if (!data || !size) {
		return 0;
	}
	ut64 i, count[256] = { 0 };
	double h = 0;
	for (i = 0; i < size; i++) {
		count[data[i]]++;
	}
	for (i = 0; i < 256; i++) {
		if (count[i]) {
			double p = (double)count[i] / size;
			h -= p * log2(p);
		}
	}
	return h;
}

RZ_API double rz_hash_entropy_fraction(const ut8 *data, ut64 size) {
	if (size) {
		return rz_hash_entropy(data, size) / log2((double)RZ_MIN(size, 256));
	}
	return 0;
}
