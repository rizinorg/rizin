// SPDX-FileCopyrightText: 2013-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>

RZ_API ut32 rz_hash_adler32(const ut8 *data, int len) {
	static const int MOD_ADLER = 65521;
	ut32 a = 1, b = 0;
	int index;
	for (index = 0; index < len; index++) {
		a = (a + data[index]) % MOD_ADLER;
		b = (b + a) % MOD_ADLER;
	}
	return (b << 16) | a;
}
