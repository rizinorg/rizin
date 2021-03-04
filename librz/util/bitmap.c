// SPDX-FileCopyrightText: 2017-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2017-2020 crowell <crowell@bu.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

#define BITMAP_TEST 0

#define BITWORD_BITS       (sizeof(RBitword) * 8)
#define BITWORD_BITS_MASK  (BITWORD_BITS - 1)
#define BITWORD_MULT(bit)  (((bit) + (BITWORD_BITS_MASK)) & ~(BITWORD_BITS_MASK))
#define BITWORD_TEST(x, y) (((x) >> (y)) & 1)

#define BITMAP_WORD_COUNT(bit) (BITWORD_MULT(bit) >> BITWORD_BITS_SHIFT)

RZ_API RzBitmap *rz_bitmap_new(size_t len) {
	RzBitmap *b = RZ_NEW0(RzBitmap);
	if (!b) {
		return NULL;
	}
	b->length = len;
	b->bitmap = calloc(BITMAP_WORD_COUNT(len), sizeof(RBitword));
	return b;
}

RZ_API void rz_bitmap_set_bytes(RzBitmap *b, const ut8 *buf, int len) {
	if (b->length < len) {
		len = b->length;
	}
	memcpy(b->bitmap, buf, len);
}

RZ_API void rz_bitmap_free(RzBitmap *b) {
	free(b->bitmap);
	free(b);
}

RZ_API void rz_bitmap_set(RzBitmap *b, size_t bit) {
	if (bit < b->length) {
		b->bitmap[(bit >> BITWORD_BITS_SHIFT)] |=
			((RBitword)1 << (bit & BITWORD_BITS_MASK));
	}
}

RZ_API void rz_bitmap_unset(RzBitmap *b, size_t bit) {
	if (bit < b->length) {
		b->bitmap[(bit >> BITWORD_BITS_SHIFT)] &=
			~((RBitword)1 << (bit & BITWORD_BITS_MASK));
	}
}

RZ_API int rz_bitmap_test(RzBitmap *b, size_t bit) {
	if (bit < b->length) {
		RBitword bword = b->bitmap[(bit >> BITWORD_BITS_SHIFT)];
		return BITWORD_TEST(bword, (bit & BITWORD_BITS_MASK));
	}
	return -1;
}
