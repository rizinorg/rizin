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

RZ_API RZ_OWN RzBitmap *rz_bitmap_new(size_t len) {
	if (len < 1) {
		return NULL;
	}

	RzBitmap *b = RZ_NEW0(RzBitmap);
	if (!b) {
		return NULL;
	}

	b->bitmap = calloc(BITMAP_WORD_COUNT(len), sizeof(RBitword));
	if (!b->bitmap) {
		free(b);
		return NULL;
	}
	b->length = len;
	return b;
}

RZ_API void rz_bitmap_set_bytes(RZ_NONNULL RzBitmap *b, RZ_NONNULL const ut8 *buf, size_t len) {
	rz_return_if_fail(b && buf);
	if (b->length < len) {
		len = b->length;
	}
	memcpy(b->bitmap, buf, len);
}

RZ_API void rz_bitmap_free(RZ_NULLABLE RzBitmap *b) {
	if (!b) {
		return;
	}
	free(b->bitmap);
	free(b);
}

RZ_API void rz_bitmap_set(RZ_NONNULL RzBitmap *b, size_t bit) {
	rz_return_if_fail(b);
	if (bit < b->length) {
		b->bitmap[(bit >> BITWORD_BITS_SHIFT)] |=
			((RBitword)1 << (bit & BITWORD_BITS_MASK));
	}
}

RZ_API void rz_bitmap_unset(RZ_NONNULL RzBitmap *b, size_t bit) {
	rz_return_if_fail(b);
	if (bit < b->length) {
		b->bitmap[(bit >> BITWORD_BITS_SHIFT)] &=
			~((RBitword)1 << (bit & BITWORD_BITS_MASK));
	}
}

RZ_API int rz_bitmap_test(RZ_NONNULL RzBitmap *b, size_t bit) {
	rz_return_val_if_fail(b, -1);
	if (bit < b->length) {
		RBitword bword = b->bitmap[(bit >> BITWORD_BITS_SHIFT)];
		return BITWORD_TEST(bword, (bit & BITWORD_BITS_MASK));
	}
	return -1;
}
