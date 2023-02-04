// SPDX-FileCopyrightText: 2017-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2017-2020 crowell <crowell@bu.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

#define BITMAP_TEST 0

#if RZ_SYS_BITS == 4
#define bitword_read  rz_read_le32
#define bitword_write rz_write_le32
#else
#define bitword_read  rz_read_le64
#define bitword_write rz_write_le64
#endif

#define BITWORD_BITS       (sizeof(RzBitword) * 8)
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

	b->bitmap = calloc(BITMAP_WORD_COUNT(len), sizeof(RzBitword));
	if (!b->bitmap) {
		free(b);
		return NULL;
	}
	b->length = len;
	return b;
}

RZ_API void rz_bitmap_set_bytes(RZ_NONNULL RzBitmap *b, RZ_NONNULL const ut8 *buf, size_t len) {
	rz_return_if_fail(b && buf);
	size_t blen = b->length << BITWORD_BITS_SHIFT;
	if (blen < len) {
		len = blen;
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
		const size_t pos = bit >> BITWORD_BITS_SHIFT;
		RzBitword value = bitword_read(&b->bitmap[pos]);
		value |= ((RzBitword)1 << (bit & BITWORD_BITS_MASK));
		bitword_write(&b->bitmap[pos], value);
	}
}

RZ_API void rz_bitmap_unset(RZ_NONNULL RzBitmap *b, size_t bit) {
	rz_return_if_fail(b);
	if (bit < b->length) {
		const size_t pos = bit >> BITWORD_BITS_SHIFT;
		RzBitword value = bitword_read(&b->bitmap[pos]);
		value &= ~((RzBitword)1 << (bit & BITWORD_BITS_MASK));
		bitword_write(&b->bitmap[pos], value);
	}
}

RZ_API int rz_bitmap_test(RZ_NONNULL RzBitmap *b, size_t bit) {
	rz_return_val_if_fail(b && bit >= 0, -1);
	if (bit < b->length) {
		const size_t pos = bit >> BITWORD_BITS_SHIFT;
		RzBitword bword = bitword_read(&b->bitmap[pos]);
		return BITWORD_TEST(bword, (bit & BITWORD_BITS_MASK));
	}
	return -1;
}
