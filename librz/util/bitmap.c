// SPDX-FileCopyrightText: 2017-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2017-2020 crowell <crowell@bu.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

RZ_API RZ_OWN RzBitmap *rz_bitmap_new(size_t len) {
	RzBitVector *bv = rz_bv_new(len);
	if (!bv) {
		return NULL;
	}
	RzBitmap *b = RZ_NEW0(RzBitmap);
	b->bv = bv;
	return b;
}

RZ_API void rz_bitmap_set_bytes(RZ_NONNULL RzBitmap *b, RZ_NONNULL const ut8 *buf, size_t len) {
	rz_return_if_fail(b && buf);
	rz_bv_set_from_bytes_le(b->bv, buf, 0, len);
}

RZ_API void rz_bitmap_free(RZ_NULLABLE RzBitmap *b) {
	if (!b || !b->bv) {
		return;
	}
	free(b->bv);
	free(b);
}

RZ_API void rz_bitmap_set(RZ_NONNULL RzBitmap *b, size_t bit) {
	rz_return_if_fail(b);
	rz_bv_set(b->bv, bit, true);
}

RZ_API void rz_bitmap_unset(RZ_NONNULL RzBitmap *b, size_t bit) {
	rz_return_if_fail(b);
	rz_bv_set(b->bv, bit, false);
}

RZ_API int rz_bitmap_test(RZ_NONNULL RzBitmap *b, size_t bit) {
	rz_return_val_if_fail(b && bit >= 0, -1);
	return rz_bv_get(b->bv, bit);
}
