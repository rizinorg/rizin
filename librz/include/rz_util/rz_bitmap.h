#ifndef RZ_BITMAP_H
#define RZ_BITMAP_H

#include <rz_types.h>

#if RZ_SYS_BITS == 4
#define BITWORD_BITS_SHIFT 5
#define RBitword           ut32
#else
#define BITWORD_BITS_SHIFT 6
#define RBitword           ut64
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_bitmap_t {
	size_t length;
	RBitword *bitmap;
} RzBitmap;

RZ_API RZ_OWN RzBitmap *rz_bitmap_new(size_t len);
RZ_API void rz_bitmap_set_bytes(RZ_NONNULL RzBitmap *b, RZ_NONNULL const ut8 *buf, size_t len);
RZ_API void rz_bitmap_free(RZ_NULLABLE RzBitmap *b);
RZ_API void rz_bitmap_set(RZ_NONNULL RzBitmap *b, size_t bit);
RZ_API void rz_bitmap_unset(RZ_NONNULL RzBitmap *b, size_t bit);
RZ_API int rz_bitmap_test(RZ_NONNULL RzBitmap *b, size_t bit);

#ifdef __cplusplus
}
#endif

#endif //  RZ_BITMAP_H
