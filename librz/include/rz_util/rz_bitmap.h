#ifndef RZ_BITMAP_H
#define RZ_BITMAP_H

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
	int length;
	RBitword *bitmap;
} RzBitmap;

RZ_API RzBitmap *rz_bitmap_new(size_t len);
RZ_API void rz_bitmap_set_bytes(RzBitmap *b, const ut8 *buf, int len);
RZ_API void rz_bitmap_free(RzBitmap *b);
RZ_API void rz_bitmap_set(RzBitmap *b, size_t bit);
RZ_API void rz_bitmap_unset(RzBitmap *b, size_t bit);
RZ_API int rz_bitmap_test(RzBitmap *b, size_t bit);

#ifdef __cplusplus
}
#endif

#endif //  RZ_BITMAP_H
