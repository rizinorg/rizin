// SPDX-FileCopyrightText: 2025 Anton Angelov <anton.angelov@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_util.h>

/**
 * \file bench_bitvector.c
 * \brief Benchmark for `rz_bv_*` functions
 *
 * Tests various copy scenarios to measure performance of optimized paths
 */

static void bench_bv_copy_small_60_bit(RzTable *t_out) {
	RzBitVector *src = rz_bv_new_from_ut64(64, 0x1122334455667788ULL);
	RzBitVector *dst = rz_bv_new_from_ut64(64, 0);

	RZ_BENCH_RUN("rz_bv_copy_nbits: small to small (60 bit)", t_out, 1000000, {
		rz_bv_copy_nbits(src, 2, dst, 2, 60);
	});

	rz_bv_free(src);
	rz_bv_free(dst);
}

static void bench_bv_copy_large_100_bit_aligned(RzTable *t_out) {
	RzBitVector *src = rz_bv_new_from_ut64(128, 0);
	RzBitVector *dst = rz_bv_new_from_ut64(128, 0);

	for (int i = 0; i < src->len; i++) {
		rz_bv_set(src, i, i % 2 == 0 ? true : false);
	}

	RZ_BENCH_RUN("rz_bv_copy_nbits: large to large (100 bit) aligned", t_out, 1000000, {
		rz_bv_copy_nbits(src, 0, dst, 0, 100);
	});

	rz_bv_free(src);
	rz_bv_free(dst);
}

static void bench_bv_copy_large_100_bit_unaligned(RzTable *t_out) {
	RzBitVector *src = rz_bv_new_from_ut64(128, 0);
	RzBitVector *dst = rz_bv_new_from_ut64(128, 0);

	for (int i = 0; i < src->len; i++) {
		rz_bv_set(src, i, i % 2 == 0 ? true : false);
	}

	RZ_BENCH_RUN("rz_bv_copy_nbits: large to large (100 bit) unaligned", t_out, 1000000, {
		rz_bv_copy_nbits(src, 2, dst, 3, 100);
	});

	rz_bv_free(src);
	rz_bv_free(dst);
}

static void bench_bv_copy_small_to_large_60_bit(RzTable *t_out) {
	RzBitVector *src = rz_bv_new_from_ut64(64, 0x1122334455667788ULL);
	RzBitVector *dst = rz_bv_new_from_ut64(128, 0);

	RZ_BENCH_RUN("rz_bv_copy_nbits: small to large (60 bit)", t_out, 1000000, {
		rz_bv_copy_nbits(src, 2, dst, 3, 60);
	});

	rz_bv_free(src);
	rz_bv_free(dst);
}

static void bench_bv_copy_large_to_small_60_bit(RzTable *t_out) {
	RzBitVector *src = rz_bv_new_from_ut64(128, 0x1122334455667788ULL);
	RzBitVector *dst = rz_bv_new_from_ut64(64, 0);

	RZ_BENCH_RUN("rz_bv_copy_nbits: large to small (60 bit)", t_out, 1000000, {
		rz_bv_copy_nbits(src, 2, dst, 3, 60);
	});

	rz_bv_free(src);
	rz_bv_free(dst);
}

static void bench_bv_set_range_60_bit(RzTable *t_out) {
	RzBitVector *a = rz_bv_new(64);

	RZ_BENCH_RUN("rz_bv_set_range (60 bit)", t_out, 1000000, {
		rz_bv_set_range(a, 1, 60, true);
	});

	rz_bv_free(a);
}

static void bench_bv_set_range_100_bit(RzTable *t_out) {
	RzBitVector *a = rz_bv_new(128);

	RZ_BENCH_RUN("rz_bv_set_range (100 bit)", t_out, 1000000, {
		rz_bv_set_range(a, 1, 100, true);
	});

	rz_bv_free(a);
}

static void bench_bv_add_inplace_64(RzTable *t_out) {
	RzBitVector *a = rz_bv_new_from_ut64(64, 0x1122334455667788ULL);
	RzBitVector *b = rz_bv_new_from_ut64(64, 0x1122334455667799ULL);

	RZ_BENCH_RUN("rz_bv_add_inplace(a, b, NULL) - (64 bit)", t_out, 1000000, {
		rz_bv_add_inplace(a, b, NULL);
	});

	rz_bv_free(a);
	rz_bv_free(b);
}

static void bench_bv_add_inplace_256(RzTable *t_out) {
	RzBitVector *a = rz_bv_new_from_ut64(256, 0x1122334455667788ULL);
	RzBitVector *b = rz_bv_new_from_ut64(256, 0x1122334455667799ULL);

	RZ_BENCH_RUN("rz_bv_add_inplace(a, b, NULL) - (256 bit)", t_out, 1000000, {
		rz_bv_add_inplace(a, b, NULL);
	});

	rz_bv_free(a);
	rz_bv_free(b);
}

static void bench_bv_add(RzTable *t_out) {
	RzBitVector *a = rz_bv_new_from_ut64(64, 0x1122334455667788ULL);
	RzBitVector *b = rz_bv_new_from_ut64(64, 0x1122334455667799ULL);

	RZ_BENCH_RUN("rz_bv_add(a, b, NULL) - (64 bit)", t_out, 1000000, {
		RzBitVector *a_prev = a;
		a = rz_bv_add(a, b, NULL);
		rz_bv_free(a_prev);
	});

	rz_bv_free(a);
	rz_bv_free(b);
}

static void bench_bv_sub_inplace(RzTable *t_out) {
	RzBitVector *a = rz_bv_new_from_ut64(64, 0x1122334455667788ULL);
	RzBitVector *b = rz_bv_new_from_ut64(64, 0x11);

	RZ_BENCH_RUN("rz_bv_sub_inplace(a, b, NULL)", t_out, 1000000, {
		rz_bv_sub_inplace(a, b, NULL);
	});

	rz_bv_free(a);
	rz_bv_free(b);
}

static void bench_bv_sub(RzTable *t_out) {
	RzBitVector *a = rz_bv_new_from_ut64(64, 0x1122334455667788ULL);
	RzBitVector *b = rz_bv_new_from_ut64(64, 0x11);

	RZ_BENCH_RUN("rz_bv_sub(a, b, NULL)", t_out, 1000000, {
		RzBitVector *a_prev = a;
		a = rz_bv_sub(a, b, NULL);
		rz_bv_free(a_prev);
	});

	rz_bv_free(a);
	rz_bv_free(b);
}

static void bench_bv_to_ut(RzTable *t_out) {
	static const ut8 pattern[20] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x5a, 0xa5, 0xc3, 0x3c
	};
	RzBitVector *bvs[4];
	for (size_t k = 0; k < RZ_ARRAY_SIZE(bvs); k++) {
		bvs[k] = rz_bv_new(128);
		rz_bv_set_from_bytes_le(bvs[k], pattern, (ut32)k, 128);
	}

	volatile ut64 sink = 0;
#define BENCH_BV_TO_UT(fn) \
	RZ_BENCH_RUN(#fn " (128 bit, 1000 calls/iter)", t_out, 10000, { \
		for (ut32 j = 0; j < 1000; j++) { \
			sink += fn(bvs[j & 3]); \
		} \
	})

	BENCH_BV_TO_UT(rz_bv_to_ut8);
	BENCH_BV_TO_UT(rz_bv_to_ut16);
	BENCH_BV_TO_UT(rz_bv_to_ut32);
	BENCH_BV_TO_UT(rz_bv_to_ut64);

#undef BENCH_BV_TO_UT
	(void)sink;
	for (size_t k = 0; k < RZ_ARRAY_SIZE(bvs); k++) {
		rz_bv_free(bvs[k]);
	}
}

int main() {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	// Micro benchmarks
	bench_bv_copy_small_60_bit(t);
	bench_bv_copy_large_100_bit_aligned(t);
	bench_bv_copy_large_100_bit_unaligned(t);
	bench_bv_copy_large_to_small_60_bit(t);
	bench_bv_copy_small_to_large_60_bit(t);
	bench_bv_set_range_60_bit(t);
	bench_bv_set_range_100_bit(t);
	bench_bv_add(t);
	bench_bv_add_inplace_64(t);
	bench_bv_add_inplace_256(t);
	bench_bv_sub(t);
	bench_bv_sub_inplace(t);
	bench_bv_to_ut(t);

	// Print results
	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
