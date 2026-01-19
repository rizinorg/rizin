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

	// Print results
	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
