// SPDX-FileCopyrightText: 2025 Anton Angelov <anton.angelov@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_util.h>

/**
 * \file bench_bitvector.c
 * \brief Benchmark for `rz_bv_*` functions (currently `rz_bv_copy_nbits` only)
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

int main(RzTable *t_out) {
	RzTable *t = rz_table_new();
	rz_table_set_columnsf(t, "snnnn", "Benchmark", "Iterations", "Total time [ms]", "Average time [us/op]", "Throughput [ops/sec]");

	// Micro benchmarks
	bench_bv_copy_small_60_bit(t);
	bench_bv_copy_large_100_bit_aligned(t);
	bench_bv_copy_large_100_bit_unaligned(t);
	bench_bv_copy_large_to_small_60_bit(t);
	bench_bv_copy_small_to_large_60_bit(t);

	// Print results
	const char *out = rz_table_tostring(t);
	printf("%s\n", out);

	free(out);
	rz_table_free(t);
	return 0;
}
