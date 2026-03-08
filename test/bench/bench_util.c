// SPDX-FileCopyrightText: 2026 Anton Angelov <anton.angelov@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_util.h>

/**
 * \file bench_util.c
 * \brief Benchmarks for `rz_util` functions
 */

static void bench_rz_bits_trailing_zeros(RzTable *t_out) {
	ut64 v = 0;

	RZ_BENCH_RUN("bench_rz_bits_trailing_zeros", t_out, 5000000, {
		RZ_DONT_OPTIMIZE(size_t, rz_bits_trailing_zeros(v++));
	});
}

int main() {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	// Micro benchmarks
	bench_rz_bits_trailing_zeros(t);

	// Print results
	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
