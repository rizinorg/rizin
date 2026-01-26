// SPDX-FileCopyrightText: 2025 Anton Angelov <anton.angelov@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_util.h>
#include <rz_il.h>

/**
 * \file bench_mem.c
 * \brief Benchmark for `rz_il_*` functions
 */

static void bench_rz_il_mem_loadw(const char *title, RzTable *t_out, ut32 bit_size, bool big_endian) {
	RzBuffer *buf = rz_buf_new_empty(bit_size);
	RzILMem *mem = rz_il_mem_new(buf, 64);
	RzBitVector *key = rz_bv_new_from_ut64(64, 0x12345678abcdef);

	RZ_BENCH_RUN(title, t_out, 1000000, {
		RzBitVector *word = rz_il_mem_loadw(mem, key, bit_size, big_endian);
		rz_bv_free(word);
	});

	rz_bv_free(key);
	rz_il_mem_free(mem);
	rz_buf_free(buf);
}

int main() {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	// Micro benchmarks
	bench_rz_il_mem_loadw("bench_rz_il_mem_loadw: big endian (64 bit)", t, 64, true);
	bench_rz_il_mem_loadw("bench_rz_il_mem_loadw: little endian (64 bit)", t, 64, false);
	bench_rz_il_mem_loadw("bench_rz_il_mem_loadw: big endian (256 bit)", t, 256, true);
	bench_rz_il_mem_loadw("bench_rz_il_mem_loadw: little endian (256 bit)", t, 256, false);

	// Print results
	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
