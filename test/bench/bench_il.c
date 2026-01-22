// SPDX-FileCopyrightText: 2025 Anton Angelov <anton.angelov@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_util.h>
#include <rz_il.h>

/**
 * \file bench_mem.c
 * \brief Benchmark for `rz_il_*` functions
 */

// todo: delete..
static bool read_n_bits_into(RzBuffer *mem_buf, RZ_OUT RzBitVector *out_bv, ut32 n_bits, const RzBitVector *key, bool big_endian) {
	ut64 address = rz_bv_to_ut64(key);
	size_t n_bytes = rz_bv_len_bytes(out_bv);

	// ut8 *data = calloc(n_bytes, 1);
	// if (!data) {
	// 	return false;
	// }
	// // we ignore bad reads. RzBuffer fills up with its "overflow byte" on failure.
	// rz_buf_read_at(mem_buf, address, data, n_bytes);
	// if (big_endian) {
	// 	rz_bv_set_from_bytes_be(out_bv, data, 0, n_bits);
	// } else {
	// 	rz_bv_set_from_bytes_le(out_bv, data, 0, n_bits);
	// }
	// free(data);

	rz_buf_seek(mem_buf, address, RZ_BUF_SET);
	rz_bv_set_from_buffer_ble(out_bv, mem_buf, n_bytes, big_endian);
	return true;
}

static void bench_read_n_bits_into(const char *title, RzTable *t_out, ut32 bit_size, bool big_endian) {
	RzBuffer *buf = rz_buf_new_empty(bit_size);
	RzILMem *mem = rz_il_mem_new(buf, 64);
	RzBitVector *key = rz_bv_new_from_ut64(64, 0x12345678abcdef);
	RzBitVector *word = rz_bv_new(bit_size);

	RZ_BENCH_RUN(title, t_out, 1000000, {
		read_n_bits_into(buf, word, bit_size, key, big_endian);
	});

	rz_bv_free(word);
	rz_bv_free(key);
	rz_il_mem_free(mem);
	rz_buf_free(buf);
}
// todo: delete ^

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

	bench_read_n_bits_into("bench_read_n_bits_into: big endian (64 bit)", t, 64, true);
	bench_read_n_bits_into("bench_read_n_bits_into: little endian (64 bit)", t, 64, false);
	bench_read_n_bits_into("bench_read_n_bits_into: big endian (256 bit)", t, 256, true);
	bench_read_n_bits_into("bench_read_n_bits_into: little endian (256 bit)", t, 256, false);

	// Print results
	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
