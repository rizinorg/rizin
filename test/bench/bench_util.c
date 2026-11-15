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

#define HEX_BYTES_N 1024

static ut8 *hex_gen_bytes(void) {
	ut8 *in = malloc(HEX_BYTES_N);
	for (int i = 0; i < HEX_BYTES_N; i++) {
		in[i] = (ut8)(i * 37);
	}
	return in;
}

static char *hex_gen_str(size_t nchars) {
	char *hex = malloc(nchars + 1);
	static const char digits[] = "0123456789abcdef";
	for (size_t i = 0; i < nchars; i++) {
		hex[i] = digits[(i * 13) & 0xf];
	}
	hex[nchars] = '\0';
	return hex;
}

static void bench_rz_hex_bin2str(RzTable *t_out) {
	ut8 *in = hex_gen_bytes();
	char *out = malloc(HEX_BYTES_N * 2 + 1);
	RZ_BENCH_RUN("rz_hex_bin2str 1KB", t_out, 3000, {
		RZ_DONT_OPTIMIZE(int, rz_hex_bin2str(in, HEX_BYTES_N, out));
	});
	free(in);
	free(out);
}

static void bench_rz_hex_bin2strdup(RzTable *t_out) {
	ut8 *in = hex_gen_bytes();
	RZ_BENCH_RUN("rz_hex_bin2strdup 1KB", t_out, 3000, {
		char *s = rz_hex_bin2strdup(in, HEX_BYTES_N);
		free(s);
	});
	free(in);
}

static void bench_rz_hex_str2bin(RzTable *t_out) {
	char *hex = hex_gen_str(HEX_BYTES_N * 2);
	ut8 *out = malloc(HEX_BYTES_N + 16);
	RZ_BENCH_RUN("rz_hex_str2bin 2048 chars", t_out, 3000, {
		RZ_DONT_OPTIMIZE(int, rz_hex_str2bin(hex, out));
	});
	free(hex);
	free(out);
}

static void bench_rz_hex_str2bin_msb(RzTable *t_out) {
	char *hex2k = hex_gen_str(HEX_BYTES_N * 2);
	ut8 *out = malloc(HEX_BYTES_N * 4 + 16);
	RZ_BENCH_RUN("rz_hex_str2bin_msb 2048 chars", t_out, 1000, {
		RZ_DONT_OPTIMIZE(int, rz_hex_str2bin_msb(hex2k, out));
	});
	free(hex2k);

	char *hex8k = hex_gen_str(HEX_BYTES_N * 8);
	RZ_BENCH_RUN("rz_hex_str2bin_msb 8192 chars", t_out, 200, {
		RZ_DONT_OPTIMIZE(int, rz_hex_str2bin_msb(hex8k, out));
	});
	free(hex8k);
	free(out);
}

int main() {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	// Micro benchmarks
	bench_rz_bits_trailing_zeros(t);

	bench_rz_hex_bin2str(t);
	bench_rz_hex_bin2strdup(t);
	bench_rz_hex_str2bin(t);
	bench_rz_hex_str2bin_msb(t);

	// Print results
	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
