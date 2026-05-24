// SPDX-FileCopyrightText: 2025 Anton Angelov <anton.angelov@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"

/**
 * \brief Initialize benchmark context
 */
RZ_API void rz_bench_init(RZ_NONNULL RzBenchCtx *ctx, RZ_NONNULL const char *name, ut64 iterations) {
	rz_return_if_fail(ctx && name);
	ctx->name = name;
	ctx->iterations = iterations;
	ctx->start_time = 0;
	ctx->total_time = 0;
}

/**
 * \brief Start timing a benchmark
 */
RZ_API void rz_bench_start(RZ_NONNULL RzBenchCtx *ctx) {
	rz_return_if_fail(ctx);
	ctx->start_time = rz_time_now_mono();
}

/**
 * \brief End timing a benchmark
 */
RZ_API void rz_bench_end(RZ_NONNULL RzBenchCtx *ctx) {
	rz_return_if_fail(ctx);
	ctx->total_time = rz_time_now_mono() - ctx->start_time;
}

/**
 * \brief Print benchmark results
 */
RZ_API void rz_bench_report(RZ_NONNULL RzBenchCtx *ctx, RZ_NONNULL RzTable *t) {
	rz_return_if_fail(ctx && t);

	double total_ms = ctx->total_time / 1000.0;
	double ops_per_sec = ctx->total_time != 0 ? (ctx->iterations * 1000000.0) / ctx->total_time : 0;

	rz_table_add_rowf(t, "sdffff", ctx->name, (int)ctx->iterations, total_ms, ctx->arith_mean_us, ops_per_sec, ctx->arith_std_dev);
}
