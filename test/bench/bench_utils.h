// SPDX-FileCopyrightText: 2025 Anton Angelov <anton.angelov@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef BENCH_UTILS_H
#define BENCH_UTILS_H

#include <rz_types.h>
#include <rz_util.h>

typedef struct rz_bench_ctx_t {
	const char *name;
	ut64 iterations;
	ut64 start_time;
	ut64 total_time;
} RzBenchCtx;

RZ_API void rz_bench_init(RZ_NONNULL RzBenchCtx *ctx, RZ_NONNULL const char *name, ut64 iterations);
RZ_API void rz_bench_start(RZ_NONNULL RzBenchCtx *ctx);
RZ_API void rz_bench_end(RZ_NONNULL RzBenchCtx *ctx);
RZ_API void rz_bench_report(RZ_NONNULL RzBenchCtx *ctx, RzTable *t);

/**
 * \brief Run a benchmark with the given code block
 *
 * Example usage:
 * \code
 * RZ_BENCH_RUN("my_function", table, 1000000, {
 *     my_function(data);
 * });
 * \endcode
 */
#define RZ_BENCH_RUN(name, table, iterations, code) \
	do { \
		RzBenchCtx ctx; \
		rz_bench_init(&ctx, name, iterations); \
		rz_bench_start(&ctx); \
		for (ut64 i = 0; i < iterations; i++) { \
			code; \
		} \
		rz_bench_end(&ctx); \
		rz_bench_report(&ctx, table); \
	} while (0)

#endif // BENCH_UTILS_H
