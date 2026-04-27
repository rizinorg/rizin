// SPDX-FileCopyrightText: 2025 Anton Angelov <anton.angelov@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef BENCH_UTILS_H
#define BENCH_UTILS_H

#include <rz_types.h>
#include <rz_util.h>

/**
 * \brief Description of the state of a micro benchmark
 */
typedef struct rz_bench_ctx_t {
	const char *name; ///< name of a micro benchmark
	ut64 iterations; ///< number of iterations
	ut64 start_time; ///< start time of the benchmark in microseconds
	ut64 total_time; ///< total elapsed time of the benchmark in microseconds
} RzBenchCtx;

RZ_API void rz_bench_init(RZ_NONNULL RzBenchCtx *ctx, RZ_NONNULL const char *name, ut64 iterations);
RZ_API void rz_bench_start(RZ_NONNULL RzBenchCtx *ctx);
RZ_API void rz_bench_end(RZ_NONNULL RzBenchCtx *ctx);
RZ_API void rz_bench_report(RZ_NONNULL RzBenchCtx *ctx, RZ_NONNULL RzTable *t);

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

#define RZ_BENCH_RUN_I(name, i, table, iterations, code) \
	do { \
		RzBenchCtx ctx; \
		rz_bench_init(&ctx, name, iterations); \
		rz_bench_start(&ctx); \
		for (ut64(i) = 0; (i) < iterations; (i)++) { \
			code; \
		} \
		rz_bench_end(&ctx); \
		rz_bench_report(&ctx, table); \
	} while (0)

/**
 * \brief Initializes the RzTable \p T used for storing results of microbenchmarks.
 * \param T table to initialize.
 */
#define RZ_BENCH_TABLE_INIT(T) \
	rz_table_set_columnsf(T, "snnnn", "Benchmark", "Iterations", "Total time [ms]", "Avg iter time [us/iteration]", "Throughput [iterations/sec]");

/**
 * \brief Prints microbenchmark results and frees the RzTable \p T. Should be called at end of a benchmark suite.
 * \param T table to print and free.
 */
#define RZ_BENCH_TABLE_PRINT_AND_FREE(T) \
	char *table_out = rz_table_tostring(T); \
	printf("%s\n", table_out); \
	free(table_out); \
	rz_table_free(T);

#if defined(__GNUC__) || defined(__clang__)
/**
 * \def Helper macro to prevent compiler optimizations on benchmarked code.
 * \param type Return type of the expression \p x.
 * \param x Function or code to be executed.
 */
#define RZ_DONT_OPTIMIZE(type, x) \
	do { \
		type tmp_ = (x); \
		__asm__ volatile("" : : "r,m"(tmp_) : "memory"); \
	} while (0)
#elif defined(_MSC_VER)
#include <intrin.h>
#define RZ_DONT_OPTIMIZE(type, x) \
	do { \
		type tmp_ = (x); \
		_WriteBarrier(); \
		*(volatile char *)&tmp_; \
		_ReadBarrier(); \
	} while (0)
#else
// Fallback
#define RZ_DONT_OPTIMIZE(type, x) \
	do { \
		volatile type tmp_ = (x); \
		(void)tmp_; \
	} while (0)
#endif

#endif // BENCH_UTILS_H
