// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>

// Allow re-entry for 32-bit pass
#if !defined(RZ_HEAP_JEMALLOC_H_TYPES) || defined(INC_HEAP32)

#ifndef INC_HEAP32
// First pass: 64-bit
#define GH(x) x##_64
typedef ut64 __attribute__((aligned(8))) GHT_64;
typedef st64 __attribute__((aligned(8))) GHST_64;
#define GHT      GHT_64
#define GHT_MAX  UT64_MAX
#define GHST     GHST_64
#define GH_IS_64 1
#else
// Second pass: 32-bit
#undef GH
#undef GHT
#undef GHT_MAX
#undef GHST
#undef GH_IS_64
#define GH(x)   x##_32
typedef ut32 __attribute__((aligned(4))) GHT_32;
typedef st32 __attribute__((aligned(4))) GHST_32;
#define GHT     GHT_32
#define GHT_MAX UT32_MAX
#define GHST    GHST_32
#endif

#include <rz_jemalloc/jemalloc.h>

#ifndef INC_HEAP32
#undef JEMALLOC_INTERNAL_H
#define INC_HEAP32 1
#include "rz_heap_jemalloc.h"
#undef INC_HEAP32
#define RZ_HEAP_JEMALLOC_H_TYPES
#endif

#endif // RZ_HEAP_JEMALLOC_H_TYPES

#ifndef RZ_HEAP_JEMALLOC_H
#define RZ_HEAP_JEMALLOC_H

#undef PRINTF_A
#undef PRINTF_YA
#undef PRINTF_GA
#undef PRINTF_BA
#undef PRINTF_RA

#define PRINTF_A(color, fmt, ...) \
	do { \
		if ((color) && rz_config_get_i(core->config, "scr.color") > 0) { \
			rz_cons_print(color); \
		} \
		rz_cons_printf(fmt, __VA_ARGS__); \
		if ((color) && rz_config_get_i(core->config, "scr.color") > 0) { \
			rz_cons_print(Color_RESET); \
		} \
	} while (0)
#define PRINTF_YA(fmt, ...) PRINTF_A(pal->offset, fmt, __VA_ARGS__)
#define PRINTF_GA(fmt, ...) PRINTF_A(pal->args, fmt, __VA_ARGS__)
#define PRINTF_BA(fmt, ...) PRINTF_A(pal->num, fmt, __VA_ARGS__)
#define PRINTF_RA(fmt, ...) PRINTF_A(pal->invalid, fmt, __VA_ARGS__)

#undef PRINT_A
#undef PRINT_YA
#undef PRINT_GA
#undef PRINT_BA
#undef PRINT_RA

#define PRINT_A(color, msg) \
	do { \
		if ((color) && rz_config_get_i(core->config, "scr.color") > 0) { \
			rz_cons_print(color); \
		} \
		rz_cons_print(msg); \
		if ((color) && rz_config_get_i(core->config, "scr.color") > 0) { \
			rz_cons_print(Color_RESET); \
		} \
	} while (0)
#define PRINT_YA(msg) PRINT_A(pal->offset, msg)
#define PRINT_GA(msg) PRINT_A(pal->args, msg)
#define PRINT_BA(msg) PRINT_A(pal->num, msg)
#define PRINT_RA(msg) PRINT_A(pal->invalid, msg)

#endif
