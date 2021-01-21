#ifndef RZ_HEAP_JEMALLOC_H
#define RZ_HEAP_JEMALLOC_H

#include "rz_jemalloc/internal/jemalloc_internal.h"

#define INC_HEAP32 1
#include "rz_heap_jemalloc.h"
#undef INC_HEAP32
#endif

#undef GH
#undef GHT
#undef GHT_MAX

#if INC_HEAP32
#define GH(x)   x##_32
#define GHT     ut32
#define GHT_MAX UT32_MAX
#else
#define GH(x)   x##_64
#define GHT     ut64
#define GHT_MAX UT64_MAX
#endif

#define PRINTF_A(color, fmt, ...) rz_cons_printf(color fmt Color_RESET, __VA_ARGS__)
#define PRINTF_YA(fmt, ...)       PRINTF_A("%s", fmt, pal->offset, __VA_ARGS__)
#define PRINTF_GA(fmt, ...)       PRINTF_A("%s", fmt, pal->args, __VA_ARGS__)
#define PRINTF_BA(fmt, ...)       PRINTF_A("%s", fmt, pal->num, __VA_ARGS__)
#define PRINTF_RA(fmt, ...)       PRINTF_A("%s", fmt, pal->invalid, __VA_ARGS__)

#define PRINT_A(color, msg) rz_cons_print(color msg Color_RESET)
#define PRINT_YA(msg)       rz_cons_printf("%s" msg Color_RESET, pal->offset)
#define PRINT_GA(msg)       rz_cons_printf("%s" msg Color_RESET, pal->args)
#define PRINT_BA(msg)       rz_cons_printf("%s" msg Color_RESET, pal->num)
#define PRINT_RA(msg)       rz_cons_printf("%s" msg Color_RESET, pal->invalid)
