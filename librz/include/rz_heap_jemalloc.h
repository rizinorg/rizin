#ifndef RZ_HEAP_JEMALLOC_H
#define RZ_HEAP_JEMALLOC_H

#include <rz_jemalloc/internal/jemalloc_internal.h>

#define INC_HEAP32 1
#include "rz_heap_jemalloc.h"
#undef INC_HEAP32

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

#undef PRINTF_A
#undef PRINTF_YA
#undef PRINTF_GA
#undef PRINTF_BA
#undef PRINTF_RA

#define PRINTF_A(color, fmt, ...) rz_cons_printf("%s" fmt "%s", \
	rz_config_get_b(core->config, "scr.color") ? color : "", \
	__VA_ARGS__, \
	rz_config_get_b(core->config, "scr.color") ? Color_RESET : "")
#define PRINTF_YA(fmt, ...) PRINTF_A(pal->offset, fmt, __VA_ARGS__)
#define PRINTF_GA(fmt, ...) PRINTF_A(pal->args, fmt, __VA_ARGS__)
#define PRINTF_BA(fmt, ...) PRINTF_A(pal->num, fmt, __VA_ARGS__)
#define PRINTF_RA(fmt, ...) PRINTF_A(pal->invalid, fmt, __VA_ARGS__)

#define PRINT_A(color, msg) rz_cons_printf("%s%s%s", \
	rz_config_get_b(core->config, "scr.color") ? color : "", \
	msg, \
	rz_config_get_b(core->config, "scr.color") ? Color_RESET : "")
#define PRINT_YA(msg) PRINT_A(pal->offset, msg)
#define PRINT_GA(msg) PRINT_A(pal->args, msg)
#define PRINT_BA(msg) PRINT_A(pal->num, msg)
#define PRINT_RA(msg) PRINT_A(pal->invalid, msg)

#endif
