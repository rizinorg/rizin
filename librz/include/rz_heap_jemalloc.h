// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_HEAP_JEMALLOC_H
#define RZ_HEAP_JEMALLOC_H

#include <rz_jemalloc/jemalloc_arch.h>
#include <rz_jemalloc/jemalloc_450.h>
#include <rz_jemalloc/jemalloc_530.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_types.h>

// Undefine any previous definitions from rz_heap_glibc.h
#undef PRINTF_A
#undef PRINTF_YA
#undef PRINTF_GA
#undef PRINTF_BA
#undef PRINTF_RA
#undef PRINT_A
#undef PRINT_YA
#undef PRINT_GA
#undef PRINT_BA
#undef PRINT_RA

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

RZ_IPI RzCmdStatus rz_heap_jemalloc_cmd_a(RzCore *core, bool has_specified_addr, ut64 addr);
RZ_IPI RzCmdStatus rz_heap_jemalloc_cmd_b(RzCore *core, bool has_specified_addr, ut64 addr, bool has_bin_info, ut64 bin_info_addr);
RZ_IPI RzCmdStatus rz_heap_jemalloc_cmd_c(RzCore *core, bool has_specified_addr, ut64 addr);
RZ_IPI RzCmdStatus rz_heap_jemalloc_cmd_e(RzCore *core, bool has_specified_addr, ut64 addr);
RZ_IPI RzCmdStatus rz_heap_jemalloc_cmd_ei(RzCore *core, bool has_specified_addr, ut64 addr);

#endif // RZ_HEAP_JEMALLOC_H
