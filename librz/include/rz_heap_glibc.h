// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_HEAP_GLIBC_H
#define RZ_HEAP_GLIBC_H

#include <rz_cmd.h>
#include <rz_types.h>
#include <rz_glibc/glibc_types.h>
#include <rz_list.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_heap_glibc);

#define PRINTF_A(color, fmt, ...) rz_cons_printf("%s" fmt "%s", \
	rz_config_get_i(core->config, "scr.color") > 0 ? color : "", \
	__VA_ARGS__, \
	rz_config_get_i(core->config, "scr.color") > 0 ? Color_RESET : "")
#define PRINTF_YA(fmt, ...) PRINTF_A(pal->offset, fmt, __VA_ARGS__)
#define PRINTF_GA(fmt, ...) PRINTF_A(pal->args, fmt, __VA_ARGS__)
#define PRINTF_BA(fmt, ...) PRINTF_A(pal->num, fmt, __VA_ARGS__)
#define PRINTF_RA(fmt, ...) PRINTF_A(pal->invalid, fmt, __VA_ARGS__)

#define PRINT_A(color, msg) rz_cons_printf("%s%s%s", \
	rz_config_get_i(core->config, "scr.color") > 0 ? color : "", \
	msg, \
	rz_config_get_i(core->config, "scr.color") > 0 ? Color_RESET : "")
#define PRINT_YA(msg) PRINT_A(pal->offset, msg)
#define PRINT_GA(msg) PRINT_A(pal->args, msg)
#define PRINT_BA(msg) PRINT_A(pal->num, msg)
#define PRINT_RA(msg) PRINT_A(pal->invalid, msg)

RZ_API double rz_get_glibc_version(RzCore *core, const char *libc_path, ut8 *banner);

#ifdef __cplusplus
}
#endif
#endif
