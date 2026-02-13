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

RZ_API RzHeapChunkSimple *rz_heap_chunk(RzCore *core, ut64 addr);
RZ_API RzHeapChunk *rz_heap_get_chunk_at_addr(RzCore *core, ut64 addr);
RZ_API RzList /*<RzArenaListItem *>*/ *rz_heap_arenas_list(RzCore *core);
RZ_API bool rz_heap_resolve_main_arena(RzCore *core, ut64 *m_arena);
RZ_API double rz_get_glibc_version(RzCore *core, const char *libc_path, ut8 *banner);
RZ_API bool rz_heap_update_main_arena(RzCore *core, ut64 m_arena, MallocState *main_arena);
RZ_API bool rz_heap_write_chunk(RzCore *core, RzHeapChunkSimple *chunk_simple);
RZ_API RzList /*<RzHeapBin *>*/ *rz_heap_tcache_content(RzCore *core, ut64 arena_base);
RZ_API MallocState *rz_heap_get_arena(RzCore *core, ut64 m_state);
RZ_API RzHeapBin *rz_heap_fastbin_content(RzCore *core, MallocState *main_arena, int bin_num);
RZ_API RzHeapBin *rz_heap_bin_content(RzCore *core, MallocState *main_arena, int bin_num, ut64 m_arena);
RZ_API RzList /*<RzHeapChunkListItem *>*/ *rz_heap_chunks(RzCore *core, ut64 m_state);
RZ_API RzList /*<RzArenaListItem *>*/ *rz_heap_arena_list(RzCore *core);
RZ_IPI RzCmdStatus rz_cmd_heap_fastbins_print_handler(RzCore *core, int argc, const char **argv);
RZ_IPI RzCmdStatus rz_cmd_heap_bins_list_print_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode);
RZ_API void rz_heap_bin_free(RzHeapBin *bin);

#ifdef __cplusplus
}
#endif
#endif
