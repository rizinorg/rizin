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

RZ_API RzHeapChunkSimple *rz_heap_chunk(RzCore *core, ut64 addr);
RZ_API RzHeapChunk *rz_heap_get_chunk_at_addr(RzCore *core, ut64 addr);
RZ_API RzList /*<RzHeapChunkListItem *>*/ *rz_heap_chunks_list(RzCore *core, ut64 m_arena);
RZ_API RzList /*<RzArenaListItem *>*/ *rz_heap_arenas_list(RzCore *core);
RZ_API bool rz_heap_resolve_main_arena(RzCore *core, ut64 *m_arena);
RZ_API double rz_get_glibc_version(RzCore *core, const char *libc_path, ut8 *banner);
RZ_API bool rz_heap_update_main_arena(RzCore *core, ut64 m_arena, MallocState *main_arena);
RZ_API bool rz_heap_write_chunk(RzCore *core, RzHeapChunkSimple *chunk_simple);
RZ_API RzList /*<RzHeapBin *>*/ *rz_heap_tcache_content(RzCore *core, ut64 arena_base);
RZ_API MallocState *rz_heap_get_arena(RzCore *core, ut64 m_state);
RZ_API RzHeapBin *rz_heap_fastbin_content(RzCore *core, MallocState *main_arena, int bin_num);
RZ_API RzHeapBin *rz_heap_bin_content(RzCore *core, MallocState *main_arena, int bin_num, ut64 m_arena);
RZ_API void rz_heap_bin_free(RzHeapBin *bin);

#ifdef __cplusplus
}
#endif
#endif
