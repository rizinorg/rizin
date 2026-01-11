// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_MEMORY_MAP_H
#define RZ_MEMORY_MAP_H

#include <rz_types.h>
#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_memory_map_t RzMemoryMap;

#ifdef RZ_API

RZ_API RzMemoryMap *rz_memory_map_new(RZ_NONNULL const char *name, ut32 perms, RZ_NONNULL RzBuffer *buffer, RZ_NONNULL const RzInterval *buf_offset, RZ_NONNULL const RzInterval *mem_offset);
RZ_API const char *rz_memory_map_get_name(RZ_NONNULL const RzMemoryMap *mmap);
RZ_API ut32 rz_memory_map_get_permissions(RZ_NONNULL const RzMemoryMap *mmap);
RZ_API size_t rz_memory_map_get_identifier(RZ_NONNULL const RzMemoryMap *mmap);
RZ_API void rz_memory_map_set_permissions(RZ_NONNULL RzMemoryMap *mmap, ut32 permissions);
RZ_API void rz_memory_map_get_memory_boundaries(RZ_NONNULL const RzMemoryMap *mmap, RZ_NONNULL RzInterval *mem_offset);
RZ_API void rz_memory_map_get_buffer_boundaries(RZ_NONNULL const RzMemoryMap *mmap, RZ_NONNULL RzInterval *buf_offset);
RZ_API bool rz_memory_map_convert_memory_to_buffer(RZ_NONNULL const RzMemoryMap *mmap, ut64 mem_offset, RZ_NONNULL ut64 *buf_offset);
RZ_API bool rz_memory_map_convert_buffer_to_memory(RZ_NONNULL const RzMemoryMap *mmap, ut64 buf_offset, RZ_NONNULL ut64 *mem_offset);
RZ_API bool rz_memory_map_read_memory(RZ_NONNULL const RzMemoryMap *mmap, ut64 mem_offset, RZ_NONNULL RZ_OUT ut8 *output, size_t out_len, RZ_NULLABLE size_t *read_len);
RZ_API bool rz_memory_map_read_buffer(RZ_NONNULL const RzMemoryMap *mmap, ut64 buf_offset, RZ_NONNULL RZ_OUT ut8 *output, size_t out_len, RZ_NULLABLE size_t *read_len);
RZ_API bool rz_memory_map_write_memory(RZ_NONNULL RzMemoryMap *mmap, ut64 mem_offset, const RZ_NONNULL ut8 *input, size_t in_len, RZ_NULLABLE size_t *write_len);
RZ_API bool rz_memory_map_write_buffer(RZ_NONNULL RzMemoryMap *mmap, ut64 buf_offset, const RZ_NONNULL ut8 *input, size_t in_len, RZ_NULLABLE size_t *write_len);

#endif

#ifdef __cplusplus
}
#endif

#endif /* RZ_MEMORY_MAP_H */
