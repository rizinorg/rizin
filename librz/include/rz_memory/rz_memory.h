// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_MEMORY_H
#define RZ_MEMORY_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_memory/rz_memory_map.h>
#include <rz_memory/rz_memory_region.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	RZ_MEMORY_VISIBILITY_HIDDEN = 0,
	RZ_MEMORY_VISIBILITY_PARTIAL,
	RZ_MEMORY_VISIBILITY_COMPLETE,
} RzMemoryVisibility;

typedef struct rz_memory_t RzMemory;
typedef bool (*RzMemoryIterator)(size_t i, const RzMemoryMap *mmap, RzMemoryVisibility visibility, void *user);

#ifdef RZ_API

RZ_API void rz_memory_free(RZ_NULLABLE RzMemory *mem);
RZ_API RZ_OWN RzMemory *rz_memory_new(void);
RZ_API bool rz_memory_add_map(RZ_NONNULL RzMemory *memory, RZ_NONNULL RZ_OWN RzMemoryMap *mmap, bool top_region);
RZ_API bool rz_memory_remove_map(RZ_NONNULL RzMemory *memory, size_t mmap_id);
RZ_API bool rz_memory_move_map(RZ_NONNULL RzMemory *memory, size_t mmap_id, bool top_region);
RZ_API RZ_BORROW RzMemoryMap *rz_memory_get_map(RZ_NONNULL RzMemory *memory, size_t mmap_id);
RZ_API void rz_memory_iterate_maps(RZ_NONNULL const RzMemory *memory, RZ_NONNULL RzMemoryIterator iterator, RZ_NULLABLE void *user);
RZ_API void rz_memory_iterate_visible(RZ_NONNULL const RzMemory *memory, RZ_NONNULL RzMemoryRegionIterator iterator, RZ_NULLABLE void *user);
RZ_API RZ_OWN RzMemoryRegion *rz_memory_new_region(RZ_NONNULL const RzMemory *memory, RZ_NONNULL const RzInterval *mem_boundaries);

#endif

#ifdef __cplusplus
}
#endif

#endif /* RZ_MEMORY_H */
