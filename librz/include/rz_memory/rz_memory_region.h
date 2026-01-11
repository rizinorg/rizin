// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_MEMORY_REGION_H
#define RZ_MEMORY_REGION_H

#include <rz_types.h>
#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	RZ_MEMORY_REGION_CONTAINS_OUTSIDE = 0, ///< The compared boundaries are outside the memory region
	RZ_MEMORY_REGION_CONTAINS_PARTIAL, ///< The compared boundaries are partially inside the memory region
	RZ_MEMORY_REGION_CONTAINS_COMPLETE, ///< The compared boundaries are inside or are the memory region
} RzMemoryRegionContains;

typedef struct rz_memory_region_t RzMemoryRegion;
typedef bool (*RzMemoryRegionIterator)(size_t i, const RzMemoryMap *mmap, const RzInterval *boundaries, void *user);

#ifdef RZ_API

RZ_API void rz_memory_region_free(RZ_NULLABLE RzMemoryRegion *mregion);
RZ_API RZ_OWN RzMemoryRegion *rz_memory_region_new_subregion(RZ_NONNULL RzMemoryRegion *mregion, RZ_NONNULL const RzInterval *boundaries);
RZ_API bool rz_memory_region_has_memory_maps(RZ_NONNULL RzMemoryRegion *mregion);
RZ_API RzMemoryRegionContains rz_memory_region_contains_boundaries(RZ_NONNULL const RzMemoryRegion *mregion, RZ_NONNULL const RzInterval *boundaries);
RZ_API void rz_memory_region_iterate_over(RZ_NONNULL const RzMemoryRegion *mregion, RZ_NONNULL RzMemoryRegionIterator iterator, RZ_NULLABLE void *user);
RZ_API bool rz_memory_region_read_memory(RZ_NONNULL RzMemoryRegion *mregion, ut64 mem_offset, RZ_NONNULL RZ_OUT ut8 *output, size_t out_len, bool sparse, RZ_NULLABLE size_t *read_len);
RZ_API bool rz_memory_region_write_memory(RZ_NONNULL RzMemoryRegion *mregion, ut64 mem_offset, const RZ_NONNULL ut8 *input, size_t in_len, bool sparse, RZ_NULLABLE size_t *write_len);

#endif

#ifdef __cplusplus
}
#endif

#endif /* RZ_MEMORY_REGION_H */
