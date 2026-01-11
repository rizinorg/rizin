// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_memory/rz_memory.h>
#include <rz_list.h>
#include <rz_vector.h>

struct rz_memory_map_t {
	size_t id; ///< Memory Map identifier
	char *name; ///< Memory sector name.
	ut32 permissions; ///< Memory permission (rwx).
	RzBuffer *buffer; ///< Linked RzBuffer layer.
	RzInterval buf_offset; ///< Interval where this memory is located in the buffer space.
	RzInterval mem_offset; ///< Interval where this memory is located in the memory space.
};

typedef bool (*memory_map_read)(const RzMemoryMap *mmap, ut64 buf_offset, ut8 *output, size_t out_len, size_t *read_len);
typedef bool (*memory_map_write)(RzMemoryMap *mmap, ut64 mem_offset, const ut8 *input, size_t in_len, size_t *write_len);

typedef struct memory_region_map_t {
	RzMemoryMap *mmap; ///< Memory Map associated to this region.
	RzInterval boundaries; ///< Region boundaries.
} MemoryRegionMap;

struct rz_memory_region_t {
	RzInterval boundaries; ///< Memory boundaries of the requested layer.
	RzVector /*<MemoryRegionMap>*/ maps; ///< List of visible memory maps (sorted).
	size_t last_used; ///< Last used index for improved performace.
};

struct rz_memory_t {
	size_t id_counter;
	RzPVector /*<RzMemoryMap *>*/ maps; ///< List of all memory maps.
	RzMemoryRegion *contiguous_region; ///< Defines the memory in a contiguous way, where each region contains a maps
};

static inline bool memory_is_valid_interval(const RzInterval interval) {
	if (rz_itv_size(interval) < 1) {
		return false;
	}
	ut64 beg = rz_itv_begin(interval);
	ut64 end = rz_itv_end(interval);

	// we always allow end to be 0 as it is (exclusive) in the range.
	// and allows addresses to go up to UT64_MAX (inclusive)
	return !(end && end < beg);
}

RZ_IPI void rz_memory_map_free(RZ_NULLABLE RzMemoryMap *mmap);

RZ_IPI RZ_OWN RzMemoryRegion *rz_memory_region_new(void);
RZ_IPI MemoryRegionMap *rz_memory_region_find_region_map(RZ_NONNULL const RzMemoryRegion *mregion, const RzMemoryMap *mmap);
RZ_IPI bool rz_memory_region_add_map(RZ_NONNULL RzMemoryRegion *mregion, RZ_NONNULL RZ_BORROW RzMemoryMap *mmap, RZ_NONNULL const RzInterval *boundaries);
RZ_IPI MemoryRegionMap *rz_memory_region_find_overlap(RZ_NONNULL const RzMemoryRegion *mregion, RZ_NONNULL const RzInterval *boundaries);
