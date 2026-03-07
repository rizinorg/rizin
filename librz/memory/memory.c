// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file: memory.c
 *
 * This file describes a memory space that goes from 0 to UT64_MAX
 *
 * Allows to add memory maps and modify their visibility.
 * You can request memory regions to perform read/write operations, which
 * are linked to a RzBuffer structure that is then used to read & write.
 */

#include "memory_internal.h"

/**
 * \brief      Frees a RzMemory structure.
 *
 * \param      memory  The memory to free
 */
RZ_API void rz_memory_free(RZ_NULLABLE RzMemory *mem) {
	if (!mem) {
		return;
	}

	rz_pvector_fini(&mem->maps);
	rz_memory_region_free(mem->contiguous_region);
	free(mem);
}

/**
 * \brief      Allocates and initializes a RzMemory structure.
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN RzMemory *rz_memory_new(void) {
	RzMemory *mem = RZ_NEW0(RzMemory);
	if (!mem) {
		return NULL;
	}

	rz_pvector_init(&mem->maps, (RzPVectorFree)rz_memory_map_free);
	mem->contiguous_region = rz_memory_region_new();
	if (mem->contiguous_region) {
		return mem;
	}

	rz_memory_free(mem);
	return NULL;
}

static void memory_add_mmap_contiguous_region_with_boundaries(RzMemory *mem, RzMemoryMap *mmap, const RzInterval *boundaries);

static void memory_add_mmap_to_overlapping_contiguous_region(RzMemory *mem, RzMemoryMap *mmap, const RzInterval *in_boundaries) {
	RzInterval boundaries = *in_boundaries;

	MemoryRegionMap *overlapping_map = rz_memory_region_find_overlap(mem->contiguous_region, &boundaries);
	while (overlapping_map) {
		ut64 over_beg = rz_itv_begin(overlapping_map->boundaries);
		ut64 over_end = rz_itv_end(overlapping_map->boundaries);
		ut64 curr_beg = rz_itv_begin(boundaries);
		ut64 curr_end = rz_itv_end(boundaries);

		if (rz_itv_include(boundaries, overlapping_map->boundaries)) {
			// the mmap is likely fragmented where a smaller map is already mapped but is
			// within these mmap boundaries! we need to try to add the mmap in the unmmapped
			// space before and after the overlapping map.
			RzInterval left = {
				.addr = curr_beg,
				.size = over_beg - curr_beg,
			};
			RzInterval right = {
				.addr = over_end,
				.size = curr_end - over_end,
			};

			// we try to add left
			memory_add_mmap_contiguous_region_with_boundaries(mem, mmap, &left);
			// we try to add right
			memory_add_mmap_contiguous_region_with_boundaries(mem, mmap, &right);
			return;
		}

		// check where it overlaps.
		if ((!curr_end || over_beg < curr_end)) {
			// the new boundaries starts before the overlapping map, but ends inside
			boundaries.size = over_beg - curr_beg;
		} else /* if ((!over_end || curr_beg < over_end)) */ {
			// the new boundaries starts in the overlapping map, but ends outside
			boundaries.addr = over_end;
			boundaries.size = curr_end - over_end;
		}

		// check if boundaries are still valid.
		if (rz_itv_size(boundaries) < 1) {
			// the map is hidden by two higher priority maps.
			return;
		}

		// check again if there is a map that still overlaps the new calculated boundaries
		overlapping_map = rz_memory_region_find_overlap(mem->contiguous_region, &boundaries);
	}

	rz_memory_region_add_map(mem->contiguous_region, mmap, &boundaries);
}

static void memory_add_mmap_contiguous_region_with_boundaries(RzMemory *mem, RzMemoryMap *mmap, const RzInterval *boundaries) {
	// check if boundaries are still valid.
	if (rz_itv_size(*boundaries) < 1) {
		return;
	}

	RzMemoryRegionContains contains = rz_memory_region_contains_boundaries(mem->contiguous_region, boundaries);
	if (contains == RZ_MEMORY_REGION_CONTAINS_COMPLETE) {
		// the memory region is already mapped by a higher priority map
		// this means the current mmap is hidden and shall not be added to the contiguous region
		return;
	} else if (contains == RZ_MEMORY_REGION_CONTAINS_OUTSIDE) {
		// the contiguous region does not contain the map, so we add it
		rz_memory_region_add_map(mem->contiguous_region, mmap, boundaries);
		return;
	}

	// the contiguous region does overlap with the current mmap
	// we need to calculate the first non-overlapping interval
	memory_add_mmap_to_overlapping_contiguous_region(mem, mmap, boundaries);
}

static bool memory_recalculate_contiguous_region(RzMemory *memory) {
	rz_memory_region_free(memory->contiguous_region);
	memory->contiguous_region = rz_memory_region_new();
	if (!memory->contiguous_region) {
		RZ_LOG_ERROR("memory: failed to allocate RzMemoryRegion\n");
		return false;
	}

	if (rz_pvector_len(&memory->maps) < 1) {
		return true;
	}

	void **it;
	rz_pvector_foreach (&memory->maps, it) {
		RzMemoryMap *mmap = *it;
		memory_add_mmap_contiguous_region_with_boundaries(memory, mmap, &mmap->mem_offset);
	}

	return true;
}

static bool memory_add_map(RzMemory *memory, RzMemoryMap *mmap, bool top_layer) {
	if (top_layer) {
		return rz_pvector_push_front(&memory->maps, mmap) != NULL;
	}
	return rz_pvector_push(&memory->maps, mmap) != NULL;
}

/**
 * \brief      Adds a given memory map to the memory
 *
 * \param      memory       The memory to modify
 * \param[in]  RzMemoryMap  The memory map
 * \param[in]  top_layer    When true, adds the memory map as top layer
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_memory_add_map(RZ_NONNULL RzMemory *memory, RZ_NONNULL RZ_OWN RzMemoryMap *mmap, bool top_layer) {
	rz_return_val_if_fail(memory && mmap, false);

	mmap->id = memory->id_counter++;
	if (!memory_add_map(memory, mmap, top_layer)) {
		RZ_LOG_ERROR("memory: failed to add memory map: %s\n", mmap->name);
		rz_memory_map_free(mmap);
		return false;
	}

	return memory_recalculate_contiguous_region(memory);
}

static int compare_mmap_with_id(const void *value, const void *elem, void *user) {
	size_t *mmap_id = (size_t *)value;
	const RzMemoryMap *mmap = (RzMemoryMap *)elem;
	return mmap->id == *mmap_id ? 0 : 1;
}

/**
 * \brief      Removes the n-th memory map from the memory
 *
 * \param      memory   The memory to modify
 * \param[in]  mmap_id  The mmap id to remove
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_memory_remove_map(RZ_NONNULL RzMemory *memory, size_t mmap_id) {
	rz_return_val_if_fail(memory, false);

	size_t index = rz_pvector_find_index(&memory->maps, &mmap_id, compare_mmap_with_id, NULL);
	if (index >= rz_pvector_len(&memory->maps)) {
		RZ_LOG_ERROR("memory: failed to find memory map to remove with id: %" PFMTSZu "\n", mmap_id);
		return false;
	}

	RzMemoryMap *mmap = rz_pvector_remove_at(&memory->maps, index);
	if (!mmap) {
		RZ_LOG_ERROR("memory: failed to remove memory map with id: %" PFMTSZu "\n", mmap_id);
		return false;
	}
	rz_memory_map_free(mmap);

	return memory_recalculate_contiguous_region(memory);
}

/**
 * \brief      Moves the n-th memory map from the memory to the top or bottom
 *
 * \param      memory     The memory to modify
 * \param[in]  mmap_id    The mmap id to move
 * \param[in]  top_layer  When true, moves the memory map as top layer, otherwise as bottom
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_memory_move_map(RZ_NONNULL RzMemory *memory, size_t mmap_id, bool top_layer) {
	rz_return_val_if_fail(memory, false);

	size_t index = rz_pvector_find_index(&memory->maps, &mmap_id, compare_mmap_with_id, NULL);
	if (index >= rz_pvector_len(&memory->maps)) {
		RZ_LOG_ERROR("memory: failed to find memory map to move with id: %" PFMTSZu "\n", mmap_id);
		return false;
	}

	RzMemoryMap *mmap = rz_pvector_remove_at(&memory->maps, index);
	if (!mmap) {
		RZ_LOG_ERROR("memory: failed to remove memory map to move with id: %" PFMTSZu "\n", mmap_id);
		return false;
	}

	if (!memory_add_map(memory, mmap, top_layer)) {
		const char *where = top_layer ? "top" : "bottom";
		RZ_LOG_ERROR("memory: failed to move memory map at %s: %s\n", where, mmap->name);
		rz_memory_map_free(mmap);
		return false;
	}

	return memory_recalculate_contiguous_region(memory);
}

/**
 * \brief      Given a mmap id, returns its RzMemoryMap
 *
 * \param      memory   The memory
 * \param[in]  mmap_id  The mmap identifier
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_BORROW RzMemoryMap *rz_memory_get_map(RZ_NONNULL RzMemory *memory, size_t mmap_id) {
	void **it = rz_pvector_find(&memory->maps, &mmap_id, compare_mmap_with_id, NULL);
	if (!it) {
		RZ_LOG_ERROR("memory: failed to find memory map with id: %" PFMTSZu "\n", mmap_id);
		return false;
	}
	return (RzMemoryMap *)*it;
}

static RzMemoryVisibility memory_calculate_map_visibility(const RzMemory *memory, const RzMemoryMap *mmap) {
	MemoryRegionMap *rmap = rz_memory_region_find_region_map(memory->contiguous_region, mmap);
	if (!rmap) {
		return RZ_MEMORY_VISIBILITY_HIDDEN;
	} else if (rz_itv_eq(rmap->boundaries, mmap->mem_offset)) {
		return RZ_MEMORY_VISIBILITY_COMPLETE;
	}
	return RZ_MEMORY_VISIBILITY_PARTIAL;
}

/**
 * \brief      Iterates over the contiguous memory
 *
 * \param[in]  memory    The memory to iterate over
 * \param[in]  iterator  The iterator to use
 * \param      user      User given pointer to pass additional info to the iterator
 */
RZ_API void rz_memory_iterate_maps(RZ_NONNULL const RzMemory *memory, RzMemoryIterator iterator, RZ_NULLABLE void *user) {
	rz_return_if_fail(memory && iterator);

	size_t i;
	void **it;
	rz_pvector_enumerate (&memory->maps, it, i) {
		const RzMemoryMap *mmap = *it;
		RzMemoryVisibility visibility = memory_calculate_map_visibility(memory, mmap);
		if (!iterator(i, mmap, visibility, user)) {
			return;
		}
	}
}

/**
 * \brief      Returns a memory region within the given memory boundaries
 *
 * \param[in]  memory          The memory
 * \param[in]  mem_boundaries  The memory boundaries
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN RzMemoryRegion *rz_memory_new_region(RZ_NONNULL const RzMemory *memory, RZ_NONNULL const RzInterval *mem_boundaries) {
	rz_return_val_if_fail(memory && mem_boundaries, NULL);

	// RzMemory should include all 64bit address space so we always return a memory region, even if empty.
	if (!rz_memory_region_has_memory_maps(memory->contiguous_region)) {
		return rz_memory_region_new();
	}

	return rz_memory_region_new_subregion(memory->contiguous_region, mem_boundaries);
}
