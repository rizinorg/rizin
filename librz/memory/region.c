// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file: region.c
 *
 * This file describes a memory region which is composed by fragmented memory maps.
 *
 * The region is always sorted by lower map to higher map and contains only areas
 * that are visible (i.e. highest priority).
 *
 * If a low-priority map overlaps another higher priority map, depending on the
 * boundaries, it can be partially mapped in the memory region or missing if
 * the higher priority map overlaps completely the low-priority map.
 */

#include "memory_internal.h"

/**
 * \brief      Frees a RzMemoryRegion
 *
 * \param      mregion  The RzMemoryRegion to free
 */
RZ_API void rz_memory_region_free(RZ_NULLABLE RzMemoryRegion *mregion) {
	if (!mregion) {
		return;
	}

	rz_vector_fini(&mregion->maps);
	free(mregion);
}

/**
 * \brief      Allocates and initialize a RzMemoryRegion
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_IPI RZ_OWN RzMemoryRegion *rz_memory_region_new(void) {
	RzMemoryRegion *mregion = RZ_NEW0(RzMemoryRegion);
	if (!mregion) {
		return NULL;
	}

	rz_vector_init(&mregion->maps, sizeof(MemoryRegionMap), NULL, NULL);
	return mregion;
}

static int memory_region_map_compare(const void *_a, const void *_b, void *user) {
	MemoryRegionMap *a = (MemoryRegionMap *)_a;
	MemoryRegionMap *b = (MemoryRegionMap *)_b;

	const ut64 a_start = rz_itv_begin(a->boundaries);
	const ut64 b_start = rz_itv_begin(b->boundaries);
	if (a_start < b_start) {
		return -1;
	} else if (a_start > b_start) {
		return 1;
	}

	// there should be NO map that starts at the same address.
	rz_warn_if_reached();
	return 0;
}

/**
 * \brief      Adds a given memory map and its boundaries to a RzMemoryRegion
 *
 * \param      mregion     The RzMemoryRegion to add to
 * \param      mmap        The RzMemoryMap to add
 * \param[in]  boundaries  The boundaries of the RzMemoryMap
 *
 * \return     On success returns true, otherwise false
 */
RZ_IPI bool rz_memory_region_add_map(RZ_NONNULL RzMemoryRegion *mregion, RZ_NONNULL RZ_BORROW RzMemoryMap *mmap, RZ_NONNULL const RzInterval *boundaries) {
	rz_return_val_if_fail(mregion && mmap && boundaries, false);

	MemoryRegionMap rmap = {
		.mmap = mmap,
		.boundaries = *boundaries,
	};

	if (rz_vector_push(&mregion->maps, &rmap) == NULL) {
		return false;
	}

	rz_vector_sort(&mregion->maps, memory_region_map_compare, false, NULL);

	// fix boundaries.
	MemoryRegionMap *first = rz_vector_head(&mregion->maps);
	MemoryRegionMap *last = rz_vector_tail(&mregion->maps);
	ut64 reg_start = rz_itv_begin(first->boundaries);
	ut64 reg_end = rz_itv_end(last->boundaries);

	mregion->boundaries.addr = reg_start;
	mregion->boundaries.size = reg_end - reg_start;

	return true;
}

/**
 * \brief      Finds the first MemoryRegionMap which holds mmap
 *
 * \param[in]  mregion   The RzMemoryRegion to use
 * \param      mmap      The RzMemoryMap to find
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_IPI MemoryRegionMap *rz_memory_region_find_region_map(RZ_NONNULL const RzMemoryRegion *mregion, const RzMemoryMap *mmap) {
	rz_return_val_if_fail(mregion && mmap, NULL);

	MemoryRegionMap *rmap;
	rz_vector_foreach (&mregion->maps, rmap) {
		if (rmap->mmap == mmap) {
			return rmap;
		}
	}
	return NULL;
}

/**
 * \brief      Returns the first MemoryRegionMap which overlaps a given boundaries
 *
 * \param[in]  mregion     The RzMemoryRegion to use
 * \param      boundaries  The RzInterval to overlap
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_IPI MemoryRegionMap *rz_memory_region_find_overlap(RZ_NONNULL const RzMemoryRegion *mregion, RZ_NONNULL const RzInterval *boundaries) {
	rz_return_val_if_fail(mregion && boundaries, RZ_MEMORY_REGION_CONTAINS_OUTSIDE);

	MemoryRegionMap *rmap;
	rz_vector_foreach (&mregion->maps, rmap) {
		if (rz_itv_overlap(rmap->boundaries, *boundaries)) {
			return rmap;
		}
	}
	return NULL;
}

/**
 * \brief      Returns a subregion
 *
 * \param[in]  mregion     The RzMemoryRegion to use
 * \param[in]  boundaries  The boundaries to use for the defined region.
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzMemoryRegion *rz_memory_region_new_subregion(RZ_NONNULL RzMemoryRegion *mregion, RZ_NONNULL const RzInterval *boundaries) {
	rz_return_val_if_fail(mregion && boundaries, NULL);

	RzMemoryRegion *sub_region = rz_memory_region_new();
	if (!sub_region) {
		return NULL;
	}

	const ut64 req_end = rz_itv_end(*boundaries);
	MemoryRegionMap *rmap = NULL;
	rz_vector_foreach (&mregion->maps, rmap) {
		if (req_end <= rz_itv_begin(rmap->boundaries)) {
			break;
		} else if (!rz_itv_overlap(rmap->boundaries, *boundaries)) {
			continue;
		}

		// boundaries are [start, end)
		RzInterval intersection = rz_itv_intersect(rmap->boundaries, *boundaries);
		if (rz_itv_size(intersection) < 0) {
			continue;
		}

		if (!rz_memory_region_add_map(sub_region, rmap->mmap, &intersection)) {
			rz_memory_region_free(sub_region);
			return NULL;
		}
	}

	return sub_region;
}

/**
 * \brief      Returns true if a RzMemoryRegion has valid RzMemoryMap
 *
 * \param      mregion  The RzMemoryRegion to use
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_memory_region_has_memory_maps(RZ_NONNULL RzMemoryRegion *mregion) {
	rz_return_val_if_fail(mregion, false);

	return rz_vector_len(&mregion->maps) > 0;
}

/**
 * \brief      Compares a RzMemoryRegion with a given boundaries and returns if the boundaries are outside, partially inside or inside the memory region.
 *
 * \param      mregion     The RzMemoryRegion to use
 * \param[in]  boundaries  The boundaries to compare to
 *
 * \return     The returned value defines the location of the boundaries.
 */
RZ_API RzMemoryRegionContains rz_memory_region_contains_boundaries(RZ_NONNULL const RzMemoryRegion *mregion, RZ_NONNULL const RzInterval *boundaries) {
	rz_return_val_if_fail(mregion && boundaries, RZ_MEMORY_REGION_CONTAINS_OUTSIDE);

	if (rz_vector_len(&mregion->maps) < 1) {
		// don't try to calculate the boundaries when there are no maps.
		return RZ_MEMORY_REGION_CONTAINS_OUTSIDE;
	}

	ut64 reg_start = rz_itv_begin(mregion->boundaries);
	ut64 reg_end = rz_itv_end(mregion->boundaries);
	ut64 start = rz_itv_begin(*boundaries);
	ut64 end = rz_itv_end(*boundaries);

	if (end <= reg_start || start > reg_end) {
		return RZ_MEMORY_REGION_CONTAINS_OUTSIDE;
	}

	MemoryRegionMap *rmap = rz_memory_region_find_overlap(mregion, boundaries);
	if (rmap) {
		if (rz_itv_include(rmap->boundaries, *boundaries)) {
			return RZ_MEMORY_REGION_CONTAINS_COMPLETE;
		}
		return RZ_MEMORY_REGION_CONTAINS_PARTIAL;
	}

	return RZ_MEMORY_REGION_CONTAINS_OUTSIDE;
}

/**
 * \brief      Iterates over all the maps hold by the RzMemoryRegion
 *
 * \param[in]  mregion   The RzMemoryRegion to use
 * \param[in]  iterator  The iterator to call
 * \param      user      The user pointer for additional context passed to the iterator
 */
RZ_API void rz_memory_region_iterate_over(RZ_NONNULL const RzMemoryRegion *mregion, RZ_NONNULL RzMemoryRegionIterator iterator, RZ_NULLABLE void *user) {
	rz_return_if_fail(mregion && iterator);

	size_t i;
	MemoryRegionMap *rmap;
	rz_vector_enumerate (&mregion->maps, rmap, i) {
		if (!iterator(i, rmap->mmap, &rmap->boundaries, user)) {
			return;
		}
	}
}

static bool memory_region_in_boundaries(const RzMemoryRegion *mregion, ut64 address, size_t size, bool sparse) {
	bool contains = rz_itv_contain(mregion->boundaries, address);
	if (!sparse) {
		return contains;
	}
	RzInterval requested = {
		.addr = address,
		.size = size,
	};

	RzInterval intersection = rz_itv_intersect(mregion->boundaries, requested);
	return contains && rz_itv_size(intersection) > 0;
}

/**
 * \brief      Reads the buffer of a given memory offset and writes it into output.
 *
 * \param[in]  mregion     The RzMemoryRegion to use
 * \param[in]  mem_offset  The memory offset to read from
 * \param      output      The output buffer to write to
 * \param[in]  out_len     The out length of the buffer
 * \param      sparse      When true allows to skip reading in an unmapped areas if the buffer still falls in mapped regions.
 * \param      read_len    The actual read length (read_len can be <= out_len)
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_memory_region_read_memory(RZ_NONNULL RzMemoryRegion *mregion, ut64 mem_offset, RZ_NONNULL RZ_OUT ut8 *output, size_t out_len, bool sparse, RZ_NULLABLE size_t *read_len) {
	rz_return_val_if_fail(mregion && output && out_len > 0, false);

	const size_t n_maps = rz_vector_len(&mregion->maps);

	if (n_maps < 1 || !memory_region_in_boundaries(mregion, mem_offset, out_len, sparse)) {
		return false;
	}

	size_t total_read = 0;
	MemoryRegionMap *rmap = NULL;
	size_t start_index = 0;
	if (mregion->last_used < n_maps) {
		rmap = rz_vector_index_ptr(&mregion->maps, mregion->last_used);
		if (rz_itv_contain(rmap->boundaries, mem_offset)) {
			start_index = mregion->last_used;
		}
	}

	for (size_t i = start_index; i < n_maps && total_read < out_len; ++i) {
		rmap = rz_vector_index_ptr(&mregion->maps, i);
		ut64 start = mem_offset + total_read;
		size_t leftovers = out_len - total_read;
		RzInterval current = {
			.addr = start,
			.size = leftovers,
		};

		if (!rz_itv_overlap(rmap->boundaries, current)) {
			continue;
		}

		RzInterval intersection = rz_itv_intersect(rmap->boundaries, current);
		if (rz_itv_size(intersection) < 1) {
			continue;
		} else if (rz_itv_begin(intersection) != start) {
			if (!sparse) {
				break;
			}
			// increase "read" total
			total_read += rz_itv_begin(intersection) - start;
			start = rz_itv_begin(intersection);
		}
		leftovers = rz_itv_size(intersection);

		mregion->last_used = i;
		ut8 *curr_out = output + start - mem_offset;

		size_t n_bytes = 0;
		if (!rz_memory_map_read_memory(rmap->mmap, start, curr_out, leftovers, &n_bytes)) {
			if (read_len) {
				*read_len = total_read;
			}
			return false;
		}
		total_read += n_bytes;
	}

	if (read_len) {
		*read_len = total_read;
	}
	return total_read > 0;
}

/**
 * \brief      Writes a given buffer to a memory offset.
 *
 * \param[in]  mregion     The RzMemoryRegion to use
 * \param[in]  mem_offset  The memory offset to read from
 * \param      input       The input buffer to read from
 * \param[in]  in_len      The input length of the buffer
 * \param      sparse      When true allows to skip writing in an unmapped areas if the buffer still falls in mapped regions.
 * \param      write_len   The actual read length (write_len can be <= in_len)
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_memory_region_write_memory(RZ_NONNULL RzMemoryRegion *mregion, ut64 mem_offset, const RZ_NONNULL ut8 *input, size_t in_len, bool sparse, RZ_NULLABLE size_t *write_len) {
	rz_return_val_if_fail(mregion && input && in_len > 0, false);

	const size_t n_maps = rz_vector_len(&mregion->maps);

	if (n_maps < 1 || !memory_region_in_boundaries(mregion, mem_offset, in_len, sparse)) {
		return false;
	}

	size_t total_write = 0;
	MemoryRegionMap *rmap = NULL;
	size_t start_index = 0;
	if (mregion->last_used < n_maps) {
		rmap = rz_vector_index_ptr(&mregion->maps, mregion->last_used);
		if (rz_itv_contain(rmap->boundaries, mem_offset)) {
			start_index = mregion->last_used;
		}
	}

	for (size_t i = start_index; i < n_maps && total_write < in_len; ++i) {
		rmap = rz_vector_index_ptr(&mregion->maps, i);
		ut64 start = mem_offset + total_write;
		size_t leftovers = in_len - total_write;
		RzInterval current = {
			.addr = start,
			.size = leftovers,
		};

		if (!rz_itv_overlap(rmap->boundaries, current)) {
			continue;
		}

		RzInterval intersection = rz_itv_intersect(rmap->boundaries, current);
		if (rz_itv_size(intersection) < 1) {
			continue;
		} else if (rz_itv_begin(intersection) != start) {
			if (!sparse) {
				break;
			}
			// increase "write" total
			total_write += rz_itv_begin(intersection) - start;
			start = rz_itv_begin(intersection);
		}
		leftovers = rz_itv_size(intersection);

		mregion->last_used = i;
		const ut8 *curr_in = input + start - mem_offset;

		size_t n_bytes = 0;
		if (!rz_memory_map_write_memory(rmap->mmap, start, curr_in, leftovers, &n_bytes)) {
			if (write_len) {
				*write_len = total_write;
			}
			return false;
		}
		total_write += n_bytes;
	}

	if (write_len) {
		*write_len = total_write;
	}
	return total_write > 0;
}
