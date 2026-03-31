// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_util.h>

#include <rz_util/rz_assert.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_buf.h>
#include <rz_util/rz_regex.h>
#include <rz_util/rz_mem.h>
#include <rz_util/rz_itv.h>
#include "search_internal.h"

static inline RzIntervalAffiliation in_range(const RzBuffer *buf, ut64 offset, RzSearchValueRange *range) {
	ut64 value = 0;
	switch (range->width) {
	default:
		RZ_LOG_ERROR("Unhandled width: %" PFMTSZu ".\n", range->width);
		return RZ_INTERVAL_UNDEF;
	case 1: {
		ut8 out;
		if (!rz_buf_read_ble8_at((RzBuffer *)buf, offset, &out, range->big_endian)) {
			goto failed_to_read;
		}
		value = out;
		break;
	}
	case 2: {
		ut16 out;
		if (!rz_buf_read_ble16_at((RzBuffer *)buf, offset, &out, range->big_endian)) {
			goto failed_to_read;
		}
		value = out;
		break;
	}
	case 4: {
		ut32 out;
		if (!rz_buf_read_ble32_at((RzBuffer *)buf, offset, &out, range->big_endian)) {
			goto failed_to_read;
		}
		value = out;
		break;
	}
	case 8: {
		ut64 out;
		if (!rz_buf_read_ble64_at((RzBuffer *)buf, offset, &out, range->big_endian)) {
			goto failed_to_read;
		}
		value = out;
		break;
	}
	}
	return rz_itv_bound_contains_ut64(&range->itv, value);

failed_to_read:
	RZ_LOG_ERROR("Failed to read from buffer.\n");
	return -1;
}

static bool values_find(RzSearchFindOpt *fopts, void *user, ut64 address, const RzBuffer *buffer,
	RZ_OUT RzThreadQueue *hits, RZ_OUT size_t *n_hits) {
	if (!fopts) {
		RZ_LOG_ERROR("bytes_find requires valid find options.\n");
		return false;
	}

	ut64 size = rz_buf_size((RzBuffer *)buffer);
	// Remove const classifier. Because the buffer API is not constified, unfortunately.
	*n_hits = 0;
	RzVector /*<RzSearchValueRange>*/ *intervals = (RzVector *)user;
	RzSearchValueRange *range = NULL;
	rz_vector_foreach (intervals, range) {
		for (size_t offset = 0; offset < size;) {
			RAW_BUF_ITER_ALIGN(fopts, address, offset);
			size_t leftovers = size - offset;
			if (range->width > leftovers) {
				break;
			}
			switch (in_range(buffer, offset, range)) {
			default:
			case RZ_INTERVAL_UNDEF:
				// Error case
				return false;
			case RZ_INTERVAL_OUT:
				// Not in range
				offset++;
				continue;
			case RZ_INTERVAL_IN:
				(*n_hits)++;
				RzSearchHit *hit = rz_search_hit_new("value", address + offset, range->width, NULL);
				if (!hit || !rz_th_queue_push(hits, hit, true)) {
					rz_search_hit_free(hit);
					return false;
				}
				offset += fopts->match_overlap ? 1 : range->width;
				continue;
			}
		}
	}
	return true;
}

static bool values_are_empty(void *user) {
	return rz_vector_empty((RzVector *)user);
}

/**
 * \brief      Allocates and initialize a RzSearchCollection for value searching.
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_values() {
	RzVector /*<RzSearchValueRange>*/ *intervals = rz_vector_new(sizeof(RzSearchValueRange), NULL, NULL);
	if (!intervals) {
		RZ_LOG_ERROR("search: failed to initialize value search collection\n");
		return NULL;
	}
	return rz_search_collection_new_bytes_space(values_find, values_are_empty, (RzSearchFreeCallback)rz_vector_free, intervals);
}

/**
 * \brief Add value ranges to the search collection.
 *
 * \param col The search collection to extend.
 * \param vranges The value ranges to add. The values change ownership.
 *
 * \return True if the value range was added successfully. False otherwise.
 */
RZ_API bool rz_search_collection_values_add(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL RZ_OWN RzVector /*<RzSearchValueRange>*/ *vranges) {
	rz_return_val_if_fail(col && vranges, false);
	if (!rz_search_collection_has_find_callback(col, values_find)) {
		RZ_LOG_ERROR("search: cannot add values to a non-values collection\n");
		rz_vector_free(vranges);
		return false;
	}
	rz_return_val_if_fail(col->user, false);
	RzSearchValueRange *range;
	rz_vector_foreach (vranges, range) {
		rz_vector_push(col->user, range);
	}
	rz_vector_free(vranges);
	return true;
}
