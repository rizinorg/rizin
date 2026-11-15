// SPDX-FileCopyrightText: 2024 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>

static bool add_interval(RzIO *io, RzList /*<RzIOMap *>*/ *list, const RzInterval boundaries, const RzInterval interval, int perms) {
	RzInterval map_itv = { 0 };
	RzIOMap *map = NULL;

	if (interval.addr == UT64_MAX && !interval.size) {
		// use the boundaries
		map_itv = boundaries;
	} else if (rz_itv_overlap(boundaries, interval)) {
		// use the intersect.
		map_itv = rz_itv_intersect(boundaries, interval);
	}

	if (!map_itv.size) {
		// invalid interval which we always ignore.
		return true;
	}

	map = RZ_NEW0(RzIOMap);
	if (!map || !rz_list_append(list, map)) {
		RZ_LOG_ERROR("io: failed to allocate and append RzIOMap boundaries.\n");
		free(map);
		return false;
	}

	map->itv = map_itv;
	map->perm = perms;

	if (io && io->desc) {
		map->fd = rz_io_fd_get_current(io);
	}

	return true;
}

static RZ_OWN RzList /*<RzIOMap *>*/ *io_get_boundaries_generic(RzIO *io, ut64 address, ut64 size, const RzInterval interval, int perms) {
	RzList *list = NULL;
	RzInterval boundaries = { 0 };

	boundaries.addr = address;
	boundaries.size = size;

	if (boundaries.size == UT64_MAX) {
		RZ_LOG_ERROR("io: invalid boundaries (size is UT64_MAX).\n");
		return NULL;
	}

	// rz_io_map_free does not exist.
	list = rz_list_newf(free);
	if (!list) {
		RZ_LOG_ERROR("io: failed to allocate RzList for RzIOMap boundaries.\n");
		return NULL;
	}

	if (!add_interval(io, list, boundaries, interval, perms)) {
		rz_list_free(list);
		return NULL;
	}

	return list;
}

/**
 * \brief      Returns the malloc:// or the file boundaries as a RzIOMap list
 *
 * \param      io      The Rzio to use
 * \param      interval  The requested interval in RzIOMaps
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_io_get_boundaries_raw(RZ_NONNULL RzIO *io, const RzInterval interval) {
	rz_return_val_if_fail(io, NULL);

	ut64 size = rz_io_size(io);
	// raw/file is always RWX
	return io_get_boundaries_generic(io, 0, size, interval, RZ_PERM_RWX);
}

/**
 * \brief      Returns the RzIO maps boundaries as a RzIOMap list
 *
 * \param      io        The Rzio to use
 * \param      interval    The requested interval in RzIOMaps
 * \param      perms       The permissions to match
 * \param      perms_mask  The permissions mask filter
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_io_get_boundaries_io_maps(RZ_NONNULL RzIO *io, const RzInterval interval, int perms, int perms_mask) {
	rz_return_val_if_fail(io, NULL);

	void **it;
	RzList *list = NULL;
	RzPVector *maps = rz_io_maps(io);

	// rz_io_map_free does not exist.
	list = rz_list_newf(free);
	if (!list) {
		RZ_LOG_ERROR("io: failed to allocate RzList for io.maps boundaries.\n");
		return NULL;
	}

	rz_pvector_foreach (maps, it) {
		RzIOMap *map = *it;
		if ((map->perm & perms_mask) != perms) {
			continue;
		}
		if (!(map->perm & RZ_PERM_R)) {
			RZ_LOG_WARN("Skip adding map '%s' to boundaries, because it is not readable.\n", map->name);
			continue;
		}
		if (!add_interval(io, list, map->itv, interval, map->perm)) {
			rz_list_free(list);
			return NULL;
		}
	}

	return list;
}

/**
 * \brief      Returns the RzIO skyline boundaries as a RzIOMap list
 *
 * \param      io        The Rzio to use
 * \param      interval    The requested interval in RzIOMaps
 * \param      perms       The permissions to match
 * \param      perms_mask  The permissions mask filter
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_io_get_boundaries_io_skyline(RZ_NONNULL RzIO *io, const RzInterval interval, int perms, int perms_mask) {
	rz_return_val_if_fail(io, NULL);

	RzList *list = NULL;
	RzVector *skyline = io ? &io->map_skyline.v : NULL;
	size_t skyline_size = skyline ? rz_vector_len(skyline) : 0;

	// rz_io_map_free does not exist.
	list = rz_list_newf(free);
	if (!list) {
		RZ_LOG_ERROR("io: failed to allocate RzList for io.sky boundaries.\n");
		return NULL;
	}

	for (size_t i = 0; i < skyline_size; i++) {
		const RzSkylineItem *item = rz_vector_index_ptr(skyline, i);
		RzIOMap *map = ((RzIOMap *)item->user);
		if ((map->perm & perms_mask) != perms) {
			continue;
		}
		if (!add_interval(io, list, item->itv, interval, map->perm)) {
			rz_list_free(list);
			return NULL;
		}
	}

	return list;
}
