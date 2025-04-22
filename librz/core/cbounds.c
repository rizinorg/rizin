// SPDX-FileCopyrightText: 2024 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

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
		RZ_LOG_ERROR("core: failed to allocate and append RzIOMap boundaries.\n");
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

static RZ_OWN RzList /*<RzIOMap *>*/ *core_get_boundaries_generic(RzCore *core, ut64 address, ut64 size, const RzInterval interval, int perms) {
	RzList *list = NULL;
	RzInterval boundaries = { 0 };

	boundaries.addr = address;
	boundaries.size = size;

	if (boundaries.size == UT64_MAX) {
		RZ_LOG_ERROR("core: invalid boundaries (size is UT64_MAX).\n");
		return NULL;
	}

	// rz_io_map_free does not exist.
	list = rz_list_newf(free);
	if (!list) {
		RZ_LOG_ERROR("core: failed to allocate RzList for RzIOMap boundaries.\n");
		return NULL;
	}

	if (!add_interval(core->io, list, boundaries, interval, perms)) {
		rz_list_free(list);
		return NULL;
	}

	return list;
}

/**
 * \brief      Returns the malloc:// or the file boundaries as a RzIOMap list
 *
 * \param      core      The RzCore to use
 * \param      interval  The requested interval in RzIOMaps
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_raw(RZ_NONNULL RzCore *core, const RzInterval interval) {
	rz_return_val_if_fail(core, NULL);

	ut64 size = rz_io_size(core->io);
	// raw/file is always RWX
	return core_get_boundaries_generic(core, 0, size, interval, RZ_PERM_RWX);
}

/**
 * \brief      Returns the current RzCore block boundaries as a RzIOMap list
 *
 * \param      core      The RzCore to use
 * \param      interval  The requested interval in RzIOMaps
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_block(RZ_NONNULL RzCore *core, const RzInterval interval) {
	rz_return_val_if_fail(core, NULL);

	// block is always RWX
	return core_get_boundaries_generic(core, core->offset, core->blocksize, interval, RZ_PERM_RWX);
}

/**
 * \brief      Returns the current function boundaries as a RzIOMap list
 *
 * \param      core      The RzCore to use
 * \param      interval  The requested interval in RzIOMaps
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_current_function(RZ_NONNULL RzCore *core, const RzInterval interval) {
	rz_return_val_if_fail(core, NULL);

	RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
	if (!f) {
		RZ_LOG_ERROR("core: invalid function boundaries, not found at 0x%" PFMT64x "\n", core->offset);
		return NULL;
	}

	ut64 from = rz_analysis_function_min_addr(f);
	ut64 size = rz_analysis_function_linear_size(f);
	return core_get_boundaries_generic(core, from, size, interval, RZ_PERM_RX);
}

/**
 * \brief      Returns the current basic block boundaries as a RzIOMap list
 *
 * \param      core      The RzCore to use
 * \param      interval  The requested interval in RzIOMaps
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_current_function_bb(RZ_NONNULL RzCore *core, const RzInterval interval) {
	rz_return_val_if_fail(core, NULL);

	RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
	if (!f) {
		RZ_LOG_ERROR("core: invalid basic block boundaries, function not found at 0x%" PFMT64x "\n", core->offset);
		return NULL;
	}

	void **iter;
	RzAnalysisBlock *bb;

	rz_pvector_foreach (f->bbs, iter) {
		bb = (RzAnalysisBlock *)*iter;
		if (RZ_BETWEEN(bb->addr, core->offset, (bb->addr + bb->size))) {
			return core_get_boundaries_generic(core, bb->addr, bb->size, interval, RZ_PERM_RX);
		}
	}

	RZ_LOG_ERROR("core: invalid basic block boundaries, bb not found at 0x%" PFMT64x "\n", core->offset);
	return NULL;
}

/**
 * \brief      Returns the current RzIO map boundaries as a RzIOMap list
 *
 * \param      core      The RzCore to use
 * \param      interval  The requested interval in RzIOMaps
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_current_io_map(RZ_NONNULL RzCore *core, const RzInterval interval) {
	rz_return_val_if_fail(core, NULL);

	const RzIOMap *m = rz_io_map_get(core->io, core->offset);
	if (!m) {
		// return an empty list.
		return rz_list_newf(free);
	}

	return core_get_boundaries_generic(core, m->itv.addr, m->itv.size, interval, m->perm);
}

/**
 * \brief      Returns the current RzBin section boundaries as a RzIOMap list
 *
 * \param      core      The RzCore to use
 * \param      interval  The requested interval in RzIOMaps
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_current_bin_section(RZ_NONNULL RzCore *core, const RzInterval interval) {
	rz_return_val_if_fail(core, NULL);

	bool va = rz_config_get_b(core->config, "io.va");
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzBinSection *elem = NULL;

	if (!obj || !(elem = rz_bin_get_section_at(obj, core->offset, va))) {
		// return an empty list
		return rz_list_newf(free);
	}

	if (va) {
		// virtual
		return core_get_boundaries_generic(core, elem->vaddr, elem->vsize, interval, elem->perm);
	}
	// physical
	return core_get_boundaries_generic(core, elem->paddr, elem->size, interval, elem->perm);
}

/**
 * \brief      Returns the current RzBin segment boundaries as a RzIOMap list
 *
 * \param      core      The RzCore to use
 * \param      interval  The requested interval in RzIOMaps
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_current_bin_segment(RZ_NONNULL RzCore *core, const RzInterval interval) {
	rz_return_val_if_fail(core, NULL);

	bool va = rz_config_get_b(core->config, "io.va");
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzBinSection *elem = NULL;

	if (!obj || !(elem = rz_bin_get_segment_at(obj, core->offset, va))) {
		// return an empty list
		return rz_list_newf(free);
	}

	if (va) {
		// virtual
		return core_get_boundaries_generic(core, elem->vaddr, elem->vsize, interval, elem->perm);
	}
	// physical
	return core_get_boundaries_generic(core, elem->paddr, elem->size, interval, elem->perm);
}

/**
 * \brief      Returns the RzIO maps boundaries as a RzIOMap list
 *
 * \param      core        The RzCore to use
 * \param      interval    The requested interval in RzIOMaps
 * \param      perms       The permissions to match
 * \param      perms_mask  The permissions mask filter
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_io_maps(RZ_NONNULL RzCore *core, const RzInterval interval, int perms, int perms_mask) {
	rz_return_val_if_fail(core, NULL);

	void **it;
	RzList *list = NULL;
	RzPVector *maps = rz_io_maps(core->io);

	// rz_io_map_free does not exist.
	list = rz_list_newf(free);
	if (!list) {
		RZ_LOG_ERROR("core: failed to allocate RzList for io.maps boundaries.\n");
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
		if (!add_interval(core->io, list, map->itv, interval, map->perm)) {
			rz_list_free(list);
			return NULL;
		}
	}

	return list;
}

/**
 * \brief      Returns the RzIO skyline boundaries as a RzIOMap list
 *
 * \param      core        The RzCore to use
 * \param      interval    The requested interval in RzIOMaps
 * \param      perms       The permissions to match
 * \param      perms_mask  The permissions mask filter
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_io_skyline(RZ_NONNULL RzCore *core, const RzInterval interval, int perms, int perms_mask) {
	rz_return_val_if_fail(core, NULL);

	RzList *list = NULL;
	RzVector *skyline = core->io ? &core->io->map_skyline.v : NULL;
	size_t skyline_size = skyline ? rz_vector_len(skyline) : 0;

	// rz_io_map_free does not exist.
	list = rz_list_newf(free);
	if (!list) {
		RZ_LOG_ERROR("core: failed to allocate RzList for io.sky boundaries.\n");
		return NULL;
	}

	for (size_t i = 0; i < skyline_size; i++) {
		const RzSkylineItem *item = rz_vector_index_ptr(skyline, i);
		RzIOMap *map = ((RzIOMap *)item->user);
		if ((map->perm & perms_mask) != perms) {
			continue;
		}
		if (!add_interval(core->io, list, item->itv, interval, map->perm)) {
			rz_list_free(list);
			return NULL;
		}
	}

	return list;
}

/**
 * \brief      Returns the RzBin segments boundaries as a RzIOMap list
 *
 * \param      core        The RzCore to use
 * \param      interval    The requested interval in RzIOMaps
 * \param      perms       The permissions to match
 * \param      perms_mask  The permissions mask filter
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_bin_segments(RZ_NONNULL RzCore *core, const RzInterval interval, int perms, int perms_mask) {
	rz_return_val_if_fail(core, NULL);

	void **iter = NULL;
	RzList *list = NULL;
	RzInterval boundaries = { 0 };
	bool va = rz_config_get_b(core->config, "io.va");
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzPVector *pvec = NULL;

	// rz_io_map_free does not exist.
	list = rz_list_newf(free);
	if (!list) {
		RZ_LOG_ERROR("core: failed to allocate RzList for io.segments boundaries.\n");
		return NULL;
	}

	if (obj) {
		// returns as RZ_OWN
		pvec = rz_bin_object_get_segments(obj);
	}

	rz_pvector_foreach (pvec, iter) {
		RzBinSection *elem = *iter;
		if ((elem->perm & perms_mask) != perms) {
			continue;
		}

		if (va) {
			// virtual
			boundaries.addr = elem->vaddr;
			boundaries.size = elem->vsize;
		} else {
			// physical
			boundaries.addr = elem->paddr;
			boundaries.size = elem->size;
		}

		if (!add_interval(core->io, list, boundaries, interval, elem->perm)) {
			rz_list_free(list);
			list = NULL;
			break;
		}
	}

	rz_pvector_free(pvec);
	return list;
}

/**
 * \brief      Returns the RzBin sections boundaries as a RzIOMap list
 *
 * \param      core        The RzCore to use
 * \param      interval    The requested interval in RzIOMaps
 * \param      perms       The permissions to match
 * \param      perms_mask  The permissions mask filter
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_bin_sections(RZ_NONNULL RzCore *core, const RzInterval interval, int perms, int perms_mask) {
	rz_return_val_if_fail(core, NULL);

	void **iter = NULL;
	RzList *list = NULL;
	RzInterval boundaries = { 0 };
	bool va = rz_config_get_b(core->config, "io.va");
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzPVector *pvec = NULL;

	// rz_io_map_free does not exist.
	list = rz_list_newf(free);
	if (!list) {
		RZ_LOG_ERROR("core: failed to allocate RzList for io.segments boundaries.\n");
		return NULL;
	}

	if (obj) {
		// returns as RZ_OWN
		pvec = rz_bin_object_get_sections(obj);
	}

	rz_pvector_foreach (pvec, iter) {
		RzBinSection *elem = *iter;
		if ((elem->perm & perms_mask) != perms) {
			continue;
		}

		if (va) {
			// virtual
			boundaries.addr = elem->vaddr;
			boundaries.size = elem->vsize;
		} else {
			// physical
			boundaries.addr = elem->paddr;
			boundaries.size = elem->size;
		}

		if (!add_interval(core->io, list, boundaries, interval, elem->perm)) {
			rz_list_free(list);
			list = NULL;
			break;
		}
	}

	rz_pvector_free(pvec);
	return list;
}

/**
 * \brief      Returns all the RzBin sections or RzIO maps with exec perms set as boundaries list of RzIOMap
 *
 * \param      core        The RzCore to use
 * \param      interval    The requested interval in RzIOMaps
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_code_only(RZ_NONNULL RzCore *core, const RzInterval interval) {
	rz_return_val_if_fail(core, NULL);

	void **iter = NULL;
	RzList *list = NULL;
	RzInterval boundaries = { 0 };
	bool va = rz_config_get_b(core->config, "io.va");
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzPVector *pvec = NULL;

	// rz_io_map_free does not exist.
	list = rz_list_newf(free);
	if (!list) {
		RZ_LOG_ERROR("core: failed to allocate RzList for code-only boundaries.\n");
		return NULL;
	}

	if (obj) {
		// returns as RZ_OWN
		pvec = rz_bin_object_get_sections(obj);
	}

	rz_pvector_foreach (pvec, iter) {
		RzBinSection *elem = *iter;
		if (!(elem->perm & RZ_PERM_X)) {
			continue;
		}

		if (va) {
			// virtual
			boundaries.addr = elem->vaddr;
			boundaries.size = elem->vsize;
		} else {
			// physical
			boundaries.addr = elem->paddr;
			boundaries.size = elem->size;
		}

		if (!add_interval(core->io, list, boundaries, interval, elem->perm)) {
			rz_list_free(list);
			list = NULL;
			break;
		}
	}
	rz_pvector_free(pvec);

	if (rz_list_empty(list)) {
		// if no matches with sections, then we use maps.

		pvec = rz_io_maps(core->io);
		rz_pvector_foreach (pvec, iter) {
			RzIOMap *map = *iter;
			if (!(map->perm & RZ_PERM_X)) {
				continue;
			}
			if (!add_interval(core->io, list, map->itv, interval, map->perm)) {
				rz_list_free(list);
				return NULL;
			}
		}
	}

	return list;
}

/**
 * \brief      Returns the RzDebug maps boundaries as a RzIOMap list
 *
 * \param      core        The RzCore to use
 * \param      interval    The requested interval in RzIOMaps
 * \param      perms       The permissions to match
 * \param      perms_mask  The permissions mask filter
 * \param      current     When true, returns only the RzIOMaps that matches the current offset
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_debug_maps(RZ_NONNULL RzCore *core, const RzInterval interval, int perms, int perms_mask, bool current) {
	rz_return_val_if_fail(core, NULL);

	if (!core->bin->is_debugger) {
		RZ_LOG_ERROR("core: no debugger connected for debug maps boundaries.\n");
		return NULL;
	}

	// ensure data is syncronized
	rz_debug_map_sync(core->dbg);

	RzList *list = NULL;
	RzListIter *iter = NULL;
	RzDebugMap *map = NULL;
	RzInterval boundaries;

	// rz_io_map_free does not exist.
	list = rz_list_newf(free);
	if (!list) {
		RZ_LOG_ERROR("core: failed to allocate RzList for io.maps boundaries.\n");
		return NULL;
	}

	rz_list_foreach (core->dbg->maps, iter, map) {
		if ((map->perm & perms_mask) != perms) {
			continue;
		}

		boundaries.addr = map->addr;
		boundaries.size = map->addr_end - map->addr;

		if (current) {
			// accept only elements which includes the current offset.
			const ut64 begin = rz_itv_begin(boundaries);
			const ut64 end = rz_itv_end(boundaries);
			if (!RZ_BETWEEN(begin, core->offset, end)) {
				continue;
			}
		}

		if (!add_interval(core->io, list, boundaries, interval, map->perm)) {
			rz_list_free(list);
			return NULL;
		}
	}

	return list;
}

/**
 * \brief      Returns the RzDebug heap boundaries as a RzIOMap list
 *
 * \param      core        The RzCore to use
 * \param      interval    The requested interval in RzIOMaps
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_debug_heap(RZ_NONNULL RzCore *core, const RzInterval interval) {
	rz_return_val_if_fail(core, NULL);

	if (!core->bin->is_debugger) {
		RZ_LOG_ERROR("core: no debugger connected for debug heap boundaries.\n");
		return NULL;
	}

	// ensure data is syncronized
	rz_debug_map_sync(core->dbg);

	RzList *list = NULL;
	RzListIter *iter = NULL;
	RzDebugMap *map = NULL;
	RzInterval boundaries;

	// rz_io_map_free does not exist.
	list = rz_list_newf(free);
	if (!list) {
		RZ_LOG_ERROR("core: failed to allocate RzList for debug heap boundaries.\n");
		return NULL;
	}

	rz_list_foreach (core->dbg->maps, iter, map) {
		if (!strstr(map->name, "heap") || !(map->perm & RZ_PERM_W)) {
			continue;
		}

		boundaries.addr = map->addr;
		boundaries.size = map->addr_end - map->addr;

		if (!add_interval(core->io, list, boundaries, interval, map->perm)) {
			rz_list_free(list);
			return NULL;
		}
	}

	return list;
}

/**
 * \brief      Returns the RzDebug stack boundaries as a RzIOMap list
 *
 * \param      core        The RzCore to use
 * \param      interval    The requested interval in RzIOMaps
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_debug_stack(RZ_NONNULL RzCore *core, const RzInterval interval) {
	rz_return_val_if_fail(core, NULL);

	if (!core->bin->is_debugger) {
		RZ_LOG_ERROR("core: no debugger connected for debug stack boundaries.\n");
		return NULL;
	}

	// ensure data is syncronized
	rz_debug_map_sync(core->dbg);

	RzList *list = NULL;
	RzListIter *iter = NULL;
	RzDebugMap *map = NULL;
	RzInterval boundaries;

	// rz_io_map_free does not exist.
	list = rz_list_newf(free);
	if (!list) {
		RZ_LOG_ERROR("core: failed to allocate RzList for debug stack boundaries.\n");
		return NULL;
	}

	rz_list_foreach (core->dbg->maps, iter, map) {
		if (!strstr(map->name, "stack")) {
			continue;
		}

		boundaries.addr = map->addr;
		boundaries.size = map->addr_end - map->addr;

		if (!add_interval(core->io, list, boundaries, interval, map->perm)) {
			rz_list_free(list);
			return NULL;
		}
	}

	return list;
}

/**
 * \brief      Returns the RzDebug exec-set maps boundaries as a RzIOMap list
 *
 * \param      core        The RzCore to use
 * \param      interval    The requested interval in RzIOMaps
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_debug_program(RZ_NONNULL RzCore *core, const RzInterval interval) {
	rz_return_val_if_fail(core, NULL);

	if (!core->bin->is_debugger) {
		RZ_LOG_ERROR("core: no debugger connected for debug program boundaries.\n");
		return NULL;
	}

	// ensure data is syncronized
	rz_debug_map_sync(core->dbg);

	RzList *list = NULL;
	RzListIter *iter = NULL;
	RzDebugMap *map = NULL;
	RzInterval boundaries;

	// rz_io_map_free does not exist.
	list = rz_list_newf(free);
	if (!list) {
		RZ_LOG_ERROR("core: failed to allocate RzList for debug program boundaries.\n");
		return NULL;
	}

	rz_list_foreach (core->dbg->maps, iter, map) {
		if (!(map->perm & RZ_PERM_X)) {
			continue;
		}

		boundaries.addr = map->addr;
		boundaries.size = map->addr_end - map->addr;

		if (!add_interval(core->io, list, boundaries, interval, map->perm)) {
			rz_list_free(list);
			return NULL;
		}
	}

	return list;
}

/**
 * \brief      Returns a list of boundaries (as RzIOMap), based on the selected mode; see [search/analysis/zoom/[in/from/to]] for available modes.
 *
 * \param      core      The RzCore to use
 * \param      from_key  The [search|analysis|zoom].from keyword to use in RzConfig
 * \param      to_key    The [search|analysis|zoom].to keyword to use in RzConfig
 * \param      in_key    The [search|analysis|zoom].in keyword to use in RzConfig
 *
 * \return     On success a valid pointer (can be an empty list), otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_get_boundaries_select(RZ_NONNULL RzCore *core, RZ_NONNULL const char *from_key, RZ_NONNULL const char *to_key, RZ_NONNULL const char *in_key) {
	rz_return_val_if_fail(core && from_key && to_key && in_key, NULL);

	RzInterval interval;
	ut64 from = rz_config_get_i(core->config, from_key);
	ut64 to = rz_config_get_i(core->config, to_key);
	const char *use_mode = rz_config_get(core->config, in_key);

	interval.addr = from;
	interval.size = to - from;

	if (!strcmp(use_mode, "raw") || !strcmp(use_mode, "file")) {
		return rz_core_get_boundaries_raw(core, interval);
	} else if (!strcmp(use_mode, "block")) {
		return rz_core_get_boundaries_block(core, interval);
	} else if (!strcmp(use_mode, "dbg.map")) {
		return rz_core_get_boundaries_current_debug_map(core, interval);
	} else if (!strcmp(use_mode, "io.map")) {
		return rz_core_get_boundaries_current_io_map(core, interval);
	} else if (!strcmp(use_mode, "range") || !strcmp(use_mode, "io.maps")) {
		return rz_core_get_boundaries_all_io_maps(core, interval);
	} else if (!strcmp(use_mode, "io.sky")) {
		return rz_core_get_boundaries_all_io_skyline(core, interval);
	} else if (!strcmp(use_mode, "code")) {
		return rz_core_get_boundaries_code_only(core, interval);
	} else if (!strcmp(use_mode, "bin.segment")) {
		return rz_core_get_boundaries_current_bin_segment(core, interval);
	} else if (!strcmp(use_mode, "bin.section")) {
		return rz_core_get_boundaries_current_bin_section(core, interval);
	} else if (!strcmp(use_mode, "bin.segments")) {
		return rz_core_get_boundaries_all_bin_segments(core, interval);
	} else if (!strcmp(use_mode, "bin.sections")) {
		return rz_core_get_boundaries_all_bin_sections(core, interval);
	} else if (!strcmp(use_mode, "analysis.fcn")) {
		return rz_core_get_boundaries_current_function(core, interval);
	} else if (!strcmp(use_mode, "analysis.bb")) {
		return rz_core_get_boundaries_current_function_bb(core, interval);
	} else if (!strcmp(use_mode, "dbg.maps")) {
		return rz_core_get_boundaries_all_debug_maps(core, interval);
	} else if (!strcmp(use_mode, "dbg.heap")) {
		return rz_core_get_boundaries_debug_heap(core, interval);
	} else if (!strcmp(use_mode, "dbg.stack")) {
		return rz_core_get_boundaries_debug_stack(core, interval);
	} else if (!strcmp(use_mode, "dbg.program")) {
		return rz_core_get_boundaries_debug_program(core, interval);
	} else if (rz_str_startswith(use_mode, "dbg.maps.")) {
#define PARSE_PERMS(input, mode_name) rz_str_rwx(input + strlen(mode_name))
		int perms = PARSE_PERMS(use_mode, "dbg.maps.");
		return rz_core_get_boundaries_debug_maps(core, interval, perms, perms, false);
	} else if (rz_str_startswith(use_mode, "io.sky.")) {
		int perms = PARSE_PERMS(use_mode, "io.sky.");
		return rz_core_get_boundaries_io_skyline(core, interval, perms, perms);
	} else if (rz_str_startswith(use_mode, "io.maps.")) {
		int perms = PARSE_PERMS(use_mode, "io.maps.");
		return rz_core_get_boundaries_io_maps(core, interval, perms, perms);
	} else if (rz_str_startswith(use_mode, "bin.segments.")) {
		int perms = PARSE_PERMS(use_mode, "bin.segments.");
		return rz_core_get_boundaries_bin_segments(core, interval, perms, perms);
	} else if (rz_str_startswith(use_mode, "bin.sections.")) {
		int perms = PARSE_PERMS(use_mode, "bin.sections.");
		return rz_core_get_boundaries_bin_sections(core, interval, perms, perms);
#undef PARSE_PERMS
	}

	RZ_LOG_ERROR("core: unknown mode '%s' for %s\n", use_mode, in_key);
	return NULL;
}
