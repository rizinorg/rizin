// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_util/ht_uu.h>

/// Finm a suitable location for putting the artificial reloc targets map
RZ_API ut64 rz_bin_relocs_patch_find_targets_map_base(RzPVector /*<RzBinMap *>*/ *maps, ut64 target_sz) {
	// find the lowest unmapped address
	ut64 max = 0;
	if (maps) {
		void **it;
		RzBinMap *map;
		rz_pvector_foreach (maps, it) {
			map = *it;
			ut64 addr = map->vaddr + map->vsize;
			if (addr > max) {
				max = addr;
			}
		}
	}
	max += 0x8; // small additional shift to not overlap with symbols like _end
	return max + rz_num_align_delta(max, target_sz);
}

struct rz_bin_reloc_target_builder {
	ut64 target_size; ///< size per target
	HtUU *targets_by_sym; ///< to create only a single target per symbol, if there are more relocs for a single symbol
	ut64 next_target;
} /* RzBinRelocTargetBuilder */;

/**
 * \param target_size size of a single reloc target in the vfile
 * \param target_base base address where the target vfile will be mapped, generated targets will start at this address.
 */
RZ_API RzBinRelocTargetBuilder *rz_bin_reloc_target_builder_new(ut64 target_size, ut64 target_base) {
	RzBinRelocTargetBuilder *builder = RZ_NEW(RzBinRelocTargetBuilder);
	if (!builder) {
		return NULL;
	}
	builder->target_size = target_size;
	builder->next_target = target_base;
	HtUUOptions opt = { 0 };
	builder->targets_by_sym = ht_uu_new_opt(&opt);
	if (!builder->targets_by_sym) {
		free(builder);
		return NULL;
	}
	return builder;
}

RZ_API void rz_bin_reloc_target_builder_free(RZ_NULLABLE RzBinRelocTargetBuilder *builder) {
	if (!builder) {
		return;
	}
	ht_uu_free(builder->targets_by_sym);
	free(builder);
}

/**
 * \brief obtain the address of the target for a given symbol
 *
 * When patchin a reloc that points to some symbol that itself is not part of the file (e.g. an import),
 * this function is used to obtain an address in the reloc target map that the reloc can be patched to.
 * On the first call with a new symbol, the builder will allocate a new address, which will be returned on
 * all following calls with the same sym value.
 *
 * \param sym some (uninterpreted) unique identifier for a symbol. This function will always return the same value for a single symbol.
 */
RZ_API ut64 rz_bin_reloc_target_builder_get_target(RzBinRelocTargetBuilder *builder, ut64 sym) {
	bool found;
	ut64 r = ht_uu_find(builder->targets_by_sym, sym, &found);
	if (found) {
		return r;
	}
	r = builder->next_target;
	ht_uu_insert(builder->targets_by_sym, sym, r);
	builder->next_target += builder->target_size;
	return r;
}

/**
 * \brief Change file-mapped maps to the patched vfile if covered by the buffer and add the reloc target map
 * \param buf_patched_offset the offset of the data in buf_patched inside the real file.
 *        This is especially relevant for fatmach0 where the buf starts further into the fat file.
 */
RZ_API void rz_bin_relocs_patch_maps(RZ_NONNULL RzPVector /*<RzBinMap *>*/ *maps,
	RZ_NULLABLE RzBuffer *buf_patched, ut64 buf_patched_offset,
	ut64 target_vfile_base, ut64 target_vfile_size,
	RZ_NONNULL const char *vfile_name_patched, RZ_NONNULL const char *vfile_name_reloc_targets) {
	rz_return_if_fail(maps);

	// if relocs should be patched, use the patched vfile for everything from the file
	if (buf_patched) {
		void **it;
		RzBinMap *map;
		rz_pvector_foreach (maps, it) {
			map = *it;
			if (map->vfile_name) {
				// For mach0, this skips rebased+stripped maps, preventing reloc patching there.
				// But as far as we can tell, these two features are mutually exclusive in practice.
				continue;
			}
			ut64 buf_addr = map->paddr - buf_patched_offset;
			if (!map->psize || !rz_buf_sparse_populated_in(buf_patched, buf_addr, buf_addr + map->psize - 1)) {
				// avoid using the patched file if there is nothing different in this range
				continue;
			}
			map->vfile_name = strdup(vfile_name_patched);
			map->paddr = buf_addr;
		}
	}

	if (target_vfile_size) {
		// virtual file for reloc targets (where the relocs will point into)
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			return;
		}
		map->name = strdup("reloc-targets");
		map->paddr = 0;
		map->psize = target_vfile_size;
		map->vaddr = target_vfile_base;
		map->vsize = target_vfile_size;
		map->perm = RZ_PERM_R;
		map->vfile_name = strdup(vfile_name_reloc_targets);
		rz_pvector_push_front(maps, map);
	}
}
