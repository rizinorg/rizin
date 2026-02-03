// SPDX-FileCopyrightText: 2017 javierptd <javierptd@gmail.com>
// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_heap_jemalloc.h>
#include <stdio.h>

static ut64 je_get_va_symbol(RzCore *core, const char *path, const char *sym_name, bool *is_pie) {
	ut64 vaddr = UT64_MAX;
	RzBin *bin = core->bin;
	RzBinFile *current_bf = rz_bin_cur(bin);
	void **iter;
	RzBinSymbol *s;

	if (is_pie) {
		*is_pie = false;
	}

	RzBinOptions opt;
	rz_bin_options_init(&opt, -1, 0, 0, false);
	opt.obj_opts.elf_load_sections = rz_config_get_b(core->config, "elf.load.sections");
	opt.obj_opts.elf_checks_sections = rz_config_get_b(core->config, "elf.checks.sections");
	opt.obj_opts.elf_checks_segments = rz_config_get_b(core->config, "elf.checks.segments");

	RzBinFile *libc_bf = rz_bin_open(bin, path, &opt);
	if (!libc_bf) {
		return vaddr;
	}

	RzBinObject *o = rz_bin_cur_object(bin);
	RzPVector *syms = o ? (RzPVector *)rz_bin_object_get_symbols(o) : NULL;
	rz_pvector_foreach (syms, iter) {
		s = *iter;
		if (!strcmp(s->name, sym_name)) {
			vaddr = s->vaddr;
			break;
		}
	}

	// Check if binary is PIE/shared object
	if (is_pie && o && o->info) {
		*is_pie = o->info->has_pi;
	}

	rz_bin_file_delete(bin, libc_bf);
	rz_bin_file_set_obj(current_bf, current_bf->o);
	rz_bin_set_cur_binfile(bin, current_bf);
	return vaddr;
}

static bool rz_resolve_jemalloc(RzCore *core, const char *symname, ut64 *symbol) {
	RzListIter *iter;
	RzDebugMap *map;
	const char *jemalloc_path = NULL;
	ut64 jemalloc_addr = UT64_MAX;
	const char *binary_path = NULL;
	ut64 binary_addr = UT64_MAX;

	if (!core || !core->dbg || !core->dbg->maps) {
		return false;
	}
	rz_debug_map_sync(core->dbg);

	rz_list_foreach (core->dbg->maps, iter, map) {
		if (strstr(map->name, "libjemalloc.")) {
			if (jemalloc_addr == UT64_MAX || map->addr < jemalloc_addr) {
				jemalloc_addr = map->addr;
				jemalloc_path = map->name;
			}
		}
		if (!strstr(map->name, ".so") && !strstr(map->name, "lib") &&
			!strstr(map->name, "[") && strlen(map->name) > 0) {
			if (binary_addr == UT64_MAX || map->addr < binary_addr) {
				binary_addr = map->addr;
				binary_path = map->name;
			}
		}
	}

	// Try dynamic library first
	if (jemalloc_path) {
		char *path = rz_str_newf("%s", jemalloc_path);
		if (rz_file_exists(path)) {
			bool is_pie = false;
			ut64 vaddr = je_get_va_symbol(core, path, symname, &is_pie);
			if (jemalloc_addr != UT64_MAX && vaddr != UT64_MAX) {
				// For shared libraries, always add base address
				*symbol = jemalloc_addr + vaddr;
				free(path);
				return true;
			}
		}
		free(path);
	}

	// Fall back to static linking
	if (binary_path) {
		char *path = rz_str_newf("%s", binary_path);
		if (rz_file_exists(path)) {
			bool is_pie = false;
			ut64 vaddr = je_get_va_symbol(core, path, symname, &is_pie);
			if (binary_addr != UT64_MAX && vaddr != UT64_MAX) {
				// For PIE binaries, add base address (Linux PIE binaries)
				// For non-PIE binaries, vaddr is already absolute (FreeBSD non-PIE)
				*symbol = is_pie ? (binary_addr + vaddr) : vaddr;
				free(path);
				return true;
			}
		}
		free(path);
	}
	return false;
}

/**
 * \brief Detect jemalloc version by checking for version-specific symbols
 *
 * jemalloc 4.x has je_chunksize symbol (chunk-based architecture)
 * jemalloc 5.x does NOT have je_chunksize (extent-based architecture)
 */
static bool rz_jemalloc_detect_version(RzCore *core) {
	ut64 chunksize_addr;
	const char *current_version = rz_config_get(core->config, "dbg.jemalloc.version");

	// Try to resolve je_chunksize - only exists in jemalloc 4.5.0
	if (rz_resolve_jemalloc(core, "je_chunksize", &chunksize_addr)) {
		// je_chunksize found -> jemalloc 4.5.0
		if (strcmp(current_version, "4.5.0") != 0) {
			rz_config_set(core->config, "dbg.jemalloc.version", "4.5.0");
			RZ_LOG_INFO("Detected jemalloc 4.5.0 (je_chunksize symbol found)\n");
		}
		return true;
	} else if (rz_resolve_jemalloc(core, "je_arena_emap_global", &chunksize_addr)) {
		if (strcmp(current_version, "5.3.0") != 0) {
			rz_config_set(core->config, "dbg.jemalloc.version", "5.3.0");
			RZ_LOG_INFO("Detected jemalloc 5.3.0 (je_arena_emap_global symbol found)\n");
		}
		return true;
	} else {
		rz_config_set(core->config, "dbg.jemalloc.version", "NULL");
		RZ_LOG_WARN("jemalloc version cannot be determined\n");
		return false;
	}
}

static inline bool read_ptr_at(RzIO *io, ut64 addr, ut64 *value, ut8 ptr_size) {
	if (ptr_size == 8) {
		ut8 buf[8];
		if (!rz_io_read_at_mapped(io, addr, buf, 8)) {
			return false;
		}
		*value = rz_read_le64(buf);
	} else {
		ut8 buf[4];
		if (!rz_io_read_at_mapped(io, addr, buf, 4)) {
			return false;
		}
		*value = rz_read_le32(buf);
	}
	return true;
}

// ============================================================================
// jemalloc 4.5.0
// ============================================================================

static void jemalloc_get_chunks_450(RzCore *core, bool has_specified_addr, ut64 arena_addr, const RzJemallocConfig450 *config) {
	ut64 cnksz;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!rz_resolve_jemalloc(core, "je_chunksize", &cnksz)) {
		RZ_LOG_ERROR("Fail at reading symbol je_chunksize\n");
		return;
	}
	if (!read_ptr_at(core->io, cnksz, &cnksz, config->ptr_size)) {
		RZ_LOG_ERROR("Failed to read je_chunksize value\n");
		return;
	}

	if (has_specified_addr) {
		arena_t_450 ar;
		extent_node_t_450 node, head;

		if (arena_addr == 0) {
			RZ_LOG_ERROR("need an arena_t_450 to associate chunks\n");
			return;
		}

		if (!read_and_parse_arena_t_450(core->io, arena_addr, &ar, config)) {
			RZ_LOG_ERROR("Failed to read arena at 0x%" PFMT64x "\n", arena_addr);
			return;
		}

		// Read achunks.qlh_first pointer
		ut64 achunks_first = 0;
		if (!read_achunks_first_450(core->io, ar.achunks_addr, &achunks_first, config)) {
			RZ_LOG_ERROR("Failed to read achunks list head\n");
			return;
		}

		if (achunks_first == 0) {
			return;
		}

		if (!read_and_parse_extent_node_t_450(core->io, achunks_first, &head, config)) {
			RZ_LOG_ERROR("Failed to read extent_node\n");
			return;
		}

		if (head.en_addr) {
			PRINT_YA("   Chunk - start: ");
			PRINTF_BA("0x%08" PFMT64x, head.en_addr);
			PRINT_YA(", end: ");
			PRINTF_BA("0x%08" PFMT64x, head.en_addr + cnksz);
			PRINT_YA(", size: ");
			PRINTF_BA("0x%08" PFMT64x "\n", cnksz);

			ut64 next_addr = head.ql_link_next;
			while (next_addr && read_and_parse_extent_node_t_450(core->io, next_addr, &node, config)) {
				if (node.en_addr == head.en_addr) {
					break;
				}
				PRINT_YA("   Chunk - start: ");
				PRINTF_BA("0x%08" PFMT64x, node.en_addr);
				PRINT_YA(", end: ");
				PRINTF_BA("0x%" PFMT64x, node.en_addr + cnksz);
				PRINT_YA(", size: ");
				PRINTF_BA("0x%08" PFMT64x "\n", cnksz);
				next_addr = node.ql_link_next;
			}
		}
	} else {
		int i = 0;
		ut64 sym;
		ut64 arenas_ptr = UT64_MAX;
		ut64 arena_addr = UT64_MAX;
		arena_t_450 ar;
		extent_node_t_450 node, head;

		if (!rz_resolve_jemalloc(core, "je_arenas", &sym)) {
			RZ_LOG_ERROR("Cannot resolve je_arenas\n");
			return;
		}

		if (!read_ptr_at(core->io, sym, &arenas_ptr, config->ptr_size)) {
			RZ_LOG_ERROR("Failed to read je_arenas pointer\n");
			return;
		}

		for (;;) {
			if (!read_ptr_at(core->io, arenas_ptr + i * config->ptr_size, &arena_addr, config->ptr_size)) {
				break;
			}
			if (!arena_addr) {
				break;
			}

			PRINTF_GA("arenas[%d]: @ 0x%" PFMT64x " { \n", i++, arena_addr);

			if (!read_and_parse_arena_t_450(core->io, arena_addr, &ar, config)) {
				PRINT_GA("}\n");
				continue;
			}

			ut64 achunks_first = 0;
			if (!read_achunks_first_450(core->io, ar.achunks_addr, &achunks_first, config) ||
				achunks_first == 0) {
				PRINT_GA("}\n");
				continue;
			}

			if (!read_and_parse_extent_node_t_450(core->io, achunks_first, &head, config)) {
				PRINT_GA("}\n");
				continue;
			}

			if (head.en_addr != 0) {
				PRINT_YA("   Chunk - start: ");
				PRINTF_BA("0x%08" PFMT64x, head.en_addr);
				PRINT_YA(", end: ");
				PRINTF_BA("0x%" PFMT64x, head.en_addr + cnksz);
				PRINT_YA(", size: ");
				PRINTF_BA("0x%08" PFMT64x "\n", cnksz);

				ut64 next_addr = head.ql_link_next;
				while (next_addr && read_and_parse_extent_node_t_450(core->io, next_addr, &node, config)) {
					if (node.en_addr == head.en_addr) {
						break;
					}
					PRINT_YA("   Chunk - start: ");
					PRINTF_BA("0x%08" PFMT64x, node.en_addr);
					PRINT_YA(", end: ");
					PRINTF_BA("0x%" PFMT64x, node.en_addr + cnksz);
					PRINT_YA(", size: ");
					PRINTF_BA("0x%" PFMT64x "\n", cnksz);
					next_addr = node.ql_link_next;
				}
			}
			PRINT_GA("}\n");
		}
	}
}

static void jemalloc_print_narenas_450(RzCore *core, bool has_specified_addr, ut64 addr, const RzJemallocConfig450 *config) {
	ut64 symaddr;
	ut64 arenas;
	ut64 arena_addr = UT64_MAX;
	int i = 0;
	ut64 narenas = 0;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!has_specified_addr) {
		if (rz_resolve_jemalloc(core, "narenas_total", &symaddr)) {
			if (!read_ptr_at(core->io, symaddr, &narenas, config->ptr_size)) {
				RZ_LOG_ERROR("Failed to read narenas_total\n");
				return;
			}
			PRINTF_GA("narenas : %" PFMT64d "\n", narenas);
		}
		if (narenas == 0) {
			RZ_LOG_ERROR("No arenas allocated.\n");
			return;
		}
		if (narenas == UT64_MAX) {
			RZ_LOG_ERROR("Cannot find narenas_total\n");
			return;
		}

		if (rz_resolve_jemalloc(core, "je_arenas", &arenas)) {
			if (!read_ptr_at(core->io, arenas, &arenas, config->ptr_size)) {
				RZ_LOG_ERROR("Failed to read je_arenas pointer\n");
				return;
			}
			PRINTF_GA("arenas[%" PFMT64d "] @ 0x%" PFMT64x " {\n", narenas, arenas);
			for (i = 0; i < (int)narenas; i++) {
				ut64 at = arenas + (i * config->ptr_size);
				if (!read_ptr_at(core->io, at, &arena_addr, config->ptr_size)) {
					continue;
				}
				if (!arena_addr) {
					PRINTF_YA("  arenas[%d]: (empty)\n", i);
					continue;
				}
				PRINTF_YA("  arenas[%d]: ", i);
				PRINTF_BA("@ 0x%" PFMT64x "\n", arena_addr);
			}
		}
		PRINT_GA("}\n");
	} else {
		arena_t_450 ar;
		arena_addr = addr;
		if (!read_and_parse_arena_t_450(core->io, arena_addr, &ar, config)) {
			RZ_LOG_ERROR("Failed to read arena at 0x%" PFMT64x "\n", arena_addr);
			return;
		}

		PRINT_GA("struct arena_s {\n");
		PRINTF_BA("  ind = 0x%x\n", ar.ind);
		PRINTF_BA("  nthreads: application allocation = 0x%x\n", ar.nthreads[0]);
		PRINTF_BA("  nthreads: internal metadata allocation = 0x%x\n", ar.nthreads[1]);
		PRINTF_BA("  lock = 0x%" PFMT64x "\n", ar.lock_addr);
		PRINTF_BA("  stats = 0x%" PFMT64x "\n", ar.stats_addr);
		PRINTF_BA("  tcache_ql = 0x%" PFMT64x "\n", ar.tcache_ql_addr);
		PRINTF_BA("  prof_accumbytes = 0x%" PFMT64x "x\n", ar.prof_accumbytes);
		PRINTF_BA("  offset_state = 0x%" PFMT64x "\n", ar.offset_state);
		PRINTF_BA("  dss_prec_t = 0x%x\n", ar.dss_prec);
		PRINTF_BA("  achunks = 0x%" PFMT64x "\n", ar.achunks_addr);
		PRINTF_BA("  extent_sn_next = 0x%" PFMT64x "\n", ar.extent_sn_next);
		PRINTF_BA("  spare = 0x%" PFMT64x "\n", ar.spare);
		PRINTF_BA("  lg_dirty_mult = 0x%" PFMT64x "\n", (ut64)ar.lg_dirty_mult);
		PRINTF_BA("  purging = %s\n", rz_str_bool(ar.purging));
		PRINTF_BA("  nactive = 0x%" PFMT64x "\n", ar.nactive);
		PRINTF_BA("  ndirty = 0x%" PFMT64x "\n", ar.ndirty);
		PRINTF_BA("  runs_dirty = 0x%" PFMT64x "\n", ar.runs_dirty_addr);
		PRINTF_BA("  chunks_cache = 0x%" PFMT64x "\n", ar.chunks_cache_addr);
		PRINTF_BA("  huge = 0x%" PFMT64x "\n", ar.huge_addr);
		PRINTF_BA("  huge_mtx = 0x%" PFMT64x "\n", ar.huge_mtx_addr);
		PRINTF_BA("  chunks_szsnad_cached = 0x%" PFMT64x "\n", ar.chunks_szsnad_cached_addr);
		PRINTF_BA("  chunks_ad_cached = 0x%" PFMT64x "\n", ar.chunks_ad_cached_addr);
		PRINTF_BA("  chunks_szsnad_retained = 0x%" PFMT64x "\n", ar.chunks_szsnad_cached_addr);
		PRINTF_BA("  chunks_ad_cached = 0x%" PFMT64x "\n", ar.chunks_ad_cached_addr);
		PRINTF_BA("  chunks_mtx = 0x%" PFMT64x "\n", ar.chunks_mtx_addr);
		PRINTF_BA("  node_cache = 0x%" PFMT64x "\n", ar.node_cache_addr);
		PRINTF_BA("  node_cache_mtx = 0x%" PFMT64x "\n", ar.node_cache_mtx_addr);
		PRINTF_BA("  chunks_hooks = 0x%" PFMT64x "\n", ar.chunk_hooks_addr);
		PRINTF_BA("  bins = %d 0x%" PFMT64x "\n", config->sc_nbins, ar.bins_addr);
		PRINTF_BA("  runs_avail = %d 0x%" PFMT64x "\n", config->npsizes, ar.runs_avail_addr);
		PRINT_GA("}\n");
	}
}

// Helper to print bin info for a single arena
static void jemalloc_print_arena_bins_450(RzCore *core, ut64 arena_addr, ut64 bin_info, RzConsPrintablePalette *pal, const RzJemallocConfig450 *config) {
	arena_bin_info_t_450 b;

	for (ut32 j = 0; j < config->sc_nbins; j++) {
		if (!read_and_parse_arena_bin_info_t_450(core->io, bin_info + j * config->bin_info_size, &b, config)) {
			continue;
		}
		PRINT_YA("    {\n");
		PRINT_YA("       regsize : ");
		PRINTF_BA("0x%" PFMT64x "\n", b.reg_size);
		PRINT_YA("       redzone size ");
		PRINTF_BA("0x%" PFMT64x "\n", b.redzone_size);
		PRINT_YA("       reg_interval : ");
		PRINTF_BA("0x%" PFMT64x "\n", b.reg_interval);
		PRINT_YA("       run_size : ");
		PRINTF_BA("0x%" PFMT64x "\n", b.run_size);
		PRINT_YA("       nregs : ");
		PRINTF_BA("0x%x\n", b.nregs);
		PRINT_YA("       reg0_offset : ");
		PRINTF_BA("0x%x\n\n", b.reg0_offset);
		PRINT_YA("    }\n");
	}
}

static void jemalloc_get_bins_450(RzCore *core, bool has_specified_addr, ut64 addr, bool has_bin_info,
	ut64 bin_info_addr, const RzJemallocConfig450 *config) {
	ut64 bin_info = 0;
	ut64 arenas = 0;
	ut64 arena_addr = UT64_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	int i = 0;

	if (!has_specified_addr) {
		// No argument - use symbol resolution (debug mode)
		if (!rz_resolve_jemalloc(core, "je_arena_bin_info", &bin_info)) {
			RZ_LOG_ERROR("Cannot resolve je_arena_bin_info\n");
			return;
		}
		if (rz_resolve_jemalloc(core, "je_arenas", &arenas)) {
			if (!read_ptr_at(core->io, arenas, &arenas, config->ptr_size)) {
				RZ_LOG_ERROR("Failed to read je_arenas pointer\n");
				return;
			}
			PRINTF_GA("arenas @ 0x%" PFMT64x " {\n", arenas);
			for (;;) {
				if (!read_ptr_at(core->io, arenas + i * config->ptr_size, &arena_addr, config->ptr_size)) {
					break;
				}
				if (!arena_addr) {
					break;
				}
				PRINTF_YA("  arenas[%d]: @ 0x%" PFMT64x " {\n", i++, arena_addr);
				jemalloc_print_arena_bins_450(core, arena_addr, bin_info, pal, config);
				PRINT_YA("  }\n");
			}
		}
		PRINT_GA("}\n");
	} else {
		// Static mode - requires two arguments: dmxb <arena_addr> <bin_info_addr>
		arena_addr = addr;
		if (!has_bin_info) {
			RZ_LOG_ERROR("Usage: dmxb <arena_addr> <bin_info_addr>\n");
			return;
		}

		PRINTF_GA("arena_t @ 0x%" PFMT64x " bins[%d] {\n", arena_addr, config->sc_nbins);
		jemalloc_print_arena_bins_450(core, arena_addr, bin_info_addr, pal, config);
		PRINT_GA("}\n");
	}
}

// ============================================================================
// jemalloc 5.3.0
// ============================================================================

static void jemalloc_print_extent_info_530(RzCore *core, ut64 edata_addr, const RzJemallocConfig530 *config) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	edata_t_530 edata;
	static const char *state_names[] = { "Active", "Dirty", "Muzzy", "Retained" };

	if (!read_and_parse_edata_t_530(core->io, edata_addr, &edata, config)) {
		RZ_LOG_ERROR("Failed to read edata at 0x%" PFMT64x "\n", edata_addr);
		return;
	}

	ut64 e_bits = edata.e_bits;
	ut64 e_addr = edata.e_addr;
	ut64 e_size = edata.e_size_esn & ~((ut64)(1 << config->lg_page) - 1);
	ut32 state = (e_bits & EDATA_BITS_STATE_MASK) >> EDATA_BITS_STATE_SHIFT;
	bool slab = (e_bits & EDATA_BITS_SLAB_MASK) >> EDATA_BITS_SLAB_SHIFT;

	PRINT_YA("Extent @ ");
	PRINTF_BA("0x%" PFMT64x "\n", edata_addr);
	PRINT_YA("  Allocated Address: ");
	PRINTF_BA("0x%" PFMT64x "\n", e_addr);
	PRINT_YA("  Size: ");
	PRINTF_BA("0x%" PFMT64x "\n", e_size);
	PRINT_YA("  Small class (slab): ");
	PRINTF_BA("%s\n", slab ? "true" : "false");
	PRINT_YA("  State: ");
	PRINTF_BA("%s\n", state < 4 ? state_names[state] : "Unknown");
}

static void jemalloc_process_leaf_elm_530(RzCore *core, ut64 leaf_addr, const RzJemallocConfig530 *config,
	HtUU *seen_extents, ut32 *extent_count) {
	rtree_leaf_elm_t_530 leaf;

	if (!read_and_parse_rtree_leaf_elm_t_530(core->io, leaf_addr, &leaf, config)) {
		return;
	}

	ut64 edata_addr;
	if (config->rtree_leaf_compact) {
		// Compact leaf format with le_bits
		if (leaf.le_bits == 0) {
			return;
		}
		edata_addr = rtree_leaf_elm_bits_edata_get_530(leaf.le_bits);
	} else {
		// Non-compact format with direct le_edata pointer
		edata_addr = leaf.le_edata;
	}

	if (edata_addr == 0) {
		return;
	}

	// Skip duplicates
	bool found = false;
	ht_uu_find(seen_extents, edata_addr, &found);
	if (found) {
		return;
	}
	ht_uu_insert(seen_extents, edata_addr, 1);

	jemalloc_print_extent_info_530(core, edata_addr, config);
	rz_cons_printf("\n");
	(*extent_count)++;
}

static void jemalloc_enumerate_extents_530(RzCore *core, ut64 rtree_addr, const RzJemallocConfig530 *config) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	HtUU *seen_extents = ht_uu_new();
	if (!seen_extents) {
		RZ_LOG_ERROR("Failed to allocate hash table\n");
		return;
	}

	ut32 lg_page, rtree_nsb, bits_per_level, max_subkeys;
	ut64 root_offset;
	rtree_params_530(config, &lg_page, &rtree_nsb, &bits_per_level, &max_subkeys, &root_offset);

	ut64 root_addr = rtree_addr + root_offset;
	ut32 extent_count = 0;
	ut32 rtree_height = config->rtree_height;

	PRINT_GA("Enumerating extents from rtree...\n");

	if (rtree_height == 2) {
		// 2-level tree: root -> leaf (x86_64, aarch64, i386, arm32)
		for (ut32 i = 0; i < max_subkeys; i++) {
			rtree_node_elm_t_530 node;
			ut64 node_addr = root_addr + i * config->rtree_node_elm_size;

			if (!read_and_parse_rtree_node_elm_t_530(core->io, node_addr, &node, config)) {
				continue;
			}

			ut64 leaf_base = node.child;
			if (leaf_base == 0) {
				continue;
			}

			// Level 2: iterate through leaf nodes
			for (ut32 j = 0; j < max_subkeys; j++) {
				ut64 leaf_addr = leaf_base + j * config->rtree_leaf_elm_size;
				jemalloc_process_leaf_elm_530(core, leaf_addr, config, seen_extents, &extent_count);
			}
		}
	} else if (rtree_height == 3) {
		// 3-level tree: root -> node -> leaf (riscv64)
		for (ut32 i = 0; i < max_subkeys; i++) {
			rtree_node_elm_t_530 level1_node;
			ut64 level1_addr = root_addr + i * config->rtree_node_elm_size;

			if (!read_and_parse_rtree_node_elm_t_530(core->io, level1_addr, &level1_node, config)) {
				continue;
			}

			ut64 level2_base = level1_node.child;
			if (level2_base == 0) {
				continue;
			}

			// Level 2: intermediate nodes
			for (ut32 j = 0; j < max_subkeys; j++) {
				rtree_node_elm_t_530 level2_node;
				ut64 level2_addr = level2_base + j * config->rtree_node_elm_size;

				if (!read_and_parse_rtree_node_elm_t_530(core->io, level2_addr, &level2_node, config)) {
					continue;
				}

				ut64 leaf_base = level2_node.child;
				if (leaf_base == 0) {
					continue;
				}

				// Level 3: leaf nodes
				for (ut32 k = 0; k < max_subkeys; k++) {
					ut64 leaf_addr = leaf_base + k * config->rtree_leaf_elm_size;
					jemalloc_process_leaf_elm_530(core, leaf_addr, config, seen_extents, &extent_count);
				}
			}
		}
	} else {
		RZ_LOG_ERROR("Unsupported rtree height: %u\n", rtree_height);
	}

	PRINTF_GA("Total extents found: %u\n", extent_count);
	ht_uu_free(seen_extents);
}

static ut64 jemalloc_rtree_lookup_530(RzCore *core, ut64 rtree_addr, ut64 addr, const RzJemallocConfig530 *config) {
	ut32 lg_page, rtree_nsb, bits_per_level, max_subkeys;
	ut64 root_offset;
	rtree_params_530(config, &lg_page, &rtree_nsb, &bits_per_level, &max_subkeys, &root_offset);

	// Remove page offset to get the key
	ut64 key = addr >> lg_page;

	ut32 mask = (1U << bits_per_level) - 1;
	ut64 root_addr = rtree_addr + root_offset;
	ut32 rtree_height = config->rtree_height;

	ut64 leaf_base = 0;

	if (rtree_height == 2) {
		// 2-level tree: root -> leaf
		ut32 root_idx = (key >> bits_per_level) & mask;
		ut32 leaf_idx = key & mask;

		rtree_node_elm_t_530 node;
		ut64 node_addr = root_addr + (ut64)root_idx * config->rtree_node_elm_size;
		if (!read_and_parse_rtree_node_elm_t_530(core->io, node_addr, &node, config)) {
			return 0;
		}

		leaf_base = node.child;
		if (leaf_base == 0) {
			return 0;
		}

		rtree_leaf_elm_t_530 leaf;
		ut64 leaf_addr = leaf_base + (ut64)leaf_idx * config->rtree_leaf_elm_size;
		if (!read_and_parse_rtree_leaf_elm_t_530(core->io, leaf_addr, &leaf, config)) {
			return 0;
		}

		if (config->rtree_leaf_compact) {
			if (leaf.le_bits == 0) {
				return 0;
			}
			return rtree_leaf_elm_bits_edata_get_530(leaf.le_bits);
		} else {
			return leaf.le_edata;
		}
	} else if (rtree_height == 3) {
		// 3-level tree: root -> node -> leaf (riscv64)
		ut32 level1_idx = (key >> (2 * bits_per_level)) & mask;
		ut32 level2_idx = (key >> bits_per_level) & mask;
		ut32 leaf_idx = key & mask;

		// Level 1: root node
		rtree_node_elm_t_530 level1_node;
		ut64 level1_addr = root_addr + (ut64)level1_idx * config->rtree_node_elm_size;
		if (!read_and_parse_rtree_node_elm_t_530(core->io, level1_addr, &level1_node, config)) {
			return 0;
		}

		ut64 level2_base = level1_node.child;
		if (level2_base == 0) {
			return 0;
		}

		// Level 2: intermediate node
		rtree_node_elm_t_530 level2_node;
		ut64 level2_addr = level2_base + (ut64)level2_idx * config->rtree_node_elm_size;
		if (!read_and_parse_rtree_node_elm_t_530(core->io, level2_addr, &level2_node, config)) {
			return 0;
		}

		leaf_base = level2_node.child;
		if (leaf_base == 0) {
			return 0;
		}

		// Level 3: leaf
		rtree_leaf_elm_t_530 leaf;
		ut64 leaf_addr = leaf_base + (ut64)leaf_idx * config->rtree_leaf_elm_size;
		if (!read_and_parse_rtree_leaf_elm_t_530(core->io, leaf_addr, &leaf, config)) {
			return 0;
		}

		if (config->rtree_leaf_compact) {
			if (leaf.le_bits == 0) {
				return 0;
			}
			return rtree_leaf_elm_bits_edata_get_530(leaf.le_bits);
		} else {
			return leaf.le_edata;
		}
	}

	return 0;
}

static void jemalloc_find_extent_530(RzCore *core, bool has_specified_addr, ut64 addr, const RzJemallocConfig530 *config) {
	ut64 je_arena_emap_global_addr;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!has_specified_addr) {
		// No argument: enumerate all extents
		if (rz_resolve_jemalloc(core, "je_arena_emap_global", &je_arena_emap_global_addr)) {
			jemalloc_enumerate_extents_530(core, je_arena_emap_global_addr, config);
		} else {
			RZ_LOG_ERROR("Cannot resolve je_arena_emap_global\n");
		}
	} else {
		// Address argument: lookup single address in rtree
		if (!rz_resolve_jemalloc(core, "je_arena_emap_global", &je_arena_emap_global_addr)) {
			RZ_LOG_ERROR("Cannot resolve je_arena_emap_global\n");
			return;
		}

		ut64 edata_addr = jemalloc_rtree_lookup_530(core, je_arena_emap_global_addr, addr, config);
		if (edata_addr == 0) {
			PRINTF_RA("No extent found for address 0x%" PFMT64x "\n", addr);
			return;
		}

		jemalloc_print_extent_info_530(core, edata_addr, config);
	}
}

static void jemalloc_extent_info_530(RzCore *core, bool has_specified_addr, ut64 edata_addr, const RzJemallocConfig530 *config) {
	if (!has_specified_addr) {
		RZ_LOG_ERROR("Usage: dmxei <edata_addr>\n");
		return;
	}

	jemalloc_print_extent_info_530(core, edata_addr, config);
}

static void jemalloc_print_arena_bins_530(RzCore *core, ut64 arena, ut64 bin_info_addr, const RzJemallocConfig530 *config) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	bin_info_t_530 bin_info;
	bin_t_530 bin;

	ut64 bins_off = config->arena_offsets.bins;

	for (ut32 j = 0; j < config->sc_nbins; j++) {
		if (!read_and_parse_bin_info_t_530(core->io, bin_info_addr + j * config->bin_info_size, &bin_info, config)) {
			continue;
		}

		ut64 bin_addr = arena + bins_off + j * config->bin_size;
		if (!read_and_parse_bin_t_530(core->io, bin_addr, &bin, config)) {
			continue;
		}

		PRINTF_YA("    bin[%d] @ 0x%" PFMT64x " {\n", j, bin_addr);
		PRINT_YA("      reg_size : ");
		PRINTF_BA("0x%" PFMT64x "\n", bin_info.reg_size);
		PRINT_YA("      slab_size : ");
		PRINTF_BA("0x%" PFMT64x "\n", bin_info.slab_size);
		PRINT_YA("      nregs : ");
		PRINTF_BA("0x%x\n", bin_info.nregs);
		PRINT_YA("      n_shards : ");
		PRINTF_BA("0x%x\n", bin_info.n_shards);
		PRINT_YA("      slabcur : ");
		PRINTF_BA("0x%" PFMT64x "\n", bin.slabcur);
		PRINT_YA("    }\n");
	}
}

static void jemalloc_get_bins_530(RzCore *core, bool has_specified_addr, ut64 addr, bool has_bin_info,
	ut64 bin_info_addr, const RzJemallocConfig530 *config) {
	int i = 0;
	ut64 bin_info = 0;
	ut64 arenas_sym = 0;
	ut64 arena_addr = UT64_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!has_specified_addr) {
		// No argument - use symbol resolution (debug mode)
		if (!rz_resolve_jemalloc(core, "je_bin_infos", &bin_info)) {
			RZ_LOG_ERROR("Cannot resolve je_bin_infos\n");
			return;
		}
		if (rz_resolve_jemalloc(core, "je_arenas", &arenas_sym)) {
			PRINTF_GA("arenas @ 0x%" PFMT64x " {\n", arenas_sym);
			for (;;) {
				if (!read_ptr_at(core->io, arenas_sym + i * config->ptr_size, &arena_addr, config->ptr_size)) {
					break;
				}
				if (!arena_addr) {
					break;
				}
				PRINTF_YA("  arenas[%d]: @ 0x%" PFMT64x " {\n", i++, arena_addr);
				jemalloc_print_arena_bins_530(core, arena_addr, bin_info, config);
				PRINT_YA("  }\n");
			}
		}
		PRINT_GA("}\n");
	} else {
		// Static mode - requires two arguments: dmxb <arena_addr> <bin_info_addr>
		arena_addr = addr;
		if (!has_bin_info) {
			RZ_LOG_ERROR("Usage: dmxb <arena_addr> <bin_info_addr>\n");
			return;
		}

		PRINTF_GA("arena_t @ 0x%" PFMT64x " bins[%d] {\n", arena_addr, config->sc_nbins);
		jemalloc_print_arena_bins_530(core, arena_addr, bin_info_addr, config);
		PRINT_GA("}\n");
	}
}

static void jemalloc_print_narenas_530(RzCore *core, bool has_specified_addr, ut64 addr, const RzJemallocConfig530 *config) {
	ut64 symaddr;
	ut64 arenas;
	ut64 arena_addr = UT64_MAX;
	int i = 0;
	ut64 narenas = 0;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!has_specified_addr) { // no args, list all arenas
		if (rz_resolve_jemalloc(core, "narenas_total", &symaddr)) {
			if (!read_ptr_at(core->io, symaddr, &narenas, config->ptr_size)) {
				RZ_LOG_ERROR("Failed to read narenas_total\n");
				return;
			}
			PRINTF_GA("narenas : %" PFMT64d "\n", narenas);
		}
		if (narenas == 0) {
			RZ_LOG_ERROR("No arenas allocated.\n");
			return;
		}
		if (narenas == UT64_MAX) {
			RZ_LOG_ERROR("Cannot find narenas_total\n");
			return;
		}

		if (rz_resolve_jemalloc(core, "je_arenas", &arenas)) {
			PRINTF_GA("arenas[%" PFMT64d "] @ 0x%" PFMT64x " {\n", narenas, arenas);
			for (i = 0; i < (int)narenas; i++) {
				ut64 at = arenas + (i * config->ptr_size);
				if (!read_ptr_at(core->io, at, &arena_addr, config->ptr_size)) {
					continue;
				}
				if (!arena_addr) {
					PRINTF_YA("  arenas[%d]: (empty)\n", i);
					continue;
				}
				PRINTF_YA("  arenas[%d]: ", i);
				PRINTF_BA("@ 0x%" PFMT64x "\n", arena_addr);
			}
		}
		PRINT_GA("}\n");
	} else {
		arena_t_530 ar;
		arena_addr = addr;
		if (!read_and_parse_arena_t_530(core->io, arena_addr, &ar, config)) {
			RZ_LOG_ERROR("Failed to read arena at 0x%" PFMT64x "\n", arena_addr);
			return;
		}

		PRINT_GA("struct arena_s {\n");
		PRINTF_BA("  ind = 0x%x\n", ar.ind);
		PRINTF_BA("  nthreads: application allocation = 0x%x\n", ar.nthreads[0]);
		PRINTF_BA("  nthreads: internal metadata allocation = 0x%x\n", ar.nthreads[1]);
		PRINTF_BA("  binshard_next = 0x%x\n", ar.binshard_next);
		PRINTF_BA("  last_thd = 0x%" PFMT64x "\n", ar.last_thd);
		PRINTF_BA("  stats = 0x%" PFMT64x "\n", ar.stats_addr);
		PRINTF_BA("  tcache_ql = 0x%" PFMT64x "\n", ar.tcache_ql_addr);
		PRINTF_BA("  cache_bin_array_descriptor_ql = 0x%" PFMT64x "\n", ar.cache_bin_array_descriptor_ql_addr);
		PRINTF_BA("  tcache_ql_mtx = 0x%" PFMT64x "\n", ar.tcache_ql_mtx_addr);
		PRINTF_BA("  dss_prec = 0x%x\n", ar.dss_prec);
		PRINTF_BA("  large = 0x%" PFMT64x "\n", ar.large_addr);
		PRINTF_BA("  large_mtx = 0x%" PFMT64x "\n", ar.large_mtx_addr);
		PRINTF_BA("  pa_shard = 0x%" PFMT64x "\n", ar.pa_shard_addr);
		PRINTF_BA("  base = 0x%" PFMT64x "\n", ar.base);
		PRINTF_BA("  create_time.ns = 0x%" PFMT64x "\n", ar.create_time_ns);
		PRINTF_BA("  bins = 0x%" PFMT64x "\n", ar.bins_addr);
		PRINT_GA("}\n");
	}
}

// ============================================================================
// page size detection
// ============================================================================

static const char *detect_page_size_from_smaps(int pid) {
#if __linux__
	if (pid <= 0) {
		return NULL;
	}

	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/smaps", pid);

	FILE *f = fopen(path, "r");
	if (!f) {
		return NULL;
	}

	char line[256];
	const char *result = NULL;
	while (fgets(line, sizeof(line), f)) {
		int page_kb = 0;
		if (sscanf(line, "KernelPageSize: %d kB", &page_kb) == 1) {
			switch (page_kb) {
			case 4:
				result = "4k";
				break;
			case 16:
				result = "16k";
				break;
			case 64:
				result = "64k";
				break;
			default:
				result = "4k";
				break;
			}
			break;
		}
	}
	fclose(f);
	return result;
#else
	return NULL;
#endif
}

static const char *detect_page_size(RzCore *core, const char *arch, const char *os, int bits) {
	const char *page_size = rz_config_get(core->config, "dbg.jemalloc.page_size");
	if (page_size && strcmp(page_size, "auto") != 0) {
		return page_size;
	}

	bool is_darwin = os && (!strcmp(os, "darwin") || !strcmp(os, "macos") || !strcmp(os, "ios"));
	bool is_linux = os && !strcmp(os, "linux");
	bool is_aarch64 = arch && (!strcmp(arch, "arm") || !strcmp(arch, "aarch64")) && bits == 64;

	// darwin on aarch64: always 16KB
	if (is_darwin && is_aarch64) {
		return "16k";
	}

	// aarch64 linux: Can be 4k, 16k, or 64k
	if (is_linux && is_aarch64) {
		int pid = core->dbg ? core->dbg->pid : -1;
		const char *detected = detect_page_size_from_smaps(pid);
		if (detected) {
			return detected;
		}
		// Fall back to 4k (most common)
	}

	// everything else: 4k (x86, x86_64, riscv, arm32)
	return "4k";
}

typedef enum {
	JEMALLOC_VERSION_UNKNOWN,
	JEMALLOC_VERSION_450,
	JEMALLOC_VERSION_530,
} JemallocVersion;

static JemallocVersion jemalloc_get_version_kind(RzCore *core) {
	const char *version = rz_config_get(core->config, "dbg.jemalloc.version");
	if (!version || strcmp(version, "auto") == 0 || strcmp(version, "NULL") == 0 || version[0] == '\0') {
		rz_jemalloc_detect_version(core);
		version = rz_config_get(core->config, "dbg.jemalloc.version");
	}

	if (version && strcmp(version, "4.5.0") == 0) {
		return JEMALLOC_VERSION_450;
	}
	if (version && strcmp(version, "5.3.0") == 0) {
		return JEMALLOC_VERSION_530;
	}
	return JEMALLOC_VERSION_UNKNOWN;
}

static bool jemalloc_get_common_params(RzCore *core, const char **arch, const char **os, int *bits,
	const char **page_size, JemallocVersion *version) {
	*arch = rz_config_get(core->config, "asm.arch");
	*os = rz_config_get(core->config, "asm.os");
	*bits = rz_config_get_i(core->config, "asm.bits");
	*page_size = detect_page_size(core, *arch, *os, *bits);
	*version = jemalloc_get_version_kind(core);

	if (*version == JEMALLOC_VERSION_UNKNOWN) {
		RZ_LOG_ERROR("Unknown jemalloc version. Please set dbg.jemalloc.version to '4.5.0' or '5.3.0'\n");
		return false;
	}
	return true;
}

RZ_IPI RzCmdStatus rz_heap_jemalloc_cmd_a(RzCore *core, bool has_specified_addr, ut64 addr) {
	const char *arch = NULL;
	const char *os = NULL;
	const char *page_size = NULL;
	int bits = 0;
	JemallocVersion version = JEMALLOC_VERSION_UNKNOWN;

	if (!jemalloc_get_common_params(core, &arch, &os, &bits, &page_size, &version)) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (version == JEMALLOC_VERSION_450) {
		const RzJemallocConfig450 *config = rz_jemalloc_get_config_450(arch, os, bits, page_size);
		if (!config) {
			RZ_LOG_ERROR("Failed to get jemalloc 4.5.0 configuration\n");
			return RZ_CMD_STATUS_ERROR;
		}
		jemalloc_print_narenas_450(core, has_specified_addr, addr, config);
		return RZ_CMD_STATUS_OK;
	}

	const RzJemallocConfig530 *config = rz_jemalloc_get_config_530(arch, os, bits, page_size);
	if (!config) {
		RZ_LOG_ERROR("Failed to get jemalloc 5.3.0 configuration\n");
		return RZ_CMD_STATUS_ERROR;
	}
	jemalloc_print_narenas_530(core, has_specified_addr, addr, config);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_heap_jemalloc_cmd_b(RzCore *core, bool has_specified_addr, ut64 addr, bool has_bin_info, ut64 bin_info_addr) {
	const char *arch = NULL;
	const char *os = NULL;
	const char *page_size = NULL;
	int bits = 0;
	JemallocVersion version = JEMALLOC_VERSION_UNKNOWN;

	if (!jemalloc_get_common_params(core, &arch, &os, &bits, &page_size, &version)) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (version == JEMALLOC_VERSION_450) {
		const RzJemallocConfig450 *config = rz_jemalloc_get_config_450(arch, os, bits, page_size);
		if (!config) {
			RZ_LOG_ERROR("Failed to get jemalloc 4.5.0 configuration\n");
			return RZ_CMD_STATUS_ERROR;
		}
		jemalloc_get_bins_450(core, has_specified_addr, addr, has_bin_info, bin_info_addr, config);
		return RZ_CMD_STATUS_OK;
	}

	const RzJemallocConfig530 *config = rz_jemalloc_get_config_530(arch, os, bits, page_size);
	if (!config) {
		RZ_LOG_ERROR("Failed to get jemalloc 5.3.0 configuration\n");
		return RZ_CMD_STATUS_ERROR;
	}
	jemalloc_get_bins_530(core, has_specified_addr, addr, has_bin_info, bin_info_addr, config);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_heap_jemalloc_cmd_c(RzCore *core, bool has_specified_addr, ut64 addr) {
	const char *arch = NULL;
	const char *os = NULL;
	const char *page_size = NULL;
	int bits = 0;
	JemallocVersion version = JEMALLOC_VERSION_UNKNOWN;

	if (!jemalloc_get_common_params(core, &arch, &os, &bits, &page_size, &version)) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (version != JEMALLOC_VERSION_450) {
		RZ_LOG_ERROR("Command not supported for jemalloc 5.3.0\n");
		return RZ_CMD_STATUS_ERROR;
	}

	const RzJemallocConfig450 *config = rz_jemalloc_get_config_450(arch, os, bits, page_size);
	if (!config) {
		RZ_LOG_ERROR("Failed to get jemalloc 4.5.0 configuration\n");
		return RZ_CMD_STATUS_ERROR;
	}
	jemalloc_get_chunks_450(core, has_specified_addr, addr, config);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_heap_jemalloc_cmd_e(RzCore *core, bool has_specified_addr, ut64 addr) {
	const char *arch = NULL;
	const char *os = NULL;
	const char *page_size = NULL;
	int bits = 0;
	JemallocVersion version = JEMALLOC_VERSION_UNKNOWN;

	if (!jemalloc_get_common_params(core, &arch, &os, &bits, &page_size, &version)) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (version != JEMALLOC_VERSION_530) {
		RZ_LOG_ERROR("Command not supported for jemalloc 4.5.0\n");
		return RZ_CMD_STATUS_ERROR;
	}

	const RzJemallocConfig530 *config = rz_jemalloc_get_config_530(arch, os, bits, page_size);
	if (!config) {
		RZ_LOG_ERROR("Failed to get jemalloc 5.3.0 configuration\n");
		return RZ_CMD_STATUS_ERROR;
	}
	jemalloc_find_extent_530(core, has_specified_addr, addr, config);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_heap_jemalloc_cmd_ei(RzCore *core, bool has_specified_addr, ut64 addr) {
	const char *arch = NULL;
	const char *os = NULL;
	const char *page_size = NULL;
	int bits = 0;
	JemallocVersion version = JEMALLOC_VERSION_UNKNOWN;

	if (!jemalloc_get_common_params(core, &arch, &os, &bits, &page_size, &version)) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (version != JEMALLOC_VERSION_530) {
		RZ_LOG_ERROR("Command not supported for jemalloc 4.5.0\n");
		return RZ_CMD_STATUS_ERROR;
	}

	const RzJemallocConfig530 *config = rz_jemalloc_get_config_530(arch, os, bits, page_size);
	if (!config) {
		RZ_LOG_ERROR("Failed to get jemalloc 5.3.0 configuration\n");
		return RZ_CMD_STATUS_ERROR;
	}
	jemalloc_extent_info_530(core, has_specified_addr, addr, config);
	return RZ_CMD_STATUS_OK;
}
