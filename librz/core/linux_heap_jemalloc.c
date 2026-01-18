// SPDX-FileCopyrightText: 2017 javierptd <javierptd@gmail.com>
// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef INCLUDE_HEAP_JEMALLOC_STD_C
#define INCLUDE_HEAP_JEMALLOC_STD_C
#include "rz_util/rz_log.h"
#include "time.h"
#define HEAP32 1
#include "linux_heap_jemalloc.c"
#undef HEAP32
#endif

#undef GH
#undef GHT
#undef GHST
#undef GHT_MAX
#undef PFMTx
#undef GH_IS_64

#if HEAP32
#define GH(x)   x##_32
#define GHT     ut32
#define GHST    st32
#define GHT_MAX UT32_MAX
#define PFMTx   PFMT32x
#else
#define GH(x)   x##_64
#define GHT     ut64
#define GHST    st64
#define GHT_MAX UT64_MAX
#define PFMTx   PFMT64x
#define GH_IS_64
#endif

static GHT GH(je_get_va_symbol)(RzCore *core, const char *path, const char *sym_name) {
	GHT vaddr = GHT_MAX;
	RzBin *bin = core->bin;
	RzBinFile *current_bf = rz_bin_cur(bin);
	void **iter;
	RzBinSymbol *s;

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

	rz_bin_file_delete(bin, libc_bf);
	rz_bin_file_set_obj(current_bf, current_bf->o);
	rz_bin_set_cur_binfile(bin, current_bf);
	return vaddr;
}

static bool GH(rz_resolve_jemalloc)(RzCore *core, char *symname, ut64 *symbol) {
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

	/* Try dynamic library first */
	if (jemalloc_path) {
		char *path = rz_str_newf("%s", jemalloc_path);
		if (rz_file_exists(path)) {
			GHT vaddr = GH(je_get_va_symbol)(core, path, symname);
			if (jemalloc_addr != GHT_MAX && vaddr != GHT_MAX) {
				*symbol = jemalloc_addr + vaddr;
				free(path);
				return true;
			}
		}
		free(path);
	}

	/* Fall back to static linking */
	if (binary_path) {
		char *path = rz_str_newf("%s", binary_path);
		if (rz_file_exists(path)) {
			GHT vaddr = GH(je_get_va_symbol)(core, path, symname);
			if (binary_addr != GHT_MAX && vaddr != GHT_MAX) {
				*symbol = binary_addr + vaddr;
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
static bool GH(rz_jemalloc_detect_version)(RzCore *core) {
	ut64 chunksize_addr;
	const char *current_version = rz_config_get(core->config, "dbg.jemalloc.version");

	// Try to resolve je_chunksize - only exists in jemalloc 4.5.0
	if (GH(rz_resolve_jemalloc)(core, "je_chunksize", &chunksize_addr)) {
		// je_chunksize found -> jemalloc 4.5.0
		if (strcmp(current_version, "4.5.0") != 0) {
			rz_config_set(core->config, "dbg.jemalloc.version", "4.5.0");
			RZ_LOG_INFO("Detected jemalloc 4.5.0 (je_chunksize symbol found)\n");
		}
		return true;
	} else if (GH(rz_resolve_jemalloc)(core, "je_arena_emap_global", &chunksize_addr)) {
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

static void GH(jemalloc_get_chunks_450)(RzCore *core, const char *input) {
	ut64 cnksz;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!GH(rz_resolve_jemalloc)(core, "je_chunksize", &cnksz)) {
		RZ_LOG_ERROR("Fail at reading symbol je_chunksize\n");
		return;
	}
	rz_io_read_at_mapped(core->io, cnksz, (ut8 *)&cnksz, sizeof(GHT));

	if (input[0] == '\0') {
		RZ_LOG_ERROR("need an arena_t_450 to associate chunks\n");
	} else if (input[0] != '*') {
		const char *addr_str = (input[0] == ' ') ? input + 1 : input;
		GHT arena = GHT_MAX;
		arena_t_450 *ar = RZ_NEW0(arena_t_450);
		extent_node_t_450 *node = RZ_NEW0(extent_node_t_450), *head = RZ_NEW0(extent_node_t_450);
		arena = rz_num_math(core->num, addr_str);

		if (arena) {
			rz_io_read_at_mapped(core->io, arena, (ut8 *)ar, sizeof(arena_t_450));
			rz_io_read_at_mapped(core->io, (GHT)(size_t)ar->achunks.qlh_first, (ut8 *)head, sizeof(extent_node_t_450));
			if (head->en_addr) {
				PRINT_YA("   Chunk - start: ");
				PRINTF_BA("0x%08" PFMT64x, (ut64)(size_t)head->en_addr);
				PRINT_YA(", end: ");
				PRINTF_BA("0x%08" PFMT64x, (ut64)head->en_addr + cnksz);
				PRINT_YA(", size: ");
				PRINTF_BA("0x%08" PFMT64x "\n", (ut64)cnksz);
				rz_io_read_at_mapped(core->io, (ut64)(size_t)head->ql_link.qre_next, (ut8 *)node, sizeof(extent_node_t_450));
				while (node && node->en_addr != head->en_addr) {
					PRINT_YA("   Chunk - start: ");
					PRINTF_BA("0x%08" PFMT64x, (ut64)(size_t)node->en_addr);
					PRINT_YA(", end: ");
					PRINTF_BA("0x%" PFMT64x, (ut64)node->en_addr + cnksz);
					PRINT_YA(", size: ");
					PRINTF_BA("0x%08" PFMT64x "\n", cnksz);
					rz_io_read_at_mapped(core->io, (ut64)(size_t)node->ql_link.qre_next, (ut8 *)node, sizeof(extent_node_t_450));
				}
			}
		}
		free(ar);
		free(head);
		free(node);
	} else if (input[0] == '*') {
		int i = 0;
		ut64 sym;
		GHT arenas = GHT_MAX, arena = GHT_MAX;
		arena_t_450 *ar = RZ_NEW0(arena_t_450);
		extent_node_t_450 *node = RZ_NEW0(extent_node_t_450);
		extent_node_t_450 *head = RZ_NEW0(extent_node_t_450);

		if (!node || !head) {
			RZ_LOG_ERROR("Failed to allocate extent_node_t_450\n");
			free(ar);
			free(node);
			free(head);
			return;
		}

		if (GH(rz_resolve_jemalloc)(core, "je_arenas", &sym)) {
			rz_io_read_at_mapped(core->io, sym, (ut8 *)&arenas, sizeof(GHT));
			for (;;) {
				rz_io_read_at_mapped(core->io, arenas + i * sizeof(GHT), (ut8 *)&arena, sizeof(GHT));
				if (!arena) {
					break;
				}
				PRINTF_GA("arenas[%d]: @ 0x%" PFMTx " { \n", i++, (GHT)arena);
				rz_io_read_at_mapped(core->io, arena, (ut8 *)ar, sizeof(arena_t_450));
				rz_io_read_at_mapped(core->io, (GHT)(size_t)ar->achunks.qlh_first, (ut8 *)head, sizeof(extent_node_t_450));
				if (head->en_addr != 0) {
					PRINT_YA("   Chunk - start: ");
					PRINTF_BA("0x%08" PFMT64x, (ut64)(size_t)head->en_addr);
					PRINT_YA(", end: ");
					PRINTF_BA("0x%" PFMT64x, (ut64)head->en_addr + cnksz);
					PRINT_YA(", size: ");
					PRINTF_BA("0x%08" PFMT64x "\n", (ut64)cnksz);
					ut64 addr = (ut64)(size_t)head->ql_link.qre_next;
					rz_io_read_at_mapped(core->io, addr, (ut8 *)node, sizeof(extent_node_t_450));
					while (node && head && node->en_addr != head->en_addr) {
						PRINT_YA("   Chunk - start: ");
						PRINTF_BA("0x%08" PFMT64x, (ut64)(size_t)node->en_addr);
						PRINT_YA(", end: ");
						PRINTF_BA("0x%" PFMT64x, (ut64)node->en_addr + cnksz);
						PRINT_YA(", size: ");
						PRINTF_BA("0x%" PFMT64x "\n", cnksz);
						rz_io_read_at_mapped(core->io, (GHT)(size_t)node->ql_link.qre_next, (ut8 *)node, sizeof(extent_node_t_450));
					}
				}
				PRINT_GA("}\n");
			}
		}
		free(ar);
		free(head);
		free(node);
	}
}

static void GH(jemalloc_print_narenas_450)(RzCore *core, const char *input) {
	ut64 symaddr;
	ut64 arenas;
	GHT arena = GHT_MAX;
	arena_t_450 *ar = RZ_NEW0(arena_t_450);
	if (!ar) {
		return;
	}
	GH(arena_stats_t_450) *stats = RZ_NEW0(GH(arena_stats_t_450));
	if (!stats) {
		free(ar);
		return;
	}
	int i = 0;
	GHT narenas = 0;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (input[0] == '\0') {
		if (GH(rz_resolve_jemalloc)(core, "narenas_total", &symaddr)) {
			rz_io_read_at_mapped(core->io, symaddr, (ut8 *)&narenas, sizeof(GHT));
			PRINTF_GA("narenas : %" PFMT64d "\n", (ut64)narenas);
		}
		if (narenas == 0) {
			RZ_LOG_ERROR("No arenas allocated.\n");
			free(stats);
			free(ar);
			return;
		}
		if (narenas == GHT_MAX) {
			RZ_LOG_ERROR("Cannot find narenas_total\n");
			free(stats);
			free(ar);
			return;
		}

		if (GH(rz_resolve_jemalloc)(core, "je_arenas", &arenas)) {
			rz_io_read_at_mapped(core->io, arenas, (ut8 *)&arenas, sizeof(GHT));
			PRINTF_GA("arenas[%" PFMT64d "] @ 0x%" PFMT64x " {\n", (ut64)narenas, (ut64)arenas);
			for (i = 0; i < narenas; i++) {
				ut64 at = arenas + (i * sizeof(GHT));
				rz_io_read_at_mapped(core->io, at, (ut8 *)&arena, sizeof(GHT));
				if (!arena) {
					PRINTF_YA("  arenas[%d]: (empty)\n", i);
					continue;
				}
				PRINTF_YA("  arenas[%d]: ", i);
				PRINTF_BA("@ 0x%" PFMT64x "\n", (ut64)arena);
			}
		}
		PRINT_GA("}\n");
	} else {
		// Handle address argument (with or without leading space)
		const char *addr_str = (input[0] == ' ') ? input + 1 : input;
		arena = rz_num_math(core->num, addr_str);
		rz_io_read_at_mapped(core->io, (GHT)arena, (ut8 *)ar, sizeof(arena_t_450));
		PRINT_GA("struct arena_s {\n");
#define OO(x) (ut64)(arena + rz_offsetof(arena_t_450, x))
		PRINTF_BA("  ind = 0x%x\n", ar->ind);
		PRINTF_BA("  nthreads: application allocation = 0x%" PFMT64x "\n", (ut64)ar->nthreads[0]);
		PRINTF_BA("  nthreads: internal metadata allocation = 0x%" PFMT64x "\n", (ut64)ar->nthreads[1]);
		PRINTF_BA("  lock = 0x%" PFMT64x "\n", OO(lock));
		PRINTF_BA("  stats = 0x%" PFMT64x "\n", OO(stats));
		PRINTF_BA("  tcache_ql = 0x%" PFMT64x "\n", OO(tcache_ql));
		PRINTF_BA("  prof_accumbytes = 0x%" PFMT64x "x\n", (ut64)ar->prof_accumbytes);
		PRINTF_BA("  offset_state = 0x%" PFMT64x "\n", (ut64)ar->offset_state);
		PRINTF_BA("  dss_prec_t = 0x%" PFMT64x "\n", OO(dss_prec));
		PRINTF_BA("  achunks = 0x%" PFMT64x "\n", OO(achunks));
		PRINTF_BA("  extent_sn_next = 0x%" PFMT64x "\n", (ut64)(size_t)ar->extent_sn_next);
		PRINTF_BA("  spare = 0x%" PFMT64x "\n", (ut64)(size_t)ar->spare);
		PRINTF_BA("  lg_dirty_mult = 0x%" PFMT64x "\n", (ut64)(ssize_t)ar->lg_dirty_mult);
		PRINTF_BA("  purging = %s\n", rz_str_bool(ar->purging));
		PRINTF_BA("  nactive = 0x%" PFMT64x "\n", (ut64)(size_t)ar->nactive);
		PRINTF_BA("  ndirty = 0x%" PFMT64x "\n", (ut64)(size_t)ar->ndirty);

		PRINTF_BA("  runs_dirty = 0x%" PFMT64x "\n", OO(runs_dirty));
		PRINTF_BA("  chunks_cache = 0x%" PFMT64x "\n", OO(chunks_cache));
		PRINTF_BA("  huge = 0x%" PFMT64x "\n", OO(huge));
		PRINTF_BA("  huge_mtx = 0x%" PFMT64x "\n", OO(huge_mtx));

		PRINTF_BA("  chunks_szsnad_cached = 0x%" PFMT64x "\n", OO(chunks_szsnad_cached));
		PRINTF_BA("  chunks_ad_cached = 0x%" PFMT64x "\n", OO(chunks_ad_cached));
		PRINTF_BA("  chunks_szsnad_retained = 0x%" PFMT64x "\n", OO(chunks_szsnad_retained));
		PRINTF_BA("  chunks_ad_cached = 0x%" PFMT64x "\n", OO(chunks_ad_retained));

		PRINTF_BA("  chunks_mtx = 0x%" PFMT64x "\n", OO(chunks_mtx));
		PRINTF_BA("  node_cache = 0x%" PFMT64x "\n", OO(node_cache));
		PRINTF_BA("  node_cache_mtx = 0x%" PFMT64x "\n", OO(node_cache_mtx));
		PRINTF_BA("  chunks_hooks = 0x%" PFMT64x "\n", OO(chunk_hooks));
		PRINTF_BA("  bins = %d 0x%" PFMT64x "\n", JM_NBINS, OO(bins));
		PRINTF_BA("  runs_avail = %d 0x%" PFMT64x "\n", GH(NPSIZES), OO(runs_avail));
		PRINT_GA("}\n");
	}
	free(ar);
	free(stats);
}

// Helper to print bin info for a single arena
static void GH(jemalloc_print_arena_bins_450)(RzCore *core, GHT arena, ut64 bin_info, RzConsPrintablePalette *pal) {
	int j;
	arena_t_450 *ar = RZ_NEW0(arena_t_450);
	arena_bin_info_t_450 *b = RZ_NEW0(arena_bin_info_t_450);
	if (!ar || !b) {
		free(ar);
		free(b);
		return;
	}

	rz_io_read_at_mapped(core->io, arena, (ut8 *)ar, sizeof(arena_t_450));
	for (j = 0; j < JM_NBINS; j++) {
		rz_io_read_at_mapped(core->io, (GHT)(bin_info + j * sizeof(arena_bin_info_t_450)),
			(ut8 *)b, sizeof(arena_bin_info_t_450));
		PRINT_YA("    {\n");
		PRINT_YA("       regsize : ");
		PRINTF_BA("0x%" PFMT64x "\n", (ut64)b->reg_size);
		PRINT_YA("       redzone size ");
		PRINTF_BA("0x%" PFMT64x "\n", (ut64)b->redzone_size);
		PRINT_YA("       reg_interval : ");
		PRINTF_BA("0x%" PFMT64x "\n", (ut64)b->reg_interval);
		PRINT_YA("       run_size : ");
		PRINTF_BA("0x%" PFMT64x "\n", (ut64)b->run_size);
		PRINT_YA("       nregs : ");
		PRINTF_BA("0x%x\n", b->nregs);
		PRINT_YA("       reg0_offset : ");
		PRINTF_BA("0x%" PFMT64x "\n\n", (ut64)b->reg0_offset);
		PRINT_YA("    }\n");
	}
	free(ar);
	free(b);
}

static void GH(jemalloc_get_bins_450)(RzCore *core, const char *input) {
	int i = 0;
	ut64 bin_info;
	ut64 arenas;
	GHT arena = GHT_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (input[0] == '\0') {
		// No argument - use symbol resolution (debug mode)
		if (!GH(rz_resolve_jemalloc)(core, "je_arena_bin_info", &bin_info)) {
			RZ_LOG_ERROR("Cannot resolve je_arena_bin_info\n");
			return;
		}
		if (GH(rz_resolve_jemalloc)(core, "je_arenas", &arenas)) {
			rz_io_read_at_mapped(core->io, arenas, (ut8 *)&arenas, sizeof(GHT));
			PRINTF_GA("arenas @ 0x%" PFMTx " {\n", (GHT)arenas);
			for (;;) {
				rz_io_read_at_mapped(core->io, arenas + i * sizeof(GHT), (ut8 *)&arena, sizeof(GHT));
				if (!arena) {
					break;
				}
				PRINTF_YA("  arenas[%d]: @ 0x%" PFMTx " {\n", i++, (GHT)arena);
				GH(jemalloc_print_arena_bins_450)(core, arena, bin_info, pal);
				PRINT_YA("  }\n");
			}
		}
		PRINT_GA("}\n");
	} else {
		// Static mode - requires two arguments: dmxb <arena_addr> <bin_info_addr>
		const char *addr_str = (input[0] == ' ') ? input + 1 : input;

		char *args = strdup(addr_str);
		char *bin_info_str = strchr(args, ' ');

		if (!bin_info_str) {
			RZ_LOG_ERROR("Usage: dmxb <arena_addr> <bin_info_addr>\n");
			free(args);
			return;
		}

		*bin_info_str++ = '\0';
		arena = rz_num_math(core->num, args);
		bin_info = rz_num_math(core->num, bin_info_str);

		PRINTF_GA("arena_t @ 0x%" PFMT64x " bins[%d] {\n", (ut64)arena, JM_NBINS);
		GH(jemalloc_print_arena_bins_450)(core, arena, bin_info, pal);
		PRINT_GA("}\n");

		free(args);
	}
}

#ifndef JEMALLOC_530_DEFINED_ONCE
#define JEMALLOC_530_DEFINED_ONCE

static ut64 je_get_va_symbol_530(RzCore *core, const char *path, const char *sym_name, bool is_64bit) {
	ut64 vaddr = UT64_MAX;
	RzBin *bin = core->bin;
	RzBinFile *current_bf = rz_bin_cur(bin);
	void **iter;
	RzBinSymbol *s;

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

	rz_bin_file_delete(bin, libc_bf);
	rz_bin_file_set_obj(current_bf, current_bf->o);
	rz_bin_set_cur_binfile(bin, current_bf);
	return vaddr;
}

static bool rz_resolve_jemalloc_530(RzCore *core, const char *symname, ut64 *symbol, bool is_64bit) {
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

	/* Try dynamic library first */
	if (jemalloc_path) {
		char *path = rz_str_newf("%s", jemalloc_path);
		if (rz_file_exists(path)) {
			ut64 vaddr = je_get_va_symbol_530(core, path, symname, is_64bit);
			if (jemalloc_addr != UT64_MAX && vaddr != UT64_MAX) {
				*symbol = jemalloc_addr + vaddr;
				free(path);
				return true;
			}
		}
		free(path);
	}

	/* Fall back to static linking */
	if (binary_path) {
		char *path = rz_str_newf("%s", binary_path);
		if (rz_file_exists(path)) {
			ut64 vaddr = je_get_va_symbol_530(core, path, symname, is_64bit);
			if (binary_addr != UT64_MAX && vaddr != UT64_MAX) {
				*symbol = binary_addr + vaddr;
				free(path);
				return true;
			}
		}
		free(path);
	}
	return false;
}

static void jemalloc_print_extent_info_530(RzCore *core, ut64 edata_addr, bool is_64bit) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	edata_t_530 edata;
	static const char *state_names[] = { "Active", "Dirty", "Muzzy", "Retained" };

	if (!read_and_parse_edata_t_530(core->io, edata_addr, &edata, is_64bit)) {
		RZ_LOG_ERROR("Failed to read edata at 0x%" PFMT64x "\n", edata_addr);
		return;
	}

	ut64 e_bits = edata.e_bits;
	ut64 e_addr = edata.e_addr;
	ut64 e_size = edata.e_size_esn & ~((ut64)(1 << LG_PAGE_530) - 1);
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

static void jemalloc_enumerate_extents_530(RzCore *core, ut64 rtree_addr, bool is_64bit) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	HtUU *seen_extents = ht_uu_new();
	if (!seen_extents) {
		RZ_LOG_ERROR("Failed to allocate hash table\n");
		return;
	}

	ut32 lg_page, rtree_nsb, bits_per_level, max_subkeys;
	ut64 root_offset;
	rtree_params_530(is_64bit, &lg_page, &rtree_nsb, &bits_per_level, &max_subkeys, &root_offset);

	ut64 root_addr = rtree_addr + root_offset;
	size_t node_elm_size = rtree_node_elm_size_530(is_64bit);
	size_t leaf_elm_size = rtree_leaf_elm_size_530(is_64bit);
	ut32 extent_count = 0;

	PRINT_GA("Enumerating extents from rtree...\n");

	// Level 1: iterate through root nodes
	for (ut32 i = 0; i < max_subkeys; i++) {
		rtree_node_elm_t_530 node;
		ut64 node_addr = root_addr + i * node_elm_size;

		if (!read_and_parse_rtree_node_elm_t_530(core->io, node_addr, &node, is_64bit)) {
			continue;
		}

		ut64 leaf_base = node.child;
		if (leaf_base == 0) {
			continue;
		}

		// Level 2: iterate through leaf nodes
		for (ut32 j = 0; j < max_subkeys; j++) {
			rtree_leaf_elm_t_530 leaf;
			ut64 leaf_addr = leaf_base + j * leaf_elm_size;

			if (!read_and_parse_rtree_leaf_elm_t_530(core->io, leaf_addr, &leaf, is_64bit)) {
				continue;
			}

			ut64 edata_addr;
			if (is_64bit) {
				// 64-bit uses compact leaf format with le_bits
				if (leaf.le_bits == 0) {
					continue;
				}
				edata_addr = rtree_leaf_elm_bits_edata_get_530(leaf.le_bits);
			} else {
				// 32-bit uses non-compact format with direct le_edata pointer
				edata_addr = leaf.le_edata;
			}

			if (edata_addr == 0) {
				continue;
			}

			// Skip duplicates
			bool found = false;
			ht_uu_find(seen_extents, edata_addr, &found);
			if (found) {
				continue;
			}
			ht_uu_insert(seen_extents, edata_addr, 1);

			jemalloc_print_extent_info_530(core, edata_addr, is_64bit);
			rz_cons_printf("\n");
			extent_count++;
		}
	}

	PRINTF_GA("Total extents found: %u\n", extent_count);
	ht_uu_free(seen_extents);
}

static ut64 jemalloc_rtree_lookup_530(RzCore *core, ut64 rtree_addr, ut64 addr, bool is_64bit) {
	ut32 lg_page, rtree_nsb, bits_per_level, max_subkeys;
	ut64 root_offset;
	rtree_params_530(is_64bit, &lg_page, &rtree_nsb, &bits_per_level, &max_subkeys, &root_offset);

	// Remove page offset to get the key
	ut64 key = addr >> lg_page;

	// Calculate indices for each level
	ut32 mask = (1U << bits_per_level) - 1;
	ut32 root_idx = (key >> bits_per_level) & mask;
	ut32 leaf_idx = key & mask;

	ut64 root_addr = rtree_addr + root_offset;
	size_t node_elm_size = rtree_node_elm_size_530(is_64bit);
	size_t leaf_elm_size = rtree_leaf_elm_size_530(is_64bit);

	// Read root node to get leaf array base
	rtree_node_elm_t_530 node;
	ut64 node_addr = root_addr + (ut64)root_idx * node_elm_size;
	if (!read_and_parse_rtree_node_elm_t_530(core->io, node_addr, &node, is_64bit)) {
		return 0;
	}

	ut64 leaf_base = node.child;
	if (leaf_base == 0) {
		return 0;
	}

	rtree_leaf_elm_t_530 leaf;
	ut64 leaf_addr = leaf_base + (ut64)leaf_idx * leaf_elm_size;
	if (!read_and_parse_rtree_leaf_elm_t_530(core->io, leaf_addr, &leaf, is_64bit)) {
		return 0;
	}

	if (is_64bit) {
		if (leaf.le_bits == 0) {
			return 0;
		}
		return rtree_leaf_elm_bits_edata_get_530(leaf.le_bits);
	} else {
		return leaf.le_edata;
	}
}

static void jemalloc_find_extent_530(RzCore *core, const char *input, bool is_64bit) {
	ut64 je_arena_emap_global_addr;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (input[0] == '\0') {
		/* No argument: enumerate all extents */
		if (rz_resolve_jemalloc_530(core, "je_arena_emap_global", &je_arena_emap_global_addr, is_64bit)) {
			jemalloc_enumerate_extents_530(core, je_arena_emap_global_addr, is_64bit);
		} else {
			RZ_LOG_ERROR("Cannot resolve je_arena_emap_global\n");
		}
	} else {
		/* Address argument: lookup single address in rtree */
		const char *addr_str = (input[0] == ' ') ? input + 1 : input;
		ut64 lookup_addr = rz_num_math(core->num, addr_str);

		if (!rz_resolve_jemalloc_530(core, "je_arena_emap_global", &je_arena_emap_global_addr, is_64bit)) {
			RZ_LOG_ERROR("Cannot resolve je_arena_emap_global\n");
			return;
		}

		ut64 edata_addr = jemalloc_rtree_lookup_530(core, je_arena_emap_global_addr, lookup_addr, is_64bit);
		if (edata_addr == 0) {
			PRINTF_RA("No extent found for address 0x%" PFMT64x "\n", lookup_addr);
			return;
		}

		jemalloc_print_extent_info_530(core, edata_addr, is_64bit);
	}
}

static void jemalloc_extent_info_530(RzCore *core, const char *input, bool is_64bit) {
	if (input[0] == '\0') {
		RZ_LOG_ERROR("Usage: dmxei <edata_addr>\n");
		return;
	}

	const char *addr_str = (input[0] == ' ') ? input + 1 : input;
	ut64 edata_addr = rz_num_math(core->num, addr_str);

	jemalloc_print_extent_info_530(core, edata_addr, is_64bit);
}

static void jemalloc_print_arena_bins_530(RzCore *core, ut64 arena, ut64 bin_info_addr, bool is_64bit) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	bin_info_t_530 bin_info;
	bin_t_530 bin;

	ut64 bins_off = bins_offset_530(is_64bit);
	size_t bin_info_size = bin_info_size_530(is_64bit);
	size_t bin_size = bin_size_530(is_64bit);

	for (int j = 0; j < JM_NBINS_530; j++) {
		if (!read_and_parse_bin_info_t_530(core->io, bin_info_addr + j * bin_info_size, &bin_info, is_64bit)) {
			continue;
		}

		ut64 bin_addr = arena + bins_off + j * bin_size;
		if (!read_and_parse_bin_t_530(core->io, bin_addr, &bin, is_64bit)) {
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

static void jemalloc_get_bins_530(RzCore *core, const char *input, bool is_64bit) {
	int i = 0;
	ut64 bin_info;
	ut64 arenas_sym;
	ut64 arena = UT64_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	size_t ptr_size = is_64bit ? 8 : 4;

	if (input[0] == '\0') {
		// No argument - use symbol resolution (debug mode)
		if (!rz_resolve_jemalloc_530(core, "je_bin_infos", &bin_info, is_64bit)) {
			RZ_LOG_ERROR("Cannot resolve je_bin_infos\n");
			return;
		}
		if (rz_resolve_jemalloc_530(core, "je_arenas", &arenas_sym, is_64bit)) {
			PRINTF_GA("arenas @ 0x%" PFMT64x " {\n", arenas_sym);
			for (;;) {
				if (is_64bit) {
					rz_io_read_at_mapped(core->io, arenas_sym + i * ptr_size, (ut8 *)&arena, ptr_size);
				} else {
					ut32 arena32 = 0;
					rz_io_read_at_mapped(core->io, arenas_sym + i * ptr_size, (ut8 *)&arena32, ptr_size);
					arena = arena32;
				}
				if (!arena) {
					break;
				}
				PRINTF_YA("  arenas[%d]: @ 0x%" PFMT64x " {\n", i++, arena);
				jemalloc_print_arena_bins_530(core, arena, bin_info, is_64bit);
				PRINT_YA("  }\n");
			}
		}
		PRINT_GA("}\n");
	} else {
		// Static mode - requires two arguments: dmxb <arena_addr> <bin_info_addr>
		const char *addr_str = (input[0] == ' ') ? input + 1 : input;
		char *args = strdup(addr_str);
		if (!args) {
			return;
		}
		char *bin_info_str = strchr(args, ' ');

		if (!bin_info_str) {
			RZ_LOG_ERROR("Usage: dmxb <arena_addr> <bin_info_addr>\n");
			free(args);
			return;
		}

		*bin_info_str++ = '\0';
		arena = rz_num_math(core->num, args);
		bin_info = rz_num_math(core->num, bin_info_str);

		PRINTF_GA("arena_t @ 0x%" PFMT64x " bins[%d] {\n", arena, JM_NBINS_530);
		jemalloc_print_arena_bins_530(core, arena, bin_info, is_64bit);
		PRINT_GA("}\n");
		free(args);
	}
}

static void jemalloc_print_narenas_530(RzCore *core, const char *input, bool is_64bit) {
	ut64 symaddr;
	ut64 arenas;
	ut64 arena = UT64_MAX;
	int i = 0;
	ut64 narenas = 0;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	size_t ptr_size = is_64bit ? 8 : 4;

	if (input[0] == '\0') { // no args, list all arenas
		if (rz_resolve_jemalloc_530(core, "narenas_total", &symaddr, is_64bit)) {
			if (is_64bit) {
				rz_io_read_at_mapped(core->io, symaddr, (ut8 *)&narenas, ptr_size);
			} else {
				ut32 narenas32 = 0;
				rz_io_read_at_mapped(core->io, symaddr, (ut8 *)&narenas32, ptr_size);
				narenas = narenas32;
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

		if (rz_resolve_jemalloc_530(core, "je_arenas", &arenas, is_64bit)) {
			PRINTF_GA("arenas[%" PFMT64d "] @ 0x%" PFMT64x " {\n", narenas, arenas);
			for (i = 0; i < (int)narenas; i++) {
				ut64 at = arenas + (i * ptr_size);
				if (is_64bit) {
					rz_io_read_at_mapped(core->io, at, (ut8 *)&arena, ptr_size);
				} else {
					ut32 arena32 = 0;
					rz_io_read_at_mapped(core->io, at, (ut8 *)&arena32, ptr_size);
					arena = arena32;
				}
				if (!arena) {
					PRINTF_YA("  arenas[%d]: (empty)\n", i);
					continue;
				}
				PRINTF_YA("  arenas[%d]: ", i);
				PRINTF_BA("@ 0x%" PFMT64x "\n", arena);
			}
		}
		PRINT_GA("}\n");
	} else {
		const char *addr_str = (input[0] == ' ') ? input + 1 : input;
		arena = rz_num_math(core->num, addr_str);

		arena_t_530 ar;
		if (!read_and_parse_arena_t_530(core->io, arena, &ar, is_64bit)) {
			RZ_LOG_ERROR("Failed to read arena at 0x%" PFMT64x "\n", arena);
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

static void cmd_dbg_map_jemalloc_530(RzCore *core, char dmx_variant, const char *arg) {
	bool is_64bit = core->rasm->bits == 64;
	switch (dmx_variant) {
	case 'a': // dmxa - print arena
		jemalloc_print_narenas_530(core, arg, is_64bit);
		break;
	case 'b': // dmxb - bin info
		jemalloc_get_bins_530(core, arg, is_64bit);
		break;
	case 'e': // dmxe - find extent for malloc'd address
		jemalloc_find_extent_530(core, arg, is_64bit);
		break;
	case 'i': // dmxei - extent info
		jemalloc_extent_info_530(core, arg, is_64bit);
		break;
	}
}

#endif /* JEMALLOC_530_DEFINED_ONCE */

static void GH(cmd_dbg_map_jemalloc)(RzCore *core, char dmx_variant, const char *arg) {
	const char *version = rz_config_get(core->config, "dbg.jemalloc.version");
	if (!version || strcmp(version, "auto") == 0 || strcmp(version, "NULL") == 0 || version[0] == '\0') {
		GH(rz_jemalloc_detect_version)(core);
		version = rz_config_get(core->config, "dbg.jemalloc.version");
	}

	if (version && strcmp(version, "4.5.0") == 0) {
		switch (dmx_variant) {
		case 'a': // dmxa
			GH(jemalloc_print_narenas_450)(core, arg);
			break;
		case 'b': // dmxb
			GH(jemalloc_get_bins_450)(core, arg);
			break;
		case 'c': // dmxc
			GH(jemalloc_get_chunks_450)(core, arg);
			break;
		}
	} else if (version && strcmp(version, "5.3.0") == 0) {
		cmd_dbg_map_jemalloc_530(core, dmx_variant, arg);
	} else {
		RZ_LOG_ERROR("Unknown jemalloc version. Please set dbg.jemalloc.version to '4.5.0' or '5.3.0'\n");
	}
}
