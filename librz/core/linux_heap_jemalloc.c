// SPDX-FileCopyrightText: 2017 javierptd <javierptd@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef INCLUDE_HEAP_JEMALLOC_STD_C
#define INCLUDE_HEAP_JEMALLOC_STD_C
#define HEAP32 1
#include "linux_heap_jemalloc.c"
#undef HEAP32
#endif

#undef GH
#undef GHT
#undef GHT_MAX
#undef PFMTx

// FIXME: It should be detected at runtime, not during the compilation stage
#if HEAP32
#define GH(x)   x##_32
#define GHT     ut32
#define GHT_MAX UT32_MAX
#define PFMTx   PFMT32x
#else
#define GH(x)   x##_64
#define GHT     ut64
#define GHT_MAX UT64_MAX
#define PFMTx   PFMT64x
#endif

#if __linux__
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
	rz_bin_file_set_cur_binfile(bin, current_bf);
	return vaddr;
}

static int GH(je_matched)(const char *ptr, const char *str) {
	int ret = strncmp(ptr, str, strlen(str) - 1);
	return !ret;
}
#endif

static bool GH(rz_resolve_jemalloc)(RzCore *core, char *symname, ut64 *symbol) {
	RzListIter *iter;
	RzDebugMap *map;
	const char *jemalloc_ver_end = NULL;
	ut64 jemalloc_addr = UT64_MAX;

	if (!core || !core->dbg || !core->dbg->maps) {
		return false;
	}
	rz_debug_map_sync(core->dbg);
	rz_list_foreach (core->dbg->maps, iter, map) {
		if (strstr(map->name, "libjemalloc.")) {
			jemalloc_addr = map->addr;
			jemalloc_ver_end = map->name;
			break;
		}
	}
	if (!jemalloc_ver_end) {
		RZ_LOG_WARN("Is jemalloc mapped in memory? (see dm command)\n");
		return false;
	}
#if __linux__
	bool is_debug_file = GH(je_matched)(jemalloc_ver_end, "/usr/local/lib");

	if (!is_debug_file) {
		RZ_LOG_WARN("Is libjemalloc.so.2 in /usr/local/lib path?\n");
		return false;
	}
	char *path = rz_str_newf("%s", jemalloc_ver_end);
	if (rz_file_exists(path)) {
		ut64 vaddr = GH(je_get_va_symbol)(core, path, symname);
		if (jemalloc_addr != GHT_MAX && vaddr != 0) {
			*symbol = jemalloc_addr + vaddr;
			free(path);
			return true;
		}
	}
	free(path);
	return false;
#else
	(void)jemalloc_addr;
	RZ_LOG_INFO("Resolving %s from libjemalloc.2... ", symname);
	// this is quite sloooow, we must optimize dmi
	char *va = rz_core_cmd_strf(core, "dmi libjemalloc.2 %s$~[1]", symname);
	ut64 n = rz_num_get(NULL, va);
	if (n && n != UT64_MAX) {
		*symbol = n;
		rz_cons_printf("0x%08" PFMT64x "\n", n);
	} else {
		rz_cons_printf("NOT FOUND\n");
	}
	free(va);
	return true;
#endif
}

static void GH(jemalloc_get_chunks)(RzCore *core, const char *input) {
	ut64 cnksz;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!GH(rz_resolve_jemalloc)(core, "je_chunksize", &cnksz)) {
		RZ_LOG_ERROR("Fail at reading symbol je_chunksize\n");
		return;
	}
	rz_io_read_at(core->io, cnksz, (ut8 *)&cnksz, sizeof(GHT));

	switch (input[0]) {
	case '\0':
		RZ_LOG_ERROR("need an arena_t to associate chunks\n");
		break;
	case ' ': {
		GHT arena = GHT_MAX;
		arena_t *ar = RZ_NEW0(arena_t);
		extent_node_t *node = RZ_NEW0(extent_node_t), *head = RZ_NEW0(extent_node_t);
		input += 1;
		arena = rz_num_math(core->num, input);

		if (arena) {
			rz_io_read_at(core->io, arena, (ut8 *)ar, sizeof(arena_t));
			rz_io_read_at(core->io, (GHT)(size_t)ar->achunks.qlh_first, (ut8 *)head, sizeof(extent_node_t));
			if (head->en_addr) {
				PRINT_YA("   Chunk - start: ");
				PRINTF_BA("0x%08" PFMT64x, (ut64)(size_t)head->en_addr);
				PRINT_YA(", end: ");
				PRINTF_BA("0x%08" PFMT64x, (ut64)(size_t)((char *)head->en_addr + cnksz));
				PRINT_YA(", size: ");
				PRINTF_BA("0x%08" PFMT64x "\n", (ut64)cnksz);
				rz_io_read_at(core->io, (ut64)(size_t)head->ql_link.qre_next, (ut8 *)node, sizeof(extent_node_t));
				while (node && node->en_addr != head->en_addr) {
					PRINT_YA("   Chunk - start: ");
					PRINTF_BA("0x%08" PFMT64x, (ut64)(size_t)node->en_addr);
					PRINT_YA(", end: ");
					PRINTF_BA("0x%" PFMT64x, (ut64)(size_t)((char *)node->en_addr + cnksz));
					PRINT_YA(", size: ");
					PRINTF_BA("0x%08" PFMT64x "\n", cnksz);
					rz_io_read_at(core->io, (ut64)(size_t)node->ql_link.qre_next, (ut8 *)node, sizeof(extent_node_t));
				}
			}
		}
		free(ar);
		free(head);
		free(node);
		break;
	}
	case '*': {
		int i = 0;
		ut64 sym;
		GHT arenas = GHT_MAX, arena = GHT_MAX;
		arena_t *ar = RZ_NEW0(arena_t);
		extent_node_t *node = RZ_NEW0(extent_node_t);
		extent_node_t *head = RZ_NEW0(extent_node_t);

		if (!node || !head) {
			RZ_LOG_ERROR("Failed to allocate extent_node_t\n");
			free(ar);
			free(node);
			free(head);
			return;
		}

		if (GH(rz_resolve_jemalloc)(core, "je_arenas", &sym)) {
			rz_io_read_at(core->io, sym, (ut8 *)&arenas, sizeof(GHT));
			for (;;) {
				rz_io_read_at(core->io, arenas + i * sizeof(GHT), (ut8 *)&arena, sizeof(GHT));
				if (!arena) {
					break;
				}
				PRINTF_GA("arenas[%d]: @ 0x%" PFMTx " { \n", i++, (GHT)arena);
				rz_io_read_at(core->io, arena, (ut8 *)ar, sizeof(arena_t));
				rz_io_read_at(core->io, (GHT)(size_t)ar->achunks.qlh_first, (ut8 *)head, sizeof(extent_node_t));
				if (head->en_addr != 0) {
					PRINT_YA("   Chunk - start: ");
					PRINTF_BA("0x%08" PFMT64x, (ut64)(size_t)head->en_addr);
					PRINT_YA(", end: ");
					PRINTF_BA("0x%" PFMT64x, (ut64)(size_t)((char *)head->en_addr + cnksz));
					PRINT_YA(", size: ");
					PRINTF_BA("0x%08" PFMT64x "\n", (ut64)cnksz);
					ut64 addr = (ut64)(size_t)head->ql_link.qre_next;
					rz_io_read_at(core->io, addr, (ut8 *)node, sizeof(extent_node_t));
					while (node && head && node->en_addr != head->en_addr) {
						PRINT_YA("   Chunk - start: ");
						PRINTF_BA("0x%08" PFMT64x, (ut64)(size_t)node->en_addr);
						PRINT_YA(", end: ");
						PRINTF_BA("0x%" PFMT64x, (ut64)(size_t)((char *)node->en_addr + cnksz));
						PRINT_YA(", size: ");
						PRINTF_BA("0x%" PFMT64x "\n", cnksz);
						rz_io_read_at(core->io, (GHT)(size_t)node->ql_link.qre_next, (ut8 *)node, sizeof(extent_node_t));
					}
				}
				PRINT_GA("}\n");
			}
		}
		free(ar);
		free(head);
		free(node);
	} break;
	}
}

static void GH(jemalloc_print_narenas)(RzCore *core, const char *input) {
	ut64 symaddr;
	ut64 arenas;
	GHT arena = GHT_MAX;
	arena_t *ar = RZ_NEW0(arena_t);
	if (!ar) {
		return;
	}
	arena_stats_t *stats = RZ_NEW0(arena_stats_t);
	if (!stats) {
		free(ar);
		return;
	}
	int i = 0;
	GHT narenas = 0;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	switch (input[0]) {
	case '\0':
		if (GH(rz_resolve_jemalloc)(core, "narenas_total", &symaddr)) {
			rz_io_read_at(core->io, symaddr, (ut8 *)&narenas, sizeof(GHT));
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
			rz_io_read_at(core->io, arenas, (ut8 *)&arenas, sizeof(GHT));
			PRINTF_GA("arenas[%" PFMT64d "] @ 0x%" PFMT64x " {\n", (ut64)narenas, (ut64)arenas);
			for (i = 0; i < narenas; i++) {
				ut64 at = arenas + (i * sizeof(GHT));
				rz_io_read_at(core->io, at, (ut8 *)&arena, sizeof(GHT));
				if (!arena) {
					PRINTF_YA("  arenas[%d]: (empty)\n", i);
					continue;
				}
				PRINTF_YA("  arenas[%d]: ", i);
				PRINTF_BA("@ 0x%" PFMT64x "\n", at);
			}
		}
		PRINT_GA("}\n");
		break;
	case ' ':
		arena = rz_num_math(core->num, input + 1);
		rz_io_read_at(core->io, (GHT)arena, (ut8 *)ar, sizeof(arena_t));

		PRINT_GA("struct arena_s {\n");
#define OO(x) (ut64)(arena + rz_offsetof(arena_t, x))
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
		PRINTF_BA("  runs_avail = %d 0x%" PFMT64x "\n", NPSIZES, OO(runs_avail));
		PRINT_GA("}\n");
		break;
	}
	free(ar);
	free(stats);
}

static void GH(jemalloc_get_bins)(RzCore *core, const char *input) {
	int i = 0, j;
	ut64 bin_info;
	ut64 arenas;
	GHT arena = GHT_MAX; //, bin = GHT_MAX;
	arena_t *ar = NULL;
	arena_bin_info_t *b = NULL;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	switch (input[0]) {
	case ' ':
		ar = RZ_NEW0(arena_t);
		if (!ar) {
			break;
		}
		b = RZ_NEW0(arena_bin_info_t);
		if (!b) {
			break;
		}
		if (!GH(rz_resolve_jemalloc)(core, "je_arena_bin_info", &bin_info)) {
			RZ_LOG_ERROR("Cannot resolve je_arena_bin_info\n");
			RZ_FREE(b);
			break;
		}
		if (GH(rz_resolve_jemalloc)(core, "je_arenas", &arenas)) {
			rz_io_read_at(core->io, arenas, (ut8 *)&arenas, sizeof(GHT));
			PRINTF_GA("arenas @ 0x%" PFMTx " {\n", (GHT)arenas);
			for (;;) {
				rz_io_read_at(core->io, arenas + i * sizeof(GHT), (ut8 *)&arena, sizeof(GHT));
				if (!arena) {
					RZ_FREE(b);
					break;
				}
				PRINTF_YA("   arenas[%d]: ", i++);
				PRINTF_BA("@ 0x%" PFMTx, (GHT)arena);
				PRINT_YA(" {\n");
				rz_io_read_at(core->io, arena, (ut8 *)ar, sizeof(arena_t));
				for (j = 0; j < JM_NBINS; j++) {
					rz_io_read_at(core->io, (GHT)(bin_info + j * sizeof(arena_bin_info_t)),
						(ut8 *)b, sizeof(arena_bin_info_t));
					PRINT_YA("    {\n");
					PRINT_YA("       regsize : ");
					PRINTF_BA("0x%zx\n", b->reg_size);
					PRINT_YA("       redzone size ");
					PRINTF_BA("0x%zx\n", b->redzone_size);
					PRINT_YA("       reg_interval : ");
					PRINTF_BA("0x%zx\n", b->reg_interval);
					PRINT_YA("       run_size : ");
					PRINTF_BA("0x%zx\n", b->run_size);
					PRINT_YA("       nregs : ");
					PRINTF_BA("0x%x\n", b->nregs);
					// FIXME: It's a structure of bitmap_info_t
					// PRINT_YA ("       bitmap_info : ");
					// PRINTF_BA ("0x%"PFMT64x"\n", b->bitmap_info);
					PRINT_YA("       reg0_offset : ");
					PRINTF_BA("0x%" PFMT64x "\n\n", (ut64)b->reg0_offset);
					// FIXME: It's a structure of malloc_mutex_t
					// PRINTF_YA ("       bins[%d]->lock ", j);
					// PRINTF_BA ("= 0x%"PFMT64x"\n", ar->bins[j].lock);
					// FIXME: It's a structure of arena_run_t*
					// PRINTF_YA ("       bins[%d]->runcur ", j);
					// PRINTF_BA ("@ 0x%"PFMT64x"\n", ar->bins[j].runcur);
					// FIXME: It's a structure of arena_run_heap_t*
					// PRINTF_YA ("       bins[%d]->runs ", j);
					// PRINTF_BA ("@ 0x%"PFMTx"\n", ar->bins[j].runs);
					// FIXME: It's a structure of malloc_bin_stats_t
					// PRINTF_YA ("       bins[%d]->stats ", j);
					// PRINTF_BA ("= 0x%"PFMTx"\n", ar->bins[j].stats);
					PRINT_YA("    }\n");
				}
				PRINT_YA("  }\n");
			}
		}
		PRINT_GA("}\n");
		break;
	}
	free(ar);
	free(b);
}

#if 0
static void GH(jemalloc_get_runs)(RzCore *core, const char *input) {
	switch (input[0]) {
	case ' ':
		{
			int pageind;
			ut64 npages, chunksize_mask, map_bias, map_misc_offset, chunk, mapbits;;
			arena_chunk_t *c = RZ_NEW0 (arena_chunk_t);

			if (!c) {
				RZ_LOG_ERROR ("Cannot call calloc\n");
				return;
			}

			input += 1;
			chunk = rz_num_math (core->num, input);

			if (!GH(rz_resolve_jemalloc)(core, "je_chunk_npages", &npages)) {
				RZ_LOG_ERROR ("Cannot resolve je_chunk_npages\n");
				return;
			}
			if (!GH(rz_resolve_jemalloc)(core, "je_chunksize_mask", &chunksize_mask)) {
				RZ_LOG_ERROR ("Cannot resolve je_chunksize_mask\n");
				return;
			}
			if (!GH(rz_resolve_jemalloc)(core, "je_map_bias", &map_bias)) {
				RZ_LOG_ERROR ("Cannot resolve je_map_bias\n");
				return;
			}
			if (!GH(rz_resolve_jemalloc)(core, "je_map_misc_offset", &map_misc_offset)) {
				RZ_LOG_ERROR ("Cannot resolve je_map_misc_offset\n");
				return;
			}

			rz_io_read_at (core->io, npages, (ut8*)&npages, sizeof (GHT));
			rz_io_read_at (core->io, chunksize_mask, (ut8*)&chunksize_mask, sizeof (GHT));
			rz_io_read_at (core->io, map_bias, (ut8*)&map_bias, sizeof (GHT));
			rz_io_read_at (core->io, map_misc_offset, (ut8*)&map_misc_offset, sizeof (GHT));

			rz_cons_printf ("map_misc_offset 0x%08"PFMT64x"\n", (ut64)map_misc_offset);

			rz_io_read_at (core->io, chunk, (ut8 *)c, sizeof (arena_chunk_t));
			mapbits = *(GHT *)&c->map_bits;
			rz_cons_printf ("map_bits: 0x%08"PFMT64x"\n", (ut64)mapbits);

			uint32_t offset = rz_offsetof (arena_chunk_t, map_bits);

			arena_chunk_map_bits_t *dwords = (void *)calloc (sizeof (arena_chunk_map_bits_t), npages);
			rz_io_read_at (core->io, chunk + offset, (ut8*)dwords, sizeof (arena_chunk_map_bits_t) * npages);
			rz_cons_printf ("map_bits @ 0x%08"PFMT64x"\n", (ut64)(chunk + offset));

			arena_run_t *r = RZ_NEW0 (arena_run_t);
			if (!r) {
				RZ_LOG_ERROR ("Cannot call calloc\n");
				return;
			}
			for (pageind = map_bias; pageind < npages; pageind++) {
				arena_chunk_map_bits_t mapelm = dwords[pageind-map_bias];
				if (mapelm.bits & CHUNK_MAP_ALLOCATED) {
					// ut64 elm = ((arena_chunk_map_misc_t *)((uintptr_t)chunk + (uintptr_t)map_misc_offset) + pageind-map_bias);
					ut64 elm = chunk + map_misc_offset + pageind-map_bias;
					rz_cons_printf ("\nelm: 0x%"PFMT64x"\n", elm);
					arena_chunk_map_misc_t *m = RZ_NEW0 (arena_chunk_map_misc_t);
					if (m) {
						ut64 run = elm + rz_offsetof (arena_chunk_map_misc_t, run);
						rz_io_read_at (core->io, elm, (ut8*)m, sizeof (arena_chunk_map_misc_t));
						rz_cons_printf ("Small run @ 0x%08"PFMT64x"\n", (ut64)elm);
						rz_io_read_at (core->io, run, (ut8*)r, sizeof (arena_run_t));
						rz_cons_printf ("binind: 0x%08"PFMT64x"\n", (ut64)r->binind);
						rz_cons_printf ("nfree: 0x%08"PFMT64x"\n", (ut64)r->nfree);
						rz_cons_printf ("bitmap: 0x%08"PFMT64x"\n\n", (ut64)*(GHT*)r->bitmap);
						free (m);
					}
				} else if (mapelm.bits & CHUNK_MAP_LARGE) {
					ut64 run = (ut64) (size_t) chunk + (pageind << LG_PAGE);
					rz_cons_printf ("Large run @ 0x%08"PFMT64x"\n", run);
					rz_io_read_at (core->io, run, (ut8*)r, sizeof (arena_run_t));
					rz_cons_printf ("binind: 0x%08"PFMT64x"\n", (ut64)r->binind);
					rz_cons_printf ("nfree: 0x%08"PFMT64x"\n", (ut64)r->nfree);
					rz_cons_printf ("bitmap: 0x%08"PFMT64x"\n\n", (ut64)*(GHT*)r->bitmap);
				}
			}
			free (c);
			free (r);
         	}
	break;
	}
}
#endif

static int GH(cmd_dbg_map_jemalloc)(RzCore *core, const char *input) {
	const char *help_msg[] = {
		"Usage:", "dmx", " # Jemalloc heap parsing commands",
		"dmxa", "[arena_t]", "show all arenas created, or print arena_t structure for given arena",
		"dmxb", "[arena_t]", "show all bins created for given arena",
		"dmxc", "*|[arena_t]", "show all chunks created in all arenas, or show all chunks created for a given arena_t instance",
		// "dmxr", "[arena_chunk_t]", "print all runs created for a given arena_chunk_t instance",
		"dmx?", "", "Show map heap help", NULL
	};

	switch (input[0]) {
	case '?':
		rz_core_cmd_help(core, help_msg);
		break;
	case 'a': // dmxa
		GH(jemalloc_print_narenas)
		(core, input + 1);
		break;
	case 'b': // dmxb
		GH(jemalloc_get_bins)
		(core, input + 1);
		break;
	case 'c': // dmxc
		GH(jemalloc_get_chunks)
		(core, input + 1);
		break;
		/*
	case 'r': //dmxr
		GH(jemalloc_get_runs) (core, input + 1);
		break;
	*/
	}
	return 0;
}
