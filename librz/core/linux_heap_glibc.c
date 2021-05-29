// SPDX-FileCopyrightText: 2016-2020 n4x0r <kalianon2816@gmail.com>
// SPDX-FileCopyrightText: 2016-2020 soez <soez@amn3s1a.com>
// SPDX-FileCopyrightText: 2016-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef INCLUDE_HEAP_GLIBC_C
#define INCLUDE_HEAP_GLIBC_C
#include "rz_config.h"
#define HEAP32 1
#include "linux_heap_glibc.c"
#undef HEAP32
#endif

#undef GH
#undef GHT
#undef GHT_MAX
#undef read_le

#if HEAP32
#define GH(x)      x##_32
#define GHT        ut32
#define GHT_MAX    UT32_MAX
#define read_le(x) rz_read_le##32(x)
#else
#define GH(x)      x##_64
#define GHT        ut64
#define GHT_MAX    UT64_MAX
#define read_le(x) rz_read_le##64(x)
#endif

/**
 * \brief Find the address of a given symbol
 * \param core RzCore Pointer to the r2's core
 * \param path Pointer to the binary path in which to look for the symbol
 * \param sym_name Pointer to the symbol's name to search for
 * \return address
 *
 * Used to find the address of a given symbol inside a binary
 *
 * TODO: Stop using deprecated functions like rz_bin_cur
 */
static GHT GH(get_va_symbol)(RzCore *core, const char *path, const char *sym_name) {
	GHT vaddr = GHT_MAX;
	RzBin *bin = core->bin;
	RzBinFile *current_bf = rz_bin_cur(bin);
	RzListIter *iter;
	RzBinSymbol *s;

	RzBinOptions opt;
	rz_bin_options_init(&opt, -1, 0, 0, false, false);
	RzBinFile *libc_bf = rz_bin_open(bin, path, &opt);
	if (!libc_bf) {
		return vaddr;
	}

	RzList *syms = rz_bin_get_symbols(bin);
	rz_list_foreach (syms, iter, s) {
		if (!strcmp(s->name, sym_name)) {
			vaddr = s->vaddr;
			break;
		}
	}

	rz_bin_file_delete(bin, libc_bf);
	rz_bin_file_set_cur_binfile(bin, current_bf);
	return vaddr;
}

static inline GHT GH(align_address_to_size)(ut64 addr, ut64 align) {
	return addr + ((align - (addr % align)) % align);
}

static inline GHT GH(get_next_pointer)(RzCore *core, GHT pos, GHT next) {
	return (core->dbg->glibc_version < 232) ? next : (GHT)((pos >> 12) ^ next);
}

static GHT GH(get_main_arena_with_symbol)(RzCore *core, RzDebugMap *map) {
	rz_return_val_if_fail(core && map, GHT_MAX);
	GHT base_addr = map->addr;
	rz_return_val_if_fail(base_addr != GHT_MAX, GHT_MAX);

	GHT main_arena = GHT_MAX;
	GHT vaddr = GHT_MAX;
	char *path = strdup(map->name);
	if (path && rz_file_exists(path)) {
		vaddr = GH(get_va_symbol)(core, path, "main_arena");
		if (vaddr != GHT_MAX) {
			main_arena = base_addr + vaddr;
		} else {
			vaddr = GH(get_va_symbol)(core, path, "__malloc_hook");
			if (vaddr == GHT_MAX) {
				return main_arena;
			}
			RzBinInfo *info = rz_bin_get_info(core->bin);
			if (!strcmp(info->arch, "x86")) {
				main_arena = GH(align_address_to_size)(vaddr + base_addr + sizeof(GHT), 0x20);
			} else if (!strcmp(info->arch, "arm")) {
				main_arena = vaddr + base_addr - sizeof(GHT) * 2 - sizeof(MallocState);
			}
		}
	}
	free(path);
	return main_arena;
}

static bool GH(is_tcache)(RzCore *core) {
	char *fp = NULL;
	double v = 0;
	if (rz_config_get_b(core->config, "cfg.debug")) {
		RzDebugMap *map;
		RzListIter *iter;
		rz_debug_map_sync(core->dbg);
		rz_list_foreach (core->dbg->maps, iter, map) {
			// In case the binary is named *libc-*
			if (strncmp(map->name, core->bin->file, strlen(map->name)) != 0) {
				fp = strstr(map->name, "libc-");
				if (fp) {
					break;
				}
			}
		}
	} else {
		int tcv = rz_config_get_i(core->config, "dbg.glibc.tcache");
		eprintf("dbg.glibc.tcache = %i\n", tcv);
		return tcv != 0;
	}
	if (fp) {
		v = rz_num_get_float(NULL, fp + 5);
		core->dbg->glibc_version = (int)round((v * 100));
	}
	return (v > 2.25);
}

static GHT GH(tcache_chunk_size)(RzCore *core, GHT brk_start) {
	GHT sz = 0;

	GH(RzHeapChunk) *cnk = RZ_NEW0(GH(RzHeapChunk));
	if (!cnk) {
		return sz;
	}
	rz_io_read_at(core->io, brk_start, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
	sz = (cnk->size >> 3) << 3; //clear chunk flag
	return sz;
}

static void GH(update_arena_with_tc)(GH(RzHeap_MallocState_tcache) * cmain_arena, MallocState *main_arena) {
	int i = 0;
	main_arena->mutex = cmain_arena->mutex;
	main_arena->flags = cmain_arena->flags;
	for (i = 0; i < BINMAPSIZE; i++) {
		main_arena->binmap[i] = cmain_arena->binmap[i];
	}
	main_arena->have_fast_chunks = cmain_arena->have_fast_chunks;
	main_arena->attached_threads = cmain_arena->attached_threads;
	for (i = 0; i < NFASTBINS; i++) {
		main_arena->GH(fastbinsY)[i] = cmain_arena->fastbinsY[i];
	}
	main_arena->GH(top) = cmain_arena->top;
	main_arena->GH(last_remainder) = cmain_arena->last_remainder;
	for (i = 0; i < NBINS * 2 - 2; i++) {
		main_arena->GH(bins)[i] = cmain_arena->bins[i];
	}
	main_arena->GH(next) = cmain_arena->next;
	main_arena->GH(next_free) = cmain_arena->next_free;
	main_arena->GH(system_mem) = cmain_arena->system_mem;
	main_arena->GH(max_system_mem) = cmain_arena->max_system_mem;
}

static void GH(update_arena_without_tc)(GH(RzHeap_MallocState) * cmain_arena, MallocState *main_arena) {
	int i = 0;
	main_arena->mutex = cmain_arena->mutex;
	main_arena->flags = cmain_arena->flags;
	for (i = 0; i < BINMAPSIZE; i++) {
		main_arena->binmap[i] = cmain_arena->binmap[i];
	}
	main_arena->attached_threads = 1;
	for (i = 0; i < NFASTBINS; i++) {
		main_arena->GH(fastbinsY)[i] = cmain_arena->fastbinsY[i];
	}
	main_arena->GH(top) = cmain_arena->top;
	main_arena->GH(last_remainder) = cmain_arena->last_remainder;
	for (i = 0; i < NBINS * 2 - 2; i++) {
		main_arena->GH(bins)[i] = cmain_arena->bins[i];
	}
	main_arena->GH(next) = cmain_arena->next;
	main_arena->GH(next_free) = cmain_arena->next_free;
	main_arena->GH(system_mem) = cmain_arena->system_mem;
	main_arena->GH(max_system_mem) = cmain_arena->max_system_mem;
}

static bool GH(update_main_arena)(RzCore *core, GHT m_arena, MallocState *main_arena) {
	const int tcache = rz_config_get_i(core->config, "dbg.glibc.tcache");
	if (tcache) {
		GH(RzHeap_MallocState_tcache) *cmain_arena = RZ_NEW0(GH(RzHeap_MallocState_tcache));
		if (!cmain_arena) {
			return false;
		}
		(void)rz_io_read_at(core->io, m_arena, (ut8 *)cmain_arena, sizeof(GH(RzHeap_MallocState_tcache)));
		GH(update_arena_with_tc)
		(cmain_arena, main_arena);
	} else {
		GH(RzHeap_MallocState) *cmain_arena = RZ_NEW0(GH(RzHeap_MallocState));
		if (!cmain_arena) {
			return false;
		}
		(void)rz_io_read_at(core->io, m_arena, (ut8 *)cmain_arena, sizeof(GH(RzHeap_MallocState)));
		GH(update_arena_without_tc)
		(cmain_arena, main_arena);
	}
	return true;
}

static void GH(get_brks)(RzCore *core, GHT *brk_start, GHT *brk_end) {
	if (rz_config_get_b(core->config, "cfg.debug")) {
		RzListIter *iter;
		RzDebugMap *map;
		rz_debug_map_sync(core->dbg);
		rz_list_foreach (core->dbg->maps, iter, map) {
			if (map->name) {
				if (strstr(map->name, "[heap]")) {
					*brk_start = map->addr;
					*brk_end = map->addr_end;
					break;
				}
			}
		}
	} else {
		void **it;
		RzPVector *maps = rz_io_maps(core->io);
		rz_pvector_foreach (maps, it) {
			RzIOMap *map = *it;
			if (map->name) {
				if (strstr(map->name, "[heap]")) {
					*brk_start = map->itv.addr;
					*brk_end = map->itv.addr + map->itv.size;
					break;
				}
			}
		}
	}
}

static void GH(print_arena_stats)(RzCore *core, GHT m_arena, MallocState *main_arena, GHT global_max_fast, int format) {
	size_t i, j, k, start;
	GHT align = 12 * SZ + sizeof(int) * 2;
	const int tcache = rz_config_get_i(core->config, "dbg.glibc.tcache");
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (tcache) {
		align = 16;
	}

	GHT apart[NSMALLBINS + 1] = { 0LL };
	if (format == '*') {
		for (i = 0; i < NBINS * 2 - 2; i += 2) {
			GHT addr = m_arena + align + SZ * i - SZ * 2;
			GHT bina = main_arena->GH(bins)[i];
			rz_cons_printf("f chunk.%zu.bin = 0x%" PFMT64x "\n", i, (ut64)addr);
			rz_cons_printf("f chunk.%zu.fd = 0x%" PFMT64x "\n", i, (ut64)bina);
			bina = main_arena->GH(bins)[i + 1];
			rz_cons_printf("f chunk.%zu.bk = 0x%" PFMT64x "\n", i, (ut64)bina);
		}
		for (i = 0; i < BINMAPSIZE; i++) {
			rz_cons_printf("f binmap.%zu = 0x%" PFMT64x, i, (ut64)main_arena->binmap[i]);
		}
		{ /* maybe use SDB instead of flags for this? */
			char units[8];
			rz_num_units(units, sizeof(units), main_arena->GH(max_system_mem));
			rz_cons_printf("f heap.maxmem = %s\n", units);

			rz_num_units(units, sizeof(units), main_arena->GH(system_mem));
			rz_cons_printf("f heap.sysmem = %s\n", units);

			rz_num_units(units, sizeof(units), main_arena->GH(next_free));
			rz_cons_printf("f heap.nextfree = %s\n", units);

			rz_num_units(units, sizeof(units), main_arena->GH(next));
			rz_cons_printf("f heap.next= %s\n", units);
		}
		return;
	}

	PRINT_GA("malloc_state @ ");
	PRINTF_BA("0x%" PFMT64x "\n\n", (ut64)m_arena);
	PRINT_GA("struct malloc_state main_arena {\n");
	PRINT_GA("  mutex = ");
	PRINTF_BA("0x%08x\n", (ut32)main_arena->mutex);
	PRINT_GA("  flags = ");
	PRINTF_BA("0x%08x\n", (ut32)main_arena->flags);
	PRINT_GA("  fastbinsY = {\n");

	for (i = 0, j = 1, k = SZ * 4; i < NFASTBINS; i++, j++, k += SZ * 2) {
		if (FASTBIN_IDX_TO_SIZE(j) <= global_max_fast) {
			PRINTF_YA(" Fastbin %02zu\n", j);
		} else {
			PRINTF_RA(" Fastbin %02zu\n", j);
		}
		PRINT_GA(" chunksize:");
		PRINTF_BA(" == %04zu ", k);
		PRINTF_GA("0x%" PFMT64x, (ut64)main_arena->GH(fastbinsY)[i]);
		PRINT_GA(",\n");
	}
	PRINT_GA("}\n");
	PRINT_GA("  top = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->GH(top));
	PRINT_GA(",\n");
	PRINT_GA("  last_remainder = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->GH(last_remainder));
	PRINT_GA(",\n");
	PRINT_GA("  bins {\n");

	/* Index & size for largebins */
	start = SZ * 128;
	for (i = start, k = 0, j = 0; j < NBINS - 2 && i < 1024 * 1024; i += 64) {
		j = largebin_index(i);
		if (j == k + NSMALLBINS + 1) {
			apart[k++] = i;
		}
	}
	for (i = 0, j = 1, k = SZ * 4; i < NBINS * 2 - 2; i += 2, j++) {
		PRINTF_YA(" Bin %03zu: ", j);
		if (j == 1) {
			PRINT_GA("Unsorted Bin");
			PRINT_GA(" [");
			PRINT_GA(" chunksize:");
			PRINT_BA(" undefined ");
		} else if (j > 1 && j <= NSMALLBINS) {
			if (j == 2) {
				PRINT_GA("             ┌");
			} else if (j == (NSMALLBINS / 2)) {
				PRINT_GA("  Small Bins │");
			} else if (j != 2 && j != (NSMALLBINS / 2) && j != NSMALLBINS) {
				PRINT_GA("             │");
			} else {
				PRINT_GA("             └");
			}
			PRINT_GA(" chunksize:");
			PRINTF_BA(" == %06zu  ", k);
			if (j < NSMALLBINS) {
				k += SZ * 2;
			}
		} else {
			if (j == NSMALLBINS + 1) {
				PRINT_GA("             ┌");
			} else if (j == (NSMALLBINS / 2) * 3) {
				PRINT_GA("  Large Bins │");
			} else if (j != NSMALLBINS + 1 && j != (NSMALLBINS / 2) * 3 && j != NBINS - 1) {
				PRINT_GA("             │");
			} else {
				PRINT_GA("             └");
			}
			PRINT_GA(" chunksize:");
			if (j != NBINS - 1) {
				PRINTF_BA(" >= %06" PFMT64d "  ", (ut64)apart[j - NSMALLBINS - 1]);
			} else {
				PRINT_BA(" remaining ");
			}
		}
		GHT bin = m_arena + align + SZ * i - SZ * 2;
		PRINTF_GA("0x%" PFMT64x "->fd = ", (ut64)bin);
		PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->GH(bins)[i]);
		PRINT_GA(", ");
		PRINTF_GA("0x%" PFMT64x "->bk = ", (ut64)bin);
		PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->GH(bins)[i + 1]);
		PRINT_GA(", ");
		rz_cons_newline();
	}

	PRINT_GA("  }\n");
	PRINT_GA("  binmap = {");

	for (i = 0; i < BINMAPSIZE; i++) {
		if (i) {
			PRINT_GA(",");
		}
		PRINTF_BA("0x%x", (ut32)main_arena->binmap[i]);
	}
	PRINT_GA("}\n");
	PRINT_GA("  next = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->GH(next));
	PRINT_GA(",\n");
	PRINT_GA("  next_free = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->GH(next_free));
	PRINT_GA(",\n");
	PRINT_GA("  system_mem = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->GH(system_mem));
	PRINT_GA(",\n");
	PRINT_GA("  max_system_mem = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->GH(max_system_mem));
	PRINT_GA(",\n");
	PRINT_GA("}\n\n");
}

static bool GH(rz_resolve_main_arena)(RzCore *core, GHT *m_arena) {
	rz_return_val_if_fail(core && core->dbg && core->dbg->maps, false);

	if (core->dbg->main_arena_resolved) {
		return true;
	}

	GHT brk_start = GHT_MAX, brk_end = GHT_MAX;
	GHT libc_addr_sta = GHT_MAX, libc_addr_end = 0;
	GHT addr_srch = GHT_MAX, heap_sz = GHT_MAX;
	GHT main_arena_sym = GHT_MAX;
	bool is_debugged = rz_config_get_b(core->config, "cfg.debug");
	bool first_libc = true;

	if (is_debugged) {
		RzListIter *iter;
		RzDebugMap *map;
		rz_debug_map_sync(core->dbg);
		rz_list_foreach (core->dbg->maps, iter, map) {
			/* Try to find the main arena address using the glibc's symbols. */
			if (strstr(map->name, "/libc-") && first_libc && main_arena_sym == GHT_MAX) {
				first_libc = false;
				main_arena_sym = GH(get_main_arena_with_symbol)(core, map);
			}
			if (strstr(map->name, "/libc-") && map->perm == RZ_PERM_RW) {
				libc_addr_sta = map->addr;
				libc_addr_end = map->addr_end;
				break;
			}
		}
	} else {
		void **it;
		RzPVector *maps = rz_io_maps(core->io);
		rz_pvector_foreach (maps, it) {
			RzIOMap *map = *it;
			if (map->name && strstr(map->name, "arena")) {
				libc_addr_sta = map->itv.addr;
				libc_addr_end = map->itv.addr + map->itv.size;
				break;
			}
		}
	}

	if (libc_addr_sta == GHT_MAX || libc_addr_end == GHT_MAX) {
		if (rz_config_get_b(core->config, "cfg.debug")) {
			eprintf("Warning: Can't find glibc mapped in memory (see dm)\n");
		} else {
			eprintf("Warning: Can't find arena mapped in memory (see om)\n");
		}
		return false;
	}

	GH(get_brks)
	(core, &brk_start, &brk_end);
	if (brk_start == GHT_MAX || brk_end == GHT_MAX) {
		eprintf("No Heap section\n");
		return false;
	}

	addr_srch = libc_addr_sta;
	heap_sz = brk_end - brk_start;
	MallocState *ta = RZ_NEW0(MallocState);
	if (!ta) {
		return false;
	}

	if (main_arena_sym != GHT_MAX) {
		GH(update_main_arena)
		(core, main_arena_sym, ta);
		*m_arena = main_arena_sym;
		core->dbg->main_arena_resolved = true;
		free(ta);
		return true;
	}
	while (addr_srch < libc_addr_end) {
		GH(update_main_arena)
		(core, addr_srch, ta);
		if (ta->GH(top) > brk_start && ta->GH(top) < brk_end &&
			ta->GH(system_mem) == heap_sz) {

			*m_arena = addr_srch;
			free(ta);
			if (is_debugged) {
				core->dbg->main_arena_resolved = true;
			}
			return true;
		}
		addr_srch += sizeof(GHT);
	}
	eprintf("Warning: Can't find main_arena in mapped memory\n");
	free(ta);
	return false;
}

void GH(print_heap_chunk)(RzCore *core) {
	GH(RzHeapChunk) *cnk = RZ_NEW0(GH(RzHeapChunk));
	GHT chunk = core->offset;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!cnk) {
		return;
	}

	(void)rz_io_read_at(core->io, chunk, (ut8 *)cnk, sizeof(*cnk));

	PRINT_GA("struct malloc_chunk @ ");
	PRINTF_BA("0x%" PFMT64x, (ut64)chunk);
	PRINT_GA(" {\n  prev_size = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)cnk->prev_size);
	PRINT_GA(",\n  size = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)cnk->size & ~(NON_MAIN_ARENA | IS_MMAPPED | PREV_INUSE));
	PRINT_GA(",\n  flags: |N:");
	PRINTF_BA("%1" PFMT64u, (ut64)(cnk->size & NON_MAIN_ARENA) >> 2);
	PRINT_GA(" |M:");
	PRINTF_BA("%1" PFMT64u, (ut64)(cnk->size & IS_MMAPPED) >> 1);
	PRINT_GA(" |P:");
	PRINTF_BA("%1" PFMT64u, (ut64)cnk->size & PREV_INUSE);

	PRINT_GA(",\n  fd = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)cnk->fd);

	PRINT_GA(",\n  bk = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)cnk->bk);

	if (cnk->size > SZ * 128) {
		PRINT_GA(",\n  fd-nextsize = ");
		PRINTF_BA("0x%" PFMT64x, (ut64)cnk->fd_nextsize);
		PRINT_GA(",\n  bk-nextsize = ");
		PRINTF_BA("0x%" PFMT64x, (ut64)cnk->bk_nextsize);
	}

	PRINT_GA(",\n}\n");
	GHT size = ((cnk->size >> 3) << 3) - SZ * 2;
	if (size > SZ * 128) {
		PRINT_GA("chunk too big to be displayed\n");
		size = SZ * 128;
	}

	char *data = calloc(1, size);
	if (data) {
		rz_io_read_at(core->io, chunk + SZ * 2, (ut8 *)data, size);
		PRINT_GA("chunk data = \n");
		rz_print_hexdump(core->print, chunk + SZ * 2, (ut8 *)data, size, SZ * 8, SZ, 1);
		free(data);
	}
	free(cnk);
}

/**
 * \brief Prints compact representation of a heap chunk. Format: Chunk(addr=, size=, flags=)
 * \param core RzCore pointer
 * \param chunk Offset of the chunk in memory
 */
void GH(print_heap_chunk_simple)(RzCore *core, GHT chunk, const char *status, PJ *pj) {
	GH(RzHeapChunk) *cnk = RZ_NEW0(GH(RzHeapChunk));
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!cnk) {
		return;
	}

	(void)rz_io_read_at(core->io, chunk, (ut8 *)cnk, sizeof(*cnk));
	if (pj == NULL) {
		PRINT_GA("Chunk");
		rz_cons_printf("(");
		if (status) {
			rz_cons_printf("status=");
			if (!strcmp(status, "free")) {
				PRINTF_GA("%s", status);
				rz_cons_printf("%-6s", ",");
			} else {
				rz_cons_printf("%s,", status);
			}
			rz_cons_printf(" ");
		}
		rz_cons_printf("addr=");
		PRINTF_YA("0x%" PFMT64x, (ut64)chunk);
		rz_cons_printf(", size=");
		PRINTF_BA("0x%" PFMT64x, (ut64)cnk->size & ~(NON_MAIN_ARENA | IS_MMAPPED | PREV_INUSE));
		rz_cons_printf(", flags=");
		bool print_comma = false;
		if (cnk->size & NON_MAIN_ARENA) {
			PRINT_RA("NON_MAIN_ARENA");
			print_comma = true;
		}
		if (cnk->size & IS_MMAPPED) {
			if (print_comma) {
				PRINT_RA(",");
			}
			PRINT_RA("IS_MMAPPED");
			print_comma = true;
		}
		if (cnk->size & PREV_INUSE) {
			if (print_comma) {
				PRINT_RA(",");
			}
			PRINT_RA("PREV_INUSE");
		}
		rz_cons_printf(")");
	} else {
		pj_o(pj);
		pj_kn(pj, "prev_size", cnk->prev_size);
		pj_kn(pj, "addr", chunk);
		pj_kn(pj, "size", (ut64)cnk->size & ~(NON_MAIN_ARENA | IS_MMAPPED | PREV_INUSE));
		pj_kn(pj, "non_main_arena", cnk->size & NON_MAIN_ARENA);
		pj_kn(pj, "mmapped", cnk->size & IS_MMAPPED);
		pj_kn(pj, "prev_inuse", cnk->size & PREV_INUSE);
		pj_kn(pj, "fd", cnk->fd);
		pj_kn(pj, "bk", cnk->bk);
		pj_end(pj);
	}
	free(cnk);
}

static bool GH(is_arena)(RzCore *core, GHT m_arena, GHT m_state) {
	if (m_arena == m_state) {
		return true;
	}
	MallocState *ta = RZ_NEW0(MallocState);
	if (!ta) {
		return false;
	}
	if (!GH(update_main_arena)(core, m_arena, ta)) {
		free(ta);
		return false;
	}
	if (ta->GH(next) == m_state) {
		free(ta);
		return true;
	}
	while (ta->GH(next) != GHT_MAX && ta->GH(next) != m_arena) {
		if (!GH(update_main_arena)(core, ta->GH(next), ta)) {
			free(ta);
			return false;
		}
		if (ta->GH(next) == m_state) {
			free(ta);
			return true;
		}
	}
	free(ta);
	return false;
}

static int GH(print_double_linked_list_bin_simple)(RzCore *core, GHT bin, MallocState *main_arena, GHT brk_start) {
	GHT next = GHT_MAX;
	int ret = 1;
	GH(RzHeapChunk) *cnk = RZ_NEW0(GH(RzHeapChunk));
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!cnk) {
		return -1;
	}

	rz_io_read_at(core->io, bin, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));

	PRINTF_GA("    0x%" PFMT64x, (ut64)bin);
	if (cnk->fd != bin) {
		ret = 0;
	}
	while (cnk->fd != bin) {
		PRINTF_BA("->fd = 0x%" PFMT64x, (ut64)cnk->fd);
		next = cnk->fd;
		if (next < brk_start || next > main_arena->GH(top)) {
			PRINT_RA("Double linked list corrupted\n");
			free(cnk);
			return -1;
		}
		rz_io_read_at(core->io, next, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
	}

	PRINTF_GA("->fd = 0x%" PFMT64x, (ut64)cnk->fd);
	next = cnk->fd;

	if (next != bin) {
		PRINT_RA("Double linked list corrupted\n");
		free(cnk);
		return -1;
	}
	(void)rz_io_read_at(core->io, next, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
	PRINTF_GA("\n    0x%" PFMT64x, (ut64)bin);

	while (cnk->bk != bin) {
		PRINTF_BA("->bk = 0x%" PFMT64x, (ut64)cnk->bk);
		next = cnk->bk;
		if (next < brk_start || next > main_arena->GH(top)) {
			PRINT_RA("Double linked list corrupted.\n");
			free(cnk);
			return -1;
		}
		(void)rz_io_read_at(core->io, next, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
	}

	PRINTF_GA("->bk = 0x%" PFMT64x, (ut64)cnk->bk);
	free(cnk);
	return ret;
}

static int GH(print_double_linked_list_bin_graph)(RzCore *core, GHT bin, MallocState *main_arena, GHT brk_start) {
	RzAGraph *g = rz_agraph_new(rz_cons_canvas_new(1, 1));
	GHT next = GHT_MAX;
	char title[256], chunk[256];
	RzANode *bin_node = NULL, *prev_node = NULL, *next_node = NULL;
	GH(RzHeapChunk) *cnk = RZ_NEW0(GH(RzHeapChunk));
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!cnk || !g) {
		free(cnk);
		rz_agraph_free(g);
		return -1;
	}
	g->can->color = rz_config_get_i(core->config, "scr.color");

	(void)rz_io_read_at(core->io, bin, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
	snprintf(title, sizeof(title) - 1, "bin @ 0x%" PFMT64x "\n", (ut64)bin);
	snprintf(chunk, sizeof(chunk) - 1, "fd: 0x%" PFMT64x "\nbk: 0x%" PFMT64x "\n",
		(ut64)cnk->fd, (ut64)cnk->bk);
	bin_node = rz_agraph_add_node(g, title, chunk);
	prev_node = bin_node;

	while (cnk->bk != bin) {
		next = cnk->bk;
		if (next < brk_start || next > main_arena->GH(top)) {
			PRINT_RA("Double linked list corrupted\n");
			free(cnk);
			free(g);
			return -1;
		}

		rz_io_read_at(core->io, next, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
		snprintf(title, sizeof(title) - 1, "Chunk @ 0x%" PFMT64x "\n", (ut64)next);
		snprintf(chunk, sizeof(chunk) - 1, "fd: 0x%" PFMT64x "\nbk: 0x%" PFMT64x "\n",
			(ut64)cnk->fd, (ut64)cnk->bk);
		next_node = rz_agraph_add_node(g, title, chunk);
		rz_agraph_add_edge(g, prev_node, next_node);
		rz_agraph_add_edge(g, next_node, prev_node);
		prev_node = next_node;
	}

	rz_agraph_add_edge(g, prev_node, bin_node);
	rz_agraph_add_edge(g, bin_node, prev_node);
	rz_agraph_print(g);

	free(cnk);
	rz_agraph_free(g);
	return 0;
}

static int GH(print_double_linked_list_bin)(RzCore *core, MallocState *main_arena, GHT m_arena, GHT offset, GHT num_bin, int graph) {
	if (!core || !core->dbg || !core->dbg->maps) {
		return -1;
	}
	int ret = 0;
	GHT brk_start = GHT_MAX, brk_end = GHT_MAX, initial_brk = GHT_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (num_bin > 126) {
		return -1;
	}
	GHT bin = main_arena->GH(bins)[num_bin];

	if (!bin) {
		return -1;
	}

	GH(get_brks)
	(core, &brk_start, &brk_end);
	if (brk_start == GHT_MAX || brk_end == GHT_MAX) {
		eprintf("No Heap section\n");
		return -1;
	}

	const int tcache = rz_config_get_i(core->config, "dbg.glibc.tcache");
	if (tcache) {
		const int fc_offset = rz_config_get_i(core->config, "dbg.glibc.fc_offset");
		bin = m_arena + offset + SZ * num_bin * 2 + 10 * SZ;
		initial_brk = ((brk_start >> 12) << 12) + fc_offset;
	} else {
		bin = m_arena + offset + SZ * num_bin * 2 - SZ * 2;
		initial_brk = (brk_start >> 12) << 12;
	}

	if (num_bin == 0) {
		PRINT_GA("  double linked list unsorted bin {\n");
	} else if (num_bin >= 1 && num_bin <= NSMALLBINS - 1) {
		PRINT_GA("  double linked list small bin {\n");
	} else if (num_bin >= NSMALLBINS && num_bin <= NBINS - 2) {
		PRINT_GA("  double linked list large bin {\n");
	}

	if (!graph || graph == 1) {
		ret = GH(print_double_linked_list_bin_simple)(core, bin, main_arena, initial_brk);
	} else {
		ret = GH(print_double_linked_list_bin_graph)(core, bin, main_arena, initial_brk);
	}
	PRINT_GA("\n  }\n");
	return ret;
}

static void GH(print_heap_bin)(RzCore *core, GHT m_arena, MallocState *main_arena, const char *input) {
	int i, j = 2;
	GHT num_bin = GHT_MAX;
	GHT offset;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	const int tcache = rz_config_get_i(core->config, "dbg.glibc.tcache");
	if (tcache) {
		offset = 16;
	} else {
		offset = 12 * SZ + sizeof(int) * 2;
	}

	switch (input[0]) {
	case '\0': // dmhb
		PRINT_YA("Bins {\n");
		for (i = 0; i < NBINS - 1; i++) {
			PRINTF_YA(" Bin %03d:\n", i + 1);
			GH(print_double_linked_list_bin)
			(core, main_arena, m_arena, offset, i, 0);
		}
		PRINT_YA("\n}\n");
		break;
	case ' ': // dmhb [bin_num]
		j--; // for spaces after input
		/* fallthu */
	case 'g': // dmhbg [bin_num]
		num_bin = rz_num_get(NULL, input + j) - 1;
		if (num_bin > NBINS - 2) {
			eprintf("Error: 0 < bin <= %d\n", NBINS - 1);
			break;
		}
		PRINTF_YA("  Bin %03" PFMT64u ":\n", (ut64)num_bin + 1);
		GH(print_double_linked_list_bin)
		(core, main_arena, m_arena, offset, num_bin, j);
		break;
	}
}

static int GH(print_single_linked_list_bin)(RzCore *core, MallocState *main_arena, GHT m_arena, GHT offset, GHT bin_num, PJ *pj) {
	if (!core || !core->dbg || !core->dbg->maps) {
		return -1;
	}
	GHT next = GHT_MAX, brk_start = GHT_MAX, brk_end = GHT_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	GH(RzHeapChunk) *cnk = RZ_NEW0(GH(RzHeapChunk));
	if (!cnk) {
		return 0;
	}

	if (!GH(update_main_arena)(core, m_arena, main_arena)) {
		free(cnk);
		return 0;
	}

	GHT bin = main_arena->GH(fastbinsY)[bin_num];
	if (!bin) {
		free(cnk);
		return -1;
	}

	bin = m_arena + offset + SZ * bin_num;
	rz_io_read_at(core->io, bin, (ut8 *)&next, SZ);

	GH(get_brks)
	(core, &brk_start, &brk_end);
	if (brk_start == GHT_MAX || brk_end == GHT_MAX) {
		eprintf("No Heap section\n");
		free(cnk);
		return 0;
	}
	if (!pj) {
		rz_cons_printf("\n -> ");
	}
	GHT size = main_arena->GH(top) - brk_start;

	GHT next_root = next, next_tmp = next, double_free = GHT_MAX;
	while (next && next >= brk_start && next < main_arena->GH(top)) {
		GH(print_heap_chunk_simple)
		(core, (ut64)next, NULL, pj);
		if (!pj) {
			rz_cons_newline();
		}
		while (double_free == GHT_MAX && next_tmp && next_tmp >= brk_start && next_tmp <= main_arena->GH(top)) {
			rz_io_read_at(core->io, next_tmp, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
			next_tmp = GH(get_next_pointer)(core, next_tmp, cnk->fd);
			if (cnk->prev_size > size || ((cnk->size >> 3) << 3) > size) {
				break;
			}
			if (next_root == next_tmp) {
				double_free = next_root;
				break;
			}
		}
		rz_io_read_at(core->io, next, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
		next = GH(get_next_pointer)(core, next, cnk->fd);
		if (!pj) {
			rz_cons_printf("%s", next ? " -> " : "");
		}
		if (cnk->prev_size > size || ((cnk->size >> 3) << 3) > size) {
			PRINTF_RA(" 0x%" PFMT64x, (ut64)next);
			PRINT_RA(" Linked list corrupted\n");
			free(cnk);
			return -1;
		}

		next_root = next_tmp = next;
		if (double_free == next) {
			PRINTF_RA("0x%" PFMT64x, (ut64)next);
			PRINT_RA(" Double free detected\n");
			free(cnk);
			return -1;
		}
	}

	if (next && (next < brk_start || next >= main_arena->GH(top))) {
		PRINTF_RA("0x%" PFMT64x, (ut64)next);
		PRINT_RA(" Linked list corrupted\n");
		free(cnk);
		return -1;
	}

	free(cnk);
	return 0;
}

void GH(print_heap_fastbin)(RzCore *core, GHT m_arena, MallocState *main_arena, GHT global_max_fast, const char *input, bool main_arena_only, PJ *pj) {
	size_t i, j, k;
	GHT num_bin = GHT_MAX, offset = sizeof(int) * 2;
	const int tcache = rz_config_get_i(core->config, "dbg.glibc.tcache");
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (tcache) {
		offset = 16;
	}

	int fastbins_max = rz_config_get_i(core->config, "dbg.glibc.fastbinmax") - 1;
	int global_max_fast_idx = fastbin_index(global_max_fast);
	int fastbin_count = fastbins_max < global_max_fast_idx ? fastbins_max : global_max_fast_idx;

	switch (input[0]) {
	case '\0': // dmhf
		if (!main_arena_only && core->offset != core->prompt_offset) {
			m_arena = core->offset;
		}
		if (!pj) {
			rz_cons_printf("Fast bins in Arena @ ");
			PRINTF_YA("0x%" PFMT64x "\n", (ut64)m_arena);
		}
		for (i = 0, j = 1, k = SZ * 4; i <= fastbin_count; i++, j++, k += SZ * 2) {
			if (!pj) {
				rz_cons_printf("Fast_bin[");
				PRINTF_BA("%02zu", j);
				rz_cons_printf("] [size: ");
				PRINTF_BA("0x%" PFMT64x, (ut64)k);
				rz_cons_printf("]");
			} else {
				pj_o(pj);
				pj_ks(pj, "bin_type", "fast");
				pj_kn(pj, "bin_num", j);
				pj_ka(pj, "chunks");
			}
			if (GH(print_single_linked_list_bin)(core, main_arena, m_arena, offset, i, pj)) {
				if (!pj) {
					PRINT_RA(" Empty bin\n");
				}
			}
			if (pj) {
				pj_end(pj);
				pj_end(pj);
			}
		}
		break;
	case ' ': // dmhf [bin_num]
		num_bin = rz_num_get(NULL, input) - 1;
		if (num_bin >= fastbin_count + 1) {
			eprintf("Error: 0 < bin <= %d\n", fastbin_count + 1);
			break;
		}
		rz_cons_printf("Fast_bin[");
		PRINTF_BA("%02zu", (size_t)(num_bin + 1));
		rz_cons_printf("] [size: ");
		PRINTF_BA("0x%" PFMT64x, (ut64)FASTBIN_IDX_TO_SIZE(num_bin + 1));
		rz_cons_printf("]");
		if (GH(print_single_linked_list_bin)(core, main_arena, m_arena, offset, num_bin, pj)) {
			PRINT_RA(" Empty bin\n");
		}
		break;
	}
}

static GH(RTcache) * GH(tcache_new)(RzCore *core) {
	rz_return_val_if_fail(core, NULL);
	GH(RTcache) *tcache = RZ_NEW0(GH(RTcache));
	if (core->dbg->glibc_version >= TCACHE_NEW_VERSION) {
		tcache->type = NEW;
		tcache->RzHeapTcache.heap_tcache = RZ_NEW0(GH(RzHeapTcache));
	} else {
		tcache->type = OLD;
		tcache->RzHeapTcache.heap_tcache_pre_230 = RZ_NEW0(GH(RzHeapTcachePre230));
	}
	return tcache;
}

static void GH(tcache_free)(GH(RTcache) * tcache) {
	rz_return_if_fail(tcache);
	tcache->type == NEW
		? free(tcache->RzHeapTcache.heap_tcache)
		: free(tcache->RzHeapTcache.heap_tcache_pre_230);
	free(tcache);
}

static bool GH(tcache_read)(RzCore *core, GHT tcache_start, GH(RTcache) * tcache) {
	rz_return_val_if_fail(core && tcache, false);
	return tcache->type == NEW
		? rz_io_read_at(core->io, tcache_start, (ut8 *)tcache->RzHeapTcache.heap_tcache, sizeof(GH(RzHeapTcache)))
		: rz_io_read_at(core->io, tcache_start, (ut8 *)tcache->RzHeapTcache.heap_tcache_pre_230, sizeof(GH(RzHeapTcachePre230)));
}

static int GH(tcache_get_count)(GH(RTcache) * tcache, int index) {
	rz_return_val_if_fail(tcache, 0);
	return tcache->type == NEW
		? tcache->RzHeapTcache.heap_tcache->counts[index]
		: tcache->RzHeapTcache.heap_tcache_pre_230->counts[index];
}

static GHT GH(tcache_get_entry)(GH(RTcache) * tcache, int index) {
	rz_return_val_if_fail(tcache, 0);
	return tcache->type == NEW
		? tcache->RzHeapTcache.heap_tcache->entries[index]
		: tcache->RzHeapTcache.heap_tcache_pre_230->entries[index];
}

static void GH(tcache_print)(RzCore *core, GH(RTcache) * tcache, PJ *pj) {
	rz_return_if_fail(core && tcache);
	GHT tcache_fd = GHT_MAX;
	GHT tcache_tmp = GHT_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	size_t i;
	for (i = 0; i < TCACHE_MAX_BINS; i++) {
		int count = GH(tcache_get_count)(tcache, i);
		GHT entry = GH(tcache_get_entry)(tcache, i);
		if (count > 0) {
			if (!pj) {
				PRINT_GA("Tcache_bin[");
				PRINTF_BA("%02zu", i);
				PRINT_GA("] Items:");
				PRINTF_BA("%2d", count);
				rz_cons_newline();
				rz_cons_printf(" -> ");
			} else {
				pj_o(pj);
				pj_ks(pj, "bin_type", "tcache");
				pj_kn(pj, "bin_num", i);
				pj_ka(pj, "chunks");
			}
			GH(print_heap_chunk_simple)
			(core, (ut64)(entry - GH(HDR_SZ)), NULL, pj);
			if (count > 1) {
				tcache_fd = entry;
				size_t n;
				for (n = 1; n < count; n++) {
					bool r = rz_io_read_at(core->io, tcache_fd, (ut8 *)&tcache_tmp, sizeof(GHT));
					if (!r) {
						break;
					}
					tcache_tmp = GH(get_next_pointer)(core, tcache_fd, read_le(&tcache_tmp));
					if (!pj) {
						rz_cons_printf("\n -> ");
					}
					GH(print_heap_chunk_simple)
					(core, (ut64)(tcache_tmp - TC_HDR_SZ), NULL, pj);
					tcache_fd = tcache_tmp;
				}
			}
			if (!pj) {
				PRINT_BA("\n");
			} else {
				pj_end(pj);
				pj_end(pj);
			}
		}
	}
}

static void GH(print_tcache_instance)(RzCore *core, GHT m_arena, MallocState *main_arena, bool main_thread_only, PJ *pj) {
	rz_return_if_fail(core && core->dbg && core->dbg->maps);

	const int tcache = rz_config_get_i(core->config, "dbg.glibc.tcache");
	if (!tcache) {
		rz_cons_printf("No Tcache in this libc version\n");
		return;
	}
	GHT brk_start = GHT_MAX, brk_end = GHT_MAX, initial_brk = GHT_MAX;
	GH(get_brks)
	(core, &brk_start, &brk_end);
	GHT tcache_start = GHT_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	tcache_start = brk_start + 0x10;
	GHT fc_offset = GH(tcache_chunk_size)(core, brk_start);
	initial_brk = brk_start + fc_offset;
	if (brk_start == GHT_MAX || brk_end == GHT_MAX || initial_brk == GHT_MAX) {
		eprintf("No heap section\n");
		return;
	}

	GH(RTcache) *rz_tcache = GH(tcache_new)(core);
	if (!rz_tcache) {
		return;
	}
	if (!GH(tcache_read)(core, tcache_start, rz_tcache)) {
		return;
	}
	if (!pj) {
		rz_cons_printf("Tcache bins in Main Arena @");
		PRINTF_YA(" 0x%" PFMT64x "\n", (ut64)m_arena);
	}
	GH(tcache_print)
	(core, rz_tcache, pj);
	if (main_thread_only) {
		return;
	}

	if (main_arena->GH(next) != m_arena) {
		GHT mmap_start = GHT_MAX, tcache_start = GHT_MAX;
		MallocState *ta = RZ_NEW0(MallocState);
		if (!ta) {
			free(ta);
			GH(tcache_free)
			(rz_tcache);
			return;
		}
		ta->GH(next) = main_arena->GH(next);
		while (GH(is_arena)(core, m_arena, ta->GH(next)) && ta->GH(next) != m_arena) {
			if (!pj) {
				PRINT_YA("Tcache in Thread Arena @ ");
				PRINTF_BA(" 0x%" PFMT64x, (ut64)ta->GH(next));
			}
			mmap_start = ((ta->GH(next) >> 16) << 16);
			tcache_start = mmap_start + sizeof(GH(RzHeapInfo)) + sizeof(GH(RzHeap_MallocState_tcache)) + GH(MMAP_ALIGN);

			if (!GH(update_main_arena)(core, ta->GH(next), ta)) {
				free(ta);
				GH(tcache_free)
				(rz_tcache);
				return;
			}

			if (ta->attached_threads) {
				PRINT_BA("\n");
				GH(tcache_read)
				(core, tcache_start, rz_tcache);
				GH(tcache_print)
				(core, rz_tcache, pj);
			} else {
				PRINT_GA(" free\n");
			}
		}
	}
	GH(tcache_free)
	(rz_tcache);
	if (pj) {
		pj_end(pj);
		pj_end(pj);
	}
}

static void GH(print_heap_segment)(RzCore *core, MallocState *main_arena,
	GHT m_arena, GHT m_state, GHT global_max_fast, int format_out) {

	if (!core || !core->dbg || !core->dbg->maps) {
		return;
	}

	int w, h;
	GHT brk_start = GHT_MAX, brk_end = GHT_MAX, size_tmp, min_size = SZ * 4;
	GHT tcache_fd = GHT_MAX, tcache_tmp = GHT_MAX;
	GHT initial_brk = GHT_MAX, tcache_initial_brk = GHT_MAX;

	const int tcache = rz_config_get_i(core->config, "dbg.glibc.tcache");
	const int offset = rz_config_get_i(core->config, "dbg.glibc.fc_offset");
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	int glibc_version = core->dbg->glibc_version;

	if (m_arena == m_state) {
		GH(get_brks)
		(core, &brk_start, &brk_end);
		if (tcache) {
			initial_brk = ((brk_start >> 12) << 12) + GH(HDR_SZ);
			if (rz_config_get_b(core->config, "cfg.debug")) {
				tcache_initial_brk = initial_brk;
			}
			initial_brk += (glibc_version < 230)
				? sizeof(GH(RzHeapTcachePre230))
				: sizeof(GH(RzHeapTcache));
		} else {
			initial_brk = (brk_start >> 12) << 12;
		}
	} else {
		brk_start = ((m_state >> 16) << 16);
		brk_end = brk_start + main_arena->GH(system_mem);
		if (tcache) {
			tcache_initial_brk = brk_start + sizeof(GH(RzHeapInfo)) + sizeof(GH(RzHeap_MallocState_tcache)) + GH(MMAP_ALIGN);
			initial_brk = tcache_initial_brk + offset;
		} else {
			initial_brk = brk_start + sizeof(GH(RzHeapInfo)) + sizeof(GH(RzHeap_MallocState)) + MMAP_OFFSET;
		}
	}

	if (brk_start == GHT_MAX || brk_end == GHT_MAX || initial_brk == GHT_MAX) {
		eprintf("No Heap section\n");
		return;
	}

	GHT next_chunk = initial_brk, prev_chunk = next_chunk;
	GH(RzHeapChunk) *cnk = RZ_NEW0(GH(RzHeapChunk));
	if (!cnk) {
		return;
	}
	GH(RzHeapChunk) *cnk_next = RZ_NEW0(GH(RzHeapChunk));
	if (!cnk_next) {
		free(cnk);
		return;
	}

	RzConfigHold *hc = rz_config_hold_new(core->config);
	if (!hc) {
		free(cnk);
		free(cnk_next);
		return;
	}

	w = rz_cons_get_size(&h);
	RzConsCanvas *can = rz_cons_canvas_new(w, h);
	if (!can) {
		free(cnk);
		free(cnk_next);
		rz_config_hold_free(hc);
		return;
	}

	RzAGraph *g = rz_agraph_new(can);
	if (!g) {
		free(cnk);
		free(cnk_next);
		rz_cons_canvas_free(can);
		rz_config_hold_restore(hc);
		rz_config_hold_free(hc);
		return;
	}

	RzANode *top = RZ_EMPTY, *chunk_node = RZ_EMPTY, *prev_node = RZ_EMPTY;
	char *top_title, *top_data, *node_title, *node_data;
	bool first_node = true;

	top_data = rz_str_new("");
	top_title = rz_str_new("");

	(void)rz_io_read_at(core->io, next_chunk, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
	size_tmp = (cnk->size >> 3) << 3;
	ut64 prev_chunk_addr;
	ut64 prev_chunk_size;
	PJ *pj = NULL;

	switch (format_out) {
	case 'j':
		pj = rz_core_pj_new(core);
		if (!pj) {
			return;
		}
		pj_o(pj);
		pj_ka(pj, "chunks");
		break;
	case '*':
		rz_cons_printf("fs+heap.allocated\n");
		break;
	case 'g':
		can->linemode = rz_config_get_i(core->config, "graph.linemode");
		can->color = rz_config_get_i(core->config, "scr.color");
		core->cons->use_utf8 = rz_config_get_i(core->config, "scr.utf8");
		g->layout = rz_config_get_i(core->config, "graph.layout");
		rz_agraph_set_title(g, "Heap Layout");
		top_title = rz_str_newf("Top chunk @ 0x%" PFMT64x "\n", (ut64)main_arena->GH(top));
	case 'c':
	case 'v':
		rz_cons_printf("Arena @ ");
		PRINTF_YA("0x%" PFMT64x, (ut64)m_state);
		rz_cons_newline();
	}

	while (next_chunk && next_chunk >= brk_start && next_chunk < main_arena->GH(top)) {
		if (size_tmp < min_size || next_chunk + size_tmp > main_arena->GH(top)) {
			const char *status = "corrupted";
			switch (format_out) {
			case 'v':
				GH(print_heap_chunk_simple)
				(core, next_chunk, status, NULL);
				rz_cons_newline();
				PRINTF_RA("   size: 0x%" PFMT64x "\n   fd: 0x%" PFMT64x ", bk: 0x%" PFMT64x "\n",
					(ut64)cnk->size, (ut64)cnk->fd, (ut64)cnk->bk);
				int size = 0x10;
				char *data = calloc(1, size);
				if (data) {
					rz_io_nread_at(core->io, (ut64)(next_chunk + SZ * 2), (ut8 *)data, size);
					core->print->flags &= ~RZ_PRINT_FLAGS_HEADER;
					core->print->pairs = false;
					PRINT_GA("  ");
					rz_print_hexdump(core->print, (ut64)(next_chunk + SZ * 2), (ut8 *)data, size, SZ * 2, 1, 1);
					core->print->flags |= RZ_PRINT_FLAGS_HEADER;
					core->print->pairs = true;
					free(data);
				}
				break;
			case 'c':
				GH(print_heap_chunk_simple)
				(core, next_chunk, status, NULL);
				rz_cons_newline();
				PRINTF_RA("   size: 0x%" PFMT64x "\n   fd: 0x%" PFMT64x ", bk: 0x%" PFMT64x "\n",
					(ut64)cnk->size, (ut64)cnk->fd, (ut64)cnk->bk);
				break;
			case 'j':
				pj_o(pj);
				pj_kn(pj, "addr", next_chunk);
				pj_kn(pj, "size", cnk->size);
				pj_ks(pj, "status", status);
				pj_kN(pj, "fd", cnk->fd);
				pj_kN(pj, "bk", cnk->bk);
				pj_end(pj);
				break;
			case '*':
				rz_cons_printf("fs heap.corrupted\n");
				char *name = rz_str_newf("chunk.corrupted.%06" PFMT64x, ((prev_chunk >> 4) & 0xffffULL));
				rz_cons_printf("f %s %d 0x%" PFMT64x "\n", name, (int)cnk->size, (ut64)prev_chunk);
				free(name);
				break;
			case 'g':
				node_title = rz_str_newf("  Malloc chunk @ 0x%" PFMT64x " ", (ut64)prev_chunk);
				node_data = rz_str_newf("[corrupted] size: 0x%" PFMT64x "\n fd: 0x%" PFMT64x ", bk: 0x%" PFMT64x
							"\nHeap graph could not be recovered\n",
					(ut64)cnk->size, (ut64)cnk->fd, (ut64)cnk->bk);
				rz_agraph_add_node(g, node_title, node_data);
				if (first_node) {
					first_node = false;
				}
				break;
			}
			break;
		}

		prev_chunk_addr = (ut64)prev_chunk;
		prev_chunk_size = (((ut64)cnk->size) >> 3) << 3;

		bool fastbin = size_tmp >= SZ * 4 && size_tmp <= global_max_fast;
		bool is_free = false, double_free = false;

		if (fastbin) {
			int i = (size_tmp / (SZ * 2)) - 2;
			GHT idx = (GHT)main_arena->GH(fastbinsY)[i];
			(void)rz_io_read_at(core->io, idx, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
			GHT next = GH(get_next_pointer)(core, idx, cnk->fd);
			if (prev_chunk == idx && idx && !next) {
				is_free = true;
			}
			while (next && next >= brk_start && next < main_arena->GH(top)) {
				if (prev_chunk == idx || prev_chunk == next || idx == next) {
					is_free = true;
					if (idx == next) {
						double_free = true;
						break;
					}
					(void)rz_io_read_at(core->io, next, (ut8 *)cnk_next, sizeof(GH(RzHeapChunk)));
					GHT next_node = GH(get_next_pointer)(core, next, cnk_next->fd);
					// avoid triple while?
					while (next_node && next_node >= brk_start && next_node < main_arena->GH(top)) {
						if (prev_chunk == next_node) {
							double_free = true;
							break;
						}
						(void)rz_io_read_at(core->io, next_node, (ut8 *)cnk_next, sizeof(GH(RzHeapChunk)));
						next_node = GH(get_next_pointer)(core, next_node, cnk_next->fd);
					}
					if (double_free) {
						break;
					}
				}
				(void)rz_io_read_at(core->io, next, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
				next = GH(get_next_pointer)(core, next, cnk->fd);
			}
			if (double_free) {
				PRINT_RA(" Double free in simple-linked list detected ");
				break;
			}
			prev_chunk_size = ((i + 1) * GH(HDR_SZ)) + GH(HDR_SZ);
		}

		if (tcache) {
			GH(RTcache) *tcache_heap = GH(tcache_new)(core);
			if (!tcache_heap) {
				rz_cons_canvas_free(can);
				rz_config_hold_restore(hc);
				rz_config_hold_free(hc);
				free(g);
				free(cnk);
				free(cnk_next);
				return;
			}
			GH(tcache_read)
			(core, tcache_initial_brk, tcache_heap);
			size_t i;
			for (i = 0; i < TCACHE_MAX_BINS; i++) {
				int count = GH(tcache_get_count)(tcache_heap, i);
				GHT entry = GH(tcache_get_entry)(tcache_heap, i);
				if (count > 0) {
					if (entry - SZ * 2 == prev_chunk) {
						is_free = true;
						prev_chunk_size = ((i + 1) * TC_HDR_SZ + GH(TC_SZ));
						break;
					}
					if (count > 1) {
						tcache_fd = entry;
						int n;
						for (n = 1; n < count; n++) {
							bool r = rz_io_read_at(core->io, tcache_fd, (ut8 *)&tcache_tmp, sizeof(GHT));
							if (!r) {
								break;
							}
							tcache_tmp = GH(get_next_pointer)(core, tcache_fd, read_le(&tcache_tmp));
							if (tcache_tmp - SZ * 2 == prev_chunk) {
								is_free = true;
								prev_chunk_size = ((i + 1) * TC_HDR_SZ + GH(TC_SZ));
								break;
							}
							tcache_fd = (ut64)tcache_tmp;
						}
					}
				}
			}
			GH(tcache_free)
			(tcache_heap);
		}

		next_chunk += size_tmp;
		prev_chunk = next_chunk;
		rz_io_read_at(core->io, next_chunk, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
		size_tmp = (cnk->size >> 3) << 3;

		const char *status = "allocated";
		if (fastbin) {
			if (is_free) {
				status = "free";
			}
		}
		if (!(cnk->size & 1)) {
			status = "free";
		}
		if (tcache) {
			if (is_free) {
				status = "free";
			}
		}

		switch (format_out) {
		case 'c':
			GH(print_heap_chunk_simple)
			(core, prev_chunk_addr, status, NULL);
			rz_cons_newline();
			break;
		case 'v':
			GH(print_heap_chunk_simple)
			(core, prev_chunk_addr, status, NULL);
			rz_cons_newline();
			int size = 0x10;
			char *data = calloc(1, size);
			if (data) {
				rz_io_nread_at(core->io, (ut64)(prev_chunk_addr + SZ * 2), (ut8 *)data, size);
				core->print->flags &= ~RZ_PRINT_FLAGS_HEADER;
				core->print->pairs = false;
				rz_cons_printf("   ");
				rz_print_hexdump(core->print, (ut64)(prev_chunk_addr + SZ * 2), (ut8 *)data, size, SZ * 2, 1, 1);
				core->print->flags |= RZ_PRINT_FLAGS_HEADER;
				core->print->pairs = true;
				free(data);
			}
			break;
		case 'j':
			pj_o(pj);
			pj_kn(pj, "addr", prev_chunk_addr);
			pj_kn(pj, "size", prev_chunk_size);
			pj_ks(pj, "status", status);
			pj_end(pj);
			break;
		case '*':
			rz_cons_printf("fs heap.%s\n", status);
			char *name = rz_str_newf("chunk.%06" PFMT64x, ((prev_chunk_addr >> 4) & 0xffffULL));
			rz_cons_printf("f %s %d 0x%" PFMT64x "\n", name, (int)prev_chunk_size, (ut64)prev_chunk_addr);
			free(name);
			break;
		case 'g':
			node_title = rz_str_newf("  Malloc chunk @ 0x%" PFMT64x " ", (ut64)prev_chunk_addr);
			node_data = rz_str_newf("size: 0x%" PFMT64x " status: %s\n", (ut64)prev_chunk_size, status);
			chunk_node = rz_agraph_add_node(g, node_title, node_data);
			if (first_node) {
				first_node = false;
			} else {
				rz_agraph_add_edge(g, prev_node, chunk_node);
			}
			prev_node = chunk_node;
			break;
		}
	}

	switch (format_out) {
	case 'v':
	case 'c':
		GH(print_heap_chunk_simple)
		(core, main_arena->GH(top), "free", NULL);
		PRINT_RA("[top]");
		rz_cons_printf("[brk_start: ");
		PRINTF_YA("0x%" PFMT64x, (ut64)brk_start);
		rz_cons_printf(", brk_end: ");
		PRINTF_YA("0x%" PFMT64x, (ut64)brk_end);
		rz_cons_printf("]\n");
		break;
	case 'j':
		pj_end(pj);
		pj_kn(pj, "top", main_arena->GH(top));
		pj_kn(pj, "brk", brk_start);
		pj_kn(pj, "end", brk_end);
		pj_end(pj);
		rz_cons_print(pj_string(pj));
		pj_free(pj);
		break;
	case '*':
		rz_cons_printf("fs-\n");
		rz_cons_printf("f heap.top = 0x%08" PFMT64x "\n", (ut64)main_arena->GH(top));
		rz_cons_printf("f heap.brk = 0x%08" PFMT64x "\n", (ut64)brk_start);
		rz_cons_printf("f heap.end = 0x%08" PFMT64x "\n", (ut64)brk_end);
		break;
	case 'g':
		top = rz_agraph_add_node(g, top_title, top_data);
		if (!first_node) {
			rz_agraph_add_edge(g, prev_node, top);
			free(node_data);
			free(node_title);
		}
		rz_agraph_print(g);
		rz_cons_canvas_free(can);
		rz_config_hold_restore(hc);
		rz_config_hold_free(hc);
		break;
	}

	rz_cons_printf("\n");
	free(g);
	free(top_data);
	free(top_title);
	free(cnk);
	free(cnk_next);
}

void GH(print_malloc_states)(RzCore *core, GHT m_arena, MallocState *main_arena) {
	MallocState *ta = RZ_NEW0(MallocState);
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!ta) {
		return;
	}
	PRINT_YA("main_arena @ ");
	PRINTF_BA("0x%" PFMT64x "\n", (ut64)m_arena);
	if (main_arena->GH(next) != m_arena) {
		ta->GH(next) = main_arena->GH(next);
		while (GH(is_arena)(core, m_arena, ta->GH(next)) && ta->GH(next) != m_arena) {
			PRINT_YA("thread arena @ ");
			PRINTF_BA("0x%" PFMT64x, (ut64)ta->GH(next));
			if (!GH(update_main_arena)(core, ta->GH(next), ta)) {
				free(ta);
				return;
			}
			if (ta->attached_threads) {
				PRINT_BA("\n");
			} else {
				PRINT_GA(" free\n");
			}
		}
	}
	free(ta);
}

void GH(print_inst_minfo)(GH(RzHeapInfo) * heap_info, GHT hinfo) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	PRINT_YA("malloc_info @ ");
	PRINTF_BA("0x%" PFMT64x, (ut64)hinfo);
	PRINT_YA(" {\n  ar_ptr = ");
	PRINTF_BA("0x%" PFMT64x "\n", (ut64)heap_info->ar_ptr);
	PRINT_YA("  prev = ");
	PRINTF_BA("0x%" PFMT64x "\n", (ut64)heap_info->prev);
	PRINT_YA("  size = ");
	PRINTF_BA("0x%" PFMT64x "\n", (ut64)heap_info->size);
	PRINT_YA("  mprotect_size = ");
	PRINTF_BA("0x%" PFMT64x "\n", (ut64)heap_info->mprotect_size);
	PRINT_YA("}\n\n");
}

void GH(print_malloc_info)(RzCore *core, GHT m_state, GHT malloc_state) {
	GHT h_info;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (malloc_state == m_state) {
		PRINT_RA("main_arena does not have an instance of malloc_info\n");
	} else if (GH(is_arena)(core, malloc_state, m_state)) {

		h_info = (malloc_state >> 16) << 16;
		GH(RzHeapInfo) *heap_info = RZ_NEW0(GH(RzHeapInfo));
		if (!heap_info) {
			return;
		}
		rz_io_read_at(core->io, h_info, (ut8 *)heap_info, sizeof(GH(RzHeapInfo)));
		GH(print_inst_minfo)
		(heap_info, h_info);
		MallocState *ms = RZ_NEW0(MallocState);
		if (!ms) {
			free(heap_info);
			return;
		}

		while (heap_info->prev != 0x0 && heap_info->prev != GHT_MAX) {
			if (!GH(update_main_arena)(core, malloc_state, ms)) {
				free(ms);
				free(heap_info);
				return;
			}
			if ((ms->GH(top) >> 16) << 16 != h_info) {
				h_info = (ms->GH(top) >> 16) << 16;
				rz_io_read_at(core->io, h_info, (ut8 *)heap_info, sizeof(GH(RzHeapInfo)));
				GH(print_inst_minfo)
				(heap_info, h_info);
			}
		}
		free(heap_info);
		free(ms);
	} else {
		PRINT_RA("This address is not part of the arenas\n");
	}
}

/**
 * \brief Prints the heap chunks in a bin with double linked list (small|large|unsorted)
 * \param core RzCore pointer
 * \param main_arena MallocState struct for the arena in which bins are
 * \param bin_num The bin number for the bin from which chunks have to printed
 * \return number of chunks found in the bin
 */
static int GH(print_bin_content)(RzCore *core, MallocState *main_arena, int bin_num, PJ *pj) {
	int idx = 2 * bin_num;
	ut64 fw = main_arena->GH(bins)[idx];
	ut64 bk = main_arena->GH(bins)[idx + 1];

	GH(RzHeapChunk) *head = RZ_NEW0(GH(RzHeapChunk));
	if (!head) {
		return 0;
	}
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	(void)rz_io_read_at(core->io, bk, (ut8 *)head, sizeof(GH(RzHeapChunk)));

	size_t chunks_cnt = 0;
	if (head->fd == fw) {
		return chunks_cnt;
	}
	if (!pj) {
		if (bin_num == 0) {
			rz_cons_printf("Unsorted");
		} else if (bin_num >= 1 && bin_num <= NSMALLBINS - 1) {
			rz_cons_printf("Small");
		} else if (bin_num >= NSMALLBINS && bin_num <= NBINS - 2) {
			rz_cons_printf("Large");
		}
		rz_cons_printf("_bin[");
		PRINTF_BA("%d", bin_num);
		rz_cons_printf("]: fd=");
		PRINTF_YA("0x%" PFMT64x, fw);
		rz_cons_printf(", bk=");
		PRINTF_YA("0x%" PFMT64x, bk);
		rz_cons_newline();
	} else {
		pj_kn(pj, "fd", fw);
		pj_kn(pj, "bk", bk);
		pj_ka(pj, "chunks");
	}
	GH(RzHeapChunk) *cnk = RZ_NEW0(GH(RzHeapChunk));

	if (!cnk) {
		return 0;
	}

	while (fw != head->fd) {
		rz_io_read_at(core->io, fw, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
		if (!pj) {
			rz_cons_printf(" -> ");
		}
		GH(print_heap_chunk_simple)
		(core, fw, NULL, pj);
		if (!pj) {
			rz_cons_newline();
		}
		fw = cnk->fd;
		chunks_cnt += 1;
	}
	free(cnk);
	free(head);
	if (pj) {
		pj_end(pj);
	}
	return chunks_cnt;
}

/**
 * \brief Prints unsorted bin description for an arena (used for `dmhd` command)
 * \param core RzCore pointer
 * \param m_arena Offset of the arena in memory
 * \param main_arena MallocState struct for the arena in which bin are
 */
static void GH(print_unsortedbin_description)(RzCore *core, GHT m_arena, MallocState *main_arena, PJ *pj) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	if (!pj) {
		rz_cons_printf("Unsorted bin in Arena @ ");
		PRINTF_YA("0x%" PFMT64x "\n", (ut64)m_arena);
	}
	if (pj) {
		pj_o(pj);
		pj_kn(pj, "bin_num", 0);
		pj_ks(pj, "bin_type", "unsorted");
	}
	int chunk_cnt = GH(print_bin_content)(core, main_arena, 0, pj);
	if (!pj) {
		rz_cons_printf("Found %d chunks in unsorted bin\n", chunk_cnt);
	} else {
		pj_end(pj);
	}
}

/**
 * \brief Prints small bins description for an arena (used for `dmhd` command)
 * \param core RzCore pointer
 * \param m_arena Offset of the arena in memory
 * \param main_arena Pointer to MallocState struct for the arena in which bins are
 */
static void GH(print_smallbin_description)(RzCore *core, GHT m_arena, MallocState *main_arena, PJ *pj) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	if (!pj) {
		rz_cons_printf("Small bins in Arena @ ");
		PRINTF_YA("0x%" PFMT64x "\n", (ut64)m_arena);
	}
	int chunk_cnt = 0;
	int non_empty_cnt = 0;
	for (int bin_num = 1; bin_num < NSMALLBINS; bin_num++) {
		if (pj) {
			pj_o(pj);
			pj_kn(pj, "bin_num", bin_num);
			pj_ks(pj, "bin_type", "small");
		}
		int chunk_found = GH(print_bin_content)(core, main_arena, bin_num, pj);
		if (pj) {
			pj_end(pj);
		}
		if (chunk_found > 0) {
			non_empty_cnt += 1;
		}
		chunk_cnt += chunk_found;
	}
	if (!pj) {
		rz_cons_printf("Found %d chunks in %d small bins\n", chunk_cnt, non_empty_cnt);
	}
}

/**
 * \brief Prints large bins description for an arena (used for `dmhd` command)
 * \param core RzCore pointer
 * \param m_arena Offset of the arena in memory
 * \param main_arena Pointer to MallocState struct for the arena in which bins are
 */
static void GH(print_largebin_description)(RzCore *core, GHT m_arena, MallocState *main_arena, PJ *pj) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	if (!pj) {
		rz_cons_printf("Large bins in Arena @ ");
		PRINTF_YA("0x%" PFMT64x "\n", (ut64)m_arena);
	}
	int chunk_cnt = 0;
	int non_empty_cnt = 0;
	for (int bin_num = NSMALLBINS; bin_num < NBINS - 2; bin_num++) {
		if (pj) {
			pj_o(pj);
			pj_kn(pj, "bin_num", bin_num);
			pj_ks(pj, "bin_type", "large");
		}
		int chunk_found = GH(print_bin_content)(core, main_arena, bin_num, pj);
		if (pj) {
			pj_end(pj);
		}
		if (chunk_found > 0) {
			non_empty_cnt += 1;
		}
		chunk_cnt += chunk_found;
	}
	if (!pj) {
		rz_cons_printf("Found %d chunks in %d large bins\n", chunk_cnt, non_empty_cnt);
	}
}

/**
 * \brief Prints description of bins for main arena for `dmhd` command
 * \param core RzCore pointer
 * \param m_arena Offset of main arena in memory
 * \param main_arena Pointer to Malloc state struct for main arena
 * \param global_max_fast The largest fast bin size
 * \param format Enum to determine which type of bins to print.
 */
static void GH(print_main_arena_bins)(RzCore *core, GHT m_arena, MallocState *main_arena, GHT global_max_fast, RzHeapBinType format, bool json) {
	rz_return_if_fail(core && core->dbg && core->dbg->maps);
	PJ *pj = NULL;
	if (json) {
		pj = pj_new();
		pj_o(pj);
		pj_ka(pj, "bins");
	}
	if (format == RZ_HEAP_BIN_ANY || format == RZ_HEAP_BIN_TCACHE) {
		bool main_thread_only = true;
		GH(print_tcache_instance)
		(core, m_arena, main_arena, main_thread_only, pj);
		rz_cons_newline();
	}
	if (format == RZ_HEAP_BIN_ANY || format == RZ_HEAP_BIN_FAST) {
		char *input = malloc(sizeof(char) * 1);
		input[0] = '\0';
		bool main_arena_only = true;
		GH(print_heap_fastbin)
		(core, m_arena, main_arena, global_max_fast, input, main_arena_only, pj);
		free(input);
		rz_cons_newline();
	}
	if (format == RZ_HEAP_BIN_ANY || format == RZ_HEAP_BIN_UNSORTED) {
		GH(print_unsortedbin_description)
		(core, m_arena, main_arena, pj);
		rz_cons_newline();
	}
	if (format == RZ_HEAP_BIN_ANY || format == RZ_HEAP_BIN_SMALL) {
		GH(print_smallbin_description)
		(core, m_arena, main_arena, pj);
		rz_cons_newline();
	}
	if (format == RZ_HEAP_BIN_ANY || format == RZ_HEAP_BIN_LARGE) {
		GH(print_largebin_description)
		(core, m_arena, main_arena, pj);
		rz_cons_newline();
	}
	if (json) {
		pj_end(pj);
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

static const char *GH(help_msg)[] = {
	"Usage:", " dmh", " # Memory map heap",
	"dmh", "", "List the chunks inside the heap segment",
	"dmh", " @[malloc_state]", "List heap chunks of a particular arena",
	"dmha", "", "List all malloc_state instances in application",
	"dmhb", " @[malloc_state]", "Display all parsed Double linked list of main_arena's or a particular arena bins instance",
	"dmhb", " [bin_num|bin_num:malloc_state]", "Display parsed double linked list of bins instance from a particular arena",
	"dmhbg", " [bin_num]", "Display double linked list graph of main_arena's bin [Under development]",
	"dmhc", " @[chunk_addr]", "Display malloc_chunk struct for a given malloc chunk",
	"dmhd", " [tcache|unsorted|fast|small|large]", "Display description of bins in the main_arena",
	"dmhf", " @[malloc_state]", "Display all parsed fastbins of main_arena's or a particular arena fastbinY instance",
	"dmhf", " [fastbin_num|fastbin_num:malloc_state]", "Display parsed single linked list in fastbinY instance from a particular arena",
	"dmhg", "", "Display heap graph of heap segment",
	"dmhg", " [malloc_state]", "Display heap graph of a particular arena",
	"dmhi", " @[malloc_state]", "Display heap_info structure/structures for a given arena",
	"dmhj", "", "List the chunks inside the heap segment in JSON format",
	"dmhm", "", "List all elements of struct malloc_state of main thread (main_arena)",
	"dmhm", " @[malloc_state]", "List all malloc_state instance of a particular arena",
	"dmht", "", "Display all parsed thread cache bins of all arena's tcache instance",
	"dmhv", " @[malloc_state]", "List heap chunks of a particular arena along with hexdump of first 0x10 bytes",
	"dmh?", "", "Show map heap help",
	NULL
};

static int GH(cmd_dbg_map_heap_glibc)(RzCore *core, const char *input) {
	static GHT m_arena = GHT_MAX, m_state = GHT_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	GHT global_max_fast = (64 * SZ / 4);

	MallocState *main_arena = RZ_NEW0(MallocState);
	if (!main_arena) {
		return false;
	}

	rz_config_set_i(core->config, "dbg.glibc.tcache", GH(is_tcache)(core));

	int format = 'c';
	bool get_state = false;

	switch (input[0]) {
	case ' ': // dmh [malloc_state]
		m_state = rz_num_get(NULL, input);
		get_state = true;
	case '\0': // dmh
		if (GH(rz_resolve_main_arena)(core, &m_arena)) {

			if (core->offset != core->prompt_offset) {
				m_state = core->offset;
			} else {
				if (!get_state) {
					m_state = m_arena;
				}
			}
			if (GH(is_arena)(core, m_arena, m_state)) {
				if (!GH(update_main_arena)(core, m_state, main_arena)) {
					break;
				}
				GH(print_heap_segment)
				(core, main_arena, m_arena, m_state, global_max_fast, format);
				break;
			} else {
				PRINT_RA("This address is not part of the arenas\n");
				break;
			}
		}
		break;
	case 'a': // dmha
		if (GH(rz_resolve_main_arena)(core, &m_arena)) {
			if (!GH(update_main_arena)(core, m_arena, main_arena)) {
				break;
			}
			GH(print_malloc_states)
			(core, m_arena, main_arena);
		}
		break;
	case 'i': // dmhi
		if (GH(rz_resolve_main_arena)(core, &m_arena)) {
			if (!GH(update_main_arena)(core, m_arena, main_arena)) {
				break;
			}
			input += 1;
			if (!strcmp(input, "\0")) {
				if (core->offset != core->prompt_offset) {
					m_state = core->offset;
				}
			} else {
				m_state = rz_num_get(NULL, input);
			}
			GH(print_malloc_info)
			(core, m_arena, m_state);
		}
		break;
	case 'm': // "dmhm"
		if (GH(rz_resolve_main_arena)(core, &m_arena)) {

			switch (input[1]) {
			case '*':
				format = '*';
				input += 1;
				break;
			case 'j':
				format = 'j';
				input += 1;
				break;
			}
			input += 1;
			if (!strcmp(input, "\0")) {
				if (core->offset != core->prompt_offset) {
					m_arena = core->offset;
					if (!GH(update_main_arena)(core, m_arena, main_arena)) {
						break;
					}
				} else {
					if (!GH(update_main_arena)(core, m_arena, main_arena)) {
						break;
					}
				}
			} else {
				m_arena = rz_num_get(NULL, input);
				if (!GH(update_main_arena)(core, m_arena, main_arena)) {
					break;
				}
			}
			GH(print_arena_stats)
			(core, m_arena, main_arena, global_max_fast, format);
		}
		break;
	case 'b': // "dmhb"
		if (GH(rz_resolve_main_arena)(core, &m_arena)) {
			char *m_state_str, *dup = strdup(input + 1);
			if (*dup) {
				strtok(dup, ":");
				m_state_str = strtok(NULL, ":");
				m_state = rz_num_get(NULL, m_state_str);
				if (!m_state) {
					m_state = m_arena;
				}
			} else {
				if (core->offset != core->prompt_offset) {
					m_state = core->offset;
				} else {
					m_state = m_arena;
				}
			}
			if (GH(is_arena)(core, m_arena, m_state)) {
				if (!GH(update_main_arena)(core, m_state, main_arena)) {
					free(dup);
					break;
				}
				GH(print_heap_bin)
				(core, m_state, main_arena, dup);
			} else {
				PRINT_RA("This address is not part of the arenas\n");
				free(dup);
				break;
			}
			free(dup);
		}
		break;
	case 'c': // "dmhc"
		if (GH(rz_resolve_main_arena)(core, &m_arena)) {
			GH(print_heap_chunk)
			(core);
		}
		break;
	case 'd': // "dmhd"
		if (!GH(rz_resolve_main_arena)(core, &m_arena)) {
			break;
		}
		if (!GH(update_main_arena)(core, m_arena, main_arena)) {
			break;
		}
		input += 1;
		bool json = false;
		if (input[0] == 'j') { // dmhdj
			json = true;
			input += 1;
		}
		RzHeapBinType bin_format = RZ_HEAP_BIN_ANY;
		if (input[0] == ' ') {
			input += 1;
			if (!strcmp(input, "tcache")) {
				bin_format = RZ_HEAP_BIN_TCACHE;
			} else if (!strcmp(input, "fast")) {
				bin_format = RZ_HEAP_BIN_FAST;
			} else if (!strcmp(input, "unsorted")) {
				bin_format = RZ_HEAP_BIN_UNSORTED;
			} else if (!strcmp(input, "small")) {
				bin_format = RZ_HEAP_BIN_SMALL;
			} else if (!strcmp(input, "large")) {
				bin_format = RZ_HEAP_BIN_LARGE;
			} else {
				break;
			}
		}

		GH(print_main_arena_bins)
		(core, m_arena, main_arena, global_max_fast, bin_format, json);
		break;
	case 'f': // "dmhf"
		if (GH(rz_resolve_main_arena)(core, &m_arena)) {
			bool main_arena_only = false;
			char *m_state_str, *dup = strdup(input + 1);
			if (*dup) {
				strtok(dup, ":");
				m_state_str = strtok(NULL, ":");
				m_state = rz_num_get(NULL, m_state_str);
				if (!m_state) {
					m_state = m_arena;
				}
			} else {
				if (core->offset != core->prompt_offset) {
					m_state = core->offset;
				} else {
					m_state = m_arena;
				}
			}
			if (GH(is_arena)(core, m_arena, m_state)) {
				if (!GH(update_main_arena)(core, m_state, main_arena)) {
					free(dup);
					break;
				}
				GH(print_heap_fastbin)
				(core, m_state, main_arena, global_max_fast, dup, main_arena_only, NULL);
			} else {
				PRINT_RA("This address is not part of the arenas\n");
				free(dup);
				break;
			}
			free(dup);
		}
		break;
	case 'v':
		if (input[0] == 'v') {
			format = 'v';
		}
	case 'g': //dmhg
		if (input[0] == 'g') {
			format = 'g';
		}
	case '*': //dmh*
		if (input[0] == '*') {
			format = '*';
		}
	case 'j': // "dmhj"
		if (input[0] == 'j') {
			format = 'j';
		}
		if (GH(rz_resolve_main_arena)(core, &m_arena)) {
			input += 1;
			if (!strcmp(input, "\0")) {
				if (core->offset != core->prompt_offset) {
					m_state = core->offset;
					get_state = true;
				}
			} else {
				m_state = rz_num_get(NULL, input);
				get_state = true;
			}
			if (!get_state) {
				m_state = m_arena;
			}
			if (GH(is_arena)(core, m_arena, m_state)) {
				if (!GH(update_main_arena)(core, m_state, main_arena)) {
					break;
				}
				GH(print_heap_segment)
				(core, main_arena, m_arena, m_state, global_max_fast, format);
			} else {
				PRINT_RA("This address is not part of the arenas\n");
			}
		}
		break;
	case 't':
		if (GH(rz_resolve_main_arena)(core, &m_arena)) {
			if (!GH(update_main_arena)(core, m_arena, main_arena)) {
				break;
			}
			bool main_thread_only = false;
			GH(print_tcache_instance)
			(core, m_arena, main_arena, main_thread_only, NULL);
		}
		break;
	case '?':
		rz_core_cmd_help(core, GH(help_msg));
		break;
	}
	free(main_arena);
	return true;
}
