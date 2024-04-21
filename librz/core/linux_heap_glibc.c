// SPDX-FileCopyrightText: 2016-2020 n4x0r <kalianon2816@gmail.com>
// SPDX-FileCopyrightText: 2016-2020 soez <soez@amn3s1a.com>
// SPDX-FileCopyrightText: 2016-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_config.h>
#include <rz_types.h>

#include <rz_debug.h>
#include <math.h>

#include "core_private.h"

#ifdef HEAP64
#include "linux_heap_glibc64.h"
#else
#include "linux_heap_glibc.h"
#endif

static GH(RTcache) * GH(tcache_new)(RzCore *core);
static bool GH(tcache_read)(RzCore *core, GHT tcache_start, GH(RTcache) * tcache);
static int GH(tcache_get_count)(GH(RTcache) * tcache, int index);
static GHT GH(tcache_get_entry)(GH(RTcache) * tcache, int index);
void GH(rz_heap_chunk_free)(RzHeapChunkListItem *item);
static bool GH(is_arena)(RzCore *core, GHT m_arena, GHT m_state);
RZ_API void GH(tcache_free)(GH(RTcache) * tcache);
void GH(print_heap_chunk_simple)(RzCore *core, GHT chunk, const char *status, PJ *pj);

/**
 * \brief Find the address of a given symbol
 * \param core RzCore Pointer to the Rizin's core
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

#if 0
static inline GHT GH(align_address_to_size)(ut64 addr, ut64 align) {
	return addr + ((align - (addr % align)) % align);
}
#endif

static inline GHT GH(get_next_pointer)(RzCore *core, GHT pos, GHT next) {
	return (core->dbg->glibc_version < 232) ? next : (GHT)((pos >> 12) ^ next);
}

static GHT GH(get_main_arena_with_symbol)(RzCore *core, RzDebugMap *map) {
	rz_return_val_if_fail(core && map, GHT_MAX);
	GHT base_addr = map->addr;
	rz_return_val_if_fail(base_addr != GHT_MAX, GHT_MAX);

	GHT main_arena = GHT_MAX;
	GHT off = GHT_MAX;
	char *path = strdup(map->name);
	if (path && rz_file_exists(path)) {
		off = GH(get_va_symbol)(core, path, "main_arena");
		if (off != GHT_MAX) {
			main_arena = base_addr + off;
			goto beach;
		}
		RzBinObject *o = rz_bin_cur_object(core->bin);
		RzBinInfo *info = o ? (RzBinInfo *)rz_bin_object_get_info(o) : NULL;
		if (!strcmp(info->arch, "x86") && info->bits == 64 &&
			// Assumes that the vaddr of LOAD0 is 0x0
			(off = GH(get_va_symbol)(core, path, "mallopt")) != GHT_MAX) {
			// This code looks for the following instructions:
			//     mov edx, 1
			//     (lock) cmpxchg dword [<main_arena_addr>], edx
			//
			// The instructions should be part of the following C
			// code in mallopt():
			//     __libc_lock_lock (av->mutex);
			ut64 mallopt_addr = base_addr + off;
			ut8 bytes[200] = { 0 };
			rz_io_read_at(core->io, mallopt_addr, bytes, sizeof(bytes));
			const ut8 mov[] = { 0xba, 0x1, 0x0, 0x0, 0x0 };
			const ut8 cmpxchg[] = { 0x0f, 0xb1, 0x15 };
			const ut8 *mov_ptr = rz_mem_mem(bytes, sizeof(bytes), mov, sizeof(mov));
			if (!mov_ptr ||
				sizeof(bytes) - (mov_ptr - bytes) <
					sizeof(mov) + 1 /* LOCK */ + sizeof(cmpxchg) + sizeof(ut32)) {
				goto beach;
			}
			const ut8 *cmpxchg_ptr = mov_ptr + sizeof(mov);
			if (*cmpxchg_ptr == 0xf0) { // LOCK prefix
				cmpxchg_ptr++;
			}
			if (memcmp(cmpxchg_ptr, cmpxchg, sizeof(cmpxchg))) {
				goto beach;
			}
			const ut8 *main_arena_off_ptr = cmpxchg_ptr + sizeof(cmpxchg);
			ut32 main_arena_off = rz_read_le32(main_arena_off_ptr);
			ut64 rip_addr = (main_arena_off_ptr + sizeof(ut32) - bytes) + mallopt_addr;
			main_arena = rip_addr + main_arena_off;
			goto beach;
		}
	}
beach:
	free(path);
	return main_arena;
}

static ut8 *GH(get_glibc_banner)(RzCore *core, const char *section_name,
	const char *libc_path) {
	RzPVector *sections = NULL;
	RzBin *bin = core->bin;
	RzBinFile *current_bf = rz_bin_cur(bin);

	void **iter;
	ut8 *buf = NULL;
	ut8 *buf_parse = NULL;
	ut8 *ret_buf = NULL;
	RzBinSection *rz_section = NULL;

	RzBinOptions opt;
	rz_bin_options_init(&opt, -1, 0, 0, false);
	opt.obj_opts.elf_load_sections = rz_config_get_b(core->config, "elf.load.sections");
	opt.obj_opts.elf_checks_sections = rz_config_get_b(core->config, "elf.checks.sections");
	opt.obj_opts.elf_checks_segments = rz_config_get_b(core->config, "elf.checks.segments");

	RzBinFile *libc_buf = rz_bin_open(bin, libc_path, &opt);
	if (!libc_buf) {
		goto cleanup;
	}

	sections = rz_bin_object_get_sections(libc_buf->o);
	if (!sections) {
		goto cleanup;
	}

	rz_pvector_foreach (sections, iter) {
		rz_section = *iter;
		if (strncmp(rz_section->name, section_name, strlen(section_name))) {
			continue;
		}
		buf = calloc(rz_section->size, 1);
		GHT read_size = rz_buf_read_at(libc_buf->buf, rz_section->paddr, buf, rz_section->size);
		if (read_size != rz_section->size) {
			free(buf);
			buf = NULL;
			goto cleanup;
		}
		buf_parse = (ut8 *)rz_mem_mem((const ut8 *)buf, rz_section->size, (const ut8 *)"GNU C Library", strlen("GNU C Library"));
		ret_buf = (ut8 *)strdup((char *)buf_parse);
		break;
	}

cleanup:
	free(buf);
	rz_pvector_free(sections);
	rz_bin_file_delete(bin, libc_buf);
	rz_bin_file_set_cur_binfile(bin, current_bf);
	return ret_buf;
}

/**
 * \brief Find the glibc version using string search
 * \param core RzCore Pointer to the Rizin's core
 * \param libc_path Pointer to the libc binary path.
 * \param banner_start Pointer to the libc banner start which contains libc details.
 * \return version
 *
 * Used to find the glibc version for the provided libc path or libc banner.
 *
 */

RZ_API double GH(rz_get_glibc_version)(RzCore *core, const char *libc_path, ut8 *banner_start) {
	double version = 0.0;
	ut8 *libc_ro_section = NULL;

	if (!banner_start) {
		libc_ro_section = GH(get_glibc_banner)(core, ".rodata", libc_path);
		if (!libc_ro_section) {
			return version;
		}
	}

	const char *pattern = "release version (\\d.\\d\\d)";
	RzRegex *re = rz_regex_new(pattern, RZ_REGEX_EXTENDED | RZ_REGEX_CASELESS, 0);
	if (!re) {
		return version;
	}
	RzPVector *matches = rz_regex_match_first(re, (const char *)libc_ro_section,
		RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	if (rz_pvector_empty(matches)) {
		goto cleanup;
	}

	RzRegexMatch *match = rz_pvector_at(matches, 1);
	if (!match) {
		goto cleanup;
	}
	char *version_str = rz_str_ndup((const char *)libc_ro_section + match->start, match->len);
	if (!version_str) {
		goto cleanup;
	}
	version = strtod(version_str, NULL);
	if (version != 0) {
		RZ_LOG_INFO("libc version %.2f identified from .rodata banner\n", version);
	}

	free(version_str);
cleanup:
	rz_pvector_free(matches);
	rz_regex_free(re);
	free(libc_ro_section);
	return version;
}

static GHT GH(read_val)(RzCore *core, const void *src, bool is_big_endian) {
	if (SZ == RZ_SYS_BITS_16) {
		return rz_read_ble16(src, is_big_endian);
	} else if (SZ == RZ_SYS_BITS_32) {
		return rz_read_ble32(src, is_big_endian);
	} else {
		return rz_read_ble64(src, is_big_endian);
	}
}

/**
 * \brief Fill the glibc tcache entries.
 * \param core RzCore Pointer to the Rizin's core
 * \param tcache Pointer to the tcache struct.
 * \return RzList pointer for the list of tcache bins.
 *
 * Used to fill the tcache bins for the specific tcache.
 *
 */

static RZ_BORROW RzList /*<RzList *>*/ *GH(fill_tcache_entries)(RzCore *core, GH(RTcache) * tcache) {
	RzList *tcache_bins_list = rz_list_newf((RzListFree)GH(rz_heap_bin_free));
	if (!tcache_bins_list) {
		goto error;
	}

	// Use rz_tcache struct to get bins
	for (int i = 0; i < TCACHE_MAX_BINS; i++) {
		int count = GH(tcache_get_count)(tcache, i);
		GHT entry = GH(tcache_get_entry)(tcache, i);

		RzHeapBin *bin = RZ_NEW0(RzHeapBin);
		if (!bin) {
			goto error;
		}
		bin->type = rz_str_dup("Tcache");
		bin->bin_num = i;
		bin->chunks = rz_list_newf((RzListFree)GH(rz_heap_chunk_free));
		if (!bin->chunks) {
			GH(rz_heap_bin_free)
			(bin);
			goto error;
		}
		rz_list_append(tcache_bins_list, bin);
		if (count <= 0) {
			continue;
		}
		bin->fd = (ut64)(entry - GH(HDR_SZ));
		// get first chunk
		RzHeapChunkListItem *chunk = RZ_NEW0(RzHeapChunkListItem);
		if (!chunk) {
			GH(rz_heap_bin_free)
			(bin);
			goto error;
		}
		chunk->addr = (ut64)(entry - GH(HDR_SZ));
		rz_list_append(bin->chunks, chunk);

		if (count <= 1) {
			continue;
		}

		// get rest of the chunks
		GHT tcache_fd = entry;
		GHT tcache_tmp = GHT_MAX;
		for (size_t n = 1; n < count; n++) {
			int r = rz_io_nread_at(core->io, tcache_fd, (ut8 *)&tcache_tmp, sizeof(GHT));
			if (r <= 0) {
				goto error;
			}
			tcache_tmp = GH(get_next_pointer)(core, tcache_fd, read_le(&tcache_tmp));
			chunk = RZ_NEW0(RzHeapChunkListItem);
			if (!chunk) {
				goto error;
			}
			// the base address of the chunk = address - 2 * PTR_SIZE
			chunk->addr = (ut64)(tcache_tmp - GH(HDR_SZ));
			rz_list_append(bin->chunks, chunk);
			tcache_fd = tcache_tmp;
		}
	}
	return tcache_bins_list;

error:
	rz_list_free(tcache_bins_list);
	return NULL;
}

static void GH(print_tcache)(RzCore *core, RzList /*<RzList *>*/ *bins, PJ *pj, const GHT tid) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	RzHeapBin *bin;
	RzListIter *iter;

	if (tid != 0) {
		rz_cons_printf("---------- Tcachebins for thread %d ----------", (int)tid);
		rz_cons_newline();
	}

	rz_list_foreach (bins, iter, bin) {
		if (!bin) {
			continue;
		}
		if (!bin->chunks->length) {
			continue;
		}
		if (!pj) {
			rz_cons_printf("%s", bin->type);
			rz_cons_printf("_bin[");
			PRINTF_BA("%02zu", (size_t)bin->bin_num);
			rz_cons_printf("]: Items:");
			PRINTF_BA("%2d", rz_list_length(bin->chunks));
			rz_cons_newline();
		} else {
			pj_o(pj);
			pj_ks(pj, "bin_type", "tcache");
			pj_kn(pj, "bin_num", bin->bin_num);
			pj_ka(pj, "chunks");
		}
		RzHeapChunkListItem *pos;
		RzListIter *iter2;
		RzList *chunks = bin->chunks;
		rz_list_foreach (chunks, iter2, pos) {
			if (!pj) {
				rz_cons_printf(" -> ");
			}
			GH(print_heap_chunk_simple)
			(core, pos->addr, NULL, pj);
			if (!pj) {
				rz_cons_newline();
			}
		}
		if (bin->message) {
			PRINTF_RA("%s\n", bin->message);
		}
		if (pj) {
			pj_end(pj);
			pj_end(pj);
		}
	}
	rz_list_free(bins);
}

/**
 * \brief Checks if the binary is using tcache from glibc.
 * \param core RzCore Pointer to the Rizin's core
 * \return True if binary uses tcache else False.
 *
 * Find if the binary uses tcache using glibc version parsing.
 */

static bool GH(is_tcache)(RzCore *core) {
	// NOTE This method of resolving libc fails in the following cases:
	// 1. libc shared object file does not have version number
	// 2. if another map has `libc-` in its absolute path
	char *fp = NULL;
	double v = 0;
	RzDebugMap *map = NULL;
	bool is_libc_map = false;

	if (core->dbg->is_glibc_resolved) {
		return true;
	}

	if (rz_config_get_b(core->config, "cfg.debug")) {
		RzListIter *iter;
		rz_debug_map_sync(core->dbg);
		RzRegex *re = rz_regex_new(".*libc[.-]", RZ_REGEX_EXTENDED | RZ_REGEX_CASELESS, 0);
		rz_list_foreach (core->dbg->maps, iter, map) {
			// In case the binary is named *libc-*
			if (strncmp(map->name, core->bin->file, strlen(map->name)) == 0) {
				continue;
			}
			fp = strstr(map->name, "libc-");
			if (fp) {
				is_libc_map = true;
				break;
			}
			RzRegexStatus ret_status = rz_regex_match(re, map->name, RZ_REGEX_ZERO_TERMINATED,
				0, RZ_REGEX_DEFAULT);
			if (ret_status > 0) {
				is_libc_map = true;
				break;
			}
		}
		rz_regex_free(re);
	} else {
		int tcv = rz_config_get_i(core->config, "dbg.glibc.tcache");
		RZ_LOG_WARN("core: dbg.glibc.tcache has been set to %i\n", tcv);
		return tcv != 0;
	}
	if (fp) {

		// In case there is string `libc-` in path actual libc go to last occurrence of `libc-`
		while (strstr(fp + 1, "libc-") != NULL) {
			fp = strstr(fp + 1, "libc-");
		}

		v = rz_num_get_float(NULL, fp + 5);
	} else if (map && is_libc_map) {
		v = GH(rz_get_glibc_version)(core, map->file, NULL);
		if (v) {
			core->dbg->is_glibc_resolved = true;
		}
	}

	core->dbg->glibc_version = (int)round((v * 100));
	return (v > 2.25);
}

static GHT GH(tcache_chunk_size)(RzCore *core, GHT brk_start) {
	GHT sz = 0;

	GH(RzHeapChunk) *cnk = RZ_NEW0(GH(RzHeapChunk));
	if (!cnk) {
		return sz;
	}
	rz_io_read_at(core->io, brk_start, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
	sz = (cnk->size >> 3) << 3; // clear chunk flag
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
		main_arena->fastbinsY[i] = cmain_arena->fastbinsY[i];
	}
	main_arena->top = cmain_arena->top;
	main_arena->last_remainder = cmain_arena->last_remainder;
	for (i = 0; i < NBINS * 2 - 2; i++) {
		main_arena->bins[i] = cmain_arena->bins[i];
	}
	main_arena->next = cmain_arena->next;
	main_arena->next_free = cmain_arena->next_free;
	main_arena->system_mem = cmain_arena->system_mem;
	main_arena->max_system_mem = cmain_arena->max_system_mem;
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
		main_arena->fastbinsY[i] = cmain_arena->fastbinsY[i];
	}
	main_arena->top = cmain_arena->top;
	main_arena->last_remainder = cmain_arena->last_remainder;
	for (i = 0; i < NBINS * 2 - 2; i++) {
		main_arena->bins[i] = cmain_arena->bins[i];
	}
	main_arena->next = cmain_arena->next;
	main_arena->next_free = cmain_arena->next_free;
	main_arena->system_mem = cmain_arena->system_mem;
	main_arena->max_system_mem = cmain_arena->max_system_mem;
}

/**
 * \brief Store the MallocState struct of an arena with base address m_arena in main_arena
 * \param core RzCore pointer
 * \param m_arena The base address of malloc state struct of the arena
 * \param main_arena The MallocState struct in which the data is stored
 * \return True if the main_arena struct was successfully updated else False
 */
RZ_API bool GH(rz_heap_update_main_arena)(RzCore *core, GHT m_arena, MallocState *main_arena) {
	const int tcache = rz_config_get_i(core->config, "dbg.glibc.tcache");
	if (tcache) {
		GH(RzHeap_MallocState_tcache) *cmain_arena = RZ_NEW0(GH(RzHeap_MallocState_tcache));
		if (!cmain_arena) {
			return false;
		}
		(void)rz_io_read_at(core->io, m_arena, (ut8 *)cmain_arena, sizeof(GH(RzHeap_MallocState_tcache)));
		/* arena->next should point to itself even if there is only one thread */
		if (!cmain_arena->next) {
			return false;
		}
		GH(update_arena_with_tc)
		(cmain_arena, main_arena);
		free(cmain_arena);
	} else {
		GH(RzHeap_MallocState) *cmain_arena = RZ_NEW0(GH(RzHeap_MallocState));
		if (!cmain_arena) {
			return false;
		}
		(void)rz_io_read_at(core->io, m_arena, (ut8 *)cmain_arena, sizeof(GH(RzHeap_MallocState)));
		GH(update_arena_without_tc)
		(cmain_arena, main_arena);
		free(cmain_arena);
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
	if (format == RZ_OUTPUT_MODE_RIZIN) {
		for (i = 0; i < NBINS * 2 - 2; i += 2) {
			GHT addr = m_arena + align + SZ * i - SZ * 2;
			GHT bina = main_arena->bins[i];
			rz_cons_printf("f chunk.%zu.bin @ 0x%" PFMT64x "\n", i, (ut64)addr);
			rz_cons_printf("f chunk.%zu.fd @ 0x%" PFMT64x "\n", i, (ut64)bina);
			bina = main_arena->bins[i + 1];
			rz_cons_printf("f chunk.%zu.bk @ 0x%" PFMT64x "\n", i, (ut64)bina);
		}
		for (i = 0; i < BINMAPSIZE; i++) {
			rz_cons_printf("f binmap.%zu @ 0x%" PFMT64x, i, (ut64)main_arena->binmap[i]);
		}
		{ /* maybe use SDB instead of flags for this? */
			char units[8];
			rz_num_units(units, sizeof(units), main_arena->max_system_mem);
			rz_cons_printf("f heap.maxmem @ %s\n", units);

			rz_num_units(units, sizeof(units), main_arena->system_mem);
			rz_cons_printf("f heap.sysmem @ %s\n", units);

			rz_num_units(units, sizeof(units), main_arena->next_free);
			rz_cons_printf("f heap.nextfree @ %s\n", units);

			rz_num_units(units, sizeof(units), main_arena->next);
			rz_cons_printf("f heap.next @ %s\n", units);
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
		PRINTF_GA("0x%" PFMT64x, (ut64)main_arena->fastbinsY[i]);
		PRINT_GA(",\n");
	}
	PRINT_GA("}\n");
	PRINT_GA("  top = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->top);
	PRINT_GA(",\n");
	PRINT_GA("  last_remainder = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->last_remainder);
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
		PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->bins[i]);
		PRINT_GA(", ");
		PRINTF_GA("0x%" PFMT64x "->bk = ", (ut64)bin);
		PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->bins[i + 1]);
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
	PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->next);
	PRINT_GA(",\n");
	PRINT_GA("  next_free = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->next_free);
	PRINT_GA(",\n");
	PRINT_GA("  system_mem = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->system_mem);
	PRINT_GA(",\n");
	PRINT_GA("  max_system_mem = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)main_arena->max_system_mem);
	PRINT_GA(",\n");
	PRINT_GA("}\n\n");
}

static inline bool GH(is_map_name_libc)(const char *map_name) {
	return strstr(map_name, "/libc-") || strstr(map_name, "/libc.");
}

/**
 * \brief Store the base address of main arena at m_arena
 * \param core RzCore pointer
 * \param m_arena Store the location of main arena at this integer pointer
 * \return True if a main arena was found else False
 */
RZ_API bool GH(rz_heap_resolve_main_arena)(RzCore *core, GHT *m_arena) {
	rz_return_val_if_fail(core && core->dbg && core->dbg->maps, false);

	GHT brk_start = GHT_MAX, brk_end = GHT_MAX;
	GHT libc_addr_sta = GHT_MAX, libc_addr_end = 0;
	GHT addr_srch = GHT_MAX, heap_sz = GHT_MAX;
	GHT main_arena_sym = GHT_MAX;
	bool is_debugged = rz_config_get_b(core->config, "cfg.debug");
	bool first_libc = true;
	rz_config_set_i(core->config, "dbg.glibc.tcache", GH(is_tcache)(core));

	if (is_debugged) {
		RzListIter *iter;
		RzDebugMap *map;
		rz_debug_map_sync(core->dbg);
		rz_list_foreach (core->dbg->maps, iter, map) {
			/* Try to find the main arena address using the glibc's symbols. */
			if (GH(is_map_name_libc)(map->name) && first_libc && main_arena_sym == GHT_MAX) {
				first_libc = false;
				main_arena_sym = GH(get_main_arena_with_symbol)(core, map);
			}
			if (GH(is_map_name_libc)(map->name) && map->perm == RZ_PERM_RW) {
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
			RZ_LOG_WARN("core: Can't find glibc mapped in memory (see dm)\n");
		} else {
			RZ_LOG_WARN("core: Can't find arena mapped in memory (see om)\n");
		}
		return false;
	}

	GH(get_brks)
	(core, &brk_start, &brk_end);
	if (brk_start == GHT_MAX || brk_end == GHT_MAX) {
		RZ_LOG_ERROR("core: no heap section\n");
		return false;
	}

	addr_srch = libc_addr_sta;
	heap_sz = brk_end - brk_start;
	MallocState *ta = RZ_NEW0(MallocState);
	if (!ta) {
		return false;
	}

	if (main_arena_sym != GHT_MAX) {
		GH(rz_heap_update_main_arena)
		(core, main_arena_sym, ta);
		*m_arena = main_arena_sym;
		core->dbg->main_arena_resolved = true;
		free(ta);
		return true;
	}
	while (addr_srch < libc_addr_end) {
		GH(rz_heap_update_main_arena)
		(core, addr_srch, ta);
		if (ta->top > brk_start && ta->top < brk_end &&
			ta->system_mem == heap_sz) {

			*m_arena = addr_srch;
			free(ta);
			if (is_debugged) {
				core->dbg->main_arena_resolved = true;
			}
			return true;
		}
		addr_srch += sizeof(GHT);
	}
	RZ_LOG_WARN("core: Can't find main_arena in mapped memory\n");
	free(ta);
	return false;
}

/**
 * \brief Parses tcache information from the given address in the target process memory.
 * \param core RzCore Pointer to the Rizin's core
 * \param tls_addr Address of the thread-local storage base address.
 * \param tid Thread ID.
 * \return True if tcache information was successfully parsed else false.
 *
 * Parse the tcache and tcache bins struct for the provided thread local base and print it.
 */

static bool GH(parse_tcache_from_addr)(RzCore *core, const GHT tls_addr, const GHT tid) {
	RzDebugMap *map;
	RzListIter *iter;
	ut8 tcache_addr[8] = { 0 };
	GH(RTcache) *tcache_heap = NULL;

	rz_list_foreach (core->dbg->maps, iter, map) {
		/*
		 * TODO: Send a list of maps with this page size and perms
		 * instead of traversing through every map
		 */
		if (map->size != HEAP_PAGE_SIZE || map->perm != RZ_PERM_RW) {
			if (strcmp(core->dbg->arch, "x86") || map->size != HEAP_PAGE_SIZE_X86) {
				continue;
			}
		}

		rz_io_nread_at(core->io, tls_addr, tcache_addr, sizeof(GHT));
		const GHT tcache_guess = GH(read_val)(core, tcache_addr, false);
		if (tcache_guess < map->addr || tcache_guess > map->addr_end) {
			continue;
		}

#if __aarch64__
		/* We will encounter main_arena pointer somewhere in ARM64 */
		if (GH(is_arena)(core, tcache_guess, GHT_MIN)) {
			break;
		}
#endif
		tcache_heap = GH(tcache_new)(core);
		if (!GH(tcache_read)(core, tcache_guess, tcache_heap)) {
			GH(tcache_free)
			(tcache_heap);
			tcache_heap = NULL;
		}
		break;
	}
	if (tcache_heap != NULL) {
		RzList *bins = GH(fill_tcache_entries)(core, tcache_heap);
		GH(print_tcache)
		(core, bins, NULL, tid);
		GH(tcache_free)
		(tcache_heap);
		tcache_heap = NULL;
		return true;
	}

	return false;
}

/**
 * \brief Parses Thread-Local Storage (TLS) data for a given thread ID to identify tcache structures.
 * \param core RzCore Pointer to the Rizin's core
 * \param th RzDebugPid Pointer to the Rizin's Debug PID structure representing the thread.
 * \param tid Thread ID.
 * \return True if tcache and bin structures were successfully parsed from TLS data else False.
 *
 * Parse the TLS data and identify the tcache and tcache-bins for the given thread ID.
 */

static bool GH(parse_tls_data)(RzCore *core, RZ_NONNULL RzDebugPid *th, GHT tid) {
	rz_return_val_if_fail(th, false);
	GHT tls_addr = GHT_MAX;
	GHT addr = GHT_MAX;

	if (!th->tls) {
		return false;
	}

#if __x86_64__
	ut8 dtv[sizeof(GHT)] = { 0 };
	rz_io_nread_at(core->io, th->tls + SZ, dtv, sizeof(GHT));
	addr = GH(read_val)(core, dtv, false);
	memset(dtv, 0, sizeof(dtv));
	/*
	 * https://github.com/jart/cosmopolitan/blob/06839ab3017d86e87db3ec740a2b5e00d9fe9e11/libc/runtime/enable_tls.c#L65
	 */
	// size of dtv is SZ*2
	rz_io_nread_at(core->io, addr + SZ * 2, dtv, sizeof(GHT));
	addr = GH(read_val)(core, dtv, false);
#elif __aarch64__
	/*
	 * https://github.com/jart/cosmopolitan/blob/06839ab3017d86e87db3ec740a2b5e00d9fe9e11/libc/runtime/enable_tls.c#L79
	 */
	addr = th->tls + SZ * 2;
#endif
	const GHT end = addr + 0x10 * SZ * 2;
	// Parse tls data and check if it complies with tcache struct
	for (tls_addr = addr; tls_addr <= end; tls_addr += SZ) {
		if (GH(parse_tcache_from_addr)(core, tls_addr, tid)) {
			return true;
		}
	}
	return false;
}

/**
 * \brief Resolves tcache structures per thread.
 * \param core RzCore Pointer to the Rizin's core
 *
 * Resolves the TLS base for every thread and parse to identify the tcache structures.
 */

static void GH(resolve_tcache_perthread)(RZ_NONNULL RzCore *core) {
	RzDebugPid *th;
	RzListIter *it;
	GHT tid = 1;
	RzDebug *dbg = core->dbg;

	rz_list_foreach (dbg->threads, it, th) {
		// First try: fetch tls value and update debug pid
		if (!th->tls) {
			th->tls = rz_debug_get_tls(core->dbg, th->pid);
		}
		if (!GH(parse_tls_data)(core, th, tid++)) {
			// Second try: Update the thread list if the tls parsing fails.
			RzList *thread_list = rz_debug_native_threads(dbg, dbg->pid);
			RzDebugPid *thread_dbg = rz_debug_get_thread(thread_list, th->pid);
			if (thread_dbg) {
				GH(parse_tls_data)
				(core, thread_dbg, tid);
			}
		}
	}
}

RZ_API RZ_OWN bool GH(resolve_heap_tcache)(RZ_NONNULL RzCore *core, GHT arena_base) {
	RzDebug *dbg = core->dbg;

	if (dbg->threads) {
		GH(resolve_tcache_perthread)
		(core);
		return true;
	}

	// Only main thread is present
	RzList *bins = GH(rz_heap_tcache_content)(core, arena_base);
	GH(print_tcache)
	(core, bins, NULL, 0);

	return true;
}

void GH(print_heap_chunk)(RzCore *core, GHT chunk) {
	GH(RzHeapChunk) *cnk = RZ_NEW0(GH(RzHeapChunk));
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
		rz_core_print_hexdump(core, chunk + SZ * 2, (ut8 *)data, size, SZ * 8, SZ, 1);
		free(data);
	}
	free(cnk);
}

/**
 * \brief Get a heap chunk with base address <addr>
 * \param core RzCore pointer
 * \param addr Base address of the chunk
 * \return RzHeapChunk struct pointer of the chunk
 */
RZ_API GH(RzHeapChunk) * GH(rz_heap_get_chunk_at_addr)(RzCore *core, GHT addr) {
	GH(RzHeapChunk) *cnk = RZ_NEW0(GH(RzHeapChunk));
	if (!cnk) {
		return NULL;
	}
	(void)rz_io_nread_at(core->io, addr, (ut8 *)cnk, sizeof(*cnk));
	return cnk;
}

/**
 * \brief Prints compact representation of a heap chunk. Format: Chunk(addr=, size=, flags=)
 * \param core RzCore pointer
 * \param chunk Offset of the chunk in memory
 */
void GH(print_heap_chunk_simple)(RzCore *core, GHT chunk, const char *status, PJ *pj) {
	GH(RzHeapChunk) *cnk = GH(rz_heap_get_chunk_at_addr)(core, chunk);
	if (!cnk) {
		return;
	}
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
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
	if (!GH(rz_heap_update_main_arena)(core, m_arena, ta)) {
		free(ta);
		return false;
	}
	if (ta->next == m_state) {
		free(ta);
		return true;
	}
	while (ta->next != GHT_MAX && ta->next != m_arena) {
		if (!GH(rz_heap_update_main_arena)(core, ta->next, ta)) {
			free(ta);
			return false;
		}
		if (ta->next == m_state) {
			free(ta);
			return true;
		}
	}
	free(ta);
	if (m_state == GHT_MIN) {
		return true;
	}
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
		if (next < brk_start || next > main_arena->top) {
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
		if (next < brk_start || next > main_arena->top) {
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
		if (next < brk_start || next > main_arena->top) {
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
	GHT bin = main_arena->bins[num_bin];

	if (!bin) {
		return -1;
	}

	GH(get_brks)
	(core, &brk_start, &brk_end);
	if (brk_start == GHT_MAX || brk_end == GHT_MAX) {
		RZ_LOG_ERROR("core: no heap section\n");
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
			PRINTF_YA(" Bin %03d:\n", i);
			GH(print_double_linked_list_bin)
			(core, main_arena, m_arena, offset, i, 0);
		}
		PRINT_YA("\n}\n");
		break;
	case ' ': // dmhb [bin_num]
		j--; // for spaces after input
		// fallthrough
	case 'g': // dmhbg [bin_num]
		num_bin = rz_num_get(NULL, input + j);
		if (num_bin > NBINS - 2) {
			RZ_LOG_ERROR("core: the number of bins is greater than %d\n", NBINS - 2);
			break;
		}
		PRINTF_YA("  Bin %03" PFMT64u ":\n", (ut64)num_bin);
		GH(print_double_linked_list_bin)
		(core, main_arena, m_arena, offset, num_bin, j);
		break;
	}
}

void GH(rz_heap_chunk_free)(RzHeapChunkListItem *item) {
	if (!item) {
		return;
	}
	free(item->status);
	free(item);
}

RZ_API RzHeapBin *GH(rz_heap_fastbin_content)(RzCore *core, MallocState *main_arena, int bin_num) {
	if (!core || !core->dbg || !core->dbg->maps) {
		return NULL;
	}
	GHT brk_start = GHT_MAX, brk_end = GHT_MAX;
	RzHeapBin *heap_bin = RZ_NEW0(RzHeapBin);
	GH(RzHeapChunk) *cnk = RZ_NEW0(GH(RzHeapChunk));
	if (!cnk || !heap_bin) {
		free(heap_bin);
		free(cnk);
		return NULL;
	}
	heap_bin->chunks = rz_list_newf((RzListFree)GH(rz_heap_chunk_free));
	heap_bin->bin_num = bin_num + 1;
	heap_bin->size = FASTBIN_IDX_TO_SIZE(bin_num + 1);
	heap_bin->type = rz_str_dup("Fast");
	GHT next = main_arena->fastbinsY[bin_num];
	if (!next) {
		free(cnk);
		return heap_bin;
	}
	GH(get_brks)
	(core, &brk_start, &brk_end);
	heap_bin->fd = next;
	if (brk_start == GHT_MAX || brk_end == GHT_MAX) {
		free(cnk);
		return heap_bin;
	}
	GHT size = main_arena->top - brk_start;

	GHT next_root = next, next_tmp = next, double_free = GHT_MAX;
	while (next && next >= brk_start && next < main_arena->top) {
		RzHeapChunkListItem *item = RZ_NEW0(RzHeapChunkListItem);
		if (!item) {
			break;
		}
		item->addr = next;
		item->status = rz_str_dup("free");
		rz_list_append(heap_bin->chunks, item);
		while (double_free == GHT_MAX && next_tmp && next_tmp >= brk_start && next_tmp <= main_arena->top) {
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
		if (cnk->prev_size > size || ((cnk->size >> 3) << 3) > size) {
			char message[50];
			rz_snprintf(message, 50, "Linked list corrupted @ 0x%" PFMT64x, (ut64)next);
			heap_bin->message = rz_str_dup(message);
			free(cnk);
			return heap_bin;
		}

		next_root = next_tmp = next;
		if (double_free == next) {
			char message[50];
			rz_snprintf(message, 50, "Double free detected @ 0x%" PFMT64x, (ut64)next);
			heap_bin->message = rz_str_dup(message);
			free(cnk);
			return heap_bin;
		}
	}
	if (next && (next < brk_start || next >= main_arena->top)) {
		char message[50];
		rz_snprintf(message, 50, "Linked list corrupted @ 0x%" PFMT64x, (ut64)next);
		heap_bin->message = rz_str_dup(message);
		free(cnk);
		return heap_bin;
	}
	free(cnk);
	return heap_bin;
}

void GH(print_heap_fastbin)(RzCore *core, GHT m_arena, MallocState *main_arena, GHT global_max_fast, const char *input, bool main_arena_only, PJ *pj) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	int fastbins_max = rz_config_get_i(core->config, "dbg.glibc.fastbinmax") - 1;
	int global_max_fast_idx = fastbin_index(global_max_fast);
	int fastbin_count = fastbins_max < global_max_fast_idx ? fastbins_max : global_max_fast_idx;
	int bin_to_print = 0;
	switch (input[0]) {
	case ' ':
		bin_to_print = (int)rz_num_get(NULL, input);
		if (bin_to_print <= 0 || bin_to_print - 1 > fastbin_count) {
			RZ_LOG_ERROR("core: the number of bins is greater than %d\n", fastbin_count + 1);
			return;
		}
	}
	if (!pj) {
		rz_cons_printf("Fast bins in Arena @ ");
		PRINTF_YA("0x%" PFMT64x, (ut64)m_arena);
		rz_cons_newline();
	}
	for (int i = 0; i <= fastbin_count; i++) {
		if (bin_to_print && i != bin_to_print - 1) {
			continue;
		}
		RzHeapBin *bin = GH(rz_heap_fastbin_content)(core, main_arena, i);
		if (!bin) {
			continue;
		}
		if (!pj) {
			rz_cons_printf("Fast_bin[");
			PRINTF_BA("%02zu", (size_t)bin->bin_num);
			rz_cons_printf("] [size: ");
			PRINTF_BA("0x%" PFMT64x, bin->size);
			rz_cons_printf("]");
		} else {
			pj_o(pj);
			pj_ks(pj, "bin_type", "fast");
			pj_kn(pj, "bin_num", bin->bin_num);
			pj_ka(pj, "chunks");
		}
		if (!bin->chunks || !rz_list_length(bin->chunks)) {
			if (!pj) {
				PRINT_RA(" Empty bin\n");
			}
		} else {
			RzListIter *iter;
			RzHeapChunkListItem *pos;
			rz_cons_newline();
			rz_list_foreach (bin->chunks, iter, pos) {
				if (!pj) {
					rz_cons_printf(" -> ");
				}
				GH(print_heap_chunk_simple)
				(core, pos->addr, NULL, pj);
				if (!pj) {
					rz_cons_newline();
				}
			}
			if (bin->message && !pj) {
				PRINTF_RA("%s\n", bin->message);
			}
		}
		if (pj) {
			pj_end(pj);
			pj_end(pj);
		}
		GH(rz_heap_bin_free)
		(bin);
	}
}

static GH(RTcache) * GH(tcache_new)(RzCore *core) {
	rz_return_val_if_fail(core, NULL);
	GH(RTcache) *tcache = RZ_NEW0(GH(RTcache));
	if (!tcache) {
		return NULL;
	}
	if (core->dbg->glibc_version >= TCACHE_NEW_VERSION) {
		tcache->type = NEW;
		tcache->RzHeapTcache.heap_tcache = RZ_NEW0(GH(RzHeapTcache));
	} else {
		tcache->type = OLD;
		tcache->RzHeapTcache.heap_tcache_pre_230 = RZ_NEW0(GH(RzHeapTcachePre230));
	}
	return tcache;
}

RZ_API void GH(tcache_free)(GH(RTcache) * tcache) {
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

/**
 * \brief Get a list of bins for the tcache associated with arena with base address arena_base
 * \param core RzCore pointer
 * \param arena_base Base address of the arena
 * \return RzList of RzHeapBin pointers
 */
RZ_API RzList /*<RzHeapBin *>*/ *GH(rz_heap_tcache_content)(RzCore *core, GHT arena_base) {
	// check if tcache is even present in this Glibc version
	const int tc = rz_config_get_i(core->config, "dbg.glibc.tcache");
	if (!tc) {
		rz_cons_printf("No tcache present in this version of libc\n");
		return NULL;
	}

	// get main arena base address to compare
	GHT m_arena;
	if (!GH(rz_heap_resolve_main_arena)(core, &m_arena)) {
		return NULL;
	}

	GHT brk_start = GHT_MAX, brk_end = GHT_MAX, initial_brk = GHT_MAX;
	GH(get_brks)
	(core, &brk_start, &brk_end);
	GHT fc_offset = GH(tcache_chunk_size)(core, brk_start);
	initial_brk = brk_start + fc_offset;
	if (brk_start == GHT_MAX || brk_end == GHT_MAX || initial_brk == GHT_MAX) {
		// no heap section exists in this case
		return NULL;
	}

	// get the base address of tcache
	GHT tcache_start;
	if (arena_base == m_arena) {
		// get tcache base for main arena
		// tcache is consistently the first allocation in the main arena.
		tcache_start = brk_start + 0x10;
	} else {
		// get tcache base for thread arena
		GHT mmap_start = ((arena_base >> 16) << 16);
		tcache_start = mmap_start + sizeof(GH(RzHeapInfo)) + sizeof(GH(RzHeap_MallocState_tcache)) + GH(MMAP_ALIGN);

		// for thread arena check if the arena has threads attached or not
		MallocState *arena = RZ_NEW0(MallocState);
		if (!arena) {
			return NULL;
		}
		if (!GH(rz_heap_update_main_arena)(core, arena_base, arena) || !arena->attached_threads) {
			free(arena);
			return NULL;
		}
		free(arena);
	}
	// Get rz_tcache struct
	GH(RTcache) *tcache = GH(tcache_new)(core);
	if (!GH(tcache_read)(core, tcache_start, tcache)) {
		GH(tcache_free)
		(tcache);
		return NULL;
	}

	// List of heap bins to return
	RzList *tcache_bins_list = rz_list_newf((RzListFree)GH(rz_heap_bin_free));

	// Use rz_tcache struct to get bins
	for (int i = 0; i < TCACHE_MAX_BINS; i++) {
		int count = GH(tcache_get_count)(tcache, i);
		GHT entry = GH(tcache_get_entry)(tcache, i);

		RzHeapBin *bin = RZ_NEW0(RzHeapBin);
		if (!bin) {
			goto error;
		}
		bin->type = rz_str_dup("Tcache");
		bin->bin_num = i;
		bin->chunks = rz_list_newf((RzListFree)GH(rz_heap_chunk_free));
		if (!bin->chunks) {
			GH(rz_heap_bin_free)
			(bin);
			goto error;
		}

		rz_list_append(tcache_bins_list, bin);
		if (count <= 0) {
			continue;
		}
		bin->fd = (ut64)(entry - GH(HDR_SZ));
		// get first chunk
		RzHeapChunkListItem *chunk = RZ_NEW0(RzHeapChunkListItem);
		if (!chunk) {
			goto error;
		}
		chunk->addr = (ut64)(entry - GH(HDR_SZ));
		rz_list_append(bin->chunks, chunk);

		if (count <= 1) {
			continue;
		}

		// get rest of the chunks
		GHT tcache_fd = entry;
		GHT tcache_tmp = GHT_MAX;
		for (size_t n = 1; n < count; n++) {
			int r = rz_io_nread_at(core->io, tcache_fd, (ut8 *)&tcache_tmp, sizeof(GHT));
			if (r <= 0) {
				goto error;
			}
			tcache_tmp = GH(get_next_pointer)(core, tcache_fd, read_le(&tcache_tmp));
			chunk = RZ_NEW0(RzHeapChunkListItem);
			if (!chunk) {
				goto error;
			}
			// the base address of the chunk = address - 2 * PTR_SIZE
			chunk->addr = (ut64)(tcache_tmp - GH(HDR_SZ));
			rz_list_append(bin->chunks, chunk);
			tcache_fd = tcache_tmp;
		}
	}
	free(tcache);
	return tcache_bins_list;

error:
	rz_list_free(tcache_bins_list);
	free(tcache);
	return NULL;
}

static void GH(print_tcache_content)(RzCore *core, GHT arena_base, GHT main_arena_base, PJ *pj) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	RzList *bins = GH(rz_heap_tcache_content)(core, arena_base);
	if (!bins) {
		return;
	}
	if (!pj) {
		if (main_arena_base == arena_base) {
			rz_cons_printf("Tcache bins in Main Arena @ ");
		} else {
			rz_cons_printf("Tcache bins in Thread Arena @ ");
		}
		PRINTF_YA("0x%" PFMT64x "\n", (ut64)arena_base);
	}
	GH(print_tcache)
	(core, bins, pj, 0);
}

void GH(print_malloc_states)(RzCore *core, GHT m_arena, MallocState *main_arena, bool json) {
	MallocState *ta = RZ_NEW0(MallocState);
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!ta) {
		return;
	}
	PJ *pj = NULL;
	if (!json) {
		rz_cons_printf("Main arena  (addr=");
		PRINTF_YA("0x%" PFMT64x, (ut64)m_arena);
		rz_cons_printf(", lastRemainder=");
		PRINTF_YA("0x%" PFMT64x, (ut64)main_arena->last_remainder);
		rz_cons_printf(", top=");
		PRINTF_YA("0x%" PFMT64x, (ut64)main_arena->top);
		rz_cons_printf(", next=");
		PRINTF_YA("0x%" PFMT64x, (ut64)main_arena->next);
		rz_cons_printf(")\n");
	} else {
		pj = pj_new();
		if (!pj) {
			free(ta);
			return;
		}
		pj_o(pj);
		pj_ka(pj, "arenas");
		pj_o(pj);
		pj_kn(pj, "addr", m_arena);
		pj_kn(pj, "last_rem", main_arena->last_remainder);
		pj_kn(pj, "top", main_arena->top);
		pj_kn(pj, "next", main_arena->next);
		pj_ks(pj, "type", "main");
		pj_ks(pj, "state", "used");
		pj_end(pj);
	}
	if (main_arena->next != m_arena) {
		ta->next = main_arena->next;
		while (GH(is_arena)(core, m_arena, ta->next) && ta->next != m_arena) {
			ut64 ta_addr = ta->next;
			/* If the pointer is equal to unsigned -1, we assume it is invalid */
			if (ta->next == GHT_MAX) {
				break;
			}
			if (!GH(rz_heap_update_main_arena)(core, ta->next, ta)) {
				goto end;
			}
			if (!json) {
				rz_cons_printf("Thread arena(addr=");
				PRINTF_YA("0x%" PFMT64x, ta_addr);
				rz_cons_printf(", lastRemainder=");
				PRINTF_YA("0x%" PFMT64x, (ut64)ta->last_remainder);
				rz_cons_printf(", top=");
				PRINTF_YA("0x%" PFMT64x, (ut64)ta->top);
				rz_cons_printf(", next=");
				PRINTF_YA("0x%" PFMT64x, (ut64)ta->next);
				if (ta->attached_threads) {
					rz_cons_printf(")\n");
				} else {
					rz_cons_printf(" free)\n");
				}
			} else {
				pj_o(pj);
				pj_kn(pj, "addr", (ut64)ta_addr);
				pj_kn(pj, "last_rem", ta->last_remainder);
				pj_kn(pj, "top", ta->top);
				pj_kn(pj, "next", ta->next);
				pj_ks(pj, "type", "thread");
				if (ta->attached_threads) {
					pj_ks(pj, "state", "used");
				} else {
					pj_ks(pj, "state", "free");
				}
				pj_end(pj);
			}
		}
	}
end:
	if (json) {
		pj_end(pj);
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
	free(ta);
}

void GH(print_inst_minfo)(RzCore *core, GH(RzHeapInfo) * heap_info, GHT hinfo) {
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
		(core, heap_info, h_info);
		MallocState *ms = RZ_NEW0(MallocState);
		if (!ms) {
			free(heap_info);
			return;
		}

		while (heap_info->prev != 0x0 && heap_info->prev != GHT_MAX) {
			if (!GH(rz_heap_update_main_arena)(core, malloc_state, ms)) {
				free(ms);
				free(heap_info);
				return;
			}
			if ((ms->top >> 16) << 16 != h_info) {
				h_info = (ms->top >> 16) << 16;
				rz_io_read_at(core->io, h_info, (ut8 *)heap_info, sizeof(GH(RzHeapInfo)));
				GH(print_inst_minfo)
				(core, heap_info, h_info);
			}
		}
		free(heap_info);
		free(ms);
	} else {
		PRINT_RA("This address is not part of the arenas\n");
	}
}

char *GH(rz_bin_num_to_type)(int bin_num) {
	if (bin_num == 0) {
		return rz_str_dup("Unsorted");
	} else if (bin_num >= 1 && bin_num <= NSMALLBINS - 1) {
		return rz_str_dup("Small");
	} else if (bin_num >= NSMALLBINS && bin_num <= NBINS - 2) {
		return rz_str_dup("Large");
	}
	return NULL;
}

RZ_API void GH(rz_heap_bin_free)(RzHeapBin *bin) {
	if (!bin) {
		return;
	}
	free(bin->type);
	free(bin->message);
	rz_list_free(bin->chunks);
	free(bin);
}
/**
 * \brief Get information about <bin_num> bin from NBINS array of an arena.
 * \param core RzCore pointer
 * \param main_arena MallocState struct of arena
 * \param bin_num bin number of bin whose chunk list you want
 * \return RzHeapBin struct for the bin
 */
RZ_API RzHeapBin *GH(rz_heap_bin_content)(RzCore *core, MallocState *main_arena, int bin_num, GHT m_arena) {
	int idx = 2 * bin_num;
	ut64 fw = main_arena->bins[idx];
	ut64 bk = main_arena->bins[idx + 1];
	RzHeapBin *bin = RZ_NEW0(RzHeapBin);
	if (!bin) {
		return NULL;
	}
	bin->fd = fw;
	bin->bk = bk;
	bin->bin_num = bin_num;
	bin->type = GH(rz_bin_num_to_type)(bin_num);

	// small bins hold chunks of a fixed size
	if (!strcmp(bin->type, "Small")) {
		bin->size = 4 * SZ + (bin_num - 1) * 2 * SZ;
	}

	bin->chunks = rz_list_newf(free);
	GH(RzHeapChunk) *head = RZ_NEW0(GH(RzHeapChunk));
	if (!head) {
		GH(rz_heap_bin_free)
		(bin);
		return NULL;
	}

	(void)rz_io_read_at(core->io, bk, (ut8 *)head, sizeof(GH(RzHeapChunk)));

	if (head->fd == fw) {
		return bin;
	}
	GH(RzHeapChunk) *cnk = RZ_NEW0(GH(RzHeapChunk));
	if (!cnk) {
		GH(rz_heap_bin_free)
		(bin);
		return NULL;
	}
	GHT brk_start = GHT_MAX, brk_end = GHT_MAX, initial_brk = GHT_MAX;
	GH(get_brks)
	(core, &brk_start, &brk_end);
	if (brk_start == GHT_MAX || brk_end == GHT_MAX) {
		free(cnk);
		return bin;
	}
	const int tcache = rz_config_get_i(core->config, "dbg.glibc.tcache");
	int offset;
	GHT base;
	if (tcache) {
		offset = 16;
		const int fc_offset = rz_config_get_i(core->config, "dbg.glibc.fc_offset");
		base = m_arena + offset + SZ * (ut64)bin_num * 2 + 10 * SZ;
		initial_brk = ((brk_start >> 12) << 12) + fc_offset;
	} else {
		offset = 12 * SZ + sizeof(int) * 2;
		base = m_arena + offset + SZ * (ut64)bin_num * 2 - SZ * 2;
		initial_brk = (brk_start >> 12) << 12;
	}
	bin->addr = base;
	while (fw != head->fd) {
		if (fw > main_arena->top || fw < initial_brk) {
			bin->message = rz_str_dup("Corrupted list");
			break;
		}
		rz_io_read_at(core->io, fw, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
		RzHeapChunkListItem *chunk = RZ_NEW0(RzHeapChunkListItem);
		if (!chunk) {
			break;
		}
		chunk->addr = fw;
		rz_list_append(bin->chunks, chunk);
		fw = cnk->fd;
	}
	free(cnk);
	free(head);
	return bin;
}
/**
 * \brief Prints the heap chunks in a bin with double linked list (small|large|unsorted)
 * \param core RzCore pointer
 * \param main_arena MallocState struct for the arena in which bins are
 * \param bin_num The bin number for the bin from which chunks have to printed
 * \return number of chunks found in the bin
 */
static int GH(print_bin_content)(RzCore *core, MallocState *main_arena, int bin_num, PJ *pj, GHT m_arena) {
	RzListIter *iter;
	RzHeapChunkListItem *pos;
	RzHeapBin *bin = GH(rz_heap_bin_content)(core, main_arena, bin_num, m_arena);
	RzList *chunks = bin->chunks;
	if (rz_list_length(chunks) == 0) {
		GH(rz_heap_bin_free)
		(bin);
		return 0;
	}
	int chunks_cnt = 0;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	if (!pj) {
		rz_cons_printf("%s", bin->type);
		rz_cons_printf("_bin[");
		PRINTF_BA("%d", bin->bin_num);
		rz_cons_printf("]: fd=");
		PRINTF_YA("0x%" PFMT64x, bin->fd);
		rz_cons_printf(", bk=");
		PRINTF_YA("0x%" PFMT64x, bin->bk);
		rz_cons_printf(", base=");
		PRINTF_YA("0x%" PFMT64x, bin->addr);
		if (!strcmp(bin->type, "Small")) {
			rz_cons_printf(", size=");
			PRINTF_BA("0x%" PFMT64x, bin->size);
		}
		rz_cons_newline();
	} else {
		pj_kn(pj, "fd", bin->fd);
		pj_kn(pj, "bk", bin->bk);
		pj_kn(pj, "base", bin->addr);
		pj_ka(pj, "chunks");
	}
	rz_list_foreach (chunks, iter, pos) {
		if (!pj) {
			rz_cons_printf(" -> ");
		}
		GH(print_heap_chunk_simple)
		(core, pos->addr, NULL, pj);
		if (!pj) {
			rz_cons_newline();
		}
		chunks_cnt += 1;
	}
	if (bin->message) {
		PRINTF_RA("%s\n", bin->message);
	}
	GH(rz_heap_bin_free)
	(bin);
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
	int chunk_cnt = GH(print_bin_content)(core, main_arena, 0, pj, m_arena);
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
		int chunk_found = GH(print_bin_content)(core, main_arena, bin_num, pj, m_arena);
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
		int chunk_found = GH(print_bin_content)(core, main_arena, bin_num, pj, m_arena);
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
static void GH(print_main_arena_bins)(RzCore *core, GHT m_arena, MallocState *main_arena, GHT main_arena_base, GHT global_max_fast, RzHeapBinType format, bool json) {
	rz_return_if_fail(core && core->dbg && core->dbg->maps);
	PJ *pj = NULL;
	if (json) {
		pj = pj_new();
		if (!pj) {
			return;
		}
		pj_o(pj);
		pj_ka(pj, "bins");
	}
	if (format == RZ_HEAP_BIN_ANY || format == RZ_HEAP_BIN_TCACHE) {
		GH(print_tcache_content)
		(core, m_arena, main_arena_base, pj);
		rz_cons_newline();
	}
	if (format == RZ_HEAP_BIN_ANY || format == RZ_HEAP_BIN_FAST) {
		char *input = rz_str_newlen("", 1);
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

void GH(rz_arena_list_free)(RzArenaListItem *item) {
	free(item->arena);
	free(item->type);
	free(item);
}
/**
 * \brief Get a list of RzArenaListItem structs for all the arenas
 * \param core RzCore pointer
 * \param m_arena Base address of MallocState struct of main arena
 * \param main_arena MallocState struct of main arena
 * \return RzList pointer for list of RzArenaListItem structs of all the arenas
 */
RZ_API RzList /*<RzArenaListItem *>*/ *GH(rz_heap_arenas_list)(RzCore *core, GHT m_arena, MallocState *main_arena) {
	RzList *arena_list = rz_list_newf((RzListFree)GH(rz_arena_list_free));
	MallocState *ta = RZ_NEW0(MallocState);
	if (!ta) {
		return arena_list;
	}
	// main arena
	if (!GH(rz_heap_update_main_arena)(core, m_arena, ta)) {
		free(ta);
		return arena_list;
	}
	RzArenaListItem *item = RZ_NEW0(RzArenaListItem);
	if (!item) {
		free(ta);
		return arena_list;
	}
	item->addr = m_arena;
	item->type = rz_str_dup("Main");
	item->arena = ta;
	rz_list_append(arena_list, item);
	if (main_arena->next != m_arena) {
		ta->next = main_arena->next;
		while (GH(is_arena)(core, m_arena, ta->next) && ta->next != m_arena) {
			ut64 ta_addr = ta->next;
			ta = RZ_NEW0(MallocState);
			if (!GH(rz_heap_update_main_arena)(core, ta_addr, ta)) {
				free(ta);
				return arena_list;
			}
			// thread arenas
			item = RZ_NEW0(RzArenaListItem);
			if (!item) {
				free(ta);
				break;
			}
			item->addr = ta_addr;
			item->type = rz_str_dup("Thread");
			item->arena = ta;
			rz_list_append(arena_list, item);
		}
	}
	return arena_list;
}

/**
 * \brief Get a list of all the heap chunks in an arena. The chunks are in form of a struct RzHeapChunkListItem
 * \param core RzCore pointer
 * \param main_arena MallocState struct of main arena
 * \param m_arena Base address of malloc state of main arena
 * \param m_state Base address of malloc state of the arena whose chunks are required
 * \param top_chunk Boolean value to return the top chunk in the list or not
 * \return RzList pointer for list of all chunks in a given arena
 */
RZ_API RzList /*<RzHeapChunkListItem *>*/ *GH(rz_heap_chunks_list)(RzCore *core, MallocState *main_arena,
	GHT m_arena, GHT m_state, bool top_chunk) {
	RzList *chunks = rz_list_newf((RzListFree)GH(rz_heap_chunk_free));
	if (!core || !core->dbg || !core->dbg->maps) {
		return chunks;
	}
	GHT global_max_fast = (64 * SZ / 4);
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
		brk_end = brk_start + main_arena->system_mem;
		if (tcache) {
			tcache_initial_brk = brk_start + sizeof(GH(RzHeapInfo)) + sizeof(GH(RzHeap_MallocState_tcache)) + GH(MMAP_ALIGN);
			initial_brk = tcache_initial_brk + offset;
		} else {
			initial_brk = brk_start + sizeof(GH(RzHeapInfo)) + sizeof(GH(RzHeap_MallocState)) + MMAP_OFFSET;
		}
	}

	if (brk_start == GHT_MAX || brk_end == GHT_MAX || initial_brk == GHT_MAX) {
		RZ_LOG_ERROR("core: no heap section\n");
		return chunks;
	}

	GHT next_chunk = initial_brk, prev_chunk = next_chunk;
	GH(RzHeapChunk) *cnk = RZ_NEW0(GH(RzHeapChunk));
	if (!cnk) {
		return chunks;
	}
	GH(RzHeapChunk) *cnk_next = RZ_NEW0(GH(RzHeapChunk));
	if (!cnk_next) {
		free(cnk);
		return chunks;
	}

	(void)rz_io_read_at(core->io, next_chunk, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
	size_tmp = (cnk->size >> 3) << 3;
	ut64 prev_chunk_addr;
	ut64 prev_chunk_size;
	while (next_chunk && next_chunk >= brk_start && next_chunk < main_arena->top) {
		if (size_tmp < min_size || next_chunk + size_tmp > main_arena->top) {
			RzHeapChunkListItem *block = RZ_NEW0(RzHeapChunkListItem);
			if (!block) {
				break;
			}
			block->addr = next_chunk;
			block->status = rz_str_dup("corrupted");
			block->size = size_tmp;
			rz_list_append(chunks, block);
			break;
		}

		prev_chunk_addr = (ut64)prev_chunk;
		prev_chunk_size = (((ut64)cnk->size) >> 3) << 3;
		bool fastbin = size_tmp >= SZ * 4 && size_tmp <= global_max_fast;
		bool is_free = false, double_free = false;

		if (fastbin) {
			int i = (size_tmp / (SZ * 2)) - 2;
			GHT idx = (GHT)main_arena->fastbinsY[i];
			(void)rz_io_read_at(core->io, idx, (ut8 *)cnk, sizeof(GH(RzHeapChunk)));
			GHT next = GH(get_next_pointer)(core, idx, cnk->fd);
			if (prev_chunk == idx && idx && !next) {
				is_free = true;
			}
			while (next && next >= brk_start && next < main_arena->top) {
				if (prev_chunk == idx || prev_chunk == next || idx == next) {
					is_free = true;
					if (idx == next) {
						double_free = true;
						break;
					}
					(void)rz_io_read_at(core->io, next, (ut8 *)cnk_next, sizeof(GH(RzHeapChunk)));
					GHT next_node = GH(get_next_pointer)(core, next, cnk_next->fd);
					// avoid triple while?
					while (next_node && next_node >= brk_start && next_node < main_arena->top) {
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
				free(cnk);
				free(cnk_next);
				return chunks;
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
		RzHeapChunkListItem *block = RZ_NEW0(RzHeapChunkListItem);
		if (!block) {
			break;
		}
		char *status = rz_str_dup("allocated");
		if (fastbin) {
			if (is_free) {
				strcpy(status, "free");
			}
		}
		if (!(cnk->size & 1)) {
			strcpy(status, "free");
		}
		if (tcache) {
			if (is_free) {
				strcpy(status, "free");
			}
		}
		block->addr = prev_chunk_addr;
		block->status = status;
		block->size = prev_chunk_size;
		rz_list_append(chunks, block);
	}
	if (top_chunk) {
		RzHeapChunkListItem *block = RZ_NEW0(RzHeapChunkListItem);
		if (block) {
			block->addr = main_arena->top;
			block->status = rz_str_dup("free (top)");
			RzHeapChunkSimple *chunkSimple = GH(rz_heap_chunk_wrapper)(core, main_arena->top);
			if (chunkSimple) {
				block->size = chunkSimple->size;
				free(chunkSimple);
			}
			rz_list_append(chunks, block);
		}
	}
	free(cnk);
	free(cnk_next);
	return chunks;
}

RZ_IPI RzCmdStatus GH(rz_cmd_arena_print_handler)(RzCore *core, int argc, const char **argv) {
	GHT m_arena = GHT_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	MallocState *main_arena = RZ_NEW0(MallocState);
	if (!main_arena) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (!GH(rz_heap_resolve_main_arena)(core, &m_arena)) {
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	if (!GH(rz_heap_update_main_arena)(core, m_arena, main_arena)) {
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	RzList *arenas_list = GH(rz_heap_arenas_list)(core, m_arena, main_arena);
	RzListIter *iter;
	RzArenaListItem *pos;
	bool flag = false;
	rz_list_foreach (arenas_list, iter, pos) {
		MallocState *arena = pos->arena;
		if (!flag) {
			flag = true;
			rz_cons_printf("Main arena  (addr=");
		} else {
			rz_cons_printf("Thread arena(addr=");
		}
		PRINTF_YA("0x%" PFMT64x, (ut64)pos->addr);
		rz_cons_printf(", lastRemainder=");
		PRINTF_YA("0x%" PFMT64x, (ut64)arena->last_remainder);
		rz_cons_printf(", top=");
		PRINTF_YA("0x%" PFMT64x, (ut64)arena->top);
		rz_cons_printf(", next=");
		PRINTF_YA("0x%" PFMT64x, (ut64)arena->next);
		if (arena->attached_threads) {
			rz_cons_printf(")\n");
		} else {
			rz_cons_printf(", free)\n");
		}
	}
	rz_list_free(arenas_list);
	free(main_arena);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus GH(rz_cmd_heap_chunks_print_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	GHT m_arena = GHT_MAX, m_state = GHT_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	MallocState *main_arena = RZ_NEW0(MallocState);
	RzOutputMode mode = state->mode;
	if (!main_arena) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (!GH(rz_heap_resolve_main_arena)(core, &m_arena)) {
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc == 1) {
		m_state = m_arena;
	} else if (argc == 2) {
		m_state = rz_num_get(NULL, argv[1]);
	}
	if (!GH(is_arena)(core, m_arena, m_state)) {
		free(main_arena);
		PRINT_RA("This address is not a valid arena\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (!GH(rz_heap_update_main_arena)(core, m_state, main_arena)) {
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	GHT brk_start, brk_end;
	if (m_arena == m_state) {
		GH(get_brks)
		(core, &brk_start, &brk_end);

	} else {
		brk_start = ((m_state >> 16) << 16);
		brk_end = brk_start + main_arena->system_mem;
	}
	RzListIter *iter;
	RzHeapChunkListItem *pos;
	PJ *pj = state->d.pj;
	int w, h;
	RzConfigHold *hc = rz_config_hold_new(core->config);
	if (!hc) {
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	w = rz_cons_get_size(&h);
	RzConsCanvas *can = rz_cons_canvas_new(w, h);
	if (!can) {
		free(main_arena);
		rz_config_hold_free(hc);
		return RZ_CMD_STATUS_ERROR;
	}

	RzAGraph *g = rz_agraph_new(can);
	if (!g) {
		free(main_arena);
		rz_cons_canvas_free(can);
		rz_config_hold_restore(hc);
		rz_config_hold_free(hc);
		return RZ_CMD_STATUS_ERROR;
	}
	RzANode *top = RZ_EMPTY, *chunk_node = RZ_EMPTY, *prev_node = RZ_EMPTY;
	char *top_title = NULL, *top_data = NULL, *node_title = NULL, *node_data = NULL;
	bool first_node = true;
	top_data = rz_str_dup("");
	RzList *chunks = GH(rz_heap_chunks_list)(core, main_arena, m_arena, m_state, false);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		if (!pj) {
			goto end;
		}
		pj_o(pj);
		pj_ka(pj, "chunks");
	} else if (mode == RZ_OUTPUT_MODE_STANDARD || mode == RZ_OUTPUT_MODE_LONG) {
		rz_cons_printf("Arena @ ");
		PRINTF_YA("0x%" PFMT64x, (ut64)m_state);
		rz_cons_newline();
	} else if (mode == RZ_OUTPUT_MODE_LONG_JSON) {
		can->linemode = rz_config_get_i(core->config, "graph.linemode");
		can->color = rz_config_get_i(core->config, "scr.color");
		core->cons->use_utf8 = rz_config_get_i(core->config, "scr.utf8");
		g->layout = rz_config_get_i(core->config, "graph.layout");
		rz_agraph_set_title(g, "Heap Layout");
		top_title = rz_str_newf("Top chunk @ 0x%" PFMT64x "\n", (ut64)main_arena->top);
	}
	rz_list_foreach (chunks, iter, pos) {
		if (mode == RZ_OUTPUT_MODE_STANDARD || mode == RZ_OUTPUT_MODE_LONG) {
			GH(print_heap_chunk_simple)
			(core, pos->addr, pos->status, NULL);
			rz_cons_newline();
			if (mode == RZ_OUTPUT_MODE_LONG) {
				int size = 0x10;
				char *data = calloc(1, size);
				if (data) {
					rz_io_nread_at(core->io, (ut64)(pos->addr + SZ * 2), (ut8 *)data, size);
					core->print->flags &= ~RZ_PRINT_FLAGS_HEADER;
					core->print->pairs = false;
					rz_cons_printf("   ");
					rz_core_print_hexdump(core, (ut64)(pos->addr + SZ * 2), (ut8 *)data, size, SZ * 2, 1, 1);
					core->print->flags |= RZ_PRINT_FLAGS_HEADER;
					core->print->pairs = true;
					free(data);
				}
			}
		} else if (mode == RZ_OUTPUT_MODE_JSON) {
			pj_o(pj);
			pj_kn(pj, "addr", pos->addr);
			pj_kn(pj, "size", pos->size);
			pj_ks(pj, "status", pos->status);
			pj_end(pj);
		} else if (mode == RZ_OUTPUT_MODE_RIZIN) {
			rz_cons_printf("fs heap.%s\n", pos->status);
			char *name = rz_str_newf("chunk.%06" PFMT64x, ((pos->addr >> 4) & 0xffffULL));
			rz_cons_printf("f %s %d @ 0x%" PFMT64x "\n", name, (int)pos->size, (ut64)pos->addr);
			free(name);
		} else if (mode == RZ_OUTPUT_MODE_LONG_JSON) { // graph
			free(node_title);
			free(node_data);
			node_title = rz_str_newf("  Malloc chunk @ 0x%" PFMT64x " ", (ut64)pos->addr);
			node_data = rz_str_newf("size: 0x%" PFMT64x " status: %s\n", (ut64)pos->size, pos->status);
			chunk_node = rz_agraph_add_node(g, node_title, node_data);
			if (first_node) {
				first_node = false;
			} else {
				rz_agraph_add_edge(g, prev_node, chunk_node);
			}
			prev_node = chunk_node;
		}
	}
	if (mode == RZ_OUTPUT_MODE_STANDARD || mode == RZ_OUTPUT_MODE_LONG) {
		GH(print_heap_chunk_simple)
		(core, main_arena->top, "free", NULL);
		PRINT_RA("[top]");
		rz_cons_printf("[brk_start: ");
		PRINTF_YA("0x%" PFMT64x, (ut64)brk_start);
		rz_cons_printf(", brk_end: ");
		PRINTF_YA("0x%" PFMT64x, (ut64)brk_end);
		rz_cons_printf("]");
	} else if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		pj_kn(pj, "top", main_arena->top);
		pj_kn(pj, "brk", brk_start);
		pj_kn(pj, "end", brk_end);
		pj_end(pj);
	} else if (mode == RZ_OUTPUT_MODE_RIZIN) {
		rz_cons_printf("fs-\n");
		rz_cons_printf("f heap.top @ 0x%08" PFMT64x "\n", (ut64)main_arena->top);
		rz_cons_printf("f heap.brk @ 0x%08" PFMT64x "\n", (ut64)brk_start);
		rz_cons_printf("f heap.end @ 0x%08" PFMT64x "\n", (ut64)brk_end);
	} else if (mode == RZ_OUTPUT_MODE_LONG_JSON) {
		top = rz_agraph_add_node(g, top_title, top_data);
		if (!first_node) {
			rz_agraph_add_edge(g, prev_node, top);
			free(node_data);
			free(node_title);
		}
		rz_agraph_print(g);
	}
end:
	rz_cons_newline();
	free(g);
	free(top_data);
	free(top_title);
	rz_list_free(chunks);
	free(main_arena);
	rz_cons_canvas_free(can);
	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus GH(rz_cmd_main_arena_print_handler)(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	GHT m_arena = GHT_MAX, m_state = GHT_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	GHT global_max_fast = (64 * SZ / 4);
	MallocState *main_arena = RZ_NEW0(MallocState);
	if (!main_arena) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (!GH(rz_heap_resolve_main_arena)(core, &m_arena)) {
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc == 1) {
		m_state = m_arena;
	} else if (argc == 2) {
		m_state = rz_num_get(NULL, argv[1]);
	}
	if (!GH(is_arena)(core, m_arena, m_state)) {
		PRINT_RA("This address is not a valid arena\n");
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	if (!GH(rz_heap_update_main_arena)(core, m_state, main_arena)) {
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	GH(print_arena_stats)
	(core, m_state, main_arena, global_max_fast, mode);
	free(main_arena);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus GH(rz_cmd_heap_chunk_print_handler)(RzCore *core, int argc, const char **argv) {
	GHT m_arena = GHT_MAX;
	MallocState *main_arena = RZ_NEW0(MallocState);
	if (!main_arena) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (!GH(rz_heap_resolve_main_arena)(core, &m_arena)) {
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 addr = core->offset;
	GH(print_heap_chunk)
	(core, addr);
	free(main_arena);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus GH(rz_cmd_heap_info_print_handler)(RzCore *core, int argc, const char **argv) {
	GHT m_arena = GHT_MAX, m_state = GHT_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	MallocState *main_arena = RZ_NEW0(MallocState);
	if (!main_arena) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (!GH(rz_heap_resolve_main_arena)(core, &m_arena)) {
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc == 1) {
		m_state = m_arena;
	} else if (argc == 2) {
		m_state = rz_num_get(NULL, argv[1]);
	}
	if (!GH(is_arena)(core, m_arena, m_state)) {
		PRINT_RA("This address is not a valid arena\n");
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	if (!GH(rz_heap_update_main_arena)(core, m_state, main_arena)) {
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	GH(print_malloc_info)
	(core, m_arena, m_state);
	free(main_arena);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus GH(rz_cmd_heap_tcache_print_handler)(RzCore *core, int argc, const char **argv) {
	GHT m_arena = GHT_MAX;

	if (!GH(rz_heap_resolve_main_arena)(core, &m_arena)) {
		return RZ_CMD_STATUS_ERROR;
	}

	const int tc = rz_config_get_i(core->config, "dbg.glibc.tcache");
	if (!tc) {
		rz_cons_printf("No tcache present in this version of libc\n");
		return RZ_CMD_STATUS_ERROR;
	}

	if (!GH(resolve_heap_tcache)(core, m_arena)) {
		return RZ_CMD_STATUS_ERROR;
	}

	return RZ_CMD_STATUS_OK;
}

RZ_IPI int GH(rz_cmd_heap_bins_list_print)(RzCore *core, const char *input) {
	GHT m_arena = GHT_MAX, m_state = GHT_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	MallocState *main_arena = RZ_NEW0(MallocState);
	if (!GH(rz_heap_resolve_main_arena)(core, &m_arena)) {
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	char *m_state_str, *dup = strdup(input);
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
		if (!GH(rz_heap_update_main_arena)(core, m_state, main_arena)) {
			free(main_arena);
			free(dup);
			return RZ_CMD_STATUS_ERROR;
		}
		GH(print_heap_bin)
		(core, m_state, main_arena, dup);
	} else {
		PRINT_RA("This address is not part of the arenas\n");
		free(main_arena);
		free(dup);
		return RZ_CMD_STATUS_ERROR;
	}
	free(dup);
	free(main_arena);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI int GH(rz_cmd_heap_fastbins_print)(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	GHT m_arena = GHT_MAX, m_state = GHT_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	MallocState *main_arena = RZ_NEW0(MallocState);
	GHT global_max_fast = (64 * SZ / 4);
	if (!GH(rz_heap_resolve_main_arena)(core, &m_arena)) {
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	bool main_arena_only = false;
	char *m_state_str, *dup = strdup(input);
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
		if (!GH(rz_heap_update_main_arena)(core, m_state, main_arena)) {
			free(dup);
			free(main_arena);
			return RZ_CMD_STATUS_ERROR;
		}
		GH(print_heap_fastbin)
		(core, m_state, main_arena, global_max_fast, dup, main_arena_only, NULL);
	} else {
		PRINT_RA("This address is not part of the arenas\n");
		free(dup);
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	free(dup);
	free(main_arena);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus GH(rz_cmd_heap_arena_bins_print_handler)(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	GHT m_arena = GHT_MAX, m_state = GHT_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	GHT global_max_fast = (64 * SZ / 4);
	MallocState *main_arena = RZ_NEW0(MallocState);
	if (!main_arena) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (!GH(rz_heap_resolve_main_arena)(core, &m_arena)) {
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	if (core->offset != core->prompt_offset) {
		m_state = core->offset;
	} else {
		m_state = m_arena;
	}
	if (!GH(is_arena)(core, m_arena, m_state)) {
		PRINT_RA("This address is not part of the arenas\n");
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}
	if (!GH(rz_heap_update_main_arena)(core, m_state, main_arena)) {
		free(main_arena);
		return RZ_CMD_STATUS_ERROR;
	}

	bool json = false;
	if (mode == RZ_OUTPUT_MODE_JSON) { // dmhdj
		json = true;
	}
	RzHeapBinType bin_format = RZ_HEAP_BIN_ANY;
	if (argc == 2) {
		const char *input = argv[1];
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
		}
	}
	GH(print_main_arena_bins)
	(core, m_state, main_arena, m_arena, global_max_fast, bin_format, json);
	free(main_arena);
	return RZ_CMD_STATUS_OK;
}

/**
 * \brief A wrapper around GH(rz_heap_arenas_list) which handles finding main_arena
 * \param core RzCore pointer
 * \return RzList of RzArenaListItem
 */
RZ_API RzList /*<RzArenaListItem *>*/ *GH(rz_heap_arena_list_wrapper)(RzCore *core) {
	GHT m_arena;
	if (!GH(rz_heap_resolve_main_arena)(core, &m_arena)) {
		return rz_list_newf(free);
	}
	MallocState *main_arena = RZ_NEW0(MallocState);
	if (!main_arena) {
		return rz_list_newf(free);
	}
	if (!GH(rz_heap_update_main_arena)(core, m_arena, main_arena)) {
		free(main_arena);
		return rz_list_newf(free);
	}
	RzList *arenas_list = GH(rz_heap_arenas_list)(core, m_arena, main_arena);
	free(main_arena);
	return arenas_list;
}

/**
 * \brief A wrapper around GH(rz_heap_chunks_list) which handles finding the main arena
 * \param core RzCore pointer
 * \param m_arena Base Address of the arena
 * \return RzList of heap chunks as RzHeapChunkListItem structs
 */
RZ_API RzList /*<RzHeapChunkListItem *>*/ *GH(rz_heap_chunks_list_wrapper)(RzCore *core, ut64 m_state) {
	GHT m_arena;
	if (!GH(rz_heap_resolve_main_arena)(core, &m_arena)) {
		return rz_list_newf(free);
	}
	if (!GH(is_arena)(core, m_arena, m_state)) {
		return rz_list_newf(free);
	}
	MallocState *main_arena = RZ_NEW0(MallocState);
	if (!main_arena) {
		return rz_list_newf(free);
	}
	if (!GH(rz_heap_update_main_arena)(core, m_state, main_arena)) {
		free(main_arena);
		return rz_list_newf(free);
	}
	RzList *chunks = GH(rz_heap_chunks_list)(core, main_arena, m_arena, m_state, true);
	free(main_arena);
	return chunks;
}

/**
 * \brief Get info about a heap chunk as RzHeapChunkSimple
 * \param core RzCore pointer
 * \param addr Base address of the heap chunk
 * \return RzHeapChunkSimple struct pointer for the chunk
 */
RZ_API RzHeapChunkSimple *GH(rz_heap_chunk_wrapper)(RzCore *core, GHT addr) {
	GH(RzHeapChunk) *heap_chunk = GH(rz_heap_get_chunk_at_addr)(core, addr);
	if (!heap_chunk) {
		return NULL;
	}
	RzHeapChunkSimple *simple_chunk = RZ_NEW0(RzHeapChunkSimple);
	if (!simple_chunk) {
		free(heap_chunk);
		return NULL;
	}
	ut64 size = heap_chunk->size;
	simple_chunk->addr = addr;
	simple_chunk->size = size & ~(NON_MAIN_ARENA | IS_MMAPPED | PREV_INUSE);
	simple_chunk->non_main_arena = (bool)((size & NON_MAIN_ARENA) >> 2);
	simple_chunk->is_mmapped = (bool)((size & IS_MMAPPED) >> 1);
	simple_chunk->prev_inuse = (bool)(size & PREV_INUSE);
	simple_chunk->prev_size = heap_chunk->prev_size;
	simple_chunk->bk = heap_chunk->bk;
	simple_chunk->fd = heap_chunk->fd;
	simple_chunk->fd_nextsize = heap_chunk->fd_nextsize;
	simple_chunk->bk_nextsize = heap_chunk->bk_nextsize;
	free(heap_chunk);
	return simple_chunk;
}

/**
 * \brief Get MallocState struct for arena with given base address
 * if base address is 0 then return MallocState for main arena
 * \param core RzCore pointer
 * \param addr Base address of the arena
 * \return MallocState struct pointer for the arena
 */
RZ_API MallocState *GH(rz_heap_get_arena)(RzCore *core, GHT m_state) {
	GHT m_arena;
	if (!GH(rz_heap_resolve_main_arena)(core, &m_arena)) {
		return NULL;
	}
	if (!m_state) {
		m_state = m_arena;
	}
	if (!GH(is_arena)(core, m_arena, m_state)) {
		return NULL;
	}
	MallocState *main_arena = RZ_NEW0(MallocState);
	if (!main_arena) {
		return NULL;
	}
	if (!GH(rz_heap_update_main_arena)(core, m_state, main_arena)) {
		free(main_arena);
		return NULL;
	}
	return main_arena;
}

/**
 * \brief Write a heap chunk header to memory
 * \param core RzCore pointer
 * \param chunk_simple RzHeapChunkSimple pointer to the heap chunk data
 * \return bool if the write succeeded or not
 */
RZ_API bool GH(rz_heap_write_heap_chunk)(RzCore *core, RzHeapChunkSimple *chunk_simple) {
	if (!chunk_simple) {
		return false;
	}
	GH(RzHeapChunk) *heap_chunk = RZ_NEW0(GH(RzHeapChunk));
	if (!heap_chunk) {
		return false;
	}

	heap_chunk->size = chunk_simple->size;
	// add flag bits to chunk size
	if (chunk_simple->prev_inuse) {
		heap_chunk->size |= PREV_INUSE;
	}
	if (chunk_simple->is_mmapped) {
		heap_chunk->size |= IS_MMAPPED;
	}
	if (chunk_simple->non_main_arena) {
		heap_chunk->size |= NON_MAIN_ARENA;
	}

	heap_chunk->fd = chunk_simple->fd;
	heap_chunk->bk = chunk_simple->bk;
	heap_chunk->fd_nextsize = chunk_simple->fd_nextsize;
	heap_chunk->bk_nextsize = chunk_simple->bk_nextsize;
	bool res = rz_io_write_at(core->io, chunk_simple->addr, (ut8 *)heap_chunk, sizeof(GH(RzHeapChunk)));
	free(heap_chunk);
	return res;
}
