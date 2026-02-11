// SPDX-FileCopyrightText: 2016-2020 n4x0r <kalianon2816@gmail.com>
// SPDX-FileCopyrightText: 2016-2020 soez <soez@amn3s1a.com>
// SPDX-FileCopyrightText: 2016-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_config.h>
#include <rz_types.h>
#include <rz_glibc/glibc_types.h>
#include <rz_glibc/glibc_parser.h>
#include <rz_heap_glibc.h>
#include <rz_debug.h>
#include <math.h>
#include "core_private.h"

void print_heap_chunk_simple(RzCore *core, ut64 chunk, const char *status, PJ *pj, const RzHeapConfig *config);
static void rz_heap_get_brks(RzCore *core, ut64 *brk_start, ut64 *brk_end);
static inline bool init_glibc_config(RzCore *core, RzHeapConfig *config);
static ut64 rz_heap_get_main_arena_with_symbol(RzCore *core, RzDebugMap *map);
static bool rz_heap_is_arena(RzCore *core, ut64 m_arena, ut64 m_state, const RzHeapConfig *config);
static bool rz_heap_is_tcache(RzCore *core);
static char *rz_heap_bin_num_to_type(int bin_num);
void rz_heap_chunk_free(RzHeapChunkListItem *item);
void rz_arena_list_free(RzArenaListItem *item);
RzList /*<RzHeapBin *>*/ *rz_heap_tcache_content_internal(RzCore *core, ut64 arena_base, const RzHeapConfig *config);
RzHeapBin *rz_heap_fastbin_content_internal(RzCore *core, MallocState *arena, int bin_num, const RzHeapConfig *config);
RzHeapBin *rz_heap_bin_content_internal(RzCore *core, MallocState *arena, int bin_num, ut64 m_arena, const RzHeapConfig *config);
RzList /*<RzHeapChunkListItem *>*/ *rz_heap_chunks_list_internal(RzCore *core, MallocState *main_arena, ut64 m_arena, ut64 m_state, bool show_unallocated, const RzHeapConfig *config);
RzHeapChunkSimple *rz_heap_chunk_internal(RzCore *core, ut64 addr, const RzHeapConfig *config);
RzHeapChunk *rz_heap_get_chunk_at_addr_internal(RzCore *core, ut64 chunk, const RzHeapConfig *config);
RzList /*<RzArenaListItem *>*/ *rz_heap_arenas_list_internal(RzCore *core, ut64 m_arena, MallocState *main_arena, const RzHeapConfig *config);
bool rz_heap_update_main_arena_internal(RzCore *core, ut64 m_arena, MallocState *main_arena, const RzHeapConfig *config);

static inline ut8 rz_heap_ptr_size(RzCore *core) {
	ut8 bits = (ut8)core->rasm->bits;
	if (!bits) {
		bits = (ut8)core->dbg->bits;
	}
	return bits ? (ut8)(bits / 8) : 0;
}

static inline ut64 rz_heap_fastbin_idx_to_size(int idx, ut8 ptr_size) {
	return (ptr_size * 4) + (ptr_size * 2) * (idx - 1);
}

static inline int rz_heap_fastbin_index(ut64 size, ut8 ptr_size) {
	return (ptr_size == 8) ? ((size >> 4) - 2) : ((size >> 3) - 2);
}

static inline int rz_heap_largebin_index(ut64 size, ut8 ptr_size) {
	ut32 s = (ut32)size;
	if (ptr_size == 8) {
		if ((s >> 6) <= 48) {
			return 48 + (s >> 6);
		} else if ((s >> 9) <= 20) {
			return 91 + (s >> 9);
		} else if ((s >> 12) <= 10) {
			return 110 + (s >> 12);
		} else if ((s >> 15) <= 4) {
			return 119 + (s >> 15);
		} else if ((s >> 18) <= 2) {
			return 124 + (s >> 18);
		}
		return 126;
	}
	if ((s >> 6) <= 38) {
		return 56 + (s >> 6);
	} else if ((s >> 9) <= 20) {
		return 91 + (s >> 9);
	} else if ((s >> 12) <= 10) {
		return 110 + (s >> 12);
	} else if ((s >> 15) <= 4) {
		return 119 + (s >> 15);
	} else if ((s >> 18) <= 2) {
		return 124 + (s >> 18);
	}
	return 126;
}

static bool read_chunk_ptr_pair_fallback(RzIO *io, ut64 chunk, ut64 mem_offset, ut64 *first, ut64 *second, const RzHeapConfig *config) {
	rz_return_val_if_fail(io && first && second && config, false);
	ut8 ptr_buf[16] = { 0 };
	ut64 read_addr = rz_glibc_chunk_to_mem(chunk, config) + mem_offset;
	if (!rz_io_read_at_mapped(io, read_addr, ptr_buf, config->ptr_size * 2)) {
		return false;
	}
	if (config->ptr_size == 8) {
		*first = rz_read_le64(ptr_buf);
		*second = rz_read_le64(ptr_buf + 8);
	} else {
		*first = rz_read_le32(ptr_buf);
		*second = rz_read_le32(ptr_buf + 4);
	}
	return true;
}

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
static ut64 rz_heap_get_va_symbol(RzCore *core, const char *path, const char *sym_name) {
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

static inline ut64 rz_heap_get_next_pointer(RzCore *core, ut64 pos, ut64 next, const RzHeapConfig *config) {
	if (!config) {
		return next;
	}
	return rz_glibc_has_safe_linking(config->glibc_version)
		? rz_glibc_safe_link_decode(next, pos)
		: next;
}

static ut64 rz_heap_get_main_arena_with_symbol(RzCore *core, RzDebugMap *map) {
	rz_return_val_if_fail(core && map, UT64_MAX);
	ut64 base_addr = map->addr;
	rz_return_val_if_fail(base_addr != UT64_MAX, UT64_MAX);

	ut64 main_arena = UT64_MAX;
	ut64 off = UT64_MAX;
	char *path = rz_str_dup(map->name);
	if (path && rz_file_exists(path)) {
		off = rz_heap_get_va_symbol(core, path, "main_arena");
		if (off != UT64_MAX) {
			main_arena = base_addr + off;
			goto beach;
		}
		RzBinObject *o = rz_bin_cur_object(core->bin);
		RzBinInfo *info = o ? (RzBinInfo *)rz_bin_object_get_info(o) : NULL;
		if (!strcmp(info->arch, "x86") && info->bits == 64 &&
			// Assumes that the vaddr of LOAD0 is 0x0
			(off = rz_heap_get_va_symbol(core, path, "mallopt")) != UT64_MAX) {
			// This code looks for the following instructions:
			//     mov edx, 1
			//     (lock) cmpxchg dword [<main_arena_addr>], edx
			//
			// The instructions should be part of the following C
			// code in mallopt():
			//     __libc_lock_lock (av->mutex);
			ut64 mallopt_addr = base_addr + off;
			ut8 bytes[200] = { 0 };
			rz_io_read_at_mapped(core->io, mallopt_addr, bytes, sizeof(bytes));
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

static ut8 *get_glibc_banner(RzCore *core, const char *section_name,
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
		ut64 read_size = rz_buf_read_at(libc_buf->buf, rz_section->paddr, buf, rz_section->size);
		if (read_size != rz_section->size) {
			free(buf);
			buf = NULL;
			goto cleanup;
		}
		buf_parse = (ut8 *)rz_mem_mem((const ut8 *)buf, rz_section->size, (const ut8 *)"GNU C Library", strlen("GNU C Library"));
		ret_buf = (ut8 *)rz_str_dup((char *)buf_parse);
		break;
	}

cleanup:
	free(buf);
	rz_pvector_free(sections);
	rz_bin_file_delete(bin, libc_buf);
	rz_bin_file_set_obj(current_bf, current_bf->o);
	rz_bin_set_cur_binfile(bin, current_bf);
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

RZ_API double rz_get_glibc_version(RzCore *core, const char *libc_path, ut8 *banner_start) {
	double version = 0.0;
	ut8 *libc_ro_section = NULL;

	if (!banner_start) {
		libc_ro_section = get_glibc_banner(core, ".rodata", libc_path);
		if (!libc_ro_section) {
			return version;
		}
	}

	const char *pattern = "release version (\\d.\\d\\d)";
	RzRegex *re = rz_regex_new(pattern, RZ_REGEX_EXTENDED | RZ_REGEX_CASELESS, 0, NULL);
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

static ut64 read_val(RzCore *core, const void *src, bool is_big_endian) {
	const ut8 ptr_size = rz_heap_ptr_size(core);
	if (ptr_size == 2) {
		return rz_read_ble16(src, is_big_endian);
	} else if (ptr_size == 4) {
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
static RZ_BORROW RzList /*<RzList *>*/ *fill_tcache_entries(RzCore *core, const RzHeapTcache *tcache,
	const RzHeapConfig *config) {
	RzList *tcache_bins_list = rz_list_newf((RzListFree)rz_heap_bin_free);
	if (!tcache_bins_list) {
		goto error;
	}

	// Use rz_tcache struct to get bins
	for (ut32 i = 0; i < config->tcache.num_bins; i++) {
		ut16 count = tcache->counts[i];
		ut64 entry = tcache->entries[i];

		RzHeapBin *bin = RZ_NEW0(RzHeapBin);
		if (!bin) {
			goto error;
		}
		bin->type = rz_str_dup("Tcache");
		bin->bin_num = i;
		bin->chunks = rz_list_newf((RzListFree)rz_heap_chunk_free);
		if (!bin->chunks) {
			rz_heap_bin_free(bin);
			goto error;
		}
		rz_list_append(tcache_bins_list, bin);
		if (count <= 0) {
			continue;
		}
		bin->fd = rz_glibc_mem_to_chunk(entry, config);
		// get first chunk
		RzHeapChunkListItem *chunk = RZ_NEW0(RzHeapChunkListItem);
		if (!chunk) {
			rz_heap_bin_free(bin);
			goto error;
		}
		chunk->addr = rz_glibc_mem_to_chunk(entry, config);
		rz_list_append(bin->chunks, chunk);

		if (count <= 1) {
			continue;
		}

		// get rest of the chunks
		ut64 tcache_fd = entry;
		for (size_t n = 1; n < count; n++) {
			RzHeapTcacheEntry tentry;
			if (!rz_glibc_read_tcache_entry(core->io, tcache_fd, &tentry, config)) {
				goto error;
			}
			ut64 tcache_tmp = rz_glibc_tcache_next(&tentry, tcache_fd, config);
			if (!tcache_tmp) {
				break;
			}
			chunk = RZ_NEW0(RzHeapChunkListItem);
			if (!chunk) {
				goto error;
			}
			// the base address of the chunk = address - 2 * PTR_SIZE
			chunk->addr = rz_glibc_mem_to_chunk(tcache_tmp, config);
			rz_list_append(bin->chunks, chunk);
			tcache_fd = tcache_tmp;
		}
	}
	return tcache_bins_list;

error:
	rz_list_free(tcache_bins_list);
	return NULL;
}

static void print_tcache(RzCore *core, RzList /*<RzList *>*/ *bins, PJ *pj, const ut64 tid, const RzHeapConfig *config) {
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
			print_heap_chunk_simple(core, pos->addr, NULL, pj, config);
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
static bool rz_heap_is_tcache(RzCore *core) {
	if (!rz_config_get_b(core->config, "cfg.debug")) {
		int tcv = rz_config_get_i(core->config, "dbg.glibc.tcache");
		RZ_LOG_WARN("core: dbg.glibc.tcache has been set to %i\n", tcv);
		return tcv != 0;
	}

	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return false;
	}
	return rz_glibc_has_tcache(config.glibc_version);
}

/**
 * \brief Store the MallocState struct of an arena with base address m_arena in main_arena
 * \param core RzCore pointer
 * \param m_arena The base address of malloc state struct of the arena
 * \param main_arena The MallocState struct in which the data is stored
 * \return True if the main_arena struct was successfully updated else False
 */
RZ_API bool rz_heap_update_main_arena(RzCore *core, ut64 m_arena, MallocState *main_arena) {
	rz_return_val_if_fail(core && main_arena, false);
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return false;
	}
	return rz_heap_update_main_arena_internal(core, m_arena, main_arena, &config);
}

bool rz_heap_update_main_arena_internal(RzCore *core, ut64 m_arena, MallocState *main_arena, const RzHeapConfig *config) {
	rz_return_val_if_fail(core && main_arena && config, false);
	const int tcache = rz_config_get_i(core->config, "dbg.glibc.tcache");
	if (!rz_glibc_read_malloc_state(core->io, m_arena, main_arena, config)) {
		return false;
	}

	if (tcache && !main_arena->next) {
		return false;
	}
	return true;
}

static void rz_heap_get_brks(RzCore *core, ut64 *brk_start, ut64 *brk_end) {
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

static void print_arena_stats(RzCore *core, ut64 m_arena, MallocState *main_arena, ut64 global_max_fast, int format, const RzHeapConfig *config) {
	size_t i, j, k, start;
	const ut8 ptr_size = config ? config->ptr_size : rz_heap_ptr_size(core);
	ut64 align = 12 * ptr_size + sizeof(int) * 2;
	const int tcache = rz_config_get_i(core->config, "dbg.glibc.tcache");
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (tcache) {
		align = 16;
	}

	ut64 apart[RZ_GLIBC_NSMALLBINS + 1] = { 0LL };

	PRINT_GA("malloc_state @ ");
	PRINTF_BA("0x%" PFMT64x "\n\n", (ut64)m_arena);
	PRINT_GA("struct malloc_state main_arena {\n");
	PRINT_GA("  mutex = ");
	PRINTF_BA("0x%08x\n", (ut32)main_arena->mutex);
	PRINT_GA("  flags = ");
	PRINTF_BA("0x%08x\n", (ut32)main_arena->flags);
	PRINT_GA("  fastbinsY = {\n");

	for (i = 0, j = 1, k = ptr_size * 4; i < RZ_GLIBC_NFASTBINS; i++, j++, k += ptr_size * 2) {
		if (rz_heap_fastbin_idx_to_size(j, ptr_size) <= global_max_fast) {
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
	start = ptr_size * 128;
	for (i = start, k = 0, j = 0; j < RZ_GLIBC_NBINS - 2 && i < 1024 * 1024; i += 64) {
		j = rz_heap_largebin_index(i, ptr_size);
		if (j == k + RZ_GLIBC_NSMALLBINS + 1) {
			apart[k++] = i;
		}
	}
	for (i = 0, j = 1, k = ptr_size * 4; i < RZ_GLIBC_NBINS * 2 - 2; i += 2, j++) {
		PRINTF_YA(" Bin %03zu: ", j);
		if (j == 1) {
			PRINT_GA("Unsorted Bin");
			PRINT_GA(" [");
			PRINT_GA(" chunksize:");
			PRINT_BA(" undefined ");
		} else if (j > 1 && j <= RZ_GLIBC_NSMALLBINS) {
			if (j == 2) {
				PRINT_GA("             ┌");
			} else if (j == (RZ_GLIBC_NSMALLBINS / 2)) {
				PRINT_GA("  Small Bins │");
			} else if (j != 2 && j != (RZ_GLIBC_NSMALLBINS / 2) && j != RZ_GLIBC_NSMALLBINS) {
				PRINT_GA("             │");
			} else {
				PRINT_GA("             └");
			}
			PRINT_GA(" chunksize:");
			PRINTF_BA(" == %06zu  ", k);
			if (j < RZ_GLIBC_NSMALLBINS) {
				k += ptr_size * 2;
			}
		} else {
			if (j == RZ_GLIBC_NSMALLBINS + 1) {
				PRINT_GA("             ┌");
			} else if (j == (RZ_GLIBC_NSMALLBINS / 2) * 3) {
				PRINT_GA("  Large Bins │");
			} else if (j != RZ_GLIBC_NSMALLBINS + 1 && j != (RZ_GLIBC_NSMALLBINS / 2) * 3 && j != RZ_GLIBC_NBINS - 1) {
				PRINT_GA("             │");
			} else {
				PRINT_GA("             └");
			}
			PRINT_GA(" chunksize:");
			if (j != RZ_GLIBC_NBINS - 1) {
				PRINTF_BA(" >= %06" PFMT64d "  ", (ut64)apart[j - RZ_GLIBC_NSMALLBINS - 1]);
			} else {
				PRINT_BA(" remaining ");
			}
		}
		ut64 bin = m_arena + align + ptr_size * i - ptr_size * 2;
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

	for (i = 0; i < RZ_GLIBC_BINMAPSIZE; i++) {
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

RZ_IPI bool rz_heap_is_map_name_libc(const char *map_name) {
	return strstr(map_name, "/libc-") || strstr(map_name, "/libc.");
}

/**
 * \brief Store the base address of main arena at m_arena
 * \param core RzCore pointer
 * \param m_arena Store the location of main arena at this integer pointer
 * \return True if a main arena was found else False
 */
RZ_API bool rz_heap_resolve_main_arena(RzCore *core, ut64 *m_arena) {
	rz_return_val_if_fail(core && core->dbg && core->dbg->maps, false);

	ut64 brk_start = UT64_MAX, brk_end = UT64_MAX;
	ut64 libc_addr_sta = UT64_MAX, libc_addr_end = 0;
	ut64 addr_srch = UT64_MAX, heap_sz = UT64_MAX;
	ut64 main_arena_sym = UT64_MAX;
	bool is_debugged = rz_config_get_b(core->config, "cfg.debug");
	bool first_libc = true;
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return false;
	}
	ut8 ptr_size = config.ptr_size;

	rz_config_set_i(core->config, "dbg.glibc.tcache", rz_heap_is_tcache(core));

	if (is_debugged) {
		RzListIter *iter;
		RzDebugMap *map;
		rz_debug_map_sync(core->dbg);
		rz_list_foreach (core->dbg->maps, iter, map) {
			/* Try to find the main arena address using the glibc's symbols. */
			if (rz_heap_is_map_name_libc(map->name) && first_libc && main_arena_sym == UT64_MAX) {
				first_libc = false;
				main_arena_sym = rz_heap_get_main_arena_with_symbol(core, map);
			}
			if (rz_heap_is_map_name_libc(map->name) && map->perm == RZ_PERM_RW) {
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

	if (libc_addr_sta == UT64_MAX || libc_addr_end == UT64_MAX) {
		if (rz_config_get_b(core->config, "cfg.debug")) {
			RZ_LOG_WARN("core: Can't find glibc mapped in memory (see dm)\n");
		} else {
			RZ_LOG_WARN("core: Can't find arena mapped in memory (see om)\n");
		}
		return false;
	}

	rz_heap_get_brks(core, &brk_start, &brk_end);
	if (brk_start == UT64_MAX || brk_end == UT64_MAX) {
		RZ_LOG_ERROR("core: no heap section\n");
		return false;
	}

	addr_srch = libc_addr_sta;
	heap_sz = brk_end - brk_start;
	MallocState ta_storage = { 0 };
	MallocState *ta = &ta_storage;

	if (main_arena_sym != UT64_MAX) {
		rz_heap_update_main_arena_internal(core, main_arena_sym, ta, &config);
		*m_arena = main_arena_sym;
		core->dbg->main_arena_resolved = true;
		return true;
	}

	while (addr_srch < libc_addr_end) {
		rz_heap_update_main_arena_internal(core, addr_srch, ta, &config);
		if (ta->top > brk_start && ta->top < brk_end &&
			ta->system_mem == heap_sz) {

			*m_arena = addr_srch;
			if (is_debugged) {
				core->dbg->main_arena_resolved = true;
			}
			return true;
		}
		addr_srch += ptr_size;
	}
	RZ_LOG_WARN("core: Can't find main_arena in mapped memory\n");
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

static bool parse_tcache_from_addr(RzCore *core, const ut64 tls_addr, const ut64 tid, const RzHeapConfig *config) {
	RzDebugMap *map;
	RzListIter *iter;
	ut8 tcache_addr[8] = { 0 };
	if (!config) {
		return false;
	}

	rz_list_foreach (core->dbg->maps, iter, map) {
		/*
		 * TODO: Send a list of maps with this page size and perms
		 * instead of traversing through every map
		 */
		if (map->size != config->heap_page_size || map->perm != RZ_PERM_RW) {
			if (strcmp(core->dbg->arch, "x86") || map->size != config->heap_page_size_x86) {
				continue;
			}
		}

		rz_io_nread_at(core->io, tls_addr, tcache_addr, sizeof(ut64));
		const ut64 tcache_guess = read_val(core, tcache_addr, false);
		if (tcache_guess < map->addr || tcache_guess > map->addr_end) {
			continue;
		}

#if __aarch64__
		/* We will encounter main_arena pointer somewhere in ARM64 */
		if (rz_heap_is_arena(core, tcache_guess, UT64_MIN, config)) {
			break;
		}
#endif
		RzHeapTcache tcache_heap;
		if (!rz_glibc_read_tcache(core->io, tcache_guess, &tcache_heap, config)) {
			continue;
		}
		RzList *bins = fill_tcache_entries(core, &tcache_heap, config);
		print_tcache(core, bins, NULL, tid, config);
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

static bool parse_tls_data(RzCore *core, RZ_NONNULL RzDebugPid *th, ut64 tid, const RzHeapConfig *config) {
	rz_return_val_if_fail(th, false);
	ut64 tls_addr = UT64_MAX;
	ut64 addr = UT64_MAX;
	const ut8 ptr_size = config ? config->ptr_size : rz_heap_ptr_size(core);

	if (!th->tls) {
		return false;
	}

#if __x86_64__
	ut8 dtv[sizeof(ut64)] = { 0 };
	rz_io_nread_at(core->io, th->tls + ptr_size, dtv, sizeof(ut64));
	addr = read_val(core, dtv, false);
	memset(dtv, 0, sizeof(dtv));
	/*
	 * https://github.com/jart/cosmopolitan/blob/06839ab3017d86e87db3ec740a2b5e00d9fe9e11/libc/runtime/enable_tls.c#L65
	 */
	// size of dtv is ptr_size * 2
	rz_io_nread_at(core->io, addr + ptr_size * 2, dtv, sizeof(ut64));
	addr = read_val(core, dtv, false);
#elif __aarch64__
	/*
	 * https://github.com/jart/cosmopolitan/blob/06839ab3017d86e87db3ec740a2b5e00d9fe9e11/libc/runtime/enable_tls.c#L79
	 */
	addr = th->tls + ptr_size * 2;
#endif
	const ut64 end = addr + 0x10 * ptr_size * 2;
	// Parse tls data and check if it complies with tcache struct
	for (tls_addr = addr; tls_addr <= end; tls_addr += ptr_size) {
		if (parse_tcache_from_addr(core, tls_addr, tid, config)) {
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

static void resolve_tcache_perthread(RZ_NONNULL RzCore *core, const RzHeapConfig *config) {
	RzDebugPid *th;
	RzListIter *it;
	ut64 tid = 1;
	RzDebug *dbg = core->dbg;

	rz_list_foreach (dbg->threads, it, th) {
		// First try: fetch tls value and update debug pid
		if (!th->tls) {
			th->tls = rz_debug_get_tls(core->dbg, th->pid);
		}
		if (!parse_tls_data(core, th, tid++, config)) {
			// Second try: Update the thread list if the tls parsing fails.
			RzList *thread_list = rz_debug_native_threads(dbg, dbg->pid);
			RzDebugPid *thread_dbg = rz_debug_get_thread(thread_list, th->pid);
			if (thread_dbg) {
				parse_tls_data(core, thread_dbg, tid, config);
			}
		}
	}
}

RZ_API RZ_OWN bool resolve_heap_tcache(RZ_NONNULL RzCore *core, ut64 arena_base, const RzHeapConfig *config) {
	RzDebug *dbg = core->dbg;

	if (dbg->threads) {
		resolve_tcache_perthread(core, config);
		return true;
	}

	// Only main thread is present
	RzList *bins = rz_heap_tcache_content_internal(core, arena_base, config);
	print_tcache(core, bins, NULL, 0, config);

	return true;
}

void print_heap_chunk(RzCore *core, ut64 chunk, const RzHeapConfig *config) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	if (!config) {
		return;
	}
	RzHeapChunk cnk = { 0 };
	ut64 prev_size = 0;
	ut64 size_raw = 0;
	if (!rz_glibc_read_chunk_header(core->io, chunk, &prev_size, &size_raw, config)) {
		return;
	}
	cnk.prev_size = prev_size;
	cnk.size = size_raw;
	bool have_full = rz_glibc_read_chunk(core->io, chunk, &cnk, config);
	if (!have_full) {
		read_chunk_ptr_pair_fallback(core->io, chunk, 0, &cnk.fd, &cnk.bk, config);
	}
	ut64 size = rz_glibc_chunk_size(&cnk, config);

	PRINT_GA("struct malloc_chunk @ ");
	PRINTF_BA("0x%" PFMT64x, (ut64)chunk);
	PRINT_GA(" {\n  prev_size = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)cnk.prev_size);
	PRINT_GA(",\n  size = ");
	PRINTF_BA("0x%" PFMT64x, size);
	PRINT_GA(",\n  flags: |N:");
	PRINTF_BA("%1" PFMT64u, (ut64)rz_glibc_chunk_non_main_arena(&cnk));
	PRINT_GA(" |M:");
	PRINTF_BA("%1" PFMT64u, (ut64)rz_glibc_chunk_is_mmapped(&cnk));
	PRINT_GA(" |P:");
	PRINTF_BA("%1" PFMT64u, (ut64)rz_glibc_chunk_prev_inuse(&cnk));

	PRINT_GA(",\n  fd = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)cnk.fd);

	PRINT_GA(",\n  bk = ");
	PRINTF_BA("0x%" PFMT64x, (ut64)cnk.bk);

	if (size > config->ptr_size * 128) {
		if (!have_full) {
			read_chunk_ptr_pair_fallback(core->io, chunk, config->ptr_size * 2, &cnk.fd_nextsize, &cnk.bk_nextsize, config);
		}
		PRINT_GA(",\n  fd-nextsize = ");
		PRINTF_BA("0x%" PFMT64x, (ut64)cnk.fd_nextsize);
		PRINT_GA(",\n  bk-nextsize = ");
		PRINTF_BA("0x%" PFMT64x, (ut64)cnk.bk_nextsize);
	}

	PRINT_GA(",\n}\n");
	ut64 data_size = size - config->chunk_hdr_size;
	if (data_size > config->ptr_size * 128) {
		PRINT_GA("chunk too big to be displayed\n");
		data_size = config->ptr_size * 128;
	}

	char *data = calloc(1, data_size);
	if (data) {
		rz_io_read_at_mapped(core->io, rz_glibc_chunk_to_mem(chunk, config), (ut8 *)data, data_size);
		PRINT_GA("chunk data = \n");
		rz_core_print_hexdump(core, rz_glibc_chunk_to_mem(chunk, config), (ut8 *)data, data_size,
			config->ptr_size * 8, config->ptr_size, 1);
		free(data);
	}
}

/**
 * \brief Get a heap chunk with base address <addr>
 * \param core RzCore pointer
 * \param addr Base address of the chunk
 * \return RzHeapChunk struct pointer of the chunk
 */
RzHeapChunk *rz_heap_get_chunk_at_addr_internal(RzCore *core, ut64 chunk, const RzHeapConfig *config) {
	if (!config) {
		return NULL;
	}

	RzHeapChunk *cnk = RZ_NEW0(RzHeapChunk);
	if (!cnk) {
		return NULL;
	}
	ut64 prev_size = 0;
	ut64 size_raw = 0;
	bool have_header = rz_glibc_read_chunk_header(core->io, chunk, &prev_size, &size_raw, config);
	cnk->prev_size = prev_size;
	cnk->size = size_raw;
	if (have_header) {
		(void)rz_glibc_read_chunk(core->io, chunk, cnk, config);
	}
	return cnk;
}

RZ_API RzHeapChunk *rz_heap_get_chunk_at_addr(RzCore *core, ut64 chunk) {
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return NULL;
	}
	return rz_heap_get_chunk_at_addr_internal(core, chunk, &config);
}
/**
 * \brief Prints compact representation of a heap chunk. Format: Chunk(addr=, size=, flags=)
 * \param core RzCore pointer
 * \param chunk Offset of the chunk in memory
 */
void print_heap_chunk_simple(RzCore *core, ut64 chunk, const char *status, PJ *pj, const RzHeapConfig *config) {
	if (!config) {
		return;
	}
	RzHeapChunk *cnk = rz_heap_get_chunk_at_addr_internal(core, chunk, config);
	if (!cnk) {
		return;
	}
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	ut64 size = rz_glibc_chunk_size(cnk, config);
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
		PRINTF_BA("0x%" PFMT64x, size);
		rz_cons_printf(", flags=");
		bool print_comma = false;
		if (rz_glibc_chunk_non_main_arena(cnk)) {
			PRINT_RA("NON_MAIN_ARENA");
			print_comma = true;
		}
		if (rz_glibc_chunk_is_mmapped(cnk)) {
			if (print_comma) {
				PRINT_RA(",");
			}
			PRINT_RA("IS_MMAPPED");
			print_comma = true;
		}
		if (rz_glibc_chunk_prev_inuse(cnk)) {
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
		pj_kn(pj, "size", size);
		pj_kn(pj, "non_main_arena", rz_glibc_chunk_non_main_arena(cnk));
		pj_kn(pj, "mmapped", rz_glibc_chunk_is_mmapped(cnk));
		pj_kn(pj, "prev_inuse", rz_glibc_chunk_prev_inuse(cnk));
		pj_kn(pj, "fd", cnk->fd);
		pj_kn(pj, "bk", cnk->bk);
		pj_end(pj);
	}
	free(cnk);
}

static bool rz_heap_is_arena(RzCore *core, ut64 m_arena, ut64 m_state, const RzHeapConfig *config) {
	if (m_arena == m_state) {
		return true;
	}

	MallocState ta_storage = { 0 };
	MallocState *ta = &ta_storage;
	if (!rz_heap_update_main_arena_internal(core, m_arena, ta, config)) {
		return false;
	}
	if (ta->next == m_state) {
		return true;
	}
	while (ta->next != UT64_MAX && ta->next != m_arena) {
		if (!rz_heap_update_main_arena_internal(core, ta->next, ta, config)) {
			return false;
		}
		if (ta->next == m_state) {
			return true;
		}
	}
	if (m_state == 0) {
		return true;
	}
	return false;
}

static int print_double_linked_list_bin_simple(RzCore *core, ut64 bin, MallocState *main_arena, ut64 brk_start) {
	ut64 next = UT64_MAX;
	int ret = 1;
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return -1;
	}
	RzHeapChunk cnk;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!rz_glibc_read_chunk(core->io, bin, &cnk, &config)) {
		return -1;
	}

	PRINTF_GA("    0x%" PFMT64x, (ut64)bin);
	if (cnk.fd != bin) {
		ret = 0;
	}
	while (cnk.fd != bin) {
		PRINTF_BA("->fd = 0x%" PFMT64x, (ut64)cnk.fd);
		next = cnk.fd;
		if (next < brk_start || next > main_arena->top) {
			PRINT_RA("Double linked list corrupted\n");
			return -1;
		}
		if (!rz_glibc_read_chunk(core->io, next, &cnk, &config)) {
			return -1;
		}
	}

	PRINTF_GA("->fd = 0x%" PFMT64x, (ut64)cnk.fd);
	next = cnk.fd;

	if (next != bin) {
		PRINT_RA("Double linked list corrupted\n");
		return -1;
	}
	if (!rz_glibc_read_chunk(core->io, next, &cnk, &config)) {
		return -1;
	}
	PRINTF_GA("\n    0x%" PFMT64x, (ut64)bin);

	while (cnk.bk != bin) {
		PRINTF_BA("->bk = 0x%" PFMT64x, (ut64)cnk.bk);
		next = cnk.bk;
		if (next < brk_start || next > main_arena->top) {
			PRINT_RA("Double linked list corrupted.\n");
			return -1;
		}
		if (!rz_glibc_read_chunk(core->io, next, &cnk, &config)) {
			return -1;
		}
	}

	PRINTF_GA("->bk = 0x%" PFMT64x, (ut64)cnk.bk);
	return ret;
}

static int print_double_linked_list_bin_graph(RzCore *core, ut64 bin, MallocState *main_arena, ut64 brk_start) {
	RzAGraph *g = rz_agraph_new(rz_cons_canvas_new(1, 1));
	ut64 next = UT64_MAX;
	char title[256], chunk[256];
	RzANode *bin_node = NULL, *prev_node = NULL, *next_node = NULL;
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		rz_agraph_free(g);
		return -1;
	}
	RzHeapChunk cnk;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (!g) {
		rz_agraph_free(g);
		return -1;
	}
	g->can->color = rz_config_get_i(core->config, "scr.color");

	if (!rz_glibc_read_chunk(core->io, bin, &cnk, &config)) {
		rz_agraph_free(g);
		return -1;
	}
	snprintf(title, sizeof(title) - 1, "bin @ 0x%" PFMT64x "\n", (ut64)bin);
	snprintf(chunk, sizeof(chunk) - 1, "fd: 0x%" PFMT64x "\nbk: 0x%" PFMT64x "\n",
		(ut64)cnk.fd, (ut64)cnk.bk);
	bin_node = rz_agraph_add_node(g, title, chunk);
	prev_node = bin_node;

	while (cnk.bk != bin) {
		next = cnk.bk;
		if (next < brk_start || next > main_arena->top) {
			PRINT_RA("Double linked list corrupted\n");
			rz_agraph_free(g);
			return -1;
		}

		if (!rz_glibc_read_chunk(core->io, next, &cnk, &config)) {
			rz_agraph_free(g);
			return -1;
		}
		snprintf(title, sizeof(title) - 1, "Chunk @ 0x%" PFMT64x "\n", (ut64)next);
		snprintf(chunk, sizeof(chunk) - 1, "fd: 0x%" PFMT64x "\nbk: 0x%" PFMT64x "\n",
			(ut64)cnk.fd, (ut64)cnk.bk);
		next_node = rz_agraph_add_node(g, title, chunk);
		rz_agraph_add_edge(g, prev_node, next_node);
		rz_agraph_add_edge(g, next_node, prev_node);
		prev_node = next_node;
	}

	rz_agraph_add_edge(g, prev_node, bin_node);
	rz_agraph_add_edge(g, bin_node, prev_node);
	rz_agraph_print(g);

	rz_agraph_free(g);
	return 0;
}

static int print_double_linked_list_bin(RzCore *core, MallocState *main_arena, ut64 m_arena, ut64 offset, ut64 num_bin, int graph) {
	if (!core || !core->dbg || !core->dbg->maps) {
		return -1;
	}
	int ret = 0;
	ut64 brk_start = UT64_MAX, brk_end = UT64_MAX, initial_brk = UT64_MAX;
	const ut8 ptr_size = rz_heap_ptr_size(core);
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (num_bin > 126) {
		return -1;
	}
	ut64 bin = main_arena->bins[num_bin];

	if (!bin) {
		return -1;
	}

	rz_heap_get_brks(core, &brk_start, &brk_end);
	if (brk_start == UT64_MAX || brk_end == UT64_MAX) {
		RZ_LOG_ERROR("core: no heap section\n");
		return -1;
	}

	const int tcache = rz_config_get_i(core->config, "dbg.glibc.tcache");
	if (tcache) {
		const int fc_offset = rz_config_get_i(core->config, "dbg.glibc.fc_offset");
		bin = m_arena + offset + ptr_size * num_bin * 2 + 10 * ptr_size;
		initial_brk = ((brk_start >> 12) << 12) + fc_offset;
	} else {
		bin = m_arena + offset + ptr_size * num_bin * 2 - ptr_size * 2;
		initial_brk = (brk_start >> 12) << 12;
	}

	if (num_bin == 0) {
		PRINT_GA("  double linked list unsorted bin {\n");
	} else if (num_bin >= 1 && num_bin <= RZ_GLIBC_NSMALLBINS - 1) {
		PRINT_GA("  double linked list small bin {\n");
	} else if (num_bin >= RZ_GLIBC_NSMALLBINS && num_bin <= RZ_GLIBC_NBINS - 2) {
		PRINT_GA("  double linked list large bin {\n");
	}

	if (!graph || graph == 1) {
		ret = print_double_linked_list_bin_simple(core, bin, main_arena, initial_brk);
	} else {
		ret = print_double_linked_list_bin_graph(core, bin, main_arena, initial_brk);
	}
	PRINT_GA("\n  }\n");
	return ret;
}

static void print_heap_bin(RzCore *core, ut64 m_arena, MallocState *main_arena, const char *input, bool print_graph, const RzHeapConfig *config) {
	ut64 num_bin = UT64_MAX;
	ut64 offset;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	const ut8 ptr_size = config ? config->ptr_size : rz_heap_ptr_size(core);

	const int tcache = rz_config_get_i(core->config, "dbg.glibc.tcache");
	if (tcache) {
		offset = 16;
	} else {
		offset = 12 * ptr_size + sizeof(int) * 2;
	}

	if (!input[0]) {
		PRINT_YA("Bins {\n");
		for (size_t i = 0; i < RZ_GLIBC_NBINS - 1; i++) {
			PRINTF_YA(" Bin %03" PFMTSZu ":\n", i);
			print_double_linked_list_bin(core, main_arena, m_arena, offset, i, print_graph);
		}
		PRINT_YA("\n}\n");
	} else {
		num_bin = rz_num_get(NULL, input);
		if (num_bin > RZ_GLIBC_NBINS - 2) {
			RZ_LOG_ERROR("The number of bins is greater than %d\n", RZ_GLIBC_NBINS - 2);
			return;
		}
		PRINTF_YA("  Bin %03" PFMT64u ":\n", (ut64)num_bin);
		print_double_linked_list_bin(core, main_arena, m_arena, offset, num_bin, print_graph);
	}
	return;
}

void rz_heap_chunk_free(RzHeapChunkListItem *item) {
	if (!item) {
		return;
	}
	free(item->status);
	free(item);
}

RZ_API RzHeapBin *rz_heap_fastbin_content(RzCore *core, MallocState *arena, int bin_num) {
	rz_return_val_if_fail(core && arena, NULL);
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return NULL;
	}
	return rz_heap_fastbin_content_internal(core, arena, bin_num, &config);
}

RzHeapBin *rz_heap_fastbin_content_internal(RzCore *core, MallocState *arena, int bin_num, const RzHeapConfig *config) {
	rz_return_val_if_fail(core && core->dbg && core->dbg->maps && arena && config, NULL);

	ut64 brk_start = UT64_MAX, brk_end = UT64_MAX;
	RzHeapBin *heap_bin = RZ_NEW0(RzHeapBin);
	RzHeapChunk cnk;
	if (!heap_bin) {
		return NULL;
	}
	heap_bin->chunks = rz_list_newf((RzListFree)rz_heap_chunk_free);
	heap_bin->bin_num = bin_num + 1;
	heap_bin->size = rz_heap_fastbin_idx_to_size(bin_num + 1, config->ptr_size);
	heap_bin->type = rz_str_dup("Fast");

	ut64 next = arena->fastbinsY[bin_num];
	if (!next) {
		return heap_bin;
	}

	rz_heap_get_brks(core, &brk_start, &brk_end);
	heap_bin->fd = next;
	if (brk_start == UT64_MAX || brk_end == UT64_MAX) {
		return heap_bin;
	}

	ut64 size = arena->top - brk_start;
	ut64 next_root = next, next_tmp = next, double_free = UT64_MAX;

	while (next && next >= brk_start && next < arena->top) {
		RzHeapChunkListItem *item = RZ_NEW0(RzHeapChunkListItem);
		if (!item) {
			break;
		}
		item->addr = next;
		item->status = rz_str_dup("free");
		rz_list_append(heap_bin->chunks, item);

		while (double_free == UT64_MAX && next_tmp && next_tmp >= brk_start && next_tmp <= arena->top) {
			if (!rz_glibc_read_chunk(core->io, next_tmp, &cnk, config)) {
				break;
			}
			next_tmp = rz_heap_get_next_pointer(core, next_tmp, cnk.fd, config);
			if (cnk.prev_size > size || rz_glibc_chunk_size(&cnk, config) > size) {
				break;
			}
			if (next_root == next_tmp) {
				double_free = next_root;
				break;
			}
		}

		if (!rz_glibc_read_chunk(core->io, next, &cnk, config)) {
			break;
		}
		next = rz_heap_get_next_pointer(core, next, cnk.fd, config);
		if (cnk.prev_size > size || rz_glibc_chunk_size(&cnk, config) > size) {
			char message[50];
			rz_snprintf(message, 50, "Linked list corrupted @ 0x%" PFMT64x, (ut64)next);
			heap_bin->message = rz_str_dup(message);
			return heap_bin;
		}

		next_root = next_tmp = next;
		if (double_free == next) {
			char message[50];
			rz_snprintf(message, 50, "Double free detected @ 0x%" PFMT64x, (ut64)next);
			heap_bin->message = rz_str_dup(message);
			return heap_bin;
		}
	}

	if (next && (next < brk_start || next >= arena->top)) {
		char message[50];
		rz_snprintf(message, 50, "Linked list corrupted @ 0x%" PFMT64x, (ut64)next);
		heap_bin->message = rz_str_dup(message);
	}
	return heap_bin;
}

void print_heap_fastbin(RzCore *core, ut64 m_arena, MallocState *main_arena, ut64 global_max_fast, const char *input, bool main_arena_only, PJ *pj, const RzHeapConfig *config) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	const ut8 ptr_size = config ? config->ptr_size : rz_heap_ptr_size(core);
	int fastbins_max = rz_config_get_i(core->config, "dbg.glibc.fastbinmax") - 1;
	int global_max_fast_idx = rz_heap_fastbin_index(global_max_fast, ptr_size);
	int fastbin_count = fastbins_max < global_max_fast_idx ? fastbins_max : global_max_fast_idx;
	int bin_to_print = 0;
	if (input[0]) {
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
		RzHeapBin *bin = rz_heap_fastbin_content_internal(core, main_arena, i, config);
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
				print_heap_chunk_simple(core, pos->addr, NULL, pj, config);
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
		rz_heap_bin_free(bin);
	}
}

/**
 * \brief Get a list of bins for the tcache associated with arena with base address arena_base
 * \param core RzCore pointer
 * \param arena_base Base address of the arena
 * \return RzList of RzHeapBin pointers
 */
RzList /*<RzHeapBin *>*/ *rz_heap_tcache_content_internal(RzCore *core, ut64 arena_base, const RzHeapConfig *config) {
	rz_return_val_if_fail(core && config, NULL);

	const int tc = rz_config_get_i(core->config, "dbg.glibc.tcache");
	if (!tc) {
		rz_cons_printf("No tcache present in this version of libc\n");
		return NULL;
	}
	if (!rz_glibc_has_tcache(config->glibc_version)) {
		return NULL;
	}

	ut64 m_arena;
	if (!rz_heap_resolve_main_arena(core, &m_arena)) {
		return NULL;
	}

	ut64 brk_start = UT64_MAX, brk_end = UT64_MAX;
	rz_heap_get_brks(core, &brk_start, &brk_end);
	if (brk_start == UT64_MAX || brk_end == UT64_MAX) {
		return NULL;
	}

	ut64 tcache_start;
	if (arena_base == m_arena) {
		tcache_start = brk_start + 0x10;
	} else {
		ut64 mmap_start = ((arena_base >> 16) << 16);
		ut64 mmap_align = config->mmap_align;
		tcache_start = mmap_start + config->heap_info.struct_size + config->malloc_state.struct_size + mmap_align;

		MallocState arena_storage = { 0 };
		MallocState *arena = &arena_storage;
		if (!rz_heap_update_main_arena_internal(core, arena_base, arena, config) || !arena->attached_threads) {
			return NULL;
		}
	}

	RzHeapTcache tcache;
	if (!rz_glibc_read_tcache(core->io, tcache_start, &tcache, config)) {
		return NULL;
	}

	RzList *tcache_bins_list = rz_list_newf((RzListFree)rz_heap_bin_free);
	if (!tcache_bins_list) {
		return NULL;
	}

	for (ut32 i = 0; i < config->tcache.num_bins; i++) {
		ut16 count = tcache.counts[i];
		ut64 entry = tcache.entries[i];

		RzHeapBin *bin = RZ_NEW0(RzHeapBin);
		if (!bin) {
			goto error;
		}
		bin->type = rz_str_dup("Tcache");
		bin->bin_num = i;
		bin->chunks = rz_list_newf((RzListFree)rz_heap_chunk_free);
		if (!bin->chunks) {
			rz_heap_bin_free(bin);
			goto error;
		}
		rz_list_append(tcache_bins_list, bin);

		if (count <= 0) {
			continue;
		}
		if (!entry) {
			continue;
		}
		bin->fd = rz_glibc_mem_to_chunk(entry, config);

		RzHeapChunkListItem *chunk = RZ_NEW0(RzHeapChunkListItem);
		if (!chunk) {
			goto error;
		}
		chunk->addr = rz_glibc_mem_to_chunk(entry, config);
		rz_list_append(bin->chunks, chunk);

		if (count <= 1) {
			continue;
		}

		ut64 tcache_fd = entry;
		for (size_t n = 1; n < count; n++) {
			RzHeapTcacheEntry tentry;
			if (!rz_glibc_read_tcache_entry(core->io, tcache_fd, &tentry, config)) {
				goto error;
			}
			ut64 next = rz_glibc_tcache_next(&tentry, tcache_fd, config);
			if (!next) {
				break;
			}
			chunk = RZ_NEW0(RzHeapChunkListItem);
			if (!chunk) {
				goto error;
			}
			chunk->addr = rz_glibc_mem_to_chunk(next, config);
			rz_list_append(bin->chunks, chunk);
			tcache_fd = next;
		}
	}

	return tcache_bins_list;

error:
	rz_list_free(tcache_bins_list);
	return NULL;
}

RZ_API RzList /*<RzHeapBin *>*/ *rz_heap_tcache_content(RzCore *core, ut64 arena_base) {
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return NULL;
	}
	return rz_heap_tcache_content_internal(core, arena_base, &config);
}

static void print_tcache_content(RzCore *core, ut64 arena_base, ut64 main_arena_base, PJ *pj, const RzHeapConfig *config) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	RzList *bins = rz_heap_tcache_content_internal(core, arena_base, config);
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
	print_tcache(core, bins, pj, 0, config);
}

void print_inst_minfo(RzCore *core, const RzHeapHeapInfo *heap_info, ut64 hinfo) {
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

void print_malloc_info(RzCore *core, ut64 m_state, ut64 malloc_state, const RzHeapConfig *config) {
	ut64 h_info;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	if (malloc_state == m_state) {
		PRINT_RA("main_arena does not have an instance of malloc_info\n");
	} else if (rz_heap_is_arena(core, malloc_state, m_state, config)) {

		h_info = (malloc_state >> 16) << 16;
		RzHeapHeapInfo heap_info;
		if (!rz_glibc_read_heap_info(core->io, h_info, &heap_info, config)) {
			return;
		}
		print_inst_minfo(core, &heap_info, h_info);
		MallocState ms_storage = { 0 };
		MallocState *ms = &ms_storage;

		while (heap_info.prev != 0x0 && heap_info.prev != UT64_MAX) {
			if (!rz_heap_update_main_arena_internal(core, malloc_state, ms, config)) {
				return;
			}
			if ((ms->top >> 16) << 16 != h_info) {
				h_info = (ms->top >> 16) << 16;
				if (!rz_glibc_read_heap_info(core->io, h_info, &heap_info, config)) {
					return;
				}
				print_inst_minfo(core, &heap_info, h_info);
			}
		}
	} else {
		PRINT_RA("This address is not part of the arenas\n");
	}
}

static char *rz_heap_bin_num_to_type(int bin_num) {
	if (bin_num == 0) {
		return rz_str_dup("Unsorted");
	} else if (bin_num >= 1 && bin_num <= RZ_GLIBC_NSMALLBINS - 1) {
		return rz_str_dup("Small");
	} else if (bin_num >= RZ_GLIBC_NSMALLBINS && bin_num <= RZ_GLIBC_NBINS - 2) {
		return rz_str_dup("Large");
	}
	return NULL;
}

RZ_API void rz_heap_bin_free(RzHeapBin *bin) {
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
RzHeapBin *rz_heap_bin_content_internal(RzCore *core, MallocState *arena, int bin_num, ut64 m_arena, const RzHeapConfig *config) {
	rz_return_val_if_fail(core && arena && config, NULL);
	const ut8 ptr_size = config->ptr_size;

	int idx = 2 * bin_num;
	ut64 fw = arena->bins[idx];
	ut64 bk = arena->bins[idx + 1];

	RzHeapBin *bin = RZ_NEW0(RzHeapBin);
	if (!bin) {
		return NULL;
	}
	bin->fd = fw;
	bin->bk = bk;
	bin->bin_num = bin_num;
	bin->type = rz_heap_bin_num_to_type(bin_num);

	if (bin->type && !strcmp(bin->type, "Small")) {
		bin->size = 4 * ptr_size + (bin_num - 1) * 2 * ptr_size;
	}

	bin->chunks = rz_list_newf((RzListFree)rz_heap_chunk_free);

	RzHeapChunk head;
	if (!rz_glibc_read_chunk(core->io, bk, &head, config)) {
		return bin;
	}
	if (head.fd == fw) {
		return bin;
	}

	ut64 brk_start = UT64_MAX, brk_end = UT64_MAX, initial_brk = UT64_MAX;
	rz_heap_get_brks(core, &brk_start, &brk_end);
	if (brk_start == UT64_MAX || brk_end == UT64_MAX) {
		return bin;
	}

	const int tcache = rz_config_get_i(core->config, "dbg.glibc.tcache");
	int offset;
	ut64 base;
	if (tcache) {
		offset = 16;
		const int fc_offset = rz_config_get_i(core->config, "dbg.glibc.fc_offset");
		base = m_arena + offset + ptr_size * (ut64)bin_num * 2 + 10 * ptr_size;
		initial_brk = ((brk_start >> 12) << 12) + fc_offset;
	} else {
		offset = 12 * ptr_size + sizeof(int) * 2;
		base = m_arena + offset + ptr_size * (ut64)bin_num * 2 - ptr_size * 2;
		initial_brk = (brk_start >> 12) << 12;
	}
	bin->addr = base;

	RzHeapChunk cnk;
	while (fw != head.fd) {
		if (fw > arena->top || fw < initial_brk) {
			bin->message = rz_str_dup("Corrupted list");
			break;
		}
		if (!rz_glibc_read_chunk(core->io, fw, &cnk, config)) {
			bin->message = rz_str_dup("Corrupted list");
			break;
		}
		RzHeapChunkListItem *chunk = RZ_NEW0(RzHeapChunkListItem);
		if (!chunk) {
			break;
		}
		chunk->addr = fw;
		rz_list_append(bin->chunks, chunk);
		fw = cnk.fd;
	}
	return bin;
}

RZ_API RzHeapBin *rz_heap_bin_content(RzCore *core, MallocState *arena, int bin_num, ut64 m_arena) {
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return NULL;
	}
	return rz_heap_bin_content_internal(core, arena, bin_num, m_arena, &config);
}

/**
 * \brief Prints the heap chunks in a bin with double linked list (small|large|unsorted)
 * \param core RzCore pointer
 * \param main_arena MallocState struct for the arena in which bins are
 * \param bin_num The bin number for the bin from which chunks have to printed
 * \return number of chunks found in the bin
 */
static int print_bin_content(RzCore *core, MallocState *main_arena, int bin_num, PJ *pj, ut64 m_arena, const RzHeapConfig *config) {
	RzListIter *iter;
	RzHeapChunkListItem *pos;
	RzHeapBin *bin = rz_heap_bin_content_internal(core, main_arena, bin_num, m_arena, config);
	RzList *chunks = bin->chunks;
	if (rz_list_length(chunks) == 0) {
		rz_heap_bin_free(bin);
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
		print_heap_chunk_simple(core, pos->addr, NULL, pj, config);
		if (!pj) {
			rz_cons_newline();
		}
		chunks_cnt += 1;
	}
	if (bin->message) {
		PRINTF_RA("%s\n", bin->message);
	}
	rz_heap_bin_free(bin);
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
static void print_unsortedbin_description(RzCore *core, ut64 m_arena, MallocState *main_arena, PJ *pj, const RzHeapConfig *config) {
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
	int chunk_cnt = print_bin_content(core, main_arena, 0, pj, m_arena, config);
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
static void print_smallbin_description(RzCore *core, ut64 m_arena, MallocState *main_arena, PJ *pj, const RzHeapConfig *config) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	if (!pj) {
		rz_cons_printf("Small bins in Arena @ ");
		PRINTF_YA("0x%" PFMT64x "\n", (ut64)m_arena);
	}
	int chunk_cnt = 0;
	int non_empty_cnt = 0;
	for (int bin_num = 1; bin_num < RZ_GLIBC_NSMALLBINS; bin_num++) {
		if (pj) {
			pj_o(pj);
			pj_kn(pj, "bin_num", bin_num);
			pj_ks(pj, "bin_type", "small");
		}
		int chunk_found = print_bin_content(core, main_arena, bin_num, pj, m_arena, config);
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
static void print_largebin_description(RzCore *core, ut64 m_arena, MallocState *main_arena, PJ *pj, const RzHeapConfig *config) {
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	if (!pj) {
		rz_cons_printf("Large bins in Arena @ ");
		PRINTF_YA("0x%" PFMT64x "\n", (ut64)m_arena);
	}
	int chunk_cnt = 0;
	int non_empty_cnt = 0;
	for (int bin_num = RZ_GLIBC_NSMALLBINS; bin_num < RZ_GLIBC_NBINS - 2; bin_num++) {
		if (pj) {
			pj_o(pj);
			pj_kn(pj, "bin_num", bin_num);
			pj_ks(pj, "bin_type", "large");
		}
		int chunk_found = print_bin_content(core, main_arena, bin_num, pj, m_arena, config);
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
static void print_main_arena_bins(RzCore *core, ut64 m_arena, MallocState *main_arena, ut64 main_arena_base, ut64 global_max_fast, RzHeapBinType format, bool json, const RzHeapConfig *config) {
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
		print_tcache_content(core, m_arena, main_arena_base, pj, config);
		rz_cons_newline();
	}
	if (format == RZ_HEAP_BIN_ANY || format == RZ_HEAP_BIN_FAST) {
		char *input = rz_str_newlen("", 1);
		bool main_arena_only = true;
		print_heap_fastbin(core, m_arena, main_arena, global_max_fast, input, main_arena_only, pj, config);
		free(input);
		rz_cons_newline();
	}
	if (format == RZ_HEAP_BIN_ANY || format == RZ_HEAP_BIN_UNSORTED) {
		print_unsortedbin_description(core, m_arena, main_arena, pj, config);
		rz_cons_newline();
	}
	if (format == RZ_HEAP_BIN_ANY || format == RZ_HEAP_BIN_SMALL) {
		print_smallbin_description(core, m_arena, main_arena, pj, config);
		rz_cons_newline();
	}
	if (format == RZ_HEAP_BIN_ANY || format == RZ_HEAP_BIN_LARGE) {
		print_largebin_description(core, m_arena, main_arena, pj, config);
		rz_cons_newline();
	}
	if (json) {
		pj_end(pj);
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

void rz_arena_list_free(RzArenaListItem *item) {
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
RzList /*<RzArenaListItem *>*/ *rz_heap_arenas_list_internal(RzCore *core, ut64 m_arena, MallocState *main_arena, const RzHeapConfig *config) {
	RzList *arena_list = rz_list_newf((RzListFree)rz_arena_list_free);
	if (!config) {
		return arena_list;
	}
	MallocState *ta = RZ_NEW0(MallocState);
	if (!ta) {
		return arena_list;
	}
	// main arena
	if (!rz_heap_update_main_arena_internal(core, m_arena, ta, config)) {
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
		while (rz_heap_is_arena(core, m_arena, ta->next, config) && ta->next != m_arena) {
			ut64 ta_addr = ta->next;
			ta = RZ_NEW0(MallocState);
			if (!rz_heap_update_main_arena_internal(core, ta_addr, ta, config)) {
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
RzList /*<RzHeapChunkListItem *>*/ *rz_heap_chunks_list_internal(RzCore *core, MallocState *main_arena,
	ut64 m_arena, ut64 m_state, bool top_chunk, const RzHeapConfig *config) {
	RzList *chunks = rz_list_newf((RzListFree)rz_heap_chunk_free);
	if (!core || !core->dbg || !core->dbg->maps) {
		return chunks;
	}
	if (!config) {
		return chunks;
	}
	const ut8 ptr_size = config->ptr_size;
	ut64 global_max_fast = (64 * ptr_size / 4);
	ut64 brk_start = UT64_MAX, brk_end = UT64_MAX, size_tmp, min_size = config->min_chunk_size;
	ut64 tcache_fd = UT64_MAX, tcache_tmp = UT64_MAX;
	ut64 initial_brk = UT64_MAX, tcache_initial_brk = UT64_MAX;

	const int tcache = rz_config_get_i(core->config, "dbg.glibc.tcache");
	const int offset = rz_config_get_i(core->config, "dbg.glibc.fc_offset");
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;

	if (m_arena == m_state) {
		rz_heap_get_brks(core, &brk_start, &brk_end);
		if (tcache) {
			initial_brk = ((brk_start >> 12) << 12) + config->chunk_hdr_size;
			if (rz_config_get_b(core->config, "cfg.debug")) {
				tcache_initial_brk = initial_brk;
			}
			initial_brk += config->tcache.struct_size;
		} else {
			initial_brk = (brk_start >> 12) << 12;
		}
	} else {
		brk_start = ((m_state >> 16) << 16);
		brk_end = brk_start + main_arena->system_mem;
		if (tcache) {
			ut64 mmap_align = config->mmap_align;
			tcache_initial_brk = brk_start + config->heap_info.struct_size + config->malloc_state.struct_size + mmap_align;
			initial_brk = tcache_initial_brk + offset;
		} else {
			initial_brk = brk_start + config->heap_info.struct_size + config->malloc_state.struct_size + config->mmap_offset;
		}
	}

	if (brk_start == UT64_MAX || brk_end == UT64_MAX || initial_brk == UT64_MAX) {
		RZ_LOG_ERROR("core: no heap section\n");
		return chunks;
	}

	ut64 next_chunk = initial_brk, prev_chunk = next_chunk;
	RzHeapChunk cnk;
	RzHeapChunk cnk_next;
	ut64 size_raw = 0;
	ut64 prev_size = 0;

	if (!rz_glibc_read_chunk(core->io, next_chunk, &cnk, config)) {
		return chunks;
	}
	size_tmp = rz_glibc_chunk_size(&cnk, config);
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
		prev_chunk_size = size_tmp;
		bool fastbin = size_tmp >= ptr_size * 4 && size_tmp <= global_max_fast;
		bool is_free = false, double_free = false;

		if (fastbin) {
			int i = (size_tmp / (ptr_size * 2)) - 2;
			ut64 idx = (ut64)main_arena->fastbinsY[i];
			if (!rz_glibc_read_chunk(core->io, idx, &cnk, config)) {
				continue;
			}
			ut64 next = rz_heap_get_next_pointer(core, idx, cnk.fd, config);
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
					if (!rz_glibc_read_chunk(core->io, next, &cnk_next, config)) {
						continue;
					}
					ut64 next_node = rz_heap_get_next_pointer(core, next, cnk_next.fd, config);
					// avoid triple while?
					while (next_node && next_node >= brk_start && next_node < main_arena->top) {
						if (prev_chunk == next_node) {
							double_free = true;
							break;
						}
						if (!rz_glibc_read_chunk(core->io, next_node, &cnk_next, config)) {
							continue;
						}
						next_node = rz_heap_get_next_pointer(core, next_node, cnk_next.fd, config);
					}
					if (double_free) {
						break;
					}
				}
				if (!rz_glibc_read_chunk(core->io, next, &cnk, config)) {
					continue;
				}
				next = rz_heap_get_next_pointer(core, next, cnk.fd, config);
			}
			if (double_free) {
				PRINT_RA(" Double free in simple-linked list detected ");
				break;
			}
			prev_chunk_size = ((i + 1) * config->chunk_hdr_size) + config->chunk_hdr_size;
		}

		if (!tcache) {
			goto skip_tcache;
		}
		RzHeapTcache tcache_heap;
		if (!rz_glibc_read_tcache(core->io, tcache_initial_brk, &tcache_heap, config)) {
			goto skip_tcache;
		}
		for (ut32 i = 0; i < config->tcache.num_bins; i++) {
			ut16 count = tcache_heap.counts[i];
			ut64 entry = tcache_heap.entries[i];
			if (count == 0) {
				continue;
			}
			if (rz_glibc_mem_to_chunk(entry, config) == prev_chunk) {
				is_free = true;
				prev_chunk_size = ((i + 1) * config->tcache_hdr_size) + config->tcache_chunk_extra;
				break;
			}
			tcache_fd = entry;
			for (ut16 n = 1; n < count; n++) {
				RzHeapTcacheEntry tentry;
				if (!rz_glibc_read_tcache_entry(core->io, tcache_fd, &tentry, config)) {
					break;
				}
				tcache_tmp = rz_glibc_tcache_next(&tentry, tcache_fd, config);
				if (!tcache_tmp) {
					continue;
				}
				if (rz_glibc_mem_to_chunk(tcache_tmp, config) == prev_chunk) {
					is_free = true;
					prev_chunk_size = ((i + 1) * config->tcache_hdr_size) + config->tcache_chunk_extra;
					break;
				}
				tcache_fd = (ut64)tcache_tmp;
			}
		}
	skip_tcache:

		next_chunk += size_tmp;
		prev_chunk = next_chunk;
		if (!rz_glibc_read_chunk(core->io, next_chunk, &cnk, config)) {
			if (next_chunk == main_arena->top) {
				cnk.size = 0;
				size_tmp = 0;
			} else if (rz_glibc_read_chunk_header(core->io, next_chunk, &prev_size, &size_raw, config)) {
				cnk.size = size_raw;
				RzHeapChunk tmp_next = { .size = size_raw };
				size_tmp = rz_glibc_chunk_size(&tmp_next, config);
			} else {
				break;
			}
		}
		if (size_tmp != 0) {
			size_tmp = rz_glibc_chunk_size(&cnk, config);
		}
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
		if (!(cnk.size & 1)) {
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
			RzHeapChunkSimple *chunkSimple = rz_heap_chunk_internal(core, main_arena->top, config);
			if (chunkSimple) {
				block->size = chunkSimple->size;
				free(chunkSimple);
			}
			rz_list_append(chunks, block);
		}
	}
	return chunks;
}

RZ_IPI RzCmdStatus rz_cmd_arena_print_handler(RzCore *core, int argc, const char **argv) {
	ut64 m_arena = UT64_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return RZ_CMD_STATUS_ERROR;
	}
	MallocState main_arena_storage = { 0 };
	MallocState *main_arena = &main_arena_storage;
	if (!rz_heap_resolve_main_arena(core, &m_arena)) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_heap_update_main_arena_internal(core, m_arena, main_arena, &config)) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzList *arenas_list = rz_heap_arenas_list_internal(core, m_arena, main_arena, &config);
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
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_heap_chunks_print_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut64 m_arena = UT64_MAX, m_state = UT64_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	MallocState main_arena_storage = { 0 };
	MallocState *main_arena = &main_arena_storage;
	RzOutputMode mode = state->mode;
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return RZ_CMD_STATUS_ERROR;
	}
	const ut8 ptr_size = config.ptr_size;
	if (!rz_heap_resolve_main_arena(core, &m_arena)) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc == 1) {
		m_state = m_arena;
	} else if (argc == 2) {
		m_state = rz_num_get(NULL, argv[1]);
	}
	if (!rz_heap_is_arena(core, m_arena, m_state, &config)) {
		PRINT_RA("This address is not a valid arena\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_heap_update_main_arena_internal(core, m_state, main_arena, &config)) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 brk_start = 0, brk_end = 0;
	if (m_arena == m_state) {
		rz_heap_get_brks(core, &brk_start, &brk_end);

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
		return RZ_CMD_STATUS_ERROR;
	}
	w = rz_cons_get_size(&h);
	RzConsCanvas *can = rz_cons_canvas_new(w, h);
	if (!can) {
		rz_config_hold_free(hc);
		return RZ_CMD_STATUS_ERROR;
	}

	RzAGraph *g = rz_agraph_new(can);
	if (!g) {
		rz_cons_canvas_free(can);
		rz_config_hold_restore(hc);
		rz_config_hold_free(hc);
		return RZ_CMD_STATUS_ERROR;
	}
	RzANode *top = RZ_EMPTY, *chunk_node = RZ_EMPTY, *prev_node = RZ_EMPTY;
	char *top_title = NULL, *top_data = NULL, *node_title = NULL, *node_data = NULL;
	bool first_node = true;
	top_data = rz_str_dup("");
	RzList *chunks = rz_heap_chunks_list_internal(core, main_arena, m_arena, m_state, false, &config);
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
			print_heap_chunk_simple(core, pos->addr, pos->status, NULL, &config);
			rz_cons_newline();
			if (mode == RZ_OUTPUT_MODE_LONG) {
				int size = 0x10;
				char *data = calloc(1, size);
				if (data) {
					rz_io_nread_at(core->io, (ut64)(pos->addr + ptr_size * 2), (ut8 *)data, size);
					core->print->flags &= ~RZ_PRINT_FLAGS_HEADER;
					core->print->pairs = false;
					rz_cons_printf("   ");
					rz_core_print_hexdump(core, (ut64)(pos->addr + ptr_size * 2), (ut8 *)data, size, ptr_size * 2, 1, 1);
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
		print_heap_chunk_simple(core, main_arena->top, "free", NULL, &config);
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
	rz_cons_canvas_free(can);
	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_main_arena_print_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	ut64 m_arena = UT64_MAX, m_state = UT64_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return RZ_CMD_STATUS_ERROR;
	}
	const ut8 ptr_size = config.ptr_size;
	ut64 global_max_fast = (64 * ptr_size / 4);
	MallocState main_arena_storage = { 0 };
	MallocState *main_arena = &main_arena_storage;
	if (!rz_heap_resolve_main_arena(core, &m_arena)) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc == 1) {
		m_state = m_arena;
	} else if (argc == 2) {
		m_state = rz_num_get(NULL, argv[1]);
	}
	if (!rz_heap_is_arena(core, m_arena, m_state, &config)) {
		PRINT_RA("This address is not a valid arena\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_heap_update_main_arena_internal(core, m_state, main_arena, &config)) {
		return RZ_CMD_STATUS_ERROR;
	}
	print_arena_stats(core, m_state, main_arena, global_max_fast, mode, &config);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_heap_chunk_print_handler(RzCore *core, int argc, const char **argv) {
	ut64 m_arena = UT64_MAX;
	if (!rz_heap_resolve_main_arena(core, &m_arena)) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 addr = core->offset;
	print_heap_chunk(core, addr, &config);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_heap_info_print_handler(RzCore *core, int argc, const char **argv) {
	ut64 m_arena = UT64_MAX, m_state = UT64_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return RZ_CMD_STATUS_ERROR;
	}
	MallocState main_arena_storage = { 0 };
	MallocState *main_arena = &main_arena_storage;
	if (!rz_heap_resolve_main_arena(core, &m_arena)) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc == 1) {
		m_state = m_arena;
	} else if (argc == 2) {
		m_state = rz_num_get(NULL, argv[1]);
	}
	if (!rz_heap_is_arena(core, m_arena, m_state, &config)) {
		PRINT_RA("This address is not a valid arena\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_heap_update_main_arena_internal(core, m_state, main_arena, &config)) {
		return RZ_CMD_STATUS_ERROR;
	}
	print_malloc_info(core, m_arena, m_state, &config);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_heap_tcache_print_handler(RzCore *core, int argc, const char **argv) {
	ut64 m_arena = UT64_MAX;
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (!rz_heap_resolve_main_arena(core, &m_arena)) {
		return RZ_CMD_STATUS_ERROR;
	}

	const int tc = rz_config_get_i(core->config, "dbg.glibc.tcache");
	if (!tc) {
		rz_cons_printf("No tcache present in this version of libc\n");
		return RZ_CMD_STATUS_ERROR;
	}

	if (!resolve_heap_tcache(core, m_arena, &config)) {
		return RZ_CMD_STATUS_ERROR;
	}

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_heap_bins_list_print_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	const char *input = (argc == 1) ? "" : argv[1];
	ut64 m_arena = UT64_MAX, m_state = UT64_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return RZ_CMD_STATUS_ERROR;
	}
	MallocState main_arena_storage = { 0 };
	MallocState *main_arena = &main_arena_storage;
	if (!rz_heap_resolve_main_arena(core, &m_arena)) {
		return RZ_CMD_STATUS_ERROR;
	}
	char *m_state_str, *dup = rz_str_dup(input);
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
	if (rz_heap_is_arena(core, m_arena, m_state, &config)) {
		if (!rz_heap_update_main_arena_internal(core, m_state, main_arena, &config)) {
			free(dup);
			return RZ_CMD_STATUS_ERROR;
		}
		print_heap_bin(core, m_state, main_arena, dup, mode == RZ_OUTPUT_MODE_GRAPH, &config);
	} else {
		PRINT_RA("This address is not part of the arenas\n");
		free(dup);
		return RZ_CMD_STATUS_ERROR;
	}
	free(dup);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_heap_fastbins_print_handler(RzCore *core, int argc, const char **argv) {
	const char *input = (argc == 1) ? "" : argv[1];
	ut64 m_arena = UT64_MAX, m_state = UT64_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return RZ_CMD_STATUS_ERROR;
	}
	MallocState main_arena_storage = { 0 };
	MallocState *main_arena = &main_arena_storage;
	const ut8 ptr_size = config.ptr_size;
	ut64 global_max_fast = (64 * ptr_size / 4);
	if (!rz_heap_resolve_main_arena(core, &m_arena)) {
		return RZ_CMD_STATUS_ERROR;
	}
	bool main_arena_only = false;
	char *m_state_str, *dup = rz_str_dup(input);
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
	if (rz_heap_is_arena(core, m_arena, m_state, &config)) {
		if (!rz_heap_update_main_arena_internal(core, m_state, main_arena, &config)) {
			free(dup);
			return RZ_CMD_STATUS_ERROR;
		}
		print_heap_fastbin(core, m_state, main_arena, global_max_fast, dup, main_arena_only, NULL, &config);
	} else {
		PRINT_RA("This address is not part of the arenas\n");
		free(dup);
		return RZ_CMD_STATUS_ERROR;
	}
	free(dup);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_heap_arena_bins_print_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	ut64 m_arena = UT64_MAX, m_state = UT64_MAX;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return RZ_CMD_STATUS_ERROR;
	}
	const ut8 ptr_size = config.ptr_size;
	ut64 global_max_fast = (64 * ptr_size / 4);
	MallocState main_arena_storage = { 0 };
	MallocState *main_arena = &main_arena_storage;
	if (!rz_heap_resolve_main_arena(core, &m_arena)) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (core->offset != core->prompt_offset) {
		m_state = core->offset;
	} else {
		m_state = m_arena;
	}
	if (!rz_heap_is_arena(core, m_arena, m_state, &config)) {
		PRINT_RA("This address is not part of the arenas\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_heap_update_main_arena_internal(core, m_state, main_arena, &config)) {
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
	print_main_arena_bins(core, m_state, main_arena, m_arena, global_max_fast, bin_format, json, &config);
	return RZ_CMD_STATUS_OK;
}

/**
 * \brief A wrapper around GH(rz_heap_arenas_list) which handles finding main_arena
 * \param core RzCore pointer
 * \return RzList of RzArenaListItem
 */
RZ_API RzList /*<RzArenaListItem *>*/ *rz_heap_arenas_list(RzCore *core) {
	ut64 m_arena;
	if (!rz_heap_resolve_main_arena(core, &m_arena)) {
		return rz_list_newf(free);
	}
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return rz_list_newf(free);
	}
	MallocState main_arena_storage = { 0 };
	MallocState *main_arena = &main_arena_storage;
	if (!rz_heap_update_main_arena_internal(core, m_arena, main_arena, &config)) {
		return rz_list_newf(free);
	}
	RzList *arenas_list = rz_heap_arenas_list_internal(core, m_arena, main_arena, &config);
	return arenas_list;
}

/**
 * default version is 2.31
 */
static inline bool init_glibc_config(RzCore *core, RzHeapConfig *config) {
	ut8 ptr_size = rz_heap_ptr_size(core);
	int glibc_version = core->dbg->glibc_version;
	const char *version_cfg = rz_config_get(core->config, "dbg.glibc.version");
	if (version_cfg && strcmp(version_cfg, "auto") != 0) {
		double v = strtod(version_cfg, NULL);
		if (v >= 2.0 && v < 3.0) {
			glibc_version = (int)round(v * 100);
			core->dbg->glibc_version = glibc_version;
			core->dbg->is_glibc_resolved = true;
		}
	} else if (!core->dbg->is_glibc_resolved) {
		RzDebugMap *map = NULL;
		bool is_libc_map = false;
		if (rz_config_get_b(core->config, "cfg.debug")) {
			RzListIter *iter;
			rz_debug_map_sync(core->dbg);
			RzRegex *re = rz_regex_new(".*libc[.-]", RZ_REGEX_EXTENDED | RZ_REGEX_CASELESS, 0, NULL);
			rz_list_foreach (core->dbg->maps, iter, map) {
				if (map->name && core->bin && core->bin->file) {
					if (strncmp(map->name, core->bin->file, strlen(map->name)) == 0) {
						continue;
					}
				}
				if (map->name && strstr(map->name, "libc-")) {
					is_libc_map = true;
					break;
				}
				if (map->name) {
					RzRegexStatus ret_status = rz_regex_match(re, map->name, RZ_REGEX_ZERO_TERMINATED,
						0, RZ_REGEX_DEFAULT);
					if (ret_status > 0) {
						is_libc_map = true;
						break;
					}
				}
			}
			rz_regex_free(re);
		}
		if (map && is_libc_map) {
			double v = rz_get_glibc_version(core, map->file, NULL);
			if (v >= 2.0 && v < 3.0) {
				core->dbg->glibc_version = (int)round(v * 100);
				core->dbg->is_glibc_resolved = true;
				glibc_version = core->dbg->glibc_version;
			}
		}
	}
	if (glibc_version <= 0) {
		glibc_version = 231;
	}
	bool is_big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	rz_glibc_config_init(config, ptr_size, glibc_version, is_big_endian);
	return true;
}

/**
 * \brief A wrapper around GH(rz_heap_chunks_list) which handles finding the main arena
 * \param core RzCore pointer
 * \param m_arena Base Address of the arena
 * \return RzList of heap chunks as RzHeapChunkListItem structs
 */
RZ_API RzList /*<RzHeapChunkListItem *>*/ *rz_heap_chunks_list(RzCore *core, ut64 m_state) {
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return rz_list_newf(free);
	}
	ut64 m_arena;
	if (!rz_heap_resolve_main_arena(core, &m_arena)) {
		return rz_list_newf(free);
	}
	if (!rz_heap_is_arena(core, m_arena, m_state, &config)) {
		return rz_list_newf(free);
	}
	MallocState main_arena_storage = { 0 };
	MallocState *main_arena = &main_arena_storage;
	if (!rz_heap_update_main_arena_internal(core, m_state, main_arena, &config)) {
		return rz_list_newf(free);
	}
	RzList *chunks = rz_heap_chunks_list_internal(core, main_arena, m_arena, m_state, true, &config);
	return chunks;
}

/**
 * \brief Get info about a heap chunk as RzHeapChunkSimple
 * \param core RzCore pointer
 * \param addr Base address of the heap chunk
 * \return RzHeapChunkSimple struct pointer for the chunk
 */
RzHeapChunkSimple *rz_heap_chunk_internal(RzCore *core, ut64 addr, const RzHeapConfig *config) {
	rz_return_val_if_fail(core && config, NULL);
	RzHeapChunk *chunk = rz_heap_get_chunk_at_addr_internal(core, addr, config);
	if (!chunk) {
		return NULL;
	}
	RzHeapChunkSimple *chunk_simple = RZ_NEW0(RzHeapChunkSimple);
	if (!chunk_simple) {
		return NULL;
	}

	chunk_simple->addr = addr;
	chunk_simple->prev_size = chunk->prev_size;
	chunk_simple->size = rz_glibc_chunk_size(chunk, config);
	chunk_simple->prev_inuse = rz_glibc_chunk_prev_inuse(chunk);
	chunk_simple->is_mmapped = rz_glibc_chunk_is_mmapped(chunk);
	chunk_simple->non_main_arena = rz_glibc_chunk_non_main_arena(chunk);
	chunk_simple->fd = chunk->fd;
	chunk_simple->bk = chunk->bk;
	chunk_simple->fd_nextsize = chunk->fd_nextsize;
	chunk_simple->bk_nextsize = chunk->bk_nextsize;

	return chunk_simple;
}

RZ_API RzHeapChunkSimple *rz_heap_chunk(RzCore *core, ut64 addr) {
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return NULL;
	}
	return rz_heap_chunk_internal(core, addr, &config);
}

RZ_IPI RzCmdStatus rz_cmd_heap_chunks_graph_handler(RzCore *core, int argc, const char **argv) {
	// RZ_OUTPUT_MODE_LONG_JSON mode workaround for graph
	RzCmdStateOutput state = { 0 };
	if (!rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_LONG_JSON, core)) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzCmdStatus res = rz_cmd_heap_chunks_print_handler(core, argc, argv, &state);
	rz_cmd_state_output_print(&state);
	rz_cmd_state_output_fini(&state);
	return res;
}

/**
 * \brief Get MallocState struct for arena with given base address
 * if base address is 0 then return MallocState for main arena
 * \param core RzCore pointer
 * \param addr Base address of the arena
 * \return MallocState struct pointer for the arena
 */
RZ_API MallocState *rz_heap_get_arena(RzCore *core, ut64 m_state) {
	ut64 m_arena;
	if (!rz_heap_resolve_main_arena(core, &m_arena)) {
		return NULL;
	}
	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return NULL;
	}
	if (!m_state) {
		m_state = m_arena;
	}
	if (!rz_heap_is_arena(core, m_arena, m_state, &config)) {
		return NULL;
	}
	MallocState *main_arena = RZ_NEW0(MallocState);
	if (!main_arena) {
		return NULL;
	}
	if (!rz_heap_update_main_arena_internal(core, m_state, main_arena, &config)) {
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
RZ_API bool rz_heap_write_chunk(RzCore *core, RzHeapChunkSimple *chunk_simple) {
	rz_return_val_if_fail(core && chunk_simple, false);

	RzHeapConfig config;
	if (!init_glibc_config(core, &config)) {
		return false;
	}

	RzHeapChunk chunk = { 0 };
	chunk.prev_size = chunk_simple->prev_size;
	chunk.size = chunk_simple->size;
	if (chunk_simple->prev_inuse) {
		chunk.size |= RZ_GLIBC_PREV_INUSE;
	}
	if (chunk_simple->is_mmapped) {
		chunk.size |= RZ_GLIBC_IS_MMAPPED;
	}
	if (chunk_simple->non_main_arena) {
		chunk.size |= RZ_GLIBC_NON_MAIN_ARENA;
	}
	chunk.fd = chunk_simple->fd;
	chunk.bk = chunk_simple->bk;
	chunk.fd_nextsize = chunk_simple->fd_nextsize;
	chunk.bk_nextsize = chunk_simple->bk_nextsize;

	const ut32 struct_size = config.chunk.struct_size;
	ut8 *buf = RZ_NEWS0(ut8, struct_size);
	if (!buf) {
		return false;
	}

	const bool be = config.is_big_endian;
	const int ptr_bits = config.ptr_size * 8;
	rz_write_ble(buf + config.chunk.prev_size, chunk.prev_size, be, ptr_bits);
	rz_write_ble(buf + config.chunk.size, chunk.size, be, ptr_bits);
	rz_write_ble(buf + config.chunk.fd, chunk.fd, be, ptr_bits);
	rz_write_ble(buf + config.chunk.bk, chunk.bk, be, ptr_bits);
	rz_write_ble(buf + config.chunk.fd_nextsize, chunk.fd_nextsize, be, ptr_bits);
	rz_write_ble(buf + config.chunk.bk_nextsize, chunk.bk_nextsize, be, ptr_bits);

	bool res = rz_io_write_at(core->io, chunk_simple->addr, buf, struct_size);
	free(buf);
	return res;
}
