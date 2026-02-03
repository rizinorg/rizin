// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Helper program to extract jemalloc 4.5.0 configuration values.
 *
 * This program prints struct sizes and field offsets that are needed
 * for the RzJemallocConfig450 structure in Rizin's heap parser.
 *
 * Usage:
 *   1. Configure jemalloc for target: ./configure --host=<target> --with-lg-page=<N>
 *   2. Build jemalloc: make
 *   3. Build this tool (Meson):
 *      meson setup build -Djemalloc=/path/to/jemalloc -Djemalloc_version=4
 *      meson compile -C build
 *   4. Run: ./build/extract_config_450
 */

#include "jemalloc/internal/jemalloc_internal.h"

#include <stdio.h>
#include <stddef.h>

int main(void) {
	printf("// =============================================================================\n");
	printf("// jemalloc 4.5.0 configuration extracted from compiled source\n");
	printf("// =============================================================================\n");
	printf("//\n");
	printf("// Compile-time configuration:\n");
	printf("//   sizeof(void*) = %zu\n", sizeof(void *));
	printf("//   LG_PAGE = %d (page size = %zu bytes)\n", LG_PAGE, (size_t)1 << LG_PAGE);
	printf("//   NBINS = %d\n", NBINS);
	printf("//   NPSIZES = %d\n", NPSIZES);
#ifdef USE_TREE
	printf("//   USE_TREE = defined\n");
#else
	printf("//   USE_TREE = not defined\n");
#endif
	printf("//   BITMAP_MAXBITS = %zu\n", (size_t)BITMAP_MAXBITS);
	printf("//   LG_BITMAP_GROUP_NBITS = %d\n", LG_BITMAP_GROUP_NBITS);
#ifdef USE_TREE
	printf("//   BITMAP_MAX_LEVELS = %d\n", BITMAP_MAX_LEVELS);
#endif
	printf("//\n\n");

	// Determine architecture name
	const char *arch_name;
	const char *arch_enum;
	if (sizeof(void *) == 8) {
#if defined(__aarch64__)
		arch_name = "aarch64";
		arch_enum = "RZ_JEMALLOC_ARCH_AARCH64";
#elif defined(__riscv) && __riscv_xlen == 64
		arch_name = "riscv64";
		arch_enum = "RZ_JEMALLOC_ARCH_RISCV64";
#else
		arch_name = "amd64";
		arch_enum = "RZ_JEMALLOC_ARCH_AMD64";
#endif
	} else {
#if defined(__arm__)
		arch_name = "arm32";
		arch_enum = "RZ_JEMALLOC_ARCH_ARM32";
#elif defined(__riscv) && __riscv_xlen == 32
		arch_name = "riscv32";
		arch_enum = "RZ_JEMALLOC_ARCH_RISCV32";
#else
		arch_name = "i386";
		arch_enum = "RZ_JEMALLOC_ARCH_I386";
#endif
	}

	// OS name
	const char *os_name;
#if defined(__linux__)
	os_name = "linux";
#elif defined(__APPLE__)
	os_name = "darwin";
#elif defined(__FreeBSD__)
	os_name = "freebsd";
#elif defined(__OpenBSD__)
	os_name = "openbsd";
#elif defined(__NetBSD__)
	os_name = "netbsd";
#elif defined(_WIN32)
	os_name = "windows";
#else
	os_name = "unknown";
#endif

	// Page size suffix
	const char *page_suffix;
	switch (LG_PAGE) {
	case 12: page_suffix = "4k"; break;
	case 14: page_suffix = "16k"; break;
	case 16: page_suffix = "64k"; break;
	default: page_suffix = "unknown"; break;
	}

	printf("static const RzJemallocConfig450 rz_jemalloc_config_%s_%s_%s_450 = {\n",
		arch_name, os_name, page_suffix);
	printf("\t.arch = %s,\n", arch_enum);
	printf("\t.ptr_size = %zu,\n", sizeof(void *));
	printf("\t.is_big_endian = false,\n");
	printf("\t.lg_page = %d,\n", LG_PAGE);
	printf("\t.sc_nbins = %d,\n", NBINS);
	printf("\t.npsizes = %d,\n", NPSIZES);
#ifdef USE_TREE
	printf("\t.bitmap_use_tree = true,\n");
	printf("\t.bitmap_max_levels = %d,\n", BITMAP_MAX_LEVELS);
#else
	printf("\t.bitmap_use_tree = false,\n");
	printf("\t.bitmap_max_levels = 0,\n");
#endif
	printf("\t.extent_node_size = %zu,\n", sizeof(extent_node_t));
	printf("\t.bin_info_size = %zu,\n", sizeof(arena_bin_info_t));
	printf("\t.bin_size = %zu,\n", sizeof(arena_bin_t));
	printf("\t.arena_size = %zu,\n", sizeof(arena_t));
	printf("\t.bitmap_info_size = %zu,\n", sizeof(bitmap_info_t));
	printf("\t.malloc_mutex_size = %zu,\n", sizeof(malloc_mutex_t));

	// Arena offsets
	printf("\t.arena_offsets = {\n");
	printf("\t\t.lock = %zu,\n", offsetof(arena_t, lock));
	printf("\t\t.stats = %zu,\n", offsetof(arena_t, stats));
	printf("\t\t.tcache_ql = %zu,\n", offsetof(arena_t, tcache_ql));
	printf("\t\t.prof_accumbytes = %zu,\n", offsetof(arena_t, prof_accumbytes));
	printf("\t\t.achunks = %zu,\n", offsetof(arena_t, achunks));
	printf("\t\t.extent_sn_next = %zu,\n", offsetof(arena_t, extent_sn_next));
	printf("\t\t.lg_dirty_mult = %zu,\n", offsetof(arena_t, lg_dirty_mult));
	printf("\t\t.purging = %zu,\n", offsetof(arena_t, purging));
	printf("\t\t.nactive = %zu,\n", offsetof(arena_t, nactive));
	printf("\t\t.runs_dirty = %zu,\n", offsetof(arena_t, runs_dirty));
	printf("\t\t.chunks_cache = %zu,\n", offsetof(arena_t, chunks_cache));
	printf("\t\t.decay = %zu,\n", offsetof(arena_t, decay));
	printf("\t\t.huge = %zu,\n", offsetof(arena_t, huge));
	printf("\t\t.huge_mtx = %zu,\n", offsetof(arena_t, huge_mtx));
	printf("\t\t.chunks_szsnad_cached = %zu,\n", offsetof(arena_t, chunks_szsnad_cached));
	printf("\t\t.chunks_ad_cached = %zu,\n", offsetof(arena_t, chunks_ad_cached));
	printf("\t\t.chunks_mtx = %zu,\n", offsetof(arena_t, chunks_mtx));
	printf("\t\t.node_cache = %zu,\n", offsetof(arena_t, node_cache));
	printf("\t\t.node_cache_mtx = %zu,\n", offsetof(arena_t, node_cache_mtx));
	printf("\t\t.chunk_hooks = %zu,\n", offsetof(arena_t, chunk_hooks));
	printf("\t\t.bins = %zu,\n", offsetof(arena_t, bins));
	printf("\t\t.runs_avail = %zu,\n", offsetof(arena_t, runs_avail));
	printf("\t},\n");

	// Extent node offsets
	printf("\t.extent_node_offsets = {\n");
	printf("\t\t.ql_link_next = %zu,\n", offsetof(extent_node_t, ql_link));
	printf("\t},\n");

	// Bin info offsets
	printf("\t.bin_info_offsets = {\n");
	printf("\t\t.bitmap_info = %zu,\n", offsetof(arena_bin_info_t, bitmap_info));
	printf("\t\t.reg0_offset = %zu,\n", offsetof(arena_bin_info_t, reg0_offset));
	printf("\t},\n");

	printf("};\n");

	// Print additional useful information
	printf("\n// Additional struct information:\n");
	printf("// extent_node_t:\n");
	printf("//   en_arena offset: %zu\n", offsetof(extent_node_t, en_arena));
	printf("//   en_addr offset: %zu\n", offsetof(extent_node_t, en_addr));
	printf("//   en_size offset: %zu\n", offsetof(extent_node_t, en_size));
	printf("//   en_sn offset: %zu\n", offsetof(extent_node_t, en_sn));
	printf("//   ql_link offset: %zu\n", offsetof(extent_node_t, ql_link));
	printf("//   total size: %zu\n", sizeof(extent_node_t));

	printf("//\n// arena_bin_info_t:\n");
	printf("//   reg_size offset: %zu\n", offsetof(arena_bin_info_t, reg_size));
	printf("//   redzone_size offset: %zu\n", offsetof(arena_bin_info_t, redzone_size));
	printf("//   reg_interval offset: %zu\n", offsetof(arena_bin_info_t, reg_interval));
	printf("//   run_size offset: %zu\n", offsetof(arena_bin_info_t, run_size));
	printf("//   nregs offset: %zu\n", offsetof(arena_bin_info_t, nregs));
	printf("//   bitmap_info offset: %zu\n", offsetof(arena_bin_info_t, bitmap_info));
	printf("//   reg0_offset offset: %zu\n", offsetof(arena_bin_info_t, reg0_offset));
	printf("//   total size: %zu\n", sizeof(arena_bin_info_t));

	printf("//\n// bitmap_info_t:\n");
	printf("//   nbits offset: %zu\n", offsetof(bitmap_info_t, nbits));
#ifdef USE_TREE
	printf("//   nlevels offset: %zu\n", offsetof(bitmap_info_t, nlevels));
	printf("//   levels offset: %zu\n", offsetof(bitmap_info_t, levels));
#else
	printf("//   ngroups offset: %zu\n", offsetof(bitmap_info_t, ngroups));
#endif
	printf("//   total size: %zu\n", sizeof(bitmap_info_t));

	return 0;
}
