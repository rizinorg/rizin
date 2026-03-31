// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Helper program to extract jemalloc 5.3.0 configuration values.
 *
 * This program prints struct sizes and field offsets that are needed
 * for the RzJemallocConfig530 structure in Rizin's heap parser.
 *
 * Usage:
 *   1. Configure jemalloc for target: ./configure --host=<target> --with-lg-page=<N>
 *   2. Build jemalloc: make
 *   3. Build this tool (Meson):
 *      meson setup build -Djemalloc=/path/to/jemalloc -Djemalloc_version=5
 *      meson compile -C build
 *   4. Run: ./build/extract_config_530
 */

// Note: We do NOT define JEMALLOC_NO_PRIVATE_NAMESPACE because we need the
// namespace macros to remap internal symbols (e.g., malloc_printf -> je_malloc_printf)
// when linking against the built jemalloc library.
#include "jemalloc/internal/jemalloc_preamble.h"
#include "jemalloc/internal/jemalloc_internal_includes.h"

#include <stdio.h>
#include <stddef.h>

// Stub implementations for symbols referenced by jemalloc inline functions.
// We only need struct layouts, not actual runtime functionality.
void je_malloc_printf(const char *fmt, ...) {
	(void)fmt;
	// Never called - stub only
}

// ticker_geom_table is referenced by ticker.h inline functions
const uint8_t ticker_geom_table[1 << TICKER_GEOM_NBITS] = { 0 };

int main(void) {
	printf("// =============================================================================\n");
	printf("// jemalloc 5.3.0 configuration extracted from compiled source\n");
	printf("// =============================================================================\n");
	printf("//\n");
	printf("// Compile-time configuration:\n");
	printf("//   sizeof(void*) = %zu\n", sizeof(void *));
	printf("//   LG_PAGE = %d (page size = %zu bytes)\n", LG_PAGE, (size_t)1 << LG_PAGE);
	printf("//   SC_NBINS = %zu\n", (size_t)SC_NBINS);
	printf("//   SC_NSIZES = %zu\n", (size_t)SC_NSIZES);
#ifdef BITMAP_USE_TREE
	printf("//   BITMAP_USE_TREE = defined\n");
	printf("//   BITMAP_MAX_LEVELS = %d\n", BITMAP_MAX_LEVELS);
#else
	printf("//   BITMAP_USE_TREE = not defined\n");
#endif
	printf("//   LG_VADDR = %d\n", LG_VADDR);
	printf("//   RTREE_NSB = %d\n", RTREE_NSB);
	printf("//   RTREE_HEIGHT = %d\n", RTREE_HEIGHT);
	printf("//   RTREE_LEAF_COMPACT = %s\n",
#ifdef RTREE_LEAF_COMPACT
		"defined"
#else
		"not defined"
#endif
	);
	printf("//   rtree_levels[0].bits = %d\n", rtree_levels[0].bits);
#if RTREE_HEIGHT > 1
	printf("//   rtree_levels[1].bits = %d\n", rtree_levels[1].bits);
#endif
#if RTREE_HEIGHT > 2
	printf("//   rtree_levels[2].bits = %d\n", rtree_levels[2].bits);
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

	printf("static const RzJemallocConfig530 rz_jemalloc_config_%s_%s_%s_530 = {\n",
		arch_name, os_name, page_suffix);
	printf("\t.arch = %s,\n", arch_enum);
	printf("\t.ptr_size = %zu,\n", sizeof(void *));
	printf("\t.is_big_endian = false,\n");
	printf("\t.lg_page = %d,\n", LG_PAGE);
	printf("\t.sc_nbins = %zu,\n", (size_t)SC_NBINS);
	printf("\t.sc_nsizes = %zu,\n", (size_t)SC_NSIZES);
#ifdef BITMAP_USE_TREE
	printf("\t.bitmap_use_tree = true,\n");
	printf("\t.bitmap_max_levels = %d,\n", BITMAP_MAX_LEVELS);
#else
	printf("\t.bitmap_use_tree = false,\n");
	printf("\t.bitmap_max_levels = 0,\n");
#endif
	printf("\t.rtree_nsb = %d,\n", RTREE_NSB);
	printf("\t.rtree_bits_per_level = %d,\n", rtree_levels[0].bits);
	printf("\t.rtree_height = %d,\n", RTREE_HEIGHT);
#ifdef RTREE_LEAF_COMPACT
	printf("\t.rtree_leaf_compact = true,\n");
#else
	printf("\t.rtree_leaf_compact = false,\n");
#endif
	printf("\t.edata_size = %zu,\n", sizeof(edata_t));
	printf("\t.bin_info_size = %zu,\n", sizeof(bin_info_t));
	printf("\t.bin_size = %zu,\n", sizeof(bin_t));
	printf("\t.arena_size = %zu,\n", sizeof(arena_t));
	printf("\t.bitmap_info_size = %zu,\n", sizeof(bitmap_info_t));
	printf("\t.rtree_node_elm_size = %zu,\n", sizeof(rtree_node_elm_t));
	printf("\t.rtree_leaf_elm_size = %zu,\n", sizeof(rtree_leaf_elm_t));

	// Arena offsets
	printf("\t.arena_offsets = {\n");
	printf("\t\t.stats = %zu,\n", offsetof(arena_t, stats));
	printf("\t\t.tcache_ql = %zu,\n", offsetof(arena_t, tcache_ql));
	printf("\t\t.cache_bin_arr = %zu,\n", offsetof(arena_t, cache_bin_array_descriptor_ql));
	printf("\t\t.tcache_ql_mtx = %zu,\n", offsetof(arena_t, tcache_ql_mtx));
	printf("\t\t.dss_prec = %zu,\n", offsetof(arena_t, dss_prec));
	printf("\t\t.large = %zu,\n", offsetof(arena_t, large));
	printf("\t\t.large_mtx = %zu,\n", offsetof(arena_t, large_mtx));
	printf("\t\t.pa_shard = %zu,\n", offsetof(arena_t, pa_shard));
	printf("\t\t.ind = %zu,\n", offsetof(arena_t, ind));
	printf("\t\t.base = %zu,\n", offsetof(arena_t, base));
	printf("\t\t.create_time = %zu,\n", offsetof(arena_t, create_time));
	printf("\t\t.bins = %zu,\n", offsetof(arena_t, bins));
	printf("\t\t.last_thd = %zu,\n", offsetof(arena_t, last_thd));
	printf("\t},\n");

	// Bin offsets
	printf("\t.bin_offsets = {\n");
	printf("\t\t.slabcur = %zu,\n", offsetof(bin_t, slabcur));
	printf("\t},\n");

	// Rtree offsets - need to check if rtree_t has root field directly
	printf("\t.rtree_offsets = {\n");
	printf("\t\t.root = %zu,\n", offsetof(rtree_t, root));
	printf("\t},\n");

	printf("};\n");

	// Print additional useful information
	printf("\n// Additional struct information:\n");
	printf("// edata_t:\n");
	printf("//   e_bits offset: %zu\n", offsetof(edata_t, e_bits));
	printf("//   e_addr offset: %zu\n", offsetof(edata_t, e_addr));
	printf("//   total size: %zu\n", sizeof(edata_t));

	printf("//\n// bin_info_t:\n");
	printf("//   reg_size offset: %zu\n", offsetof(bin_info_t, reg_size));
	printf("//   slab_size offset: %zu\n", offsetof(bin_info_t, slab_size));
	printf("//   nregs offset: %zu\n", offsetof(bin_info_t, nregs));
	printf("//   n_shards offset: %zu\n", offsetof(bin_info_t, n_shards));
	printf("//   total size: %zu\n", sizeof(bin_info_t));

	printf("//\n// bin_t:\n");
	printf("//   lock offset: %zu\n", offsetof(bin_t, lock));
	printf("//   slabcur offset: %zu\n", offsetof(bin_t, slabcur));
	printf("//   slabs_nonfull offset: %zu\n", offsetof(bin_t, slabs_nonfull));
	printf("//   total size: %zu\n", sizeof(bin_t));

	printf("//\n// rtree_t:\n");
	printf("//   root offset: %zu\n", offsetof(rtree_t, root));
	printf("//   total size: %zu\n", sizeof(rtree_t));

	printf("//\n// rtree_node_elm_t:\n");
	printf("//   total size: %zu\n", sizeof(rtree_node_elm_t));

	printf("//\n// rtree_leaf_elm_t:\n");
#ifdef RTREE_LEAF_COMPACT
	printf("//   le_bits offset: %zu (compact mode)\n", offsetof(rtree_leaf_elm_t, le_bits));
#else
	printf("//   le_edata offset: %zu (non-compact mode)\n", offsetof(rtree_leaf_elm_t, le_edata));
#endif
	printf("//   total size: %zu\n", sizeof(rtree_leaf_elm_t));

	printf("//\n// bitmap_info_t:\n");
	printf("//   nbits offset: %zu\n", offsetof(bitmap_info_t, nbits));
#ifdef BITMAP_USE_TREE
	printf("//   nlevels offset: %zu\n", offsetof(bitmap_info_t, nlevels));
	printf("//   levels offset: %zu\n", offsetof(bitmap_info_t, levels));
#else
	printf("//   ngroups offset: %zu\n", offsetof(bitmap_info_t, ngroups));
#endif
	printf("//   total size: %zu\n", sizeof(bitmap_info_t));

	return 0;
}
