// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_GLIBC_TYPES_H
#define RZ_GLIBC_TYPES_H

#include <rz_cmd.h>
#include <rz_types.h>
#include <rz_list.h>
#include "glibc_versions.h"

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_heap_glibc);

typedef struct rz_glibc_malloc_state_t {
	ut32 mutex;
	ut32 flags;
	ut32 have_fast_chunks; // 0 if not present in this version
	ut64 fastbinsY[RZ_GLIBC_NFASTBINS];
	ut64 top;
	ut64 last_remainder;
	ut64 bins[RZ_GLIBC_NBINS * 2 - 2];
	ut32 binmap[RZ_GLIBC_BINMAPSIZE];
	ut64 next;
	ut64 next_free;
	ut64 attached_threads; // 0 if not present in this version
	ut64 system_mem;
	ut64 max_system_mem;
} MallocState;

typedef enum rz_heap_bin_type {
	RZ_HEAP_BIN_ANY,
	RZ_HEAP_BIN_TCACHE,
	RZ_HEAP_BIN_FAST,
	RZ_HEAP_BIN_UNSORTED,
	RZ_HEAP_BIN_SMALL,
	RZ_HEAP_BIN_LARGE
} RzHeapBinType;

typedef struct rz_heap_chunk_list_item {
	ut64 addr;
	ut64 size;
	char *status;
} RzHeapChunkListItem;

typedef struct rz_arena_list_item {
	ut64 addr;
	char *type;
	MallocState *arena;
} RzArenaListItem;

// normalized API/view model
typedef struct rz_heap_chunk_simple {
	ut64 addr;
	ut64 prev_size;
	ut64 size;
	bool non_main_arena;
	bool prev_inuse;
	bool is_mmapped;
	ut64 fd;
	ut64 bk;
	ut64 fd_nextsize;
	ut64 bk_nextsize;
} RzHeapChunkSimple;

typedef struct rz_heap_bin {
	ut64 addr;
	ut64 size;
	ut64 fd;
	ut64 bk;
	int bin_num;
	char *type;
	RzList /*<RzHeapChunkListItem *>*/ *chunks;
	char *message;
} RzHeapBin;

typedef struct rz_glibc_config_t {
	ut8 ptr_size;
	bool is_big_endian;
	int glibc_version; // 3-digit, e.g. 231 for 2.31

	RzHeapChunkLayout chunk;
	MallocStateLayout malloc_state;
	RzHeapHeapInfoLayout heap_info;
	RzHeapTcacheLayout tcache;
	RzHeapTcacheEntryLayout tcache_entry;

	ut32 min_chunk_size;
	ut32 malloc_alignment;
	ut32 chunk_hdr_size;
	ut64 heap_page_size;
	ut64 heap_page_size_x86;
	ut64 mmap_align;
	ut64 mmap_offset;
	ut64 tcache_hdr_size;
	ut64 tcache_chunk_extra;
} RzHeapConfig;

// raw on-memory glibc chunk layout
typedef struct rz_glibc_chunk_t {
	ut64 prev_size;
	ut64 size;
	ut64 fd;
	ut64 bk;
	ut64 fd_nextsize;
	ut64 bk_nextsize;
} RzHeapChunk;

typedef struct rz_glibc_heap_info_t {
	ut64 ar_ptr;
	ut64 prev;
	ut64 size;
	ut64 mprotect_size;
} RzHeapHeapInfo;

typedef struct rz_glibc_tcache_t {
	ut16 counts[RZ_GLIBC_TCACHE_MAX_BINS];
	ut64 entries[RZ_GLIBC_TCACHE_MAX_BINS];
} RzHeapTcache;

typedef struct rz_glibc_tcache_entry_t {
	ut64 next;
	ut64 key; // 0 if not present in this version
} RzHeapTcacheEntry;

#define RZ_GLIBC_PREV_INUSE     0x1
#define RZ_GLIBC_IS_MMAPPED     0x2
#define RZ_GLIBC_NON_MAIN_ARENA 0x4
#define RZ_GLIBC_SIZE_BITS      (RZ_GLIBC_PREV_INUSE | RZ_GLIBC_IS_MMAPPED | RZ_GLIBC_NON_MAIN_ARENA)

static inline ut64 rz_glibc_chunk_size(const RzHeapChunk *chunk, const RzHeapConfig *config) {
	ut64 mask = ~(ut64)(config->malloc_alignment - 1);
	return chunk->size & mask;
}

static inline bool rz_glibc_chunk_prev_inuse(const RzHeapChunk *chunk) {
	return (chunk->size & RZ_GLIBC_PREV_INUSE) != 0;
}

static inline bool rz_glibc_chunk_is_mmapped(const RzHeapChunk *chunk) {
	return (chunk->size & RZ_GLIBC_IS_MMAPPED) != 0;
}

static inline bool rz_glibc_chunk_non_main_arena(const RzHeapChunk *chunk) {
	return (chunk->size & RZ_GLIBC_NON_MAIN_ARENA) != 0;
}

static inline ut64 rz_glibc_chunk_to_mem(ut64 chunk_addr, const RzHeapConfig *config) {
	return chunk_addr + config->chunk_hdr_size;
}

static inline ut64 rz_glibc_mem_to_chunk(ut64 mem_addr, const RzHeapConfig *config) {
	return mem_addr - config->chunk_hdr_size;
}

static inline ut64 rz_glibc_safe_link_decode(ut64 ptr, ut64 ptr_addr) {
	return ptr ^ (ptr_addr >> 12);
}

static inline ut64 rz_glibc_safe_link_encode(ut64 target, ut64 ptr_addr) {
	return target ^ (ptr_addr >> 12);
}

static inline void rz_glibc_config_init(RzHeapConfig *config, ut8 ptr_size,
	int glibc_version, bool is_big_endian) {
	config->ptr_size = ptr_size;
	config->is_big_endian = is_big_endian;
	config->glibc_version = glibc_version;

	config->chunk = rz_glibc_chunk_layout(ptr_size);
	config->malloc_state = rz_glibc_get_malloc_state_layout(config->glibc_version, ptr_size);
	config->heap_info = rz_glibc_get_heap_info_layout(config->glibc_version, ptr_size);
	config->tcache = rz_glibc_get_tcache_layout(config->glibc_version, ptr_size);
	config->tcache_entry = rz_glibc_get_tcache_entry_layout(config->glibc_version, ptr_size);

	config->min_chunk_size = ptr_size * 4; // used to be RZ_SEARCH_MIN_CHUNK_SIZE
	config->malloc_alignment = ptr_size * 2;
	config->chunk_hdr_size = ptr_size * 2; // used to be GH(HDR_SZ)
	config->heap_page_size = 0x21000; // used to be HEAP_PAGE_SIZE
	config->heap_page_size_x86 = 0x22000; // used to be HEAP_PAGE_SIZE_X86
	config->mmap_align = (ptr_size == 8) ? 0x18 : 0x14; // used to be GH(MMAP_ALIGN)
	config->mmap_offset = 0x8; // used to be MMAP_OFFSET
	config->tcache_hdr_size = 0x10; // used to be TC_HDR_SZ
	config->tcache_chunk_extra = (ptr_size == 8) ? 0x10 : 0x0; // used to be GH(TC_SZ)
}

#ifdef __cplusplus
}
#endif

#endif // RZ_GLIBC_TYPES_H
