// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * References:
 * - https://sourceware.org/git/glibc.git
 * - https://github.com/pwndbg/pwndbg/blob/dev/pwndbg/aglib/heap/structs.py
 */

#ifndef RZ_GLIBC_VERSIONS_H
#define RZ_GLIBC_VERSIONS_H

#include <rz_types.h>

#define RZ_GLIBC_VERSION_UNKNOWN 0
#define RZ_GLIBC_VERSION_2_23    223
#define RZ_GLIBC_VERSION_2_26    226
#define RZ_GLIBC_VERSION_2_27    227
#define RZ_GLIBC_VERSION_2_28    228
#define RZ_GLIBC_VERSION_2_29    229
#define RZ_GLIBC_VERSION_2_30    230
#define RZ_GLIBC_VERSION_2_32    232
#define RZ_GLIBC_VERSION_2_35    235
#define RZ_GLIBC_VERSION_2_42    242

static inline bool rz_glibc_has_tcache(int glibc_version) {
	return glibc_version >= RZ_GLIBC_VERSION_2_26;
}

static inline bool rz_glibc_has_safe_linking(int glibc_version) {
	return glibc_version >= RZ_GLIBC_VERSION_2_32;
}

#define RZ_GLIBC_NBINS             128
#define RZ_GLIBC_NFASTBINS         10
#define RZ_GLIBC_BINMAPSIZE        4
#define RZ_GLIBC_NSMALLBINS        64
#define RZ_GLIBC_TCACHE_LARGE_BINS 12
#define RZ_GLIBC_TCACHE_MAX_BINS   (RZ_GLIBC_NSMALLBINS + RZ_GLIBC_TCACHE_LARGE_BINS)

typedef struct rz_glibc_chunk_layout_t {
	ut32 prev_size;
	ut32 size;
	ut32 fd;
	ut32 bk;
	ut32 fd_nextsize;
	ut32 bk_nextsize;
	ut32 struct_size;
} RzHeapChunkLayout;

static inline RzHeapChunkLayout rz_glibc_chunk_layout(ut8 ptr_size) {
	RzHeapChunkLayout layout = {
		.prev_size = 0,
		.size = ptr_size,
		.fd = (ut32)(ptr_size * 2),
		.bk = (ut32)(ptr_size * 3),
		.fd_nextsize = (ut32)(ptr_size * 4),
		.bk_nextsize = (ut32)(ptr_size * 5),
		.struct_size = (ut32)(ptr_size * 6),
	};
	return layout;
}

typedef struct rz_glibc_malloc_state_layout_t {
	ut32 mutex;
	ut32 flags;
	ut32 have_fast_chunks; // 2.27+ only, 0 if not present
	ut32 fastbinsY;
	ut32 top;
	ut32 last_remainder;
	ut32 bins;
	ut32 binmap;
	ut32 next;
	ut32 next_free;
	ut32 attached_threads; // 2.23+ only, 0 if not present
	ut32 system_mem;
	ut32 max_system_mem;
	ut32 struct_size;
	bool has_have_fast_chunks;
	bool has_attached_threads;
} MallocStateLayout;

static const MallocStateLayout rz_glibc_malloc_state_226_64 = {
	.mutex = 0,
	.flags = 4,
	.have_fast_chunks = 0, // not present
	.fastbinsY = 8,
	.top = 88,
	.last_remainder = 96,
	.bins = 104,
	.binmap = 2136,
	.next = 2152,
	.next_free = 2160,
	.attached_threads = 2168,
	.system_mem = 2176,
	.max_system_mem = 2184,
	.struct_size = 2192,
	.has_have_fast_chunks = false,
	.has_attached_threads = true,
};

static const MallocStateLayout rz_glibc_malloc_state_227_64 = {
	.mutex = 0,
	.flags = 4,
	.have_fast_chunks = 8,
	.fastbinsY = 16,
	.top = 96,
	.last_remainder = 104,
	.bins = 112,
	.binmap = 2144,
	.next = 2160,
	.next_free = 2168,
	.attached_threads = 2176,
	.system_mem = 2184,
	.max_system_mem = 2192,
	.struct_size = 2200,
	.has_have_fast_chunks = true,
	.has_attached_threads = true,
};

static const MallocStateLayout rz_glibc_malloc_state_226_32 = {
	.mutex = 0,
	.flags = 4,
	.have_fast_chunks = 0, // not present
	.fastbinsY = 8,
	.top = 48,
	.last_remainder = 52,
	.bins = 56,
	.binmap = 1072,
	.next = 1088,
	.next_free = 1092,
	.attached_threads = 1096,
	.system_mem = 1100,
	.max_system_mem = 1104,
	.struct_size = 1108,
	.has_have_fast_chunks = false,
	.has_attached_threads = true,
};

static const MallocStateLayout rz_glibc_malloc_state_227_32 = {
	.mutex = 0,
	.flags = 4,
	.have_fast_chunks = 8,
	.fastbinsY = 12,
	.top = 52,
	.last_remainder = 56,
	.bins = 60,
	.binmap = 1076,
	.next = 1092,
	.next_free = 1096,
	.attached_threads = 1100,
	.system_mem = 1104,
	.max_system_mem = 1108,
	.struct_size = 1112,
	.has_have_fast_chunks = true,
	.has_attached_threads = true,
};

static inline MallocStateLayout rz_glibc_get_malloc_state_layout(
	int glibc_version, ut8 ptr_size) {
	if (ptr_size == 8) {
		if (glibc_version >= RZ_GLIBC_VERSION_2_27) {
			return rz_glibc_malloc_state_227_64;
		}
		return rz_glibc_malloc_state_226_64;
	} else {
		if (glibc_version >= RZ_GLIBC_VERSION_2_27) {
			return rz_glibc_malloc_state_227_32;
		}
		return rz_glibc_malloc_state_226_32;
	}
}

typedef struct rz_glibc_heap_info_layout_t {
	ut32 ar_ptr;
	ut32 prev;
	ut32 size;
	ut32 mprotect_size;
	ut32 struct_size;
} RzHeapHeapInfoLayout;

static const RzHeapHeapInfoLayout rz_glibc_heap_info_layout_234_64 = {
	.ar_ptr = 0,
	.prev = 8,
	.size = 16,
	.mprotect_size = 24,
	.struct_size = 32,
};

static const RzHeapHeapInfoLayout rz_glibc_heap_info_layout_235_64 = {
	.ar_ptr = 0,
	.prev = 8,
	.size = 16,
	.mprotect_size = 24,
	.struct_size = 48,
};

static const RzHeapHeapInfoLayout rz_glibc_heap_info_layout_234_32 = {
	.ar_ptr = 0,
	.prev = 4,
	.size = 8,
	.mprotect_size = 12,
	.struct_size = 16
};

static const RzHeapHeapInfoLayout rz_glibc_heap_info_layout_235_32 = {
	.ar_ptr = 0,
	.prev = 4,
	.size = 8,
	.mprotect_size = 12,
	.struct_size = 24
};

static inline RzHeapHeapInfoLayout rz_glibc_get_heap_info_layout(
	int glibc_version, ut8 ptr_size) {
	if (ptr_size == 8) {
		if (glibc_version >= RZ_GLIBC_VERSION_2_35) {
			return rz_glibc_heap_info_layout_235_64;
		}
		return rz_glibc_heap_info_layout_234_64;
	} else {
		if (glibc_version >= RZ_GLIBC_VERSION_2_35) {
			return rz_glibc_heap_info_layout_235_32;
		}
		return rz_glibc_heap_info_layout_234_32;
	}
}

typedef struct rz_glibc_tcache_layout_t {
	ut32 counts;
	ut32 entries;
	ut32 struct_size;
	ut8 count_type_size;
	ut32 num_bins;
} RzHeapTcacheLayout;

// no tcache before 225
static const RzHeapTcacheLayout rz_glibc_tcache_layout_226_64 = {
	.counts = 0,
	.entries = 64,
	.struct_size = 576,
	.count_type_size = 1,
	.num_bins = 64
};

static const RzHeapTcacheLayout rz_glibc_tcache_layout_230_64 = {
	.counts = 0,
	.entries = 128,
	.struct_size = 640,
	.count_type_size = 2,
	.num_bins = 64
};

static const RzHeapTcacheLayout rz_glibc_tcache_layout_242_64 = {
	.counts = 0,
	.entries = 152,
	.struct_size = 760,
	.count_type_size = 2,
	.num_bins = 76,
};

static const RzHeapTcacheLayout rz_glibc_tcache_layout_226_32 = {
	.counts = 0,
	.entries = 64,
	.struct_size = 320,
	.count_type_size = 1,
	.num_bins = 64
};

static const RzHeapTcacheLayout rz_glibc_tcache_layout_230_32 = {
	.counts = 0,
	.entries = 128,
	.struct_size = 384,
	.count_type_size = 2,
	.num_bins = 64
};

static const RzHeapTcacheLayout rz_glibc_tcache_layout_242_32 = {
	.counts = 0,
	.entries = 152,
	.struct_size = 456,
	.count_type_size = 2,
	.num_bins = 76
};

static inline RzHeapTcacheLayout rz_glibc_get_tcache_layout(
	int glibc_version, ut8 ptr_size) {
	if (ptr_size == 8) {
		if (glibc_version >= RZ_GLIBC_VERSION_2_42) {
			return rz_glibc_tcache_layout_242_64;
		}
		if (glibc_version >= RZ_GLIBC_VERSION_2_30) {
			return rz_glibc_tcache_layout_230_64;
		}
		return rz_glibc_tcache_layout_226_64;
	} else {
		if (glibc_version >= RZ_GLIBC_VERSION_2_42) {
			return rz_glibc_tcache_layout_242_32;
		}
		if (glibc_version >= RZ_GLIBC_VERSION_2_30) {
			return rz_glibc_tcache_layout_230_32;
		}
		return rz_glibc_tcache_layout_226_32;
	}
}

typedef struct rz_glibc_tcache_entry_layout_t {
	ut32 next;
	ut32 key;
	ut32 struct_size;
	bool has_key;
} RzHeapTcacheEntryLayout;

// 225 has no tcache_entry
static const RzHeapTcacheEntryLayout rz_glibc_tcache_entry_layout_226_64 = {
	.next = 0,
	.key = 0,
	.struct_size = 8,
	.has_key = false
};

static const RzHeapTcacheEntryLayout rz_glibc_tcache_entry_layout_229_64 = {
	.next = 0,
	.key = 8,
	.struct_size = 16,
	.has_key = true
};

static const RzHeapTcacheEntryLayout rz_glibc_tcache_entry_layout_226_32 = {
	.next = 0,
	.key = 0,
	.struct_size = 4,
	.has_key = false
};

static const RzHeapTcacheEntryLayout rz_glibc_tcache_entry_layout_229_32 = {
	.next = 0,
	.key = 4,
	.struct_size = 8,
	.has_key = true
};

static inline RzHeapTcacheEntryLayout rz_glibc_get_tcache_entry_layout(
	int glibc_version, ut8 ptr_size) {
	if (ptr_size == 8) {
		if (glibc_version >= RZ_GLIBC_VERSION_2_29) {
			return rz_glibc_tcache_entry_layout_229_64;
		}
		return rz_glibc_tcache_entry_layout_226_64;
	} else {
		if (glibc_version >= RZ_GLIBC_VERSION_2_29) {
			return rz_glibc_tcache_entry_layout_229_32;
		}
		return rz_glibc_tcache_entry_layout_226_32;
	}
}

#endif // RZ_GLIBC_VERSIONS_H
