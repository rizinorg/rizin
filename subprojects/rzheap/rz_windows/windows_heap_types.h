// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_WINDOWS_HEAP_TYPES_H
#define RZ_WINDOWS_HEAP_TYPES_H

#include <rz_types.h>
#include <rz_list.h>
#include "windows_heap_versions.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_w32_heap_config_t {
	ut8 ptr_size;
	bool is_big_endian;
	int build_number;

	RzW32HeapEntryLayout entry;
	RzW32HeapSegmentLayout segment;
	RzW32HeapLayout heap;

	ut32 entry_granularity;
} RzWindowsHeapConfig;

typedef struct rz_w32_heap_block_t {
	ut64 header_address;
	ut64 user_address;
	ut64 size;
	ut8 flags;
	ut8 unused_bytes;
	bool is_busy;
} RzWindowsHeapEntry;

typedef struct rz_w32_heap_info_t {
	ut64 base_address;
	ut64 first_entry;
	ut64 last_valid_entry;
	ut32 segment_signature;
	ut32 heap_signature;
	ut32 flags;
	ut32 encode_flag_mask;
	ut8 encoding[16];
	ut32 number_of_pages;
	ut8 front_end_heap_type;
	ut64 front_end_heap;
	ut32 total_blocks;
	ut32 busy_blocks;
	ut32 free_blocks;
} RzWindowsHeapInfo;

static inline void rz_w32_heap_config_init(RzWindowsHeapConfig *config,
	ut8 ptr_size, int build_number) {
	config->ptr_size = ptr_size;
	config->is_big_endian = false;
	config->build_number = build_number;
	config->entry = rz_w32_get_heap_entry_layout(ptr_size);
	config->segment = rz_w32_get_heap_segment_layout(ptr_size);
	config->heap = rz_w32_get_heap_layout(build_number, ptr_size);
	config->entry_granularity = config->entry.struct_size;
}

#ifdef __cplusplus
}
#endif

#endif /* RZ_WINDOWS_HEAP_TYPES_H */
