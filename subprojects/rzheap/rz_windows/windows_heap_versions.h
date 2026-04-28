// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_WINDOWS_HEAP_VERSIONS_H
#define RZ_WINDOWS_HEAP_VERSIONS_H

#include <rz_types.h>

#define RZ_W10_BUILD_UNKNOWN 0
#define RZ_W10_BUILD_1511    10586 /* 1511, Threshold 2 */
#define RZ_W10_BUILD_1607    14393 /* 1607, Redstone 1 */
#define RZ_W10_BUILD_21H1    19043 /* 21H1 */

#define RZ_NT_HEAP_SIGNATURE      0xffeeffee
#define RZ_SEGMENT_HEAP_SIGNATURE 0xddeeddee

#define RZ_NT_HEAP_ENTRY_BUSY     0x01
#define RZ_NT_HEAP_ENTRY_EXTRA    0x02
#define RZ_NT_HEAP_ENTRY_FILL     0x04
#define RZ_NT_HEAP_ENTRY_VIRTUAL  0x08
#define RZ_NT_HEAP_ENTRY_LAST     0x10
#define RZ_NT_HEAP_ENTRY_SETTABLE 0x20

static inline bool rz_w32_has_stack_trace_init_var(int build) {
	return build >= RZ_W10_BUILD_1607;
}

static inline bool rz_w32_has_commit_limit_data(int build) {
	return build >= RZ_W10_BUILD_21H1;
}

typedef struct rz_w32_heap_entry_layout_t {
	ut32 previous_block_private_data;
	ut32 size;
	ut32 flags;
	ut32 small_tag_index;
	ut32 previous_size;
	ut32 segment_offset;
	ut32 unused_bytes;
	ut32 struct_size;
	ut32 header_offset;
} RzW32HeapEntryLayout;

typedef struct rz_w32_heap_segment_layout_t {
	ut32 entry;
	ut32 segment_signature;
	ut32 segment_flags;
	ut32 segment_list_entry;
	ut32 heap_ptr;
	ut32 base_address;
	ut32 number_of_pages;
	ut32 first_entry;
	ut32 last_valid_entry;
	ut32 struct_size;
} RzW32HeapSegmentLayout;

typedef struct rz_w32_heap_layout_t {
	ut32 flags;
	ut32 force_flags;
	ut32 compatibility_flags;
	ut32 encode_flag_mask;
	ut32 encoding;
	ut32 interceptor;
	ut32 virtual_mem_thresh;
	ut32 signature;
	ut32 virtual_alloc_blocks;
	ut32 segment_list;
	ut32 front_end_heap;
	ut32 front_end_heap_type;
	ut32 counters;
	ut32 tuning_parameters;
	ut32 struct_size;
} RzW32HeapLayout;

static const RzW32HeapEntryLayout rz_w32_heap_entry_layout_64 = {
	.previous_block_private_data = 0x00,
	.size = 0x08,
	.flags = 0x0A,
	.small_tag_index = 0x0B,
	.previous_size = 0x0C,
	.segment_offset = 0x0E,
	.unused_bytes = 0x0F,
	.struct_size = 16,
	.header_offset = 8,
};

static const RzW32HeapEntryLayout rz_w32_heap_entry_layout_32 = {
	.previous_block_private_data = 0, /* not present on x86 */
	.size = 0x00,
	.flags = 0x02,
	.small_tag_index = 0x03,
	.previous_size = 0x04,
	.segment_offset = 0x06,
	.unused_bytes = 0x07,
	.struct_size = 8,
	.header_offset = 0,
};

static inline RzW32HeapEntryLayout rz_w32_get_heap_entry_layout(ut8 ptr_size) {
	if (ptr_size == 8) {
		return rz_w32_heap_entry_layout_64;
	}
	return rz_w32_heap_entry_layout_32;
}

static const RzW32HeapSegmentLayout rz_w32_heap_segment_layout_64 = {
	.entry = 0x00,
	.segment_signature = 0x10,
	.segment_flags = 0x14,
	.segment_list_entry = 0x18,
	.heap_ptr = 0x28,
	.base_address = 0x30,
	.number_of_pages = 0x38,
	.first_entry = 0x40,
	.last_valid_entry = 0x48,
	.struct_size = 0x70,
};

static const RzW32HeapSegmentLayout rz_w32_heap_segment_layout_32 = {
	.entry = 0x00,
	.segment_signature = 0x08,
	.segment_flags = 0x0C,
	.segment_list_entry = 0x10,
	.heap_ptr = 0x18,
	.base_address = 0x1C,
	.number_of_pages = 0x20,
	.first_entry = 0x24,
	.last_valid_entry = 0x28,
	.struct_size = 0x40,
};

static inline RzW32HeapSegmentLayout rz_w32_get_heap_segment_layout(ut8 ptr_size) {
	if (ptr_size == 8) {
		return rz_w32_heap_segment_layout_64;
	}
	return rz_w32_heap_segment_layout_32;
}

static const RzW32HeapLayout rz_w32_heap_layout_10586_64 = {
	.flags = 0x70,
	.force_flags = 0x74,
	.compatibility_flags = 0x78,
	.encode_flag_mask = 0x7C,
	.encoding = 0x80,
	.interceptor = 0x90,
	.virtual_mem_thresh = 0x94,
	.signature = 0x98,
	.virtual_alloc_blocks = 0x110,
	.segment_list = 0x120,
	.front_end_heap = 0x170,
	.front_end_heap_type = 0x17A,
	.counters = 0x0210,
	.tuning_parameters = 0x0288,
	.struct_size = 0x0298,
};

static const RzW32HeapLayout rz_w32_heap_layout_10586_32 = {
	.flags = 0x40,
	.force_flags = 0x44,
	.compatibility_flags = 0x48,
	.encode_flag_mask = 0x4C,
	.encoding = 0x50,
	.interceptor = 0x58,
	.virtual_mem_thresh = 0x5C,
	.signature = 0x60,
	.virtual_alloc_blocks = 0x9C,
	.segment_list = 0xA4,
	.front_end_heap = 0xD0,
	.front_end_heap_type = 0xD6,
	.counters = 0x01E0,
	.tuning_parameters = 0x023C,
	.struct_size = 0x0248,
};

static const RzW32HeapLayout rz_w32_heap_layout_14393_64 = {
	.flags = 0x70,
	.force_flags = 0x74,
	.compatibility_flags = 0x78,
	.encode_flag_mask = 0x7C,
	.encoding = 0x80,
	.interceptor = 0x90,
	.virtual_mem_thresh = 0x94,
	.signature = 0x98,
	.virtual_alloc_blocks = 0x110,
	.segment_list = 0x120,
	.front_end_heap = 0x178,
	.front_end_heap_type = 0x0182,
	.counters = 0x0218,
	.tuning_parameters = 0x0290,
	.struct_size = 0x02A0,
};

static const RzW32HeapLayout rz_w32_heap_layout_14393_32 = {
	.flags = 0x40,
	.force_flags = 0x44,
	.compatibility_flags = 0x48,
	.encode_flag_mask = 0x4C,
	.encoding = 0x50,
	.interceptor = 0x58,
	.virtual_mem_thresh = 0x5C,
	.signature = 0x60,
	.virtual_alloc_blocks = 0x9C,
	.segment_list = 0xA4,
	.front_end_heap = 0xD4,
	.front_end_heap_type = 0xDA,
	.counters = 0x01E4,
	.tuning_parameters = 0x0240,
	.struct_size = 0x0248,
};

static const RzW32HeapLayout rz_w32_heap_layout_19043_64 = {
	.flags = 0x70,
	.force_flags = 0x74,
	.compatibility_flags = 0x78,
	.encode_flag_mask = 0x7C,
	.encoding = 0x80,
	.interceptor = 0x90,
	.virtual_mem_thresh = 0x94,
	.signature = 0x98,
	.virtual_alloc_blocks = 0x110,
	.segment_list = 0x120,
	.front_end_heap = 0x198,
	.front_end_heap_type = 0x1A2,
	.counters = 0x0238,
	.tuning_parameters = 0x02B0,
	.struct_size = 0x02C0,
};

static const RzW32HeapLayout rz_w32_heap_layout_19043_32 = {
	.flags = 0x40,
	.force_flags = 0x44,
	.compatibility_flags = 0x48,
	.encode_flag_mask = 0x4C,
	.encoding = 0x50,
	.interceptor = 0x58,
	.virtual_mem_thresh = 0x5C,
	.signature = 0x60,
	.virtual_alloc_blocks = 0x9C,
	.segment_list = 0xA4,
	.front_end_heap = 0xE4,
	.front_end_heap_type = 0xEA,
	.counters = 0x01F4,
	.tuning_parameters = 0x0250,
	.struct_size = 0x0258,
};

static inline RzW32HeapLayout rz_w32_get_heap_layout(int build, ut8 ptr_size) {
	if (ptr_size == 8) {
		if (build >= RZ_W10_BUILD_21H1) {
			return rz_w32_heap_layout_19043_64;
		}
		if (build >= RZ_W10_BUILD_1607) {
			return rz_w32_heap_layout_14393_64;
		}
		return rz_w32_heap_layout_10586_64;
	} else {
		if (build >= RZ_W10_BUILD_21H1) {
			return rz_w32_heap_layout_19043_32;
		}
		if (build >= RZ_W10_BUILD_1607) {
			return rz_w32_heap_layout_14393_32;
		}
		return rz_w32_heap_layout_10586_32;
	}
}

#endif /* RZ_WINDOWS_HEAP_VERSIONS_H */
