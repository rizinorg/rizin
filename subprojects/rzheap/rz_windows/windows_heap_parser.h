// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_WINDOWS_HEAP_PARSER_H
#define RZ_WINDOWS_HEAP_PARSER_H

#include <rz_io.h>
#include "windows_heap_types.h"

static inline ut64 rz_w32_read_ptr(const ut8 *buf, ut32 offset, ut8 ptr_size) {
	if (ptr_size == 8) {
		return rz_read_le64(buf + offset);
	}
	return (ut64)rz_read_le32(buf + offset);
}

static inline bool rz_w32_decode_heap_entry(ut8 *entry_buf, const ut8 *encoding,
	ut32 encode_flag_mask, const RzWindowsHeapConfig *config) {
	const RzW32HeapEntryLayout *el = &config->entry;

	ut32 hdr = rz_read_le32(entry_buf + el->header_offset);
	if (encode_flag_mask && (hdr & encode_flag_mask)) {
		// XOR the header bytes with the encoding key
		for (ut32 i = el->header_offset; i < el->struct_size; i++) {
			entry_buf[i] ^= encoding[i];
		}
	}

	// Size[0] ^ Size[1] ^ Flags ^ SmallTagIndex == 0
	ut8 checksum = entry_buf[el->size] ^
		entry_buf[el->size + 1] ^
		entry_buf[el->flags] ^
		entry_buf[el->small_tag_index];
	return checksum == 0;
}

static inline void rz_w32_extract_heap_entry(const ut8 *entry_buf, ut64 entry_va,
	RzWindowsHeapEntry *block, const RzWindowsHeapConfig *config) {
	const RzW32HeapEntryLayout *el = &config->entry;

	ut16 size_units = rz_read_le16(entry_buf + el->size);
	ut8 flags = entry_buf[el->flags];
	ut8 unused_bytes = entry_buf[el->unused_bytes];

	block->header_address = entry_va;
	block->user_address = entry_va + config->entry_granularity;
	block->size = (ut64)size_units * config->entry_granularity;
	block->flags = flags;
	block->unused_bytes = unused_bytes;
	block->is_busy = (flags & RZ_NT_HEAP_ENTRY_BUSY) != 0;
}

static inline bool rz_w32_read_heap_info(RzIO *io, ut64 addr,
	RzWindowsHeapInfo *info, const RzWindowsHeapConfig *config) {
	const RzW32HeapSegmentLayout *sl = &config->segment;
	const RzW32HeapLayout *hl = &config->heap;
	const RzW32HeapEntryLayout *el = &config->entry;

	ut32 read_size = hl->struct_size;
	ut8 *hdr = RZ_NEWS0(ut8, read_size);
	if (!hdr) {
		return false;
	}

	if (!rz_io_read_at_mapped(io, addr, hdr, read_size)) {
		free(hdr);
		return false;
	}

	info->segment_signature = rz_read_le32(hdr + sl->segment_signature);
	info->base_address = rz_w32_read_ptr(hdr, sl->base_address, config->ptr_size);
	info->number_of_pages = rz_read_le32(hdr + sl->number_of_pages);
	info->first_entry = rz_w32_read_ptr(hdr, sl->first_entry, config->ptr_size);
	info->last_valid_entry = rz_w32_read_ptr(hdr, sl->last_valid_entry, config->ptr_size);
	info->flags = rz_read_le32(hdr + hl->flags);
	info->encode_flag_mask = rz_read_le32(hdr + hl->encode_flag_mask);
	info->heap_signature = rz_read_le32(hdr + hl->signature);
	info->front_end_heap = rz_w32_read_ptr(hdr, hl->front_end_heap, config->ptr_size);
	info->front_end_heap_type = hdr[hl->front_end_heap_type];
	memcpy(info->encoding, hdr + hl->encoding, el->struct_size);

	free(hdr);
	return true;
}

#endif // RZ_WINDOWS_HEAP_PARSER_H
