// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_windows_heap.h>
#include <rz_windows/windows_heap_parser.h>

RZ_OWN RzWindowsHeapInfo *rz_w32_heap_info_parse(RZ_NONNULL RzIO *io,
	ut64 heap_base, RZ_NONNULL const RzWindowsHeapConfig *config) {
	rz_return_val_if_fail(io && config, NULL);

	RzWindowsHeapInfo *info = RZ_NEW0(RzWindowsHeapInfo);
	if (!info) {
		return NULL;
	}

	if (!rz_w32_read_heap_info(io, heap_base, info, config)) {
		RZ_LOG_ERROR("Failed to read heap header at 0x%" PFMT64x "\n", heap_base);
		free(info);
		return NULL;
	}

	// Verify NT heap segment signature
	if (info->segment_signature != RZ_NT_HEAP_SIGNATURE) {
		if (info->segment_signature == RZ_SEGMENT_HEAP_SIGNATURE) {
			RZ_LOG_ERROR("Segment Heap detected (0x%08x) - not supported version\n",
				info->segment_signature);
		} else {
			RZ_LOG_ERROR("Invalid NT heap signgature: 0x%08x (expected 0x%08x)\n",
				info->segment_signature, RZ_NT_HEAP_SIGNATURE);
		}
		free(info);
		return NULL;
	}

	// Use the provided heap_base if the one in the dump doesn't make sense
	if (info->base_address == 0) {
		info->base_address = heap_base;
	}

	return info;
}

RZ_API RZ_OWN RzList /*<RzWindowsHeapEntry *>*/ *rz_heap_windows_blocks_list(RzCore *core) {
	RzWindowsHeapConfig config;
	init_heap_config(core, &config);

	ut64 heap_base = get_heap_base(core->io, &config);
	RzWindowsHeapInfo *info = rz_w32_heap_info_parse(core->io, heap_base, &config);
	if (!info) {
		return NULL;
	}
	return rz_w32_heap_blocks_list(core->io, info, &config);
}

RZ_OWN RzList /*<RzWindowsHeapEntry *>*/ *rz_w32_heap_blocks_list(RZ_NONNULL RzIO *io,
	RZ_NONNULL const RzWindowsHeapInfo *heap_info, RZ_NONNULL const RzWindowsHeapConfig *config) {
	rz_return_val_if_fail(io && heap_info && config, NULL);

	RzList *list = rz_list_newf(free);
	if (!list) {
		return NULL;
	}

	ut64 base = heap_info->base_address;
	ut64 first_entry_va = heap_info->first_entry;
	ut64 last_valid_va = heap_info->last_valid_entry;
	const ut32 granularity = config->entry_granularity;

	// Convert first entry VA to file offset
	ut64 off = first_entry_va - base;
	ut64 io_size = rz_io_size(io);

	/* Allocate a reusable entry buffer */
	ut8 *entry_buf = RZ_NEWS0(ut8, config->entry.struct_size);
	if (!entry_buf) {
		rz_list_free(list);
		return NULL;
	}

	while (off + granularity <= io_size) {
		ut64 entry_va = base + off;

		// Safety: don't walk past LastValidEntry
		if (entry_va >= last_valid_va) {
			break;
		}

		if (!rz_io_read_at_mapped(io, off, entry_buf, config->entry.struct_size)) {
			RZ_LOG_ERROR("Failed to read heap entry at offset 0x%" PFMT64x "\n", off);
			break;
		}

		// Decode the entry
		if (!rz_w32_decode_heap_entry(entry_buf, heap_info->encoding,
			    heap_info->encode_flag_mask, config)) {
			// Invalid checksum - stop walking
			break;
		}

		ut16 size_units = rz_read_le16(entry_buf + config->entry.size);
		if (size_units == 0) {
			// Size 0 marks the last (sentinel) entry
			break;
		}

		RzWindowsHeapEntry *block = RZ_NEW0(RzWindowsHeapEntry);
		if (!block) {
			break;
		}

		rz_w32_extract_heap_entry(entry_buf, entry_va, block, config);
		rz_list_append(list, block);

		off += block->size;
	}

	RZ_FREE(entry_buf);

	return list;
}
