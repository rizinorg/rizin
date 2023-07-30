// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_IPI bool ListsHeader_parse(RzBinDwarfListsHeader *hdr, RzBuffer *buffer, bool big_endian) {
	memset(hdr, 0, sizeof(RzBinDwarfListsHeader));
	bool is_64bit = false;
	ut64 length = 0;
	RET_FALSE_IF_FAIL(buf_read_initial_length(buffer, &is_64bit, &length, big_endian));
	hdr->encoding.big_endian = big_endian;
	hdr->encoding.is_64bit = is_64bit;
	hdr->unit_length = length;

	U_OR_RET_FALSE(16, hdr->encoding.version);
	U8_OR_RET_FALSE(hdr->encoding.address_size);
	U8_OR_RET_FALSE(hdr->segment_selector_size);
	if (hdr->segment_selector_size != 0) {
		RZ_LOG_ERROR("Segment selector size not supported: %d", hdr->segment_selector_size);
	}
	U_OR_RET_FALSE(32, hdr->offset_entry_count);

	if (hdr->offset_entry_count > 0) {
		ut64 byte_size = sizeof(ut64) * hdr->offset_entry_count;
		hdr->location_offsets = malloc(byte_size);
		for (ut32 i = 0; i < hdr->offset_entry_count; ++i) {
			RET_FALSE_IF_FAIL(buf_read_offset(buffer, hdr->location_offsets + i, is_64bit, big_endian));
		}
	}
	return true;
}
