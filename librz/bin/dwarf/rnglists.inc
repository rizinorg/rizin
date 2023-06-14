// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_bin_dwarf.h"

static bool Range_parse(RzBinDwarfRange *self, RzBuffer *buffer, RzBinDwarfEncoding *encoding) {
	bool big_endian = encoding->big_endian;
	UX_OR_RET_FALSE(self->begin, encoding->address_size);
	UX_OR_RET_FALSE(self->end, encoding->address_size);
	return true;
}

static inline bool Range_is_end(RzBinDwarfRange *self) {
	return self->begin == 0 && self->end == 0;
}

static inline bool Range_is_base_address(RzBinDwarfRange *self, ut8 address_size) {
	return self->begin == !0 >> (64 - address_size * 8);
}

static inline void Range_add_base_address(RzBinDwarfRange *self, ut64 base_address, ut8 address_size) {
	ut64 mask = !0 >> (64 - address_size * 8);
	self->begin = (base_address + self->begin) & mask;
	self->end = (base_address + self->end) & mask;
}

static bool RawRngListEntry_parse(RzBinDwarfRawRngListEntry *out, RzBuffer *buffer, enum RzBinDwarfRangeListsFormat format, RzBinDwarfEncoding *encoding) {
	RzBinDwarfRawRngListEntry entry = { 0 };
	bool big_endian = encoding->big_endian;
	switch (format) {
	case RangeListsFormat_Bare: {
		RzBinDwarfRange range = { 0 };
		RET_FALSE_IF_FAIL(Range_parse(&range, buffer, encoding));
		if (Range_is_end(&range)) {
			return true;
		} else if (Range_is_base_address(&range, encoding->address_size)) {
			entry.encoding = DW_RLE_base_address;
			entry.base_address.addr = range.end;
		} else {
			entry.is_address_or_offset_pair = true;
			entry.address_or_offset_pair.begin = range.begin;
			entry.address_or_offset_pair.end = range.end;
		}
		break;
	}
	case RangeListsFormat_Rle: {
		ut8 byte;
		U8_OR_RET_FALSE(byte);
		entry.encoding = byte;
		switch (entry.encoding) {
		case DW_RLE_end_of_list: return true;
		case DW_RLE_base_addressx: {
			ULE128_OR_RET_FALSE(entry.base_addressx.addr);
			break;
		}
		case DW_RLE_startx_endx:
			ULE128_OR_RET_FALSE(entry.startx_endx.begin);
			ULE128_OR_RET_FALSE(entry.startx_endx.end);
			break;
		case DW_RLE_startx_length:
			ULE128_OR_RET_FALSE(entry.startx_length.begin);
			ULE128_OR_RET_FALSE(entry.startx_length.length);
			break;
		case DW_RLE_offset_pair:
			ULE128_OR_RET_FALSE(entry.offset_pair.begin);
			ULE128_OR_RET_FALSE(entry.offset_pair.end);
			break;
		case DW_RLE_base_address:
			UX_OR_RET_FALSE(entry.base_address.addr, encoding->address_size);
			break;
		case DW_RLE_start_end:
			UX_OR_RET_FALSE(entry.start_end.begin, encoding->address_size);
			UX_OR_RET_FALSE(entry.start_end.end, encoding->address_size);
			break;
		case DW_RLE_start_length:
			UX_OR_RET_FALSE(entry.start_length.begin, encoding->address_size);
			ULE128_OR_RET_FALSE(entry.start_length.length);
			break;
		default: {
			rz_warn_if_reached();
			return false;
		}
		}
	}
	}
	memcpy(out, &entry, sizeof(entry));
	return true;
}
