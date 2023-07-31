// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_IPI bool Range_parse(RzBinDwarfRange *self, RzBuffer *buffer, RzBinDwarfEncoding *encoding) {
	bool big_endian = encoding->big_endian;
	U_ADDR_SIZE_OR_RET_FALSE(self->begin);
	U_ADDR_SIZE_OR_RET_FALSE(self->end);
	return true;
}

RZ_IPI bool Range_is_end(RzBinDwarfRange *self) {
	return self->begin == 0 && self->end == 0;
}

RZ_IPI bool Range_is_base_address(RzBinDwarfRange *self, ut8 address_size) {
	return self->begin == (~0ULL >> (64 - address_size * 8));
}

RZ_IPI void Range_add_base_address(RzBinDwarfRange *self, ut64 base_address, ut8 address_size) {
	ut64 mask = address_size == 0 ? ~0ULL : (~0ULL >> (64 - address_size * 8));
	self->begin = (base_address + self->begin) & mask;
	self->end = (base_address + self->end) & mask;
}

RZ_IPI void Range_free(RzBinDwarfRange *self) {
	if (!self) {
		return;
	}
	free(self);
}

RZ_IPI bool RzBinDwarfRawRngListEntry_parse(RzBinDwarfRawRngListEntry *out, RzBuffer *buffer, RzBinDwarfEncoding *encoding, RzBinDwarfRngListsFormat format) {
	RzBinDwarfRawRngListEntry entry = { 0 };
	bool big_endian = encoding->big_endian;
	switch (format) {
	case RzBinDwarfRngListsFormat_Bare: {
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
	case RzBinDwarfRngListsFormat_Rle: {
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
			U_ADDR_SIZE_OR_RET_FALSE(entry.base_address.addr);
			break;
		case DW_RLE_start_end:
			U_ADDR_SIZE_OR_RET_FALSE(entry.start_end.begin);
			U_ADDR_SIZE_OR_RET_FALSE(entry.start_end.end);
			break;
		case DW_RLE_start_length:
			U_ADDR_SIZE_OR_RET_FALSE(entry.start_length.begin);
			ULE128_OR_RET_FALSE(entry.start_length.length);
			break;
		default: {
			RZ_LOG_DEBUG("Invalid address range list encoding: %u\n", entry.encoding);
			return false;
		}
		}
	}
	}
	memcpy(out, &entry, sizeof(entry));
	return true;
}

void RzBinDwarfRawRngListEntry_free(RzBinDwarfRawRngListEntry *self) {
	free(self);
}

void RzBinDwarfRngList_free(RzBinDwarfRngList *self) {
	rz_pvector_fini(&self->raw_entries);
	rz_pvector_fini(&self->entries);
	free(self);
}

void HTUP_RzBinDwarfRngList_free(HtUPKv *kv) {
	RzBinDwarfRngList_free(kv->value);
}

RZ_IPI void RzBinDwarfRngListTable_free(RzBinDwarfRngListTable *self) {
	if (!self) {
		return;
	}
	rz_buf_free(self->debug_ranges);
	rz_buf_free(self->debug_rnglists);
	ht_up_free(self->rnglist_by_offset);
	free(self);
}

bool RzBinDwarfRngListTable_convert_raw(RzBinDwarfRngListTable *self, RzBinDwarfRawRngListEntry *raw, RzBinDwarfRange **out) {
	ut64 mask = self->encoding.address_size == 0 ? ~0ULL : (~0ULL >> (64 - self->encoding.address_size * 8));
	ut64 tombstone = self->encoding.version <= 4 ? mask - 1
						     : mask;
	RzBinDwarfRange *range = NULL;
	if (raw->is_address_or_offset_pair) {
		if (self->base_address == tombstone) {
			OK_None;
		}
		range = RZ_NEW0(RzBinDwarfRange);
		RET_FALSE_IF_FAIL(range);
		range->begin = raw->address_or_offset_pair.begin;
		range->end = raw->address_or_offset_pair.end;
		Range_add_base_address(range, self->base_address, self->encoding.address_size);
	} else {
		switch (raw->encoding) {
		case DW_RLE_end_of_list: break;
		case DW_RLE_base_address:
			self->base_address = raw->base_address.addr;
			OK_None;
		case DW_RLE_base_addressx:
			RET_FALSE_IF_FAIL(self->debug_addr);
			RET_FALSE_IF_FAIL(DebugAddr_get_address(self->debug_addr, &self->base_address,
				self->encoding.address_size, self->encoding.big_endian,
				self->base_address, raw->base_addressx.addr));
			OK_None;
		case DW_RLE_startx_endx:
			range = RZ_NEW0(RzBinDwarfRange);
			RET_FALSE_IF_FAIL(range);
			range->begin = raw->startx_endx.begin;
			range->end = raw->startx_endx.end;
			break;
		case DW_RLE_startx_length:
			range = RZ_NEW0(RzBinDwarfRange);
			RET_FALSE_IF_FAIL(range);
			range->begin = raw->startx_length.begin;
			range->end = (raw->startx_length.length + raw->startx_length.begin) & mask;
			break;
		case DW_RLE_offset_pair:
			if (self->base_address == tombstone) {
				OK_None;
			}
			range = RZ_NEW0(RzBinDwarfRange);
			RET_FALSE_IF_FAIL(range);
			range->begin = raw->address_or_offset_pair.begin;
			range->end = raw->address_or_offset_pair.end;
			Range_add_base_address(range, self->base_address, self->encoding.address_size);
			break;
		case DW_RLE_start_end:
			range = RZ_NEW0(RzBinDwarfRange);
			RET_FALSE_IF_FAIL(range);
			range->begin = raw->startx_endx.begin;
			range->end = raw->startx_endx.end;
			break;
		case DW_RLE_start_length:
			range = RZ_NEW0(RzBinDwarfRange);
			RET_FALSE_IF_FAIL(range);
			range->begin = raw->startx_length.begin;
			range->end = (raw->startx_length.length + raw->startx_length.begin) & mask;
			break;
		}
	}

	if (!range) {
		return false;
	}
	if (range->begin == tombstone) {
		free(range);
		OK_None;
	}
	if (range->begin > range->end) {
		RZ_LOG_WARN("Invalid Address Range (0x%" PFMT64x ",0x%" PFMT64x ")\n", range->begin, range->end);
		free(range);
		return false;
	}

	*out = range;
	return true;
}

static inline bool RzBinDwarfRngListTable_parse(RzBinDwarfRngListTable *self, RzBuffer *buffer, RzBinDwarfEncoding *encoding, RzBinDwarfRngListsFormat format) {
	RzBinDwarfRngList *rnglist = RZ_NEW0(RzBinDwarfRngList);
	rnglist->offset = rz_buf_tell(buffer);
	rz_pvector_init(&rnglist->raw_entries, (RzPVectorFree)RzBinDwarfRawRngListEntry_free);
	rz_pvector_init(&rnglist->entries, (RzPVectorFree)Range_free);

	while (true) {
		RzBinDwarfRawRngListEntry *raw_entry = RZ_NEW0(RzBinDwarfRawRngListEntry);
		GOTO_IF_FAIL(raw_entry, err1);
		RzBinDwarfRange *range = NULL;
		GOTO_IF_FAIL(RzBinDwarfRawRngListEntry_parse(raw_entry, buffer, encoding, format), err1);
		rz_pvector_push(&rnglist->raw_entries, raw_entry);
		if (raw_entry->encoding == DW_RLE_end_of_list && !raw_entry->is_address_or_offset_pair) {
			break;
		}
		GOTO_IF_FAIL(RzBinDwarfRngListTable_convert_raw(self, raw_entry, &range), err2);
		if (!range) {
			continue;
		}
		rz_pvector_push(&rnglist->entries, range);
		continue;
	err1:
		RzBinDwarfRawRngListEntry_free(raw_entry);
		RzBinDwarfRngList_free(rnglist);
		return false;
	err2:
		Range_free(range);
	}
	ht_up_update(self->rnglist_by_offset, rnglist->offset, rnglist);
	return true;
}

RZ_API RZ_OWN RzBinDwarfRngListTable *rz_bin_dwarf_rnglists_new(RZ_BORROW RZ_NONNULL RzBinFile *bf, RZ_BORROW RZ_NONNULL RzBinDwarf *dw) {
	RET_NULL_IF_FAIL(bf && dw);
	RzBinDwarfRngListTable *self = RZ_NEW0(RzBinDwarfRngListTable);
	self->debug_addr = dw->addr;
	self->debug_ranges = get_section_buf(bf, ".debug_ranges");
	self->debug_rnglists = get_section_buf(bf, ".debug_rnglists");
	if (!(self->debug_ranges || self->debug_rnglists)) {
		RZ_LOG_DEBUG("No .debug_loc and .debug_loclists section found\n");
		RzBinDwarfRngListTable_free(self);
		return NULL;
	}
	self->rnglist_by_offset = ht_up_new(NULL, HTUP_RzBinDwarfRngList_free, NULL);
	return self;
}

/**
 * \brief Parse the RzBinDwarfRngList at the given offset
 * \param self  The RzBinDwarfRngListTable
 * \param encoding The RzBinDwarfEncoding
 * \param offset The offset to parse at
 * \return true on success, false otherwise
 */
RZ_API bool rz_bin_dwarf_rnglist_table_parse_at(RZ_BORROW RZ_NONNULL RzBinDwarfRngListTable *self, RZ_BORROW RZ_NONNULL RzBinDwarfEncoding *encoding, ut64 offset) {
	RET_FALSE_IF_FAIL(self);
	RzBuffer *buffer = self->debug_ranges;
	RzBinDwarfRngListsFormat format = RzBinDwarfRngListsFormat_Bare;
	ut64 old_offset = UT64_MAX;
	if (encoding->version == 5) {
		buffer = self->debug_rnglists;
		format = RzBinDwarfRngListsFormat_Rle;
		old_offset = rz_buf_tell(buffer);
		ERR_IF_FAIL(ListsHeader_parse(&self->hdr, buffer, encoding->big_endian));
	} else {
		old_offset = rz_buf_tell(buffer);
	}

	rz_buf_seek(buffer, (st64)offset, RZ_BUF_SET);
	ERR_IF_FAIL(RzBinDwarfRngListTable_parse(self, buffer, encoding, format));
	rz_buf_seek(buffer, (st64)old_offset, RZ_BUF_SET);
	return true;
err:
	rz_buf_seek(buffer, (st64)old_offset, RZ_BUF_SET);
	return false;
}

/**
 * \brief Similar to rz_bin_dwarf_rnglist_table_parse_at but parses all the RzBinDwarfRngList sequentially
 * \param self The RzBinDwarfRngListTable instance
 * \param encoding The RzBinDwarfEncoding instance
 * \return true on success, false otherwise
 */
RZ_API bool rz_bin_dwarf_rnglist_table_parse_all(RZ_BORROW RZ_NONNULL RzBinDwarfRngListTable *self, RZ_BORROW RZ_NONNULL RzBinDwarfEncoding *encoding) {
	RET_FALSE_IF_FAIL(self);
	RzBuffer *buffer = self->debug_ranges;
	RzBinDwarfRngListsFormat format = RzBinDwarfRngListsFormat_Bare;
	ut64 old_offset = UT64_MAX;
	if (encoding->version == 5) {
		buffer = self->debug_rnglists;
		RET_FALSE_IF_FAIL(buffer);
		old_offset = rz_buf_tell(buffer);
		format = RzBinDwarfRngListsFormat_Rle;
		RET_FALSE_IF_FAIL(ListsHeader_parse(&self->hdr, buffer, encoding->big_endian));
	} else {
		RET_FALSE_IF_FAIL(buffer);
		old_offset = rz_buf_tell(buffer);
	}

	if (self->hdr.offset_entry_count > 0) {
		for (ut32 i = 0; i < self->hdr.offset_entry_count; ++i) {
			ut64 offset = self->hdr.location_offsets[i];
			rz_buf_seek(buffer, (st64)offset, RZ_BUF_SET);
			RzBinDwarfRngListTable_parse(self, buffer, encoding, format);
		}
	} else {
		while (rz_buf_tell(buffer) < rz_buf_size(buffer)) {
			RzBinDwarfRngListTable_parse(self, buffer, encoding, format);
		}
	}

	rz_buf_seek(buffer, (st64)old_offset, RZ_BUF_SET);
	return self;
}
