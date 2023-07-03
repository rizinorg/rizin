// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

static inline ut64 get_max_offset(size_t addr_size) {
	switch (addr_size) {
	case 2:
		return UT16_MAX;
	case 4:
		return UT32_MAX;
	case 8:
		return UT64_MAX;
	default:
		rz_warn_if_reached();
		break;
	}
	return 0;
}

static void block_free(RzBinDwarfBlock *block) {
	if (!block) {
		return;
	}
	free(block->data);
	free(block);
}

static bool parse_data(RzBuffer *buffer, RzBinDwarfBlock *block, RzBinDwarfEncoding *encoding) {
	bool big_endian = encoding->big_endian;
	if (encoding->version >= 5) {
		ULE128_OR_RET_FALSE(block->length);
	} else {
		U16_OR_RET_FALSE(block->length);
	}
	RET_FALSE_IF_FAIL(buf_read_block(buffer, block));
	return true;
}

static bool RawLocListEntry_parse(RzBinDwarfRawLocListEntry *out, RzBuffer *buffer, RzBinDwarfEncoding *encoding, RzBinDwarfLocListsFormat format) {
	RzBinDwarfRawLocListEntry entry = { 0 };
	bool big_endian = encoding->big_endian;
	switch (format) {
	case LOCLISTSFORMAT_BARE: {
		RzBinDwarfRange range = { 0 };
		RET_FALSE_IF_FAIL(Range_parse(&range, buffer, encoding));
		if (Range_is_end(&range)) {
			return true;
		} else if (Range_is_base_address(&range, encoding->address_size)) {
			entry.encoding = DW_LLE_base_address;
			entry.base_address.addr = range.end;
		} else {
			entry.is_address_or_offset_pair = true;
			entry.address_or_offset_pair.begin = range.begin;
			entry.address_or_offset_pair.end = range.end;
			RET_FALSE_IF_FAIL(buf_read_block(buffer, &entry.address_or_offset_pair.data));
		}
		break;
	}
	case LOCLISTSFORMAT_LLE: {
		ut8 byte = 0;
		U8_OR_RET_FALSE(byte);
		entry.encoding = byte;
		switch (entry.encoding) {
		case DW_LLE_end_of_list: return true;
		case DW_LLE_base_addressx:
			ULE128_OR_RET_FALSE(entry.base_addressx.addr);
			break;
		case DW_LLE_startx_endx:
			ULE128_OR_RET_FALSE(entry.startx_endx.begin);
			ULE128_OR_RET_FALSE(entry.startx_endx.end);
			RET_FALSE_IF_FAIL(parse_data(buffer, &entry.startx_endx.data, encoding));
			break;
		case DW_LLE_startx_length:
			ULE128_OR_RET_FALSE(entry.startx_length.begin);
			if (encoding->version >= 5) {
				ULE128_OR_RET_FALSE(entry.startx_length.length);
			} else {
				U32_OR_RET_FALSE(entry.startx_length.length);
			}
			RET_FALSE_IF_FAIL(parse_data(buffer, &entry.startx_length.data, encoding));
			break;
		case DW_LLE_offset_pair:
			ULE128_OR_RET_FALSE(entry.offset_pair.begin);
			ULE128_OR_RET_FALSE(entry.offset_pair.end);
			RET_FALSE_IF_FAIL(parse_data(buffer, &entry.offset_pair.data, encoding));
			break;
		case DW_LLE_default_location:
			RET_FALSE_IF_FAIL(parse_data(buffer, &entry.default_location.data, encoding));
			break;
		case DW_LLE_base_address:
			UX_OR_RET_FALSE(entry.base_address.addr, encoding->address_size);
			break;
		case DW_LLE_start_end:
			UX_OR_RET_FALSE(entry.start_end.begin, encoding->address_size);
			UX_OR_RET_FALSE(entry.start_end.end, encoding->address_size);
			RET_FALSE_IF_FAIL(parse_data(buffer, &entry.start_end.data, encoding));
			break;
		case DW_LLE_start_length:
			UX_OR_RET_FALSE(entry.start_length.begin, encoding->address_size);
			ULE128_OR_RET_FALSE(entry.start_length.length);
			RET_FALSE_IF_FAIL(parse_data(buffer, &entry.start_length.data, encoding));
			break;
		case DW_LLE_GNU_view_pair: break;
		}
		break;
	}
	}
	memcpy(out, &entry, sizeof(entry));
	return true;
}

void RzBinDwarfLocationListEntry_free(RzBinDwarfLocationListEntry *self) {
	if (!self) {
		return;
	}
	free(self->range);
	RzBinDwarfBlock_free(self->data);
	free(self);
}

static bool convert_raw(RzBinDwarfLocLists *self, RzBinDwarfRawLocListEntry *raw, RzBinDwarfLocationListEntry **out) {
	ut64 mask = !0 >> (64 - self->encoding.address_size * 8);
	ut64 tombstone = self->encoding.version <= 4 ? mask - 1
						     : mask;
	RzBinDwarfRange *range = NULL;
	RzBinDwarfBlock *data = NULL;
	if (raw->is_address_or_offset_pair) {
		if (self->base_address == tombstone) {
			OK_None;
		}
		range = RZ_NEW0(RzBinDwarfRange);
		range->end = raw->address_or_offset_pair.begin;
		range->end = raw->address_or_offset_pair.end;
		Range_add_base_address(range, self->base_address, self->encoding.address_size);
		data = RzBinDwarfBlock_clone(&raw->address_or_offset_pair.data);
	} else {
		switch (raw->encoding) {
		case DW_LLE_end_of_list: break;
		case DW_LLE_base_addressx:
			self->base_address = raw->base_addressx.addr;
			OK_None;
		case DW_LLE_base_address:
			RET_FALSE_IF_FAIL(DebugAddr_get_address(self->debug_addr, &self->base_address,
				self->encoding.address_size, self->encoding.big_endian,
				self->base_address, raw->base_addressx.addr));
			OK_None;
		case DW_LLE_startx_endx:
			range = RZ_NEW0(RzBinDwarfRange);
			range->begin = raw->startx_endx.begin;
			range->end = raw->startx_endx.end;
			break;
		case DW_LLE_startx_length:
			range = RZ_NEW0(RzBinDwarfRange);
			range->begin = raw->startx_length.begin;
			range->end = (raw->startx_length.length + raw->startx_length.begin) & mask;
			break;
		case DW_LLE_offset_pair:
			if (self->base_address == tombstone) {
				OK_None;
			}
			range = RZ_NEW0(RzBinDwarfRange);
			range->end = raw->address_or_offset_pair.begin;
			range->end = raw->address_or_offset_pair.end;
			Range_add_base_address(range, self->base_address, self->encoding.address_size);
			data = RzBinDwarfBlock_clone(&raw->address_or_offset_pair.data);
			break;
		case DW_LLE_default_location: break;
		case DW_LLE_start_end:
			range = RZ_NEW0(RzBinDwarfRange);
			range->begin = raw->startx_endx.begin;
			range->end = raw->startx_endx.end;
			break;
		case DW_LLE_start_length:
			range = RZ_NEW0(RzBinDwarfRange);
			range->begin = raw->startx_length.begin;
			range->end = (raw->startx_length.length + raw->startx_length.begin) & mask;
			break;
		case DW_LLE_GNU_view_pair: break;
		}
	}
	if (range && range->begin == tombstone) {
		free(range);
		RzBinDwarfBlock_free(data);
		OK_None;
	}

	if (range && range->begin > range->end) {
		RZ_LOG_ERROR("Invalid Address Range\n");
		free(range);
		RzBinDwarfBlock_free(data);
		return false;
	}
	*out = RZ_NEW0(RzBinDwarfLocationListEntry);
	(*out)->range = range;
	(*out)->data = data;
	return true;
}

static bool LocLists_parse(RzBinDwarfLocLists *self, RzBuffer *buffer, RzBinDwarfLocListsFormat format) {
	while (true) {
		RzBinDwarfRawLocListEntry raw_entry = { 0 };
		RET_FALSE_IF_FAIL(RawLocListEntry_parse(&raw_entry, buffer, &self->encoding, format));
		if (raw_entry.encoding == DW_LLE_end_of_list) {
			break;
		}
		RzBinDwarfLocationListEntry *entry = NULL;
		RET_FALSE_IF_FAIL(convert_raw(self, &raw_entry, &entry));
		if (!entry) {
			break;
		}
		rz_vector_push(&self->raw_entries, &raw_entry);
		rz_vector_push(&self->entries, entry);
		ht_up_update(self->entry_by_offset, entry->range->begin, entry);
		RzBinDwarfLocationListEntry_free(entry);
	}
	return true;
}

void RzBinDwarfLocLists_free(RzBinDwarfLocLists *self) {
	if (!self) {
		return;
	}
	rz_vector_free(&self->raw_entries);
	rz_vector_free(&self->entries);
	ht_up_free(self->entry_by_offset);
	free(self);
}

RZ_IPI RzBinDwarfLocLists *bf_loclists_parse(RzBinFile *bf, RzBinDwarf *dw) {
	RET_NULL_IF_FAIL(bf && dw);
	RzBuffer *buffer = dw->encoding.version <= 4 ? get_section_buf(bf, ".debug_loc")
						     : get_section_buf(bf, ".debug_loclists");
	RET_FALSE_IF_FAIL(buffer);
	RzBinDwarfLocListsFormat format = dw->encoding.version <= 4 ? LOCLISTSFORMAT_BARE : LOCLISTSFORMAT_LLE;
	RzBinDwarfLocLists *self = RZ_NEW0(RzBinDwarfLocLists);
	self->encoding = dw->encoding;
	self->debug_addr = dw->addr;
	rz_vector_init(&self->raw_entries, sizeof(RzBinDwarfRawLocListEntry), NULL, NULL);
	rz_vector_init(&self->entries, sizeof(RzBinDwarfLocationListEntry), NULL, NULL);
	self->entry_by_offset = ht_up_new(NULL, NULL, NULL);
	GOTO_IF_FAIL(LocLists_parse(self, buffer, format), err);
	return self;
err:
	rz_buf_free(buffer);
	RzBinDwarfLocLists_free(self);
	return NULL;
}
