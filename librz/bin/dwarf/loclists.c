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

void RzBinDwarfRawLocListEntry_fini(RzBinDwarfRawLocListEntry *self, void *user) {
	if (!self) {
		return;
	}
	RzBinDwarfBlock_fini(&self->address_or_offset_pair.data);
}

void RzBinDwarfLocationListEntry_fini(RzBinDwarfLocationListEntry *self, void *user) {
	if (!self) {
		return;
	}
	free(self->range);
	RzBinDwarfBlock_free(self->data);
}

static inline bool parse_data(RzBuffer *buffer, RzBinDwarfBlock *block, RzBinDwarfEncoding *encoding) {
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
			parse_data(buffer, &entry.address_or_offset_pair.data, encoding);
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

static bool convert_raw(RzBinDwarfLocListTable *self, RzBinDwarfRawLocListEntry *raw, RzBinDwarfLocationListEntry **out) {
	ut64 mask = self->encoding.address_size == 0 ? ~0ULL : (~0ULL >> (64 - self->encoding.address_size * 8));
	ut64 tombstone = self->encoding.version <= 4 ? mask - 1
						     : mask;
	RzBinDwarfRange *range = NULL;
	RzBinDwarfBlock *data = NULL;
	if (raw->is_address_or_offset_pair) {
		if (self->base_address == tombstone) {
			OK_None;
		}
		range = RZ_NEW0(RzBinDwarfRange);
		range->begin = raw->address_or_offset_pair.begin;
		range->end = raw->address_or_offset_pair.end;
		Range_add_base_address(range, self->base_address, self->encoding.address_size);
		data = RzBinDwarfBlock_clone(&raw->address_or_offset_pair.data);
	} else {
		switch (raw->encoding) {
		case DW_LLE_end_of_list: break;
		case DW_LLE_base_address:
			self->base_address = raw->base_address.addr;
			OK_None;
		case DW_LLE_base_addressx:
			RET_FALSE_IF_FAIL(self->debug_addr);
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
			range->begin = raw->address_or_offset_pair.begin;
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
	if (!range) {
		return false;
	}
	*out = RZ_NEW0(RzBinDwarfLocationListEntry);
	(*out)->range = range;
	(*out)->data = data;
	return true;
}

static inline bool loclist_parse(RzBinDwarfLocListTable *self, RzBuffer *buffer, RzBinDwarfLocListsFormat format, RzBinDwarfEncoding *encoding) {
	while (true) {
		RzBinDwarfRawLocListEntry raw_entry = { 0 };
		RzBinDwarfLocationListEntry *entry = NULL;
		GOTO_IF_FAIL(RawLocListEntry_parse(&raw_entry, buffer, encoding, format), err);
		GOTO_IF_FAIL(convert_raw(self, &raw_entry, &entry), err);
		if (!entry) {
			break;
		}
		rz_vector_push(&self->raw_entries, &raw_entry);
		rz_vector_push(&self->entries, entry);
		ht_up_update(self->entry_by_offset, entry->range->begin, entry);
		continue;
	err:
		RzBinDwarfRawLocListEntry_fini(&raw_entry, NULL);
		RzBinDwarfLocationListEntry_free(entry);
		break;
	}
	return true;
}

RZ_API bool rz_bin_dwarf_loclist_table_parse_at(RzBinDwarfLocListTable *self, RzBinDwarfEncoding *encoding, ut64 offset) {
	RzBuffer *buffer = encoding->version == 5 ? self->debug_loclists : self->debug_loc;
	RzBinDwarfLocListsFormat format = encoding->version <= 4 ? LOCLISTSFORMAT_BARE : LOCLISTSFORMAT_LLE;
	buffer = rz_buf_new_with_buf(buffer);
	rz_buf_seek(buffer, (st64)offset, RZ_BUF_CUR);
	RET_FALSE_IF_FAIL(loclist_parse(self, buffer, format, encoding));
	return true;
}

RZ_API RzBinDwarfLocListTable *rz_bin_dwarf_loclist_table_parse_all(RzBinFile *bf, RzBinDwarf *dw) {
	RET_NULL_IF_FAIL(bf && dw);
	RzBinDwarfLocListTable *self = rz_bin_dwarf_loclists_new(bf, dw);
	RET_NULL_IF_FAIL(self);
	RzBuffer *buffer = dw->encoding.version == 5 ? self->debug_loclists : self->debug_loc;
	buffer = rz_buf_new_with_buf(buffer);
	if (dw->encoding.version == 5) {
		RET_FALSE_IF_FAIL(ListsHeader_parse(&self->hdr, buffer, dw->encoding.big_endian));
		// TODO: ut64 hdr_offset = rz_buf_tell(buffer);
		for (ut32 i = 0; i < self->hdr.offset_entry_count; ++i) {
			ut64 offset = self->hdr.location_offsets[i];
			rz_buf_seek(buffer, (st64)offset, RZ_BUF_SET);
			loclist_parse(self, buffer, LOCLISTSFORMAT_LLE, &dw->encoding);
		}
	} else {
		while (rz_buf_tell(buffer) < rz_buf_size(buffer)) {
			loclist_parse(self, buffer, LOCLISTSFORMAT_BARE, &dw->encoding);
		}
	}
	rz_buf_free(buffer);
	return self;
}

void RzBinDwarfLocLists_free(RzBinDwarfLocListTable *self);

void HTUP_RzBinDwarfLocationListEntry_free(HtUPKv *kv) {
	if (!kv) {
		return;
	}
	RzBinDwarfLocationListEntry_free(kv->value);
}

RZ_API RzBinDwarfLocListTable *rz_bin_dwarf_loclists_new(RzBinFile *bf, RzBinDwarf *dw) {
	RET_NULL_IF_FAIL(bf && dw);
	RzBinDwarfLocListTable *self = RZ_NEW0(RzBinDwarfLocListTable);
	self->debug_addr = dw->addr;
	self->debug_loc = get_section_buf(bf, ".debug_loc");
	self->debug_loclists = get_section_buf(bf, ".debug_loclists");
	if (!(self->debug_loc || self->debug_loclists)) {
		RZ_LOG_ERROR("No .debug_loc and .debug_loclists section found\n");
		RzBinDwarfLocLists_free(self);
		return NULL;
	}
	rz_vector_init(&self->raw_entries, sizeof(RzBinDwarfRawLocListEntry), (RzVectorFree)RzBinDwarfRawLocListEntry_fini, NULL);
	rz_vector_init(&self->entries, sizeof(RzBinDwarfLocationListEntry), (RzVectorFree)RzBinDwarfLocationListEntry_fini, NULL);
	self->entry_by_offset = ht_up_new(NULL, HTUP_RzBinDwarfLocationListEntry_free, NULL);
	return self;
}

RZ_IPI void RzBinDwarfLocLists_free(RzBinDwarfLocListTable *self) {
	if (!self) {
		return;
	}
	rz_vector_fini(&self->raw_entries);
	rz_vector_fini(&self->entries);
	ht_up_free(self->entry_by_offset);
	rz_buf_free(self->debug_loc);
	rz_buf_free(self->debug_loclists);
	free(self);
}

RZ_IPI void RzBinDwarfLocation_free(RzBinDwarfLocation *self) {
	if (!self) {
		return;
	}
	switch (self->kind) {
	case RzBinDwarfLocationKind_BYTES:
		RzBinDwarfBlock_fini(&self->bytes.value);
		break;
	default: break;
	}
	free(self);
}
