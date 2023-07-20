// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

void RzBinDwarfRawLocListEntry_free(RzBinDwarfRawLocListEntry *self) {
	if (!self) {
		return;
	}
	RzBinDwarfBlock_fini(&self->address_or_offset_pair.data);
	free(self);
}

void RzBinDwarfLocationListEntry_fini(RzBinDwarfLocationListEntry *self) {
	if (!self) {
		return;
	}
	free(self->range);
	RzBinDwarfBlock_fini(self->expression);
	rz_bin_dwarf_location_free(self->location);
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
	bool big_endian = encoding->big_endian;
	switch (format) {
	case RzBinDwarfLocListsFormat_BARE: {
		RzBinDwarfRange range = { 0 };
		RET_FALSE_IF_FAIL(Range_parse(&range, buffer, encoding));
		if (Range_is_end(&range)) {
			return true;
		} else if (Range_is_base_address(&range, encoding->address_size)) {
			out->encoding = DW_LLE_base_address;
			out->base_address.addr = range.end;
		} else {
			out->is_address_or_offset_pair = true;
			out->address_or_offset_pair.begin = range.begin;
			out->address_or_offset_pair.end = range.end;
			RET_FALSE_IF_FAIL(parse_data(buffer, &out->address_or_offset_pair.data, encoding));
		}
		break;
	}
	case RzBinDwarfLocListsFormat_LLE: {
		ut8 byte = 0;
		U8_OR_RET_FALSE(byte);
		out->encoding = byte;
		switch (out->encoding) {
		case DW_LLE_end_of_list: return true;
		case DW_LLE_base_addressx:
			ULE128_OR_RET_FALSE(out->base_addressx.addr);
			break;
		case DW_LLE_startx_endx:
			ULE128_OR_RET_FALSE(out->startx_endx.begin);
			ULE128_OR_RET_FALSE(out->startx_endx.end);
			RET_FALSE_IF_FAIL(parse_data(buffer, &out->startx_endx.data, encoding));
			break;
		case DW_LLE_startx_length:
			ULE128_OR_RET_FALSE(out->startx_length.begin);
			if (encoding->version >= 5) {
				ULE128_OR_RET_FALSE(out->startx_length.length);
			} else {
				U32_OR_RET_FALSE(out->startx_length.length);
			}
			RET_FALSE_IF_FAIL(parse_data(buffer, &out->startx_length.data, encoding));
			break;
		case DW_LLE_offset_pair:
			ULE128_OR_RET_FALSE(out->offset_pair.begin);
			ULE128_OR_RET_FALSE(out->offset_pair.end);
			RET_FALSE_IF_FAIL(parse_data(buffer, &out->offset_pair.data, encoding));
			break;
		case DW_LLE_default_location:
			RET_FALSE_IF_FAIL(parse_data(buffer, &out->default_location.data, encoding));
			break;
		case DW_LLE_base_address:
			UX_OR_RET_FALSE(out->base_address.addr, encoding->address_size);
			break;
		case DW_LLE_start_end:
			UX_OR_RET_FALSE(out->start_end.begin, encoding->address_size);
			UX_OR_RET_FALSE(out->start_end.end, encoding->address_size);
			RET_FALSE_IF_FAIL(parse_data(buffer, &out->start_end.data, encoding));
			break;
		case DW_LLE_start_length:
			UX_OR_RET_FALSE(out->start_length.begin, encoding->address_size);
			ULE128_OR_RET_FALSE(out->start_length.length);
			RET_FALSE_IF_FAIL(parse_data(buffer, &out->start_length.data, encoding));
			break;
		case DW_LLE_GNU_view_pair:
			RZ_LOG_ERROR("GNU_view_pair not implemented");
			return false;
		}
		break;
	}
	}
	return true;
}

void RzBinDwarfLocationListEntry_free(RzBinDwarfLocationListEntry *self) {
	if (!self) {
		return;
	}
	free(self->range);
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
		RET_FALSE_IF_FAIL(range);
		range->begin = raw->address_or_offset_pair.begin;
		range->end = raw->address_or_offset_pair.end;
		Range_add_base_address(range, self->base_address, self->encoding.address_size);
		data = RzBinDwarfBlock_clone(&raw->address_or_offset_pair.data);
		RET_FALSE_IF_FAIL(data);
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
			RET_FALSE_IF_FAIL(range);
			range->begin = raw->startx_endx.begin;
			range->end = raw->startx_endx.end;
			break;
		case DW_LLE_startx_length:
			range = RZ_NEW0(RzBinDwarfRange);
			RET_FALSE_IF_FAIL(range);
			range->begin = raw->startx_length.begin;
			range->end = (raw->startx_length.length + raw->startx_length.begin) & mask;
			break;
		case DW_LLE_offset_pair:
			if (self->base_address == tombstone) {
				OK_None;
			}
			range = RZ_NEW0(RzBinDwarfRange);
			RET_FALSE_IF_FAIL(range);
			range->begin = raw->address_or_offset_pair.begin;
			range->end = raw->address_or_offset_pair.end;
			Range_add_base_address(range, self->base_address, self->encoding.address_size);
			data = RzBinDwarfBlock_clone(&raw->address_or_offset_pair.data);
			RET_FALSE_IF_FAIL(data);
			break;
		case DW_LLE_default_location: break;
		case DW_LLE_start_end:
			range = RZ_NEW0(RzBinDwarfRange);
			RET_FALSE_IF_FAIL(range);
			range->begin = raw->startx_endx.begin;
			range->end = raw->startx_endx.end;
			break;
		case DW_LLE_start_length:
			range = RZ_NEW0(RzBinDwarfRange);
			RET_FALSE_IF_FAIL(range);
			range->begin = raw->startx_length.begin;
			range->end = (raw->startx_length.length + raw->startx_length.begin) & mask;
			break;
		case DW_LLE_GNU_view_pair: break;
		}
	}

	if (!range) {
		return false;
	}
	if (range->begin == tombstone) {
		free(range);
		RzBinDwarfBlock_free(data);
		OK_None;
	}
	if (range->begin > range->end) {
		RZ_LOG_ERROR("Invalid Address Range (0x%" PFMT64x ",0x%" PFMT64x ")\n", range->begin, range->end);
		free(range);
		RzBinDwarfBlock_free(data);
		return false;
	}

	*out = RZ_NEW0(RzBinDwarfLocationListEntry);
	(*out)->range = range;
	(*out)->expression = data;
	return true;
}

void loclist_free(RzBinDwarfLocList *self) {
	if (!self) {
		return;
	}
	rz_pvector_fini(&self->raw_entries);
	rz_pvector_fini(&self->entries);
	free(self);
}

static inline bool loclist_parse(RzBinDwarfLocListTable *self, RzBuffer *buffer, RzBinDwarfEncoding *encoding, RzBinDwarfLocListsFormat format) {
	RzBinDwarfLocList *loclist = RZ_NEW0(RzBinDwarfLocList);
	loclist->offset = rz_buf_tell(buffer);
	rz_pvector_init(&loclist->raw_entries, (RzPVectorFree)RzBinDwarfRawLocListEntry_free);
	rz_pvector_init(&loclist->entries, (RzPVectorFree)RzBinDwarfLocationListEntry_fini);
	while (true) {
		RzBinDwarfRawLocListEntry *raw_entry = RZ_NEW0(RzBinDwarfRawLocListEntry);
		GOTO_IF_FAIL(raw_entry, err1);
		RzBinDwarfLocationListEntry *entry = NULL;
		GOTO_IF_FAIL(RawLocListEntry_parse(raw_entry, buffer, encoding, format), err1);
		rz_pvector_push(&loclist->raw_entries, raw_entry);
		if (raw_entry->encoding == DW_LLE_end_of_list && !raw_entry->is_address_or_offset_pair) {
			break;
		}

		GOTO_IF_FAIL(convert_raw(self, raw_entry, &entry), err2);
		if (!entry) {
			continue;
		}
		rz_pvector_push(&loclist->entries, entry);
		continue;
	err1:
		RzBinDwarfRawLocListEntry_free(raw_entry);
		loclist_free(loclist);
		return false;
	err2:
		RzBinDwarfLocationListEntry_free(entry);
	}
	ht_up_update(self->loclist_by_offset, loclist->offset, loclist);
	return true;
}

RZ_API bool rz_bin_dwarf_loclist_table_parse_at(RZ_BORROW RZ_NONNULL RzBinDwarfLocListTable *self, RZ_BORROW RZ_NONNULL RzBinDwarfEncoding *encoding, ut64 offset) {
	RzBuffer *buffer = encoding->version == 5 ? self->debug_loclists : self->debug_loc;
	RzBinDwarfLocListsFormat format = encoding->version <= 4 ? RzBinDwarfLocListsFormat_BARE : RzBinDwarfLocListsFormat_LLE;
	buffer = rz_buf_new_with_buf(buffer);
	rz_buf_seek(buffer, (st64)offset, RZ_BUF_SET);
	RET_FALSE_IF_FAIL(loclist_parse(self, buffer, encoding, format));
	return true;
}

RZ_API bool rz_bin_dwarf_loclist_table_parse_all(RZ_BORROW RZ_NONNULL RzBinDwarfLocListTable *self, RZ_BORROW RZ_NONNULL RzBinDwarfEncoding *encoding) {
	RET_NULL_IF_FAIL(self);
	RzBuffer *buffer = self->debug_loc;
	RzBinDwarfLocListsFormat format = RzBinDwarfLocListsFormat_BARE;
	if (encoding->version == 5) {
		buffer = self->debug_loclists;
		format = RzBinDwarfLocListsFormat_LLE;
		buffer = rz_buf_new_with_buf(buffer);
		RET_FALSE_IF_FAIL(ListsHeader_parse(&self->hdr, buffer, encoding->big_endian));
	} else {
		buffer = rz_buf_new_with_buf(buffer);
	}

	if (self->hdr.offset_entry_count > 0) {
		for (ut32 i = 0; i < self->hdr.offset_entry_count; ++i) {
			ut64 offset = self->hdr.location_offsets[i];
			rz_buf_seek(buffer, (st64)offset, RZ_BUF_SET);
			GOTO_IF_FAIL(loclist_parse(self, buffer, encoding, format), err);
		}
	} else {
		while (rz_buf_tell(buffer) < rz_buf_size(buffer)) {
			GOTO_IF_FAIL(loclist_parse(self, buffer, encoding, format), err);
		}
	}

	rz_buf_free(buffer);
	return true;
err:
	rz_buf_free(buffer);
	return false;
}

void HTUP_RzBinDwarfLocList_free(HtUPKv *kv) {
	if (!kv) {
		return;
	}
	loclist_free(kv->value);
}

RZ_API RZ_OWN RzBinDwarfLocListTable *rz_bin_dwarf_loclists_new(RZ_BORROW RZ_NONNULL RzBinFile *bf, RZ_BORROW RZ_NONNULL RzBinDwarf *dw) {
	RET_NULL_IF_FAIL(bf && dw);
	RzBinDwarfLocListTable *self = RZ_NEW0(RzBinDwarfLocListTable);
	self->debug_addr = dw->addr;
	self->debug_loc = get_section_buf(bf, ".debug_loc");
	self->debug_loclists = get_section_buf(bf, ".debug_loclists");
	if (!(self->debug_loc || self->debug_loclists)) {
		RZ_LOG_DEBUG("No .debug_loc and .debug_loclists section found\n");
		rz_bin_dwarf_loclists_free(self);
		return NULL;
	}
	self->loclist_by_offset = ht_up_new(NULL, HTUP_RzBinDwarfLocList_free, NULL);
	return self;
}

RZ_API void rz_bin_dwarf_loclists_free(RZ_OWN RZ_NULLABLE RzBinDwarfLocListTable *self) {
	if (!self) {
		return;
	}
	ht_up_free(self->loclist_by_offset);
	rz_buf_free(self->debug_loc);
	rz_buf_free(self->debug_loclists);
	free(self);
}

RZ_API void rz_bin_dwarf_location_free(RZ_BORROW RZ_NONNULL RzBinDwarfLocation *self) {
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

RZ_API RZ_OWN RzBinDwarfLocation *rz_bin_dwarf_location_clone(RZ_BORROW RZ_NONNULL RzBinDwarfLocation *self) {
	RzBinDwarfLocation *loc = RZ_NEWCOPY(RzBinDwarfLocation, self);
	assert(loc->kind != RzBinDwarfLocationKind_EVALUATION_WAITING);
	return loc;
}
