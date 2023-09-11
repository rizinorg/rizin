// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

static void RawLocListEntry_free(RzBinDwarfRawLocListEntry *self) {
	if (!self) {
		return;
	}
	if (self->is_address_or_offset_pair) {
		RzBinDwarfBlock_fini(&self->address_or_offset_pair.data);
	} else {
		switch (self->encoding) {
		case DW_LLE_end_of_list:
		case DW_LLE_base_addressx: break;
		case DW_LLE_startx_endx: RzBinDwarfBlock_fini(&self->startx_endx.data); break;
		case DW_LLE_startx_length: RzBinDwarfBlock_fini(&self->startx_length.data); break;
		case DW_LLE_offset_pair: RzBinDwarfBlock_fini(&self->offset_pair.data); break;
		case DW_LLE_default_location: RzBinDwarfBlock_fini(&self->default_location.data); break;
		case DW_LLE_base_address: break;
		case DW_LLE_start_end: RzBinDwarfBlock_fini(&self->start_end.data); break;
		case DW_LLE_start_length: RzBinDwarfBlock_fini(&self->start_length.data); break;
		case DW_LLE_GNU_view_pair: break;
		}
	}

	free(self);
}

static void LocListEntry_fini(RzBinDwarfLocListEntry *self) {
	Range_free(self->range);
	RzBinDwarfBlock_free(self->expression);
	rz_bin_dwarf_location_free(self->location);
}

static void LocListEntry_free(RzBinDwarfLocListEntry *self) {
	if (!self) {
		return;
	}
	LocListEntry_fini(self);
	free(self);
}

static inline bool parse_data(
	RzBinEndianReader *reader, RzBinDwarfBlock *block, RzBinDwarfEncoding *encoding) {
	if (encoding->version >= 5) {
		ULE128_OR_RET_FALSE(block->length);
	} else {
		U_OR_RET_FALSE(16, block->length);
	}
	RET_FALSE_IF_FAIL(read_block(reader, block));
	return true;
}

static bool RawLocListEntry_parse(
	RzBinDwarfRawLocListEntry *out,
	RzBinEndianReader *reader,
	RzBinDwarfEncoding *encoding,
	RzBinDwarfLocListsFormat format) {
	switch (format) {
	case RzBinDwarfLocListsFormat_BARE: {
		RzBinDwarfRange range = { 0 };
		RET_FALSE_IF_FAIL(Range_parse(&range, reader, encoding->address_size));
		if (Range_is_end(&range)) {
			return true;
		} else if (Range_is_base_address(&range, encoding->address_size)) {
			out->encoding = DW_LLE_base_address;
			out->base_address.addr = range.end;
		} else {
			out->is_address_or_offset_pair = true;
			out->address_or_offset_pair.begin = range.begin;
			out->address_or_offset_pair.end = range.end;
			RET_FALSE_IF_FAIL(parse_data(
				reader, &out->address_or_offset_pair.data, encoding));
		}
		break;
	}
	case RzBinDwarfLocListsFormat_LLE: {
		U8_OR_RET_FALSE(out->encoding);
		switch (out->encoding) {
		case DW_LLE_end_of_list: return true;
		case DW_LLE_base_addressx:
			ULE128_OR_RET_FALSE(out->base_addressx.addr);
			break;
		case DW_LLE_startx_endx:
			ULE128_OR_RET_FALSE(out->startx_endx.begin);
			ULE128_OR_RET_FALSE(out->startx_endx.end);
			RET_FALSE_IF_FAIL(parse_data(reader, &out->startx_endx.data, encoding));
			break;
		case DW_LLE_startx_length:
			ULE128_OR_RET_FALSE(out->startx_length.begin);
			if (encoding->version >= 5) {
				ULE128_OR_RET_FALSE(out->startx_length.length);
			} else {
				U_OR_RET_FALSE(32, out->startx_length.length);
			}
			RET_FALSE_IF_FAIL(parse_data(reader, &out->startx_length.data, encoding));
			break;
		case DW_LLE_offset_pair:
			ULE128_OR_RET_FALSE(out->offset_pair.begin);
			ULE128_OR_RET_FALSE(out->offset_pair.end);
			RET_FALSE_IF_FAIL(parse_data(reader, &out->offset_pair.data, encoding));
			break;
		case DW_LLE_default_location:
			RET_FALSE_IF_FAIL(parse_data(reader, &out->default_location.data, encoding));
			break;
		case DW_LLE_base_address:
			RET_FALSE_IF_FAIL(read_address(reader, &out->base_address.addr, encoding->address_size));
			break;
		case DW_LLE_start_end:
			RET_FALSE_IF_FAIL(read_address(reader, &out->start_end.begin, encoding->address_size));
			RET_FALSE_IF_FAIL(read_address(reader, &out->start_end.end, encoding->address_size));
			RET_FALSE_IF_FAIL(parse_data(reader, &out->start_end.data, encoding));
			break;
		case DW_LLE_start_length:
			RET_FALSE_IF_FAIL(read_address(reader, &out->start_length.begin, encoding->address_size));
			ULE128_OR_RET_FALSE(out->start_length.length);
			RET_FALSE_IF_FAIL(parse_data(reader, &out->start_length.data, encoding));
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

static bool convert_raw(
	RzBinDwarfLocLists *self,
	RzBinDwarfAddr *addr,
	RzBinDwarfCompUnit *cu,
	RzBinDwarfRawLocListEntry *raw,
	RZ_OUT RzBinDwarfLocListEntry **out) {
	RzBinDwarfEncoding *encoding = &cu->hdr.encoding;
	ut64 mask = encoding->address_size == 0 ? ~0ULL
						: (~0ULL >> (64 - encoding->address_size * 8));
	ut64 tombstone = encoding->version <= 4 ? mask - 1
						: mask;
	RzBinDwarfRange *range = NULL;
	RzBinDwarfBlock *data = NULL;
	if (raw->is_address_or_offset_pair) {
		if (self->base_address == tombstone) {
			OK_None;
		}
		range = RZ_NEW0(RzBinDwarfRange);
		ERR_IF_FAIL(range);
		range->begin = raw->address_or_offset_pair.begin;
		range->end = raw->address_or_offset_pair.end;
		Range_add_base_address(range, self->base_address, encoding->address_size);
		data = RzBinDwarfBlock_clone(&raw->address_or_offset_pair.data);
		ERR_IF_FAIL(data);
	} else {
		switch (raw->encoding) {
		case DW_LLE_end_of_list: break;
		case DW_LLE_base_address:
			self->base_address = raw->base_address.addr;
			OK_None;
		case DW_LLE_base_addressx:
			ERR_IF_FAIL(DebugAddr_get_address(
				addr, &self->base_address,
				encoding->address_size, cu->addr_base, raw->base_addressx.addr));
			OK_None;
		case DW_LLE_startx_endx:
			range = RZ_NEW0(RzBinDwarfRange);
			ERR_IF_FAIL(range);
			ERR_IF_FAIL(DebugAddr_get_address(
				addr, &range->begin,
				encoding->address_size, cu->addr_base, raw->startx_endx.begin));
			ERR_IF_FAIL(DebugAddr_get_address(
				addr, &range->end,
				encoding->address_size, cu->addr_base, raw->startx_endx.end));
			break;
		case DW_LLE_startx_length:
			range = RZ_NEW0(RzBinDwarfRange);
			ERR_IF_FAIL(range);
			ERR_IF_FAIL(DebugAddr_get_address(
				addr, &range->begin,
				encoding->address_size, cu->addr_base, raw->startx_length.begin));
			range->end = (raw->startx_length.length + raw->startx_length.begin) & mask;
			break;
		case DW_LLE_offset_pair:
			if (self->base_address == tombstone) {
				OK_None;
			}
			range = RZ_NEW0(RzBinDwarfRange);
			ERR_IF_FAIL(range);
			range->begin = raw->address_or_offset_pair.begin;
			range->end = raw->address_or_offset_pair.end;
			Range_add_base_address(range, self->base_address, encoding->address_size);
			data = RzBinDwarfBlock_clone(&raw->address_or_offset_pair.data);
			ERR_IF_FAIL(data);
			break;
		case DW_LLE_default_location: break;
		case DW_LLE_start_end:
			range = RZ_NEW0(RzBinDwarfRange);
			ERR_IF_FAIL(range);
			range->begin = raw->startx_endx.begin;
			range->end = raw->startx_endx.end;
			break;
		case DW_LLE_start_length:
			range = RZ_NEW0(RzBinDwarfRange);
			ERR_IF_FAIL(range);
			range->begin = raw->startx_length.begin;
			range->end = (raw->startx_length.length + raw->startx_length.begin) & mask;
			break;
		case DW_LLE_GNU_view_pair:
			rz_warn_if_reached();
			break;
		}
	}

	ERR_IF_FAIL(range);
	if (range->begin == tombstone) {
		Range_free(range);
		RzBinDwarfBlock_free(data);
		OK_None;
	}
	if (range->begin > range->end) {
		RZ_LOG_VERBOSE("Invalid Address Range (0x%" PFMT64x ",0x%" PFMT64x ")\n", range->begin, range->end);
		goto err;
	}

	*out = RZ_NEW0(RzBinDwarfLocListEntry);
	ERR_IF_FAIL(*out);
	(*out)->range = range;
	(*out)->expression = data;
	return true;
err:
	Range_free(range);
	RzBinDwarfBlock_free(data);
	return false;
}

static void LocList_free(RzBinDwarfLocList *self) {
	if (!self) {
		return;
	}
	rz_pvector_fini(&self->raw_entries);
	rz_pvector_fini(&self->entries);
	free(self);
}

static bool LocList_parse(
	RzBinDwarfLocLists *self, RzBinDwarfAddr *addr, RzBinDwarfCompUnit *cu) {
	rz_return_val_if_fail(self && cu, false);
	RzBinEndianReader *reader = self->reader;
	RzBinDwarfLocListsFormat format = cu->hdr.encoding.version <= 4
		? RzBinDwarfLocListsFormat_BARE
		: RzBinDwarfLocListsFormat_LLE;
	RzBinDwarfLocList *loclist = RZ_NEW0(RzBinDwarfLocList);
	RET_FALSE_IF_FAIL(loclist);
	loclist->offset = rz_buf_tell(reader->buffer);
	rz_pvector_init(&loclist->raw_entries, (RzPVectorFree)RawLocListEntry_free);
	rz_pvector_init(&loclist->entries, (RzPVectorFree)LocListEntry_free);
	while (true) {
		RzBinDwarfRawLocListEntry *raw_entry = RZ_NEW0(RzBinDwarfRawLocListEntry);
		RzBinDwarfLocListEntry *entry = NULL;
		ERR_IF_FAIL(raw_entry);
		ERR_IF_FAIL(RawLocListEntry_parse(raw_entry, self->reader, &cu->hdr.encoding, format));
		ERR_IF_FAIL(rz_pvector_push(&loclist->raw_entries, raw_entry));
		if (raw_entry->encoding == DW_LLE_end_of_list && !raw_entry->is_address_or_offset_pair) {
			break;
		}

		if (convert_raw(self, addr, cu, raw_entry, &entry)) {
			if (!entry) {
				continue;
			}
			ERR_IF_FAIL(rz_pvector_push(&loclist->entries, entry));
		} else {
			LocListEntry_free(entry);
		}
		continue;
	err:
		RawLocListEntry_free(raw_entry);
		LocList_free(loclist);
		return false;
	}
	ht_up_update(self->loclist_by_offset, loclist->offset, loclist);
	return true;
}

/**
 * \brief Parse a location list table at the given offset
 * \param self RzBinDwarfLocListTable instance
 * \param cu RzBinDwarfCompUnit instance
 * \param offset The offset to parse at
 * \return true on success, false otherwise
 */
RZ_API bool rz_bin_dwarf_loclists_parse_at(
	RZ_BORROW RZ_NONNULL RzBinDwarfLocLists *self,
	RZ_BORROW RZ_NONNULL RzBinDwarfAddr *addr,
	RZ_BORROW RZ_NONNULL RzBinDwarfCompUnit *cu,
	ut64 offset) {
	rz_return_val_if_fail(self && cu, false);
	ERR_IF_FAIL(rz_buf_seek(self->reader->buffer, offset, RZ_BUF_SET) >= 0);
	ERR_IF_FAIL(LocList_parse(self, addr, cu));
	return true;
err:
	return false;
}

RZ_API RzBinDwarfLocList *rz_bin_dwarf_loclists_get(
	RZ_BORROW RZ_NONNULL RzBinDwarfLocLists *self,
	RZ_BORROW RZ_NONNULL RzBinDwarfAddr *addr,
	RZ_BORROW RZ_NONNULL RzBinDwarfCompUnit *cu,
	ut64 offset) {
	rz_return_val_if_fail(self && cu, false);
	RzBinDwarfLocList *loclist = ht_up_find(self->loclist_by_offset, offset, NULL);
	if (loclist) {
		return loclist;
	}
	if (rz_bin_dwarf_loclists_parse_at(self, addr, cu, offset)) {
		return ht_up_find(self->loclist_by_offset, offset, NULL);
	}
	return NULL;
}

Ht_FREE_IMPL(UP, LocList, LocList_free);

/**
 * \brief Create a new RzBinDwarfLocListTable instance,
 *        takes ownership of the buffers, and any of them must be non-NULL
 * \param debug_loc .debug_loc section buffer
 * \param debug_loc_lists .debug_loclists section buffer
 * \param dw RzBinDWARF instance
 * \return RzBinDwarfLocListTable instance on success, NULL otherwise
 */
RZ_API RZ_OWN RzBinDwarfLocLists *rz_bin_dwarf_loclists_new(RzBinEndianReader *reader) {
	rz_return_val_if_fail(reader, NULL);
	RzBinDwarfLocLists *self = RZ_NEW0(RzBinDwarfLocLists);
	RET_NULL_IF_FAIL(self);
	self->reader = reader;
	self->loclist_by_offset = ht_up_new(NULL, HtUP_LocList_free, NULL);
	if (reader->section->name && rz_str_strchr(reader->section->name, "debug_loclists")) {
		ListsHdr_parse(&self->hdr, reader);
	}
	return self;
}

/**
 * \brief Create a new RzBinDwarfLocListTable instance
 * \param bf RzBinFile instance
 * \param dw RzBinDwarf instance
 * \return RzBinDwarfLocListTable instance on success, NULL otherwise
 */
RZ_API RZ_OWN RzBinDwarfLocLists *rz_bin_dwarf_loclists_new_from_file(RZ_BORROW RZ_NONNULL RzBinFile *bf) {
	RET_NULL_IF_FAIL(bf);
	RzBinEndianReader *reader = RzBinEndianReader_from_file(bf, ".debug_loc");
	reader = reader ? reader : RzBinEndianReader_from_file(bf, ".debug_loclists");
	RET_NULL_IF_FAIL(reader);
	return rz_bin_dwarf_loclists_new(reader);
}

RZ_API void rz_bin_dwarf_loclists_free(RZ_OWN RZ_NULLABLE RzBinDwarfLocLists *self) {
	if (!self) {
		return;
	}
	ht_up_free(self->loclist_by_offset);
	rz_buf_free(self->reader->buffer);
	free(self);
}

RZ_API void rz_bin_dwarf_location_fini(RZ_BORROW RZ_NONNULL RzBinDwarfLocation *self) {
	if (!self) {
		return;
	}
	switch (self->kind) {
	case RzBinDwarfLocationKind_BYTES:
		RzBinDwarfBlock_fini(&self->bytes);
		break;
	case RzBinDwarfLocationKind_EVALUATION_WAITING:
		rz_bin_dwarf_evaluation_free(self->eval_waiting.eval);
		RzBinDwarfEvaluationResult_free(self->eval_waiting.result);
		break;
	case RzBinDwarfLocationKind_COMPOSITE:
		rz_vector_free(self->composite);
		break;
	case RzBinDwarfLocationKind_LOCLIST:
	default: break;
	}
}

RZ_API void rz_bin_dwarf_location_free(RZ_BORROW RZ_NONNULL RzBinDwarfLocation *self) {
	if (!self) {
		return;
	}
	rz_bin_dwarf_location_fini(self);
	free(self);
}

/**
 * \brief Clone a RzBinDwarfLocation instance
 * \param self RzBinDwarfLocation instance
 * \return RzBinDwarfLocation instance on success, NULL otherwise
 */
RZ_API RZ_OWN RzBinDwarfLocation *rz_bin_dwarf_location_clone(RZ_BORROW RZ_NONNULL RzBinDwarfLocation *self) {
	rz_return_val_if_fail(self &&
			self->kind != RzBinDwarfLocationKind_EVALUATION_WAITING,
		NULL);
	RzBinDwarfLocation *loc = RZ_NEWCOPY(RzBinDwarfLocation, self);
	switch (loc->kind) {
	case RzBinDwarfLocationKind_COMPOSITE:
		loc->composite = rz_vector_clone(self->composite);
		break;
	default:
		break;
	}
	return loc;
}
