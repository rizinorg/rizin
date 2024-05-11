// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_IPI bool Range_parse(RzBinDwarfRange *self, RzBinEndianReader *R, ut8 address_size) {
	RET_FALSE_IF_FAIL(R_read_address(R, &self->begin, address_size));
	RET_FALSE_IF_FAIL(R_read_address(R, &self->end, address_size));
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

static bool RawRngListEntry_parse(
	RzBinDwarfRawRngListEntry *out,
	RzBinEndianReader *R,
	RzBinDwarfEncoding *encoding,
	RzBinDwarfRngListsFormat format) {
	RzBinDwarfRawRngListEntry entry = { 0 };
	switch (format) {
	case RzBinDwarfRngListsFormat_Bare: {
		RzBinDwarfRange range = { 0 };
		RET_FALSE_IF_FAIL(Range_parse(&range, R, encoding->address_size));
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
			RET_FALSE_IF_FAIL(R_read_address(R, &entry.base_address.addr, encoding->address_size));
			break;
		case DW_RLE_start_end:
			RET_FALSE_IF_FAIL(R_read_address(R, &entry.start_end.begin, encoding->address_size));
			RET_FALSE_IF_FAIL(R_read_address(R, &entry.start_end.end, encoding->address_size));
			break;
		case DW_RLE_start_length:
			RET_FALSE_IF_FAIL(R_read_address(R, &entry.start_length.begin, encoding->address_size));
			ULE128_OR_RET_FALSE(entry.start_length.length);
			break;
		default: {
			RZ_LOG_DEBUG("Invalid address range list encoding: %u\n", entry.encoding);
			return false;
		}
		}
		break;
	}
	default: {
		RZ_LOG_DEBUG("Invalid address range list format: %u\n", format);
		return false;
	}
	}
	memcpy(out, &entry, sizeof(entry));
	return true;
}

static void RawRngListEntry_free(RzBinDwarfRawRngListEntry *self) {
	free(self);
}

static void RngList_free(RzBinDwarfRngList *self) {
	rz_pvector_fini(&self->raw_entries);
	rz_pvector_fini(&self->entries);
	free(self);
}

RZ_IPI void RngLists_free(RzBinDwarfRngLists *self) {
	if (!self) {
		return;
	}

	R_free(self->ranges);
	R_free(self->rnglists);
	ht_up_free(self->by_offset);
	free(self);
}

static bool convert_raw(
	RzBinDwarfRngLists *self,
	RzBinDwarfCompUnit *cu,
	RzBinDwarfAddr *addr,
	RzBinDwarfRawRngListEntry *raw,
	RzBinDwarfRange **out) {
	RzBinDwarfEncoding *encoding = &cu->hdr.encoding;
	ut64 mask = encoding->address_size == 0 ? ~0ULL : (~0ULL >> (64 - encoding->address_size * 8));
	ut64 tombstone = encoding->version <= 4 ? mask - 1
						: mask;
	RzBinDwarfRange *range = NULL;
	if (raw->is_address_or_offset_pair) {
		if (self->base_address == tombstone) {
			*out = NULL;
			return true;
		}
		range = RZ_NEW0(RzBinDwarfRange);
		RET_FALSE_IF_FAIL(range);
		range->begin = raw->address_or_offset_pair.begin;
		range->end = raw->address_or_offset_pair.end;
		Range_add_base_address(range, self->base_address, encoding->address_size);
	} else {
		switch (raw->encoding) {
		case DW_RLE_end_of_list: break;
		case DW_RLE_base_address:
			self->base_address = raw->base_address.addr;
			*out = NULL;
			return true;
		case DW_RLE_base_addressx:
			RET_FALSE_IF_FAIL(rz_bin_dwarf_addr_get(addr, &self->base_address,
				cu->hdr.encoding.address_size, cu->addr_base, raw->base_addressx.addr));
			*out = NULL;
			return true;
		case DW_RLE_startx_endx:
			range = RZ_NEW0(RzBinDwarfRange);
			RET_FALSE_IF_FAIL(range);
			RET_FALSE_IF_FAIL(rz_bin_dwarf_addr_get(addr, &range->begin,
				cu->hdr.encoding.address_size, cu->addr_base, raw->startx_endx.begin));
			RET_FALSE_IF_FAIL(rz_bin_dwarf_addr_get(addr, &range->end,
				cu->hdr.encoding.address_size, cu->addr_base, raw->startx_endx.end));
			break;
		case DW_RLE_startx_length:
			range = RZ_NEW0(RzBinDwarfRange);
			RET_FALSE_IF_FAIL(range);
			RET_FALSE_IF_FAIL(rz_bin_dwarf_addr_get(addr, &range->begin,
				cu->hdr.encoding.address_size, cu->addr_base, raw->startx_length.begin));
			range->end = (raw->startx_length.length + raw->startx_length.begin) & mask;
			break;
		case DW_RLE_offset_pair:
			if (self->base_address == tombstone) {
				*out = NULL;
				return true;
			}
			range = RZ_NEW0(RzBinDwarfRange);
			RET_FALSE_IF_FAIL(range);
			range->begin = raw->address_or_offset_pair.begin;
			range->end = raw->address_or_offset_pair.end;
			Range_add_base_address(range, self->base_address, encoding->address_size);
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
		*out = NULL;
		return true;
	}
	if (range->begin > range->end) {
		RZ_LOG_VERBOSE("Invalid Address Range (0x%" PFMT64x ",0x%" PFMT64x ")\n", range->begin, range->end);
		free(range);
		return false;
	}

	*out = range;
	return true;
}

static bool RngList_at(
	RzBinDwarfRngLists *self,
	RzBinDwarfAddr *addr,
	RzBinDwarfCompUnit *cu,
	ut64 offset,
	RzBinDwarfRngList **out) {
	RzBinEndianReader *R = cu->hdr.encoding.version <= 4
		? self->ranges
		: self->rnglists;
	RzBinDwarfRngListsFormat format = cu->hdr.encoding.version <= 4
		? RzBinDwarfRngListsFormat_Bare
		: RzBinDwarfRngListsFormat_Rle;
	OK_OR(R && R_seek(R, offset, RZ_BUF_SET) && out, return false);

	RzBinDwarfRngList *rnglist = RZ_NEW0(RzBinDwarfRngList);
	RET_FALSE_IF_FAIL(rnglist);
	rnglist->offset = R_tell(R);
	rz_pvector_init(&rnglist->raw_entries, (RzPVectorFree)RawRngListEntry_free);
	rz_pvector_init(&rnglist->entries, (RzPVectorFree)Range_free);
	while (true) {
		RzBinDwarfRawRngListEntry *raw_entry = RZ_NEW0(RzBinDwarfRawRngListEntry);
		RzBinDwarfRange *range = NULL;
		GOTO_IF_FAIL(raw_entry && RawRngListEntry_parse(raw_entry, R, &cu->hdr.encoding, format),
			err1);
		rz_pvector_push(&rnglist->raw_entries, raw_entry);
		if (raw_entry->encoding == DW_RLE_end_of_list && !raw_entry->is_address_or_offset_pair) {
			break;
		}
		GOTO_IF_FAIL(convert_raw(self, cu, addr, raw_entry, &range), err2);
		if (!range) {
			continue;
		}
		rz_pvector_push(&rnglist->entries, range);
		continue;
	err1:
		RawRngListEntry_free(raw_entry);
		RngList_free(rnglist);
		return false;
	err2:
		Range_free(range);
	}
	ht_up_update(self->by_offset, rnglist->offset, rnglist, NULL);
	*out = rnglist;
	return true;
}

/**
 * \brief Create a new RzBinDwarfRngListTable from the given buffers
 *        takes ownership of the buffers, and any of them must be non-NULL
 * \param debug_ranges the .debug_ranges buffer
 * \param debug_rnglists  the .debug_rnglists buffer
 * \param dw the RzBinDWARF instance
 * \return RzBinDwarfRngListTable instance on success, NULL otherwise
 */
RZ_API RZ_OWN RzBinDwarfRngLists *rz_bin_dwarf_rnglists_new(
	RZ_OWN RZ_NULLABLE RzBinEndianReader *rnglists, RZ_OWN RZ_NULLABLE RzBinEndianReader *ranges) {
	rz_return_val_if_fail(rnglists || ranges, NULL);
	RzBinDwarfRngLists *self = RZ_NEW0(RzBinDwarfRngLists);
	RET_NULL_IF_FAIL(self);
	self->rnglists = rnglists;
	self->ranges = ranges;
	self->by_offset = ht_up_new(NULL, (HtUPFreeValue)RngList_free);
	return self;
}

/**
 * \brief Create a new RzBinDwarfRngListTable from the given RzBinFile
 * \param bf the RzBinFile
 * \param dw the RzBinDWARF instance
 * \return the RzBinDwarfRngListTable instance on success, NULL otherwise
 */
RZ_API RZ_OWN RzBinDwarfRngLists *rz_bin_dwarf_rnglists_new_from_file(
	RZ_BORROW RZ_NONNULL RzBinFile *bf, bool is_dwo) {
	RET_NULL_IF_FAIL(bf);
	RzBinEndianReader *rnglists = RzBinEndianReader_from_file(bf, ".debug_rnglists", is_dwo);
	RzBinEndianReader *ranges = RzBinEndianReader_from_file(bf, ".debug_ranges", is_dwo);
	if (!(rnglists || ranges)) {
		R_free(rnglists);
		R_free(ranges);
		return NULL;
	}
	return rz_bin_dwarf_rnglists_new(rnglists, ranges);
}

/**
 * \brief Get the RzBinDwarfRngList at the given offset
 * \param self  The RzBinDwarfRngListTable
 * \param encoding The RzBinDwarfEncoding
 * \param offset The offset to parse at
 * \return The RzBinDwarfRngList instance on success, NULL otherwise
 */
RZ_API RzBinDwarfRngList *rz_bin_dwarf_rnglists_get(
	RZ_BORROW RZ_NONNULL RzBinDwarfRngLists *self,
	RZ_BORROW RZ_NONNULL RzBinDwarfAddr *addr,
	RZ_BORROW RZ_NONNULL RzBinDwarfCompUnit *cu,
	ut64 offset) {
	rz_return_val_if_fail(self && cu, NULL);
	RzBinDwarfRngList *rngs = ht_up_find(self->by_offset, offset, NULL);
	if (rngs) {
		return rngs;
	}
	if (RngList_at(self, addr, cu, offset, &rngs)) {
		return rngs;
	}
	return NULL;
}

static bool cb_rnglist_dump(void *u, ut64 k, const void *v) {
	const RzBinDwarfRngList *rnglist = v;
	RzStrBuf *sb = u;
	if (!(rnglist && sb)) {
		return false;
	}

	rz_strbuf_appendf(sb, "0x%" PFMT64x "\n", rnglist->offset);
	void **it;
	rz_pvector_foreach (&rnglist->entries, it) {
		RzBinDwarfRange *range = *it;
		rz_strbuf_appendf(sb, "\t(0x%" PFMT64x ", 0x%" PFMT64x ")\n",
			range->begin, range->end);
	}
	return true;
}

RZ_API void rz_bin_dwarf_rnglists_dump(
	RZ_NONNULL RZ_BORROW RzBinDwarfRngLists *rnglists,
	RZ_NONNULL RZ_BORROW RzStrBuf *sb) {
	rz_return_if_fail(rnglists && rnglists->by_offset && sb);
	if (rnglists->by_offset->count > 0) {
		rz_strbuf_append(sb, ".debug_loclists content:\n");
	}
	ht_up_foreach(rnglists->by_offset, cb_rnglist_dump, sb);
	rz_strbuf_append(sb, "\n");
}
