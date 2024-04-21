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
	free(self);
}

static void LocListEntry_fini(RzBinDwarfLocListEntry *self) {
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
	RzBinEndianReader *R, RzBinDwarfBlock *block, RzBinDwarfEncoding *encoding) {
	if (encoding->version >= 5) {
		ULE128_OR_RET_FALSE(block->length);
	} else {
		U_OR_RET_FALSE(16, block->length);
	}
	RET_FALSE_IF_FAIL(R_read_block(R, block));
	return true;
}

static bool RawLocListEntry_parse(
	RzBinDwarfRawLocListEntry *raw,
	RzBinEndianReader *R,
	RzBinDwarfEncoding *encoding,
	RzBinDwarfLocListsFormat format) {
	switch (format) {
	case RzBinDwarfLocListsFormat_BARE: {
		RzBinDwarfRange range = { 0 };
		RET_FALSE_IF_FAIL(Range_parse(&range, R, encoding->address_size));
		if (Range_is_end(&range)) {
			return true;
		} else if (Range_is_base_address(&range, encoding->address_size)) {
			raw->encoding = DW_LLE_base_address;
			raw->base_address.addr = range.end;
		} else {
			raw->is_address_or_offset_pair = true;
			raw->address_or_offset_pair.begin = range.begin;
			raw->address_or_offset_pair.end = range.end;
			RET_FALSE_IF_FAIL(parse_data(
				R, &raw->address_or_offset_pair.data, encoding));
		}
		break;
	}
	case RzBinDwarfLocListsFormat_LLE: {
		U8_OR_RET_FALSE(raw->encoding);
		switch (raw->encoding) {
		case DW_LLE_end_of_list: return true;
		case DW_LLE_base_addressx:
			ULE128_OR_RET_FALSE(raw->base_addressx.addr);
			break;
		case DW_LLE_startx_endx:
			ULE128_OR_RET_FALSE(raw->startx_endx.begin);
			ULE128_OR_RET_FALSE(raw->startx_endx.end);
			RET_FALSE_IF_FAIL(parse_data(R, &raw->startx_endx.data, encoding));
			break;
		case DW_LLE_startx_length:
			ULE128_OR_RET_FALSE(raw->startx_length.begin);
			if (encoding->version >= 5) {
				ULE128_OR_RET_FALSE(raw->startx_length.length);
			} else {
				U_OR_RET_FALSE(32, raw->startx_length.length);
			}
			RET_FALSE_IF_FAIL(parse_data(R, &raw->startx_length.data, encoding));
			break;
		case DW_LLE_offset_pair:
			ULE128_OR_RET_FALSE(raw->offset_pair.begin);
			ULE128_OR_RET_FALSE(raw->offset_pair.end);
			RET_FALSE_IF_FAIL(parse_data(R, &raw->offset_pair.data, encoding));
			break;
		case DW_LLE_default_location:
			RET_FALSE_IF_FAIL(parse_data(R, &raw->default_location.data, encoding));
			break;
		case DW_LLE_base_address:
			RET_FALSE_IF_FAIL(R_read_address(R, &raw->base_address.addr, encoding->address_size));
			break;
		case DW_LLE_start_end:
			RET_FALSE_IF_FAIL(R_read_address(R, &raw->start_end.begin, encoding->address_size));
			RET_FALSE_IF_FAIL(R_read_address(R, &raw->start_end.end, encoding->address_size));
			RET_FALSE_IF_FAIL(parse_data(R, &raw->start_end.data, encoding));
			break;
		case DW_LLE_start_length:
			RET_FALSE_IF_FAIL(R_read_address(R, &raw->start_length.begin, encoding->address_size));
			ULE128_OR_RET_FALSE(raw->start_length.length);
			RET_FALSE_IF_FAIL(parse_data(R, &raw->start_length.data, encoding));
			break;
		case DW_LLE_GNU_view_pair:
			RZ_LOG_ERROR("GNU_view_pair not implemented\n");
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
	RZ_OUT RzBinDwarfLocListEntry **entry) {
	RzBinDwarfEncoding *encoding = &cu->hdr.encoding;
	ut64 mask = encoding->address_size == 0 ? ~0ULL
						: (~0ULL >> (64 - encoding->address_size * 8));
	ut64 tombstone = encoding->version <= 4 ? mask - 1
						: mask;
	RzBinDwarfRange range = { 0 };
	const RzBinDwarfBlock *data = NULL;
	if (raw->is_address_or_offset_pair) {
		if (self->base_address == tombstone) {
			*entry = NULL;
			return true;
		}
		range.begin = raw->address_or_offset_pair.begin;
		range.end = raw->address_or_offset_pair.end;
		Range_add_base_address(&range, self->base_address, encoding->address_size);
		data = &raw->address_or_offset_pair.data;
	} else {
		switch (raw->encoding) {
		case DW_LLE_end_of_list: break;
		case DW_LLE_base_address:
			self->base_address = raw->base_address.addr;
			*entry = NULL;
			return true;
		case DW_LLE_base_addressx:
			ERR_IF_FAIL(rz_bin_dwarf_addr_get(
				addr, &self->base_address,
				encoding->address_size, cu->addr_base, raw->base_addressx.addr));
			return true;
		case DW_LLE_startx_endx:
			ERR_IF_FAIL(rz_bin_dwarf_addr_get(
				addr, &range.begin,
				encoding->address_size, cu->addr_base, raw->startx_endx.begin));
			ERR_IF_FAIL(rz_bin_dwarf_addr_get(
				addr, &range.end,
				encoding->address_size, cu->addr_base, raw->startx_endx.end));
			break;
		case DW_LLE_startx_length:
			ERR_IF_FAIL(rz_bin_dwarf_addr_get(
				addr, &range.begin,
				encoding->address_size, cu->addr_base, raw->startx_length.begin));
			range.end = (raw->startx_length.length + raw->startx_length.begin) & mask;
			break;
		case DW_LLE_offset_pair:
			if (self->base_address == tombstone) {
				*entry = NULL;
				return true;
			}
			range.begin = raw->address_or_offset_pair.begin;
			range.end = raw->address_or_offset_pair.end;
			Range_add_base_address(&range, self->base_address, encoding->address_size);
			data = &raw->address_or_offset_pair.data;
			ERR_IF_FAIL(data);
			break;
		case DW_LLE_default_location: break;
		case DW_LLE_start_end:
			range.begin = raw->startx_endx.begin;
			range.end = raw->startx_endx.end;
			break;
		case DW_LLE_start_length:
			range.begin = raw->startx_length.begin;
			range.end = (raw->startx_length.length + raw->startx_length.begin) & mask;
			break;
		case DW_LLE_GNU_view_pair:
			rz_warn_if_reached();
			break;
		}
	}

	if (range.begin == tombstone) {
		*entry = NULL;
		return true;
	}
	if (range.begin > range.end) {
		RZ_LOG_VERBOSE("Invalid Address Range (0x%" PFMT64x ",0x%" PFMT64x ")\n",
			range.begin, range.end);
		goto err;
	}

	*entry = RZ_NEW0(RzBinDwarfLocListEntry);
	ERR_IF_FAIL(*entry);
	(*entry)->range = range;
	(*entry)->expression = data;
	return true;
err:
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

/**
 * \brief Parse a location list table at the given offset
 * \param self RzBinDwarfLocListTable instance
 * \param cu RzBinDwarfCompUnit instance
 * \param offset The offset to parse at
 * \param out Pointer to output the location list
 * \return true on success, false otherwise
 */
static bool LocList_at(
	RzBinDwarfLocLists *self, RzBinDwarfAddr *addr, RzBinDwarfCompUnit *cu, ut64 offset,
	RzBinDwarfLocList **out) {
	rz_return_val_if_fail(self && cu && out, false);
	RzBinEndianReader *R = cu->hdr.encoding.version <= 4
		? self->loc
		: self->loclists;
	RzBinDwarfLocListsFormat format = cu->hdr.encoding.version <= 4
		? RzBinDwarfLocListsFormat_BARE
		: RzBinDwarfLocListsFormat_LLE;
	OK_OR(R && R_seek(R, offset, RZ_BUF_SET), return false);

	RzBinDwarfLocList *loclist = RZ_NEW0(RzBinDwarfLocList);
	RET_FALSE_IF_FAIL(loclist);
	self->base_address = cu->low_pc;
	loclist->offset = R_tell(R);
	rz_pvector_init(&loclist->raw_entries, (RzPVectorFree)RawLocListEntry_free);
	rz_pvector_init(&loclist->entries, (RzPVectorFree)LocListEntry_free);
	while (true) {
		RzBinDwarfRawLocListEntry *raw = RZ_NEW0(RzBinDwarfRawLocListEntry);
		RzBinDwarfLocListEntry *entry = NULL;
		ERR_IF_FAIL(raw && RawLocListEntry_parse(raw, R, &cu->hdr.encoding, format) &&
			rz_pvector_push(&loclist->raw_entries, raw));
		if (raw->encoding == DW_LLE_end_of_list && !raw->is_address_or_offset_pair) {
			break;
		}

		if (convert_raw(self, addr, cu, raw, &entry)) {
			if (!entry) {
				continue;
			}
			ERR_IF_FAIL(rz_pvector_push(&loclist->entries, entry));
		} else {
			LocListEntry_free(entry);
		}
		continue;
	err:
		RawLocListEntry_free(raw);
		LocList_free(loclist);
		return false;
	}
	ht_up_update(self->by_offset, loclist->offset, loclist);
	*out = loclist;
	return true;
}

RZ_API RzBinDwarfLocList *rz_bin_dwarf_loclists_get(
	RZ_BORROW RZ_NONNULL RzBinDwarfLocLists *self,
	RZ_BORROW RZ_NONNULL RzBinDwarfAddr *addr,
	RZ_BORROW RZ_NONNULL RzBinDwarfCompUnit *cu,
	ut64 offset) {
	rz_return_val_if_fail(self && cu, false);
	RzBinDwarfLocList *loclist = ht_up_find(self->by_offset, offset, NULL);
	if (loclist) {
		return loclist;
	}
	if (LocList_at(self, addr, cu, offset, &loclist)) {
		return loclist;
	}
	return NULL;
}

/**
 * \brief Create a new RzBinDwarfLocListTable instance,
 *        takes ownership of the buffers, and any of them must be non-NULL
 * \param debug_loc .debug_loc section buffer
 * \param debug_loc_lists .debug_loclists section buffer
 * \param dw RzBinDWARF instance
 * \return RzBinDwarfLocListTable instance on success, NULL otherwise
 */
RZ_API RZ_OWN RzBinDwarfLocLists *rz_bin_dwarf_loclists_new(RzBinEndianReader *loclists, RzBinEndianReader *loc) {
	rz_return_val_if_fail(loclists || loc, NULL);
	RzBinDwarfLocLists *self = RZ_NEW0(RzBinDwarfLocLists);
	RET_NULL_IF_FAIL(self);
	self->loclists = loclists;
	self->loc = loc;
	self->by_offset = ht_up_new(NULL, (HtUPFreeValue)LocList_free);
	return self;
}

/**
 * \brief Create a new RzBinDwarfLocListTable instance
 * \param bf RzBinFile instance
 * \param dw RzBinDwarf instance
 * \return RzBinDwarfLocListTable instance on success, NULL otherwise
 */
RZ_API RZ_OWN RzBinDwarfLocLists *rz_bin_dwarf_loclists_new_from_file(
	RZ_BORROW RZ_NONNULL RzBinFile *bf, bool is_dwo) {
	RET_NULL_IF_FAIL(bf);
	RzBinEndianReader *loclists = RzBinEndianReader_from_file(bf, ".debug_loclists", is_dwo);
	RzBinEndianReader *loc = RzBinEndianReader_from_file(bf, ".debug_loc", is_dwo);
	if (!(loclists || loc)) {
		R_free(loclists);
		R_free(loc);
		return NULL;
	}
	return rz_bin_dwarf_loclists_new(loclists, loc);
}

RZ_API void rz_bin_dwarf_loclists_free(RZ_OWN RZ_NULLABLE RzBinDwarfLocLists *self) {
	if (!self) {
		return;
	}
	ht_up_free(self->by_offset);
	R_free(self->loclists);
	R_free(self->loc);
	free(self);
}

RZ_API void rz_bin_dwarf_location_fini(RZ_BORROW RZ_NONNULL RzBinDwarfLocation *self) {
	if (!self) {
		return;
	}
	switch (self->kind) {
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
RZ_API RZ_OWN RzBinDwarfLocation *rz_bin_dwarf_location_clone(
	RZ_BORROW RZ_NONNULL RzBinDwarfLocation *self) {
	rz_return_val_if_fail(self &&
			self->kind != RzBinDwarfLocationKind_EVALUATION_WAITING,
		NULL);
	RzBinDwarfLocation *loc = RZ_NEWCOPY(RzBinDwarfLocation, self);
	switch (loc->kind) {
	case RzBinDwarfLocationKind_COMPOSITE:
		loc->composite = rz_vector_clonef(self->composite, (RzVectorItemCpyFunc)RzBinDwarfPiece_cpy);
		break;
	default:
		break;
	}
	return loc;
}

RZ_IPI void Location_cpy(Location *dst, Location *src) {
	rz_return_if_fail(dst && src);
	memcpy(dst, src, sizeof(Location));
	switch (src->kind) {
	case RzBinDwarfLocationKind_BYTES:
		memcpy(&dst->bytes, &src->bytes, sizeof(RzBinDwarfBlock));
		break;
	case RzBinDwarfLocationKind_EVALUATION_WAITING:
		rz_bin_dwarf_evaluation_cpy(dst->eval_waiting.eval, src->eval_waiting.eval);
		RzBinDwarfEvaluationResult_cpy(dst->eval_waiting.result, src->eval_waiting.result);
		break;
	case RzBinDwarfLocationKind_COMPOSITE:
		rz_vector_clone_intof(dst->composite, src->composite, (RzVectorItemCpyFunc)RzBinDwarfPiece_cpy);
		break;
	case RzBinDwarfLocationKind_LOCLIST:
		rz_warn_if_reached();
		break;
	case RzBinDwarfLocationKind_EMPTY:
	case RzBinDwarfLocationKind_DECODE_ERROR:
	case RzBinDwarfLocationKind_REGISTER:
	case RzBinDwarfLocationKind_REGISTER_OFFSET:
	case RzBinDwarfLocationKind_ADDRESS:
	case RzBinDwarfLocationKind_VALUE:
	case RzBinDwarfLocationKind_IMPLICIT_POINTER:
	case RzBinDwarfLocationKind_CFA_OFFSET:
	case RzBinDwarfLocationKind_FB_OFFSET: break;
	}
}

typedef struct {
	RzBinDWARF *dw;
	RzStrBuf *sb;
} DumpContext;

static bool cb_loclist_dump(void *u, ut64 k, const void *v) {
	const RzBinDwarfLocList *loclist = v;
	DumpContext *ctx = u;
	if (!(loclist && ctx && ctx->sb && ctx->dw)) {
		return false;
	}
	RzStrBuf *sb = ctx->sb;
	rz_strbuf_appendf(sb, "0x%" PFMT64x "\n", loclist->offset);
	void **it;
	rz_pvector_foreach (&loclist->entries, it) {
		RzBinDwarfLocListEntry *entry = *it;
		rz_strbuf_appendf(sb, "\t(0x%" PFMT64x ", 0x%" PFMT64x ")\t",
			entry->range.begin, entry->range.end);
		if (entry->expression) {
			const RzBinDwarfEncoding *enc = ht_up_find(
				ctx->dw->info->location_encoding, k, NULL);
			if (!enc) {
				continue;
			}
			RzBinDWARFDumpOption dump_opt = {
				.loclist_sep = ",\t",
				.loclist_indent = "",
				.expr_sep = ", "
			};
			rz_bin_dwarf_expression_dump(
				enc, entry->expression, ctx->sb, &dump_opt);
		}
		rz_strbuf_append(sb, "\n");
	}
	return true;
}

RZ_API void rz_bin_dwarf_loclists_dump(
	RZ_NONNULL RZ_BORROW RzBinDwarfLocLists *loclists,
	RZ_NONNULL RZ_BORROW RzBinDWARF *dw,
	RZ_NONNULL RZ_BORROW RzStrBuf *sb) {
	rz_return_if_fail(dw && loclists && loclists->by_offset && sb);
	if (loclists->by_offset->count > 0) {
		rz_strbuf_append(sb, ".debug_loclists content:\n");
	}
	DumpContext ctx = {
		.dw = dw,
		.sb = sb,
	};
	ht_up_foreach(loclists->by_offset, cb_loclist_dump, &ctx);
	rz_strbuf_append(sb, "\n");
}
