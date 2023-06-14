// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

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

static inline RzBinDwarfLocList *create_loc_list(ut64 offset) {
	RzBinDwarfLocList *list = RZ_NEW0(RzBinDwarfLocList);
	if (list) {
		list->list = rz_list_new();
		list->offset = offset;
	}
	return list;
}

static inline RzBinDwarfLocRange *create_loc_range(ut64 start, ut64 end, RzBinDwarfBlock *block) {
	RzBinDwarfLocRange *range = RZ_NEW0(RzBinDwarfLocRange);
	if (range) {
		range->start = start;
		range->end = end;
		range->expression = block;
	}
	return range;
}

static void loc_list_tree(RzBinDwarfLocList *loc_list) {
	RzListIter *iter;
	RzBinDwarfLocRange *range;
	rz_list_foreach (loc_list->list, iter, range) {
		free(range->expression->data);
		free(range->expression);
		free(range);
	}
	rz_list_free(loc_list->list);
	free(loc_list);
}

static void block_free(RzBinDwarfBlock *block) {
	if (!block) {
		return;
	}
	free(block->data);
	free(block);
}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "UnreachableCode"
static HtUP *parse_loc_raw(RzBuffer *buffer, HtUP /*<offset, List *<LocListEntry>*/ *loc_table, size_t addr_size,
	bool big_endian) {
	/* GNU has their own extensions GNU locviews that we can't parse */
	/* for recognizing Base address entry */
	ut64 max_offset = get_max_offset(addr_size);

	ut64 address_base = 0; /* remember base of the loclist */
	ut64 list_offset = 0;

	RzBinDwarfLocList *loc_list = NULL;
	RzBinDwarfLocRange *range = NULL;
	while (true) {
		ut64 start_addr = 0;
		ut64 end_addr = 0;
		UX_OR_RET_FALSE(start_addr, addr_size);
		UX_OR_RET_FALSE(end_addr, addr_size);

		if (start_addr == 0 && end_addr == 0) { /* end of list entry: 0, 0 */
			if (loc_list) {
				if (!ht_up_insert(loc_table, loc_list->offset, loc_list)) {
					loc_list_tree(loc_list);
				}
				list_offset = rz_buf_tell(buffer);
				loc_list = NULL;
			}
			address_base = 0;
			continue;
		} else if (start_addr == max_offset && end_addr != max_offset) {
			/* base address, DWARF2 doesn't have this type of entry, these entries shouldn't
			   be in the list, they are just informational entries for further parsing (address_base) */
			address_base = end_addr;
		} else { /* location list entry: */
			if (!loc_list) {
				loc_list = create_loc_list(list_offset);
			}
			/* TODO in future parse expressions to better structure in dwarf.c and not in dwarf_process.c */
			RzBinDwarfBlock *block = RZ_NEW0(RzBinDwarfBlock);
			U16_OR_RET_FALSE(block->length);
			buf_read_block(buffer, block);
			range = create_loc_range(start_addr + address_base, end_addr + address_base, block);
			if (!range) {
				block_free(block);
			}
			rz_list_append(loc_list->list, range);
			range = NULL;
		}
	}
	/* if for some reason end of list is missing, then loc_list would leak */
	if (loc_list) {
		loc_list_tree(loc_list);
	}
	return loc_table;
}
#pragma clang diagnostic pop

/**
 * @brief Parses out the .debug_loc section into a table that maps each list as
 *        offset of a list -> LocationList
 *
 * @param binfile
 * @param addr_size machine address size used in executable (necessary for parsing)
 * @return RZ_API*
 */
RZ_API HtUP /*<offset, RzBinDwarfLocList *>*/ *rz_bin_dwarf_loc_parse(RzBinFile *binfile, int addr_size) {
	rz_return_val_if_fail(binfile, NULL);
	/* The standarparse_loc_raw_frame, not sure why is that */
	RzBuffer *buf = get_section_buf(binfile, "debug_loc");
	if (!buf) {
		return NULL;
	}
	HtUP /*<offset, RzBinDwarfLocList*/ *loc_table = ht_up_new0();
	if (!loc_table) {
		free(buf);
		return NULL;
	}
	loc_table = parse_loc_raw(buf, loc_table, addr_size, binfile->o && binfile->o->info && binfile->o->info->big_endian);
	free(buf);
	return loc_table;
}

static void ht_loc_list_free(HtUPKv *kv) {
	if (kv) {
		loc_list_tree(kv->value);
	}
}

RZ_API void rz_bin_dwarf_loc_free(HtUP /*<offset, RzBinDwarfLocList *>*/ *loc_table) {
	if (!loc_table) {
		return;
	}
	loc_table->opt.freefn = ht_loc_list_free;
	ht_up_free(loc_table);
}

static bool parse_data(RzBuffer *buffer, RzBinDwarfBlock *block, Encoding *encoding) {
	bool big_endian = encoding->big_endian;
	if (encoding->version >= 5) {
		ULE128_OR_RET_FALSE(block->length);
	} else {
		U16_OR_RET_FALSE(block->length);
	}
	RET_FALSE_IF_FAIL(buf_read_block(buffer, block));
	return true;
}

static bool RawLocListEntry_parse(RzVector *entries, RzBuffer *buffer, Encoding *encoding, LocListsFormat format) {
	RawLocListEntry entry = { 0 };
	bool big_endian = encoding->big_endian;
	switch (format) {
	case LocListsFormat_Bare: {
		RawRange range = { 0 };
		RET_FALSE_IF_FAIL(RawRange_parse(&range, buffer, encoding));
		if (RawRange_is_end(&range)) {
			return true;
		} else if (RawRange_is_base_address(&range, encoding->address_size)) {
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
	case LocListsFormat_Lle: {
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
	rz_vector_push(entries, &entry);
	return true;
}
