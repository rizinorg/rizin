// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_API void rz_bin_dwarf_arange_set_free(RZ_OWN RZ_NULLABLE RzBinDwarfARangeSet *set) {
	if (!set) {
		return;
	}
	free(set->aranges);
	free(set);
}

RZ_API void rz_bin_dwarf_aranges_free(RZ_OWN RZ_NULLABLE RzBinDwarfARanges *aranges) {
	if (!aranges) {
		return;
	}
	rz_list_free(aranges->list);
	RzBinEndianReader_free(aranges->reader);
	free(aranges);
}

static bool RzBinDwarfARanges_parse(
	RzBinDwarfARanges *aranges) {
	rz_return_val_if_fail(aranges, NULL);
	RzBinEndianReader *reader = aranges->reader;
	// DWARF 3 Standard Section 6.1.2 Lookup by Address
	// also useful to grep for display_debug_aranges in binutils
	while (true) {
		ut64 offset = rz_buf_tell(reader->buffer);
		ut64 unit_length = 0;
		bool is_64bit;
		GOTO_IF_FAIL(read_initial_length(reader, &is_64bit, &unit_length), ok);
		// Sanity check: length must be at least the minimal size of the remaining header fields
		// and at maximum the remaining buffer size.
		size_t header_rest_size = 2 + (is_64bit ? 8 : 4) + 1 + 1;
		if (unit_length < header_rest_size || unit_length > rz_buf_size(reader->buffer) - rz_buf_tell(reader->buffer)) {
			break;
		}
		ut64 next_set_off = rz_buf_tell(reader->buffer) + unit_length;
		RzBinDwarfARangeSet *set = RZ_NEW0(RzBinDwarfARangeSet);
		if (!set) {
			break;
		}
		set->unit_length = unit_length;
		set->is_64bit = is_64bit;

		U_OR_GOTO(16, set->version, err);
		GOTO_IF_FAIL(read_offset(reader, &set->debug_info_offset, is_64bit), err);
		U8_OR_GOTO(set->address_size, err);
		U8_OR_GOTO(set->segment_size, err);

		unit_length -= header_rest_size;
		GOTO_IF_FAIL(set->address_size > 0, err);

		// align to 2*addr_size
		size_t off = rz_buf_tell(reader->buffer) - offset;
		size_t pad = rz_num_align_delta(off, 2 * set->address_size);
		GOTO_IF_FAIL(pad <= unit_length && pad <= rz_buf_size(reader->buffer) - rz_buf_tell(reader->buffer), err);
		rz_buf_seek(reader->buffer, (st64)pad, RZ_BUF_CUR);
		unit_length -= pad;

		size_t arange_size = 2 * set->address_size;
		set->aranges_count = unit_length / arange_size;
		GOTO_IF_FAIL(set->aranges_count > 0, err);

		set->aranges = RZ_NEWS0(RzBinDwarfARange, set->aranges_count);
		GOTO_IF_FAIL(set->aranges, err);

		size_t count = 0;
		for (; count < set->aranges_count; count++) {
			RzBinDwarfARange *range = set->aranges + count;
			GOTO_IF_FAIL(read_address(reader, &range->addr, set->address_size), err);
			GOTO_IF_FAIL(read_address(reader, &range->length, set->address_size), err);
			if (!range->addr && !range->length) {
				// last entry has two 0s
				count++;
				break;
			}
		}
		set->aranges_count = count;
		rz_buf_seek(reader->buffer, (st64)next_set_off, RZ_BUF_SET);
		rz_list_push(aranges->list, set);
		continue;
	err:
		free(set->aranges);
		free(set);
		break;
	}
ok:
	return aranges;
}

RZ_API RZ_OWN RzBinDwarfARanges *rz_bin_dwarf_aranges_new(RZ_NONNULL RZ_OWN RzBinEndianReader *reader) {
	RzBinDwarfARanges *aranges = RZ_NEW0(RzBinDwarfARanges);
	ERR_IF_FAIL(aranges);
	aranges->list = rz_list_newf((RzListFree)rz_bin_dwarf_arange_set_free);
	ERR_IF_FAIL(aranges->list);
	aranges->reader = reader;
	ERR_IF_FAIL(RzBinDwarfARanges_parse(aranges));
	return aranges;
err:
	rz_bin_dwarf_aranges_free(aranges);
	return NULL;
}

/**
 * \brief Parse .debug_aranges section
 *
 * \param bf Binfile to parse
 * \return List of RzBinDwarfARangeSet
 */
RZ_API RZ_OWN RzBinDwarfARanges *rz_bin_dwarf_aranges_from_file(RZ_BORROW RZ_NONNULL RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzBinEndianReader *reader = RzBinEndianReader_from_file(bf, ".debug_aranges", false);
	RET_NULL_IF_FAIL(reader);
	return rz_bin_dwarf_aranges_new(reader);
}
