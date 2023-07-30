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

static bool RzBinDwarfARangeSet_list_parse(RzBuffer *buffer, bool big_endian, RzList /*<RzBinDwarfARangeSet *>*/ *aranges) {
	rz_return_val_if_fail(buffer && aranges, NULL);
	// DWARF 3 Standard Section 6.1.2 Lookup by Address
	// also useful to grep for display_debug_aranges in binutils
	while (true) {
		ut64 offset = rz_buf_tell(buffer);
		ut64 unit_length = 0;
		bool is_64bit;
		GOTO_IF_FAIL(buf_read_initial_length(buffer, &is_64bit, &unit_length, big_endian), ok);
		// Sanity check: length must be at least the minimal size of the remaining header fields
		// and at maximum the remaining buffer size.
		size_t header_rest_size = 2 + (is_64bit ? 8 : 4) + 1 + 1;
		if (unit_length < header_rest_size || unit_length > rz_buf_size(buffer) - rz_buf_tell(buffer)) {
			break;
		}
		ut64 next_set_off = rz_buf_tell(buffer) + unit_length;
		RzBinDwarfARangeSet *set = RZ_NEW0(RzBinDwarfARangeSet);
		if (!set) {
			break;
		}
		set->unit_length = unit_length;
		set->is_64bit = is_64bit;

		U_OR_GOTO(16, set->version, err);
		GOTO_IF_FAIL(buf_read_offset(buffer, &set->debug_info_offset, is_64bit, big_endian), err);
		U8_OR_GOTO(set->address_size, err);
		U8_OR_GOTO(set->segment_size, err);

		unit_length -= header_rest_size;
		GOTO_IF_FAIL(set->address_size > 0, err);

		// align to 2*addr_size
		size_t off = rz_buf_tell(buffer) - offset;
		size_t pad = rz_num_align_delta(off, 2 * set->address_size);
		GOTO_IF_FAIL(pad <= unit_length && pad <= rz_buf_size(buffer) - rz_buf_tell(buffer), err);
		rz_buf_seek(buffer, (st64)pad, RZ_BUF_CUR);
		unit_length -= pad;

		size_t arange_size = 2 * set->address_size;
		set->aranges_count = unit_length / arange_size;
		GOTO_IF_FAIL(set->aranges_count > 0, err);

		set->aranges = RZ_NEWS0(RzBinDwarfARange, set->aranges_count);
		GOTO_IF_FAIL(set->aranges, err);

		size_t i = 0;
		for (; i < set->aranges_count; i++) {
			RzBinDwarfARange *range = set->aranges + i;
			UX_OR_GOTO(set->address_size, range->addr, err);
			UX_OR_GOTO(set->address_size, range->length, err);
			if (!range->addr && !range->length) {
				// last entry has two 0s
				i++; // so i will be the total count of read entries
				break;
			}
		}
		set->aranges_count = i;
		rz_buf_seek(buffer, (st64)next_set_off, RZ_BUF_SET);
		rz_list_push(aranges, set);
		continue;
	err:
		free(set->aranges);
		free(set);
		break;
	}
ok:
	return aranges;
}

/**
 * \brief Parse .debug_aranges section
 *
 * \param binfile Binfile to parse
 * \return List of RzBinDwarfARangeSet
 */
RZ_API RZ_OWN RzList /*<RzBinDwarfARangeSet *>*/ *rz_bin_dwarf_aranges_parse(RZ_BORROW RZ_NONNULL RzBinFile *binfile) {
	rz_return_val_if_fail(binfile, NULL);
	RzBuffer *buffer = get_section_buf(binfile, "debug_aranges");
	RET_NULL_IF_FAIL(buffer);
	bool big_endian = binfile->o && binfile->o->info && binfile->o->info->big_endian;
	RzList *aranges = rz_list_newf((RzListFree)rz_bin_dwarf_arange_set_free);
	RET_NULL_IF_FAIL(aranges);
	RET_NULL_IF_FAIL(RzBinDwarfARangeSet_list_parse(buffer, big_endian, aranges));
	rz_buf_free(buffer);
	return aranges;
}
