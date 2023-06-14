// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

RZ_API void rz_bin_dwarf_arange_set_free(RzBinDwarfARangeSet *set) {
	if (!set) {
		return;
	}
	free(set->aranges);
	free(set);
}

static RzList /*<RzBinDwarfARangeSet *>*/ *parse_aranges_raw(const ut8 *obuf, size_t obuf_sz, bool big_endian) {
	rz_return_val_if_fail(obuf, NULL);
	const ut8 *buf = obuf;
	const ut8 *buf_end = buf + obuf_sz;

	RzList *r = rz_list_newf((RzListFree)rz_bin_dwarf_arange_set_free);
	if (!r) {
		return NULL;
	}

	// DWARF 3 Standard Section 6.1.2 Lookup by Address
	// also useful to grep for display_debug_aranges in binutils
	while (buf < buf_end) {
		const ut8 *start = buf;
		bool is_64bit;
		ut64 unit_length = dwarf_read_initial_length(&is_64bit, big_endian, &buf, buf_end);
		// Sanity check: length must be at least the minimal size of the remaining header fields
		// and at maximum the remaining buffer size.
		size_t header_rest_size = 2 + (is_64bit ? 8 : 4) + 1 + 1;
		if (unit_length < header_rest_size || unit_length > buf_end - buf) {
			break;
		}
		const ut8 *next_set_buf = buf + unit_length;
		RzBinDwarfARangeSet *set = RZ_NEW(RzBinDwarfARangeSet);
		if (!set) {
			break;
		}
		set->unit_length = unit_length;
		set->is_64bit = is_64bit;
		set->version = READ16(buf);
		set->debug_info_offset = dwarf_read_offset(set->is_64bit, big_endian, &buf, buf_end);
		set->address_size = READ8(buf);
		set->segment_size = READ8(buf);
		unit_length -= header_rest_size;
		if (!set->address_size) {
			free(set);
			break;
		}

		// align to 2*addr_size
		size_t off = buf - start;
		size_t pad = rz_num_align_delta(off, 2 * set->address_size);
		if (pad > unit_length || pad > buf_end - buf) {
			free(set);
			break;
		}
		buf += pad;
		unit_length -= pad;

		size_t arange_size = 2 * set->address_size;
		set->aranges_count = unit_length / arange_size;
		if (!set->aranges_count) {
			free(set);
			break;
		}
		set->aranges = RZ_NEWS0(RzBinDwarfARange, set->aranges_count);
		if (!set->aranges) {
			free(set);
			break;
		}
		size_t i;
		for (i = 0; i < set->aranges_count; i++) {
			set->aranges[i].addr = dwarf_read_address(set->address_size, big_endian, &buf, buf_end);
			set->aranges[i].length = dwarf_read_address(set->address_size, big_endian, &buf, buf_end);
			if (!set->aranges[i].addr && !set->aranges[i].length) {
				// last entry has two 0s
				i++; // so i will be the total count of read entries
				break;
			}
		}
		set->aranges_count = i;
		buf = next_set_buf;
		rz_list_push(r, set);
	}

	return r;
}

RZ_API RzList /*<RzBinDwarfARangeSet *>*/ *rz_bin_dwarf_aranges_parse(RzBinFile *binfile) {
	rz_return_val_if_fail(binfile, NULL);
	size_t len;
	ut8 *buf = get_section_bytes(binfile, "debug_aranges", &len);
	if (!buf) {
		return NULL;
	}
	RzList *r = parse_aranges_raw(buf, len, binfile->o && binfile->o->info && binfile->o->info->big_endian);
	free(buf);
	return r;
}
