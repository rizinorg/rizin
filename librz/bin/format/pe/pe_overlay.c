// SPDX-FileCopyrightText: 2008-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pe.h"

static void computeOverlayOffset(ut64 offset, ut64 size, ut64 file_size, ut64 *largest_offset, ut64 *largest_size) {
	if (offset + size <= file_size && offset + size > (*largest_offset + *largest_size)) {
		*largest_offset = offset;
		*largest_size = size;
	}
}

/* Inspired from https://github.com/erocarrera/pefile/blob/master/pefile.py#L5425 */
int PE_(bin_pe_get_overlay)(RzBinPEObj *bin, ut64 *size) {
	ut64 largest_offset = 0;
	ut64 largest_size = 0;
	*size = 0;
	int i;

	if (!bin) {
		return 0;
	}

	if (bin->optional_header) {
		computeOverlayOffset(
			bin->nt_header_offset + 4 + sizeof(bin->nt_headers->file_header),
			bin->nt_headers->file_header.SizeOfOptionalHeader,
			bin->size,
			&largest_offset,
			&largest_size);
	}

	struct rz_bin_pe_section_t *sects = bin->sections;
	for (i = 0; !sects[i].last; i++) {
		computeOverlayOffset(
			sects[i].paddr,
			sects[i].size,
			bin->size,
			&largest_offset,
			&largest_size);
	}

	if (bin->optional_header) {
		for (i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES; i++) {
			if (i == PE_IMAGE_DIRECTORY_ENTRY_SECURITY) {
				continue;
			}

			computeOverlayOffset(
				PE_(bin_pe_rva_to_paddr)(bin, bin->data_directory[i].VirtualAddress),
				bin->data_directory[i].Size,
				bin->size,
				&largest_offset,
				&largest_size);
		}
	}

	if ((ut64)bin->size > largest_offset + largest_size) {
		*size = bin->size - largest_offset - largest_size;
		return largest_offset + largest_size;
	}
	return 0;
}

int PE_(bin_pe_init_overlay)(RzBinPEObj *bin) {
	ut64 pe_overlay_size;
	ut64 pe_overlay_offset = PE_(bin_pe_get_overlay)(bin, &pe_overlay_size);
	if (pe_overlay_offset) {
		sdb_num_set(bin->kv, "pe_overlay.offset", pe_overlay_offset);
		sdb_num_set(bin->kv, "pe_overlay.size", pe_overlay_size);
	}
	return 0;
}