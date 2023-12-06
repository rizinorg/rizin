// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PDB_PE_H
#define PDB_PE_H

#include <rz_util.h>

typedef union {
	ut32 physical_address;
	ut32 virtual_address;
} PeMisc;

#define PDB_SIZEOF_SECTION_NAME 8

typedef struct {
	char name[8];
	PeMisc misc;
	ut32 virtual_address;
	ut32 size_of_raw_data;
	ut32 pointer_to_raw_data;
	ut32 pointer_to_relocations;
	ut32 pointer_to_line_numbers;
	ut16 number_of_relocations;
	ut16 number_of_line_numbers;
	ut32 charactestics;
} PeImageSectionHeader;

static inline PeImageSectionHeader *pdb_section_hdr_by_index(RZ_NONNULL const RzPdbPeStream *s, ut64 index) {
	return rz_list_get_n(s->sections_hdrs, index - 1);
}

#endif