// SPDX-FileCopyrightText: 2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PE_H
#define PE_H

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

typedef struct {
	RzList /* PeImageSectionHeader */ *sections_hdrs;
} PeStream;

#endif // PE_H
