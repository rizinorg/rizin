// SPDX-FileCopyrightText: 2022-2024 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2014 Alberto Ortega
// SPDX-License-Identifier: LGPL-3.0-only

/*
http://dsibrew.org/wiki/NDS_Format
http://sourceforge.net/p/devkitpro/ndstool/ci/master/tree/source/header.h
https://dsibrew.org/wiki/DSi_cartridge_header
*/

#ifndef NIN_NDS_H
#define NIN_NDS_H

#include <rz_types_base.h>

typedef struct nds_overlay_table_entry_t {
	ut32 id;
	ut32 load_address;
	ut32 ram_size;
	ut32 bss_size;
	ut32 static_initializer_start_address;
	ut32 static_initializer_end_address;
	ut32 file_id;
	ut32 reserved;
} NDSOverlayTblEntry;

typedef struct nds_file_alloc_table_entry_t {
	ut32 file_start_offset;
	ut32 file_end_offset;
} NDSFatEntry;

typedef struct nds_header_t {
	st8 title[0xC];
	st8 gamecode[0x4];
	st8 makercode[2];
	ut8 unitcode;
	ut8 devicetype;
	ut8 devicecap;
	ut8 reserved1[0x9];
	ut8 romversion;
	ut8 reserved2;
	ut32 arm9_rom_offset;
	ut32 arm9_entry_address;
	ut32 arm9_ram_address;
	ut32 arm9_size;
	ut32 arm7_rom_offset;
	ut32 arm7_entry_address;
	ut32 arm7_ram_address;
	ut32 arm7_size;
	ut32 fnt_offset; ///< Filename Table Offset
	ut32 fnt_size; ///< Filename Table Size
	ut32 fat_offset; ///< File Allocaton Table Offset
	ut32 fat_size; ///< File Allocaton Table Size
	ut32 arm9_overlay_offset;
	ut32 arm9_overlay_size;
	ut32 arm7_overlay_offset;
	ut32 arm7_overlay_size;
	ut32 rom_control_info1;
	ut32 rom_control_info2;
	ut32 banner_offset;
	ut16 secure_area_crc;
	ut16 secure_transfer_timeout;
	ut32 arm9_autoload;
	ut32 arm7_autoload;
	ut64 secure_disable;
	ut32 ntr_region_rom_size;
	ut32 rom_header_size;
	ut32 offset_0x88;
	ut32 offset_0x8C;

	/* reserved */
	ut32 offset_0x90;
	ut32 offset_0x94;
	ut32 offset_0x98;
	ut32 offset_0x9C;
	ut32 offset_0xA0;
	ut32 offset_0xA4;
	ut32 offset_0xA8;
	ut32 offset_0xAC;
	ut32 offset_0xB0;
	ut32 offset_0xB4;
	ut32 offset_0xB8;
	ut32 offset_0xBC;

	ut8 logo[156];
	ut16 logo_crc;
	ut16 header_crc;
} NDSHeader;

#endif /* NIN_NDS_H */
