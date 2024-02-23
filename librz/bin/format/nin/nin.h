// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2024 maijin <maijin21@gmail.com>
// SPDX-FileCopyrightText: 2013-2017 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <string.h>

enum {
	GB_SGB = 3,
	GB_GBC = 0x80
};

enum {
	GB_ROM = 0x00,
	GB_ROM_MBC1 = 0x01,
	GB_ROM_MBC1_RAM = 0x02,
	GB_ROM_MBC1_RAM_BAT = 0x03,
	GB_ROM_MBC2 = 0x05,
	GB_ROM_MBC2_BAT = 0x06,
	GB_ROM_RAM = 0x08,
	GB_ROM_RAM_BAT = 0x09,
	GB_ROM_MMM01 = 0x0b,
	GB_ROM_MMM01_SRAM = 0xc,
	GB_ROM_MMM01_SRAM_BAT = 0xd,
	GB_ROM_MBC3_TIMER_BAT = 0xf,
	GB_ROM_MBC3_TIMER_RAM_BAT = 0x10,
	GB_ROM_MBC3 = 0x11,
	GB_ROM_MBC3_RAM = 0x12,
	GB_ROM_MBC3_RAM_BAT = 0x13,
	GB_ROM_MBC5 = 0x19,
	GB_ROM_MBC5_RAM = 0x1a,
	GB_ROM_MBC5_RAM_BAT = 0x1b,
	GB_ROM_MBC5_RMBL = 0x1c,
	GB_ROM_MBC5_RMBL_SRAM = 0x1d,
	GB_ROM_MBC5_RMBL_SRAM_BAT = 0x1e,
	GB_CAM = 0x1f,
	GB_TAMA5 = 0xfd,
	GB_HUC3 = 0xfe,
	GB_HUC1 = 0xff
};

enum {
	GB_ROM_BANKS_2,
	GB_ROM_BANKS_4,
	GB_ROM_BANKS_8,
	GB_ROM_BANKS_16,
	GB_ROM_BANKS_32,
	GB_ROM_BANKS_64,
	GB_ROM_BANKS_128,
	GB_ROM_BANKS_72 = 0x52,
	GB_ROM_BANKS_80,
	GB_ROM_BANKS_96
};

enum {
	GB_NO_RAM,
	GB_RAM_2,
	GB_RAM_8,
	GB_RAM_32,
	GB_RAM_128
};

const ut8 lic[] = {
	0xce, 0xed, 0x66, 0x66, 0xcc, 0x0d, 0x00, 0x0b, 0x03, 0x73, 0x00,
	0x83, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x08, 0x11, 0x1f, 0x88, 0x89,
	0x00, 0x0e, 0xdc, 0xcc, 0x6e, 0xe6, 0xdd, 0xdd, 0xd9, 0x99, 0xbb,
	0xbb, 0x67, 0x63, 0x6e, 0x0e, 0xec, 0xcc, 0xdd, 0xdc, 0x99, 0x9f,
	0xbb, 0xb9, 0x33, 0x3e
};
