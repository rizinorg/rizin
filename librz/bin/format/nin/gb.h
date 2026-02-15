// SPDX-FileCopyrightText: 2024-2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2024 maijin <maijin21@gmail.com>
// SPDX-FileCopyrightText: 2013-2017 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <string.h>

enum gb_sgb_e {
	GB_SGB_NOT_SUPPORTED = 0x00, ///< No SGB functions (Normal Gameboy or CGB only game)
	GB_SGB_SUPPORTED = 0x03, ///< Game supports SGB functions
};

enum gb_cgb_e {
	GB_GBC_COMPATIBLE = 0x80, ///< Game supports CGB functions, but works on old gameboys also.
	GB_GBC_ONLY = 0xC0, ///< Game works on CGB only (physically the same as 80h).
};

enum gb_rom_type_e {
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

enum gb_rom_e {
	GB_ROM_32_K_BYTES = 0x00, ///<  32KBytes (no ROM banking)
	GB_ROM_64_K_BYTES = 0x01, ///<  64KBytes (4 banks)
	GB_ROM_128_K_BYTES = 0x02, ///< 128KBytes (8 banks)
	GB_ROM_256_K_BYTES = 0x03, ///< 256KBytes (16 banks)
	GB_ROM_512_K_BYTES = 0x04, ///< 512KBytes (32 banks)
	GB_ROM_1_M_BYTES = 0x05, ///<   1MBytes (64 banks)  - only 63 banks used by MBC1
	GB_ROM_2_M_BYTES = 0x06, ///<   2MBytes (128 banks) - only 125 banks used by MBC1
	GB_ROM_4_M_BYTES = 0x07, ///<   4MBytes (256 banks)
	GB_ROM_8_M_BYTES = 0x08, ///<   8MBytes (512 banks)
	GB_ROM_1_1_M_BYTES = 0x52, ///< 1.1MBytes (72 banks)
	GB_ROM_1_2_M_BYTES = 0x53, ///< 1.2MBytes (80 banks)
	GB_ROM_1_5_M_BYTES = 0x54, ///< 1.5MBytes (96 banks)
};

enum gb_ram_e {
	GB_RAM_NONE = 0x00, ///< None
	GB_RAM_2_K_BYTES = 0x01, ///< 2 KBytes
	GB_RAM_8_K_BYTES = 0x02, ///< 8 Kbytes
	GB_RAM_32_K_BYTES = 0x03, ///< 32 KBytes (4 banks of 8KBytes each)
	GB_RAM_128_K_BYTES = 0x04, ///< 128 KBytes (16 banks of 8KBytes each)
	GB_RAM_64_K_BYTES = 0x05, ///< 64 KBytes (8 banks of 8KBytes each)
};

enum gb_destination_code_e {
	GB_DEST_CODE_JAPANESE = 0, ///< Japanese
	GB_DEST_CODE_NON_JAPANESE = 1, ///< Non-Japanese
};

#define GB_ROM_CARTRIDGE_HEADER_OFFSET   0x100
#define GB_ROM_TITLE_SIZE                16
#define GB_ROM_MANUFACTURER_SIZE         4
#define GB_ROM_NINTENDO_LOGO_SIZE        48
#define GB_ROM_NINTENDO_LOGO_OFFSET      0x104
#define GB_ROM_OLD_LICENSEE_NEW_LICENSEE 0x33

/**
 * Reference: https://gbdev.gg8.se/wiki/articles/The_Cartridge_Header
 */
typedef struct gb_header_s {
	ut32 main_address;
	ut8 nintendo_logo[GB_ROM_NINTENDO_LOGO_SIZE];
	char title[GB_ROM_TITLE_SIZE]; ///< Always in UPPER CASE ASCII
	char manufacturer[GB_ROM_MANUFACTURER_SIZE]; ///< It's part of the title in new roms.
	ut8 cgb_flag; ///< It's the 16th byte of the title
	char new_licensee_code[2]; ///< only to be checked when `licensee_code` is 0x33
	ut8 sgb_flag;
	ut8 cartridge_type;
	ut8 rom_size;
	ut8 ram_size;
	ut8 destination_code;
	ut8 licensee_code;
	ut8 mask_rom_version_number;
	ut8 header_checksum;
	ut16 global_checksum;
} gb_header_t;

const ut8 gb_nintendo_logo[GB_ROM_NINTENDO_LOGO_SIZE] = {
	0xce, 0xed, 0x66, 0x66, 0xcc, 0x0d, 0x00, 0x0b, 0x03, 0x73, 0x00, 0x83, 0x00, 0x0c, 0x00, 0x0d,
	0x00, 0x08, 0x11, 0x1f, 0x88, 0x89, 0x00, 0x0e, 0xdc, 0xcc, 0x6e, 0xe6, 0xdd, 0xdd, 0xd9, 0x99,
	0xbb, 0xbb, 0x67, 0x63, 0x6e, 0x0e, 0xec, 0xcc, 0xdd, 0xdc, 0x99, 0x9f, 0xbb, 0xb9, 0x33, 0x3e
};
