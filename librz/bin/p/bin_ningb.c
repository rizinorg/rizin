// SPDX-FileCopyrightText: 2024-2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2024 maijin <maijin21@gmail.com>
// SPDX-FileCopyrightText: 2013-2017 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>
#include "../format/nin/gb.h"

typedef struct gb_new_licensee_code_s {
	char code[2];
	const char *name;
} gb_new_licensee_code_t;

typedef struct gb_memory_s gb_memory_t;

struct gb_memory_s {
	const char *name;
	ut64 addr;
	ut32 size;
	ut32 perms;
	const gb_memory_t *mirror;
};

typedef struct gb_symbol_s {
	ut32 ordinal;
	ut64 addr;
	ut32 size;
	const char *name;
} gb_symbol_t;

static const gb_memory_t gb_iram_mirror = {
	// clang-format off
	"iram_echo", 0xe000ll, 0x1e00, RZ_PERM_RX, NULL,
	// clang-format on
};

static const gb_memory_t gb_memory[] = {
	// clang-format off
	{ "fastram",  0xff80ll, 0x0080, RZ_PERM_RWX, NULL },
	{ "ioports",  0xff00ll, 0x004c, RZ_PERM_RWX, NULL },
	{ "oam",      0xfe00ll, 0x00a0, RZ_PERM_RWX, NULL },
	{ "videoram", 0x8000ll, 0x2000, RZ_PERM_RWX, NULL },
	{ "iram",     0xc000ll, 0x2000, RZ_PERM_RWX, &gb_iram_mirror },
	// clang-format on
};

static const gb_symbol_t gb_cpu_symbols[] = {
	// clang-format off
	{  0, 0x00ll, 1, "rst_0" },
	{  1, 0x08ll, 1, "rst_8" },
	{  2, 0x10ll, 1, "rst_16" },
	{  3, 0x18ll, 1, "rst_24" },
	{  4, 0x20ll, 1, "rst_32" },
	{  5, 0x28ll, 1, "rst_40" },
	{  6, 0x30ll, 1, "rst_48" },
	{  7, 0x38ll, 1, "rst_56" },
	{  8, 0x40ll, 1, "Interrupt_Vblank" },
	{  9, 0x48ll, 1, "Interrupt_LCDC-Status" },
	{ 10, 0x50ll, 1, "Interrupt_Timer-Overflow" },
	{ 11, 0x58ll, 1, "Interrupt_Serial-Transfere" },
	{ 12, 0x60ll, 1, "Interrupt_Joypad" },
	// clang-format on
};

const gb_new_licensee_code_t gb_new_licensee[] = {
	// clang-format off
	{ { '0', '0' }, "none", },
	{ { '0', '1' }, "nintendo", },
	{ { '0', '8' }, "capcom", },
	{ { '1', '3' }, "electronic arts", },
	{ { '1', '8' }, "hudsonsoft", },
	{ { '1', '9' }, "b-ai", },
	{ { '2', '0' }, "kss", },
	{ { '2', '2' }, "pow", },
	{ { '2', '4' }, "pcm complete", },
	{ { '2', '5' }, "san-x", },
	{ { '2', '8' }, "kemco japan", },
	{ { '2', '9' }, "seta", },
	{ { '3', '0' }, "viacom", },
	{ { '3', '1' }, "nintendo", },
	{ { '3', '2' }, "bandia", },
	{ { '3', '3' }, "ocean/acclaim", },
	{ { '3', '4' }, "konami", },
	{ { '3', '5' }, "hector", },
	{ { '3', '7' }, "taito", },
	{ { '3', '8' }, "hudson", },
	{ { '3', '9' }, "banpresto", },
	{ { '4', '1' }, "ubi soft", },
	{ { '4', '2' }, "atlus", },
	{ { '4', '4' }, "malibu", },
	{ { '4', '6' }, "angel", },
	{ { '4', '7' }, "pullet-proof", },
	{ { '4', '9' }, "irem", },
	{ { '5', '0' }, "absolute", },
	{ { '5', '1' }, "acclaim", },
	{ { '5', '2' }, "activision", },
	{ { '5', '3' }, "american sammy", },
	{ { '5', '4' }, "konami", },
	{ { '5', '5' }, "hi tech entertainment", },
	{ { '5', '6' }, "ljn", },
	{ { '5', '7' }, "matchbox", },
	{ { '5', '8' }, "mattel", },
	{ { '5', '9' }, "milton bradley", },
	{ { '6', '0' }, "titus", },
	{ { '6', '1' }, "virgin", },
	{ { '6', '4' }, "lucasarts", },
	{ { '6', '7' }, "ocean", },
	{ { '6', '9' }, "electronic arts", },
	{ { '7', '0' }, "infogrames", },
	{ { '7', '1' }, "interplay", },
	{ { '7', '2' }, "broderbund", },
	{ { '7', '3' }, "sculptured", },
	{ { '7', '5' }, "sci", },
	{ { '7', '8' }, "t*hq", },
	{ { '7', '9' }, "accolade", },
	{ { '8', '0' }, "misawa", },
	{ { '8', '3' }, "lozc", },
	{ { '8', '6' }, "tokuma shoten i*", },
	{ { '8', '7' }, "tsukuda ori*", },
	{ { '9', '1' }, "chun soft", },
	{ { '9', '2' }, "video system", },
	{ { '9', '3' }, "ocean/acclaim", },
	{ { '9', '5' }, "varie", },
	{ { '9', '6' }, "yonezawa/s'pal", },
	{ { '9', '7' }, "kaneko", },
	{ { '9', '9' }, "pack in soft", },
	// clang-format on
};

const char *gb_old_licensee[256] = {
	// clang-format off
	[0x00] = "none",
	[0x01] = "nintendo",
	[0x08] = "capcom",
	[0x09] = "hot-b",
	[0x0A] = "jaleco",
	[0x0B] = "coconuts",
	[0x0C] = "elite systems",
	[0x13] = "electronic arts",
	[0x18] = "hudsonsoft",
	[0x19] = "itc entertainment",
	[0x1A] = "yanoman",
	[0x1D] = "clary",
	[0x1F] = "virgin",
	[0x20] = "KSS",
	[0x24] = "pcm complete",
	[0x25] = "san-x",
	[0x28] = "kotobuki systems",
	[0x29] = "seta",
	[0x30] = "infogrames",
	[0x31] = "nintendo",
	[0x32] = "bandai",
	[0x34] = "konami",
	[0x35] = "hector",
	[0x38] = "Capcom",
	[0x39] = "Banpresto",
	[0x3C] = "*entertainment i",
	[0x3E] = "gremlin",
	[0x41] = "Ubisoft",
	[0x42] = "Atlus",
	[0x44] = "Malibu",
	[0x46] = "angel",
	[0x47] = "spectrum holoby",
	[0x49] = "irem",
	[0x4A] = "virgin",
	[0x4D] = "malibu",
	[0x4F] = "u.s. gold",
	[0x50] = "absolute",
	[0x51] = "acclaim",
	[0x52] = "activision",
	[0x53] = "american sammy",
	[0x54] = "gametek",
	[0x55] = "park place",
	[0x56] = "ljn",
	[0x57] = "matchbox",
	[0x59] = "milton bradley",
	[0x5A] = "mindscape",
	[0x5B] = "romstar",
	[0x5C] = "naxat soft",
	[0x5D] = "tradewest",
	[0x60] = "titus",
	[0x61] = "virgin",
	[0x67] = "ocean",
	[0x69] = "electronic arts",
	[0x6E] = "elite systems",
	[0x6F] = "electro brain",
	[0x70] = "Infogrammes",
	[0x71] = "Interplay",
	[0x72] = "broderbund",
	[0x73] = "sculptered soft",
	[0x75] = "the sales curve",
	[0x78] = "t*hq",
	[0x79] = "accolade",
	[0x7A] = "triffix entertainment",
	[0x7C] = "microprose",
	[0x7F] = "kemco",
	[0x80] = "misawa entertainment",
	[0x83] = "lozc",
	[0x86] = "tokuma shoten intermedia",
	[0x8B] = "bullet-proof software",
	[0x8C] = "vic tokai",
	[0x8E] = "ape",
	[0x8F] = "i'max",
	[0x91] = "chun soft",
	[0x92] = "video system",
	[0x93] = "tsuburava",
	[0x95] = "varie",
	[0x96] = "yonezawa/s'pal",
	[0x97] = "kaneko",
	[0x99] = "arc",
	[0x9A] = "nihon bussan",
	[0x9B] = "Tecmo",
	[0x9C] = "imagineer",
	[0x9D] = "Banpresto",
	[0x9F] = "nova",
	[0xA1] = "Hori electric",
	[0xA2] = "Bandai",
	[0xA4] = "Konami",
	[0xA6] = "kawada",
	[0xA7] = "takara",
	[0xA9] = "technos japan",
	[0xAA] = "broderbund",
	[0xAC] = "Toei animation",
	[0xAD] = "toho",
	[0xAF] = "Namco",
	[0xB0] = "Acclaim",
	[0xB1] = "ascii or nexoft",
	[0xB2] = "Bandai",
	[0xB4] = "Enix",
	[0xB6] = "HAL",
	[0xB7] = "SNK",
	[0xB9] = "pony canyon",
	[0xBA] = "culture brain o",
	[0xBB] = "Sunsoft",
	[0xBD] = "Sony imagesoft",
	[0xBF] = "sammy",
	[0xC0] = "Taito",
	[0xC2] = "Kemco",
	[0xC3] = "Squaresoft",
	[0xC4] = "tokuma shoten intermedia",
	[0xC5] = "data east",
	[0xC6] = "tonkin house",
	[0xC8] = "koei",
	[0xC9] = "ufl",
	[0xCA] = "ultra",
	[0xCB] = "vap",
	[0xCC] = "use",
	[0xCD] = "meldac",
	[0xCE] = "*pony canyon or",
	[0xCF] = "angel",
	[0xD0] = "Taito",
	[0xD1] = "sofel",
	[0xD2] = "quest",
	[0xD3] = "sigma enterprises",
	[0xD4] = "ask kodansha",
	[0xD6] = "naxat soft",
	[0xD7] = "copya systems",
	[0xD9] = "Banpresto",
	[0xDA] = "tomy",
	[0xDB] = "ljn",
	[0xDD] = "ncs",
	[0xDE] = "human",
	[0xDF] = "altron",
	[0xE0] = "jaleco",
	[0xE1] = "towachiki",
	[0xE2] = "uutaka",
	[0xE3] = "varie",
	[0xE5] = "epoch",
	[0xE7] = "athena",
	[0xE8] = "asmik",
	[0xE9] = "natsume",
	[0xEA] = "king records",
	[0xEB] = "atlus",
	[0xEC] = "Epic/Sony records",
	[0xEE] = "igs",
	[0xF0] = "a wave",
	[0xF3] = "extreme entertainment",
	[0xFF] = "ljn",
	// clang-format on
};

static const char *gb_get_gameboy_type(const gb_header_t *hdr) {
	if (hdr->sgb_flag == GB_SGB_SUPPORTED) {
		return "Super GameBoy";
	} else if (hdr->cgb_flag == GB_GBC_COMPATIBLE) {
		return "GameBoy & GameBoy Color";
	} else if (hdr->cgb_flag == GB_GBC_ONLY) {
		return "GameBoy Color";
	}
	return "GameBoy";
}

static const char *gb_get_cartridge_type(const gb_header_t *hdr) {
	switch (hdr->cartridge_type) {
	case GB_ROM: return "ROM";
	case GB_ROM_MBC1: return "ROM+MBC1";
	case GB_ROM_MBC1_RAM: return "ROM+MBC1+RAM";
	case GB_ROM_MBC1_RAM_BAT: return "ROM+MBC1+RAM+BATT";
	case GB_ROM_MBC2: return "ROM+MBC2";
	case GB_ROM_MBC2_BAT: return "ROM+MBC2+BATT";
	case GB_ROM_RAM: return "ROM+RAM";
	case GB_ROM_RAM_BAT: return "ROM+RAM+BATT";
	case GB_ROM_MMM01: return "ROM+MMM01";
	case GB_ROM_MMM01_SRAM: return "ROM+MMM01+SRAM";
	case GB_ROM_MMM01_SRAM_BAT: return "ROM+MMM01+SRAM+BATT";
	case GB_ROM_MBC3_TIMER_BAT: return "ROM+MBC3+TIMER+BATT";
	case GB_ROM_MBC3_TIMER_RAM_BAT: return "ROM+MBC3+TIMER+RAM+BATT";
	case GB_ROM_MBC3: return "ROM+MBC3";
	case GB_ROM_MBC3_RAM: return "ROM+MBC3+RAM";
	case GB_ROM_MBC3_RAM_BAT: return "ROM+MBC3+RAM+BATT";
	case GB_ROM_MBC5: return "ROM+MBC5";
	case GB_ROM_MBC5_RAM: return "ROM+MBC5+RAM";
	case GB_ROM_MBC5_RAM_BAT: return "ROM+MBC5+RAM+BATT";
	case GB_ROM_MBC5_RMBL: return "ROM+MBC5+RUMBLE";
	case GB_ROM_MBC5_RMBL_SRAM: return "ROM+MBC5+RUMBLE+SRAM";
	case GB_ROM_MBC5_RMBL_SRAM_BAT: return "ROM+MBC5+RUMBLE+SRAM+BATT";
	case GB_CAM: return "Pocket Camera";
	case GB_TAMA5: return "Bandai TAMA5";
	case GB_HUC3: return "Hudson HuC-3";
	case GB_HUC1: return "Hudson HuC-1";
	default: return NULL;
	}
}

static const char *gb_get_rom_type(const gb_header_t *hdr) {
	switch (hdr->rom_size) {
	case GB_ROM_32_K_BYTES:
		return "32 KBytes (no ROM banking)";
	case GB_ROM_64_K_BYTES:
		return "64 KBytes (4 banks)";
	case GB_ROM_128_K_BYTES:
		return "128 KBytes (8 banks)";
	case GB_ROM_256_K_BYTES:
		return "256 KBytes (16 banks)";
	case GB_ROM_512_K_BYTES:
		return "512 KBytes (32 banks)";
	case GB_ROM_1_M_BYTES:
		return "1 MBytes (64 banks)";
	case GB_ROM_2_M_BYTES:
		return "2 MBytes (128 banks)";
	case GB_ROM_4_M_BYTES:
		return "4 MBytes (256 banks)";
	case GB_ROM_8_M_BYTES:
		return "8 MBytes (512 banks)";
	case GB_ROM_1_1_M_BYTES:
		return "1.1 MBytes (72 banks)";
	case GB_ROM_1_2_M_BYTES:
		return "1.2 MBytes (80 banks)";
	case GB_ROM_1_5_M_BYTES:
		return "1.5 MBytes (96 banks)";
	default: return NULL;
	}
}

static const char *gb_get_ram_type(const gb_header_t *hdr) {
	switch (hdr->ram_size) {
	case GB_RAM_NONE:
		return "None";
	case GB_RAM_2_K_BYTES:
		return "2 KBytes";
	case GB_RAM_8_K_BYTES:
		return "8 Kbytes";
	case GB_RAM_32_K_BYTES:
		return "32 KBytes (4 banks)";
	case GB_RAM_128_K_BYTES:
		return "128 KBytes (16 banks)";
	case GB_RAM_64_K_BYTES:
		return "64 KBytes (8 banks)";
	default: return NULL;
	}
}

static ut32 gb_get_ram_banks(const gb_header_t *hdr) {
	switch (hdr->ram_size) {
	case GB_RAM_2_K_BYTES:
		return 1;
	case GB_RAM_8_K_BYTES:
		return 1;
	case GB_RAM_32_K_BYTES:
		return 4;
	case GB_RAM_128_K_BYTES:
		return 16;
	case GB_RAM_64_K_BYTES:
		return 8;
	default:
		return 0;
	}
}

static ut32 gb_get_rom_banks(const gb_header_t *hdr) {
	switch (hdr->rom_size) {
	case GB_ROM_32_K_BYTES:
		return 0; /// (no ROM banking)
	case GB_ROM_64_K_BYTES:
		return 4; /// (4 banks)
	case GB_ROM_128_K_BYTES:
		return 8; /// (8 banks)
	case GB_ROM_256_K_BYTES:
		return 16; /// (16 banks)
	case GB_ROM_512_K_BYTES:
		return 32; /// (32 banks)
	case GB_ROM_1_M_BYTES:
		return 64; /// (64 banks)  - only 63 banks used by MBC1
	case GB_ROM_2_M_BYTES:
		return 128; /// (128 banks) - only 125 banks used by MBC1
	case GB_ROM_4_M_BYTES:
		return 256; /// (256 banks)
	case GB_ROM_8_M_BYTES:
		return 512; /// (512 banks)
	case GB_ROM_1_1_M_BYTES:
		return 72; /// (72 banks)
	case GB_ROM_1_2_M_BYTES:
		return 80; /// (80 banks)
	case GB_ROM_1_5_M_BYTES:
		return 96; /// (96 banks)
	default:
		return 2;
	}
}

static bool gb_check_buffer(RzBuffer *b) {
	ut8 nin_logo[GB_ROM_NINTENDO_LOGO_SIZE];

	st32 read = rz_buf_read_at(b, GB_ROM_NINTENDO_LOGO_OFFSET, nin_logo, sizeof(nin_logo));
	if (read != sizeof(nin_logo)) {
		return false;
	}
	return !memcmp(nin_logo, gb_nintendo_logo, sizeof(nin_logo));
}

/**
 * This function just resolves the first 4 bytes of the header
 * which is the entrypoint of the cartridge.
 *
 * The expected instructions are
 *
 * 0x00000100 xx      ?
 * 0x00000101 c3yyyy  jp 0xyyyy
 */
static bool gb_header_parse_main(RzBuffer *buf, ut64 *offset, gb_header_t *hdr) {
	ut8 code[4];

	if (!rz_buf_read_offset(buf, offset, code, sizeof(code))) {
		return false;
	}

	// if we don't find `jp` instruction
	// we just ignore this address.
	hdr->main_address = UT32_MAX;
	if (code[1] == 0xc3) {
		hdr->main_address = code[3] * 0x100 + code[2];
	}
	return true;
}

static bool gb_header_resolve_title(RzBuffer *buf, ut64 *offset, gb_header_t *hdr) {
	if (!rz_buf_read_offset(buf, offset, (ut8 *)hdr->title, sizeof(hdr->title))) {
		return false;
	}

	hdr->cgb_flag = hdr->title[15];
	if (hdr->cgb_flag == GB_GBC_COMPATIBLE) {
		// manufacturer is never present
		hdr->title[15] = 0;
	} else if (hdr->cgb_flag == GB_GBC_ONLY) {
		// manufacturer is always present
		hdr->manufacturer[0] = hdr->title[11];
		hdr->manufacturer[1] = hdr->title[12];
		hdr->manufacturer[2] = hdr->title[13];
		hdr->manufacturer[3] = hdr->title[14];
		// cleanup the title.
		hdr->title[11] = 0;
		hdr->title[12] = 0;
		hdr->title[13] = 0;
		hdr->title[14] = 0;
		hdr->title[15] = 0;
	}

	return true;
}

static bool gb_header_parse(RzBuffer *buf, ut64 off, gb_header_t *hdr) {
	return gb_header_parse_main(buf, &off, hdr) &&
		rz_buf_read_offset(buf, &off, hdr->nintendo_logo, sizeof(hdr->nintendo_logo)) &&
		gb_header_resolve_title(buf, &off, hdr) &&
		rz_buf_read_offset(buf, &off, (ut8 *)hdr->new_licensee_code, sizeof(hdr->new_licensee_code)) &&
		rz_buf_read8_offset(buf, &off, &hdr->sgb_flag) &&
		rz_buf_read8_offset(buf, &off, &hdr->cartridge_type) &&
		rz_buf_read8_offset(buf, &off, &hdr->rom_size) &&
		rz_buf_read8_offset(buf, &off, &hdr->ram_size) &&
		rz_buf_read8_offset(buf, &off, &hdr->destination_code) &&
		rz_buf_read8_offset(buf, &off, &hdr->licensee_code) &&
		rz_buf_read8_offset(buf, &off, &hdr->mask_rom_version_number) &&
		rz_buf_read8_offset(buf, &off, &hdr->header_checksum) &&
		rz_buf_read_le16_offset(buf, &off, &hdr->global_checksum);
}

static bool gb_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	gb_header_t *hdr = RZ_NEW0(gb_header_t);
	if (!hdr) {
		return false;
	}

	if (!gb_header_parse(buf, GB_ROM_CARTRIDGE_HEADER_OFFSET, hdr)) {
		free(hdr);
		return false;
	}

	obj->bin_obj = hdr;
	return true;
}

static void gb_destroy(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return;
	}

	RZ_FREE(bf->o->bin_obj);
}

static ut64 gb_baddr(RzBinFile *bf) {
	return 0LL;
}

static RzBinAddr *gb_bin_addr_new(ut32 address, ut32 type) {
	if (address == UT32_MAX) {
		return NULL;
	}

	RzBinAddr *baddr = RZ_NEW0(RzBinAddr);
	if (!baddr) {
		return NULL;
	}

	baddr->paddr = address;
	baddr->vaddr = address;
	baddr->type = type;
	baddr->bits = 16;
	return baddr;
}

static RzBinAddr *gb_binsym(RzBinFile *bf, RzBinSpecialSymbol type) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	const gb_header_t *hdr = bf->o->bin_obj;

	switch (type) {
	case RZ_BIN_SPECIAL_SYMBOL_ENTRY:
		// the header contains the entrypoint code that jumps to the main
		return gb_bin_addr_new(GB_ROM_CARTRIDGE_HEADER_OFFSET, RZ_BIN_SPECIAL_SYMBOL_ENTRY);
	case RZ_BIN_SPECIAL_SYMBOL_MAIN:
		return gb_bin_addr_new(hdr->main_address, RZ_BIN_SPECIAL_SYMBOL_MAIN);
	default:
		break;
	}
	return NULL;
}

static RzPVector /*<RzBinAddr *>*/ *gb_entries(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	const gb_header_t *hdr = bf->o->bin_obj;

	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}

	RzBinAddr *baddr = gb_bin_addr_new(GB_ROM_CARTRIDGE_HEADER_OFFSET, RZ_BIN_SPECIAL_SYMBOL_ENTRY);
	if (!baddr) {
		rz_pvector_free(ret);
		return NULL;
	}
	rz_pvector_push(ret, baddr);

	baddr = gb_bin_addr_new(hdr->main_address, RZ_BIN_SPECIAL_SYMBOL_MAIN);
	if (!baddr) {
		// can be NULL.
		return ret;
	}

	rz_pvector_push(ret, baddr);
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *gb_sections(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	const gb_header_t *hdr = bf->o->bin_obj;

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	for (ut32 i = 0; i < gb_get_rom_banks(hdr); i++) {
		RzBinSection *section = RZ_NEW0(RzBinSection);
		if (!section) {
			return ret;
		}

		section->name = rz_str_newf("rom_bank%02x", i);
		section->paddr = i * 16384; // 16KBytes
		section->vaddr = i ? (i * 0x10000 - 0xc000) : 0;
		section->size = section->vsize = 16384; // 16KBytes
		section->perm = RZ_PERM_RX;
		rz_pvector_push(ret, section);
	}

	size_t ram_bank_size = 8192; // 8KBytes
	if (hdr->ram_size == GB_RAM_2_K_BYTES) {
		ram_bank_size = 2048; // 2KBytes
	}

	for (ut32 i = 0; i < gb_get_ram_banks(hdr); i++) {
		RzBinSection *section = RZ_NEW0(RzBinSection);
		if (!section) {
			return ret;
		}

		section->name = rz_str_newf("ram_bank%02x", i);
		section->paddr = 0;
		section->size = 0;
		section->vaddr = 0xa000;
		section->vsize = ram_bank_size;
		section->perm = RZ_PERM_RWX;
		rz_pvector_push(ret, section);
	}
	return ret;
}

static RzBinSymbol *gb_symbol_new(const gb_symbol_t *gsym) {
	RzBinSymbol *bsym = RZ_NEW0(RzBinSymbol);
	if (!bsym) {
		return NULL;
	}

	bsym->name = rz_str_dup(gsym->name);
	bsym->paddr = gsym->addr;
	bsym->vaddr = gsym->addr;
	bsym->size = gsym->size;
	bsym->ordinal = gsym->ordinal;

	return bsym;
}

static RzPVector /*<RzBinSymbol *>*/ *gb_symbols(RzBinFile *bf) {
	RzPVector *ret = NULL;
	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free))) {
		return NULL;
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(gb_cpu_symbols); i++) {
		const gb_symbol_t *gsym = &gb_cpu_symbols[i];

		RzBinSymbol *bsym = gb_symbol_new(gsym);
		if (!bsym) {
			rz_pvector_free(ret);
			return NULL;
		}

		rz_pvector_push(ret, bsym);
	}

	return ret;
}

static RzBinInfo *gb_info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret || !bf || !bf->o || !bf->o->bin_obj) {
		free(ret);
		return NULL;
	}

	const gb_header_t *hdr = bf->o->bin_obj;

	const char *gbtype = gb_get_gameboy_type(hdr);
	const char *cardtype = gb_get_cartridge_type(hdr);

	ret->type = rz_str_dup(cardtype);
	ret->file = rz_str_ndup(hdr->title, sizeof(hdr->title));
	ret->machine = rz_str_dup(gbtype);
	ret->os = rz_str_dup("any");
	ret->arch = rz_str_dup("gb");
	ret->has_va = true;
	ret->bits = 16;
	ret->big_endian = false;
	ret->dbg_info = 0;
	return ret;
}

static RzBinMem *gb_mem_new(const gb_memory_t *mem) {
	RzBinMem *bmem = RZ_NEW0(RzBinMem);
	if (!bmem) {
		return NULL;
	}

	bmem->name = rz_str_dup(mem->name);
	bmem->addr = mem->addr;
	bmem->size = mem->size;
	bmem->perms = mem->perms;

	if (!mem->mirror) {
		return bmem;
	}

	if (!(bmem->mirrors = rz_pvector_new(rz_bin_mem_free))) {
		return bmem;
	}

	RzBinMem *m = gb_mem_new(mem->mirror);
	rz_pvector_push(bmem->mirrors, m);

	return bmem;
}

static RzPVector /*<RzBinMem *>*/ *gb_mem(RzBinFile *bf) {
	RzPVector *ret;
	if (!(ret = rz_pvector_new(rz_bin_mem_free))) {
		return NULL;
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(gb_memory); ++i) {
		const gb_memory_t *mem = &gb_memory[i];
		RzBinMem *m = gb_mem_new(mem);
		if (!m) {
			rz_pvector_free(ret);
			return NULL;
		}

		rz_pvector_push(ret, m);
	}

	return ret;
}

static const char *gb_old_resolve_licensee(const gb_header_t *hdr) {
	return gb_old_licensee[hdr->licensee_code];
}

static const char *gb_new_resolve_licensee(const gb_header_t *hdr) {
	for (size_t i = 0; i < RZ_ARRAY_SIZE(gb_new_licensee); ++i) {
		const gb_new_licensee_code_t *elem = &gb_new_licensee[i];

		if (hdr->new_licensee_code[0] == elem->code[0] &&
			hdr->new_licensee_code[1] == elem->code[1]) {
			return elem->name;
		}
	}
	return NULL;
}

static void gb_structure_licensee(const gb_header_t *hdr, RzStructuredData *root) {
	const char *readable = NULL;
	RzStructuredData *licensee = rz_structured_data_map_add_map(root, "licensee");
	if (!licensee) {
		return;
	}

	rz_structured_data_map_add_unsigned(licensee, "old_code", hdr->licensee_code, true);
	if (hdr->licensee_code != GB_ROM_OLD_LICENSEE_NEW_LICENSEE) {
		readable = gb_old_resolve_licensee(hdr);
	} else {
		rz_structured_data_map_add_string_n(licensee, "new_code", hdr->new_licensee_code, sizeof(hdr->new_licensee_code));
		readable = gb_new_resolve_licensee(hdr);
	}

	if (!readable) {
		return;
	}

	rz_structured_data_map_add_string(licensee, "readable", readable);
}

static void gb_structure_destination_code(const gb_header_t *hdr, RzStructuredData *root) {
	RzStructuredData *dst = rz_structured_data_map_add_map(root, "destination");
	if (!dst) {
		return;
	}

	rz_structured_data_map_add_unsigned(dst, "value", hdr->destination_code, true);

	switch (hdr->destination_code) {
	case GB_DEST_CODE_JAPANESE:
		rz_structured_data_map_add_string(dst, "readable", "Japanese");
		break;
	case GB_DEST_CODE_NON_JAPANESE:
		rz_structured_data_map_add_string(dst, "readable", "Non-Japanese");
		break;
	default:
		break;
	}
}

static void gb_structure_cgb_flag(const gb_header_t *hdr, RzStructuredData *root) {
	if (!hdr->cgb_flag) {
		// never add it if not set.
		return;
	}

	RzStructuredData *cgb = rz_structured_data_map_add_map(root, "cgb_flag");
	if (!cgb) {
		return;
	}

	rz_structured_data_map_add_unsigned(cgb, "value", hdr->cgb_flag, true);

	switch (hdr->cgb_flag) {
	case GB_GBC_COMPATIBLE:
		rz_structured_data_map_add_string(cgb, "readable", "GameBoy & GameBoy Color Rom");
		break;
	case GB_GBC_ONLY:
		rz_structured_data_map_add_string(cgb, "readable", "GameBoy Color Only Rom");
		break;
	default:
		break;
	}
}

static void gb_structure_sgb_flag(const gb_header_t *hdr, RzStructuredData *root) {
	RzStructuredData *sgb = rz_structured_data_map_add_map(root, "sgb_flag");
	if (!sgb) {
		return;
	}

	rz_structured_data_map_add_unsigned(sgb, "value", hdr->sgb_flag, true);

	switch (hdr->sgb_flag) {
	case GB_SGB_NOT_SUPPORTED:
		rz_structured_data_map_add_string(sgb, "readable", "No SGB support");
		break;
	case GB_SGB_SUPPORTED:
		rz_structured_data_map_add_string(sgb, "readable", "Game supports SGB");
		break;
	default:
		break;
	}
}

static void gb_structure_cartridge_type(const gb_header_t *hdr, RzStructuredData *root) {
	RzStructuredData *cart = rz_structured_data_map_add_map(root, "cartridge");
	if (!cart) {
		return;
	}

	const char *readable = gb_get_cartridge_type(hdr);

	rz_structured_data_map_add_unsigned(cart, "value", hdr->cartridge_type, true);
	if (!readable) {
		return;
	}

	rz_structured_data_map_add_string(cart, "readable", readable);
}

static void gb_structure_ram_size(const gb_header_t *hdr, RzStructuredData *root) {
	RzStructuredData *ram = rz_structured_data_map_add_map(root, "ram");
	if (!ram) {
		return;
	}

	const char *readable = gb_get_ram_type(hdr);

	rz_structured_data_map_add_unsigned(ram, "value", hdr->ram_size, true);
	if (!readable) {
		return;
	}

	rz_structured_data_map_add_string(ram, "readable", readable);
}

static void gb_structure_rom_size(const gb_header_t *hdr, RzStructuredData *root) {
	RzStructuredData *rom = rz_structured_data_map_add_map(root, "rom");
	if (!rom) {
		return;
	}

	const char *readable = gb_get_rom_type(hdr);

	rz_structured_data_map_add_unsigned(rom, "value", hdr->rom_size, true);
	if (!readable) {
		return;
	}

	rz_structured_data_map_add_string(rom, "readable", readable);
}

static RzStructuredData *gb_structure(RzBinFile *bf) {
	const gb_header_t *hdr = bf->o->bin_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_map_add_map(info, "gb");
	if (!root) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(root, "main_address", hdr->main_address, true);
	rz_structured_data_map_add_bytes(root, "nintendo_logo", hdr->nintendo_logo, sizeof(hdr->nintendo_logo), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_string_n(root, "title", hdr->title, sizeof(hdr->title));
	if (hdr->cgb_flag == GB_GBC_ONLY) {
		rz_structured_data_map_add_string_n(root, "manufacturer", hdr->manufacturer, sizeof(hdr->manufacturer));
	}
	gb_structure_cgb_flag(hdr, root);
	gb_structure_licensee(hdr, root);
	gb_structure_sgb_flag(hdr, root);
	gb_structure_cartridge_type(hdr, root);
	gb_structure_rom_size(hdr, root);
	gb_structure_ram_size(hdr, root);
	gb_structure_destination_code(hdr, root);
	rz_structured_data_map_add_unsigned(root, "mask_rom_version_number", hdr->mask_rom_version_number, true);
	rz_structured_data_map_add_unsigned(root, "header_checksum", hdr->header_checksum, true);
	rz_structured_data_map_add_unsigned(root, "global_checksum", hdr->global_checksum, true);

	return info;
}

RzBinPlugin rz_bin_plugin_ningb = {
	.name = "ningb",
	.desc = "Nintendo Game Boy",
	.license = "LGPL3",
	.author = "condret",
	.load_buffer = &gb_load_buffer,
	.check_buffer = &gb_check_buffer,
	.baddr = &gb_baddr,
	.binsym = &gb_binsym,
	.entries = &gb_entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &gb_sections,
	.symbols = &gb_symbols,
	.info = &gb_info,
	.mem = &gb_mem,
	.destroy = &gb_destroy,
	.bin_structure = &gb_structure,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_ningb,
	.version = RZ_VERSION
};
#endif
