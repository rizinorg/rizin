// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2018-2019 lowlyw <cutlassc91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file bin_nin64.c
 *
 * This plugin is for parsing the Nintendo 64 ROM.
 *
 * References:
 * - https://n64brew.dev/wiki/ROM_Header
 * - https://github.com/mikeryan/n64dev
 * - http://en64.shoutwiki.com/wiki/N64_Memory
 *
 * According to the wiki there is no magic header
 * but for some reasons, the first 4 bytes of all
 * official software is always set to 0x80, 0x37, 0x12, 0x40
 *
 * This plugin will use these "constant" values to detect the
 * endianness of the binary and parse the header accordingly.
 *
 * This plugin also supports the homebrew ROM header values
 * See https://n64brew.dev/wiki/ROM_Header for more info.
 */

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_io.h>
#include <rz_cons.h>

#define N64_CLOCK_RATE_MASK     0xfffffff0
#define N64_CLOCK_RATE_LIBULTRA 0x03b9aca0

#define N64_ROM_HEADER_SIZE 0x1000

#define N64_IPL3_ENTRYPOINT 0x40
#define N64_ROM_ENTRYPOINT  N64_ROM_HEADER_SIZE

#define N64_IPL3_PHY_ADDRESS 0
#define N64_IPL3_VIRT_ADDR   0x04000000
#define N64_IPL3_SIZE        N64_ROM_HEADER_SIZE

#define N64_HB_CONTROLLER_UNKNOWN             0x00 //< No information provided.
#define N64_HB_CONTROLLER_RUMBLE_PAK          0x01 //< N64 controller with Rumble Pak
#define N64_HB_CONTROLLER_CONTROLLER_PAK      0x02 //< N64 controller with Controller Pak
#define N64_HB_CONTROLLER_TRANSFER_PAK        0x03 //< N64 controller with Transfer Pak
#define N64_HB_CONTROLLER_MOUSE               0x80 //< N64 mouse
#define N64_HB_CONTROLLER_VRU                 0x81 //< VRU
#define N64_HB_CONTROLLER_GAMECUBE_CONTROLLER 0x82 //< Gamecube controller
#define N64_HB_CONTROLLER_RANDNET_KEYBOARD    0x83 //< Randnet keyboard
#define N64_HB_CONTROLLER_GAMECUBE_KEYBOARD   0x84 //< Gamecube keyboard
#define N64_HB_CONTROLLER_EMPTY               0xFF //< Nothing attached to this port

#define N64_HB_SAVETYPE_BIT_ENABLE_RTC  (1 << 0)
#define N64_HB_SAVETYPE_BIT_REGION_FREE (1 << 1)
#define N64_HB_SAVETYPE_SIZE_MASK       (0xf0)

typedef enum {
	N64_HB_SAVETYPE_UNUSED = 0,
	N64_HB_SAVETYPE_4K_EEPROM = 1,
	N64_HB_SAVETYPE_16K_EEPROM = 2,
	N64_HB_SAVETYPE_256K_SRAM = 3,
	N64_HB_SAVETYPE_768K_SRAM = 4, // banked
	N64_HB_SAVETYPE_FLASH_RAM = 5,
	N64_HB_SAVETYPE_1M_SRAM = 6,
} N64SaveTypeSize;

typedef struct n64_homebrew {
	ut8 controller_1;
	ut8 controller_2;
	ut8 controller_3;
	ut8 controller_4;
	bool enable_rtc;
	bool is_region_free;
	N64SaveTypeSize save_size;
} N64Homebrew;

typedef struct n64_rom {
	ut8 reserved0;
	ut8 rls_pgs; /* bit 4-5 release timing - PI_BSD_DOM1_RLS | bit 0-3 page size - PI_BSD_DOM1_PGS */
	ut8 pulse_width; /* PI_BSD_DOM1_PWD */
	ut8 latency; /* PI_BSD_DOM1_LAT */
	ut32 clock_rate;
	ut32 boot_address;
	ut8 libultra_version[4];
	ut64 check_code;
	ut8 reserved1[8];
	char game_title[20];
	ut8 reserved2[7];
	ut8 game_code[4];
	ut8 rom_version;
} N64Rom;

#define n64_is_homebrew(rom) (rom->game_code[1] == 'E' && rom->game_code[2] == 'D')

static bool n64_has_magic(RzBuffer *b, bool *big_endian) {
	ut8 magic[4] = { 0 };
	if (rz_buf_size(b) < N64_ROM_HEADER_SIZE) {
		return false;
	} else if (rz_buf_read_at(b, 0, magic, sizeof(magic)) != sizeof(magic)) {
		return false;
	} else if (!memcmp(magic, "\x80\x37\x12\x40", 4)) {
		*big_endian = true;
		return true;
	} else if (!memcmp(magic, "\x40\x12\x37\x80", 4)) {
		*big_endian = false;
		return true;
	}
	return false;
}

static bool n64_check_buffer(RzBuffer *b) {
	bool big_endian = false;
	return n64_has_magic(b, &big_endian);
}

static bool n64_parse_rom_header(RzBuffer *buf, N64Rom *rom, bool big_endian) {
	ut64 offset = 0;
	return rz_buf_read_ble8_offset(buf, &offset, &rom->reserved0, big_endian) &&
		rz_buf_read_ble8_offset(buf, &offset, &rom->rls_pgs, big_endian) &&
		rz_buf_read_ble8_offset(buf, &offset, &rom->pulse_width, big_endian) &&
		rz_buf_read_ble8_offset(buf, &offset, &rom->latency, big_endian) &&
		rz_buf_read_ble32_offset(buf, &offset, &rom->clock_rate, big_endian) &&
		rz_buf_read_ble32_offset(buf, &offset, &rom->boot_address, big_endian) &&
		rz_buf_read_offset(buf, &offset, rom->libultra_version, sizeof(rom->libultra_version)) &&
		rz_buf_read_ble64_offset(buf, &offset, &rom->check_code, big_endian) &&
		rz_buf_read_offset(buf, &offset, rom->reserved1, sizeof(rom->reserved1)) &&
		rz_buf_read_offset(buf, &offset, (ut8 *)rom->game_title, sizeof(rom->game_title)) &&
		rz_buf_read_offset(buf, &offset, rom->reserved2, sizeof(rom->reserved2)) &&
		rz_buf_read_offset(buf, &offset, rom->game_code, sizeof(rom->game_code)) &&
		rz_buf_read_ble8_offset(buf, &offset, &rom->rom_version, big_endian);
}

static bool n64_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	bool big_endian = false;
	if (!n64_has_magic(b, &big_endian)) {
		return false;
	}

	N64Rom *rom = RZ_NEW0(N64Rom);
	if (!rom || !n64_parse_rom_header(b, rom, big_endian)) {
		free(rom);
		return false;
	}

	// sanitize in case game_code is empty.
	if (!rom->game_code[1]) {
		rom->game_code[1] = '.';
	}
	if (!rom->game_code[2]) {
		rom->game_code[2] = '.';
	}

	obj->bin_obj = rom;
	return true;
}

static RzBinAddr *n64_bin_addr(RzBinSpecialSymbol type, ut64 paddr, ut64 vaddr) {
	RzBinAddr *ba = RZ_NEW0(RzBinAddr);
	if (!ba) {
		return NULL;
	}
	ba->type = type;
	ba->paddr = ba->hpaddr = paddr;
	ba->vaddr = ba->hvaddr = vaddr;
	return ba;
}

static RzPVector /*<RzBinAddr *>*/ *n64_entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);

	N64Rom *rom = bf->o->bin_obj;
	RzBinAddr *ptr = NULL;

	RzPVector /*<RzBinAddr *>*/ *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}

	// ipl3 always includes the header, but ipl2 will jump after the ROM header.
	ptr = n64_bin_addr(RZ_BIN_SPECIAL_SYMBOL_ENTRY, N64_IPL3_PHY_ADDRESS + N64_IPL3_ENTRYPOINT, N64_IPL3_VIRT_ADDR + N64_IPL3_ENTRYPOINT);
	if (!ptr) {
		rz_pvector_free(ret);
		return NULL;
	}
	rz_pvector_push(ret, ptr);

	// boot address is the main function
	ptr = n64_bin_addr(RZ_BIN_SPECIAL_SYMBOL_MAIN, N64_ROM_ENTRYPOINT, rom->boot_address);
	if (!ptr) {
		rz_pvector_free(ret);
		return NULL;
	}
	rz_pvector_push(ret, ptr);

	return ret;
}

static RzBinSection *n64_section(const char *name, ut64 paddr, ut64 vaddr, size_t size) {
	RzBinSection *sect = RZ_NEW0(RzBinSection);
	if (!sect) {
		return NULL;
	}
	sect->name = rz_str_dup(name);
	sect->size = size;
	sect->vsize = size;
	sect->paddr = paddr;
	sect->vaddr = vaddr;
	sect->perm = RZ_PERM_RX;
	return sect;
}

static RzPVector /*<RzBinSection *>*/ *n64_sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);

	N64Rom *rom = bf->o->bin_obj;
	size_t file_size = rz_buf_size(bf->buf);
	RzBinSection *sect = NULL;

	RzPVector /*<RzBinSection *>*/ *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	// ipl3 includes the rom header
	sect = n64_section("ipl3", N64_IPL3_PHY_ADDRESS, N64_IPL3_VIRT_ADDR, N64_IPL3_SIZE);
	if (!sect) {
		rz_pvector_free(ret);
		return NULL;
	}
	rz_pvector_push(ret, sect);

	// after the ipl3 there is the text game section
	sect = n64_section("text", N64_IPL3_SIZE, rom->boot_address, file_size - N64_IPL3_SIZE);
	if (!sect) {
		rz_pvector_free(ret);
		return NULL;
	}
	rz_pvector_push(ret, sect);

	return ret;
}

static RzBinInfo *n64_info(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);

	bool big_endian = false;
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	n64_has_magic(bf->buf, &big_endian);

	ret->file = rz_str_dup(bf->file);
	ret->os = rz_str_dup("n64");
	ret->arch = rz_str_dup("mips");
	ret->machine = rz_str_dup("Nintendo 64");
	ret->type = rz_str_dup("ROM");
	ret->bits = 64;
	ret->has_va = true;
	ret->big_endian = big_endian;

	return ret;
}

static ut64 n64_boffset(RzBinFile *bf) {
	return 0LL;
}

static ut64 n64_baddr(RzBinFile *bf) {
	rz_return_val_if_fail(bf, UT64_MAX);

	N64Rom *rom = bf->o->bin_obj;
	return (ut64)rom->boot_address;
}

static void n64_destroy(RzBinFile *bf) {
	free(bf->o->bin_obj);
}

static void n64_decode_rls_pgs(N64Rom *rom, ut8 *rls, ut8 *pgs) {
	*rls = (rom->rls_pgs >> 4) & 3;
	*pgs = rom->rls_pgs & 0xF;
}

static ut32 n64_decode_clock_rate(N64Rom *rom) {
	ut32 clock = rom->clock_rate & N64_CLOCK_RATE_MASK;
	if (!clock) {
		// if the masked value equals zero, libultra defaults to 0x03B9ACA0
		return N64_CLOCK_RATE_LIBULTRA;
	}
	return clock;
}

static char *n64_decode_libultra_version(N64Rom *rom) {
	ut8 major = rom->libultra_version[2] / 10;
	ut8 minor = rom->libultra_version[2] % 10;
	return rz_str_newf("%u.%u%c", major, minor, (char)rom->libultra_version[3]);
}

static const char *n64_decode_controller(ut8 controller) {
	switch (controller) {
	case N64_HB_CONTROLLER_RUMBLE_PAK:
		return "Rumble Pak";
	case N64_HB_CONTROLLER_CONTROLLER_PAK:
		return "Controller Pak";
	case N64_HB_CONTROLLER_TRANSFER_PAK:
		return "Transfer Pak";
	case N64_HB_CONTROLLER_MOUSE:
		return "Mouse";
	case N64_HB_CONTROLLER_VRU:
		return "Vru";
	case N64_HB_CONTROLLER_GAMECUBE_CONTROLLER:
		return "Gamecube Controller";
	case N64_HB_CONTROLLER_RANDNET_KEYBOARD:
		return "Randnet Keyboard";
	case N64_HB_CONTROLLER_GAMECUBE_KEYBOARD:
		return "Gamecube Keyboard";
	case N64_HB_CONTROLLER_EMPTY:
		return "Empty";
	default:
		return "Not Used";
	}
}

static const char *n64_decode_savetype_size(N64SaveTypeSize size) {
	switch (size) {
	case N64_HB_SAVETYPE_4K_EEPROM: return "4K EEPROM";
	case N64_HB_SAVETYPE_16K_EEPROM: return "16K EEPROM";
	case N64_HB_SAVETYPE_256K_SRAM: return "256K SRAM";
	case N64_HB_SAVETYPE_768K_SRAM: return "768K SRAM (banked)";
	case N64_HB_SAVETYPE_FLASH_RAM: return "Flash RAM";
	case N64_HB_SAVETYPE_1M_SRAM: return "1M SRAM";
	default: return "";
	}
}

static const char *n64_decode_game_category(N64Rom *rom) {
	switch (rom->game_code[0]) {
	case 'N': return "Game Pak";
	case 'D': return "64DD Disk";
	case 'C': return "Expandable Game: Game Pak Part";
	case 'E': return "Expandable Game: 64DD Disk Part";
	case 'Z': return "Aleck64 Game Pak";
	default:
		if (n64_is_homebrew(rom)) {
			return "Homebrew";
		}
		return "Unset";
	}
}

static const char *n64_decode_game_destination(N64Rom *rom) {
	switch (rom->game_code[3]) {
	case 'A': return "All";
	case 'H': return "Netherlands";
	case 'S': return "Spain";
	case 'B': return "Brazil";
	case 'I': return "Italy";
	case 'U': return "Australia";
	case 'C': return "China";
	case 'J': return "Japan";
	case 'W': return "Scandinavia";
	case 'D': return "Germany";
	case 'K': return "Korea";
	case 'X': return "Europe";
	case 'E': return "North America";
	case 'L': return "Gateway 64 (PAL)";
	case 'Y': return "Europe";
	case 'F': return "France";
	case 'N': return "Canada";
	case 'Z': return "Europe";
	case 'G': return "Gateway 64 (NTSC)";
	case 'P': return "Europe";
	default:
		if (n64_is_homebrew(rom)) {
			return "Region Free";
		}
		return "Unset";
	}
}

static bool n64_parse_homebrew_header(N64Rom *rom, N64Homebrew *hb) {
	if (!n64_is_homebrew(rom)) {
		return false;
	}
	hb->controller_1 = rom->reserved2[0]; // 0x34
	hb->controller_2 = rom->reserved2[1]; // 0x35
	hb->controller_3 = rom->reserved2[2]; // 0x36
	hb->controller_4 = rom->reserved2[3]; // 0x37
	hb->enable_rtc = rom->rom_version & N64_HB_SAVETYPE_BIT_ENABLE_RTC;
	hb->is_region_free = rom->rom_version & N64_HB_SAVETYPE_BIT_REGION_FREE;
	hb->save_size = (rom->rom_version & N64_HB_SAVETYPE_SIZE_MASK) >> 4;
	return true;
}

static bool n64_structure_homebrew(N64Rom *rom, RzStructuredData *rom_data) {
	N64Homebrew hb = { 0 };
	if (!n64_parse_homebrew_header(rom, &hb)) {
		return true;
	}

	RzStructuredData *homebrew = rz_structured_data_map_add_map(rom_data, "homebrew");
	if (!homebrew) {
		return false;
	}

	RzStructuredData *controllers = rz_structured_data_map_add_array(homebrew, "controllers");
	if (!controllers) {
		return false;
	}

	RzStructuredData *controller = rz_structured_data_array_add_map(controllers);
	if (!controller) {
		return false;
	}

	rz_structured_data_map_add_string(controller, "description", n64_decode_controller(hb.controller_1));
	rz_structured_data_map_add_unsigned(controller, "value", hb.controller_1, true);

	if (!(controller = rz_structured_data_array_add_map(controllers))) {
		return false;
	}

	rz_structured_data_map_add_string(controller, "description", n64_decode_controller(hb.controller_2));
	rz_structured_data_map_add_unsigned(controller, "value", hb.controller_2, true);

	if (!(controller = rz_structured_data_array_add_map(controllers))) {
		return false;
	}

	rz_structured_data_map_add_string(controller, "description", n64_decode_controller(hb.controller_3));
	rz_structured_data_map_add_unsigned(controller, "value", hb.controller_3, true);

	if (!(controller = rz_structured_data_array_add_map(controllers))) {
		return false;
	}

	rz_structured_data_map_add_string(controller, "description", n64_decode_controller(hb.controller_4));
	rz_structured_data_map_add_unsigned(controller, "value", hb.controller_4, true);

	rz_structured_data_map_add_boolean(homebrew, "enable_rtc", hb.enable_rtc);
	rz_structured_data_map_add_boolean(homebrew, "region_free", hb.is_region_free);
	rz_structured_data_map_add_string(homebrew, "savetype_size", n64_decode_savetype_size(hb.save_size));

	return true;
}

static RzStructuredData *n64_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	N64Rom *rom = bf->o->bin_obj;

	char game_code[4] = { 0 };
	ut8 rls = 0, pgs = 0;
	n64_decode_rls_pgs(rom, &rls, &pgs);

	// only the 3rd & 4th value
	game_code[0] = rom->game_code[1];
	game_code[1] = rom->game_code[2];

	ut32 clock_rate = n64_decode_clock_rate(rom);
	char *reserved1 = rz_hex_bin2strdup(rom->reserved1, sizeof(rom->reserved1));
	char *game_title = rz_str_ndup(rom->game_title, sizeof(rom->game_title));
	char *libultra_version = n64_decode_libultra_version(rom);
	char *reserved2 = rz_hex_bin2strdup(rom->reserved2, sizeof(rom->reserved2));

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *rom_data = rz_structured_data_map_add_map(info, "n64_rom");
	if (!rom_data) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(rom_data, "reserved_0", rom->reserved0, true);
	rz_structured_data_map_add_unsigned(rom_data, "PI_BSD_DOM1_RLS", rls, true);
	rz_structured_data_map_add_unsigned(rom_data, "PI_BSD_DOM1_PGS", pgs, true);
	rz_structured_data_map_add_unsigned(rom_data, "PI_BSD_DOM1_PWD", rom->pulse_width, true);
	rz_structured_data_map_add_unsigned(rom_data, "PI_BSD_DOM1_LAT", rom->latency, true);
	rz_structured_data_map_add_unsigned(rom_data, "clock_rate", clock_rate, true);
	rz_structured_data_map_add_unsigned(rom_data, "boot_address", rom->boot_address, true);
	rz_structured_data_map_add_string(rom_data, "libultra_version", rz_str_get(libultra_version));
	rz_structured_data_map_add_unsigned(rom_data, "check_code", rom->check_code, true);
	rz_structured_data_map_add_string(rom_data, "reserved_1", reserved1);
	rz_structured_data_map_add_string(rom_data, "game_title", rz_str_get(game_title));
	rz_structured_data_map_add_string(rom_data, "reserved_2", reserved2);
	rz_structured_data_map_add_string(rom_data, "game_category", n64_decode_game_category(rom));
	rz_structured_data_map_add_string(rom_data, "game_unique_code", game_code);
	rz_structured_data_map_add_string(rom_data, "game_destination", n64_decode_game_destination(rom));
	rz_structured_data_map_add_unsigned(rom_data, "version", rom->rom_version, false);

	free(reserved2);
	free(libultra_version);
	free(game_title);
	free(reserved1);

	if (!n64_structure_homebrew(rom, rom_data)) {
		rz_structured_data_free(info);
		return NULL;
	}

	return info;
}

RzBinPlugin rz_bin_plugin_z64 = {
	.name = "z64",
	.desc = "Nintendo 64 Big-Endian binary",
	.license = "LGPL3",
	.author = "lowlyw",
	.load_buffer = &n64_load_buffer,
	.check_buffer = &n64_check_buffer,
	.destroy = &n64_destroy,
	.bin_structure = &n64_structure,
	.baddr = n64_baddr,
	.boffset = &n64_boffset,
	.entries = &n64_entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &n64_sections,
	.info = &n64_info
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_z64,
	.version = RZ_VERSION
};
#endif