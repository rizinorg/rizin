// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2015-2018 shengdi <github@sheng.my>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>

/** \file bin_sms.c
 *  This plugin is used to parse the Sega Master System & Game Gear
 *  roms. the binary format is as follows:
 *
 *  The rom contains "TMR SEGA" string which defines where the ROM header
 *  is located, for example:
 *
 *  - offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
 *  0x00007ff0  544d 5220 5345 4741 4b57 33ba 5550 024f  TMR SEGAKW3.UP.O
 *
 *  offset | size | description
 *  0x7ff0 | 8    | TMR SEGA header
 *  0x7ff8 | 2    | Reserved
 *  0x7ffa | 2    | Checksum (little endian)
 *  0x7ffc | 3    | Product code + Version
 *  0x7fff | 1    | Region Code + ROM size in KB
 *
 *  Some examples:
 *
 *       Example A                      Example B
 *  - offset -   0 1  2            - offset -   0 1  2
 *  0x00007ffc  2670 a5            0x00007ffc  2670 21
 *
 *  In example A, the product code becomes 107026 and the version is 5.
 *  In example B, the product code becomes 27026 and the version is 1.
 *
 *  Regarding the region code + ROM size, the upper 4 bits are the region code
 *  meanwhile the lower 4 bits are the rom size.
 *
 *  In the homebrew scene, the SDSC header has been added 16 bytes before the
 *  "TMR SEGA" header as a standard way to tag software.
 *
 *  offset | size | description
 *  0x7fe0 | 4    | SDSC header
 *  0x7fe4 | 2    | Version BCD (major.minor)
 *  0x7fe6 | 4    | Date BCD (day.month.year)
 *  0x7fea | 2    | Author 16-bit offset
 *  0x7fec | 2    | Name 16-bit offset
 *  0x7fee | 2    | Description 16-bit offset
 *
 *   Reference:
 *   - Rom (TMR SEGA) header https://www.smspower.org/Development/ROMHeader
 *   - Homebrew (SDSC) header https://www.smspower.org/Development/SDSCHeader
 */

#define SMS_MAGIC_TMR_SEGA "TMR SEGA"
#define SMS_MAGIC_SDSC     "SDSC"

#define SMS_MAGIC_SIZE_TMR_SEGA (sizeof(SMS_MAGIC_TMR_SEGA) - 1)
#define SMS_MAGIC_SIZE_SDSC     (sizeof(SMS_MAGIC_SDSC) - 1)

#define SMS_ROM_SIZE_8KB    0xa
#define SMS_ROM_SIZE_16KB   0xb
#define SMS_ROM_SIZE_32KB   0xc
#define SMS_ROM_SIZE_48KB   0xd
#define SMS_ROM_SIZE_64KB   0xe
#define SMS_ROM_SIZE_128KB  0xf
#define SMS_ROM_SIZE_256KB  0x0
#define SMS_ROM_SIZE_512KB  0x1
#define SMS_ROM_SIZE_1024KB 0x2

typedef struct sms_system {
	ut32 id;
	const char *system;
	const char *region;
} SMSSys;

typedef struct sms_rom {
	ut64 offset;
	ut8 reserved[2];
	ut32 checksum;
	ut32 product_code;
	ut8 version;
	const char *system;
	const char *region;
	ut32 size_kb;
} SMSRom;

typedef struct sms_date {
	ut8 day;
	ut8 month;
	ut16 year;
} SMSDate;

typedef struct sms_version {
	ut8 major;
	ut8 minor;
} SMSVersion;

typedef struct sms_sdsc {
	ut64 offset;
	SMSVersion version;
	SMSDate date;
	char *author;
	char *name;
	char *description;
} SMSSdsc;

typedef struct sms_info {
	SMSRom rom;
	SMSSdsc sdsc;
} SMSInfo;

static const ut16 sms_offsets[] = {
	0x1ff0, 0x3ff0, 0x7ff0
};

// clang-format off
static const SMSSys sms_systems[] = {
	{ 3, "Sega Master System", "Japan" },
	{ 4, "Sega Master System", "Export" },
	{ 5, "Game Gear",          "Japan" },
	{ 6, "Game Gear",          "Export" },
	{ 7, "Game Gear",          "International" },
};
// clang-format on

static ut64 sms_find_tmr_sega_magic(RzBuffer *b) {
	ut8 magic[8];
	for (size_t i = 0; i < RZ_ARRAY_SIZE(sms_offsets); i++) {
		if (rz_buf_read_at(b, sms_offsets[i], magic, sizeof(magic)) != sizeof(magic)) {
			return UT64_MAX;
		} else if (strncmp((const char *)magic, SMS_MAGIC_TMR_SEGA, SMS_MAGIC_SIZE_TMR_SEGA)) {
			continue;
		}
		return sms_offsets[i];
	}
	return UT64_MAX;
}

static bool sms_check_buffer(RzBuffer *b) {
	return sms_find_tmr_sega_magic(b) != UT64_MAX;
}

static ut8 byte_to_bcd(ut8 value) {
	ut8 bcd_hi = value >> 4;
	ut8 bcd_lo = value & 0x0f;

	return (bcd_hi * 10) + bcd_lo;
}

static ut32 sms_parse_product_code_bcd(ut8 *data) {
	// reverse byte order
	ut32 value = byte_to_bcd(data[2] >> 4); // only upper 4 bits
	value *= 100;
	value += byte_to_bcd(data[1]);
	value *= 100;
	value += byte_to_bcd(data[0]);
	return value;
}

static void sms_parse_version_bcd(ut8 *data, SMSVersion *version) {
	version->major = byte_to_bcd(data[0]);
	version->minor = byte_to_bcd(data[1]);
}

static void sms_parse_date_bcd(ut8 *data, SMSDate *date) {
	date->day = byte_to_bcd(data[0]);
	date->month = byte_to_bcd(data[1]);
	date->year = byte_to_bcd(data[3]);
	date->year *= 100;
	date->year += byte_to_bcd(data[2]);
}

static void sms_parse_region_code(ut8 region_code, SMSRom *rom) {
	for (size_t i = 0; i < RZ_ARRAY_SIZE(sms_systems); i++) {
		if (sms_systems[i].id == region_code) {
			rom->system = sms_systems[i].system;
			rom->region = sms_systems[i].region;
			return;
		}
	}
	rom->system = NULL;
	rom->region = "Unknown";
}

static ut32 sms_parse_rom_size(ut8 rom_size) {
	switch (rom_size) {
	case SMS_ROM_SIZE_8KB: return 8;
	case SMS_ROM_SIZE_16KB: return 16;
	case SMS_ROM_SIZE_32KB: return 32;
	case SMS_ROM_SIZE_48KB: return 48;
	case SMS_ROM_SIZE_64KB: return 64;
	case SMS_ROM_SIZE_128KB: return 128;
	case SMS_ROM_SIZE_256KB: return 256;
	case SMS_ROM_SIZE_512KB: return 512;
	case SMS_ROM_SIZE_1024KB: return 1024;
	default: return 0;
	}
}

static bool sms_parse_rom(RzBuffer *b, SMSRom *rom, ut64 offset) {
	ut8 data[16];

	if (rz_buf_read_at(b, offset, data, sizeof(data)) != sizeof(data)) {
		return false;
	}

	rom->offset = offset;
	rom->reserved[0] = data[8];
	rom->reserved[1] = data[9];
	rom->checksum = rz_read_at_le16(data, 10);
	rom->product_code = sms_parse_product_code_bcd(data + 12);
	rom->version = data[14] & 0x0f; // only lower 4 bits
	sms_parse_region_code(data[15] >> 4, rom); // only upper 4 bits
	rom->size_kb = sms_parse_rom_size(data[15] & 0x0f); // only lower 4 bits
	return true;
}

static char *sms_parse_sdsc_string(RzBuffer *b, ut64 offset) {
	if (!offset || offset == 0xffff) {
		return NULL;
	}

	ut8 data[256];
	if (rz_buf_read_at(b, offset, data, sizeof(data)) < 1) {
		return NULL;
	}

	// ensure the terminator always at the end of the buffer.
	data[sizeof(data) - 1] = 0;
	return rz_str_ndup((const char *)data, sizeof(data));
}

static bool sms_parse_sdsc(RzBuffer *b, SMSSdsc *sdsc, ut64 offset) {
	ut8 data[16];
	ut16 off_author = 0;
	ut16 off_name = 0;
	ut16 off_descr = 0;

	if (rz_buf_read_at(b, offset, data, sizeof(data)) != sizeof(data)) {
		return false;
	} else if (strncmp((const char *)data, SMS_MAGIC_SDSC, SMS_MAGIC_SIZE_SDSC)) {
		// if the magic does not exist we still return true
		// since this is only present for homebrews.
		return true;
	}

	sdsc->offset = offset;
	sms_parse_version_bcd(data + 4, &sdsc->version);
	sms_parse_date_bcd(data + 6, &sdsc->date);
	off_author = rz_read_at_le16(data, 10);
	off_name = rz_read_at_le16(data, 12);
	off_descr = rz_read_at_le16(data, 14);

	sdsc->author = sms_parse_sdsc_string(b, off_author);
	sdsc->name = sms_parse_sdsc_string(b, off_name);
	sdsc->description = sms_parse_sdsc_string(b, off_descr);

	return true;
}

static bool sms_parse_header(RzBuffer *b, SMSInfo *sms, ut64 offset) {
	sms->rom.offset = UT64_MAX;
	sms->sdsc.offset = UT64_MAX;

	return sms_parse_rom(b, &sms->rom, offset) &&
		sms_parse_sdsc(b, &sms->sdsc, offset - 16);
}

static void sms_info_free(SMSInfo *sms) {
	if (!sms) {
		return;
	}

	free(sms->sdsc.author);
	free(sms->sdsc.name);
	free(sms->sdsc.description);
	free(sms);
}

static bool sms_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	ut64 offset = sms_find_tmr_sega_magic(buf);
	if (offset == UT64_MAX) {
		return false;
	}

	SMSInfo *sms = RZ_NEW0(SMSInfo);
	if (!sms || !sms_parse_header(buf, sms, offset)) {
		sms_info_free(sms);
		return false;
	}

	obj->bin_obj = sms;
	return true;
}

static void sms_destroy(RzBinFile *bf) {
	sms_info_free(bf->o->bin_obj);
}

static RzStructuredData *sms_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	char tmp[256] = { 0 };
	SMSInfo *sms = bf->o->bin_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *rom = rz_structured_data_map_add_map(info, "sms_rom");
	if (!rom) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(rom, "offset", sms->rom.offset, true);
	rz_structured_data_map_add_unsigned(rom, "reserved0", sms->rom.reserved[0], false);
	rz_structured_data_map_add_unsigned(rom, "reserved1", sms->rom.reserved[1], false);
	rz_structured_data_map_add_unsigned(rom, "checksum", sms->rom.checksum, true);
	rz_strf(tmp, "%06u", sms->rom.product_code);
	rz_structured_data_map_add_string(rom, "product_code", tmp);
	rz_structured_data_map_add_unsigned(rom, "version", sms->rom.version, false);
	rz_structured_data_map_add_string(rom, "console", rz_str_get(sms->rom.system));
	rz_structured_data_map_add_string(rom, "region", rz_str_get(sms->rom.region));
	rz_structured_data_map_add_unsigned(rom, "size_kb", sms->rom.size_kb, false);

	if (sms->sdsc.offset == UT64_MAX) {
		return info;
	}

	RzStructuredData *sdsc = rz_structured_data_map_add_map(rom, "sdsc");
	if (!sdsc) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(sdsc, "offset", sms->sdsc.offset, true);
	rz_strf(tmp, "%02u.%02u\n", sms->sdsc.version.major, sms->sdsc.version.minor);
	rz_structured_data_map_add_string(sdsc, "version", tmp);
	rz_strf(tmp, "%04u-%02u-%02u\n", sms->sdsc.date.year, sms->sdsc.date.month, sms->sdsc.date.day);
	rz_structured_data_map_add_string(sdsc, "date", tmp);
	rz_structured_data_map_add_string(sdsc, "author", rz_str_get(sms->sdsc.author));
	rz_structured_data_map_add_string(sdsc, "name", rz_str_get(sms->sdsc.name));
	rz_structured_data_map_add_string(sdsc, "description", rz_str_get(sms->sdsc.description));

	return info;
}

static RzBinInfo *sms_info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret || !bf || !bf->buf) {
		free(ret);
		return NULL;
	}
	SMSInfo *sms = bf->o->bin_obj;

	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("ROM");
	ret->machine = rz_str_newf("SEGA %s", sms->rom.system ? sms->rom.system : "MasterSystem/GameGear");
	ret->os = rz_str_dup("sms");
	ret->arch = rz_str_dup("z80");
	ret->has_va = 1;
	ret->bits = 8;
	return ret;
}

static RzPVector /*<RzBinString *>*/ *sms_strings(RzBinFile *bf) {
	RzBinStringSearchOpt opt;
	rz_bin_string_search_opt_init(&opt);
	// we only search strings with a minimum length of 10 bytes.
	opt.min_length = 10;
	return rz_bin_file_strings(bf, &opt);
}

RzBinPlugin rz_bin_plugin_sms = {
	.name = "sms",
	.desc = "SEGA MasterSystem / GameGear ROM",
	.license = "LGPL3",
	.author = "shengdi",
	.load_buffer = &sms_load_buffer,
	.check_buffer = &sms_check_buffer,
	.destroy = &sms_destroy,
	.bin_structure = &sms_structure,
	.info = &sms_info,
	.strings = &sms_strings,
	.strfilter = 'U'
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_sms,
	.version = RZ_VERSION
};
#endif
