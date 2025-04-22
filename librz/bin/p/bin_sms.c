// SPDX-FileCopyrightText: 2015-2018 shengdi <github@sheng.my>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>

typedef struct gen_hdr {
	ut8 HeaderID[8];
	ut8 ReservedWord[2];
	ut16 CheckSum;
	ut8 ProductCode[2];
	ut8 Version; // Low 4 bits version, Top 4 bits ProductCode
	ut8 RegionRomSize; // Low 4 bits RomSize, Top 4 bits Region
} SMS_Header;

static ut32 cb = 0;

static bool check_buffer(RzBuffer *b) {
	ut32 *off, offs[] = { 0x2000, 0x4000, 0x8000, 0x9000, 0 };
	ut8 signature[8];
	for (off = (ut32 *)&offs; *off; off++) {
		rz_buf_read_at(b, *off - 16, (ut8 *)&signature, 8);
		if (!strncmp((const char *)signature, "TMR SEGA", 8)) {
			cb = *off - 16;
			return true; // int)(*off - 16);
		}
		if (*off == 0x8000) {
			if (!strncmp((const char *)signature, "SDSC", 4)) {
				cb = *off - 16;
				return true; // (int)(*off - 16);
			}
		}
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	return check_buffer(buf);
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret || !bf || !bf->buf) {
		free(ret);
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("ROM");
	ret->machine = rz_str_dup("SEGA MasterSystem");
	ret->os = rz_str_dup("sms");
	ret->arch = rz_str_dup("z80");
	ret->has_va = 1;
	ret->bits = 8;
	if (!check_buffer(bf->buf)) {
		eprintf("Cannot find magic SEGA copyright\n");
		free(ret);
		return NULL;
	}
	SMS_Header hdr = { { 0 } };
	rz_buf_read_at(bf->buf, cb, (ut8 *)&hdr, sizeof(hdr));
	hdr.CheckSum = rz_read_le16(&hdr.CheckSum);

	eprintf("Checksum: 0x%04x\n", (ut32)hdr.CheckSum); // use endian safe apis here
	eprintf("ProductCode: %02d%02X%02X\n", (hdr.Version >> 4), hdr.ProductCode[1],
		hdr.ProductCode[0]);
	switch (hdr.RegionRomSize >> 4) {
	case 3:
		eprintf("Console: Sega Master System\n");
		eprintf("Region: Japan\n");
		break;
	case 4:
		eprintf("Console: Sega Master System\n");
		eprintf("Region: Export\n");
		break;
	case 5:
		eprintf("Console: Game Gear\n");
		eprintf("Region: Japan\n");
		break;
	case 6:
		eprintf("Console: Game Gear\n");
		eprintf("Region: Export\n");
		break;
	case 7:
		eprintf("Console: Game Gear\n");
		eprintf("Region: International\n");
		break;
	}
	int romsize = 0;
	switch (hdr.RegionRomSize & 0xf) {
	case 0xa: romsize = 8; break;
	case 0xb: romsize = 16; break;
	case 0xc: romsize = 32; break;
	case 0xd: romsize = 48; break;
	case 0xe: romsize = 64; break;
	case 0xf: romsize = 128; break;
	case 0x0: romsize = 256; break;
	case 0x1: romsize = 512; break;
	case 0x2: romsize = 1024; break;
	}
	eprintf("RomSize: %dKB\n", romsize);
	return ret;
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	RzBinStringSearchOpt opt;
	rz_bin_string_search_opt_init(&opt);
	// we only search strings with a minimum length of 10 bytes.
	opt.min_length = 10;
	return rz_bin_file_strings(bf, &opt);
}

RzBinPlugin rz_bin_plugin_sms = {
	.name = "sms",
	.desc = "SEGA MasterSystem/GameGear",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.info = &info,
	.strings = &strings,
	.strfilter = 'U'
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_sms,
	.version = RZ_VERSION
};
#endif
