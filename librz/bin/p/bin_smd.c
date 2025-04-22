// SPDX-FileCopyrightText: 2015-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>

typedef struct gen_hdr {
	ut8 CopyRights[32];
	ut8 DomesticName[48];
	ut8 OverseasName[48];
	ut8 ProductCode[14];
	ut16 CheckSum;
	ut8 Peripherials[16];
	ut32 RomStart;
	ut32 RomEnd;
	ut32 RamStart;
	ut32 RamEnd;
	ut8 SramCode[12];
	ut8 ModemCode[12];
	ut8 Reserved[40];
	ut8 CountryCode[16];
} SMD_Header;

typedef struct gen_vect {
	union {
		struct {
			ut32 SSP;
			ut32 Reset;
			ut32 BusErr;
			ut32 AdrErr;
			ut32 InvOpCode;
			ut32 DivBy0;
			ut32 Check;
			ut32 TrapV;
			ut32 GPF;
			ut32 Trace;
			ut32 Reserv0;
			ut32 Reserv1;
			ut32 Reserv2;
			ut32 Reserv3;
			ut32 Reserv4;
			ut32 BadInt;
			ut32 Reserv10;
			ut32 Reserv11;
			ut32 Reserv12;
			ut32 Reserv13;
			ut32 Reserv14;
			ut32 Reserv15;
			ut32 Reserv16;
			ut32 Reserv17;
			ut32 BadIRQ;
			ut32 IRQ1;
			ut32 EXT;
			ut32 IRQ3;
			ut32 HBLANK;
			ut32 IRQ5;
			ut32 VBLANK;
			ut32 IRQ7;
			ut32 Trap0;
			ut32 Trap1;
			ut32 Trap2;
			ut32 Trap3;
			ut32 Trap4;
			ut32 Trap5;
			ut32 Trap6;
			ut32 Trap7;
			ut32 Trap8;
			ut32 Trap9;
			ut32 Trap10;
			ut32 Trap11;
			ut32 Trap12;
			ut32 Trap13;
			ut32 Trap14;
			ut32 Trap15;
			ut32 Reserv30;
			ut32 Reserv31;
			ut32 Reserv32;
			ut32 Reserv33;
			ut32 Reserv34;
			ut32 Reserv35;
			ut32 Reserv36;
			ut32 Reserv37;
			ut32 Reserv38;
			ut32 Reserv39;
			ut32 Reserv3A;
			ut32 Reserv3B;
			ut32 Reserv3C;
			ut32 Reserv3D;
			ut32 Reserv3E;
			ut32 Reserv3F;
		};
		ut32 vectors[64];
	};
} SMD_Vectors;

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

static bool check_buffer(RzBuffer *b) {
	if (rz_buf_size(b) > 0x190) {
		ut8 buf[4];
		rz_buf_read_at(b, 0x100, buf, sizeof(buf));
		return !memcmp(buf, "SEGA", 4);
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	return check_buffer(b);
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("ROM");
	ret->machine = rz_str_dup("Sega Megadrive");
	ut8 tmp[32];
	rz_buf_read_at(bf->buf, 0x100, tmp, sizeof(tmp));
	ret->bclass = rz_str_ndup((char *)tmp, 32);
	ret->os = rz_str_dup("smd");
	ret->arch = rz_str_dup("m68k");
	ret->bits = 16;
	ret->has_va = 1;
	ret->big_endian = 1;
	return ret;
}

static void addsym(RzPVector /*<RzBinSymbol *>*/ *ret, const char *name, ut64 addr) {
	RzBinSymbol *ptr = RZ_NEW0(RzBinSymbol);
	if (!ptr) {
		return;
	}
	ptr->name = rz_str_dup(name ? name : "");
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = 0;
	ptr->ordinal = 0;
	rz_pvector_push(ret, ptr);
}

static void showstr(const char *str, const ut8 *s, int len) {
	char *msg = rz_str_ndup((const char *)s, len);
	eprintf("%s: %s\n", str, msg);
	free(msg);
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	RzPVector *ret = NULL;
	const char *name = NULL;
	int i;

	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free))) {
		return NULL;
	}
	SMD_Header hdr;
	int left = rz_buf_read_at(bf->buf, 0x100, (ut8 *)&hdr, sizeof(hdr));
	if (left < sizeof(SMD_Header)) {
		return NULL;
	}
	// TODO: store all this stuff in SDB
	addsym(ret, "rom_start", rz_read_be32(&hdr.RomStart));
	addsym(ret, "rom_end", rz_read_be32(&hdr.RomEnd));
	addsym(ret, "ram_start", rz_read_be32(&hdr.RamStart));
	addsym(ret, "ram_end", rz_read_be32(&hdr.RamEnd));
	showstr("Copyright", hdr.CopyRights, 32);
	showstr("DomesticName", hdr.DomesticName, 48);
	showstr("OverseasName", hdr.OverseasName, 48);
	showstr("ProductCode", hdr.ProductCode, 14);
	eprintf("Checksum: 0x%04x\n", (ut32)hdr.CheckSum);
	showstr("Peripherials", hdr.Peripherials, 16);
	showstr("SramCode", hdr.SramCode, 12);
	showstr("ModemCode", hdr.ModemCode, 12);
	showstr("CountryCode", hdr.CountryCode, 16);
	ut32 vtable[64];
	rz_buf_read_at(bf->buf, 0, (ut8 *)&vtable, sizeof(ut32) * 64);
	/* parse vtable */
	for (i = 0; i < 64; i++) {
		switch (i) {
		case 0: name = "SSP"; break;
		case 1: name = "Reset"; break;
		case 2: name = "BusErr"; break;
		case 3: name = "AdrErr"; break;
		case 4: name = "InvOpCode"; break;
		case 5: name = "DivBy0"; break;
		case 6: name = "Check"; break;
		case 7: name = "TrapV"; break;
		case 8: name = "GPF"; break;
		case 9: name = "Trace"; break;
		case 10: name = "Reserv0"; break;
		case 11: name = "Reserv1"; break;
		case 12: name = "Reserv2"; break;
		case 13: name = "Reserv3"; break;
		case 14: name = "Reserv4"; break;
		case 15: name = "BadInt"; break;
		case 16: name = "Reserv10"; break;
		case 17: name = "Reserv11"; break;
		case 18: name = "Reserv12"; break;
		case 19: name = "Reserv13"; break;
		case 20: name = "Reserv14"; break;
		case 21: name = "Reserv15"; break;
		case 22: name = "Reserv16"; break;
		case 23: name = "Reserv17"; break;
		case 24: name = "BadIRQ"; break;
		case 25: name = "IRQ1"; break;
		case 26: name = "EXT"; break;
		case 27: name = "IRQ3"; break;
		case 28: name = "HBLANK"; break;
		case 29: name = "IRQ5"; break;
		case 30: name = "VBLANK"; break;
		case 31: name = "IRQ7"; break;
		case 32: name = "Trap0"; break;
		case 33: name = "Trap1"; break;
		case 34: name = "Trap2"; break;
		case 35: name = "Trap3"; break;
		case 36: name = "Trap4"; break;
		case 37: name = "Trap5"; break;
		case 38: name = "Trap6"; break;
		case 39: name = "Trap7"; break;
		case 40: name = "Trap8"; break;
		case 41: name = "Trap9"; break;
		case 42: name = "Trap10"; break;
		case 43: name = "Trap11"; break;
		case 44: name = "Trap12"; break;
		case 45: name = "Trap13"; break;
		case 46: name = "Trap14"; break;
		case 47: name = "Trap15"; break;
		case 48: name = "Reserv30"; break;
		case 49: name = "Reserv31"; break;
		case 50: name = "Reserv32"; break;
		case 51: name = "Reserv33"; break;
		case 52: name = "Reserv34"; break;
		case 53: name = "Reserv35"; break;
		case 54: name = "Reserv36"; break;
		case 55: name = "Reserv37"; break;
		case 56: name = "Reserv38"; break;
		case 57: name = "Reserv39"; break;
		case 58: name = "Reserv3A"; break;
		case 59: name = "Reserv3B"; break;
		case 60: name = "Reserv3C"; break;
		case 61: name = "Reserv3D"; break;
		case 62: name = "Reserv3E"; break;
		case 63: name = "Reserv3F"; break;
		default: name = NULL;
		}
		if (name && vtable[i]) {
			ut32 addr = rz_read_be32(&vtable[i]);
			addsym(ret, name, addr);
		}
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret = NULL;
	if (!(ret = rz_pvector_new(NULL))) {
		return NULL;
	}
	RzBinSection *ptr;
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup("vtable");
	ptr->paddr = ptr->vaddr = 0;
	ptr->size = ptr->vsize = 0x100;
	ptr->perm = RZ_PERM_R;
	rz_pvector_push(ret, ptr);

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup("header");
	ptr->paddr = ptr->vaddr = 0x100;
	ptr->size = ptr->vsize = sizeof(SMD_Header);
	ptr->perm = RZ_PERM_R;
	rz_pvector_push(ret, ptr);

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup("text");
	ptr->paddr = ptr->vaddr = 0x100 + sizeof(SMD_Header);
	{
		SMD_Header hdr = { { 0 } };
		rz_buf_read_at(bf->buf, 0x100, (ut8 *)&hdr, sizeof(hdr));
		ut64 baddr = rz_read_be32(&hdr.RomStart);
		ptr->vaddr += baddr;
	}
	ptr->size = ptr->vsize = rz_buf_size(bf->buf) - ptr->paddr;
	ptr->perm = RZ_PERM_RX;
	rz_pvector_push(ret, ptr);
	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) { // Should be 3 offsets pointed by NMI, RESET, IRQ after mapping && default = 1st CHR
	RzPVector *ret;
	RzBinAddr *ptr = NULL;
	if (!(ret = rz_pvector_new(NULL))) {
		return NULL;
	}
	if (!(ptr = RZ_NEW0(RzBinAddr))) {
		return ret;
	}
	if (bf->size < sizeof(SMD_Vectors)) {
		eprintf("ERR: binfile too small!\n");
		ptr->paddr = ptr->vaddr = 0x100 + sizeof(SMD_Header);
		rz_pvector_push(ret, ptr);
	} else {
		SMD_Vectors vectors;
		rz_buf_read_at(bf->buf, 0, (ut8 *)&vectors, sizeof(vectors));
		ptr->paddr = ptr->vaddr = rz_read_be32(&vectors.Reset);
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	RzBinStringSearchOpt opt;
	rz_bin_string_search_opt_init(&opt);
	// we only search strings with a minimum length of 10 bytes.
	opt.mode = RZ_BIN_STRING_SEARCH_MODE_READ_ONLY_SECTIONS;
	opt.min_length = 10;
	return rz_bin_file_strings(bf, &opt);
}

RzBinPlugin rz_bin_plugin_smd = {
	.name = "smd",
	.desc = "SEGA Genesis/Megadrive",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = &entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.symbols = &symbols,
	.strings = &strings,
	.info = &info,
	.strfilter = 'U'
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_smd,
	.version = RZ_VERSION
};
#endif
