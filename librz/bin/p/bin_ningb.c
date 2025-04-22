// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2024 maijin <maijin21@gmail.com>
// SPDX-FileCopyrightText: 2013-2017 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>
#include "../format/nin/nin.h"

static const char *gb_get_gameboy_type(ut8 byte0, ut8 byte1) {
	if (byte0 == GB_SGB) {
		return "SuperGameboy-Rom";
	} else if (byte1 == GB_GBC) {
		return "GameboyColor-Rom";
	}
	return "Gameboy-Rom";
}

static const char *gb_add_card_type(ut8 cardcode) {
	switch (cardcode) {
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

static int gb_get_rombanks(ut8 id) {
	switch (id) {
	case GB_ROM_BANKS_2:
		return 2;
	case GB_ROM_BANKS_4:
		return 4;
	case GB_ROM_BANKS_8:
		return 8;
	case GB_ROM_BANKS_16:
		return 16;
	case GB_ROM_BANKS_32:
		return 32;
	case GB_ROM_BANKS_64:
		return 64;
	case GB_ROM_BANKS_128:
		return 128;
	case GB_ROM_BANKS_72:
		return 72;
	case GB_ROM_BANKS_80:
		return 80;
	case GB_ROM_BANKS_96:
		return 96;
	}
	return 2;
}

static bool check_buffer(RzBuffer *b) {
	ut8 lict[sizeof(lic)];
	if (rz_buf_read_at(b, 0x104, lict, sizeof(lict)) == sizeof(lict)) {
		return !memcmp(lict, lic, sizeof(lict));
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	return check_buffer(buf);
}

static ut64 baddr(RzBinFile *bf) {
	return 0LL;
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol type) {
	if (type == RZ_BIN_SPECIAL_SYMBOL_MAIN && bf && bf->buf) {
		ut8 init_jmp[4];
		RzBinAddr *ret = RZ_NEW0(RzBinAddr);
		if (!ret) {
			return NULL;
		}
		rz_buf_read_at(bf->buf, 0x100, init_jmp, 4);
		if (init_jmp[1] == 0xc3) {
			ret->paddr = ret->vaddr = init_jmp[3] * 0x100 + init_jmp[2];
			return ret;
		}
		free(ret);
	}
	return NULL;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new(free);
	RzBinAddr *ptr = NULL;

	if (bf && bf->buf != NULL) {
		if (!ret) {
			return NULL;
		}
		if (!(ptr = RZ_NEW0(RzBinAddr))) {
			return ret;
		}
		ptr->paddr = ptr->vaddr = ptr->hpaddr = 0x100;
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	if (!bf || !bf->buf) {
		return NULL;
	}
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}
	ut8 bank_id;
	rz_buf_read_at(bf->buf, 0x148, &bank_id, 1);
	int banks_count = gb_get_rombanks(bank_id);
	for (size_t i = 0; i < banks_count; i++) {
		RzBinSection *section = RZ_NEW0(RzBinSection);
		section->name = rz_str_newf("rombank%02x", (unsigned int)i);
		section->paddr = i * 0x4000;
		section->vaddr = i ? (i * 0x10000 - 0xc000) : 0;
		section->size = section->vsize = 0x4000;
		section->perm = rz_str_rwx("rx");
		rz_pvector_push(ret, section);
	}
	return ret;
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	RzPVector *ret = NULL;
	RzBinSymbol *ptr[13];
	int i;
	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free))) {
		return NULL;
	}

	for (i = 0; i < 8; i++) {
		if (!(ptr[i] = RZ_NEW0(RzBinSymbol))) {
			rz_pvector_free(ret);
			return NULL;
		}
		ptr[i]->name = rz_str_newf("rst_%i", i * 8);
		ptr[i]->paddr = ptr[i]->vaddr = i * 8;
		ptr[i]->size = 1;
		ptr[i]->ordinal = i;
		rz_pvector_push(ret, ptr[i]);
	}

	if (!(ptr[8] = RZ_NEW0(RzBinSymbol))) {
		return ret;
	}

	ptr[8]->name = rz_str_dup("Interrupt_Vblank");
	ptr[8]->paddr = ptr[8]->vaddr = 64;
	ptr[8]->size = 1;
	ptr[8]->ordinal = 8;
	rz_pvector_push(ret, ptr[8]);

	if (!(ptr[9] = RZ_NEW0(RzBinSymbol))) {
		return ret;
	}

	ptr[9]->name = rz_str_dup("Interrupt_LCDC-Status");
	ptr[9]->paddr = ptr[9]->vaddr = 72;
	ptr[9]->size = 1;
	ptr[9]->ordinal = 9;
	rz_pvector_push(ret, ptr[9]);

	if (!(ptr[10] = RZ_NEW0(RzBinSymbol))) {
		return ret;
	}

	ptr[10]->name = rz_str_dup("Interrupt_Timer-Overflow");
	ptr[10]->paddr = ptr[10]->vaddr = 80;
	ptr[10]->size = 1;
	ptr[10]->ordinal = 10;
	rz_pvector_push(ret, ptr[10]);

	if (!(ptr[11] = RZ_NEW0(RzBinSymbol))) {
		return ret;
	}

	ptr[11]->name = rz_str_dup("Interrupt_Serial-Transfere");
	ptr[11]->paddr = ptr[11]->vaddr = 88;
	ptr[11]->size = 1;
	ptr[11]->ordinal = 11;
	rz_pvector_push(ret, ptr[11]);

	if (!(ptr[12] = RZ_NEW0(RzBinSymbol))) {
		return ret;
	}

	ptr[12]->name = rz_str_dup("Interrupt_Joypad");
	ptr[12]->paddr = ptr[12]->vaddr = 96;
	ptr[12]->size = 1;
	ptr[12]->ordinal = 12;
	rz_pvector_push(ret, ptr[12]);

	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	ut8 rom_header[76];
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret || !bf || !bf->buf) {
		free(ret);
		return NULL;
	}
	rz_buf_read_at(bf->buf, 0x104, rom_header, 76);

	const char *gbtype = gb_get_gameboy_type(rom_header[66], rom_header[63]);
	const char *cardtype = gb_add_card_type(rom_header[67]);

	if (cardtype) {
		ret->type = rz_str_newf("%s %s", gbtype, cardtype);
	} else {
		ret->type = rz_str_newf("%s card_%02x", gbtype, (ut32)rom_header[67]);
	}
	ret->file = rz_str_ndup((const char *)&rom_header[48], 16);
	ret->machine = rz_str_dup("Gameboy");
	ret->os = rz_str_dup("any");
	ret->arch = rz_str_dup("gb");
	ret->has_va = true;
	ret->bits = 16;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

RzPVector /*<RzBinMem *>*/ *mem(RzBinFile *bf) {
	RzPVector *ret;
	RzBinMem *m, *n;
	if (!(ret = rz_pvector_new(rz_bin_mem_free))) {
		return NULL;
	}
	if (!(m = RZ_NEW0(RzBinMem))) {
		rz_pvector_free(ret);
		return NULL;
	}
	m->name = rz_str_dup("fastram");
	m->addr = 0xff80LL;
	m->size = 0x80;
	m->perms = rz_str_rwx("rwx");
	rz_pvector_push(ret, m);

	if (!(m = RZ_NEW0(RzBinMem))) {
		return ret;
	}
	m->name = rz_str_dup("ioports");
	m->addr = 0xff00LL;
	m->size = 0x4c;
	m->perms = rz_str_rwx("rwx");
	rz_pvector_push(ret, m);

	if (!(m = RZ_NEW0(RzBinMem))) {
		return ret;
	}
	m->name = rz_str_dup("oam");
	m->addr = 0xfe00LL;
	m->size = 0xa0;
	m->perms = rz_str_rwx("rwx");
	rz_pvector_push(ret, m);

	if (!(m = RZ_NEW0(RzBinMem))) {
		return ret;
	}
	m->name = rz_str_dup("videoram");
	m->addr = 0x8000LL;
	m->size = 0x2000;
	m->perms = rz_str_rwx("rwx");
	rz_pvector_push(ret, m);

	if (!(m = RZ_NEW0(RzBinMem))) {
		return ret;
	}
	m->name = rz_str_dup("iram");
	m->addr = 0xc000LL;
	m->size = 0x2000;
	m->perms = rz_str_rwx("rwx");
	rz_pvector_push(ret, m);
	if (!(m->mirrors = rz_pvector_new(rz_bin_mem_free))) {
		return ret;
	}
	if (!(n = RZ_NEW0(RzBinMem))) {
		rz_pvector_free(m->mirrors);
		m->mirrors = NULL;
		return ret;
	}
	n->name = rz_str_dup("iram_echo");
	n->addr = 0xe000LL;
	n->size = 0x1e00;
	n->perms = rz_str_rwx("rx");
	rz_pvector_push(m->mirrors, n);

	return ret;
}

RzBinPlugin rz_bin_plugin_ningb = {
	.name = "ningb",
	.desc = "Nintendo Gameboy plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.mem = &mem,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_ningb,
	.version = RZ_VERSION
};
#endif
