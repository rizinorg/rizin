// SPDX-FileCopyrightText: 2013-2017 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <string.h>
#include "../format/nin/nin.h"

static bool check_buffer(RzBuffer *b) {
	ut8 lict[sizeof(lic)];
	if (rz_buf_read_at(b, 0x104, lict, sizeof(lict)) == sizeof(lict)) {
		return !memcmp(lict, lic, sizeof(lict));
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return check_buffer(buf);
}

static ut64 baddr(RzBinFile *bf) {
	return 0LL;
}

static RzBinAddr *binsym(RzBinFile *bf, int type) {
	if (type == RZ_BIN_SYM_MAIN && bf && bf->buf) {
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

static RzList *entries(RzBinFile *bf) {
	RzList *ret = rz_list_new();
	RzBinAddr *ptr = NULL;

	if (bf && bf->buf != NULL) {
		if (!ret) {
			return NULL;
		}
		ret->free = free;
		if (!(ptr = RZ_NEW0(RzBinAddr))) {
			return ret;
		}
		ptr->paddr = ptr->vaddr = ptr->hpaddr = 0x100;
		rz_list_append(ret, ptr);
	}
	return ret;
}

static RzList *sections(RzBinFile *bf) {
	ut8 bank;
	int i;
	RzList *ret;

	if (!bf) {
		return NULL;
	}

	ret = rz_list_new();
	if (!ret) {
		return NULL;
	}

	rz_buf_read_at(bf->buf, 0x148, &bank, 1);
	bank = gb_get_rombanks(bank);
#ifdef _MSC_VER
	RzBinSection **rombank = (RzBinSection **)malloc(sizeof(RzBinSection *) * bank);
#else
	RzBinSection *rombank[bank];
#endif

	if (!bf->buf) {
		free(ret);
#ifdef _MSC_VER
		free(rombank);
#endif
		return NULL;
	}

	ret->free = free;

	rombank[0] = RZ_NEW0(RzBinSection);
	rombank[0]->name = strdup("rombank00");
	rombank[0]->paddr = 0;
	rombank[0]->size = 0x4000;
	rombank[0]->vsize = 0x4000;
	rombank[0]->vaddr = 0;
	rombank[0]->perm = rz_str_rwx("rx");
	rombank[0]->add = true;

	rz_list_append(ret, rombank[0]);

	for (i = 1; i < bank; i++) {
		rombank[i] = RZ_NEW0(RzBinSection);
		rombank[i]->name = rz_str_newf("rombank%02x", i);
		rombank[i]->paddr = i * 0x4000;
		rombank[i]->vaddr = i * 0x10000 - 0xc000; //spaaaaaaaaaaaaaaaace!!!
		rombank[i]->size = rombank[i]->vsize = 0x4000;
		rombank[i]->perm = rz_str_rwx("rx");
		rombank[i]->add = true;
		rz_list_append(ret, rombank[i]);
	}
#ifdef _MSC_VER
	free(rombank);
#endif
	return ret;
}

static RzList *symbols(RzBinFile *bf) {
	RzList *ret = NULL;
	RzBinSymbol *ptr[13];
	int i;
	if (!(ret = rz_list_new())) {
		return NULL;
	}
	ret->free = free;

	for (i = 0; i < 8; i++) {
		if (!(ptr[i] = RZ_NEW0(RzBinSymbol))) {
			ret->free(ret);
			return NULL;
		}
		ptr[i]->name = rz_str_newf("rst_%i", i * 8);
		ptr[i]->paddr = ptr[i]->vaddr = i * 8;
		ptr[i]->size = 1;
		ptr[i]->ordinal = i;
		rz_list_append(ret, ptr[i]);
	}

	if (!(ptr[8] = RZ_NEW0(RzBinSymbol))) {
		return ret;
	}

	ptr[8]->name = strdup("Interrupt_Vblank");
	ptr[8]->paddr = ptr[8]->vaddr = 64;
	ptr[8]->size = 1;
	ptr[8]->ordinal = 8;
	rz_list_append(ret, ptr[8]);

	if (!(ptr[9] = RZ_NEW0(RzBinSymbol))) {
		return ret;
	}

	ptr[9]->name = strdup("Interrupt_LCDC-Status");
	ptr[9]->paddr = ptr[9]->vaddr = 72;
	ptr[9]->size = 1;
	ptr[9]->ordinal = 9;
	rz_list_append(ret, ptr[9]);

	if (!(ptr[10] = RZ_NEW0(RzBinSymbol))) {
		return ret;
	}

	ptr[10]->name = strdup("Interrupt_Timer-Overflow");
	ptr[10]->paddr = ptr[10]->vaddr = 80;
	ptr[10]->size = 1;
	ptr[10]->ordinal = 10;
	rz_list_append(ret, ptr[10]);

	if (!(ptr[11] = RZ_NEW0(RzBinSymbol))) {
		return ret;
	}

	ptr[11]->name = strdup("Interrupt_Serial-Transfere");
	ptr[11]->paddr = ptr[11]->vaddr = 88;
	ptr[11]->size = 1;
	ptr[11]->ordinal = 11;
	rz_list_append(ret, ptr[11]);

	if (!(ptr[12] = RZ_NEW0(RzBinSymbol))) {
		return ret;
	}

	ptr[12]->name = strdup("Interrupt_Joypad");
	ptr[12]->paddr = ptr[12]->vaddr = 96;
	ptr[12]->size = 1;
	ptr[12]->ordinal = 12;
	rz_list_append(ret, ptr[12]);

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
	ret->file = rz_str_ndup((const char *)&rom_header[48], 16);
	ret->type = malloc(128);
	ret->type[0] = 0;
	gb_get_gbtype(ret->type, rom_header[66], rom_header[63]);
	gb_add_cardtype(ret->type, rom_header[67]); // XXX
	ret->machine = strdup("Gameboy");
	ret->os = strdup("any");
	ret->arch = strdup("gb");
	ret->has_va = true;
	ret->bits = 16;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

RzList *mem(RzBinFile *bf) {
	RzList *ret;
	RzBinMem *m, *n;
	if (!(ret = rz_list_new())) {
		return NULL;
	}
	ret->free = free;
	if (!(m = RZ_NEW0(RzBinMem))) {
		rz_list_free(ret);
		return NULL;
	}
	m->name = strdup("fastram");
	m->addr = 0xff80LL;
	m->size = 0x80;
	m->perms = rz_str_rwx("rwx");
	rz_list_append(ret, m);

	if (!(m = RZ_NEW0(RzBinMem))) {
		return ret;
	}
	m->name = strdup("ioports");
	m->addr = 0xff00LL;
	m->size = 0x4c;
	m->perms = rz_str_rwx("rwx");
	rz_list_append(ret, m);

	if (!(m = RZ_NEW0(RzBinMem))) {
		return ret;
	}
	m->name = strdup("oam");
	m->addr = 0xfe00LL;
	m->size = 0xa0;
	m->perms = rz_str_rwx("rwx");
	rz_list_append(ret, m);

	if (!(m = RZ_NEW0(RzBinMem))) {
		return ret;
	}
	m->name = strdup("videoram");
	m->addr = 0x8000LL;
	m->size = 0x2000;
	m->perms = rz_str_rwx("rwx");
	rz_list_append(ret, m);

	if (!(m = RZ_NEW0(RzBinMem))) {
		return ret;
	}
	m->name = strdup("iram");
	m->addr = 0xc000LL;
	m->size = 0x2000;
	m->perms = rz_str_rwx("rwx");
	rz_list_append(ret, m);
	if (!(m->mirrors = rz_list_new())) {
		return ret;
	}
	if (!(n = RZ_NEW0(RzBinMem))) {
		rz_list_free(m->mirrors);
		m->mirrors = NULL;
		return ret;
	}
	n->name = strdup("iram_echo");
	n->addr = 0xe000LL;
	n->size = 0x1e00;
	n->perms = rz_str_rwx("rx");
	rz_list_append(m->mirrors, n);

	return ret;
}

RzBinPlugin rz_bin_plugin_ningb = {
	.name = "ningb",
	.desc = "Gameboy format rz_bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
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
