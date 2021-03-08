// SPDX-FileCopyrightText: 2017-2019 usrshare
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_lib.h>
#include "sfc/sfc_specs.h"
#include <rz_endian.h>

static bool check_buffer(RzBuffer *b) {
	ut16 cksum1, cksum2;
	ut64 length = rz_buf_size(b);
	// FIXME: this was commented out because it always evaluates to false.
	//        Need to be fixed by someone with SFC knowledge
	// if ((length & 0x8000) == 0x200) {
	// 	buf_hdr += 0x200;
	// }
	if (length < 0x8000) {
		return false;
	}
	//determine if ROM is headered, and add a 0x200 gap if so.
	cksum1 = rz_buf_read_le16_at(b, 0x7fdc);
	cksum2 = rz_buf_read_le16_at(b, 0x7fde);

	if (cksum1 == (ut16)~cksum2) {
		return true;
	}
	if (length < 0xffee) {
		return false;
	}
	cksum1 = rz_buf_read_le16_at(b, 0xffdc);
	cksum2 = rz_buf_read_le16_at(b, 0xffde);
	return (cksum1 == (ut16)~cksum2);
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *b, ut64 loadaddr, Sdb *sdb) {
	return check_buffer(b);
}

static RzBinInfo *info(RzBinFile *bf) {
	sfc_int_hdr sfchdr = { { 0 } };
	RzBinInfo *ret = NULL;
	int hdroffset = 0;
#if THIS_IS_ALWAYS_FALSE_WTF
	if ((bf->size & 0x8000) == 0x200) {
		hdroffset = 0x200;
	}
#endif
	int reat = rz_buf_read_at(bf->buf, 0x7FC0 + hdroffset,
		(ut8 *)&sfchdr, SFC_HDR_SIZE);
	if (reat != SFC_HDR_SIZE) {
		eprintf("Unable to read SFC/SNES header\n");
		return NULL;
	}

	if ((sfchdr.comp_check != (ut16) ~(sfchdr.checksum)) || ((sfchdr.rom_setup & 0x1) != 0)) {

		// if the fixed 0x33 byte or the LoROM indication are not found, then let's try interpreting the ROM as HiROM

		reat = rz_buf_read_at(bf->buf, 0xFFC0 + hdroffset, (ut8 *)&sfchdr, SFC_HDR_SIZE);
		if (reat != SFC_HDR_SIZE) {
			eprintf("Unable to read SFC/SNES header\n");
			return NULL;
		}

		if ((sfchdr.comp_check != (ut16) ~(sfchdr.checksum)) || ((sfchdr.rom_setup & 0x1) != 1)) {

			eprintf("Cannot determine if this is a LoROM or HiROM file\n");
			return NULL;
		}
	}

	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = strdup(bf->file);
	ret->type = strdup("ROM");
	ret->machine = strdup("Super NES / Super Famicom");
	ret->os = strdup("snes");
	ret->arch = strdup("snes");
	ret->bits = 16;
	ret->has_va = 1;
	return ret;
}

static void addrom(RzList *ret, const char *name, int i, ut64 paddr, ut64 vaddr, ut32 size) {
	RzBinSection *ptr = RZ_NEW0(RzBinSection);
	if (!ptr) {
		return;
	}
	ptr->name = rz_str_newf("%s_%02x", name, i);
	ptr->paddr = paddr;
	ptr->vaddr = vaddr;
	ptr->size = ptr->vsize = size;
	ptr->perm = RZ_PERM_RX;
	ptr->add = true;
	rz_list_append(ret, ptr);
}

#if 0
static void addsym(RzList *ret, const char *name, ut64 addr, ut32 size) {
	RzBinSymbol *ptr = RZ_NEW0 (RzBinSymbol);
	if (!ptr) {
		return;
	}
	ptr->name = strdup (name? name: "");
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = size;
	ptr->ordinal = 0;
	rz_list_append (ret, ptr);
}
#endif

static RzList *symbols(RzBinFile *bf) {
	return NULL;
}

static RzList *sections(RzBinFile *bf) {
	RzList *ret = NULL;
	// RzBinSection *ptr = NULL;
	int hdroffset = 0;
	bool is_hirom = false;
	int i = 0; //0x8000-long bank number for loops
#if THIS_IS_ALWAYS_FALSE_WTF
	if ((bf->size & 0x8000) == 0x200) {
		hdroffset = 0x200;
	}
#endif
	sfc_int_hdr sfchdr = { { 0 } };

	int reat = rz_buf_read_at(bf->buf, 0x7FC0 + hdroffset, (ut8 *)&sfchdr, SFC_HDR_SIZE);
	if (reat != SFC_HDR_SIZE) {
		eprintf("Unable to read SFC/SNES header\n");
		return NULL;
	}

	if ((sfchdr.comp_check != (ut16) ~(sfchdr.checksum)) || ((sfchdr.rom_setup & 0x1) != 0)) {

		// if the fixed 0x33 byte or the LoROM indication are not found, then let's try interpreting the ROM as HiROM

		reat = rz_buf_read_at(bf->buf, 0xFFC0 + hdroffset, (ut8 *)&sfchdr, SFC_HDR_SIZE);
		if (reat != SFC_HDR_SIZE) {
			eprintf("Unable to read SFC/SNES header\n");
			return NULL;
		}

		if ((sfchdr.comp_check != (ut16) ~(sfchdr.checksum)) || ((sfchdr.rom_setup & 0x1) != 1)) {

			eprintf("Cannot determine if this is a LoROM or HiROM file\n");
			return NULL;
		}
		is_hirom = true;
	}

	if (!(ret = rz_list_new())) {
		return NULL;
	}

	if (is_hirom) {
		for (i = 0; i < ((bf->size - hdroffset) / 0x8000); i++) {
			// XXX check integer overflow here
			addrom(ret, "ROM", i, hdroffset + i * 0x8000, 0x400000 + (i * 0x8000), 0x8000);
			if (i % 2) {
				addrom(ret, "ROM_MIRROR", i, hdroffset + i * 0x8000, (i * 0x8000), 0x8000);
			}
		}

	} else {
		for (i = 0; i < ((bf->size - hdroffset) / 0x8000); i++) {

			addrom(ret, "ROM", i, hdroffset + i * 0x8000, 0x8000 + (i * 0x10000), 0x8000);
		}
	}
	return ret;
}

static RzList *mem(RzBinFile *bf) {
	RzList *ret;
	RzBinMem *m;
	RzBinMem *m_bak;
	if (!(ret = rz_list_new())) {
		return NULL;
	}
	ret->free = free;
	if (!(m = RZ_NEW0(RzBinMem))) {
		rz_list_free(ret);
		return NULL;
	}
	m->name = strdup("LOWRAM");
	m->addr = LOWRAM_START_ADDRESS;
	m->size = LOWRAM_SIZE;
	m->perms = rz_str_rwx("rwx");
	rz_list_append(ret, m);

	if (!(m = RZ_NEW0(RzBinMem))) {
		return ret;
	}
	m->mirrors = rz_list_new();
	m->name = strdup("LOWRAM_MIRROR");
	m->addr = LOWRAM_MIRROR_START_ADDRESS;
	m->size = LOWRAM_MIRROR_SIZE;
	m->perms = rz_str_rwx("rwx");
	rz_list_append(m->mirrors, m);
	m_bak = m;
	if (!(m = RZ_NEW0(RzBinMem))) {
		rz_list_free(m_bak->mirrors);
		return ret;
	}
	m->name = strdup("HIRAM");
	m->addr = HIRAM_START_ADDRESS;
	m->size = HIRAM_SIZE;
	m->perms = rz_str_rwx("rwx");
	rz_list_append(ret, m);
	if (!(m = RZ_NEW0(RzBinMem))) {
		return ret;
	}
	m->name = strdup("EXTRAM");
	m->addr = EXTRAM_START_ADDRESS;
	m->size = EXTRAM_SIZE;
	m->perms = rz_str_rwx("rwx");
	rz_list_append(ret, m);
	if (!(m = RZ_NEW0(RzBinMem))) {
		return ret;
	}
	m->name = strdup("PPU1_REG");
	m->addr = PPU1_REG_ADDRESS;
	m->size = PPU1_REG_SIZE;
	m->perms = rz_str_rwx("rwx");
	rz_list_append(ret, m);
	if (!(m = RZ_NEW0(RzBinMem))) {
		rz_list_free(ret);
		return NULL;
	}
	m->name = strdup("DSP_REG");
	m->addr = DSP_REG_ADDRESS;
	m->size = DSP_REG_SIZE;
	m->perms = rz_str_rwx("rwx");
	rz_list_append(ret, m);
	if (!(m = RZ_NEW0(RzBinMem))) {
		rz_list_free(ret);
		return NULL;
	}
	m->name = strdup("OLDJOY_REG");
	m->addr = OLDJOY_REG_ADDRESS;
	m->size = OLDJOY_REG_SIZE;
	m->perms = rz_str_rwx("rwx");
	rz_list_append(ret, m);
	if (!(m = RZ_NEW0(RzBinMem))) {
		rz_list_free(ret);
		return NULL;
	}
	m->name = strdup("PPU2_REG");
	m->addr = PPU2_REG_ADDRESS;
	m->size = PPU2_REG_SIZE;
	m->perms = rz_str_rwx("rwx");
	rz_list_append(ret, m);
	return ret;
}

static RzList *entries(RzBinFile *bf) { //Should be 3 offsets pointed by NMI, RESET, IRQ after mapping && default = 1st CHR
	RzList *ret;
	if (!(ret = rz_list_new())) {
		return NULL;
	}
	/*
	RzBinAddr *ptr = NULL;
	if (!(ptr = RZ_NEW0 (RzBinAddr))) {
		return ret;
	}
	ptr->paddr = INES_HDR_SIZE;
	ptr->vaddr = ROM_START_ADDRESS;
	rz_list_append (ret, ptr);
	*/
	return ret;
}

RzBinPlugin rz_bin_plugin_sfc = {
	.name = "sfc",
	.desc = "Super NES / Super Famicom ROM file",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.sections = sections,
	.symbols = &symbols,
	.info = &info,
	.mem = &mem,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_sfc,
	.version = RZ_VERSION
};
#endif
