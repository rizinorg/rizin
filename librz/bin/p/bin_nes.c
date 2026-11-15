// SPDX-FileCopyrightText: 2015-2019 maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_lib.h>
#include "nes/nes_specs.h"

static bool nes_check_buffer(RzBuffer *b) {
	if (rz_buf_size(b) > 4) {
		ut8 buf[4];
		rz_buf_read_at(b, 0, buf, sizeof(buf));
		return (!memcmp(buf, INES_MAGIC, sizeof(buf)));
	}
	return false;
}

static bool nes_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	ines_hdr *hdr = RZ_NEW0(ines_hdr);
	if (!hdr) {
		return false;
	}
	if (rz_buf_read_at(buf, 0, (ut8 *)hdr, INES_HDR_SIZE) != INES_HDR_SIZE) {
		free(hdr);
		return false;
	}
	if (memcmp(hdr->id, INES_MAGIC, 4)) {
		free(hdr);
		return false;
	}
	obj->bin_obj = hdr;
	return true;
}

static void nes_destroy(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return;
	}
	free(bf->o->bin_obj);
}

static RzBinInfo *nes_info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("ROM");
	ret->machine = rz_str_dup("Nintendo NES");
	ret->os = rz_str_dup("nes");
	ret->arch = rz_str_dup("6502");
	ret->bits = 8;
	ret->has_va = 1;
	return ret;
}

static void addsym(RzPVector /*<RzBinSymbol *>*/ *ret, const char *name, ut64 addr, ut32 size) {
	RzBinSymbol *ptr = RZ_NEW0(RzBinSymbol);
	if (!ptr) {
		return;
	}
	ptr->name = rz_str_dup(name ? name : "");
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = size;
	ptr->ordinal = 0;
	rz_pvector_push(ret, ptr);
}

static RzPVector /*<RzBinSymbol *>*/ *nes_symbols(RzBinFile *bf) {
	RzPVector *ret = NULL;
	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free))) {
		return NULL;
	}
	addsym(ret, "NMI_VECTOR_START_ADDRESS", NMI_VECTOR_START_ADDRESS, 2);
	addsym(ret, "RESET_VECTOR_START_ADDRESS", RESET_VECTOR_START_ADDRESS, 2);
	addsym(ret, "IRQ_VECTOR_START_ADDRESS", IRQ_VECTOR_START_ADDRESS, 2);
	addsym(ret, "PPU_CTRL_REG1", PPU_CTRL_REG1, 0x1);
	addsym(ret, "PPU_CTRL_REG2", PPU_CTRL_REG2, 0x1);
	addsym(ret, "PPU_STATUS", PPU_STATUS, 0x1);
	addsym(ret, "PPU_SPR_ADDR", PPU_SPR_ADDR, 0x1);
	addsym(ret, "PPU_SPR_DATA", PPU_SPR_DATA, 0x1);
	addsym(ret, "PPU_SCROLL_REG", PPU_SCROLL_REG, 0x1);
	addsym(ret, "PPU_ADDRESS", PPU_ADDRESS, 0x1);
	addsym(ret, "PPU_DATA", PPU_DATA, 0x1);
	addsym(ret, "SND_REGISTER", SND_REGISTER, 0x15);
	addsym(ret, "SND_SQUARE1_REG", SND_SQUARE1_REG, 0x4);
	addsym(ret, "SND_SQUARE2_REG", SND_SQUARE2_REG, 0x4);
	addsym(ret, "SND_TRIANGLE_REG", SND_TRIANGLE_REG, 0x4);
	addsym(ret, "SND_NOISE_REG", SND_NOISE_REG, 0x2);
	addsym(ret, "SND_DELTA_REG", SND_DELTA_REG, 0x4);
	addsym(ret, "SND_MASTERCTRL_REG", SND_MASTERCTRL_REG, 0x5);
	addsym(ret, "SPR_DMA", SPR_DMA, 0x2);
	addsym(ret, "JOYPAD_PORT", JOYPAD_PORT, 0x1);
	addsym(ret, "JOYPAD_PORT1", JOYPAD_PORT1, 0x1);
	addsym(ret, "JOYPAD_PORT2", JOYPAD_PORT2, 0x1);
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *nes_sections(RzBinFile *bf) {
	const ines_hdr *hdr = bf->o->bin_obj;
	if (!hdr) {
		return NULL;
	}
	RzPVector *ret = rz_pvector_new(NULL);
	if (!ret) {
		return NULL;
	}
	RzBinSection *ptr = RZ_NEW0(RzBinSection);
	if (!ptr) {
		return ret;
	}
	ptr->name = rz_str_dup("ROM");
	ptr->paddr = INES_HDR_SIZE;
	ptr->size = hdr->prg_page_count_16k * PRG_PAGE_SIZE;
	bool mirror = ROM_START_ADDRESS + ptr->size <= ROM_MIRROR_ADDRESS;
	ptr->vaddr = ROM_START_ADDRESS;
	ptr->vsize = mirror ? ROM_MIRROR_ADDRESS - ROM_START_ADDRESS : ROM_SIZE;
	ptr->perm = RZ_PERM_RX;
	rz_pvector_push(ret, ptr);
	if (mirror) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ptr->name = rz_str_dup("ROM_MIRROR");
		ptr->paddr = INES_HDR_SIZE;
		ptr->size = hdr->prg_page_count_16k * PRG_PAGE_SIZE;
		ptr->vaddr = ROM_MIRROR_ADDRESS;
		ptr->vsize = ROM_MIRROR_SIZE;
		ptr->perm = RZ_PERM_RX;
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static RzPVector /*<RzBinMem *>*/ *nes_mem(RzBinFile *bf) {
	RzPVector *ret;
	RzBinMem *m, *n;
	if (!(ret = rz_pvector_new(rz_bin_mem_free))) {
		return NULL;
	}
	if (!(m = RZ_NEW0(RzBinMem))) {
		rz_pvector_free(ret);
		return NULL;
	}
	m->name = rz_str_dup("RAM");
	m->addr = RAM_START_ADDRESS;
	m->size = RAM_SIZE;
	m->perms = rz_str_rwx("rwx");
	rz_pvector_push(ret, m);
	if (!(n = RZ_NEW0(RzBinMem))) {
		return ret;
	}
	m->mirrors = rz_pvector_new(rz_bin_mem_free);
	n->name = rz_str_dup("RAM_MIRROR_2");
	n->addr = RAM_MIRROR_2_ADDRESS;
	n->size = RAM_MIRROR_2_SIZE;
	n->perms = rz_str_rwx("rwx");
	rz_pvector_push(m->mirrors, n);
	if (!(n = RZ_NEW0(RzBinMem))) {
		rz_pvector_free(m->mirrors);
		m->mirrors = NULL;
		return ret;
	}
	n->name = rz_str_dup("RAM_MIRROR_3");
	n->addr = RAM_MIRROR_3_ADDRESS;
	n->size = RAM_MIRROR_3_SIZE;
	n->perms = rz_str_rwx("rwx");
	rz_pvector_push(m->mirrors, n);
	if (!(m = RZ_NEW0(RzBinMem))) {
		rz_pvector_free(ret);
		return NULL;
	}
	m->name = rz_str_dup("PPU_REG");
	m->addr = PPU_REG_ADDRESS;
	m->size = PPU_REG_SIZE;
	m->perms = rz_str_rwx("rwx");
	rz_pvector_push(ret, m);
	m->mirrors = rz_pvector_new(rz_bin_mem_free);
	int i;
	for (i = 1; i < 1024; i++) {
		if (!(n = RZ_NEW0(RzBinMem))) {
			rz_pvector_free(m->mirrors);
			m->mirrors = NULL;
			return ret;
		}
		n->name = rz_str_newf("PPU_REG_MIRROR_%d", i);
		n->addr = PPU_REG_ADDRESS + i * PPU_REG_SIZE;
		n->size = PPU_REG_SIZE;
		n->perms = rz_str_rwx("rwx");
		rz_pvector_push(m->mirrors, n);
	}
	if (!(m = RZ_NEW0(RzBinMem))) {
		rz_pvector_free(ret);
		return NULL;
	}
	m->name = rz_str_dup("APU_AND_IOREGS");
	m->addr = APU_AND_IOREGS_START_ADDRESS;
	m->size = APU_AND_IOREGS_SIZE;
	m->perms = rz_str_rwx("rwx");
	rz_pvector_push(ret, m);
	if (!(m = RZ_NEW0(RzBinMem))) {
		rz_pvector_free(ret);
		return NULL;
	}
	m->name = rz_str_dup("SRAM");
	m->addr = SRAM_START_ADDRESS;
	m->size = SRAM_SIZE;
	m->perms = rz_str_rwx("rwx");
	rz_pvector_push(ret, m);
	return ret;
}

// Should be 3 offsets pointed by NMI, RESET, IRQ after mapping && default = 1st CHR
static RzPVector /*<RzBinAddr *>*/ *nes_entries(RzBinFile *bf) {
	RzPVector *ret;
	RzBinAddr *ptr = NULL;
	if (!(ret = rz_pvector_new(NULL))) {
		return NULL;
	}
	if (!(ptr = RZ_NEW0(RzBinAddr))) {
		return ret;
	}
	ptr->paddr = INES_HDR_SIZE;
	ptr->vaddr = ROM_START_ADDRESS;
	rz_pvector_push(ret, ptr);
	return ret;
}

static ut64 nes_baddr(RzBinFile *bf) {
	return 0;
}

static RzStructuredData *nes_structure(RzBinFile *bf) {
	const ines_hdr *hdr = bf->o->bin_obj;
	if (!hdr) {
		return NULL;
	}
	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}
	RzStructuredData *nes = rz_structured_data_map_add_map(info, "nes");
	if (!nes) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add_bytes(nes, "magic", (const ut8 *)hdr->id, sizeof(hdr->id), RZ_STRUCTURED_DATA_FORMAT_DEFAULT);
	rz_structured_data_map_add_unsigned(nes, "prg_pages", hdr->prg_page_count_16k, false);
	rz_structured_data_map_add_unsigned(nes, "chr_pages", hdr->chr_page_count_8k, false);
	rz_structured_data_map_add_unsigned(nes, "prg_size", (ut64)hdr->prg_page_count_16k * PRG_PAGE_SIZE, true);
	rz_structured_data_map_add_unsigned(nes, "chr_size", (ut64)hdr->chr_page_count_8k * CHR_PAGE_SIZE, true);
	rz_structured_data_map_add_unsigned(nes, "mapper", INES_MAPPER(hdr->rom_control_byte_0, hdr->rom_control_byte_1), true);
	rz_structured_data_map_add_string(nes, "mirroring", INES_MIRROR(hdr->rom_control_byte_0) ? "vertical" : "horizontal");
	rz_structured_data_map_add_boolean(nes, "battery", INES_BATTERY(hdr->rom_control_byte_0) != 0);
	rz_structured_data_map_add_boolean(nes, "trainer", INES_TRAINER(hdr->rom_control_byte_0) != 0);
	rz_structured_data_map_add_boolean(nes, "alternative_nametable_layout", INES_ALT_NAMETABLE(hdr->rom_control_byte_0) != 0);
	rz_structured_data_map_add_unsigned(nes, "ram_banks", hdr->ram_bank_count_8k, false);
	return info;
}

RzBinPlugin rz_bin_plugin_nes = {
	.name = "nes",
	.desc = "Nintendo NES",
	.license = "MIT",
	.author = "maijin",
	.load_buffer = &nes_load_buffer,
	.baddr = &nes_baddr,
	.check_buffer = &nes_check_buffer,
	.entries = &nes_entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &nes_sections,
	.symbols = &nes_symbols,
	.info = &nes_info,
	.mem = &nes_mem,
	.destroy = &nes_destroy,
	.bin_structure = &nes_structure,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_nes,
	.version = RZ_VERSION
};
#endif
