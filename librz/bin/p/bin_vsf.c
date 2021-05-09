// SPDX-FileCopyrightText: 2015-2019 riq <ricardoquesada@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/* VICE Snapshot File loader: http://vice-emu.sourceforge.net/ */

#include <rz_bin.h>
#include "vsf/vsf_specs.h"

static const char VICE_MAGIC[] = "VICE Snapshot File\032";
#define VICE_MAGIC_LEN sizeof(VICE_MAGIC) - 1
static const char VICE_MAINCPU[] = "MAINCPU";
static const char VICE_C64MEM[] = "C64MEM";
static const char VICE_C64ROM[] = "C64ROM";
static const char VICE_C128MEM[] = "C128MEM";
static const char VICE_C128ROM[] = "C128ROM";

static const struct {
	const char *name;
	const char *desc;
	const int offset_mem;
	const int ram_size;
} _machines[] = {
	{ "C64", "Commodore 64", rz_offsetof(struct vsf_c64mem, ram), 64 * 1024 },
	{ "C128", "Commodore 128", rz_offsetof(struct vsf_c128mem, ram), 128 * 1024 },
};
static const int MACHINES_MAX = sizeof(_machines) / sizeof(_machines[0]);

static Sdb *get_sdb(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	struct rz_bin_vsf_obj *bin = (struct rz_bin_vsf_obj *)bf->o->bin_obj;
	return bin->kv;
}

static bool check_buffer(RzBuffer *b) {
	ut8 magic[VICE_MAGIC_LEN];
	if (rz_buf_read_at(b, 0, magic, VICE_MAGIC_LEN) == VICE_MAGIC_LEN) {
		return !memcmp(magic, VICE_MAGIC, VICE_MAGIC_LEN);
	}
	return false;
}

// XXX b vs bf->buf
static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *b, ut64 loadaddr, Sdb *sdb) {
	ut64 offset = 0;
	struct rz_bin_vsf_obj *res = NULL;
	if (check_buffer(bf->buf)) {
		int i = 0;
		if (!(res = RZ_NEW0(struct rz_bin_vsf_obj))) {
			return false;
		}
		offset = rz_offsetof(struct vsf_hdr, machine);
		if (offset > bf->size) {
			free(res);
			return false;
		}
		char machine[20];
		int l = rz_buf_read_at(bf->buf, offset, (ut8 *)machine, sizeof(machine));
		if (l < 0) {
			free(res);
			return false;
		}
		for (; i < MACHINES_MAX; i++) {
			if (offset + strlen(_machines[i].name) > bf->size) {
				free(res);
				return false;
			}
			if (!strncmp(machine, _machines[i].name, strlen(_machines[i].name))) {
				res->machine_idx = i;
				break;
			}
		}
		if (i >= MACHINES_MAX) {
			eprintf("Unsupported machine type\n");
			free(res);
			return false;
		}
		// read all VSF modules
		offset = sizeof(struct vsf_hdr);
		ut64 sz = rz_buf_size(bf->buf);
		while (offset < sz) {
			struct vsf_module module;
			int read = rz_buf_fread_at(bf->buf, offset, (ut8 *)&module, "16ccci", 1);
			if (read != sizeof(module)) {
				eprintf("Truncated Header\n");
				free(res);
				return false;
			}
#define CMP_MODULE(x) memcmp(module.module_name, x, sizeof(x) - 1)
			if (!CMP_MODULE(VICE_C64MEM) && !module.major) {
				res->mem = offset + read;
			} else if (!CMP_MODULE(VICE_C64ROM) && !module.major) {
				res->rom = offset + read;
			} else if (!CMP_MODULE(VICE_C128MEM) && !module.major) {
				res->mem = offset + read;
			} else if (!CMP_MODULE(VICE_C128ROM) && !module.major) {
				res->rom = offset + read;
			} else if (!CMP_MODULE(VICE_MAINCPU) && module.major == 1) {
				res->maincpu = RZ_NEW(struct vsf_maincpu);
				rz_buf_read_at(bf->buf, offset + read, (ut8 *)res->maincpu, sizeof(*res->maincpu));
			}
#undef CMP_MODULE
			offset += module.length;
			if (module.length == 0) {
				eprintf("Malformed VSF module with length 0\n");
				break;
			}
		}
	}
	if (res) {
		res->kv = sdb_new0();
		sdb_ns_set(sdb, "info", res->kv);
	}
	*bin_obj = res;
	return true;
}

static RzList *mem(RzBinFile *bf) {
	// FIXME: What does Mem do? Should I remove it ?
	struct rz_bin_vsf_obj *vsf_obj = (struct rz_bin_vsf_obj *)bf->o->bin_obj;
	if (!vsf_obj) {
		return NULL;
	}
	RzList *ret;
	RzBinMem *m;
	if (!(ret = rz_list_new())) {
		return NULL;
	}
	ret->free = free;
	if (!(m = RZ_NEW0(RzBinMem))) {
		rz_list_free(ret);
		return NULL;
	}
	m->name = strdup("RAM");
	m->addr = 0; // start address
	m->size = _machines[vsf_obj->machine_idx].ram_size;
	m->perms = rz_str_rwx("rwx");
	rz_list_append(ret, m);
	return ret;
}

static RzList *sections(RzBinFile *bf) {
	struct rz_bin_vsf_obj *vsf_obj = (struct rz_bin_vsf_obj *)bf->o->bin_obj;
	if (!vsf_obj) {
		return NULL;
	}

	RzList *ret = NULL;
	RzBinSection *ptr = NULL;
	if (!(ret = rz_list_new())) {
		return NULL;
	}
	const int m_idx = vsf_obj->machine_idx;
	// Rizin doesn't support BANK switching.
	// But by adding the ROM sections first, and then the RAM
	// it kind of simulate bank switching since users can remove existing sections
	// and the RAM section won't overwrite the ROM since it was added last.
	if (vsf_obj->rom) {
		if (!vsf_obj->machine_idx) {
			// Commodore 64 ROMS
			// BASIC (0xa000 - 0xbfff)
			if (!(ptr = RZ_NEW0(RzBinSection))) {
				return ret;
			}
			ptr->name = strdup("BASIC");
			ptr->paddr = vsf_obj->rom + rz_offsetof(struct vsf_c64rom, basic);
			ptr->size = 1024 * 8; // (8k)
			ptr->vaddr = 0xa000;
			ptr->vsize = 1024 * 8; // BASIC size (8k)
			ptr->perm = RZ_PERM_RX;
			rz_list_append(ret, ptr);

			// KERNAL (0xe000 - 0xffff)
			if (!(ptr = RZ_NEW0(RzBinSection))) {
				return ret;
			}
			ptr->name = strdup("KERNAL");
			ptr->paddr = vsf_obj->rom + rz_offsetof(struct vsf_c64rom, kernal);
			ptr->size = 1024 * 8; // (8k)
			ptr->vaddr = 0xe000;
			ptr->vsize = 1024 * 8; // KERNAL size (8k)
			ptr->perm = RZ_PERM_RX;
			rz_list_append(ret, ptr);

			// CHARGEN section ignored
		} else {
			// Commodore 128 ROMS
			// BASIC (0x4000 - 0xafff)
			if (!(ptr = RZ_NEW0(RzBinSection))) {
				return ret;
			}
			ptr->name = strdup("BASIC");
			ptr->paddr = vsf_obj->rom + rz_offsetof(struct vsf_c128rom, basic);
			ptr->size = 1024 * 28; // (28k)
			ptr->vaddr = 0x4000;
			ptr->vsize = 1024 * 28; // BASIC size (28k)
			ptr->perm = RZ_PERM_RX;
			rz_list_append(ret, ptr);

			// MONITOR (0xb000 - 0xbfff)
			if (!(ptr = RZ_NEW0(RzBinSection))) {
				return ret;
			}
			ptr->name = strdup("MONITOR");
			// skip first 28kb  since "BASIC" and "MONITOR" share the same section in VSF
			ptr->paddr = vsf_obj->rom + rz_offsetof(struct vsf_c128rom, basic) + 1024 * 28;
			ptr->size = 1024 * 4; // (4k)
			ptr->vaddr = 0xb000;
			ptr->vsize = 1024 * 4; // BASIC size (4k)
			ptr->perm = RZ_PERM_RX;
			rz_list_append(ret, ptr);

			// EDITOR (0xc000 - 0xcfff)
			if (!(ptr = RZ_NEW0(RzBinSection))) {
				return ret;
			}
			ptr->name = strdup("EDITOR");
			ptr->paddr = vsf_obj->rom + rz_offsetof(struct vsf_c128rom, editor);
			ptr->size = 1024 * 4; // (4k)
			ptr->vaddr = 0xc000;
			ptr->vsize = 1024 * 4; // BASIC size (4k)
			ptr->perm = RZ_PERM_RX;
			rz_list_append(ret, ptr);

			// KERNAL (0xe000 - 0xffff)
			if (!(ptr = RZ_NEW0(RzBinSection))) {
				return ret;
			}
			ptr->name = strdup("KERNAL");
			ptr->paddr = vsf_obj->rom + rz_offsetof(struct vsf_c128rom, kernal);
			ptr->size = 1024 * 8; // (8k)
			ptr->vaddr = 0xe000;
			ptr->vsize = 1024 * 8; // KERNAL size (8k)
			ptr->perm = RZ_PERM_RX;
			rz_list_append(ret, ptr);

			// CHARGEN section ignored
		}
	}

	if (vsf_obj->mem) {
		int offset = _machines[m_idx].offset_mem;
		if (!vsf_obj->machine_idx) {
			// RAM C64 (0x0000 - 0xffff)
			int size = _machines[m_idx].ram_size;
			if (!(ptr = RZ_NEW0(RzBinSection))) {
				return ret;
			}
			ptr->name = strdup("RAM");
			ptr->paddr = vsf_obj->mem + offset;
			ptr->size = size;
			ptr->vaddr = 0x0;
			ptr->vsize = size;
			ptr->perm = RZ_PERM_RWX;
			rz_list_append(ret, ptr);
		} else {
			// RAM C128 (0x0000 - 0xffff): Bank 0
			// RAM C128 (0x0000 - 0xffff): Bank 1

			// size of each bank: 64k
			int size = 1024 * 64;
			if (!(ptr = RZ_NEW0(RzBinSection))) {
				return ret;
			}
			ptr->name = strdup("RAM BANK 0");
			ptr->paddr = vsf_obj->mem + offset;
			ptr->size = size;
			ptr->vaddr = 0x0;
			ptr->vsize = size;
			ptr->perm = RZ_PERM_RWX;
			rz_list_append(ret, ptr);

			if (!(ptr = RZ_NEW0(RzBinSection))) {
				return ret;
			}
			ptr->name = strdup("RAM BANK 1");
			ptr->paddr = vsf_obj->mem + offset + size;
			ptr->size = size;
			ptr->vaddr = 0x0;
			ptr->vsize = size;
			ptr->perm = RZ_PERM_RWX;
			rz_list_append(ret, ptr);
		}
	}

	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {

	struct rz_bin_vsf_obj *vsf_obj = (struct rz_bin_vsf_obj *)bf->o->bin_obj;
	if (!vsf_obj) {
		return NULL;
	}

	const int m_idx = vsf_obj->machine_idx;

	RzBinInfo *ret = NULL;
	struct vsf_hdr hdr;
	memset(&hdr, 0, sizeof(hdr));
	int read = rz_buf_read_at(bf->buf, 0, (ut8 *)&hdr, sizeof(hdr));
	if (read != sizeof(hdr)) {
		eprintf("Truncated Header\n");
		return NULL;
	}
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = strdup(bf->file);
	ret->type = strdup("Snapshot");
	ret->machine = strdup(_machines[m_idx].desc);
	ret->os = strdup(_machines[m_idx].name);
	ret->arch = strdup("6502");
	ret->bits = 8;
	ret->has_va = true;

	if (!vsf_obj->maincpu) {
		//safe to return, sdb will not be populated
		return ret;
	}

	sdb_num_set(vsf_obj->kv, "vsf.reg_a", vsf_obj->maincpu->ac, 0);
	sdb_num_set(vsf_obj->kv, "vsf.reg_x", vsf_obj->maincpu->xr, 0);
	sdb_num_set(vsf_obj->kv, "vsf.reg_y", vsf_obj->maincpu->yr, 0);
	sdb_num_set(vsf_obj->kv, "vsf.reg_sp", vsf_obj->maincpu->sp, 0);
	sdb_num_set(vsf_obj->kv, "vsf.reg_pc", vsf_obj->maincpu->pc, 0);
	sdb_num_set(vsf_obj->kv, "vsf.reg_st", vsf_obj->maincpu->st, 0);
	sdb_num_set(vsf_obj->kv, "vsf.clock", vsf_obj->maincpu->clk, 0);

	return ret;
}

static RzList *symbols(RzBinFile *bf) {

	static const struct {
		const ut16 address;
		const char *symbol_name;
	} _symbols[] = {
		//		{0xfffa, "NMI_VECTOR_LSB"},
		//		{0xfffb, "NMI_VECTOR_MSB"},
		//		{0xfffe, "IRQ_VECTOR_LSB"},
		//		{0xffff, "IRQ_VECTOR_MSB"},

		// Defines taken from c64.inc from cc65
		// I/O: VIC
		{ 0xd000, "VIC_SPR0_X" },
		{ 0xd001, "VIC_SPR0_Y" },
		{ 0xd002, "VIC_SPR1_X" },
		{ 0xd003, "VIC_SPR1_Y" },
		{ 0xd004, "VIC_SPR2_X" },
		{ 0xd005, "VIC_SPR2_Y" },
		{ 0xd006, "VIC_SPR3_X" },
		{ 0xd007, "VIC_SPR3_Y" },
		{ 0xd008, "VIC_SPR4_X" },
		{ 0xd009, "VIC_SPR4_Y" },
		{ 0xd00a, "VIC_SPR5_X" },
		{ 0xd00b, "VIC_SPR5_Y" },
		{ 0xd00c, "VIC_SPR6_X" },
		{ 0xd00d, "VIC_SPR6_Y" },
		{ 0xd00e, "VIC_SPR7_X" },
		{ 0xd00f, "VIC_SPR7_Y" },
		{ 0xd010, "VIC_SPR_HI_X" },
		{ 0xd015, "VIC_SPR_ENA" },
		{ 0xd017, "VIC_SPR_EXP_Y" },
		{ 0xd01d, "VIC_SPR_EXP_X" },
		{ 0xd01c, "VIC_SPR_MCOLOR" },
		{ 0xd01b, "VIC_SPR_BG_PRzIO" },

		{ 0xd025, "VIC_SPR_MCOLOR0" },
		{ 0xd026, "VIC_SPR_MCOLOR1" },

		{ 0xd027, "VIC_SPR0_COLOR" },
		{ 0xd028, "VIC_SPR1_COLOR" },
		{ 0xd029, "VIC_SPR2_COLOR" },
		{ 0xd02A, "VIC_SPR3_COLOR" },
		{ 0xd02B, "VIC_SPR4_COLOR" },
		{ 0xd02C, "VIC_SPR5_COLOR" },
		{ 0xd02D, "VIC_SPR6_COLOR" },
		{ 0xd02E, "VIC_SPR7_COLOR" },

		{ 0xd011, "VIC_CTRL1" },
		{ 0xd016, "VIC_CTRL2" },

		{ 0xd012, "VIC_HLINE" },

		{ 0xd013, "VIC_LPEN_X" },
		{ 0xd014, "VIC_LPEN_Y" },

		{ 0xd018, "VIC_VIDEO_ADR" },

		{ 0xd019, "VIC_IRR" },
		{ 0xd01a, "VIC_IMR" },

		{ 0xd020, "VIC_BORDERCOLOR" },
		{ 0xd021, "VIC_BG_COLOR0" },
		{ 0xd022, "VIC_BG_COLOR1" },
		{ 0xd023, "VIC_BG_COLOR2" },
		{ 0xd024, "VIC_BG_COLOR3" },

		// 128 stuff
		{ 0xd02F, "VIC_KBD_128" },
		{ 0xd030, "VIC_CLK_128" },

		// I/O: SID
		{ 0xD400, "SID_S1Lo" },
		{ 0xD401, "SID_S1Hi" },
		{ 0xD402, "SID_PB1Lo" },
		{ 0xD403, "SID_PB1Hi" },
		{ 0xD404, "SID_Ctl1" },
		{ 0xD405, "SID_AD1" },
		{ 0xD406, "SID_SUR1" },

		{ 0xD407, "SID_S2Lo" },
		{ 0xD408, "SID_S2Hi" },
		{ 0xD409, "SID_PB2Lo" },
		{ 0xD40A, "SID_PB2Hi" },
		{ 0xD40B, "SID_Ctl2" },
		{ 0xD40C, "SID_AD2" },
		{ 0xD40D, "SID_SUR2" },

		{ 0xD40E, "SID_S3Lo" },
		{ 0xD40F, "SID_S3Hi" },
		{ 0xD410, "SID_PB3Lo" },
		{ 0xD411, "SID_PB3Hi" },
		{ 0xD412, "SID_Ctl3" },
		{ 0xD413, "SID_AD3" },
		{ 0xD414, "SID_SUR3" },

		{ 0xD415, "SID_FltLo" },
		{ 0xD416, "SID_FltHi" },
		{ 0xD417, "SID_FltCtl" },
		{ 0xD418, "SID_Amp" },
		{ 0xD419, "SID_ADConv1" },
		{ 0xD41A, "SID_ADConv2" },
		{ 0xD41B, "SID_Noise" },
		{ 0xD41C, "SID_Read3" },

		// I/O: VDC (128 only)
		{ 0xd600, "VDC_INDEX" },
		{ 0xd601, "VDC_DATA" },

		// I/O: CIAs
		{ 0xDC00, "CIA1_PRA" },
		{ 0xDC01, "CIA1_PRB" },
		{ 0xDC02, "CIA1_DDRA" },
		{ 0xDC03, "CIA1_DDRB" },
		{ 0xDC08, "CIA1_TOD10" },
		{ 0xDC09, "CIA1_TODSEC" },
		{ 0xDC0A, "CIA1_TODMIN" },
		{ 0xDC0B, "CIA1_TODHR" },
		{ 0xDC0D, "CIA1_ICR" },
		{ 0xDC0E, "CIA1_CRA" },
		{ 0xDC0F, "CIA1_CRB" },

		{ 0xDD00, "CIA2_PRA" },
		{ 0xDD01, "CIA2_PRB" },
		{ 0xDD02, "CIA2_DDRA" },
		{ 0xDD03, "CIA2_DDRB" },
		{ 0xDD08, "CIA2_TOD10" },
		{ 0xDD09, "CIA2_TODSEC" },
		{ 0xDD0A, "CIA2_TODMIN" },
		{ 0xDD0B, "CIA2_TODHR" },
		{ 0xDD0D, "CIA2_ICR" },
		{ 0xDD0E, "CIA2_CRA" },
		{ 0xDD0F, "CIA2_CRB" },
	};
	static const int SYMBOLS_MAX = sizeof(_symbols) / sizeof(_symbols[0]);
	struct rz_bin_vsf_obj *vsf_obj = (struct rz_bin_vsf_obj *)bf->o->bin_obj;
	if (!vsf_obj) {
		return NULL;
	}
	const int m_idx = vsf_obj->machine_idx;
	int offset = _machines[m_idx].offset_mem;
	RzList *ret = NULL;
	RzBinSymbol *ptr;
	if (!(ret = rz_list_newf((RzListFree)rz_bin_symbol_free))) {
		return NULL;
	}

	int i;
	for (i = 0; i < SYMBOLS_MAX; i++) {
		if (!(ptr = RZ_NEW0(RzBinSymbol))) {
			return ret;
		}
		if (!ptr->name) {
			ptr->name = calloc(1, RZ_BIN_SIZEOF_STRINGS);
		}
		strncpy(ptr->name, _symbols[i].symbol_name, RZ_BIN_SIZEOF_STRINGS);
		ptr->vaddr = _symbols[i].address;
		ptr->size = 2;
		ptr->paddr = vsf_obj->mem + offset + _symbols[i].address;
		ptr->ordinal = i;
		rz_list_append(ret, ptr);
	}

	return ret;
}

static void destroy(RzBinFile *bf) {
	struct rz_bin_vsf_obj *obj = (struct rz_bin_vsf_obj *)bf->o->bin_obj;
	free(obj->maincpu);
	free(obj);
}

static RzList *entries(RzBinFile *bf) {
	struct rz_bin_vsf_obj *vsf_obj = (struct rz_bin_vsf_obj *)bf->o->bin_obj;
	if (!vsf_obj) {
		return NULL;
	}
	const int m_idx = vsf_obj->machine_idx;

	RzList *ret;
	RzBinAddr *ptr = NULL;
	if (!(ret = rz_list_new())) {
		return NULL;
	}
	int offset = _machines[m_idx].offset_mem;
	// PC
	if (!(ptr = RZ_NEW0(RzBinAddr))) {
		return ret;
	}
	ptr->paddr = vsf_obj->mem + offset;
	ptr->vaddr = vsf_obj->maincpu ? vsf_obj->maincpu->pc : 0;
	rz_list_append(ret, ptr);

	// IRQ: 0xFFFE or 0x0314 ?
	//	if (!(ptr = RZ_NEW0 (RzBinAddr)))
	//		return ret;
	//	ptr->paddr = (vsf_obj->mem + offset) - (void*) bf->buf->buf;
	//	ptr->vaddr = 0x314; // or 0xfffe ?
	//	rz_list_append (ret, ptr);

	return ret;
}

RzBinPlugin rz_bin_plugin_vsf = {
	.name = "vsf",
	.desc = "VICE Snapshot File",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = sections,
	.symbols = &symbols,
	.info = &info,
	.destroy = &destroy,
	.mem = &mem,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_vsf,
	.version = RZ_VERSION
};
#endif
