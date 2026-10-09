// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_bin.h>
#include <c166/c166_raw.h>

/**
 * \brief Check if file starts with a vector table
 * */
static bool is_c166_buffer(RzBuffer *buf) {
	ut8 c = 0;
	if (!rz_buf_read8_at(buf, 0, &c) || c != 0xFA) {
		return false; // Not a jmp
	}
	return true;
}

static bool check_vector(const ut8 *buf, ut64 size) {
	(void)size;
	const ut8 c = rz_read_le8(buf);
	if (!c || c != 0xFA) {
		return false; // Not a jmp
	}
	return true;
}

bool gb_check_buffer(RzBuffer *b);
static bool check_buffer(RzBuffer *buf) {
	if (is_c166_buffer(buf)) {
		return !gb_check_buffer(buf);
	}
	return false;
}

rz_bin_c166_obj *rz_bin_format_c166_load(const ut8 *buf, ut64 size) {
	if (size < 4) {
		return NULL;
	}
	rz_bin_c166_obj *ret = RZ_NEW0(rz_bin_c166_obj);
	if (!ret) {
		return NULL;
	}
	const ut8 c = rz_read_le8(buf + 1);
	ret->base_addr = (ut32)c << 16;

	ret->interrupts = rz_vector_new(sizeof(ut64), NULL, NULL);
	if (!ret->interrupts) {
		RZ_FREE(ret);
		return NULL;
	}
	ut16 i = 0;
	while (i <= (1 << 9)) {
		if (i > size) {
			break;
		}
		const ut8 cc = rz_read_le8(buf + i);
		if (cc && cc == 0xFA) {
			ut64 addr = ret->base_addr | i;
			rz_vector_push(ret->interrupts, &addr);
			i += 4;
			continue;
		}
		i += 4;
		const ut8 cc2 = rz_read_le8(buf + i);
		if (!cc2 || cc2 != 0xFA) {
			if (cc2 == 0xFF || cc2 == 0x00) {
				continue;
			}
			break; // Not a jmp
		}
	}
	return ret;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	(void)bf;
	(void)sdb;
	ut64 size = rz_buf_size(b);
	const ut8 *buf = rz_buf_data(b, &size);
	if (!buf) {
		return false;
	}
	if (!check_vector(buf, size)) {
		return false;
	}
	obj->bin_obj = rz_bin_format_c166_load(buf, size);
	if (!obj->bin_obj) {
		return false;
	}
	return true;
}

static void destroy(RzBinFile *bf) {
	rz_bin_c166_obj *obj = (rz_bin_c166_obj *)bf->o->bin_obj;
	if (obj->interrupts) {
		rz_vector_free(obj->interrupts);
	}
	RZ_FREE(obj);
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret)
		return NULL;

	if (!bf || !bf->buf) {
		free(ret);
		return NULL;
	}
	const rz_bin_c166_obj *obj = bf->o->bin_obj;

	ret->type = rz_str_dup("ROM");
	ret->file = rz_str_dup(bf->file);
	ret->bclass = rz_str_dup("C16x Raw Dump");
	ret->rclass = rz_str_dup("C16x Raw");
	ret->compiler = rz_str_dup("keil");
	ret->os = rz_str_dup("c166");
	ret->cpu = cpu_name(obj->cpu);
	ret->machine = rz_str_dup("Siemens/Infineon C166 family microcontroller");
	ret->arch = rz_str_dup("c166");
	ret->big_endian = false;
	ret->has_va = true;
	ret->bits = 16;
	ret->dbg_info = 0;
	ret->has_nx = false;
	return ret;
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	const rz_bin_c166_obj *obj = bf->o->bin_obj;

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	RzBinMap *map = RZ_NEW0(RzBinMap);
	if (!map) {
		rz_pvector_free(ret);
		return NULL;
	}
	map->paddr = 0;
	map->vaddr = obj->base_addr;
	map->psize = bf->size;
	map->vsize = bf->size;
	map->perm = RZ_PERM_RX;
	map->name = rz_str_dup("code");
	rz_pvector_push(ret, map);

	RzBinMap *ram_sfr = RZ_NEW0(RzBinMap);
	if (!ram_sfr) {
		rz_pvector_free(ret);
		return NULL;
	}
	ram_sfr->paddr = 0;
	ram_sfr->vaddr = 0xF000;
	ram_sfr->psize = 0;
	ram_sfr->vsize = 0xFFF;
	ram_sfr->perm = RZ_PERM_RW;
	ram_sfr->name = rz_str_dup("ram_sfr");
	rz_pvector_push(ret, ram_sfr);
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	const rz_bin_c166_obj *obj = bf->o->bin_obj;

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}
	RzBinSection *new = RZ_NEW0(RzBinSection);
	if (!new) {
		rz_pvector_free(ret);
		return NULL;
	}
	new->name = rz_str_dup("code");
	new->paddr = 0;
	new->vaddr = obj->base_addr;
	new->size = bf->size;
	new->vsize = bf->size;
	new->perm = RZ_PERM_RX;
	new->is_data = true;
	rz_pvector_push(ret, new);

	RzBinSection *ram_sfr = RZ_NEW0(RzBinSection);
	if (!ram_sfr) {
		rz_pvector_free(ret);
		return NULL;
	}
	ram_sfr->name = rz_str_dup("ram_sfr");
	ram_sfr->paddr = 0;
	ram_sfr->vaddr = 0xF000;
	ram_sfr->size = 0;
	ram_sfr->vsize = 0xFFF;
	ram_sfr->perm = RZ_PERM_RW;
	ram_sfr->is_data = true;

	rz_pvector_push(ret, ram_sfr);
	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	const rz_bin_c166_obj *obj = bf->o->bin_obj;

	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}
	RzBinAddr *addr = RZ_NEW0(RzBinAddr);
	if (!addr) {
		rz_pvector_free(ret);
		return NULL;
	}
	addr->type = RZ_BIN_SPECIAL_SYMBOL_ENTRY;
	addr->vaddr = obj->base_addr;
	rz_pvector_push(ret, addr);
	return ret;
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	RzBinStringSearchOpt opt;
	rz_bin_string_search_opt_init(&opt);
	opt.mode = RZ_BIN_STRING_SEARCH_MODE_READ_ONLY_SECTIONS;
	opt.string_encoding = RZ_STRING_ENC_UTF8;
	return rz_bin_file_strings(bf, &opt);
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol type) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	const rz_bin_c166_obj *obj = bf->o->bin_obj;
	if (type == RZ_BIN_SPECIAL_SYMBOL_ENTRY) {
		// entrypoint is always RESET vector (0xC00000)
		RzBinAddr *ptr = RZ_NEW0(RzBinAddr);
		if (!ptr) {
			RZ_FREE(ptr);
			return NULL;
		}
		ptr->type = RZ_BIN_SPECIAL_SYMBOL_ENTRY;
		ptr->vaddr = obj->base_addr;
		return ptr;
	}
	return NULL;
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return NULL;
	}
	const rz_bin_c166_obj *obj = (rz_bin_c166_obj *)bf->o->bin_obj;
	if (!obj) {
		return NULL;
	}

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}
	populate_isr_table(obj->interrupts, ret, obj->base_addr);
	return ret;
}

static ut64 baddr(RzBinFile *bf) {
	const rz_bin_c166_obj *obj = (rz_bin_c166_obj *)bf->o->bin_obj;
	return obj->base_addr;
}

static RzStructuredData *c166_structure(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return NULL;
	}
	const rz_bin_c166_obj *obj = (rz_bin_c166_obj *)bf->o->bin_obj;
	if (!obj) {
		return NULL;
	}

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}
	char *cpu = cpu_name(obj->cpu);
	rz_structured_data_map_add_string(info, "cpu", cpu);
	free(cpu);

	RzStructuredData *bininfo = rz_structured_data_map_add_map(info, "c166-bininfo");
	if (!bininfo) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add_unsigned(bininfo, "isr_count",
		rz_vector_len(obj->interrupts), false);
	rz_structured_data_map_add_unsigned(bininfo, "base_addr", obj->base_addr, true);
	return info;
}

struct rz_bin_plugin_t rz_bin_plugin_c166 = {
	.name = "c166",
	.desc = "Siemens/Infineon C166 family microcontroller binary",
	.author = "SSharshunov",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.maps = &maps,
	.sections = &sections,
	.bin_structure = &c166_structure,
	.info = &info,
	.binsym = &binsym,
	.symbols = &symbols,
	.strings = &strings,
	.baddr = baddr
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_c166,
	.version = RZ_VERSION
};
#endif
