// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_bin.h>
#include <c166/c166_raw.h>

/**
 * \brief Check if file starts with a vector table
 * */
static bool is_c166_vector_table(RzBuffer *buf) {
	if (rz_buf_size(buf) < 64)
		return false;
	ut8 c = 0;
	ut8 i = 0;
	while (i <= 24) {
		if (!rz_buf_read8_at(buf, i, &c) || c != 0xFA) {
			return false; // Not a jmp
		}
		i += 4 + 2 * 2;
	}
	return true;
}

static bool check_buffer(RzBuffer *buf) {
	if (is_c166_vector_table(buf))
		return true;
	return false;
}

rz_bin_c166_obj *rz_bin_format_c166_load(const ut8 *buf, ut64 size) {
	rz_bin_c166_obj *ret = RZ_NEW0(rz_bin_c166_obj);
	if (!ret) {
		return NULL;
	}
	const ut8 c = rz_read_le8(buf + 1);
	ret->base_addr = (ut32)c << 16;
	return ret;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	ut64 size;
	const ut8 *buf = rz_buf_data(b, &size);
	if (!buf) {
		return false;
	}
	obj->bin_obj = rz_bin_format_c166_load(buf, size);
	if (!obj->bin_obj) {
		return false;
	}
	return true;
}

static void destroy(RzBinFile *bf) {
	RZ_FREE(bf->o->bin_obj);
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret)
		return NULL;

	if (!bf || !bf->buf) {
		free(ret);
		return NULL;
	}
	ret->type = rz_str_dup("ROM");
	ret->file = rz_str_dup(bf->file);
	ret->bclass = rz_str_dup("Unknown");
	ret->rclass = rz_str_dup("Unknown");
	ret->compiler = rz_str_dup("keil");
	ret->os = rz_str_dup("c166");
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

	RzBinMap *map = NULL;
	if (!((map = RZ_NEW0(RzBinMap)))) {
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
	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	const rz_bin_c166_obj *obj = bf->o->bin_obj;

	RzPVector *ret;
	RzBinAddr *addr;
	if (!((ret = rz_pvector_new(free)))) {
		return NULL;
	}
	if (!((addr = RZ_NEW0(RzBinAddr)))) {
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
	RzBinAddr *ptr = NULL;
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	rz_bin_c166_obj *obj = bf->o->bin_obj;
	switch (type) {
	case RZ_BIN_SPECIAL_SYMBOL_ENTRY:
		// entrypoint is always RESET vector (0xC00000)
		if (!((ptr = RZ_NEW0(RzBinAddr)))) {
			RZ_FREE(ptr);
			return NULL;
		}
		ptr->type = RZ_BIN_SPECIAL_SYMBOL_ENTRY;
		ptr->vaddr = obj->base_addr;
		return ptr;
	case RZ_BIN_SPECIAL_SYMBOL_MAIN:
	default:
		return NULL;
	}
}

static ut64 baddr(RzBinFile *bf) {
	const rz_bin_c166_obj *obj = (rz_bin_c166_obj *)bf->o->bin_obj;
	return obj->base_addr;
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
	.info = &info,
	.binsym = &binsym,
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
