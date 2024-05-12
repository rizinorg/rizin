// SPDX-FileCopyrightText: 2017-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

// TODO: Support NRR and MODF
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "nxo/nxo.h"

#define NRO_OFF(x)           (sizeof(NXOStart) + rz_offsetof(NROHeader, x))
#define NRO_OFFSET_MODMEMOFF rz_offsetof(NXOStart, mod_memoffset)

// starting at 0x10 (16th byte)
typedef struct {
	ut32 magic; // NRO0
	ut32 unknown; // 4
	ut32 size; // 8
	ut32 unknown2; // 12
	ut32 text_memoffset; // 16
	ut32 text_size; // 20
	ut32 ro_memoffset; // 24
	ut32 ro_size; // 28
	ut32 data_memoffset; // 32
	ut32 data_size; // 36
	ut32 bss_size; // 40
	ut32 unknown3;
} NROHeader;

static ut64 baddr(RzBinFile *bf) {
	if (!bf) {
		return 0;
	}

	ut32 result;
	if (!rz_buf_read_le32_at(bf->buf, NRO_OFFSET_MODMEMOFF, &result)) {
		return 0;
	}

	return result;
}

static bool check_buffer(RzBuffer *b) {
	ut8 magic[4];
	if (rz_buf_read_at(b, NRO_OFF(magic), magic, sizeof(magic)) == 4) {
		return fileType(magic) != NULL;
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	ut32 mod0;
	if (!rz_buf_read_le32_at(b, NRO_OFFSET_MODMEMOFF, &mod0)) {
		return false;
	}

	// XX bf->buf vs b :D this load_b
	RzBinNXOObj *bin = RZ_NEW0(RzBinNXOObj);
	if (!bin) {
		return false;
	}

	ut64 ba = baddr(bf);
	bin->methods_vec = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	bin->imports_vec = rz_pvector_new((RzListFree)rz_bin_import_free);
	parseMod(b, bin, mod0, ba);
	obj->bin_obj = bin;

	return true;
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol type) {
	return NULL; // TODO
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret;
	RzBinAddr *ptr = NULL;
	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	if ((ptr = RZ_NEW0(RzBinAddr))) {
		ptr->paddr = 0x80;
		ptr->vaddr = ptr->paddr + baddr(bf);
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static Sdb *get_sdb(RzBinFile *bf) {
	Sdb *kv = sdb_new0();
	sdb_num_set(kv, "nro_start.offset", 0);
	sdb_num_set(kv, "nro_start.size", 16);
	sdb_set(kv, "nro_start.format", "xxq unused mod_memoffset padding");
	sdb_num_set(kv, "nro_header.offset", 16);
	sdb_num_set(kv, "nro_header.size", 0x70);
	sdb_set(kv, "nro_header.format", "xxxxxxxxxxxx magic unk size unk2 text_offset text_size ro_offset ro_size data_offset data_size bss_size unk3");
	sdb_ns_set(bf->sdb, "info", kv);
	return kv;
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	RzBuffer *b = bf->buf;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	ut64 ba = baddr(bf);
	ut64 bufsz = rz_buf_size(bf->buf);

	ut32 sig0;
	if (!rz_buf_read_le32_at(bf->buf, 0x18, &sig0)) {
		rz_pvector_free(ret);
		return NULL;
	}

	RzBinMap *map = NULL;
	if (sig0 && sig0 + 8 < bufsz) {
		map = RZ_NEW0(RzBinMap);
		if (!map) {
			return ret;
		}

		ut32 sig0sz;
		if (!rz_buf_read_le32_at(bf->buf, sig0 + 4, &sig0sz)) {
			rz_pvector_free(ret);
			ret = NULL;
			goto maps_err;
		}

		map->name = strdup("sig0");
		map->paddr = sig0;
		map->psize = sig0sz;
		map->vsize = sig0sz;
		map->vaddr = sig0 + ba;
		map->perm = RZ_PERM_R;
		rz_pvector_push(ret, map);
	} else {
		RZ_LOG_ERROR("Invalid SIG0 address\n");
	}

	// add text segment
	if (!(map = RZ_NEW0(RzBinMap))) {
		return ret;
	}
	map->name = strdup("text");
	ut32 tmp;
	if (!rz_buf_read_le32_at(b, NRO_OFF(text_memoffset), &tmp)) {
		goto maps_err;
	}
	map->paddr = tmp;

	if (!rz_buf_read_le32_at(b, NRO_OFF(text_size), &tmp)) {
		goto maps_err;
	}
	map->psize = tmp;

	map->vsize = map->psize;
	map->vaddr = map->paddr + ba;
	map->perm = RZ_PERM_RX;
	rz_pvector_push(ret, map);

	// add ro segment
	if (!(map = RZ_NEW0(RzBinMap))) {
		return ret;
	}
	map->name = strdup("ro");
	if (!rz_buf_read_le32_at(b, NRO_OFF(ro_memoffset), &tmp)) {
		goto maps_err;
	}
	map->paddr = tmp;

	if (!rz_buf_read_le32_at(b, NRO_OFF(ro_size), &tmp)) {
		goto maps_err;
	}
	map->psize = tmp;

	map->vsize = map->psize;
	map->vaddr = map->paddr + ba;
	map->perm = RZ_PERM_R;
	rz_pvector_push(ret, map);

	// add data segment
	if (!(map = RZ_NEW0(RzBinMap))) {
		return ret;
	}
	map->name = strdup("data");
	if (!rz_buf_read_le32_at(b, NRO_OFF(data_memoffset), &tmp)) {
		goto maps_err;
	}
	map->paddr = tmp;

	if (!rz_buf_read_le32_at(b, NRO_OFF(data_size), &tmp)) {
		goto maps_err;
	}
	map->psize = tmp;

	map->vsize = map->psize;
	map->vaddr = map->paddr + ba;
	map->perm = RZ_PERM_RW;
	rz_pvector_push(ret, map);
	return ret;

maps_err:
	free(map);
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret = NULL;
	RzBinSection *ptr = NULL;
	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free))) {
		return NULL;
	}

	ut64 ba = baddr(bf);

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = strdup("header");
	ptr->size = 0x80;
	ptr->vsize = 0x80;
	ptr->paddr = 0;
	ptr->vaddr = 0;
	ptr->perm = RZ_PERM_R;
	rz_pvector_push(ret, ptr);

	int bufsz = rz_buf_size(bf->buf);

	ut32 mod0;
	if (!rz_buf_read_le32_at(bf->buf, NRO_OFFSET_MODMEMOFF, &mod0)) {
		free(ret);
		return NULL;
	}

	if (mod0 && mod0 + 8 < bufsz) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			return ret;
		}
		ut32 mod0sz;
		if (!rz_buf_read_le32_at(bf->buf, mod0 + 4, &mod0sz)) {
			free(ret);
			return NULL;
		}
		ptr->name = strdup("mod0");
		ptr->size = mod0sz;
		ptr->vsize = mod0sz;
		ptr->paddr = mod0;
		ptr->vaddr = mod0 + ba;
		ptr->perm = RZ_PERM_R; // rw-
		rz_pvector_push(ret, ptr);
	} else {
		RZ_LOG_ERROR("Invalid MOD0 address\n");
	}

	RzPVector *mappies = maps(bf);
	if (mappies) {
		RzPVector *msecs = rz_bin_sections_of_maps(mappies);
		if (msecs) {
			void **iter;
			RzBinSection *section;
			rz_pvector_foreach (msecs, iter) {
				section = *iter;
				rz_pvector_push(ret, section);
			}
			msecs->v.len = 0;
			rz_pvector_free(msecs);
		}
		rz_pvector_free(mappies);
	}
	return ret;
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	RzBinNXOObj *bin;
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	bin = (RzBinNXOObj *)bf->o->bin_obj;
	return bin->methods_vec;
}

static RzPVector /*<RzBinImport *>*/ *imports(RzBinFile *bf) {
	RzBinNXOObj *bin;
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	bin = (RzBinNXOObj *)bf->o->bin_obj;
	return bin->imports_vec;
}

static RzPVector /*<char *>*/ *libs(RzBinFile *bf) {
	return NULL;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ut8 magic[4];
	rz_buf_read_at(bf->buf, NRO_OFF(magic), magic, sizeof(magic));
	const char *ft = fileType(magic);
	if (!ft) {
		ft = "nro";
	}
	ret->file = strdup(bf->file);
	ret->rclass = strdup(ft);
	ret->os = strdup("switch");
	ret->arch = strdup("arm");
	ret->machine = strdup("Nintendo Switch");
	ret->subsystem = strdup(ft);
	if (!strncmp(ft, "nrr", 3)) {
		ret->bclass = strdup("program");
		ret->type = strdup("EXEC (executable file)");
	} else if (!strncmp(ft, "nro", 3)) {
		ret->bclass = strdup("object");
		ret->type = strdup("OBJECT (executable code)");
	} else { // mod
		ret->bclass = strdup("library");
		ret->type = strdup("MOD (executable library)");
	}
	ret->bits = 64;
	ret->has_va = true;
	ret->big_endian = false;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	return ret;
}

#if !RZ_BIN_NRO

RzBinPlugin rz_bin_plugin_nro = {
	.name = "nro",
	.desc = "Nintendo Switch NRO0 binaries",
	.license = "MIT",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.maps = &maps,
	.sections = &sections,
	.get_sdb = &get_sdb,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_nro,
	.version = RZ_VERSION
};
#endif
#endif
