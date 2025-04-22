// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "dex/dex.h"

#define rz_bin_file_get_dex(bf) ((RzBinDex *)bf->o->bin_obj)

static RzBinInfo *info(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	RzBinInfo *binfo = RZ_NEW0(RzBinInfo);
	if (!binfo) {
		return NULL;
	}

	binfo->lang = "java";
	binfo->file = rz_str_dup(bf->file);
	binfo->type = rz_str_dup("DEX CLASS");
	binfo->bclass = rz_bin_dex_version(dex);
	binfo->has_va = true;
	binfo->rclass = rz_str_dup("class");
	binfo->os = rz_str_dup("linux");
	binfo->subsystem = rz_str_dup("any");
	binfo->machine = rz_str_dup("Dalvik VM");
	binfo->arch = rz_str_dup("dalvik");
	binfo->bits = 32;
	binfo->big_endian = false;
	binfo->dbg_info = rz_bin_dex_debug_info(dex);

	rz_bin_dex_checksum(dex, &binfo->sum[0]);
	rz_bin_dex_sha1(dex, &binfo->sum[1]);

	return binfo;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	RzBinDex *dex = rz_bin_dex_new(buf, obj->opts.loadaddr, sdb);
	if (!dex) {
		return false;
	}
	obj->bin_obj = dex;
	return true;
}

static void destroy(RzBinFile *bf) {
	rz_bin_dex_free(rz_bin_file_get_dex(bf));
}

static bool check_buffer(RzBuffer *b) {
	if (rz_buf_size(b) > 32) {
		ut8 buf[4] = { 0 };
		rz_buf_read_at(b, 0, buf, sizeof(buf));
		return !memcmp(buf, "dex\n", 4);
	}
	return false;
}

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

static Sdb *get_sdb(RzBinFile *bf) {
	return bf->sdb;
}

static RzPVector /*<RzBinClass *>*/ *classes(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_classes(dex);
}

static RzPVector /*<RzBinImport *>*/ *imports(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_imports(dex);
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_sections(dex);
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_symbols(dex);
}

static RzPVector /*<char *>*/ *libraries(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_libraries(dex);
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol sym) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_resolve_symbol(dex, sym);
}

static RzPVector /*<RzBinAddr *>*/ *entrypoints(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_entrypoints(dex);
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_strings(dex);
}

static RzPVector /*<RzBinVirtualFile *>*/ *virtual_files(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	RzBuffer *buffer = rz_bin_dex_relocations(dex);
	if (!buffer) {
		return NULL;
	}

	RzPVector *vfiles = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
	if (!vfiles) {
		return NULL;
	}

	RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
	if (!vf) {
		rz_buf_free(buffer);
		return vfiles;
	}
	vf->buf = buffer;
	vf->buf_owned = false;
	vf->name = rz_str_dup(RZ_DEX_RELOC_TARGETS);

	rz_pvector_push(vfiles, vf);
	return vfiles;
}

static int demangle_type(const char *str) {
	return RZ_BIN_LANGUAGE_JAVA;
}

static char *get_name(RzBinFile *bf, int type, int index) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}
	switch (type) {
	case 'm': // method
		return rz_bin_dex_resolve_method_by_idx(dex, index);
	case 'f': // field
		return rz_bin_dex_resolve_field_by_idx(dex, index);
	case 's': // string
		return rz_bin_dex_resolve_string_by_idx(dex, index);
	case 'c': // class
		return rz_bin_dex_resolve_class_by_idx(dex, index);
	case 'p': // proto
		return rz_bin_dex_resolve_proto_by_idx(dex, index);
	default:
		return NULL;
	}
}

static ut64 get_offset(RzBinFile *bf, int type, int index) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return -1;
	}
	switch (type) {
	case 'm': // method
		return rz_bin_dex_resolve_method_offset_by_idx(dex, index);
	case 's': // strings
		return rz_bin_dex_resolve_string_offset_by_idx(dex, index);
	case 't': // type
		return rz_bin_dex_resolve_type_id_offset_by_idx(dex, index);
	case 'c': // class
		return rz_bin_dex_resolve_type_id_offset_by_idx(dex, index);
	case 'o': // objects
	default:
		return -1;
	}
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	RzPVector *maps = rz_bin_maps_of_file_sections(bf);
	void **iter;
	RzBinMap *map;

	rz_pvector_foreach (maps, iter) {
		map = *iter;
		if (strcmp(map->name, RZ_DEX_RELOC_TARGETS)) {
			continue;
		}
		map->vfile_name = rz_str_dup(RZ_DEX_RELOC_TARGETS);
	}
	return maps;
}

RzBinPlugin rz_bin_plugin_dex = {
	.name = "dex",
	.desc = "dex bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entrypoints,
	.virtual_files = &virtual_files,
	.maps = &maps,
	.sections = sections,
	.symbols = symbols,
	.imports = &imports,
	.strings = &strings,
	.get_name = &get_name,
	.get_offset = &get_offset,
	.info = &info,
	.libs = libraries,
	.classes = classes,
	.demangle_type = demangle_type,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_dex,
	.version = RZ_VERSION
};
#endif
