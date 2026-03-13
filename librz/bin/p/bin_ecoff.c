// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_bin.h>

#include "ecoff/ecoff.h"

#define VFILE_NAME_RELOC_TARGETS "reloc-targets"
#define VFILE_NAME_PATCHED       "patched"

#define VFILE_NAME_RELOC_TARGETS "reloc-targets"
#define VFILE_NAME_PATCHED       "patched"

static Sdb *ecoff_get_sdb(RzBinFile *bf) {
	return NULL;
}

static bool ecoff_check_buffer(RzBuffer *buf) {
	return ecoff_is_valid_buffer(buf);
}

static bool ecoff_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	ECoff *ecoff = ecoff_parse_from_buffer(buf);
	if (!ecoff) {
		return false;
	}
	obj->bin_obj = ecoff;
	return true;
}

static void ecoff_destroy(RzBinFile *bf) {
	ecoff_free((ECoff *)bf->o->bin_obj);
}

static RzPVector /*<RzBinAddr *>*/ *ecoff_entries(RzBinFile *bf) {
	const ECoff *ecoff = (ECoff *)bf->o->bin_obj;
	if (!ecoff) {
		return NULL;
	}
	return ecoff_get_entries(ecoff);
}

static RzBinAddr *ecoff_binsym(RzBinFile *bf, RzBinSpecialSymbol num) {
	return NULL;
}

static RzPVector /*<RzBinVirtualFile *>*/ *ecoff_virtual_files(RzBinFile *bf) {
	return NULL;
}

static RzPVector /*<RzBinMap *>*/ *ecoff_maps(RzBinFile *bf) {
	return rz_bin_maps_of_file_sections(bf);
}

static RzPVector /*<RzBinSection *>*/ *ecoff_sections(RzBinFile *bf) {
	const ECoff *ecoff = (ECoff *)bf->o->bin_obj;
	if (!ecoff) {
		return NULL;
	}
	return ecoff_get_sections(ecoff);
}

static RzPVector /*<RzBinSymbol *>*/ *ecoff_symbols(RzBinFile *bf) {
	const ECoff *ecoff = (ECoff *)bf->o->bin_obj;
	if (!ecoff) {
		return NULL;
	}
	return ecoff_get_symbols(ecoff);
}

static RzPVector /*<RzBinImport *>*/ *ecoff_imports(RzBinFile *bf) {
	const ECoff *ecoff = (ECoff *)bf->o->bin_obj;
	if (!ecoff) {
		return NULL;
	}
	return ecoff_get_imports(ecoff);
}

static RzPVector /*<RzBinReloc *>*/ *ecoff_relocs(RzBinFile *bf) {
	return NULL;
}

static RzBinInfo *ecoff_info(RzBinFile *bf) {
	const ECoff *ecoff = (ECoff *)bf->o->bin_obj;
	if (!ecoff) {
		return NULL;
	}
	RzBinInfo *ret = ecoff_get_info(ecoff);
	if (!ret) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	return ret;
}

static RzStructuredData *ecoff_structure(RzBinFile *bf) {
	const ECoff *ecoff = (ECoff *)bf->o->bin_obj;
	if (!ecoff) {
		return NULL;
	}

	RzStructuredData *parent = rz_structured_data_new_map();
	if (!parent || !ecoff_new_structure(ecoff, parent)) {
		rz_structured_data_free(parent);
		return NULL;
	}
	return parent;
}

RzBinPlugin rz_bin_plugin_ecoff = {
	.name = "ecoff",
	.desc = "ECOFF (Extended Common Object File Format)",
	.license = "LGPL3",
	.author = "deroad",
	.get_sdb = &ecoff_get_sdb,
	.load_buffer = &ecoff_load_buffer,
	.destroy = &ecoff_destroy,
	.check_buffer = &ecoff_check_buffer,
	.entries = &ecoff_entries,
	.binsym = &ecoff_binsym,
	.virtual_files = &ecoff_virtual_files,
	.maps = &ecoff_maps,
	.sections = &ecoff_sections,
	.symbols = &ecoff_symbols,
	.imports = &ecoff_imports,
	.info = &ecoff_info,
	.relocs = &ecoff_relocs,
	.section_flag_to_rzlist = &ecoff_resolve_section_flags,
	.bin_structure = &ecoff_structure,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_ecoff,
	.version = RZ_VERSION
};
#endif
