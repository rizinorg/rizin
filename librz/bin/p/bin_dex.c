// SPDX-FileCopyrightText: 2011-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2011-2021 h4ng3r
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "dex/dex.h"
/*
static ut32 __adler32(const ut8 *data, int len) {
	ut32 a = 1, b = 0;
	for (int i = 0; i < len; i++) {
		a = (a + data[i]) % 65521;
		b = (b + a) % 65521;
	}
	return (b << 16) | a;
}
*/
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

	binfo->lang = "dalvik"; // rz_bin_dex_language(dex);
	binfo->file = strdup(bf->file);
	binfo->type = strdup("DEX CLASS");
	binfo->bclass = strdup("?"); // rz_bin_dex_version(dex);
	binfo->has_va = false;
	binfo->rclass = strdup("class");
	binfo->os = strdup("linux");
	binfo->subsystem = strdup("any"); // rz_bin_dex_subsystem(dex);
	binfo->machine = strdup("Dalvik VM");
	binfo->arch = strdup("dalvik");
	binfo->bits = 32;
	binfo->big_endian = false;
	binfo->dbg_info = 0; // rz_bin_dex_debug_info(dex);

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
		ut8 buf[4] = {0};
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

static RzList *classes(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_classes(dex);
}

static RzList *imports(RzBinFile *bf) {
	return NULL;
	/*
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_java_class_const_pool_as_imports(dex);
	*/
}

static RzList *sections(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_sections(dex);
}

static RzList *symbols(RzBinFile *bf) {
	return NULL;
	/*
	RzList *tmp;
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	RzList *list = rz_bin_java_class_methods_as_symbols(dex);
	if (!list) {
		return NULL;
	}

	tmp = rz_bin_java_class_fields_as_symbols(dex);
	rz_list_join(list, tmp);
	rz_list_free(tmp);

	tmp = rz_bin_java_class_const_pool_as_symbols(dex);
	rz_list_join(list, tmp);
	rz_list_free(tmp);
	return list;
	*/
}

static RzList *fields(RzBinFile *bf) {
	return NULL;
	/*
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_java_class_fields_as_binfields(dex);
	*/
}

static RzList *libs(RzBinFile *bf) {
	return NULL;
	/*
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_java_class_as_libraries(dex);
	*/
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol sym) {
	return NULL;
	/*
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_java_class_resolve_symbol(dex, sym);
	*/
}

static RzList *entrypoints(RzBinFile *bf) {
	return NULL;
	/*
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_java_class_entrypoints(dex);
	*/
}

static RzList *strings(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_strings(dex);
}

static int demangle_type(const char *str) {
	return RZ_BIN_NM_JAVA;
}

static char *enrich_asm(RzBinFile *bf, const char *asm_str, int asm_len) {
	return NULL;
	/*
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}
	for (int i = 0; i < asm_len; ++i) {
		if (!strncmp(asm_str + i, JAVA_ASM_CONSTANT_POOL_STR, strlen(JAVA_ASM_CONSTANT_POOL_STR))) {
			const char *snum = asm_str + i + strlen(JAVA_ASM_CONSTANT_POOL_STR);
			if (!IS_DIGIT(*snum)) {
				rz_warn_if_reached();
				continue;
			}
			int index = atoi(snum);
			char *tmp = rz_bin_java_class_const_pool_resolve_index(dex, index);
			if (!tmp) {
				rz_warn_if_reached();
				return NULL;
			}
			char *dem = rz_bin_demangle_java(tmp);
			if (!dem) {
				dem = tmp;
			} else {
				free(tmp);
			}
			char *result = rz_str_newf("%.*s%s", i, asm_str, dem);
			free(dem);
			return result;
		}
	}
	return NULL;
	*/
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
	.maps = &rz_bin_maps_of_file_sections,
	.sections = sections,
	.symbols = symbols,
	.imports = &imports,
	.strings = &strings,
	.enrich_asm = &enrich_asm,
	.info = &info,
	.fields = fields,
	.libs = libs,
	.classes = classes,
	.demangle_type = demangle_type,
	.minstrlen = 3,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_dex,
	.version = RZ_VERSION
};
#endif
