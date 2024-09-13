// SPDX-FileCopyrightText: 2021-2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#include "../format/java/class_bin.h"
#include "../../arch/isa/java/const.h"

#define rz_bin_file_get_java_class(bf) ((RzBinJavaClass *)bf->o->bin_obj)

static RzBinInfo *info(RzBinFile *bf) {
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}
	RzBinInfo *binfo = RZ_NEW0(RzBinInfo);
	if (!binfo) {
		return NULL;
	}
	binfo->lang = rz_bin_java_class_language(jclass);
	binfo->file = rz_str_dup(bf->file);
	binfo->type = rz_str_dup("JAVA CLASS");
	binfo->bclass = rz_bin_java_class_version(jclass);
	binfo->has_va = false;
	binfo->rclass = rz_str_dup("class");
	binfo->os = rz_str_dup("any");
	binfo->subsystem = rz_str_dup("any");
	binfo->machine = rz_str_dup("jvm");
	binfo->arch = rz_str_dup("java");
	binfo->bits = 32;
	binfo->big_endian = true;
	binfo->dbg_info = rz_bin_java_class_debug_info(jclass);
	return binfo;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	RzBinJavaClass *jclass = rz_bin_java_class_new(buf, obj->opts.loadaddr, sdb);
	if (!jclass) {
		return false;
	}
	obj->bin_obj = jclass;
	return true;
}

static void destroy(RzBinFile *bf) {
	rz_bin_java_class_free(rz_bin_file_get_java_class(bf));
}

static bool check_buffer(RzBuffer *b) {
	if (rz_buf_size(b) > 32) {
		ut8 buf[4];
		rz_buf_read_at(b, 0, buf, sizeof(buf));
		return !memcmp(buf, "\xca\xfe\xba\xbe", 4);
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
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	return rz_bin_java_class_as_classes(jclass);
}

static RzPVector /*<RzBinImport *>*/ *imports(RzBinFile *bf) {
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	return rz_bin_java_class_const_pool_as_imports(jclass);
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	return rz_bin_java_class_as_sections(jclass);
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	RzList *tmp;
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	// read from list and save to pvector
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	RzListIter *iter;
	RzBinSymbol *sym;
	RzList *list = rz_bin_java_class_methods_as_symbols(jclass);
	if (!list) {
		return NULL;
	}
	rz_list_foreach (list, iter, sym) {
		rz_pvector_push(ret, sym);
	}

	tmp = rz_bin_java_class_fields_as_symbols(jclass);
	rz_list_foreach (tmp, iter, sym) {
		rz_pvector_push(ret, sym);
	}
	tmp->length = 0;
	tmp->head = tmp->tail = NULL;
	rz_list_free(tmp);

	tmp = rz_bin_java_class_const_pool_as_symbols(jclass);
	rz_list_foreach (tmp, iter, sym) {
		rz_pvector_push(ret, sym);
	}
	tmp->length = 0;
	tmp->head = tmp->tail = NULL;
	rz_list_free(tmp);
	return ret;
}

static RzPVector /*<char *>*/ *libs(RzBinFile *bf) {
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	return rz_bin_java_class_as_libraries(jclass);
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol sym) {
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	return rz_bin_java_class_resolve_symbol(jclass, sym);
}

static RzPVector /*<RzBinAddr *>*/ *entrypoints(RzBinFile *bf) {
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	return rz_bin_java_class_entrypoints(jclass);
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	return rz_bin_java_class_strings(jclass);
}

static int demangle_type(const char *str) {
	return RZ_BIN_LANGUAGE_JAVA;
}

static char *enrich_asm(RzBinFile *bf, const char *asm_str, int asm_len) {
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
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
			char *tmp = rz_bin_java_class_const_pool_resolve_index(jclass, index);
			if (!tmp) {
				rz_warn_if_reached();
				return NULL;
			}
			char *result = rz_str_newf("%.*s%s", i, asm_str, tmp);
			free(tmp);
			return result;
		}
	}
	return NULL;
}

RzBinPlugin rz_bin_plugin_java = {
	.name = "java",
	.desc = "java bin plugin",
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
	.symbols = &symbols,
	.imports = &imports,
	.strings = &strings,
	.enrich_asm = &enrich_asm,
	.info = &info,
	.libs = libs,
	.classes = classes,
	.demangle_type = demangle_type,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_java,
	.version = RZ_VERSION
};
#endif
