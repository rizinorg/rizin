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

static RzBinInfo *java_info(RzBinFile *bf) {
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

static bool java_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	RzBinJavaClass *jclass = rz_bin_java_class_new(buf, obj->opts.loadaddr, sdb);
	if (!jclass) {
		return false;
	}
	obj->bin_obj = jclass;
	return true;
}

static void java_destroy(RzBinFile *bf) {
	rz_bin_java_class_free(rz_bin_file_get_java_class(bf));
}

static bool java_check_buffer(RzBuffer *b) {
	if (rz_buf_size(b) > 32) {
		ut8 buf[4];
		rz_buf_read_at(b, 0, buf, sizeof(buf));
		return !memcmp(buf, "\xca\xfe\xba\xbe", 4);
	}
	return false;
}

static ut64 java_baddr(RzBinFile *bf) {
	return 0;
}

static Sdb *java_get_sdb(RzBinFile *bf) {
	return bf->sdb;
}

static RzPVector /*<RzBinClass *>*/ *java_classes(RzBinFile *bf) {
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	return rz_bin_java_class_as_classes(jclass);
}

static RzPVector /*<RzBinImport *>*/ *java_imports(RzBinFile *bf) {
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	return rz_bin_java_class_const_pool_as_imports(jclass);
}

static RzPVector /*<RzBinSection *>*/ *java_sections(RzBinFile *bf) {
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	return rz_bin_java_class_as_sections(jclass);
}

static RzPVector /*<RzBinSymbol *>*/ *java_symbols(RzBinFile *bf) {
	RzList *tmp;
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	// read from list and save to pvector
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	RzListIter *iter;
	RzBinSymbol *sym;
	tmp = rz_bin_java_class_methods_as_symbols(jclass);
	if (!tmp) {
		rz_pvector_free(ret);
		return NULL;
	}
	rz_list_foreach (tmp, iter, sym) {
		rz_pvector_push(ret, sym);
	}
	// moved ownership to pvec
	tmp->free = NULL;
	rz_list_free(tmp);

	tmp = rz_bin_java_class_fields_as_symbols(jclass);
	rz_list_foreach (tmp, iter, sym) {
		rz_pvector_push(ret, sym);
	}
	// moved ownership to pvec
	tmp->free = NULL;
	rz_list_free(tmp);

	tmp = rz_bin_java_class_const_pool_as_symbols(jclass);
	rz_list_foreach (tmp, iter, sym) {
		rz_pvector_push(ret, sym);
	}
	// moved ownership to pvec
	tmp->free = NULL;
	rz_list_free(tmp);
	return ret;
}

static RzPVector /*<char *>*/ *java_libs(RzBinFile *bf) {
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	return rz_bin_java_class_as_libraries(jclass);
}

static RzBinAddr *java_binsym(RzBinFile *bf, RzBinSpecialSymbol sym) {
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	return rz_bin_java_class_resolve_symbol(jclass, sym);
}

static RzPVector /*<RzBinAddr *>*/ *java_entrypoints(RzBinFile *bf) {
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	return rz_bin_java_class_entrypoints(jclass);
}

static RzPVector /*<RzBinString *>*/ *java_strings(RzBinFile *bf) {
	RzBinJavaClass *jclass = rz_bin_file_get_java_class(bf);
	if (!jclass) {
		return NULL;
	}

	return rz_bin_java_class_strings(jclass);
}

static int java_demangle_type(const char *str) {
	return RZ_BIN_LANGUAGE_JAVA;
}

static char *java_enrich_asm(RzBinFile *bf, const char *asm_str, int asm_len) {
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
	.desc = "Java binary",
	.license = "LGPL3",
	.author = "deroad",
	.get_sdb = &java_get_sdb,
	.load_buffer = &java_load_buffer,
	.destroy = &java_destroy,
	.check_buffer = &java_check_buffer,
	.baddr = &java_baddr,
	.binsym = &java_binsym,
	.entries = &java_entrypoints,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = java_sections,
	.symbols = &java_symbols,
	.imports = &java_imports,
	.strings = &java_strings,
	.enrich_asm = &java_enrich_asm,
	.info = &java_info,
	.libs = java_libs,
	.classes = java_classes,
	.demangle_type = java_demangle_type,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_java,
	.version = RZ_VERSION
};
#endif
