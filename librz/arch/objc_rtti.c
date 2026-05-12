// SPDX-FileCopyrightText: 2025 tushar3q34 <tushar3q34@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_analysis.h"
#include "rz_core.h"

static const RzBinSymbol *get_objc_superclass(RzCore *core, const RzPVector /*<RzBinSymbol *>*/ *symbols, const RzBinSymbol *meta_info) {
	ut64 addr;
	rz_io_nread_at(core->io, meta_info->vaddr + 8, (ut8 *)&addr, 8);
	void **it;
	rz_pvector_foreach (symbols, it) {
		if (!it) {
			continue;
		}
		RzBinSymbol *super_meta = *it;
		if (!super_meta) {
			continue;
		}
		if (super_meta->vaddr == addr) {
			return super_meta;
		}
	}
	return NULL;
}

static void add_objc_superclass(RzAnalysis *analysis, RzPVector /*<SdbKv *>*/ *classes, RzBinSymbol *meta_class, const RzBinSymbol *meta_superclass) {
	if (!strstr(meta_superclass->name, "_OBJC_METACLASS_$_")) {
		return;
	}
	// meta class info symbol is of the form _OBJC_METACLASS_$_<class_name>
	char *class_name = meta_class->name + strlen("_OBJC_METACLASS_$_");
	char *superclass_name = rz_str_dup(meta_superclass->name + strlen("_OBJC_METACLASS_$_"));

	RzAnalysisBaseClass base = { .class_name = superclass_name, .offset = 0 };
	rz_analysis_class_base_set(analysis, class_name, &base);
	rz_analysis_class_base_fini(&base);
}

RZ_API void rz_analysis_rtti_objc(RZ_NULLABLE RzAnalysis *analysis) {
	if (!analysis) {
		return;
	}
	RzPVector *classes = rz_analysis_class_get_all(analysis, false);
	if (!classes) {
		return;
	}
	RzBinObject *o = rz_bin_cur_object(analysis->binb.bin);
	if (!o) {
		return;
	}
	const RzPVector *symbols = rz_bin_object_get_symbols(o);
	void **it;
	rz_pvector_foreach (symbols, it) {
		if (!it) {
			continue;
		}
		RzBinSymbol *sym = *it;
		if (!sym) {
			continue;
		}
		const RzBinSymbol *meta_superclass = NULL;
		if (strstr(sym->name, "_OBJC_METACLASS_$_")) {
			meta_superclass = get_objc_superclass(analysis->core, symbols, sym);
		}
		if (meta_superclass) {
			add_objc_superclass(analysis, classes, sym, meta_superclass);
		}
	}
	rz_pvector_free(classes);
}