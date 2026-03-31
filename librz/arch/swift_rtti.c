// SPDX-FileCopyrightText: 2025 tushar3q34 <tushar3q34@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_analysis.h"
#include "rz_core.h"
#include "rz_io.h"

static void add_metaclass_info(HtUP *swift_metaclass_info, RzList /*<RzBinClassField *>*/ *fields, char *class_name) {
	RzListIter *iter;
	RzBinClassField *field;
	rz_list_foreach (fields, iter, field) {
		if (!field) {
			continue;
		}
		if (strstr(field->name, "type metadata for ")) {
			ht_up_insert(swift_metaclass_info, field->vaddr + 0x100000000, class_name);
		}
	}
}

static void add_class_base(RzAnalysis *analysis, char *class_name, char *super_class_name) {
	RzAnalysisBaseClass base = { .class_name = super_class_name, .offset = 0 };
	rz_analysis_class_base_set(analysis, class_name, &base);
}

static void rz_add_swift_base_classes(RzAnalysis *analysis, RzBinClass *bin_class, HtUP *swift_metaclass_info) {
	RzList *fields = bin_class->fields;
	RzListIter *iter;
	RzBinClassField *field;
	ut64 vaddr = UT64_MAX;
	rz_list_foreach (fields, iter, field) {
		if (!field) {
			continue;
		}
		if (strstr(field->name, "type metadata for ")) {
			vaddr = field->vaddr + 0x100000000;
			break;
		}
	}
	if (vaddr == UT64_MAX) {
		return;
	}

	vaddr += 0x8;
	// check hexa value ar vaddr + 0x8
	// it should be address to type metadata of superclass
	ut64 super_vaddr = 0;
	ut8 buffer[sizeof(ut64)] = { 0 };
	if (analysis->iob.read_at(analysis->iob.io, vaddr, (ut8 *)&buffer, sizeof(super_vaddr))) {
		super_vaddr = rz_read_ble64(buffer, analysis->big_endian);
	}
	bool found = false;
	char *super_class_name = ht_up_find(swift_metaclass_info, super_vaddr, &found);
	if (found) {
		// If found, we can use the superclass name
		add_class_base(analysis, bin_class->name, super_class_name);
	}
}

static void identify_constructor_destructor(RzAnalysis *analysis) {
	RzPVector *vect = rz_analysis_class_get_all(analysis, false);
	void **iter;
	rz_pvector_foreach (vect, iter) {
		SdbKv *kv = *iter;
		const char *class_name = sdbkv_key(kv);
		RzVector *methods = rz_analysis_class_method_get_all(analysis, class_name);
		RzAnalysisMethod *method;
		rz_vector_foreach (methods, method) {
			if (!method || !method->name) {
				continue;
			}
			if (strstr(method->name, "_init") != NULL && strstr(method->name, "_allocating_init") == NULL) {
				method->method_type = RZ_ANALYSIS_CLASS_METHOD_CONSTRUCTOR;
				rz_analysis_class_method_set(analysis, class_name, method);
			} else if (strstr(method->name, "_deinit") != NULL && strstr(method->name, "_deallocating_deinit") == NULL) {
				method->method_type = RZ_ANALYSIS_CLASS_METHOD_DESTRUCTOR;
				rz_analysis_class_method_set(analysis, class_name, method);
			}
		}
	}
	rz_pvector_free(vect);
}

/**
 * \brief Process Swift RTTI information.
 * This function processes Swift RTTI information from the given RzBinObject.
 * It extracts class, metaclass and method information, and adds it to the analysis.
 * \param analysis The RzAnalysis context to use for processing.
 */
RZ_API void rz_analysis_rtti_swift(RzAnalysis *analysis) {
	HtUP *swift_metaclass_info = ht_up_new(NULL, free);
	RzBinObject *bin_obj = rz_bin_cur_object(analysis->binb.bin);
	const RzPVector *classes = rz_bin_object_get_classes(bin_obj);
	if (!classes) {
		return;
	}
	void **iter_class;
	RzBinClass *class;
	rz_pvector_foreach (classes, iter_class) {
		class = *iter_class;
		if (!class) {
			continue;
		}
		RzList *fields = class->fields;
		if (fields) {
			add_metaclass_info(swift_metaclass_info, fields, class->name);
		}
	}

	rz_pvector_foreach (classes, iter_class) {
		class = *iter_class;
		rz_add_swift_base_classes(analysis, class, swift_metaclass_info);
	}

	identify_constructor_destructor(analysis);
}