// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_bin.h>
#include "i/private.h"

static void process_class_method(RzBinObject *o, RzBinSymbol *method) {
	// rebase physical address
	method->paddr += o->opts.loadaddr;

	char *key = rz_str_newf(RZ_BIN_FMT_CLASS_HT_GLUE, method->classname, method->name);
	if (!key) {
		RZ_LOG_ERROR("bin: failed to allocate class-method string\n");
		return;
	}

	ht_pp_insert(o->glue_to_class_method, key, method);
	free(key);

	ht_up_insert(o->vaddr_to_class_method, method->vaddr, method);
}

static void process_class_field(RzBinObject *o, RzBinClassField *field) {
	// rebase physical address
	field->paddr += o->opts.loadaddr;

	char *key = rz_str_newf(RZ_BIN_FMT_CLASS_HT_GLUE, field->classname, field->name);
	if (!key) {
		RZ_LOG_ERROR("bin: failed to allocate class-field string\n");
		return;
	}

	ht_pp_insert(o->glue_to_class_field, key, field);
	free(key);
}

static void process_handle_class(RzBinObject *o, RzBinClass *klass) {
	if (!klass->name) {
		klass->name = rz_str_new("unknown_class");
	}
	RzBinClass *found = ht_pp_find(o->name_to_class_object, klass->name, NULL);
	if (!found) {
		ht_pp_insert(o->name_to_class_object, klass->name, klass);
		found = klass;
	} else {
		RZ_LOG_WARN("Found duplicated class: %s\n", klass->name);
	}

	RzListIter *iter;
	RzBinSymbol *method;
	RzBinClassField *field;
	rz_list_foreach (klass->methods, iter, method) {
		process_class_method(o, method);
	}

	rz_list_foreach (klass->fields, iter, field) {
		process_class_field(o, field);
	}

	rz_list_sort(klass->methods, (RzListComparator)rz_bin_compare_method);
	rz_list_sort(klass->fields, (RzListComparator)rz_bin_compare_class_field);
}

RZ_IPI void rz_bin_set_and_process_classes(RzBinFile *bf, RzBinObject *o) {
	RzBin *bin = bf->rbin;
	RzBinPlugin *plugin = o->plugin;

	rz_list_free(o->classes);
	if (!(bin->filter_rules & (RZ_BIN_REQ_CLASSES | RZ_BIN_REQ_CLASSES_SOURCES)) ||
		!plugin->classes || !(o->classes = plugin->classes(bf))) {
		o->classes = rz_list_newf((RzListFree)rz_bin_class_free);
	}
	rz_warn_if_fail(o->classes->free);

	ht_pp_free(o->name_to_class_object);
	ht_pp_free(o->glue_to_class_method);
	ht_pp_free(o->glue_to_class_field);
	ht_up_free(o->vaddr_to_class_method);

	o->name_to_class_object = ht_pp_new0();
	o->glue_to_class_method = ht_pp_new0();
	o->glue_to_class_field = ht_pp_new0();
	o->vaddr_to_class_method = ht_up_new0();

	RzListIter *it;
	RzBinClass *element;
	rz_list_foreach (o->classes, it, element) {
		process_handle_class(o, element);
	}
}
