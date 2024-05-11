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

	ht_sp_insert(o->glue_to_class_method, key, method, NULL);
	free(key);

	ht_up_insert(o->vaddr_to_class_method, method->vaddr, method, NULL);
}

static void process_class_field(RzBinObject *o, RzBinClassField *field) {
	// rebase physical address
	field->paddr += o->opts.loadaddr;

	char *key = rz_str_newf(RZ_BIN_FMT_CLASS_HT_GLUE, field->classname, field->name);
	if (!key) {
		RZ_LOG_ERROR("bin: failed to allocate class-field string\n");
		return;
	}

	ht_sp_insert(o->glue_to_class_field, key, field, NULL);
	free(key);
}

static int bin_compare_method(RzBinSymbol *a, RzBinSymbol *b, void *user) {
	return rz_bin_compare_method(a, b);
}

static int bin_compare_class_field(RzBinClassField *a, RzBinClassField *b, void *user) {
	return rz_bin_compare_class_field(a, b);
}

static void process_handle_class(RzBinObject *o, RzBinClass *klass) {
	if (!klass->name) {
		klass->name = rz_str_dup("unknown_class");
	}
	RzBinClass *found = ht_sp_find(o->name_to_class_object, klass->name, NULL);
	if (!found) {
		ht_sp_insert(o->name_to_class_object, klass->name, klass, NULL);
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

	rz_list_sort(klass->methods, (RzListComparator)bin_compare_method, NULL);
	rz_list_sort(klass->fields, (RzListComparator)bin_compare_class_field, NULL);
}

RZ_IPI void rz_bin_set_and_process_classes(RzBinFile *bf, RzBinObject *o) {
	RzBin *bin = bf->rbin;
	RzBinPlugin *plugin = o->plugin;

	rz_pvector_free(o->classes);
	if (!(bin->filter_rules & (RZ_BIN_REQ_CLASSES | RZ_BIN_REQ_CLASSES_SOURCES)) ||
		!plugin->classes || !(o->classes = plugin->classes(bf))) {
		o->classes = rz_pvector_new((RzPVectorFree)rz_bin_class_free);
	}
	rz_warn_if_fail(o->classes->v.free_user);

	ht_sp_free(o->name_to_class_object);
	ht_sp_free(o->glue_to_class_method);
	ht_sp_free(o->glue_to_class_field);
	ht_up_free(o->vaddr_to_class_method);

	o->name_to_class_object = ht_sp_new(HT_STR_DUP, NULL, NULL);
	o->glue_to_class_method = ht_sp_new(HT_STR_DUP, NULL, NULL);
	o->glue_to_class_field = ht_sp_new(HT_STR_DUP, NULL, NULL);
	o->vaddr_to_class_method = ht_up_new(NULL, NULL);

	void **it;
	RzBinClass *element;
	rz_pvector_foreach (o->classes, it) {
		element = *it;
		process_handle_class(o, element);
	}
}
