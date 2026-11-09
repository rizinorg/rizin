// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "minunit.h"

static void init_classes(RzBinObject *o) {
	o->classes = rz_pvector_new((RzPVectorFree)rz_bin_class_free);
	o->name_to_class_object = ht_sp_new(HT_STR_DUP, NULL, NULL);
}

static void fini_classes(RzBinObject *o) {
	ht_sp_free(o->name_to_class_object);
	rz_pvector_free(o->classes);
}

static RzBinClass *plugin_class(RzBinObject *o, const char *name, ut64 addr) {
	RzBinClass *c = RZ_NEW0(RzBinClass);
	c->name = rz_str_dup(name);
	c->addr = addr;
	rz_pvector_push(o->classes, c);
	if (!ht_sp_find(o->name_to_class_object, name, NULL)) {
		ht_sp_insert(o->name_to_class_object, name, c);
	}
	return c;
}

bool test_class_insertion_order(void) {
	RzBinObject o = { 0 };
	init_classes(&o);
	const char *names[] = { "Delta", "Beta", "Alpha", "Gamma", "Charlie", "Epsilon" };
	const char *sorted[] = { "Alpha", "Beta", "Charlie", "Delta", "Epsilon", "Gamma" };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(names); i++) {
		mu_assert_notnull(rz_bin_object_add_class(&o, names[i], NULL, UT64_MAX), "insert class");
		for (size_t j = 1; j < rz_pvector_len(o.classes); j++) {
			RzBinClass *a = rz_pvector_at(o.classes, j - 1);
			RzBinClass *b = rz_pvector_at(o.classes, j);
			mu_assert_true(strcmp(a->name, b->name) < 0, "ordered after every insertion");
		}
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(sorted); i++) {
		RzBinClass *c = rz_pvector_at(o.classes, i);
		mu_assert_streq(c->name, sorted[i], "final class order");
		mu_assert_ptreq(rz_bin_object_find_class(&o, sorted[i]), c, "hash lookup identity");
	}
	fini_classes(&o);
	mu_end;
}

bool test_class_duplicate_metadata(void) {
	RzBinObject o = { 0 };
	init_classes(&o);
	RzBinClass *c = rz_bin_object_add_class(&o, "Class", NULL, UT64_MAX);
	mu_assert_notnull(c, "initial class");
	mu_assert_ptreq(rz_bin_object_add_class(&o, "Class", "Base", 0x100), c, "reuse class");
	mu_assert_streq(c->super, "Base", "fill missing superclass");
	mu_assert_eq(c->addr, 0x100, "fill missing address");
	mu_assert_ptreq(rz_bin_object_add_class(&o, "Class", "Other", 0x200), c, "reuse again");
	mu_assert_streq(c->super, "Base", "keep existing superclass");
	mu_assert_eq(c->addr, 0x100, "keep existing address");
	mu_assert_eq(rz_pvector_len(o.classes), 1, "no duplicate insertion");
	fini_classes(&o);
	mu_end;
}

bool test_class_plugin_order_and_address_update(void) {
	RzBinObject o = { 0 };
	init_classes(&o);
	RzBinClass *z = plugin_class(&o, "Zulu", UT64_MAX);
	RzBinClass *missing = plugin_class(&o, "Same", UT64_MAX);
	RzBinClass *known = plugin_class(&o, "Same", 0x200);
	mu_assert_ptreq(rz_bin_object_add_class(&o, "Zulu", "Base", UT64_MAX), z, "reuse plugin class");
	mu_assert_ptreq(rz_pvector_at(o.classes, 0), z, "duplicate does not reorder plugin classes");
	mu_assert_notnull(rz_bin_object_add_class(&o, "Alpha", NULL, UT64_MAX), "sort on first new class");
	mu_assert_ptreq(rz_pvector_at(o.classes, 1), missing, "initial duplicate address order");
	mu_assert_ptreq(rz_pvector_at(o.classes, 2), known, "initial known address order");
	mu_assert_ptreq(rz_bin_object_add_class(&o, "Same", NULL, 0x300), missing, "update first plugin duplicate");
	mu_assert_ptreq(rz_pvector_at(o.classes, 1), missing, "metadata update does not immediately reorder");
	mu_assert_notnull(rz_bin_object_add_class(&o, "Beta", NULL, UT64_MAX), "insert after address update");
	mu_assert_ptreq(rz_pvector_at(o.classes, 2), known, "reorder updated duplicate on insertion");
	mu_assert_ptreq(rz_pvector_at(o.classes, 3), missing, "updated address sorts after known");
	mu_assert_eq(rz_pvector_len(o.classes), 5, "preserve plugin duplicates");
	fini_classes(&o);
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_class_insertion_order);
	mu_run_test(test_class_duplicate_metadata);
	mu_run_test(test_class_plugin_order_and_address_update);
	return tests_passed != tests_run;
}

mu_main(all_tests)
