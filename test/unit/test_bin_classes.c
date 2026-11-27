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

static bool load_classes_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	return true;
}

static RzPVector *plugin_classes(RzBinFile *bf) {
	RzPVector *classes = rz_pvector_new((RzPVectorFree)rz_bin_class_free);
	const char *names[] = { "Zulu", "Same", "Same", "Duplicate", "Duplicate" };
	const ut64 addresses[] = { UT64_MAX, UT64_MAX, 0x200, 0x300, 0x100 };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(names); i++) {
		RzBinClass *c = RZ_NEW0(RzBinClass);
		c->name = rz_str_dup(names[i]);
		c->addr = addresses[i];
		rz_pvector_push(classes, c);
	}
	return classes;
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
	RzBinPlugin plugin = {
		.name = "test_classes",
		.load_buffer = load_classes_buffer,
		.classes = plugin_classes,
	};
	RzBin *bin = rz_bin_new();
	mu_assert_notnull(bin, "create bin");
	mu_assert_true(rz_bin_plugin_add(bin, &plugin), "register plugin");
	bin->filter_rules = RZ_BIN_REQ_CLASSES;
	RzBuffer *buf = rz_buf_new_with_bytes((const ut8 *)"classes", 7);
	RzBinOptions opt;
	rz_bin_options_init(&opt, -1, 0, 0, false);
	opt.filename = "classes.bin";
	opt.pluginname = plugin.name;
	RzBinFile *bf = rz_bin_open_buf(bin, buf, &opt);
	mu_assert_notnull(bf, "load plugin classes");
	RzBinObject *o = bf->o;
	const char *sorted[] = { "Duplicate", "Duplicate", "Same", "Same", "Zulu" };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(sorted); i++) {
		RzBinClass *c = rz_pvector_at(o->classes, i);
		mu_assert_streq(c->name, sorted[i], "sorted immediately on load");
	}
	RzBinClass *first = rz_bin_object_find_class(o, "Duplicate");
	mu_assert_eq(first->addr, 0x300, "lookup preserves first plugin duplicate");
	mu_assert_ptreq(rz_pvector_at(o->classes, 1), first, "duplicate addresses sorted on load");
	RzBinClass *missing = rz_bin_object_find_class(o, "Same");
	RzBinClass *known = rz_pvector_at(o->classes, 3);
	mu_assert_ptreq(rz_pvector_at(o->classes, 2), missing, "initial missing address order");
	mu_assert_ptreq(rz_bin_object_add_class(o, "Same", NULL, 0x300), missing, "update plugin duplicate");
	mu_assert_ptreq(rz_pvector_at(o->classes, 2), known, "address update immediately restores order");
	mu_assert_ptreq(rz_pvector_at(o->classes, 3), missing, "updated class follows known address");
	mu_assert_ptreq(rz_bin_object_find_class(o, "Same"), missing, "update preserves lookup identity");
	mu_assert_notnull(rz_bin_object_add_class(o, "Alpha", NULL, UT64_MAX), "insert before plugin classes");
	mu_assert_notnull(rz_bin_object_add_class(o, "Beta", NULL, UT64_MAX), "insert among sorted classes");
	mu_assert_ptreq(rz_pvector_at(o->classes, 4), known, "known address remains ordered");
	mu_assert_ptreq(rz_pvector_at(o->classes, 5), missing, "updated address remains ordered");
	mu_assert_eq(rz_pvector_len(o->classes), 7, "preserve plugin duplicates");
	rz_bin_free(bin);
	rz_buf_free(buf);
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_class_insertion_order);
	mu_run_test(test_class_duplicate_metadata);
	mu_run_test(test_class_plugin_order_and_address_update);
	return tests_passed != tests_run;
}

mu_main(all_tests)
