// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_bin.h>
#include "../unit/minunit.h"

bool test_rz_bin(void) {
	RzBin *bin = rz_bin_new();
	const char *default_algos[] = { "md5", "sha1", "sha256", "crc32", "entropy" };
	bin->default_hashes = rz_list_new_from_array((const void **)default_algos, RZ_ARRAY_SIZE(default_algos));
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/ioli/crackme0x00", &opt);
	mu_assert_notnull(bf, "crackme0x00 binary could not be opened");
	mu_assert_notnull(bf->o, "bin object");

	RzBinObject *obj = rz_bin_cur_object(bin);

	RzPVector *sections = rz_bin_object_get_sections(obj);
	mu_assert_eq(rz_pvector_len(sections), 29, "rz_bin_object_get_sections");
	rz_pvector_free(sections);

	RzPVector *segments = rz_bin_object_get_segments(obj);
	mu_assert_eq(rz_pvector_len(segments), 10, "rz_bin_object_get_segments");
	rz_pvector_free(segments);

	const RzPVector *entries = rz_bin_object_get_entries(obj);
	mu_assert_eq(rz_pvector_len(entries), 1, "rz_bin_object_get_entries");
	RzBinAddr *entry = (RzBinAddr *)rz_pvector_at(entries, 0);
	mu_assert_eq(entry->vaddr, 0x8048360, "entry virtual address");
	mu_assert_eq(entry->paddr, 0x360, "entry file offset");

	const RzPVector *imports = rz_bin_object_get_imports(obj);
	mu_assert_eq(rz_pvector_len(imports), 5, "rz_bin_object_get_imports");
	const char *import_names[] = { "__libc_start_main", "printf", "scanf", "strcmp", "__gmon_start__" };
	bool has_import_names[sizeof(import_names)] = { 0 };
	RzBinImport *import;
	void **it;
	void **vec_it;
	rz_pvector_foreach (imports, vec_it) {
		import = *vec_it;
		for (int i = 0; i < RZ_ARRAY_SIZE(import_names); ++i) {
			if (!strcmp(import->name, import_names[i])) {
				has_import_names[i] = true;
				break;
			}
		}
	}
	for (int i = 0; i < RZ_ARRAY_SIZE(import_names); ++i) {
		mu_assert_true(has_import_names[i], "Import name was not found");
	}

	const RzPVector *strings = rz_bin_object_get_strings(obj);
	mu_assert_eq(rz_pvector_len(strings), 5, "rz_bin_object_get_strings");
	const char *exp_strings[] = {
		"IOLI Crackme Level 0x00\n",
		"Password: ",
		// "%s", // This is not automatically recognized because too short
		"250382",
		"Invalid Password!\n",
		"Password OK :)\n",
	};
	RzBinString *s;
	int i = 0;
	rz_pvector_foreach (strings, it) {
		s = *it;
		mu_assert_streq(s->string, exp_strings[i], "String not found");
		mu_assert_true(rz_bin_object_get_string_at(obj, s->vaddr, true) != NULL, "is_string (virt) should be true");
		mu_assert_false(rz_bin_object_get_string_at(obj, s->vaddr, false) != NULL, "is_string (phys) should be false");
		mu_assert_true(rz_bin_object_get_string_at(obj, s->paddr, false) != NULL, "is_string (virt) should be false");
		mu_assert_false(rz_bin_object_get_string_at(obj, s->paddr, true) != NULL, "is_string (phys) should be true");
		i++;
	}

	RzPVector *hashes = rz_bin_file_compute_hashes(bin, bf, UT64_MAX);
	mu_assert_eq(rz_pvector_len(hashes), 5, "rz_bin_file_get_hashes");
	const char *hash_names[] = { "md5", "sha1", "sha256", "crc32", "entropy" };
	const char *hash_hexes[] = { "99327411dd72a11d7198b54298648adf", "f2bf1c7758c7b1e22bdea1d7681882783b658705", "3aed9a3821134a2ab1d69cb455e5e9d80bb651a1c97af04cdba4f3bb0adaa37b", "cf8cb28a", "3.484857" };
	RzBinFileHash *hash;
	i = 0;
	void **v_it;
	rz_pvector_foreach (hashes, v_it) {
		hash = *v_it;
		mu_assert_streq(hash->type, hash_names[i], "hash name is wrong");
		mu_assert_streq(hash->hex, hash_hexes[i], "hash digest is wrong");
		i++;
	}
	rz_pvector_free(hashes);

	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

static RzBinReloc *add_reloc(RzPVector *l, ut64 paddr, ut64 vaddr, ut64 target_vaddr) {
	RzBinReloc *reloc = RZ_NEW0(RzBinReloc);
	reloc->type = RZ_BIN_RELOC_8;
	reloc->paddr = paddr;
	reloc->vaddr = vaddr;
	reloc->target_vaddr = target_vaddr;
	rz_pvector_push(l, reloc);
	return reloc;
}

bool test_rz_bin_reloc_storage(void) {
	RzPVector *l = rz_pvector_new(NULL);
	RzBinReloc *r0 = add_reloc(l, 0x108, 0x1000, 0x2004);
	mu_assert_notnull(r0, "reloc");
	RzBinReloc *r1 = add_reloc(l, 0x2002, 0x1003, 0x2008);
	mu_assert_notnull(r1, "reloc");
	RzBinReloc *rz = add_reloc(l, 0x1001, 0x1004, UT64_MAX);
	mu_assert_notnull(rz, "reloc");
	RzBinReloc *r3 = add_reloc(l, 0x1003, 0x1006, 0x200c);
	mu_assert_notnull(r3, "reloc");
	RzBinRelocStorage *relocs = rz_bin_reloc_storage_new(l, NULL);

	RzBinReloc *r = rz_bin_reloc_storage_get_reloc_in(relocs, 0xfff, 1);
	mu_assert_null(r, "reloc in");
	r = rz_bin_reloc_storage_get_reloc_in(relocs, 0xfff, 2);
	mu_assert_ptreq(r, r0, "reloc in");
	r = rz_bin_reloc_storage_get_reloc_in(relocs, 0x1000, 1);
	mu_assert_ptreq(r, r0, "reloc in");
	r = rz_bin_reloc_storage_get_reloc_in(relocs, 0x1002, 1);
	mu_assert_null(r, "reloc in");
	r = rz_bin_reloc_storage_get_reloc_in(relocs, 0x1002, 10);
	mu_assert_ptreq(r, r1, "reloc in");
	r = rz_bin_reloc_storage_get_reloc_in(relocs, 0x1003, 10);
	mu_assert_ptreq(r, r1, "reloc in");
	r = rz_bin_reloc_storage_get_reloc_in(relocs, 0x1006, 8);
	mu_assert_ptreq(r, r3, "reloc in");
	r = rz_bin_reloc_storage_get_reloc_in(relocs, 0x1007, 8);
	mu_assert_null(r, "reloc in");
	r = rz_bin_reloc_storage_get_reloc_in(relocs, 0x2004, 8);
	mu_assert_null(r, "reloc in");
	r = rz_bin_reloc_storage_get_reloc_in(relocs, 0x108, 8);
	mu_assert_null(r, "reloc in");

	r = rz_bin_reloc_storage_get_reloc_to(relocs, 0x1000);
	mu_assert_null(r, "reloc to");
	r = rz_bin_reloc_storage_get_reloc_to(relocs, 0x108);
	mu_assert_null(r, "reloc to");
	r = rz_bin_reloc_storage_get_reloc_to(relocs, 0x2003);
	mu_assert_null(r, "reloc to");
	r = rz_bin_reloc_storage_get_reloc_to(relocs, 0x2004);
	mu_assert_ptreq(r, r0, "reloc to");
	r = rz_bin_reloc_storage_get_reloc_to(relocs, 0x2005);
	mu_assert_null(r, "reloc to");
	r = rz_bin_reloc_storage_get_reloc_to(relocs, 0x2007);
	mu_assert_null(r, "reloc to");
	r = rz_bin_reloc_storage_get_reloc_to(relocs, 0x2008);
	mu_assert_ptreq(r, r1, "reloc to");
	r = rz_bin_reloc_storage_get_reloc_to(relocs, 0x2009);
	mu_assert_null(r, "reloc to");
	r = rz_bin_reloc_storage_get_reloc_to(relocs, 0x200c);
	mu_assert_ptreq(r, r3, "reloc to");
	r = rz_bin_reloc_storage_get_reloc_to(relocs, 0x200d);
	mu_assert_null(r, "reloc to");

	rz_bin_reloc_storage_free(relocs);
	mu_end;
}

typedef struct {
	RzList /*<RzBinFile>*/ *expect; /// things whose delete events are expected now
	bool failed_unexpected;
} DelTracker;

static void event_file_del_cb(RzEvent *ev, int type, void *user, void *data) {
	DelTracker *tracker = user;
	if (type != RZ_EVENT_BIN_FILE_DEL) {
		tracker->failed_unexpected = true;
		return;
	}
	RzEventBinFileDel *bev = data;
	RzListIter *it = rz_list_find_ptr(tracker->expect, bev->bf);
	if (!it) {
		tracker->failed_unexpected = true;
		return;
	}
	rz_list_delete(tracker->expect, it);
}

bool test_rz_bin_file_delete(void) {
	RzIO *io = rz_io_new();
	RzBin *bin = rz_bin_new();
	rz_io_bind(io, &bin->iob);

	DelTracker tracker = {
		.expect = rz_list_new(),
		.failed_unexpected = false
	};
	rz_event_hook(bin->event, RZ_EVENT_BIN_FILE_DEL, event_file_del_cb, &tracker);

	RzBinOptions opt = { 0 };
	RzBinFile *f0 = rz_bin_open(bin, "hex://42424242424242", &opt);
	mu_assert_notnull(f0, "open file");

	RzBinFile *f1 = rz_bin_open(bin, "malloc://1024", &opt);
	mu_assert_notnull(f1, "open file");
	mu_assert_ptrneq(f1, f0, "unique files");

	mu_assert_eq(rz_list_length(bin->binfiles), 2, "files count");
	mu_assert_true(rz_list_contains(bin->binfiles, f0), "f0 in list");
	mu_assert_true(rz_list_contains(bin->binfiles, f1), "f1 in list");

	mu_assert_false(tracker.failed_unexpected, "unexpected del event");
	rz_list_push(tracker.expect, f0);
	rz_bin_file_delete(bin, f0);
	mu_assert_false(tracker.failed_unexpected, "unexpected del event");
	mu_assert_true(rz_list_empty(tracker.expect), "missing del event");

	mu_assert_eq(rz_list_length(bin->binfiles), 1, "files count");
	mu_assert_true(rz_list_contains(bin->binfiles, f1), "f1 in list");

	rz_bin_free(bin);
	rz_io_free(io);

	// free should not send del events for remaining files
	mu_assert_true(rz_list_empty(tracker.expect), "missing del event");
	mu_assert_false(tracker.failed_unexpected, "unexpected del event");

	rz_list_free(tracker.expect);
	mu_end;
}

bool test_rz_bin_file_delete_all(void) {
	RzIO *io = rz_io_new();
	RzBin *bin = rz_bin_new();
	rz_io_bind(io, &bin->iob);

	DelTracker tracker = {
		.expect = rz_list_new(),
		.failed_unexpected = false
	};
	rz_event_hook(bin->event, RZ_EVENT_BIN_FILE_DEL, event_file_del_cb, &tracker);

	RzBinOptions opt = { 0 };
	RzBinFile *f0 = rz_bin_open(bin, "hex://42424242424242", &opt);
	mu_assert_notnull(f0, "open file");

	RzBinFile *f1 = rz_bin_open(bin, "malloc://1024", &opt);
	mu_assert_notnull(f1, "open file");
	mu_assert_ptrneq(f1, f0, "unique files");

	mu_assert_eq(rz_list_length(bin->binfiles), 2, "files count");
	mu_assert_true(rz_list_contains(bin->binfiles, f0), "f0 in list");
	mu_assert_true(rz_list_contains(bin->binfiles, f1), "f1 in list");

	mu_assert_false(tracker.failed_unexpected, "unexpected del event");
	rz_list_push(tracker.expect, f0);
	rz_list_push(tracker.expect, f1);
	rz_bin_file_delete_all(bin);
	mu_assert_false(tracker.failed_unexpected, "unexpected del event");
	mu_assert_true(rz_list_empty(tracker.expect), "missing del event");

	mu_assert_eq(rz_list_length(bin->binfiles), 0, "files count");

	rz_bin_free(bin);
	rz_io_free(io);

	mu_assert_true(rz_list_empty(tracker.expect), "missing del event");
	mu_assert_false(tracker.failed_unexpected, "unexpected del event");

	rz_list_free(tracker.expect);
	mu_end;
}

bool test_rz_bin_sections_mapping(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/ioli/crackme0x00", &opt);
	mu_assert_notnull(bf, "crackme0x00 binary could not be opened");
	mu_assert_notnull(bf->o, "bin object");
	mu_assert_streq(bf->file, "bins/elf/ioli/crackme0x00", "filename should be right");

	RzBinObject *o = bf->o;
	RzVector *maps = rz_bin_object_sections_mapping_list(o);
	mu_assert_eq(rz_vector_len(maps), 10, "there should be 10 maps, because 10 are the segments");

	RzBinSectionMap *map0 = rz_vector_index_ptr(maps, 0);
	mu_assert_streq(map0->segment->name, "PHDR", "first map is for PHDR");
	mu_assert_eq(rz_pvector_len(&map0->sections), 0, "no sections in PHDR");
	RzBinSectionMap *map1 = rz_vector_index_ptr(maps, 1);
	mu_assert_streq(map1->segment->name, "INTERP", "second map is for INTERP");
	mu_assert_eq(rz_pvector_len(&map1->sections), 1, "just .interp in INTERP");
	RzBinSection *sec1_0 = rz_pvector_at(&map1->sections, 0);
	mu_assert_streq(sec1_0->name, ".interp", "section is .interp");
	RzBinSectionMap *map7 = rz_vector_index_ptr(maps, 7);
	mu_assert_streq(map7->segment->name, "GNU_RELRO", "seventh map is for GNURELRO");
	mu_assert_eq(rz_pvector_len(&map7->sections), 5, "5 elements in GNURELRO");
	RzBinSection *sec7_0 = rz_pvector_at(&map7->sections, 0);
	mu_assert_streq(sec7_0->name, ".ctors", "section is .ctors");
	RzBinSection *sec7_1 = rz_pvector_at(&map7->sections, 1);
	mu_assert_streq(sec7_1->name, ".dtors", "section is .dtors");

	rz_vector_free(maps);

	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_rz_bin_p2v2p(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/ls", &opt);
	mu_assert_notnull(bf, "ls binary could not be opened");

	RzBinObject *o = bf->o;
	mu_assert_eq(rz_bin_object_p2v(o, 0x0001c0f8), 0x0001c0f8, "xstrtoumax string p2v");
	mu_assert_eq(rz_bin_object_v2p(o, 0x0001c0f8), 0x0001c0f8, "xstrtoumax string v2p");
	mu_assert_eq(rz_bin_object_p2v(o, 0x00021260), 0x00022260, "obstack_alloc_failed_handler symbol p2v");
	mu_assert_eq(rz_bin_object_v2p(o, 0x00022260), 0x00021260, "obstack_alloc_failed_handler symbol v2p");

	mu_assert_eq(rz_bin_object_v2p(o, 0xcafebabe), UT64_MAX, "non existing vaddr");
	mu_assert_eq(rz_bin_object_p2v(o, 0xcafebabe), UT64_MAX, "non existing paddr");

	RzVector *v = rz_bin_object_p2v_all(o, 0xcafebabe);
	mu_assert_eq(rz_vector_len(v), 0, "non existing paddr should have 0 elements in vector");
	rz_vector_free(v);

	v = rz_bin_object_p2v_all(o, 0x21260);
	mu_assert_eq(rz_vector_len(v), 1, "p2v_all of obstack_alloc_failed_handler paddr should have 1 element");
	mu_assert_eq(*(ut64 *)rz_vector_head(v), 0x22260, "obstack_alloc_failed_handler symbol p2v_all");
	rz_vector_free(v);

	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_bin);
	mu_run_test(test_rz_bin_reloc_storage);
	mu_run_test(test_rz_bin_file_delete);
	mu_run_test(test_rz_bin_file_delete_all);
	mu_run_test(test_rz_bin_sections_mapping);
	mu_run_test(test_rz_bin_p2v2p);
	return tests_passed != tests_run;
}

mu_main(all_tests)
