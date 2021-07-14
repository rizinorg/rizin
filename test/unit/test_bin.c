// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"
#include <rz_bin.h>

bool test_rz_bin(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/ioli/crackme0x00", &opt);
	mu_assert_notnull(bf, "crackme0x00 binary could not be opened");
	mu_assert_notnull(bf->o, "bin object");

	RzBinObject *obj = rz_bin_cur_object(bin);

	RzList *sections = rz_bin_object_get_sections(obj);
	mu_assert_eq(rz_list_length(sections), 29, "rz_bin_object_get_sections");
	rz_list_free(sections);

	RzList *segments = rz_bin_object_get_segments(obj);
	mu_assert_eq(rz_list_length(segments), 10, "rz_bin_object_get_segments");
	rz_list_free(segments);

	const RzList *entries = rz_bin_object_get_entries(obj);
	mu_assert_eq(rz_list_length(entries), 1, "rz_bin_object_get_entries");
	RzBinAddr *entry = rz_list_first(entries);
	mu_assert_eq(entry->vaddr, 0x8048360, "entry virtual address");
	mu_assert_eq(entry->paddr, 0x360, "entry file offset");

	const RzList *imports = rz_bin_object_get_imports(obj);
	mu_assert_eq(rz_list_length(imports), 5, "rz_bin_object_get_imports");
	const char *import_names[] = {"__libc_start_main", "printf", "scanf", "strcmp", "__gmon_start__"};
	bool has_import_names[] = {0};
	RzBinImport *import;
	RzListIter *it;
	rz_list_foreach(imports, it, import) {
		for(int i = 0; i < RZ_ARRAY_SIZE(import_names); ++i) {
			if (!strcmp(import->name, import_names[i])) {
				has_import_names[i] = true;
				break;
			}
		}
	}
	for(int i = 0; i < RZ_ARRAY_SIZE(import_names); ++i) {
		mu_assert_true(has_import_names[i], "Import name was not found");
	}

	const RzList *strings = rz_bin_object_get_strings(obj);
	mu_assert_eq(rz_list_length(strings), 5, "rz_bin_object_get_strings");
	const char *exp_strings[] = {
		"IOLI Crackme Level 0x00\\n",
		"Password: ",
		// "%s", // This is not automatically recognized because too short
		"250382",
		"Invalid Password!\\n",
		"Password OK :)\\n",
	};
	RzBinString *s;
	int i = 0;
	rz_list_foreach(strings, it, s) {
		mu_assert_streq(s->string, exp_strings[i], "String not found");
		mu_assert_true(rz_bin_object_is_string(obj, s->vaddr), "is_string should be true");
		i++;
	}

	const RzList *hashes = rz_bin_file_compute_hashes(bin, bf, UT64_MAX);
	mu_assert_eq(rz_list_length(hashes), 3, "rz_bin_file_get_hashes");
	const char *hash_names[] = {"md5", "sha1", "sha256"};
	const char *hash_hexes[] = {"99327411dd72a11d7198b54298648adf", "f2bf1c7758c7b1e22bdea1d7681882783b658705", "3aed9a3821134a2ab1d69cb455e5e9d80bb651a1c97af04cdba4f3bb0adaa37b"};
	RzBinFileHash *hash;
	i = 0;
	rz_list_foreach(hashes, it, hash) {
		mu_assert_streq(hash->type, hash_names[i], "hash name is wrong");
		mu_assert_streq(hash->hex, hash_hexes[i], "hash digest is wrong");
		i++;
	}

	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

static RzBinReloc *add_reloc(RzList *l, ut64 paddr, ut64 vaddr, ut64 target_vaddr) {
	RzBinReloc *reloc = RZ_NEW0(RzBinReloc);
	reloc->type = RZ_BIN_RELOC_8;
	reloc->paddr = paddr;
	reloc->vaddr = vaddr;
	reloc->target_vaddr = target_vaddr;
	rz_list_push(l, reloc);
	return reloc;
}

bool test_rz_bin_reloc_storage(void) {
	RzList *l = rz_list_new();
	RzBinReloc *r0 = add_reloc(l, 0x108, 0x1000, 0x2004);
	mu_assert_notnull(r0, "reloc");
	RzBinReloc *r1 = add_reloc(l, 0x2002, 0x1003, 0x2008);
	mu_assert_notnull(r1, "reloc");
	RzBinReloc *rz = add_reloc(l, 0x1001, 0x1004, UT64_MAX);
	mu_assert_notnull(rz, "reloc");
	RzBinReloc *r3 = add_reloc(l, 0x1003, 0x1006, 0x200c);
	mu_assert_notnull(r3, "reloc");
	RzBinRelocStorage *relocs = rz_bin_reloc_storage_new(l);

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

bool all_tests() {
	mu_run_test(test_rz_bin);
	mu_run_test(test_rz_bin_reloc_storage);
	mu_run_test(test_rz_bin_file_delete);
	mu_run_test(test_rz_bin_file_delete_all);
	return tests_passed != tests_run;
}

mu_main(all_tests)
