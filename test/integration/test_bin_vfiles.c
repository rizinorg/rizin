// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>

#include "../unit/minunit.h"

/// Test using RzBin without RzCore and extract some data from a vfiile
bool test_bin_vfiles() {
	// 1. Open the file as RzBuffer
	RzBuffer *buf = rz_buf_new_file("bins/elf/ls", O_RDONLY, 0644);
	mu_assert_notnull(buf, "open file");

	// 2. Load the buffer into RzBin
	RzBin *bin = rz_bin_new();
	RzBinOptions opts = { 0 };
	opts.filename = "<internal>";
	opts.obj_opts.patch_relocs = true;
	RzBinFile *bf = rz_bin_open_buf(bin, buf, &opts);
	mu_assert_notnull(bf, "load bin file");

	// 2. Extract the reloc-patched buffer
	mu_assert_notnull(bf->o, "object");
	mu_assert_notnull(bf->o->vfiles, "vfiles");
	RzBinVirtualFile *patched = rz_bin_object_get_virtual_file(bf->o, "patched");
	mu_assert_notnull(patched, "patched vfile");

	// 3. Find an interesting reloc by an import name
	mu_assert_notnull(bf->o->relocs, "relocs");
	RzBinReloc *reloc = NULL;
	for (size_t i = 0; i < bf->o->relocs->relocs_count; i++) {
		RzBinReloc *r = bf->o->relocs->relocs[i];
		if (!r->import) {
			continue;
		}
		if (!strcmp(r->import->name, "isatty")) {
			reloc = r;
			break;
		}
	}
	mu_assert_notnull(reloc, "found reloc by name");
	mu_assert_eq(reloc->paddr, 0x00020ce8, "reloc paddr");
	mu_assert_eq(reloc->vaddr, 0x00021ce8, "reloc vaddr");
	mu_assert_neq(reloc->target_vaddr, 0, "target not 0");
	mu_assert_neq(reloc->target_vaddr, UT64_MAX, "target not UT64_MAX");

	// 4. Check the contents of the original buf and the vfile against the data in the reloc
	ut64 val = 1;
	mu_assert_true(rz_buf_read_le64_at(buf, reloc->paddr, &val), "failed to read");

	mu_assert_eq(val, 0, "original buf has nothing patched");
	mu_assert_true(rz_buf_read_le64_at(patched->buf, reloc->paddr, &val), "failed to read");
	mu_assert_eq(val, reloc->target_vaddr, "read patched target from vfile");

	// 5. Exit
	rz_bin_free(bin);
	rz_buf_free(buf);
	mu_end;
}

int all_tests() {
	mu_run_test(test_bin_vfiles);
	return tests_passed != tests_run;
}

mu_main(all_tests)
