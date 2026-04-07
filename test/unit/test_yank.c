// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "minunit.h"

static RzCore *fake_core_new(void) {
	RzCore *core = rz_core_new();
	RzCoreFile *file = rz_core_file_open(core, "malloc://1024", RZ_PERM_RW, 0);
	mu_assert_notnull(file, "open file");

	rz_core_bin_load(core, NULL, 0);
	// the default arch depends by the RZ_SYS_ARCH, and
	// some archs allows different endianness, like ARM, but
	// x86 is always LE, s390x is always BE, so we cannot set
	// the endianness to a value not supported by the arch.
	// ARM can be LE and BE, so we change the arch first
	// then change the endianness.
	rz_config_set(core->config, "asm.arch", "arm");
	rz_config_set_b(core->config, "cfg.bigendian", false);
	return core;
}

bool test_yank(void) {
	RzCore *core = fake_core_new();
	bool r = rz_core_write_value_at(core, 0, 0x11223344, 4);
	mu_assert_true(r, "value should be written at 0");
	mu_assert_memeq(core->block, (const ut8 *)"\x44\x33\x22\x11", 4, "original bytes should be right at address 0");
	r = rz_core_yank(core, 0, 4);
	mu_assert_true(r, "4 bytes should be yanked from 0");
	r = rz_core_seek(core, 4, true);
	mu_assert_true(r, "seek should be moved to 4");
	r = rz_core_yank_paste(core, 4, 4);
	mu_assert_true(r, "clipboard content should be pasted at address 4");
	r = rz_core_block_read(core) > 0;
	mu_assert_true(r, "more than 0 bytes should be read at address 4");
	mu_assert_memeq(core->block, (const ut8 *)"\x44\x33\x22\x11", 4, "yanked bytes should be pasted at address 4");
	rz_core_free(core);
	mu_end;
}

bool test_yank_string(void) {
	RzCore *core = fake_core_new();
	bool r = rz_core_write_string_at(core, 0, "Hello World");
	mu_assert_true(r, "string should be written at 0");
	r = rz_core_yank_string(core, 0, 0);
	mu_assert_true(r, "string should be yanked from address 0");
	r = rz_core_seek(core, 4, true);
	mu_assert_true(r, "seek should be moved to 4");
	r = rz_core_yank_paste(core, 4, 0);
	mu_assert_true(r, "clipboard string should be pasted at address 4");
	r = rz_core_block_read(core) > 0;
	mu_assert_true(r, "more than 0 bytes should be read at address 4");
	mu_assert_streq((const char *)core->block, "Hello World", "yanked bytes should be pasted at address 4");
	rz_core_seek(core, 0, true);
	mu_assert_streq((const char *)core->block, "HellHello World", "yanked bytes should be pasted at address 4, original content there");
	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_yank);
	mu_run_test(test_yank_string);
	return tests_passed != tests_run;
}

mu_main(all_tests)
