// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "minunit.h"

// --------------------------

static bool check_buffer(RzBuffer *b) {
	// match everything
	return true;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return true;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup(bf->file);
	ret->has_va = 1;
	return ret;
}

static RzList *maps(RzBinFile *bf) {
	RzList *ret = rz_list_newf((RzListFree)rz_bin_map_free);

	RzBinMap *map = RZ_NEW0(RzBinMap);
	map->name = strdup("direct map");
	map->paddr = 2;
	map->vaddr = 0x100;
	map->psize = 2;
	map->vsize = 2;
	map->perm = RZ_PERM_RX;
	rz_list_push(ret, map);

	map = RZ_NEW0(RzBinMap);
	map->name = strdup("direct map with zeroes");
	map->paddr = 2;
	map->vaddr = 0x200;
	map->psize = 2;
	map->vsize = 0x30;
	map->perm = RZ_PERM_R;
	rz_list_push(ret, map);

	return ret;
}

RzBinPlugin mock_plugin = {
	.name = "mock",
	.desc = "Testing Plugin",
	.license = "LGPL3",
	.load_buffer = load_buffer,
	.check_buffer = check_buffer,
	.maps = maps,
	.info = info,
};

// --------------------------

bool test_map(void) {
	RzCore *core = rz_core_new();
	rz_bin_plugin_add(core->bin, &mock_plugin);
	RzCoreFile *f = rz_core_file_open(core, "hex://424213374242", RZ_PERM_R, 0);
	mu_assert_notnull(f, "load core file");
	bool r = rz_core_bin_load(core, NULL, 0);
	mu_assert_true(r, "core bin load");
	RzBinFile *bf = rz_bin_file_find_by_fd(core->bin, f->fd);
	mu_assert_notnull(bf, "binfile");
	mu_assert_streq(bf->o->plugin->name, "mock", "binfile with mock plugin");

	mu_assert_eq(rz_pvector_len(&core->io->maps), 3, "io maps count");
	RzIOMap *map = rz_pvector_at(&core->io->maps, 0);
	mu_assert_streq(map->name, "mmap.direct map with zeroes", "io map name");
	mu_assert_eq(map->delta, 0, "map delta");
	mu_assert_eq(map->itv.addr, 0x202, "map addr");
	mu_assert_eq(map->itv.size, 0x2e, "map size");
	mu_assert_eq(map->perm, RZ_PERM_R, "io map perm");
	map = rz_pvector_at(&core->io->maps, 1);
	mu_assert_streq(map->name, "fmap.direct map with zeroes", "io map name");
	mu_assert_eq(map->delta, 2, "map delta");
	mu_assert_eq(map->itv.addr, 0x200, "map addr");
	mu_assert_eq(map->itv.size, 2, "map size");
	mu_assert_eq(map->perm, RZ_PERM_R, "io map perm");
	map = rz_pvector_at(&core->io->maps, 2);
	mu_assert_streq(map->name, "fmap.direct map", "io map name");
	mu_assert_eq(map->delta, 2, "map delta");
	mu_assert_eq(map->itv.addr, 0x100, "map addr");
	mu_assert_eq(map->itv.size, 2, "map size");
	mu_assert_eq(map->perm, RZ_PERM_RX, "io map perm");

	ut8 buf[8];
	r = rz_io_read_at(core->io, 0, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xff\xff\xff\xff\xff\xff", 8, "unmapped read");
	r = rz_io_read_at(core->io, 0xfe, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\x13\x37\xff\xff\xff\xff", 8, "direct map read");
	r = rz_io_read_at(core->io, 0x1fe, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\x13\x37\x00\x00\x00\x00", 8, "direct map read with zeroes");
	r = rz_io_read_at(core->io, 0x22e, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\x00\x00\xff\xff\xff\xff\xff\xff", 8, "direct map read with zeroes end");

	rz_core_free(core);
	mu_end;
}

bool test_map_close(void) {
	RzCore *core = rz_core_new();
	rz_bin_plugin_add(core->bin, &mock_plugin);
	RzCoreFile *f = rz_core_file_open(core, "hex://424213374242", RZ_PERM_R, 0);
	mu_assert_notnull(f, "load core file");
	bool r = rz_core_bin_load(core, NULL, 0);
	mu_assert_true(r, "core bin load");
	RzBinFile *bf = rz_bin_file_find_by_fd(core->bin, f->fd);
	mu_assert_notnull(bf, "binfile");
	mu_assert_streq(bf->o->plugin->name, "mock", "binfile with mock plugin");

	mu_assert_eq(rz_pvector_len(&core->io->maps), 3, "io maps count");
	rz_core_file_close(core, f);

	// TODO: this is broken
#if 0
	mu_assert_eq(rz_pvector_len(&core->io->maps), 0, "io maps count");
#endif

	// TODO: test reading, etc

	rz_core_free(core);
	mu_end;
}

// TODO: test closing one file, keeping another one open
// TODO: test closing one file, keeping custom user-mappings open

bool all_tests() {
	mu_run_test(test_map);
	mu_run_test(test_map_close);
	return tests_passed != tests_run;
}

mu_main(all_tests)
