// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "analysis_private.h"
#include "minunit.h"

// --------------------------

static bool check_buffer(RzBuffer *b) {
	// match everything
	return true;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
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

static RzPVector *virtual_files(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);

	RzBinVirtualFile *vfile = RZ_NEW0(RzBinVirtualFile);
	vfile->name = strdup("vfile0");
	vfile->buf = rz_buf_new_with_bytes((const ut8 *)"\xc0\xff\xee", 3);
	vfile->buf_owned = true;
	rz_pvector_push(ret, vfile);

	vfile = RZ_NEW0(RzBinVirtualFile);
	vfile->name = strdup("vfile1");
	vfile->buf = rz_buf_new_with_bytes((const ut8 *)"rizin123", 8);
	vfile->buf_owned = true;
	rz_pvector_push(ret, vfile);

	return ret;
}

static RzPVector *maps(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);

	RzBinMap *map = RZ_NEW0(RzBinMap);
	map->name = strdup("direct map");
	map->paddr = 2;
	map->vaddr = 0x100;
	map->psize = 2;
	map->vsize = 2;
	map->perm = RZ_PERM_RX;
	rz_pvector_push(ret, map);

	map = RZ_NEW0(RzBinMap);
	map->name = strdup("direct map with zeroes");
	map->paddr = 2;
	map->vaddr = 0x200;
	map->psize = 2;
	map->vsize = 0x30;
	map->perm = RZ_PERM_R;
	rz_pvector_push(ret, map);

	map = RZ_NEW0(RzBinMap);
	map->name = strdup("vfile map");
	map->paddr = 4;
	map->vaddr = 0x300;
	map->psize = 4;
	map->vsize = 4;
	map->perm = RZ_PERM_RWX;
	map->vfile_name = strdup("vfile1");
	rz_pvector_push(ret, map);

	map = RZ_NEW0(RzBinMap);
	map->name = strdup("vfile map with zeroes");
	map->paddr = 0;
	map->vaddr = 0x400;
	map->psize = 3;
	map->vsize = 4;
	map->perm = RZ_PERM_R;
	map->vfile_name = strdup("vfile0");
	rz_pvector_push(ret, map);

	return ret;
}

RzBinPlugin mock_plugin = {
	.name = "mock",
	.desc = "Testing Plugin",
	.license = "LGPL3",
	.load_buffer = load_buffer,
	.check_buffer = check_buffer,
	.virtual_files = &virtual_files,
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

	mu_assert_eq(rz_pvector_len(&core->io->maps), 6, "io maps count");
	RzIOMap *map = rz_pvector_at(&core->io->maps, 4);
	mu_assert_streq(map->name, "mmap.vfile map with zeroes", "io map name");
	mu_assert_eq(map->delta, 0, "map delta");
	mu_assert_eq(map->itv.addr, 0x403, "map addr");
	mu_assert_eq(map->itv.size, 1, "map size");
	mu_assert_eq(map->perm, RZ_PERM_R, "io map perm");
	RzCoreIOMapInfo *info = map->user;
	mu_assert_notnull(info, "map info");
	mu_assert_ptreq(info->cf, f, "map info corefile");
	mu_assert_eq(info->perm_orig, RZ_PERM_R, "map info perm");

	map = rz_pvector_at(&core->io->maps, 5);
	mu_assert_streq(map->name, "vmap.vfile map with zeroes", "io map name");
	mu_assert_eq(map->delta, 0, "map delta");
	mu_assert_eq(map->itv.addr, 0x400, "map addr");
	mu_assert_eq(map->itv.size, 3, "map size");
	mu_assert_eq(map->perm, RZ_PERM_R, "io map perm");

	map = rz_pvector_at(&core->io->maps, 3);
	mu_assert_streq(map->name, "vmap.vfile map", "io map name");
	mu_assert_eq(map->delta, 4, "map delta");
	mu_assert_eq(map->itv.addr, 0x300, "map addr");
	mu_assert_eq(map->itv.size, 4, "map size");
	mu_assert_eq(map->perm, RZ_PERM_RWX, "io map perm");
	info = map->user;
	mu_assert_notnull(info, "map info");
	mu_assert_ptreq(info->cf, f, "map info corefile");
	mu_assert_eq(info->perm_orig, RZ_PERM_RWX, "map info perm");

	map = rz_pvector_at(&core->io->maps, 1);
	mu_assert_streq(map->name, "mmap.direct map with zeroes", "io map name");
	mu_assert_eq(map->delta, 0, "map delta");
	mu_assert_eq(map->itv.addr, 0x202, "map addr");
	mu_assert_eq(map->itv.size, 0x2e, "map size");
	mu_assert_eq(map->perm, RZ_PERM_R, "io map perm");
	info = map->user;
	mu_assert_notnull(info, "map info");
	mu_assert_ptreq(info->cf, f, "map info corefile");
	mu_assert_eq(info->perm_orig, RZ_PERM_R, "map info perm");

	map = rz_pvector_at(&core->io->maps, 2);
	mu_assert_streq(map->name, "fmap.direct map with zeroes", "io map name");
	mu_assert_eq(map->delta, 2, "map delta");
	mu_assert_eq(map->itv.addr, 0x200, "map addr");
	mu_assert_eq(map->itv.size, 2, "map size");
	mu_assert_eq(map->perm, RZ_PERM_R, "io map perm");

	map = rz_pvector_at(&core->io->maps, 0);
	mu_assert_streq(map->name, "fmap.direct map", "io map name");
	mu_assert_eq(map->delta, 2, "map delta");
	mu_assert_eq(map->itv.addr, 0x100, "map addr");
	mu_assert_eq(map->itv.size, 2, "map size");
	mu_assert_eq(map->perm, RZ_PERM_RX, "io map perm");
	info = map->user;
	mu_assert_notnull(info, "map info");
	mu_assert_ptreq(info->cf, f, "map info corefile");
	mu_assert_eq(info->perm_orig, RZ_PERM_RX, "map info perm");

	ut8 buf[8];
	r = rz_io_read_at_mapped(core->io, 0, buf, sizeof(buf));
	mu_assert_false(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xff\xff\xff\xff\xff\xff", 8, "unmapped read");
	r = rz_io_read_at_mapped(core->io, 0xfe, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\x13\x37\xff\xff\xff\xff", 8, "direct map read");
	r = rz_io_read_at_mapped(core->io, 0x1fe, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\x13\x37\x00\x00\x00\x00", 8, "direct map read with zeroes");
	r = rz_io_read_at_mapped(core->io, 0x22e, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\x00\x00\xff\xff\xff\xff\xff\xff", 8, "direct map read with zeroes end");

	r = rz_io_read_at_mapped(core->io, 0x2fe, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xffn123\xff\xff", 8, "virtual file read");
	r = rz_io_read_at_mapped(core->io, 0x3fe, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xc0\xff\xee\x00\xff\xff", 8, "virtual file read");

	// first vfile mapped as readonly at 0x400, write should fail and change nothing
	RzBinVirtualFile *vf = rz_pvector_at(bf->o->vfiles, 0);
	ut8 red = rz_buf_read_at(vf->buf, 0, buf, 3);
	mu_assert_eq(red, 3, "pre-sanity check buf read size");
	mu_assert_memeq(buf, (const ut8 *)"\xc0\xff\xee", 3, "pre-sanity check buf contents");
	r = rz_io_write_at(core->io, 0x400, (const ut8 *)"zir", 3);
	mu_assert_false(r, "io write");
	r = rz_io_read_at_mapped(core->io, 0x3fe, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xc0\xff\xee\x00\xff\xff", 8, "virtual file read");
	red = rz_buf_read_at(vf->buf, 0, buf, 3);
	mu_assert_eq(red, 3, "buf read size");
	mu_assert_memeq(buf, (const ut8 *)"\xc0\xff\xee", 3, "nothing changed in buf");

	// second vfile mapped as rw at 0x300, write should succeed and change the buffer
	vf = rz_pvector_at(bf->o->vfiles, 1);
	red = rz_buf_read_at(vf->buf, 0, buf, 8);
	mu_assert_eq(red, 8, "pre-sanity check buf read size");
	mu_assert_memeq(buf, (const ut8 *)"rizin123", 8, "pre-sanity check buf contents");
	r = rz_io_write_at(core->io, 0x301, (const ut8 *)"izi", 3);
	mu_assert_true(r, "io write");
	r = rz_io_read_at_mapped(core->io, 0x2fe, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xffnizi\xff\xff", 8, "virtual file read");
	red = rz_buf_read_at(vf->buf, 0, buf, 8);
	mu_assert_eq(red, 8, "buf read size");
	mu_assert_memeq(buf, (const ut8 *)"rizinizi", 8, "buf written");

	rz_core_free(core);
	mu_end;
}

/// test behavior after closing a single RzCoreFile
bool test_cfile_close(void) {
	RzCore *core = rz_core_new();
	rz_bin_plugin_add(core->bin, &mock_plugin);
	RzCoreFile *f = rz_core_file_open(core, "hex://424213374242", RZ_PERM_R, 0);
	mu_assert_notnull(f, "load core file");
	mu_assert_ptreq(core->file, f, "current file");
	mu_assert_eq(rz_list_length(core->bin->binfiles), 0, "no binfiles");
	bool r = rz_core_bin_load(core, NULL, 0);
	mu_assert_true(r, "core bin load");
	mu_assert_eq(rz_list_length(core->bin->binfiles), 1, "binfile loaded");
	RzBinFile *bf = rz_bin_file_find_by_fd(core->bin, f->fd);
	mu_assert_notnull(bf, "binfile");
	mu_assert_streq(bf->o->plugin->name, "mock", "binfile with mock plugin");

	mu_assert_ptreq(core->file, f, "current file");
	mu_assert_eq(rz_pvector_len(&core->io->maps), 6, "io maps count");
	rz_core_file_close(f);
	mu_assert_null(core->file, "closed current file");
	mu_assert_eq(rz_list_length(core->bin->binfiles), 0, "binfile deleted");

	// all maps related to the file, including zero-mmaps, should be closed
	mu_assert_eq(rz_pvector_len(&core->io->maps), 0, "io maps count");

	RzList *descs = rz_id_storage_list(core->io->files);
	mu_assert_true(rz_list_empty(descs), "no files left");
	rz_list_free(descs);

	ut8 buf[8];
	r = rz_io_read_at_mapped(core->io, 0xfe, buf, sizeof(buf));
	mu_assert_false(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xff\xff\xff\xff\xff\xff", 8, "direct map read after close");
	r = rz_io_read_at_mapped(core->io, 0x22e, buf, sizeof(buf));
	mu_assert_false(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xff\xff\xff\xff\xff\xff", 8, "direct map read with zeroes end after close");

	rz_core_free(core);
	mu_end;
}

/// test behavior after closing an RzCoreFile when another one is present at the same time
bool test_cfile_close_multiple(void) {
	RzCore *core = rz_core_new();
	rz_bin_plugin_add(core->bin, &mock_plugin);

	RzCoreFile *f0 = rz_core_file_open(core, "hex://424213374242", RZ_PERM_R, 0);
	mu_assert_notnull(f0, "load core file");
	mu_assert_ptreq(core->file, f0, "current file");
	mu_assert_eq(rz_list_length(core->bin->binfiles), 0, "no binfiles");
	bool r = rz_core_bin_load(core, NULL, 0);
	mu_assert_true(r, "core bin load");
	mu_assert_eq(rz_list_length(core->bin->binfiles), 1, "binfile loaded");

	RzCoreFile *f1 = rz_core_file_open(core, "hex://c0ffeec0ffee", RZ_PERM_R, 0);
	mu_assert_notnull(f1, "load another core file");
	mu_assert_ptreq(core->file, f1, "current file");
	r = rz_core_bin_load(core, NULL, 0);
	mu_assert_true(r, "core bin load");
	mu_assert_eq(rz_list_length(core->bin->binfiles), 2, "binfile loaded");
	RzBinFile *bf1 = rz_bin_file_find_by_fd(core->bin, f1->fd);
	mu_assert_notnull(bf1, "binfile");

	mu_assert_ptreq(core->file, f1, "current file");
	mu_assert_eq(rz_list_length(core->files), 2, "core files count");
	mu_assert_eq(rz_list_length(core->bin->binfiles), 2, "bin files count");
	mu_assert_eq(rz_pvector_len(&core->io->maps), 12, "io maps count");

	rz_core_file_close(f0);
	mu_assert_ptreq(core->file, f1, "closed non-current file");
	mu_assert_eq(rz_pvector_len(&f1->extra_files), 4, "other file still has its extra file refs");
	mu_assert_eq(rz_list_length(core->bin->binfiles), 1, "binfile loaded");
	mu_assert_true(rz_list_contains(core->bin->binfiles, bf1), "other binfile still there");

	// all maps related to the file, including zero-mmaps, should be closed
	mu_assert_eq(rz_pvector_len(&core->io->maps), 6, "io maps count");
	RzList *descs = rz_id_storage_list(core->io->files);
	mu_assert_eq(rz_list_length(descs), 5, "files left");
	mu_assert_eq(rz_pvector_len(&f1->extra_files), 4, "remaining core file files");

	// f1 should still be alive and happy
	RzIODesc *desc = rz_io_desc_get(core->io, f1->fd);
	mu_assert_true(rz_list_contains(descs, desc), "remaining main file");
	mu_assert_true(rz_list_contains(descs, rz_pvector_at(&f1->extra_files, 0)), "remaining extra file");
	mu_assert_true(rz_list_contains(descs, rz_pvector_at(&f1->extra_files, 1)), "remaining extra file");
	mu_assert_true(rz_list_contains(descs, rz_pvector_at(&f1->extra_files, 2)), "remaining extra file");
	mu_assert_true(rz_list_contains(descs, rz_pvector_at(&f1->extra_files, 3)), "remaining extra file");
	rz_list_free(descs);

	ut8 buf[8];
	r = rz_io_read_at_mapped(core->io, 0xfe, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xee\xc0\xff\xff\xff\xff", 8, "direct map read");
	r = rz_io_read_at_mapped(core->io, 0x22e, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\x00\x00\xff\xff\xff\xff\xff\xff", 8, "direct map read with zeroes end");

	r = rz_io_read_at_mapped(core->io, 0x2fe, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xffn123\xff\xff", 8, "virtual file read");
	r = rz_io_read_at_mapped(core->io, 0x3fe, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xc0\xff\xee\x00\xff\xff", 8, "virtual file read");

	rz_core_free(core);
	mu_end;
}

/// test behavior after closing an RzCoreFile when the underlying mappings have been changed manually
bool test_cfile_close_manual_maps(void) {
	RzCore *core = rz_core_new();
	rz_bin_plugin_add(core->bin, &mock_plugin);
	RzCoreFile *f = rz_core_file_open(core, "hex://424213374242", RZ_PERM_R, 0);
	mu_assert_notnull(f, "load core file");
	mu_assert_ptreq(core->file, f, "current file");
	bool r = rz_core_bin_load(core, NULL, 0);
	mu_assert_true(r, "core bin load");
	RzBinFile *bf = rz_bin_file_find_by_fd(core->bin, f->fd);
	mu_assert_notnull(bf, "binfile");
	mu_assert_streq(bf->o->plugin->name, "mock", "binfile with mock plugin");

	mu_assert_ptreq(core->file, f, "current file");
	mu_assert_eq(rz_pvector_len(&core->io->maps), 6, "io maps count");

	RzIOMap *map0 = rz_io_map_get(core->io, 0x100);
	mu_assert_streq(map0->name, "fmap.direct map", "io map name");
	mu_assert_eq(map0->delta, 2, "map delta");
	mu_assert_eq(map0->itv.addr, 0x100, "map addr");
	mu_assert_eq(map0->itv.size, 2, "map size");
	mu_assert_eq(map0->perm, RZ_PERM_RX, "io map perm");

	RzIOMap *map1 = rz_io_map_get(core->io, 0x200);
	mu_assert_streq(map1->name, "fmap.direct map with zeroes", "io map name");
	mu_assert_eq(map1->delta, 2, "map delta");
	mu_assert_eq(map1->itv.addr, 0x200, "map addr");
	mu_assert_eq(map1->itv.size, 2, "map size");
	mu_assert_eq(map1->perm, RZ_PERM_R, "io map perm");

	RzIOMap *map2 = rz_io_map_get(core->io, 0x202);
	mu_assert_streq(map2->name, "mmap.direct map with zeroes", "io map name");
	mu_assert_eq(map2->delta, 0, "map delta");
	mu_assert_eq(map2->itv.addr, 0x202, "map addr");
	mu_assert_eq(map2->itv.size, 0x2e, "map size");
	mu_assert_eq(map2->perm, RZ_PERM_R, "io map perm");

	mu_assert_eq(rz_pvector_len(&f->extra_files), 4, "tracked extra file for mmaps and vfiles");
	mu_assert_eq(rz_pvector_len(&f->maps), 6, "tracked maps count");
	mu_assert_true(rz_pvector_contains(&f->maps, map0), "core file ref to map");
	mu_assert_true(rz_pvector_contains(&f->maps, map1), "core file ref to map");
	mu_assert_true(rz_pvector_contains(&f->maps, map2), "core file ref to map");

	// manually delete some of the maps
	rz_io_map_del(core->io, map1->id);
	mu_assert_eq(rz_pvector_len(&f->extra_files), 4, "tracked extra file for mmaps and vfiles");
	mu_assert_eq(rz_pvector_len(&f->maps), 5, "tracked maps count");
	mu_assert_true(rz_pvector_contains(&f->maps, map0), "core file ref to map");
	mu_assert_true(rz_pvector_contains(&f->maps, map2), "core file ref to map");
	rz_io_map_del(core->io, map2->id);
	mu_assert_eq(rz_pvector_len(&f->extra_files), 4, "tracked extra file for mmaps and vfiles");
	mu_assert_eq(rz_pvector_len(&f->maps), 4, "tracked maps count");
	mu_assert_true(rz_pvector_contains(&f->maps, map0), "core file ref to map");
	// and add a new one, unrelated to the core file
	RzIOMap *map3;
	RzIODesc *mdesc = rz_io_open_at(core->io, "hex://c0ffee", 0644, RZ_PERM_R, 0x8000, &map3);
	mu_assert_notnull(mdesc, "manual io file");
	mu_assert_eq(map3->itv.addr, 0x8000, "manual map addr");
	mu_assert_eq(rz_pvector_len(&core->io->maps), 5, "io maps count");

	rz_core_file_close(f);
	mu_assert_null(core->file, "closed current file");

	// all maps related to the file, including zero-mmaps, should be closed, but not the ones we created manually
	mu_assert_eq(rz_pvector_len(&core->io->maps), 1, "io maps count");
	mu_assert_ptreq(rz_pvector_at(&core->io->maps, 0), map3, "remaining manual map");

	ut8 buf[8];
	r = rz_io_read_at_mapped(core->io, 0x8000, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xc0\xff\xee\xff\xff\xff\xff\xff", 8, "untouched manual map");

	rz_core_free(core);
	mu_end;
}

/// test behavior after closing an RzCoreFile when the underlying fd has been closed manually
bool test_cfile_close_manual_fd(void) {
	RzCore *core = rz_core_new();
	rz_bin_plugin_add(core->bin, &mock_plugin);
	RzCoreFile *f = rz_core_file_open(core, "hex://424213374242", RZ_PERM_R, 0);
	mu_assert_notnull(f, "load core file");
	mu_assert_ptreq(core->file, f, "current file");
	bool r = rz_core_bin_load(core, NULL, 0);
	mu_assert_true(r, "core bin load");
	RzBinFile *bf = rz_bin_file_find_by_fd(core->bin, f->fd);
	mu_assert_notnull(bf, "binfile");
	mu_assert_streq(bf->o->plugin->name, "mock", "binfile with mock plugin");

	mu_assert_ptreq(core->file, f, "current file");
	mu_assert_eq(rz_pvector_len(&core->io->maps), 6, "io maps count");

	// manually close the low-level io fd
	rz_io_fd_close(core->io, f->fd);
	// io behavior: all maps directly from the fd are automatically closed with it
	// The zero-mmapped one stays because core is the one who tracks it
	mu_assert_eq(rz_pvector_len(&core->io->maps), 4, "io maps count");
	RzIOMap *map = rz_io_map_get(core->io, 0x202);
	mu_assert_streq(map->name, "mmap.direct map with zeroes", "io map name");
	mu_assert_eq(map->delta, 0, "map delta");
	mu_assert_eq(map->itv.addr, 0x202, "map addr");
	mu_assert_eq(map->itv.size, 0x2e, "map size");
	mu_assert_eq(map->perm, RZ_PERM_R, "io map perm");
	map = rz_io_map_get(core->io, 0x403);
	mu_assert_streq(map->name, "mmap.vfile map with zeroes", "io map name");
	mu_assert_eq(map->delta, 0, "map delta");
	mu_assert_eq(map->itv.addr, 0x403, "map addr");
	mu_assert_eq(map->itv.size, 1, "map size");
	mu_assert_eq(map->perm, RZ_PERM_R, "io map perm");
	map = rz_io_map_get(core->io, 0x400);
	mu_assert_streq(map->name, "vmap.vfile map with zeroes", "io map name");
	mu_assert_eq(map->delta, 0, "map delta");
	mu_assert_eq(map->itv.addr, 0x400, "map addr");
	mu_assert_eq(map->itv.size, 3, "map size");
	mu_assert_eq(map->perm, RZ_PERM_R, "io map perm");
	map = rz_io_map_get(core->io, 0x300);
	mu_assert_streq(map->name, "vmap.vfile map", "io map name");
	mu_assert_eq(map->delta, 4, "map delta");
	mu_assert_eq(map->itv.addr, 0x300, "map addr");
	mu_assert_eq(map->itv.size, 4, "map size");
	mu_assert_eq(map->perm, RZ_PERM_RWX, "io map perm");

	rz_core_file_close(f);
	mu_assert_null(core->file, "closed current file");

	// now everything should be gone
	mu_assert_eq(rz_pvector_len(&core->io->maps), 0, "io maps count");

	rz_core_free(core);
	mu_end;
}

/// test behavior after closing the core file when there have been additional vfile fds/maps created manually outside of it
bool test_cfile_close_manual_vfile_fd(void) {
	RzCore *core = rz_core_new();
	rz_bin_plugin_add(core->bin, &mock_plugin);
	RzCoreFile *f = rz_core_file_open(core, "hex://424213374242", RZ_PERM_R, 0);
	mu_assert_notnull(f, "load core file");
	mu_assert_ptreq(core->file, f, "current file");
	bool r = rz_core_bin_load(core, NULL, 0);
	mu_assert_true(r, "core bin load");
	RzBinFile *bf = rz_bin_file_find_by_fd(core->bin, f->fd);
	mu_assert_notnull(bf, "binfile");
	mu_assert_streq(bf->o->plugin->name, "mock", "binfile with mock plugin");

	mu_assert_eq(rz_pvector_len(&core->io->maps), 6, "io maps count");

	// the bf->id value should not be seen as a specification but it has to be consistent with the vfile uri below.
	mu_assert_eq(bf->id, 0, "binfile id");
	RzIOMap *map;
	RzIODesc *desc = rz_io_open_at(core->io, "vfile://0/vfile0", 0644, RZ_PERM_R, 0x8000, &map);
	mu_assert_notnull(desc, "vfile open");
	int vfd = desc->fd; // remember fd, desc should be freed later

	ut8 buf[8];
	r = rz_io_read_at_mapped(core->io, 0x8000, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xc0\xff\xee\xff\xff\xff\xff\xff", 8, "manual vfile map read");

	rz_core_file_close(f);
	mu_assert_null(core->file, "closed current file");

	// now everything should be gone, including the vfile which indirectly pointed into the core file
	desc = rz_io_desc_get(core->io, vfd);
	mu_assert_null(desc, "vfile closed");
	mu_assert_eq(rz_pvector_len(&core->io->maps), 0, "io maps count");

	r = rz_io_read_at_mapped(core->io, 0x8000, buf, sizeof(buf));
	mu_assert_false(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xff\xff\xff\xff\xff\xff", 8, "manual vfile map read");

	rz_core_free(core);
	mu_end;
}

/// test behavior after closing the core file when there have been additional maps into its vfiles created manually outside of it
bool test_cfile_close_manual_vfile_map(void) {
	RzCore *core = rz_core_new();
	rz_bin_plugin_add(core->bin, &mock_plugin);
	RzCoreFile *f = rz_core_file_open(core, "hex://424213374242", RZ_PERM_R, 0);
	mu_assert_notnull(f, "load core file");
	mu_assert_ptreq(core->file, f, "current file");
	bool r = rz_core_bin_load(core, NULL, 0);
	mu_assert_true(r, "core bin load");
	RzBinFile *bf = rz_bin_file_find_by_fd(core->bin, f->fd);
	mu_assert_notnull(bf, "binfile");
	mu_assert_streq(bf->o->plugin->name, "mock", "binfile with mock plugin");

	mu_assert_eq(rz_pvector_len(&core->io->maps), 6, "io maps count");

	mu_assert_eq(rz_pvector_len(&f->extra_files), 4, "extra files count");
	RzIODesc *desc = rz_pvector_at(&f->extra_files, 3);
	mu_assert_streq(desc->name, "vfile://0/vfile0", "vfile desc name");

	RzIOMap *map = rz_io_map_add(core->io, desc->fd, RZ_PERM_R, 0, 0x8000, 0x3);
	mu_assert_notnull(map, "map added");

	ut8 buf[8];
	r = rz_io_read_at_mapped(core->io, 0x8000, buf, sizeof(buf));
	mu_assert_true(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xc0\xff\xee\xff\xff\xff\xff\xff", 8, "manual vfile map read");

	rz_core_file_close(f);
	mu_assert_null(core->file, "closed current file");

	// now everything should be gone, including the vfile map which indirectly pointed into the core file's vfile fd
	mu_assert_eq(rz_pvector_len(&core->io->maps), 0, "io maps count");
	r = rz_io_read_at_mapped(core->io, 0x8000, buf, sizeof(buf));
	mu_assert_false(r, "io read");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xff\xff\xff\xff\xff\xff", 8, "manual vfile map read");

	rz_core_free(core);
	mu_end;
}

/// test behavior after closing an RzCoreFile with manual vfile maps added when another one is present at the same time
bool test_cfile_close_manual_cfile_map_multiple(void) {
	RzCore *core = rz_core_new();
	rz_bin_plugin_add(core->bin, &mock_plugin);

	RzCoreFile *f0 = rz_core_file_open(core, "hex://424213374242", RZ_PERM_R, 0);
	mu_assert_notnull(f0, "load core file");
	mu_assert_ptreq(core->file, f0, "current file");
	mu_assert_eq(rz_list_length(core->bin->binfiles), 0, "no binfiles");
	bool r = rz_core_bin_load(core, NULL, 0);
	mu_assert_true(r, "core bin load");
	mu_assert_eq(rz_list_length(core->bin->binfiles), 1, "binfile loaded");
	mu_assert_eq(rz_pvector_len(&f0->binfiles), 1, "binfile in core file");
	RzBinFile *bf0 = rz_pvector_at(&f0->binfiles, 0);
	mu_assert_notnull(bf0, "binfile");
	mu_assert_eq(bf0->fd, f0->fd, "binfile fd");

	RzCoreFile *f1 = rz_core_file_open(core, "hex://c0ffeec0ffee", RZ_PERM_R, 0);
	mu_assert_notnull(f1, "load another core file");
	mu_assert_ptreq(core->file, f1, "current file");
	r = rz_core_bin_load(core, NULL, 0);
	mu_assert_true(r, "core bin load");
	mu_assert_eq(rz_list_length(core->bin->binfiles), 2, "binfile loaded");
	mu_assert_eq(rz_pvector_len(&f1->binfiles), 1, "binfile in core file");
	RzBinFile *bf1 = rz_pvector_at(&f1->binfiles, 0);
	mu_assert_notnull(bf1, "binfile");
	mu_assert_eq(bf1->fd, f1->fd, "binfile fd");

	// the bf->id values should not be seen as a specification but it has to be consistent with the vfile uri below.
	mu_assert_eq(bf0->id, 0, "binfile id");
	mu_assert_eq(bf1->id, 1, "binfile id");
	RzIOMap *vmap0;
	RzIODesc *vdesc0 = rz_io_open_at(core->io, "vfile://0/vfile0", 0644, RZ_PERM_R, 0x8000, &vmap0);
	mu_assert_notnull(vdesc0, "vfile open");
	mu_assert_notnull(vmap0, "vfile mapped");
	RzIOMap *vmap1;
	RzIODesc *vdesc1 = rz_io_open_at(core->io, "vfile://1/vfile0", 0644, RZ_PERM_R, 0x9000, &vmap1);
	mu_assert_notnull(vdesc1, "vfile open");
	mu_assert_notnull(vmap1, "vfile mapped");
	int vfd0 = vdesc0->fd; // remember fds, desc should be freed later
	int vfd1 = vdesc1->fd;

	rz_core_file_close(f0);
	mu_assert_ptreq(core->file, f1, "closed non-current file");
	mu_assert_eq(rz_pvector_len(&f1->extra_files), 4, "other file still has its extra file refs");
	mu_assert_eq(rz_list_length(core->bin->binfiles), 1, "binfile loaded");
	mu_assert_true(rz_list_contains(core->bin->binfiles, bf1), "other binfile still there");

	vdesc0 = rz_io_desc_get(core->io, vfd0);
	mu_assert_null(vdesc0, "vdesc backed by closed binfile should be gone");
	vdesc1 = rz_io_desc_get(core->io, vfd1);
	mu_assert_notnull(vdesc1, "vdesc backed by unclosed binfile should be there");

	rz_core_free(core);
	mu_end;
}

bool test_bin_set_export_info(void) {
	RzCore *core = rz_core_new();
	rz_bin_plugin_add(core->bin, &mock_plugin);

	RzCoreFile *f = rz_core_file_open(core, "hex://424213374242", RZ_PERM_R, 0);
	mu_assert_notnull(f, "load core file");

	bool r = rz_core_bin_load(core, NULL, 0);
	mu_assert_true(r, "core bin load");

	RzBinFile *bf = rz_bin_cur(core->bin);
	Sdb *sdb = sdb_ns(bf->sdb, "info", 0);

	sdb_set(sdb, "my_item.offset", "0x200");
	sdb_set(sdb, "my_item.format", "test_struct");
	sdb_set(sdb, "my_item.size", "8");

	rz_core_bin_set_export_info(core);

	rz_flag_space_set(core->flags, "format");
	RzFlagItem *fi = rz_flag_get(core->flags, "my_item");
	mu_assert_notnull(fi, "flag 'my_item' should exist");
	mu_assert_eq(fi->offset, 0x200, "flag offset");
	mu_assert_eq(fi->size, 8, "flag size");

	rz_core_free(core);
	mu_end;
}

static void emit_x64_go_lea_mov(ut8 *code, ut64 pc, ut64 str_addr, ut32 str_len) {
	st32 disp = (st32)((st64)str_addr - (st64)(pc + 7));
	code[0] = 0x48;
	code[1] = 0x8d;
	code[2] = 0x05;
	rz_write_le32(code + 3, (ut32)disp);
	code[7] = 0xbb;
	rz_write_le32(code + 8, str_len);
}

bool test_golang_oversized_bb_strings(void) {
	const size_t total = 0x12000;
	ut8 *mem = malloc(total);
	if (!mem) {
		mu_fail("alloc synthetic go buffer");
		return false;
	}
	memset(mem, 0x90, total);
	mem[0] = 0x31;
	mem[1] = 0xc0;

	const char *s1 = "BEFORE_64K_OK";
	const char *s2 = "AFTER_64K_OK";
	const ut64 s1_addr = 0x11800;
	const ut64 s2_addr = 0x11840;
	memcpy(mem + s1_addr, s1, strlen(s1));
	memcpy(mem + s2_addr, s2, strlen(s2));
	emit_x64_go_lea_mov(mem + 0x100, 0x100, s1_addr, (ut32)strlen(s1));
	emit_x64_go_lea_mov(mem + 0x10200, 0x10200, s2_addr, (ut32)strlen(s2));
	mem[0x10210] = 0xc3;

	RzCore *core = rz_core_new();
	if (!core) {
		free(mem);
		mu_fail("rz_core_new");
		return false;
	}
	rz_config_set_b(core->config, "scr.interactive", false);
	RzCoreFile *cf = rz_core_file_open(core, "malloc://0x12000", RZ_PERM_RWX, 0);
	if (!cf) {
		free(mem);
		rz_core_free(core);
		mu_fail("open malloc://0x12000");
		return false;
	}
	rz_core_bin_load(core, "malloc://0x12000", 0);
	rz_io_write_at(core->io, 0, mem, total);
	free(mem);

	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf) {
		RzBinOptions opt;
		rz_bin_options_init(&opt, cf->fd, 0, 0, false);
		opt.filename = "synthetic_go";
		rz_bin_open_io(core->bin, &opt);
		bf = rz_bin_cur(core->bin);
	}
	rz_config_set(core->config, "asm.arch", "x86");
	rz_config_set_i(core->config, "asm.bits", 64);
	if (!bf || !bf->o) {
		rz_core_free(core);
		mu_fail("cur bin file/object");
		return false;
	}
	if (!bf->o->sections) {
		bf->o->sections = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	}
	RzBinSection *sec = RZ_NEW0(RzBinSection);
	if (!sec) {
		rz_core_free(core);
		mu_fail("alloc section");
		return false;
	}
	sec->name = rz_str_dup(".rodata");
	sec->vaddr = 0;
	sec->paddr = 0;
	sec->vsize = total;
	sec->size = total;
	sec->perm = RZ_PERM_RX;
	rz_pvector_push(bf->o->sections, sec);
	if (!bf->o->strings) {
		bf->o->strings = rz_bin_string_database_new(NULL);
	}

	RzAnalysisFunction *fcn = rz_analysis_create_function(core->analysis, "sym.go.main.big", 0, RZ_ANALYSIS_FCN_TYPE_FCN);
	RzAnalysisBlock *bb = rz_analysis_create_block(core->analysis, 0, 0x10211);
	if (!fcn || !bb) {
		rz_analysis_block_unref(bb);
		rz_core_free(core);
		mu_fail("create function/block");
		return false;
	}
	rz_analysis_block_analyze_ops(bb);
	rz_analysis_function_add_block(fcn, bb);
	rz_analysis_block_unref(bb);

	rz_core_analysis_resolve_golang_strings(core);

	RzFlagItem *f1 = rz_flag_get_i(core->flags, s1_addr);
	RzFlagItem *f2 = rz_flag_get_i(core->flags, s2_addr);
	mu_assert_notnull(f1, "string before 64KB recovered");
	mu_assert_streq(f1->name, "str.BEFORE_64K_OK", "before 64KB string name");
	mu_assert_notnull(f2, "string after 64KB recovered despite ut16 op_pos cap");
	mu_assert_streq(f2->name, "str.AFTER_64K_OK", "after 64KB string name");

	rz_core_free(core);
	mu_end;
}

typedef struct trycatch_collect_ctx_t {
	ut64 handlers[64];
	size_t count;
	size_t stop_after;
} TrycatchCollectCtx;

static bool collect_trycatch_cb(RZ_NONNULL RzBinTrycatch *tc, RZ_NULLABLE void *user) {
	TrycatchCollectCtx *ctx = user;
	if (ctx->count < RZ_ARRAY_SIZE(ctx->handlers)) {
		ctx->handlers[ctx->count++] = tc->handler;
	}
	if (ctx->stop_after && ctx->count >= ctx->stop_after) {
		return false;
	}
	return true;
}

bool test_bin_classes_lazy_sort(void) {
	RzCore *core = rz_core_new();
	rz_bin_plugin_add(core->bin, &mock_plugin);
	RzCoreFile *f = rz_core_file_open(core, "hex://424213374242", RZ_PERM_R, 0);
	mu_assert_notnull(f, "load core file");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "core bin load");

	RzBinFile *bf = rz_bin_cur(core->bin);
	mu_assert_notnull(bf, "binfile");
	RzBinObject *o = bf->o;

	mu_assert_null(rz_bin_object_find_class(o, "Missing"), "missing class returns NULL");

	mu_assert_notnull(rz_bin_object_add_class(o, "Zeta", NULL, 0x300), "add Zeta");
	mu_assert_notnull(rz_bin_object_add_class(o, "Alpha", NULL, 0x100), "add Alpha");
	mu_assert_notnull(rz_bin_object_add_class(o, "Mid", NULL, 0x200), "add Mid");
	RzBinClass *empty = rz_bin_object_add_class(o, "Empty", NULL, 0x150);
	mu_assert_notnull(empty, "add Empty");
	rz_list_free(empty->methods);
	empty->methods = NULL;
	rz_list_free(empty->fields);
	empty->fields = NULL;

	mu_assert_notnull(rz_bin_object_add_method(o, "Alpha", "m2", 0x20, 0x120), "add m2");
	mu_assert_notnull(rz_bin_object_add_method(o, "Alpha", "m1", 0x10, 0x110), "add m1");
	mu_assert_notnull(rz_bin_object_add_field(o, "Alpha", "f2", 0x40, 0x140), "add f2");
	mu_assert_notnull(rz_bin_object_add_field(o, "Alpha", "f1", 0x30, 0x130), "add f1");
	mu_assert_notnull(rz_bin_object_add_method(o, "Mid", "mm2", 0x60, 0x220), "add Mid mm2");
	mu_assert_notnull(rz_bin_object_add_method(o, "Mid", "mm1", 0x50, 0x210), "add Mid mm1");
	mu_assert_notnull(rz_bin_object_add_field(o, "Mid", "mf2", 0x80, 0x240), "add Mid mf2");
	mu_assert_notnull(rz_bin_object_add_field(o, "Mid", "mf1", 0x70, 0x230), "add Mid mf1");

	mu_assert_ptreq(rz_bin_object_find_class(o, "Empty"), empty, "find class with NULL members");

	RzBinClass *found = rz_bin_object_find_class(o, "Alpha");
	mu_assert_notnull(found, "find Alpha");
	mu_assert_eq(rz_list_length(found->methods), 2, "2 methods");
	RzBinSymbol *m0 = rz_list_first_val(found->methods);
	RzBinSymbol *m1 = rz_list_last_val(found->methods);
	mu_assert_streq(m0->name, "m1", "first method sorted by vaddr");
	mu_assert_streq(m1->name, "m2", "second method sorted by vaddr");
	RzBinClassField *f0 = rz_list_first_val(found->fields);
	RzBinClassField *f1 = rz_list_last_val(found->fields);
	mu_assert_streq(f0->name, "f1", "first field sorted by vaddr");
	mu_assert_streq(f1->name, "f2", "second field sorted by vaddr");

	const RzPVector *classes = rz_bin_object_get_classes(o);
	mu_assert_eq(rz_pvector_len(classes), 4, "4 classes");
	RzBinClass *c0 = rz_pvector_at(classes, 0);
	RzBinClass *c1 = rz_pvector_at(classes, 1);
	RzBinClass *c2 = rz_pvector_at(classes, 2);
	RzBinClass *c3 = rz_pvector_at(classes, 3);
	mu_assert_streq(c0->name, "Alpha", "class 0 sorted");
	mu_assert_streq(c1->name, "Empty", "class 1 sorted");
	mu_assert_streq(c2->name, "Mid", "class 2 sorted");
	mu_assert_streq(c3->name, "Zeta", "class 3 sorted");
	mu_assert_eq(rz_list_length(c2->methods), 2, "Mid has 2 methods");
	mu_assert_streq(((RzBinSymbol *)rz_list_first_val(c2->methods))->name, "mm1", "Mid first method sorted");
	mu_assert_streq(((RzBinSymbol *)rz_list_last_val(c2->methods))->name, "mm2", "Mid second method sorted");
	mu_assert_eq(rz_list_length(c2->fields), 2, "Mid has 2 fields");
	mu_assert_streq(((RzBinClassField *)rz_list_first_val(c2->fields))->name, "mf1", "Mid first field sorted");
	mu_assert_streq(((RzBinClassField *)rz_list_last_val(c2->fields))->name, "mf2", "Mid second field sorted");

	// Second call when already sorted takes the clean fast path.
	mu_assert_ptreq(rz_bin_object_get_classes(o), classes, "already sorted classes");

	// Apply classes to core flags, and verify NULL bin object handling.
	mu_assert_true(rz_core_bin_apply_classes(core, bf), "apply classes");
	RzBinFile empty_bf = { 0 };
	mu_assert_false(rz_core_bin_apply_classes(core, &empty_bf), "apply classes with NULL bin object");

	// Demangle hook re-sorts classes if needed.
	rz_bin_demangle_with_flags(core->bin, RZ_DEMANGLER_FLAG_ENABLE_ALL);

	// NULL classes vector returns NULL cleanly.
	RzPVector *saved_classes = o->classes;
	o->classes = NULL;
	mu_assert_null(rz_bin_object_get_classes(o), "NULL classes vector");
	o->classes = saved_classes;

	rz_core_free(core);
	mu_end;
}

bool test_bin_trycatch_index(void) {
	RzCore *core = rz_core_new();
	rz_bin_plugin_add(core->bin, &mock_plugin);
	RzCoreFile *f = rz_core_file_open(core, "hex://424213374242", RZ_PERM_R, 0);
	mu_assert_notnull(f, "load core file");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "core bin load");

	RzBinFile *bf = rz_bin_cur(core->bin);
	RzPVector *tcs = rz_bin_file_get_trycatch(bf);
	mu_assert_notnull(tcs, "trycatch vector");

	// Empty query succeeds with 0 matches.
	TrycatchCollectCtx ctx = { 0 };
	mu_assert_true(rz_bin_file_trycatch_foreach_at(bf, 0x1050, false, collect_trycatch_cb, &ctx), "empty query");
	mu_assert_eq(ctx.count, 0, "no matches");

	// Mirror Windows SEH inner-before-outer ordering:
	// idx 0: inner [0x104c, 0x1066) -> handler 0x1066
	// idx 1: outer [0x1022, 0x1076) -> handler 0x1076
	// idx 2: same-from [0x104c, 0x1060) -> handler 0x1060
	// idx 3: disjoint [0x2000, 0x2050) -> handler 0x2050
	rz_pvector_push(tcs, rz_bin_trycatch_new(0x1010, 0x104c, 0x1066, 0x1066, 0));
	rz_pvector_push(tcs, rz_bin_trycatch_new(0x1010, 0x1022, 0x1076, 0x1076, 0));
	rz_pvector_push(tcs, rz_bin_trycatch_new(0x1010, 0x104c, 0x1060, 0x1060, 0));
	rz_pvector_push(tcs, rz_bin_trycatch_new(0x2000, 0x2000, 0x2050, 0x2050, 0));

	// Exact from match at 0x104c returns idx 0 then idx 2.
	memset(&ctx, 0, sizeof(ctx));
	mu_assert_true(rz_bin_file_trycatch_foreach_at(bf, 0x104c, true, collect_trycatch_cb, &ctx), "exact 0x104c");
	mu_assert_eq(ctx.count, 2, "2 exact matches");
	mu_assert_eq(ctx.handlers[0], 0x1066, "exact match 0");
	mu_assert_eq(ctx.handlers[1], 0x1060, "exact match 1");

	// Exact from match at last entry (0x2000), miss in middle (0x1050), and past end (0x9000).
	memset(&ctx, 0, sizeof(ctx));
	mu_assert_true(rz_bin_file_trycatch_foreach_at(bf, 0x2000, true, collect_trycatch_cb, &ctx), "exact last entry");
	mu_assert_eq(ctx.count, 1, "1 exact match at last entry");
	mu_assert_eq(ctx.handlers[0], 0x2050, "last entry handler");

	memset(&ctx, 0, sizeof(ctx));
	mu_assert_true(rz_bin_file_trycatch_foreach_at(bf, 0x1050, true, collect_trycatch_cb, &ctx), "exact middle miss");
	mu_assert_eq(ctx.count, 0, "0 exact matches in middle");

	memset(&ctx, 0, sizeof(ctx));
	mu_assert_true(rz_bin_file_trycatch_foreach_at(bf, 0x9000, true, collect_trycatch_cb, &ctx), "exact past end");
	mu_assert_eq(ctx.count, 0, "0 exact matches past end");

	// Early stop on exact match.
	memset(&ctx, 0, sizeof(ctx));
	ctx.stop_after = 1;
	mu_assert_false(rz_bin_file_trycatch_foreach_at(bf, 0x104c, true, collect_trycatch_cb, &ctx), "exact early stop");
	mu_assert_eq(ctx.count, 1, "stopped after 1");

	// Range match at 0x1050 preserves original order: idx 0, idx 1, idx 2.
	memset(&ctx, 0, sizeof(ctx));
	mu_assert_true(rz_bin_file_trycatch_foreach_at(bf, 0x1050, false, collect_trycatch_cb, &ctx), "range 0x1050");
	mu_assert_eq(ctx.count, 3, "3 range matches");
	mu_assert_eq(ctx.handlers[0], 0x1066, "inner handler first");
	mu_assert_eq(ctx.handlers[1], 0x1076, "outer handler second");
	mu_assert_eq(ctx.handlers[2], 0x1060, "third handler third");

	// Early stop on range match.
	memset(&ctx, 0, sizeof(ctx));
	ctx.stop_after = 1;
	mu_assert_false(rz_bin_file_trycatch_foreach_at(bf, 0x1050, false, collect_trycatch_cb, &ctx), "range early stop");
	mu_assert_eq(ctx.count, 1, "range stopped after 1");

	// Range match at 0x1070 skips ended inner intervals (addr >= tc->to) while matching outer [0x1022, 0x1076).
	memset(&ctx, 0, sizeof(ctx));
	mu_assert_true(rz_bin_file_trycatch_foreach_at(bf, 0x1070, false, collect_trycatch_cb, &ctx), "range 0x1070");
	mu_assert_eq(ctx.count, 1, "1 match at 0x1070");
	mu_assert_eq(ctx.handlers[0], 0x1076, "outer handler after ended inner");

	// Range match inside outer only (0x1030), before all (0x500), and miss between intervals (0x1500).
	memset(&ctx, 0, sizeof(ctx));
	mu_assert_true(rz_bin_file_trycatch_foreach_at(bf, 0x1030, false, collect_trycatch_cb, &ctx), "range 0x1030");
	mu_assert_eq(ctx.count, 1, "1 match at 0x1030");
	mu_assert_eq(ctx.handlers[0], 0x1076, "outer handler");

	memset(&ctx, 0, sizeof(ctx));
	mu_assert_true(rz_bin_file_trycatch_foreach_at(bf, 0x500, false, collect_trycatch_cb, &ctx), "range before all");
	mu_assert_eq(ctx.count, 0, "0 matches before all");

	memset(&ctx, 0, sizeof(ctx));
	mu_assert_true(rz_bin_file_trycatch_foreach_at(bf, 0x1500, false, collect_trycatch_cb, &ctx), "range miss");
	mu_assert_eq(ctx.count, 0, "0 matches at 0x1500");

	// >32 overlapping records exercises both malloc (16->32) and realloc (32->64) plus qsort restoration.
	for (ut64 i = 0; i < 36; i++) {
		rz_pvector_push(tcs, rz_bin_trycatch_new(0x3000, 0x3000 + (35 - i), 0x3100, 0x4000 + i, 0));
	}
	memset(&ctx, 0, sizeof(ctx));
	mu_assert_true(rz_bin_file_trycatch_foreach_at(bf, 0x3050, false, collect_trycatch_cb, &ctx), "36 overlapping");
	mu_assert_eq(ctx.count, 36, "all 36 matches");
	mu_assert_eq(ctx.handlers[0], 0x4000, "orig_idx 0 preserved after qsort");
	mu_assert_eq(ctx.handlers[35], 0x4023, "orig_idx 35 preserved after qsort");

	// Early stop on heap-allocated match list frees buffer cleanly.
	memset(&ctx, 0, sizeof(ctx));
	ctx.stop_after = 2;
	mu_assert_false(rz_bin_file_trycatch_foreach_at(bf, 0x3050, false, collect_trycatch_cb, &ctx), "heap early stop");
	mu_assert_eq(ctx.count, 2, "heap stopped after 2");

	rz_core_free(core);
	mu_end;
}

bool test_analysis_trycatch_handlers(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");
	rz_config_set(core->config, "asm.arch", "x86");
	rz_config_set_i(core->config, "asm.bits", 64);
	rz_config_set_b(core->config, "analysis.trycatch", true);
	rz_config_set_b(core->config, "analysis.nopskip", false);

	RzIODesc *code_desc = rz_io_open_at(core->io, "malloc://0x200", RZ_PERM_RWX, 0, 0x1000, NULL);
	mu_assert_notnull(code_desc, "open code buffer");

	// 0x1000: nop; call 0x1080 (noreturn CALL)
	const ut8 fcn_call[] = { 0x90, 0xe8, 0x7a, 0x00, 0x00, 0x00 };
	// 0x1010: nop; call 0x1080 (for overlapped block analysis)
	const ut8 fcn_ovlp[] = { 0x90, 0xe8, 0x6a, 0x00, 0x00, 0x00 };
	// 0x1020: jmp 0x1080 (noreturn JMP)
	const ut8 fcn_jmp[] = { 0xe9, 0x5b, 0x00, 0x00, 0x00 };
	// 0x1030: call qword [rip + 0x4a] -> 0x1036 + 0x4a = 0x1080 (noreturn UCALL)
	const ut8 fcn_ucall[] = { 0xff, 0x15, 0x4a, 0x00, 0x00, 0x00 };
	const ut8 ret_op[] = { 0xc3 };
	rz_io_write_at(core->io, 0x1000, fcn_call, sizeof(fcn_call));
	rz_io_write_at(core->io, 0x1010, fcn_ovlp, sizeof(fcn_ovlp));
	rz_io_write_at(core->io, 0x1020, fcn_jmp, sizeof(fcn_jmp));
	rz_io_write_at(core->io, 0x1030, fcn_ucall, sizeof(fcn_ucall));
	rz_io_write_at(core->io, 0x1040, ret_op, sizeof(ret_op));
	rz_io_write_at(core->io, 0x1050, ret_op, sizeof(ret_op));
	rz_io_write_at(core->io, 0x1060, ret_op, sizeof(ret_op));
	rz_io_write_at(core->io, 0x1080, ret_op, sizeof(ret_op));
	rz_analysis_noreturn_add(core->analysis, NULL, 0x1080);

	// 1. No current binfile: analysis succeeds without trycatch handlers.
	rz_core_analysis_fcn(core, 0x1000, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, 0x1000);
	mu_assert_notnull(fcn, "fcn without binfile");
	rz_analysis_function_delete(fcn);

	// 2. Loaded binfile with empty trycatch vector.
	rz_bin_plugin_add(core->bin, &mock_plugin);
	RzCoreFile *f = rz_core_file_open(core, "hex://424213374242", RZ_PERM_R, 0);
	mu_assert_notnull(f, "open mock bin");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "load mock bin");

	rz_core_analysis_fcn(core, 0x1000, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	fcn = rz_analysis_get_function_at(core->analysis, 0x1000);
	mu_assert_notnull(fcn, "fcn with empty trycatch");
	rz_analysis_function_delete(fcn);

	// 3. Loaded binfile with temporarily NULL bf->o.
	RzBinFile *bf = rz_bin_cur(core->bin);
	RzBinObject *saved_o = bf->o;
	bf->o = NULL;
	rz_core_analysis_fcn(core, 0x1000, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	fcn = rz_analysis_get_function_at(core->analysis, 0x1000);
	mu_assert_notnull(fcn, "fcn with NULL bf->o");
	rz_analysis_function_delete(fcn);
	bf->o = saved_o;

	// 4. Populate trycatch records covering zero-handler, filter+handler, second handler, JMP, UCALL, and overlap.
	RzPVector *tcs = rz_bin_file_get_trycatch(bf);
	mu_assert_notnull(tcs, "trycatch vector");
	rz_pvector_push(tcs, rz_bin_trycatch_new(0x1000, 0x1000, 0x1008, 0, 0));
	rz_pvector_push(tcs, rz_bin_trycatch_new(0x1000, 0x1000, 0x1008, 0x1040, 0x1060));
	rz_pvector_push(tcs, rz_bin_trycatch_new(0x1000, 0x1000, 0x1008, 0x1050, 0));
	rz_pvector_push(tcs, rz_bin_trycatch_new(0x1010, 0x1010, 0x1018, 0x1040, 0));
	rz_pvector_push(tcs, rz_bin_trycatch_new(0x1020, 0x1020, 0x1028, 0x1040, 0));
	rz_pvector_push(tcs, rz_bin_trycatch_new(0x1030, 0x1030, 0x1038, 0x1040, 0));

	// Noreturn CALL at 0x1001 with op-start trycatch at 0x1000.
	rz_core_analysis_fcn(core, 0x1000, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	fcn = rz_analysis_get_function_at(core->analysis, 0x1000);
	mu_assert_notnull(fcn, "fcn at 0x1000");
	RzAnalysisBlock *bb0 = rz_analysis_get_block_at(core->analysis, 0x1000);
	mu_assert_notnull(bb0, "bb at 0x1000");
	mu_assert_eq(bb0->jump, 0x1040, "first non-zero handler sets bb->jump");
	mu_assert_notnull(rz_analysis_get_block_at(core->analysis, 0x1040), "handler1 block analyzed");
	mu_assert_notnull(rz_analysis_get_block_at(core->analysis, 0x1050), "handler2 block analyzed");
	RzList *xrefs = rz_analysis_xrefs_get_from(core->analysis, 0x1000);
	mu_assert_notnull(xrefs, "xrefs from 0x1000");
	mu_assert_true(rz_list_length(xrefs) >= 2, "filter and handler xrefs created");
	rz_list_free(xrefs);

	// Overlapped block hitting noreturn CALL at 0x1011.
	rz_core_analysis_fcn(core, 0x1011, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	rz_core_analysis_fcn(core, 0x1010, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	mu_assert_notnull(rz_analysis_get_function_at(core->analysis, 0x1010), "overlapped fcn at 0x1010");

	// Noreturn JMP at 0x1020.
	rz_core_analysis_fcn(core, 0x1020, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	RzAnalysisBlock *bb_jmp = rz_analysis_get_block_at(core->analysis, 0x1020);
	mu_assert_notnull(bb_jmp, "bb at 0x1020");
	mu_assert_eq(bb_jmp->jump, 0x1040, "noreturn jmp routes to trycatch handler");

	// Noreturn UCALL at 0x1030.
	rz_core_analysis_fcn(core, 0x1030, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	RzAnalysisBlock *bb_ucall = rz_analysis_get_block_at(core->analysis, 0x1030);
	mu_assert_notnull(bb_ucall, "bb at 0x1030");
	mu_assert_eq(bb_ucall->jump, 0x1040, "noreturn ucall routes to trycatch handler");

	// Missing bin binding (binb.bin == NULL and binb.get_trycatch == NULL) skips trycatch cleanly.
	rz_analysis_function_delete_address(core->analysis, 0x1020);
	RzBin *saved_bin = core->analysis->binb.bin;
	core->analysis->binb.bin = NULL;
	rz_core_analysis_fcn(core, 0x1020, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	core->analysis->binb.bin = saved_bin;
	rz_analysis_function_delete_address(core->analysis, 0x1020);
	RzBinGetTrycatch saved_get_tc = core->analysis->binb.get_trycatch;
	core->analysis->binb.get_trycatch = NULL;
	rz_core_analysis_fcn(core, 0x1020, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	core->analysis->binb.get_trycatch = saved_get_tc;

	rz_core_free(core);
	mu_end;
}

enum {
	SYNTH_ELF_REL = 1u << 0,
	SYNTH_ELF_NO_IMPORTS = 1u << 1,
	SYNTH_ELF_RUST_SYM = 1u << 2,
	SYNTH_ELF_RUST_IMP = 1u << 3,
	SYNTH_ELF_RETGUARD_PROGBITS = 1u << 4,
	SYNTH_ELF_RETGUARD_NOBITS = 1u << 5,
	SYNTH_ELF_NO_RELOCS = 1u << 6,
	SYNTH_ELF_RESOLVED_ONLY = 1u << 7,
};

static void synth_elf_fill_strtabs(ut8 *raw) {
	// .dynstr / .strtab at 0x300
	static const char strtab[] =
		"\0"
		"imp_res\0" // 1
		"imp_unres\0" // 9
		"_NSConcreteGlobalBlock\0" // 19
		"__rust_oom\0" // 42
		"def_sym\0"; // 53
	memcpy(raw + 0x300, strtab, sizeof(strtab));

	// .shstrtab at 0x880
	static const char shstrtab[] =
		"\0"
		".shstrtab\0" // 1
		".text\0" // 11
		".strtab\0" // 17
		".symtab\0" // 25
		".openbsd.randomdata\0"; // 33
	memcpy(raw + 0x880, shstrtab, sizeof(shstrtab));
}

static RzBuffer *build_synth_elf64(ut32 flags) {
	ut8 raw[0x1000] = { 0 };
	const ut64 base = 0x400000;
	const bool is_rel = (flags & SYNTH_ELF_REL) != 0;
	const bool no_imp = (flags & SYNTH_ELF_NO_IMPORTS) != 0;
	const bool res_only = (flags & SYNTH_ELF_RESOLVED_ONLY) != 0;
	const bool has_rg = (flags & (SYNTH_ELF_RETGUARD_PROGBITS | SYNTH_ELF_RETGUARD_NOBITS)) != 0;
	const ut16 nsh = res_only ? 4 : (has_rg ? 6 : 5);

	synth_elf_fill_strtabs(raw);

	// Elf64_Ehdr
	static const ut8 elf_magic[4] = { 0x7f, 'E', 'L', 'F' };
	memcpy(raw, elf_magic, sizeof(elf_magic));
	raw[4] = 2; // ELFCLASS64
	raw[5] = 1; // ELFDATA2LSB
	raw[6] = 1; // EV_CURRENT
	rz_write_le16(raw + 16, is_rel ? 1 : 2); // ET_REL / ET_EXEC
	rz_write_le16(raw + 18, 62); // EM_X86_64
	rz_write_le32(raw + 20, 1);
	rz_write_le64(raw + 24, base + 0x800); // e_entry
	rz_write_le64(raw + 32, is_rel ? 0 : 0x40); // e_phoff
	rz_write_le64(raw + 40, 0x900); // e_shoff
	rz_write_le16(raw + 52, 64); // e_ehsize
	rz_write_le16(raw + 54, 56); // e_phentsize
	rz_write_le16(raw + 56, is_rel ? 0 : 2); // e_phnum
	rz_write_le16(raw + 58, 64); // e_shentsize
	rz_write_le16(raw + 60, nsh); // e_shnum
	rz_write_le16(raw + 62, 1); // e_shstrndx

	if (!is_rel) {
		// Phdr 0: PT_LOAD covering the whole buffer
		ut8 *p0 = raw + 0x40;
		rz_write_le32(p0 + 0, 1); // PT_LOAD
		rz_write_le32(p0 + 4, 5); // PF_R | PF_X
		rz_write_le64(p0 + 8, 0); // p_offset
		rz_write_le64(p0 + 16, base); // p_vaddr
		rz_write_le64(p0 + 24, base); // p_paddr
		rz_write_le64(p0 + 32, sizeof(raw)); // p_filesz
		rz_write_le64(p0 + 40, sizeof(raw)); // p_memsz
		rz_write_le64(p0 + 48, 0x1000); // p_align

		// Phdr 1: PT_DYNAMIC at 0x200
		ut8 *p1 = raw + 0x40 + 56;
		rz_write_le32(p1 + 0, 2); // PT_DYNAMIC
		rz_write_le32(p1 + 4, 6); // PF_R | PF_W
		rz_write_le64(p1 + 8, 0x200);
		rz_write_le64(p1 + 16, base + 0x200);
		rz_write_le64(p1 + 24, base + 0x200);
		rz_write_le64(p1 + 32, 0x100);
		rz_write_le64(p1 + 40, 0x100);
		rz_write_le64(p1 + 48, 8);

		const ut32 nsyms = (no_imp || res_only) ? 2 : 6;
		const ut32 nrelocs = (flags & SYNTH_ELF_NO_RELOCS) ? 0 : ((no_imp || res_only) ? 1 : 5);

		// Elf64_Dyn at 0x200
		ut8 *d = raw + 0x200;
		const ut64 dyn_entries[][2] = {
			{ 5, base + 0x300 }, // DT_STRTAB
			{ 10, 0x100 }, // DT_STRSZ
			{ 6, base + 0x400 }, // DT_SYMTAB
			{ 11, 24 }, // DT_SYMENT
			{ 4, base + 0x500 }, // DT_HASH
			{ nrelocs ? 20u : 0u, 7 }, // DT_PLTREL = DT_RELA
			{ nrelocs ? 23u : 0u, base + 0x580 }, // DT_JMPREL
			{ nrelocs ? 2u : 0u, (ut64)nrelocs * 24 }, // DT_PLTRELSZ
			{ 0, 0 }, // DT_NULL
		};
		for (size_t i = 0; i < RZ_ARRAY_SIZE(dyn_entries); i++) {
			rz_write_le64(d + i * 16, dyn_entries[i][0]);
			rz_write_le64(d + i * 16 + 8, dyn_entries[i][1]);
		}

		// DT_HASH at 0x500
		rz_write_le32(raw + 0x500, 1); // nbuckets
		rz_write_le32(raw + 0x504, nsyms); // nchains

		// .dynsym at 0x400 (Elf64_Sym: 24 bytes)
		if (no_imp) {
			ut8 *s1 = raw + 0x400 + 24;
			rz_write_le32(s1 + 0, 53); // "def_sym"
			s1[4] = 0x12; // STB_GLOBAL | STT_FUNC
			rz_write_le16(s1 + 6, 2); // .text
			rz_write_le64(s1 + 8, base + 0x800);
		} else if (res_only) {
			// Single pre-resolved undefined import (no defined symbols -> bin->symbols == NULL)
			ut8 *s1 = raw + 0x400 + 24;
			rz_write_le32(s1 + 0, 1); // "imp_res"
			s1[4] = 0x12;
			rz_write_le16(s1 + 6, 0);
			rz_write_le64(s1 + 8, base + 0x820);
		} else {
			// sym 1: empty name undefined import (st_size=4 -> initial vaddr==0)
			ut8 *s = raw + 0x400 + 1 * 24;
			rz_write_le32(s + 0, 0);
			s[4] = 0x12;
			rz_write_le16(s + 6, 0);
			rz_write_le64(s + 16, 4);
			// sym 2: "imp_res" undefined import (resolved via GOT)
			s = raw + 0x400 + 2 * 24;
			rz_write_le32(s + 0, 1);
			s[4] = 0x12;
			rz_write_le16(s + 6, 0);
			// sym 3: "imp_unres" undefined import (zero GOT entry -> UT64_MAX)
			s = raw + 0x400 + 3 * 24;
			rz_write_le32(s + 0, 9);
			s[4] = 0x12;
			rz_write_le16(s + 6, 0);
			// sym 4: "_NSConcreteGlobalBlock" or "__rust_oom" (non-zero st_value exercises pre-resolved import)
			s = raw + 0x400 + 4 * 24;
			rz_write_le32(s + 0, (flags & SYNTH_ELF_RUST_IMP) ? 42 : 19);
			s[4] = 0x12;
			rz_write_le16(s + 6, 0);
			rz_write_le64(s + 8, base + 0x820);
			// sym 5: "def_sym" defined symbol
			s = raw + 0x400 + 5 * 24;
			rz_write_le32(s + 0, 53);
			s[4] = 0x12;
			rz_write_le16(s + 6, 2);
			rz_write_le64(s + 8, base + 0x800);
		}

		// .rela.plt at 0x580 (Elf64_Rela: 24 bytes) & GOT at 0x700
		if ((no_imp || res_only) && nrelocs) {
			ut8 *r = raw + 0x580;
			rz_write_le64(r + 0, base + 0x700);
			rz_write_le64(r + 8, ((res_only ? 2ULL : 1ULL) << 32) | 7); // R_X86_64_JUMP_SLOT
		} else if (nrelocs) {
			rz_write_le64(raw + 0x700, base + 0x806); // GOT slot 0 -> PLT 0x400800
			rz_write_le64(raw + 0x708, base + 0x816); // GOT slot 1 (duplicate sym 2)
			rz_write_le64(raw + 0x710, 0); // GOT slot 2 -> unresolved (0)
			const struct {
				ut64 off;
				ut32 sym;
				ut32 type;
			} rels[5] = {
				{ base + 0x700, 2, 7 }, // R_X86_64_JUMP_SLOT -> imp_res
				{ base + 0x708, 2, 7 }, // duplicate reloc for already-resolved imp_res
				{ base + 0x710, 3, 7 }, // imp_unres with GOT=0
				{ base + 0x718, 5, 7 }, // defined sym (not in import_addrs)
				{ base + 0x720, 99, 7 }, // missing ordinal
			};
			for (size_t i = 0; i < 5; i++) {
				ut8 *r = raw + 0x580 + i * 24;
				rz_write_le64(r + 0, rels[i].off);
				rz_write_le64(r + 8, (((ut64)rels[i].sym) << 32) | rels[i].type);
			}
		}
	}

	// .symtab at 0x780 (3 entries)
	if (is_rel) {
		// Undefined symbol with st_value=0, st_size=4 (vaddr==0 -> UT64_MAX)
		ut8 *s1 = raw + 0x780 + 1 * 24;
		rz_write_le32(s1 + 0, 9); // "imp_unres"
		s1[4] = 0x12;
		rz_write_le16(s1 + 6, 0);
		rz_write_le64(s1 + 8, 0);
		rz_write_le64(s1 + 16, 4);
		// Undefined symbol with non-zero st_value=0x100
		ut8 *s2 = raw + 0x780 + 2 * 24;
		rz_write_le32(s2 + 0, 1); // "imp_res"
		s2[4] = 0x12;
		rz_write_le16(s2 + 6, 0);
		rz_write_le64(s2 + 8, 0x100);
		rz_write_le64(s2 + 16, 4);
	} else {
		// sym 1: empty name defined symbol
		ut8 *s1 = raw + 0x780 + 1 * 24;
		rz_write_le32(s1 + 0, 0);
		s1[4] = 0x12;
		rz_write_le16(s1 + 6, 2);
		rz_write_le64(s1 + 8, base + 0x800);
		// sym 2: "__rust_oom" or "def_sym"
		ut8 *s2 = raw + 0x780 + 2 * 24;
		rz_write_le32(s2 + 0, (flags & SYNTH_ELF_RUST_SYM) ? 42 : 53);
		s2[4] = 0x12;
		rz_write_le16(s2 + 6, 2);
		rz_write_le64(s2 + 8, base + 0x810);
	}

	// Section headers at 0x900 (Elf64_Shdr: 64 bytes)
	// sh 1: .shstrtab
	ut8 *sh = raw + 0x900 + 1 * 64;
	rz_write_le32(sh + 0, 1);
	rz_write_le32(sh + 4, 3); // SHT_STRTAB
	rz_write_le64(sh + 24, 0x880);
	rz_write_le64(sh + 32, 0x80);
	// sh 2: .text
	sh = raw + 0x900 + 2 * 64;
	rz_write_le32(sh + 0, 11);
	rz_write_le32(sh + 4, 1); // SHT_PROGBITS
	rz_write_le64(sh + 8, 6); // SHF_ALLOC | SHF_EXECINSTR
	rz_write_le64(sh + 16, base + 0x800);
	rz_write_le64(sh + 24, 0x800);
	rz_write_le64(sh + 32, 0x80);
	// sh 3: .strtab
	sh = raw + 0x900 + 3 * 64;
	rz_write_le32(sh + 0, 17);
	rz_write_le32(sh + 4, 3); // SHT_STRTAB
	rz_write_le64(sh + 24, 0x300);
	rz_write_le64(sh + 32, 0x100);
	// sh 4: .symtab
	sh = raw + 0x900 + 4 * 64;
	rz_write_le32(sh + 0, 25);
	rz_write_le32(sh + 4, 2); // SHT_SYMTAB
	rz_write_le64(sh + 24, 0x780);
	rz_write_le64(sh + 32, 3 * 24);
	rz_write_le32(sh + 40, 3); // sh_link = .strtab
	rz_write_le64(sh + 56, 24); // sh_entsize
	if (has_rg) {
		// sh 5: .openbsd.randomdata
		sh = raw + 0x900 + 5 * 64;
		rz_write_le32(sh + 0, 33);
		rz_write_le32(sh + 4, (flags & SYNTH_ELF_RETGUARD_NOBITS) ? 8 : 1); // SHT_NOBITS : SHT_PROGBITS
		rz_write_le64(sh + 8, 2); // SHF_ALLOC
		rz_write_le64(sh + 16, base + 0x800);
		rz_write_le64(sh + 24, 0x800);
		rz_write_le64(sh + 32, 64);
	}

	return rz_buf_new_with_bytes(raw, sizeof(raw));
}

static RzBuffer *build_synth_elf32(ut32 flags) {
	ut8 raw[0x1000] = { 0 };
	const ut32 base = 0x08048000;
	const bool is_rel = (flags & SYNTH_ELF_REL) != 0;
	const bool no_imp = (flags & SYNTH_ELF_NO_IMPORTS) != 0;
	const bool res_only = (flags & SYNTH_ELF_RESOLVED_ONLY) != 0;
	const bool has_rg = (flags & (SYNTH_ELF_RETGUARD_PROGBITS | SYNTH_ELF_RETGUARD_NOBITS)) != 0;
	const ut16 nsh = res_only ? 4 : (has_rg ? 6 : 5);

	synth_elf_fill_strtabs(raw);

	// Elf32_Ehdr (52 bytes)
	static const ut8 elf_magic[4] = { 0x7f, 'E', 'L', 'F' };
	memcpy(raw, elf_magic, sizeof(elf_magic));
	raw[4] = 1; // ELFCLASS32
	raw[5] = 1; // ELFDATA2LSB
	raw[6] = 1; // EV_CURRENT
	rz_write_le16(raw + 16, is_rel ? 1 : 2); // ET_REL / ET_EXEC
	rz_write_le16(raw + 18, 3); // EM_386
	rz_write_le32(raw + 20, 1);
	rz_write_le32(raw + 24, base + 0x800); // e_entry
	rz_write_le32(raw + 28, is_rel ? 0 : 0x40); // e_phoff
	rz_write_le32(raw + 32, 0x900); // e_shoff
	rz_write_le16(raw + 40, 52); // e_ehsize
	rz_write_le16(raw + 42, 32); // e_phentsize
	rz_write_le16(raw + 44, is_rel ? 0 : 2); // e_phnum
	rz_write_le16(raw + 46, 40); // e_shentsize
	rz_write_le16(raw + 48, nsh); // e_shnum
	rz_write_le16(raw + 50, 1); // e_shstrndx

	if (!is_rel) {
		// Phdr 0: PT_LOAD (32 bytes)
		ut8 *p0 = raw + 0x40;
		rz_write_le32(p0 + 0, 1); // PT_LOAD
		rz_write_le32(p0 + 4, 0); // p_offset
		rz_write_le32(p0 + 8, base); // p_vaddr
		rz_write_le32(p0 + 12, base); // p_paddr
		rz_write_le32(p0 + 16, sizeof(raw)); // p_filesz
		rz_write_le32(p0 + 20, sizeof(raw)); // p_memsz
		rz_write_le32(p0 + 24, 5); // PF_R | PF_X
		rz_write_le32(p0 + 28, 0x1000); // p_align

		// Phdr 1: PT_DYNAMIC
		ut8 *p1 = raw + 0x40 + 32;
		rz_write_le32(p1 + 0, 2); // PT_DYNAMIC
		rz_write_le32(p1 + 4, 0x200);
		rz_write_le32(p1 + 8, base + 0x200);
		rz_write_le32(p1 + 12, base + 0x200);
		rz_write_le32(p1 + 16, 0x100);
		rz_write_le32(p1 + 20, 0x100);
		rz_write_le32(p1 + 24, 6); // PF_R | PF_W
		rz_write_le32(p1 + 28, 4);

		const ut32 nsyms = (no_imp || res_only) ? 2 : 6;
		const ut32 nrelocs = (flags & SYNTH_ELF_NO_RELOCS) ? 0 : ((no_imp || res_only) ? 1 : 5);

		// Elf32_Dyn at 0x200 (8 bytes each)
		ut8 *d = raw + 0x200;
		const ut32 dyn_entries[][2] = {
			{ 5, base + 0x300 }, // DT_STRTAB
			{ 10, 0x100 }, // DT_STRSZ
			{ 6, base + 0x400 }, // DT_SYMTAB
			{ 11, 16 }, // DT_SYMENT
			{ 4, base + 0x500 }, // DT_HASH
			{ nrelocs ? 20u : 0u, 17 }, // DT_PLTREL = DT_REL
			{ nrelocs ? 23u : 0u, base + 0x580 }, // DT_JMPREL
			{ nrelocs ? 2u : 0u, nrelocs * 8 }, // DT_PLTRELSZ
			{ 0, 0 }, // DT_NULL
		};
		for (size_t i = 0; i < RZ_ARRAY_SIZE(dyn_entries); i++) {
			rz_write_le32(d + i * 8, dyn_entries[i][0]);
			rz_write_le32(d + i * 8 + 4, dyn_entries[i][1]);
		}

		// DT_HASH at 0x500
		rz_write_le32(raw + 0x500, 1);
		rz_write_le32(raw + 0x504, nsyms);

		// .dynsym at 0x400 (Elf32_Sym: 16 bytes: name, value, size, info, other, shndx)
		if (no_imp) {
			ut8 *s1 = raw + 0x400 + 16;
			rz_write_le32(s1 + 0, 53); // "def_sym"
			rz_write_le32(s1 + 4, base + 0x800);
			s1[12] = 0x12;
			rz_write_le16(s1 + 14, 2);
		} else if (res_only) {
			// Single pre-resolved undefined import (no defined symbols -> bin->symbols == NULL)
			ut8 *s1 = raw + 0x400 + 16;
			rz_write_le32(s1 + 0, 1); // "imp_res"
			rz_write_le32(s1 + 4, base + 0x820);
			s1[12] = 0x12;
		} else {
			ut8 *s = raw + 0x400 + 1 * 16;
			rz_write_le32(s + 0, 0);
			rz_write_le32(s + 8, 4); // st_size=4 -> initial vaddr==0
			s[12] = 0x12;
			s = raw + 0x400 + 2 * 16;
			rz_write_le32(s + 0, 1); // "imp_res"
			s[12] = 0x12;
			s = raw + 0x400 + 3 * 16;
			rz_write_le32(s + 0, 9); // "imp_unres"
			s[12] = 0x12;
			s = raw + 0x400 + 4 * 16;
			rz_write_le32(s + 0, (flags & SYNTH_ELF_RUST_IMP) ? 42 : 19);
			rz_write_le32(s + 4, base + 0x820);
			s[12] = 0x12;
			s = raw + 0x400 + 5 * 16;
			rz_write_le32(s + 0, 53); // "def_sym"
			rz_write_le32(s + 4, base + 0x800);
			s[12] = 0x12;
			rz_write_le16(s + 14, 2);
		}

		// .rel.plt at 0x580 (Elf32_Rel: 8 bytes) & GOT at 0x700
		if ((no_imp || res_only) && nrelocs) {
			ut8 *r = raw + 0x580;
			rz_write_le32(r + 0, base + 0x700);
			rz_write_le32(r + 4, ((res_only ? 2u : 1u) << 8) | 7); // R_386_JMP_SLOT
		} else if (nrelocs) {
			rz_write_le32(raw + 0x700, base + 0x806);
			rz_write_le32(raw + 0x704, base + 0x816);
			rz_write_le32(raw + 0x708, 0);
			const struct {
				ut32 off;
				ut32 sym;
				ut32 type;
			} rels[5] = {
				{ base + 0x700, 2, 7 }, // R_386_JMP_SLOT
				{ base + 0x704, 2, 7 }, // duplicate
				{ base + 0x708, 3, 7 }, // unresolved GOT=0
				{ base + 0x70c, 5, 7 }, // defined sym
				{ base + 0x710, 99, 7 }, // missing ordinal
			};
			for (size_t i = 0; i < 5; i++) {
				ut8 *r = raw + 0x580 + i * 8;
				rz_write_le32(r + 0, rels[i].off);
				rz_write_le32(r + 4, (rels[i].sym << 8) | rels[i].type);
			}
		}
	}

	// .symtab at 0x780 (3 entries, 16 bytes each)
	if (is_rel) {
		ut8 *s1 = raw + 0x780 + 1 * 16;
		rz_write_le32(s1 + 0, 9);
		rz_write_le32(s1 + 4, 0);
		rz_write_le32(s1 + 8, 4);
		s1[12] = 0x12;
		ut8 *s2 = raw + 0x780 + 2 * 16;
		rz_write_le32(s2 + 0, 1);
		rz_write_le32(s2 + 4, 0x100);
		rz_write_le32(s2 + 8, 4);
		s2[12] = 0x12;
	} else {
		ut8 *s1 = raw + 0x780 + 1 * 16;
		rz_write_le32(s1 + 0, 0);
		rz_write_le32(s1 + 4, base + 0x800);
		s1[12] = 0x12;
		rz_write_le16(s1 + 14, 2);
		ut8 *s2 = raw + 0x780 + 2 * 16;
		rz_write_le32(s2 + 0, (flags & SYNTH_ELF_RUST_SYM) ? 42 : 53);
		rz_write_le32(s2 + 4, base + 0x810);
		s2[12] = 0x12;
		rz_write_le16(s2 + 14, 2);
	}

	// Section headers at 0x900 (Elf32_Shdr: 40 bytes)
	ut8 *sh = raw + 0x900 + 1 * 40;
	rz_write_le32(sh + 0, 1);
	rz_write_le32(sh + 4, 3); // SHT_STRTAB
	rz_write_le32(sh + 16, 0x880);
	rz_write_le32(sh + 20, 0x80);
	sh = raw + 0x900 + 2 * 40;
	rz_write_le32(sh + 0, 11);
	rz_write_le32(sh + 4, 1); // SHT_PROGBITS
	rz_write_le32(sh + 8, 6);
	rz_write_le32(sh + 12, base + 0x800);
	rz_write_le32(sh + 16, 0x800);
	rz_write_le32(sh + 20, 0x80);
	sh = raw + 0x900 + 3 * 40;
	rz_write_le32(sh + 0, 17);
	rz_write_le32(sh + 4, 3); // SHT_STRTAB
	rz_write_le32(sh + 16, 0x300);
	rz_write_le32(sh + 20, 0x100);
	sh = raw + 0x900 + 4 * 40;
	rz_write_le32(sh + 0, 25);
	rz_write_le32(sh + 4, 2); // SHT_SYMTAB
	rz_write_le32(sh + 16, 0x780);
	rz_write_le32(sh + 20, 3 * 16);
	rz_write_le32(sh + 24, 3); // sh_link = .strtab
	rz_write_le32(sh + 36, 16); // sh_entsize
	if (has_rg) {
		sh = raw + 0x900 + 5 * 40;
		rz_write_le32(sh + 0, 33);
		rz_write_le32(sh + 4, (flags & SYNTH_ELF_RETGUARD_NOBITS) ? 8 : 1);
		rz_write_le32(sh + 8, 2);
		rz_write_le32(sh + 12, base + 0x800);
		rz_write_le32(sh + 16, 0x800);
		rz_write_le32(sh + 20, 64);
	}

	return rz_buf_new_with_bytes(raw, sizeof(raw));
}

static bool check_synth_elf_variant(bool is64, ut32 flags, const char *expect_lang, bool expect_retguard) {
	RzBin *bin = rz_bin_new();
	mu_assert_notnull(bin, "rz_bin_new");
	RzIO *io = rz_io_new();
	mu_assert_notnull(io, "rz_io_new");
	rz_io_bind(io, &bin->iob);

	RzBuffer *buf = is64 ? build_synth_elf64(flags) : build_synth_elf32(flags);
	mu_assert_notnull(buf, "synth elf buf");
	RzBinOptions bopt;
	rz_bin_options_init(&bopt, -1, UT64_MAX, 0, false);
	bopt.filename = is64 ? "synth64.elf" : "synth32.elf";

	RzBinFile *bf = rz_bin_open_buf(bin, buf, &bopt);
	mu_assert_notnull(bf, "open synth elf");
	mu_assert_notnull(bf->o, "elf bin object");
	const RzBinInfo *binfo = rz_bin_object_get_info(bf->o);
	mu_assert_notnull(binfo, "elf bin info");
	if (expect_lang) {
		mu_assert_streq(binfo->lang, expect_lang, "detected lang");
	}
	mu_assert_eq(binfo->has_retguard, expect_retguard, "retguard detection");

	// Access imports, symbols, and relocs to exercise ordinal index lookups.
	const RzPVector *imps = rz_bin_object_get_imports(bf->o);
	mu_assert_notnull(imps, "imports");
	const RzPVector *syms = rz_bin_object_get_symbols(bf->o);
	mu_assert_notnull(syms, "symbols");
	RzBinRelocStorage *relocs = rz_bin_object_patch_relocs(bf, bf->o);
	mu_assert_notnull(relocs, "relocs");

	if (!(flags & (SYNTH_ELF_REL | SYNTH_ELF_NO_IMPORTS | SYNTH_ELF_NO_RELOCS | SYNTH_ELF_RESOLVED_ONLY))) {
		bool saw_resolved = false;
		void **it;
		rz_pvector_foreach (syms, it) {
			RzBinSymbol *sym = *it;
			if (sym->name && !strcmp(sym->name, "imp_res") && sym->is_imported) {
				saw_resolved = (sym->vaddr == (is64 ? 0x400800 : 0x08048800));
			}
		}
		mu_assert_true(saw_resolved, "resolved import PLT vaddr");
	}

	rz_buf_free(buf);
	rz_bin_free(bin);
	rz_io_free(io);
	return true;
}

bool test_bin_elf_indexing_and_info(void) {
	for (int mode = 0; mode < 2; mode++) {
		bool is64 = mode == 1;
		mu_assert_true(check_synth_elf_variant(is64, SYNTH_ELF_RETGUARD_PROGBITS, "c blocks ext.", true), "blocks + retguard progbits");
		mu_assert_true(check_synth_elf_variant(is64, SYNTH_ELF_RETGUARD_NOBITS | SYNTH_ELF_RUST_SYM, "rust", false), "rust sym + retguard nobits");
		mu_assert_true(check_synth_elf_variant(is64, SYNTH_ELF_RUST_IMP, "rust", false), "rust import + no retguard");
		mu_assert_true(check_synth_elf_variant(is64, SYNTH_ELF_NO_IMPORTS, NULL, false), "dynamic relocs with no imports");
		mu_assert_true(check_synth_elf_variant(is64, SYNTH_ELF_NO_RELOCS, NULL, false), "dynamic without relocs");
		mu_assert_true(check_synth_elf_variant(is64, SYNTH_ELF_NO_RELOCS | SYNTH_ELF_NO_IMPORTS, NULL, false), "dynamic without relocs or imports");
		mu_assert_true(check_synth_elf_variant(is64, SYNTH_ELF_RESOLVED_ONLY, NULL, false), "pre-resolved import with no defined symbols");
		mu_assert_true(check_synth_elf_variant(is64, SYNTH_ELF_REL, NULL, false), "ET_REL without dynamic/relocs");
	}
	mu_end;
}

bool all_tests() {
	mu_run_test(test_map);
	mu_run_test(test_cfile_close);
	mu_run_test(test_cfile_close_multiple);
	mu_run_test(test_cfile_close_manual_maps);
	mu_run_test(test_cfile_close_manual_fd);
	mu_run_test(test_cfile_close_manual_vfile_fd);
	mu_run_test(test_cfile_close_manual_vfile_map);
	mu_run_test(test_cfile_close_manual_cfile_map_multiple);
	mu_run_test(test_bin_set_export_info);
	mu_run_test(test_golang_oversized_bb_strings);
	mu_run_test(test_bin_classes_lazy_sort);
	mu_run_test(test_bin_trycatch_index);
	mu_run_test(test_analysis_trycatch_handlers);
	mu_run_test(test_bin_elf_indexing_and_info);
	return tests_passed != tests_run;
}

mu_main(all_tests)
