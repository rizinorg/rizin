// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
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

static bool test_vtable_api_and_edge_cases(void) {
	rz_analysis_vtable_info_free(NULL);

	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new");
	rz_config_set(core->config, "asm.arch", "x86");
	RzCoreFile *cf = rz_core_file_open(core, "malloc://16", RZ_PERM_RWX, 0);
	mu_assert_notnull(cf, "open malloc://16");
	mu_assert_notnull(rz_io_map_add(core->io, cf->fd, RZ_PERM_RWX, 0, 0, 16), "map malloc://16");
	const ut8 bytes[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	mu_assert_true(rz_io_write_at(core->io, 0, bytes, sizeof(bytes)), "write test bytes");

	static const struct {
		int bits;
		ut8 ws;
		ut64 le;
		ut64 be;
	} cases[] = {
		{ 8, 1, 0x01ULL, 0x01ULL },
		{ 16, 2, 0x0201ULL, 0x0102ULL },
		{ 32, 4, 0x04030201ULL, 0x01020304ULL },
		{ 64, 8, 0x0807060504030201ULL, 0x0102030405060708ULL },
	};

	RVTableContext ctx = { 0 };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		mu_assert_true(rz_analysis_set_bits(core->analysis, cases[i].bits), "set_bits");
		rz_analysis_set_big_endian(core->analysis, false);
		mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "vtable_begin LE");
		mu_assert_eq(ctx.word_size, cases[i].ws, "word_size LE");
		ut64 val = 0;
		mu_assert_true(ctx.read_addr(core->analysis, 0, &val), "read_addr LE");
		mu_assert_eq(val, cases[i].le, "read_addr LE value");
		mu_assert_false(ctx.read_addr(core->analysis, 0x1000, &val), "read_addr OOB");

		rz_analysis_set_big_endian(core->analysis, true);
		mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "vtable_begin BE");
		mu_assert_true(ctx.read_addr(core->analysis, 0, &val), "read_addr BE");
		mu_assert_eq(val, cases[i].be, "read_addr BE value");
	}

	mu_assert_true(rz_analysis_set_bits(core->analysis, 64), "set_bits 64");
	rz_analysis_set_big_endian(core->analysis, false);
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "vtable_begin 64");

	RVTableInfo info = { 0 };
	rz_vector_init(&info.methods, sizeof(RVTableMethodInfo), NULL, NULL);
	mu_assert_eq(rz_analysis_vtable_info_get_size(&ctx, &info), 0, "empty vtable size");
	RVTableMethodInfo m = { .addr = 0x1000, .vtable_offset = 0 };
	rz_vector_push(&info.methods, &m);
	rz_vector_push(&info.methods, &m);
	mu_assert_eq(rz_analysis_vtable_info_get_size(&ctx, &info), 16, "2-method vtable size");
	rz_vector_fini(&info.methods);

	mu_assert_null(rz_analysis_vtable_parse_at(&ctx, 0x1000), "parse_at unmapped returns NULL");

	/* No bin object loaded -> sections == NULL */
	mu_assert_null(rz_analysis_vtable_search(&ctx), "search without bin sections returns NULL");

	/* NULL analysis guard */
	RVTableContext empty_ctx = { 0 };
	mu_assert_null(rz_analysis_vtable_search(&empty_ctx), "search with NULL analysis returns NULL");

	rz_core_free(core);
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
	mu_run_test(test_vtable_api_and_edge_cases);
	return tests_passed != tests_run;
}

mu_main(all_tests)
