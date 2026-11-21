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

static RzPVector *vtable_mock_sections(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);

	RzBinSection *text = RZ_NEW0(RzBinSection);
	text->name = rz_str_dup(".text");
	text->paddr = 0;
	text->vaddr = 0x1000;
	text->size = 0x100;
	text->vsize = 0x100;
	text->perm = RZ_PERM_RX;
	rz_pvector_push(ret, text);

	// Small .rodata (< word_size = 8) previously underflowed ut64 and broke
	// out of the section loop.
	RzBinSection *small_rodata = RZ_NEW0(RzBinSection);
	small_rodata->name = rz_str_dup(".rodata");
	small_rodata->paddr = 0;
	small_rodata->vaddr = 0x2000;
	small_rodata->size = 4;
	small_rodata->vsize = 4;
	small_rodata->perm = RZ_PERM_R;
	rz_pvector_push(ret, small_rodata);

	RzBinSection *relro = RZ_NEW0(RzBinSection);
	relro->name = rz_str_dup(".data.rel.ro");
	relro->paddr = 0;
	relro->vaddr = 0x3000;
	relro->size = 0x40;
	relro->vsize = 0x40;
	relro->perm = RZ_PERM_R;
	rz_pvector_push(ret, relro);

	return ret;
}

static RzPVector *vtable_mock_maps(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);

	RzBinMap *m = RZ_NEW0(RzBinMap);
	m->name = rz_str_dup("relro");
	m->paddr = 0;
	m->vaddr = 0x3000;
	m->psize = 0x40;
	m->vsize = 0x40;
	m->perm = RZ_PERM_R;
	rz_pvector_push(ret, m);

	return ret;
}

static RzBinPlugin vtable_mock_plugin = {
	.name = "vtable_mock",
	.desc = "Testing VTable Plugin",
	.license = "LGPL3",
	.load_buffer = load_buffer,
	.check_buffer = check_buffer,
	.sections = vtable_mock_sections,
	.maps = vtable_mock_maps,
	.info = info,
};

static RzPVector *vtable_high_addr_sections(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);

	RzBinSection *text = RZ_NEW0(RzBinSection);
	text->name = rz_str_dup(".text");
	text->paddr = 0;
	text->vaddr = 0x1000;
	text->size = 0x100;
	text->vsize = 0x100;
	text->perm = RZ_PERM_RX;
	rz_pvector_push(ret, text);

	// Section at UT64_MAX - 15 (0xfffffffffffffff0) of size 8
	// (triggers chunk_base + 2*ws wrap if unguarded).
	RzBinSection *hi_relro = RZ_NEW0(RzBinSection);
	hi_relro->name = rz_str_dup(".data.rel.ro");
	hi_relro->paddr = 0x10;
	hi_relro->vaddr = UT64_MAX - 15;
	hi_relro->size = 8;
	hi_relro->vsize = 8;
	hi_relro->perm = RZ_PERM_R;
	rz_pvector_push(ret, hi_relro);

	// Section reaching UT64_MAX inclusive (vaddr = 0xfffffffffffffff0, vsize = 0x10).
	RzBinSection *hi_rodata = RZ_NEW0(RzBinSection);
	hi_rodata->name = rz_str_dup(".rodata");
	hi_rodata->paddr = 0x10;
	hi_rodata->vaddr = UT64_MAX - 15;
	hi_rodata->size = 0x10;
	hi_rodata->vsize = 0x10;
	hi_rodata->perm = RZ_PERM_R;
	rz_pvector_push(ret, hi_rodata);

	return ret;
}

static RzPVector *vtable_high_addr_maps(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);

	// Map [0xffffffffffffffe0, 0xfffffffffffffff8) (size 0x18) so
	// offset_to_top/rtti/method0 are readable.
	RzBinMap *m = RZ_NEW0(RzBinMap);
	m->name = rz_str_dup("hi_relro");
	m->paddr = 0;
	m->vaddr = UT64_MAX - 31;
	m->psize = 0x18;
	m->vsize = 0x18;
	m->perm = RZ_PERM_R;
	rz_pvector_push(ret, m);

	return ret;
}

static RzBinPlugin vtable_high_addr_plugin = {
	.name = "vtable_high_addr_mock",
	.desc = "Testing High Address VTable Plugin",
	.license = "LGPL3",
	.load_buffer = load_buffer,
	.check_buffer = check_buffer,
	.sections = vtable_high_addr_sections,
	.maps = vtable_high_addr_maps,
	.info = info,
};

static RzPVector *vtable_pa_sections(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);

	RzBinSection *text = RZ_NEW0(RzBinSection);
	text->name = rz_str_dup(".text");
	text->paddr = 0;
	text->vaddr = 0x1000;
	text->size = 0x100;
	text->vsize = 0x100;
	text->perm = RZ_PERM_RX;
	rz_pvector_push(ret, text);

	RzBinSection *relro = RZ_NEW0(RzBinSection);
	relro->name = rz_str_dup(".data.rel.ro");
	relro->paddr = 0;
	relro->vaddr = 0;
	relro->size = 0x40;
	relro->vsize = 0x40;
	relro->perm = RZ_PERM_R;
	rz_pvector_push(ret, relro);

	return ret;
}

static RzPVector *vtable_pa_maps(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);

	RzBinMap *m = RZ_NEW0(RzBinMap);
	m->name = rz_str_dup("relro_pa");
	m->paddr = 0;
	m->vaddr = 0;
	m->psize = 0x20;
	m->vsize = 0x40;
	m->perm = RZ_PERM_R;
	rz_pvector_push(ret, m);

	return ret;
}

static RzBinPlugin vtable_pa_plugin = {
	.name = "vtable_pa_mock",
	.desc = "Testing PA VTable Plugin",
	.license = "LGPL3",
	.load_buffer = load_buffer,
	.check_buffer = check_buffer,
	.sections = vtable_pa_sections,
	.maps = vtable_pa_maps,
	.info = info,
};

bool test_vtable_search_small_rodata_underflow(void) {
	RzCore *core = rz_core_new();
	rz_bin_plugin_add(core->bin, &vtable_mock_plugin);
	rz_analysis_use(core->analysis, "x86");
	rz_analysis_set_bits(core->analysis, 64);
	rz_analysis_set_cpp_abi(core->analysis, RZ_ANALYSIS_CPP_ABI_ITANIUM);

	// 0x3000: offset_to_top = 0
	// 0x3008: rtti = 0x3030 (inside .data.rel.ro)
	// 0x3010: method 0 = 0x1010 (inside .text)
	// 0x3018: method 1 = 0x1020 (inside .text)
	// 0x3020..0x303f: zeroes
	const char *uri =
		"hex://"
		"0000000000000000"
		"3030000000000000"
		"1010000000000000"
		"2010000000000000"
		"0000000000000000"
		"0000000000000000"
		"0000000000000000"
		"0000000000000000";
	RzCoreFile *f = rz_core_file_open(core, uri, RZ_PERM_R, 0);
	mu_assert_notnull(f, "open vtable mock file");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "load vtable mock bin");

	RVTableContext ctx;
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "vtable begin");
	RzList *vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_notnull(vtables, "vtable found after small .rodata section");
	mu_assert_eq(rz_list_length(vtables), 1, "one vtable found");

	RVTableInfo *vt = rz_list_first_val(vtables);
	mu_assert_eq(vt->saddr, 0x3010, "vtable saddr");
	mu_assert_eq(rz_vector_len(&vt->methods), 2, "two methods");
	RVTableMethodInfo *m0 = rz_vector_index_ptr(&vt->methods, 0);
	RVTableMethodInfo *m1 = rz_vector_index_ptr(&vt->methods, 1);
	mu_assert_eq(m0->addr, 0x1010, "method 0");
	mu_assert_eq(m1->addr, 0x1020, "method 1");

	rz_list_free(vtables);
	rz_core_free(core);
	mu_end;
}

bool test_vtable_search_boundaries(void) {
	// 1. High address near UT64_MAX (must not wrap or underflow chunk buffer).
	RzCore *core = rz_core_new();
	rz_bin_plugin_add(core->bin, &vtable_high_addr_plugin);
	rz_analysis_use(core->analysis, "x86");
	rz_analysis_set_bits(core->analysis, 64);
	rz_analysis_set_cpp_abi(core->analysis, RZ_ANALYSIS_CPP_ABI_ITANIUM);

	// paddr 0x00 (0xffffffffffffffe0): offset_to_top = 0
	// paddr 0x08 (0xffffffffffffffe8): rtti = 0
	// paddr 0x10 (0xfffffffffffffff0): method 0 = 0x1010 (.text)
	// paddr 0x18 (0xfffffffffffffff8): zeroes
	const char *hi_uri =
		"hex://"
		"0000000000000000"
		"0000000000000000"
		"1010000000000000"
		"0000000000000000";
	RzCoreFile *f = rz_core_file_open(core, hi_uri, RZ_PERM_R, 0);
	mu_assert_notnull(f, "open high-addr vtable file");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "load high-addr vtable bin");

	RVTableContext ctx;
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "high-addr vtable begin");
	RzList *vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_notnull(vtables, "high-addr vtable found without overflow");
	mu_assert_eq(rz_list_length(vtables), 2, "both high-addr sections scanned cleanly");
	RVTableInfo *vt = rz_list_first_val(vtables);
	mu_assert_eq(vt->saddr, UT64_MAX - 15, "high-addr vtable saddr");
	mu_assert_eq(rz_vector_len(&vt->methods), 1, "high-addr vtable has 1 method");
	rz_list_free(vtables);
	rz_core_free(core);

	// 2. Overlaid non-readable map inside a readable section must stop scanning
	// (parity with is_valid_offset).
	core = rz_core_new();
	rz_bin_plugin_add(core->bin, &vtable_mock_plugin);
	rz_analysis_use(core->analysis, "x86");
	rz_analysis_set_bits(core->analysis, 64);
	rz_analysis_set_cpp_abi(core->analysis, RZ_ANALYSIS_CPP_ABI_ITANIUM);

	// 0x3000..0x3017: zeroes
	// 0x3018: offset_to_top = 0, 0x3020: rtti = 0, 0x3028: method 0 = 0x1010
	const char *overlay_uri =
		"hex://"
		"0000000000000000"
		"0000000000000000"
		"0000000000000000"
		"0000000000000000"
		"0000000000000000"
		"1010000000000000"
		"0000000000000000"
		"0000000000000000";
	f = rz_core_file_open(core, overlay_uri, RZ_PERM_R, 0);
	mu_assert_notnull(f, "open overlay vtable file");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "load overlay vtable bin");

	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "overlay vtable begin");
	vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_notnull(vtables, "vtable found before non-readable overlay");
	vt = rz_list_first_val(vtables);
	mu_assert_eq(vt->saddr, 0x3028, "overlay baseline saddr");
	rz_list_free(vtables);

	// Overlay [0x3010, 0x3018) with a higher-priority non-readable map.
	RzIOMap *nr_map = rz_io_map_add(core->io, f->fd, 0, 0, 0x3010, 8);
	mu_assert_notnull(nr_map, "add non-readable overlay map");
	vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_null(vtables, "scan stops at non-readable overlay instead of crossing to 0x3028");
	rz_core_free(core);

	// 3. io.va = false must stop past desc EOF even when an IO map extends
	// past EOF and cache has data.
	core = rz_core_new();
	rz_bin_plugin_add(core->bin, &vtable_pa_plugin);
	rz_analysis_use(core->analysis, "x86");
	rz_analysis_set_bits(core->analysis, 64);
	rz_analysis_set_cpp_abi(core->analysis, RZ_ANALYSIS_CPP_ABI_ITANIUM);

	// 0x20-byte file of zeroes; map extends to 0x40.
	const char *pa_uri =
		"hex://"
		"0000000000000000"
		"0000000000000000"
		"0000000000000000"
		"0000000000000000";
	f = rz_core_file_open(core, pa_uri, RZ_PERM_R, 0);
	mu_assert_notnull(f, "open pa vtable file");
	mu_assert_true(rz_core_bin_load(core, NULL, 0), "load pa vtable bin");

	core->io->va = false;
	core->io->cached = RZ_PERM_RW;
	ut8 past_eof_vtable[24] = { 0 };
	rz_write_le64(past_eof_vtable + 16, 0x1010);
	mu_assert_true(rz_io_cache_write(core->io, 0x18, past_eof_vtable, sizeof(past_eof_vtable)),
		"write cached vtable past EOF");

	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "pa vtable begin");
	vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_null(vtables,
		"io.va=false stops past EOF instead of scanning cached vtable at 0x28");

	// Also verify io.va = false finds a vtable strictly within [0, desc_size).
	ut8 in_bounds_vtable[24] = { 0 };
	rz_write_le64(in_bounds_vtable + 16, 0x1010);
	mu_assert_true(rz_io_cache_write(core->io, 0x0, in_bounds_vtable, sizeof(in_bounds_vtable)),
		"write cached vtable in bounds");
	vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_notnull(vtables, "io.va=false finds in-bounds vtable at 0x10");
	vt = rz_list_first_val(vtables);
	mu_assert_eq(vt->saddr, 0x10, "io.va=false vtable saddr");
	rz_list_free(vtables);
	rz_core_free(core);

	mu_end;
}

#define VT_SEC(n, va, sz, vsz, p) \
	{ .name = (n), .vaddr = (va), .size = (sz), .vsize = (vsz), .perm = (p) }
#define VT_MAP(n, pa, va, psz, vsz, p) \
	{ .name = (n), .paddr = (pa), .vaddr = (va), .psize = (psz), .vsize = (vsz), .perm = (p) }
#define VT_CFG(s, m) { (s), RZ_ARRAY_SIZE(s), (m), RZ_ARRAY_SIZE(m) }

typedef struct {
	const RzBinSection *sections;
	size_t section_count;
	const RzBinMap *maps;
	size_t map_count;
} VTableTestCfg;

static VTableTestCfg g_vt_cfg;

static RzPVector *vtable_cfg_sections(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	for (size_t i = 0; i < g_vt_cfg.section_count; i++) {
		RzBinSection *s = RZ_NEW0(RzBinSection);
		*s = g_vt_cfg.sections[i];
		s->name = g_vt_cfg.sections[i].name ? rz_str_dup(g_vt_cfg.sections[i].name) : NULL;
		rz_pvector_push(ret, s);
	}
	return ret;
}

static RzPVector *vtable_cfg_maps(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	for (size_t i = 0; i < g_vt_cfg.map_count; i++) {
		RzBinMap *m = RZ_NEW0(RzBinMap);
		*m = g_vt_cfg.maps[i];
		m->name = g_vt_cfg.maps[i].name ? rz_str_dup(g_vt_cfg.maps[i].name) : NULL;
		rz_pvector_push(ret, m);
	}
	return ret;
}

static RzBinPlugin vtable_cfg_plugin = {
	.name = "vtable_cfg_mock",
	.desc = "Configurable Testing VTable Plugin",
	.license = "LGPL3",
	.load_buffer = load_buffer,
	.check_buffer = check_buffer,
	.sections = vtable_cfg_sections,
	.maps = vtable_cfg_maps,
	.info = info,
};

typedef struct {
	bool has_fail_addr;
	ut64 fail_addr;
	int fail_on_hit;
	int fail_hits;
	bool has_break_addr;
	ut64 break_addr;
	int break_on_hit;
	int break_hits;
	bool force_const;
	ut64 const_val;
	ut8 ws;
} VTableReadHook;

static VTableReadHook g_vt_hook;

static bool vtable_always_valid_offset(RzIO *io, ut64 offset, int hasperm) {
	return true;
}

static ut64 g_vt_invalid_off = UT64_MAX;

static bool vtable_fail_valid_at(RzIO *io, ut64 offset, int hasperm) {
	return offset != g_vt_invalid_off;
}

static bool vtable_custom_read_addr(RzAnalysis *analysis, ut64 addr, ut64 *buf) {
	if (g_vt_hook.has_break_addr && addr == g_vt_hook.break_addr) {
		g_vt_hook.break_hits++;
		if (g_vt_hook.break_on_hit == 0 || g_vt_hook.break_hits == g_vt_hook.break_on_hit) {
			rz_interrupt_set_breaked(analysis->intr, true);
		}
	}
	if (g_vt_hook.has_fail_addr && addr == g_vt_hook.fail_addr) {
		g_vt_hook.fail_hits++;
		if (g_vt_hook.fail_on_hit == 0 || g_vt_hook.fail_hits == g_vt_hook.fail_on_hit) {
			return false;
		}
	}
	if (g_vt_hook.force_const) {
		*buf = g_vt_hook.const_val;
		return true;
	}
	ut8 tmp[8] = { 0 };
	ut8 ws = g_vt_hook.ws ? g_vt_hook.ws : (ut8)(analysis->bits / 8);
	if (!analysis->iob.read_at(analysis->iob.io, addr, tmp, ws)) {
		return false;
	}
	if (ws == 1 || ws == 2 || ws == 4 || ws == 8) {
		*buf = rz_read_ble(tmp, analysis->big_endian, ws * 8);
	} else {
		*buf = 0;
	}
	return true;
}

static RzCore *vtable_open_cfg(
	const VTableTestCfg *cfg, const ut8 *data, size_t len, int bits, bool be) {
	g_vt_cfg = *cfg;
	RzCore *core = rz_core_new();
	if (!core) {
		return NULL;
	}
	rz_bin_plugin_add(core->bin, &vtable_cfg_plugin);
	rz_analysis_use(core->analysis, "x86");
	core->analysis->bits = bits;
	core->analysis->big_endian = be;
	rz_analysis_set_cpp_abi(core->analysis, RZ_ANALYSIS_CPP_ABI_ITANIUM);

	char uri[64];
	snprintf(uri, sizeof(uri), "malloc://%" PFMT64u, (ut64)(len ? len : 16));
	RzCoreFile *f = rz_core_file_open(core, uri, RZ_PERM_RW, 0);
	if (!f) {
		rz_core_free(core);
		return NULL;
	}
	if (data && len) {
		rz_io_desc_write_at(core->io->desc, 0, data, len);
	}
	if (!rz_core_bin_load(core, NULL, 0)) {
		rz_core_free(core);
		return NULL;
	}
	return core;
}

bool test_vtable_search_word_sizes_and_endianness(void) {
	static const RzBinSection secs[] = {
		VT_SEC(".text", 0x40, 0x20, 0x20, RZ_PERM_RX),
		VT_SEC(".data.rel.ro", 0x60, 0x40, 0x40, RZ_PERM_R),
	};
	static const RzBinMap mps[] = {
		VT_MAP("relro", 0, 0x60, 0x40, 0x40, RZ_PERM_R),
	};
	const VTableTestCfg cfg = VT_CFG(secs, mps);
	static const int bit_sizes[] = { 8, 16, 32, 64 };

	for (size_t i = 0; i < RZ_ARRAY_SIZE(bit_sizes); i++) {
		const int bits = bit_sizes[i];
		const ut8 ws = (ut8)(bits / 8);
		for (int be_i = 0; be_i < 2; be_i++) {
			const bool be = be_i != 0;
			ut8 buf[0x40] = { 0 };
			rz_write_ble(buf, 0, be, bits);
			rz_write_ble(buf + ws, 0x60 + 4 * ws, be, bits);
			rz_write_ble(buf + 2 * ws, 0x44, be, bits);
			rz_write_ble(buf + 3 * ws, 0x48, be, bits);

			RzCore *core = vtable_open_cfg(&cfg, buf, sizeof(buf), bits, be);
			mu_assert_notnull(core, "open word-size mock");

			RVTableContext ctx;
			bool ok = rz_analysis_vtable_begin(core->analysis, &ctx);
			mu_assert_true(ok, "vtable begin");
			RzList *vtables = rz_analysis_vtable_search(&ctx);
			mu_assert_notnull(vtables, "vtable found for word size and endianness");
			mu_assert_eq(rz_list_length(vtables), 1, "one vtable");
			RVTableInfo *vt = rz_list_first_val(vtables);
			mu_assert_eq(vt->saddr, (ut64)(0x60 + 2 * ws), "vtable saddr");
			mu_assert_eq(rz_vector_len(&vt->methods), 2, "two methods");
			RVTableMethodInfo *m0 = rz_vector_index_ptr(&vt->methods, 0);
			RVTableMethodInfo *m1 = rz_vector_index_ptr(&vt->methods, 1);
			mu_assert_eq(m0->addr, 0x44, "method 0");
			mu_assert_eq(m1->addr, 0x48, "method 1");

			rz_list_free(vtables);
			rz_core_free(core);
		}
	}

	// Non-standard word_size hits default branch in vtable_has_default_read_addr
	// and falls back to unbuffered reads.
	ut8 zeroes[0x40] = { 0 };
	RzCore *core = vtable_open_cfg(&cfg, zeroes, sizeof(zeroes), 64, false);
	mu_assert_notnull(core, "open default word_size mock");
	RVTableContext ctx;
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "vtable begin");
	memset(&g_vt_hook, 0, sizeof(g_vt_hook));
	g_vt_hook.ws = 3;
	ctx.word_size = 3;
	ctx.read_addr = vtable_custom_read_addr;
	mu_assert_null(rz_analysis_vtable_search(&ctx), "no vtable with custom word_size 3");
	rz_core_free(core);

	mu_end;
}

bool test_vtable_search_section_cache_edge_cases(void) {
	// 1. NULL analysis and unloaded binary return NULL.
	RVTableContext ctx = { 0 };
	mu_assert_null(rz_analysis_vtable_search(&ctx), "NULL analysis returns NULL");

	RzCore *core = rz_core_new();
	rz_analysis_use(core->analysis, "x86");
	rz_analysis_set_bits(core->analysis, 64);
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin unloaded");
	mu_assert_null(rz_analysis_vtable_search(&ctx), "unloaded bin returns NULL");
	rz_core_free(core);

	// 2. Empty sections vector hits rz_pvector_empty and !has_text early return.
	const VTableTestCfg empty_cfg = { NULL, 0, NULL, 0 };
	core = vtable_open_cfg(&empty_cfg, NULL, 0, 64, false);
	mu_assert_notnull(core, "open empty sections mock");
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin empty sections");
	mu_assert_null(rz_analysis_vtable_search(&ctx), "empty sections returns NULL");
	rz_core_free(core);

	// 3. Single non-text section (count == 1, !has_text) and single text section
	// (count == 1, has_text).
	static const RzBinSection ro_only[] = {
		VT_SEC(".rodata", 0x3000, 0x20, 0x20, RZ_PERM_R),
	};
	const VTableTestCfg ro_cfg = { ro_only, RZ_ARRAY_SIZE(ro_only), NULL, 0 };
	core = vtable_open_cfg(&ro_cfg, NULL, 0, 64, false);
	mu_assert_notnull(core, "open ro_only mock");
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin ro_only");
	mu_assert_null(rz_analysis_vtable_search(&ctx), "ro_only has no text section");
	rz_core_free(core);

	static const RzBinSection text_only[] = {
		VT_SEC(".text", 0x1000, 0x100, 0x100, RZ_PERM_RX),
	};
	const VTableTestCfg text_cfg = { text_only, RZ_ARRAY_SIZE(text_only), NULL, 0 };
	core = vtable_open_cfg(&text_cfg, NULL, 0, 64, false);
	mu_assert_notnull(core, "open text_only mock");
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin text_only");
	mu_assert_null(rz_analysis_vtable_search(&ctx), "text_only has no vtable sections");
	rz_core_free(core);

	// 4. Multi-.text, gaps, non-exec .text, segments, zero/oversized sections,
	// RTTI rejections, and xref stop.
	static const RzBinSection multi_secs[] = {
		{
			.name = "LOAD0",
			.vaddr = 0x1000,
			.size = 0x100,
			.vsize = 0x100,
			.perm = RZ_PERM_RX,
			.is_segment = true,
		},
		VT_SEC(".rdata", 0x1200, 0, 0, RZ_PERM_R),
		VT_SEC(".text_ro", 0x1300, 0x100, 0x100, RZ_PERM_R),
		VT_SEC(".text_mid", 0x2000, 0x100, 0x100, RZ_PERM_RX),
		VT_SEC(".text_lo", 0x1000, 0x100, 0x100, RZ_PERM_RX),
		VT_SEC(".text_hi", 0x4000, 0x100, 0x100, RZ_PERM_RX),
		VT_SEC(".rodata", 0x3000, 0x100, 0x100, RZ_PERM_R),
		VT_SEC("big__const", 0x6000, 0x10, (ut64)ST32_MAX + 0x100, RZ_PERM_R),
		VT_SEC(".data.rel.ro", 0x5000, 0x100, 0x100, RZ_PERM_R),
	};
	static const RzBinMap multi_mps[] = {
		VT_MAP("relro", 0, 0x5000, 0x100, 0x100, RZ_PERM_R),
	};
	ut8 multi_buf[0x100] = { 0 };
	rz_write_le64(multi_buf + 0x00, 0x1500); // gap between .text_lo and .text_mid
	rz_write_le64(multi_buf + 0x08, 0x3010); // non-text .rodata between .text_mid and .text_hi
	rz_write_le64(multi_buf + 0x10, 0); // offset_to_top = 0
	rz_write_le64(multi_buf + 0x18, 0x100); // RTTI below lowest section (!lo in cache_find)
	rz_write_le64(multi_buf + 0x20, 0x1010); // rejected: invalid RTTI
	rz_write_le64(multi_buf + 0x28, 0); // offset_to_top = 0
	rz_write_le64(multi_buf + 0x30, 0x1010); // RTTI in .text (iv && !iv->is_rtti)
	rz_write_le64(multi_buf + 0x38, 0x1010); // rejected: non-RTTI section
	rz_write_le64(multi_buf + 0x40, 1); // positive offset_to_top
	rz_write_le64(multi_buf + 0x48, 0x50f0); // valid RTTI in .data.rel.ro
	rz_write_le64(multi_buf + 0x50, 0x1010); // rejected: positive offset_to_top
	rz_write_le64(multi_buf + 0x58, (ut64)(st64)-8); // valid negative offset_to_top
	rz_write_le64(multi_buf + 0x60, 0x50f0); // valid RTTI
	rz_write_le64(multi_buf + 0x68, 0x1010); // method 0 (.text_lo)
	rz_write_le64(multi_buf + 0x70, 0x2010); // method 1 (.text_mid)
	rz_write_le64(multi_buf + 0x78, 0x4010); // method 2 (.text_hi), cut off by xref

	const VTableTestCfg multi_cfg = VT_CFG(multi_secs, multi_mps);
	core = vtable_open_cfg(&multi_cfg, multi_buf, sizeof(multi_buf), 64, false);
	mu_assert_notnull(core, "open multi-section mock");
	bool xref_ok = rz_analysis_xrefs_set(
		core->analysis, 0x5000, 0x5078, RZ_ANALYSIS_XREF_TYPE_DATA);
	mu_assert_true(xref_ok, "set xref to method 2");

	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin multi");
	RzList *vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_notnull(vtables, "multi-section vtable found");
	mu_assert_eq(rz_list_length(vtables), 1, "only valid vtable accepted");
	RVTableInfo *vt = rz_list_first_val(vtables);
	mu_assert_eq(vt->saddr, 0x5068, "valid vtable saddr");
	mu_assert_eq(rz_vector_len(&vt->methods), 2, "xref stops method parsing before 0x5078");
	rz_list_free(vtables);
	rz_core_free(core);

	// 5. Overlapping sections with equal `from` (<, >, == `to`) trigger uncached fallback.
	static const RzBinSection ov_secs[] = {
		VT_SEC(".text", 0x1000, 0x100, 0x100, RZ_PERM_RX),
		VT_SEC(".rodata", 0x3000, 0x40, 0x40, RZ_PERM_R),
		VT_SEC(".rdata", 0x3000, 0x40, 0x40, RZ_PERM_R),
		VT_SEC(".data.rel.ro", 0x3000, 0x80, 0x80, RZ_PERM_R),
		VT_SEC(".data.rel.ro.local", 0x3000, 0x60, 0x60, RZ_PERM_R),
	};
	static const RzBinMap ov_mps[] = {
		VT_MAP("ov_relro", 0, 0x3000, 0x80, 0x80, RZ_PERM_R),
	};
	ut8 ov_buf[0x80] = { 0 };
	rz_write_le64(ov_buf + 0x00, 0);
	rz_write_le64(ov_buf + 0x08, 0x1010); // invalid RTTI under overlaps
	rz_write_le64(ov_buf + 0x10, 0x1010);
	rz_write_le64(ov_buf + 0x18, 0);
	rz_write_le64(ov_buf + 0x20, 0x3070); // valid RTTI in .data.rel.ro under overlaps
	rz_write_le64(ov_buf + 0x28, 0x1010);

	const VTableTestCfg ov_cfg = VT_CFG(ov_secs, ov_mps);
	core = vtable_open_cfg(&ov_cfg, ov_buf, sizeof(ov_buf), 64, false);
	mu_assert_notnull(core, "open overlapping mock");
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin overlapping");
	vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_notnull(vtables, "overlapping sections vtable found");
	mu_assert_eq(rz_list_length(vtables), 4, "vtable matched in all four overlapping sections");
	vt = rz_list_first_val(vtables);
	mu_assert_eq(vt->saddr, 0x3028, "overlapping vtable saddr");
	rz_list_free(vtables);
	rz_core_free(core);

	// 6. Overflowing .text section (with and without an earlier lower .text)
	// and wrapping .rodata.
	static const RzBinSection ovf_text_only[] = {
		VT_SEC(".text", UT64_MAX - 15, 0x10, 0x10, RZ_PERM_RX),
		VT_SEC(".rodata", UT64_MAX - 4, 0x10, 0x20, RZ_PERM_R),
	};
	const VTableTestCfg ovf_t1 = { ovf_text_only, RZ_ARRAY_SIZE(ovf_text_only), NULL, 0 };
	core = vtable_open_cfg(&ovf_t1, NULL, 0, 64, false);
	mu_assert_notnull(core, "open overflowing text mock 1");
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin ovf text 1");
	mu_assert_null(rz_analysis_vtable_search(&ctx), "overflowing text only has no vtables");
	rz_core_free(core);

	static const RzBinSection ovf_text_two[] = {
		VT_SEC(".text", 0x1000, 0x100, 0x100, RZ_PERM_RX),
		VT_SEC(".text_hi", UT64_MAX - 15, 0x10, 0x10, RZ_PERM_RX),
	};
	const VTableTestCfg ovf_t2 = { ovf_text_two, RZ_ARRAY_SIZE(ovf_text_two), NULL, 0 };
	core = vtable_open_cfg(&ovf_t2, NULL, 0, 64, false);
	mu_assert_notnull(core, "open overflowing text mock 2");
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin ovf text 2");
	mu_assert_null(rz_analysis_vtable_search(&ctx), "overflowing second text has no vtables");
	rz_core_free(core);

	mu_end;
}

bool test_vtable_search_chunk_boundary_and_p_cache(void) {
	// 1. Multi-chunk section (> 128 KB) testing chunk refill and
	// boundary-straddling RTTI/offset_to_top.
	const size_t sec_sz = 0x20040;
	static const RzBinSection big_secs[] = {
		VT_SEC(".text", 0x1000, 0x100, 0x100, RZ_PERM_RX),
		VT_SEC(".data.rel.ro", 0x10000, 0x20040, 0x20040, RZ_PERM_R),
	};
	static const RzBinMap big_mps[] = {
		VT_MAP("big_relro", 0, 0x10000, 0x20040, 0x20040, RZ_PERM_R),
	};
	ut8 *big_buf = calloc(1, sec_sz);
	mu_assert_notnull(big_buf, "alloc big_buf");
	if (!big_buf) {
		return false;
	}
	// Vtable 1 at 0x10010 (inside chunk 0).
	rz_write_le64(big_buf + 0x10, 0x1010);
	// Vtable 2 at 0x20008 (offset == ws in chunk 1: rtti in chunk, offset_to_top before chunk).
	rz_write_le64(big_buf + 0x10008, 0x1020);
	// Vtable 3 at 0x30000 (offset == 0 in chunk 2: both rtti and offset_to_top before chunk).
	rz_write_le64(big_buf + 0x20000, 0x1030);

	const VTableTestCfg big_cfg = VT_CFG(big_secs, big_mps);
	RzCore *core = vtable_open_cfg(&big_cfg, big_buf, sec_sz, 64, false);
	free(big_buf);
	mu_assert_notnull(core, "open big chunk mock");

	RVTableContext ctx;
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin big chunk");
	RzList *vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_notnull(vtables, "multi-chunk vtables found");
	mu_assert_eq(rz_list_length(vtables), 3, "three vtables across chunk boundaries");
	RVTableInfo *vt0 = rz_list_get_n(vtables, 0);
	RVTableInfo *vt1 = rz_list_get_n(vtables, 1);
	RVTableInfo *vt2 = rz_list_get_n(vtables, 2);
	mu_assert_eq(vt0->saddr, 0x10010, "chunk 0 vtable");
	mu_assert_eq(vt1->saddr, 0x20008, "chunk 1 boundary+ws vtable");
	mu_assert_eq(vt2->saddr, 0x30000, "chunk 2 boundary vtable");
	rz_list_free(vtables);
	rz_core_free(core);

	// 2. io->p_cache != 0 forces per-word is_valid_offset checks inside cached chunk
	// (stops at invalid offset).
	static const RzBinSection pc_secs[] = {
		VT_SEC(".text", 0x1000, 0x100, 0x100, RZ_PERM_RX),
		VT_SEC(".data.rel.ro", 0x3000, 0x40, 0x40, RZ_PERM_R),
	};
	static const RzBinMap pc_mps[] = {
		VT_MAP("pc_relro", 0, 0x3000, 0x40, 0x40, RZ_PERM_R),
	};
	ut8 pc_buf[0x40] = { 0 };
	rz_write_le64(pc_buf + 0x28, 0x1010);

	const VTableTestCfg pc_cfg = VT_CFG(pc_secs, pc_mps);
	core = vtable_open_cfg(&pc_cfg, pc_buf, sizeof(pc_buf), 64, false);
	mu_assert_notnull(core, "open p_cache mock");
	mu_assert_true(rz_io_desc_cache_init(core->io->desc), "init desc cache");
	mu_assert_eq(rz_io_desc_cache_write(core->io->desc, 0, pc_buf, sizeof(pc_buf)),
		(int)sizeof(pc_buf), "seed desc cache");
	core->io->p_cache = 1;
	RzIOIsValidOff saved_valid = core->analysis->iob.is_valid_offset;
	g_vt_invalid_off = 0x3010;
	core->analysis->iob.is_valid_offset = vtable_fail_valid_at;
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin p_cache");
	mu_assert_null(rz_analysis_vtable_search(&ctx),
		"p_cache stops at invalid offset inside chunk");
	core->analysis->iob.is_valid_offset = saved_valid;
	core->io->p_cache = 0;

	// 3. nread_at == NULL falls back cleanly to unbuffered reads and still finds the vtable.
	RzIONReadAt saved_nread = core->analysis->iob.nread_at;
	core->analysis->iob.nread_at = NULL;
	vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_notnull(vtables, "nread_at==NULL finds vtable via unbuffered fallback");
	RVTableInfo *vt = rz_list_first_val(vtables);
	mu_assert_eq(vt->saddr, 0x3028, "nread_at==NULL saddr");
	rz_list_free(vtables);
	core->analysis->iob.nread_at = saved_nread;
	rz_core_free(core);

	// 4. io->va = false with desc_size == NULL falls back to per-word validity check.
	static const RzBinSection pa_secs[] = {
		VT_SEC(".text", 0x1000, 0x100, 0x100, RZ_PERM_RX),
		VT_SEC(".data.rel.ro", 0, 0x40, 0x40, RZ_PERM_R),
	};
	static const RzBinMap pa_mps[] = {
		VT_MAP("pa_relro", 0, 0, 0x20, 0x40, RZ_PERM_R),
	};
	ut8 pa_buf[0x20] = { 0 };
	rz_write_le64(pa_buf + 0x10, 0x1010);
	const VTableTestCfg pa_cfg = VT_CFG(pa_secs, pa_mps);
	core = vtable_open_cfg(&pa_cfg, pa_buf, sizeof(pa_buf), 64, false);
	mu_assert_notnull(core, "open pa desc_size mock");
	core->io->va = false;
	RzIODescSize saved_desc_size = core->analysis->iob.desc_size;
	core->analysis->iob.desc_size = NULL;
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin pa desc_size=NULL");
	vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_notnull(vtables, "pa search with desc_size=NULL finds in-bounds vtable");
	vt = rz_list_first_val(vtables);
	mu_assert_eq(vt->saddr, 0x10, "pa saddr");
	core->analysis->iob.desc_size = saved_desc_size;
	rz_list_free(vtables);
	rz_core_free(core);

	mu_end;
}

bool test_vtable_search_custom_read_msvc_and_interrupts(void) {
	// 1. MSVC ABI vtable search with MOV xref from .text into .rdata.
	static const RzBinSection msvc_secs[] = {
		VT_SEC(".text", 0x1000, 0x40, 0x40, RZ_PERM_RX),
		VT_SEC(".rdata", 0x3000, 0x40, 0x40, RZ_PERM_R),
	};
	static const RzBinMap msvc_mps[] = {
		VT_MAP("text", 0, 0x1000, 0x40, 0x40, RZ_PERM_RX),
		VT_MAP("rdata", 0x40, 0x3000, 0x40, 0x40, RZ_PERM_R),
	};
	ut8 msvc_buf[0x80] = { 0 };
	// 0x1000: mov rax, 0x3010 (48 b8 10 30 00 00 00 00 00 00)
	static const ut8 mov_ins[] = { 0x48, 0xb8, 0x10, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	memcpy(msvc_buf, mov_ins, sizeof(mov_ins));
	rz_write_le64(msvc_buf + 0x50, 0x1010); // .rdata + 0x10 -> 0x3010

	const VTableTestCfg msvc_cfg = VT_CFG(msvc_secs, msvc_mps);
	RzCore *core = vtable_open_cfg(&msvc_cfg, msvc_buf, sizeof(msvc_buf), 64, false);
	mu_assert_notnull(core, "open msvc mock");
	rz_analysis_set_cpp_abi(core->analysis, RZ_ANALYSIS_CPP_ABI_MSVC);
	rz_analysis_xrefs_set(core->analysis, 0x1000, 0x3010, RZ_ANALYSIS_XREF_TYPE_DATA);

	RVTableContext ctx;
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin msvc");
	RzList *vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_notnull(vtables, "msvc vtable found");
	mu_assert_eq(rz_list_length(vtables), 1, "one msvc vtable");
	RVTableInfo *vt = rz_list_first_val(vtables);
	mu_assert_eq(vt->saddr, 0x3010, "msvc vtable saddr");
	rz_list_free(vtables);
	rz_core_free(core);

	// 2. Method at UT64_MAX - 7 triggers req_len < ws fallback and
	// UT64_ADD_OVFCHK break in parse_at_cached.
	static const RzBinSection max7_secs[] = {
		VT_SEC(".text", 0x1000, 0x100, 0x100, RZ_PERM_RX),
		VT_SEC(".data.rel.ro", UT64_MAX - 7, 8, 8, RZ_PERM_R),
	};
	static const RzBinMap max7_mps[] = {
		VT_MAP("max7", 0, UT64_MAX - 31, 0x1f, 0x1f, RZ_PERM_R),
	};
	ut8 max7_buf[0x20] = { 0 };
	rz_write_le64(max7_buf + 0x18, 0x1010); // UT64_MAX - 7
	const VTableTestCfg max7_cfg = VT_CFG(max7_secs, max7_mps);
	core = vtable_open_cfg(&max7_cfg, max7_buf, sizeof(max7_buf), 64, false);
	mu_assert_notnull(core, "open max7 mock");
	core->io->Oxff = 0;
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin max7");
	vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_notnull(vtables, "vtable at UT64_MAX - 7 found without wrap");
	vt = rz_list_first_val(vtables);
	mu_assert_eq(vt->saddr, UT64_MAX - 7, "max7 saddr");
	rz_list_free(vtables);
	rz_core_free(core);

	// 3. curAddress == 0 and curAddress == UT64_MAX are rejected by
	// vtable_is_addr_vtable_start_itanium_cached.
	static const RzBinSection zero_secs[] = {
		VT_SEC(".text", 0x1000, 0x100, 0x100, RZ_PERM_RX),
		VT_SEC(".data.rel.ro", 0, 0x20, 0x20, RZ_PERM_R),
	};
	static const RzBinMap zero_mps[] = {
		VT_MAP("zero_relro", 0, 0, 0x20, 0x20, RZ_PERM_R),
	};
	ut8 zero_buf[0x20] = { 0 };
	rz_write_le64(zero_buf, 0x1010);
	const VTableTestCfg zero_cfg = VT_CFG(zero_secs, zero_mps);
	core = vtable_open_cfg(&zero_cfg, zero_buf, sizeof(zero_buf), 64, false);
	mu_assert_notnull(core, "open zero-addr mock");
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin zero-addr");
	mu_assert_null(rz_analysis_vtable_search(&ctx), "curAddress == 0 rejected");
	rz_core_free(core);

	static const RzBinSection max1_secs[] = {
		VT_SEC(".text", 0x10, 0x20, 0x20, RZ_PERM_RX),
		VT_SEC(".data.rel.ro", UT64_MAX, 1, 1, RZ_PERM_R),
	};
	const VTableTestCfg max1_cfg = { max1_secs, RZ_ARRAY_SIZE(max1_secs), NULL, 0 };
	core = vtable_open_cfg(&max1_cfg, NULL, 0, 8, false);
	mu_assert_notnull(core, "open UT64_MAX 8-bit mock");
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin UT64_MAX 8-bit");
	RzIOIsValidOff saved_valid_off = core->analysis->iob.is_valid_offset;
	core->analysis->iob.is_valid_offset = vtable_always_valid_offset;
	memset(&g_vt_hook, 0, sizeof(g_vt_hook));
	g_vt_hook.force_const = true;
	g_vt_hook.const_val = 0x14;
	ctx.read_addr = vtable_custom_read_addr;
	mu_assert_null(rz_analysis_vtable_search(&ctx), "curAddress == UT64_MAX rejected");
	core->analysis->iob.is_valid_offset = saved_valid_off;
	rz_core_free(core);

	// 4. Custom read_addr failure paths (cur_val, rtti, offset_to_top,
	// parse_at_cached) and interrupts.
	static const RzBinSection hook_secs[] = {
		VT_SEC(".text", 0x1000, 0x100, 0x100, RZ_PERM_RX),
		VT_SEC(".rodata", 0x3000, 0x40, 0x40, RZ_PERM_R),
		VT_SEC(".data.rel.ro", 0x4000, 0x40, 0x40, RZ_PERM_R),
	};
	static const RzBinMap hook_mps[] = {
		VT_MAP("ro", 0, 0x3000, 0x40, 0x40, RZ_PERM_R),
		VT_MAP("relro", 0, 0x4000, 0x40, 0x40, RZ_PERM_R),
	};
	ut8 hook_buf[0x40] = { 0 };
	rz_write_le64(hook_buf + 0x10, 0x1010);
	const VTableTestCfg hook_cfg = VT_CFG(hook_secs, hook_mps);
	core = vtable_open_cfg(&hook_cfg, hook_buf, sizeof(hook_buf), 64, false);
	mu_assert_notnull(core, "open custom read_addr mock");
	mu_assert_true(rz_analysis_vtable_begin(core->analysis, &ctx), "begin custom read_addr");
	ctx.read_addr = vtable_custom_read_addr;

	// 4a. Fail cur_val read at 0x3008 -> skips word via continue,
	// still finds vtables at 0x3010 & 0x4010.
	memset(&g_vt_hook, 0, sizeof(g_vt_hook));
	g_vt_hook.has_fail_addr = true;
	g_vt_hook.fail_addr = 0x3008;
	g_vt_hook.fail_on_hit = 1;
	vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_notnull(vtables, "recovers after single cur_val read failure");
	mu_assert_eq(rz_list_length(vtables), 2, "finds both vtables");
	rz_list_free(vtables);

	// 4b. Fail RTTI read (2nd hit of 0x3008, when curAddress == 0x3010).
	memset(&g_vt_hook, 0, sizeof(g_vt_hook));
	g_vt_hook.has_fail_addr = true;
	g_vt_hook.fail_addr = 0x3008;
	g_vt_hook.fail_on_hit = 2;
	vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_notnull(vtables, "second section still found after RTTI read failure");
	mu_assert_eq(rz_list_length(vtables), 1, "first vtable skipped on RTTI failure");
	vt = rz_list_first_val(vtables);
	mu_assert_eq(vt->saddr, 0x4010, "remaining vtable");
	rz_list_free(vtables);

	// 4c. Fail offset_to_top read in start check
	// (2nd hit of 0x3000, when curAddress == 0x3010).
	memset(&g_vt_hook, 0, sizeof(g_vt_hook));
	g_vt_hook.has_fail_addr = true;
	g_vt_hook.fail_addr = 0x3000;
	g_vt_hook.fail_on_hit = 2;
	vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_notnull(vtables, "second section still found after offset_to_top failure");
	mu_assert_eq(rz_list_length(vtables), 1, "first vtable skipped on offset_to_top failure");
	rz_list_free(vtables);

	// 4d. Fail offset_to_top read in vtable_parse_at_cached (3rd hit of 0x3000).
	memset(&g_vt_hook, 0, sizeof(g_vt_hook));
	g_vt_hook.has_fail_addr = true;
	g_vt_hook.fail_addr = 0x3000;
	g_vt_hook.fail_on_hit = 3;
	vtables = rz_analysis_vtable_search(&ctx);
	mu_assert_notnull(vtables, "second section still found after parse_at_cached failure");
	mu_assert_eq(rz_list_length(vtables), 1, "first vtable NULL on parse_at_cached failure");
	rz_list_free(vtables);

	// 4e. Interrupt during chunk/word loop breaks inner and outer loops cleanly.
	RzInterrupt *own_intr = NULL;
	if (!core->analysis->intr) {
		own_intr = rz_interrupt_new();
		core->analysis->intr = own_intr;
	}
	memset(&g_vt_hook, 0, sizeof(g_vt_hook));
	g_vt_hook.has_break_addr = true;
	g_vt_hook.break_addr = 0x3000;
	g_vt_hook.break_on_hit = 1;
	mu_assert_null(rz_analysis_vtable_search(&ctx), "interrupt aborts scan before vtable");
	rz_interrupt_set_breaked(core->analysis->intr, false);

	// 4f. Interrupt right after is_start becomes true (2nd hit of 0x3000)
	// hits pre-parse break check.
	memset(&g_vt_hook, 0, sizeof(g_vt_hook));
	g_vt_hook.has_break_addr = true;
	g_vt_hook.break_addr = 0x3000;
	g_vt_hook.break_on_hit = 2;
	mu_assert_null(rz_analysis_vtable_search(&ctx),
		"interrupt aborts scan before vtable_parse_at_cached");
	rz_interrupt_set_breaked(core->analysis->intr, false);
	if (own_intr) {
		core->analysis->intr = NULL;
		rz_interrupt_free(own_intr);
	}

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
	mu_run_test(test_vtable_search_small_rodata_underflow);
	mu_run_test(test_vtable_search_boundaries);
	mu_run_test(test_vtable_search_word_sizes_and_endianness);
	mu_run_test(test_vtable_search_section_cache_edge_cases);
	mu_run_test(test_vtable_search_chunk_boundary_and_p_cache);
	mu_run_test(test_vtable_search_custom_read_msvc_and_interrupts);
	return tests_passed != tests_run;
}

mu_main(all_tests)
