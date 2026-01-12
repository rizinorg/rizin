// SPDX-FileCopyrightText: 2025 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2017 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include "minunit.h"

bool test_rz_io_read_at_mapped(void) {
	RzIO *io = rz_io_new();
	io->va = true;
	io->ff = true;
	io->Oxff = '_';
	rz_io_open_at(io, "malloc://8", RZ_PERM_RW, 0, 0x10, NULL);
	rz_io_write_at(io, 0x10, (ut8 *)"abcdefgh", 15);
	rz_io_open_at(io, "malloc://4", RZ_PERM_RW, 0, 0x15, NULL);
	rz_io_write_at(io, 0x15, (ut8 *)"1234", 15);

	ut8 buf[0x20];
	bool r = rz_io_read_at_mapped(io, 0xe, buf, sizeof(buf));
	mu_assert_true(r, "read before map");
	mu_assert_memeq(buf, (const ut8 *)"__abcde1234___", 14, "nread at map start content");

	r = rz_io_read_at_mapped(io, 0x10, buf, sizeof(buf));
	mu_assert_true(r, "read at map start");
	mu_assert_memeq(buf, (const ut8 *)"abcde1234___", 12, "nread at map start content");

	r = rz_io_read_at_mapped(io, 0x12, buf, sizeof(buf));
	mu_assert_true(r, "read inside map");
	mu_assert_memeq(buf, (const ut8 *)"cde1234_____", 10, "nread insite map content");

	rz_io_free(io);
	mu_end;
}

bool test_rz_io_nread_at(void) {
	RzIO *io = rz_io_new();
	io->va = true;
	io->ff = true;
	io->Oxff = '_';
	rz_io_open_at(io, "malloc://8", RZ_PERM_RW, 0, 0x10, NULL);
	rz_io_write_at(io, 0x10, (ut8 *)"abcdefgh", 15);
	rz_io_open_at(io, "malloc://4", RZ_PERM_RW, 0, 0x15, NULL);
	rz_io_write_at(io, 0x15, (ut8 *)"1234", 15);

	ut8 buf[0x20];
	int r = rz_io_nread_at(io, 0xe, buf, sizeof(buf));
	mu_assert_eq(r, 0, "nread fails before map");

	r = rz_io_nread_at(io, 0x10, buf, sizeof(buf));
	mu_assert_eq(r, 9, "nread at map start size");
	mu_assert_memeq(buf, (const ut8 *)"abcde1234", 9, "nread at map start content");

	r = rz_io_nread_at(io, 0x12, buf, sizeof(buf));
	mu_assert_eq(r, 7, "nread inside map size");
	mu_assert_memeq(buf, (const ut8 *)"cde1234", 7, "nread insite map content");

	rz_io_free(io);
	mu_end;
}

bool test_rz_io_cache(void) {
	RzIO *io = rz_io_new();
	rz_io_open(io, "malloc://15", RZ_PERM_RW, 0);
	rz_io_write(io, (ut8 *)"ZZZZZZZZZZZZZZZ", 15);
	mu_assert_false(rz_io_cache_at(io, 0), "Cache shouldn't exist at 0");
	mu_assert_false(rz_io_cache_at(io, 10), "Cache shouldn't exist at 10");
	mu_assert_true(rz_io_cache_write(io, 0, (ut8 *)"AAAAA", 5), "Cache write at 0 failed");
	mu_assert_true(rz_io_cache_write(io, 10, (ut8 *)"BBBBB", 5), "Cache write at 10 failed");
	mu_assert_true(rz_io_cache_at(io, 0), "Cache should exist at 0 (beggining of cache)");
	mu_assert_true(rz_io_cache_at(io, 4), "Cache should exist at 4 (end of cache)");
	mu_assert_false(rz_io_cache_at(io, 5), "Cache shouldn't exist at 5 (after end of cache)");
	mu_assert_false(rz_io_cache_at(io, 8), "Cache shouldn't exist at 8 (between 2 caches)");
	mu_assert_true(rz_io_cache_at(io, 12), "Cache should exist at 12 (middle of cache)");
	size_t copied = 0;
	ut8 buf[15];
	memset(buf, 'Z', sizeof(buf));
	mu_assert_true(rz_io_cache_read(io, 0, buf, sizeof(buf), &copied), "Cache read failed");
	mu_assert_eq(copied, 10, "Incorrect number of bytes copied.");
	mu_assert_memeq(buf, (ut8 *)"AAAAAZZZZZBBBBB", sizeof(buf), "Cache read doesn't match expected output");
	memset(buf, 'Z', sizeof(buf));
	mu_assert_true(rz_io_cache_write(io, 0, (ut8 *)"AB", 2), "Overlapped cache write at 0 failed");
	mu_assert_true(rz_io_cache_write(io, 4, (ut8 *)"CD", 2), "Overlapped cache write at 4 failed");
	mu_assert_true(rz_io_cache_write(io, 8, (ut8 *)"EFG", 3), "Cache write at 8 failed");
	mu_assert_true(rz_io_cache_read(io, 0, buf, 2, &copied), "Cache read at 0 failed");
	mu_assert_eq(copied, 2, "Incorrect number of bytes copied.");
	mu_assert_true(rz_io_cache_read(io, 2, buf + 2, 2, &copied), "Cache read at 2 failed");
	mu_assert_eq(copied, 2, "Incorrect number of bytes copied.");
	mu_assert_true(rz_io_cache_read(io, 4, buf + 4, 2, &copied), "Cache read at 4 failed");
	mu_assert_eq(copied, 2, "Incorrect number of bytes copied.");
	mu_assert_false(rz_io_cache_read(io, 6, buf + 6, 2, &copied), "Cache read at 6 should fail");
	// There is no cache at address 7. It should read only one byte at address 8.
	mu_assert_true(rz_io_cache_read(io, 7, buf + 7, 2, &copied), "Cache read at 7 with size 2 should succeed");
	mu_assert_eq(copied, 1, "Incorrect number of bytes copied.");
	mu_assert_true(rz_io_cache_read(io, 9, buf + 9, 2, &copied), "Cache read at 9 failed");
	mu_assert_eq(copied, 2, "Incorrect number of bytes copied.");
	mu_assert_true(rz_io_cache_read(io, 11, buf + 11, 4, &copied), "Cache read at 11 failed");
	mu_assert_eq(copied, 4, "Incorrect number of bytes copied.");
	mu_assert_memeq(buf, (ut8 *)"ABAACDZZEFGBBBB", sizeof(buf), "Cache read doesn't match expected output");
	mu_assert_true(rz_io_cache_write(io, 0, (ut8 *)"FFFFFFFFFFFFFFF", 15), "Cache write failed");
	mu_assert_true(rz_io_cache_read(io, 0, buf, sizeof(buf), &copied), "Cache read failed");
	mu_assert_eq(copied, sizeof(buf), "Incorrect number of bytes copied.");
	mu_assert_memeq(buf, (ut8 *)"FFFFFFFFFFFFFFF", sizeof(buf), "Cache read doesn't match expected output");
	rz_io_read_at_mapped(io, 0, buf, sizeof(buf));
	mu_assert_memeq(buf, (ut8 *)"ZZZZZZZZZZZZZZZ", sizeof(buf), "IO read without cache doesn't match expected output");
	io->cached = RZ_PERM_R;
	rz_io_read_at_mapped(io, 0, buf, sizeof(buf));
	mu_assert_memeq(buf, (ut8 *)"FFFFFFFFFFFFFFF", sizeof(buf), "IO read with cache doesn't match expected output");
	rz_io_cache_invalidate(io, 6, 1);
	memset(buf, 'Z', sizeof(buf));
	rz_io_read_at_mapped(io, 0, buf, sizeof(buf));
	mu_assert_memeq(buf, (ut8 *)"ABAACDZZEFGBBBB", sizeof(buf), "IO read after cache invalidate doesn't match expected output");
	rz_io_cache_commit(io, 0, 15);
	memset(buf, 'Z', sizeof(buf));
	io->cached = 0;
	rz_io_read_at_mapped(io, 0, buf, sizeof(buf));
	mu_assert_memeq(buf, (ut8 *)"ABAACDZZEFGBBBB", sizeof(buf), "IO read after cache commit doesn't match expected output");
	io->cached = RZ_PERM_R;
	mu_assert_true(rz_io_cache_write(io, UT64_MAX - 8, (ut8 *)"FFFFFFFFFFFFFFF", 15), "Cache write failed");
	rz_io_read_at_mapped(io, UT64_MAX - 8, buf, sizeof(buf));
	mu_assert_memeq(buf, (ut8 *)"FFFFFFFFFFFFFFF", sizeof(buf), "IO read with cache doesn't match expected output");
	rz_io_free(io);
	mu_end;
}

bool test_rz_io_mapsplit(void) {
	RzIO *io = rz_io_new();
	io->va = true;
	rz_io_open_at(io, "null://2", RZ_PERM_R, 0LL, UT64_MAX, NULL);
	mu_assert_true(rz_io_map_is_mapped(io, 0x0), "0x0 not mapped");
	mu_assert_true(rz_io_map_is_mapped(io, UT64_MAX), "UT64_MAX not mapped");
	mu_assert_notnull(rz_io_map_get(io, 0x0), "Found no map at 0x0");
	mu_assert_notnull(rz_io_map_get(io, UT64_MAX), "Found no map at UT64_MAX");
	rz_io_free(io);
	mu_end;
}

bool test_rz_io_mapsplit2(void) {
	RzIO *io = rz_io_new();
	io->va = true;
	RzIOMap *map;
	rz_io_open_at(io, "null://2", RZ_PERM_R, 0LL, 0LL, &map);
	mu_assert_true(rz_io_map_is_mapped(io, 0x0), "0x0 not mapped");
	mu_assert_true(rz_io_map_is_mapped(io, 0x1), "0x1 not mapped");
	mu_assert_ptreq(rz_io_map_get(io, 0LL), map, "returned map");
	rz_io_map_remap(io, map->id, UT64_MAX);
	mu_assert_true(rz_io_map_is_mapped(io, 0x0), "0x0 not mapped");
	mu_assert_true(rz_io_map_is_mapped(io, UT64_MAX), "UT64_MAX not mapped");
	mu_assert_false(rz_io_map_is_mapped(io, 0x1), "0x1 mapped");
	mu_assert_notnull(rz_io_map_get(io, 0x0), "Found no map at 0x0");
	mu_assert_notnull(rz_io_map_get(io, UT64_MAX), "Found no map at UT64_MAX");
	mu_assert_null(rz_io_map_get(io, 0x1), "Found map at 0x1");
	rz_io_free(io);
	mu_end;
}

bool test_rz_io_mapsplit3(void) {
	RzIO *io = rz_io_new();
	io->va = true;
	rz_io_open_at(io, "null://2", RZ_PERM_R, 0LL, UT64_MAX - 1, NULL);
	mu_assert_true(rz_io_map_is_mapped(io, UT64_MAX - 1), "UT64_MAX - 1 not mapped");
	mu_assert_true(rz_io_map_is_mapped(io, UT64_MAX), "UT64_MAX not mapped");
	rz_io_map_resize(io, rz_io_map_get(io, UT64_MAX)->id, 3);
	mu_assert_true(rz_io_map_is_mapped(io, UT64_MAX - 1), "UT64_MAX - 1 not mapped");
	mu_assert_true(rz_io_map_is_mapped(io, UT64_MAX), "UT64_MAX not mapped");
	mu_assert_true(rz_io_map_is_mapped(io, 0x0), "0x0 not mapped");
	mu_assert_false(rz_io_map_is_mapped(io, 0x1), "0x1 mapped");
	mu_assert_notnull(rz_io_map_get(io, UT64_MAX), "Found no map at UT64_MAX");
	mu_assert_notnull(rz_io_map_get(io, 0x0), "Found no map at 0x0");
	rz_io_free(io);
	mu_end;
}

bool test_rz_io_maps_vector(void) {
	RzIO *io = rz_io_new();
	io->ff = 1;
	int fd = rz_io_fd_open(io, "malloc://3", RZ_PERM_RW, 0);
	int perms[4] = { RZ_PERM_RW, RZ_PERM_R, RZ_PERM_RW, RZ_PERM_W };
	ut64 deltas[4] = { 0ULL, 1, 1, 1 };
	ut64 addrs[4] = { 0ULL, 1, 2, 3 };
	ut64 sizes[4] = { 1, 1, 1, 1 };
	rz_io_map_add(io, fd, perms[0], deltas[0], addrs[0], sizes[0]);
	rz_io_map_add(io, fd, perms[1], deltas[1], addrs[1], sizes[1]);
	rz_io_map_add(io, fd, perms[2], deltas[2], addrs[2], sizes[2]);
	rz_io_map_add(io, fd, perms[3], deltas[3], addrs[3], sizes[3]);
	RzPVector *maps = rz_io_maps(io);
	mu_assert_notnull(maps, "maps vector should not be null");
	mu_assert_eq(rz_pvector_len(maps), 4, "expected 4 maps");
	int i = 3; // They are located in the reverse order
	void **it;
	rz_pvector_foreach_prev(maps, it) {
		RzIOMap *map = *it;
		mu_assert_eq(map->perm, perms[i], "expected valid map permission");
		mu_assert_eq(map->delta, deltas[i], "expected valid map delta");
		mu_assert_eq(map->delta, deltas[i], "expected valid map delta");
		mu_assert_eq(map->itv.addr, addrs[i], "expected to have right addr");
		i--;
	}
	rz_io_free(io);
	mu_end;
}

bool test_rz_io_pcache(void) {
	RzIO *io = rz_io_new();
	io->ff = 1;
	ut8 buf[8];
	int fd = rz_io_fd_open(io, "malloc://3", RZ_PERM_RW, 0);
	rz_io_map_add(io, fd, RZ_PERM_RW, 0LL, 0LL, 1); // 8
	rz_io_map_add(io, fd, RZ_PERM_RW, 1, 1, 1); //=
	rz_io_map_add(io, fd, RZ_PERM_RW, 1, 2, 1); //=
	rz_io_map_add(io, fd, RZ_PERM_RW, 1, 3, 1); //=
	rz_io_map_add(io, fd, RZ_PERM_RW, 1, 4, 1); //=
	rz_io_map_add(io, fd, RZ_PERM_RW, 1, 5, 1); //=
	rz_io_map_add(io, fd, RZ_PERM_RW, 2, 6, 1); // D
	io->p_cache = 2;
	io->va = true;
	rz_io_fd_write_at(io, fd, 0, (const ut8 *)"8=D", 3);
	rz_io_read_at_mapped(io, 0x0, buf, 8);
	mu_assert_streq((const char *)buf, "", "pcache read happened, but it shouldn't");
	io->p_cache = 1;
	rz_io_read_at_mapped(io, 0x0, buf, 8);
	mu_assert_streq((const char *)buf, "8=====D", "expected an ascii-pn from pcache");
	rz_io_fd_write_at(io, fd, 0, (const ut8 *)"XXX", 3);
	rz_io_read_at_mapped(io, 0x0, buf, 8);
	mu_assert_streq((const char *)buf, "8=====D", "expected an ascii-pn from pcache");
	io->p_cache = 0;
	rz_io_read_at_mapped(io, 0x0, buf, 8);
	mu_assert_streq((const char *)buf, "XXXXXXX", "expected censorship of the ascii-pn");
	rz_io_free(io);
	mu_end;
}

bool test_rz_io_desc_exchange(void) {
	RzIO *io = rz_io_new();
	int fd = rz_io_fd_open(io, "malloc://3", RZ_PERM_R, 0),
	    fdx = rz_io_fd_open(io, "malloc://6", RZ_PERM_R, 0);
	rz_io_desc_exchange(io, fd, fdx);
	mu_assert("Desc-exchange is broken", (rz_io_fd_size(io, fd) == 6));
	rz_io_free(io);
	mu_end;
}

bool test_va_malloc_zero(void) {
	RzIO *io;
	ut64 buf;
	bool ret;

	io = rz_io_new();
	io->va = false;
	rz_io_open_at(io, "malloc://8", RZ_PERM_RW, 0644, 0x0, NULL);
	buf = 0xdeadbeefcafebabe;
	ret = rz_io_read_at_mapped(io, 0, (ut8 *)&buf, 8);
	mu_assert("should be able to read", ret);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x00\x00\x00\x00\x00\x00\x00\x00", 8, "0 should be there initially");
	rz_io_free(io);

	io = rz_io_new();
	io->va = true;
	rz_io_open_at(io, "malloc://8", RZ_PERM_RW, 0644, 0x0, NULL);
	buf = 0xdeadbeefcafebabe;
	ret = rz_io_read_at_mapped(io, 0, (ut8 *)&buf, 8);
	mu_assert("should be able to read", ret);
	mu_test_status = MU_TEST_BROKEN;
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x00\x00\x00\x00\x00\x00\x00\x00", 8, "0 should be there initially");
	rz_io_free(io);

	mu_end;
}

bool test_rz_io_priority(void) {
	RzIO *io = rz_io_new();
	ut32 map0, map1, map_big;
	ut64 buf;
	bool ret;

	io->va = true;
	rz_io_open_at(io, "malloc://8", RZ_PERM_RW, 0644, 0x0, NULL);
	map0 = rz_io_map_get(io, 0)->id;
	ret = rz_io_read_at_mapped(io, 0, (ut8 *)&buf, 8);
	mu_assert("should be able to read", ret);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x00\x00\x00\x00\x00\x00\x00\x00", 8, "0 should be there initially");
	buf = 0x9090909090909090;
	rz_io_write_at(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x90\x90\x90\x90\x90\x90\x90\x90", 8, "0x90 should have been written");

	rz_io_open_at(io, "malloc://2", RZ_PERM_RW, 0644, 0x4, NULL);
	map1 = rz_io_map_get(io, 4)->id;
	rz_io_read_at_mapped(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x90\x90\x90\x90\x00\x00\x90\x90", 8, "0x00 from map1 should overlap");

	buf ^= UT64_MAX;
	rz_io_write_at(io, 0, (ut8 *)&buf, 8);
	rz_io_read_at_mapped(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x6f\x6f\x6f\x6f\xff\xff\x6f\x6f", 8, "memory has been xored");

	rz_io_map_priorize(io, map0);
	rz_io_read_at_mapped(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x6f\x6f\x6f\x6f\x90\x90\x6f\x6f", 8, "map0 should have been prioritized");

	rz_io_map_remap(io, map1, 0x2);
	rz_io_read_at_mapped(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x6f\x6f\x6f\x6f\x90\x90\x6f\x6f", 8, "map1 should have been remapped");

	rz_io_map_priorize(io, map1);
	rz_io_read_at_mapped(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x6f\x6f\xff\xff\x90\x90\x6f\x6f", 8, "map1 should have been prioritized");

	rz_io_open_at(io, "malloc://2", RZ_PERM_RW, 0644, 0x0, NULL);
	rz_io_read_at_mapped(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x00\x00\xff\xff\x90\x90\x6f\x6f", 8, "0x00 from map2 at start should overlap");

	rz_io_map_remap(io, map1, 0x1);
	rz_io_read_at_mapped(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x00\x00\xff\x6f\x90\x90\x6f\x6f", 8, "map1 should have been remapped and partialy hidden");

	rz_io_open_at(io, "malloc://2", RZ_PERM_RW, 0644, 0x4, NULL);
	rz_io_open_at(io, "malloc://2", RZ_PERM_RW, 0644, 0x6, NULL);
	rz_io_read_at_mapped(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x00\x00\xff\x6f\x00\x00\x00\x00", 8, "Multiple maps opened");

	buf = 0x9090909090909090;
	rz_io_open_at(io, "malloc://8", RZ_PERM_RW, 0644, 0x10, NULL);
	map_big = rz_io_map_get(io, 0x10)->id;
	rz_io_write_at(io, 0x10, (ut8 *)&buf, 8);
	rz_io_map_remap(io, map_big, 0x1);
	rz_io_read_at_mapped(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x00\x90\x90\x90\x90\x90\x90\x90", 8, "map_big should cover everything from 0x1");

	rz_io_map_remap(io, map_big, 0x10);
	rz_io_map_remap(io, map_big, 0);
	rz_io_read_at_mapped(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x90\x90\x90\x90\x90\x90\x90\x90", 8, "map_big should cover everything");

	rz_io_free(io);
	mu_end;
}

bool test_rz_io_priority2(void) {
	RzIO *io = rz_io_new();
	ut32 map0;
	ut8 buf[2];
	bool ret;

	io->va = true;
	RzIOMap *map;
	RzIODesc *desc0 = rz_io_open_at(io, "malloc://1024", RZ_PERM_RW, 0644, 0x0, &map);
	mu_assert_notnull(desc0, "first malloc should be opened");
	mu_assert_ptreq(map, rz_io_map_get(io, 0), "returned map");
	map0 = map->id;
	ret = rz_io_read_at_mapped(io, 0, (ut8 *)&buf, 2);
	mu_assert("should be able to read", ret);
	mu_assert_memeq(buf, (ut8 *)"\x00\x00", 2, "0 should be there initially");
	rz_io_write_at(io, 0, (const ut8 *)"\x90\x90", 2);
	rz_io_read_at_mapped(io, 0, buf, 2);
	mu_assert_memeq(buf, (ut8 *)"\x90\x90", 2, "0x90 was written");

	RzIODesc *desc1 = rz_io_open_at(io, "malloc://1024", RZ_PERM_R, 0644, 0x0, &map);
	mu_assert_ptreq(map, rz_io_map_get(io, 0), "returned map");
	mu_assert_notnull(desc1, "second malloc should be opened");
	rz_io_read_at_mapped(io, 0, buf, 2);
	mu_assert_memeq(buf, (ut8 *)"\x00\x00", 2, "0x00 from map1 should be on top");

	rz_io_map_priorize(io, map0);
	rz_io_read_at_mapped(io, 0, buf, 2);
	mu_assert_memeq(buf, (ut8 *)"\x90\x90", 2, "0x90 from map0 should be on top after prioritize");

	rz_io_free(io);
	mu_end;
}

bool test_rz_io_default(void) {
	ut8 buf[0x10];

	char *filename = rz_file_temp(NULL);
	int fd = open(filename, O_RDWR | O_CREAT, 0644);
	rz_xwrite(fd, "1234567890ABCDEF", 0x10);
	close(fd);

	char *filename_io = rz_str_newf("file://%s", filename);

	RzIO *io = rz_io_new();
	io->va = true;

	RzIOMap *map;
	RzIODesc *desc = rz_io_open_at(io, filename, RZ_PERM_R, 0, 0, &map);
	mu_assert_notnull(desc, "temp file has been opened");
	mu_assert_notnull(map, "map");
	mu_assert_ptreq(map, rz_io_map_get(io, 0), "returned mapped map");
	rz_io_read_at_mapped(io, 0x0, buf, 0x10);
	mu_assert_memeq(buf, (ut8 *)"1234567890ABCDEF", 0x10, "data has been correctly read");

	map = NULL;
	RzIODesc *desc2 = rz_io_open_at(io, filename, RZ_PERM_R, 0, 0x30, &map);
	mu_assert_notnull(desc2, "temp file has been opened at 0x30");
	mu_assert_notnull(map, "map");
	mu_assert_ptreq(map, rz_io_map_get(io, 0x30), "returned mapped map");
	rz_io_read_at_mapped(io, 0x30, buf, 0x10);
	mu_assert_memeq(buf, (ut8 *)"1234567890ABCDEF", 0x10, "data has been correctly read at 0x30");

	RzIODesc *desc3 = rz_io_open_at(io, filename, RZ_PERM_RW, 0, 0x50, NULL);
	mu_assert_notnull(desc3, "temp file has been opened in RW mode at 0x50");
	rz_io_read_at_mapped(io, 0x50, buf, 0x10);
	mu_assert_memeq(buf, (ut8 *)"1234567890ABCDEF", 0x10, "data has been correctly read at 0x50");
	memcpy(buf, "FEDCBA0987654321", 0x10);
	rz_io_write_at(io, 0x50, buf, 0x10);
	rz_io_read_at_mapped(io, 0x50, buf, 0x10);
	mu_assert_memeq(buf, (ut8 *)"FEDCBA0987654321", 0x10, "data has been correctly written at 0x50");
	rz_io_free(io);

	free(filename_io);

	fd = open(filename, O_RDONLY, 0644);
	rz_xread(fd, buf, 0x10);
	close(fd);
	mu_assert_memeq(buf, (ut8 *)"FEDCBA0987654321", 0x10, "data has been correctly written at 0x50");
	rz_file_rm(filename);
	free(filename);
	mu_end;
}

typedef struct {
	RzList /*<RzIODesc/RzIOMap>*/ *expect; /// things whose close events are expected now
	bool failed_unexpected;
} CloseTracker;

static void event_desc_close_cb(RzEvent *ev, int type, void *user, void *data) {
	CloseTracker *tracker = user;
	if (type != RZ_EVENT_IO_DESC_CLOSE) {
		tracker->failed_unexpected = true;
		return;
	}
	RzEventIODescClose *iev = data;
	RzListIter *it = rz_list_find_val(tracker->expect, iev->desc);
	if (!it) {
		tracker->failed_unexpected = true;
		return;
	}
	rz_list_delete(tracker->expect, it);
}

bool test_rz_io_event_desc_close(void) {
	RzIO *io = rz_io_new();
	io->va = true;

	CloseTracker tracker = {
		.expect = rz_list_new(),
		.failed_unexpected = false
	};
	rz_event_hook(io->event, RZ_EVENT_IO_DESC_CLOSE, event_desc_close_cb, &tracker);

	RzIODesc *desc0 = rz_io_open_nomap(io, "malloc://1024", 0644, RZ_PERM_R);
	mu_assert_notnull(desc0, "temp file has been opened");
	mu_assert_false(tracker.failed_unexpected, "unexpected close event");

	RzIODesc *desc1 = rz_io_open_nomap(io, "malloc://1024", 0644, RZ_PERM_R);
	mu_assert_notnull(desc1, "temp file has been opened");
	mu_assert_ptrneq(desc0, desc1, "new file is different");
	mu_assert_false(tracker.failed_unexpected, "unexpected close event");

	RzIODesc *desc2 = rz_io_open_nomap(io, "malloc://512", 0644, RZ_PERM_R);
	mu_assert_notnull(desc2, "temp file has been opened");
	mu_assert_ptrneq(desc0, desc2, "new file is different");
	mu_assert_ptrneq(desc1, desc2, "new file is different");
	mu_assert_false(tracker.failed_unexpected, "unexpected close event");

	rz_list_push(tracker.expect, desc1);
	rz_io_desc_close(desc1);
	mu_assert_eq(rz_list_length(tracker.expect), 0, "missing close event");
	mu_assert_false(tracker.failed_unexpected, "unexpected close event");

	desc1 = rz_io_open_nomap(io, "malloc://100", 0644, RZ_PERM_R);
	mu_assert_notnull(desc1, "temp file has been opened");
	mu_assert_false(tracker.failed_unexpected, "unexpected close event");

	rz_list_push(tracker.expect, desc0);
	rz_io_desc_close(desc0);
	mu_assert_eq(rz_list_length(tracker.expect), 0, "missing close event");
	mu_assert_false(tracker.failed_unexpected, "unexpected close event");

	rz_list_push(tracker.expect, desc1);
	rz_io_desc_close(desc1);
	mu_assert_eq(rz_list_length(tracker.expect), 0, "missing close event");
	mu_assert_false(tracker.failed_unexpected, "unexpected close event");

	RzIODesc *desctest = rz_io_desc_get(io, desc2->fd);
	mu_assert_ptreq(desctest, desc2, "still things open before free");
	rz_io_free(io);
	// free should not emit any events, we just know everything is closed
	mu_assert_eq(rz_list_length(tracker.expect), 0, "missing close event");
	mu_assert_false(tracker.failed_unexpected, "unexpected close event");
	rz_list_free(tracker.expect);
	mu_end;
}

static void event_map_del_cb(RzEvent *ev, int type, void *user, void *data) {
	CloseTracker *tracker = user;
	if (type != RZ_EVENT_IO_MAP_DEL) {
		tracker->failed_unexpected = true;
		return;
	}
	RzEventIOMapDel *iev = data;
	RzListIter *it = rz_list_find_val(tracker->expect, iev->map);
	if (!it) {
		tracker->failed_unexpected = true;
		return;
	}
	rz_list_delete(tracker->expect, it);
}

#define FILL_DUMMY_IO \
	RzIODesc *desc0 = rz_io_open_nomap(io, "malloc://1024", 0644, RZ_PERM_R); \
	mu_assert_false(tracker.failed_unexpected, "unexpected del event"); \
	RzIODesc *desc1 = rz_io_open_nomap(io, "malloc://1024", 0644, RZ_PERM_R); \
	mu_assert_false(tracker.failed_unexpected, "unexpected del event"); \
	RzIODesc *desc2 = rz_io_open_nomap(io, "malloc://512", 0644, RZ_PERM_R); \
	mu_assert_false(tracker.failed_unexpected, "unexpected del event"); \
	RzIOMap *map00 = rz_io_map_add(io, desc0->fd, RZ_PERM_R, 0, 0x100, 0x100); \
	mu_assert_notnull(map00, "map"); \
	RzIOMap *map01 = rz_io_map_add(io, desc0->fd, RZ_PERM_RW, 0, 0x300, 0x100); \
	mu_assert_notnull(map01, "map"); \
	RzIOMap *map02 = rz_io_map_add(io, desc0->fd, RZ_PERM_R, 0x10, 0x1a0, 0x40); \
	mu_assert_notnull(map02, "map"); \
	RzIOMap *map10 = rz_io_map_add(io, desc1->fd, RZ_PERM_R, 0, 0x10100, 0x100); \
	mu_assert_notnull(map10, "map"); \
	RzIOMap *map11 = rz_io_map_add(io, desc1->fd, RZ_PERM_R, 0, 0x10300, 0x100); \
	mu_assert_notnull(map11, "map"); \
	RzIOMap *map20 = rz_io_map_add(io, desc2->fd, RZ_PERM_RWX, 3, 1337, 0x50); \
	mu_assert_notnull(map20, "map");

bool test_rz_io_map_del(void) {
	RzIO *io = rz_io_new();
	io->va = true;
	io->ff = true;
	io->Oxff = 0xff;

	CloseTracker tracker = {
		.expect = rz_list_new(),
		.failed_unexpected = false
	};
	rz_event_hook(io->event, RZ_EVENT_IO_MAP_DEL, event_map_del_cb, &tracker);

	ut8 buf[4] = { 0x42, 0x42, 0x42, 0x42 };
	bool red = rz_io_read_at_mapped(io, 0x300, buf, sizeof(buf));
	mu_assert_false(red, "read before map");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xff\xff", 4, "read before map contents");
	FILL_DUMMY_IO
	mu_assert_false(tracker.failed_unexpected, "unexpected del event");
	red = rz_io_read_at_mapped(io, 0x300, buf, sizeof(buf));
	mu_assert_true(red, "read in map");
	mu_assert_memeq(buf, (const ut8 *)"\0\0\0\0", 4, "read in map contents");

	RzPVector *maps = rz_io_maps(io);
	mu_assert_true(rz_pvector_contains(maps, map01), "map registered");

	rz_list_push(tracker.expect, map01);
	rz_io_map_del(io, map01->id);
	mu_assert_eq(rz_list_length(tracker.expect), 0, "missing del event");
	mu_assert_false(tracker.failed_unexpected, "unexpected del event");
	mu_assert_false(rz_pvector_contains(maps, map01), "map unregistered");
	red = rz_io_read_at_mapped(io, 0x300, buf, sizeof(buf));
	mu_assert_false(red, "read after unmap");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xff\xff", 4, "read after unmap");

	rz_list_push(tracker.expect, map00);
	rz_list_push(tracker.expect, map02);
	rz_list_push(tracker.expect, map10);
	rz_list_push(tracker.expect, map11);
	rz_list_push(tracker.expect, map20);
	rz_io_free(io);
	mu_assert_eq(rz_list_length(tracker.expect), 0, "missing del event");
	mu_assert_false(tracker.failed_unexpected, "unexpected del event");
	rz_list_free(tracker.expect);
	mu_end;
}

bool test_rz_io_map_del_for_fd(void) {
	RzIO *io = rz_io_new();
	io->va = true;
	io->ff = true;
	io->Oxff = 0xff;

	CloseTracker tracker = {
		.expect = rz_list_new(),
		.failed_unexpected = false
	};
	rz_event_hook(io->event, RZ_EVENT_IO_MAP_DEL, event_map_del_cb, &tracker);

	FILL_DUMMY_IO

	RzPVector *maps = rz_io_maps(io);
	mu_assert_true(rz_pvector_contains(maps, map01), "map registered");

	rz_list_push(tracker.expect, map00);
	rz_list_push(tracker.expect, map01);
	rz_list_push(tracker.expect, map02);
	rz_io_map_del_for_fd(io, desc0->fd);
	mu_assert_eq(rz_list_length(tracker.expect), 0, "missing del event");
	mu_assert_false(tracker.failed_unexpected, "unexpected del event");
	mu_assert_false(rz_pvector_contains(maps, map00), "map unregistered");
	mu_assert_false(rz_pvector_contains(maps, map01), "map unregistered");
	mu_assert_false(rz_pvector_contains(maps, map02), "map unregistered");
	ut8 buf[4] = { 0x42, 0x42, 0x42, 0x42 };
	bool red = rz_io_read_at_mapped(io, 0x300, buf, sizeof(buf));
	mu_assert_false(red, "read after unmap");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xff\xff", 4, "read after unmap");

	rz_list_push(tracker.expect, map10);
	rz_list_push(tracker.expect, map11);
	rz_list_push(tracker.expect, map20);
	rz_io_free(io);
	mu_assert_eq(rz_list_length(tracker.expect), 0, "missing del event");
	mu_assert_false(tracker.failed_unexpected, "unexpected del event");
	rz_list_free(tracker.expect);
	mu_end;
}

bool test_rz_io_map_del_on_close(void) {
	RzIO *io = rz_io_new();
	io->va = true;
	io->ff = true;
	io->Oxff = 0xff;

	CloseTracker tracker = {
		.expect = rz_list_new(),
		.failed_unexpected = false
	};
	rz_event_hook(io->event, RZ_EVENT_IO_MAP_DEL, event_map_del_cb, &tracker);

	FILL_DUMMY_IO

	RzPVector *maps = rz_io_maps(io);
	mu_assert_true(rz_pvector_contains(maps, map01), "map registered");

	rz_list_push(tracker.expect, map00);
	rz_list_push(tracker.expect, map01);
	rz_list_push(tracker.expect, map02);
	rz_io_desc_close(desc0);
	mu_assert_eq(rz_list_length(tracker.expect), 0, "missing del event");
	mu_assert_false(tracker.failed_unexpected, "unexpected del event");
	mu_assert_false(rz_pvector_contains(maps, map00), "map unregistered");
	mu_assert_false(rz_pvector_contains(maps, map01), "map unregistered");
	mu_assert_false(rz_pvector_contains(maps, map02), "map unregistered");
	ut8 buf[4] = { 0x42, 0x42, 0x42, 0x42 };
	bool red = rz_io_read_at_mapped(io, 0x300, buf, sizeof(buf));
	mu_assert_false(red, "read after unmap");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xff\xff", 4, "read after unmap");

	rz_list_push(tracker.expect, map10);
	rz_list_push(tracker.expect, map11);
	rz_list_push(tracker.expect, map20);
	rz_io_free(io);
	mu_assert_eq(rz_list_length(tracker.expect), 0, "missing del event");
	mu_assert_false(tracker.failed_unexpected, "unexpected del event");
	rz_list_free(tracker.expect);
	mu_end;
}

bool test_rz_io_map_del_on_close_all(void) {
	RzIO *io = rz_io_new();
	io->va = true;
	io->ff = true;
	io->Oxff = 0xff;

	CloseTracker tracker = {
		.expect = rz_list_new(),
		.failed_unexpected = false
	};
	rz_event_hook(io->event, RZ_EVENT_IO_MAP_DEL, event_map_del_cb, &tracker);

	FILL_DUMMY_IO

	RzPVector *maps = rz_io_maps(io);
	mu_assert_true(rz_pvector_contains(maps, map01), "map registered");

	rz_list_push(tracker.expect, map00);
	rz_list_push(tracker.expect, map01);
	rz_list_push(tracker.expect, map02);
	rz_list_push(tracker.expect, map10);
	rz_list_push(tracker.expect, map11);
	rz_list_push(tracker.expect, map20);
	rz_io_close_all(io);
	mu_assert_eq(rz_list_length(tracker.expect), 0, "missing del event");
	mu_assert_false(tracker.failed_unexpected, "unexpected del event");
	mu_assert_true(rz_pvector_empty(maps), "map unregistered");
	ut8 buf[4] = { 0x42, 0x42, 0x42, 0x42 };
	bool red = rz_io_read_at_mapped(io, 0x300, buf, sizeof(buf));
	mu_assert_false(red, "read after unmap");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xff\xff", 4, "read after unmap");

	rz_io_free(io);
	// free should not emit any events, we just know everything is closed
	mu_assert_eq(rz_list_length(tracker.expect), 0, "missing del event");
	mu_assert_false(tracker.failed_unexpected, "unexpected del event");
	rz_list_free(tracker.expect);
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_rz_io_read_at_mapped);
	mu_run_test(test_rz_io_nread_at);
	mu_run_test(test_rz_io_cache);
	mu_run_test(test_rz_io_mapsplit);
	mu_run_test(test_rz_io_mapsplit2);
	mu_run_test(test_rz_io_mapsplit3);
	mu_run_test(test_rz_io_maps_vector);
	mu_run_test(test_rz_io_pcache);
	mu_run_test(test_rz_io_desc_exchange);
	mu_run_test(test_rz_io_priority);
	mu_run_test(test_rz_io_priority2);
	mu_run_test(test_va_malloc_zero);
	mu_run_test(test_rz_io_default);
	mu_run_test(test_rz_io_event_desc_close);
	mu_run_test(test_rz_io_map_del);
	mu_run_test(test_rz_io_map_del_for_fd);
	mu_run_test(test_rz_io_map_del_on_close);
	mu_run_test(test_rz_io_map_del_on_close_all);
	return tests_passed != tests_run;
}

mu_main(all_tests)
