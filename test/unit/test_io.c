// SPDX-FileCopyrightText: 2017 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include "minunit.h"

bool test_rz_io_cache(void) {
	RzIO *io = rz_io_new();
	rz_io_open(io, "malloc://15", RZ_PERM_RW, 0);
	rz_io_write(io, (ut8 *)"ZZZZZZZZZZZZZZZ", 15);
	rz_io_cache_init(io);
	mu_assert_false(rz_io_cache_at(io, 0), "Cache shouldn't exist at 0");
	mu_assert_false(rz_io_cache_at(io, 10), "Cache shouldn't exist at 10");
	mu_assert_true(rz_io_cache_write(io, 0, (ut8 *)"AAAAA", 5), "Cache write at 0 failed");
	mu_assert_true(rz_io_cache_write(io, 10, (ut8 *)"BBBBB", 5), "Cache write at 10 failed");
	mu_assert_true(rz_io_cache_at(io, 0), "Cache should exist at 0 (beggining of cache)");
	mu_assert_true(rz_io_cache_at(io, 4), "Cache should exist at 4 (end of cache)");
	mu_assert_false(rz_io_cache_at(io, 8), "Cache shouldn't exist at 8 (between 2 caches)");
	mu_assert_true(rz_io_cache_at(io, 12), "Cache should exist at 12 (middle of cache)");
	ut8 buf[15];
	memset(buf, 'Z', sizeof(buf));
	mu_assert_true(rz_io_cache_read(io, 0, buf, sizeof(buf)), "Cache read failed");
	mu_assert_memeq(buf, (ut8 *)"AAAAAZZZZZBBBBB", sizeof(buf), "Cache read doesn't match expected output");
	memset(buf, 'Z', sizeof(buf));
	mu_assert_true(rz_io_cache_write(io, 0, (ut8 *)"CC", 2), "Overlapped cache write at 0 failed");
	mu_assert_true(rz_io_cache_write(io, 4, (ut8 *)"DD", 2), "Overlapped cache write at 4 failed");
	mu_assert_true(rz_io_cache_write(io, 8, (ut8 *)"EEE", 3), "Cache write at 4 failed");
	mu_assert_true(rz_io_cache_read(io, 0, buf, 2), "Cache read at 0 failed");
	mu_assert_true(rz_io_cache_read(io, 2, buf + 2, 2), "Cache read at 2 failed");
	mu_assert_true(rz_io_cache_read(io, 4, buf + 4, 2), "Cache read at 4 failed");
	mu_assert_true(rz_io_cache_read(io, 6, buf + 6, 2), "Cache read at 6 failed");
	mu_assert_true(rz_io_cache_read(io, 8, buf + 8, 3), "Cache read at 8 failed");
	mu_assert_true(rz_io_cache_read(io, 11, buf + 11, 4), "Cache read at 11 failed");
	mu_assert_memeq(buf, (ut8 *)"CCAADDZZEEEBBBB", sizeof(buf), "Cache read doesn't match expected output");
	mu_assert_true(rz_io_cache_write(io, 0, (ut8 *)"FFFFFFFFFFFFFFF", 15), "Cache write failed");
	mu_assert_true(rz_io_cache_read(io, 0, buf, sizeof(buf)), "Cache read failed");
	mu_assert_memeq(buf, (ut8 *)"FFFFFFFFFFFFFFF", sizeof(buf), "Cache read doesn't match expected output");
	rz_io_read_at(io, 0, buf, sizeof(buf));
	mu_assert_memeq(buf, (ut8 *)"ZZZZZZZZZZZZZZZ", sizeof(buf), "IO read without cache doesn't match expected output");
	io->cached = RZ_PERM_R;
	rz_io_read_at(io, 0, buf, sizeof(buf));
	mu_assert_memeq(buf, (ut8 *)"FFFFFFFFFFFFFFF", sizeof(buf), "IO read with cache doesn't match expected output");
	rz_io_cache_invalidate(io, 6, 1);
	memset(buf, 'Z', sizeof(buf));
	rz_io_read_at(io, 0, buf, sizeof(buf));
	mu_assert_memeq(buf, (ut8 *)"CCAADDZZEEEBBBB", sizeof(buf), "IO read after cache invalidate doesn't match expected output");
	rz_io_cache_commit(io, 0, 15);
	memset(buf, 'Z', sizeof(buf));
	io->cached = 0;
	rz_io_read_at(io, 0, buf, sizeof(buf));
	mu_assert_memeq(buf, (ut8 *)"CCAADDZZEEEBBBB", sizeof(buf), "IO read after cache commit doesn't match expected output");
	rz_io_free(io);
	mu_end;
}

bool test_rz_io_mapsplit(void) {
	RzIO *io = rz_io_new();
	io->va = true;
	rz_io_open_at(io, "null://2", RZ_PERM_R, 0LL, UT64_MAX);
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
	rz_io_open_at(io, "null://2", RZ_PERM_R, 0LL, 0LL);
	mu_assert_true(rz_io_map_is_mapped(io, 0x0), "0x0 not mapped");
	mu_assert_true(rz_io_map_is_mapped(io, 0x1), "0x1 not mapped");
	rz_io_map_remap(io, rz_io_map_get(io, 0LL)->id, UT64_MAX);
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
	rz_io_open_at(io, "null://2", RZ_PERM_R, 0LL, UT64_MAX - 1);
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

bool test_rz_io_pcache(void) {
	RzIO *io = rz_io_new();
	io->ff = 1;
	ut8 buf[8];
	int fd = rz_io_fd_open(io, "malloc://3", RZ_PERM_RW, 0);
	rz_io_map_add(io, fd, RZ_PERM_RW, 0LL, 0LL, 1); //8
	rz_io_map_add(io, fd, RZ_PERM_RW, 1, 1, 1); //=
	rz_io_map_add(io, fd, RZ_PERM_RW, 1, 2, 1); //=
	rz_io_map_add(io, fd, RZ_PERM_RW, 1, 3, 1); //=
	rz_io_map_add(io, fd, RZ_PERM_RW, 1, 4, 1); //=
	rz_io_map_add(io, fd, RZ_PERM_RW, 1, 5, 1); //=
	rz_io_map_add(io, fd, RZ_PERM_RW, 2, 6, 1); //D
	io->p_cache = 2;
	io->va = true;
	rz_io_fd_write_at(io, fd, 0, (const ut8 *)"8=D", 3);
	rz_io_read_at(io, 0x0, buf, 8);
	mu_assert_streq((const char *)buf, "", "pcache read happened, but it shouldn't");
	io->p_cache = 1;
	rz_io_read_at(io, 0x0, buf, 8);
	mu_assert_streq((const char *)buf, "8=====D", "expected an ascii-pn from pcache");
	rz_io_fd_write_at(io, fd, 0, (const ut8 *)"XXX", 3);
	rz_io_read_at(io, 0x0, buf, 8);
	mu_assert_streq((const char *)buf, "8=====D", "expected an ascii-pn from pcache");
	io->p_cache = 0;
	rz_io_read_at(io, 0x0, buf, 8);
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
	rz_io_open_at(io, "malloc://8", RZ_PERM_RW, 0644, 0x0);
	buf = 0xdeadbeefcafebabe;
	ret = rz_io_read_at(io, 0, (ut8 *)&buf, 8);
	mu_assert("should be able to read", ret);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x00\x00\x00\x00\x00\x00\x00\x00", 8, "0 should be there initially");
	rz_io_free(io);

	io = rz_io_new();
	io->va = true;
	rz_io_open_at(io, "malloc://8", RZ_PERM_RW, 0644, 0x0);
	buf = 0xdeadbeefcafebabe;
	ret = rz_io_read_at(io, 0, (ut8 *)&buf, 8);
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
	rz_io_open_at(io, "malloc://8", RZ_PERM_RW, 0644, 0x0);
	map0 = rz_io_map_get(io, 0)->id;
	ret = rz_io_read_at(io, 0, (ut8 *)&buf, 8);
	mu_assert("should be able to read", ret);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x00\x00\x00\x00\x00\x00\x00\x00", 8, "0 should be there initially");
	buf = 0x9090909090909090;
	rz_io_write_at(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x90\x90\x90\x90\x90\x90\x90\x90", 8, "0x90 should have been written");

	rz_io_open_at(io, "malloc://2", RZ_PERM_RW, 0644, 0x4);
	map1 = rz_io_map_get(io, 4)->id;
	rz_io_read_at(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x90\x90\x90\x90\x00\x00\x90\x90", 8, "0x00 from map1 should overlap");

	buf ^= UT64_MAX;
	rz_io_write_at(io, 0, (ut8 *)&buf, 8);
	rz_io_read_at(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x6f\x6f\x6f\x6f\xff\xff\x6f\x6f", 8, "memory has been xored");

	rz_io_map_priorize(io, map0);
	rz_io_read_at(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x6f\x6f\x6f\x6f\x90\x90\x6f\x6f", 8, "map0 should have been prioritized");

	rz_io_map_remap(io, map1, 0x2);
	rz_io_read_at(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x6f\x6f\x6f\x6f\x90\x90\x6f\x6f", 8, "map1 should have been remapped");

	rz_io_map_priorize(io, map1);
	rz_io_read_at(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x6f\x6f\xff\xff\x90\x90\x6f\x6f", 8, "map1 should have been prioritized");

	rz_io_open_at(io, "malloc://2", RZ_PERM_RW, 0644, 0x0);
	rz_io_read_at(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x00\x00\xff\xff\x90\x90\x6f\x6f", 8, "0x00 from map2 at start should overlap");

	rz_io_map_remap(io, map1, 0x1);
	rz_io_read_at(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x00\x00\xff\x6f\x90\x90\x6f\x6f", 8, "map1 should have been remapped and partialy hidden");

	rz_io_open_at(io, "malloc://2", RZ_PERM_RW, 0644, 0x4);
	rz_io_open_at(io, "malloc://2", RZ_PERM_RW, 0644, 0x6);
	rz_io_read_at(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x00\x00\xff\x6f\x00\x00\x00\x00", 8, "Multiple maps opened");

	buf = 0x9090909090909090;
	rz_io_open_at(io, "malloc://8", RZ_PERM_RW, 0644, 0x10);
	map_big = rz_io_map_get(io, 0x10)->id;
	rz_io_write_at(io, 0x10, (ut8 *)&buf, 8);
	rz_io_map_remap(io, map_big, 0x1);
	rz_io_read_at(io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq((ut8 *)&buf, (ut8 *)"\x00\x90\x90\x90\x90\x90\x90\x90", 8, "map_big should cover everything from 0x1");

	rz_io_map_remap(io, map_big, 0x10);
	rz_io_map_remap(io, map_big, 0);
	rz_io_read_at(io, 0, (ut8 *)&buf, 8);
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
	RzIODesc *desc0 = rz_io_open_at(io, "malloc://1024", RZ_PERM_RW, 0644, 0x0);
	mu_assert_notnull(desc0, "first malloc should be opened");
	map0 = rz_io_map_get(io, 0)->id;
	ret = rz_io_read_at(io, 0, (ut8 *)&buf, 2);
	mu_assert("should be able to read", ret);
	mu_assert_memeq(buf, (ut8 *)"\x00\x00", 2, "0 should be there initially");
	rz_io_write_at(io, 0, (const ut8 *)"\x90\x90", 2);
	rz_io_read_at(io, 0, buf, 2);
	mu_assert_memeq(buf, (ut8 *)"\x90\x90", 2, "0x90 was written");

	RzIODesc *desc1 = rz_io_open_at(io, "malloc://1024", RZ_PERM_R, 0644, 0x0);
	mu_assert_notnull(desc1, "second malloc should be opened");
	rz_io_read_at(io, 0, buf, 2);
	mu_assert_memeq(buf, (ut8 *)"\x00\x00", 2, "0x00 from map1 should be on top");

	rz_io_map_priorize(io, map0);
	rz_io_read_at(io, 0, buf, 2);
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

	RzIODesc *desc = rz_io_open_at(io, filename, RZ_PERM_R, 0, 0);
	mu_assert_notnull(desc, "temp file has been opened");
	rz_io_read_at(io, 0x0, buf, 0x10);
	mu_assert_memeq(buf, (ut8 *)"1234567890ABCDEF", 0x10, "data has been correctly read");

	RzIODesc *desc2 = rz_io_open_at(io, filename, RZ_PERM_R, 0, 0x30);
	mu_assert_notnull(desc2, "temp file has been opened at 0x30");
	rz_io_read_at(io, 0x30, buf, 0x10);
	mu_assert_memeq(buf, (ut8 *)"1234567890ABCDEF", 0x10, "data has been correctly read at 0x30");

	RzIODesc *desc3 = rz_io_open_at(io, filename, RZ_PERM_RW, 0, 0x50);
	mu_assert_notnull(desc3, "temp file has been opened in RW mode at 0x50");
	rz_io_read_at(io, 0x50, buf, 0x10);
	mu_assert_memeq(buf, (ut8 *)"1234567890ABCDEF", 0x10, "data has been correctly read at 0x50");
	memcpy(buf, "FEDCBA0987654321", 0x10);
	rz_io_write_at(io, 0x50, buf, 0x10);
	rz_io_read_at(io, 0x50, buf, 0x10);
	mu_assert_memeq(buf, (ut8 *)"FEDCBA0987654321", 0x10, "data has been correctly written at 0x50");
	rz_io_free(io);

	free(filename_io);

	fd = open(filename, O_RDONLY, 0644);
	rz_xread(fd, buf, 0x10);
	close(fd);
	mu_assert_memeq(buf, (ut8 *)"FEDCBA0987654321", 0x10, "data has been correctly written at 0x50");
	rz_file_rm(filename);
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_rz_io_cache);
	mu_run_test(test_rz_io_mapsplit);
	mu_run_test(test_rz_io_mapsplit2);
	mu_run_test(test_rz_io_mapsplit3);
	mu_run_test(test_rz_io_pcache);
	mu_run_test(test_rz_io_desc_exchange);
	mu_run_test(test_rz_io_priority);
	mu_run_test(test_rz_io_priority2);
	mu_run_test(test_va_malloc_zero);
	mu_run_test(test_rz_io_default);
	return tests_passed != tests_run;
}

mu_main(all_tests)
