#include <rz_io.h>
#include "minunit.h"

bool test_r_io_mapsplit (void) {
	RzIO *io = rz_io_new ();
	io->va = true;
	rz_io_open_at (io, "null://2", RZ_PERM_R, 0LL, UT64_MAX);
	mu_assert_true (rz_io_map_is_mapped (io, 0x0), "0x0 not mapped");
	mu_assert_true (rz_io_map_is_mapped (io, UT64_MAX), "UT64_MAX not mapped");
	mu_assert_notnull (rz_io_map_get (io, 0x0), "Found no map at 0x0");
	mu_assert_notnull (rz_io_map_get (io, UT64_MAX), "Found no map at UT64_MAX");
	rz_io_free (io);
	mu_end;
}

bool test_r_io_mapsplit2 (void) {
	RzIO *io = rz_io_new ();
	io->va = true;
	rz_io_open_at (io, "null://2", RZ_PERM_R, 0LL, 0LL);
	mu_assert_true (rz_io_map_is_mapped (io, 0x0), "0x0 not mapped");
	mu_assert_true (rz_io_map_is_mapped (io, 0x1), "0x1 not mapped");
	rz_io_map_remap (io, rz_io_map_get (io, 0LL)->id, UT64_MAX);
	mu_assert_true (rz_io_map_is_mapped (io, 0x0), "0x0 not mapped");
	mu_assert_true (rz_io_map_is_mapped (io, UT64_MAX), "UT64_MAX not mapped");
	mu_assert_false (rz_io_map_is_mapped (io, 0x1), "0x1 mapped");
	mu_assert_notnull (rz_io_map_get (io, 0x0), "Found no map at 0x0");
	mu_assert_notnull (rz_io_map_get (io, UT64_MAX), "Found no map at UT64_MAX");
	mu_assert_null (rz_io_map_get (io, 0x1), "Found map at 0x1");
	rz_io_free (io);
	mu_end;
}

bool test_r_io_mapsplit3 (void) {
	RzIO *io = rz_io_new ();
	io->va = true;
	rz_io_open_at (io, "null://2", RZ_PERM_R, 0LL, UT64_MAX - 1);
	mu_assert_true (rz_io_map_is_mapped (io, UT64_MAX - 1), "UT64_MAX - 1 not mapped");
	mu_assert_true (rz_io_map_is_mapped (io, UT64_MAX), "UT64_MAX not mapped");
	rz_io_map_resize (io, rz_io_map_get (io, UT64_MAX)->id, 3);
	mu_assert_true (rz_io_map_is_mapped (io, UT64_MAX - 1), "UT64_MAX - 1 not mapped");
	mu_assert_true (rz_io_map_is_mapped (io, UT64_MAX), "UT64_MAX not mapped");
	mu_assert_true (rz_io_map_is_mapped (io, 0x0), "0x0 not mapped");
	mu_assert_false (rz_io_map_is_mapped (io, 0x1), "0x1 mapped");
	mu_assert_notnull (rz_io_map_get (io, UT64_MAX), "Found no map at UT64_MAX");
	mu_assert_notnull (rz_io_map_get (io, 0x0), "Found no map at 0x0");
	rz_io_free (io);
	mu_end;
}

bool test_r_io_pcache (void) {
	RzIO *io = rz_io_new ();
	io->ff = 1;
	ut8 buf[8];
	int fd = rz_io_fd_open (io, "malloc://3", RZ_PERM_RW, 0);
	rz_io_map_add (io, fd, RZ_PERM_RW, 0LL, 0LL, 1); //8
	rz_io_map_add (io, fd, RZ_PERM_RW, 1, 1, 1); //=
	rz_io_map_add (io, fd, RZ_PERM_RW, 1, 2, 1); //=
	rz_io_map_add (io, fd, RZ_PERM_RW, 1, 3, 1); //=
	rz_io_map_add (io, fd, RZ_PERM_RW, 1, 4, 1); //=
	rz_io_map_add (io, fd, RZ_PERM_RW, 1, 5, 1); //=
	rz_io_map_add (io, fd, RZ_PERM_RW, 2, 6, 1); //D
	io->p_cache = 2;
	io->va = true;
	rz_io_fd_write_at (io, fd, 0, (const ut8*)"8=D", 3);
	rz_io_read_at (io, 0x0, buf, 8);
	mu_assert_streq ((const char *)buf, "", "pcache read happened, but it shouldn't");
	io->p_cache = 1;
	rz_io_read_at (io, 0x0, buf, 8);
	mu_assert_streq ((const char *)buf, "8=====D", "expected an ascii-pn from pcache");
	rz_io_fd_write_at (io, fd, 0, (const ut8*)"XXX", 3);
	rz_io_read_at (io, 0x0, buf, 8);
	mu_assert_streq ((const char *)buf, "8=====D", "expected an ascii-pn from pcache");
	io->p_cache = 0;
	rz_io_read_at (io, 0x0, buf, 8);
	mu_assert_streq ((const char *)buf, "XXXXXXX", "expected censorship of the ascii-pn");
	rz_io_free (io);
	mu_end;
}

bool test_r_io_desc_exchange (void) {
	RzIO *io = rz_io_new ();
	int fd = rz_io_fd_open (io, "malloc://3", RZ_PERM_R, 0),
	    fdx = rz_io_fd_open (io, "malloc://6", RZ_PERM_R, 0);
	rz_io_desc_exchange (io, fd, fdx);
	mu_assert ("Desc-exchange is broken", (rz_io_fd_size (io, fd) == 6));
	rz_io_free (io);
	mu_end;
}

bool test_va_malloc_zero(void) {
	RzIO *io;
	ut64 buf;
	bool ret;

	io = rz_io_new ();
	io->va = false;
	rz_io_open_at (io, "malloc://8", RZ_PERM_RW, 0644, 0x0);
	buf = 0xdeadbeefcafebabe;
	ret = rz_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert ("should be able to read", ret);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x00\x00\x00\x00\x00\x00\x00", 8, "0 should be there initially");
	rz_io_free (io);

	io = rz_io_new ();
	io->va = true;
	rz_io_open_at (io, "malloc://8", RZ_PERM_RW, 0644, 0x0);
	buf = 0xdeadbeefcafebabe;
	ret = rz_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert ("should be able to read", ret);
	mu_test_status = MU_TEST_BROKEN;
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x00\x00\x00\x00\x00\x00\x00", 8, "0 should be there initially");
	rz_io_free (io);

	mu_end;
}

bool test_r_io_priority(void) {
	RzIO *io = rz_io_new();
	ut32 map0, map1, map_big;
	ut64 buf;
	bool ret;

	io->va = true;
	rz_io_open_at (io, "malloc://8", RZ_PERM_RW, 0644, 0x0);
	map0 = rz_io_map_get (io, 0)->id;
	ret = rz_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert ("should be able to read", ret);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x00\x00\x00\x00\x00\x00\x00", 8, "0 should be there initially");
	buf = 0x9090909090909090;
	rz_io_write_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x90\x90\x90\x90\x90\x90\x90\x90", 8, "0x90 should have been written");

	rz_io_open_at (io, "malloc://2", RZ_PERM_RW, 0644, 0x4);
	map1 = rz_io_map_get (io, 4)->id;
	rz_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x90\x90\x90\x90\x00\x00\x90\x90", 8, "0x00 from map1 should overlap");

	buf ^= UT64_MAX;
	rz_io_write_at (io, 0, (ut8 *)&buf, 8);
	rz_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x6f\x6f\x6f\x6f\xff\xff\x6f\x6f", 8, "memory has been xored");

	rz_io_map_priorize (io, map0);
	rz_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x6f\x6f\x6f\x6f\x90\x90\x6f\x6f", 8, "map0 should have been prioritized");

	rz_io_map_remap (io, map1, 0x2);
	rz_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x6f\x6f\x6f\x6f\x90\x90\x6f\x6f", 8, "map1 should have been remapped");

	rz_io_map_priorize (io, map1);
	rz_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x6f\x6f\xff\xff\x90\x90\x6f\x6f", 8, "map1 should have been prioritized");

	rz_io_open_at (io, "malloc://2", RZ_PERM_RW, 0644, 0x0);
	rz_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x00\xff\xff\x90\x90\x6f\x6f", 8, "0x00 from map2 at start should overlap");

	rz_io_map_remap (io, map1, 0x1);
	rz_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x00\xff\x6f\x90\x90\x6f\x6f", 8, "map1 should have been remapped and partialy hidden");

	rz_io_open_at (io, "malloc://2", RZ_PERM_RW, 0644, 0x4);
	rz_io_open_at (io, "malloc://2", RZ_PERM_RW, 0644, 0x6);
	rz_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x00\xff\x6f\x00\x00\x00\x00", 8, "Multiple maps opened");

	buf = 0x9090909090909090;
	rz_io_open_at (io, "malloc://8", RZ_PERM_RW, 0644, 0x10);
	map_big = rz_io_map_get (io, 0x10)->id;
	rz_io_write_at (io, 0x10, (ut8 *)&buf, 8);
	rz_io_map_remap (io, map_big, 0x1);
	rz_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x90\x90\x90\x90\x90\x90\x90", 8, "map_big should cover everything from 0x1");

	rz_io_map_remap (io, map_big, 0x10);
	rz_io_map_remap (io, map_big, 0);
	rz_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x90\x90\x90\x90\x90\x90\x90\x90", 8, "map_big should cover everything");

	rz_io_free (io);
	mu_end;
}

bool test_r_io_priority2(void) {
	RzIO *io = rz_io_new();
	ut32 map0;
	ut8 buf[2];
	bool ret;

	io->va = true;
	RzIODesc *desc0 = rz_io_open_at (io, "malloc://1024", RZ_PERM_RW, 0644, 0x0);
	mu_assert_notnull (desc0, "first malloc should be opened");
	map0 = rz_io_map_get (io, 0)->id;
	ret = rz_io_read_at (io, 0, (ut8 *)&buf, 2);
	mu_assert ("should be able to read", ret);
	mu_assert_memeq (buf, (ut8 *)"\x00\x00", 2, "0 should be there initially");
	rz_io_write_at (io, 0, (const ut8 *)"\x90\x90", 2);
	rz_io_read_at (io, 0, buf, 2);
	mu_assert_memeq (buf, (ut8 *)"\x90\x90", 2, "0x90 was written");

	RzIODesc *desc1 = rz_io_open_at (io, "malloc://1024", RZ_PERM_R, 0644, 0x0);
	mu_assert_notnull (desc1, "second malloc should be opened");
	rz_io_read_at (io, 0, buf, 2);
	mu_assert_memeq (buf, (ut8 *)"\x00\x00", 2, "0x00 from map1 should be on top");

	rz_io_map_priorize (io, map0);
	rz_io_read_at (io, 0, buf, 2);
	mu_assert_memeq (buf, (ut8 *)"\x90\x90", 2, "0x90 from map0 should be on top after prioritize");

	rz_io_free (io);
	mu_end;
}

int all_tests() {
	mu_run_test(test_r_io_mapsplit);
	mu_run_test(test_r_io_mapsplit2);
	mu_run_test(test_r_io_mapsplit3);
	mu_run_test(test_r_io_pcache);
	mu_run_test(test_r_io_desc_exchange);
	mu_run_test(test_r_io_priority);
	mu_run_test(test_r_io_priority2);
	mu_run_test(test_va_malloc_zero);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
