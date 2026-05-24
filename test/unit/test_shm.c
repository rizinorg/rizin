// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_shm_basic(void) {
	RzShm *shm = rz_shm_new();
	mu_assert_notnull(shm, "shm_new");

#if HAVE_HEADER_LINUX_ASHMEM_H || HAVE_HEADER_SYS_SHM_H || __WINDOWS__
	bool opened = rz_shm_open(shm, "rz_shm_test_area", true, 4096);
	mu_assert("shm_open", opened);

	mu_assert_notnull(shm->buf, "shm->buf is not null");
	mu_assert_eq(shm->size, 4096, "shm size matches");

	ut8 write_buf[] = "Hello Shared Memory!";
	int written = rz_shm_write(shm, 0, write_buf, sizeof(write_buf));
	mu_assert_eq(written, (int)sizeof(write_buf), "written count");

	ut8 read_buf[sizeof(write_buf)] = { 0 };
	int read_bytes = rz_shm_read(shm, 0, read_buf, sizeof(read_buf));
	mu_assert_eq(read_bytes, (int)sizeof(write_buf), "read count");
	mu_assert_streq((char *)read_buf, (char *)write_buf, "data read matches");

	int read_out = rz_shm_read(shm, 4096, read_buf, 10);
	mu_assert_eq(read_out, 0, "read at boundary");

	int read_out_err = rz_shm_read(shm, 4097, read_buf, 10);
	mu_assert_eq(read_out_err, -1, "read out of bounds");

	rz_shm_close(shm);
#else
	// Fallback platform
	bool opened = rz_shm_open(shm, "rz_shm_test_area", true, 4096);
	mu_assert("shm_open should fail on unsupported platform", !opened);
#endif

	rz_shm_free(shm);
	mu_end;
}

bool test_rz_shm_zero_huge(void) {
	RzShm *shm = rz_shm_new();
	mu_assert_notnull(shm, "shm_new");

#if HAVE_HEADER_LINUX_ASHMEM_H || HAVE_HEADER_SYS_SHM_H || __WINDOWS__
	bool zero_ok = rz_shm_open(shm, "rz_shm_zero_test", true, 0);
	if (zero_ok) {
		ut8 byte = 0xFF;
		int write_res = rz_shm_write(shm, 0, &byte, 1);
		mu_assert_eq(write_res, -1, "writing to zero-size shm should fail");
		rz_shm_close(shm);
	}

	size_t huge_size = (sizeof(void *) == 4) ? 0xFFFFF000 : 0xFFFFFFFFFFFFF000ULL;
	bool huge_ok = rz_shm_open(shm, "rz_shm_huge_test", true, huge_size);
	if (huge_ok) {
		rz_shm_close(shm);
	}
#else
	bool zero_ok = rz_shm_open(shm, "rz_shm_zero_test", true, 0);
	mu_assert("zero-size should fail on unsupported", !zero_ok);
#endif

	rz_shm_free(shm);
	mu_end;
}

bool test_rz_shm_lifecycle(void) {
	RzShm *shm = rz_shm_new();
	mu_assert_notnull(shm, "shm_new");

#if HAVE_HEADER_LINUX_ASHMEM_H || HAVE_HEADER_SYS_SHM_H || __WINDOWS__
	bool opened = rz_shm_open(shm, "rz_shm_lifecycle_test", true, 1024);
	mu_assert("shm_open", opened);

	// standard close
	int close_rc = rz_shm_close(shm);
	(void)close_rc;

	// use after close, read/write should return -1
	ut8 tmp[10] = { 0 };
	int read_rc = rz_shm_read(shm, 0, tmp, 5);
	mu_assert_eq(read_rc, -1, "read after close fails");
	int write_rc = rz_shm_write(shm, 0, tmp, 5);
	mu_assert_eq(write_rc, -1, "write after close fails");

	// double close should not crash
	(void)rz_shm_close(shm);
#else
	(void)rz_shm_close(shm);
#endif

	rz_shm_free(shm);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_shm_basic);
	mu_run_test(test_rz_shm_zero_huge);
	mu_run_test(test_rz_shm_lifecycle);
	return tests_passed != tests_run;
}

mu_main(all_tests)
