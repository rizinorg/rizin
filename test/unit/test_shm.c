// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_th.h>
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
	rz_shm_unlink("rz_shm_test_area");
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
		rz_shm_unlink("rz_shm_zero_test");
	}

	size_t huge_size = (sizeof(void *) == 4) ? 0xFFFFF000 : 0xFFFFFFFFFFFFF000ULL;
	bool huge_ok = rz_shm_open(shm, "rz_shm_huge_test", true, huge_size);
	if (huge_ok) {
		rz_shm_close(shm);
		rz_shm_unlink("rz_shm_huge_test");
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
	rz_shm_unlink("rz_shm_lifecycle_test");
#else
	(void)rz_shm_close(shm);
#endif

	rz_shm_free(shm);
	mu_end;
}

bool test_rz_shm_unlink(void) {
	RzShm *shm = rz_shm_new();
	mu_assert_notnull(shm, "shm_new");

#if HAVE_HEADER_LINUX_ASHMEM_H || HAVE_HEADER_SYS_SHM_H || __WINDOWS__
	bool opened = rz_shm_open(shm, "rz_shm_unlink_test", true, 1024);
	mu_assert("shm_open", opened);
	rz_shm_close(shm);

	int unlink_rc = rz_shm_unlink("rz_shm_unlink_test");
#if HAVE_SHM_OPEN
	mu_assert_eq(unlink_rc, 0, "unlink should succeed");
#else
	(void)unlink_rc;
#endif

	int unlink_rc_again = rz_shm_unlink("rz_shm_unlink_test");
#if HAVE_SHM_OPEN
	mu_assert_eq(unlink_rc_again, -1, "second unlink should fail");
#else
	(void)unlink_rc_again;
#endif
#else
	int unlink_rc = rz_shm_unlink("rz_shm_unlink_test");
	mu_assert_eq(unlink_rc, 0, "unlink on unsupported returns 0");
#endif

	rz_shm_free(shm);
	mu_end;
}

#if HAVE_HEADER_LINUX_ASHMEM_H || HAVE_HEADER_SYS_SHM_H || __WINDOWS__
static void *thread_consumer(void *arg) {
	RzShm *client_shm = rz_shm_new();
	if (!client_shm) {
		return "failed to allocate";
	}
	bool opened = rz_shm_open(client_shm, "rz_shm_thread_test", false, 1024);
	if (!opened) {
		rz_shm_free(client_shm);
		return "failed to open";
	}
	ut8 buf[16] = { 0 };
	int bytes = rz_shm_read(client_shm, 0, buf, 11);
	if (bytes != 11) {
		rz_shm_close(client_shm);
		rz_shm_free(client_shm);
		return "read size mismatch";
	}
	if (strcmp((char *)buf, "parent_msg") != 0) {
		rz_shm_close(client_shm);
		rz_shm_free(client_shm);
		return "message mismatch";
	}
	rz_shm_close(client_shm);
	rz_shm_free(client_shm);
	return "OK";
}
#endif

bool test_rz_shm_thread_lifecycle(void) {
	RzShm *shm = rz_shm_new();
	mu_assert_notnull(shm, "shm_new");

#if HAVE_HEADER_LINUX_ASHMEM_H || HAVE_HEADER_SYS_SHM_H || __WINDOWS__
	bool opened = rz_shm_open(shm, "rz_shm_thread_test", true, 1024);
	mu_assert("shm_open", opened);

	int written = rz_shm_write(shm, 0, (const ut8 *)"parent_msg", 11);
	mu_assert_eq(written, 11, "parent write");

	// Spawn consumer thread
	RzThread *th = rz_th_new((RzThreadFunction)thread_consumer, NULL);
	mu_assert_notnull(th, "rz_th_new");
	rz_th_wait(th);

	const char *ret = rz_th_get_retv(th);
	mu_assert_streq(ret, "OK", "thread consumer verified mapping successfully");
	rz_th_free(th);

	// Verify parent still has access and memory holds correct content
	ut8 pbuf[16] = { 0 };
	int read_bytes = rz_shm_read(shm, 0, pbuf, 11);
	mu_assert_eq(read_bytes, 11, "parent read bytes");
	mu_assert_streq((char *)pbuf, "parent_msg", "parent read content");

	// Verify that a new client can still connect (since shm_unlink wasn't called by first client close)
	RzShm *client2 = rz_shm_new();
	mu_assert_notnull(client2, "client2 new");
	bool opened2 = rz_shm_open(client2, "rz_shm_thread_test", false, 1024);
	mu_assert("second client can open segment", opened2);
	rz_shm_close(client2);
	rz_shm_free(client2);

	// Parent closes and unlinks
	rz_shm_close(shm);
	rz_shm_unlink("rz_shm_thread_test");

	// Verify new client cannot connect after unlink
#if HAVE_SHM_OPEN
	RzShm *client3 = rz_shm_new();
	mu_assert_notnull(client3, "client3 new");
	bool opened3 = rz_shm_open(client3, "rz_shm_thread_test", false, 1024);
	mu_assert("cannot open after unlink", !opened3);
	rz_shm_free(client3);
#endif

#else
	// Fallback platform unlink
	int unlink_rc = rz_shm_unlink("rz_shm_thread_test");
	mu_assert_eq(unlink_rc, 0, "unlink fallback");
#endif

	rz_shm_free(shm);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_shm_basic);
	mu_run_test(test_rz_shm_zero_huge);
	mu_run_test(test_rz_shm_lifecycle);
	mu_run_test(test_rz_shm_unlink);
	mu_run_test(test_rz_shm_thread_lifecycle);
	return tests_passed != tests_run;
}

mu_main(all_tests)
