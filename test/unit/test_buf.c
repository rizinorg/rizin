// SPDX-FileCopyrightText: 2019 xarkes
// SPDX-FileCopyrightText: 2019 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_io.h>
#include <stdlib.h>
#include "minunit.h"

bool test_buf(RzBuffer *b) {
	ut8 buffer[1024] = { 0 };
	const char *content = "Something To\nSay Here..";
	const int length = 23;
	int r;

	ut64 buf_sz = rz_buf_size(b);
	mu_assert_eq(buf_sz, length, "file size should be computed");

	r = rz_buf_read(b, buffer, length);
	mu_assert_eq(r, length, "rz_buf_read_at failed");
	mu_assert_memeq(buffer, (ut8 *)content, length, "rz_buf_read_at has corrupted content");

	const char *s = "This is a new content";
	const size_t sl = strlen(s);
	bool res = rz_buf_set_bytes(b, (ut8 *)s, sl);
	mu_assert("New content should be written", res);

	rz_buf_seek(b, 0, RZ_BUF_SET);
	r = rz_buf_read(b, buffer, sl);
	mu_assert_eq(r, sl, "rz_buf_read_at failed");
	mu_assert_memeq(buffer, (ut8 *)s, sl, "rz_buf_read_at has corrupted content");

	rz_buf_seek(b, 0, RZ_BUF_SET);
	r = rz_buf_read(b, buffer, 3);
	mu_assert_eq(r, 3, "rz_buf_read_at failed");
	mu_assert_memeq(buffer, (ut8 *)"Thi", 3, "rz_buf_read_at has corrupted content");
	r = rz_buf_read(b, buffer, 5);
	mu_assert_eq(r, 5, "rz_buf_read_at failed");
	mu_assert_memeq(buffer, (ut8 *)"s is ", 5, "rz_buf_read_at has corrupted content");

	const char *s2 = ", hello world";
	const size_t s2l = strlen(s2);
	res = rz_buf_append_string(b, s2);
	mu_assert("string should be appended", res);

	buf_sz = rz_buf_size(b);
	mu_assert_eq(buf_sz, sl + s2l, "file size should be computed");

	res = rz_buf_resize(b, 10);
	mu_assert("file should be resized", res);
	buf_sz = rz_buf_size(b);
	mu_assert_eq(buf_sz, 10, "file size should be 10");

	const int rl = rz_buf_read_at(b, 1, buffer, sizeof(buffer));
	mu_assert_eq(rl, 9, "only 9 bytes can be read from offset 1");
	mu_assert_memeq(buffer, (ut8 *)"his is a ", 9, "read right bytes from offset 1");

	rz_buf_set_bytes(b, (ut8 *)"World", strlen("World"));
	char *base = rz_buf_to_string(b);
	mu_assert_notnull(base, "string should be there");
	mu_assert_streq(base, "World", "World there");
	free(base);

	const char *s3 = "Hello ";
	res = rz_buf_prepend_bytes(b, (const ut8 *)s3, strlen(s3));
	mu_assert("bytes should be prepended", res);
	char *st = rz_buf_to_string(b);
	mu_assert_notnull(st, "string should be there");
	mu_assert_streq(st, "Hello World", "hello world there");
	free(st);

	rz_buf_insert_bytes(b, 5, (ut8 *)",", 1);
	char *st2 = rz_buf_to_string(b);
	mu_assert_notnull(st2, "string should be there");
	mu_assert_streq(st2, "Hello, World", "comma inserted");
	free(st2);

	r = rz_buf_seek(b, 0x100, RZ_BUF_SET);
	mu_assert_eq(r, 0x100, "moving seek out of current length");
	r = rz_buf_write(b, (ut8 *)"mydata", 6);
	mu_assert_eq(r, 6, "writes 6 bytes");
	r = rz_buf_read_at(b, 0xf0, buffer, sizeof(buffer));
	mu_assert_eq(r, 0x16, "read 16 bytes at the end of gap and new data");
	mu_assert_memeq(buffer, (ut8 *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, "first bytes should be 0");
	mu_assert_memeq(buffer + 0x10, (ut8 *)"mydata", 6, "then there is mydata");

	rz_buf_set_bytes(b, (ut8 *)"Hello", 5);
	RzBuffer *sec_buf = rz_buf_new_with_bytes((ut8 *)" second", 7);
	res = rz_buf_append_buf(b, sec_buf);
	mu_assert("append buf should succeed", res);
	char *st3 = rz_buf_to_string(b);
	mu_assert_streq(st3, "Hello second", "append buf correctly");
	free(st3);
	rz_buf_free(sec_buf);

	sec_buf = rz_buf_new_with_bytes((ut8 *)"123456789", 9);
	res = rz_buf_append_buf_slice(b, sec_buf, 5, 3);
	mu_assert("append buf slice should succeed", res);
	char *st4 = rz_buf_to_string(b);
	mu_assert_streq(st4, "Hello second678", "append buf slice correctly");
	free(st4);
	rz_buf_free(sec_buf);

	return MU_PASSED;
}

bool test_rz_buf_file(void) {
	RzBuffer *b;
	char *filename = "r2-XXXXXX";
	const char *content = "Something To\nSay Here..";
	const int length = 23;

	// Prepare file
	int fd = rz_file_mkstemp("", &filename);
	mu_assert_neq((ut64)fd, (ut64)-1, "mkstemp failed...");
	rz_xwrite(fd, content, length);
	close(fd);

	b = rz_buf_new_file(filename, O_RDWR, 0);
	mu_assert_notnull(b, "rz_buf_new_file failed");

	if (test_buf(b) != MU_PASSED) {
		mu_fail("test failed");
	}

	// Cleanup
	rz_buf_free(b);
	unlink(filename);
	free(filename);
	mu_end;
}

bool test_rz_buf_bytes(void) {
	RzBuffer *b;
	const char *content = "Something To\nSay Here..";
	const int length = 23;

	b = rz_buf_new_with_bytes((const ut8 *)content, length);
	mu_assert_notnull(b, "rz_buf_new_with_bytes failed");

	if (test_buf(b) != MU_PASSED) {
		mu_fail("test failed");
	}

	// Cleanup
	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_mmap(void) {
	RzBuffer *b;
	char *filename = "r2-XXXXXX";
	const char *content = "Something To\nSay Here..";
	const int length = 23;

	// Prepare file
	int fd = rz_file_mkstemp("", &filename);
	mu_assert_neq((long long)fd, -1LL, "mkstemp failed...");
	rz_xwrite(fd, content, length);
	close(fd);

	b = rz_buf_new_mmap(filename, O_RDWR, 0);
	mu_assert_notnull(b, "rz_buf_new_mmap failed");

	if (test_buf(b) != MU_PASSED) {
		rz_buf_free(b);
		unlink(filename);
		free(filename);
		mu_fail("test failed");
	}

	// Cleanup
	rz_buf_free(b);
	unlink(filename);
	free(filename);

	filename = rz_file_temp(NULL);
	b = rz_buf_new_mmap(filename, O_RDWR | O_CREAT, 0644);
	mu_assert_notnull(b, "buffer mmaped should be created");

	st64 r = rz_buf_write(b, (const ut8 *)content, length);
	mu_assert_eq(r, length, "Initial content has been written correctly to created-mmapped file");
	rz_buf_seek(b, 0, RZ_BUF_SET);

	if (test_buf(b) != MU_PASSED) {
		rz_buf_free(b);
		unlink(filename);
		free(filename);
		mu_fail("test failed");
	}

	rz_buf_free(b);
	unlink(filename);
	free(filename);

	mu_end;
}

bool test_rz_buf_io(void) {
	RzBuffer *b;
	const char *content = "Something To\nSay Here..";
	const int length = 23;

	RzIO *io = rz_io_new();
	char *tmpfile = rz_file_temp(NULL);
	char *filename = rz_str_newf("file://%s", tmpfile);
	free(tmpfile);
	RzIODesc *desc = rz_io_open_at(io, filename, RZ_PERM_RW | RZ_PERM_CREAT, 0644, 0);
	free(filename);
	mu_assert_notnull(desc, "file should be opened for writing");

	bool res = rz_io_write_at(io, 0, (ut8 *)content, length);
	mu_assert("initial content should be written", res);

	RzIOBind bnd;
	rz_io_bind(io, &bnd);

	b = rz_buf_new_with_io(&bnd, desc->fd);
	mu_assert_notnull(b, "rz_buf_new_file failed");
	rz_buf_seek(b, 0, RZ_BUF_SET);

	if (test_buf(b) != MU_PASSED) {
		mu_fail("test failed");
	}

	// Cleanup
	rz_buf_free(b);
	rz_io_close(io);
	rz_io_free(io);
	mu_end;
}

bool test_rz_buf_sparse(void) {
	RzBuffer *b;
	const char *content = "Something To\nSay Here..";
	const int length = 23;

	b = rz_buf_new_sparse(0);
	mu_assert_notnull(b, "rz_buf_new_file failed");

	rz_buf_write(b, (ut8 *)content, length);
	rz_buf_seek(b, 0, RZ_BUF_SET);

	if (test_buf(b) != MU_PASSED) {
		mu_fail("test failed");
	}

	// Cleanup
	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_sparse2(void) {
	RzBuffer *b = rz_buf_new_sparse(0xff);
	rz_buf_write(b, (ut8 *)"aaaa", 4);
	rz_buf_write(b, (ut8 *)"bbbbb", 5);
	rz_buf_write(b, (ut8 *)"cccccc", 6);
	rz_buf_write_at(b, 2, (ut8 *)"D", 1);
	rz_buf_write_at(b, 7, (ut8 *)"EEE", 3);

	ut8 tmp[20];
	int r = rz_buf_read_at(b, 0, tmp, sizeof(tmp));
	mu_assert_eq(r, 15, "read only 15 bytes");
	mu_assert_memeq(tmp, (ut8 *)"aaDabbbEEEccccc", 15, "read the right bytes");

	bool res = rz_buf_resize(b, 0);
	mu_assert("resized to 0", res);

	r = rz_buf_read_at(b, 0, tmp, sizeof(tmp));
	mu_assert_eq(r, 0, "nothing to read");

	rz_buf_write_at(b, 3, (ut8 *)"aaaa", 4);
	r = rz_buf_read_at(b, 0, tmp, sizeof(tmp));
	mu_assert_eq(r, 7, "read the initial 0xff bytes");
	mu_assert_memeq(tmp, (ut8 *)"\xff\xff\xff\x61\x61\x61\x61", 7, "right 7 bytes");

	res = rz_buf_resize(b, 10);
	mu_assert("resized to 10", res);

	ut64 sz = rz_buf_size(b);
	mu_assert_eq(sz, 10, "size is 10");
	r = rz_buf_read_at(b, 0, tmp, sizeof(tmp));
	mu_assert_eq(r, 10, "read the initial/final 0xff bytes");
	mu_assert_memeq(tmp, (ut8 *)"\xff\xff\xff\x61\x61\x61\x61\xff\xff\xff", 10, "right 10 bytes");

	r = rz_buf_write_at(b, 0x100, (ut8 *)"ABCDEF", 6);
	mu_assert_eq(r, 6, "write 6 bytes at 0x100");
	r = rz_buf_read_at(b, 0xfe, tmp, sizeof(tmp));
	mu_assert_eq(r, 8, "read 8 bytes");
	mu_assert_memeq(tmp, (ut8 *)"\xff\xff\x41\x42\x43\x44\x45\x46", 8, "right bytes");

	sz = rz_buf_size(b);
	mu_assert_eq(sz, 0x106, "size is 0x106");

	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_bytes_steal(void) {
	RzBuffer *b;
	const char *content = "Something To\nSay Here..";
	const int length = 23;

	b = rz_buf_new_with_bytes((const ut8 *)content, length);
	mu_assert_notnull(b, "rz_buf_new_file failed");
	char *s = rz_buf_to_string(b);
	mu_assert_streq(s, content, "content is right");
	free(s);

	// Cleanup
	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_format(void) {
	RzBuffer *b = rz_buf_new();
	uint16_t a[] = { 0xdead, 0xbeef, 0xcafe, 0xbabe };
	ut8 buf[4 * sizeof(uint16_t)];

	rz_buf_fwrite(b, (ut8 *)a, "4s", 1);
	rz_buf_read_at(b, 0, buf, sizeof(buf));
	mu_assert_memeq(buf, (ut8 *)"\xad\xde\xef\xbe\xfe\xca\xbe\xba", sizeof(buf), "fwrite");

	rz_buf_fread_at(b, 0, (ut8 *)a, "S", 4);
	mu_assert_eq(a[0], 0xadde, "first");
	mu_assert_eq(a[1], 0xefbe, "second");
	mu_assert_eq(a[2], 0xfeca, "third");
	mu_assert_eq(a[3], 0xbeba, "fourth");

	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_with_buf(void) {
	const char *content = "Something To\nSay Here..";
	const int length = 23;
	RzBuffer *buf = rz_buf_new_with_bytes((ut8 *)content, length);

	RzBuffer *b = rz_buf_new_with_buf(buf);
	mu_assert_notnull(b, "rz_buf_new_with_buf failed");
	rz_buf_free(buf);

	if (test_buf(b) != MU_PASSED) {
		mu_fail("rz_buf_with_buf failed");
	}

	// Cleanup
	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_slice(void) {
	const char *content = "AAAAAAAAAASomething To\nSay Here..BBBBBBBBBB";
	const int length = strlen(content);
	RzBuffer *buf = rz_buf_new_with_bytes((ut8 *)content, length);
	ut8 buffer[1024];

	RzBuffer *b = rz_buf_new_slice(buf, 10, 23);
	mu_assert_notnull(b, "rz_buf_new_slice failed");

	ut64 buf_sz = rz_buf_size(b);
	mu_assert_eq(buf_sz, 23, "file size should be computed");

	int r = rz_buf_read_at(b, 0, buffer, 23);
	mu_assert_eq(r, 23, "rz_buf_read_at failed");
	mu_assert_memeq(buffer, (ut8 *)"Something To\nSay Here..", 23, "rz_buf_read_at has corrupted content");

	rz_buf_seek(b, 3, RZ_BUF_SET);
	r = rz_buf_read(b, buffer, 3);
	mu_assert_eq(r, 3, "only 3 read");
	mu_assert_memeq(buffer, (ut8 *)"eth", 3, "base should be considered");

	r = rz_buf_read(b, buffer, 40);
	mu_assert_eq(r, 23 - 6, "consider limit");

	bool res = rz_buf_resize(b, 30);
	mu_assert("file should be resized", res);
	buf_sz = rz_buf_size(b);
	mu_assert_eq(buf_sz, 30, "file size should be 30");

	// Cleanup
	rz_buf_free(b);
	rz_buf_free(buf);
	mu_end;
}

bool test_rz_buf_get_string(void) {
	ut8 *ch = malloc(128);
	memset(ch, 'A', 127);
	ch[127] = '\0';
	RzBuffer *b = rz_buf_new_with_bytes(ch, 128);
	char *s = rz_buf_get_string(b, 100);
	mu_assert_streq(s, (char *)ch + 100, "the string is the same");
	free(s);
	s = rz_buf_get_string(b, 0);
	mu_assert_streq(s, (char *)ch, "the string is the same");
	free(s);
	s = rz_buf_get_string(b, 127);
	mu_assert_streq(s, "\x00", "the string is empty");
	free(s);
	rz_buf_free(b);
	free(ch);
	mu_end;
}

bool test_rz_buf_get_string_nothing(void) {
	RzBuffer *b = rz_buf_new_with_bytes((ut8 *)"\x33\x22", 2);
	char *s = rz_buf_get_string(b, 0);
	mu_assert_null(s, "there is no string in the buffer (no null terminator)");
	rz_buf_append_bytes(b, (ut8 *)"\x00", 1);
	s = rz_buf_get_string(b, 0);
	mu_assert_streq(s, "\x33\x22", "now there is a string because of the null terminator");
	free(s);
	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_slice_too_big(void) {
	RzBuffer *buf = rz_buf_new_with_bytes((ut8 *)"AAAA", 4);
	RzBuffer *sl = rz_buf_new_slice(buf, 1, 5);
	ut64 sz = rz_buf_size(sl);
	mu_assert_eq(sz, 3, "the size cannot be more than the original buffer");
	rz_buf_resize(sl, 1);
	sz = rz_buf_size(sl);
	mu_assert_eq(sz, 1, "it should be shrinked to 1 byte");
	bool res = rz_buf_resize(sl, 7);
	mu_assert("the resize should be successful", res);
	sz = rz_buf_size(sl);
	mu_assert_eq(sz, 3, "but it should just use the biggest value");
	rz_buf_free(sl);
	rz_buf_free(buf);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_buf_file);
	mu_run_test(test_rz_buf_bytes);
	mu_run_test(test_rz_buf_mmap);
	mu_run_test(test_rz_buf_with_buf);
	mu_run_test(test_rz_buf_slice);
	mu_run_test(test_rz_buf_io);
	mu_run_test(test_rz_buf_sparse);
	mu_run_test(test_rz_buf_sparse2);
	mu_run_test(test_rz_buf_bytes_steal);
	mu_run_test(test_rz_buf_format);
	mu_run_test(test_rz_buf_get_string);
	mu_run_test(test_rz_buf_get_string_nothing);
	mu_run_test(test_rz_buf_slice_too_big);
	return tests_passed != tests_run;
}

mu_main(all_tests)
