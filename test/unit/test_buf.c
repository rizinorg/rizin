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

bool test_rz_buf_io_fd(void) {
	RzBuffer *b;
	const char *content = "Something To\nSay Here..";
	const int length = 23;

	RzIO *io = rz_io_new();
	char *tmpfile = rz_file_temp(NULL);
	char *filename = rz_str_newf("file://%s", tmpfile);
	free(tmpfile);
	RzIODesc *desc = rz_io_open_at(io, filename, RZ_PERM_RW | RZ_PERM_CREAT, 0644, 0, NULL);
	free(filename);
	mu_assert_notnull(desc, "file should be opened for writing");

	bool res = rz_io_write_at(io, 0, (ut8 *)content, length);
	mu_assert("initial content should be written", res);

	RzIOBind bnd;
	rz_io_bind(io, &bnd);

	b = rz_buf_new_with_io_fd(&bnd, desc->fd);
	mu_assert_notnull(b, "rz_buf_new_with_io_fd");
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

bool test_rz_buf_io(void) {
	RzIO *io = rz_io_new();
	io->ff = true;
	io->Oxff = 0xff;
	io->va = true;
	RzIODesc *desc = rz_io_open_at(io, "hex://0102030405060708", RZ_PERM_RW, 0644, 0x10, NULL);
	mu_assert_notnull(desc, "file should be opened for writing");
	RzIOBind bnd;
	rz_io_bind(io, &bnd);

	RzBuffer *b = rz_buf_new_with_io(&bnd);
	rz_buf_set_overflow_byte(b, 0x42); // we don't want to see this 0x42 anywhere because the IO 0xff should be used!
	mu_assert_notnull(b, "rz_buf_new_with_io");
	rz_buf_seek(b, 0, RZ_BUF_SET);

	ut8 data[0x20] = { 0 };
	st64 red = rz_buf_read_at(b, 0x4, data, sizeof(data));
	mu_assert_eq(red, sizeof(data), "read size");
	ut8 data_expect[0x20] = {
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff
	};
	mu_assert_memeq(data, data_expect, sizeof(data), "read");

	ut8 wdata[] = { 0xab, 0xcd };
	st64 written = rz_buf_write_at(b, 0x11, wdata, sizeof(wdata));
	mu_assert_eq(written, sizeof(wdata), "written size");
	memset(data, 0, sizeof(data));
	int redi = rz_io_desc_read_at(desc, 0, data, 8);
	mu_assert_eq(redi, 8, "read size from rewritten fd");
	ut8 data_expect1[0x8] = {
		0x01, 0x0ab, 0xcd, 0x04, 0x05, 0x06, 0x07, 0x08
	};
	mu_assert_memeq(data, data_expect1, sizeof(data_expect1), "rewritten fd");

	rz_buf_free(b);
	rz_io_close(io);
	rz_io_free(io);
	mu_end;
}

bool test_rz_buf_sparse_common(void) {
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

bool test_rz_buf_sparse_split(void) {
	RzBuffer *b;
	b = rz_buf_new_sparse(0x42);
	mu_assert_notnull(b, "rz_buf_new_file failed");

	// simple cases, just some non-overlapping writes

	rz_buf_write_at(b, 0x10, (const ut8 *)"Versions", 8);
	size_t count;
	const RzBufferSparseChunk *chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Versions", 8, "chunk data");

	rz_buf_write_at(b, 0x20, (const ut8 *)"Truth", 5);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 2, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Versions", 8, "chunk data");
	mu_assert_eq(chunks[1].from, 0x20, "chunk from");
	mu_assert_eq(chunks[1].to, 0x24, "chunk to");
	mu_assert_memeq(chunks[1].data, (const ut8 *)"Truth", 5, "chunk data");

	rz_buf_write_at(b, 0x1c, (const ut8 *)"The", 3);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 3, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Versions", 8, "chunk data");
	mu_assert_eq(chunks[1].from, 0x1c, "chunk from");
	mu_assert_eq(chunks[1].to, 0x1e, "chunk to");
	mu_assert_memeq(chunks[1].data, (const ut8 *)"The", 3, "chunk data");
	mu_assert_eq(chunks[2].from, 0x20, "chunk from");
	mu_assert_eq(chunks[2].to, 0x24, "chunk to");
	mu_assert_memeq(chunks[2].data, (const ut8 *)"Truth", 5, "chunk data");

	rz_buf_write_at(b, 0x19, (const ut8 *)"Of", 2);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 4, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Versions", 8, "chunk data");
	mu_assert_eq(chunks[1].from, 0x19, "chunk from");
	mu_assert_eq(chunks[1].to, 0x1a, "chunk to");
	mu_assert_memeq(chunks[1].data, (const ut8 *)"Of", 2, "chunk data");
	mu_assert_eq(chunks[2].from, 0x1c, "chunk from");
	mu_assert_eq(chunks[2].to, 0x1e, "chunk to");
	mu_assert_memeq(chunks[2].data, (const ut8 *)"The", 3, "chunk data");
	mu_assert_eq(chunks[3].from, 0x20, "chunk from");
	mu_assert_eq(chunks[3].to, 0x24, "chunk to");
	mu_assert_memeq(chunks[3].data, (const ut8 *)"Truth", 5, "chunk data");

	ut8 buf[0x17];
	st64 r = rz_buf_read_at(b, 0xf, buf, sizeof(buf));
	mu_assert_eq(r, 0x16, "read size");
	mu_assert_memeq(buf, (const ut8 *)"\x42Versions\x42Of\x42The\x42Truth\x42", sizeof(buf), "split chunks read");

	r = rz_buf_read_at(b, 0x10, buf, sizeof(buf));
	mu_assert_eq(r, 0x15, "read size");
	mu_assert_memeq(buf, (const ut8 *)"Versions\x42Of\x42The\x42Truth\x42\x42", sizeof(buf), "split chunks read");

	r = rz_buf_read_at(b, 0xe, buf, sizeof(buf));
	mu_assert_eq(r, sizeof(buf), "read size");
	mu_assert_memeq(buf, (const ut8 *)"\x42\x42Versions\x42Of\x42The\x42Truth", sizeof(buf), "split chunks read");

	r = rz_buf_read_at(b, 0x11, buf, sizeof(buf));
	mu_assert_eq(r, 0x14, "read size");
	mu_assert_memeq(buf, (const ut8 *)"ersions\x42Of\x42The\x42Truth\x42\x42\x42", sizeof(buf), "split chunks read");

	r = rz_buf_read_at(b, 0xd, buf, sizeof(buf));
	mu_assert_eq(r, sizeof(buf), "read size");
	mu_assert_memeq(buf, (const ut8 *)"\x42\x42\x42Versions\x42Of\x42The\x42Trut", sizeof(buf), "split chunks read");

	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_sparse_write_inside(void) {
	RzBuffer *b;
	b = rz_buf_new_sparse(0x42);
	mu_assert_notnull(b, "rz_buf_new_file failed");

	// write entirely contained in another chunk

	rz_buf_write_at(b, 0x10, (const ut8 *)"Versions", 8);
	size_t count;
	const RzBufferSparseChunk *chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Versions", 8, "chunk data");

	rz_buf_write_at(b, 0x11, (const ut8 *)"Truth", 5);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"VTruthns", 8, "chunk data");

	ut8 buf[10];
	st64 r = rz_buf_read_at(b, 0xf, buf, sizeof(buf));
	mu_assert_eq(r, 9, "read size");
	mu_assert_memeq(buf, (const ut8 *)"\x42VTruthns\x42", 10, "chunks read");

	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_sparse_write_start_exact(void) {
	RzBuffer *b;
	b = rz_buf_new_sparse(0x42);
	mu_assert_notnull(b, "rz_buf_new_file failed");

	// write starting exactly at another chunk

	rz_buf_write_at(b, 0x10, (const ut8 *)"Versions", 8);
	size_t count;
	const RzBufferSparseChunk *chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Versions", 8, "chunk data");

	rz_buf_write_at(b, 0x10, (const ut8 *)"Truth", 5);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Truthons", 8, "chunk data");

	ut8 buf[10];
	st64 r = rz_buf_read_at(b, 0xf, buf, sizeof(buf));
	mu_assert_eq(r, 9, "read size");
	mu_assert_memeq(buf, (const ut8 *)"\x42Truthons\x42", 10, "chunks read");

	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_sparse_write_end_exact(void) {
	RzBuffer *b;
	b = rz_buf_new_sparse(0x42);
	mu_assert_notnull(b, "rz_buf_new_file failed");

	// write ending exactly at another chunk's end

	rz_buf_write_at(b, 0x10, (const ut8 *)"Versions", 8);
	size_t count;
	const RzBufferSparseChunk *chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Versions", 8, "chunk data");

	rz_buf_write_at(b, 0x13, (const ut8 *)"Truth", 5);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"VerTruth", 8, "chunk data");

	ut8 buf[10];
	st64 r = rz_buf_read_at(b, 0xf, buf, sizeof(buf));
	mu_assert_eq(r, 9, "read size");
	mu_assert_memeq(buf, (const ut8 *)"\x42VerTruth\x42", 10, "chunks read");

	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_sparse_write_beyond(void) {
	RzBuffer *b;
	b = rz_buf_new_sparse(0x42);
	mu_assert_notnull(b, "rz_buf_new_file failed");

	// write starting in a chunk and going beyond its end

	rz_buf_write_at(b, 0x10, (const ut8 *)"Versions", 8);
	size_t count;
	const RzBufferSparseChunk *chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Versions", 8, "chunk data");

	rz_buf_write_at(b, 0x15, (const ut8 *)"Truth", 5);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x19, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"VersiTruth", 10, "chunk data");

	ut8 buf[12];
	st64 r = rz_buf_read_at(b, 0xf, buf, sizeof(buf));
	mu_assert_eq(r, 11, "read size");
	mu_assert_memeq(buf, (const ut8 *)"\x42VersiTruth\x42", 12, "chunks read");

	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_sparse_write_into(void) {
	RzBuffer *b;
	b = rz_buf_new_sparse(0x42);
	mu_assert_notnull(b, "rz_buf_new_file failed");

	// write starting outside a chunk and going inside of it

	rz_buf_write_at(b, 0x10, (const ut8 *)"Versions", 8);
	size_t count;
	const RzBufferSparseChunk *chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Versions", 8, "chunk data");

	rz_buf_write_at(b, 0xe, (const ut8 *)"Truth", 5);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0xe, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Truthsions", 10, "chunk data");

	ut8 buf[12];
	st64 r = rz_buf_read_at(b, 0xd, buf, sizeof(buf));
	mu_assert_eq(r, 11, "read size");
	mu_assert_memeq(buf, (const ut8 *)"\x42Truthsions\x42", 12, "chunks read");

	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_sparse_write_bridge(void) {
	RzBuffer *b;
	b = rz_buf_new_sparse(0x42);
	mu_assert_notnull(b, "rz_buf_new_file failed");

	// write starting in one chunk and ending in another, bridging them into a single one

	rz_buf_write_at(b, 0x10, (const ut8 *)"Versions", 8);
	size_t count;
	const RzBufferSparseChunk *chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Versions", 8, "chunk data");

	rz_buf_write_at(b, 0x19, (const ut8 *)"Truth", 5);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 2, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Versions", 8, "chunk data");
	mu_assert_eq(chunks[1].from, 0x19, "chunk from");
	mu_assert_eq(chunks[1].to, 0x1d, "chunk to");
	mu_assert_memeq(chunks[1].data, (const ut8 *)"Truth", 5, "chunk data");

	rz_buf_write_at(b, 0x14, (const ut8 *)"OurMire", 7);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x1d, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"VersOurMireuth", 0xe, "chunk data");

	ut8 buf[0x10];
	st64 r = rz_buf_read_at(b, 0xf, buf, sizeof(buf));
	mu_assert_eq(r, 0xf, "read size");
	mu_assert_memeq(buf, (const ut8 *)"\x42VersOurMireuth\x42", 0x10, "split chunks read");

	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_sparse_write_bridge_exact(void) {
	RzBuffer *b;
	b = rz_buf_new_sparse(0x42);
	mu_assert_notnull(b, "rz_buf_new_file failed");

	// write starting exactly at the start of one chunk and ending exactly at the end of another, bridging them into a single one

	rz_buf_write_at(b, 0x10, (const ut8 *)"Versions", 8);
	size_t count;
	const RzBufferSparseChunk *chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Versions", 8, "chunk data");

	rz_buf_write_at(b, 0x19, (const ut8 *)"Truth", 5);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 2, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Versions", 8, "chunk data");
	mu_assert_eq(chunks[1].from, 0x19, "chunk from");
	mu_assert_eq(chunks[1].to, 0x1d, "chunk to");
	mu_assert_memeq(chunks[1].data, (const ut8 *)"Truth", 5, "chunk data");

	rz_buf_write_at(b, 0x10, (const ut8 *)"Try As I Might", 0xe);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x1d, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Try As I Might", 0xe, "chunk data");

	ut8 buf[0x10];
	st64 r = rz_buf_read_at(b, 0xf, buf, sizeof(buf));
	mu_assert_eq(r, 0xf, "read size");
	mu_assert_memeq(buf, (const ut8 *)"\x42Try As I Might\x42", 0x10, "split chunks read");

	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_sparse_write_bridge_over_outside(void) {
	RzBuffer *b;
	b = rz_buf_new_sparse(0x42);
	mu_assert_notnull(b, "rz_buf_new_file failed");

	// write starting before one chunk and ending after another, bridging over them into a single one

	rz_buf_write_at(b, 0x10, (const ut8 *)"Versions", 8);
	size_t count;
	const RzBufferSparseChunk *chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Versions", 8, "chunk data");

	rz_buf_write_at(b, 0x19, (const ut8 *)"Truth", 5);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 2, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x17, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Versions", 8, "chunk data");
	mu_assert_eq(chunks[1].from, 0x19, "chunk from");
	mu_assert_eq(chunks[1].to, 0x1d, "chunk to");
	mu_assert_memeq(chunks[1].data, (const ut8 *)"Truth", 5, "chunk data");

	rz_buf_write_at(b, 0xe, (const ut8 *)"Driving Like Maniacs", 0x14);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0xe, "chunk from");
	mu_assert_eq(chunks[0].to, 0x21, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Driving Like Maniacs", 0x14, "chunk data");

	ut8 buf[0x16];
	st64 r = rz_buf_read_at(b, 0xd, buf, sizeof(buf));
	mu_assert_eq(r, 0x15, "read size");
	mu_assert_memeq(buf, (const ut8 *)"\x42"
					  "Driving Like Maniacs\x42",
		0x16, "split chunks read");

	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_sparse_write_bridge_over_inside(void) {
	RzBuffer *b;
	b = rz_buf_new_sparse(0x42);
	mu_assert_notnull(b, "rz_buf_new_file failed");

	// write starting in one chunk and ending in another, bridging over one in between and combining them into a single one

	rz_buf_write_at(b, 0x10, (const ut8 *)"Not", 3);
	rz_buf_write_at(b, 0x14, (const ut8 *)"Naming", 6);
	rz_buf_write_at(b, 0x1b, (const ut8 *)"Any", 3);
	rz_buf_write_at(b, 0x1f, (const ut8 *)"Names", 5);
	size_t count;
	const RzBufferSparseChunk *chunks = rz_buf_sparse_get_chunks(b, &count);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 4, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x12, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"Not", 3, "chunk data");
	mu_assert_eq(chunks[1].from, 0x14, "chunk from");
	mu_assert_eq(chunks[1].to, 0x19, "chunk to");
	mu_assert_memeq(chunks[1].data, (const ut8 *)"Naming", 6, "chunk data");
	mu_assert_eq(chunks[2].from, 0x1b, "chunk from");
	mu_assert_eq(chunks[2].to, 0x1d, "chunk to");
	mu_assert_memeq(chunks[2].data, (const ut8 *)"Any", 3, "chunk data");
	mu_assert_eq(chunks[3].from, 0x1f, "chunk from");
	mu_assert_eq(chunks[3].to, 0x23, "chunk to");
	mu_assert_memeq(chunks[3].data, (const ut8 *)"Names", 5, "chunk data");

	rz_buf_write_at(b, 0x11, (const ut8 *)"o Man's Land", 0xc);
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 2, "chunks count");
	mu_assert_notnull(chunks, "chunks");
	mu_assert_eq(chunks[0].from, 0x10, "chunk from");
	mu_assert_eq(chunks[0].to, 0x1d, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"No Man's Landy", 0xe, "chunk data");
	mu_assert_eq(chunks[1].from, 0x1f, "chunk from");
	mu_assert_eq(chunks[1].to, 0x23, "chunk to");
	mu_assert_memeq(chunks[1].data, (const ut8 *)"Names", 5, "chunk data");

	ut8 buf[0x16];
	st64 r = rz_buf_read_at(b, 0xf, buf, sizeof(buf));
	mu_assert_eq(r, 0x15, "read size");
	mu_assert_memeq(buf, (const ut8 *)"\x42"
					  "No Man's Landy\x42Names\x42",
		0x16, "split chunks read");

	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_sparse_resize(void) {
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

	// resize to empty area
	res = rz_buf_resize(b, 10);
	mu_assert("resized to 10", res);
	ut64 sz = rz_buf_size(b);
	mu_assert_eq(sz, 10, "size is 10");
	size_t count;
	const RzBufferSparseChunk *chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 2, "chunks count after resize");
	mu_assert_eq(chunks[0].from, 3, "chunk from");
	mu_assert_eq(chunks[0].to, 6, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"aaaa", 4, "chunk data");
	mu_assert_eq(chunks[1].from, 9, "chunk from");
	mu_assert_eq(chunks[1].to, 9, "chunk to");
	mu_assert_memeq(chunks[1].data, (const ut8 *)"\xff", 1, "chunk data");

	r = rz_buf_read_at(b, 0, tmp, sizeof(tmp));
	mu_assert_eq(r, 10, "read the initial/final 0xff bytes");
	mu_assert_memeq(tmp, (ut8 *)"\xff\xff\xff\x61\x61\x61\x61\xff\xff\xff", 10, "right 10 bytes");

	// resize to exact bounds
	res = rz_buf_resize(b, 7);
	mu_assert("resized to 7", res);
	sz = rz_buf_size(b);
	mu_assert_eq(sz, 7, "size is 7");
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count after resize");
	mu_assert_eq(chunks[0].from, 3, "chunk from");
	mu_assert_eq(chunks[0].to, 6, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"aaaa", 4, "chunk data");

	r = rz_buf_read_at(b, 0, tmp, sizeof(tmp));
	mu_assert_eq(r, 7, "read the initial/final 0xff bytes");
	mu_assert_memeq(tmp, (ut8 *)"\xff\xff\xff\x61\x61\x61\x61\xff\xff\xff", 7, "right 10 bytes");

	// resize to same
	res = rz_buf_resize(b, 7);
	mu_assert("resized to 7", res);
	sz = rz_buf_size(b);
	mu_assert_eq(sz, 7, "size is 7");
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count after resize");
	mu_assert_eq(chunks[0].from, 3, "chunk from");
	mu_assert_eq(chunks[0].to, 6, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"aaaa", 4, "chunk data");

	r = rz_buf_read_at(b, 0, tmp, sizeof(tmp));
	mu_assert_eq(r, 7, "read the initial/final 0xff bytes");
	mu_assert_memeq(tmp, (ut8 *)"\xff\xff\xff\x61\x61\x61\x61\xff\xff\xff", 7, "right 10 bytes");

	// resize with chopping
	res = rz_buf_resize(b, 4);
	mu_assert("resized to 4", res);
	sz = rz_buf_size(b);
	mu_assert_eq(sz, 4, "size is 4");
	chunks = rz_buf_sparse_get_chunks(b, &count);
	mu_assert_eq(count, 1, "chunks count after resize");
	mu_assert_eq(chunks[0].from, 3, "chunk from");
	mu_assert_eq(chunks[0].to, 3, "chunk to");
	mu_assert_memeq(chunks[0].data, (const ut8 *)"a", 1, "chunk data");

	r = rz_buf_read_at(b, 0, tmp, sizeof(tmp));
	mu_assert_eq(r, 4, "read the initial/final 0xff bytes");
	mu_assert_memeq(tmp, (ut8 *)"\xff\xff\xff\x61\xff\xff\xff\xff\xff\xff", 7, "right 10 bytes");

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

bool test_rz_buf_sparse_fuzz(void) {
#define FUZZ_COUNT           200
#define AREA_SIZE            0x1000
#define FUZZ_WRITES          100
#define FUZZ_WRITE_SIZE_MAX  0x100
#define FUZZ_READS_PER_WRITE 10
	for (size_t f = 0; f < FUZZ_COUNT; f++) {
		RzBuffer *b = rz_buf_new_sparse(0xff);
		ut8 ref[AREA_SIZE];
		memset(ref, 0xff, sizeof(ref));
		// do FUZZ_WRITES random writes in both the sparse buffer and reference array
		for (size_t s = 0; s < FUZZ_WRITES; s++) {
			ut64 write_from = rand() % (AREA_SIZE - 1);
			ut64 write_size = rand() % (FUZZ_WRITE_SIZE_MAX - 1) + 1;
			if (write_from + write_size > AREA_SIZE) {
				write_size = AREA_SIZE - write_from;
				assert(write_size);
			}
			ut8 write_data[FUZZ_WRITE_SIZE_MAX];
			for (size_t i = 0; i < write_size; i++) {
				write_data[i] = rand();
			}
			st64 r = rz_buf_write_at(b, write_from, write_data, write_size);
			mu_assert_eq(r, write_size, "written size");
			memcpy(ref + write_from, write_data, write_size);

			// check the entire contents once
			ut8 read_data[AREA_SIZE];
			memset(read_data, 0x42, sizeof(read_data));
			rz_buf_read_at(b, 0, read_data, AREA_SIZE);
			mu_assert_true(!memcmp(read_data, ref, AREA_SIZE), "full read"); // faster than mu_assert_memeq

			// also after each write, do FUZZ_READS_PER_WRITE random reads from the sparse buffer and check against the ref array
			for (size_t r = 0; r < FUZZ_READS_PER_WRITE; r++) {
				ut64 read_from = rand() % (AREA_SIZE - 1);
				ut64 read_size = rand() % (AREA_SIZE - read_from - 1) + 1;
				memset(read_data, 0x42, sizeof(read_data));
				rz_buf_read_at(b, read_from, read_data, read_size);
				mu_assert_true(!memcmp(read_data, ref + read_from, read_size), "read");
			}
		}
		rz_buf_free(b);
	}
	mu_end;
#undef FUZZ_COUNT
#undef AREA_SIZE
#undef FUZZ_WRITES
#undef FUZZ_WRITE_SIZE_MAX
#undef FUZZ_READS_PER_WRITE
}

bool test_rz_buf_sparse_overlay(void) {
	ut8 tmp[0x100];
	for (size_t i = 0; i < sizeof(tmp); i++) {
		tmp[i] = i;
	}
	RzBuffer *base = rz_buf_new_with_bytes(tmp, sizeof(tmp));
	rz_buf_set_overflow_byte(base, 0x42);

	RzBuffer *b = rz_buf_new_sparse_overlay(base, RZ_BUF_SPARSE_WRITE_MODE_SPARSE);
	mu_assert_notnull(b, "rz_buf_new_sparse_overlay failed");
	rz_buf_set_overflow_byte(b, 0x24);

	rz_buf_read_at(b, 8, tmp, 0x20);
	mu_assert_memeq(tmp,
		(const ut8 *)"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a"
			     "\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27",
		0x20, "read unpopulated");

	rz_buf_write_at(b, 0x10, (const ut8 *)"Not", 3);
	rz_buf_write_at(b, 0x14, (const ut8 *)"Naming", 6);
	rz_buf_write_at(b, 0x1b, (const ut8 *)"Any", 3);
	rz_buf_write_at(b, 0x1f, (const ut8 *)"Names", 5);

	memset(tmp, 0, sizeof(tmp));
	rz_buf_read_at(base, 0, tmp, sizeof(tmp));
	for (size_t i = 0; i < sizeof(tmp); i++) {
		mu_assert_eq(tmp[i], i, "write into sparse and keep base");
	}

	rz_buf_read_at(b, 8, tmp, 0x20);
	mu_assert_memeq(tmp,
		(const ut8 *)"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0fNot\x13Naming\x1a"
			     "Any\x1eNames\x24\x25\x26\x27",
		0x20, "read combined");

	rz_buf_read_at(b, 0x30, tmp, 8);
	mu_assert_memeq(tmp, (const ut8 *)"\x30\x31\x32\x33\x34\x35\x36\x37", 8, "read base");
	rz_buf_read_at(b, 0xfe, tmp, 8);
	mu_assert_memeq(tmp, (const ut8 *)"\xfe\xff\x42\x42\x42\x42\x42\x42", 8, "read base bounds");
	rz_buf_read_at(b, 0x200, tmp, 8);
	mu_assert_memeq(tmp, (const ut8 *)"\x42\x42\x42\x42\x42\x42\x42\x42", 8, "read base 0xff only");

	// now test write through to the base buffer, the overlay should not change in writethrough mode
	rz_buf_sparse_set_write_mode(b, RZ_BUF_SPARSE_WRITE_MODE_THROUGH);
	st64 r = rz_buf_write_at(b, 0x11, (const ut8 *)"Magnolia", 8);
	mu_assert_eq(r, 8, "write success");
	r = rz_buf_read_at(base, 0x10, tmp, 0x10);
	mu_assert_eq(r, 0x10, "base read success");
	mu_assert_memeq(tmp, (const ut8 *)"\x10Magnolia\x19\x1a\x1b\x1c\x1d\x1e\x1f", 0x10, "base written");
	rz_buf_read_at(b, 8, tmp, 0x20);
	mu_assert_memeq(tmp,
		(const ut8 *)"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0fNotgNaming\x1a"
			     "Any\x1eNames\x24\x25\x26\x27",
		0x20, "overlay untouched");

	rz_buf_free(b);
	rz_buf_free(base);
	mu_end;
}

bool test_rz_buf_sparse_populated_in(void) {
	RzBuffer *b = rz_buf_new_sparse(0x42);
	mu_assert_notnull(b, "rz_buf_new_sparse failed");

	rz_buf_write_at(b, 0x10, (const ut8 *)"Not", 3);
	rz_buf_write_at(b, 0x14, (const ut8 *)"Naming", 6);
	rz_buf_write_at(b, 0x1b, (const ut8 *)"Any", 3);
	rz_buf_write_at(b, 0x1f, (const ut8 *)"Names", 5);

	bool r = rz_buf_sparse_populated_in(b, 0x0, 0x0);
	mu_assert_false(r, "populated in");
	r = rz_buf_sparse_populated_in(b, 0x0, 0xf);
	mu_assert_false(r, "populated in");
	r = rz_buf_sparse_populated_in(b, 0x0, 0x10);
	mu_assert_true(r, "populated in");
	r = rz_buf_sparse_populated_in(b, 0xf, 0x10);
	mu_assert_true(r, "populated in");
	r = rz_buf_sparse_populated_in(b, 0x10, 0x10);
	mu_assert_true(r, "populated in");
	r = rz_buf_sparse_populated_in(b, 0x0, 0x10000);
	mu_assert_true(r, "populated in");
	r = rz_buf_sparse_populated_in(b, 0x0, UT64_MAX);
	mu_assert_true(r, "populated in");
	r = rz_buf_sparse_populated_in(b, 0x12, 0x20);
	mu_assert_true(r, "populated in");
	r = rz_buf_sparse_populated_in(b, 0x18, 0x20);
	mu_assert_true(r, "populated in");
	r = rz_buf_sparse_populated_in(b, 0x1a, 0x20);
	mu_assert_true(r, "populated in");
	r = rz_buf_sparse_populated_in(b, 0x1a, 0x1a);
	mu_assert_false(r, "populated in");
	r = rz_buf_sparse_populated_in(b, 0x1f, 0x1f);
	mu_assert_true(r, "populated in");
	r = rz_buf_sparse_populated_in(b, 0x1f, 0x20);
	mu_assert_true(r, "populated in");
	r = rz_buf_sparse_populated_in(b, 0x20, 0x20);
	mu_assert_true(r, "populated in");

	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_sparse_size(void) {
	RzBuffer *b = rz_buf_new_sparse(0x42);
	mu_assert_notnull(b, "rz_buf_new_sparse failed");
	mu_assert_eq(rz_buf_size(b), 0, "buf sz");

	rz_buf_write_at(b, 0x10, (const ut8 *)"Not", 3);
	rz_buf_write_at(b, 0x14, (const ut8 *)"Naming", 6);
	rz_buf_write_at(b, 0x1f, (const ut8 *)"Names", 5);
	rz_buf_write_at(b, 0x1b, (const ut8 *)"Any", 3);
	mu_assert_eq(rz_buf_size(b), 0x24, "buf sz");

	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_sparse_overlay_size(void) {
	ut8 tmp[0x100];
	for (size_t i = 0; i < sizeof(tmp); i++) {
		tmp[i] = i;
	}
	RzBuffer *base = rz_buf_new_with_bytes(tmp, sizeof(tmp));
	rz_buf_set_overflow_byte(base, 0x42);

	RzBuffer *b = rz_buf_new_sparse_overlay(base, RZ_BUF_SPARSE_WRITE_MODE_SPARSE);
	mu_assert_notnull(b, "rz_buf_new_sparse_overlay failed");
	rz_buf_set_overflow_byte(b, 0x24);
	mu_assert_eq(rz_buf_size(b), 0x100, "buf sz");

	rz_buf_write_at(b, 0x10, (const ut8 *)"Not", 3);
	rz_buf_write_at(b, 0x14, (const ut8 *)"Naming", 6);
	rz_buf_write_at(b, 0x1f, (const ut8 *)"Names", 5);
	rz_buf_write_at(b, 0x1b, (const ut8 *)"Any", 3);
	mu_assert_eq(rz_buf_size(b), 0x100, "buf sz");

	rz_buf_write_at(b, 0x200, (const ut8 *)"Mire", 4);
	mu_assert_eq(rz_buf_size(b), 0x204, "buf sz");

	rz_buf_free(b);
	rz_buf_free(base);
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
	RzBuffer *b = rz_buf_new_with_bytes(NULL, 0);
	uint16_t a[] = { 0xdead, 0xbeef, 0xcafe, 0xbabe };
	ut8 buf[4 * sizeof(uint16_t)];

	rz_buf_fwrite(b, (ut8 *)a, "4s", 1);
	rz_buf_read_at(b, 0, buf, sizeof(buf));
	mu_assert_memeq(buf, (ut8 *)"\xad\xde\xef\xbe\xfe\xca\xbe\xba", sizeof(buf), "fwrite");

	memset(a, 0, 4 * sizeof(uint16_t));
	rz_buf_fread_at(b, 0, (ut8 *)a, "S", 4);
	mu_assert_eq(a[0], 0xadde, "first");
	mu_assert_eq(a[1], 0xefbe, "second");
	mu_assert_eq(a[2], 0xfeca, "third");
	mu_assert_eq(a[3], 0xbeba, "fourth");

	memset(a, 0, 4 * sizeof(uint16_t));
	rz_buf_fread_at(b, 0, (ut8 *)a, "1S", 4);
	mu_assert_eq(a[0], 0xadde, "first");
	mu_assert_eq(a[1], 0xefbe, "second");
	mu_assert_eq(a[2], 0xfeca, "third");
	mu_assert_eq(a[3], 0xbeba, "fourth");

	memset(a, 0, 4 * sizeof(uint16_t));
	rz_buf_fread_at(b, 0, (ut8 *)a, "S2S1S1S", 1);
	mu_assert_eq(a[0], 0xadde, "first");
	mu_assert_eq(a[1], 0xefbe, "second");
	mu_assert_eq(a[2], 0xfeca, "third");
	mu_assert_eq(a[3], 0xbeba, "fourth");

	st64 ret = rz_buf_fread_at(b, 0, (ut8 *)a, "0S", 4);
	mu_assert_eq(ret, -1, "Zero repeat count");

	ret = rz_buf_fread_at(b, 0, (ut8 *)a, "16", 1);
	mu_assert_eq(ret, -1, "No type");

	ret = rz_buf_fread_at(b, 0, (ut8 *)a, "65536c", 1);
	mu_assert_eq(ret, -1, "Big repeat count");

	uint16_t a2[] = { 0xdead, 0xbeef, 0xcafe, 0xbabe };
	ut8 buf2[8 * sizeof(uint16_t)];

	rz_buf_fwrite(b, (ut8 *)a2, "4s", 1);
	memset(buf, 0, 4 * sizeof(uint16_t));
	rz_buf_fread_at(b, 0, buf2, "13c3c", 1);
	mu_assert_memeq(buf2, (ut8 *)"\xad\xde\xef\xbe\xfe\xca\xbe\xba\xad\xde\xef\xbe\xfe\xca\xbe\xba", sizeof(buf2), "read block of bytes");

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

bool test_rz_buf_get_nstring(void) {
	ut8 *ch = malloc(128);
	memset(ch, 'A', 127);
	ch[127] = '\0';

	RzBuffer *b = rz_buf_new_with_bytes(ch, 128);

	char *s = rz_buf_get_nstring(b, 100, 10);
	mu_assert_null(s, "there is no string with size < 10 (no null terminator)");

	s = rz_buf_get_nstring(b, 117, 11);
	mu_assert_true(strlen(s) < 11, "the string length is lower than the max length");
	mu_assert_streq_free(s, (char *)ch + 117, "the string is the same");

	s = rz_buf_get_nstring(b, 0, 128);
	mu_assert_true(strlen(s) < 128, "the string length is lower than the max length");
	mu_assert_streq_free(s, (char *)ch, "the string is the same");

	s = rz_buf_get_nstring(b, 96, 50);
	mu_assert_true(strlen(s) < 50, "the string length is lower than the max length");
	mu_assert_streq_free(s, (char *)ch + 96, "the string is the same");

	s = rz_buf_get_nstring(b, 96, 32);
	mu_assert_true(strlen(s) < 32, "the string length is lower than the max length");
	mu_assert_streq_free(s, (char *)ch + 96, "the string is the same");

	rz_buf_free(b);
	free(ch);

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

typedef struct {
	ut64 offset;
	int init_count;
	int fini_count;
	bool offset_fail;
	ut8 *whole_buf;
} CustomCtx;

static bool custom_init(RzBuffer *b, const void *user) {
	CustomCtx *ctx = (void *)user;
	ctx->init_count++;
	b->priv = ctx;
	return true;
}

static bool custom_fini(RzBuffer *b) {
	CustomCtx *ctx = b->priv;
	ctx->fini_count++;
	return true;
}

static st64 custom_seek(RzBuffer *b, st64 addr, int whence) {
	CustomCtx *ctx = b->priv;
	ctx->offset = rz_seek_offset(ctx->offset, 0x200, addr, whence);
	return ctx->offset;
}

static st64 custom_read(RzBuffer *b, ut8 *buf, ut64 len) {
	CustomCtx *ctx = b->priv;
	if (ctx->offset != 0x100) {
		ctx->offset_fail = true;
	}
	memset(buf, 0x42, len);
	return len;
}

const RzBufferMethods custom_methods = {
	.init = custom_init,
	.fini = custom_fini,
	.read = custom_read,
	.seek = custom_seek
};

bool test_rz_buf_with_methods(void) {
	CustomCtx ctx = { 0 };
	RzBuffer *buf = rz_buf_new_with_methods(&custom_methods, &ctx, RZ_BUFFER_CUSTOM);
	mu_assert_notnull(buf, "buf");
	mu_assert_eq(ctx.init_count, 1, "init count");
	mu_assert_eq(ctx.fini_count, 0, "fini count");
	mu_assert_false(ctx.offset_fail, "offset fail");

	ut8 tmp[4] = { 0 };
	st64 r = rz_buf_read_at(buf, 0x100, tmp, sizeof(tmp));
	mu_assert_eq(r, sizeof(tmp), "read ret");
	mu_assert_eq(ctx.init_count, 1, "init count");
	mu_assert_eq(ctx.fini_count, 0, "fini count");
	mu_assert_false(ctx.offset_fail, "offset fail");
	mu_assert_memeq(tmp, (const ut8 *)"\x42\x42\x42\x42", sizeof(tmp), "read result");

	rz_buf_free(buf);
	mu_assert_eq(ctx.init_count, 1, "init count");
	mu_assert_eq(ctx.fini_count, 1, "fini count");
	mu_assert_false(ctx.offset_fail, "offset fail");
	mu_end;
}

bool test_rz_buf_whole_buf(void) {
	RzBuffer *b = rz_buf_new_with_bytes((ut8 *)"AAA", 3);
	ut64 size;
	const ut8 *bb1 = rz_buf_data(b, &size);
	mu_assert_notnull(bb1, "buf_data is not NULL");
	const ut8 *bb2 = rz_buf_data(b, &size);
	mu_assert_notnull(bb2, "buf_data is not NULL");
	rz_buf_free(b);
	mu_end;
}

static ut8 *custom_whole_buf(RzBuffer *b, ut64 *sz) {
	CustomCtx *ctx = b->priv;
	ut8 *r = malloc(10);
	ctx->whole_buf = r;
	if (sz) {
		*sz = 10;
	}
	return r;
}

static void custom_free_whole_buf(RzBuffer *b) {
	CustomCtx *ctx = b->priv;
	RZ_FREE(ctx->whole_buf);
}

const RzBufferMethods custom_methods2 = {
	.init = custom_init,
	.fini = custom_fini,
	.read = custom_read,
	.seek = custom_seek,
	.get_whole_buf = custom_whole_buf,
	.free_whole_buf = custom_free_whole_buf,
};

bool test_rz_buf_whole_buf_alloc(void) {
	CustomCtx ctx = { 0 };
	ut64 size;
	RzBuffer *b = rz_buf_new_with_methods(&custom_methods2, &ctx, RZ_BUFFER_CUSTOM);
	const ut8 *bb1 = rz_buf_data(b, &size);
	mu_assert_notnull(bb1, "buf_data is not NULL");
	const ut8 *bb2 = rz_buf_data(b, &size);
	mu_assert_notnull(bb2, "buf_data is not NULL");
	rz_buf_free(b);
	mu_end;
}

ut64 fwd_cmp(const ut8 *buf, ut64 sz, void *user) {
	if (!user || !sz) {
		return -1;
	}
	return memcmp(buf, user, sz) ? 0 : sz;
}

ut64 fwd_adder(const ut8 *buf, ut64 sz, void *user) {
	if (!user || !sz) {
		return -1;
	}
	ut64 *result = user;
	ut64 i;
	for (i = 0; i < sz; i++) {
		*result += buf[i];
	}
	return sz;
}

bool test_rz_buf_fwd_scan_helper(RzBuffer *b) {
	ut64 res = rz_buf_fwd_scan(b, 0, 4, fwd_cmp, (void *)"ABCD");
	mu_assert_eq(res, 4, "rz_buf_fwd_scan should return 4");
	res = rz_buf_fwd_scan(b, 0, UT64_MAX, fwd_cmp, (void *)"ABCD");
	mu_assert_eq(res, 4, "rz_buf_fwd_scan should return 4");
	res = rz_buf_fwd_scan(b, 1, UT64_MAX, fwd_cmp, (void *)"BCD");
	mu_assert_eq(res, 3, "rz_buf_fwd_scan should return 3");
	res = rz_buf_fwd_scan(b, 2, UT64_MAX, fwd_cmp, (void *)"CD");
	mu_assert_eq(res, 2, "rz_buf_fwd_scan should return 3");
	res = rz_buf_fwd_scan(b, 3, UT64_MAX, fwd_cmp, (void *)"D");
	mu_assert_eq(res, 1, "rz_buf_fwd_scan should return 1");
	res = rz_buf_fwd_scan(b, 4, UT64_MAX, fwd_cmp, NULL);
	mu_assert_eq(res, 0, "rz_buf_fwd_scan should return 0");
	res = rz_buf_fwd_scan(b, 5, UT64_MAX, fwd_cmp, NULL);
	mu_assert_eq(res, 0, "rz_buf_fwd_scan should return 0");
	res = rz_buf_fwd_scan(b, 0, 3, fwd_cmp, (void *)"ABCD");
	mu_assert_eq(res, 3, "rz_buf_fwd_scan should return 3");
	res = rz_buf_fwd_scan(b, 1, 2, fwd_cmp, (void *)"BC");
	mu_assert_eq(res, 2, "rz_buf_fwd_scan should return 2");
	res = rz_buf_fwd_scan(b, 1, 1, fwd_cmp, (void *)"B");
	mu_assert_eq(res, 1, "rz_buf_fwd_scan should return 1");
	res = rz_buf_fwd_scan(b, 1, 0, fwd_cmp, (void *)"B");
	mu_assert_eq(res, 0, "rz_buf_fwd_scan should return 0");
	res = rz_buf_fwd_scan(b, 2, 4, fwd_cmp, (void *)"CD");
	mu_assert_eq(res, 2, "rz_buf_fwd_scan should return 2");
	return true;
}

bool test_rz_buf_fwd_scan(void) {
	RzBuffer *b = rz_buf_new_with_bytes((ut8 *)"ABCD", 4);
	mu_assert_true(test_rz_buf_fwd_scan_helper(b), "rz_buf_fwd_scan with whole buffer available failed");
	RzBufferMethods methods = *b->methods;
	methods.get_whole_buf = NULL;
	b->methods = &methods;
	mu_assert_true(test_rz_buf_fwd_scan_helper(b), "rz_buf_fwd_scan with whole buffer unavailable failed");
	ut8 zero_buf[0x1000 - 4] = { 0 };
	rz_buf_append_bytes(b, zero_buf, 0x1000 - 4);
	rz_buf_append_bytes(b, (ut8 *)"EFGH", 4);
	ut64 res = rz_buf_fwd_scan(b, 0, 4, fwd_cmp, (void *)"ABCD");
	mu_assert_eq(res, 4, "rz_buf_fwd_scan should return 4");
	res = rz_buf_fwd_scan(b, 0x1000, UT64_MAX, fwd_cmp, (void *)"EFGH");
	mu_assert_eq(res, 4, "rz_buf_fwd_scan should return 4");
	res = rz_buf_fwd_scan(b, 0x1000, 3, fwd_cmp, (void *)"EFG");
	mu_assert_eq(res, 3, "rz_buf_fwd_scan should return 3");
	ut64 add_result = 0;
	res = rz_buf_fwd_scan(b, 0, UT64_MAX, fwd_adder, &add_result);
	mu_assert_eq(res, 0x1004, "rz_buf_fwd_scan should return 0x1004");
	mu_assert_eq(add_result, 'A' + 'B' + 'C' + 'D' + 'E' + 'F' + 'G' + 'H', "add_result should return be the sum of all bytes");
	rz_buf_free(b);
	mu_end;
}

bool test_rz_buf_negative(bool use_slice) {
	// Tests for reading around the high boundary of a 64bit address space
	// This is unfortunately currently not fully supported due to st64 being used
	// in many places where negative values indicate failure.
	// But at attempted read at such a high address should at least not break the
	// buffer and further reads should continue to succeed.
	RzBuffer *orig = rz_buf_new_with_bytes((ut8 *)"ABCD", 4);
	RzBuffer *b = use_slice ? rz_buf_new_slice(orig, 0, 100) : orig;

	ut8 buf[8];
	st64 r = rz_buf_read_at(b, 0xFFFFFFFFFFFF0000ULL, buf, sizeof(buf));
	mu_assert_eq(r, -1, "high read failure");

	// Due to read_at temporarily having to set and reset the seek,
	// a high read is prone to break the seek state.
	// So check if the buffer is still functional.

	r = rz_buf_read_at(b, 1, buf, sizeof(buf));
	mu_assert_eq(r, 3, "low read after high read succeeded");
	mu_assert_eq(strncmp((const char *)buf, "BCD", 3), 0, "low read result");

	// Add more tests here when full 64bit spaces are supported in RzBuffer

	if (use_slice) {
		rz_buf_free(b);
	}
	rz_buf_free(orig);
	mu_end;
}

int all_tests() {
	time_t seed = time(0);
	printf("Jamie Seed: %llu\n", (unsigned long long)seed);
	srand(seed);
	mu_run_test(test_rz_buf_file);
	mu_run_test(test_rz_buf_bytes);
	mu_run_test(test_rz_buf_mmap);
	mu_run_test(test_rz_buf_with_buf);
	mu_run_test(test_rz_buf_slice);
	mu_run_test(test_rz_buf_io_fd);
	mu_run_test(test_rz_buf_io);
	mu_run_test(test_rz_buf_sparse_common);
	mu_run_test(test_rz_buf_sparse_split);
	mu_run_test(test_rz_buf_sparse_write_inside);
	mu_run_test(test_rz_buf_sparse_write_start_exact);
	mu_run_test(test_rz_buf_sparse_write_end_exact);
	mu_run_test(test_rz_buf_sparse_write_beyond);
	mu_run_test(test_rz_buf_sparse_write_into);
	mu_run_test(test_rz_buf_sparse_write_bridge);
	mu_run_test(test_rz_buf_sparse_write_bridge_exact);
	mu_run_test(test_rz_buf_sparse_write_bridge_over_outside);
	mu_run_test(test_rz_buf_sparse_write_bridge_over_inside);
	mu_run_test(test_rz_buf_sparse_resize);
	mu_run_test(test_rz_buf_sparse_fuzz);
	mu_run_test(test_rz_buf_sparse_overlay);
	mu_run_test(test_rz_buf_sparse_populated_in);
	mu_run_test(test_rz_buf_sparse_size);
	mu_run_test(test_rz_buf_sparse_overlay_size);
	mu_run_test(test_rz_buf_bytes_steal);
	mu_run_test(test_rz_buf_format);
	mu_run_test(test_rz_buf_get_string);
	mu_run_test(test_rz_buf_get_string_nothing);
	mu_run_test(test_rz_buf_get_nstring);
	mu_run_test(test_rz_buf_slice_too_big);
	mu_run_test(test_rz_buf_with_methods);
	mu_run_test(test_rz_buf_whole_buf);
	mu_run_test(test_rz_buf_whole_buf_alloc);
	mu_run_test(test_rz_buf_fwd_scan);
	mu_run_test(test_rz_buf_negative, false);
	mu_run_test(test_rz_buf_negative, true);
	return tests_passed != tests_run;
}

mu_main(all_tests)
