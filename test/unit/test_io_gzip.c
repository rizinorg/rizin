// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include "minunit.h"

static const ut8 first_member[] = { 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x73, 0xf3, 0x0c, 0x0a, 0x0e, 0x01, 0x00, 0xe7, 0x2c, 0x25, 0x65, 0x05, 0x00, 0x00, 0x00 };
static const ut8 second_member[] = { 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x0b, 0x76, 0x75, 0xf6, 0xf7, 0x73, 0x01, 0x00, 0xef, 0xd6, 0xe7, 0x46, 0x06, 0x00, 0x00, 0x00 };
static const ut8 third_member[] = { 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x0b, 0xf1, 0xf0, 0x0c, 0x72, 0x01, 0x00, 0xd4, 0xe2, 0x66, 0xd3, 0x05, 0x00, 0x00, 0x00 };
static const ut8 empty_member[] = { 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const ut8 invalid_member[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };

static char *create_fixture(const ut8 **parts, const size_t *part_lens, size_t parts_count) {
	char *filename = rz_file_temp("io_gzip");
	size_t total_len = 0;
	for (size_t i = 0; i < parts_count; i++) {
		total_len += part_lens[i];
	}
	ut8 *contents = malloc(total_len);
	size_t offset = 0;
	for (size_t i = 0; i < parts_count; i++) {
		memcpy(contents + offset, parts[i], part_lens[i]);
		offset += part_lens[i];
	}
	int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	rz_xwrite(fd, contents, total_len);
	close(fd);
	free(contents);
	return filename;
}

static RzIODesc *open_fixture(RzIO *io, const ut8 **parts, const size_t *part_lens, size_t parts_count, char **filename, char **uri) {
	*filename = create_fixture(parts, part_lens, parts_count);
	*uri = rz_str_newf("gzip://%s", *filename);
	return rz_io_open_nomap(io, *uri, RZ_PERM_R, 0);
}

static void close_fixture(char *filename, char *uri) {
	rz_file_rm(filename);
	free(filename);
	free(uri);
}

bool test_rz_io_gzip_single_member(void) {
	RzIO *io = rz_io_new();
	const ut8 *parts[] = { first_member };
	const size_t lens[] = { sizeof(first_member) };
	char *filename, *uri;
	RzIODesc *desc = open_fixture(io, parts, lens, 1, &filename, &uri);
	mu_assert_notnull(desc, "open single member");
	mu_assert_eq(rz_io_desc_size(desc), 5, "single member size");
	ut8 buf[6] = { 0 };
	bool r = rz_io_read_at_mapped(io, 0, buf, 5);
	mu_assert_true(r, "read single member");
	mu_assert_memeq(buf, (const ut8 *)"FIRST", 5, "single member contents");
	rz_io_free(io);
	close_fixture(filename, uri);
	mu_end;
}

bool test_rz_io_gzip_two_concatenated_members(void) {
	RzIO *io = rz_io_new();
	io->ff = true;
	io->Oxff = 0xff;
	const ut8 *parts[] = { first_member, second_member };
	const size_t lens[] = { sizeof(first_member), sizeof(second_member) };
	char *filename, *uri;
	RzIODesc *desc = open_fixture(io, parts, lens, 2, &filename, &uri);
	mu_assert_notnull(desc, "open concatenated members");
	mu_assert_eq(rz_io_desc_size(desc), 11, "combined logical size");
	ut8 buf[12] = { 0 };
	bool r = rz_io_read_at_mapped(io, 0, buf, 11);
	mu_assert_true(r, "read combined members");
	mu_assert_memeq(buf, (const ut8 *)"FIRSTSECOND", 11, "combined member contents");
	memset(buf, 0xff, sizeof(buf));
	r = rz_io_read_at_mapped(io, 5, buf, 6);
	mu_assert_true(r, "read crossing member boundary");
	mu_assert_memeq(buf, (const ut8 *)"SECOND", 6, "second member starts at offset 5");
	r = rz_io_read_at_mapped(io, 10, buf, 4);
	mu_assert_true(r, "read past the end");
	mu_assert_eq(buf[0], 'D', "bytes at the end remain in range");
	mu_assert_eq(buf[1], 0xff, "bytes after the end use the fill byte");
	rz_io_free(io);
	close_fixture(filename, uri);
	mu_end;
}

bool test_rz_io_gzip_three_concatenated_members(void) {
	RzIO *io = rz_io_new();
	const ut8 *parts[] = { first_member, second_member, third_member };
	const size_t lens[] = { sizeof(first_member), sizeof(second_member), sizeof(third_member) };
	char *filename, *uri;
	RzIODesc *desc = open_fixture(io, parts, lens, 3, &filename, &uri);
	mu_assert_notnull(desc, "open three members");
	mu_assert_eq(rz_io_desc_size(desc), 16, "combined logical size");
	ut8 buf[17] = { 0 };
	bool r = rz_io_read_at_mapped(io, 0, buf, 16);
	mu_assert_true(r, "read three members");
	mu_assert_memeq(buf, (const ut8 *)"FIRSTSECONDTHIRD", 16, "three member contents");
	rz_io_free(io);
	close_fixture(filename, uri);
	mu_end;
}

bool test_rz_io_gzip_empty_members(void) {
	RzIO *io = rz_io_new();
	const ut8 *parts[] = { first_member, empty_member, second_member };
	const size_t lens[] = { sizeof(first_member), sizeof(empty_member), sizeof(second_member) };
	char *filename, *uri;
	RzIODesc *desc = open_fixture(io, parts, lens, 3, &filename, &uri);
	mu_assert_notnull(desc, "open with an empty member");
	mu_assert_eq(rz_io_desc_size(desc), 11, "empty member contributes no bytes");
	ut8 buf[12] = { 0 };
	bool r = rz_io_read_at_mapped(io, 0, buf, 11);
	mu_assert_true(r, "read with an empty member");
	mu_assert_memeq(buf, (const ut8 *)"FIRSTSECOND", 11, "content around an empty member");
	rz_io_free(io);
	close_fixture(filename, uri);

	io = rz_io_new();
	const ut8 *only_empty[] = { empty_member };
	const size_t only_empty_lens[] = { sizeof(empty_member) };
	desc = open_fixture(io, only_empty, only_empty_lens, 1, &filename, &uri);
	mu_assert_notnull(desc, "open a single empty member");
	mu_assert_eq(rz_io_desc_size(desc), 0, "empty member size");
	rz_io_free(io);
	close_fixture(filename, uri);
	mu_end;
}

bool test_rz_io_gzip_invalid_second_member(void) {
	RzIO *io = rz_io_new();
	const ut8 *parts[] = { first_member, invalid_member };
	const size_t lens[] = { sizeof(first_member), sizeof(invalid_member) };
	char *filename, *uri;
	RzIODesc *desc = open_fixture(io, parts, lens, 2, &filename, &uri);
	mu_assert_null(desc, "invalid second member fails the whole file");
	rz_io_free(io);
	close_fixture(filename, uri);
	mu_end;
}

bool test_rz_io_gzip_truncated_second_member(void) {
	RzIO *io = rz_io_new();
	const ut8 *parts[] = { first_member, second_member };
	const size_t lens[] = { sizeof(first_member), 5 };
	char *filename, *uri;
	RzIODesc *desc = open_fixture(io, parts, lens, 2, &filename, &uri);
	mu_assert_null(desc, "truncated second member fails the whole file");
	rz_io_free(io);
	close_fixture(filename, uri);
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_rz_io_gzip_single_member);
	mu_run_test(test_rz_io_gzip_two_concatenated_members);
	mu_run_test(test_rz_io_gzip_three_concatenated_members);
	mu_run_test(test_rz_io_gzip_empty_members);
	mu_run_test(test_rz_io_gzip_invalid_second_member);
	mu_run_test(test_rz_io_gzip_truncated_second_member);
	return tests_passed != tests_run;
}

mu_main(all_tests)
