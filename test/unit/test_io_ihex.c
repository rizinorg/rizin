// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include "minunit.h"

static const char *ihex_sample =
	":020000021000EC\r\n"
	":10010000214601360121470136007EFE09D2190140\r\n"
	":100110002146017EB7C20001FF5F16002148011988\r\n"
	":020000022000DC\r\n"
	":10010000194E79234623965778239EDA3F01B2CAC7\r\n"
	":100110003F0156702B5E712B722B732146013421E7\r\n"
	":00000001FF\r\n";

char *create_sample_file(const char *prefix) {
	char *filename = rz_file_temp(prefix);
	int fd = open(filename, O_RDWR | O_CREAT, 0644);
	rz_xwrite(fd, ihex_sample, strlen(ihex_sample));
	close(fd);
	return filename;
}

bool test_rz_io_ihex_read(void) {
	RzIO *io = rz_io_new();
	io->ff = true;
	io->Oxff = 0xff;

	char *filename = create_sample_file("ihex0");
	char *uri = rz_str_newf("ihex://%s", filename);
	rz_io_open_nomap(io, uri, RZ_PERM_R, 0);
	free(uri);

	ut8 buf[8];
	bool r = rz_io_read_at_mapped(io, 0, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\xff\xff\xff\xff\xff\xff", sizeof(buf), "read");
	r = rz_io_read_at_mapped(io, 0x10100, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\x21\x46\x01\x36\x01\x21\x47\x01", sizeof(buf), "read");
	r = rz_io_read_at_mapped(io, 0x1010e, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\x19\x01\x21\x46\x01\x7e\xb7\xc2", sizeof(buf), "read");
	r = rz_io_read_at_mapped(io, 0x200fe, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\xff\xff\x19\x4e\x79\x23\x46\x23", sizeof(buf), "read");

	rz_io_free(io);
	rz_file_rm(filename);
	free(filename);
	mu_end;
}

bool test_rz_io_ihex_write(void) {
	char *filename = create_sample_file("ihex1");
	char *uri = rz_str_newf("ihex://%s", filename);

	RzIO *io = rz_io_new();
	io->ff = true;
	io->Oxff = 0xff;
	RzIODesc *desc = rz_io_open_nomap(io, uri, RZ_PERM_RW, 0);
	mu_assert_notnull(desc, "open");

	// simple write contained entirely within one source chunk
	bool r = rz_io_write_at(io, 0x10101, (const ut8 *)"Ulu", 3);
	mu_assert_true(r, "write success");
	ut8 buf[8];
	r = rz_io_read_at_mapped(io, 0x10100, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\x21Ulu\x01\x21\x47\x01", sizeof(buf), "read");

	// write crossing source chunk boundaries
	r = rz_io_write_at(io, 0x1010e, (const ut8 *)"Mulu", 4);
	mu_assert_true(r, "write success");
	r = rz_io_read_at_mapped(io, 0x1010d, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\xd2Mulu\x01\x7e\xb7", sizeof(buf), "read");

	// write beyond source chunk boundaries
	r = rz_io_write_at(io, 0x1011e, (const ut8 *)"UrShak", 6);
	mu_assert_true(r, "write success");
	r = rz_io_read_at_mapped(io, 0x1011d, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\x48UrShak\xff", sizeof(buf), "read");

	// write before and into source chunk boundaries
	r = rz_io_write_at(io, 0x200fe, (const ut8 *)"Tarrok", 6);
	mu_assert_true(r, "write success");
	r = rz_io_read_at_mapped(io, 0x200fd, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\xffTarrok\x46", sizeof(buf), "read");

	// write outside any chunks
	r = rz_io_write_at(io, 0x10300, (const ut8 *)"Krushak", 7);
	mu_assert_true(r, "write success");
	r = rz_io_read_at_mapped(io, 0x102ff, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\xffKrushak", sizeof(buf), "read");

	// write that ends exactly at an extended addr boundary
	r = rz_io_write_at(io, 0xfff8, (const ut8 *)"01234567", 8);
	mu_assert_true(r, "write success");
	r = rz_io_read_at_mapped(io, 0xfff8, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"01234567", sizeof(buf), "read");

	// write far out in the open space
	mu_assert_eq(rz_io_desc_size(desc), 0x20120, "desc size");
	r = rz_io_write_at(io, 0x40000, (const ut8 *)"Arecibo", 7);
	mu_assert_true(r, "write success");
	// writing outside also resizes
	mu_assert_eq(rz_io_desc_size(desc), 0x40007, "desc size");
	r = rz_io_read_at_mapped(io, 0x3ffff, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\xff"
					  "Arecibo",
		sizeof(buf), "read");

	rz_io_free(io);

	const char *file_expect =
		":08FFF800303132333435363765\n"
		":020000040001F9\n"
		":1001000021556c750121470136007efe09d24d75df\n"
		":100110006c75017eb7c20001ff5f16002148557261\n"
		":040120005368616B54\n"
		":070300004B72757368616B1D\n"
		":020000040002F8\n"
		":1000fe00546172726f6b4623965778239eda3f01d6\n"
		":02010E00B2CA73\n"
		":100110003F0156702B5E712B722B732146013421E7\n"
		":020000040004F6\n"
		":070000004172656369626F44\n"
		":00000001FF\n";
	char *res = rz_file_slurp(filename, NULL);
	rz_str_remove_char(res, '\r');
	mu_assert_streq(res, file_expect, "written ihex file");
	free(res);

	// reopen and check reads again
	io = rz_io_new();
	io->ff = true;
	io->Oxff = 0xff;
	rz_io_open_nomap(io, uri, RZ_PERM_R, 0);
	r = rz_io_read_at_mapped(io, 0x10100, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\x21Ulu\x01\x21\x47\x01", sizeof(buf), "read");
	r = rz_io_read_at_mapped(io, 0x1010d, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\xd2Mulu\x01\x7e\xb7", sizeof(buf), "read");
	r = rz_io_read_at_mapped(io, 0x1011d, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\x48UrShak\xff", sizeof(buf), "read");
	r = rz_io_read_at_mapped(io, 0x200fd, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\xffTarrok\x46", sizeof(buf), "read");
	r = rz_io_read_at_mapped(io, 0x102ff, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\xffKrushak", sizeof(buf), "read");
	r = rz_io_read_at_mapped(io, 0xfff8, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"01234567", sizeof(buf), "read");
	r = rz_io_read_at_mapped(io, 0x3ffff, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\xff"
					  "Arecibo",
		sizeof(buf), "read");
	rz_io_free(io);

	rz_file_rm(filename);
	free(filename);
	free(uri);
	mu_end;
}

bool test_rz_io_ihex_write_large(void) {
	// write of a single chunk spanning more than 2 16bit pages

	char *filename = create_sample_file("ihex1");
	char *uri = rz_str_newf("ihex://%s", filename);

	RzIO *io = rz_io_new();
	io->ff = true;
	io->Oxff = 0xff;
	RzIODesc *desc = rz_io_open_nomap(io, uri, RZ_PERM_RW, 0);
	mu_assert_notnull(desc, "open");

#define DATA_SIZE 0x26219 // some large size, more than 2 16bit pages
	ut8 data[DATA_SIZE];
	for (size_t i = 0; i < sizeof(data); i++) {
		data[i] = rand();
	}

	bool r = rz_io_write_at(io, 0x1337, data, sizeof(data));
	mu_assert_true(r, "write success");

	ut8 tmp[DATA_SIZE];
#undef DATA_SIZE
	r = rz_io_read_at_mapped(io, 0x1337, tmp, sizeof(tmp));
	mu_assert_true(r, "read success");
	mu_assert_true(!memcmp(tmp, data, sizeof(data)), "re-read in memory"); // faster for this large size than mu_assert_memeq
	rz_io_free(io);

	// reopen and check again
	io = rz_io_new();
	io->ff = true;
	io->Oxff = 0xff;
	rz_io_open_nomap(io, uri, RZ_PERM_R, 0);
	r = rz_io_read_at_mapped(io, 0x1337, tmp, sizeof(tmp));
	mu_assert_true(r, "read success");
	mu_assert_true(!memcmp(tmp, data, sizeof(data)), "re-read from file"); // faster for this large size than mu_assert_memeq
	rz_io_free(io);

	rz_file_rm(filename);
	free(filename);
	free(uri);
	mu_end;
}

bool test_rz_io_ihex_resize_bigger(void) {
	char *filename = create_sample_file("ihex2");
	char *uri = rz_str_newf("ihex://%s", filename);

	RzIO *io = rz_io_new();
	io->ff = true;
	io->Oxff = 0xff;
	RzIODesc *desc = rz_io_open_nomap(io, uri, RZ_PERM_RW, 0);
	mu_assert_notnull(desc, "open");

	mu_assert_eq(rz_io_desc_size(desc), 0x20120, "desc size");
	bool r = rz_io_desc_resize(desc, 0x30000);
	mu_assert_true(r, "resized");
	mu_assert_eq(rz_io_desc_size(desc), 0x30000, "desc size");

	// Resizing to something bigger will write a single 0xff at the end since the size is
	// defined as the address after the last populated byte.
	// This behavior is debatable, but Intel Hex doesn't really have any notion of size so
	// it can actually make sense.

	// write in new space
	r = rz_io_write_at(io, 0x21000, (const ut8 *)"HoshPak", 7);
	mu_assert_true(r, "write success");
	ut8 buf[8];
	r = rz_io_read_at_mapped(io, 0x20fff, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\xffHoshPak", sizeof(buf), "read");

	rz_io_free(io);

	const char *file_expect =
		":020000040001F9\n"
		":10010000214601360121470136007EFE09D2190140\n"
		":100110002146017EB7C20001FF5F16002148011988\n"
		":020000040002F8\n"
		":10010000194E79234623965778239EDA3F01B2CAC7\n"
		":100110003F0156702B5E712B722B732146013421E7\n"
		":07100000486F736850616B3B\n"
		":01FFFF00FF02\n"
		":00000001FF\n";
	char *res = rz_file_slurp(filename, NULL);
	rz_str_remove_char(res, '\r');
	mu_assert_streq(res, file_expect, "written ihex file");
	free(res);

	// reopen and check again
	io = rz_io_new();
	io->ff = true;
	io->Oxff = 0xff;
	desc = rz_io_open_nomap(io, uri, RZ_PERM_R, 0);
	mu_assert_notnull(desc, "reopen");
	mu_assert_eq(rz_io_desc_size(desc), 0x30000, "desc size");
	r = rz_io_read_at_mapped(io, 0x20fff, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\xffHoshPak", sizeof(buf), "read");
	rz_io_free(io);

	rz_file_rm(filename);
	free(filename);
	free(uri);
	mu_end;
}

bool test_rz_io_ihex_resize_smaller(void) {
	char *filename = create_sample_file("ihex3");
	char *uri = rz_str_newf("ihex://%s", filename);

	RzIO *io = rz_io_new();
	io->ff = true;
	io->Oxff = 0xff;
	RzIODesc *desc = rz_io_open_nomap(io, uri, RZ_PERM_RW, 0);
	mu_assert_notnull(desc, "open");

	mu_assert_eq(rz_io_desc_size(desc), 0x20120, "desc size");
	bool r = rz_io_desc_resize(desc, 0x20108);
	mu_assert_true(r, "resized");
	mu_assert_eq(rz_io_desc_size(desc), 0x20108, "desc size");

	ut8 buf[8];
	r = rz_io_read_at_mapped(io, 0x20104, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\x46\x23\x96\x57\xff\xff\xff\xff", sizeof(buf), "read");

	rz_io_free(io);

	const char *file_expect =
		":020000040001F9\n"
		":10010000214601360121470136007EFE09D2190140\n"
		":100110002146017EB7C20001FF5F16002148011988\n"
		":020000040002F8\n"
		":08010000194E7923462396579E\n"
		":00000001FF\n";
	char *res = rz_file_slurp(filename, NULL);
	rz_str_remove_char(res, '\r');
	mu_assert_streq(res, file_expect, "written ihex file");
	free(res);

	// reopen and check again
	io = rz_io_new();
	io->ff = true;
	io->Oxff = 0xff;
	desc = rz_io_open_nomap(io, uri, RZ_PERM_R, 0);
	mu_assert_notnull(desc, "reopen");
	mu_assert_eq(rz_io_desc_size(desc), 0x20108, "desc size");
	r = rz_io_read_at_mapped(io, 0x20104, buf, sizeof(buf));
	mu_assert_true(r, "read success");
	mu_assert_memeq(buf, (const ut8 *)"\x46\x23\x96\x57\xff\xff\xff\xff", sizeof(buf), "read");
	rz_io_free(io);

	rz_file_rm(filename);
	free(filename);
	free(uri);
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_rz_io_ihex_read);
	mu_run_test(test_rz_io_ihex_write);
	mu_run_test(test_rz_io_ihex_write_large);
	mu_run_test(test_rz_io_ihex_resize_bigger);
	mu_run_test(test_rz_io_ihex_resize_smaller);
	return tests_passed != tests_run;
}

mu_main(all_tests)
