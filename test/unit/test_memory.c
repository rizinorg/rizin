// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_memory/rz_memory.h>
#include "minunit.h"

typedef struct mem_check_s {
	const RzMemoryMap *mmap;
	RzMemoryVisibility visibility;
	const RzInterval *boundaries;
} mem_check_t;

static RzMemoryMap *new_mmap_ro(const char *name, RzBuffer *buffer, ut64 paddr, ut64 psize, ut64 vaddr, ut64 vsize) {
	RzInterval buf_offset = {
		.addr = paddr,
		.size = psize,
	};
	RzInterval mem_offset = {
		.addr = vaddr,
		.size = vsize,
	};
	return rz_memory_map_new(name, RZ_PERM_R, buffer, &buf_offset, &mem_offset);
}

static RzMemoryMap *new_mmap_rw(const char *name, RzBuffer *buffer, ut64 paddr, ut64 psize, ut64 vaddr, ut64 vsize) {
	RzInterval buf_offset = {
		.addr = paddr,
		.size = psize,
	};
	RzInterval mem_offset = {
		.addr = vaddr,
		.size = vsize,
	};
	return rz_memory_map_new(name, RZ_PERM_RW, buffer, &buf_offset, &mem_offset);
}

static bool test_check_memory_position(size_t i, const RzMemoryMap *mmap, RzMemoryVisibility visibility, void *user) {
	mem_check_t *check_map = (mem_check_t *)user;
	check_map[i].mmap = mmap;
	check_map[i].visibility = visibility;
	return true;
}

static bool test_rz_memory_map_memory_boundaries(const RzMemoryMap *mmap, ut64 start, ut64 size) {
	RzInterval itv = { 0 };
	rz_memory_map_get_memory_boundaries(mmap, &itv);

	return start == itv.addr && size == itv.size;
}

static bool test_rz_memory_map_buffer_boundaries(const RzMemoryMap *mmap, ut64 start, ut64 size) {
	RzInterval itv = { 0 };
	rz_memory_map_get_buffer_boundaries(mmap, &itv);

	return start == itv.addr && size == itv.size;
}

static bool test_check_region_position(size_t i, const RzMemoryMap *mmap, const RzInterval *boundaries, void *user) {
	mem_check_t *check_map = (mem_check_t *)user;
	check_map[i].mmap = mmap;
	check_map[i].boundaries = boundaries;
	return true;
}

bool test_rz_memory_free_functions(void) {
	rz_memory_free(NULL);
	rz_memory_region_free(NULL);

	mu_end;
}

bool test_rz_memory_map_new(void) {
	RzInterval buf_offset = {
		.addr = 0,
		.size = 0x10,
	};
	RzInterval mem_offset = {
		.addr = 0x100,
		.size = 0x400,
	};
	RzMemoryMap *mmap = NULL;
	RzBuffer *buf = rz_buf_new_empty(0x10);

	// invalid buf_offset
	buf_offset.size = 0;
	mmap = rz_memory_map_new("whatever", RZ_PERM_R, buf, &buf_offset, &mem_offset);
	mu_assert_null(mmap, "mmap is null due buf_offset");

	// invalid mem_offset
	buf_offset.size = 0x10;
	mem_offset.size = 0;
	mmap = rz_memory_map_new("whatever", RZ_PERM_R, buf, &buf_offset, &mem_offset);
	mu_assert_null(mmap, "mmap is null due mem_offset");

	rz_buf_free(buf);
	mu_end;
}

bool test_rz_memory_region_iterate(void) {
	bool ret = false;
	RzMemoryRegion *mem_region = NULL;
	RzInterval partial_memspace = {
		.addr = 0x90,
		.size = 0x200,
	};
	mem_check_t check_map[5] = { 0 };

	RzBuffer *short_buf1 = rz_buf_new_with_string("|hidden|");
	mu_assert_notnull(short_buf1, "rz_buf_new_with_string is not null");
	size_t short_buf1_sz = rz_buf_size(short_buf1);
	mu_assert_neq(short_buf1_sz, 0, "short_buf_sz is not zero");

	RzBuffer *short_buf2 = rz_buf_new_with_string("(h!de)");
	mu_assert_notnull(short_buf2, "rz_buf_new_with_string is not null");
	size_t short_buf2_sz = rz_buf_size(short_buf2);
	mu_assert_neq(short_buf2_sz, 0, "short_buf_sz is not zero");

	RzBuffer *long_buf = rz_buf_new_with_string("this is a longg string| these chars are part of the long string!!!!");
	mu_assert_notnull(long_buf, "rz_buf_new_with_string is not null");
	size_t long_buf_sz = rz_buf_size(long_buf);
	mu_assert_neq(long_buf_sz, 0, "long_buf_sz is not zero");

	RzMemory *memory = rz_memory_new();
	mu_assert_notnull(memory, "rz_memory_new is not null");

	// map a short buffer but vsize is bigger than the actual buffer
	RzMemoryMap *short_mmap1 = new_mmap_ro("short1", short_buf1, 0, short_buf1_sz, 0x120, 0x10);
	mu_assert_notnull(short_mmap1, "rz_memory_map_new is not null");

	// map a short buffer but vsize is bigger than the actual buffer
	RzMemoryMap *short_mmap2 = new_mmap_ro("short2", short_buf2, 0, short_buf2_sz, 0x110, short_buf2_sz);
	mu_assert_notnull(short_mmap2, "rz_memory_map_new is not null");

	// map a short buffer but vsize is bigger than the actual buffer
	RzMemoryMap *long_mmap = new_mmap_ro("longgg", long_buf, 0, long_buf_sz, 0x100, long_buf_sz);
	mu_assert_notnull(long_mmap, "rz_memory_map_new is not null");

	// Add short1 map to the top
	ret = rz_memory_add_map(memory, short_mmap1, true);
	mu_assert_true(ret, "rz_memory_add_map(short_mmap1, top=true) should not fail");

	// Add short2 map to the bottom
	ret = rz_memory_add_map(memory, short_mmap2, false);
	mu_assert_true(ret, "rz_memory_add_map(short_mmap2, top=false) should not fail");

	// Add long map to the bottom
	ret = rz_memory_add_map(memory, long_mmap, false);
	mu_assert_true(ret, "rz_memory_add_map(long_mmap, top=true) should not fail");

	// request mem region based on current space
	mem_region = rz_memory_new_region(memory, &partial_memspace);
	mu_assert_notnull(mem_region, "when requested the partial");
	mu_assert_true(rz_memory_region_has_memory_maps(mem_region), "when requested the partial, it should not be null");

	rz_memory_region_iterate_over(mem_region, test_check_region_position, check_map);

	/// memory space visualization
	///     |- short_mmap2 -|
	///                           |- short_mmap1 -|
	/// |- long_mmap -------------------------------------|

	// below is the flatten version
	mu_assert_ptreq(check_map[0].mmap, long_mmap, "at 0 is long_mmap");
	mu_assert_ptreq(check_map[1].mmap, short_mmap2, "at 1 is short_mmap2");
	mu_assert_ptreq(check_map[2].mmap, long_mmap, "at 2 is long_mmap");
	mu_assert_ptreq(check_map[3].mmap, short_mmap1, "at 3 is short_mmap1");
	mu_assert_ptreq(check_map[4].mmap, long_mmap, "at 4 is long_mmap");

	rz_memory_region_free(mem_region);

	rz_buf_free(short_buf1);
	rz_buf_free(short_buf2);
	rz_buf_free(long_buf);
	rz_memory_free(memory);
	mu_end;
}

bool test_rz_memory_region_reads_fragmented(void) {
	bool ret = false;
	ut8 buffer[64];
	size_t read_len = 0;
	RzMemoryRegion *mem_region = NULL;
	char *dump = NULL;
	RzInterval complete = {
		.addr = 0x112,
		.size = 0x125 - 0x112,
	};

	RzBuffer *short_buf1 = rz_buf_new_with_string("|hidden|");
	mu_assert_notnull(short_buf1, "rz_buf_new_with_string is not null");
	size_t short_buf1_sz = rz_buf_size(short_buf1);
	mu_assert_neq(short_buf1_sz, 0, "short_buf_sz is not zero");

	RzBuffer *short_buf2 = rz_buf_new_with_string("(h!de)");
	mu_assert_notnull(short_buf2, "rz_buf_new_with_string is not null");
	size_t short_buf2_sz = rz_buf_size(short_buf2);
	mu_assert_neq(short_buf2_sz, 0, "short_buf_sz is not zero");

	RzMemory *memory = rz_memory_new();
	mu_assert_notnull(memory, "rz_memory_new is not null");

	// map a short buffer but vsize is bigger than the actual buffer
	RzMemoryMap *short_mmap1 = new_mmap_ro("short1", short_buf1, 0, short_buf1_sz, 0x120, 0x10);
	mu_assert_notnull(short_mmap1, "rz_memory_map_new is not null");

	// map a short buffer but vsize is bigger than the actual buffer
	RzMemoryMap *short_mmap2 = new_mmap_ro("short2", short_buf2, 0, short_buf2_sz, 0x110, short_buf2_sz);
	mu_assert_notnull(short_mmap2, "rz_memory_map_new is not null");

	// Add short1 map to the top
	ret = rz_memory_add_map(memory, short_mmap1, true);
	mu_assert_true(ret, "rz_memory_add_map(short_mmap1, top=true) should not fail");

	// Add short2 map to the top
	ret = rz_memory_add_map(memory, short_mmap2, false);
	mu_assert_true(ret, "rz_memory_add_map(short_mmap2, top=false) should not fail");

	// request mem region1 based on current space
	mem_region = rz_memory_new_region(memory, &complete);
	mu_assert_notnull(mem_region, "when requested the partial1");
	mu_assert_true(rz_memory_region_has_memory_maps(mem_region), "when requested the partial1, it should not be null");

	///////////////////////////////////////
	///////////////////////////////////////
	///////////////////////////////////////

	// cannot read sparse even outside the region
	ret = rz_memory_region_read_memory(mem_region, 0x109, buffer, sizeof(buffer), true, &read_len);
	mu_assert_false(ret, "rz_memory_region_read_memory(0x109, buffer, sizeof(buffer)) starts at unmapped area");

	// cannot read sparse even outside the region
	ret = rz_memory_region_read_memory(mem_region, 0x130, buffer, sizeof(buffer), true, &read_len);
	mu_assert_false(ret, "rz_memory_region_read_memory(0x130, buffer, sizeof(buffer)) starts at unmapped area");

	// read memory from region1
	memset(buffer, 0x2b, sizeof(buffer));
	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region, 0x113, buffer, sizeof(buffer), true, &read_len);
	mu_assert_true(ret, "rz_memory_region_read_memory(0x113, buffer, sizeof(buffer)) starts at mapped area");
	mu_assert_eq(read_len, 18, "read_len should be 18");

	dump = rz_hex_bin2strdup(buffer, sizeof(buffer));
	// clang-format off
	mu_assert_streq(dump, "6465292b2b2b2b2b2b2b2b2b2b7c686964642b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
	                      "output should contain only short_mmap2 + empty + short_mmap1");
	// clang-format on
	free(dump);

	dump = rz_str_ndup((const char *)buffer, read_len);
	mu_assert_streq(dump, "de)++++++++++|hidd",
		"output should contain only short_mmap2 + empty + short_mmap1");
	free(dump);

	rz_memory_region_free(mem_region);

	rz_buf_free(short_buf1);
	rz_buf_free(short_buf2);
	rz_memory_free(memory);
	mu_end;
}

bool test_rz_memory_region_writes_fragmented(void) {
	bool ret = false;
	ut8 buffer[0x100];
	size_t write_len = 0, read_len = 0;
	RzMemoryRegion *mem_region = NULL;
	char *dump = NULL;
	RzInterval complete = {
		.addr = 0,
		.size = UT64_MAX,
	};

	RzBuffer *buf_0x40 = rz_buf_new_empty(0x40);
	mu_assert_notnull(buf_0x40, "rz_buf_new_empty is not null");
	size_t buf_0x40_sz = rz_buf_size(buf_0x40);
	mu_assert_neq(buf_0x40_sz, 0, "buf_0x40_sz is not zero");

	RzBuffer *buf_0x10 = rz_buf_new_empty(0x10);
	mu_assert_notnull(buf_0x10, "rz_buf_new_empty is not null");
	size_t buf_0x10_sz = rz_buf_size(buf_0x10);
	mu_assert_neq(buf_0x10_sz, 0, "buf_0x10_sz is not zero");

	RzBuffer *buf_string = rz_buf_new_with_string("!!!!!!!!!!!!!!!!");
	mu_assert_notnull(buf_string, "rz_buf_new_with_string is not null");
	size_t buf_string_sz = rz_buf_size(buf_string);
	mu_assert_neq(buf_string_sz, 0, "buf_0x10_sz is not zero");

	RzMemory *memory = rz_memory_new();
	mu_assert_notnull(memory, "rz_memory_new is not null");

	// map only 0x20 of the writable buffer to 0x100
	RzMemoryMap *mmap_0x40 = new_mmap_rw("writ0x40", buf_0x40, 0x20, buf_0x40_sz, 0x100, 0x30);
	mu_assert_notnull(mmap_0x40, "rz_memory_map_new is not null");

	// map only 0x10 of the writable buffer to 0x100
	RzMemoryMap *mmap_0x10 = new_mmap_rw("writ0x10", buf_0x10, 0, buf_0x10_sz, 0x170, buf_0x10_sz);
	mu_assert_notnull(mmap_0x10, "rz_memory_map_new is not null");

	// map the read-only buffer to 0x140
	RzMemoryMap *mmap_str = new_mmap_ro("readonly", buf_string, 0, buf_string_sz, 0x140, 0x20);
	mu_assert_notnull(mmap_str, "rz_memory_map_new is not null");

	ret = rz_memory_add_map(memory, mmap_0x40, true);
	mu_assert_true(ret, "rz_memory_add_map(mmap_0x40, top=true) should not fail");
	ret = rz_memory_add_map(memory, mmap_0x10, false);
	mu_assert_true(ret, "rz_memory_add_map(mmap_0x10, top=false) should not fail");
	ret = rz_memory_add_map(memory, mmap_str, true);
	mu_assert_true(ret, "rz_memory_add_map(mmap_str, top=true) should not fail");

	// request mem region1 based on current space
	mem_region = rz_memory_new_region(memory, &complete);
	mu_assert_notnull(mem_region, "the requested region should not be null");
	mu_assert_true(rz_memory_region_has_memory_maps(mem_region), "the requested region must have maps");

	// we will fill the buffer with '6'
	memset(buffer, '6', sizeof(buffer));

	// cannot write when outside the region
	write_len = 0;
	ret = rz_memory_region_write_memory(mem_region, 0x90, buffer, sizeof(buffer), false, &write_len);
	mu_assert_false(ret, "rz_memory_region_write_memory(0x109, buffer, sizeof(buffer)) starts at unmapped area");

	// cannot write sparse even outside the region
	write_len = 0;
	ret = rz_memory_region_write_memory(mem_region, 0x90, buffer, sizeof(buffer), false, &write_len);
	mu_assert_false(ret, "rz_memory_region_write_memory(0x109, buffer, sizeof(buffer)) starts at unmapped area");

	///////////////////////////////////////
	///////////////////////////////////////
	///////////////////////////////////////

	// can write non-sparse
	write_len = 0;
	ret = rz_memory_region_write_memory(mem_region, 0x100, buffer, sizeof(buffer), false, &write_len);
	mu_assert_true(ret, "rz_memory_region_write_memory(0x100, buffer, sizeof(buffer)) starts at mapped area");
	mu_assert_eq(write_len, 0x30, "write_len should be 0x30");

	// fill buffer with '+' to check what we read.
	memset(buffer, '+', sizeof(buffer));

	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region, 0x100, buffer, sizeof(buffer), false, &read_len);
	mu_assert_true(ret, "rz_memory_region_read_memory(0x100, buffer, sizeof(buffer)) starts at mapped area");
	mu_assert_eq(read_len, 0x30, "read_len should be 0x30");

	dump = rz_hex_bin2strdup(buffer, sizeof(buffer));
	// clang-format off
	mu_assert_streq(dump, "3636363636363636363636363636363636363636363636363636363636363636"
	                      "363636363636363636363636363636362b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
	                      "output should contain only changes on mmap_0x40");
	// clang-format on
	free(dump);

	///////////////////////////////////////
	///////////////////////////////////////
	///////////////////////////////////////

	// we will fill the buffer with 0x33
	memset(buffer, 0x33, sizeof(buffer));

	// can write non-sparse
	write_len = 0;
	ret = rz_memory_region_write_memory(mem_region, 0x100, buffer, sizeof(buffer), true, &write_len);
	mu_assert_false(ret, "rz_memory_region_write_memory(0x100, buffer, sizeof(buffer)) starts at mapped area");
	mu_assert_eq(write_len, 0x40, "write_len should be 0x40");

	// fill buffer with '+' to check what we read.
	memset(buffer, 0xff, sizeof(buffer));

	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region, 0x100, buffer, sizeof(buffer), true, &read_len);
	mu_assert_true(ret, "rz_memory_region_read_memory(0x100, buffer, sizeof(buffer)) starts at mapped area");
	mu_assert_eq(read_len, 0x80, "read_len should be 0x80");

	dump = rz_hex_bin2strdup(buffer, sizeof(buffer));
	// clang-format off
	mu_assert_streq(dump, "3333333333333333333333333333333333333333333333333333333333333333"
	                      "33333333333333333333333333333333ffffffffffffffffffffffffffffffff"
	                      "21212121212121212121212121212121ffffffffffffffffffffffffffffffff"
	                      "ffffffffffffffffffffffffffffffff00000000000000000000000000000000"
	                      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	                      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	                      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	                      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	                      "output should contain only changes on mmap_0x40 + mmap_0x10");
	// clang-format on
	free(dump);

	///////////////////////////////////////
	///////////////////////////////////////
	///////////////////////////////////////

	RzMemoryMap *found = rz_memory_get_map(memory, rz_memory_map_get_identifier(mmap_str));
	mu_assert_notnull(found, "rz_memory_get_map is not null");
	mu_assert_ptreq(found, mmap_str, "found is mmap_str");
	rz_memory_map_set_permissions(found, RZ_PERM_RWX);
	mu_assert_eq(rz_memory_map_get_permissions(found), RZ_PERM_RWX, "mmap_str has now RWX permissions");

	// we will fill the buffer with 0xee
	memset(buffer, 0xee, sizeof(buffer));

	// can write non-sparse
	write_len = 0;
	ret = rz_memory_region_write_memory(mem_region, 0x100, buffer, sizeof(buffer), true, &write_len);
	mu_assert_true(ret, "rz_memory_region_write_memory(0x100, buffer, sizeof(buffer)) starts at mapped area");
	mu_assert_eq(write_len, 0x80, "write_len should be 0x80");

	// fill buffer with 0x11 to check what we read.
	memset(buffer, 0x11, sizeof(buffer));

	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region, 0x100, buffer, sizeof(buffer), true, &read_len);
	mu_assert_true(ret, "rz_memory_region_read_memory(0x100, buffer, sizeof(buffer)) starts at mapped area");
	mu_assert_eq(read_len, 0x80, "read_len should be 0x80");

	dump = rz_hex_bin2strdup(buffer, sizeof(buffer));
	// clang-format off
	mu_assert_streq(dump, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	                      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee11111111111111111111111111111111"
	                      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee11111111111111111111111111111111"
	                      "11111111111111111111111111111111eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	                      "1111111111111111111111111111111111111111111111111111111111111111"
	                      "1111111111111111111111111111111111111111111111111111111111111111"
	                      "1111111111111111111111111111111111111111111111111111111111111111"
	                      "1111111111111111111111111111111111111111111111111111111111111111",
	                      "output should contain only changes on mmap_0x40 + mmap_str + mmap_0x10");
	// clang-format on
	free(dump);

	// check that a non-readable region cannot be read.
	memset(buffer, 0xff, sizeof(buffer));
	rz_memory_map_set_permissions(found, RZ_PERM_X);
	mu_assert_eq(rz_memory_map_get_permissions(found), RZ_PERM_X, "mmap_str has now WX permissions");

	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region, 0x100, buffer, sizeof(buffer), true, &read_len);
	mu_assert_false(ret, "rz_memory_region_read_memory(0x100, buffer, sizeof(buffer)) starts at mapped area");
	mu_assert_eq(read_len, 0x40, "read_len should be 0x40");

	dump = rz_hex_bin2strdup(buffer, sizeof(buffer));
	// clang-format off
	mu_assert_streq(dump, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	                      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeffffffffffffffffffffffffffffffff"
	                      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	                      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	                      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	                      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	                      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	                      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	                      "output should contain only changes on mmap_0x40");
	// clang-format on
	free(dump);

	rz_memory_region_free(mem_region);

	rz_buf_free(buf_0x40);
	rz_buf_free(buf_0x10);
	rz_buf_free(buf_string);
	rz_memory_free(memory);
	mu_end;
}

bool test_rz_memory_region_reads_in_different_state(void) {
	bool ret = false;
	ut8 buffer[128];
	size_t read_len = 0;
	RzMemoryRegion *mem_region1 = NULL;
	RzMemoryRegion *mem_region2 = NULL;
	char *dump = NULL;
	RzInterval partial_memspace = {
		.addr = 0x106,
		.size = 0x23,
	};

	RzBuffer *short_buf1 = rz_buf_new_with_string("|hidden|");
	mu_assert_notnull(short_buf1, "rz_buf_new_with_string is not null");
	size_t short_buf1_sz = rz_buf_size(short_buf1);
	mu_assert_neq(short_buf1_sz, 0, "short_buf_sz is not zero");

	RzBuffer *short_buf2 = rz_buf_new_with_string("(h!de)");
	mu_assert_notnull(short_buf2, "rz_buf_new_with_string is not null");
	size_t short_buf2_sz = rz_buf_size(short_buf2);
	mu_assert_neq(short_buf2_sz, 0, "short_buf_sz is not zero");

	RzBuffer *long_buf = rz_buf_new_with_string("this is a longg string| these chars are part of the long string!!!!");
	mu_assert_notnull(long_buf, "rz_buf_new_with_string is not null");
	size_t long_buf_sz = rz_buf_size(long_buf);
	mu_assert_neq(long_buf_sz, 0, "long_buf_sz is not zero");

	RzMemory *memory = rz_memory_new();
	mu_assert_notnull(memory, "rz_memory_new is not null");

	// map a short buffer but vsize is bigger than the actual buffer
	RzMemoryMap *short_mmap1 = new_mmap_ro("short1", short_buf1, 0, short_buf1_sz, 0x120, 0x10);
	mu_assert_notnull(short_mmap1, "rz_memory_map_new is not null");

	// map a short buffer but vsize is bigger than the actual buffer
	RzMemoryMap *short_mmap2 = new_mmap_ro("short2", short_buf2, 0, short_buf2_sz, 0x110, short_buf2_sz);
	mu_assert_notnull(short_mmap2, "rz_memory_map_new is not null");

	// map a short buffer but vsize is bigger than the actual buffer
	RzMemoryMap *long_mmap = new_mmap_ro("longgg", long_buf, 0, long_buf_sz, 0x100, long_buf_sz);
	mu_assert_notnull(long_mmap, "rz_memory_map_new is not null");

	// Add short1 map to the top
	ret = rz_memory_add_map(memory, short_mmap1, true);
	mu_assert_true(ret, "rz_memory_add_map(short_mmap1, top=true) should not fail");

	// Add short2 map to the top
	ret = rz_memory_add_map(memory, short_mmap2, false);
	mu_assert_true(ret, "rz_memory_add_map(short_mmap2, top=false) should not fail");

	// Add long map to the top, which should hide short_map
	ret = rz_memory_add_map(memory, long_mmap, true);
	mu_assert_true(ret, "rz_memory_add_map(long_mmap, top=true) should not fail");

	// request mem region1 based on current space
	mem_region1 = rz_memory_new_region(memory, &partial_memspace);
	mu_assert_notnull(mem_region1, "when requested the partial1");
	mu_assert_true(rz_memory_region_has_memory_maps(mem_region1), "when requested the partial1, it should not be null");

	// move long_mmap to the bottom
	rz_memory_move_map(memory, rz_memory_map_get_identifier(long_mmap), false);

	// request mem region2 based on current space
	partial_memspace.addr = 0x116;
	partial_memspace.size = 0x50;
	mem_region2 = rz_memory_new_region(memory, &partial_memspace);
	mu_assert_notnull(mem_region2, "when requested the partial2");
	mu_assert_true(rz_memory_region_has_memory_maps(mem_region2), "when requested the partial2, it should not be null");

	///////////////////////////////////////
	///////////////////////////////////////
	///////////////////////////////////////

	// read memory from region1
	memset(buffer, 0x2b, sizeof(buffer));
	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region1, 0x109, buffer, sizeof(buffer), true, &read_len);
	mu_assert_true(ret, "rz_memory_region_read_memory(0x109, buffer, sizeof(buffer)) starts at mapped area");
	mu_assert_eq(read_len, 32, "read_len should be 32");

	dump = rz_hex_bin2strdup(buffer, sizeof(buffer));
	// clang-format off
	mu_assert_streq(dump, "206c6f6e676720737472696e677c207468657365206368617273206172652070"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
	                      "output should contain only long_mmap");
	// clang-format on
	free(dump);

	dump = rz_str_ndup((const char *)buffer, read_len);
	mu_assert_streq(dump, " longg string| these chars are p", "output should contain only long_mmap but truncated");
	free(dump);

	///////////////////////////////////////
	///////////////////////////////////////
	///////////////////////////////////////

	// read memory from region2
	memset(buffer, 0x2b, sizeof(buffer));
	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region2, 0x119, buffer, sizeof(buffer), true, &read_len);
	mu_assert_true(ret, "rz_memory_region_read_memory(0x119, buffer, sizeof(buffer)) starts at mapped area but has hole");
	mu_assert_eq(read_len, 42, "read_len should be 42");

	dump = rz_hex_bin2strdup(buffer, sizeof(buffer));
	// clang-format off
	mu_assert_streq(dump, "686573652063687c68696464656e7c2b2b2b2b2b2b2b2b746865206c6f6e6720"
	                      "737472696e67212121212b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
	                      "output should contain short_mmap1 + long_mmap (hex)");
	// clang-format on
	free(dump);

	dump = rz_str_ndup((const char *)buffer, read_len);
	mu_assert_streq(dump, "hese ch|hidden|++++++++the long string!!!!",
		"output should contain only short_mmap1 + long_mmap");
	free(dump);

	rz_memory_region_free(mem_region1);
	rz_memory_region_free(mem_region2);

	rz_buf_free(short_buf1);
	rz_buf_free(short_buf2);
	rz_buf_free(long_buf);
	rz_memory_free(memory);
	mu_end;
}

bool test_rz_memory_overlap_in_the_middle(void) {
	bool ret = false;
	ut8 buffer[128];
	size_t read_len = 0;
	RzMemoryRegion *mem_region = NULL;
	char *dump = NULL;
	mem_check_t check_map[3] = { 0 };
	RzInterval complete_memspace = {
		.addr = 0,
		.size = UT64_MAX,
	};

	RzBuffer *short_buf1 = rz_buf_new_with_string("|hidden|");
	mu_assert_notnull(short_buf1, "rz_buf_new_with_string is not null");
	size_t short_buf1_sz = rz_buf_size(short_buf1);
	mu_assert_neq(short_buf1_sz, 0, "short_buf_sz is not zero");

	RzBuffer *short_buf2 = rz_buf_new_with_string("(h!de)");
	mu_assert_notnull(short_buf2, "rz_buf_new_with_string is not null");
	size_t short_buf2_sz = rz_buf_size(short_buf2);
	mu_assert_neq(short_buf2_sz, 0, "short_buf_sz is not zero");

	RzBuffer *long_buf = rz_buf_new_with_string("this is a longg string| these chars are part of the long string!!!!");
	mu_assert_notnull(long_buf, "rz_buf_new_with_string is not null");
	size_t long_buf_sz = rz_buf_size(long_buf);
	mu_assert_neq(long_buf_sz, 0, "long_buf_sz is not zero");

	RzMemory *memory = rz_memory_new();
	mu_assert_notnull(memory, "rz_memory_new is not null");

	// map a short buffer but vsize is bigger than the actual buffer
	RzMemoryMap *short_mmap1 = new_mmap_ro("short1", short_buf1, 0, short_buf1_sz, 0x120, 0x10);
	mu_assert_notnull(short_mmap1, "rz_memory_map_new is not null");

	// map a short buffer but vsize is bigger than the actual buffer
	RzMemoryMap *short_mmap2 = new_mmap_ro("short2", short_buf2, 0, short_buf2_sz, 0x110, short_buf2_sz);
	mu_assert_notnull(short_mmap2, "rz_memory_map_new is not null");

	// map a short buffer but vsize is bigger than the actual buffer
	RzMemoryMap *long_mmap = new_mmap_ro("longgg", long_buf, 0, long_buf_sz, 0x100, long_buf_sz);
	mu_assert_notnull(long_mmap, "rz_memory_map_new is not null");

	// Add short1 map to the top
	ret = rz_memory_add_map(memory, short_mmap1, true);
	mu_assert_true(ret, "rz_memory_add_map(short_mmap1, top=true) should not fail");

	// Add short2 map to the top
	ret = rz_memory_add_map(memory, short_mmap2, false);
	mu_assert_true(ret, "rz_memory_add_map(short_mmap2, top=false) should not fail");

	// Add long map to the top, which should hide short_map
	ret = rz_memory_add_map(memory, long_mmap, true);
	mu_assert_true(ret, "rz_memory_add_map(long_mmap, top=true) should not fail");

	// get current positions
	rz_memory_iterate_maps(memory, test_check_memory_position, check_map);

	mu_assert_ptreq(check_map[0].mmap, long_mmap, "long_mmap is at the top");
	mu_assert_eq(check_map[0].visibility, RZ_MEMORY_VISIBILITY_COMPLETE, "long_mmap visibility is complete");
	mu_assert_streq(rz_memory_map_get_name(check_map[0].mmap), "longgg", "long_mmap is named longgg");
	mu_assert_eq(rz_memory_map_get_identifier(check_map[0].mmap), 2, "long_mmap id is always 2");

	mu_assert_ptreq(check_map[1].mmap, short_mmap1, "short_mmap1 is at the middle");
	mu_assert_eq(check_map[1].visibility, RZ_MEMORY_VISIBILITY_HIDDEN, "short_mmap1 visibility is hidden");
	mu_assert_streq(rz_memory_map_get_name(check_map[1].mmap), "short1", "short_mmap1 is named short1");
	mu_assert_eq(rz_memory_map_get_identifier(check_map[1].mmap), 0, "short_mmap1 id is always 0");

	mu_assert_ptreq(check_map[2].mmap, short_mmap2, "short_mmap2 is at the bottom");
	mu_assert_eq(check_map[2].visibility, RZ_MEMORY_VISIBILITY_HIDDEN, "short_mmap2 visibility is hidden");
	mu_assert_streq(rz_memory_map_get_name(check_map[2].mmap), "short2", "short_mmap2 is named short2");
	mu_assert_eq(rz_memory_map_get_identifier(check_map[2].mmap), 1, "short_mmap2 id is always 1");

	mem_region = rz_memory_new_region(memory, &complete_memspace);
	mu_assert_notnull(mem_region, "when requested the full memory");
	mu_assert_true(rz_memory_region_has_memory_maps(mem_region), "when requested the full memory, it should not be null");

	// memory is made only by long_mmap
	memset(buffer, 0x2b, sizeof(buffer));
	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region, 0x100, buffer, sizeof(buffer), true, &read_len);
	mu_assert_true(ret, "rz_memory_region_read_memory(0x100, buffer, sizeof(buffer)) starts at mapped area but has hole");
	mu_assert_eq(read_len, 67, "read_len should be 67");

	dump = rz_hex_bin2strdup(buffer, sizeof(buffer));
	// clang-format off
	mu_assert_streq(dump, "746869732069732061206c6f6e676720737472696e677c207468657365206368"
	                      "617273206172652070617274206f6620746865206c6f6e6720737472696e6721"
	                      "2121212b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
	                      "output should contain only long_mmap");
	// clang-format on
	free(dump);

	dump = rz_str_ndup((const char *)buffer, read_len);
	mu_assert_streq(dump, "this is a longg string| these chars are part of the long string!!!!", "output should contain only long_mmap");
	free(dump);

	rz_memory_region_free(mem_region);

	///////////////////////////////////////
	///////////////////////////////////////
	///////////////////////////////////////

	// move long_mmap to the bottom
	rz_memory_move_map(memory, rz_memory_map_get_identifier(long_mmap), false);

	mem_region = rz_memory_new_region(memory, &complete_memspace);
	mu_assert_notnull(mem_region, "when requested the full memory");
	mu_assert_true(rz_memory_region_has_memory_maps(mem_region), "when requested the full memory, it should not be null");

	// memory is fragmented
	memset(buffer, 0x2b, sizeof(buffer));
	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region, 0x100, buffer, sizeof(buffer), true, &read_len);
	mu_assert_true(ret, "rz_memory_region_read_memory(0x100, buffer, sizeof(buffer)) starts at mapped area but has hole");
	mu_assert_eq(read_len, 67, "read_len should be 67");

	dump = rz_hex_bin2strdup(buffer, sizeof(buffer));
	// clang-format off
	mu_assert_streq(dump, "746869732069732061206c6f6e6767202868216465297c207468657365206368"
	                      "7c68696464656e7c2b2b2b2b2b2b2b2b746865206c6f6e6720737472696e6721"
	                      "2121212b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
	                      "output should contain short_mmap1 + short_mmap2 + long_mmap (hex)");
	// clang-format on
	free(dump);

	dump = rz_str_ndup((const char *)buffer, read_len);
	mu_assert_streq(dump, "this is a longg (h!de)| these ch|hidden|++++++++the long string!!!!",
		"output should contain only short_mmap1 + short_mmap2 + long_mmap");
	free(dump);

	rz_memory_region_free(mem_region);

	rz_buf_free(short_buf1);
	rz_buf_free(short_buf2);
	rz_buf_free(long_buf);
	rz_memory_free(memory);
	mu_end;
}

bool test_rz_memory_overlap_same_address(void) {
	bool ret = false;
	ut8 buffer[128];
	ut64 conv_addr = 0;
	size_t read_len = 0;
	RzMemoryRegion *mem_region = NULL;
	char *dump = NULL;
	mem_check_t check_map[2] = { 0 };
	RzInterval complete_memspace = {
		.addr = 0,
		.size = UT64_MAX,
	};

	RzBuffer *short_buf = rz_buf_new_with_string("this is a short string");
	mu_assert_notnull(short_buf, "rz_buf_new_with_string is not null");
	size_t short_buf_sz = rz_buf_size(short_buf);
	mu_assert_neq(short_buf_sz, 0, "short_buf_sz is not zero");

	RzBuffer *long_buf = rz_buf_new_with_string("this is a long string| hidden!! | now this is going to be shown!!!");
	mu_assert_notnull(long_buf, "rz_buf_new_with_string is not null");
	size_t long_buf_sz = rz_buf_size(long_buf);
	mu_assert_neq(long_buf_sz, 0, "long_buf_sz is not zero");

	RzMemory *memory = rz_memory_new();
	mu_assert_notnull(memory, "rz_memory_new is not null");

	// map a short buffer but vsize is bigger than the actual buffer
	RzMemoryMap *short_mmap = new_mmap_ro("short", short_buf, 0, short_buf_sz, 0x100, 0x20);
	mu_assert_notnull(short_mmap, "rz_memory_map_new is not null");

	mu_assert_eq(rz_memory_map_get_permissions(short_mmap), RZ_PERM_R, "short_mmap is read only");
	mu_assert_true(test_rz_memory_map_memory_boundaries(short_mmap, 0x100, 0x20), "short_mmap is vmapped at 0x100 with size 0x20");
	mu_assert_true(test_rz_memory_map_buffer_boundaries(short_mmap, 0, short_buf_sz), "short_mmap is pmapped at 0 with size short_buf_sz");

	// map a short buffer but vsize is bigger than the actual buffer
	RzMemoryMap *long_mmap = new_mmap_ro("long", long_buf, 0, long_buf_sz, 0x100, long_buf_sz);
	mu_assert_notnull(long_mmap, "rz_memory_map_new is not null");

	// Add first short map to the top
	ret = rz_memory_add_map(memory, short_mmap, true);
	mu_assert_true(ret, "rz_memory_add_map(short_mmap, top=true) should not fail");

	// Add long map to the top, which should hide short_map
	ret = rz_memory_add_map(memory, long_mmap, true);
	mu_assert_true(ret, "rz_memory_add_map(long_mmap, top=true) should not fail");

	// get current positions
	memset(check_map, 0, sizeof(check_map));
	rz_memory_iterate_maps(memory, test_check_memory_position, check_map);

	mu_assert_ptreq(check_map[0].mmap, long_mmap, "long_mmap is at the top");
	mu_assert_eq(check_map[0].visibility, RZ_MEMORY_VISIBILITY_COMPLETE, "long_mmap visibility is complete");
	mu_assert_streq(rz_memory_map_get_name(check_map[0].mmap), "long", "long_mmap is named long");
	mu_assert_eq(rz_memory_map_get_identifier(check_map[0].mmap), 1, "long_mmap id is always 1");

	mu_assert_ptreq(check_map[1].mmap, short_mmap, "short_mmap is at the bottom");
	mu_assert_eq(check_map[1].visibility, RZ_MEMORY_VISIBILITY_HIDDEN, "short_mmap visibility is hidden");
	mu_assert_streq(rz_memory_map_get_name(check_map[1].mmap), "short", "short_mmap is named short");
	mu_assert_eq(rz_memory_map_get_identifier(check_map[1].mmap), 0, "short_mmap id is always 0");

	mem_region = rz_memory_new_region(memory, &complete_memspace);
	mu_assert_notnull(mem_region, "when requested the full memory");
	mu_assert_true(rz_memory_region_has_memory_maps(mem_region), "when requested the full memory, it should not be null");

	// bad read
	memset(buffer, 0x2b, sizeof(buffer));
	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region, 0x90, buffer, sizeof(buffer), false, &read_len);
	mu_assert_false(ret, "rz_memory_region_read_memory(0x90, buffer, sizeof(buffer)) starts at unmapped area");
	mu_assert_eq(read_len, 0, "read_len should be zero");

	// ok read (not sparse)
	memset(buffer, 0x2b, sizeof(buffer));
	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region, 0x100, buffer, sizeof(buffer), false, &read_len);
	mu_assert_true(ret, "rz_memory_region_read_memory(0x100, buffer, sizeof(buffer)) starts at mapped area");
	mu_assert_eq(read_len, 66, "read_len should be 66");

	dump = rz_hex_bin2strdup(buffer, sizeof(buffer));
	// clang-format off
	mu_assert_streq(dump, "746869732069732061206c6f6e6720737472696e677c2068696464656e212120"
	                      "7c206e6f77207468697320697320676f696e6720746f2062652073686f776e21"
	                      "21212b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
	                      "output should contain only long_mmap (hex - not sparse)");
	// clang-format on
	free(dump);

	dump = rz_str_ndup((const char *)buffer, read_len);
	mu_assert_streq(dump, "this is a long string| hidden!! | now this is going to be shown!!!",
		"output should contain only long_mmap - not sparse");
	free(dump);

	// ok read (sparse)
	memset(buffer, 0x2b, sizeof(buffer));
	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region, 0x100, buffer, sizeof(buffer), true, &read_len);
	mu_assert_true(ret, "rz_memory_region_read_memory(0x100, buffer, sizeof(buffer), sparse) starts at mapped area");
	mu_assert_eq(read_len, 66, "read_len should be 66");

	dump = rz_hex_bin2strdup(buffer, sizeof(buffer));
	// clang-format off
	mu_assert_streq(dump, "746869732069732061206c6f6e6720737472696e677c2068696464656e212120"
	                      "7c206e6f77207468697320697320676f696e6720746f2062652073686f776e21"
	                      "21212b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
	                      "output should contain only long_mmap (hex - sparse)");
	// clang-format on
	free(dump);

	dump = rz_str_ndup((const char *)buffer, read_len);
	mu_assert_streq(dump, "this is a long string| hidden!! | now this is going to be shown!!!", "output should contain only long_mmap (sparse)");
	free(dump);

	rz_memory_region_free(mem_region);

	///////////////////////////////////////
	///////////////////////////////////////
	///////////////////////////////////////

	// move short_mmap to the top.
	rz_memory_move_map(memory, rz_memory_map_get_identifier(short_mmap), true);

	// get current positions
	memset(check_map, 0, sizeof(check_map));
	rz_memory_iterate_maps(memory, test_check_memory_position, check_map);

	mu_assert_ptreq(check_map[0].mmap, short_mmap, "short_mmap is at the top");
	mu_assert_eq(check_map[0].visibility, RZ_MEMORY_VISIBILITY_COMPLETE, "short_mmap visibility is complete");
	mu_assert_streq(rz_memory_map_get_name(check_map[0].mmap), "short", "short_mmap is named short");
	mu_assert_eq(rz_memory_map_get_identifier(check_map[0].mmap), 0, "short_mmap id is always 0");

	mu_assert_ptreq(check_map[1].mmap, long_mmap, "long_mmap is at the bottom");
	mu_assert_eq(check_map[1].visibility, RZ_MEMORY_VISIBILITY_PARTIAL, "long_mmap visibility is partial");
	mu_assert_streq(rz_memory_map_get_name(check_map[1].mmap), "long", "long_mmap is named long");
	mu_assert_eq(rz_memory_map_get_identifier(check_map[1].mmap), 1, "long_mmap id is always 1");

	mem_region = rz_memory_new_region(memory, &complete_memspace);
	mu_assert_notnull(mem_region, "when requested the full memory");
	mu_assert_true(rz_memory_region_has_memory_maps(mem_region), "when requested the full memory, it should not be null");

	// bad read
	memset(buffer, 0x2b, sizeof(buffer));
	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region, 0x90, buffer, sizeof(buffer), false, &read_len);
	mu_assert_false(ret, "rz_memory_region_read_memory(0x90, buffer, sizeof(buffer)) starts at unmapped area");
	mu_assert_eq(read_len, 0, "read_len should be zero");

	// ok read (not sparse)
	memset(buffer, 0x2b, sizeof(buffer));
	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region, 0x100, buffer, sizeof(buffer), false, &read_len);
	mu_assert_true(ret, "rz_memory_region_read_memory(0x100, buffer, sizeof(buffer)) starts at mapped area but has hole");
	mu_assert_eq(read_len, 22, "read_len should be 22");

	dump = rz_hex_bin2strdup(buffer, sizeof(buffer));
	// clang-format off
	mu_assert_streq(dump, "7468697320697320612073686f727420737472696e672b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
	                      "output should contain only short_mmap (not sparse)");
	// clang-format on
	free(dump);

	dump = rz_str_ndup((const char *)buffer, read_len);
	mu_assert_streq(dump, "this is a short string", "output should contain only short_mmap (not sparse)");
	free(dump);

	// bad read
	memset(buffer, 0x2b, sizeof(buffer));
	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region, 0x90, buffer, sizeof(buffer), false, &read_len);
	mu_assert_false(ret, "rz_memory_region_read_memory(0x90, buffer, sizeof(buffer)) starts at unmapped area");
	mu_assert_eq(read_len, 0, "read_len should be zero");

	// ok read (sparse)
	memset(buffer, 0x2b, sizeof(buffer));
	read_len = 0;
	ret = rz_memory_region_read_memory(mem_region, 0x100, buffer, sizeof(buffer), true, &read_len);
	mu_assert_true(ret, "rz_memory_region_read_memory(0x100, buffer, sizeof(buffer)) starts at mapped area but has hole");
	mu_assert_eq(read_len, 66, "read_len should be 66");

	dump = rz_hex_bin2strdup(buffer, sizeof(buffer));
	// clang-format off
	mu_assert_streq(dump, "7468697320697320612073686f727420737472696e672b2b2b2b2b2b2b2b2b2b"
	                      "7c206e6f77207468697320697320676f696e6720746f2062652073686f776e21"
	                      "21212b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	                      "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
	                      "output should contain only short_mmap + invalid + long_mmap (sparse)");
	// clang-format on
	free(dump);

	dump = rz_str_ndup((const char *)buffer, sizeof(buffer));
	// clang-format off
	mu_assert_streq(dump, "this is a short string++++++++++| now this is going to be shown!!!"
							"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++",
							"output should contain only short_mmap + invalid + long_mmap (sparse)");
	// clang-format on
	free(dump);

	// convert VALID memory mapped to buffer offset
	conv_addr = 0;
	ret = rz_memory_map_convert_memory_to_buffer(long_mmap, 0x110, &conv_addr);
	mu_assert_true(ret, "rz_memory_map_convert_memory_to_buffer(long_mmap, 0x110, &conv_addr) can convert address");
	mu_assert_eq(conv_addr, 0x10, "conv_addr from mem to buf must be 0x10");

	// convert INVALID memory mapped to buffer offset
	conv_addr = 0;
	ret = rz_memory_map_convert_memory_to_buffer(long_mmap, 0x150, &conv_addr);
	mu_assert_false(ret, "rz_memory_map_convert_memory_to_buffer(long_mmap, 0x150, &conv_addr) can convert address");
	mu_assert_eq(conv_addr, 0, "conv_addr from mem to buf must be 0");

	// convert VALID buffer offset to memory mapped
	conv_addr = 0;
	ret = rz_memory_map_convert_buffer_to_memory(long_mmap, 0x10, &conv_addr);
	mu_assert_true(ret, "rz_memory_map_convert_buffer_to_memory(long_mmap, 0x10, &conv_addr) can convert address");
	mu_assert_eq(conv_addr, 0x110, "conv_addr from buf to mem must be 0x110");

	// convert INVALID buffer offset to memory mapped
	conv_addr = 0;
	ret = rz_memory_map_convert_buffer_to_memory(long_mmap, 0x50, &conv_addr);
	mu_assert_false(ret, "rz_memory_map_convert_buffer_to_memory(long_mmap, 0x50, &conv_addr) can convert address");
	mu_assert_eq(conv_addr, 0, "conv_addr from buf to mem must be 0");

	rz_memory_region_free(mem_region);

	///////////////////////////////////////
	///////////////////////////////////////
	///////////////////////////////////////

	// cannot remove a map when the id is invalid
	ret = rz_memory_remove_map(memory, 1337);
	mu_assert_false(ret, "rz_memory_remove_map(1337) is invalid id");

	// can remove a map when the id is valid
	ret = rz_memory_remove_map(memory, rz_memory_map_get_identifier(long_mmap));
	mu_assert_true(ret, "rz_memory_remove_map(long_mmap) is valid");

	// get current positions
	memset(check_map, 0, sizeof(check_map));
	rz_memory_iterate_maps(memory, test_check_memory_position, check_map);

	mu_assert_ptreq(check_map[0].mmap, short_mmap, "short_mmap is at the top");
	mu_assert_null(check_map[1].mmap, "second map has been removed");

	rz_buf_free(short_buf);
	rz_buf_free(long_buf);
	rz_memory_free(memory);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_memory_map_new);
	mu_run_test(test_rz_memory_free_functions);
	mu_run_test(test_rz_memory_overlap_same_address);
	mu_run_test(test_rz_memory_overlap_in_the_middle);
	mu_run_test(test_rz_memory_region_reads_in_different_state);
	mu_run_test(test_rz_memory_region_iterate);
	mu_run_test(test_rz_memory_region_reads_fragmented);
	mu_run_test(test_rz_memory_region_writes_fragmented);

	return tests_passed != tests_run;
}

mu_main(all_tests)
