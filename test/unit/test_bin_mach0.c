// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_endian.h>
#include "../../librz/bin/format/mach0/mach0_defines.h"
#include "../../librz/bin/format/mach0/dyldcache.h"
#include "minunit.h"

/*
 * In real dyld, the dyld_chained_ptr_* structs are parsed by simply
 * reinterpreting a 64bit value as the respective bitfield struct. This of
 * course only works on little endian hosts, but we want to be
 * endian-independent, so we define or own readers.
 * The tests below compare the output of our readers against the dyld-style
 * reinterpretation to make sure we are parsing correctly. For adding tests for
 * a new struct, simply add a TEST_READ_DEF(...) and
 * mu_run_test(test_dyld_chained_..._read); line.
 */

#if !RZ_SYS_ENDIAN

#define SAMPLES 10000

static ut64 rand_ut64() {
	ut64 r = 0;
	for (int i = 0; i < 8; i++) {
		r = (rand() % 0xff) | (r << 8);
	}
	return r;
}

static void memset_rand(ut8 *dst, size_t size) {
	for (size_t i = 0; i < size; i++) {
		dst[i] = (ut8)rand();
	}
}

#define TEST_READ_DEF(name, size) \
	bool test_##name##_read() { \
		RZ_STATIC_ASSERT(sizeof(struct name) == sizeof(ut##size)); \
		for (int i = 0; i < SAMPLES; i++) { \
			ut##size raw_val = rand_ut64(); /* this is the value we want to parse */ \
\
			/* Parse with our endian-independent function */ \
			struct name s; \
			/* some compilers incorrectly optimized the following without volatile */ \
			volatile ut##size *s_direct = (ut##size *)&s; \
			*s_direct = rand_ut64(); /* init with garbage */ \
			name##_read(&s, raw_val); \
\
			/* Compare our parsed value against a direct copy into the struct. */ \
			/* This only works on little endian hosts! */ \
			if (*s_direct != raw_val) { /* manual check to avoid rz_strf below */ \
				char message[128]; \
				snprintf(message, sizeof(message), #name "_read(0x%" PFMT64x ")", (ut64)raw_val); \
				mu_assert_eq(*s_direct, raw_val, message); \
			} \
		} \
		mu_end; \
	}

TEST_READ_DEF(dyld_chained_ptr_arm64e_rebase, 64)
TEST_READ_DEF(dyld_chained_ptr_arm64e_bind, 64)
TEST_READ_DEF(dyld_chained_ptr_arm64e_auth_rebase, 64)
TEST_READ_DEF(dyld_chained_ptr_arm64e_auth_bind, 64)
TEST_READ_DEF(dyld_chained_ptr_64_rebase, 64)
TEST_READ_DEF(dyld_chained_ptr_64_bind, 64)
TEST_READ_DEF(dyld_chained_ptr_arm64e_cache_rebase, 64)
TEST_READ_DEF(dyld_chained_ptr_arm64e_cache_auth_rebase, 64)
TEST_READ_DEF(dyld_chained_ptr_arm64e_bind24, 64)
TEST_READ_DEF(dyld_chained_ptr_arm64e_auth_bind24, 64)
TEST_READ_DEF(dyld_chained_ptr_32_rebase, 32)
TEST_READ_DEF(dyld_chained_ptr_32_bind, 32)

#define TEST_READ_BUF_DEF(name) \
	bool test_##name##_read() { \
		for (int i = 0; i < SAMPLES; i++) { \
			ut8 raw_val[sizeof(struct name)]; /* this is the value we want to parse */ \
			memset_rand(raw_val, sizeof(raw_val)); \
\
			/* Parse with our endian-independent function */ \
			struct name s; \
			memset_rand((ut8 *)&s, sizeof(s)); /* init with garbage */ \
			name##_read(&s, raw_val); \
\
			/* Compare our parsed value against a direct copy of the struct. */ \
			/* This only works on little endian hosts! */ \
			mu_assert_memeq((const ut8 *)&s, raw_val, sizeof(s), "read mismatch"); \
		} \
		mu_end; \
	}

TEST_READ_BUF_DEF(dyld_chained_import);
TEST_READ_BUF_DEF(dyld_chained_import_addend);
TEST_READ_BUF_DEF(dyld_chained_import_addend64);

#endif

static void init_synthetic_dyldcache_header(ut8 *raw, size_t total_size, ut64 slide_off, ut64 slide_size) {
	memset(raw, 0, total_size);
	memcpy(raw, "dyld_v1   arm64", 16);
	rz_write_le32(raw + 0x10, 0x100); // mappingOffset
	rz_write_le32(raw + 0x14, 2); // mappingCount
	rz_write_le32(raw + 0x18, 0x160); // imagesOffset
	rz_write_le32(raw + 0x1c, 1); // imagesCount
	rz_write_le64(raw + 0x20, 0x180000000ULL); // dyldBaseAddress
	rz_write_le64(raw + 0x28, (ut64)total_size); // codeSignatureOffset (stops multi-hdr loop)
	rz_write_le64(raw + 0x30, 0); // codeSignatureSize
	rz_write_le64(raw + 0x38, slide_off); // slideInfoOffset
	rz_write_le64(raw + 0x40, slide_size); // slideInfoSize

	// map[0]: header/text [0x0, 0x1000)
	rz_write_le64(raw + 0x100, 0x180000000ULL);
	rz_write_le64(raw + 0x108, 0x1000);
	rz_write_le64(raw + 0x110, 0);
	rz_write_le32(raw + 0x118, 5);
	rz_write_le32(raw + 0x11c, 5);

	// map[1]: data [0x1000, 0x2000)
	rz_write_le64(raw + 0x120, 0x180001000ULL);
	rz_write_le64(raw + 0x128, 0x1000);
	rz_write_le64(raw + 0x130, 0x1000);
	rz_write_le32(raw + 0x138, 3);
	rz_write_le32(raw + 0x13c, 3);

	// img[0] at 0x160 pointing to minimal MH_MAGIC_64 header at pa 0x400
	rz_write_le64(raw + 0x160, 0x180000400ULL); // address
	rz_write_le32(raw + 0x178, 0x180); // pathFileOffset
	memcpy(raw + 0x180, "/usr/lib/libtest.dylib", sizeof("/usr/lib/libtest.dylib"));
	rz_write_le32(raw + 0x400, MH_MAGIC_64);
}

static void write_slide_v1(ut8 *slide, ut32 toc_off, ut32 toc_cnt, ut32 ent_off, ut32 ent_cnt, ut32 ent_sz) {
	rz_write_le32(slide + 0, 1); // version
	rz_write_le32(slide + 4, toc_off);
	rz_write_le32(slide + 8, toc_cnt);
	rz_write_le32(slide + 12, ent_off);
	rz_write_le32(slide + 16, ent_cnt);
	rz_write_le32(slide + 20, ent_sz);
}

static void write_slide_v2(ut8 *slide, ut32 page_sz, ut32 ps_off, ut32 ps_cnt, ut32 pe_off, ut32 pe_cnt) {
	rz_write_le32(slide + 0, 2); // version
	rz_write_le32(slide + 4, page_sz);
	rz_write_le32(slide + 8, ps_off);
	rz_write_le32(slide + 12, ps_cnt);
	rz_write_le32(slide + 16, pe_off);
	rz_write_le32(slide + 20, pe_cnt);
	rz_write_le64(slide + 24, 0x00ffff0000000000ULL); // delta_mask
	rz_write_le64(slide + 32, 0x180000000ULL); // value_add
}

static void write_slide_v3(ut8 *slide, ut32 page_sz, ut32 ps_cnt, ut16 first_start) {
	rz_write_le32(slide + 0, 3); // version
	rz_write_le32(slide + 4, page_sz);
	rz_write_le32(slide + 8, ps_cnt);
	rz_write_le32(slide + 12, 0); // padding
	rz_write_le64(slide + 16, 0x180000000ULL); // auth_value_add
	rz_write_le16(slide + 24, first_start);
}

bool test_dyldcache_slide_info_bounds(void) {
	ut8 raw[0x1010];
	const ut64 slide_off = 0x200;
	const ut64 slide_sz = 0x100;

	// v2: overflowing page_starts_count * 2 rejected cleanly
	init_synthetic_dyldcache_header(raw, sizeof(raw), slide_off, slide_sz);
	write_slide_v2(raw + slide_off, 4096, 40, 0x80000001U, 40, 0);
	RzBuffer *buf = rz_buf_new_with_bytes(raw, sizeof(raw));
	mu_assert_notnull(buf, "v2 bad page_starts buf");
	RzDyldCache *cache = rz_dyldcache_new_buf(buf);
	mu_assert_notnull(cache, "v2 bad page_starts cache");
	mu_assert_notnull(cache->rebase_infos, "rebase_infos container");
	mu_assert_null(cache->rebase_infos->entries[0].info, "v2 overflowing page_starts rejected");
	rz_dyldcache_free(cache);
	rz_buf_free(buf);

	// v2: overflowing page_extras_count * 2 rejected cleanly
	init_synthetic_dyldcache_header(raw, sizeof(raw), slide_off, slide_sz);
	write_slide_v2(raw + slide_off, 4096, 40, 1, 42, 0x80000001U);
	buf = rz_buf_new_with_bytes(raw, sizeof(raw));
	mu_assert_notnull(buf, "v2 bad page_extras buf");
	cache = rz_dyldcache_new_buf(buf);
	mu_assert_notnull(cache, "v2 bad page_extras cache");
	mu_assert_null(cache->rebase_infos->entries[0].info, "v2 overflowing page_extras rejected");
	rz_dyldcache_free(cache);
	rz_buf_free(buf);

	// v2: valid with non-empty page_extras
	init_synthetic_dyldcache_header(raw, sizeof(raw), slide_off, slide_sz);
	write_slide_v2(raw + slide_off, 4096, 40, 1, 42, 1);
	rz_write_le16(raw + slide_off + 40, DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE);
	rz_write_le16(raw + slide_off + 42, DYLD_CACHE_SLIDE_PAGE_ATTR_END);
	buf = rz_buf_new_with_bytes(raw, sizeof(raw));
	mu_assert_notnull(buf, "v2 valid extras buf");
	cache = rz_dyldcache_new_buf(buf);
	mu_assert_notnull(cache, "v2 valid extras cache");
	mu_assert_notnull(cache->rebase_infos->entries[0].info, "v2 valid extras info");
	mu_assert_eq(((RzDyldRebaseInfo2 *)cache->rebase_infos->entries[0].info)->page_extras_count, 1, "v2 page_extras_count");
	rz_dyldcache_free(cache);
	rz_buf_free(buf);

	// v1: overflowing toc_count * 2 rejected cleanly
	init_synthetic_dyldcache_header(raw, sizeof(raw), slide_off, slide_sz);
	write_slide_v1(raw + slide_off, 24, 0x80000001U, 24, 0, 128);
	buf = rz_buf_new_with_bytes(raw, sizeof(raw));
	mu_assert_notnull(buf, "v1 bad toc buf");
	cache = rz_dyldcache_new_buf(buf);
	mu_assert_notnull(cache, "v1 bad toc cache");
	mu_assert_null(cache->rebase_infos->entries[0].info, "v1 overflowing toc_count rejected");
	rz_dyldcache_free(cache);
	rz_buf_free(buf);

	// v1: overflowing entries_count * entries_size rejected cleanly
	init_synthetic_dyldcache_header(raw, sizeof(raw), slide_off, slide_sz);
	write_slide_v1(raw + slide_off, 24, 1, 26, 0x02000001U, 128);
	buf = rz_buf_new_with_bytes(raw, sizeof(raw));
	mu_assert_notnull(buf, "v1 bad entries buf");
	cache = rz_dyldcache_new_buf(buf);
	mu_assert_notnull(cache, "v1 bad entries cache");
	mu_assert_null(cache->rebase_infos->entries[0].info, "v1 overflowing entries_count rejected");
	rz_dyldcache_free(cache);
	rz_buf_free(buf);

	mu_end;
}

bool test_dyldcache_rebase_v1_v2_v3_bounds(void) {
	ut8 raw[0x2000];
	ut8 out[0x1000];
	const ut64 slide_off = 0x200;
	const ut64 slide_sz = 0x100;

	// v1: valid full-page rebase (also covers rem == 0 in buf_read) + OOB toc_entry
	init_synthetic_dyldcache_header(raw, sizeof(raw), slide_off, slide_sz);
	write_slide_v1(raw + slide_off, 24, 1, 26, 1, 128);
	rz_write_le16(raw + slide_off + 24, 0); // toc[0] = 0
	raw[slide_off + 26] = 0x01; // bit 0 set: rebase offset 0
	rz_write_le64(raw + 0x1000, 0x180000000ULL);
	RzBuffer *buf = rz_buf_new_with_bytes(raw, sizeof(raw));
	mu_assert_notnull(buf, "v1 full buf");
	RzDyldCache *cache = rz_dyldcache_new_buf(buf);
	mu_assert_notnull(cache, "v1 full cache");
	RzDyldRebaseInfo1 *ri1 = (RzDyldRebaseInfo1 *)cache->rebase_infos->entries[0].info;
	mu_assert_notnull(ri1, "v1 rebase info");
	mu_assert_eq(ri1->entries_count, 1, "v1 entries_count stored");
	ri1->slide = 0x2000;
	RzBuffer *rbuf = rz_dyldcache_new_rebasing_buf(cache);
	mu_assert_notnull(rbuf, "v1 rebasing buf");
	mu_assert_eq(rz_buf_read_at(rbuf, 0x1000, out, 0x1000), 0x1000, "v1 full page read");
	mu_assert_eq(rz_read_le64(out), 0x180002000ULL, "v1 rebased pointer");

	// Out-of-range toc_entry must break cleanly without OOB read
	ri1->toc[0] = 5;
	mu_assert_eq(rz_buf_read_at(rbuf, 0x1000, out, 8), 8, "v1 oob toc read");
	mu_assert_eq(rz_read_le64(out), 0x180000000ULL, "v1 oob toc leaves data unchanged");
	rz_buf_free(rbuf);
	rz_dyldcache_free(cache);
	rz_buf_free(buf);

	// v1: truncated page (12B) hitting count - in_buf < 8 at offset 8
	init_synthetic_dyldcache_header(raw, 0x100c, slide_off, slide_sz);
	write_slide_v1(raw + slide_off, 24, 1, 26, 1, 128);
	rz_write_le16(raw + slide_off + 24, 0);
	raw[slide_off + 26] = 0x05; // bits 0 and 2 set (offsets 0 and 8)
	rz_write_le64(raw + 0x1000, 0x180000000ULL);
	rz_write_le32(raw + 0x1008, 0x11223344U);
	buf = rz_buf_new_with_bytes(raw, 0x100c);
	mu_assert_notnull(buf, "v1 12B buf");
	cache = rz_dyldcache_new_buf(buf);
	mu_assert_notnull(cache, "v1 12B cache");
	cache->rebase_infos->entries[0].info->slide = 0x1000;
	rbuf = rz_dyldcache_new_rebasing_buf(cache);
	mu_assert_notnull(rbuf, "v1 12B rebasing buf");
	mu_assert_eq(rz_buf_read_at(rbuf, 0x1000, out, 12), 12, "v1 12B read");
	mu_assert_eq(rz_read_le64(out), 0x180001000ULL, "v1 first qword rebased");
	mu_assert_eq(rz_read_le32(out + 8), 0x11223344U, "v1 trailing 4B untouched");
	rz_buf_free(rbuf);
	rz_dyldcache_free(cache);
	rz_buf_free(buf);

	// v1: truncated page (< 8B) hitting count < 8 guard
	init_synthetic_dyldcache_header(raw, 0x1004, slide_off, slide_sz);
	write_slide_v1(raw + slide_off, 24, 1, 26, 1, 128);
	rz_write_le16(raw + slide_off + 24, 0);
	raw[slide_off + 26] = 0x01;
	buf = rz_buf_new_with_bytes(raw, 0x1004);
	mu_assert_notnull(buf, "v1 4B buf");
	cache = rz_dyldcache_new_buf(buf);
	mu_assert_notnull(cache, "v1 4B cache");
	rbuf = rz_dyldcache_new_rebasing_buf(cache);
	mu_assert_notnull(rbuf, "v1 4B rebasing buf");
	mu_assert_eq(rz_buf_read_at(rbuf, 0x1000, out, 4), 4, "v1 4B short page read");
	rz_buf_free(rbuf);
	rz_dyldcache_free(cache);
	rz_buf_free(buf);

	// v1: empty toc (!rebase_info->toc) and empty entries (!rebase_info->entries) + short read fallback
	init_synthetic_dyldcache_header(raw, 0x1010, slide_off, slide_sz);
	write_slide_v1(raw + slide_off, 24, 0, 26, 1, 128);
	buf = rz_buf_new_with_bytes(raw, 0x1010);
	mu_assert_notnull(buf, "v1 null toc buf");
	cache = rz_dyldcache_new_buf(buf);
	mu_assert_notnull(cache, "v1 null toc cache");
	rbuf = rz_dyldcache_new_rebasing_buf(cache);
	mu_assert_notnull(rbuf, "v1 null toc rebasing buf");
	mu_assert_eq(rz_buf_read_at(rbuf, 0x1000, out, 8), 8, "v1 null toc read");
	// Read past EOF so internal_result < page_offset + len triggers fallback path
	mu_assert_eq(rz_buf_read_at(rbuf, 0x1008, out, 32), 8, "buf_read short fallback");
	rz_buf_free(rbuf);
	rz_dyldcache_free(cache);
	rz_buf_free(buf);

	init_synthetic_dyldcache_header(raw, 0x1010, slide_off, slide_sz);
	write_slide_v1(raw + slide_off, 24, 1, 26, 0, 128);
	buf = rz_buf_new_with_bytes(raw, 0x1010);
	mu_assert_notnull(buf, "v1 null entries buf");
	cache = rz_dyldcache_new_buf(buf);
	mu_assert_notnull(cache, "v1 null entries cache");
	rbuf = rz_dyldcache_new_rebasing_buf(cache);
	mu_assert_notnull(rbuf, "v1 null entries rebasing buf");
	mu_assert_eq(rz_buf_read_at(rbuf, 0x1000, out, 8), 8, "v1 null entries read");
	rz_buf_free(rbuf);
	rz_dyldcache_free(cache);
	rz_buf_free(buf);

	// v2: short page (< 8B) and truncated pointer (position > count - 8)
	init_synthetic_dyldcache_header(raw, 0x1004, slide_off, slide_sz);
	write_slide_v2(raw + slide_off, 4096, 40, 1, 42, 0);
	rz_write_le16(raw + slide_off + 40, 0);
	buf = rz_buf_new_with_bytes(raw, 0x1004);
	mu_assert_notnull(buf, "v2 4B buf");
	cache = rz_dyldcache_new_buf(buf);
	mu_assert_notnull(cache, "v2 4B cache");
	rbuf = rz_dyldcache_new_rebasing_buf(cache);
	mu_assert_notnull(rbuf, "v2 4B rebasing buf");
	mu_assert_eq(rz_buf_read_at(rbuf, 0x1000, out, 4), 4, "v2 4B short page read");
	rz_buf_free(rbuf);
	rz_dyldcache_free(cache);
	rz_buf_free(buf);

	init_synthetic_dyldcache_header(raw, 0x100c, slide_off, slide_sz);
	write_slide_v2(raw + slide_off, 4096, 40, 1, 42, 0);
	rz_write_le16(raw + slide_off + 40, 2); // first_rebase_off = 2 * 4 = 8 > 12 - 8
	buf = rz_buf_new_with_bytes(raw, 0x100c);
	mu_assert_notnull(buf, "v2 12B buf");
	cache = rz_dyldcache_new_buf(buf);
	mu_assert_notnull(cache, "v2 12B cache");
	rbuf = rz_dyldcache_new_rebasing_buf(cache);
	mu_assert_notnull(rbuf, "v2 12B rebasing buf");
	mu_assert_eq(rz_buf_read_at(rbuf, 0x1000, out, 12), 12, "v2 truncated pointer break");
	rz_buf_free(rbuf);
	rz_dyldcache_free(cache);
	rz_buf_free(buf);

	// v3: short page (< 8B) and truncated pointer (position > count - 8)
	init_synthetic_dyldcache_header(raw, 0x1004, slide_off, slide_sz);
	write_slide_v3(raw + slide_off, 4096, 1, 0);
	buf = rz_buf_new_with_bytes(raw, 0x1004);
	mu_assert_notnull(buf, "v3 4B buf");
	cache = rz_dyldcache_new_buf(buf);
	mu_assert_notnull(cache, "v3 4B cache");
	rbuf = rz_dyldcache_new_rebasing_buf(cache);
	mu_assert_notnull(rbuf, "v3 4B rebasing buf");
	mu_assert_eq(rz_buf_read_at(rbuf, 0x1000, out, 4), 4, "v3 4B short page read");
	rz_buf_free(rbuf);
	rz_dyldcache_free(cache);
	rz_buf_free(buf);

	init_synthetic_dyldcache_header(raw, 0x100c, slide_off, slide_sz);
	write_slide_v3(raw + slide_off, 4096, 1, 8); // first_rebase_off = 8 > 12 - 8
	buf = rz_buf_new_with_bytes(raw, 0x100c);
	mu_assert_notnull(buf, "v3 12B buf");
	cache = rz_dyldcache_new_buf(buf);
	mu_assert_notnull(cache, "v3 12B cache");
	rbuf = rz_dyldcache_new_rebasing_buf(cache);
	mu_assert_notnull(rbuf, "v3 12B rebasing buf");
	mu_assert_eq(rz_buf_read_at(rbuf, 0x1000, out, 12), 12, "v3 truncated pointer break");
	rz_buf_free(rbuf);
	rz_dyldcache_free(cache);
	rz_buf_free(buf);

	mu_end;
}

bool all_tests() {
	srand(time(0));
#if !RZ_SYS_ENDIAN
	mu_run_test(test_dyld_chained_ptr_arm64e_rebase_read);
	mu_run_test(test_dyld_chained_ptr_arm64e_bind_read);
	mu_run_test(test_dyld_chained_ptr_arm64e_auth_rebase_read);
	mu_run_test(test_dyld_chained_ptr_arm64e_auth_bind_read);
	mu_run_test(test_dyld_chained_ptr_64_rebase_read);
	mu_run_test(test_dyld_chained_ptr_64_bind_read);
	mu_run_test(test_dyld_chained_ptr_arm64e_cache_rebase_read);
	mu_run_test(test_dyld_chained_ptr_arm64e_cache_auth_rebase_read);
	mu_run_test(test_dyld_chained_ptr_arm64e_bind24_read);
	mu_run_test(test_dyld_chained_ptr_arm64e_auth_bind24_read);
	mu_run_test(test_dyld_chained_ptr_32_rebase_read);
	mu_run_test(test_dyld_chained_ptr_32_bind_read);
	mu_run_test(test_dyld_chained_import_read);
	mu_run_test(test_dyld_chained_import_addend_read);
	mu_run_test(test_dyld_chained_import_addend64_read);
#endif
	mu_run_test(test_dyldcache_slide_info_bounds);
	mu_run_test(test_dyldcache_rebase_v1_v2_v3_bounds);
	return tests_passed != tests_run;
}

mu_main(all_tests)
