// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "../../librz/bin/format/mach0/mach0_defines.h"
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
	return tests_passed != tests_run;
}

mu_main(all_tests)
