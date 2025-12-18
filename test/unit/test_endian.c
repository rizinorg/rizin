// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \internal
 * \file
 * \brief Test the functions in rz_endian.h
 */

#include <rz_util.h>
#include <rz_io.h>
#include <stdlib.h>
#include "minunit.h"

static const char data_pool[] =
	"\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8"
	"\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8";

#undef INPUT
#undef OFFSET
#undef ENDIANNESS
#undef SIZE
#undef RESULT
#undef BIG_ENDIAN
#undef LITTLE_ENDIAN
#undef MIDDLE_ENDIAN
#undef BE_TEST
#undef LE_TEST
#undef ME_TEST
#undef BE24_TEST
#undef LE24_TEST
#undef IS_be_SIZE
#undef IS_le_SIZE
#undef IS_me_SIZE
#undef IS_ble_SIZE
#undef MAKE_INTEGRAL_READ_TEST_AUX
#undef MAKE_INTEGRAL_READ_AT_TEST
#define INPUT(i)      (rz_read_table[i].input)
#define OFFSET(i)     (rz_read_table[i].offset)
#define ENDIANNESS(i) (rz_read_table[i].endianness)
#define SIZE(i)       (rz_read_table[i].size)
#define RESULT(i)     (rz_read_table[i].result)
#define BIG_ENDIAN    1
#define LITTLE_ENDIAN 2
#define MIDDLE_ENDIAN 3

/**
 * \def BE_TEST Create entries in \c rz_read_table for big-endian unit tests.
 */
#define BE_TEST(input, offset, size) (&data_pool[input]), offset, BIG_ENDIAN, size, .result.u##size
/**
 * \def LE_TEST Create entries in \c rz_read_table for little-endian unit tests.
 */
#define LE_TEST(input, offset, size) (&data_pool[input]), offset, LITTLE_ENDIAN, size, .result.u##size
/**
 * \def ME_TEST Create entries in \c rz_read_table for middle-endian unit tests.
 */
#define ME_TEST(input, offset, size) (&data_pool[input]), offset, MIDDLE_ENDIAN, size, .result.u##size
/**
 * \def BE24_TEST Create entries in \c rz_read_table for 24-bit big-endian unit tests.
 */
#define BE24_TEST(input, offset) (&data_pool[input]), offset, BIG_ENDIAN, 24, .result.u##32
/**
 * \def LE24_TEST Create entries in \c rz_read_table for 24-bit little-endian unit tests.
 */
#define LE24_TEST(input, offset) (&data_pool[input]), offset, LITTLE_ENDIAN, 24, .result.u##32

/**
 * \def IS_be_SIZE Check if entry is big-endian and of given size.
 */
#define IS_be_SIZE(i, N) (ENDIANNESS(i) == BIG_ENDIAN && SIZE(i) == N)
/**
 * \def IS_le_SIZE Check if entry is little-endian and of given size.
 */
#define IS_le_SIZE(i, N) (ENDIANNESS(i) == LITTLE_ENDIAN && SIZE(i) == N)
/**
 * \def IS_me_SIZE Check if entry is middle-endian and of given size.
 */
#define IS_me_SIZE(i, N) (ENDIANNESS(i) == MIDDLE_ENDIAN && SIZE(i) == N)
/**
 * \def IS_ble_SIZE Check if entry is big- or little-endian and of given size.
 */
#define IS_ble_SIZE(i, N) ((ENDIANNESS(i) == BIG_ENDIAN || ENDIANNESS(i) == LITTLE_ENDIAN) && SIZE(i) == N)

static const struct {
	const char *input; ///< source parameter of read function
	size_t offset; ///< offset parameter of read functions
	int endianness; ///< 1 = be, 2 = le, 3 = me
	int size; ///< 32 for ut32, st32, or float, etc
	union {
		ut8 u8;
		ut16 u16;
		ut32 u32;
		ut64 u64;
		ut128 u128;
		float f;
		double d;
	} result;
} rz_read_table[] = {
	/* rz_read_be128, rz_read_at_be128 */
	{ BE_TEST(0, 0, 128) = { .High = 0xA1A2A3A4A5A6A7A8, .Low = 0xB1B2B3B4B5B6B7B8 } },
	{ BE_TEST(0, 16, 128) = { .High = 0xC1C2C3C4C5C6C7C8, .Low = 0xD1D2D3D4D5D6D7D8 } },
	{ BE_TEST(8, 0, 128) = { .High = 0xB1B2B3B4B5B6B7B8, .Low = 0xC1C2C3C4C5C6C7C8 } },
	{ BE_TEST(8, 8, 128) = { .High = 0xC1C2C3C4C5C6C7C8, .Low = 0xD1D2D3D4D5D6D7D8 } },
	/* rz_reat_be64, rz_reat_at_be64 */
	{ BE_TEST(0, 0, 64) = 0xA1A2A3A4A5A6A7A8 },
	{ BE_TEST(0, 8, 64) = 0xB1B2B3B4B5B6B7B8 },
	{ BE_TEST(8, 0, 64) = 0xB1B2B3B4B5B6B7B8 },
	{ BE_TEST(8, 8, 64) = 0xC1C2C3C4C5C6C7C8 },
	/* rz_reat_be32, rz_reat_at_be32 */
	{ BE_TEST(0, 0, 32) = 0xA1A2A3A4 },
	{ BE_TEST(0, 8, 32) = 0xB1B2B3B4 },
	{ BE_TEST(8, 0, 32) = 0xB1B2B3B4 },
	{ BE_TEST(8, 8, 32) = 0xC1C2C3C4 },
	/* rz_reat_be24, rz_reat_at_be24 */
	{ BE24_TEST(0, 0) = 0xA1A2A3 },
	{ BE24_TEST(0, 8) = 0xB1B2B3 },
	{ BE24_TEST(8, 0) = 0xB1B2B3 },
	{ BE24_TEST(8, 8) = 0xC1C2C3 },
	/* rz_reat_be16, rz_reat_at_be16 */
	{ BE_TEST(0, 0, 16) = 0xA1A2 },
	{ BE_TEST(0, 8, 16) = 0xB1B2 },
	{ BE_TEST(8, 0, 16) = 0xB1B2 },
	{ BE_TEST(8, 8, 16) = 0xC1C2 },
	/* rz_read_le128, rz_read_at_le128 */
	{ LE_TEST(0, 0, 128) = { .High = 0xB8B7B6B5B4B3B2B1, .Low = 0xA8A7A6A5A4A3A2A1 } },
	{ LE_TEST(0, 16, 128) = { .High = 0xD8D7D6D5D4D3D2D1, .Low = 0xC8C7C6C5C4C3C2C1 } },
	{ LE_TEST(8, 0, 128) = { .High = 0xC8C7C6C5C4C3C2C1, .Low = 0xB8B7B6B5B4B3B2B1 } },
	{ LE_TEST(8, 8, 128) = { .High = 0xD8D7D6D5D4D3D2D1, .Low = 0xC8C7C6C5C4C3C2C1 } },
	/* rz_reat_le64, rz_reat_at_le64 */
	{ LE_TEST(0, 0, 64) = 0xA8A7A6A5A4A3A2A1 },
	{ LE_TEST(0, 8, 64) = 0xB8B7B6B5B4B3B2B1 },
	{ LE_TEST(8, 0, 64) = 0xB8B7B6B5B4B3B2B1 },
	{ LE_TEST(8, 8, 64) = 0xC8C7C6C5C4C3C2C1 },
	/* rz_reat_le32, rz_reat_at_le32 */
	{ LE_TEST(0, 0, 32) = 0xA4A3A2A1 },
	{ LE_TEST(0, 8, 32) = 0xB4B3B2B1 },
	{ LE_TEST(8, 0, 32) = 0xB4B3B2B1 },
	{ LE_TEST(8, 8, 32) = 0xC4C3C2C1 },
	/* rz_reat_le24, rz_reat_at_le24 */
	{ LE24_TEST(0, 0) = 0xA3A2A1 },
	{ LE24_TEST(0, 8) = 0xB3B2B1 },
	{ LE24_TEST(8, 0) = 0xB3B2B1 },
	{ LE24_TEST(8, 8) = 0xC3C2C1 },
	/* rz_reat_le16, rz_reat_at_le16 */
	{ LE_TEST(0, 0, 16) = 0xA2A1 },
	{ LE_TEST(0, 8, 16) = 0xB2B1 },
	{ LE_TEST(8, 0, 16) = 0xB2B1 },
	{ LE_TEST(8, 8, 16) = 0xC2C1 },
	/* rz_reat_me64, rz_reat_at_me64 */
	{ ME_TEST(0, 0, 64) = 0xA7A8A5A6A3A4A1A2 },
	{ ME_TEST(0, 8, 64) = 0xB7B8B5B6B3B4B1B2 },
	{ ME_TEST(8, 0, 64) = 0xB7B8B5B6B3B4B1B2 },
	{ ME_TEST(8, 8, 64) = 0xC7C8C5C6C3C4C1C2 },
	/* rz_reat_me32, rz_reat_at_me32 */
	{ ME_TEST(0, 0, 32) = 0xA3A4A1A2 },
	{ ME_TEST(0, 8, 32) = 0xB3B4B1B2 },
	{ ME_TEST(8, 0, 32) = 0xB3B4B1B2 },
	{ ME_TEST(8, 8, 32) = 0xC3C4C1C2 },
	/* rz_reat_me16, rz_reat_at_me16 */
	{ ME_TEST(0, 0, 16) = 0xA1A2 },
	{ ME_TEST(0, 8, 16) = 0xB1B2 },
	{ ME_TEST(8, 0, 16) = 0xB1B2 },
	{ ME_TEST(8, 8, 16) = 0xC1C2 }
};

/* This is a helper macro, we later abstract away the vararg
   detail.
 */
#define MAKE_INTEGRAL_READ_TEST_AUX(ret_type, endianness, size, ...) \
	bool test_rz_read_##__VA_ARGS__##endianness##size() { \
		char dest[1024]; \
		size_t offset = 0; \
		size_t i; \
		ut##ret_type test_result = { 0 }; \
		ut##ret_type actual_result = { 0 }; \
		(void)offset; \
		for (i = 0; i < sizeof rz_read_table / sizeof rz_read_table[0]; i++) { \
			if (IS_##endianness##_SIZE(i, size)) { \
				test_result = rz_read_aux_##endianness##size(1 < sizeof "" #__VA_ARGS__, INPUT(i), OFFSET(i)); \
				actual_result = RESULT(i).u##ret_type; \
				mu_assert_memeq((void *)&test_result, (void *)&actual_result, size / 8, "rz_read_" #__VA_ARGS__ #endianness #size); \
				rz_write_aux_##endianness##size(1 < sizeof "" #__VA_ARGS__, dest, actual_result, OFFSET(i)); \
				mu_assert_memeq((void *)&dest[OFFSET(i)], (void *)(INPUT(i) + OFFSET(i)), size / 8, "rz_write_" #__VA_ARGS__ #endianness #size); \
			} \
		} \
		mu_end; \
	}

/**
 * \def MAKE_INTEGRAL_READ_TEST
 * \brief Create an integral read test.
 * \param ret_type The return type of the function.
 * \param endianness The endianness of the function.
 * \param size The read function of this size is called.
 * \attention \p size and \p ret_type are different when calling the
 * 24-bit functions because there is no 24-bit type, instead a \c ut32
 * is returned.
 * \attention The read test also tests the write functions. The name
 * of the function that failed is correctly reported, so there is no
 * confusion.
 * \bug The offset should not be more than 512, otherwise a buffer
 * overflow may occur. This issue can be solved by using malloc for
 * the dest buffer to allocate at least \c offset+sizeof(ut128)
 * bytes.
 *
 * The \p ret_type is one of \c 8, \c 16, \c 32, \c 64, \c 128. The \p
 * size is one of \c 8, \c 16, \c 24, \c 32, \c 64, \c 128. The \p
 * endianness is one of \c be, \c le, \c me.
 *
 * # Example
 *
 * Create two tests, \c test_rz_read_be64 and \c test_rz_read_at_be64.
 * They test from data in \c data_pool and \c rz_read_table.
 *
 * \code{.c}
 * MAKE_INTEGRAL_READ_TEST(64, be, 64)
 * \endcode
 *
 * To create tests for the 24-bit big-endian version, use
 *
 * \code{.c}
 * MAKE_INTEGRAL_READ_TEST(32, be, 24)
 * \endcode
 *
 * The \c 32 here is the size of the return type of \c rz_read_be24,
 * while \c 24 selects the 24-bit variant.
 */
#define MAKE_INTEGRAL_READ_TEST(ret_type, endianness, size) \
	/* This helper function decides at runtime which version of the two \
	   rz_read functions (with offset and without) to call.  The issue \
	   cannot be decided at preprocessing time because the number of \
	   arguments these functions take are not the same. */ \
	ut##ret_type rz_read_aux_##endianness##size(bool at, const char *src, size_t offset) { \
		if (at) { \
			if (#endianness[2] && #size[1]) { \
				return rz_read_at_ble##size(src, offset, #endianness[0] == 'b'); \
			} else { \
				return rz_read_at_##endianness##size(src, offset); \
			} \
		} else { \
			if (#endianness[2] && #size[1]) { \
				return rz_read_ble##size(&src[offset], #endianness[0] == 'b'); \
			} else { \
				return rz_read_##endianness##size(&src[offset]); \
			} \
		} \
	} \
	/* This helper function decides at runtime which version of the two \
	   rz_write functions (with offset and without) to call.  The issue \
	   cannot be decided at preprocessing time because the number of \
	   arguments these functions take are not the same. */ \
	void rz_write_aux_##endianness##size(bool at, char *dest, ut##ret_type val, size_t offset) { \
		if (at) { \
			if (#endianness[2] && #size[1]) { \
				rz_write_at_ble##size(dest, val, #endianness[0] == 'b', offset); \
			} else { \
				rz_write_at_##endianness##size(dest, val, offset); \
			} \
		} else { \
			if (#endianness[2] && #size[1]) { \
				rz_write_ble##size(&dest[offset], val, #endianness[0] == 'b'); \
			} else { \
				rz_write_##endianness##size(&dest[offset], val); \
			} \
		} \
	} \
	MAKE_INTEGRAL_READ_TEST_AUX(ret_type, endianness, size, at_) \
	MAKE_INTEGRAL_READ_TEST_AUX(ret_type, endianness, size)

MAKE_INTEGRAL_READ_TEST(128, be, 128)
MAKE_INTEGRAL_READ_TEST(64, be, 64)
MAKE_INTEGRAL_READ_TEST(32, be, 32)
MAKE_INTEGRAL_READ_TEST(32, be, 24)
MAKE_INTEGRAL_READ_TEST(16, be, 16)

MAKE_INTEGRAL_READ_TEST(128, le, 128)
MAKE_INTEGRAL_READ_TEST(64, le, 64)
MAKE_INTEGRAL_READ_TEST(32, le, 32)
MAKE_INTEGRAL_READ_TEST(32, le, 24)
MAKE_INTEGRAL_READ_TEST(16, le, 16)

MAKE_INTEGRAL_READ_TEST(64, me, 64)
MAKE_INTEGRAL_READ_TEST(32, me, 32)
MAKE_INTEGRAL_READ_TEST(16, me, 16)

/**
 * \brief Test the 8-bit read and write endianness functions.
 * \bug If \c data_pool grows larger than 1024 bytes, there will be a
 * buffer overflow in this function. To fix this if necessary, use
 * malloc to allocate at least \c sizeof(data_pool) bytes in \c buf.
 */
bool test_rz_read_8bit(void) {
	ut8 buf[1024];
	ut8 c;
	size_t i;
	for (i = 0; i < sizeof data_pool; i++) {
		c = rz_read_be8(&data_pool[i]);
		mu_assert_memeq((void *)&c, (void *)&data_pool[i], 1, "rz_read_be8");
		rz_write_be8(buf, c);
		mu_assert_memeq((void *)buf, (void *)&data_pool[i], 1, "rz_write_be8");

		c = rz_read_le8(&data_pool[i]);
		mu_assert_memeq((void *)&c, (void *)&data_pool[i], 1, "rz_read_le8");
		rz_write_le8(buf, c);
		mu_assert_memeq((void *)buf, (void *)&data_pool[i], 1, "rz_write_le8");

		c = rz_read_me8(&data_pool[i]);
		mu_assert_memeq((void *)&c, (void *)&data_pool[i], 1, "rz_read_me8");
		rz_write_me8(buf, c);
		mu_assert_memeq((void *)buf, (void *)&data_pool[i], 1, "rz_write_me8");

		c = rz_read_ble8(&data_pool[i]);
		mu_assert_memeq((void *)&c, (void *)&data_pool[i], 1, "rz_read_ble8");
		rz_write_ble8(buf, c);
		mu_assert_memeq((void *)buf, (void *)&data_pool[i], 1, "rz_write_ble8");

		c = rz_read_at_be8(data_pool, i);
		mu_assert_memeq((void *)&c, (void *)&data_pool[i], 1, "rz_read_at_be8");
		rz_write_at_be8(buf, c, i);
		mu_assert_memeq((void *)&buf[i], (void *)&data_pool[i], 1, "rz_write_at_be8");

		c = rz_read_at_le8(data_pool, i);
		mu_assert_memeq((void *)&c, (void *)&data_pool[i], 1, "rz_read_at_le8");
		rz_write_at_le8(buf, c, i);
		mu_assert_memeq((void *)&buf[i], (void *)&data_pool[i], 1, "rz_write_at_le8");

		c = rz_read_at_me8(data_pool, i);
		mu_assert_memeq((void *)&c, (void *)&data_pool[i], 1, "rz_read_at_me8");
		rz_write_at_me8(buf, c, i);
		mu_assert_memeq((void *)&buf[i], (void *)&data_pool[i], 1, "rz_write_at_me8");

		c = rz_read_at_ble8(data_pool, i);
		mu_assert_memeq((void *)&c, (void *)&data_pool[i], 1, "rz_read_at_ble8");
		rz_write_at_ble8(buf, c, i);
		mu_assert_memeq((void *)&buf[i], (void *)&data_pool[i], 1, "rz_write_at_ble8");
	}
	mu_end;
}

bool test_endian(void) {
	ut8 buf[8];
	rz_write_be16(buf, 0x1122);
	mu_assert_memeq((ut8 *)"\x11\x22", buf, 2, "be16");
	rz_write_le16(buf, 0x1122);
	mu_assert_memeq((ut8 *)"\x22\x11", buf, 2, "le16");

	rz_write_be32(buf, 0x11223344);
	mu_assert_memeq((ut8 *)"\x11\x22\x33\x44", buf, 4, "be32");
	rz_write_le32(buf, 0x11223344);
	mu_assert_memeq((ut8 *)"\x44\x33\x22\x11", buf, 4, "le32");

	rz_write_ble(buf, 0x1122, true, 16);
	mu_assert_memeq((ut8 *)"\x11\x22", buf, 2, "ble 16 true");
	rz_write_ble(buf, 0x1122, false, 16);
	mu_assert_memeq((ut8 *)"\x22\x11", buf, 2, "ble 16 false");

	mu_end;
}

bool test_rz_swap_ut64(void) {
	ut64 a = 0x1122334455667788;
	ut64 b = rz_swap_ut64(a);
	mu_assert_eq(b, 0x8877665544332211, "rz_swap_ut64");
	mu_end;
}

bool test_rz_swap_4b_ut64(void) {
	ut64 a = 0x1122334455667788;
	ut64 b = rz_swap_4b_ut64(a);
	mu_assert_eq(b, 0x4433221188776655, "rz_swap_4b_ut64");
	mu_end;
}

bool test_rz_swap_2b_ut64(void) {
	ut64 a = 0x1122334455667788;
	ut64 b = rz_swap_2b_ut64(a);
	mu_assert_eq(b, 0x2211443366558877, "rz_swap_2b_ut64");
	mu_end;
}

bool test_rz_swap_ut32(void) {
	ut32 a = 0x11223344;
	ut32 b = rz_swap_ut32(a);
	mu_assert_eq(b, 0x44332211, "rz_swap_ut32");
	mu_end;
}

bool test_rz_swap_2b_ut32(void) {
	ut32 a = 0x11223344;
	ut32 b = rz_swap_2b_ut32(a);
	mu_assert_eq(b, 0x22114433, "rz_swap_2b_ut32");
	mu_end;
}

bool test_rz_swap_ut16(void) {
	ut16 a = 0x1122;
	ut16 b = rz_swap_ut16(a);
	mu_assert_eq(b, 0x2211, "rz_swap_ut16");
	mu_end;
}

bool test_be(void) {
	const float f32 = 5.728f;
	const ut8 bf32[4] = { 0x40, 0xb7, 0x4b, 0xc7 };
	const double f64 = 821.3987218732134;
	const ut8 bf64[8] = { 0x40, 0x89, 0xab, 0x30, 0x95, 0x17, 0xed, 0x36 };

	float val32;
	double val64;

	ut8 buffer[8] = { 0 };

	val32 = rz_read_be_float(bf32);
	mu_assert_eqf(val32, f32, "float big endian decoded");

	val64 = rz_read_be_double(bf64);
	mu_assert_eqf(val64, f64, "double big endian decoded");

	rz_write_be_float(buffer, f32);
	mu_assert_memeq(buffer, bf32, sizeof(bf32), "float big endian encoded");

	rz_write_be_double(buffer, f64);
	mu_assert_memeq(buffer, bf64, sizeof(bf64), "double big endian encoded");

	mu_end;
}

bool test_le(void) {
	const float f32 = 5.728f;
	const ut8 bf32[4] = { 0xc7, 0x4b, 0xb7, 0x40 };
	const double f64 = 821.3987218732134;
	const ut8 bf64[8] = { 0x36, 0xed, 0x17, 0x95, 0x30, 0xab, 0x89, 0x40 };

	float val32;
	double val64;

	ut8 buffer[8] = { 0 };

	val32 = rz_read_le_float(bf32);
	mu_assert_eqf(val32, f32, "float little endian decoded");

	val64 = rz_read_le_double(bf64);
	mu_assert_eqf(val64, f64, "double little endian decoded");

	rz_write_le_float(buffer, f32);
	mu_assert_memeq(buffer, bf32, sizeof(bf32), "float little endian encoded");

	rz_write_le_double(buffer, f64);
	mu_assert_memeq(buffer, bf64, sizeof(bf64), "double little endian encoded");

	mu_end;
}

bool test_me(void) {
	const float f32 = 5.728f;
	const ut8 bf32[4] = { 0x4b, 0xc7, 0x40, 0xb7 };
	const double f64 = 821.3987218732134;
	const ut8 bf64[8] = { 0xed, 0x36, 0x95, 0x17, 0xab, 0x30, 0x40, 0x89 };

	float val32;
	double val64;

	ut8 buffer[8] = { 0 };

	val32 = rz_read_me_float(bf32);
	mu_assert_eqf(val32, f32, "float middle endian decoded");

	val64 = rz_read_me_double(bf64);
	mu_assert_eqf(val64, f64, "double middle endian decoded");

	rz_write_me_float(buffer, f32);
	mu_assert_memeq(buffer, bf32, sizeof(bf32), "float middle endian encoded");

	rz_write_me_double(buffer, f64);
	mu_assert_memeq(buffer, bf64, sizeof(bf64), "double middle endian encoded");

	mu_end;
}

// clang-format off
const ut8 blu64[32] = {
	0x36, 0xed, 0x17, 0x95, 0x30, 0xab, 0x89, 0x40,
	0x63, 0xde, 0x71, 0x59, 0x03, 0xba, 0x98, 0x04,
	0x36, 0xed, 0x17, 0x95, 0x30, 0xab, 0x89, 0x40,
	0x63, 0xde, 0x71, 0x59, 0x03, 0xba, 0x98, 0x04,
};
// clang-format on
#define check_offset(endianness, size, offset, prev_offset, expected) \
	ut##size val##size = rz_read_##endianness##size##_offset(blu64, &offset); \
	mu_assert_eq_fmt(val##size, expected, "wrong value of read " #endianness #size, "0x%04llx"); \
	prev_offset += sizeof(val##size); \
	mu_assert_eq(offset, prev_offset, "wrong offset after read " #endianness #size);

#define check_offset128(endianness, offset, prev_offset, expected) \
	ut128 val128 = rz_read_##endianness##128_offset(blu64, &offset); \
	mu_assert_eq_fmt(val128.High, expected.High, "wrong High value of read " #endianness "128", "0x%04llx"); \
	mu_assert_eq_fmt(val128.Low, expected.Low, "wrong Low value of read " #endianness "128", "0x%04llx"); \
	prev_offset += sizeof(val128); \
	mu_assert_eq(offset, prev_offset, "wrong offset after read " #endianness "128");

bool test_rz_read_offset_le() {
	const ut16 u16 = 0x9517;
	const ut32 u32 = 0x4089ab30;
	const ut64 u64 = 0x0498ba035971de63;
	const ut128 u128 = {
		.High = 0x360498ba035971de,
		.Low = 0x634089ab309517ed
	};

	size_t offset = 1, prev_offset = 1;
	check_offset(le, 8, offset, prev_offset, blu64[prev_offset]);
	check_offset(le, 16, offset, prev_offset, u16);
	check_offset(le, 32, offset, prev_offset, u32);
	check_offset(le, 64, offset, prev_offset, u64);
	offset = prev_offset = 1;
	check_offset128(le, offset, prev_offset, u128);
	mu_end;
}

bool test_rz_read_offset_be() {
	const ut16 u16 = 0x1795;
	const ut32 u32 = 0x30ab8940;
	const ut64 u64 = 0x63de715903ba9804;
	const ut128 u128 = {
		.High = 0xed179530ab894063,
		.Low = 0xde715903ba980436
	};

	size_t offset = 1, prev_offset = 1;
	check_offset(le, 8, offset, prev_offset, blu64[prev_offset]);
	check_offset(be, 16, offset, prev_offset, u16);
	check_offset(be, 32, offset, prev_offset, u32);
	check_offset(be, 64, offset, prev_offset, u64);
	offset = prev_offset = 1;
	check_offset128(be, offset, prev_offset, u128);
	mu_end;
}
int all_tests() {
	/* big-endian read tests */
	mu_run_test(test_rz_read_be128);
	mu_run_test(test_rz_read_at_be128);
	mu_run_test(test_rz_read_be64);
	mu_run_test(test_rz_read_at_be64);
	mu_run_test(test_rz_read_be32);
	mu_run_test(test_rz_read_at_be32);
	mu_run_test(test_rz_read_be24);
	mu_run_test(test_rz_read_at_be24);
	mu_run_test(test_rz_read_be16);
	mu_run_test(test_rz_read_at_be16);

	/* little-endian read tests */
	mu_run_test(test_rz_read_le128);
	mu_run_test(test_rz_read_at_le128);
	mu_run_test(test_rz_read_le64);
	mu_run_test(test_rz_read_at_le64);
	mu_run_test(test_rz_read_le32);
	mu_run_test(test_rz_read_at_le32);
	mu_run_test(test_rz_read_le24);
	mu_run_test(test_rz_read_at_le24);
	mu_run_test(test_rz_read_le16);
	mu_run_test(test_rz_read_at_le16);

	/* middle-endian read tests */
	mu_run_test(test_rz_read_me64);
	mu_run_test(test_rz_read_at_me64);
	mu_run_test(test_rz_read_me32);
	mu_run_test(test_rz_read_at_me32);
	mu_run_test(test_rz_read_me16);
	mu_run_test(test_rz_read_at_me16);

	/* 8-bit read/write tests */
	mu_run_test(test_rz_read_8bit);

	mu_run_test(test_endian);
	mu_run_test(test_rz_swap_ut64);
	mu_run_test(test_rz_swap_4b_ut64);
	mu_run_test(test_rz_swap_2b_ut64);
	mu_run_test(test_rz_swap_ut32);
	mu_run_test(test_rz_swap_2b_ut32);
	mu_run_test(test_rz_swap_ut16);
	mu_run_test(test_be);
	mu_run_test(test_le);
	mu_run_test(test_me);

	mu_run_test(test_rz_read_offset_le);
	mu_run_test(test_rz_read_offset_be);

	return tests_passed != tests_run;
}

mu_main(all_tests)
