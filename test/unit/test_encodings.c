// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"
#include <rz_util/rz_unicode.h>
#include <rz_util/rz_utf32.h>
#include <rz_util/rz_ebcdic.h>
#include <rz_util/rz_utf8.h>

bool test_rz_utf8_decode(void) {
	RzCodePoint codepoint = 0;
	const ut8 utf8_1b_valid_first[] = { 0x00 };
	const ut8 utf8_1b_valid_last[] = { 0x7f };
	const ut8 utf8_2b_valid_first[] = { 0xC2, 0x80 };
	const ut8 utf8_2b_valid_last[] = { 0xDF, 0xBF };
	const ut8 utf8_3b_valid_first[] = { 0xE0, 0xA0, 0x80 };
	const ut8 utf8_3b_valid_last[] = { 0xEF, 0xBF, 0xBD };
	const ut8 utf8_4b_valid_first[] = { 0xF0, 0x90, 0x80, 0x80 };
	const ut8 utf8_4b_valid_last[] = { 0xF4, 0x8F, 0xBF, 0xBD };

	mu_assert_eq(rz_utf8_decode(utf8_1b_valid_first, sizeof(utf8_1b_valid_first), &codepoint, true), 1, "Decode failed");
	mu_assert_eq(codepoint, 0, "Code point incorrect");
	mu_assert_eq(rz_utf8_decode(utf8_1b_valid_last, sizeof(utf8_1b_valid_last), &codepoint, true), 1, "Decode failed");
	mu_assert_eq(codepoint, 0x7f, "Code point incorrect");

	mu_assert_eq(rz_utf8_decode(utf8_2b_valid_first, sizeof(utf8_2b_valid_first), &codepoint, true), 2, "Decode failed");
	mu_assert_eq(codepoint, 0x80, "Code point incorrect");
	mu_assert_eq(rz_utf8_decode(utf8_2b_valid_last, sizeof(utf8_2b_valid_last), &codepoint, true), 2, "Decode failed");
	mu_assert_eq(codepoint, 0x07FF, "Code point incorrect");

	mu_assert_eq(rz_utf8_decode(utf8_3b_valid_first, sizeof(utf8_3b_valid_first), &codepoint, true), 3, "Decode failed");
	mu_assert_eq(codepoint, 0x800, "Code point incorrect");
	mu_assert_eq(rz_utf8_decode(utf8_3b_valid_last, sizeof(utf8_3b_valid_last), &codepoint, true), 3, "Decode failed");
	mu_assert_eq(codepoint, 0xFFFD, "Code point incorrect");

	mu_assert_eq(rz_utf8_decode(utf8_4b_valid_first, sizeof(utf8_4b_valid_first), &codepoint, true), 4, "Decode failed");
	mu_assert_eq(codepoint, 0x10000, "Code point incorrect");
	mu_assert_eq(rz_utf8_decode(utf8_4b_valid_last, sizeof(utf8_4b_valid_last), &codepoint, true), 4, "Decode failed");
	mu_assert_eq(codepoint, 0x10FFFD, "Code point incorrect");

	const ut8 utf8_1b_invalid_F[] = { 0xFF };
	const ut8 utf8_2b_invalid_F[] = { 0xFF, 0x00 };
	const ut8 utf8_3b_invalid_F[] = { 0xFF, 0x00, 0x00 };
	mu_assert_eq(rz_utf8_decode(utf8_1b_invalid_F, sizeof(utf8_1b_invalid_F), &codepoint, true), 0, "Invalid decode, prefix bit false.");
	mu_assert_eq(rz_utf8_decode(utf8_2b_invalid_F, sizeof(utf8_2b_invalid_F), &codepoint, true), 0, "Invalid decode, prefix bit false.");
	mu_assert_eq(rz_utf8_decode(utf8_3b_invalid_F, sizeof(utf8_3b_invalid_F), &codepoint, true), 0, "Invalid decode, prefix bit false.");

	const ut8 utf8_2b_invalid_small_code_point[] = { 0xC0, 0x80 };
	const ut8 utf8_3b_invalid_small_code_point[] = { 0xE0, 0x80, 0x80 };
	const ut8 utf8_4b_invalid_small_code_point[] = { 0xF0, 0x80, 0x80, 0x80 };

	mu_assert_eq(rz_utf8_decode(utf8_2b_invalid_small_code_point, sizeof(utf8_2b_invalid_small_code_point), &codepoint, true), 0, "Invalid decode, code point is too small for encoding.");
	mu_assert_eq(rz_utf8_decode(utf8_3b_invalid_small_code_point, sizeof(utf8_3b_invalid_small_code_point), &codepoint, true), 0, "Invalid decode, code point is too small for encoding.");
	mu_assert_eq(rz_utf8_decode(utf8_4b_invalid_small_code_point, sizeof(utf8_4b_invalid_small_code_point), &codepoint, true), 0, "Invalid decode, code point is too small for encoding.");

	mu_end;
}

/**
 * \brief Examples partially taken from: https://en.wikipedia.org/wiki/UTF-16#Examples
 */
bool test_rz_utf16_decode(void) {
	RzCodePoint codepoint = 0;
	const ut8 utf16le_surrogate[] = { 0xd8, 0x00 };
	mu_assert_eq(rz_utf16_decode(utf16le_surrogate, 2, &codepoint, true, true), 0, "Invalid decode");

	char utf8_out[5] = { 0 };
	const ut8 utf16le_A[] = { 0x41, 0x00 };
	const ut8 utf16be_A[] = { 0x00, 0x41 };

	int nbytes = rz_utf16_decode(utf16le_A, 2, &codepoint, true, false);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x0041, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "A", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	nbytes = rz_utf16_decode(utf16be_A, 2, &codepoint, true, true);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x0041, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "A", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	const ut8 utf16le[] = { 0xAC, 0x20 };
	const ut8 utf16be[] = { 0x20, 0xAC };

	nbytes = rz_utf16_decode(utf16le, 2, &codepoint, true, false);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x20AC, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "€", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	nbytes = rz_utf16_decode(utf16be, 2, &codepoint, true, true);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x20AC, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "€", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	// With surrogate
	const ut8 utf16le_surr[] = { 0x01, 0xD8, 0x37, 0xDC };
	const ut8 utf16be_surr[] = { 0xD8, 0x01, 0xDC, 0x37 };

	nbytes = rz_utf16_decode(utf16le_surr, 4, &codepoint, true, false);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x10437, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "𐐷", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	nbytes = rz_utf16_decode(utf16be_surr, 4, &codepoint, true, true);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x10437, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "𐐷", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	const ut8 utf16le_first_surr[] = { 0x00, 0xD8, 0x00, 0xDC };
	const ut8 utf16be_first_surr[] = { 0xD8, 0x00, 0xDC, 0x00 };

	nbytes = rz_utf16_decode(utf16le_first_surr, 4, &codepoint, true, false);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x10000, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "𐀀", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	nbytes = rz_utf16_decode(utf16be_first_surr, 4, &codepoint, true, true);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x10000, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "𐀀", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	const ut8 utf16le_last_surr[] = { 0xFF, 0xDB, 0xFF, 0xDF };
	const ut8 utf16be_last_surr[] = { 0xDB, 0xFF, 0xDF, 0xFF };

	nbytes = rz_utf16_decode(utf16le_last_surr, 4, &codepoint, true, false);
	mu_assert_eq(nbytes, 0, "Undefined code point.");

	nbytes = rz_utf16_decode(utf16be_last_surr, 4, &codepoint, true, true);
	mu_assert_eq(nbytes, 0, "Undefined code point.");

	nbytes = rz_utf16_decode(utf16be_last_surr, 2, &codepoint, false, true);
	mu_assert_eq(nbytes, 0, "Surrogate should never be allowed.");
	const ut8 utf16_undef[] = { 0xFF, 0xFF };
	nbytes = rz_utf16_decode(utf16_undef, 2, &codepoint, false, true);
	mu_assert_eq(nbytes, 2, "Undefined was allowed.");

	const ut8 utf16le_invalid_small_surr[] = { 0x00, 0xD7, 0x00, 0xDB };
	const ut8 utf16be_invalid_small_surr[] = { 0xD7, 0x00, 0xDB, 0x00 };

	// Fails to decode 4, should decode 2 bytes.
	nbytes = rz_utf16_decode(utf16le_invalid_small_surr, 4, &codepoint, true, false);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0xD700, "Character decode failed.", "0x%" PFMT64x);

	nbytes = rz_utf16_decode(utf16be_invalid_small_surr, 4, &codepoint, true, true);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0xD700, "Character decode failed.", "0x%" PFMT64x);

	const ut8 utf16le_invalid_big_surr[] = { 0x01, 0xDC, 0x37, 0xE0 };
	const ut8 utf16be_invalid_big_surr[] = { 0xDC, 0x01, 0xE0, 0x37 };

	nbytes = rz_utf16_decode(utf16le_invalid_big_surr, 4, &codepoint, true, false);
	mu_assert_eq(nbytes, 0, "Undefined code point.");
	nbytes = rz_utf16_decode(utf16be_invalid_big_surr, 4, &codepoint, true, true);
	mu_assert_eq(nbytes, 0, "Undefined code point.");

	const ut8 utf16le_last_non_surr[] = { 0xff, 0xff, 0xff, 0xff };
	const ut8 utf16be_last_non_surr[] = { 0xff, 0xff, 0xff, 0xff };

	nbytes = rz_utf16_decode(utf16le_last_non_surr, 4, &codepoint, true, false);
	mu_assert_eq(nbytes, 0, "Undefined code point.");
	nbytes = rz_utf16_decode(utf16be_last_non_surr, 4, &codepoint, true, true);
	mu_assert_eq(nbytes, 0, "Undefined code point.");

	mu_end;
}

/**
 * \brief Examples partially taken from: https://en.wikipedia.org/wiki/UTF-16#Examples
 */
bool test_rz_utf16_encode(void) {
	ut8 utf16_out[5] = { 0 };

	const ut8 utf16le[] = { 0xAC, 0x20 };
	const ut8 utf16be[] = { 0x20, 0xAC };
	RzCodePoint codepoint = 0x20AC;
	int nbytes = rz_utf16_encode(utf16_out, codepoint, false);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_memeq(utf16_out, utf16le, sizeof(utf16le), "Encode failed.");
	nbytes = rz_utf16_encode(utf16_out, codepoint, true);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_memeq(utf16_out, utf16be, sizeof(utf16be), "Encode failed.");
	memset(utf16_out, 0, sizeof(utf16_out));

	// With surrogate
	const ut8 utf16le_surr[] = { 0x01, 0xD8, 0x37, 0xDC };
	const ut8 utf16be_surr[] = { 0xD8, 0x01, 0xDC, 0x37 };
	codepoint = 0x10437;
	nbytes = rz_utf16_encode(utf16_out, codepoint, false);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_memeq(utf16_out, utf16le_surr, sizeof(utf16le), "Encode failed.");
	nbytes = rz_utf16_encode(utf16_out, codepoint, true);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_memeq(utf16_out, utf16be_surr, sizeof(utf16be_surr), "Encode failed.");
	memset(utf16_out, 0, sizeof(utf16_out));

	const ut8 utf16le_first_surr[] = { 0x00, 0xD8, 0x00, 0xDC };
	const ut8 utf16be_first_surr[] = { 0xD8, 0x00, 0xDC, 0x00 };
	codepoint = 0x10000;
	nbytes = rz_utf16_encode(utf16_out, codepoint, false);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_memeq(utf16_out, utf16le_first_surr, sizeof(utf16le_first_surr), "Encode failed.");
	nbytes = rz_utf16_encode(utf16_out, codepoint, true);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_memeq(utf16_out, utf16be_first_surr, sizeof(utf16be_first_surr), "Encode failed.");
	memset(utf16_out, 0, sizeof(utf16_out));

	const ut8 utf16le_last_surr[] = { 0xFF, 0xDB, 0xFF, 0xDF };
	const ut8 utf16be_last_surr[] = { 0xDB, 0xFF, 0xDF, 0xFF };
	codepoint = RZ_UNICODE_LAST_CODE_POINT;
	nbytes = rz_utf16_encode(utf16_out, codepoint, false);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_memeq(utf16_out, utf16le_last_surr, sizeof(utf16le_last_surr), "Encode failed.");
	nbytes = rz_utf16_encode(utf16_out, codepoint, true);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_memeq(utf16_out, utf16be_last_surr, sizeof(utf16be_last_surr), "Encode failed.");

	memset(utf16_out, 0, sizeof(utf16_out));

	ut8 zero[5] = { 0 };
	codepoint = 0x110000;
	nbytes = rz_utf16_encode(utf16_out, codepoint, false);
	mu_assert_eq(nbytes, 0, "Decoded number of bytes mismatch.");
	nbytes = rz_utf16_encode(utf16_out, codepoint, true);
	mu_assert_eq(nbytes, 0, "Decoded number of bytes mismatch.");
	mu_assert_memeq(utf16_out, zero, sizeof(zero), "Encode failed.");

	mu_end;
}

bool test_rz_utf32_decode(void) {
	const ut8 utf32_size_1[] = { 0xAC };
	const ut8 utf32_size_2[] = { 0xAC, 0xAC };
	const ut8 utf32_size_3[] = { 0xAC, 0xAC, 0x20 };
	const ut8 utf32_undefined_I[] = { 0xFF, 0xFF, 0xFF, 0xFF };
	const ut8 utf32_invalid_surrogate[] = { 0x00, 0x00, 0xD8, 0x00 };

	const ut8 utf32be_A[] = { 0x00, 0x00, 0x00, 0x41 };
	const ut8 utf32le_A[] = { 0x41, 0x00, 0x00, 0x00 };

	// The non-ascii small a
	const ut8 utf32be_a[] = { 0x00, 0x00, 0xff, 0x41 };
	const ut8 utf32le_a[] = { 0x41, 0xff, 0x00, 0x00 };

	// Chess tower symbol Red General: 🩠
	const ut8 utf32be_red_general[] = { 0x00, 0x01, 0xFA, 0x60 };
	const ut8 utf32le_red_general[] = { 0x60, 0xfa, 0x01, 0x00 };

	// Chess tower symbol Red General: 🩠  🩁
	const ut8 utf32be_red_general_black_tower[] = { 0x00, 0x01, 0xFA, 0x60, 0x00, 0x01, 0xFA, 0x41 };
	const ut8 utf32le_red_general_black_tower[] = { 0x60, 0xFA, 0x01, 0x00, 0x41, 0xFA, 0x01, 0x00 };

	RzCodePoint cp;
	mu_assert_eq(rz_utf32_decode((ut8 *)INT_MIN, 0, &cp, true, false), 0, "Length check failed");
	mu_assert_eq(rz_utf32_decode(utf32_size_1, sizeof(utf32_size_1), &cp, true, false), 0, "Length check failed");
	mu_assert_eq(rz_utf32_decode(utf32_size_2, sizeof(utf32_size_2), &cp, true, false), 0, "Length check failed");
	mu_assert_eq(rz_utf32_decode(utf32_size_3, sizeof(utf32_size_3), &cp, true, false), 0, "Length check failed");
	mu_assert_eq(rz_utf32_decode(utf32_undefined_I, sizeof(utf32_undefined_I), &cp, true, false), 0, "Undefined");
	mu_assert_eq(rz_utf32_decode(utf32_undefined_I, sizeof(utf32_undefined_I), &cp, false, false), 4, "Undefined was allowed");
	mu_assert_eq(rz_utf32_decode(utf32_invalid_surrogate, sizeof(utf32_invalid_surrogate), &cp, true, false), 0, "Undefined");

	mu_assert_eq(rz_utf32_decode(utf32be_A, sizeof(utf32be_A), &cp, true, true), 4, "Length check failed");
	mu_assert_eq(cp, 0x41, "Incorrect decoding.");
	mu_assert_eq(rz_utf32_decode(utf32le_A, sizeof(utf32le_A), &cp, true, false), 4, "Length check failed");
	mu_assert_eq(cp, 0x41, "Incorrect decoding.");

	mu_assert_eq(rz_utf32_decode(utf32be_a, sizeof(utf32be_a), &cp, true, true), 4, "Length check failed");
	mu_assert_eq(cp, 0xff41, "Incorrect decoding.");
	mu_assert_eq(rz_utf32_decode(utf32le_a, sizeof(utf32le_a), &cp, true, false), 4, "Length check failed");
	mu_assert_eq(cp, 0xff41, "Incorrect decoding.");

	mu_assert_eq(rz_utf32_decode(utf32be_red_general, sizeof(utf32be_red_general), &cp, true, true), 4, "Length check failed");
	mu_assert_eq(cp, 0x01fa60, "Incorrect decoding.");
	mu_assert_eq(rz_utf32_decode(utf32le_red_general, sizeof(utf32le_red_general), &cp, true, false), 4, "Length check failed");
	mu_assert_eq(cp, 0x01fa60, "Incorrect decoding.");

	mu_assert_eq(rz_utf32_decode(utf32be_red_general_black_tower, sizeof(utf32be_red_general_black_tower), &cp, true, true), 4, "Length check failed");
	mu_assert_eq(cp, 0x01fa60, "Incorrect decoding.");
	mu_assert_eq(rz_utf32_decode(utf32le_red_general_black_tower, sizeof(utf32le_red_general_black_tower), &cp, true, false), 4, "Length check failed");
	mu_assert_eq(cp, 0x01fa60, "Incorrect decoding.");

	mu_assert_eq(rz_utf32_decode(utf32be_red_general_black_tower + 4, sizeof(utf32be_red_general_black_tower) - 4, &cp, true, true), 4, "Length check failed");
	mu_assert_eq(cp, 0x01fa41, "Incorrect decoding.");
	mu_assert_eq(rz_utf32_decode(utf32le_red_general_black_tower + 4, sizeof(utf32le_red_general_black_tower) - 4, &cp, true, false), 4, "Length check failed");
	mu_assert_eq(cp, 0x01fa41, "Incorrect decoding.");

	mu_end;
}

bool test_rz_utf32_valid(void) {
	const ut8 utf32le_invalid_size[] = { 0xAC, 0xAC, 0x20 };

	const ut8 utf32be_valid_max_cp[] = { 0x00, 0x10, 0xff, 0xff };
	const ut8 utf32be_invalid_max_cp[] = { 0x00, 0x11, 0x00, 0x00 };

	const ut8 utf32le_valid_max_cp[] = { 0xff, 0xff, 0x10, 0x00 };
	const ut8 utf32le_invalid_max_cp[] = { 0x00, 0x00, 0x11, 0x00 };

	const ut8 utf32be_invalid_surrogate_I[] = { 0x00, 0x00, 0xd8, 0x00 };
	const ut8 utf32be_invalid_surrogate_II[] = { 0x00, 0x00, 0xdf, 0xff };
	const ut8 utf32be_invalid_surrogate_III[] = { 0x00, 0x00, 0xd7, 0xff };
	const ut8 utf32be_invalid_surrogate_IV[] = { 0x00, 0x00, 0xe0, 0x00 };

	const ut8 utf32be_valid_invalid[] = { 0x00, 0x10, 0xff, 0xff, 0x00, 0x11, 0x00, 0x00 };

	mu_assert_false(rz_utf32_valid_code_point(utf32le_invalid_size, sizeof(utf32le_invalid_size), false, 1), "Length check failed");

	mu_assert_false(rz_utf32_valid_code_point(utf32be_invalid_max_cp, sizeof(utf32be_invalid_max_cp), true, 1), "Invalid max failed");
	mu_assert_true(rz_utf32_valid_code_point(utf32be_valid_max_cp, sizeof(utf32be_valid_max_cp), true, 1), "Valid max failed");

	mu_assert_false(rz_utf32_valid_code_point(utf32le_invalid_max_cp, sizeof(utf32le_invalid_max_cp), false, 1), "Invalid max failed");
	mu_assert_true(rz_utf32_valid_code_point(utf32le_valid_max_cp, sizeof(utf32le_valid_max_cp), false, 1), "Valid max failed");

	mu_assert_false(rz_utf32_valid_code_point(utf32be_invalid_surrogate_I, sizeof(utf32be_invalid_surrogate_I), true, 1), "Surrogate failed");
	mu_assert_false(rz_utf32_valid_code_point(utf32be_invalid_surrogate_II, sizeof(utf32be_invalid_surrogate_II), true, 1), "Surrogate failed");
	mu_assert_true(rz_utf32_valid_code_point(utf32be_invalid_surrogate_III, sizeof(utf32be_invalid_surrogate_III), true, 1), "Surrogate failed");
	mu_assert_true(rz_utf32_valid_code_point(utf32be_invalid_surrogate_IV, sizeof(utf32be_invalid_surrogate_IV), true, 1), "Surrogate failed");

	mu_assert_false(rz_utf32_valid_code_point(utf32be_invalid_surrogate_IV, sizeof(utf32be_invalid_surrogate_IV), true, 2), "Look ahead is not covered by buffer.");
	mu_assert_false(rz_utf32_valid_code_point(utf32be_invalid_surrogate_IV, sizeof(utf32be_invalid_surrogate_IV), true, 0), "Look ahead is 0.");

	mu_assert_true(rz_utf32_valid_code_point(utf32be_valid_invalid, sizeof(utf32be_valid_invalid), true, 1), "First is ok.");
	mu_assert_false(rz_utf32_valid_code_point(utf32be_valid_invalid, sizeof(utf32be_valid_invalid), true, 2), "But last one is not ok.");

	mu_end;
}

bool test_rz_ebcdic_valid(void) {
	// General
	mu_assert_true(rz_str_ebcdic_valid_code_point(0x41), "A should be valid.");
	mu_assert_true(rz_str_ebcdic_valid_code_point(0), "\\0 should be valid.");
	// EBCDIC-ES
	mu_assert_true(rz_str_ebcdic_valid_code_point(0xf1), "ñ should be valid.");
	// EBCDIC-US
	mu_assert_true(rz_str_ebcdic_valid_code_point(0xa2), "¢ should be valid.");
	// EBCDIC-UK
	mu_assert_true(rz_str_ebcdic_valid_code_point(0xa3), "£ should be valid.");
	// IBM037
	mu_assert_true(rz_str_ebcdic_valid_code_point(0xe4), "ä should be valid.");
	// IBM290
	mu_assert_true(rz_str_ebcdic_valid_code_point(0x30a5), "ゥshould be valid.");

	// An unsopported one.
	mu_assert_false(rz_str_ebcdic_valid_code_point(0x1E4E), "Ṏ should not be valid.");

	mu_end;
}

bool test_rz_unicode_printable(void) {
	// Control
	mu_assert_false(rz_unicode_code_point_is_printable(0x0), "Not printable.");
	mu_assert_false(rz_unicode_code_point_is_printable(31), "Not printable.");
	mu_assert_true(rz_unicode_code_point_is_printable(32), "Printable.");
	mu_assert_true(rz_unicode_code_point_is_printable(126), "Printable.");
	mu_assert_false(rz_unicode_code_point_is_printable(127), "Not printable.");
	mu_assert_false(rz_unicode_code_point_is_printable(159), "Not printable.");
	mu_assert_true(rz_unicode_code_point_is_printable(160), "Printable.");

	// Surrogates
	mu_assert_false(rz_unicode_code_point_is_printable(55296), "Not printable.");
	mu_assert_false(rz_unicode_code_point_is_printable(57343), "Not printable.");

	// Private - consider them not printable
	mu_assert_false(rz_unicode_code_point_is_printable(57344), "Not printable.");
	mu_assert_false(rz_unicode_code_point_is_printable(63743), "Not printable.");
	mu_assert_true(rz_unicode_code_point_is_printable(63744), "Printable.");

	mu_assert_false(rz_unicode_code_point_is_printable(983040), "Not printable.");
	mu_assert_false(rz_unicode_code_point_is_printable(1048573), "Not printable.");

	mu_assert_false(rz_unicode_code_point_is_printable(1048576), "Not printable.");
	mu_assert_false(rz_unicode_code_point_is_printable(1114109), "Not printable.");

	// Undefined
	// First
	mu_assert_true(rz_unicode_code_point_is_printable(887), "Printable.");
	mu_assert_false(rz_unicode_code_point_is_printable(888), "Not printable.");
	mu_assert_false(rz_unicode_code_point_is_printable(889), "Not printable.");
	mu_assert_true(rz_unicode_code_point_is_printable(890), "Printable.");
	// Last
	mu_assert_false(rz_unicode_code_point_is_printable(1114110), "Not printable.");
	mu_assert_false(rz_unicode_code_point_is_printable(1114111), "Not printable.");
	// Out of code point range.
	mu_assert_false(rz_unicode_code_point_is_printable(0x110000), "Not printable.");
	mu_assert_false(rz_unicode_code_point_is_printable(0xFFFFFFFF), "Not printable.");
	// Even offset in table
	mu_assert_true(rz_unicode_code_point_is_printable(3010), "Printable.");
	mu_assert_false(rz_unicode_code_point_is_printable(3011), "Not printable.");
	mu_assert_false(rz_unicode_code_point_is_printable(3013), "Not printable.");
	mu_assert_true(rz_unicode_code_point_is_printable(3014), "Printable.");
	// Odd offset in table
	mu_assert_true(rz_unicode_code_point_is_printable(3016), "Printable.");
	mu_assert_false(rz_unicode_code_point_is_printable(3017), "Not printable.");
	mu_assert_true(rz_unicode_code_point_is_printable(3018), "Printable.");

	mu_end;
}

bool test_rz_unicode_control(void) {
	// Control
	mu_assert_true(rz_unicode_code_point_is_control(0x0), "Control.");
	mu_assert_true(rz_unicode_code_point_is_control(31), "Control.");
	mu_assert_false(rz_unicode_code_point_is_control(32), "Not control.");
	mu_assert_false(rz_unicode_code_point_is_control(126), "Not control.");
	mu_assert_true(rz_unicode_code_point_is_control(127), "Control.");
	mu_assert_true(rz_unicode_code_point_is_control(159), "Control.");
	mu_assert_false(rz_unicode_code_point_is_control(160), "Not control.");
	mu_end;
}

bool test_rz_unicode_surrogate(void) {
	// Surrogates
	mu_assert_false(rz_unicode_code_point_is_printable(55296), "Not printable.");
	mu_assert_false(rz_unicode_code_point_is_printable(57343), "Not printable.");
	mu_end;
}

bool test_rz_unicode_private(void) {
	// Private - consider them private
	mu_assert_false(rz_unicode_code_point_is_private(57343), "Not private.");
	mu_assert_true(rz_unicode_code_point_is_private(57344), "Private.");
	mu_assert_true(rz_unicode_code_point_is_private(63743), "Private.");
	mu_assert_false(rz_unicode_code_point_is_private(63744), "Not private.");

	mu_assert_false(rz_unicode_code_point_is_private(983039), "Not private.");
	mu_assert_true(rz_unicode_code_point_is_private(983040), "Private.");
	mu_assert_true(rz_unicode_code_point_is_private(1048573), "Private.");
	mu_assert_false(rz_unicode_code_point_is_private(1048574), "Not private.");

	mu_assert_false(rz_unicode_code_point_is_private(1048575), "Not private.");
	mu_assert_true(rz_unicode_code_point_is_private(1048576), "Private.");
	mu_assert_true(rz_unicode_code_point_is_private(1114109), "Private.");
	mu_assert_false(rz_unicode_code_point_is_private(1114110), "Not private.");
	mu_end;
}

bool test_rz_unicode_undefined(void) {
	// Undefined
	// First
	mu_assert_true(rz_unicode_code_point_is_defined(887), "Defined.");
	mu_assert_false(rz_unicode_code_point_is_defined(888), "Not defined.");
	mu_assert_false(rz_unicode_code_point_is_defined(889), "Not defined.");
	mu_assert_true(rz_unicode_code_point_is_defined(890), "Defined.");
	// Last
	mu_assert_true(rz_unicode_code_point_is_defined(1114109), "Defined.");
	mu_assert_false(rz_unicode_code_point_is_defined(1114110), "Not defined.");
	mu_assert_false(rz_unicode_code_point_is_defined(1114111), "Not defined.");
	mu_assert_false(rz_unicode_code_point_is_defined(1114112), "Defined.");
	// Out of range
	mu_assert_false(rz_unicode_code_point_is_defined(0x110000), "Not defined.");
	mu_assert_false(rz_unicode_code_point_is_defined(0xFFFFFFFF), "Not defined.");
	// Even offset in table
	mu_assert_true(rz_unicode_code_point_is_defined(3010), "Defined.");
	mu_assert_false(rz_unicode_code_point_is_defined(3011), "Not defined.");
	mu_assert_false(rz_unicode_code_point_is_defined(3013), "Not defined.");
	mu_assert_true(rz_unicode_code_point_is_defined(3014), "Defined.");
	// Odd offset in table
	mu_assert_true(rz_unicode_code_point_is_defined(3016), "Defined.");
	mu_assert_false(rz_unicode_code_point_is_defined(3017), "Not defined.");
	mu_assert_true(rz_unicode_code_point_is_defined(3018), "Defined.");

	mu_end;
}

bool test_rz_utf16_valid(void) {
	const ut8 utf16be_one_byte[] = { 0x00 };
	const ut8 utf16be_A[] = { 0x00, 0x41 };
	const ut8 utf16be_ff[] = { 0x00, 0x00 };
	const ut8 utf16be_EUR[] = { 0x20, 0xAC };
	const ut8 utf16be_complex[] = { 0xD8, 0x01, 0xDC, 0x37 };
	const ut8 utf16be_A_A[] = { 0x00, 0x41, 0x00, 0x41 };
	const ut8 utf16be_complex_EUR_A[] = { 0xD8, 0x01, 0xDC, 0x37, 0x20, 0xAC, 0x00, 0x41 };
	const ut8 utf16be_complex_A_EUR[] = { 0xD8, 0x01, 0xDC, 0x37, 0x00, 0x41, 0x20, 0xAC };
	const ut8 utf16be_A_complex_EUR[] = { 0x00, 0x41, 0xD8, 0x01, 0xDC, 0x37, 0x20, 0xAC };
	const ut8 utf16be_invalid_complex_EUR[] = { 0x00, 0x00, 0xD8, 0x01, 0xDC, 0x37, 0x20, 0xAC };
	const ut8 utf16be_complex_invalid_EUR[] = { 0xD8, 0x01, 0xDC, 0x37, 0x00, 0x00, 0x20, 0xAC };
	const ut8 utf16be_complex_EUR_invalid[] = { 0xD8, 0x01, 0xDC, 0x37, 0x20, 0xAC, 0xD8, 0xff, 0xDC, 0xff };

	// Simple error cases
	mu_assert_false(rz_utf16_is_printable_code_point(utf16be_A, sizeof(utf16be_A), true, 0), "lookahead == 0 is not valid.");
	mu_assert_false(rz_utf16_is_printable_code_point(utf16be_one_byte, sizeof(utf16be_one_byte), false, 1), "Buffer too small.");
	mu_assert_false(rz_utf16_is_printable_code_point(utf16be_ff, sizeof(utf16be_ff), true, 1), "Not printable.");

	// Simple cases. One character in buffer.
	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_A, sizeof(utf16be_A), true, 1), "Should be valid");
	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_EUR, sizeof(utf16be_EUR), true, 1), "Should be valid");
	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_complex, sizeof(utf16be_complex), true, 1), "Should be valid");

	// Different width UTF-16 characters
	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_complex_EUR_A, sizeof(utf16be_complex_EUR_A), true, 1), "Should true with 1 different characters.");
	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_complex_A_EUR, sizeof(utf16be_complex_A_EUR), true, 1), "Should true with 1 different characters.");
	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_A_complex_EUR, sizeof(utf16be_A_complex_EUR), true, 1), "Should true with 1 different characters.");
	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_A_A, sizeof(utf16be_A_A), true, 1), "Should true with 1 different characters.");
	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_complex_EUR_A, sizeof(utf16be_complex_EUR_A), true, 2), "Should true with 2 different characters.");
	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_complex_A_EUR, sizeof(utf16be_complex_A_EUR), true, 2), "Should true with 2 different characters.");
	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_A_complex_EUR, sizeof(utf16be_A_complex_EUR), true, 2), "Should true with 2 different characters.");
	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_A_A, sizeof(utf16be_A_A), true, 2), "Should true with 2 different characters.");
	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_complex_EUR_A, sizeof(utf16be_complex_EUR_A), true, 3), "Should true with 3 different characters.");
	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_complex_A_EUR, sizeof(utf16be_complex_A_EUR), true, 3), "Should true with 3 different characters.");
	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_A_complex_EUR, sizeof(utf16be_A_complex_EUR), true, 3), "Should true with 3 different characters.");

	// Look ahead goes past buffer.
	mu_assert_false(rz_utf16_is_printable_code_point(utf16be_A, sizeof(utf16be_A), true, 2), "Too many code point checks for buffer.");
	mu_assert_false(rz_utf16_is_printable_code_point(utf16be_EUR, sizeof(utf16be_EUR), true, 2), "Too many code point checks for buffer.");
	mu_assert_false(rz_utf16_is_printable_code_point(utf16be_complex, sizeof(utf16be_complex), true, 2), "Too many code point checks for buffer.");
	mu_assert_false(rz_utf16_is_printable_code_point(utf16be_A_A, sizeof(utf16be_A_A), true, 3), "Too many code point checks for buffer.");
	mu_assert_false(rz_utf16_is_printable_code_point(utf16be_complex_EUR_A, sizeof(utf16be_complex_EUR_A), true, 4), "Too many code point checks for buffer.");
	mu_assert_false(rz_utf16_is_printable_code_point(utf16be_complex_A_EUR, sizeof(utf16be_complex_A_EUR), true, 4), "Too many code point checks for buffer.");
	mu_assert_false(rz_utf16_is_printable_code_point(utf16be_A_complex_EUR, sizeof(utf16be_A_complex_EUR), true, 4), "Too many code point checks for buffer.");

	mu_assert_false(rz_utf16_is_printable_code_point(utf16be_invalid_complex_EUR, sizeof(utf16be_invalid_complex_EUR), true, 3), "Should fail at first.");

	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_complex_invalid_EUR, sizeof(utf16be_complex_invalid_EUR), true, 1), "The first is still valid.");
	mu_assert_false(rz_utf16_is_printable_code_point(utf16be_complex_invalid_EUR, sizeof(utf16be_complex_invalid_EUR), true, 3), "Should fail before EUR.");

	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_complex_EUR_invalid, sizeof(utf16be_complex_EUR_invalid), true, 1), "The first is still valid.");
	mu_assert_true(rz_utf16_is_printable_code_point(utf16be_complex_EUR_invalid, sizeof(utf16be_complex_EUR_invalid), true, 2), "The second is still valid.");
	mu_assert_false(rz_utf16_is_printable_code_point(utf16be_complex_EUR_invalid, sizeof(utf16be_complex_EUR_invalid), true, 3), "Should be false.");

	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_utf8_decode);
	mu_run_test(test_rz_utf16_decode);
	mu_run_test(test_rz_utf16_encode);
	mu_run_test(test_rz_utf32_decode);
	mu_run_test(test_rz_utf32_valid);
	mu_run_test(test_rz_utf16_valid);
	mu_run_test(test_rz_ebcdic_valid);
	mu_run_test(test_rz_unicode_printable);
	mu_run_test(test_rz_unicode_undefined);
	mu_run_test(test_rz_unicode_surrogate);
	mu_run_test(test_rz_unicode_private);
	mu_run_test(test_rz_unicode_control);

	return tests_passed != tests_run;
}

mu_main(all_tests)
