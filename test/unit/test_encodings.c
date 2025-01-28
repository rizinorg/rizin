// SPDX-FileCopyrightText: 2025 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"
#include <rz_util/rz_ebcdic.h>
#include <rz_util/rz_utf8.h>

/**
 * \brief Examples partially taken from: https://en.wikipedia.org/wiki/UTF-16#Examples
 */
bool test_rz_utf16_decode(void) {
	char utf8_out[5] = { 0 };
	RzCodePoint codepoint = 0;
	const ut8 utf16le[] = { 0xAC, 0x20 };
	const ut8 utf16be[] = { 0x20, 0xAC };

	int nbytes = rz_utf16_decode(utf16le, 2, &codepoint, false);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x20AC, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "€", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	nbytes = rz_utf16_decode(utf16be, 2, &codepoint, true);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x20AC, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "€", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	// With surrogate
	const ut8 utf16le_surr[] = { 0x01, 0xD8, 0x37, 0xDC };
	const ut8 utf16be_surr[] = { 0xD8, 0x01, 0xDC, 0x37 };

	nbytes = rz_utf16_decode(utf16le_surr, 4, &codepoint, false);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x10437, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "𐐷", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	nbytes = rz_utf16_decode(utf16be_surr, 4, &codepoint, true);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x10437, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "𐐷", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	const ut8 utf16le_first_surr[] = { 0x00, 0xD8, 0x00, 0xDC };
	const ut8 utf16be_first_surr[] = { 0xD8, 0x00, 0xDC, 0x00 };

	nbytes = rz_utf16_decode(utf16le_first_surr, 4, &codepoint, false);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x10000, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "𐀀", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	nbytes = rz_utf16_decode(utf16be_first_surr, 4, &codepoint, true);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x10000, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "𐀀", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	const ut8 utf16le_last_surr[] = { 0xFF, 0xDB, 0xFF, 0xDF };
	const ut8 utf16be_last_surr[] = { 0xDB, 0xFF, 0xDF, 0xFF };

	nbytes = rz_utf16_decode(utf16le_last_surr, 4, &codepoint, false);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x10FFFF, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "􏿿", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	nbytes = rz_utf16_decode(utf16be_last_surr, 4, &codepoint, true);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0x10FFFF, "Character decode failed.", "0x%" PFMT64x);
	rz_utf8_encode((ut8 *)utf8_out, codepoint);
	mu_assert_streq(utf8_out, "􏿿", "Encode failed.");
	memset(utf8_out, 0, sizeof(utf8_out));

	const ut8 utf16le_invalid_small_surr[] = { 0x00, 0xD7, 0x00, 0xDB };
	const ut8 utf16be_invalid_small_surr[] = { 0xD7, 0x00, 0xDB, 0x00 };

	// Fails to decode 4, should decode 2 bytes.
	nbytes = rz_utf16_decode(utf16le_invalid_small_surr, 4, &codepoint, false);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0xD700, "Character decode failed.", "0x%" PFMT64x);

	nbytes = rz_utf16_decode(utf16be_invalid_small_surr, 4, &codepoint, true);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0xD700, "Character decode failed.", "0x%" PFMT64x);

	const ut8 utf16le_invalid_big_surr[] = { 0x01, 0xDC, 0x37, 0xE0 };
	const ut8 utf16be_invalid_big_surr[] = { 0xDC, 0x01, 0xE0, 0x37 };

	nbytes = rz_utf16_decode(utf16le_invalid_big_surr, 4, &codepoint, false);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0xDC01, "Character decode failed.", "0x%" PFMT64x);
	nbytes = rz_utf16_decode(utf16be_invalid_big_surr, 4, &codepoint, true);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0xDC01, "Character decode failed.", "0x%" PFMT64x);

	const ut8 utf16le_invalid[] = { 0xff, 0xff, 0xff, 0xff };
	const ut8 utf16be_invalid[] = { 0xff, 0xff, 0xff, 0xff };

	nbytes = rz_utf16_decode(utf16le_invalid, 4, &codepoint, false);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0xFFFF, "Character decode failed.", "0x%" PFMT64x);
	nbytes = rz_utf16_decode(utf16be_invalid, 4, &codepoint, true);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_eq_fmt(codepoint, 0xFFFF, "Character decode failed.", "0x%" PFMT64x);

	mu_end;
}

/**
 * \brief Examples partially taken from: https://en.wikipedia.org/wiki/UTF-16#Examples
 */
bool test_rz_utf16_encode(void) {
	ut8 utf16_out[5] = { 0 };

	const ut8 utf16le[] = { 0xAC, 0x20 };
	RzCodePoint codepoint = 0x20AC;
	int nbytes = rz_utf16le_encode(utf16_out, codepoint);
	mu_assert_eq(nbytes, 2, "Decoded number of bytes mismatch.");
	mu_assert_memeq(utf16_out, utf16le, sizeof(utf16le), "Encode failed.");
	memset(utf16_out, 0, sizeof(utf16_out));

	// With surrogate
	const ut8 utf16le_surr[] = { 0x01, 0xD8, 0x37, 0xDC };
	codepoint = 0x10437;
	nbytes = rz_utf16le_encode(utf16_out, codepoint);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_memeq(utf16_out, utf16le_surr, sizeof(utf16le), "Encode failed.");
	memset(utf16_out, 0, sizeof(utf16_out));

	const ut8 utf16le_first_surr[] = { 0x00, 0xD8, 0x00, 0xDC };
	codepoint = 0x10000;
	nbytes = rz_utf16le_encode(utf16_out, codepoint);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_memeq(utf16_out, utf16le_first_surr, sizeof(utf16le), "Encode failed.");
	memset(utf16_out, 0, sizeof(utf16_out));

	const ut8 utf16le_last_surr[] = { 0xFF, 0xDB, 0xFF, 0xDF };
	codepoint = 0x10FFFF;
	nbytes = rz_utf16le_encode(utf16_out, codepoint);
	mu_assert_eq(nbytes, 4, "Decoded number of bytes mismatch.");
	mu_assert_memeq(utf16_out, utf16le_last_surr, sizeof(utf16le), "Encode failed.");
	memset(utf16_out, 0, sizeof(utf16_out));

	ut8 zero[5] = { 0 };
	codepoint = 0x110000;
	nbytes = rz_utf16le_encode(utf16_out, codepoint);
	mu_assert_eq(nbytes, 0, "Decoded number of bytes mismatch.");
	mu_assert_memeq(utf16_out, zero, sizeof(utf16le), "Encode failed.");

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

	mu_assert_false(rz_utf32_valid_cp(utf32le_invalid_size, sizeof(utf32le_invalid_size), false), "Length check failed");

	mu_assert_false(rz_utf32_valid_cp(utf32be_invalid_max_cp, sizeof(utf32be_invalid_max_cp), true), "Invalid max failed");
	mu_assert_true(rz_utf32_valid_cp(utf32be_valid_max_cp, sizeof(utf32be_valid_max_cp), true), "Valid max failed");

	mu_assert_false(rz_utf32_valid_cp(utf32le_invalid_max_cp, sizeof(utf32le_invalid_max_cp), false), "Invalid max failed");
	mu_assert_true(rz_utf32_valid_cp(utf32le_valid_max_cp, sizeof(utf32le_valid_max_cp), false), "Valid max failed");

	mu_assert_false(rz_utf32_valid_cp(utf32be_invalid_surrogate_I, sizeof(utf32be_invalid_surrogate_I), true), "Surrogate failed");
	mu_assert_false(rz_utf32_valid_cp(utf32be_invalid_surrogate_II, sizeof(utf32be_invalid_surrogate_II), true), "Surrogate failed");
	mu_assert_true(rz_utf32_valid_cp(utf32be_invalid_surrogate_III, sizeof(utf32be_invalid_surrogate_III), true), "Surrogate failed");
	mu_assert_true(rz_utf32_valid_cp(utf32be_invalid_surrogate_IV, sizeof(utf32be_invalid_surrogate_IV), true), "Surrogate failed");

	mu_end;
}


bool test_rz_ebcdic_valid(void) {
	// General
	mu_assert_true(rz_str_ebcdic_valid_cp(0x41), "A should be valid.");
	mu_assert_true(rz_str_ebcdic_valid_cp(0), "\\0 should be valid.");
	// EBCDIC-ES
	mu_assert_true(rz_str_ebcdic_valid_cp(0xf1), "ñ should be valid.");
	// EBCDIC-US
	mu_assert_true(rz_str_ebcdic_valid_cp(0xa2), "¢ should be valid.");
	// EBCDIC-UK
	mu_assert_true(rz_str_ebcdic_valid_cp(0xa3), "£ should be valid.");
	// IBM037
	mu_assert_true(rz_str_ebcdic_valid_cp(0xe4), "ä should be valid.");
	// IBM290
	mu_assert_true(rz_str_ebcdic_valid_cp(0x30a5), "ゥshould be valid.");

	// An unsopported one.
	mu_assert_false(rz_str_ebcdic_valid_cp(0x1E4E), "Ṏ should not be valid.");

	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_utf16_decode);
	mu_run_test(test_rz_utf16_encode);
	mu_run_test(test_rz_utf32_valid);
	mu_run_test(test_rz_ebcdic_valid);

	return tests_passed != tests_run;
}

mu_main(all_tests)
