// SPDX-FileCopyrightText: 2025 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"
#include "rz_util/rz_utf8.h"

/**
 * \brief Examples partially taken from: https://en.wikipedia.org/wiki/UTF-16#Examples
 */
bool test_rz_utf16_decode_encode(void) {
	char utf8_out[5] = { 0 };
	RzRune codepoint = 0;
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

	nbytes = rz_utf16_decode(utf16le_invalid_small_surr, 4, &codepoint, false);
	mu_assert_eq(nbytes, 0, "Decoded number of bytes mismatch.");
	nbytes = rz_utf16_decode(utf16be_invalid_small_surr, 4, &codepoint, true);
	mu_assert_eq(nbytes, 0, "Decoded number of bytes mismatch.");

	const ut8 utf16le_invalid_big_surr[] = { 0x01, 0xDC, 0x37, 0xE0 };
	const ut8 utf16be_invalid_big_surr[] = { 0xDC, 0x01, 0xE0, 0x37 };

	nbytes = rz_utf16_decode(utf16le_invalid_big_surr, 4, &codepoint, false);
	mu_assert_eq(nbytes, 0, "Decoded number of bytes mismatch.");
	nbytes = rz_utf16_decode(utf16be_invalid_big_surr, 4, &codepoint, true);
	mu_assert_eq(nbytes, 0, "Decoded number of bytes mismatch.");

	const ut8 utf16le_invalid[] = { 0xff, 0xff, 0xff, 0xff };
	const ut8 utf16be_invalid[] = { 0xff, 0xff, 0xff, 0xff };

	nbytes = rz_utf16_decode(utf16le_invalid, 4, &codepoint, false);
	mu_assert_eq(nbytes, 0, "Decoded number of bytes mismatch.");
	nbytes = rz_utf16_decode(utf16be_invalid, 4, &codepoint, true);
	mu_assert_eq(nbytes, 0, "Decoded number of bytes mismatch.");

	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_utf16_decode_encode);

	return tests_passed != tests_run;
}

mu_main(all_tests)
