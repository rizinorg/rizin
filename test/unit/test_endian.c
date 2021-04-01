// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_io.h>
#include <stdlib.h>
#include "minunit.h"

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

int all_tests() {
	mu_run_test(test_be);
	mu_run_test(test_le);
	mu_run_test(test_me);
	return tests_passed != tests_run;
}

mu_main(all_tests)