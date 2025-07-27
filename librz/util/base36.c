// SPDX-FileCopyrightText: 2014-2020 abcSup <zifan.tan@gmail.com>
// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim <a.ibrahim8686@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Base36 encoding and decoding functions.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rz_types_base.h>
#include <rz_util.h>

#define RZ_BASE36_BUFSZ 13

// Constants to convert ASCII to its base36 value
static const char d32[] = "[\\]^_`abcd$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$efghijklmnopqrstuvwxyz{|}~";

// The powers of 36 up to the 13th for 64-bit values
static const ut64 pow36[] = { 1, 36, 1296, 46656, 1679616, 60466176, 2176782336,
	78364164096, 2821109907456, 101559956668416, 3656158440062976,
	131621703842267136, 4738381338321616896 };

/**
 * \brief Dynamically allocate and return the Base 36 representation of a 64‑bit value.
 *
 * \param val  The unsigned 64‑bit integer to encode.
 * \return     Pointer to a freshly allocated, NUL‑terminated digit string,
 *             or \c NULL if memory allocation fails.
 *
 * The caller \b must free the returned buffer with \c free().
 *
 */
RZ_API RZ_OWN char *rz_base36_encode_dyn(ut64 val) {
	static const char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyz";

	char tmp[RZ_BASE36_BUFSZ] = { 0 };
	size_t n = 0;

	if (val == 0) {
		tmp[n++] = '0';
	} else {
		while (val && n < RZ_BASE36_BUFSZ) {
			tmp[n++] = alphabet[val % 36];
			val /= 36;
		}
	}

	char *out = (char *)malloc(n + 1);
	if (!out) {
		return NULL;
	}
	for (size_t i = 0; i < n; i++) {
		out[i] = tmp[n - 1 - i];
	}
	out[n] = '\0';
	return out;
}

/**
 * \brief Convert an ASCII Base 36 string to a 64‑bit unsigned integer.
 *
 * \param[in]  str  Pointer to the digit sequence (no NUL required).
 * \param      len  Number of characters in \p str.
 *                  A value greater than 13 implies overflow and is rejected.
 * \return The decoded value, or \c -1 on any error (invalid digit, overflow,
 *         or length > 13).
 *
 * The function treats the right‑most character as the least‑significant digit,
 * multiplies each digit by the corresponding 36‑power from \a pow36, and
 * accumulates the result.
 * Digits are validated in constant time with the lookup table \a d32.  When
 * processing the most‑significant position (index 12) the function performs an
 * explicit overflow check: the digit must be ≤ 3 and the addition
 * <code>ret + v × pow36[12]</code> must not wrap.
 */
RZ_API st64 rz_base36_decode(RZ_NULLABLE const char *str, const size_t len) {
	ut64 ret = 0;
	size_t i;
	// 64-bit base36 str has at most 13 characters
	if (len > RZ_BASE36_BUFSZ) {
		RZ_LOG_ERROR("base36_decode supports up to 64-bit values only\n");
		return -1;
	}
	for (i = 0; i < len; i++) {
		char c = str[len - i - 1];
		// "01234567890abcdefghijklmnopqrstuvwxyz"
		if (c < '0' || c > 'z' || ('9' < c && c < 'a')) {
			RZ_LOG_ERROR("%s is not a valid base36 encoded string\n", str);
			return -1;
		}
		ut8 v = d32[c - '0'];
		// Character does not exist in base36 encoding
		if (v == '$') {
			RZ_LOG_ERROR("Error: %s is not a valid base36 encoded string\n", str);
			return -1;
		}
		v -= 91;
		// Check for overflow
		if (i == 12) {
			if (v > 3 || UT64_ADD_OVFCHK(ret, v * pow36[i])) {
				RZ_LOG_ERROR("Error: base36_decode supports up to 64-bit values only\n");
				return -1;
			}
		}
		ret += v * pow36[i];
	}
	return ret;
}
