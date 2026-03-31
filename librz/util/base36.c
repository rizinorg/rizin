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
 * \brief Encode a 64-bit unsigned integer as a Base 36 digit string.
 *
 * \param[out] bout Buffer to receive the NUL-terminated encoded output.
 *                  Must have at least \c RZ_BASE36_BUFSZ bytes (\c 13 characters plus the terminator).
 * \param      val  The unsigned 64-bit integer to encode.
 * \return Number of characters written (excluding the NUL terminator), or \c 0 if \p bout is \c NULL.
 *
 * This function converts \p val to its lowercase Base 36 representation,
 * writing the result to \p bout followed by a NUL terminator.
 * The most-significant digit appears first in the output.
 */
RZ_API size_t rz_base36_encode(RZ_OUT RZ_NONNULL char *bout, ut64 val) {
	rz_return_val_if_fail(bout, 0);
	static const char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	char tmp[RZ_BASE36_BUFSZ];
	size_t n = 0;

	if (val == 0) {
		tmp[n++] = '0';
	} else {
		while (val && n < RZ_BASE36_BUFSZ) {
			tmp[n++] = alphabet[val % 36];
			val /= 36;
		}
	}

	// reverse into output buffer
	for (size_t i = 0; i < n; i++) {
		bout[i] = tmp[n - 1 - i];
	}
	bout[n] = '\0';
	return n;
}

/**
 * \brief Dynamically allocate and return the Base 36 representation of a 64‑bit value.
 *
 * \param val  The unsigned 64‑bit integer to encode.
 * \return     Pointer to a freshly allocated, NUL‑terminated digit string,
 *             or \c NULL if memory allocation fails.
 */
RZ_API RZ_OWN char *rz_base36_encode_dyn(ut64 val) {
	char *out = (char *)malloc(RZ_BASE36_BUFSZ + 1);
	if (!out) {
		return NULL;
	}
	if (rz_base36_encode(out, val) == 0) {
		free(out);
		return NULL;
	}
	return out;
}

/**
 * \brief Decode a Base36 string into a 64-bit unsigned integer.
 *
 * \param[out] bout Pointer to a ut64 that will receive the decoded value.
 * \param[in]  bin  Input Base36-encoded string (not necessarily NUL-terminated).
 * \param[in]  len  Length of the Base36 string.
 * \return Number of characters consumed on success, or -1 on error.
 *
 * This function decodes the given Base36 string \p bin of length \p len into
 * a 64-bit unsigned integer. The maximum supported length is
 * \c RZ_BASE36_BUFSZ (13 characters). Input is case-sensitive and only
 * lowercase 'a'–'z' and '0'–'9' are accepted.
 */
RZ_API st64 rz_base36_decode(RZ_OUT RZ_NONNULL ut64 *bout, RZ_NONNULL const char *bin, st64 len) {
	rz_return_val_if_fail(bin && bout, -1);
	size_t i;
	// 64-bit base36 str has at most 13 characters
	if (len > RZ_BASE36_BUFSZ) {
		RZ_LOG_ERROR("base36_decode supports up to 64-bit values only\n");
		return -1;
	}
	for (i = 0; i < len; i++) {
		char c = bin[len - i - 1];
		// "01234567890abcdefghijklmnopqrstuvwxyz"
		if (c < '0' || c > 'z' || ('9' < c && c < 'a')) {
			RZ_LOG_ERROR("%s is not a valid base36 encoded string\n", bin);
			return -1;
		}
		ut8 v = d32[c - '0'];
		// Character does not exist in base36 encoding
		if (v == '$') {
			RZ_LOG_ERROR("Error: %s is not a valid base36 encoded string\n", bin);
			return -1;
		}
		v -= 91;
		// Check for overflow
		if (i == 12) {
			if (v > 3 || UT64_ADD_OVFCHK(*bout, v * pow36[i])) {
				RZ_LOG_ERROR("Error: base36_decode supports up to 64-bit values only\n");
				return -1;
			}
		}
		*bout += v * pow36[i];
	}
	return i;
}

/**
 * \brief Decode a Base36 string into a newly allocated 64-bit integer.
 *
 * \param[in] bin Base36-encoded string (not necessarily NUL-terminated).
 * \param[in] len Length of the string.
 * \return A newly allocated \c ut64* holding the decoded value,
 *         or \c NULL on error.
 */
RZ_API RZ_OWN ut64 *rz_base36_decode_dyn(RZ_NONNULL const char *bin, const size_t len) {
	rz_return_val_if_fail(bin, NULL);
	ut64 *out = RZ_NEW0(ut64);
	if (!out) {
		return NULL;
	}

	if (rz_base36_decode(out, bin, (st64)len) < 0) {
		free(out);
		return NULL;
	}

	return out;
}
