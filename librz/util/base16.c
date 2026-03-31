// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim <a.ibrahim8686@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Base16 encoding and decoding functions
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rz_types_base.h>
#include <rz_util.h>

/** \internal
 * \brief Calculate the length of \p src.
 * \param[in] src The binary data to be Base16-encoded later.
 * \param len The length of the binary data in bytes.
 *
 * This function returns \p len as it is unless it is negative, in
 * which case, it returns the string length of \p src. A possibility
 * of a string size larger than \c ST64_MAX requires us to make a
 * bounds check, and error if overflow is possible. This function is
 * provided in lieu of modifying the decoding API parameter list.
 */
static st64 calculate_src_length(const char *src, st64 len) {
	if (len >= 0)
		return len;
	size_t real_len = strlen(src);
	if (ST64_MAX < real_len) {
		return -1;
	}
	return (st64)real_len;
}

/**
 * \brief Base-16-encode binary data.
 * \param[out] dest Buffer to receive NUL-terminated encoded output.
 *                  Must have at least \c (2 × n) + 1 bytes.
 * \param[in]  src  Pointer to the binary input.
 * \param[in]  n    Number of bytes in \p src.
 * \return Number of characters written (excluding the NUL terminator),
 *         or \c 0 if parameters are invalid.
 *
 * This function converts each input byte to two lowercase hexadecimal
 * characters using \c rz_hex_bin2str().
 */
RZ_API int rz_base16_encode(RZ_OUT RZ_NONNULL char *dest, RZ_NONNULL const ut8 *src, size_t n) {
	rz_return_val_if_fail(src && dest, 0);
	if (rz_hex_bin2str(src, (int)n, dest) == 0) {
		return 0;
	}
	return n * 2;
}

/**
 * \brief Dynamically allocate and fill a Base-16-encoded string.
 * \param[in] src Pointer to the binary input.
 * \param[in] n   Number of bytes in \p src.
 * \return Pointer to a NUL-terminated Base-16 string allocated with
 *         \c malloc, or \c NULL if allocation fails or \p src is \c NULL.
 *         Caller must \c free() the returned pointer.
 *
 * Allocates exactly \c (2 × n) + 1 bytes, encodes the input, and NUL-terminates.
 */
RZ_API RZ_OWN char *rz_base16_encode_dyn(RZ_NONNULL const ut8 *src, size_t n) {
	rz_return_val_if_fail(src, NULL);
	char *out = (char *)malloc(2 * n + 1);
	if (!out) {
		return NULL;
	}
	if (rz_base16_encode(out, src, n) == 0) {
		return NULL;
	}
	return out;
}

/**
 * \brief Decode a Base-16 string into binary form.
 * \param[out] dest Output buffer for decoded bytes.
 *                  Must have at least (\c strlen(src) / 2) + 1 bytes.
 * \param[in]  src  NUL-terminated Base-16 string.
 * \return Number of decoded bytes on success,
 *         or a negative value if an odd number of nibbles was parsed,
 *         or \c 0 if parameters are invalid.
 *
 * This is a thin wrapper around \c rz_hex_str2bin().
 * Output is **not** automatically NUL-terminated unless you add it yourself.
 */
RZ_API int rz_base16_decode(RZ_OUT RZ_NONNULL ut8 *dest, RZ_NONNULL const char *src) {
	rz_return_val_if_fail(src && dest, 0);

	int out_len = rz_hex_str2bin(src, dest);
	if (out_len < 0) {
		// Odd number of nibbles — still terminate after absolute length
		dest[-out_len] = '\0';
		return out_len;
	}

	// NUL terminate after the decoded bytes
	dest[out_len] = '\0';
	return out_len;
}

/**
 * \brief Dynamically decode a Base-16 string into binary form.
 * \param[in]  src NUL-terminated Base-16 string to decode.
 * \param[in]  len Length of \p src in characters, or \c -1 to use \c strlen().
 * \return Pointer to a newly allocated buffer containing the decoded
 *         binary data followed by a NUL byte, or \c NULL on error.
 *
 * Accepts even or odd numbers of hex digits. For odd lengths, the final
 * nibble is padded with zero.
 */
RZ_API RZ_OWN ut8 *rz_base16_decode_dyn(RZ_NONNULL const char *src, st64 len) {
	rz_return_val_if_fail(src, NULL);

	len = calculate_src_length(src, len);
	if (len < 0) {
		return NULL;
	}

	st64 cap = (len / 2) + 1;
	ut8 *buf = (ut8 *)malloc((size_t)cap);
	if (!buf) {
		return NULL;
	}

	st64 out_len = rz_base16_decode(buf, src);
	if (out_len == 0) { // truly invalid hex
		free(buf);
		return NULL;
	}
	if (out_len < 0) { // odd nibble count — still valid, pad added
		out_len = -out_len;
	}

	buf[out_len] = '\0';
	if (out_len + 1 < cap) {
		ut8 *tmp = (ut8 *)realloc(buf, (size_t)out_len + 1);
		if (tmp) {
			buf = tmp;
		}
	}
	return buf;
}
