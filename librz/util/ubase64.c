// SPDX-FileCopyrightText: 2023 Nikolaos Chatzikonstantinou <nchatz314@gmail.com>
// SPDX-FileCopyrightText: 2017-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Base64 encoding and decoding functions.
 *
 * Functions for encoding and decoding Base64 are provided. The
 * dynamic verions allocate and return the result, while the others
 * write to the provided buffer. The Base64 encoding and decoding
 * algorithms are described in RFC 4648.
 *
 * The encoder produces canonical encodings and the decoder accepts
 * non-canonical encodings by ignoring padding characters. Newlines in
 * the encoding are rejected.
 *
 * The decoding functions work for code pages that superset ASCII in
 * the lower 128 characters.
 */

/* Original code from:
 * dmc - dynamic mail client -- author: pancake
 * See LICENSE file for copyright and license details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rz_types_base.h>
#include <rz_util.h>

/** \internal
 * \brief Table for mapping 6-bit index to symbol.
 */
static const char cb64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** \internal
 * \brief Function for mapping symbol to 6-bit index.
 */
static size_t cd64(int c) {
	if (isdigit(c)) {
		return 52 + c - '0';
	} else if (c >= 'A' && c <= 'Z') {
		return c - 'A';
	} else if (c >= 'a' && c <= 'z') {
		return 26 + c - 'a';
	} else if (c == '+') {
		return 62;
	} else if (c == '/') {
		return 63;
	}
	return SIZE_MAX;
}

/** \internal
 * \brief Base64 encode a single input group.
 * \param[in] src The input group to encode.
 * \param[out] dest The buffer in which the encoded base64 is placed.
 *
 * This function works on an input group of exactly 3 characters. If
 * the final group is less than 3 characters, it must be padded with
 * the \c '=' character before this function is used. The encoded
 * output will be exactly 4 characters.
 */
static void pack_to6(ut8 dest[4], const ut8 src[3]) {
	/* The operation '& 0x3f' keeps the 6 least significant bits. */
	dest[0] = cb64[(src[0] >> 2) & 0x3f];
	dest[1] = cb64[((src[0] << 4) & 0x3f) | src[1] >> 4];
	dest[2] = cb64[((src[1] << 2) & 0x3f) | src[2] >> 6];
	dest[3] = cb64[(src[2] << 0) & 0x3f];
}

/** \internal
 * \brief Decode a single base64-output group.
 * \param[in] src The encoded group of octets to decode.
 * \param[out] dest The decoded group of octets.
 *
 * This function works on a encoded group of exactly 4 characters. The
 * decoded output will be exactly 3 bytes.
 */
static void unpack_from6(ut8 dest[3], const ut8 src[4]) {
	ut8 idx[4];
	size_t i;
	for (i = 0; i < 4; i++) {
		idx[i] = cd64(src[i]);
	}
	dest[0] = idx[0] << 2 | idx[1] >> 4;
	dest[1] = idx[1] << 4 | idx[2] >> 2;
	dest[2] = idx[2] << 6 | idx[3] >> 0;
}

/** \internal
 * \brief Validating Base64 characters.
 * \parameter c The character to validate.
 *
 * The function returns \c true if the character is inside the ranges
 * \c a-z, \c A-Z, or \c 0-9, or one of \c +, or \c /, and otherwise
 * returns \false.
 */
static bool is_base64(int c) {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || isdigit(c) ||
		c == '+' || c == '/';
}

/** \internal
 * \brief Calculate the length of \p src.
 * \param[in] src The binary data to be Base64-encoded later.
 * \param len The length of the binary data in bytes.
 *
 * This function returns \p len as it is unless it is negative, in
 * which case, it returns the string length of \p src. A possibility
 * of a string size larger than \c ST64_MAX requires us to make a
 * bounds check, and error if overflow is possible. This function is
 * provided in lieu of modifying the decoding API parameter list.
 */
static st64 calculate_src_length(const char *src, st64 len) {
	size_t real_len;
	if (len < 0) {
		real_len = strlen(src);
		if (ST64_MAX < real_len) {
			return -1;
		}
		len = (st64)real_len;
	}
	return len;
}

/** \internal
 * \brief Calculate the length in bytes of the Base64-encoded result.
 * \param[in] src The binary data to be Base64-encoded later.
 * \param len The length of the binary data in bytes.
 *
 * For every three-byte group we have a four-byte group output. The
 * naive formula suggests \c 4*(len/3). The order of operations
 * matters due to integral division in C taking the integer part of
 * the quotient, and in particular because the inequality
 * \f$\operatorname{floor}(a)*\operatorname{floor}(b) \leq
 * \operatorname{floor}(a*b)\f$ holds for any two positive real
 * numbers \f$a, b\f$ in mathematics (We want the left-hand side
 * because the right-hand side is an overestimate.)
 *
 * We add an additional \c 2 to \p len before using the above formula
 * to account for an entire additional final output group despite a
 * (potentially) incomplete final input group.
 */
static size_t calculate_dest_length(const ut8 *src, size_t len) {
	return 4 * ((len + 2) / 3);
}

/**
 * \brief Base64-encode binary data.
 * \param[out] dest The encoded output.
 * \param[in] src The binary data.
 * \param n The length of the binary data in bytes.
 * \return The length of the encoded output, excluding the NUL byte.
 * \attention The \p dest parameter should have sufficient space to
 * accomodate the encoded output, including the terminating NUL
 * byte. In particular, it should have at least \c 1+4*((n+2)/3) bytes
 * available.
 *
 * Base64-encode binary data. The encoded output is stored in \p dest,
 * together with a NUL byte signifying the end of the string. The
 * encoding is canonical as defined by RFC 4648, which means that the
 * data is padded by zero bits, until it is a whole multiple of 24
 * bits, before being encoded.
 *
 * If either \p dest or \p src is \c NULL, nothing is done and the
 * value \c 0 is returned.
 *
 * # Example
 *
 * \code{.c}
 * const ut8 msg[] = "Hello, world!";
 * size_t msg_len = strlen(msg);
 * size_t enc_len = 4 * ((msg_len + 2) / 3);
 * char *enc = malloc(enc_len + 1); // +1 for NUL byte
 * if (enc == NULL) { goto memory_error; }
 * rz_base64_encode(enc, msg, msg_len);
 * assert(strcmp(enc, "SGVsbG8sIHdvcmxkIQ==") == 0);
 * free(enc);
 * \endcode
 */
RZ_API size_t rz_base64_encode(RZ_OUT RZ_NULLABLE char *dest, RZ_NULLABLE const ut8 *src, size_t n) {
	ut8 final_group[3] = { 0 };
	size_t ret;
	rz_return_val_if_fail(src, 0);
	rz_return_val_if_fail(dest, 0);
	ret = calculate_dest_length(src, n);
	while (n >= 3) {
		pack_to6((ut8 *)dest, src);
		src += 3;
		dest += 4;
		n -= 3;
	}
	if (n == 1) {
		final_group[0] = src[0];
		pack_to6((ut8 *)dest, final_group);
		dest[2] = dest[3] = '=';
		dest += 4;
	} else if (n == 2) {
		final_group[0] = src[0];
		final_group[1] = src[1];
		pack_to6((ut8 *)dest, final_group);
		dest[3] = '=';
		dest += 4;
	}
	dest[0] = '\0'; // NUL byte terminator
	return ret;
}

/**
 * \brief Base64-encode binary data.
 * \param[in] src The binary data to encode.
 * \param n The length of the binary data in bytes.
 * \return The dynamically allocated Base64-encoding.
 *
 * This function dynamically allocates a buffer in which to store the
 * Base64-encoding. The return value will either be \c NULL in case of
 * a memory allocation error or the encoding, which must then be freed
 * when no longer needed.
 *
 * If the parameter \p src is \c NULL, nothing is done and the value
 * \c NULL is returned.
 *
 * # Example
 *
 * \code{.c}
 * const ut8 foo[] = "foo";
 * const ut8 bin[] = { 0x00, 0x01, 0x02, 0x03 };
 * // Base64-encode textual data.
 * char *foo_enc = rz_base64_encode_dyn(foo, strlen(foo));
 * if(foo_enc == NULL) { goto memory_error; }
 * assert(strcmp(foo_enc, "Zm9v") == 0);
 * ut8 *foo_dec = rz_base64_decode_dyn(foo_enc, -1);
 * if(foo_dec == NULL) { goto memory_error; }
 * assert(strcmp(foo_dec, foo) == 0);
 * // Base64-encode binary data.
 * char *bin_enc = rz_base64_encode_dyn(bin, sizeof bin);
 * if(bin_enc == NULL) { goto memory_error; }
 * assert(strcmp(bin_enc, "AAECAw==") == 0);
 * ut8 *bin_dec = rz_base64_decode_dyn(bin_enc, strlen(bin_enc));
 * if(bin_dec == NULL) { goto memory_error; }
 * assert(memcmp(bin_dec, bin, sizeof bin) == 0);
 * // It's important to free all resources after use!
 * free(foo_enc);
 * free(foo_dec);
 * free(bin_enc);
 * free(bin_dec);
 * \endcode
 */
RZ_API RZ_OWN char *rz_base64_encode_dyn(RZ_NULLABLE const ut8 *src, size_t n) {
	size_t ret_size;
	char *ret;
	rz_return_val_if_fail(src, NULL);
	ret_size = 1 + calculate_dest_length(src, n);
	ret = malloc(ret_size);
	if (ret) {
		(void)rz_base64_encode(ret, src, n);
	}
	return ret;
}

/**
 * \brief Decode a Base64-encoded message.
 * \param[out] dest The decoded output.
 * \param[in] src The Base64-encoded message.
 * \param n The length of the encoded message.
 * \return The length of the decoded message, excluding the NUL byte.
 * \attention The \p dest parameter should have sufficient space to
 * accomodate the decoded output, including the NUL byte. In
 * particular, it should have at least \c 1+(3*(n+1))/4 bytes
 * available, although an exact computation of the space size can be
 * obtained (if desired by the user) by counting the non-ignored
 * characters in the encoding before applying the size formula.
 *
 * Decode a base64-encoded message. The \p n parameter may be
 * negative, in which case \p src is treated as a C string and its
 * string length is calculated. The decoded output is stored in \p
 * dest, and will be NUL byte terminated.
 *
 * This decoder is lax in its acceptance of invalid character values;
 * apart from the values ranging below \c 43 or above \c 122, all
 * others are accepted, but ignored if invalid. The final padding
 * character \c '=', which in a canonical encoding will appear once or
 * twice, is not required to appear,
 *
 * If either \p dest or \p src is \c NULL, nothing is done and the
 * value \c 0 is returned.
 *
 * The return value is \c -1 in the following cases:
 *
 * - the characters in \p src were rejected because their value was
 *   below \c 43 or above \c 122,
 * - the parameter \p n was \c -1 and the length of the string in \p
 *   src exceeds \c ST64_MAX.
 *
 * # Example
 *
 * \code{.c}
 * const char enc[] = "QQ==";
 * size_t enc_len = strlen(enc);
 * size_t msg_len_bound = 3*(enc/4);
 * ut8 *msg = malloc(msg_len_bound + 1); // +1 for NUL byte
 * if (msg == NULL) { goto memory_error; }
 * rz_base64_decode(msg, enc, enc_len);
 * assert(strcmp(msg, "A") == 0);
 * free(msg);
 * \endcode
 */
RZ_API st64 rz_base64_decode(RZ_OUT RZ_NULLABLE ut8 *dest, RZ_NULLABLE const char *src, st64 n) {
	char buf[4], tmp[3];
	int c;
	size_t i, j;
	st64 ret = 0;
	rz_return_val_if_fail(src, 0);
	rz_return_val_if_fail(dest, 0);
	n = calculate_src_length(src, n);
	if (n == -1) {
		return -1;
	}
	for (i = j = 0; i < n; i++) {
		c = src[i];
		if (is_base64(c)) {
			buf[j++] = c;
			// the j counter is reset every 4 bytes
			if (j == 4) {
				j = 0;
				ret += 3;
				unpack_from6((ut8 *)dest, (const ut8 *)buf);
				dest += 3;
			}
		} else if (c < 43 || c > 122) {
			// rejected Base64 characters
			return -1;
		}
	}
	if (j == 0) {
		dest[0] = '\0';
		return ret;
	} else if (j == 1) {
		return -1;
	} else if (j == 2) {
		buf[2] = buf[3] = 0;
		unpack_from6((ut8 *)tmp, (const ut8 *)buf);
		dest[0] = tmp[0];
		dest[1] = '\0';
		return ret + 1;
	}
	/* j == 3 */
	buf[3] = 0;
	unpack_from6((ut8 *)tmp, (const ut8 *)buf);
	dest[0] = tmp[0];
	dest[1] = tmp[1];
	dest[2] = '\0';
	return ret + 2;
}

/**
 * \brief Decode a Base64-encoded message.
 * \param[in] src The encoded message to decode.
 * \param n The length of the encoded message.
 * \return The dynamically-allocated decoded binary-data.
 *
 * This function dynamically allocates a buffer in which to store the
 * decoded binary data. The return value will either be \c NULL the
 * decoding, which must then be freed when no longer needed. The
 * decoding will be NUL byte terminated.
 *
 * The parameter \p len may be equal to \c -1, in which case the \p
 * src is treated as a C-string, and it is decoded across its length.
 *
 * There are three cases in which \c NULL is returned:
 *
 * - in case of a memory allocation error,
 * - in case \p len is equal to \c -1 and \p src is longer than \c
 *   ST64_MAX,
 * - if \p src is \c NULL.
 *
 * It is not necessary that this function fails in case of the integer
 * overflow error, however it is done for consistency with the
 * behavior of \a rz_base64_decode.
 *
 * If the parameter \p src is \c NULL, nothing is done and the value
 * \c NULL is returned.
 *
 * # Example
 *
 * See \a rz_base64_encode_dyn for an example.
 */
RZ_API RZ_OWN ut8 *rz_base64_decode_dyn(RZ_NULLABLE const char *src, st64 len) {
	ut8 *ret, *tmp;
	st64 ret_size;
	rz_return_val_if_fail(src, NULL);
	len = calculate_src_length(src, len);
	if (len < 0) {
		return NULL;
	}
	// calculate 1 + (3*(len+1))/4 but avoid integer overflow
	ret_size = 1 + 3 * (len / 4) + (3 * (len % 4 + 1)) / 4;
	ret = malloc((size_t)ret_size);
	if (!ret) {
		return NULL;
	}
	if ((ret_size = rz_base64_decode(ret, src, len)) == -1) {
		free(ret);
		return NULL;
	}
	ret_size += 1; // include NUL byte
	// we attempt to minimize memory usage
	if ((tmp = realloc(ret, ret_size)) != NULL) {
		return tmp;
	}
	return ret;
}
