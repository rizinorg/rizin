// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim <a.ibrahim8686@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Base32 encoding and decoding functions
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rz_types_base.h>
#include <rz_util.h>

/** \internal
 * \brief Table for mapping a 5‑bit value (0 – 31) to its Base‑32 symbol.
 */
static const char cb32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** \internal
 * \brief Map a Base‑32 symbol to its 5‑bit index (0 – 31).
 */
static size_t cd32(int c) {
	if (c >= 'A' && c <= 'Z') {
		return (size_t)(c - 'A');
	}
	if (c >= 'a' && c <= 'z') {
		return (size_t)(c - 'a');
	}
	if (c >= '2' && c <= '7') {
		return (size_t)(26 + (c - '2'));
	}
	return SIZE_MAX;
}

/** \internal
 * \brief Base‑32 encode one 40‑bit (5‑byte) block.
 * \param[in]  src   Five input bytes.
 * \param[out] dest  Eight‑character output (no padding chars).
 *
 * The caller must pad any partial final block with zeros *before*
 * invoking this function; the encoder later converts the surplus
 * characters to ‘=’ if RFC‑4648 padding is desired.
 */
static void pack_to5(ut8 dest[8], const ut8 src[5]) {
	/* Each line extracts a 5‑bit group from the 40‑bit stream */
	dest[0] = cb32[(src[0] >> 3) & 0x1F];
	dest[1] = cb32[((src[0] << 2) | (src[1] >> 6)) & 0x1F];
	dest[2] = cb32[(src[1] >> 1) & 0x1F];
	dest[3] = cb32[((src[1] << 4) | (src[2] >> 4)) & 0x1F];
	dest[4] = cb32[((src[2] << 1) | (src[3] >> 7)) & 0x1F];
	dest[5] = cb32[(src[3] >> 2) & 0x1F];
	dest[6] = cb32[((src[3] << 3) | (src[4] >> 5)) & 0x1F];
	dest[7] = cb32[src[4] & 0x1F];
}

/** \internal
 * \brief Decode a single base32-output group.
 * \param[in] src The encoded group of 8 base32 characters.
 * \param[out] dest The decoded group of 5 binary bytes.
 *
 * This function operates on a group of exactly 8 base32 symbols and
 * reconstructs the original 5 input bytes (8 × 5 = 40 bits = 5 × 8).
 */
static void unpack_from5(ut8 dest[5], const ut8 src[8]) {
	ut8 idx[8];
	size_t i;
	for (i = 0; i < 8; i++) {
		idx[i] = cd32(src[i]);
	}
	dest[0] = (idx[0] << 3) | (idx[1] >> 2);
	dest[1] = (idx[1] << 6) | (idx[2] << 1) | (idx[3] >> 4);
	dest[2] = (idx[3] << 4) | (idx[4] >> 1);
	dest[3] = (idx[4] << 7) | (idx[5] << 2) | (idx[6] >> 3);
	dest[4] = (idx[6] << 5) | (idx[7] >> 0);
}

/** \internal
 * \brief Validate a Base‑32 character.
 * \param c  The character to examine (promoted to \c int by the caller).
 *
 * The function returns true in case:
 * - an upper‑case letter in the range <code>'A'–'Z'</code>, or
 * - a lower‑case letter in the range <code>'a'–'z'</code> (accepted for
 *   leniency), or
 * - a digit in the range <code>'2'–'7'</code>.
 *
 * Any other value yields \c false.
 */
static inline bool is_base32(int c) {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') || /* allow lower‑case */
		(c >= '2' && c <= '7');
}

/** \internal
 * \brief Calculate the length of \p src.
 * \param[in] src The binary data to be Base32-encoded later.
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
	return real_len;
}

/** \internal
 * \brief Calculate the length, in bytes, of the Base‑32 encoded result.
 * \param      len the length of the binary input in bytes.
 *
 * Base‑32 processes the data in 5‑byte blocks and produces an 8‑character
 * output block for each full 40‑bit chunk.  When the input is not an exact
 * multiple of five bytes, the final (partial) block is still encoded as a
 * *full* 8‑character group, with the surplus characters subsequently replaced
 * by the ‘\c =’ padding symbol to reach the next 8‑byte boundary.
 */
static size_t calculate_dest_length(size_t len) {
	return 8 * ((len + 4) / 5);
}

/**
 * \brief Base32‑encode binary data.
 * \param[out] dest The encoded output.
 * \param[in]  src  The binary input data.
 * \param      n    The length of the binary data in bytes.
 * \return The length of the encoded output, excluding the NUL byte.
 * \attention The \p dest parameter must have enough space to hold the
 * full encoded output, including a terminating NUL byte. In particular,
 * it should reserve at least \c 1 + 8 × ((n + 4)/5) bytes.
 *
 * This function implements canonical Base‑32 encoding as per RFC 4648.
 * The input is padded with zero bits to a full 40‑bit block (5 bytes)
 * if needed. The output is a sequence of 8‑character blocks, padded
 * using the ‘\c =’ character to fill any final incomplete group.
 *
 * If \p dest or \p src is \c NULL, nothing is written and \c 0 is returned.
 *
 * # Example
 * \code{.c}
 * const ut8 msg[] = "Hi!";
 * size_t msg_len = strlen((const char *)msg);
 * size_t enc_len = 8 * ((msg_len + 4) / 5);
 * char *enc = malloc(enc_len + 1); // +1 for NUL byte
 * if (!enc) goto memory_error;
 * rz_base32_encode(enc, msg, msg_len);
 * assert(strcmp(enc, "JBUSC===") == 0);
 * free(enc);
 * \endcode
 */
RZ_API size_t rz_base32_encode(RZ_OUT RZ_NONNULL char *dest, RZ_NONNULL const ut8 *src, size_t n) {
	rz_return_val_if_fail(src && dest, 0);
	ut8 final_group[5] = { 0 };
	size_t ret = calculate_dest_length(n);
	while (n >= 5) {
		pack_to5((ut8 *)dest, src);
		src += 5;
		dest += 8;
		n -= 5;
	}
	if (n > 0) {
		memcpy(final_group, src, n);
		pack_to5((ut8 *)dest, final_group);
		static const ut8 pad_count[5] = { 6, 4, 3, 1 };
		size_t pad = pad_count[n - 1];
		memset(dest + (8 - pad), '=', pad);
		dest += 8;
	}
	dest[0] = '\0';
	return ret;
}

/**
 * \brief Base‑32‑encode binary data and return the result in a newly allocated buffer.
 * \param[in] src  Pointer to the binary data to encode.
 * \param      n   the length of the binary data in bytes.
 * \return A pointer to a NUL‑terminated Base‑32 string allocated with
 *         \c malloc, or \c NULL if \p src is \c NULL or a memory‑allocation
 *         failure occurs.  The caller is responsible for \c free()‑ing the
 *         returned buffer.
 *
 * This function is the Base‑32 analogue of \c rz_base64_encode_dyn.  It first
 * computes the exact output size—\c 1 + 8 × ((n + 4)/5) bytes to accommodate
 * complete 8‑character blocks plus a terminating NUL—allocates that much
 * memory, and then invokes \c rz_base32_encode to fill the buffer.
 *
 * # Example
 * \code{.c}
 * const ut8 plain[] = { 0x48, 0x69 }; // "Hi"
 * char *enc = rz_base32_encode_dyn(plain, sizeof plain);
 * if (!enc) { goto memory_error; }
 * assert(strcmp(enc, "JBUSC===") == 0);
 * free(enc);
 * \endcode
 */
RZ_API RZ_OWN char *rz_base32_encode_dyn(RZ_NONNULL const ut8 *src, size_t n) {
	rz_return_val_if_fail(src, NULL);
	size_t buf_sz = calculate_dest_length(n) + 1;
	char *out = (char *)malloc(buf_sz);
	if (!out) {
		return NULL;
	}
	if (rz_base32_encode(out, src, n) == 0) {
		return NULL;
	}
	out[buf_sz - 1] = '\0';
	return out;
}

/**
 * \brief Decode a Base32-encoded message.
 * \param[out] dest The decoded output.
 * \param[in] src The Base32-encoded message.
 * \param n The length of the encoded message.
 * \return The length of the decoded message, excluding the NUL byte.
 * \attention The \p dest parameter should have sufficient space to
 * accomodate the decoded output, including the NUL byte. In
 * particular, it should have at least \c 1+(5*(n+4))/8 bytes
 * available.
 *
 * Decode a Base32-encoded message. The \p n parameter may be
 * negative, in which case \p src is treated as a C string and its
 * string length is calculated via strlen. The decoded output is stored in \p
 * dest, and will be NUL byte terminated.
 *
 * If either \p dest or \p src is \c NULL, nothing is done and the
 * value \c 0 is returned.
 *
 * The return value is \c -1 in the following cases:
 * - Characters in \p src are rejected as invalid.
 * - The parameter \p n was \c -1 and the string length exceeds \c ST64_MAX.
 *
 * # Example
 *
 * \code{.c}
 * const char *b32 = "MZXW6==="; // "foo"
 * ut8 buf[16];
 * st64 len = rz_base32_decode(buf, b32, -1);
 * assert(len == 3);
 * assert(memcmp(buf, "foo", 3) == 0);
 * \endcode
 */
RZ_API st64 rz_base32_decode(RZ_OUT RZ_NONNULL ut8 *dest, RZ_NONNULL const char *src, st64 n) {
	rz_return_val_if_fail(src && dest, 0);

	char buf[8] = { 0 }, tmp[5] = { 0 };
	int c = 0;
	size_t i = 0, j = 0;
	st64 ret = 0;

	n = calculate_src_length(src, n);
	if (n == -1) {
		return -1;
	}

	for (i = j = 0; i < (size_t)n; i++) {
		c = src[i];
		if (is_base32(c)) {
			buf[j++] = c;
			if (j == 8) {
				j = 0;
				ret += 5;
				unpack_from5((ut8 *)dest, (const ut8 *)buf);
				dest += 5;
			}
		} else if (c == '=') {
			continue;
		} else {
			return -1;
		}
	}

	if (j == 0) {
		dest[0] = '\0';
		return ret;
	} else if (j <= 1) {
		return -1;
	}

	size_t rem = j;
	for (; j < 8; j++) {
		buf[j] = 'A'; // zero padding for partial group
	}
	unpack_from5((ut8 *)tmp, (const ut8 *)buf);
	// decide how many of the unpacked bytes are valid based on how many base32 symbols you originally had.
	static const int rem2bytes[8] = { 0, 0, 1, 0, 2, 3, 0, 4 };
	int bytes = rem2bytes[rem];
	if (bytes == 0) {
		return -1;
	}
	memcpy(dest, tmp, bytes);
	dest[bytes] = '\0';
	return ret + bytes;
}

/**
 * \brief Dynamically decode a Base32‑encoded string.
 * \param[in]  src  Pointer to the Base32 text.
 * \param      len  The length of \p src; pass \c -1 to use \c strlen(src).
 * \return A newly allocated buffer holding the decoded binary data and
 *         terminated with a NUL byte, or \c NULL on error.
 *
 * Memory is obtained with \c malloc and must be released with \c free
 * by the caller.  The function returns \c NULL when:
 *  - \p src is \c NULL,
 *  - a length overflow would exceed \c ST64_MAX,
 *  - a memory allocation fails, or
 *  - the underlying decoder reports malformed input.
 *
 * The worst‑case decoded size for \p len bytes of Base32 is
 * \c 1 + 5 × ((len + 7)/8) bytes (the final “\c 1” is for the NUL terminator).
 * This bound is used to pre‑allocate the buffer and then \c realloc
 * trims it to the exact number of bytes actually produced.
 */
RZ_API RZ_OWN ut8 *rz_base32_decode_dyn(RZ_NONNULL const char *src, st64 len) {
	rz_return_val_if_fail(src, NULL);

	len = calculate_src_length(src, len);
	if (len < 0) {
		return NULL;
	}

	st64 cap = 1 + (5 * ((len + 7) / 8));
	ut8 *buf = (ut8 *)malloc((size_t)cap);
	if (!buf) {
		return NULL;
	}

	st64 out_len = rz_base32_decode(buf, src, len);
	if (out_len < 0) {
		free(buf);
		return NULL;
	}

	/* NUL‑terminate and shrink to fit. */
	buf[out_len] = '\0';
	if (out_len + 1 < cap) {
		ut8 *tmp = (ut8 *)realloc(buf, (size_t)out_len + 1);
		if (tmp) {
			buf = tmp;
		}
	}
	return buf;
}
