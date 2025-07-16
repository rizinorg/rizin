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
 * \brief Table for mapping a 4‑bit value (0 – 15) to its Base‑16 symbol.
 */
static const char cb16[] = "0123456789ABCDEF";

/** \internal
 * \brief Map a Base‑16 symbol to its 4‑bit index (0 – 15).
 */
static size_t cd16(int c) {
	if (c >= '0' && c <= '9') {
		return (size_t)(c - '0');
	}
	if (c >= 'A' && c <= 'F') {
		return (size_t)(10 + (c - 'A'));
	}
	if (c >= 'a' && c <= 'f') {
		return (size_t)(10 + (c - 'a'));
	}
	return SIZE_MAX;
}

/** \internal
 * \brief Base‑16 encode a single byte.
 * \param[in]  src   One input byte.
 * \param[out] dest  Two‑character output (no padding chars).
 */
static void pack_to4(ut8 dest[2], const ut8 src[1]) {
	dest[0] = cb16[(src[0] >> 4) & 0x0F]; // High 4 bits
	dest[1] = cb16[src[0] & 0x0F]; // Low 4 bits
}

/** \internal
 * \brief Decode a single Base‑16 output group.
 * \param[in] src The encoded group of 2 Base‑16 characters.
 * \param[out] dest The decoded single binary byte.
 *
 * This function operates on exactly 2 Base‑16 symbols and reconstructs
 * the original byte (2 × 4 bits = 8 bits = 1 byte).
 */
static void unpack_from4(ut8 dest[1], const ut8 src[2]) {
	size_t high = cd16(src[0]);
	size_t low = cd16(src[1]);
	dest[0] = (high << 4) | low;
}

/** \internal
 * \brief Validate a Base‑16 (hexadecimal) character.
 * \param c  The character to examine (promoted to \c int by the caller).
 *
 * The function returns true if:
 * - an upper‑case letter in the range <code>'A'–'F'</code>, or
 * - a lower‑case letter in the range <code>'a'–'f'</code> (accepted for
 *   leniency), or
 * - a digit in the range <code>'0'–'9'</code>.
 *
 * Any other value yields \c false.
 */
static bool is_base16(int c) {
	return (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'F') ||
		(c >= 'a' && c <= 'f'); /* allow lower‑case */
}

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
 * \brief Calculate the length, in bytes, of the Base‑16 encoded result.
 * \param      len the length of the binary input in bytes.
 *
 * Base‑16 encodes each byte as two hexadecimal characters. Therefore,
 * the output length is always exactly twice the input length.
 */
static size_t calculate_dest_length(size_t len) {
	return 2 * len;
}

/**
 * \brief Base16‑encode binary data (hexadecimal encoding).
 * \param[out] dest The encoded output.
 * \param[in]  src  The binary input data.
 * \param      n    The length of the binary data in bytes.
 * \return The length of the encoded output, excluding the NUL byte.
 * \attention The \p dest parameter must have at least \c 1 + 2 × n bytes.
 *
 * Base16 encoding writes two ASCII characters per byte of input using
 * uppercase hexadecimal characters ‘0’–‘9’, ‘A’–‘F’. No padding is used.
 *
 * If \p dest or \p src is \c NULL, nothing is written and \c 0 is returned.
 */
RZ_API size_t rz_base16_encode(RZ_OUT RZ_NULLABLE char *dest, RZ_NULLABLE const ut8 *src, size_t n) {
	ut8 group[1];
	size_t ret;
	rz_return_val_if_fail(src, 0);
	rz_return_val_if_fail(dest, 0);
	ret = calculate_dest_length(n);

	while (n--) {
		group[0] = *src++;
		pack_to4((ut8 *)dest, group);
		dest += 2;
	}

	dest[0] = '\0';
	return ret;
}

/**
 * \brief Base‑16‑encode binary data and return the result in a newly allocated buffer.
 * \param[in] src  Pointer to the binary data to encode.
 * \param      n   The length of the binary data in bytes.
 * \return A pointer to a NUL‑terminated Base‑16 string allocated with
 *         \c malloc, or \c NULL if \p src is \c NULL or a memory‑allocation
 *         failure occurs. The caller is responsible for \c free()‑ing the
 *         returned buffer.
 *
 * This function first computes the exact output size—\c 1 + 2 × n bytes to accommodate two
 * hexadecimal characters per input byte plus a terminating NUL—allocates
 * that much memory, and then invokes \c rz_base16_encode to fill the buffer.
 *
 * # Example
 * \code{.c}
 * const ut8 plain[] = { 0x48, 0x69 }; // "Hi"
 * char *enc = rz_base16_encode_dyn(plain, sizeof plain);
 * if (!enc) { goto memory_error; }
 * assert(strcmp(enc, "4869") == 0);
 * free(enc);
 * \endcode
 */
RZ_API RZ_OWN char *rz_base16_encode_dyn(RZ_NULLABLE const ut8 *src, size_t n) {
	rz_return_val_if_fail(src, NULL);
	size_t buf_sz = calculate_dest_length(n) + 1;
	char *out = (char *)malloc(buf_sz);
	if (!out) {
		return NULL;
	}
	(void)rz_base16_encode(out, src, n);
	return out;
}

/**
 * \brief Decode a Base16-encoded message.
 * \param[out] dest The decoded output.
 * \param[in] src The Base16-encoded message.
 * \param n The length of the encoded message.
 * \return The length of the decoded message, excluding the NUL byte.
 * \attention The \p dest parameter must have sufficient space to
 * accommodate the decoded output, including the NUL byte.
 * Specifically, at least \c 1 + n/2 bytes must be available.
 *
 * Decode a Base16-encoded message. If \p n is negative, the length of
 * \p src is determined via strlen. The decoded output is stored in \p
 * dest and is NUL byte terminated.
 *
 * If either \p dest or \p src is \c NULL, nothing is done and the
 * value \c 0 is returned.
 *
 * Returns \c -1 if:
 * - Characters in \p src are invalid.
 * - \p n was \c -1 and the length of \p src exceeds \c ST64_MAX.
 * - \p n is not an even number (invalid Base16 length).
 *
 * # Example
 * \code{.c}
 * const char *b16 = "4869"; // "Hi"
 * ut8 buf[16];
 * st64 len = rz_base16_decode(buf, b16, -1);
 * assert(len == 2);
 * assert(memcmp(buf, "Hi", 2) == 0);
 * \endcode
 */
RZ_API st64 rz_base16_decode(RZ_OUT RZ_NULLABLE ut8 *dest, RZ_NULLABLE const char *src, st64 n) {
	char buf[2];
	ut8 tmp[1];
	size_t i, j;
	st64 ret = 0;

	rz_return_val_if_fail(src, 0);
	rz_return_val_if_fail(dest, 0);

	n = calculate_src_length(src, n);
	if (n == -1) {
		return -1;
	}

	if (n % 2 != 0) {
		return -1;
	}

	for (i = j = 0; i < (size_t)n; i++) {
		int c = src[i];
		if (is_base16(c)) {
			buf[j++] = c;
			if (j == 2) {
				unpack_from4(tmp, (const ut8 *)buf);
				*dest++ = tmp[0];
				ret += 1;
				j = 0;
			}
		} else {
			return -1;
		}
	}

	*dest = '\0';
	return ret;
}

/**
 * \brief Dynamically decode a Base16‑encoded string.
 * \param[in]  src  Pointer to the Base16 text.
 * \param      len  The length of \p src; pass \c -1 to use \c strlen(src).
 * \return A newly allocated buffer holding the decoded binary data and
 *         terminated with a NUL byte, or \c NULL on error.
 *
 * Memory is obtained with \c malloc and must be released with \c free
 * by the caller.  The function returns \c NULL when:
 *  - \p src is \c NULL,
 *  - the string length is odd or exceeds \c ST64_MAX,
 *  - a memory allocation fails, or
 *  - the decoder encounters malformed characters.
 *
 * The decoded binary size of a Base16 string of length \p len is
 * \c len/2 bytes, plus one byte for the NUL terminator.
 */
RZ_API RZ_OWN ut8 *rz_base16_decode_dyn(RZ_NULLABLE const char *src, st64 len) {
	rz_return_val_if_fail(src, NULL);

	len = calculate_src_length(src, len);
	if (len < 0 || (len % 2) != 0) {
		return NULL;
	}

	st64 cap = (len / 2) + 1;
	ut8 *buf = (ut8 *)malloc((size_t)cap);
	if (!buf) {
		return NULL;
	}

	st64 out_len = rz_base16_decode(buf, src, len);
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
