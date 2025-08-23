// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_types.h"
#include "rz_util.h"
#include <stdio.h>
#include <ctype.h>

/**
 * \brief Returns the byte value for a hexadecimal nibble.
 *
 * \param The hexadecimal nibble to get the raw byte value for.
 *
 * \param The byte value of the nibble.
 * Or UT8_MAX if the nibble is no hexadecimal character.
 *
 * \return The byte value of the hex digit.
 * Or UT8_MAX if the character was not a hexadecimal character.
 *
 * Example:
 * ```c
 *    assert(rz_hex_nibble_to_byte('1') == 1);
 *    assert(rz_hex_nibble_to_byte('A') == 10);
 *    assert(rz_hex_nibble_to_byte('b') == 11);
 *    assert(rz_hex_nibble_to_byte('S') == UT8_MAX);
 *    assert(rz_hex_nibble_to_byte('\0') == UT8_MAX);
 * ```
 */
RZ_API ut8 rz_hex_digit_to_byte(const char c) {
	if (!isxdigit(c)) {
		return UT8_MAX;
	}
	// Check an ASCII table for this.
	// Bit 6 indicates if it is A-F or a-f.
	ut8 byte = (c & 0x40) ? 9 : 0;
	// Bit 3-0 are the same bits for upper and lower case A-F.
	// And 'a' & 0xf == 1, so 9 + 1 == 10.
	byte += (c & 0xf);
	return byte;
}

/**
 * \brief Returns the byte value for a hexadecimal nibble pair.
 * It stops parsing at the first non hex digit.
 *
 * \param The string to parse as hex digit pair.
 *
 * \return The byte value of the nibble pair.
 * Or UT16_MAX if the first nibble is no hexadecimal character.
 *
 * Example:
 * ```c
 *    assert(rz_hex_nibble_pair_to_byte("1") == 1);
 *    assert(rz_hex_nibble_pair_to_byte("11") == 17);
 *    assert(rz_hex_nibble_pair_to_byte("fe") == 254);
 *
 *    assert(rz_hex_nibble_pair_to_byte("ff01") == 255);
 *    assert(rz_hex_nibble_pair_to_byte("F@") == 15);
 *    assert(rz_hex_nibble_pair_to_byte("p1") == UT16_MAX);
 *    assert(rz_hex_nibble_pair_to_byte("") == UT16_MAX);
 * ```
 */
RZ_API ut16 rz_hex_digit_pair_to_byte(const char *npair) {
	if (!isxdigit(npair[0])) {
		return UT16_MAX;
	}
	ut8 n0 = rz_hex_digit_to_byte(npair[0]);
	if (n0 == UT8_MAX) {
		return UT16_MAX;
	}
	if (!isxdigit(npair[1])) {
		return n0;
	}
	ut8 n1 = rz_hex_digit_to_byte(npair[1]);
	if (n1 == UT8_MAX) {
		return UT16_MAX;
	}
	return (n0 << 4 | n1);
}

/* int c = 0; ret = hex_to_byte(&c, 'c'); */
RZ_API bool rz_hex_to_byte(ut8 *val, ut8 c) {
	if (IS_DIGIT(c)) {
		*val = (ut8)(*val) * 16 + (c - '0');
	} else if (c >= 'A' && c <= 'F') {
		*val = (ut8)(*val) * 16 + (c - 'A' + 10);
	} else if (c >= 'a' && c <= 'f') {
		*val = (ut8)(*val) * 16 + (c - 'a' + 10);
	} else {
		return 1;
	}
	return 0;
}

RZ_API char *rz_hex_from_py_str(char *out, const char *code) {
	if (!strncmp(code, "'''", 3)) {
		const char *s = code + 2;
		return rz_hex_from_c_str(out, &s);
	}
	return rz_hex_from_c_str(out, &code);
}

static const char *skip_comment_py(const char *code) {
	if (*code != '#') {
		return code;
	}
	char *end = strchr(code, '\n');
	if (end) {
		code = end;
	}
	return code + 1;
}

RZ_API char *rz_hex_from_py_array(char *out, const char *code) {
	const char abc[] = "0123456789abcdef";
	if (*code != '[' || !strchr(code, ']')) {
		return NULL;
	}
	code++;
	for (; *code; code++) {
		char *comma = strchr(code, ',');
		if (!comma) {
			comma = strchr(code, ']');
		}
		if (!comma) {
			break;
		}
		char *_word = rz_str_ndup(code, comma - code);
		const char *word = _word;
		while (*word == ' ' || *word == '\t' || *word == '\n') {
			word++;
			word = skip_comment_py(word);
		}
		if (IS_DIGIT(*word)) {
			ut8 n = (ut8)rz_num_math(NULL, word);
			*out++ = abc[(n >> 4) & 0xf];
			*out++ = abc[n & 0xf];
		}
		free(_word);
		code = comma;
		if (*code == ']') {
			break;
		}
	}
	return out;
}

RZ_API char *rz_hex_from_py(const char *code) {
	if (!code) {
		return NULL;
	}
	char *const ret = malloc(strlen(code) * 3);
	if (!ret) {
		return NULL;
	}
	*ret = '\0';
	char *out = ret;
	const char *tmp_code = strchr(code, '=');
	if (tmp_code) {
		code = tmp_code;
	}
	for (; *code && *code != '[' && *code != '\'' && *code != '"'; code++) {
		code = skip_comment_py(code);
	}
	if (*code == '[') {
		out = rz_hex_from_py_array(out, code);
	} else if (*code == '"' || *code == '\'') {
		out = rz_hex_from_py_str(out, code);
	}
	if (!out) {
		free(ret);
		return NULL;
	}
	*out = '\0';
	return ret;
}

RZ_API char *rz_hex_from_c_str(char *out, const char **code) {
	const char abc[] = "0123456789abcdefABCDEF";
	const char *iter = *code;
	if (*iter != '\'' && *iter != '"') {
		return NULL;
	}
	const char end_char = *iter;
	iter++;
	for (; *iter && *iter != end_char; iter++) {
		if (*iter == '\\') {
			iter++;
			switch (iter[0]) {
			case 'e':
				*out++ = '1';
				*out++ = 'b';
				break;
			case 'r':
				*out++ = '0';
				*out++ = 'd';
				break;
			case 'n':
				*out++ = '0';
				*out++ = 'a';
				break;
			case 'x': {
				ut8 c1 = iter[1];
				ut8 c2 = iter[2];
				iter += 2;
				if (c1 == '\0' || c2 == '\0') {
					return NULL;
				} else if (strchr(abc, c1) && strchr(abc, c2)) {
					*out++ = tolower(c1);
					*out++ = tolower(c2);
				} else {
					return NULL;
				}
				break;
			}
			default:
				if (iter[0] == end_char) {
					ut8 x = *iter;
					*out++ = abc[x >> 4];
					*out++ = abc[x & 0xf];
				}
				return NULL;
			}
		} else {
			ut8 x = *iter;
			*out++ = abc[x >> 4];
			*out++ = abc[x & 0xf];
		}
	}
	*code = iter;
	return out;
}

const char *skip_comment_c(const char *code) {
	if (!strncmp(code, "/*", 2)) {
		char *end = strstr(code, "*/");
		if (end) {
			code = end + 2;
		} else {
			eprintf("Missing closing comment\n");
		}
	} else if (!strncmp(code, "//", 2)) {
		char *end = strchr(code, '\n');
		if (end) {
			code = end + 2;
		}
	}
	return code;
}

RZ_API char *rz_hex_from_c_array(char *out, const char *code) {
	if (!code) {
		return NULL;
	}
	const char abc[] = "0123456789abcdef";
	if (*code != '{' || !strchr(code, '}')) {
		return NULL;
	}
	code++;
	for (; *code; code++) {
		const char *comma = strchr(code, ',');
		if (!comma) {
			comma = strchr(code, '}');
		}
		char *_word = rz_str_ndup(code, comma - code);
		const char *word = _word;
		word = skip_comment_c(word);
		while (*word == ' ' || *word == '\t' || *word == '\n') {
			word++;
			word = skip_comment_c(word);
		}
		if (IS_DIGIT(*word)) {
			ut8 n = (ut8)rz_num_math(NULL, word);
			*out++ = abc[(n >> 4) & 0xf];
			*out++ = abc[n & 0xf];
		}
		free(_word);
		code = comma;
		if (code && *code == '}') {
			break;
		}
	}
	return out;
}

/* convert:
 *    char *foo = "\x41\x23\x42\x1b";
 * into:
 *    4123421b
 */
RZ_API char *rz_hex_from_c(const char *code) {
	if (!code) {
		return NULL;
	}
	char *const ret = malloc(strlen(code) * 3);
	if (!ret) {
		return NULL;
	}
	*ret = '\0';
	char *out = ret;
	const char *tmp_code = strchr(code, '=');
	if (tmp_code) {
		code = tmp_code;
	}
	for (; *code != '\0' && *code != '{' && *code != '"'; code++) {
		code = skip_comment_c(code);
	}
	if (*code == '{') {
		out = rz_hex_from_c_array(out, code);
	} else if (*code == '"') {
		const char *s1, *s2;
		s1 = code;
		do {
			code = s1;
			out = rz_hex_from_c_str(out, &code);
			if (!out) {
				break;
			}
			s1 = strchr(code + 1, '"');
			s2 = strchr(code + 1, ';');
		} while (s1 && s2 && (s1 <= s2));
	}
	if (!out) {
		free(ret);
		return NULL;
	}
	*out = '\0';
	return ret;
}

RZ_API char *rz_hex_from_js(const char *code) {
	char *s1 = strchr(code, '\'');
	char *s2 = strchr(code, '"');

	/* there are no strings in the input */
	if (!(s1 || s2)) {
		return NULL;
	}

	char *start, *end;
	if (s1 < s2) {
		start = s1;
		end = strchr(start + 1, '\'');
	} else {
		start = s2;
		end = strchr(start + 1, '"');
	}

	/* the string isn't properly terminated */
	if (!end) {
		return NULL;
	}

	char *str = rz_str_ndup(start + 1, end - start - 1);

	/* assuming base64 input, output will always be shorter */
	ut8 *b64d = malloc(end - start);
	if (!b64d) {
		free(str);
		return NULL;
	}

	rz_base64_decode(b64d, str, end - start - 1);
	if (!b64d) {
		free(str);
		free(b64d);
		return NULL;
	}

	// TODO: use rz_str_bin2hex
	int i, len = strlen((const char *)b64d);
	char *out = malloc(len * 2 + 1);
	if (!out) {
		free(str);
		free(b64d);
		return NULL;
	}
	for (i = 0; i < len; i++) {
		sprintf(&out[i * 2], "%02x", b64d[i]);
	}
	out[len * 2] = '\0';

	free(str);
	free(b64d);
	return out;
}

/* convert
 * "\x41\x23\x42\x1b"
 * "\x41\x23\x42\x1b"
 * into
 * 4123421b4123421b
 */
RZ_API char *rz_hex_no_code(const char *code) {
	if (!code) {
		return NULL;
	}
	char *const ret = calloc(1, strlen(code) * 3);
	if (!ret) {
		return NULL;
	}
	*ret = '\0';
	char *out = ret;
	out = rz_hex_from_c_str(out, &code);
	code = strchr(code + 1, '"');
	if (!out) {
		free(ret);
		return NULL;
	}
	*out = '\0';
	while (out && code) {
		*out = '\0';
		out = rz_hex_from_c_str(out, &code);
		code = strchr(code + 1, '"');
	}
	return ret;
}

RZ_API char *rz_hex_from_code(const char *code) {
	if (!strchr(code, '=')) {
		return rz_hex_no_code(code);
	}
	/* C language */
	if (strstr(code, "char") || strstr(code, "int")) {
		return rz_hex_from_c(code);
	}
	/* JavaScript */
	if (strstr(code, "var")) {
		return rz_hex_from_js(code);
	}
	/* Python */
	return rz_hex_from_py(code);
}

/* int byte = hexpair2bin("A0"); */
// (0A) => 10 || -1 (on error)
RZ_API int rz_hex_pair2bin(const char *arg) {
	ut8 *ptr, c = 0, d = 0;
	ut32 j = 0;

	for (ptr = (ut8 *)arg;; ptr = ptr + 1) {
		if (!*ptr || *ptr == ' ' || j == 2) {
			break;
		}
		d = c;
		if (*ptr != '.' && rz_hex_to_byte(&c, *ptr)) {
			eprintf("Invalid hexa string at char '%c' (%s).\n",
				*ptr, arg);
			return -1;
		}
		c |= d;
		if (j++ == 0) {
			c <<= 4;
		}
	}
	return (int)c;
}

/**
 * \brief Convert binary data to a lowercase hexadecimal string.
 * \param[in]  in   Pointer to the binary input.
 * \param[in]  len  Number of bytes in \p in. Must be non-negative.
 * \param[out] out  Buffer to receive NUL-terminated hexadecimal output.
 *                  Must have at least \c (2 × len) + 1 bytes.
 * \return Number of bytes processed (same as \p len), or \c 0 if \p len
 *         is negative.
 *
 * This function encodes each input byte as two lowercase hexadecimal
 * characters (e.g., \c 0xAF becomes "af") using \c snprintf() and writes
 * them sequentially to the output buffer, followed by a NUL terminator.
 */
RZ_API int rz_hex_bin2str(const ut8 *in, int len, char *out) {
	int i, idx;
	char tmp[8];
	if (len < 0) {
		return 0;
	}
	for (idx = i = 0; i < len; i++, idx += 2) {
		snprintf(tmp, sizeof(tmp), "%02x", in[i]);
		memcpy(out + idx, tmp, 2);
	}
	out[idx] = 0;
	return len;
}

/**
 * \brief Takes an unsigned 32bit integer with MSB set to 1 and returns the signed integer in hex format as string.
 * E.g.: 0xffffffff -> "-0x1"
 *
 * \param in The integer to convert to the signed string.
 * \param out The buffer to write the signed hex string to.
 * \param len Length of the out buffer.
 * \return char* The signed integer as hex string.
 */
RZ_API void rz_hex_ut2st_str(const ut32 in, RZ_INOUT char *out, const int len) {
	char tmp[12];
	if (len < sizeof(tmp)) {
		RZ_LOG_FATAL("Output buffer too small for negative 32bit value.\n");
	}
	snprintf(tmp, sizeof(tmp), "-0x%" PFMT32x, ~in + 1);
	memcpy(out, tmp, sizeof(tmp));
	return;
}

RZ_API char *rz_hex_bin2strdup(const ut8 *in, int len) {
	int i, idx;
	char tmp[5], *out;

	if ((len + 1) * 2 < len) {
		return NULL;
	}
	out = malloc((len + 1) * 2);
	if (!out) {
		return NULL;
	}
	for (i = idx = 0; i < len; i++, idx += 2) {
		snprintf(tmp, sizeof(tmp), "%02x", in[i]);
		memcpy(out + idx, tmp, 2);
	}
	out[idx] = 0;
	return out;
}

/**
 * \brief Convert an input string \p in into the binary form in \p out.
 * For odd number of nibbles, the MSB side is extended with a 0 nibble.
 *
 * If \p in contains non-hexadecimal digits, the result is undefined.
 *
 * Convert an input string in the hexadecimal form (e.g. "41424344") into the
 * raw binary form (e.g. "\x41\x42\x43\x44" or "ABCD").
 *
 * Note: If an odd number of nibbles is given, the buffer is extended on the side of the MSB with a 0 nibble.
 * So, "444" becomes "\x04\x44".
 * Use rz_hex_str2bin() if you need to extend it on the LSB side.
 *
 * \param in Input string in hexadecimal form. An optional "0x" prefix may be present.
 * \param out Output buffer having at least strlen(in) / 2 bytes available
 * \return Number of bytes written into \p out. The number is negative if an odd number of nibbles was parsed.
 */
RZ_API int rz_hex_str2bin_msb(RZ_NONNULL const char *in, RZ_NONNULL RZ_OUT ut8 *out) {
	rz_return_val_if_fail(in && out, 0);

	if (!in[0]) {
		return 0;
	}

	size_t i = 0, j = 0;
	if (in[0] == '0' && in[1] == 'x') {
		i += 2;
	}

	ut16 byte = 0;
	size_t nibbles = rz_str_ansi_len(in + i);

	bool odd_nibble = (nibbles % 2) == 1;
	if (odd_nibble) {
		byte = rz_hex_digit_to_byte(in[i]);
		if (byte >= UT8_MAX) {
			return 0;
		}
		out[j] = byte;
		i++;
		j++;
	}

	for (byte = rz_hex_digit_pair_to_byte(in + i); i < strlen(in) && byte <= UT8_MAX; j++, i += 2, byte = rz_hex_digit_pair_to_byte(in + i)) {
		out[j] = byte;
	}

	return odd_nibble ? -j : j;
}

/**
 * \brief Convert an input string \p in into the binary form in \p out
 * For odd number of nibbles, the LSB side is extended with a 0 nibble.
 *
 * If \p in contains non-hexadecimal digits, the result is undefined.
 *
 * Convert an input string in the hexadecimal form (e.g. "41424344") into the
 * raw binary form (e.g. "\x41\x42\x43\x44" or "ABCD").
 *
 * Note: If an odd number of nibbles is given, the buffer is extended on the side of the LSB with a 0 nibble.
 * So, "444" becomes "\x44\x40".
 * Use rz_hex_str2bin_msb() if you need to extend it on the MSB side.
 *
 * \param in Input string in hexadecimal form. An optional "0x" prefix may be present.
 * \param out Output buffer having at least (strlen(in) / 2) + 1 bytes available.
 *
 * \return Number of bytes written into \p out. The number is negative if an odd number of nibbles was parsed.
 */
RZ_API int rz_hex_str2bin(RZ_NONNULL const char *in, RZ_NONNULL RZ_OUT ut8 *out) {
	rz_return_val_if_fail(in && out, 0);

	long nibbles = 0;

	while (in && *in) {
		ut8 tmp;
		/* skip hex prefix */
		if (*in == '0' && in[1] == 'x') {
			in += 2;
		}
		/* read hex digits */
		while (!rz_hex_to_byte(out ? &out[nibbles / 2] : &tmp, *in)) {
			nibbles++;
			in++;
		}
		if (*in == '\0') {
			break;
		}
		/* comments */
		if (*in == '#' || (*in == '/' && in[1] == '/')) {
			if ((in = strchr(in, '\n'))) {
				in++;
			}
			continue;
		} else if (*in == '/' && in[1] == '*') {
			if ((in = strstr(in, "*/"))) {
				in += 2;
			}
			continue;
		} else if (!IS_WHITESPACE(*in) && *in != '\n') {
			/* this is not a valid string */
			return 0;
		}
		/* ignore character */
		in++;
	}

	if (nibbles % 2) {
		if (out) {
			rz_hex_to_byte(&out[nibbles / 2], '0');
		}
		return -(nibbles + 1) / 2;
	}

	return nibbles / 2;
}

/**
 * \brief Transforms an input hex string to its byte array eqivalent and a mask for it.
 * The hex string is allowed to contain '.' characters as wildcard.
 * Wildcards in \p in are set to '0' in the mask and \p out.
 * It stops at the first invalid character and returns.
 *
 * If \p in contains non-hexadecimal digits, the result is undefined.
 *
 * The input string may be prefixed with a "0x".
 *
 * \param in The hex string to parse and transform.
 * \param out The output buffer. It must be the same size as \p strlen(in) / 2.
 * \param mask The output buffer for the mask. It must be the same size as \p out.
 * Can be NULL, if no mask is required.
 * \param lsb_extend If set and \p in has an odd number hex digits,
 * it extends the byte buffer with a wildcard nibble at the LSB (right) side.
 * If unset and with an odd digit count, it extends on the MSB (left) side.
 *
 * \return The number of bytes written to \p out and \p mask. In case of failure it returns less then 0.
 * Note: In case of failure the content of \p out and \p mask are undefined.
 *
 * Example:
 * ```c
 *   rz_hex_str2bin_mask("ffe4", out, mask, false);
 *   assert_mem_eq(out, { 0xff, 0xe4 });
 *   assert_mem_eq(mask, { 0xff, 0xff });
 *
 *   rz_hex_str2bin_mask("ff.4", out, mask, false);
 *   assert_mem_eq(out, { 0xff, 0x04 });
 *   assert_mem_eq(mask, { 0xff, 0x0f });
 *
 *   // Extend on MSB side
 *   rz_hex_str2bin_mask("ffee4", out, mask, false);
 *   assert_mem_eq(out, { 0x0f, 0xfe, 0xe4 });
 *   assert_mem_eq(mask, { 0x0f, 0xff, 0xff });
 *
 *   // Extend on LSB side
 *   rz_hex_str2bin_mask("ee4", out, mask, true);
 *   assert_mem_eq(out, { 0xee, 0x40 });
 *   assert_mem_eq(mask, { 0xff, 0xf0 });
 * ```
 */
RZ_API size_t rz_hex_str2bin_mask(RZ_NONNULL const char *in, RZ_NONNULL RZ_OUT ut8 *out, RZ_NULLABLE RZ_OUT ut8 *mask, bool lsb_extend) {
	rz_return_val_if_fail(in && out, 0);

	if (in[0] == '\0') {
		return 0;
	}

	char *in_cpy = strdup(in);
	for (size_t i = 0; in_cpy[i]; ++i) {
		if (in_cpy[i] == '.') {
			in_cpy[i] = '0';
		}
	}

	int bytes_copied;
	if (lsb_extend) {
		bytes_copied = rz_hex_str2bin(in_cpy, out);
	} else {
		bytes_copied = rz_hex_str2bin_msb(in_cpy, out);
	}
	size_t ret = bytes_copied < 0 ? -bytes_copied : bytes_copied;

	if (!mask) {
		free(in_cpy);
		return ret;
	}
	bool odd_nibbles = bytes_copied < 0;
	for (size_t i = 0; i < ret; ++i) {
		int low_offset = (i * 2);
		int high_offset = (i * 2) + 1;
		char low_digit;
		char high_digit;
		if (odd_nibbles && (i == 0 || i == (ret - 1))) {
			low_digit = (i == 0 && !lsb_extend) ? '.' : in[low_offset];
			high_digit = (i == ret - 1) && lsb_extend ? '.' : in[high_offset - 1];
		} else {
			low_digit = in[low_offset];
			high_digit = in[high_offset];
		}

		mask[i] = 0x00;
		if (low_digit != '.') {
			mask[i] |= 0xf0;
		}
		if (high_digit != '.') {
			mask[i] |= 0x0f;
		}
	}
	free(in_cpy);
	return ret;
}

RZ_API st64 rz_hex_bin_truncate(ut64 in, int n) {
	switch (n) {
	case 1:
		if ((in & UT8_GT0)) {
			return UT64_8U | in;
		}
		return in & UT8_MAX;
	case 2:
		if ((in & UT16_GT0)) {
			return UT64_16U | in;
		}
		return in & UT16_MAX;
	case 4:
		if ((in & UT32_GT0)) {
			return UT64_32U | in;
		}
		return in & UT32_MAX;
	case 8:
		return in & UT64_MAX;
	}
	return in;
}

/**
 * \brief Check if \p str contains only hexadecimal characters
 *
 * Check that the input string is in the hexadecimal form (e.g. "41424344", with whitespace ignored), and return the number of bytes of its raw binary form (4 for the previous example), or an error if non-hexadecimal characters were found
 *
 * \param str Input string in hexadecimal form.
 * \param allow_prefix Whether an optional "0x" prefix may be present at the start of \p str.
 * \return number of bytes in the raw binary form of \p str, or -1 if invalid characters were found
 */
RZ_API int rz_hex_str_is_valid(const char *str, bool allow_prefix) {
	int i;
	int len = 0;
	if (allow_prefix && !strncmp(str, "0x", 2)) {
		str += 2;
	}
	for (i = 0; str[i] != '\0'; i++) {
		if (IS_HEXCHAR(str[i])) {
			len++;
		}
		if (IS_HEXCHAR(str[i]) || IS_WHITESPACE(str[i])) {
			continue;
		}
		return -1; // if we're here, then str isn't valid
	}
	return len;
}
