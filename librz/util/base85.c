// SPDX-FileCopyrightText: 2011 Remy Oukaour
// SPDX-FileCopyrightText: 2017 pancake
// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim
// SPDX-License-Identifier: MIT

/*
 * ascii85 - Ascii85 encode/decode data
 *
 * Copyright (C) 2011 Remy Oukaour
 *  Updated by pancake in 2017
 *  Updated by Ahmed Ibrahim in 2025
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <rz_types.h>
#include <rz_util.h>

/** \internal
 * \brief Return the next non‑whitespace character from an in‑memory buffer.
 *
 * \param src  Pointer to the start of the Ascii 85 text.
 * \param len  Total length of the buffer in bytes.
 * \param pos  Pointer to the current cursor index; on return it is advanced
 *             past the character that was delivered.
 *
 * \return The first non‑space character at or after \p *pos, or <tt>EOF</tt>
 *         when the cursor reaches \p len. Whitespace is determined by the C library’s \c isspace() predicate.
 *
 */
static int getc_nospace_buf(const char *src, st64 len, st64 *pos) {
	while (*pos < len && isspace((unsigned char)src[*pos])) {
		(*pos)++;
	}
	if (*pos >= len) {
		return EOF;
	}
	return (unsigned char)src[(*pos)++];
}

/** \internal
 * \brief Append a character to an output buffer, inserting a newline when the wrap width is reached.
 *
 * \param d    Pointer to the current write cursor inside the destination buffer.
 *             The pointer is advanced as characters are written.
 * \param len  Pointer to a running count of bytes already written; incremented by this function.
 * \param wrap Maximum printable‐character column before a automatic newline is inserted.
 *             A value of \c 0 disables wrapping entirely.
 * \param col  Pointer to the column counter (characters since the last newline); reset when a wrap occurs.
 * \param c    The character to append.
 *
 * If \p wrap is non‑zero and the column counter referenced by \p col is
 * greater than or equal to \p wrap, the function first appends a newline
 * to the buffer and resets \p *col to 0. It then appends \p c, advancing \p *d, and increments both \p *len
 * and \p *col to reflect the newly written character.
 */
static void putc_wrap_buf(char **d, size_t *len, int wrap, int *col, char c) {
	if (wrap && *col >= wrap) {
		*(*d)++ = '\n';
		(*len)++;
		*col = 0;
	}
	*(*d)++ = c;
	(*len)++;
	(*col)++;
}

/** \internal
 * \brief Encoding up to four input bytes and append their Ascii 85 representation to a buffer.
 *
 * \param tuple   A big‑endian 32‑bit value holding the pending input bytes.
 * \param count   Number of meaningful bytes inside \p tuple ( 1 – 4 ).
 *                A value of 4 represents a full 32‑bit group; smaller values
 *                occur only for the final, partial block at end‑of‑input.
 * \param wrap    Maximum printable‑column width before a newline is inserted;
 *                a value of 0 disables automatic wrapping.
 * \param d       Pointer to the current write cursor inside the destination
 *                buffer. The cursor is advanced as characters are written.
 * \param len     Pointer to a running total of bytes written so far; incremented
 *                by this function.
 * \param col     Pointer to the current column counter (characters since the
 *                last newline); reset to 0 whenever a wrap occurs.
 * \param y_abbr  When non‑zero, emit the non‑standard abbreviation
 *                <tt>'y'</tt> for four space characters (<tt>0x20202020</tt>).
 *
 * **Abbreviations**
 * - A tuple of 0 (<tt>count == 4</tt>) is emitted as a single <tt>'z'</tt>.
 * - With \p y_abbr ≠ 0, the tuple 0x20202020 (<tt>count == 4</tt>) is emitted
 *   as a single <tt>'y'</tt> (Adobe extension).
 *
 * **General case**
 * Otherwise the 32‑bit value is converted to five base‑85 digits.
 * For partial final blocks only the leading <tt>count + 1</tt> digits are
 * appended, exactly matching the Adobe/ RFC 1924 padding rule.
 */
static void encode_tuple_buf(unsigned long tuple, int count, int wrap, char **d, size_t *len, int *col, int y_abbr) {
	if (tuple == 0 && count == 4) {
		putc_wrap_buf(d, len, wrap, col, 'z');
	} else if (tuple == 0x20202020 && count == 4 && y_abbr) {
		putc_wrap_buf(d, len, wrap, col, 'y');
	} else {
		char out[5];
		for (int i = 0; i < 5; i++) {
			out[i] = (tuple % 85) + '!';
			tuple /= 85;
		}
		int lim = 4 - count;
		for (int i = 4; i >= lim; i--) {
			putc_wrap_buf(d, len, wrap, col, out[i]);
		}
	}
}

/** \internal
 * \brief Calculate the buffer size required for an Ascii 85 encoding.
 *
 * \param n       The length of the binary input in bytes.
 * \param delims  Non‑zero if the encoding will be wrapped in the Adobe
 *                delimiters <code>"<~"</code> and <code>"~>"</code>.
 * \param wrap    Line‑wrap column width.  A value of 0 disables wrapping.
 * \return        The number of bytes needed to store the encoded text
 *                *including* the terminating NUL.
 *
 * The formula derives from:
 *
 *  * **Expansion** – Each full 4‑byte block produces 5 digits.
 *    A partial final block of <i>r</i> ∈ {1,2,3} bytes produces <i>r + 1</i> digits.
 *  * **Delimiters** – When \p delims ≠ 0, exactly four characters
 *    (<tt><~</tt> and <tt>~></tt>) are added.
 *  * **Line breaks** – If \p wrap &gt; 0, the encoder inserts a newline
 *    before every byte whose position would otherwise push the current
 *    column counter beyond \p wrap.  The number of newline characters is
 *    therefore <code>(total_chars ? (total_chars – 1) / wrap : 0)</code>.
 *
 * Finally one extra byte is added for the NUL terminator.
 */
static size_t rz_base85_enc_buflen(size_t n, int delims, int wrap) {
	size_t full = n / 4;
	size_t rem = n % 4;
	size_t digits = 5 * full + (rem ? rem + 1 : 0);
	size_t chars = digits + (delims ? 4 : 0);
	if (wrap > 0 && chars > 0) {
		size_t newlines = (chars - 1) / (size_t)wrap;
		chars += newlines;
	}
	return chars + 1;
}

/** \internal
 * \brief Append up to four bytes decoded from an Ascii 85 tuple to a buffer.
 *
 * \param tuple   The 32‑bit value obtained by accumulating five base‑85 digits.
 * \param count   Number of digits that were present in the source group
 *                ( 2 – 5 ).  A full group ( 5 digits ) produces four bytes,
 *                while a partial final group produces \p count – 1 bytes.
 * \param d       Pointer to the current write cursor inside the destination
 *                buffer; advanced as bytes are written.
 * \param len     Pointer to a running total of bytes written so far; incremented
 *                by this function.
 *
 * The function starts with the most‑significant decoded byte and appends up to
 * four bytes to the buffer referenced by \p d.
 */
static void decode_tuple_buf(unsigned long tuple, size_t count, char **d, size_t *len) {
	for (size_t i = 1; i < count; i++) {
		*(*d)++ = (char)(tuple >> ((4 - i) * 8));
		(*len)++;
	}
}

/** \internal
 * \brief Compute the buffer size required to hold the decoded bytes.
 *
 * \param enc_len  The length, in characters, of the Ascii 85 text that will be
 *                 passed to the decoder <b>after</b> stripping any
 *                 delimiters, line‑breaks, or whitespace.
 *
 * \return  A value large enough to store every possible decoding of a string
 *          of length \p enc_len, <em>plus</em> one extra byte for a NUL
 *          terminator.
 */
static size_t rz_base85_dec_buflen(size_t enc_len) {
	/* Upper bound: each Ascii85 char can produce up to 4 bytes, plus NUL */
	return 1 + 4 * enc_len;
}

/**
 * \brief Base-encode a memory buffer to Ascii 85.
 *
 * \param dest    Destination buffer that receives the encoded text.
 * \param src     Pointer to the binary data to encode.
 * \param n       The length of \p src in bytes.
 * \param delims  When non-zero, wrap the output between literal
 *                <code>"<~"</code> and <code>"~>"</code>.
 * \param wrap    Column width for automatic line wrapping.
 *                A value of 0 disables wrapping.
 * \param y_abbr  When non-zero, enable the non-standard abbreviation
 *                <code>'y'</code> for the pattern 0x20 0x20 0x20 0x20.
 * \return The number of characters written to \p dest (excluding the
 *         terminating NUL), or \c 0 if either \p dest or \p src is <code>NULL</code>.
 *
 * \attention The caller must allocate at least \c 1 + 5 × ((n + 3)/4) bytes,
 * plus room for optional delimiters and line-wrap newlines.
 *
 * The function processes the input four bytes at a time, converts each group
 * into five base-85 digits, and appends the result to \p dest.  Special-case
 * abbreviations are emitted where possible:
 *   - <code>'z'</code> for four zero bytes,
 *   - <code>'y'</code> for four space bytes when \p y_abbr is true.
 */
RZ_API int rz_base85_encode(RZ_OUT RZ_NONNULL char *dest, RZ_NONNULL const char *src, size_t n, int delims, int wrap, int y_abbr) {
	if (!dest || !src) {
		return 0;
	}

	char *d = dest;
	size_t out = 0;
	int col = 0;

	if (delims) {
		putc_wrap_buf(&d, &out, wrap, &col, '<');
		putc_wrap_buf(&d, &out, wrap, &col, '~');
	}

	unsigned long tuple = 0;
	int count = 0;

	for (size_t i = 0; i < n || count > 0;) {
		if (i < n) {
			tuple |= (unsigned long)src[i++] << ((3 - count) * 8);
			if (++count < 4) {
				continue;
			}
		}
		encode_tuple_buf(tuple, count, wrap, &d, &out, &col, y_abbr);
		tuple = 0;
		count = 0;
	}
	if (delims) {
		putc_wrap_buf(&d, &out, wrap, &col, '~');
		putc_wrap_buf(&d, &out, wrap, &col, '>');
	}
	*d = '\0'; /* NUL‑terminate the C‑string   */
	return (int)out;
}

/**
 * \brief Dynamically allocate and return an Ascii 85 encoding.
 *
 * \param src     Pointer to the binary data to encode.
 * \param n       The length of \p src in bytes.
 * \param delims  Non‑zero to surround the payload with <tt>"<~"</tt> … <tt>"~>"</tt>.
 * \param wrap    Column width for automatic line wrapping (0 = none).
 * \param y_abbr  Non‑zero to enable the <tt>'y'</tt> abbreviation for four spaces.
 *
 * \return Pointer to a freshly‑allocated, NUL‑terminated string containing
 *         the Ascii 85 representation, or <code>NULL</code> if either
 *         <code>src == NULL</code> or a memory allocation fails.
 */
RZ_API RZ_OWN char *rz_base85_encode_dyn(RZ_NONNULL const char *src, size_t n, int delims, int wrap, int y_abbr) {
	rz_return_val_if_fail(src, NULL);

	char *ret = (char *)malloc(rz_base85_enc_buflen(n, delims, wrap));
	if (!ret) {
		return NULL;
	}
	rz_base85_encode(ret, src, n, delims, wrap, y_abbr);
	return ret;
}

/**
 * \brief Decode an Ascii 85 string held in memory.
 *
 * \param[out] dest   Destination buffer that receives the decoded bytes.
 * \param[in]  src    Pointer to the Ascii 85 text.  Need not be NUL‑terminated.
 * \param       len   Number of characters in \p src; pass –1 to decode up to
 *                    the first <code>'\0'</code>.
 * \param delims      When non‑zero, require the Adobe delimiters
 *                    <tt>"<~"</tt> … <tt>"~>"</tt>.
 * \param ignore_garbage  When non‑zero, silently skip bytes outside the legal
 *                    digit range; otherwise such bytes trigger an error.
 *
 * \return The number of decoded bytes on success, or –1 on error
 *         (malformed input or delimiter mismatch).
 *
 * \attention The caller must allocate \p dest large enough.  A safe upper bound is
 * \c 1 + 3 × ((len + 1)/4) bytes.
 */
RZ_API st64 rz_base85_decode(RZ_OUT RZ_NONNULL char *dest, RZ_NONNULL const char *src, st64 len, int delims, int ignore_garbage) {
	rz_return_val_if_fail(dest, -1);
	rz_return_val_if_fail(src, -1);

	if (len < 0) {
		len = (st64)strlen(src);
	}

	st64 pos = 0;
	int count = 0;
	int have_end = 0;
	size_t out = 0;

	unsigned long tuple = 0;
	const unsigned long pows[5] = {
		85u * 85u * 85u * 85u,
		85u * 85u * 85u,
		85u * 85u,
		85u,
		1u
	};

	if (delims) {
		int c = getc_nospace_buf(src, len, &pos);
		if (c != '<' || getc_nospace_buf(src, len, &pos) != '~') {
			RZ_LOG_ERROR("ascii85: missing <~\n");
			return -1;
		}
	}

	for (;;) {
		int c = getc_nospace_buf(src, len, &pos);
		if (c == 'z' && count == 0) {
			decode_tuple_buf(0, 5, &dest, &out);
			continue;
		}
		if (c == 'y' && count == 0) {
			decode_tuple_buf(0x20202020, 5, &dest, &out);
			continue;
		}
		if (c == '~' && delims) {
			if (getc_nospace_buf(src, len, &pos) != '>') {
				RZ_LOG_ERROR("ascii85: '~' not followed by '>'\n");
				return -1;
			}
			have_end = 1;
			break;
		}
		if (c == EOF) {
			break;
		}
		if (c < '!' || c > 'u') {
			if (ignore_garbage) {
				continue;
			}
			RZ_LOG_ERROR("ascii85: invalid character '%c'\n", c);
			return -1;
		}
		tuple += (unsigned long)(c - '!') * pows[count++];
		if (count == 5) {
			decode_tuple_buf(tuple, count, &dest, &out);
			tuple = 0;
			count = 0;
		}
	}

	if (delims && !have_end) {
		RZ_LOG_ERROR("ascii85: missing ~>\n");
		return -1;
	}
	if (count > 0) { /* partial final group */
		tuple += pows[count - 1]; /* implicit 'u' padding */
		decode_tuple_buf(tuple, count, &dest, &out);
	}
	return (st64)out;
}

/**
 * \brief Decode an Ascii 85 string, allocating the output buffer automatically.
 *
 * \param src             Ascii 85 text to decode (may contain NUL‑bytes).
 * \param len             The length of \p src in bytes, or –1 to use strlen().
 * \param delims          Expect <tt>"<~"</tt> … <tt>"~>"</tt> delimiters.
 * \param ignore_garbage  Skip vs. error on invalid characters.
 * \param[out] out_len    Optional pointer that receives the decoded size.
 *
 * \return Pointer to a newly allocated buffer containing the raw bytes,
 *         or \c NULL on error.  The buffer is NUL‑terminated for convenience.
 */
RZ_API RZ_OWN char *rz_base85_decode_dyn(RZ_NONNULL const char *src, st64 len, int delims, int ignore_garbage, size_t *out_len) {
	rz_return_val_if_fail(src, NULL);

	if (len < 0) {
		len = (st64)strlen(src);
	}

	size_t cap = rz_base85_dec_buflen(len);
	char *buf = (char *)malloc(cap);
	if (!buf) {
		return NULL;
	}

	st64 written = rz_base85_decode(buf, src, len, delims, ignore_garbage);
	if (written < 0) {
		free(buf);
		return NULL;
	}

	/* shrink‑to‑fit and NUL‑terminate */
	if (written + 1 < (st64)cap) {
		char *tmp = (char *)realloc(buf, (size_t)written + 1);
		if (tmp) {
			buf = tmp;
		}
	}
	buf[written] = '\0';
	if (out_len) {
		*out_len = (size_t)written;
	}
	return buf;
}
