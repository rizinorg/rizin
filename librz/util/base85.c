// SPDX-FileCopyrightText: 2011 Remy Oukaour
// SPDX-FileCopyrightText: 2017 pancake
// SPDX-License-Identifier: MIT

/*
 * ascii85 - Ascii85 encode/decode data and print to standard output
 *
 * Copyright (C) 2011 Remy Oukaour
 *  Updated by pancake in 2017
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
#include <errno.h>
#include <ctype.h>
#include <rz_types.h>
#include <rz_util.h>

/**
 * \internal
 * \brief Read next non-whitespace character from a file.
 * \param f The input file stream to read from.
 * \return The first non-whitespace character, or \c EOF on end-of-file or error.
 *
 * Reads characters from the file stream \p f, skipping any whitespace characters
 * (as defined by \c isspace), until a non-whitespace character is found or \c EOF is reached.
 */
static int getc_nospace(FILE *f) {
	int c;
	while (isspace(c = getc(f))) {
		;
	}
	return c;
}

/**
 * \internal
 * \brief Output a character, inserting a newline when a wrap‑width is reached.
 * \param c    The character to write to standard output.
 * \param wrap The maximum number of characters per line before wrapping.
 *             A value of \c 0 disables automatic wrapping.
 * \param len  Pointer to the current line‑length counter; updated on output.
 *
 * Writes \p c using \c putchar.
 * If \p wrap is non‑zero and the counter referenced by \p len is greater than
 * or equal to \p wrap, a newline is emitted first and the counter is reset to
 * zero. After printing the character, the counter is incremented.
 */
static void putc_wrap(char c, int wrap, int *len) {
	if (wrap && *len >= wrap) {
		putchar('\n');
		*len = 0;
	}
	putchar(c);
	(*len)++;
}

/**
 * \internal
 * \brief Encode up to four input bytes into their Ascii85 representation.
 * \param tuple   The big‑endian 32‑bit tuple containing up to four input bytes.
 * \param count   Number of significant bytes in \p tuple (1–4). A value of
 *                \c 4 indicates a full 32‑bit group; smaller values are used
 *                only for the final, partial group at end‑of‑file.
 * \param wrap    Maximum column width before output is wrapped with a newline;
 *                \c 0 disables wrapping.
 * \param plen    Pointer to the current output column counter; updated on each
 *                emitted byte.
 * \param y_abbr  When non‑zero, enable the non‑standard \c 'y' abbreviation for
 *                four space characters (0x20202020).
 *
 * The function writes the Ascii85 encoding of \p tuple to \c stdout via
 * \a putc_wrap, honouring the requested line wrapping.
 * Special‑case abbreviations are used when possible:
 * - A full zero tuple (\p tuple==0 and \p count==4) is emitted as a single
 *   \c 'z' character.
 * - When \p y_abbr is true, the value 0x20202020 with \p count==4 is emitted as
 *   a single \c 'y' character, mirroring Adobe’s PostScript extension.
 *
 * For all other cases the 32‑bit value is converted into five Ascii85 digits;
 * only the first \p count\!+\!1 characters are output for partial final groups.
 */
static void encode_tuple(unsigned long tuple, int count, int wrap, int *plen, int y_abbr) {
	int i, lim;
	char out[5];
	if (tuple == 0 && count == 4) {
		putc_wrap('z', wrap, plen);
	} else if (tuple == 0x20202020 && count == 4 && y_abbr) {
		putc_wrap('y', wrap, plen);
	} else {
		for (i = 0; i < 5; i++) {
			out[i] = tuple % 85 + '!';
			tuple /= 85;
		}
		lim = 4 - count;
		for (i = 4; i >= lim; i--) {
			putc_wrap(out[i], wrap, plen);
		}
	}
}

/**
 * \internal
 * \brief Output up to four bytes decoded from an Ascii85 tuple.
 * \param tuple  The 32‑bit value produced by accumulating five Ascii85 digits.
 * \param count  The number of meaningful input digits in the original group
 *               (1 – 5).  This determines how many decoded bytes are written.
 *
 * The function extracts at most four bytes from \p tuple, starting with the
 * most‑significant decoded byte, and writes them to \c stdout via
 * \c putchar.
 *
 * It is used internally by the streaming decoder; a full five‑digit group
 * (\p count == 5) yields four output bytes, whereas a partial final group
 * (e.g.\ 2–4 digits) yields \p count – 1 bytes.
 */
RZ_API void rz_base85_decode_tuple(unsigned long tuple, int count) {
	int i;
	for (i = 1; i < count; i++) {
		putchar(tuple >> ((4 - i) * 8));
	}
}

/**
 * \brief Encode binary data from a stream to Ascii85 and write it to stdout.
 * \param fp      Input stream containing the binary data to encode.
 * \param delims  If non‑zero, wrap the output between \c "<~" and \c "~>" delimiters.
 * \param wrap    Column width for line wrapping. A value of \c 0 disables wrapping.
 * \param y_abbr  If non‑zero, enable the non‑standard abbreviation \c 'y' for four spaces.
 *
 * This function reads up to four bytes at a time from \p fp, encodes each group
 * into Ascii85, and writes the result to \c stdout using \a encode_tuple.
 *
 * If the final input group contains fewer than four bytes, it is padded with
 * zero bytes before encoding. Optional Adobe-style delimiters may be added
 * around the encoded stream by enabling \p delims.
 *
 * If line wrapping is requested, output lines will be broken after \p wrap
 * characters using \a putc_wrap. The function continues until end-of-file.
 */
RZ_API void rz_base85_encode(FILE *fp, int delims, int wrap, int y_abbr) {
	int c, count = 0, len = 0;
	unsigned long tuple = 0;
	if (delims) {
		putc_wrap('<', wrap, &len);
		putc_wrap('~', wrap, &len);
	}
	for (;;) {
		c = getc(fp);
		if (c != EOF) {
			tuple |= c << ((3 - count++) * 8);
			if (count < 4) {
				continue;
			}
		} else if (count == 0) {
			break;
		}
		encode_tuple(tuple, count, wrap, &len, y_abbr);
		if (c == EOF) {
			break;
		}
		tuple = 0;
		count = 0;
	}
	if (delims) {
		putc_wrap('~', wrap, &len);
		putc_wrap('>', wrap, &len);
	}
}

/**
 * \brief Decode an Ascii85 stream read from \p fp and write raw bytes to stdout.
 * \param fp             Input stream that provides the Ascii85‑encoded data.
 * \param delims         If non‑zero, require Adobe‑style delimiters
 *                       \c "<~" … \c "~>" around the payload.
 * \param ignore_garbage If non‑zero, silently skip bytes outside the legal
 *                       Ascii85 range \c '!'–\c 'u'. If zero, such characters
 *                       trigger an error.
 * \return \c true on successful decoding; \c false if the input is malformed
 *         (missing delimiters, bad character, etc.) or a stream error occurs.
 *
 * The function reads printable characters from \p fp, converts groups of five
 * Ascii85 digits into four binary bytes, and writes those bytes to \c stdout
 * via \a rz_base85_decode_tuple.
 *
 * Special‑case abbreviations are recognised:
 * - \c 'z' expands to four zero bytes.
 * - \c 'y' expands to four spaces if the abbreviation appears at the start of
 *   a 5‑digit group.
 *
 * At end‑of‑file any partial group of 2–4 digits is decoded into 1–3 bytes,
 * with the implicit trailing digit(s) interpreted as \c 'u' (value 84) per the
 * Ascii85 padding rule.
 *
 */
RZ_API bool rz_base85_decode(FILE *fp, int delims, int ignore_garbage) {
	int c, count = 0, end = 0;
	unsigned long tuple = 0, pows[] = { 85 * 85 * 85 * 85, 85 * 85 * 85, 85 * 85, 85, 1 };
	while (delims) {
		c = getc_nospace(fp);
		if (c == '<') {
			c = getc_nospace(fp);
			if (c == '~') {
				break;
			}
			ungetc(c, fp);
		} else if (c == EOF) {
			eprintf("ascii85: missing <~");
			return false;
		}
	}
	for (;;) {
		c = getc_nospace(fp);
		if (c == 'z' && count == 0) {
			rz_base85_decode_tuple(0, 5);
			continue;
		}
		if (c == 'y' && count == 0) {
			rz_base85_decode_tuple(0x20202020, 5);
			continue;
		}
		if (c == '~' && delims) {
			c = getc_nospace(fp);
			if (c != '>') {
				eprintf("ascii85: ~ without >\n");
				return false;
			}
			c = EOF;
			end = 1;
		}
		if (c == EOF) {
			if (delims && !end) {
				eprintf("ascii85: missing ~>");
				return false;
			}
			if (count > 0) {
				tuple += pows[count - 1];
				rz_base85_decode_tuple(tuple, count);
			}
			break;
		}
		if (c < '!' || c > 'u') {
			if (ignore_garbage) {
				continue;
			}
			eprintf("ascii85: invalid character '%c'\n", c);
			return false;
		}
		tuple += (c - '!') * pows[count++];
		if (count == 5) {
			rz_base85_decode_tuple(tuple, count);
			tuple = 0;
			count = 0;
		}
	}
	return true;
}
