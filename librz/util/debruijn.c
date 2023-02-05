// SPDX-FileCopyrightText: 2014-2016 crowell <crowell@bu.edu>
// SPDX-FileCopyrightText: 2014-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

// The following two (commented out) lines are the character set used in peda.
// You may use this charset instead of the A-Za-z0-9 charset normally used.
// char* peda_charset =
//    "A%sB$nC-(D;)Ea0Fb1Gc2Hd3Ie4Jf5Kg6Lh7Mi8Nj9OkPlQmRnSoTpUqVrWsXtYuZvwxyz";

static const char *debruijn_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";

// Generate a De Bruijn sequence.
static void de_bruijn_seq(int prenecklace_len_t, int lyndon_prefix_len_p, int order,
	int maxlen, int size, int *prenecklace_a, char *sequence, const char *charset) {
	int j;
	if (!charset || !sequence || strlen(sequence) == maxlen) {
		return;
	}
	if (prenecklace_len_t > order) {
		if (order % lyndon_prefix_len_p == 0) {
			for (j = 1; j <= lyndon_prefix_len_p; j++) {
				sequence[strlen(sequence)] = charset[prenecklace_a[j]];
				if (strlen(sequence) == maxlen) {
					return;
				}
			}
		}
	} else {
		prenecklace_a[prenecklace_len_t] =
			prenecklace_a[prenecklace_len_t - lyndon_prefix_len_p];
		de_bruijn_seq(prenecklace_len_t + 1, lyndon_prefix_len_p, order, maxlen,
			size, prenecklace_a, sequence, charset);
		for (j = prenecklace_a[prenecklace_len_t - lyndon_prefix_len_p] + 1;
			j < size; j++) {
			prenecklace_a[prenecklace_len_t] = j;
			de_bruijn_seq(prenecklace_len_t + 1, prenecklace_len_t, order, maxlen,
				size, prenecklace_a, sequence, charset);
		}
	}
}

// Generate a De Bruijn sequence.
// The returned string is malloced, and it is the responsibility of the caller
// to free the memory.
static char *de_bruijn(const char *charset, int order, int maxlen) {
	if (!charset) {
		return NULL;
	}
	size_t size = strlen(charset);
	int *prenecklace_a = calloc(size * (size_t)order, sizeof(int));
	if (!prenecklace_a) {
		return NULL;
	}
	char *sequence = calloc(maxlen + 1, sizeof(char));
	if (!sequence) {
		free(prenecklace_a);
		return NULL;
	}
	de_bruijn_seq(1, 1, order, maxlen, size, prenecklace_a, sequence, charset);
	free(prenecklace_a);
	return sequence;
}

/**
 * \brief Generate a cyclic pattern following the Debruijn pattern
 *
 * Generate a cyclic pattern of desired size, and charset, return with starting
 * offset of start.
 *
 * For example, AAABAACAAD is a sequence of size 10, start 0, charset =
 * debruijn_charset.
 *
 * \param size Size of the string to return
 * \param start Starting offset in the Debruijn pattern
 * \param charset Set of characters to use to generate the string
 * \return String of length \p size allocated on the heap
 */
RZ_API RZ_OWN char *rz_debruijn_pattern(int size, int start, const char *charset) {
	rz_return_val_if_fail(size >= 0, NULL);
	rz_return_val_if_fail(start >= 0, NULL);
	if (!charset) {
		charset = debruijn_charset;
	}
	char *pat = de_bruijn(charset, 3, size + start);
	if (!pat || start == 0) {
		return pat;
	}

	char *pat2 = RZ_NEWS0(char, size + 1);
	if (!pat2) {
		free(pat);
		return NULL;
	}
	size_t len = strlen(pat + start);
	if (len > size) {
		free(pat);
		return NULL;
	}
	strcpy(pat2, pat + start);
	free(pat);
	return pat2;
}

/**
 * \brief Finds the offset of a given value in a debrujn sequence
 *
 * \param start Starting offset in the Debruijn pattern
 * \param charset Set of characters to use to generate the sequence
 * \param value Value to search in the sequence
 * \param is_big_endian Endianess of \p value
 * \return The offset in the sequence where \p value is found or -1 if not found
 */
RZ_API int rz_debruijn_offset(int start, const char *charset, ut64 value, bool is_big_endian) {
	int retval = -1;
	// 0x10000 should be long enough. This is how peda works, and nobody complains
	// ... but is slow. Optimize for common case.
	int lens[] = { 0x1000, 0x10000, 0x100000 };
	int j;

	if (value == 0) {
		return -1;
	}

	for (j = 0; j < RZ_ARRAY_SIZE(lens) && retval == -1; j++) {
		char *pattern = rz_debruijn_pattern(lens[j], start, charset);
		if (!pattern) {
			return -1;
		}

		char buf[9];
		buf[8] = '\0';
		if (is_big_endian) {
			rz_write_be64(buf, value);
		} else {
			rz_write_le64(buf, value);
		}
		char *needle;
		for (needle = buf; !*needle; needle++) {
			/* do nothing here */
		}

		char *pch = strstr(pattern, needle);
		if (pch) {
			retval = (int)(size_t)(pch - pattern);
		}
		free(pattern);
	}
	return retval;
}
