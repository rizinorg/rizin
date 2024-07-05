// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_regex.h>
#include "rz_list.h"
#include "rz_types.h"
#include "rz_util.h"
#include "rz_cons.h"
#include "rz_bin.h"
#include "rz_util/rz_assert.h"
#include <rz_vector.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <wchar.h>
#include <stdarg.h>
#include <rz_util/rz_base64.h>
#include <rz_util/rz_utf8.h>
#include <rz_util/rz_utf16.h>
#include <rz_util/rz_utf32.h>
#include <rz_util/rz_ebcdic.h>

/* stable code */
static const char *rwxstr[] = {
	[0] = "---",
	[1] = "--x",
	[2] = "-w-",
	[3] = "-wx",
	[4] = "r--",
	[5] = "r-x",
	[6] = "rw-",
	[7] = "rwx",

	[8] = "---",
	[9] = "--x",
	[10] = "-w-",
	[11] = "-wx",
	[12] = "r--",
	[13] = "r-x",
	[14] = "rw-",
	[15] = "rwx",
};

RZ_API const char *rz_str_enc_as_string(RzStrEnc enc) {
	switch (enc) {
	case RZ_STRING_ENC_8BIT:
		return "ascii";
	case RZ_STRING_ENC_UTF8:
		return "utf8";
	case RZ_STRING_ENC_MUTF8:
		return "mutf8";
	case RZ_STRING_ENC_UTF16LE:
		return "utf16le";
	case RZ_STRING_ENC_UTF32LE:
		return "utf32le";
	case RZ_STRING_ENC_UTF16BE:
		return "utf16be";
	case RZ_STRING_ENC_UTF32BE:
		return "utf32be";
	case RZ_STRING_ENC_BASE64:
		return "base64";
	case RZ_STRING_ENC_IBM037:
		return "ibm037";
	case RZ_STRING_ENC_IBM290:
		return "ibm290";
	case RZ_STRING_ENC_EBCDIC_ES:
		return "ebcdices";
	case RZ_STRING_ENC_EBCDIC_UK:
		return "ebcdicuk";
	case RZ_STRING_ENC_EBCDIC_US:
		return "ebcdicus";
	case RZ_STRING_ENC_GUESS:
		return "guessed";
	default:
		rz_warn_if_reached();
		return "unknown";
	}
}

/**
 * \brief      converts an encoding name to RzStrEnc
 *
 * \param[in]  encoding Encoding name
 * \return     Returns a RzStrEnc type.
 */
RZ_API RzStrEnc rz_str_enc_string_as_type(RZ_NULLABLE const char *encoding) {
	if (!encoding || !strncmp(encoding, "guess", 5)) {
		return RZ_STRING_ENC_GUESS;
	} else if (!strcmp(encoding, "ascii") || !strcmp(encoding, "8bit")) {
		return RZ_STRING_ENC_8BIT;
	} else if (!strcmp(encoding, "mutf8")) {
		return RZ_STRING_ENC_MUTF8;
	} else if (!strcmp(encoding, "utf8")) {
		return RZ_STRING_ENC_UTF8;
	} else if (!strcmp(encoding, "utf16le")) {
		return RZ_STRING_ENC_UTF16LE;
	} else if (!strcmp(encoding, "utf32le")) {
		return RZ_STRING_ENC_UTF32LE;
	} else if (!strcmp(encoding, "utf16be")) {
		return RZ_STRING_ENC_UTF16BE;
	} else if (!strcmp(encoding, "utf32be")) {
		return RZ_STRING_ENC_UTF32BE;
	} else if (!strcmp(encoding, "ibm037")) {
		return RZ_STRING_ENC_IBM037;
	} else if (!strcmp(encoding, "ibm290")) {
		return RZ_STRING_ENC_IBM290;
	} else if (!strcmp(encoding, "ebcdices")) {
		return RZ_STRING_ENC_EBCDIC_ES;
	} else if (!strcmp(encoding, "ebcdicuk")) {
		return RZ_STRING_ENC_EBCDIC_UK;
	} else if (!strcmp(encoding, "ebcdicus")) {
		return RZ_STRING_ENC_EBCDIC_US;
	} else if (!strcmp(encoding, "base64")) {
		return RZ_STRING_ENC_BASE64;
	}

	RZ_LOG_ERROR("rz_str: encoding %s not supported\n", encoding);
	return RZ_STRING_ENC_GUESS;
}

RZ_API int rz_str_casecmp(const char *s1, const char *s2) {
#ifdef _MSC_VER
	return stricmp(s1, s2);
#else
	return strcasecmp(s1, s2);
#endif
}

RZ_API int rz_str_ncasecmp(const char *s1, const char *s2, size_t n) {
#ifdef _MSC_VER
	return _strnicmp(s1, s2, n);
#else
	return strncasecmp(s1, s2, n);
#endif
}

// GOOD
// In-place replace the first instance of the character a, with the character b.
RZ_API int rz_str_replace_ch(char *s, char a, char b, bool global) {
	int ret = 0;
	char *o = s;
	if (!s || a == b) {
		return 0;
	}
	for (; *o; s++, o++) {
		if (*o == a) {
			ret++;
			if (b) {
				*s = b;
			} else {
				/* remove char */
				s--;
			}
			if (!global) {
				return 1;
			}
		} else {
			*s = *o;
		}
	}
	*s = 0;
	return ret;
}

RZ_API int rz_str_replace_char_once(char *s, int a, int b) {
	return rz_str_replace_ch(s, a, b, false);
}

RZ_API int rz_str_replace_char(char *s, int a, int b) {
	return rz_str_replace_ch(s, a, b, true);
}

RZ_API void rz_str_remove_char(char *str, char c) {
	while (*str) {
		if (*str == c) {
			memmove(str, str + 1, strlen(str + 1) + 1);
			continue;
		}
		str++;
	}
}

RZ_API void rz_str_reverse(char *str) {
	int i, len = strlen(str);
	int half = len / 2;
	for (i = 0; i < half; i++) {
		char ch = str[i];
		str[i] = str[len - i - 1];
		str[len - i - 1] = ch;
	}
}

// TODO: do not use toupper.. must support modes to also append lowercase chars like in r1
// TODO: this functions needs some stabilization
RZ_API int rz_str_bits(char *strout, const ut8 *buf, int len, const char *bitz) {
	int i, j, idx;
	if (bitz) {
		for (i = j = 0; i < len && (!bitz || bitz[i]); i++) {
			if (i > 0 && (i % 8) == 0) {
				buf++;
			}
			if (*buf & (1 << (i % 8))) {
				strout[j++] = toupper((const ut8)bitz[i]);
			}
		}
	} else {
		for (i = j = 0; i < len; i++) {
			idx = (i / 8);
			int bit = 7 - (i % 8);
			strout[j++] = (buf[idx] & (1 << bit)) ? '1' : '0';
		}
	}
	strout[j] = 0;
	return j;
}

RZ_API const char *rz_str_sysbits(const int v) {
	switch (v) {
	case RZ_SYS_BITS_8: return "8";
	case RZ_SYS_BITS_16: return "16";
	case RZ_SYS_BITS_32: return "32";
	case RZ_SYS_BITS_64: return "64";
	case RZ_SYS_BITS_16 | RZ_SYS_BITS_32: return "16,32";
	case RZ_SYS_BITS_16 | RZ_SYS_BITS_32 | RZ_SYS_BITS_64: return "16,32,64";
	case RZ_SYS_BITS_32 | RZ_SYS_BITS_64: return "32,64";
	}
	return "?";
}

// In-place trims a bitstring to groups of 8 bits.
// For example, the bitstring 1000000000000000 will not be modified, but the
// bitstring 0000000001000000 will be changed to 01000000.
static void trimbits(char *b) {
	const int len = strlen(b);
	char *one = strchr(b, '1');
	int pos = one ? (int)(size_t)(one - b) : len - 1;
	pos = (pos / 8) * 8;
	memmove(b, b + pos, len - pos + 1);
}

// Set 'strout' to the binary representation of the input value.
// strout must be a char array of 65 or greater.
// The string is then trimmed using the "trimbits" function above.
RZ_API int rz_str_bits64(char *strout, ut64 in) {
	int i, bit, count = 0;
	count = 0;
	for (i = (sizeof(in) * 8) - 1; i >= 0; i--) {
		bit = in >> i;
		if (bit & 1) {
			strout[count] = '1';
		} else {
			strout[count] = '0';
		}
		count++;
	}
	strout[count] = '\0';
	/* trim by 8 bits */
	trimbits(strout);
	return count;
}

/**
 * function: rz_str_bits_from_num
 *
 */
RZ_API ut64 rz_str_bits_from_string(const char *buf, const char *bitz) {
	ut64 out = 0LL;
	/* return the numeric value associated to a string (rflags) */
	for (; *buf; buf++) {
		char *ch = strchr(bitz, toupper((const unsigned char)*buf));
		if (!ch) {
			ch = strchr(bitz, tolower((const unsigned char)*buf));
		}
		if (ch) {
			int bit = (int)(size_t)(ch - bitz);
			out |= (ut64)(1LL << bit);
		} else {
			return UT64_MAX;
		}
	}
	return out;
}

RZ_API int rz_str_binstr2bin(const char *str, ut8 *out, int outlen) {
	int n, i, j, k, ret, len;
	len = strlen(str);
	for (n = i = 0; i < len; i += 8) {
		ret = 0;
		while (str[i] == ' ') {
			str++;
		}
		if (i + 7 < len) {
			for (k = 0, j = i + 7; j >= i; j--, k++) {
				// INVERSE for (k=0,j=i; j<i+8; j++,k++) {
				if (str[j] == ' ') {
					// k--;
					continue;
				}
				//		printf ("---> j=%d (%c) (%02x)\n", j, str[j], str[j]);
				if (str[j] == '1') {
					ret |= 1 << k;
				} else if (str[j] != '0') {
					return n;
				}
			}
		}
		//	printf ("-======> %02x\n", ret);
		out[n++] = ret;
		if (n == outlen) {
			return n;
		}
	}
	return n;
}

// Returns the permissions as in integer given an input in the form of rwx, rx,
// etc.
RZ_API int rz_str_rwx(const char *str) {
	int ret = atoi(str);
	if (!ret) {
		ret |= strchr(str, 'm') ? 16 : 0;
		ret |= strchr(str, 'r') ? 4 : 0;
		ret |= strchr(str, 'w') ? 2 : 0;
		ret |= strchr(str, 'x') ? 1 : 0;
	} else if (ret < 0 || ret >= RZ_ARRAY_SIZE(rwxstr)) {
		ret = 0;
	}
	return ret;
}

// Returns the string representation of the permission of the inputted integer.
RZ_API const char *rz_str_rwx_i(int rwx) {
	if (rwx < 0 || rwx >= RZ_ARRAY_SIZE(rwxstr)) {
		rwx = 0;
	}
	return rwxstr[rwx % 24]; // 15 for srwx
}

// If up is true, upcase all characters in the string, otherwise downcase all
// characters in the string.
RZ_API void rz_str_case(char *str, bool up) {
	if (up) {
		char oc = 0;
		for (; *str; oc = *str++) {
			*str = (*str == 'x' && oc == '0') ? 'x' : toupper((int)(ut8)*str);
		}
	} else {
		for (; *str; str++) {
			*str = tolower((int)(ut8)*str);
		}
	}
}

RZ_API char *rz_str_home(const char *str) {
	char *dst, *home = rz_sys_getenv(RZ_SYS_HOME);
	size_t length;
	if (!home) {
		home = rz_file_tmpdir();
		if (!home) {
			return NULL;
		}
	}
	length = strlen(home) + 1;
	if (str) {
		length += strlen(RZ_SYS_DIR) + strlen(str);
	}
	dst = (char *)malloc(length);
	if (!dst) {
		goto fail;
	}
	int home_len = strlen(home);
	memcpy(dst, home, home_len + 1);
	if (str) {
		dst[home_len] = RZ_SYS_DIR[0];
		strcpy(dst + home_len + 1, str);
	}
fail:
	free(home);
	return dst;
}

// Compute a 64 bit DJB hash of a string.
RZ_API ut64 rz_str_djb2_hash(const char *s) {
	ut64 len, h = 5381;
	if (!s) {
		return 0;
	}
	for (len = strlen(s); len > 0; len--) {
		h = (h ^ (h << 5)) ^ *s++;
	}
	return h;
}

RZ_API int rz_str_delta(char *p, char a, char b) {
	char *_a = strchr(p, a);
	char *_b = strchr(p, b);
	return (!_a || !_b) ? 0 : (_a - _b);
}

/**
 * \brief Split string \p str in place by using \p ch as a delimiter.
 *
 * Replaces all instances of \p ch in \p str with a NULL byte and it returns
 * the number of split strings.
 */
RZ_API size_t rz_str_split(char *str, char ch) {
	rz_return_val_if_fail(str, 0);
	size_t i;
	char *p;
	for (i = 1, p = str; *p; p++) {
		if (*p == ch) {
			i++;
			*p = '\0';
		}
	}
	return i;
}

// Convert a string into an array of string separated by \0
// And the last by \0\0
// Separates by words and skip spaces.
// Returns the number of tokens that the string is tokenized into.
RZ_API int rz_str_word_set0(char *str) {
	int i, quote = 0;
	char *p;
	if (!str || !*str) {
		return 0;
	}
	for (i = 0; str[i] && str[i + 1]; i++) {
		if (i > 0 && str[i - 1] == ' ' && str[i] == ' ') {
			int len = strlen(str + i);
			memmove(str + i, str + i + 1, len);
			i--;
		}
	}
	if (str[i] == ' ') {
		str[i] = 0;
	}
	for (i = 1, p = str; *p; p++) {
		if (*p == '\"') {
			if (quote) {
				quote = 0;
				*p = '\0';
				// FIX: i++;
				continue;
			} else {
				quote = 1;
				memmove(p, p + 1, strlen(p + 1) + 1);
			}
		}
		if (quote) {
			continue;
		}
		if (*p == ' ') {
			char *q = p - 1;
			if (p > str && (*q == '\\' || !*q)) {
				memmove(p, p + 1, strlen(p + 1) + 1);
				if (*q == '\\') {
					*q = ' ';
					continue;
				}
				p--;
			}
			i++;
			*p = '\0';
		} // s/ /\0/g
	}
	return i;
}

RZ_API int rz_str_word_set0_stack(char *str) {
	int i;
	char *p, *q;
	RzStack *s;
	void *pop;
	if (!str || !*str) {
		return 0;
	}
	for (i = 0; str[i] && str[i + 1]; i++) {
		if (i > 0 && str[i - 1] == ' ' && str[i] == ' ') {
			memmove(str + i, str + i + 1, strlen(str + i));
			i--;
		}
		if (i == 0 && str[i] == ' ') {
			memmove(str + i, str + i + 1, strlen(str + i));
		}
	}
	if (str[i] == ' ') {
		str[i] = 0;
	}
	s = rz_stack_new(5); // Some random number
	for (i = 1, p = str; *p; p++) {
		q = p - 1;
		if (p > str && (*q == '\\')) {
			memmove(q, p, strlen(p) + 1);
			p--;
			continue;
		}
		switch (*p) {
		case '(':
		case '{':
		case '[':
			rz_stack_push(s, (void *)p);
			continue;
		case '\'':
		case '"':
			pop = rz_stack_pop(s);
			if (pop && *(char *)pop != *p) {
				rz_stack_push(s, pop);
				rz_stack_push(s, (void *)p);
			} else if (!pop) {
				rz_stack_push(s, (void *)p);
			}
			continue;
		case ')':
		case '}':
		case ']':
			pop = rz_stack_pop(s);
			if (pop) {
				if ((*(char *)pop == '(' && *p == ')') ||
					(*(char *)pop == '{' && *p == '}') ||
					(*(char *)pop == '[' && *p == ']')) {
					continue;
				}
			}
			break;
		case ' ':
			if (p > str && !*q) {
				memmove(p, p + 1, strlen(p + 1) + 1);
				if (*q == '\\') {
					*q = ' ';
					continue;
				}
				p--;
			}
			if (rz_stack_is_empty(s)) {
				i++;
				*p = '\0';
			}
		default:
			break;
		}
	}
	rz_stack_free(s);
	return i;
}

RZ_API char *rz_str_word_get0set(char *stra, int stralen, int idx, const char *newstr, int *newlen) {
	char *p = NULL;
	char *out;
	int alen, blen, nlen;
	if (!stra && !newstr) {
		return NULL;
	}
	if (stra) {
		p = (char *)rz_str_word_get0(stra, idx);
	}
	if (!p) {
		int nslen = strlen(newstr);
		out = malloc(nslen + 1);
		if (!out) {
			return NULL;
		}
		strcpy(out, newstr);
		out[nslen] = 0;
		if (newlen) {
			*newlen = nslen;
		}
		return out;
	}
	alen = (size_t)(p - stra);
	blen = stralen - ((alen + strlen(p)) + 1);
	if (blen < 0) {
		blen = 0;
	}
	nlen = alen + blen + strlen(newstr);
	out = malloc(nlen + 2);
	if (!out) {
		return NULL;
	}
	if (alen > 0) {
		memcpy(out, stra, alen);
	}
	memcpy(out + alen, newstr, strlen(newstr) + 1);
	if (blen > 0) {
		memcpy(out + alen + strlen(newstr) + 1, p + strlen(p) + 1, blen + 1);
	}
	out[nlen + 1] = 0;
	if (newlen) {
		*newlen = nlen + ((blen == 0) ? 1 : 0);
	}
	return out;
}

// Get the idx'th entry of a tokenized string.
// XXX: Warning! this function is UNSAFE, check that the string has, at least,
// idx+1 tokens.
RZ_API const char *rz_str_word_get0(const char *str, int idx) {
	int i;
	const char *ptr = str;
	if (!ptr || idx < 0 /* prevent crashes with negative index */) {
		return "";
	}
	for (i = 0; i != idx; i++) {
		ptr = rz_str_word_get_next0(ptr);
	}
	return ptr;
}

// Return the number of times that the character ch appears in the string.
RZ_API int rz_str_char_count(const char *string, char ch) {
	int i, count = 0;
	for (i = 0; string[i]; i++) {
		if (string[i] == ch) {
			count++;
		}
	}
	return count;
}

static const char *skip_non_separator_chars(const char *text) {
	rz_return_val_if_fail(text, NULL);
	for (; *text && !IS_SEPARATOR(*text); text++)
		;

	return text;
}

static const char *skip_separator_chars(const char *text) {
	rz_return_val_if_fail(text, NULL);
	for (; *text && IS_SEPARATOR(*text); text++)
		;

	return text;
}

/**
 * \brief Skips over separator characters and moves to the first non-separator character in the string.
 * \param text The string to process.
 * \return A pointer to the first non-separator character in the string.
 *
 * This function iterates through the given string and skips over any separator characters until it reaches the first non-separator character.
 */
RZ_API RZ_OWN char *rz_str_skip_separator_chars(RZ_NONNULL const char *text) {
	rz_return_val_if_fail(text, NULL);
	return strdup(skip_separator_chars(text));
}

// Counts the number of words (separated by separator characters: newlines, tabs,
// return, space). See rz_util.h for more details of the IS_SEPARATOR macro.
RZ_API int rz_str_word_count(const char *string) {
	int word;
	const char *text = skip_separator_chars(string);

	for (word = 0; *text; word++) {
		text = skip_non_separator_chars(text);
		text = skip_separator_chars(text);
	}

	return word;
}

// Returns a pointer to the first instance of a character that isn't chr in a
// string.
// TODO: make this const-correct.
// XXX if the string is only made up of chr, then the pointer will just point to
// a null byte!
RZ_API char *rz_str_ichr(char *str, char chr) {
	while (*str == chr) {
		str++;
	}
	return str;
}

// Returns a pointer to the last instance of the character chr in the input
// string.
RZ_API const char *rz_str_lchr(const char *str, char chr) {
	if (str) {
		int len = strlen(str);
		for (; len >= 0; len--) {
			if (str[len] == chr) {
				return str + len;
			}
		}
	}
	return NULL;
}

/* find the last char chr in the substring str[start:end] with end not included */
RZ_API const char *rz_sub_str_lchr(RZ_NONNULL const char *str, int start, int end, char chr) {
	rz_return_val_if_fail(str, NULL);
	do {
		end--;
	} while (str[end] != chr && end >= start);
	return str[end] == chr ? &str[end] : NULL;
}

/* find the first char chr in the substring str[start:end] with end not included */
RZ_API const char *rz_sub_str_rchr(RZ_NONNULL const char *str, int start, int end, char chr) {
	rz_return_val_if_fail(str, NULL);
	while (str[start] && str[start] != chr && start < end) {
		start++;
	}
	return str[start] == chr ? str + start : NULL;
}

/* \brief Extract a substring between two pointers inside some strings
 *
 * \param str A source string
 * \param start Pointer inside the source string from where substring starts
 * \param end Pointer inside the source string where substring ends
 */
RZ_API RZ_OWN char *rz_sub_str_ptr(RZ_NONNULL const char *str, RZ_NONNULL const char *start, RZ_NONNULL const char *end) {
	rz_return_val_if_fail(str && start && end, NULL);
	ssize_t len = end - start + 1;
	if (len < 1 || len > strlen(str)) {
		return NULL;
	}
	char *result = malloc(len + 1);
	if (!result) {
		return NULL;
	}
	memcpy(result, start, len);
	result[len] = '\0';
	return result;
}

/**
 * \brief Checks if the given character string is a two byte UTF-8 character.
 *
 * \param c The character string to test.
 * \return bool True if the character string is a two byte UTF-8 character. False otherwise.
 */
RZ_API bool rz_str_is2utf8(RZ_NONNULL const char *c) {
	rz_return_val_if_fail(c, false);
	if (!c[0] || !c[1]) {
		return false;
	}
	return ((c[0] & 0xe0) == 0xc0) && ((c[1] & 0xc0) == 0x80);
}

/**
 * \brief Checks if the given character string is a three byte UTF-8 character.
 *
 * \param c The character string to test.
 * \return bool True if the character string is a three byte UTF-8 character. False otherwise.
 */
RZ_API bool rz_str_is3utf8(RZ_NONNULL const char *c) {
	rz_return_val_if_fail(c, false);
	if (!c[0] || !c[1] || !c[2]) {
		return false;
	}
	return ((c[0] & 0xf0) == 0xe0) && ((c[1] & 0xc0) == 0x80) && ((c[2] & 0xc0) == 0x80);
}

/**
 * \brief Checks if the given character string is a four byte UTF-8 character.
 *
 * \param c The character string to test.
 * \return bool True if the character string is a four byte UTF-8 character. False otherwise.
 */
RZ_API bool rz_str_is4utf8(RZ_NONNULL const char *c) {
	rz_return_val_if_fail(c, false);
	if (!c[0] || !c[1] || !c[2] || !c[3]) {
		return false;
	}
	return ((c[0] & 0xf8) == 0xf0) && ((c[1] & 0xc0) == 0x80) && ((c[2] & 0xc0) == 0x80) && ((c[3] & 0xc0) == 0x80);
}

/**
 * \brief Checks if the byte string matches the criteria of a UTF-8 character of length \p x.
 *
 * \param c The byte string to test.
 * \return bool True if the bytes match an UTF-8 character of length \p x. False otherwise.
 */
RZ_API bool rz_str_isXutf8(RZ_NONNULL const char *c, ut8 x) {
	rz_return_val_if_fail(c, false);
	switch (x) {
	default:
		return false;
	case 1:
		return isascii(c[0]);
	case 2:
		return rz_str_is2utf8(c);
	case 3:
		return rz_str_is3utf8(c);
	case 4:
		return rz_str_is4utf8(c);
	}
}

/**
 * \brief Returns a pointer to the first occurrence of UTF-8 character \p c in the string \p s.
 *
 * \param str The string to search.
 * \param c The UTF-8 character to search for.
 * \return char* A pointer to the first occurrence of \p c in the string (first from the left) or NULL if \p c was not found.
 */
RZ_API const char *rz_str_strchr(RZ_NONNULL const char *str, RZ_NONNULL const char *c) {
	rz_return_val_if_fail(str && c, NULL);
	ut32 i = 0;
	ut64 str_len = strlen(str);
	ut8 c_len = isascii(*c) ? 1 : (rz_str_is2utf8(c) ? 2 : (rz_str_is3utf8(c) ? 3 : (rz_str_is4utf8(c) ? 4 : 1)));
	while (i <= str_len && i + c_len <= str_len) {
		if (c_len == 1) {
			if (str[i] == c[0]) {
				return str + i;
			}
		} else {
			if (rz_mem_eq((ut8 *)str + i, (ut8 *)c, c_len)) {
				return str + i;
			}
		}
		++i;
	}
	return NULL;
}

RZ_API const char *rz_str_sep(const char *base, const char *sep) {
	int i;
	while (*base) {
		for (i = 0; sep[i]; i++) {
			if (*base == sep[i]) {
				return base;
			}
		}
		base++;
	}
	return NULL;
}

RZ_API const char *rz_str_rsep(const char *base, const char *p, const char *sep) {
	int i;
	while (p >= base) {
		for (i = 0; sep[i]; i++) {
			if (*p == sep[i]) {
				return p;
			}
		}
		p--;
	}
	return NULL;
}

RZ_API const char *rz_str_rstr(const char *base, const char *p) {
	char *s = strdup(base);
	char *k = strdup(p);
	rz_str_reverse(s);
	rz_str_reverse(k);
	char *q = strstr(s, k);
	const char *r = NULL;
	if (q) {
		r = base + strlen(base) - (q - s) - strlen(p);
	}
	free(s);
	free(k);
	return r;
}

RZ_API const char *rz_str_rchr(const char *base, const char *p, int ch) {
	rz_return_val_if_fail(base, NULL);
	if (!p) {
		return strrchr(base, ch);
	}
	for (; p >= base; p--) {
		if (ch == *p) {
			break;
		}
	}
	return (p >= base) ? p : NULL;
}

RZ_API const char *rz_str_nstr(const char *s, const char *find, int slen) {
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0') {
		len = strlen(find);
		do {
			do {
				if (slen-- < 1 || !(sc = *s++)) {
					return NULL;
				}
			} while (sc != c);
			if (len > slen) {
				return NULL;
			}
		} while (strncmp(s, find, len) != 0);
		s--;
	}
	return (char *)s;
}

/**
 * \brief Finds the first occurrence of \p find in \p s, ignore case.
 * \param s pointer to the string to examine
 * \param find pointer to the string to search for
 * \param slen the maximum number of characters to search
 */
RZ_API const char *rz_str_case_nstr(RZ_NONNULL const char *s, RZ_NONNULL const char *find, int slen) {
	rz_return_val_if_fail(s && find, NULL);
	char *new_s = strdup(s), *new_find = strdup(find);
	const char *res = NULL;
	rz_str_case(new_s, false);
	rz_str_case(new_find, false);
	const char *pos = rz_str_nstr(new_s, new_find, slen);
	if (pos) {
		res = s + (pos - new_s);
	}
	free(new_s);
	free(new_find);
	return res;
}

// Returns a new heap-allocated copy of str, sets str[len] to '\0'.
// If the input str is longer than len, it will be truncated.
RZ_API char *rz_str_newlen(const char *str, int len) {
	if (len < 0) {
		return NULL;
	}
	char *buf = malloc(len + 1);
	if (buf) {
		memcpy(buf, str, len);
		buf[len] = 0;
	}
	return buf;
}

RZ_API char *rz_str_trunc_ellipsis(const char *str, int len) {
	if (!str) {
		return NULL;
	}
	if (strlen(str) < len) {
		return strdup(str);
	}
	char *buf = rz_str_newlen(str, len);
	if (buf && len > 4) {
		strcpy(buf + len - 4, "...");
	}
	return buf;
}

RZ_API char *rz_str_newf(const char *fmt, ...) {
	rz_return_val_if_fail(fmt, NULL);
	va_list ap, ap2;

	va_start(ap, fmt);
	if (!strchr(fmt, '%')) {
		va_end(ap);
		return strdup(fmt);
	}
	va_copy(ap2, ap);
	int ret = vsnprintf(NULL, 0, fmt, ap2);
	ret++;
	char *p = calloc(1, ret);
	if (p) {
		(void)vsnprintf(p, ret, fmt, ap);
	}
	va_end(ap2);
	va_end(ap);
	return p;
}

/**
 * \brief Secure string copy with null terminator
 *
 * 	This API behaves like strlcpy or strscpy.
 */
RZ_API size_t rz_str_ncpy(char *dst, const char *src, size_t dst_size) {
	rz_return_val_if_fail(dst && src, 0);

	// do not do anything if dst_size is 0
	if (dst_size == 0) {
		return 0;
	}
#if HAVE_STRLCPY
	return strlcpy(dst, src, dst_size);
#else
	strncpy(dst, src, dst_size - 1);
	dst[dst_size - 1] = '\0';
	return strlen(src);
#endif
}

/* memccmp("foo.bar", "foo.cow, '.') == 0 */
// Returns 1 if src and dst are equal up until the first instance of ch in src.
RZ_API bool rz_str_ccmp(const char *dst, const char *src, int ch) {
	rz_return_val_if_fail(dst && src, false);
	int i;
	for (i = 0; src[i] && src[i] != ch; i++) {
		if (dst[i] != src[i]) {
			return true;
		}
	}
	return false;
}

// Returns true if item is in sep-separated list
RZ_API bool rz_str_cmp_list(const char *list, const char *item, char sep) {
	if (!list || !item) {
		return false;
	}
	int i = 0, j = 0;
	for (; list[i] && list[i] != sep; i++, j++) {
		if (item[j] != list[i]) {
			while (list[i] && list[i] != sep) {
				i++;
			}
			if (!list[i]) {
				return false;
			}
			j = -1;
			continue;
		}
	}
	return true;
}

// like strncmp, but checking for null pointers
RZ_API int rz_str_cmp(const char *a, const char *b, int len) {
	if ((a == b) || (!a && !b)) {
		return 0;
	}
	if (!a && b) {
		return -1;
	}
	if (a && !b) {
		return 1;
	}
	if (len < 0) {
		return strcmp(a, b);
	}
	return strncmp(a, b, len);
}

// Copies all characters from src to dst up until the character 'ch'.
RZ_API int rz_str_ccpy(char *dst, char *src, int ch) {
	int i;
	for (i = 0; src[i] && src[i] != ch; i++) {
		dst[i] = src[i];
	}
	dst[i] = '\0';
	return i;
}

/**
 * \brief Create new copy of string \p ptr limited to size \p len
 * \param[in] ptr String to create new copy from
 * \param[in] len Upper limit for new string size
 * \return New copy of string \p ptr with size limited by \p len or NULL if \p ptr is NULL
 */
RZ_API char *rz_str_ndup(RZ_NULLABLE const char *ptr, int len) {
	if (!ptr || len < 0) {
		return NULL;
	}
	const size_t str_len = rz_str_nlen(ptr, len);
	char *out = malloc(str_len + 1);
	if (!out) {
		return NULL;
	}
	memcpy(out, ptr, str_len);
	out[str_len] = 0;
	return out;
}

/**
 * \brief Duplicates a string.
 *
 * This function duplicates the given string. If the input string is NULL,
 * the function will return NULL.
 *
 * \param str The string to duplicate. Can be NULL.
 * \return A new string which is a duplicate of the input string, or NULL if the input string was NULL.
 */
RZ_API RZ_OWN char *rz_str_dup(RZ_NULLABLE const char *str) {
	return str ? strdup(str) : NULL;
}

RZ_API char *rz_str_prepend(char *ptr, const char *string) {
	int slen, plen;
	if (!ptr) {
		return strdup(string);
	}
	plen = strlen(ptr);
	slen = strlen(string);
	ptr = realloc(ptr, slen + plen + 1);
	if (!ptr) {
		return NULL;
	}
	memmove(ptr + slen, ptr, plen + 1);
	memmove(ptr, string, slen);
	return ptr;
}

RZ_API char *rz_str_appendlen(char *ptr, const char *string, int slen) {
	char *msg = rz_str_newlen(string, slen);
	char *ret = rz_str_append(ptr, msg);
	free(msg);
	return ret;
}

RZ_API char *rz_str_append_owned(char *ptr, char *string) {
	if (!ptr) {
		return string;
	}
	char *r = rz_str_append(ptr, string);
	free(string);
	return r;
}

/**
 * \brief Appends \p string to \p ptr. If \p ptr is NULL, \p string is duplicated and returned.
 * Note: If \p ptr is not NULL, it might be freed by realloc and the returned pointer
 * should be used from here on.
 *
 * \param ptr Pointer to the string to append to.
 * \param string The string to append.
 *
 * \return The concatenation of \p ptr + \p string or NULL in case of failure.
 */
RZ_API RZ_OWN char *rz_str_append(RZ_OWN RZ_NULLABLE char *ptr, const char *string) {
	if (string && !ptr) {
		return strdup(string);
	}
	if (RZ_STR_ISEMPTY(string)) {
		return ptr;
	}
	int plen = strlen(ptr);
	int slen = strlen(string);
	char *newptr = realloc(ptr, slen + plen + 1);
	if (!newptr) {
		free(ptr);
		return NULL;
	}
	ptr = newptr;
	memcpy(ptr + plen, string, slen + 1);
	return ptr;
}

/**
 * \brief Appends a formatted string to \p ptr. If \p ptr is NULL, the formatted string is returned.
 * Note: If \p ptr is not NULL, it might be freed by realloc and the returned pointer
 * should be used from here on.
 *
 * \param ptr Pointer to the string to append to.
 * \param fmt The formatting string.
 *
 * \return The concatenation of \p ptr + the formatted string or NULL in case of failure.
 */
RZ_API RZ_OWN char *rz_str_appendf(RZ_OWN RZ_NULLABLE char *ptr, const char *fmt, ...) {
	rz_return_val_if_fail(fmt, NULL);
	va_list ap, ap2;

	va_start(ap, fmt);
	if (!strchr(fmt, '%')) {
		va_end(ap);
		return rz_str_append(ptr, fmt);
	}
	va_copy(ap2, ap);
	int ret = vsnprintf(NULL, 0, fmt, ap2);
	ret++;
	char *p = calloc(1, ret);
	if (p) {
		(void)vsnprintf(p, ret, fmt, ap);
		ptr = rz_str_append(ptr, p);
		free(p);
	}
	va_end(ap2);
	va_end(ap);
	return ptr;
}

RZ_API char *rz_str_appendch(char *x, char y) {
	char b[2] = { y, 0 };
	return rz_str_append(x, b);
}

/**
 * \brief In-place replacement of string \p key with \p val in \p str.
 * In case of realloc \p str is freed and NULL is returned.
 *
 * \param str The string to replace the sub-string in.
 * \param key The sub-string to replace.
 * \param val The sub-string to replace \p key with.
 * \param g If 'i' it does an "ignore case" replacement. If 0 it replaces only the first occurance.
 *
 * \return Pointer to the given string but replaced sub_strings. And NULL in case of failure.
 */
RZ_API RZ_OWN char *rz_str_replace(RZ_OWN char *str, const char *key, const char *val, int g) {
	if (g == 'i') {
		return rz_str_replace_icase(str, key, val, g, true);
	}
	rz_return_val_if_fail(str && key && val, NULL);

	int key_off, i, str_len;
	char *newstr, *key_ptr = str;
	int key_len = strlen(key);
	int val_len = strlen(val);
	if (key_len == 1 && val_len < 2) {
		rz_str_replace_char(str, *key, *val);
		return str;
	}
	if (key_len == val_len && !strcmp(key, val)) {
		return str;
	}
	str_len = strlen(str);
	char *q = str;
	for (;;) {
		key_ptr = strstr(q, key);
		if (!key_ptr) {
			break;
		}
		key_off = (int)(size_t)(key_ptr - str);
		if (val_len != key_len) {
			int tail_len = str_len - (key_off + key_len);
			str_len += val_len - key_len;
			if (val_len > key_len) {
				newstr = realloc(str, str_len + 1);
				if (!newstr) {
					eprintf("realloc fail\n");
					RZ_FREE(str);
					return NULL;
				}
				str = newstr;
			}
			key_ptr = str + key_off;
			memmove(key_ptr + val_len, key_ptr + key_len, tail_len + 1);
		}
		memcpy(key_ptr, val, val_len);
		i = key_off + val_len;
		q = str + i;
		if (!g) {
			break;
		}
	}
	return str;
}

RZ_API char *rz_str_replace_icase(char *str, const char *key, const char *val, int g, int keep_case) {
	rz_return_val_if_fail(str && key && val, NULL);

	int off, i, klen, vlen, slen;
	char *newstr, *p = str;
	klen = strlen(key);
	vlen = strlen(val);

	slen = strlen(str);
	for (i = 0; i < slen;) {
		p = (char *)rz_str_casestr(str + i, key);
		if (!p) {
			break;
		}
		off = (int)(size_t)(p - str);
		if (vlen != klen) {
			int tlen = slen - (off + klen);
			slen += vlen - klen;
			if (vlen > klen) {
				newstr = realloc(str, slen + 1);
				if (!newstr) {
					goto alloc_fail;
				}
				str = newstr;
			}
			p = str + off;
			memmove(p + vlen, p + klen, tlen + 1);
		}

		if (keep_case) {
			char *tmp_val = strdup(val);
			char *str_case = rz_str_ndup(p, klen);
			if (!tmp_val || !str_case) {
				free(tmp_val);
				free(str_case);
				goto alloc_fail;
			}
			tmp_val = rz_str_replace_icase(tmp_val, key, str_case, 0, 0);
			free(str_case);
			if (!tmp_val) {
				goto alloc_fail;
			}
			memcpy(p, tmp_val, vlen);
			free(tmp_val);
		} else {
			memcpy(p, val, vlen);
		}

		i = off + vlen;
		if (!g) {
			break;
		}
	}
	return str;

alloc_fail:
	eprintf("alloc fail\n");
	free(str);
	return NULL;
}

/* replace the key in str with val.
 *
 * str - input string
 * clean - input string cleaned of ANSI chars
 * thunk - array of integers that map each char of the clean string into the
 *         position in the str string
 * clen  - number of elements in thunk
 * key   - string to find in the clean string
 * val   - string that replaces key in the str string
 * g     - if true, replace all occurrences of key
 *
 * It returns a pointer to the modified string */
RZ_API char *rz_str_replace_thunked(char *str, char *clean, int *thunk, int clen,
	const char *key, const char *val, int g) {
	int i, klen, vlen, slen, delta = 0, bias;
	char *newstr, *scnd, *p = clean, *str_p;

	if (!str || !key || !val || !clean || !thunk) {
		return NULL;
	}
	klen = strlen(key);
	vlen = strlen(val);
	if (klen == vlen && !strcmp(key, val)) {
		return str;
	}
	slen = strlen(str) + 1;

	for (i = 0; i < clen;) {
		p = (char *)rz_mem_mem(
			(const ut8 *)clean + i, clen - i,
			(const ut8 *)key, klen);
		if (!p) {
			break;
		}
		i = (int)(size_t)(p - clean);
		/* as the original string changes size during replacement
		 * we need delta to keep track of it*/
		str_p = str + thunk[i] + delta;

		int newo = thunk[i + klen] - thunk[i];
		rz_str_ansi_filter(str_p, NULL, NULL, newo);
		scnd = strdup(str_p + newo);
		bias = vlen - newo;

		slen += bias;
		// HACK: this 32 avoids overwrites
		newstr = realloc(str, slen + klen);
		if (!newstr) {
			eprintf("realloc fail\n");
			RZ_FREE(str);
			free(scnd);
			break;
		}
		str = newstr;
		str_p = str + thunk[i] + delta;
		memcpy(str_p, val, vlen);
		memcpy(str_p + vlen, scnd, strlen(scnd) + 1);
		i += klen;
		delta += bias;
		free(scnd);
		if (!g) {
			break;
		}
	}
	return str;
}

RZ_API char *rz_str_replace_in(char *str, ut32 sz, const char *key, const char *val, int g) {
	if (!str || !key || !val) {
		return NULL;
	}
	char *heaped = rz_str_replace(strdup(str), key, val, g);
	if (heaped) {
		strncpy(str, heaped, sz);
		free(heaped);
	}
	return str;
}

RZ_API int rz_str_unescape(char *buf) {
	unsigned char ch = 0, ch2 = 0;
	int err = 0;
	int i;

	for (i = 0; buf[i]; i++) {
		if (buf[i] != '\\') {
			continue;
		}
		int esc_seq_len = 2;
		switch (buf[i + 1]) {
		case '\\':
		case '?':
		case '$':
			buf[i] = buf[i + 1];
			break;
		case 'e':
			buf[i] = 0x1b;
			break;
		case 'r':
			buf[i] = 0x0d;
			break;
		case 'n':
			buf[i] = 0x0a;
			break;
		case 'a':
			buf[i] = 0x07;
			break;
		case 'b':
			buf[i] = 0x08;
			break;
		case 't':
			buf[i] = 0x09;
			break;
		case 'v':
			buf[i] = 0x0b;
			break;
		case 'f':
			buf[i] = 0x0c;
			break;
		case 'x':
			err = ch2 = ch = 0;
			if (!buf[i + 2] || !buf[i + 3]) {
				eprintf("Unexpected end of string.\n");
				return 0;
			}
			err |= rz_hex_to_byte(&ch, buf[i + 2]);
			err |= rz_hex_to_byte(&ch2, buf[i + 3]);
			if (err) {
				eprintf("Error: Non-hexadecimal chars in input.\n");
				return 0; // -1?
			}
			buf[i] = (ch << 4) + ch2;
			esc_seq_len = 4;
			break;
		case '\0':
			buf[i] = '\0';
			return i;
		default:
			if (IS_OCTAL(buf[i + 1])) {
				int num_digits = 1;
				buf[i] = buf[i + 1] - '0';
				if (IS_OCTAL(buf[i + 2])) {
					num_digits++;
					buf[i] = (ut8)buf[i] * 8 + (buf[i + 2] - '0');
					if (IS_OCTAL(buf[i + 3])) {
						num_digits++;
						buf[i] = (ut8)buf[i] * 8 + (buf[i + 3] - '0');
					}
				}
				esc_seq_len = 1 + num_digits;
			} else {
				buf[i] = buf[i + 1];
			}
			break;
		}
		memmove(buf + i + 1, buf + i + esc_seq_len, strlen(buf + i + esc_seq_len) + 1);
	}
	return i;
}

RZ_API void rz_str_sanitize(char *c) {
	char *d = c;
	if (d) {
		for (; *d; c++, d++) {
			switch (*d) {
			case '`':
			case '$':
			case '{':
			case '}':
			case '~':
			case '|':
			case ';':
			case '#':
			case '@':
			case '&':
			case '<':
			case '>':
				*c = '_';
				continue;
			}
		}
	}
}

RZ_API char *rz_str_sanitize_sdb_key(const char *s) {
	if (!s || !*s) {
		return NULL;
	}
	size_t len = strlen(s);
	char *ret = malloc(len + 1);
	if (!ret) {
		return NULL;
	}
	char *cur = ret;
	while (len > 0) {
		char c = *s;
		if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '_' && c != ':') {
			c = '_';
		}
		*cur = c;
		s++;
		cur++;
		len--;
	}
	*cur = '\0';
	return ret;
}

/**
 * \brief Converts unprintable characters to C-like backslash representation
 *
 * \param p pointer to the original string
 * \param dst pointer where pointer to the resulting characters sequence is put
 * \param opt pointer to encoding options structure
 **/
RZ_API void rz_str_byte_escape(const char *p, char **dst, RzStrEscOptions *opt) {
	char *q = *dst;
	switch (*p) {
	case '\n':
		*q++ = '\\';
		*q++ = opt->dot_nl ? 'l' : 'n';
		break;
	case '\r':
		*q++ = '\\';
		*q++ = 'r';
		break;
	case '\\':
		if (opt->esc_bslash) {
			*q++ = '\\';
		}
		*q++ = '\\';
		break;
	case '\t':
		*q++ = '\\';
		*q++ = 't';
		break;
	case '"':
		if (opt->esc_double_quotes) {
			*q++ = '\\';
		}
		*q++ = '"';
		break;
	case '\f':
		*q++ = '\\';
		*q++ = 'f';
		break;
	case '\b':
		*q++ = '\\';
		*q++ = 'b';
		break;
	case '\v':
		*q++ = '\\';
		*q++ = 'v';
		break;
	case '\a':
		*q++ = '\\';
		*q++ = 'a';
		break;
	case '\x1b':
		*q++ = '\\';
		*q++ = 'e';
		break;
	default:
		/* Outside the ASCII printable range */
		if (!IS_PRINTABLE(*p)) {
			if (opt->show_asciidot) {
				*q++ = '.';
			} else {
				*q++ = '\\';
				*q++ = 'x';
				*q++ = "0123456789abcdef"[*p >> 4 & 0xf];
				*q++ = "0123456789abcdef"[*p & 0xf];
			}
		} else {
			*q++ = *p;
		}
	}
	*dst = q;
}

/* Internal function. dot_nl specifies whether to convert \n into the
 * graphiz-compatible newline \l */
static RZ_OWN char *rz_str_escape_(const char *buf, bool parse_esc_seq, bool ign_esc_seq, RzStrEscOptions *opt) {
	rz_return_val_if_fail(buf, NULL);

	/* Worst case scenario, we convert every byte to a single-char escape
	 * (e.g. \n) if show_asciidot, or \xhh if !show_asciidot */
	char *new_buf = malloc(1 + strlen(buf) * (opt->show_asciidot ? 2 : 4));
	if (!new_buf) {
		return NULL;
	}
	const char *p = buf;
	char *q = new_buf;
	while (*p) {
		switch (*p) {
		case 0x1b: // ESC
			if (parse_esc_seq) {
				const char *start_seq = p;
				p++;
				/* Parse the ANSI code (only the graphic mode
				 * set ones are supported) */
				if (*p == '\0') {
					goto out;
				}
				if (*p == '[') {
					for (p++; *p != 'm'; p++) {
						if (*p == '\0') {
							goto out;
						}
					}
					if (!ign_esc_seq) {
						memcpy(q, start_seq, p - start_seq + 1);
						q += (p - start_seq + 1);
					}
				}
				break;
			}
			/* fallthrough */
		default:
			rz_str_byte_escape(p, &q, opt);
			break;
		}
		p++;
	}
out:
	*q = '\0';
	return new_buf;
}

RZ_API RZ_OWN char *rz_str_escape(RZ_NONNULL const char *buf) {
	rz_return_val_if_fail(buf, NULL);
	RzStrEscOptions opt = { 0 };
	opt.dot_nl = false;
	opt.show_asciidot = false;
	opt.esc_bslash = true;
	return rz_str_escape_(buf, true, true, &opt);
}

// Return MUST BE surrounded by double-quotes
RZ_API char *rz_str_escape_sh(const char *buf) {
	rz_return_val_if_fail(buf, NULL);
	char *new_buf = malloc(1 + strlen(buf) * 2);
	if (!new_buf) {
		return NULL;
	}
	const char *p = buf;
	char *q = new_buf;
	while (*p) {
		switch (*p) {
#if __UNIX__
		case '$':
		case '`':
#endif
		case '\\':
		case '"':
			*q++ = '\\';
			/* FALLTHRU */
		default:
			*q++ = *p++;
			break;
		}
	}
	*q = '\0';
	return new_buf;
}

RZ_API char *rz_str_escape_dot(const char *buf) {
	RzStrEscOptions opt = { 0 };
	opt.dot_nl = true;
	opt.show_asciidot = false;
	opt.esc_bslash = true;
	return rz_str_escape_(buf, true, true, &opt);
}

RZ_API char *rz_str_escape_8bit(const char *buf, bool colors, RzStrEscOptions *opt) {
	return rz_str_escape_(buf, colors, !colors, opt);
}

static char *rz_str_escape_utf(const char *buf, int buf_size, RzStrEnc enc, bool show_asciidot, bool esc_bslash, bool esc_double_quotes, bool keep_printable) {
	char *new_buf, *q;
	const char *p, *end;
	RzRune ch;
	int i, len, ch_bytes;

	if (!buf) {
		return NULL;
	}
	switch (enc) {
	case RZ_STRING_ENC_UTF16LE:
	case RZ_STRING_ENC_UTF16BE:
	case RZ_STRING_ENC_UTF32LE:
	case RZ_STRING_ENC_UTF32BE:
		if (buf_size < 0) {
			return NULL;
		}
		if (enc == RZ_STRING_ENC_UTF16LE || enc == RZ_STRING_ENC_UTF16BE) {
			end = (char *)rz_mem_mem_aligned((ut8 *)buf, buf_size, (ut8 *)"\0\0", 2, 2);
		} else {
			end = (char *)rz_mem_mem_aligned((ut8 *)buf, buf_size, (ut8 *)"\0\0\0\0", 4, 4);
		}
		if (!end) {
			end = buf + buf_size - 1; /* TODO: handle overlong strings properly */
		}
		len = end - buf;
		break;
	default:
		len = strlen(buf);
		end = buf + len;
	}
	/* Worst case scenario, we convert every byte to \xhh */
	new_buf = malloc(1 + (len * 4));
	if (!new_buf) {
		return NULL;
	}
	p = buf;
	q = new_buf;
	while (p < end) {
		switch (enc) {
		case RZ_STRING_ENC_UTF16LE:
		case RZ_STRING_ENC_UTF16BE:
		case RZ_STRING_ENC_UTF32LE:
		case RZ_STRING_ENC_UTF32BE:
			if (enc == RZ_STRING_ENC_UTF16LE || enc == RZ_STRING_ENC_UTF16BE) {
				ch_bytes = rz_utf16_decode((ut8 *)p, end - p, &ch, enc == RZ_STRING_ENC_UTF16BE);
			} else {
				ch_bytes = rz_utf32_decode((ut8 *)p, end - p, &ch, enc == RZ_STRING_ENC_UTF32BE);
			}
			if (ch_bytes == 0) {
				p++;
				continue;
			}
			break;
		default:
			ch_bytes = rz_utf8_decode((ut8 *)p, end - p, &ch);
			if (ch_bytes == 0) {
				ch_bytes = 1;
			}
		}
		if (show_asciidot && !IS_PRINTABLE(ch)) {
			*q++ = '.';
		} else if (ch_bytes > 1) {
			if (keep_printable) {
				q += rz_utf8_encode((ut8 *)q, ch);
			} else {
				*q++ = '\\';
				*q++ = ch_bytes == 4 ? 'U' : 'u';
				for (i = ch_bytes == 4 ? 6 : 2; i >= 0; i -= 2) {
					*q++ = "0123456789abcdef"[ch >> 4 * (i + 1) & 0xf];
					*q++ = "0123456789abcdef"[ch >> 4 * i & 0xf];
				}
			}
		} else {
			int offset = enc == RZ_STRING_ENC_UTF16BE ? 1 : enc == RZ_STRING_ENC_UTF32BE ? 3
												     : 0;
			RzStrEscOptions opt = { 0 };
			opt.dot_nl = false;
			opt.show_asciidot = false;
			opt.esc_bslash = esc_bslash;
			opt.esc_double_quotes = esc_double_quotes;
			rz_str_byte_escape(p + offset, &q, &opt);
		}
		switch (enc) {
		case RZ_STRING_ENC_UTF16LE:
		case RZ_STRING_ENC_UTF16BE:
			p += ch_bytes < 2 ? 2 : ch_bytes;
			break;
		case RZ_STRING_ENC_UTF32LE:
		case RZ_STRING_ENC_UTF32BE:
			p += 4;
			break;
		default:
			p += ch_bytes;
		}
	}
	*q = '\0';
	return new_buf;
}

RZ_API char *rz_str_escape_utf8(const char *buf, RzStrEscOptions *opt) {
	return rz_str_escape_utf(buf, -1, RZ_STRING_ENC_UTF8, opt->show_asciidot, opt->esc_bslash, opt->esc_double_quotes, false);
}

RZ_API char *rz_str_escape_utf8_keep_printable(const char *buf, RzStrEscOptions *opt) {
	return rz_str_escape_utf(buf, -1, RZ_STRING_ENC_UTF8, opt->show_asciidot, opt->esc_bslash, opt->esc_double_quotes, true);
}

RZ_API char *rz_str_escape_utf16le(const char *buf, int buf_size, RzStrEscOptions *opt) {
	return rz_str_escape_utf(buf, buf_size, RZ_STRING_ENC_UTF16LE, opt->show_asciidot, opt->esc_bslash, opt->esc_double_quotes, false);
}

RZ_API char *rz_str_escape_utf32le(const char *buf, int buf_size, RzStrEscOptions *opt) {
	return rz_str_escape_utf(buf, buf_size, RZ_STRING_ENC_UTF32LE, opt->show_asciidot, opt->esc_bslash, opt->esc_double_quotes, false);
}

RZ_API char *rz_str_escape_utf16be(const char *buf, int buf_size, RzStrEscOptions *opt) {
	return rz_str_escape_utf(buf, buf_size, RZ_STRING_ENC_UTF16BE, opt->show_asciidot, opt->esc_bslash, opt->esc_double_quotes, false);
}

RZ_API char *rz_str_escape_utf32be(const char *buf, int buf_size, RzStrEscOptions *opt) {
	return rz_str_escape_utf(buf, buf_size, RZ_STRING_ENC_UTF32BE, opt->show_asciidot, opt->esc_bslash, opt->esc_double_quotes, false);
}

static char *escape_utf8_for_json(const char *buf, int buf_size, bool mutf8) {
	char *new_buf, *q;
	const ut8 *p, *end;
	RzRune ch;
	int i, len, ch_bytes;

	if (!buf) {
		return NULL;
	}
	len = buf_size < 0 ? strlen(buf) : buf_size;
	end = (const ut8 *)buf + len;
	/* Worst case scenario, we convert every byte to \u00hh */
	new_buf = malloc(1 + (len * 6));
	if (!new_buf) {
		return NULL;
	}
	p = (const ut8 *)buf;
	q = new_buf;
	while (p < end) {
		ptrdiff_t bytes_left = end - p;
		ch_bytes = mutf8 ? rz_mutf8_decode(p, bytes_left, &ch) : rz_utf8_decode(p, bytes_left, &ch);
		if (ch_bytes == 1) {
			switch (*p) {
			case '\n':
				*q++ = '\\';
				*q++ = 'n';
				break;
			case '\r':
				*q++ = '\\';
				*q++ = 'r';
				break;
			case '\\':
				*q++ = '\\';
				*q++ = '\\';
				break;
			case '\t':
				*q++ = '\\';
				*q++ = 't';
				break;
			case '"':
				*q++ = '\\';
				*q++ = '"';
				break;
			case '\f':
				*q++ = '\\';
				*q++ = 'f';
				break;
			case '\b':
				*q++ = '\\';
				*q++ = 'b';
				break;
			default:
				if (!IS_PRINTABLE(*p)) {
					*q++ = '\\';
					*q++ = 'u';
					*q++ = '0';
					*q++ = '0';
					*q++ = "0123456789abcdef"[*p >> 4 & 0xf];
					*q++ = "0123456789abcdef"[*p & 0xf];
				} else {
					*q++ = *p;
				}
			}
		} else if (ch_bytes == 4) {
			if (rz_rune_is_printable(ch)) {
				// Assumes buf is UTF8-encoded
				for (i = 0; i < ch_bytes; i++) {
					*q++ = *(p + i);
				}
			} else {
				RzRune high, low;
				ch -= 0x10000;
				high = 0xd800 + (ch >> 10 & 0x3ff);
				low = 0xdc00 + (ch & 0x3ff);
				*q++ = '\\';
				*q++ = 'u';
				for (i = 2; i >= 0; i -= 2) {
					*q++ = "0123456789abcdef"[high >> 4 * (i + 1) & 0xf];
					*q++ = "0123456789abcdef"[high >> 4 * i & 0xf];
				}
				*q++ = '\\';
				*q++ = 'u';
				for (i = 2; i >= 0; i -= 2) {
					*q++ = "0123456789abcdef"[low >> 4 * (i + 1) & 0xf];
					*q++ = "0123456789abcdef"[low >> 4 * i & 0xf];
				}
			}
		} else if (ch_bytes > 1) {
			if (rz_rune_is_printable(ch)) {
				// Assumes buf is UTF8-encoded
				for (i = 0; i < ch_bytes; i++) {
					*q++ = *(p + i);
				}
			} else {
				*q++ = '\\';
				*q++ = 'u';
				for (i = 2; i >= 0; i -= 2) {
					*q++ = "0123456789abcdef"[ch >> 4 * (i + 1) & 0xf];
					*q++ = "0123456789abcdef"[ch >> 4 * i & 0xf];
				}
			}
		} else { // ch_bytes == 0
			// invalid utf-8
			ch_bytes = 1;
		}
		p += ch_bytes;
	}
	*q = '\0';
	return new_buf;
}

RZ_API char *rz_str_escape_utf8_for_json(const char *buf, int buf_size) {
	return escape_utf8_for_json(buf, buf_size, false);
}

RZ_API char *rz_str_escape_mutf8_for_json(const char *buf, int buf_size) {
	return escape_utf8_for_json(buf, buf_size, true);
}

// http://daviddeley.com/autohotkey/parameters/parameters.htm#WINCRULES
// https://docs.microsoft.com/en-us/cpp/cpp/main-function-command-line-args?redirectedfrom=MSDN&view=vs-2019#parsing-c-command-line-arguments
RZ_API char *rz_str_format_msvc_argv(size_t argc, const char **argv) {
	RzStrBuf sb;
	rz_strbuf_init(&sb);

	size_t i;
	for (i = 0; i < argc; i++) {
		if (i > 0) {
			rz_strbuf_append(&sb, " ");
		}
		const char *arg = argv[i];
		bool must_escape = strchr(arg, '\"') != NULL;
		bool must_quote = strpbrk(arg, " \t") != NULL || !*arg;
		if (!must_escape && must_quote && *arg && arg[strlen(arg) - 1] == '\\') {
			// if the last char is a bs and we would quote it, we must also escape
			must_escape = true;
		}
		if (must_quote) {
			rz_strbuf_append(&sb, "\"");
		}
		if (must_escape) {
			size_t bs_count = 0; // backslash counter
			for (; *arg; arg++) {
				switch (*arg) {
				case '\"':
					for (; bs_count; bs_count--) {
						// backslashes must be escaped iff they precede a "
						// so just duplicate the number of backslashes already printed
						rz_strbuf_append(&sb, "\\");
					}
					rz_strbuf_append(&sb, "\\\"");
					break;
				case '\\':
					bs_count++;
					rz_strbuf_append(&sb, "\\");
					break;
				default:
					bs_count = 0;
					rz_strbuf_append_n(&sb, arg, 1);
					break;
				}
			}
			if (must_quote) {
				// there will be a quote after this so we have to escape bs here as well
				for (; bs_count; bs_count--) {
					rz_strbuf_append(&sb, "\\");
				}
			}
		} else {
			rz_strbuf_append(&sb, arg);
		}
		if (must_quote) {
			rz_strbuf_append(&sb, "\"");
		}
	}

	return rz_strbuf_drain_nofree(&sb);
}

static size_t __str_ansi_length(char const *str) {
	size_t i = 1;
	if (str[0] == 0x1b) {
		if (str[1] == '[') {
			i++;
			while (str[i] && str[i] != 'J' && str[i] != 'm' && str[i] != 'H' && str[i] != 'K') {
				i++;
			}
		} else if (str[1] == '#') {
			while (str[i] && str[i] != 'q') {
				i++;
			}
		}
		if (str[i]) {
			i++;
		}
	}
	return i;
}

/* ansi helpers */
RZ_API size_t rz_str_ansi_nlen(const char *str, size_t slen) {
	size_t i = 0, len = 0;
	if (slen > 0) {
		while (str[i] && i < slen) {
			size_t chlen = __str_ansi_length(str + i);
			if (chlen == 1) {
				len++;
			}
			i += chlen;
		}
		return len > 0 ? len : 1;
	}
	while (str[i]) {
		size_t chlen = __str_ansi_length(str + i);
		if (chlen == 1) {
			len++;
		}
		i += chlen;
	}
	return len > 0 ? len : 1;
}

RZ_API size_t rz_str_ansi_len(const char *str) {
	return rz_str_ansi_nlen(str, 0);
}

RZ_API size_t rz_str_nlen(const char *str, size_t n) {
	rz_return_val_if_fail(str, 0);
#if HAVE_STRNLEN
	return strnlen(str, n);
#else
	size_t len = 0;
	while (*str && n) {
		len++;
		str++;
		n--;
	}
	return len;
#endif
}

// to handle wide string as well
// XXX can be error prone
RZ_API size_t rz_str_nlen_w(const char *str, int n) {
	size_t len = 0;
	if (str) {
		while (*str && n > 0) {
			len++;
			str++;
			if (!*str) {
				// handle wide strings
				// xx00yy00bb00
				if (n - 2 > 0) {
					if (str[2]) {
						break;
					}
				}
				str++;
			}
			n--;
		}
	}
	return len;
}

RZ_API bool rz_str_is_ascii(const char *str) {
	const ut8 *ptr;
	for (ptr = (const ut8 *)str; *ptr; ptr++) {
		if (*ptr > 0x7f) {
			return false;
		}
	}
	return true;
}

/**
 * \brief Checks if the whole string is composed of whitespace
 *
 * \param str input string
 * \return bool true if whitespace (or empty), false otherwise
 */
RZ_API bool rz_str_is_whitespace(RZ_NONNULL const char *str) {
	rz_return_val_if_fail(str, false);
	for (const char *ptr = str; *ptr != '\0'; ptr++) {
		if (!isspace(*ptr)) {
			return false;
		}
	}
	return true;
}

/**
 * \brief Returns true if the input string is correctly UTF-8-encoded.
 *
 * Goes through a null-terminated string and returns false if there is a byte
 * sequence that does not encode a valid UTF-8 code point (as determined by
 * rz_utf8_decode()). If there are no such sequences, it returns true.
 *
 * \param str Input string to check for UTF-8 validity.
 */
RZ_API bool rz_str_is_utf8(RZ_NONNULL const char *str) {
	rz_return_val_if_fail(str, false);
	const ut8 *ptr = (const ut8 *)str;
	size_t len = strlen(str);
	while (len) {
		int bytes = rz_utf8_decode(ptr, len, NULL);
		if (!bytes) {
			return false;
		}
		len -= bytes;
		ptr += bytes;
	}
	return true;
}

RZ_API bool rz_str_is_printable(const char *str) {
	while (*str) {
		int ulen = rz_utf8_decode((const ut8 *)str, strlen(str), NULL);
		if (ulen > 1) {
			str += ulen;
			continue;
		}
		if (!IS_PRINTABLE(*str)) {
			return false;
		}
		str++;
	}
	return true;
}

RZ_API bool rz_str_is_printable_limited(const char *str, int size) {
	while (size > 0 && *str) {
		int ulen = rz_utf8_decode((const ut8 *)str, strlen(str), NULL);
		if (ulen > 1) {
			str += ulen;
			continue;
		}
		if (!IS_PRINTABLE(*str)) {
			return false;
		}
		str++;
		size--;
	}
	return true;
}

RZ_API bool rz_str_is_printable_incl_newlines(const char *str) {
	while (*str) {
		int ulen = rz_utf8_decode((const ut8 *)str, strlen(str), NULL);
		if (ulen > 1) {
			str += ulen;
			continue;
		}
		if (!IS_PRINTABLE(*str)) {
			if (*str != '\r' && *str != '\n' && *str != '\t') {
				return false;
			}
		}
		str++;
	}
	return true;
}

// Length in chars of a wide string (find better name?)
RZ_API size_t rz_wstr_clen(const char *s) {
	size_t len = 0;
	if (!*s++) {
		return 0;
	}
	while (*s++ || *s++) {
		len++;
	}
	return len + 1;
}

RZ_API const char *rz_str_ansi_chrn(const char *str, size_t n) {
	int len, i, li;
	for (li = i = len = 0; str[i] && (n != len); i++) {
		size_t chlen = __str_ansi_length(str + i);
		if (chlen > 1) {
			i += chlen - 1;
		} else {
			if ((str[i] & 0xc0) != 0x80) {
				len++;
			}
			li = i;
		}
	}
	return str + li;
}

/*
 * filter out ansi CSI.
 * str - input string,
 * out - if not NULL write a pointer to the original string there,
 * cposs - if not NULL write a pointer to thunk array there
 * (*cposs)[i] is the offset of the out[i] in str
 * len - length of str
 *
 * it returns the number of normal characters found in str
 */
RZ_API int rz_str_ansi_filter(char *str, char **out, int **cposs, int len) {
	int i, j, *cps;

	if (len == 0) {
		return 0;
	}
	if (len < 0) {
		len = strlen(str);
	}
	char *tmp = malloc(len + 1);
	if (!tmp) {
		return -1;
	}
	memcpy(tmp, str, len + 1);
	cps = calloc(len + 1, sizeof(int));
	if (!cps) {
		free(tmp);
		return -1;
	}

	for (i = j = 0; i < len; i++) {
		if (tmp[i] == 0x1b) {
			size_t chlen = __str_ansi_length(str + i);
			if (chlen > 1) {
				i += chlen;
				i--;
			}
		} else {
			str[j] = tmp[i];
			cps[j] = i;
			j++;
		}
	}
	str[j] = tmp[i];

	if (out) {
		*out = tmp;
	} else {
		free(tmp);
	}

	if (cposs) {
		*cposs = cps;
	} else {
		free(cps);
	}

	return j;
}

RZ_API char *rz_str_ansi_crop(const char *str, ut32 x, ut32 y, ut32 x2, ut32 y2) {
	char *r, *rz_end, *ret;
	const char *s, *s_start;
	size_t rz_len, str_len = 0, nr_of_lines = 0;
	ut32 ch = 0, cw = 0;
	if (x2 <= x || y2 <= y || !str) {
		return strdup("");
	}
	s = s_start = str;
	while (*s) {
		str_len++;
		if (*s == '\n') {
			nr_of_lines++;
		}
		s++;
	}
	rz_len = str_len + nr_of_lines * strlen(Color_RESET) + 1;
	r = ret = malloc(rz_len);
	if (!r) {
		return NULL;
	}
	rz_end = r + rz_len;
	while (*str) {
		/* crop height */
		if (ch >= y2) {
			r--;
			break;
		}
		if (*str == '\n') {
			if (ch >= y && ch < y2) {
				const char *reset = Color_RESET "\n";
				if (strlen(reset) < (rz_end - r)) {
					const int reset_length = strlen(reset);
					memcpy(r, reset, reset_length + 1);
					r += reset_length;
				}
			}
			str++;
			ch++;
			cw = 0;
		} else {
			if (ch >= y && ch < y2) {
				if ((*str & 0xc0) == 0x80) {
					if (cw > x) {
						*r++ = *str++;
					} else {
						str++;
					}
					continue;
				}
				if (rz_str_char_fullwidth(str, str_len - (str - s_start))) {
					cw++;
					if (cw == x) {
						*r++ = ' ';
						str++;
						continue;
					}
				}
				if (*str == 0x1b && *(str + 1) == '[') {
					const char *ptr = str;
					if ((rz_end - r) > 2) {
						/* copy 0x1b and [ */
						*r++ = *str++;
						*r++ = *str++;
						for (ptr = str; *ptr && *ptr != 'J' && *ptr != 'm' && *ptr != 'H'; ptr++) {
							*r++ = *ptr;
						}
						*r++ = *ptr++;
					}
					str = ptr;
					continue;
				} else if (cw >= x && cw < x2) {
					*r++ = *str;
				}
			}
			/* skip until newline */
			if (cw >= x2) {
				while (*str && *str != '\n') {
					str++;
				}
			} else {
				str++;
			}
			cw++;
		}
	}
	*r = 0;
	return ret;
}

RZ_API size_t rz_str_utf8_codepoint(const char *s, size_t left) {
	if ((*s & 0x80) != 0x80) {
		return 0;
	} else if ((*s & 0xe0) == 0xc0 && left >= 1) {
		return ((*s & 0x1f) << 6) + (*(s + 1) & 0x3f);
	} else if ((*s & 0xf0) == 0xe0 && left >= 2) {
		return ((*s & 0xf) << 12) + ((*(s + 1) & 0x3f) << 6) + (*(s + 2) & 0x3f);
	} else if ((*s & 0xf8) == 0xf0 && left >= 3) {
		return ((*s & 0x7) << 18) + ((*(s + 1) & 0x3f) << 12) + ((*(s + 2) & 0x3f) << 6) + (*(s + 3) & 0x3f);
	}
	return 0;
}

RZ_API bool rz_str_char_fullwidth(const char *s, size_t left) {
	size_t codepoint = rz_str_utf8_codepoint(s, left);
	return (codepoint >= 0x1100 &&
		(codepoint <= 0x115f || /* Hangul Jamo init. consonants */
			codepoint == 0x2329 || codepoint == 0x232a ||
			(RZ_BETWEEN(0x2e80, codepoint, 0xa4cf) && codepoint != 0x303f) || /* CJK ... Yi */
			RZ_BETWEEN(0xac00, codepoint, 0xd7a3) || /* Hangul Syllables */
			RZ_BETWEEN(0xf900, codepoint, 0xfaff) || /* CJK Compatibility Ideographs */
			RZ_BETWEEN(0xfe10, codepoint, 0xfe19) || /* Vertical forms */
			RZ_BETWEEN(0xfe30, codepoint, 0xfe6f) || /* CJK Compatibility Forms */
			RZ_BETWEEN(0xff00, codepoint, 0xff60) || /* Fullwidth Forms */
			RZ_BETWEEN(0xffe0, codepoint, 0xffe6) ||
			RZ_BETWEEN(0x20000, codepoint, 0x2fffd) ||
			RZ_BETWEEN(0x30000, codepoint, 0x3fffd)));
}

/**
 * Returns size in bytes of the utf8 char
 * Returns 1 in case of ASCII
 * str - Pointer to buffer
 */
RZ_API size_t rz_str_utf8_charsize(const char *str) {
	rz_return_val_if_fail(str, 0);
	size_t size = 0;
	size_t length = strlen(str);
	while (size < length && size < 5) {
		size++;
		if ((str[size] & 0xc0) != 0x80) {
			break;
		}
	}
	return size < 5 ? size : 0;
}

/**
 * Returns size in bytes of the utf8 char previous to str
 * Returns 1 in case of ASCII
 * str - Pointer to leading utf8 char
 * prev_len - Length in bytes of the buffer until str
 */
RZ_API size_t rz_str_utf8_charsize_prev(const char *str, int prev_len) {
	rz_return_val_if_fail(str, 0);
	int pos = 0;
	size_t size = 0, minsize = RZ_MIN(5, prev_len);
	while (size < minsize) {
		size++;
		if ((str[--pos] & 0xc0) != 0x80) {
			break;
		}
	}
	return size < 5 ? size : 0;
}

/**
 * Returns size in bytes of the last utf8 char of the string
 * Returns 1 in case of ASCII
 * str - Pointer to buffer
 */
RZ_API size_t rz_str_utf8_charsize_last(const char *str) {
	rz_return_val_if_fail(str, 0);
	size_t len = strlen(str);
	return rz_str_utf8_charsize_prev(str + len, len);
}

RZ_API void rz_str_filter_zeroline(char *str, int len) {
	int i;
	for (i = 0; i < len && str[i]; i++) {
		if (str[i] == '\n' || str[i] == '\r') {
			break;
		}
		if (!IS_PRINTABLE(str[i])) {
			break;
		}
	}
	str[i] = 0;
}

/**
 * \brief Convert all non-printable characters in \p str with '.'
 *
 * \param str String to make printable.
 */
RZ_API void rz_str_filter(char *str) {
	size_t i;
	for (i = 0; str[i]; i++) {
		if (!IS_PRINTABLE(str[i])) {
			str[i] = '.';
		}
	}
}

RZ_API bool rz_str_glob(const char *str, const char *glob) {
	if (!glob) {
		return true;
	}
	char *begin = strchr(glob, '^');
	if (begin) {
		glob = ++begin;
	}
	while (*str) {
		if (!*glob) {
			return true;
		}
		switch (*glob) {
		case '*':
			if (!*++glob) {
				return true;
			}
			while (*str) {
				if (*glob == *str) {
					break;
				}
				str++;
			}
			break;
		case '$':
			return (*++glob == '\x00');
		case '?':
			str++;
			glob++;
			break;
		default:
			if (*glob != *str) {
				return false;
			}
			str++;
			glob++;
		}
	}
	while (*glob == '*') {
		++glob;
	}
	return ((*glob == '$' && !*glob++) || !*glob);
}

// Escape the string arg so that it is parsed as a single argument by rz_str_argv
RZ_API char *rz_str_arg_escape(const char *arg) {
	char *str;
	int dest_i = 0, src_i = 0;
	if (!arg) {
		return NULL;
	}
	str = malloc((2 * strlen(arg) + 1) * sizeof(char)); // Worse case when every character need to be escaped
	if (!str) {
		return NULL;
	}
	for (src_i = 0; arg[src_i] != '\0'; src_i++) {
		char c = arg[src_i];
		switch (c) {
		case '\'':
		case '"':
		case '\\':
		case ' ':
			str[dest_i++] = '\\';
			str[dest_i++] = c;
			break;
		default:
			str[dest_i++] = c;
			break;
		}
	}
	str[dest_i] = '\0';
	return realloc(str, (strlen(str) + 1) * sizeof(char));
}

// Unescape the string arg to its original format
RZ_API int rz_str_arg_unescape(char *arg) {
	int dest_i = 0, src_i = 0;
	if (!arg) {
		return 0;
	}
	for (src_i = 0; arg[src_i] != '\0'; src_i++) {
		char c = arg[src_i];
		if (c == '\\') {
			if (arg[++src_i] == '\0') {
				break;
			}
			arg[dest_i++] = arg[src_i];
		} else {
			arg[dest_i++] = c;
		}
	}
	arg[dest_i] = '\0';
	return dest_i;
}

RZ_API char *rz_str_path_escape(const char *path) {
	char *str;
	int dest_i = 0, src_i = 0;

	if (!path) {
		return NULL;
	}
	// Worst case when every character need to be escaped
	str = malloc((2 * strlen(path) + 1) * sizeof(char));
	if (!str) {
		return NULL;
	}

	for (src_i = 0; path[src_i] != '\0'; src_i++) {
		char c = path[src_i];
		switch (c) {
		case ' ':
			str[dest_i++] = '\\';
			str[dest_i++] = c;
			break;
		default:
			str[dest_i++] = c;
			break;
		}
	}

	str[dest_i] = '\0';
	return realloc(str, (strlen(str) + 1) * sizeof(char));
}

RZ_API int rz_str_path_unescape(char *path) {
	int i;

	for (i = 0; path[i]; i++) {
		if (path[i] != '\\') {
			continue;
		}
		if (path[i + 1] == ' ') {
			path[i] = ' ';
			memmove(path + i + 1, path + i + 2, strlen(path + i + 2) + 1);
		}
	}

	return i;
}

RZ_API char **rz_str_argv(const char *cmdline, int *_argc) {
	int argc = 0;
	int argv_len = 128; // Begin with that, argv will reallocated if necessary
	char *args; // Working buffer for writing unescaped args
	int cmdline_current = 0; // Current character index in _cmdline
	int args_current = 0; // Current character index in  args
	int arg_begin = 0; // Index of the first character of the current argument in args

	if (!cmdline) {
		return NULL;
	}

	char **argv = malloc(argv_len * sizeof(char *));
	if (!argv) {
		return NULL;
	}
	args = malloc(128 + strlen(cmdline) * sizeof(char)); // Unescaped args will be shorter, so strlen (cmdline) will be enough
	if (!args) {
		free(argv);
		return NULL;
	}
	do {
		// States for parsing args
		int escaped = 0;
		int singlequoted = 0;
		int doublequoted = 0;

		// Seek the beginning of next argument (skip whitespaces)
		while (cmdline[cmdline_current] != '\0' && IS_WHITECHAR(cmdline[cmdline_current])) {
			cmdline_current++;
		}

		if (cmdline[cmdline_current] == '\0') {
			break; // No more arguments
		}
		// Read the argument
		while (1) {
			char c = cmdline[cmdline_current];
			int end_of_current_arg = 0;
			if (escaped) {
				switch (c) {
				case '\'':
				case '"':
				case ' ':
				case '\\':
					args[args_current++] = '\\';
					args[args_current++] = c;
					break;
				case '\0':
					args[args_current++] = '\\';
					end_of_current_arg = 1;
					break;
				default:
					args[args_current++] = '\\';
					args[args_current++] = c;
				}
				escaped = 0;
			} else {
				switch (c) {
				case '\'':
					if (doublequoted) {
						args[args_current++] = c;
					} else {
						singlequoted = !singlequoted;
					}
					break;
				case '"':
					if (singlequoted) {
						args[args_current++] = c;
					} else {
						doublequoted = !doublequoted;
					}
					break;
				case '\\':
					escaped = 1;
					break;
				case ' ':
					if (singlequoted || doublequoted) {
						args[args_current++] = c;
					} else {
						end_of_current_arg = 1;
					}
					break;
				case '\0':
					end_of_current_arg = 1;
					break;
				default:
					args[args_current++] = c;
				}
			}
			if (end_of_current_arg) {
				break;
			}
			cmdline_current++;
		}
		args[args_current++] = '\0';
		argv[argc++] = strdup(&args[arg_begin]);
		if (argc >= argv_len) {
			argv_len *= 2;
			char **tmp = realloc(argv, argv_len * sizeof(char *));
			if (!tmp) {
				free(args);
				free(argv);
				return NULL;
			}
			argv = tmp;
		}
		arg_begin = args_current;
	} while (cmdline[cmdline_current++] != '\0');
	argv[argc] = NULL;
	char **tmp = realloc(argv, (argc + 1) * sizeof(char *));
	if (tmp) {
		argv = tmp;
	} else {
		free(argv);
		argv = NULL;
	}
	if (_argc) {
		*_argc = argc;
	}
	free(args);
	return argv;
}

RZ_API void rz_str_argv_free(char **argv) {
	int argc = 0;
	if (!argv) {
		return;
	}
	while (argv[argc]) {
		free(argv[argc++]);
	}
	free(argv);
}

RZ_API const char *rz_str_firstbut(const char *s, char ch, const char *but) {
	int idx, _b = 0;
	ut8 *b = (ut8 *)&_b;
	const char *isbut, *p;
	const int bsz = sizeof(_b) * 8;
	if (!but) {
		return strchr(s, ch);
	}
	if (strlen(but) >= bsz) {
		eprintf("rz_str_firstbut: but string too long\n");
		return NULL;
	}
	for (p = s; *p; p++) {
		isbut = strchr(but, *p);
		if (isbut) {
			idx = (int)(size_t)(isbut - but);
			_b = RZ_BIT_TOGGLE(b, idx);
			continue;
		}
		if (*p == ch && !_b) {
			return p;
		}
	}
	return NULL;
}

RZ_API const char *rz_str_lastbut(const char *s, char ch, const char *but) {
	int idx, _b = 0;
	ut8 *b = (ut8 *)&_b;
	const char *isbut, *p, *lp = NULL;
	const int bsz = sizeof(_b) * 8;
	if (!but) {
		return rz_str_lchr(s, ch);
	}
	if (strlen(but) >= bsz) {
		eprintf("rz_str_lastbut: but string too long\n");
		return NULL;
	}
	for (p = s; *p; p++) {
		isbut = strchr(but, *p);
		if (isbut) {
			idx = (int)(size_t)(isbut - but);
			_b = RZ_BIT_TOGGLE(b, idx);
			continue;
		}
		if (*p == ch && !_b) {
			lp = p;
		}
	}
	return lp;
}

// Must be merged inside strlen
RZ_API size_t rz_str_len_utf8char(const char *s, int left) {
	size_t i = 1;
	while (s[i] && (!left || i < left)) {
		if ((s[i] & 0xc0) != 0x80) {
			i++;
		} else {
			break;
		}
	}
	return i;
}

RZ_API size_t rz_str_len_utf8(const char *s) {
	size_t i = 0, j = 0, fullwidths = 0;
	while (s[i]) {
		if ((s[i] & 0xc0) != 0x80) {
			j++;
			if (rz_str_char_fullwidth(s + i, 4)) {
				fullwidths++;
			}
		}
		i++;
	}
	return j + fullwidths;
}

RZ_API size_t rz_str_len_utf8_ansi(const char *str) {
	int i = 0, len = 0, fullwidths = 0;
	while (str[i]) {
		char ch = str[i];
		size_t chlen = __str_ansi_length(str + i);
		if (chlen > 1) {
			i += chlen - 1;
		} else if ((ch & 0xc0) != 0x80) { // utf8
			len++;
			if (rz_str_char_fullwidth(str + i, chlen)) {
				fullwidths++;
			}
		}
		i++;
	}
	return len + fullwidths;
}

// XXX must find across the ansi tags, as well as support utf8
/**
 * \brief Finds the first occurrence of \p b in \p a, skip ansi sequence.
 * \param a pointer to the string to examine
 * \param b pointer to the string to search for
 * \param icase whether ignore case
 */
RZ_API const char *rz_strstr_ansi(RZ_NONNULL const char *a, RZ_NONNULL const char *b, bool icase) {
	rz_return_val_if_fail(a && b, NULL);
	const char *ch, *p = a;
	do {
		ch = strchr(p, '\x1b');
		if (ch) {
			const char *v;
			if (icase) {
				v = rz_str_case_nstr(p, b, ch - p);
			} else {
				v = rz_str_nstr(p, b, ch - p);
			}
			if (v) {
				return v;
			}
			p = ch + __str_ansi_length(ch);
		}
	} while (ch);
	if (icase) {
		return rz_str_casestr(p, b);
	}
	return strstr(p, b);
}

RZ_API const char *rz_str_casestr(const char *a, const char *b) {
	// That's a GNUism that works in many places.. but we don't want it
	// return strcasestr (a, b);
	size_t hay_len = strlen(a);
	size_t needle_len = strlen(b);
	if (!needle_len) {
		return a;
	}
	while (hay_len >= needle_len) {
		if (!rz_str_ncasecmp(a, b, needle_len)) {
			return (const char *)a;
		}
		a++;
		hay_len--;
	}
	return NULL;
}

RZ_API int rz_str_write(int fd, const char *b) {
	return write(fd, b, strlen(b));
}

RZ_API void rz_str_range_foreach(const char *r, RzStrRangeCallback cb, void *u) {
	const char *p = r;
	for (; *r; r++) {
		if (*r == ',') {
			cb(u, atoi(p));
			p = r + 1;
		}
		if (*r == '-') {
			if (p != r) {
				int from = atoi(p);
				int to = atoi(r + 1);
				for (; from <= to; from++) {
					cb(u, from);
				}
			} else {
				fprintf(stderr, "Invalid range\n");
			}
			for (r++; *r && *r != ',' && *r != '-'; r++) {
				;
			}
			p = r;
		}
	}
	if (*p) {
		cb(u, atoi(p));
	}
}

RZ_API bool rz_str_range_in(const char *r, ut64 addr) {
	const char *p = r;
	if (!r) {
		return false;
	}
	for (; *r; r++) {
		if (*r == ',') {
			if (addr == rz_num_get(NULL, p)) {
				return true;
			}
			p = r + 1;
		}
		if (*r == '-') {
			if (p != r) {
				ut64 from = rz_num_get(NULL, p);
				ut64 to = rz_num_get(NULL, r + 1);
				if (addr >= from && addr <= to) {
					return true;
				}
			} else {
				fprintf(stderr, "Invalid range\n");
			}
			for (r++; *r && *r != ',' && *r != '-'; r++) {
				;
			}
			p = r;
		}
	}
	if (*p) {
		if (addr == rz_num_get(NULL, p)) {
			return true;
		}
	}
	return false;
}

// convert from html escaped sequence "foo%20bar" to "foo bar"
// TODO: find better name.. unencode? decode
RZ_API void rz_str_uri_decode(char *s) {
	int n;
	char *d;
	for (d = s; *s; s++, d++) {
		if (*s == '%') {
			sscanf(s + 1, "%02x", &n);
			*d = n;
			s += 2;
		} else {
			*d = *s;
		}
	}
	*d = 0;
}

RZ_API char *rz_str_uri_encode(const char *s) {
	char ch[4], *d, *od;
	if (!s) {
		return NULL;
	}
	od = d = malloc(1 + (strlen(s) * 4));
	if (!d) {
		return NULL;
	}
	for (; *s; s++) {
		if ((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z')) {
			*d++ = *s;
		} else {
			*d++ = '%';
			snprintf(ch, sizeof(ch), "%02x", 0xff & ((ut8)*s));
			*d++ = ch[0];
			*d++ = ch[1];
		}
	}
	*d = 0;
	char *trimDown = realloc(od, strlen(od) + 1); // FIT
	return trimDown ? trimDown : od;
}

RZ_API int rz_str_utf16_to_utf8(ut8 *dst, int len_dst, const ut8 *src, int len_src, bool little_endian) {
	ut8 *outstart = dst;
	ut8 *outend = dst + len_dst;
	ut16 *in = (ut16 *)src;
	ut16 *inend;
	ut32 c, d, inlen;
	int bits;

	if ((len_src % 2) == 1) {
		len_src--;
	}
	inlen = len_src / 2;
	inend = in + inlen;
	while ((in < inend) && (dst - outstart + 5 < len_dst)) {
		c = rz_read_ble16((const ut8 *)in, !little_endian);
		in++;
		if ((c & 0xFC00) == 0xD800) { /* surrogates */
			if (in >= inend) { /* (in > inend) shouldn't happens */
				break;
			}
			d = rz_read_ble16((const ut8 *)in, !little_endian);
			in++;
			if ((d & 0xFC00) == 0xDC00) {
				c &= 0x03FF;
				c <<= 10;
				c |= d & 0x03FF;
				c += 0x10000;
			} else {
				return -2;
			}
		}

		/* assertion: c is a single UTF-4 value */
		if (dst >= outend) {
			break;
		}
		if (c < 0x80) {
			*dst++ = c;
			bits = -6;
		} else if (c < 0x800) {
			*dst++ = ((c >> 6) & 0x1F) | 0xC0;
			bits = 0;
		} else if (c < 0x10000) {
			*dst++ = ((c >> 12) & 0x0F) | 0xE0;
			bits = 6;
		} else {
			*dst++ = ((c >> 18) & 0x07) | 0xF0;
			bits = 12;
		}

		for (; bits >= 0; bits -= 6) {
			if (dst >= outend) {
				break;
			}
			*dst++ = ((c >> bits) & 0x3F) | 0x80;
		}
	}
	len_dst = dst - outstart;
	return len_dst;
}

RZ_API char *rz_str_utf16_decode(const ut8 *s, int len) {
	int i = 0;
	int j = 0;
	char *result = NULL;
	int count_unicode = 0;
	int count_ascii = 0;
	int lenresult = 0;
	if (!s) {
		return NULL;
	}
	for (i = 0; i < len && (s[i] || s[i + 1]); i += 2) {
		if (!s[i + 1] && 0x20 <= s[i] && s[i] <= 0x7E) {
			++count_ascii;
		} else {
			++count_unicode;
		}
	}
	lenresult = 1 + count_ascii + count_unicode * 6; // len("\\uXXXX") = 6
	if (!(result = calloc(1 + count_ascii + count_unicode * 6, 1))) {
		return NULL;
	}
	for (i = 0; i < len && j < lenresult && (s[i] || s[i + 1]); i += 2) {
		if (!s[i + 1] && IS_PRINTABLE(s[i])) {
			result[j++] = s[i];
		} else {
			j += snprintf(&result[j], lenresult - j, "\\u%.2" HHXFMT "%.2" HHXFMT "", s[i], s[i + 1]);
		}
	}
	return result;
}

// TODO: kill this completely, it makes no sense:
RZ_API char *rz_str_utf16_encode(const char *s, int len) {
	int i;
	char ch[4], *d, *od, *tmp;
	if (!s) {
		return NULL;
	}
	if (len < 0) {
		len = strlen(s);
	}
	if ((len * 7) + 1 < len) {
		return NULL;
	}
	od = d = malloc(1 + (len * 7));
	if (!d) {
		return NULL;
	}
	for (i = 0; i < len; s++, i++) {
		if (*s == '\\') {
			*d++ = '\\';
			*d++ = '\\';
		} else if (*s == '"') {
			*d++ = '\\';
			*d++ = '"';
		} else if ((*s >= 0x20) && (*s <= 126)) {
			*d++ = *s;
		} else {
			*d++ = '\\';
			//	*d++ = '\\';
			*d++ = 'u';
			*d++ = '0';
			*d++ = '0';
			snprintf(ch, sizeof(ch), "%02x", 0xff & ((ut8)*s));
			*d++ = ch[0];
			*d++ = ch[1];
		}
	}
	*d = 0;
	tmp = realloc(od, strlen(od) + 1); // FIT
	if (!tmp) {
		free(od);
		return NULL;
	}
	return tmp;
}

RZ_API char *rz_str_prefix_all(const char *s, const char *pfx) {
	const char *os = s;
	char *p;
	int newlines = 1;
	int len = 0;
	int pfx_len = 0;

	if (!s) {
		return strdup(pfx);
	}
	if (!pfx) {
		return strdup(s);
	}
	len = strlen(s);
	pfx_len = strlen(pfx);
	for (os = s; *os; os++) {
		if (*os == '\n') {
			newlines++;
		}
	}
	char *o = malloc(len + (pfx_len * newlines) + 1);
	if (!o) {
		return NULL;
	}
	memcpy(o, pfx, pfx_len);
	for (p = o + pfx_len; *s; s++) {
		*p++ = *s;
		if (*s == '\n' && s[1]) {
			memcpy(p, pfx, pfx_len);
			p += pfx_len;
		}
	}
	*p = 0;
	return o;
}

#define HASCH(x) strchr(input_value, x)
#define CAST     (void *)(size_t)
RZ_API ut8 rz_str_contains_macro(const char *input_value) {
	char *has_tilde = input_value ? HASCH('~') : NULL,
	     *has_bang = input_value ? HASCH('!') : NULL,
	     *has_brace = input_value ? CAST(HASCH('[') || HASCH(']')) : NULL,
	     *has_paren = input_value ? CAST(HASCH('(') || HASCH(')')) : NULL,
	     *has_cbrace = input_value ? CAST(HASCH('{') || HASCH('}')) : NULL,
	     *has_qmark = input_value ? HASCH('?') : NULL,
	     *has_colon = input_value ? HASCH(':') : NULL,
	     *has_at = input_value ? strchr(input_value, '@') : NULL;

	return has_tilde || has_bang || has_brace || has_cbrace || has_qmark || has_paren || has_colon || has_at;
}

RZ_API void rz_str_truncate_cmd(char *string) {
	ut32 pos = 0;
	if (string && *string) {
		ut32 sz = strlen(string);
		for (pos = 0; pos < sz; pos++) {
			switch (string[pos]) {
			case '!':
			case ':':
			case ';':
			case '@':
			case '~':
			case '(':
			case '[':
			case '{':
			case '?':
				string[pos] = '\0';
				return;
			}
		}
	}
}

RZ_API const char *rz_str_closer_chr(const char *b, const char *s) {
	const char *a;
	while (*b) {
		for (a = s; *a; a++) {
			if (*b == *a) {
				return b;
			}
		}
		b++;
	}
	return NULL;
}

RZ_API int rz_str_bounds(const char *_str, int *h) {
	const char *str, *ptr;
	int W = 0, H = 0;
	int cw = 0;

	if (_str) {
		ptr = str = _str;
		while (*str) {
			if (*str == '\n') {
				H++;
				cw = rz_str_ansi_nlen(ptr, (size_t)(str - ptr));
				if (cw > W) {
					W = cw;
				}
				cw = 0;
				ptr = str + 1;
			}
			str++;
			cw++;
		}
		if (*str == '\n') { // skip last newline
			H--;
		}
		if (h) {
			*h = H;
		}
	}
	return W;
}

/* crop a string like it is in a rectangle with the upper-left corner at (x, y)
 * coordinates and the bottom-right corner at (x2, y2) coordinates. The result
 * is a newly allocated string, that should be deallocated by the user */
RZ_API char *rz_str_crop(const char *str, unsigned int x, unsigned int y,
	unsigned int x2, unsigned int y2) {
	char *r, *ret;
	unsigned int ch = 0, cw = 0;
	if (x2 < 1 || y2 < 1 || !str) {
		return strdup("");
	}
	r = ret = strdup(str);
	while (*str) {
		/* crop height */
		if (ch >= y2) {
			r--;
			break;
		}

		if (*str == '\n') {
			if (ch >= y && ch < y2) {
				*r++ = *str;
			}
			str++;
			ch++;
			cw = 0;
		} else {
			if (ch >= y && ch < y2 && cw >= x && cw < x2) {
				*r++ = *str;
			}
			/* crop width */
			/* skip until newline */
			if (cw >= x2) {
				while (*str && *str != '\n') {
					str++;
				}
			} else {
				str++;
			}
			cw++;
		}
	}
	*r = 0;
	return ret;
}

RZ_API const char *rz_str_tok(const char *str1, const char b, size_t len) {
	const char *p = str1;
	size_t i = 0;
	if (!p || !*p) {
		return p;
	}
	if (len == -1) {
		len = strlen(str1);
	}
	for (; i < len; i++, p++) {
		if (*p == b) {
			break;
		}
	}
	if (i == len) {
		p = NULL;
	}
	return p;
}

RZ_API int rz_str_do_until_token(str_operation op, char *str, const char tok) {
	int ret;
	if (!str) {
		return -1;
	}
	if (!op) {
		for (ret = 0; (str[ret] != tok) && str[ret]; ret++) {
			// empty body
		}
	} else {
		for (ret = 0; (str[ret] != tok) && str[ret]; ret++) {
			op(str + ret);
		}
	}
	return ret;
}

RZ_API RZ_OWN char *rz_str_pad(const char ch, int sz) {
	if (sz < 0) {
		sz = 0;
	}
	char *pad = malloc(sz + 1);
	if (!pad) {
		return NULL;
	}
	memset(pad, ch, sz);
	pad[sz] = 0;
	return pad;
}

/**
 * \brief Repeats specified \p str string \p times
 */
RZ_API RZ_OWN char *rz_str_repeat(const char *str, ut16 times) {
	rz_return_val_if_fail(str, NULL);
	int i;
	if (times == 0) {
		return strdup("");
	}
	RzStrBuf *buf = rz_strbuf_new(str);
	for (i = 1; i < times; i++) {
		rz_strbuf_append(buf, str);
	}
	return rz_strbuf_drain(buf);
}

RZ_API char *rz_str_between(const char *cmt, const char *prefix, const char *suffix) {
	char *c0, *c1;
	if (!cmt || !prefix || !suffix || !*cmt) {
		return NULL;
	}
	c0 = strstr(cmt, prefix);
	if (c0) {
		c1 = strstr(c0 + strlen(prefix), suffix);
		if (c1) {
			return rz_str_ndup(c0 + strlen(prefix), (c1 - c0 - strlen(prefix)));
		}
	}
	return NULL;
}

/**
 * \brief Checks if a string starts with a specifc sequence of characters (case sensitive)
 * \param str C-string to be scanned
 * \param needle C-string containing the sequence of characters to match
 * \return True if \p needle is found at the beginning of \p str and false otherwise
 * \see rz_str_startswith_icase()
 */
RZ_API bool rz_str_startswith(RZ_NONNULL const char *str, RZ_NONNULL const char *needle) {
	rz_return_val_if_fail(str && needle, false);
	if (str == needle) {
		return true;
	}
	return !strncmp(str, needle, strlen(needle));
}

/**
 * \brief Checks if a string starts with a specifc sequence of characters (case insensitive)
 * \param str C-string to be scanned
 * \param needle C-string containing the sequence of characters to match
 * \return True if \p needle is found at the beginning of \p str and false otherwise
 * \see rz_str_startswith()
 */
RZ_API bool rz_str_startswith_icase(RZ_NONNULL const char *str, RZ_NONNULL const char *needle) {
	rz_return_val_if_fail(str && needle, false);
	if (str == needle) {
		return true;
	}
	return !rz_str_ncasecmp(str, needle, strlen(needle));
}

static bool str_endswith(RZ_NONNULL const char *str, RZ_NONNULL const char *needle, bool case_sensitive) {
	rz_return_val_if_fail(str && needle, false);
	if (!*needle) {
		return true;
	}
	int slen = strlen(str);
	int nlen = strlen(needle);
	if (!slen || !nlen || slen < nlen) {
		return false;
	}
	return case_sensitive ? !strcmp(str + (slen - nlen), needle) : !rz_str_ncasecmp(str + (slen - nlen), needle, nlen);
}

/**
 * \brief Checks if a string ends with a specifc sequence of characters (case sensitive)
 * \param str C-string to be scanned
 * \param needle C-string containing the sequence of characters to match
 * \return True if \p needle is found at the end of \p str and false otherwise
 * \see rz_str_endswith_icase()
 */
RZ_API bool rz_str_endswith(RZ_NONNULL const char *str, RZ_NONNULL const char *needle) {
	return str_endswith(str, needle, true);
}

/**
 * \brief Checks if a string ends with a specifc sequence of characters (case insensitive)
 * \param str C-string to be scanned
 * \param needle C-string containing the sequence of characters to match
 * \return True if \p needle is found at the end of \p str and false otherwise
 * \see rz_str_endswith()
 */
RZ_API bool rz_str_endswith_icase(RZ_NONNULL const char *str, RZ_NONNULL const char *needle) {
	return str_endswith(str, needle, false);
}

static RzList /*<char *>*/ *str_split_list_common(char *str, const char *c, int n, bool trim, bool dup) {
	rz_return_val_if_fail(str && c, NULL);
	RzList *lst = rz_list_newf(dup ? free : NULL);
	char *aux = str;
	int i = 0;
	char *e = aux;
	size_t clen = strlen(c);
	for (; e;) {
		e = strstr(aux, c);
		if (n > 0 && ++i > n) {
			rz_list_append(lst, dup ? strdup(aux) : aux);
			break;
		}
		if (e) {
			*e = 0;
			e += clen;
		}
		if (trim) {
			rz_str_trim(aux);
		}
		rz_list_append(lst, dup ? strdup(aux) : aux);
		aux = e;
	}
	return lst;
}

static RzList /*<char *>*/ *str_split_list_common_regex(RZ_BORROW char *str, RZ_BORROW RzRegex *r, int n, bool trim, bool dup) {
	rz_return_val_if_fail(str && r, NULL);
	RzList *lst = rz_list_newf(dup ? free : NULL);
	char *aux;
	int i = 0;
	int s = 0, e = 0;
	int j = 0;
	void **it;
	RzPVector *matches = rz_regex_match_all(r, str, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	rz_pvector_foreach (matches, it) {
		RzPVector *m = (RzPVector *)*it;
		RzRegexMatch *group0 = rz_pvector_head(m);
		if (n == i && n > 0) {
			break;
		}
		s = group0->start; // Match start (inclusive) in string str + j
		e = group0->start + group0->len; // Match end (exclusive) in string str + j
		if (dup) {
			aux = rz_str_ndup(str + j, s - j);
		} else {
			// Overwrite split chararcters.
			memset(str + s, 0, e - s);
			aux = str + j;
		}
		if (trim) {
			rz_str_trim(aux);
		}
		rz_list_append(lst, aux);
		j = e;
		++i;
	}
	rz_pvector_free(matches);
	if (*(str + j) == 0 || (n == i && n > 0) || rz_list_length(lst) == 0) {
		// No token left.
		return lst;
	}

	if (dup) {
		aux = rz_str_ndup(str + j, strlen(str + j));
	} else {
		// Overwrite split chararcters.
		memset(str + j + s, 0, e - s);
		aux = str + j;
	}
	if (trim) {
		rz_str_trim(aux);
	}
	rz_list_append(lst, aux);

	return lst;
}

/**
 * \brief Split the string \p str according to the substring \p c and returns a \p RzList with the result.
 *
 * Split a string \p str according to the delimiter specified in \p c and it
 * considers at most \p n delimiters. The result is a \p RzList with pointers
 * to the input string \p str. Each token is trimmed as well.
 *
 * \param str Input string to split. It will be modified by this function.
 * \param c Delimiter string used to split \p str
 * \param n If > 0 at most this number of delimiters are considered.
 */
RZ_API RzList /*<char *>*/ *rz_str_split_list(char *str, const char *c, int n) {
	rz_return_val_if_fail(str && c, NULL);
	return str_split_list_common(str, c, n, true, false);
}

/**
 * \brief Split the string \p str according to the regex \p r and returns a \p RzList with the result.
 *
 * Split a string \p str according to the regex specified in \p r and it
 * considers at most \p n delimiters. The result is a \p RzList with pointers
 * to the input string \p str.
 *
 * \param str Input string to split. It will be modified by this function.
 * \param r Delimiter regex used to split \p str
 * \param n If > 0 at most this number of delimiters are considered.
 */
RZ_API RZ_OWN RzList /*<char *>*/ *rz_str_split_list_regex(RZ_NONNULL char *str, RZ_NONNULL const char *r, int n) {
	rz_return_val_if_fail(str && r, NULL);
	RzRegex *regex = rz_regex_new(r, RZ_REGEX_EXTENDED, 0);
	RzList *res = str_split_list_common_regex(str, regex, n, false, false);
	rz_regex_free(regex);
	return res;
}

/**
 * \brief Split the string \p str on 2 parts according to the first occurence of the substring \p r . Result is stored in the \p first_half , \p second_half .
 *
 * \param str Input string to split
 * \param c Delimiter string used to split \p str
 * \param trim If true each half is trimmed after split
 * \return true on success
 */
RZ_API RZ_OWN bool rz_str_split_by_first_dupstr(RZ_NONNULL const char *_str, RZ_NONNULL const char *r, bool trim, char **first_half, char **second_half) {
	char *str = strdup(_str);
	if (!str) {
		return false;
	}

	char *e = strstr(str, r);

	if (!e) {
		return false;
	}

	*e = '\0';

	char *_first_half = str;
	char *_second_half = e + strlen(r);

	if (trim) {
		rz_str_trim(_first_half);
		rz_str_trim(_second_half);
	}

	*first_half = strdup(_first_half);
	*second_half = strdup(_second_half);

	free(str);

	return true;
}

/**
 * \brief Split the string \p str according to the substring \p c and returns a \p RzList with the result.
 *
 * Split a string \p str according to the delimiter specified in \p c. It can
 * optionally trim (aka remove spaces) the tokens. The result is a \p RzList
 * with newly allocated strings for each token.
 *
 * \param str Input string to split
 * \param c Delimiter string used to split \p str
 * \param trim If true each token is considered without trailing/leading whitespaces.
 */
RZ_API RzList /*<char *>*/ *rz_str_split_duplist(const char *_str, const char *c, bool trim) {
	rz_return_val_if_fail(_str && c, NULL);
	char *str = strdup(_str);
	RzList *res = str_split_list_common(str, c, 0, trim, true);
	free(str);
	return res;
}

/**
 * \brief Split the string \p str according to the substring \p c and returns a \p RzList with the result.
 *
 * Split a string \p str according to the delimiter specified in \p c. It can
 * optionally trim (aka remove spaces) the tokens and/or consider at most \p n
 * delimiters. The result is a \p RzList with newly allocated strings for each
 * token.
 *
 * \param str Input string to split
 * \param c Delimiter string used to split \p str
 * \param n If > 0 at most this number of delimiters are considered.
 * \param trim If true each token is considered without trailing/leading whitespaces.
 */
RZ_API RzList /*<char *>*/ *rz_str_split_duplist_n(const char *_str, const char *c, int n, bool trim) {
	rz_return_val_if_fail(_str && c, NULL);
	char *str = strdup(_str);
	RzList *res = str_split_list_common(str, c, n, trim, true);
	free(str);
	return res;
}

/**
 * \brief Split the string \p str according to the regex \p r and returns a \p RzList with the result.
 *
 * Split a string \p str according to the regex specified in \p r. It can
 * optionally trim (aka remove spaces) the tokens and/or consider at most \p n
 * delimiters. The result is a \p RzList with newly allocated strings for each
 * token.
 *
 * \param str Input string to split
 * \param r Delimiter regex string used to split \p str
 * \param n If > 0 at most this number of delimiters are considered.
 * \param trim If true each token is considered without trailing/leading whitespaces.
 */
RZ_API RZ_OWN RzList /*<char *>*/ *rz_str_split_duplist_n_regex(RZ_NONNULL const char *_str, RZ_NONNULL const char *r, int n, bool trim) {
	rz_return_val_if_fail(_str && r, NULL);
	char *str = strdup(_str);
	RzRegex *regex = rz_regex_new(r, RZ_REGEX_EXTENDED, 0);
	RzList *res = str_split_list_common_regex(str, regex, n, trim, true);
	free(str);
	rz_regex_free(regex);
	return res;
}

/**
 * \brief Split the string \p str in lines and returns the result in an array.
 *
 * Split a string \p str in lines. The number of lines is optionally stored in
 * \p count, if not NULL. The result is an array of \p count entries, with the
 * i-th entry containing the index of the first character of the i-th line.
 *
 * \param str Input string to split
 * \param count Pointer to a size_t variable that can hold the number of lines.
 */
RZ_API size_t *rz_str_split_lines(char *str, size_t *count) {
	rz_return_val_if_fail(str, NULL);
	RzList *l = str_split_list_common(str, "\n", 0, false, false);
	if (!l) {
		return NULL;
	}
	size_t cnt = rz_list_length(l);
	size_t *res = RZ_NEWS(size_t, cnt);
	if (!res) {
		return NULL;
	}
	RzListIter *it;
	char *s;
	size_t i = 0;
	rz_list_foreach (l, it, s) {
		res[i++] = s - str;
	}
	if (count) {
		*count = cnt;
	}
	rz_list_free(l);
	return res;
}

RZ_API bool rz_str_isnumber(const char *str) {
	if (!str || (!IS_DIGIT(*str) && *str != '-')) {
		return false;
	}

	while (*++str) {
		if (!IS_DIGIT(*str)) {
			return false;
		}
	}

	return true;
}

/* TODO: optimize to start searching by the end of the string */
RZ_API const char *rz_str_last(const char *str, const char *ch) {
	char *ptr, *end = NULL;
	if (!str || !ch) {
		return NULL;
	}
	do {
		ptr = strstr(str, ch);
		if (!ptr) {
			break;
		}
		end = ptr;
		str = ptr + 1;
	} while (true);
	return end;
}

// copies the WHOLE string but check n against non color code chars only.
static int strncpy_with_color_codes(char *s1, char *s2, int n) {
	int i = 0, j = 0;
	int count = 0;
	while (s2[j] && count < n) {
		// detect (consecutive) color codes
		while (s2[j] == 0x1b) {
			// copy till 'm'
			while (s2[j] && s2[j] != 'm') {
				s1[i++] = s2[j++];
			}
			// copy 'm'
			if (s2[j]) {
				s1[i++] = s2[j++];
			}
		}
		if (s2[j]) {
			s1[i++] = s2[j++];
			count++;
		}
	}
	return i;
}

static int strncmp_skip_color_codes(const char *s1, const char *s2, int n) {
	int i = 0, j = 0;
	int count = 0;
	for (i = 0, j = 0; s1[i] && s2[j] && count < n; i++, j++, count++) {
		while (s1[i] == 0x1b) {
			while (s1[i] && s1[i] != 'm') {
				i++;
			}
			if (s1[i]) {
				i++;
			}
		}
		while (s2[j] == 0x1b) {
			while (s2[j] && s2[j] != 'm') {
				j++;
			}
			if (s2[j]) {
				j++;
			}
		}
		if (s1[i] != s2[j]) {
			return -1;
		}
	}

	if (count < n && s1[i] != s2[j]) {
		return -1;
	}

	return 0;
}

static char *strchr_skip_color_codes(const char *s, int c) {
	int i = 0;
	for (i = 0; s[i]; i++) {
		while (s[i] && s[i] == 0x1b) {
			while (s[i] && s[i] != 'm') {
				i++;
			}
			if (s[i]) {
				i++;
			}
		}
		if (!s[i] || s[i] == (char)c) {
			return (char *)s + i;
		}
	}
	return NULL;
}

// Global buffer to speed up colorizing performance

RZ_API char *rz_str_highlight(char *str, const char *word, const char *color, const char *color_reset) {
	if (!str || !*str) {
		return NULL;
	}
	ut32 i = 0, j = 0, to_copy;
	char *start = str;
	ut32 l_str = strlen(str);
	ut32 l_reset = strlen(color_reset);
	ut32 l_color = color ? strlen(color) : 0;
	if (!color) {
		return strdup(str);
	}
	if (!word || !*word) {
		return rz_str_newf("%s%s%s", color, str, color_reset);
	}
	ut32 l_word = strlen(word);
	// XXX don't use static buffers
	char o[1024] = { 0 };
	while (start && (start < str + l_str)) {
		int copied = 0;
		// find first letter
		start = strchr_skip_color_codes(str + i, *word);
		if (start) {
			to_copy = start - (str + i);
			if (to_copy + j + 1 > sizeof(o)) {
				// XXX. no limits
				break;
			}
			strncpy(o + j, str + i, to_copy);
			i += to_copy;
			j += to_copy;
			if (!strncmp_skip_color_codes(start, word, l_word)) {
				if (j + strlen(color) >= sizeof(o)) {
					// XXX. no limits
					break;
				}
				strcpy(o + j, color);
				j += l_color;
				if (j + l_word >= sizeof(o)) {
					// XXX. no limits
					break;
				}
				copied = strncpy_with_color_codes(o + j, str + i, l_word);
				i += copied;
				j += copied;
				if (j + strlen(color_reset) >= sizeof(o)) {
					// XXX. no limits
					break;
				}
				strcpy(o + j, color_reset);
				j += l_reset;
			} else {
				o[j++] = str[i++];
			}
		} else {
			if (j + strlen(str + i) >= sizeof(o)) {
				break;
			}
			strcpy(o + j, str + i);
			break;
		}
	}
	return strdup(o);
}

RZ_API char *rz_str_from_ut64(ut64 val) {
	int i = 0;
	char *v = (char *)&val;
	char *str = (char *)calloc(1, 9);
	if (!str) {
		return NULL;
	}
	while (i < 8 && *v) {
		str[i++] = *v++;
	}
	return str;
}

RZ_API int rz_snprintf(char *string, int len, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	int ret = vsnprintf(string, len, fmt, ap);
	string[len - 1] = 0;
	va_end(ap);
	return ret;
}

// Strips all the lines in str that contain key
RZ_API void rz_str_stripLine(char *str, const char *key) {
	size_t i, j, klen, slen, off;
	const char *ptr;

	if (!str || !key) {
		return;
	}
	klen = strlen(key);
	slen = strlen(str);

	for (i = 0; i < slen;) {
		ptr = (char *)rz_mem_mem((ut8 *)str + i, slen - i, (ut8 *)"\n", 1);
		if (!ptr) {
			ptr = (char *)rz_mem_mem((ut8 *)str + i, slen - i, (ut8 *)key, klen);
			if (ptr) {
				str[i] = '\0';
				break;
			}
			break;
		}

		off = (size_t)(ptr - (str + i)) + 1;

		ptr = (char *)rz_mem_mem((ut8 *)str + i, off, (ut8 *)key, klen);
		if (ptr) {
			for (j = i; j < slen - off + 1; j++) {
				str[j] = str[j + off];
			}
			slen -= off;
		} else {
			i += off;
		}
	}
}

RZ_API char *rz_str_list_join(RzList /*<char *>*/ *str, const char *sep) {
	RzStrBuf *sb = rz_strbuf_new("");
	const char *p;
	while ((p = rz_list_pop_head(str))) {
		if (rz_strbuf_length(sb) != 0) {
			rz_strbuf_append(sb, sep);
		}
		rz_strbuf_append(sb, p);
	}
	return rz_strbuf_drain(sb);
}

RZ_API char *rz_str_array_join(const char **a, size_t n, const char *sep) {
	RzStrBuf *sb = rz_strbuf_new("");
	size_t i;

	if (n > 0) {
		rz_strbuf_append(sb, a[0]);
	}

	for (i = 1; i < n; i++) {
		rz_strbuf_append(sb, sep);
		rz_strbuf_append(sb, a[i]);
	}
	return rz_strbuf_drain(sb);
}

/* return the number of arguments expected as extra arguments */
RZ_API int rz_str_fmtargs(const char *fmt) {
	int n = 0;
	while (*fmt) {
		if (*fmt == '%') {
			if (fmt[1] == '*') {
				n++;
			}
			n++;
		}
		fmt++;
	}
	return n;
}

// str-bool

// Returns "true" or "false" as a string given an input integer. The returned
// value is consistent with C's definition of 0 is false, and all other values
// are true.
RZ_API const char *rz_str_bool(int b) {
	return b ? "true" : "false";
}

RZ_API bool rz_str_is_true(const char *s) {
	return !rz_str_casecmp("yes", s) || !rz_str_casecmp("on", s) || !rz_str_casecmp("true", s) || !rz_str_casecmp("1", s);
}

RZ_API bool rz_str_is_false(const char *s) {
	return !rz_str_casecmp("no", s) || !rz_str_casecmp("off", s) || !rz_str_casecmp("false", s) || !rz_str_casecmp("0", s) || !*s;
}

RZ_API bool rz_str_is_bool(const char *val) {
	return rz_str_is_true(val) || rz_str_is_false(val);
}

RZ_API char *rz_str_nextword(char *s, char ch) {
	char *p = strchr(s, ch);
	if (!p) {
		return NULL;
	}
	*p++ = 0;
	return p;
}

RZ_API char *rz_str_scale(const char *s, int w, int h) {
	// count lines and rows in (s) string
	// compute how many lines we should remove or combine
	// return a string containing
	// for now this function is ascii only (no utf8 or ansi escapes)
	RzListIter *iter;
	char *line;
	char *str = strdup(s);
	RzList *lines = rz_str_split_list(str, "\n", 0);
	int i, j;
	int rows = 0;
	int maxcol = 0;

	rows = rz_list_length(lines);
	rz_list_foreach (lines, iter, line) {
		maxcol = RZ_MAX(strlen(line), maxcol);
	}

	RzList *out = rz_list_newf(free);

	int curline = -1;
	char *linetext = rz_str_pad(' ', w);
	for (i = 0; i < h; i++) {
		int zoomedline = i * (int)((float)rows / h);
		const char *srcline = rz_list_get_n(lines, zoomedline);
		int cols = strlen(srcline);
		for (j = 0; j < w; j++) {
			int zoomedcol = j * ((float)cols / w);
			linetext[j] = srcline[zoomedcol];
		}
		if (curline != zoomedline) {
			rz_list_append(out, strdup(linetext));
			curline = zoomedline;
		}
		memset(linetext, ' ', w);
	}
	free(linetext);
	free(str);

	char *join = rz_str_list_join(out, "\n");
	rz_list_free(out);
	return join;
}

RZ_API const char *rz_str_str_xy(const char *s, const char *word, const char *prev, int *x, int *y) {
	rz_return_val_if_fail(s && word && x && y, NULL);
	rz_return_val_if_fail(word[0] != '\0' && word[0] != '\n', NULL);
	const char *src = prev ? prev + 1 : s;
	const char *d = strstr(src, word);
	if (!d) {
		return NULL;
	}
	const char *q;
	for (q = prev ? prev : s; q < d; q++) {
		if (*q == '\n') {
			(*y)++;
			*x = 0;

		} else {
			(*x)++;
		}
	}
	return d;
}

/**
 * Wrap the input string according to the provided width, so that (if possible),
 * each line fits in \p width characters. Words will not be split across
 * multiple lines. Words are consecutive characters separated by one or more
 * space. Spaces at the beginning of \p string will be maintained, trailing
 * whitespaces at the end of each split line is removed.
 *
 * \param string a writable string, it will be modified by the function
 * \param width the maximum size of each line. It will be respected only if
 *              possible, as the function won't split words.
 */
RZ_API RzList /*<char *>*/ *rz_str_wrap(char *str, size_t width) {
	rz_return_val_if_fail(str, NULL);

	RzList *res = rz_list_new();
	if (!res) {
		return NULL;
	}
	char *p, *start_line = str;
	char *first_space = NULL, *last_space = NULL;

	p = (char *)rz_str_trim_head_ro(str);
	if (!*p) {
		return res;
	}

	do {
		p++;
		if (!*p || isspace((int)*p)) {
			if (!last_space || p != last_space + 1) {
				if (p - start_line > width && first_space) {
					rz_list_append(res, start_line);
					*first_space = '\0';
					start_line = last_space + 1;
				}
				first_space = p;
			}
			last_space = p;
		}
	} while (*p);
	p--;
	while (p >= str && isspace((int)*p)) {
		*p = '\0';
		p--;
	}
	if (p > start_line) {
		rz_list_append(res, start_line);
	}

	return res;
}

/**
 * \brief Tries to guess the string encoding method from the buffer.
 *
 * \param buffer  The string buffer to use for guessing the encoding
 * \param length  The string buffer length
 *
 * \return string encoding as RzStrEnc type
 */
RZ_API RzStrEnc rz_str_guess_encoding_from_buffer(RZ_NONNULL const ut8 *buffer, ut32 length) {
	rz_return_val_if_fail(buffer, RZ_STRING_ENC_UTF8);
	RzStrEnc enc = rz_utf_bom_encoding(buffer, length);
	if (enc != RZ_STRING_ENC_GUESS) {
		return enc;
	}
	for (ut32 i = 0, utf32le = 0, utf32be = 0, utf16le = 0, utf16be = 0, ascii = 0; i < length; ++i) {
		ut32 leftovers = length - i;
		if (leftovers > 4 && IS_PRINTABLE(buffer[i]) && buffer[i + 1] == 0 && buffer[i + 2] == 0 && buffer[i + 3] == 0) {
			utf32le++;
			// `i > ascii + 1` means at least one non-ascii byte
			// `utf32le  == i / 4 + 1` means neatly algined like 7700 0000 3000 0000 7700 0000
			if (utf32le > 2 && (i > ascii + 1 || utf32le == i / 4 + 1)) {
				enc = RZ_STRING_ENC_UTF32LE;
				break;
			}
		} else if (leftovers > 4 && buffer[i] == 0 && buffer[i + 1] == 0 && buffer[i + 2] == 0 && IS_PRINTABLE(buffer[i + 3])) {
			utf32be++;
			if (utf32be > 2 && (i > ascii + 1 || utf32be == i / 4 + 1)) {
				enc = RZ_STRING_ENC_UTF32BE;
				break;
			}
		}
		if (leftovers > 2 && IS_PRINTABLE(buffer[i]) && buffer[i + 1] == 0) {
			utf16le++;
			if (utf16le > 2 && i > ascii + 1) {
				enc = RZ_STRING_ENC_UTF16LE;
				break;
			}
		} else if (leftovers > 2 && buffer[i] == 0 && IS_PRINTABLE(buffer[i + 1])) {
			utf16be++;
			if (utf16be > 2 && i > ascii + 1) {
				enc = RZ_STRING_ENC_UTF16BE;
				break;
			}
		}
		if (IS_PRINTABLE(buffer[i]) || buffer[i] == ' ' || buffer[i] == '\0') {
			ascii++;
			if (ascii > length - 1) {
				enc = RZ_STRING_ENC_8BIT;
				break;
			}
		}
	}

	return enc == RZ_STRING_ENC_GUESS ? RZ_STRING_ENC_UTF8 : enc;
}

/**
 * \brief Converts a raw buffer to a printable string based on the selected options
 *
 * \param  option Pointer to RzStrStringifyOpt.
 * \param  length The real string length.
 * \return The stringified raw buffer
 */
RZ_API RZ_OWN char *rz_str_stringify_raw_buffer(RzStrStringifyOpt *option, RZ_NULLABLE RZ_OUT ut32 *length) {
	rz_return_val_if_fail(option && option->buffer && option->encoding != RZ_STRING_ENC_GUESS, NULL);
	if (option->length < 1) {
		return NULL;
	}

	RzStrBuf sb;
	const ut8 *buf = option->buffer;
	ut32 buflen = option->length;
	RzStrEnc enc = option->encoding;
	ut32 wrap_at = option->wrap_at;
	RzRune rune;
	ut32 n_runes = 0;
	int rsize = 1; // rune size

	rz_strbuf_init(&sb);
	for (ut32 i = 0, line_runes = 0; i < buflen; i += rsize) {
		if (enc == RZ_STRING_ENC_UTF32LE) {
			rsize = rz_utf32le_decode(&buf[i], buflen - i, &rune);
			if (rsize) {
				rsize = 4;
			}
		} else if (enc == RZ_STRING_ENC_UTF16LE) {
			rsize = rz_utf16le_decode(&buf[i], buflen - i, &rune);
			if (rsize == 1) {
				rsize = 2;
			}
		} else if (enc == RZ_STRING_ENC_UTF32BE) {
			rsize = rz_utf32be_decode(&buf[i], buflen - i, &rune);
			if (rsize) {
				rsize = 4;
			}
		} else if (enc == RZ_STRING_ENC_UTF16BE) {
			rsize = rz_utf16be_decode(&buf[i], buflen - i, &rune);
			if (rsize == 1) {
				rsize = 2;
			}
		} else if (enc == RZ_STRING_ENC_IBM037) {
			rsize = rz_str_ibm037_to_unicode(buf[i], &rune);
		} else if (enc == RZ_STRING_ENC_IBM290) {
			rsize = rz_str_ibm290_to_unicode(buf[i], &rune);
		} else if (enc == RZ_STRING_ENC_EBCDIC_ES) {
			rsize = rz_str_ebcdic_es_to_unicode(buf[i], &rune);
		} else if (enc == RZ_STRING_ENC_EBCDIC_UK) {
			rsize = rz_str_ebcdic_uk_to_unicode(buf[i], &rune);
		} else if (enc == RZ_STRING_ENC_EBCDIC_US) {
			rsize = rz_str_ebcdic_us_to_unicode(buf[i], &rune);
		} else if (enc == RZ_STRING_ENC_8BIT) {
			rune = buf[i];
			rsize = rune < 0x7F ? 1 : 0;
		} else {
			rsize = rz_utf8_decode(&buf[i], buflen - i, &rune);
		}

		if (rsize == 0) {
			switch (enc) {
			case RZ_STRING_ENC_UTF32LE:
				rsize = RZ_MIN(4, buflen - i);
				break;
			case RZ_STRING_ENC_UTF16LE:
				rsize = RZ_MIN(2, buflen - i);
				break;
			case RZ_STRING_ENC_UTF32BE:
				rsize = RZ_MIN(4, buflen - i);
				break;
			case RZ_STRING_ENC_UTF16BE:
				rsize = RZ_MIN(2, buflen - i);
				break;
			default:
				rsize = 1;
				break;
			}
			for (int j = 0; j < rsize; ++j) {
				rune = buf[i + j];
				n_runes++;
				if (option->urlencode) {
					rz_strbuf_appendf(&sb, "%%%02x", rune);
				} else if (option->json) {
					rz_strbuf_appendf(&sb, "\\u%04x", rune);
				} else {
					rz_strbuf_appendf(&sb, "\\x%02x", rune);
				}
			}
			if (wrap_at && line_runes + 1 >= wrap_at) {
				rz_strbuf_appendf(&sb, "\n");
				line_runes = 0;
			}
			continue;
		} else if (rune == '\0' && option->stop_at_nil) {
			break;
		} else if (rune == '\n') {
			line_runes = 0;
		}
		line_runes++;
		n_runes++;
		if (option->urlencode) {
			if (IS_DIGIT(rune) || IS_UPPER(rune) || IS_LOWER(rune) || rune == '-' || rune == '_' || rune == '.' || rune == '~') {
				// RFC 3986 section 2.3 Unreserved Characters
				// A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
				// a b c d e f g h i j k l m n o p q r s t u v w x y z
				// 0 1 2 3 4 5 6 7 8 9 - _ . ~
				char ch = rune;
				rz_strbuf_appendf(&sb, "%c", ch);
			} else {
				ut8 tmp[4];
				int n_enc = rz_utf8_encode((ut8 *)tmp, rune);
				for (int j = 0; j < n_enc; ++j) {
					rz_strbuf_appendf(&sb, "%%%02x", tmp[j]);
				}
			}
		} else if (option->json) {
			if (IS_PRINTABLE(rune) && rune != '\"' && rune != '\\') {
				char ch = rune;
				rz_strbuf_appendf(&sb, "%c", ch);
			} else if (rune == '\n') {
				rz_strbuf_append(&sb, "\\n");
			} else if (rune == '\r') {
				rz_strbuf_append(&sb, "\\r");
			} else if (rune == '\\') {
				rz_strbuf_append(&sb, "\\\\");
			} else if (rune == '\t') {
				rz_strbuf_append(&sb, "\\t");
			} else if (rune == '\f') {
				rz_strbuf_append(&sb, "\\f");
			} else if (rune == '\b') {
				rz_strbuf_append(&sb, "\\b");
			} else if (rune == '"') {
				rz_strbuf_append(&sb, "\\\"");
			} else {
				for (int j = 0; j < rsize; ++j) {
					rune = buf[i + j];
					rz_strbuf_appendf(&sb, "\\u%04x", rune);
				}
				n_runes += rsize - 1;
			}
		} else {
			if (rune == '\\') {
				rz_strbuf_appendf(&sb, "\\\\");
			} else if ((rune == '\n' && !option->escape_nl) || (rz_rune_is_printable(rune) && rune >= ' ')) {
				char tmp[5] = { 0 };
				rz_utf8_encode((ut8 *)tmp, rune);
				rz_strbuf_appendf(&sb, "%s", tmp);
			} else {
				ut8 tmp[4];
				int n_enc = rz_utf8_encode((ut8 *)tmp, rune);
				for (int j = 0; j < n_enc; ++j) {
					rz_strbuf_appendf(&sb, "\\x%02x", tmp[j]);
				}
			}
		}
		if (wrap_at && line_runes + 1 >= wrap_at) {
			rz_strbuf_appendf(&sb, "\n");
			line_runes = 0;
		}
	}
	if (!option->json) {
		rz_strbuf_appendf(&sb, "\n");
	}
	if (length) {
		*length = n_runes;
	}
	return rz_strbuf_drain_nofree(&sb);
}

/**
 * \brief Get the indent string
 * \param indent indent level, max 9
 * \return indent string
 */
RZ_API const char *rz_str_indent(int indent) {
	static const char *indent_tbl[] = {
		"",
		"\t",
		"\t\t",
		"\t\t\t",
		"\t\t\t\t",
		"\t\t\t\t\t",
		"\t\t\t\t\t\t",
		"\t\t\t\t\t\t\t",
		"\t\t\t\t\t\t\t\t",
		"\t\t\t\t\t\t\t\t\t",
	};
	if (indent < 0 || indent >= RZ_ARRAY_SIZE(indent_tbl)) {
		return "";
	}
	return indent_tbl[indent];
}
