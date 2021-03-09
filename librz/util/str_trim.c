// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_types.h"
#include "rz_util.h"
#include "rz_cons.h"
#include "rz_bin.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

// TODO: simplify this horrible loop
RZ_API void rz_str_trim_path(char *s) {
	char *src, *dst, *p;
	int i = 0;
	if (!s || !*s) {
		return;
	}
	dst = src = s + 1;
	while (*src) {
		if (*(src - 1) == '/' && *src == '.' && *(src + 1) == '.') {
			if (*(src + 2) == '/' || *(src + 2) == '\0') {
				p = dst - 1;
				while (s != p) {
					if (*p == '/') {
						if (i) {
							dst = p + 1;
							i = 0;
							break;
						}
						i = 1;
					}
					p--;
				}
				if (s == p && *p == '/') {
					dst = p + 1;
				}
				src = src + 2;
			} else {
				*dst = *src;
				dst++;
			}
		} else if (*src == '/' && *(src + 1) == '.' && (*(src + 2) == '/' || *(src + 2) == '\0')) {
			src++;
		} else if (*src != '/' || *(src - 1) != '/') {
			*dst = *src;
			dst++;
		}
		src++;
	}
	if (dst > s + 1 && *(dst - 1) == '/') {
		*(dst - 1) = 0;
	} else {
		*dst = 0;
	}
}

RZ_API char *rz_str_trim_lines(char *str) {
	RzList *list = rz_str_split_list(str, "\n", 0);
	char *s;
	RzListIter *iter;
	RzStrBuf *sb = rz_strbuf_new("");
	rz_list_foreach (list, iter, s) {
		//rz_str_ansi_trim (s, -1, 99999);
		rz_str_ansi_filter(s, NULL, NULL, -1);
		rz_str_trim(s);
		if (*s) {
			rz_strbuf_appendf(sb, "%s\n", s);
		}
	}
	rz_list_free(list);
	free(str);
	return rz_strbuf_drain(sb);
}

RZ_API char *rz_str_trim_dup(const char *str) {
	char *a = strdup(str);
	rz_str_trim(a);
	return a;
}

// Returns a pointer to the first non-whitespace character of str.
// TODO: Find a better name: to rz_str_trim_head_ro(), rz_str_skip_head or so
RZ_API const char *rz_str_trim_head_ro(const char *str) {
	rz_return_val_if_fail(str, NULL);
	for (; *str && IS_WHITECHAR(*str); str++) {
		;
	}
	return str;
}

// TODO: find better name
RZ_API const char *rz_str_trim_head_wp(const char *str) {
	rz_return_val_if_fail(str, NULL);
	for (; *str && !IS_WHITESPACE(*str); str++) {
		;
	}
	return str;
}

/* remove spaces from the head of the string.
 * the string is changed in place */
RZ_API void rz_str_trim_head(char *str) {
	char *p = (char *)rz_str_trim_head_ro(str);
	if (p) {
		memmove(str, p, strlen(p) + 1);
	}
}

// Remove whitespace chars from the tail of the string, replacing them with
// null bytes. The string is changed in-place.
RZ_API void rz_str_trim_tail(char *str) {
	rz_return_if_fail(str);
	size_t length = strlen(str);
	while (length-- > 0) {
		if (IS_WHITECHAR(str[length])) {
			str[length] = '\0';
		} else {
			break;
		}
	}
}

// Removes spaces from the head of the string, and zeros out whitespaces from
// the tail of the string. The string is changed in place.
RZ_API void rz_str_trim(char *str) {
	rz_str_trim_head(str);
	rz_str_trim_tail(str);
}

// no copy, like trim_head+tail but with trim_head_ro, beware heap issues
// TODO: rename to rz_str_trim_weak() ?
RZ_API char *rz_str_trim_nc(char *str) {
	char *s = (char *)rz_str_trim_head_ro(str);
	rz_str_trim_tail(s);
	return s;
}

/* supposed to chop a string with ansi controls to max length of n. */
RZ_API int rz_str_ansi_trim(char *str, int str_len, int n) {
	rz_return_val_if_fail(str, 0);
	char ch, ch2;
	int back = 0, i = 0, len = 0;
	/* simple case - no need to cut */
	if (str_len < 0) {
		str_len = strlen(str);
	}
	if (n >= str_len) {
		str[str_len] = 0;
		return str_len;
	}
	while ((i < str_len) && str[i] && len < n && n > 0) {
		ch = str[i];
		ch2 = str[i + 1];
		if (ch == 0x1b) {
			if (ch2 == '\\') {
				i++;
			} else if (ch2 == ']') {
				if (!strncmp(str + 2 + 5, "rgb:", 4)) {
					i += 18;
				}
			} else if (ch2 == '[') {
				for (++i; (i < str_len) && str[i] && str[i] != 'J' && str[i] != 'm' && str[i] != 'H';
					i++) {
					;
				}
			}
		} else if ((str[i] & 0xc0) != 0x80) {
			len++;
		}
		i++;
		back = i; /* index in the original array */
	}
	str[back] = 0;
	return back;
}
