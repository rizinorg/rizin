// SPDX-FileCopyrightText: 2014-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include "sdb.h"
#include <stdarg.h>
#include <string.h>

// TODO: convert into a function
// TODO: Add 'a' format for array of pointers null terminated??
// XXX SLOW CONCAT
#define concat(x) \
	if (x) { \
		int size = 2 + strlen(x ? x : "") + (out ? strlen(out) + 4 : 0); \
		if (out) { \
			char *o = realloc(out, size); \
			if (o) { \
				strcat(o, ","); \
				strcat(o, x); \
				out = o; \
			} \
		} else { \
			out = strdup(x); \
		} \
	}

RZ_API char *sdb_fmt_tostr(void *p, const char *fmt) {
	char buf[128], *e_str, *out = NULL;
	int n, len = 0;
	if (!p || !fmt) {
		return NULL;
	}
	for (; *fmt; fmt++) {
		n = 4;
		switch (*fmt) {
		case 'b':
			concat(sdb_itoa((ut64) * ((ut8 *)p + len), buf, 10));
			break;
		case 'h':
			concat(sdb_itoa((ut64) * ((short *)((ut8 *)p + len)), buf, 10));
			break;
		case 'd':
			concat(sdb_itoa((ut64) * ((int *)((ut8 *)p + len)), buf, 10));
			break;
		case 'q':
			concat(sdb_itoa(*((ut64 *)((ut8 *)p + len)), buf, 10));
			n = 8;
			break;
		case 'z':
			concat((char *)p + len);
			break;
		case 's':
			e_str = sdb_encode((const ut8 *)*((char **)((ut8 *)p + len)), -1);
			concat(e_str);
			free(e_str);
			break;
		case 'p':
			concat(sdb_itoa((ut64) * ((size_t *)((ut8 *)p + len)), buf, 16));
			n = sizeof(size_t);
			break;
		}
		len += RZ_MAX((long)sizeof(void *), n); // align
	}
	return out;
}

static const char *sdb_anext2(const char *str, const char **next) {
	char *nxt, *p = strchr(str, SDB_RS);
	if (p) {
		nxt = p + 1;
	} else {
		nxt = NULL;
	}
	if (next) {
		*next = nxt;
	}
	return str;
}

// TODO: move this into fmt?
RZ_API ut64 *sdb_fmt_array_num(const char *list) {
	ut64 *retp, *ret = NULL;
	ut32 size;
	const char *next, *ptr = list;
	if (list && *list) {
		ut32 len = (ut32)sdb_alen(list);
		size = sizeof(ut64) * (len + 1);
		if (size < len) {
			return NULL;
		}
		retp = ret = (ut64 *)malloc(size);
		if (!ret) {
			return NULL;
		}
		*retp++ = len;
		do {
			const char *str = sdb_anext2(ptr, &next);
			ut64 n = sdb_atoi(str);
			*retp++ = n;
			ptr = next;
		} while (next);
	}
	return ret;
}

RZ_API char **sdb_fmt_array(const char *list) {
	char *_s, **retp, **ret = NULL;
	const char *next, *ptr = list;
	if (list && *list) {
		int len = sdb_alen(list);
		retp = ret = (char **)malloc(2 * strlen(list) +
			((len + 1) * sizeof(char *)) + 1);
		_s = (char *)ret + ((len + 1) * sizeof(char *));
		if (!ret) {
			return NULL;
		}
		do {
			const char *str = sdb_anext2(ptr, &next);
			int slen = next ? (next - str) - 1 : (int)strlen(str) + 1;
			memcpy(_s, str, slen);
			_s[slen] = 0;
			*retp++ = _s;
			_s += slen + 1;
			ptr = next;
		} while (next);
		*retp = NULL;
	}
	return ret;
}
