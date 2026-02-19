// SPDX-FileCopyrightText: 2011-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include "sdb.h"
#include <rz_util/rz_time.h>

RZ_API ut32 sdb_hash_len(const char *s, ut32 *len) {
	ut32 h = CDB_HASHSTART;
	ut32 count = 0;
	if (s) {
		while (*s) {
			h = (h + (h << 5)) ^ *s++;
			count++;
		}
	}
	if (len) {
		*len = count;
	}
	return h;
}

RZ_API ut32 sdb_hash(const char *s) {
	return sdb_hash_len(s, NULL);
}

RZ_API ut8 sdb_hash_byte(const char *s) {
	const ut32 hash = sdb_hash_len(s, NULL);
	const ut8 *h = (const ut8 *)&hash;
	return h[0] ^ h[1] ^ h[2] ^ h[3];
}

// assert (sizeof (s)>64)
// if s is null, the returned pointer must be freed!!
RZ_API char *sdb_itoa(ut64 n, char *s, int base) {
	static const char *lookup = "0123456789abcdef";
	const int imax = 62;
	int i = imax, copy_string = 1, alloc = 0;
	if (s) {
		*s = 0;
	} else {
		alloc = 1;
		s = malloc(64);
		if (!s) {
			return NULL;
		}
	}
	if (base < 0) {
		copy_string = 0;
		base = -base;
	}
	if ((base > 16) || (base < 1)) {
		if (alloc) {
			free(s);
		}
		return NULL;
	}
	if (!n) {
		strcpy(s, "0");
		return s;
	}
	s[imax + 1] = '\0';
	if (base <= 10) {
		for (; n && i > 0; n /= base) {
			s[i--] = (n % base) + '0';
		}
	} else {
		for (; n && i > 0; n /= base) {
			s[i--] = lookup[(n % base)];
		}
		if (i != imax) {
			s[i--] = 'x';
		}
		s[i--] = '0';
	}
	if (copy_string || alloc) {
		// unnecessary memmove in case we use the return value
		// return s + i + 1;
		memmove(s, s + i + 1, strlen(s + i + 1) + 1);
		return s;
	}
	return s + i + 1;
}

RZ_API ut64 sdb_atoi(const char *s) {
	char *p;
	ut64 ret;
	if (!s || *s == '-') {
		return 0LL;
	}
	ret = strtoull(s, &p, 0);
	return p ? ret : 0LL;
}

// NOTE: Reuses memory. probably not bindings friendly..
RZ_API char *sdb_array_compact(char *p) {
	char *e;
	// remove empty elements
	while (*p) {
		if (!strncmp(p, ",,", 2)) {
			p++;
			for (e = p + 1; *e == ','; e++) {
			};
			memmove(p, e, strlen(e) + 1);
		} else {
			p++;
		}
	}
	return p;
}

// NOTE: Reuses memory. probably not bindings friendly..
RZ_API char *sdb_aslice(char *out, int from, int to) {
	int len, idx = 0;
	char *str = NULL;
	char *end = NULL;
	char *p = out;
	if (from >= to) {
		return NULL;
	}
	while (*p) {
		if (!str && idx == from) {
			str = p;
		}
		if (idx == to) {
			end = p;
			break;
		}
		if (*p == ',') {
			idx++;
		}
		p++;
	}
	if (str) {
		if (!end) {
			end = str + strlen(str);
		}
		len = (size_t)(end - str);
		memmove(out, str, len);
		out[len] = 0;
		return out;
	}
	return NULL;
}

// TODO: find better name for it
// TODO: optimize, because this is the main bottleneck for sdb_array_set()
RZ_API int sdb_alen(const char *str) {
	int len = 1;
	const char *n, *p = str;
	if (!p || !*p) {
		return 0;
	}
	for (len = 0;; len++) {
		n = strchr(p, SDB_RS);
		if (!n) {
			break;
		}
		p = n + 1;
	}
	return ++len;
}

RZ_API int sdb_alen_ignore_empty(const char *str) {
	int len = 1;
	const char *n, *p = str;
	if (!p || !*p) {
		return 0;
	}
	while (*p == SDB_RS) {
		p++;
	}
	for (len = 0;;) {
		n = strchr(p, SDB_RS);
		if (!n) {
			break;
		}
		p = n + 1;
		if (*(p) == SDB_RS) {
			continue;
		}
		len++;
	}
	if (*p)
		len++;
	return len;
}

RZ_API char *sdb_anext(char *str, char **next) {
	char *nxt, *p = strchr(str, SDB_RS);
	if (p) {
		*p = 0;
		nxt = p + 1;
	} else {
		nxt = NULL;
	}
	if (next) {
		*next = nxt;
	}
	return str;
}

RZ_API const char *sdb_const_anext(const char *str) {
	const char *p = strchr(str, SDB_RS);
	return p ? p + 1 : NULL;
}

RZ_API ut64 sdb_now(void) {
	ut64 usec = rz_time_now();
	return usec / 1000000;
}

RZ_API int sdb_isnum(const char *s) {
	const char vs = *s;
	return ((vs == '-' || vs == '+') || (vs >= '0' && vs <= '9'));
}

RZ_API int sdb_num_base(const char *s) {
	if (!s) {
		return SDB_NUM_BASE;
	}
	if (!strncmp(s, "0x", 2)) {
		return 16;
	}
	return (*s == '0' && s[1]) ? 8 : 10;
}

RZ_API const char *sdb_type(const char *k) {
	if (!k || !*k) {
		return "undefined";
	}
	if (sdb_isnum(k)) {
		return "number";
	}
	if (strchr(k, ',')) {
		return "array";
	}
	if (!strcmp(k, "true") || !strcmp(k, "false")) {
		return "boolean";
	}
	return "string";
}
