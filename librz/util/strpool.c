// SPDX-FileCopyrightText: 2012-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

RZ_API RzStrpool *rz_strpool_new(int sz) {
	RzStrpool *p = RZ_NEW(RzStrpool);
	if (!p) {
		eprintf("Malloc failed!\n");
		return NULL;
	}
	if (sz < 1) {
		sz = 1024;
	}
	p->str = malloc(sz);
	if (!p->str) {
		eprintf("Malloc failed!\n");
		free(p);
		return NULL;
	}
	p->size = sz;
	p->len = 0;
	p->str[0] = 0;
	return p;
}

RZ_API char *rz_strpool_empty(RzStrpool *p) {
	p->len = 0;
	p->str[0] = 0;
	p->str[1] = 0;
	return p->str;
}

RZ_API char *rz_strpool_alloc(RzStrpool *p, int l) {
	char *ret = p->str + p->len;
	if ((p->len + l) >= p->size) {
		ut64 osize = p->size;
		if (l >= RZ_STRPOOL_INC) {
			p->size += l + RZ_STRPOOL_INC;
		} else {
			p->size += RZ_STRPOOL_INC;
		}
		if (p->size < osize) {
			eprintf("Underflow!\n");
			p->size = osize;
			return NULL;
		}
		ret = realloc(p->str, p->size);
		if (!ret) {
			eprintf("Realloc failed!\n");
			free(p->str);
			return NULL;
		}
		p->str = ret;
		ret += p->len;
	}
	p->len += l;
	return ret;
}

RZ_API int rz_strpool_memcat(RzStrpool *p, const char *s, int len) {
	char *ptr = rz_strpool_alloc(p, len);
	if (!ptr) {
		return -1;
	}
	memcpy(ptr, s, len);
	return (size_t)(ptr - p->str);
}

RZ_API int rz_strpool_append(RzStrpool *p, const char *s) {
	int l = strlen(s) + 1;
	return rz_strpool_memcat(p, s, l);
}

RZ_API int rz_strpool_ansi_chop(RzStrpool *p, int n) {
	/* p->str need not be a c-string */
	int i = rz_str_ansi_trim(p->str, p->len, n);
	p->len = i;
	return i;
}

RZ_API void rz_strpool_free(RzStrpool *p) {
	free(p->str);
	free(p);
}

RZ_API int rz_strpool_fit(RzStrpool *p) {
	char *s;
	if (p->len == p->size) {
		return false;
	}
	s = realloc(p->str, p->len);
	if (!s) {
		eprintf("Realloc failed!\n");
		free(p->str);
		return false;
	}
	p->str = s;
	p->size = p->len;
	return true;
}

RZ_API char *rz_strpool_get(RzStrpool *p, int index) {
	if (!p || !p->str || index < 0 || index >= p->len) {
		return NULL;
	}
	return p->str + index;
}

RZ_API char *rz_strpool_get_i(RzStrpool *p, int index) {
	int i, n = 0;
	if (index < 0 || index >= p->len) {
		return NULL;
	}
	for (i = 0; i < index; i++) {
		char *s = rz_strpool_next(p, n);
		n = rz_strpool_get_index(p, s);
	}
	return p->str + n;
}

RZ_API int rz_strpool_get_index(RzStrpool *p, const char *s) {
	int ret = (size_t)(s - p->str);
	return (ret > 0) ? ret : 0;
}

RZ_API char *rz_strpool_next(RzStrpool *p, int index) {
	char *ptr = rz_strpool_get(p, index);
	if (ptr) {
		char *q = ptr + strlen(ptr) + 1;
		if (q >= (p->str + p->len)) {
			return NULL;
		}
		ptr = q;
		if (!*ptr) {
			ptr = NULL;
		}
	}
	return ptr;
}

RZ_API char *rz_strpool_slice(RzStrpool *p, int index) {
	int idx, len;
	char *o, *x = rz_strpool_get_i(p, index + 1);
	if (!x || !*x) {
		return NULL;
	}
	idx = (size_t)(x - p->str);
	len = p->len - idx;
	o = malloc(len + 128);
	if (!o) {
		return NULL;
	}
	memcpy(o, x, len);
	free(p->str);
	p->str = o;
	p->size = len + 128;
	p->len = len;
	return o;
}

#if TEST
int main() {
	RzStrpool *p = rz_strpool_new(1024);
	printf("%d\n", rz_strpool_append(p, "Hello World"));
	printf("%d\n", rz_strpool_append(p, "Patata Barata"));
	printf("%s\n", rz_strpool_get(p, 12));
	rz_strpool_fit(p);
	rz_strpool_free(p);
	return 0;
}
#endif
