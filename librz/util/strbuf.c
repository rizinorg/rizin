// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_types.h"
#include "rz_util.h"
#include <stdio.h>

RZ_API RzStrBuf *rz_strbuf_new(const char *str) {
	RzStrBuf *s = RZ_NEW0(RzStrBuf);
	if (str) {
		rz_strbuf_set(s, str);
	}
	return s;
}

RZ_API bool rz_strbuf_equals(RzStrBuf *sa, RzStrBuf *sb) {
	rz_return_val_if_fail(sa && sb, false);
	if (sa->len != sb->len) {
		return false;
	}
	return strcmp(rz_strbuf_get(sa), rz_strbuf_get(sb)) == 0;
}

RZ_API bool rz_strbuf_is_empty(RzStrBuf *sb) {
	return sb->len == 0;
}

RZ_API int rz_strbuf_length(RzStrBuf *sb) {
	rz_return_val_if_fail(sb, 0);
	return sb->len;
}

RZ_API void rz_strbuf_init(RzStrBuf *sb) {
	rz_return_if_fail(sb);
	memset(sb, 0, sizeof(RzStrBuf));
}

RZ_API const char *rz_strbuf_initf(RzStrBuf *sb, const char *fmt, ...) {
	rz_return_val_if_fail(sb && fmt, NULL);
	rz_strbuf_init(sb);
	va_list ap;
	va_start(ap, fmt);
	const char *r = rz_strbuf_vsetf(sb, fmt, ap);
	va_end(ap);
	return r;
}

RZ_API bool rz_strbuf_copy(RzStrBuf *dst, RzStrBuf *src) {
	rz_return_val_if_fail(dst && src, false);
	if (src->ptr) {
		char *p = malloc(src->ptrlen);
		if (!p) {
			return false;
		}
		memcpy(p, src->ptr, src->ptrlen);
		free(dst->ptr);
		dst->ptr = p;
		dst->ptrlen = src->ptrlen;
	} else {
		RZ_FREE(dst->ptr);
		memcpy(dst->buf, src->buf, sizeof(dst->buf));
	}
	dst->len = src->len;
	return true;
}

RZ_API bool rz_strbuf_reserve(RzStrBuf *sb, size_t len) {
	rz_return_val_if_fail(sb, false);

	if ((sb->ptr && len < sb->ptrlen) || (!sb->ptr && len < sizeof(sb->buf))) {
		return true;
	}
	char *newptr = realloc(sb->ptr, len + 1);
	if (!newptr) {
		return false;
	}
	if (!sb->ptr) {
		memcpy(newptr, sb->buf, sizeof(sb->buf));
	}
	sb->ptr = newptr;
	sb->ptrlen = len + 1;
	return true;
}

RZ_API bool rz_strbuf_setbin(RzStrBuf *sb, const ut8 *s, size_t l) {
	rz_return_val_if_fail(sb && s, false);
	if (l >= sizeof(sb->buf)) {
		char *ptr = sb->ptr;
		if (!ptr || l + 1 > sb->ptrlen) {
			ptr = malloc(l + 1);
			if (!ptr) {
				return false;
			}
			RZ_FREE(sb->ptr);
			sb->ptrlen = l + 1;
			sb->ptr = ptr;
		}
		memcpy(ptr, s, l);
		ptr[l] = 0;
	} else {
		RZ_FREE(sb->ptr);
		memcpy(sb->buf, s, l);
		sb->buf[l] = 0;
	}
	sb->len = l;
	sb->weakref = false;
	return true;
}

// TODO: there's room for optimizations here
RZ_API bool rz_strbuf_slice(RzStrBuf *sb, int from, int len) {
	rz_return_val_if_fail(sb && from >= 0 && len >= 0, false);
	if (from < 1 && len >= sb->len) {
		return false;
	}
	const char *s = rz_strbuf_get(sb);
	const char *fr = rz_str_ansi_chrn(s, from + 1);
	const char *to = rz_str_ansi_chrn(s, from + len + 1);
	char *r = rz_str_newlen(fr, to - fr);
	rz_strbuf_fini(sb);
	rz_strbuf_init(sb);
	if (from >= len) {
		rz_strbuf_set(sb, "");
		free(r);
		return false;
	}
	rz_strbuf_set(sb, r);
	free(r);
	return true;
}

RZ_API bool rz_strbuf_setptr(RzStrBuf *sb, char *s, int len) {
	rz_return_val_if_fail(sb, false);
	if (len < 0) {
		sb->len = strlen(s);
		sb->ptrlen = sb->len + 1;
	} else {
		sb->ptrlen = len;
		sb->len = len;
	}
	sb->ptr = s;
	sb->weakref = true;
	return true;
}

RZ_API const char *rz_strbuf_set(RzStrBuf *sb, const char *s) {
	rz_return_val_if_fail(sb, NULL);
	if (!s) {
		rz_strbuf_init(sb);
		return rz_strbuf_get(sb);
	}
	size_t len = strlen(s);
	if (!rz_strbuf_setbin(sb, (const ut8 *)s, len)) {
		return NULL;
	}
	sb->len = len;
	return rz_strbuf_get(sb);
}

RZ_API const char *rz_strbuf_setf(RzStrBuf *sb, const char *fmt, ...) {
	rz_return_val_if_fail(sb && fmt, false);

	va_list ap;
	va_start(ap, fmt);
	const char *ret = rz_strbuf_vsetf(sb, fmt, ap);
	va_end(ap);
	return ret;
}

RZ_API const char *rz_strbuf_vsetf(RzStrBuf *sb, const char *fmt, va_list ap) {
	rz_return_val_if_fail(sb && fmt, false);

	const char *ret = NULL;
	va_list ap2;
	va_copy(ap2, ap);
	char string[1024];
	int rc = vsnprintf(string, sizeof(string), fmt, ap);
	if (rc >= sizeof(string)) {
		char *p = malloc(rc + 1);
		if (!p) {
			goto done;
		}
		vsnprintf(p, rc + 1, fmt, ap2);
		ret = rz_strbuf_set(sb, p);
		free(p);
	} else if (rc >= 0) {
		ret = rz_strbuf_set(sb, string);
	}
done:
	va_end(ap2);
	return ret;
}

RZ_API bool rz_strbuf_prepend(RzStrBuf *sb, const char *s) {
	rz_return_val_if_fail(sb && s, false);
	int l = strlen(s);
	// fast path if no chars to append
	if (l == 0) {
		return true;
	}
	int newlen = l + sb->len;
	char *ns = malloc(newlen + 1);
	bool ret = false;
	if (ns) {
		memcpy(ns, s, l);
		char *s = sb->ptr ? sb->ptr : sb->buf;
		memcpy(ns + l, s, sb->len);
		ns[newlen] = 0;
		ret = rz_strbuf_set(sb, ns);
		free(ns);
	}
	return ret;
}

RZ_API bool rz_strbuf_append(RzStrBuf *sb, const char *s) {
	rz_return_val_if_fail(sb && s, false);

	int l = strlen(s);
	return rz_strbuf_append_n(sb, s, l);
}

RZ_API bool rz_strbuf_append_n(RzStrBuf *sb, const char *s, size_t l) {
	rz_return_val_if_fail(sb && s, false);

	if (sb->weakref) {
		return false;
	}

	// fast path if no chars to append
	if (l == 0) {
		return true;
	}

	if ((sb->len + l + 1) <= sizeof(sb->buf)) {
		memcpy(sb->buf + sb->len, s, l);
		sb->buf[sb->len + l] = 0;
		RZ_FREE(sb->ptr);
	} else {
		int newlen = sb->len + l + 128;
		char *p = sb->ptr;
		bool allocated = true;
		if (!sb->ptr) {
			p = malloc(newlen);
			if (p && sb->len > 0) {
				memcpy(p, sb->buf, sb->len);
			}
		} else if (sb->len + l + 1 > sb->ptrlen) {
			p = realloc(sb->ptr, newlen);
		} else {
			allocated = false;
		}
		if (allocated) {
			if (!p) {
				return false;
			}
			sb->ptr = p;
			sb->ptrlen = newlen;
		}
		if (p) {
			memcpy(p + sb->len, s, l);
			*(p + sb->len + l) = 0;
		}
	}
	sb->len += l;
	return true;
}

RZ_API bool rz_strbuf_appendf(RzStrBuf *sb, const char *fmt, ...) {
	va_list ap;

	rz_return_val_if_fail(sb && fmt, -1);

	va_start(ap, fmt);
	bool ret = rz_strbuf_vappendf(sb, fmt, ap);
	va_end(ap);
	return ret;
}

RZ_API bool rz_strbuf_vappendf(RzStrBuf *sb, const char *fmt, va_list ap) {
	int ret;
	va_list ap2;
	char string[1024];

	rz_return_val_if_fail(sb && fmt, -1);

	if (sb->weakref) {
		return false;
	}
	va_copy(ap2, ap);
	ret = vsnprintf(string, sizeof(string), fmt, ap);
	if (ret >= sizeof(string)) {
		char *p = malloc(ret + 1);
		if (!p) {
			va_end(ap2);
			return false;
		}
		*p = 0;
		vsnprintf(p, ret + 1, fmt, ap2);
		ret = rz_strbuf_append(sb, p);
		free(p);
	} else if (ret >= 0) {
		ret = rz_strbuf_append(sb, string);
	} else {
		ret = false;
	}
	va_end(ap2);
	return ret;
}

RZ_API char *rz_strbuf_get(RzStrBuf *sb) {
	rz_return_val_if_fail(sb, NULL);
	return sb->ptr ? sb->ptr : sb->buf;
}

RZ_API ut8 *rz_strbuf_getbin(RzStrBuf *sb, int *len) {
	rz_return_val_if_fail(sb, NULL);
	if (len) {
		*len = sb->len;
	}
	return (ut8 *)(sb->ptr ? sb->ptr : sb->buf);
}

static inline char *drain(RzStrBuf *sb) {
	return sb->ptr
		? sb->weakref
			? rz_mem_dup(sb->ptr, sb->ptrlen)
			: sb->ptr
		: strdup(sb->buf);
}

RZ_API char *rz_strbuf_drain(RzStrBuf *sb) {
	rz_return_val_if_fail(sb, NULL);
	char *ret = drain(sb);
	free(sb);
	return ret;
}

RZ_API char *rz_strbuf_drain_nofree(RzStrBuf *sb) {
	rz_return_val_if_fail(sb, NULL);
	char *ret = drain(sb);
	sb->ptr = NULL;
	sb->len = 0;
	sb->buf[0] = '\0';
	return ret;
}

RZ_API void rz_strbuf_free(RzStrBuf *sb) {
	if (sb) {
		rz_strbuf_fini(sb);
		free(sb);
	}
}

RZ_API void rz_strbuf_fini(RzStrBuf *sb) {
	if (sb && !sb->weakref) {
		RZ_FREE(sb->ptr);
		sb->len = 0;
		sb->buf[0] = '\0';
	}
}
