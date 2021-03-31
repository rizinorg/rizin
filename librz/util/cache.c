// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

// XXX: should use the same code as librz/io/cache.c
// one malloc per write
#include <rz_util.h>
// TODO: optimize reallocs.. store RzBuffer info.. wait. extend rz_buf_ for that?

RZ_API RzCache *rz_cache_new(void) {
	RzCache *c = RZ_NEW0(RzCache);
	if (!c) {
		return NULL;
	}
	c->buf = NULL;
	c->base = 0;
	c->len = 0;
	return c;
}

RZ_API void rz_cache_free(RzCache *c) {
	if (c) {
		free(c->buf);
	}
	free(c);
}

RZ_API const ut8 *rz_cache_get(RzCache *c, ut64 addr, int *len) {
	if (!c->buf) {
		return NULL;
	}
	if (len) {
		*len = c->base - addr;
	}
	if (addr < c->base) {
		return NULL;
	}
	if (addr > (c->base + c->len)) {
		return NULL;
	}
	if (len) {
		*len = c->len - (addr - c->base);
	}
	// eprintf ("4 - %d\n", (addr-c->base));
	return c->buf + (addr - c->base);
}

RZ_API int rz_cache_set(RzCache *c, ut64 addr, const ut8 *buf, int len) {
	if (!c) {
		return 0;
	}
	if (!c->buf) {
		c->buf = malloc(len);
		if (!c->buf) {
			return 0;
		}
		memcpy(c->buf, buf, len);
		c->base = addr;
		c->len = len;
	} else if (addr < c->base) {
		ut8 *b;
		int baselen = (c->base - addr);
		int newlen = baselen + ((len > c->len) ? len : c->base);
		// XXX expensive heap usage. must simplify
		b = malloc(newlen);
		if (!b) {
			return 0;
		}
		memset(b, 0xff, newlen);
		memcpy(b + baselen, c->buf, c->len);
		memcpy(b, buf, len);
		free(c->buf);
		c->buf = b;
		c->base = addr;
		c->len = newlen;
	} else if ((addr + len) > (c->base + c->len)) {
		ut8 *b;
		int baselen = (addr - c->base);
		int newlen = baselen + len;
		b = realloc(c->buf, newlen);
		if (!b) {
			return 0;
		}
		memcpy(b + baselen, buf, len);
		c->buf = b;
		c->len = newlen;
	} else {
		memcpy(c->buf, buf, len);
	}
	return c->len;
}

RZ_API void rz_cache_flush(RzCache *c) {
	if (c) {
		c->base = 0;
		c->len = 0;
		RZ_FREE(c->buf);
	}
}
