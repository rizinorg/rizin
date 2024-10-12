// SPDX-FileCopyrightText: 2009-2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

struct buf_bytes_user {
	const ut8 *data;
	const ut8 *data_steal;
	ut64 length;
	bool steal;
};

struct buf_bytes_priv {
	ut8 *buf;
	ut64 length;
	ut64 offset;
	bool is_bufowner;
};

static inline struct buf_bytes_priv *get_priv_bytes(RzBuffer *b) {
	struct buf_bytes_priv *priv = (struct buf_bytes_priv *)b->priv;
	rz_warn_if_fail(priv);
	return priv;
}

static bool buf_bytes_init(RzBuffer *b, const void *user) {
	const struct buf_bytes_user *u = (const struct buf_bytes_user *)user;
	struct buf_bytes_priv *priv = RZ_NEW0(struct buf_bytes_priv);
	if (!priv) {
		return false;
	}

	priv->offset = 0;
	priv->length = u->length;
	if (u->data_steal) {
		priv->buf = (ut8 *)u->data_steal;
		priv->is_bufowner = u->steal;
	} else {
		priv->buf = malloc(priv->length);
		if (!priv->buf) {
			free(priv);
			return false;
		}
		if (priv->length) {
			memmove(priv->buf, u->data, priv->length);
		}
		priv->is_bufowner = true;
	}
	b->priv = priv;
	return true;
}

static bool buf_bytes_fini(RzBuffer *b) {
	struct buf_bytes_priv *priv = get_priv_bytes(b);
	if (priv->is_bufowner) {
		free(priv->buf);
	}
	RZ_FREE(b->priv);
	return true;
}

static bool buf_bytes_resize(RzBuffer *b, ut64 newsize) {
	struct buf_bytes_priv *priv = get_priv_bytes(b);
	if (newsize > priv->length) {
		ut8 *t = realloc(priv->buf, newsize);
		if (!t) {
			return false;
		}
		priv->buf = t;
		memset(priv->buf + priv->length, b->Oxff_priv, newsize - priv->length);
	}
	priv->length = newsize;
	return true;
}

static st64 buf_bytes_read(RZ_BORROW RzBuffer *b, RZ_OUT ut8 *buf, ut64 len) {
	struct buf_bytes_priv *priv = get_priv_bytes(b);
	if (!priv->buf) {
		// This can happen when called from buf_mmap.c, when you open a 0-length
		// file.
		return -1;
	}
	ut64 real_len = priv->length < priv->offset ? 0 : RZ_MIN(priv->length - priv->offset, len);
	memmove(buf, priv->buf + priv->offset, real_len);
	priv->offset += real_len;
	return real_len;
}

static st64 buf_bytes_write(RzBuffer *b, const ut8 *buf, ut64 len) {
	struct buf_bytes_priv *priv = get_priv_bytes(b);
	if (priv->offset > priv->length || priv->offset + len >= priv->length) {
		bool r = rz_buf_resize(b, priv->offset + len);
		if (!r) {
			return -1;
		}
	}
	rz_warn_if_fail(priv->buf);
	memmove(priv->buf + priv->offset, buf, len);
	priv->offset += len;
	return len;
}

static ut64 buf_bytes_get_size(RzBuffer *b) {
	struct buf_bytes_priv *priv = get_priv_bytes(b);
	return priv->length;
}

static st64 buf_bytes_seek(RzBuffer *b, st64 addr, int whence) {
	struct buf_bytes_priv *priv = get_priv_bytes(b);
	st64 val = rz_seek_offset(priv->offset, priv->length, addr, whence);
	if (val == -1) {
		return -1;
	}
	return priv->offset = val;
}

static ut8 *buf_bytes_get_whole_buf(RzBuffer *b, ut64 *sz) {
	struct buf_bytes_priv *priv = get_priv_bytes(b);
	if (sz) {
		*sz = priv->length;
	}
	return priv->buf;
}

static const RzBufferMethods buffer_bytes_methods = {
	.init = buf_bytes_init,
	.fini = buf_bytes_fini,
	.read = buf_bytes_read,
	.write = buf_bytes_write,
	.get_size = buf_bytes_get_size,
	.resize = buf_bytes_resize,
	.seek = buf_bytes_seek,
	.get_whole_buf = buf_bytes_get_whole_buf
};
