// SPDX-FileCopyrightText: 2009-2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

struct buf_ref_user {
	RzBuffer *parent;
	ut64 offset;
	ut64 size;
};

struct buf_ref_priv {
	RzBuffer *parent;
	ut64 cur;
	ut64 base;
	ut64 size;
};

static inline struct buf_ref_priv *get_priv_ref(RzBuffer *b) {
	struct buf_ref_priv *priv = (struct buf_ref_priv *)b->priv;
	rz_warn_if_fail(priv);
	return priv;
}

static bool buf_ref_init(RzBuffer *b, const void *user) {
	const struct buf_ref_user *u = (const struct buf_ref_user *)user;
	struct buf_ref_priv *priv = RZ_NEW0(struct buf_ref_priv);
	if (!priv) {
		return false;
	}

	// NOTE: we only support readonly ref-buffers for now. Supporting
	// read-write would mean to choose how we want to handle writing to the
	// referencer. Copy-on-write? Write to the buffer underneath?
	ut64 parent_sz = rz_buf_size(u->parent);
	b->readonly = true;
	priv->parent = rz_buf_ref(u->parent);
	priv->base = RZ_MIN(u->offset, parent_sz);
	priv->size = RZ_MIN(parent_sz - priv->base, u->size);
	b->priv = priv;
	return true;
}

static bool buf_ref_fini(RzBuffer *b) {
	struct buf_ref_priv *priv = get_priv_ref(b);
	rz_buf_free(priv->parent);
	RZ_FREE(b->priv);
	return true;
}

static bool buf_ref_resize(RzBuffer *b, ut64 newsize) {
	struct buf_ref_priv *priv = get_priv_ref(b);
	ut64 parent_sz = rz_buf_size(priv->parent);
	priv->size = RZ_MIN(parent_sz - priv->base, newsize);
	return true;
}

static st64 buf_ref_read(RzBuffer *b, ut8 *buf, ut64 len) {
	struct buf_ref_priv *priv = get_priv_ref(b);
	if (priv->size < priv->cur) {
		return -1;
	}
	len = RZ_MIN(len, priv->size - priv->cur);
	st64 r = rz_buf_read_at(priv->parent, priv->base + priv->cur, buf, len);
	if (r < 0) {
		return r;
	}
	priv->cur += r;
	return r;
}

static ut64 buf_ref_get_size(RzBuffer *b) {
	struct buf_ref_priv *priv = get_priv_ref(b);
	return priv->size;
}

static st64 buf_ref_seek(RzBuffer *b, st64 addr, int whence) {
	struct buf_ref_priv *priv = get_priv_ref(b);
	switch (whence) {
	case RZ_BUF_CUR:
		priv->cur += addr;
		break;
	case RZ_BUF_SET:
		priv->cur = addr;
		break;
	case RZ_BUF_END:
		priv->cur = priv->size + addr;
		break;
	default:
		rz_warn_if_reached();
		return -1;
	}
	return priv->cur;
}

static const RzBufferMethods buffer_ref_methods = {
	.init = buf_ref_init,
	.fini = buf_ref_fini,
	.read = buf_ref_read,
	.get_size = buf_ref_get_size,
	.resize = buf_ref_resize,
	.seek = buf_ref_seek,
};
