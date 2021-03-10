// SPDX-FileCopyrightText: 2009-2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

struct buf_sparse_priv {
	RzList *sparse;
	ut64 offset;
};

static void buffer_sparse_free(void *a) {
	RzBufferSparse *s = (RzBufferSparse *)a;
	free(s->data);
	free(s);
}

static bool sparse_limits(RzList *l, ut64 *max) {
	bool set = false;
	RzBufferSparse *s;
	RzListIter *iter;

	rz_list_foreach (l, iter, s) {
		if (set) {
			if (max && s->to > *max) {
				*max = s->to;
			}
		} else {
			set = true;
			if (max) {
				*max = s->to;
			}
		}
	}
	return set;
}

static RzBufferSparse *sparse_append(RzList *l, ut64 addr, const ut8 *data, ut64 len) {
	if (l && data) {
		RzBufferSparse *s = RZ_NEW0(RzBufferSparse);
		if (s) {
			s->data = calloc(1, len);
			if (s->data) {
				s->from = addr;
				s->to = addr + len;
				s->size = len;
				memcpy(s->data, data, len);
				return rz_list_append(l, s) ? s : NULL;
			}
			free(s);
		}
	}
	return NULL;
}

//ret -1 if failed; # of bytes copied if success
static st64 sparse_write(RzList *l, ut64 addr, const ut8 *data, ut64 len) {
	RzBufferSparse *s;
	RzListIter *iter;
	ut64 olen = len;

	rz_list_foreach (l, iter, s) {
		if (addr >= s->from && addr < s->to) {
			ut64 delta = addr - s->from;
			ut64 reallen = s->size - delta >= len ? len : s->size - delta;
			memcpy(s->data + delta, data, reallen);
			data += reallen;
			len -= reallen;
			addr += reallen;
		}
		if (len == 0) {
			return olen;
		}
	}
	if (len > 0 && !sparse_append(l, addr, data, len)) {
		return -1;
	}
	return olen;
}

static inline struct buf_sparse_priv *get_priv_sparse(RzBuffer *b) {
	struct buf_sparse_priv *priv = (struct buf_sparse_priv *)b->priv;
	rz_warn_if_fail(priv);
	return priv;
}

static bool buf_sparse_init(RzBuffer *b, const void *user) {
	struct buf_sparse_priv *priv = RZ_NEW0(struct buf_sparse_priv);
	if (!priv) {
		return false;
	}
	priv->sparse = rz_list_newf(buffer_sparse_free);
	priv->offset = 0;
	b->priv = priv;
	return true;
}

static bool buf_sparse_fini(RzBuffer *b) {
	struct buf_sparse_priv *priv = get_priv_sparse(b);
	rz_list_free(priv->sparse);
	RZ_FREE(b->priv);
	return true;
}

static bool buf_sparse_resize(RzBuffer *b, ut64 newsize) {
	struct buf_sparse_priv *priv = get_priv_sparse(b);
	RzListIter *iter, *tmp;
	RzBufferSparse *s;

	rz_list_foreach_safe (priv->sparse, iter, tmp, s) {
		if (s->from >= newsize) {
			rz_list_delete(priv->sparse, iter);
		} else if (s->to >= newsize) {
			RzBufferSparse *ns = RZ_NEW(RzBufferSparse);
			ns->from = s->from;
			ns->to = newsize;
			ns->size = ns->to - ns->from;
			ut8 *tmp = realloc(s->data, s->size);
			if (!tmp) {
				free(ns);
				return false;
			}
			// otherwise it will be double-freed by rz_list_delete
			s->data = NULL;
			ns->data = tmp;
			ns->written = s->written;
			rz_list_append(priv->sparse, ns);
			rz_list_delete(priv->sparse, iter);
		}
	}
	ut64 max;
	max = sparse_limits(priv->sparse, &max) ? max : 0;
	if (max < newsize) {
		return !!sparse_write(priv->sparse, newsize - 1, &b->Oxff_priv, 1);
	}
	return true;
}

static ut64 buf_sparse_size(RzBuffer *b) {
	struct buf_sparse_priv *priv = get_priv_sparse(b);
	ut64 max;

	return sparse_limits(priv->sparse, &max) ? max : 0;
}

static st64 buf_sparse_read(RzBuffer *b, ut8 *buf, ut64 len) {
	struct buf_sparse_priv *priv = get_priv_sparse(b);
	RzBufferSparse *c;
	RzListIter *iter;
	ut64 max = 0;

	memset(buf, b->Oxff_priv, len);
	rz_list_foreach (priv->sparse, iter, c) {
		if (max < c->to) {
			max = c->to;
		}
		if (priv->offset < c->to && c->from < priv->offset + len) {
			if (priv->offset < c->from) {
				ut64 l = RZ_MIN(priv->offset + len - c->from, c->size);
				memcpy(buf + c->from - priv->offset, c->data, l);
			} else {
				ut64 l = RZ_MIN(c->to - priv->offset, len);
				memcpy(buf, c->data + priv->offset - c->from, l);
			}
		}
	}
	if (priv->offset > max) {
		return -1;
	}
	ut64 r = RZ_MIN(max - priv->offset, len);
	priv->offset += r;
	return r;
}

static st64 buf_sparse_write(RzBuffer *b, const ut8 *buf, ut64 len) {
	struct buf_sparse_priv *priv = get_priv_sparse(b);
	st64 r = sparse_write(priv->sparse, priv->offset, buf, len);
	priv->offset += r;
	return r;
}

static st64 buf_sparse_seek(RzBuffer *b, st64 addr, int whence) {
	struct buf_sparse_priv *priv = get_priv_sparse(b);
	ut64 max;
	if (addr < 0 && (-addr) > (st64)priv->offset) {
		return -1;
	}

	switch (whence) {
	case RZ_BUF_CUR:
		priv->offset += addr;
		break;
	case RZ_BUF_SET:
		priv->offset = addr;
		break;
	case RZ_BUF_END:
		if (!sparse_limits(priv->sparse, &max)) {
			max = 0;
		}
		priv->offset = max + addr;
		break;
	default:
		rz_warn_if_reached();
		return -1;
	}
	return priv->offset;
}

static RzList *buf_sparse_nonempty_list(RzBuffer *b) {
	struct buf_sparse_priv *priv = get_priv_sparse(b);
	return rz_list_clone(priv->sparse);
}

static const RzBufferMethods buffer_sparse_methods = {
	.init = buf_sparse_init,
	.fini = buf_sparse_fini,
	.read = buf_sparse_read,
	.write = buf_sparse_write,
	.get_size = buf_sparse_size,
	.resize = buf_sparse_resize,
	.seek = buf_sparse_seek,
	.nonempty_list = buf_sparse_nonempty_list,
};
