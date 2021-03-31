// SPDX-FileCopyrightText: 2009-2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_io.h>

struct buf_io_user {
	RzIOBind *iob;
	int fd;
};

struct buf_io_priv {
	RzIOBind *iob;
	int fd;
};

static inline struct buf_io_priv *get_priv_io(RzBuffer *b) {
	struct buf_io_priv *priv = (struct buf_io_priv *)b->priv;
	rz_warn_if_fail(priv);
	return priv;
}

static bool buf_io_init(RzBuffer *b, const void *user) {
	const struct buf_io_user *u = (const struct buf_io_user *)user;
	struct buf_io_priv *priv = RZ_NEW0(struct buf_io_priv);
	if (!priv) {
		return false;
	}
	priv->iob = u->iob;
	priv->fd = u->fd;
	b->priv = priv;
	b->fd = priv->fd;
	return true;
}

static bool buf_io_fini(RzBuffer *b) {
	//struct buf_io_priv *priv = get_priv_io (b);
	RZ_FREE(b->priv);
	return true;
}

static st64 buf_io_seek(RzBuffer *b, st64 addr, int whence) {
	struct buf_io_priv *priv = get_priv_io(b);
	int io_whence;

	switch (whence) {
	default:
		rz_warn_if_reached();
	case RZ_BUF_SET:
		io_whence = RZ_IO_SEEK_SET;
		break;
	case RZ_BUF_END:
		io_whence = RZ_IO_SEEK_END;
		break;
	case RZ_BUF_CUR:
		io_whence = RZ_IO_SEEK_CUR;
		break;
	}
	return priv->iob->fd_seek(priv->iob->io, priv->fd, addr, io_whence);
}

static ut64 buf_io_get_size(RzBuffer *b) {
	struct buf_io_priv *priv = get_priv_io(b);
	return priv->iob->fd_size(priv->iob->io, priv->fd);
}

static bool buf_io_resize(RzBuffer *b, ut64 newsize) {
	struct buf_io_priv *priv = get_priv_io(b);
	return priv->iob->fd_resize(priv->iob->io, priv->fd, newsize);
}

static st64 buf_io_read(RzBuffer *b, ut8 *buf, ut64 len) {
	struct buf_io_priv *priv = get_priv_io(b);
	return priv->iob->fd_read(priv->iob->io, priv->fd, buf, len);
}

static st64 buf_io_write(RzBuffer *b, const ut8 *buf, ut64 len) {
	struct buf_io_priv *priv = get_priv_io(b);
	return priv->iob->fd_write(priv->iob->io, priv->fd, buf, len);
}

static const RzBufferMethods buffer_io_methods = {
	.init = buf_io_init,
	.fini = buf_io_fini,
	.read = buf_io_read,
	.write = buf_io_write,
	.get_size = buf_io_get_size,
	.resize = buf_io_resize,
	.seek = buf_io_seek,
};
