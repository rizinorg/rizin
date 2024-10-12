// SPDX-FileCopyrightText: 2009-2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_io.h>

struct buf_io_fd_user {
	RzIOBind *iob;
	int fd;
};

struct buf_io_fd_priv {
	RzIOBind *iob;
	int fd;
};

static inline struct buf_io_fd_priv *get_priv_io(RzBuffer *b) {
	struct buf_io_fd_priv *priv = (struct buf_io_fd_priv *)b->priv;
	rz_warn_if_fail(priv);
	return priv;
}

static bool buf_io_fd_init(RzBuffer *b, const void *user) {
	const struct buf_io_fd_user *u = (const struct buf_io_fd_user *)user;
	struct buf_io_fd_priv *priv = RZ_NEW0(struct buf_io_fd_priv);
	if (!priv) {
		return false;
	}
	priv->iob = u->iob;
	priv->fd = u->fd;
	b->priv = priv;
	b->fd = priv->fd;
	return true;
}

static bool buf_io_fd_fini(RzBuffer *b) {
	// struct buf_io_fd_priv *priv = get_priv_io (b);
	RZ_FREE(b->priv);
	return true;
}

static st64 buf_io_fd_seek(RzBuffer *b, st64 addr, int whence) {
	struct buf_io_fd_priv *priv = get_priv_io(b);
	int io_whence;

	switch (whence) {
	default:
		rz_warn_if_reached();
		// fallthrough
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

static ut64 buf_io_fd_get_size(RzBuffer *b) {
	struct buf_io_fd_priv *priv = get_priv_io(b);
	return priv->iob->fd_size(priv->iob->io, priv->fd);
}

static bool buf_io_fd_resize(RzBuffer *b, ut64 newsize) {
	struct buf_io_fd_priv *priv = get_priv_io(b);
	return priv->iob->fd_resize(priv->iob->io, priv->fd, newsize);
}

static st64 buf_io_fd_read(RZ_BORROW RzBuffer *b, RZ_OUT ut8 *buf, ut64 len) {
	struct buf_io_fd_priv *priv = get_priv_io(b);
	st64 result = priv->iob->fd_read(priv->iob->io, priv->fd, buf, len);
	return result;
}

static st64 buf_io_fd_write(RzBuffer *b, const ut8 *buf, ut64 len) {
	struct buf_io_fd_priv *priv = get_priv_io(b);
	return priv->iob->fd_write(priv->iob->io, priv->fd, buf, len);
}

static ut8 *buf_io_fd_get_whole_buf(RzBuffer *b, ut64 *size) {
	struct buf_io_fd_priv *priv = get_priv_io(b);
	return priv->iob->fd_getbuf(priv->iob->io, priv->fd, size);
}

static const RzBufferMethods buffer_io_fd_methods = {
	.init = buf_io_fd_init,
	.fini = buf_io_fd_fini,
	.read = buf_io_fd_read,
	.write = buf_io_fd_write,
	.get_size = buf_io_fd_get_size,
	.resize = buf_io_fd_resize,
	.seek = buf_io_fd_seek,
	.get_whole_buf = buf_io_fd_get_whole_buf
};
