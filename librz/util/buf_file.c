// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>

struct buf_file_user {
	const char *file;
	int perm;
	int mode;
};

struct buf_file_priv {
	int fd;
	ut8 tmp[8];
};

static inline struct buf_file_priv *get_priv_file(RzBuffer *b) {
	struct buf_file_priv *priv = (struct buf_file_priv *)b->priv;
	rz_warn_if_fail (priv);
	return priv;
}

static bool buf_file_init(RzBuffer *b, const void *user) {
	const struct buf_file_user *u = (const struct buf_file_user *)user;
	struct buf_file_priv *priv = RZ_NEW0 (struct buf_file_priv);
	if (!priv) {
		return false;
	}
	int fd = rz_sys_open (u->file, u->perm, u->mode);
	if (fd == -1) {
		free (priv);
		return false;
	}
	priv->fd = fd;
	b->priv = priv;
	b->fd = priv->fd;
	return true;
}

static bool buf_file_fini(RzBuffer *b) {
	struct buf_file_priv *priv = get_priv_file (b);
	close (priv->fd);
	RZ_FREE (b->priv);
	return true;
}

static ut64 buf_file_get_size(RzBuffer *b) {
	struct buf_file_priv *priv = get_priv_file (b);
	int pos = lseek (priv->fd, 0, SEEK_CUR);
	int res = lseek (priv->fd, 0, SEEK_END);
	lseek (priv->fd, (off_t)pos, SEEK_SET);
	return (ut64)res;
}

static st64 buf_file_read(RzBuffer *b, ut8 *buf, ut64 len) {
	struct buf_file_priv *priv = get_priv_file (b);
	return read (priv->fd, buf, len);
}

static st64 buf_file_write(RzBuffer *b, const ut8 *buf, ut64 len) {
	struct buf_file_priv *priv = get_priv_file (b);
	return write (priv->fd, buf, len);
}

static st64 buf_file_seek(RzBuffer *b, st64 addr, int whence) {
	struct buf_file_priv *priv = get_priv_file (b);
	switch (whence) {
	case RZ_BUF_CUR: whence = SEEK_CUR; break;
	case RZ_BUF_SET: whence = SEEK_SET; break;
	case RZ_BUF_END: whence = SEEK_END; break;
	}
	return lseek (priv->fd, (off_t)addr, whence);
}

static bool buf_file_resize(RzBuffer *b, ut64 newsize) {
	struct buf_file_priv *priv = get_priv_file (b);
	return rz_sys_truncate_fd (priv->fd, newsize) >= 0;
}

static const RzBufferMethods buffer_file_methods = {
	.init = buf_file_init,
	.fini = buf_file_fini,
	.read = buf_file_read,
	.write = buf_file_write,
	.get_size = buf_file_get_size,
	.resize = buf_file_resize,
	.seek = buf_file_seek,
};
