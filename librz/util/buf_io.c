// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_io.h>

typedef RzIOBind *BufIOUser;

typedef struct buf_io_priv {
	RzIOBind *iob;
	ut64 offset;
} BufIOPriv;

static bool buf_io_init(RzBuffer *b, const void *user) {
	BufIOUser u = (void *)user;
	rz_return_val_if_fail(u, false);
	BufIOPriv *priv = RZ_NEW(BufIOPriv);
	if (!priv) {
		return false;
	}
	priv->iob = u;
	priv->offset = 0;
	b->priv = priv;
	return true;
}

static bool buf_io_fini(RzBuffer *b) {
	free(b->priv);
	return true;
}

static st64 buf_io_seek(RzBuffer *b, st64 addr, int whence) {
	BufIOPriv *priv = b->priv;
	priv->offset = rz_seek_offset(priv->offset, 0, addr, whence);
	return priv->offset; // TODO: this might be negative and be detected as error
}

static ut64 buf_io_get_size(RzBuffer *b) {
	return 0; // TODO: overflow :-(
}

static bool buf_io_resize(RzBuffer *b, ut64 newsize) {
	return false;
}

static st64 buf_io_read(RzBuffer *b, ut8 *buf, ut64 len) {
	BufIOPriv *priv = b->priv;
	len = RZ_MIN(INT_MAX, len); // remove if read_at takes ut64 at some point
	return priv->iob->read_at(priv->iob->io, priv->offset, buf, len);
}

static st64 buf_io_write(RzBuffer *b, const ut8 *buf, ut64 len) {
	BufIOPriv *priv = b->priv;
	len = RZ_MIN(INT_MAX, len); // remove if write_at takes ut64 at some point
	return priv->iob->write_at(priv->iob->io, priv->offset, buf, len);
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
