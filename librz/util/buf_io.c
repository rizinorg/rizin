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
	st64 val = rz_seek_offset(priv->offset, 0, addr, whence);
	if (val == -1) {
		return -1;
	}
	priv->offset = val;
	// can't express the seek right if the highest bit is set,
	// but at least tell the caller there was no error:
	return RZ_MIN(priv->offset, ST64_MAX);
}

static st64 buf_io_read(RzBuffer *b, ut8 *buf, ut64 len) {
	BufIOPriv *priv = b->priv;
	len = RZ_MIN(INT_MAX, len); // remove if read_at takes ut64 at some point
	bool success = priv->iob->read_at(priv->iob->io, priv->offset, buf, len);
	if (success) {
		rz_seek_offset(priv->offset, 0, len, RZ_BUF_CUR);
	}
	return success ? len : -1;
}

static st64 buf_io_write(RzBuffer *b, const ut8 *buf, ut64 len) {
	BufIOPriv *priv = b->priv;
	len = RZ_MIN(INT_MAX, len); // remove if write_at takes ut64 at some point
	bool r = priv->iob->write_at(priv->iob->io, priv->offset, buf, len);
	return r ? len : -1;
}

static const RzBufferMethods buffer_io_methods = {
	.init = buf_io_init,
	.fini = buf_io_fini,
	.read = buf_io_read,
	.write = buf_io_write,
	.seek = buf_io_seek,
};
