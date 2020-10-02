/* radare - LGPL - Copyright 2013-2016 - pancake */

#include <rz_userconf.h>
#include <rz_io.h>
#include <rz_lib.h>

typedef struct rz_io_mmo_t {
	char * filename;
	int mode;
	int flags;
	int fd;
	int opened;
	ut8 modified;
	RBuffer *buf;
	RzIO * io_backref;
} RzIOMMapFileObj;

static ut64 rz_io_mmap_seek(RzIO *io, RzIOMMapFileObj *mmo, ut64 offset, int whence) {
	ut64 seek_val = rz_buf_tell (mmo->buf);
	switch (whence) {
	case SEEK_SET:
		seek_val = (rz_buf_size (mmo->buf) < offset)? rz_buf_size (mmo->buf): offset;
		rz_buf_seek (mmo->buf, io->off = seek_val, RZ_BUF_SET);
		return seek_val;
	case SEEK_CUR:
		seek_val = (rz_buf_size (mmo->buf) < (offset + rz_buf_tell (mmo->buf)))? rz_buf_size (mmo->buf): offset + rz_buf_tell (mmo->buf);
		rz_buf_seek (mmo->buf, io->off = seek_val, RZ_BUF_SET);
		return seek_val;
	case SEEK_END:
		seek_val = rz_buf_size (mmo->buf);
		rz_buf_seek (mmo->buf, io->off = seek_val, RZ_BUF_SET);
		return seek_val;
	}
	return seek_val;
}

static bool rz_io_mmap_refresh_buf(RzIOMMapFileObj *mmo) {
	RzIO* io = mmo->io_backref;
	ut64 cur = mmo->buf? rz_buf_tell (mmo->buf): 0;
	if (mmo->buf) {
		rz_buf_free (mmo->buf);
		mmo->buf = NULL;
	}
	mmo->buf = rz_buf_new_mmap (mmo->filename, mmo->flags);
	if (mmo->buf) {
		rz_io_mmap_seek (io, mmo, cur, SEEK_SET);
	}
	return mmo->buf != NULL;
}

static void rz_io_mmap_free(RzIOMMapFileObj *mmo) {
	free (mmo->filename);
	rz_buf_free (mmo->buf);
	memset (mmo, 0, sizeof (RzIOMMapFileObj));
	free (mmo);
}

RzIOMMapFileObj *rz_io_mmap_create_new_file(RzIO  *io, const char *filename, int mode, int flags) {
	RzIOMMapFileObj *mmo;
	if (!io) {
		return NULL;
	}
	mmo = RZ_NEW0 (RzIOMMapFileObj);
	if (!mmo) {
		return NULL;
	}
	mmo->filename = strdup (filename);
	mmo->fd = rz_num_rand (0xFFFF); // XXX: Use rz_io_fd api
	mmo->mode = mode;
	mmo->flags = flags;
	mmo->io_backref = io;
	if (!rz_io_mmap_refresh_buf (mmo)) {
		rz_io_mmap_free (mmo);
		mmo = NULL;
	}
	return mmo;
}

static int rz_io_mmap_close(RzIODesc *fd) {
	if (!fd || !fd->data) {
		return -1;
	}
	rz_io_mmap_free ((RzIOMMapFileObj *) fd->data);
	fd->data = NULL;
	return 0;
}

static int rz_io_mmap_check (const char *filename) {
	return (filename && !strncmp (filename, "mmap://", 7) && *(filename + 7));
}

static int rz_io_mmap_read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	RzIOMMapFileObj *mmo = NULL;
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	mmo = fd->data;
	if (rz_buf_size (mmo->buf) < io->off) {
		io->off = rz_buf_size (mmo->buf);
	}
	int r = rz_buf_read_at (mmo->buf, io->off, buf, count);
	if (r >= 0) {
		rz_buf_seek (mmo->buf, r, RZ_BUF_CUR);
	}
	return r;
}

static int rz_io_mmap_write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	RzIOMMapFileObj *mmo;
	int len = count;
	ut64 addr;

	if (!io || !fd || !fd->data || !buf) {
		return -1;
	}
	mmo = fd->data;
	addr = io->off;
	if ( !(mmo->flags & RZ_PERM_W)) {
		return -1;
	}
	if ( (count + addr > rz_buf_size (mmo->buf)) || rz_buf_size (mmo->buf) == 0) {
		ut64 sz = count + addr;
		rz_file_truncate (mmo->filename, sz);
	}
	len = rz_file_mmap_write (mmo->filename, io->off, buf, len);
	if (!rz_io_mmap_refresh_buf (mmo) ) {
		eprintf ("io_mmap: failed to refresh the mmap backed buffer.\n");
		// XXX - not sure what needs to be done here (error handling).
	}
	return len;
}

static RzIODesc *rz_io_mmap_open(RzIO *io, const char *file, int flags, int mode) {
	if (!strncmp (file, "mmap://", 7)) {
		file += 7;
	}
	RzIOMMapFileObj *mmo = rz_io_mmap_create_new_file (io, file, mode, flags);
	return mmo? rz_io_desc_new (io, &rz_io_plugin_mmap, mmo->filename, flags, mode, mmo): NULL;
}

static ut64 rz_io_mmap_lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	RzIOMMapFileObj *mmo;
	if (!fd || !fd->data) {
		return -1;
	}
	mmo = fd->data;
	return rz_io_mmap_seek (io, mmo, offset, whence);
}

static bool rz_io_mmap_truncate(RzIOMMapFileObj *mmo, ut64 size) {
	int res = rz_file_truncate (mmo->filename, size);
	if (res && !rz_io_mmap_refresh_buf (mmo)) {
		eprintf ("rz_io_mmap_truncate: Error trying to refresh the mmap'ed file.");
		res = false;
	} else if (res) {
		eprintf ("rz_io_mmap_truncate: Error trying to resize the file.");
	}
	return res;
}


static bool __plugin_open(RzIO *io, const char *file, bool many) {
	return rz_io_mmap_check (file);
}

static RzIODesc *__open(RzIO *io, const char *file, int flags, int mode) {
	if (!rz_io_mmap_check (file)) {
		return NULL;
	}
	return rz_io_mmap_open (io, file, flags, mode);
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, int len) {
	return rz_io_mmap_read (io, fd, buf, len);
}

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int len) {
	return rz_io_mmap_write(io, fd, buf, len);
}

static ut64 __lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	return rz_io_mmap_lseek (io, fd, offset, whence);
}

static int __close(RzIODesc *fd) {
	return rz_io_mmap_close (fd);
}

static bool __resize(RzIO *io, RzIODesc *fd, ut64 size) {
	if (!fd || !fd->data) {
		return false;
	}
	return rz_io_mmap_truncate ((RzIOMMapFileObj*)fd->data, size);
}

struct rz_io_plugin_t rz_io_plugin_mmap = {
	.name = "mmap",
	.desc = "Open files using mmap",
	.uris = "mmap://",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_mmap,
	.version = RZ_VERSION
};
#endif
