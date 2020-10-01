/* radare - LGPL - Copyright 2008-2020 - pancake */

#include <rz_userconf.h>
#include <rz_io.h>
#include <rz_lib.h>
#include <stdio.h>

typedef struct rz_io_mmo_t {
	char * filename;
	int mode;
	int perm;
	int fd;
	int opened;
	bool nocache;
	ut8 modified;
	RBuffer *buf;
	RzIO * io_backref;
	bool rawio;
} RzIOMMapFileObj;

static int __io_posix_open(const char *file, int perm, int mode) {
	int fd;
	if (rz_str_startswith (file, "file://")) {
		file += strlen ("file://");
	}
	if (rz_file_is_directory (file)) {
		return -1;
	}
#if __WINDOWS__
	// probably unnecessary to have this ifdef nowadays windows is posix enough
	if (perm & R_PERM_W) {
		fd = rz_sandbox_open (file, O_RDWR, 0);
		if (fd == -1 && (perm & R_PERM_CREAT)) {
			rz_sandbox_creat (file, 0644);
			fd = rz_sandbox_open (file, O_RDWR | O_CREAT, 0);
		}
	} else {
		fd = rz_sandbox_open (file, O_RDONLY | O_BINARY, 0);
	}
#else
	const size_t posixFlags = (perm & R_PERM_W) ? (perm & R_PERM_CREAT)
			? (O_RDWR | O_CREAT) : O_RDWR : O_RDONLY;
	fd = rz_sandbox_open (file, posixFlags, mode);
#endif
	return fd;
}

static ut64 rz_io_def_mmap_seek(RzIO *io, RzIOMMapFileObj *mmo, ut64 offset, int whence) {
	if (!mmo) {
		return UT64_MAX;
	}
	if (mmo->rawio) {
		io->off = lseek (mmo->fd, offset, whence);
		return io->off;
	}
	if (!mmo->buf) {
		return UT64_MAX;
	}
	io->off = rz_buf_seek (mmo->buf, offset, whence);
	return io->off;
}

static int rz_io_def_mmap_refresh_def_mmap_buf(RzIOMMapFileObj *mmo) {
	RzIO* io = mmo->io_backref;
	ut64 cur;
	if (mmo->buf) {
		cur = rz_buf_tell (mmo->buf);
		rz_buf_free (mmo->buf);
		mmo->buf = NULL;
	} else {
		cur = 0;
	}
	st64 sz = rz_file_size (mmo->filename);
	if (sz > ST32_MAX) {
		// Do not use mmap if the file is huge
		mmo->rawio = true;
	}
	if (mmo->rawio) {
		mmo->fd = __io_posix_open (mmo->filename, mmo->perm, mmo->mode);
		if (mmo->nocache) {
#ifdef F_NOCACHE
			fcntl (mmo->fd, F_NOCACHE, 1);
#endif
		}
		return mmo->fd != -1;
	}
	mmo->buf = rz_buf_new_mmap (mmo->filename, mmo->perm);
	if (mmo->buf) {
		rz_io_def_mmap_seek (io, mmo, cur, SEEK_SET);
		return true;
	} else {
		mmo->rawio = true;
		mmo->fd = __io_posix_open (mmo->filename, mmo->perm, mmo->mode);
		if (mmo->nocache) {
#ifdef F_NOCACHE
			fcntl (mmo->fd, F_NOCACHE, 1);
#endif
		}
		return mmo->fd != -1;
	}
	return false;
}

static void rz_io_def_mmap_free (RzIOMMapFileObj *mmo) {
	if (mmo) {
		free (mmo->filename);
		rz_buf_free (mmo->buf);
		close (mmo->fd);
		free (mmo);
	}
}

RzIOMMapFileObj *rz_io_def_mmap_create_new_file(RzIO  *io, const char *filename, int perm, int mode) {
	rz_return_val_if_fail (io && filename, NULL);
	RzIOMMapFileObj *mmo = R_NEW0 (RzIOMMapFileObj);
	if (!mmo) {
		return NULL;
	}
	if (rz_str_startswith (filename, "file://")) {
		filename += strlen ("file://");
	}
	mmo->nocache = rz_str_startswith (filename, "nocache://");
	if (mmo->nocache) {
		filename += strlen ("nocache://");
	}
	mmo->filename = strdup (filename);
	mmo->perm = perm;
	mmo->mode = mode;
	mmo->io_backref = io;
	const int posixFlags = (perm & R_PERM_W)
			?(
				(perm & R_PERM_CREAT)
					? (O_RDWR | O_CREAT)
					: O_RDWR
			): O_RDONLY;
	mmo->fd = rz_sandbox_open (filename, posixFlags, mode);
	if (mmo->fd == -1) {
		free (mmo->filename);
		free (mmo);
		return NULL;
	}
	if (!rz_io_def_mmap_refresh_def_mmap_buf (mmo)) {
		mmo->rawio = true;
		if (!rz_io_def_mmap_refresh_def_mmap_buf (mmo)) {
			rz_io_def_mmap_free (mmo);
			mmo = NULL;
		}
	}
	return mmo;
}

static int rz_io_def_mmap_close(RzIODesc *fd) {
	rz_return_val_if_fail (fd && fd->data, -1);
	rz_io_def_mmap_free ((RzIOMMapFileObj *) fd->data);
	fd->data = NULL;
	return 0;
}

static bool rz_io_def_mmap_check_default (const char *filename) {
	rz_return_val_if_fail (filename && *filename, false);
	if (rz_str_startswith (filename, "file://")) {
		filename += strlen ("file://");
	}
	const char * peekaboo = (!strncmp (filename, "nocache://", 10))
		? NULL : strstr (filename, "://");
	return (!peekaboo || (peekaboo - filename) > 10);
}

static int rz_io_def_mmap_read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	rz_return_val_if_fail (fd && fd->data && buf, -1);
	if (io->off == UT64_MAX) {
		memset (buf, 0xff, count);
		return count;
	}
	// TODO : unbox magic
	RzIOMMapFileObj *mmo = fd->data;
	if (!mmo) {
		return -1;
	}
	if (mmo->rawio) {
		if (lseek (mmo->fd, io->off, SEEK_SET) < 0) {
			return -1;
		}
		return read (mmo->fd, buf, count);
	}
	if (rz_buf_size (mmo->buf) < io->off) {
		io->off = rz_buf_size (mmo->buf);
	}
	int r = rz_buf_read_at (mmo->buf, io->off, buf, count);
	if (r < 0) {
		return r;
	}
	rz_buf_seek (mmo->buf, r, R_BUF_CUR);
	io->off += r;
	return r;
}

static int rz_io_def_mmap_write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	rz_return_val_if_fail (io && fd && fd->data && buf, -1);

	int len = -1;
	ut64 addr = io->off;
	RzIOMMapFileObj *mmo = fd->data;
	if (mmo->rawio) {
		if (lseek (mmo->fd, addr, 0) < 0) {
			return -1;
		}
		len = write (mmo->fd, buf, count);
		return len;
	}

	if (mmo && mmo->buf) {
		if (!(mmo->perm & R_PERM_W)) {
			return -1;
		}
		if ( (count + addr > rz_buf_size (mmo->buf)) || rz_buf_size (mmo->buf) == 0) {
			ut64 sz = count + addr;
			rz_file_truncate (mmo->filename, sz);
		}
	}

	len = rz_file_mmap_write (mmo->filename, io->off, buf, count);
	if (len != count) {
		// aim to hack some corner cases?
		if (lseek (fd->fd, addr, 0) < 0) {
			return -1;
		}
		len = write (fd->fd, buf, count);
	}
	if (!rz_io_def_mmap_refresh_def_mmap_buf (mmo) ) {
		eprintf ("io_def_mmap: failed to refresh the def_mmap backed buffer.\n");
		// XXX - not sure what needs to be done here (error handling).
	}
	return len;
}

static RzIODesc *rz_io_def_mmap_open(RzIO *io, const char *file, int perm, int mode) {
	rz_return_val_if_fail (io && file, NULL);
	RzIOMMapFileObj *mmo = rz_io_def_mmap_create_new_file (io, file, perm, mode);
	if (!mmo) {
		return NULL;
	}
	RzIODesc *d = rz_io_desc_new (io, &rz_io_plugin_default, mmo->filename, perm, mode, mmo);
	if (!d->name) {
		d->name = strdup (file);
	}
	if (rz_str_startswith (d->name, "file://")) {
		char *oldname = d->name;
		d->name = strdup (oldname + strlen ("file://"));
		free (oldname);
	}
	return d;
}

static ut64 rz_io_def_mmap_lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	rz_return_val_if_fail (fd && fd->data, UT64_MAX);
	return rz_io_def_mmap_seek (io, (RzIOMMapFileObj *)fd->data, offset, whence);
}

static int rz_io_def_mmap_truncate(RzIOMMapFileObj *mmo, ut64 size) {
	bool res = rz_file_truncate (mmo->filename, size);
	if (res && !rz_io_def_mmap_refresh_def_mmap_buf (mmo) ) {
		eprintf ("rz_io_def_mmap_truncate: Error trying to refresh the def_mmap'ed file.");
		res = false;
	} else if (!res) {
		eprintf ("rz_io_def_mmap_truncate: Error trying to resize the file.");
	}
	return res;
}

static bool __plugin_open_default(RzIO *io, const char *file, bool many) {
	return rz_io_def_mmap_check_default (file);
}

// default open should permit opening
static RzIODesc *__open_default(RzIO *io, const char *file, int perm, int mode) {
	if (rz_io_def_mmap_check_default (file)) {
		return rz_io_def_mmap_open (io, file, perm, mode);
	}
	return NULL;
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, int len) {
	return rz_io_def_mmap_read (io, fd, buf, len);
}

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int len) {
	return rz_io_def_mmap_write(io, fd, buf, len);
}

static ut64 __lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	return rz_io_def_mmap_lseek (io, fd, offset, whence);
}

static int __close(RzIODesc *fd) {
	return rz_io_def_mmap_close (fd);
}

static bool __resize(RzIO *io, RzIODesc *fd, ut64 size) {
	rz_return_val_if_fail (io && fd && fd->data, false);
	RzIOMMapFileObj *mmo = fd->data;
	if (!(mmo->perm & R_PERM_W)) {
		return false;
	}
	return rz_io_def_mmap_truncate (mmo, size);
}

#if __UNIX__
static bool __is_blockdevice (RzIODesc *desc) {
	rz_return_val_if_fail (desc && desc->data, false);
	RzIOMMapFileObj *mmo = desc->data;
	struct stat buf;
	if (fstat (mmo->fd, &buf) == -1) {
		return false;
	}
	return ((buf.st_mode & S_IFBLK) == S_IFBLK);
}
#endif

RzIOPlugin rz_io_plugin_default = {
	.name = "default",
	.desc = "Open local files",
	.license = "LGPL3",
	.uris = "file://,nocache://",
	.open = __open_default,
	.close = __close,
	.read = __read,
	.check = __plugin_open_default,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
#if __UNIX__
	.is_blockdevice = __is_blockdevice,
#endif
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &rz_io_plugin_default,
	.version = R2_VERSION
};
#endif
