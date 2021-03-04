// SPDX-FileCopyrightText: 2017-2020 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>

RZ_API int rz_io_fd_open(RzIO *io, const char *uri, int flags, int mode) {
	RzIODesc *desc = rz_io_desc_open(io, uri, flags, mode);
	return desc ? desc->fd : -1;
}

RZ_API bool rz_io_fd_close(RzIO *io, int fd) {
	return rz_io_desc_close(rz_io_desc_get(io, fd));
}

//returns length of read bytes
RZ_API int rz_io_fd_read(RzIO *io, int fd, ut8 *buf, int len) {
	rz_return_val_if_fail(io && buf, -1);
	if (len < 0) {
		return -1;
	}
	RzIODesc *desc = rz_io_desc_get(io, fd);
	return desc ? rz_io_desc_read(desc, buf, len) : -1;
}

//returns length of written bytes
RZ_API int rz_io_fd_write(RzIO *io, int fd, const ut8 *buf, int len) {
	rz_return_val_if_fail(io && buf, -1);
	if (len < 0) {
		return -1;
	}
	RzIODesc *desc = rz_io_desc_get(io, fd);
	return desc ? rz_io_desc_write(desc, buf, len) : -1;
}

RZ_API ut64 rz_io_fd_seek(RzIO *io, int fd, ut64 addr, int whence) {
	if (!io) {
		return (ut64)-2;
	}
	return rz_io_desc_seek(rz_io_desc_get(io, fd), addr, whence);
}

RZ_API ut64 rz_io_fd_size(RzIO *io, int fd) {
	return rz_io_desc_size(rz_io_desc_get(io, fd));
}

RZ_API bool rz_io_fd_resize(RzIO *io, int fd, ut64 newsize) {
	return rz_io_desc_resize(rz_io_desc_get(io, fd), newsize);
}

RZ_API bool rz_io_fd_is_blockdevice(RzIO *io, int fd) {
	return rz_io_desc_is_blockdevice(rz_io_desc_get(io, fd));
}

RZ_API bool rz_io_fd_is_chardevice(RzIO *io, int fd) {
	return rz_io_desc_is_chardevice(rz_io_desc_get(io, fd));
}

//returns length of read bytes
RZ_API int rz_io_fd_read_at(RzIO *io, int fd, ut64 addr, ut8 *buf, int len) {
	RzIODesc *desc;
	if (!io || !buf || (len < 1) || !(desc = rz_io_desc_get(io, fd))) {
		return 0;
	}
	return rz_io_desc_read_at(desc, addr, buf, len);
}

//returns length of written bytes
RZ_API int rz_io_fd_write_at(RzIO *io, int fd, ut64 addr, const ut8 *buf, int len) {
	rz_return_val_if_fail(io && buf, false);
	RzIODesc *desc = rz_io_desc_get(io, fd);
	return desc ? rz_io_desc_write_at(desc, addr, buf, len) : -1;
}

RZ_API bool rz_io_fd_is_dbg(RzIO *io, int fd) {
	rz_return_val_if_fail(io && io->files, false);
	RzIODesc *desc = rz_io_desc_get(io, fd);
	return desc ? rz_io_desc_is_dbg(desc) : false;
}

RZ_API int rz_io_fd_get_pid(RzIO *io, int fd) {
	if (!io || !io->files) {
		return -2;
	}
	RzIODesc *desc = rz_io_desc_get(io, fd);
	return rz_io_desc_get_pid(desc);
}

RZ_API int rz_io_fd_get_tid(RzIO *io, int fd) {
	rz_return_val_if_fail(io && io->files, -2);
	RzIODesc *desc = rz_io_desc_get(io, fd);
	return rz_io_desc_get_tid(desc);
}

RZ_API bool rz_io_fd_get_base(RzIO *io, int fd, ut64 *base) {
	rz_return_val_if_fail(io && io->files && base, false);
	RzIODesc *desc = rz_io_desc_get(io, fd);
	return rz_io_desc_get_base(desc, base);
}

RZ_API const char *rz_io_fd_get_name(RzIO *io, int fd) {
	rz_return_val_if_fail(io && io->files, NULL);
	RzIODesc *desc = rz_io_desc_get(io, fd);
	return desc ? desc->name : NULL;
}

RZ_API bool rz_io_use_fd(RzIO *io, int fd) {
	rz_return_val_if_fail(io, false);
	if (!io->desc) {
		io->desc = rz_io_desc_get(io, fd);
		return io->desc != NULL;
	}
	if (io->desc->fd != fd) {
		RzIODesc *desc;
		//update io->desc if fd is not the same
		if (!(desc = rz_io_desc_get(io, fd))) {
			return false;
		}
		io->desc = desc;
	}
	return true;
}

RZ_API int rz_io_fd_get_current(RzIO *io) {
	rz_return_val_if_fail(io, -1);
	if (io->desc) {
		return io->desc->fd;
	}
	return -1;
}

RZ_API int rz_io_fd_get_next(RzIO *io, int fd) {
	rz_return_val_if_fail(io, -1);
	int ret = fd;
	if (!rz_id_storage_get_next(io->files, (ut32 *)&ret)) {
		return -1;
	}
	return ret;
}

RZ_API int rz_io_fd_get_prev(RzIO *io, int fd) {
	rz_return_val_if_fail(io, -1);
	int ret = fd;
	if (!rz_id_storage_get_prev(io->files, (ut32 *)&ret)) {
		return -1;
	}
	return ret;
}

RZ_API int rz_io_fd_get_highest(RzIO *io) {
	rz_return_val_if_fail(io, -1);
	int fd = -1;
	if (!rz_id_storage_get_highest(io->files, (ut32 *)&fd)) {
		return -1;
	}
	return fd;
}

RZ_API int rz_io_fd_get_lowest(RzIO *io) {
	rz_return_val_if_fail(io, -1);
	int fd = -1;
	if (!rz_id_storage_get_lowest(io->files, (ut32 *)&fd)) {
		return -1;
	}
	return fd;
}
