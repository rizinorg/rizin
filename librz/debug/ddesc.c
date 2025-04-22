// SPDX-FileCopyrightText: 2010-2013 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

// XXX: All this stuff must be linked to the code injection api

#include <rz_debug.h>

RZ_API RzDebugDesc *rz_debug_desc_new(int fd, char *path, int perm, int type, int off) {
	RzDebugDesc *desc = RZ_NEW(RzDebugDesc);
	if (desc) {
		desc->fd = fd;
		desc->path = rz_str_dup(path);
		desc->perm = perm;
		desc->type = type;
		desc->off = off;
	}
	return desc;
}

RZ_API void rz_debug_desc_free(RzDebugDesc *p) {
	if (p) {
		if (p->path) {
			free(p->path);
		}
		free(p);
	}
}

RZ_API int rz_debug_desc_open(RzDebug *dbg, const char *path) {
	if (dbg && dbg->cur && dbg->cur->desc.open) {
		return dbg->cur->desc.open(path);
	}
	return false;
}

RZ_API int rz_debug_desc_close(RzDebug *dbg, int fd) {
	if (dbg && dbg->cur && dbg->cur->desc.close) {
		return dbg->cur->desc.close(fd);
	}
	return false;
}

RZ_API int rz_debug_desc_dup(RzDebug *dbg, int fd, int newfd) {
	if (dbg && dbg->cur && dbg->cur->desc.dup) {
		return dbg->cur->desc.dup(fd, newfd);
	}
	return false;
}

RZ_API int rz_debug_desc_read(RzDebug *dbg, int fd, ut64 addr, int len) {
	if (dbg && dbg->cur && dbg->cur->desc.read) {
		return dbg->cur->desc.read(fd, addr, len);
	}
	return false;
}

RZ_API int rz_debug_desc_seek(RzDebug *dbg, int fd, ut64 addr) {
	if (dbg && dbg->cur && dbg->cur->desc.seek) {
		return dbg->cur->desc.seek(fd, addr);
	}
	return false;
}

RZ_API int rz_debug_desc_write(RzDebug *dbg, int fd, ut64 addr, int len) {
	if (dbg && dbg->cur && dbg->cur->desc.write) {
		return dbg->cur->desc.write(fd, addr, len);
	}
	return false;
}
