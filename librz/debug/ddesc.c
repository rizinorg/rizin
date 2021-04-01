// SPDX-FileCopyrightText: 2010-2013 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

// XXX: All this stuff must be linked to the code injection api

#include <rz_debug.h>

RZ_API RzDebugDesc *rz_debug_desc_new(int fd, char *path, int perm, int type, int off) {
	RzDebugDesc *desc = RZ_NEW(RzDebugDesc);
	if (desc) {
		desc->fd = fd;
		desc->path = strdup(path);
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
	if (dbg && dbg->h && dbg->h->desc.open) {
		return dbg->h->desc.open(path);
	}
	return false;
}

RZ_API int rz_debug_desc_close(RzDebug *dbg, int fd) {
	if (dbg && dbg->h && dbg->h->desc.close) {
		return dbg->h->desc.close(fd);
	}
	return false;
}

RZ_API int rz_debug_desc_dup(RzDebug *dbg, int fd, int newfd) {
	if (dbg && dbg->h && dbg->h->desc.dup) {
		return dbg->h->desc.dup(fd, newfd);
	}
	return false;
}

RZ_API int rz_debug_desc_read(RzDebug *dbg, int fd, ut64 addr, int len) {
	if (dbg && dbg->h && dbg->h->desc.read) {
		return dbg->h->desc.read(fd, addr, len);
	}
	return false;
}

RZ_API int rz_debug_desc_seek(RzDebug *dbg, int fd, ut64 addr) {
	if (dbg && dbg->h && dbg->h->desc.seek) {
		return dbg->h->desc.seek(fd, addr);
	}
	return false;
}

RZ_API int rz_debug_desc_write(RzDebug *dbg, int fd, ut64 addr, int len) {
	if (dbg && dbg->h && dbg->h->desc.write) {
		return dbg->h->desc.write(fd, addr, len);
	}
	return false;
}

RZ_API int rz_debug_desc_list(RzDebug *dbg, int rad) {
	int count = 0;
	RzList *list;
	RzListIter *iter;
	RzDebugDesc *p;

	if (rad) {
		if (dbg && dbg->cb_printf) {
			dbg->cb_printf("TODO \n");
		}
	} else {
		if (dbg && dbg->h && dbg->h->desc.list) {
			list = dbg->h->desc.list(dbg->pid);
			rz_list_foreach (list, iter, p) {
				dbg->cb_printf("%i 0x%" PFMT64x " %c%c%c %s\n", p->fd, p->off,
					(p->perm & RZ_PERM_R) ? 'r' : '-',
					(p->perm & RZ_PERM_W) ? 'w' : '-',
					p->type, p->path);
			}
			rz_list_purge(list);
			free(list);
		}
	}
	return count;
}
