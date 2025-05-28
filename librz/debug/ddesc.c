// SPDX-FileCopyrightText: 2010-2013 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

// XXX: All this stuff must be linked to the code injection api

#include <rz_debug.h>
#include <rz_cons.h> // For rz_cons_printf, etc.
#include <rz_util/rz_str.h> // For rz_str_rwx_i, rz_strf
#include <rz_util/rz_json.h> // For PJ

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
	return -1;
}

RZ_API int rz_debug_desc_close(RzDebug *dbg, int fd) {
	if (dbg && dbg->cur && dbg->cur->desc.close) {
		return dbg->cur->desc.close(fd);
	}
	return -1;
}

RZ_API int rz_debug_desc_dup(RzDebug *dbg, int fd, int newfd) {
	if (dbg && dbg->cur && dbg->cur->desc.dup) {
		return dbg->cur->desc.dup(fd, newfd);
	}
	return -1;
}

RZ_API int rz_debug_desc_read(RzDebug *dbg, int fd, ut64 addr, int len) {
	if (dbg && dbg->cur && dbg->cur->desc.read) {
		return dbg->cur->desc.read(fd, addr, len);
	}
	return -1;
}

RZ_API int rz_debug_desc_seek(RzDebug *dbg, int fd, ut64 addr) {
	if (dbg && dbg->cur && dbg->cur->desc.seek) {
		return dbg->cur->desc.seek(fd, addr);
	}
	return -1;
}

RZ_API int rz_debug_desc_write(RzDebug *dbg, int fd, ut64 addr, int len) {
	if (dbg && dbg->cur && dbg->cur->desc.write) {
		return dbg->cur->desc.write(fd, addr, len);
	}
	return -1;
}

RZ_API int rz_debug_desc_list(RzDebug *dbg, RzOutputMode mode) {
	if (!dbg || !dbg->cur || !dbg->cur->desc.list) {
		return -1; // Error: no plugin or list function
	}
	RzList *list = dbg->cur->desc.list(dbg->pid);
	if (!list) {
		return 0; 
	}

	PJ *pj = NULL;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj = pj_new();
		if (!pj) {
			rz_list_free(list); 
			return -1; 
		}
		pj_a(pj);
	}

	RzListIter *iter;
	RzDebugDesc *p;
	char desctype[2]; 

	rz_list_foreach (list, iter, p) {
		rz_strf(desctype, "%c", p->type); 
		switch (mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(pj);
			pj_ki(pj, "fd", p->fd);
			pj_kn(pj, "offset", p->off);
			pj_ks(pj, "perms", rz_str_rwx_i(p->perm));
			pj_ks(pj, "type", desctype);
			pj_ks(pj, "path", p->path);
			pj_end(pj);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("%d 0x%08" PFMT64x " %s %s %s\n", p->fd, p->off,
				rz_str_rwx_i(p->perm),
				desctype, p->path);
			break;
		case RZ_OUTPUT_MODE_RIZIN:
			rz_cons_printf("dod %d 0x%08"PFMT64x" %s %s %s\n", p->fd, p->off, 
                           p->path, rz_str_rwx_i(p->perm), desctype);
			break;
		case RZ_OUTPUT_MODE_SIMPLE: // Equivalent to QUIET
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("%d\n", p->fd);
			break;
		case RZ_OUTPUT_MODE_SIMPLEST: // Equivalent to QUIETEST
		case RZ_OUTPUT_MODE_QUIETEST:
			// No output, or minimal like just fd if absolutely necessary
			// For now, no output for quietest.
			break;
		default:
			// Fallback for unhandled modes (e.g. LONG, TABLE) to standard
			rz_cons_printf("%d 0x%08" PFMT64x " %s %s %s\n", p->fd, p->off,
				rz_str_rwx_i(p->perm),
				desctype, p->path);
			break;
		}
	}

	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}

	int count = rz_list_length(list);
	// Items in the list are RzDebugDesc*. The plugin that created them should own them.
	// If the list itself was allocated by the plugin, it should provide a free function.
	// Here, we assume `list` is allocated by `dbg->cur->desc.list` and must be freed,
	// but the RzDebugDesc items themselves are managed elsewhere or are not heap-allocated by this specific list call.
	rz_list_free(list); 
	return count;
}
