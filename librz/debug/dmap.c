// SPDX-FileCopyrightText: 2009-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include <rz_list.h>

RZ_API RZ_OWN RzDebugMap *rz_debug_map_new(RZ_NULLABLE char *name, ut64 begin, ut64 end, int perm, int user) {
	/* range could be 0k on OpenBSD, it's a honeypot */
	if (begin > end) {
		RZ_LOG_ERROR("debug: begin address 0x%" PFMT64x " is greater than end address 0x%" PFMT64x "\n", begin, end);
		return NULL;
	}
	RzDebugMap *map = RZ_NEW0(RzDebugMap);
	if (!map) {
		return NULL;
	}
	map->name = rz_str_dup(name ? name : "");
	map->addr = begin;
	map->addr_end = end;
	map->size = end - begin;
	map->perm = perm;
	map->user = user;
	return map;
}

RZ_API RzList /*<RzDebugMap *>*/ *rz_debug_modules_list(RzDebug *dbg) {
	return (dbg && dbg->cur && dbg->cur->modules_get) ? dbg->cur->modules_get(dbg) : NULL;
}

RZ_API bool rz_debug_map_sync(RzDebug *dbg) {
	bool ret = false;
	if (dbg && dbg->cur && dbg->cur->map_get) {
		RzList *newmaps = dbg->cur->map_get(dbg);
		if (newmaps) {
			rz_list_free(dbg->maps);
			dbg->maps = newmaps;
			ret = true;
		}
	}
	return ret;
}

RZ_API RzDebugMap *rz_debug_map_alloc(RzDebug *dbg, ut64 addr, int size, bool thp) {
	RzDebugMap *map = NULL;
	if (dbg && dbg->cur && dbg->cur->map_alloc) {
		map = dbg->cur->map_alloc(dbg, addr, size, thp);
	}
	return map;
}

RZ_API int rz_debug_map_dealloc(RzDebug *dbg, RzDebugMap *map) {
	bool ret = false;
	ut64 addr = map->addr;
	if (dbg && dbg->cur && dbg->cur->map_dealloc) {
		if (dbg->cur->map_dealloc(dbg, addr, map->size)) {
			ret = true;
		}
	}
	return (int)ret;
}

RZ_API RzDebugMap *rz_debug_map_get(RzDebug *dbg, ut64 addr) {
	RzDebugMap *map, *ret = NULL;
	RzListIter *iter;
	rz_list_foreach (dbg->maps, iter, map) {
		if (addr >= map->addr && addr <= map->addr_end) {
			ret = map;
			break;
		}
	}
	return ret;
}

RZ_API void rz_debug_map_free(RZ_NULLABLE RzDebugMap *map) {
	if (!map) {
		return;
	}
	free(map->name);
	free(map->file);
	free(map);
}

RZ_API RzList /*<RzDebugMap *>*/ *rz_debug_map_list_new(void) {
	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}
	list->free = (RzListFree)rz_debug_map_free;
	return list;
}

/**
 * \brief Get RzList* of memory maps for the process currently being debugged
 * \param dbg RzDebug pointer
 * \param user_map Boolean value, if true return memory maps belonging to user space else return memory maps belonging to kernel space
 * \return
 */
RZ_API RZ_BORROW RzList /*<RzDebugMap *>*/ *rz_debug_map_list(RzDebug *dbg, bool user_map) {
	return user_map ? dbg->maps_user : dbg->maps;
}
