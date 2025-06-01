// SPDX-FileCopyrightText: 2015-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2015-2020 rkx1209 <rkx1209dev@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>

RZ_API void rz_debug_snap_free(RzDebugSnap *snap) {
	if (snap) {
		free(snap->name);
		free(snap->data);
		RZ_FREE(snap);
	}
}

RZ_API RzDebugSnap *rz_debug_snap_map(RzDebug *dbg, RzDebugMap *map) {
	rz_return_val_if_fail(dbg && map, NULL);
	if (map->size < 1) {
		eprintf("Invalid map size\n");
		return NULL;
	}

	RzDebugSnap *snap = RZ_NEW0(RzDebugSnap);
	if (!snap) {
		return NULL;
	}

	snap->name = rz_str_dup(map->name);
	snap->addr = map->addr;
	snap->addr_end = map->addr_end;
	snap->size = map->size;
	snap->perm = map->perm;
	snap->user = map->user;
	snap->shared = map->shared;

	snap->data = malloc(map->size);
	if (!snap->data) {
		rz_debug_snap_free(snap);
		return NULL;
	}
	eprintf("Reading %d byte(s) from 0x%08" PFMT64x "...\n", snap->size, snap->addr);
	dbg->iob.read_at(dbg->iob.io, snap->addr, snap->data, snap->size);

	return snap;
}

RZ_API bool rz_debug_snap_contains(RzDebugSnap *snap, ut64 addr) {
	return (snap->addr <= addr && addr >= snap->addr_end);
}

RZ_API ut8 *rz_debug_snap_get_hash(RzDebug *dbg, RzDebugSnap *snap, RzHashSize *size) {
	ut8 *digest = rz_hash_cfg_calculate_small_block(dbg->hash, "sha256", snap->data, snap->size, size);
	if (!digest) {
		return NULL;
	}
	return digest;
}

RZ_API bool rz_debug_snap_is_equal(RzDebug *dbg, RzDebugSnap *a, RzDebugSnap *b) {
	RzHashSize digest_size = 0;
	ut8 *a_dgst = rz_debug_snap_get_hash(dbg, a, &digest_size);
	ut8 *b_dgst = rz_debug_snap_get_hash(dbg, b, NULL);

	bool ret = a_dgst && b_dgst && !memcmp(a_dgst, b_dgst, digest_size);
	free(a_dgst);
	free(b_dgst);
	return ret;
}
