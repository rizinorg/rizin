// SPDX-FileCopyrightText: 2015-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2015-2020 rkx1209 <rkx1209dev@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include <rz_hash.h>

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

	snap->name = strdup(map->name);
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

RZ_API ut8 *rz_debug_snap_get_hash(RzDebugSnap *snap) {
	ut64 algobit = rz_hash_name_to_bits("sha256");
	RzHash *ctx = rz_hash_new(true, algobit);
	if (!ctx) {
		return NULL;
	}

	rz_hash_do_begin(ctx, algobit);
	rz_hash_calculate(ctx, algobit, snap->data, snap->size);
	rz_hash_do_end(ctx, algobit);

	ut8 *ret = malloc(RZ_HASH_SIZE_SHA256);
	if (!ret) {
		rz_hash_free(ctx);
		return NULL;
	}
	memcpy(ret, ctx->digest, RZ_HASH_SIZE_SHA256);

	rz_hash_free(ctx);
	return ret;
}

RZ_API bool rz_debug_snap_is_equal(RzDebugSnap *a, RzDebugSnap *b) {
	bool ret = false;
	ut64 algobit = rz_hash_name_to_bits("sha256");
	RzHash *ctx = rz_hash_new(true, algobit);
	if (!ctx) {
		return ret;
	}

	rz_hash_do_begin(ctx, algobit);
	rz_hash_calculate(ctx, algobit, a->data, a->size);
	rz_hash_do_end(ctx, algobit);

	ut8 *temp = malloc(RZ_HASH_SIZE_SHA256);
	if (!temp) {
		rz_hash_free(ctx);
		return ret;
	}
	memcpy(temp, ctx->digest, RZ_HASH_SIZE_SHA256);

	rz_hash_do_begin(ctx, algobit);
	rz_hash_calculate(ctx, algobit, b->data, b->size);
	rz_hash_do_end(ctx, algobit);

	ret = memcmp(temp, ctx->digest, RZ_HASH_SIZE_SHA256) == 0;
	free(temp);
	rz_hash_free(ctx);
	return ret;
}
