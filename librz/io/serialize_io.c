// SPDX-FileCopyrightText: 2020 thestr4ng3r
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_io.h>

#include <errno.h>

/*
 *
 * SDB Format:
 *
 * /
 *   /files
 *     <fd>={perm:<int>, uri:<str>, name:<str>, referer?:<str>}
 *     /pcache
 *       <fd>.<ut64>={cached:<ut64>, data:<base64>}
 */

typedef struct {
	int fd;
	int perm;
	char *uri;
	char *name;
	char *referer;
	HtUP *cache;
	void *data;
	struct rz_io_plugin_t *plugin;
	RzIO *io;
} RzIODescasd;

typedef struct {
	int fd;
	Sdb *db;
} PCacheSaveCtx;

static bool pcache_save_cb(void *user, const ut64 k, const void *v) {
	PCacheSaveCtx *ctx = user;
	const RzIODescCache *cache = v;
	char key[0x30];
	if (snprintf(key, sizeof(key), "%d.0x%" PFMT64x, ctx->fd, k) < 0) {
		return false;
	}
	char val[RZ_IO_DESC_CACHE_SIZE * 4 + 1];
	rz_base64_encode(val, cache->cdata, RZ_IO_DESC_CACHE_SIZE);
	return true;
}

static bool file_save_cb(void *user, void *data, ut32 id) {
	Sdb *db = user;
	RzIODesc *desc = (RzIODesc *)data;

	char key[0x20];
	if (snprintf(key, sizeof(key), "%d", desc->fd) < 0) {
		return false;
	}

	PJ *j = pj_new();
	if (!j) {
		return false;
	}
	pj_o(j);

	pj_ki(j, "perm", desc->perm);
	// obsz is irrelevant (never written, always 0)
	pj_ks(j, "uri", desc->uri);
	pj_ks(j, "name", desc->name);
	if (desc->referer) {
		pj_ks(j, "referer", desc->referer);
	}
	// TODO: plugin

	pj_end(j);
	sdb_set(db, key, pj_string(j));
	pj_free(j);

	if (desc->cache->count) {
		PCacheSaveCtx ctx = {
			.fd = desc->fd,
			.db = sdb_ns(db, "pcache", true)
		};
		ht_up_foreach(desc->cache, pcache_save_cb, &ctx);
	}
	return true;
}

RZ_API void rz_serialize_io_files_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzIO *io) {
	sdb_ns(db, "pcache", true);
	rz_id_storage_foreach(io->files, file_save_cb, db);
}

RZ_API bool rz_serialize_io_files_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzIO *io, RZ_NULLABLE RzSerializeResultInfo *res) {
	// TODO
	return true;
}

RZ_API void rz_serialize_io_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzIO *io) {
	rz_serialize_io_files_save(sdb_ns(db, "files", true), io);
}

RZ_API bool rz_serialize_io_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzIO *io, RZ_NULLABLE RzSerializeResultInfo *res) {
	// TODO: purge RzIO?
	bool ret = false;
	Sdb *subdb;
#define SUB(ns, call) RZ_SERIALIZE_SUB_DO(db, subdb, res, ns, call, goto beach;)
	SUB("files", rz_serialize_io_files_load(subdb, io, res));
#undef SUB
	ret = true;
beach:
	return ret;
}
