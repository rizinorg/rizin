// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_core.h>

/*
 * SDB Format:
 *
 * /
 *   /config => see config.c
 *   /flags => see flag.c
 *   /analysis => see analysis.c
 *   /file => see below
 *   /seek => see serialize_core_seek.c
 *   offset=<offset>
 *   blocksize=<blocksize>
 */

static void file_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE const char *prj_file);
static bool file_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE const char *prj_file,
	RZ_NULLABLE RzSerializeResultInfo *res);

RZ_API void rz_serialize_core_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE const char *prj_file) {
	file_save(sdb_ns(db, "file", true), core, prj_file);
	rz_serialize_config_save(sdb_ns(db, "config", true), core->config);
	rz_serialize_flag_save(sdb_ns(db, "flags", true), core->flags);
	rz_serialize_analysis_save(sdb_ns(db, "analysis", true), core->analysis);
	rz_serialize_debug_save(sdb_ns(db, "debug", true), core->dbg);
	rz_serialize_core_seek_save(sdb_ns(db, "seek", true), core);

	char buf[0x20];
	if (snprintf(buf, sizeof(buf), "0x%" PFMT64x, core->offset) < 0) {
		return;
	}
	sdb_set(db, "offset", buf, 0);

	if (snprintf(buf, sizeof(buf), "0x%" PFMT32x, core->blocksize) < 0) {
		return;
	}
	sdb_set(db, "blocksize", buf, 0);
}

static const char *const config_exclude[] = {
	"dir.home",
	"dir.libs",
	"dir.magic",
	"dir.plugins",
	"dir.prefix",
	"dir.projects",
	"dir.source",
	"dir.tmp",
	"dir.types",
	"http.root",
	"pdb.symstore",
	"scr.color",
	"scr.color.args",
	"scr.color.bytes",
	"scr.color.grep",
	"scr.color.ops",
	"scr.color.pipe",
	"scr.interactive", // especially relevant for Cutter since it needs this to be false
	"scr.prompt", // especially relevant for rzpipe, otherwise loading a project might break the pipe
	"scr.rainbow",
	"scr.utf8",
	"scr.utf8.curvy",
	"ghidra.sleighhome", // also important for Cutter
	NULL
};

RZ_API bool rz_serialize_core_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, bool load_bin_io,
	RZ_NULLABLE const char *prj_file, RZ_NULLABLE RzSerializeResultInfo *res) {
	Sdb *subdb;

#define SUB(ns, call) RZ_SERIALIZE_SUB_DO(db, subdb, res, ns, call, return false;)

	if (load_bin_io) {
		SUB("file", file_load(subdb, core, prj_file, res));
	}
	SUB("config", rz_serialize_config_load(subdb, core->config, config_exclude, res));
	SUB("flags", rz_serialize_flag_load(subdb, core->flags, res));
	SUB("analysis", rz_serialize_analysis_load(subdb, core->analysis, res));
	SUB("debug", rz_serialize_debug_load(subdb, core->dbg, res));
	SUB("seek", rz_serialize_core_seek_load(subdb, core, res));

	const char *str = sdb_const_get(db, "offset", 0);
	if (!str || !*str) {
		RZ_SERIALIZE_ERR(res, "missing offset in core");
		return false;
	}
	core->offset = strtoull(str, NULL, 0);

	str = sdb_const_get(db, "blocksize", 0);
	if (!str || !*str) {
		RZ_SERIALIZE_ERR(res, "missing blocksize in core");
		return false;
	}
	ut64 bs = strtoull(str, NULL, 0);
	rz_core_block_size(core, (int)bs);

	// handled by config already:
	// cfglog, cmdrepeat, cmdtimes

	return true;
}

/* these file functions are a high-level serialization of RBin and RIO, i.e. for loading the project's underlying binary.
 * It only supports a subset of possible RBin and RIO configurations:
 *  - Only a single binary, loaded as a regular file
 *  - No IO cache (if there is cache, it will be discarded on save)
 *  - No custom IO mappings, etc.
 * Thus it will eventually be replaced by more in-depth serialization of RBin and RIO.
 *
 * tl;dr it's a quick and dirty thing that only saves the binary's filename.
 *
 * SDB Format:
 * /file
 *   raw=<entered filename, as passed to rizin:str>
 *   absolute=<absolute filename:str>
 *   relative=<relative to the project file, if saving project to a file:str>
 */

static char *prj_dir_abs(const char *prj_file) {
	char *prj_abs = rz_file_abspath(prj_file);
	if (!prj_abs) {
		return NULL;
	}
	char *r = rz_file_dirname(prj_abs);
	free(prj_abs);
	return r;
}

// (absolute) local filepath => project-relative platform-agnostic path
static char *prj_relative_make(const char *prj_dir, const char *abs_file) {
	char *rel = rz_file_relpath(prj_dir, abs_file);
	if (!rel) {
		return NULL;
	}
	// convert only the relative path to a common format because it is the only path that makes any sense
	// when a project file is relocated to another machine. Absolute and raw are always specific to one environment.
	char *rel_unix = rz_file_path_local_to_unix(rel);
	free(rel);
	return rel_unix;
}

// project-relative platform-agnostic path => (absolute) local filepath
static char *prj_relative_restore(const char *prj_dir, const char *rel_file) {
	char *rel_local = rz_file_path_unix_to_local(rel_file);
	if (!rel_local) {
		return NULL;
	}
	char *abs = rz_file_abspath_rel(prj_dir, rel_local);
	free(rel_local);
	return abs;
}

static void file_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE const char *prj_file) {
	rz_return_if_fail(db && core);

	if (!core->file) {
		return;
	}
	RzIODesc *desc = rz_io_desc_get(core->io, core->file->fd);
	if (!desc) {
		return;
	}
	if (!desc->plugin || strcmp(desc->plugin->name, "default")) {
		RZ_LOG_WARN("core: The current file is not loaded as a regular file. "
			    "This is not supported in projects yet and it will be necessary to manually re-load to use the project.\n");
		return;
	}
	const char *filename = desc->uri;
	if (!filename) {
		return;
	}
	sdb_set(db, "raw", filename, 0);
	char *abs = rz_file_abspath(filename);
	if (!abs) {
		return;
	}
	sdb_set(db, "absolute", abs, 0);
	if (prj_file) {
		char *prj_dir = prj_dir_abs(prj_file);
		if (!prj_dir) {
			goto beach;
		}
		char *rel = prj_relative_make(prj_dir, abs);
		if (rel) {
			sdb_set(db, "relative", rel, 0);
			free(rel);
		}
		free(prj_dir);
	}
beach:
	free(abs);
	return;
}

typedef enum {
	FILE_SUCCESS,
	FILE_DOES_NOT_EXIST,
	FILE_LOAD_FAIL
} FileRet;

static FileRet try_load_file(RZ_NONNULL RzCore *core, const char *file, RZ_NULLABLE RzSerializeResultInfo *res) {
	if (!rz_file_is_regular(file)) {
		return FILE_DOES_NOT_EXIST;
	}

	RzCoreFile *fh = rz_core_file_open(core, file, RZ_PERM_RX, 0);
	if (!fh) {
		RZ_SERIALIZE_ERR(res, "failed re-open file \"%s\" referenced by project", file);
		return FILE_LOAD_FAIL;
	}
	rz_core_bin_load(core, file, UT64_MAX);

	return FILE_SUCCESS;
}

static bool file_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE const char *prj_file,
	RZ_NULLABLE RzSerializeResultInfo *res) {
	rz_core_file_close_fd(core, -1);
	rz_io_close_all(core->io);
	rz_bin_file_delete_all(core->bin);

	FileRet r = FILE_DOES_NOT_EXIST;
	const char *rel = sdb_const_get(db, "relative", 0);
	if (rel && prj_file) {
		char *prj_dir = prj_dir_abs(prj_file);
		if (prj_dir) {
			char *file = prj_relative_restore(prj_dir, rel);
			if (file) {
				r = try_load_file(core, file, res);
				free(file);
			}
			free(prj_dir);
		}
	}
	if (r != FILE_DOES_NOT_EXIST) {
		return r == FILE_SUCCESS;
	}

	const char *file = sdb_const_get(db, "absolute", 0);
	if (file) {
		r = try_load_file(core, file, res);
	}
	if (r != FILE_DOES_NOT_EXIST) {
		return r == FILE_SUCCESS;
	}

	file = sdb_const_get(db, "raw", 0);
	if (file) {
		r = try_load_file(core, file, res);
	}
	if (r != FILE_DOES_NOT_EXIST) {
		return r == FILE_SUCCESS;
	}

	RZ_SERIALIZE_ERR(res, "failed to re-locate file referenced by project");
	return false;
}

/**
 * \brief Serialize seek history state and save to a sdb
 *
 * \param db sdb to save the state
 * \param core RzCore instance to save from
 */
RZ_API void rz_serialize_core_seek_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core) {
	rz_return_if_fail(db && core);

	RzList *list = rz_core_seek_list(core);
	if (!list) {
		return;
	}

	RzListIter *iter;
	RzCoreSeekItem *undo;
	rz_list_foreach (list, iter, undo) {
		PJ *j = pj_new();
		if (!j) {
			goto err;
		}
		pj_o(j);
		pj_kn(j, "offset", undo->offset);
		pj_kn(j, "cursor", undo->cursor);
		pj_kb(j, "current", undo->is_current);
		pj_end(j);

		char key[12];
		sdb_set(db, rz_strf(key, "%" PFMT32d, undo->idx), pj_string(j), 0);
		pj_free(j);
	}

err:
	rz_list_free(list);
}

enum {
	SEEK_FIELD_OFFSET,
	SEEK_FIELD_CURSOR,
	SEEK_FIELD_CURRENT
};

/**
 * \brief Create and initialize a JSON parser for seek history items
 * \return a RzKeyParser* for seek history items
 **/
static RzKeyParser *seek_parser_new(void) {
	RzKeyParser *parser = rz_key_parser_new();
	if (!parser) {
		return NULL;
	}

	rz_key_parser_add(parser, "offset", SEEK_FIELD_OFFSET);
	rz_key_parser_add(parser, "cursor", SEEK_FIELD_CURSOR);
	rz_key_parser_add(parser, "current", SEEK_FIELD_CURRENT);

	return parser;
}

typedef struct {
	RzCore *core;
	RzKeyParser *parser;
	char *current_key;
	RzVector /*<RzCoreSeekItem>*/ *vec;
} SeekLoadCtx;

/**
 * \brief Load a single seek history item
 * \param ctx context for loading the item
 * \param k sdb item key
 * \param v sdb item value (expected to be JSON)
 **/
static bool seek_load_item(SeekLoadCtx *ctx, const char *k, const char *v) {
	bool ret = false;
	char *json_str = strdup(v);
	if (!json_str) {
		return true;
	}
	RzJson *json = rz_json_parse(json_str);
	if (!json || json->type != RZ_JSON_OBJECT) {
		goto out_free_str;
	}
	RzCoreSeekItem seek_item = { 0 };

	RZ_KEY_PARSER_JSON(ctx->parser, json, child, {
		case SEEK_FIELD_OFFSET:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			seek_item.offset = child->num.u_value;
			break;
		case SEEK_FIELD_CURSOR:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			seek_item.cursor = child->num.s_value;
			break;
		case SEEK_FIELD_CURRENT:
			if (child->type != RZ_JSON_BOOLEAN) {
				break;
			}
			seek_item.is_current = child->num.u_value;
			break;
	})

	if (seek_item.is_current && !ctx->current_key) {
		// The offset is serialized by the core, so ignore the information from the seek history
		// But the cursor position isn't serialized otherwise
		ctx->core->print->cur = seek_item.cursor;
		// Switch to the vector of redos
		ctx->vec = &ctx->core->seek_history.redos;
		// Remember we've found the current seek
		ctx->current_key = strdup(k);
	} else {
		if (seek_item.is_current) {
			// Warn about this additional "current" seek
			RZ_LOG_WARN("Seek history item \"%s\" marked as current, but current already found at \"%s\"!\n", k, ctx->current_key);
		}
		rz_vector_push(ctx->vec, &seek_item);
	}
	ret = true;

	rz_json_free(json);
out_free_str:
	free(json_str);
	return ret;
}

static int __cmp_num_asc(const void *a, const void *b, RZ_UNUSED void *user) {
	const SdbKv *ka = a, *kb = b;
	// Parse as signed ints but don't bother witb error detection, it'll sort bad and that's it
	long ia = strtol(sdbkv_key(ka), NULL, 10);
	long ib = strtol(sdbkv_key(kb), NULL, 10);
	return RZ_NUM_CMP(ia, ib);
}

/**
 * \brief Deserialize seek history state from an sdb
 *
 * \param db sdb to load state from
 * \param core RzCore instance to load into
 * \param res RzSerializeResultInfo to store info/errors/warnings
 * \return true if successful, false otherwise
 */
RZ_API bool rz_serialize_core_seek_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE RzSerializeResultInfo *res) {
	rz_return_val_if_fail(db && core, false);

	bool ret = true;
	RzKeyParser *seek_parser = seek_parser_new();
	if (!seek_parser) {
		return false;
	}

	// Sort by (numeric) key
	RzPVector *db_items = sdb_get_items(db, false);
	if (!db_items) {
		ret = false;
		goto out_free_parser;
	}
	rz_pvector_sort(db_items, __cmp_num_asc, NULL);

	// Clear the current history
	rz_core_seek_reset(core);
	core->seek_history.saved_set = false;

	SeekLoadCtx ctx = {
		.core = core,
		.parser = seek_parser,
		.current_key = NULL,
		.vec = &core->seek_history.undos,
	};
	bool parsed = true;
	void **it;
	rz_pvector_foreach (db_items, it) {
		SdbKv *kv = *it;
		parsed &= seek_load_item(&ctx, sdbkv_key(kv), sdbkv_value(kv));
	}
	ret &= parsed;
	if (!parsed) {
		RZ_SERIALIZE_ERR(res, "failed to parse seek history offset from json");
	}

	// Reverse the redo vector, which has been deserialized from oldest to youngest entry
	// but should be ordered from youngest to oldest
	// (so the entry closest to the current seek can be pushed/popped)
	bool reversed = true;
	size_t rlen = rz_vector_len(&core->seek_history.redos);
	for (size_t i = 0; i < rlen / 2; i++) {
		// Swap with the mirror item from the end of the vector
		reversed &= rz_vector_swap(&core->seek_history.redos, i, rlen - 1 - i);
	}
	ret &= reversed;
	if (!reversed) {
		RZ_SERIALIZE_ERR(res, "failed to reorder seek history redo items");
	}

	// Increase cfg.seek.histsize as needed
	size_t ulen = rz_vector_len(&core->seek_history.undos);
	if (SZT_ADD_OVFCHK(ulen, rlen)) {
		ret = false;
		RZ_SERIALIZE_ERR(res, "failed to adjust cfg.seek.histsize");
		rz_goto_if_reached(out_free_list);
	}
	ut64 histsize = rz_config_get_i(core->config, "cfg.seek.histsize");
	if (histsize != 0 && histsize < ulen + rlen) {
		RZ_LOG_WARN("Loaded project seek history exceeds cfg.seek.histsize, increasing that limit.\n");
		rz_config_set_i(core->config, "cfg.seek.histsize", ulen + rlen);
	}

out_free_list:
	free(ctx.current_key);
	rz_pvector_free(db_items);
out_free_parser:
	rz_key_parser_free(seek_parser);
	return ret;
}
