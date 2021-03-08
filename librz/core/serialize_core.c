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
	"scr.interactive", // especially relevant for Cutter since it needs this to be false
	"scr.color",
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

	const char *str = sdb_get(db, "offset", 0);
	if (!str || !*str) {
		RZ_SERIALIZE_ERR(res, "missing offset in core");
		return false;
	}
	core->offset = strtoull(str, NULL, 0);

	str = sdb_get(db, "blocksize", 0);
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
	if (!core->file) {
		return;
	}
	RzIODesc *desc = rz_io_desc_get(core->io, core->file->fd);
	if (!desc) {
		return;
	}
	if (!desc->plugin || strcmp(desc->plugin->name, "default")) {
		eprintf("Warning: The current file is not loaded as a regular file. "
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
