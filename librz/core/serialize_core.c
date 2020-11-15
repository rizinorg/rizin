// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_core.h>

#include "../util/serialize_helper.h"

/*
 * SDB Format:
 *
 * /
 *   /config => see config.c
 *   /flags => see flag.c
 *   /anal => see anal.c
 *   /file => see below
 *   offset=<offset>
 *   blocksize=<blocksize>
 */

static void file_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE const char *prj_file);
static bool file_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE const char *prj_file,
		RZ_NULLABLE RzSerializeResultInfo *res);

RZ_API void rz_serialize_core_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core) {
	file_save (sdb_ns (db, "file", true), core, NULL); // TODO: prj_file
	rz_serialize_config_save (sdb_ns (db, "config", true), core->config);
	rz_serialize_flag_save (sdb_ns (db, "flags", true), core->flags);
	rz_serialize_anal_save (sdb_ns (db, "anal", true), core->anal);

	char buf[0x20];
	if (snprintf (buf, sizeof (buf), "0x%"PFMT64x, core->offset) < 0) {
		return;
	}
	sdb_set (db, "offset", buf, 0);

	if (snprintf (buf, sizeof (buf), "0x%"PFMT32x, core->blocksize) < 0) {
		return;
	}
	sdb_set (db, "blocksize", buf, 0);
}

RZ_API bool rz_serialize_core_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE RzSerializeResultInfo *res) {
	Sdb *subdb;

#define SUB(ns, call) SUB_DO(ns, call, return false;)

	SUB ("file", file_load (subdb, core, NULL, res)); // TODO: prj_file
	SUB ("config", rz_serialize_config_load (subdb, core->config, res));
	SUB ("flags", rz_serialize_flag_load (subdb, core->flags, res));
	SUB ("anal", rz_serialize_anal_load (subdb, core->anal, res));

	const char *str = sdb_get (db, "offset", 0);
	if (!str || !*str) {
		SERIALIZE_ERR ("missing offset in core");
		return false;
	}
	core->offset = strtoull (str, NULL, 0);

	str = sdb_get (db, "blocksize", 0);
	if (!str || !*str) {
		SERIALIZE_ERR ("missing blocksize in core");
		return false;
	}
	ut64 bs = strtoull (str, NULL, 0);
	rz_core_block_size (core, (int)bs);

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

static void file_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE const char *prj_file) {
	if (!core->file) {
		return;
	}
	RzIODesc *desc = rz_io_desc_get (core->io, core->file->fd);
	if (!desc) {
		return;
	}
	if (!desc->plugin || strcmp (desc->plugin->name, "default")) {
		eprintf ("Warning: The current file is not loaded as a regular file. This is not supported in projects yet.\n");
		return;
	}
	const char *filename = desc->uri;
	if (!filename) {
		return;
	}
	sdb_set (db, "raw", filename, 0);
	char *abs = rz_file_abspath (filename);
	if (abs) {
		sdb_set (db, "absolute", abs, 0);
		if (prj_file) {
			char *prj_abs = rz_file_abspath (prj_file);
			if (prj_abs) {
				char *rel = rz_file_relpath (prj_abs, abs);
				if (rel) {
					sdb_set (db, "relative", rel, 0);
					free (rel);
				}
				free (prj_abs);
			}
		}
		free (abs);
	}
	return;
}

static bool file_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE const char *prj_file,
		RZ_NULLABLE RzSerializeResultInfo *res) {
	return true;
}

