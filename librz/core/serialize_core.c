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
	rz_serialize_debug_save(sdb_ns(db, "debug", true), core->dbg);

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
	"dir.zigns",
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

typedef struct {
	Sdb *db;
	const char *prj_file;
} FileSaveHelper;

unsigned int file_num = 0;

static bool file_save_cb(void *user, void *data, ut32 id) {
	FileSaveHelper *fsh = user;
	Sdb *db = fsh->db;
	const char *prj_file = fsh->prj_file;
	RzIODesc *desc = data;
	if (!desc) {
		return true;
	}
	PJ *j = pj_new();
	if (!j) {
		return true;
	}
	if (!desc->plugin || strcmp(desc->plugin->name, "default")) {
		eprintf("Warning: The current file is not loaded as a regular file. "
			"This is not supported in projects yet and it will be necessary to manually re-load to use the project.\n");
		goto desert;
	}
	pj_o(j);
	const char *filename = desc->uri;
	if (!filename) {
		pj_end(j);
		goto desert;
	}
	pj_ks(j, "raw", filename);
	char *abs = rz_file_abspath(filename);
	if (!abs) {
		pj_end(j);
		goto desert;
	}
	pj_ks(j, "absolute", abs);
	if (prj_file) {
		char *prj_dir = prj_dir_abs(prj_file);
		if (!prj_dir) {
			pj_end(j);
			goto beach;
		}
		char *rel = prj_relative_make(prj_dir, abs);
		if (rel) {
			pj_ks(j, "relative", rel);
			free(rel);
		}
		free(prj_dir);
	}
	pj_ki(j, "perm", desc->perm);
	pj_kn(j, "addr", rz_io_desc_size(desc));
	pj_end(j);
	char *key = rz_str_newf("file%d", file_num);
	sdb_set(db, key, pj_string(j), 0);
	file_num++;
	free(key);

beach:
	free(abs);
desert:
	free(j);
	return true;
}

static void file_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE const char *prj_file) {
	rz_return_if_fail(db && core);

	if (!core->file) {
		return;
	}
	FileSaveHelper fsh = {
		.db = db,
		.prj_file = prj_file
	};
	file_num = 0;
	rz_id_storage_foreach(core->io->files, &file_save_cb, &fsh);
}

typedef enum {
	FILE_SUCCESS,
	FILE_DOES_NOT_EXIST,
	FILE_LOAD_FAIL
} FileRet;

static FileRet try_load_file(RZ_NONNULL RzCore *core, const char *file, int perm, ut64 addr, RZ_NULLABLE RzSerializeResultInfo *res) {
	if (!rz_file_is_regular(file)) {
		return FILE_DOES_NOT_EXIST;
	}

	RzCoreFile *fh;
	if (addr == UT64_MAX) {
		fh = rz_core_file_open(core, file, perm, 0);
	} else {
		fh = rz_core_file_open(core, file, perm, addr);
	}
	if (!fh) {
		RZ_SERIALIZE_ERR(res, "failed re-open file \"%s\" referenced by project", file);
		return FILE_LOAD_FAIL;
	}
	rz_core_bin_load(core, file, addr);

	return FILE_SUCCESS;
}

enum {
	FILE_FIELD_RAW,
	FILE_FIELD_ABSOLUTE,
	FILE_FIELD_RELATIVE,
	FILE_FIELD_PERM,
	FILE_FIELD_ADDR
};

typedef void *SerializeFileParser;

SerializeFileParser serialize_file_parser_new(void) {
	SerializeFileParser parser = rz_key_parser_new();
	if (!parser) {
		return NULL;
	}

	rz_key_parser_add(parser, "raw", FILE_FIELD_RAW);
	rz_key_parser_add(parser, "absolute", FILE_FIELD_ABSOLUTE);
	rz_key_parser_add(parser, "relative", FILE_FIELD_RELATIVE);
	rz_key_parser_add(parser, "perm", FILE_FIELD_PERM);
	rz_key_parser_add(parser, "addr", FILE_FIELD_ADDR);
	return parser;
}

typedef struct {
	SerializeFileParser parser;
	const char *prj_file;
	RzCore *core;
	RzSerializeResultInfo *res;
} FileLoadHelper;

static bool file_load_cb(void *user, const char *k, const char *v) {
	bool ret = false;
	char *json_str = strdup(v);
	if (!json_str) {
		return true;
	}
	RzJson *json = rz_json_parse(json_str);
	if (!json || json->type != RZ_JSON_OBJECT) {
		goto heaven;
	}
	FileLoadHelper *flh = user;
	char *abs = NULL, *rel = NULL, *raw = NULL;
	int perm = RZ_PERM_RX;
	ut64 addr = UT64_MAX;

	RZ_KEY_PARSER_JSON(flh->parser, json, child, {
		case FILE_FIELD_RAW:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			raw = strdup(child->str_value);
			break;
		case FILE_FIELD_ABSOLUTE:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			abs = strdup(child->str_value);
			break;
		case FILE_FIELD_RELATIVE:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			rel = strdup(child->str_value);
			break;
		case FILE_FIELD_PERM:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			perm = child->num.s_value;
			break;
		case FILE_FIELD_ADDR:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			addr = child->num.u_value;
			break;
	})

	FileRet r = FILE_DOES_NOT_EXIST;
	const char *prj_file = flh->prj_file;
	RzCore *core = flh->core;
	RzSerializeResultInfo *res = flh->res;
	if (rel && prj_file) {
		char *prj_dir = prj_dir_abs(prj_file);
		if (prj_dir) {
			char *file = prj_relative_restore(prj_dir, rel);
			if (file) {
				r = try_load_file(core, file, perm, addr, res);
				free(file);
			}
			free(prj_dir);
		}
	}
	if (r != FILE_DOES_NOT_EXIST) {
		ret = r == FILE_SUCCESS;
		goto beach;
	}

	const char *file = abs;
	if (file) {
		r = try_load_file(core, file, perm, addr, res);
	}
	if (r != FILE_DOES_NOT_EXIST) {
		ret = (r == FILE_SUCCESS);
		goto beach;
	}

	file = raw;
	if (file) {
		r = try_load_file(core, file, perm, addr, res);
	}
	if (r != FILE_DOES_NOT_EXIST) {
		ret = (r == FILE_SUCCESS);
		goto beach;
	}
	RZ_SERIALIZE_ERR(res, "failed to re-locate file referenced by project");

beach:
	free(raw);
	free(abs);
	free(rel);
heaven:
	rz_json_free(json);
	free(json_str);
	return ret;
}

static bool file_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzCore *core, RZ_NULLABLE const char *prj_file,
	RZ_NULLABLE RzSerializeResultInfo *res) {
	rz_core_file_close_fd(core, -1);
	rz_io_close_all(core->io);
	rz_bin_file_delete_all(core->bin);

	SerializeFileParser parser = serialize_file_parser_new();

	FileLoadHelper flh = {
		.prj_file = prj_file,
		.core = core,
		.parser = parser,
		.res = res
	};
	return sdb_foreach(db, &file_load_cb, &flh);
}
