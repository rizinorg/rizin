// SPDX-FileCopyrightText: 2010-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2010-2020 maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_project.h>

#define RZ_DB_KEY_TYPE    "type"
#define RZ_DB_KEY_VERSION "version"

#define RZ_DB_PROJECT_VERSION 1
#define RZ_DB_PROJECT_TYPE    "rizin rz-db project"

RZ_API RZ_NONNULL const char *rz_project_err_message(RzProjectErr err) {
	switch (err) {
	case RZ_PROJECT_ERR_SUCCESS:
		return "success";
	case RZ_PROJECT_ERR_FILE:
		return "file access error";
	case RZ_PROJECT_ERR_INVALID_TYPE:
		return "invalid file type";
	case RZ_PROJECT_ERR_INVALID_VERSION:
		return "invalid project version";
	case RZ_PROJECT_ERR_NEWER_VERSION:
		return "newer project version";
	case RZ_PROJECT_ERR_INVALID_CONTENTS:
		return "invalid content encountered";
	case RZ_PROJECT_ERR_UNKNOWN:
		break;
	}
	return "unknown error";
}

RZ_API RzProjectErr rz_project_save(RzCore *core, RzProject *prj, const char *file) {
	sdb_set(prj, RZ_DB_KEY_TYPE, RZ_DB_PROJECT_TYPE, 0);
	sdb_set(prj, RZ_DB_KEY_VERSION, sdb_fmt("%u", RZ_DB_PROJECT_VERSION), 0);
	rz_serialize_core_save(sdb_ns(prj, "core", true), core, file);
	return RZ_PROJECT_ERR_SUCCESS;
}

RZ_API RzProjectErr rz_project_save_file(RzCore *core, const char *file) {
	RzProject *prj = sdb_new0();
	if (!prj) {
		return RZ_PROJECT_ERR_UNKNOWN;
	}
	RzProjectErr err = rz_project_save(core, prj, file);
	if (err != RZ_PROJECT_ERR_SUCCESS) {
		sdb_free(prj);
		return err;
	}
	if (!sdb_text_save(prj, file, true)) {
		err = RZ_PROJECT_ERR_FILE;
	}
	sdb_free(prj);
	if (err == RZ_PROJECT_ERR_SUCCESS) {
		rz_config_set(core->config, "prj.file", file);
	}
	return err;
}

RZ_API RzProjectErr rz_project_load(RzCore *core, RzProject *prj, bool load_bin_io, RZ_NULLABLE const char *file, RzSerializeResultInfo *res) {
	const char *type = sdb_const_get(prj, RZ_DB_KEY_TYPE, 0);
	if (!type || strcmp(type, RZ_DB_PROJECT_TYPE) != 0) {
		return RZ_PROJECT_ERR_INVALID_TYPE;
	}
	const char *version_str = sdb_const_get(prj, RZ_DB_KEY_VERSION, 0);
	if (!version_str) {
		return RZ_PROJECT_ERR_INVALID_VERSION;
	}
	unsigned long version = strtoul(version_str, NULL, 0);
	if (!version || version == ULONG_MAX) {
		return RZ_PROJECT_ERR_INVALID_VERSION;
	} else if (version > RZ_DB_PROJECT_VERSION) {
		return RZ_PROJECT_ERR_NEWER_VERSION;
	}

	Sdb *core_db = sdb_ns(prj, "core", false);
	if (!core_db) {
		RZ_SERIALIZE_ERR(res, "missing core namespace");
		return RZ_PROJECT_ERR_INVALID_CONTENTS;
	}
	if (!rz_serialize_core_load(core_db, core, load_bin_io, file, res)) {
		return RZ_PROJECT_ERR_INVALID_CONTENTS;
	}

	rz_config_set(core->config, "prj.file", file);

	return RZ_PROJECT_ERR_SUCCESS;
}

RZ_API RzProjectErr rz_project_load_file(RzCore *core, const char *file, bool load_bin_io, RzSerializeResultInfo *res) {
	RzProject *prj = sdb_new0();
	if (!prj) {
		return RZ_PROJECT_ERR_UNKNOWN;
	}
	if (!sdb_text_load(prj, file)) {
		RZ_SERIALIZE_ERR(res, "failed to read database file");
		return RZ_PROJECT_ERR_FILE;
	}
	RzProjectErr ret = rz_project_load(core, prj, load_bin_io, file, res);
	sdb_free(prj);
	return ret;
}
