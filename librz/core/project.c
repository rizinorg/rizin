// SPDX-FileCopyrightText: 2020-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_project.h>

#define RZ_PROJECT_KEY_TYPE    "type"
#define RZ_PROJECT_KEY_VERSION "version"

#define RZ_PROJECT_TYPE "rizin rz-db project"

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
	case RZ_PROJECT_ERR_MIGRATION_FAILED:
		return "migration failed";
	case RZ_PROJECT_ERR_UNKNOWN:
		break;
	}
	return "unknown error";
}

RZ_API RzProjectErr rz_project_save(RzCore *core, RzProject *prj, const char *file) {
	sdb_set(prj, RZ_PROJECT_KEY_TYPE, RZ_PROJECT_TYPE, 0);
	sdb_set(prj, RZ_PROJECT_KEY_VERSION, sdb_fmt("%u", RZ_PROJECT_VERSION), 0);
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

/// Load a file into an RzProject but don't actually migrate anything or load it into an RzCore
RZ_API RzProject *rz_project_load_file_raw(const char *file) {
	RzProject *prj = sdb_new0();
	if (!prj) {
		return NULL;
	}
	if (!sdb_text_load(prj, file)) {
		sdb_free(prj);
		return NULL;
	}
	return prj;
}

RZ_API void rz_project_free(RzProject *prj) {
	sdb_free(prj);
}

RZ_API RzProjectErr rz_project_load(RzCore *core, RzProject *prj, bool load_bin_io, RZ_NULLABLE const char *file, RzSerializeResultInfo *res) {
	rz_return_val_if_fail(core && prj, RZ_PROJECT_ERR_UNKNOWN);
	const char *type = sdb_const_get(prj, RZ_PROJECT_KEY_TYPE, 0);
	if (!type || strcmp(type, RZ_PROJECT_TYPE) != 0) {
		return RZ_PROJECT_ERR_INVALID_TYPE;
	}
	const char *version_str = sdb_const_get(prj, RZ_PROJECT_KEY_VERSION, 0);
	if (!version_str) {
		return RZ_PROJECT_ERR_INVALID_VERSION;
	}
	unsigned long version = strtoul(version_str, NULL, 0);
	if (!version || version == ULONG_MAX) {
		return RZ_PROJECT_ERR_INVALID_VERSION;
	}
	if (version > RZ_PROJECT_VERSION) {
		return RZ_PROJECT_ERR_NEWER_VERSION;
	}
	if (!rz_project_migrate(prj, version, res)) {
		return RZ_PROJECT_ERR_MIGRATION_FAILED;
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
	RzProject *prj = rz_project_load_file_raw(file);
	if (!prj) {
		RZ_SERIALIZE_ERR(res, "failed to read database file");
		return RZ_PROJECT_ERR_FILE;
	}
	RzProjectErr ret = rz_project_load(core, prj, load_bin_io, file, res);
	sdb_free(prj);
	return ret;
}
