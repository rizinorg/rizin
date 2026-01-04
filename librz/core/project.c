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
	case RZ_PROJECT_ERR_COMPRESSION_FAILED:
		return "project file compression failed";
	case RZ_PROJECT_ERR_UNKNOWN:
		break;
	}
	return "unknown error";
}

RZ_API RzProjectErr rz_project_save(RzCore *core, RzProject *prj, const char *file) {
	char projver[32];
	sdb_set(prj, RZ_PROJECT_KEY_TYPE, RZ_PROJECT_TYPE);
	sdb_set(prj, RZ_PROJECT_KEY_VERSION, rz_strf(projver, "%u", RZ_PROJECT_VERSION));
	rz_serialize_core_save(sdb_ns(prj, "core", true), core, file);
	return RZ_PROJECT_ERR_SUCCESS;
}

static unsigned long rz_project_get_version(RzProject *prj) {
	const char *version_str = sdb_const_get(prj, RZ_PROJECT_KEY_VERSION);
	if (!version_str) {
		return ULONG_MAX;
	}
	return strtoul(version_str, NULL, 0);
}

/**
 * \brief Write the backup-database to a backup file.
 *
 * The backup-file will be created with the following name-scheme:
 * `.${FileBasename}_${OriginalVersion}.BAK`
 *
 * \param core[in,out] RzCore instance
 * \param file[in] A string representing the path to the original file. This is not the backup-file-path!
 * \param compress[in] Indiates if the database was originally compressed (backup file will also be compressed)
 * \return An error code, indicating the state of the operation
 * \retval RZ_PROJECT_ERR_SUCCESS If the backup was written correctly, or no backup was necessary
 * \retval RZ_PROJECT_ERR_INVALID_VERSION If the backup has a corrupted version number
 * \retval RZ_PROJECT_ERR_FILE If the backup could not be written, due to file operation errors
 * \retval RZ_PROJECT_ERR_UNKNOWN If a memory allocation failed
 * \retval RZ_PROJECT_ERR_COMPRESSION_FAILED If the deflate operation failed
 */
RZ_API RzProjectErr rz_project_save_backup_file(RzCore *core, const char *file, bool compress) {
	char *tmp_file = NULL;
	if (!core->backup) {
		/* No backup necessary */
		return RZ_PROJECT_ERR_SUCCESS;
	}

	if (compress) {
		int mkstemp_fd = rz_file_mkstemp("svprjbu", &tmp_file);
		if (mkstemp_fd == -1 || !tmp_file) {
			return RZ_PROJECT_ERR_FILE;
		}
		close(mkstemp_fd);
	}

	char *dst_path = NULL;
	const char *basename = rz_file_basename(file);
	char *dirname = rz_file_dirname(file);
	unsigned long version = rz_project_get_version(core->backup);
	if (!version || version == ULONG_MAX) {
		free(dirname);
		return RZ_PROJECT_ERR_INVALID_VERSION;
	}

	int dst_path_len = snprintf(NULL, 0, "%s/.%s_%ld.BAK", dirname, basename, version);
	if (dst_path_len < 0) {
		free(dirname);
		return RZ_PROJECT_ERR_UNKNOWN;
	}

	dst_path_len++;
	dst_path = calloc(dst_path_len, 1);
	if (dst_path == NULL) {
		free(dirname);
		return RZ_PROJECT_ERR_UNKNOWN;
	}

	if (strlen(dirname) > 0) {
		snprintf(dst_path, dst_path_len, "%s/.%s_%ld.BAK", dirname, basename, version);
	} else {
		snprintf(dst_path, dst_path_len, ".%s_%ld.BAK", basename, version);
	}

	free(dirname);

	const char *save_file = compress ? tmp_file : dst_path;
	RzProjectErr err = RZ_PROJECT_ERR_SUCCESS;

	if (!sdb_text_save(core->backup, save_file, true)) {
		err = RZ_PROJECT_ERR_FILE;
		goto tmp_file_err;
	}

	if (compress && !rz_file_deflate(tmp_file, dst_path)) {
		err = RZ_PROJECT_ERR_COMPRESSION_FAILED;
	}

tmp_file_err:
	free(dst_path);
	return err;
}

RZ_API RzProjectErr rz_project_save_file(RzCore *core, const char *file, bool compress) {
	char *tmp_file = NULL;

	if (compress) {
		int mkstemp_fd = rz_file_mkstemp("svprj", &tmp_file);
		if (mkstemp_fd == -1 || !tmp_file) {
			return RZ_PROJECT_ERR_FILE;
		}
		close(mkstemp_fd);
	}

	RzProjectErr err;
	const char *save_file = compress ? tmp_file : file;
	RzProject *prj = sdb_new0();
	if (!prj) {
		err = RZ_PROJECT_ERR_UNKNOWN;
		goto tmp_file_err;
	}
	err = rz_project_save(core, prj, file);
	if (err != RZ_PROJECT_ERR_SUCCESS) {
		sdb_free(prj);
		return err;
	}
	if (!sdb_text_save(prj, save_file, true)) {
		err = RZ_PROJECT_ERR_FILE;
	}
	sdb_free(prj);

	if (err != RZ_PROJECT_ERR_SUCCESS) {
		goto tmp_file_err;
	}

	if (compress && !rz_file_deflate(tmp_file, file)) {
		err = RZ_PROJECT_ERR_COMPRESSION_FAILED;
		goto tmp_file_err;
	}

	rz_config_set(core->config, "prj.file", file);

tmp_file_err:
	rz_file_rm(tmp_file);
	free(tmp_file);
	return err;
}

/// Load a file into an RzProject but don't actually migrate anything or load it into an RzCore
RZ_API RzProject *rz_project_load_file_raw(const char *file) {
	RzProject *prj = sdb_new0();
	if (!prj) {
		return NULL;
	}

	char *tmp_file;
	int mkstemp_fd = rz_file_mkstemp("ldprj", &tmp_file);
	close(mkstemp_fd);

	if (mkstemp_fd == -1 || !tmp_file) {
		free(tmp_file);
		return NULL;
	}

	const char *load_file = tmp_file;

	if (!rz_file_exists(file)) {
		prj = NULL;
		goto return_goto;
	}
	if (rz_file_is_deflated(file)) {
		if (!rz_file_inflate(file, tmp_file)) {
			prj = NULL;
			goto return_goto;
		}
	} else {
		load_file = file;
	}

	if (!sdb_text_load(prj, load_file)) {
		sdb_free(prj);
		prj = NULL;
	}

return_goto:
	rz_file_rm(tmp_file);
	free(tmp_file);
	return prj;
}

RZ_API void rz_project_free(RzProject *prj) {
	sdb_free(prj);
}

RZ_API RzProjectErr rz_project_load(RzCore *core, RzProject *prj, bool load_bin_io, RZ_NULLABLE const char *file, RzSerializeResultInfo *res) {
	rz_return_val_if_fail(core && prj, RZ_PROJECT_ERR_UNKNOWN);
	const char *type = sdb_const_get(prj, RZ_PROJECT_KEY_TYPE);
	if (!type || strcmp(type, RZ_PROJECT_TYPE) != 0) {
		return RZ_PROJECT_ERR_INVALID_TYPE;
	}
	unsigned long version = rz_project_get_version(prj);
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

	if (prj->backup) {
		prj->backup->refs++;
		core->backup = prj->backup;
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

RZ_API bool rz_core_project_load_for_cli(RzCore *core, const char *file, bool load_bin_io) {
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	RzProjectErr err = rz_project_load_file(core, file, load_bin_io, res);
	if (err != RZ_PROJECT_ERR_SUCCESS) {
		RZ_LOG_ERROR("core: Failed to load project: %s\n", rz_project_err_message(err));
	} else if (!rz_list_empty(res)) {
		rz_cons_printf("Detailed project load info:\n");
	}
	RzListIter *it;
	char *s;
	rz_list_foreach (res, it, s) {
		rz_cons_printf("  %s\n", s);
	}
	rz_serialize_result_info_free(res);
	return err == RZ_PROJECT_ERR_SUCCESS;
}
