// SPDX-FileCopyrightText: 2020-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_PROJECT_H
#define RZ_PROJECT_H

#include <rz_util/rz_serialize.h>
#include <rz_core.h>
#include <sdb.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_PROJECT_VERSION 18

typedef Sdb RzProject;

typedef enum rz_project_err {
	RZ_PROJECT_ERR_SUCCESS,
	RZ_PROJECT_ERR_FILE,
	RZ_PROJECT_ERR_INVALID_TYPE,
	RZ_PROJECT_ERR_INVALID_VERSION,
	RZ_PROJECT_ERR_NEWER_VERSION,
	RZ_PROJECT_ERR_INVALID_CONTENTS,
	RZ_PROJECT_ERR_MIGRATION_FAILED,
	RZ_PROJECT_ERR_COMPRESSION_FAILED,
	RZ_PROJECT_ERR_UNKNOWN
} RzProjectErr;

RZ_API RZ_NONNULL const char *rz_project_err_message(RzProjectErr err);
RZ_API RzProjectErr rz_project_save(RzCore *core, RzProject *prj, const char *file);
RZ_API RzProjectErr rz_project_save_file(RzCore *core, const char *file, bool compress);
RZ_API RzProject *rz_project_load_file_raw(const char *file);
RZ_API void rz_project_free(RzProject *prj);

/**
 * @param load_bin_io whether to also load the underlying RIO and RBin state from the project. If false, the current state will be kept and the project loaded on top.
 * @param file filename of the project that db comes from. This is only used to re-locate the loaded RIO descs, the project file itself is not touched by this function.
 */
RZ_API RzProjectErr rz_project_load(RzCore *core, RzProject *prj, bool load_bin_io, RZ_NULLABLE const char *file, RzSerializeResultInfo *res);

/**
 * @param load_bin_io whether to also load the underlying RIO and RBin state from the project. If false, the current state will be kept and the project loaded on top.
 * @param file filename of the project to load from
 */
RZ_API RzProjectErr rz_project_load_file(RzCore *core, const char *file, bool load_bin_io, RzSerializeResultInfo *res);

RZ_API bool rz_project_migrate_v1_v2(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v2_v3(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v3_v4(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v4_v5(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v5_v6(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v6_v7(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v7_v8(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v8_v9(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v9_v10(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v10_v11(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v11_v12(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v12_v13(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v13_v14(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v14_v15(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v15_v16(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v16_v17(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate_v17_v18(RzProject *prj, RzSerializeResultInfo *res);
RZ_API bool rz_project_migrate(RzProject *prj, unsigned long version, RzSerializeResultInfo *res);

#ifdef __cplusplus
}
#endif

#endif
