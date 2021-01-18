
#ifndef RZ_PROJECT_H
#define RZ_PROJECT_H

#include <rz_util/rz_serialize.h>
#include <rz_core.h>
#include <sdb.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef Sdb RzProject;

typedef enum rz_project_err {
	RZ_PROJECT_ERR_SUCCESS,
	RZ_PROJECT_ERR_FILE,
	RZ_PROJECT_ERR_INVALID_TYPE,
	RZ_PROJECT_ERR_INVALID_VERSION,
	RZ_PROJECT_ERR_NEWER_VERSION,
	RZ_PROJECT_ERR_INVALID_CONTENTS,
	RZ_PROJECT_ERR_UNKNOWN
} RzProjectErr;

RZ_API RZ_NONNULL const char *rz_project_err_message(RzProjectErr err);
RZ_API RzProjectErr rz_project_save(RzCore *core, RzProject *prj, const char *file);
RZ_API RzProjectErr rz_project_save_file(RzCore *core, const char *file);

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

#ifdef __cplusplus
}
#endif

#endif
