
#ifndef R2_PROJECT_H
#define R2_PROJECT_H

#include <rz_serialize.h>
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
RZ_API RzProjectErr rz_project_save(RzCore *core, RzProject *prj);
RZ_API RzProjectErr rz_project_save_file(RzCore *core, const char *file);
RZ_API RzProjectErr rz_project_load(RzCore *core, RzProject *prj, RZ_NULLABLE const char *file, RSerializeResultInfo *res);
RZ_API RzProjectErr rz_project_load_file(RzCore *core, const char *file, RSerializeResultInfo *res);

#ifdef __cplusplus
}
#endif

#endif
