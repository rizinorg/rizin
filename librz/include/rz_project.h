
#ifndef R2_PROJECT_H
#define R2_PROJECT_H

#include <rz_serialize.h>
#include <rz_core.h>
#include <sdb.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef Sdb RProject;

typedef enum rz_project_err {
	R_PROJECT_ERR_SUCCESS,
	R_PROJECT_ERR_FILE,
	R_PROJECT_ERR_INVALID_TYPE,
	R_PROJECT_ERR_INVALID_VERSION,
	R_PROJECT_ERR_NEWER_VERSION,
	R_PROJECT_ERR_INVALID_CONTENTS,
	R_PROJECT_ERR_UNKNOWN
} RProjectErr;

RZ_API RZ_NONNULL const char *rz_project_err_message(RProjectErr err);
RZ_API RProjectErr rz_project_save(RzCore *core, RProject *prj);
RZ_API RProjectErr rz_project_save_file(RzCore *core, const char *file);
RZ_API RProjectErr rz_project_load(RzCore *core, RProject *prj, RSerializeResultInfo *res);
RZ_API RProjectErr rz_project_load_file(RzCore *core, const char *file, RSerializeResultInfo *res);

#ifdef __cplusplus
}
#endif

#endif
