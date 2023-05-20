#ifndef RZ_UTIL_PATH_H_
#define RZ_UTIL_PATH_H_

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API void rz_path_set_prefix(RZ_NONNULL const char *path);
RZ_API RZ_OWN char *rz_path_prefix(RZ_NULLABLE const char *path);
RZ_API RZ_OWN char *rz_path_incdir(void);
RZ_API RZ_OWN char *rz_path_bindir(void);
RZ_API RZ_OWN char *rz_path_libdir(void);

RZ_API RZ_OWN char *rz_path_system(RZ_NULLABLE const char *path);
RZ_API RZ_OWN char *rz_path_extra(RZ_NULLABLE const char *path);
RZ_API RZ_OWN char *rz_path_home_prefix(RZ_NULLABLE const char *path);
RZ_API RZ_OWN char *rz_path_home(RZ_NULLABLE const char *path);

RZ_API RZ_OWN char *rz_path_system_rc(void);
RZ_API RZ_OWN char *rz_path_home_rc(void);
RZ_API RZ_OWN char *rz_path_home_config_rc(void);
RZ_API RZ_OWN char *rz_path_home_config_rcdir(void);
RZ_API RZ_OWN char *rz_path_home_config(void);
RZ_API RZ_OWN char *rz_path_home_cache(void);
RZ_API RZ_OWN char *rz_path_home_history(void);

RZ_API RZ_OWN char *rz_path_home_expand(RZ_NULLABLE const char *path);

RZ_API RZ_OWN char *rz_path_realpath(RZ_NULLABLE const char *path);

#ifdef __cplusplus
}
#endif

#endif
