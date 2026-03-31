#ifndef RZ_UTIL_PATH_H_
#define RZ_UTIL_PATH_H_

#include <rz_types.h>
#include <rz_th.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Holds Rizin's path prefix and synchronization utilities.
 *
 * This structure stores the computed prefix of Rizin's path, along with a flag
 * indicating whether the prefix has already been computed to avoid redundant work.
 * It also includes a mutex to ensure thread-safe access when computing or accessing the prefix.
 */
typedef struct rz_path_t {
	char *prefix; ///< the computed path prefix.
	bool prefix_searched; ///< flag indicating if the prefix has already been computed.
	RzThreadLock *prefix_mutex; ///< mutex to protect access to the prefix in multithreaded contexts.
} RzPath;

#ifdef RZ_API

RZ_API void rz_path_set_prefix(RZ_BORROW RZ_NONNULL RzPath *sys_path, RZ_NONNULL const char *path);
RZ_API const char *rz_path_prefix(RZ_BORROW RZ_NONNULL RzPath *sys_path);
RZ_API RZ_OWN char *rz_path_incdir(RZ_BORROW RZ_NULLABLE RzPath *sys_path);
RZ_API RZ_OWN char *rz_path_bindir(RZ_BORROW RZ_NULLABLE RzPath *sys_path);
RZ_API RZ_OWN char *rz_path_libdir(RZ_BORROW RZ_NULLABLE RzPath *sys_path);

RZ_API RZ_OWN char *rz_path_system(RZ_BORROW RZ_NULLABLE RzPath *sys_path, RZ_NULLABLE const char *path);
RZ_API RZ_OWN char *rz_path_extra(RZ_NULLABLE const char *path);
RZ_API RZ_OWN char *rz_path_home_prefix(RZ_NULLABLE const char *path);
RZ_API RZ_OWN char *rz_path_home(RZ_NULLABLE const char *path);

RZ_API RZ_OWN char *rz_path_system_rc(RZ_BORROW RZ_NULLABLE RzPath *sys_path);
RZ_API RZ_OWN char *rz_path_home_rc(void);
RZ_API RZ_OWN char *rz_path_home_config_rc(void);
RZ_API RZ_OWN char *rz_path_home_config_rcdir(void);
RZ_API RZ_OWN char *rz_path_home_config(void);
RZ_API RZ_OWN char *rz_path_home_cache(void);
RZ_API RZ_OWN char *rz_path_home_history(void);
RZ_API RZ_OWN char *rz_path_normalize_expand(char *usr_input, size_t len);

RZ_API RZ_OWN char *rz_path_home_expand(RZ_NULLABLE const char *path);

RZ_API RZ_OWN char *rz_path_realpath(RZ_NULLABLE const char *path);

RZ_API RZ_OWN RzPath *rz_path_new(void);
RZ_API void rz_path_free(RZ_OWN RZ_NULLABLE RzPath *p);

#endif

#ifdef __cplusplus
}
#endif

#endif
