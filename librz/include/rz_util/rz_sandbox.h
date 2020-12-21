#ifndef RZ_SANDBOX_H
#define RZ_SANDBOX_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __FreeBSD__
#include <sys/param.h>

#if __FreeBSD_version >= 1000000
#define HAVE_CAPSICUM 1
#else
#define HAVE_CAPSICUM 0
#endif
#else
#define HAVE_CAPSICUM 0
#endif
/**
 * This function verifies that the given path is allowed. Paths are allowed only if they don't
 * contain .. components (which would indicate directory traversal) and they are relative.
 * Paths pointing into the webroot are an exception: For reaching the webroot, .. and absolute
 * path are ok.
 */
#if __WINDOWS__
RZ_API HANDLE rz_sandbox_opendir(const char *path, WIN32_FIND_DATAW *entry);
#else
RZ_API DIR* rz_sandbox_opendir(const char *path);
#endif
RZ_API int rz_sandbox_truncate(int fd, ut64 length);
RZ_API int rz_sandbox_open(const char *path, int mode, int perm);
RZ_API FILE *rz_sandbox_fopen(const char *path, const char *mode);
RZ_API int rz_sandbox_kill(int pid, int sig);

#ifdef __cplusplus
}
#endif

#endif //  RZ_SANDBOX_H
