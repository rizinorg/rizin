#ifndef RZ_SHM_H
#define RZ_SHM_H
#include <rz_types.h>

#if __WINDOWS__
#include <rz_windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
#if __WINDOWS__
	HANDLE h;
#else
	int fd;
	int id;
#endif
	char *name;
	ut8 *buf;
	ut32 size;
} RzShm;

RZ_API RzShm *rz_shm_new(void);
RZ_API void rz_shm_free(RzShm *shm);
RZ_API bool rz_shm_open(RzShm *shm, const char *name, bool rw, size_t size);
RZ_API int rz_shm_close(RzShm *shm);
RZ_API int rz_shm_read(RzShm *shm, ut64 offset, ut8 *buf, size_t count);
RZ_API int rz_shm_write(RzShm *shm, ut64 offset, const ut8 *buf, size_t count);

#ifdef __cplusplus
}
#endif
#endif // RZ_SHM_H