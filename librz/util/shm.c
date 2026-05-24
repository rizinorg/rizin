// SPDX-FileCopyrightText: 2008-2026 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#if HAVE_HEADER_LINUX_ASHMEM_H || HAVE_HEADER_SYS_SHM_H || __WINDOWS__
#if HAVE_HEADER_LINUX_ASHMEM_H
#include <linux/ashmem.h>
#include <sys/ioctl.h>
#endif
#if HAVE_HEADER_SYS_SHM_H
#include <sys/shm.h>
#endif
#if HAVE_HEADER_SYS_IPC_H
#include <sys/ipc.h>
#endif
#if HAVE_HEADER_SYS_MMAN_H
#include <sys/mman.h>
#endif
#if __WINDOWS__
#include <windows.h>
#endif

#if !__WINDOWS__
#include <unistd.h>
#endif

#define SHMATSZ 0x9000

#if !HAVE_SHM_OPEN && !HAVE_HEADER_LINUX_ASHMEM_H
static inline int getshmfd(RzShm *shm) {
	return (((int)(size_t)shm->buf) >> 4) & 0xfff;
}
#endif

RZ_API RzShm *rz_shm_new(void) {
	return RZ_NEW0(RzShm);
}

RZ_API void rz_shm_free(RzShm *shm) {
	if (!shm) {
		return;
	}
	free(shm->name);
	free(shm);
}

RZ_API bool rz_shm_open(RzShm *shm, const char *name, bool rw, size_t size) {
	rz_return_val_if_fail(shm, false);
	shm->name = rz_str_newf("/%s", name);
	if (!shm->name) {
		return false;
	}
#if __WINDOWS__
	LPWSTR wname = rz_utf8_to_utf16(name);
	const DWORD desired_access = rw ? FILE_MAP_ALL_ACCESS : FILE_MAP_READ;
	shm->h = OpenFileMappingW(desired_access, FALSE, wname);
	free(wname);
	if (!shm->h) {
		RZ_LOG_ERROR("Cannot open shared memory \"%s\"\n", shm->name);
		free(shm->name);
		return false;
	}
	if (size > 0) {
		shm->size = size;
	}
	shm->buf = MapViewOfFile(shm->h, desired_access, 0, 0, size);
	if (!shm->buf) {
		RZ_LOG_ERROR("Cannot map shared memory \"%s\"\n", shm->name);
		CloseHandle(shm->h);
		shm->h = NULL;
		free(shm->name);
		return false;
	}
	if (size == 0) {
		MEMORY_BASIC_INFORMATION mi;
		if (VirtualQuery(shm->buf, &mi, sizeof(mi)) == sizeof(mi)) {
			shm->size = mi.RegionSize;
		}
	}
	RZ_LOG_INFO("Connected to shared memory \"%s\" size 0x%x\n",
		shm->name, shm->size);
#else
#if HAVE_SHM_OPEN || HAVE_HEADER_LINUX_ASHMEM_H
	shm->id = rz_str_djb2_hash(name);

#if HAVE_SHM_OPEN
	shm->fd = shm_open(shm->name, O_CREAT | (rw ? O_RDWR : O_RDONLY), 0644);
#else // HAVE_HEADER_LINUX_ASHMEM_H
	shm->fd = open("/dev/ashmem", O_CREAT | (rw ? O_RDWR : O_RDONLY), 0644);
#endif
	if (shm->fd == -1) {
		RZ_LOG_ERROR("Cannot connect to shared memory \"%s\" (0x%08x)\n", shm->name, shm->id);
		free(shm->name);
		return false;
	}
	if (size > 0) {
		shm->size = size;
#if HAVE_SHM_OPEN
		if (rw) {
			(void)ftruncate(shm->fd, shm->size);
		}
#endif
	} else {
		struct stat st;
		if (fstat(shm->fd, &st)) {
			RZ_LOG_ERROR("Cannot determine the size of shared memory \"%s\" (0x%08x)\n", shm->name, shm->id);
			close(shm->fd);
			shm->fd = -1;
			free(shm->name);
			return false;
		}
		shm->size = st.st_size;
	}

#if HAVE_HEADER_LINUX_ASHMEM_H
	if (ioctl(shm->fd, ASHMEM_SET_NAME, name) == -1 ||
		ioctl(shm->fd, ASHMEM_SET_SIZE, shm->size) == -1) {
		RZ_LOG_ERROR("Cannot set shared memory \"%s\"/%lu (0x%08x)\n", shm->name, (unsigned long)shm->size, shm->id);
		close(shm->fd);
		shm->fd = -1;
		free(shm->name);
		return false;
	}
#endif
	shm->buf = mmap(NULL, shm->size, (rw ? (PROT_READ | PROT_WRITE) : PROT_READ), MAP_SHARED, shm->fd, 0);
	if (shm->buf == MAP_FAILED) {
		RZ_LOG_ERROR("Cannot mmap shared memory \"%s\"/%lu (0x%08x)\n", shm->name, (unsigned long)shm->size, shm->id);
		close(shm->fd);
		shm->fd = -1;
		shm->buf = NULL;
		free(shm->name);
		return false;
	}
#else
	shm->id = atoi(name);
	if (!shm->id) {
		shm->id = rz_str_djb2_hash(name);
	}

	shm->buf = shmat(shm->id, 0, 0);
	if (shm->buf == (void *)(size_t)-1) {
		shm->fd = -1;
		shm->buf = NULL;
	} else {
		shm->fd = getshmfd(shm);
	}
	shm->size = SHMATSZ;
	if (shm->fd == -1) {
		RZ_LOG_ERROR("Cannot connect to shared memory (%d)\n", shm->id);
		free(shm->name);
		return false;
	}
#endif
	RZ_LOG_INFO("Connected to shared memory \"%s\" (0x%08x) size 0x%x\n",
		shm->name, shm->id, shm->size);
#endif // __WINDOWS__
	return true;
}

RZ_API int rz_shm_close(RzShm *shm) {
	rz_return_val_if_fail(shm, -1);
	int ret = 0;
#if __WINDOWS__
	UnmapViewOfFile(shm->buf);
	ret = CloseHandle(shm->h);
	shm->buf = NULL;
	shm->h = NULL;
#else
#if HAVE_SHM_OPEN || HAVE_HEADER_LINUX_ASHMEM_H
	ret = close(shm->fd);
	shm->fd = -1;
	shm->buf = NULL;
#else
	if (shm->buf) {
		ret = shmdt(shm->buf);
		shm->buf = NULL;
	} else {
		ret = close(shm->fd);
		shm->fd = -1;
	}
#endif
#endif
	return ret;
}

RZ_API int rz_shm_read(RzShm *shm, ut64 offset, ut8 *buf, size_t count) {
	rz_return_val_if_fail(shm, -1);
	if (offset + count >= shm->size) {
		if (offset > shm->size) {
			return -1;
		}
		count = shm->size - offset;
	}
	if (shm->buf) {
		memcpy(buf, shm->buf + offset, count);
		return count;
	}
#if !defined(__WINDOWS__)
	return read(shm->fd, buf, count);
#else
	return 0;
#endif
}

RZ_API int rz_shm_write(RzShm *shm, ut64 offset, const ut8 *buf, size_t count) {
	rz_return_val_if_fail(shm, -1);
	if (shm->buf) {
		(void)memcpy(shm->buf + offset, buf, count);
		return count;
	}
#if !defined(__WINDOWS__)
	return write(shm->fd, buf, count);
#else
	return 0;
#endif
}
#else

RZ_API RzShm *rz_shm_new(void) {
	return RZ_NEW0(RzShm);
}

RZ_API void rz_shm_free(RzShm *shm) {
	if (shm) {
		free(shm->name);
		free(shm);
	}
}

RZ_API bool rz_shm_open(RzShm *shm, const char *name, bool rw, size_t size) {
	return false;
}

RZ_API int rz_shm_close(RzShm *shm) {
	return -1;
}

RZ_API int rz_shm_read(RzShm *shm, ut64 offset, ut8 *buf, size_t count) {
	return -1;
}

RZ_API int rz_shm_write(RzShm *shm, ut64 offset, const ut8 *buf, size_t count) {
	return -1;
}

#endif
