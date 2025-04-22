// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_lib.h>
#include <sys/types.h>

#include "rz_io_plugins.h"

#if HAVE_HEADER_LINUX_ASHMEM_H || HAVE_HEADER_SYS_SHM_H || __WINDOWS__
#if HAVE_HEADER_LINUX_ASHMEM_H
#include <linux/ashmem.h>
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
} RzIOShm;

#define SHMATSZ 0x9000; // 32*1024*1024; /* 32MB : XXX not used correctly? */

static int shm__write(RzIO *io, RzIODesc *fd, const ut8 *buf, size_t count) {
	rz_return_val_if_fail(fd && fd->data, -1);
	RzIOShm *shm = fd->data;
	if (shm->buf) {
		(void)memcpy(shm->buf + io->off, buf, count);
		return count;
	}
#if !defined(__WINDOWS__)
	return write(shm->fd, buf, count);
#else
	return 0;
#endif
}

static int shm__read(RzIO *io, RzIODesc *fd, ut8 *buf, size_t count) {
	rz_return_val_if_fail(fd && fd->data, -1);
	RzIOShm *shm = fd->data;
	if (io->off + count >= shm->size) {
		if (io->off > shm->size) {
			return -1;
		}
		count = shm->size - io->off;
	}
	if (shm->buf) {
		memcpy(buf, shm->buf + io->off, count);
		return count;
	}
#if !defined(__WINDOWS__)
	return read(shm->fd, buf, count);
#else
	return 0;
#endif
}

static int shm__close(RzIODesc *fd) {
	rz_return_val_if_fail(fd && fd->data, -1);
	int ret;
	RzIOShm *shm = fd->data;
#if __WINDOWS__
	UnmapViewOfFile(shm->buf);
	ret = CloseHandle(shm->h);
#else
#if HAVE_SHM_OPEN || HAVE_HEADER_LINUX_ASHMEM_H
	ret = close(shm->fd);
#else
	if (shm->buf) {
		ret = shmdt(((RzIOShm *)(fd->data))->buf);
	} else {
		ret = close(shm->fd);
	}
#endif
#endif
	free(shm->name);
	RZ_FREE(fd->data);
	return ret;
}

static ut64 shm__lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	rz_return_val_if_fail(fd && fd->data, -1);
	RzIOShm *shm = fd->data;
	switch (whence) {
	case RZ_IO_SEEK_SET:
		return io->off = offset;
	case RZ_IO_SEEK_CUR:
		if (io->off + offset > shm->size) {
			return io->off = shm->size;
		}
		io->off += offset;
		return io->off;
	case RZ_IO_SEEK_END:
		return io->off = (shm->size ? shm->size : 0xffffffff) + offset;
	}
	return io->off;
}

static bool shm__plugin_open(RzIO *io, const char *pathname, bool many) {
	return (!strncmp(pathname, "shm://", 6));
}

#if !HAVE_SHM_OPEN && !HAVE_HEADER_LINUX_ASHMEM_H
static inline int getshmfd(RzIOShm *shm) {
	return (((int)(size_t)shm->buf) >> 4) & 0xfff;
}
#endif

static RzIODesc *shm__open(RzIO *io, const char *uri, int rw, int mode) {
	if (strncmp(uri, "shm://", 6)) {
		return NULL;
	}
	RzIOShm *shm = RZ_NEW0(RzIOShm);
	if (!shm) {
		return NULL;
	}
	const char *name = strstr(uri, "://");
	if (!name) {
		free(shm);
		return NULL;
	}
	name += 3;

	// The shared memory size is an optional parameter
	char *size = strstr(name, "/");
	if (size) {
		*size = 0;
		size += 1;
	}

	shm->name = rz_str_newf("/%s", name);
#if __WINDOWS__
	LPWSTR wname = rz_utf8_to_utf16(name);
	const DWORD desired_access = rw ? FILE_MAP_ALL_ACCESS : FILE_MAP_READ;
	shm->h = OpenFileMappingW(desired_access, FALSE, wname);
	free(wname);
	if (!shm->h) {
		RZ_LOG_ERROR("Cannot open shared memory \"%s\"\n", shm->name);
		free(shm->name);
		free(shm);
		return NULL;
	}
	size_t given_size = 0;
	if (size && (given_size = rz_num_math(NULL, size))) {
		shm->size = given_size;
	}
	shm->buf = MapViewOfFile(shm->h, desired_access, 0, 0, given_size);
	if (!shm->buf) {
		RZ_LOG_ERROR("Cannot map shared memory \"%s\"\n", shm->name);
		CloseHandle(shm->h);
		free(shm->name);
		free(shm);
	}
	if (!given_size) {
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
		free(shm);
		return NULL;
	}
	ut64 given_size = 0;
	// If the memory size is supplied - we use it,
	// otherwise try to read it from the file descriptor itself
	if (size && (given_size = rz_num_math(NULL, size))) {
		shm->size = given_size;
	} else {
		struct stat st;
		if (fstat(shm->fd, &st)) {
			RZ_LOG_ERROR("Cannot determine the size of shared memory \"%s\" (0x%08x)\n", shm->name, shm->id);
			close(shm->fd);
			free(shm->name);
			free(shm);
			return NULL;
		}
		shm->size = st.st_size;
	}

#if HAVE_HEADER_LINUX_ASHMEM_H
	if (ioctl(shm->fd, ASHMEM_SET_NAME, name) == -1 ||
		ioctl(shm->fd, ASHMEM_SET_SIZE, shm->size) == -1) {
		RZ_LOG_ERROR("Cannot set shared memory \"%s\"/%lu (0x%08x)\n", shm->name, (unsigned long)shm->size, shm->id);
		close(shm->fd);
		free(shm->name);
		free(shm);
		return NULL;
	}
#endif
	shm->buf = mmap(NULL, shm->size, (rw ? (PROT_READ | PROT_WRITE) : PROT_READ), MAP_SHARED, shm->fd, 0);
	if (shm->buf == MAP_FAILED) {
		RZ_LOG_ERROR("Cannot mmap shared memory \"%s\"/%lu (0x%08x)\n", shm->name, (unsigned long)shm->size, shm->id);
		close(shm->fd);
		free(shm->name);
		free(shm);
		return NULL;
	}
#else
	shm->id = atoi(ptr);
	if (!shm->id) {
		shm->id = rz_str_djb2_hash(ptr);
	}

	shm->buf = shmat(shm->id, 0, 0);
	if (shm->buf == (void *)(size_t)-1) {
		shm->fd = -1;
	} else {
		shm->fd = getshmfd(shm);
	}
	shm->size = SHMATSZ;
	if (shm->fd == -1) {
		RZ_LOG_ERROR("Cannot connect to shared memory (%d)\n", shm->id);
		free(shm->name);
		free(shm);
		return NULL;
	}
#endif
	RZ_LOG_INFO("Connected to shared memory \"%s\" (0x%08x) size 0x%x\n",
		shm->name, shm->id, shm->size);
#endif // __WINDOWS__
	return rz_io_desc_new(io, &rz_io_plugin_shm, uri, rw, mode, shm);
}

RzIOPlugin rz_io_plugin_shm = {
	.name = "shm",
	.desc = "Shared memory resources plugin",
	.uris = "shm://",
	.license = "MIT",
	.open = shm__open,
	.close = shm__close,
	.read = shm__read,
	.check = shm__plugin_open,
	.lseek = shm__lseek,
	.write = shm__write,
};

#else
RzIOPlugin rz_io_plugin_shm = {
	.name = "shm",
	.desc = "shared memory resources",
};
#endif

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_shm,
	.version = RZ_VERSION
};
#endif
