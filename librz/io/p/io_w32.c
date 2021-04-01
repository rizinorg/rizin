// SPDX-FileCopyrightText: 2008-2011 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_io.h"
#include "rz_lib.h"

#if __WINDOWS__
#include <sys/types.h>

typedef struct {
	HANDLE hnd;
	ut64 winbase;
} RzIOW32;
#define RzIOW32_HANDLE(x) (((RzIOW32 *)x)->hnd)

static int w32__write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data)
		return -1;
	return WriteFile(RzIOW32_HANDLE(fd), buf, count, NULL, NULL);
}

static int w32__read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	DWORD ret;
	return ReadFile(RzIOW32_HANDLE(fd), buf, count, &ret, NULL) ? ret : -1;
}

static int w32__close(RzIODesc *fd) {
	if (fd->data) {
		// TODO: handle return value
		CloseHandle(RzIOW32_HANDLE(fd));
		RZ_FREE(fd->data);
		return 0;
	}
	return -1;
}

// TODO: handle filesize and so on
static ut64 w32__lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	SetFilePointer(RzIOW32_HANDLE(fd), offset, 0, !whence ? FILE_BEGIN : whence == 1 ? FILE_CURRENT
											 : FILE_END);
	return (!whence) ? offset : whence == 1 ? io->off + offset
						: ST64_MAX;
}

static bool w32__plugin_open(RzIO *io, const char *pathname, bool many) {
	return (!strncmp(pathname, "w32://", 6));
}

static RzIODesc *w32__open(RzIO *io, const char *pathname, int rw, int mode) {
	if (!strncmp(pathname, "w32://", 6)) {
		RzIOW32 *w32 = RZ_NEW0(RzIOW32);
		if (!w32) {
			return NULL;
		}
		const char *filename = pathname + 6;
		LPTSTR filename_ = rz_sys_conv_utf8_to_win(filename);
		w32->hnd = CreateFile(filename_,
			GENERIC_READ | (rw ? GENERIC_WRITE : 0),
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		free(filename_);
		if (w32->hnd != INVALID_HANDLE_VALUE)
			return rz_io_desc_new(io, &rz_io_plugin_w32,
				pathname, rw, mode, w32);
		free(w32);
	}
	return NULL;
}

static char *w32__system(RzIO *io, RzIODesc *fd, const char *cmd) {
	if (io && fd && fd->data && cmd && !strcmp(cmd, "winbase")) {
		RzIOW32 *w32 = (RzIOW32 *)fd->data;
		io->cb_printf("%" PFMT64u, w32->winbase);
	}
	return NULL;
}

RzIOPlugin rz_io_plugin_w32 = {
	.name = "w32",
	.desc = "w32 API io",
	.license = "LGPL3",
	.uris = "w32://",
	.open = w32__open,
	.close = w32__close,
	.read = w32__read,
	.check = w32__plugin_open,
	.lseek = w32__lseek,
	.system = w32__system,
	.write = w32__write,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_w32,
	.version = RZ_VERSION
};
#endif

#else
struct rz_io_plugin_t rz_io_plugin_w32 = {
	.name = (void *)0
};

#endif
