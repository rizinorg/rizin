// SPDX-FileCopyrightText: 2016-2018 SkUaTeR <skuater@hotmail.com>
// SPDX-FileCopyrightText: 2016-2018 panda
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_lib.h>
#include <rz_types.h>
#include <rz_util.h>
#include <sys/types.h>

#if __WINDOWS__
#include "io_rzk_windows.h"
#elif defined(__linux__) && !defined(__GNU__)
#include "io_rzk_linux.h"
struct io_rzk_linux rzk_struct; //TODO: move this into desc->data
#endif

int rzk__write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
#if __WINDOWS__
	//eprintf("writing to: 0x%"PFMT64x" len: %x\n",io->off, count);
	return WriteKernelMemory(io->off, buf, count);
#elif defined(__linux__) && !defined(__GNU__)
	switch (rzk_struct.beid) {
	case 0:
		return WriteMemory(io, fd, IOCTL_WRITE_KERNEL_MEMORY, rzk_struct.pid, io->off, buf, count);
	case 1:
		return WriteMemory(io, fd, IOCTL_WRITE_PROCESS_ADDR, rzk_struct.pid, io->off, buf, count);
	case 2:
		return WriteMemory(io, fd, IOCTL_WRITE_PHYSICAL_ADDR, rzk_struct.pid, io->off, buf, count);
	default:
		io->cb_printf("ERROR: Undefined beid in rzk__write.\n");
		return -1;
	}
#else
	io->cb_printf("TODO: rzk not implemented for this plataform.\n");
	return -1;
#endif
}

static int rzk__read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
#if __WINDOWS__
	return ReadKernelMemory(io->off, buf, count);
#elif defined(__linux__) && !defined(__GNU__)
	switch (rzk_struct.beid) {
	case 0:
		return ReadMemory(io, fd, IOCTL_READ_KERNEL_MEMORY, rzk_struct.pid, io->off, buf, count);
	case 1:
		return ReadMemory(io, fd, IOCTL_READ_PROCESS_ADDR, rzk_struct.pid, io->off, buf, count);
	case 2:
		return ReadMemory(io, fd, IOCTL_READ_PHYSICAL_ADDR, rzk_struct.pid, io->off, buf, count);
	default:
		io->cb_printf("ERROR: Undefined beid in rzk__read.\n");
		memset(buf, 0xff, count);
		return count;
	}
#else
	io->cb_printf("TODO: rzk not implemented for this plataform.\n");
	memset(buf, 0xff, count);
	return count;
#endif
}

static int rzk__close(RzIODesc *fd) {
#if __WINDOWS__
	if (gHandleDriver) {
		CloseHandle(gHandleDriver);
		StartStopService(TEXT("rzk"), TRUE);
	}
#elif defined(__linux__) && !defined(__GNU__)
	if (fd) {
		close((int)(size_t)fd->data);
	}
#else
	eprintf("TODO: rzk not implemented for this plataform.\n");
#endif
	return 0;
}

static ut64 rzk__lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	return (!whence) ? offset : whence == 1 ? io->off + offset
						: UT64_MAX;
}

static bool rzk__plugin_open(RzIO *io, const char *pathname, bool many) {
	return (!strncmp(pathname, "rzk://", 6));
}

static char *rzk__system(RzIO *io, RzIODesc *fd, const char *cmd) {
	if (!strcmp(cmd, "")) {
		return NULL;
	}
	if (!strncmp(cmd, "mod", 3)) {
#if __WINDOWS__
		GetSystemModules(io);
#endif
	} else {
#if defined(__linux__) && !defined(__GNU__)
		(void)run_ioctl_command(io, fd, cmd);
		return NULL;
#else
		eprintf("Try: '=!mod'\n    '.=!mod'\n");
#endif
	}
	return NULL;
}

static RzIODesc *rzk__open(RzIO *io, const char *pathname, int rw, int mode) {
	if (!strncmp(pathname, "rzk://", 6)) {
		rw |= RZ_PERM_WX;
#if __WINDOWS__
		RzIOW32 *w32 = RZ_NEW0(RzIOW32);
		if (Init(&pathname[6]) == FALSE) {
			eprintf("rzk__open: Error cant init driver: %s\n", &pathname[6]);
			free(w32);
			return NULL;
		}
		//return rz_io_desc_new (&rz_io_plugin_rzk, -1, pathname, rw, mode, w32);
		return rz_io_desc_new(io, &rz_io_plugin_rzk, pathname, rw, mode, w32);
#elif defined(__linux__) && !defined(__GNU__)
		int fd = open("/dev/rzk", O_RDONLY);
		if (fd == -1) {
			io->cb_printf("rzk__open: Error in opening /dev/rzk.");
			return NULL;
		}

		rzk_struct.beid = 0;
		rzk_struct.pid = 0;
		rzk_struct.wp = 1;
		return rz_io_desc_new(io, &rz_io_plugin_rzk, pathname, rw, mode, (void *)(size_t)fd);
#else
		io->cb_printf("Not supported on this platform\n");
#endif
	}
	return NULL;
}

RzIOPlugin rz_io_plugin_rzk = {
	.name = "rzk",
	.desc = "Kernel access API io",
	.uris = "rzk://",
	.license = "LGPL3",
	.open = rzk__open,
	.close = rzk__close,
	.read = rzk__read,
	.check = rzk__plugin_open,
	.lseek = rzk__lseek,
	.system = rzk__system,
	.write = rzk__write,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_rzk,
	.version = RZ_VERSION
};
#endif
