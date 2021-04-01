// SPDX-FileCopyrightText: 2010-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_userconf.h>

#include <rz_io.h>
#include <rz_lib.h>
#include <rz_cons.h>

#if __linux__

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

typedef struct {
	int fd;
	int pid;
} RzIOProcpid;

#define RzIOPROCPID_PID(x) (((RzIOProcpid *)(x)->data)->pid)
#define RzIOPROCPID_FD(x)  (((RzIOProcpid *)(x)->data)->fd)

static int __waitpid(int pid) {
	int st = 0;
	return (waitpid(pid, &st, 0) != -1);
}

static int debug_os_read_at(int fdn, void *buf, int sz, ut64 addr) {
	if (lseek(fdn, addr, 0) < 0) {
		return -1;
	}
	return read(fdn, buf, sz);
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, int len) {
	memset(buf, 0xff, len); // TODO: only memset the non-readed bytes
	return debug_os_read_at(RzIOPROCPID_FD(fd), buf, len, io->off);
}

static int procpid_write_at(int fd, const ut8 *buf, int sz, ut64 addr) {
	if (lseek(fd, addr, 0) < 0) {
		return -1;
	}
	return write(fd, buf, sz);
}

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int len) {
	return procpid_write_at(RzIOPROCPID_FD(fd), buf, len, io->off);
}

static bool __plugin_open(RzIO *io, const char *file, bool many) {
	return (!strncmp(file, "procpid://", 10));
}

static RzIODesc *__open(RzIO *io, const char *file, int rw, int mode) {
	char procpidpath[64];
	int fd;
	if (__plugin_open(io, file, 0)) {
		int pid = atoi(file + 10);
		if (file[0] == 'a') {
			int ret = ptrace(PTRACE_ATTACH, pid, 0, 0);
			if (ret == -1) {
				switch (errno) {
				case EPERM:
					eprintf("Operation not permitted\n");
					break;
				case EINVAL:
					perror("ptrace: Cannot attach");
					eprintf("ERRNO: %d (EINVAL)\n", errno);
					break;
				}
			} else if (!__waitpid(pid)) {
				eprintf("Error in waitpid\n");
			}
		}
		snprintf(procpidpath, sizeof(procpidpath), "/proc/%d/mem", pid);
		fd = rz_sys_open(procpidpath, O_RDWR, 0);
		if (fd != -1) {
			RzIOProcpid *riop = RZ_NEW0(RzIOProcpid);
			if (!riop) {
				close(fd);
				return NULL;
			}
			riop->pid = pid;
			riop->fd = fd;
			RzIODesc *d = rz_io_desc_new(io, &rz_io_plugin_procpid, file, true, 0, riop);
			d->name = rz_sys_pid_to_path(riop->pid);
			return d;
		}
		/* kill children */
		eprintf("Cannot open /proc/%d/mem of already attached process\n", pid);
		(void)ptrace(PTRACE_DETACH, pid, 0, 0);
	}
	return NULL;
}

static ut64 __lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	return offset;
}

static int __close(RzIODesc *fd) {
	int ret = ptrace(PTRACE_DETACH, RzIOPROCPID_PID(fd), 0, 0);
	RZ_FREE(fd->data);
	return ret;
}

static char *__system(RzIO *io, RzIODesc *fd, const char *cmd) {
	RzIOProcpid *iop = (RzIOProcpid *)fd->data;
	if (!strncmp(cmd, "pid", 3)) {
		int pid = atoi(cmd + 3);
		if (pid > 0) {
			iop->pid = pid;
		}
		io->cb_printf("%d\n", iop->pid);
	} else {
		eprintf("Try: '=!pid'\n");
	}
	return NULL;
}

RzIOPlugin rz_io_plugin_procpid = {
	.name = "procpid",
	.desc = "Open /proc/[pid]/mem io",
	.license = "LGPL3",
	.uris = "procpid://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.write = __write,
};

#else
RzIOPlugin rz_io_plugin_procpid = {
	.name = NULL
};
#endif

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_procpid,
	.version = RZ_VERSION
};
#endif
