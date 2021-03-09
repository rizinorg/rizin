// SPDX-FileCopyrightText: 2008-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_userconf.h>
#include <rz_util.h>
#include <rz_io.h>
#include <rz_lib.h>
#include <rz_cons.h>
#include <rz_debug.h>

#if DEBUGGER && (__linux__ || __BSD__)

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

typedef struct {
	int pid;
	int tid;
	int fd;
	int opid;
} RzIOPtrace;
#define RzIOPTRACE_OPID(x) (((RzIOPtrace *)(x)->data)->opid)
#define RzIOPTRACE_PID(x)  (((RzIOPtrace *)(x)->data)->pid)
#define RzIOPTRACE_FD(x)   (((RzIOPtrace *)(x)->data)->fd)
static void open_pidmem(RzIOPtrace *iop);

#undef RZ_IO_NFDS
#define RZ_IO_NFDS 2
#ifndef __ANDROID__
extern int errno;
#endif

// PTRACE_GETSIGINFO is defined only since glibc 2.4 but appeared much
// earlier in linux kernel - since 2.3.99-pre6
// So we define it manually
#if __linux__ && defined(__GLIBC__)
#ifndef PTRACE_GETSIGINFO
#define PTRACE_GETSIGINFO 0x4202
#endif
#endif

#if 0
procpidmem is buggy.. running this sometimes results in ffff

	while : ; do rizin -qc 'oo;x' -d ls ; done
#endif
#define USE_PROC_PID_MEM 0

static int __waitpid(int pid) {
	int st = 0;
	return (waitpid(pid, &st, 0) != -1);
}

#define debug_read_raw(io, x, y)     rz_io_ptrace((io), PTRACE_PEEKTEXT, (x), (void *)(y), RZ_PTRACE_NODATA)
#define debug_write_raw(io, x, y, z) rz_io_ptrace((io), PTRACE_POKEDATA, (x), (void *)(y), (rz_ptrace_data_t)(z))
#if __OpenBSD__ || __NetBSD__ || __KFBSD__
typedef int ptrace_word; // int ptrace(int request, pid_t pid, caddr_t addr, int data);
#else
typedef size_t ptrace_word; // long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
// XXX. using int read fails on some addresses
// XXX. using long here breaks 'w AAAABBBBCCCCDDDD' in rizin -d
#endif

static int debug_os_read_at(RzIO *io, int pid, ut32 *buf, int sz, ut64 addr) {
	ut32 words = sz / sizeof(ut32);
	ut32 last = sz % sizeof(ut32);
	ut32 x, lr, *at = (ut32 *)(size_t)addr;
	if (sz < 1 || addr == UT64_MAX) {
		return -1;
	}
	for (x = 0; x < words; x++) {
		buf[x] = (ut32)debug_read_raw(io, pid, (void *)(at++));
	}
	if (last) {
		lr = (ut32)debug_read_raw(io, pid, at);
		memcpy(buf + x, &lr, last);
	}
	return sz;
}

static int __read(RzIO *io, RzIODesc *desc, ut8 *buf, int len) {
#if USE_PROC_PID_MEM
	int ret, fd;
#endif
	ut64 addr = io->off;
	if (!desc || !desc->data) {
		return -1;
	}
	memset(buf, '\xff', len); // TODO: only memset the non-readed bytes
	/* reopen procpidmem if necessary */
#if USE_PROC_PID_MEM
	fd = RzIOPTRACE_FD(desc);
	if (RzIOPTRACE_PID(desc) != RzIOPTRACE_OPID(desc)) {
		if (fd != -1) {
			close(fd);
		}
		open_pidmem((RzIOPtrace *)desc->data);
		fd = RzIOPTRACE_FD(desc);
		RzIOPTRACE_OPID(desc) = RzIOPTRACE_PID(desc);
	}
	// /proc/pid/mem fails on latest linux
	if (fd != -1) {
		ret = lseek(fd, addr, SEEK_SET);
		if (ret >= 0) {
			// Workaround for the buggy Debian Wheeze's /proc/pid/mem
			if (read(fd, buf, len) != -1) {
				return ret;
			}
		}
	}
#endif
	ut32 *aligned_buf = (ut32 *)rz_malloc_aligned(len, sizeof(ut32));
	if (aligned_buf) {
		int res = debug_os_read_at(io, RzIOPTRACE_PID(desc), (ut32 *)aligned_buf, len, addr);
		memcpy(buf, aligned_buf, len);
		rz_free_aligned(aligned_buf);
		return res;
	}
	return -1;
}

static int ptrace_write_at(RzIO *io, int pid, const ut8 *pbuf, int sz, ut64 addr) {
	ptrace_word *buf = (ptrace_word *)pbuf;
	ut32 words = sz / sizeof(ptrace_word);
	ut32 last = sz % sizeof(ptrace_word);
	ptrace_word x, *at = (ptrace_word *)(size_t)addr;
	ptrace_word lr;
	if (sz < 1 || addr == UT64_MAX) {
		return -1;
	}
	for (x = 0; x < words; x++) {
		int rc = debug_write_raw(io, pid, at++, buf[x]); //((ut32*)(at)), buf[x]);
		if (rc) {
			return -1;
		}
	}
	if (last) {
		lr = debug_read_raw(io, pid, (void *)at);
		memcpy(&lr, buf + x, last);
		if (debug_write_raw(io, pid, (void *)at, lr)) {
			return sz - last;
		}
	}
	return sz;
}

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int len) {
	if (!fd || !fd->data) {
		return -1;
	}
	return ptrace_write_at(io, RzIOPTRACE_PID(fd), buf, len, io->off);
}

static void open_pidmem(RzIOPtrace *iop) {
#if USE_PROC_PID_MEM
	char pidmem[32];
	snprintf(pidmem, sizeof(pidmem), "/proc/%d/mem", iop->pid);
	iop->fd = open(pidmem, O_RDWR);
	if (iop->fd == -1) {
		iop->fd = open(pidmem, O_RDONLY);
	}
#if 0
	if (iop->fd == -1)
		eprintf ("Warning: Cannot open /proc/%d/mem. "
			"Fallback to ptrace io.\n", iop->pid);
#endif
#else
	iop->fd = -1;
#endif
}

static void close_pidmem(RzIOPtrace *iop) {
	if (iop->fd != -1) {
		close(iop->fd);
		iop->fd = -1;
	}
}

static bool __plugin_open(RzIO *io, const char *file, bool many) {
	if (!strncmp(file, "ptrace://", 9)) {
		return true;
	}
	if (!strncmp(file, "attach://", 9)) {
		return true;
	}
	return false;
}

static inline bool is_pid_already_attached(RzIO *io, int pid) {
#if defined(__linux__)
	siginfo_t sig = { 0 };
	return rz_io_ptrace(io, PTRACE_GETSIGINFO, pid, NULL, &sig) != -1;
#elif defined(__FreeBSD__)
	struct ptrace_lwpinfo info = { 0 };
	int len = (int)sizeof(info);
	return rz_io_ptrace(io, PT_LWPINFO, pid, &info, len) != -1;
#elif defined(__OpenBSD__) || defined(__NetBSD__)
	ptrace_state_t state = { 0 };
	int len = (int)sizeof(state);
	return rz_io_ptrace(io, PT_GET_PROCESS_STATE, pid, &state, len) != -1;
#else
	return false;
#endif
}

static RzIODesc *__open(RzIO *io, const char *file, int rw, int mode) {
	RzIODesc *desc = NULL;

	if (!__plugin_open(io, file, 0)) {
		return NULL;
	}

	int pid = atoi(file + 9);

	// Safely check if the PID has already been attached to avoid printing errors
	// and attempt attaching on failure
	if (!is_pid_already_attached(io, pid)) {
		int ret = rz_io_ptrace(io, PTRACE_ATTACH, pid, 0, 0);
		if (ret == -1) {
#ifdef __ANDROID__
			eprintf("ptrace_attach: Operation not permitted\n");
#else
			switch (errno) {
			case EPERM:
				eprintf("ptrace_attach: Operation not permitted\n");
				break;
			case EINVAL:
				perror("ptrace: Cannot attach");
				eprintf("ERRNO: %d (EINVAL)\n", errno);
				break;
			default:
				break;
			}
			return NULL;
#endif
		} else if (!__waitpid(pid)) {
			eprintf("Error in waitpid\n");
			return NULL;
		}
	}

	RzIOPtrace *riop = RZ_NEW0(RzIOPtrace);
	if (!riop) {
		return NULL;
	}

	riop->pid = riop->tid = pid;
	open_pidmem(riop);
	desc = rz_io_desc_new(io, &rz_io_plugin_ptrace, file, rw | RZ_PERM_X, mode, riop);
	desc->name = rz_sys_pid_to_path(pid);

	return desc;
}

static ut64 __lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case RZ_IO_SEEK_SET:
		io->off = offset;
		break;
	case RZ_IO_SEEK_CUR:
		io->off += offset;
		break;
	case RZ_IO_SEEK_END:
		io->off = ST64_MAX;
	}
	return io->off;
}

static int __close(RzIODesc *desc) {
	int pid, fd;
	if (!desc || !desc->data) {
		return -1;
	}
	pid = RzIOPTRACE_PID(desc);
	fd = RzIOPTRACE_FD(desc);
	if (fd != -1) {
		close(fd);
	}
	RzIOPtrace *riop = desc->data;
	desc->data = NULL;
	long ret = rz_io_ptrace(desc->io, PTRACE_DETACH, pid, 0, 0);
	if (errno == ESRCH) {
		// process does not exist, may have been killed earlier -- continue as normal
		ret = 0;
	}
	free(riop);
	return ret;
}

static char *__system(RzIO *io, RzIODesc *fd, const char *cmd) {
	RzIOPtrace *iop = (RzIOPtrace *)fd->data;
	//printf("ptrace io command (%s)\n", cmd);
	/* XXX ugly hack for testing purposes */
	if (!strcmp(cmd, "")) {
		return NULL;
	}
	if (!strcmp(cmd, "help")) {
		eprintf("Usage: =!cmd args\n"
			" =!ptrace   - use ptrace io\n"
			" =!mem      - use /proc/pid/mem io if possible\n"
			" =!pid      - show targeted pid\n"
			" =!pid <#>  - select new pid\n");
	} else if (!strcmp(cmd, "ptrace")) {
		close_pidmem(iop);
	} else if (!strcmp(cmd, "mem")) {
		open_pidmem(iop);
	} else if (!strncmp(cmd, "pid", 3)) {
		if (iop) {
			if (cmd[3] == ' ') {
				int pid = atoi(cmd + 4);
				if (pid > 0 && pid != iop->pid) {
					(void)rz_io_ptrace(io, PTRACE_ATTACH, pid, 0, 0);
					// TODO: do not set pid if attach fails?
					iop->pid = iop->tid = pid;
				}
			} else {
				io->cb_printf("%d\n", iop->pid);
			}
			return rz_str_newf("%d", iop->pid);
		}
	} else {
		eprintf("Try: '=!pid'\n");
	}
	return NULL;
}

static int __getpid(RzIODesc *fd) {
	RzIOPtrace *iop = (RzIOPtrace *)fd->data;
	if (!iop) {
		return -1;
	}
	return iop->pid;
}

// TODO: rename ptrace to io_ptrace .. err io.ptrace ??
RzIOPlugin rz_io_plugin_ptrace = {
	.name = "ptrace",
	.desc = "Ptrace and /proc/pid/mem (if available) io plugin",
	.license = "LGPL3",
	.uris = "ptrace://,attach://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.write = __write,
	.getpid = __getpid,
	.gettid = __getpid,
	.isdbg = true
};
#else
struct rz_io_plugin_t rz_io_plugin_ptrace = {
	.name = NULL
};
#endif

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_ptrace,
	.version = RZ_VERSION
};
#endif
