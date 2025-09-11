// SPDX-FileCopyrightText: 2008-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_io.h>

#include "rz_io_plugins.h"

#if __WINDOWS__
#include <rz_windows.h>
#include <rz_core.h>
#include <w32dbg_wrap.h>

static ut64 __find_next_valid_addr(HANDLE h, ut64 from, ut64 to) {
	// Align to next page and try to get to next valid addr
	const int page_size = 0x1000;
	from = ((from + page_size) / page_size) * page_size;
	ut8 buf;
	while (from < to && !ReadProcessMemory(h, (void *)from, &buf, 1, NULL)) {
		from += page_size;
	}
	return from < to ? from : UT64_MAX;
}

static int debug_os_read_at(W32DbgWInst *dbg, ut8 *buf, size_t len, ut64 addr) {
	SIZE_T ret = 0;
	if (!ReadProcessMemory(dbg->pi.hProcess, (void *)(size_t)addr, buf, len, &ret) && GetLastError() == ERROR_PARTIAL_COPY) {
		int skipped = 0;
		if (!ReadProcessMemory(dbg->pi.hProcess, (void *)(size_t)addr, buf, 1, &ret)) {
			// We are starting a read from invalid memory
			ut64 valid_addr = __find_next_valid_addr(dbg->pi.hProcess, addr, addr + len);
			if (valid_addr == UT64_MAX) {
				return len;
			}
			skipped = valid_addr - addr;
			memset(buf, '\xff', skipped);
			addr = valid_addr;
			buf += skipped;
		}
		// We are in a valid page now, try to read again
		int read_len = len - skipped;
		int totRead = skipped;
		while (totRead < len) {
			while (!ReadProcessMemory(dbg->pi.hProcess, (void *)(size_t)addr, buf, read_len, &ret)) {
				// Maybe read_len is too big, we are reaching invalid memory
				read_len /= 2;
				if (!read_len) {
					// Reached the end of valid memory, find another to continue reading if possible
					ut64 valid_addr = __find_next_valid_addr(dbg->pi.hProcess, addr, addr + len - totRead);
					if (valid_addr == UT64_MAX) {
						return len;
					}
					skipped = valid_addr - addr;
					addr = valid_addr;
					memset(buf, '\xff', skipped);
					buf += skipped;
					totRead += skipped;
					read_len = len - totRead;
				}
			}
			buf += ret;
			addr += ret;
			totRead += ret;
			read_len = RZ_MIN(read_len, len - totRead);
		}
	}
	return len;
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, size_t len) {
	return debug_os_read_at(fd->data, buf, len, io->off);
}

static int w32dbg_write_at(W32DbgWInst *dbg, const ut8 *buf, size_t len, ut64 addr) {
	SIZE_T ret;
	return 0 != WriteProcessMemory(dbg->pi.hProcess, (void *)(size_t)addr, buf, len, &ret) ? len : 0;
}

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, size_t len) {
	return w32dbg_write_at(fd->data, buf, len, io->off);
}

static bool __plugin_open(RzIO *io, const char *file, bool many) {
	if (!strncmp(file, "attach://", 9)) {
		return true;
	}
	return !strncmp(file, "w32dbg://", 9);
}

static inline bool current_handle_valid(W32DbgWInst *wrap, int pid) {
	return wrap->pi.dwProcessId == pid && wrap->pi.hProcess != INVALID_HANDLE_VALUE;
}

static int __open_proc(RzIO *io, int pid, bool attach) {
	W32DbgWInst *wrap = (W32DbgWInst *)rz_io_get_w32dbg_wrap(io);
	if (!wrap) {
		return -1;
	}
	if (current_handle_valid(wrap, pid)) {
		if (!attach) {
			return pid;
		}
		// We will get a new handle when we attach
		CloseHandle(wrap->pi.hProcess);
	}

	if (attach) {
		RzCore *core = io->corebind.core;
		core->dbg->plugin_data = wrap;
		/* Attach to the process */
		return core->dbg->cur->attach(core->dbg, pid);
	}

	HANDLE h_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!h_proc) {
		rz_sys_perror("OpenProcess");
		return -1;
	}
	wrap->pi.dwProcessId = pid;
	wrap->pi.hProcess = h_proc;
	return pid;
}

static RzIODesc *__open(RzIO *io, const char *file, int rw, int mode) {
	if (__plugin_open(io, file, 0)) {
		RzIODesc *ret;
		W32DbgWInst *wrap = (W32DbgWInst *)rz_io_get_w32dbg_wrap(io);
		if (!wrap) {
			return NULL;
		}
		if (__open_proc(io, atoi(file + 9), !strncmp(file, "attach://", 9)) == -1) {
			return NULL;
		}
		ret = rz_io_desc_new(io, &rz_io_plugin_w32dbg,
			file, rw | RZ_PERM_X, wrap);
		ret->name = rz_sys_pid_to_path(wrap->pi.dwProcessId);
		return ret;
	}
	return NULL;
}

static ut64 __lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case RZ_IO_SEEK_SET:
		io->off = offset;
		break;
	case RZ_IO_SEEK_CUR:
		io->off += (st64)offset;
		break;
	case RZ_IO_SEEK_END:
		io->off = UT64_MAX;
		break;
	}
	return io->off;
}

static int __close(RzIODesc *fd) {
	if (rz_str_startswith(fd->uri, "attach://")) {
		W32DbgWInst *wrap = fd->data;
		wrap->params.type = W32_DETACH;
		w32dbg_wrap_wait_ret(wrap);
	}
	return false;
}

static char *__system(RzIO *io, RzIODesc *fd, const char *cmd) {
	W32DbgWInst *wrap = fd->data;
	if (!strcmp(cmd, "")) {
		// do nothing
	} else if (!strncmp(cmd, "pid", 3)) {
		return rz_str_newf("%lu", wrap->pi.dwProcessId);
	} else {
		eprintf("Try: 'R!pid'\n");
	}
	return NULL;
}

static int __getpid(RzIODesc *fd) {
	W32DbgWInst *wrap = (W32DbgWInst *)(fd ? fd->data : NULL);
	if (!wrap) {
		return -1;
	}
	return wrap->pi.dwProcessId;
}

static int __gettid(RzIODesc *fd) {
	W32DbgWInst *wrap = (W32DbgWInst *)(fd ? fd->data : NULL);
	return wrap ? wrap->pi.dwThreadId : -1;
}

static bool __getbase(RzIODesc *fd, ut64 *base) {
	W32DbgWInst *wrap = (W32DbgWInst *)(fd ? fd->data : NULL);
	if (base && wrap) {
		*base = wrap->winbase;
		return true;
	}
	return false;
}

RzIOPlugin rz_io_plugin_w32dbg = {
	.name = "w32dbg",
	.desc = "w32 debugger io plugin",
	.license = "LGPL3",
	.uris = "w32dbg://,attach://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.write = __write,
	.getpid = __getpid,
	.gettid = __gettid,
	.getbase = __getbase,
	.isdbg = true
};
#else
RzIOPlugin rz_io_plugin_w32dbg = {
	.name = NULL
};
#endif

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_w32dbg,
	.version = RZ_VERSION
};
#endif
