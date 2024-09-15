// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file io_bochs.c
 * Spawns a bochs session with the given configuration file.
 *
 * Website: https://bochs.sourceforge.io/
 *
 * Bochs is a highly portable open source IA-32 (x86) PC emulator written in C++,
 * that runs on most popular platforms.
 * It includes emulation of the Intel x86 CPU, common I/O devices, and a custom BIOS.
 *
 * This plugin spawns via rz_subprocess the bochs binary and provides methods
 * to read and write the memory of the debugger/emulator.
 *
 * Bochs always spawns a GUI which emulates the framebuffer and the terminal
 * allows to input commands.
 *
 * This IO plugins uses the following commands to read and write the memory of the emulator:
 *
 * - `setpmem <addr> <word len> <value>` is used to write at a given address a word/half/byte
 *   to avoid endianness problems, the io plugins write 1 byte per command
 *
 * - `xp /<n bytes>mb <addr>` is used to dump memory at a given address; it outputs bytes
 *   which are then parsed and written into a ut8 buffer.
 *
 * The emulator does not allow to seek at an address therefore the lseek method always
 * returns whatever offset the user requests and outputs `UT32_MAX + offset` when RZ_IO_SEEK_END
 * is used.
 */

#include <rz_io.h>
#include <rz_lib.h>
#include <rz_util.h>

#include "rz_io_plugins.h"

#define BOCHS_URI_PREFIX "bochs://"
#define BOCHS_URI_SIZE   strlen(BOCHS_URI_PREFIX)
#define BOCHS_STDIN_SIZE 256

extern RzIOPlugin rz_io_plugin_bochs;

static void io_bochs_uri_usage(void) {
	RZ_LOG_ERROR("io: bochs: Expected 'bochs://<path to bochs bin>#<path to bochs rc file>\n");
	RZ_LOG_ERROR("io: bochs: Usage example: 'rizin bochs:///bin/bochs#/path/to/bochsrc\n");
}

static bool io_bochs_is_uri(RzIO *io, const char *file, bool many) {
	return !strncmp(file, BOCHS_URI_PREFIX, BOCHS_URI_SIZE);
}

static void io_bochs_wait_till_prompt(RzSubprocess *bochs) {
	RzStrBuf *sb = NULL;
	while ((sb = rz_subprocess_stdout_readline(bochs, 5))) {
		const char *line = rz_strbuf_get(sb);
		if (strstr(line, "<bochs:")) {
			break;
		}
	}
}

static char *io_bochs_send_command(RzSubprocess *bochs, bool wait_output, const char *format, ...) {
	char command[BOCHS_STDIN_SIZE] = { 0 };
	va_list args;

	va_start(args, format);
	vsnprintf(command, BOCHS_STDIN_SIZE, format, args);
	va_end(args);

	// send command
	rz_subprocess_stdin_write(bochs, (ut8 *)command, strlen(command));

	if (!wait_output) {
		io_bochs_wait_till_prompt(bochs);
		return NULL;
	}
	// wait for output

	RzStrBuf *output = rz_strbuf_new("");
	if (!output) {
		return NULL;
	}

	RzStrBuf *sb = NULL;
	while ((sb = rz_subprocess_stdout_readline(bochs, 10))) {
		const char *line = rz_strbuf_get(sb);
		if (strstr(line, "<bochs:")) {
			break;
		}
		rz_strbuf_append_n(output, line, sb->len);
	}

	return rz_strbuf_drain(output);
}

static RzIODesc *io_bochs_open(RzIO *io, const char *file, int rw, int mode) {
	if (!io_bochs_is_uri(io, file, 0)) {
		return NULL;
	} else if (RZ_STR_ISEMPTY(file + BOCHS_URI_SIZE)) {
		io_bochs_uri_usage();
		return NULL;
	}

	const char *hashtag = strchr(file + BOCHS_URI_SIZE, '#');
	if (!hashtag) {
		io_bochs_uri_usage();
		return NULL;
	}

	size_t bin_path_length = hashtag - file - BOCHS_URI_SIZE;
	RzSubprocess *bochs = NULL;
	char *bochs_bin_path = rz_str_ndup(file + BOCHS_URI_SIZE, bin_path_length);
	char *bochs_cfg_path = rz_str_dup(hashtag + 1);

	const char *args[3] = {
		"-f",
		bochs_cfg_path,
		"-q",
	};

	RzSubprocessOpt opt = {
		.file = bochs_bin_path,
		.args = (const char **)args,
		.args_size = 3,
		.envvars = NULL,
		.envvals = NULL,
		.env_size = 0,
		.stdin_pipe = RZ_SUBPROCESS_PIPE_CREATE,
		.stdout_pipe = RZ_SUBPROCESS_PIPE_CREATE,
		.stderr_pipe = RZ_SUBPROCESS_PIPE_STDOUT,
	};
	rz_subprocess_init();

	bochs = rz_subprocess_start_opt(&opt);
	if (!bochs) {
		RZ_LOG_ERROR("io: bochs: Failed to spawn program '%s'.\n", bochs_bin_path);
		goto fail;
	}

	RzStrBuf *sb = NULL;

	while ((sb = rz_subprocess_stdout_readline(bochs, 5))) {
		const char *output = rz_strbuf_get(sb);
		if (strstr(output, "<bochs:")) {
			break;
		}
		eprintf("%s", output);
	}

	RzIODesc *iodesc = rz_io_desc_new(io, &rz_io_plugin_bochs, file, rw, mode, bochs);
	if (!iodesc) {
		RZ_LOG_ERROR("io: bochs: Failed create RzIODesc.\n");
		goto fail;
	}
	free(bochs_bin_path);
	free(bochs_cfg_path);
	return iodesc;

fail:
	rz_subprocess_free(bochs);
	rz_subprocess_fini();
	free(bochs_bin_path);
	free(bochs_cfg_path);
	return NULL;
}

static int io_bochs_no_write(RzIO *io, RzIODesc *fd, const ut8 *buf, size_t count) {
	if (!fd || !fd->data || count < 0) {
		return -1;
	}

	RzSubprocess *bochs = fd->data;

	ut64 address = io->off;
	for (int i = 0; i < count; ++i) {
		io_bochs_send_command(bochs, false, "setpmem 0x%" PFMT64x " 1 0x%02x\n", address, buf[i]);
		address += i;
	}
	// ensure the output buffer is alywas empty
	free(rz_subprocess_out(bochs, NULL));
	return count;
}

static ut64 io_bochs_no_lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	// bochs does not need to seek at address.

	switch (whence) {
	case RZ_IO_SEEK_END:
		return offset + UT32_MAX;
	case RZ_IO_SEEK_CUR:
	case RZ_IO_SEEK_SET:
	default:
		return offset;
	}
}

static bool io_bochs_read_memory(RzSubprocess *bochs, ut64 address, ut8 *buf, size_t count) {
	char *raw = io_bochs_send_command(bochs, true, "xp /%dmb 0x%" PFMT64x "\n", (int)count, address);

	char *output = raw ? strstr(raw, "[bochs]:") : NULL;
	if (!output) {
		free(raw);
		RZ_LOG_ERROR("io: bochs: Failed to read memory at 0x%" PFMT64x ".\n", address);
		return false;
	}

	char *newline = NULL;
	char *begin = output + 7;
	ut8 *cur = buf;
	while ((begin = strchr(begin + 1, ':'))) {
		if ((newline = strchr(begin, '\n'))) {
			*newline = 0;
		}
		cur += rz_hex_str2bin(begin + 1, cur);
		if (newline) {
			*newline = '\n';
		}
	}
	size_t written = cur - buf;
	free(raw);
	return written == count;
}

static int io_bochs_read(RzIO *io, RzIODesc *fd, ut8 *buf, size_t count) {
	if (!fd || !fd->data || count < 0) {
		return -1;
	}
	memset(buf, 0xff, count);

	RzSubprocess *bochs = fd->data;
	ut64 address = io->off;
	int copied = 0;
	for (copied = 0; copied < count;) {
		size_t increase = RZ_MIN(512, count - copied);
		if (!io_bochs_read_memory(bochs, address + copied, buf + copied, increase)) {
			break;
		}
		copied += increase;
	}
	return copied;
}

static int io_bochs_close(RzIODesc *fd) {
	RzSubprocess *bochs = fd->data;
	rz_subprocess_free(bochs);
	rz_subprocess_fini();
	return true;
}

static char *io_bochs_command(RzIO *io, RzIODesc *fd, const char *cmd) {
	if (!strncmp(cmd, "pid ", strlen("pid "))) {
		return NULL;
	}

	RzSubprocess *bochs = fd->data;
	char *output = io_bochs_send_command(bochs, true, "%s\n", cmd);
	if (!output) {
		RZ_LOG_ERROR("io: bochs: Failed to send command '%s'.\n", cmd);
		return NULL;
	}

	io->cb_printf("%s\n", output);
	free(output);
	return NULL;
}

RzIOPlugin rz_io_plugin_bochs = {
	.name = "bochs",
	.desc = "Attach to a BOCHS debugger instance",
	.license = "LGPL3",
	.uris = "bochs://",
	.open = io_bochs_open,
	.close = io_bochs_close,
	.read = io_bochs_read,
	.write = io_bochs_no_write,
	.check = io_bochs_is_uri,
	.lseek = io_bochs_no_lseek,
	.system = io_bochs_command,
	.isdbg = true
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_bochs,
	.version = RZ_VERSION
};
#endif
