// SPDX-FileCopyrightText: 2016-2017 SkUaTeR <skuater@hotmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <libbochs.h>

typedef struct {
	libbochs_t desc;
} RzIOBochs;

static libbochs_t *desc = NULL;
static RzIODesc *riobochs = NULL;
extern RzIOPlugin rz_io_plugin_bochs; // forward declaration

static bool __plugin_open(RzIO *io, const char *file, bool many) {
	return !strncmp(file, "bochs://", strlen("bochs://"));
}

static RzIODesc *__open(RzIO *io, const char *file, int rw, int mode) {
	RzIOBochs *riob;
	lprintf("io_open\n");
	const char *i;
	char *fileBochs = NULL;
	char *fileCfg = NULL;
	int l;
	if (!__plugin_open(io, file, 0)) {
		return NULL;
	}
	if (riobochs) {
		return riobochs;
	}

	i = strchr(file + 8, '#');
	if (i) {
		l = i - file - 8;
		fileBochs = rz_str_ndup(file + 8, l);
		fileCfg = strdup(i + 1);
	} else {
		free(fileCfg);
		eprintf("Error can't find :\n");
		return NULL;
	}
	riob = RZ_NEW0(RzIOBochs);

	// Inicializamos
	if (bochs_open(&riob->desc, fileBochs, fileCfg) == true) {
		desc = &riob->desc;
		riobochs = rz_io_desc_new(io, &rz_io_plugin_bochs, file, rw, mode, riob);
		//riogdb = rz_io_desc_new (&rz_io_plugin_gdb, riog->desc.sock->fd, file, rw, mode, riog);
		free(fileBochs);
		free(fileCfg);
		return riobochs;
	}
	lprintf("bochsio.open: Cannot connect to bochs.\n");
	free(riob);
	free(fileBochs);
	free(fileCfg);
	return NULL;
}

static int __write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count) {
	lprintf("io_write\n");
	return -1;
}

static ut64 __lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence) {
	lprintf("io_seek %016" PFMT64x " \n", offset);
	return offset;
}

static int __read(RzIO *io, RzIODesc *fd, ut8 *buf, int count) {
	memset(buf, 0xff, count);
	ut64 addr = io->off;
	if (!desc || !desc->data) {
		return -1;
	}
	lprintf("io_read ofs= %016" PFMT64x " count= %x\n", io->off, count);
	bochs_read(desc, addr, count, buf);
	return count;
}

static int __close(RzIODesc *fd) {
	lprintf("io_close\n");
	bochs_close(desc);
	return true;
}

static char *__system(RzIO *io, RzIODesc *fd, const char *cmd) {
	lprintf("system command (%s)\n", cmd);
	if (!strcmp(cmd, "help")) {
		lprintf("Usage: =!cmd args\n"
			" =!:<bochscmd>      - Send a bochs command.\n"
			" =!dobreak          - pause bochs.\n");
		lprintf("io_system: Enviando commando bochs\n");
		bochs_send_cmd(desc, &cmd[1], true);
		io->cb_printf("%s\n", desc->data);
	} else if (!strncmp(cmd, "dobreak", 7)) {
		bochs_cmd_stop(desc);
		io->cb_printf("%s\n", desc->data);
	}
	return NULL;
}

RzIOPlugin rz_io_plugin_bochs = {
	.name = "bochs",
	.desc = "Attach to a BOCHS debugger instance",
	.license = "LGPL3",
	.uris = "bochs://",
	.open = __open,
	.close = __close,
	.read = __read,
	.write = __write,
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.isdbg = true
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_IO,
	.data = &rz_io_plugin_bochs,
	.version = RZ_VERSION
};
#endif
