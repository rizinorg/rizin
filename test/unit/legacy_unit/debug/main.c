// SPDX-FileCopyrightText: 2009-2010 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_debug.h>
#include <rz_io.h>

int main(int argc, char **argv) {
	int ret, i;
	RzIODesc *fd;
	int tid, pid;
	struct rz_io_t *io;
	struct rz_debug_t *dbg = NULL;

	io = rz_io_new();
	printf("Supported IO pluggins:\n");
	rz_io_plugin_list(io);

	fd = rz_io_open_nomap(io, "dbg:///bin/ls", 0, 0);
	if (!fd) {
		printf("Cannot open dbg:///bin/ls\n");
		goto beach;
	}
	//	rz_io_set_fd(io, ret);
	printf("rz_io_open_nomap dbg:///bin/ls' = %d\n", io->fd->fd);

	{
		/* dump process memory */
		ut8 buf[128];
#if __arm__
		int ret = rz_io_read_at(io, 0x8000, buf, 128);
#else
		int ret = rz_io_read_at(io, 0x8048000, buf, 128);
#endif
		if (ret != 128)
			eprintf("OOps cannot read 128 bytes\n");
		else
			for (i = 0; i < 128; i++) {
				printf("%02x ", buf[i]);
				if (!((i + 1) % 16))
					printf("\n");
			}
	}

	dbg = rz_debug_new(true);
	printf("Supported debugger backends:\n");

	ret = rz_debug_use(dbg, "native");
	printf("Using native debugger = %s\n", rz_str_bool(ret));

	tid = pid = rz_io_system(io, "pid");
	eprintf(" My pid is : %d\n", pid);
	rz_debug_select(dbg, pid, tid);

	//printf("--> regs pre step\n");
	//rz_io_system(io, "reg");

	rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, 0);
	rz_debug_reg_list(dbg, RZ_REG_TYPE_GPR, 32, NULL);

	printf("--> perform 2 steps (only 1 probably?)\n");
	rz_debug_step(dbg, 2);

	rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, 0);
	rz_debug_reg_list(dbg, RZ_REG_TYPE_GPR, 32, NULL);

	//printf("--> regs post step\n");
	//rz_io_system(io, "reg");

	printf("---\n");
	rz_debug_continue(dbg);
	printf("---\n");

beach:
	rz_io_free(io);
	rz_debug_free(dbg);
	return 0;
}
