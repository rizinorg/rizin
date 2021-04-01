// SPDX-FileCopyrightText: 2011-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include <rz_debug.h>

static int __rap_step(RzDebug *dbg) {
	rz_io_system(dbg->iob.io, "ds");
	return true;
}

static int __rap_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	rz_io_system(dbg->iob.io, "dr");
	return 0;
}

static int __rap_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	return false; // XXX Error check
}

static int __rap_continue(RzDebug *dbg, int pid, int tid, int sig) {
	rz_io_system(dbg->iob.io, "dc");
	return true;
}

static int __rap_wait(RzDebug *dbg, int pid) {
	/* do nothing */
	return true;
}

static int __rap_attach(RzDebug *dbg, int pid) {
	// XXX TODO PID must be a socket here !!1
	RzIODesc *d = dbg->iob.io->desc;
	if (d && d->plugin && d->plugin->name) {
		if (!strcmp("rap", d->plugin->name)) {
			eprintf("SUCCESS: rap attach with inferior rap rio worked\n");
		} else {
			eprintf("ERROR: Underlying IO descriptor is not a rap one..\n");
		}
	}
	return true;
}

static int __rap_detach(RzDebug *dbg, int pid) {
	// XXX TODO PID must be a socket here !!1
	//	close (pid);
	//XXX Maybe we should continue here?
	return true;
}

static char *__rap_reg_profile(RzDebug *dbg) {
	char *out, *tf = rz_file_temp("rap.XXXXXX");
	int fd = rz_cons_pipe_open(tf, 1, 0);
	rz_io_system(dbg->iob.io, "drp");
	rz_cons_flush();
	rz_cons_pipe_close(fd);
	out = rz_file_slurp(tf, NULL);
	rz_file_rm(tf);
	free(tf);
	return out;
}

static int __rap_breakpoint(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
	//rz_io_system (dbg->iob.io, "db");
	return false;
}

RzDebugPlugin rz_debug_plugin_rap = {
	.name = "rap",
	.license = "LGPL3",
	.arch = "any",
	.bits = RZ_SYS_BITS_32,
	.step = __rap_step,
	.cont = __rap_continue,
	.attach = &__rap_attach,
	.detach = &__rap_detach,
	.wait = &__rap_wait,
	.breakpoint = __rap_breakpoint,
	.reg_read = &__rap_reg_read,
	.reg_write = &__rap_reg_write,
	.reg_profile = (void *)__rap_reg_profile,
	//.bp_write = &__rap_bp_write,
	//.bp_read = &__rap_bp_read,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_DBG,
	.data = &rz_debug_plugin_rap,
	.version = RZ_VERSION
};
#endif
