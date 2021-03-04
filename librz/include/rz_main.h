// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_MAIN_H
#define RZ_MAIN_H

#include <rz_types.h>
#include <rz_getopt.h>

RZ_LIB_VERSION_HEADER(rz_main);

typedef struct rz_main_t {
	const char *name;
	int (*main)(int argc, const char **argv);
	// stdin/stdout
} RzMain;

typedef int (*RzMainCallback)(int argc, const char **argv);

RZ_API RzMain *rz_main_new(const char *name);
RZ_API void rz_main_free(RzMain *m);
RZ_API int rz_main_run(RzMain *m, int argc, const char **argv);

RZ_API int rz_main_version_print(const char *program);
RZ_API int rz_main_rz_ax(int argc, const char **argv);
RZ_API int rz_main_rz_run(int argc, const char **argv);
RZ_API int rz_main_rz_hash(int argc, const char **argv);
RZ_API int rz_main_rz_bin(int argc, const char **argv);
RZ_API int rz_main_rizin(int argc, const char **argv);
RZ_API int rz_main_rz_asm(int argc, const char **argv);
RZ_API int rz_main_rz_agent(int argc, const char **argv);
RZ_API int rz_main_rz_find(int argc, const char **argv);
RZ_API int rz_main_rz_diff(int argc, const char **argv);
RZ_API int rz_main_rz_gg(int argc, const char **argv);
RZ_API int rz_main_rz_sign(int argc, const char **argv);

#endif
