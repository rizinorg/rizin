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

#if __WINDOWS__
#define MAIN_NAME                       wmain
#define ARGV_TYPE                       wchar_t
#define ARGV_TYPE_TO_UTF8(argc, argv)   rz_sys_utf8_argv_new(argc, argv)
#define FREE_UTF8_ARGV(argc, utf8_argv) rz_sys_utf8_argv_free(argc, utf8_argv)
#else
#define MAIN_NAME                     main
#define ARGV_TYPE                     char
#define ARGV_TYPE_TO_UTF8(argc, argv) (char **)argv
#define FREE_UTF8_ARGV(argc, utf8_argv)
#endif

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
