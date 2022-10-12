// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_MAIN_H
#define RZ_MAIN_H

#include <rz_types.h>
#include <rz_getopt.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_main);

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

RZ_API RzMainCallback rz_main_find(const char *name);
RZ_API int rz_main_version_print(const char *program);
RZ_API int rz_main_rz_ax(int argc, const char **argv);
RZ_API int rz_main_rz_run(int argc, const char **argv);
RZ_API int rz_main_rz_hash(int argc, const char **argv);
RZ_API int rz_main_rz_bin(int argc, const char **argv);
RZ_API int rz_main_rizin(int argc, const char **argv);
RZ_API int rz_main_rz_asm(int argc, const char **argv);
RZ_API int rz_main_rz_find(int argc, const char **argv);
RZ_API int rz_main_rz_diff(int argc, const char **argv);
RZ_API int rz_main_rz_gg(int argc, const char **argv);
RZ_API int rz_main_rz_sign(int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif
