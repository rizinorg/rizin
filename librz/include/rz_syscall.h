// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_SYSCALL_H
#define RZ_SYSCALL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <rz_types.h>
#include <rz_util.h>
#include <sdb.h>

RZ_LIB_VERSION_HEADER(rz_syscall);

#define RZ_SYSCALL_ARGS 7

typedef struct rz_syscall_item_t {
	char *name;
	int swi;
	int num;
	int args;
	char *sargs;
} RzSyscallItem;

typedef struct rz_syscall_port_t {
	int port;
	const char *name;
} RzSyscallPort;

typedef struct rz_syscall_t {
	FILE *fd;
	// memoization
	char *arch;
	char *os;
	int bits;
	char *cpu;
	// database
	RzSyscallItem *sysptr;
	RzSyscallPort *sysport;
	Sdb *db;
	Sdb *srdb;
	int refs;
} RzSyscall;

#if 0
// todo: add the ability to describe particular bits
typedef struct rz_sysregs_item_t {
	ut64 address;
	ut64 size;
	int type;
	const char *name;
	const char *description;
} RSysregsItem;

typedef struct rz_sysregs_t {
	FILE *fd;
	char *arch;
	char *cpu;
	RSysregsItem *sysregs;
	Sdb *db;
} RSysregs;
#endif

/* plugin struct */
typedef struct rz_syscall_plugin_t {
	char *name;
	char *arch;
	char *os;
	char *desc;
	int bits;
	int nargs;
	struct rz_syscall_args_t *args;
} RzSyscallPlugin;

typedef struct rz_syscall_arch_plugin_t {
	char *name;
	char *arch;
	char *desc;
	int *bits;
	int nargs;
	struct rz_syscall_args_t **args;
} RzSyscallArchPlugin;

#ifdef RZ_API
RZ_API RzSyscallItem *rz_syscall_item_new_from_string(const char *name, const char *s);
RZ_API void rz_syscall_item_free(RzSyscallItem *si);

RZ_API RzSyscall *rz_syscall_new(void);
RZ_API void rz_syscall_free(RzSyscall *ctx);
RZ_API RzSyscall *rz_syscall_ref(RzSyscall *sc);
RZ_API bool rz_syscall_setup(RzSyscall *s, const char *arch, int bits, const char *cpu, const char *os);
RZ_API RzSyscallItem *rz_syscall_get(RzSyscall *ctx, int num, int swi);
RZ_API int rz_syscall_get_num(RzSyscall *ctx, const char *str);
RZ_API const char *rz_syscall_get_i(RzSyscall *ctx, int num, int swi);
RZ_API const char *rz_syscall_sysreg(RzSyscall *s, const char *type, ut64 num);
RZ_API RzList *rz_syscall_list(RzSyscall *ctx);
RZ_API int rz_syscall_get_swi(RzSyscall *s);

/* io */
RZ_API const char *rz_syscall_get_io(RzSyscall *s, int ioport);
#endif

#ifdef __cplusplus
}
#endif

#endif
