// SPDX-FileCopyrightText: 2015-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIND_H
#define RZ_BIND_H

// TODO: move riobind here too?
// TODO: move rprint here too

typedef int (*RzCoreCmd)(void *core, const char *cmd);
typedef int (*RzCoreCmdF)(void *user, const char *fmt, ...);
typedef int (*RzCoreDebugBpHit)(void *core, void *bp);
typedef void (*RzCoreDebugSyscallHit)(void *core);
typedef char *(*RzCoreCmdStr)(void *core, const char *cmd);
typedef char *(*RzCoreCmdStrF)(void *core, const char *cmd, ...);
typedef void (*RzCorePuts)(const char *cmd);
typedef void (*RzCoreSetArchBits)(void *core, const char *arch, int bits);
typedef bool (*RzCoreIsMapped)(void *core, ut64 addr, int perm);
typedef bool (*RzCoreDebugMapsSync)(void *core);
typedef const char *(*RzCoreGetName)(void *core, ut64 off);
typedef char *(*RzCoreGetNameDelta)(void *core, ut64 off);
typedef void (*RzCoreSeekArchBits)(void *core, ut64 addr);
typedef int (*RzCoreConfigGetI)(void *core, const char *key);
typedef const char *(*RzCoreConfigGet)(void *core, const char *key);
typedef ut64 (*RzCoreNumGet)(void *core, const char *str);
typedef void *(*RzCorePJWithEncoding)(void *core);

typedef struct rz_core_bind_t {
	void *core;
	RzCoreCmd cmd;
	RzCoreCmdF cmdf;
	RzCoreCmdStr cmdstr;
	RzCoreCmdStrF cmdstrf;
	RzCorePuts puts;
	RzCoreDebugBpHit bphit;
	RzCoreDebugSyscallHit syshit;
	RzCoreSetArchBits setab;
	RzCoreGetName getName;
	RzCoreGetNameDelta getNameDelta;
	RzCoreSeekArchBits archbits;
	RzCoreConfigGetI cfggeti;
	RzCoreConfigGet cfgGet;
	RzCoreNumGet numGet;
	RzCoreIsMapped isMapped;
	RzCoreDebugMapsSync syncDebugMaps;
	RzCorePJWithEncoding pjWithEncoding;
} RzCoreBind;

#endif
