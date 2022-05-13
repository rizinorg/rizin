// SPDX-FileCopyrightText: 2015-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIND_H
#define RZ_BIND_H

#include <rz_list.h>

// TODO: These binds needs to be removed.

typedef int (*RzCoreCmd)(void *core, const char *cmd);
typedef int (*RzCoreCmdF)(void *user, const char *fmt, ...);
typedef int (*RzCoreDebugBpHit)(void *core, void *bp);
typedef void (*RzCoreDebugSyscallHit)(void *core);
typedef char *(*RzCoreCmdStr)(void *core, const char *cmd);
typedef char *(*RzCoreCmdStrF)(void *core, const char *cmd, ...);
typedef void (*RzCorePuts)(const char *cmd);
typedef void (*RzCoreSetArchBits)(void *core, const char *arch, int bits);
typedef const char *(*RzCoreGetName)(void *core, ut64 off);
typedef char *(*RzCoreGetNameDelta)(void *core, ut64 off);
typedef void (*RzCoreSeekArchBits)(void *core, ut64 addr);
typedef ut64 (*RzCoreConfigGetI)(void *core, const char *key);
typedef const char *(*RzCoreConfigGet)(void *core, const char *key);
typedef bool (*RzCoreConfigSet)(void *core, const char *key, const char *value);
typedef bool (*RzCoreConfigSetI)(void *core, const char *key, ut64 value);
typedef ut64 (*RzCoreNumGet)(void *core, const char *str);
typedef const RzList *(*RzCoreFlagsGet)(void *core, ut64 offset);
typedef bool (*RzCoreBinApplyInfo)(void *core, void *binfile, ut32 mask);

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
	RzCoreConfigSet cfgSet;
	RzCoreConfigSetI cfgSetI;
	RzCoreNumGet numGet;
	RzCoreFlagsGet flagsGet;
	RzCoreBinApplyInfo applyBinInfo;
} RzCoreBind;

#endif
