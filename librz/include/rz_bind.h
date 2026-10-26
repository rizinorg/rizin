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
typedef ut64 (*RzCoreNumGet)(void *core, const char *str);
typedef const RzList *(*RzCoreFlagsGet)(void *core, ut64 offset);
typedef bool (*RzCoreBinApplyInfo)(void *core, void *binfile, ut32 mask);
typedef ut64 (*RzCoreConfigGetInteger)(void *core, const char *key);
typedef bool (*RzCoreConfigGetBool)(void *core, const char *key);
typedef const char *(*RzCoreConfigGetString)(void *core, const char *key);
typedef bool (*RzCoreConfigSetString)(void *core, const char *key, const char *value);
typedef bool (*RzCoreConfigSetBool)(void *core, const char *key, bool value);
typedef bool (*RzCoreConfigSetInteger)(void *core, const char *key, ut64 value);

/* deprecated */
typedef ut64 (*RzCoreConfigGetI)(void *core, const char *key);
typedef const char *(*RzCoreConfigGet)(void *core, const char *key);
typedef bool (*RzCoreConfigSet)(void *core, const char *key, const char *value);
typedef bool (*RzCoreConfigSetI)(void *core, const char *key, ut64 value);

// TODO: Not really confident in these and binds in general
// These two are only used in:
// 1 - librz/arch/p/analysis/analysis_wasm.c
// 2 - librz/arch/p/parse/parse_wasm_pseudo.c
// (PremadeS)
typedef void (*RzCoreConsPush)(void *core);
typedef void (*RzCoreConsPop)(void *core);

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
	RzCoreConfigGetI cfggeti; ///< deprecated
	RzCoreConfigGet cfgGet; ///< deprecated
	RzCoreConfigSet cfgSet; ///< deprecated
	RzCoreConfigSetI cfgSetI; ///< deprecated
	RzCoreConfigGetInteger config_get_integer;
	RzCoreConfigGetBool config_get_bool;
	RzCoreConfigGetString config_get_string;
	RzCoreConfigSetString config_set_string;
	RzCoreConfigSetBool config_set_bool;
	RzCoreConfigSetInteger config_set_integer;
	RzCoreNumGet numGet;
	RzCoreFlagsGet flagsGet;
	RzCoreBinApplyInfo applyBinInfo;
	RzCoreConsPush consPush;
	RzCoreConsPop consPop;
} RzCoreBind;

#endif
