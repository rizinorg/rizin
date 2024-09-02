// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_userconf.h>
#include <rz_debug.h>
#include <rz_drx.h>
#include <rz_core.h>
#include <rz_reg.h>
#include <rz_lib.h>
#include <rz_analysis.h>
#include <signal.h>
#include <sys/types.h>

#include "native/drx.c" // x86 specific
#include "rz_cons.h"

static int rz_debug_native_continue(RzDebug *dbg, int pid, int tid, int sig);
static int rz_debug_native_reg_read(RzDebug *dbg, int type, ut8 *buf, int size);
static int rz_debug_native_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size);

#include "native/bt.c"

// Native OS & Arch
#if __APPLE__
#if __i386__ || __x86_64__
#include "apple_x86_64.c"
#else
#include "apple_aarch64.c"
#endif

#elif __ANDROID__
#if __i386__ || __x86_64__
#include "android_x86_64.c"
#elif __arm__
#include "android_arm.c"
#else
#include "android_arm64.c"
#endif

#elif __linux__
#if __i386__ || __x86_64__
#include "linux_x86_64.c"
#elif __arm__
#include "linux_arm.c"
#else
#include "linux_arm64.c"
#endif

#elif __WIDOWS__
#include "windows.c"

#elif __BSD__
#if __KFBSD__
#include "KFBSD.c"
#elif __OpenBSD__
#include "OpenBSD.c"
#elif __NetBSD__
#include "NetBSD.c"
#elif __DragonFly__
#include "DragonFly.c"
#else
#warning Unsupported debugging platform
#undef DEBUGGER
#define DEBUGGER 0
#endif

#elif __sun
#define RZ_DEBUG_REG_T gregset_t
#undef DEBUGGER
#define DEBUGGER 0
#warning No debugger support for SunOS yet

#else
#warning Unsupported debugging platform
#undef DEBUGGER
#define DEBUGGER 0
#endif // Native OS & Arch

#if DEBUGGER
struct rz_debug_desc_plugin_t rz_debug_desc_plugin_native = {
	.open = rz_debug_desc_native_open,
	.list = rz_debug_desc_native_list,
};

RzDebugPlugin rz_debug_plugin_native = {
	.name = "native",
	.license = "LGPL3",
#if __i386__
	.bits = RZ_SYS_BITS_32,
	.arch = "x86",
	.canstep = 1,
#elif __x86_64__
	.bits = RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.arch = "x86",
	.canstep = 1, // XXX it's 1 on some platforms...
#elif __aarch64__ || __arm64__
	.bits = RZ_SYS_BITS_16 | RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.arch = "arm",
#if __WINDOWS__
	.canstep = 0,
#else
	.canstep = 1,
#endif
#elif __arm__
	.bits = RZ_SYS_BITS_16 | RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.arch = "arm",
	.canstep = 0,
#elif __mips__
	.bits = RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.arch = "mips",
	.canstep = 0,
#elif __powerpc__
#if __powerpc64__
	.bits = RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
#else
	.bits = RZ_SYS_BITS_32,
#endif
	.arch = "ppc",
	.canstep = 1,
#else
	.bits = 0,
	.arch = 0,
	.canstep = 0,
	.arch = "unsupported",
#ifdef _MSC_VER
#pragma message("Unsupported architecture")
#else
#warning Unsupported architecture
#endif
#endif
	.init = &rz_debug_native_init,
	.fini = &rz_debug_native_fini,
	.step = &rz_debug_native_step,
	.cont = &rz_debug_native_continue,
	.stop = &rz_debug_native_stop,
	.contsc = &rz_debug_native_continue_syscall,
	.attach = &rz_debug_native_attach,
	.detach = &rz_debug_native_detach,
// TODO: add native select for other platforms?
#if __WINDOWS__ || __linux__
	.select = &rz_debug_native_select,
#endif
	.pids = &rz_debug_native_pids,
	.threads = &rz_debug_native_threads,
	.wait = &rz_debug_native_wait,
	.kill = &rz_debug_native_kill,
	.frames = &rz_debug_native_frames, // rename to backtrace ?
	.reg_profile = rz_debug_native_reg_profile,
	.reg_read = rz_debug_native_reg_read,
	.info = rz_debug_native_info,
	.reg_write = (void *)&rz_debug_native_reg_write,
	.map_alloc = rz_debug_native_map_alloc,
	.map_dealloc = rz_debug_native_map_dealloc,
	.map_get = rz_debug_native_map_get,
	.modules_get = rz_debug_native_modules_get,
	.map_protect = rz_debug_native_map_protect,
	.breakpoint = rz_debug_native_bp,
	.drx = rz_debug_native_drx,
	.gcore = rz_debug_gcore,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_DBG,
	.data = &rz_debug_plugin_native,
	.version = RZ_VERSION
};
#endif // RZ_PLUGIN_INCORE

#else
RzDebugPlugin rz_debug_plugin_native = {
	NULL // .name = "native",
};

#endif // DEBUGGER