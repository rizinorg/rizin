// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>

#if __ANDROID__
#include "../native/android/debugger.h"
#elif __BSD__
#include "../native/bsd/debugger.h"
#elif __linux__
#include "../native/linux/debugger.h"
#elif __WINDOWS__
#include "../native/windows/debugger.h"
#elif __APPLE__
#include "../native/xnu/debugger.h"
#else /* Unsupported */
#warning Unsupported debugger for this operating system
#endif /* Operating System */

RzDebugPlugin rz_debug_plugin_native = {
	.name = "native",
	.license = "LGPL3",
	.author = "RizinOrg",
	.arch = NATIVE_ARCH_NAME,
	.bits = NATIVE_ARCH_BITS,
	.canstep = NATIVE_CAN_STEP,
	.init = NATIVE_INIT_CB,
	.fini = NATIVE_FINI_CB,
	.info = NATIVE_INFO_CB,
	.attach = NATIVE_ATTACH_CB,
	.detach = NATIVE_DETACH_CB,
	.select = NATIVE_SELECT_CB,
	.threads = NATIVE_THREADS_CB,
	.pids = NATIVE_PIDS_CB,
	.stop = NATIVE_STOP_CB,
	.step = NATIVE_STEP_CB,
	.step_over = NATIVE_STEP_OVER_CB,
	.cont = NATIVE_CONT_CB,
	.wait = NATIVE_WAIT_CB,
	.gcore = NATIVE_GCORE_CB,
	.kill = NATIVE_KILL_CB,
	.contsc = NATIVE_CONTSC_CB,
	.frames = NATIVE_FRAMES_CB,
	.breakpoint = NATIVE_BREAKPOINT_CB,
	.reg_read = NATIVE_REG_READ_CB,
	.reg_write = NATIVE_REG_WRITE_CB,
	.sync_registers = NATIVE_SYNC_REGISTERS_CB,
	.reg_profile = NATIVE_REG_PROFILE_CB,
	.set_reg_profile = NATIVE_SET_REG_PROFILE_CB,
	.map_get = NATIVE_MAP_GET_CB,
	.modules_get = NATIVE_MODULES_GET_CB,
	.map_alloc = NATIVE_MAP_ALLOC_CB,
	.map_dealloc = NATIVE_MAP_DEALLOC_CB,
	.map_protect = NATIVE_MAP_PROTECT_CB,
	.drx = NATIVE_DRX_CB,
	.desc = NATIVE_DESC_CB,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_DBG,
	.data = &rz_debug_plugin_native,
	.version = RZ_VERSION
};
#endif
