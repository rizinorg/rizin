// SPDX-FileCopyrightText: 2015 Álvaro Felipe Melchor <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// code to support natively debugging mach binaries
/*   _
    _\)/_
   /    /
   \    \
    \_._/
*/
#ifndef _XNU_DEBUG_H
#define _XNU_DEBUG_H

#include <rz_util/rz_log.h>
#include <rz_debug.h>

#define LOG_MACH_ERROR(name, rc) \
	do { \
		const char *str = mach_error_string(rc); \
		RZ_LOG_ERROR("%s/%s: %s\n", __FUNCTION__, name, str ? str : "(unknown)"); \
	} while (0)

#if !TARGET_OS_IPHONE && !__POWERPC__
#include <sys/proc_info.h>
#include <libproc.h>
#define HAS_LIBPROC
#endif
#include <sys/types.h>
#include <sys/wait.h>
#include <mach/exception_types.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_interface.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
// no available for ios #include <mach/mach_vm.h>
#include <mach/mach_error.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <errno.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/fcntl.h>
#include <sys/proc.h>

#if __POWERPC__
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <mach/ppc/thread_status.h>
// iPhone5
#elif __aarch64
#include <mach/aarch64/thread_status.h>
// iPhone
#elif __arm
#include <mach/arm/thread_status.h>
#elif __arm64
#include <mach/arm/thread_status.h>
#else
/* x86 32/64 */
#include <mach/i386/thread_status.h>
#include <sys/ucontext.h>
#include <mach/i386/_structs.h>

// APPLE

/*
#if OLDIEDEF
#if __x86_64__
#define RZ_DEBUG_STATE_T x86_THREAD_STATE
#define RZ_DEBUG_REG_T _STRUCT_X86_THREAD_STATE64
#define RZ_DEBUG_STATE_SZ x86_THREAD_STATE_COUNT
#else
#define RZ_DEBUG_REG_T _STRUCT_X86_THREAD_STATE32
#define RZ_DEBUG_STATE_T i386_THREAD_STATE
#define RZ_DEBUG_STATE_SZ i386_THREAD_STATE_COUNT
#endif
#endif // OLDIEDEF
*/

#if __LP64__
#define ADDR         "%16lx"
#define HEADER_SIZE  0x1000
#define IMAGE_OFFSET 0x2000
#define KERNEL_LOWER 0xffffff8000000000
#else
#define ADDR         "%8x"
#define HEADER_SIZE  0x1000
#define IMAGE_OFFSET 0x201000
#define KERNEL_LOWER 0x80000000
#endif
// #define RZ_DEBUG_STATE_T XXX
//(dbg->bits==64)?x86_THREAD_STATE:_STRUCT_X86_THREAD_STATE32
// #define RZ_DEBUG_REG_T _STRUCT_X86_THREAD_STATE64
// #define RZ_DEBUG_STATE_SZ ((dbg->bits == RZ_SYS_BITS_64) ? 168 : 64)
#define REG_PC ((dbg->bits == RZ_SYS_BITS_64) ? 16 : 10)
#define REG_FL ((dbg->bits == RZ_SYS_BITS_64) ? 17 : 9)
#define REG_SP (7)
#endif

#if TARGET_OS_IPHONE

typedef struct {
	ut64 bvr[16];
	ut64 bcr[16];
	ut64 wvr[16];
	ut64 wcr[16];
	ut64 mdscr_el1;
} ARMDebugState64;

typedef struct {
	ut32 bvr[16];
	ut32 bcr[16];
	ut32 wvr[16];
	ut32 wcr[16];
	ut64 mdscr_el1;
} ARMDebugState32;

// BCR address match type
#define BCR_M_IMVA_MATCH       ((uint32_t)(0u << 21))
#define BCR_M_CONTEXT_ID_MATCH ((uint32_t)(1u << 21))
#define BCR_M_IMVA_MISMATCH    ((uint32_t)(2u << 21))
#define BCR_M_RESERVED         ((uint32_t)(3u << 21))

// Link a BVR/BCR or WVR/WCR pair to another
#define E_ENABLE_LINKING ((uint32_t)(1u << 20))

// Byte Address Select
#define BAS_IMVA_PLUS_0 ((uint32_t)(1u << 5))
#define BAS_IMVA_PLUS_1 ((uint32_t)(1u << 6))
#define BAS_IMVA_PLUS_2 ((uint32_t)(1u << 7))
#define BAS_IMVA_PLUS_3 ((uint32_t)(1u << 8))
#define BAS_IMVA_0_1    ((uint32_t)(3u << 5))
#define BAS_IMVA_2_3    ((uint32_t)(3u << 7))
#define BAS_IMVA_ALL    ((uint32_t)(0xfu << 5))

// Break only in privileged or user mode
#define S_RSVD      ((uint32_t)(0u << 1))
#define S_PRIV      ((uint32_t)(1u << 1))
#define S_USER      ((uint32_t)(2u << 1))
#define S_PRIV_USER ((S_PRIV) | (S_USER))

#define BCR_ENABLE ((uint32_t)(1u))
#define WCR_ENABLE ((uint32_t)(1u))

// Watchpoint load/store
#define WCR_LOAD  ((uint32_t)(1u << 3))
#define WCR_STORE ((uint32_t)(1u << 4))

#endif

typedef struct {
	int flavor;
	mach_msg_type_number_t count;
} coredump_thread_state_flavor_t;

#if defined(__ppc__)

static coredump_thread_state_flavor_t
	thread_flavor_array[] = {
		{ PPC_THREAD_STATE, PPC_THREAD_STATE_COUNT },
		{ PPC_FLOAT_STATE, PPC_FLOAT_STATE_COUNT },
		{ PPC_EXCEPTION_STATE, PPC_EXCEPTION_STATE_COUNT },
		{ PPC_VECTOR_STATE, PPC_VECTOR_STATE_COUNT },
	};

static int coredump_nflavors = 4;

#elif defined(__ppc64__)

coredump_thread_state_flavor_t
	thread_flavor_array[] = {
		{ PPC_THREAD_STATE64, PPC_THREAD_STATE64_COUNT },
		{ PPC_FLOAT_STATE, PPC_FLOAT_STATE_COUNT },
		{ PPC_EXCEPTION_STATE64, PPC_EXCEPTION_STATE64_COUNT },
		{ PPC_VECTOR_STATE, PPC_VECTOR_STATE_COUNT },
	};

static int coredump_nflavors = 4;

#elif defined(__i386__)

static coredump_thread_state_flavor_t
	thread_flavor_array[] = {
		{ x86_THREAD_STATE32, x86_THREAD_STATE32_COUNT },
		{ x86_FLOAT_STATE32, x86_FLOAT_STATE32_COUNT },
		{ x86_EXCEPTION_STATE32, x86_EXCEPTION_STATE32_COUNT },
	};

static int coredump_nflavors = 3;

#elif defined(__x86_64__)

static coredump_thread_state_flavor_t
	thread_flavor_array[] = {
		{ x86_THREAD_STATE64, x86_THREAD_STATE64_COUNT },
		{ x86_FLOAT_STATE64, x86_FLOAT_STATE64_COUNT },
		{ x86_EXCEPTION_STATE64, x86_EXCEPTION_STATE64_COUNT },
	};

static int coredump_nflavors = 3;

#elif defined(__aarch64__) || defined(__arm64__)

static coredump_thread_state_flavor_t
	thread_flavor_array[] = {
		{ ARM_UNIFIED_THREAD_STATE, ARM_UNIFIED_THREAD_STATE_COUNT }
	};

static int coredump_nflavors = 1;

#elif defined(__arm__)

static coredump_thread_state_flavor_t
	thread_flavor_array[] = {
		{ ARM_THREAD_STATE64, ARM_THREAD_STATE64_COUNT }
	};

static int coredump_nflavors = 1;

#else
// XXX: Add __arm__ for iOS devices?
#warning Unsupported architecture

#endif

#define MAX_TSTATE_FLAVORS                   10
#define DEFAULT_COREFILE_DEST                "core.%u"
#define RZ_DEBUG_REASON_MACH_RCV_INTERRUPTED -2

typedef struct {
	vm_offset_t header;
	int hoffset;
	int tstate_size;
	coredump_thread_state_flavor_t *flavors;
} tir_t;

typedef struct _exception_info {
	exception_mask_t masks[EXC_TYPES_COUNT];
	mach_port_t ports[EXC_TYPES_COUNT];
	exception_behavior_t behaviors[EXC_TYPES_COUNT];
	thread_state_flavor_t flavors[EXC_TYPES_COUNT];
	mach_msg_type_number_t count;
	pthread_t thread;
	mach_port_t exception_port;
} xnu_exception_info;

typedef struct rz_xnu_debug_t {
	cpu_type_t cpu; ///< CPU/Architecture of the debuggee, determined and set once after attach
	task_t task_dbg;
	int old_pid;
	xnu_exception_info ex;
} RzXnuDebug;

RZ_IPI bool rz_xnu_debug_init(RzDebug *dbg, void **user);
RZ_IPI void rz_xnu_debug_fini(RzDebug *dbg, void *user);

task_t pid_to_task(RzXnuDebug *ctx, int pid);
int xnu_get_vmmap_entries_for_pid(RzXnuDebug *ctx, pid_t pid);
char *xnu_corefile_default_location(void);
bool xnu_generate_corefile(RzDebug *dbg, RzBuffer *dest);
int xnu_reg_read(RzDebug *dbg, int type, ut8 *buf, int size);
int xnu_reg_write(RzDebug *dgb, int type, const ut8 *buf, int size);
char *xnu_reg_profile(RzDebug *dbg);
int xnu_attach(RzDebug *dbg, int pid);
bool xnu_step(RzDebug *dbg);
int xnu_detach(RzDebug *dbg, int pid);
int xnu_stop(RzDebug *dbg, int pid);
int xnu_continue(RzDebug *dbg, int pid, int tid, int sig);
RzDebugMap *xnu_map_alloc(RzDebug *dbg, ut64 addr, int size);
int xnu_map_dealloc(RzDebug *dbg, ut64 addr, int size);
int xnu_map_protect(RzDebug *dbg, ut64 addr, int size, int perms);
int xnu_wait(RzDebug *dbg, int pid);
RzDebugPid *xnu_get_pid(int pid);
RzList *xnu_dbg_maps(RzDebug *dbg, int only_modules);
RzList *xnu_thread_list(RzDebug *dbg, int pid, RzList *list);
RzDebugInfo *xnu_info(RzDebug *dbg, const char *arg);

#endif
