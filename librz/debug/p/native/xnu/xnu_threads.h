// SPDX-FileCopyrightText: 2015 Álvaro Felipe Melchor <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _INCLUDE_XNU_THREADS_H_
#define _INCLUDE_XNU_THREADS_H_

#include "xnu_debug.h"

#if __POWERPC__
// TODO add better support for PPC
#define RZ_REG_T        ppc_thread_state_t
#define RZ_REG_STATE_T  PPC_THREAD_STATE
#define RZ_REG_STATE_SZ PPC_THREAD_STATE_SZ

#elif __arm || __arm64 || __aarch64
#include <mach/arm/thread_status.h>
#ifndef ARM_THREAD_STATE
#define ARM_THREAD_STATE 1
#endif
#ifndef ARM_THREAD_STATE64
#define ARM_THREAD_STATE64 6
#endif
typedef union rz_xnu_arm_reg_state_t {
	// which one is used here is determined by RzXnuDebug.cpu
	arm_thread_state32_t arm32;
	arm_thread_state64_t arm64;
} RzXnuArmRegState;
#define RZ_REG_T        RzXnuArmRegState
#define RZ_REG_STATE_T  MACHINE_THREAD_STATE
#define RZ_REG_STATE_SZ MACHINE_THREAD_STATE_COUNT
#elif __x86_64__ || __i386__
#define RZ_REG_T        x86_thread_state_t
#define RZ_REG_STATE_T  MACHINE_THREAD_STATE
#define RZ_REG_STATE_SZ MACHINE_THREAD_STATE_COUNT
#endif

#define RETURN_ON_MACH_ERROR(msg, retval) \
	if (kr != KERN_SUCCESS) { \
		mach_error(msg, kr); \
		return ((retval)); \
	}

typedef struct _xnu_thread {
	thread_t port; // mach_port // XXX bad naming here
	char *name; // name of thread
	thread_basic_info_data_t basic_info; // need this?
	ut8 stepping; // thread is stepping or not //TODO implement stepping
	RZ_REG_T gpr; // type RZ_REG_T using unified API XXX bad naming
	void *state;
	ut32 state_size;
#if __arm64 || __aarch64 || __arm64__ || __aarch64__
	union {
		arm_debug_state32_t drx32;
		arm_debug_state64_t drx64;
	} debug;
#elif __arm__ || __arm || __armv7__
	union {
		arm_debug_state_t drx;
	} debug;
#elif __x86_64__ || __i386__
	x86_debug_state_t drx;
#endif
	ut16 flavor;
	ut32 count;
} xnu_thread_t;

typedef struct _exc_msg {
	mach_msg_header_t hdr;
	/* start of the kernel processed data */
	mach_msg_body_t msg_body;
	mach_msg_port_descriptor_t thread;
	mach_msg_port_descriptor_t task;
	/* end of the kernel processed data */
	NDR_record_t NDR;
	exception_type_t exception;
	mach_msg_type_number_t code_cnt;

	/*!
	 * code and subcode,
	 * two 64-bit values here because of MACH_EXCEPTION_CODES,
	 * but not 64-bit aligned, so we use ut32.
	 */
	ut32 code[0x4];

	/* some times RCV_TO_LARGE probs */
	char pad[512];
} exc_msg;

typedef struct _rep_msg {
	mach_msg_header_t hdr;
	NDR_record_t NDR;
	kern_return_t ret_code;
} rep_msg;

RZ_IPI int rz_xnu_update_thread_list(RzDebug *dbg);
RZ_IPI xnu_thread_t *rz_xnu_get_thread(RzDebug *dbg, int tid);
RZ_IPI thread_t rz_xnu_get_cur_thread(RzDebug *dbg);
RZ_IPI bool rz_xnu_thread_set_gpr(RzXnuDebug *ctx, xnu_thread_t *thread);
RZ_IPI bool rz_xnu_thread_get_gpr(RzXnuDebug *ctx, xnu_thread_t *thread);
RZ_IPI bool rz_xnu_thread_get_drx(RzXnuDebug *ctx, xnu_thread_t *thread);
RZ_IPI bool rz_xnu_thread_set_drx(RzXnuDebug *ctx, xnu_thread_t *thread);

RZ_IPI bool xnu_modify_trace_bit(RzDebug *dbg, xnu_thread_t *th, int enable);
static inline bool xnu_set_trace_bit(RzDebug *dbg, xnu_thread_t *th) {
	return xnu_modify_trace_bit(dbg, th, 1);
}
static inline bool xnu_clear_trace_bit(RzDebug *dbg, xnu_thread_t *th) {
	return xnu_modify_trace_bit(dbg, th, 0);
}

RZ_IPI bool xnu_create_exception_thread(RzDebug *dbg);
RZ_IPI bool xnu_restore_exception_ports(RzXnuDebug *ctx, int pid);
RZ_IPI RzDebugReasonType xnu_wait_for_exception(RzDebug *dbg, int pid, ut32 timeout_ms, bool quiet_signal);

#endif
