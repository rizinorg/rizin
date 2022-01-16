// SPDX-FileCopyrightText: 2014-2017 LemonBoy <thatlemon@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _winkd_H_
#define _winkd_H_

#include <rz_util.h>
#include <stdint.h>
#include "kd.h"

typedef struct WindProc {
	ut64 eprocess;
	ut32 uniqueid;
	ut64 vadroot;
	ut64 dir_base_table;
	ut64 peb;
	char name[17];
} WindProc;

typedef struct WindThread {
	ut32 uniqueid;
	bool runnable;
	char status;
	ut64 ethread;
	ut64 entrypoint;
} WindThread;

typedef struct WindModule {
	char *name;
	ut64 addr;
	ut32 size;
	ut32 timestamp;
} WindModule;

enum {
	K_PaeEnabled = 0x036,
	K_PsActiveProcessHead = 0x050,
	K_CmNtCSDVersion = 0x268,
};

enum {
	E_ActiveProcessLinks, // EPROCESS
	E_UniqueProcessId, // EPROCESS
	E_Peb, // EPROCESS
	E_ImageFileName, // EPROCESS
	E_VadRoot, // EPROCESS
	E_ThreadListHead, // EPROCESS
	K_DirectoryTableBase, // KPROCESS
	P_ImageBaseAddress, // PEB
	P_ProcessParameters, // PEB
	RZ_ImagePathName, // RTL_USER_PROCESS_PARAMETERS
	ET_Tcb, // ETHREAD
	ET_ThreadListEntry, // ETHREAD
	ET_Win32StartAddress, // ETHREAD
	ET_Cid, // ETHREAD
	C_UniqueThread, // CLIENT_ID
	O_Max,
};

typedef struct {
	int build;
	int sp;
	int bits;
	int flags;
	int f[O_Max];
} Profile;

typedef int WindReadAt(void *user, ut64 address, RZ_NONNULL RZ_OUT ut8 *buf, int count);
typedef int WindWriteAt(void *user, ut64 address, RZ_NONNULL RZ_IN const ut8 *buf, int count);

typedef struct _WindCtx {
	Profile *profile;
	WindReadAt *read_at_physical;
	WindReadAt *read_at_kernel_virtual;
	WindWriteAt *write_at_physical;
	void *user;
	ut64 KdDebuggerDataBlock;
	ut64 PsLoadedModuleList;
	ut64 PsActiveProcessHead;
	bool is_64bit;
	bool is_pae;
	bool is_arm;
	WindProc target;
	WindThread target_thread;
} WindCtx;

typedef struct _KdCtx {
	WindCtx windctx;
	io_desc_t *desc;
	uint32_t seq_id;
	int syncd;
	int cpu_count;
	int cpu;
	RzList *plist_cache;
	RzList *tlist_cache;
	RzThreadLock *dontmix;
} KdCtx;

#define TARGET_BACKEND  0
#define TARGET_PHYSICAL 1
#define TARGET_KERNEL   2
#define TARGET_VIRTUAL  3

typedef struct _DmpCtx {
	WindCtx windctx;
	ut32 type;
	ut64 target; // TARGET_BACKEND, TARGET_PHYSICAL, or DirectoryTable
	ut64 kernelDirectoryTable;
	RzIODesc *backend;
	RzVector /*<ut64>*/ KiProcessorBlock;
	ut32 kprcb_context_offset; // nt!_KPRCB ProcessorState.ContextFrame
	ut32 kthread_switch_frame_offset; // nt!_KTHREAD SwitchFrame.Fp
	ut32 kthread_process_offset; // nt!_KTHREAD Process
	ut8 *context;
	size_t context_sz;
} DmpCtx;

static inline ut64 winkd_read_ptr_at(WindCtx *ctx, WindReadAt *read_at_func, ut64 at) {
	ut8 ptr_buf[8];
	if (!read_at_func(ctx->user, at, ptr_buf, ctx->is_64bit ? 8 : 4)) {
		return 0;
	}
	return ctx->is_64bit ? rz_read_le64(ptr_buf) : rz_read_le32(ptr_buf);
}

static inline void winkd_ctx_fini(WindCtx *ctx) {
	free(ctx->user);
	free(ctx->profile);
}

// grep -e "^winkd_" subprojects/rzwinkd/winkd.c | sed -e 's/ {$/;/' -e 's/^/int /'
int winkd_get_bits(WindCtx *ctx);
int winkd_get_sp(WindCtx *ctx);
Profile *winkd_get_profile(int bits, int build, int sp);
bool winkd_va_to_pa(WindCtx *ctx, ut64 directory_table, ut64 va, ut64 *pa);
ut64 winkd_get_target_base(WindCtx *ctx);
ut32 winkd_get_target(WindCtx *ctx);
ut32 winkd_get_target_thread(WindCtx *ctx);
bool winkd_set_target(WindCtx *ctx, ut32 pid, ut32 tid);
WindProc *winkd_get_process_at(WindCtx *ctx, ut64 address);
WindThread *winkd_get_thread_at(WindCtx *ctx, ut64 address);
RzList *winkd_list_process(WindCtx *ctx);
RzList *winkd_list_threads(WindCtx *ctx);
RzList *winkd_list_modules(WindCtx *ctx);
int winkd_read_at_uva(WindCtx *ctx, ut64 offset, uint8_t *buf, int count);
int winkd_write_at_uva(WindCtx *ctx, ut64 offset, const uint8_t *buf, int count);

KdCtx *winkd_kdctx_new(io_desc_t *desc);
void winkd_kdctx_free(KdCtx **ctx);
int winkd_get_cpus(KdCtx *ctx);
bool winkd_set_cpu(KdCtx *ctx, int cpu);
int winkd_get_cpu(KdCtx *ctx);
int winkd_wait_packet(KdCtx *ctx, const ut32 type, kd_packet_t **p);
int winkd_sync(KdCtx *ctx);
bool winkd_read_ver(KdCtx *ctx);
int winkd_continue(KdCtx *ctx);
bool winkd_write_reg(KdCtx *ctx, const uint8_t *buf, int size);
int winkd_read_reg(KdCtx *ctx, uint8_t *buf, int size);
int winkd_query_mem(KdCtx *ctx, const ut64 addr, int *address_space, int *flags);
int winkd_bkpt(KdCtx *ctx, const ut64 addr, const int set, const int hw, int *handle);
int winkd_read_at(KdCtx *ctx, const ut64 offset, uint8_t *buf, const int count);
int winkd_read_at_phys(KdCtx *ctx, const ut64 offset, uint8_t *buf, const int count);
int winkd_write_at(KdCtx *ctx, const ut64 offset, const uint8_t *buf, const int count);
int winkd_write_at_phys(KdCtx *ctx, const ut64 offset, const uint8_t *buf, const int count);
void winkd_break(void *ctx);
int winkd_break_read(KdCtx *ctx);
bool winkd_lock_enter(KdCtx *ctx);
bool winkd_lock_leave(KdCtx *ctx);
bool winkd_lock_tryenter(KdCtx *ctx);
#endif
