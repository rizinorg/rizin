// SPDX-FileCopyrightText: 2014-2017 LemonBoy <thatlemon@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <rz_util.h>
#include <rz_cons.h>
#include <rz_list.h>
#include <rz_debug.h>
#include "transport.h"
#include "winkd.h"
#include "kd.h"

#define O_FLAG_XPVAD 1
#define O_(n)        ctx->profile->f[n]
#include "profiles.h"

#define LOG_REQ(r) \
	{ \
		RZ_LOG_DEBUG("Request : %08x\nProcessor : %08x\nReturn : %08x\n", \
			(r)->req, \
			(r)->cpu, \
			(r)->ret); \
	}

#define KOBJECT_PROCESS 3
#define KOBJECT_THREAD  6

bool winkd_lock_enter(KdCtx *ctx) {
	rz_cons_break_push(winkd_break, ctx);
	rz_th_lock_enter(ctx->dontmix);
	return true;
}

bool winkd_lock_tryenter(KdCtx *ctx) {
	if (!rz_th_lock_tryenter(ctx->dontmix)) {
		return false;
	}
	rz_cons_break_push(winkd_break, ctx);
	return true;
}

bool winkd_lock_leave(KdCtx *ctx) {
	rz_cons_break_pop();
	rz_th_lock_leave(ctx->dontmix);
	return true;
}

int winkd_get_sp(WindCtx *ctx) {
	ut64 ptr = 0;
	// Grab the CmNtCSDVersion field to extract the Service Pack number
	if (!ctx->read_at_kernel_virtual(ctx->user, ctx->KdDebuggerDataBlock + K_CmNtCSDVersion, (ut8 *)&ptr, 8)) {
		RZ_LOG_DEBUG("Failed to read at %" PFMT64x "\n", ctx->KdDebuggerDataBlock + K_CmNtCSDVersion);
		return 0;
	}
	ut64 res;
	if (!ctx->read_at_kernel_virtual(ctx->user, ptr, (ut8 *)&res, 8)) {
		RZ_LOG_DEBUG("Failed to read at %" PFMT64x "\n", ptr);
		return 0;
	}
	if (res == UT64_MAX) {
		return 0;
	}
	return (res >> 8) & 0xff;
}

Profile *winkd_get_profile(int bits, int build, int sp) {
	int i;
	for (i = 0; p_table[i]; i++) {
		if (p_table[i]->build != build) {
			continue;
		}
		if (p_table[i]->sp != sp) {
			continue;
		}
		if (p_table[i]->bits != bits) {
			continue;
		}
		Profile *p = RZ_NEW0(Profile);
		if (!p) {
			return NULL;
		}
		*p = *p_table[i];
		return p;
	}
	return NULL;
}

int winkd_get_bits(WindCtx *ctx) {
	return ctx->is_64bit ? RZ_SYS_BITS_64 : RZ_SYS_BITS_32;
}

int winkd_get_cpus(KdCtx *ctx) {
	if (!ctx) {
		return -1;
	}
	return ctx->cpu_count;
}

bool winkd_set_cpu(KdCtx *ctx, int cpu) {
	if (!ctx || cpu > ctx->cpu_count) {
		return false;
	}
	ctx->cpu = cpu;
	return true;
}

int winkd_get_cpu(KdCtx *ctx) {
	if (!ctx) {
		return -1;
	}
	return ctx->cpu;
}

bool winkd_set_target(WindCtx *ctx, ut32 pid, ut32 tid) {
	WindProc *p;
	WindThread *t;
	RzList *l;
	RzListIter *it;
	const bool is_cur_process = ctx->target.eprocess && (ctx->target.uniqueid == pid);
	bool found = false;
	if (!is_cur_process) {
		l = winkd_list_process(ctx);
		rz_list_foreach (l, it, p) {
			if (p->uniqueid == pid) {
				found = true;
				ctx->target = *p;
				break;
			}
		}
		rz_list_free(l);
		if (!found) {
			ctx->target.eprocess = 0;
			ctx->target.uniqueid = 0;
			return false;
		}
	}
	const bool is_cur_thread = ctx->target_thread.ethread && (ctx->target_thread.uniqueid == tid);
	found = false;
	if (!is_cur_thread || !is_cur_process) {
		l = winkd_list_threads(ctx);
		if (is_cur_process) {
			rz_list_foreach (l, it, t) {
				if (t->uniqueid == tid) {
					ctx->target_thread = *t;
					found = true;
					break;
				}
			}
		} else {
			t = rz_list_first(l);
			if (t) {
				ctx->target_thread = *t;
				found = true;
			}
		}
		rz_list_free(l);
		if (!found) {
			ctx->target_thread.ethread = 0;
			ctx->target_thread.uniqueid = 0;
			return false;
		}
	}
	return true;
}

uint32_t winkd_get_target(WindCtx *ctx) {
	return ctx->target.uniqueid;
}

ut32 winkd_get_target_thread(WindCtx *ctx) {
	return ctx->target_thread.uniqueid;
}

ut64 winkd_get_target_base(WindCtx *ctx) {
	ut64 base = 0;

	if (!winkd_read_at_uva(ctx, ctx->target.peb + O_(P_ImageBaseAddress),
		    (uint8_t *)&base, 4 << ctx->is_64bit)) {
		return 0;
	}

	return base;
}

KdCtx *winkd_kdctx_new(io_desc_t *desc) {
	KdCtx *ctx = RZ_NEW0(KdCtx);
	if (!ctx) {
		return NULL;
	}
	ctx->dontmix = rz_th_lock_new(true);
	ctx->desc = desc;
	return ctx;
}

void winkd_kdctx_free(KdCtx **ctx) {
	if (!ctx || !*ctx) {
		return;
	}
	rz_list_free((*ctx)->plist_cache);
	rz_list_free((*ctx)->tlist_cache);
	io_desc_t *desc = (*ctx)->desc;
	desc->iob->close(desc->fp);
	RZ_FREE(desc);
	rz_th_lock_free((*ctx)->dontmix);
	winkd_ctx_fini(&(*ctx)->windctx);
	RZ_FREE(*ctx);
}

#define PKT_REQ(p) ((kd_req_t *)(((kd_packet_t *)p)->data))
#define PKT_STC(p) ((kd_stc_64 *)(((kd_packet_t *)p)->data))

#if 0
static void dump_stc(kd_packet_t *p) {
	kd_stc_64 *stc = PKT_STC (p);

	eprintf ("New state: %08x\n", stc->state);
	eprintf ("EIP: 0x%016"PFMT64x " Kthread: 0x%016"PFMT64x "\n",
		(ut64) stc->pc, (ut64) stc->kthread);
	eprintf ("On cpu %i/%i\n", stc->cpu + 1, stc->cpu_count);

	if (stc->state == DbgKdExceptionStateChange) {
		eprintf ("Exception\n");
		eprintf (" Code   : %08x\n", stc->exception.code);
		eprintf (" Flags  : %08x\n", stc->exception.flags);
		eprintf (" Record : %016"PFMT64x "\n", (ut64) stc->exception.ex_record);
		eprintf (" Addr   : %016"PFMT64x "\n", (ut64) stc->exception.ex_addr);
	}
}
#endif

static int do_io_reply(KdCtx *ctx, kd_packet_t *pkt) {
	kd_ioc_t ioc = {
		0
	};
	static int id = 0;
	if (id == pkt->id) {
		RZ_LOG_DEBUG("Host resent io packet, ignoring.\n");
		return true;
	}
	int ret;
	ioc.req = 0x3430;
	ioc.ret = KD_RET_ENOENT;
	winkd_lock_enter(ctx);
	id = pkt->id;
	ret = kd_send_data_packet(ctx->desc, KD_PACKET_TYPE_FILE_IO,
		(ctx->seq_id ^= 1), (uint8_t *)&ioc, sizeof(kd_ioc_t), NULL, 0);
	if (ret != KD_E_OK) {
		goto error;
	}
	RZ_LOG_DEBUG("Waiting for io_reply ack...\n");
	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}
	id = 0;
	winkd_lock_leave(ctx);
	RZ_LOG_DEBUG("Ack received, restore flow\n");
	return true;
error:
	id = 0;
	winkd_lock_leave(ctx);
	return 0;
}

int winkd_wait_packet(KdCtx *ctx, const uint32_t type, kd_packet_t **p) {
	kd_packet_t *pkt = NULL;
	int ret;
	int retries = 10;

	do {
		if (pkt) {
			RZ_FREE(pkt);
		}
		// Try to read a whole packet
		ret = kd_read_packet(ctx->desc, &pkt);
		if (ret != KD_E_OK || !pkt) {
			break;
		}
		if (pkt->type == KD_PACKET_TYPE_UNUSED) {
			retries++;
			continue;
		}

		// eprintf ("Received %08x\n", pkt->type);
		if (pkt->type != type) {
			RZ_LOG_DEBUG("We were not waiting for this... %08x\n", pkt->type);
		}
		if (pkt->leader == KD_PACKET_DATA && pkt->type == KD_PACKET_TYPE_STATE_CHANGE64) {
			// dump_stc (pkt);
			RZ_LOG_DEBUG("State64\n");
		}
		if (pkt->leader == KD_PACKET_DATA && pkt->type == KD_PACKET_TYPE_FILE_IO) {
			RZ_LOG_DEBUG("Replying IO\n");
			do_io_reply(ctx, pkt);
		}

		// Check for RESEND
		// The host didn't like our request
		if (pkt->leader == KD_PACKET_CTRL && pkt->type == KD_PACKET_TYPE_RESEND) {
			rz_sys_backtrace();
			RZ_LOG_DEBUG("Waoh. You probably sent a malformed packet !\n");
			ret = KD_E_MALFORMED;
			break;
		}
	} while (pkt->type != type && retries--);

	if (ret != KD_E_OK) {
		free(pkt);
		return ret;
	}

	if (p) {
		*p = pkt;
	} else {
		free(pkt);
	}

	return KD_E_OK;
}

#if 0 // Unused for now

// http://dfrws.org/2007/proceedings/p62-dolan-gavitt.pdf
RZ_PACKED(
	typedef struct {
		char tag[4];
		uint32_t start_vpn;
		uint32_t end_vpn;
		uint32_t parent;
		uint32_t left;
		uint32_t right;
		uint32_t flags;
	})
mmvad_short;

int winkd_walk_vadtree(WindCtx *ctx, ut64 address, ut64 parent) {
	mmvad_short entry = { { 0 } };
	ut64 start, end;
	int prot;

	if (ctx->read_at_kernel_virtual(ctx, address - 0x4, (uint8_t *)&entry, sizeof(mmvad_short)) != sizeof(mmvad_short)) {
		RZ_LOG_DEBUG("0x%" PFMT64x " Could not read the node!\n", (ut64)address);
		return 0;
	}

	if (parent != UT64_MAX && entry.parent != parent) {
		RZ_LOG_DEBUG("Wrong parent!\n");
		return 0;
	}

	start = entry.start_vpn << 12;
	end = ((entry.end_vpn + 1) << 12) - 1;
	prot = (entry.flags >> 24) & 0x1F;

	RZ_LOG_DEBUG("Start 0x%016" PFMT64x " End 0x%016" PFMT64x " Prot 0x%08" PFMT64x "\n",
		(ut64)start, (ut64)end, (ut64)prot);

	if (entry.left) {
		winkd_walk_vadtree(ctx, entry.left, address);
	}
	if (entry.right) {
		winkd_walk_vadtree(ctx, entry.right, address);
	}

	return 1;
}

#endif

WindProc *winkd_get_process_at(WindCtx *ctx, ut64 address) {
	ut8 type;
	if (!ctx->read_at_kernel_virtual(ctx->user, address, &type, 1)) {
		RZ_LOG_WARN("Failed to read DISPACHER_HEAD.Type at: 0x%" PFMT64x "\n", address);
		return NULL;
	}
	if ((type & 0x7f) != KOBJECT_PROCESS) {
		RZ_LOG_WARN("KOBJECT at 0x%" PFMT64x " is not a process.\n", address);
		return NULL;
	}
	WindProc *proc = RZ_NEW0(WindProc);
	if (!proc) {
		return NULL;
	}
	// Read the short name
	ctx->read_at_kernel_virtual(ctx->user, address + O_(E_ImageFileName), (ut8 *)proc->name, sizeof(proc->name));
	proc->name[sizeof(proc->name) - 1] = '\0';
	proc->eprocess = address;
	proc->vadroot = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, address + O_(E_VadRoot));
	proc->uniqueid = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, address + O_(E_UniqueProcessId));
	proc->peb = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, address + O_(E_Peb));
	proc->dir_base_table = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, address + O_(K_DirectoryTableBase));
	return proc;
}

RzList *winkd_list_process(WindCtx *ctx) {
	RzList *ret = NULL;
	bool current_process_found = false;
	// Grab the PsActiveProcessHead from _KDDEBUGGER_DATA64
	ctx->PsActiveProcessHead = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->KdDebuggerDataBlock + K_PsActiveProcessHead);

	// Walk the LIST_ENTRY
	ut64 ptr = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ctx->PsActiveProcessHead);

	// Check for empty list
	if (ptr == 0 || ptr == UT64_MAX) {
		RZ_LOG_ERROR("NULL value at PsActiveProcessHead\n");
		if (ctx->target.eprocess) {
			ret = rz_list_newf(free);
			goto get_cur_process;
		}
		return NULL;
	}
	ret = rz_list_newf(free);

	do {
		ut64 next;

		// Read the ActiveProcessLinks entry
		next = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, ptr);

		if (!next || next == UT64_MAX) {
			RZ_LOG_WARN("Corrupted ActiveProcessLinks entry found at: 0x%" PFMT64x "\n", ptr);
			break;
		}

		// This points to the 'ActiveProcessLinks' list, adjust the ptr so that it point to the
		// EPROCESS base
		ptr -= O_(E_ActiveProcessLinks);

		WindProc *proc = winkd_get_process_at(ctx, ptr);
		if (proc) {
			if (proc->eprocess == ctx->target.eprocess) {
				current_process_found = true;
			}
			rz_list_append(ret, proc);
		}
		ptr = next;
	} while (ptr != ctx->PsActiveProcessHead);
get_cur_process:
	if (!current_process_found && ctx->target.eprocess) {
		WindProc *proc = winkd_get_process_at(ctx, ctx->target.eprocess);
		if (proc) {
			rz_list_append(ret, proc);
		}
	}
	return ret;
}

int winkd_op_at_uva(WindCtx *ctx, ut64 address, uint8_t *buf, int count, bool write) {
	ut32 total = 0;
	ut32 offset = 0;
	const ut64 end = address + count;
	while (address < end) {
		ut64 pa;
		const ut32 restOfPage = 0x1000 - (address & 0xfff);
		if (!winkd_va_to_pa(ctx, ctx->target.dir_base_table, address, &pa)) {
			RZ_LOG_DEBUG("0x%" PFMT64x " not mapped\n", address);
			if (UT64_ADD_OVFCHK(address, restOfPage)) {
				break;
			}
			address += restOfPage;
			offset += restOfPage;
			continue;
		}
		int result;
		if (write) {
			result = ctx->write_at_physical(ctx->user, pa, buf + offset, RZ_MIN(count - offset, restOfPage));
		} else {
			result = ctx->read_at_physical(ctx->user, pa, buf + offset, RZ_MIN(count - offset, restOfPage));
		}
		address += restOfPage;
		offset += restOfPage;
		total += result;
	}
	return total;
}

int winkd_read_at_uva(WindCtx *ctx, ut64 address, uint8_t *buf, int count) {
	return winkd_op_at_uva(ctx, address, buf, count, false);
}

int winkd_write_at_uva(WindCtx *ctx, ut64 address, const uint8_t *buf, int count) {
	return winkd_op_at_uva(ctx, address, (uint8_t *)buf, count, true);
}

RzList *winkd_list_modules(WindCtx *ctx) {
	ut64 ptr, base;
	int list_entry_off = 0;
	const bool is_target_kernel = ctx->target.uniqueid <= 4;
	if (is_target_kernel) {
		if (!ctx->PsLoadedModuleList) {
			RZ_LOG_ERROR("No PsLoadedModuleList\n");
			return NULL;
		}
		ptr = ctx->PsLoadedModuleList;
		base = ptr;
		if (!winkd_read_at_uva(ctx, ptr, (uint8_t *)&ptr, 4 << ctx->is_64bit)) {
			RZ_LOG_ERROR("PsLoadedModuleList not present in mappings\n");
		}
		if (ptr == base) {
			return NULL;
		}
	} else {
		if (!ctx->target.peb) {
			RZ_LOG_ERROR("No PEB for target\n");
			return NULL;
		}

		// Grab the _PEB_LDR_DATA from PEB
		ut64 ldroff = ctx->is_64bit ? 0x18 : 0xC;
		if (!winkd_read_at_uva(ctx, ctx->target.peb + ldroff, (uint8_t *)&ptr, 4 << ctx->is_64bit)) {
			RZ_LOG_ERROR("PEB not present in target mappings\n");
			return NULL;
		}

		RZ_LOG_DEBUG("_PEB_LDR_DATA : 0x%016" PFMT64x "\n", ptr);

		// LIST_ENTRY InMemoryOrderModuleList
		ut64 mlistoff = ctx->is_64bit ? 0x20 : 0x14;

		base = ptr + mlistoff;

		winkd_read_at_uva(ctx, base, (uint8_t *)&ptr, 4 << ctx->is_64bit);

		// Offset of InMemoryOrderLinks inside _LDR_DATA_TABLE_ENTRY
		list_entry_off = (4 << ctx->is_64bit) * 2;
	}

	RZ_LOG_DEBUG("InMemoryOrderModuleList : 0x%016" PFMT64x "\n", ptr);

	RzList *ret = rz_list_newf(free);

	const ut64 baseoff = ctx->is_64bit ? 0x30 : 0x18;
	const ut64 sizeoff = ctx->is_64bit ? 0x40 : 0x20;
	const ut64 nameoff = ctx->is_64bit ? 0x48 : 0x24;
	const ut64 timestampoff = is_target_kernel
		? ctx->is_64bit ? 0x9c : 0x58
		: ctx->is_64bit ? 0x80
				: 0x44;
	do {

		ut64 next = 0;
		winkd_read_at_uva(ctx, ptr, (uint8_t *)&next, 4 << ctx->is_64bit);

		RZ_LOG_DEBUG("_%sLDR_DATA_TABLE_ENTRY : 0x%016" PFMT64x "\n", is_target_kernel ? "K" : "", next);
		if (!next || next == UT64_MAX) {
			RZ_LOG_WARN("Corrupted InMemoryOrderModuleList found at: 0x%" PFMT64x "\n", ptr);
			break;
		}

		ptr -= list_entry_off;

		WindModule *mod = RZ_NEW0(WindModule);
		if (!mod) {
			break;
		}
		winkd_read_at_uva(ctx, ptr + baseoff, (uint8_t *)&mod->addr, 4 << ctx->is_64bit);
		winkd_read_at_uva(ctx, ptr + sizeoff, (uint8_t *)&mod->size, 4);
		winkd_read_at_uva(ctx, ptr + timestampoff, (uint8_t *)&mod->timestamp, 4);

		ut16 length;
		winkd_read_at_uva(ctx, ptr + nameoff, (uint8_t *)&length, sizeof(ut16));

		ut64 bufferaddr = 0;
		int align = ctx->is_64bit ? sizeof(ut64) : sizeof(ut32);
		winkd_read_at_uva(ctx, ptr + nameoff + align, (uint8_t *)&bufferaddr, 4 << ctx->is_64bit);

		ut8 *unname = calloc((ut64)length + 2, 1);
		if (!unname) {
			break;
		}

		winkd_read_at_uva(ctx, bufferaddr, unname, length);

		mod->name = calloc((ut64)length + 1, 1);
		if (!mod->name) {
			break;
		}
		rz_str_utf16_to_utf8((ut8 *)mod->name, length + 1, unname, length + 2, true);
		free(unname);
		rz_list_append(ret, mod);

		ptr = next;
	} while (ptr != base);
	return ret;
}

WindThread *winkd_get_thread_at(WindCtx *ctx, ut64 address) {
	int running_offset;
	if (ctx->profile->build < 9200) {
		running_offset = ctx->is_64bit ? 0x49 : 0x39;
	} else {
		running_offset = ctx->is_64bit ? 0x71 : 0x55;
	}
	ut8 type = 0;
	if (!ctx->read_at_kernel_virtual(ctx->user, address, &type, 1)) {
		RZ_LOG_WARN("Failed to read DISPACHER_HEAD.Type at: 0x%" PFMT64x "\n", address);
		return NULL;
	}
	if ((type & 0x7f) != KOBJECT_THREAD) {
		RZ_LOG_WARN("KOBJECT at 0x%" PFMT64x " is not a thread.\n", address);
		return NULL;
	}
	ut64 entrypoint = 0;
	if (!ctx->read_at_kernel_virtual(ctx->user, address + O_(ET_Win32StartAddress), (uint8_t *)&entrypoint, 4 << ctx->is_64bit)) {
		RZ_LOG_WARN("Failed to read Win32StartAddress at: 0x%" PFMT64x "\n", address + O_(ET_Win32StartAddress));
		return NULL;
	}
	ut64 uniqueid = 0;
	if (!ctx->read_at_kernel_virtual(ctx->user, address + O_(ET_Cid) + O_(C_UniqueThread), (uint8_t *)&uniqueid, 4 << ctx->is_64bit)) {
		RZ_LOG_WARN("Failed to read UniqueThread at: 0x%" PFMT64x "\n", address + O_(ET_Cid) + O_(C_UniqueThread));
		return NULL;
	}
	bool running = false;
	if (!ctx->read_at_kernel_virtual(ctx->user, address + running_offset, (uint8_t *)&running, 1)) {
		RZ_LOG_WARN("Failed to read KTHREAD.Running at: 0x%" PFMT64x "\n", address + running_offset);
		return NULL;
	}
	WindThread *thread = calloc(1, sizeof(WindThread));
	if (!thread) {
		return NULL;
	}
	thread->uniqueid = uniqueid;
	thread->status = running ? 'r' : 's';
	thread->runnable = true;
	thread->ethread = address;
	thread->entrypoint = entrypoint;
	return thread;
}

RzList *winkd_list_threads(WindCtx *ctx) {
	RzList *ret;
	ut64 ptr, base;
	bool current_thread_found = false;
	ptr = ctx->target.eprocess;
	if (!ptr) {
		RZ_LOG_ERROR("No _EPROCESS for target\n");
		if (ctx->target_thread.ethread) {
			ret = rz_list_newf(free);
			goto get_cur_thread;
		}
		return NULL;
	}

	// Grab the ThreadListHead from _EPROCESS
	ctx->read_at_kernel_virtual(ctx->user, ptr + O_(E_ThreadListHead), (uint8_t *)&ptr, 4 << ctx->is_64bit);
	if (!ptr) {
		RZ_LOG_ERROR("No ThreadListHead for target\n");
		if (ctx->target_thread.ethread) {
			ret = rz_list_newf(free);
			goto get_cur_thread;
		}
		return NULL;
	}

	base = ptr;

	ret = rz_list_newf(free);

	do {
		ut64 next = 0;

		ctx->read_at_kernel_virtual(ctx->user, ptr, (uint8_t *)&next, 4 << ctx->is_64bit);
		if (!next || next == UT64_MAX) {
			RZ_LOG_WARN("Corrupted ThreadListEntry found at: 0x%" PFMT64x "\n", ptr);
			break;
		}
		if (next == base) {
			break;
		}

		// Adjust the ptr so that it points to the ETHREAD base
		ptr -= O_(ET_ThreadListEntry);

		WindThread *thread = winkd_get_thread_at(ctx, ptr);
		if (thread) {
			if (thread->ethread == ctx->target_thread.ethread) {
				current_thread_found = true;
			}
			rz_list_append(ret, thread);
		}
		ptr = next;
	} while (true);
get_cur_thread:
	if (!current_thread_found && ctx->target_thread.ethread) {
		WindThread *thread = winkd_get_thread_at(ctx, ctx->target_thread.ethread);
		if (thread) {
			rz_list_append(ret, thread);
		}
	}
	return ret;
}

#define PTE_VALID      0x0001
#define PTE_LARGEPAGE  0x0080
#define PTE_PROTOTYPE  0x0400
#define ARM_DESCRIPTOR 0x0002

static inline bool is_page_large(WindCtx *ctx, ut64 page_descriptor) {
	if (ctx->is_arm) {
		return !(page_descriptor & ARM_DESCRIPTOR);
	}
	return page_descriptor & PTE_LARGEPAGE;
}

// http://blogs.msdn.com/b/ntdebugging/archive/2010/02/05/understanding-pte-part-1-let-s-get-physical.aspx
// http://blogs.msdn.com/b/ntdebugging/archive/2010/04/14/understanding-pte-part2-flags-and-large-pages.aspx
// http://blogs.msdn.com/b/ntdebugging/archive/2010/06/22/part-3-understanding-pte-non-pae-and-x64.aspx
bool winkd_va_to_pa(WindCtx *ctx, ut64 directory_table, ut64 va, ut64 *pa) {
	ut64 pml4i, pdpi, pdi, pti;
	ut64 tmp, mask;

	if (ctx->is_64bit) {
		pti = (va >> 12) & 0x1ff;
		pdi = (va >> 21) & 0x1ff;
		pdpi = (va >> 30) & 0x1ff;
		pml4i = (va >> 39) & 0x1ff;
		// Grab the PageFrameNumber field off the _HARDWARE_PTE entry
		mask = 0x000000fffffff000;
	} else {
		if (ctx->is_pae) {
			pti = (va >> 12) & 0x1ff;
			pdi = (va >> 21) & 0x1ff;
			pdpi = (va >> 30) & 0x3;
			pml4i = 0;
		} else {
			pti = (va >> 12) & 0x3ff;
			pdi = (va >> 22) & 0x3ff;
			pdpi = 0;
			pml4i = 0;
		}
		// Grab the PageFrameNumber field off the _HARDWARE_PTE entry
		mask = 0xfffff000;
	}

	tmp = directory_table;
	tmp &= ~0x1f;

	if (ctx->is_64bit) {
		// PML4 lookup
		if (!ctx->read_at_physical(ctx->user, tmp + pml4i * 8, (ut8 *)&tmp, 8)) {
			return false;
		}
		tmp &= mask;
	}

	if (ctx->is_pae) {
		// PDPT lookup
		if (!ctx->read_at_physical(ctx->user, tmp + pdpi * 8, (ut8 *)&tmp, 8)) {
			return false;
		}
		tmp &= mask;
	}

	const int read_size = ctx->is_pae ? 8 : 4;

	// PDT lookup
	if (!ctx->read_at_physical(ctx->user, tmp + pdi * read_size, (ut8 *)&tmp, read_size)) {
		return false;
	}

	// Large page entry
	// The page size differs between pae and non-pae systems, the former points to 2MB pages while
	// the latter points to 4MB pages
	if (is_page_large(ctx, tmp)) {
		tmp = (tmp << 16) >> 16;
		*pa = ctx->is_pae ? (tmp & (~0x1fffff)) | (va & 0x1fffff) : (tmp & (~0x3fffff)) | (va & 0x3fffff);
		return true;
	}

	// PT lookup
	if (!ctx->read_at_physical(ctx->user, (tmp & mask) + pti * read_size, (ut8 *)&tmp, read_size)) {
		return false;
	}

	if (tmp & PTE_VALID) {
		*pa = (tmp & mask) | (va & 0xfff);
		return true;
	}

	if (tmp & PTE_PROTOTYPE) {
		// TODO : prototype PTE support
		RZ_LOG_ERROR("Prototype PTE lookup is currently missing!\n");
	}

	return false;
}

bool winkd_read_ver(KdCtx *ctx) {
	kd_req_t req = {
		0
	};
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return false;
	}

	req.req = 0x3146;
	req.cpu = ctx->cpu;

	winkd_lock_enter(ctx);

	ret = kd_send_data_packet(ctx->desc, KD_PACKET_TYPE_STATE_MANIPULATE,
		(ctx->seq_id ^= 1), (uint8_t *)&req, sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	winkd_lock_leave(ctx);

	kd_req_t *rr = PKT_REQ(pkt);

	if (rr->ret) {
		RZ_LOG_DEBUG("%s : req returned %08x\n", __FUNCTION__, rr->ret);
		free(pkt);
		return 0;
	}

	RZ_LOG_DEBUG("Major : %i Minor %i\n", rr->rz_ver.major, rr->rz_ver.minor);
	RZ_LOG_DEBUG("Protocol version : %i.%i\n", rr->rz_ver.proto_major, rr->rz_ver.proto_minor);
	RZ_LOG_DEBUG("Flags : %08x\n", rr->rz_ver.flags);
	RZ_LOG_DEBUG("Machine : %08x\n", rr->rz_ver.machine);
	RZ_LOG_DEBUG("Module list : %016" PFMT64x "\n", (ut64)rr->rz_ver.mod_addr);
	RZ_LOG_DEBUG("Debug block : %016" PFMT64x "\n", (ut64)rr->rz_ver.dbg_addr);

	if (rr->rz_ver.machine != KD_MACH_I386 && rr->rz_ver.machine != KD_MACH_AMD64) {
		RZ_LOG_ERROR("Unsupported target host\n");
		free(pkt);
		return 0;
	}

	if (!(rr->rz_ver.flags & DBGKD_VERS_FLAG_DATA)) {
		RZ_LOG_ERROR("No _KDDEBUGGER_DATA64 pointer has been supplied by the debugee!\n");
		free(pkt);
		return 0;
	}

	ctx->windctx.is_64bit = (rr->rz_ver.machine == KD_MACH_AMD64);

	ut64 ptr = 0;
	if (!winkd_read_at(ctx, rr->rz_ver.dbg_addr, (uint8_t *)&ptr, 4 << ctx->windctx.is_64bit)) {
		free(pkt);
		return false;
	}

	ctx->windctx.KdDebuggerDataBlock = ptr;

	RZ_LOG_DEBUG("_KDDEBUGGER_DATA64 at 0x%016" PFMT64x "\n", ctx->windctx.KdDebuggerDataBlock);

	// Thanks to this we don't have to find a way to read the cr4
	uint16_t pae_enabled;
	if (!winkd_read_at(ctx, ctx->windctx.KdDebuggerDataBlock + K_PaeEnabled, (uint8_t *)&pae_enabled, sizeof(uint16_t))) {
		free(pkt);
		return false;
	}

	ctx->windctx.is_pae = pae_enabled & 1;
	ctx->windctx.profile = winkd_get_profile(32 << ctx->windctx.is_64bit, rr->rz_ver.minor, winkd_get_sp(&ctx->windctx));
	if (!ctx->windctx.profile) {
		RZ_LOG_ERROR("Could not find a suitable profile for the target OS\n");
		free(pkt);
		return false;
	}
	free(pkt);
	return true;
error:
	winkd_lock_leave(ctx);
	return 0;
}

int winkd_sync(KdCtx *ctx) {
	int ret = -1;
	kd_packet_t *s;

	if (!ctx || !ctx->desc) {
		return 0;
	}

	if (ctx->syncd) {
		return 1;
	}

	winkd_lock_enter(ctx);

	if (ctx->desc->iob->type == KD_IO_NET) {
		// Read a KD packet to initialize KDNet interface
		// The first packet will always be type of KD_PACKET_TYPE_UNUSED
		ret = kd_read_packet(ctx->desc, &s);
		if (ret != KD_E_OK) {
			ret = 0;
			goto end;
		}
	}

	// Send the breakin packet
	if (iob_write(ctx->desc, (const uint8_t *)"b", 1) != 1) {
		ret = 0;
		goto end;
	}

	if (ctx->desc->iob->type == KD_IO_PIPE) {
		// Reset the host
		ret = kd_send_ctrl_packet(ctx->desc, KD_PACKET_TYPE_RESET, 0);
		if (ret != KD_E_OK) {
			ret = 0;
			goto end;
		}

		// Wait for the response
		ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_RESET, NULL);
		if (ret != KD_E_OK) {
			ret = 0;
			goto end;
		}
	}

	// Syncronize with the first KD_PACKET_TYPE_STATE_CHANGE64 packet
	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_STATE_CHANGE64, &s);
	if (ret != KD_E_OK) {
		ret = 0;
		goto end;
	}

	// Reset the sequence id
	ctx->seq_id = 0x80800001;

	kd_stc_64 *stc64 = (kd_stc_64 *)s->data;
	ctx->cpu = stc64->cpu;
	ctx->cpu_count = stc64->cpu_count;
	ctx->windctx.target.eprocess = 0;
	rz_list_free(ctx->plist_cache);
	ctx->plist_cache = NULL;
	rz_list_free(ctx->tlist_cache);
	ctx->tlist_cache = NULL;
	ctx->windctx.is_pae = 0;
	// We're ready to go
	ctx->syncd = 1;

	free(s);
	RZ_LOG_INFO("Sync done! (%i cpus found)\n", ctx->cpu_count);
	ret = 1;

end:
	winkd_lock_leave(ctx);
	return ret;
}

int winkd_continue(KdCtx *ctx) {
	kd_req_t req = {
		0
	};
	int ret;

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return 0;
	}
	req.req = DbgKdContinueApi;
	req.cpu = ctx->cpu;
	req.rz_cont.reason = 0x10001;
	// The meaning of 0x400 is unknown, but Windows doesn't
	// behave like suggested by ReactOS source
	req.rz_cont.tf = 0x400;

	winkd_lock_enter(ctx);

	ret = kd_send_data_packet(ctx->desc, KD_PACKET_TYPE_STATE_MANIPULATE,
		(ctx->seq_id ^= 1), (uint8_t *)&req, sizeof(kd_req_t), NULL, 0);
	if (ret == KD_E_OK) {
		ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
		if (ret == KD_E_OK) {
			rz_list_free(ctx->plist_cache);
			ctx->plist_cache = NULL;
			ret = true;
			goto end;
		}
	}
	ret = false;

end:
	winkd_lock_leave(ctx);
	return ret;
}

bool winkd_write_reg(KdCtx *ctx, const uint8_t *buf, int size) {
	kd_packet_t *pkt;
	kd_req_t req = {
		0
	};
	int ret;

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return false;
	}
	req.req = DbgKdSetContextApi;
	req.cpu = ctx->cpu;
	req.rz_ctx.flags = 0x1003F;

	RZ_LOG_DEBUG("Regwrite() size: %x\n", size);

	winkd_lock_enter(ctx);

	ret = kd_send_data_packet(ctx->desc, KD_PACKET_TYPE_STATE_MANIPULATE,
		(ctx->seq_id ^= 1), (uint8_t *)&req, sizeof(kd_req_t), buf, size);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	winkd_lock_leave(ctx);

	kd_req_t *rr = PKT_REQ(pkt);

	if (rr->ret) {
		RZ_LOG_DEBUG("%s: req returned %08x\n", __FUNCTION__, rr->ret);
		free(pkt);
		return 0;
	}

	free(pkt);

	return size;
error:
	winkd_lock_leave(ctx);
	return 0;
}

int winkd_read_reg(KdCtx *ctx, uint8_t *buf, int size) {
	kd_req_t req;
	kd_packet_t *pkt = NULL;
	int ret;

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return 0;
	}

	memset(&req, 0, sizeof(kd_req_t));

	req.req = DbgKdGetContextApi;
	req.cpu = ctx->cpu;

	req.rz_ctx.flags = 0x1003F;

	// Don't wait on the lock in read_reg since it's frequently called. Otherwise the user
	// will be forced to interrupt exit read_reg constantly while another task is in progress
	if (!winkd_lock_tryenter(ctx)) {
		goto error;
	}

	ret = kd_send_data_packet(ctx->desc, KD_PACKET_TYPE_STATE_MANIPULATE, (ctx->seq_id ^= 1), (uint8_t *)&req,
		sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	winkd_lock_leave(ctx);

	kd_req_t *rr = PKT_REQ(pkt);

	if (rr->ret) {
		RZ_LOG_DEBUG("%s: req returned %08x\n", __FUNCTION__, rr->ret);
		free(pkt);
		return 0;
	}

	memcpy(buf, rr->data, RZ_MIN(size, pkt->length - sizeof(*rr)));

	free(pkt);

	return size;
error:
	winkd_lock_leave(ctx);
	return 0;
}

int winkd_query_mem(KdCtx *ctx, const ut64 addr, int *address_space, int *flags) {
	kd_req_t req;
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return 0;
	}

	memset(&req, 0, sizeof(kd_req_t));

	req.req = DbgKdQueryMemoryApi;
	req.cpu = ctx->cpu;

	req.rz_query_mem.addr = addr;
	req.rz_query_mem.address_space = 0; // Tells the kernel that 'addr' is a virtual address

	winkd_lock_enter(ctx);

	ret = kd_send_data_packet(ctx->desc, KD_PACKET_TYPE_STATE_MANIPULATE, (ctx->seq_id ^= 1), (uint8_t *)&req,
		sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	winkd_lock_leave(ctx);

	kd_req_t *rr = PKT_REQ(pkt);

	if (rr->ret) {
		free(pkt);
		return 0;
	}

	if (address_space) {
		*address_space = rr->rz_query_mem.address_space;
	}
	if (flags) {
		*flags = rr->rz_query_mem.flags;
	}

	free(pkt);

	return ret;
error:
	winkd_lock_leave(ctx);
	return 0;
}

int winkd_bkpt(KdCtx *ctx, const ut64 addr, const int set, const int hw, int *handle) {
	kd_req_t req = {
		0
	};
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return 0;
	}

	req.req = set ? DbgKdWriteBreakPointApi : DbgKdRestoreBreakPointApi;
	req.cpu = ctx->cpu;

	if (set) {
		req.rz_set_bp.addr = addr;
	} else {
		req.rz_del_bp.handle = *handle;
	}

	winkd_lock_enter(ctx);

	ret = kd_send_data_packet(ctx->desc, KD_PACKET_TYPE_STATE_MANIPULATE, (ctx->seq_id ^= 1), (uint8_t *)&req,
		sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	winkd_lock_leave(ctx);

	kd_req_t *rr = PKT_REQ(pkt);

	if (rr->ret) {
		free(pkt);
		return 0;
	}
	*handle = rr->rz_set_bp.handle;
	ret = !!rr->ret;
	free(pkt);
	return ret;
error:
	winkd_lock_leave(ctx);
	return 0;
}

int winkd_read_at_phys(KdCtx *ctx, const ut64 offset, uint8_t *buf, const int count) {
	kd_req_t req = {
		0
	},
		 *rr;
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return 0;
	}
	req.req = DbgKdReadPhysicalMemoryApi;
	req.cpu = ctx->cpu;
	req.rz_mem.addr = offset;
	req.rz_mem.length = RZ_MIN(count, KD_MAX_PAYLOAD);
	req.rz_mem.read = 0; // Default caching option

	// Don't wait on the lock in read_reg since it's frequently called. Otherwise the user
	// will be forced to interrupt exit read_at_phys constantly while another task is in progress
	if (!winkd_lock_tryenter(ctx)) {
		goto error;
	}

	ret = kd_send_data_packet(ctx->desc, KD_PACKET_TYPE_STATE_MANIPULATE, (ctx->seq_id ^= 1),
		(uint8_t *)&req, sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	winkd_lock_leave(ctx);

	rr = PKT_REQ(pkt);

	if (rr->ret) {
		free(pkt);
		return 0;
	}

	memcpy(buf, rr->data, rr->rz_mem.read);
	ret = rr->rz_mem.read;
	free(pkt);
	return ret;
error:
	winkd_lock_leave(ctx);
	return 0;
}

int winkd_read_at(KdCtx *ctx, const ut64 offset, uint8_t *buf, const int count) {
	kd_req_t *rr, req = { 0 };
	kd_packet_t *pkt;
	int ret;

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return 0;
	}
	req.req = DbgKdReadVirtualMemoryApi;
	req.cpu = ctx->cpu;
	req.rz_mem.addr = offset;
	req.rz_mem.length = RZ_MIN(count, KD_MAX_PAYLOAD);

	// Don't wait on the lock in read_at since it's frequently called, including each
	// time "enter" is pressed. Otherwise the user will be forced to interrupt exit
	// read_registers constantly while another task is in progress
	if (!winkd_lock_tryenter(ctx)) {
		goto error;
	}

	ret = kd_send_data_packet(ctx->desc, KD_PACKET_TYPE_STATE_MANIPULATE,
		(ctx->seq_id ^= 1), (uint8_t *)&req, sizeof(kd_req_t), NULL, 0);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}
	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		return 0;
	}

	winkd_lock_leave(ctx);

	rr = PKT_REQ(pkt);

	if (rr->ret) {
		free(pkt);
		return 0;
	}

	memcpy(buf, rr->data, rr->rz_mem.read);
	ret = rr->rz_mem.read;
	free(pkt);
	return ret;
error:
	winkd_lock_leave(ctx);
	return 0;
}

int winkd_write_at(KdCtx *ctx, const ut64 offset, const uint8_t *buf, const int count) {
	kd_packet_t *pkt;
	kd_req_t req = {
		0
	},
		 *rr;
	int payload, ret;

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return 0;
	}

	payload = RZ_MIN(count, KD_MAX_PAYLOAD - sizeof(kd_req_t));
	req.req = DbgKdWriteVirtualMemoryApi;
	req.cpu = ctx->cpu;
	req.rz_mem.addr = offset;
	req.rz_mem.length = payload;

	winkd_lock_enter(ctx);

	ret = kd_send_data_packet(ctx->desc, KD_PACKET_TYPE_STATE_MANIPULATE,
		(ctx->seq_id ^= 1), (uint8_t *)&req,
		sizeof(kd_req_t), buf, payload);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	winkd_lock_leave(ctx);

	rr = PKT_REQ(pkt);

	if (rr->ret) {
		free(pkt);
		return 0;
	}

	ret = rr->rz_mem.read;
	free(pkt);
	return ret;
error:
	winkd_lock_leave(ctx);
	return 0;
}

int winkd_write_at_phys(KdCtx *ctx, const ut64 offset, const uint8_t *buf, const int count) {
	kd_packet_t *pkt;
	kd_req_t req;
	int ret;
	int payload;

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return 0;
	}

	payload = RZ_MIN(count, KD_MAX_PAYLOAD - sizeof(kd_req_t));

	memset(&req, 0, sizeof(kd_req_t));

	req.req = DbgKdWritePhysicalMemoryApi;
	req.cpu = ctx->cpu;

	req.rz_mem.addr = offset;
	req.rz_mem.length = payload;
	req.rz_mem.read = 0; // Default caching option

	winkd_lock_enter(ctx);

	ret = kd_send_data_packet(ctx->desc, KD_PACKET_TYPE_STATE_MANIPULATE,
		(ctx->seq_id ^= 1), (uint8_t *)&req, sizeof(kd_req_t), buf, payload);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}

	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_STATE_MANIPULATE, &pkt);
	if (ret != KD_E_OK) {
		goto error;
	}

	winkd_lock_leave(ctx);

	kd_req_t *rr = PKT_REQ(pkt);

	if (rr->ret) {
		free(pkt);
		return 0;
	}
	ret = rr->rz_mem.read;
	free(pkt);
	return ret;
error:
	winkd_lock_leave(ctx);
	return 0;
}

void winkd_break(void *arg) {
	// This command shouldn't be wrapped by locks since it can always be sent and we don't
	// want break queued up after another background task
	KdCtx *ctx = (KdCtx *)arg;
	(void)iob_write(ctx->desc, (const uint8_t *)"b", 1);
}

int winkd_break_read(KdCtx *ctx) {
#if __WINDOWS__ && defined(_MSC_VER)
	static BOOL(WINAPI * w32_CancelIoEx)(HANDLE, LPOVERLAPPED) = NULL;
	if (!w32_CancelIoEx) {
		w32_CancelIoEx = (BOOL(WINAPI *)(HANDLE, LPOVERLAPPED))
			GetProcAddress(GetModuleHandle(TEXT("kernel32")),
				"CancelIoEx");
	}
	if (w32_CancelIoEx) {
		w32_CancelIoEx(ctx->desc, NULL);
	}
#endif
	return 1;
}
