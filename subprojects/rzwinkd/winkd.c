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

#define KOBJECT_PROCESS 3
#define KOBJECT_THREAD  6

bool winkd_lock_enter(RZ_BORROW RZ_NONNULL KdCtx *ctx) {
	rz_cons_break_push(winkd_break, ctx);
	while (!rz_th_lock_tryenter(ctx->dontmix)) {
		if (rz_cons_is_breaked()) {
			rz_cons_break_pop();
			return false;
		}
	}
	return true;
}

bool winkd_lock_leave(RZ_BORROW RZ_NONNULL KdCtx *ctx) {
	rz_cons_break_pop();
	rz_th_lock_leave(ctx->dontmix);
	return true;
}

int winkd_get_sp(RZ_BORROW RZ_NONNULL WindCtx *ctx) {
	ut8 buf[sizeof(ut64)] = { 0 };
	// Grab the CmNtCSDVersion field to extract the Service Pack number
	if (!ctx->read_at_kernel_virtual(ctx->user, ctx->KdDebuggerDataBlock + K_CmNtCSDVersion, buf, sizeof(ut64))) {
		RZ_LOG_DEBUG("Failed to read at %" PFMT64x "\n", ctx->KdDebuggerDataBlock + K_CmNtCSDVersion);
		return 0;
	}
	ut64 ptr = rz_read_le64(buf);
	if (!ctx->read_at_kernel_virtual(ctx->user, ptr, buf, sizeof(ut64))) {
		RZ_LOG_DEBUG("Failed to read at %" PFMT64x "\n", ptr);
		return 0;
	}
	ut64 res = rz_read_le64(buf);
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

int winkd_get_bits(RZ_BORROW RZ_NONNULL WindCtx *ctx) {
	return ctx->is_64bit ? RZ_SYS_BITS_64 : RZ_SYS_BITS_32;
}

int winkd_get_cpus(RZ_BORROW RZ_NONNULL KdCtx *ctx) {
	if (!ctx) {
		return -1;
	}
	return ctx->cpu_count;
}

bool winkd_set_cpu(RZ_BORROW RZ_NONNULL KdCtx *ctx, int cpu) {
	if (!ctx || cpu > ctx->cpu_count) {
		return false;
	}
	ctx->cpu = cpu;
	return true;
}

int winkd_get_cpu(RZ_BORROW RZ_NONNULL KdCtx *ctx) {
	if (!ctx) {
		return -1;
	}
	return ctx->cpu;
}

bool winkd_set_target(RZ_BORROW RZ_NONNULL WindCtx *ctx, ut32 pid, ut32 tid) {
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
			t = rz_list_first_val(l);
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

ut32 winkd_get_target(RZ_BORROW RZ_NONNULL WindCtx *ctx) {
	return ctx->target.uniqueid;
}

ut32 winkd_get_target_thread(RZ_BORROW RZ_NONNULL WindCtx *ctx) {
	return ctx->target_thread.uniqueid;
}

ut64 winkd_get_target_base(RZ_BORROW RZ_NONNULL WindCtx *ctx) {
	ut8 tmp[8] = { 0 };
	ut64 address = ctx->target.peb + O_(P_ImageBaseAddress);

	if (!winkd_read_at_uva(ctx, address, tmp, ctx->is_64bit ? sizeof(ut64) : sizeof(ut32))) {
		return 0;
	}

	return rz_read_ble(tmp, false, ctx->is_64bit ? 64 : 32);
}

KdCtx *winkd_kdctx_new(RZ_BORROW RZ_NONNULL io_desc_t *desc) {
	KdCtx *ctx = RZ_NEW0(KdCtx);
	if (!ctx) {
		return NULL;
	}
	ctx->dontmix = rz_th_lock_new(true);
	ctx->desc = desc;
	return ctx;
}

void winkd_kdctx_free(RZ_OWN KdCtx **ctx) {
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
	free((*ctx)->kernel_module.name);
	RZ_FREE(*ctx);
}

#define PKT_REQ(p) ((kd_req_t *)(((kd_packet_t *)p)->data))
#define PKT_STC(p) ((kd_stc_64 *)(((kd_packet_t *)p)->data))
#define PKT_IO(p)  ((kd_ioc_t *)(((kd_packet_t *)p)->data))

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

static int do_io_reply(RZ_BORROW RZ_NONNULL KdCtx *ctx, kd_packet_t *pkt) {
	kd_ioc_t ioc = {
		0
	};
	int ret;
	ioc.req = PKT_IO(pkt)->req;
	ioc.ret = KD_RET_ENOENT;
	while (!winkd_lock_enter(ctx)) {
	};
	ret = kd_send_data_packet(ctx->desc, KD_PACKET_TYPE_FILE_IO,
		ctx->seq_id, (ut8 *)&ioc, sizeof(kd_ioc_t), NULL, 0);
	if (ret != KD_E_OK) {
		goto error;
	}
	RZ_LOG_DEBUG("Waiting for io_reply ack...\n");
	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
	if (ret != KD_E_OK) {
		goto error;
	}
	winkd_lock_leave(ctx);
	RZ_LOG_DEBUG("Ack received, restore flow\n");
	return true;
error:
	winkd_lock_leave(ctx);
	return 0;
}

static inline bool load_symbol_path_is_valid(kd_packet_t *pkt) {
	kd_stc_64 *stc = PKT_STC(pkt);
	return stc->load_symbols.pathsize &&
		(stc->load_symbols.pathsize < pkt->length - (rz_offsetof(kd_stc_64, load_symbols.unload) + sizeof(stc->load_symbols.unload)));
}

int winkd_wait_packet(RZ_BORROW RZ_NONNULL KdCtx *ctx, const ut32 type, RZ_NULLABLE RZ_OUT kd_packet_t **p) {
	kd_packet_t *pkt = NULL;
	int ret;
	if (p) {
		*p = NULL;
	}

	bool is_repeated_packet;
	do {
		free(pkt);
		// Try to read a whole packet
		ret = kd_read_packet(ctx->desc, &pkt);
		if (ret != KD_E_OK) {
			return ret;
		}
		RZ_LOG_DEBUG("=== Received Packet ===\n");
		RZ_LOG_DEBUG("PACKET ID : 0x%x\n", pkt->id);
		is_repeated_packet = ctx->last_received_id == pkt->id;
		if (is_repeated_packet) {
			RZ_LOG_DEBUG("Repeated packet, skipping\n");
		} else if (pkt->leader == KD_PACKET_DATA) {
			ctx->last_received_id = pkt->id;
		}
		if (pkt->type == KD_PACKET_TYPE_UNUSED) {
			is_repeated_packet = true;
			continue;
		}
	} while (is_repeated_packet);

	if (pkt->type != type) {
		RZ_LOG_DEBUG("We were not waiting for this: %02x Expected: %02x\n", pkt->type, type);
	}
	if (pkt->leader == KD_PACKET_DATA && pkt->type == KD_PACKET_TYPE_STATE_CHANGE64) {
		RZ_LOG_VERBOSE("Got STATE_CHANGE64 packet\n");
		kd_stc_64 *stc = PKT_STC(pkt);
		if (stc->state == DbgKdExceptionStateChange) {
			RZ_LOG_VERBOSE("    Exception\n");
			RZ_LOG_VERBOSE("        Code   : %08" PFMT32x "\n", stc->exception.code);
			RZ_LOG_VERBOSE("        Flags  : %08" PFMT32x "\n", stc->exception.flags);
			RZ_LOG_VERBOSE("        Record : %016" PFMT64x "\n", stc->exception.ex_record);
			RZ_LOG_VERBOSE("        Addr   : %016" PFMT64x "\n", stc->exception.ex_addr);
			if (ctx->breaked) {
				RZ_LOG_VERBOSE("    BREAKED\n");
			}
		} else if (stc->state == DbgKdLoadSymbolsStateChange) {
			RZ_LOG_VERBOSE(stc->load_symbols.unload ? "    Unload Symbols\n" : "    Load Symbols\n");
			RZ_LOG_VERBOSE("        Path Size : %016" PFMT64x "\n", stc->load_symbols.pathsize);
			RZ_LOG_VERBOSE("        Base      : %016" PFMT64x "\n", stc->load_symbols.base);
			RZ_LOG_VERBOSE("        Checksum  : %08" PFMT32x "\n", stc->load_symbols.checksum);
			RZ_LOG_VERBOSE("        ImageSize : %08" PFMT32x "\n", stc->load_symbols.size);
			if (load_symbol_path_is_valid(pkt)) {
				char *path = (char *)pkt->data + pkt->length - stc->load_symbols.pathsize;
				path[stc->load_symbols.pathsize - 1] = 0;
				RZ_LOG_VERBOSE("        Image     : %s\n", path);
				if (rz_str_endswith(path, "\\ntoskrnl.exe")) {
					ctx->kernel_module.addr = stc->load_symbols.base;
					ctx->kernel_module.size = stc->load_symbols.size;
					ctx->kernel_module.name = strdup(path);
				}
			}
		} else if (stc->state == DbgKdCommandStringStateChange) {
			RZ_LOG_VERBOSE("CommandString\n");
		} else {
			RZ_LOG_WARN("Unknown state change packet type: 0x%" PFMT32x "\n", (ut32)pkt->type);
		}
	} else if (pkt->leader == KD_PACKET_DATA && pkt->type == KD_PACKET_TYPE_FILE_IO) {
		RZ_LOG_DEBUG("File IO\n");
		RZ_LOG_DEBUG("  req: %08" PFMT32x "\n", PKT_IO(pkt)->req);
		RZ_LOG_DEBUG("  ret: %08" PFMT32x "\n", PKT_IO(pkt)->ret);
		RZ_LOG_DEBUG("Replying IO\n");
		do_io_reply(ctx, pkt);
	} else if (pkt->leader == KD_PACKET_DATA && pkt->type == KD_PACKET_TYPE_STATE_MANIPULATE) {
		RZ_LOG_DEBUG("State_manipulate\n");
		RZ_LOG_DEBUG("  req: %08" PFMT32x "\n", PKT_REQ(pkt)->req);
		RZ_LOG_DEBUG("  cpu_level: %08x\n", PKT_REQ(pkt)->cpu_level);
		RZ_LOG_DEBUG("  cpu: %i\n", PKT_REQ(pkt)->cpu);
		RZ_LOG_DEBUG("  ret: %08" PFMT32x "\n", PKT_REQ(pkt)->ret);
	}

	if (pkt->leader == KD_PACKET_CTRL) {
		switch (pkt->type) {
		case KD_PACKET_TYPE_ACKNOWLEDGE:
			RZ_LOG_DEBUG("ACK received\n");
			if (pkt->id == ctx->seq_id) {
				ctx->seq_id ^= 1;
			}
			if (type == KD_PACKET_TYPE_ACKNOWLEDGE) {
				free(pkt);
				return KD_E_OK;
			}
			break;
		case KD_PACKET_TYPE_RESET:
			RZ_LOG_DEBUG("Reset received\n");
			ctx->seq_id = KD_INITIAL_PACKET_ID;
			ctx->last_received_id = KD_INITIAL_PACKET_ID;
			free(pkt);
			if (type == KD_PACKET_TYPE_RESET) {
				return KD_E_OK;
			}
			return KD_E_MALFORMED;
		case KD_PACKET_TYPE_RESEND:
			// The host didn't like our request
			rz_sys_backtrace();
			RZ_LOG_DEBUG("Waoh. You probably sent a malformed packet!\n");
			free(pkt);
			return KD_E_MALFORMED;
		}
	}
	if (pkt->type != type) {
		free(pkt);
		if (ctx->breaked) {
			ctx->breaked = false;
			return KD_E_BREAK;
		} else {
			return KD_E_MALFORMED;
		}
	}
	ctx->breaked = false;
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

void winkd_walk_vadtree(RZ_BORROW RZ_NONNULL WindCtx *ctx, ut64 address, ut64 parent, RzList *out) {
	ut8 buf[4];
	const ut8 ptr_size = ctx->is_64bit ? sizeof(ut64) : sizeof(ut32);
	const ut64 self = address;
	const ut64 tag_addr = self - ptr_size - 4;

	if (ctx->read_at_kernel_virtual(ctx->user, tag_addr, buf, 4) != 4) {
		RZ_LOG_DEBUG("Failed to read vadtree\n");
		return;
	}

	if (memcmp(buf, "Vad", 3)) {
		RZ_LOG_DEBUG("Failed to read VAD: Tag is not 'Vad'\n");
		return;
	}

	const bool is_vad_short = buf[3] == 'S';

	ut64 left = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, address);
	address += ptr_size;
	ut64 right = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, address);
	address += ptr_size;
	ut64 parent_value = winkd_read_ptr_at(ctx, ctx->read_at_kernel_virtual, address);
	address += ptr_size;

	if (parent != UT64_MAX && (parent_value & ~3) != (parent & ~3)) {
		RZ_LOG_DEBUG("Wrong parent!\n");
		return;
	}

	if (ctx->read_at_kernel_virtual(ctx->user, address, buf, 4) != 4) {
		RZ_LOG_DEBUG("Failed to read vadtree\n");
		return;
	}
	address += 4;
	const ut64 start_vpn = rz_read_le32(buf);

	if (ctx->read_at_kernel_virtual(ctx->user, address, buf, 4) != 4) {
		RZ_LOG_DEBUG("Failed to read vadtree\n");
		return;
	}
	address += 4;
	const ut64 end_vpn = rz_read_le32(buf);
	ut8 start_vpn_high = 0;
	ut8 end_vpn_high = 0;
	if (ctx->is_64bit) {
		if (ctx->read_at_kernel_virtual(ctx->user, address, &start_vpn_high, 1) != 1) {
			RZ_LOG_DEBUG("Failed to read vadtree\n");
			return;
		}
		address++;
		if (ctx->read_at_kernel_virtual(ctx->user, address, &end_vpn_high, 1) != 1) {
			RZ_LOG_DEBUG("Failed to read vadtree\n");
			return;
		}
		address++;
	}

	const ut64 start = (start_vpn | (ut64)start_vpn_high << 32) << 12;
	const ut64 end = (((end_vpn | (ut64)end_vpn_high << 32) + 1) << 12) - 1;

	if (!is_vad_short) {
		// TODO: get file info that vad is based from
		// either in nt!_MMVAD->FileObject or in nt!_MMVAD->Subsection->ControlArea->FilePointer
	}

	WindMap *map = RZ_NEW0(WindMap);
	if (!map) {
		return;
	}
	map->start = start;
	map->end = end;
	// TODO: get permission from nt!_MMVAD_FLAGS bitfield,
	// Protection is an index into nt!MmProtectToValue
	// that contains the PAGE_* memory protection constants
	map->perm = RZ_PERM_RWX;
	rz_list_append(out, map);

	if (left) {
		winkd_walk_vadtree(ctx, left, self, out);
	}
	if (right) {
		winkd_walk_vadtree(ctx, right, self, out);
	}
}

RzList /*<WindMap *>*/ *winkd_list_maps(RZ_BORROW RZ_NONNULL WindCtx *ctx) {
	if (!ctx->target.vadroot) {
		return NULL;
	}
	RzList *maps = rz_list_newf(free);
	if (!maps) {
		return NULL;
	}
	winkd_walk_vadtree(ctx, ctx->target.vadroot, UT64_MAX, maps);
	return maps;
}

WindProc *winkd_get_process_at(RZ_BORROW RZ_NONNULL WindCtx *ctx, ut64 address) {
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

RzList /*<WindProc *>*/ *winkd_list_process(RZ_BORROW RZ_NONNULL WindCtx *ctx) {
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

int winkd_op_at_uva(RZ_BORROW RZ_NONNULL WindCtx *ctx, ut64 address, ut8 *buf, int count, bool write) {
	ut32 total = 0;
	ut32 offset = 0;
	const ut64 end = address + count;
	while (address < end) {
		ut64 pa;
		const ut32 restOfPage = 0x1000 - (address & 0xfff);
		if (!winkd_va_to_pa(ctx, ctx->target.dir_base_table, address, &pa)) {
			RZ_LOG_VERBOSE("0x%" PFMT64x " not mapped\n", address);
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
		address += result;
		offset += result;
		total += result;
	}
	return total;
}

int winkd_read_at_uva(RZ_BORROW RZ_NONNULL WindCtx *ctx, ut64 address, RZ_BORROW RZ_NONNULL RZ_OUT ut8 *buf, int count) {
	return winkd_op_at_uva(ctx, address, buf, count, false);
}

int winkd_write_at_uva(RZ_BORROW RZ_NONNULL WindCtx *ctx, ut64 address, RZ_BORROW RZ_NONNULL RZ_IN const ut8 *buf, int count) {
	return winkd_op_at_uva(ctx, address, (ut8 *)buf, count, true);
}

int map_comparator(const void *m1, const void *m2, void *user) {
	const RzDebugMap *map1 = m1;
	const RzDebugMap *map2 = m2;
	return map1->addr > map2->addr ? 1 : map1->addr < map2->addr ? -1
								     : 0;
}

void winkd_windmodule_free(void *ptr) {
	WindModule *mod = ptr;
	free(mod->name);
	free(mod);
}

static int read_at_uva_or_kernel(RZ_BORROW RZ_NONNULL WindCtx *ctx, ut64 address, ut8 *buf, int count) {
	const bool is_target_kernel = ctx->target.uniqueid <= 4;
	if (is_target_kernel) {
		return ctx->read_at_kernel_virtual(ctx->user, address, buf, count);
	}
	return winkd_read_at_uva(ctx, address, buf, count);
}

RzList /*<WindModule *>*/ *winkd_list_modules(RZ_BORROW RZ_NONNULL WindCtx *ctx) {
	RzList *ret = rz_list_newf(winkd_windmodule_free);
	if (!ret) {
		return NULL;
	}
	ut8 tmp[8] = { 0 };
	ut64 ptr, base;
	int list_entry_off = 0;
	const bool is_target_kernel = ctx->target.uniqueid <= 4;
	if (is_target_kernel) {
		if (!ctx->PsLoadedModuleList) {
			RZ_LOG_ERROR("No PsLoadedModuleList\n");
			return ret;
		}
		base = ctx->PsLoadedModuleList;
		if (!ctx->read_at_kernel_virtual(ctx->user, base, tmp, ctx->is_64bit ? sizeof(ut64) : sizeof(ut32))) {
			RZ_LOG_ERROR("PsLoadedModuleList not present in mappings (0x%08" PFMT64x ")\n", base);
		}
		ptr = rz_read_ble(tmp, false, ctx->is_64bit ? 64 : 32);
		if (ptr == base) {
			return ret;
		}
	} else {
		// Get kernel modules
		const ut32 saved_target = ctx->target.uniqueid;
		ctx->target.uniqueid = 0;
		RzList *kernel_modules = winkd_list_modules(ctx);
		ctx->target.uniqueid = saved_target;

		if (kernel_modules) {
			rz_list_join(ret, kernel_modules);
			rz_list_free(kernel_modules);
		}

		if (!ctx->target.peb) {
			RZ_LOG_ERROR("No PEB for target\n");
			return ret;
		}

		// Grab the _PEB_LDR_DATA from PEB
		ut64 ldroff = ctx->is_64bit ? 0x18 : 0xC;
		if (!winkd_read_at_uva(ctx, ctx->target.peb + ldroff, tmp, ctx->is_64bit ? sizeof(ut64) : sizeof(ut32))) {
			RZ_LOG_ERROR("PEB not present in target mappings\n");
			return ret;
		}

		ptr = rz_read_ble(tmp, false, ctx->is_64bit ? 64 : 32);
		RZ_LOG_DEBUG("_PEB_LDR_DATA : 0x%016" PFMT64x "\n", ptr);

		// LIST_ENTRY InMemoryOrderModuleList
		ut64 mlistoff = ctx->is_64bit ? 0x20 : 0x14;

		base = ptr + mlistoff;

		winkd_read_at_uva(ctx, base, tmp, ctx->is_64bit ? sizeof(ut64) : sizeof(ut32));

		ptr = rz_read_ble(tmp, false, ctx->is_64bit ? 64 : 32);
		// Offset of InMemoryOrderLinks inside _LDR_DATA_TABLE_ENTRY
		list_entry_off = (ctx->is_64bit ? (sizeof(ut64) << 1) : (sizeof(ut32) << 1));
	}

	RZ_LOG_DEBUG("InMemoryOrderModuleList : 0x%016" PFMT64x "\n", ptr);

	const ut64 baseoff = ctx->is_64bit ? 0x30 : 0x18;
	const ut64 sizeoff = ctx->is_64bit ? 0x40 : 0x20;
	const ut64 nameoff = ctx->is_64bit ? 0x48 : 0x24;
	const ut64 timestampoff = is_target_kernel
		? ctx->is_64bit ? 0x9c : 0x58
		: ctx->is_64bit ? 0x80
				: 0x44;
	do {

		read_at_uva_or_kernel(ctx, ptr, tmp, ctx->is_64bit ? sizeof(ut64) : sizeof(ut32));
		ut64 next = rz_read_ble(tmp, false, ctx->is_64bit ? 64 : 32);

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

		read_at_uva_or_kernel(ctx, ptr + baseoff, tmp, ctx->is_64bit ? sizeof(ut64) : sizeof(ut32));
		mod->addr = rz_read_ble(tmp, false, ctx->is_64bit ? 64 : 32);

		read_at_uva_or_kernel(ctx, ptr + sizeoff, tmp, 4);
		mod->size = rz_read_le32(tmp);

		read_at_uva_or_kernel(ctx, ptr + timestampoff, tmp, 4);
		mod->timestamp = rz_read_le32(tmp);

		read_at_uva_or_kernel(ctx, ptr + nameoff, tmp, sizeof(ut16));
		ut64 length = rz_read_le16(tmp);

		int align = ctx->is_64bit ? sizeof(ut64) : sizeof(ut32);
		read_at_uva_or_kernel(ctx, ptr + nameoff + align, tmp, ctx->is_64bit ? sizeof(ut64) : sizeof(ut32));
		ut64 bufferaddr = rz_read_ble(tmp, false, ctx->is_64bit ? 64 : 32);

		ut8 *unname = calloc(length + 2, 1);
		if (!unname) {
			break;
		}
		read_at_uva_or_kernel(ctx, bufferaddr, unname, length);

		mod->name = (char *)rz_str_utf16_to_utf8(unname, length + 2, false);
		free(unname);
		if (!mod->name) {
			break;
		}
		rz_list_add_sorted(ret, mod, map_comparator, NULL);

		ptr = next;
	} while (ptr != base);
	return ret;
}

WindThread *winkd_get_thread_at(RZ_BORROW RZ_NONNULL WindCtx *ctx, ut64 address) {
	ut8 tmp[8] = { 0 };
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
	if (!ctx->read_at_kernel_virtual(ctx->user, address + O_(ET_Win32StartAddress), tmp, ctx->is_64bit ? sizeof(ut64) : sizeof(ut32))) {
		RZ_LOG_WARN("Failed to read Win32StartAddress at: 0x%" PFMT64x "\n", address + O_(ET_Win32StartAddress));
		return NULL;
	}
	ut64 entrypoint = rz_read_ble(tmp, false, ctx->is_64bit ? 64 : 32);

	if (!ctx->read_at_kernel_virtual(ctx->user, address + O_(ET_Cid) + O_(C_UniqueThread), tmp, ctx->is_64bit ? sizeof(ut64) : sizeof(ut32))) {
		RZ_LOG_WARN("Failed to read UniqueThread at: 0x%" PFMT64x "\n", address + O_(ET_Cid) + O_(C_UniqueThread));
		return NULL;
	}
	ut64 uniqueid = rz_read_ble(tmp, false, ctx->is_64bit ? 64 : 32);
	ut8 running = 0;
	if (!ctx->read_at_kernel_virtual(ctx->user, address + running_offset, &running, 1)) {
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

RzList /*<WindThread *>*/ *winkd_list_threads(RZ_BORROW RZ_NONNULL WindCtx *ctx) {
	ut8 tmp[8] = { 0 };
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
	ctx->read_at_kernel_virtual(ctx->user, ptr + O_(E_ThreadListHead), tmp, ctx->is_64bit ? sizeof(ut64) : sizeof(ut32));
	ptr = rz_read_ble(tmp, false, ctx->is_64bit ? 64 : 32);
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
		ctx->read_at_kernel_virtual(ctx->user, ptr, tmp, ctx->is_64bit ? sizeof(ut64) : sizeof(ut32));
		ut64 next = rz_read_ble(tmp, false, ctx->is_64bit ? 64 : 32);
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

static inline bool is_page_large(RZ_BORROW RZ_NONNULL WindCtx *ctx, ut64 page_descriptor) {
	if (ctx->is_arm) {
		return !(page_descriptor & ARM_DESCRIPTOR);
	}
	return page_descriptor & PTE_LARGEPAGE;
}

// http://blogs.msdn.com/b/ntdebugging/archive/2010/02/05/understanding-pte-part-1-let-s-get-physical.aspx
// http://blogs.msdn.com/b/ntdebugging/archive/2010/04/14/understanding-pte-part2-flags-and-large-pages.aspx
// http://blogs.msdn.com/b/ntdebugging/archive/2010/06/22/part-3-understanding-pte-non-pae-and-x64.aspx
bool winkd_va_to_pa(RZ_BORROW RZ_NONNULL WindCtx *ctx, ut64 directory_table, ut64 va, RZ_BORROW RZ_NONNULL RZ_OUT ut64 *pa) {
	ut64 pml4i, pdpi, pdi, pti;
	ut64 tmp, mask;

	ut8 buf64[sizeof(ut64)] = { 0 };

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
		if (!ctx->read_at_physical(ctx->user, tmp + pml4i * 8, buf64, sizeof(buf64))) {
			return false;
		}
		tmp = rz_read_le64(buf64);
		tmp &= mask;
	}

	if (ctx->is_pae) {
		// PDPT lookup
		if (!ctx->read_at_physical(ctx->user, tmp + pdpi * 8, buf64, sizeof(buf64))) {
			return false;
		}
		tmp = rz_read_le64(buf64);
		tmp &= mask;
	}

	const int read_size = ctx->is_pae ? 8 : 4;

	// PDT lookup
	if (!ctx->read_at_physical(ctx->user, tmp + pdi * read_size, buf64, read_size)) {
		return false;
	}

	tmp = ctx->is_pae ? rz_read_le64(buf64) : rz_read_le32(buf64);

	// Large page entry
	// The page size differs between pae and non-pae systems, the former points to 2MB pages while
	// the latter points to 4MB pages
	if (is_page_large(ctx, tmp)) {
		tmp = (tmp << 16) >> 16;
		*pa = ctx->is_pae ? (tmp & (~0x1fffff)) | (va & 0x1fffff) : (tmp & (~0x3fffff)) | (va & 0x3fffff);
		return true;
	}

	// PT lookup
	if (!ctx->read_at_physical(ctx->user, (tmp & mask) + pti * read_size, buf64, read_size)) {
		return false;
	}

	tmp = ctx->is_pae ? rz_read_le64(buf64) : rz_read_le32(buf64);

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

static bool winkd_send_state_manipulate_req(RZ_BORROW RZ_NONNULL KdCtx *ctx, kd_req_t *req, RZ_BORROW RZ_NULLABLE RZ_IN const ut8 *buf, const ut32 buf_len, RZ_BORROW RZ_NULLABLE RZ_OUT kd_packet_t **pkt) {
	if (pkt) {
		*pkt = NULL;
	}
	int ret;
	if (!winkd_lock_enter(ctx)) {
		return false;
	}
	const ut32 cur_seq_id = ctx->seq_id;
	do {
		ret = kd_send_data_packet(ctx->desc, KD_PACKET_TYPE_STATE_MANIPULATE,
			ctx->seq_id, (ut8 *)req, sizeof(kd_req_t), buf, buf_len);
		if (ret != KD_E_OK) {
			break;
		}

		ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
		if (ret == KD_E_OK) {
			ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_STATE_MANIPULATE, pkt);
			if (ret == KD_E_OK) {
				kd_req_t *rr = PKT_REQ(*pkt);
				if (rr->req != req->req) {
					RZ_LOG_DEBUG("Got wrong packet %x for request %x\n", rr->req, req->req);
					ret = KD_E_MALFORMED;
				} else if ((*pkt)->length < sizeof(kd_req_t)) {
					RZ_LOG_DEBUG("Got too small of a packet: %u bytes\n", (*pkt)->length);
					ret = KD_E_MALFORMED;
				}
			}
		}
		if (rz_cons_is_breaked()) {
			break;
		}
	} while (ret == KD_E_MALFORMED);

	if (ret == KD_E_OK && cur_seq_id == ctx->seq_id) {
		RZ_LOG_DEBUG("We didn't get and ACK but got the packet\n");
		ctx->seq_id ^= 1;
	}

	winkd_lock_leave(ctx);

	if (ret != KD_E_OK) {
		return false;
	}

	kd_req_t *rr = PKT_REQ(*pkt);

	if (rr->ret) {
		RZ_LOG_DEBUG("%s : req returned %08x\n", __FUNCTION__, rr->ret);
		RZ_FREE(*pkt);
		return false;
	}

	return true;
}

bool winkd_read_ver(RZ_BORROW RZ_NONNULL KdCtx *ctx) {
	kd_req_t req = { 0 };
	kd_packet_t *pkt;

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return false;
	}

	req.req = 0x3146;
	req.cpu = ctx->cpu;

	if (!winkd_send_state_manipulate_req(ctx, &req, NULL, 0, &pkt)) {
		return false;
	}

	kd_req_t *rr = PKT_REQ(pkt);

	RZ_LOG_DEBUG("Major : %i Minor %i\n", rr->rz_ver.major, rr->rz_ver.minor);
	RZ_LOG_DEBUG("Protocol version : %i.%i\n", rr->rz_ver.proto_major, rr->rz_ver.proto_minor);
	RZ_LOG_DEBUG("Flags : %08x\n", rr->rz_ver.flags);
	RZ_LOG_DEBUG("Machine : %08x\n", rr->rz_ver.machine);
	RZ_LOG_DEBUG("Kernel Base : %016" PFMT64x "\n", rr->rz_ver.kernel_base);
	RZ_LOG_DEBUG("Module list : %016" PFMT64x "\n", rr->rz_ver.mod_addr);
	RZ_LOG_DEBUG("Debug block : %016" PFMT64x "\n", rr->rz_ver.dbg_addr);

	if (rr->rz_ver.machine != KD_MACH_I386 && rr->rz_ver.machine != KD_MACH_AMD64) {
		RZ_LOG_ERROR("Unsupported target host\n");
		free(pkt);
		return false;
	}

	if (!(rr->rz_ver.flags & DBGKD_VERS_FLAG_DATA)) {
		RZ_LOG_ERROR("No _KDDEBUGGER_DATA64 pointer has been supplied by the debugee!\n");
		free(pkt);
		return false;
	}

	ctx->kernel_module.addr = rr->rz_ver.kernel_base;
	ctx->windctx.is_64bit = rr->rz_ver.flags & DBGKD_VERS_FLAG_PTR64;

	ut64 ptr = 0;
	if (!winkd_read_at(ctx, rr->rz_ver.dbg_addr, (ut8 *)&ptr, 4 << ctx->windctx.is_64bit)) {
		free(pkt);
		return false;
	}

	ctx->windctx.PsLoadedModuleList = rr->rz_ver.mod_addr;
	ctx->windctx.KdDebuggerDataBlock = ptr;

	RZ_LOG_DEBUG("PsLoadedModuleList at 0x%016" PFMT64x "\n", ctx->windctx.PsLoadedModuleList);
	RZ_LOG_DEBUG("_KDDEBUGGER_DATA64 at 0x%016" PFMT64x "\n", ctx->windctx.KdDebuggerDataBlock);

	// Thanks to this we don't have to find a way to read the cr4
	ut16 pae_enabled;
	if (!winkd_read_at(ctx, ctx->windctx.KdDebuggerDataBlock + K_PaeEnabled, (ut8 *)&pae_enabled, sizeof(ut16))) {
		free(pkt);
		return false;
	}

	ctx->windctx.is_pae = pae_enabled & 1;
	ctx->windctx.profile = winkd_get_profile(32 << ctx->windctx.is_64bit, rr->rz_ver.minor, winkd_get_sp(&ctx->windctx));
	if (!ctx->windctx.profile) {
		RZ_LOG_WARN("Could not find a suitable profile for the target OS\n");
	}
	free(pkt);
	return true;
}

int winkd_sync(RZ_BORROW RZ_NONNULL KdCtx *ctx) {
	int ret = -1;
	kd_packet_t *s;

	if (!ctx || !ctx->desc) {
		return -1;
	}

	if (ctx->syncd) {
		return 0;
	}

	while (!winkd_lock_enter(ctx)) {
	};

	if (ctx->desc->iob->type == KD_IO_NET) {
		// Read a KD packet to initialize KDNet interface
		// The first packet will always be type of KD_PACKET_TYPE_UNUSED
		ret = kd_read_packet(ctx->desc, &s);
		if (ret != KD_E_OK) {
			goto end;
		}
	}

	// Send the breakin packet
	if (iob_write(ctx->desc, (const ut8 *)"b", 1) != 1) {
		ret = KD_E_IOERR;
		goto end;
	}

	if (ctx->desc->iob->type == KD_IO_PIPE) {
		// Reset the host
		ret = kd_send_ctrl_packet(ctx->desc, KD_PACKET_TYPE_RESET, 0);
		if (ret != KD_E_OK) {
			goto end;
		}

		// Wait for the response
		ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_RESET, NULL);
		if (ret != KD_E_OK) {
			goto end;
		}
	}
	ctx->last_received_id = KD_INITIAL_PACKET_ID;

	// Syncronize with the first KD_PACKET_TYPE_STATE_CHANGE64 packet
	ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_STATE_CHANGE64, &s);
	if (ret != KD_E_OK) {
		goto end;
	}

	// Reset the sequence id
	ctx->seq_id = KD_INITIAL_PACKET_ID;

	kd_stc_64 *stc64 = PKT_STC(s);
	ctx->cpu = stc64->cpu;
	ctx->cpu_count = stc64->cpu_count;
	ctx->windctx.target.eprocess = 0;
	rz_list_free(ctx->plist_cache);
	ctx->plist_cache = NULL;
	rz_list_free(ctx->tlist_cache);
	ctx->tlist_cache = NULL;
	ctx->windctx.is_pae = 0;
	ctx->windctx.target_thread.ethread = stc64->kthread;
	// We're ready to go
	ctx->syncd = 1;

	free(s);
	RZ_LOG_INFO("Sync done! (%i cpus found)\n", ctx->cpu_count);
	ret = 1;

end:
	winkd_lock_leave(ctx);
	return ret;
}

int winkd_continue(RZ_BORROW RZ_NONNULL KdCtx *ctx, bool handled) {
	kd_req_t req = { 0 };

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return 0;
	}
	req.req = DbgKdContinueApi;
	req.cpu = ctx->cpu;
	req.rz_cont.reason = handled ? 0x10001 : 0x80010001;
	// The meaning of 0x400 is unknown, but Windows doesn't
	// behave like suggested by ReactOS source
	req.rz_cont.tf = 0x400;

	if (!winkd_lock_enter(ctx)) {
		return KD_E_TIMEOUT;
	}
	int ret;
	do {
		ret = kd_send_data_packet(ctx->desc, KD_PACKET_TYPE_STATE_MANIPULATE,
			ctx->seq_id, (ut8 *)&req, sizeof(kd_req_t), NULL, 0);
		if (ret != KD_E_OK) {
			break;
		}
		ret = winkd_wait_packet(ctx, KD_PACKET_TYPE_ACKNOWLEDGE, NULL);
		if (ret == KD_E_OK) {
			break;
		}
	} while (ret == KD_E_MALFORMED);

	rz_list_free(ctx->plist_cache);
	ctx->plist_cache = NULL;
	rz_list_free(ctx->tlist_cache);
	ctx->tlist_cache = NULL;
	ctx->context_cache_valid = false;
	winkd_lock_leave(ctx);
	return ret == KD_E_OK;
}

bool winkd_write_reg(RZ_BORROW RZ_NONNULL KdCtx *ctx, ut32 flags, RZ_BORROW RZ_NONNULL RZ_IN const ut8 *buf, int size) {
	kd_packet_t *pkt = NULL;
	kd_req_t req = { 0 };

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return false;
	}
	const ut64 max_ctx_size = KD_MAX_PAYLOAD - sizeof(kd_req_t);
	RZ_LOG_DEBUG("Regwrite() size: %x\n", size);
	if (size > max_ctx_size) {
		ut32 offset = 0;
		ut32 left = size;
		req.req = DbgKdSetContextEx;
		req.cpu = ctx->cpu;
		req.rz_ctx_ex.copied = size;
		do {
			const ut64 rest = RZ_MIN(left, max_ctx_size);
			req.rz_ctx_ex.count = rest;
			req.rz_ctx_ex.offset = offset;
			RZ_FREE(pkt);
			if (!winkd_send_state_manipulate_req(ctx, &req, buf + offset, rest, &pkt)) {
				break;
			}
			if (PKT_REQ(pkt)->rz_ctx_ex.count > left) {
				offset = size;
				break;
			}
			left -= PKT_REQ(pkt)->rz_ctx_ex.count;
			offset += PKT_REQ(pkt)->rz_ctx_ex.count;
		} while (left);
		size = offset;
	} else {
		req.req = DbgKdSetContextApi;
		req.cpu = ctx->cpu;
		req.rz_ctx.flags = flags;
		if (!winkd_send_state_manipulate_req(ctx, &req, buf, size, &pkt)) {
			return false;
		}
	}

	if (size > ctx->context_cache_size) {
		free(ctx->context_cache);
		ctx->context_cache = malloc(size);
		ctx->context_cache_size = size;
	}

	memcpy(ctx->context_cache, buf, size);

	free(pkt);
	return size;
}

int winkd_read_reg(RZ_BORROW RZ_NONNULL KdCtx *ctx, RZ_BORROW RZ_NONNULL RZ_OUT ut8 *buf, int size) {
	kd_req_t req = { 0 };
	kd_packet_t *pkt = NULL;

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return 0;
	}

	if (ctx->context_cache_size >= size && ctx->context_cache_valid) {
		memcpy(buf, ctx->context_cache, size);
		return size;
	}

	req.req = DbgKdGetContextApi;
	req.cpu = ctx->cpu;

	req.rz_ctx.flags = 0x1003F;

	if (!winkd_send_state_manipulate_req(ctx, &req, NULL, 0, &pkt)) {
		return 0;
	}

	kd_req_t *rr = PKT_REQ(pkt);
	const size_t context_rq_sz = pkt->length - sizeof(kd_req_t);
	memcpy(buf, rr->data, RZ_MIN(size, context_rq_sz));
	free(pkt);

	if (context_rq_sz > ctx->context_cache_size || !ctx->context_cache) {
		void *tmp = realloc(ctx->context_cache, context_rq_sz);
		if (!tmp) {
			free(ctx->context_cache);
			ctx->context_cache = NULL;
			ctx->context_cache_size = 0;
			ctx->context_cache_valid = false;
			return 0;
		}
		ctx->context_cache = tmp;
		ctx->context_cache_size = context_rq_sz;
	}
	memcpy(ctx->context_cache, rr->data, context_rq_sz);
	ctx->context_cache_valid = true;
	ctx->context_cache_valid = context_rq_sz;
	return context_rq_sz;
}

int winkd_query_mem(RZ_BORROW RZ_NONNULL KdCtx *ctx, const ut64 addr, int *address_space, int *flags) {
	kd_req_t req = { 0 };
	kd_packet_t *pkt;

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return 0;
	}

	req.req = DbgKdQueryMemoryApi;
	req.cpu = ctx->cpu;

	req.rz_query_mem.addr = addr;
	req.rz_query_mem.address_space = 0; // Tells the kernel that 'addr' is a virtual address

	if (!winkd_send_state_manipulate_req(ctx, &req, NULL, 0, &pkt)) {
		return 0;
	}

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
	return 1;
}

int winkd_bkpt(RZ_BORROW RZ_NONNULL KdCtx *ctx, const ut64 addr, const int set, const int hw, RZ_BORROW RZ_NONNULL int *handle) {
	kd_req_t req = { 0 };
	kd_packet_t *pkt;

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

	if (!winkd_send_state_manipulate_req(ctx, &req, NULL, 0, &pkt)) {
		return 0;
	}

	kd_req_t *rr = PKT_REQ(pkt);

	if (rr->ret) {
		free(pkt);
		return 0;
	}
	*handle = rr->rz_set_bp.handle;
	free(pkt);
	return 1;
}

static int read_at(RZ_BORROW RZ_NONNULL KdCtx *ctx, enum KD_PACKET_MANIPULATE_TYPE type, ut8 *buf, const ut64 offset, const int count) {
	kd_req_t req = {
		.req = type,
		.cpu = ctx->cpu
	};
	int ret = 0;
	int left = count;
	do {
		req.rz_mem.addr = offset + ret;
		req.rz_mem.length = RZ_MIN(left, KD_MAX_PAYLOAD - sizeof(kd_req_t));
		kd_packet_t *pkt;
		if (!winkd_send_state_manipulate_req(ctx, &req, NULL, 0, &pkt)) {
			return ret;
		}

		kd_req_t *rr = PKT_REQ(pkt);
		const int returned_bytes = RZ_MIN(rr->rz_mem.read, pkt->length - sizeof(kd_req_t));
		const int read_len = RZ_MIN(returned_bytes, RZ_MIN(rr->rz_mem.read, left));
		memcpy(buf + ret, rr->data, read_len);
		ret += read_len;
		left -= read_len;
		free(pkt);
	} while (left);
	return ret;
}

int winkd_read_at_phys(RZ_BORROW RZ_NONNULL KdCtx *ctx, const ut64 offset, RZ_BORROW RZ_NONNULL RZ_OUT ut8 *buf, const int count) {
	if (!ctx || !ctx->desc || !ctx->syncd) {
		return 0;
	}
	return read_at(ctx, DbgKdReadPhysicalMemoryApi, buf, offset, count);
}

int winkd_read_at(RZ_BORROW RZ_NONNULL KdCtx *ctx, const ut64 offset, RZ_BORROW RZ_NONNULL RZ_OUT ut8 *buf, const int count) {
	if (!ctx || !ctx->desc || !ctx->syncd || count < 0) {
		return 0;
	}
	return read_at(ctx, DbgKdReadVirtualMemoryApi, buf, offset, count);
}

int winkd_write_at(RZ_BORROW RZ_NONNULL KdCtx *ctx, const ut64 offset, RZ_BORROW RZ_NONNULL RZ_IN const ut8 *buf, const int count) {
	kd_packet_t *pkt = NULL;
	kd_req_t req = { 0 };

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return 0;
	}

	int payload = RZ_MIN(count, KD_MAX_PAYLOAD - sizeof(kd_req_t));
	req.req = DbgKdWriteVirtualMemoryApi;
	req.cpu = ctx->cpu;
	req.rz_mem.addr = offset;
	req.rz_mem.length = payload;

	if (!winkd_send_state_manipulate_req(ctx, &req, buf, payload, &pkt)) {
		return 0;
	}

	kd_req_t *rr = PKT_REQ(pkt);
	int ret = rr->rz_mem.read;
	free(pkt);
	return ret;
}

int winkd_write_at_phys(RZ_BORROW RZ_NONNULL KdCtx *ctx, const ut64 offset, RZ_BORROW RZ_NONNULL RZ_IN const ut8 *buf, const int count) {
	kd_packet_t *pkt;
	kd_req_t req = { 0 };

	if (!ctx || !ctx->desc || !ctx->syncd) {
		return 0;
	}

	int payload = RZ_MIN(count, KD_MAX_PAYLOAD - sizeof(kd_req_t));

	memset(&req, 0, sizeof(kd_req_t));

	req.req = DbgKdWritePhysicalMemoryApi;
	req.cpu = ctx->cpu;

	req.rz_mem.addr = offset;
	req.rz_mem.length = payload;
	req.rz_mem.read = 0; // Default caching option

	if (!winkd_send_state_manipulate_req(ctx, &req, buf, payload, &pkt)) {
		return 0;
	}

	kd_req_t *rr = PKT_REQ(pkt);

	if (rr->ret) {
		free(pkt);
		return 0;
	}
	int ret = rr->rz_mem.read;
	free(pkt);
	return ret;
}

void winkd_break(void *arg) {
	// This command shouldn't be wrapped by locks since it can always be sent and we don't
	// want break queued up after another background task
	KdCtx *ctx = (KdCtx *)arg;
	ctx->breaked = true;
	(void)iob_write(ctx->desc, (const ut8 *)"b", 1);
}
