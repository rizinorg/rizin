// SPDX-FileCopyrightText: 2017-2021 xvilka <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2017-2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <analysis_private.h>
#include <wasm/wasm.h>

#define WASM_INDEX_MAX_BODY (32 * 1024 * 1024)

extern RzAnalysisPlugin rz_analysis_plugin_wasm;

static bool wasm_fn_patched(WasmContext *ctx, ut64 addr);
static void wasm_invalidate_range(WasmContext *ctx, ut64 addr, ut64 len);
static void wasm_on_io_write(RzEvent *ev, int type, void *user, void *data);
static void wasm_hook_writes(RzAnalysis *analysis, WasmContext *ctx);
static bool wasm_end_is_function(RzAnalysis *analysis, WasmContext *ctx, ut64 addr);

static int wasm_func_cmp(const void *a, const void *b, void *user) {
	const WasmFuncScope *fa = a;
	const WasmFuncScope *fb = b;
	(void)user;
	if (fa->addr < fb->addr) {
		return -1;
	}
	if (fa->addr > fb->addr) {
		return 1;
	}
	return 0;
}

static WasmFuncScope *wasm_find_func(WasmContext *ctx, ut64 addr) {
	st32 lo, hi, best;
	size_t nfuncs;
	if (!ctx || !ctx->funcs || rz_pvector_empty(ctx->funcs)) {
		return NULL;
	}
	// Bail rather than truncate huge counts.
	nfuncs = rz_pvector_len(ctx->funcs);
	if (nfuncs > (size_t)ST32_MAX) {
		return NULL;
	}
	lo = 0;
	hi = (st32)nfuncs - 1;
	best = -1;
	while (lo <= hi) {
		st32 mid = lo + (hi - lo) / 2;
		WasmFuncScope *fn = rz_pvector_at(ctx->funcs, mid);
		if (fn->addr <= addr) {
			best = mid;
			lo = mid + 1;
		} else {
			hi = mid - 1;
		}
	}
	if (best < 0) {
		return NULL;
	}
	WasmFuncScope *fn = rz_pvector_at(ctx->funcs, best);
	// subtract just to prevent underflow
	if (addr - fn->addr >= fn->len) {
		return NULL;
	}
	return fn;
}

static bool wasm_cache_stale(RzAnalysis *analysis, WasmContext *ctx) {
	RzBinObject *obj;
	RzBinFile *bf;
	const RzPVector *syms;
	bool va = false;
	if (!ctx->indexed) {
		return true;
	}
	if (analysis->coreb.cfggeti && analysis->coreb.core) {
		va = analysis->coreb.cfggeti(analysis->coreb.core, "io.va") != 0;
	}
	if (va != ctx->used_va || !analysis->binb.get_bin_object) {
		return true;
	}
	if (analysis->iob.io != ctx->iob_io) {
		return true;
	}
	obj = analysis->binb.get_bin_object(analysis->binb.bin);
	if (!obj) {
		return true;
	}
	bf = rz_bin_cur(analysis->binb.bin);
	syms = rz_bin_object_get_symbols(obj);
	// Not the symbol-vector pointer: a freed vector can be reallocated at the same address.
	return !bf || !syms || ctx->bin_id != bf->id || ctx->bin_obj != obj ||
		ctx->bin_size != obj->size || rz_pvector_len(syms) != ctx->nsyms;
}

static bool wasm_build_cache(RzAnalysis *analysis, WasmContext *ctx) {
	RzBinObject *obj;
	RzBinFile *bf;
	const RzPVector *syms;
	void **it;
	RzPVector *defined = NULL;
	bool va = false;
	bool ok = false;
	if (analysis->coreb.cfggeti && analysis->coreb.core) {
		va = analysis->coreb.cfggeti(analysis->coreb.core, "io.va") != 0;
	}
	if (!analysis->binb.get_bin_object || !analysis->iob.read_at) {
		return false;
	}
	obj = analysis->binb.get_bin_object(analysis->binb.bin);
	if (!obj) {
		return false;
	}
	syms = rz_bin_object_get_symbols(obj);
	if (!syms) {
		return false;
	}
	bf = rz_bin_cur(analysis->binb.bin);
	// Clear stale cache. Never duplicate slots.
	if (ctx->funcs || rz_vector_len(&ctx->calls)) {
		wasm_context_clear_cache(ctx);
	}
	defined = rz_pvector_new(NULL);
	ctx->funcs = rz_pvector_new(free);
	if (!defined || !ctx->funcs) {
		goto beach;
	}
	// Function index: FUNC imports in symbol order, then code entries in that
	// same order. bin_wasm.c emits them that way. Non-function imports are not
	// FUNC, so they consume no function index. Every FUNC symbol consumes one
	// call slot, even an import or a body skipped for indexing below, or later
	// indices shift.
	rz_pvector_foreach (syms, it) {
		RzBinSymbol *sym = *it;
		ut64 addr;
		if (!sym || !sym->type || strcmp(sym->type, RZ_BIN_TYPE_FUNC_STR)) {
			continue;
		}
		addr = va ? rz_bin_object_get_vaddr(obj, sym->paddr, sym->vaddr) : sym->paddr;
		if (!rz_vector_push(&ctx->calls, &addr)) {
			goto beach;
		}
		if (sym->is_imported) {
			continue;
		}
		if (!rz_pvector_push(defined, sym)) {
			goto beach;
		}
	}
	rz_pvector_foreach (defined, it) {
		RzBinSymbol *sym = *it;
		ut64 addr;
		WasmFuncScope *fn;
		addr = va ? rz_bin_object_get_vaddr(obj, sym->paddr, sym->vaddr) : sym->paddr;
		// Track all bodies. Index skips oversized.
		if (!sym->size || addr == UT64_MAX) {
			continue;
		}
		fn = RZ_NEW0(WasmFuncScope);
		if (!fn || !rz_pvector_push(ctx->funcs, fn)) {
			free(fn);
			goto beach;
		}
		fn->addr = addr;
		fn->len = sym->size;
	}
	rz_pvector_sort(ctx->funcs, wasm_func_cmp, NULL);
	ctx->bin_obj = obj;
	ctx->bin_id = bf ? bf->id : UT32_MAX;
	ctx->bin_size = obj->size;
	ctx->nsyms = (ut32)rz_pvector_len(syms);
	ctx->iob_io = analysis->iob.io;
	ctx->used_va = va;
	ctx->indexed = true;
	wasm_hook_writes(analysis, ctx);
	ok = true;
beach:
	rz_pvector_free(defined);
	if (!ok) {
		wasm_context_clear_cache(ctx);
	}
	return ok;
}

static bool wasm_prepare(RzAnalysis *analysis, WasmContext *ctx) {
	if (!ctx) {
		return false;
	}
	if (ctx->indexed && wasm_cache_stale(analysis, ctx)) {
		wasm_context_clear_cache(ctx);
	}
	if (ctx->indexed) {
		return true;
	}
	return wasm_build_cache(analysis, ctx);
}

// True when cached bytes at addr were patched, stored hints may be stale.
static bool wasm_fn_patched(WasmContext *ctx, ut64 addr) {
	WasmFuncScope *fn = ctx ? wasm_find_func(ctx, addr) : NULL;
	return fn && fn->patched;
}

// Drop the scope index of every cached function overlapped by [addr, addr + len).
// Overlap always marks patched, even with no index yet: pre-write hints are stale.
// The subtraction form avoids fn->addr + fn->len overflow (funcs is sorted).
static void wasm_invalidate_range(WasmContext *ctx, ut64 addr, ut64 len) {
	ut64 end;
	void **it;
	bool dropped = false;
	if (!ctx || !ctx->funcs || !len) {
		return;
	}
	end = UT64_ADD_OVFCHK(addr, len) ? UT64_MAX : addr + len;
	rz_pvector_foreach (ctx->funcs, it) {
		WasmFuncScope *fn = *it;
		if (fn->addr >= end) {
			break;
		}
		if (fn->addr > addr || addr - fn->addr < fn->len) {
			if (fn->idx) {
				wasm_scope_index_free(fn->idx);
				fn->idx = NULL;
			}
			fn->unindexable = false;
			fn->patched = true;
			dropped = true;
		}
	}
	if (dropped) {
		ctx->scope_hint = UT64_MAX;
		ctx->addr_old = UT64_MAX;
	}
}

// Invalidate cached scope indexes whose bytes were overwritten.
// Never unhooked in wasm_fini: the IO bus dies before the analysis there.
// Instead drop any orphaned subscription before hooking, keeping at most one
// per analysis, stale callbacks bail via the plugin check below.
static void wasm_on_io_write(RzEvent *ev, int type, void *user, void *data) {
	RzAnalysis *analysis = user;
	RzEventIOWrite *iow = data;
	WasmContext *ctx;
	(void)type;
	if (!analysis || !iow || !ev) {
		return;
	}
	// Ignore stale buses. Only current IO invalidates.
	if (!analysis->iob.io || ev != analysis->iob.io->event) {
		return;
	}
	if (analysis->cur != &rz_analysis_plugin_wasm) {
		return;
	}
	ctx = analysis->plugin_data;
	if (!ctx || !ctx->indexed) {
		return;
	}
	wasm_invalidate_range(ctx, iow->addr, iow->len);
}

static void wasm_hook_writes(RzAnalysis *analysis, WasmContext *ctx) {
	RzIO *io;
	if (!analysis || !ctx) {
		return;
	}
	io = analysis->iob.io;
	if (!io || !io->event) {
		return;
	}
	rz_event_unhook_by_callback(io->event, RZ_EVENT_IO_WRITE, wasm_on_io_write, analysis);
	rz_event_hook(io->event, RZ_EVENT_IO_WRITE, wasm_on_io_write, analysis);
}

static WasmScopeIndex *wasm_index_body(RzAnalysis *analysis, WasmFuncScope *fn) {
	ut8 *buf;
	WasmScopeIndex *idx;
	if (fn->unindexable || fn->len > WASM_INDEX_MAX_BODY) {
		return NULL;
	}
	if (fn->idx) {
		return fn->idx;
	}
	// Indexed once per function. The caller caches the result, so later
	// branches in the same body do no IO.
	buf = RZ_NEWS(ut8, fn->len);
	if (!buf) {
		return NULL;
	}
	if (!analysis->iob.read_at(analysis->iob.io, fn->addr, buf, fn->len)) {
		free(buf);
		return NULL;
	}
	idx = wasm_scope_index_new(buf, (int)fn->len);
	free(buf);
	if (!idx) {
		fn->unindexable = true;
		return NULL;
	}
	fn->idx = idx;
	return idx;
}

// finds the address of the call function (essentially where to jump to).
static ut64 get_cf_offset(RzAnalysis *analysis, const ut8 *data, int len) {
	ut32 fcn_id;
	WasmContext *ctx = analysis->plugin_data;
	if (len < 2 || !read_u32_leb128(&data[1], &data[len], &fcn_id)) {
		return UT64_MAX;
	}
	if (!ctx || !wasm_prepare(analysis, ctx) || fcn_id >= rz_vector_len(&ctx->calls)) {
		return UT64_MAX;
	}
	// 0xfff.. are bad addresses for wasm
	// cgvwzq: 0xfff... can be external imported JS funcs
	return *(ut64 *)rz_vector_index_ptr(&ctx->calls, fcn_id);
}

static bool advance_till_scope_end(RzAnalysis *analysis, RzAnalysisOp *op, ut64 address, ut32 expected_type, ut32 depth, bool use_else) {
	WasmContext *ctx = analysis->plugin_data;
	ut8 buffer[16];
	ut8 *end = buffer + sizeof(buffer);
	if (ctx && wasm_prepare(analysis, ctx)) {
		WasmFuncScope *fn = wasm_find_func(ctx, address);
		ut32 jump_off = 0;
		WasmScopeIndex *idx = fn ? wasm_index_body(analysis, fn) : NULL;
		if (idx && wasm_scope_index_query(idx, (ut32)(address - fn->addr), depth, use_else, &jump_off)) {
			op->type = expected_type;
			op->jump = fn->addr + jump_off;
			return true;
		}
	}
	while (analysis->iob.read_at(analysis->iob.io, address, buffer, sizeof(buffer))) {
		WasmOp wop = { 0 };
		int size = wasm_dis(&wop, buffer, (int)(end - buffer));
		bool stop = size < 1 || wop.failed;
		WasmOpCodes wopop = wop.op.core;
		bool core = wop.type == WASM_TYPE_OP_CORE && !stop;
		free(wop.txt);
		if (stop) {
			// invalid stops here; unreachable is skipped.
			break;
		}
		if (core) {
			if (wopop == WASM_OP_LOOP || wopop == WASM_OP_BLOCK || wopop == WASM_OP_IF) {
				depth++;
			}
			if (use_else && wopop == WASM_OP_ELSE && !depth) {
				op->type = expected_type;
				op->jump = address + 1; // else size == 1
				return true;
			} else if (wopop == WASM_OP_END && depth > 0) {
				// let's wait till i get the final depth
				depth--;
			} else if (wopop == WASM_OP_END && !depth) {
				op->type = expected_type;
				op->jump = address;
				return true;
			}
		}
		address += size;
	}
	return false;
}

// True when the open scope already tracks this block, skips duplicate pushes.
static bool wasm_scope_top_is(RzAnalysis *analysis, WasmContext *ctx, ut64 addr, const char *op) {
	RzAnalysisHint *hint;
	bool match = false;
	if (ctx->scope_hint == UT64_MAX) {
		return false;
	}
	hint = rz_analysis_hint_get(analysis, ctx->scope_hint);
	if (hint && hint->opcode && !strcmp(hint->opcode, op) && hint->jump == addr) {
		match = true;
	}
	rz_analysis_hint_free(hint);
	return match;
}

// True when addr is the body end, true when unindexable (baseline RET).
static bool wasm_end_is_function(RzAnalysis *analysis, WasmContext *ctx, ut64 addr) {
	WasmFuncScope *fn = wasm_prepare(analysis, ctx) ? wasm_find_func(ctx, addr) : NULL;
	WasmScopeIndex *idx = fn ? wasm_index_body(analysis, fn) : NULL;
	return !fn || !idx || (ut32)(addr - fn->addr) == wasm_scope_index_root_end(idx);
}

// analyzes the wasm opcode.
static int wasm_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	WasmContext *ctx = analysis->plugin_data;
	WasmOp wop = { { 0 } };
	RzAnalysisHint *hint = NULL;
	int ret = wasm_dis(&wop, data, len);
	op->size = ret;
	op->addr = addr;
	op->sign = true;
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	switch (wop.type) {
	case WASM_TYPE_OP_CORE:
		op->id = wop.op.core;
		break;
	case WASM_TYPE_OP_ATOMIC:
		op->id = (0xfe << 8) | wop.op.atomic;
		break;
	case WASM_TYPE_OP_SIMD:
		op->id = 0xfd;
		break;
	}

	if (wop.failed || !wop.txt) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		free(wop.txt);
		return -1;
	}

	if (ctx->addr_old == addr && (wop.type != WASM_TYPE_OP_CORE || wop.op.core != WASM_OP_END)) {
		goto analysis_end;
	}

	switch (wop.type) {
	case WASM_TYPE_OP_CORE:
		switch (wop.op.core) {
		/* Calls here are using index instead of address */
		case WASM_OP_LOOP:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			hint = rz_analysis_hint_get(analysis, addr);
			// Post-patch hints go dormant. user hints are kept, not trusted.
			if ((!hint || wasm_fn_patched(ctx, addr)) &&
				!wasm_scope_top_is(analysis, ctx, addr, "loop")) {
				ctx->scope_hint--;
				rz_analysis_hint_set_opcode(analysis, ctx->scope_hint, "loop");
				rz_analysis_hint_set_jump(analysis, ctx->scope_hint, addr);
			}
			rz_analysis_hint_free(hint);
			hint = NULL;
			break;
		case WASM_OP_BLOCK:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			hint = rz_analysis_hint_get(analysis, addr);
			// Post-patch hints go dormant. user hints are kept, not trusted.
			if ((!hint || wasm_fn_patched(ctx, addr)) &&
				!wasm_scope_top_is(analysis, ctx, addr, "block")) {
				ctx->scope_hint--;
				rz_analysis_hint_set_opcode(analysis, ctx->scope_hint, "block");
				rz_analysis_hint_set_jump(analysis, ctx->scope_hint, addr);
			}
			rz_analysis_hint_free(hint);
			hint = NULL;
			break;
		case WASM_OP_IF:
			if ((hint = rz_analysis_hint_get(analysis, addr)) && !wasm_fn_patched(ctx, addr)) {
				op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
				op->jump = hint->jump;
				op->fail = addr + op->size;
				break;
			}
			if (!wasm_scope_top_is(analysis, ctx, addr, "if")) {
				ctx->scope_hint--;
				rz_analysis_hint_set_opcode(analysis, ctx->scope_hint, "if");
				rz_analysis_hint_set_jump(analysis, ctx->scope_hint, addr);
			}
			if (advance_till_scope_end(analysis, op, addr + op->size, RZ_ANALYSIS_OP_TYPE_CJMP, 0, true)) {
				op->fail = addr + op->size;
			}
			break;
		case WASM_OP_ELSE:
			// get if and set hint.
			hint = rz_analysis_hint_get(analysis, addr);
			if (hint && !wasm_fn_patched(ctx, addr)) {
				op->type = RZ_ANALYSIS_OP_TYPE_JMP;
				op->jump = hint->jump;
			} else {
				advance_till_scope_end(analysis, op, addr + op->size, RZ_ANALYSIS_OP_TYPE_JMP, 0, true);
			}
			break;
		case WASM_OP_BR: {
			RzAnalysisHint *hint2 = NULL;
			ut32 val = 0;
			read_u32_leb128(data + 1, data + len, &val);
			hint2 = rz_analysis_hint_get(analysis, addr);
			if (hint2 && hint2->jump != UT64_MAX && !wasm_fn_patched(ctx, addr)) {
				op->type = RZ_ANALYSIS_OP_TYPE_JMP;
				op->jump = hint2->jump;
			} else if ((hint = rz_analysis_hint_get(analysis, ctx->scope_hint))) {
				if (!val && hint->opcode && !strncmp("loop", hint->opcode, 4)) {
					op->type = RZ_ANALYSIS_OP_TYPE_JMP;
					op->jump = hint->jump;
				} else {
					advance_till_scope_end(analysis, op, addr + op->size, RZ_ANALYSIS_OP_TYPE_JMP, val, false);
				}
			} else {
				if (advance_till_scope_end(analysis, op, addr + op->size, RZ_ANALYSIS_OP_TYPE_JMP, val, false)) {
					RZ_LOG_ERROR("wasm: cannot find jump type for br (using block type)\n");
				} else {
					RZ_LOG_ERROR("wasm: cannot find jump for br\n");
				}
			}
			rz_analysis_hint_free(hint2);
		} break;
		case WASM_OP_BRIF: {
			RzAnalysisHint *hint2 = NULL;
			ut32 val = 0;
			read_u32_leb128(data + 1, data + len, &val);
			hint2 = rz_analysis_hint_get(analysis, addr);
			if (hint2 && hint2->jump != UT64_MAX && !wasm_fn_patched(ctx, addr)) {
				op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
				op->jump = hint2->jump;
				op->fail = addr + op->size;
			} else if ((hint = rz_analysis_hint_get(analysis, ctx->scope_hint))) {
				if (!val && hint->opcode && !strncmp("loop", hint->opcode, 4)) {
					op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
					op->fail = addr + op->size;
					op->jump = hint->jump;
				} else {
					if (advance_till_scope_end(analysis, op, addr + op->size, RZ_ANALYSIS_OP_TYPE_CJMP, val, false)) {
						op->fail = addr + op->size;
					}
				}
			} else {
				if (advance_till_scope_end(analysis, op, addr + op->size, RZ_ANALYSIS_OP_TYPE_CJMP, val, false)) {
					RZ_LOG_ERROR("wasm: cannot find jump type for br_if (using block type)\n");
					op->fail = addr + op->size;
				} else {
					RZ_LOG_ERROR("wasm: cannot find jump for br_if\n");
				}
			}
			rz_analysis_hint_free(hint2);
		} break;
		case WASM_OP_END: {
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			if (ctx->scope_hint < UT64_MAX) {
				hint = rz_analysis_hint_get(analysis, ctx->scope_hint);
				if (hint && !strncmp("loop", hint->opcode, 4)) {
					rz_analysis_hint_set_jump(analysis, addr, op->jump);
					rz_analysis_hint_set_jump(analysis, op->jump, addr);
				} else if (hint && !strncmp("block", hint->opcode, 5)) {
					// if/else/block
					rz_analysis_hint_set_jump(analysis, hint->jump, addr);
					rz_analysis_hint_set_jump(analysis, addr, UT64_MAX);
				}
				if (hint) {
					rz_analysis_hint_set_opcode(analysis, ctx->scope_hint, "invalid");
					rz_analysis_hint_set_jump(analysis, ctx->scope_hint, UT64_MAX);
					rz_analysis_hint_del(analysis, ctx->scope_hint, 1);
					ctx->scope_hint++;
				} else {
					// all wasm routines ends with an end.
					op->eob = true;
					op->type = RZ_ANALYSIS_OP_TYPE_RET;
					ctx->scope_hint = UT64_MAX;
				}
			} else {
				bool patched = wasm_fn_patched(ctx, addr);
				hint = rz_analysis_hint_get(analysis, addr);
				if ((!hint || patched) &&
					(!patched || wasm_end_is_function(analysis, ctx, addr))) {
					// all wasm routines ends with an end.
					op->eob = true;
					op->type = RZ_ANALYSIS_OP_TYPE_RET;
				}
			}
		} break;
		case WASM_OP_I32REMS:
		case WASM_OP_I32REMU:
			op->type = RZ_ANALYSIS_OP_TYPE_MOD;
			break;
		case WASM_OP_GETLOCAL:
		case WASM_OP_I32LOAD:
		case WASM_OP_I64LOAD:
		case WASM_OP_F32LOAD:
		case WASM_OP_F64LOAD:
		case WASM_OP_I32LOAD8S:
		case WASM_OP_I32LOAD8U:
		case WASM_OP_I32LOAD16S:
		case WASM_OP_I32LOAD16U:
		case WASM_OP_I64LOAD8S:
		case WASM_OP_I64LOAD8U:
		case WASM_OP_I64LOAD16S:
		case WASM_OP_I64LOAD16U:
		case WASM_OP_I64LOAD32S:
		case WASM_OP_I64LOAD32U:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case WASM_OP_SETLOCAL:
		case WASM_OP_TEELOCAL:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			break;
		case WASM_OP_I32EQZ:
		case WASM_OP_I32EQ:
		case WASM_OP_I32NE:
		case WASM_OP_I32LTS:
		case WASM_OP_I32LTU:
		case WASM_OP_I32GTS:
		case WASM_OP_I32GTU:
		case WASM_OP_I32LES:
		case WASM_OP_I32LEU:
		case WASM_OP_I32GES:
		case WASM_OP_I32GEU:
		case WASM_OP_I64EQZ:
		case WASM_OP_I64EQ:
		case WASM_OP_I64NE:
		case WASM_OP_I64LTS:
		case WASM_OP_I64LTU:
		case WASM_OP_I64GTS:
		case WASM_OP_I64GTU:
		case WASM_OP_I64LES:
		case WASM_OP_I64LEU:
		case WASM_OP_I64GES:
		case WASM_OP_I64GEU:
		case WASM_OP_F32EQ:
		case WASM_OP_F32NE:
		case WASM_OP_F32LT:
		case WASM_OP_F32GT:
		case WASM_OP_F32LE:
		case WASM_OP_F32GE:
		case WASM_OP_F64EQ:
		case WASM_OP_F64NE:
		case WASM_OP_F64LT:
		case WASM_OP_F64GT:
		case WASM_OP_F64LE:
		case WASM_OP_F64GE:
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			break;
		case WASM_OP_I64OR:
		case WASM_OP_I32OR:
			op->type = RZ_ANALYSIS_OP_TYPE_OR;
			break;
		case WASM_OP_I64XOR:
		case WASM_OP_I32XOR:
			op->type = RZ_ANALYSIS_OP_TYPE_XOR;
			break;
		case WASM_OP_I32CONST:
		case WASM_OP_I64CONST:
		case WASM_OP_F32CONST:
		case WASM_OP_F64CONST:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		case WASM_OP_I64ADD:
		case WASM_OP_I32ADD:
		case WASM_OP_F32ADD:
		case WASM_OP_F64ADD:
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		case WASM_OP_I64SUB:
		case WASM_OP_I32SUB:
		case WASM_OP_F32SUB:
		case WASM_OP_F64SUB:
			op->type = RZ_ANALYSIS_OP_TYPE_SUB;
			break;
		case WASM_OP_NOP:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			break;
		case WASM_OP_TRAP:
			op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
			break;
		case WASM_OP_CALL:
		case WASM_OP_CALLINDIRECT:
			// call_indirect encodes type/table immediates, not a fcn
			// index, resolving it is legacy best-effort, not a table lookup.
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->jump = get_cf_offset(analysis, data, len);
			op->fail = addr + op->size;
			if (op->jump != UT64_MAX) {
				op->ptr = op->jump;
			}
			break;
		case WASM_OP_RETURN:
			// should be ret, but if there the analisys is stopped.
			op->type = RZ_ANALYSIS_OP_TYPE_CRET;
		default:
			break;
		}
		break;
	case WASM_TYPE_OP_ATOMIC:
		switch (wop.op.atomic) {
		case WASM_OP_I32ATOMICLOAD:
		case WASM_OP_I64ATOMICLOAD:
		case WASM_OP_I32ATOMICLOAD8U:
		case WASM_OP_I32ATOMICLOAD16U:
		case WASM_OP_I64ATOMICLOAD8U:
		case WASM_OP_I64ATOMICLOAD16U:
		case WASM_OP_I64ATOMICLOAD32U:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case WASM_OP_I32ATOMICSTORE:
		case WASM_OP_I64ATOMICSTORE:
		case WASM_OP_I32ATOMICSTORE8:
		case WASM_OP_I32ATOMICSTORE16:
		case WASM_OP_I64ATOMICSTORE8:
		case WASM_OP_I64ATOMICSTORE16:
		case WASM_OP_I64ATOMICSTORE32:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			break;
		case WASM_OP_I32ATOMICRMWADD:
		case WASM_OP_I64ATOMICRMWADD:
		case WASM_OP_I32ATOMICRMW8UADD:
		case WASM_OP_I32ATOMICRMW16UADD:
		case WASM_OP_I64ATOMICRMW8UADD:
		case WASM_OP_I64ATOMICRMW16UADD:
		case WASM_OP_I64ATOMICRMW32UADD:
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		case WASM_OP_I32ATOMICRMW8USUB:
		case WASM_OP_I32ATOMICRMW16USUB:
		case WASM_OP_I32ATOMICRMWSUB:
		case WASM_OP_I64ATOMICRMW8USUB:
		case WASM_OP_I64ATOMICRMW16USUB:
		case WASM_OP_I64ATOMICRMW32USUB:
		case WASM_OP_I64ATOMICRMWSUB:
			op->type = RZ_ANALYSIS_OP_TYPE_SUB;
			break;
		case WASM_OP_I32ATOMICRMWAND:
		case WASM_OP_I64ATOMICRMWAND:
		case WASM_OP_I32ATOMICRMW8UAND:
		case WASM_OP_I32ATOMICRMW16UAND:
		case WASM_OP_I64ATOMICRMW8UAND:
		case WASM_OP_I64ATOMICRMW16UAND:
		case WASM_OP_I64ATOMICRMW32UAND:
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
			break;
		case WASM_OP_I32ATOMICRMWOR:
		case WASM_OP_I64ATOMICRMWOR:
		case WASM_OP_I32ATOMICRMW8UOR:
		case WASM_OP_I32ATOMICRMW16UOR:
		case WASM_OP_I64ATOMICRMW8UOR:
		case WASM_OP_I64ATOMICRMW16UOR:
		case WASM_OP_I64ATOMICRMW32UOR:
			op->type = RZ_ANALYSIS_OP_TYPE_OR;
			break;
		case WASM_OP_I32ATOMICRMWXOR:
		case WASM_OP_I64ATOMICRMWXOR:
		case WASM_OP_I32ATOMICRMW8UXOR:
		case WASM_OP_I32ATOMICRMW16UXOR:
		case WASM_OP_I64ATOMICRMW8UXOR:
		case WASM_OP_I64ATOMICRMW16UXOR:
		case WASM_OP_I64ATOMICRMW32UXOR:
			op->type = RZ_ANALYSIS_OP_TYPE_XOR;
			break;
		case WASM_OP_I32ATOMICRMWXCHG:
		case WASM_OP_I64ATOMICRMWXCHG:
		case WASM_OP_I32ATOMICRMW8UXCHG:
		case WASM_OP_I32ATOMICRMW16UXCHG:
		case WASM_OP_I64ATOMICRMW8UXCHG:
		case WASM_OP_I64ATOMICRMW16UXCHG:
		case WASM_OP_I64ATOMICRMW32UXCHG:
			op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
			break;
		default:
			break;
		}
	default:
		break;
	}

analysis_end:
	ctx->addr_old = addr;
	free(wop.txt);
	rz_analysis_hint_free(hint);
	return op->size;
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return false;
	default:
		return -1;
	}
}

static char *get_reg_profile(RzAnalysis *analysis) {
	return rz_str_dup(
		"=PC	pc\n"
		"=BP	bp\n"
		"=SP	sp\n"
		"=A0	r0\n"
		"gpr	sp	.32	0	0\n" // stack pointer
		"gpr	pc	.32	4	0\n" // program counter
		"gpr	bp	.32	8	0\n" // base pointer // unused
	);
}

RzAnalysisPlugin rz_analysis_plugin_wasm = {
	.name = "wasm",
	.desc = "WebAssembly analysis plugin",
	.license = "LGPL3",
	.arch = "wasm",
	.bits = 64,
	.archinfo = archinfo,
	.get_reg_profile = get_reg_profile,
	.op = &wasm_op,
	.init = wasm_init,
	.fini = wasm_fini,
};
