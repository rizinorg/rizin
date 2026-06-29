// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_lib.h>
#include <rz_inquiry.h>

#include "rz_analysis.h"
#include "rz_bin.h"
#include "rz_cons.h"
#include "rz_il/definitions/mem.h"
#include "rz_il/rz_il_vm.h"
#include "rz_inquiry/rz_bcfg.h"
#include "rz_inquiry/rz_il_cache.h"
#include "rz_inquiry/rz_interpreter.h"
#include "rz_inquiry_plugins.h"
#include "rz_th.h"
#include "rz_types.h"
#include "rz_util/ht_pp.h"
#include "rz_util/ht_sp.h"
#include "rz_util/ht_up.h"
#include "rz_util/rz_bitvector.h"
#include "rz_util/rz_buf.h"
#include "rz_util/rz_graph.h"
#include "rz_util/rz_iterator.h"
#include "rz_util/rz_log.h"
#include "rz_util/rz_set.h"
#include "rz_util/rz_str.h"
#include "rz_vector.h"
#include <rz_il.h>
#include <rz_list.h>
#include <rz_types_base.h>
#include <rz_util/rz_assert.h>

RZ_LIB_VERSION(rz_inquiry);

static RzInquiryPlugin *inquiry_static_plugins[] = { RZ_INQUIRY_STATIC_PLUGINS };

RZ_API const size_t rz_inquiry_get_n_plugins() {
	return RZ_ARRAY_SIZE(inquiry_static_plugins);
}

RZ_API RZ_BORROW RzInquiryPlugin *rz_inquiry_get_plugin(size_t index) {
	if (index >= RZ_ARRAY_SIZE(inquiry_static_plugins)) {
		return NULL;
	}
	return inquiry_static_plugins[index];
}

RZ_API bool rz_inquiry_plugin_add(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_OWN RZ_NONNULL RzInquiryPlugin *plugin) {
	rz_return_val_if_fail(inquiry && plugin, false);
	if (!plugin->p_interpreter) {
		rz_warn_if_reached();
		return false;
	}

	if (!ht_sp_insert(inquiry->plugins, plugin->p_interpreter->name, plugin)) {
		RZ_LOG_WARN("Plugin '%s' was already added.\n", plugin->p_interpreter->name);
		return true;
	}

	void **p_data = RZ_NEW0(void *);
	if (!ht_sp_insert(inquiry->plugins_data, plugin->p_interpreter->name, p_data)) {
		rz_warn_if_reached();
		return false;
	}
	return true;
}

RZ_API bool rz_inquiry_plugin_del(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_OWN RZ_NONNULL RzInquiryPlugin *plugin) {
	rz_return_val_if_fail(inquiry && plugin, false);

	void **p_data = ht_sp_find(inquiry->plugins_data, plugin->p_interpreter->name, NULL);
	if (plugin->p_interpreter->fini) {
		plugin->p_interpreter->fini(p_data ? *p_data : NULL);
	}
	free(p_data);
	if (plugin->p_interpreter) {
		return ht_sp_delete(inquiry->plugins, plugin->p_interpreter->name);
	}
	rz_warn_if_reached();
	return false;
}

RZ_API void rz_inquiry_function_free(RZ_NULLABLE RZ_OWN RzInquiryFunction *fcn) {
	if (!fcn) {
		return;
	}
	rz_inquiry_bcfg_free(fcn->bcfg);
	rz_vector_free(fcn->entry_points);
	free(fcn);
}

RZ_IPI RZ_OWN RzInquiryFunction *rz_inquiry_function_new() {
	RzInquiryFunction *fcn = RZ_NEW0(RzInquiryFunction);
	if (!fcn) {
		return NULL;
	}
	fcn->bcfg = rz_inquiry_bcfg_new(RZ_GRAPH_IMPL_LIST);
	fcn->entry_points = rz_vector_new(sizeof(ut64), NULL, NULL);
	if (!fcn->bcfg || !fcn->entry_points) {
		rz_inquiry_function_free(fcn);
		return NULL;
	}
	return fcn;
}

RZ_API RZ_OWN char *rz_inquiry_function_str(const RzInquiryFunction *fcn) {
	RzStrBuf *buf = rz_strbuf_new("");
	rz_strbuf_append(buf, "ifcn: [");
	ut64 *it;
	size_t i = 0;
	rz_vector_foreach (fcn->entry_points, it) {
		rz_strbuf_appendf(buf, "%s0x%" PFMT64x, (i++ > 0 ? ", " : " "), *it);
	}
	rz_strbuf_append(buf, " ]\n");
	RzIterator *iter = rz_graph_get_nodes(fcn->bcfg->graph);
	RzGraphNode *n;
	rz_iterator_foreach(iter, n) {
		const RzInquiryBlock *bb = rz_graph_node_get_data(n);
		rz_strbuf_appendf(buf, "\t0x%" PFMT64x ":0x%" PFMT64x "\n", bb->addr, bb->size);
	}
	rz_iterator_free(iter);
	return rz_strbuf_drain(buf);
}

RZ_API RZ_OWN RzInquiry *rz_inquiry_new(void) {
	RzInquiry *iq = RZ_NEW0(RzInquiry);
	if (!iq) {
		return NULL;
	}
	iq->plugins = ht_sp_new(HT_STR_CONST, NULL, NULL);
	iq->plugins_data = ht_sp_new(HT_STR_CONST, NULL, NULL);
	iq->call_candidates = ht_up_new(NULL, free);
	iq->dynamic_xrefs = rz_vector_new(sizeof(RzAnalysisXRef), NULL, NULL);
	iq->bcfg = rz_inquiry_bcfg_new(RZ_GRAPH_IMPL_LIST);
	if (!iq->plugins || !iq->plugins_data || !iq->bcfg) {
		ht_sp_free(iq->plugins);
		ht_sp_free(iq->plugins_data);
		rz_inquiry_bcfg_free(iq->bcfg);
		free(iq);
		return NULL;
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(inquiry_static_plugins); ++i) {
		rz_inquiry_plugin_add(iq, inquiry_static_plugins[i]);
	}
	return iq;
}

RZ_API void rz_inquiry_free(RZ_OWN RZ_NULLABLE RzInquiry *iq) {
	if (!iq) {
		return;
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(inquiry_static_plugins); ++i) {
		rz_inquiry_plugin_del(iq, inquiry_static_plugins[i]);
	}
	ht_sp_free(iq->plugins);
	ht_sp_free(iq->plugins_data);
	ht_up_free(iq->call_candidates);
	rz_inquiry_bcfg_free(iq->bcfg);
	rz_vector_free(iq->dynamic_xrefs);
	free(iq);
}

RZ_IPI void rz_inquiry_add_xref(RzInquiry *iq, const RzAnalysisXRef *xref) {
	rz_vector_push(iq->dynamic_xrefs, (void *)xref);
}

RZ_API bool rz_inquiry_xref_interpreter_filter(RZ_NONNULL const RzAnalysisXRef *xref, RZ_NONNULL const RzPVector /*<RzBinSection *>*/ *allowed_segments) {
	rz_return_val_if_fail(xref && allowed_segments, false);
	void **it;
	rz_pvector_foreach (allowed_segments, it) {
		const RzBinSection *sec = *it;

		ut64 start = sec->vaddr;
		ut64 end = start + sec->vsize;
		if (RZ_BETWEEN_EXCL(start, xref->to, end)) {
			switch (xref->type) {
			case RZ_ANALYSIS_XREF_TYPE_CALL_RET:
			case RZ_ANALYSIS_XREF_TYPE_CALL:
			case RZ_ANALYSIS_XREF_TYPE_CODE:
			case RZ_ANALYSIS_XREF_TYPE_RETURN:
				return sec->perm & RZ_PERM_X;
			case RZ_ANALYSIS_XREF_TYPE_MEM_WRITE:
				return sec->perm & RZ_PERM_W;
			case RZ_ANALYSIS_XREF_TYPE_MEM_READ:
			case RZ_ANALYSIS_XREF_TYPE_STRING:
				return sec->perm & RZ_PERM_R;
			case RZ_ANALYSIS_XREF_TYPE_NULL:
				rz_warn_if_reached();
				return false;
			}
		}
	}
	return false;
}

static void handle_io_request(RzAnalysisILContext *il_ctx, RzInterpIOReadRequest *io_req, RZ_OUT RzInterpIOResult *io_res) {
	RZ_LOG_DEBUG("inquiry: Received IO read request: mem:%" PFMTSZd " 0x%" PFMT64x "\n",
		io_req->mem_idx,
		rz_bv_to_ut64(io_req->addr));
	io_res->req_ok = false;
	RzILMemIndex mem_idx = io_req->mem_idx;
	if (mem_idx <= rz_vector_len(&il_ctx->memory)) {
		rz_warn_if_reached();
		return;
	}
	if (rz_bv_len(io_req->addr) == 64 && rz_bv_msb(io_req->addr)) {
		RZ_LOG_ERROR("Due to the Unix seek() implementation, addresses with the "
			     "63 bit set can't be addresses.\n");
		return;
	}
	RzAnalysisILMem *mem = rz_vector_index_ptr(&il_ctx->memory, mem_idx);
	if (!mem->base_buf) {
		io_res->req_ok = false;
	} else {
		// TODO: here only memory should be read that can be assumed to be constant!
		io_res->req_ok = rz_il_loadw_into(mem->base_buf, io_req->ld_data, io_req->addr, io_req->n_bits, io_req->big_endian);
	}
	RZ_LOG_DEBUG("inquiry: Sent IO read result. Success = %s.\n",
		rz_str_bool(io_res->req_ok));
}

RZ_API bool rz_inquiry_get_fcn_symbol_addr(RzCore *core, RZ_OUT RzSetU *symbol_targets) {
	rz_return_val_if_fail(core && symbol_targets, false);
	RzPVector /*<RzBinSection *>*/ *sections = rz_bin_object_get_sections(core->bin->cur->o);
	if (!sections) {
		rz_warn_if_reached();
		return false;
	}
	// Add function addresses of function symbols in the executable region.
	void **it;
	const RzPVector *symbols = rz_bin_object_get_symbols(core->bin->cur->o);
	if (!symbols) {
		rz_pvector_free(sections);
		rz_warn_if_reached();
		return false;
	}
	rz_pvector_foreach (symbols, it) {
		RzBinSymbol *sym = *it;
		if (!RZ_STR_EQ(sym->type, RZ_BIN_TYPE_FUNC_STR)) {
			continue;
		}
		void **it2;
		rz_pvector_foreach (sections, it2) {
			RzBinSection *sec = *it2;
			if (sec->perm & RZ_PERM_X &&
				RZ_BETWEEN_EXCL(sec->vaddr, sym->vaddr, sec->vaddr + sec->vsize)) {
				rz_set_u_add(symbol_targets, sym->vaddr);
				break;
			}
		}
	}
	rz_pvector_free(sections);
	return true;
}

static bool get_branch_targets(RzCore *core, RzSetU *branch_targets) {
	RzPVector /*<RzBinSection *>*/ *sections = rz_bin_object_get_sections(core->bin->cur->o);
	if (!sections) {
		rz_warn_if_reached();
		return false;
	}
	RzVector *non_x_idx = rz_vector_new(sizeof(size_t), NULL, NULL);
	void **it;
	size_t i;
	rz_pvector_enumerate (sections, it, i) {
		RzBinSection *sec = *it;
		if (!(sec->perm & RZ_PERM_X)) {
			rz_vector_push(non_x_idx, &i);
		}
	}
	size_t *j;
	rz_vector_foreach_prev (non_x_idx, j) {
		rz_pvector_remove_at(sections, *j);
	}
	rz_vector_free(non_x_idx);
	if (!rz_analysis_get_all_cf_targets(core->analysis, sections, true, branch_targets)) {
		RZ_LOG_ERROR("Failed to get branch targets.\n");
		return false;
	}
	rz_pvector_free(sections);
	return true;
}

static bool log_control_flow(RzInquiry *inquiry, RzInterpCtrlFlow *cf) {
	RZ_LOG_DEBUG("inquiry: Received control flow: 0x%" PFMT64x " size: %" PFMTSZu " (alt: 0x%" PFMT64x ")\n",
		cf->target_addr, cf->target_block_size, cf->alt_target);
	rz_inquiry_bcfg_add_block(inquiry->bcfg, cf->actual_target, cf->target_block_size);
	if (cf->alt_target) {
		// Add a dummy basic block at the address the call originally jumped to.
		// This is the basic block for the imported function.
		rz_inquiry_bcfg_add_block(inquiry->bcfg, cf->target_addr, 1);
	}
	// Add a simple control flow edge here.
	// It gets later updated to another type if a reported xref has it.
	rz_inquiry_bcfg_add_edge(inquiry->bcfg, cf->src_block_addr, cf->actual_target, cf->type);
	return true;
}

static bool handle_yields(RzInquiry *inquiry, RzInterpYieldRBuf *yield_rbufs[RZ_INTERP_YIELD_KIND_NUM]) {
	RzInterpYieldRBuf *rbuf_xrefs = yield_rbufs[RZ_INTERP_YIELD_KIND_XREF];
	rz_return_val_if_fail(rbuf_xrefs, false);

	RzAnalysisXRef xref = { 0 };
	if (!rz_th_ring_buf_is_empty_unsafe(rbuf_xrefs->rbuf)) {
		RzThreadRingBufResult r = rz_th_ring_buf_take(rbuf_xrefs->rbuf, &xref);
		if (r == RZ_THREAD_RING_BUF_CLOSED) {
			rz_warn_if_reached();
			return false;
		} else if (r == RZ_THREAD_RING_BUF_OK) {
			rz_inquiry_add_xref(inquiry, &xref);
			RZ_LOG_DEBUG("inquiry: Added xref: 0x%" PFMT64x " -> 0x%" PFMT64x " (%s)\n", xref.from, xref.to, rz_analysis_ref_type_tostring(xref.type));
		}
	}

	RzInterpYieldRBuf *rbuf_cf = yield_rbufs[RZ_INTERP_YIELD_KIND_CONTROL_FLOW];
	if (!rz_th_ring_buf_is_empty_unsafe(rbuf_cf->rbuf)) {
		RzInterpCtrlFlow cf = { 0 };
		RzThreadRingBufResult r = rz_th_ring_buf_take(rbuf_cf->rbuf, &cf);
		if (r == RZ_THREAD_RING_BUF_CLOSED) {
			rz_warn_if_reached();
			return false;
		} else if (r == RZ_THREAD_RING_BUF_OK) {
			log_control_flow(inquiry, &cf);
		}
	}

	RzInterpYieldRBuf *rbuf_calls = yield_rbufs[RZ_INTERP_YIELD_KIND_CALL_CANDIDATE];
	rz_return_val_if_fail(rbuf_calls, false);

	RzAnalysisCallCandidate cc = { 0 };
	if (!rz_th_ring_buf_is_empty_unsafe(rbuf_calls->rbuf)) {
		RzThreadRingBufResult r = rz_th_ring_buf_take(rbuf_calls->rbuf, &cc);
		if (r == RZ_THREAD_RING_BUF_CLOSED) {
			rz_warn_if_reached();
			return false;
		} else if (r == RZ_THREAD_RING_BUF_OK) {
			RzAnalysisCallCandidate *cc_clone = RZ_NEW0(RzAnalysisCallCandidate);
			memcpy(cc_clone, &cc, sizeof(RzAnalysisCallCandidate));
			if (ht_up_update(inquiry->call_candidates, cc_clone->bb_addr, cc_clone)) {
				RZ_LOG_DEBUG("inquiry: Overwrote a call candidate located at 0x%" PFMT64x "\n", cc_clone->candidate_addr);
			} else {
				RZ_LOG_DEBUG("inquiry: Added call candidate located at 0x%" PFMT64x "\n", cc_clone->candidate_addr);
			}
		}
	}
	return true;
}

/**
 * \brief Removes entry points which were requested from the IL cache
 * (and hence have been interpreted).
 * Returns false if no entry points are left to interpret.
 * True otherwise.
 */
// TODO: Optimize
static bool reduce_get_entry_points(
	RzInterpSet *iset,
	RzILCache *il_cache,
	RZ_BORROW RzSetU /*<ut64>*/ *entry_points) {
	// Add the next entry point we need to check for executable regions the interpreters did not cover.
	// For this we simply delete all entry points which point
	// into the already handled basic blocks.
	// Then add a few addresses as new entry point.
	// The addresses we add are jump targets from jump/call instructions in the binary.

	RzVector to_del = { 0 };
	rz_vector_init(&to_del, sizeof(ut64), NULL, NULL);

	RzIterator *entries = rz_set_u_as_iter(entry_points);
	ut64 *ct;
	rz_iterator_foreach(entries, ct) {
		// This call target was interpreted before (hence is in the IL cache).
		if (rz_il_cache_was_requested(il_cache, *ct)) {
			rz_vector_push(&to_del, ct);
		}
	}
	rz_iterator_free(entries);

	rz_vector_foreach (&to_del, ct) {
		rz_set_u_delete(entry_points, *ct);
	}
	rz_vector_fini(&to_del);

	if (rz_set_u_size(entry_points) == 0) {
		return false;
	}
	return true;
}

static void close_reset_ipc_obj(RzInterpSet *iset) {
	// Close and clear all the IPC objects of this interpreter.
	// This also clears the buffer and queues
	rz_th_ring_buf_close(iset->io_request_rbuf);
	rz_th_ring_buf_close(iset->io_result_rbuf);
	rz_th_ring_buf_close(iset->entry_points);
	rz_th_ring_buf_close(iset->il_cache_client->req_rbuf);
	rz_th_queue_close(iset->il_cache_client->il_queue);
	rz_list_free(rz_th_queue_pop_all(iset->il_cache_client->il_queue));
}

static void open_ipc_obj(RzInterpSet *iset) {
	// Open queue again, so the interpretation can start at another
	// jump target again.
	rz_th_ring_buf_open(iset->io_request_rbuf);
	rz_th_ring_buf_open(iset->io_result_rbuf);
	rz_th_ring_buf_open(iset->il_cache_client->req_rbuf);
	rz_th_queue_open(iset->il_cache_client->il_queue);
	rz_th_ring_buf_open(iset->entry_points);
}

static bool collect_entry_points(RzCore *core,
	RzSetU *entry_points,
	RzSetU *symbol_targets) {

	if (!get_branch_targets(core, entry_points) ||
		!rz_inquiry_get_fcn_symbol_addr(core, symbol_targets)) {
		rz_warn_if_reached();
		return false;
	}
	RzIterator *iter = rz_set_u_as_iter(symbol_targets);
	ut64 *sym_addr;
	rz_iterator_foreach(iter, sym_addr) {
		rz_set_u_add(entry_points, *sym_addr);
	}
	rz_iterator_free(iter);
	rz_set_u_free(symbol_targets);
	return true;
}

static bool setup_yield_rbufs(
	RzInterpYieldRBuf *yield_rbufs[RZ_INTERP_YIELD_KIND_NUM],
	RZ_OWN RzPVector /*<RzBinSection *>*/ *sections,
	RzInterpYieldFilter yield_filter) {
	// A single interpreter can produce different yields.
	// E.g. if the interpreter has a complex abstract memory model
	// for stack, heap and constant values.
	// Then it can produce three kind of yields.
	// These yield queues can be shared between different interpreters.
	// So we have one yield queue for each yield type.

	RzInterpYieldKind yield_kind = RZ_INTERP_YIELD_KIND_CALL_CANDIDATE;
	RzInterpYieldRBuf *rbuf = NULL;
	rbuf = rz_interpreter_yield_rbuf_new(yield_kind, NULL, NULL);
	if (!rbuf) {
		rz_warn_if_reached();
		return false;
	}
	yield_rbufs[RZ_INTERP_YIELD_KIND_CALL_CANDIDATE] = rbuf;

	yield_kind = RZ_INTERP_YIELD_KIND_CONTROL_FLOW;
	rbuf = NULL;
	rbuf = rz_interpreter_yield_rbuf_new(yield_kind, NULL, NULL);
	if (!rbuf) {
		rz_warn_if_reached();
		return false;
	}
	yield_rbufs[RZ_INTERP_YIELD_KIND_CONTROL_FLOW] = rbuf;

	yield_kind = RZ_INTERP_YIELD_KIND_XREF;
	rbuf = rz_interpreter_yield_rbuf_new(
		yield_kind,
		yield_filter,
		sections);
	if (!rbuf) {
		rz_warn_if_reached();
		return false;
	}
	yield_rbufs[RZ_INTERP_YIELD_KIND_XREF] = rbuf;
	return true;
}

struct ituple {
	RzThread *ithread;
	RzInterpSet *iset;
	RzInterpRunStateFlag next_run_state;
};

/**
 * A function to call the prototype interpreter.
 * Usually these tasks will be split between different caches and yield consumers.
 */
RZ_API bool rz_inquiry_interpreter(RzCore *core,
	RZ_OWN RzSetU *entry_points,
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code) {
	// All the things we need
	bool return_code = true;
	RzInterpSet *intp_iset = NULL;

	RzBuffer *io_buf = rz_buf_new_with_io(rz_analysis_get_io_bind(core->analysis));
	RzSetU *symbol_targets = rz_set_u_new();
	bool user_sent_signal = false;
	struct ituple *iset_map = NULL;
	RzThread *il_cache_th = NULL;

	rz_cons_push();

	RZ_LOG_DEBUG("inquiry: Create IL Cache");
	RzILCache *il_cache = rz_il_cache_new(core->analysis, core->io,
		rz_bin_object_get_sections(core->bin->cur->o),
		RZ_IL_CACHE_CONFIG_NOP_UNLIFTED | RZ_IL_CACHE_CONFIG_NO_SLEEP);
	if (!il_cache) {
		return_code = false;
		goto error_free;
	}

	// collect_entry_points(core, entry_points, symbol_targets);

	if (rz_log_get_level() > RZ_LOGLVL_INFO && rz_cons_is_interactive()) {
		eprintf("Total branch targets in binary: %" PFMT32d "\n", rz_set_u_size(entry_points));
	}

	// Initialize the abstract state with the architecture's registers.
	if (!rz_analysis_plugin_current(core->analysis)->il_config) {
		RZ_LOG_ERROR("The RzArch plugin doesn't have il_config() implemented.\n");
		return_code = false;
		goto error_free;
	}

	// Bundle all the queues into one object to pass it to the thread.
	// Later we would pass a unique iset to each interpreter with
	// the required queues only.
	// But for the prototype we have only one iset with all queues.
	RzInquiryPlugin *prototype = ht_sp_find(core->inquiry->plugins, "abstr_int_prototype", NULL);
	if (!prototype) {
		return_code = false;
		rz_warn_if_reached();
		goto error_free;
	}
	size_t n_threads = 1;
	iset_map = RZ_NEWS0(struct ituple, n_threads);

	RzInterpYieldRBuf *yield_rbufs[RZ_INTERP_YIELD_KIND_NUM] = { 0 };
	if (!setup_yield_rbufs(yield_rbufs, rz_bin_object_get_sections(core->bin->cur->o),
		    (RzInterpYieldFilter)rz_inquiry_xref_interpreter_filter)) {
		return_code = false;
		rz_warn_if_reached();
		goto error_free;
	}

	//
	// Initialize and spawn the interpreters.
	//
	for (size_t i = 0; i < n_threads; ++i) {
		RzILCacheClient *cache_client = rz_il_cache_new_client(il_cache);
		if (!cache_client) {
			return_code = false;
			rz_warn_if_reached();
			goto error_free;
		}
		intp_iset = rz_interpreter_set_new(
			core->analysis,
			prototype->p_interpreter,
			RZ_INTERP_ABSTRACTION_CONST,
			cache_client,
			yield_rbufs,
			ignored_code);
		if (!intp_iset) {
			return_code = false;
			rz_warn_if_reached();
			goto error_free;
		}

		// Dispatch prototype interpreter into a thread.
		RZ_LOG_DEBUG("inquiry: Start main interpretation thread.\n");
		RzThread *interpr_th = rz_th_new((RzThreadFunction)rz_interpreter_run, intp_iset);
		iset_map[i].ithread = interpr_th;
		iset_map[i].iset = intp_iset;
		iset_map[i].next_run_state = RZ_INTERP_RUN_STATE_INIT;
	}

	//
	// Spawn the IL cache.
	//
	RZ_LOG_DEBUG("inquiry: Spawn IL Cache");
	il_cache_th = rz_th_new((RzThreadFunction)rz_il_cache_serve, il_cache);

	ut64 intpr_terminated = 0;
	ut64 check_signal = 0;

	//
	// Enter the loop to serve the interpreters.
	//
	for (ut64 i = 0;; check_signal++, i = (i + 1) % n_threads) {
		if (check_signal % RZ_INQUIRY_CHECK_USER_SIGNAL_ITC == 0 && rz_cons_is_breaked()) {
			user_sent_signal = true;
			break;
		}
		RzInterpSet *iset = iset_map[i].iset;
		RzInterpRunStateFlag expected_rs = iset_map[i].next_run_state;

		switch (rz_interp_run_state_get_unsafe(iset->run_state)) {
		case RZ_INTERP_RUN_STATE_OUT_OF_LOOP:
			break;
		case RZ_INTERP_RUN_STATE_INIT: {
			if (expected_rs != RZ_INTERP_RUN_STATE_INIT) {
				break;
			}
			// This interpreter is waiting for the next emulation task.
			// TODO: Really reduce the entry points each and every time?
			// This eats too much runtime I think.
			// Better live with some duplicate emulation and reduce less often?
			if (!reduce_get_entry_points(iset, il_cache, entry_points)) {
				// None left.
				// TODO Remove?
				rz_th_queue_close(iset->il_cache_client->il_queue);
				iset_map[i].next_run_state = RZ_INTERP_RUN_STATE_TERM;
				intpr_terminated++;
				// RZ_LOG_DEBUG("Next: TERM\n");
				continue;
			}
			ut64 next_entry_point = rz_set_u_take(entry_points);
			switch (rz_th_ring_buf_put(iset->entry_points, &next_entry_point)) {
			case RZ_THREAD_RING_BUF_OK:
				// Successfully lifted and pushed the entry point's basic block into the queue.
				// Expect the interpreter to emulate now.
				iset_map[i].next_run_state = RZ_INTERP_RUN_STATE_EMU;
				// RZ_LOG_DEBUG("Next: EMU\n");
				break;
			case RZ_THREAD_RING_BUF_FAIL:
				// The entry point buffer is full.
				// Insert the entry point to the todo set again.
				rz_set_u_add(entry_points, next_entry_point);
				break;
			case RZ_THREAD_RING_BUF_CLOSED:
				rz_warn_if_reached();
				// Something went pretty wrong.
				iset_map[i].next_run_state = RZ_INTERP_RUN_STATE_TERM;
				intpr_terminated++;
				// RZ_LOG_DEBUG("Next: TERM\n");
				continue;
			}
			break;
		}
		case RZ_INTERP_RUN_STATE_EMU: {
			if (expected_rs != RZ_INTERP_RUN_STATE_EMU) {
				break;
			}
			// From here on, the code plays the role of the IO handler,
			// and yield consumer.
			// - Handling IO requests.
			// - Receiving and adding the found xrefs to RzAnalysis.
			// In the final implementation each of those roles would be split into
			// two or more separated modules running in parallel.

			// ==========
			// IO HANDLER
			// ==========
			//
			// This plays the IO handler for a single(!) interpreter instances.
			// In the future we should have only one IO handler for multiple interpreters.
			// But this requires multiple IO write caches
			// (one for each interpreter instance).
			// Because this is not yet implemented, there is only one interpreter thread for now.
			RzInterpIOReadRequest io_req = { 0 };
			if (!rz_th_ring_buf_is_empty_unsafe(iset->io_request_rbuf)) {
				RzThreadRingBufResult r = rz_th_ring_buf_take(iset->io_request_rbuf, &io_req);
				if (r == RZ_THREAD_RING_BUF_CLOSED) {
					rz_warn_if_reached();
					goto fatal_error;
				} else if (r == RZ_THREAD_RING_BUF_OK) {
					RzInterpIOResult io_res = { 0 };
					handle_io_request(iset->il_ctx, &io_req, &io_res);
					if (rz_th_ring_buf_put(iset->io_result_rbuf, &io_res) != RZ_THREAD_RING_BUF_OK) {
						rz_warn_if_reached();
						goto fatal_error;
					}
				}
				// Else r == RZ_THREAD_RING_BUF_FAIL
				// Due to a race condition the ring buffer was actually empty.
			}

			// ==============
			// YIELD CONSUMER
			// ==============
			//
			// This part plays the role of a yield consumer.
			// In our prototype it only receives xrefs and call candidates.
			if (!handle_yields(core->inquiry, iset->yield_rbufs)) {
				iset_map[i].next_run_state = RZ_INTERP_RUN_STATE_TERM;
				intpr_terminated++;
				// RZ_LOG_DEBUG("Next: TERM\n");
			}
			break;
		}
		case RZ_INTERP_RUN_STATE_CLEAN: {
			if (!((expected_rs == RZ_INTERP_RUN_STATE_CLEAN || expected_rs == RZ_INTERP_RUN_STATE_EMU))) {
				break;
			}
			close_reset_ipc_obj(iset);
			open_ipc_obj(iset);
			rz_th_sem_post(iset->run_state_sync);
			iset_map[i].next_run_state = RZ_INTERP_RUN_STATE_INIT;
			// RZ_LOG_DEBUG("Next: INIT\n");
			break;
		}
		case RZ_INTERP_RUN_STATE_TERM: {
			if (expected_rs != RZ_INTERP_RUN_STATE_TERM) {
				iset_map[i].next_run_state = RZ_INTERP_RUN_STATE_TERM;
				intpr_terminated++;
			}
			// RZ_LOG_DEBUG("Next: TERM\n");
			break;
		}
		}
		if (intpr_terminated == n_threads) {
			break;
		}
	}

fatal_error:

	RZ_LOG_DEBUG("inquiry: Wait for join\n");
	for (size_t i = 0; i < n_threads; i++) {
		close_reset_ipc_obj(iset_map[i].iset);
		// Open semaphore so the interpreter can transition
		// EMU -> CLEAN -> INIT -> TERM
		rz_th_sem_post(iset_map[i].iset->run_state_sync);
	}

	// Wait for thread to finish before cleaning.
	for (size_t i = 0; i < n_threads; i++) {
		rz_th_wait(iset_map[i].ithread);
		bool interpr_ret = rz_th_get_retv(iset_map[i].ithread);
		rz_th_free(iset_map[i].ithread);
		if (!interpr_ret || user_sent_signal) {
			return_code = false;
			if (!user_sent_signal) {
				RZ_LOG_ERROR("Interpreter failed with an error. Abort.\n");
			} else {
				RZ_LOG_ERROR("User sent signal.\n");
			}
		}
		rz_interpreter_set_free(iset_map[i].iset);
	}
	rz_il_cache_stop_serving(il_cache);

	if (rz_log_get_level() > RZ_LOGLVL_INFO && rz_cons_is_interactive()) {
		eprintf("\n");
	}
	RzIterator *iter = rz_il_cache_get_blocks(il_cache);
	if (!iter) {
		rz_warn_if_reached();
		goto error_free;
	}
	void **it;
	rz_iterator_foreach(iter, it) {
		RzILCacheBlock *block = *it;
		char *bstr = rz_il_cache_block_str(block);
		RZ_LOG_DEBUG("inquiry: Add ILCache block: %s\n", bstr);
		free(bstr);
		rz_inquiry_bcfg_add_block(core->inquiry->bcfg, block->addr, block->size);
	}
	rz_iterator_free(iter);
	if (!rz_inquiry_bcfg_add_edge_xref(core->inquiry->bcfg, rz_il_cache_get_static_xrefs(il_cache))) {
		rz_warn_if_reached();
	}
	if (!rz_inquiry_bcfg_add_edge_xref(core->inquiry->bcfg, core->inquiry->dynamic_xrefs)) {
		rz_warn_if_reached();
	}
	// char *g = rz_inquiry_bcfg_as_dot(core->inquiry->bcfg, "not_reduced");
	// printf("%s\n", g);
	// free(g);
	if (!rz_inquiry_bcfg_reduce(core->inquiry->bcfg)) {
		rz_warn_if_reached();
	}
	// g = rz_inquiry_bcfg_as_dot(core->inquiry->bcfg, "reduced");
	// printf("%s\n", g);
	// free(g);

	RZ_LOG_DEBUG("inquiry: inquiry: inquiry: Done\n");

error_free:
	rz_interpreter_yield_rbuf_free(yield_rbufs[RZ_INTERP_YIELD_KIND_XREF]);
	rz_interpreter_yield_rbuf_free(yield_rbufs[RZ_INTERP_YIELD_KIND_CALL_CANDIDATE]);
	rz_interpreter_yield_rbuf_free(yield_rbufs[RZ_INTERP_YIELD_KIND_CONTROL_FLOW]);
	free(iset_map);
	rz_set_u_free(entry_points);
	rz_buf_free(io_buf);
	rz_il_cache_stop_serving(il_cache);
	if (il_cache_th) {
		rz_th_wait(il_cache_th);
		rz_th_free(il_cache_th);
	}
	rz_il_cache_free(il_cache);
	rz_cons_pop();
	return return_code && !user_sent_signal;
}

RZ_API bool rz_inquiry_convert_and_add_to_analysis(
	RzAnalysis *analysis,
	RzInquiry *inquiry,
	const RzPVector /*<RzInquiryFunction *>*/ *fcns,
	const RzPVector /*<RzBinSymbol *>*/ *symbols) {
	rz_return_val_if_fail(analysis && inquiry && fcns && symbols, false);
	// Add all discovered binary blocks to analysis

	RzIterator *iter = rz_graph_get_nodes(inquiry->bcfg->graph);
	RzGraphNode *n;
	rz_iterator_foreach(iter, n) {
		const RzInquiryBlock *bb = rz_graph_node_get_data(n);
		rz_analysis_add_bb(analysis, bb->addr, bb->size);
		RzAnalysisBlock *abb = rz_analysis_get_block_at(analysis, bb->addr);
		RzIterator *out_edges = rz_inquiry_bcfg_get_outgoing_edges(inquiry->bcfg, bb->addr);
		if (!out_edges) {
			continue;
		}
		RzGraphEdge *e;
		rz_iterator_foreach(out_edges, e) {
			ut64 target = rz_graph_node_get_id(rz_graph_edge_get_to(e));
			RzInquiryBCFGEdgeType type = (RzInquiryBCFGEdgeType)(utptr)rz_graph_edge_get_data(e);
			switch (type) {
			default:
				continue;
			case RZ_INQUIRY_BCFG_EDGE_TYPE_CALL_RET:
			case RZ_INQUIRY_BCFG_EDGE_TYPE_CF:
			case RZ_INQUIRY_BCFG_EDGE_TYPE_JMP: {
				if (abb->jump == UT64_MAX && abb->fail != target) {
					abb->jump = target;
				} else if (abb->fail == UT64_MAX && abb->jump != target) {
					abb->fail = target;
				} else if (abb->fail != target && abb->jump != target) {
					RZ_LOG_WARN("The basic block at 0x%" PFMT64x " has more than two outgoing edges.\n"
						    "\t\tHas jump = 0x%" PFMT64x " fail = 0x%" PFMT64x ". Will miss = 0x%" PFMT64x " (%d)\n",
						bb->addr, abb->jump, abb->fail,
						target, type);
				}
				break;
			}
			}
		}
		rz_iterator_free(out_edges);
	}
	rz_iterator_free(iter);

	RzAnalysisXRef *xref;
	rz_vector_foreach (inquiry->dynamic_xrefs, xref) {
		rz_analysis_xrefs_set(analysis, xref->from, xref->to, xref->type);
	}

	// Convert the Inquiry functions to analysis function.
	void **it;
	rz_pvector_foreach (fcns, it) {
		RzInquiryFunction *fcn = *it;

		ut64 fcn_addr = *(ut64 *)rz_vector_head(fcn->entry_points);
		char new_fcn_name[64] = { 0 };
		void **it;
		rz_pvector_foreach (symbols, it) {
			RzBinSymbol *s = *it;
			if (s->vaddr == fcn_addr && RZ_STR_EQ(s->type, RZ_BIN_TYPE_FUNC_STR)) {
				rz_strf(new_fcn_name, "sym.%s", s->name);
				break;
			}
		}
		if (new_fcn_name[0] == '\0') {
			rz_strf(new_fcn_name, "fcn_0x%" PFMT64x, fcn_addr);
		}
		RzAnalysisFunction *afcn = rz_analysis_create_function(analysis, new_fcn_name, fcn_addr, RZ_ANALYSIS_FCN_TYPE_FCN);
		if (!afcn) {
			rz_warn_if_reached();
			continue;
		}

		RzIterator *iter = rz_graph_get_nodes(fcn->bcfg->graph);
		RzGraphNode *n;
		rz_iterator_foreach(iter, n) {
			const RzInquiryBlock *bb = rz_graph_node_get_data(n);
			RzAnalysisBlock *abb = rz_analysis_get_block_at(analysis, bb->addr);
			if (!abb && !(abb = rz_analysis_create_block(analysis, bb->addr, bb->size))) {
				rz_warn_if_reached();
				continue;
			}
			rz_analysis_function_add_block(afcn, abb);
		}
		rz_iterator_free(iter);
	}
	return true;
}

RZ_API bool rz_inquiry_function_deduction(
	RZ_NONNULL RZ_BORROW RzAnalysis *analysis,
	RZ_NONNULL RZ_BORROW RzInquiry *inquiry,
	RZ_NONNULL RZ_BORROW RzSetU *symbol_addresses,
	RZ_NONNULL const RzPVector /*<RzBinSymbol *>*/ *symbols,
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code,
	RZ_NONNULL RZ_OUT RzPVector /*<RzInquiryFunction *>*/ *inquiry_fcns) {
	rz_return_val_if_fail(analysis && inquiry && symbol_addresses && symbols && ignored_code && inquiry_fcns, false);
	if (!rz_inquiry_algo_revng_fcn_detection(
		    symbol_addresses,
		    inquiry->call_candidates,
		    inquiry->bcfg,
		    inquiry_fcns,
		    ignored_code)) {
		rz_warn_if_reached();
		return false;
	}
	return true;
}
