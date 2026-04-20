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
#include "rz_inquiry/rz_bb_graph.h"
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
	rz_inquiry_bb_cfg_free(fcn->bb_cfg);
	rz_vector_free(fcn->entry_points);
	rz_vector_free(fcn->call_candidates);
	free(fcn);
}

RZ_IPI RZ_OWN RzInquiryFunction *rz_inquiry_function_new() {
	RzInquiryFunction *fcn = RZ_NEW0(RzInquiryFunction);
	if (!fcn) {
		return NULL;
	}
	fcn->bb_cfg = rz_inquiry_bb_cfg_new(RZ_GRAPH_IMPL_LIST);
	fcn->entry_points = rz_vector_new(sizeof(ut64), NULL, NULL);
	fcn->call_candidates = rz_vector_new(sizeof(RzAnalysisCallCandidate), NULL, NULL);
	if (!fcn->bb_cfg || !fcn->entry_points) {
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
	RzIterator *iter = rz_graph_get_nodes(fcn->bb_cfg->graph);
	RzGraphNode *n;
	rz_iterator_foreach(iter, n) {
		const RzInquiryBB *bb = rz_graph_node_get_data(n);
		rz_strbuf_appendf(buf, "\t0x%" PFMT64x ":0x%" PFMT64x "\n", bb->addr, bb->size);
	}
	rz_iterator_free(iter);
	return rz_strbuf_drain(buf);
}

/**
 * \brief Add edges from \p insn_to_insn_edges to the cfg.
 * These are edges statically known by checking RzAnalysisOp->jump and fail.
 *
 * TODO: Crazy inefficient.
 * But for now it is left in here. The problem is that the graph has basic blocks as nodes.
 * But the xrefs are instruction to instruction. So we have this super expansive |bb| * |E| lookup.
 *
 * It would be way faster if we have an R-Tree to get bbs by an address it covers.
 * Or just do a better design all along.
 */
RZ_IPI bool rz_inquiry_bb_cfg_complement(RzInquiry *iq, RzVector /*<RzAnalysisXRef>*/ *insn_to_insn_edges) {
	// Add the instruction to instruction edges.
	RzAnalysisXRef *i2i_edge;
	rz_vector_foreach (insn_to_insn_edges, i2i_edge) {
		// First check if the edge is already in the CFG.
		// If so (not unlikely), skip the step where it iterates over all BBs.
		RzIterator *incoming = rz_inquiry_bb_cfg_get_incoming_edges(iq->bb_cfg, i2i_edge->to);
		if (!incoming) {
			// Basic block not present.
			continue;
		}
		RzGraphEdge *in_e;
		rz_iterator_foreach(incoming, in_e) {
			const RzInquiryBB *bb = rz_graph_node_get_data(rz_graph_edge_get_from(in_e));
			if (RZ_BETWEEN_EXCL(bb->addr, i2i_edge->from, bb->addr + bb->size)) {
				rz_iterator_free(incoming);
				// This edge was already covered.
				goto next_i2i_edge;
			}
		}
		rz_iterator_free(incoming);

		// Edge isn't in the CFG yet.
		// Now we have to do the crazy expansive |bb| * |E| search.
		RzGraphNode *n;
		RzIterator *bb_iter = rz_graph_get_nodes(iq->bb_cfg->graph);
		rz_iterator_foreach(bb_iter, n) {
			const RzInquiryBB *bb = rz_graph_node_get_data(n);
			if (!RZ_BETWEEN_EXCL(bb->addr, i2i_edge->from, bb->addr + bb->size)) {
				continue;
			}
			switch (i2i_edge->type) {
			default:
				rz_warn_if_reached();
				break;
			case RZ_ANALYSIS_XREF_TYPE_CALL:
				if (!rz_inquiry_bb_cfg_add_edge(iq->bb_cfg, bb->addr, i2i_edge->to, RZ_INQUIRY_BB_CFG_EDGE_TYPE_CALL)) {
					rz_warn_if_reached();
				}
				break;
			case RZ_ANALYSIS_XREF_TYPE_CODE:
				eprintf("Add i2i jump: 0x%llx -> 0x%llx\n", bb->addr, i2i_edge->to);
				if (!rz_inquiry_bb_cfg_add_edge(iq->bb_cfg, bb->addr, i2i_edge->to, RZ_INQUIRY_BB_CFG_EDGE_TYPE_JMP)) {
					rz_warn_if_reached();
				}
				break;
			case RZ_ANALYSIS_XREF_TYPE_CALL_RET:
				if (!rz_inquiry_bb_cfg_add_edge(iq->bb_cfg, bb->addr, i2i_edge->to, RZ_INQUIRY_BB_CFG_EDGE_TYPE_CALL_RET)) {
					rz_warn_if_reached();
				}
				break;
			}
		}
		rz_iterator_free(bb_iter);
	next_i2i_edge:
		continue;
	}
	return true;
}

RZ_API RZ_OWN RzInquiry *rz_inquiry_new(void) {
	RzInquiry *iq = RZ_NEW0(RzInquiry);
	if (!iq) {
		return NULL;
	}
	iq->plugins = ht_sp_new(HT_STR_CONST, NULL, NULL);
	iq->plugins_data = ht_sp_new(HT_STR_CONST, NULL, NULL);
	iq->call_candidates = ht_up_new(NULL, free);
	iq->xrefs = rz_vector_new(sizeof(RzAnalysisXRef), NULL, NULL);
	iq->bb_cfg = rz_inquiry_bb_cfg_new(RZ_GRAPH_IMPL_LIST);
	if (!iq->plugins || !iq->plugins_data || !iq->bb_cfg) {
		ht_sp_free(iq->plugins);
		ht_sp_free(iq->plugins_data);
		rz_inquiry_bb_cfg_free(iq->bb_cfg);
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
	rz_inquiry_bb_cfg_free(iq->bb_cfg);
	rz_vector_free(iq->xrefs);
	free(iq);
}

RZ_IPI void rz_inquiry_add_xref(RzInquiry *iq, const RzAnalysisXRef *xref) {
	rz_vector_push(iq->xrefs, (void *)xref);
}

RZ_API bool rz_inquiry_xref_interpreter_filter(ut64 *xref_to_addr, RZ_NONNULL const RzPVector /*<RzBinSection *>*/ *allowed_segments) {
	rz_return_val_if_fail(xref_to_addr && allowed_segments, false);
	void **it;
	rz_pvector_foreach (allowed_segments, it) {
		const RzBinSection *sec = *it;

		ut64 start = sec->vaddr;
		ut64 end = start + sec->vsize;
		if (RZ_BETWEEN(start, *xref_to_addr, end)) {
			return true;
		}
	}
	return false;
}

static void handle_io_request(RzCore *core, RzPVector /*<RzILMem *>*/ *il_mems, RzInterpreterIORequest *io_req, RZ_OUT RzInterpreterIOResult *io_res) {
	RZ_LOG_DEBUG("INQUIRY: Received IO %s request: mem:%" PFMTSZd " 0x%" PFMT64x "\n",
		io_req->type == RZ_INTERPRETER_IO_WRITE ? "write" : "read",
		io_req->mem_idx,
		rz_bv_to_ut64(io_req->addr));
	io_res->req_ok = false;
	RzILMemIndex mem_idx = io_req->mem_idx;
	if (rz_pvector_empty(il_mems) || rz_pvector_len(il_mems) <= mem_idx) {
		rz_warn_if_reached();
		return;
	}
	if (rz_bv_len(io_req->addr) == 64 && rz_bv_msb(io_req->addr)) {
		RZ_LOG_ERROR("Due to the Unix seek() implementation, addresses with the "
			     "63 bit set can't be addresses.\n");
		return;
	}
	RzILMem *mem = rz_pvector_at(il_mems, mem_idx);
	if (io_req->type == RZ_INTERPRETER_IO_READ) {
		io_res->req_ok = rz_il_mem_loadw_into(mem, io_req->ld_data, io_req->addr, io_req->n_bits, io_req->big_endian);
	} else {
		io_res->req_ok = rz_il_mem_storew(mem, io_req->addr, io_req->st_data, io_req->big_endian);
	}
	RZ_LOG_DEBUG("INQUIRY: Sent IO %s result. Success = %s.\n",
		io_req->type == RZ_INTERPRETER_IO_WRITE ? "write" : "read",
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

static bool get_branch_targets(RzCore *core, RzSetU *branch_targets, RzVector /*<RzAnalysisXRef>*/ *insn_to_insn_edges) {
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
	if (!rz_analysis_get_all_branch_targets(core->analysis, sections, true, branch_targets, insn_to_insn_edges)) {
		RZ_LOG_ERROR("Failed to get branch targets.\n");
		return false;
	}
	rz_pvector_free(sections);
	return true;
}

static bool handle_yields(RzCore *core, RzInterpreterYieldRBuf *yield_rbufs[RZ_INTERPRETER_YIELD_KIND_NUM]) {
	RzInterpreterYieldRBuf *rbuf_xrefs = yield_rbufs[RZ_INTERPRETER_YIELD_KIND_XREF];
	rz_return_val_if_fail(rbuf_xrefs, false);

	RzAnalysisXRef xref = { 0 };
	if (!rz_th_ring_buf_is_empty_unsafe(rbuf_xrefs->rbuf)) {
		RzThreadRingBufResult r = rz_th_ring_buf_take_blocking(rbuf_xrefs->rbuf, &xref);
		if (r == RZ_THREAD_RING_BUF_CLOSED) {
			rz_warn_if_reached();
			return false;
		} else if (r == RZ_THREAD_RING_BUF_OK) {
			rz_inquiry_add_xref(core->inquiry, &xref);
			RZ_LOG_DEBUG("Added xref: 0x%" PFMT64x " -> 0x%" PFMT64x " (%s)\n", xref.from, xref.to, rz_analysis_ref_type_tostring(xref.type));
		}
	}

	RzInterpreterYieldRBuf *rbuf_calls = yield_rbufs[RZ_INTERPRETER_YIELD_KIND_CALL_CANDIDATE];
	rz_return_val_if_fail(rbuf_calls, false);

	RzAnalysisCallCandidate cc = { 0 };
	if (!rz_th_ring_buf_is_empty_unsafe(rbuf_calls->rbuf)) {
		RzThreadRingBufResult r = rz_th_ring_buf_take_blocking(rbuf_calls->rbuf, &cc);
		if (r == RZ_THREAD_RING_BUF_CLOSED) {
			rz_warn_if_reached();
			return false;
		} else if (r == RZ_THREAD_RING_BUF_OK) {
			RzAnalysisCallCandidate *cc_clone = RZ_NEW0(RzAnalysisCallCandidate);
			memcpy(cc_clone, &cc, sizeof(RzAnalysisCallCandidate));
			if (ht_up_update(core->inquiry->call_candidates, cc_clone->bb_addr, cc_clone)) {
				RZ_LOG_DEBUG("Overwrote a call candidate located at 0x%" PFMT64x "\n", cc_clone->candidate_addr);
			} else {
				RZ_LOG_DEBUG("Added call candidate located at 0x%" PFMT64x "\n", cc_clone->candidate_addr);
			}
		}
	}
	return true;
}

#if 0
static void validate_il_bb(RzCore *core, RzInterpreterILBB *bb) {
	RzAnalysisILVM *vm = rz_analysis_il_vm_new(core->analysis, NULL);
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_from_vm(vm->vm);
	void **it;
	size_t i = 0;
	rz_pvector_enumerate (bb->il_ops, it, i) {
		char *report = NULL;
		RzInterpreterInsnPkt *pkt = *it;
		if (!rz_il_validate_effect(pkt->effect, ctx, NULL, NULL, &report)) {
			RZ_LOG_ERROR("Validation failed for IL op %" PFMTSZu " in BB 0x%" PFMT64x " in insn packet:\n"
				     "\t'%s'\n",
				i, bb->bb_addr, report);
		}
		free(report);
	}
	rz_analysis_il_vm_free(vm);
	rz_il_validate_global_context_free(ctx);
}
#endif

static const RzInterpreterILBB *get_il_bb(RzCore *core, HtUP *il_cache, ut64 addr) {
	RzInterpreterILBB *bb = ht_up_find(il_cache, addr, NULL);
	if (!bb) {
		RZ_LOG_DEBUG("INQUIRY: Lift new BB\n");
		bb = rz_inquiry_gen_il_bb(core->analysis, core->io, addr);
		if (!bb) {
			RZ_LOG_DEBUG("Failed to lift basic block at 0x%" PFMT64x "\n", addr);
			return NULL;
		}

#if 0
		// Validate IL to catch more errors during testing.
		validate_il_bb(core, bb);
		// Otherwise YOLO
#endif

		RZ_LOG_DEBUG("INQUIRY: Send IL result: %p.\n", bb);
		ht_up_insert(il_cache, bb->bb_addr, bb);
	} else {
		RZ_LOG_DEBUG("INQUIRY: Serve BB from cache\n");
	}
	return bb;
}

static bool send_next_il_bb(RzCore *core,
	RzThreadQueue *il_queue,
	HtUP *il_cache,
	RzSetU *entry_points,
	RzInterpreterBranch *branch) {
	RZ_LOG_DEBUG("INQUIRY: Received IL request: 0x%" PFMT64x " (alt: 0x%" PFMT64x ")\n", branch->target_addr, branch->alt_target);
	const RzInterpreterILBB *bb = get_il_bb(core, il_cache, branch->alt_target ? branch->alt_target : branch->target_addr);
	if (!bb) {
		// Delete the address from the branch targets.
		// This is currently necessary as a work around, because if the interpreter
		// fails before interpreting the address, it is added again as next entry point.
		// Giving an endless loop.
		// One of the design thingies to fix in the proper implementation.
		rz_set_u_delete(entry_points, branch->target_addr);
		if (branch->alt_target) {
			rz_set_u_delete(entry_points, branch->alt_target);
		}
		return false;
	}
	rz_inquiry_bb_cfg_add_basic_block(core->inquiry->bb_cfg, bb->bb_addr, bb->size);
	if (branch->alt_target) {
		// Add a dummy basic block at the address the call originally jumped to.
		// This is the basic block for the imported function.
		rz_inquiry_bb_cfg_add_basic_block(core->inquiry->bb_cfg, branch->target_addr, 1);
	}
	rz_th_queue_push(il_queue, (void *)bb, true);
	return true;
}

static bool reduce_get_entry_points(
	RzInterpreterSet *iset,
	HtUP *il_cache,
	RZ_BORROW RzSetU /*<ut64>*/ *entry_points,
	RZ_OUT ut64 *next_entry_point) {
	// Add the next entry point we need to check for executable regions the interpreters did not cover.
	// For this we simply delete all entry points which point
	// into the already handled basic blocks.
	// Then add a few addresses as new entry point.
	// The addresses we add are jump targets from jump/call instructions in the binary.

	RzIterator *il_bb_iter = ht_up_as_iter_keys(il_cache);
	ut64 *ct;
	rz_iterator_foreach(il_bb_iter, ct) {
		// This call target was interpreted before (hence is in the IL cache).
		rz_set_u_delete(entry_points, *ct);
	}
	rz_iterator_free(il_bb_iter);
	if (rz_set_u_size(entry_points) == 0) {
		return false;
	}

	*next_entry_point = rz_set_u_take(entry_points);
	return true;
}

static void close_reset_ipc_obj(RzInterpreterSet *iset) {
	// Close and clear all the IPC objects of this interpreter.
	// This also clears the buffer and queues
	rz_th_ring_buf_close(iset->io_request_rbuf);
	rz_th_ring_buf_close(iset->io_result_rbuf);
	rz_th_ring_buf_close(iset->branch_rbuf);
	rz_th_queue_close(iset->il_queue);
	rz_list_free(rz_th_queue_pop_all(iset->il_queue));
}

static void open_ipc_obj(RzInterpreterSet *iset) {
	// Open queue again, so the interpretation can start at another
	// jump target again.
	rz_th_ring_buf_open(iset->io_request_rbuf);
	rz_th_ring_buf_open(iset->io_result_rbuf);
	rz_th_ring_buf_open(iset->branch_rbuf);
	rz_th_queue_open(iset->il_queue);
}

static bool collect_entry_points(RzCore *core,
	RzVector /*<RzAnalysisXRef>*/ *insn_to_insn_edges,
	RzSetU *entry_points,
	RzSetU *symbol_targets) {

	if (!get_branch_targets(core, entry_points, insn_to_insn_edges) ||
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
	RzInterpreterYieldRBuf *yield_rbufs[RZ_INTERPRETER_YIELD_KIND_NUM],
	RZ_OWN RzPVector /*<RzBinSection *>*/ *sections,
	RzInterpreterYieldFilter yield_filter) {
	// A single interpreter can produce different yields.
	// E.g. if the interpreter has a complex abstract memory model
	// for stack, heap and constant values.
	// Then it can produce three kind of yields.
	// These yield queues can be shared between different interpreters.
	// So we have one yield queue for each yield type.

	RzInterpreterYieldKind yield_kind = RZ_INTERPRETER_YIELD_KIND_CALL_CANDIDATE;
	RzInterpreterYieldRBuf *rbuf = NULL;
	rbuf = rz_interpreter_yield_rbuf_new(yield_kind, NULL, NULL);
	if (!rbuf) {
		rz_warn_if_reached();
		return false;
	}
	yield_rbufs[RZ_INTERPRETER_YIELD_KIND_CALL_CANDIDATE] = rbuf;

	yield_kind = RZ_INTERPRETER_YIELD_KIND_XREF;
	rbuf = rz_interpreter_yield_rbuf_new(
		yield_kind,
		yield_filter,
		sections);
	if (!rbuf) {
		rz_warn_if_reached();
		return false;
	}
	yield_rbufs[RZ_INTERPRETER_YIELD_KIND_XREF] = rbuf;
	return true;
}

struct ituple {
	RzThread *ithread;
	RzInterpreterSet *iset;
	RzIntpRunStateFlag next_run_state;
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
	RzInterpreterSet *intp_iset = NULL;
	HtUP *il_cache = NULL;

	RzBuffer *io_buf = rz_buf_new_with_io(rz_analysis_get_io_bind(core->analysis));
	RzSetU *symbol_targets = rz_set_u_new();
	bool user_sent_signal = false;
	struct ituple *iset_map = NULL;
	RzVector /*<RzAnalysisXRef>*/ *insn_to_insn_edges = rz_vector_new(sizeof(RzAnalysisXRef), NULL, NULL);

	rz_cons_push();

	// The pseudo cache of IL effects.
	// This is only a vector so we can simulate the ownership separation
	// of the pointers.
	il_cache = ht_up_new(NULL, (RzPVectorFree)rz_interpreter_il_bb_free);

	collect_entry_points(core, insn_to_insn_edges, entry_points, symbol_targets);

	if (rz_log_get_level() > RZ_LOGLVL_INFO && rz_cons_is_interactive()) {
		eprintf("Total branch targets in binary: %" PFMT32d "\n", rz_set_u_size(entry_points));
	}

	// Initialize the abstract state with the architecture's registers.
	if (!rz_analysis_plugin_current(core->analysis)->il_config) {
		RZ_LOG_ERROR("The RzArch plugin doesn't have il_config() implemented.\n");
		return_code = false;
		goto error_free;
	}

	RZ_LOG_DEBUG("INQUIRY: Enforce enabling IO cache.\n");
	const char *io_cache_opt = rz_config_get(core->config, "io.cache");
	rz_config_set(core->config, "io.cache", "true");

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
	size_t n_threads = 8;
	iset_map = RZ_NEWS0(struct ituple, n_threads);

	RzInterpreterYieldRBuf *yield_rbufs[RZ_INTERPRETER_YIELD_KIND_NUM] = { 0 };
	if (!setup_yield_rbufs(yield_rbufs, rz_bin_object_get_sections(core->bin->cur->o),
		    (RzInterpreterYieldFilter)rz_inquiry_xref_interpreter_filter)) {
		return_code = false;
		rz_warn_if_reached();
		goto error_free;
	}

	for (size_t i = 0; i < n_threads; ++i) {
		intp_iset = rz_interpreter_set_new(
			core->analysis,
			prototype->p_interpreter,
			RZ_INTERPRETER_ABSTRACTION_CONST,
			yield_rbufs,
			ignored_code);
		if (!intp_iset) {
			return_code = false;
			rz_warn_if_reached();
			goto error_free;
		}

		// Dispatch prototype interpreter into a thread.
		RZ_LOG_DEBUG("INQUIRY: Start main interpretation thread.\n");
		RzThread *interpr_th = interpr_th = rz_th_new((RzThreadFunction)rz_interpreter_run, intp_iset);
		iset_map[i].ithread = interpr_th;
		iset_map[i].iset = intp_iset;
		iset_map[i].next_run_state = RZ_INTP_RUN_STATE_INIT;
	}

	ut64 intpr_terminated = 0;
	ut64 check_signal = 0;

	for (ut64 i = 0;; check_signal++, i = (i + 1) % n_threads) {
		if (check_signal % RZ_INQUIRY_CHECK_USER_SIGNAL_ITC == 0 && rz_cons_is_breaked()) {
			user_sent_signal = true;
			break;
		}
		RzInterpreterSet *iset = iset_map[i].iset;
		RzIntpRunStateFlag expected_rs = iset_map[i].next_run_state;

		switch (rz_intp_run_state_get_unsafe(iset->run_state)) {
		case RZ_INTP_RUN_STATE_OUT_OF_LOOP:
			break;
		case RZ_INTP_RUN_STATE_INIT: {
			if (expected_rs != RZ_INTP_RUN_STATE_INIT) {
				break;
			}
			// This interpreter is waiting for the next emulation task.
			RzInterpreterBranch branch = { 0 };
			if (!reduce_get_entry_points(iset, il_cache, entry_points, &branch.target_addr)) {
				// None left.
				rz_th_queue_close(iset->il_queue);
				iset_map[i].next_run_state = RZ_INTP_RUN_STATE_TERM;
				intpr_terminated++;
				// RZ_LOG_DEBUG("Next: TERM\n");
				continue;
			}
			if (send_next_il_bb(core, iset->il_queue, il_cache, entry_points, &branch)) {
				// Successfully lifted and pushed the entry point's basic block into the queue.
				// Expect the interpreter to emulate now.
				iset_map[i].next_run_state = RZ_INTP_RUN_STATE_EMU;
				// RZ_LOG_DEBUG("Next: EMU\n");
			} else {
				iset_map[i].next_run_state = RZ_INTP_RUN_STATE_CLEAN;
				rz_th_queue_close(iset->il_queue);
				// RZ_LOG_DEBUG("Next: CLEAN\n");
			}
			break;
		}
		case RZ_INTP_RUN_STATE_EMU: {
			if (expected_rs != RZ_INTP_RUN_STATE_EMU) {
				break;
			}
			// From here on, the code plays the role of the cache, IO handler,
			// and yield consumer.
			// - Waiting for new Effects to be requested and sending them.
			// - Handling IO requests.
			// - Receiving and adding the found xrefs to RzAnalysis.
			// In the final implementation each of those roles would be split into
			// two or more separated modules running in parallel.

			// =========
			// IL CACHE
			// =========
			//
			// This block mimics the IL cache. It uplifts basic blocks and
			// caches them.
			if (!rz_th_ring_buf_is_empty_unsafe(iset->branch_rbuf)) {
				RzInterpreterBranch branch = { 0 };
				RzThreadRingBufResult r = rz_th_ring_buf_take(iset->branch_rbuf, &branch);
				if (r == RZ_THREAD_RING_BUF_CLOSED) {
					rz_warn_if_reached();
					goto fatal_error;
				} else if (r == RZ_THREAD_RING_BUF_OK) {
					if (!send_next_il_bb(core, iset->il_queue, il_cache, entry_points, &branch)) {
						// Signal interpreter the lifting failed.
						rz_th_queue_close(iset->il_queue);
						iset_map[i].next_run_state = RZ_INTP_RUN_STATE_CLEAN;
						// RZ_LOG_DEBUG("Next: CLEAN\n");
					} else {
						RZ_LOG_DEBUG("Pushed: il_bb: 0x%llx\n", branch.target_addr);
					}
				}
				// Else r == RZ_THREAD_RING_BUF_FAIL
				// Due to a race condition the ring buffer was actually empty.
			}

			// ==========
			// IO HANDLER
			// ==========
			//
			// This plays the IO handler for a single(!) interpreter instances.
			// In the future we should have only one IO handler for multiple interpreters.
			// But this requires multiple IO write caches
			// (one for each interpreter instance).
			// Because this is not yet implemented, there is only one interpreter thread for now.
			RzInterpreterIORequest io_req = { 0 };
			if (!rz_th_ring_buf_is_empty_unsafe(iset->io_request_rbuf)) {
				RzThreadRingBufResult r = rz_th_ring_buf_take(iset->io_request_rbuf, &io_req);
				if (r == RZ_THREAD_RING_BUF_CLOSED) {
					rz_warn_if_reached();
					goto fatal_error;
				} else if (r == RZ_THREAD_RING_BUF_OK) {
					RzInterpreterIOResult io_res = { 0 };
					handle_io_request(core, &iset->il_vm->vm->vm_memory, &io_req, &io_res);
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
			if (!handle_yields(core, iset->yield_rbufs)) {
				iset_map[i].next_run_state = RZ_INTP_RUN_STATE_TERM;
				intpr_terminated++;
				// RZ_LOG_DEBUG("Next: TERM\n");
			}
			break;
		}
		case RZ_INTP_RUN_STATE_CLEAN: {
			if (!((expected_rs == RZ_INTP_RUN_STATE_CLEAN || expected_rs == RZ_INTP_RUN_STATE_EMU))) {
				break;
			}
			close_reset_ipc_obj(iset);
			open_ipc_obj(iset);
			rz_th_sem_post(iset->run_state_sync);
			iset_map[i].next_run_state = RZ_INTP_RUN_STATE_INIT;
			// RZ_LOG_DEBUG("Next: INIT\n");
			break;
		}
		case RZ_INTP_RUN_STATE_TERM: {
			if (expected_rs != RZ_INTP_RUN_STATE_TERM) {
				iset_map[i].next_run_state = RZ_INTP_RUN_STATE_TERM;
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

	RZ_LOG_DEBUG("INQUIRY: Wait for join\n");
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

	if (rz_log_get_level() > RZ_LOGLVL_INFO && rz_cons_is_interactive()) {
		eprintf("\n");
	}
	if (!rz_inquiry_bb_cfg_add_xrefs(core->inquiry->bb_cfg, core->inquiry->xrefs)) {
		rz_warn_if_reached();
	}
	if (!rz_inquiry_bb_cfg_reduce(core->inquiry->bb_cfg)) {
		rz_warn_if_reached();
	}
	if (!user_sent_signal) {
		eprintf("Complement BB CFG with statically known xrefs...\n");
		if (!rz_inquiry_bb_cfg_complement(core->inquiry, insn_to_insn_edges)) {
			rz_warn_if_reached();
		}
	}

	RZ_LOG_DEBUG("INQUIRY: Done\n");

	rz_config_set(core->config, "io.cache", io_cache_opt);

error_free:
	rz_interpreter_yield_rbuf_free(yield_rbufs[RZ_INTERPRETER_YIELD_KIND_XREF]);
	rz_interpreter_yield_rbuf_free(yield_rbufs[RZ_INTERPRETER_YIELD_KIND_CALL_CANDIDATE]);
	free(iset_map);
	rz_set_u_free(entry_points);
	rz_buf_free(io_buf);
	rz_vector_free(insn_to_insn_edges);
	ht_up_free(il_cache);
	rz_cons_pop();
	return return_code && !user_sent_signal;
}

static bool convert_and_add_to_analysis(RzAnalysis *analysis, RzInquiry *inquiry, RzPVector *fcns,
	const RzPVector /*<RzBinSymbol *>*/ *symbols) {
	// Add all discovered binary blocks to analysis

	RzIterator *iter = rz_graph_get_nodes(inquiry->bb_cfg->graph);
	RzGraphNode *n;
	rz_iterator_foreach(iter, n) {
		const RzInquiryBB *bb = rz_graph_node_get_data(n);
		rz_analysis_add_bb(analysis, bb->addr, bb->size);
	}
	rz_iterator_free(iter);


	iter = ht_up_as_iter(inquiry->call_candidates);
	void **it;
	rz_iterator_foreach (iter, it) {
		RzAnalysisCallCandidate *cc = *it;
		rz_analysis_xrefs_set(analysis, cc->candidate_addr, cc->target, RZ_ANALYSIS_XREF_TYPE_CALL);
	}
	rz_iterator_free(iter);

	RzAnalysisXRef *xref;
	rz_vector_foreach(inquiry->xrefs, xref) {
		rz_analysis_xrefs_set(analysis, xref->from, xref->to, xref->type != RZ_ANALYSIS_XREF_TYPE_CALL_RET ? xref->type : RZ_ANALYSIS_XREF_TYPE_CODE);
		RzAnalysisBlock *abb = rz_analysis_get_block_at(analysis, xref->bb_addr);
			RzIterator *out_edges = rz_inquiry_bb_cfg_get_outgoing_edges(inquiry->bb_cfg, xref->bb_addr);
			if (!out_edges) {
				continue;
			}
			RzGraphEdge *e;
			rz_iterator_foreach(out_edges, e) {
				RzInquiryBBCFGEdgeType type = (RzInquiryBBCFGEdgeType)(utptr)rz_graph_edge_get_data(e);
				switch (type) {
				case RZ_INQUIRY_BB_CFG_EDGE_TYPE_NONE:
					rz_warn_if_reached();
					// fall through
				case RZ_INQUIRY_BB_CFG_EDGE_TYPE_CF:
				case RZ_INQUIRY_BB_CFG_EDGE_TYPE_JMP: {
					ut64 target = rz_graph_node_get_id(rz_graph_edge_get_to(e));
					if (abb->jump == UT64_MAX || abb->jump == target) {
						abb->jump = target;
						eprintf("Add jump = 0x%llx -> 0x%llx (%d)\n", xref->bb_addr, target, type);
					} else if (abb->fail == UT64_MAX || abb->fail == target) {
						abb->fail = target;
						eprintf("Add fail = 0x%llx -> 0x%llx (%d)\n", xref->bb_addr, target, type);
					} else if (abb->fail != target && abb->jump != target) {
						RZ_LOG_WARN("The basic block at 0x%" PFMT64x " has more than two outgoing edges.\n"
							    "\t\tHas jump = 0x%llx fail = 0x%llx. Will miss = 0x%llx (%d)\n", xref->bb_addr, abb->jump, abb->fail,
							target, type);
					}
					break;
				}
				case RZ_INQUIRY_BB_CFG_EDGE_TYPE_CALL_RET:
				case RZ_INQUIRY_BB_CFG_EDGE_TYPE_CALL:
					break;
				}
			}
			rz_iterator_free(out_edges);
	}

	// // Convert the Inquiry functions to analysis function.
	// rz_pvector_foreach (fcns, it) {
	// 	RzInquiryFunction *fcn = *it;

	// 	ut64 fcn_addr = *(ut64 *)rz_vector_head(fcn->entry_points);
	// 	char new_fcn_name[64] = { 0 };
	// 	void **it;
	// 	rz_pvector_foreach (symbols, it) {
	// 		RzBinSymbol *s = *it;
	// 		if (s->vaddr == fcn_addr && RZ_STR_EQ(s->type, RZ_BIN_TYPE_FUNC_STR)) {
	// 			rz_strf(new_fcn_name, "sym.%s", s->name);
	// 			break;
	// 		}
	// 	}
	// 	if (new_fcn_name[0] == '\0') {
	// 		rz_strf(new_fcn_name, "fcn_0x%" PFMT64x, fcn_addr);
	// 	}
	// 	RzAnalysisFunction *afcn = rz_analysis_create_function(analysis, new_fcn_name, fcn_addr, RZ_ANALYSIS_FCN_TYPE_FCN);
	// 	if (!afcn) {
	// 		rz_warn_if_reached();
	// 		continue;
	// 	}

	// 	RzIterator *iter = rz_graph_get_nodes(fcn->bb_cfg->graph);
	// 	RzGraphNode *n;
	// 	rz_iterator_foreach(iter, n) {
	// 		const RzInquiryBB *bb = rz_graph_node_get_data(n);
	// 		RzAnalysisBlock *abb = rz_analysis_get_block_at(analysis, bb->addr);
	// 		if (!abb && !(abb = rz_analysis_create_block(analysis, bb->addr, bb->size))) {
	// 			rz_warn_if_reached();
	// 			continue;
	// 		}
	// 		rz_analysis_function_add_block(afcn, abb);
	// 	}
	// 	rz_iterator_free(iter);
	// }
	rz_pvector_free(fcns);
	return true;
}

RZ_API bool rz_inquiry_function_deduction(RzAnalysis *analysis, RzInquiry *inquiry, RzSetU *symbol_addresses,
	const RzPVector /*<RzBinSymbol *>*/ *symbols,
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code) {
	RzPVector *fcns = rz_pvector_new((RzPVectorFree)rz_inquiry_function_free);
	if (!rz_inquiry_algo_revng_fcn_detection(
		    symbol_addresses,
		    inquiry->call_candidates,
		    inquiry->bb_cfg,
		    fcns,
		    ignored_code)) {
		rz_warn_if_reached();
		return false;
	}

	return convert_and_add_to_analysis(analysis, inquiry, fcns, symbols);
}
