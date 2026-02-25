// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_lib.h>
#include <rz_inquiry.h>

#include "rz_analysis.h"
#include "rz_bin.h"
#include "rz_config.h"
#include "rz_cons.h"
#include "rz_il/definitions/mem.h"
#include "rz_il/rz_il_validate.h"
#include "rz_il/rz_il_vm.h"
#include "rz_inquiry/rz_interpreter.h"
#include "rz_inquiry_plugins.h"
#include "rz_th.h"
#include "rz_types.h"
#include "rz_util/ht_pp.h"
#include "rz_util/ht_sp.h"
#include "rz_util/ht_up.h"
#include "rz_util/rz_bitvector.h"
#include "rz_util/rz_buf.h"
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
	if (plugin->p_interpreter->init) {
		plugin->p_interpreter->init(ht_sp_find(inquiry->plugins_data, plugin->p_interpreter->name, NULL));
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
	free(fcn);
}

RZ_IPI RZ_OWN RzInquiryFunction *rz_inquiry_function_new() {
	RzInquiryFunction *fcn = RZ_NEW0(RzInquiryFunction);
	if (!fcn) {
		return NULL;
	}
	fcn->bb_cfg = rz_inquiry_bb_cfg_new();
	fcn->entry_points = rz_vector_new(sizeof(ut64), NULL, NULL);
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
	RzIterator *iter = ht_up_as_iter(fcn->bb_cfg->basic_blocks);
	RzInterval **itv;
	rz_iterator_foreach(iter, itv) {
		RzInterval *bb = *itv;
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
	iq->xrefs = rz_vector_new(sizeof(RzAnalysisXRef), NULL, NULL);
	iq->bb_cfg = rz_inquiry_bb_cfg_new();
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
	if (xref->type == RZ_ANALYSIS_XREF_TYPE_CODE) {
		rz_inquiry_bb_cfg_add_edge(iq->bb_cfg, xref->bb_addr, xref->to);
	}
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

static bool setup_queues(RzCore *core,
	RZ_OUT RzThreadQueue **il_queue,
	RZ_OUT RzThreadQueue **io_request_q,
	RZ_OUT RzThreadQueue **io_result_q,
	RZ_OUT RzThreadQueue **addr_queue,
	RZ_OUT HtUP **yield_queues) {
	*il_queue = NULL;
	*io_request_q = NULL;
	*io_result_q = NULL;
	*addr_queue = NULL;
	*yield_queues = NULL;

	RzPVector /*<RzBinSection *>*/ *boundaries = NULL;
	RzInterpreterYieldQueue *yield_queue = NULL;
	// The queue to pass the Effects to the interpreter.
	// This is only one queue for the prototype.
	// In practice it would be one for each interpreter.
	*il_queue = rz_th_queue_new(RZ_INTERPRETER_IL_QUEUE_SIZE, NULL);
	if (!il_queue) {
		goto error_free;
	}

	// Setup the IO queues. Each interpreter instance needs it's own queue at
	// for writing IO. Because the writing is done on the IO cache, and each
	// instance needs its own cache.
	*io_request_q = rz_th_queue_new(RZ_INTERPRETER_IO_QUEUE_SIZE, NULL);
	*io_result_q = rz_th_queue_new(RZ_INTERPRETER_IO_QUEUE_SIZE, NULL);
	if (!io_request_q || !io_result_q) {
		goto error_free;
	}

	// The address queue. It is the queue the interpreter can request new Effects.
	// Of course, currently there is only a single one for the prototype.
	// In practice there would be one for each interpreter instance.
	*addr_queue = rz_th_queue_new(RZ_INTERPRETER_ADDR_QUEUE_SIZE, NULL);
	if (!addr_queue) {
		goto error_free;
	}

	// Multiple yield queues can be used by a single interpreter.
	// E.g. if the interpreter has a complex abstract memory model
	// for stack, heap and constant values.
	// Then it can produce three kind of yields.
	*yield_queues = ht_up_new(NULL, (HtUPFreeValue)rz_interpreter_yield_queue_free);
	if (!yield_queues) {
		goto error_free;
	}

	// Here we build the filter for the yield queue.
	// The prototype generates constant xrefs.
	// So the filter checks the generated xrefs, if they are within the IO map
	// boundaries.
	boundaries = rz_bin_object_get_sections(core->bin->cur->o);
	if (!boundaries) {
		goto error_free;
	}

	// These yield queues can be shared between different interpreters.
	// So we have one yield queue for each yield type.

	// Xref yield queue.
	RzInterpreterYieldKind yield_kind = RZ_INTERPRETER_YIELD_KIND_XREF;
	yield_queue = rz_interpreter_yield_queue_new(
		yield_kind,
		(RzInterpreterYieldFilter)rz_inquiry_xref_interpreter_filter,
		boundaries);
	if (!yield_queue) {
		goto error_free;
	}
	ht_up_insert(*yield_queues, yield_kind, yield_queue);

	yield_kind = RZ_INTERPRETER_YIELD_KIND_CALL_CANDIDATE;
	yield_queue = rz_interpreter_yield_queue_new(yield_kind, NULL, NULL);
	if (!yield_queue) {
		goto error_free;
	}
	ht_up_insert(*yield_queues, yield_kind, yield_queue);
	return true;

error_free:
	ht_up_free(*yield_queues);
	rz_th_queue_free(*il_queue);
	rz_th_queue_free(*io_request_q);
	rz_th_queue_free(*io_result_q);
	rz_th_queue_free(*addr_queue);
	return false;
}

static bool get_branch_targets(RzCore *core, RzSetU *branch_targets, RzVector /*<RzAnalysisXRef>*/ *insn_to_insn_edges) {
	RzPVector /*<RzBinSection *>*/ *sections = rz_bin_object_get_sections(core->bin->cur->o);
	if (!sections) {
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

static RzVector /*<RzInterval>*/ *get_ignored_code_regions(
	const RzPVector /*<RzBinSymbol *>*/ *symbols,
	RzPVector /*<RzBinSection *>*/ *sections) {
	void **it;
	RzVector *v = rz_vector_new(sizeof(RzInterval), NULL, NULL);
	rz_pvector_foreach (sections, it) {
		RzBinSection *sec = *it;
		if (sec->layout.role == RZ_BIN_SECTION_ROLE_LINKING) {
			RzInterval itv = { .addr = sec->vaddr, .size = sec->vsize };
			rz_vector_push(v, &itv);
		}
	}
	rz_pvector_free(sections);
	rz_pvector_foreach (symbols, it) {
		RzBinSymbol *sym = *it;
		if (sym->is_imported) {
			RzInterval itv = { .addr = sym->vaddr, .size = sym->size };
			rz_vector_push(v, &itv);
		}
	}
	return v;
}

static bool handle_yields(RzCore *core, HtUP *yield_queues) {
	RzInterpreterYieldQueue *q_xrefs = ht_up_find(yield_queues, RZ_INTERPRETER_YIELD_KIND_XREF, NULL);
	if (!rz_th_queue_is_empty(q_xrefs->yield_queue)) {
		RzAnalysisXRef *xref = NULL;
		if (!rz_th_queue_pop(q_xrefs->yield_queue, false, (void **)&xref) || !xref) {
			return false;
		}
		rz_inquiry_add_xref(core->inquiry, xref);
		rz_analysis_xrefs_set(core->analysis, xref->from, xref->to, xref->type);
		RZ_LOG_DEBUG("Added xref: 0x%" PFMT64x " -> 0x%" PFMT64x " (%s)\n", xref->from, xref->to, rz_analysis_ref_type_tostring(xref->type));
	}

	RzInterpreterYieldQueue *q_calls = ht_up_find(yield_queues, RZ_INTERPRETER_YIELD_KIND_CALL_CANDIDATE, NULL);
	if (!rz_th_queue_is_empty(q_calls->yield_queue)) {
		RzAnalysisCallCandidate *cc = NULL;
		if (!rz_th_queue_pop(q_calls->yield_queue, false, (void **)&cc) || !cc) {
			return false;
		}
		RzAnalysisCallCandidate *cc_clone = RZ_NEW0(RzAnalysisCallCandidate);
		memcpy(cc_clone, cc, sizeof(RzAnalysisCallCandidate));
		if (!ht_up_update(core->inquiry->call_candidates, cc_clone->bb_addr, cc_clone)) {
			RZ_LOG_DEBUG("Overwrote a call candidate located at 0x%" PFMT64x "\n", cc_clone->candidate_addr);
		} else {
			RZ_LOG_DEBUG("Added call candidate located at 0x%" PFMT64x "\n", cc_clone->candidate_addr);
		}
	}
	return true;
}

static const RzInterpreterILBB *get_il_bb(RzCore *core, HtUP *il_cache, ut64 addr) {
	RzInterpreterILBB *bb = ht_up_find(il_cache, addr, NULL);
	if (!bb) {
		RZ_LOG_DEBUG("INQUIRY: Lift new BB\n");
		bb = rz_inquiry_gen_il_bb(core->analysis, core->io, addr);
		if (!bb) {
			RZ_LOG_DEBUG("Failed to lift basic block at 0x%" PFMT64x "\n", addr);
			return NULL;
		}

#if RZ_BUILD_DEBUG
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
		// Otherwise YOLO
#endif

		RZ_LOG_DEBUG("INQUIRY: Send IL result: %p.\n", bb);
		ht_up_insert(il_cache, bb->bb_addr, bb);
	} else {
		RZ_LOG_DEBUG("INQUIRY: Serve BB from cache\n");
	}
	return bb;
}

/**
 * A function to call the prototype interpreter.
 * Usually these tasks will be split between different caches and yield consumers.
 */
RZ_API bool rz_inquiry_interpreter(RzCore *core, RZ_OWN RzVector /*<ut64>*/ *entry_points) {
	// All the things we need
	bool return_code = true;
	RzThreadQueue *io_request_q = NULL;
	RzThreadQueue *io_result_q = NULL;
	RzThreadQueue *addr_queue = NULL;
	HtUP *yield_queues = NULL;
	RzAtomicBool *is_running = rz_atomic_bool_new(true);
	RzInterpreterAbstrState *abstr_state = NULL;
	RzInterpreterSet *iset = NULL;
	HtUP *il_cache = NULL;
	RzThreadQueue *il_queue = NULL;
	RzThread *interpr_th = NULL;
	RzBuffer *io_buf = rz_buf_new_with_io(&core->analysis->iob);
	RzAnalysisILVM *analysis_vm = NULL;
	RzSetU *branch_targets = rz_set_u_new();
	bool user_sent_signal = false;

	rz_cons_push();

	if (!setup_queues(core, &il_queue, &io_request_q, &io_result_q, &addr_queue, &yield_queues)) {
		return_code = false;
		goto error_free;
	}

	// The pseudo cache of IL effects.
	// This is only a vector so we can simulate the ownership separation
	// of the pointers.
	il_cache = ht_up_new(NULL, (RzPVectorFree)rz_interpreter_il_bb_free);

	RzVector /*<RzAnalysisXRef>*/ *insn_to_insn_edges = rz_vector_new(sizeof(RzAnalysisXRef), NULL, NULL);
	if (!get_branch_targets(core, branch_targets, insn_to_insn_edges)) {
		RZ_LOG_ERROR("Failed to get branch targets.\n");
		return_code = false;
		goto error_free;
	}

	if (rz_log_get_level() > RZ_LOGLVL_INFO && rz_cons_is_interactive()) {
		printf("Total branch targets in binary: %" PFMT32d "\n", rz_set_u_size(branch_targets));
	}

	// Initialize the abstract state with the architecture's registers.
	if (!core->analysis->cur->il_config) {
		RZ_LOG_ERROR("The RzArch plugin doesn't have il_config() implemented.\n");
		return_code = false;
		goto error_free;
	}

	// Perform the RzAnalysisILVM and abstract state setup procedure.
	// This prototype won't use the RzAnalysisILVM directly but its components.
	// That is because the prototypes doesn't handle the VM tasks (track PC, handle IO)
	// in one VM object, but in separated modules.
	// So analysis_vm->vm->vm_memorys is used for handling IO requests and
	// analysis_vm->reg_binding is used for the abstract state setup.
	//
	// TODO: Is it a good idea to separate these tasks into different modules?
	// It allows the IO handler to buffer reads in r-- sections for multiple interpreters.
	// Possibly allows to optimize the IO access, because there is only module accessing it (not every interpreter).
	// But is there any other advantage?
	{
		analysis_vm = rz_analysis_il_vm_new(core->analysis, core->analysis->reg);
		if (!analysis_vm) {
			RZ_LOG_ERROR("Failed during RzAnalysisILVM setup.\n");
			return_code = false;
			goto error_free;
		}

		RzAnalysisILConfig *config = core->analysis->cur->il_config(core->analysis);
		abstr_state = rz_interpreter_abstr_state_new(
			core->analysis->cur->arch,
			RZ_INTERPRETER_ABSTRACTION_CONST,
			config,
			analysis_vm->reg_binding);
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
	iset = rz_interpreter_set_new(
		// TODO: Maybe use the pointer from RzCore.
		// But in general the whole thing should run without RzCore.
		prototype->p_interpreter,
		abstr_state,
		addr_queue,
		il_queue,
		yield_queues,
		io_request_q,
		io_result_q,
		is_running,
		rz_vector_clone(entry_points),
		get_ignored_code_regions(
			rz_bin_object_get_symbols(core->bin->cur->o),
			rz_bin_object_get_sections(core->bin->cur->o)));
	if (!iset) {
		return_code = false;
		rz_warn_if_reached();
		goto error_free;
	}

	do {
		bool bb_decode_failed = false;

		// Dispatch prototype interpreter into a thread.
		RZ_LOG_DEBUG("INQUIRY: Start main interpretation thread.\n");
		interpr_th = rz_th_new((RzThreadFunction)rz_interpreter_run, iset);

		// Poor man's shared memory.
		RzInterpreterIOResult _io_res = { 0 };
		RzInterpreterIOResult *io_res = &_io_res;

		// From here on, the code plays the role of the cache, IO handler,
		// and yield consumer.
		// - Waiting for new Effects to be requested and sending them.
		// - Handling IO requests.
		// - Receiving and adding the found xrefs to RzAnalysis.
		// In the final implementation each of those roles would be split into
		// two or more separated modules running in parallel.
		RZ_LOG_DEBUG("INQUIRY: Start IL providing loop.\n");
		rz_atomic_bool_set(is_running, true);

		while (rz_atomic_bool_get(is_running)) {
			if (rz_th_terminated(interpr_th) || rz_cons_is_breaked()) {
				rz_atomic_bool_set(is_running, false);
				user_sent_signal = rz_cons_is_breaked();
				break;
			}

			// =========
			// IL CACHE
			// =========
			//
			// This block mimics the IL cache. It uplifts basic blocks and
			// caches them.
			{
				if (!rz_th_queue_is_empty(iset->branch_queue)) {
					RzInterpreterBranch *branch = NULL;
					if (!rz_th_queue_pop(iset->branch_queue, false, (void **)&branch) || !branch) {
						rz_warn_if_reached();
						break;
					}
					RZ_LOG_DEBUG("INQUIRY: Received IL request: 0x%" PFMT64x "\n", branch->target_addr);
					const RzInterpreterILBB *bb = get_il_bb(core, il_cache, branch->target_addr);
					if (!bb) {
						// Delete the address from the branch targets.
						// This is currently necessary as a work around, because if the interpreter
						// fails before interpreting the address, it is added again as next entry point.
						// Giving an endless loop.
						// One of the design thingies to fix in the proper implementation.
						rz_set_u_delete(branch_targets, branch->target_addr);
						// Signal interpreter the lifting failed.
						rz_atomic_bool_set(is_running, false);
						rz_th_queue_close(io_request_q);
						rz_th_queue_close(io_result_q);
						rz_th_queue_close(iset->branch_queue);
						rz_th_queue_close(iset->il_queue);
						bb_decode_failed = true;
						break;
					}
					rz_inquiry_bb_cfg_add_basic_block(core->inquiry->bb_cfg, bb->bb_addr, bb->size);
					rz_inquiry_bb_cfg_add_edge(core->inquiry->bb_cfg, branch->branching_bb_addr, branch->target_addr);
					rz_th_queue_push(iset->il_queue, (void *)bb, true);
				}
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
			{
				if (!rz_th_queue_is_empty(io_request_q)) {
					RzInterpreterIORequest *io_req = NULL;
					if (!rz_th_queue_pop(io_request_q, false, (void **)&io_req) || !io_req) {
						rz_atomic_bool_set(is_running, false);
						rz_warn_if_reached();
						break;
					}
					handle_io_request(core, &analysis_vm->vm->vm_memory, io_req, io_res);
					rz_th_queue_push(io_result_q, io_res, true);
				}
			}

			// ==============
			// YIELD CONSUMER
			// ==============
			//
			// This part plays the role of a yield consumer.
			// In our prototype it only receives xrefs and call candidates.
			{
				if (!handle_yields(core, yield_queues)) {
					rz_atomic_bool_set(is_running, false);
					break;
				}
			}
		}

		rz_th_queue_close(io_request_q);
		rz_th_queue_close(io_result_q);
		rz_th_queue_close(iset->branch_queue);
		rz_th_queue_close(iset->il_queue);

		RZ_LOG_DEBUG("INQUIRY: Wait for join\n");
		rz_th_wait(interpr_th);
		bool interpr_ret = rz_th_get_retv(interpr_th);
		rz_th_free(interpr_th);
		if ((!interpr_ret && !bb_decode_failed) || user_sent_signal) {
			if (!user_sent_signal) {
				RZ_LOG_ERROR("Interpreter failed with an error. Abort.\n");
			} else {
				RZ_LOG_ERROR("User sent signal.\n");
			}
			break;
		}
		// Clear shared objects to not have any left overs in the next run.
		memset((ut8 *)iset->state->shared_obj, 0, sizeof(RzInterpreterSharedObjects));
		// Open queue again, so the interpretation can start at another
		// jump target again.
		rz_th_queue_open(io_request_q);
		rz_th_queue_open(io_result_q);
		rz_th_queue_open(iset->branch_queue);
		rz_th_queue_open(iset->il_queue);
		// Clear queues from any left overs of previous runs.
		rz_list_free(rz_th_queue_pop_all(io_result_q));
		rz_list_free(rz_th_queue_pop_all(io_request_q));
		rz_list_free(rz_th_queue_pop_all(iset->il_queue));
		rz_list_free(rz_th_queue_pop_all(iset->branch_queue));

		// At this point the interpreter is finished and returned.
		// Now we need to check for executable regions it did not cover.
		// For this we simply delete all jump targets from our set, which point
		// into the already handled basic blocks.
		// Then add a few addresses as new entry point.
		// The addresses we add are jump targets from jump/call instructions in the binary.
		{
			rz_vector_clear(entry_points);
			RzVector *covered_jump_targets = rz_vector_new(sizeof(ut64), NULL, NULL);
			RzIterator *ct_iter = rz_set_u_as_iter(branch_targets);
			size_t x = 0;
			ut64 *ct;
			rz_iterator_foreach(ct_iter, ct) {
				if (ht_up_find(il_cache, *ct, NULL)) {
					// This call target was interpreted before (hence is in the IL cache).
					rz_vector_push(covered_jump_targets, ct);
					continue;
				}
				x++;
				rz_vector_push(entry_points, ct);
				// Experiment how many new entry points we add.
				if (x >= 1) {
					break;
				}
			}
			rz_iterator_free(ct_iter);
			rz_interpreter_set_add_entry_points(iset, entry_points);

			ut64 *ep;
			rz_vector_foreach (covered_jump_targets, ep) {
				// Delete the selected ones from the jump target set.
				// So they are not requested again.
				rz_set_u_delete(branch_targets, *ep);
			}
			rz_vector_free(covered_jump_targets);
		}
		if (rz_log_get_level() > RZ_LOGLVL_INFO && rz_cons_is_interactive()) {
			printf(RZ_CONS_CLEAR_LINE "\rBranch targets left: %" PFMT32d, rz_set_u_size(branch_targets));
			fflush(stdout);
		}
	} while (!rz_vector_empty(entry_points));

	if (rz_log_get_level() > RZ_LOGLVL_INFO && rz_cons_is_interactive()) {
		printf("\n");
	}
	if (!rz_inquiry_bb_cfg_reduce(core->inquiry->bb_cfg)) {
		rz_warn_if_reached();
		goto error_free;
	}
	if (!rz_inquiry_bb_cfg_complement(core->inquiry, insn_to_insn_edges)) {
		rz_warn_if_reached();
		goto error_free;
	}
	rz_vector_free(insn_to_insn_edges);

	RZ_LOG_DEBUG("INQUIRY: Done\n");

	rz_config_set(core->config, "io.cache", io_cache_opt);

	// Wait for thread to finish before cleaning.
error_free:
	RZ_LOG_DEBUG("INQUIRY: Close queues\n");
	rz_vector_free(entry_points);
	rz_set_u_free(branch_targets);
	rz_buf_free(io_buf);
	rz_analysis_il_vm_free(analysis_vm);
	rz_th_queue_close(io_request_q);
	rz_th_queue_close(io_result_q);
	rz_th_queue_close(iset->branch_queue);
	rz_th_queue_close(iset->il_queue);

	if (!iset) {
		// Ownership of all those objects wasn't yet passed to the iset.
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		rz_th_queue_free(io_request_q);
		rz_th_queue_free(io_result_q);
		// yield_queues frees each individual queue as well.
		ht_up_free(yield_queues);
		rz_atomic_bool_free(is_running);
		rz_interpreter_abstr_state_free(abstr_state);
	} else {
		// Ownership was passed to iset
		rz_interpreter_set_free(iset);
	}
	ht_up_free(il_cache);

	rz_cons_pop();
	return return_code && !user_sent_signal;
}

static bool convert_and_add_to_analysis(RzAnalysis *analysis, RzInquiry *inquiry, RzPVector *fcns,
	const RzPVector /*<RzBinSymbol *>*/ *symbols) {
	// Add all discovered binary blocks to analysis

	RzIterator *iter = ht_up_as_iter(inquiry->bb_cfg->basic_blocks);
	RzInterval **it_bb;
	rz_iterator_foreach(iter, it_bb) {
		RzInterval *bb = *it_bb;
		rz_analysis_add_bb(analysis, bb->addr, bb->size);
	}
	rz_iterator_free(iter);

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
			return false;
		}

		void **it2;
		RzIterator *iter = ht_up_as_iter(fcn->bb_cfg->basic_blocks);
		rz_iterator_foreach(iter, it2) {
			RzInterval *bb = *it2;
			RzAnalysisBlock *abb = rz_analysis_get_block_at(analysis, bb->addr);
			if (!abb && !(abb = rz_analysis_create_block(analysis, bb->addr, bb->size))) {
				rz_warn_if_reached();
				return false;
			}
			const RzList *successors = rz_inquiry_bb_cfg_get_neighbours_from(inquiry->bb_cfg, bb->addr);
			RzGraphNode *n;
			if (rz_list_length(successors) > 0) {
				n = rz_list_get_n(successors, 0);
				abb->jump = (ut64)n->data;
			}
			if (rz_list_length(successors) > 1) {
				n = rz_list_get_n(successors, 1);
				abb->fail = (ut64)n->data;
			}
			RzAnalysisCallCandidate *cc;
			if ((cc = ht_up_find(inquiry->call_candidates, bb->addr, NULL))) {
				// Calls need an edge between the call instruction and its return address.
				// That is technically wrong, because the call could be a tail call.
				// But the prototype doesn't model this.
				// So just add an edge.
				abb->jump = cc->npc;
			}
			rz_analysis_function_add_block(afcn, abb);
		}
		rz_iterator_free(iter);
	}
	rz_pvector_free(fcns);
	return true;
}

RZ_API bool rz_inquiry_function_deduction(RzAnalysis *analysis, RzInquiry *inquiry, ut64 entry_point,
	const RzPVector /*<RzBinSymbol *>*/ *symbols) {
	RzPVector *fcns = rz_pvector_new((RzPVectorFree)rz_inquiry_function_free);
	if (!rz_inquiry_algo_revng_fcn_detection(
		entry_point,
		inquiry->call_candidates,
		inquiry->bb_cfg,
		fcns)) {
		rz_warn_if_reached();
		return false;
	}

	return convert_and_add_to_analysis(analysis, inquiry, fcns, symbols);
}
