// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_lib.h>
#include <rz_inquiry.h>

#include "rz_analysis.h"
#include "rz_config.h"
#include "rz_cons.h"
#include "rz_il/definitions/mem.h"
#include "rz_il/rz_il_vm.h"
#include "rz_inquiry/rz_interpreter.h"
#include "rz_inquiry_plugins.h"
#include "rz_io.h"
#include "rz_th.h"
#include "rz_util/rz_bitvector.h"
#include "rz_util/rz_buf.h"
#include "rz_util/rz_set.h"
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
	if (plugin->p_interpreter) {
		if (!ht_sp_insert(inquiry->plugins, plugin->p_interpreter->name, plugin)) {
			RZ_LOG_WARN("Plugin '%s' was already added.\n", plugin->p_interpreter->name);
		}
		return true;
	}

	rz_warn_if_reached();
	return false;
}

RZ_API bool rz_inquiry_plugin_del(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_OWN RZ_NONNULL RzInquiryPlugin *plugin) {
	rz_return_val_if_fail(inquiry && plugin, false);

	if (plugin->p_interpreter) {
		return ht_sp_delete(inquiry->plugins, plugin->p_interpreter->name);
	}
	rz_warn_if_reached();
	return false;
}

RZ_API bool rz_inquiry_xref_interpreter_filter(ut64 *xref_to_addr, RZ_NONNULL const RzList /*<RzIOMap *>*/ *allowed_io_maps) {
	rz_return_val_if_fail(xref_to_addr && allowed_io_maps, false);
	const RzIOMap *map;
	RzListIter *it;
	rz_list_foreach (allowed_io_maps, it, map) {
		ut64 start = map->itv.addr;
		ut64 end = map->itv.addr + map->itv.size;
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

static bool setup_queues(RzIO *io,
	RZ_OUT RzThreadQueue **il_queue,
	RZ_OUT RzThreadQueue **io_request_q,
	RZ_OUT RzThreadQueue **io_result_q,
	RZ_OUT RzThreadQueue **addr_queue,
	RZ_OUT HtUP **yield_queues) {
	RzList *boundaries = NULL;
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

	// Here we build the filter for the yield queue.
	// The prototype generates constant xrefs.
	// So the filter checks the generated xrefs, if they are within the IO map
	// boundaries.
	RzInterval iv = { .addr = 0, .size = UT64_MAX };
	boundaries = rz_io_get_boundaries_all_io_maps(io, iv);
	if (!boundaries) {
		goto error_free;
	}

	// Now create a set of yield queue(s).
	// These yield queues can be shared between different interpreters.
	// So we have one yield queue for each yield type.
	RzInterpreterYieldKind yield_kind = RZ_INTERPRETER_YIELD_KIND_XREF;
	yield_queue = rz_interpreter_yield_queue_new(
		yield_kind,
		(RzInterpreterYieldFilter)rz_inquiry_xref_interpreter_filter,
		boundaries);
	if (!yield_queue) {
		goto error_free;
	}

	// Multiple yield queues can be used by a single interpreter.
	// E.g. if the interpreter has a complex abstract memory model
	// for stack, heap and constant values.
	// Then it can produce three kind of yields.
	*yield_queues = ht_up_new(NULL, (HtUPFreeValue)rz_interpreter_yield_queue_free);
	if (!yield_queue || !yield_queues) {
		goto error_free;
	}
	ht_up_insert(*yield_queues, yield_kind, yield_queue);

	return true;

error_free:
	return false;
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
	RzPVector *il_cache = NULL;
	RzThreadQueue *il_queue = NULL;
	RzThread *interpr_th = NULL;
	RzBuffer *io_buf = rz_buf_new_with_io(&core->analysis->iob);
	RzAnalysisILVM *analysis_vm = NULL;
	RzSetU *call_targets = rz_set_u_new();

	rz_cons_push();

	if (!setup_queues(core->io, &il_queue, &io_request_q, &io_result_q, &addr_queue, &yield_queues)) {
		return_code = false;
		goto error_free;
	}

	// The pseudo cache of IL effects.
	// This is only a vector so we can simulate the ownership separation
	// of the pointers.
	il_cache = rz_pvector_new((RzPVectorFree)rz_interpreter_il_bb_free);

	RzInterval iv = { .addr = 0, .size = UT64_MAX };
	RzList *boundaries = rz_io_get_boundaries_all_io_maps(core->io, iv);
	if (!boundaries) {
		goto error_free;
	}
	if (!rz_analysis_get_all_call_targets(core->analysis, boundaries, call_targets)) {
		RZ_LOG_ERROR("Failed to get call targets.\n");
		return_code = false;
		goto error_free;
	}
	rz_list_free(boundaries);
	RZ_LOG_DEBUG("Total call targets in binary: %" PFMT32d "\n", rz_set_u_size(call_targets));

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
	iset = rz_interpreter_set_new(
		rz_inquiry_plugin_interpreter_prototype.p_interpreter,
		abstr_state,
		addr_queue,
		il_queue,
		yield_queues,
		io_request_q,
		io_result_q,
		is_running,
		rz_vector_clone(entry_points));
	if (!iset) {
		return_code = false;
		rz_warn_if_reached();
		goto error_free;
	}

	do {
		bool bb_decode_failed = false;
		// Clear queues from any left overs of previous runs.
		rz_list_free(rz_th_queue_pop_all(iset->il_queue));
		rz_list_free(rz_th_queue_pop_all(iset->addr_queue));

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
				break;
			}

			// =========
			// IL CACHE
			// =========
			//
			// This block mimics the IL cache.
			{
				if (!rz_th_queue_is_empty(iset->addr_queue)) {
					ut64 *addr = NULL;
					if (!rz_th_queue_pop(iset->addr_queue, false, (void **)&addr) || !addr) {
						rz_warn_if_reached();
						break;
					}
					RZ_LOG_DEBUG("INQUIRY: Received IL request: 0x%" PFMT64x "\n", (*addr));
					size_t bb_size = 0;
					RzInterpreterILBB *bb = rz_inquiry_gen_il_bb(core->analysis, core->io, *addr, &bb_size);
					if (!bb) {
						RZ_LOG_ERROR("Failed to lift basic block at 0x%" PFMT64x "\n", *addr);
						// Signal interpreter the lifting failed.
						rz_atomic_bool_set(is_running, false);
						rz_th_queue_close(iset->addr_queue);
						rz_th_queue_close(iset->il_queue);
						bb_decode_failed = true;
						break;
					}
					rz_analysis_add_bb(core->analysis, *addr, bb_size);
					RZ_LOG_DEBUG("INQUIRY: Send IL result: %p.\n", bb);
					rz_pvector_push(il_cache, bb);
					// TODO: Free unused if too big.
					rz_th_queue_push(iset->il_queue, bb, true);
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
			// In our prototype it only receives xrefs and stores them in RzAnalysis.
			{
				RzInterpreterYieldQueue *q = ht_up_find(yield_queues, RZ_INTERPRETER_YIELD_KIND_XREF, NULL);
				if (!rz_th_queue_is_empty(q->yield_queue)) {
					RzAnalysisXRef *xref = NULL;
					if (!rz_th_queue_pop(q->yield_queue, false, (void **)&xref) || !xref) {
						rz_atomic_bool_set(is_running, false);
						break;
					}
					// TODO: Currently we can't classify calls as such.
					rz_analysis_xrefs_set(core->analysis, xref->from, xref->to, xref->type);
					RZ_LOG_DEBUG("Added xref: 0x%" PFMT64x " -> 0x%" PFMT64x " (%s)\n", xref->from, xref->to, rz_analysis_ref_type_tostring(xref->type));
				}
			}
		}

		RZ_LOG_DEBUG("INQUIRY: Wait for join\n");
		rz_th_wait(interpr_th);
		return_code = rz_th_get_retv(interpr_th);
		rz_th_free(interpr_th);
		if (!return_code && !bb_decode_failed) {
			RZ_LOG_ERROR("Interpreter failed with an error. Abort.\n");
			break;
		} else if (bb_decode_failed) {
			// Open queue again, so the interpretation can start at another
			// call target again.
			rz_th_queue_open(iset->addr_queue);
			rz_th_queue_open(iset->il_queue);
		}

		// At this point the interpreter is finished and returned.
		// Now we need to check for executable regions it did not cover.
		// For this we simply delete all call targets from our set, which point
		// into the already handled basic blocks.
		// Then add a few addresses as new entry points.
		// The addresses we add are call targets from call instructions in the binary.
		{
			rz_vector_clear(entry_points);
			RzVector *covered_call_targets = rz_vector_new(sizeof(ut64), NULL, NULL);
			RzIterator *ct_iter = rz_set_u_as_iter(call_targets);
			size_t x = 0;
			ut64 *ct;
			rz_iterator_foreach(ct_iter, ct) {
				RzList *containing_blocks = rz_analysis_get_blocks_in(core->analysis, *ct);
				if (rz_list_length(containing_blocks) != 0) {
					rz_vector_push(covered_call_targets, ct);
					rz_list_free(containing_blocks);
					continue;
				}
				rz_list_free(containing_blocks);
				x++;
				rz_vector_push(entry_points, ct);
				// Experiment how many new entry points we add.
				if (x >= 1) {
					break;
				}
			}
			rz_interpreter_set_add_entry_points(iset, entry_points);

			rz_iterator_free(ct_iter);
			ut64 *ep;
			rz_vector_foreach (covered_call_targets, ep) {
				// Delete the selected ones from the call target set.
				// So they are not requested again.
				rz_set_u_delete(call_targets, *ep);
			}
			rz_vector_free(covered_call_targets);

			RZ_LOG_DEBUG("Call targets left: %" PFMT32d "\n", rz_set_u_size(call_targets));
		}
	} while (!rz_vector_empty(entry_points));

	RZ_LOG_DEBUG("INQUIRY: Done\n");

	rz_config_set(core->config, "io.cache", io_cache_opt);

	// Wait for thread to finish before cleaning.
error_free:
	RZ_LOG_DEBUG("INQUIRY: Close queues\n");
	rz_vector_free(entry_points);
	rz_set_u_free(call_targets);
	rz_buf_free(io_buf);
	rz_analysis_il_vm_free(analysis_vm);
	rz_th_queue_close(il_queue);
	rz_th_queue_close(io_request_q);
	rz_th_queue_close(io_result_q);

	if (!iset) {
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
	rz_pvector_free(il_cache);

	rz_cons_pop();
	return return_code;
}
