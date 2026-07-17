// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2025-2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Interpreter Driver
 *
 * Main loop spawning and serving interpreter threads,
 * as well as integrating results as they are emitted.
 */

#include <rz_inquiry/rz_interpreter.h>
#include <rz_core.h>

static void close_reset_ipc_obj(RzInterpInstance *iset) {
	// Close and clear all the IPC objects of this interpreter.
	// This also clears the buffer and queues
	rz_th_ring_buf_close(iset->io_request_rbuf);
	rz_th_ring_buf_close(iset->io_result_rbuf);
	rz_th_ring_buf_close(iset->entry_points);
	rz_th_ring_buf_close(iset->il_cache_client->req_rbuf);
	rz_th_queue_close(iset->il_cache_client->il_queue);
	rz_list_free(rz_th_queue_pop_all(iset->il_cache_client->il_queue));
}

static void open_ipc_obj(RzInterpInstance *iset) {
	// Open queue again, so the interpretation can start at another
	// jump target again.
	rz_th_ring_buf_open(iset->io_request_rbuf);
	rz_th_ring_buf_open(iset->io_result_rbuf);
	rz_th_ring_buf_open(iset->il_cache_client->req_rbuf);
	rz_th_queue_open(iset->il_cache_client->il_queue);
	rz_th_ring_buf_open(iset->entry_points);
}

static void handle_io_request(RzAnalysisILContext *il_ctx, RzInterpIOReadRequest *io_req, RZ_OUT RzInterpIOResult *io_res) {
	RZ_LOG_DEBUG("inquiry: Received IO read request: mem:%" PFMTSZd " 0x%" PFMT64x "\n",
		io_req->mem_idx,
		rz_bv_to_ut64(io_req->addr));
	io_res->req_ok = false;
	RzILMemIndex mem_idx = io_req->mem_idx;
	if (mem_idx > rz_vector_len(&il_ctx->memory)) {
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

struct ituple {
	RzThread *ithread;
	RzInterpInstance *iset;
	RzInterpRunStateFlag next_run_state;
};

RZ_API bool rz_interp_driver_run(RzCore *core, RZ_OWN RzSetU *entry_points) {
	// All the things we need
	bool return_code = true;
	RzInterpInstance *inst = NULL;

	RzBuffer *io_buf = rz_buf_new_with_io(rz_analysis_get_io_bind(core->analysis));
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
	size_t n_threads = 1;
	iset_map = RZ_NEWS0(struct ituple, n_threads);

	RzInterpYieldRBuf *yield_rbufs[RZ_INTERP_YIELD_KIND_NUM] = { 0 };

	//
	// Initialize and spawn the interpreters.
	//
	for (size_t i = 0; i < n_threads; ++i) {
		RzILCacheClient *cache_client = rz_il_cache_new_client(il_cache, true);
		if (!cache_client) {
			return_code = false;
			rz_warn_if_reached();
			goto error_free;
		}
		inst = rz_interp_instance_new(
			core->analysis,
			&rz_interp_value_domain_const,
			cache_client,
			yield_rbufs);
		if (!inst) {
			return_code = false;
			rz_warn_if_reached();
			goto error_free;
		}

		// Dispatch prototype interpreter into a thread.
		RZ_LOG_DEBUG("inquiry: Start main interpretation thread.\n");
		RzThread *interpr_th = rz_th_new((RzThreadFunction)rz_interp_instance_th, inst);
		iset_map[i].ithread = interpr_th;
		iset_map[i].iset = inst;
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
		RzInterpInstance *iset = iset_map[i].iset;
		RzInterpRunStateFlag expected_rs = iset_map[i].next_run_state;

		switch (rz_interp_run_state_get_unsafe(iset->run_state)) {
		case RZ_INTERP_RUN_STATE_OUT_OF_LOOP:
			break;
		case RZ_INTERP_RUN_STATE_INIT: {
			if (expected_rs != RZ_INTERP_RUN_STATE_INIT) {
				break;
			}
			if (!rz_set_u_size(entry_points)) {
				rz_th_queue_close(iset->il_cache_client->il_queue);
				iset_map[i].next_run_state = RZ_INTERP_RUN_STATE_TERM;
				intpr_terminated++;
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
	}
	rz_il_cache_stop_serving(il_cache);

	if (rz_log_get_level() > RZ_LOGLVL_INFO && rz_cons_is_interactive()) {
		eprintf("\n");
	}

	// Apply results
	void **it;
	rz_pvector_foreach (&inst->results, it) {
		RzInterpResult *res = *it;
		rz_interp_result_apply_to_analysis(res, core->analysis);
	}

	for (size_t i = 0; i < n_threads; i++) {
		rz_interp_instance_free(iset_map[i].iset);
	}

	RZ_LOG_DEBUG("inquiry: inquiry: inquiry: Done\n");

error_free:
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
