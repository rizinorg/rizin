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

typedef struct rz_interp_io_result_t {
	bool req_ok; ///< Set to true if IO request succeeded.
} RzInterpIOResult;

typedef struct rz_interp_run_state RzInterpRunState;

typedef enum rz_interp_state_flag {
	/**
	 * \brief Interpreter is still outside of its defined loop.
	 * E.g. shortly after its thread was spawned.
	 */
	RZ_INTERP_RUN_STATE_OUT_OF_LOOP,
	RZ_INTERP_RUN_STATE_INIT, ///< Initialization state.
	RZ_INTERP_RUN_STATE_EMU, ///< Emulation state.
	RZ_INTERP_RUN_STATE_CLEAN, ///< Cleaning state.
	RZ_INTERP_RUN_STATE_TERM, ///< Termination state.
} RzInterpRunStateFlag;

RZ_API RZ_OWN RzInterpRunState *rz_interp_run_state_new();
RZ_API void rz_interp_run_state_free(RZ_OWN RZ_NULLABLE RzInterpRunState *state);
RZ_API RzInterpRunStateFlag rz_interp_run_state_get(RZ_BORROW RZ_NONNULL RzInterpRunState *state);
RZ_API RzInterpRunStateFlag rz_interp_run_state_get_unsafe(const RZ_NONNULL RzInterpRunState *state);
RZ_API const char *rz_interp_run_state_flag_str(RzInterpRunStateFlag flag);

RZ_IPI void rz_interp_run_state_set(RZ_BORROW RZ_NONNULL RzInterpRunState *state, RzInterpRunStateFlag flag);

struct rz_interp_run_state {
	RzThreadLock *lock; ///< The mutex around the state flag.
	RzInterpRunStateFlag flag; ///< The current set state.
};

RZ_API const char *rz_interp_run_state_flag_str(RzInterpRunStateFlag flag) {
	switch (flag) {
	case RZ_INTERP_RUN_STATE_OUT_OF_LOOP:
		return "-";
	case RZ_INTERP_RUN_STATE_INIT:
		return "I";
	case RZ_INTERP_RUN_STATE_EMU:
		return "O";
	case RZ_INTERP_RUN_STATE_CLEAN:
		return "C";
	case RZ_INTERP_RUN_STATE_TERM:
		return "T";
	}
	rz_warn_if_reached();
	return "-";
}

RZ_API RZ_OWN RzInterpRunState *rz_interp_run_state_new() {
	RzInterpRunState *state = RZ_NEW0(RzInterpRunState);
	if (!state) {
		return NULL;
	}
	state->flag = RZ_INTERP_RUN_STATE_OUT_OF_LOOP;
	state->lock = rz_th_lock_new(false);
	if (!state->lock) {
		free(state);
		return NULL;
	}
	return state;
}

RZ_API void rz_interp_run_state_free(RZ_OWN RZ_NULLABLE RzInterpRunState *state) {
	if (!state) {
		return;
	}
	rz_th_lock_free(state->lock);
	free(state);
}

RZ_API RzInterpRunStateFlag rz_interp_run_state_get(RZ_BORROW RZ_NONNULL RzInterpRunState *state) {
	rz_return_val_if_fail(state, RZ_INTERP_RUN_STATE_TERM);
	rz_th_lock_enter(state->lock);
	RzInterpRunStateFlag flag = state->flag;
	rz_th_lock_leave(state->lock);
	return flag;
}

RZ_API RzInterpRunStateFlag rz_interp_run_state_get_unsafe(const RZ_NONNULL RzInterpRunState *state) {
	rz_return_val_if_fail(state, RZ_INTERP_RUN_STATE_TERM);
	return state->flag;
}

/**
 * \brief Sets the run state.
 * This function is declared IPI, so it is not used outside of the interpreter module!
 */
RZ_IPI void rz_interp_run_state_set(RZ_BORROW RZ_NONNULL RzInterpRunState *state, RzInterpRunStateFlag flag) {
	rz_th_lock_enter(state->lock);
	state->flag = flag;
	rz_th_lock_leave(state->lock);
}

typedef struct interp_thread_context {
	RzThread *th;
	RzInterpInstance *inst;
	RzInterpRunState *run_state; ///< The state the interpreter is currently in.
	/**
	 * \brief The semaphore to sync RzInquiry and the interpreter between the Clean and Init run state.
	 */
	RzThreadSemaphore *run_state_sync;

	RzThreadRingBuf /*<RzInterpIORequest>*/ *io_request_rbuf; ///< The ring buffer for read/write requests to the IO layer.
	RzThreadRingBuf /*<const RzInterpIOResult *>*/ *io_result_rbuf; ///< The ring buffer for the read/write requests' answers.

	/**
	 * \brief Entry points the interpreter starts interpreting from.
	 */
	RzThreadRingBuf *entry_points;
} InterpThread;

static void *interp_th(void *user) {
	InterpThread *ctx = user;
	RzInterpInstance *inst = ctx->inst;

	bool success = true;

	RZ_LOG_DEBUG("interpreter: Main: Hello.\n");

	while (true) {
		// INIT
		RZ_LOG_DEBUG("interpreter: Enter INIT\n");
		rz_interp_run_state_set(ctx->run_state, RZ_INTERP_RUN_STATE_INIT);

		ut64 entry_point;
		if (rz_th_ring_buf_take_blocking(ctx->entry_points, &entry_point) != RZ_THREAD_RING_BUF_OK) {
			// No more entry points to interpret => Terminate.
			// OR.
			success = true;
			break;
		}

		// EMU
		RZ_LOG_DEBUG("interpreter: Enter EMU\n");
		rz_interp_run_state_set(ctx->run_state, RZ_INTERP_RUN_STATE_EMU);

		RzInterpResult *res = rz_interp_run(inst, entry_point, RZ_INTERP_RESULT_DIMEN_XREFS | RZ_INTERP_RESULT_DIMEN_COMMENTS); // TODO: make dimensions configurable
		if (res) {
			// TODO: use some sort of channel for delivering results
			rz_pvector_push(&inst->results, res);
		} else {
			RZ_LOG_ERROR("Interpreter run failed for entry point 0x%" PFMT64x "\n", entry_point);
		}

		// CLEAN
		RZ_LOG_DEBUG("interpreter: Enter CLEAN\n");
		rz_interp_run_state_set(ctx->run_state, RZ_INTERP_RUN_STATE_CLEAN);

		// Wait until RzInquiry asks to start again.
		rz_th_sem_wait(ctx->run_state_sync);
	}

	RZ_LOG_DEBUG("interpreter: Enter TERM\n");
	rz_interp_run_state_set(ctx->run_state, RZ_INTERP_RUN_STATE_TERM);
	return (void *)success;
}

static bool setup_ipc_objects(
	RZ_OUT RzThreadRingBuf **io_request_rbuf,
	RZ_OUT RzThreadRingBuf **io_result_rbuf,
	RZ_OUT RzThreadRingBuf **entry_points) {
	*io_request_rbuf = NULL;
	*io_result_rbuf = NULL;
	*entry_points = NULL;

	// Setup the IO queues. Each interpreter instance needs it's own queue at
	// for writing IO. Because the writing is done on the IO cache, and each
	// instance needs its own cache.
	*io_request_rbuf = rz_th_ring_buf_new(RZ_INTERP_IO_RBUF_SIZE, sizeof(RzInterpIOReadRequest));
	*io_result_rbuf = rz_th_ring_buf_new(RZ_INTERP_IO_RBUF_SIZE, sizeof(RzInterpIOResult));
	*entry_points = rz_th_ring_buf_new(RZ_INTERP_ENTRY_POINTS_RBUF_SIZE, sizeof(ut64));
	if (!*io_request_rbuf || !*io_result_rbuf || !*entry_points) {
		rz_warn_if_reached();
		goto error_free;
	}

	return true;

error_free:
	rz_th_ring_buf_free(*io_request_rbuf);
	rz_th_ring_buf_free(*io_result_rbuf);
	rz_th_ring_buf_free(*entry_points);
	return false;
}

static InterpThread *interp_thread_new(RZ_OWN RzInterpInstance *inst) {
	InterpThread *ctx = RZ_NEW(InterpThread);
	if (!ctx) {
		return NULL;
	}
	ctx->inst = inst;
	ctx->run_state = rz_interp_run_state_new();
	if (!ctx->run_state) {
		goto err_ctx;
	}

	RzThreadRingBuf *io_request_rbuf = NULL;
	RzThreadRingBuf *io_result_rbuf = NULL;
	RzThreadRingBuf *entry_points = NULL;
	if (!setup_ipc_objects(&io_request_rbuf, &io_result_rbuf, &entry_points)) {
		goto err_run_state;
	}
	ctx->io_request_rbuf = io_request_rbuf;
	ctx->io_result_rbuf = io_result_rbuf;
	ctx->entry_points = entry_points;

	inst->config.cb_user = ctx; // TODO: remove this hack

	ctx->run_state_sync = rz_th_sem_new(0);
	ctx->th = rz_th_new(interp_th, ctx);
	if (!ctx->th) {
		goto err_run_state;
	}

	return ctx;
err_run_state:
	rz_interp_run_state_free(ctx->run_state);
err_ctx:
	free(ctx);
	return NULL;
}

static void close_reset_ipc_obj(InterpThread *th) {
	// Close and clear all the IPC objects of this interpreter.
	// This also clears the buffer and queues
	RzInterpInstance *inst = th->inst;
	rz_th_ring_buf_close(th->io_request_rbuf);
	rz_th_ring_buf_close(th->io_result_rbuf);
	rz_th_ring_buf_close(th->entry_points);
	rz_th_ring_buf_close(inst->config.il_cache_client->req_rbuf);
	rz_th_queue_close(inst->config.il_cache_client->il_queue);
	rz_list_free(rz_th_queue_pop_all(inst->config.il_cache_client->il_queue));
}

static void open_ipc_obj(InterpThread *th) {
	// Open queue again, so the interpretation can start at another
	// jump target again.
	RzInterpInstance *inst = th->inst;
	rz_th_ring_buf_open(th->io_request_rbuf);
	rz_th_ring_buf_open(th->io_result_rbuf);
	rz_th_ring_buf_open(inst->config.il_cache_client->req_rbuf);
	rz_th_queue_open(inst->config.il_cache_client->il_queue);
	rz_th_ring_buf_open(th->entry_points);
}

static bool send_io_read(RZ_NONNULL RzInterpIOReadRequest *req, void *user) {
	InterpThread *th = user;
	if (rz_th_ring_buf_put(th->io_request_rbuf, req) != RZ_THREAD_RING_BUF_OK) {
		return false;
	}
	RzInterpIOResult io_res = { 0 };
	if (rz_th_ring_buf_take_blocking(th->io_result_rbuf, &io_res) != RZ_THREAD_RING_BUF_OK) {
		return false;
	}
	return io_res.req_ok;
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
	InterpThread *th;
	RzInterpRunStateFlag next_run_state;
};

RZ_API bool rz_interp_driver_run(RzCore *core, RZ_OWN RzSetU *entry_points) {
	bool return_code = true;

	bool user_sent_signal = false;
	struct ituple *interp_map = NULL;
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
	interp_map = RZ_NEWS0(struct ituple, n_threads);

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
		RzInterpConfig config = {
			.val_domain = &rz_interp_value_domain_const,
			.il_cache_client = cache_client,
			.cb_user = NULL, // TODO, injected by hack
			.io_read = send_io_read
		};
		RzInterpInstance *inst = rz_interp_instance_new(core->analysis, &config);
		if (!inst) {
			return_code = false;
			rz_warn_if_reached();
			goto error_free;
		}
		RZ_LOG_DEBUG("inquiry: Start main interpretation thread.\n");
		interp_map[i].th = interp_thread_new(inst);
		if (!interp_map[i].th) {
			rz_interp_instance_free(inst);
			return_code = false;
			goto error_free;
		}
		interp_map[i].next_run_state = RZ_INTERP_RUN_STATE_INIT;
	}

	//
	// Spawn the IL cache.
	//
	RZ_LOG_DEBUG("inquiry: Spawn IL Cache");
	il_cache_th = rz_th_new((RzThreadFunction)rz_il_cache_serve, il_cache);

	ut64 interp_terminated = 0;
	ut64 check_signal = 0;

	//
	// Enter the loop to serve the interpreters.
	//
	for (ut64 i = 0;; check_signal++, i = (i + 1) % n_threads) {
		if (check_signal % RZ_INQUIRY_CHECK_USER_SIGNAL_ITC == 0 && rz_cons_is_breaked()) {
			user_sent_signal = true;
			break;
		}
		RzInterpInstance *inst = interp_map[i].th->inst;
		RzInterpRunStateFlag expected_rs = interp_map[i].next_run_state;

		switch (rz_interp_run_state_get_unsafe(interp_map[i].th->run_state)) {
		case RZ_INTERP_RUN_STATE_OUT_OF_LOOP:
			break;
		case RZ_INTERP_RUN_STATE_INIT: {
			if (expected_rs != RZ_INTERP_RUN_STATE_INIT) {
				break;
			}
			if (!rz_set_u_size(entry_points)) {
				rz_th_queue_close(inst->config.il_cache_client->il_queue);
				interp_map[i].next_run_state = RZ_INTERP_RUN_STATE_TERM;
				interp_terminated++;
				continue;
			}
			ut64 next_entry_point = rz_set_u_take(entry_points);
			switch (rz_th_ring_buf_put(interp_map[i].th->entry_points, &next_entry_point)) {
			case RZ_THREAD_RING_BUF_OK:
				// Successfully lifted and pushed the entry point's basic block into the queue.
				// Expect the interpreter to emulate now.
				interp_map[i].next_run_state = RZ_INTERP_RUN_STATE_EMU;
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
				interp_map[i].next_run_state = RZ_INTERP_RUN_STATE_TERM;
				interp_terminated++;
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
			if (!rz_th_ring_buf_is_empty_unsafe(interp_map[i].th->io_request_rbuf)) {
				RzThreadRingBufResult r = rz_th_ring_buf_take(interp_map[i].th->io_request_rbuf, &io_req);
				if (r == RZ_THREAD_RING_BUF_CLOSED) {
					rz_warn_if_reached();
					goto fatal_error;
				} else if (r == RZ_THREAD_RING_BUF_OK) {
					RzInterpIOResult io_res = { 0 };
					handle_io_request(inst->il_ctx, &io_req, &io_res);
					if (rz_th_ring_buf_put(interp_map[i].th->io_result_rbuf, &io_res) != RZ_THREAD_RING_BUF_OK) {
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
			close_reset_ipc_obj(interp_map[0].th); // TODO
			open_ipc_obj(interp_map[0].th); // TODO
			rz_th_sem_post(interp_map[0].th->run_state_sync);
			interp_map[i].next_run_state = RZ_INTERP_RUN_STATE_INIT;
			// RZ_LOG_DEBUG("Next: INIT\n");
			break;
		}
		case RZ_INTERP_RUN_STATE_TERM: {
			if (expected_rs != RZ_INTERP_RUN_STATE_TERM) {
				interp_map[i].next_run_state = RZ_INTERP_RUN_STATE_TERM;
				interp_terminated++;
			}
			// RZ_LOG_DEBUG("Next: TERM\n");
			break;
		}
		}
		if (interp_terminated == n_threads) {
			break;
		}
	}

fatal_error:

	RZ_LOG_DEBUG("inquiry: Wait for join\n");
	for (size_t i = 0; i < n_threads; i++) {
		close_reset_ipc_obj(interp_map[i].th);
		// Open semaphore so the interpreter can transition
		// EMU -> CLEAN -> INIT -> TERM
		rz_th_sem_post(interp_map[i].th->run_state_sync);
	}

	// Wait for thread to finish before cleaning.
	for (size_t i = 0; i < n_threads; i++) {
		rz_th_wait(interp_map[i].th->th);
		bool interpr_ret = rz_th_get_retv(interp_map[i].th->th);
		rz_th_free(interp_map[i].th->th);
		rz_th_ring_buf_free(interp_map[i].th->io_request_rbuf);
		rz_th_ring_buf_free(interp_map[i].th->io_result_rbuf);
		rz_th_ring_buf_free(interp_map[i].th->entry_points);
		rz_th_sem_free(interp_map[i].th->run_state_sync);
		rz_interp_run_state_free(interp_map[i].th->run_state);
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

	for (size_t i = 0; i < n_threads; i++) {
		// Apply results
		void **it;
		rz_pvector_foreach (&interp_map[i].th->inst->results, it) {
			RzInterpResult *res = *it;
			rz_interp_result_apply_to_analysis(res, core->analysis);
		}

		rz_interp_instance_free(interp_map[i].th->inst);
	}

	RZ_LOG_DEBUG("inquiry: inquiry: inquiry: Done\n");

error_free:
	free(interp_map);
	rz_set_u_free(entry_points);
	rz_il_cache_stop_serving(il_cache);
	if (il_cache_th) {
		rz_th_wait(il_cache_th);
		rz_th_free(il_cache_th);
	}
	rz_il_cache_free(il_cache);
	rz_cons_pop();
	return return_code && !user_sent_signal;
}
