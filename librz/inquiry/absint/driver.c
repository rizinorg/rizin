// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2025-2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Interpreter Driver
 *
 * Main loop spawning and serving interpreter threads,
 * as well as integrating results as they are emitted.
 *
 * Threads:
 * - rz_absint_driver_run is the entrypoint and contains the single main loop that has access to all of rizin.
 * - n interpreter threads are started that take care of the actual interpretation and analysis work.
 *   They communicate with the main loop through channels whenever they need any information from rizin.
 *
 * Channels:
 * - 1 InterpDriver.entry_points_ch      (1 main -> n threads)
 *     Main fills it with entrypoints and interpreters pop and analyze them until the queue is empty.
 * - 1 InterpDriver.main_ch              (n threads -> 1 main)
 *     Interpreters push io, instruction request and analysis results to this for the main loop to handle.
 * - n InterpThread.ch                   (1 main -> 1 thread)
 *     For io and instruction requests, main replies with the result to the thread that sent the request.
 */

#include <rz_inquiry/rz_absint.h>
#include <rz_core.h>

typedef struct interp_thread InterpThread;

/**
 * \brief Message from an interpreter to the main loop
 */
typedef struct interp_driver_message_t {
	enum {
		DRIVER_MESSAGE_IO_READ,
		DRIVER_MESSAGE_LIFT_BLOCK,
		DRIVER_MESSAGE_INTERP_RESULT
	} type;
	InterpThread *sender;
	union {
		struct {
			RzAbsIntIOReadRequest *request;
		} io_read;
		struct {
			ut64 addr;
		} lift_block;
		struct {
			ut64 entry;
			RzAbsIntResult *res;
		} interp_result;
	} payload;
} InterpDriverMessage;

#define DRIVER_MAIN_CH_SIZE 16 ///< TODO: optimize this to be small but blocking any interpreters under practical circumstances

typedef struct interp_driver_t {
	RzThreadQueue /* ut64 */ *entry_points_ch; ///< Main delivers entry points to multiple interpreters with this. TODO: linked list is not optimal, but rbuf may lead to starvation
	RzThreadRingBuf *main_ch; ///< Channel to main. Multiple interpreters send info requests and analysis results with this.
	RzAbsIntResultDimen dimens;
	RzAbsIntTraceOptions trace_opts;
} InterpDriver;

/**
 * \brief Message from the main loop to an interpreter thread
 * Currently corresponds to exactly one request sent on InterpDriver.main_ch
 */
typedef struct interp_thread_message_t {
	enum {
		INTERP_MESSAGE_IO_READ_RESULT,
		INTERP_MESSAGE_LIFT_BLOCK_RESULT
	} type;
	union {
		RzAbsIntIOReadResult io_read_result;
		const RzILCacheBlock *lift_block_result;
	} payload;
} InterpThreadMessage;

struct interp_thread {
	InterpDriver *driver;
	RzThread *th;
	RzAbsIntInstance *inst;

	/**
	 * \brief Channel to this thread.
	 * Main delivers responses to requests on InterpDriver.main_ch to this in the exact order they were requested.
	 */
	RzThreadRingBuf *ch;
} /* InterpThread */;

static void *interp_th(void *user) {
	InterpThread *ctx = user;
	RzAbsIntInstance *inst = ctx->inst;
	while (true) {
		ut64 *entry_point;
		if (!rz_th_queue_pop(ctx->driver->entry_points_ch, false, (void **)&entry_point)) {
			// closed, no more entry points to interpret
			break;
		}
		ut64 entry_point_val = *entry_point;
		free(entry_point);
		RzAbsIntResult *res = NULL;
		RzAbsIntResultCode code = rz_absint_run(inst, entry_point_val, ctx->driver->dimens, &res);
		if (code == RZ_ABSINT_RESULT_BREAK) {
			break;
		}
		InterpDriverMessage msg = {
			.type = DRIVER_MESSAGE_INTERP_RESULT,
			.sender = ctx,
			.payload = {
				.interp_result = {
					.entry = entry_point_val,
					.res = res } }
		};
		rz_th_ring_buf_put(ctx->driver->main_ch, &msg);
	}
	return NULL;
}

static RzAbsIntIOReadResult send_io_read(RZ_NONNULL RzAbsIntIOReadRequest *req, void *user) {
	InterpThread *th = user;
	InterpDriverMessage msg = {
		.type = DRIVER_MESSAGE_IO_READ,
		.sender = th,
		.payload = {
			.io_read = {
				.request = req } }
	};
	if (rz_th_ring_buf_put(th->driver->main_ch, &msg) != RZ_THREAD_RING_BUF_OK) {
		return RZ_ABSINT_IO_READ_RESULT_BREAK;
	}
	InterpThreadMessage ret;
	if (rz_th_ring_buf_take_blocking(th->ch, &ret) != RZ_THREAD_RING_BUF_OK) {
		return RZ_ABSINT_IO_READ_RESULT_BREAK;
	}
	rz_return_val_if_fail(ret.type == INTERP_MESSAGE_IO_READ_RESULT, RZ_ABSINT_IO_READ_RESULT_BREAK);
	return ret.payload.io_read_result;
}

static RzAbsIntLiftBlockResult send_lift_il_block(ut64 addr, const RzILCacheBlock **block_out, void *user) {
	InterpThread *th = user;
	InterpDriverMessage msg = {
		.type = DRIVER_MESSAGE_LIFT_BLOCK,
		.sender = th,
		.payload = {
			.lift_block = {
				.addr = addr } }
	};
	if (rz_th_ring_buf_put(th->driver->main_ch, &msg) != RZ_THREAD_RING_BUF_OK) {
		return RZ_ABSINT_LIFT_BLOCK_RESULT_BREAK;
	}
	InterpThreadMessage ret;
	if (rz_th_ring_buf_take_blocking(th->ch, &ret) != RZ_THREAD_RING_BUF_OK) {
		return RZ_ABSINT_LIFT_BLOCK_RESULT_BREAK;
	}
	rz_return_val_if_fail(ret.type == INTERP_MESSAGE_LIFT_BLOCK_RESULT, RZ_ABSINT_LIFT_BLOCK_RESULT_BREAK);
	if (ret.payload.lift_block_result) {
		*block_out = ret.payload.lift_block_result;
		return RZ_ABSINT_LIFT_BLOCK_RESULT_OK;
	}
	return RZ_ABSINT_LIFT_BLOCK_RESULT_FAILED;
}

static InterpThread *interp_thread_new(RzAnalysis *analysis, InterpDriver *driver) {
	InterpThread *ctx = RZ_NEW(InterpThread);
	if (!ctx) {
		return NULL;
	}
	ctx->driver = driver;
	ctx->ch = rz_th_ring_buf_new(1, sizeof(InterpThreadMessage)); // At the moment, threads directly wait after a single request, so size 1 is enough
	if (!ctx->ch) {
		goto err_ctx;
	}
	RzAbsIntConfig interp_config = {
		.val_domain = rz_absint_builtin_value_domain(RZ_ABSINT_VALUE_DOMAIN_CONST),
		.trace_opts = driver->trace_opts,
		.cb_user = ctx,
		.io_read = send_io_read,
		.lift_block = send_lift_il_block
	};
	ctx->inst = rz_absint_instance_new(analysis, &interp_config);
	if (!ctx->inst) {
		goto err_ch;
	}
	ctx->th = rz_th_new(interp_th, ctx);
	if (!ctx->th) {
		goto err_inst;
	}
	return ctx;
err_inst:
	rz_absint_instance_free(ctx->inst);
err_ch:
	rz_th_ring_buf_free(ctx->ch);
err_ctx:
	free(ctx);
	return NULL;
}

static void interp_thread_free(InterpThread *th) {
	if (!th) {
		return;
	}
	rz_th_ring_buf_close(th->ch);
	rz_th_wait(th->th);
	rz_th_free(th->th);
	rz_th_ring_buf_free(th->ch);
	rz_absint_instance_free(th->inst);
	free(th);
}

static RzAbsIntIOReadResult handle_io_request(const RzAnalysisILContext *il_ctx, RzAbsIntIOReadRequest *io_req) {
	RZ_LOG_DEBUG("inquiry: Received IO read request: mem:%" PFMTSZd " 0x%" PFMT64x "\n",
		io_req->mem_idx,
		rz_bv_to_ut64(io_req->addr));
	RzILMemIndex mem_idx = io_req->mem_idx;
	if (mem_idx > rz_vector_len(&il_ctx->memory)) {
		rz_warn_if_reached();
		return RZ_ABSINT_IO_READ_RESULT_TOP;
	}
	if (rz_bv_len(io_req->addr) == 64 && rz_bv_msb(io_req->addr)) {
		// TODO: remove this when not needed anymore
		RZ_LOG_ERROR("Due to the Unix seek() implementation, addresses with the "
			     "63 bit set can't be addresses.\n");
		return RZ_ABSINT_IO_READ_RESULT_TOP;
	}
	RzAnalysisILMem *mem = rz_vector_index_ptr(&il_ctx->memory, mem_idx);
	if (!mem->base_buf) {
		return RZ_ABSINT_IO_READ_RESULT_TOP;
	}
	// TODO: here only memory should be read that can be assumed to be constant!
	bool ok = rz_il_loadw_into(mem->base_buf, io_req->ld_data, io_req->addr, io_req->n_bits, io_req->big_endian);
	RZ_LOG_DEBUG("inquiry: Sent IO read result. Success = %s.\n", rz_str_bool(ok));
	return ok ? RZ_ABSINT_IO_READ_RESULT_OK : RZ_ABSINT_IO_READ_RESULT_TOP;
}

RZ_API bool rz_absint_driver_run(RZ_NONNULL RZ_BORROW RzAbsIntDriverConfig *config) {
	rz_return_val_if_fail(config && config->analysis && config->io && config->entry_points && config->n_threads > 0, false);
	bool return_code = false;
	bool breaked = false;

	RzILCacheConfig il_cache_config = RZ_IL_CACHE_CONFIG_NOP_UNLIFTED;
	if (config->trace_opts & RZ_ABSINT_TRACE_IL_BLOCK) {
		il_cache_config |= RZ_IL_CACHE_CONFIG_TRACE;
	}
	RzILCache *il_cache = rz_il_cache_new(config->analysis, config->io, il_cache_config);
	if (!il_cache) {
		goto err_none;
	}

	InterpDriver driver = {
		.dimens = config->dimens,
		.trace_opts = config->trace_opts
	};
	driver.entry_points_ch = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, free);
	if (!driver.entry_points_ch) {
		goto err_il_cache;
	}
	driver.main_ch = rz_th_ring_buf_new(DRIVER_MAIN_CH_SIZE, sizeof(InterpDriverMessage));
	if (!driver.main_ch) {
		goto err_entry_points_ch;
	}

	// Push all root entries
	size_t entries_pushed = 0;
	RzIterator *it = rz_set_u_as_iter(config->entry_points);
	ut64 *entry;
	rz_iterator_foreach(it, entry) {
		ut64 *tmp = RZ_NEW(ut64);
		if (!tmp) {
			rz_iterator_free(it);
			goto err_main_ch;
		}
		*tmp = *entry;
		if (!rz_th_queue_push(driver.entry_points_ch, tmp, true)) {
			rz_iterator_free(it);
			goto err_main_ch;
		}
		entries_pushed++;
	}
	rz_iterator_free(it);

	InterpThread **threads = RZ_NEWS0(InterpThread *, config->n_threads);
	if (!threads) {
		goto err_main_ch;
	}

	// Initialize and spawn the interpreters.
	for (size_t i = 0; i < config->n_threads; ++i) {
		threads[i] = interp_thread_new(config->analysis, &driver);
		if (!threads[i]) {
			goto err_threads;
		}
	}

	rz_cons_break_push(NULL, NULL);

	// Serve the interpreters
	size_t entries_finished = 0;
	while (entries_finished < entries_pushed) {
		if (rz_cons_is_breaked()) {
			breaked = true;
			break;
		}
		InterpDriverMessage msg;
		if (rz_th_ring_buf_take_blocking(driver.main_ch, &msg) != RZ_THREAD_RING_BUF_OK) {
			// closed
			break;
		}
		if (rz_cons_is_breaked()) {
			breaked = true;
			break;
		}
		switch (msg.type) {
		case DRIVER_MESSAGE_IO_READ: {
			RzAbsIntIOReadResult res = handle_io_request(msg.sender->inst->il_ctx, msg.payload.io_read.request);
			InterpThreadMessage res_msg = {
				.type = INTERP_MESSAGE_IO_READ_RESULT,
				.payload = {
					.io_read_result = res }
			};
			if (rz_th_ring_buf_put(msg.sender->ch, &res_msg) != RZ_THREAD_RING_BUF_OK) {
				// should not be closed
				rz_warn_if_reached();
			}
			break;
		}
		case DRIVER_MESSAGE_LIFT_BLOCK: {
			const RzILCacheBlock *block = rz_il_cache_lift_il_block(il_cache, msg.payload.lift_block.addr);
			InterpThreadMessage res_msg = {
				.type = INTERP_MESSAGE_LIFT_BLOCK_RESULT,
				.payload = {
					.lift_block_result = block }
			};
			if (rz_th_ring_buf_put(msg.sender->ch, &res_msg) != RZ_THREAD_RING_BUF_OK) {
				// should not be closed
				rz_warn_if_reached();
			}
			break;
		}
		case DRIVER_MESSAGE_INTERP_RESULT: {
			RzAbsIntResult *res = msg.payload.interp_result.res;
			if (res) {
				char *name = config->choose_fcn_name ? config->choose_fcn_name(res->entry, config->cb_user) : NULL;
				if (!rz_absint_result_apply_to_analysis(res, config->analysis, name)) {
					RZ_LOG_WARN("Failed to apply to analysis\n");
				}
				free(name);
				rz_absint_result_free(msg.sender->inst, res);
			} else {
				RZ_LOG_WARN("Failed to analyze entry point 0x%" PFMT64x "\n", msg.payload.interp_result.entry);
			}
			entries_finished++;
			break;
		}
		default:
			rz_warn_if_reached();
			break;
		}
	}

	return_code = true;

	rz_cons_break_pop();

err_threads:
	// Close channels to make interp threads stop.
	rz_th_queue_close(driver.entry_points_ch);
	rz_th_ring_buf_close(driver.main_ch);
	for (size_t i = 0; i < config->n_threads; i++) {
		interp_thread_free(threads[i]);
	}
	free(threads);
err_main_ch:
	rz_th_ring_buf_free(driver.main_ch);
err_entry_points_ch:
	rz_th_queue_free(driver.entry_points_ch);
err_il_cache:
	rz_il_cache_free(il_cache);
err_none:
	return return_code && !breaked;
}
