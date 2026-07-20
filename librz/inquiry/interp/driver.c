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

/**
 *
 * 1         queue for entry points main -> interps
 * 1         request_rbuf for requests from interps -> main
 * n_thread  response_rbuf for responses main -> interp (rbuf here only works if for every request that causes a response, the requester always also waits for the response)
 *
 * break must close at least request_rbuf
 *
 */

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
	union {
		struct {
			RzInterpIOReadRequest *request;
			InterpThread *requester;
		} io_read;
		struct {
			ut64 addr;
			InterpThread *requester;
		} lift_block;
		RzInterpResult *interp_result;
	} payload;
} InterpDriverMessage;

#define DRIVER_MAIN_CH_SIZE 16 ///< TODO: optimize this to be small but blocking any interpreters under practical circumstances

typedef struct interp_driver_t {
	RzThreadQueue /*<ut64>*/ *entry_points_ch; ///< Main delivers entry points to multiple interpreters with this. TODO: linked list is not optimal, but rbuf may lead to starvation
	RzThreadRingBuf *main_ch; ///< Channel to main. Multiple interpreters send info requests and analysis results with this.
	RzInterpResultDimen dimens;
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
		RzInterpIOReadResult io_read_result;
		const RzILCacheBlock *lift_block_result;
	} payload;
} InterpThreadMessage;

struct interp_thread {
	InterpDriver *driver;
	RzThread *th;
	RzInterpInstance *inst;

	/**
	 * \brief Channel to this thread.
	 * Main delivers responses to requests on InterpDriver.main_ch to this in the exact order they were requested.
	 */
	RzThreadRingBuf *ch;
} /* InterpThread */;

static void *interp_th(void *user) {
	InterpThread *ctx = user;
	RzInterpInstance *inst = ctx->inst;
	while (true) {
		ut64 *entry_point;
		if (!rz_th_queue_pop(ctx->driver->entry_points_ch, false, (void **)&entry_point)) {
			// closed, no more entry points to interpret
			break;
		}
		ut64 entry_point_val = *entry_point;
		free(entry_point);
		RzInterpResult *res = rz_interp_run(inst, entry_point_val, ctx->driver->dimens);
		if (res) {
			InterpDriverMessage msg = {
				.type = DRIVER_MESSAGE_INTERP_RESULT,
				.payload = {
					.interp_result = res
				}
			};
			rz_th_ring_buf_put(ctx->driver->main_ch, &msg);
		} else {
			RZ_LOG_ERROR("Interpreter run failed for entry point 0x%" PFMT64x "\n", entry_point_val);
		}
	}
	return NULL;
}

static RzInterpIOReadResult send_io_read(RZ_NONNULL RzInterpIOReadRequest *req, void *user) {
	InterpThread *th = user;
	InterpDriverMessage msg = {
		.type = DRIVER_MESSAGE_IO_READ,
		.payload = {
			.io_read = {
				.request = req,
				.requester = th
			}
		}
	};
	if (rz_th_ring_buf_put(th->driver->main_ch, &msg) != RZ_THREAD_RING_BUF_OK) {
		return RZ_INTERP_IO_READ_RESULT_BREAK;
	}
	InterpThreadMessage ret;
	if (rz_th_ring_buf_take_blocking(th->ch, &ret) != RZ_THREAD_RING_BUF_OK) {
		return RZ_INTERP_IO_READ_RESULT_BREAK;
	}
	rz_return_val_if_fail(ret.type != INTERP_MESSAGE_IO_READ_RESULT, RZ_INTERP_IO_READ_RESULT_BREAK);
	return ret.payload.io_read_result;
}

static RzInterpLiftBlockResult send_lift_il_block(ut64 addr, const RzILCacheBlock **block_out, void *user) {
	InterpThread *th = user;
	InterpDriverMessage msg = {
		.type = DRIVER_MESSAGE_LIFT_BLOCK,
		.payload = {
			.lift_block = {
				.addr = addr,
				.requester = th
			}
		}
	};
	if (rz_th_ring_buf_put(th->driver->main_ch, &msg) != RZ_THREAD_RING_BUF_OK) {
		return RZ_INTERP_LIFT_BLOCK_RESULT_BREAK;
	}
	InterpThreadMessage ret;
	if (rz_th_ring_buf_take_blocking(th->ch, &ret) != RZ_THREAD_RING_BUF_OK) {
		return RZ_INTERP_LIFT_BLOCK_RESULT_BREAK;
	}
	rz_return_val_if_fail(ret.type == INTERP_MESSAGE_LIFT_BLOCK_RESULT, RZ_INTERP_LIFT_BLOCK_RESULT_BREAK);
	if (ret.payload.lift_block_result) {
		*block_out = ret.payload.lift_block_result;
		return RZ_INTERP_LIFT_BLOCK_RESULT_OK;
	}
	return RZ_INTERP_LIFT_BLOCK_RESULT_FAILED;
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
	RzInterpConfig interp_config = {
		.val_domain = &rz_interp_value_domain_const,
		.cb_user = ctx,
		.io_read = send_io_read,
		.lift_block = send_lift_il_block
	};
	ctx->inst = rz_interp_instance_new(analysis, &interp_config);
	if (!ctx->inst) {
		goto err_ch;
	}
	ctx->th = rz_th_new(interp_th, ctx);
	if (!ctx->th) {
		goto err_inst;
	}
	return ctx;
err_inst:
	rz_interp_instance_free(ctx->inst);
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
	rz_th_wait(th->th);
	rz_th_free(th->th);
	rz_th_ring_buf_free(th->ch);
	rz_interp_instance_free(th->inst);
	free(th);
}

static RzInterpIOReadResult handle_io_request(const RzAnalysisILContext *il_ctx, RzInterpIOReadRequest *io_req) {
	RZ_LOG_DEBUG("inquiry: Received IO read request: mem:%" PFMTSZd " 0x%" PFMT64x "\n",
		io_req->mem_idx,
		rz_bv_to_ut64(io_req->addr));
	RzILMemIndex mem_idx = io_req->mem_idx;
	if (mem_idx > rz_vector_len(&il_ctx->memory)) {
		rz_warn_if_reached();
		return RZ_INTERP_IO_READ_RESULT_TOP;
	}
	if (rz_bv_len(io_req->addr) == 64 && rz_bv_msb(io_req->addr)) {
		// TODO: remove this
		RZ_LOG_ERROR("Due to the Unix seek() implementation, addresses with the "
			     "63 bit set can't be addresses.\n");
		return RZ_INTERP_IO_READ_RESULT_TOP;
	}
	RzAnalysisILMem *mem = rz_vector_index_ptr(&il_ctx->memory, mem_idx);
	if (!mem->base_buf) {
		return RZ_INTERP_IO_READ_RESULT_TOP;
	}
	// TODO: here only memory should be read that can be assumed to be constant!
	bool ok = rz_il_loadw_into(mem->base_buf, io_req->ld_data, io_req->addr, io_req->n_bits, io_req->big_endian);
	RZ_LOG_DEBUG("inquiry: Sent IO read result. Success = %s.\n", rz_str_bool(ok));
	return ok ? RZ_INTERP_IO_READ_RESULT_TOP : RZ_INTERP_IO_READ_RESULT_TOP;
}

RZ_API bool rz_interp_driver_run(RzCore *core, RZ_OWN RzSetU *entry_points, RzInterpResultDimen dimens) {
	bool return_code = false;

	bool user_sent_signal = false;

	RzILCache *il_cache = rz_il_cache_new(core->analysis, core->io, RZ_IL_CACHE_CONFIG_NOP_UNLIFTED);
	if (!il_cache) {
		goto err_none;
	}

	InterpDriver driver = {
		.dimens = dimens
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
	RzIterator *it = rz_set_u_as_iter(entry_points);
	ut64 *entry;
	rz_iterator_foreach (it, entry) {
		ut64 *tmp = RZ_NEW(ut64);
		if (!tmp) {
			goto err_main_ch;
		}
		*tmp = *entry;
		if (!rz_th_queue_push(driver.entry_points_ch, tmp, true)) {
			goto err_main_ch;
		}
		entries_pushed++;
	}

	size_t n_threads = 1;
	InterpThread **threads = RZ_NEWS0(InterpThread *, n_threads);
	if (!threads) {
		goto err_main_ch;
	}

	// Initialize and spawn the interpreters.
	for (size_t i = 0; i < n_threads; ++i) {
		threads[i] = interp_thread_new(core->analysis, &driver);
		if (!threads[i]) {
			goto err_threads;
		}
	}

	// TODO: rz_cons_break_push

	// Serve the interpreters
	size_t entries_finished = 0;
	while (entries_finished < entries_pushed) {
		InterpDriverMessage msg;
		if (rz_th_ring_buf_take_blocking(driver.main_ch, &msg) != RZ_THREAD_RING_BUF_OK) {
			// closed
			break;
		}
		switch (msg.type) {
		case DRIVER_MESSAGE_IO_READ: {
			RzInterpIOReadResult res = handle_io_request(msg.payload.io_read.requester->inst->il_ctx, msg.payload.io_read.request);
			InterpThreadMessage res_msg = {
				.type = INTERP_MESSAGE_IO_READ_RESULT,
				.payload = {
					.io_read_result = res
				}
			};
			if (rz_th_ring_buf_put(msg.payload.io_read.requester->ch, &res_msg) != RZ_THREAD_RING_BUF_OK) {
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
					.lift_block_result = block
				}
			};
			if (rz_th_ring_buf_put(msg.payload.lift_block.requester->ch, &res_msg) != RZ_THREAD_RING_BUF_OK) {
				// should not be closed
				rz_warn_if_reached();
			}
			break;
		}
		case DRIVER_MESSAGE_INTERP_RESULT: {
			RzInterpResult *res = msg.payload.interp_result;
			if (!rz_interp_result_apply_to_analysis(res, core->analysis)) {
				RZ_LOG_WARN("Failed to apply to analysis\n");
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

err_threads:
	// Close channel to make interp threads stop.
	rz_th_queue_close(driver.entry_points_ch);
	for (size_t i = 0; i < n_threads; i++) {
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
	return return_code && !user_sent_signal;
}
