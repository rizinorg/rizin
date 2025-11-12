// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_vector.h>
#include <rz_th.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_util/rz_assert.h>

RZ_IPI RzCmdStatus rz_inquiry_interpreter_prototype_handler(RzCore *core, int argc, const char **argv) {
	rz_return_val_if_fail(core->analysis && core->io, RZ_CMD_STATUS_ERROR);

	RzThreadQueue *il_queue = rz_th_queue_new(RZ_INTERPRETER_IL_QUEUE_SIZE, (RzListFree)rz_interpreter_il_queue_free);
	if (!il_queue) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzILOpEffect *eff = NULL;
	if (argc == 1) {
		ut64 entry_point = rz_bin_get_first_entrypoint(core->bin->cur->o);
		eff = rz_inquiry_gen_il_bb(core->analysis, core->io, entry_point);
		if (!eff) {
			rz_th_queue_free(il_queue);
			RZ_LOG_WARN("Could not get entry point IL operation at 0x%" PFMT64x "\n", (ut64)entry_point);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		// Add all entry points given as arguments.
		for (size_t i = 1; i < argc; i++) {
			ut64 entry_point = rz_num_get(core->num, argv[i]);
			eff = rz_inquiry_gen_il_bb(core->analysis, core->io, entry_point);
			if (!eff) {
				rz_th_queue_free(il_queue);
				return RZ_CMD_STATUS_ERROR;
			}
		}
	}
	rz_th_queue_push(il_queue, eff, true);

	RzThreadQueue *addr_queue = rz_th_queue_new(RZ_INTERPRETER_ADDR_QUEUE_SIZE, (RzListFree)rz_interpreter_addr_queue_free);
	if (!addr_queue) {
		rz_th_queue_free(il_queue);
		return RZ_CMD_STATUS_ERROR;
	}
	RzInterval iv = { .addr = 0, .size = UT64_MAX };
	RzList *boundaries = rz_io_get_boundaries_all_io_maps(core->io, iv);
	if (!boundaries) {
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		return RZ_CMD_STATUS_ERROR;
	}
	RzInterpreterYieldKind yield_kind = RZ_INTERPRETER_YIELD_KIND_XREF;
	RzInterpreterYieldQueue *yield_queue = rz_interpreter_yield_queue_new(
		yield_kind,
		(RzInterpreterYieldFilter *)rz_inquiry_xref_interpreter_filter,
		boundaries);
	if (!yield_queue) {
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		return RZ_CMD_STATUS_ERROR;
	}
	HtUP *yield_queues = ht_up_new(NULL, (HtUPFreeValue)rz_interpreter_yield_queue_free);
	if (!yield_queue || !yield_queues) {
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		rz_interpreter_yield_queue_free(yield_queue);
		ht_up_free(yield_queues);
		return RZ_CMD_STATUS_ERROR;
	}
	ht_up_insert(yield_queues, yield_kind, yield_queue);
	RzAtomicBool *is_running = rz_atomic_bool_new(true);
	RzInterpreterQueueSet *qset = rz_interpreter_queue_set_new(addr_queue, il_queue, yield_queues, is_running);
	if (!qset) {
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		rz_interpreter_yield_queue_free(yield_queue);
		ht_up_free(yield_queues);
		rz_atomic_bool_free(is_running);
		return RZ_CMD_STATUS_ERROR;
	}

	// Dispatch interpreter into thread
	// and do a busy loop on the queue for now
	RZ_LOG_WARN("INQUIRY: Start thread.\n");
	RzThread *iterpr_th = rz_th_new((RzThreadFunction)rz_interpreter_run, qset);
	RZ_LOG_WARN("INQUIRY: Start loop.\n");
	while (rz_atomic_bool_get(is_running)) {
		ut64 *addr = rz_th_queue_pop(addr_queue, false);
		if (!addr) {
			// Some artifical lag for testing.
			rz_sys_sleep(1);
			RZ_LOG_WARN("INQUIRY: Sleep over.\n");
			continue;
		}
		RZ_LOG_WARN("INQUIRY: Received %" PFMT64x ".\n", (*addr));
		RzILOpEffect *bb = rz_inquiry_gen_il_bb(core->analysis, core->io, *addr);
		free(addr);
		if (!bb) {
			// Stop interpreter.
			rz_atomic_bool_set(is_running, false);
			continue;
		}
		RZ_LOG_WARN("INQUIRY: Send %p.\n", bb);
		rz_th_queue_push(il_queue, bb, true);
	}
	// Wait for thread to finish before cleaning.
	rz_th_wait(iterpr_th);
	rz_th_free(iterpr_th);
	rz_interpreter_queue_set_free(qset);

	return RZ_CMD_STATUS_OK;
}
