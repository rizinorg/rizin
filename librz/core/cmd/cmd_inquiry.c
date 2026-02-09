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
	rz_return_val_if_fail(core->analysis && core->io && core->bin->cur && core->bin->cur->o, RZ_CMD_STATUS_ERROR);
	RzVector *entry_points = rz_vector_new(sizeof(ut64), NULL, NULL);
	if (!entry_points) {
		return RZ_CMD_STATUS_ERROR;
	}

	ut64 entry_point;
	if (argc == 1) {
		// No specific entry point given. Pick the one provided by the bin plugin.
		entry_point = rz_bin_get_first_entrypoint(core->bin->cur->o);
		rz_vector_push(entry_points, &entry_point);
	} else {
		// Add all entry points given as arguments.
		for (size_t i = 1; i < argc; i++) {
			ut64 entry_point = rz_num_get(core->num, argv[i]);
			rz_vector_push(entry_points, &entry_point);
		}
	}
	bool success = rz_inquiry_interpreter(core, entry_points);

	RZ_LOG_INFO("Finished reference recovery.\n");
	RZ_LOG_INFO("Perform function deduction.\n");

	RzPVector *fcns = rz_pvector_new((RzPVectorFree)rz_inquiry_function_free);
	rz_inquiry_algo_revng_fcn_detection(
		core->inquiry->call_candidates,
		core->inquiry->bb_cfg,
		fcns);

	// Create analysis function and add their blocks to them.
	void **it;
	rz_pvector_foreach (fcns, it) {
		RzInquiryFunction *fcn = *it;
		char *fcn_desc = rz_inquiry_function_str(fcn);
		printf("%s", fcn_desc);
		free(fcn_desc);

		ut64 fcn_addr = *(ut64 *)rz_vector_head(fcn->entry_points);
		char fcn_name[512] = { 0 };
		rz_strf(fcn_name, "iq_fcn_0x%" PFMT64x, fcn_addr);
		RzAnalysisFunction *afcn = rz_analysis_create_function(core->analysis, fcn_name, fcn_addr, RZ_ANALYSIS_FCN_TYPE_FCN);

		void **it2;
		RzIterator *iter = ht_up_as_iter(fcn->bb_cfg->basic_blocks);
		rz_iterator_foreach(iter, it2) {
			RzInterval *bb = *it2;
			RzAnalysisBlock *abb = rz_analysis_get_block_at(core->analysis, bb->addr);
			if (!abb) {
				rz_analysis_create_block(core->analysis, bb->addr, bb->size);
				if (!abb) {
					rz_warn_if_reached();
					break;
				}
			}
			rz_analysis_function_add_block(afcn, abb);
			rz_analysis_block_update_hash(abb);
		}
		rz_iterator_free(iter);
	}
	rz_pvector_free(fcns);

	// Add edges between blocks

	return success ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}
