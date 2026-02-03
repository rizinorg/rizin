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

	printf("Found call candidates:\n");
	RzIterator *it = ht_up_as_iter(core->inquiry->call_candidates);
	RzAnalysisCallCandidate **v;
	rz_iterator_foreach(it, v) {
		RzAnalysisCallCandidate *cc = *v;
		printf("\n");
		printf("\tbb_addr = 0x%" PFMT64x "\n", cc->bb_addr);
		printf("\tstore_addr = 0x%" PFMT64x "\n", cc->store_addr);
		printf("\tjmp_addr = 0x%" PFMT64x "\n", cc->jmp_addr);
		printf("\tnpc = 0x%" PFMT64x "\n", cc->npc);
		printf("\tin_mem = %s\n", rz_str_bool(cc->in_mem));
	}
	rz_iterator_free(it);

	return success ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}
