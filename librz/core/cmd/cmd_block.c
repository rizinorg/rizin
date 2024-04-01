// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

RZ_IPI RzCmdStatus rz_block_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (argc > 1) {
		ut64 newsize = rz_num_math(core->num, argv[1]);
		rz_core_block_size(core, newsize);
	} else {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON: {
			PJ *pj = state->d.pj;
			pj_o(pj);
			pj_ki(pj, "blocksize", core->blocksize);
			pj_ki(pj, "blocksize_limit", core->blocksize_max);
			pj_end(pj);
			break;
		}
		case RZ_OUTPUT_MODE_RIZIN:
			rz_cons_printf("b 0x%x\n", core->blocksize);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("0x%x\n", core->blocksize);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_block_decrease_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = rz_num_math(core->num, argv[1]);
	rz_core_block_size(core, core->blocksize - n);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_block_increase_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = rz_num_math(core->num, argv[1]);
	rz_core_block_size(core, core->blocksize + n);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_block_flag_handler(RzCore *core, int argc, const char **argv) {
	RzFlagItem *flag = rz_flag_get(core->flags, argv[1]);
	if (!flag) {
		RZ_LOG_ERROR("Cannot find flag named \"%s\"", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_block_size(core, rz_flag_item_get_size(flag));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_block_max_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 1) {
		ut64 n = rz_num_math(core->num, argv[1]);
		core->blocksize_max = n;
	} else {
		rz_cons_printf("0x%x\n", core->blocksize_max);
	}
	return RZ_CMD_STATUS_OK;
}
