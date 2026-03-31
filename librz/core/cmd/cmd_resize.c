// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_core.h>

static int rebase_helper(RzCore *core, ut64 oldbase, ut64 newbase) {
	rz_debug_bp_rebase(core->dbg, oldbase, newbase);
	rz_bin_set_baddr(core->bin, newbase);
	rz_flag_move(core->flags, oldbase, newbase);
	rz_core_bin_apply_all_info(core, rz_bin_cur(core->bin));
	// TODO: rz_analysis_move :??
	// TODO: differentiate analysis by map ranges (associated with files or memory maps)
	return 0;
}

RZ_IPI RzCmdStatus rz_rebase_handler(RzCore *core, int argc, const char **argv) {
	ut64 oldbase = rz_num_math(core->num, argv[1]);
	// old base = addr
	// new base = core->offset
	return rebase_helper(core, oldbase, core->offset);
}

static RzCmdStatus resize_helper(RzCore *core, st64 delta) {
	if (!core->file) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 oldsize = (core->file) ? rz_io_fd_size(core->io, core->file->fd) : 0;
	if (oldsize == -1) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_file_resize_delta(core, delta);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_resize_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (!core->file) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 oldsize = rz_io_fd_size(core->io, core->file->fd);
	if (oldsize == -1) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc > 1) {
		ut64 newsize = rz_num_math(core->num, argv[1]);
		if (newsize == 0) {
			RZ_LOG_ERROR("Invalid new file size\n");
			return RZ_CMD_STATUS_ERROR;
		}
		rz_core_file_resize(core, newsize);
	} else {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON: {
			PJ *pj = state->d.pj;
			pj_o(pj);
			pj_kn(pj, "size", oldsize);
			pj_end(pj);
			break;
		}
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("%" PFMT64d "\n", oldsize);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_resize_remove_handler(RzCore *core, int argc, const char **argv) {
	st64 delta = (st64)rz_num_math(core->num, argv[1]);
	return resize_helper(core, -delta);
}

RZ_IPI RzCmdStatus rz_resize_insert_handler(RzCore *core, int argc, const char **argv) {
	st64 delta = (st64)rz_num_math(core->num, argv[1]);
	return resize_helper(core, delta);
}

RZ_IPI RzCmdStatus rz_resize_human_handler(RzCore *core, int argc, const char **argv) {
	if (!core->file) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 oldsize = (core->file) ? rz_io_fd_size(core->io, core->file->fd) : 0;
	if (oldsize == -1) {
		return RZ_CMD_STATUS_ERROR;
	}
	char humansz[8];
	rz_num_units(humansz, sizeof(humansz), oldsize);
	rz_cons_println(humansz);
	return RZ_CMD_STATUS_OK;
}
