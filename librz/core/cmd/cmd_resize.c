// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_core.h>

/**
 * \brief rb - rebase all flags, binary, information, breakpoints, and analysis.
 * \param core Rizin core.
 * \param argc Count of command arguments.
 * \param argv Vector containing command arguments.
 * \return RZ_CMD_STATUS_OK or RZ_CMD_STATUS_ERROR.
 */
RZ_IPI RzCmdStatus rz_rebase_handler(RzCore *core, int argc, RZ_NONNULL RZ_BORROW const char **argv) {

	// get current file and current object
	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf) {
		RZ_LOG_ERROR("Cannot open current RzBinFile.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	RzBinObject *obj = rz_bin_cur_object(core->bin);
	if (!obj) {
		RZ_LOG_ERROR("Cannot retrieve current object.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	// The file's "default" loading address, that baddr_shift is computed relative to.
	ut64 static_base = obj->plugin->baddr(bf);

	// Compute current baddr_shift of analysis.
	// Requires user input of the base address.
	ut64 old_base = rz_num_math(core->num, argv[1]);
	ut64 static_old_delta = old_base - static_base;

	// perform actual rebase
	RzList *sections_backup = rz_core_create_sections_backup(core);
	if (!sections_backup) {
		RZ_LOG_ERROR("Cannot create sections backup.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	if (argc > 2) {
		// User has supplied manual new base address
		ut64 new_base = rz_num_math(core->num, argv[2]);
		ut64 static_new_delta = new_base - static_base;

		rz_core_rebase_everything(core, sections_backup, false, static_old_delta, static_new_delta);
	} else {
		// Rebase to file's current baddr_shift
		rz_core_rebase_everything(core, sections_backup, true, static_old_delta, 0);
	}
	rz_list_free(sections_backup);
	return RZ_CMD_STATUS_OK;
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
	ut64 oldsize = (core->file) ? rz_io_fd_size(core->io, core->file->fd) : 0;
	if (oldsize == -1) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc > 1) {
		ut64 newsize = rz_num_math(core->num, argv[1]);
		if (newsize == 0) {
			RZ_LOG_ERROR("Invalid new file size");
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
