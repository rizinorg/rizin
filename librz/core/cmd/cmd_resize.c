// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_core.h>


RZ_IPI RzCmdStatus rz_rebase_handler(RzCore *core, int argc, const char **argv) {
    /*RzBinObject *obj = rz_bin_cur_object(core->bin);
    if (!obj) {
        RZ_LOG_ERROR("Cannot open current RzBinObject.\n");
        return RZ_CMD_STATUS_ERROR;
    }*/
    /*
    RzBinFile *bf = rz_bin_cur(core->bin);
	if (!(bf && rz_file_exists(bf->file))) {
		RZ_LOG_ERROR("Cannot open current RzBinFile.\n");
		return RZ_CMD_STATUS_ERROR;
	}

    const RzList *fields = rz_bin_object_get_fields(bf->o);
    rz_list_free(fields);

    ut64 binfile_loadaddr = 0;
    ut64 old_baddr_shift = old_base - binfile_loadaddr;
    
    RZ_LOG_ERROR("old base: %x, binfile loadaddr: %x, old baddr shift: %x\n", old_base, binfile_loadaddr, old_baddr_shift);
	*/
    
    ut64 user_input = rz_num_math(core->num, argv[1]);
    RzList *sections_backup = rz_core_create_sections_backup(core);
    rz_core_rebase_everything(core, sections_backup, user_input);
    rz_list_free(sections_backup);
    return 0;
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
