// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_core.h>


RZ_IPI RzCmdStatus rz_rebase_handler(RzCore *core, int argc, const char **argv) {
    //get current object
    RzBinFile *bf = rz_bin_cur(core->bin);
	if (!(bf && rz_file_exists(bf->file))) {
		RZ_LOG_ERROR("Cannot open current RzBinFile.\n");
		return RZ_CMD_STATUS_ERROR;
	}

    //retrieve image base
    const RzList *fields = rz_bin_object_get_fields(bf->o);
    if (!fields) {
		RZ_LOG_ERROR("Cannot retrieve executable fields.\n");
        return RZ_CMD_STATUS_ERROR;
    }

    bool found_static_base = false;
    ut64 static_base;
    RzListIter *iter;
	RzBinField *field;
    rz_list_foreach (fields, iter, field) {
        if (strcmp(field->name,"ImageBase") == 0) {
            found_static_base = true;
            static_base = (int)strtol(field->comment,NULL,16);
        }
    }
    if (!found_static_base) {
		RZ_LOG_ERROR("Cannot find image base.\n");
        return RZ_CMD_STATUS_ERROR;
    }
    
    // compute old vs. static base delta
    ut64 old_base = rz_num_math(core->num, argv[1]);
    ut64 static_old_delta = old_base - static_base;
   
    //perform actual rebase 
    RzList *sections_backup = rz_core_create_sections_backup(core);
    if (!sections_backup) {
		RZ_LOG_ERROR("Cannot create sections backup.\n");
        return RZ_CMD_STATUS_ERROR;
    }

    if (argc > 2) {
        ut64 new_base = rz_num_math(core->num, argv[2]);
        ut64 static_new_delta = new_base - static_base;
        rz_core_rebase_everything(core, sections_backup, false, static_old_delta, static_new_delta);
    } else {
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
