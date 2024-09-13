// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_debug.h>
#include <rz_core.h>
#include <rz_io.h>
#include "../core_private.h"

struct open_list_ascii_data_t {
	RzCore *core;
	RzPrint *p;
	int fdsz;
};

static bool core_bin_reload(RzCore *r, const char *file, ut64 baseaddr) {
	RzCoreFile *cf = rz_core_file_cur(r);
	if (!cf) {
		return false;
	}
	RzBinFile *obf = rz_bin_file_find_by_fd(r->bin, cf->fd);
	if (!obf) {
		return false;
	}
	RzBinFile *nbf = rz_bin_reload(r->bin, obf, baseaddr);
	if (!nbf) {
		return false;
	}
	rz_core_bin_apply_all_info(r, nbf);
	return true;
}

static bool init_desc_list_visual_cb(void *user, void *data, ut32 id) {
	struct open_list_ascii_data_t *u = (struct open_list_ascii_data_t *)user;
	RzIODesc *desc = (RzIODesc *)data;
	ut64 sz = rz_io_desc_size(desc);
	if (sz > u->fdsz) {
		u->fdsz = sz;
	}
	return true;
}

static bool desc_list_visual_cb(void *user, void *data, ut32 id) {
	struct open_list_ascii_data_t *u = (struct open_list_ascii_data_t *)user;
	RzCore *core = u->core;
	RzIODesc *desc = (RzIODesc *)data;
	ut64 sz = rz_io_desc_size(desc);
	rz_cons_printf("%2d %c %s 0x%08" PFMT64x " ", desc->fd,
		(desc->io && (desc->io->desc == desc)) ? '*' : '-', rz_str_rwx_i(desc->perm), sz);
	RzBarOptions opts = {
		.unicode = rz_config_get_b(core->config, "scr.utf8"),
		.thinline = !rz_config_get_b(core->config, "scr.hist.block"),
		.legend = false,
		.offset = rz_config_get_b(core->config, "hex.offset"),
		.offpos = 0,
		.cursor = false,
		.curpos = 0,
		.color = rz_config_get_i(core->config, "scr.color")
	};
	RzStrBuf *strbuf = rz_progressbar(&opts, sz * 100 / u->fdsz, rz_cons_get_size(NULL) - 40);
	if (!strbuf) {
		RZ_LOG_ERROR("Cannot generate progressbar\n");
	} else {
		char *bar = rz_strbuf_drain(strbuf);
		rz_cons_print(bar);
		free(bar);
	}
	rz_cons_printf(" %s\n", desc->uri);
	return true;
}

static bool desc_list_quiet_cb(void *user, void *data, ut32 id) {
	RzPrint *p = (RzPrint *)user;
	RzIODesc *desc = (RzIODesc *)data;
	p->cb_printf("%d\n", desc->fd);
	return true;
}

static bool desc_list_cb(void *user, void *data, ut32 id) {
	RzPrint *p = (RzPrint *)user;
	RzIODesc *desc = (RzIODesc *)data;
	p->cb_printf("%2d %c %s 0x%08" PFMT64x " %s\n", desc->fd,
		(desc->io && (desc->io->desc == desc)) ? '*' : '-',
		rz_str_rwx_i(desc->perm), rz_io_desc_size(desc), desc->uri);
	return true;
}

static bool desc_list_json_cb(void *user, void *data, ut32 id) {
	PJ *pj = (PJ *)user;
	RzIODesc *desc = (RzIODesc *)data;
	// TODO: from is always 0? See librz/core/file.c:945
	ut64 from = 0LL;
	pj_o(pj);
	pj_kb(pj, "raised", desc->io && (desc->io->desc == desc));
	pj_kN(pj, "fd", desc->fd);
	pj_ks(pj, "uri", desc->uri);
	pj_kn(pj, "from", from);
	pj_kb(pj, "writable", desc->perm & RZ_PERM_W);
	pj_kN(pj, "size", rz_io_desc_size(desc));
	pj_end(pj);
	return true;
}

static bool desc_list_table_cb(void *user, void *data, ut32 id) {
	RzTable *t = (RzTable *)user;
	RzIODesc *desc = (RzIODesc *)data;
	rz_table_add_rowf(t, "dbsXs", desc->fd, desc->io && (desc->io->desc == desc),
		rz_str_rwx_i(desc->perm), rz_io_desc_size(desc), desc->uri);
	return true;
}

RZ_IPI RzCmdStatus rz_open_close_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_num_is_valid_input(NULL, argv[1])) {
		RZ_LOG_ERROR("Invalid fd: %s\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	int fd = (int)rz_num_math(NULL, argv[1]);
	if (!rz_core_file_close_fd(core, fd)) {
		RZ_LOG_ERROR("Unable to find file descriptor %d\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_close_all_handler(RzCore *core, int argc, const char **argv) {
	rz_core_file_close_fd(core, -1);
	rz_io_close_all(core->io);
	rz_bin_file_delete_all(core->bin);

	// TODO: Move to a-- ?
	rz_analysis_purge(core->analysis);
	// TODO: Move to f-- ?
	rz_flag_unset_all(core->flags);
	RZ_LOG_INFO("Close all files\n");
	return RZ_CMD_STATUS_OK;
}
RZ_IPI RzCmdStatus rz_open_list_ascii_handler(RzCore *core, int argc, const char **argv) {
	struct open_list_ascii_data_t data = { 0 };
	data.core = core;
	data.p = core->print;
	data.fdsz = 0;
	rz_id_storage_foreach(core->io->files, init_desc_list_visual_cb, &data);
	rz_id_storage_foreach(core->io->files, desc_list_visual_cb, &data);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_arch_bits_handler(RzCore *core, int argc, const char **argv) {
	const char *filename = argc > 3 ? argv[3] : NULL;
	ut16 bits = rz_num_math(core->num, argv[2]);
	const char *arch = argv[1];

	int res = rz_core_bin_set_arch_bits(core, filename, arch, bits);
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_open_use_handler(RzCore *core, int argc, const char **argv) {
	RzListIter *iter = NULL;
	RzCoreFile *f;

	int fdnum = rz_num_math(NULL, argv[1]);
	rz_list_foreach (core->files, iter, f) {
		if (f->fd == fdnum) {
			core->file = f;
			rz_io_use_fd(core->io, fdnum);
			RzBinFile *bf = rz_bin_file_find_by_fd(core->bin, fdnum);
			if (!bf) {
				RZ_LOG_ERROR("Could not find binfile with fd %d\n", fdnum);
				return RZ_CMD_STATUS_ERROR;
			}
			rz_core_bin_raise(core, bf->id);
			rz_core_block_read(core);
			RZ_LOG_INFO("Switched to fd %d (%s)\n", fdnum, bf->file);
			return RZ_CMD_STATUS_OK;
		}
	}
	RZ_LOG_ERROR("Could not find any opened file with fd %d\n", fdnum);
	return RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus prioritize_file(RzCore *core, int fd) {
	if (fd <= 0) {
		RZ_LOG_ERROR("Wrong file descriptor %d\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	int curfd = rz_io_fd_get_current(core->io);
	if (fd == curfd) {
		return RZ_CMD_STATUS_OK;
	}

	if (!rz_io_use_fd(core->io, fd)) {
		RZ_LOG_ERROR("Could not use IO fd %d\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_block_read(core);
	RzBinFile *bf = rz_bin_file_find_by_fd(core->bin, fd);
	if (bf && !rz_core_bin_raise(core, bf->id)) {
		RZ_LOG_ERROR("Could not use bin id %d\n", bf->id);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_prioritize_handler(RzCore *core, int argc, const char **argv) {
	int fd = atoi(argv[1]);
	return prioritize_file(core, fd);
}

RZ_IPI RzCmdStatus rz_open_prioritize_next_handler(RzCore *core, int argc, const char **argv) {
	int fd = rz_io_fd_get_next(core->io, rz_io_fd_get_current(core->io));
	return prioritize_file(core, fd);
}

RZ_IPI RzCmdStatus rz_open_prioritize_prev_handler(RzCore *core, int argc, const char **argv) {
	int fd = rz_io_fd_get_prev(core->io, rz_io_fd_get_current(core->io));
	return prioritize_file(core, fd);
}

RZ_IPI RzCmdStatus rz_open_prioritize_next_rotate_handler(RzCore *core, int argc, const char **argv) {
	int fd = rz_io_fd_get_next(core->io, rz_io_fd_get_current(core->io));
	if (fd == -1) {
		fd = rz_io_fd_get_lowest(core->io);
	}
	return prioritize_file(core, fd) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_open_maps_remove_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_num_is_valid_input(NULL, argv[1])) {
		RZ_LOG_ERROR("Invalid map id '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	ut32 map_id = rz_num_math(NULL, argv[1]);
	if (!rz_io_map_del(core->io, map_id)) {
		RZ_LOG_ERROR("Could not delete IO map %d\n", map_id);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_remove_all_handler(RzCore *core, int argc, const char **argv) {
	rz_io_map_reset(core->io);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_list_ascii_handler(RzCore *core, int argc, const char **argv) {
	RzList *list = rz_list_newf((RzListFree)rz_listinfo_free);
	if (!list) {
		return RZ_CMD_STATUS_ERROR;
	}
	void **it;
	RzPVector *maps = rz_io_maps(core->io);
	rz_pvector_foreach_prev(maps, it) {
		RzIOMap *map = *it;
		char temp[32];
		rz_strf(temp, "%d", map->fd);
		RzListInfo *info = rz_listinfo_new(map->name, map->itv, map->itv, map->perm, temp);
		if (!info) {
			break;
		}
		rz_list_append(list, info);
	}
	RzTable *table = rz_core_table(core);
	rz_table_visual_list(table, list, core->offset, core->blocksize,
		rz_cons_get_size(NULL), rz_config_get_i(core->config, "scr.color"));
	char *tablestr = rz_table_tostring(table);
	rz_cons_printf("%s", tablestr);
	rz_table_free(table);
	rz_list_free(list);
	free(tablestr);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_all_fd_handler(RzCore *core, int argc, const char **argv) {
	ut32 fd = argc > 1 ? rz_num_math(NULL, argv[1]) : rz_io_fd_get_current(core->io);
	RzIODesc *desc = rz_io_desc_get(core->io, fd);
	if (!desc) {
		RZ_LOG_ERROR("Could not find any file descriptor with fd %d\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	RzIOMap *map = rz_io_map_add(core->io, fd, desc->perm, 0, 0, UT64_MAX);
	if (!map) {
		RZ_LOG_ERROR("Could not create a IO map for file descriptor %d\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_io_map_set_name(map, desc->name);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_relocate_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_num_is_valid_input(NULL, argv[1])) {
		RZ_LOG_ERROR("Invalid map id '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_num_is_valid_input(core->num, argv[2])) {
		RZ_LOG_ERROR("Invalid address '%s'\n", argv[2]);
		return RZ_CMD_STATUS_ERROR;
	}
	ut32 map_id = (ut32)rz_num_math(NULL, argv[1]);
	ut64 addr = rz_num_math(core->num, argv[2]);
	if (!rz_io_map_remap(core->io, map_id, addr)) {
		RZ_LOG_ERROR("Could not relocate map with id %d to %" PFMT64x "\n", map_id, addr);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_relocate_current_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_num_is_valid_input(core->num, argv[1])) {
		RZ_LOG_ERROR("Invalid address '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	RzIOMap *map = rz_io_map_get(core->io, core->offset);
	if (!map) {
		RZ_LOG_ERROR("Could not find any IO map at current offset\n");
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 addr = rz_num_math(core->num, argv[1]);
	if (!rz_io_map_remap(core->io, map->id, addr)) {
		RZ_LOG_ERROR("Could not relocate map with id %d to %" PFMT64x "\n", map->id, addr);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_resize_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_num_is_valid_input(NULL, argv[1])) {
		RZ_LOG_ERROR("Invalid map id '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_num_is_valid_input(core->num, argv[2])) {
		RZ_LOG_ERROR("Invalid size '%s'\n", argv[2]);
		return RZ_CMD_STATUS_ERROR;
	}
	ut32 map_id = (ut32)rz_num_math(NULL, argv[1]);
	ut64 size = rz_num_math(core->num, argv[2]);
	if (!rz_io_map_resize(core->io, map_id, size)) {
		RZ_LOG_ERROR("Could not resize map with id %d to %" PFMT64x "\n", map_id, size);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_prioritize_handler(RzCore *core, int argc, const char **argv) {
	ut32 id = (ut32)rz_num_math(core->num, argv[1]);
	if (!rz_io_map_exists_for_id(core->io, id)) {
		RZ_LOG_ERROR("Cannot find any map with mapid %d\n", id);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_io_map_priorize(core->io, id);
	rz_core_block_read(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_prioritize_binid_handler(RzCore *core, int argc, const char **argv) {
	ut32 id = (ut32)rz_num_math(core->num, argv[1]);
	if (!rz_bin_file_set_cur_by_id(core->bin, id)) {
		RZ_LOG_ERROR("Cannot prioritize bin with fd %d\n", id);
		return RZ_CMD_STATUS_ERROR;
	}
	RzListIter *it;
	RzCoreFile *file = NULL;
	rz_list_foreach (core->files, it, file) {
		void **binfile;
		rz_pvector_foreach (&file->binfiles, binfile) {
			RzBinFile *bf = *binfile;
			if (bf->id == id) {
				void **map;
				rz_pvector_foreach (&file->maps, map) {
					RzIOMap *m = *map;
					rz_io_map_priorize(core->io, m->id);
				}
			}
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_deprioritize_handler(RzCore *core, int argc, const char **argv) {
	ut32 id = (ut32)rz_num_math(core->num, argv[1]);
	if (!rz_io_map_exists_for_id(core->io, id)) {
		RZ_LOG_ERROR("Cannot find any map with mapid %d\n", id);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_io_map_depriorize(core->io, id);
	rz_core_block_read(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_prioritize_fd_handler(RzCore *core, int argc, const char **argv) {
	int fd = (int)rz_num_math(core->num, argv[1]);
	if (!rz_io_map_priorize_for_fd(core->io, fd)) {
		RZ_LOG_ERROR("Cannot prioritize any map for fd %d\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_name_handler(RzCore *core, int argc, const char **argv) {
	RzIOMap *map = rz_io_map_get(core->io, core->offset);
	if (!map) {
		RZ_LOG_ERROR("Cannot find any map at address %" PFMT64x "d\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_io_map_set_name(map, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_name_del_handler(RzCore *core, int argc, const char **argv) {
	RzIOMap *map = rz_io_map_get(core->io, core->offset);
	if (!map) {
		RZ_LOG_ERROR("Cannot find any map at address %" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_io_map_del_name(map);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_name_id_handler(RzCore *core, int argc, const char **argv) {
	ut32 id = rz_num_math(core->num, argv[1]);
	RzIOMap *map = rz_io_map_resolve(core->io, id);
	if (!map) {
		RZ_LOG_ERROR("Cannot find any map with id %d\n", id);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_io_map_set_name(map, argv[2]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_name_id_del_handler(RzCore *core, int argc, const char **argv) {
	ut32 id = rz_num_math(core->num, argv[1]);
	RzIOMap *map = rz_io_map_resolve(core->io, id);
	if (!map) {
		RZ_LOG_ERROR("Cannot find any map with id %d\n", id);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_io_map_del_name(map);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_map_fd_handler(RzCore *core, int argc, const char **argv) {
	ut32 fd = argc > 1 ? rz_num_math(NULL, argv[1]) : rz_io_fd_get_current(core->io);
	RzIODesc *desc = rz_io_desc_get(core->io, fd);
	if (!desc) {
		RZ_LOG_ERROR("Cannot find any descriptor with fd %d\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 size = rz_io_desc_size(desc);
	RzIOMap *map = rz_io_map_add(core->io, fd, desc->perm, 0, 0, size);
	if (!map) {
		RZ_LOG_ERROR("Cannot create new map for fd %d\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_io_map_set_name(map, desc->name);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_flags_handler(RzCore *core, int argc, const char **argv) {
	int perm = rz_str_rwx(argv[1]);
	RzIOMap *map = NULL;
	if (argc > 2) {
		ut32 id = rz_num_math(NULL, argv[2]);
		map = rz_io_map_resolve(core->io, id);
		if (!map) {
			RZ_LOG_ERROR("Cannot find any map with id %d\n", id);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		map = rz_io_map_get(core->io, core->offset);
		if (!map) {
			RZ_LOG_ERROR("Cannot find any map at the current address %" PFMT64x "\n", core->offset);
			return RZ_CMD_STATUS_ERROR;
		}
	}

	map->perm = perm;
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_flags_global_handler(RzCore *core, int argc, const char **argv) {
	const char *arg = argv[1];
	enum mode {
		ADD,
		DEL,
		SET,
	} mode = SET;
	if (arg[0] == '+') {
		mode = ADD;
		arg++;
	} else if (arg[0] == '-') {
		mode = DEL;
		arg++;
	}
	int perm = rz_str_rwx(arg);
	RzPVector *maps = rz_io_maps(core->io);
	void **it;
	rz_pvector_foreach (maps, it) {
		RzIOMap *map = *it;
		switch (mode) {
		case ADD:
			map->perm |= perm;
			break;
		case DEL:
			map->perm &= ~perm;
			break;
		case SET:
			map->perm = perm;
			break;
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_map_handler(RzCore *core, int argc, const char **argv) {
	int fd = (int)rz_num_math(NULL, argv[1]);
	if (fd < 3) {
		RZ_LOG_ERROR("Wrong fd, it must be greather than 3\n");
		return RZ_CMD_STATUS_ERROR;
	}

	ut64 vaddr = rz_num_math(core->num, argv[2]);
	ut64 size = argc > 3 ? rz_num_math(core->num, argv[3]) : rz_io_fd_size(core->io, fd);
	ut64 paddr = argc > 4 ? rz_num_math(core->num, argv[4]) : 0;
	int rwx = argc > 5 ? rz_str_rwx(argv[5]) : 0;
	const char *name = argc > 6 ? argv[6] : "";

	if (argc <= 5) {
		RzIODesc *desc = rz_io_desc_get(core->io, fd);
		if (!desc) {
			RZ_LOG_ERROR("Could not determine any opened file with fd %d\n", fd);
			return RZ_CMD_STATUS_ERROR;
		}

		rwx = desc->perm;
	}
	RzIOMap *map = rz_io_map_add(core->io, fd, rwx, paddr, vaddr, size);
	if (!map) {
		RZ_LOG_ERROR("Could not create new map for fd %d at vaddr %" PFMT64x "\n", fd, vaddr);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_io_map_set_name(map, name);
	return RZ_CMD_STATUS_OK;
}

static void open_maps_show(RzCore *core, RzCmdStateOutput *state, RzIOMap *map, bool seek_inside) {
	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("%d %d\n", map->fd, map->id);
		break;
	case RZ_OUTPUT_MODE_QUIETEST:
		rz_cons_printf("0x%08" PFMT64x "\n", rz_io_map_get_from(map));
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_ki(state->d.pj, "map", map->id);
		pj_ki(state->d.pj, "fd", map->fd);
		pj_kn(state->d.pj, "delta", map->delta);
		pj_kn(state->d.pj, "from", rz_io_map_get_from(map));
		pj_kn(state->d.pj, "to", rz_itv_end(map->itv));
		pj_ks(state->d.pj, "perm", rz_str_rwx_i(map->perm));
		pj_ks(state->d.pj, "name", rz_str_get(map->name));
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "ddxxxxxss",
			map->id, map->fd, map->delta, map->delta + rz_itv_size(map->itv), rz_itv_size(map->itv),
			rz_io_map_get_from(map), rz_itv_end(map->itv), rz_str_rwx_i(map->perm), rz_str_get(map->name));
		break;
	default:
		rz_cons_printf("%2d fd: %i +0x%08" PFMT64x " 0x%08" PFMT64x " %c 0x%08" PFMT64x " %s %s\n",
			map->id, map->fd,
			map->delta, rz_io_map_get_from(map), seek_inside ? '*' : '-', rz_io_map_get_to(map),
			rz_str_rwx_i(map->perm), rz_str_get(map->name));
		break;
	}
}

static void open_maps_list(RzCore *core, RzCmdStateOutput *state, int fd) {
	RzPVector *maps = rz_io_maps(core->io);
	void **it;

	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "ddxxxxxss", "id", "fd", "pa", "pa_end", "size", "va", "va_end", "perm", "name");
	if (state->mode == RZ_OUTPUT_MODE_TABLE) {
		state->d.t->showFancy = true;
	}
	RzIOMap *at_seek = NULL;
	if (state->mode == RZ_OUTPUT_MODE_STANDARD) {
		at_seek = rz_io_map_get(core->io, core->offset);
	}
	rz_pvector_foreach (maps, it) {
		RzIOMap *map = *it;
		if (fd >= 0 && map->fd != fd) {
			continue;
		}
		open_maps_show(core, state, map, map == at_seek);
	}
	rz_cmd_state_output_array_end(state);
}

RZ_IPI RzCmdStatus rz_open_maps_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int fd = argc > 1 ? rz_num_math(NULL, argv[1]) : -1;
	open_maps_list(core, state, fd);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_maps_list_cur_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzIOMap *map = rz_io_map_get(core->io, core->offset);
	if (!map) {
		RZ_LOG_ERROR("Cannot find any map at the current address %" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cmd_state_output_set_columnsf(state, "ddxxxxxss", "id", "fd", "pa", "pa_end", "va", "va_end", "perm", "name");
	if (state->mode == RZ_OUTPUT_MODE_TABLE) {
		state->d.t->showFancy = true;
	}
	open_maps_show(core, state, map, false);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_binary_select_id_handler(RzCore *core, int argc, const char **argv) {
	ut32 id = (ut32)rz_num_math(NULL, argv[1]);
	if (!rz_core_bin_raise(core, id)) {
		RZ_LOG_ERROR("Could not select binary file with id %d\n", id);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_binary_select_fd_handler(RzCore *core, int argc, const char **argv) {
	ut32 fd = rz_num_math(NULL, argv[1]);
	RzBinFile *bf = rz_bin_file_find_by_fd(core->bin, fd);
	if (!bf) {
		RZ_LOG_ERROR("Could not find any binary file for fd %d.\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_core_bin_raise(core, bf->id)) {
		RZ_LOG_ERROR("core: Could not select the binary file for fd %d.\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_binary_del_handler(RzCore *core, int argc, const char **argv) {
	ut32 id = (ut32)rz_num_math(NULL, argv[1]);
	RzBinFile *bf = rz_bin_file_find_by_id(core->bin, id);
	if (!bf) {
		RZ_LOG_ERROR("Could not find any binary file with id %d.\n", id);
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_core_binfiles_delete(core, bf)) {
		RZ_LOG_ERROR("Could not delete binary file with id %d\n", id);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_binary_del_all_handler(RzCore *core, int argc, const char **argv) {
	rz_bin_file_delete_all(core->bin);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_binary_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_binfiles_print(core, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_binary_show_handler(RzCore *core, int argc, const char **argv) {
	RzBinFile *bf = rz_bin_file_at(core->bin, core->offset);
	if (bf) {
		rz_cons_printf("%d\n", bf->id);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_binary_list_ascii_handler(RzCore *core, int argc, const char **argv) {
	RzBin *bin = core->bin;
	if (!bin) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzList *list = rz_list_newf((RzListFree)rz_listinfo_free);
	if (!list) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzListIter *iter;
	RzBinFile *bf = NULL;
	rz_list_foreach (bin->binfiles, iter, bf) {
		char temp[64];
		RzInterval inter = (RzInterval){ bf->o->opts.baseaddr, bf->o->size };
		RzListInfo *info = rz_listinfo_new(bf->file, inter, inter, -1, sdb_itoa(bf->fd, temp, 10));
		if (!info) {
			break;
		}
		rz_list_append(list, info);
	}
	RzTable *table = rz_core_table(core);
	rz_table_visual_list(table, list, core->offset, core->blocksize,
		rz_cons_get_size(NULL), rz_config_get_i(core->config, "scr.color"));
	char *table_text = rz_table_tostring(table);
	rz_cons_printf("\n%s\n", table_text);
	free(table_text);
	rz_table_free(table);
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_binary_add_handler(RzCore *core, int argc, const char **argv) {
	ut64 loadaddr = rz_num_math(core->num, argv[1]);
	int fd = rz_io_fd_get_current(core->io);
	RzIODesc *desc = rz_io_desc_get(core->io, fd);
	if (!desc) {
		RZ_LOG_ERROR("Could not determine any opened file with fd %d\n", fd);
		return RZ_CMD_STATUS_ERROR;
	}
	RzBinOptions opt;
	opt.sz = 1024 * 1024 * 1;
	rz_core_bin_options_init(core, &opt, desc->fd, core->offset, loadaddr);
	RzBinFile *bf = rz_bin_open_io(core->bin, &opt);
	rz_core_bin_apply_all_info(core, bf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_binary_file_handler(RzCore *core, int argc, const char **argv) {
	int saved_fd = rz_io_fd_get_current(core->io);
	RzList *files = rz_list_newf(NULL);
	RzListIter *iter;

	RzIODesc *desc = NULL;
	if (argc > 1) {
		desc = rz_io_open(core->io, argv[1], RZ_PERM_R, 0);
		if (!desc) {
			RZ_LOG_ERROR("Could not open file %s\n", argv[1]);
			rz_list_free(files);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_list_append(files, (void *)(size_t)desc->fd);
	} else {
		RzList *ofiles = rz_id_storage_list(core->io->files);
		RzIODesc *desc;
		rz_list_foreach (ofiles, iter, desc) {
			rz_list_append(files, (void *)(size_t)desc->fd);
		}
	}

	void *_fd;
	rz_list_foreach (files, iter, _fd) {
		RzBinOptions opt;
		int fd = (size_t)_fd;
		rz_core_bin_options_init(core, &opt, fd, core->offset, 0);
		RzBinFile *bf = rz_bin_open_io(core->bin, &opt);
		rz_core_bin_apply_all_info(core, bf);
	}
	rz_list_free(files);

	rz_io_desc_close(desc);
	rz_io_use_fd(core->io, saved_fd);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_binary_rebase_handler(RzCore *core, int argc, const char **argv) {
	rz_core_bin_rebase(core, rz_num_math(core->num, argv[1]));
	rz_core_bin_apply_all_info(core, rz_bin_cur(core->bin));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_binary_reload_handler(RzCore *core, int argc, const char **argv) {
	// XXX: this will reload the bin using the buffer.
	// An assumption is made that assumes there is an underlying
	// plugin that will be used to load the bin (e.g. malloc://)
	// TODO: Might be nice to reload a bin at a specified offset?
	core_bin_reload(core, NULL, rz_num_math(core->num, argv[1]));
	rz_core_block_read(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = argc > 2 ? rz_num_math(core->num, argv[2]) : 0;
	int perms = argc > 3 ? rz_str_rwx(argv[3]) : RZ_PERM_R;
	return bool2status(rz_core_file_open_load(core, argv[1], addr, perms, false));
}

RZ_IPI RzCmdStatus rz_open_write_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = argc > 2 ? rz_num_math(core->num, argv[2]) : 0;
	int perms = argc > 3 ? rz_str_rwx(argv[3]) : RZ_PERM_RW;
	return bool2status(rz_core_file_open_load(core, argv[1], addr, perms, true));
}

RZ_IPI RzCmdStatus rz_open_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "dbsXs", "fd", "raised", "perm", "size", "uri");
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_id_storage_foreach(core->io->files, desc_list_cb, core->print);
		break;
	case RZ_OUTPUT_MODE_JSON:
		rz_id_storage_foreach(core->io->files, desc_list_json_cb, state->d.pj);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_id_storage_foreach(core->io->files, desc_list_table_cb, state->d.t);
		break;
	case RZ_OUTPUT_MODE_QUIET:
		rz_id_storage_foreach(core->io->files, desc_list_quiet_cb, core->print);
		break;
	default:
		break;
	}
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_show_current_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzIOMap *map = rz_io_map_get(core->io, core->offset);
	if (!map) {
		RZ_LOG_ERROR("Could not find any map at current address %" PFMT64x ".\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	RzIODesc *desc = rz_io_desc_get(core->io, map->fd);
	if (!desc) {
		RZ_LOG_ERROR("Could not find file for map fd %d.\n", map->fd);
		return RZ_CMD_STATUS_ERROR;
	}

	rz_cmd_state_output_set_columnsf(state, "dbsXs", "fd", "raised", "perm", "size", "uri");
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		desc_list_cb(core->print, desc, 0);
		break;
	case RZ_OUTPUT_MODE_JSON:
		desc_list_json_cb(state->d.pj, desc, 0);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		desc_list_table_cb(state->d.t, desc, 0);
		break;
	case RZ_OUTPUT_MODE_QUIET:
		desc_list_quiet_cb(core->print, desc, 0);
		break;
	default:
		break;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_exchange_handler(RzCore *core, int argc, const char **argv) {
	int fd = (int)rz_num_math(NULL, argv[1]);
	int fdx = (int)rz_num_math(NULL, argv[2]);
	if ((fdx == -1) || (fd == -1) || (fdx == fd)) {
		RZ_LOG_ERROR("Could not exchange file descriptor %d and %d.\n", fd, fdx);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_io_desc_exchange(core->io, fd, fdx);
	rz_core_block_read(core);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus open_core_file(RzCore *core, const char *filename) {
	if (core->tasks.current_task != core->tasks.main_task) {
		RZ_LOG_ERROR("This command can only be executed on the main task!\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_task_sync_end(&core->tasks);
	rz_core_fini(core);
	rz_core_init(core);
	rz_core_task_sync_begin(&core->tasks);
	if (!rz_core_file_open(core, filename, RZ_PERM_R, 0)) {
		RZ_LOG_ERROR("Cannot open file '%s'\n", filename);
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 baddr = rz_config_get_i(core->config, "bin.baddr");
	return bool2status(rz_core_bin_load(core, NULL, baddr));
}

RZ_IPI RzCmdStatus rz_open_core_file_handler(RzCore *core, int argc, const char **argv) {
	return open_core_file(core, argv[1]);
}

RZ_IPI RzCmdStatus rz_open_malloc_handler(RzCore *core, int argc, const char **argv) {
	int len = (int)rz_num_math(core->num, argv[1]);
	if (len < 0) {
		RZ_LOG_ERROR("Invalid length %d.\n", len);
		return RZ_CMD_STATUS_ERROR;
	}
	return bool2status(rz_core_file_malloc_copy_chunk(core, len, core->offset));
}

static RzCmdStatus open_nobin_file(RzCore *core, const char *uri, ut64 addr, int perms) {
	if (!strcmp(uri, "=")) {
		uri = "malloc://512";
	}

	RzIODesc *desc = rz_io_open_at(core->io, uri, perms, 0644, addr, NULL);
	if (!desc || desc->fd == -1) {
		RZ_LOG_ERROR("Cannot open '%s' at %" PFMT64x ".\n", uri, addr);
		return RZ_CMD_STATUS_ERROR;
	}

	core->num->value = desc->fd;
	rz_core_block_read(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_open_nobin_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = argc > 2 ? rz_num_math(core->num, argv[2]) : 0;
	int perms = argc > 3 ? rz_str_rwx(argv[3]) : RZ_PERM_R;
	return open_nobin_file(core, argv[1], addr, perms);
}

RZ_IPI RzCmdStatus rz_open_nobin_write_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = argc > 2 ? rz_num_math(core->num, argv[2]) : 0;
	int perms = argc > 3 ? rz_str_rwx(argv[3]) : RZ_PERM_RW;
	return open_nobin_file(core, argv[1], addr, perms);
}

RZ_IPI RzCmdStatus rz_reopen_handler(RzCore *core, int argc, const char **argv) {
	int fd;
	if (argc > 1) {
		fd = (int)rz_num_math(NULL, argv[1]);
		if (fd < 0) {
			RZ_LOG_ERROR("Invalid negative fd %d\n", fd);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		if (!core->io || !core->io->desc) {
			RZ_LOG_ERROR("Cannot find current file.\n");
			return RZ_CMD_STATUS_ERROR;
		}
		fd = core->io->desc->fd;
	}
	rz_core_io_file_open(core, fd);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reopen_write_handler(RzCore *core, int argc, const char **argv) {
	int fd;
	int perms = RZ_PERM_RW;
	if (argc > 1) {
		fd = (int)rz_num_math(NULL, argv[1]);
		if (fd < 0) {
			RZ_LOG_ERROR("Invalid negative fd %d\n", fd);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		if (!core->io || !core->io->desc) {
			RZ_LOG_ERROR("Cannot find current file.\n");
			return RZ_CMD_STATUS_ERROR;
		}
		fd = core->io->desc->fd;
		perms |= core->io->desc->perm;
	}
	rz_core_io_file_reopen(core, fd, perms);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reopen_binary_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_file_reopen(core, argv[1], 0, 2));
}

RZ_IPI RzCmdStatus rz_reopen_core_handler(RzCore *core, int argc, const char **argv) {
	if (!core->io || !core->io->desc) {
		RZ_LOG_ERROR("Could not find current file\n");
		return RZ_CMD_STATUS_ERROR;
	}

	return open_core_file(core, core->io->desc->uri);
}

RZ_IPI RzCmdStatus rz_reopen_debug_handler(RzCore *core, int argc, const char **argv) {
	// TODO: this is bad as we force ourselves to convert arguments to strings.
	//       There should be an API to reopen a file in debug mode and directly
	//       pass args to it.
	char **args = RZ_NEWS(char *, argc - 1);
	int i;
	for (i = 1; i < argc; i++) {
		char *t = rz_cmd_escape_arg(argv[i], RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG);
		args[i - 1] = rz_str_newf("\"%s\"", t);
		free(t);
	}
	char *args_str = rz_str_array_join((const char **)args, argc - 1, " ");
	for (i = 0; i < argc - 1; i++) {
		free(args[i]);
	}
	free(args);
	rz_core_file_reopen_debug(core, args_str);
	free(args_str);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reopen_debug_file_handler(RzCore *core, int argc, const char **argv) {
	const char *uri = argv[1];
	ut64 addr = argc > 2 ? rz_num_math(core->num, argv[2]) : 0;
	rz_core_file_reopen_remote_debug(core, uri, addr);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reopen_debug_rzrun_handler(RzCore *core, int argc, const char **argv) {
	char *file = rz_file_temp("rz-run");
	char *s = rz_str_dup(argv[1]);
	rz_config_set(core->config, "dbg.profile", file);
	rz_str_replace_char(s, ',', '\n');
	rz_file_dump(file, (const ut8 *)s, strlen(s), 0);
	rz_file_dump(file, (const ut8 *)"\n", 1, 1);
	free(s);
	free(file);
	rz_core_file_reopen_debug(core, "");
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reopen_malloc_handler(RzCore *core, int argc, const char **argv) {
	rz_core_file_reopen_in_malloc(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reopen_nobin_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_file_reopen(core, NULL, 0, 0));
}

RZ_IPI RzCmdStatus rz_reopen_nobin_write_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_file_reopen(core, NULL, RZ_PERM_RW, 0));
}

static RzCmdStatus reopen_nobin_headers(RzCore *core, int add_perms) {
	RzIODesc *desc = rz_io_desc_get(core->io, core->file->fd);
	if (!desc) {
		RZ_LOG_ERROR("Could not find current file.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	int perms = core->io->desc->perm | add_perms;
	char *fname = rz_str_dup(desc->name);
	if (!fname) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_core_bin_load_structs(core, fname)) {
		RZ_LOG_WARN("Could not load file format information for '%s'.\n", fname);
	}
	bool res = rz_core_file_reopen(core, fname, perms, 0);
	free(fname);
	return bool2status(res);
}

RZ_IPI RzCmdStatus rz_reopen_nobin_headers_handler(RzCore *core, int argc, const char **argv) {
	return reopen_nobin_headers(core, 0);
}

RZ_IPI RzCmdStatus rz_reopen_nobin_write_headers_handler(RzCore *core, int argc, const char **argv) {
	return reopen_nobin_headers(core, RZ_PERM_RW);
}
