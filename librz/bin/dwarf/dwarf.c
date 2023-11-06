// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include <rz_socket.h>
#include "dwarf_private.h"
#include "../format/elf/elf.h"

RZ_IPI bool RzBinDwarfEncoding_from_file(RzBinDwarfEncoding *encoding, RzBinFile *bf) {
	if (!(encoding && bf)) {
		return false;
	}
	RzBinInfo *binfo = bf->o && bf->o->info ? bf->o->info : NULL;
	encoding->address_size = binfo->bits ? binfo->bits / 8 : 4;
	return true;
}

static inline RZ_OWN RzBinDWARF *dwarf_from_file(
	RZ_BORROW RZ_NONNULL RzBinFile *bf, bool is_dwo) {
	rz_return_val_if_fail(bf, NULL);
	RzBinDWARF *dw = RZ_NEW0(RzBinDWARF);
	RET_NULL_IF_FAIL(dw);

	dw->addr = rz_bin_dwarf_addr_from_file(bf);
	dw->line_str = rz_bin_dwarf_line_str_from_file(bf);
	dw->aranges = rz_bin_dwarf_aranges_from_file(bf);

	dw->str = rz_bin_dwarf_str_from_file(bf, is_dwo);
	dw->str_offsets = rz_bin_dwarf_str_offsets_from_file(bf, is_dwo);
	dw->loclists = rz_bin_dwarf_loclists_new_from_file(bf, is_dwo);
	dw->rnglists = rz_bin_dwarf_rnglists_new_from_file(bf, is_dwo);
	dw->abbrev = rz_bin_dwarf_abbrev_from_file(bf, is_dwo);

	if (dw->abbrev) {
		dw->info = rz_bin_dwarf_info_from_file(bf, dw, is_dwo);
	}
	if (dw->info) {
		dw->line = rz_bin_dwarf_line_from_file(bf, dw, is_dwo);
	}
	return dw;
}

static inline char *read_debuglink(RzBinFile *binfile) {
	RzBinSection *sect = rz_bin_dwarf_section_by_name(binfile, ".gnu_debuglink", false);
	RET_NULL_IF_FAIL(sect);
	RzBuffer *buffer = rz_bin_dwarf_section_buf(binfile, sect);
	RET_NULL_IF_FAIL(buffer);
	char *name = rz_buf_get_string(buffer, 0);
	// TODO: Verification the CRC
	rz_buf_free(buffer);
	return name;
}

static inline char *read_build_id(RzBinFile *binfile) {
	RzBinSection *sect = rz_bin_dwarf_section_by_name(binfile, ".note.gnu.build-id", false);
	RET_NULL_IF_FAIL(sect);
	RzBuffer *buffer = rz_bin_dwarf_section_buf(binfile, sect);
	RET_NULL_IF_FAIL(buffer);

	char *build_id = NULL;
	/**
	 * struct build_id_note {
	 *   Elf_Nhdr nhdr;
	 *   char name[4];
	 *   uint8_t buf[0];
	 * };
	 */
	size_t nhdr_sz = binfile->o->info->bits == 64 ? sizeof(Elf64_Nhdr) : sizeof(Elf32_Nhdr);
	size_t begin = nhdr_sz + 4;
	size_t sz = rz_buf_size(buffer) - begin;
	ut8 *buf = RZ_NEWS0(ut8, sz);
	if (!buf) {
		goto beach;
	}
	if (rz_buf_read_at(buffer, begin, buf, sz) != sz) {
		goto beach;
	}
	build_id = rz_hex_bin2strdup(buf, (int)sz);

beach:
	rz_buf_free(buffer);
	free(buf);
	return build_id;
}

static inline RzBinDWARF *dwarf_from_debuglink(
	const char *file_directory,
	RzList /*<const char *>*/ *debug_file_directorys,
	const char *debuglink_path) {
	RzBinDWARF *dw = NULL;
	char *dir = NULL;
	char *path = NULL;
	char *file_dir = NULL;

	path = rz_file_path_join(file_directory, debuglink_path);
	if (rz_file_exists(path)) {
		goto ok;
	}
	free(path);

	dir = rz_file_path_join(file_directory, ".debug");
	path = rz_file_path_join(dir, debuglink_path);
	if (rz_file_exists(path)) {
		goto ok;
	}
	free(dir);
	free(path);

	if (RZ_STR_ISNOTEMPTY(file_directory) && strlen(file_directory) >= 2 && file_directory[1] == ':') {
		file_dir = rz_str_newf("/%c%s", file_directory[0], file_directory + 2);
	} else {
		file_dir = rz_str_new(file_directory);
	}
	RzListIter *it = NULL;
	const char *debug_file_directory = NULL;
	rz_list_foreach (debug_file_directorys, it, debug_file_directory) {
		dir = rz_file_path_join(debug_file_directory, file_dir);
		path = rz_file_path_join(dir, debuglink_path);
		if (rz_file_exists(path)) {
			goto ok;
		}
		free(dir);
		free(path);
	}

	return NULL;
ok:
	dw = rz_bin_dwarf_from_path(path, false);
	free(dir);
	free(path);
	free(file_dir);
	return dw;
}

static inline RzBinDWARF *dwarf_from_build_id(
	RzList /*<const char *>*/ *debug_file_directorys,
	const char *build_id_path) {
	RzListIter *it = NULL;
	const char *debug_file_directory = NULL;
	rz_list_foreach (debug_file_directorys, it, debug_file_directory) {
		char *dir = rz_file_path_join(debug_file_directory, ".build-id");
		char *path = rz_file_path_join(dir, build_id_path);
		if (rz_file_exists(path)) {
			RzBinDWARF *dw = rz_bin_dwarf_from_path(path, false);
			free(dir);
			free(path);
			return dw;
		}
		free(dir);
		free(path);
	}
	return NULL;
}

RZ_API RZ_OWN RzBinDWARF *rz_bin_dwarf_search_debug_file_directory(
	RZ_BORROW RZ_NONNULL RzBinFile *bf,
	RZ_BORROW RZ_NONNULL RzList /*<const char *>*/ *debug_file_directorys) {
	rz_return_val_if_fail(bf && debug_file_directorys, NULL);

	RzBinDWARF *dw = NULL;
	char *build_id = read_build_id(bf);
	if (build_id) {
		char *build_id_path = rz_str_newf("%c%c/%s", build_id[0], build_id[1], build_id + 2);
		dw = dwarf_from_build_id(debug_file_directorys, build_id_path);
		free(build_id);
		free(build_id_path);
		if (dw) {
			return dw;
		}
	}
	char *debuglink = read_debuglink(bf);
	if (debuglink) {
		char *file_abspath = rz_file_abspath(bf->file);
		char *file_dir = file_abspath ? rz_file_dirname(file_abspath) : NULL;
		if (file_dir) {
			dw = dwarf_from_debuglink(file_dir, debug_file_directorys, debuglink);
		}
		free(debuglink);
		free(file_dir);
		if (dw) {
			return dw;
		}
	}
	return NULL;
}

RZ_API RZ_OWN RzBinDWARF *rz_bin_dwarf_from_debuginfod(
	RZ_BORROW RZ_NONNULL RzBinFile *bf,
	RZ_BORROW RZ_NONNULL RzList /*<const char *>*/ *debuginfod_urls) {
	RzBinDWARF *dw = NULL;
	char *build_id = read_build_id(bf);
	if (!build_id) {
		return NULL;
	}
	RzListIter *it = NULL;
	const char *debuginfod_url = NULL;
	rz_list_foreach (debuginfod_urls, it, debuginfod_url) {
		char *url = rz_str_newf("%s/buildid/%s/debuginfo", debuginfod_url, build_id);
		if (!url) {
			break;
		}
		dw = rz_bin_dwarf_from_path(url, false);
		free(url);
		if (dw) {
			break;
		}
	}
	free(build_id);
	return dw;
}

/**
 * \brief Load DWARF from split DWARF file
 * \param filepath The file path
 * \return RzBinDWARF pointer or NULL if failed
 */
RZ_API RZ_OWN RzBinDWARF *rz_bin_dwarf_from_path(
	RZ_BORROW RZ_NONNULL const char *filepath, bool is_dwo) {
	rz_return_val_if_fail(filepath, NULL);

	RzBinDWARF *dwo = NULL;
	RzIO *io_tmp = rz_io_new();
	RzBin *bin_tmp = rz_bin_new();
	rz_io_bind(io_tmp, &bin_tmp->iob);

	RzBinOptions bopt = { 0 };
	rz_bin_options_init(&bopt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin_tmp, filepath, &bopt);
	if (!bf) {
		goto beach;
	}
	dwo = dwarf_from_file(bf, is_dwo);

beach:
	rz_bin_free(bin_tmp);
	rz_io_free(io_tmp);
	return dwo;
}

RZ_API RZ_OWN RzBinDWARF *rz_bin_dwarf_from_file(
	RZ_BORROW RZ_NONNULL RzBinFile *bf) {
	return dwarf_from_file(bf, false);
}

RZ_API void rz_bin_dwarf_free(RZ_OWN RZ_NULLABLE RzBinDWARF *dw) {
	if (!dw) {
		return;
	}
	rz_bin_dwarf_free(dw->parent);

	DebugRngLists_free(dw->rnglists);
	rz_bin_dwarf_addr_free(dw->addr);
	rz_bin_dwarf_str_free(dw->str);
	rz_bin_dwarf_str_offsets_free(dw->str_offsets);

	rz_bin_dwarf_abbrev_free(dw->abbrev);
	rz_bin_dwarf_info_free(dw->info);
	rz_bin_dwarf_line_free(dw->line);
	rz_bin_dwarf_loclists_free(dw->loclists);
	rz_bin_dwarf_aranges_free(dw->aranges);
	free(dw);
}
