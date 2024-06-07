// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"
#include "../format/elf/elf.h"
#include "../format/mach0/mach0.h"

RZ_IPI bool RzBinDwarfEncoding_from_file(RzBinDwarfEncoding *encoding, RzBinFile *bf) {
	if (!(encoding && bf)) {
		return false;
	}
	RzBinInfo *binfo = bf->o && bf->o->info ? bf->o->info : NULL;
	if (!binfo) {
		return false;
	}
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
	if (!(dw->addr || dw->line_str || dw->aranges || dw->str || dw->str_offsets || dw->loclists || dw->rnglists || dw->abbrev)) {
		rz_bin_dwarf_free(dw);
		return NULL;
	}
	return dw;
}

static inline char *read_debuglink(RzBinFile *binfile) {
	RzBinSection *sect = NULL;
	const char *name = NULL;
	RzBinEndianReader *R = NULL;
	RET_NULL_IF_FAIL(
		(sect = rz_bin_dwarf_section_by_name(binfile, ".gnu_debuglink", false)) &&
		(R = rz_bin_dwarf_section_reader(binfile, sect)) &&
		R_read_cstring(R, &name));
	// TODO: Verification the CRC
	char *debuglink = rz_str_dup(name);
	R_free(R);
	return debuglink;
}

static inline char *read_build_id(RzBinFile *binfile) {
	RzBinSection *sect = rz_bin_dwarf_section_by_name(binfile, ".note.gnu.build-id", false);
	RET_NULL_IF_FAIL(sect);
	RzBinEndianReader *R = rz_bin_dwarf_section_reader(binfile, sect);
	RET_NULL_IF_FAIL(R);

	char *build_id = NULL;
	/**
	 * struct build_id_note {
	 *   Elf_Nhdr nhdr;
	 *   char name[4];
	 *   uint8_t buf[0];
	 * };
	 */
	st64 nhdr_sz = binfile->o->info->bits == 64 ? sizeof(Elf64_Nhdr) : sizeof(Elf32_Nhdr);
	st64 begin = nhdr_sz + 4;
	R_seek(R, begin, SEEK_SET);
	build_id = rz_hex_bin2strdup(R_data(R), (int)R_remain(R));

	R_free(R);
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
		file_dir = rz_str_dup(file_directory);
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

	free(file_dir);
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

static const char *mach0_uuid(RZ_BORROW RZ_NONNULL RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	if (!rz_bin_file_rclass_is(bf, "mach0")) {
		return NULL;
	}
	struct MACH0_(obj_t) *mo = bf->o->bin_obj;
	if (mo->uuidn <= 0) {
		RZ_LOG_WARN("mach0 file don't contains uuid\n");
		return NULL;
	}
	char key[32];
	if (mo->uuidn > 1) {
		RZ_LOG_WARN("mach0 file contains multiple uuids\n");
	}
	snprintf(key, sizeof(key) - 1, "uuid.%d", mo->uuidn - 1);
	return sdb_const_get(mo->kv, key);
}

typedef struct {
	RzIO *io;
	RzBin *bin;
	RzBinFile *bf;
} DwBinary;

static bool binary_from_path(DwBinary *b, const char *filepath) {
	b->io = rz_io_new();
	if (!b->io) {
		return false;
	}
	b->bin = rz_bin_new();
	if (!b->bin) {
		return false;
	}
	rz_io_bind(b->io, &b->bin->iob);

	RzBinOptions bopt = { 0 };
	rz_bin_options_init(&bopt, 0, 0, 0, false);
	b->bf = rz_bin_open(b->bin, filepath, &bopt);

	return b->bf;
}

static void binary_close(DwBinary *b) {
	rz_io_free(b->io);
	rz_bin_free(b->bin);
}

RZ_API RZ_OWN RzBinDWARF *rz_bin_dwarf_load_dsym(RZ_BORROW RZ_NONNULL RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);

	if (RZ_STR_ISEMPTY(bf->file)) {
		return NULL;
	}

	RzBinDWARF *dw = NULL;
	RzStrBuf path_buf = { 0 };
	DwBinary binary = { 0 };
	char *file_abspath = rz_file_abspath(bf->file);
	const char *filename = rz_file_basename(bf->file);
	const char *dwarf_path = ".dSYM/Contents/Resources/DWARF/";
	rz_strbuf_initf(&path_buf, "%s%s%s", file_abspath, dwarf_path, filename);
	if (!rz_file_exists(rz_strbuf_get(&path_buf))) {
		goto out;
	}

	if (!binary_from_path(&binary, rz_strbuf_get(&path_buf))) {
		goto out;
	}

	const char *uuid = mach0_uuid(bf);
	const char *uuid_dw = mach0_uuid(binary.bf);
	if ((uuid && uuid_dw && RZ_STR_EQ(uuid_dw, uuid))) {
		dw = dwarf_from_file(binary.bf, false);
	}

out:
	free(file_abspath);
	rz_strbuf_fini(&path_buf);
	binary_close(&binary);
	return dw;
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
		free(file_abspath);
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
	rz_return_val_if_fail(bf && debuginfod_urls, NULL);

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
	DwBinary binary = { 0 };
	if (!binary_from_path(&binary, filepath)) {
		goto beach;
	}
	dwo = dwarf_from_file(binary.bf, is_dwo);

beach:
	binary_close(&binary);
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

	RngLists_free(dw->rnglists);
	rz_bin_dwarf_addr_free(dw->addr);
	rz_bin_dwarf_str_free(dw->str);
	rz_bin_dwarf_line_str_free(dw->line_str);
	rz_bin_dwarf_str_offsets_free(dw->str_offsets);

	rz_bin_dwarf_abbrev_free(dw->abbrev);
	rz_bin_dwarf_info_free(dw->info);
	rz_bin_dwarf_line_free(dw->line);
	rz_bin_dwarf_loclists_free(dw->loclists);
	rz_bin_dwarf_aranges_free(dw->aranges);
	free(dw);
}

RZ_API void rz_bin_dwarf_dump(
	RZ_BORROW RZ_NONNULL RzBinDWARF *dw,
	RZ_BORROW RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(dw && sb);
	if (dw->abbrev) {
		rz_core_bin_dwarf_abbrevs_dump(dw->abbrev, sb);
	}
	if (dw->info) {
		rz_bin_dwarf_debug_info_dump(dw->info, dw, sb);
	}
	if (dw->loclists) {
		rz_bin_dwarf_loclists_dump(dw->loclists, dw, sb);
	}
	if (dw->aranges) {
		rz_bin_dwarf_aranges_dump(dw->aranges, sb);
	}
	if (dw->rnglists) {
		rz_bin_dwarf_rnglists_dump(dw->rnglists, sb);
	}
	if (dw->line) {
		rz_bin_dwarf_line_units_dump(dw->line, sb);
	}
}
