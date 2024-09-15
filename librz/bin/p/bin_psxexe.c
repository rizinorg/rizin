// SPDX-FileCopyrightText: 2015-2018 Dax89 <trogu.davide@gmail.com>
// SPDX-FileCopyrightText: 2015-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "../i/private.h"
#include "psxexe/psxexe.h"

static bool check_buffer(RzBuffer *b) {
	ut8 magic[PSXEXE_ID_LEN];
	if (rz_buf_read_at(b, 0, magic, sizeof(magic)) == PSXEXE_ID_LEN) {
		return !memcmp(magic, PSXEXE_ID, PSXEXE_ID_LEN);
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	return check_buffer(b);
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;
	psxexe_header psxheader;

	if (rz_buf_read_at(bf->buf, 0, (ut8 *)&psxheader, sizeof(psxexe_header)) < sizeof(psxexe_header)) {
		RZ_LOG_ERROR("Truncated Header\n");
		return NULL;
	}

	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}

	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("Sony PlayStation 1 Executable");
	ret->machine = rz_str_dup("Sony PlayStation 1");
	ret->os = rz_str_dup("psx");
	ret->arch = rz_str_dup("mips");
	ret->bits = 32;
	ret->has_va = true;
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret = NULL;
	RzBinSection *sect = NULL;
	psxexe_header psxheader;
	ut64 sz = 0;

	if (!(ret = rz_pvector_new(NULL))) {
		return NULL;
	}

	if (!(sect = RZ_NEW0(RzBinSection))) {
		rz_pvector_free(ret);
		return NULL;
	}

	if (rz_buf_fread_at(bf->buf, 0, (ut8 *)&psxheader, "8c17i", 1) < sizeof(psxexe_header)) {
		RZ_LOG_ERROR("Truncated Header\n");
		free(sect);
		rz_pvector_free(ret);
		return NULL;
	}

	sz = rz_buf_size(bf->buf);

	sect->name = rz_str_dup("TEXT");
	sect->paddr = PSXEXE_TEXTSECTION_OFFSET;
	sect->size = sz - PSXEXE_TEXTSECTION_OFFSET;
	sect->vaddr = psxheader.t_addr;
	sect->vsize = psxheader.t_size;
	sect->perm = RZ_PERM_RX;
	sect->has_strings = true;

	rz_pvector_push(ret, sect);
	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret = NULL;
	RzBinAddr *addr = NULL;
	psxexe_header psxheader;

	if (!(ret = rz_pvector_new(NULL))) {
		return NULL;
	}

	if (!(addr = RZ_NEW0(RzBinAddr))) {
		rz_pvector_free(ret);
		return NULL;
	}

	if (rz_buf_fread_at(bf->buf, 0, (ut8 *)&psxheader, "8c17i", 1) < sizeof(psxexe_header)) {
		RZ_LOG_ERROR("Truncated Header\n");
		rz_pvector_free(ret);
		free(addr);
		return NULL;
	}

	addr->paddr = (psxheader.pc0 - psxheader.t_addr) + PSXEXE_TEXTSECTION_OFFSET;
	addr->vaddr = psxheader.pc0;

	rz_pvector_push(ret, addr);
	return ret;
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	RzBinStringSearchOpt opt;
	rz_bin_string_search_opt_init(&opt);
	// we only search strings with a minimum length of 20 bytes.
	opt.mode = RZ_BIN_STRING_SEARCH_MODE_RAW_BINARY;
	opt.min_length = 20;
	return rz_bin_file_strings(bf, &opt);
}

RzBinPlugin rz_bin_plugin_psxexe = {
	.name = "psxexe",
	.desc = "Sony PlayStation 1 Executable",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.info = &info,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.entries = &entries,
	.strings = &strings,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_psxexe,
	.version = RZ_VERSION
};
#endif
