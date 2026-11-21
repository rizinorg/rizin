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

static bool psxexe_parse_header(RzBuffer *buf, psxexe_header *hdr) {
	rz_return_val_if_fail(buf && hdr, false);

	ut64 offset = 0;
	return rz_buf_read_offset(buf, &offset, hdr->id, sizeof(hdr->id)) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->text) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->data) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->pc0) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->gp0) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->t_addr) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->t_size) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->d_addr) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->d_size) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->b_addr) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->b_size) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->S_addr) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->S_size) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->SavedSP) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->SavedFP) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->SavedGP) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->SavedRA) &&
		rz_buf_read_le32_offset(buf, &offset, &hdr->SavedS0);
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	if (!check_buffer(b)) {
		return false;
	}

	psxexe_header *hdr = RZ_NEW0(psxexe_header);
	if (!hdr) {
		return false;
	}
	if (!psxexe_parse_header(b, hdr)) {
		free(hdr);
		return false;
	}

	obj->bin_obj = hdr;
	return true;
}

static void destroy(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return;
	}
	RZ_FREE(bf->o->bin_obj);
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
	ret->cpu = strdup("mips3");
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

static RzStructuredData *psxexe_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	const psxexe_header *psxheader = bf->o->bin_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *psx = rz_structured_data_map_add_map(info, "psxexe");
	if (!psx) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_string_n(psx, "id", (const char *)psxheader->id, sizeof(psxheader->id));
	rz_structured_data_map_add_unsigned(psx, "text", psxheader->text, true);
	rz_structured_data_map_add_unsigned(psx, "data", psxheader->data, true);
	rz_structured_data_map_add_unsigned(psx, "pc0", psxheader->pc0, true);
	rz_structured_data_map_add_unsigned(psx, "gp0", psxheader->gp0, true);
	rz_structured_data_map_add_unsigned(psx, "t_addr", psxheader->t_addr, true);
	rz_structured_data_map_add_unsigned(psx, "t_size", psxheader->t_size, true);
	rz_structured_data_map_add_unsigned(psx, "d_addr", psxheader->d_addr, true);
	rz_structured_data_map_add_unsigned(psx, "d_size", psxheader->d_size, true);
	rz_structured_data_map_add_unsigned(psx, "b_addr", psxheader->b_addr, true);
	rz_structured_data_map_add_unsigned(psx, "b_size", psxheader->b_size, true);
	rz_structured_data_map_add_unsigned(psx, "s_addr", psxheader->S_addr, true);
	rz_structured_data_map_add_unsigned(psx, "s_size", psxheader->S_size, true);
	rz_structured_data_map_add_unsigned(psx, "saved_sp", psxheader->SavedSP, true);
	rz_structured_data_map_add_unsigned(psx, "saved_fp", psxheader->SavedFP, true);
	rz_structured_data_map_add_unsigned(psx, "saved_gp", psxheader->SavedGP, true);
	rz_structured_data_map_add_unsigned(psx, "saved_ra", psxheader->SavedRA, true);
	rz_structured_data_map_add_unsigned(psx, "saved_s0", psxheader->SavedS0, true);

	return info;
}

RzBinPlugin rz_bin_plugin_psxexe = {
	.name = "psxexe",
	.desc = "Sony PlayStation 1 executable",
	.license = "LGPL3",
	.author = "Dax89",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.info = &info,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.entries = &entries,
	.strings = &strings,
	.bin_structure = &psxexe_structure,
	.destroy = &destroy,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_psxexe,
	.version = RZ_VERSION
};
#endif
