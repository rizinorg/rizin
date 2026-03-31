// SPDX-FileCopyrightText: 2008-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_hash.h>
#include "pe.h"
#include <time.h>

PE_DWord PE_(bin_pe_rva_to_paddr)(RzBinPEObj *bin, PE_DWord rva) {
	PE_DWord section_base;
	int i, section_size;
	for (i = 0; i < bin->num_sections; i++) {
		section_base = bin->sections[i].vaddr;
		section_size = bin->sections[i].vsize;
		if (rva >= section_base && rva < section_base + section_size) {
			return bin->sections[i].paddr + (rva - section_base);
		}
	}
	return rva;
}

PE_DWord PE_(bin_pe_rva_to_va)(RzBinPEObj *bin, PE_DWord rva) {
	return PE_(rz_bin_pe_get_image_base)(bin) + rva;
}

PE_DWord PE_(bin_pe_va_to_rva)(RzBinPEObj *bin, PE_DWord va) {
	ut64 imageBase = PE_(rz_bin_pe_get_image_base)(bin);
	if (va < imageBase) {
		return va;
	}
	return va - imageBase;
}

static int bin_pe_init(RzBinPEObj *bin) {
	bin->dos_header = NULL;
	bin->nt_headers = NULL;
	bin->section_header = NULL;
	bin->export_directory = NULL;
	bin->import_directory = NULL;
	bin->resource_directory = NULL;
	bin->security_directory = NULL;
	bin->delay_import_directory = NULL;
	bin->optional_header = NULL;
	bin->data_directory = NULL;
	bin->big_endian = 0;
	bin->cms = NULL;
	bin->spcinfo = NULL;
	if (!PE_(bin_pe_init_hdr)(bin)) {
		RZ_LOG_ERROR("File is not PE\n");
		return false;
	}
	if (!PE_(bin_pe_init_sections)(bin)) {
		RZ_LOG_ERROR("Cannot initialize sections\n");
		return false;
	}
	bin->sections = PE_(rz_bin_pe_get_sections)(bin);
	PE_(bin_pe_init_imports)(bin);
	PE_(bin_pe_init_exports)(bin);
	PE_(bin_pe_init_resource)(bin);
	PE_(bin_pe_init_security)(bin);
	PE_(bin_pe_init_relocs)(bin);

	bin->big_endian = PE_(rz_bin_pe_is_big_endian)(bin);

	PE_(bin_pe_init_rich_info)(bin);
	PE_(bin_pe_init_tls)(bin);
	PE_(bin_pe_init_clr)(bin);
	PE_(bin_pe_init_overlay)(bin);
	PE_(bin_pe_parse_resource)(bin);
	return true;
}

void *PE_(rz_bin_pe_free)(RzBinPEObj *bin) {
	if (!bin) {
		return NULL;
	}
	free(bin->dos_header);
	free(bin->nt_headers);
	free(bin->section_header);
	free(bin->export_directory);
	free(bin->import_directory);
	free(bin->resource_directory);
	PE_(free_security_directory)(bin->security_directory);
	free(bin->delay_import_directory);
	bin_pe_dotnet_destroy_clr(bin->clr);
	free(bin->tls_directory);
	free(bin->sections);
	free(bin->authentihash);
	rz_list_free(bin->rich_entries);
	rz_list_free(bin->resources);
	rz_pkcs7_cms_free(bin->cms);
	rz_pkcs7_spcinfo_free(bin->spcinfo);
	rz_hash_free(bin->hash);
	rz_buf_free(bin->b);
	bin->b = NULL;
	free(bin);
	return NULL;
}

RzBinPEObj *PE_(rz_bin_pe_new_buf)(RzBuffer *buf, bool verbose) {
	RzBinPEObj *bin = RZ_NEW0(RzBinPEObj);
	if (!bin) {
		return NULL;
	}
	bin->kv = sdb_new0();
	bin->b = rz_buf_ref(buf);
	bin->verbose = verbose;
	bin->size = rz_buf_size(buf);
	bin->hash = rz_hash_new();
	if (!bin_pe_init(bin)) {
		return PE_(rz_bin_pe_free)(bin);
	}
	return bin;
}
