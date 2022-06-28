// SPDX-FileCopyrightText: 2008-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pe.h"

struct SCV_NB10_HEADER;
typedef struct {
	ut8 signature[4];
	ut32 offset;
	ut32 timestamp;
	ut32 age;
	ut8 *file_name;
	void (*free)(struct SCV_NB10_HEADER *cv_nb10_header);
} SCV_NB10_HEADER;

typedef struct {
	ut32 data1;
	ut16 data2;
	ut16 data3;
	ut8 data4[8];
} SGUID;

struct SCV_RSDS_HEADER;
typedef struct {
	ut8 signature[4];
	SGUID guid;
	ut32 age;
	ut8 *file_name;
	void (*free)(struct SCV_RSDS_HEADER *rsds_hdr);
} SCV_RSDS_HEADER;

static void free_rsdr_hdr(SCV_RSDS_HEADER *rsds_hdr) {
	RZ_FREE(rsds_hdr->file_name);
}

static void init_rsdr_hdr(SCV_RSDS_HEADER *rsds_hdr) {
	memset(rsds_hdr, 0, sizeof(SCV_RSDS_HEADER));
	rsds_hdr->free = (void (*)(struct SCV_RSDS_HEADER *))free_rsdr_hdr;
}

static void free_cv_nb10_header(SCV_NB10_HEADER *cv_nb10_header) {
	RZ_FREE(cv_nb10_header->file_name);
}

static void init_cv_nb10_header(SCV_NB10_HEADER *cv_nb10_header) {
	memset(cv_nb10_header, 0, sizeof(SCV_NB10_HEADER));
	cv_nb10_header->free = (void (*)(struct SCV_NB10_HEADER *))free_cv_nb10_header;
}

static bool get_rsds(ut8 *dbg_data, int dbg_data_len, SCV_RSDS_HEADER *res) {
	const int rsds_sz = 4 + sizeof(SGUID) + 4;
	if (dbg_data_len < rsds_sz) {
		return false;
	}
	memcpy(res, dbg_data, rsds_sz);
	res->file_name = (ut8 *)strdup((const char *)dbg_data + rsds_sz);
	return true;
}

static void get_nb10(ut8 *dbg_data, int dbg_data_len, SCV_NB10_HEADER *res) {
	const int nb10sz = 16;
	if (dbg_data_len < nb10sz) {
		return;
	}
	memcpy(res, dbg_data, nb10sz);
	res->file_name = (ut8 *)strdup((const char *)dbg_data + nb10sz);
}

static int get_debug_info(RzBinPEObj *bin, PE_(image_debug_directory_entry) * dbg_dir_entry, ut8 *dbg_data, int dbg_data_len, SDebugInfo *res) {
#define SIZEOF_FILE_NAME 255
	int i = 0;
	const char *dbgname;
	if (!dbg_data) {
		return 0;
	}
	switch (dbg_dir_entry->Type) {
	case IMAGE_DEBUG_TYPE_CODEVIEW:
		if (!strncmp((char *)dbg_data, "RSDS", 4)) {
			SCV_RSDS_HEADER rsds_hdr;
			init_rsdr_hdr(&rsds_hdr);
			if (!get_rsds(dbg_data, dbg_data_len, &rsds_hdr)) {
				RZ_LOG_INFO("Cannot read PE debug info\n");
				return 0;
			}
			snprintf(res->guidstr, GUIDSTR_LEN,
				"%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x%x",
				rsds_hdr.guid.data1,
				rsds_hdr.guid.data2,
				rsds_hdr.guid.data3,
				rsds_hdr.guid.data4[0],
				rsds_hdr.guid.data4[1],
				rsds_hdr.guid.data4[2],
				rsds_hdr.guid.data4[3],
				rsds_hdr.guid.data4[4],
				rsds_hdr.guid.data4[5],
				rsds_hdr.guid.data4[6],
				rsds_hdr.guid.data4[7],
				rsds_hdr.age);
			dbgname = (char *)rsds_hdr.file_name;
			strncpy(res->file_name, (const char *)dbgname, sizeof(res->file_name));
			res->file_name[sizeof(res->file_name) - 1] = 0;
			rsds_hdr.free((struct SCV_RSDS_HEADER *)&rsds_hdr);
		} else if (strncmp((const char *)dbg_data, "NB10", 4) == 0) {
			if (dbg_data_len < 20) {
				RZ_LOG_ERROR("Truncated NB10 entry, not enough data to parse\n");
				return 0;
			}
			SCV_NB10_HEADER nb10_hdr = { { 0 } };
			init_cv_nb10_header(&nb10_hdr);
			get_nb10(dbg_data, dbg_data_len, &nb10_hdr);
			snprintf(res->guidstr, sizeof(res->guidstr),
				"%x%x", nb10_hdr.timestamp, nb10_hdr.age);
			res->file_name[0] = 0;
			if (nb10_hdr.file_name) {
				strncpy(res->file_name, (const char *)nb10_hdr.file_name, sizeof(res->file_name) - 1);
			}
			res->file_name[sizeof(res->file_name) - 1] = 0;
			nb10_hdr.free((struct SCV_NB10_HEADER *)&nb10_hdr);
		} else {
			RZ_LOG_INFO("CodeView section not NB10 or RSDS\n");
			return 0;
		}
		break;
	default:
		// RZ_LOG_INFO("get_debug_info(): not supported type\n");
		return 0;
	}

	while (i < 33) {
		res->guidstr[i] = toupper((ut8)res->guidstr[i]);
		i++;
	}

	return 1;
}

static int read_image_debug_directory_entry(RzBuffer *b, ut64 addr, PE_(image_debug_directory_entry) * entry) {
	st64 o_addr = rz_buf_seek(b, 0, RZ_BUF_CUR);
	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return -1;
	}
	ut8 buf[sizeof(PE_(image_debug_directory_entry))];
	rz_buf_read(b, buf, sizeof(buf));
	PE_READ_STRUCT_FIELD(entry, PE_(image_debug_directory_entry), Characteristics, 32);
	PE_READ_STRUCT_FIELD(entry, PE_(image_debug_directory_entry), TimeDateStamp, 32);
	PE_READ_STRUCT_FIELD(entry, PE_(image_debug_directory_entry), MajorVersion, 16);
	PE_READ_STRUCT_FIELD(entry, PE_(image_debug_directory_entry), MinorVersion, 16);
	PE_READ_STRUCT_FIELD(entry, PE_(image_debug_directory_entry), Type, 32);
	PE_READ_STRUCT_FIELD(entry, PE_(image_debug_directory_entry), SizeOfData, 32);
	PE_READ_STRUCT_FIELD(entry, PE_(image_debug_directory_entry), AddressOfRawData, 32);
	PE_READ_STRUCT_FIELD(entry, PE_(image_debug_directory_entry), PointerToRawData, 32);
	rz_buf_seek(b, o_addr, RZ_BUF_SET);
	return sizeof(PE_(image_debug_directory_entry));
}

int PE_(rz_bin_pe_get_debug_data)(RzBinPEObj *bin, SDebugInfo *res) {
	PE_(image_debug_directory_entry)
	img_dbg_dir_entry = { 0 };
	PE_(image_data_directory) *dbg_dir = NULL;
	PE_DWord dbg_dir_offset;
	ut8 *dbg_data = 0;
	int result = 0;
	if (!bin) {
		return 0;
	}
	dbg_dir = &bin->nt_headers->optional_header.DataDirectory[6 /*IMAGE_DIRECTORY_ENTRY_DEBUG*/];
	dbg_dir_offset = PE_(bin_pe_rva_to_paddr)(bin, dbg_dir->VirtualAddress);
	if ((int)dbg_dir_offset < 0 || dbg_dir_offset >= bin->size) {
		return false;
	}
	if (dbg_dir_offset >= rz_buf_size(bin->b)) {
		return false;
	}
	read_image_debug_directory_entry(bin->b, dbg_dir_offset, &img_dbg_dir_entry);
	if ((rz_buf_size(bin->b) - dbg_dir_offset) < sizeof(PE_(image_debug_directory_entry))) {
		return false;
	}
	ut32 dbg_data_poff = RZ_MIN(img_dbg_dir_entry.PointerToRawData, rz_buf_size(bin->b));
	int dbg_data_len = RZ_MIN(img_dbg_dir_entry.SizeOfData, rz_buf_size(bin->b) - dbg_data_poff);
	if (dbg_data_len < 1) {
		return false;
	}
	dbg_data = (ut8 *)calloc(1, dbg_data_len + 1);
	if (dbg_data) {
		rz_buf_read_at(bin->b, dbg_data_poff, dbg_data, dbg_data_len);
		result = get_debug_info(bin, &img_dbg_dir_entry, dbg_data, dbg_data_len, res);
		RZ_FREE(dbg_data);
	}
	return result;
}
