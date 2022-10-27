// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2008-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pe.h"

#define SGUID_SIZE                (16)
#define SCV_NB10_HEADER_MIN_SIZE  (16) // does not include the size of file_name because is dynamic
#define SCV_RSDS_HEADER_MIN_SIZE  (8 + SGUID_SIZE) // does not include the size of file_name because is dynamic
#define PE_DEBUG_INFO_NAME_LEN(x) RZ_MIN(DBG_FILE_NAME_LEN - 1, x)

typedef struct sguid_t {
	ut32 data1;
	ut16 data2;
	ut16 data3;
	ut8 data4[8];
} SGUID;

typedef struct scv_nb10_header_t {
	ut8 signature[4];
	ut32 offset;
	ut32 timestamp;
	ut32 age;
	char file_name[DBG_FILE_NAME_LEN];
} ScvNb10Header;

typedef struct scv_rsds_header_t {
	ut8 signature[4];
	SGUID guid;
	ut32 age;
	char file_name[DBG_FILE_NAME_LEN];
} ScvRsdsHeader;

static bool scv_rsds_header_init(RzBuffer *buf, ut64 base_offset, size_t size, ScvRsdsHeader *res) {
	if (size < SCV_RSDS_HEADER_MIN_SIZE) {
		return false;
	}
	ut64 offset = base_offset;
	return rz_buf_read_offset(buf, &offset, res->signature, sizeof(res->signature)) &&
		rz_buf_read_le32_offset(buf, &offset, &res->guid.data1) &&
		rz_buf_read_le16_offset(buf, &offset, &res->guid.data2) &&
		rz_buf_read_le16_offset(buf, &offset, &res->guid.data3) &&
		rz_buf_read_offset(buf, &offset, res->guid.data4, sizeof(res->guid.data4)) &&
		rz_buf_read_le32_offset(buf, &offset, &res->age) &&
		rz_buf_read_offset(buf, &offset, (ut8 *)res->file_name, PE_DEBUG_INFO_NAME_LEN(size - offset));
}

static bool scv_nb10_header_init(RzBuffer *buf, ut64 base_offset, size_t size, ScvNb10Header *res) {
	if (size < SCV_NB10_HEADER_MIN_SIZE) {
		return false;
	}

	ut64 offset = base_offset;
	return rz_buf_read_offset(buf, &offset, res->signature, sizeof(res->signature)) &&
		rz_buf_read_le32_offset(buf, &offset, &res->offset) &&
		rz_buf_read_le32_offset(buf, &offset, &res->timestamp) &&
		rz_buf_read_le32_offset(buf, &offset, &res->age) &&
		rz_buf_read_offset(buf, &offset, (ut8 *)res->file_name, PE_DEBUG_INFO_NAME_LEN(size - offset));
}

static bool read_pe_debug_info(RzBinPEObj *bin, PE_(image_debug_directory_entry) * entry, RzBuffer *buffer, ut64 offset, size_t size, SDebugInfo *res) {
	char magic[4] = { 0 };
	if (!buffer || rz_buf_read_at(buffer, offset, (ut8 *)magic, sizeof(magic)) != sizeof(magic)) {
		return false;
	}

	if (entry->Type != IMAGE_DEBUG_TYPE_CODEVIEW) {
		// RZ_LOG_INFO("read_pe_debug_info: not supported type\n");
		return false;
	}

	if (!strncmp(magic, "RSDS", 4)) {
		ScvRsdsHeader rsds_hdr = { 0 };
		if (!scv_rsds_header_init(buffer, offset, size, &rsds_hdr)) {
			RZ_LOG_INFO("bin: pe: Cannot read PE debug info\n");
			return false;
		}
		rz_strf(res->guidstr,
			"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
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
		rz_strf(res->file_name, "%s", rsds_hdr.file_name);
		return true;
	} else if (!strncmp(magic, "NB10", 4)) {
		if (size < 20) {
			RZ_LOG_ERROR("bin: pe: Truncated NB10 entry, not enough data to parse\n");
			return false;
		}
		ScvNb10Header nb10_hdr = { 0 };
		if (!scv_nb10_header_init(buffer, offset, size, &nb10_hdr)) {
			RZ_LOG_INFO("bin: pe: Cannot read PE NB10 entry\n");
			return false;
		}
		rz_strf(res->guidstr, "%X%X", nb10_hdr.timestamp, nb10_hdr.age);
		rz_strf(res->file_name, "%s", nb10_hdr.file_name);
		return true;
	}

	RZ_LOG_INFO("bin: pe: CodeView section not NB10 or RSDS\n");
	return false;
}

static int read_image_debug_directory_entry(RzBuffer *b, ut64 addr, PE_(image_debug_directory_entry) * entry) {
	st64 o_addr = rz_buf_tell(b);
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

bool PE_(rz_bin_pe_get_debug_data)(RzBinPEObj *bin, SDebugInfo *res) {
	PE_(image_debug_directory_entry)
	img_dbg_dir_entry = { 0 };
	PE_(image_data_directory) *dbg_dir = NULL;
	PE_DWord dbg_dir_offset;
	if (!bin) {
		return false;
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
	st64 dbg_data_len = RZ_MIN(img_dbg_dir_entry.SizeOfData, rz_buf_size(bin->b) - dbg_data_poff);
	if (dbg_data_len < 1) {
		return false;
	}

	return read_pe_debug_info(bin, &img_dbg_dir_entry, bin->b, dbg_data_poff, dbg_data_len, res);
}
