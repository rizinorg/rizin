// SPDX-FileCopyrightText: 2021 smac89 <noblechuk5[at]web[dot]de>
// SPDX-License-Identifier: LPGL-3.0-only

#include "xex.h"

/**
 * \brief Initialize the main XEX header
 *
 * \param xex_bin The xex bin abstraction
 * \param buf The file buffer to read from
 */
static void xex_header_init(RzBinXex *xex_bin, RzBuffer *buf) {
	RzBinXexHeader *xex_header = xex_bin->xex_header;
	xex_header->module_flags = rz_buf_read_be32_at(buf, XEX_MODULE_OFFSET);
	xex_header->pe_data_offset = rz_buf_read_be32_at(buf, XEX_PE_DATA_OFFSET);
	xex_header->security_info_offset = rz_buf_read_be32_at(buf, XEX_SECURITY_INFO_OFFSET);
}

/**
 * \brief Initializes each optional header
 *
 * \param xex_bin The xex bin abstraction
 * \param buf The file buffer to read from
 * \param offset The offset of the optional header
 */
static void xex_opt_header_init(RzBinXex *xex_bin, RzBuffer *buf, ut32 offset) {
	// ut32 header_id = rz_buf_read_be32_at(buf, offset);
	// ut32 header_mask = 0;
	// ut32 header_data_size = 0;
	// offset += 0x4; /* move offset in preparation for reading the data/offset */
	// switch ((header_mask = (header_id & 0xFF))) {
	// case 0x01:
	// 	/* data is just in the next offset */
	// 	xex_opt_header->header_data = rz_buf_read_be64_at(buf, offset);
	// 	break;
	// case 0xFF:
	// 	/* 0xFF means the size is encoded in the data
	// 	TODO: verify this please */
	// 	header_data_size = 0xFF;

	// 	break;
	// default:
	// 	/* size in DWORDS (times by 0x4 to get real size) */
	// 	header_data_size = header_mask << 2;
	// }

	// switch (header_data_size) {
	// }
	RzBinXexOptHeader *xex_opt_header = RZ_NEW(RzBinXexOptHeader);
	xex_opt_header->header_id = rz_buf_read_be32_at(buf, offset);
	xex_opt_header->header_data = rz_buf_read_be64_at(buf, offset + 0x4);
	rz_list_append(xex_bin->opt_headers, xex_opt_header);
}

RzBinXexHeader *construct_header(RzBinXex *xex_bin, RzBuffer *buf) {
	rz_return_val_if_fail(xex_bin, NULL);
	if (!xex_bin->xex_header) {
		if ((xex_bin->xex_header = RZ_NEW(RzBinXexHeader))) {
			xex_header_init(xex_bin, buf);
			ut32 opt_header_count = rz_buf_read_be32_at(buf, XEX_OPT_HEADER_COUNT_OFFSET);
			ut32 offset = 1, count = opt_header_count;
			for (xex_bin->opt_headers = rz_list_new(); count--; offset++) {
				xex_opt_header_init(xex_bin, buf, offset * XEX_OPT_HEADER_BASE_OFFSET);
			}
			/* TODO: poplulate the opt headers with data (either here or as the need arises?) */
			return xex_bin->xex_header;
		}
		rz_return_val_if_reached(NULL);
	}
	return xex_bin->xex_header;
}

RzBinXex *xex_parse(RzBuffer *buf) {
	RzBinXex *xex_bin = NULL;
	xex_bin = RZ_NEW0(RzBinXex);
	return xex_bin;
}

void xex_destroy_bin(RzBinXex **bin_obj) {
	RzBinXex *xex_bin = NULL;
	if ((xex_bin = *bin_obj) != NULL) {
		if (xex_bin->opt_headers) {
			rz_list_free(xex_bin->opt_headers);
			xex_bin->opt_headers = NULL;
		}

		if (xex_bin->xex_header) {
			/* clear executable data(?) */
			rz_free(xex_bin->xex_header);
			xex_bin->xex_header = NULL;
		}
		rz_free(xex_bin);
		*bin_obj = NULL;
	}
}
