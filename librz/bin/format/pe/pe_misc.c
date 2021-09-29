// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pe.h"

bool rz_bin_pe_buffer_read_le8(RzBuffer *buf, ut64 *offset, ut8 *result) {
	rz_return_val_if_fail(buf && offset && result, false);
	if (!rz_buf_read8_at(buf, *offset, result)) {
		return false;
	}
	*offset += 1;
	return true;
}

bool rz_bin_pe_buffer_read_le16(RzBuffer *buf, ut64 *offset, ut16 *result) {
	rz_return_val_if_fail(buf && offset && result, false);
	if (!rz_buf_read_le16_at(buf, *offset, result)) {
		return false;
	}
	*offset += 2;
	return true;
}

bool rz_bin_pe_buffer_read_le32(RzBuffer *buf, ut64 *offset, ut32 *result) {
	rz_return_val_if_fail(buf && offset && result, false);
	if (!rz_buf_read_le32_at(buf, *offset, result)) {
		return false;
	}
	*offset += 4;
	return true;
}

bool rz_bin_pe_buffer_read_le64(RzBuffer *buf, ut64 *offset, ut64 *result) {
	rz_return_val_if_fail(buf && offset && result, false);
	if (!rz_buf_read_le64_at(buf, *offset, result)) {
		return false;
	}
	*offset += 8;
	return true;
}
