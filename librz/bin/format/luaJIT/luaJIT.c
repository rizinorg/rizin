// SPDX-FileCopyrightText: 2025 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Implementation of luaJIT compiled binary parser.
 *
 * Detection heuristic:
 * - Dword at offset 0xC (first chunk offset) must be >= 0x64
 * - Dword at offset 0x8 (should be 0, end of list marker in a valid table)
 *
 * Reference: https://github.com/nlitsme/AppleC4000/blob/master/loadgns.py
 */
#include "luaJIT.h"
#include <rz_util/rz_str.h>

ut64 LUAJIT_FLAG_END_OFFSET = UT64_MAX;

RZ_IPI bool luaJIT_check_buffer(RzBuffer *b) {
	rz_return_val_if_fail(b, false);

	if (rz_buf_size(b) > 4) {
		ut8 buf[LUAJIT_MAGIC_BYTE_SIZE];
		rz_buf_read_at(b, LUAJIT_MAGIC_OFFSET, buf, LUAJIT_MAGIC_BYTE_SIZE);
		return !memcpy(buf, LUAJIT_MAGIC, LUAJIT_MAGIC_BYTE_SIZE);
	}
	return false;
}

RZ_IPI ut64 luaJIT_decode_ULEB128(RzBuffer *buf, ut64 start, ut64 *value) {
	ut64 result = 0;
	ut32 shift = 0;
	ut64 off = start;
	ut8 byte;
	int count = 0;

	while (count++ < LUAJIT_ULEB128_MAX) {
		rz_buf_read8_at(buf, off, &byte);

		result |= ((ut64)(byte & 0x7F)) << shift;

		if (!(byte & 0x80)) {
			*value = result;
			return off;
		}
		shift += 7;
		off++;
	}
	return UT64_MAX;
}

static ut64 get_flag_end_offset(RzBuffer *buff) {
	ut64 off = luaJIT_parse_ULEB128(buff, NULL, LUAJIT_FLAG_OFFSET_AT);
	return off;
}

static bool check_big_endian(RzBuffer *buf) {
	if (!buf) {
		return false;
	}
	ut8 res;
	ut64 counter = LUAJIT_MAGIC_OFFSET;
	int flag_len = rz_buf_size(buf);
	while (counter < flag_len) {
		rz_buf_read8_at(buf, counter, &res);
		luaJIT_decode_ULEB128(buf, LUAJIT_FLAG_OFFSET_AT, (ut64*)res);
		if (((ut64)res & LUAJIT_BCDUMP_F_BE)) {
			return true;
		}
		counter++;
	}
	return false;
}

RZ_IPI ut64 luaJIT_parse_ULEB128(RzBuffer *r_buffer, RzBuffer *w_buffer, ut64 offset) {
	ut64 off = offset;
	ut8 *b = NULL;
	while (1) {
		rz_buf_read8_at(r_buffer, off, b);
		if (w_buffer) {
			rz_buf_append_bytes(w_buffer, (const ut8 *)b, 1);
		}
		if (!(*b & 0x80)) {
			LUAJIT_FLAG_END_OFFSET = off;
			return off;
		}
		off += 0x01;
	}
}

RZ_IPI RzBinInfo *luaJIT_header_parser(RzBinFile *bf, ut8 min) {
	RzBinInfo *info = NULL;
	RzBuffer *r_buffer;
	RzBuffer *w_buffer;

	w_buffer = RZ_NEW(RzBuffer);
	ut64 flag_end = 0x00;

	int bin_buf_size = bf->size;
	w_buffer = rz_buf_new_empty(0);
	w_buffer->readonly = 0;
	r_buffer = bf->buf;
	flag_end = get_flag_end_offset(r_buffer);

	// Header is not fixed size due to (ULEB128 Encoding)
	info->file = rz_str_dup(bf->file);
	info->type = rz_str_newf("LuaJIT 2.%c.x compiled file", min);
	info->bclass = rz_str_dup("LuaJIT compiled file");
	info->rclass = rz_str_dup("LuaJIT");
	info->arch = rz_str_dup("LuaJIT");
	info->cpu = rz_str_newf("2.%c.x", min);
	info->lang = "lua";
	info->os = rz_str_dup("any");
	// info->bits = 8;

	if (check_big_endian(w_buffer)) {
		info->big_endian = 1;
	}
	char *src_file = NULL;
	int name_len;

	free(w_buffer);
}

RZ_IPI bool luaJIT_load_buffer(RzBinFile *b, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	ut8 version;
	RzBinInfo *bin_info_hdr = NULL;

	rz_buf_read_at(buf, LUAJIT_VERSION_OFFSET, &version, sizeof(version));

	bin_info_hdr = RZ_NEW(LuaJITBinInfo);
	if (!bin_info_hdr) {
		return false;
	}

	switch (version) {
	case 0x01:
		bin_info_hdr = luaJIT_header_parser(b, version);
		break;
	case 0x02:
		break;
	default:
		RZ_LOG_ERROR("luaJIT %c not supported\n", version + '0');
		break;
	}
}