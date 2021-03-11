// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "luac_specs_54.h"

#define INNER_BUFFER_SIZE 256

RzBinInfo *info_54(RzBinFile *bf, st32 major, st32 minor) {
	ut8 work_buffer[INNER_BUFFER_SIZE];
	RzBinInfo *ret = NULL;

	st64 reat = rz_buf_read_at(bf->buf, 0, work_buffer, LUAC_54_HDRSIZE);
	if (reat != LUAC_54_HDRSIZE) {
		eprintf("Truncated Header\n");
		return NULL;
	}

	/* read header members from work buffer */
	ut8 luac_format = work_buffer[LUAC_54_FORMAT_OFFSET];
	ut8 instruction_size = work_buffer[LUAC_54_INSTRUCTION_SIZE_OFFSET];
	ut8 integer_size = work_buffer[LUAC_54_INTEGER_SIZE_OFFSET];
	ut8 number_size = work_buffer[LUAC_54_NUMBER_SIZE_OFFSET];
	LUA_INTEGER int_valid = luaLoadInteger(work_buffer + LUAC_54_INTEGER_VALID_OFFSET);
	LUA_NUMBER number_valid = luaLoadNumber(work_buffer + LUAC_54_NUMBER_VALID_OFFSET);

	/* Common Ret */
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = strdup(bf->file);
	ret->type = rz_str_newf("Lua %c.%c compiled file", major + '0', minor + '0');
	ret->bclass = strdup("Lua compiled file");
	ret->rclass = strdup("luac");
	ret->arch = strdup("luac");
	ret->machine = rz_str_newf("Lua %c.%c VM", major + '0', minor + '0');
	ret->os = strdup("any");
	ret->bits = 8;

	/* official format ? */
	if (luac_format != LUAC_54_FORMAT) {
		ret->compiler = strdup("Unofficial Lua Compiler");
		return ret;
	}
	ret->compiler = strdup("Official Lua Compiler");

	/* if LUAC_DATA checksum corrupted */
	if (memcmp(work_buffer + LUAC_54_LUAC_DATA_OFFSET,
		    LUAC_54_DATA,
		    LUAC_54_LUAC_DATA_SIZE) != 0) {
		eprintf("Corrupted Luac\n");
		return ret;
	}

	/* Check Size */
	if ((instruction_size != sizeof(LUA_INSTRUCTION)) ||
		(integer_size != sizeof(LUA_INTEGER)) ||
		(number_size != sizeof(LUA_NUMBER))) {
		eprintf("Size Definition not matched\n");
		return ret;
	}

	/* Check Loader -- endian */
	if (int_valid != LUAC_54_INT_VALIDATION) {
		eprintf("Integer Format Not Matched\n");
		return ret;
	}
	if (number_valid != LUAC_54_NUMBER_VALIDATION) {
		eprintf("Number Format Not Matched\n");
		return ret;
	}

	rz_buf_read_at(bf->buf, LUAC_FILENAME_OFFSET, work_buffer, INNER_BUFFER_SIZE);
	char *src_file = luaLoadString(work_buffer, INNER_BUFFER_SIZE);

	/* put source file info into GUID */
	ret->guid = strdup(src_file ? src_file : "stripped");
	free(src_file);

	return ret;
}