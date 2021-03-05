// SPDX-License-Identifier: LGPL-3.0-only

#include "luac_54.h"

#define INNER_BUFFER_SIZE 256

RzBinInfo *info_54(RzBinFile *bf, int major, int minor) {
	ut8 work_buffer[INNER_BUFFER_SIZE];

	RzBinInfo *ret = NULL;
	luacHdr54 hdr;
	memset(&hdr, 0, LUAC_HDR_SIZE_54);

	int reat = rz_buf_read_at(bf->buf, 0, (ut8 *)&hdr, LUAC_HDR_SIZE_54);
	if (reat != LUAC_HDR_SIZE_54) {
		eprintf("Truncated Header\n");
		return NULL;
	}

	/* Common Ret */
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = strdup(bf->file);
	ret->type = rz_str_newf("Lua %c.%c compiled file", major + '0', minor + '0');
	ret->bclass = strdup("Lua compiled file");
	ret->rclass = strdup("luac");
	ret->arch = strdup("luac");
	ret->machine = rz_str_newf("Lua %c.%c VM ", major + '0', minor + '0');
	ret->os = strdup("any");
	ret->bits = 8;

	/* official format ? */
	if (hdr.format != 0x00) {
		ret->compiler = strdup("Unofficial Lua Compiler");
		return ret;
	}
	ret->compiler = strdup("Official Lua Compiler");

	/* if LUAC_DATA checksum corrupted */
	if (memcmp(hdr.luac_data, LUAC_DATA, sizeof(hdr.luac_data)) != 0) {
		eprintf("Corrupted Luac\n");
		return ret;
	}

	/* Check Size */
	if ((hdr.instruction_size != sizeof(LUA_INSTRUCTION)) ||
		(hdr.integer_size != sizeof(LUA_INTEGER)) ||
		(hdr.number_size != sizeof(LUA_NUMBER))) {
		eprintf("Size Definition not matched\n");
		return ret;
	}

	/* Check Loader -- endian */
	if (luaLoadInteger(hdr.integer_valid_data) != LUAC_INT_VALIDATION) {
		eprintf("Integer Format Not Matched\n");
		return ret;
	}
	if (luaLoadNumber(hdr.number_valid_data) != LUAC_NUMBER_VALIDATION) {
		eprintf("Number Format Not Matched\n");
		return ret;
	}

	rz_buf_read_at(bf->buf, LUAC_HDR_SIZE_54, work_buffer, INNER_BUFFER_SIZE);
	char *src_file = luaLoadString(work_buffer);

	/* put source file info into GUID */
	if (src_file == NULL) {
		ret->guid = strdup("stripped");
		return ret;
	}
	ret->guid = strdup(src_file);
	free(src_file);

	return ret;
}