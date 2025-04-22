// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "lua_arch.h"

LuaInstruction lua_build_instruction(const ut8 *buf) {
	LuaInstruction ret = 0;
	ret |= buf[3] << 24;
	ret |= buf[2] << 16;
	ret |= buf[1] << 8;
	ret |= buf[0];
	return ret;
}

void lua_set_instruction(LuaInstruction instruction, ut8 *data) {
	data[3] = instruction >> 24;
	data[2] = instruction >> 16;
	data[1] = instruction >> 8;
	data[0] = instruction >> 0;
}

bool free_lua_opnames(LuaOpNameList list) {
	if (list != NULL) {
		RZ_FREE(list);
		return true;
	}
	return false;
}

/* formatted strings for asm_buf */
char *luaop_new_str_3arg(char *opname, int a, int b, int c) {
	char *asm_string;

	asm_string = rz_str_newf(
		"%s %d %d %d",
		opname,
		a, b, c);

	return asm_string;
}

char *luaop_new_str_2arg(char *opname, int a, int b) {
	char *asm_string;

	asm_string = rz_str_newf(
		"%s %d %d",
		opname,
		a, b);

	return asm_string;
}

char *luaop_new_str_1arg(char *opname, int a) {
	char *asm_string;

	asm_string = rz_str_newf(
		"%s %d",
		opname,
		a);

	return asm_string;
}

/* For the k flag */
char *luaop_new_str_3arg_ex(char *opname, int a, int b, int c, int isk) {
	char *asm_string;

	asm_string = rz_str_newf(
		"%s %d %d %d %d",
		opname,
		a, b, c, isk);

	return asm_string;
}

char *luaop_new_str_2arg_ex(char *opname, int a, int b, int isk) {
	char *asm_string;

	asm_string = rz_str_newf(
		"%s %d %d %d",
		opname,
		a, b, isk);

	return asm_string;
}

char *luaop_new_str_1arg_ex(char *opname, int a, int isk) {
	char *asm_string;

	asm_string = rz_str_newf(
		"%s %d %d",
		opname,
		a, isk);

	return asm_string;
}

int lua_load_next_arg_start(const char *raw_string, char *recv_buf) {
	if (!raw_string) {
		return 0;
	}

	const char *arg_start = NULL;
	const char *arg_end = NULL;
	int arg_len = 0;

	/* locate the start point */
	arg_start = rz_str_trim_head_ro(raw_string);
	if (strlen(arg_start) == 0) {
		return 0;
	}

	arg_end = strchr(arg_start, ' ');
	if (arg_end == NULL) {
		/* is last arg */
		arg_len = strlen(arg_start);
	} else {
		arg_len = arg_end - arg_start;
	}

	/* Set NUL */
	memcpy(recv_buf, arg_start, arg_len);
	recv_buf[arg_len] = 0x00;

	/* Calculate offset */
	return arg_start - raw_string + arg_len;
}

bool lua_is_valid_num_value_string(const char *str) {
	if (!rz_is_valid_input_num_value(NULL, str)) {
		RZ_LOG_ERROR("assembler: lua: %s is not a valid number argument\n", str);
		return false;
	}
	return true;
}

int lua_convert_str_to_num(const char *str) {
	return strtoll(str, NULL, 0);
}