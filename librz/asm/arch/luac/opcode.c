// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "opcode.h"

LuaInstruction lua_build_instruction(const ut8 *buf) {
	LuaInstruction ret = 0;
	ret |= buf[3] << 24;
	ret |= buf[2] << 16;
	ret |= buf[1] << 8;
	ret |= buf[0];
	return ret;
}

bool free_lua_opnames(LuaOpNameList list){
	if (list != NULL){
		RZ_FREE(list);
		return true;
	}
	return false;
}

/* formatted strings for asm_buf */
char *luaop_new_str_3arg(char *opname, int a, int b, int c, char *mark){
	char *comment_mark;
	char *asm_string;

	comment_mark = mark ? mark : "";

        asm_string = rz_str_newf(
                "%s R[%d] R[%d] R[%d]%s",
		opname,
                a, b, c, comment_mark);

	return asm_string;
}

char *luaop_new_str_2arg(char *opname, int a, int b, char *mark){
        char *comment_mark;
        char *asm_string;

        comment_mark = mark ? mark : "";

        asm_string = rz_str_newf(
                "%s R[%d] R[%d]%s",
                opname,
                a, b, comment_mark);

        return asm_string;

}

char *luaop_new_str_1arg(char *opname, int a, char *mark){
        char *comment_mark;
        char *asm_string;

        comment_mark = mark ? mark : "";

        asm_string = rz_str_newf(
                "%s R[%d]%s",
                opname,
                a, comment_mark);

        return asm_string;
}

char *luaop_new_str_3arg_ex(char *opname, int a, int b, int c, char *mark, char *prefix_a, char *prefix_b, char *prefix_c){
        char *comment_mark;
        char *asm_string;

        comment_mark = mark ? mark : "";

        asm_string = rz_str_newf(
                "%s %s[%d] %s[%d] %s[%d]%s",
                opname,
		prefix_a, a,
		prefix_b, b,
		prefix_c, c,
		comment_mark);

        return asm_string;
}

char *luaop_new_str_2arg_ex(char *opname, int a, int b, char *mark, char *prefix_a, char *prefix_b){
        char *comment_mark;
        char *asm_string;

        comment_mark = mark ? mark : "";

        asm_string = rz_str_newf(
                "%s %s[%d] %s[%d]%s",
                opname,
                prefix_a, a,
                prefix_b, b,
                comment_mark);

        return asm_string;
}

char *luaop_new_str_1arg_ex(char *opname, int a, char *mark, char *prefix_a){
        char *comment_mark;
        char *asm_string;

        comment_mark = mark ? mark : "";

        asm_string = rz_str_newf(
                "%s %s[%d]%s",
                opname,
                prefix_a, a,
                comment_mark);

        return asm_string;
}