// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_51.h"

static const char *op_names[] = {
	"move",
	"loadk",
	"loadbool",
	"loadnil",
	"getupval",
	"getglobal",
	"gettable",
	"setglobal",
	"setupval",
	"settable",
	"newtable",
	"self",
	"add",
	"sub",
	"mul",
	"div",
	"mod",
	"pow",
	"unm",
	"not",
	"len",
	"concat",
	"jmp",
	"eq",
	"lt",
	"le",
	"test",
	"testset",
	"call",
	"tailcall",
	"return",
	"forloop",
	"forprep",
	"tforloop",
	"setlist",
	"close",
	"closure",
	"vararg"
};

static ut8 OP_SHUFFLE_ARRAY[2][LUA_NUM_OPCODES51] = {
	{
		///> VANILA, OPENWRT
		0, ///< move
		1, ///< loadk
		2, ///< loadbool
		3, ///< loadnil
		4, ///< getupval
		5, ///< getglobal
		6, ///< gettable
		7, ///< setglobal
		8, ///< setupval
		9, ///< settable
		10, ///< newtable
		11, ///< self
		12, ///< add
		13, ///< sub
		14, ///< mul
		15, ///< div
		16, ///< mod
		17, ///< pow
		18, ///< unm
		19, ///< not
		20, ///< len
		21, ///< concat
		22, ///< jmp
		23, ///< eq
		24, ///< lt
		25, ///< le
		26, ///< test
		27, ///< testset
		28, ///< call
		29, ///< tailcall
		30, ///< return
		31, ///< forloop
		32, ///< forprep
		33, ///< tforloop
		34, ///< setlist
		35, ///< close
		36, ///< closure
		37 ///< vararg
	},
	{
		///< TPLINK
		6, ///< gettable
		5, ///< getglobal
		7, ///< setglobal
		8, ///< setupval
		9, ///< settable
		10, ///< newtable
		11, ///< self
		3, ///< loadnil
		1, ///< loadk
		2, ///< loadbool
		4, ///< getupval
		24, ///< lt
		25, ///< le
		23, ///< eq
		15, ///< div
		14, ///< mul
		13, ///< sub
		12, ///< add
		16, ///< mod
		17, ///< pow
		18, ///< unm
		19, ///< not
		20, ///< len
		21, ///< concat
		22, ///< jmp
		26, ///< test
		27, ///< testset
		0, ///< move
		31, ///< forloop
		32, ///< forprep
		33, ///< tforloop
		34, ///< setlist
		35, ///< close
		36, ///< closure
		28, ///< call
		30, ///< return
		29, ///< tailcall
		37 ///< vararg
	}
};

LuaOpNameList get_lua51_opnames(const int version) {
	LuaOpNameList list = RZ_NEWS(char *, LUA_NUM_OPCODES51 + 1);
	if (list == NULL) {
		RZ_LOG_ERROR("Cannot allocate lua51 opcode list.\n");
		return NULL;
	}

	for (int i = 0; i <= OP_VARARG; i++) {
		list[i] = (char *)op_names[i];
	}
	return list;
}

ut8 get_lua51_opcode_by_name(const char *name, int limit) {
	for (int i = 0; i <= OP_VARARG; i++) {
		lua_strcase(op_names[i]) return i;
	}
	return OP_VARARG + 1; // invalid
}

ut8 get_lua51_shuffled_opcode_by_index(const int opcode, const int version) {
	return OP_SHUFFLE_ARRAY[version][opcode];
}

ut8 get_lua51_opcode_shuffled_index_by_id(const int opcode, const int version) {
	for (int i = 0; i <= OP_VARARG; i++) {
		if (OP_SHUFFLE_ARRAY[version][i] == opcode) {
			return i;
		}
	}
	return OP_VARARG + 1; // invalid
}

char *get_lua51_opcode_name(const int opcode) {
	return (char *)op_names[opcode];
}