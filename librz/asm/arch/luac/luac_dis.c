// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "luac_dis.h"
int luac_disasm(RzAsm *a, RzAsmOp *opstruct, const ut8 *buf, int len){
        // switch version here ?

	LuaOpNameList oplist = get_lua54_opnames();
        int r = lua54_disasm(opstruct, buf, len, oplist);
	free_lua_opnames(oplist);
	opstruct->size = r;
	return r;
}