// SPDX-FileCopyrightText: 2014-2020 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2014-2020 eagleoflqj <liumeo@pku.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "../arch/i4004/i4004dis.c"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	return i4004dis(op, buf, len);
}

RzAsmPlugin rz_asm_plugin_i4004 = {
	.name = "i4004",
	.desc = "Intel 4004 microprocessor",
	.arch = "i4004",
	.license = "LGPL3",
	.bits = 4,
	.endian = RZ_SYS_ENDIAN_NONE,
	.disassemble = &disassemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_i4004,
	.version = RZ_VERSION
};
#endif
