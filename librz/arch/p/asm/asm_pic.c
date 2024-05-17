// SPDX-FileCopyrightText: 2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2018 courk <courk@courk.cc>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>

#include "pic/pic14.h"
#include "pic/pic18.h"
#include "pic/pic16.h"

static int asm_pic_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *b, int l) {
	int res = -1;
	if (a->cpu && is_pic14(a->cpu)) {
		res = pic14_disassemble(a, op, b, l);
	} else if (a->cpu && is_pic16(a->cpu)) {
		res = pic16_disassemble(a, op, b, l);
	} else if (a->cpu && is_pic18(a->cpu)) {
		res = pic18_disassemble(a, op, b, l);
	}
	return op->size = res;
}

RzAsmPlugin rz_asm_plugin_pic = {
	.name = "pic",
	.arch = "pic",
	.cpus = "pic18,pic16,pic14,highend,midrange,baseline",
	.bits = 8,
	.license = "LGPL3",
	.desc = "PIC disassembler",
	.disassemble = &asm_pic_disassemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_pic
};
#endif
