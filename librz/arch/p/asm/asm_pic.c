// SPDX-FileCopyrightText: 2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2018 courk <courk@courk.cc>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>

#include "pic/pic_baseline.h"
#include "pic/pic_midrange.h"
#include "pic/pic_highend.h"

static int asm_pic_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *b, int l) {
	int res = -1;
	if (a->cpu && is_pic_baseline(a->cpu)) {
		res = pic_baseline_disassemble(a, op, b, l);
	} else if (a->cpu && is_pic_midrange(a->cpu)) {
		res = pic_midrange_disassemble(a, op, b, l);
	} else if (a->cpu && is_pic_highend(a->cpu)) {
		res = pic_highend_disassemble(a, op, b, l);
	}
	return op->size = res;
}

char **pic_cpu_descriptions() {
	static char *cpu_desc[] = {
		"baseline", "Baseline 12-bit instruction set microcontrollers: PIC10Fxxx, PIC12Fxxx, and PIC16Fxxx",
		"midrange", "Mid-Range 14-bit instruction set microcontrollers: PIC10Fxxx, PIC12Fxxx, and PIC16Fxxx",
		"highend", "High-End 16-bit instruction set microcontrollers: PIC18Fxxxx, PIC18FxxJxx, and PIC18FxxKxx",
		"pic18", "alias for highend",
		NULL
	};
	return cpu_desc;
}

RzAsmPlugin rz_asm_plugin_pic = {
	.name = "pic",
	.arch = "pic",
	.cpus = "baseline,midrange,highend,pic18",
	.bits = 16 | 32,
	.license = "LGPL3",
	.desc = "PIC disassembler",
	.disassemble = &asm_pic_disassemble,
	.get_cpu_desc = pic_cpu_descriptions,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_pic
};
#endif
