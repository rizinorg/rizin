/* rizin - LGPL - Copyright 2018 - thestr4ng3r, courk */

#include <rz_asm.h>
#include <rz_lib.h>

#include "../arch/pic/pic_baseline.h"
#include "../arch/pic/pic_pic18.h"
#include "../arch/pic/pic_midrange.h"

static int asm_pic_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *b, int l) {
	int res = -1;
	char opbuf[128];
	const char *opstr = opbuf;
	strcpy(opbuf, "invalid");
	if (a->cpu && strcasecmp(a->cpu, "baseline") == 0) {
		res = pic_baseline_disassemble(op, opbuf, b, l);
	} else if (a->cpu && strcasecmp(a->cpu, "midrange") == 0) {
		res = pic_midrange_disassemble(op, opbuf, b, l);
	} else if (a->cpu && strcasecmp(a->cpu, "pic18") == 0) {
		res = pic_pic18_disassemble(op, opbuf, b, l);
	}
	rz_asm_op_set_asm(op, opstr);
	return op->size = res;
}

RzAsmPlugin rz_asm_plugin_pic = {
	.name = "pic",
	.arch = "pic",
	.cpus = "baseline,midrange,pic18",
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
