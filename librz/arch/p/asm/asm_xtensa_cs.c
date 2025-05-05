// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_asm.h>
#include <xtensa/xtensa.h>

static int asm_xtensa_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	XtensaContext *ctx = a->plugin_data;
	if (!xtensa_open(ctx, a->cpu, a->big_endian)) {
		goto beach;
	}
	if (!xtensa_disassemble(ctx, buf, len, a->pc)) {
		goto beach;
	}

	rz_asm_op_setf_asm(op,
		"%s%s%s",
		ctx->insn->mnemonic,
		ctx->insn->op_str[0] ? " " : "",
		ctx->insn->op_str);
	op->size = ctx->insn->size;
	xtensa_disassemble_fini(ctx);
	return op->size;

beach:
	rz_asm_op_set_asm(op, "illegal");
	xtensa_disassemble_fini(ctx);
	return -1;
}

static char **xtensa_cpu_descriptions() {
	static char *cpu_desc[] = {
		"esp32", "Xtensa microcontroller with Wi-Fi and Bluetooth capabilities",
		"esp32s2", "Xtensa microcontroller with Wi-Fi and USB OTG support",
		"esp8266", "Xtensa microcontroller with Wi-Fi support",
		NULL
	};
	return cpu_desc;
}

RzAsmPlugin rz_asm_plugin_xtensa_cs = {
	.name = "xtensa",
	.license = "LGPL3",
	.desc = "Tensilica Xtensa Capstone-based disassembler",
	.author = "billow",
	.arch = "xtensa",
	.cpus = "esp32,esp32s2,esp8266",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.disassemble = asm_xtensa_disassemble,
	.init = &xtensa_init,
	.fini = &xtensa_fini,
	.get_cpu_desc = xtensa_cpu_descriptions,
};
