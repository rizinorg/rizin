// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <rz_types.h>

#include "cris/cris.h"

static int cris_disassemble_op(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CrisIsaVersion ver = CRIS_ISA_V32;
	if (a->cpu && strstr(a->cpu, "v10")) {
		ver = CRIS_ISA_V10;
	}

	CrisInsn insn;
	int ret = cris_disas(buf, len, &op->buf_asm, ver, &insn);
	if (ret < 0) {
		rz_strbuf_set(&op->buf_asm, "invalid");
		return -1;
	}
	op->size = ret;
	return ret;
}

RzAsmPlugin rz_asm_plugin_cris = {
	.name = "cris",
	.arch = "cris",
	.cpus = "v10,v32",
	.license = "LGPL3",
	.author = "RizinOrg",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.desc = "Axis Communications CRIS disassembler",
	.disassemble = &cris_disassemble_op,
};
