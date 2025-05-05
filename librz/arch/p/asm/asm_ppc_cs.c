// SPDX-FileCopyrightText: 2014-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include "ppc/libvle/vle.h"
#include "ppc/libps/libps.h"

#include "cs_helper.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(ppc_asm);

static int decompile_vle(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	vle_t *instr = 0;
	vle_handle handle = { 0 };
	if (len < 2) {
		return -1;
	}
	if (!vle_init(&handle, buf, len) && (instr = vle_next(&handle))) {
		op->size = instr->size;
		char buf_asm[64];
		vle_snprint(buf_asm, sizeof(buf_asm), a->pc, instr);
		rz_asm_op_set_asm(op, buf_asm);
		vle_free(instr);
	} else {
		rz_asm_op_set_asm(op, "invalid");
		op->size = 2;
		return -1;
	}
	return op->size;
}

static int decompile_ps(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	ppcps_t instr = { 0 };
	if (len < 4) {
		return -1;
	}
	op->size = 4;
	const ut32 data = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
	if (libps_decode(data, &instr) < 1) {
		rz_asm_op_set_asm(op, "invalid");
		return -1;
	}
	char buf_asm[64];
	libps_snprint(buf_asm, sizeof(buf_asm), a->pc, &instr);
	rz_asm_op_set_asm(op, buf_asm);
	return op->size;
}

static int ppc_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;
	int n, ret;
	ut64 off = a->pc;
	cs_mode mode = 0;
	cs_insn *insn;
	if (a->cpu && strncmp(a->cpu, "vle", 3) == 0) {
		// vle is big-endian only
		if (!a->big_endian) {
			return -1;
		}
		ret = decompile_vle(a, op, buf, len);
		if (ret >= 0) {
			return op->size;
		}
	} else if (a->cpu && strncmp(a->cpu, "ps", 2) == 0) {
		// libps is big-endian only
		if (!a->big_endian) {
			return -1;
		}
		ret = decompile_ps(a, op, buf, len);
		if (ret >= 0) {
			return op->size;
		}
	}
	switch (a->bits) {
	case 32:
		mode = CS_MODE_32;
		break;
	case 64:
		mode = CS_MODE_64;
		break;
	default:
		mode = 0;
		break;
	}
	mode |= a->big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
	if (a->cpu && RZ_STR_EQ(a->cpu, "qpx")) {
		mode |= CS_MODE_QPX;
	}

	if (ctx->omode != mode) {
		cs_close(&ctx->handle);
		ctx->omode = -1;
	}
	if (!ctx->handle) {
		ret = cs_open(CS_ARCH_PPC, mode, &ctx->handle);
		if (ret) {
			return -1;
		}
		ctx->omode = mode;
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_OFF);
	}

	op->size = 4;
	n = cs_disasm(ctx->handle, (const ut8 *)buf, len, off, 1, &insn);
	op->size = 4;
	if (n > 0 && insn->size > 0) {
		rz_asm_op_setf_asm(op, "%s%s%s", insn->mnemonic,
			insn->op_str[0] ? " " : "", insn->op_str);
		cs_free(insn, n);
		return op->size;
	}
	rz_asm_op_set_asm(op, "invalid");
	op->size = 4;
	cs_free(insn, n);
	return op->size;
}

static char **ppc_cpu_descriptions() {
	static char *cpu_desc[] = {
		"ppc", "Generic PowerPC CPU",
		"vle", "PowerPC with Variable Length Encoding extension",
		"ps", "PowerPC with Paired Single SIMD extension",
		"qpx", "PowerPC with Quad Processing eXtensions",
		NULL
	};
	return cpu_desc;
}

static bool ppc_sw_breakpoint(RzAsm *a, RzAsmOp *op) {
	// ppc | tw 31, 0, 0 | trap
	// { 0x7f, 0xe0, 0x00, 0x08 } | big endian
	// { 0x08, 0x00, 0xe0, 0x7f } | little endian
	rz_asm_op_set_buf(op, a->big_endian ? (const ut8 *)"\x7f\xe0\x00\x08" : (const ut8 *)"\x08\x00\xe0\x7f", 4);
	return true;
}

RzAsmPlugin rz_asm_plugin_ppc_cs = {
	.name = "ppc",
	.desc = "PowerPC Capstone-based disassembler",
	.license = "BSD",
	.author = "pancake",
	.arch = "ppc",
	.cpus = "ppc,vle,ps,qpx",
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.init = ppc_asm_init,
	.fini = ppc_asm_fini,
	.disassemble = &ppc_disassemble,
	.mnemonics = ppc_asm_mnemonics,
	.get_cpu_desc = ppc_cpu_descriptions,
	.sw_breakpoint = ppc_sw_breakpoint,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_ppc_cs,
	.version = RZ_VERSION
};
#endif
