#include <rz_asm.h>
#include <rz_lib.h>
#include "cs_helper.h"

CAPSTONE_DEFINE_PLUGIN_FUNCTIONS(bpf_asm);

static int bpf_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	CapstoneContext *ctx = (CapstoneContext *)a->plugin_data;
	cs_insn *insn;
	int n, ret = -1;
	cs_mode mode = CS_MODE_BPF_CLASSIC | (a->big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN);
	memset(op, 0, sizeof(RzAsmOp));
	op->size = 8;

	if (ctx->omode != mode) {
		cs_close(&ctx->handle);
		ctx->omode = -1;
	}
	if (!ctx->handle) {
		ret = cs_open(CS_ARCH_BPF, mode, &ctx->handle);
		if (ret) {
			return ret;
		}
		ctx->omode = mode;
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_OFF);
	}

	n = cs_disasm(ctx->handle, buf, len, a->pc, 1, &insn);
	if (n < 1) {
		rz_asm_op_set_asm(op, "invalid");
		ret = -1;
		cs_free(insn, n);
		return ret;
	}
	if (insn->size != 8 && insn->size != 16) {
		cs_free(insn, n);
		ret = -1;
		return ret;
	}
	op->size = insn->size;
	ret = op->size;

	if (insn->op_str[0]) {
		rz_asm_op_setf_asm(op, "%s %s", insn->mnemonic, insn->op_str);
	} else {
		rz_asm_op_set_asm(op, insn->mnemonic);
	}
	cs_free(insn, n);
	return ret;
}

RzAsmPlugin rz_asm_plugin_bpf_cs = {
	.name = "bpf",
	.license = "LGPL3",
	.desc = "BPF disassembly plugin",
	.arch = "bpf",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BIG | RZ_SYS_ENDIAN_LITTLE,
	.init = &bpf_asm_init,
	.fini = &bpf_asm_fini,
	.disassemble = &bpf_disassemble,
	.mnemonics = &bpf_asm_mnemonics
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_bpf_cs,
	.version = RZ_VERSION
};
#endif
