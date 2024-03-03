// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2018 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>

#include "disas-asm.h"
#include "opcode/mips.h"
int mips_assemble(const char *str, ut64 pc, ut8 *out);

static int mips_mode = 0;
static unsigned long Offset = 0;
static RzStrBuf *buf_global = NULL;
static unsigned char bytes[4];
static char *pre_cpu = NULL;
static char *pre_features = NULL;

static int mips_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info) {
	int delta = (memaddr - Offset);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if ((delta + length) > 4) {
		return -1;
	}
	memcpy(myaddr, bytes + delta, length);
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC()
DECLARE_GENERIC_FPRINTF_FUNC()

typedef struct {
	struct disassemble_info disasm_obj;
} MIPSGnuContext;

static int disassemble(struct rz_asm_t *a, struct rz_asm_op_t *op, const ut8 *buf, int len) {
	MIPSGnuContext *ctx = (MIPSGnuContext *)a->plugin_data;
	if (len < 4) {
		return -1;
	}
	buf_global = &op->buf_asm;
	Offset = a->pc;
	memcpy(bytes, buf, 4); // TODO handle thumb

	if ((a->cpu != pre_cpu) && (a->features != pre_features)) {
		free(ctx->disasm_obj.disassembler_options);
		memset(&ctx->disasm_obj, '\0', sizeof(struct disassemble_info));
	}

	/* prepare disassembler */
	if (a->cpu && (!pre_cpu || !strcmp(a->cpu, pre_cpu))) {
		if (!rz_str_casecmp(a->cpu, "mips64r2")) {
			ctx->disasm_obj.mach = bfd_mach_mipsisa64r2;
		} else if (!rz_str_casecmp(a->cpu, "mips32r2")) {
			ctx->disasm_obj.mach = bfd_mach_mipsisa32r2;
		} else if (!rz_str_casecmp(a->cpu, "mips64")) {
			ctx->disasm_obj.mach = bfd_mach_mipsisa64;
		} else if (!rz_str_casecmp(a->cpu, "mips32")) {
			ctx->disasm_obj.mach = bfd_mach_mipsisa32;
		}
		char *tmp = rz_str_dup(a->cpu);
		free(pre_cpu);
		pre_cpu = tmp;
	}

	if (a->features && (!pre_features || !strcmp(a->features, pre_features))) {
		free(ctx->disasm_obj.disassembler_options);
		if (strstr(a->features, "n64")) {
			ctx->disasm_obj.disassembler_options = rz_str_dup("abi=n64");
		} else if (strstr(a->features, "n32")) {
			ctx->disasm_obj.disassembler_options = rz_str_dup("abi=n32");
		} else if (strstr(a->features, "o32")) {
			ctx->disasm_obj.disassembler_options = rz_str_dup("abi=o32");
		}
		char *tmp = rz_str_dup(a->features);
		free(pre_features);
		pre_features = tmp;
	}

	mips_mode = a->bits;
	ctx->disasm_obj.arch = CPU_LOONGSON_2F;
	ctx->disasm_obj.buffer = bytes;
	ctx->disasm_obj.read_memory_func = &mips_buffer_read_memory;
	ctx->disasm_obj.symbol_at_address_func = &symbol_at_address;
	ctx->disasm_obj.memory_error_func = &memory_error_func;
	ctx->disasm_obj.print_address_func = &generic_print_address_func;
	ctx->disasm_obj.buffer_vma = Offset;
	ctx->disasm_obj.buffer_length = 4;
	ctx->disasm_obj.endian = !a->big_endian;
	ctx->disasm_obj.fprintf_func = &generic_fprintf_func;
	ctx->disasm_obj.stream = stdout;
	op->size = (ctx->disasm_obj.endian == BFD_ENDIAN_LITTLE)
		? print_insn_little_mips((bfd_vma)Offset, &ctx->disasm_obj)
		: print_insn_big_mips((bfd_vma)Offset, &ctx->disasm_obj);
	if (op->size == -1) {
		rz_strbuf_set(&op->buf_asm, "(data)");
	}
	return op->size;
}

static int assemble(RzAsm *a, RzAsmOp *op, const char *str) {
	ut8 *opbuf = (ut8 *)rz_strbuf_get(&op->buf);
	int ret = mips_assemble(str, a->pc, opbuf);
	if (a->big_endian) {
		ut8 tmp = opbuf[0];
		opbuf[0] = opbuf[3];
		opbuf[3] = tmp;
		tmp = opbuf[1];
		opbuf[1] = opbuf[2];
		opbuf[2] = tmp;
	}
	return ret;
}

static bool mips_gnu_init(void **user) {
	MIPSGnuContext *ctx = RZ_NEW0(MIPSGnuContext);
	rz_return_val_if_fail(ctx, false);
	*user = ctx;
	return true;
}

static bool mips_gnu_fini(void *user) {
	MIPSGnuContext *ctx = (MIPSGnuContext *)user;
	if (ctx) {
		RZ_FREE(ctx);
	}
	return true;
}

RzAsmPlugin rz_asm_plugin_mips_gnu = {
	.name = "mips.gnu",
	.arch = "mips",
	.license = "GPL3",
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.desc = "MIPS CPU",
	.init = mips_gnu_init,
	.fini = mips_gnu_fini,
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_mips_gnu,
	.version = RZ_VERSION
};
#endif
