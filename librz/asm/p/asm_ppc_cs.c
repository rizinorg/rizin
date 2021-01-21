/* rizin - LGPL - Copyright 2014-2018 - pancake */

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone.h>
#include "../arch/ppc/libvle/vle.h"
#include "../arch/ppc/libps/libps.h"

static csh handle = 0;

static bool the_end(void *p) {
	if (handle) {
		cs_close(&handle);
		handle = 0;
	}
	return true;
}

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

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	static int omode = -1, obits = -1;
	int n, ret;
	ut64 off = a->pc;
	cs_insn *insn;
	int mode = (a->bits == 64) ? CS_MODE_64 : (a->bits == 32) ? CS_MODE_32
								  : 0;
	mode |= a->big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;

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
	if (mode != omode || a->bits != obits) {
		cs_close(&handle);
		handle = 0;
		omode = mode;
		obits = a->bits;
	}
	if (handle == 0) {
		ret = cs_open(CS_ARCH_PPC, mode, &handle);
		if (ret != CS_ERR_OK) {
			return -1;
		}
	}
	op->size = 4;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
	n = cs_disasm(handle, (const ut8 *)buf, len, off, 1, &insn);
	op->size = 4;
	if (n > 0 && insn->size > 0) {
		const char *opstr = sdb_fmt("%s%s%s", insn->mnemonic,
			insn->op_str[0] ? " " : "", insn->op_str);
		rz_asm_op_set_asm(op, opstr);
		cs_free(insn, n);
		return op->size;
	}
	rz_asm_op_set_asm(op, "invalid");
	op->size = 4;
	cs_free(insn, n);
	return op->size;
}

RzAsmPlugin rz_asm_plugin_ppc_cs = {
	.name = "ppc",
	.desc = "Capstone PowerPC disassembler",
	.license = "BSD",
	.author = "pancake",
	.arch = "ppc",
	.cpus = "ppc,vle,ps",
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.fini = the_end,
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_ppc_cs,
	.version = RZ_VERSION
};
#endif
