// SPDX-FileCopyrightText: 2013-2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

// instruction set : http://www.tachyonsoft.com/inst390m.htm

#include <rz_asm.h>
#include <rz_lib.h>
#include <capstone.h>

static csh cd = 0;

static bool the_end(void *p) {
	if (cd) {
		cs_close(&cd);
		cd = 0;
	}
	return true;
}

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	static int omode = 0;
	int mode, n, ret;
	ut64 off = a->pc;
	cs_insn *insn = NULL;
	mode = CS_MODE_BIG_ENDIAN;
	if (cd && mode != omode) {
		cs_close(&cd);
		cd = 0;
	}
	op->size = 0;
	omode = mode;
	if (cd == 0) {
		ret = cs_open(CS_ARCH_SYSZ, mode, &cd);
		if (ret) {
			return 0;
		}
		cs_option(cd, CS_OPT_DETAIL, CS_OPT_OFF);
	}
	n = cs_disasm(cd, (const ut8 *)buf, len, off, 1, &insn);
	if (n > 0) {
		if (insn->size > 0) {
			op->size = insn->size;
			char *buf_asm = sdb_fmt("%s%s%s",
				insn->mnemonic, insn->op_str[0] ? " " : "",
				insn->op_str);
			char *ptrstr = strstr(buf_asm, "ptr ");
			if (ptrstr) {
				memmove(ptrstr, ptrstr + 4, strlen(ptrstr + 4) + 1);
			}
			rz_asm_op_set_asm(op, buf_asm);
		}
		cs_free(insn, n);
	}
	return op->size;
}

RzAsmPlugin rz_asm_plugin_sysz = {
	.name = "sysz",
	.desc = "SystemZ CPU disassembler",
	.license = "BSD",
	.arch = "sysz",
	.bits = 32 | 64,
	.endian = RZ_SYS_ENDIAN_BIG,
	.fini = the_end,
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_sysz,
	.version = RZ_VERSION
};
#endif
