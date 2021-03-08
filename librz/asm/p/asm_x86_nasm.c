// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_asm.h>

static int assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
	char *ipath, *opath;
	if (a->syntax != RZ_ASM_SYNTAX_INTEL) {
		eprintf("asm.x86.nasm does not support non-intel syntax\n");
		return -1;
	}

	int ifd = rz_file_mkstemp("rz_nasm", &ipath);
	if (ifd == -1) {
		return -1;
	}

	int ofd = rz_file_mkstemp("rz_nasm", &opath);
	if (ofd == -1) {
		free(ipath);
		return -1;
	}

	char *asm_buf = rz_str_newf("[BITS %i]\nORG 0x%" PFMT64x "\n%s\n", a->bits, a->pc, buf);
	if (asm_buf) {
		rz_xwrite(ifd, asm_buf, strlen(asm_buf));
		free(asm_buf);
	}

	close(ifd);

	if (!rz_sys_cmdf("nasm %s -o %s", ipath, opath)) {
		ut8 buf[512]; // TODO: remove limits
		op->size = read(ofd, buf, sizeof(buf));
		rz_asm_op_set_buf(op, buf, op->size);
	} else {
		eprintf("Error running 'nasm'\n");
	}

	close(ofd);
	unlink(ipath);
	unlink(opath);
	free(ipath);
	free(opath);

	return op->size;
}

RzAsmPlugin rz_asm_plugin_x86_nasm = {
	.name = "x86.nasm",
	.desc = "X86 nasm assembler",
	.license = "LGPL3",
	.arch = "x86",
	// NOTE: 64bits is not supported on OSX's nasm :(
	.bits = 16 | 32 | 64,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.assemble = &assemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_x86_nasm,
	.version = RZ_VERSION
};
#endif
