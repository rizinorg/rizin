// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

#define RZ_VISUAL_ASM_BUFSIZE 1024

typedef struct {
	RzCore *core;
	char blockbuf[RZ_VISUAL_ASM_BUFSIZE];
	char codebuf[RZ_VISUAL_ASM_BUFSIZE];
	int oplen;
	ut8 buf[128];
	RzAsmCode *acode;
	int blocklen;
	ut64 off;
} RzCoreVisualAsm;

static int readline_callback(void *_a, const char *str) {
	RzCoreVisualAsm *a = _a;
	RzCore *core = a->core;
	rz_cons_clear00();
	rz_cons_printf("Write some %s-%" PFMT64d " assembly...\n\n",
		rz_config_get(a->core->config, "asm.arch"),
		rz_config_get_i(a->core->config, "asm.bits"));
	if (*str == '?') {
		rz_cons_printf("0> ?\n\n"
			       "Visual assembler help:\n\n"
			       "  assemble input while typing using asm.arch, asm.bits and cfg.bigendian\n"
			       "  press enter to quit (prompt if there are bytes to be written)\n"
			       "  this assembler supports various directives like .hex ...\n");
	} else {
		rz_asm_code_free(a->acode);
		rz_asm_set_pc(a->core->rasm, a->off);
		a->acode = rz_asm_massemble(a->core->rasm, str);
		if (a->acode) {
			char *hex = rz_asm_code_get_hex(a->acode);
			rz_cons_printf("[VA:%d]> %s\n", a->acode ? a->acode->len : 0, str);
			if (a->acode && a->acode->len) {
				rz_cons_printf("* %s\n\n", hex);
			} else {
				rz_cons_print("\n\n");
			}
			int xlen = RZ_MIN(strlen(hex), RZ_VISUAL_ASM_BUFSIZE - 2);
			strcpy(a->codebuf, a->blockbuf);
			memcpy(a->codebuf, hex, xlen);
			if (xlen >= strlen(a->blockbuf)) {
				a->codebuf[xlen] = '\0';
			}
			free(hex);
		} else {
			rz_cons_printf("[VA:0]> %s\n* ?\n\n", str);
		}
		{
			int rows = 0;
			int cols = rz_cons_get_size(&rows);
			core->print->cur_enabled = 1;
			core->print->ocur = 0;
			core->print->cur = (a->acode && a->acode->len) ? a->acode->len - 1 : 0;
			char *cmd = rz_str_newf("pd %d @x:%s @0x%" PFMT64x, rows - 11, a->codebuf, a->off);
			char *res = rz_core_cmd_str(a->core, cmd);
			char *msg = rz_str_ansi_crop(res, 0, 0, cols - 2, rows - 5);
			rz_cons_printf("%s\n", msg);
			free(msg);
			free(res);
			free(cmd);
		}
	}
	rz_cons_flush();
	return 1;
}

RZ_API void rz_core_visual_asm(RzCore *core, ut64 off) {
	RzCoreVisualAsm cva = {
		.core = core,
		.off = off
	};
	rz_io_read_at(core->io, off, cva.buf, sizeof(cva.buf));
	cva.blocklen = rz_hex_bin2str(cva.buf, sizeof(cva.buf), cva.blockbuf);

	rz_line_readline_cb(readline_callback, &cva);

	if (cva.acode && cva.acode->len > 0) {
		if (rz_cons_yesno('y', "Save changes? (Y/n)")) {
			if (!rz_io_write_at(core->io, off, cva.acode->bytes, cva.acode->len)) {
				eprintf("ERROR: Cannot write in here, check map permissions or reopen the file with oo+\n");
				rz_cons_any_key(NULL);
			}
		}
	}
	rz_asm_code_free(cva.acode);
}
