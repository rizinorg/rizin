// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_core.h>
#include <rz_util.h>

#include "../core_private.h"
#include <rz_asm.h>
#include <rz_util/rz_print.h>
#include <rz_util/rz_strbuf.h>

static int wordpos(const char *esil, int n) {
	const char *w = esil;
	if (n < 1) {
		n = 0;
	}
	while (w && n--) {
		const char *nw = strchr(w + 1, ',');
		if (!nw) {
			return strlen(esil);
		}
		w = nw;
	}
	if (!w && n > 0) {
		return strlen(esil);
	}
	return (size_t)(w - esil);
}

static void showreg(RzAnalysisEsil *esil, const char *rn, const char *desc) {
	ut64 nm = 0;
	int sz = 0;
	rz_cons_printf("%s 0x%08" PFMT64x " (%d) ; %s\n", rn, nm, sz, desc);
}

RZ_IPI bool rz_core_visual_esil(RzCore *core) {
	const int nbits = sizeof(ut64) * 8;
	char *word = NULL;
	int x = 0;
	RzAnalysisOp aop = { 0 };
	ut8 buf[sizeof(ut64)];
	unsigned int addrsize = rz_config_get_i(core->config, "esil.addr.size");
	RzLine *line = core->cons->line;

	if (core->blocksize < sizeof(ut64)) {
		return false;
	}
	memcpy(buf, core->block, sizeof(ut64));
	RzAnalysisEsil *esil = rz_analysis_esil_new(20, 0, addrsize);
	esil->analysis = core->analysis;
	rz_analysis_esil_set_pc(esil, core->offset);
	for (;;) {
		rz_cons_clear00();
		RzAsmOp asmop = { 0 };
		// bool use_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
		(void)rz_asm_disassemble(core->rasm, &asmop, buf, sizeof(ut64));
		rz_analysis_op_init(&aop);
		(void)rz_analysis_op(core->analysis, &aop, core->offset, buf, sizeof(ut64), RZ_ANALYSIS_OP_MASK_ESIL);
		rz_cons_printf("rizin's esil debugger:\n\n");
		rz_cons_printf("pos: %d\n", x);
		{
			char *op_hex = rz_asm_op_get_hex(&asmop);
			char *res = rz_print_hexpair(core->print, op_hex, -1);
			rz_cons_printf("hex: %s\n" Color_RESET, res);
			free(res);
			free(op_hex);
		}
		{
			RzStrBuf *colored_asm;
			RzAsmParseParam *param = rz_asm_get_parse_param(core->analysis->reg, aop.type);
			colored_asm = rz_asm_colorize_asm_str(&asmop.buf_asm, core->print, param, asmop.asm_toks);
			rz_asm_parse_param_free(param);
			rz_cons_printf(Color_RESET "asm: %s\n" Color_RESET, colored_asm ? rz_strbuf_get(colored_asm) : "");
			rz_strbuf_free(colored_asm);
		}
		{
			const char *expr = rz_strbuf_get(&aop.esil);
			rz_cons_printf(Color_RESET "esil: %s\n" Color_RESET, expr);
			int wp = wordpos(expr, x);
			char *pas = rz_str_pad(' ', wp ? wp + 1 : 0);
			int wp2 = wordpos(expr, x + 1);
			free(word);
			word = rz_str_ndup(expr + (wp ? (wp + 1) : 0), (wp2 - wp) - (wp ? 1 : 0));
			if (wp == wp2) {
				// x --;
				eprintf("Done\n");
				x = 0;
				rz_sys_sleep(1);
				free(pas);
				continue;
			}
			char *pad = rz_str_pad('-', wp2 - ((wp > 0) ? wp + 1 : 0));
			rz_cons_printf(Color_RESET "      %s%s\n" Color_RESET, pas, pad);
			free(pas);
			free(pad);
		}
		rz_cons_printf("esil regs:\n");
		showreg(esil, "$$", "address");
		showreg(esil, "$z", "zero");
		showreg(esil, "$b", "borrow");
		showreg(esil, "$c", "carry");
		showreg(esil, "$o", "overflow");
		showreg(esil, "$p", "parity");
		showreg(esil, "$r", "regsize");
		showreg(esil, "$s", "sign");
		showreg(esil, "$d", "delay");
		showreg(esil, "$j", "jump");

		rz_cons_printf("regs:\n");
		char *r = rz_core_cmd_str(core, "dr=");
		if (r) {
			rz_cons_printf("%s", r);
			free(r);
		}
		rz_cons_printf("esil stack:\n");
		rz_core_esil_dumpstack(esil);
		rz_analysis_op_fini(&aop);
		rz_cons_newline();
		rz_cons_visual_flush();

		int ch = rz_cons_readchar();
		if (ch == -1 || ch == 4) {
			break;
		}
		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'Q':
		case 'q':
			goto beach;
		case 's':
			eprintf("step ((%s))\n", word);
			rz_sys_usleep(500);
			x = RZ_MIN(x + 1, nbits - 1);
			rz_analysis_esil_runword(esil, word);
			break;
		case 'S':
			eprintf("esil step over :D\n");
			rz_sys_usleep(500);
			break;
		case 'r':
		case 'h':
			x = 0; // RZ_MAX (x - 1, 0);
			break;
		case '?':
			rz_cons_clear00();
			rz_cons_printf(
				"Vd1?: Visual Bit Editor Help:\n\n"
				" q     - quit the bit editor\n"
				" h/r   - reset / go back (reinitialize esil state)\n"
				" s     - esil step in\n"
				" j/k   - toggle bit value (same as space key)\n"
				" :     - enter command\n");
			rz_cons_flush();
			rz_cons_any_key(NULL);
			break;
		case ':': // TODO: move this into a separate helper function
		{
			char cmd[1024];
			rz_cons_show_cursor(true);
			rz_cons_set_raw(0);
			*cmd = 0;
			rz_line_set_prompt(line, ":> ");
			if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) < 0) {
				cmd[0] = '\0';
			}
			rz_core_cmd0(core, cmd);
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
			if (cmd[0]) {
				rz_cons_any_key(NULL);
			}
			rz_cons_clear();
		} break;
		}
		rz_asm_op_fini(&asmop);
	}
beach:
	rz_analysis_esil_free(esil);
	free(word);
	return true;
}
