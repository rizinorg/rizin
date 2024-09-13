// SPDX-FileCopyrightText: 2015-2018 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2015-2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2015-2018 courk <courk@courk.cc>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pic.h"
#include "pic16.h"
#include "pic16_il.inc"

typedef void (*pic16_inst_handler_t)(RzAnalysis *analysis, RzAnalysisOp *op,
	ut64 addr,
	Pic16OpArgsVal *args);

typedef struct {
	Pic16Opcode opcode;
	pic16_inst_handler_t handler;
	pic16_il_handler il_handler;
} Pic16OpAnalysisInfo;

#define INST_HANDLER(OPCODE_NAME) \
	static void _inst__##OPCODE_NAME(RzAnalysis *analysis, RzAnalysisOp *op, \
		ut64 addr, \
		Pic16OpArgsVal *args)
#define INST_DECL(NAME) \
	[PIC16_OPCODE_##NAME] = { \
		PIC16_OPCODE_##NAME, _inst__##NAME, IL_LIFTER(NAME) \
	}

#include "pic16_esil.inc"

static const Pic16OpAnalysisInfo pic16_op_analysis_info[] = {
	INST_DECL(NOP),
	INST_DECL(RETURN),
	INST_DECL(RETFIE),
	INST_DECL(OPTION),
	INST_DECL(SLEEP),
	INST_DECL(CLRWDT),
	INST_DECL(TRIS),
	INST_DECL(MOVWF),
	INST_DECL(SUBWF),
	INST_DECL(DECF),
	INST_DECL(IORWF),
	INST_DECL(ANDWF),
	INST_DECL(XORWF),
	INST_DECL(ADDWF),
	INST_DECL(MOVF),
	INST_DECL(COMF),
	INST_DECL(INCF),
	INST_DECL(DECFSZ),
	INST_DECL(RRF),
	INST_DECL(RLF),
	INST_DECL(SWAPF),
	INST_DECL(INCFSZ),
	INST_DECL(BCF),
	INST_DECL(BSF),
	INST_DECL(BTFSC),
	INST_DECL(BTFSS),
	INST_DECL(CALL),
	INST_DECL(GOTO),
	INST_DECL(MOVLW),
	INST_DECL(RETLW),
	INST_DECL(IORLW),
	INST_DECL(ANDLW),
	INST_DECL(XORLW),
	INST_DECL(SUBLW),
	INST_DECL(ADDLW),
	INST_DECL(RESET),
	INST_DECL(CALLW),
	INST_DECL(BRW),
	INST_DECL(MOVIW_1),
	INST_DECL(MOVWI_1),
	INST_DECL(MOVLB),
	INST_DECL(LSLF),
	INST_DECL(LSRF),
	INST_DECL(ASRF),
	INST_DECL(SUBWFB),
	INST_DECL(ADDWFC),
	INST_DECL(ADDFSR),
	INST_DECL(MOVLP),
	INST_DECL(BRA),
	INST_DECL(MOVIW_2),
	INST_DECL(MOVWI_2),
	INST_DECL(CLRF),
	INST_DECL(CLRW),
};

static RzIODesc *cpu_memory_map(
	RzIOBind *iob, RzIODesc *desc, ut32 addr, ut32 size) {
	char mstr[16];
	rz_strf(mstr, "malloc://%d", size);
	if (desc && iob->fd_get_name(iob->io, desc->fd)) {
		iob->fd_remap(iob->io, desc->fd, addr);
	} else {
		desc = iob->open_at(iob->io, mstr, RZ_PERM_RW, 0, addr, NULL);
	}
	return desc;
}

static bool pic16_reg_write(RzReg *reg, const char *regname, ut32 num) {
	if (reg) {
		RzRegItem *item = rz_reg_get(reg, regname, RZ_REG_TYPE_GPR);
		if (item) {
			rz_reg_set_value(reg, item, num);
			return true;
		}
	}
	return false;
}

static void analysis_pic16_setup(RzAnalysis *analysis, bool force) {
	PicContext *ctx = (PicContext *)analysis->plugin_data;

	if (!ctx->init_done || force) {
		// Allocate memory as needed.
		// We assume that code is already allocated with firmware
		// image
		ctx->mem_sram =
			cpu_memory_map(&analysis->iob, ctx->mem_sram,
				PIC16_ESIL_SRAM_START, 0x1000);
		ctx->mem_stack =
			cpu_memory_map(&analysis->iob, ctx->mem_sram,
				PIC16_ESIL_CSTACK_TOP, 0x20);

		pic16_reg_write(analysis->reg, "_sram",
			PIC16_ESIL_SRAM_START);
		pic16_reg_write(analysis->reg, "_stack",
			PIC16_ESIL_CSTACK_TOP);
		pic16_reg_write(analysis->reg, "stkptr", 0x1f);

		ctx->init_done = true;
	}
}

int pic16_op(
	RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {

	if (!buf || len < 2) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		return -1;
	}
	Pic16Op x = { 0 };
	if (!pic16_disasm_op(&x, addr, buf, len)) {
		return -1;
	}
	if (!(x.opcode < RZ_ARRAY_SIZE(pic16_op_analysis_info))) {
		return -1;
	}
	const Pic16OpAnalysisInfo *info = pic16_op_analysis_info + x.opcode;
	if (!info) {
		return -1;
	}

	op->size = x.size;
	op->cycles = 1;
	op->type = RZ_ANALYSIS_OP_TYPE_NOP;

	if (mask & RZ_ANALYSIS_OP_MASK_ESIL && info->handler) {
		analysis_pic16_setup(analysis, false);
		info->handler(analysis, op, addr, &x.args);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL && info->il_handler) {
		Pic16ILContext il_ctx = {
			.analysis = analysis,
			.op = op,
			.x = &x,
		};
		op->il_op = info->il_handler(&il_ctx, x.opcode);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf("%s%s%s",
			x.mnemonic,
			x.operands[0] ? " " : "",
			x.operands);
	}

	return op->size;
}

char *pic16_get_reg_profile(RzAnalysis *a) {
	const char *p =
		"=PC	pc\n"
		"=SP	stkptr\n"
		"=A0	porta\n"
		"=A1	portb\n"
		"gpr	indf0	.8	0	0\n"
		"gpr	indf1	.8	1	0\n"
		"gpr	pcl	.8	2	0\n"
		"gpr	status	.8	3	0\n"
		"flg	c	.1	3.0	0\n"
		"flg	dc	.1	3.1	0\n"
		"flg	z	.1	3.2	0\n"
		"flg	pd	.1	3.3	0\n"
		"flg	to	.1	3.4	0\n"
		"gpr	fsr0l	.8	4	0\n"
		"gpr	fsr0h	.8	5	0\n"
		"gpr	fsr1l	.8	6	0\n"
		"gpr	fsr1h	.8	7	0\n"
		"gpr	bsr	.8	8	0\n"
		"gpr	wreg	.8	9	0\n"
		"gpr	pclath	.8	10	0\n"
		"gpr	intcon	.8	11	0\n"
		"gpr	pc	.16	12	0\n"
		"gpr	stkptr	.8	14	0\n"
		"gpr	_sram	.32 15	0\n"
		"gpr	_stack	.32 19	0\n"
		"gpr tosl .8 24 0\n"
		"gpr tosh .8 25 0\n"
		"gpr tris .8 26 0\n"
		"gpr _bank .8 27 0\n";
	return rz_str_dup(p);
}
