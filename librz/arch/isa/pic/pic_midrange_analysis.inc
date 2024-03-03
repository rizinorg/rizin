// SPDX-FileCopyrightText: 2015-2018 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2015-2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2015-2018 courk <courk@courk.cc>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pic_midrange.h"
#include "pic_midrange_il.inc"

typedef void (*pic_midrange_inst_handler_t)(RzAnalysis *analysis, RzAnalysisOp *op,
	ut64 addr,
	PicMidrangeOpArgsVal *args);

typedef struct {
	PicMidrangeOpcode opcode;
	PicMidrangeOpArgs args;
	pic_midrange_inst_handler_t handler;
	pic_midrange_il_handler il_handler;
} PicMidrangeOpAnalysisInfo;

#define INST_HANDLER(OPCODE_NAME) \
	static void _inst__##OPCODE_NAME(RzAnalysis *analysis, RzAnalysisOp *op, \
		ut64 addr, \
		PicMidrangeOpArgsVal *args)
#define INST_DECL(NAME, ARGS) \
	[PIC_MIDRANGE_OPCODE_##NAME] = { \
		PIC_MIDRANGE_OPCODE_##NAME, PIC_MIDRANGE_OP_ARGS_##ARGS, \
		_inst__##NAME, IL_LIFTER(NAME) \
	}

#include "pic_midrange_esil.inc"

static const PicMidrangeOpAnalysisInfo pic_midrange_op_analysis_info[] = {
	INST_DECL(NOP, NONE),
	INST_DECL(RETURN, NONE),
	INST_DECL(RETFIE, NONE),
	INST_DECL(OPTION, NONE),
	INST_DECL(SLEEP, NONE),
	INST_DECL(CLRWDT, NONE),
	INST_DECL(TRIS, 2F),
	INST_DECL(MOVWF, 7F),
	INST_DECL(CLR, 1D_7F),
	INST_DECL(SUBWF, 1D_7F),
	INST_DECL(DECF, 1D_7F),
	INST_DECL(IORWF, 1D_7F),
	INST_DECL(ANDWF, 1D_7F),
	INST_DECL(XORWF, 1D_7F),
	INST_DECL(ADDWF, 1D_7F),
	INST_DECL(MOVF, 1D_7F),
	INST_DECL(COMF, 1D_7F),
	INST_DECL(INCF, 1D_7F),
	INST_DECL(DECFSZ, 1D_7F),
	INST_DECL(RRF, 1D_7F),
	INST_DECL(RLF, 1D_7F),
	INST_DECL(SWAPF, 1D_7F),
	INST_DECL(INCFSZ, 1D_7F),
	INST_DECL(BCF, 3B_7F),
	INST_DECL(BSF, 3B_7F),
	INST_DECL(BTFSC, 3B_7F),
	INST_DECL(BTFSS, 3B_7F),
	INST_DECL(CALL, 11K),
	INST_DECL(GOTO, 11K),
	INST_DECL(MOVLW, 8K),
	INST_DECL(RETLW, 8K),
	INST_DECL(IORLW, 8K),
	INST_DECL(ANDLW, 8K),
	INST_DECL(XORLW, 8K),
	INST_DECL(SUBLW, 8K),
	INST_DECL(ADDLW, 8K),
	INST_DECL(RESET, NONE),
	INST_DECL(CALLW, NONE),
	INST_DECL(BRW, NONE),
	INST_DECL(MOVIW_1, 1N_2M),
	INST_DECL(MOVWI_1, 1N_2M),
	INST_DECL(MOVLB, 4K),
	INST_DECL(LSLF, 1D_7F),
	INST_DECL(LSRF, 1D_7F),
	INST_DECL(ASRF, 1D_7F),
	INST_DECL(SUBWFB, 1D_7F),
	INST_DECL(ADDWFC, 1D_7F),
	INST_DECL(ADDFSR, 1N_6K),
	INST_DECL(MOVLP, 7F),
	INST_DECL(BRA, 9K),
	INST_DECL(MOVIW_2, 1N_6K),
	INST_DECL(MOVWI_2, 1N_6K),
	INST_DECL(CLRF, 7F),
};

static void analysis_pic_midrange_extract_args(
	ut16 instr,
	PicMidrangeOpArgs args,
	PicMidrangeOpArgsVal *args_val) {

	memset(args_val, 0, sizeof(PicMidrangeOpArgsVal));

	switch (args) {
	case PIC_MIDRANGE_OP_ARGS_NONE: return;
	case PIC_MIDRANGE_OP_ARGS_2F:
		args_val->f = instr & PIC_MIDRANGE_OP_ARGS_2F_MASK_F;
		return;
	case PIC_MIDRANGE_OP_ARGS_7F:
		args_val->f = instr & PIC_MIDRANGE_OP_ARGS_7F_MASK_F;
		return;
	case PIC_MIDRANGE_OP_ARGS_1D_7F:
		args_val->f = instr & PIC_MIDRANGE_OP_ARGS_1D_7F_MASK_F;
		args_val->d =
			(instr & PIC_MIDRANGE_OP_ARGS_1D_7F_MASK_D) >> 7;
		return;
	case PIC_MIDRANGE_OP_ARGS_1N_6K:
		args_val->n =
			(instr & PIC_MIDRANGE_OP_ARGS_1N_6K_MASK_N) >> 6;
		args_val->k = instr & PIC_MIDRANGE_OP_ARGS_1N_6K_MASK_K;
		return;
	case PIC_MIDRANGE_OP_ARGS_3B_7F:
		args_val->b =
			(instr & PIC_MIDRANGE_OP_ARGS_3B_7F_MASK_B) >> 7;
		args_val->f = instr & PIC_MIDRANGE_OP_ARGS_3B_7F_MASK_F;
		return;
	case PIC_MIDRANGE_OP_ARGS_4K:
		args_val->k = instr & PIC_MIDRANGE_OP_ARGS_4K_MASK_K;
		return;
	case PIC_MIDRANGE_OP_ARGS_8K:
		args_val->k = instr & PIC_MIDRANGE_OP_ARGS_8K_MASK_K;
		return;
	case PIC_MIDRANGE_OP_ARGS_9K:
		args_val->k = instr & PIC_MIDRANGE_OP_ARGS_9K_MASK_K;
		return;
	case PIC_MIDRANGE_OP_ARGS_11K:
		args_val->k = instr & PIC_MIDRANGE_OP_ARGS_11K_MASK_K;
		return;
	case PIC_MIDRANGE_OP_ARGS_1N_2M:
		args_val->n =
			(instr & PIC_MIDRANGE_OP_ARGS_1N_2M_MASK_N) >> 2;
		args_val->m = instr & PIC_MIDRANGE_OP_ARGS_1N_2M_MASK_M;
		return;
	}
}

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

static bool pic_midrange_reg_write(RzReg *reg, const char *regname, ut32 num) {
	if (reg) {
		RzRegItem *item = rz_reg_get(reg, regname, RZ_REG_TYPE_GPR);
		if (item) {
			rz_reg_set_value(reg, item, num);
			return true;
		}
	}
	return false;
}

static void analysis_pic_midrange_setup(RzAnalysis *analysis, bool force) {
	PicContext *ctx = (PicContext *)analysis->plugin_data;

	if (!ctx->init_done || force) {
		// Allocate memory as needed.
		// We assume that code is already allocated with firmware
		// image
		ctx->mem_sram =
			cpu_memory_map(&analysis->iob, ctx->mem_sram,
				PIC_MIDRANGE_ESIL_SRAM_START, 0x1000);
		ctx->mem_stack =
			cpu_memory_map(&analysis->iob, ctx->mem_sram,
				PIC_MIDRANGE_ESIL_CSTACK_TOP, 0x20);

		pic_midrange_reg_write(analysis->reg, "_sram",
			PIC_MIDRANGE_ESIL_SRAM_START);
		pic_midrange_reg_write(analysis->reg, "_stack",
			PIC_MIDRANGE_ESIL_CSTACK_TOP);
		pic_midrange_reg_write(analysis->reg, "stkptr", 0x1f);

		ctx->init_done = true;
	}
}

static int analysis_pic_midrange_op(
	RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {

	if (!buf || len < 2) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		return op->size;
	}

	analysis_pic_midrange_setup(analysis, false);
	ut16 instr = rz_read_le16(buf);
	// Default op params
	op->size = 2;
	op->cycles = 1;
	op->type = RZ_ANALYSIS_OP_TYPE_NOP;

	PicMidrangeOpcode opcode = pic_midrange_get_opcode(instr);
	PicMidrangeOpArgsVal args_val;

	if (opcode < RZ_ARRAY_SIZE(pic_midrange_op_analysis_info)) {
		const PicMidrangeOpAnalysisInfo *info = pic_midrange_op_analysis_info + opcode;
		if (!info) {
			return -1;
		}
		analysis_pic_midrange_extract_args(
			instr, info->args,
			&args_val);
		if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
			info->handler(analysis, op, addr, &args_val);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			PicMidrangeILContext il_ctx = {
				.analysis = analysis,
				.op = op,
				.args = args_val,
				.addr = addr,
				.d = instr,
			};
			rz_pic_midrange_cpu_state_setup(&il_ctx.cpu, PIC16F886);
			op->il_op = info->il_handler(&il_ctx, opcode);
		}
	}

	return op->size;
}

static char *analysis_pic_midrange_get_reg_profile(RzAnalysis *a) {
	const char *p =
		"=PC	pc\n"
		"=SP	stkptr\n"
		"=A0	porta\n"
		"=A1	portb\n"
		"gpr	indf0	.8	0	0\n"
		"gpr	indf1	.8	1	0\n"
		"gpr	pcl		.8	2	0\n"
		"gpr	status	.8	3	0\n"
		"flg	c		.1	3.0	0\n"
		"flg	dc		.1	3.1	0\n"
		"flg	z		.1	3.2	0\n"
		"flg	pd		.1	3.3	0\n"
		"flg	to		.1	3.4	0\n"
		"gpr	fsr0l	.8	4	0\n"
		"gpr	fsr0h	.8	5	0\n"
		"gpr	fsr1l	.8	6	0\n"
		"gpr	fsr1h	.8	7	0\n"
		"gpr	bsr		.8	8	0\n"
		"gpr	wreg	.8	9	0\n"
		"gpr	pclath	.8	10	0\n"
		"gpr	intcon	.8	11	0\n"
		"gpr	pc		.16	12	0\n"
		"gpr	stkptr	.8	14	0\n"
		"gpr	_sram	.32 15	0\n"
		"gpr	_stack	.32 19	0\n";
	return strdup(p);
}
