// SPDX-FileCopyrightText: 2015-2018 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2015-2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2015-2018 courk <courk@courk.cc>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pic_pic18.h"
#include "pic18_esil.inc"

typedef struct {
	const Pic18Op *op;
	const HtSU *mm;
} Pic18ILContext;

#include "pic18_il.inc"

static void pic18_cond_branch(RzAnalysisOp *aop, ut64 addr, const ut8 *buf) {
	aop->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	aop->jump = addr + 2 + 2 * (*(ut16 *)buf & 0xff);
	aop->fail = addr + aop->size;
	aop->cycles = 2;
}

static int analysis_pic18_op(
	RzAnalysis *analysis, RzAnalysisOp *aop, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {

	aop->size = 2;
	Pic18Op op = { 0 };
	if (!pic18_disasm_op(&op, addr, buf, len)) {
		goto err;
	}
	aop->size = op.size;
	switch (op.code) {
	case PIC18_OPCODE_CALL:
	case PIC18_OPCODE_RCALL:
		aop->type = RZ_ANALYSIS_OP_TYPE_CALL;
		break;
	case PIC18_OPCODE_BRA: // bra
		aop->type = RZ_ANALYSIS_OP_TYPE_JMP;
		aop->cycles = 2;
		aop->jump = addr + 2 + 2 * (*(ut16 *)buf & 0x7ff);
		break;
	case PIC18_OPCODE_MOVFF: // movff
		aop->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case PIC18_OPCODE_BTFSC: // btfsc
	case PIC18_OPCODE_BTFSS: // btfss
		aop->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case PIC18_OPCODE_BCF: // bcf
	case PIC18_OPCODE_BSF: // bsf
	case PIC18_OPCODE_BTG: // btg
		aop->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case PIC18_OPCODE_BZ: // bz
		pic18_cond_branch(aop, addr, buf);
		break;
	case PIC18_OPCODE_BNZ: // bnz
		pic18_cond_branch(aop, addr, buf);
		break;
	case PIC18_OPCODE_BNC: // bnc
		pic18_cond_branch(aop, addr, buf);
		break;
	case PIC18_OPCODE_BOV: // bov
		pic18_cond_branch(aop, addr, buf);
		break;
	case PIC18_OPCODE_BNOV: // bnov
		pic18_cond_branch(aop, addr, buf);
		break;
	case PIC18_OPCODE_BN: // bn
		pic18_cond_branch(aop, addr, buf);
		break;
	case PIC18_OPCODE_BNN: // bnn
		pic18_cond_branch(aop, addr, buf);
		break;
	case PIC18_OPCODE_BC: // bc
		pic18_cond_branch(aop, addr, buf);
		break;
	case PIC18_OPCODE_GOTO: // goto
		aop->cycles = 2;
		aop->jump = op.k;
		aop->type = RZ_ANALYSIS_OP_TYPE_JMP;
		break;
	case PIC18_OPCODE_ADDLW: // addlw
		aop->type = RZ_ANALYSIS_OP_TYPE_ADD;
		aop->cycles = 1;
		break;
	case PIC18_OPCODE_MOVLW: // movlw
		aop->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		aop->cycles = 1;
		break;
	case PIC18_OPCODE_MULLW: // mullw
		aop->type = RZ_ANALYSIS_OP_TYPE_MUL;
		aop->cycles = 1;
		break;
	case PIC18_OPCODE_RETLW: // retlw
		aop->type = RZ_ANALYSIS_OP_TYPE_RET;
		aop->cycles = 2;
		break;
	case PIC18_OPCODE_ANDLW: // andlw
		aop->type = RZ_ANALYSIS_OP_TYPE_AND;
		aop->cycles = 1;
		break;
	case PIC18_OPCODE_XORLW: // xorlw
		aop->type = RZ_ANALYSIS_OP_TYPE_XOR;
		aop->cycles = 1;
		break;
	case PIC18_OPCODE_IORLW: // iorlw
		aop->type = RZ_ANALYSIS_OP_TYPE_OR;
		aop->cycles = 1;
		break;
	case PIC18_OPCODE_SUBLW: // sublw
		aop->type = RZ_ANALYSIS_OP_TYPE_SUB;
		aop->cycles = 1;
		break;
	case PIC18_OPCODE_LFSR: // lfsr
		aop->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case PIC18_OPCODE_SUBWF: // subwf
	case PIC18_OPCODE_SUBFWB: // subwfb
	case PIC18_OPCODE_SUBWFB: // subfwb
	case PIC18_OPCODE_DCFSNZ: // dcfsnz
	case PIC18_OPCODE_DECFSZ: // decfsz
	case PIC18_OPCODE_DECF: // decf
		aop->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case PIC18_OPCODE_MOVF: // movf
		aop->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case PIC18_OPCODE_INFSNZ: // infsnz
	case PIC18_OPCODE_INCFSZ: // incfsz
	case PIC18_OPCODE_INCF: // incf
	case PIC18_OPCODE_ADDWFC: // addwfc
		aop->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case PIC18_OPCODE_ADDWF: // addwf
		aop->cycles = 1;
		aop->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case PIC18_OPCODE_RLNCF: // rlncf
	case PIC18_OPCODE_RLCF: // rlcf
		aop->type = RZ_ANALYSIS_OP_TYPE_ROL;
		break;
	case PIC18_OPCODE_RRNCF: // rrncf
	case PIC18_OPCODE_RRCF: // rrcf
		aop->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;
	case PIC18_OPCODE_SWAPF: // swapf
		aop->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case PIC18_OPCODE_COMF: // comf
		aop->type = RZ_ANALYSIS_OP_TYPE_CPL;
		break;
	case PIC18_OPCODE_XORWF: // xorwf
		aop->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case PIC18_OPCODE_ANDWF: // andwf
		aop->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case PIC18_OPCODE_IORWF: // iorwf
		aop->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case PIC18_OPCODE_MOVWF: // movwf
		aop->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case PIC18_OPCODE_NEGF: // negf
	case PIC18_OPCODE_CLRF: // clrf
	case PIC18_OPCODE_SETF: // setf
		aop->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case PIC18_OPCODE_TSTFSZ: // tstfsz
		aop->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case PIC18_OPCODE_CPFSGT: // cpfsgt
	case PIC18_OPCODE_CPFSEQ: // cpfseq
	case PIC18_OPCODE_CPFSLT: // cpfslt
		aop->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case PIC18_OPCODE_MULWF: // mulwf
		aop->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case PIC18_OPCODE_MOVLB: // movlb
		aop->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		aop->cycles = 1;
		break;
	case PIC18_OPCODE_RESET: // reset
	case PIC18_OPCODE_DAW: // daw
			       //	case CLWDT // clwdt
	case PIC18_OPCODE_SLEEP: // sleep
		aop->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case PIC18_OPCODE_RETURN: // return
		aop->type = RZ_ANALYSIS_OP_TYPE_RET;
		aop->cycles = 2;
		break;
	case PIC18_OPCODE_RETFIE: // retfie
		aop->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case PIC18_OPCODE_TBLWTMs: // tblwt
	case PIC18_OPCODE_TBLWTMsi: // tblwt
	case PIC18_OPCODE_TBLWTis: // tblwt
	case PIC18_OPCODE_TBLWTMsd: // tblwt
		aop->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case PIC18_OPCODE_TBLRDis: // tblrd
	case PIC18_OPCODE_TBLRDs: // tblrd
	case PIC18_OPCODE_TBLRDsi: // tblrd
	case PIC18_OPCODE_TBLRDsd: // tblrd
		aop->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case PIC18_OPCODE_POP: // pop
		aop->type = RZ_ANALYSIS_OP_TYPE_POP;
		break;
	case PIC18_OPCODE_PUSH: // push
		aop->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case PIC18_OPCODE_NOP: // nop
		aop->type = RZ_ANALYSIS_OP_TYPE_NOP;
		aop->cycles = 1;
		break;
	default:
		goto err;
	}

	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		pic18_esil(aop, &op, addr, buf);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		Pic18ILContext ctx = {
			.op = &op,
			.mm = ((PicContext *)analysis->plugin_data)->pic18_mm,
		};
		aop->il_op = pic18_il(&ctx);
	}

	return aop->size;
err:
	aop->type = RZ_ANALYSIS_OP_TYPE_ILL;
	return aop->size;
}

static char *analysis_pic_pic18_get_reg_profile(RzAnalysis *esil) {
	const char *p =
		"#pc lives in nowhere actually\n"
		"=PC	pc\n"
		"=SP	tos\n"
		"=A0	porta\n"
		"=A1	portb\n"
		"gpr	pc	.32	0	0\n"
		"gpr	pcl	.8	0	0\n"
		"gpr	pclath	.8	1	0\n"
		"gpr	pclatu	.8	2	0\n"
		"#bsr max is 0b111\n"
		"gpr	bsr	.8	4	0\n"
		"#tos doesn't exist\n"
		"#general rule of thumb any register of size >8 bits has no existence\n"
		"gpr	tos	.32	5	0\n"
		"gpr	tosl	.8	5	0\n"
		"gpr	tosh	.8	6	0\n"
		"gpr	tosu	.8	7	0\n"

		"gpr	indf0	.16	9	0\n"
		"gpr	fsr0	.12	9	0\n"
		"gpr	fsr0l	.8	9	0\n"
		"gpr	fsr0h	.8	10	0\n"
		"gpr	indf1	.16	11	0\n"
		"gpr	fsr1	.12	11	0\n"
		"gpr	fsr1l	.8	11	0\n"
		"gpr	fsr1h	.8	12	0\n"
		"gpr	indf2	.16	13	0\n"
		"gpr	fsr2	.12	13	0\n"
		"gpr	frs2l	.8	13	0\n"
		"gpr	fsr2h	.8	14	0\n"
		"gpr	tblptr	.22	15	0\n"
		"gpr	tblptrl	.8	15	0\n"
		"gpr	tblptrh	.8	16	0\n"
		"gpr	tblptru	.8	17	0\n"
		"gpr	rcon	.8	18	0\n"
		"gpr	memcon	.8	19	0\n"
		"gpr	intcon	.8	20	0\n"
		"gpr	intcon2	.8	21	0\n"
		"gpr	intcon3	.8	22	0\n"
		"gpr	pie1	.8	23	0\n"
		"gpr	porta	.7	29	0\n"
		"gpr	trisa	.8	30	0\n"
		"gpr	portb	.8	33	0\n"
		"gpr	tisb	.8	34	0\n"
		"gpr	latb	.8	35	0\n"
		"gpr	portc	.8	36	0\n"
		"gpr	trisc	.8	37	0\n"
		"gpr	latc	.8	38	0\n"
		"gpr	portd	.8	39	0\n"
		"gpr	trisd	.8	40	0\n"
		"gpr	latd	.8	41	0\n"
		"gpr	pspcon	.8	42	0\n"
		"gpr	porte	.8	43	0\n"
		"gpr	trise	.8	44	0\n"
		"gpr	late	.8	45	0\n"
		"gpr	t0con	.8	46	0\n"
		"gpr	t1con	.8	47	0\n"
		"gpr	t2con	.8	48	0\n"
		"gpr	tmr1h	.8	50	0\n"
		"gpr	tmr0h	.8	51	0\n"
		"gpr	tmr1l	.8	52	0\n"
		"gpr	tmr2	.8	53	0\n"
		"gpr	pr2	.8	54	0\n"
		"gpr	ccpr1h	.8	55	0\n"
		"gpr	postinc2 .8	56	0\n"
		"gpr	ccpr1l	.8	57	0\n"
		"gpr	postdec2 .8	58	0\n"
		"gpr	ccp1con	.8	59	0\n"
		"gpr	preinc2	.8	60	0\n"
		"gpr	ccpr2h	.8	61	0\n"
		"gpr	plusw2	.8	62	0\n"
		"gpr	ccpr2l	.8	63	0\n"
		"gpr	ccp2con	.8	64	0\n"
		"gpr	status	.8	65	0\n"
		"flg	c	.1	.520	0\n"
		"flg	dc	.1	.521	0\n"
		"flg	z	.1	.522	0\n"
		"flg	ov	.1	.523	0\n"
		"flg	n	.1	.524	0\n"
		"gpr	prod	.16	66	0\n"
		"gpr	prodl	.8	66	0\n"
		"gpr	prodh	.8	67	0\n"
		"gpr	osccon	.8	68	0\n"
		"gpr	tmr3h	.8	69	0\n"
		"gpr	lvdcon	.8	70	0\n"
		"gpr	tmr3l	.8	71	0\n"
		"gpr	wdtcon	.8	72	0\n"
		"gpr	t3con	.8	73	0\n"
		"gpr	spbrg	.8	74	0\n"
		"gpr	postinc0 .8	75	0\n"
		"gpr	rcreg	.8	76	0\n"
		"gpr	postdec0 .8	77	0\n"
		"gpr	txreg	.8	78	0\n"
		"gpr	preinc0	.8	79	0\n"
		"gpr	txsta	.8	80	0\n"
		"gpr	plusw0	.8	81	0\n"
		"gpr	rcsta	.8	82	0\n"
		"gpr	sspbuf	.8	83	0\n"
		"gpr	wreg	.8	84	0\n"
		"gpr	sspadd	.8	85	0\n"
		"gpr	sspstat	.8	86	0\n"
		"gpr	postinc1 .8	87	0\n"
		"gpr	sspcon1	.8	88	0\n"
		"gpr	postdec1 .8	89	0\n"
		"gpr	sspcon2	.8	90	0\n"
		"gpr	preinc1	.8	91	0\n"
		"gpr	adresh	.8	92	0\n"
		"gpr	plusw1	.8	93	0\n"
		"gpr	adresl	.8	94	0\n"
		"gpr	adcon0	.8	95	0\n"
		"#stkprt max is 0b11111\n"
		"gpr	stkptr	.8	96	0\n"
		"gpr	tblat	.8	14	0\n"
		"gpr	_sram	.8	98	0\n"
		"gpr	_stack	.8	99	0\n";
	return strdup(p);
}
