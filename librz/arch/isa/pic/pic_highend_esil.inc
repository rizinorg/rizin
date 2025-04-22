// SPDX-FileCopyrightText: 2015-2018 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2015-2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2015-2018 courk <courk@courk.cc>
// SPDX-License-Identifier: LGPL-3.0-only

static void pic_highend_cond_branch_esil(RzAnalysisOp *aop, ut64 addr, const ut8 *buf, char *flag) {
	rz_strbuf_setf(&aop->esil, "%s,?,{,0x%" PFMT64x ",pc,=,}", flag, aop->jump);
}

static void pic_highend_esil(
	RzAnalysisOp *aop, PicHighendOp *op, ut64 addr, const ut8 *buf) {
	switch (op->code) {
	case PIC_HIGHEND_OPCODE_BRA: // bra
		rz_strbuf_setf(&aop->esil, "0x%" PFMT64x ",pc,=", aop->jump);
		break;
	case PIC_HIGHEND_OPCODE_BZ: // bz
		pic_highend_cond_branch_esil(aop, addr, buf, "z");
		break;
	case PIC_HIGHEND_OPCODE_BNZ: // bnz
		pic_highend_cond_branch_esil(aop, addr, buf, "z,!");
		break;
	case PIC_HIGHEND_OPCODE_BNC: // bnc
		pic_highend_cond_branch_esil(aop, addr, buf, "c,!");
		break;
	case PIC_HIGHEND_OPCODE_BOV: // bov
		pic_highend_cond_branch_esil(aop, addr, buf, "ov");
		break;
	case PIC_HIGHEND_OPCODE_BNOV: // bnov
		pic_highend_cond_branch_esil(aop, addr, buf, "ov,!");
		break;
	case PIC_HIGHEND_OPCODE_BN: // bn
		pic_highend_cond_branch_esil(aop, addr, buf, "n");
		break;
	case PIC_HIGHEND_OPCODE_BNN: // bnn
		pic_highend_cond_branch_esil(aop, addr, buf, "n,!");
		break;
	case PIC_HIGHEND_OPCODE_BC: // bc
		pic_highend_cond_branch_esil(aop, addr, buf, "c");
		break;
	case PIC_HIGHEND_OPCODE_GOTO: // goto
		rz_strbuf_setf(&aop->esil, "0x%" PFMT64x ",pc,=", aop->jump);
		break;
	case PIC_HIGHEND_OPCODE_ADDLW: // addlw
		// TODO add support for dc flag
		rz_strbuf_setf(&aop->esil, "0x%" PFMT32x ",wreg,+=,$z,z,:=,7,$s,n,:=,7,$c,c,:=,7,$o,ov,:=,", (ut32)buf[0]);
		break;
	case PIC_HIGHEND_OPCODE_MOVLW: // movlw
		rz_strbuf_setf(&aop->esil, "0x%" PFMT32x ",wreg,=,", (ut32)buf[0]);
		break;
	case PIC_HIGHEND_OPCODE_MULLW: // mullw
		rz_strbuf_setf(&aop->esil, "0x%" PFMT32x ",wreg,*,prod,=", (ut32)buf[0]);
		break;
	case PIC_HIGHEND_OPCODE_RETLW: // retlw
		rz_strbuf_setf(&aop->esil, "0x%" PFMT32x ",wreg,=,tos,pc,=,", (ut32)buf[0]);
		break;
	case PIC_HIGHEND_OPCODE_ANDLW: // andlw
		rz_strbuf_setf(&aop->esil, "0x%" PFMT32x ",wreg,&=,$z,z,:=,7,$s,n,:=,", (ut32)buf[0]);
		break;
	case PIC_HIGHEND_OPCODE_XORLW: // xorlw
		rz_strbuf_setf(&aop->esil, "0x%" PFMT32x ",wreg,^=,$z,z,:=,7,$s,n,:=,", (ut32)buf[0]);
		break;
	case PIC_HIGHEND_OPCODE_IORLW: // iorlw
		rz_strbuf_setf(&aop->esil, "0x%" PFMT32x ",wreg,^=,$z,z,:=,7,$s,n,:=,", (ut32)buf[0]);
		break;
	case PIC_HIGHEND_OPCODE_SUBLW: // sublw
		// TODO add support for dc flag
		rz_strbuf_setf(&aop->esil, "wreg,0x%" PFMT32x ",-,wreg,=,$z,z,:=,7,$s,n,:=,7,$c,c,:=,7,$o,ov,:=,", (ut32)buf[0]);
		break;
	case PIC_HIGHEND_OPCODE_MOVLB: // movlb
		rz_strbuf_setf(&aop->esil, "0x%" PFMT32x ",bsr,=,", (ut32)(buf[0] & 0xf));
		break;
	case PIC_HIGHEND_OPCODE_RETURN: // return
		rz_strbuf_setf(&aop->esil, "tos,pc,=,");
		break;
	case PIC_HIGHEND_OPCODE_NOP: // nop
		rz_strbuf_setf(&aop->esil, ",");
		break;
	default: break;
	}
}
