// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_lib.h>
#include <rz_types.h>

#include "cris/cris.h"

static CrisIsaVersion get_version(RzAnalysis *a) {
	const char *cpu = a->cpu;
	/* Prefer asm.cpu from config when analysis->cpu may still be arch name (e.g. "cris") */
	if (a->coreb.cfgGet && a->coreb.core) {
		const char *asm_cpu = a->coreb.cfgGet(a->coreb.core, "asm.cpu");
		if (asm_cpu && *asm_cpu) {
			cpu = asm_cpu;
		}
	}
	if (cpu && strstr(cpu, "v10")) {
		return CRIS_ISA_V10;
	}
	return CRIS_ISA_V32;
}

static int cris_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	CrisIsaVersion ver = get_version(a);
	CrisInsn insn;
	int ret = cris_decode(buf, len, &insn, ver);

	if (ret < 0) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->size = 2;
		return 2;
	}

	op->size = ret;
	op->addr = addr;

	switch (insn.type) {
	// Arithmetic
	case CRIS_INSN_ADD:
	case CRIS_INSN_ADDQ:
	case CRIS_INSN_ADDS:
	case CRIS_INSN_ADDU:
	case CRIS_INSN_ADD_M:
	case CRIS_INSN_ADDS_M:
	case CRIS_INSN_ADDU_M:
	case CRIS_INSN_ADDC:
	case CRIS_INSN_ADDI:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case CRIS_INSN_SUB:
	case CRIS_INSN_SUBQ:
	case CRIS_INSN_SUBS:
	case CRIS_INSN_SUBU:
	case CRIS_INSN_SUB_M:
	case CRIS_INSN_SUBS_M:
	case CRIS_INSN_SUBU_M:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case CRIS_INSN_CMP:
	case CRIS_INSN_CMPQ:
	case CRIS_INSN_CMPS:
	case CRIS_INSN_CMPU:
	case CRIS_INSN_CMP_M:
	case CRIS_INSN_CMPS_M:
	case CRIS_INSN_CMPU_M:
	case CRIS_INSN_BTST:
	case CRIS_INSN_BTSTQ:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;

	// Logic
	case CRIS_INSN_AND:
	case CRIS_INSN_ANDQ:
	case CRIS_INSN_AND_M:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case CRIS_INSN_OR:
	case CRIS_INSN_ORQ:
	case CRIS_INSN_OR_M:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case CRIS_INSN_XOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case CRIS_INSN_NOT:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case CRIS_INSN_NEG:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;

	// Move
	case CRIS_INSN_MOVE_R:
	case CRIS_INSN_MOVEQ:
	case CRIS_INSN_MOVS:
	case CRIS_INSN_MOVU:
	case CRIS_INSN_MOVE_RP:
	case CRIS_INSN_MOVE_PR:
	case CRIS_INSN_MOVE_RS:
	case CRIS_INSN_MOVE_SR:
	case CRIS_INSN_SWAP:
	case CRIS_INSN_ABS:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		if (insn.type == CRIS_INSN_MOVEQ) {
			op->val = insn.immediate;
		}
		break;

	// Load
	case CRIS_INSN_MOVE_MR:
	case CRIS_INSN_MOVEM_MR:
	case CRIS_INSN_MOVE_MP:
	case CRIS_INSN_MOVS_M:
	case CRIS_INSN_MOVU_M:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		if (insn.autoincr && insn.reg1 == 0xF) {
			op->ptr = (ut64)(ut32)insn.immediate;
		}
		break;

	// Store
	case CRIS_INSN_MOVE_RM:
	case CRIS_INSN_MOVEM_RM:
	case CRIS_INSN_MOVE_PM:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;

	// Shift
	case CRIS_INSN_ASR:
	case CRIS_INSN_ASRQ:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case CRIS_INSN_LSL:
	case CRIS_INSN_LSLQ:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case CRIS_INSN_LSR:
	case CRIS_INSN_LSRQ:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;

	// Multiply
	case CRIS_INSN_MULS:
	case CRIS_INSN_MULU:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;

	// Branch
	case CRIS_INSN_BCC_8:
	case CRIS_INSN_BCC_16:
		if (insn.cond == CRIS_CC_A) {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->jump = addr + insn.immediate;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = addr + insn.immediate;
			op->fail = addr + insn.size;
		}
		break;
	case CRIS_INSN_BA_DWORD:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = addr + insn.immediate;
		break;

	// Call
	case CRIS_INSN_BSR:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = addr + insn.immediate;
		op->fail = addr + insn.size;
		break;
	case CRIS_INSN_JSR_R:
		op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		break;
	case CRIS_INSN_JSR_N:
	case CRIS_INSN_JSR_M:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = (ut64)(ut32)insn.immediate;
		op->fail = addr + insn.size;
		break;
	case CRIS_INSN_JAS:
	case CRIS_INSN_JASC:
	case CRIS_INSN_BAS:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		if (insn.size > 2) {
			op->jump = (ut64)(ut32)insn.immediate;
		}
		op->fail = addr + insn.size;
		break;

	// Jump
	case CRIS_INSN_JUMP_R:
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		break;
	case CRIS_INSN_JUMP_P:
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		break;
	case CRIS_INSN_JUMP_N:
	case CRIS_INSN_JUMP_M:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = (ut64)(ut32)insn.immediate;
		break;

	// Return
	case CRIS_INSN_RET:
	case CRIS_INSN_RETI:
	case CRIS_INSN_RETE:
	case CRIS_INSN_RETN:
	case CRIS_INSN_RETB:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;

	// LEA-like
	case CRIS_INSN_LAPC:
	case CRIS_INSN_LAPCQ:
		op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		op->ptr = addr + insn.immediate;
		break;

	// Address offset (v32)
	case CRIS_INSN_ADDOQ:
	case CRIS_INSN_ADDO:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;

	// Prefix (v10)
	case CRIS_INSN_BDAP_Q:
	case CRIS_INSN_BDAP:
	case CRIS_INSN_BIAP:
	case CRIS_INSN_DIP:
		op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		break;

	// Scc
	case CRIS_INSN_SCC:
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		break;

	// Special
	case CRIS_INSN_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case CRIS_INSN_BREAK:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		op->val = insn.immediate;
		break;
	case CRIS_INSN_HALT:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case CRIS_INSN_SETF:
	case CRIS_INSN_CLEARF:
	case CRIS_INSN_EI:
	case CRIS_INSN_DI:
	case CRIS_INSN_AX:
	case CRIS_INSN_RFE:
	case CRIS_INSN_RFG:
	case CRIS_INSN_RFN:
	case CRIS_INSN_SFE:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// Clear/Test
	case CRIS_INSN_CLEAR_R:
	case CRIS_INSN_CLEAR_M:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case CRIS_INSN_TEST_M:
	case CRIS_INSN_MOVE_R_TEST:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;

	// Misc
	case CRIS_INSN_BOUND:
	case CRIS_INSN_BOUND_M:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case CRIS_INSN_DSTEP:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case CRIS_INSN_LZ:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case CRIS_INSN_MCP:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// FIDX/FTAG
	case CRIS_INSN_FIDXI:
	case CRIS_INSN_FIDXD:
	case CRIS_INSN_FTAGD:
	case CRIS_INSN_FTAGI:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;

	case CRIS_INSN_ADDC_M:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;

	default:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}

	// Disassembly
	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		cris_disassemble(&insn, &sb, ver);
		op->mnemonic = rz_strbuf_drain_nofree(&sb);
	}

	// ESIL
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		cris_esil(&insn, &op->esil, addr, ver);
	}

	// RzIL
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		CrisILContext ctx = {
			.a = a,
			.insn = insn,
			.pc = addr,
			.ver = ver,
		};
		op->il_op = cris_il_op(&ctx);
	}

	return ret;
}

static char *cris_get_reg_profile(RzAnalysis *a) {
	CrisIsaVersion ver = get_version(a);

	if (ver == CRIS_ISA_V32) {
		const char *p =
			"=PC	pc\n"
			"=SP	sp\n"
			"=BP	srp\n"
			"=SN	r10\n"
			"=A0	r10\n"
			"=A1	r11\n"
			"=A2	r12\n"
			"=A3	r13\n"
			// GPR
			"gpr	r0	.32	0	0\n"
			"gpr	r1	.32	4	0\n"
			"gpr	r2	.32	8	0\n"
			"gpr	r3	.32	12	0\n"
			"gpr	r4	.32	16	0\n"
			"gpr	r5	.32	20	0\n"
			"gpr	r6	.32	24	0\n"
			"gpr	r7	.32	28	0\n"
			"gpr	r8	.32	32	0\n"
			"gpr	r9	.32	36	0\n"
			"gpr	r10	.32	40	0\n"
			"gpr	r11	.32	44	0\n"
			"gpr	r12	.32	48	0\n"
			"gpr	r13	.32	52	0\n"
			"gpr	sp	.32	56	0\n"
			"gpr	acr	.32	60	0\n"
			// Special registers
			"gpr	pc	.32	64	0\n"
			"gpr	srp	.32	68	0\n"
			"gpr	mof	.32	72	0\n"
			"gpr	ccs	.32	76	0\n"
			"gpr	pid	.32	80	0\n"
			"gpr	srs	.32	84	0\n"
			"gpr	ebp	.32	88	0\n"
			"gpr	erp	.32	92	0\n"
			"gpr	nrp	.32	96	0\n"
			"gpr	usp	.32	100	0\n"
			"gpr	spc	.32	104	0\n"
			"gpr	exs	.32	108	0\n"
			"gpr	eda	.32	112	0\n"
			"gpr	vr	.32	116	0\n"
			// Flags
			"flg	C	.1	76.0	0\n"
			"flg	V	.1	76.1	0\n"
			"flg	Z	.1	76.2	0\n"
			"flg	N	.1	76.3	0\n";
		return rz_str_dup(p);
	}

	// v10
	const char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP	srp\n"
		"=SN	r10\n"
		"=A0	r10\n"
		"=A1	r11\n"
		"=A2	r12\n"
		"=A3	r13\n"
		// GPR
		"gpr	r0	.32	0	0\n"
		"gpr	r1	.32	4	0\n"
		"gpr	r2	.32	8	0\n"
		"gpr	r3	.32	12	0\n"
		"gpr	r4	.32	16	0\n"
		"gpr	r5	.32	20	0\n"
		"gpr	r6	.32	24	0\n"
		"gpr	r7	.32	28	0\n"
		"gpr	r8	.32	32	0\n"
		"gpr	r9	.32	36	0\n"
		"gpr	r10	.32	40	0\n"
		"gpr	r11	.32	44	0\n"
		"gpr	r12	.32	48	0\n"
		"gpr	r13	.32	52	0\n"
		"gpr	sp	.32	56	0\n"
		"gpr	pc	.32	60	0\n"
		// Special registers
		"gpr	srp	.32	64	0\n"
		"gpr	mof	.32	68	0\n"
		"gpr	dccr	.32	72	0\n"
		"gpr	ibr	.32	76	0\n"
		"gpr	irp	.32	80	0\n"
		"gpr	bar	.32	84	0\n"
		"gpr	brp	.32	88	0\n"
		"gpr	usp	.32	92	0\n"
		"gpr	ccr	.32	96	0\n"
		"gpr	vr	.32	100	0\n"
		// Flags (in DCCR)
		"flg	C	.1	72.0	0\n"
		"flg	V	.1	72.1	0\n"
		"flg	Z	.1	72.2	0\n"
		"flg	N	.1	72.3	0\n";
	return rz_str_dup(p);
}

RzAnalysisPlugin rz_analysis_plugin_cris = {
	.name = "cris",
	.desc = "Axis Communications CRIS analysis plugin",
	.license = "LGPL3",
	.author = "RizinOrg",
	.arch = "cris",
	.bits = 32,
	.esil = true,
	.op = &cris_op,
	.get_reg_profile = &cris_get_reg_profile,
	.il_config = cris_il_config,
};
