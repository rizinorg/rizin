#include "h8300_disas.h"
#include <rz_il/rz_il_opbuilder_begin.h>

#define OPS_GET(I) (cmd->ops[(I)])

static const char *GPRs[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7"
};

RzILOpPure *r8_op(H8300Cmd *cmd, ut8 i) {
	H8300Operand *op = &OPS_GET(i);
	if (op->typ != H8300_OP_R8) {
		RZ_LOG_ERROR("invalid op type r8\n");
		return NULL;
	}
	ut8 index = op->reg % 8;
	bool low = op->reg & 8;
	RzILOpPure *x = VARG(GPRs[index]);
	return low ? UNSIGNED(8, x) : UNSIGNED(8, SHIFTR0(x, U8(8)));
}

RzILOpEffect *r8_op_set(H8300Cmd *cmd, ut8 i, RzILOpPure *x) {
	H8300Operand *op = &OPS_GET(i);
	if (op->typ != H8300_OP_R8) {
		RZ_LOG_ERROR("invalid op type r8\n");
		return NULL;
	}
	ut8 index = op->reg % 8;
	bool low = op->reg & 8;
	return SETG(GPRs[index],
		UNSIGNED(16, DEPOSIT32(UNSIGNED(32, VARG(GPRs[index])), low ? U32(0) : U32(8), U32(8), UNSIGNED(32, x))));
}

RzILOpPure *r16_op(H8300Cmd *cmd, ut8 i) {
	H8300Operand *op = &OPS_GET(i);
	if (op->typ != H8300_OP_R16 && op->typ != H8300_OP_RI16) {
		RZ_LOG_ERROR("invalid op type r16/ri16\n");
		return NULL;
	}
	ut8 index = op->reg % 8;
	return VARG(GPRs[index]);
}

RzILOpEffect *r16_op_set(H8300Cmd *cmd, ut8 i, RzILOpPure *x) {
	H8300Operand *op = &OPS_GET(i);
	if (op->typ != H8300_OP_R16) {
		RZ_LOG_ERROR("invalid op type r16\n");
		return NULL;
	}
	ut8 index = op->reg % 8;
	return SETG(GPRs[index], x);
}

RzILOpPure *u16_op(H8300Cmd *cmd, ut8 i) {
	H8300Operand *op = &OPS_GET(i);
	if (op->typ != H8300_OP_IMM && op->typ != H8300_OP_ABS) {
		RZ_LOG_ERROR("invalid op type imm/abs!=%d\n", op->typ);
		return NULL;
	}
	return U16(op->imm);
}

RzILOpPure *rd16_op(H8300Cmd *cmd, ut8 i) {
	H8300Operand *op = &OPS_GET(i);
	if (op->typ != H8300_OP_RD16) {
		RZ_LOG_ERROR("invalid op type rd16\n");
		return NULL;
	}
	return ADD(VARG(GPRs[op->rd.reg]), S16(op->rd.disp));
}

#define R8_OP(I)    r8_op(cmd, (I))
#define R8_X(I, X)  r8_op_set(cmd, (I), (X))
#define R16_OP(I)   r16_op(cmd, (I))
#define R16_X(I, X) r16_op_set(cmd, (I), (X))
#define U16_OP(I)   u16_op(cmd, (I))
#define U8_OP(I)    UNSIGNED(8, u16_op(cmd, (I)))
#define RD16_OP(I)  rd16_op(cmd, (I))

int h8300_analyze_op_il(RzAnalysis *a, RzAnalysisOp *op, H8300Cmd *cmd) {
	switch (cmd->id) {
	case H8300_INSN_MOV_B:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_R8R8:
			op->il_op = R8_X(1, R8_OP(0));
			break;
		case H8300_INSN_FORMAT_ABSR8:
			op->il_op = R8_X(1, LOAD(U16_OP(0)));
			break;
		case H8300_INSN_FORMAT_R8ABS:
			op->il_op = STORE(U16_OP(1), R8_OP(0));
			break;
		case H8300_INSN_FORMAT_IMMR8:
			op->il_op = R8_X(1, U8_OP(0));
			break;
		case H8300_INSN_FORMAT_R8RI16:
			op->il_op = STORE(R16_OP(1), R8_OP(0));
			break;
		case H8300_INSN_FORMAT_RI16R8:
			op->il_op = R8_X(1, LOAD(R16_OP(0)));
			break;
		case H8300_INSN_FORMAT_R8RD16:
			op->il_op = STORE(RD16_OP(1), R8_OP(0));
			break;
		case H8300_INSN_FORMAT_RD16R8:
			op->il_op = R8_X(1, LOAD(RD16_OP(0)));
			break;
		default: break;
		}

		break;
	case H8300_INSN_MOV_W: break;
	case H8300_INSN_ADD_B: break;
	case H8300_INSN_ADD_W: break;
	case H8300_INSN_ADDX: break;
	case H8300_INSN_CMP_B: break;
	case H8300_INSN_CMP_W: break;
	case H8300_INSN_SUB_B: break;
	case H8300_INSN_SUB_W: break;
	case H8300_INSN_SUBX: break;
	case H8300_INSN_OR: break;
	case H8300_INSN_XOR: break;
	case H8300_INSN_AND: break;
	case H8300_INSN_NOP: break;
	case H8300_INSN_SLEEP: break;
	case H8300_INSN_STC: break;
	case H8300_INSN_LDC: break;
	case H8300_INSN_ORC: break;
	case H8300_INSN_XORC: break;
	case H8300_INSN_ANDC: break;
	case H8300_INSN_INC: break;
	case H8300_INSN_ADDS: break;
	case H8300_INSN_DAA: break;
	case H8300_INSN_SHL: break;
	case H8300_INSN_SHR: break;
	case H8300_INSN_ROTL: break;
	case H8300_INSN_ROTR: break;
	case H8300_INSN_NEG: break;
	case H8300_INSN_DEC: break;
	case H8300_INSN_SUBS: break;
	case H8300_INSN_DAS: break;
	case H8300_INSN_BRA: break;
	case H8300_INSN_BRN: break;
	case H8300_INSN_BHI: break;
	case H8300_INSN_BLS: break;
	case H8300_INSN_BCC: break;
	case H8300_INSN_BCS: break;
	case H8300_INSN_BNE: break;
	case H8300_INSN_BEQ: break;
	case H8300_INSN_BVC: break;
	case H8300_INSN_BVS: break;
	case H8300_INSN_BPL: break;
	case H8300_INSN_BMI: break;
	case H8300_INSN_BGE: break;
	case H8300_INSN_BLT: break;
	case H8300_INSN_BGT: break;
	case H8300_INSN_BLE: break;
	case H8300_INSN_MULXU: break;
	case H8300_INSN_DIVXU: break;
	case H8300_INSN_RTS: break;
	case H8300_INSN_BSR: break;
	case H8300_INSN_RTE: break;
	case H8300_INSN_JMP: break;
	case H8300_INSN_JSR: break;
	case H8300_INSN_BSET: break;
	case H8300_INSN_BNOT: break;
	case H8300_INSN_BCLR: break;
	case H8300_INSN_BTST: break;
	case H8300_INSN_BST: break;
	case H8300_INSN_BST_BIST: break;
	case H8300_INSN_BOR_BIOR: break;
	case H8300_INSN_BXOR: break;
	case H8300_INSN_BAND: break;
	case H8300_INSN_BAND_BIAND: break;
	case H8300_INSN_BILD: break;
	case H8300_INSN_EEPMOV: break;
	case H8300_INSN_BIAND: break;
	case H8300_INSN_BIST: break;
	case H8300_INSN_BOR: break;
	case H8300_INSN_BIOR: break;
	case H8300_INSN_BIXOR: break;
	case H8300_INSN_BLD: break;
	}
	return 0;
}

RzAnalysisILConfig *h8300_il_config(RzAnalysis *a) {
	rz_return_val_if_fail(a, NULL);

	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(16, a->big_endian, 16);
	if (!cfg) {
		return NULL;
	}
	return cfg;
}
