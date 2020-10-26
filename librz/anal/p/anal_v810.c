// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_anal.h>
#include <rz_util.h>

#include <v810_disas.h>

enum {
	V810_FLAG_CY = 1,
	V810_FLAG_OV = 2,
	V810_FLAG_S = 4,
	V810_FLAG_Z = 8,
};

static void update_flags(RzAnalOp *op, int flags) {
	if (flags & V810_FLAG_CY) {
		rz_strbuf_append (&op->esil, ",31,$c,cy,:=");
	}
	if (flags & V810_FLAG_OV) {
		rz_strbuf_append (&op->esil, ",31,$o,ov,:=");
	}
	if (flags & V810_FLAG_S) {
		rz_strbuf_append (&op->esil, ",31,$s,s,:=");
	}
	if (flags & V810_FLAG_Z) {
		rz_strbuf_append (&op->esil, ",$z,z,:=");
	}
}

static void clear_flags(RzAnalOp *op, int flags) {
	if (flags & V810_FLAG_CY) {
		rz_strbuf_append (&op->esil, ",0,cy,:=");
	}
	if (flags & V810_FLAG_OV) {
		rz_strbuf_append (&op->esil, ",0,ov,:=");
	}
	if (flags & V810_FLAG_S) {
		rz_strbuf_append (&op->esil, ",0,s,:=");
	}
	if (flags & V810_FLAG_Z) {
		rz_strbuf_append (&op->esil, ",0,z,:=");
	}
}

static int v810_op(RzAnal *anal, RzAnalOp *op, ut64 addr, const ut8 *buf, int len, RzAnalOpMask mask) {
	int ret;
	ut8 opcode, reg1, reg2, imm5, cond;
	ut16 word1, word2 = 0;
	st32 jumpdisp;
	struct v810_cmd cmd;

	memset (&cmd, 0, sizeof(cmd));

	ret = op->size = v810_decode_command (buf, len, &cmd);
	if (ret <= 0) {
		return ret;
	}

	word1 = rz_read_ble16 (buf, anal->big_endian);

	if (ret == 4) {
		word2 = rz_read_ble16 (buf+2, anal->big_endian);
	}

	op->addr = addr;

	opcode = OPCODE(word1);
	if (opcode >> 3 == 0x4) {
		opcode &= 0x20;
	}

	switch (opcode) {
	case V810_MOV:
		op->type = RZ_ANAL_OP_TYPE_MOV;
		rz_strbuf_appendf (&op->esil, "r%u,r%u,=",
						 REG1(word1), REG2(word1));
		break;
	case V810_MOV_IMM5:
		op->type = RZ_ANAL_OP_TYPE_MOV;
		rz_strbuf_appendf (&op->esil, "%d,r%u,=",
						  (st8)SEXT5(IMM5(word1)), REG2(word1));
		break;
	case V810_MOVHI:
		op->type = RZ_ANAL_OP_TYPE_MOV;
		rz_strbuf_appendf (&op->esil, "16,%hu,<<,r%u,+,r%u,=",
						 word2, REG1(word1), REG2(word1));
		break;
	case V810_MOVEA:
		op->type = RZ_ANAL_OP_TYPE_MOV;
		rz_strbuf_appendf (&op->esil, "%hd,r%u,+,r%u,=",
						 word2, REG1(word1), REG2(word1));
		break;
	case V810_LDSR:
		op->type = RZ_ANAL_OP_TYPE_MOV;
		break;
	case V810_STSR:
		op->type = RZ_ANAL_OP_TYPE_MOV;
		break;
	case V810_NOT:
		op->type = RZ_ANAL_OP_TYPE_NOT;
		rz_strbuf_appendf (&op->esil, "r%u,0xffffffff,^,r%u,=",
						 REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_DIV:
	case V810_DIVU:
		op->type = RZ_ANAL_OP_TYPE_DIV;
		rz_strbuf_appendf (&op->esil, "r%u,r%u,/=,r%u,r%u,%%,r30,=",
						 REG1(word1), REG2(word1),
						 REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_OV | V810_FLAG_S | V810_FLAG_Z);
		break;
	case V810_JMP:
		if (REG1 (word1) == 31) {
			op->type = RZ_ANAL_OP_TYPE_RET;
		} else {
			op->type = RZ_ANAL_OP_TYPE_UJMP;
		}
		rz_strbuf_appendf (&op->esil, "r%u,pc,=",
						 REG1(word1));
		break;
	case V810_OR:
		op->type = RZ_ANAL_OP_TYPE_OR;
		rz_strbuf_appendf (&op->esil, "r%u,r%u,|=",
						 REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_ORI:
		op->type = RZ_ANAL_OP_TYPE_OR;
		rz_strbuf_appendf (&op->esil, "%hu,r%u,|,r%u,=",
						 word2, REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_MUL:
	case V810_MULU:
		op->type = RZ_ANAL_OP_TYPE_MUL;
		rz_strbuf_appendf (&op->esil, "r%u,r%u,*=,32,r%u,r%u,*,>>,r30,=",
						 REG1(word1), REG2(word1),
						 REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_OV | V810_FLAG_S | V810_FLAG_Z);
		break;
	case V810_XOR:
		op->type = RZ_ANAL_OP_TYPE_XOR;
		rz_strbuf_appendf (&op->esil, "r%u,r%u,^=",
						 REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_XORI:
		op->type = RZ_ANAL_OP_TYPE_XOR;
		rz_strbuf_appendf (&op->esil, "%hu,r%u,^,r%u,=",
						 word2, REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_AND:
		op->type = RZ_ANAL_OP_TYPE_AND;
		rz_strbuf_appendf (&op->esil, "r%u,r%u,&=",
						 REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_ANDI:
		op->type = RZ_ANAL_OP_TYPE_AND;
		rz_strbuf_appendf (&op->esil, "%hu,r%u,&,r%u,=",
						 word2, REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV | V810_FLAG_S);
		break;
	case V810_CMP:
		op->type = RZ_ANAL_OP_TYPE_CMP;
		rz_strbuf_appendf (&op->esil, "r%u,r%u,==",
						 REG1(word1), REG2(word1));
		update_flags (op, -1);
		break;
	case V810_CMP_IMM5:
		op->type = RZ_ANAL_OP_TYPE_CMP;
		rz_strbuf_appendf (&op->esil, "%d,r%u,==",
						  (st8)SEXT5(IMM5(word1)), REG2(word1));
		update_flags (op, -1);
		break;
	case V810_SUB:
		op->type = RZ_ANAL_OP_TYPE_SUB;
		rz_strbuf_appendf (&op->esil, "r%u,r%u,-=",
						 REG1(word1), REG2(word1));
		update_flags (op, -1);
		break;
	case V810_ADD:
		op->type = RZ_ANAL_OP_TYPE_ADD;
		rz_strbuf_appendf (&op->esil, "r%u,r%u,+=",
						 REG1(word1), REG2(word1));
		update_flags (op, -1);
		break;
	case V810_ADDI:
		op->type = RZ_ANAL_OP_TYPE_ADD;
		rz_strbuf_appendf (&op->esil, "%hd,r%u,+,r%u,=",
						 word2, REG1(word1), REG2(word1));
		update_flags (op, -1);
		break;
	case V810_ADD_IMM5:
		op->type = RZ_ANAL_OP_TYPE_ADD;
		rz_strbuf_appendf (&op->esil, "%d,r%u,+=",
						  (st8)SEXT5(IMM5(word1)), REG2(word1));
		update_flags(op, -1);
		break;
	case V810_SHR:
		op->type = RZ_ANAL_OP_TYPE_SHR;
		rz_strbuf_appendf (&op->esil, "r%u,r%u,>>=",
						 REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_CY | V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_SHR_IMM5:
		op->type = RZ_ANAL_OP_TYPE_SHR;
		rz_strbuf_appendf (&op->esil, "%u,r%u,>>=",
						  (ut8)IMM5(word1), REG2(word1));
		update_flags (op, V810_FLAG_CY | V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_SAR:
		op->type = RZ_ANAL_OP_TYPE_SAR;
		reg1 = REG1(word1);
		reg2 = REG2(word1);
		rz_strbuf_appendf (&op->esil, "31,r%u,>>,?{,r%u,32,-,r%u,1,<<,--,<<,}{,0,},r%u,r%u,>>,|,r%u,=",
						 reg2, reg1, reg1, reg1, reg2, reg2);
		update_flags (op, V810_FLAG_CY | V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_SAR_IMM5:
		op->type = RZ_ANAL_OP_TYPE_SAR;
		imm5 = IMM5(word1);
		reg2 = REG2(word1);
		rz_strbuf_appendf (&op->esil, "31,r%u,>>,?{,%u,32,-,%u,1,<<,--,<<,}{,0,},%u,r%u,>>,|,r%u,=",
						  reg2, (ut8)imm5, (ut8)imm5, (ut8)imm5, reg2, reg2);
		update_flags (op, V810_FLAG_CY | V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_SHL:
		op->type = RZ_ANAL_OP_TYPE_SHL;
		rz_strbuf_appendf (&op->esil, "r%u,r%u,<<=",
						 REG1(word1), REG2(word1));
		update_flags (op, V810_FLAG_CY | V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_SHL_IMM5:
		op->type = RZ_ANAL_OP_TYPE_SHL;
		rz_strbuf_appendf (&op->esil, "%u,r%u,<<=",
						  (ut8)IMM5(word1), REG2(word1));
		update_flags (op, V810_FLAG_CY | V810_FLAG_S | V810_FLAG_Z);
		clear_flags (op, V810_FLAG_OV);
		break;
	case V810_LDB:
		op->type = RZ_ANAL_OP_TYPE_LOAD;
		rz_strbuf_appendf (&op->esil, "r%u,%hd,+,[1],r%u,=",
						 REG1(word1), word2, REG2(word1));
		rz_strbuf_appendf (&op->esil, ",DUP,0x80,&,?{,0xffffff00,|,}");
		break;
	case V810_LDH:
		op->type = RZ_ANAL_OP_TYPE_LOAD;
		rz_strbuf_appendf (&op->esil, "r%u,%hd,+,0xfffffffe,&,[2],r%u,=",
						 REG1(word1), word2, REG2(word1));
		rz_strbuf_appendf (&op->esil, ",DUP,0x8000,&,?{,0xffffff00,|,}");
		break;
	case V810_LDW:
		op->type = RZ_ANAL_OP_TYPE_LOAD;
		rz_strbuf_appendf (&op->esil, "r%u,%hd,+,0xfffffffc,&,[4],r%u,=",
						 REG1(word1), word2, REG2(word1));
		rz_strbuf_appendf (&op->esil, ",DUP,0x80000000,&,?{,0xffffff00,|,}");
		break;
	case V810_STB:
		op->type = RZ_ANAL_OP_TYPE_STORE;
		rz_strbuf_appendf (&op->esil, "r%u,r%u,%hd,+,=[1]",
						 REG2(word1), REG1(word1), word2);
		break;
	case V810_STH:
		op->type = RZ_ANAL_OP_TYPE_STORE;
		rz_strbuf_appendf (&op->esil, "r%u,r%u,%hd,+,0xfffffffe,&,=[2]",
						 REG2(word1), REG1(word1), word2);
		break;
	case V810_STW:
		op->type = RZ_ANAL_OP_TYPE_STORE;
		rz_strbuf_appendf (&op->esil, "r%u,r%u,%hd,+,=[4]",
						 REG2(word1), REG1(word1), word2);
		break;
	case V810_INB:
	case V810_INH:
	case V810_INW:
	case V810_OUTB:
	case V810_OUTH:
	case V810_OUTW:
		op->type = RZ_ANAL_OP_TYPE_IO;
		break;
	case V810_TRAP:
		op->type = RZ_ANAL_OP_TYPE_TRAP;
		rz_strbuf_appendf (&op->esil, "%u,TRAP", IMM5(word1));
		break;
	case V810_RETI:
		op->type = RZ_ANAL_OP_TYPE_RET;
		//rz_strbuf_appendf (&op->esil, "np,?{,fepc,fepsw,}{,eipc,eipsw,},psw,=,pc,=");
		break;
	case V810_JAL:
	case V810_JR:
		jumpdisp = DISP26(word1, word2);
		op->jump = addr + jumpdisp;
		op->fail = addr + 4;

		if (opcode == V810_JAL) {
			op->type = RZ_ANAL_OP_TYPE_CALL;
			rz_strbuf_appendf (&op->esil, "$$,4,+,r31,=,");
		} else {
			op->type = RZ_ANAL_OP_TYPE_JMP;
		}

		rz_strbuf_appendf (&op->esil, "$$,%d,+,pc,=", jumpdisp);
		break;
	case V810_BCOND:
		cond = COND(word1);
		if (cond == V810_COND_NOP) {
			op->type = RZ_ANAL_OP_TYPE_NOP;
			break;
		}

		jumpdisp = DISP9(word1);
		op->jump = addr + jumpdisp;
		op->fail = addr + 2;
		op->type = RZ_ANAL_OP_TYPE_CJMP;

		switch (cond) {
		case V810_COND_V:
			rz_strbuf_appendf (&op->esil, "ov");
			break;
		case V810_COND_L:
			rz_strbuf_appendf (&op->esil, "cy");
			break;
		case V810_COND_E:
			rz_strbuf_appendf (&op->esil, "z");
			break;
		case V810_COND_NH:
			rz_strbuf_appendf (&op->esil, "cy,z,|");
			break;
		case V810_COND_N:
			rz_strbuf_appendf (&op->esil, "s");
			break;
		case V810_COND_NONE:
			rz_strbuf_appendf (&op->esil, "1");
			break;
		case V810_COND_LT:
			rz_strbuf_appendf (&op->esil, "s,ov,^");
			break;
		case V810_COND_LE:
			rz_strbuf_appendf (&op->esil, "s,ov,^,z,|");
			break;
		case V810_COND_NV:
			rz_strbuf_appendf (&op->esil, "ov,!");
			break;
		case V810_COND_NL:
			rz_strbuf_appendf (&op->esil, "cy,!");
			break;
		case V810_COND_NE:
			rz_strbuf_appendf (&op->esil, "z,!");
			break;
		case V810_COND_H:
			rz_strbuf_appendf (&op->esil, "cy,z,|,!");
			break;
		case V810_COND_P:
			rz_strbuf_appendf (&op->esil, "s,!");
			break;
		case V810_COND_GE:
			rz_strbuf_appendf (&op->esil, "s,ov,^,!");
			break;
		case V810_COND_GT:
			rz_strbuf_appendf (&op->esil, "s,ov,^,z,|,!");
			break;
		}
		rz_strbuf_appendf (&op->esil, ",?{,$$,%d,+,pc,=,}", jumpdisp);
		break;
	}

	return ret;
}

static bool set_reg_profile(RzAnal *anal) {
	const char *p =
		"=PC	pc\n"
		"=SP	r3\n"
		"=A0	r0\n"
		"=ZF	z\n"
		"=SF	s\n"
		"=OF	ov\n"
		"=CF	cy\n"

		"gpr	r0	.32	0   0\n"
		"gpr	r1	.32	4   0\n"
		"gpr	r2	.32	8   0\n"
		"gpr	r3	.32	12  0\n"
		"gpr	r4	.32	16  0\n"
		"gpr	r5	.32	20  0\n"
		"gpr	r6	.32	24  0\n"
		"gpr	r7	.32	28  0\n"
		"gpr	r8	.32	32  0\n"
		"gpr	r9	.32	36  0\n"
		"gpr	r10	.32	40  0\n"
		"gpr	r11	.32	44  0\n"
		"gpr	r12	.32	48  0\n"
		"gpr	r13	.32	52  0\n"
		"gpr	r14	.32	56  0\n"
		"gpr	r15	.32	60  0\n"
		"gpr	r16	.32	64  0\n"
		"gpr	r17	.32	68  0\n"
		"gpr	r18	.32	72  0\n"
		"gpr	r19	.32	76  0\n"
		"gpr	r20	.32	80  0\n"
		"gpr	r21	.32	84  0\n"
		"gpr	r22	.32	88  0\n"
		"gpr	r23	.32	92  0\n"
		"gpr	r24	.32	96  0\n"
		"gpr	r25	.32	100 0\n"
		"gpr	r26	.32	104 0\n"
		"gpr	r27	.32	108 0\n"
		"gpr	r28	.32	112 0\n"
		"gpr	r29	.32	116 0\n"
		"gpr	r30	.32	120 0\n"
		"gpr	r31	.32	124 0\n"
		"gpr	pc	.32	128 0\n"

		"gpr	psw .32 132 0\n"
		"gpr	np  .1 132.16 0\n"
		"gpr	ep  .1 132.17 0\n"
		"gpr	ae  .1 132.18 0\n"
		"gpr	id  .1 132.19 0\n"
		"flg	cy  .1 132.28 0\n"
		"flg	ov  .1 132.29 0\n"
		"flg	s   .1 132.30 0\n"
		"flg	z   .1 132.31 0\n";

	return rz_reg_set_profile_string (anal->reg, p);
}

RzAnalPlugin rz_anal_plugin_v810 = {
	.name = "v810",
	.desc = "V810 code analysis plugin",
	.license = "LGPL3",
	.arch = "v810",
	.bits = 32,
	.op = v810_op,
	.esil = true,
	.set_reg_profile = set_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = RZ_LIB_TYPE_ANAL,
	.data = &rz_anal_plugin_v810,
	.version = RZ_VERSION
};
#endif
