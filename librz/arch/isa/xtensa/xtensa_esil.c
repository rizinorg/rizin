// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_analysis.h>
#include <xtensa/xtensa.h>
#include <capstone/xtensa.h>

#define CM      ","
#define opcode  (ctx->insn->id)
#define REG(I)  cs_reg_name(ctx->handle, I)
#define MEM(I)  xtensa_op_mem(ctx->insn, I)
#define REGO(I) REG(xtensa_op_reg(ctx->insn, I))
#define IMM(I)  xtensa_op_imm(ctx->insn, I)
#define L32R(I) xtensa_op_l32r(ctx->insn, I)

static void esil_push_signed_imm(RzStrBuf *esil, st32 imm) {
	if (imm >= 0) {
		rz_strbuf_appendf(esil, "0x%x" CM, imm);
	} else {
		rz_strbuf_appendf(
			esil,
			"0x%x" CM
			"0x0" CM
			"-" CM,
			-imm);
	}
}

static void esil_sign_extend(RzStrBuf *esil, ut8 bit) {
	// check sign bit, and, if needed, apply or mask

	ut32 bit_mask = 1 << bit;
	ut32 extend_mask = 0xFFFFFFFF << bit;

	rz_strbuf_appendf(
		esil,
		"DUP" CM
		"0x%x" CM
		"&" CM
		"0" CM
		"==,$z,!" CM
		"?{" CM
		"0x%x" CM
		"|" CM
		"}" CM,
		bit_mask,
		extend_mask);
}

static void esil_load_imm(XtensaContext *ctx, RzAnalysisOp *op) {
	ut8 sign_extend_bit;

	// example: l32i a2, a1, 0x10
	//          0x10,a1,+, // address on stack
	//          [x], // read data
	//          a2, // push data reg
	//			= // assign to data reg

	ut8 data_size = 1;
	sign_extend_bit = 0;
	switch (opcode) {
	case XTENSA_INS_L32I: // l32i
		//	case 31: // l32i.n
		data_size = 4;
		break;
	case XTENSA_INS_L16SI: // l16si
		sign_extend_bit = 15;
		data_size = 2;
		// fallthrough
	case XTENSA_INS_L16UI:
		// l16ui
		break;
	}

	rz_strbuf_appendf(
		&op->esil,
		"0x%x" CM
		"%s" CM
		"+" CM
		"[%d]" CM,
		// offset
		MEM(1)->disp,
		// address
		REG(MEM(1)->base),
		// size
		data_size);

	if (sign_extend_bit != 0) {
		esil_sign_extend(&op->esil, sign_extend_bit);
	}

	rz_strbuf_appendf(
		&op->esil,
		"%s" CM
		"=",
		// data
		REGO(0));
}

static void esil_load_relative(XtensaContext *ctx, RzAnalysisOp *op) {
	// example: l32r a2, 0x10
	//          0x10,$$,3,+ // l32r address + 3 on stack
	//          0xFFFFFFFC,&, // clear 2 lsb
	//          -, // subtract offset
	//          [4], // read data
	//          a2, // push data reg
	//          = // assign to data reg

	rz_strbuf_appendf(
		&op->esil,
		"0x%x" CM
		"$$" CM
		"3" CM
		"+" CM
		"0xFFFFFFFC" CM
		"&" CM
		"-" CM
		"[4]" CM
		"%s" CM
		"=",
		// offset
		L32R(1),
		// data
		REGO(0));
}

static void esil_add_imm(XtensaContext *ctx, RzAnalysisOp *op) {
	// example: addi a3, a4, 0x01
	//          a4,0x01,+,a3,=

	rz_strbuf_appendf(&op->esil, "%s" CM, REGO(1));
	esil_push_signed_imm(&op->esil, IMM(2));
	rz_strbuf_appendf(
		&op->esil,
		"+" CM
		"%s" CM
		"=",
		REGO(0));
}

static void esil_store_imm(XtensaContext *ctx, RzAnalysisOp *op) { // example: s32i a2, a1, 0x10
	//          a2, // push data
	//          0x10,a1,+, // address on stack
	//          =[x] // write data

	ut8 data_size =
		opcode == XTENSA_INS_S32I ? 4 // s32cli
		//		: opcode == 36  ? 4 // s32i.n
		//		: opcode == 100 ? 4 // s32i
		: opcode == XTENSA_INS_S16I ? 2 // s16i
					    : 1; // opcode == 101 ? 1 : 1; // s8i

	rz_strbuf_appendf(
		&op->esil,
		"%s" CM
		"0x%x" CM
		"%s" CM
		"+" CM
		"=[%d]",
		// data
		REG(MEM(1)->base),
		// offset
		MEM(1)->disp,
		// address
		REGO(0),
		// size
		data_size);
}

static void esil_move_imm(XtensaContext *ctx, RzAnalysisOp *op) {
	esil_push_signed_imm(&op->esil, IMM(1));
	rz_strbuf_appendf(
		&op->esil,
		"%s" CM
		"=",
		REGO(0));
}

// static void esil_move(XtensaContext *ctx, RzAnalysisOp *op) {
//	rz_strbuf_appendf(
//		&op->esil,
//		"%s" CM
//		"%s" CM
//		"=",
//		REGO(1),
//		REGO(0));
// }

static void esil_move_conditional(XtensaContext *ctx, RzAnalysisOp *op) {
	const char *compare_op = "";

	switch (opcode) {
	case XTENSA_INS_MOVEQZ: /* moveqz */
		compare_op = "==,$z";
		break;
	case XTENSA_INS_MOVNEZ: /* movnez */
		compare_op = "==,$z,!";
		break;
	case XTENSA_INS_MOVLTZ: /* movltz */
		compare_op = "<";
		break;
	case XTENSA_INS_MOVGEZ: /* movgez */
		compare_op = ">=";
		break;
	}

	// example: moveqz a3, a4, a5
	//          0,
	//          a5,
	//          ==,
	//          ?{,
	//            a4,
	//            a3,
	//            =,
	//          }

	rz_strbuf_appendf(
		&op->esil,
		"0" CM
		"%s" CM
		"%s" CM
		"?{" CM
		"%s" CM
		"%s" CM
		"=" CM
		"}",
		REGO(2),
		compare_op,
		REGO(1),
		REGO(0));
}

static ut8 add_sub_shift(XtensaContext *ctx) {
	ut8 shift = 0;
	switch (opcode) {
	case XTENSA_INS_ADDX2:
	case XTENSA_INS_SUBX2:
		shift = 1;
		break;
	case XTENSA_INS_ADDX4:
	case XTENSA_INS_SUBX4:
		shift = 2;
		break;
	case XTENSA_INS_ADDX8:
	case XTENSA_INS_SUBX8:
		shift = 3;
		break;
	default:
		shift = 0;
		break;
	}
	return shift;
}

static bool add_sub_is_add(XtensaContext *ctx) {
	return opcode == XTENSA_INS_ADD ||
		opcode == XTENSA_INS_ADDX2 ||
		opcode == XTENSA_INS_ADDX4 ||
		opcode == XTENSA_INS_ADDX8;
}

static void esil_add_sub(XtensaContext *ctx, RzAnalysisOp *op) {
	rz_strbuf_appendf(
		&op->esil,
		"%s" CM
		"%d" CM
		"%s" CM
		"<<" CM
		"%s" CM
		"%s" CM
		"=",
		REGO(2),
		add_sub_shift(ctx),
		REGO(1),
		(add_sub_is_add(ctx) ? "+" : "-"),
		REGO(0));
}

static void esil_branch_compare_imm(XtensaContext *ctx, RzAnalysisOp *op) {
	const char *compare_op = "";

	// TODO: unsigned comparisons
	switch (opcode) {
	case XTENSA_INS_BEQI: /* beqi */
		compare_op = "==,$z";
		break;
	case XTENSA_INS_BNEI: /* bnei */
		compare_op = "==,$z,!";
		break;
	case XTENSA_INS_BGEUI: /* bgeui */
	case XTENSA_INS_BGEI: /* bgei */
		compare_op = ">=";
		break;
	case XTENSA_INS_BLTUI: /* bltui */
	case XTENSA_INS_BLTI: /* blti */
		compare_op = "<";
		break;
	}

	// example: beqi a4, 4, offset
	//            a4, // push data reg
	//            0x4, // push imm operand
	//            ==,
	//            ?{,
	//              offset,
	//              pc,
	//              +=,
	//            }

	rz_strbuf_appendf(
		&op->esil,
		"%s" CM,
		// data reg
		REGO(0));

	esil_push_signed_imm(&op->esil, IMM(1));

	rz_strbuf_appendf(&op->esil, "%s" CM, compare_op);
	rz_strbuf_appendf(&op->esil, "?{" CM);

	// ISA defines branch target as offset + 4,
	// but at the time of ESIL evaluation
	// PC will be already incremented by 3
	esil_push_signed_imm(&op->esil, IMM(2) + 4 - 3);

	rz_strbuf_appendf(&op->esil, "pc" CM "+=" CM "}");
}

static void esil_branch_compare(XtensaContext *ctx, RzAnalysisOp *op) {
	const char *compare_op = "";
	switch (opcode) {
	case XTENSA_INS_BEQ: /* beq */
		compare_op = "==,$z";
		break;
	case XTENSA_INS_BNE: /* bne */
		compare_op = "==,$z,!";
		break;
	case XTENSA_INS_BGE: /* bge */
	case XTENSA_INS_BGEU: /* bgeu */
		compare_op = ">=";
		break;
	case XTENSA_INS_BLT: /* blt */
	case XTENSA_INS_BLTU: /* bltu */
		compare_op = "<";
		break;
	}
	// example: beq a4, a3, offset
	//            a3, // push op1
	//            a4, // push op2
	//            ==,
	//            ?{,
	//              offset,
	//              pc,
	//              +=,
	//            }

	rz_strbuf_appendf(
		&op->esil,
		"%s" CM
		"%s" CM
		"%s" CM
		"?{" CM,
		REGO(1),
		REGO(0),
		compare_op);

	esil_push_signed_imm(&op->esil, IMM(2));

	rz_strbuf_append(&op->esil, "pc" CM "+=" CM "}");
}

static void esil_branch_compare_single(XtensaContext *ctx, RzAnalysisOp *op) {
	const char *compare_op = "";

	switch (opcode) {
	case XTENSA_INS_BEQZ: /* beqz */
		//	case 28: /* beqz.n */
		compare_op = "==,$z";
		break;
	case XTENSA_INS_BNEZ: /* bnez */
		//	case 29: /* bnez.n */
		compare_op = "==,$z,!";
		break;
	case XTENSA_INS_BGEZ: /* bgez */
		compare_op = ">=";
		break;
	case XTENSA_INS_BLTZ: /* bltz */
		compare_op = "<";
		break;
	}

	// example: beqz a4, 0, offset
	//            0,  // push 0
	//            a4, // push op
	//            ==,
	//            ?{,
	//              offset,
	//              pc,
	//              +=,
	//            }

	rz_strbuf_appendf(
		&op->esil,
		"0" CM
		"%s" CM
		"%s" CM
		"?{" CM,
		REGO(0),
		compare_op);

	esil_push_signed_imm(&op->esil, IMM(1));

	rz_strbuf_append(&op->esil, "pc" CM "+=" CM "}");
}

static void esil_branch_check_mask(XtensaContext *ctx, RzAnalysisOp *op) {
	const char *compare_op = "";
	char compare_val[4] = "0";

	switch (opcode) {
	case XTENSA_INS_BNALL: /* bnall */
	case XTENSA_INS_BANY: /* bany */
		compare_op = "==,$z,!";
		break;
	case XTENSA_INS_BALL: /* ball */
	case XTENSA_INS_BNONE: /* bnone */
		compare_op = "==,$z";
		break;
	}

	switch (opcode) {
	case XTENSA_INS_BNALL: /* bnall */
	case XTENSA_INS_BALL: /* ball */
		snprintf(
			compare_val,
			sizeof(compare_val),
			"%s",
			REGO(1));
		break;
	}

	// example: bnall a4, a3, offset
	//            a4, // push op1
	//            a3, // push op2
	//            &,
	//            a3,
	//            ==,!,
	//            ?{,
	//              offset,
	//              pc,
	//              +=,
	//            }

	rz_strbuf_appendf(
		&op->esil,
		"%s" CM
		"%s" CM
		"&" CM
		"%s" CM
		"%s" CM
		"?{" CM,
		REGO(0),
		REGO(1),
		REGO(1),
		compare_op);

	esil_push_signed_imm(&op->esil, IMM(2));

	rz_strbuf_append(&op->esil, "pc" CM "+=" CM "}");
}

static void esil_bitwise_op(XtensaContext *ctx, RzAnalysisOp *op) {
	char bop;
	switch (opcode) {
	case XTENSA_INS_AND: /* and */
		bop = '&';
		break;
	case XTENSA_INS_OR: /* or */
		bop = '|';
		break;
	case XTENSA_INS_XOR: /* xor */
		bop = '^';
		break;
	default:
		bop = '=';
		break;
	}

	rz_strbuf_appendf(
		&op->esil,
		"%s" CM
		"%s" CM
		"%c" CM
		"%s" CM
		"=",
		REGO(1),
		REGO(2),
		bop,
		REGO(0));
}

static void esil_branch_check_bit_imm(XtensaContext *ctx, RzAnalysisOp *op) {
	ut8 bit_clear;
	const char *cmp_op;

	bit_clear = opcode == XTENSA_INS_BBSI;
	cmp_op = bit_clear ? "==,$z" : "==,$z,!";

	// example: bbsi a4, 2, offset
	//          a4,
	//          mask,
	//          &,
	//          0,
	//          ==,
	//          ?{,
	//            offset,
	//            pc,
	//            +=,
	//          }

	rz_strbuf_appendf(
		&op->esil,
		"%s" CM
		"0x%x" CM
		"&" CM
		"0" CM
		"%s" CM
		"?{" CM,
		REGO(0),
		IMM(1),
		cmp_op);

	esil_push_signed_imm(&op->esil, IMM(2));

	rz_strbuf_appendf(
		&op->esil,
		"pc" CM
		"+=" CM
		"}");
}

static void esil_branch_check_bit(XtensaContext *ctx, RzAnalysisOp *op) {
	ut8 bit_clear;
	const char *cmp_op;

	// bbc
	bit_clear = opcode == XTENSA_INS_BBC;
	cmp_op = bit_clear ? "==,$z" : "==,$z,!";

	// example: bbc a4, a2, offset
	//          a2,
	//          1,
	//          <<,
	//          a4,
	//          &
	//          0
	//          ==,
	//          ?{,
	//            offset,
	//            pc,
	//            +=,
	//          }

	rz_strbuf_appendf(
		&op->esil,
		"%s" CM
		"1" CM
		"<<" CM
		"%s" CM
		"&" CM
		"0" CM
		"%s" CM
		"?{" CM,
		REGO(1),
		REGO(0),
		cmp_op);

	esil_push_signed_imm(&op->esil, IMM(2));

	rz_strbuf_appendf(
		&op->esil,
		"pc" CM
		"+=" CM
		"}");
}

static void esil_abs_neg(XtensaContext *ctx, RzAnalysisOp *op) {
	ut8 neg;
	neg = opcode == XTENSA_INS_NEG;

	if (!neg) {
		rz_strbuf_appendf(
			&op->esil,
			"0" CM
			"%s" CM
			"<" CM
			"?{" CM
			"0" CM
			"%s" CM
			"-" CM
			"}" CM
			"0" CM
			"%s" CM
			">=" CM
			"?{" CM
			"%s" CM
			"}" CM,
			REGO(0),
			REGO(0),
			REGO(0),
			REGO(0));
	} else {
		rz_strbuf_appendf(
			&op->esil,
			"0" CM
			"%s" CM
			"-" CM,
			REGO(0));
	}

	rz_strbuf_appendf(
		&op->esil,
		"%s" CM
		"=" CM,
		REGO(1));
}

static void esil_call(XtensaContext *ctx, RzAnalysisOp *op) {
	bool call = opcode == XTENSA_GRP_CALL;
	if (call) {
		rz_strbuf_append(
			&op->esil,
			"pc" CM
			"a0" CM
			"=" CM);
	}

	esil_push_signed_imm(&op->esil, IMM(0));

	rz_strbuf_append(&op->esil, "pc" CM "+=");
}

static void esil_callx(XtensaContext *ctx, RzAnalysisOp *op) {
	bool callx = opcode == XTENSA_INS_CALLX0;
	rz_strbuf_appendf(
		&op->esil,
		"%s" CM "0" CM "+" CM,
		REGO(0));

	if (callx) {
		rz_strbuf_append(
			&op->esil,
			"pc" CM
			"a0" CM
			"=" CM);
	}

	rz_strbuf_append(&op->esil, "pc" CM "=");
}

static void esil_set_shift_amount(XtensaContext *ctx, RzAnalysisOp *op) {
	rz_strbuf_appendf(
		&op->esil,
		"%s" CM
		"sar" CM
		"=",
		REGO(0));
}

static void esil_set_shift_amount_imm(XtensaContext *ctx, RzAnalysisOp *op) {
	rz_strbuf_appendf(
		&op->esil,
		"0x%x" CM
		"sar" CM
		"=",
		IMM(0));
}

static void esil_shift_logic_imm(XtensaContext *ctx, RzAnalysisOp *op) {
	const char *shift_op = "";

	// srli
	if (opcode == XTENSA_INS_SRLI) {
		shift_op = ">>";
	} else {
		shift_op = "<<";
	}

	rz_strbuf_appendf(
		&op->esil,
		"0x%x" CM
		"%s" CM
		"%s" CM
		"%s" CM
		"=",
		IMM(2),
		REGO(1),
		shift_op,
		REGO(0));
}

static void esil_shift_logic_sar(XtensaContext *ctx, RzAnalysisOp *op) {
	const char *shift_op = "";
	// srl
	if (opcode == XTENSA_INS_SRL) {
		shift_op = ">>";
	} else {
		shift_op = "<<";
	}

	rz_strbuf_appendf(
		&op->esil,
		"sar" CM
		"%s" CM
		"%s" CM
		"%s" CM
		"=",
		REGO(1),
		shift_op,
		REGO(0));
}

static void esil_extract_unsigned(XtensaContext *ctx, RzAnalysisOp *op) {
	rz_strbuf_appendf(
		&op->esil,
		"0x%x" CM
		"%s" CM
		">>" CM
		"0x%x" CM
		"&" CM
		"%s" CM
		"=",
		IMM(2),
		REGO(1),
		IMM(3),
		REGO(0));
}

void xtensa_analyze_op_esil(XtensaContext *ctx, RzAnalysisOp *op) {
	switch (opcode) {
		//	case 26: /* add.n */
	case XTENSA_INS_ADD: /* add */
	case XTENSA_INS_ADDX2: /* addx2 */
	case XTENSA_INS_ADDX4: /* addx4 */
	case XTENSA_INS_ADDX8: /* addx8 */
	case XTENSA_INS_SUB: /* sub */
	case XTENSA_INS_SUBX2: /* subx2 */
	case XTENSA_INS_SUBX4: /* subx4 */
	case XTENSA_INS_SUBX8: /* subx8 */
		esil_add_sub(ctx, op);
		break;
		//	case 32: /* mov.n */
		//		esil_move(ctx, op);
		//		break;
	case XTENSA_INS_MOVI: /* movi */
		//	case 33: /* movi.n */
		esil_move_imm(ctx, op);
		break;
		//	case 0: /* excw */
	case XTENSA_INS_NOP: /* nop.n */
		rz_strbuf_setf(&op->esil, "%s", "");
		break;
		// TODO: s32cli (s32c1i) is conditional (CAS)
		// should it be handled here?
		//	case 453: /* s32c1i */
		//	case 36: /* s32i.n */
	case XTENSA_INS_S32I: /* s32i */
	case XTENSA_INS_S16I: /* s16i */
	case XTENSA_INS_S8I: /* s8i */
		esil_store_imm(ctx, op);
		break;
		//	case 27: /* addi.n */
	case XTENSA_INS_ADDI: /* addi */
		esil_add_imm(ctx, op);
		break;
	case XTENSA_INS_RET: /* ret */
		//	case 35: /* ret.n */
		rz_strbuf_setf(&op->esil, "a0,pc,=");
		break;
	case XTENSA_INS_L16UI: /* l16ui */
	case XTENSA_INS_L16SI: /* l16si */
	case XTENSA_INS_L32I: /* l32i */
		//	case 31: /* l32i.n */
	case XTENSA_INS_L8UI: /* l8ui */
		esil_load_imm(ctx, op);
		break;
	// TODO: s32r
	// l32r is different because it is relative to LITBASE
	// which also may or may not be present
	case XTENSA_INS_L32R: /* l32r */
		esil_load_relative(ctx, op);
		break;
	case XTENSA_INS_ADDMI: /* addmi */
		break;
	case XTENSA_INS_AND: /* and */
	case XTENSA_INS_OR: /* or */
	case XTENSA_INS_XOR: /* xor */
		esil_bitwise_op(ctx, op);
		break;
	case XTENSA_INS_BEQI: /* beqi */
	case XTENSA_INS_BNEI: /* bnei */
	case XTENSA_INS_BGEI: /* bgei */
	case XTENSA_INS_BLTI: /* blti */
	case XTENSA_INS_BGEUI: /* bgeui */
	case XTENSA_INS_BLTUI: /* bltui */
		esil_branch_compare_imm(ctx, op);
		break;
	case XTENSA_INS_BBCI: /* bbci */
	case XTENSA_INS_BBSI: /* bbsi */
		esil_branch_check_bit_imm(ctx, op);
		break;
	case XTENSA_INS_BEQ: /* beq */
	case XTENSA_INS_BNE: /* bne */
	case XTENSA_INS_BGE: /* bge */
	case XTENSA_INS_BLT: /* blt */
	case XTENSA_INS_BGEU: /* bgeu */
	case XTENSA_INS_BLTU: /* bltu */
		esil_branch_compare(ctx, op);
		break;
	case XTENSA_INS_BANY: /* bany */
	case XTENSA_INS_BNONE: /* bnone */
	case XTENSA_INS_BALL: /* ball */
	case XTENSA_INS_BNALL: /* bnall */
		esil_branch_check_mask(ctx, op);
		break;
	case XTENSA_INS_BBC: /* bbc */
	case XTENSA_INS_BBS: /* bbs */
		esil_branch_check_bit(ctx, op);
		break;
	case XTENSA_INS_BEQZ: /* beqz */
	case XTENSA_INS_BNEZ: /* bnez */
		//	case 28: /* beqz.n */
		//	case 29: /* bnez.n */
	case XTENSA_INS_BGEZ: /* bgez */
	case XTENSA_INS_BLTZ: /* bltz */
		esil_branch_compare_single(ctx, op);
		break;
	case XTENSA_INS_EXTUI: /* extui */
		esil_extract_unsigned(ctx, op);
		break;
		//	case 79: /* ill */
		//		rz_strbuf_setf(&op->esil, "%s", "");
		//		break;
		// TODO: windowed calls?
		//	case 7: /* call4 */
		//		break;
		//	case 76: /* call0 */
	case XTENSA_INS_J: /* j */
		esil_call(ctx, op);
		break;
	case 81: /* jx */
	case XTENSA_INS_CALLX0: /* callx0 */
		esil_callx(ctx, op);
		break;
	case XTENSA_INS_MOVEQZ: /* moveqz */
	case XTENSA_INS_MOVNEZ: /* movnez */
	case XTENSA_INS_MOVLTZ: /* movltz */
	case XTENSA_INS_MOVGEZ: /* movgez */
		esil_move_conditional(ctx, op);
		break;
	case XTENSA_INS_ABS: /* abs */
	case XTENSA_INS_NEG: /* neg */
		esil_abs_neg(ctx, op);
		break;
	case XTENSA_INS_SSR: /* ssr */
	case XTENSA_INS_SSL: /* ssl */
		esil_set_shift_amount(ctx, op);
		break;
	case XTENSA_INS_SLLI: /* slli */
	case XTENSA_INS_SRLI: /* srli */
		esil_shift_logic_imm(ctx, op);
		break;
	case XTENSA_INS_SSAI: /* ssai */
		esil_set_shift_amount_imm(ctx, op);
		break;
	case XTENSA_INS_SLL: /* sll */
	case XTENSA_INS_SRL: /* srl */
		esil_shift_logic_sar(ctx, op);
		break;
	}
}