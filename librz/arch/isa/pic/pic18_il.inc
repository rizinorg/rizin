#include <rz_il.h>

#define K    (op->k)
#define D    (op->d)
#define F    (op->f)
#define B    (op->b)
#define N    (op->n)
#define PC   (op->addr)
#define VPC  (U16(PC))
#define RC   "c"
#define VRC  VARG(RC)
#define RN   "n"
#define VRN  VARG(RN)
#define ROV  "ov"
#define VROV VARG(ROV)
#define RZ   "z"
#define VRZ  VARG(RZ)
#define RS   "s"
#define VRS  VARG(RS)

/**
 * The `d` bit selects the destination for the operation.
 * If `d` is 1; the result is stored back in the File Register `f`.
 * If `d` is 0; the result is stored in the WREG Register.
 *
 * The `a` bit selects which bank is accessed for the operation.
 * If `a` is 1; the bank specified by the BSR Register is used.
 * If `a` is 0; the access bank is used.
 */
static const char *op_destination(Pic18Op *op) {
	return NULL;
}

#define R_DEST  op_destination(op)
#define VR_DEST VARG(R_DEST)

static RzILOpEffect *status_add(RzILOpPure *a, RzILOpPure *b, RzILOpPure *res, RzILOpPure *curry) {
	return NOP();
}

static RzILOpEffect *status_sub(RzILOpPure *a, RzILOpPure *b, RzILOpPure *res, RzILOpPure *curry) {
	return NOP();
}

static RzILOpEffect *status_res(RzILOpPure *res) {
	return NOP();
}

static RzILOpPure *complement_1(RzILOpPure *x) {
	return NEG(x);
}

static RzILOpPure *complement_2(RzILOpPure *x) {
	return ADD(U8(1), NEG(x));
}

static RzILOpPure *decimal_adjust(RzILOpPure *x) {
	return LET(
		"_x03", UNSIGNED(4, x),
		LET(
			"_x47", UNSIGNED(4, SHIFTR0(DUP(x), U8(4))),
			APPEND(
				ITE(OR(UGT(VARL("_x47"), UN(4, 9)), VARG("c")),
					ADD(VARL("_x47"), UN(4, 6)),
					VARL("_x47")),
				ITE(OR(UGT(VARL("_x03"), UN(4, 9)), VARG("dc")),
					ADD(VARL("_x03"), UN(4, 6)),
					VARL("_x03")))));
}

static RzILOpEffect *op_add(const char *dst,
	RzILOpPure *a, RzILOpPure *b, RzILOpPure *curry) {
	return SEQ3(
		SETL("_res", ADD(a, curry ? ADD(b, curry) : b)),
		status_add(DUP(a), DUP(b), VARL("_res"), curry ? DUP(curry) : NULL),
		SETG(dst, VARL("_res")));
}

static RzILOpEffect *op_sub(const char *dst,
	RzILOpPure *a, RzILOpPure *b, RzILOpPure *curry) {
	return SEQ3(
		SETL("_res", SUB(a, curry ? ADD(b, curry) : b)),
		status_sub(DUP(a), DUP(b), VARL("_res"), curry ? DUP(curry) : NULL),
		SETG(dst, VARL("_res")));
}

static RzILOpEffect *op_branch(Pic18Op *op, RzILOpPure *condition) {
	return condition ? BRANCH(condition, JMP(U16(PC + 2 + 2 * op->n)), NOP())
			 : JMP(U16(PC + 2 + 2 * op->n));
}

static RzILOpEffect *load_shadows_opt() {
	return BRANCH(NON_ZERO(VARG("s")),
		SEQ3(
			SETG("ws", VRW),
			SETG("ss", VRS),
			SETG("bsrs", VARG("bsr"))),
		NOP());
}

static RzILOpEffect *op_call(Pic18Op *op) {
	return SEQ3(
		SETG("tos", U16(PC + 4)),
		JMP(U32(K << 1)),
		load_shadows_opt());
}

static RzILOpEffect *op_and(const char *dst,
	RzILOpPure *a, RzILOpPure *b) {
	return SEQ3(
		SETL("_res", LOGAND(a, b)),
		status_res(VARL("res")),
		SETG(dst, VARL("_res")));
}

static RzILOpEffect *op_skip_if(Pic18Op *op, RzILOpPure *condition) {
	return BRANCH(condition, JMP(U16(PC + INS_LEN * 2)), NOP());
}

static RzILOpEffect *set_prod16(RzILOpPure *res) {
	return SEQ3(
		SETL("_res", res),
		SETG("prodh", UNSIGNED(8, SHIFTR0(VARL("_res"), U8(8)))),
		SETG("prodl", UNSIGNED(8, VARL("_res"))));
}

static RzILOpEffect *op_pop() {
	return SEQ2(
		SETG("_stack_ptr", SUB(VARG("_stack_ptr"), U16(4))),
		SETG("tos", LOADW(32, ADD(VARG("_stack"), VARG("_stack_ptr")))));
}

static RzILOpEffect *op_pop_jmp() {
	return SEQ3(
		SETL("_pc", VARG("tos")),
		op_pop(),
		JMP(VARL("_pc")));
}

static RzILOpEffect *op_push(RzILOpPure *x) {
	return SEQ3(
		SETG("_stack_ptr", ADD(VARG("_stack_ptr"), U16(4))),
		STOREW(ADD(VARG("_stack"), VARG("_stack_ptr")), x),
		SETG("tos", DUP(x)));
}

static RzILOpEffect *pic18_il(Pic18Op *op) {
	switch (op->code) {
	case PIC18_OPCODE_ADDLW: return op_add(RW, VRW, U16(K), NULL);
	case PIC18_OPCODE_ADDWF: return op_add(R_DEST, VRW, VRF, NULL);
	case PIC18_OPCODE_ADDWFC: return op_add(R_DEST, VRW, VRF, VRC);
	case PIC18_OPCODE_ANDLW: return op_and(RW, VRW, U16(K));
	case PIC18_OPCODE_ANDWF: return op_and(R_DEST, VRW, VRF);
	case PIC18_OPCODE_BC: return op_branch(op, VRC);
	case PIC18_OPCODE_BN: return op_branch(op, VRN);
	case PIC18_OPCODE_BOV: return op_branch(op, VROV);
	case PIC18_OPCODE_BZ: return op_branch(op, VRZ);
	case PIC18_OPCODE_BNC: return op_branch(op, INV(VRC));
	case PIC18_OPCODE_BNN: return op_branch(op, INV(VRN));
	case PIC18_OPCODE_BNOV: return op_branch(op, INV(VROV));
	case PIC18_OPCODE_BNZ: return op_branch(op, INV(VRZ));
	case PIC18_OPCODE_BRA: return op_branch(op, NULL);

	case PIC18_OPCODE_BCF: return regbit_set(RF, B, 0);
	case PIC18_OPCODE_BSF: return regbit_set(RF, B, 1);
	case PIC18_OPCODE_BTG: return regbit_set1(RF, B, INV(bit_get(VRF, B)));
	case PIC18_OPCODE_BTFSC: return op_skip_if(op, INV(bit_get(VRF, B)));
	case PIC18_OPCODE_BTFSS: return op_skip_if(op, bit_get(VRF, B));

	case PIC18_OPCODE_CALL: return op_call(op);
	case PIC18_OPCODE_CLRF: return SEQ2(SETG(RF, U8(0)), SETG("z", IL_TRUE));
	case PIC18_OPCODE_CLRWDT:
		return SEQ4(
			SETG("wdt", U8(0)),
			SETG("wdt_prescaler_count", IL_FALSE),
			SETG("to", IL_TRUE),
			SETG("pd", IL_TRUE));
	case PIC18_OPCODE_COMF:
		return SEQ3(
			SETL("_res", complement_1(VRF)),
			status_res(VARL("_res")),
			SETG(op_destination(op), VARL("_res")));
	case PIC18_OPCODE_CPFSEQ: return op_skip_if(op, EQ(VRW, VRF));
	case PIC18_OPCODE_CPFSGT: return op_skip_if(op, SGT(VRW, VRF));
	case PIC18_OPCODE_CPFSLT: return op_skip_if(op, SLT(VRW, VRF));
	case PIC18_OPCODE_DAW:
		return SEQ3(
			SETL("_res", decimal_adjust(VRW)),
			SETG("c", IL_FALSE), // TODO: status C
			SETG(RW, VARL("_res")));
	case PIC18_OPCODE_DECF:
		return SEQ3(
			SETG("_res", SUB(VRF, U8(1))),
			status_sub(VRF, U8(1), VARL("_res"), NULL),
			SETG(op_destination(op), VARL("_res")));
	case PIC18_OPCODE_DECFSZ:
		return SEQ3(
			SETG("_res", SUB(VRF, U8(1))),
			SETG(op_destination(op), VARL("_res")),
			op_skip_if(op, IS_ZERO(VARL("_res"))));
	case PIC18_OPCODE_DCFSNZ:
		return SEQ3(
			SETG("_res", SUB(VRF, U8(1))),
			SETG(op_destination(op), VARL("_res")),
			op_skip_if(op, NON_ZERO(VARL("_res"))));
	case PIC18_OPCODE_GOTO: return JMP(U32((ut32)K << 1));
	case PIC18_OPCODE_INCF:
		return SEQ3(
			SETG("_res", ADD(VRF, U8(1))),
			status_add(VRF, U8(1), VARL("_res"), NULL),
			SETG(op_destination(op), VARL("_res")));
	case PIC18_OPCODE_INCFSZ:
		return SEQ3(
			SETG("_res", ADD(VRF, U8(1))),
			SETG(op_destination(op), VARL("_res")),
			op_skip_if(op, IS_ZERO(VARL("_res"))));
	case PIC18_OPCODE_INFSNZ:
		return SEQ3(
			SETG("_res", ADD(VRF, U8(1))),
			SETG(op_destination(op), VARL("_res")),
			op_skip_if(op, NON_ZERO(VARL("_res"))));
	case PIC18_OPCODE_IORWF:
		return SEQ2(
			SETG(op_destination(op), LOGOR(VRW, VRF)),
			status_res(VARG(op_destination(op))));
	case PIC18_OPCODE_IORLW:
		return SEQ2(
			SETG(RW, LOGOR(VRW, U16(K))),
			status_res(VRW));
	case PIC18_OPCODE_LFSR: return SETG(RFSR(F), U16(K));
	case PIC18_OPCODE_MOVF:
		return SEQ2(
			SETG(R_DEST, VRF),
			status_res(VR_DEST));
	case PIC18_OPCODE_MOVFF:
		return SETG(RFSR(op->d), VARG(RFSR(op->s)));
	case PIC18_OPCODE_MOVLB:
		return SETG("bsr", LOGOR(U8(K), LOGAND(VARG("bsr"), U8(0xf0))));
	case PIC18_OPCODE_MOVLW:
		return SETG(RW, U8(K));
	case PIC18_OPCODE_MOVWF:
		return SETG(RF, VRW);
	case PIC18_OPCODE_MULLW:
		return set_prod16(MUL(UNSIGNED(16, VRW), U16(K)));
	case PIC18_OPCODE_MULWF:
		return set_prod16(MUL(UNSIGNED(16, VRW), UNSIGNED(16, VRF)));
	case PIC18_OPCODE_NOP: return NOP();
	case PIC18_OPCODE_NEGF: return SETG(RF, complement_2(VRF));
	case PIC18_OPCODE_POP: return op_pop();
	case PIC18_OPCODE_PUSH: return op_push(U32(PC));
	case PIC18_OPCODE_RCALL:
		return SEQ2(
			op_push(U32(PC + 2)),
			JMP(U32(PC + 2 + 2 * N)));
	case PIC18_OPCODE_RESET: return NOP();
	case PIC18_OPCODE_RETFIE:
		return SEQ3(
			BRANCH(
				IS_ZERO(VARG("ipen")),
				SETG("gie", IL_TRUE),
				SEQ2(
					SETL("_g", APPEND(VARG("gieh"), VARG("geil"))),
					BRANCH(
						EQ(VARG("_g"), UN(2, 0b11)),
						SETG("invalid", IL_TRUE),
						BRANCH(
							EQ(VARG("_g"), UN(2, 0b10)),
							SEQ2(SETG("giel", IL_TRUE),
								SETG("gieh", IL_TRUE)),
							NOP())))),
			load_shadows_opt(),
			op_pop_jmp());
	case PIC18_OPCODE_RETLW:
		return SEQ2(
			SETG(RW, U8(K)),
			op_pop_jmp());
	case PIC18_OPCODE_RETURN:
		return SEQ2(
			load_shadows_opt(),
			op_pop_jmp());
	case PIC18_OPCODE_RLNCF:
		return SEQ2(
			SETL(R_DEST, LET("_x", VRF, LOGOR(SHIFTL0(VARLP("_x"), U8(7)), BOOL_TO_BV(MSB(VARLP("_x")), 8)))),
			status_res(VR_DEST));
	case PIC18_OPCODE_RRNCF:
		return SEQ2(
			SETL(R_DEST, LET("_x", VRF, LOGOR(SHIFTR0(VARLP("_x"), U8(7)), BOOL_TO_BV(LSB(VARLP("_x")), 8)))),
			status_res(VR_DEST));
	case PIC18_OPCODE_RLCF:
		return SEQ4(
			SETL("_x", VRF),
			SETL(R_DEST, LOGOR(SHIFTL0(VARLP("_x"), U8(7)), BOOL_TO_BV(VRC, 8))),
			SETG("c", MSB(VARG("_x"))),
			status_res(VR_DEST));
	case PIC18_OPCODE_RRCF:
		return SEQ4(
			SETL("_x", VRF),
			SETL(R_DEST, LOGOR(SHIFTR0(VARLP("_x"), U8(7)), BOOL_TO_BV(VRC, 8))),
			SETG("c", LSB(VARG("_x"))),
			status_res(VR_DEST));
	case PIC18_OPCODE_SETF:
		return SETG(RF, U8(0xff));
	case PIC18_OPCODE_SLEEP:
		return SEQ4(
			SETG("wdt", U8(0)),
			SETG("wdt_prescaler_count", IL_FALSE),
			SETG("to", IL_TRUE),
			SETG("pd", IL_FALSE));
	case PIC18_OPCODE_SUBFWB: return op_sub(R_DEST, VRW, VRF, VRC);
	case PIC18_OPCODE_SUBLW: return op_sub(RW, U8(K), VRW, NULL);
	case PIC18_OPCODE_SUBWF: return op_sub(R_DEST, VRF, VRW, NULL);
	case PIC18_OPCODE_SUBWFB: return op_sub(R_DEST, VRF, VRW, VRC);
	case PIC18_OPCODE_SWAPF:
		return SETG(R_DEST, APPEND(UNSIGNED(4, VRF), UNSIGNED(4, SHIFTR0(VRF, U8(4)))));
	case PIC18_OPCODE_TBLWTam: break;
	case PIC18_OPCODE_TBLWTMms: break;
	case PIC18_OPCODE_TBLWTMma: break;
	case PIC18_OPCODE_TBLWTMm: break;
	case PIC18_OPCODE_TBLRDam: break;
	case PIC18_OPCODE_TBLRDms: break;
	case PIC18_OPCODE_TBLRDma: break;
	case PIC18_OPCODE_TBLRDm: break;
	case PIC18_OPCODE_TSTFSZ: break;
	case PIC18_OPCODE_XORWF: break;
	case PIC18_OPCODE_XORLW: break;
	case PIC18_OPCODE_INVALID: break;
	}
	return NULL;
}

#undef K
#undef D
#undef F
#undef B
#undef N
#undef PC
#undef VPC

static const char *pic18_regnames[] = {
	"_sram",
	"_stack",
	"_stack_ptr",
};

static RzAnalysisILConfig *pic18_il_config(
	RZ_NONNULL RzAnalysis *analysis) {
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(32, false, 16);
	cfg->reg_bindings = pic18_regnames;
	return cfg;
}
