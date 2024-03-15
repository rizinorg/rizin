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

#define DEST op_destination(op)

static RzILOpEffect *status_add(RzILOpPure *a, RzILOpPure *b, RzILOpPure *res, RzILOpPure *curry) {
	return NOP();
}

static RzILOpEffect *status_res(RzILOpPure *res) {
	return NOP();
}

static RzILOpPure *complement_1(RzILOpPure *x) {
	// TODO: complement_1
	return NULL;
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

static RzILOpEffect *op_branch(Pic18Op *op, RzILOpPure *condition) {
	return condition ? BRANCH(condition, JMP(U16(PC + 2 + 2 * op->n)), NOP())
			 : JMP(U16(PC + 2 + 2 * op->n));
}

static RzILOpEffect *op_call(Pic18Op *op) {
	return SEQ3(
		SETG("tos", U16(PC + 4)),
		JMP(U32(K << 1)),
		BRANCH(NON_ZERO(VARG("s")),
			SEQ3(
				SETG("ws", VRW),
				SETG("ss", VRS),
				SETG("bsrs", VARG("bsr"))),
			NOP()));
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

static RzILOpEffect *pic18_il(Pic18Op *op) {
	switch (op->code) {
	case PIC18_OPCODE_ADDLW: return op_add(RW, VRW, U16(K), NULL);
	case PIC18_OPCODE_ADDWF: return op_add(DEST, VRW, VRF, NULL);
	case PIC18_OPCODE_ADDWFC: return op_add(DEST, VRW, VRF, VRC);
	case PIC18_OPCODE_ANDLW: return op_and(RW, VRW, U16(K));
	case PIC18_OPCODE_ANDWF: return op_and(DEST, VRW, VRF);
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
	case PIC18_OPCODE_CLRWDT: return SEQ4(
		SETG("wdt", U8(0)),
		SETG("wdt_prescaler_count", IL_FALSE),
		SETG("to", IL_TRUE),
		SETG("pd", IL_TRUE));
	case PIC18_OPCODE_COMF: return SEQ3(
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
	case PIC18_OPCODE_DECF: break;
	case PIC18_OPCODE_DECFSZ: break;
	case PIC18_OPCODE_DCFSNZ: break;
	case PIC18_OPCODE_GOTO: break;
	case PIC18_OPCODE_IORWF: break;
	case PIC18_OPCODE_INFSNZ: break;
	case PIC18_OPCODE_INCF: break;
	case PIC18_OPCODE_INCFSZ: break;
	case PIC18_OPCODE_IORLW: break;
	case PIC18_OPCODE_LFSR: break;
	case PIC18_OPCODE_MOVF: break;
	case PIC18_OPCODE_MOVWF: break;
	case PIC18_OPCODE_MULWF: break;
	case PIC18_OPCODE_MOVLB: break;
	case PIC18_OPCODE_MOVFF: break;
	case PIC18_OPCODE_MOVLW: break;
	case PIC18_OPCODE_MULLW: break;
	case PIC18_OPCODE_NOP: return NOP();
	case PIC18_OPCODE_NEGF: break;
	case PIC18_OPCODE_POP: break;
	case PIC18_OPCODE_PUSH: break;
	case PIC18_OPCODE_RETURN: break;
	case PIC18_OPCODE_RETFIE: break;
	case PIC18_OPCODE_RLNCF: break;
	case PIC18_OPCODE_RRNCF: break;
	case PIC18_OPCODE_RLCF: break;
	case PIC18_OPCODE_RRCF: break;
	case PIC18_OPCODE_RCALL: break;
	case PIC18_OPCODE_RESET: break;
	case PIC18_OPCODE_RETLW: break;
	case PIC18_OPCODE_SLEEP: break;
	case PIC18_OPCODE_SETF: break;
	case PIC18_OPCODE_SUBWF: break;
	case PIC18_OPCODE_SUBWFB: break;
	case PIC18_OPCODE_SUBFWB: break;
	case PIC18_OPCODE_SWAPF: break;
	case PIC18_OPCODE_SUBLW: break;
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
