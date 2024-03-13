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

static RzILOpEffect *op_and(const char *dst,
	RzILOpPure *a, RzILOpPure *b) {
	return SEQ3(
		SETL("_res", LOGAND(a, b)),
		status_res(VARL("res")),
		SETG(dst, VARL("_res")));
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
	case PIC18_OPCODE_BTFSC: break;
	case PIC18_OPCODE_BTFSS: break;
	case PIC18_OPCODE_BTG: break;

	case PIC18_OPCODE_COMF: break;
	case PIC18_OPCODE_CALL: break;
	case PIC18_OPCODE_CLRWDT: break;
	case PIC18_OPCODE_CLRF: break;
	case PIC18_OPCODE_CPFSQT: break;
	case PIC18_OPCODE_CPFSEQ: break;
	case PIC18_OPCODE_CPFSLT: break;
	case PIC18_OPCODE_DAW: break;
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
