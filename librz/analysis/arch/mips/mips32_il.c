#include "mips_il.h"

#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * @note
 *                      **Macro Naming Conventions**
 *                      ----------------------------
 * - If there's IL at the beginning of names of macro, this means it will
 *   return either RzILOpEffect* or RzILOpPure*, whatever makes sense in that case.
 * - Use REG_OPND(opnd_idx) if you want only the name of register and you
 *   know it's an operand.
 * - Use ILREG_OPND(opnd_idx) if you want to get the VARG(reg_name) value.
 * - Similarly there are other macros to get operands in pure value or in
 *   RzILOpPure* value.
 *
 * - Macros ending with an "I" are for special cases when only of the operands
 *   is an immediate value. Other arguments can be used with VARL()
 * */

typedef RzILOpEffect *(*MipsILLifterFunction)(cs_insn *);
#define IL_LIFTER(name)      static RzILOpEffect *MipsLifter_##name(cs_insn *insn)
#define IL_LIFTER_NAME(name) MipsLifter_##name

// size of gprs in 32 bits
#define GPRLEN 32

// v  : value to be sign extended
// vn : bitsize of v
// n  : number of bits to sign extend to
#define SIGN_EXTEND(v, nv, n) ((v & (1 << (nv - 1))) ? (v | ((st64)(1 << (n - nv)) - 1) << nv) : v)
#define ZERO_EXTEND(v, nv, n) v & ~(((st64)(1 << (n - nv)) - 1) << nv)

// get instruction operand count
#define OPND_CNT() ((insn)->detail->mips.op_count)
// get instruction operand at given index type
#define OPND_TYPE(idx) ((insn)->detail->mips.operands[(idx)].type)

// get instruction operand at given index
#define OPND_IS_REG(idx) INSN_OPND_TYPE(insn, idx) == MIPS_OP_REG
#define REG_OPND(idx)    REG_NAME((insn)->detail->mips.operands[(idx)].reg)

// get instruction operand at given index
#define OPND_IS_MEM(insn, idx) INSN_OPND_TYPE(insn, idx) == MIPS_OP_MEM
#define MEM_OPND(idx)          ((insn)->detail->mips.operands[(idx)].mem)

// get instruction operand at given index
#define OPND_IS_IMM(insn, idx) INSN_OPND_TYPE(insn, idx) == MIPS_OP_IMM
#define IMM_OPND(idx)          ((insn)->detail->mips.operands[(idx)].imm)

#define INSN_ID(insn) (insn)->id

// register names to  map from enum to strings
static char *cpu_reg_enum_to_name_map[] = {
	[MIPS_REG_PC] = "pc",
	[MIPS_REG_0] = "zero",
	[MIPS_REG_1] = "r1",
	[MIPS_REG_2] = "r2",
	[MIPS_REG_3] = "r3",
	[MIPS_REG_4] = "r4",
	[MIPS_REG_5] = "r5",
	[MIPS_REG_6] = "r6",
	[MIPS_REG_7] = "r7",
	[MIPS_REG_8] = "r8",
	[MIPS_REG_9] = "r9",
	[MIPS_REG_10] = "r10",
	[MIPS_REG_11] = "r11",
	[MIPS_REG_12] = "r12",
	[MIPS_REG_13] = "r13",
	[MIPS_REG_14] = "r14",
	[MIPS_REG_15] = "r15",
	[MIPS_REG_16] = "r16",
	[MIPS_REG_17] = "r17",
	[MIPS_REG_18] = "r18",
	[MIPS_REG_19] = "r19",
	[MIPS_REG_20] = "r20",
	[MIPS_REG_21] = "r21",
	[MIPS_REG_22] = "r22",
	[MIPS_REG_23] = "r23",
	[MIPS_REG_24] = "r24",
	[MIPS_REG_25] = "r25",
	[MIPS_REG_26] = "r26",
	[MIPS_REG_27] = "r27",
	[MIPS_REG_28] = "r28",
	[MIPS_REG_29] = "r29",
	[MIPS_REG_30] = "r30",
	[MIPS_REG_31] = "r31",
};

// returns RzILOpPure*
#define REG_NAME(regenum)   cpu_reg_enum_to_name_map[regenum]
#define ILREG_OPND(opndidx) VARG(REG_OPND(opndidx))

// TODO: add status handlers

// res must be a global variable
// x and y must be local variable
#define ILCHECK_OVERFLOW(x, y, res) AND(XOR(MSB(VARL(x)), MSB(VARG(res))), XOR(MSB(VARL(y)), MSB(VARG(res))))
#define ILCHECK_CARRY(x, y, res)    OR(AND(MSB(VARL(x)), MSB(VARL(y))), AND(OR(MSB(VARL(x)), MSB(VARL(y))), INV(MSB(VARG(res)))))

// if second operands is an immediate value and only first and third are VARL compatible
#define ILCHECK_OVERFLOWI(x, y, res) AND(XOR(MSB(VARL(x)), MSB(VARG(res))), XOR(MSB(y), MSB(VARG(res))))
#define ILCHECK_CARRYI(x, y, res)    OR(AND(MSB(VARL(x)), MSB(y)), AND(OR(MSB(VARL(x)), MSB(y)), INV(MSB(VARG(res)))))

// rd must be a global variable
// rs and rt must be local variables
#define ILADD(rd, rs, rt) SETG((rd), ADD(VARL(rs), VARL(rt)))
#define ILAND(rd, rs, rt) SETG((rd), LOGAND(VARL(rs), VARL(rt)))

// imm is an immediate
#define ILADDI(rd, rs, imm) SETG((rd), ADD(VARL(rs), imm))
#define ILANDI(rd, rs, imm) SETG((rd), LOGAND(VARL(rs), imm))

// MISSING: ABS.fmt
// MISSING: ADD.fmt

IL_LIFTER(ABSQ_S) {
	return NULL;
}

/**
 * Add word.
 * Format : ADD rd, rs, rt
 * Description: GPR[rd] <- GPR[rs] + GPR[rt]
 * Exceptions: IntegerOverflow
 *
 * \param cs_insn* insn
 * \return RzILOpEffect*
 * */
IL_LIFTER(ADD) {
	// get operand registers
	RzILOpEffect *rs = SETL("rs", ILREG_OPND(1));
	RzILOpEffect *rt = SETL("rt", ILREG_OPND(2));

	// perform addition and set to destination register
	RzILOpEffect *add_op = ILADD(REG_OPND(0), "rs", "rt");
	RzILOpPure *overflow_check_op = IS_ZERO(ILCHECK_OVERFLOW("rs", "rt", REG_OPND(0)));
	RzILOpEffect *update_status_op = NULL; // TODO: set status flag

	return SEQ5(rs, rt, add_op, overflow_check_op, update_status_op);
}

/**
 * Add Immediate to PC.
 * Format: ADDIUPC rs, immdediate
 * Description: GPR[rs] <- (PC + sign_extend( immediate << 2 ))
 * Exceptions: None
 *
 * \param cs_insn* insn
 * \return RzILOpEffect*
 * */
IL_LIFTER(ADDIUPC) {
	st32 imm_val = (st32)IMM_OPND(1);
	imm_val = SIGN_EXTEND(imm_val, 21, GPRLEN);
	RzILOpPure *imm = S32(imm_val);

	RzILOpPure *pc = VARG(REG_NAME(MIPS_REG_PC));

	RzILOpEffect *add_op = SETG(REG_OPND(0), ADD(pc, imm));

	return add_op; // no need to return SEQ2(imm, add_op) here
}

IL_LIFTER(ADDIUR1SP) {
	return NULL;
}
IL_LIFTER(ADDIUR2) {
	return NULL;
}
IL_LIFTER(ADDIUS5) {
	return NULL;
}
IL_LIFTER(ADDIUSP) {
	return NULL;
}
IL_LIFTER(ADDQH) {
	return NULL;
}
IL_LIFTER(ADDQH_R) {
	return NULL;
}
IL_LIFTER(ADDQ) {
	return NULL;
}
IL_LIFTER(ADDQ_S) {
	return NULL;
}
IL_LIFTER(ADDSC) {
	return NULL;
}
IL_LIFTER(ADDS_A) {
	return NULL;
}
IL_LIFTER(ADDS_S) {
	return NULL;
}
IL_LIFTER(ADDS_U) {
	return NULL;
}
IL_LIFTER(ADDU16) {
	return NULL;
}
IL_LIFTER(ADDUH) {
	return NULL;
}
IL_LIFTER(ADDUH_R) {
	return NULL;
}

/**
 * Add Unsigned word.
 * Format: ADDU rd, rs, rt
 * Description: GPR[rd] <- GPR[rs] + GPR[rt]
 * Exceptions: None
 *
 * \param cs_insn* insn
 * \return RzILOpEffect*
 * */
IL_LIFTER(ADDU) {
	RzILOpEffect *rs = SETL("rs", ILREG_OPND(1));
	RzILOpEffect *rt = SETL("rt", ILREG_OPND(2));

	RzILOpEffect *add_op = ILADD(REG_OPND(0), "rs", "rt");
	return SEQ3(rs, rt, add_op);
}

IL_LIFTER(ADDU_S) {
	return NULL;
}
IL_LIFTER(ADDVI) {
	return NULL;
}
IL_LIFTER(ADDV) {
	return NULL;
}
IL_LIFTER(ADDWC) {
	return NULL;
}
IL_LIFTER(ADD_A) {
	return NULL;
}

/**
 * Add Immediate word.
 * Format: ADDI rt, rs, immediate
 * Description: GPR[rt] <- GPR[rs] + immediate
 * Exceptions: IntegerOverflow
 *
 * \param cs_insn* insn
 * \return RzILOpEffect*
 * */
IL_LIFTER(ADDI) {
	RzILOpEffect *rs = SETL("rs", ILREG_OPND(1));

	st32 imm_val = (st32)IMM_OPND(1);
	imm_val = SIGN_EXTEND(imm_val, 16, GPRLEN);
	RzILOpPure *imm = S32(imm_val);

	RzILOpEffect *add_op = ILADDI(REG_OPND(0), "rs", imm);
	RzILOpPure *overflow_check_op = IS_ZERO(ILCHECK_OVERFLOWI("rs", imm, REG_OPND(0)));
	RzILOpEffect *update_status_op = NULL; // TODO: update status

	return SEQ5(rs, imm, add_op, overflow_check_op, update_status_op);
}

/**
 * Add Immediate Unsigned Word.
 * Format: ADDI rt, rs, immediate
 * Description: GPR[rt] <- GPR[rs] + immediate
 * Exceptions: None
 *
 * \param cs_insn* insn
 * \return RzILOpEffect*
 * */
IL_LIFTER(ADDIU) {
	RzILOpEffect *rs = SETL("rs", ILREG_OPND(1));

	st32 imm_val = (st32)IMM_OPND(1);
	imm_val = SIGN_EXTEND(imm_val, 16, GPRLEN);
	RzILOpPure *imm = S32(imm_val);

	RzILOpEffect *add_op = ILADDI(REG_OPND(0), "rs", imm);

	return SEQ2(rs, add_op);
}

/**
 * Align.
 * Concatenate two GPRs and extract a contiguous subset
 * at a byte position.
 * Format: ALIGN rd, rs, rt, bp
 * Description: GPR[rd] <- (GPR[rt] << (8*bp)) or (GPR[rs] >> (GPRLEN - 8*bp))
 * Exceptions: None
 *
 * \param cs_insn* insn
 * \return RzILOpEffect*
 * */
IL_LIFTER(ALIGN) {
	RzILOpEffect *rs = SETL("rs", ILREG_OPND(1));
	RzILOpEffect *rt = SETL("rt", ILREG_OPND(2));
	ut8 bp = 8 * IMM_OPND(3); // 8*bp is used everywhere

	RzILOpEffect *align_op = SETL(REG_OPND(0), LOGOR(SHIFTL0(VARL("rt"), U8(bp)), SHIFTR0(VARL("rs"), U8(GPRLEN - bp))));

	return SEQ3(rs, rt, align_op);
}

// MISSING: ALNV.PS

/**
 * Aligned Add Upper Intermedate to PC.
 * Format: ALUIPC rs, immediate
 * Description: GPR[rs] <- ~0x0FFFF & (PC + sign_extend(immediate << 16))
 * Exceptions: None
 *
 * \param cs_insn* insn
 * \return RzILOpEffect*
 * */
IL_LIFTER(ALUIPC) {
	// NOTE: Do I really need to sign extend here?
	// Value after and before sign extension should be same.
	st32 imm_val = IMM_OPND(1) << 16;
	RzILOpPure *imm = S32(imm_val);

	RzILOpPure *pc = VARG(REG_NAME(MIPS_REG_PC));
	RzILOpEffect *and_add_op = SETG(REG_OPND(0), LOGAND(U32(0xFFFF0000), ADD(pc, imm)));

	return and_add_op;
}

/**
 * And
 * Perform bitwise logical AND.
 * Format: AND rd, rs, rt
 * Description: GPR[rd] <- GPR[rs] and GPR[rt]
 * Exceptions: None
 *
 * \param cs_insn* insn
 * \return RzILOpEffect*
 * */
IL_LIFTER(AND) {
	RzILOpEffect *rs = SETL("rs", ILREG_OPND(1));
	RzILOpEffect *rt = SETL("rt", ILREG_OPND(2));

	RzILOpEffect *and_op = ILAND(REG_OPND(0), "rs", "rt");

	return SEQ3(rs, rt, and_op);
}

IL_LIFTER(AND16) {
	return NULL;
}
IL_LIFTER(ANDI16) {
	return NULL;
}

/**
 * And Immediate word
 * Format: AND rd, rs, immediate
 * Description: GPR[rd] <- GPR[rs] and zero_extend(immediate)
 * Exceptions: None
 *
 * \param cs_insn* insn
 * \return RzILOpEffect*
 * */
IL_LIFTER(ANDI) {
	RzILOpEffect *rs = SETL("rs", ILREG_OPND(1));

	st32 imm_val = (st32)IMM_OPND(2);
	imm_val = ZERO_EXTEND(imm_val, 16, GPRLEN);
	RzILOpPure *imm = S32(imm_val);

	RzILOpEffect *and_op = ILANDI(REG_OPND(0), "rs", imm);

	return SEQ2(rs, and_op);
}

IL_LIFTER(APPEND) {
	return NULL;
}
IL_LIFTER(ASUB_S) {
	return NULL;
}
IL_LIFTER(ASUB_U) {
	return NULL;
}

/**
 * And Immediate to Upper bits
 * Format: AUI rd, rs, immediate
 * Description: GPR[rd] <- GPR[rs] and sign_extend(immediate << 16)
 * Exceptions: None
 *
 * \param cs_insn* insn
 * \return RzILOpEffect*
 * */
IL_LIFTER(AUI) {
	RzILOpEffect *rs = SETL("rs", ILREG_OPND(1));

	// NOTE: Sign extend here?
	st32 imm_val = (st32)IMM_OPND(2) << 16;
	RzILOpPure *imm = S32(imm_val);

	RzILOpEffect *add_op = ILADDI(REG_OPND(0), "rs", imm);

	return SEQ2(rs, add_op);
}

/**
 * And Upper Immediate to PC
 * Format: AUIPC rs, immediate
 * Description: GPR[rs] <- PC and immediate << 16
 * Exceptions: None
 *
 * \param cs_insn* insn
 * \return RzILOpEffect*
 * */
IL_LIFTER(AUIPC) {
	// NOTE: Sign extend here?
	st32 imm_val = (st32)IMM_OPND(1) << 16;
	RzILOpPure *imm = S32(imm_val);

	RzILOpPure *pc = VARG(REG_NAME(MIPS_REG_PC));

	RzILOpEffect *add_op = SETG(REG_OPND(0), ADD(pc, imm));

	return add_op;
}

IL_LIFTER(AVER_S) {
	return NULL;
}
IL_LIFTER(AVER_U) {
	return NULL;
}
IL_LIFTER(AVE_S) {
	return NULL;
}
IL_LIFTER(AVE_U) {
	return NULL;
}
IL_LIFTER(B16) {
	return NULL;
}
IL_LIFTER(BADDU) {
	return NULL;
}
IL_LIFTER(BAL) {
	return NULL;
}
IL_LIFTER(BALC) {
	return NULL;
}
IL_LIFTER(BALIGN) {
	return NULL;
}
IL_LIFTER(BBIT0) {
	return NULL;
}
IL_LIFTER(BBIT032) {
	return NULL;
}
IL_LIFTER(BBIT1) {
	return NULL;
}
IL_LIFTER(BBIT132) {
	return NULL;
}
IL_LIFTER(BC) {
	return NULL;
}
IL_LIFTER(BC0F) {
	return NULL;
}
IL_LIFTER(BC0FL) {
	return NULL;
}
IL_LIFTER(BC0T) {
	return NULL;
}
IL_LIFTER(BC0TL) {
	return NULL;
}
IL_LIFTER(BC1EQZ) {
	return NULL;
}
IL_LIFTER(BC1F) {
	return NULL;
}
IL_LIFTER(BC1FL) {
	return NULL;
}
IL_LIFTER(BC1NEZ) {
	return NULL;
}
IL_LIFTER(BC1T) {
	return NULL;
}
IL_LIFTER(BC1TL) {
	return NULL;
}
IL_LIFTER(BC2EQZ) {
	return NULL;
}
IL_LIFTER(BC2F) {
	return NULL;
}
IL_LIFTER(BC2FL) {
	return NULL;
}
IL_LIFTER(BC2NEZ) {
	return NULL;
}
IL_LIFTER(BC2T) {
	return NULL;
}
IL_LIFTER(BC2TL) {
	return NULL;
}
IL_LIFTER(BC3F) {
	return NULL;
}
IL_LIFTER(BC3FL) {
	return NULL;
}
IL_LIFTER(BC3T) {
	return NULL;
}
IL_LIFTER(BC3TL) {
	return NULL;
}
IL_LIFTER(BCLRI) {
	return NULL;
}
IL_LIFTER(BCLR) {
	return NULL;
}
IL_LIFTER(BEQ) {
	return NULL;
}
IL_LIFTER(BEQC) {
	return NULL;
}
IL_LIFTER(BEQL) {
	return NULL;
}
IL_LIFTER(BEQZ16) {
	return NULL;
}
IL_LIFTER(BEQZALC) {
	return NULL;
}
IL_LIFTER(BEQZC) {
	return NULL;
}
IL_LIFTER(BGEC) {
	return NULL;
}
IL_LIFTER(BGEUC) {
	return NULL;
}
IL_LIFTER(BGEZ) {
	return NULL;
}
IL_LIFTER(BGEZAL) {
	return NULL;
}
IL_LIFTER(BGEZALC) {
	return NULL;
}
IL_LIFTER(BGEZALL) {
	return NULL;
}
IL_LIFTER(BGEZALS) {
	return NULL;
}
IL_LIFTER(BGEZC) {
	return NULL;
}
IL_LIFTER(BGEZL) {
	return NULL;
}
IL_LIFTER(BGTZ) {
	return NULL;
}
IL_LIFTER(BGTZALC) {
	return NULL;
}
IL_LIFTER(BGTZC) {
	return NULL;
}
IL_LIFTER(BGTZL) {
	return NULL;
}
IL_LIFTER(BINSLI) {
	return NULL;
}
IL_LIFTER(BINSL) {
	return NULL;
}
IL_LIFTER(BINSRI) {
	return NULL;
}
IL_LIFTER(BINSR) {
	return NULL;
}
IL_LIFTER(BITREV) {
	return NULL;
}
IL_LIFTER(BITSWAP) {
	return NULL;
}
IL_LIFTER(BLEZ) {
	return NULL;
}
IL_LIFTER(BLEZALC) {
	return NULL;
}
IL_LIFTER(BLEZC) {
	return NULL;
}
IL_LIFTER(BLEZL) {
	return NULL;
}
IL_LIFTER(BLTC) {
	return NULL;
}
IL_LIFTER(BLTUC) {
	return NULL;
}
IL_LIFTER(BLTZ) {
	return NULL;
}
IL_LIFTER(BLTZAL) {
	return NULL;
}
IL_LIFTER(BLTZALC) {
	return NULL;
}
IL_LIFTER(BLTZALL) {
	return NULL;
}
IL_LIFTER(BLTZALS) {
	return NULL;
}
IL_LIFTER(BLTZC) {
	return NULL;
}
IL_LIFTER(BLTZL) {
	return NULL;
}
IL_LIFTER(BMNZI) {
	return NULL;
}
IL_LIFTER(BMNZ) {
	return NULL;
}
IL_LIFTER(BMZI) {
	return NULL;
}
IL_LIFTER(BMZ) {
	return NULL;
}
IL_LIFTER(BNE) {
	return NULL;
}
IL_LIFTER(BNEC) {
	return NULL;
}
IL_LIFTER(BNEGI) {
	return NULL;
}
IL_LIFTER(BNEG) {
	return NULL;
}
IL_LIFTER(BNEL) {
	return NULL;
}
IL_LIFTER(BNEZ16) {
	return NULL;
}
IL_LIFTER(BNEZALC) {
	return NULL;
}
IL_LIFTER(BNEZC) {
	return NULL;
}
IL_LIFTER(BNVC) {
	return NULL;
}
IL_LIFTER(BNZ) {
	return NULL;
}
IL_LIFTER(BOVC) {
	return NULL;
}
IL_LIFTER(BPOSGE32) {
	return NULL;
}
IL_LIFTER(BREAK) {
	return NULL;
}
IL_LIFTER(BREAK16) {
	return NULL;
}
IL_LIFTER(BSELI) {
	return NULL;
}
IL_LIFTER(BSEL) {
	return NULL;
}
IL_LIFTER(BSETI) {
	return NULL;
}
IL_LIFTER(BSET) {
	return NULL;
}
IL_LIFTER(BZ) {
	return NULL;
}
IL_LIFTER(BEQZ) {
	return NULL;
}
IL_LIFTER(B) {
	return NULL;
}
IL_LIFTER(BNEZ) {
	return NULL;
}
IL_LIFTER(BTEQZ) {
	return NULL;
}
IL_LIFTER(BTNEZ) {
	return NULL;
}
IL_LIFTER(CACHE) {
	return NULL;
}
IL_LIFTER(CEIL) {
	return NULL;
}
IL_LIFTER(CEQI) {
	return NULL;
}
IL_LIFTER(CEQ) {
	return NULL;
}
IL_LIFTER(CFC1) {
	return NULL;
}
IL_LIFTER(CFCMSA) {
	return NULL;
}
IL_LIFTER(CINS) {
	return NULL;
}
IL_LIFTER(CINS32) {
	return NULL;
}
IL_LIFTER(CLASS) {
	return NULL;
}
IL_LIFTER(CLEI_S) {
	return NULL;
}
IL_LIFTER(CLEI_U) {
	return NULL;
}
IL_LIFTER(CLE_S) {
	return NULL;
}
IL_LIFTER(CLE_U) {
	return NULL;
}
IL_LIFTER(CLO) {
	return NULL;
}
IL_LIFTER(CLTI_S) {
	return NULL;
}
IL_LIFTER(CLTI_U) {
	return NULL;
}
IL_LIFTER(CLT_S) {
	return NULL;
}
IL_LIFTER(CLT_U) {
	return NULL;
}
IL_LIFTER(CLZ) {
	return NULL;
}
IL_LIFTER(CMPGDU) {
	return NULL;
}
IL_LIFTER(CMPGU) {
	return NULL;
}
IL_LIFTER(CMPU) {
	return NULL;
}
IL_LIFTER(CMP) {
	return NULL;
}
IL_LIFTER(COPY_S) {
	return NULL;
}
IL_LIFTER(COPY_U) {
	return NULL;
}
IL_LIFTER(CTC1) {
	return NULL;
}
IL_LIFTER(CTCMSA) {
	return NULL;
}
IL_LIFTER(CVT) {
	return NULL;
}
IL_LIFTER(C) {
	return NULL;
}
IL_LIFTER(CMPI) {
	return NULL;
}
IL_LIFTER(DADD) {
	return NULL;
}
IL_LIFTER(DADDI) {
	return NULL;
}
IL_LIFTER(DADDIU) {
	return NULL;
}
IL_LIFTER(DADDU) {
	return NULL;
}
IL_LIFTER(DAHI) {
	return NULL;
}
IL_LIFTER(DALIGN) {
	return NULL;
}
IL_LIFTER(DATI) {
	return NULL;
}
IL_LIFTER(DAUI) {
	return NULL;
}
IL_LIFTER(DBITSWAP) {
	return NULL;
}
IL_LIFTER(DCLO) {
	return NULL;
}
IL_LIFTER(DCLZ) {
	return NULL;
}
IL_LIFTER(DDIV) {
	return NULL;
}
IL_LIFTER(DDIVU) {
	return NULL;
}
IL_LIFTER(DERET) {
	return NULL;
}
IL_LIFTER(DEXT) {
	return NULL;
}
IL_LIFTER(DEXTM) {
	return NULL;
}
IL_LIFTER(DEXTU) {
	return NULL;
}
IL_LIFTER(DI) {
	return NULL;
}
IL_LIFTER(DINS) {
	return NULL;
}
IL_LIFTER(DINSM) {
	return NULL;
}
IL_LIFTER(DINSU) {
	return NULL;
}
IL_LIFTER(DIV) {
	return NULL;
}
IL_LIFTER(DIVU) {
	return NULL;
}
IL_LIFTER(DIV_S) {
	return NULL;
}
IL_LIFTER(DIV_U) {
	return NULL;
}
IL_LIFTER(DLSA) {
	return NULL;
}
IL_LIFTER(DMFC0) {
	return NULL;
}
IL_LIFTER(DMFC1) {
	return NULL;
}
IL_LIFTER(DMFC2) {
	return NULL;
}
IL_LIFTER(DMOD) {
	return NULL;
}
IL_LIFTER(DMODU) {
	return NULL;
}
IL_LIFTER(DMTC0) {
	return NULL;
}
IL_LIFTER(DMTC1) {
	return NULL;
}
IL_LIFTER(DMTC2) {
	return NULL;
}
IL_LIFTER(DMUH) {
	return NULL;
}
IL_LIFTER(DMUHU) {
	return NULL;
}
IL_LIFTER(DMUL) {
	return NULL;
}
IL_LIFTER(DMULT) {
	return NULL;
}
IL_LIFTER(DMULTU) {
	return NULL;
}
IL_LIFTER(DMULU) {
	return NULL;
}
IL_LIFTER(DOTP_S) {
	return NULL;
}
IL_LIFTER(DOTP_U) {
	return NULL;
}
IL_LIFTER(DPADD_S) {
	return NULL;
}
IL_LIFTER(DPADD_U) {
	return NULL;
}
IL_LIFTER(DPAQX_SA) {
	return NULL;
}
IL_LIFTER(DPAQX_S) {
	return NULL;
}
IL_LIFTER(DPAQ_SA) {
	return NULL;
}
IL_LIFTER(DPAQ_S) {
	return NULL;
}
IL_LIFTER(DPAU) {
	return NULL;
}
IL_LIFTER(DPAX) {
	return NULL;
}
IL_LIFTER(DPA) {
	return NULL;
}
IL_LIFTER(DPOP) {
	return NULL;
}
IL_LIFTER(DPSQX_SA) {
	return NULL;
}
IL_LIFTER(DPSQX_S) {
	return NULL;
}
IL_LIFTER(DPSQ_SA) {
	return NULL;
}
IL_LIFTER(DPSQ_S) {
	return NULL;
}
IL_LIFTER(DPSUB_S) {
	return NULL;
}
IL_LIFTER(DPSUB_U) {
	return NULL;
}
IL_LIFTER(DPSU) {
	return NULL;
}
IL_LIFTER(DPSX) {
	return NULL;
}
IL_LIFTER(DPS) {
	return NULL;
}
IL_LIFTER(DROTR) {
	return NULL;
}
IL_LIFTER(DROTR32) {
	return NULL;
}
IL_LIFTER(DROTRV) {
	return NULL;
}
IL_LIFTER(DSBH) {
	return NULL;
}
IL_LIFTER(DSHD) {
	return NULL;
}
IL_LIFTER(DSLL) {
	return NULL;
}
IL_LIFTER(DSLL32) {
	return NULL;
}
IL_LIFTER(DSLLV) {
	return NULL;
}
IL_LIFTER(DSRA) {
	return NULL;
}
IL_LIFTER(DSRA32) {
	return NULL;
}
IL_LIFTER(DSRAV) {
	return NULL;
}
IL_LIFTER(DSRL) {
	return NULL;
}
IL_LIFTER(DSRL32) {
	return NULL;
}
IL_LIFTER(DSRLV) {
	return NULL;
}
IL_LIFTER(DSUB) {
	return NULL;
}
IL_LIFTER(DSUBU) {
	return NULL;
}
IL_LIFTER(EHB) {
	return NULL;
}
IL_LIFTER(EI) {
	return NULL;
}
IL_LIFTER(ERET) {
	return NULL;
}
IL_LIFTER(EXT) {
	return NULL;
}
IL_LIFTER(EXTP) {
	return NULL;
}
IL_LIFTER(EXTPDP) {
	return NULL;
}
IL_LIFTER(EXTPDPV) {
	return NULL;
}
IL_LIFTER(EXTPV) {
	return NULL;
}
IL_LIFTER(EXTRV_RS) {
	return NULL;
}
IL_LIFTER(EXTRV_R) {
	return NULL;
}
IL_LIFTER(EXTRV_S) {
	return NULL;
}
IL_LIFTER(EXTRV) {
	return NULL;
}
IL_LIFTER(EXTR_RS) {
	return NULL;
}
IL_LIFTER(EXTR_R) {
	return NULL;
}
IL_LIFTER(EXTR_S) {
	return NULL;
}
IL_LIFTER(EXTR) {
	return NULL;
}
IL_LIFTER(EXTS) {
	return NULL;
}
IL_LIFTER(EXTS32) {
	return NULL;
}
IL_LIFTER(ABS) {
	return NULL;
}
IL_LIFTER(FADD) {
	return NULL;
}
IL_LIFTER(FCAF) {
	return NULL;
}
IL_LIFTER(FCEQ) {
	return NULL;
}
IL_LIFTER(FCLASS) {
	return NULL;
}
IL_LIFTER(FCLE) {
	return NULL;
}
IL_LIFTER(FCLT) {
	return NULL;
}
IL_LIFTER(FCNE) {
	return NULL;
}
IL_LIFTER(FCOR) {
	return NULL;
}
IL_LIFTER(FCUEQ) {
	return NULL;
}
IL_LIFTER(FCULE) {
	return NULL;
}
IL_LIFTER(FCULT) {
	return NULL;
}
IL_LIFTER(FCUNE) {
	return NULL;
}
IL_LIFTER(FCUN) {
	return NULL;
}
IL_LIFTER(FDIV) {
	return NULL;
}
IL_LIFTER(FEXDO) {
	return NULL;
}
IL_LIFTER(FEXP2) {
	return NULL;
}
IL_LIFTER(FEXUPL) {
	return NULL;
}
IL_LIFTER(FEXUPR) {
	return NULL;
}
IL_LIFTER(FFINT_S) {
	return NULL;
}
IL_LIFTER(FFINT_U) {
	return NULL;
}
IL_LIFTER(FFQL) {
	return NULL;
}
IL_LIFTER(FFQR) {
	return NULL;
}
IL_LIFTER(FILL) {
	return NULL;
}
IL_LIFTER(FLOG2) {
	return NULL;
}
IL_LIFTER(FLOOR) {
	return NULL;
}
IL_LIFTER(FMADD) {
	return NULL;
}
IL_LIFTER(FMAX_A) {
	return NULL;
}
IL_LIFTER(FMAX) {
	return NULL;
}
IL_LIFTER(FMIN_A) {
	return NULL;
}
IL_LIFTER(FMIN) {
	return NULL;
}
IL_LIFTER(MOV) {
	return NULL;
}
IL_LIFTER(FMSUB) {
	return NULL;
}
IL_LIFTER(FMUL) {
	return NULL;
}
IL_LIFTER(MUL) {
	return NULL;
}
IL_LIFTER(NEG) {
	return NULL;
}
IL_LIFTER(FRCP) {
	return NULL;
}
IL_LIFTER(FRINT) {
	return NULL;
}
IL_LIFTER(FRSQRT) {
	return NULL;
}
IL_LIFTER(FSAF) {
	return NULL;
}
IL_LIFTER(FSEQ) {
	return NULL;
}
IL_LIFTER(FSLE) {
	return NULL;
}
IL_LIFTER(FSLT) {
	return NULL;
}
IL_LIFTER(FSNE) {
	return NULL;
}
IL_LIFTER(FSOR) {
	return NULL;
}
IL_LIFTER(FSQRT) {
	return NULL;
}
IL_LIFTER(SQRT) {
	return NULL;
}
IL_LIFTER(FSUB) {
	return NULL;
}
IL_LIFTER(SUB) {
	return NULL;
}
IL_LIFTER(FSUEQ) {
	return NULL;
}
IL_LIFTER(FSULE) {
	return NULL;
}
IL_LIFTER(FSULT) {
	return NULL;
}
IL_LIFTER(FSUNE) {
	return NULL;
}
IL_LIFTER(FSUN) {
	return NULL;
}
IL_LIFTER(FTINT_S) {
	return NULL;
}
IL_LIFTER(FTINT_U) {
	return NULL;
}
IL_LIFTER(FTQ) {
	return NULL;
}
IL_LIFTER(FTRUNC_S) {
	return NULL;
}
IL_LIFTER(FTRUNC_U) {
	return NULL;
}
IL_LIFTER(HADD_S) {
	return NULL;
}
IL_LIFTER(HADD_U) {
	return NULL;
}
IL_LIFTER(HSUB_S) {
	return NULL;
}
IL_LIFTER(HSUB_U) {
	return NULL;
}
IL_LIFTER(ILVEV) {
	return NULL;
}
IL_LIFTER(ILVL) {
	return NULL;
}
IL_LIFTER(ILVOD) {
	return NULL;
}
IL_LIFTER(ILVR) {
	return NULL;
}
IL_LIFTER(INS) {
	return NULL;
}
IL_LIFTER(INSERT) {
	return NULL;
}
IL_LIFTER(INSV) {
	return NULL;
}
IL_LIFTER(INSVE) {
	return NULL;
}
IL_LIFTER(J) {
	return NULL;
}
IL_LIFTER(JAL) {
	return NULL;
}
IL_LIFTER(JALR) {
	return NULL;
}
IL_LIFTER(JALRS16) {
	return NULL;
}
IL_LIFTER(JALRS) {
	return NULL;
}
IL_LIFTER(JALS) {
	return NULL;
}
IL_LIFTER(JALX) {
	return NULL;
}
IL_LIFTER(JIALC) {
	return NULL;
}
IL_LIFTER(JIC) {
	return NULL;
}
IL_LIFTER(JR) {
	return NULL;
}
IL_LIFTER(JR16) {
	return NULL;
}
IL_LIFTER(JRADDIUSP) {
	return NULL;
}
IL_LIFTER(JRC) {
	return NULL;
}
IL_LIFTER(JALRC) {
	return NULL;
}
IL_LIFTER(LB) {
	return NULL;
}
IL_LIFTER(LBU16) {
	return NULL;
}
IL_LIFTER(LBUX) {
	return NULL;
}
IL_LIFTER(LBU) {
	return NULL;
}
IL_LIFTER(LD) {
	return NULL;
}
IL_LIFTER(LDC1) {
	return NULL;
}
IL_LIFTER(LDC2) {
	return NULL;
}
IL_LIFTER(LDC3) {
	return NULL;
}
IL_LIFTER(LDI) {
	return NULL;
}
IL_LIFTER(LDL) {
	return NULL;
}
IL_LIFTER(LDPC) {
	return NULL;
}
IL_LIFTER(LDR) {
	return NULL;
}
IL_LIFTER(LDXC1) {
	return NULL;
}
IL_LIFTER(LH) {
	return NULL;
}
IL_LIFTER(LHU16) {
	return NULL;
}
IL_LIFTER(LHX) {
	return NULL;
}
IL_LIFTER(LHU) {
	return NULL;
}
IL_LIFTER(LI16) {
	return NULL;
}
IL_LIFTER(LL) {
	return NULL;
}
IL_LIFTER(LLD) {
	return NULL;
}
IL_LIFTER(LSA) {
	return NULL;
}
IL_LIFTER(LUXC1) {
	return NULL;
}
IL_LIFTER(LUI) {
	return NULL;
}
IL_LIFTER(LW) {
	return NULL;
}
IL_LIFTER(LW16) {
	return NULL;
}
IL_LIFTER(LWC1) {
	return NULL;
}
IL_LIFTER(LWC2) {
	return NULL;
}
IL_LIFTER(LWC3) {
	return NULL;
}
IL_LIFTER(LWL) {
	return NULL;
}
IL_LIFTER(LWM16) {
	return NULL;
}
IL_LIFTER(LWM32) {
	return NULL;
}
IL_LIFTER(LWPC) {
	return NULL;
}
IL_LIFTER(LWP) {
	return NULL;
}
IL_LIFTER(LWR) {
	return NULL;
}
IL_LIFTER(LWUPC) {
	return NULL;
}
IL_LIFTER(LWU) {
	return NULL;
}
IL_LIFTER(LWX) {
	return NULL;
}
IL_LIFTER(LWXC1) {
	return NULL;
}
IL_LIFTER(LWXS) {
	return NULL;
}
IL_LIFTER(LI) {
	return NULL;
}
IL_LIFTER(MADD) {
	return NULL;
}
IL_LIFTER(MADDF) {
	return NULL;
}
IL_LIFTER(MADDR_Q) {
	return NULL;
}
IL_LIFTER(MADDU) {
	return NULL;
}
IL_LIFTER(MADDV) {
	return NULL;
}
IL_LIFTER(MADD_Q) {
	return NULL;
}
IL_LIFTER(MAQ_SA) {
	return NULL;
}
IL_LIFTER(MAQ_S) {
	return NULL;
}
IL_LIFTER(MAXA) {
	return NULL;
}
IL_LIFTER(MAXI_S) {
	return NULL;
}
IL_LIFTER(MAXI_U) {
	return NULL;
}
IL_LIFTER(MAX_A) {
	return NULL;
}
IL_LIFTER(MAX) {
	return NULL;
}
IL_LIFTER(MAX_S) {
	return NULL;
}
IL_LIFTER(MAX_U) {
	return NULL;
}
IL_LIFTER(MFC0) {
	return NULL;
}
IL_LIFTER(MFC1) {
	return NULL;
}
IL_LIFTER(MFC2) {
	return NULL;
}
IL_LIFTER(MFHC1) {
	return NULL;
}
IL_LIFTER(MFHI) {
	return NULL;
}
IL_LIFTER(MFLO) {
	return NULL;
}
IL_LIFTER(MINA) {
	return NULL;
}
IL_LIFTER(MINI_S) {
	return NULL;
}
IL_LIFTER(MINI_U) {
	return NULL;
}
IL_LIFTER(MIN_A) {
	return NULL;
}
IL_LIFTER(MIN) {
	return NULL;
}
IL_LIFTER(MIN_S) {
	return NULL;
}
IL_LIFTER(MIN_U) {
	return NULL;
}
IL_LIFTER(MOD) {
	return NULL;
}
IL_LIFTER(MODSUB) {
	return NULL;
}
IL_LIFTER(MODU) {
	return NULL;
}
IL_LIFTER(MOD_S) {
	return NULL;
}
IL_LIFTER(MOD_U) {
	return NULL;
}
IL_LIFTER(MOVE) {
	return NULL;
}
IL_LIFTER(MOVEP) {
	return NULL;
}
IL_LIFTER(MOVF) {
	return NULL;
}
IL_LIFTER(MOVN) {
	return NULL;
}
IL_LIFTER(MOVT) {
	return NULL;
}
IL_LIFTER(MOVZ) {
	return NULL;
}
IL_LIFTER(MSUB) {
	return NULL;
}
IL_LIFTER(MSUBF) {
	return NULL;
}
IL_LIFTER(MSUBR_Q) {
	return NULL;
}
IL_LIFTER(MSUBU) {
	return NULL;
}
IL_LIFTER(MSUBV) {
	return NULL;
}
IL_LIFTER(MSUB_Q) {
	return NULL;
}
IL_LIFTER(MTC0) {
	return NULL;
}
IL_LIFTER(MTC1) {
	return NULL;
}
IL_LIFTER(MTC2) {
	return NULL;
}
IL_LIFTER(MTHC1) {
	return NULL;
}
IL_LIFTER(MTHI) {
	return NULL;
}
IL_LIFTER(MTHLIP) {
	return NULL;
}
IL_LIFTER(MTLO) {
	return NULL;
}
IL_LIFTER(MTM0) {
	return NULL;
}
IL_LIFTER(MTM1) {
	return NULL;
}
IL_LIFTER(MTM2) {
	return NULL;
}
IL_LIFTER(MTP0) {
	return NULL;
}
IL_LIFTER(MTP1) {
	return NULL;
}
IL_LIFTER(MTP2) {
	return NULL;
}
IL_LIFTER(MUH) {
	return NULL;
}
IL_LIFTER(MUHU) {
	return NULL;
}
IL_LIFTER(MULEQ_S) {
	return NULL;
}
IL_LIFTER(MULEU_S) {
	return NULL;
}
IL_LIFTER(MULQ_RS) {
	return NULL;
}
IL_LIFTER(MULQ_S) {
	return NULL;
}
IL_LIFTER(MULR_Q) {
	return NULL;
}
IL_LIFTER(MULSAQ_S) {
	return NULL;
}
IL_LIFTER(MULSA) {
	return NULL;
}
IL_LIFTER(MULT) {
	return NULL;
}
IL_LIFTER(MULTU) {
	return NULL;
}
IL_LIFTER(MULU) {
	return NULL;
}
IL_LIFTER(MULV) {
	return NULL;
}
IL_LIFTER(MUL_Q) {
	return NULL;
}
IL_LIFTER(MUL_S) {
	return NULL;
}
IL_LIFTER(NLOC) {
	return NULL;
}
IL_LIFTER(NLZC) {
	return NULL;
}
IL_LIFTER(NMADD) {
	return NULL;
}
IL_LIFTER(NMSUB) {
	return NULL;
}
IL_LIFTER(NOR) {
	return NULL;
}
IL_LIFTER(NORI) {
	return NULL;
}
IL_LIFTER(NOT16) {
	return NULL;
}
IL_LIFTER(NOT) {
	return NULL;
}
IL_LIFTER(OR) {
	return NULL;
}
IL_LIFTER(OR16) {
	return NULL;
}
IL_LIFTER(ORI) {
	return NULL;
}
IL_LIFTER(PACKRL) {
	return NULL;
}
IL_LIFTER(PAUSE) {
	return NULL;
}
IL_LIFTER(PCKEV) {
	return NULL;
}
IL_LIFTER(PCKOD) {
	return NULL;
}
IL_LIFTER(PCNT) {
	return NULL;
}
IL_LIFTER(PICK) {
	return NULL;
}
IL_LIFTER(POP) {
	return NULL;
}
IL_LIFTER(PRECEQU) {
	return NULL;
}
IL_LIFTER(PRECEQ) {
	return NULL;
}
IL_LIFTER(PRECEU) {
	return NULL;
}
IL_LIFTER(PRECRQU_S) {
	return NULL;
}
IL_LIFTER(PRECRQ) {
	return NULL;
}
IL_LIFTER(PRECRQ_RS) {
	return NULL;
}
IL_LIFTER(PRECR) {
	return NULL;
}
IL_LIFTER(PRECR_SRA) {
	return NULL;
}
IL_LIFTER(PRECR_SRA_R) {
	return NULL;
}
IL_LIFTER(PREF) {
	return NULL;
}
IL_LIFTER(PREPEND) {
	return NULL;
}
IL_LIFTER(RADDU) {
	return NULL;
}
IL_LIFTER(RDDSP) {
	return NULL;
}
IL_LIFTER(RDHWR) {
	return NULL;
}
IL_LIFTER(REPLV) {
	return NULL;
}
IL_LIFTER(REPL) {
	return NULL;
}
IL_LIFTER(RINT) {
	return NULL;
}
IL_LIFTER(ROTR) {
	return NULL;
}
IL_LIFTER(ROTRV) {
	return NULL;
}
IL_LIFTER(ROUND) {
	return NULL;
}
IL_LIFTER(SAT_S) {
	return NULL;
}
IL_LIFTER(SAT_U) {
	return NULL;
}
IL_LIFTER(SB) {
	return NULL;
}
IL_LIFTER(SB16) {
	return NULL;
}
IL_LIFTER(SC) {
	return NULL;
}
IL_LIFTER(SCD) {
	return NULL;
}
IL_LIFTER(SD) {
	return NULL;
}
IL_LIFTER(SDBBP) {
	return NULL;
}
IL_LIFTER(SDBBP16) {
	return NULL;
}
IL_LIFTER(SDC1) {
	return NULL;
}
IL_LIFTER(SDC2) {
	return NULL;
}
IL_LIFTER(SDC3) {
	return NULL;
}
IL_LIFTER(SDL) {
	return NULL;
}
IL_LIFTER(SDR) {
	return NULL;
}
IL_LIFTER(SDXC1) {
	return NULL;
}
IL_LIFTER(SEB) {
	return NULL;
}
IL_LIFTER(SEH) {
	return NULL;
}
IL_LIFTER(SELEQZ) {
	return NULL;
}
IL_LIFTER(SELNEZ) {
	return NULL;
}
IL_LIFTER(SEL) {
	return NULL;
}
IL_LIFTER(SEQ) {
	return NULL;
}
IL_LIFTER(SEQI) {
	return NULL;
}
IL_LIFTER(SH) {
	return NULL;
}
IL_LIFTER(SH16) {
	return NULL;
}
IL_LIFTER(SHF) {
	return NULL;
}
IL_LIFTER(SHILO) {
	return NULL;
}
IL_LIFTER(SHILOV) {
	return NULL;
}
IL_LIFTER(SHLLV) {
	return NULL;
}
IL_LIFTER(SHLLV_S) {
	return NULL;
}
IL_LIFTER(SHLL) {
	return NULL;
}
IL_LIFTER(SHLL_S) {
	return NULL;
}
IL_LIFTER(SHRAV) {
	return NULL;
}
IL_LIFTER(SHRAV_R) {
	return NULL;
}
IL_LIFTER(SHRA) {
	return NULL;
}
IL_LIFTER(SHRA_R) {
	return NULL;
}
IL_LIFTER(SHRLV) {
	return NULL;
}
IL_LIFTER(SHRL) {
	return NULL;
}
IL_LIFTER(SLDI) {
	return NULL;
}
IL_LIFTER(SLD) {
	return NULL;
}
IL_LIFTER(SLL) {
	return NULL;
}
IL_LIFTER(SLL16) {
	return NULL;
}
IL_LIFTER(SLLI) {
	return NULL;
}
IL_LIFTER(SLLV) {
	return NULL;
}
IL_LIFTER(SLT) {
	return NULL;
}
IL_LIFTER(SLTI) {
	return NULL;
}
IL_LIFTER(SLTIU) {
	return NULL;
}
IL_LIFTER(SLTU) {
	return NULL;
}
IL_LIFTER(SNE) {
	return NULL;
}
IL_LIFTER(SNEI) {
	return NULL;
}
IL_LIFTER(SPLATI) {
	return NULL;
}
IL_LIFTER(SPLAT) {
	return NULL;
}
IL_LIFTER(SRA) {
	return NULL;
}
IL_LIFTER(SRAI) {
	return NULL;
}
IL_LIFTER(SRARI) {
	return NULL;
}
IL_LIFTER(SRAR) {
	return NULL;
}
IL_LIFTER(SRAV) {
	return NULL;
}
IL_LIFTER(SRL) {
	return NULL;
}
IL_LIFTER(SRL16) {
	return NULL;
}
IL_LIFTER(SRLI) {
	return NULL;
}
IL_LIFTER(SRLRI) {
	return NULL;
}
IL_LIFTER(SRLR) {
	return NULL;
}
IL_LIFTER(SRLV) {
	return NULL;
}
IL_LIFTER(SSNOP) {
	return NULL;
}
IL_LIFTER(ST) {
	return NULL;
}
IL_LIFTER(SUBQH) {
	return NULL;
}
IL_LIFTER(SUBQH_R) {
	return NULL;
}
IL_LIFTER(SUBQ) {
	return NULL;
}
IL_LIFTER(SUBQ_S) {
	return NULL;
}
IL_LIFTER(SUBSUS_U) {
	return NULL;
}
IL_LIFTER(SUBSUU_S) {
	return NULL;
}
IL_LIFTER(SUBS_S) {
	return NULL;
}
IL_LIFTER(SUBS_U) {
	return NULL;
}
IL_LIFTER(SUBU16) {
	return NULL;
}
IL_LIFTER(SUBUH) {
	return NULL;
}
IL_LIFTER(SUBUH_R) {
	return NULL;
}
IL_LIFTER(SUBU) {
	return NULL;
}
IL_LIFTER(SUBU_S) {
	return NULL;
}
IL_LIFTER(SUBVI) {
	return NULL;
}
IL_LIFTER(SUBV) {
	return NULL;
}
IL_LIFTER(SUXC1) {
	return NULL;
}
IL_LIFTER(SW) {
	return NULL;
}
IL_LIFTER(SW16) {
	return NULL;
}
IL_LIFTER(SWC1) {
	return NULL;
}
IL_LIFTER(SWC2) {
	return NULL;
}
IL_LIFTER(SWC3) {
	return NULL;
}
IL_LIFTER(SWL) {
	return NULL;
}
IL_LIFTER(SWM16) {
	return NULL;
}
IL_LIFTER(SWM32) {
	return NULL;
}
IL_LIFTER(SWP) {
	return NULL;
}
IL_LIFTER(SWR) {
	return NULL;
}
IL_LIFTER(SWXC1) {
	return NULL;
}
IL_LIFTER(SYNC) {
	return NULL;
}
IL_LIFTER(SYNCI) {
	return NULL;
}
IL_LIFTER(SYSCALL) {
	return NULL;
}
IL_LIFTER(TEQ) {
	return NULL;
}
IL_LIFTER(TEQI) {
	return NULL;
}
IL_LIFTER(TGE) {
	return NULL;
}
IL_LIFTER(TGEI) {
	return NULL;
}
IL_LIFTER(TGEIU) {
	return NULL;
}
IL_LIFTER(TGEU) {
	return NULL;
}
IL_LIFTER(TLBP) {
	return NULL;
}
IL_LIFTER(TLBR) {
	return NULL;
}
IL_LIFTER(TLBWI) {
	return NULL;
}
IL_LIFTER(TLBWR) {
	return NULL;
}
IL_LIFTER(TLT) {
	return NULL;
}
IL_LIFTER(TLTI) {
	return NULL;
}
IL_LIFTER(TLTIU) {
	return NULL;
}
IL_LIFTER(TLTU) {
	return NULL;
}
IL_LIFTER(TNE) {
	return NULL;
}
IL_LIFTER(TNEI) {
	return NULL;
}
IL_LIFTER(TRUNC) {
	return NULL;
}
IL_LIFTER(V3MULU) {
	return NULL;
}
IL_LIFTER(VMM0) {
	return NULL;
}
IL_LIFTER(VMULU) {
	return NULL;
}
IL_LIFTER(VSHF) {
	return NULL;
}
IL_LIFTER(WAIT) {
	return NULL;
}
IL_LIFTER(WRDSP) {
	return NULL;
}
IL_LIFTER(WSBH) {
	return NULL;
}
IL_LIFTER(XOR) {
	return NULL;
}
IL_LIFTER(XOR16) {
	return NULL;
}
IL_LIFTER(XORI) {
	return NULL;
}
IL_LIFTER(NOP) {
	return NULL;
}
IL_LIFTER(NEGU) {
	return NULL;
}
IL_LIFTER(JALR_HB) {
	return NULL;
}
IL_LIFTER(JR_HB) {
	return NULL;
}

// clang-format off
MipsILLifterFunction mips_lifters[] = {
    [MIPS_INS_ABSQ_S]      = IL_LIFTER_NAME(ABSQ_S),
    [MIPS_INS_ADD]         = IL_LIFTER_NAME(ADD),
    [MIPS_INS_ADDIUPC]     = IL_LIFTER_NAME(ADDIUPC),
    [MIPS_INS_ADDIUR1SP]   = IL_LIFTER_NAME(ADDIUR1SP),
    [MIPS_INS_ADDIUR2]     = IL_LIFTER_NAME(ADDIUR2),
    [MIPS_INS_ADDIUS5]     = IL_LIFTER_NAME(ADDIUS5),
    [MIPS_INS_ADDIUSP]     = IL_LIFTER_NAME(ADDIUSP),
    [MIPS_INS_ADDQH]       = IL_LIFTER_NAME(ADDQH),
    [MIPS_INS_ADDQH_R]     = IL_LIFTER_NAME(ADDQH_R),
    [MIPS_INS_ADDQ]        = IL_LIFTER_NAME(ADDQ),
    [MIPS_INS_ADDQ_S]      = IL_LIFTER_NAME(ADDQ_S),
    [MIPS_INS_ADDSC]       = IL_LIFTER_NAME(ADDSC),
    [MIPS_INS_ADDS_A]      = IL_LIFTER_NAME(ADDS_A),
    [MIPS_INS_ADDS_S]      = IL_LIFTER_NAME(ADDS_S),
    [MIPS_INS_ADDS_U]      = IL_LIFTER_NAME(ADDS_U),
    [MIPS_INS_ADDU16]      = IL_LIFTER_NAME(ADDU16),
    [MIPS_INS_ADDUH]       = IL_LIFTER_NAME(ADDUH),
    [MIPS_INS_ADDUH_R]     = IL_LIFTER_NAME(ADDUH_R),
    [MIPS_INS_ADDU]        = IL_LIFTER_NAME(ADDU),
    [MIPS_INS_ADDU_S]      = IL_LIFTER_NAME(ADDU_S),
    [MIPS_INS_ADDVI]       = IL_LIFTER_NAME(ADDVI),
    [MIPS_INS_ADDV]        = IL_LIFTER_NAME(ADDV),
    [MIPS_INS_ADDWC]       = IL_LIFTER_NAME(ADDWC),
    [MIPS_INS_ADD_A]       = IL_LIFTER_NAME(ADD_A),
    [MIPS_INS_ADDI]        = IL_LIFTER_NAME(ADDI),
    [MIPS_INS_ADDIU]       = IL_LIFTER_NAME(ADDIU),
    [MIPS_INS_ALIGN]       = IL_LIFTER_NAME(ALIGN),
    [MIPS_INS_ALUIPC]      = IL_LIFTER_NAME(ALUIPC),
    [MIPS_INS_AND]         = IL_LIFTER_NAME(AND),
    [MIPS_INS_AND16]       = IL_LIFTER_NAME(AND16),
    [MIPS_INS_ANDI16]      = IL_LIFTER_NAME(ANDI16),
    [MIPS_INS_ANDI]        = IL_LIFTER_NAME(ANDI),
    [MIPS_INS_APPEND]      = IL_LIFTER_NAME(APPEND),
    [MIPS_INS_ASUB_S]      = IL_LIFTER_NAME(ASUB_S),
    [MIPS_INS_ASUB_U]      = IL_LIFTER_NAME(ASUB_U),
    [MIPS_INS_AUI]         = IL_LIFTER_NAME(AUI),
    [MIPS_INS_AUIPC]       = IL_LIFTER_NAME(AUIPC),
    [MIPS_INS_AVER_S]      = IL_LIFTER_NAME(AVER_S),
    [MIPS_INS_AVER_U]      = IL_LIFTER_NAME(AVER_U),
    [MIPS_INS_AVE_S]       = IL_LIFTER_NAME(AVE_S),
    [MIPS_INS_AVE_U]       = IL_LIFTER_NAME(AVE_U),
    [MIPS_INS_B16]         = IL_LIFTER_NAME(B16),
    [MIPS_INS_BADDU]       = IL_LIFTER_NAME(BADDU),
    [MIPS_INS_BAL]         = IL_LIFTER_NAME(BAL),
    [MIPS_INS_BALC]        = IL_LIFTER_NAME(BALC),
    [MIPS_INS_BALIGN]      = IL_LIFTER_NAME(BALIGN),
    [MIPS_INS_BBIT0]       = IL_LIFTER_NAME(BBIT0),
    [MIPS_INS_BBIT032]     = IL_LIFTER_NAME(BBIT032),
    [MIPS_INS_BBIT1]       = IL_LIFTER_NAME(BBIT1),
    [MIPS_INS_BBIT132]     = IL_LIFTER_NAME(BBIT132),
    [MIPS_INS_BC]          = IL_LIFTER_NAME(BC),
    [MIPS_INS_BC0F]        = IL_LIFTER_NAME(BC0F),
    [MIPS_INS_BC0FL]       = IL_LIFTER_NAME(BC0FL),
    [MIPS_INS_BC0T]        = IL_LIFTER_NAME(BC0T),
    [MIPS_INS_BC0TL]       = IL_LIFTER_NAME(BC0TL),
    [MIPS_INS_BC1EQZ]      = IL_LIFTER_NAME(BC1EQZ),
    [MIPS_INS_BC1F]        = IL_LIFTER_NAME(BC1F),
    [MIPS_INS_BC1FL]       = IL_LIFTER_NAME(BC1FL),
    [MIPS_INS_BC1NEZ]      = IL_LIFTER_NAME(BC1NEZ),
    [MIPS_INS_BC1T]        = IL_LIFTER_NAME(BC1T),
    [MIPS_INS_BC1TL]       = IL_LIFTER_NAME(BC1TL),
    [MIPS_INS_BC2EQZ]      = IL_LIFTER_NAME(BC2EQZ),
    [MIPS_INS_BC2F]        = IL_LIFTER_NAME(BC2F),
    [MIPS_INS_BC2FL]       = IL_LIFTER_NAME(BC2FL),
    [MIPS_INS_BC2NEZ]      = IL_LIFTER_NAME(BC2NEZ),
    [MIPS_INS_BC2T]        = IL_LIFTER_NAME(BC2T),
    [MIPS_INS_BC2TL]       = IL_LIFTER_NAME(BC2TL),
    [MIPS_INS_BC3F]        = IL_LIFTER_NAME(BC3F),
    [MIPS_INS_BC3FL]       = IL_LIFTER_NAME(BC3FL),
    [MIPS_INS_BC3T]        = IL_LIFTER_NAME(BC3T),
    [MIPS_INS_BC3TL]       = IL_LIFTER_NAME(BC3TL),
    [MIPS_INS_BCLRI]       = IL_LIFTER_NAME(BCLRI),
    [MIPS_INS_BCLR]        = IL_LIFTER_NAME(BCLR),
    [MIPS_INS_BEQ]         = IL_LIFTER_NAME(BEQ),
    [MIPS_INS_BEQC]        = IL_LIFTER_NAME(BEQC),
    [MIPS_INS_BEQL]        = IL_LIFTER_NAME(BEQL),
    [MIPS_INS_BEQZ16]      = IL_LIFTER_NAME(BEQZ16),
    [MIPS_INS_BEQZALC]     = IL_LIFTER_NAME(BEQZALC),
    [MIPS_INS_BEQZC]       = IL_LIFTER_NAME(BEQZC),
    [MIPS_INS_BGEC]        = IL_LIFTER_NAME(BGEC),
    [MIPS_INS_BGEUC]       = IL_LIFTER_NAME(BGEUC),
    [MIPS_INS_BGEZ]        = IL_LIFTER_NAME(BGEZ),
    [MIPS_INS_BGEZAL]      = IL_LIFTER_NAME(BGEZAL),
    [MIPS_INS_BGEZALC]     = IL_LIFTER_NAME(BGEZALC),
    [MIPS_INS_BGEZALL]     = IL_LIFTER_NAME(BGEZALL),
    [MIPS_INS_BGEZALS]     = IL_LIFTER_NAME(BGEZALS),
    [MIPS_INS_BGEZC]       = IL_LIFTER_NAME(BGEZC),
    [MIPS_INS_BGEZL]       = IL_LIFTER_NAME(BGEZL),
    [MIPS_INS_BGTZ]        = IL_LIFTER_NAME(BGTZ),
    [MIPS_INS_BGTZALC]     = IL_LIFTER_NAME(BGTZALC),
    [MIPS_INS_BGTZC]       = IL_LIFTER_NAME(BGTZC),
    [MIPS_INS_BGTZL]       = IL_LIFTER_NAME(BGTZL),
    [MIPS_INS_BINSLI]      = IL_LIFTER_NAME(BINSLI),
    [MIPS_INS_BINSL]       = IL_LIFTER_NAME(BINSL),
    [MIPS_INS_BINSRI]      = IL_LIFTER_NAME(BINSRI),
    [MIPS_INS_BINSR]       = IL_LIFTER_NAME(BINSR),
    [MIPS_INS_BITREV]      = IL_LIFTER_NAME(BITREV),
    [MIPS_INS_BITSWAP]     = IL_LIFTER_NAME(BITSWAP),
    [MIPS_INS_BLEZ]        = IL_LIFTER_NAME(BLEZ),
    [MIPS_INS_BLEZALC]     = IL_LIFTER_NAME(BLEZALC),
    [MIPS_INS_BLEZC]       = IL_LIFTER_NAME(BLEZC),
    [MIPS_INS_BLEZL]       = IL_LIFTER_NAME(BLEZL),
    [MIPS_INS_BLTC]        = IL_LIFTER_NAME(BLTC),
    [MIPS_INS_BLTUC]       = IL_LIFTER_NAME(BLTUC),
    [MIPS_INS_BLTZ]        = IL_LIFTER_NAME(BLTZ),
    [MIPS_INS_BLTZAL]      = IL_LIFTER_NAME(BLTZAL),
    [MIPS_INS_BLTZALC]     = IL_LIFTER_NAME(BLTZALC),
    [MIPS_INS_BLTZALL]     = IL_LIFTER_NAME(BLTZALL),
    [MIPS_INS_BLTZALS]     = IL_LIFTER_NAME(BLTZALS),
    [MIPS_INS_BLTZC]       = IL_LIFTER_NAME(BLTZC),
    [MIPS_INS_BLTZL]       = IL_LIFTER_NAME(BLTZL),
    [MIPS_INS_BMNZI]       = IL_LIFTER_NAME(BMNZI),
    [MIPS_INS_BMNZ]        = IL_LIFTER_NAME(BMNZ),
    [MIPS_INS_BMZI]        = IL_LIFTER_NAME(BMZI),
    [MIPS_INS_BMZ]         = IL_LIFTER_NAME(BMZ),
    [MIPS_INS_BNE]         = IL_LIFTER_NAME(BNE),
    [MIPS_INS_BNEC]        = IL_LIFTER_NAME(BNEC),
    [MIPS_INS_BNEGI]       = IL_LIFTER_NAME(BNEGI),
    [MIPS_INS_BNEG]        = IL_LIFTER_NAME(BNEG),
    [MIPS_INS_BNEL]        = IL_LIFTER_NAME(BNEL),
    [MIPS_INS_BNEZ16]      = IL_LIFTER_NAME(BNEZ16),
    [MIPS_INS_BNEZALC]     = IL_LIFTER_NAME(BNEZALC),
    [MIPS_INS_BNEZC]       = IL_LIFTER_NAME(BNEZC),
    [MIPS_INS_BNVC]        = IL_LIFTER_NAME(BNVC),
    [MIPS_INS_BNZ]         = IL_LIFTER_NAME(BNZ),
    [MIPS_INS_BOVC]        = IL_LIFTER_NAME(BOVC),
    [MIPS_INS_BPOSGE32]    = IL_LIFTER_NAME(BPOSGE32),
    [MIPS_INS_BREAK]       = IL_LIFTER_NAME(BREAK),
    [MIPS_INS_BREAK16]     = IL_LIFTER_NAME(BREAK16),
    [MIPS_INS_BSELI]       = IL_LIFTER_NAME(BSELI),
    [MIPS_INS_BSEL]        = IL_LIFTER_NAME(BSEL),
    [MIPS_INS_BSETI]       = IL_LIFTER_NAME(BSETI),
    [MIPS_INS_BSET]        = IL_LIFTER_NAME(BSET),
    [MIPS_INS_BZ]          = IL_LIFTER_NAME(BZ),
    [MIPS_INS_BEQZ]        = IL_LIFTER_NAME(BEQZ),
    [MIPS_INS_B]           = IL_LIFTER_NAME(B),
    [MIPS_INS_BNEZ]        = IL_LIFTER_NAME(BNEZ),
    [MIPS_INS_BTEQZ]       = IL_LIFTER_NAME(BTEQZ),
    [MIPS_INS_BTNEZ]       = IL_LIFTER_NAME(BTNEZ),
    [MIPS_INS_CACHE]       = IL_LIFTER_NAME(CACHE),
    [MIPS_INS_CEIL]        = IL_LIFTER_NAME(CEIL),
    [MIPS_INS_CEQI]        = IL_LIFTER_NAME(CEQI),
    [MIPS_INS_CEQ]         = IL_LIFTER_NAME(CEQ),
    [MIPS_INS_CFC1]        = IL_LIFTER_NAME(CFC1),
    [MIPS_INS_CFCMSA]      = IL_LIFTER_NAME(CFCMSA),
    [MIPS_INS_CINS]        = IL_LIFTER_NAME(CINS),
    [MIPS_INS_CINS32]      = IL_LIFTER_NAME(CINS32),
    [MIPS_INS_CLASS]       = IL_LIFTER_NAME(CLASS),
    [MIPS_INS_CLEI_S]      = IL_LIFTER_NAME(CLEI_S),
    [MIPS_INS_CLEI_U]      = IL_LIFTER_NAME(CLEI_U),
    [MIPS_INS_CLE_S]       = IL_LIFTER_NAME(CLE_S),
    [MIPS_INS_CLE_U]       = IL_LIFTER_NAME(CLE_U),
    [MIPS_INS_CLO]         = IL_LIFTER_NAME(CLO),
    [MIPS_INS_CLTI_S]      = IL_LIFTER_NAME(CLTI_S),
    [MIPS_INS_CLTI_U]      = IL_LIFTER_NAME(CLTI_U),
    [MIPS_INS_CLT_S]       = IL_LIFTER_NAME(CLT_S),
    [MIPS_INS_CLT_U]       = IL_LIFTER_NAME(CLT_U),
    [MIPS_INS_CLZ]         = IL_LIFTER_NAME(CLZ),
    [MIPS_INS_CMPGDU]      = IL_LIFTER_NAME(CMPGDU),
    [MIPS_INS_CMPGU]       = IL_LIFTER_NAME(CMPGU),
    [MIPS_INS_CMPU]        = IL_LIFTER_NAME(CMPU),
    [MIPS_INS_CMP]         = IL_LIFTER_NAME(CMP),
    [MIPS_INS_COPY_S]      = IL_LIFTER_NAME(COPY_S),
    [MIPS_INS_COPY_U]      = IL_LIFTER_NAME(COPY_U),
    [MIPS_INS_CTC1]        = IL_LIFTER_NAME(CTC1),
    [MIPS_INS_CTCMSA]      = IL_LIFTER_NAME(CTCMSA),
    [MIPS_INS_CVT]         = IL_LIFTER_NAME(CVT),
    [MIPS_INS_C]           = IL_LIFTER_NAME(C),
    [MIPS_INS_CMPI]        = IL_LIFTER_NAME(CMPI),
    [MIPS_INS_DADD]        = IL_LIFTER_NAME(DADD),
    [MIPS_INS_DADDI]       = IL_LIFTER_NAME(DADDI),
    [MIPS_INS_DADDIU]      = IL_LIFTER_NAME(DADDIU),
    [MIPS_INS_DADDU]       = IL_LIFTER_NAME(DADDU),
    [MIPS_INS_DAHI]        = IL_LIFTER_NAME(DAHI),
    [MIPS_INS_DALIGN]      = IL_LIFTER_NAME(DALIGN),
    [MIPS_INS_DATI]        = IL_LIFTER_NAME(DATI),
    [MIPS_INS_DAUI]        = IL_LIFTER_NAME(DAUI),
    [MIPS_INS_DBITSWAP]    = IL_LIFTER_NAME(DBITSWAP),
    [MIPS_INS_DCLO]        = IL_LIFTER_NAME(DCLO),
    [MIPS_INS_DCLZ]        = IL_LIFTER_NAME(DCLZ),
    [MIPS_INS_DDIV]        = IL_LIFTER_NAME(DDIV),
    [MIPS_INS_DDIVU]       = IL_LIFTER_NAME(DDIVU),
    [MIPS_INS_DERET]       = IL_LIFTER_NAME(DERET),
    [MIPS_INS_DEXT]        = IL_LIFTER_NAME(DEXT),
    [MIPS_INS_DEXTM]       = IL_LIFTER_NAME(DEXTM),
    [MIPS_INS_DEXTU]       = IL_LIFTER_NAME(DEXTU),
    [MIPS_INS_DI]          = IL_LIFTER_NAME(DI),
    [MIPS_INS_DINS]        = IL_LIFTER_NAME(DINS),
    [MIPS_INS_DINSM]       = IL_LIFTER_NAME(DINSM),
    [MIPS_INS_DINSU]       = IL_LIFTER_NAME(DINSU),
    [MIPS_INS_DIV]         = IL_LIFTER_NAME(DIV),
    [MIPS_INS_DIVU]        = IL_LIFTER_NAME(DIVU),
    [MIPS_INS_DIV_S]       = IL_LIFTER_NAME(DIV_S),
    [MIPS_INS_DIV_U]       = IL_LIFTER_NAME(DIV_U),
    [MIPS_INS_DLSA]        = IL_LIFTER_NAME(DLSA),
    [MIPS_INS_DMFC0]       = IL_LIFTER_NAME(DMFC0),
    [MIPS_INS_DMFC1]       = IL_LIFTER_NAME(DMFC1),
    [MIPS_INS_DMFC2]       = IL_LIFTER_NAME(DMFC2),
    [MIPS_INS_DMOD]        = IL_LIFTER_NAME(DMOD),
    [MIPS_INS_DMODU]       = IL_LIFTER_NAME(DMODU),
    [MIPS_INS_DMTC0]       = IL_LIFTER_NAME(DMTC0),
    [MIPS_INS_DMTC1]       = IL_LIFTER_NAME(DMTC1),
    [MIPS_INS_DMTC2]       = IL_LIFTER_NAME(DMTC2),
    [MIPS_INS_DMUH]        = IL_LIFTER_NAME(DMUH),
    [MIPS_INS_DMUHU]       = IL_LIFTER_NAME(DMUHU),
    [MIPS_INS_DMUL]        = IL_LIFTER_NAME(DMUL),
    [MIPS_INS_DMULT]       = IL_LIFTER_NAME(DMULT),
    [MIPS_INS_DMULTU]      = IL_LIFTER_NAME(DMULTU),
    [MIPS_INS_DMULU]       = IL_LIFTER_NAME(DMULU),
    [MIPS_INS_DOTP_S]      = IL_LIFTER_NAME(DOTP_S),
    [MIPS_INS_DOTP_U]      = IL_LIFTER_NAME(DOTP_U),
    [MIPS_INS_DPADD_S]     = IL_LIFTER_NAME(DPADD_S),
    [MIPS_INS_DPADD_U]     = IL_LIFTER_NAME(DPADD_U),
    [MIPS_INS_DPAQX_SA]    = IL_LIFTER_NAME(DPAQX_SA),
    [MIPS_INS_DPAQX_S]     = IL_LIFTER_NAME(DPAQX_S),
    [MIPS_INS_DPAQ_SA]     = IL_LIFTER_NAME(DPAQ_SA),
    [MIPS_INS_DPAQ_S]      = IL_LIFTER_NAME(DPAQ_S),
    [MIPS_INS_DPAU]        = IL_LIFTER_NAME(DPAU),
    [MIPS_INS_DPAX]        = IL_LIFTER_NAME(DPAX),
    [MIPS_INS_DPA]         = IL_LIFTER_NAME(DPA),
    [MIPS_INS_DPOP]        = IL_LIFTER_NAME(DPOP),
    [MIPS_INS_DPSQX_SA]    = IL_LIFTER_NAME(DPSQX_SA),
    [MIPS_INS_DPSQX_S]     = IL_LIFTER_NAME(DPSQX_S),
    [MIPS_INS_DPSQ_SA]     = IL_LIFTER_NAME(DPSQ_SA),
    [MIPS_INS_DPSQ_S]      = IL_LIFTER_NAME(DPSQ_S),
    [MIPS_INS_DPSUB_S]     = IL_LIFTER_NAME(DPSUB_S),
    [MIPS_INS_DPSUB_U]     = IL_LIFTER_NAME(DPSUB_U),
    [MIPS_INS_DPSU]        = IL_LIFTER_NAME(DPSU),
    [MIPS_INS_DPSX]        = IL_LIFTER_NAME(DPSX),
    [MIPS_INS_DPS]         = IL_LIFTER_NAME(DPS),
    [MIPS_INS_DROTR]       = IL_LIFTER_NAME(DROTR),
    [MIPS_INS_DROTR32]     = IL_LIFTER_NAME(DROTR32),
    [MIPS_INS_DROTRV]      = IL_LIFTER_NAME(DROTRV),
    [MIPS_INS_DSBH]        = IL_LIFTER_NAME(DSBH),
    [MIPS_INS_DSHD]        = IL_LIFTER_NAME(DSHD),
    [MIPS_INS_DSLL]        = IL_LIFTER_NAME(DSLL),
    [MIPS_INS_DSLL32]      = IL_LIFTER_NAME(DSLL32),
    [MIPS_INS_DSLLV]       = IL_LIFTER_NAME(DSLLV),
    [MIPS_INS_DSRA]        = IL_LIFTER_NAME(DSRA),
    [MIPS_INS_DSRA32]      = IL_LIFTER_NAME(DSRA32),
    [MIPS_INS_DSRAV]       = IL_LIFTER_NAME(DSRAV),
    [MIPS_INS_DSRL]        = IL_LIFTER_NAME(DSRL),
    [MIPS_INS_DSRL32]      = IL_LIFTER_NAME(DSRL32),
    [MIPS_INS_DSRLV]       = IL_LIFTER_NAME(DSRLV),
    [MIPS_INS_DSUB]        = IL_LIFTER_NAME(DSUB),
    [MIPS_INS_DSUBU]       = IL_LIFTER_NAME(DSUBU),
    [MIPS_INS_EHB]         = IL_LIFTER_NAME(EHB),
    [MIPS_INS_EI]          = IL_LIFTER_NAME(EI),
    [MIPS_INS_ERET]        = IL_LIFTER_NAME(ERET),
    [MIPS_INS_EXT]         = IL_LIFTER_NAME(EXT),
    [MIPS_INS_EXTP]        = IL_LIFTER_NAME(EXTP),
    [MIPS_INS_EXTPDP]      = IL_LIFTER_NAME(EXTPDP),
    [MIPS_INS_EXTPDPV]     = IL_LIFTER_NAME(EXTPDPV),
    [MIPS_INS_EXTPV]       = IL_LIFTER_NAME(EXTPV),
    [MIPS_INS_EXTRV_RS]    = IL_LIFTER_NAME(EXTRV_RS),
    [MIPS_INS_EXTRV_R]     = IL_LIFTER_NAME(EXTRV_R),
    [MIPS_INS_EXTRV_S]     = IL_LIFTER_NAME(EXTRV_S),
    [MIPS_INS_EXTRV]       = IL_LIFTER_NAME(EXTRV),
    [MIPS_INS_EXTR_RS]     = IL_LIFTER_NAME(EXTR_RS),
    [MIPS_INS_EXTR_R]      = IL_LIFTER_NAME(EXTR_R),
    [MIPS_INS_EXTR_S]      = IL_LIFTER_NAME(EXTR_S),
    [MIPS_INS_EXTR]        = IL_LIFTER_NAME(EXTR),
    [MIPS_INS_EXTS]        = IL_LIFTER_NAME(EXTS),
    [MIPS_INS_EXTS32]      = IL_LIFTER_NAME(EXTS32),
    [MIPS_INS_ABS]         = IL_LIFTER_NAME(ABS),
    [MIPS_INS_FADD]        = IL_LIFTER_NAME(FADD),
    [MIPS_INS_FCAF]        = IL_LIFTER_NAME(FCAF),
    [MIPS_INS_FCEQ]        = IL_LIFTER_NAME(FCEQ),
    [MIPS_INS_FCLASS]      = IL_LIFTER_NAME(FCLASS),
    [MIPS_INS_FCLE]        = IL_LIFTER_NAME(FCLE),
    [MIPS_INS_FCLT]        = IL_LIFTER_NAME(FCLT),
    [MIPS_INS_FCNE]        = IL_LIFTER_NAME(FCNE),
    [MIPS_INS_FCOR]        = IL_LIFTER_NAME(FCOR),
    [MIPS_INS_FCUEQ]       = IL_LIFTER_NAME(FCUEQ),
    [MIPS_INS_FCULE]       = IL_LIFTER_NAME(FCULE),
    [MIPS_INS_FCULT]       = IL_LIFTER_NAME(FCULT),
    [MIPS_INS_FCUNE]       = IL_LIFTER_NAME(FCUNE),
    [MIPS_INS_FCUN]        = IL_LIFTER_NAME(FCUN),
    [MIPS_INS_FDIV]        = IL_LIFTER_NAME(FDIV),
    [MIPS_INS_FEXDO]       = IL_LIFTER_NAME(FEXDO),
    [MIPS_INS_FEXP2]       = IL_LIFTER_NAME(FEXP2),
    [MIPS_INS_FEXUPL]      = IL_LIFTER_NAME(FEXUPL),
    [MIPS_INS_FEXUPR]      = IL_LIFTER_NAME(FEXUPR),
    [MIPS_INS_FFINT_S]     = IL_LIFTER_NAME(FFINT_S),
    [MIPS_INS_FFINT_U]     = IL_LIFTER_NAME(FFINT_U),
    [MIPS_INS_FFQL]        = IL_LIFTER_NAME(FFQL),
    [MIPS_INS_FFQR]        = IL_LIFTER_NAME(FFQR),
    [MIPS_INS_FILL]        = IL_LIFTER_NAME(FILL),
    [MIPS_INS_FLOG2]       = IL_LIFTER_NAME(FLOG2),
    [MIPS_INS_FLOOR]       = IL_LIFTER_NAME(FLOOR),
    [MIPS_INS_FMADD]       = IL_LIFTER_NAME(FMADD),
    [MIPS_INS_FMAX_A]      = IL_LIFTER_NAME(FMAX_A),
    [MIPS_INS_FMAX]        = IL_LIFTER_NAME(FMAX),
    [MIPS_INS_FMIN_A]      = IL_LIFTER_NAME(FMIN_A),
    [MIPS_INS_FMIN]        = IL_LIFTER_NAME(FMIN),
    [MIPS_INS_MOV]         = IL_LIFTER_NAME(MOV),
    [MIPS_INS_FMSUB]       = IL_LIFTER_NAME(FMSUB),
    [MIPS_INS_FMUL]        = IL_LIFTER_NAME(FMUL),
    [MIPS_INS_MUL]         = IL_LIFTER_NAME(MUL),
    [MIPS_INS_NEG]         = IL_LIFTER_NAME(NEG),
    [MIPS_INS_FRCP]        = IL_LIFTER_NAME(FRCP),
    [MIPS_INS_FRINT]       = IL_LIFTER_NAME(FRINT),
    [MIPS_INS_FRSQRT]      = IL_LIFTER_NAME(FRSQRT),
    [MIPS_INS_FSAF]        = IL_LIFTER_NAME(FSAF),
    [MIPS_INS_FSEQ]        = IL_LIFTER_NAME(FSEQ),
    [MIPS_INS_FSLE]        = IL_LIFTER_NAME(FSLE),
    [MIPS_INS_FSLT]        = IL_LIFTER_NAME(FSLT),
    [MIPS_INS_FSNE]        = IL_LIFTER_NAME(FSNE),
    [MIPS_INS_FSOR]        = IL_LIFTER_NAME(FSOR),
    [MIPS_INS_FSQRT]       = IL_LIFTER_NAME(FSQRT),
    [MIPS_INS_SQRT]        = IL_LIFTER_NAME(SQRT),
    [MIPS_INS_FSUB]        = IL_LIFTER_NAME(FSUB),
    [MIPS_INS_SUB]         = IL_LIFTER_NAME(SUB),
    [MIPS_INS_FSUEQ]       = IL_LIFTER_NAME(FSUEQ),
    [MIPS_INS_FSULE]       = IL_LIFTER_NAME(FSULE),
    [MIPS_INS_FSULT]       = IL_LIFTER_NAME(FSULT),
    [MIPS_INS_FSUNE]       = IL_LIFTER_NAME(FSUNE),
    [MIPS_INS_FSUN]        = IL_LIFTER_NAME(FSUN),
    [MIPS_INS_FTINT_S]     = IL_LIFTER_NAME(FTINT_S),
    [MIPS_INS_FTINT_U]     = IL_LIFTER_NAME(FTINT_U),
    [MIPS_INS_FTQ]         = IL_LIFTER_NAME(FTQ),
    [MIPS_INS_FTRUNC_S]    = IL_LIFTER_NAME(FTRUNC_S),
    [MIPS_INS_FTRUNC_U]    = IL_LIFTER_NAME(FTRUNC_U),
    [MIPS_INS_HADD_S]      = IL_LIFTER_NAME(HADD_S),
    [MIPS_INS_HADD_U]      = IL_LIFTER_NAME(HADD_U),
    [MIPS_INS_HSUB_S]      = IL_LIFTER_NAME(HSUB_S),
    [MIPS_INS_HSUB_U]      = IL_LIFTER_NAME(HSUB_U),
    [MIPS_INS_ILVEV]       = IL_LIFTER_NAME(ILVEV),
    [MIPS_INS_ILVL]        = IL_LIFTER_NAME(ILVL),
    [MIPS_INS_ILVOD]       = IL_LIFTER_NAME(ILVOD),
    [MIPS_INS_ILVR]        = IL_LIFTER_NAME(ILVR),
    [MIPS_INS_INS]         = IL_LIFTER_NAME(INS),
    [MIPS_INS_INSERT]      = IL_LIFTER_NAME(INSERT),
    [MIPS_INS_INSV]        = IL_LIFTER_NAME(INSV),
    [MIPS_INS_INSVE]       = IL_LIFTER_NAME(INSVE),
    [MIPS_INS_J]           = IL_LIFTER_NAME(J),
    [MIPS_INS_JAL]         = IL_LIFTER_NAME(JAL),
    [MIPS_INS_JALR]        = IL_LIFTER_NAME(JALR),
    [MIPS_INS_JALRS16]     = IL_LIFTER_NAME(JALRS16),
    [MIPS_INS_JALRS]       = IL_LIFTER_NAME(JALRS),
    [MIPS_INS_JALS]        = IL_LIFTER_NAME(JALS),
    [MIPS_INS_JALX]        = IL_LIFTER_NAME(JALX),
    [MIPS_INS_JIALC]       = IL_LIFTER_NAME(JIALC),
    [MIPS_INS_JIC]         = IL_LIFTER_NAME(JIC),
    [MIPS_INS_JR]          = IL_LIFTER_NAME(JR),
    [MIPS_INS_JR16]        = IL_LIFTER_NAME(JR16),
    [MIPS_INS_JRADDIUSP]   = IL_LIFTER_NAME(JRADDIUSP),
    [MIPS_INS_JRC]         = IL_LIFTER_NAME(JRC),
    [MIPS_INS_JALRC]       = IL_LIFTER_NAME(JALRC),
    [MIPS_INS_LB]          = IL_LIFTER_NAME(LB),
    [MIPS_INS_LBU16]       = IL_LIFTER_NAME(LBU16),
    [MIPS_INS_LBUX]        = IL_LIFTER_NAME(LBUX),
    [MIPS_INS_LBU]         = IL_LIFTER_NAME(LBU),
    [MIPS_INS_LD]          = IL_LIFTER_NAME(LD),
    [MIPS_INS_LDC1]        = IL_LIFTER_NAME(LDC1),
    [MIPS_INS_LDC2]        = IL_LIFTER_NAME(LDC2),
    [MIPS_INS_LDC3]        = IL_LIFTER_NAME(LDC3),
    [MIPS_INS_LDI]         = IL_LIFTER_NAME(LDI),
    [MIPS_INS_LDL]         = IL_LIFTER_NAME(LDL),
    [MIPS_INS_LDPC]        = IL_LIFTER_NAME(LDPC),
    [MIPS_INS_LDR]         = IL_LIFTER_NAME(LDR),
    [MIPS_INS_LDXC1]       = IL_LIFTER_NAME(LDXC1),
    [MIPS_INS_LH]          = IL_LIFTER_NAME(LH),
    [MIPS_INS_LHU16]       = IL_LIFTER_NAME(LHU16),
    [MIPS_INS_LHX]         = IL_LIFTER_NAME(LHX),
    [MIPS_INS_LHU]         = IL_LIFTER_NAME(LHU),
    [MIPS_INS_LI16]        = IL_LIFTER_NAME(LI16),
    [MIPS_INS_LL]          = IL_LIFTER_NAME(LL),
    [MIPS_INS_LLD]         = IL_LIFTER_NAME(LLD),
    [MIPS_INS_LSA]         = IL_LIFTER_NAME(LSA),
    [MIPS_INS_LUXC1]       = IL_LIFTER_NAME(LUXC1),
    [MIPS_INS_LUI]         = IL_LIFTER_NAME(LUI),
    [MIPS_INS_LW]          = IL_LIFTER_NAME(LW),
    [MIPS_INS_LW16]        = IL_LIFTER_NAME(LW16),
    [MIPS_INS_LWC1]        = IL_LIFTER_NAME(LWC1),
    [MIPS_INS_LWC2]        = IL_LIFTER_NAME(LWC2),
    [MIPS_INS_LWC3]        = IL_LIFTER_NAME(LWC3),
    [MIPS_INS_LWL]         = IL_LIFTER_NAME(LWL),
    [MIPS_INS_LWM16]       = IL_LIFTER_NAME(LWM16),
    [MIPS_INS_LWM32]       = IL_LIFTER_NAME(LWM32),
    [MIPS_INS_LWPC]        = IL_LIFTER_NAME(LWPC),
    [MIPS_INS_LWP]         = IL_LIFTER_NAME(LWP),
    [MIPS_INS_LWR]         = IL_LIFTER_NAME(LWR),
    [MIPS_INS_LWUPC]       = IL_LIFTER_NAME(LWUPC),
    [MIPS_INS_LWU]         = IL_LIFTER_NAME(LWU),
    [MIPS_INS_LWX]         = IL_LIFTER_NAME(LWX),
    [MIPS_INS_LWXC1]       = IL_LIFTER_NAME(LWXC1),
    [MIPS_INS_LWXS]        = IL_LIFTER_NAME(LWXS),
    [MIPS_INS_LI]          = IL_LIFTER_NAME(LI),
    [MIPS_INS_MADD]        = IL_LIFTER_NAME(MADD),
    [MIPS_INS_MADDF]       = IL_LIFTER_NAME(MADDF),
    [MIPS_INS_MADDR_Q]     = IL_LIFTER_NAME(MADDR_Q),
    [MIPS_INS_MADDU]       = IL_LIFTER_NAME(MADDU),
    [MIPS_INS_MADDV]       = IL_LIFTER_NAME(MADDV),
    [MIPS_INS_MADD_Q]      = IL_LIFTER_NAME(MADD_Q),
    [MIPS_INS_MAQ_SA]      = IL_LIFTER_NAME(MAQ_SA),
    [MIPS_INS_MAQ_S]       = IL_LIFTER_NAME(MAQ_S),
    [MIPS_INS_MAXA]        = IL_LIFTER_NAME(MAXA),
    [MIPS_INS_MAXI_S]      = IL_LIFTER_NAME(MAXI_S),
    [MIPS_INS_MAXI_U]      = IL_LIFTER_NAME(MAXI_U),
    [MIPS_INS_MAX_A]       = IL_LIFTER_NAME(MAX_A),
    [MIPS_INS_MAX]         = IL_LIFTER_NAME(MAX),
    [MIPS_INS_MAX_S]       = IL_LIFTER_NAME(MAX_S),
    [MIPS_INS_MAX_U]       = IL_LIFTER_NAME(MAX_U),
    [MIPS_INS_MFC0]        = IL_LIFTER_NAME(MFC0),
    [MIPS_INS_MFC1]        = IL_LIFTER_NAME(MFC1),
    [MIPS_INS_MFC2]        = IL_LIFTER_NAME(MFC2),
    [MIPS_INS_MFHC1]       = IL_LIFTER_NAME(MFHC1),
    [MIPS_INS_MFHI]        = IL_LIFTER_NAME(MFHI),
    [MIPS_INS_MFLO]        = IL_LIFTER_NAME(MFLO),
    [MIPS_INS_MINA]        = IL_LIFTER_NAME(MINA),
    [MIPS_INS_MINI_S]      = IL_LIFTER_NAME(MINI_S),
    [MIPS_INS_MINI_U]      = IL_LIFTER_NAME(MINI_U),
    [MIPS_INS_MIN_A]       = IL_LIFTER_NAME(MIN_A),
    [MIPS_INS_MIN]         = IL_LIFTER_NAME(MIN),
    [MIPS_INS_MIN_S]       = IL_LIFTER_NAME(MIN_S),
    [MIPS_INS_MIN_U]       = IL_LIFTER_NAME(MIN_U),
    [MIPS_INS_MOD]         = IL_LIFTER_NAME(MOD),
    [MIPS_INS_MODSUB]      = IL_LIFTER_NAME(MODSUB),
    [MIPS_INS_MODU]        = IL_LIFTER_NAME(MODU),
    [MIPS_INS_MOD_S]       = IL_LIFTER_NAME(MOD_S),
    [MIPS_INS_MOD_U]       = IL_LIFTER_NAME(MOD_U),
    [MIPS_INS_MOVE]        = IL_LIFTER_NAME(MOVE),
    [MIPS_INS_MOVEP]       = IL_LIFTER_NAME(MOVEP),
    [MIPS_INS_MOVF]        = IL_LIFTER_NAME(MOVF),
    [MIPS_INS_MOVN]        = IL_LIFTER_NAME(MOVN),
    [MIPS_INS_MOVT]        = IL_LIFTER_NAME(MOVT),
    [MIPS_INS_MOVZ]        = IL_LIFTER_NAME(MOVZ),
    [MIPS_INS_MSUB]        = IL_LIFTER_NAME(MSUB),
    [MIPS_INS_MSUBF]       = IL_LIFTER_NAME(MSUBF),
    [MIPS_INS_MSUBR_Q]     = IL_LIFTER_NAME(MSUBR_Q),
    [MIPS_INS_MSUBU]       = IL_LIFTER_NAME(MSUBU),
    [MIPS_INS_MSUBV]       = IL_LIFTER_NAME(MSUBV),
    [MIPS_INS_MSUB_Q]      = IL_LIFTER_NAME(MSUB_Q),
    [MIPS_INS_MTC0]        = IL_LIFTER_NAME(MTC0),
    [MIPS_INS_MTC1]        = IL_LIFTER_NAME(MTC1),
    [MIPS_INS_MTC2]        = IL_LIFTER_NAME(MTC2),
    [MIPS_INS_MTHC1]       = IL_LIFTER_NAME(MTHC1),
    [MIPS_INS_MTHI]        = IL_LIFTER_NAME(MTHI),
    [MIPS_INS_MTHLIP]      = IL_LIFTER_NAME(MTHLIP),
    [MIPS_INS_MTLO]        = IL_LIFTER_NAME(MTLO),
    [MIPS_INS_MTM0]        = IL_LIFTER_NAME(MTM0),
    [MIPS_INS_MTM1]        = IL_LIFTER_NAME(MTM1),
    [MIPS_INS_MTM2]        = IL_LIFTER_NAME(MTM2),
    [MIPS_INS_MTP0]        = IL_LIFTER_NAME(MTP0),
    [MIPS_INS_MTP1]        = IL_LIFTER_NAME(MTP1),
    [MIPS_INS_MTP2]        = IL_LIFTER_NAME(MTP2),
    [MIPS_INS_MUH]         = IL_LIFTER_NAME(MUH),
    [MIPS_INS_MUHU]        = IL_LIFTER_NAME(MUHU),
    [MIPS_INS_MULEQ_S]     = IL_LIFTER_NAME(MULEQ_S),
    [MIPS_INS_MULEU_S]     = IL_LIFTER_NAME(MULEU_S),
    [MIPS_INS_MULQ_RS]     = IL_LIFTER_NAME(MULQ_RS),
    [MIPS_INS_MULQ_S]      = IL_LIFTER_NAME(MULQ_S),
    [MIPS_INS_MULR_Q]      = IL_LIFTER_NAME(MULR_Q),
    [MIPS_INS_MULSAQ_S]    = IL_LIFTER_NAME(MULSAQ_S),
    [MIPS_INS_MULSA]       = IL_LIFTER_NAME(MULSA),
    [MIPS_INS_MULT]        = IL_LIFTER_NAME(MULT),
    [MIPS_INS_MULTU]       = IL_LIFTER_NAME(MULTU),
    [MIPS_INS_MULU]        = IL_LIFTER_NAME(MULU),
    [MIPS_INS_MULV]        = IL_LIFTER_NAME(MULV),
    [MIPS_INS_MUL_Q]       = IL_LIFTER_NAME(MUL_Q),
    [MIPS_INS_MUL_S]       = IL_LIFTER_NAME(MUL_S),
    [MIPS_INS_NLOC]        = IL_LIFTER_NAME(NLOC),
    [MIPS_INS_NLZC]        = IL_LIFTER_NAME(NLZC),
    [MIPS_INS_NMADD]       = IL_LIFTER_NAME(NMADD),
    [MIPS_INS_NMSUB]       = IL_LIFTER_NAME(NMSUB),
    [MIPS_INS_NOR]         = IL_LIFTER_NAME(NOR),
    [MIPS_INS_NORI]        = IL_LIFTER_NAME(NORI),
    [MIPS_INS_NOT16]       = IL_LIFTER_NAME(NOT16),
    [MIPS_INS_NOT]         = IL_LIFTER_NAME(NOT),
    [MIPS_INS_OR]          = IL_LIFTER_NAME(OR),
    [MIPS_INS_OR16]        = IL_LIFTER_NAME(OR16),
    [MIPS_INS_ORI]         = IL_LIFTER_NAME(ORI),
    [MIPS_INS_PACKRL]      = IL_LIFTER_NAME(PACKRL),
    [MIPS_INS_PAUSE]       = IL_LIFTER_NAME(PAUSE),
    [MIPS_INS_PCKEV]       = IL_LIFTER_NAME(PCKEV),
    [MIPS_INS_PCKOD]       = IL_LIFTER_NAME(PCKOD),
    [MIPS_INS_PCNT]        = IL_LIFTER_NAME(PCNT),
    [MIPS_INS_PICK]        = IL_LIFTER_NAME(PICK),
    [MIPS_INS_POP]         = IL_LIFTER_NAME(POP),
    [MIPS_INS_PRECEQU]     = IL_LIFTER_NAME(PRECEQU),
    [MIPS_INS_PRECEQ]      = IL_LIFTER_NAME(PRECEQ),
    [MIPS_INS_PRECEU]      = IL_LIFTER_NAME(PRECEU),
    [MIPS_INS_PRECRQU_S]   = IL_LIFTER_NAME(PRECRQU_S),
    [MIPS_INS_PRECRQ]      = IL_LIFTER_NAME(PRECRQ),
    [MIPS_INS_PRECRQ_RS]   = IL_LIFTER_NAME(PRECRQ_RS),
    [MIPS_INS_PRECR]       = IL_LIFTER_NAME(PRECR),
    [MIPS_INS_PRECR_SRA]   = IL_LIFTER_NAME(PRECR_SRA),
    [MIPS_INS_PRECR_SRA_R] = IL_LIFTER_NAME(PRECR_SRA_R),
    [MIPS_INS_PREF]        = IL_LIFTER_NAME(PREF),
    [MIPS_INS_PREPEND]     = IL_LIFTER_NAME(PREPEND),
    [MIPS_INS_RADDU]       = IL_LIFTER_NAME(RADDU),
    [MIPS_INS_RDDSP]       = IL_LIFTER_NAME(RDDSP),
    [MIPS_INS_RDHWR]       = IL_LIFTER_NAME(RDHWR),
    [MIPS_INS_REPLV]       = IL_LIFTER_NAME(REPLV),
    [MIPS_INS_REPL]        = IL_LIFTER_NAME(REPL),
    [MIPS_INS_RINT]        = IL_LIFTER_NAME(RINT),
    [MIPS_INS_ROTR]        = IL_LIFTER_NAME(ROTR),
    [MIPS_INS_ROTRV]       = IL_LIFTER_NAME(ROTRV),
    [MIPS_INS_ROUND]       = IL_LIFTER_NAME(ROUND),
    [MIPS_INS_SAT_S]       = IL_LIFTER_NAME(SAT_S),
    [MIPS_INS_SAT_U]       = IL_LIFTER_NAME(SAT_U),
    [MIPS_INS_SB]          = IL_LIFTER_NAME(SB),
    [MIPS_INS_SB16]        = IL_LIFTER_NAME(SB16),
    [MIPS_INS_SC]          = IL_LIFTER_NAME(SC),
    [MIPS_INS_SCD]         = IL_LIFTER_NAME(SCD),
    [MIPS_INS_SD]          = IL_LIFTER_NAME(SD),
    [MIPS_INS_SDBBP]       = IL_LIFTER_NAME(SDBBP),
    [MIPS_INS_SDBBP16]     = IL_LIFTER_NAME(SDBBP16),
    [MIPS_INS_SDC1]        = IL_LIFTER_NAME(SDC1),
    [MIPS_INS_SDC2]        = IL_LIFTER_NAME(SDC2),
    [MIPS_INS_SDC3]        = IL_LIFTER_NAME(SDC3),
    [MIPS_INS_SDL]         = IL_LIFTER_NAME(SDL),
    [MIPS_INS_SDR]         = IL_LIFTER_NAME(SDR),
    [MIPS_INS_SDXC1]       = IL_LIFTER_NAME(SDXC1),
    [MIPS_INS_SEB]         = IL_LIFTER_NAME(SEB),
    [MIPS_INS_SEH]         = IL_LIFTER_NAME(SEH),
    [MIPS_INS_SELEQZ]      = IL_LIFTER_NAME(SELEQZ),
    [MIPS_INS_SELNEZ]      = IL_LIFTER_NAME(SELNEZ),
    [MIPS_INS_SEL]         = IL_LIFTER_NAME(SEL),
    [MIPS_INS_SEQ]         = IL_LIFTER_NAME(SEQ),
    [MIPS_INS_SEQI]        = IL_LIFTER_NAME(SEQI),
    [MIPS_INS_SH]          = IL_LIFTER_NAME(SH),
    [MIPS_INS_SH16]        = IL_LIFTER_NAME(SH16),
    [MIPS_INS_SHF]         = IL_LIFTER_NAME(SHF),
    [MIPS_INS_SHILO]       = IL_LIFTER_NAME(SHILO),
    [MIPS_INS_SHILOV]      = IL_LIFTER_NAME(SHILOV),
    [MIPS_INS_SHLLV]       = IL_LIFTER_NAME(SHLLV),
    [MIPS_INS_SHLLV_S]     = IL_LIFTER_NAME(SHLLV_S),
    [MIPS_INS_SHLL]        = IL_LIFTER_NAME(SHLL),
    [MIPS_INS_SHLL_S]      = IL_LIFTER_NAME(SHLL_S),
    [MIPS_INS_SHRAV]       = IL_LIFTER_NAME(SHRAV),
    [MIPS_INS_SHRAV_R]     = IL_LIFTER_NAME(SHRAV_R),
    [MIPS_INS_SHRA]        = IL_LIFTER_NAME(SHRA),
    [MIPS_INS_SHRA_R]      = IL_LIFTER_NAME(SHRA_R),
    [MIPS_INS_SHRLV]       = IL_LIFTER_NAME(SHRLV),
    [MIPS_INS_SHRL]        = IL_LIFTER_NAME(SHRL),
    [MIPS_INS_SLDI]        = IL_LIFTER_NAME(SLDI),
    [MIPS_INS_SLD]         = IL_LIFTER_NAME(SLD),
    [MIPS_INS_SLL]         = IL_LIFTER_NAME(SLL),
    [MIPS_INS_SLL16]       = IL_LIFTER_NAME(SLL16),
    [MIPS_INS_SLLI]        = IL_LIFTER_NAME(SLLI),
    [MIPS_INS_SLLV]        = IL_LIFTER_NAME(SLLV),
    [MIPS_INS_SLT]         = IL_LIFTER_NAME(SLT),
    [MIPS_INS_SLTI]        = IL_LIFTER_NAME(SLTI),
    [MIPS_INS_SLTIU]       = IL_LIFTER_NAME(SLTIU),
    [MIPS_INS_SLTU]        = IL_LIFTER_NAME(SLTU),
    [MIPS_INS_SNE]         = IL_LIFTER_NAME(SNE),
    [MIPS_INS_SNEI]        = IL_LIFTER_NAME(SNEI),
    [MIPS_INS_SPLATI]      = IL_LIFTER_NAME(SPLATI),
    [MIPS_INS_SPLAT]       = IL_LIFTER_NAME(SPLAT),
    [MIPS_INS_SRA]         = IL_LIFTER_NAME(SRA),
    [MIPS_INS_SRAI]        = IL_LIFTER_NAME(SRAI),
    [MIPS_INS_SRARI]       = IL_LIFTER_NAME(SRARI),
    [MIPS_INS_SRAR]        = IL_LIFTER_NAME(SRAR),
    [MIPS_INS_SRAV]        = IL_LIFTER_NAME(SRAV),
    [MIPS_INS_SRL]         = IL_LIFTER_NAME(SRL),
    [MIPS_INS_SRL16]       = IL_LIFTER_NAME(SRL16),
    [MIPS_INS_SRLI]        = IL_LIFTER_NAME(SRLI),
    [MIPS_INS_SRLRI]       = IL_LIFTER_NAME(SRLRI),
    [MIPS_INS_SRLR]        = IL_LIFTER_NAME(SRLR),
    [MIPS_INS_SRLV]        = IL_LIFTER_NAME(SRLV),
    [MIPS_INS_SSNOP]       = IL_LIFTER_NAME(SSNOP),
    [MIPS_INS_ST]          = IL_LIFTER_NAME(ST),
    [MIPS_INS_SUBQH]       = IL_LIFTER_NAME(SUBQH),
    [MIPS_INS_SUBQH_R]     = IL_LIFTER_NAME(SUBQH_R),
    [MIPS_INS_SUBQ]        = IL_LIFTER_NAME(SUBQ),
    [MIPS_INS_SUBQ_S]      = IL_LIFTER_NAME(SUBQ_S),
    [MIPS_INS_SUBSUS_U]    = IL_LIFTER_NAME(SUBSUS_U),
    [MIPS_INS_SUBSUU_S]    = IL_LIFTER_NAME(SUBSUU_S),
    [MIPS_INS_SUBS_S]      = IL_LIFTER_NAME(SUBS_S),
    [MIPS_INS_SUBS_U]      = IL_LIFTER_NAME(SUBS_U),
    [MIPS_INS_SUBU16]      = IL_LIFTER_NAME(SUBU16),
    [MIPS_INS_SUBUH]       = IL_LIFTER_NAME(SUBUH),
    [MIPS_INS_SUBUH_R]     = IL_LIFTER_NAME(SUBUH_R),
    [MIPS_INS_SUBU]        = IL_LIFTER_NAME(SUBU),
    [MIPS_INS_SUBU_S]      = IL_LIFTER_NAME(SUBU_S),
    [MIPS_INS_SUBVI]       = IL_LIFTER_NAME(SUBVI),
    [MIPS_INS_SUBV]        = IL_LIFTER_NAME(SUBV),
    [MIPS_INS_SUXC1]       = IL_LIFTER_NAME(SUXC1),
    [MIPS_INS_SW]          = IL_LIFTER_NAME(SW),
    [MIPS_INS_SW16]        = IL_LIFTER_NAME(SW16),
    [MIPS_INS_SWC1]        = IL_LIFTER_NAME(SWC1),
    [MIPS_INS_SWC2]        = IL_LIFTER_NAME(SWC2),
    [MIPS_INS_SWC3]        = IL_LIFTER_NAME(SWC3),
    [MIPS_INS_SWL]         = IL_LIFTER_NAME(SWL),
    [MIPS_INS_SWM16]       = IL_LIFTER_NAME(SWM16),
    [MIPS_INS_SWM32]       = IL_LIFTER_NAME(SWM32),
    [MIPS_INS_SWP]         = IL_LIFTER_NAME(SWP),
    [MIPS_INS_SWR]         = IL_LIFTER_NAME(SWR),
    [MIPS_INS_SWXC1]       = IL_LIFTER_NAME(SWXC1),
    [MIPS_INS_SYNC]        = IL_LIFTER_NAME(SYNC),
    [MIPS_INS_SYNCI]       = IL_LIFTER_NAME(SYNCI),
    [MIPS_INS_SYSCALL]     = IL_LIFTER_NAME(SYSCALL),
    [MIPS_INS_TEQ]         = IL_LIFTER_NAME(TEQ),
    [MIPS_INS_TEQI]        = IL_LIFTER_NAME(TEQI),
    [MIPS_INS_TGE]         = IL_LIFTER_NAME(TGE),
    [MIPS_INS_TGEI]        = IL_LIFTER_NAME(TGEI),
    [MIPS_INS_TGEIU]       = IL_LIFTER_NAME(TGEIU),
    [MIPS_INS_TGEU]        = IL_LIFTER_NAME(TGEU),
    [MIPS_INS_TLBP]        = IL_LIFTER_NAME(TLBP),
    [MIPS_INS_TLBR]        = IL_LIFTER_NAME(TLBR),
    [MIPS_INS_TLBWI]       = IL_LIFTER_NAME(TLBWI),
    [MIPS_INS_TLBWR]       = IL_LIFTER_NAME(TLBWR),
    [MIPS_INS_TLT]         = IL_LIFTER_NAME(TLT),
    [MIPS_INS_TLTI]        = IL_LIFTER_NAME(TLTI),
    [MIPS_INS_TLTIU]       = IL_LIFTER_NAME(TLTIU),
    [MIPS_INS_TLTU]        = IL_LIFTER_NAME(TLTU),
    [MIPS_INS_TNE]         = IL_LIFTER_NAME(TNE),
    [MIPS_INS_TNEI]        = IL_LIFTER_NAME(TNEI),
    [MIPS_INS_TRUNC]       = IL_LIFTER_NAME(TRUNC),
    [MIPS_INS_V3MULU]      = IL_LIFTER_NAME(V3MULU),
    [MIPS_INS_VMM0]        = IL_LIFTER_NAME(VMM0),
    [MIPS_INS_VMULU]       = IL_LIFTER_NAME(VMULU),
    [MIPS_INS_VSHF]        = IL_LIFTER_NAME(VSHF),
    [MIPS_INS_WAIT]        = IL_LIFTER_NAME(WAIT),
    [MIPS_INS_WRDSP]       = IL_LIFTER_NAME(WRDSP),
    [MIPS_INS_WSBH]        = IL_LIFTER_NAME(WSBH),
    [MIPS_INS_XOR]         = IL_LIFTER_NAME(XOR),
    [MIPS_INS_XOR16]       = IL_LIFTER_NAME(XOR16),
    [MIPS_INS_XORI]        = IL_LIFTER_NAME(XORI),
    [MIPS_INS_NOP]         = IL_LIFTER_NAME(NOP),
    [MIPS_INS_NEGU]        = IL_LIFTER_NAME(NEGU),
    [MIPS_INS_JALR_HB]     = IL_LIFTER_NAME(JALR_HB),
    [MIPS_INS_JR_HB]       = IL_LIFTER_NAME(JR_HB),
};
// clang-format on

/**
 * Mips lifter dispatch function.
 *
 * \param cs_insn
 * \return Valid RzILOpEffect* on success, NULL otherwise.
 **/
RZ_IPI RzILOpEffect *mips32_il(RZ_NONNULL cs_insn *insn) {
	rz_return_val_if_fail(insn, NULL);

	MipsILLifterFunction fn = mips_lifters[INSN_ID(insn)];
	if (fn) {
		return fn(insn);
	}

	rz_warn_if_reached();
	return NULL;
}

RZ_IPI RzAnalysisILConfig *mips32_il_config() {
	return NULL;
}
