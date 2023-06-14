// SPDX-FileCopyrightText: 2023 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#include "mips_il.h"
#include <rz_il/rz_il_opbuilder_begin.h>

// typedefs for shorter name
typedef RzILOpPure Pure;
typedef RzILOpEffect Effect;
typedef RzILOpBool Bool;
typedef RzILOpBitVector BitVector;
typedef RzILOpFloat Float;

// TODO: Handle different releases

/**
 * \note
 *                      **Macro Naming Conventions**
 *                      ----------------------------
 * - If there's IL at the beginning of names of macro, this means it will
 *   return either Effect* or Pure*, whatever makes sense in that case.
 * - Use REG_OPND(opnd_idx) if you want only the name of register and you
 *   know it's an operand.
 * - Use ILREG_OPND(opnd_idx) if you want to get the VARG(reg_name) value.
 * - Similarly there are other macros to get operands in pure value or in
 *   Pure* value.
 *
 * - Macros ending with an "I" are for special cases when only of the operands
 *   is an immediate value. Other arguments can be used with VARL()
 *
 *
 *                    **Handling Delay/Forbidden Slot**
 *                    ---------------------------------
 * - They will be handled in RzAnalysis.
 *
 * */

/**
 * Lifter function prototype.
 *
 * \param analysis To inform about MIPS32 or MIPS64.
 * \param insn Details about current instruction.
 * \param pc Position of current instruction insn
 * \param fl_op Is this a floating point operation?
 * \param fp64 Do we use all 64 bits of FPU registers?
 * \return Effect*
 * */
typedef Effect *(*MipsILLifterFunction)(RzAnalysis *, cs_insn *, ut32, bool, bool);
#define IL_LIFTER(name)      static Effect *MipsLifter_##name(RzAnalysis *analysis, cs_insn *insn, ut32 pc, bool float_op, bool fp64)
#define IL_LIFTER_NAME(name) MipsLifter_##name

// size of Registers
#define GPRLEN   (analysis->bits)
#define FPRLEN() (fp64 ? 64 : 32)

// v  : value to be sign extended
// vn : bitsize of v
// n  : number of bits to sign extend to
#define SIGN_EXTEND(v, nv, n) ((v & ((ut64)1 << (nv - 1))) ? (v | ((ut64)((ut64)1 << (n - nv)) - 1) << nv) : v)
#define ZERO_EXTEND(v, nv, n) v & ~(((ut64)(1 << (n - nv)) - 1) << nv)

// get instruction operand count
#define OPND_COUNT() ((insn)->detail->mips.op_count)
// get instruction operand at given index type
#define OPND_TYPE(idx) ((insn)->detail->mips.operands[(idx)].type)

// get instruction operand at given index
#define OPND_IS_REG(idx) INSN_OPND_TYPE(insn, idx) == MIPS_OP_REG
#define REG_OPND(idx)    REG_NAME((insn)->detail->mips.operands[(idx)].reg)

// get instruction operand at given index
#define OPND_IS_MEM(insn, idx) INSN_OPND_TYPE(insn, idx) == MIPS_OP_MEM
#define MEM_OPND(idx)          ((insn)->detail->mips.operands[(idx)].mem)
#define MEM_OPND_BASE(idx)     REG_NAME(MEM_OPND(idx).base)
#define MEM_OPND_OFFSET(idx)   MEM_OPND(idx).disp

// get instruction operand at given index
#define OPND_IS_IMM(insn, idx) INSN_OPND_TYPE(insn, idx) == MIPS_OP_IMM
#define IMM_OPND(idx)          ((insn)->detail->mips.operands[(idx)].imm)

#define INSN_ID(insn)           (insn)->id
#define INSN_GROUP(grpdx)       ((insn)->detail->groups[grpdx])
#define INSN_GROUP_COUNT(gprdx) ((insn)->detail->groups_count)

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

	[MIPS_REG_HI] = "hi",
	[MIPS_REG_LO] = "lo",

	[MIPS_REG_F0] = "f0",
	[MIPS_REG_F1] = "f1",
	[MIPS_REG_F2] = "f2",
	[MIPS_REG_F3] = "f3",
	[MIPS_REG_F4] = "f4",
	[MIPS_REG_F5] = "f5",
	[MIPS_REG_F6] = "f6",
	[MIPS_REG_F7] = "f7",
	[MIPS_REG_F8] = "f8",
	[MIPS_REG_F9] = "f9",
	[MIPS_REG_F10] = "f10",
	[MIPS_REG_F11] = "f11",
	[MIPS_REG_F12] = "f12",
	[MIPS_REG_F13] = "f13",
	[MIPS_REG_F14] = "f14",
	[MIPS_REG_F15] = "f15",
	[MIPS_REG_F16] = "f16",
	[MIPS_REG_F17] = "f17",
	[MIPS_REG_F18] = "f18",
	[MIPS_REG_F19] = "f19",
	[MIPS_REG_F20] = "f20",
	[MIPS_REG_F21] = "f21",
	[MIPS_REG_F22] = "f22",
	[MIPS_REG_F23] = "f23",
	[MIPS_REG_F24] = "f24",
	[MIPS_REG_F25] = "f25",
	[MIPS_REG_F26] = "f26",
	[MIPS_REG_F27] = "f27",
	[MIPS_REG_F28] = "f28",
	[MIPS_REG_F29] = "f29",
	[MIPS_REG_F30] = "f30",
	[MIPS_REG_F31] = "f31",

	// FCC registers are removed in MISPr6
	// but we don't need to care about that
	// since MIPSr6 instructions will
	// automatically not use these registers
	[MIPS_REG_FCC0] = "FCC0",
	[MIPS_REG_FCC1] = "FCC1",
	[MIPS_REG_FCC2] = "FCC2",
	[MIPS_REG_FCC3] = "FCC3",
	[MIPS_REG_FCC4] = "FCC4",
	[MIPS_REG_FCC5] = "FCC5",
	[MIPS_REG_FCC6] = "FCC6",
	[MIPS_REG_FCC7] = "FCC7",

	// COP registers
	[MIPS_REG_CC0] = "CC0",
	[MIPS_REG_CC1] = "CC1",
	[MIPS_REG_CC2] = "CC2",
	[MIPS_REG_CC3] = "CC3",
	[MIPS_REG_CC4] = "CC4",
	[MIPS_REG_CC5] = "CC5",
	[MIPS_REG_CC6] = "CC6",
	[MIPS_REG_CC7] = "CC7",
};

// char*
#define REG_PC()     REG_NAME(MIPS_REG_PC)
#define REG_HI()     REG_NAME(MIPS_REG_HI)
#define REG_LO()     REG_NAME(MIPS_REG_LO)
#define REG_R(idx)   REG_NAME(MIPS_REG_##idx)
#define REG_FCC(idx) REG_NAME(MIPS_REG_FCC##idx)
#define REG_CC(idx)  REG_NAME(MIPS_REG_CC##idx)
// Pure*
#define IL_REG_PC()     VARG(REG_PC())
#define IL_REG_HI()     VARG(REG_HI())
#define IL_REG_LO()     VARG(REG_LO())
#define IL_REG_R(idx)   VARG(REG_R(idx))
#define IL_REG_FCC(idx) VARG(REG_FCC(idx))
#define IL_REG_CC(idx)  VARG(REG_CC(idx))

// char*
#define REG_F(idx) REG_NAME(MIPS_REG_F##idx)
// Pure*
#define IL_REG_F(idx) VARG(REG_F(idx))

// difference between INSN and INSN.fmt operations (eg: ADD and ADD.fmt)
// is in type of operands only. They both take same number of arguments
// this macro will check if instruction needs to be a ".fmt" instruction
// Use only in operations where first operand itself can be float
// NOTE: I'm checking only first operand for
#define IS_FLOAT_OPND(opndx) ((((insn)->detail->mips.operands[opndx].reg) >= MIPS_REG_F0) && (((insn)->detail->mips.operands[opndx].reg) <= MIPS_REG_F31))

// returns Pure*
#define REG_NAME(regenum)           cpu_reg_enum_to_name_map[regenum]
#define IL_REG_OPND(opndidx)        VARG(REG_OPND(opndidx))
#define IL_MEM_OPND_BASE(opndidx)   VARG(MEM_OPND_BASE(opndidx))
#define IL_MEM_OPND_OFFSET(opndidx) SN(GPRLEN, SIGN_EXTEND(MEM_OPND_OFFSET(opndidx), 16, GPRLEN))

// TODO: FIGURE OUT ROUNDING MODE
#define RMODE RZ_FLOAT_RMODE_RNE

// CAUSE REGISTER HANDLER MACROS
// only the exception bits present here are used in whole code
// ones not present will never be used
#define REG_CAUSE_EXCEPTION()    "CAUSE_EXC"
#define IL_REG_CAUSE_EXCEPTION() VARG(REG_CAUSE_EXCEPTION())
#define IL_CAUSE_CLEAR()         SETG(REG_CAUSE_EXCEPTION(), U8(0));
// list of managed exceptions
#define IL_CAUSE_INTERRUPT()            SETG(REG_CAUSE_EXCEPTION(), U8(0x00))
#define IL_CAUSE_ADDRESS_LOAD_ERROR()   SETG(REG_CAUSE_EXCEPTION(), U8(0x04))
#define IL_CAUSE_ADDRESS_STORE_ERROR()  SETG(REG_CAUSE_EXCEPTION(), U8(0x05))
#define IL_CAUSE_SYSCALL()              SETG(REG_CAUSE_EXCEPTION(), U8(0x08))
#define IL_CAUSE_BREAKPOINT()           SETG(REG_CAUSE_EXCEPTION(), U8(0x09))
#define IL_CAUSE_OVERFLOW()             SETG(REG_CAUSE_EXCEPTION(), U8(0x0C))
#define IL_CAUSE_RESERVED_INSTRUCTION() SETG(REG_CAUSE_EXCEPTION(), U8(0x0A))
#define IL_CAUSE_TRAP()                 SETG(REG_CAUSE_EXCEPTION(), U8(0x0D))

// TODO: REMOVE IF NOT NEEDED IN FUTURE
// res must be a global variable
// x and y must be local variable
// returns Bool*
/* #define IL_CHECK_OVERFLOW(x, y, res) IS_ZERO(AND(XOR(MSB(x), MSB(res)), XOR(MSB(y), MSB(res)))) */
/* #define IL_CHECK_CARRY(x, y, res)    IS_ZERO(OR(AND(MSB(x), MSB(y)), AND(OR(MSB(x), MSB(y)), INV(MSB(res))))) */

// This is how MIPS ISA defines it [REG_BIT(n) == REG_BIT(n-1)]
#define IL_BITN(x, n)            SHIFTR0(LOGAND(x, UN(GPRLEN, (ut64)1 << (n - 1))), UN(GPRLEN, n - 1))
#define IL_CHECK_OVERFLOW(r, sz) EQ(IL_BITN(r, sz), IL_BITN(r, sz - 1))

IL_LIFTER(ABSQ_S) {
	return NULL;
}

/**
 * Add word.
 * Format : ADD rd, rs, rt
 *          ADD.S fd, fs, ft
 *          ADD.d fd, fs, ft
 *          ADD.ps is removed in release 6
 * Description: GPR[rd] <- GPR[rs] + GPR[rt]
 * Exceptions: IntegerOverflow
 * */
IL_LIFTER(ADD) {
	// destination reg
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	// add.fmt
	// TODO: Verify if 32 bits or 64 bits FPRLEN makes any difference
	// do we need to explicitly cast floats to 32 bit?
	if (float_op) {
		Float *fsum = FADD(RMODE, rs, rt);
		return SETG(rd, fsum);
	} else {
		// sign extend to 32 or 64 bit based on (analyisis->bits)
		BitVector *sum = SIGNED(GPRLEN, ADD(rs, rt));
		// check 32 bit overflow
		Bool *overflow = IL_CHECK_OVERFLOW(DUP(sum), 32);
		Effect *set_rd = SETG(rd, sum);
		return BRANCH(overflow, IL_CAUSE_OVERFLOW(), set_rd);
	}
}

/**
 * Add Immediate to PC.
 * Format: ADDIUPC rs, immdediate
 * Description: GPR[rs] <- (PC + sign_extend( immediate << 2 ))
 * Exceptions: None
 * */
IL_LIFTER(ADDIUPC) {
	char *rs = REG_OPND(0);

	st32 imm_val = (st32)IMM_OPND(1);
	imm_val = SIGN_EXTEND(imm_val, 21, GPRLEN);
	BitVector *imm = SN(GPRLEN, imm_val);

	BitVector *sum = ADD(U32(pc), imm);
	Effect *set_rs = SETG(rs, sum);
	return set_rs;
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
 * */
IL_LIFTER(ADDU) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *sum = ADD(rs, rt);
	Effect *set_rd = SETG(rd, sum);
	return set_rd;
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
 * */
IL_LIFTER(ADDI) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);

	// get imm
	st32 imm_val = (st32)IMM_OPND(1);
	imm_val = SIGN_EXTEND(imm_val, 16, 32);
	BitVector *imm = SN(GPRLEN, imm_val);

	BitVector *sum = ADD(rs, imm);
	Bool *overflow = IL_CHECK_OVERFLOW(DUP(sum), 32);

	Effect *set_rt = SETG(rt, sum);
	Effect *add_op = BRANCH(overflow, IL_CAUSE_OVERFLOW(), set_rt);

	return add_op;
}

/**
 * Add Immediate Unsigned Word.
 * Format: ADDI rt, rs, immediate
 * Description: GPR[rt] <- GPR[rs] + immediate
 * Exceptions: None
 * */
IL_LIFTER(ADDIU) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);

	st32 imm_val = (st32)IMM_OPND(1);
	imm_val = SIGN_EXTEND(imm_val, 16, GPRLEN);
	BitVector *imm = SN(GPRLEN, imm_val);

	BitVector *sum = ADD(rs, imm);
	Effect *set_rt = SETG(rt, sum);
	return set_rt;
}

/**
 * ALIGN.
 * DALIGN
 * Concatenate two GPRs and extract a contiguous subset
 * at a byte position.
 * Format: ALIGN rd, rs, rt, bp    -> WORD SIZED GPRS
 *         DALIGN rd, rs, rt, bp   -> DWORD SIZED GPRS
 * Description: GPR[rd] <- (GPR[rt] << (8*bp)) or (GPR[rs] >> (GPRLEN - 8*bp))
 * Exceptions: ALIGN : None
 *             DALIGN : ReservedInstruction
 * */
IL_LIFTER(ALIGN) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);
	ut8 bp = 8 * IMM_OPND(3); // 8*bp is used everywhere, because 1 byte is 8 bits

	BitVector *left = SHIFTL0(rt, U8(bp));
	BitVector *right = SHIFTR0(rs, U8(GPRLEN - bp));
	BitVector *align = LOGOR(left, right);

	Effect *set_rd = SETG(rd, align);
	return set_rd;
}

// MISSING: ALNV.PS (Paired Single)
// REMOVED IN MIPSR6

/**
 * Aligned Add Upper Intermedate to PC.
 * Format: ALUIPC rs, immediate
 * Description: GPR[rs] <- ~0x0FFFF & (PC + sign_extend(immediate << 16))
 * Exceptions: None
 * */
IL_LIFTER(ALUIPC) {
	char *rs = REG_OPND(0);

	st64 imm = SIGN_EXTEND(IMM_OPND(1) << 16, 32, GPRLEN);
	BitVector *new_pc = U32(~0xFFFF & (pc + imm));

	Effect *set_rs = SETG(rs, new_pc);
	return set_rs;
}

/**
 * Logical And
 * Format: AND rd, rs, rt
 * Description: GPR[rd] <- GPR[rs] and GPR[rt]
 * Exceptions: None
 * */
IL_LIFTER(AND) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *and = LOGAND(rs, rt);
	Effect *set_rd = SETG(rd, and);
	return set_rd;
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
 * */
IL_LIFTER(ANDI) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);

	st32 imm_val = (st32)IMM_OPND(2);
	imm_val = ZERO_EXTEND(imm_val, 16, GPRLEN);
	BitVector *imm = SN(GPRLEN, imm_val);

	BitVector *and = LOGAND(rs, imm);
	Effect *set_rd = SETG(rd, and);
	return set_rd;
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
 * Format: AUI rt, rs, immediate
 * Description: GPR[rt] <- sign_extend.32(GPR[rs] + sign_extend(immediate << 16))
 * Exceptions: None
 * NOTE: Check sign extension
 * */
IL_LIFTER(AUI) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);

	st32 imm_val = (st32)IMM_OPND(2) << 16;
	BitVector *imm = SN(GPRLEN, imm_val);

	BitVector *sum = SIGNED(32, ADD(rs, imm));
	Effect *set_rt = SETG(rt, sum);
	return set_rt;
}

/**
 * And Upper Immediate to PC
 * Format: AUIPC rs, immediate
 * Description: GPR[rs] <- PC and immediate << 16
 * Exceptions: None
 * NOTE: Check sign extension
 * */
IL_LIFTER(AUIPC) {
	char *rs = REG_OPND(0);
	st64 imm = SIGN_EXTEND((st64)IMM_OPND(1) << 16, 32, GPRLEN);
	BitVector *new_pc = SN(GPRLEN, pc + imm);

	Effect *set_rs = SETG(rs, new_pc);
	return set_rs;
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

/**
 * Branch And Link
 * To do an unconditional PC relative procedure call.
 * Format: BAL offset
 * Description: procedure_call
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BAL) {
	st64 offset = (st64)IMM_OPND(0) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, pc + offset);

	// store link in r31 and jump
	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 8));
	Effect *jump_op = JMP(jump_target);

	return SEQ2(link_op, jump_op);
}

/**
 * Branch And Link Compact
 * Format: BALC offset
 * Description: procedure_call (no delay slot)
 * Exceptions: None
 * */
IL_LIFTER(BALC) {
	st64 offset = (st64)IMM_OPND(0) << 2;
	offset = SIGN_EXTEND(offset, 28, 32);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 4));
	Effect *jump_op = JMP(jump_target);

	return SEQ2(link_op, jump_op);
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

/**
 * Branch Compact
 * Format: BC offset
 * Description: PC <- PC + 4 + sign_extend(offset << 2) (no delay slot)
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BC) {
	st64 offset = (st64)IMM_OPND(0) << 2;
	offset = SIGN_EXTEND(offset, 28, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	Effect *jump_op = JMP(jump_target);
	return jump_op;
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

/**
 * Branch if Co-Processor 1 Register Bit 0 Equal to Zero
 * Format: BC1EQZ ft, offset
 * Description: if FPR[ft] & 1 == 0 then branch
 * Exceptions: CoprocessorUnusable.
 * */
IL_LIFTER(BC1EQZ) {
	Pure *ft = IL_REG_OPND(0);

	// compute jump address
	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	// create branch condition
	BitVector *ft_bv = F2BV(ft);
	BitVector *ft_bit0 = fp64 ? LOGAND(ft_bv, U64(1)) : LOGAND(ft_bv, U32(1));
	Bool *cond = IS_ZERO(ft_bit0);

	// make branch
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch on FP False
 * Format: BC1F offset (cc = 0 implied)
 *         BC1F cc, offset
 * Description: if FPConditionCode(cc) == 0 then branch
 * Exceptions: CoprocessorUnusable, ReservedInstruction
 * */
IL_LIFTER(BC1F) {
	Pure *fccr = OPND_COUNT() == 2 ? IL_REG_OPND(0) : IL_REG_FCC(0);
	st64 joff = SIGN_EXTEND((st64)IMM_OPND(1) << 2, 18, GPRLEN);

	Bool *cond = IS_ZERO(fccr);
	return BRANCH(cond, JMP(UN(GPRLEN, pc + joff)), NOP());
}

/**
 * Branch on FP False Likely
 * Format: BC1F offset (cc = 0 implied)
 *         BC1F cc, offset
 * Description: if FPConditionCode(cc) == 0 then branch_likely
 * Exceptions: CoprocessorUnusable, ReservedInstruction
 * */
IL_LIFTER(BC1FL) {
	Pure *fccr = OPND_COUNT() == 2 ? IL_REG_OPND(0) : IL_REG_FCC(0);
	st64 joff = SIGN_EXTEND((st64)IMM_OPND(1) << 2, 18, GPRLEN);

	Bool *cond = IS_ZERO(fccr);
	return BRANCH(cond, JMP(UN(GPRLEN, pc + joff)), NOP());
}

/**
 * Branch if Co-Processor 1 Register Bit 0 NOT Equal to Zero
 * Format: BC1NEZ ft, offset
 * Description: if FPR[ft] & 1 != 0 then branch
 * Exceptions: CoprocessorUnusable.
 * */
IL_LIFTER(BC1NEZ) {
	Pure *ft = IL_REG_OPND(0);

	// compute jump address
	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	// make condition for branch
	BitVector *ft_bv = F2BV(ft);
	BitVector *ft_bit0 = fp64 ? LOGAND(ft_bv, U64(1)) : LOGAND(ft_bv, U32(1));
	Bool *cond = INV(IS_ZERO(ft_bit0));

	// branch on condn
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());

	return branch_op;
}

/**
 * Branch on FP True
 * Format: BC1T offset (cc = 0 implied)
 *         BC1T cc, offset
 * Description: if FPConditionCode(cc) == 1 then branch
 * Exceptions: CoprocessorUnusable, ReservedInstruction
 * */
IL_LIFTER(BC1T) {
	Pure *fccr = OPND_COUNT() == 2 ? IL_REG_OPND(0) : IL_REG_FCC(0);
	st64 joff = SIGN_EXTEND((st64)IMM_OPND(1) << 2, 18, GPRLEN);

	Bool *cond = INV(IS_ZERO(fccr));
	return BRANCH(cond, JMP(UN(GPRLEN, pc + joff)), NOP());
}

/**
 * Branch on FP True Likely
 * Format: BC1TL offset (cc = 0 implied)
 *         BC1TL cc, offset
 * Description: if FPConditionCode(cc) == 1 then branch_likely
 * Exceptions: CoprocessorUnusable, ReservedInstruction
 * */
IL_LIFTER(BC1TL) {
	Pure *fccr = OPND_COUNT() == 2 ? IL_REG_OPND(0) : IL_REG_FCC(0);
	st64 joff = SIGN_EXTEND((st64)IMM_OPND(1) << 2, 18, GPRLEN);

	Bool *cond = INV(IS_ZERO(fccr));
	return BRANCH(cond, JMP(UN(GPRLEN, pc + joff)), NOP());
}

/**
 * Branch on COP2 Condition Register Equal to Zero
 * Format: BC2EQZ ct, offset
 * Description: if COP2Condition[ct] == 0 then branch
 * Exceptions: CoprocessorUnusable, ReservedInstruction
 * */
IL_LIFTER(BC2EQZ) {
	Pure *ccr = OPND_COUNT() == 2 ? IL_REG_OPND(0) : IL_REG_CC(0);
	st64 joff = SIGN_EXTEND((st64)IMM_OPND(1) << 2, 18, GPRLEN);

	Bool *cond = IS_ZERO(ccr);
	return BRANCH(cond, JMP(UN(GPRLEN, pc + 4 + joff)), NOP());
}

/**
 * Branch on COP2 False
 * Format: BC2F cc, offset
 * Description: if COP2Condition[cc] == 0 then branch
 * Exceptions: CoprocessorUnusable, ReservedInstruction
 * */
IL_LIFTER(BC2F) {
	Pure *ccr = OPND_COUNT() == 2 ? IL_REG_OPND(0) : IL_REG_CC(0);
	st64 joff = SIGN_EXTEND((st64)IMM_OPND(1) << 2, 18, GPRLEN);

	Bool *cond = IS_ZERO(ccr);
	return BRANCH(cond, JMP(UN(GPRLEN, pc + joff)), NOP());
}

/**
 * Branch on COP2 False Likely
 * Format: BC2FL cc, offset
 * Description: if COP2Condition[cc] == 0 then branch_likely
 * Exceptions: CoprocessorUnusable, ReservedInstruction
 * */
IL_LIFTER(BC2FL) {
	Pure *ccr = OPND_COUNT() == 2 ? IL_REG_OPND(0) : IL_REG_CC(0);
	st64 joff = SIGN_EXTEND((st64)IMM_OPND(1) << 2, 18, GPRLEN);

	Bool *cond = IS_ZERO(ccr);
	return BRANCH(cond, JMP(UN(GPRLEN, pc + joff)), NOP());
}

/**
 * Branch on COP2 Condition Register Not Equal to Zero
 * Format: BC2EQZ ct, offset
 * Description: if COP2Condition[ct] != 0 then branch
 * Exceptions: CoprocessorUnusable, ReservedInstruction
 * */
IL_LIFTER(BC2NEZ) {
	Pure *ccr = OPND_COUNT() == 2 ? IL_REG_OPND(0) : IL_REG_CC(0);
	st64 joff = SIGN_EXTEND((st64)IMM_OPND(1) << 2, 18, GPRLEN);

	Bool *cond = INV(IS_ZERO(ccr));
	return BRANCH(cond, JMP(UN(GPRLEN, pc + 4 + joff)), NOP());
}

/**
 * Branch on COP2 True
 * Format: BC2T cc, offset
 * Description: if COP2Condition[cc] != 0 then branch
 * Exceptions: CoprocessorUnusable, ReservedInstruction
 * */
IL_LIFTER(BC2T) {
	Pure *ccr = OPND_COUNT() == 2 ? IL_REG_OPND(0) : IL_REG_CC(0);
	st64 joff = SIGN_EXTEND((st64)IMM_OPND(1) << 2, 18, GPRLEN);

	Bool *cond = INV(IS_ZERO(ccr));
	return BRANCH(cond, JMP(UN(GPRLEN, pc + joff)), NOP());
}

/**
 * Branch on COP2 True Likely
 * Format: BC2TL cc, offset
 * Description: if COP2Condition[cc] != 0 then branch_likely
 * Exceptions: CoprocessorUnusable, ReservedInstruction
 * */
IL_LIFTER(BC2TL) {
	Pure *ccr = OPND_COUNT() == 2 ? IL_REG_OPND(0) : IL_REG_CC(0);
	st64 joff = SIGN_EXTEND((st64)IMM_OPND(1) << 2, 18, GPRLEN);

	Bool *cond = INV(IS_ZERO(ccr));
	return BRANCH(cond, JMP(UN(GPRLEN, pc + joff)), NOP());
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

/**
 * Branch on Equal
 * Format: BEQ rs, rt, offset
 * Description: if GPR[rs] = GPR[rt] then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BEQ) {
	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	st64 offset = (st64)IMM_OPND(2) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, pc + offset);

	Bool *cond = EQ(rs, rt);
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch on Equal
 * Format: BEQ rs, rt, offset
 * Description: if GPR[rs] = GPR[rt] then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BEQC) {
	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	st64 offset = (st64)IMM_OPND(2) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	Bool *cond = EQ(rs, rt);
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch on Equal Likely
 * Format: BEQL rs, rt, offset
 * Description: if GPR[rs] = GPR[rt] then branch_likely
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BEQL) {
	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	st64 offset = (st64)IMM_OPND(2) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, pc + offset);

	Bool *cond = EQ(rs, rt);
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

IL_LIFTER(BEQZ16) {
	return NULL;
}

/**
 * Branch Equal to Zero And Link Compact
 * Format: BEQZALC rt, offset
 * Description: GPR[rt] == 0 then link and branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BEQZALC) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 4));

	Bool *cond = IS_ZERO(rt);
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return SEQ2(link_op, branch_op);
}

IL_LIFTER(BEQZC) {
	return NULL;
}

/**
 * Branch Greater than Equal to Compact
 * Format: BLTC rs, rt, offset
 * Description: GPR[rs] < GPR[rt] then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BGEC) {
	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	st64 offset = (st64)IMM_OPND(2) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	// signed-less-than
	Bool *cond = SGE(rs, rt);
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch Greater than Equal to Unsigned Compact
 * Format: BLTC rs, rt, offset
 * Description: unsigned(GPR[rs]) >= unsigned(GPR[rt]) then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BGEUC) {
	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	st64 offset = (st64)IMM_OPND(2) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	// signed-less-than
	Bool *cond = UGE(rs, rt);
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch on Greater Than or Equal to Zero
 * Format: BGEZ rs, offset
 * Description: if GPR[rs] >= 0 then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BGEZ) {
	Pure *rs = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, pc + offset);

	// signed-greater-than-equal-to
	Bool *cond = SGE(rs, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch on Greater Than or Equal to Zero and Link
 * Format: BGEZAL rs, offset
 * Description: if GPR[rs] >= then branch_likely
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BGEZAL) {
	Pure *rs = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, pc + offset);

	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 8));

	// signed-greater-than-equal-to
	Bool *cond = SGE(rs, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return SEQ2(link_op, branch_op);
}

/**
 * Branch Greater than Equal to Zero And Link Compact
 * Format: BGEZALC rt, offset
 * Description: GPR[rt] >= 0 then link and branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BGEZALC) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 4));

	// signed-greater-than-equal-to
	Bool *cond = SGE(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return SEQ2(link_op, branch_op);
}

/**
 * Branch Greater than Equal to Zero And Link Likely
 * Format: BGEZALL rt, offset
 * Description: GPR[rt] >= 0 then link and branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BGEZALL) {
	// NOTE: same as BGEZALC, difference is in delay-slot handling
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 4));

	// signed-greater-than-equal-to
	Bool *cond = SGE(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return SEQ2(link_op, branch_op);
}

IL_LIFTER(BGEZALS) {
	return NULL;
}

/**
 * Branch Greater than Equal to Zero Compact
 * Format: BGEZC rt, offset
 * Description: GPR[rt] >= 0 then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BGEZC) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	// signed-less-than-equal-to
	Bool *cond = SGE(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch Greater than Equal to Zero Likely
 * Format: BGEZL rt, offset
 * Description: GPR[rt] >= 0 then branch_likely
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BGEZL) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, pc + offset);

	// signed-less-than-equal-to
	Bool *cond = SGE(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch Greater than Equal to Zero
 * Format: BGEZC rt, offset
 * Description: GPR[rt] >= 0 then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BGTZ) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	// signed-less-than-equal-to
	Bool *cond = SGE(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch Greater than Zero And Link Compact
 * Format: BGTZALC rt, offset
 * Description: GPR[rt] > 0 then link and branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BGTZALC) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 4));

	// signed-greater-than
	Bool *cond = SGT(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return SEQ2(link_op, branch_op);
}

/**
 * Branch Greater than Zero Compact
 * Format: BGTZC rt, offset
 * Description: GPR[rt] > 0 then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BGTZC) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 4));

	// signed-greater-than
	Bool *cond = SGT(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return SEQ2(link_op, branch_op);
}

/**
 * Branch Greater than Zero Likely
 * Format: BGTZL rt, offset
 * Description: GPR[rt] >= 0 then branch_likely
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BGTZL) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, pc + offset);

	// signed-greater-than
	Bool *cond = SGT(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
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

/**
 * Swaps (reverses) bits in each byte
 * Format: BITSWAP rd, rt
 * Description: GPR[rd].byte(i) <- reverse_bits_in_byte(GPR[rt].byte(i)) for all bytes i
 * Exceptions: None
 * */
IL_LIFTER(BITSWAP) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	// TODO: Add support for 64 bit regs
	Effect *swap0 = SETL("temp", LOGOR(SHIFTR0(LOGAND(DUP(rt), U32(0xAAAAAAAA)), U32(1)), SHIFTL0(LOGAND(rt, U32(0x55555555)), U32(1))));
	Effect *swap1 = SETL("temp", LOGOR(SHIFTR0(LOGAND(VARL("temp"), U32(0xCCCCCCCC)), U32(2)), SHIFTL0(LOGAND(VARL("temp"), U32(0x33333333)), U32(2))));
	Effect *swap2 = SETL("temp", LOGOR(SHIFTR0(LOGAND(VARL("temp"), U32(0xF0F0F0F0)), U32(4)), SHIFTL0(LOGAND(VARL("temp"), U32(0x0F0F0F0F)), U32(4))));
	Effect *swap3 = SETL("temp", LOGOR(SHIFTR0(LOGAND(VARL("temp"), U32(0xFF00FF00)), U32(8)), SHIFTL0(LOGAND(VARL("temp"), U32(0x00FF00FF)), U32(8))));
	Effect *swap4 = SETG(rd, LOGOR(SHIFTR0(VARL("temp"), U32(16)), SHIFTL0(VARL("temp"), U32(16))));

	Effect *bitswap_op = SEQ5(swap0, swap1, swap2, swap3, swap4);
	return bitswap_op;
}

/**
 * Branch Less than Equal to Zero
 * Format: BLEZL rs, rt, offset
 * Description: GPR[rs] <= 0 then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BLEZ) {
	Pure *rs = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, pc + offset);

	// signed-less-than-equal-to
	Bool *cond = SLE(rs, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch Less than Equal to Zero And Link Compact
 * Format: BLEZALC rt, offset
 * Description: GPR[rt] <= 0 then link and branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BLEZALC) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 4));

	// signed-less-than-equal-to
	Bool *cond = SLE(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return SEQ2(link_op, branch_op);
}

/**
 * Branch Less than Equal to Zero Compact
 * Format: BLEZC rt, offset
 * Description: GPR[rt] <= 0 then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BLEZC) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	// signed-less-than-equal-to
	Bool *cond = SLE(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch Less Than Compact
 * Format: BLTC rs, rt, offset
 * Description: GPR[rs] < GPR[rt] then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BLTC) {
	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	st64 offset = (st64)IMM_OPND(2) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	// signed-less-than
	Bool *cond = SLT(rs, rt);
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch Less than Equal to Zero Likely
 * Format: BLEZL rs, rt, offset
 * Description: GPR[rs] <= 0 then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BLEZL) {
	Pure *rs = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, pc + offset);

	// signed-less-than-equal-to
	Bool *cond = SLE(rs, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch Less Than Unsigned Compact
 * Format: BLTUC rs, rt, offset
 * Description: GPR[rs] < GPR[rt] then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BLTUC) {
	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	st64 offset = (st64)IMM_OPND(2) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	// signed-less-than
	Bool *cond = ULT(rs, rt);
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch Less Than to Zero
 * Format: BLTZ rt, offset
 * Description: GPR[rt] < 0 then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BLTZ) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, pc + offset);

	// signed-less-than
	Bool *cond = SLT(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch Less Than to Zero And Link
 * Format: BLTZAL rt, offset
 * Description: GPR[rt] < 0 then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BLTZAL) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, pc + offset);

	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 4));

	// signed-less-than
	Bool *cond = SLT(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return SEQ2(link_op, branch_op);
}

/**
 * Branch Less Than Zero And Link Compact
 * Format: BLTZALC rt, offset
 * Description: GPR[rt] < 0 then link and branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BLTZALC) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 4));

	// signed-less-than
	Bool *cond = SLT(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return SEQ2(link_op, branch_op);
}

/**
 * Branch Less Than to Zero And Link Likely
 * Format: BLTZALL rt, offset
 * Description: GPR[rt] < 0 then link and branch_likely
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BLTZALL) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, pc + offset);

	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 4));

	// signed-less-than
	Bool *cond = SLT(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return SEQ2(link_op, branch_op);
}

IL_LIFTER(BLTZALS) {
	return NULL;
}

/**
 * Branch Less Than to Zero Compact
 * Format: BLTZC rt, offset
 * Description: GPR[rt] < 0 then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BLTZC) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	// signed-less-than
	Bool *cond = SLT(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch Less Than to Zero Likely
 * Format: BLTZL rt, offset
 * Description: GPR[rt] < 0 then branch_likely
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BLTZL) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, pc + offset);

	// signed-less-than
	Bool *cond = SLT(rt, SN(GPRLEN, 0));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
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

/**
 * Branch Not Equal
 * Format: BNE rs, rt, offset
 * Description: if GPR[rs] != GPR[rt] then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BNE) {
	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	st64 offset = (st64)IMM_OPND(2) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, pc + offset);

	Bool *cond = INV(EQ(rs, rt));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

/**
 * Branch Not Equal Compact
 * Format: BNEC rs, rt, offset
 * Description: if GPR[rs] != GPR[rt] then branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BNEC) {
	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	st64 offset = (st64)IMM_OPND(2) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	Bool *cond = INV(EQ(rs, rt));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

IL_LIFTER(BNEGI) {
	return NULL;
}
IL_LIFTER(BNEG) {
	return NULL;
}

/**
 * Branch Not Equal Likely
 * Format: BNEL rs, rt, offset
 * Description: if GPR[rs] != GPR[rt] then branch_likely
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BNEL) {
	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	st64 offset = (st64)IMM_OPND(2) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	Bool *cond = INV(EQ(rs, rt));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return branch_op;
}

IL_LIFTER(BNEZ16) {
	return NULL;
}

/**
 * Branch Not Equal to Zero And Link Compact
 * Format: BNEZALC rt, offset
 * Description: GPR[rt] != 0 then link and branch
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(BNEZALC) {
	Pure *rt = IL_REG_OPND(0);

	st64 offset = (st64)IMM_OPND(1) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, (pc + 4) + offset);

	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 4));

	Bool *cond = INV(IS_ZERO(rt));
	Effect *branch_op = BRANCH(cond, JMP(jump_target), NOP());
	return SEQ2(link_op, branch_op);
}

IL_LIFTER(BNEZC) {
	return NULL;
}

/**
 * Branch on No overflow Compact
 * Format: BNVC rs, rt, offset
 * Description: Detect overflow for add (signed 32 bits) and branch if no overflow.
 * Exceptions: None
 * */
IL_LIFTER(BNVC) {
	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	st64 joff = SIGN_EXTEND(IMM_OPND(2) << 2, 18, GPRLEN);

	// branch condition
	Bool *cond;

	// sum_overflow
	Pure *tmp = ADD(rs, rt);
	Bool *sum_overflow = INV(EQ(IL_BITN(tmp, 32), IL_BITN(tmp, 31)));
	cond = sum_overflow;

	// input_overflow
	if (GPRLEN == 64) {
		Bool *is_rs_hiword_zero = INV(IS_ZERO(SHIFTR0(DUP(rs), U8(32))));
		Bool *is_rt_hiword_zero = INV(IS_ZERO(SHIFTR0(DUP(rt), U8(32))));
		Bool *input_overflow = AND(is_rs_hiword_zero, is_rt_hiword_zero);
		cond = OR(cond, input_overflow);
	}

	return BRANCH(INV(cond), JMP(U32((pc + 4) + joff)), NOP());
}

IL_LIFTER(BNZ) {
	return NULL;
}

/**
 * Branch On Overflow Compact
 * Format: BOVC rs, rt, offset
 * Description: Detect overflow for add (signed 32 bits) and branch if overflow.
 * Exceptions: None
 * */
IL_LIFTER(BOVC) {
	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	st64 joff = SIGN_EXTEND(IMM_OPND(2) << 2, 18, GPRLEN);

	// branch condition
	Bool *cond;

	// sum_overflow
	Pure *tmp = ADD(rs, rt);
	Bool *sum_overflow = INV(EQ(IL_BITN(tmp, 32), IL_BITN(tmp, 31)));
	cond = sum_overflow;

	// input_overflow
	if (GPRLEN == 64) {
		Bool *is_rs_word = INV(IS_ZERO(SHIFTR0(DUP(rs), U8(32))));
		Bool *is_rt_word = INV(IS_ZERO(SHIFTR0(DUP(rt), U8(32))));
		Bool *input_overflow = AND(is_rs_word, is_rt_word);
		cond = OR(cond, input_overflow);
	}

	return BRANCH(cond, JMP(U32((pc + 4) + joff)), NOP());
}

IL_LIFTER(BPOSGE32) {
	return NULL;
}

/**
 * BREAK
 * Format: BREAK
 * Description: SignalException(Breakpoint)
 * Exceptions: Breakpoint Exception
 * */
IL_LIFTER(BREAK) {
	// TODO: Does ILVM handle breakpoints?
	return IL_CAUSE_BREAKPOINT();
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

/**
 * Unconditional Branch (B)
 * Format: B offset
 * Description: branch
 * Exceptions: ReservedInstructionException
 * */
IL_LIFTER(B) {
	st64 offset = (st64)IMM_OPND(0) << 2;
	offset = SIGN_EXTEND(offset, 18, GPRLEN);
	BitVector *jump_target = UN(GPRLEN, pc + offset);

	Effect *jump_op = JMP(jump_target);
	return jump_op;
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

/**
 * CEIL
 * Format:
 * Description:
 * Exceptions:
 * */
IL_LIFTER(CEIL) {
	// CEIL requires fixed point format
	// fixed point format is not supported by RzIL for now
	return NOP();
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

/**
 * Count Leading Ones in word.
 * Format: CLO rd, rs
 * Description: GPR[rd] <- count_leading_ones(GPR[rs])
 * Exceptions: None.
 * */
IL_LIFTER(CLO) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);

	Effect *reset_rd = SETG(rd, U32(0));
	Effect *mask = SETL("mask", U32(1 << 31));

	// keep running while (rs & mask != 0)
	// since mask is starting at 1 << 31, it'll run max 32 times
	Bool *loop_cond = INV(IS_ZERO(LOGAND(rs, VARL("mask"))));

	// update mask and count
	// each time loop runs means bit at index is flagged, so simply add 1 to cnt
	Effect *mask_update = SETL("mask", SHIFTR0(VARL("mask"), U32(1)));
	Effect *cnt_update = SETG(rd, ADD(VARG(rd), U32(1)));
	Effect *loop_body = SEQ2(mask_update, cnt_update);

	Effect *loop = REPEAT(loop_cond, loop_body);
	return SEQ3(reset_rd, mask, loop);
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

/**
 * Count Leading Zeroes in word.
 * Format: CLZ rd, rs
 * Description: GPR[rd] <- count_leading_zeroes(GPR[rs])
 * Exceptions: None.
 * */
IL_LIFTER(CLZ) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);

	Effect *reset_rd = SETG(rd, U32(0));
	Effect *mask = SETL("mask", U32(1 << 31));

	// keep running while (rs & mask != 0)
	// since mask is starting at 1 << 31, it'll run max 32 times
	Bool *loop_cond = IS_ZERO(LOGAND(rs, VARL("mask")));

	// update mask and count
	// each time loop runs means bit at index is flagged, so simply add 1 to cnt
	Effect *mask_update = SETL("mask", SHIFTR0(VARL("mask"), U32(1)));
	Effect *cnt_update = SETG(rd, ADD(VARG(rd), U32(1)));
	Effect *loop_body = SEQ2(mask_update, cnt_update);

	Effect *loop = REPEAT(loop_cond, loop_body);
	return SEQ3(reset_rd, mask, loop);
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

/**
 * Doubleword Add
 * Format: DADD rd, rs, rt
 * Description: GPR[rd] <- GPR[rs] + GPR[rt]
 * Exceptions: IntegerOverflow, ReservedInstruction
 * */
IL_LIFTER(DADD) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *sum = ADD(rs, rt);
	Bool *is_overflow = IL_CHECK_OVERFLOW(DUP(sum), 64);

	return BRANCH(is_overflow, IL_CAUSE_OVERFLOW(), SETG(rd, sum));
}

/**
 * Doubleword Add Immediate
 * Format: DADD rd, rs, rt
 * Description: GPR[rd] <- GPR[rs] + GPR[rt]
 * Exceptions: IntegerOverflow, ReservedInstruction
 * */
IL_LIFTER(DADDI) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	BitVector *imm = S64(SIGN_EXTEND(IMM_OPND(2), 16, 64));

	BitVector *sum = ADD(rs, imm);
	Bool *is_overflow = IL_CHECK_OVERFLOW(DUP(sum), 64);

	return BRANCH(is_overflow, IL_CAUSE_OVERFLOW(), SETG(rd, sum));
}

/**
 * Doubleword Add Immediate Unsigned
 * Format: DADDI rd, rs, imm
 * Description: GPR[rd] <- GPR[rs] + sign_extend(imm)
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(DADDIU) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	BitVector *imm = S64(SIGN_EXTEND(IMM_OPND(2), 16, 64));

	return SETG(rd, ADD(rs, imm));
}

/**
 * Doubleword Add Unsigned
 * Format: DADD rd, rs, rt
 * Description: GPR[rd] <- GPR[rs] + GPR[rt]
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(DADDU) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	return SETG(rd, ADD(rs, rt));
}

/**
 * Doubleword And Immediate to Higher bits
 * Format: DAHI rt, rs, immediate
 * Description: GPR[rt] <- GPR[rs] + sign_extend(immediate << 32)
 * Exceptions: ReseredInstruction
 * */
IL_LIFTER(DAHI) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);

	st64 imm_val = (st64)IMM_OPND(2) << 32;
	imm_val = SIGN_EXTEND(imm_val, 48, 64);
	BitVector *imm = S64(imm_val);

	BitVector *sum = ADD(rs, imm);
	Effect *set_rt = SETG(rt, sum);
	return set_rt;
}

IL_LIFTER(DALIGN) {
	return NULL;
}

/**
 * Doubleword And Immediate to Top bits
 * Format: DAUI rt, rs, immediate
 * Description: GPR[rt] <- GPR[rs] + sign_extend(immediate << 16)
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(DATI) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);

	st64 imm_val = (st64)IMM_OPND(2) << 48;
	BitVector *imm = S64(imm_val);

	BitVector *sum = ADD(rs, imm);
	Effect *set_rt = SETG(rt, sum);
	return set_rt;
}

/**
 * Doubleword And Immediate to Upper bits
 * Format: DAUI rt, rs, immediate
 * Description: GPR[rt] <- GPR[rs] + sign_extend(immediate << 16)
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(DAUI) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);

	st64 imm_val = (st64)IMM_OPND(2) << 16;
	imm_val = SIGN_EXTEND(imm_val, 32, 64);
	BitVector *imm = S64(imm_val);

	BitVector *sum = ADD(rs, imm);
	Effect *set_rt = SETG(rt, sum);
	return set_rt;
}

IL_LIFTER(DBITSWAP) {
	return NULL;
}

/**
 * Doubleword Count Leading Ones.
 * Format: DCLO rd, rs
 * Description: GPR[rd] <- count_leading_ones(GPR[rs])
 * Exceptions: None.
 * */
IL_LIFTER(DCLO) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);

	Effect *reset_rd = SETG(rd, U64(0));
	Effect *mask = SETL("mask", U32((ut64)1 << 63));

	// keep running while (rs & mask != 0)
	// since mask is starting at 1 << 63, it'll run max 64 times
	Bool *loop_cond = INV(IS_ZERO(LOGAND(rs, VARL("mask"))));

	// update mask and count
	// each time loop runs means bit at index is flagged, so simply add 1 to cnt
	Effect *mask_update = SETL("mask", SHIFTR0(VARL("mask"), U32(1)));
	Effect *cnt_update = SETG(rd, ADD(VARG(rd), UN(GPRLEN, 1)));
	Effect *loop_body = SEQ2(mask_update, cnt_update);

	Effect *loop = REPEAT(loop_cond, loop_body);
	return SEQ3(reset_rd, mask, loop);
}

/**
 * Doubleword Count Leading Zeroes.
 * Format: DCLZ rd, rs
 * Description: GPR[rd] <- count_leading_zeroes(GPR[rs])
 * Exceptions: None.
 * */
IL_LIFTER(DCLZ) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);

	Effect *reset_rd = SETG(rd, U64(0));
	Effect *mask = SETL("mask", U64((ut64)1 << 63));

	// keep running while (rs & mask != 0)
	// since mask is starting at 1 << 31, it'll run max 32 times
	Bool *loop_cond = IS_ZERO(LOGAND(rs, VARL("mask")));

	// update mask and count
	// each time loop runs means bit at index is flagged, so simply add 1 to cnt
	Effect *mask_update = SETL("mask", SHIFTR0(VARL("mask"), U64(1)));
	Effect *cnt_update = SETG(rd, ADD(VARG(rd), U64(1)));
	Effect *loop_body = SEQ2(mask_update, cnt_update);

	Effect *loop = REPEAT(loop_cond, loop_body);
	return SEQ3(reset_rd, mask, loop);
}

/**
 * Doubleword Divide (Signed)
 * Format: DDIV rs, rt
 *         DDIV rd, rs, rt
 * Description: (HI, LO) <- GPR[rs] / GPR[rt]
 *              GPR[rd] <- (divide.signed(GPR[rs], GPR[rt]))
 * Exceptions: None
 * */
IL_LIFTER(DDIV) {
	if (OPND_COUNT() == 2) {
		Pure *rs = IL_REG_OPND(0);
		Pure *rt = IL_REG_OPND(1);

		BitVector *quotient = SDIV(DUP(rs), DUP(rt));
		BitVector *remainder = SMOD(rs, rt);

		Effect *set_lo = SETG(REG_LO(), quotient);
		Effect *set_hi = SETG(REG_HI(), remainder);
		return SEQ2(set_lo, set_hi);
	} else {
		char *rd = REG_OPND(0);
		Pure *rs = IL_REG_OPND(1);
		Pure *rt = IL_REG_OPND(2);
		if (float_op) {
			return SETG(rd, FDIV(RMODE, rs, rt));
		} else {
			return SETG(rd, SDIV(rs, rt));
		}
	}
}

/**
 * Doubleword Divide (Unsigned)
 * Format: DDIVU rs, rt
 *         DDIVU rd, rs, rt
 * Description: (HI, LO) <- GPR[rs] / GPR[rt]
 *              GPR[rd] <- (divide.usigned(GPR[rs], GPR[rt]))
 * Exceptions: None
 * */
IL_LIFTER(DDIVU) {
	// NOTE: ISA divide operations are suspicuous
	if (OPND_COUNT() == 2) {
		Pure *rs = IL_REG_OPND(0);
		Pure *rt = IL_REG_OPND(1);

		BitVector *quotient = DIV(DUP(rs), DUP(rt));
		BitVector *remainder = MOD(rs, rt);

		Effect *set_lo = SETG(REG_LO(), quotient);
		Effect *set_hi = SETG(REG_HI(), remainder);
		return SEQ2(set_lo, set_hi);
	} else {
		char *rd = REG_OPND(0);
		Pure *rs = IL_REG_OPND(1);
		Pure *rt = IL_REG_OPND(2);

		BitVector *quotient = DIV(rs, rt);

		Effect *set_rd = SETG(rd, quotient);
		return set_rd;
	}
}

IL_LIFTER(DERET) {
	return NULL;
}

/**
 * Doubleword Extract bit Field
 * Format: DEXT rt, rs, pos, size
 * Description: GPR[rt] <- ExtractField(GPR[rs], msbd, lsb)
 * Exceptions: Reserved Instruction
 * */
IL_LIFTER(DEXT) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	ut8 pos = IMM_OPND(2) & 0x1F; // max value = 32 (5 bits)
	ut8 size = IMM_OPND(3) & 0x1F; // max value = 32 (5 bits)

	// create mask to take logical and and extract bit-field
	ut64 mask = SIGN_EXTEND(1, 1, size - 1) << pos;
	BitVector *bitfield = SHIFTR0(LOGAND(rs, U64(mask)), U8(pos));

	return SETG(rt, bitfield);
}

/**
 * Doubleword Extract bit Field Middle
 * Format: DEXTM rt, rs, pos, size
 * Description: GPR[rt] <- ExtractField(GPR[rs], msbd, lsb)
 * Exceptions: Reserved Instruction
 * */
IL_LIFTER(DEXTM) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	ut8 pos = IMM_OPND(2) & 0x1F; // max value = 32 (5 bits)
	ut8 size = (IMM_OPND(3) & 0x1F) + 32; // max value = 64 (5 bits + 32 imm)

	// create mask to take logical and and extract bit-field
	ut64 mask = SIGN_EXTEND(1, 1, size - 1) << pos;
	BitVector *bitfield = SHIFTR0(LOGAND(rs, U64(mask)), U8(pos));

	return SETG(rt, bitfield);
}

/**
 * Doubleword Extract bit Field Upper
 * Format: DEXTU rt, rs, pos, size
 * Description: GPR[rt] <- ExtractField(GPR[rs], msbd, lsb)
 * Exceptions: Reserved Instruction
 * */
IL_LIFTER(DEXTU) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	ut8 pos = (IMM_OPND(2) & 0x1F) + 32; // max value = 64 (5 bits + 32 imm)
	ut8 size = IMM_OPND(3) & 0x1F; // max value = 32 (5 bits)

	// create mask to take logical and and extract bit-field
	ut64 mask = SIGN_EXTEND(1, 1, size - 1) << pos;
	BitVector *bitfield = SHIFTR0(LOGAND(rs, U64(mask)), U8(pos));

	return SETG(rt, bitfield);
}

IL_LIFTER(DI) {
	return NULL;
}

/**
 * Doubleword Insert bit Field
 * Format: DINS rt, rs, pos, size
 * Description: GPR[rt] <- InsertField(GPR[rt], GPR[rs], msbd, lsb)
 * Exceptions: Reserved Instruction
 * */
IL_LIFTER(DINS) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	ut8 pos = IMM_OPND(2) & 0x1F; // max value = 32 (5 bits)
	ut8 size = IMM_OPND(3) & 0x1F; // max value = 32 (5 bits)

	// create mask to take logical and and extract bit-field
	ut64 mask = SIGN_EXTEND(1, 1, size - 1);

	// invert mask and take logical and to remove bitfield
	ut64 rt_mask = ~(mask << pos);
	BitVector *rt_bitfield_removed = LOGAND(VARG(rt), U64(rt_mask));

	// create new bitfield from rs and insert it into rt
	BitVector *rs_as_bitfield = SHIFTL0(LOGAND(rs, U64(mask)), U8(pos));
	BitVector *rt_inserted_rs = LOGOR(rt_bitfield_removed, rs_as_bitfield);

	return SETG(rt, rt_inserted_rs);
}

/**
 * Doubleword Insert bit Field Middle
 * Format: DINSM rt, rs, pos, size
 * Description: GPR[rt] <- InsertField(GPR[rt], GPR[rs], msbd, lsb)
 * Exceptions: Reserved Instruction
 * */
IL_LIFTER(DINSM) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	ut8 pos = IMM_OPND(2) & 0x1F; // max value = 32 (5 bits)
	ut8 size = (IMM_OPND(3) & 0x1F) + 32; // max value = 64 (5 bits + 32 imm)

	// create mask to take logical and and extract bit-field
	ut64 mask = SIGN_EXTEND(1, 1, size - 1);

	// invert mask and take logical and to remove bitfield
	ut64 rt_mask = ~(mask << pos);
	BitVector *rt_bitfield_removed = LOGAND(VARG(rt), U64(rt_mask));

	// create new bitfield from rs and insert it into rt
	BitVector *rs_as_bitfield = SHIFTL0(LOGAND(rs, U64(mask)), U8(pos));
	BitVector *rt_inserted_rs = LOGOR(rt_bitfield_removed, rs_as_bitfield);

	return SETG(rt, rt_inserted_rs);
}

/**
 * Doubleword Insert bit Field Upper
 * Format: DINSM rt, rs, pos, size
 * Description: GPR[rt] <- InsertField(GPR[rt], GPR[rs], msbd, lsb)
 * Exceptions: Reserved Instruction
 * */
IL_LIFTER(DINSU) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	ut8 pos = (IMM_OPND(2) & 0x1F) + 32; // max value = 64 (5 bits + 32 imm)
	ut8 size = IMM_OPND(3) & 0x1F; // max value = 32 (5 bits)

	// create mask to take logical and and extract bit-field
	ut64 mask = SIGN_EXTEND(1, 1, size - 1);

	// invert mask and take logical and to remove bitfield
	ut64 rt_mask = ~(mask << pos);
	BitVector *rt_bitfield_removed = LOGAND(VARG(rt), U64(rt_mask));

	// create new bitfield from rs and insert it into rt
	BitVector *rs_as_bitfield = SHIFTL0(LOGAND(rs, U64(mask)), U8(pos));
	BitVector *rt_inserted_rs = LOGOR(rt_bitfield_removed, rs_as_bitfield);

	return SETG(rt, rt_inserted_rs);
}

/**
 * Divide Word (Signed)
 * Format: DIV rs, rt
 *         DIV rd, rs, rt
 * Description: (HI, LO) <- GPR[rs] / GPR[rt]
 *              GPR[rd] <- (divide.signed(GPR[rs], GPR[rt]))
 * Exceptions: None
 * */
IL_LIFTER(DIV) {
	if (OPND_COUNT() == 2) {
		Pure *rs = IL_REG_OPND(0);
		Pure *rt = IL_REG_OPND(1);

		BitVector *quotient = SDIV(DUP(rs), DUP(rt));
		BitVector *remainder = SMOD(rs, rt);

		Effect *set_lo = SETG(REG_LO(), quotient);
		Effect *set_hi = SETG(REG_HI(), remainder);
		return SEQ2(set_lo, set_hi);
	} else {
		char *rd = REG_OPND(0);
		Pure *rs = IL_REG_OPND(1);
		Pure *rt = IL_REG_OPND(2);
		if (float_op) {
			return SETG(rd, FDIV(RMODE, rs, rt));
		} else {
			return SETG(rd, SDIV(rs, rt));
		}
	}
}

/**
 * Divide Word (Unsigned)
 * Format: DIVU rs, rt
 *         DIVU rd, rs, rt
 * Description: (HI, LO) <- GPR[rs] / GPR[rt]
 *              GPR[rd] <- (divide.usigned(GPR[rs], GPR[rt]))
 * Exceptions: None
 * */
IL_LIFTER(DIVU) {
	// NOTE: ISA divide operations are suspicuous
	if (OPND_COUNT() == 2) {
		Pure *rs = IL_REG_OPND(0);
		Pure *rt = IL_REG_OPND(1);

		BitVector *quotient = DIV(DUP(rs), DUP(rt));
		BitVector *remainder = MOD(rs, rt);

		Effect *set_lo = SETG(REG_LO(), quotient);
		Effect *set_hi = SETG(REG_HI(), remainder);
		return SEQ2(set_lo, set_hi);
	} else {
		char *rd = REG_OPND(0);
		Pure *rs = IL_REG_OPND(1);
		Pure *rt = IL_REG_OPND(2);

		BitVector *quotient = DIV(rs, rt);

		return SETG(rd, quotient);
	}
}

IL_LIFTER(DIV_S) {
	return NULL;
}
IL_LIFTER(DIV_U) {
	return NULL;
}

/**
 * Doubleword Load Scaled Address
 * Format: DLSA rd, rs, rt, sa
 * Description: GPR[rd] <- (GPR[rs] << (sa+1)) + GPR[rt]
 * Exceptions: LSA: None
 *             DLSA: ReservedInstruction if MIPS64 instruction set is not enabled
 * */
IL_LIFTER(DLSA) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);
	ut8 sa = (ut8)IMM_OPND(3);

	BitVector *scaled_rs = SHIFTL0(rs, U8(sa + 1));
	BitVector *scaled_address = ADD(scaled_rs, rt);

	return SETG(rd, scaled_address);
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

/**
 * Doubleword Modulo (Signed)
 * Format: DMOD rd, rs, rt
 * Description: GPR[rd] <- (modulo.signed(GPR[rs], GPR[rt]))
 * Exceptions: None
 * */
IL_LIFTER(DMOD) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *remainder = SMOD(rs, rt);
	return SETG(rd, remainder);
}

/**
 * Doubleword Modulo (Unigned)
 * Format: DMODU rd, rs, rt
 * Description: GPR[rd] <- (modulo.usigned(GPR[rs], GPR[rt]))
 * Exceptions: None
 * */
IL_LIFTER(DMODU) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *remainder = MOD(rs, rt);
	return SETG(rd, remainder);
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

/**
 * Multiply Signed Doubleword, High Word Signed
 * Format: DMULU rd, rs, rt
 * Description: GPR[rd] <- hi_dword(multiply.unsigned(GPR[rs] x GPR[rt]))
 * Exceptions: None
 * */
IL_LIFTER(DMUH) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *rs128 = SIGNED(128, rs);
	BitVector *rt128 = SIGNED(128, rt);
	BitVector *prod = MUL(rs128, rt128);

	BitVector *prod_hi = CAST(64, IL_FALSE, SHIFTR0(prod, U8(64)));

	return SETG(rd, prod_hi);
}

/**
 * Multiply Signed Doubleword, High Word Unsigned
 * Format: DMUHU rd, rs, rt
 * Description: GPR[rd] <- hi_dword(multiply.unsigned(GPR[rs] x GPR[rt]))
 * Exceptions: None
 * */
IL_LIFTER(DMUHU) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *rs128 = UNSIGNED(128, rs);
	BitVector *rt128 = UNSIGNED(128, rt);
	BitVector *prod = MUL(rs128, rt128);

	BitVector *prod_hi = CAST(64, IL_FALSE, SHIFTR0(prod, U8(64)));

	return SETG(rd, prod_hi);
}

/**
 * Multiply Signed Doubleword, Low Doubleword
 * Format: DMUL rd, rs, rt
 * Description: GPR[rd] <- lo_dword(multiply.signed(GPR[rs] x GPR[rt]))
 * Exceptions: None
 * */
IL_LIFTER(DMUL) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *rs128 = SIGNED(128, rs);
	BitVector *rt128 = SIGNED(128, rt);
	BitVector *prod = MUL(rs128, rt128);

	BitVector *prod_lo = CAST(64, IL_FALSE, prod);

	return SETG(rd, prod_lo);
}

/**
 * Doubleword Multiply
 * Format: DMULT rs, rt
 * Description: (LO, HI) <- GPR[rs] x GPR[rt]
 * Exceptions: Reserved Instruction
 * */
IL_LIFTER(DMULT) {
	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	// extend to 128 bit values
	BitVector *rs128 = SIGNED(128, rs);
	BitVector *rt128 = SIGNED(128, rt);

	// multiply two 128 bit values
	BitVector *prod = MUL(rs128, rt128);
	BitVector *prod_lo = CAST(64, IL_FALSE, DUP(prod));
	BitVector *prod_hi = CAST(64, IL_FALSE, SHIFTR0(prod, U8(64)));

	return SEQ2(SETG(REG_LO(), prod_lo), SETG(REG_LO(), prod_hi));
}

/**
 * Doubleword Multiply Unsigned
 * Format: DMULTU rs, rt
 * Description: (LO, HI) <- GPR[rs] x GPR[rt]
 * Exceptions: Reserved Instruction
 * */
IL_LIFTER(DMULTU) {
	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	// extend to 128 bit values
	BitVector *rs128 = UNSIGNED(128, rs);
	BitVector *rt128 = UNSIGNED(128, rt);

	// multiply two 128 bit values
	BitVector *prod = MUL(rs128, rt128);
	BitVector *prod_lo = CAST(64, IL_FALSE, DUP(prod));
	BitVector *prod_hi = CAST(64, IL_FALSE, SHIFTR0(prod, U8(64)));

	return SEQ2(SETG(REG_LO(), prod_lo), SETG(REG_LO(), prod_hi));
}

/**
 * Multiply Signed Doubleword, Low Doubleword Unsigned
 * Format: DMULU rd, rs, rt
 * Description: GPR[rd] <- lo_dword(multiply.unsigned(GPR[rs] x GPR[rt]))
 * Exceptions: None
 * */
IL_LIFTER(DMULU) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *rs128 = UNSIGNED(128, rs);
	BitVector *rt128 = UNSIGNED(128, rt);
	BitVector *prod = MUL(rs128, rt128);

	BitVector *prod_lo = CAST(64, IL_FALSE, prod);

	return SETG(rd, prod_lo);
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

/**
 * Doubleword Rotate Right
 * Format: ROTR rd, rt, sa
 * Description: GPR[rd] < GPR[rt] x(right) sa
 * Exceptions: Reserved Instruction
 * */
IL_LIFTER(DROTR) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	BitVector *sa = UN(5, IMM_OPND(2));

	BitVector *left = SHIFTL0(DUP(rt), SUB(U8(GPRLEN), DUP(sa)));
	BitVector *right = SHIFTR0(rt, sa);
	BitVector *rotr = LOGOR(left, right);

	return SETG(rd, rotr);
}

/**
 * Doubleword Rotate Right Plus 32
 * Format: DROTR32 rd, rt, sa
 * Description: GPR[rd] < GPR[rt] x(right) sa
 * Exceptions: Reserved Instruction
 * */
IL_LIFTER(DROTR32) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	BitVector *sa = UN(6, (IMM_OPND(2) & 0x1F) + 32);

	BitVector *left = SHIFTL0(DUP(rt), SUB(U8(GPRLEN), DUP(sa)));
	BitVector *right = SHIFTR0(rt, sa);
	BitVector *rotr = LOGOR(left, right);

	return SETG(rd, rotr);
}

/**
 * Doubleword Rotate Right Variable
 * Format: DROTRV rd, rt, rs
 * Description: GPR[rd] < GPR[rt] x(right) sa
 * Exceptions: Reserved Instruction
 * */
IL_LIFTER(DROTRV) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	Pure *rs = CAST(6, IL_FALSE, IL_REG_OPND(2));

	BitVector *left = SHIFTL0(DUP(rt), SUB(U8(GPRLEN), DUP(rs)));
	BitVector *right = SHIFTR0(rt, rs);
	BitVector *rotr = LOGOR(left, right);

	return SETG(rd, rotr);
}

/**
 * Doubleword Swap Bytes within Halfwords
 * Format: DSBH rd, rt
 * Description: GPR[rd] <- SwapBytesWithinHalfwords(GPR[rt])
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(DSBH) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	BitVector *byte0 = LOGAND(DUP(rt), U64(0xFF));
	BitVector *byte1 = SHIFTR0(LOGAND(DUP(rt), U64(0xFFUL << 8 * 1)), U8(8 * 1));
	BitVector *byte2 = SHIFTR0(LOGAND(DUP(rt), U64(0xFFUL << 8 * 2)), U8(8 * 2));
	BitVector *byte3 = SHIFTR0(LOGAND(DUP(rt), U64(0xFFUL << 8 * 3)), U8(8 * 3));
	BitVector *byte4 = SHIFTR0(LOGAND(DUP(rt), U64(0xFFUL << 8 * 4)), U8(8 * 4));
	BitVector *byte5 = SHIFTR0(LOGAND(DUP(rt), U64(0xFFUL << 8 * 5)), U8(8 * 5));
	BitVector *byte6 = SHIFTR0(LOGAND(DUP(rt), U64(0xFFUL << 8 * 6)), U8(8 * 6));
	BitVector *byte7 = SHIFTR0(LOGAND(rt, U64(0xFFUL << 8 * 7)), U8(8 * 7));

	// hword0 = byte0 | byte1 <-- swap here
	BitVector *hword0 = LOGOR(SHIFTL0(byte0, U8(8)), byte1);
	// hword1 = byte2 | byte3 <-- swap here
	BitVector *hword1 = LOGOR(SHIFTL0(byte2, U8(8)), byte3);
	// hword2 = byte4 | byte5 <-- swap here
	BitVector *hword2 = LOGOR(SHIFTL0(byte4, U8(8)), byte5);
	// hword3 = byte6 | byte7 <-- swap here
	BitVector *hword3 = LOGOR(SHIFTL0(byte6, U8(8)), byte7);

	// word0 = hword1 | hword0
	BitVector *word0 = LOGOR(SHIFTL0(hword1, U8(16)), hword0);
	// word1 = hword3 | hword2
	BitVector *word1 = LOGOR(SHIFTL0(hword3, U8(16)), hword2);

	// dword = word1 | word0
	BitVector *dword = LOGOR(word1, word0);

	return SETG(rd, dword);
}

/**
 * Doubleword Swap Halfwords within Doublewords
 * Format: DSHD rd, rt
 * Description: GPR[rd] <- SwapHalfwordsWithinDoublewords(GPR[rt])
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(DSHD) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	BitVector *hword0 = LOGAND(DUP(rt), U64(0xFFFFUL));
	BitVector *hword1 = SHIFTR0(LOGAND(DUP(rt), U64(0xFFFFUL << 16 * 1)), U8(16 * 1));
	BitVector *hword2 = SHIFTR0(LOGAND(DUP(rt), U64(0xFFFFUL << 16 * 2)), U8(16 * 2));
	BitVector *hword3 = SHIFTR0(LOGAND(DUP(rt), U64(0xFFFFUL << 16 * 3)), U8(16 * 3));

	// word0 = hword0 | hword1 <-- swap here
	BitVector *word0 = LOGOR(SHIFTL0(hword0, U8(16)), hword1);
	// word1 = hword2 | hword3 <-- swap here
	BitVector *word1 = LOGOR(SHIFTL0(hword2, U8(16)), hword3);

	// dword = word0 | word1 <-- swap here
	BitVector *dword = LOGOR(word0, word1);

	return SETG(rd, dword);
}

/**
 * Doubleword shift word Left Logical
 * Format: DSLL rd, rt, sa
 * Description: GPR[rd] <- GPR[rt] << sa
 * Exceptions: None
 * */
IL_LIFTER(DSLL) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	BitVector *sa = UN(5, IMM_OPND(2));

	BitVector *shifted_rt = SHIFTL0(rt, sa);
	Effect *set_rd = SETG(rd, shifted_rt);
	return set_rd;
}

/**
 * Doubleword shift word Left Logical (plus) 32
 * Format: DSLL32 rd, rt, sa
 * Description: GPR[rd] <- GPR[rt] << sa
 * Exceptions: None
 * */
IL_LIFTER(DSLL32) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	BitVector *sa = UN(6, (IMM_OPND(2) & 0x1F) + 32);

	BitVector *shifted_rt = SHIFTL0(rt, sa);
	Effect *set_rd = SETG(rd, shifted_rt);
	return set_rd;
}

/**
 * Doubleword Shift word Left Logical Variable
 * Format: DSLLV rd, rt, rs
 * Description: GPR[rd] <- GPR[rt] << GPR[rs]
 * Exceptions: None
 * */
IL_LIFTER(DSLLV) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	Pure *rs = IL_REG_OPND(2);

	BitVector *sa = LOGAND(rs, UN(GPRLEN, 0x3F));
	BitVector *shifted_rt = SHIFTL0(rt, sa);
	Effect *set_rd = SETG(rd, shifted_rt);
	return set_rd;
}

/**
 * Doubleword Shift Right Arithmetic
 * Format: DSRA rd, rt, sa
 * Description: GPR[rd] <- (GPR[rt])^s || GPR[rs]
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(DSRA) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	ut8 sa_val = IMM_OPND(2) & 0x1F;

	BitVector *sa = UN(5, sa_val);
	return SETG(rd, SHIFTRA(rt, sa));
}

/**
 * Doubleword Shift Right Arithmetic (plus) 32
 * Format: DSRA32 rd, rt, sa
 * Description: GPR[rd] <- (GPR[rt])^s || GPR[rs]
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(DSRA32) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	ut8 sa_val = (IMM_OPND(2) & 0x1F) + 32;

	BitVector *sa = UN(6, sa_val);
	return SETG(rd, SHIFTRA(rt, sa));
}

/**
 * Shift word Right Arithmetic Variable
 * Format: DSRAV rd, rt, rs
 * Description: GPR[rd] <- (GPR[rt])^s || GPR[rs]
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(DSRAV) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	Pure *rs = IL_REG_OPND(2);

	BitVector *sa = LOGAND(rs, U64(0x3F));
	return SETG(rd, SHIFTRA(rt, sa));
}

/**
 * Doubleword Shift word Right Logical
 * Format: SRL rd, rt, sa
 * Description: GPR[rd] <- GPR[rt] >> sa
 * Exceptions: None
 * */
IL_LIFTER(DSRL) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	BitVector *sa = UN(5, IMM_OPND(2));

	BitVector *shifted_rt = SHIFTR0(rt, sa);
	return SETG(rd, shifted_rt);
}

/**
 * Doubleword Shift word Right Logical (plus) 32
 * Format: DSRL32 rd, rt, sa
 * Description: GPR[rd] <- GPR[rt] >> sa
 * Exceptions: None
 * */
IL_LIFTER(DSRL32) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	BitVector *sa = UN(6, (IMM_OPND(2) & 0x1F) + 32);

	BitVector *shifted_rt = SHIFTR0(rt, sa);
	return SETG(rd, shifted_rt);
}

/**
 * Doubleword Shift word Right Logical Variable
 * Format: DSRLV rd, rt, rs
 * Description: GPR[rd] <- GPR[rt] >> GPR[rs]
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(DSRLV) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	Pure *rs = IL_REG_OPND(2);

	BitVector *sa = LOGAND(rs, U64(0x3F));
	BitVector *shifted_rt = SHIFTR0(rt, sa);
	return SETG(rd, shifted_rt);
}

/**
 * Doubleword Subtract
 * Format: DSUB rd, rs, rt
 * Description: GPR[rd] <- GPR[rs] - GPR[rt]
 * Exceptions: IntegerOverflow
 * */
IL_LIFTER(DSUB) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *diff = SUB(rs, rt);
	Effect *set_rd = SETG(rd, diff);
	Bool *overflow = IL_CHECK_OVERFLOW(DUP(diff), 64);

	return BRANCH(overflow, IL_CAUSE_OVERFLOW(), set_rd);
}

/**
 * Doubleword Subtract Unsigned
 * Format: DSUBU rd, rs, rt
 * Description: GPR[rd] <- GPR[rs] - GPR[rt]
 * Exceptions: None
 * */
IL_LIFTER(DSUBU) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *diff = SUB(rs, rt);
	return SETG(rd, diff);
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

/**
 * Extract bit Field
 * Format: EXT rt, rs, pos, size
 * Description: GPR[rt] <- ExtractField(GPR[rs], msbd, lsb)
 * Exceptions: Reserved Instruction
 * */
IL_LIFTER(EXT) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	ut8 pos = IMM_OPND(2) & 0x1F; // max value = 32 (5 bits)
	ut8 size = IMM_OPND(3) & 0x1F; // max value = 32 (5 bits)

	// create mask to take logical and and extract bit-field
	ut64 mask = SIGN_EXTEND(1, 1, size - 1) << pos;
	BitVector *bitfield = SHIFTR0(LOGAND(rs, U32(mask)), U8(pos));

	return SETG(rt, bitfield);
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

/**
 * ABS
 * Format: ABS.S fd, fs
 *         ABS.D fd, fs
 *         ABS.PS is removed in MIPS6 release
 * Description: FPR[fd] <- abs(FPR[fs])
 * Exceptions: Coprocessor Unusable, Reserved Instruction
 * */
IL_LIFTER(ABS) {
	char *fd = REG_OPND(0);
	Pure *fs = IL_REG_OPND(1);

	Float *fabs = FABS(fs);
	return SETG(fd, fabs);
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

/**
 * Move
 * It doesn't matter whether it's a floating point
 * instruction or a normal one, in both cases we can
 * just move.
 * */
IL_LIFTER(MOV) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);

	return SETG(rd, rs);
}

IL_LIFTER(FMSUB) {
	return NULL;
}
IL_LIFTER(FMUL) {
	return NULL;
}

/**
 * Multiply Signed Word, Low Word
 * Format: MUL rd, rs, rt
 *         MUL.fmt fd, fs, ft
 * Description: MUL: GPR[rd] <- lo_word(multiply.signed(GPR[rs] x GPR[rt]))
 *              MUL.fmt: FPR[fd] <- FPR[fs] x FPR[ft]
 * Exceptions: None
 * */
IL_LIFTER(MUL) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	if (float_op) {
		return SETG(rd, FMUL(RMODE, rs, rt));
	} else {
		BitVector *rs64 = SIGNED(64, rs);
		BitVector *rt64 = SIGNED(64, rt);
		BitVector *prod = MUL(rs64, rt64);

		BitVector *prod_lo = SIGNED(GPRLEN, CAST(32, IL_FALSE, prod));

		return SETG(rd, prod_lo);
	}
}

/**
 * floating point Negate
 * Format: NEG fd, fs
 * Description: FPR[fd] <- -FPR[fs]
 * Exceptions: Coprocessor Unusable, Reserved Instruction, Unimplemented Operation, Invalid Operation
 * */
IL_LIFTER(NEG) {
	char *fd = REG_OPND(0);
	Pure *fs = IL_REG_OPND(1);

	return SETG(fd, FNEG(fs));
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

/**
 * Subtract word
 * Format: SUB rd, rs, rt
 * Description: GPR[rd] <- GPR[rs] - GPR[rt]
 * Exceptions: IntegerOverflow
 * */
IL_LIFTER(SUB) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *diff = SUB(rs, rt);
	Effect *set_rd = SETG(rd, diff);
	Bool *overflow = IL_CHECK_OVERFLOW(DUP(diff), 32);

	return BRANCH(overflow, IL_CAUSE_OVERFLOW(), set_rd);
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

/**
 * Insert bit Field
 * Format: INS rt, rs, pos, size
 * Description: GPR[rt] <- InsertField(GPR[rt], GPR[rs], msbd, lsb)
 * Exceptions: Reserved Instruction
 * */
IL_LIFTER(INS) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	ut8 pos = IMM_OPND(2) & 0x1F; // max value = 32 (5 bits)
	ut8 size = IMM_OPND(3) & 0x1F; // max value = 32 (5 bits)

	// create mask to take logical and and extract bit-field
	ut64 mask = SIGN_EXTEND(1, 1, size - 1);

	// invert mask and take logical and to remove bitfield
	ut64 rt_mask = ~(mask << pos);
	BitVector *rt_bitfield_removed = LOGAND(VARG(rt), U32(rt_mask));

	// create new bitfield from rs and insert it into rt
	BitVector *rs_as_bitfield = SHIFTL0(LOGAND(rs, U32(mask)), UN(5, pos));
	BitVector *rt_inserted_rs = LOGOR(rt_bitfield_removed, rs_as_bitfield);

	return SETG(rt, rt_inserted_rs);
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

/**
 * Jump
 * Format: J target
 * Description: 256 MB PC "region" jump, not a "relative" one.
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(J) {
	ut64 instr_index = IMM_OPND(0) << 2; // 26 + 2 bits
	ut64 pc_mask = ~SIGN_EXTEND(1, 1, 28); // lower 28 bits are 0
	ut64 new_pc = (pc & pc_mask) | instr_index;

	BitVector *jump_target = UN(GPRLEN, new_pc);

	return JMP(jump_target);
}

/**
 * Jump And Link
 * Format: JAL target
 * Description: Link to R31 and make a 256 MB PC "region" jump, not a "relative" one.
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(JAL) {
	ut64 instr_index = IMM_OPND(0) << 2; // 26 + 2 bits
	ut64 pc_mask = ~SIGN_EXTEND(1, 1, 28); // lower 28 bits are 0
	ut64 new_pc = (pc & pc_mask) | instr_index;

	BitVector *jump_target = UN(GPRLEN, new_pc);

	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 8));
	Effect *jmp_op = JMP(jump_target);
	return SEQ2(link_op, jmp_op);
}

/**
 * Jump And Link Register
 * Format: JALR rs (rd = 31)
 *         JALR rd, rs
 * Description: Link to rd and jump to rs (basically a procedure call)
 * Exceptions: ReservedInstruction
 *
 * NOTE: Confirm this later, there's difference in management
 *       of jump between devices that support microMIPS & MIPS16
 *       and devices that don't
 *       FOR NOW I ASSUME THE EMULATED DEVICE DOESN'T SUPPORT THOSE
 * TODO: Handle the "else" case in microMIPS uplifting phase!
 * */
IL_LIFTER(JALR) {
	char *rd = NULL;
	Pure *rs = NULL;
	if (OPND_COUNT() == 1) {
		rd = REG_R(31);
		rs = IL_REG_OPND(0);
	} else {
		rd = REG_OPND(0);
		rs = IL_REG_OPND(1);
	}

	Pure *jump_target = rs;

	Effect *link_op = SETG(rd, UN(GPRLEN, pc + 8));
	Effect *jmp_op = JMP(jump_target);
	return SEQ2(link_op, jmp_op);
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

/**
 * Jump And Link Exchange
 * Format: JALX target
 * Description: Link to r31 and jump to rs (basically a procedure call)
 * Exceptions: ReservedInstruction
 *
 * NOTE: See "JALR" note
 * TODO: Handle "else" case
 * */
IL_LIFTER(JALX) {
	ut64 instr_index = IMM_OPND(0) << 2;

	ut64 pc_mask = ~SIGN_EXTEND(1, 1, 28); // lower 28 bits are 0
	ut64 new_pc = (pc & pc_mask) | instr_index;
	BitVector *jump_target = UN(GPRLEN, new_pc);

	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 8));
	Effect *jmp_op = JMP(jump_target);
	return SEQ2(link_op, jmp_op);
}

/**
 * Jump Indexed And Link Compact
 * Format: JIALC rt, offset
 * Description: GPR[31] <- PC+4, PC <- (GPR[rt] + sign_extend(offset))
 * Exceptions: ReservedInstruction
 *
 * NOTE: See "JALR" note
 * TODO: Handle "else" case
 * */
IL_LIFTER(JIALC) {
	Pure *rt = IL_REG_OPND(0);
	st64 offset = SIGN_EXTEND(IMM_OPND(1), 16, GPRLEN);

	Effect *link_op = SETG(REG_R(31), UN(GPRLEN, pc + 4));
	BitVector *jump_target = ADD(rt, SN(GPRLEN, offset));
	Effect *jmp_op = JMP(jump_target);

	return SEQ2(link_op, jmp_op);
}

/**
 * Jump Indexed Compact
 * Format: JIC rt, offset
 * Description: PC <- (GPR[rt] + sign_extend(offset))
 * Exceptions: ReservedInstruction
 *
 * NOTE: See "JALR" note
 * TODO: Handle "else" case
 * */
IL_LIFTER(JIC) {
	Pure *rs = IL_REG_OPND(0);
	st64 offset = SIGN_EXTEND(IMM_OPND(1), 16, GPRLEN);

	BitVector *jump_target = ADD(rs, SN(GPRLEN, offset));
	return JMP(jump_target);
}

/**
 * Jump Register
 * Format: JR rs
 * Description: PC <- GPR[rs]
 * Exceptions: ReservedInstruction
 *
 * NOTE: See "JALR" note
 * TODO: Handle "else" case
 * */
IL_LIFTER(JR) {
	Pure *jump_target = IL_REG_OPND(0);
	return JMP(jump_target);
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

/**
 * Load Byte
 * Format: LB rt, offset(base)
 * Description: GPR[rt] <- memory[GPR[base] + offset]
 * Exceptions: TLB Refill, TLB Invalid, Address Error, Watch
 * */
IL_LIFTER(LB) {
	char *rt = REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	BitVector *byte = LOADW(8, memaddr);
	BitVector *sign_extended_byte = SIGNED(GPRLEN, byte);

	return SETG(rt, sign_extended_byte);
}

// MISSING: LBE

IL_LIFTER(LBU16) {
	return NULL;
}

IL_LIFTER(LBUX) {
	return NULL;
}

/**
 * Load Byte Unsigned
 * Format: LBU rt, offset(base)
 * Description: GPR[rt] <- memory[GPR[base] + offset]
 * Exceptions: TLB Refill, TLB Invalid, Address Error, Watch
 * */
IL_LIFTER(LBU) {
	char *rt = REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	BitVector *byte = LOADW(8, memaddr);
	BitVector *zero_extended_byte = UNSIGNED(GPRLEN, byte);

	return SETG(rt, zero_extended_byte);
}

// MISSING: LBUE

/**
 * Load Doubleword
 * Format: LD rt, offset(base)
 * Description: GPR[rt] <- memory[GPR[base] + offset]
 * Exceptions: TLB Refill, TLB Invalid, Address Error, Watch
 * */
IL_LIFTER(LD) {
	char *rt = REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	BitVector *byte = LOADW(64, memaddr);

	return SETG(rt, byte);
}

/**
 * Load Doubleword To Floating Point
 * Format: LDC1 ft, offset(base)
 * Description: GPR[rt] <- memory[GPR[base] + offset]
 * Exceptions: TLB Refill, TLB Invalid, Address Error, Watch
 * */
IL_LIFTER(LDC1) {
	char *ft = REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	BitVector *byte = LOADW(64, memaddr); // <-- LOAD 64 bits

	return SETG(ft, byte); // <-- UNINTERPRETED STORE
}

/**
 * TODO: HOW CAN WE DIFFERENTIATE BETWEEN REGISTERS OF CP1 & CP2
 * */
IL_LIFTER(LDC2) {
	return NULL;
}

/**
 * TODO: HOW CAN WE DIFFERENTIATE BETWEEN REGISTERS OF CP1 & CP3
 * */
IL_LIFTER(LDC3) {
	return NULL;
}
IL_LIFTER(LDI) {
	return NULL;
}

/**
 * Load Word Left
 * Format: LDL rt, offset(base)
 * Description: GPR[rt] <- GPR[rt] MERGE memory[GPR[base] + offset]
 * Exceptions: None
 * */
IL_LIFTER(LDL) {
	char *rt = REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	BitVector *memaddr_low3bit = CAST(3, IL_FALSE, DUP(memaddr));
	BitVector *aligned_memaddr = LOGAND(memaddr, U64(~0x7)); // last 3 bits set to 0
	BitVector *dword = LOADW(64, aligned_memaddr);

	Effect *b0, *b1, *b2, *b3, *b4, *b5, *b6, *b7;
	if (analysis->big_endian) {
		b7 = SETG(rt, LOGOR(LOGAND(dword, U64(0xFF00000000000000)), LOGAND(VARG(rt), U64(0x00FFFFFFFFFFFFFF))));

		Bool *b6cond = EQ(DUP(memaddr_low3bit), UN(3, 6));
		b6 = BRANCH(b6cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFF000000000000)), LOGAND(VARG(rt), U64(0x0000FFFFFFFFFFFF)))), b7);

		Bool *b5cond = EQ(DUP(memaddr_low3bit), UN(3, 5));
		b5 = BRANCH(b5cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFFFF0000000000)), LOGAND(VARG(rt), U64(0x000000FFFFFFFFFF)))), b6);

		Bool *b4cond = EQ(DUP(memaddr_low3bit), UN(3, 4));
		b4 = BRANCH(b4cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFFFFFF00000000)), LOGAND(VARG(rt), U64(0x00000000FFFFFFFF)))), b5);

		Bool *b3cond = EQ(DUP(memaddr_low3bit), UN(3, 3));
		b3 = BRANCH(b3cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFFFFFFFF000000)), LOGAND(VARG(rt), U64(0x0000000000FFFFFF)))), b4);

		Bool *b2cond = EQ(DUP(memaddr_low3bit), UN(3, 2));
		b2 = BRANCH(b2cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFFFFFFFFFF0000)), LOGAND(VARG(rt), U64(0x000000000000FFFF)))), b3);

		Bool *b1cond = EQ(DUP(memaddr_low3bit), UN(3, 1));
		b1 = BRANCH(b1cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFFFFFFFFFFFF00)), LOGAND(VARG(rt), U64(0x00000000000000FF)))), b2);

		Bool *b0cond = EQ(memaddr_low3bit, UN(3, 0));
		b0 = BRANCH(b0cond, SETG(rt, dword), b1);
	} else {
		b7 = SETG(rt, dword);

		Bool *b6cond = EQ(DUP(memaddr_low3bit), UN(3, 6));
		b6 = BRANCH(b6cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFFFFFFFFFFFF00)), LOGAND(VARG(rt), U64(0x00000000000000FF)))), b7);

		Bool *b5cond = EQ(DUP(memaddr_low3bit), UN(3, 5));
		b5 = BRANCH(b5cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFFFFFFFFFF0000)), LOGAND(VARG(rt), U64(0x000000000000FFFF)))), b6);

		Bool *b4cond = EQ(DUP(memaddr_low3bit), UN(3, 4));
		b4 = BRANCH(b4cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFFFFFFFF000000)), LOGAND(VARG(rt), U64(0x0000000000FFFFFF)))), b5);

		Bool *b3cond = EQ(DUP(memaddr_low3bit), UN(3, 3));
		b3 = BRANCH(b3cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFFFFFF00000000)), LOGAND(VARG(rt), U64(0x00000000FFFFFFFF)))), b4);

		Bool *b2cond = EQ(DUP(memaddr_low3bit), UN(3, 2));
		b2 = BRANCH(b2cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFFFF0000000000)), LOGAND(VARG(rt), U64(0x000000FFFFFFFFFF)))), b3);

		Bool *b1cond = EQ(DUP(memaddr_low3bit), UN(3, 1));
		b1 = BRANCH(b1cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFF000000000000)), LOGAND(VARG(rt), U64(0x0000FFFFFFFFFFFF)))), b2);

		Bool *b0cond = EQ(memaddr_low3bit, UN(3, 0));
		b0 = BRANCH(b0cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFF00000000000000)), LOGAND(VARG(rt), U64(0x00FFFFFFFFFFFFFF)))), b1);
	}

	return SEQ8(b0, b1, b2, b3, b4, b5, b6, b7);
}

/**
 * Load Doubleword PC relative
 * Format: LDPC rs, offset
 * Description: GPR[rt] <- memory[GPR[base] + offset)
 * Exceptions; TLB Refill, TLB Invalid, Bus Error, Address Error, Watch
 * */
IL_LIFTER(LDPC) {
	char *rs = REG_OPND(0);
	BitVector *base = LOGAND(IL_REG_PC(), U64(~0x7)); // align to 8 byte memory boundary
	st64 offset = SIGN_EXTEND(IMM_OPND(1) << 3, 21, 64);

	BitVector *memaddr = ADD(base, S64(offset));
	BitVector *dword = LOADW(64, memaddr);

	return SETG(rs, dword);
}

/**
 * Load Word Left
 * Format: LDR rt, offset(base)
 * Description: GPR[rt] <- GPR[rt] MERGE memory[GPR[base] + offset]
 * Exceptions: None
 * */
IL_LIFTER(LDR) {
	char *rt = REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	BitVector *memaddr_low3bit = CAST(3, IL_FALSE, DUP(memaddr)); // low 3 bits of memaddr
	BitVector *aligned_memaddr = LOGAND(memaddr, U64(~0x7)); // align to 8 byte memory boundary
	BitVector *dword = LOADW(64, aligned_memaddr);

	Effect *b0, *b1, *b2, *b3, *b4, *b5, *b6, *b7;
	if (analysis->big_endian) {
		b7 = SETG(rt, dword);

		Bool *b6cond = EQ(DUP(memaddr_low3bit), UN(3, 6));
		b6 = BRANCH(b6cond, SETG(rt, LOGOR(LOGAND(dword, U64(~0xFF00000000000000)), LOGAND(VARG(rt), U64(~0x00FFFFFFFFFFFFFF)))), b7);

		Bool *b5cond = EQ(DUP(memaddr_low3bit), UN(3, 5));
		b5 = BRANCH(b5cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(~0xFFFF000000000000)), LOGAND(VARG(rt), U64(~0x0000FFFFFFFFFFFF)))), b6);

		Bool *b4cond = EQ(DUP(memaddr_low3bit), UN(3, 4));
		b4 = BRANCH(b4cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(~0xFFFFFF0000000000)), LOGAND(VARG(rt), U64(~0x000000FFFFFFFFFF)))), b5);

		Bool *b3cond = EQ(DUP(memaddr_low3bit), UN(3, 3));
		b3 = BRANCH(b3cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(~0xFFFFFFFF00000000)), LOGAND(VARG(rt), U64(~0x00000000FFFFFFFF)))), b4);

		Bool *b2cond = EQ(DUP(memaddr_low3bit), UN(3, 2));
		b2 = BRANCH(b2cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(~0xFFFFFFFFFF000000)), LOGAND(VARG(rt), U64(~0x0000000000FFFFFF)))), b3);

		Bool *b1cond = EQ(DUP(memaddr_low3bit), UN(3, 1));
		b1 = BRANCH(b1cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(~0xFFFFFFFFFFFF0000)), LOGAND(VARG(rt), U64(~0x000000000000FFFF)))), b2);

		Bool *b0cond = EQ(DUP(memaddr_low3bit), UN(3, 0));
		b0 = BRANCH(b0cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(~0xFFFFFFFFFFFFFF00)), LOGAND(VARG(rt), U64(~0x00000000000000FF)))), b1);
	} else {
		b7 = SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFFFFFFFFFFFF00)), LOGAND(VARG(rt), U64(0x00000000000000FF))));

		Bool *b6cond = EQ(DUP(memaddr_low3bit), UN(3, 6));
		b6 = BRANCH(b6cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFFFFFFFFFF0000)), LOGAND(VARG(rt), U64(0x000000000000FFFF)))), b7);

		Bool *b5cond = EQ(DUP(memaddr_low3bit), UN(3, 5));
		b5 = BRANCH(b5cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFFFFFFFF000000)), LOGAND(VARG(rt), U64(0x0000000000FFFFFF)))), b6);

		Bool *b4cond = EQ(DUP(memaddr_low3bit), UN(3, 4));
		b4 = BRANCH(b4cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFFFFFF00000000)), LOGAND(VARG(rt), U64(0x00000000FFFFFFFF)))), b5);

		Bool *b3cond = EQ(DUP(memaddr_low3bit), UN(3, 3));
		b3 = BRANCH(b3cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFFFF0000000000)), LOGAND(VARG(rt), U64(0x000000FFFFFFFFFF)))), b4);

		Bool *b2cond = EQ(DUP(memaddr_low3bit), UN(3, 2));
		b2 = BRANCH(b2cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFFFF000000000000)), LOGAND(VARG(rt), U64(0x0000FFFFFFFFFFFF)))), b3);

		Bool *b1cond = EQ(DUP(memaddr_low3bit), UN(3, 1));
		b1 = BRANCH(b1cond, SETG(rt, LOGOR(LOGAND(DUP(dword), U64(0xFF00000000000000)), LOGAND(VARG(rt), U64(0x00FFFFFFFFFFFFFF)))), b2);

		Bool *b0cond = EQ(memaddr_low3bit, UN(3, 0));
		b0 = BRANCH(b0cond, SETG(rt, dword), b1);
	}

	return SEQ8(b0, b1, b2, b3, b4, b5, b6, b7);
}

/**
 * Load Doubleword Index to floating point
 * Format: LDXC1 fd, index(base)
 * Description: FPR[fd] <- memory[GPR[base] + GPR[index]]
 * Exceptions: TLB Refill, TLB Invalid, Address Error, Reserved Instruction, Coprocessor Unusable, Watch
 * */
IL_LIFTER(LDXC1) {
	char *fd = REG_OPND(0);
	Pure *index = IL_REG_OPND(1);
	Pure *base = IL_REG_OPND(2);

	BitVector *vaddr = ADD(base, index);
	BitVector *vaddr_low3bit = CAST(3, IL_FALSE, DUP(vaddr));
	Bool *address_load_error_cond = INV(IS_ZERO(vaddr_low3bit));

	BitVector *dword = LOADW(64, vaddr);

	return BRANCH(address_load_error_cond, SETG(fd, dword), IL_CAUSE_ADDRESS_LOAD_ERROR());
}

/**
 * Load Halfword
 * Format: LH rt, offset(base)
 * Description: GPR[rt] <- memory[GPR[base] + offset]
 * Exceptions: TLB Refill, TLB Invalid, Address Error, Watch
 * */
IL_LIFTER(LH) {
	char *rt = REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	BitVector *halfword = LOADW(16, memaddr);
	BitVector *sign_extended_halfword = SIGNED(GPRLEN, halfword);

	return SETG(rt, sign_extended_halfword);
}

// MISSING: LHE

IL_LIFTER(LHU16) {
	return NULL;
}
IL_LIFTER(LHX) {
	return NULL;
}

/**
 * Load Halfword Unsigned
 * Format: LHU rt, offset(base)
 * Description: GPR[rt] <- memory[GPR[base] + offset]
 * Exceptions: TLB Refill, TLB Invalid, Address Error, Watch
 * */
IL_LIFTER(LHU) {
	char *rt = REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	BitVector *halfword = LOADW(16, memaddr);
	BitVector *zero_extended_halfword = UNSIGNED(GPRLEN, halfword);

	return SETG(rt, zero_extended_halfword);
}

// MISSING: LHUE

IL_LIFTER(LI16) {
	return NULL;
}

/**
 * Load Linked Word
 * Format: LL rt, offset(base)
 * Description: GPR[rt] <- memory[GPR[base] + offset]
 * Exceptions: TLB Refill, TLB Invalid, Address Error, Watch
 * */
IL_LIFTER(LL) {
	char *rt = REG_OPND(0);
	// NOTE: size of offset relase 6 is different
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *vaddr = ADD(base, offset);
	BitVector *vaddr_low2bit = CAST(2, IL_FALSE, DUP(vaddr));
	Bool *address_error_cond = INV(IS_ZERO(vaddr_low2bit));

	BitVector *word = LOADW(32, vaddr);

	return BRANCH(address_error_cond, SETG(rt, word), IL_CAUSE_ADDRESS_LOAD_ERROR());
}

// MISSING: LLE
// MISSING: LLWP
// MISSING: LLWPE
// MISSING: LLDP

/**
 * Load Linked Doubleword
 * Format: LLD rt, offset(base)
 * Description: GPR[rt] <- memory[GPR[base] + offset]
 * Exceptions: TLB Refill, TLB Invalid, Address Error, Watch
 * */
IL_LIFTER(LLD) {
	char *rt = REG_OPND(0);
	// NOTE: size of offset relase 6 is different
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *vaddr = ADD(base, offset);
	BitVector *vaddr_low2bit = CAST(2, IL_FALSE, DUP(vaddr));
	Bool *address_error_cond = INV(IS_ZERO(vaddr_low2bit));

	BitVector *word = LOADW(64, vaddr);

	return BRANCH(address_error_cond, SETG(rt, word), IL_CAUSE_ADDRESS_LOAD_ERROR());
}

/**
 * Load Scaled Address
 * Format: LSA rd, rs, rt, sa
 * Description: GPR[rd] <- sign_extend.32((GPR[rs] << (sa+1)) + GPR[rt])
 * Exceptions: None
 * NOTE: Sign extend here?
 * */
IL_LIFTER(LSA) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);
	ut8 sa = (ut8)IMM_OPND(3);

	BitVector *scaled_rs = SHIFTL0(rs, U8(sa + 1));
	BitVector *scaled_address = ADD(scaled_rs, rt);

	return SETG(rd, scaled_address);
}

/**
 * Load Doubleword Indexed Unaligned to floating point
 * Format: LUXC1 fd, index(base)
 * Description: FPR[fd] <- memory[GPR[base] + GPR[index]]
 * Exceptions: TLB Refill, TLB Invalid, Address Error, Reserved Instruction, Coprocessor Unusable, Watch
 * */
IL_LIFTER(LUXC1) {
	char *fd = REG_OPND(0);
	Pure *index = IL_REG_OPND(1);
	Pure *base = IL_REG_OPND(2);

	BitVector *vaddr = LOGAND(ADD(base, index), U64(~0x7)); // forcefully align to 8 byte boundary
	BitVector *dword = LOADW(64, vaddr);

	return SETG(fd, dword);
}

/**
 * Load Upper Immediate
 * Format: LUI rt, immediate
 * Description: GPR[rt] <- immediate << 16
 * Exceptions: None
 * */
IL_LIFTER(LUI) {
	char *rt = REG_OPND(0);
	st32 imm = SIGN_EXTEND((st32)IMM_OPND(1) << 16, 32, GPRLEN);

	return SETG(rt, SN(GPRLEN, imm));
}

/**
 * Load Word
 * Format: LW rt, offset(base)
 * Description: GPR[rt] <- memory[GPR[base] + offset)
 * Exceptions; TLB Refill, TLB Invalid, Bus Error, Address Error, Watch
 * NOTE: Sign extend here?
 * */
IL_LIFTER(LW) {
	char *rt = REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	BitVector *word = SIGNED(GPRLEN, LOADW(32, memaddr));

	return SETG(rt, word);
}

// MISSING : LWE

IL_LIFTER(LW16) {
	return NULL;
}

/**
 * Load Word to floating point
 * Format: LDC1 ft, offset(base)
 * Description: FPR[ft] <- memory[GPR[base] + offset]
 * Exceptions: TLB Refill, TLB Invalid, Address Error, Reserved Instruction, Coprocessor Unusable, Watch
 * */
IL_LIFTER(LWC1) {
	char *ft = REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	BitVector *word = LOADW(32, memaddr);

	return SETG(ft, word);
}

IL_LIFTER(LWC2) {
	return NULL;
}
IL_LIFTER(LWC3) {
	return NULL;
}

/**
 * Load Word Left
 * Format: LWL rt, offset(base)
 * Description: GPR[rt] <- GPR[rt] MERGE memory[GPR[base] + offset]
 * Exceptions: None
 * */
IL_LIFTER(LWL) {
	char *rt = REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	BitVector *memaddr_low2bit = CAST(2, IL_FALSE, DUP(memaddr)); // lower 2 bits
	BitVector *aligned_memaddr = LOGAND(memaddr, UN(GPRLEN, ~0x3)); // lower two bits flagged as 0
	BitVector *word = SIGNED(GPRLEN, (LOADW(32, aligned_memaddr))); // load 32 bit data

	Effect *b0, *b1, *b2, *b3;
	if (analysis->big_endian) {
		b3 = SETG(rt, LOGOR(LOGAND(word, UN(GPRLEN, 0xFF000000)), LOGAND(VARG(rt), UN(GPRLEN, 0x00FFFFFF))));

		Bool *b2cond = EQ(DUP(memaddr_low2bit), UN(2, 2));
		b2 = BRANCH(b2cond, SETG(rt, LOGOR(LOGAND(DUP(word), UN(GPRLEN, 0xFFFF0000)), LOGAND(VARG(rt), UN(GPRLEN, 0x0000FFFF)))), b3);

		Bool *b1cond = EQ(DUP(memaddr_low2bit), UN(2, 1));
		b1 = BRANCH(b1cond, SETG(rt, LOGOR(LOGAND(DUP(word), UN(GPRLEN, 0xFFFFFF00)), LOGAND(VARG(rt), UN(GPRLEN, 0x000000FF)))), b2);

		Bool *b0cond = EQ(memaddr_low2bit, UN(2, 0));
		b0 = BRANCH(b0cond, SETG(rt, DUP(word)), b1);
	} else {
		b3 = SETG(rt, word);

		Bool *b2cond = EQ(DUP(memaddr_low2bit), UN(2, 2));
		b2 = BRANCH(b2cond, SETG(rt, LOGOR(LOGAND(DUP(word), UN(GPRLEN, 0xFFFFFF00)), LOGAND(VARG(rt), UN(GPRLEN, 0x000000FF)))), b3);

		Bool *b1cond = EQ(DUP(memaddr_low2bit), UN(2, 1));
		b1 = BRANCH(b1cond, SETG(rt, LOGOR(LOGAND(DUP(word), UN(GPRLEN, 0xFFFF0000)), LOGAND(VARG(rt), UN(GPRLEN, 0x0000FFFF)))), b2);

		Bool *b0cond = EQ(memaddr_low2bit, UN(2, 0));
		b0 = BRANCH(b0cond, SETG(rt, LOGOR(LOGAND(DUP(word), UN(GPRLEN, 0xFF000000)), LOGAND(VARG(rt), UN(GPRLEN, 0x00FFFFFF)))), b1);
	}

	return SEQ4(b0, b1, b2, b3);
}

IL_LIFTER(LWM16) {
	return NULL;
}
IL_LIFTER(LWM32) {
	return NULL;
}

/**
 * Load Word PC relative
 * Format: LWPC rs, offset
 * Description: GPR[rt] <- memory[GPR[base] + offset)
 * Exceptions; TLB Refill, TLB Invalid, Bus Error, Address Error, Watch
 * */
IL_LIFTER(LWPC) {
	char *rs = REG_OPND(0);
	BitVector *base = LOGAND(IL_REG_PC(), U32(~0x3)); // align to 4 byte memory boundary
	st64 offset = SIGN_EXTEND(IMM_OPND(1) << 2, 20, GPRLEN);

	BitVector *memaddr = ADD(base, SN(GPRLEN, offset));
	BitVector *word = SIGNED(GPRLEN, LOADW(32, memaddr));

	return SETG(rs, word);
}

IL_LIFTER(LWP) {
	return NULL;
}

/**
 * Load Word Right
 * Format: LWR rt, offset(base)
 * Description: GPR[rt] <- GPR[rt] MERGE memory[GPR[base] + offset]
 * Exceptions: None
 * */
IL_LIFTER(LWR) {
	char *rt = REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	BitVector *memaddr_low2bit = CAST(2, IL_FALSE, DUP(memaddr)); // lower two bits of memaddr
	BitVector *aligned_memaddr = LOGAND(memaddr, UN(GPRLEN, ~0x3)); // lower two bits of memaddr flagged to 0
	BitVector *word = SIGNED(GPRLEN, LOADW(32, aligned_memaddr));

	Effect *b0, *b1, *b2, *b3;
	if (analysis->big_endian) {
		b3 = SETG(rt, word);

		Bool *b2cond = EQ(DUP(memaddr_low2bit), UN(2, 2));
		b2 = BRANCH(b2cond, SETG(rt, LOGOR(LOGAND(DUP(word), UN(GPRLEN, 0x00FFFFFF)), LOGAND(VARG(rt), UN(GPRLEN, 0xFF000000)))), b3);

		Bool *b1cond = EQ(DUP(memaddr_low2bit), UN(2, 1));
		b1 = BRANCH(b1cond, SETG(rt, LOGOR(LOGAND(DUP(word), UN(GPRLEN, 0x0000FFFF)), LOGAND(VARG(rt), UN(GPRLEN, 0xFFFF0000)))), b2);

		Bool *b0cond = EQ(memaddr_low2bit, UN(2, 0));
		b0 = BRANCH(b0cond, SETG(rt, LOGOR(LOGAND(DUP(word), UN(GPRLEN, 0x000000FF)), LOGAND(VARG(rt), UN(GPRLEN, 0xFFFFFF00)))), b1);
	} else {
		b3 = SETG(rt, LOGOR(LOGAND(word, UN(GPRLEN, 0x000000FF)), LOGAND(VARG(rt), UN(GPRLEN, 0xFFFFFF00))));

		Bool *b2cond = EQ(DUP(memaddr_low2bit), UN(2, 2));
		b2 = BRANCH(b2cond, SETG(rt, LOGAND(LOGOR(DUP(word), UN(GPRLEN, 0x0000FFFF)), LOGAND(VARG(rt), UN(GPRLEN, 0xFFFF0000)))), b3);

		Bool *b1cond = EQ(DUP(memaddr_low2bit), UN(2, 1));
		b1 = BRANCH(b1cond, SETG(rt, LOGOR(LOGAND(DUP(word), UN(GPRLEN, 0x00FFFFFF)), LOGAND(VARG(rt), UN(GPRLEN, 0xFF000000)))), b2);

		Bool *b0cond = EQ(memaddr_low2bit, UN(2, 0));
		b0 = BRANCH(b0cond, SETG(rt, DUP(word)), b1);
	}

	return SEQ4(b0, b1, b2, b3);
}

/**
 * Load Word Unsigned PC relative
 * Format: LWPC rs, offset
 * Description: GPR[rt] <- memory[GPR[base] + offset)
 * Exceptions; TLB Refill, TLB Invalid, Bus Error, Address Error, Watch
 * */
IL_LIFTER(LWUPC) {
	char *rs = REG_OPND(0);
	BitVector *base = LOGAND(IL_REG_PC(), U32(~0x3)); // align to 4 byte memory boundary
	st64 offset = SIGN_EXTEND(IMM_OPND(1) << 2, 20, GPRLEN);

	BitVector *memaddr = ADD(base, SN(GPRLEN, offset));
	BitVector *word = UNSIGNED(GPRLEN, LOADW(32, memaddr));

	return SETG(rs, word);
}

/**
 * Load Word Unsigned
 * Format: LWU rt, offset(base)
 * Description: GPR[rt] <- memory[GPR[base] + offset]
 * Exceptions; TLB Refill, TLB Invalid, Bus Error, Address Error, Watch
 * */
IL_LIFTER(LWU) {
	char *rt = REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	BitVector *word = UNSIGNED(GPRLEN, LOADW(32, memaddr));

	return SETG(rt, word);
}

IL_LIFTER(LWX) {
	return NULL;
}

/**
 * Load Word Index to floating point
 * Format: LWXC1 fd, index(base)
 * Description: FPR[fd] <- memory[GPR[base] + GPR[index]]
 * Exceptions: TLB Refill, TLB Invalid, Address Error, Reserved Instruction, Coprocessor Unusable, Watch
 * */
IL_LIFTER(LWXC1) {
	char *fd = REG_OPND(0);
	Pure *index = IL_REG_OPND(1);
	Pure *base = IL_REG_OPND(2);

	BitVector *vaddr = ADD(base, index);
	BitVector *vaddr_low3bit = CAST(3, IL_FALSE, DUP(vaddr));
	Bool *address_load_error_cond = INV(IS_ZERO(vaddr_low3bit));

	BitVector *dword = LOADW(32, vaddr);

	return BRANCH(address_load_error_cond, SETG(fd, dword), IL_CAUSE_ADDRESS_LOAD_ERROR());
}

IL_LIFTER(LWXS) {
	return NULL;
}

IL_LIFTER(LI) {
	return NULL;
}

/**
 * Multiply and Add signed word to HI, LO
 * Format: MADD rs, rt
 *         MADD.fmt fd, fr, fs, ft
 * Description: MADD : (HI, LO) <- (HI, LO) + GPR[rs] x GPR[rt]
 *              MADD.fmt : fd = fs * ft + fr
 * Exceptions: None
 * */
IL_LIFTER(MADD) {
	if (float_op) {
		char *fd = REG_OPND(0);
		Pure *fr = IL_REG_OPND(1);
		Pure *fs = IL_REG_OPND(2);
		Pure *ft = IL_REG_OPND(3);

		// will do madd = fs * ft + fr
		Float *madd = FMAD(RMODE, fs, ft, fr);

		return SETG(fd, madd);
	} else {
		char *hi = REG_HI();
		char *lo = REG_LO();
		Pure *rs = IL_REG_OPND(0);
		Pure *rt = IL_REG_OPND(1);

		// product can be a 64 bit value so sign extend it
		BitVector *rs64 = SIGNED(64, rs);
		BitVector *rt64 = SIGNED(64, rt);
		BitVector *prod = MUL(rs64, rt64);

		// cast hi and lo to 64 bits
		// we need to take logical or of these two to form a 64 bit value
		BitVector *hi64 = CAST(64, IL_FALSE, VARG(hi));
		BitVector *lo64 = CAST(64, IL_FALSE, VARG(lo));
		BitVector *hi_lo = LOGOR(SHIFTL0(hi64, U8(32)), lo64);

		// add product and hi_lo concatenated value
		BitVector *sum = ADD(hi_lo, prod);

		// cast back to 32 and sign extend to GPRLEN bits
		BitVector *sum_hi = SIGNED(GPRLEN, CAST(32, IL_FALSE, SHIFTR0(DUP(sum), U32(32))));
		BitVector *sum_lo = SIGNED(GPRLEN, CAST(32, IL_FALSE, sum));

		Effect *set_hi = SETG(hi, sum_hi);
		Effect *set_lo = SETG(lo, sum_lo);

		return SEQ2(set_hi, set_lo);
	}
}

/**
 * Floating Point Fused Multiply Add
 * Format: MADDF.fmt fd, fs, ft
 * Description: FPR[fd] <- FPR[fd] + (FPR[fs] x FPR[ft])
 * Exception: Coprocessor Unusable, Reserved Instruction
 * */
IL_LIFTER(MADDF) {
	char *fd = REG_OPND(0);
	Pure *fs = IL_REG_OPND(1);
	Pure *ft = IL_REG_OPND(2);

	Float *madd = FMAD(RMODE, fs, ft, VARG(fd));

	return SETG(fd, madd);
}

IL_LIFTER(MADDR_Q) {
	return NULL;
}

/**
 * Multiply and Add Unsigned word to HI, LO
 * Format: MADDU rs, rt
 * Description: (HI, LO) <- (HI, LO) + GPR[rs] x GPR[rt]
 * Exceptions: None
 * */
IL_LIFTER(MADDU) {
	char *hi = REG_HI();
	char *lo = REG_LO();

	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	BitVector *rs64 = UNSIGNED(64, rs);
	BitVector *rt64 = UNSIGNED(64, rt);
	BitVector *prod = MUL(rs64, rt64);

	BitVector *hi64 = CAST(64, IL_FALSE, VARG(hi));
	BitVector *lo64 = CAST(64, IL_FALSE, VARG(lo));
	BitVector *hi_lo = LOGOR(SHIFTL0(hi64, U8(32)), lo64);

	BitVector *diff = ADD(hi_lo, prod);

	BitVector *diff_hi = SIGNED(GPRLEN, CAST(32, IL_FALSE, SHIFTR0(DUP(diff), U32(32))));
	BitVector *diff_lo = SIGNED(GPRLEN, CAST(32, IL_FALSE, diff));

	Effect *set_hi = SETG(hi, diff_hi);
	Effect *set_lo = SETG(lo, diff_lo);

	return SEQ2(set_hi, set_lo);
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

/**
 * Move From HI register
 * Format: MFHI rd
 * Description: GPR[rd] <- HI
 * Exceptions: None
 * */
IL_LIFTER(MFHI) {
	char *rd = REG_OPND(0);
	Pure *hi = VARG(REG_HI());

	return SETG(rd, hi);
}

/**
 * Move From LO register
 * Format: MFLO rd
 * Description: GPR[rd] <- LO
 * Exceptions: None
 * */
IL_LIFTER(MFLO) {
	char *rd = REG_OPND(0);
	Pure *lo = VARG(REG_LO());

	return SETG(rd, lo);
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

/**
 * Modulo Words (Signed)
 * Format: MOD rd, rs, rt
 * Description: GPR[rd] <- (modulo.signed(GPR[rs], GPR[rt]))
 * Exceptions: None
 * */
IL_LIFTER(MOD) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *remainder = SMOD(rs, rt);
	return SETG(rd, remainder);
}

IL_LIFTER(MODSUB) {
	return NULL;
}

/**
 * Modulo Words (Unigned)
 * Format: MOD rd, rs, rt
 * Description: GPR[rd] <- (modulo.usigned(GPR[rs], GPR[rt]))
 * Exceptions: None
 * */
IL_LIFTER(MODU) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *remainder = MOD(rs, rt);
	return SETG(rd, remainder);
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

/**
 * Move conditional floating point False
 * Format: MOVF rd, rs, cc
 *         MOVF.fmt fd, fs, cc
 * Description: if FPConditionCode(cc) = 0 then FPR[rd] <- FPR[rs]
 *              if FPConditionCode(cc) = 0 then FPR[fd] <- FPR[fs]
 * Exceptions: Coprocessor Unusable, Reserved Instruction, Unimplemented Operation
 * */
IL_LIFTER(MOVF) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *cc = IL_REG_OPND(2);

	Bool *cond = IS_ZERO(cc);
	return BRANCH(cond, SETG(rd, rs), NOP());
}

/**
 * Move conditional on Not zero
 * Format: MOVN rd, rs, rt
 *         MOVN.fmt fd, fs, rt
 * Description: if GPR[rt] == 0 then GPR[rd] <- GPR[rs]
 * Exceptions: None
 * */
IL_LIFTER(MOVN) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	Bool *rt_is_zero = INV(IS_ZERO(rt));
	Effect *movz = BRANCH(rt_is_zero, SETG(rd, rs), NOP());
	return movz;
}

/**
 * Move conditional on floating point condition code True
 * Format: MOVT rd, rs, cc
 *         MOVT.fmt fd, fs, cc
 * Description: if FPConditionCode[cc] == 0 then GPR[rd] <- GPR[rs]
 * Exceptions: None
 * */
IL_LIFTER(MOVT) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *cc = IL_REG_OPND(2);

	Bool *rt_is_zero = INV(IS_ZERO(cc));
	Effect *movz = BRANCH(rt_is_zero, SETG(rd, rs), NOP());
	return movz;
}

/**
 * Move conditional on Zero
 * Format: MOVZ rd, rs, rt
 *         MOVZ.fmt fd, fs, rt
 * Description: if GPR[rt] == 0 then GPR[rd] <- GPR[rs]
 * Exceptions: None
 * */
IL_LIFTER(MOVZ) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	Bool *rt_is_zero = IS_ZERO(rt);
	Effect *movz = BRANCH(rt_is_zero, SETG(rd, rs), NOP());
	return movz;
}

/**
 * Multiply and Subtract Word to HI, LO
 * Format: MSUB rs, rt
 * Description: (HI, LO) <- (HI, LO) - GPR[rs] x GPR[rt]
 * Exceptions: None
 * */
IL_LIFTER(MSUB) {
	char *hi = REG_HI();
	char *lo = REG_LO();

	if (float_op) {
		char *fd = REG_OPND(0);
		Pure *fr = IL_REG_OPND(1);
		Pure *fs = IL_REG_OPND(2);
		Pure *ft = IL_REG_OPND(3);

		// will do msub = fs * ft - fr
		Float *mul = FMUL(RMODE, fs, ft);
		Float *msub = FSUB(RMODE, mul, fr);

		return SETG(fd, msub);
	} else {
		Pure *rs = IL_REG_OPND(0);
		Pure *rt = IL_REG_OPND(1);

		// product can be a 64 bit value so sign extend it
		BitVector *rs64 = SIGNED(64, rs);
		BitVector *rt64 = SIGNED(64, rt);
		BitVector *prod = MUL(rs64, rt64);

		// cast hi and lo to 64 bits
		// we need to take logical or of these two to form a 64 bit value
		BitVector *hi64 = CAST(64, IL_FALSE, VARG(hi));
		BitVector *lo64 = CAST(64, IL_FALSE, VARG(lo));
		BitVector *hi_lo = LOGOR(SHIFTL0(hi64, U8(32)), lo64);

		// sub product and hi_lo concatenated value
		BitVector *diff = SUB(hi_lo, prod);

		// cast back to 32 and sign extend to GPRLEN bits
		BitVector *diff_hi = SIGNED(GPRLEN, CAST(32, IL_FALSE, SHIFTR0(DUP(diff), U32(32))));
		BitVector *diff_lo = SIGNED(GPRLEN, CAST(32, IL_FALSE, diff));

		Effect *set_hi = SETG(hi, diff_hi);
		Effect *set_lo = SETG(lo, diff_lo);

		return SEQ2(set_hi, set_lo);
	}
}

/**
 * Floating Point Fused Multiply Subtract
 * Format: MSUBF.fmt fd, fs, ft
 * Description: FPR[fd] <- FPR[fd] - (FPR[fs] x FPR[ft])
 * Exception: Coprocessor Unusable, Reserved Instruction
 *
 * TODO: can we use FMAD here?
 * */
IL_LIFTER(MSUBF) {
	char *fd = REG_OPND(0);
	Pure *fs = IL_REG_OPND(1);
	Pure *ft = IL_REG_OPND(2);

	Float *mul = FMUL(RMODE, fs, ft);
	Float *madd = FSUB(RMODE, VARG(fd), mul);

	return SETG(fd, madd);
}

IL_LIFTER(MSUBR_Q) {
	return NULL;
}

/**
 * Multiply and Subtract Unsigned word to HI, LO
 * Format: MSUBU rs, rt
 * Description: (HI, LO) <- (HI, LO) - GPR[rs] x GPR[rt]
 * Exceptions: None
 * */
IL_LIFTER(MSUBU) {
	char *hi = REG_HI();
	char *lo = REG_LO();

	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	// convert to 64 bit because result is 64 bit (32 x 32)
	BitVector *rs64 = UNSIGNED(64, rs);
	BitVector *rt64 = UNSIGNED(64, rt);
	BitVector *prod = MUL(rs64, rt64);

	// nneed to take shifted logical or of hi and lo regs
	// so cast to same size
	BitVector *hi64 = CAST(64, IL_FALSE, VARG(hi));
	BitVector *lo64 = CAST(64, IL_FALSE, VARG(lo));
	BitVector *hi_lo = LOGOR(SHIFTL0(hi64, U8(32)), lo64);

	BitVector *diff = SUB(hi_lo, prod);

	// cast back to 32 bit to store the result and sign extend
	BitVector *diff_hi = SIGNED(GPRLEN, CAST(32, IL_FALSE, SHIFTR0(DUP(diff), U8(32))));
	BitVector *diff_lo = SIGNED(GPRLEN, CAST(32, IL_FALSE, diff));

	Effect *set_hi = SETG(hi, diff_hi);
	Effect *set_lo = SETG(lo, diff_lo);

	return SEQ2(set_hi, set_lo);
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

/**
 * Move To HI register
 * Format: MTHI rs
 * Description: HI <- GPR[rs]
 * Exceptions: None
 * */
IL_LIFTER(MTHI) {
	Pure *rs = IL_REG_OPND(0);
	return SETG(REG_HI(), rs);
}

IL_LIFTER(MTHLIP) {
	return NULL;
}

/**
 * Move To LO register
 * Format: MTLO rs
 * Description: LO <- GPR[rs]
 * Exceptions: None
 * */
IL_LIFTER(MTLO) {
	Pure *rs = IL_REG_OPND(0);
	return SETG(REG_LO(), rs);
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

/**
 * Multiply Words Signed, High Word
 * Format: MUH rd, rs, rt
 * Description: GPR[rd] <- hi_word(multiply.signed(GPR[rs] x GPR[rt]))
 * Exceptions: None
 * */
IL_LIFTER(MUH) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *rs64 = SIGNED(64, rs);
	BitVector *rt64 = SIGNED(64, rt);
	BitVector *prod = MUL(rs64, rt64);

	BitVector *prod_hi = SIGNED(GPRLEN, CAST(32, IL_FALSE, SHIFTR0(prod, U8(32))));

	return SETG(rd, prod_hi);
}

/**
 * Multiply Words Unsigned, High Word
 * Format: MUHU rd, rs, rt
 * Description: GPR[rd] <- hi_word(multiply.unsigned(GPR[rs] x GPR[rt]))
 * Exceptions: None
 * */
IL_LIFTER(MUHU) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *rs64 = UNSIGNED(64, rs);
	BitVector *rt64 = UNSIGNED(64, rt);
	BitVector *prod = MUL(rs64, rt64);

	BitVector *prod_hi = UNSIGNED(GPRLEN, CAST(32, IL_FALSE, SHIFTR0(prod, U8(32))));

	return SETG(rd, prod_hi);
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

/**
 * Multiply Signed
 * Format: MULT rs, rt
 * Description: (HI, LO) <- GPR[rs] x GPR[rt]
 * Exceptions: None
 * */
IL_LIFTER(MULT) {
	char *hi = REG_HI();
	char *lo = REG_LO();

	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	BitVector *rs64 = SIGNED(64, rs);
	BitVector *rt64 = SIGNED(64, rt);
	BitVector *prod = MUL(rs64, rt64);

	BitVector *prod_hi = SIGNED(GPRLEN, CAST(32, IL_FALSE, SHIFTR0(DUP(prod), U8(32))));
	BitVector *prod_lo = SIGNED(GPRLEN, CAST(32, IL_FALSE, prod));

	Effect *set_hi = SETG(hi, prod_hi);
	Effect *set_lo = SETG(lo, prod_lo);

	return SEQ2(set_hi, set_lo);
}

/**
 * Multiply Unsigned
 * Format: MULTU rs, rt
 * Description: (HI, LO) <- GPR[rs] x GPR[rt]
 * Exceptions: None
 * */
IL_LIFTER(MULTU) {
	char *hi = REG_HI();
	char *lo = REG_LO();

	Pure *rs = IL_REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	BitVector *rs64 = UNSIGNED(64, rs);
	BitVector *rt64 = UNSIGNED(64, rt);
	BitVector *prod = MUL(rs64, rt64);

	BitVector *prod_hi = SIGNED(GPRLEN, CAST(32, IL_FALSE, SHIFTR0(DUP(prod), U8(32))));
	BitVector *prod_lo = SIGNED(GPRLEN, CAST(32, IL_FALSE, prod));

	Effect *set_hi = SETG(hi, prod_hi);
	Effect *set_lo = SETG(lo, prod_lo);

	return SEQ2(set_hi, set_lo);
}

// MISSING: NAL

/**
 * Multiply Unigned Word, Low Word
 * Format: MULU rd, rs, rt
 * Description: GPR[rd] <- lo_word(multiply.unsigned(GPR[rs] x GPR[rt]))
 * Exceptions: None
 * */
IL_LIFTER(MULU) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *rs64 = UNSIGNED(64, rs);
	BitVector *rt64 = UNSIGNED(64, rt);
	BitVector *prod = MUL(rs64, rt64);

	BitVector *prod_lo = SIGNED(GPRLEN, CAST(32, IL_FALSE, prod));

	return SETG(rd, prod_lo);
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

/**
 * Floating Point Negative Multiply Add
 * Format: NMADD.fmt fd, fr, fs, ft
 * Description : FPR[fd] <- -1 x MADD(fr, fs, ft)
 * Exceptions: Coprocessor Unusable, Reserved Instruction, Inexact, Unimplemented Operation, Invalid Operation, Overflow, Underflow
 * */
IL_LIFTER(NMADD) {
	char *fd = REG_OPND(0);
	Pure *fr = IL_REG_OPND(1);
	Pure *fs = IL_REG_OPND(2);
	Pure *ft = IL_REG_OPND(3);

	// will do madd = fs * ft + fr
	Float *madd = FMAD(RMODE, fs, ft, fr);

	return SETG(fd, FNEG(madd));
}

/**
 * Floating Point Negative Multiply Subtract
 * Format: NMSUB.fmt fd, fr, fs, ft
 * Description : FPR[fd] <- -1 x MSUB(fr, fs, ft)
 * Exceptions: Coprocessor Unusable, Reserved Instruction, Inexact, Unimplemented Operation, Invalid Operation, Overflow, Underflow
 * */
IL_LIFTER(NMSUB) {
	char *fd = REG_OPND(0);
	Pure *fr = IL_REG_OPND(1);
	Pure *fs = IL_REG_OPND(2);
	Pure *ft = IL_REG_OPND(3);

	// will do msub = fs * ft - fr
	Float *mul = FMUL(RMODE, fs, ft);
	Float *msub = FSUB(RMODE, mul, fr);

	return SETG(fd, FNEG(msub));
}

/**
 * Not Or (Logical NOR)
 * Format: NOR rd, rs, rt
 * Description: GPR[rd] <- GPR[rs] NOR GPR[rt]
 * Exceptions: None
 * */
IL_LIFTER(NOR) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *nor_rs_rt = LOGNOT(LOGOR(rs, rt));
	return SETG(rd, nor_rs_rt);
}

/**
 * NOR Immediate
 * Format: NORI rt, rs, immediate
 * Description: GPR[rt] <- GPR[rs] NOR immediate
 * Exceptions: None
 *
 * NOTE: Not in MIPS32 ISA
 * */
IL_LIFTER(NORI) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	BitVector *imm = U32((ut32)IMM_OPND(2));

	BitVector *nor_rs_imm = LOGNOT(LOGOR(rs, imm));
	return SETG(rt, nor_rs_imm);
}

IL_LIFTER(NOT16) {
	return NULL;
}

IL_LIFTER(NOT) {
	return NULL;
}

/**
 * OR
 * Format: OR rd, rs, rt
 * Description: GPR[rd] <- GPR[rs] OR GPR[rt]
 * Exceptions: None
 * */
IL_LIFTER(OR) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *or_rs_rt = LOGOR(rs, rt);
	return SETG(rd, or_rs_rt);
}

IL_LIFTER(OR16) {
	return NULL;
}

/**
 * OR Immediate
 * Format: ORI rt, rs, immediate
 * Description: GPR[rt] <- GPR[rs] OR immediate
 * Exceptions: None
 * */
IL_LIFTER(ORI) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	BitVector *imm = U32((ut32)IMM_OPND(2));

	BitVector *or_rs_imm = LOGOR(rs, imm);
	return SETG(rt, or_rs_imm);
}

IL_LIFTER(PACKRL) {
	return NULL;
}

/**
 * Pause execution till LLbit is cleared.
 * TODO: Verify that this needs to be NOP() in rzil
 * */
IL_LIFTER(PAUSE) {
	return NOP();
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

/**
 * Prefetch instruction cache.
 * RzIL doesn't have instruction cache
 * TODO: Verify that this can be NOP()
 * */
IL_LIFTER(PREF) {
	return NOP();
}

// MISSING PREFE
// MISSING PREFEX
// MISSING RECIP.fmt

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

/**
 * Round to Integer
 * Format: RINT.fmt fd, fs
 * Description: FPR[fd] <- round_int(FPR[fs])
 * Exceptions: Coprocessor Unusable, Reserved Instruction, Unimplemented Operation, Invalid Operation, Inexact, Overflow, Underflow
 * */
IL_LIFTER(RINT) {
	char *fd = REG_OPND(0);
	Pure *fs = IL_REG_OPND(1);

	return SETG(fd, F2INT(GPRLEN, RMODE, fs));
}

/**
 * Rotate Word Right
 * Format: ROTR rd, rt, sa
 * Description: GPR[rd] < GPR[rt] x(right) sa
 * Exceptions: Reserved Instruction
 * */
IL_LIFTER(ROTR) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	ut8 sa = IMM_OPND(2);

	BitVector *word = CAST(32, IL_FALSE, rt);
	BitVector *left = SHIFTL0(DUP(word), U8(32 - sa));
	BitVector *right = SHIFTR0(word, U8(sa));
	BitVector *rotr = SIGNED(GPRLEN, LOGOR(left, right));

	return SETG(rd, rotr);
}

/**
 * Rotate Word Right Variable
 * Format: ROTRV rd, rt, rs
 * Description: GPR[rd] < GPR[rt] x(right) sa
 * Exceptions: Reserved Instruction
 * */
IL_LIFTER(ROTRV) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	Pure *rs = CAST(6, IL_FALSE, IL_REG_OPND(2));

	BitVector *word = CAST(32, IL_FALSE, rt);
	BitVector *left = SHIFTL0(DUP(word), SUB(UN(6, GPRLEN), DUP(rs)));
	BitVector *right = SHIFTR0(word, rs);
	BitVector *rotr = SIGNED(GPRLEN, LOGOR(left, right));

	return SETG(rd, rotr);
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

/**
 * Store Byte
 * Format: SB rt, offset(base)
 * Description: memory[GPR[base] + offset] <- GPR[rt]
 * Exceptions:TLB Refill, TLB Invalid, TLB Modified, Bus Error, Address Error, Watch
 * */
IL_LIFTER(SB) {
	Pure *rt = IL_REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	Effect *store_op = STOREW(memaddr, CAST(8, IL_FALSE, rt));
	return store_op;
}

// MISSING: SBE

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

/**
 * Sign-Extend Byte
 * Format: SEB rd, rt
 * Description: GPR[rd] <- SignExtend(GPR[rt])
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(SEB) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	Effect *seb_op = SETG(rd, (SIGNED(32, CAST(8, IL_FALSE, rt))));
	return seb_op;
}
/**
 * Sign-Extend Halfword
 * Format: SEH rt, offset(base)
 * Description: GPR[rd] <- SignExtend(GPR[rt])
 * Exceptions: ReservedInstruction
 * */
IL_LIFTER(SEH) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);

	Effect *seb_op = SETG(rd, (SIGNED(32, CAST(16, IL_FALSE, rt))));
	return seb_op;
}

/**
 * Select integer GPR value or zero
 * Format: SELEQZ rd, rs, rt
 * Description: GPR[rd] <- GPR[rt] ? 0 : GPR[rs]
 * Exceptions: None.
 * */
IL_LIFTER(SELEQZ) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	Bool *cond = IS_ZERO(rt);
	return BRANCH(cond, NOP(), SETG(rd, rs));
}

/**
 * Select integer GPR value or zero
 * Format: SELEQZ rd, rs, rt
 * Description: GPR[rd] <- GPR[rt] ? 0 : GPR[rs]
 * Exceptions: None.
 * */
IL_LIFTER(SELNEZ) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	Bool *cond = IS_ZERO(rt);
	return BRANCH(cond, SETG(rd, rs), NOP());
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

/**
 * Store Halfword
 * Format: SH rt, offset(base)
 * Description: memory[GPR[base] + offset] <- GPR[rt]
 * Exceptions:TLB Refill, TLB Invalid, TLB Modified, Bus Error, Address Error, Watch
 * */
IL_LIFTER(SH) {
	Pure *rt = IL_REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	Effect *store_op = STOREW(memaddr, CAST(16, IL_FALSE, rt));
	return store_op;
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

/**
 * Shift word Left Logical
 * Format: SLL rd, rt, sa
 * Description: GPR[rd] <- GPR[rt] << sa
 * Exceptions: None
 * */
IL_LIFTER(SLL) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	BitVector *sa = UN(5, IMM_OPND(2));

	BitVector *shifted_rt = SHIFTL0(rt, sa);
	return SETG(rd, shifted_rt);
}

IL_LIFTER(SLL16) {
	return NULL;
}
IL_LIFTER(SLLI) {
	return NULL;
}

/**
 * Shift word Left Logical Variable
 * Format: SLLV rd, rt, rs
 * Description: GPR[rd] <- GPR[rt] << GPR[rs]
 * Exceptions: None
 * */
IL_LIFTER(SLLV) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	Pure *rs = IL_REG_OPND(2);

	BitVector *sa = LOGAND(rs, UN(GPRLEN, 0x1F));
	BitVector *shifted_rt = SHIFTL0(rt, sa);
	return SETG(rd, shifted_rt);
}

/**
 * Set on Less Than
 * Format: SLT rd, rs, rt
 * Description: GPR[rd] <- (GPR[rs] < sign_extend(immediate))
 * Exceptions: None
 * */
IL_LIFTER(SLT) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	// signed-less-than
	Bool *slt = SLT(rs, rt);
	return SETG(rd, UNSIGNED(GPRLEN, slt));
}

/**
 * Set on Less Than Immediate
 * Format: SLTI rt, rs, immediate
 * Description: GPR[rd] <- (GPR[rs] < sign_extend(immediate))
 * Exceptions: None
 * */
IL_LIFTER(SLTI) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	BitVector *imm = SN(GPRLEN, SIGN_EXTEND(IMM_OPND(2), 16, GPRLEN));

	// signed-less-than
	Bool *slt = SLT(rs, imm);
	return SETG(rt, UNSIGNED(GPRLEN, slt));
}

/**
 * Set on Less Than Immediate Unsigned
 * Format: SLTIU rt, rs, immediate
 * Description: GPR[rd] <- (GPR[rs] < sign_extend(immediate))
 * Exceptions: None
 * */
IL_LIFTER(SLTIU) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	BitVector *imm = SN(GPRLEN, SIGN_EXTEND(IMM_OPND(2), 16, GPRLEN));

	Bool *ult = ULT(rs, imm);
	return SETG(rt, UNSIGNED(GPRLEN, ult));
}

/**
 * Set on Less Than Unsigned
 * Format: SLTU rd, rs, rt
 * Description: GPR[rd] <- (GPR[rs] < GPR[rs])
 * Exceptions: None
 * */
IL_LIFTER(SLTU) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	Bool *ult = ULT(rs, rt);
	return SETG(rd, UNSIGNED(GPRLEN, ult));
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

/**
 * Shift word Right Arithmetic
 * Format: SRA rd, rt, sa
 * Description: GPR[rd] <- (GPR[rt])^s || GPR[rs]
 * Exceptions: None
 * */
IL_LIFTER(SRA) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	ut8 sa_val = IMM_OPND(2) & 0x1F;

	BitVector *sa = UN(5, sa_val);
	return SETG(rd, SHIFTRA(rt, sa));
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

/**
 * Shift word Right Arithmetic Variable
 * Format: SRAV rd, rt, rs
 * Description: GPR[rd] <- (GPR[rt])^s || GPR[rs]
 * Exceptions: None
 * */
IL_LIFTER(SRAV) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	Pure *rs = IL_REG_OPND(2);

	BitVector *sa = LOGAND(rs, U32(0x1F));
	return SETG(rd, SHIFTRA(rt, sa));
}

/**
 * Shift word Right Logical
 * Format: SRL rd, rt, sa
 * Description: GPR[rd] <- GPR[rt] >> sa
 * Exceptions: None
 * */
IL_LIFTER(SRL) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	BitVector *sa = UN(5, IMM_OPND(2));

	BitVector *shifted_rt = SHIFTR0(rt, sa);
	return SETG(rd, shifted_rt);
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

/**
 * Shift word Right Logical Variable
 * Format: SRLV rd, rt, rs
 * Description: GPR[rd] <- GPR[rt] >> GPR[rs]
 * Exceptions: None
 * */
IL_LIFTER(SRLV) {
	char *rd = REG_OPND(0);
	Pure *rt = IL_REG_OPND(1);
	Pure *rs = IL_REG_OPND(2);

	BitVector *sa = LOGAND(rs, U32(0x1F));
	BitVector *shifted_rt = SHIFTR0(rt, sa);
	return SETG(rd, shifted_rt);
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

/**
 * Subtract word Unsigned
 * Format: SUBU rd, rs, rt
 * Description: GPR[rd] <- GPR[rs] - GPR[rt]
 * Exceptions: None
 * */
IL_LIFTER(SUBU) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *diff = SUB(rs, rt);
	return SETG(rd, diff);
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

/**
 * Store Word
 * Format: SW rt, offset(base)
 * Description: memory[GPR[base] + offset] <- GPR[rt]
 * Exceptions:TLB Refill, TLB Invalid, TLB Modified, Bus Error, Address Error, Watch
 * */
IL_LIFTER(SW) {
	Pure *rt = IL_REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	Effect *store_op = STOREW(memaddr, rt);
	return store_op;
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

/**
 * Store Word Left
 * Format: SWL rt, offset(base)
 * Description: Store most significant part of word to an unaligned memory address
 * Exceptions: TLB Refill, TLB Invalid, TLB Modified, Bus Error, Address Error, Watch
 * */
IL_LIFTER(SWL) {
	Pure *rt = IL_REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	// compute memory address, get lower two bytes and get aligned memory address
	BitVector *memaddr = ADD(base, offset);
	BitVector *memaddr_low2bit = LOGAND(DUP(memaddr), UN(GPRLEN, 3));
	BitVector *aligned_memaddr = LOGAND(memaddr, UN(GPRLEN, 0xFFFFFFFC));

	// increasing size of upper bytes by index
	BitVector *rt_hi1 = CAST(8, IL_FALSE, SHIFTR0(DUP(rt), U8(3 * 8)));
	BitVector *rt_hi2 = CAST(2 * 8, IL_FALSE, SHIFTR0(DUP(rt), U8(2 * 8)));
	BitVector *rt_hi3 = CAST(3 * 8, IL_FALSE, SHIFTR0(DUP(rt), U8(8)));
	BitVector *rt_hi4 = rt;

	Effect *b0, *b1, *b2, *b3;
	if (analysis->big_endian) {
		// store higher byte to memory's lower byte
		b3 = STOREW(aligned_memaddr, rt_hi1);

		// store higher two bytes to memory's lower two bytes
		Bool *b2cond = EQ(memaddr_low2bit, U32(2));
		b2 = BRANCH(b2cond, STOREW(DUP(aligned_memaddr), rt_hi2), b3);

		// store higher three bytes to memory's lower three bytes
		Bool *b1cond = EQ(DUP(memaddr_low2bit), U32(1));
		b1 = BRANCH(b1cond, STOREW(DUP(aligned_memaddr), rt_hi3), b2);

		// store higher four (all) bytes to memory's lower four (all) bytes
		Bool *b0cond = EQ(DUP(memaddr_low2bit), U32(0));
		b0 = BRANCH(b0cond, STOREW(DUP(aligned_memaddr), rt_hi4), b1);
	} else {
		// store higher four (all) bytes to memory's lower four (all) bytes
		b3 = STOREW(aligned_memaddr, rt_hi4);

		// store higher three bytes to memory's lower three bytes
		Bool *b2cond = EQ(memaddr_low2bit, U32(2));
		b2 = BRANCH(b2cond, STOREW(DUP(aligned_memaddr), rt_hi3), b3);

		// store higher two bytes to memory's lower two bytes
		Bool *b1cond = EQ(DUP(memaddr_low2bit), U32(1));
		b1 = BRANCH(b1cond, STOREW(DUP(aligned_memaddr), rt_hi2), b2);

		// store higher byte to memory's lower byte
		Bool *b0cond = EQ(DUP(memaddr_low2bit), U32(0));
		b0 = BRANCH(b0cond, STOREW(DUP(aligned_memaddr), rt_hi1), b1);
	}

	return SEQ4(b0, b1, b2, b3);
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

/**
 * Store Word Right
 * Format: SWR rt, offset(base)
 * Description: Store most significant part of word to an unaligned memory address
 * Exceptions: TLB Refill, TLB Invalid, TLB Modified, Bus Error, Address Error, Watch
 * */
IL_LIFTER(SWR) {
	Pure *rt = IL_REG_OPND(0);
	BitVector *offset = IL_MEM_OPND_OFFSET(1);
	Pure *base = IL_MEM_OPND_BASE(1);

	BitVector *memaddr = ADD(base, offset);
	BitVector *memaddr_low2bit = LOGAND(DUP(memaddr), UN(GPRLEN, 3));
	BitVector *aligned_memaddr = LOGAND(memaddr, UN(GPRLEN, 0xFFFFFFFC));

	// increasing size of lower bytes by index
	BitVector *rt_lo1 = CAST(8, IL_FALSE, DUP(rt));
	BitVector *rt_lo2 = CAST(2 * 8, IL_FALSE, DUP(rt));
	BitVector *rt_lo3 = CAST(3 * 8, IL_FALSE, DUP(rt));
	BitVector *rt_lo4 = rt;

	Effect *b0, *b1, *b2, *b3;
	if (analysis->big_endian) {
		// lower four bytes from register get stored in higher four bytes of memory, so basically a simple store
		b3 = STOREW(aligned_memaddr, rt_lo4);

		// lower three bytes of register get stored to memory's higher three bytes
		Bool *b2cond = EQ(memaddr_low2bit, U32(2));
		BitVector *memaddr_hi3 = ADD(DUP(aligned_memaddr), U32(1));
		b2 = BRANCH(b2cond, STOREW(memaddr_hi3, rt_lo3), b3);

		// lower two bytes of register get stored to memory's higher two bytes
		Bool *b1cond = EQ(DUP(memaddr_low2bit), U32(1));
		BitVector *memaddr_hi2 = ADD(DUP(aligned_memaddr), U32(2));
		b1 = BRANCH(b1cond, STOREW(memaddr_hi2, rt_lo2), b2);

		// lower byte of register get stored to memory's higher byte
		Bool *b0cond = EQ(DUP(memaddr_low2bit), U32(0));
		BitVector *memaddr_hi1 = ADD(DUP(aligned_memaddr), U32(3));
		b0 = BRANCH(b0cond, STOREW(memaddr_hi1, rt_lo1), b1);
	} else {
		// lower byte gets stored into higher byte of memory
		BitVector *memaddr_hi1 = ADD(DUP(aligned_memaddr), U32(3));
		b3 = STOREW(memaddr_hi1, rt_lo1);

		// lower two bytes go to higher two bytes of memory
		Bool *b2cond = EQ(memaddr_low2bit, U32(2));
		BitVector *memaddr_hi2 = ADD(DUP(aligned_memaddr), U32(2));
		b2 = BRANCH(b2cond, STOREW(memaddr_hi2, rt_lo2), b3);

		// lower three bytes go to higher three bytes of memory
		Bool *b1cond = EQ(DUP(memaddr_low2bit), U32(1));
		BitVector *memaddr_hi3 = ADD(DUP(aligned_memaddr), U32(1));
		b1 = BRANCH(b1cond, STOREW(memaddr_hi3, rt_lo3), b2);

		// lower four (all) bytes go to higher four (all) bytes of memory
		Bool *b0cond = EQ(DUP(memaddr_low2bit), U32(0));
		b0 = BRANCH(b0cond, STOREW(aligned_memaddr, rt_lo4), b1);
	}

	return SEQ4(b0, b1, b2, b3);
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

/**
 * XOR
 * Format: XOR rd, rs, rt
 * Description: GPR[rd] <- GPR[rs] XOR GPR[rt]
 * Exceptions: None
 * */
IL_LIFTER(XOR) {
	char *rd = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	Pure *rt = IL_REG_OPND(2);

	BitVector *xor_rs_rt = LOGXOR(rs, rt);
	Effect *set_rd = SETG(rd, xor_rs_rt);
	return set_rd;
}

IL_LIFTER(XOR16) {
	return NULL;
}

/**
 * XOR Immediate
 * Format: XORI rt, rs, immediate
 * Description: GPR[rt] <- GPR[rs] XOR immediate
 * Exceptions: None
 * */
IL_LIFTER(XORI) {
	char *rt = REG_OPND(0);
	Pure *rs = IL_REG_OPND(1);
	BitVector *imm = U32((ut32)IMM_OPND(2));

	BitVector *xor_rs_imm = LOGXOR(rs, imm);
	Effect *set_rt = SETG(rt, xor_rs_imm);
	return set_rt;
}

/**
 * NOP
 * Format: NOP
 * Description: NOP
 * Exceptions: None
 * */
IL_LIFTER(NOP) {
	return NOP();
}

IL_LIFTER(NEGU) {
	return NULL;
}

/**
 * Jump And Link Register (Hazard Barrier)
 * Format: JALRHB rs (rd = 31)
 *         JALRHB rd, rs
 * Description: Link to rd and jump to rs (basically a procedure call)
 * Exceptions: ReservedInstruction
 *
 * NOTE: See "JALR" note
 * TODO: Handle the "else" case in microMIPS uplifting phase!
 * */
IL_LIFTER(JALR_HB) {
	char *rd = NULL;
	Pure *rs = NULL;
	if (OPND_COUNT() == 1) {
		rd = REG_R(31);
		rs = IL_REG_OPND(0);
	} else {
		rd = REG_OPND(0);
		rs = IL_REG_OPND(1);
	}

	Effect *link_op = SETG(rd, UN(GPRLEN, pc + 8));
	Pure *jump_target = rs;
	Effect *jmp_op = JMP(jump_target);

	return SEQ2(link_op, jmp_op);
}
/**
 * Jump Register
 * Format: JR rs
 * Description: PC <- GPR[rs]
 * Exceptions: ReservedInstruction
 *
 * NOTE: See "JALR" note
 * TODO: Handle "else" case, Handle ClearHazard() ?
 * */
IL_LIFTER(JR_HB) {
	Pure *jump_target = IL_REG_OPND(0);
	return JMP(jump_target);
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
 * \param analysis To decide architecture.
 * \param insn To get instruction details.
 * \param pc Instruction address of current instruction.
 * \return Valid RzILOpEffect* on success, NULL otherwise.
 **/
RZ_IPI Effect *mips32_il(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL cs_insn *insn, ut32 pc) {
	rz_return_val_if_fail(analysis && insn, NULL);
	if (INSN_ID(insn) >= MIPS_INS_ENDING) {
		RZ_LOG_ERROR("RzIL MIPS : Invalid MIPS instruction.")
		return NULL;
	}

	// check if this is a FLOAT OP
	// if first register is a float reg then it's a FLOAT OP
	bool float_op = IS_FLOAT_OPND(0);

	// check if this instruction uses all 64 bits of a FPR
	// if MIPS_GRP_NOTFP64BIT is in groups then use only 32 bits
	// if MIPS_GRP_FP64BIT is in groups then use all 64 bits
	bool fp64 = false;
	if (float_op) {
		for (int i = 0; i < INSN_GROUP_COUNT(insn); i++) {
			if (INSN_GROUP(i) == MIPS_GRP_FP64BIT) {
				fp64 = true;
				break;
			}
		}
	}

	// find uplifter function based on instruction id of instruction
	// and execute uplifter to get Effect*
	MipsILLifterFunction fn = mips_lifters[INSN_ID(insn)];
	if (fn) {
		Effect *op = fn(analysis, insn, pc, float_op, fp64);
		return op;
	}

	rz_warn_if_reached();
	return NULL;
}

RZ_IPI RzAnalysisILConfig *mips32_il_config() {
	return NULL;
}
