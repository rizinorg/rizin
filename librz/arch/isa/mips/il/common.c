// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2023 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#define MIPS_DWORD_SIZE 64
#define MIPS_WORD_SIZE  32
#define MIPS_HALF_SIZE  16
#define MIPS_BYTE_SIZE  8

#define MIPS_REG_LO "lo"
#define MIPS_REG_HI "hi"
#define MIPS_REG_RA "ra"

#define IS_ZERO_REG(idx) mips_is_zero_reg(insn, idx)
#define TRUNC64(x)       UNSIGNED(MIPS_DWORD_SIZE, x)
#define TRUNC32(x)       UNSIGNED(MIPS_WORD_SIZE, x)
#define TRUNC16(x)       UNSIGNED(MIPS_HALF_SIZE, x)
#define TRUNC8(x)        UNSIGNED(MIPS_BYTE_SIZE, x)

#define BITN(x, n)            SHIFTR0(LOGAND(x, UN(gprlen, (ut64)1 << (n - 1))), UN(gprlen, n - 1))
#define CHECK_OVERFLOW(r, sz) EQ(BITN(r, sz), BITN(DUP(r), sz - 1))
#define MIPS_REG(idx)         mips_get_reg(handle, insn, idx, gprlen)
#define MIPS_IMM(idx)         UN(gprlen, IMM(idx))
#define MIPS_IMM32(idx)       UN(32, IMM(idx))
#define MIPS_PCADDIMM(idx)    UN(gprlen, insn->address + IMM(idx)) /* returns an immediate which is PC + IMM */
#define MIPS_ZERO()           UN(gprlen, 0)
#define MIPS_LINK()           SETG(MIPS_REG_RA, UN(gprlen, insn->address + 8)) /* link register $ra */

/**
 * This macro checks for any writes to the $zero
 * register and returns a NOP operation.
 **/
#define MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP() \
	do { \
		if (IS_ZERO_REG(0)) { \
			return NOP(); \
		} \
	} while (0)

static bool mips_is_zero_reg(const cs_insn *insn, ut32 idx) {
	const ut32 regid = REGID(idx);

	return regid == MIPS_REG_ZERO ||
		regid == MIPS_REG_ZERO_NM ||
		regid == MIPS_REG_ZERO_64;
}

static RzILOpPure *mips_get_reg(const csh *handle, const cs_insn *insn, unsigned regid, ut32 gprlen) {
	if (IS_ZERO_REG(regid)) {
		return SN(gprlen, 0);
	}

	return VARG_REG(regid);
}

static RzILOpEffect *mips_il_move(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	const char *rt = REG(0);
	RzILOpPure *val = NULL;

	if (IS_ZERO_REG(1)) {
		// set zero if target register is $zero
		val = SN(gprlen, 0);
	} else if (IS_IMM(1)) {
		val = MIPS_IMM(2);
	} else {
		val = MIPS_REG(1);
	}

	return SETG(rt, val);
}

static RzILOpEffect *mips_il_add(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	RzILOpPure *sum = SIGNED(gprlen, ADD(rs, rt));
	return SETG(rd, sum);
}

static RzILOpEffect *mips_il_addi(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *imm = MIPS_IMM(2);

	RzILOpPure *sum = SIGNED(gprlen, ADD(rs, imm));
	return SETG(rd, sum);
}

static RzILOpEffect *mips_il_addiu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *imm = MIPS_IMM(2);
	RzILOpPure *sum = ADD(rs, imm);
	return SETG(rd, sum);
}

static RzILOpEffect *mips_il_addiupc(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// LAPC is also an alias of addiupc
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rs = REG(0);
	RzILOpPure *pc_imm = MIPS_PCADDIMM(1);
	return SETG(rs, pc_imm);
}

static RzILOpEffect *mips_il_addu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();
	if (OPCOUNT() < 3) {
		// move
		return mips_il_move(handle, insn, gprlen);
	}

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);
	RzILOpPure *sum = ADD(rs, rt);
	return SETG(rd, sum);
}

static RzILOpEffect *mips_il_align(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Concatenate two GPRs, and extract a contiguous subset at a byte position | ALIGN rd,rs,rt,bp
	// operates on 32 bit. in 64bit mode sign extends.
	// GPR[rd] = (GPR[rt] << (8*bp)) or (GPR[rs] >> (GPRLEN-8*bp))

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);
	if (gprlen > 32) {
		rs = TRUNC32(rs);
		rt = TRUNC32(rt);
	}
	RzILOpPure *bp_8 = UN(32, IMM(3) << 3); // bp * 8
	RzILOpPure *gprlen_bp_8 = UN(32, IMM(3) << 3); // gprlen - (bp * 8)

	RzILOpPure *or = LOGOR(SHIFTL0(rt, bp_8), SHIFTR0(rs, gprlen_bp_8));
	if (gprlen > 32) {
		or = SIGNED(gprlen, or);
	}
	return SETG(rd, or);
}

static RzILOpEffect *mips_il_dalign(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Concatenate two GPRs, and extract a contiguous subset at a byte position | ALIGN rd,rs,rt,bp
	// operates on in 64 bits mode
	// GPR[rd] = (GPR[rt] << (8*bp)) or (GPR[rs] >> (GPRLEN-8*bp))

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);
	RzILOpPure *bp_8 = UN(gprlen, IMM(3) << 3); // bp * 8
	RzILOpPure *gprlen_bp_8 = UN(gprlen, IMM(3) << 3); // gprlen - (bp * 8)

	RzILOpPure *or = LOGOR(SHIFTL0(rt, bp_8), SHIFTR0(rs, gprlen_bp_8));
	return SETG(rd, or);
}

static RzILOpEffect *mips_il_aluipc(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Aligned Add Upper Immediate to PC
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rs = REG(0);
	st64 imm = (st64)IMM(1);
	// cast required due possible left shift of negative value
	ut64 pc_imm = insn->address + (st64)((ut64)imm << 16);
	pc_imm &= 0xffffffffffff0000ull;
	return SETG(rs, UN(gprlen, pc_imm));
}

static RzILOpEffect *mips_il_and(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);
	RzILOpPure *and = LOGAND(rs, rt);
	return SETG(rd, and);
}

static RzILOpEffect *mips_il_andi(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *imm = MIPS_IMM(2);
	RzILOpPure *and = LOGAND(rs, imm);
	return SETG(rd, and);
}

static RzILOpEffect *mips_il_aui(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Add Upper Immediate signed
	// AUI is a 32 gpr instruction, so when in 64 gpr mode, the result
	// is sign extended as if a 32-bits signed address.
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rt = REG(0);
	st64 imm = (st64)IMM(2);
	// cast required due possible left shift of negative value
	imm = (st64)((ut64)imm << 16);

	if (IS_ZERO_REG(1)) {
		return SETG(rt, SN(gprlen, imm));
	}

	RzILOpPure *rs = MIPS_REG(1);
	if (gprlen > 32) {
		rs = TRUNC32(rs);
	}

	RzILOpPure *add = ADD(rs, SN(32, imm));
	if (gprlen > 32) {
		add = SIGNED(gprlen, add);
	}
	return SETG(rt, add);
}

static RzILOpEffect *mips_il_daui(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Doubleword Add Upper Immediate signed
	// DAUI is a 64 gpr instruction
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rt = REG(0);
	st64 imm = (st64)IMM(2);
	// cast required due possible left shift of negative value
	imm = (st64)((ut64)imm << 16);

	if (IS_ZERO_REG(1)) {
		return SETG(rt, SN(gprlen, imm));
	}

	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *add = ADD(rs, SN(gprlen, imm));
	return SETG(rt, add);
}

static RzILOpEffect *mips_il_dahi(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Doubleword Add Higher Immediate
	// DAUI is a 64 gpr instruction
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rt = REG(0);
	st64 imm = (st64)IMM(2);
	// cast required due possible left shift of negative value
	imm = (st64)((ut64)imm << 32);

	if (IS_ZERO_REG(1)) {
		return SETG(rt, SN(gprlen, imm));
	}

	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *add = ADD(rs, SN(gprlen, imm));
	return SETG(rt, add);
}

static RzILOpEffect *mips_il_dati(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Doubleword Add Top Immediate
	// DAUI is a 64 gpr instruction
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rt = REG(0);
	st64 imm = (st64)IMM(2);
	// cast required due possible left shift of negative value
	imm = (st64)((ut64)imm << 48);

	if (IS_ZERO_REG(1)) {
		return SETG(rt, SN(gprlen, imm));
	}

	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *add = ADD(rs, SN(gprlen, imm));
	return SETG(rt, add);
}

static RzILOpEffect *mips_il_auipc(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Add Upper Immediate to PC
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rs = REG(0);
	st64 imm = (st64)IMM(1);
	// cast required due possible left shift of negative value
	ut64 pc_imm = insn->address + (st64)((ut64)imm << 16);
	return SETG(rs, SN(gprlen, pc_imm));
}

static RzILOpEffect *mips_il_b(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *target = MIPS_IMM(0);
	return JMP(target);
}

static RzILOpEffect *mips_il_bal(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *jump_target = MIPS_IMM(0);
	RzILOpEffect *link_op = MIPS_LINK();
	RzILOpEffect *jmp_op = JMP(jump_target);
	return SEQ2(link_op, jmp_op);
}

static RzILOpEffect *mips_il_beqz(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *target = MIPS_IMM(1);
	if (IS_ZERO_REG(0)) {
		// always taken
		return JMP(target);
	}

	RzILOpPure *rs = MIPS_REG(0);
	return BRANCH(IS_ZERO(rs), JMP(target), NOP());
}

static RzILOpEffect *mips_il_beqzalc(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (OPCOUNT() == 1 || IS_ZERO_REG(0)) {
		return mips_il_bal(handle, insn, gprlen);
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *jump_target = MIPS_IMM(1);
	RzILOpEffect *link_op = MIPS_LINK();
	RzILOpEffect *jmp_op = JMP(jump_target);
	return BRANCH(IS_ZERO(rs), SEQ2(link_op, jmp_op), NOP());
}

static RzILOpEffect *mips_il_beq(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (OPCOUNT() == 1) {
		return mips_il_b(handle, insn, gprlen);
	} else if (OPCOUNT() == 2) {
		return mips_il_beqz(handle, insn, gprlen);
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *target = MIPS_IMM(2);

	return BRANCH(EQ(rs, rt), JMP(target), NOP());
}

static RzILOpEffect *mips_il_bgec(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (OPCOUNT() == 1) {
		return mips_il_b(handle, insn, gprlen);
	}

	RzILOpPure *target = MIPS_IMM(2);
	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);

	return BRANCH(SGE(rs, rt), JMP(target), NOP());
}

static RzILOpEffect *mips_il_bgez(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (OPCOUNT() == 1) {
		return mips_il_b(handle, insn, gprlen);
	}

	RzILOpPure *target = MIPS_IMM(1);
	if (IS_ZERO_REG(0)) {
		return JMP(target);
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *zero = MIPS_ZERO();

	return BRANCH(SGE(rs, zero), JMP(target), NOP());
}

static RzILOpEffect *mips_il_bgezal(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (OPCOUNT() == 1 || IS_ZERO_REG(0)) {
		return mips_il_bal(handle, insn, gprlen);
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *zero = MIPS_ZERO();
	RzILOpPure *jump_target = MIPS_IMM(1);
	RzILOpEffect *link_op = MIPS_LINK();
	RzILOpEffect *jmp_op = JMP(jump_target);
	return BRANCH(SGE(rs, zero), SEQ2(link_op, jmp_op), NOP());
}

static RzILOpEffect *mips_il_bgtzalc(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (OPCOUNT() == 1 || IS_ZERO_REG(0)) {
		return mips_il_bal(handle, insn, gprlen);
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *zero = MIPS_ZERO();
	RzILOpPure *jump_target = MIPS_IMM(1);
	RzILOpEffect *link_op = MIPS_LINK();
	RzILOpEffect *jmp_op = JMP(jump_target);
	return BRANCH(SGT(rs, zero), SEQ2(link_op, jmp_op), NOP());
}

static RzILOpEffect *mips_il_bgtz(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (IS_ZERO_REG(0)) {
		// never taken
		return NOP();
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *zero = MIPS_ZERO();
	RzILOpPure *target = MIPS_IMM(1);

	return BRANCH(SGT(rs, zero), JMP(target), NOP());
}

static RzILOpEffect *mips_il_blez(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (OPCOUNT() == 1) {
		return mips_il_b(handle, insn, gprlen);
	}

	RzILOpPure *target = MIPS_IMM(1);
	if (IS_ZERO_REG(0)) {
		return JMP(target);
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *zero = MIPS_ZERO();

	return BRANCH(SLE(rs, zero), JMP(target), NOP());
}

static RzILOpEffect *mips_il_bltc(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (IS_ZERO_REG(0)) {
		// never taken
		return NOP();
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *target = MIPS_IMM(2);

	return BRANCH(SLT(rs, rt), JMP(target), NOP());
}

static RzILOpEffect *mips_il_bltz(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (IS_ZERO_REG(0)) {
		// never taken
		return NOP();
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *zero = MIPS_ZERO();
	RzILOpPure *target = MIPS_IMM(1);

	return BRANCH(SLT(rs, zero), JMP(target), NOP());
}

static RzILOpEffect *mips_il_bltzal(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (OPCOUNT() < 2 || IS_ZERO_REG(0)) {
		return NOP();
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *zero = MIPS_ZERO();
	RzILOpPure *jump_target = MIPS_IMM(1);
	RzILOpEffect *link_op = MIPS_LINK();
	RzILOpEffect *jmp_op = JMP(jump_target);
	return BRANCH(SLT(rs, zero), SEQ2(link_op, jmp_op), NOP());
}

static RzILOpEffect *mips_il_blezalc(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (OPCOUNT() < 2 || IS_ZERO_REG(0)) {
		return NOP();
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *zero = MIPS_ZERO();
	RzILOpPure *jump_target = MIPS_IMM(1);
	RzILOpEffect *link_op = MIPS_LINK();
	RzILOpEffect *jmp_op = JMP(jump_target);
	return BRANCH(SLE(rs, zero), SEQ2(link_op, jmp_op), NOP());
}

static RzILOpEffect *mips_il_bnez(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (IS_ZERO_REG(0)) {
		// never taken
		return NOP();
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *target = MIPS_IMM(1);

	return BRANCH(NON_ZERO(rs), JMP(target), NOP());
}

static RzILOpEffect *mips_il_bnezalc(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (OPCOUNT() == 1 || IS_ZERO_REG(0)) {
		return mips_il_bal(handle, insn, gprlen);
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *jump_target = MIPS_IMM(1);
	RzILOpEffect *link_op = MIPS_LINK();
	RzILOpEffect *jmp_op = JMP(jump_target);
	return BRANCH(NON_ZERO(rs), SEQ2(link_op, jmp_op), NOP());
}

static RzILOpEffect *mips_il_bne(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (OPCOUNT() < 3) {
		return mips_il_bnez(handle, insn, gprlen);
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *target = MIPS_IMM(2);

	return BRANCH(NE(rs, rt), JMP(target), NOP());
}

static RzILOpEffect *mips_il_bitswap(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Swaps (reverses) bits in each byte
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_bovc(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Branch on Overflow
	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *target = MIPS_IMM(2);

	RzILOpPure *sum = SIGNED(gprlen, ADD(rs, rt));
	RzILOpPure *overflow = CHECK_OVERFLOW(sum, gprlen);
	return BRANCH(overflow, JMP(target), NOP());
}

static RzILOpEffect *mips_il_clo(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Count Leading Ones in Word
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_clz(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Count Leading Zeros in Word
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_div(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	size_t offset = 0;
	if (OPCOUNT() > 2 && IS_ZERO_REG(0)) {
		// handle mips revision 2 ot 5 format
		offset = 1;
	}
	RzILOpPure *rs = MIPS_REG(offset + 0);
	RzILOpPure *rt = MIPS_REG(offset + 1);

	RzILOpPure *quotient = SDIV(DUP(rs), DUP(rt));
	RzILOpPure *remainder = SMOD(rs, rt);

	RzILOpEffect *set_lo = SETG(MIPS_REG_LO, quotient);
	RzILOpEffect *set_hi = SETG(MIPS_REG_HI, remainder);
	return SEQ2(set_lo, set_hi);
}

static RzILOpEffect *mips_il_divu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	size_t offset = 0;
	if (OPCOUNT() > 2 && IS_ZERO_REG(0)) {
		// handle mips revision 2 ot 5 format
		offset = 1;
	}
	RzILOpPure *rs = MIPS_REG(offset + 0);
	RzILOpPure *rt = MIPS_REG(offset + 1);

	RzILOpPure *quotient = DIV(DUP(rs), DUP(rt));
	RzILOpPure *remainder = MOD(rs, rt);

	RzILOpEffect *set_lo = SETG(MIPS_REG_LO, quotient);
	RzILOpEffect *set_hi = SETG(MIPS_REG_HI, remainder);
	return SEQ2(set_lo, set_hi);
}

static RzILOpEffect *mips_il_ext(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Extract Bit Field (EXT rt, rs, pos, size)
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rt = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *pos = MIPS_IMM32(2); // EXTRACT64 requires 32 bit value.
	RzILOpPure *size = MIPS_IMM32(3); // EXTRACT64 requires 32 bit value.
	RzILOpPure *extract = NULL;
	if (gprlen > 32) {
		extract = EXTRACT64(rs, pos, size);
	} else {
		extract = EXTRACT32(rs, pos, size);
	}
	return SETG(rt, extract);
}

static RzILOpEffect *mips_il_ins(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Insert Bit Field (INS rt, rs, pos, size)
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	RzILOpPure *rt = MIPS_REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *pos = MIPS_IMM32(2); // DEPOSIT64 requires 32 bit value
	RzILOpPure *size = MIPS_IMM32(3); // DEPOSIT64 requires 32 bit value

	RzILOpPure *deposit = NULL;
	if (gprlen > 32) {
		deposit = DEPOSIT64(rt, pos, size, rs);
	} else {
		deposit = DEPOSIT32(rt, pos, size, rs);
	}
	return SETG(REG(0), deposit);
}

static RzILOpEffect *mips_il_j(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *target = MIPS_IMM(0);
	return JMP(target);
}

static RzILOpEffect *mips_il_jal(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *jump_target = MIPS_IMM(0);
	RzILOpEffect *link_op = MIPS_LINK();
	RzILOpEffect *jmp_op = JMP(jump_target);
	return SEQ2(link_op, jmp_op);
}

static RzILOpEffect *mips_il_jalr(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpEffect *link_op = NULL;
	RzILOpPure *jump_target = NULL;
	if (OPCOUNT() < 2) {
		link_op = MIPS_LINK();
		jump_target = MIPS_REG(0);
	} else {
		link_op = SETG(REG(0), UN(gprlen, insn->address + 8));
		jump_target = MIPS_REG(1);
	}

	RzILOpEffect *jmp_op = JMP(jump_target);
	return SEQ2(link_op, jmp_op);
}

static RzILOpEffect *mips_il_jalx(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Jump and Link Exchange
	// TODO: handle change of isamode: ISAMode = !ISAMode
	RzILOpPure *jump_target = MIPS_IMM(0);
	RzILOpEffect *link_op = MIPS_LINK();
	RzILOpEffect *jmp_op = JMP(jump_target);
	return SEQ2(link_op, jmp_op);
}

static RzILOpEffect *mips_il_jialc(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Jump Indexed and Link, Compact
	RzILOpPure *jump_target = MIPS_REG(0);
	RzILOpPure *jump_offset = MIPS_IMM(1);
	RzILOpEffect *link_op = MIPS_LINK();
	RzILOpEffect *jmp_op = JMP(ADD(jump_target, jump_offset));
	return SEQ2(link_op, jmp_op);
}

static RzILOpEffect *mips_il_jic(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Jump Indexed, Compact
	RzILOpPure *jump_target = MIPS_REG(0);
	if (IMM(1) == 0) {
		return JMP(jump_target);
	}
	RzILOpPure *jump_offset = MIPS_IMM(1);
	return JMP(ADD(jump_target, jump_offset));
}

static RzILOpEffect *mips_il_jr(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *target = MIPS_REG(0);
	return JMP(target);
}

static RzILOpEffect *mips_il_lb(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rt = REG(0);
	RzILOpPure *offset = SN(gprlen, MEMOFFSET(1));
	RzILOpPure *base = VARG_MEMBASE(1);

	RzILOpPure *memaddr = ADD(base, offset);
	RzILOpPure *byte = SIGNED(gprlen, LOADW(MIPS_BYTE_SIZE, memaddr));
	return SETG(rt, byte);
}

static RzILOpEffect *mips_il_lbu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rt = REG(0);
	RzILOpPure *offset = SN(gprlen, MEMOFFSET(1));
	RzILOpPure *base = VARG_MEMBASE(1);

	RzILOpPure *memaddr = ADD(base, offset);
	RzILOpPure *byte = UNSIGNED(gprlen, LOADW(MIPS_BYTE_SIZE, memaddr));
	return SETG(rt, byte);
}

static RzILOpEffect *mips_il_ld(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rt = REG(0);
	RzILOpPure *offset = SN(gprlen, MEMOFFSET(1));
	RzILOpPure *base = VARG_MEMBASE(1);

	RzILOpPure *memaddr = ADD(base, offset);
	return SETG(rt, LOADW(MIPS_DWORD_SIZE, memaddr));
}

static RzILOpEffect *mips_il_ldpc(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Doubleword PC-relative
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	ut64 address = (insn->address & (~0x7ull));
	// ensure it's sign extended.
	address += (st64)IMM(1);

	RzILOpPure *memaddr = UN(gprlen, address);
	return SETG(REG(0), LOADW(MIPS_DWORD_SIZE, memaddr));
}

static RzILOpEffect *mips_il_lh(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rt = REG(0);
	RzILOpPure *offset = SN(gprlen, MEMOFFSET(1));
	RzILOpPure *base = VARG_MEMBASE(1);

	RzILOpPure *memaddr = ADD(base, offset);
	RzILOpPure *byte = SIGNED(gprlen, LOADW(MIPS_HALF_SIZE, memaddr));
	return SETG(rt, byte);
}

static RzILOpEffect *mips_il_lhu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rt = REG(0);
	RzILOpPure *offset = SN(gprlen, MEMOFFSET(1));
	RzILOpPure *base = VARG_MEMBASE(1);

	RzILOpPure *memaddr = ADD(base, offset);
	RzILOpPure *byte = UNSIGNED(gprlen, LOADW(MIPS_HALF_SIZE, memaddr));
	return SETG(rt, byte);
}

static RzILOpEffect *mips_il_lui(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rt = REG(0);
	ut64 imm = IMM(1);
	imm <<= 16u;

	return SETG(rt, SN(gprlen, imm));
}

static RzILOpEffect *mips_il_lw(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rt = REG(0);
	RzILOpPure *offset = SN(gprlen, MEMOFFSET(1));
	RzILOpPure *base = VARG_MEMBASE(1);

	RzILOpPure *memaddr = ADD(base, offset);
	RzILOpPure *res = LOADW(MIPS_WORD_SIZE, memaddr);
	if (gprlen > 32) {
		res = SIGNED(gprlen, res);
	}
	return SETG(rt, res);
}

static RzILOpEffect *mips_il_lwpc(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Word PC-relative (signed)
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	ut64 address = (insn->address & (~0x7ull));
	// ensure it's sign extended.
	address += (st64)IMM(1);

	RzILOpPure *memaddr = UN(gprlen, address);
	RzILOpPure *res = LOADW(MIPS_WORD_SIZE, memaddr);
	if (gprlen > 32) {
		res = SIGNED(gprlen, res);
	}
	return SETG(REG(0), res);
}

static RzILOpEffect *mips_il_lwu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rt = REG(0);
	RzILOpPure *offset = SN(gprlen, MEMOFFSET(1));
	RzILOpPure *base = VARG_MEMBASE(1);

	RzILOpPure *memaddr = ADD(base, offset);
	RzILOpPure *res = LOADW(MIPS_WORD_SIZE, memaddr);
	if (gprlen > 32) {
		res = UNSIGNED(gprlen, res);
	}
	return SETG(rt, res);
}

static RzILOpEffect *mips_il_lwupc(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Word PC-relative (unsigned)
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	ut64 address = (insn->address & (~0x7ull));
	// ensure it's sign extended.
	address += (st64)IMM(1);

	RzILOpPure *memaddr = UN(gprlen, address);
	RzILOpPure *res = LOADW(MIPS_WORD_SIZE, memaddr);
	if (gprlen > 32) {
		res = UNSIGNED(gprlen, res);
	}
	return SETG(REG(0), res);
}

static RzILOpEffect *mips_il_lwl(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Word Left
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_ldl(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Doubleword Left
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_lwr(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Word Right
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_ldr(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Doubleword Right
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_lsa(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Scaled Address
	// LSA rd, rs, rt, sa | rd = (rs << (sa+1)) + rt
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);
	ut64 sa = IMM(3); // plus one added by capstone

	RzILOpPure *shiftl = SHIFTL0(rs, U8(sa));
	return SETG(rd, ADD(shiftl, rt));
}

static RzILOpEffect *mips_il_madd(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);

	// product is on 64 bit value so sign extend it
	RzILOpPure *rs64 = SIGNED(64, rs);
	RzILOpPure *rt64 = SIGNED(64, rt);
	RzILOpPure *prod = MUL(rs64, rt64);

	// cast hi and lo to 64 bits
	// we need to take logical or of these two to form a 64 bit value
	RzILOpPure *hi64 = CAST(64, IL_FALSE, VARG(MIPS_REG_HI));
	RzILOpPure *lo64 = CAST(64, IL_FALSE, VARG(MIPS_REG_LO));
	RzILOpPure *hi_lo = LOGOR(SHIFTL0(hi64, U8(32)), lo64);

	// add product and hi_lo concatenated value
	RzILOpEffect *res = SETL("temp", ADD(hi_lo, prod));

	// cast back to 32 bits
	RzILOpPure *res_hi = TRUNC32(SHIFTR0(VARL("temp"), U8(32)));
	RzILOpPure *res_lo = TRUNC32(VARL("temp"));

	RzILOpEffect *set_hi = SETG(MIPS_REG_HI, res_hi);
	RzILOpEffect *set_lo = SETG(MIPS_REG_LO, res_lo);

	return SEQ3(res, set_hi, set_lo);
}

static RzILOpEffect *mips_il_maddu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);

	// product is on 64 bit value so zero extend it
	RzILOpPure *rs64 = UNSIGNED(64, rs);
	RzILOpPure *rt64 = UNSIGNED(64, rt);
	RzILOpPure *prod = MUL(rs64, rt64);

	// cast hi and lo to 64 bits
	// we need to take logical or of these two to form a 64 bit value
	RzILOpPure *hi64 = CAST(64, IL_FALSE, VARG(MIPS_REG_HI));
	RzILOpPure *lo64 = CAST(64, IL_FALSE, VARG(MIPS_REG_LO));
	RzILOpPure *hi_lo = LOGOR(SHIFTL0(hi64, U8(32)), lo64);

	// add product and hi_lo concatenated value
	RzILOpEffect *res = SETL("temp", ADD(hi_lo, prod));

	// cast back to 32 bits
	RzILOpPure *res_hi = TRUNC32(SHIFTR0(VARL("temp"), U8(32)));
	RzILOpPure *res_lo = TRUNC32(VARL("temp"));

	RzILOpEffect *set_hi = SETG(MIPS_REG_HI, res_hi);
	RzILOpEffect *set_lo = SETG(MIPS_REG_LO, res_lo);

	return SEQ3(res, set_hi, set_lo);
}

static RzILOpEffect *mips_il_mfhi(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	return SETG(REG(0), VARG(MIPS_REG_HI));
}

static RzILOpEffect *mips_il_mflo(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	return SETG(REG(0), VARG(MIPS_REG_LO));
}

static RzILOpEffect *mips_il_mod(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Modulo Words Signed
	// MOD rd, rs, rt

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);
	return SETG(rd, SMOD(rs, rt));
}

static RzILOpEffect *mips_il_modu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Modulo Words Unsigned
	// MODU rd, rs, rt

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);
	return SETG(rd, MOD(rs, rt));
}

static RzILOpEffect *mips_il_movn(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	// Move Conditional on Not Zero
	if (IS_ZERO_REG(2)) {
		// rt is zero, thus always false
		return NOP();
	}

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);
	return BRANCH(IS_ZERO(rt), NOP(), SETG(rd, rs));
}

static RzILOpEffect *mips_il_movz(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Move Conditional on Zero
	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);

	if (IS_ZERO_REG(2)) {
		// rt is zero, thus always true
		return SETG(rd, rs);
	}

	RzILOpPure *rt = MIPS_REG(2);
	return BRANCH(IS_ZERO(rt), SETG(rd, rs), NOP());
}

static RzILOpEffect *mips_il_msub(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);

	// product is on 64 bit value so sign extend it
	RzILOpPure *rs64 = SIGNED(64, rs);
	RzILOpPure *rt64 = SIGNED(64, rt);
	RzILOpPure *prod = MUL(rs64, rt64);

	// cast hi and lo to 64 bits
	// we need to take logical or of these two to form a 64 bit value
	RzILOpPure *hi64 = CAST(64, IL_FALSE, VARG(MIPS_REG_HI));
	RzILOpPure *lo64 = CAST(64, IL_FALSE, VARG(MIPS_REG_LO));
	RzILOpPure *hi_lo = LOGOR(SHIFTL0(hi64, U8(32)), lo64);

	// add product and hi_lo concatenated value
	RzILOpEffect *res = SETL("temp", SUB(hi_lo, prod));

	// cast back to 32 bits
	RzILOpPure *res_hi = TRUNC32(SHIFTR0(VARL("temp"), U8(32)));
	RzILOpPure *res_lo = TRUNC32(VARL("temp"));

	RzILOpEffect *set_hi = SETG(MIPS_REG_HI, res_hi);
	RzILOpEffect *set_lo = SETG(MIPS_REG_LO, res_lo);

	return SEQ3(res, set_hi, set_lo);
}

static RzILOpEffect *mips_il_msubu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);

	// product is on 64 bit value so zero extend it
	RzILOpPure *rs64 = UNSIGNED(64, rs);
	RzILOpPure *rt64 = UNSIGNED(64, rt);
	RzILOpPure *prod = MUL(rs64, rt64);

	// cast hi and lo to 64 bits
	// we need to take logical or of these two to form a 64 bit value
	RzILOpPure *hi64 = CAST(64, IL_FALSE, VARG(MIPS_REG_HI));
	RzILOpPure *lo64 = CAST(64, IL_FALSE, VARG(MIPS_REG_LO));
	RzILOpPure *hi_lo = LOGOR(SHIFTL0(hi64, U8(32)), lo64);

	// subtract product to hi_lo concatenated value
	RzILOpEffect *res = SETL("temp", SUB(hi_lo, prod));

	// cast back to 32 bits
	RzILOpPure *res_hi = TRUNC32(SHIFTR0(VARL("temp"), U8(32)));
	RzILOpPure *res_lo = TRUNC32(VARL("temp"));

	RzILOpEffect *set_hi = SETG(MIPS_REG_HI, res_hi);
	RzILOpEffect *set_lo = SETG(MIPS_REG_LO, res_lo);

	return SEQ3(res, set_hi, set_lo);
}

static RzILOpEffect *mips_il_mthi(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	return SETG(MIPS_REG_HI, MIPS_REG(0));
}

static RzILOpEffect *mips_il_mtlo(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	return SETG(MIPS_REG_LO, MIPS_REG(0));
}

static RzILOpEffect *mips_il_mul(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	if (IS_ZERO_REG(1) || IS_ZERO_REG(2)) {
		// multiply by zero always returns zero.
		SETG(rd, MIPS_ZERO());
	}

	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	if (gprlen == 32) {
		// product is on 64 bit value so sign extend it
		rs = SIGNED(64, rs);
		rt = SIGNED(64, rt);
	}
	RzILOpPure *prod = MUL(rs, rt);

	// truncate to 32 bits (lo).
	rs = TRUNC32(prod);

	if (gprlen > 32) {
		// sign-extend to gprlen
		rs = SIGNED(gprlen, rs);
	}

	return SETG(rd, rs);
}

static RzILOpEffect *mips_il_mulu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	if (IS_ZERO_REG(1) || IS_ZERO_REG(2)) {
		// multiply by zero always returns zero.
		SETG(rd, MIPS_ZERO());
	}

	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	if (gprlen == 32) {
		// product is on 64 bit value so zero extend it
		rs = UNSIGNED(64, rs);
		rt = UNSIGNED(64, rt);
	}
	RzILOpPure *prod = MUL(rs, rt);

	// truncate to 32 bits (lo).
	rs = TRUNC32(prod);

	if (gprlen > 32) {
		// sign-extend to gprlen (even when unsigned)
		rs = SIGNED(gprlen, rs);
	}

	return SETG(rd, rs);
}

static RzILOpEffect *mips_il_dmul(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// 64bit only
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	if (IS_ZERO_REG(1) || IS_ZERO_REG(2)) {
		// multiply by zero always returns zero.
		SETG(rd, MIPS_ZERO());
	}

	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	// product is on 128 bit value so sign extend it
	rs = SIGNED(128, rs);
	rt = SIGNED(128, rt);
	RzILOpPure *prod = MUL(rs, rt);

	// truncate to 64 bits (lo).
	return SETG(rd, TRUNC64(prod));
}

static RzILOpEffect *mips_il_dmulu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// 64bit only
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	if (IS_ZERO_REG(1) || IS_ZERO_REG(2)) {
		// multiply by zero always returns zero.
		SETG(rd, MIPS_ZERO());
	}

	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	// product is on 128 bit value so zero extend it
	rs = UNSIGNED(128, rs);
	rt = UNSIGNED(128, rt);
	RzILOpPure *prod = MUL(rs, rt);

	// truncate to 64 bits (lo).
	return SETG(rd, TRUNC64(prod));
}

static RzILOpEffect *mips_il_muh(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	if (IS_ZERO_REG(1) || IS_ZERO_REG(2)) {
		// multiply by zero always returns zero.
		SETG(rd, MIPS_ZERO());
	}

	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	if (gprlen == 32) {
		// product is on 64 bit value so sign extend it
		rs = SIGNED(64, rs);
		rt = SIGNED(64, rt);
	}
	RzILOpPure *prod = MUL(rs, rt);

	// shift and truncate to 32 bits (hi).
	rs = TRUNC32(SHIFTR0(prod, U8(32)));

	if (gprlen > 32) {
		// sign-extend to gprlen
		rs = SIGNED(gprlen, rs);
	}

	return SETG(rd, rs);
}

static RzILOpEffect *mips_il_dmuh(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// 64bit only
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	if (IS_ZERO_REG(1) || IS_ZERO_REG(2)) {
		// multiply by zero always returns zero.
		SETG(rd, MIPS_ZERO());
	}

	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	// product is on 128 bit value so sign extend it
	rs = SIGNED(128, rs);
	rt = SIGNED(128, rt);
	RzILOpPure *prod = MUL(rs, rt);

	// shift and truncate to 64 bits (hi).
	RzILOpPure *res = TRUNC64(SHIFTR0(prod, U8(64)));
	return SETG(rd, res);
}

static RzILOpEffect *mips_il_muhu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	if (IS_ZERO_REG(1) || IS_ZERO_REG(2)) {
		// multiply by zero always returns zero.
		SETG(rd, MIPS_ZERO());
	}

	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	if (gprlen == 32) {
		// product is on 64 bit value so zero extend it
		rs = UNSIGNED(64, rs);
		rt = UNSIGNED(64, rt);
	}
	RzILOpPure *prod = MUL(rs, rt);

	// shift and truncate to 32 bits (hi).
	rs = TRUNC32(SHIFTR0(prod, U8(32)));

	if (gprlen > 32) {
		// sign-extend to gprlen (even when unsigned)
		rs = SIGNED(gprlen, rs);
	}

	return SETG(rd, rs);
}

static RzILOpEffect *mips_il_dmuhu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// 64bit only
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	if (IS_ZERO_REG(1) || IS_ZERO_REG(2)) {
		// multiply by zero always returns zero.
		SETG(rd, MIPS_ZERO());
	}

	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	// product is on 128 bit value so zero extend it
	rs = UNSIGNED(128, rs);
	rt = UNSIGNED(128, rt);
	RzILOpPure *prod = MUL(rs, rt);

	// shift and truncate to 64 bits (hi).
	RzILOpPure *res = TRUNC64(SHIFTR0(prod, U8(64)));
	return SETG(rd, res);
}

static RzILOpEffect *mips_il_mult(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (IS_ZERO_REG(0) || IS_ZERO_REG(1)) {
		// multiply by zero always returns zero.
		RzILOpEffect *set_hi = SETG(MIPS_REG_HI, MIPS_ZERO());
		RzILOpEffect *set_lo = SETG(MIPS_REG_LO, MIPS_ZERO());
		return SEQ2(set_hi, set_lo);
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);

	// product is on 64 bit value so sign extend it
	RzILOpPure *rs64 = SIGNED(64, rs);
	RzILOpPure *rt64 = SIGNED(64, rt);
	RzILOpPure *prod = MUL(rs64, rt64);

	// store result in temp
	RzILOpEffect *res = SETL("temp", prod);

	// cast back to 32 bits
	RzILOpPure *res_hi = TRUNC32(SHIFTR0(VARL("temp"), U8(32)));
	RzILOpPure *res_lo = TRUNC32(VARL("temp"));

	RzILOpEffect *set_hi = SETG(MIPS_REG_HI, res_hi);
	RzILOpEffect *set_lo = SETG(MIPS_REG_LO, res_lo);

	return SEQ3(res, set_hi, set_lo);
}

static RzILOpEffect *mips_il_dmult(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// 64bit only
	if (IS_ZERO_REG(0) || IS_ZERO_REG(1)) {
		// multiply by zero always returns zero.
		RzILOpEffect *set_hi = SETG(MIPS_REG_HI, MIPS_ZERO());
		RzILOpEffect *set_lo = SETG(MIPS_REG_LO, MIPS_ZERO());
		return SEQ2(set_hi, set_lo);
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);

	// product is on 128 bit value so sign extend it
	RzILOpPure *rs128 = SIGNED(128, rs);
	RzILOpPure *rt128 = SIGNED(128, rt);
	RzILOpPure *prod = MUL(rs128, rt128);

	// store result in temp
	RzILOpEffect *res = SETL("temp", prod);

	// cast back to 64 bits
	RzILOpPure *res_hi = TRUNC64(SHIFTR0(VARL("temp"), U8(64)));
	RzILOpPure *res_lo = TRUNC64(VARL("temp"));

	RzILOpEffect *set_hi = SETG(MIPS_REG_HI, res_hi);
	RzILOpEffect *set_lo = SETG(MIPS_REG_LO, res_lo);

	return SEQ3(res, set_hi, set_lo);
}

static RzILOpEffect *mips_il_multu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (IS_ZERO_REG(0) || IS_ZERO_REG(1)) {
		// multiply by zero always returns zero.
		RzILOpEffect *set_hi = SETG(MIPS_REG_HI, MIPS_ZERO());
		RzILOpEffect *set_lo = SETG(MIPS_REG_LO, MIPS_ZERO());
		return SEQ2(set_hi, set_lo);
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);

	// product is on 64 bit value so zero extend it
	RzILOpPure *rs64 = UNSIGNED(64, rs);
	RzILOpPure *rt64 = UNSIGNED(64, rt);
	RzILOpPure *prod = MUL(rs64, rt64);

	// store result in temp
	RzILOpEffect *res = SETL("temp", prod);

	// cast back to 32 bits
	RzILOpPure *res_hi = TRUNC32(SHIFTR0(VARL("temp"), U8(32)));
	RzILOpPure *res_lo = TRUNC32(VARL("temp"));

	RzILOpEffect *set_hi = SETG(MIPS_REG_HI, res_hi);
	RzILOpEffect *set_lo = SETG(MIPS_REG_LO, res_lo);

	return SEQ3(res, set_hi, set_lo);
}

static RzILOpEffect *mips_il_dmultu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (IS_ZERO_REG(0) || IS_ZERO_REG(1)) {
		// multiply by zero always returns zero.
		RzILOpEffect *set_hi = SETG(MIPS_REG_HI, MIPS_ZERO());
		RzILOpEffect *set_lo = SETG(MIPS_REG_LO, MIPS_ZERO());
		return SEQ2(set_hi, set_lo);
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);

	// product is on 128 bit value so zero extend it
	RzILOpPure *rs128 = UNSIGNED(128, rs);
	RzILOpPure *rt128 = UNSIGNED(128, rt);
	RzILOpPure *prod = MUL(rs128, rt128);

	// store result in temp
	RzILOpEffect *res = SETL("temp", prod);

	// cast back to 64 bits
	RzILOpPure *res_hi = TRUNC64(SHIFTR0(VARL("temp"), U8(64)));
	RzILOpPure *res_lo = TRUNC64(VARL("temp"));

	RzILOpEffect *set_hi = SETG(MIPS_REG_HI, res_hi);
	RzILOpEffect *set_lo = SETG(MIPS_REG_LO, res_lo);

	return SEQ3(res, set_hi, set_lo);
}

static RzILOpEffect *mips_il_nor(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	return SETG(rd, LOGNOT(LOGOR(rs, rt)));
}

static RzILOpEffect *mips_il_or(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	if (OPCOUNT() < 3) {
		// move
		return mips_il_move(handle, insn, gprlen);
	}

	const char *rd = REG(0);
	if (IS_ZERO_REG(1) && IS_ZERO_REG(2)) {
		RzILOpPure *zero = SN(gprlen, 0);
		return SETG(rd, zero);
	} else if (IS_ZERO_REG(1)) {
		RzILOpPure *rt = MIPS_REG(2);
		return SETG(rd, rt);
	} else if (IS_ZERO_REG(2)) {
		RzILOpPure *rs = MIPS_REG(1);
		return SETG(rd, rs);
	}

	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	return SETG(rd, LOGOR(rs, rt));
}

static RzILOpEffect *mips_il_ori(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);

	if (IS_ZERO_REG(1)) {
		// this also covers when IMM(2) is 0
		RzILOpPure *imm = MIPS_IMM(2);
		return SETG(rd, imm);
	} else if (IMM(2) == 0) {
		RzILOpPure *rs = MIPS_REG(1);
		return SETG(rd, rs);
	}

	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *imm = MIPS_IMM(2);

	return SETG(rd, LOGOR(rs, imm));
}

static RzILOpEffect *mips_il_rotr(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Rotate Word Right
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	ut32 sa = IMM(2);
	if (!sa) {
		// is just a move.
		return mips_il_move(handle, insn, gprlen);
	}

	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *left = SHIFTL0(DUP(rt), U8(gprlen - sa));
	RzILOpPure *right = SHIFTR0(rt, U8(sa));
	RzILOpPure *rotr = LOGOR(left, right);
	return SETG(rd, rotr);
}

static RzILOpEffect *mips_il_drotr32(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Doubleword Rotate Right Plus 32
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	ut32 sa = IMM(2) + 32;

	RzILOpPure *left = SHIFTL0(DUP(rt), U8(gprlen - sa));
	RzILOpPure *right = SHIFTR0(rt, U8(sa));
	RzILOpPure *rotr = LOGOR(left, right);
	return SETG(rd, rotr);
}

static RzILOpEffect *mips_il_rotrv(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Rotate Word Right Variable
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *rs = MIPS_REG(2);
	RzILOpPure *reglen = UN(gprlen, gprlen); // a number that contains its own size

	RzILOpPure *left = SHIFTL0(DUP(rt), SUB(reglen, DUP(rs)));
	RzILOpPure *right = SHIFTR0(rt, rs);
	RzILOpPure *rotr = LOGOR(left, right);
	return SETG(rd, rotr);
}

static RzILOpEffect *mips_il_sb(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *trunc = NULL;
	if (IS_ZERO_REG(0)) {
		trunc = SN(MIPS_BYTE_SIZE, 0);
	} else {
		RzILOpPure *rt = MIPS_REG(0);
		trunc = TRUNC8(rt);
	}
	RzILOpPure *offset = SN(gprlen, MEMOFFSET(1));
	RzILOpPure *base = VARG_MEMBASE(1);

	RzILOpPure *memaddr = ADD(base, offset);
	return STOREW(memaddr, trunc);
}

static RzILOpEffect *mips_il_sd(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *rt = MIPS_REG(0);
	RzILOpPure *offset = SN(gprlen, MEMOFFSET(1));
	RzILOpPure *base = VARG_MEMBASE(1);

	RzILOpPure *memaddr = ADD(base, offset);
	return STOREW(memaddr, rt);
}

static RzILOpEffect *mips_il_seb(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Sign-Extend Byte
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	RzILOpPure *rt = MIPS_REG(1);
	return SETG(REG(0), SIGNED(gprlen, UNSIGNED(MIPS_BYTE_SIZE, rt)));
}

static RzILOpEffect *mips_il_seh(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Sign-Extend Halfword
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	RzILOpPure *rt = MIPS_REG(1);
	return SETG(REG(0), SIGNED(gprlen, UNSIGNED(MIPS_HALF_SIZE, rt)));
}

static RzILOpEffect *mips_il_seleqz(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Select GPR value or zero (equal zero)
	// rd = rt == 0 ? rs : 0
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	return BRANCH(IS_ZERO(rt), SETG(REG(0), rs), SETG(REG(0), MIPS_ZERO()));
}

static RzILOpEffect *mips_il_selnez(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Select GPR value or zero (not equal zero)
	// rd = rt != 0 ? rs : 0
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	return BRANCH(IS_ZERO(rt), SETG(REG(0), MIPS_ZERO()), SETG(REG(0), rs));
}

static RzILOpEffect *mips_il_sh(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *trunc = NULL;
	if (IS_ZERO_REG(0)) {
		trunc = SN(MIPS_HALF_SIZE, 0);
	} else {
		RzILOpPure *rt = MIPS_REG(0);
		trunc = TRUNC16(rt);
	}
	RzILOpPure *offset = SN(gprlen, MEMOFFSET(1));
	RzILOpPure *base = VARG_MEMBASE(1);

	RzILOpPure *memaddr = ADD(base, offset);
	return STOREW(memaddr, trunc);
}

static RzILOpEffect *mips_il_sll(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (OPCOUNT() < 3 || IS_ZERO_REG(0)) {
		return NOP();
	}

	if (!IMM(2)) {
		return mips_il_move(handle, insn, gprlen);
	}

	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *sa = MIPS_IMM(2);

	return SETG(rd, SHIFTL0(rt, sa));
}

static RzILOpEffect *mips_il_dsll32(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	//  Doubleword Shift Left Logical Plus 32
	if (OPCOUNT() < 3 || IS_ZERO_REG(0)) {
		return NOP();
	}

	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *sa = UN(gprlen, IMM(2) + 32);

	return SETG(rd, SHIFTL0(rt, sa));
}

static RzILOpEffect *mips_il_sllv(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (OPCOUNT() < 3 || IS_ZERO_REG(0)) {
		return NOP();
	}

	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *rs = MIPS_REG(2);

	return SETG(rd, SHIFTL0(rt, rs));
}

static RzILOpEffect *mips_il_slt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(1);

	RzILOpPure *ult = SLT(rs, rt);
	return SETG(rd, BOOL_TO_BV(ult, gprlen));
}

static RzILOpEffect *mips_il_slti(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *imm = MIPS_IMM(2);

	RzILOpPure *ult = SLT(rs, imm);
	return SETG(rd, BOOL_TO_BV(ult, gprlen));
}

static RzILOpEffect *mips_il_sltiu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *imm = MIPS_IMM(2);

	RzILOpPure *ult = ULT(rs, imm);
	return SETG(rd, BOOL_TO_BV(ult, gprlen));
}

static RzILOpEffect *mips_il_sltu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	RzILOpPure *ult = ULT(rs, rt);
	return SETG(rd, BOOL_TO_BV(ult, gprlen));
}

static RzILOpEffect *mips_il_sra(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	if (!IMM(2)) {
		// is a move
		return mips_il_move(handle, insn, gprlen);
	}

	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *sa = MIPS_IMM(2);

	return SETG(rd, SHIFTRA(rt, sa));
}

static RzILOpEffect *mips_il_dsra32(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Doubleword Shift Right Arithmetic Plus 32
	if (OPCOUNT() < 3 || IS_ZERO_REG(0)) {
		return NOP();
	}

	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *sa = UN(gprlen, IMM(2) + 32);

	return SETG(rd, SHIFTRA(rt, sa));
}

static RzILOpEffect *mips_il_srav(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *sa = MIPS_REG(2);

	return SETG(rd, SHIFTRA(rt, sa));
}

static RzILOpEffect *mips_il_srl(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	if (!IMM(2)) {
		// is a move
		return mips_il_move(handle, insn, gprlen);
	}

	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *sa = MIPS_IMM(2);

	return SETG(rd, SHIFTR0(rt, sa));
}

static RzILOpEffect *mips_il_dsrl32(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Doubleword Shift Right Logical Plus 32
	if (OPCOUNT() < 3 || IS_ZERO_REG(0)) {
		return NOP();
	}

	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *sa = UN(gprlen, IMM(2) + 32);

	return SETG(rd, SHIFTR0(rt, sa));
}

static RzILOpEffect *mips_il_srlv(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *sa = MIPS_REG(2);

	return SETG(rd, SHIFTR0(rt, sa));
}

static RzILOpEffect *mips_il_sub(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	return SETG(rd, SUB(rs, rt));
}

static RzILOpEffect *mips_il_negu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *zero = MIPS_ZERO();
	RzILOpPure *rt = MIPS_REG(1);

	return SETG(rd, SUB(zero, rt));
}

static RzILOpEffect *mips_il_subu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	if (OPCOUNT() < 3) {
		// negu
		return mips_il_negu(handle, insn, gprlen);
	}

	// TODO: handle unsigness.
	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	return SETG(rd, SUB(rs, rt));
}

static RzILOpEffect *mips_il_sw(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *rt = NULL;
	if (IS_ZERO_REG(0)) {
		rt = SN(MIPS_WORD_SIZE, 0);
	} else {
		rt = MIPS_REG(0);
		if (gprlen > 32) {
			rt = TRUNC32(rt);
		}
	}

	RzILOpPure *offset = SN(gprlen, MEMOFFSET(1));
	RzILOpPure *base = VARG_MEMBASE(1);

	RzILOpPure *memaddr = ADD(base, offset);
	return STOREW(memaddr, rt);
}

static RzILOpEffect *mips_il_swl(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Store Word Left
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_sdl(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Store Doubleword Left
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_swr(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Store Word Right
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_sdr(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Store Doubleword Right
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_wsbh(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Word Swap Bytes Within Halfwords
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_dsbh(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Doubleword Swap Bytes Within Halfwords
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_dshd(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Doubleword Swap Halfwords Within Doublewords
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_xor(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);

	return SETG(rd, LOGXOR(rs, rt));
}

static RzILOpEffect *mips_il_xori(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *imm = MIPS_IMM(2);

	return SETG(rd, LOGXOR(rs, imm));
}
