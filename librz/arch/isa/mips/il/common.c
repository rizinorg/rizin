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
#define TRUNC32(x)       UNSIGNED(MIPS_WORD_SIZE, x)
#define TRUNC16(x)       UNSIGNED(MIPS_HALF_SIZE, x)
#define TRUNC8(x)        UNSIGNED(MIPS_BYTE_SIZE, x)

#define BITN(x, n)            SHIFTR0(LOGAND(x, UN(gprlen, (ut64)1 << (n - 1))), UN(gprlen, n - 1))
#define CHECK_OVERFLOW(r, sz) EQ(BITN(r, sz), BITN(r, sz - 1))
#define MIPS_REG(idx)         mips_get_reg(handle, insn, idx, gprlen)
#define MIPS_IMM(idx)         UN(gprlen, IMM(idx))
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
	RzILOpPure *overflow = CHECK_OVERFLOW(DUP(sum), 32);
	return BRANCH(overflow, IL_CAUSE_OVERFLOW(), SETG(rd, sum));
}

static RzILOpEffect *mips_il_addi(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *imm = MIPS_IMM(2);

	RzILOpPure *sum = SIGNED(gprlen, ADD(rs, imm));
	RzILOpPure *overflow = CHECK_OVERFLOW(DUP(sum), 32);
	return BRANCH(overflow, IL_CAUSE_OVERFLOW(), SETG(rd, sum));
}

static RzILOpEffect *mips_il_addiu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *imm = MIPS_IMM(2);
	RzILOpPure *sum = ADD(rs, imm);
	return SETG(rd, sum);
}

static RzILOpEffect *mips_il_addu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);
	RzILOpPure *sum = ADD(rs, rt);
	return SETG(rd, sum);
}

static RzILOpEffect *mips_il_and(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *rt = MIPS_REG(2);
	RzILOpPure *sum = LOGAND(rs, rt);
	return SETG(rd, sum);
}

static RzILOpEffect *mips_il_andi(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	const char *rd = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *imm = MIPS_IMM(2);
	RzILOpPure *sum = LOGAND(rs, imm);
	return SETG(rd, sum);
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

static RzILOpEffect *mips_il_bnez(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (IS_ZERO_REG(0)) {
		// never taken
		return NOP();
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *target = MIPS_IMM(1);

	return BRANCH(NON_ZERO(rs), JMP(target), NOP());
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

static RzILOpEffect *mips_il_clo(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Count Leading Ones in Word
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_clz(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Count Leading Zeros in Word
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_div(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);

	RzILOpPure *quotient = SDIV(DUP(rs), DUP(rt));
	RzILOpPure *remainder = SMOD(rs, rt);

	RzILOpEffect *set_lo = SETG(MIPS_REG_LO, quotient);
	RzILOpEffect *set_hi = SETG(MIPS_REG_HI, remainder);
	return SEQ2(set_lo, set_hi);
}

static RzILOpEffect *mips_il_divu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);

	RzILOpPure *quotient = DIV(DUP(rs), DUP(rt));
	RzILOpPure *remainder = MOD(rs, rt);

	RzILOpEffect *set_lo = SETG(MIPS_REG_LO, quotient);
	RzILOpEffect *set_hi = SETG(MIPS_REG_HI, remainder);
	return SEQ2(set_lo, set_hi);
}

static RzILOpEffect *mips_il_ext(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	// Extract Bit Field (EXT rt, rs, pos, size)
	const char *rt = REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *pos = MIPS_IMM(2);
	RzILOpPure *size = MIPS_IMM(3);

	return SETG(rt, EXTRACT32(rs, pos, size));
}

static RzILOpEffect *mips_il_ins(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

	// Insert Bit Field (INS rt, rs, pos, size)
	RzILOpPure *rt = MIPS_REG(0);
	RzILOpPure *rs = MIPS_REG(1);
	RzILOpPure *pos = MIPS_IMM(2);
	RzILOpPure *size = MIPS_IMM(3);

	return SETG(REG(0), DEPOSIT32(rt, pos, size, rs));
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

static RzILOpEffect *mips_il_lwl(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Word Left
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_lwr(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Word Right
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_madd(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);

	// product can be a 64 bit value so sign extend it
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

	// product can be a 64 bit value so zero extend it
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

	// product can be a 64 bit value so sign extend it
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

	// product can be a 64 bit value so zero extend it
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

	return SETG(rd, MUL(rs, rt));
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

	// product can be a 64 bit value so sign extend it
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

static RzILOpEffect *mips_il_multu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	if (IS_ZERO_REG(0) || IS_ZERO_REG(1)) {
		// multiply by zero always returns zero.
		RzILOpEffect *set_hi = SETG(MIPS_REG_HI, MIPS_ZERO());
		RzILOpEffect *set_lo = SETG(MIPS_REG_LO, MIPS_ZERO());
		return SEQ2(set_hi, set_lo);
	}

	RzILOpPure *rs = MIPS_REG(0);
	RzILOpPure *rt = MIPS_REG(1);

	// product can be a 64 bit value so zero extend it
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

	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	ut32 sa = IMM(2);

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

	RzILOpPure *left = SHIFTL0(DUP(rt), SUB(reglen, rs));
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

	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *sa = MIPS_IMM(2);

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

	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *sa = MIPS_IMM(2);

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
	const char *rd = REG(0);
	RzILOpPure *rt = MIPS_REG(1);
	RzILOpPure *sa = MIPS_IMM(2);

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

static RzILOpEffect *mips_il_subu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	MIPS_CHECK_IF_TARGET_IS_ZERO_REG_AND_NOP();

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

static RzILOpEffect *mips_il_swr(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Store Word Right
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_wsbh(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Word Swap Bytes Within Halfwords
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
