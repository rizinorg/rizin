// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>

typedef struct mips_reg {
	const char *name;
	ut32 number;
} MipsReg;

typedef bool (*mips_encode)(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be);

typedef struct mips_op {
	mips_encode encoder;
	ut32 opcode;
	const char *mnemonic;
} MipsOp;

// clang-format off
const MipsReg mips_registers[] = {
	{ "r0", 0 }, { "zero", 0 }, { "0", 0 },
	{ "at", 1 }, { "r1", 1 }, { "1", 1 },
	{ "v0", 2 }, { "r2", 2 }, { "2", 2 },
	{ "v1", 3 }, { "r3", 3 }, { "3", 3 },
	{ "a0", 4 }, { "r4", 4 }, { "4", 4 },
	{ "a1", 5 }, { "r5", 5 }, { "5", 5 },
	{ "a2", 6 }, { "r6", 6 }, { "6", 6 },
	{ "a3", 7 }, { "r7", 7 }, { "7", 7 },
	{ "t0", 8 }, { "r8", 8 }, { "8", 8 },
	{ "t1", 9 }, { "r9", 9 }, { "9", 9 },
	{ "t2", 10 }, { "r10", 10 }, { "10", 10 },
	{ "t3", 11 }, { "r11", 11 }, { "11", 11 },
	{ "t4", 12 }, { "r12", 12 }, { "12", 12 },
	{ "t5", 13 }, { "r13", 13 }, { "13", 13 },
	{ "t6", 14 }, { "r14", 14 }, { "14", 14 },
	{ "t7", 15 }, { "r15", 15 }, { "15", 15 },
	{ "s0", 16 }, { "r16", 16 }, { "16", 16 },
	{ "s1", 17 }, { "r17", 17 }, { "17", 17 },
	{ "s2", 18 }, { "r18", 18 }, { "18", 18 },
	{ "s3", 19 }, { "r19", 19 }, { "19", 19 },
	{ "s4", 20 }, { "r20", 20 }, { "20", 20 },
	{ "s5", 21 }, { "r21", 21 }, { "21", 21 },
	{ "s6", 22 }, { "r22", 22 }, { "22", 22 },
	{ "s7", 23 }, { "r23", 23 }, { "23", 23 },
	{ "t8", 24 }, { "r24", 24 }, { "24", 24 },
	{ "t9", 25 }, { "r25", 25 }, { "25", 25 },
	{ "k0", 26 }, { "r26", 26 }, { "26", 26 },
	{ "k1", 27 }, { "r27", 27 }, { "27", 27 },
	{ "gp", 28 }, { "r28", 28 }, { "28", 28 },
	{ "sp", 29 }, { "r29", 29 }, { "29", 29 },
	{ "fp", 30 }, { "r30", 30 }, { "s8", 30 }, { "30", 30 },
	{ "ra", 31 }, { "r31", 31 }, { "31", 31 },
};

const MipsReg mips_fcc_registers[] = {
	{ "fcc0", 0 }, { "0", 0 },
	{ "fcc1", 1 }, { "1", 1 },
	{ "fcc2", 2 }, { "2", 2 },
	{ "fcc3", 3 }, { "3", 3 },
	{ "fcc4", 4 }, { "4", 4 },
	{ "fcc5", 5 }, { "5", 5 },
};
// clang-format on

static bool mips_op_unsigned(const char *str_imm, ut32 *uimm, ut32 limit) {
	if (RZ_STR_ISEMPTY(str_imm)) {
		return false;
	}

	ut32 number = strtoull(str_imm, NULL, 0);
	if (number > limit) {
		return false;
	}

	*uimm = number;
	return true;
}

static bool mips_op_signed(const char *str_imm, st32 *simm, st32 min, st32 max) {
	if (RZ_STR_ISEMPTY(str_imm)) {
		return false;
	}

	st32 number = strtoll(str_imm, NULL, 0);
	if (number > max || number < min) {
		return false;
	}

	*simm = number;
	return true;
}

static bool mips_op_gpr(const char *reg, ut32 *reg_no) {
	if (RZ_STR_ISEMPTY(reg)) {
		return false;
	} else if (reg[0] == '$') {
		reg++;
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(mips_registers); ++i) {
		if (RZ_STR_NE(reg, mips_registers[i].name)) {
			continue;
		}
		*reg_no = mips_registers[i].number;
		return true;
	}
	return false;
}

static bool mips_op_fcc(const char *reg, ut32 *reg_no) {
	if (RZ_STR_ISEMPTY(reg)) {
		return false;
	} else if (reg[0] == '$') {
		reg++;
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(mips_fcc_registers); ++i) {
		if (RZ_STR_NE(reg, mips_fcc_registers[i].name)) {
			continue;
		}
		*reg_no = mips_fcc_registers[i].number;
		return true;
	}
	return false;
}

/* nop, syscall, eret */
static bool mips_op_kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	rz_write_ble32(buffer, opcode, be);
	return true;
}

/* add, sub, addu, subu, mul, and, or, xor, slt, sltu, movn, movz */
static bool mips_op_kkkkkksssssffffftttttkkkkkkkkkkk(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rs = 0, rt = 0, rf = 0;

	const char *reg_s = rz_list_get_n(tokens, 1);
	const char *reg_t = rz_list_get_n(tokens, 2);
	const char *reg_f = rz_list_get_n(tokens, 3);
	if (!mips_op_gpr(reg_s, &rs) ||
		!mips_op_gpr(reg_t, &rt) ||
		!mips_op_gpr(reg_f, &rf)) {
		return false;
	}

	assembled |= (rs << 21);
	assembled |= (rf << 16);
	assembled |= (rt << 11);

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* nor */
static bool mips_op_kkkkkkffffftttttssssskkkkkkkkkkk(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rs = 0, rt = 0, rf = 0;

	const char *reg_s = rz_list_get_n(tokens, 1);
	const char *reg_f = rz_list_get_n(tokens, 2);
	const char *reg_t = rz_list_get_n(tokens, 3);
	if (!mips_op_gpr(reg_s, &rs) ||
		!mips_op_gpr(reg_t, &rt) ||
		!mips_op_gpr(reg_f, &rf)) {
		return false;
	}

	assembled |= (rf << 21);
	assembled |= (rt << 16);
	assembled |= (rs << 11);

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* div, divu */
static bool mips_op_kkkkkkfffffssssstttttkkkkkkkkkkk(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rs = 0, rt = 0, rf = 0;

	const char *reg_s = rz_list_get_n(tokens, 1);
	const char *reg_f = rz_list_get_n(tokens, 2);
	const char *reg_t = rz_list_get_n(tokens, 3);
	if (!mips_op_gpr(reg_s, &rs) ||
		!mips_op_gpr(reg_t, &rt) ||
		!mips_op_gpr(reg_f, &rf)) {
		return false;
	}

	assembled |= (rt << 21);
	assembled |= (rf << 16);
	assembled |= (rs << 11);

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* addi, addiu, andi, ori, xori, slti, sltiu */
static bool mips_op_kkkkkksssssffffftttttttttttttttt(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rs = 0, rf = 0, imm = 0;

	const char *reg_s = rz_list_get_n(tokens, 1);
	const char *reg_f = rz_list_get_n(tokens, 2);
	const char *imm_n = rz_list_get_n(tokens, 3);
	if (!mips_op_gpr(reg_s, &rs) ||
		!mips_op_gpr(reg_f, &rf) ||
		!mips_op_signed(imm_n, (st32 *)&imm, ST16_MIN, ST16_MAX)) {
		return false;
	}

	imm &= 0xffffu;
	assembled |= (rs << 16);
	assembled |= (rf << 21);
	assembled |= imm;

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* mult, multu, madd, maddu, msub, msubu */
static bool mips_op_kkkkkkfffffssssskkkkkkkkkkkkkkkk(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rs = 0, rf = 0;

	const char *reg_s = rz_list_get_n(tokens, 1);
	const char *reg_f = rz_list_get_n(tokens, 2);
	if (!mips_op_gpr(reg_s, &rs) ||
		!mips_op_gpr(reg_f, &rf)) {
		return false;
	}

	assembled |= (rs << 16);
	assembled |= (rf << 21);

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* teq, tne, tge, tgeu, tlt, tltu */
static bool mips_op_kkkkkksssssfffffkkkkkkkkkkkkkkkk(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rs = 0, rf = 0;

	const char *reg_s = rz_list_get_n(tokens, 1);
	const char *reg_f = rz_list_get_n(tokens, 2);
	if (!mips_op_gpr(reg_s, &rs) ||
		!mips_op_gpr(reg_f, &rf)) {
		return false;
	}

	assembled |= (rs << 21);
	assembled |= (rf << 16);

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* mfhi, mflo */
static bool mips_op_kkkkkkkkkkkkkkkkfffffkkkkkkkkkkk(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rf = 0;

	const char *reg_f = rz_list_get_n(tokens, 1);
	if (!mips_op_gpr(reg_f, &rf)) {
		return false;
	}

	assembled |= (rf << 11);

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* mthi, mtlo, jr */
static bool mips_op_kkkkkkfffffkkkkkkkkkkkkkkkkkkkkk(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rf = 0;

	const char *reg_f = rz_list_get_n(tokens, 1);
	if (!mips_op_gpr(reg_f, &rf)) {
		return false;
	}

	assembled |= (rf << 21);

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* sll, srl, sra */
static bool mips_op_kkkkkkkkkkktttttdddddssssskkkkkk(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rt = 0, rf = 0, uimm = 0;

	const char *reg_t = rz_list_get_n(tokens, 1);
	const char *reg_f = rz_list_get_n(tokens, 2);
	const char *imm_n = rz_list_get_n(tokens, 3);
	if (!mips_op_gpr(reg_t, &rt) ||
		!mips_op_gpr(reg_f, &rf) ||
		!mips_op_unsigned(imm_n, &uimm, 31)) {
		return false;
	}

	assembled |= (rt << 11);
	assembled |= (rf << 16);
	assembled |= (uimm << 6);

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* sllv, srav, srlv */
static bool mips_op_kkkkkkssssstttttdddddkkkkkkkkkkk(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rd = 0, rt = 0, rs = 0;

	const char *reg_d = rz_list_get_n(tokens, 1);
	const char *reg_t = rz_list_get_n(tokens, 2);
	const char *reg_s = rz_list_get_n(tokens, 3);
	if (!mips_op_gpr(reg_d, &rd) ||
		!mips_op_gpr(reg_t, &rt) ||
		!mips_op_gpr(reg_s, &rs)) {
		return false;
	}

	assembled |= (rd << 21);
	assembled |= (rt << 16);
	assembled |= (rs << 11);

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* lw, lwl, lwr, sw, swl, swr, lb, lh, lhu, lbu, sb, sh */
static bool mips_op_kkkkkktttttfffffssssssssssssssss(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rt = 0, offset = 0, base = 0;

	const char *reg_t = rz_list_get_n(tokens, 1);
	const char *reg_o = rz_list_get_n(tokens, 2);
	const char *reg_b = rz_list_get_n(tokens, 3);

	if (!mips_op_gpr(reg_t, &rt) ||
		!mips_op_signed(reg_o, (st32 *)&offset, ST16_MIN, ST16_MAX) ||
		!mips_op_gpr(reg_b, &base)) {
		return false;
	}

	offset &= 0xffffu;
	assembled |= (base << 21);
	assembled |= (rt << 16);
	assembled |= offset;

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* lui */
static bool mips_op_kkkkkkkkkkkfffffssssssssssssssss(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rs = 0, imm = 0;

	const char *reg_s = rz_list_get_n(tokens, 1);
	const char *imm_n = rz_list_get_n(tokens, 2);
	if (!mips_op_gpr(reg_s, &rs) ||
		!mips_op_signed(imm_n, (st32 *)&imm, ST16_MIN, ST16_MAX)) {
		return false;
	}

	imm &= 0xffffu;
	assembled |= (rs << 16);
	assembled |= imm;

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* beq, bne */
static bool mips_op_kkkkkkfffffssssstttttttttttttttt(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rs = 0, rt = 0, imm = 0;

	const char *reg_s = rz_list_get_n(tokens, 1);
	const char *reg_t = rz_list_get_n(tokens, 2);
	const char *imm_n = rz_list_get_n(tokens, 3);
	if (!mips_op_gpr(reg_s, &rs) ||
		!mips_op_gpr(reg_t, &rt) ||
		!mips_op_signed(imm_n, (st32 *)&imm, (((ut32)ST16_MIN) << 2), (ST16_MAX << 2))) {
		return false;
	}

	imm -= (4 + pc);
	imm >>= 2;
	imm &= 0xffffu;

	assembled |= (rs << 21);
	assembled |= (rt << 16);
	assembled |= imm;

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* bgez, bgezal, bgtz, blez, bltz, bltzal */
static bool mips_op_kkkkkkfffffkkkkkssssssssssssssss(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rs = 0, imm = 0;

	const char *reg_s = rz_list_get_n(tokens, 1);
	const char *imm_n = rz_list_get_n(tokens, 2);
	if (!mips_op_gpr(reg_s, &rs) ||
		!mips_op_signed(imm_n, (st32 *)&imm, (((ut32)ST16_MIN) << 2), (ST16_MAX << 2))) {
		return false;
	}

	imm -= (4 + pc);
	imm >>= 2;
	imm &= 0xffffu;

	assembled |= (rs << 21);
	assembled |= imm;

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* teqi, tnei, tgei, tgeiu, tlti, tltiu */
static bool mips_op_kkkkkkssssskkkkkiiiiiiiiiiiiiiii(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rs = 0, imm = 0;

	const char *reg_s = rz_list_get_n(tokens, 1);
	const char *imm_n = rz_list_get_n(tokens, 2);
	if (!mips_op_gpr(reg_s, &rs) ||
		!mips_op_signed(imm_n, (st32 *)&imm, ST16_MIN, ST16_MAX)) {
		return false;
	}

	imm &= 0xffffu;
	assembled |= (rs << 21);
	assembled |= imm;

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* jalr */
static bool mips_op_kkkkkkssssskkkkkfffffkkkkkkkkkkk(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	// JALR rd, rs (normal form)
	// JALR rs (rd = 31 implied)
	ut32 assembled = opcode;
	ut32 rs = 0, rd = 31;
	const size_t n_toks = rz_list_length(tokens);

	if (n_toks == 3) {
		const char *reg_d = rz_list_get_n(tokens, 1);
		const char *reg_s = rz_list_get_n(tokens, 2);
		if (!mips_op_gpr(reg_d, &rd) ||
			!mips_op_gpr(reg_s, &rs)) {
			return false;
		}
	} else {
		const char *reg_s = rz_list_get_n(tokens, 1);
		if (!mips_op_gpr(reg_s, &rs)) {
			return false;
		}
	}

	assembled |= (rs << 21);
	assembled |= (rd << 11);

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* movf, movt */
static bool mips_op_kkkkkkssssstttkkfffffkkkkkkkkkkk(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 rs = 0, rd = 0, fcc = 0;

	const char *reg_d = rz_list_get_n(tokens, 1);
	const char *reg_s = rz_list_get_n(tokens, 2);
	if (!mips_op_gpr(reg_d, &rd) ||
		!mips_op_gpr(reg_s, &rs)) {
		return false;
	}

	if (rz_list_length(tokens) == 4) {
		const char *fcc_u = rz_list_get_n(tokens, 3);
		if (!mips_op_fcc(fcc_u, &fcc)) {
			return false;
		}
	}

	assembled |= (rs << 21);
	assembled |= (fcc << 18);
	assembled |= (rd << 11);

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* break */
static bool mips_op_kkkkkkuuuuuuuuuuffffffffffkkkkkk(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	const size_t n_toks = rz_list_length(tokens);
	if (n_toks != 3) {
		if (n_toks != 1) {
			return false;
		}
		// break without params.
		rz_write_ble32(buffer, opcode, be);
		return true;
	}

	ut32 assembled = opcode;
	ut32 uimm = 0, fimm = 0;

	const char *imm_u = rz_list_get_n(tokens, 1);
	const char *imm_f = rz_list_get_n(tokens, 2);
	if (!mips_op_unsigned(imm_u, &uimm, 0x7ffu) ||
		!mips_op_unsigned(imm_f, &fimm, 0x7ffu)) {
		return false;
	}

	assembled |= (uimm << 16);
	assembled |= (fimm << 6);

	rz_write_ble32(buffer, assembled, be);
	return true;
}

/* j, jal */
static bool mips_op_kkkkkkffffffffffffffffffffffffff(ut64 pc, ut8 *buffer, const ut32 opcode, RzList /*<char *>*/ *tokens, bool be) {
	ut32 assembled = opcode;
	ut32 imm32 = 0;
	const char *imm_n = rz_list_get_n(tokens, 1);
	if (!mips_op_signed(imm_n, (st32 *)&imm32, (st32)0xf0000000, 0x0fffffff)) {
		return false;
	}

	imm32 >>= 2;
	imm32 &= 0x3ffffffu;
	assembled |= imm32;

	rz_write_ble32(buffer, assembled, be);
	return true;
}

// clang-format off
const MipsOp mips_opcodes[] = {
	{ mips_op_kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk, 0x00000000, "nop" },       /// nop
	{ mips_op_kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk, 0x42000018, "eret" },      /// eret
	{ mips_op_kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk, 0x0000000c, "syscall" },   /// syscall
	{ mips_op_kkkkkksssssffffftttttkkkkkkkkkkk, 0x00000020, "add" },       /// add $t1, $t2, $t3
	{ mips_op_kkkkkksssssffffftttttkkkkkkkkkkk, 0x00000022, "sub" },       /// sub $t1, $t2, $t3
	{ mips_op_kkkkkksssssffffftttttttttttttttt, 0x20000000, "addi" },      /// addi $t1, $t2, -100
	{ mips_op_kkkkkksssssffffftttttkkkkkkkkkkk, 0x00000021, "addu" },      /// addu $t1, $t2, $t3
	{ mips_op_kkkkkksssssffffftttttkkkkkkkkkkk, 0x00000023, "subu" },      /// subu $t1, $t2, $t3
	{ mips_op_kkkkkksssssffffftttttttttttttttt, 0x24000000, "addiu" },     /// addiu $t1, $t2, -100
	{ mips_op_kkkkkkfffffssssskkkkkkkkkkkkkkkk, 0x00000018, "mult" },      /// mult $t1, $t2
	{ mips_op_kkkkkkfffffssssskkkkkkkkkkkkkkkk, 0x00000019, "multu" },     /// multu $t1, $t2
	{ mips_op_kkkkkksssssffffftttttkkkkkkkkkkk, 0x70000002, "mul" },       /// mul $t1, $t2, $t3
	{ mips_op_kkkkkkfffffssssskkkkkkkkkkkkkkkk, 0x70000000, "madd" },      /// madd $t1, $t2
	{ mips_op_kkkkkkfffffssssskkkkkkkkkkkkkkkk, 0x70000001, "maddu" },     /// maddu $t1, $t2
	{ mips_op_kkkkkkfffffssssskkkkkkkkkkkkkkkk, 0x70000004, "msub" },      /// msub $t1, $t2
	{ mips_op_kkkkkkfffffssssskkkkkkkkkkkkkkkk, 0x70000005, "msubu" },     /// msubu $t1, $t2
	{ mips_op_kkkkkkfffffssssstttttkkkkkkkkkkk, 0x0000001a, "div" },       /// div $t1, $t2
	{ mips_op_kkkkkkfffffssssstttttkkkkkkkkkkk, 0x0000001b, "divu" },      /// divu $t1, $t2
	{ mips_op_kkkkkkkkkkkkkkkkfffffkkkkkkkkkkk, 0x00000010, "mfhi" },      /// mfhi $t1
	{ mips_op_kkkkkkkkkkkkkkkkfffffkkkkkkkkkkk, 0x00000012, "mflo" },      /// mflo $t1
	{ mips_op_kkkkkkfffffkkkkkkkkkkkkkkkkkkkkk, 0x00000011, "mthi" },      /// mthi $t1
	{ mips_op_kkkkkkfffffkkkkkkkkkkkkkkkkkkkkk, 0x00000013, "mtlo" },      /// mtlo $t1
	{ mips_op_kkkkkksssssffffftttttkkkkkkkkkkk, 0x00000024, "and" },       /// and $t1, $t2, $t3
	{ mips_op_kkkkkksssssffffftttttkkkkkkkkkkk, 0x00000025, "or" },        /// or $t1, $t2, $t3
	{ mips_op_kkkkkksssssffffftttttttttttttttt, 0x30000000, "andi" },      /// andi $t1, $t2,100
	{ mips_op_kkkkkksssssffffftttttttttttttttt, 0x34000000, "ori" },       /// ori $t1, $t2,100
	{ mips_op_kkkkkkffffftttttssssskkkkkkkkkkk, 0x00000027, "nor" },       /// nor $t1, $t2, $t3
	{ mips_op_kkkkkksssssffffftttttkkkkkkkkkkk, 0x00000026, "xor" },       /// xor $t1, $t2, $t3
	{ mips_op_kkkkkksssssffffftttttttttttttttt, 0x38000000, "xori" },      /// xori $t1, $t2,100
	{ mips_op_kkkkkkkkkkktttttdddddssssskkkkkk, 0x00000000, "sll" },       /// sll $t1, $t2,10
	{ mips_op_kkkkkkssssstttttdddddkkkkkkkkkkk, 0x00000004, "sllv" },      /// sllv $t1, $t2, $t3
	{ mips_op_kkkkkkkkkkktttttdddddssssskkkkkk, 0x00000002, "srl" },       /// srl $t1, $t2,10
	{ mips_op_kkkkkkkkkkktttttdddddssssskkkkkk, 0x00000003, "sra" },       /// sra $t1, $t2,10
	{ mips_op_kkkkkkssssstttttdddddkkkkkkkkkkk, 0x00000007, "srav" },      /// srav $t1, $t2, $t3
	{ mips_op_kkkkkkssssstttttdddddkkkkkkkkkkk, 0x00000006, "srlv" },      /// srlv $t1, $t2, $t3
	{ mips_op_kkkkkktttttfffffssssssssssssssss, 0x8c000000, "lw" },        /// lw $t1, -100($t2)
	{ mips_op_kkkkkktttttfffffssssssssssssssss, 0x88000000, "lwl" },       /// lwl $t1, -100($t2)
	{ mips_op_kkkkkktttttfffffssssssssssssssss, 0x98000000, "lwr" },       /// lwr $t1, -100($t2)
	{ mips_op_kkkkkktttttfffffssssssssssssssss, 0xac000000, "sw" },        /// sw $t1, -100($t2)
	{ mips_op_kkkkkktttttfffffssssssssssssssss, 0xa8000000, "swl" },       /// swl $t1, -100($t2)
	{ mips_op_kkkkkktttttfffffssssssssssssssss, 0xb8000000, "swr" },       /// swr $t1, -100($t2)
	{ mips_op_kkkkkkkkkkkfffffssssssssssssssss, 0x3c000000, "lui" },       /// lui $t1,100
	{ mips_op_kkkkkkfffffssssstttttttttttttttt, 0x10000000, "beq" },       /// beq $t1, $t2, label
	{ mips_op_kkkkkkfffffssssstttttttttttttttt, 0x14000000, "bne" },       /// bne $t1, $t2, label
	{ mips_op_kkkkkkfffffkkkkkssssssssssssssss, 0x04010000, "bgez" },      /// bgez $t1, label
	{ mips_op_kkkkkkfffffkkkkkssssssssssssssss, 0x04110000, "bgezal" },    /// bgezal $t1, label
	{ mips_op_kkkkkkfffffkkkkkssssssssssssssss, 0x1c000000, "bgtz" },      /// bgtz $t1, label
	{ mips_op_kkkkkkfffffkkkkkssssssssssssssss, 0x18000000, "blez" },      /// blez $t1, label
	{ mips_op_kkkkkkfffffkkkkkssssssssssssssss, 0x04000000, "bltz" },      /// bltz $t1, label
	{ mips_op_kkkkkkfffffkkkkkssssssssssssssss, 0x04100000, "bltzal" },    /// bltzal $t1, label
	{ mips_op_kkkkkksssssffffftttttkkkkkkkkkkk, 0x0000002a, "slt" },       /// slt $t1, $t2, $t3
	{ mips_op_kkkkkksssssffffftttttkkkkkkkkkkk, 0x0000002b, "sltu" },      /// sltu $t1, $t2, $t3
	{ mips_op_kkkkkksssssffffftttttttttttttttt, 0x28000000, "slti" },      /// slti $t1, $t2, -100
	{ mips_op_kkkkkksssssffffftttttttttttttttt, 0x2c000000, "sltiu" },     /// sltiu $t1, $t2, -100
	{ mips_op_kkkkkksssssffffftttttkkkkkkkkkkk, 0x0000000b, "movn" },      /// movn $t1, $t2, $t3
	{ mips_op_kkkkkksssssffffftttttkkkkkkkkkkk, 0x0000000a, "movz" },      /// movz $t1, $t2, $t3
	{ mips_op_kkkkkkssssstttkkfffffkkkkkkkkkkk, 0x00000001, "movf" },      /// movf $t1, $t2, 1 | movf $t1, $t2
	{ mips_op_kkkkkkssssstttkkfffffkkkkkkkkkkk, 0x00010001, "movt" },      /// movt $t1, $t2, 1 | movt $t1, $t2
	{ mips_op_kkkkkkuuuuuuuuuuffffffffffkkkkkk, 0x0000000d, "break" },     /// break 0, 100 | break
	{ mips_op_kkkkkkffffffffffffffffffffffffff, 0x08000000, "j" },         /// j target
	{ mips_op_kkkkkkfffffkkkkkkkkkkkkkkkkkkkkk, 0x00000008, "jr" },        /// jr $t1
	{ mips_op_kkkkkkffffffffffffffffffffffffff, 0x0c000000, "jal" },       /// jal target
	{ mips_op_kkkkkkssssskkkkkfffffkkkkkkkkkkk, 0x00000009, "jalr" },      /// jalr $t1, $t2
	{ mips_op_kkkkkktttttfffffssssssssssssssss, 0x80000000, "lb" },        /// lb $t1, -100($t2)
	{ mips_op_kkkkkktttttfffffssssssssssssssss, 0x84000000, "lh" },        /// lh $t1, -100($t2)
	{ mips_op_kkkkkktttttfffffssssssssssssssss, 0x94000000, "lhu" },       /// lhu $t1, -100($t2)
	{ mips_op_kkkkkktttttfffffssssssssssssssss, 0x90000000, "lbu" },       /// lbu $t1, -100($t2)
	{ mips_op_kkkkkktttttfffffssssssssssssssss, 0xa0000000, "sb" },        /// sb $t1, -100($t2)
	{ mips_op_kkkkkktttttfffffssssssssssssssss, 0xa4000000, "sh" },        /// sh $t1, -100($t2)
	{ mips_op_kkkkkksssssfffffkkkkkkkkkkkkkkkk, 0x00000034, "teq" },       /// teq $t1, $t2
	{ mips_op_kkkkkkssssskkkkkiiiiiiiiiiiiiiii, 0x040c0000, "teqi" },      /// teqi $t1, -100
	{ mips_op_kkkkkksssssfffffkkkkkkkkkkkkkkkk, 0x00000036, "tne" },       /// tne $t1, $t2
	{ mips_op_kkkkkkssssskkkkkiiiiiiiiiiiiiiii, 0x040e0000, "tnei" },      /// tnei $t1, -100
	{ mips_op_kkkkkksssssfffffkkkkkkkkkkkkkkkk, 0x00000030, "tge" },       /// tge $t1, $t2
	{ mips_op_kkkkkksssssfffffkkkkkkkkkkkkkkkk, 0x00000031, "tgeu" },      /// tgeu $t1, $t2
	{ mips_op_kkkkkkssssskkkkkiiiiiiiiiiiiiiii, 0x04080000, "tgei" },      /// tgei $t1, -100
	{ mips_op_kkkkkkssssskkkkkiiiiiiiiiiiiiiii, 0x04090000, "tgeiu" },     /// tgeiu $t1, -100
	{ mips_op_kkkkkksssssfffffkkkkkkkkkkkkkkkk, 0x00000032, "tlt" },       /// tlt $t1, $t2
	{ mips_op_kkkkkksssssfffffkkkkkkkkkkkkkkkk, 0x00000033, "tltu" },      /// tltu $t1, $t2
	{ mips_op_kkkkkkssssskkkkkiiiiiiiiiiiiiiii, 0x040a0000, "tlti" },      /// tlti $t1, -100
	{ mips_op_kkkkkkssssskkkkkiiiiiiiiiiiiiiii, 0x040b0000, "tltiu" },     /// tltiu $t1, -100
};
// clang-format on

RZ_IPI int mips_assemble_opcode(const char *line, ut64 pc, RzStrBuf *out, bool be) {
	// on success return instruction size.
	ut8 buffer[4] = { 0 };
	RzList /*<char *>*/ *tokens = NULL;

	if (RZ_STR_ISEMPTY(line)) {
		return false;
	}

	if (!strchr(line, ' ')) {
		const char *lines[1] = { line };
		tokens = rz_list_new_from_array((const void **)lines, 1);
	} else {
		tokens = rz_str_split_duplist_n_regex(line, ",?\\s+|\\(|\\)", 0, true);
	}

	if (rz_list_length(tokens) < 1) {
		RZ_LOG_INFO("mips: assembler failed to split line\n");
		rz_list_free(tokens);
		return false;
	}

	const char *token = rz_list_get_n(tokens, 0);
	if (RZ_STR_ISEMPTY(token)) {
		return -1;
	}

	int ret = -1;

	for (size_t i = 0; i < RZ_ARRAY_SIZE(mips_opcodes); ++i) {
		if (RZ_STR_NE(token, mips_opcodes[i].mnemonic)) {
			continue;
		}

		mips_encode encoder = mips_opcodes[i].encoder;
		const ut32 opcode = mips_opcodes[i].opcode;
		if (encoder(pc, buffer, opcode, tokens, be) &&
			rz_strbuf_setbin(out, buffer, sizeof(buffer))) {
			ret = 4;
			break;
		}
	}

	rz_list_free(tokens);
	return ret;
}