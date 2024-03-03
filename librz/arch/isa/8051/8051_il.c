// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-FileCopyrightText: 2022-2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_opbuilder_begin.h>
#include "8051_il.h"

static bool is_register_memory_map(ut8 reg) {
	static const ut8 hook_registers[0x100] = {
		I8051_SP,
		I8051_R0,
		I8051_R1,
		I8051_R2,
		I8051_R3,
		I8051_R4,
		I8051_R5,
		I8051_R6,
		I8051_R7,
		I8051_DPH,
		I8051_DPL,
		//	I8051_PCON,
		//	I8051_TCON,
		//	I8051_TMOD,
		//	I8051_TL0,
		//	I8051_TL1,
		//	I8051_TH0,
		//	I8051_TH1,
		I8051_PSW,
		I8051_ACC,
		I8051_B,
		//	I8051_IE,
		//	I8051_IP,
		//	I8051_P0,
		//	I8051_P1,
		//	I8051_P2,
		//	I8051_P3,
		//	I8051_SCON,
		//	I8051_SBUF,
	};
	for (int i = 0; i < sizeof(hook_registers); ++i) {
		if (hook_registers[i] == reg) {
			return true;
		}
	}
	return false;
}

static inline bool i8051_reg_is_psw_bit(ut8 reg) {
	switch (reg) {
	case I8051_Z:
	case I8051_OV:
	case I8051_RS0:
	case I8051_RS1:
	case I8051_N:
	case I8051_AC:
	case I8051_CY:
		return true;
	default:
		return false;
	}
}

static const char *i8051_reg_names[0xff] = {
	[I8051_R0] = "r0",
	[I8051_R1] = "r1",
	[I8051_R2] = "r2",
	[I8051_R3] = "r3",
	[I8051_R4] = "r4",
	[I8051_R5] = "r5",
	[I8051_R6] = "r6",
	[I8051_R7] = "r7",
	[I8051_SP] = "sp",
	[I8051_DPH] = "dph",
	[I8051_DPL] = "dpl",
	[I8051_PCON] = "pcon",
	[I8051_TCON] = "tcon",
	[I8051_TMOD] = "tmod",
	[I8051_TL0] = "tl0",
	[I8051_TL1] = "tl1",
	[I8051_TH0] = "th0",
	[I8051_TH1] = "th1",
	[I8051_PC] = "pc",
	[I8051_PSW] = "psw",
	[I8051_Z] = "z",
	[I8051_OV] = "ov",
	[I8051_RS0] = "rs0",
	[I8051_RS1] = "rs1",
	[I8051_N] = "n",
	[I8051_AC] = "ac",
	[I8051_CY] = "cy",
	[I8051_ACC] = "acc",
	[I8051_B] = "b",
	[I8051_IE] = "ie",
	[I8051_IP] = "ip",
	[I8051_P0] = "p0",
	[I8051_P1] = "p1",
	[I8051_P2] = "p2",
	[I8051_P3] = "p3",
	[I8051_SCON] = "scon",
	[I8051_SBUF] = "sbuf",
	NULL,
};

#define ADD3(a, b, c) ADD(a, ADD(b, c))
#define SUB3(a, b, c) SUB(SUB(a, b), c)
#define AND3(a, b, c) AND(a, AND(b, c))

#define LO_BYTE(x) UNSIGNED(8, x)
#define HI_BYTE(x) UNSIGNED(8, SHIFTR0(x, U16(8)))
#define BT8(x)     BOOL_TO_BV(x, 8)

static inline RzILOpPure *bv_geti(RzILOpBitVector *v, ut8 i) {
	return NON_ZERO(LOGAND(v, U8(1 << i)));
}
static inline RzILOpPure *bv_geti_bv(RzILOpBitVector *v, ut8 i) {
	return BOOL_TO_BV(bv_geti(v, i), 8);
}
static inline RzILOpPure *bv_seti_copy(RzILOpBitVector *x, ut8 i, RzILOpBitVector *v) {
	return LOGOR(LOGAND(x, LOGNOT(SHIFTL0(U8(1), U8(i)))), SHIFTL0(v, U8(i)));
}

#define VARG_8051(x) VARG(i8051_reg_names[x])

static inline RzILOpPure *i8051_reg_get_psw(I8051Register reg) {
	return bv_geti(VARG_8051(I8051_PSW), reg - I8051_PSW);
}

static inline RzILOpPure *i8051_reg_get(I8051Register reg, I8051Op *op) {
	if (reg == I8051_PC) {
		return U16(op->pc);
	}
	if (reg == I8051_DPTR) {
		return APPEND(VARG_8051(I8051_DPH), VARG_8051(I8051_DPL));
	}
	if (i8051_reg_is_psw_bit(reg)) {
		return i8051_reg_get_psw(reg);
	}
	return VARG_8051(reg);
}
#define VAL_ACC VARG_8051(I8051_ACC)
#define VAL_B   VARG_8051(I8051_B)
#define VAL_SP  VARG_8051(I8051_SP)

#define SETG_8051(x, v) SETG(i8051_reg_names[x], v)
static inline RzILOpEffect *i8051_reg_set(I8051Register reg, RzILOpBitVector *v) {
	if (reg <= 0x7) {
		return SEQ4(SETL("val", v), SETG_8051(reg, VARL("val")),
			SETL("bank", LOGAND(VARG_8051(I8051_PSW), U8(PSWMASK_RS0 | PSWMASK_RS1))),
			STORE(UNSIGNED(16, ADD(U8(reg), VARL("bank"))), VARL("val")));
	}
	if (reg == I8051_DPTR) {
		return SEQ7(SETL("dptr", v), SETL("dph'", HI_BYTE(VARL("dptr"))), SETL("dpl'", LO_BYTE(VARL("dptr"))),
			SETG_8051(I8051_DPH, VARL("dph'")), SETG_8051(I8051_DPL, VARL("dpl'")),
			STORE(U16(I8051_DPH), VARL("dph'")), STORE(U16(I8051_DPL), VARL("dpl'")));
	}
	if (i8051_reg_is_psw_bit(reg)) {
		return i8051_reg_set(I8051_PSW, bv_seti_copy(VARG_8051(I8051_PSW), reg - I8051_PSW, v));
	}
	if (is_register_memory_map(reg)) {
		return SEQ3(SETL("val", v), SETG_8051(reg, VARL("val")), STORE(U16(reg), VARL("val")));
	}
	return SETG_8051(reg, v);
}

static inline int8_t addr_to_int(ut8 addr) {
	if ((addr & 0x8000) == 0) {
		return addr;
	} else {
		return -((~addr + 1) & 0x7FFF);
	}
}
static inline uint8_t bitaddr(ut8 addr) {
	if (addr > 0x7f) {
		addr &= 0xf8;
	} else {
		addr >>= 3;
		addr += 0x20;
	}
	return addr;
}

static RzILOpPure *i8051_addressing_get(I8051OpAddressing *a) {
	switch (a->mode) {
	case I8051_ADDRESSING_REGISTER: {
		return i8051_reg_get(a->d.reg, a->op);
	}
	case I8051_ADDRESSING_DIRECT: {
		return LOAD(U16(a->d.addr));
	}
	case I8051_ADDRESSING_INDIRECT: {
		return LET("addr", UNSIGNED(16, i8051_addressing_get(a->d.indirect)),
			ITE(UGT(VARLP("addr"), U16(0x7f)),
				LOAD(ADD(VARLP("addr"), U16(0x100))),
				LOAD(VARLP("addr"))));
	}
	case I8051_ADDRESSING_IMMEDIATE:
		return U8(a->d.addr);
	case I8051_ADDRESSING_IMMEDIATE16:
		return U16(a->d.addr16);
	case I8051_ADDRESSING_RELATIVE:
		return U16(addr_to_int(a->d.addr) + (int)a->op->pc + (int)a->op->len);
	case I8051_ADDRESSING_ABSOLUTE:
	case I8051_ADDRESSING_LONG:
		return U16(a->d.addr16);
	case I8051_ADDRESSING_INDEXED: {
		return ADD(UNSIGNED(16, LOAD(UNSIGNED(16, i8051_reg_get(I8051_ACC, a->op)))), i8051_reg_get(a->d.reg, a->op));
	}
	case I8051_ADDRESSING_BIT:
		return NON_ZERO(LOADW(1, U16(a->d.addr)));
	default:
		rz_warn_if_reached();
		return NULL;
	}
}
static RzILOpEffect *i8051_addressing_set(I8051OpAddressing *a, RzILOpPure *v) {
	switch (a->mode) {
	case I8051_ADDRESSING_REGISTER: {
		return i8051_reg_set(a->d.reg, v);
	}
	case I8051_ADDRESSING_BIT: {
		ut8 addr = bitaddr(a->d.addr);
		return STORE(U16(addr), bv_seti_copy(LOAD(U16(addr)), a->d.addr & 7, v));
	}
	case I8051_ADDRESSING_DIRECT: {
		if (a->d.addr <= 0x1f) {
			I8051Register reg = a->d.addr % 0x8;
			return SEQ3(SETL("val", v),
				SETG_8051(reg, VARL("val")),
				STORE(U16(a->d.addr), VARL("val")));
		}
		if (is_register_memory_map(a->d.addr)) {
			I8051Register reg = a->d.addr;
			return SEQ3(SETL("val", v),
				SETG_8051(reg, VARL("val")),
				STORE(U16(reg), VARL("val")));
		}

		return STORE(U16(a->d.addr), v);
	}
	case I8051_ADDRESSING_INDIRECT: {
		return SEQ3(SETL("addr", UNSIGNED(16, i8051_addressing_get(a->d.indirect))),
			SETL("val", v),
			BRANCH(UGT(VARL("addr"), U16(0x7f)),
				STORE(ADD(VARL("addr"), U16(0x100)), VARL("val")),
				STORE(VARL("addr"), VARL("val"))));
	}
	default:
		RZ_LOG_DEBUG("i8051_addressing_set: invalid addressing mode %d %x\n", a->mode, a->d.addr16);
		rz_warn_if_reached();
		return NULL;
	}
}

static RzILOpPure *carryout(RzILOpBitVector *a, RzILOpBitVector *b, RzILOpBitVector *c) {
	return LOGOR(LOGAND(a, b), LOGAND(NEG(c), LOGOR(DUP(a), DUP(b))));
}

static RzILOpEffect *set_add_carry(RzILOpBitVector *a, RzILOpBitVector *b, RzILOpBitVector *c) {
	rz_return_val_if_fail(a && b && c, NULL);
	RzILOpPure *ov = OR(AND3(MSB(a), MSB(b), INV(MSB(c))), AND3(INV(MSB(DUP(a))), INV(MSB(DUP(b))), MSB(DUP(c))));
	return SEQ4(SETL("carry", carryout(DUP(a), DUP(b), DUP(c))),
		i8051_reg_set(I8051_CY, bv_geti_bv(VARL("carry"), 7)),
		i8051_reg_set(I8051_AC, bv_geti_bv(VARL("carry"), 3)),
		i8051_reg_set(I8051_OV, BT8(ov)));
}

static RzILOpPure *borrowin(RzILOpBitVector *a, RzILOpBitVector *b, RzILOpBitVector *c) {
	rz_return_val_if_fail(a && b && c, NULL);
	return LOGOR(LOGAND(NEG(a), b), LOGAND(c, LOGOR(DUP(b), NEG(DUP(a)))));
}

static RzILOpEffect *set_sub_curry(RzILOpBitVector *a, RzILOpBitVector *b, RzILOpBitVector *c) {
	rz_return_val_if_fail(a && b && c, NULL);
	RzILOpPure *ov = OR(AND(VARL("b6"), INV(VARL("b7"))), AND(INV(VARL("b6")), VARL("b7")));
	return SEQ6(SETL("borrow", borrowin(a, b, c)),
		SETL("b6", bv_geti(VARL("borrow"), 6)),
		SETL("b7", bv_geti(VARL("borrow"), 7)),
		i8051_reg_set(I8051_CY, BT8(VARL("b7"))),
		i8051_reg_set(I8051_AC, bv_geti_bv(VARL("borrow"), 3)),
		i8051_reg_set(I8051_OV, BT8(ov)));
}

static RzILOpEffect *i_add(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0] && op->argv[1], NULL);
	return SEQ4(SETL("arg1", i8051_addressing_get(op->argv[1])),
		SETL("res", ADD(VAL_ACC, VARL("arg1"))),
		set_add_carry(VAL_ACC, VARL("arg1"), VARL("res")),
		i8051_reg_set(I8051_ACC, VARL("res")));
}

static RzILOpEffect *i_addc(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0] && op->argv[1], NULL);
	return SEQ4(SETL("arg1", i8051_addressing_get(op->argv[1])),
		SETL("res", ADD3(VAL_ACC, VARL("arg1"), BOOL_TO_BV(i8051_reg_get_psw(I8051_CY), 8))),
		set_add_carry(VAL_ACC, VARL("arg1"), VARL("res")),
		i8051_reg_set(I8051_ACC, VARL("res")));
}

static RzILOpEffect *i_subb(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0] && op->argv[1], NULL);
	return SEQ4(SETL("arg1", i8051_addressing_get(op->argv[1])),
		SETL("res", SUB3(VAL_ACC, VARL("arg1"), BOOL_TO_BV(i8051_reg_get_psw(I8051_CY), 8))),
		set_sub_curry(VAL_ACC, VARL("arg1"), VARL("res")),
		i8051_reg_set(I8051_ACC, VARL("res")));
}
static RzILOpEffect *i_div(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0] && op->argv[1], NULL);
	return SEQ6(SETL("@a", i8051_addressing_get(op->argv[0])),
		SETL("@b", i8051_addressing_get(op->argv[1])),
		i8051_reg_set(I8051_ACC, DIV(VARL("@a"), VARL("@b"))),
		i8051_reg_set(I8051_B, MOD(VARL("@a"), VARL("@b"))),
		i8051_reg_set(I8051_CY, U8(0)),
		i8051_reg_set(I8051_OV, BT8(IS_ZERO(VARL("@b")))));
}
static RzILOpEffect *i_mul(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0] && op->argv[1], NULL);
	return SEQ6(SETL("v", MUL(UNSIGNED(16, VAL_ACC), UNSIGNED(16, VAL_B))),
		SETL("MSB", HI_BYTE(VARL("v"))),
		i8051_reg_set(I8051_ACC, LO_BYTE(VARL("v"))),
		i8051_reg_set(I8051_B, VARL("MSB")),
		i8051_reg_set(I8051_CY, U8(0)),
		i8051_reg_set(I8051_OV, BT8(NON_ZERO(VARL("MSB")))));
}

static RzILOpEffect *i_dec(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0], NULL);
	return SEQ2(SETL("arg0", i8051_addressing_get(op->argv[0])), i8051_addressing_set(op->argv[0], SUB(VARL("arg0"), U8(1))));
}
static RzILOpEffect *i_inc(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0], NULL);
	RzILOpPure *one = op->opcode == 0xa3 ? U16(1) : U8(1);
	return SEQ2(SETL("arg0", i8051_addressing_get(op->argv[0])), i8051_addressing_set(op->argv[0], ADD(VARL("arg0"), one)));
}

static RzILOpEffect *i_clr(I8051Op *op) {
	rz_return_val_if_fail(op, NULL);
	return i8051_addressing_set(op->argv[0], U8(0));
}
static RzILOpEffect *i_setb(I8051Op *op) {
	rz_return_val_if_fail(op, NULL);
	return i8051_addressing_set(op->argv[0], U8(1));
}

static inline bool is_bitaddr(I8051OpAddressing *a) {
	return (a->mode == I8051_ADDRESSING_REGISTER && i8051_reg_is_psw_bit(a->d.reg)) || a->mode == I8051_ADDRESSING_BIT;
}

static RzILOpEffect *i_cpl(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0], NULL);
	RzILOpPure *v = i8051_addressing_get(op->argv[0]);
	v = is_bitaddr(op->argv[0]) ? BT8(INV(v)) : LOGNOT(v);
	return i8051_addressing_set(op->argv[0], v);
}
static RzILOpEffect *i_anl(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0] && op->argv[1], NULL);
	if (is_bitaddr(op->argv[0]) || is_bitaddr(op->argv[1])) {
		return i8051_addressing_set(op->argv[0], BT8(AND(i8051_addressing_get(op->argv[0]), i8051_addressing_get(op->argv[1]))));
	}
	return i8051_addressing_set(op->argv[0], LOGAND(i8051_addressing_get(op->argv[0]), i8051_addressing_get(op->argv[1])));
}
static RzILOpEffect *i_orl(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0] && op->argv[1], NULL);
	if (is_bitaddr(op->argv[0]) || is_bitaddr(op->argv[1])) {
		return i8051_addressing_set(op->argv[0], BT8(OR(i8051_addressing_get(op->argv[0]), i8051_addressing_get(op->argv[1]))));
	}
	return i8051_addressing_set(op->argv[0], LOGOR(i8051_addressing_get(op->argv[0]), i8051_addressing_get(op->argv[1])));
}
static RzILOpEffect *i_xrl(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0] && op->argv[1], NULL);
	return i8051_addressing_set(op->argv[0], LOGXOR(i8051_addressing_get(op->argv[0]), i8051_addressing_get(op->argv[1])));
}
static RzILOpEffect *i_mov(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0] && op->argv[1], NULL);
	if (is_bitaddr(op->argv[0]) || is_bitaddr(op->argv[1])) {
		return i8051_addressing_set(op->argv[0], BT8(i8051_addressing_get(op->argv[1])));
	}
	return i8051_addressing_set(op->argv[0], i8051_addressing_get(op->argv[1]));
}
static RzILOpEffect *i_movc(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0] && op->argv[1], NULL);
	return i8051_addressing_set(op->argv[0], UNSIGNED(8, i8051_addressing_get(op->argv[1])));
}

static RzILOpEffect *i_da(I8051Op *op) {
	return SEQ7(
		SETL("s0", OR(i8051_reg_get_psw(I8051_CY), UGT(LOGAND(VAL_ACC, U8(0xf)), U8(0x9)))),
		SETL("s1", OR(VARL("s0"), UGT(LOGAND(VAL_ACC, U8(0xf0)), U8(0x90)))),
		SETL("@a", VAL_ACC),
		BRANCH(VARL("s0"), SETL("@a", ADD(VARL("@a"), U8(0x6))), NOP()),
		BRANCH(VARL("s1"), SETL("@a", ADD(VARL("@a"), U8(0x60))), NOP()),
		i8051_reg_set(I8051_CY, BT8(UGT(VARL("@a"), U8(0x99)))),
		i8051_reg_set(I8051_ACC, VARL("@a")));
}
static RzILOpEffect *i_ijmp(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0], NULL);
	return JMP(i8051_addressing_get(op->argv[0]));
}
static RzILOpEffect *i_jmp(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0], NULL);
	return JMP(ADD(UNSIGNED(16, VAL_ACC), i8051_reg_get(I8051_DPTR, op)));
}
static RzILOpEffect *i_cjne(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0] && op->argv[1], NULL);
	return BRANCH(INV(EQ(i8051_addressing_get(op->argv[0]), i8051_addressing_get(op->argv[1]))),
		JMP(i8051_addressing_get(op->argv[2])), NOP());
}
static RzILOpEffect *i_djnz(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0] && op->argv[1], NULL);
	return SEQ3(SETL("res", SUB(i8051_addressing_get(op->argv[0]), U8(1))), i8051_addressing_set(op->argv[0], VARL("res")),
		BRANCH(NON_ZERO(VARL("res")), JMP(i8051_addressing_get(op->argv[1])), NOP()));
}
static RzILOpEffect *i_jb(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0] && op->argv[1], NULL);
	return BRANCH(i8051_addressing_get(op->argv[0]), JMP(i8051_addressing_get(op->argv[1])), NOP());
}
static RzILOpEffect *i_jnb(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0] && op->argv[1], NULL);
	return BRANCH(i8051_addressing_get(op->argv[0]), JMP(i8051_addressing_get(op->argv[1])), NOP());
}
static RzILOpEffect *i_jbc(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0] && op->argv[1], NULL);
	return BRANCH(i8051_addressing_get(op->argv[0]), SEQ2(i8051_addressing_set(op->argv[0], U8(0)), JMP(i8051_addressing_get(op->argv[1]))), NOP());
}
static RzILOpEffect *i_jc(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0], NULL);
	return BRANCH(i8051_reg_get_psw(I8051_CY), JMP(i8051_addressing_get(op->argv[0])), NOP());
}
static RzILOpEffect *i_jnc(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0], NULL);
	return BRANCH(INV(i8051_reg_get_psw(I8051_CY)), JMP(i8051_addressing_get(op->argv[0])), NOP());
}
static RzILOpEffect *i_jz(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0], NULL);
	return BRANCH(IS_ZERO(VAL_ACC), JMP(i8051_addressing_get(op->argv[0])), NOP());
}
static RzILOpEffect *i_jnz(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0], NULL);
	return BRANCH(NON_ZERO(VAL_ACC), JMP(i8051_addressing_get(op->argv[0])), NOP());
}

static RzILOpEffect *i_nop() {
	return NOP();
}

static RzILOpEffect *push_stack(RzILOpPure *x, I8051Op *op) {
	return SEQ2(i8051_reg_set(I8051_SP, ADD(VAL_SP, U8(1))),
		STORE(UNSIGNED(16, VAL_SP), x));
}
static RzILOpEffect *push_stack_16(RzILOpPure *x, I8051Op *op) {
	RzILOpPure *high_byte = UNSIGNED(8, SHIFTR0(x, U8(8)));
	RzILOpPure *low_byte = UNSIGNED(8, LOGAND(DUP(x), U16(0xff)));
	return SEQ2(push_stack(low_byte, op), push_stack(high_byte, op));
}
static RzILOpEffect *i_call(I8051Op *op) {
	rz_return_val_if_fail(op && op->argv[0], NULL);
	return SEQ2(push_stack_16(U16(op->pc + op->len), op), JMP(i8051_addressing_get(op->argv[0])));
}
static RzILOpEffect *i_pop(I8051Op *op) {
	return SEQ2(i8051_addressing_set(op->argv[0], LOAD(UNSIGNED(16, VAL_SP))),
		i8051_reg_set(I8051_SP, SUB(VAL_SP, U8(1))));
}
static RzILOpEffect *i_push(I8051Op *op) {
	return push_stack(i8051_addressing_get(op->argv[0]), op);
}
static RzILOpEffect *i_ret(I8051Op *op) {
	return SEQ4(SETL("pch", LOAD(UNSIGNED(16, VAL_SP))),
		SETL("pcl", LOAD(UNSIGNED(16, SUB(VAL_SP, U8(1))))),
		i8051_reg_set(I8051_SP, SUB(VAL_SP, U8(2))),
		JMP(APPEND(VARL("pch"), VARL("pcl"))));
}
static RzILOpEffect *i_rl(I8051Op *op) {
	return i8051_reg_set(I8051_ACC, LOGOR(SHIFTL0(VAL_ACC, U8(1)), SHIFTR0(VAL_ACC, U8(7))));
}
static RzILOpEffect *i_rlc(I8051Op *op) {
	return SEQ3(SETL("cy", BT8(i8051_reg_get_psw(I8051_CY))),
		i8051_reg_set(I8051_CY, BT8(NON_ZERO(SHIFTR0(VAL_ACC, U8(7))))),
		i8051_reg_set(I8051_ACC, LOGOR(SHIFTL0(VAL_ACC, U8(1)), VARL("cy"))));
}
static RzILOpEffect *i_rr(I8051Op *op) {
	return i8051_reg_set(I8051_ACC, LOGOR(SHIFTR0(VAL_ACC, U8(1)), SHIFTL0(VAL_ACC, U8(7))));
}
static RzILOpEffect *i_rrc(I8051Op *op) {
	return SEQ3(SETL("cy", BT8(i8051_reg_get_psw(I8051_CY))),
		i8051_reg_set(I8051_CY, BT8(NON_ZERO(LOGAND(VAL_ACC, U8(0x1))))),
		i8051_reg_set(I8051_ACC, LOGOR(SHIFTL0(VAL_ACC, U8(1)), SHIFTL0(VARL("cy"), U8(7)))));
}
static RzILOpEffect *i_swap(I8051Op *op) {
	return i8051_reg_set(I8051_ACC, LOGOR(SHIFTL0(VAL_ACC, U8(4)), SHIFTR0(VAL_ACC, U8(4))));
}
static RzILOpEffect *i_xch(I8051Op *op) {
	return SEQ3(SETL("@a", i8051_addressing_get(op->argv[0])),
		i8051_reg_set(I8051_ACC, i8051_addressing_get(op->argv[1])),
		i8051_addressing_set(op->argv[1], VARL("@a")));
}
static RzILOpEffect *i_xchd(I8051Op *op) {
	return SEQ4(SETL("@a", i8051_addressing_get(op->argv[0])), SETL("@b", i8051_addressing_get(op->argv[1])),
		i8051_reg_set(I8051_ACC, LOGOR(LOGAND(VARL("@a"), U8(0xf0)), LOGAND(VARL("@b"), U8(0x0f)))),
		i8051_addressing_set(op->argv[1], LOGOR(LOGAND(VARL("@b"), U8(0xf0)), LOGAND(VARL("@a"), U8(0x0f)))));
}

static inline RzILOpEffect *i_op_dispatch(I8051Op *op) {
	switch (op->inst) {
	case I_UNDEFINED: rz_warn_if_reached(); return NULL;
	case I_ACALL:
	case I_LCALL: return i_call(op);
	case I_ADD: return i_add(op);
	case I_ADDC: return i_addc(op);
	case I_LJMP: return i_ijmp(op);
	case I_AJMP:
	case I_SJMP:
	case I_JMP: return i_jmp(op);
	case I_ANL: return i_anl(op);
	case I_CJNE: return i_cjne(op);
	case I_CLR: return i_clr(op);
	case I_CPL: return i_cpl(op);
	case I_DA: return i_da(op);
	case I_DEC: return i_dec(op);
	case I_DIV: return i_div(op);
	case I_DJNZ: return i_djnz(op);
	case I_INC: return i_inc(op);
	case I_JB: return i_jb(op);
	case I_JBC: return i_jbc(op);
	case I_JC: return i_jc(op);
	case I_JNB: return i_jnb(op);
	case I_JNC: return i_jnc(op);
	case I_JNZ: return i_jnz(op);
	case I_JZ: return i_jz(op);
	case I_MOVC: return i_movc(op);
	case I_MOVX:
	case I_MOV: return i_mov(op);
	case I_MUL: return i_mul(op);
	case I_NOP: return i_nop();
	case I_ORL: return i_orl(op);
	case I_POP: return i_pop(op);
	case I_PUSH: return i_push(op);
	case I_RETI:
	case I_RET: return i_ret(op);
	case I_RL: return i_rl(op);
	case I_RLC: return i_rlc(op);
	case I_RR: return i_rr(op);
	case I_RRC: return i_rrc(op);
	case I_SETB: return i_setb(op);
	case I_SUBB: return i_subb(op);
	case I_SWAP: return i_swap(op);
	case I_XCHD: return i_xchd(op);
	case I_XCH: return i_xch(op);
	case I_XRL: return i_xrl(op);
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

RZ_IPI RzILOpEffect *rz_8051_il_op(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL const ut8 *buf, int len, ut64 pc) {
	rz_return_val_if_fail(analysis && buf && len > 0, NULL);
	I8051Op *op = rz_8051_op_parse(analysis, buf, len, pc);
	if (!op) {
		return NULL;
	}

	RzILOpEffect *eff = i_op_dispatch(op);
	free(op);
	return eff;
}

#include "rz_il/rz_il_opbuilder_end.h"

RZ_IPI RzAnalysisILConfig *rz_8051_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	RzAnalysisILConfig *r = rz_analysis_il_config_new(16, analysis->big_endian, 16);
	static const char *regs_bound[] = {
		"r0",
		"r1",
		"r2",
		"r3",
		"r4",
		"r5",
		"r6",
		"r7",
		"acc",
		"b",
		"dpl",
		"dph",
		"psw",
		"sp",
		NULL
	};
	r->reg_bindings = regs_bound;
	return r;
}