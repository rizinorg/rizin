// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * 6502 Lifting to be included from analysis_6502.c and plugged directly into the decoding logic.
 */

#include <rz_il.h>

typedef enum {
	_6502_ADDR_KIND_ADDR,
	_6502_ADDR_KIND_IMMEDIATE,
	_6502_ADDR_KIND_ACCUMULATOR
} _6502AddrKind;

typedef struct {
	_6502AddrKind kind;
	RzILOpBitVector *addr; ///< either the addr, or the immediate value if immedate, or NULL if accumulator
} _6502ILAddr;

#include <rz_il/rz_il_opbuilder_begin.h>

// Different common addressing modes, producing a pure value to be used for the actual instruction
// They receive the raw 1 or 2-byte value that follows the opcode byte.
// https://www.masswerk.at/6502/6502_instruction_set.html#description

/**
 * op a
 */
static void _6502_il_accumulator(_6502ILAddr *out) {
	out->kind = _6502_ADDR_KIND_ACCUMULATOR;
	out->addr = VARG("a");
}

/**
 * op #$ff
 */
static void _6502_il_immediate(_6502ILAddr *out, ut16 imm) {
	out->kind = _6502_ADDR_KIND_IMMEDIATE;
	out->addr = U8(imm);
}

/**
 * op $ff
 * op $ffff
 */
static void _6502_il_addr_absolute(_6502ILAddr *out, ut16 imm) {
	out->kind = _6502_ADDR_KIND_ADDR;
	out->addr = U16(imm);
}

/**
 * op $ff,x
 * op $ff,y
 */
static void _6502_il_addr_zero_page_reg(_6502ILAddr *out, ut16 imm, const char *reg) {
	out->kind = _6502_ADDR_KIND_ADDR;
	out->addr = UNSIGNED(16, ADD(U8(imm), VARG(reg)));
}

/**
 * op $ffff,x
 * op $ffff,y
 */
static void _6502_il_addr_reg(_6502ILAddr *out, ut16 imm, const char *reg) {
	out->kind = _6502_ADDR_KIND_ADDR;
	out->addr = ADD(U16(imm), UNSIGNED(16, VARG(reg)));
}

/**
 * op ($ff,x)
 */
static void _6502_il_addr_indirect_x(_6502ILAddr *out, ut16 imm) {
	out->kind = _6502_ADDR_KIND_ADDR;
	RzILOpPure *zp = ADD(U8(imm), VARG("x"));
	out->addr = APPEND(
		LOAD(UNSIGNED(16, ADD(DUP(zp), U8(1)))),
		LOAD(UNSIGNED(16, zp)));
}

/**
 * op ($ff),y
 */
static void _6502_il_addr_indirect_y(_6502ILAddr *out, ut16 imm) {
	out->kind = _6502_ADDR_KIND_ADDR;
	RzILOpPure *zp = U8(imm);
	RzILOpPure *base = APPEND(
		LOAD(UNSIGNED(16, ADD(DUP(zp), U8(1)))),
		LOAD(UNSIGNED(16, zp)));
	out->addr = ADD(base, UNSIGNED(16, VARG("y")));
}

///////////////////////////////////////////////////////////////////////////////
// Flags and stack handling

static RzILOpEffect *update_flags_nz(RzILOpPure *val) {
	return SEQ2(
		SETG("Z", IS_ZERO(val)),
		SETG("N", MSB(DUP(val))));
}

static RzILOpBitVector *status_byte(bool b) {
	RzILOpBitVector *r = LOGOR(
		ITE(VARG("N"), U8(0xb0), U8(0x30)), // "unused" bit is always set
		LOGOR(ITE(VARG("V"), U8(0x40), U8(0)),
			LOGOR(ITE(VARG("D"), U8(0x08), U8(0)),
				LOGOR(ITE(VARG("I"), U8(0x04), U8(0)),
					LOGOR(ITE(VARG("Z"), U8(0x02), U8(0)),
						ITE(VARG("C"), U8(0x01), U8(0)))))));
	return b ? LOGOR(r, U8(0x20)) : r;
}

static RzILOpEffect *status_byte_apply(RzILOpBitVector *sb) {
	return SEQ6(
		SETG("N", MSB(sb)),
		SETG("V", INV(IS_ZERO(LOGAND(DUP(sb), U8(0x40))))),
		SETG("D", INV(IS_ZERO(LOGAND(DUP(sb), U8(0x08))))),
		SETG("I", INV(IS_ZERO(LOGAND(DUP(sb), U8(0x04))))),
		SETG("Z", INV(IS_ZERO(LOGAND(DUP(sb), U8(0x02))))),
		SETG("C", LSB(DUP(sb))));
}

static RzILOpEffect *stack_push(RzILOpBitVector *v) {
	return SEQ2(
		STORE(APPEND(U8(1), VARG("sp")), v),
		SETG("sp", SUB(VARG("sp"), U8(1))));
}

static RzILOpEffect *stack_pop(const char *varname) {
	return SEQ2(
		SETG("sp", ADD(VARG("sp"), U8(1))),
		SETL(varname, LOAD(APPEND(U8(1), VARG("sp")))));
}

///////////////////////////////////////////////////////////////////////////////
// The ops themselves, taking a value aquired from one of the functions above,
// and (if possible) the information whether this is an immediate value or
// an address to dereference.

static RzILOpBitVector *do_load(_6502ILAddr *addr) {
	switch (addr->kind) {
	case _6502_ADDR_KIND_ADDR:
		return LOAD(addr->addr);
	case _6502_ADDR_KIND_IMMEDIATE:
		return addr->addr;
	case _6502_ADDR_KIND_ACCUMULATOR:
		return VARG("a");
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

/**
 * Dup addr->addr, for when both do_load and do_store should be used,
 * because it is moved, not copied.
 */
static _6502ILAddr *dup_addr(_6502ILAddr *addr) {
	if (addr->addr) {
		addr->addr = DUP(addr->addr);
	}
	return addr;
}

static RzILOpEffect *do_store(_6502ILAddr *addr, RzILOpBitVector *v) {
	switch (addr->kind) {
	case _6502_ADDR_KIND_ADDR:
		return STORE(addr->addr, v);
	case _6502_ADDR_KIND_ACCUMULATOR:
		return SETG("a", v);
	default:
		// can't store to immediate
		rz_warn_if_reached();
		return NULL;
	}
}

/**
 * lda
 * ldx
 * ldy
 */
static RzILOpEffect *_6502_il_op_ld(const char *reg, _6502ILAddr *addr) {
	RzILOpBitVector *v = do_load(addr);
	return SEQ2(
		SETG(reg, v),
		update_flags_nz(VARG(reg)));
}

/**
 * sta
 * stx
 * sty
 */
static RzILOpEffect *_6502_il_op_st(const char *reg, _6502ILAddr *addr) {
	return do_store(addr, VARG(reg));
}

/**
 * and
 */
static RzILOpEffect *_6502_il_op_and(_6502ILAddr *addr) {
	RzILOpBitVector *v = do_load(addr);
	return SEQ2(
		SETG("a", LOGAND(VARG("a"), v)),
		update_flags_nz(VARG("a")));
}

/**
 * ora
 */
static RzILOpEffect *_6502_il_op_ora(_6502ILAddr *addr) {
	RzILOpBitVector *v = do_load(addr);
	return SEQ2(
		SETG("a", LOGOR(VARG("a"), v)),
		update_flags_nz(VARG("a")));
}

/**
 * eor
 */
static RzILOpEffect *_6502_il_op_eor(_6502ILAddr *addr) {
	RzILOpBitVector *v = do_load(addr);
	return SEQ2(
		SETG("a", LOGXOR(VARG("a"), v)),
		update_flags_nz(VARG("a")));
}

/**
 * adc
 */
static RzILOpEffect *_6502_il_op_adc(_6502ILAddr *addr) {
	// TODO: bcd if D
	return SEQ6(
		SETL("src", do_load(addr)),
		SETL("res", ADD(ITE(VARG("C"), U8(1), U8(0)), ADD(VARG("a"), VARL("src")))),
		update_flags_nz(VARL("res")),
		SETG("C", ITE(VARG("C"), ULE(VARL("res"), VARG("a")), ULT(VARL("res"), VARG("a")))),
		SETG("V",
			AND(
				INV(XOR(MSB(VARG("a")), MSB(VARL("src")))),
				XOR(MSB(VARG("a")), MSB(VARL("res"))))),
		SETG("a", VARL("res")));
}

/**
 * sbc
 */
static RzILOpEffect *_6502_il_op_sbc(_6502ILAddr *addr) {
	// TODO: bcd if D
	return SEQ7(
		SETL("src", do_load(addr)),
		SETL("res", SUB(SUB(UNSIGNED(9, VARG("a")), UNSIGNED(9, VARL("src"))), ITE(VARG("C"), UN(9, 0), UN(9, 1)))),
		SETG("C", INV(MSB(VARL("res")))),
		SETL("res8", UNSIGNED(8, VARL("res"))),
		update_flags_nz(VARL("res8")),
		SETG("V",
			AND(
				XOR(MSB(VARG("a")), MSB(VARL("res8"))),
				XOR(MSB(VARG("a")), MSB(VARL("src"))))),
		SETG("a", VARL("res8")));
}

/**
 * asl
 */
static RzILOpEffect *_6502_il_op_asl(_6502ILAddr *addr) {
	RzILOpEffect *load = SETL("tmp", do_load(addr));
	return SEQ5(
		load,
		SETG("C", MSB(VARL("tmp"))),
		SETL("tmp", SHIFTL0(VARL("tmp"), UN(3, 1))),
		do_store(dup_addr(addr), VARL("tmp")),
		update_flags_nz(VARL("tmp")));
}

/**
 * lsr
 */
static RzILOpEffect *_6502_il_op_lsr(_6502ILAddr *addr) {
	RzILOpEffect *load = SETL("tmp", do_load(addr));
	return SEQ6(
		load,
		SETG("C", LSB(VARL("tmp"))),
		SETL("tmp", SHIFTR0(VARL("tmp"), UN(3, 1))),
		do_store(dup_addr(addr), VARL("tmp")),
		SETG("Z", IS_ZERO(VARL("tmp"))),
		SETG("N", IL_FALSE));
}

typedef enum {
	_6502_BRANCH_ON_PLUS = 0x10,
	_6502_BRANCH_ON_MINUS = 0x30,
	_6502_BRANCH_ON_OVERFLOW_CLEAR = 0x50,
	_6502_BRANCH_ON_OVERFLOW_SET = 0x70,
	_6502_BRANCH_ON_CARRY_CLEAR = 0x90,
	_6502_BRANCH_ON_CARRY_SET = 0xb0,
	_6502_BRANCH_ON_NOT_EQUAL = 0xd0,
	_6502_BRANCH_ON_EQUAL = 0xf0
} _6502BranchCond;

/**
 * bpl
 * bmi
 * bvc
 * bvs
 * bcc
 * bcs
 * bne
 * beq
 */
static RzILOpEffect *_6502_il_op_branch(_6502BranchCond cond, ut16 target) {
	RzILOpBool *c;
	switch (cond) {
	case _6502_BRANCH_ON_PLUS:
		c = INV(VARG("N"));
		break;
	case _6502_BRANCH_ON_MINUS:
		c = VARG("N");
		break;
	case _6502_BRANCH_ON_OVERFLOW_CLEAR:
		c = INV(VARG("V"));
		break;
	case _6502_BRANCH_ON_OVERFLOW_SET:
		c = VARG("V");
		break;
	case _6502_BRANCH_ON_CARRY_CLEAR:
		c = INV(VARG("C"));
		break;
	case _6502_BRANCH_ON_CARRY_SET:
		c = VARG("C");
		break;
	case _6502_BRANCH_ON_NOT_EQUAL:
		c = INV(VARG("Z"));
		break;
	case _6502_BRANCH_ON_EQUAL:
		c = VARG("Z");
		break;
	default:
		rz_warn_if_reached();
		return NULL;
	}
	return BRANCH(c, JMP(U16(target)), NOP());
}

/**
 * jmp
 */
static RzILOpEffect *_6502_il_op_jmp(ut16 target, bool indir) {
	RzILOpBitVector *addr = U16(target);
	return JMP(indir ? LOADW(16, addr) : addr);
}

/**
 * brk
 */
static RzILOpEffect *_6502_il_op_brk(ut16 offset) {
	offset += 2;
	return SEQ6(
		stack_push(U8((ut8)(offset >> 8))),
		stack_push(U8((ut8)offset)),
		stack_push(status_byte(true)),
		SETG("D", IL_FALSE),
		SETG("I", IL_TRUE),
		JMP(LOADW(16, U16(0xfffe))));
}

/**
 * jsr
 */
static RzILOpEffect *_6502_il_op_jsr(ut16 target, ut64 offset) {
	offset += 2; // yes, this is **inside** the jsr.
	return SEQ3(
		stack_push(U8((ut8)(offset >> 8))),
		stack_push(U8((ut8)offset)),
		JMP(U16(target)));
}

/**
 * rti
 */
static RzILOpEffect *_6502_il_op_rti() {
	return SEQ5(
		stack_pop("sr"),
		status_byte_apply(VARL("sr")),
		stack_pop("pcl"),
		stack_pop("pch"),
		JMP(APPEND(VARL("pch"), VARL("pcl"))));
}

/**
 * rts
 */
static RzILOpEffect *_6502_il_op_rts() {
	return SEQ3(
		stack_pop("pcl"),
		stack_pop("pch"),
		JMP(ADD(APPEND(VARL("pch"), VARL("pcl")), U16(1))));
}

/**
 * bit
 */
static RzILOpEffect *_6502_il_op_bit(_6502ILAddr *addr) {
	return SEQ4(
		SETL("tmp", do_load(addr)),
		SETG("N", MSB(VARL("tmp"))),
		SETG("V", MSB(UNSIGNED(7, VARL("tmp")))),
		SETG("Z", IS_ZERO(LOGAND(VARL("tmp"), VARG("a")))));
}

typedef enum {
	_6502_FLAG_OP_SET_I = 0x78,
	_6502_FLAG_OP_CLEAR_I = 0x58,
	_6502_FLAG_OP_SET_C = 0x38,
	_6502_FLAG_OP_CLEAR_C = 0x18,
	_6502_FLAG_OP_SET_D = 0xf8,
	_6502_FLAG_OP_CLEAR_D = 0xd8,
	_6502_FLAG_OP_CLEAR_V = 0xb8
} _6502FlagOp;

/**
 * sei
 * cli
 * sec
 * clc
 * sed
 * cld
 * clv
 */
static RzILOpEffect *_6502_il_op_flag(_6502FlagOp op) {
	switch (op) {
	case _6502_FLAG_OP_SET_I:
		return SETG("I", IL_TRUE);
	case _6502_FLAG_OP_CLEAR_I:
		return SETG("I", IL_FALSE);
	case _6502_FLAG_OP_SET_C:
		return SETG("C", IL_TRUE);
	case _6502_FLAG_OP_CLEAR_C:
		return SETG("C", IL_FALSE);
	case _6502_FLAG_OP_SET_D:
		return SETG("D", IL_TRUE);
	case _6502_FLAG_OP_CLEAR_D:
		return SETG("D", IL_FALSE);
	case _6502_FLAG_OP_CLEAR_V:
		return SETG("V", IL_FALSE);
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

/**
 * cmp
 * cpx
 * cpy
 */
static RzILOpEffect *_6502_il_op_cmp(const char *reg, _6502ILAddr *addr) {
	return SEQ3(
		SETL("cmptmp", SUB(UNSIGNED(9, VARG(reg)), UNSIGNED(9, do_load(addr)))),
		SETG("C", INV(MSB(VARL("cmptmp")))),
		update_flags_nz(UNSIGNED(8, VARL("cmptmp"))));
}

/**
 * inx
 * iny
 * dex
 * dey
 */
static RzILOpEffect *_6502_il_op_inc_reg(const char *reg, bool inc) {
	RzILOpBitVector *v = inc ? ADD(VARG(reg), U8(1)) : SUB(VARG(reg), U8(1));
	return SEQ2(
		SETG(reg, v),
		update_flags_nz(UNSIGNED(8, VARG(reg))));
}

/**
 * inc
 * dec
 */
static RzILOpEffect *_6502_il_op_inc(_6502ILAddr *addr, bool inc) {
	RzILOpBitVector *v = inc ? ADD(do_load(addr), U8(1)) : SUB(do_load(addr), U8(1));
	return SEQ3(
		SETL("tmp", v),
		do_store(dup_addr(addr), VARL("tmp")),
		update_flags_nz(VARL("tmp")));
}

/**
 * pha
 */
static RzILOpEffect *_6502_il_op_pha() {
	return stack_push(VARG("a"));
}

/**
 * php
 */
static RzILOpEffect *_6502_il_op_php() {
	return stack_push(status_byte(true));
}

/**
 * pla
 */
static RzILOpEffect *_6502_il_op_pla() {
	return SEQ3(
		stack_pop("tmp"),
		SETG("a", VARL("tmp")),
		update_flags_nz(VARL("tmp")));
}

/**
 * plp
 */
static RzILOpEffect *_6502_il_op_plp() {
	return SEQ2(
		stack_pop("tmp"),
		status_byte_apply(VARL("tmp")));
}

/**
 * rol
 */
static RzILOpEffect *_6502_il_op_rol(_6502ILAddr *addr) {
	RzILOpEffect *load = SETL("tmp", do_load(addr));
	return SEQ5(
		load,
		SETL("res", LOGOR(SHIFTL0(VARL("tmp"), UN(3, 1)), ITE(VARG("C"), U8(1), U8(0)))),
		SETG("C", MSB(VARL("tmp"))),
		do_store(dup_addr(addr), VARL("res")),
		update_flags_nz(VARL("res")));
}

/**
 * ror
 */
static RzILOpEffect *_6502_il_op_ror(_6502ILAddr *addr) {
	RzILOpEffect *load = SETL("tmp", do_load(addr));
	return SEQ5(
		load,
		SETL("res", LOGOR(SHIFTR0(VARL("tmp"), UN(3, 1)), ITE(VARG("C"), U8(0x80), U8(0)))),
		SETG("C", LSB(VARL("tmp"))),
		do_store(dup_addr(addr), VARL("res")),
		update_flags_nz(VARL("res")));
}

/**
 * tax
 * tay
 * tsx
 * txa
 * txs
 * tya
 */
static RzILOpEffect *_6502_il_op_transfer(const char *dst, const char *src, bool update_flags) {
	RzILOpEffect *tf = SETG(dst, VARG(src));
	return update_flags ? SEQ2(tf, update_flags_nz(VARG(dst))) : tf;
}

/**
 * SLO (ASL,ORA)
 */
static RzILOpEffect *_6502_il_op_slo(_6502ILAddr *addr) {
	RzILOpEffect *asl = _6502_il_op_asl(dup_addr(addr));
	RzILOpEffect *ora = _6502_il_op_ora(dup_addr(addr));
	return SEQ2(asl, ora);
}

/**
 * RLA (ROL,AND)
 */
static RzILOpEffect *_6502_il_op_rla(_6502ILAddr *addr) {
	RzILOpEffect *rol = _6502_il_op_rol(dup_addr(addr));
	RzILOpEffect *and_ = _6502_il_op_and(dup_addr(addr));
	return SEQ2(rol, and_);
}

/**
 * SRE (LSR,EOR)
 */
static RzILOpEffect *_6502_il_op_sre(_6502ILAddr *addr) {
	RzILOpEffect *lsr = _6502_il_op_lsr(dup_addr(addr));
	RzILOpEffect *eor = _6502_il_op_eor(dup_addr(addr));
	return SEQ2(lsr, eor);
}

/**
 * RRA (ROR,ADC)
 */
static RzILOpEffect *_6502_il_op_rra(_6502ILAddr *addr) {
	RzILOpEffect *ror = _6502_il_op_ror(dup_addr(addr));
	RzILOpEffect *adc = _6502_il_op_adc(dup_addr(addr));
	return SEQ2(ror, adc);
}

/**
 * SAX (STA, STX)
 */
static RzILOpEffect *_6502_il_op_sax(_6502ILAddr *addr) {
	return do_store(addr, LOGAND(VARG("a"), VARG("x")));
}

/**
 * LAX (LDA,LDX)
 */
static RzILOpEffect *_6502_il_op_lax(_6502ILAddr *addr) {
	RzILOpEffect *lda = _6502_il_op_ld("a", dup_addr(addr));
	RzILOpEffect *ldx = _6502_il_op_ld("x", dup_addr(addr));
	return SEQ2(lda, ldx);
}

/**
 * LAX #imm
 */
static RzILOpEffect *_6502_il_op_laximm(_6502ILAddr *addr, ut8 magic) {
	RzILOpEffect *tax = _6502_il_op_transfer("x", "a", false);
	RzILOpBitVector *magic_constant = U8(magic);
	// magic_constant's value is highy unpredictable (dependent on time & temperature)
	// Some common values are 0xff, 0xef, 0x00, ...

	return SEQ3(
		SETG("a", LOGAND(LOGOR(VARG("a"), magic_constant), UNSIGNED(8, addr->addr))),
		tax,
		update_flags_nz(VARG("a")));
}

/**
 * DCP (DEC,CMP)
 */
static RzILOpEffect *_6502_il_op_dcp(_6502ILAddr *addr) {
	RzILOpEffect *dec = _6502_il_op_inc(dup_addr(addr), false);
	RzILOpEffect *cmp = _6502_il_op_cmp("a", dup_addr(addr));
	return SEQ2(dec, cmp);
}

/**
 * ISC (INC,SBC)
 */
static RzILOpEffect *_6502_il_op_isc(_6502ILAddr *addr) {
	RzILOpEffect *inc = _6502_il_op_inc(dup_addr(addr), true);
	RzILOpEffect *sbc = _6502_il_op_sbc(dup_addr(addr));
	return SEQ2(inc, sbc);
}

/**
 * ANC(AND,ASL/ROL like)
 */
static RzILOpEffect *_6502_il_op_anc(_6502ILAddr *addr) {
	RzILOpEffect *and_ = _6502_il_op_and(addr);
	return SEQ2(
		and_,
		SETG("C", MSB(VARG("a"))));
}

/**
 * ALR (AND,LSR)
 */
static RzILOpEffect *_6502_il_op_alr(_6502ILAddr *addr) {
	RzILOpEffect *and_ = _6502_il_op_and(addr);
	_6502ILAddr acc = { .kind = _6502_ADDR_KIND_ACCUMULATOR, .addr = VARG("a") };
	RzILOpEffect *lsr = _6502_il_op_lsr(&acc);
	return SEQ2(and_, lsr);
}

/**
 * ARR (AND,ROR)
 */
static RzILOpEffect *_6502_il_op_arr(_6502ILAddr *addr) {
	RzILOpEffect *and_ = _6502_il_op_and(dup_addr(addr));
	_6502ILAddr acc = { .kind = _6502_ADDR_KIND_ACCUMULATOR, .addr = VARG("a") };
	RzILOpEffect *ror = _6502_il_op_ror(&acc);
	return SEQ2(and_, ror);
}

/**
 * SBX (CMP,DEX)
 */
static RzILOpEffect *_6502_il_op_sbx(_6502ILAddr *addr) {
	RzILOpEffect *load = SETL("tmp", do_load(addr));
	return SEQ5(
		load,
		SETL("ax", LOGAND(VARG("a"), VARG("x"))),
		SETL("ax", SUB(VARL("ax"), VARL("tmp"))),
		SETG("x", VARL("ax")),
		update_flags_nz(VARG("x")));
}

/**
 * LAS
 */
static RzILOpEffect *_6502_il_op_las(_6502ILAddr *addr) {
	RzILOpBitVector *v = do_load(addr);
	RzILOpEffect *tsx = _6502_il_op_transfer("x", "sp", false);
	RzILOpEffect *tsa = _6502_il_op_transfer("a", "sp", false);
	return SEQ4(
		SETG("sp", LOGAND(VARG("sp"), v)),
		update_flags_nz(VARG("sp")),
		tsx,
		tsa);
}

/**
 * JAM
 */
static RzILOpEffect *_6502_il_op_jam(_6502ILAddr *addr) {
	// RzILOpBitVector *v = do_load(addr);
	return EMPTY();
}

/**
 * SHA
 */
static RzILOpEffect *_6502_il_op_sha(_6502ILAddr *addr) {
	return SEQ2(
		SETL("tmp", LOGAND(LOGAND(VARG("a"), VARG("x")), ADD(UNSIGNED(8, SHIFTR0(DUP(addr->addr), U8(8))), U8(1)))),
		do_store(addr, VARL("tmp")));
}

/**
 * SHX
 */
static RzILOpEffect *_6502_il_op_shx(_6502ILAddr *addr) {
	return SEQ2(
		SETL("tmp", LOGAND(VARG("x"), ADD(UNSIGNED(8, SHIFTR0(DUP(addr->addr), U8(8))), U8(1)))),
		do_store(addr, VARL("tmp")));
}

/**
 * SHY
 */
static RzILOpEffect *_6502_il_op_shy(_6502ILAddr *addr) {
	return SEQ2(
		SETL("tmp", LOGAND(VARG("y"), ADD(UNSIGNED(8, SHIFTR0(DUP(addr->addr), U8(8))), U8(1)))),
		do_store(addr, VARL("tmp")));
}

/**
 * TAS
 */
static RzILOpEffect *_6502_il_op_tas(_6502ILAddr *addr) {
	return SEQ3(
		SETG("sp", LOGAND(VARG("a"), VARG("x"))),
		SETL("tmp", LOGAND(LOGAND(VARG("a"), VARG("x")), ADD(UNSIGNED(8, SHIFTR0(DUP(addr->addr), U8(8))), U8(1)))),
		do_store(addr, VARL("tmp")));
}

/**
 * ANE
 */
static RzILOpEffect *_6502_il_op_ane(_6502ILAddr *addr, ut8 magic) {
	RzILOpBitVector *magic_constant = U8(magic);
	// magic_constant's value is highy unpredictable (dependent on time & temperature)
	// Some common values are 0xff, 0xef, 0x00, ...

	return SEQ2(
		SETG("a", LOGAND(LOGOR(VARG("a"), magic_constant), LOGAND(VARG("x"), UNSIGNED(8, addr->addr)))),
		update_flags_nz(VARG("a")));
}

/**
 * NOP $ff & $ff,x
 */
static RzILOpEffect *rz_il_op_new_nopzp(_6502ILAddr *addr) {
	// RzILOpBitVector *v = do_load(addr);
	RzILOpEffect *nop = NOP();
	return nop;
}

#include <rz_il/rz_il_opbuilder_end.h>