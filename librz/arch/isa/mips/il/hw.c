// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2023 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file hw.c
 * RzIL implementation of MIPS hardware functions like breakpoint, debug, etc..
 **/

#define REG_CAUSE_EXCEPTION             "CAUSE_EXC"
#define IL_REG_CAUSE_EXCEPTION()        NOP() // VARG(REG_CAUSE_EXCEPTION)
#define IL_CAUSE_CLEAR()                NOP() // SETG(REG_CAUSE_EXCEPTION, U8(0));
#define IL_CAUSE_INTERRUPT()            NOP() // SETG(REG_CAUSE_EXCEPTION, U8(0x00))
#define IL_CAUSE_ADDRESS_LOAD_ERROR()   NOP() // SETG(REG_CAUSE_EXCEPTION, U8(0x04))
#define IL_CAUSE_ADDRESS_STORE_ERROR()  NOP() // SETG(REG_CAUSE_EXCEPTION, U8(0x05))
#define IL_CAUSE_SYSCALL()              NOP() // SETG(REG_CAUSE_EXCEPTION, U8(0x08))
#define IL_CAUSE_BREAKPOINT()           NOP() // SETG(REG_CAUSE_EXCEPTION, U8(0x09))
#define IL_CAUSE_OVERFLOW()             NOP() // SETG(REG_CAUSE_EXCEPTION, U8(0x0C))
#define IL_CAUSE_RESERVED_INSTRUCTION() NOP() // SETG(REG_CAUSE_EXCEPTION, U8(0x0A))
#define IL_CAUSE_TRAP()                 NOP() // SETG(REG_CAUSE_EXCEPTION, U8(0x0D))

static RzILOpEffect *mips_il_break(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// HW breakpoint
	return NOP();
}

static RzILOpEffect *mips_il_deret(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Debug Exception Return
	// PC = DEPC
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_eret(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Exception Return
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_eretnc(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Exception Return No Clear
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_mfc0(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Move from Coprocessor 0
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_mfhc0(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Move from High Coprocessor 0
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_mtc0(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Move to Coprocessor 0
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_mthc0(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Move to High Coprocessor 0
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_rdhwr(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Read Hardware Register
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_rdpgpr(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Read GPR from Previous Shadow Set
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_sdbbp(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Software Debug Breakpoint
	return NOP();
}

static RzILOpEffect *mips_il_syscall(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	return NOP();
}

static RzILOpEffect *mips_il_teq(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Trap if Equal
	return NOP();
}

static RzILOpEffect *mips_il_teqi(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Trap if Equal Immediate
	return NOP();
}

static RzILOpEffect *mips_il_tge(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Trap if Greater or Equal
	return NOP();
}

static RzILOpEffect *mips_il_tgei(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Trap if Greater or Equal Immediate Signed
	return NOP();
}

static RzILOpEffect *mips_il_tgeiu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Trap if Greater or Equal Immediate Unsigned
	return NOP();
}

static RzILOpEffect *mips_il_tgeu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Trap if Greater or Equal Unsigned
	return NOP();
}

static RzILOpEffect *mips_il_tlt(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Trap if Less Than
	return NOP();
}

static RzILOpEffect *mips_il_tlti(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Trap if Less Than Immediate Signed
	return NOP();
}

static RzILOpEffect *mips_il_tltiu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Trap if Less Than Immediate Unsigned
	return NOP();
}

static RzILOpEffect *mips_il_tltu(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Trap if Less Than Unsigned
	return NOP();
}

static RzILOpEffect *mips_il_tne(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Trap if Not Equal
	return NOP();
}

static RzILOpEffect *mips_il_tnei(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Trap if Not Equal Immediate
	return NOP();
}

static RzILOpEffect *mips_il_wrpgpr(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Write to GPR in Previous Shadow Set
	NOT_IMPLEMENTED;
}
