// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file c54x.c
 * TMS320C54x disassembly.
 *
 * The C54x is the predecessor of the C55x: a 16-bit fixed-point DSP with two
 * 40-bit accumulators (A/B), eight 16-bit auxiliary registers (AR0-AR7) and a
 * mostly 1-word (16-bit) instruction set, with a 2-word form for long
 * immediates, absolute addresses and program-memory branch targets.
 *
 * Instructions are stored as little-endian 16-bit words; the shared engine
 * byte-swaps each word (C55ArchDesc::words_le) so this table can be written in
 * the datasheet's MSB-first order. The encoding tables come from the
 * TMS320C54x DSP Functional Overview (SPRU307, Table 1-11) and the addressing
 * detail from the CPU manual (SPRU131, Tables 5-4 / 5-8).
 *
 * This file provides the decode half only (disasm); RzIL lifting is deferred
 * (C55ArchDesc::lift stays NULL), matching how C64x has disasm but no IL.
 */

#include <rz_analysis.h>
#include "../c55_ir.h"
#include "c54x.h"

static inline ut64 c54x_field(ut64 bits, ut8 lo, ut8 width) {
	return (bits >> lo) & (((ut64)1 << width) - 1);
}

static const char *c54x_mnemonic(ut16 id) {
	switch (id) {
	case C54X_INS_NOP: return "nop";
	case C54X_INS_B: return "b";
	case C54X_INS_BACC: return "bacc";
	case C54X_INS_CALL: return "call";
	case C54X_INS_CC: return "cc";
	case C54X_INS_RET: return "ret";
	case C54X_INS_RETE: return "rete";
	case C54X_INS_RETF: return "retf";
	case C54X_INS_FB: return "fb";
	case C54X_INS_FBACC: return "fbacc";
	case C54X_INS_FCALL: return "fcall";
	case C54X_INS_FRET: return "fret";
	case C54X_INS_FRETE: return "frete";
	case C54X_INS_RESET: return "reset";
	case C54X_INS_TRAP: return "trap";
	case C54X_INS_INTR: return "intr";
	case C54X_INS_IDLE: return "idle";
	case C54X_INS_SSBX: return "ssbx";
	case C54X_INS_RSBX: return "rsbx";
	case C54X_INS_RPT: return "rpt";
	case C54X_INS_RPTB: return "rptb";
	case C54X_INS_RPTZ: return "rptz";
	case C54X_INS_LD: return "ld";
	case C54X_INS_ADD: return "add";
	case C54X_INS_SUB: return "sub";
	case C54X_INS_PSHM: return "pshm";
	case C54X_INS_POPM: return "popm";
	case C54X_INS_PSHD: return "pshd";
	case C54X_INS_POPD: return "popd";
	case C54X_INS_STL: return "stl";
	case C54X_INS_STH: return "sth";
	case C54X_INS_STLM: return "stlm";
	case C54X_INS_ST: return "st";
	case C54X_INS_STM: return "stm";
	case C54X_INS_AND: return "and";
	case C54X_INS_OR: return "or";
	case C54X_INS_XOR: return "xor";
	case C54X_INS_MVDD: return "mvdd";
	case C54X_INS_MVDK: return "mvdk";
	case C54X_INS_MVDM: return "mvdm";
	case C54X_INS_MVKD: return "mvkd";
	case C54X_INS_MVMD: return "mvmd";
	case C54X_INS_MVMM: return "mvmm";
	case C54X_INS_MVPD: return "mvpd";
	case C54X_INS_MAR: return "mar";
	case C54X_INS_DELAY: return "delay";
	case C54X_INS_BC: return "bc";
	case C54X_INS_BANZ: return "banz";
	case C54X_INS_CALA: return "cala";
	case C54X_INS_FRAME: return "frame";
	case C54X_INS_BITF: return "bitf";
	case C54X_INS_CMPM: return "cmpm";
	case C54X_INS_MPY: return "mpy";
	case C54X_INS_BD: return "bd";
	case C54X_INS_CALLD: return "calld";
	case C54X_INS_RETD: return "retd";
	case C54X_INS_RETED: return "reted";
	case C54X_INS_RETFD: return "retfd";
	case C54X_INS_FBD: return "fbd";
	case C54X_INS_FCALLD: return "fcalld";
	case C54X_INS_FRETD: return "fretd";
	case C54X_INS_FRETED: return "freted";
	case C54X_INS_BCD: return "bcd";
	case C54X_INS_CCD: return "ccd";
	case C54X_INS_BANZD: return "banzd";
	case C54X_INS_RPTBD: return "rptbd";
	case C54X_INS_BACCD: return "baccd";
	case C54X_INS_CALAD: return "calad";
	case C54X_INS_LDM: return "ldm";
	case C54X_INS_LTD: return "ltd";
	case C54X_INS_DST: return "dst";
	case C54X_INS_DADD: return "dadd";
	case C54X_INS_DSUB: return "dsub";
	case C54X_INS_DSUBT: return "dsubt";
	case C54X_INS_DLD: return "dld";
	case C54X_INS_MAC: return "mac";
	case C54X_INS_MACD: return "macd";
	case C54X_INS_MAS: return "mas";
	case C54X_INS_ADDC: return "addc";
	case C54X_INS_SUBB: return "subb";
	case C54X_INS_NEG: return "neg";
	case C54X_INS_ABS: return "abs";
	case C54X_INS_EXP: return "exp";
	case C54X_INS_NORM: return "norm";
	case C54X_INS_SFTL: return "sftl";
	case C54X_INS_SFTA: return "sfta";
	case C54X_INS_CMPR: return "cmpr";
	case C54X_INS_ABDST: return "abdst";
	case C54X_INS_ADDM: return "addm";
	case C54X_INS_ANDM: return "andm";
	case C54X_INS_ORM: return "orm";
	case C54X_INS_XORM: return "xorm";
	case C54X_INS_FIRS: return "firs";
	case C54X_INS_LMS: return "lms";
	case C54X_INS_MAX: return "max";
	case C54X_INS_MIN: return "min";
	case C54X_INS_MPYA: return "mpya";
	case C54X_INS_MVDP: return "mvdp";
	case C54X_INS_POLY: return "poly";
	case C54X_INS_READA: return "reada";
	case C54X_INS_WRITA: return "writa";
	case C54X_INS_RND: return "rnd";
	case C54X_INS_ROL: return "rol";
	case C54X_INS_ROLTC: return "roltc";
	case C54X_INS_ROR: return "ror";
	case C54X_INS_SAT: return "sat";
	case C54X_INS_SFTC: return "sftc";
	case C54X_INS_SQDST: return "sqdst";
	case C54X_INS_SQUR: return "squr";
	case C54X_INS_SQURA: return "squra";
	case C54X_INS_SQURS: return "squrs";
	case C54X_INS_BITT: return "bitt";
	case C54X_INS_CMPL: return "cmpl";
	case C54X_INS_FCALA: return "fcala";
	case C54X_INS_FCALAD: return "fcalad";
	case C54X_INS_MPYU: return "mpyu";
	case C54X_INS_MASA: return "masa";
	case C54X_INS_BIT: return "bit";
	case C54X_INS_SACCD: return "saccd";
	case C54X_INS_SRCCD: return "srccd";
	case C54X_INS_STRCD: return "strcd";
	case C54X_INS_PORTR: return "portr";
	case C54X_INS_PORTW: return "portw";
	case C54X_INS_MASAR: return "masar";
	case C54X_INS_ADDS: return "adds";
	case C54X_INS_SUBS: return "subs";
	case C54X_INS_SUBC: return "subc";
	case C54X_INS_LDU: return "ldu";
	case C54X_INS_LDR: return "ldr";
	case C54X_INS_CMPS: return "cmps";
	case C54X_INS_DADST: return "dadst";
	case C54X_INS_DRSUB: return "drsub";
	case C54X_INS_DSADT: return "dsadt";
	case C54X_INS_MACA: return "maca";
	case C54X_INS_MACAR: return "macar";
	case C54X_INS_MACP: return "macp";
	case C54X_INS_MACSU: return "macsu";
	case C54X_INS_MACR: return "macr";
	case C54X_INS_MASR: return "masr";
	case C54X_INS_RC: return "rc";
	case C54X_INS_RCD: return "rcd";
	case C54X_INS_XC: return "xc";
	default: return "invalid";
	}
}

static ut32 c54x_op_type(ut16 id) {
	switch (id) {
	case C54X_INS_NOP: return RZ_ANALYSIS_OP_TYPE_NOP;
	case C54X_INS_B:
	case C54X_INS_FB: return RZ_ANALYSIS_OP_TYPE_JMP;
	case C54X_INS_BACC:
	case C54X_INS_FBACC: return RZ_ANALYSIS_OP_TYPE_UJMP;
	case C54X_INS_CALL:
	case C54X_INS_FCALL: return RZ_ANALYSIS_OP_TYPE_CALL;
	case C54X_INS_CC: return RZ_ANALYSIS_OP_TYPE_CCALL;
	case C54X_INS_RET:
	case C54X_INS_RETE:
	case C54X_INS_RETF:
	case C54X_INS_FRET:
	case C54X_INS_FRETE: return RZ_ANALYSIS_OP_TYPE_RET;
	case C54X_INS_TRAP:
	case C54X_INS_INTR: return RZ_ANALYSIS_OP_TYPE_SWI;
	case C54X_INS_LD: return RZ_ANALYSIS_OP_TYPE_LOAD;
	case C54X_INS_ADD: return RZ_ANALYSIS_OP_TYPE_ADD;
	case C54X_INS_SUB: return RZ_ANALYSIS_OP_TYPE_SUB;
	case C54X_INS_PSHM:
	case C54X_INS_PSHD: return RZ_ANALYSIS_OP_TYPE_PUSH;
	case C54X_INS_POPM:
	case C54X_INS_POPD: return RZ_ANALYSIS_OP_TYPE_POP;
	case C54X_INS_STL:
	case C54X_INS_STH:
	case C54X_INS_STLM:
	case C54X_INS_ST:
	case C54X_INS_STM:
	case C54X_INS_MVDD:
	case C54X_INS_MVDK:
	case C54X_INS_MVDM:
	case C54X_INS_MVKD:
	case C54X_INS_MVMD:
	case C54X_INS_MVMM:
	case C54X_INS_MVPD: return RZ_ANALYSIS_OP_TYPE_STORE;
	case C54X_INS_AND: return RZ_ANALYSIS_OP_TYPE_AND;
	case C54X_INS_OR: return RZ_ANALYSIS_OP_TYPE_OR;
	case C54X_INS_XOR: return RZ_ANALYSIS_OP_TYPE_XOR;
	case C54X_INS_BC: return RZ_ANALYSIS_OP_TYPE_CJMP;
	case C54X_INS_BANZ: return RZ_ANALYSIS_OP_TYPE_CJMP;
	case C54X_INS_CALA: return RZ_ANALYSIS_OP_TYPE_UCALL;
	case C54X_INS_CMPM: return RZ_ANALYSIS_OP_TYPE_CMP;
	case C54X_INS_BITF: return RZ_ANALYSIS_OP_TYPE_ACMP;
	case C54X_INS_MPY: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_BD:
	case C54X_INS_FBD: return RZ_ANALYSIS_OP_TYPE_JMP;
	case C54X_INS_CALLD:
	case C54X_INS_FCALLD: return RZ_ANALYSIS_OP_TYPE_CALL;
	case C54X_INS_RETD:
	case C54X_INS_RETED:
	case C54X_INS_RETFD:
	case C54X_INS_FRETD:
	case C54X_INS_FRETED: return RZ_ANALYSIS_OP_TYPE_RET;
	case C54X_INS_BCD:
	case C54X_INS_BANZD: return RZ_ANALYSIS_OP_TYPE_CJMP;
	case C54X_INS_CCD: return RZ_ANALYSIS_OP_TYPE_CCALL;
	case C54X_INS_RPTBD: return RZ_ANALYSIS_OP_TYPE_REP;
	case C54X_INS_BACCD: return RZ_ANALYSIS_OP_TYPE_UJMP;
	case C54X_INS_CALAD: return RZ_ANALYSIS_OP_TYPE_UCALL;
	case C54X_INS_LDM: return RZ_ANALYSIS_OP_TYPE_LOAD;
	case C54X_INS_LTD: return RZ_ANALYSIS_OP_TYPE_LOAD;
	case C54X_INS_DST: return RZ_ANALYSIS_OP_TYPE_STORE;
	case C54X_INS_DADD: return RZ_ANALYSIS_OP_TYPE_ADD;
	case C54X_INS_DSUB: return RZ_ANALYSIS_OP_TYPE_SUB;
	case C54X_INS_DSUBT: return RZ_ANALYSIS_OP_TYPE_SUB;
	case C54X_INS_DLD: return RZ_ANALYSIS_OP_TYPE_LOAD;
	case C54X_INS_MAC: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_MACD: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_MAS: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_ADDC: return RZ_ANALYSIS_OP_TYPE_ADD;
	case C54X_INS_SUBB: return RZ_ANALYSIS_OP_TYPE_SUB;
	case C54X_INS_NEG: return RZ_ANALYSIS_OP_TYPE_SUB;
	case C54X_INS_ABS: return RZ_ANALYSIS_OP_TYPE_MOV;
	case C54X_INS_EXP: return RZ_ANALYSIS_OP_TYPE_MOV;
	case C54X_INS_NORM: return RZ_ANALYSIS_OP_TYPE_MOV;
	case C54X_INS_SFTL: return RZ_ANALYSIS_OP_TYPE_SHL;
	case C54X_INS_SFTA: return RZ_ANALYSIS_OP_TYPE_SAR;
	case C54X_INS_CMPR: return RZ_ANALYSIS_OP_TYPE_CMP;
	case C54X_INS_ABDST: return RZ_ANALYSIS_OP_TYPE_SUB;
	case C54X_INS_ADDM: return RZ_ANALYSIS_OP_TYPE_ADD;
	case C54X_INS_ANDM: return RZ_ANALYSIS_OP_TYPE_AND;
	case C54X_INS_ORM: return RZ_ANALYSIS_OP_TYPE_OR;
	case C54X_INS_XORM: return RZ_ANALYSIS_OP_TYPE_XOR;
	case C54X_INS_FIRS: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_LMS: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_MAX: return RZ_ANALYSIS_OP_TYPE_MOV;
	case C54X_INS_MIN: return RZ_ANALYSIS_OP_TYPE_MOV;
	case C54X_INS_MPYA: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_MVDP: return RZ_ANALYSIS_OP_TYPE_STORE;
	case C54X_INS_POLY: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_READA: return RZ_ANALYSIS_OP_TYPE_LOAD;
	case C54X_INS_WRITA: return RZ_ANALYSIS_OP_TYPE_STORE;
	case C54X_INS_RND: return RZ_ANALYSIS_OP_TYPE_MOV;
	case C54X_INS_ROL: return RZ_ANALYSIS_OP_TYPE_ROL;
	case C54X_INS_ROLTC: return RZ_ANALYSIS_OP_TYPE_ROL;
	case C54X_INS_ROR: return RZ_ANALYSIS_OP_TYPE_ROR;
	case C54X_INS_SAT: return RZ_ANALYSIS_OP_TYPE_MOV;
	case C54X_INS_SFTC: return RZ_ANALYSIS_OP_TYPE_SAR;
	case C54X_INS_SQDST: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_SQUR: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_SQURA: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_SQURS: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_BITT: return RZ_ANALYSIS_OP_TYPE_ACMP;
	case C54X_INS_CMPL: return RZ_ANALYSIS_OP_TYPE_NOT;
	case C54X_INS_FCALA: return RZ_ANALYSIS_OP_TYPE_UCALL;
	case C54X_INS_FCALAD: return RZ_ANALYSIS_OP_TYPE_UCALL;
	case C54X_INS_MPYU: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_MASA: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_BIT: return RZ_ANALYSIS_OP_TYPE_ACMP;
	case C54X_INS_SACCD: return RZ_ANALYSIS_OP_TYPE_STORE;
	case C54X_INS_SRCCD: return RZ_ANALYSIS_OP_TYPE_STORE;
	case C54X_INS_STRCD: return RZ_ANALYSIS_OP_TYPE_STORE;
	case C54X_INS_PORTR: return RZ_ANALYSIS_OP_TYPE_LOAD;
	case C54X_INS_PORTW: return RZ_ANALYSIS_OP_TYPE_STORE;
	case C54X_INS_MASAR: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_ADDS: return RZ_ANALYSIS_OP_TYPE_ADD;
	case C54X_INS_SUBS: return RZ_ANALYSIS_OP_TYPE_SUB;
	case C54X_INS_SUBC: return RZ_ANALYSIS_OP_TYPE_SUB;
	case C54X_INS_LDU: return RZ_ANALYSIS_OP_TYPE_LOAD;
	case C54X_INS_LDR: return RZ_ANALYSIS_OP_TYPE_LOAD;
	case C54X_INS_CMPS: return RZ_ANALYSIS_OP_TYPE_CMP;
	case C54X_INS_DADST: return RZ_ANALYSIS_OP_TYPE_ADD;
	case C54X_INS_DRSUB: return RZ_ANALYSIS_OP_TYPE_SUB;
	case C54X_INS_DSADT: return RZ_ANALYSIS_OP_TYPE_SUB;
	case C54X_INS_MACA: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_MACAR: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_MACP: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_MACSU: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_MACR: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_MASR: return RZ_ANALYSIS_OP_TYPE_MUL;
	case C54X_INS_RC: return RZ_ANALYSIS_OP_TYPE_CRET;
	case C54X_INS_RCD: return RZ_ANALYSIS_OP_TYPE_CRET;
	case C54X_INS_XC: return RZ_ANALYSIS_OP_TYPE_CMOV;
	case C54X_INS_MAR:
	case C54X_INS_DELAY:
	case C54X_INS_FRAME: return RZ_ANALYSIS_OP_TYPE_NULL;
	case C54X_INS_RPT:
	case C54X_INS_RPTB:
	case C54X_INS_RPTZ: return RZ_ANALYSIS_OP_TYPE_REP;
	case C54X_INS_SSBX: return RZ_ANALYSIS_OP_TYPE_OR; // set a status-register bit
	case C54X_INS_RSBX: return RZ_ANALYSIS_OP_TYPE_AND; // clear a status-register bit
	case C54X_INS_RESET: return RZ_ANALYSIS_OP_TYPE_SWI; // software reset (vector, like trap)
	case C54X_INS_IDLE: return RZ_ANALYSIS_OP_TYPE_SYNC; // halt until interrupt
	case C54X_INS_INVALID: return RZ_ANALYSIS_OP_TYPE_ILL;
	default: return RZ_ANALYSIS_OP_TYPE_NULL;
	}
}

/* registers */

static const C55RegInfo c54x_ac_ri[2] = {
	{ "a", "a", 40 }, { "b", "b", 40 }
};

static const C55RegInfo c54x_ar_ri[8] = {
	{ "ar0", "ar0", 16 }, { "ar1", "ar1", 16 }, { "ar2", "ar2", 16 }, { "ar3", "ar3", 16 },
	{ "ar4", "ar4", 16 }, { "ar5", "ar5", 16 }, { "ar6", "ar6", 16 }, { "ar7", "ar7", 16 }
};

static const C55RegInfo c54x_t_ri = { "t", "t", 16 };
static const C55RegInfo c54x_trn_ri = { "trn", "trn", 16 };
static const C55RegInfo c54x_sp_ri = { "sp", "sp", 16 };
static const C55RegInfo c54x_dp_ri = { "dp", "dp", 16 };
static const C55RegInfo c54x_bk_ri = { "bk", "bk", 16 };
static const C55RegInfo c54x_st_ri[3] = {
	{ "st0", "st0", 16 }, { "st1", "st1", 16 }, { "pmst", "pmst", 16 }
};

static const C55RegInfo c54x_special_ri[C54X_SPR_COUNT] = {
	{ "brc", "brc", 16 }, { "rsa", "rsa", 16 }, { "rea", "rea", 16 },
	{ "imr", "imr", 16 }, { "ifr", "ifr", 16 },
	{ "al", "al", 16 }, { "ah", "ah", 16 }, { "ag", "ag", 8 },
	{ "bl", "bl", 16 }, { "bh", "bh", 16 }, { "bg", "bg", 8 },
	{ "xpc", "xpc", 16 }
};

static const C55RegInfo *c54x_reg_info(C55RegClass cls, ut8 num, C55SubReg sub) {
	(void)sub;
	switch (cls) {
	case C55_RC_AC: return num < 2 ? &c54x_ac_ri[num] : NULL;
	case C55_RC_AR: return num < 8 ? &c54x_ar_ri[num] : NULL;
	case C55_RC_T: return num == 0 ? &c54x_t_ri : NULL;
	case C55_RC_TRN: return num == 0 ? &c54x_trn_ri : NULL;
	case C55_RC_SP: return num == 0 ? &c54x_sp_ri : NULL;
	case C55_RC_DP: return num == 0 ? &c54x_dp_ri : NULL;
	case C55_RC_BK: return num == 0 ? &c54x_bk_ri : NULL;
	case C55_RC_ST: return num < 3 ? &c54x_st_ri[num] : NULL;
	case C55_RC_SPECIAL: return num < C54X_SPR_COUNT ? &c54x_special_ri[num] : NULL;
	default: return NULL;
	}
}

// Resolve a C54x memory-mapped-register address (SPRU131 MMR map) to a named
// register, so "pshm AR1" renders the register rather than the raw address.
static bool c54x_mmr_reg(ut8 addr, C55Reg *r) {
	r->sub = C55_SUB_NONE;
	if (addr >= 0x10 && addr <= 0x17) {
		r->cls = C55_RC_AR;
		r->num = (ut8)(addr - 0x10);
		return true;
	}
	switch (addr) {
	case 0x00:
		r->cls = C55_RC_SPECIAL;
		r->num = C54X_SPR_IMR;
		return true;
	case 0x01:
		r->cls = C55_RC_SPECIAL;
		r->num = C54X_SPR_IFR;
		return true;
	case 0x06:
		r->cls = C55_RC_ST;
		r->num = 0;
		return true; // st0
	case 0x07:
		r->cls = C55_RC_ST;
		r->num = 1;
		return true; // st1
	case 0x08:
		r->cls = C55_RC_SPECIAL;
		r->num = C54X_SPR_AL;
		return true;
	case 0x09:
		r->cls = C55_RC_SPECIAL;
		r->num = C54X_SPR_AH;
		return true;
	case 0x0a:
		r->cls = C55_RC_SPECIAL;
		r->num = C54X_SPR_AG;
		return true;
	case 0x0b:
		r->cls = C55_RC_SPECIAL;
		r->num = C54X_SPR_BL;
		return true;
	case 0x0c:
		r->cls = C55_RC_SPECIAL;
		r->num = C54X_SPR_BH;
		return true;
	case 0x0d:
		r->cls = C55_RC_SPECIAL;
		r->num = C54X_SPR_BG;
		return true;
	case 0x0e:
		r->cls = C55_RC_T;
		r->num = 0;
		return true;
	case 0x0f:
		r->cls = C55_RC_TRN;
		r->num = 0;
		return true;
	case 0x18:
		r->cls = C55_RC_SP;
		r->num = 0;
		return true;
	case 0x19:
		r->cls = C55_RC_BK;
		r->num = 0;
		return true;
	case 0x1a:
		r->cls = C55_RC_SPECIAL;
		r->num = C54X_SPR_BRC;
		return true;
	case 0x1b:
		r->cls = C55_RC_SPECIAL;
		r->num = C54X_SPR_RSA;
		return true;
	case 0x1c:
		r->cls = C55_RC_SPECIAL;
		r->num = C54X_SPR_REA;
		return true;
	case 0x1d:
		r->cls = C55_RC_ST;
		r->num = 2;
		return true; // pmst
	case 0x1e:
		r->cls = C55_RC_SPECIAL;
		r->num = C54X_SPR_XPC;
		return true;
	default: return false;
	}
}

/* extractors */

// Accumulator selected by a single S/D bit: 0 -> A, 1 -> B.
static void c54x_x_acc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_AC;
	out->reg.num = (ut8)c54x_field(bits, d->lo, d->width);
	out->reg.sub = C55_SUB_NONE;
	out->width = 40;
}

// Decode the 8-bit single-data-memory (Smem) field: bit 7 = I (0 direct / 1
// indirect), bits 6-3 = MOD, bits 2-0 = ARF (SPRU131 Table 5-4).
static void c54x_fill_smem(ut8 f, C55Operand *out) {
	out->kind = C55_OP_MEM;
	out->access = 16;
	if (!(f & 0x80)) {
		out->amode = C55_AM_DIRECT;
		out->disp = f & 0x7f;
		return;
	}
	ut8 mod = (f >> 3) & 0xf;
	out->reg.cls = C55_RC_AR;
	out->reg.num = f & 0x7;
	out->reg.sub = C55_SUB_NONE;
	out->index.cls = C55_RC_AR; // AR0 for the +0/-0 forms (rendered "+0")
	out->index.num = 0;
	out->index.sub = C55_SUB_NONE;
	switch (mod) {
	case 0: out->amode = C55_AM_INDIRECT; break;
	case 1: out->amode = C55_AM_POSTDEC; break;
	case 2: out->amode = C55_AM_POSTINC; break;
	case 3: out->amode = C55_AM_PREINC; break;
	case 4: out->amode = C55_AM_BITREV_SUB; break;
	case 5: out->amode = C55_AM_POSTSUB; break;
	case 6: out->amode = C55_AM_POSTADD; break;
	case 7: out->amode = C55_AM_BITREV; break;
	case 8:
		out->amode = C55_AM_POSTDEC;
		out->circular = true;
		break;
	case 9:
		out->amode = C55_AM_POSTSUB;
		out->circular = true;
		break;
	case 10:
		out->amode = C55_AM_POSTINC;
		out->circular = true;
		break;
	case 11:
		out->amode = C55_AM_POSTADD;
		out->circular = true;
		break;
	case 12: out->amode = C55_AM_CONST_IDX; break; // *ARx(lk): engine extends +1 word
	case 13: out->amode = C55_AM_CONST_IDX_PRE; break; // *+ARx(lk)
	case 14:
		out->amode = C55_AM_CONST_IDX_PRE;
		out->circular = true;
		break;
	case 15: // *(lk): absolute 16-bit data address
		out->amode = C55_AM_ABS16;
		out->reg.cls = C55_RC_NONE;
		break;
	}
}

static void c54x_x_smem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	c54x_fill_smem((ut8)c54x_field(bits, d->lo, d->width), out);
}

// Memory-mapped register operand (pshm/popm/...). Direct form resolves to a
// named register; the indirect form is a normal Smem.
static void c54x_x_mmr(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 f = (ut8)c54x_field(bits, d->lo, d->width);
	if (f & 0x80) {
		c54x_fill_smem(f, out);
		// MMR-operand instructions (ldm/stlm/pshm/popm/...) are single-word and
		// only allow the 1-word indirect modes (MOD 0-11). The long-offset
		// const-index / ABS16 modes (MOD 12-15) are not legal here, so never let
		// them request a trailing word (which would misalign the stream).
		if (out->amode == C55_AM_CONST_IDX || out->amode == C55_AM_CONST_IDX_PRE ||
			out->amode == C55_AM_ABS16) {
			out->amode = C55_AM_INDIRECT;
			out->circular = false;
			out->reg.cls = C55_RC_AR;
			out->reg.num = f & 0x7;
			out->reg.sub = C55_SUB_NONE;
		}
		return;
	}
	C55Reg r;
	if (c54x_mmr_reg(f & 0x7f, &r)) {
		out->kind = C55_OP_REG;
		out->reg = r;
		return;
	}
	out->kind = C55_OP_MEM;
	out->amode = C55_AM_MMR;
	out->abs_addr = f & 0x7f;
}

// Plain immediate (short K / status-bit / interrupt number).
static void c54x_x_imm(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	out->kind = C55_OP_IMM;
	out->imm = c54x_field(bits, d->lo, d->width);
	out->width = 16;
}

// 16-bit long immediate carried in the second instruction word.
static void c54x_x_lk(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = c54x_field(bits, 0, 16);
	out->width = 16;
}

// 16-bit program-memory branch/call target (pmad, second word).
static void c54x_x_pmad(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = c54x_field(bits, 0, 16);
	out->addr = true;
	out->abs_target = true;
}

// 23-bit extended (far) target: high 7 bits in word1[6:0], low 16 in word2.
static void c54x_x_extpmad(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	ut32 hi = (ut32)c54x_field(bits, 16, 7);
	ut32 lo = (ut32)c54x_field(bits, 0, 16);
	out->kind = C55_OP_IMM;
	out->imm = ((ut64)hi << 16) | lo;
	out->addr = true;
	out->abs_target = true;
}

// 16-bit data-memory address operand (dmad) of the move instructions, and the
// pmad source of mvpd: a bare address, not a control-flow target.
static void c54x_x_dmad(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)d;
	out->kind = C55_OP_IMM;
	out->imm = c54x_field(bits, 0, 16);
	out->addr = true;
}

// Signed short immediate (e.g. frame #-2).
static void c54x_x_simm(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut32 v = (ut32)c54x_field(bits, d->lo, d->width);
	ut32 sign = (ut32)1 << (d->width - 1);
	out->kind = C55_OP_IMM;
	out->imm = (ut64)(st64)(st32)((v ^ sign) - sign);
	out->imm_signed = true;
	out->hash_dec = true;
	out->width = 16;
}

// Fixed T / TRN register operands (the ST T,Smem and ST TRN,Smem stores).
static void c54x_x_t(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)bits;
	(void)d;
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_T;
	out->reg.num = 0;
	out->reg.sub = C55_SUB_NONE;
}

static void c54x_x_trn(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)bits;
	(void)d;
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_TRN;
	out->reg.num = 0;
	out->reg.sub = C55_SUB_NONE;
}

// 4-bit memory-mapped register field of MVMM (0-7 -> AR0..AR7, 8 -> SP).
static void c54x_x_mmr4(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 v = (ut8)c54x_field(bits, d->lo, d->width);
	out->kind = C55_OP_REG;
	out->reg.sub = C55_SUB_NONE;
	if (v == 8) {
		out->reg.cls = C55_RC_SP;
		out->reg.num = 0;
	} else {
		out->reg.cls = C55_RC_AR;
		out->reg.num = (ut8)(v & 7);
	}
}

// Dual-operand (Xmem/Ymem) 4-bit field: mod in bits 3-2, ARx (AR2..AR5) in 1-0.
static void c54x_fill_dual_mem(ut8 f, C55Operand *out) {
	out->kind = C55_OP_MEM;
	out->access = 16;
	out->reg.cls = C55_RC_AR;
	out->reg.num = (ut8)(2 + (f & 3));
	out->reg.sub = C55_SUB_NONE;
	switch ((f >> 2) & 3) {
	case 0: out->amode = C55_AM_INDIRECT; break;
	case 1: out->amode = C55_AM_POSTDEC; break;
	case 2: out->amode = C55_AM_POSTINC; break;
	case 3: // *ARx+0%
		out->amode = C55_AM_POSTADD;
		out->circular = true;
		out->index.cls = C55_RC_AR;
		out->index.num = 0;
		out->index.sub = C55_SUB_NONE;
		break;
	}
}

static void c54x_x_xmem(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	c54x_fill_dual_mem((ut8)c54x_field(bits, d->lo, d->width), out);
}

// C54x branch/call condition codes (SPRU172 Appendix A). Only the single-condition
// values are named; combined conditions (an OR of group codes) render numerically.
static const char *c54x_cond_name(ut8 cc) {
	switch (cc) {
	case 0x00: return "unc";
	case 0x02: return "nbio";
	case 0x03: return "bio";
	case 0x08: return "nc";
	case 0x0c: return "c";
	case 0x20: return "ntc";
	case 0x30: return "tc";
	case 0x42: return "ageq";
	case 0x43: return "alt";
	case 0x44: return "aneq";
	case 0x45: return "aeq";
	case 0x46: return "agt";
	case 0x47: return "aleq";
	case 0x4a: return "bgeq";
	case 0x4b: return "blt";
	case 0x4c: return "bneq";
	case 0x4d: return "beq";
	case 0x4e: return "bgt";
	case 0x4f: return "bleq";
	case 0x60: return "anov";
	case 0x68: return "bnov";
	case 0x70: return "aov";
	case 0x78: return "bov";
	default: return NULL;
	}
}

// Render an 8-bit branch/call/return/execute condition field. Single conditions
// resolve via c54x_cond_name; the TC (bits 5-4), C (bits 3-2) and BIO (bits 1-0)
// groups may be OR-combined and are decomposed into "a, b[, c]" here. Returns
// NULL for an unrecognized field so the caller can fall back to a bare value.
static const char *c54x_cond_str(ut8 cc) {
	const char *n = c54x_cond_name(cc);
	if (n) {
		return n;
	}
	if (cc & 0xc0) {
		return NULL; // accumulator-group conditions do not OR-combine cleanly
	}
	// The TC/C/BIO multi-condition: each 2-bit field is absent (0 or 1),
	// negated (2) or asserted (3). The result is one of a fixed set of joined
	// strings, so look it up directly rather than formatting into a buffer.
	ut8 tc = (cc >> 4) & 3, c = (cc >> 2) & 3, bio = cc & 3;
	ut8 tn = tc < 2 ? 0 : tc - 1, cn = c < 2 ? 0 : c - 1, bn = bio < 2 ? 0 : bio - 1;
	// indexed by tn*9 + cn*3 + bn (0 = absent, 1 = negated, 2 = asserted);
	// single-condition and empty combinations stay NULL (handled elsewhere).
	static const char *const tab[27] = {
		NULL, NULL, NULL,
		NULL, "nc, nbio", "nc, bio",
		NULL, "c, nbio", "c, bio",
		NULL, "ntc, nbio", "ntc, bio",
		"ntc, nc", "ntc, nc, nbio", "ntc, nc, bio",
		"ntc, c", "ntc, c, nbio", "ntc, c, bio",
		NULL, "tc, nbio", "tc, bio",
		"tc, nc", "tc, nc, nbio", "tc, nc, bio",
		"tc, c", "tc, c, nbio", "tc, c, bio"
	};
	return tab[tn * 9 + cn * 3 + bn];
}

static void c54x_x_cond(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 cc = (ut8)c54x_field(bits, d->lo, d->width);
	const char *n = c54x_cond_str(cc);
	out->kind = C55_OP_IMM;
	out->imm = cc;
	if (n) {
		out->raw = n;
	}
}

// ssbx/rsbx status bit: N (bit 9) selects ST0/ST1, SBIT (bits 3-0) the bit.
static const char *c54x_status_bit(ut8 n, ut8 sbit) {
	if (n) { // ST1
		switch (sbit) {
		case 5: return "cmpt";
		case 6: return "frct";
		case 7: return "c16";
		case 8: return "sxm";
		case 9: return "ovm";
		case 11: return "intm";
		case 12: return "hm";
		case 13: return "xf";
		case 14: return "cpl";
		case 15: return "braf";
		}
	} else { // ST0
		switch (sbit) {
		case 9: return "ovb";
		case 10: return "ova";
		case 11: return "c";
		case 12: return "tc";
		}
	}
	return NULL;
}

static void c54x_x_stbit(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)d;
	(void)a;
	ut8 n = (ut8)c54x_field(bits, 9, 1);
	ut8 sbit = (ut8)c54x_field(bits, 0, 4);
	const char *nm = c54x_status_bit(n, sbit);
	out->kind = C55_OP_IMM;
	if (nm) {
		out->raw = nm;
	} else {
		out->imm = sbit;
	}
}

// Shift counts render as a bare decimal (the "Smem, 5, src" / "#lk, 5, dst" forms).
static const char *const c54x_shift_str[16] = {
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15"
};

// 4-bit SHFT that is omitted entirely when zero (the long-immediate forms render
// "add #lk, src" rather than "add #lk, 0, src").
static void c54x_x_shft(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 sh = (ut8)c54x_field(bits, d->lo, d->width) & 0xf;
	if (sh == 0) {
		out->kind = C55_OP_NONE;
		return;
	}
	out->kind = C55_OP_IMM;
	out->raw = c54x_shift_str[sh];
	out->is_shift = true;
	out->shamt = (int8_t)sh; // 4-bit SHFT is an unsigned left shift
	out->sh_left = true;
}

// 4-bit SHFT that is always rendered (the shift-then-store/load Xmem forms).
static void c54x_x_shftx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 sh = (ut8)c54x_field(bits, d->lo, d->width) & 0xf;
	out->kind = C55_OP_IMM;
	out->raw = c54x_shift_str[sh];
	out->is_shift = true;
	out->shamt = (int8_t)sh;
	out->sh_left = true;
}

// The literal "16" operand of the shift-by-16 load/arithmetic forms.
static void c54x_x_lit16(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)bits;
	(void)d;
	out->kind = C55_OP_IMM;
	out->raw = "16";
	out->is_shift = true;
	out->shamt = 16;
	out->sh_left = true;
}

// Destination accumulator that is omitted when it equals the source (ACy -> ACx).
static void c54x_x_acc_elide(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_AC;
	out->reg.num = (ut8)c54x_field(bits, d->lo, d->width);
	out->reg.sub = C55_SUB_NONE;
	out->width = 40;
	out->elide_if_eq_prev = true;
}

// idle mode operand: the 2-bit NN field maps non-linearly to 1/2/3.
static void c54x_x_idle(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	static const char *const k[4] = { "1", "3", "2", NULL };
	ut8 nn = (ut8)c54x_field(bits, d->lo, d->width) & 3;
	out->kind = C55_OP_IMM;
	if (k[nn]) {
		out->raw = k[nn];
	} else {
		out->imm = nn;
	}
}

// Signed 5-bit shift count (-16..15) of the accumulator-shift / dual-accumulator
// forms, indexed by the raw field value.
static const char *const c54x_sft5_str[32] = {
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15",
	"-16", "-15", "-14", "-13", "-12", "-11", "-10", "-9", "-8", "-7", "-6", "-5", "-4", "-3", "-2", "-1"
};

// Decode the signed 5-bit field into the operand's numeric shift (positive =
// left, negative = arithmetic right), carried as magnitude + direction.
static void c54x_sft5_fill(ut8 v, C55Operand *out) {
	int s = (v < 16) ? (int)v : (int)v - 32;
	out->is_shift = true;
	out->shamt = (int8_t)(s < 0 ? -s : s);
	out->sh_left = s >= 0;
}

// Variant that omits a zero shift (op src, dst rather than op src, 0, dst).
static void c54x_x_sft5(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 v = (ut8)c54x_field(bits, d->lo, d->width) & 0x1f;
	if (v == 0) {
		out->kind = C55_OP_NONE;
		return;
	}
	out->kind = C55_OP_IMM;
	out->raw = c54x_sft5_str[v];
	c54x_sft5_fill(v, out);
}

// Variant that always renders the shift (the sftl forms).
static void c54x_x_sft5a(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 v = (ut8)c54x_field(bits, d->lo, d->width) & 0x1f;
	out->kind = C55_OP_IMM;
	out->raw = c54x_sft5_str[v];
	c54x_sft5_fill(v, out);
}

// Destination accumulator of the shift forms: omitted when it equals the source.
// The source bit position is passed in `param`, so it works even when a shift
// operand sits between the source and this destination.
static void c54x_x_acc_dst_if_diff(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 dst = (ut8)c54x_field(bits, d->lo, d->width);
	ut8 src = (ut8)c54x_field(bits, d->param, 1);
	if (dst == src) {
		out->kind = C55_OP_NONE;
		return;
	}
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_AC;
	out->reg.num = dst;
	out->reg.sub = C55_SUB_NONE;
	out->width = 40;
}

// 3-bit auxiliary-register selector (AR0-AR7), used by cmpr.
static void c54x_x_arx(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_AR;
	out->reg.num = (ut8)c54x_field(bits, d->lo, d->width) & 7;
	out->reg.sub = C55_SUB_NONE;
	out->width = 16;
}

// 2-bit compare condition code of cmpr, rendered as a bare 0..3.
static void c54x_x_cmpcc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 cc = (ut8)c54x_field(bits, d->lo, d->width) & 3;
	out->kind = C55_OP_IMM;
	out->raw = c54x_shift_str[cc];
	out->imm = cc; // 0:EQ 1:LT 2:GT 3:NEQ (vs AR0)
}

// Fixed accumulator A (the implicit source of squr A, dst).
static void c54x_x_acc_a(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)bits;
	(void)d;
	out->kind = C55_OP_REG;
	out->reg.cls = C55_RC_AC;
	out->reg.num = 0;
	out->reg.sub = C55_SUB_NONE;
	out->width = 40;
}

// 4-bit condition code used by the conditional stores (saccd/srccd/strcd):
// bit 3 selects accumulator A/B, bits 2-0 select the comparison.
static const char *c54x_cond4_name(ut8 cc) {
	switch (cc & 0xf) {
	case 0x2: return "ageq";
	case 0x3: return "alt";
	case 0x4: return "aneq";
	case 0x5: return "aeq";
	case 0x6: return "agt";
	case 0x7: return "aleq";
	case 0xa: return "bgeq";
	case 0xb: return "blt";
	case 0xc: return "bneq";
	case 0xd: return "beq";
	case 0xe: return "bgt";
	case 0xf: return "bleq";
	default: return NULL;
	}
}

static void c54x_x_cond4(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 cc = (ut8)c54x_field(bits, d->lo, d->width) & 0xf;
	const char *nm = c54x_cond4_name(cc);
	out->kind = C55_OP_IMM;
	out->imm = cc;
	if (nm) {
		out->raw = nm;
	}
}

// 4-bit bit number of the bit-test instruction, rendered as a bare decimal.
static void c54x_x_bitc(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 bc = (ut8)c54x_field(bits, d->lo, d->width) & 0xf;
	out->kind = C55_OP_IMM;
	out->raw = c54x_shift_str[bc];
	out->imm = bc; // BIT tests Smem bit (15 - bc)
}

// Fixed shift-mode / register keywords selected by the operand's param index:
// 0 = ts (shift by TREG), 1 = asm (shift by ASM field), 2 = dp, 3 = arp.
static const char *const c54x_kw_tab[] = { "ts", "asm", "dp", "arp" };
static void c54x_x_kw(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	(void)bits;
	out->kind = C55_OP_IMM;
	out->raw = c54x_kw_tab[d->param];
}

// Second operation of a C54x parallel instruction ("st .. || <op2> .."): renders
// the verbatim "|| <mnemonic>" via qual_join. param indexes the base mnemonic;
// when width==1 the round bit at lo selects the "..r" variant in the next slot.
static const char *const c54x_par2_tab[] = { "add", "sub", "mpy", "ld", "mac", "macr", "mas", "masr" };
static void c54x_x_par2(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	ut8 idx = d->param;
	if (d->width == 1 && c54x_field(bits, d->lo, 1)) {
		idx++; // rounding variant (mac -> macr, mas -> masr)
	}
	out->kind = C55_OP_IMM;
	out->raw = c54x_par2_tab[idx];
	out->qual_join = true;
}

// 4-bit Xmem of a parallel second operation, space-joined to the "|| <mnem>".
static void c54x_x_xmem_par(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	c54x_x_xmem(a, bits, d, out);
	out->space_join = true;
}

// XC instruction count "n": bit 9 selects 1 (the next single word) or 2 words.
static void c54x_x_xcn(const C55ArchDesc *a, ut64 bits, const C55OpDesc *d, C55Operand *out) {
	(void)a;
	out->kind = C55_OP_IMM;
	out->raw = c54x_field(bits, d->lo, 1) ? "2" : "1";
}

/* table */

// All matches operate on the big-endian head: the (swapped) opcode word lands
// in head[31:16], so a 1-word match uses mask 0xXXXX0000. Operand .lo/.width
// count from the LSB of c55_pack(buf, ilen): for a 1-word (len 2) instruction
// that is the opcode word [15:0]; for a 2-word (len 4) instruction word1 is at
// [31:16] and word2 at [15:0].
static const C55InsnDef c54x_table[] = {
	// control
	{ .mask = 0xffff0000, .match = 0xf4950000, .id = C54X_INS_NOP, .len = 2 },
	{ .mask = 0xffff0000, .match = 0xf0730000, .id = C54X_INS_B, .len = 4, .ops = { { .fn = c54x_x_pmad } } },
	{ .mask = 0xffff0000, .match = 0xf2730000, .id = C54X_INS_BD, .len = 4, .ops = { { .fn = c54x_x_pmad } } }, // bd
	{ .mask = 0xffff0000, .match = 0xf0740000, .id = C54X_INS_CALL, .len = 4, .ops = { { .fn = c54x_x_pmad } } },
	{ .mask = 0xffff0000, .match = 0xf2740000, .id = C54X_INS_CALLD, .len = 4, .ops = { { .fn = c54x_x_pmad } } }, // calld
	{ .mask = 0xfeff0000, .match = 0xf4e20000, .id = C54X_INS_BACC, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xffff0000, .match = 0xfc000000, .id = C54X_INS_RET, .len = 2 },
	{ .mask = 0xffff0000, .match = 0xfe000000, .id = C54X_INS_RETD, .len = 2 }, // retd
	{ .mask = 0xffff0000, .match = 0xf4eb0000, .id = C54X_INS_RETE, .len = 2 },
	{ .mask = 0xffff0000, .match = 0xf6eb0000, .id = C54X_INS_RETED, .len = 2 }, // reted
	{ .mask = 0xffff0000, .match = 0xf49b0000, .id = C54X_INS_RETF, .len = 2 },
	{ .mask = 0xffff0000, .match = 0xf69b0000, .id = C54X_INS_RETFD, .len = 2 }, // retfd
	// far (C548 extended addressing)
	{ .mask = 0xff800000, .match = 0xf8800000, .id = C54X_INS_FB, .len = 4, .ops = { { .fn = c54x_x_extpmad } } },
	{ .mask = 0xff800000, .match = 0xfa800000, .id = C54X_INS_FBD, .len = 4, .ops = { { .fn = c54x_x_extpmad } } }, // fbd
	{ .mask = 0xff800000, .match = 0xf9800000, .id = C54X_INS_FCALL, .len = 4, .ops = { { .fn = c54x_x_extpmad } } },
	{ .mask = 0xff800000, .match = 0xfb800000, .id = C54X_INS_FCALLD, .len = 4, .ops = { { .fn = c54x_x_extpmad } } }, // fcalld
	{ .mask = 0xfeff0000, .match = 0xf4e60000, .id = C54X_INS_FBACC, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xffff0000, .match = 0xf4e40000, .id = C54X_INS_FRET, .len = 2 },
	{ .mask = 0xffff0000, .match = 0xf6e40000, .id = C54X_INS_FRETD, .len = 2 }, // fretd
	{ .mask = 0xffff0000, .match = 0xf4e50000, .id = C54X_INS_FRETE, .len = 2 },
	{ .mask = 0xffff0000, .match = 0xf6e50000, .id = C54X_INS_FRETED, .len = 2 }, // freted
	// system / status
	{ .mask = 0xffff0000, .match = 0xf7e00000, .id = C54X_INS_RESET, .len = 2 },
	{ .mask = 0xffe00000, .match = 0xf4c00000, .id = C54X_INS_TRAP, .len = 2, .ops = { { .lo = 0, .width = 5, .fn = c54x_x_imm } } },
	{ .mask = 0xffe00000, .match = 0xf7c00000, .id = C54X_INS_INTR, .len = 2, .ops = { { .lo = 0, .width = 5, .fn = c54x_x_imm } } },
	{ .mask = 0xfcff0000, .match = 0xf4e10000, .id = C54X_INS_IDLE, .len = 2, .ops = { { .lo = 8, .width = 2, .fn = c54x_x_idle } } },
	{ .mask = 0xfdf00000, .match = 0xf5b00000, .id = C54X_INS_SSBX, .len = 2, .ops = { { .fn = c54x_x_stbit } } },
	{ .mask = 0xfdf00000, .match = 0xf4b00000, .id = C54X_INS_RSBX, .len = 2, .ops = { { .fn = c54x_x_stbit } } },
	// repeat
	{ .mask = 0xff000000, .match = 0xec000000, .id = C54X_INS_RPT, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_imm } } },
	{ .mask = 0xff000000, .match = 0x47000000, .id = C54X_INS_RPT, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xffff0000, .match = 0xf0720000, .id = C54X_INS_RPTB, .len = 4, .ops = { { .fn = c54x_x_pmad } } },
	{ .mask = 0xffff0000, .match = 0xf2720000, .id = C54X_INS_RPTBD, .len = 4, .ops = { { .fn = c54x_x_pmad } } }, // rptbd
	{ .mask = 0xfeff0000, .match = 0xf0710000, .id = C54X_INS_RPTZ, .len = 4, .ops = { { .lo = 24, .width = 1, .fn = c54x_x_acc }, { .fn = c54x_x_lk } } },
	// load / arithmetic
	{ .mask = 0xfe000000, .match = 0x10000000, .id = C54X_INS_LD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0xe8000000, .id = C54X_INS_LD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_imm }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x00000000, .id = C54X_INS_ADD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x08000000, .id = C54X_INS_SUB, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	// stack
	{ .mask = 0xff000000, .match = 0x4a000000, .id = C54X_INS_PSHM, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_mmr } } },
	{ .mask = 0xff000000, .match = 0x8a000000, .id = C54X_INS_POPM, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_mmr } } },
	{ .mask = 0xff000000, .match = 0x4b000000, .id = C54X_INS_PSHD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x8b000000, .id = C54X_INS_POPD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	// stores
	{ .mask = 0xfe000000, .match = 0x80000000, .id = C54X_INS_STL, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xfe000000, .match = 0x82000000, .id = C54X_INS_STH, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xfe000000, .match = 0x88000000, .id = C54X_INS_STLM, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 8, .fn = c54x_x_mmr } } },
	{ .mask = 0xff000000, .match = 0x8c000000, .id = C54X_INS_ST, .len = 2, .ops = { { .fn = c54x_x_t }, { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x8d000000, .id = C54X_INS_ST, .len = 2, .ops = { { .fn = c54x_x_trn }, { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x76000000, .id = C54X_INS_ST, .len = 4, .ops = { { .fn = c54x_x_lk }, { .lo = 16, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x77000000, .id = C54X_INS_STM, .len = 4, .ops = { { .fn = c54x_x_lk }, { .lo = 16, .width = 8, .fn = c54x_x_mmr } } },
	// logical
	{ .mask = 0xfe000000, .match = 0x18000000, .id = C54X_INS_AND, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x1a000000, .id = C54X_INS_OR, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x1c000000, .id = C54X_INS_XOR, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	// moves
	{ .mask = 0xff000000, .match = 0xe5000000, .id = C54X_INS_MVDD, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_xmem } } },
	{ .mask = 0xff000000, .match = 0x71000000, .id = C54X_INS_MVDK, .len = 4, .ops = { { .lo = 16, .width = 8, .fn = c54x_x_smem }, { .fn = c54x_x_dmad } } },
	{ .mask = 0xff000000, .match = 0x72000000, .id = C54X_INS_MVDM, .len = 4, .ops = { { .fn = c54x_x_dmad }, { .lo = 16, .width = 8, .fn = c54x_x_mmr } } },
	{ .mask = 0xff000000, .match = 0x70000000, .id = C54X_INS_MVKD, .len = 4, .ops = { { .fn = c54x_x_dmad }, { .lo = 16, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x73000000, .id = C54X_INS_MVMD, .len = 4, .ops = { { .lo = 16, .width = 8, .fn = c54x_x_mmr }, { .fn = c54x_x_dmad } } },
	{ .mask = 0xff000000, .match = 0xe7000000, .id = C54X_INS_MVMM, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_mmr4 }, { .lo = 0, .width = 4, .fn = c54x_x_mmr4 } } },
	{ .mask = 0xff000000, .match = 0x7c000000, .id = C54X_INS_MVPD, .len = 4, .ops = { { .fn = c54x_x_dmad }, { .lo = 16, .width = 8, .fn = c54x_x_smem } } },
	// aux-register modify / delay
	{ .mask = 0xff000000, .match = 0x6d000000, .id = C54X_INS_MAR, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x4d000000, .id = C54X_INS_DELAY, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0xee000000, .id = C54X_INS_FRAME, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_simm } } },
	{ .mask = 0xff000000, .match = 0x61000000, .id = C54X_INS_BITF, .len = 4, .ops = { { .lo = 16, .width = 8, .fn = c54x_x_smem }, { .fn = c54x_x_lk } } },
	{ .mask = 0xff000000, .match = 0x60000000, .id = C54X_INS_CMPM, .len = 4, .ops = { { .lo = 16, .width = 8, .fn = c54x_x_smem }, { .fn = c54x_x_lk } } },
	// conditional branch / call
	{ .mask = 0xff800000, .match = 0xf8000000, .id = C54X_INS_BC, .len = 4, .ops = { { .fn = c54x_x_pmad }, { .lo = 16, .width = 8, .fn = c54x_x_cond } } },
	{ .mask = 0xff800000, .match = 0xfa000000, .id = C54X_INS_BCD, .len = 4, .ops = { { .fn = c54x_x_pmad }, { .lo = 16, .width = 8, .fn = c54x_x_cond } } }, // bcd
	{ .mask = 0xff800000, .match = 0xf9000000, .id = C54X_INS_CC, .len = 4, .ops = { { .fn = c54x_x_pmad }, { .lo = 16, .width = 8, .fn = c54x_x_cond } } },
	{ .mask = 0xff800000, .match = 0xfb000000, .id = C54X_INS_CCD, .len = 4, .ops = { { .fn = c54x_x_pmad }, { .lo = 16, .width = 8, .fn = c54x_x_cond } } }, // ccd
	{ .mask = 0xff000000, .match = 0x6c000000, .id = C54X_INS_BANZ, .len = 4, .ops = { { .fn = c54x_x_pmad }, { .lo = 16, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x6e000000, .id = C54X_INS_BANZD, .len = 4, .ops = { { .fn = c54x_x_pmad }, { .lo = 16, .width = 8, .fn = c54x_x_smem } } }, // banzd
	{ .mask = 0xfeff0000, .match = 0xf4e30000, .id = C54X_INS_CALA, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfeff0000, .match = 0xf6e20000, .id = C54X_INS_BACCD, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfeff0000, .match = 0xf6e30000, .id = C54X_INS_CALAD, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	// long-immediate (#lk) arithmetic/logical/load (1111 00SD <subop> SHFT + lk)
	{ .mask = 0xfcf00000, .match = 0xf0000000, .id = C54X_INS_ADD, .len = 4, .ops = { { .fn = c54x_x_lk }, { .lo = 16, .width = 4, .fn = c54x_x_shft }, { .lo = 25, .width = 1, .fn = c54x_x_acc }, { .lo = 24, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfcf00000, .match = 0xf0100000, .id = C54X_INS_SUB, .len = 4, .ops = { { .fn = c54x_x_lk }, { .lo = 16, .width = 4, .fn = c54x_x_shft }, { .lo = 25, .width = 1, .fn = c54x_x_acc }, { .lo = 24, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfef00000, .match = 0xf0200000, .id = C54X_INS_LD, .len = 4, .ops = { { .fn = c54x_x_lk }, { .lo = 16, .width = 4, .fn = c54x_x_shft }, { .lo = 24, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfcf00000, .match = 0xf0300000, .id = C54X_INS_AND, .len = 4, .ops = { { .fn = c54x_x_lk }, { .lo = 16, .width = 4, .fn = c54x_x_shft }, { .lo = 25, .width = 1, .fn = c54x_x_acc }, { .lo = 24, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfcf00000, .match = 0xf0400000, .id = C54X_INS_OR, .len = 4, .ops = { { .fn = c54x_x_lk }, { .lo = 16, .width = 4, .fn = c54x_x_shft }, { .lo = 25, .width = 1, .fn = c54x_x_acc }, { .lo = 24, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfcf00000, .match = 0xf0500000, .id = C54X_INS_XOR, .len = 4, .ops = { { .fn = c54x_x_lk }, { .lo = 16, .width = 4, .fn = c54x_x_shft }, { .lo = 25, .width = 1, .fn = c54x_x_acc }, { .lo = 24, .width = 1, .fn = c54x_x_acc_elide } } },
	// shift-then-store/load via Xmem (1001 ...)
	{ .mask = 0xfe000000, .match = 0x90000000, .id = C54X_INS_ADD, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_shftx }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x92000000, .id = C54X_INS_SUB, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_shftx }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x94000000, .id = C54X_INS_LD, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_shftx }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x98000000, .id = C54X_INS_STL, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 4, .fn = c54x_x_shftx }, { .lo = 4, .width = 4, .fn = c54x_x_xmem } } },
	{ .mask = 0xfe000000, .match = 0x9a000000, .id = C54X_INS_STH, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 4, .fn = c54x_x_shftx }, { .lo = 4, .width = 4, .fn = c54x_x_xmem } } },
	// dual-operand (Xmem, Ymem, dst)
	{ .mask = 0xfe000000, .match = 0xa0000000, .id = C54X_INS_ADD, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_xmem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0xa2000000, .id = C54X_INS_SUB, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_xmem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	// shift-by-16
	{ .mask = 0xfe000000, .match = 0x44000000, .id = C54X_INS_LD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .fn = c54x_x_lit16 }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfc000000, .match = 0x3c000000, .id = C54X_INS_ADD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .fn = c54x_x_lit16 }, { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	// multiply
	{ .mask = 0xfe000000, .match = 0x20000000, .id = C54X_INS_MPY, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	// load MMR / load-T-with-delay
	{ .mask = 0xfe000000, .match = 0x48000000, .id = C54X_INS_LDM, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_mmr }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xff000000, .match = 0x4c000000, .id = C54X_INS_LTD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	// add/sub with carry/borrow
	{ .mask = 0xfe000000, .match = 0x06000000, .id = C54X_INS_ADDC, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x0e000000, .id = C54X_INS_SUBB, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	// double / long-word (Lmem)
	{ .mask = 0xfc000000, .match = 0x50000000, .id = C54X_INS_DADD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfe000000, .match = 0x54000000, .id = C54X_INS_DSUB, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x5c000000, .id = C54X_INS_DSUBT, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x56000000, .id = C54X_INS_DLD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x4e000000, .id = C54X_INS_DST, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	// multiply-accumulate family
	{ .mask = 0xfe000000, .match = 0x28000000, .id = C54X_INS_MAC, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x2c000000, .id = C54X_INS_MAS, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x7a000000, .id = C54X_INS_MACD, .len = 4, .ops = { { .lo = 16, .width = 8, .fn = c54x_x_smem }, { .fn = c54x_x_dmad }, { .lo = 24, .width = 1, .fn = c54x_x_acc } } },
	// unary accumulator ops
	{ .mask = 0xfcff0000, .match = 0xf4840000, .id = C54X_INS_NEG, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfcff0000, .match = 0xf4850000, .id = C54X_INS_ABS, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfeff0000, .match = 0xf48e0000, .id = C54X_INS_EXP, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfcff0000, .match = 0xf48f0000, .id = C54X_INS_NORM, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	// dual-accumulator ops: op src [, SHIFT], dst (no memory operand)
	// group 1111 00SD <op:3> <signed-5bit-shift>: AND/OR/XOR/SFTL
	{ .mask = 0xfce00000, .match = 0xf0800000, .id = C54X_INS_AND, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 5, .fn = c54x_x_sft5 }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfce00000, .match = 0xf0a00000, .id = C54X_INS_OR, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 5, .fn = c54x_x_sft5 }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfce00000, .match = 0xf0c00000, .id = C54X_INS_XOR, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 5, .fn = c54x_x_sft5 }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfce00000, .match = 0xf0e00000, .id = C54X_INS_SFTL, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 5, .fn = c54x_x_sft5a }, { .lo = 8, .width = 1, .param = 9, .fn = c54x_x_acc_dst_if_diff } } },
	// group 1111 01SD <op:3> <signed-5bit-shift>: ADD/SUB/LD/SFTA
	{ .mask = 0xfce00000, .match = 0xf4000000, .id = C54X_INS_ADD, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 5, .fn = c54x_x_sft5 }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfce00000, .match = 0xf4200000, .id = C54X_INS_SUB, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 5, .fn = c54x_x_sft5 }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfce00000, .match = 0xf4400000, .id = C54X_INS_LD, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 5, .fn = c54x_x_sft5 }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfce00000, .match = 0xf4600000, .id = C54X_INS_SFTA, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 5, .fn = c54x_x_sft5a }, { .lo = 8, .width = 1, .param = 9, .fn = c54x_x_acc_dst_if_diff } } },
	// cmpr CC, ARx
	{ .mask = 0xfcf80000, .match = 0xf4a80000, .id = C54X_INS_CMPR, .len = 2, .ops = { { .lo = 8, .width = 2, .fn = c54x_x_cmpcc }, { .lo = 0, .width = 3, .fn = c54x_x_arx } } },
	// Xmem,Ymem dual-data ops
	{ .mask = 0xff000000, .match = 0xe3000000, .id = C54X_INS_ABDST, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_xmem } } },
	{ .mask = 0xff000000, .match = 0xe1000000, .id = C54X_INS_LMS, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_xmem } } },
	{ .mask = 0xff000000, .match = 0xe2000000, .id = C54X_INS_SQDST, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_xmem } } },
	{ .mask = 0xff000000, .match = 0xe0000000, .id = C54X_INS_FIRS, .len = 4, .ops = { { .lo = 20, .width = 4, .fn = c54x_x_xmem }, { .lo = 16, .width = 4, .fn = c54x_x_xmem }, { .fn = c54x_x_dmad } } },
	// memory-immediate (#lk, Smem)
	{ .mask = 0xff000000, .match = 0x6b000000, .id = C54X_INS_ADDM, .len = 4, .ops = { { .fn = c54x_x_lk }, { .lo = 16, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x68000000, .id = C54X_INS_ANDM, .len = 4, .ops = { { .fn = c54x_x_lk }, { .lo = 16, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x69000000, .id = C54X_INS_ORM, .len = 4, .ops = { { .fn = c54x_x_lk }, { .lo = 16, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x6a000000, .id = C54X_INS_XORM, .len = 4, .ops = { { .fn = c54x_x_lk }, { .lo = 16, .width = 8, .fn = c54x_x_smem } } },
	// square / multiply variants
	{ .mask = 0xfe000000, .match = 0x26000000, .id = C54X_INS_SQUR, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x38000000, .id = C54X_INS_SQURA, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x3a000000, .id = C54X_INS_SQURS, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x24000000, .id = C54X_INS_MPYU, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	// Smem-only ops
	{ .mask = 0xff000000, .match = 0x31000000, .id = C54X_INS_MPYA, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x36000000, .id = C54X_INS_POLY, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x33000000, .id = C54X_INS_MASA, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x34000000, .id = C54X_INS_BITT, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x7e000000, .id = C54X_INS_READA, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x7f000000, .id = C54X_INS_WRITA, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x7d000000, .id = C54X_INS_MVDP, .len = 4, .ops = { { .lo = 16, .width = 8, .fn = c54x_x_smem }, { .fn = c54x_x_dmad } } },
	// single-accumulator (bit 8) ops
	{ .mask = 0xfeff0000, .match = 0xf4860000, .id = C54X_INS_MAX, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfeff0000, .match = 0xf4870000, .id = C54X_INS_MIN, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfeff0000, .match = 0xf4830000, .id = C54X_INS_SAT, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfeff0000, .match = 0xf4900000, .id = C54X_INS_ROR, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfeff0000, .match = 0xf4910000, .id = C54X_INS_ROL, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfeff0000, .match = 0xf4920000, .id = C54X_INS_ROLTC, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfeff0000, .match = 0xf4940000, .id = C54X_INS_SFTC, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfeff0000, .match = 0xf48c0000, .id = C54X_INS_MPYA, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfeff0000, .match = 0xf48d0000, .id = C54X_INS_SQUR, .len = 2, .ops = { { .fn = c54x_x_acc_a }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	// src, dst (bits 9/8) ops
	{ .mask = 0xfcff0000, .match = 0xf49f0000, .id = C54X_INS_RND, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfcff0000, .match = 0xf4930000, .id = C54X_INS_CMPL, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	// far call to accumulator (delayed variant)
	{ .mask = 0xfeff0000, .match = 0xf4e70000, .id = C54X_INS_FCALA, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfeff0000, .match = 0xf6e70000, .id = C54X_INS_FCALAD, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	// bit test / conditional stores
	{ .mask = 0xff000000, .match = 0x96000000, .id = C54X_INS_BIT, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_bitc } } },
	{ .mask = 0xfe000000, .match = 0x9e000000, .id = C54X_INS_SACCD, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc }, { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_cond4 } } },
	{ .mask = 0xff000000, .match = 0x9d000000, .id = C54X_INS_SRCCD, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_cond4 } } },
	{ .mask = 0xff000000, .match = 0x9c000000, .id = C54X_INS_STRCD, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_cond4 } } },
	// I/O port access (PA in the second word)
	{ .mask = 0xff000000, .match = 0x74000000, .id = C54X_INS_PORTR, .len = 4, .ops = { { .fn = c54x_x_dmad }, { .lo = 16, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x75000000, .id = C54X_INS_PORTW, .len = 4, .ops = { { .lo = 16, .width = 8, .fn = c54x_x_smem }, { .fn = c54x_x_dmad } } },
	// multiply-subtract with TREG (register form), optional rounding
	{ .mask = 0xfcff0000, .match = 0xf48a0000, .id = C54X_INS_MASA, .len = 2, .ops = { { .fn = c54x_x_t }, { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfcff0000, .match = 0xf48b0000, .id = C54X_INS_MASAR, .len = 2, .ops = { { .fn = c54x_x_t }, { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	// new 1-word Smem,acc mnemonics
	{ .mask = 0xfe000000, .match = 0x02000000, .id = C54X_INS_ADDS, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x0a000000, .id = C54X_INS_SUBS, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x1e000000, .id = C54X_INS_SUBC, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x12000000, .id = C54X_INS_LDU, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x16000000, .id = C54X_INS_LDR, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x5a000000, .id = C54X_INS_DADST, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x58000000, .id = C54X_INS_DRSUB, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x5e000000, .id = C54X_INS_DSADT, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x8e000000, .id = C54X_INS_CMPS, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	// multiply-by-A / signed-unsigned / program-memory MAC variants
	{ .mask = 0xff000000, .match = 0x35000000, .id = C54X_INS_MACA, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff000000, .match = 0x37000000, .id = C54X_INS_MACAR, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xfcff0000, .match = 0xf4880000, .id = C54X_INS_MACA, .len = 2, .ops = { { .fn = c54x_x_t }, { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfcff0000, .match = 0xf4890000, .id = C54X_INS_MACAR, .len = 2, .ops = { { .fn = c54x_x_t }, { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfe000000, .match = 0x78000000, .id = C54X_INS_MACP, .len = 4, .ops = { { .lo = 16, .width = 8, .fn = c54x_x_smem }, { .fn = c54x_x_dmad }, { .lo = 24, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0xa6000000, .id = C54X_INS_MACSU, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_xmem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	// Smem,TS,acc shift-by-TREG forms
	{ .mask = 0xfe000000, .match = 0x04000000, .id = C54X_INS_ADD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .param = 0, .fn = c54x_x_kw }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x0c000000, .id = C54X_INS_SUB, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .param = 0, .fn = c54x_x_kw }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfe000000, .match = 0x14000000, .id = C54X_INS_LD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .param = 0, .fn = c54x_x_kw }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	// src,ASM,dst shift-by-ASM forms
	{ .mask = 0xfcff0000, .match = 0xf4800000, .id = C54X_INS_ADD, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .param = 1, .fn = c54x_x_kw }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfcff0000, .match = 0xf4810000, .id = C54X_INS_SUB, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .param = 1, .fn = c54x_x_kw }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfcff0000, .match = 0xf4820000, .id = C54X_INS_LD, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .param = 1, .fn = c54x_x_kw }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	// #lk,16 long-immediate-shifted-by-16 forms
	{ .mask = 0xfcff0000, .match = 0xf0600000, .id = C54X_INS_ADD, .len = 4, .ops = { { .fn = c54x_x_lk }, { .fn = c54x_x_lit16 }, { .lo = 25, .width = 1, .fn = c54x_x_acc }, { .lo = 24, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfcff0000, .match = 0xf0610000, .id = C54X_INS_SUB, .len = 4, .ops = { { .fn = c54x_x_lk }, { .fn = c54x_x_lit16 }, { .lo = 25, .width = 1, .fn = c54x_x_acc }, { .lo = 24, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfeff0000, .match = 0xf0620000, .id = C54X_INS_LD, .len = 4, .ops = { { .fn = c54x_x_lk }, { .fn = c54x_x_lit16 }, { .lo = 24, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfcff0000, .match = 0xf0630000, .id = C54X_INS_AND, .len = 4, .ops = { { .fn = c54x_x_lk }, { .fn = c54x_x_lit16 }, { .lo = 25, .width = 1, .fn = c54x_x_acc }, { .lo = 24, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfcff0000, .match = 0xf0640000, .id = C54X_INS_OR, .len = 4, .ops = { { .fn = c54x_x_lk }, { .fn = c54x_x_lit16 }, { .lo = 25, .width = 1, .fn = c54x_x_acc }, { .lo = 24, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfcff0000, .match = 0xf0650000, .id = C54X_INS_XOR, .len = 4, .ops = { { .fn = c54x_x_lk }, { .fn = c54x_x_lit16 }, { .lo = 25, .width = 1, .fn = c54x_x_acc }, { .lo = 24, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfeff0000, .match = 0xf0660000, .id = C54X_INS_MPY, .len = 4, .ops = { { .fn = c54x_x_lk }, { .lo = 24, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfcff0000, .match = 0xf0670000, .id = C54X_INS_MAC, .len = 4, .ops = { { .fn = c54x_x_lk }, { .lo = 25, .width = 1, .fn = c54x_x_acc }, { .lo = 24, .width = 1, .fn = c54x_x_acc_elide } } },
	// 2-word Smem,#lk multiply/MAC
	{ .mask = 0xfe000000, .match = 0x62000000, .id = C54X_INS_MPY, .len = 4, .ops = { { .lo = 16, .width = 8, .fn = c54x_x_smem }, { .fn = c54x_x_lk }, { .lo = 24, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfc000000, .match = 0x64000000, .id = C54X_INS_MAC, .len = 4, .ops = { { .lo = 16, .width = 8, .fn = c54x_x_smem }, { .fn = c54x_x_lk }, { .lo = 25, .width = 1, .fn = c54x_x_acc }, { .lo = 24, .width = 1, .fn = c54x_x_acc_elide } } },
	// Xmem,Ymem multiply
	{ .mask = 0xfe000000, .match = 0xa4000000, .id = C54X_INS_MPY, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_xmem }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	// special LD destination-register forms
	{ .mask = 0xff000000, .match = 0x30000000, .id = C54X_INS_LD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .fn = c54x_x_t } } },
	{ .mask = 0xff000000, .match = 0x46000000, .id = C54X_INS_LD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .param = 2, .fn = c54x_x_kw } } },
	{ .mask = 0xff000000, .match = 0x32000000, .id = C54X_INS_LD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .param = 1, .fn = c54x_x_kw } } },
	{ .mask = 0xfe000000, .match = 0xea000000, .id = C54X_INS_LD, .len = 2, .ops = { { .lo = 0, .width = 9, .fn = c54x_x_imm }, { .param = 2, .fn = c54x_x_kw } } },
	{ .mask = 0xffe00000, .match = 0xed000000, .id = C54X_INS_LD, .len = 2, .ops = { { .lo = 0, .width = 5, .fn = c54x_x_imm }, { .param = 1, .fn = c54x_x_kw } } },
	{ .mask = 0xfff80000, .match = 0xf4a00000, .id = C54X_INS_LD, .len = 2, .ops = { { .lo = 0, .width = 3, .fn = c54x_x_imm }, { .param = 3, .fn = c54x_x_kw } } },
	// STL/STH with ASM-register shift
	{ .mask = 0xfe000000, .match = 0x86000000, .id = C54X_INS_STH, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc }, { .param = 1, .fn = c54x_x_kw }, { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xfe000000, .match = 0x84000000, .id = C54X_INS_STL, .len = 2, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc }, { .param = 1, .fn = c54x_x_kw }, { .lo = 0, .width = 8, .fn = c54x_x_smem } } },
	// 2-word Smem,SHIFT forms: word1 = 0x6f|Smem, the operation lives in
	// word2 bits 7-5 (add=0,sub=1,ld=2,sth=3,stl=4), src=bit9, dst=bit8,
	// signed 5-bit shift in bits 4-0. Matching reaches into word2 (it is part
	// of the 4-byte match head), so each operation gets its own row. ---
	{ .mask = 0xff00fce0, .match = 0x6f000c00, .id = C54X_INS_ADD, .len = 4, .ops = { { .lo = 16, .width = 8, .fn = c54x_x_smem }, { .lo = 0, .width = 5, .fn = c54x_x_sft5a }, { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xff00fce0, .match = 0x6f000c20, .id = C54X_INS_SUB, .len = 4, .ops = { { .lo = 16, .width = 8, .fn = c54x_x_smem }, { .lo = 0, .width = 5, .fn = c54x_x_sft5a }, { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xff00fce0, .match = 0x6f000c40, .id = C54X_INS_LD, .len = 4, .ops = { { .lo = 16, .width = 8, .fn = c54x_x_smem }, { .lo = 0, .width = 5, .fn = c54x_x_sft5a }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xff00fce0, .match = 0x6f000c60, .id = C54X_INS_STH, .len = 4, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 5, .fn = c54x_x_sft5a }, { .lo = 16, .width = 8, .fn = c54x_x_smem } } },
	{ .mask = 0xff00fce0, .match = 0x6f000c80, .id = C54X_INS_STL, .len = 4, .ops = { { .lo = 8, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 5, .fn = c54x_x_sft5a }, { .lo = 16, .width = 8, .fn = c54x_x_smem } } },
	// remaining forms: SUB shifted-by-16, repeat with long immediate
	{ .mask = 0xfc000000, .match = 0x40000000, .id = C54X_INS_SUB, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_smem }, { .fn = c54x_x_lit16 }, { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xffff0000, .match = 0xf0700000, .id = C54X_INS_RPT, .len = 4, .ops = { { .fn = c54x_x_lk } } },
	// parallel (dual-operation) instructions: a single opcode encoding two
	// operations rendered "<op1> .. || <op2> ..". XXXX=Xmem (bits 7-4),
	// YYYY=Ymem (bits 3-0); the store uses Ymem and the arithmetic uses Xmem.
	// The second mnemonic is emitted as a qual_join raw operand. ---
	{ .mask = 0xfc000000, .match = 0xc0000000, .id = C54X_INS_ST, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 4, .fn = c54x_x_xmem }, { .param = 0, .fn = c54x_x_par2 }, { .lo = 4, .width = 4, .fn = c54x_x_xmem_par }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfc000000, .match = 0xc4000000, .id = C54X_INS_ST, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 4, .fn = c54x_x_xmem }, { .param = 1, .fn = c54x_x_par2 }, { .lo = 4, .width = 4, .fn = c54x_x_xmem_par }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfc000000, .match = 0xc8000000, .id = C54X_INS_ST, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 4, .fn = c54x_x_xmem }, { .param = 3, .fn = c54x_x_par2 }, { .lo = 4, .width = 4, .fn = c54x_x_xmem_par }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfc000000, .match = 0xcc000000, .id = C54X_INS_ST, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 4, .fn = c54x_x_xmem }, { .param = 2, .fn = c54x_x_par2 }, { .lo = 4, .width = 4, .fn = c54x_x_xmem_par }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xf8000000, .match = 0xd0000000, .id = C54X_INS_ST, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 4, .fn = c54x_x_xmem }, { .lo = 10, .width = 1, .param = 4, .fn = c54x_x_par2 }, { .lo = 4, .width = 4, .fn = c54x_x_xmem_par }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xf8000000, .match = 0xd8000000, .id = C54X_INS_ST, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 4, .fn = c54x_x_xmem }, { .lo = 10, .width = 1, .param = 6, .fn = c54x_x_par2 }, { .lo = 4, .width = 4, .fn = c54x_x_xmem_par }, { .lo = 8, .width = 1, .fn = c54x_x_acc } } },
	{ .mask = 0xfd000000, .match = 0xe4000000, .id = C54X_INS_ST, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 0, .width = 4, .fn = c54x_x_xmem }, { .param = 3, .fn = c54x_x_par2 }, { .lo = 4, .width = 4, .fn = c54x_x_xmem_par }, { .fn = c54x_x_t } } },
	{ .mask = 0xfc000000, .match = 0xa8000000, .id = C54X_INS_LD, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 8, .width = 1, .fn = c54x_x_acc }, { .lo = 9, .width = 1, .param = 4, .fn = c54x_x_par2 }, { .lo = 0, .width = 4, .fn = c54x_x_xmem_par } } },
	{ .mask = 0xfc000000, .match = 0xac000000, .id = C54X_INS_LD, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 8, .width = 1, .fn = c54x_x_acc }, { .lo = 9, .width = 1, .param = 6, .fn = c54x_x_par2 }, { .lo = 0, .width = 4, .fn = c54x_x_xmem_par } } },
	// dual-operand multiply-accumulate / -subtract: src (+|-)= Xmem * Ymem,
	// optional rounding gives the macr/masr mnemonic (round bit = bit 10). ---
	{ .mask = 0xfc000000, .match = 0xb0000000, .id = C54X_INS_MAC, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_xmem }, { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfc000000, .match = 0xb4000000, .id = C54X_INS_MACR, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_xmem }, { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfc000000, .match = 0xb8000000, .id = C54X_INS_MAS, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_xmem }, { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	{ .mask = 0xfc000000, .match = 0xbc000000, .id = C54X_INS_MASR, .len = 2, .ops = { { .lo = 4, .width = 4, .fn = c54x_x_xmem }, { .lo = 0, .width = 4, .fn = c54x_x_xmem }, { .lo = 9, .width = 1, .fn = c54x_x_acc }, { .lo = 8, .width = 1, .fn = c54x_x_acc_elide } } },
	// conditional return / execute (8-bit combinable condition). The cond=UNC
	// encodings 0xfc00/0xfe00 are matched earlier as ret/retd. ---
	{ .mask = 0xff000000, .match = 0xfc000000, .id = C54X_INS_RC, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_cond } } },
	{ .mask = 0xff000000, .match = 0xfe000000, .id = C54X_INS_RCD, .len = 2, .ops = { { .lo = 0, .width = 8, .fn = c54x_x_cond } } },
	{ .mask = 0xfd000000, .match = 0xfd000000, .id = C54X_INS_XC, .len = 2, .ops = { { .lo = 9, .width = 1, .fn = c54x_x_xcn }, { .lo = 0, .width = 8, .fn = c54x_x_cond } } },
};

// Fallback length (every row sets .len explicitly; *ARx(lk) modes extend in the
// engine). A bare 1-word default keeps a partial decode from over-reading.
static ut8 c54x_insn_len(const ut8 *buf, int len) {
	(void)buf;
	(void)len;
	return 2;
}

// Analysis entry point: decode once and fill the RzAnalysisOp. The returned
// value is op->size, the decoded instruction length, which is always >= 1
// (the instruction size on success, or 1 for an illegal byte) -- never negative.
RZ_IPI int tms320_c54x_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	(void)analysis;
	(void)mask;
	if (!op || !buf || len < 1) {
		return 0;
	}
	op->addr = addr;
	op->type = RZ_ANALYSIS_OP_TYPE_NULL;
	C55Insn ci;
	if (c55_decode(&c54x_arch_desc, buf, len, &ci)) {
		c55_fill_analysis(&c54x_arch_desc, &ci, op);
	} else {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->size = 1;
	}
	return op->size;
}

const C55ArchDesc c54x_arch_desc = {
	.arch = C55_ARCH_C54X,
	.cpu_name = "c54x",
	.table = c54x_table,
	.table_len = sizeof(c54x_table) / sizeof(c54x_table[0]),
	.insn_len = c54x_insn_len,
	.reg_info = c54x_reg_info,
	.mnemonic = c54x_mnemonic,
	.op_type = c54x_op_type,
	.lift = NULL,
	.mem = { .addr_unit_log2 = 1, .ptr_width = 16, .big_endian = false, .page_reg = "dp" },
	.ea = NULL,
	.fill_dual = NULL,
	.words_le = true,
};
